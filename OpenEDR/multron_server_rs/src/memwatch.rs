//! Where the memory goes: `/api/memory` (per component, from `openedr_static::memtrack`)
//! and a watcher that writes an event naming the stages and files holding it when the
//! process grows fast.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openedr_static::memtrack::{self, ComponentMem, Kind};

use crate::scan_server::ScanServer;

const SAMPLE_EVERY: Duration = Duration::from_secs(5);
/// Samples the growth is measured against (one minute).
const WINDOW: usize = 12;
/// Growth over the window that counts as a spike: this much, or a quarter of the
/// lowest point of the window, whichever is larger.
const MIN_SPIKE_BYTES: u64 = 512 * 1024 * 1024;
const REPORT_GAP: Duration = Duration::from_secs(120);

static LAST_SPIKE: Mutex<Option<serde_json::Value>> = Mutex::new(None);

fn human(bytes: i64) -> String {
    let b = bytes.max(0) as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GB", b / (1024.0 * 1024.0 * 1024.0))
    } else {
        format!("{:.0} MB", b / (1024.0 * 1024.0))
    }
}

fn mb(bytes: i64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0
}

fn component_json(c: &ComponentMem) -> serde_json::Value {
    serde_json::json!({
        "name": c.name,
        "kind": c.kind,
        "calls": c.calls,
        "liveMB": mb(c.live_bytes),
        "retainedMB": mb(c.retained_bytes),
        "lastPeakMB": mb(c.last_peak_bytes),
        "maxPeakMB": mb(c.max_peak_bytes),
        "maxPeakInputMB": mb(c.max_peak_input_bytes as i64),
    })
}

/// Files being scanned now, largest first: (name, size bytes).
fn largest_scanning(srv: &ScanServer, n: usize) -> (Vec<(String, i64)>, usize, usize) {
    let (scanning, _, ns, nw) = srv.scan_queue.snapshot(usize::MAX);
    let mut files: Vec<(String, i64)> = scanning.into_iter().map(|q| (q.file, q.size)).collect();
    files.sort_by_key(|f| std::cmp::Reverse(f.1));
    files.truncate(n);
    (files, ns, nw)
}

pub fn report(srv: &ScanServer) -> serde_json::Value {
    let (private, ws, peak_ws) = memtrack::process_memory();
    let comps = memtrack::snapshot();
    let loaded: i64 = comps.iter().filter(|c| c.kind == Kind::Load).map(|c| c.retained_bytes.max(0)).sum();
    let live: i64 = comps.iter().filter(|c| c.kind == Kind::Scan).map(|c| c.live_bytes).sum();
    let (files, ns, nw) = largest_scanning(srv, 10);
    serde_json::json!({
        "tracking": memtrack::installed(),
        "process": {
            "privateMB": mb(private as i64),
            "workingSetMB": mb(ws as i64),
            "peakWorkingSetMB": mb(peak_ws as i64),
        },
        "loadedMB": mb(loaded),
        "scanLiveMB": mb(live),
        "uploadBuffersMB": mb(srv.budget.in_use_bytes()),
        "components": comps.iter().map(component_json).collect::<Vec<_>>(),
        "scanning": ns,
        "waiting": nw,
        "largestScanning": files.iter().map(|(f, s)| serde_json::json!({ "file": f, "sizeMB": mb(*s) })).collect::<Vec<_>>(),
        "lastSpike": LAST_SPIKE.lock().unwrap().clone(),
    })
}

/// One line naming what holds the memory now: scan stages still running (live), then
/// upload buffers and the largest files in the engine.
fn spike_summary(srv: &ScanServer, private: u64, grew: u64) -> (String, serde_json::Value) {
    let comps = memtrack::snapshot();
    let mut holders: Vec<&ComponentMem> = comps.iter().filter(|c| c.live_bytes > 16 * 1024 * 1024).collect();
    holders.sort_by_key(|c| std::cmp::Reverse(c.live_bytes));
    holders.truncate(4);
    let (files, ns, _) = largest_scanning(srv, 3);
    let uploads = srv.budget.in_use_bytes();
    let mut parts = Vec::new();
    if holders.is_empty() {
        parts.push("no scan stage holds much right now".to_string());
    } else {
        parts.push(format!(
            "held now by {}",
            holders.iter().map(|c| format!("{} {}", c.name, human(c.live_bytes))).collect::<Vec<_>>().join(", ")
        ));
    }
    parts.push(format!("upload buffers {}", human(uploads)));
    if !files.is_empty() {
        parts.push(format!(
            "{ns} file(s) in the engine, largest {}",
            files.iter().map(|(f, s)| format!("{f} ({})", human(*s))).collect::<Vec<_>>().join(", ")
        ));
    }
    let msg = format!("Memory spike: {} private (+{} in the last minute); {}", human(private as i64), human(grew as i64), parts.join("; "));
    let json = serde_json::json!({
        "at": chrono::Utc::now(),
        "privateMB": mb(private as i64),
        "grewMB": mb(grew as i64),
        "holders": holders.iter().map(|c| component_json(c)).collect::<Vec<_>>(),
        "uploadBuffersMB": mb(uploads),
        "largestScanning": files.iter().map(|(f, s)| serde_json::json!({ "file": f, "sizeMB": mb(*s) })).collect::<Vec<_>>(),
        "message": msg,
    });
    (msg, json)
}

pub fn spawn(srv: Arc<ScanServer>) {
    let _ = std::thread::Builder::new().name("memwatch".into()).spawn(move || {
        let mut window: VecDeque<u64> = VecDeque::with_capacity(WINDOW + 1);
        let mut last_report: Option<Instant> = None;
        loop {
            std::thread::sleep(SAMPLE_EVERY);
            let (private, _, _) = memtrack::process_memory();
            if private == 0 {
                continue;
            }
            let low = window.iter().copied().min().unwrap_or(private);
            window.push_back(private);
            if window.len() > WINDOW {
                window.pop_front();
            }
            let grew = private.saturating_sub(low);
            if grew < MIN_SPIKE_BYTES.max(low / 4) || last_report.is_some_and(|t| t.elapsed() < REPORT_GAP) {
                continue;
            }
            last_report = Some(Instant::now());
            let (msg, json) = spike_summary(&srv, private, grew);
            *LAST_SPIKE.lock().unwrap() = Some(json);
            srv.log_info(msg);
        }
    });
}
