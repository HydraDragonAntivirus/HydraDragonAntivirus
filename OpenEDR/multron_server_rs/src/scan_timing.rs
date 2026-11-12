//! Which engine the time goes to: `/api/engine-time`. Totals per stage since the start
//! (from `openedr_static::memtrack`), and the stage times of each scan that took a
//! second or more, so a scan that takes seconds shows which engine took them. Kept in
//! memory only: the recent slow scans and the slowest ones since the start, both bounded.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use openedr_static::memtrack::{self, StageTime};
use openedr_static::report::ExtractedObject;

/// A scan counts as slow from this long on.
const SLOW: Duration = Duration::from_secs(1);
const RECENT: usize = 50;
const SLOWEST: usize = 20;
/// Stages listed per scan (the rest are summed into "other stages").
const STAGES_PER_SCAN: usize = 8;

#[derive(Clone)]
struct SlowScan {
    at: chrono::DateTime<chrono::Utc>,
    file: String,
    sha256: String,
    size: usize,
    total: Duration,
    verdict: String,
    stages: Vec<StageTime>,
    /// Objects the engine took out of the file and scanned on their own (archive
    /// members, unpacked / decrypted payloads, overlay, ...): a file with thousands of
    /// members is slow for that reason, not because one engine is slow.
    objects: Objects,
}

#[derive(Clone, Default)]
struct Objects {
    count: usize,
    bytes: u64,
    /// Count and bytes per kind (`ArchiveMember`, `UnpackedPE`, ...), most first.
    kinds: Vec<(String, usize, u64)>,
}

impl Objects {
    fn of(objects: &[ExtractedObject]) -> Self {
        let mut kinds: Vec<(String, usize, u64)> = Vec::new();
        for o in objects {
            match kinds.iter_mut().find(|k| k.0 == o.origin_type) {
                Some(k) => {
                    k.1 += 1;
                    k.2 += o.size;
                }
                None => kinds.push((o.origin_type.clone(), 1, o.size)),
            }
        }
        kinds.sort_by(|a, b| b.1.cmp(&a.1));
        Self { count: objects.len(), bytes: objects.iter().map(|o| o.size).sum(), kinds }
    }
}

struct State {
    scans: u64,
    slow: u64,
    total_ns: u128,
    recent: VecDeque<SlowScan>,
    /// Slowest first.
    slowest: Vec<SlowScan>,
}

static STATE: Mutex<State> = Mutex::new(State { scans: 0, slow: 0, total_ns: 0, recent: VecDeque::new(), slowest: Vec::new() });

fn ms(ns: u128) -> f64 {
    (ns as f64 / 1_000_000.0 * 10.0).round() / 10.0
}

/// Engine stages are named `scan:<stage>`, the server's own `server:<stage>`.
fn label(name: &str) -> &str {
    name.strip_prefix("scan:").unwrap_or(name)
}

/// Called after every engine scan (`scan_blocking_opts`), with its stage times and the
/// objects taken out of the file (empty when the scan failed).
pub fn record(
    file: &str,
    sha: &str,
    size: usize,
    total: Duration,
    verdict: Option<&str>,
    stages: Vec<StageTime>,
    objects: &[ExtractedObject],
) {
    let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    s.scans += 1;
    s.total_ns += total.as_nanos();
    if total < SLOW {
        return;
    }
    s.slow += 1;
    let objects = Objects::of(objects);
    let kinds: Vec<String> = objects.kinds.iter().map(|(k, c, _)| format!("{c} {k}")).collect();
    let top: Vec<String> = stages
        .iter()
        .take(3)
        .map(|t| format!("{} {:.0}ms", label(t.name), ms(t.self_ns as u128)))
        .collect();
    eprintln!(
        "[SLOW-SCAN] {:.0}ms {file} ({} KB, sha256 {sha}) verdict={} objects={} ({} KB{}{}) top: {}",
        ms(total.as_nanos()),
        size / 1024,
        verdict.unwrap_or("error"),
        objects.count,
        objects.bytes / 1024,
        if kinds.is_empty() { "" } else { ": " },
        kinds.join(", "),
        top.join(", "),
    );
    let scan = SlowScan {
        at: chrono::Utc::now(),
        file: file.to_string(),
        sha256: sha.to_string(),
        size,
        total,
        verdict: verdict.unwrap_or("error").to_string(),
        stages,
        objects,
    };
    if s.slowest.len() < SLOWEST || s.slowest.last().is_some_and(|l| l.total < total) {
        let at = s.slowest.partition_point(|x| x.total >= total);
        s.slowest.insert(at, scan.clone());
        s.slowest.truncate(SLOWEST);
    }
    if s.recent.len() == RECENT {
        s.recent.pop_front();
    }
    s.recent.push_back(scan);
}

fn scan_json(s: &SlowScan) -> serde_json::Value {
    let total_ns = s.total.as_nanos();
    let shown: Vec<_> = s.stages.iter().take(STAGES_PER_SCAN).collect();
    let rest: u128 = s.stages.iter().skip(STAGES_PER_SCAN).map(|t| t.self_ns as u128).sum();
    let counted: u128 = s.stages.iter().map(|t| t.self_ns as u128).sum();
    serde_json::json!({
        "at": s.at,
        "file": s.file,
        "sha256": s.sha256,
        "size": s.size,
        "totalMs": ms(total_ns),
        "verdict": s.verdict,
        "objects": s.objects.count,
        "objectBytes": s.objects.bytes,
        "objectKinds": s.objects.kinds.iter().map(|(kind, count, bytes)| serde_json::json!({
            "kind": kind,
            "count": count,
            "bytes": bytes,
        })).collect::<Vec<_>>(),
        "slowest": shown.first().map(|t| label(t.name)),
        "stages": shown.iter().map(|t| serde_json::json!({
            "name": label(t.name),
            "ms": ms(t.self_ns as u128),
            "calls": t.calls,
            "share": if total_ns > 0 { (t.self_ns as f64 / total_ns as f64 * 1000.0).round() / 10.0 } else { 0.0 },
        })).collect::<Vec<_>>(),
        "otherStagesMs": ms(rest),
        // Time no stage covers (hashing, building the result). Worker threads of one
        // scan run side by side, so the stages can also add up to more than the scan.
        "unstagedMs": ms(total_ns.saturating_sub(counted)),
    })
}

pub fn report() -> serde_json::Value {
    let s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    // Loaders time themselves too (startup, reloads); only the per-file stages here.
    let stages: Vec<StageTime> = memtrack::time_snapshot()
        .into_iter()
        .filter(|t| t.name.starts_with("scan:") || t.name.starts_with("server:"))
        .collect();
    let all_ns: u128 = stages.iter().map(|t| t.self_ns as u128).sum();
    serde_json::json!({
        "scans": s.scans,
        "slowScans": s.slow,
        "slowFromMs": SLOW.as_millis() as u64,
        "avgScanMs": if s.scans > 0 { ms(s.total_ns / s.scans as u128) } else { 0.0 },
        "stages": stages.iter().map(|t| serde_json::json!({
            "name": label(t.name),
            "calls": t.calls,
            "totalMs": ms(t.self_ns as u128),
            "avgMs": if t.calls > 0 { ms(t.self_ns as u128 / t.calls as u128) } else { 0.0 },
            "maxMs": ms(t.max_ns as u128),
            "share": if all_ns > 0 { (t.self_ns as f64 / all_ns as f64 * 1000.0).round() / 10.0 } else { 0.0 },
        })).collect::<Vec<_>>(),
        "recent": s.recent.iter().rev().map(scan_json).collect::<Vec<_>>(),
        "slowest": s.slowest.iter().map(scan_json).collect::<Vec<_>>(),
    })
}
