//! Rescanning files kept in the work folder (multron_incoming) with the current engine,
//! analyst signatures and TLSH smart whitelist: one file from the dashboard, or every
//! kept `unknown` / `possible_clean` file in the background (also after an engine
//! reload, when enabled). The client never has to upload the file again.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cache::parse_sha;
use crate::scan_server::ScanServer;

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub sha256: String,
    pub file_name: String,
    pub old_verdict: String,
    pub new_verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub at: String,
    /// Size of the kept file in bytes.
    #[serde(default)]
    pub size: u64,
}

/// One rescanned file for the dashboard log (verdict kept or changed, or failed).
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub sha256: String,
    pub file_name: String,
    pub old_verdict: String,
    /// Empty when the rescan failed.
    pub new_verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub changed: bool,
    pub size: u64,
    pub ms: u64,
    pub at: String,
    /// "single" (one file from the dashboard), "bulk" or "reload" (after an engine reload).
    pub source: &'static str,
    /// Bulk run number (0 for single rescans).
    pub run: u64,
}

const LOG_MAX: usize = 3000;

/// Background rescan of kept files.
#[derive(Default)]
pub struct BulkRescan {
    /// Start a bulk rescan after every successful engine reload (dashboard setting).
    pub after_reload: AtomicBool,
    running: AtomicBool,
    stop: AtomicBool,
    total: AtomicUsize,
    done: AtomicUsize,
    changed: AtomicUsize,
    failed: AtomicUsize,
    started_at: Mutex<Option<String>>,
    finished_at: Mutex<Option<String>>,
    /// Verdict changes, newest first (at most 100).
    changes: Mutex<VecDeque<Change>>,
    /// Every rescanned file, newest first (at most LOG_MAX), across runs.
    log: Mutex<VecDeque<LogEntry>>,
    run: std::sync::atomic::AtomicU64,
    categories: Mutex<Vec<String>>,
}

impl BulkRescan {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "running": self.is_running(),
            "afterReload": self.after_reload.load(Ordering::Relaxed),
            "total": self.total.load(Ordering::Relaxed),
            "done": self.done.load(Ordering::Relaxed),
            "changed": self.changed.load(Ordering::Relaxed),
            "failed": self.failed.load(Ordering::Relaxed),
            "startedAt": *self.started_at.lock().unwrap(),
            "finishedAt": *self.finished_at.lock().unwrap(),
            "changes": self.changes.lock().unwrap().iter().take(30).cloned().collect::<Vec<_>>(),
            "run": self.run.load(Ordering::Relaxed),
            "categories": self.categories.lock().unwrap().clone(),
        })
    }

    /// Newest first.
    pub fn log(&self) -> Vec<LogEntry> {
        self.log.lock().unwrap().iter().cloned().collect()
    }

    fn push_log(&self, e: LogEntry) {
        let mut g = self.log.lock().unwrap();
        g.push_front(e);
        g.truncate(LOG_MAX);
    }

    fn push_change(&self, c: Change) {
        let mut g = self.changes.lock().unwrap();
        g.push_front(c);
        g.truncate(100);
    }
}

/// Rescans one kept file. Blocking: call from a blocking thread.
pub fn rescan_one(server: &Arc<ScanServer>, sha_hex: &str) -> Result<Change, String> {
    let sha_up = sha_hex.trim().to_ascii_uppercase();
    let sha = parse_sha(&sha_up).ok_or("invalid sha256")?;
    let kept = server
        .engine
        .find_kept(&sha_up)
        .ok_or("this file is not kept on the server (multron_incoming); the client has to send it again")?;
    let data = kept.read().ok_or("the kept file could not be read")?;
    let data_len = data.len() as u64;
    let actual = hex::encode_upper(Sha256::digest(&data));
    if actual != sha_up {
        return Err("the kept file does not match its SHA-256 (damaged?)".into());
    }
    let old_verdict = server.threat_intel.get(&sha_up).map(|i| i.verdict).unwrap_or_else(|| "unknown".into());

    let ti = Arc::clone(&server.threat_intel);
    let mut report = None;
    let res = server.engine.scan_blocking_opts(&data, &kept.name, &sha_up, false, |res| {
        report = crate::scan_server::apply_smart_whitelist(&ti, &data, &kept.name, res);
    })?;

    // The kept file sits in the folder of the effective verdict: a human verdict wins.
    let human = server.threat_intel.reviews.completed(&sha_up).and_then(|r| r.verdict);
    server.engine.relabel_kept(&sha_up, human.as_deref().unwrap_or(&res.verdict));
    server.remember(sha, &res);
    server.threat_intel.set_engine_verdict(&sha_up, &res.verdict, res.threat.as_deref(), res.score);
    if let Some(sg) = res.signer.as_ref() {
        server.threat_intel.set_signer(&sha_up, sg);
    }

    // Fresh static report (a newer analyzer may add fields) and TLSH index entry.
    if report.is_none() {
        report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::analyzer::analyze(&data, &kept.name))).ok();
    }
    if let Some(rep) = report.as_ref() {
        crate::reports::replace(rep);
        if let Some(t) = rep.hashes.similarity_tlsh() {
            server.threat_intel.similarity.add(&rep.hashes.sha256, t, rep.size);
        }
    }
    if crate::human_review::AUTO_QUEUE_VERDICTS.contains(&res.verdict.as_str()) {
        let _ = server.threat_intel.reviews.enqueue(&sha_up.to_ascii_lowercase(), "rescan", Some(&res.verdict), Some(&kept.name));
    }

    let change = Change {
        sha256: sha_up.to_ascii_lowercase(),
        file_name: kept.name.clone(),
        old_verdict,
        new_verdict: res.verdict.clone(),
        threat: res.threat.clone(),
        detail: res.detail.clone(),
        at: chrono::Utc::now().to_rfc3339(),
        size: data_len,
    };
    server.log_info(format!(
        "rescan {} ({}): {} -> {}{}",
        change.sha256,
        change.file_name,
        change.old_verdict,
        change.new_verdict,
        change.threat.as_deref().map(|t| format!(" {t}")).unwrap_or_default()
    ));
    Ok(change)
}

/// `rescan_one` plus a dashboard log entry (also for failures).
pub fn rescan_logged(server: &Arc<ScanServer>, sha_hex: &str, source: &'static str, run: u64) -> Result<Change, String> {
    let t = std::time::Instant::now();
    let r = rescan_one(server, sha_hex);
    let ms = t.elapsed().as_millis() as u64;
    let at = chrono::Utc::now().to_rfc3339();
    let entry = match &r {
        Ok(c) => LogEntry {
            sha256: c.sha256.clone(),
            file_name: c.file_name.clone(),
            old_verdict: c.old_verdict.clone(),
            new_verdict: c.new_verdict.clone(),
            threat: c.threat.clone(),
            detail: c.detail.clone(),
            error: None,
            changed: c.old_verdict != c.new_verdict,
            size: c.size,
            ms,
            at,
            source,
            run,
        },
        Err(e) => {
            let sha = sha_hex.trim().to_ascii_uppercase();
            let kept = server.engine.find_kept(&sha);
            LogEntry {
                sha256: sha.to_ascii_lowercase(),
                file_name: kept.as_ref().map(|k| k.name.clone()).unwrap_or_default(),
                old_verdict: server.threat_intel.get(&sha.to_ascii_lowercase()).map(|i| i.verdict).unwrap_or_else(|| "unknown".into()),
                new_verdict: String::new(),
                threat: None,
                detail: None,
                error: Some(e.clone()),
                changed: false,
                size: 0,
                ms,
                at,
                source,
                run,
            }
        }
    };
    server.rescan.push_log(entry);
    r
}

/// Kept-file categories (folders in multron_incoming) a bulk rescan can cover:
/// "unknown", "possible_clean", "suspicious", "malicious" and "clean". "threat" is
/// accepted for malicious + suspicious.
pub const CATEGORIES: [&str; 5] = crate::engine_adapter::KeptFile::CATEGORIES;
/// Used after an engine reload and when no category is given.
pub const DEFAULT_CATEGORIES: [&str; 2] = ["unknown", "possible_clean"];

/// Starts a background rescan of the kept files in `categories` (see `CATEGORIES`).
/// Returns how many files are queued.
pub fn start_bulk(server: &Arc<ScanServer>, categories: &[String]) -> Result<usize, String> {
    start_bulk_from(server, categories, "bulk")
}

/// `source`: "bulk" (dashboard button) or "reload" (after an engine reload).
pub fn start_bulk_from(server: &Arc<ScanServer>, categories: &[String], source: &'static str) -> Result<usize, String> {
    let cats: Vec<&str> = if categories.is_empty() {
        DEFAULT_CATEGORIES.to_vec()
    } else {
        let mut v = Vec::new();
        for c in categories {
            if c == "threat" {
                v.extend(["malicious", "suspicious"]);
                continue;
            }
            let c = CATEGORIES.iter().find(|k| **k == c.as_str()).ok_or_else(|| format!("unknown category {c}"))?;
            v.push(*c);
        }
        v
    };
    let bulk = &server.rescan;
    if bulk.running.swap(true, Ordering::SeqCst) {
        return Err("a rescan is already running".into());
    }
    let files: Vec<String> = server
        .engine
        .list_kept()
        .into_iter()
        .filter(|k| cats.contains(&k.category))
        .map(|k| k.sha256)
        .collect();
    bulk.stop.store(false, Ordering::Relaxed);
    bulk.total.store(files.len(), Ordering::Relaxed);
    bulk.done.store(0, Ordering::Relaxed);
    bulk.changed.store(0, Ordering::Relaxed);
    bulk.failed.store(0, Ordering::Relaxed);
    *bulk.started_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
    *bulk.finished_at.lock().unwrap() = None;
    bulk.changes.lock().unwrap().clear();
    let run = bulk.run.fetch_add(1, Ordering::Relaxed) + 1;
    *bulk.categories.lock().unwrap() = cats.iter().map(|c| c.to_string()).collect();

    let n = files.len();
    let srv = Arc::clone(server);
    let spawned = std::thread::Builder::new()
        .name("bulk-rescan".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let bulk = &srv.rescan;
            for sha in files {
                if bulk.stop.load(Ordering::Relaxed) {
                    break;
                }
                // One file at a time, so client scans keep priority on the engine threads.
                match rescan_logged(&srv, &sha, source, run) {
                    Ok(c) => {
                        if c.old_verdict != c.new_verdict {
                            bulk.changed.fetch_add(1, Ordering::Relaxed);
                            bulk.push_change(c);
                        }
                    }
                    Err(_) => {
                        bulk.failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                bulk.done.fetch_add(1, Ordering::Relaxed);
            }
            *bulk.finished_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
            bulk.running.store(false, Ordering::SeqCst);
            srv.log_info(format!(
                "bulk rescan finished: {} of {} files, {} verdicts changed, {} failed",
                bulk.done.load(Ordering::Relaxed),
                bulk.total.load(Ordering::Relaxed),
                bulk.changed.load(Ordering::Relaxed),
                bulk.failed.load(Ordering::Relaxed)
            ));
        });
    if let Err(e) = spawned {
        bulk.running.store(false, Ordering::SeqCst);
        return Err(format!("cannot start the rescan thread: {e}"));
    }
    server.log_info(format!("bulk rescan started: {n} kept files ({})", cats.join(", ")));
    Ok(n)
}
