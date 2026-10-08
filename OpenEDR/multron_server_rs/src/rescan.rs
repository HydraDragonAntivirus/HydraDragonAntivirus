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
}

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
        })
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

    server.engine.relabel_kept(&sha_up, &res.verdict);
    server.remember(sha, &res);
    server.threat_intel.set_engine_verdict(&sha_up, &res.verdict, res.threat.as_deref(), res.score);

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
    if matches!(res.verdict.as_str(), "unknown" | "suspicious" | "possible_clean") {
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

/// Starts a background rescan of every kept `unknown` and `possible_clean` file.
/// Returns how many files are queued.
pub fn start_bulk(server: &Arc<ScanServer>) -> Result<usize, String> {
    let bulk = &server.rescan;
    if bulk.running.swap(true, Ordering::SeqCst) {
        return Err("a rescan is already running".into());
    }
    let files: Vec<String> = server
        .engine
        .list_kept()
        .into_iter()
        .filter(|k| k.prefix.is_empty() || k.prefix == "possible_clean_")
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
                match rescan_one(&srv, &sha) {
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
    server.log_info(format!("bulk rescan started: {n} kept unknown / possible_clean files"));
    Ok(n)
}
