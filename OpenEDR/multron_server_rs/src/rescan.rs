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
    let Some(kept) = server.engine.find_kept(&sha_up) else {
        let why = crate::missing_files::explain(&sha_up);
        if server.threat_intel.reviews.completed(&sha_up).is_none() {
            reset_unkept_one(server, &sha_up);
            server.cache.forget(&[sha].into_iter().collect());
        }
        return Err(format!("{why}; set to unknown so the client sends it again"));
    };
    let data = kept.read().ok_or("the kept file could not be read")?;
    let data_len = data.len() as u64;
    let actual = hex::encode_upper(Sha256::digest(&data));
    if actual != sha_up {
        return Err("the kept file does not match its SHA-256 (damaged?)".into());
    }
    let old_verdict = server.threat_intel.get(&sha_up).map(|i| i.verdict.to_string()).unwrap_or_else(|| "unknown".into());

    let ti = Arc::clone(&server.threat_intel);
    let mut report = None;
    let res = server.engine.scan_blocking_opts(&data, &kept.name, &sha_up, false, |res| {
        report = crate::scan_server::apply_threat_intel(&ti, &data, &kept.name, res);
    })?;

    // The kept file sits in the folder of the effective verdict: a human verdict wins.
    let human = server.threat_intel.reviews.completed(&sha_up).and_then(|r| r.verdict);
    match human.as_deref() {
        Some(v) => server.engine.relabel_kept(&sha_up, v),
        // Engine verdict: XOR-filter hits stay in their folder until an analyst decides.
        None => server.engine.relabel_kept_to(&sha_up, crate::engine_adapter::KeptFile::category_for_result(&res)),
    }
    server.remember(sha, &res);
    if server.threat_intel.get(&sha_up).is_none() {
        // Kept on disk but missing from the list (e.g. telemetry lost): add it, so it is
        // counted in the statistics and shows up in human analysis.
        server.threat_intel.record(&sha_up.to_ascii_lowercase(), &res.verdict, res.threat.as_deref(), Some(&kept.name), Some(data_len), res.score);
    } else {
        server.threat_intel.set_engine_verdict(&sha_up, &res.verdict, res.threat.as_deref(), res.score);
    }
    if let Some(sg) = res.signer.as_ref() {
        server.threat_intel.set_signer(&sha_up, sg);
    }
    server.threat_intel.set_detections(&sha_up, &res.verdict, &res.detections, true);

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
                old_verdict: server.threat_intel.get(&sha.to_ascii_lowercase()).map(|i| i.verdict.to_string()).unwrap_or_else(|| "unknown".into()),
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
pub const CATEGORIES: [&str; 7] = crate::engine_adapter::KeptFile::CATEGORIES;
/// Used after an engine reload and when no category is given.
pub const DEFAULT_CATEGORIES: [&str; 2] = ["unknown", "possible_clean"];

/// Starts a background rescan of the kept files in `categories` (see `CATEGORIES`).
/// Returns how many files are queued.
pub fn start_bulk(server: &Arc<ScanServer>, categories: &[String]) -> Result<usize, String> {
    start_bulk_from(server, categories, "bulk")
}

/// `source`: "bulk" (dashboard button) or "reload" (after an engine reload).
fn parse_categories(categories: &[String]) -> Result<Vec<&'static str>, String> {
    Ok(if categories.is_empty() {
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
    })
}

pub fn start_bulk_from(server: &Arc<ScanServer>, categories: &[String], source: &'static str) -> Result<usize, String> {
    let cats = parse_categories(categories)?;
    let files: Vec<String> = server
        .engine
        .list_kept()
        .into_iter()
        .filter(|k| cats.contains(&k.category))
        .map(|k| k.sha256)
        .collect();
    let label = cats.join(", ");
    spawn_bulk(server, files, cats.iter().map(|c| c.to_string()).collect(), label, source)
}

/// One kept file with what is wrong with it.
#[derive(Debug, Clone, Serialize)]
pub struct AuditItem {
    pub sha256: String,
    pub file_name: String,
    /// Folders (categories) the file is in; more than one for a duplicate.
    pub categories: Vec<&'static str>,
    pub copies: usize,
    pub duplicate: bool,
    /// Not in the telemetry list, so not counted in the statistics.
    pub not_listed: bool,
}

/// Groups the kept files by SHA-256 and returns the ones that are duplicate (the same
/// file in more than one place of multron_incoming) or not listed (no telemetry entry).
pub fn kept_problems(server: &Arc<ScanServer>) -> Vec<AuditItem> {
    let mut by_sha: std::collections::BTreeMap<String, AuditItem> = std::collections::BTreeMap::new();
    for k in server.engine.list_kept() {
        let e = by_sha.entry(k.sha256.clone()).or_insert_with(|| AuditItem {
            sha256: k.sha256.to_ascii_lowercase(),
            file_name: k.name.clone(),
            categories: Vec::new(),
            copies: 0,
            duplicate: false,
            not_listed: false,
        });
        e.copies += 1;
        if !e.categories.contains(&k.category) {
            e.categories.push(k.category);
        }
    }
    by_sha
        .into_values()
        .filter_map(|mut e| {
            e.duplicate = e.copies > 1;
            e.not_listed = server.threat_intel.get(&e.sha256).is_none();
            (e.duplicate || e.not_listed).then_some(e)
        })
        .collect()
}

/// Counts per category for the dashboard plus the first files of each kind.
pub fn kept_audit(server: &Arc<ScanServer>) -> serde_json::Value {
    let items = kept_problems(server);
    let mut per = serde_json::Map::new();
    for c in CATEGORIES {
        let inc = items.iter().filter(|i| i.categories.contains(&c));
        let (dup, nl) = inc.fold((0usize, 0usize), |(d, n), i| (d + i.duplicate as usize, n + i.not_listed as usize));
        per.insert(c.to_string(), serde_json::json!({ "duplicate": dup, "not_listed": nl }));
    }
    serde_json::json!({
        "ok": true,
        "duplicate": items.iter().filter(|i| i.duplicate).count(),
        "not_listed": items.iter().filter(|i| i.not_listed).count(),
        "categories": per,
        "items": items.iter().take(500).collect::<Vec<_>>(),
        "total_items": items.len(),
    })
}

/// Engine verdicts `unkept_threats_report` can reset.
pub const UNKEPT_VERDICTS: [&str; 4] = ["malicious", "suspicious", "possible_clean", "clean"];
pub const DEFAULT_UNKEPT_VERDICTS: [&str; 3] = ["malicious", "suspicious", "possible_clean"];

fn reset_unkept_one(server: &ScanServer, sha: &str) {
    server.threat_intel.set_engine_verdict_from(sha, "unknown", None, 0.0, "unkept");
    crate::missing_files::set_unknown(sha);
    if server.threat_intel.reviews.get(sha).is_some_and(|r| !r.is_completed()) {
        server.threat_intel.reviews.remove(sha);
    }
}

/// Hashes with one of `verdicts` from the engine, verdict cache, quota-drop log or
/// pending review queue (no completed analyst verdict) whose file is not kept here: a
/// rescan cannot check them again, so their old verdict stays in the statistics and is
/// still given to clients that send the hash. (upper-case hex, verdict).
fn unkept_threats(server: &Arc<ScanServer>, verdicts: &[&str]) -> Vec<(String, String)> {
    let kept: std::collections::HashSet<String> =
        server.engine.list_kept().into_iter().map(|k| k.sha256.to_ascii_uppercase()).collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let pending = server.threat_intel.reviews.pending(usize::MAX).into_iter().filter_map(|r| {
        let v = r.engine_verdict?;
        verdicts.contains(&v.as_str()).then(|| (r.sha256.to_ascii_uppercase(), v))
    });
    for (sha, v) in server
        .threat_intel
        .engine_verdict_hashes(verdicts)
        .into_iter()
        .chain(server.cache.verdict_hashes(verdicts))
        .chain(crate::missing_files::verdict_hashes(verdicts))
        .chain(pending)
    {
        if kept.contains(&sha) || !seen.insert(sha.clone()) {
            continue;
        }
        if server.threat_intel.reviews.completed(&sha).is_some() {
            continue;
        }
        out.push((sha, v));
    }
    out
}

/// Why the file of `sha` is not here (`missing_files::explain` in short).
fn unkept_reason(sha: &str) -> &'static str {
    if crate::archived::get(sha).is_some() {
        return "archived";
    }
    match crate::missing_files::get(sha).map(|m| m.reason) {
        Some(r) if r == "offloaded" => "offloaded",
        Some(r) if r == "quota" => "quota",
        Some(_) => "other",
        None => "hash_only",
    }
}

/// `unkept_threats` with counts per verdict and per reason. `verdicts`: any of
/// `UNKEPT_VERDICTS` (empty = `DEFAULT_UNKEPT_VERDICTS`). With `apply`, their engine
/// verdict becomes unknown (written to the telemetry, missing-file log and verdict
/// history as "unkept"; nothing is deleted), pending unkept queue entries are removed,
/// and their cached verdict is dropped, so the next client that has the file uploads it
/// and it is scanned with the current engine. Dashboard button only.
pub fn unkept_threats_report(server: &Arc<ScanServer>, verdicts: &[String], apply: bool) -> Result<serde_json::Value, String> {
    let mut wanted: Vec<&str> = Vec::new();
    for v in verdicts {
        let k = UNKEPT_VERDICTS
            .iter()
            .find(|k| **k == v.as_str())
            .ok_or_else(|| format!("unknown verdict {v} ({})", UNKEPT_VERDICTS.join(", ")))?;
        if !wanted.contains(k) {
            wanted.push(k);
        }
    }
    if wanted.is_empty() {
        wanted = DEFAULT_UNKEPT_VERDICTS.to_vec();
    }
    let shas = unkept_threats(server, &wanted);
    let mut reasons: std::collections::BTreeMap<&'static str, usize> = std::collections::BTreeMap::new();
    let mut per_verdict: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (sha, v) in &shas {
        *reasons.entry(unkept_reason(sha)).or_default() += 1;
        *per_verdict.entry(v.clone()).or_default() += 1;
    }
    let sample: Vec<serde_json::Value> = shas
        .iter()
        .take(500)
        .map(|(sha, v)| {
            let item = server.threat_intel.get(sha);
            serde_json::json!({
                "sha256": sha.to_ascii_lowercase(),
                "verdict": v,
                "file_name": item.as_ref().and_then(|i| i.file_names.first().cloned()).unwrap_or_default(),
                "threat": item.and_then(|i| i.threat_name),
                "reason": unkept_reason(sha),
            })
        })
        .collect();
    let mut uncached = 0;
    if apply {
        for (sha, _) in &shas {
            reset_unkept_one(server, sha);
        }
        let set: std::collections::HashSet<_> = shas.iter().filter_map(|(s, _)| parse_sha(s)).collect();
        uncached = server.cache.forget(&set);
        server.log_info(format!(
            "{} {} hashes without a kept file set to unknown ({uncached} cached verdicts dropped)",
            shas.len(),
            wanted.join(" / ")
        ));
    }
    Ok(serde_json::json!({
        "ok": true,
        "applied": apply,
        "count": shas.len(),
        "verdicts": per_verdict,
        "reasons": reasons,
        "uncached": uncached,
        "items": sample,
    }))
}

/// Rescans the duplicate and/or not-listed kept files of `categories` (one rescan per
/// SHA-256). `kinds`: "duplicate", "not_listed" (empty = both).
pub fn start_bulk_problems(server: &Arc<ScanServer>, categories: &[String], kinds: &[String]) -> Result<usize, String> {
    let cats = parse_categories(categories)?;
    let want_dup = kinds.is_empty() || kinds.iter().any(|k| k == "duplicate");
    let want_nl = kinds.is_empty() || kinds.iter().any(|k| k == "not_listed");
    for k in kinds {
        if k != "duplicate" && k != "not_listed" {
            return Err(format!("unknown kind {k} (duplicate or not_listed)"));
        }
    }
    let files: Vec<String> = kept_problems(server)
        .into_iter()
        .filter(|i| i.categories.iter().any(|c| cats.contains(c)))
        .filter(|i| (want_dup && i.duplicate) || (want_nl && i.not_listed))
        .map(|i| i.sha256.to_ascii_uppercase())
        .collect();
    let what = match (want_dup, want_nl) {
        (true, true) => "duplicate + not listed",
        (true, false) => "duplicate",
        _ => "not listed",
    };
    let label = format!("{what}: {}", cats.join(", "));
    spawn_bulk(server, files, cats.iter().map(|c| c.to_string()).collect(), label, "bulk")
}

/// Upper bound of the bulk-rescan workers.
const MAX_RESCAN_THREADS: usize = 4;

/// Bulk-rescan workers: half the cores (the other half stays with the client scans),
/// 1..=MAX_RESCAN_THREADS.
fn rescan_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get() / 2).clamp(1, MAX_RESCAN_THREADS)
}

fn spawn_bulk(server: &Arc<ScanServer>, mut files: Vec<String>, cats: Vec<String>, label: String, source: &'static str) -> Result<usize, String> {
    // One rescan per SHA-256: two workers must not move the same file at once.
    let mut seen = std::collections::HashSet::new();
    files.retain(|f| seen.insert(f.to_ascii_uppercase()));
    let bulk = &server.rescan;
    if bulk.running.swap(true, Ordering::SeqCst) {
        return Err("a rescan is already running".into());
    }
    bulk.stop.store(false, Ordering::Relaxed);
    bulk.total.store(files.len(), Ordering::Relaxed);
    bulk.done.store(0, Ordering::Relaxed);
    bulk.changed.store(0, Ordering::Relaxed);
    bulk.failed.store(0, Ordering::Relaxed);
    *bulk.started_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
    *bulk.finished_at.lock().unwrap() = None;
    bulk.changes.lock().unwrap().clear();
    let run = bulk.run.fetch_add(1, Ordering::Relaxed) + 1;
    *bulk.categories.lock().unwrap() = cats;

    let n = files.len();
    let srv = Arc::clone(server);
    let spawned = std::thread::Builder::new()
        .name("bulk-rescan".into())
        .spawn(move || {
            let bulk = &srv.rescan;
            let next = AtomicUsize::new(0);
            let files = &files;
            std::thread::scope(|s| {
                for i in 0..rescan_threads().min(files.len().max(1)) {
                    let (srv, next) = (&srv, &next);
                    let worker = std::thread::Builder::new()
                        .name(format!("bulk-rescan-{i}"))
                        .stack_size(64 * 1024 * 1024)
                        .spawn_scoped(s, move || loop {
                            if bulk.stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let Some(sha) = files.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                            match rescan_logged(srv, sha, source, run) {
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
                        });
                    if let Err(e) = worker {
                        srv.log_info(format!("bulk rescan: cannot start worker {i}: {e}"));
                    }
                }
            });
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
    server.log_info(format!("bulk rescan started: {n} kept files ({label})"));
    Ok(n)
}
