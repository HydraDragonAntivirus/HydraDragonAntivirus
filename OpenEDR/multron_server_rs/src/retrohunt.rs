//! Retrohunt for analyst signatures (like VirusTotal Retrohunt): when a signature is
//! saved in the signature room, every file kept in the work folder (multron_incoming,
//! all categories) is matched against that one signature. Each match is then rescanned
//! with the full engine and the current settings (`rescan::rescan_logged`), so the
//! verdict, the threat name, the TLSH rules and a human verdict apply as for a client
//! scan.
//!
//! On the archive server (read-only, no engine) a hunt only matches: the analyst
//! picks a rule in the signature room and every file of the mirrored work folder is
//! matched against it; nothing is rescanned or written, the current verdict is shown.
//!
//! Hunts run one at a time on a background thread; inside a hunt the files are
//! shared out to `hunt_threads()` workers (one core is left to the live scans).
//! Signatures saved while a hunt runs wait in the queue. The newest `HISTORY` hunts are kept in
//! memory for the dashboard.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use hydradragonclamav::scanner::{Engine as ClamEngine, ScanOptions as ClamScanOptions};
use hydradragonsig::models::{MemoryScanContext, Verdict as SigVerdict};
use hydradragonsig::rules::RuleSet;

use crate::analyst_engine::SigKind;
use crate::scan_server::ScanServer;

const HISTORY: usize = 20;
/// Matches kept per hunt (the count goes on).
const MATCHES_MAX: usize = 2000;
const YARA_TIMEOUT: Duration = Duration::from_secs(20);
/// Upper bound of the workers of one hunt.
const MAX_HUNT_THREADS: usize = 8;

/// Workers of one hunt: the cores minus one for the live scans, 1..=MAX_HUNT_THREADS.
fn hunt_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1)).clamp(1, MAX_HUNT_THREADS)
}

#[derive(Debug, Clone, Serialize)]
pub struct HuntMatch {
    pub sha256: String,
    pub file_name: String,
    /// Folder the file was in when it matched.
    pub category: &'static str,
    pub size: u64,
    /// Rule / signature name that matched.
    pub rule: String,
    pub old_verdict: String,
    /// Verdict after the full rescan; empty when the rescan failed.
    pub new_verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hunt {
    pub id: u64,
    pub kind: &'static str,
    pub name: String,
    /// "queued", "running", "done", "stopped" or "error".
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// Distinct kept files (by SHA-256).
    pub total: usize,
    pub done: usize,
    pub matched: usize,
    /// Matches whose verdict changed after the rescan.
    pub changed: usize,
    /// Kept files that could not be read.
    pub unreadable: usize,
    /// Archive server: matched only, not rescanned.
    pub match_only: bool,
    pub matches: Vec<HuntMatch>,
}

struct Job {
    id: u64,
    kind: SigKind,
    source: String,
    /// Rescan each match with the full engine (false on the archive server).
    rescan: bool,
}

#[derive(Default)]
pub struct RetroHunt {
    hunts: Mutex<VecDeque<Hunt>>,
    queue: Mutex<VecDeque<Job>>,
    worker: AtomicBool,
    stop: AtomicBool,
    next_id: AtomicU64,
}

/// One signature document compiled on its own.
enum Matcher {
    Yara(yara_x::Rules),
    Clam(ClamEngine),
    Sig(RuleSet),
}

impl Matcher {
    fn build(kind: SigKind, source: &str) -> Result<Self, String> {
        match kind {
            SigKind::Yara => {
                let mut c = yara_x::Compiler::new();
                c.add_source(source).map_err(|e| e.to_string())?;
                Ok(Matcher::Yara(c.build()))
            }
            SigKind::ClamNdb | SigKind::ClamLdb => {
                let mut files = std::collections::HashMap::new();
                files.insert(format!("retrohunt.{}", kind.ext()), source.as_bytes().to_vec());
                let (engine, report) = ClamEngine::from_bytes_map(&files);
                if report.extended_loaded + report.logical_loaded + report.db_loaded == 0 {
                    return Err("hydradragonclamav loaded no signature".into());
                }
                Ok(Matcher::Clam(engine))
            }
            SigKind::HydraSig => RuleSet::from_yaml_str(source).map(Matcher::Sig).map_err(|e| format!("{e:#}")),
        }
    }

    /// Names of the matching rules (empty = no match). Takes the file by value:
    /// HydraDragonSig scans an owned buffer, so it is moved in, not copied.
    fn scan(&self, yara: &mut Option<yara_x::Scanner<'_>>, data: Vec<u8>, name: &str) -> Vec<String> {
        match self {
            Matcher::Yara(_) => {
                let Some(sc) = yara.as_mut() else { return Vec::new() };
                match sc.scan(&data) {
                    Ok(r) => r.matching_rules().map(|m| m.identifier().to_string()).collect(),
                    Err(_) => Vec::new(),
                }
            }
            Matcher::Clam(engine) => engine
                .scan_bytes_named(&data, if name.is_empty() { "file" } else { name }, ClamScanOptions::default(), &[])
                .into_iter()
                .map(|m| m.name)
                .collect(),
            Matcher::Sig(rules) => {
                let ctx = MemoryScanContext { buffer: data, identifier: name.to_string(), base_address: None };
                match hydradragonsig::scan_memory_owned(ctx, rules, &hydradragonsig::ScanOptions::default()) {
                    Ok(r) if matches!(r.verdict, SigVerdict::Malware | SigVerdict::Pua | SigVerdict::Suspicious) => {
                        vec![r.threat_name.unwrap_or_else(|| "HydraDragonSig rule".into())]
                    }
                    _ => Vec::new(),
                }
            }
        }
    }
}

impl RetroHunt {
    pub fn status(&self) -> serde_json::Value {
        let hunts: Vec<Hunt> = self.hunts.lock().unwrap().iter().cloned().collect();
        serde_json::json!({ "ok": true, "active": hunts.iter().any(|h| h.state == "running" || h.state == "queued"), "hunts": hunts })
    }

    /// Stops the running hunt and drops the queued ones.
    pub fn stop_all(&self) {
        self.stop.store(true, Ordering::Relaxed);
        let dropped: Vec<u64> = self.queue.lock().unwrap().drain(..).map(|j| j.id).collect();
        self.update_many(&dropped, |h| {
            h.state = "stopped";
            h.finished_at = Some(now());
        });
    }

    fn update(&self, id: u64, f: impl FnOnce(&mut Hunt)) {
        if let Some(h) = self.hunts.lock().unwrap().iter_mut().find(|h| h.id == id) {
            f(h);
        }
    }

    fn update_many(&self, ids: &[u64], f: impl Fn(&mut Hunt)) {
        for h in self.hunts.lock().unwrap().iter_mut().filter(|h| ids.contains(&h.id)) {
            f(h);
        }
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Queues a retrohunt for one saved signature document and starts the worker if it is
/// idle. Returns the hunt number.
pub fn start(server: &Arc<ScanServer>, kind: SigKind, name: &str, source: &str) -> u64 {
    start_with(server, kind, name, source, true)
}

/// Archive server: a hunt that only matches (no engine, nothing written).
pub fn start_match_only(server: &Arc<ScanServer>, kind: SigKind, name: &str, source: &str) -> u64 {
    start_with(server, kind, name, source, false)
}

fn start_with(server: &Arc<ScanServer>, kind: SigKind, name: &str, source: &str, rescan: bool) -> u64 {
    let rh = &server.retrohunt;
    let id = rh.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    {
        let mut hunts = rh.hunts.lock().unwrap();
        hunts.push_front(Hunt {
            id,
            kind: kind.id(),
            name: name.to_string(),
            state: "queued",
            error: None,
            queued_at: now(),
            started_at: None,
            finished_at: None,
            total: 0,
            done: 0,
            matched: 0,
            changed: 0,
            unreadable: 0,
            match_only: !rescan,
            matches: Vec::new(),
        });
        // Drop the oldest finished hunts beyond the history size.
        while hunts.len() > HISTORY {
            match hunts.iter().rposition(|h| h.state != "running" && h.state != "queued") {
                Some(i) => {
                    hunts.remove(i);
                }
                None => break,
            }
        }
    }
    rh.queue.lock().unwrap().push_back(Job { id, kind, source: source.to_string(), rescan });
    if !rh.worker.swap(true, Ordering::SeqCst) {
        let srv = Arc::clone(server);
        let spawned = std::thread::Builder::new()
            .name("retrohunt".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(move || worker(srv));
        if let Err(e) = spawned {
            rh.worker.store(false, Ordering::SeqCst);
            rh.update(id, |h| {
                h.state = "error";
                h.error = Some(format!("cannot start the retrohunt thread: {e}"));
            });
        }
    }
    id
}

fn worker(srv: Arc<ScanServer>) {
    let rh = &srv.retrohunt;
    loop {
        let job = rh.queue.lock().unwrap().pop_front();
        let Some(job) = job else {
            rh.worker.store(false, Ordering::SeqCst);
            // A job queued between the pop and the flag reset would wait forever.
            if rh.queue.lock().unwrap().is_empty() || rh.worker.swap(true, Ordering::SeqCst) {
                return;
            }
            continue;
        };
        rh.stop.store(false, Ordering::Relaxed);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&srv, &job)));
        if r.is_err() {
            rh.update(job.id, |h| {
                h.state = "error";
                h.error = Some("the retrohunt panicked".into());
                h.finished_at = Some(now());
            });
        }
    }
}

fn run(srv: &Arc<ScanServer>, job: &Job) {
    let rh = &srv.retrohunt;
    rh.update(job.id, |h| {
        h.state = "running";
        h.started_at = Some(now());
    });
    let matcher = match Matcher::build(job.kind, &job.source) {
        Ok(m) => m,
        Err(e) => {
            rh.update(job.id, |h| {
                h.state = "error";
                h.error = Some(e);
                h.finished_at = Some(now());
            });
            return;
        }
    };

    // One entry per SHA-256 (a duplicate is the same file in another folder).
    let mut seen = HashSet::new();
    let files: Vec<_> = srv.engine.list_kept().into_iter().filter(|k| seen.insert(k.sha256.to_ascii_uppercase())).collect();
    let name = rh.hunts.lock().unwrap().iter().find(|h| h.id == job.id).map(|h| h.name.clone()).unwrap_or_default();
    let threads = hunt_threads().min(files.len().max(1));
    srv.log_info(format!(
        "retrohunt #{} started: {} {name} over {} kept files, {threads} thread(s)",
        job.id,
        job.kind.id(),
        files.len()
    ));
    rh.update(job.id, |h| h.total = files.len());

    let next = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                // YARA-X scanners are per thread; the compiled rules are shared.
                let mut yara = match &matcher {
                    Matcher::Yara(rules) => {
                        let mut sc = yara_x::Scanner::new(rules);
                        sc.set_timeout(YARA_TIMEOUT);
                        Some(sc)
                    }
                    _ => None,
                };
                loop {
                    if rh.stop.load(Ordering::Relaxed) {
                        stopped.store(true, Ordering::Relaxed);
                        break;
                    }
                    let Some(k) = files.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                    hunt_file(srv, job, &matcher, &mut yara, k);
                }
            });
        }
    });
    let stopped = stopped.into_inner();
    let mut summary = String::new();
    rh.update(job.id, |h| {
        h.state = if stopped { "stopped" } else { "done" };
        h.finished_at = Some(now());
        summary = if h.match_only {
            format!("{} of {} files, {} matched (match only)", h.done, h.total, h.matched)
        } else {
            format!("{} of {} files, {} matched, {} verdicts changed", h.done, h.total, h.matched, h.changed)
        };
    });
    srv.log_info(format!("retrohunt #{} {}: {name}: {summary}", job.id, if stopped { "stopped" } else { "finished" }));
}

/// Matches one kept file and, on a match, rescans it and records it in the hunt.
fn hunt_file(
    srv: &Arc<ScanServer>,
    job: &Job,
    matcher: &Matcher,
    yara: &mut Option<yara_x::Scanner<'_>>,
    k: &crate::engine_adapter::KeptFile,
) {
    let rh = &srv.retrohunt;
    let Some(data) = k.read() else {
        rh.update(job.id, |h| {
            h.unreadable += 1;
            h.done += 1;
        });
        return;
    };
    let size = data.len() as u64;
    let hits = matcher.scan(yara, data, &k.name);
    if hits.is_empty() {
        rh.update(job.id, |h| h.done += 1);
        return;
    }
    let sha = k.sha256.to_ascii_lowercase();
    let old = srv.threat_intel.get(&sha).map(|i| i.verdict).unwrap_or_else(|| "unknown".into());
    let mut m = HuntMatch {
        sha256: sha.clone(),
        file_name: k.name.clone(),
        category: k.category,
        size,
        rule: hits.join(", "),
        old_verdict: old,
        new_verdict: String::new(),
        threat: None,
        detail: None,
        error: None,
    };
    if job.rescan {
        // Full engine with the current settings: the new signature is already live.
        match crate::rescan::rescan_logged(srv, &sha, "retrohunt", 0) {
            Ok(c) => {
                m.old_verdict = c.old_verdict;
                m.new_verdict = c.new_verdict;
                m.threat = c.threat;
                m.detail = c.detail;
            }
            Err(e) => m.error = Some(e),
        }
    } else {
        // Match only: the current verdict stays as it is.
        m.new_verdict = m.old_verdict.clone();
        m.threat = srv.threat_intel.get(&sha).and_then(|i| i.threat_name);
    }
    let changed = job.rescan && m.error.is_none() && m.old_verdict != m.new_verdict;
    rh.update(job.id, |h| {
        h.done += 1;
        h.matched += 1;
        h.changed += changed as usize;
        if h.matches.len() < MATCHES_MAX {
            h.matches.push(m);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_matcher_hits_only_matching_data() {
        let m = Matcher::build(SigKind::Yara, "rule Hunt_Test { strings: $a = \"RETROHUNT-MARK\" condition: $a }").unwrap();
        let Matcher::Yara(rules) = &m else { panic!() };
        let mut sc = Some(yara_x::Scanner::new(rules));
        assert_eq!(m.scan(&mut sc, b"xx RETROHUNT-MARK yy".to_vec(), "a"), vec!["Hunt_Test".to_string()]);
        assert!(m.scan(&mut sc, b"nothing here".to_vec(), "b").is_empty());
        assert!(Matcher::build(SigKind::Yara, "rule broken {").is_err());
    }

    #[test]
    fn clamav_ndb_matcher() {
        let hex: String = b"RETROHUNT-MARK".iter().map(|b| format!("{b:02x}")).collect();
        let m = Matcher::build(SigKind::ClamNdb, &format!("Trojan.Win32.Hunt.A:0:*:{hex}\n")).unwrap();
        let mut none = None;
        assert_eq!(m.scan(&mut none, b"xx RETROHUNT-MARK yy".to_vec(), "a.bin"), vec!["Trojan.Win32.Hunt.A".to_string()]);
        assert!(m.scan(&mut none, b"nothing here".to_vec(), "b.bin").is_empty());
    }

    #[test]
    fn clamav_ldb_matcher() {
        let h = |s: &[u8]| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let src = format!("Trojan.Win32.Hunt.B;Engine:51-255,Target:0;0&1;{};{}\n", h(b"FIRST-PART"), h(b"SECOND-PART"));
        let m = Matcher::build(SigKind::ClamLdb, &src).unwrap();
        let mut none = None;
        assert_eq!(m.scan(&mut none, b"a FIRST-PART b SECOND-PART c".to_vec(), "a.bin"), vec!["Trojan.Win32.Hunt.B".to_string()]);
        assert!(m.scan(&mut none, b"a FIRST-PART only".to_vec(), "b.bin").is_empty());
    }

    #[test]
    fn hydrasig_matcher() {
        let src = "rules:\n  - id: ANALYST-HUNT\n    title: \"Trojan.Win32.Hunt.C\"\n    severity: high\n    verdict: malware\n    confidence: 90\n    score: 90\n    family: \"Trojan.Win32.Hunt.C\"\n    logic: all\n    conditions:\n      - type: string_set\n        min: 2\n        nocase: true\n        values:\n          - \"first-unique-mark\"\n          - \"second-unique-mark\"\n";
        let m = Matcher::build(SigKind::HydraSig, src).unwrap();
        let mut none = None;
        assert_eq!(m.scan(&mut none, b"..FIRST-UNIQUE-MARK..second-unique-mark..".to_vec(), "a.bin"), vec!["Trojan.Win32.Hunt.C".to_string()]);
        assert!(m.scan(&mut none, b"..first-unique-mark only..".to_vec(), "b.bin").is_empty());
    }
}
