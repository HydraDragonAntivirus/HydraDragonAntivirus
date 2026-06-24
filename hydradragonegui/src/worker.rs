//! Background worker: owns the `Pipeline`, loads engines, and streams scan results
//! to the UI over a channel (mirrors the Win32 GUI's worker-thread architecture,
//! but with channels + shared atomics instead of `PostMessageW`).
//!
//! Two atomics drive cancellation, exactly like the Win32 GUI:
//!   * `pause`  — break the file loop but KEEP the remaining queue for Resume.
//!   * `abort`  — break the file loop and DISCARD the session (Stop).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;

use hydradragonav::pipeline::{Pipeline, PipelineConfig};
use hydradragonav::verdict::{ScanResult, Verdict};

// Scan-category bitmask (matches the Win32 GUI's CAT_* constants).
pub const CAT_REGISTRY: u8 = 0x01;
pub const CAT_MEMORY: u8 = 0x02;
pub const CAT_SIGMA: u8 = 0x04;
pub const CAT_STARTUP: u8 = 0x10;
pub const CAT_BOOT: u8 = 0x20;
pub const CAT_PUM: u8 = 0x40;

/// Engine lifecycle for the UI's loading indicator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EnginePhase {
    Idle,
    Loading,
    Ready,
    Stopped,
}

/// UI → worker commands.
pub enum ToWorker {
    /// Scan these file paths, then run the selected extra-category phases (bitmask).
    Scan { paths: Vec<PathBuf>, cats: u8 },
    /// Continue a paused scan from its remaining queue.
    Resume,
    /// Re-scan specific files uncached (bypasses the result cache).
    Rescan(Vec<PathBuf>),
    /// Disinfect / quarantine these files and remove their traces.
    Clean(Vec<PathBuf>),
    /// Load the engines (after a Stop Engine).
    StartEngine,
    /// Drop the pipeline to free memory.
    StopEngine,
    /// Rebuild the pipeline with a new config.
    Reload(PipelineConfig),
    /// Wipe the persisted result caches.
    ClearCache,
    /// Terminate the worker thread.
    Shutdown,
}

/// Worker → UI messages.
pub enum ToUi {
    EngineLoading,
    Loaded { signatures: usize },
    EngineStopped,
    Progress { scanned: usize, threats: usize, current: String },
    Detection(Box<ResultRow>),
    /// A rescanned file: `row` is `None` when it is now clean (drop it from the list).
    Rescanned { path: String, row: Option<Box<ResultRow>> },
    Cleaned { path: String, outcome: String },
    ScanDone { scanned: usize, threats: usize },
    Paused { scanned: usize, threats: usize, remaining: usize },
    Stopped,
    Status(String),
    Error(String),
}

/// One detection row shown in the results list. Severity (0–100) drives the colour.
#[derive(Clone)]
pub struct ResultRow {
    pub path: String,
    pub verdict: Verdict,
    pub threat: String,
    pub detail: String,
    pub sev: u8,
    pub elapsed_ms: u64,
    /// "File" / "Registry" / "Memory" / "Sigma" / "Startup" / "Boot" / "PUM".
    pub category: &'static str,
    /// Only real on-disk files can be disinfected.
    pub cleanable: bool,
    /// UI-side checkbox state (worker always sets this `true` so Clean-All works).
    pub checked: bool,
}

/// Verdict → severity score (matches the Win32 GUI's mapping).
pub fn verdict_severity(v: Verdict) -> u8 {
    match v.priority() {
        0 | 1 => 0,
        2 => 30,
        3 => 50,
        4 => 75,
        _ => 100,
    }
}

/// True when a verdict is a real detection (priority > 1).
pub fn is_threat(v: Verdict) -> bool {
    v.priority() > 1
}

impl ResultRow {
    pub fn from_scan(path: &Path, r: &ScanResult) -> Self {
        let mut parts: Vec<String> = r
            .engines
            .iter()
            .filter(|e| is_threat(e.verdict) && !e.detail.is_empty())
            .map(|e| format!("{}: {}", e.engine, e.detail))
            .collect();
        if let Some(p) = r.ml_malware_probability {
            parts.push(format!("ml p={p:.3}"));
        }
        let detail = if parts.is_empty() {
            r.threat_name.clone().unwrap_or_default()
        } else {
            parts.join("  |  ")
        };
        ResultRow {
            path: path.display().to_string(),
            verdict: r.verdict,
            threat: r.threat_name.clone().unwrap_or_else(|| r.verdict.label().to_string()),
            detail,
            sev: verdict_severity(r.verdict),
            elapsed_ms: r.engines.iter().filter_map(|e| e.elapsed_ms).sum(),
            category: "File",
            cleanable: true,
            checked: true,
        }
    }
}

/// A paused/in-progress scan session kept between Pause and Resume.
struct Session {
    queue: VecDeque<PathBuf>,
    cats: u8,
    scanned: usize,
    threats: usize,
    files_done: bool, // file phase finished — only category phases remain.
}

/// Worker entry point. Builds the pipeline, then services requests until Shutdown.
pub fn run(
    mut config: PipelineConfig,
    rx: Receiver<ToWorker>,
    to_ui: Sender<ToUi>,
    pause: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
) {
    let _ = to_ui.send(ToUi::EngineLoading);
    let mut pipeline: Option<Pipeline> = Some(Pipeline::new(config.clone()));
    let _ = to_ui.send(ToUi::Loaded {
        signatures: pipeline.as_ref().map_or(0, Pipeline::loaded_signature_count),
    });

    let mut session: Option<Session> = None;

    while let Ok(req) = rx.recv() {
        match req {
            ToWorker::Scan { paths, cats } => {
                pause.store(false, Ordering::SeqCst);
                abort.store(false, Ordering::SeqCst);
                session = Some(Session {
                    queue: paths.into_iter().collect(),
                    cats,
                    scanned: 0,
                    threats: 0,
                    files_done: false,
                });
                run_scan(pipeline.as_ref(), &config, &mut session, &to_ui, &pause, &abort);
            }
            ToWorker::Resume => {
                pause.store(false, Ordering::SeqCst);
                abort.store(false, Ordering::SeqCst);
                if session.is_some() {
                    run_scan(pipeline.as_ref(), &config, &mut session, &to_ui, &pause, &abort);
                }
            }
            ToWorker::Rescan(paths) => {
                if let Some(pl) = pipeline.as_ref() {
                    for path in paths {
                        let r = pl.scan_file(&path);
                        let row = if is_threat(r.verdict) {
                            Some(Box::new(ResultRow::from_scan(&path, &r)))
                        } else {
                            None
                        };
                        let _ = to_ui.send(ToUi::Rescanned {
                            path: path.display().to_string(),
                            row,
                        });
                    }
                    let _ = to_ui.send(ToUi::Status("Rescan complete.".into()));
                }
            }
            ToWorker::Clean(paths) => {
                clean_files(pipeline.as_ref(), &config, &paths, &to_ui);
            }
            ToWorker::StartEngine => {
                if pipeline.is_none() {
                    let _ = to_ui.send(ToUi::EngineLoading);
                    pipeline = Some(Pipeline::new(config.clone()));
                    let _ = to_ui.send(ToUi::Loaded {
                        signatures: pipeline.as_ref().map_or(0, Pipeline::loaded_signature_count),
                    });
                }
            }
            ToWorker::StopEngine => {
                if let Some(pl) = pipeline.as_ref() {
                    pl.save_result_caches();
                }
                pipeline = None;
                session = None;
                let _ = to_ui.send(ToUi::EngineStopped);
            }
            ToWorker::Reload(new_cfg) => {
                config = new_cfg;
                let _ = to_ui.send(ToUi::EngineLoading);
                pipeline = Some(Pipeline::new(config.clone()));
                let _ = to_ui.send(ToUi::Loaded {
                    signatures: pipeline.as_ref().map_or(0, Pipeline::loaded_signature_count),
                });
            }
            ToWorker::ClearCache => {
                if let Some(pl) = pipeline.as_mut() {
                    pl.clear_result_caches();
                }
                let _ = to_ui.send(ToUi::Status("Result cache cleared.".into()));
            }
            ToWorker::Shutdown => break,
        }
    }
}

/// Drive the file queue, then run the selected category phases. Honors `pause`/`abort`.
fn run_scan(
    pipeline: Option<&Pipeline>,
    config: &PipelineConfig,
    session: &mut Option<Session>,
    to_ui: &Sender<ToUi>,
    pause: &Arc<AtomicBool>,
    abort: &Arc<AtomicBool>,
) {
    let Some(pl) = pipeline else {
        let _ = to_ui.send(ToUi::Error("engines not loaded".into()));
        *session = None;
        return;
    };
    let Some(sess) = session.as_mut() else { return };

    let mut last_tick = Instant::now();
    if !sess.files_done {
        while let Some(path) = sess.queue.pop_front() {
            if abort.load(Ordering::SeqCst) {
                let _ = to_ui.send(ToUi::Stopped);
                *session = None;
                return;
            }
            if pause.load(Ordering::SeqCst) {
                let _ = to_ui.send(ToUi::Paused {
                    scanned: sess.scanned,
                    threats: sess.threats,
                    remaining: sess.queue.len(),
                });
                return;
            }
            let r = pl.scan_file_cached(&path);
            sess.scanned += 1;
            if is_threat(r.verdict) {
                sess.threats += 1;
                let _ = to_ui.send(ToUi::Detection(Box::new(ResultRow::from_scan(&path, &r))));
            }
            if last_tick.elapsed().as_millis() >= 150 {
                let _ = to_ui.send(ToUi::Progress {
                    scanned: sess.scanned,
                    threats: sess.threats,
                    current: path.display().to_string(),
                });
                last_tick = Instant::now();
            }
        }
        sess.files_done = true;
        pl.save_result_caches();
    }

    // Extra category phases (only meaningful for a full custom scan).
    if sess.cats != 0 && !abort.load(Ordering::SeqCst) {
        run_categories(pl, config, sess, to_ui, abort);
    }

    let _ = to_ui.send(ToUi::ScanDone {
        scanned: sess.scanned,
        threats: sess.threats,
    });
    *session = None;
}

/// Severity (0–100) for a category row, from a verdict.
fn sev_of(v: Verdict) -> u8 {
    verdict_severity(v)
}

fn emit_row(to_ui: &Sender<ToUi>, sess: &mut Session, row: ResultRow) {
    sess.threats += 1;
    let _ = to_ui.send(ToUi::Detection(Box::new(row)));
}

/// Run the registry / memory / sigma / startup / boot / PUM phases per the bitmask.
fn run_categories(
    pl: &Pipeline,
    config: &PipelineConfig,
    sess: &mut Session,
    to_ui: &Sender<ToUi>,
    abort: &Arc<AtomicBool>,
) {
    use hydradragonav::{boot_scanner, memory_scanner, registry_scanner, startup_scanner};

    let stop = |to_ui: &Sender<ToUi>| {
        let _ = to_ui.send(ToUi::Stopped);
    };

    if sess.cats & (CAT_REGISTRY | CAT_PUM) != 0 {
        let _ = to_ui.send(ToUi::Status("Scanning registry…".into()));
        let result = registry_scanner::RegistryScanner::default().scan();
        for e in &result.entries {
            if abort.load(Ordering::SeqCst) {
                return stop(to_ui);
            }
            let want_pum = sess.cats & CAT_PUM != 0;
            let want_reg = sess.cats & CAT_REGISTRY != 0;
            if (e.pum && !want_pum) || (!e.pum && !want_reg) {
                continue;
            }
            let verdict = if e.static_match {
                Verdict::Malware
            } else if e.pua_match {
                Verdict::Pua
            } else {
                Verdict::Suspicious
            };
            let threat = e.threat_name.clone().unwrap_or_else(|| {
                if e.pum { "PUM".into() } else { "Registry".into() }
            });
            emit_row(
                to_ui,
                sess,
                ResultRow {
                    path: format!("{}\\{}\\{}", e.hive, e.path, e.value_name),
                    verdict,
                    threat,
                    detail: e.detail.clone(),
                    sev: sev_of(verdict),
                    elapsed_ms: 0,
                    category: if e.pum { "PUM" } else { "Registry" },
                    cleanable: false,
                    checked: true,
                },
            );
        }
    }

    if sess.cats & CAT_MEMORY != 0 {
        if abort.load(Ordering::SeqCst) {
            return stop(to_ui);
        }
        let _ = to_ui.send(ToUi::Status("Scanning process memory…".into()));
        for d in memory_scanner::scan_process_memory(pl) {
            emit_row(
                to_ui,
                sess,
                ResultRow {
                    path: format!("{} (pid {})", d.process, d.pid),
                    verdict: d.verdict,
                    threat: d.threat_name.clone(),
                    detail: format!("addr 0x{:x}, {} bytes", d.address, d.region_size),
                    sev: sev_of(d.verdict),
                    elapsed_ms: 0,
                    category: "Memory",
                    cleanable: false,
                    checked: true,
                },
            );
        }
    }

    if sess.cats & CAT_SIGMA != 0 {
        if abort.load(Ordering::SeqCst) {
            return stop(to_ui);
        }
        if let Some(dir) = config.hayabusa_dir.as_ref() {
            let _ = to_ui.send(ToUi::Status("Scanning event logs (Sigma)…".into()));
            for m in hydradragonav::pipeline::scan_hayabusa_once(dir) {
                if m.severity < 65 {
                    continue;
                }
                let verdict = if m.severity >= 80 { Verdict::Malware } else { Verdict::Suspicious };
                emit_row(
                    to_ui,
                    sess,
                    ResultRow {
                        path: m.channel.clone(),
                        verdict,
                        threat: m.title.clone(),
                        detail: format!("sigma severity {}", m.severity),
                        sev: m.severity,
                        elapsed_ms: 0,
                        category: "Sigma",
                        cleanable: false,
                        checked: true,
                    },
                );
            }
        }
    }

    if sess.cats & CAT_STARTUP != 0 {
        if abort.load(Ordering::SeqCst) {
            return stop(to_ui);
        }
        let _ = to_ui.send(ToUi::Status("Scanning startup objects…".into()));
        for d in startup_scanner::scan_startup_objects() {
            emit_row(
                to_ui,
                sess,
                ResultRow {
                    path: d.command.clone(),
                    verdict: Verdict::Suspicious,
                    threat: d.name.clone(),
                    detail: format!("{}: {}", d.source, d.detail),
                    sev: sev_of(Verdict::Suspicious),
                    elapsed_ms: 0,
                    category: "Startup",
                    cleanable: false,
                    checked: true,
                },
            );
        }
    }

    if sess.cats & CAT_BOOT != 0 {
        if abort.load(Ordering::SeqCst) {
            return stop(to_ui);
        }
        let _ = to_ui.send(ToUi::Status("Scanning boot sectors…".into()));
        for d in boot_scanner::scan_boot_sectors() {
            emit_row(
                to_ui,
                sess,
                ResultRow {
                    path: d.device.clone(),
                    verdict: Verdict::Suspicious,
                    threat: d.sector_type.clone(),
                    detail: d.details.clone(),
                    sev: sev_of(Verdict::Suspicious),
                    elapsed_ms: 0,
                    category: "Boot",
                    cleanable: false,
                    checked: true,
                },
            );
        }
    }
}

/// Disinfect/quarantine the given files and remove their on-disk/registry traces.
fn clean_files(pipeline: Option<&Pipeline>, config: &PipelineConfig, paths: &[PathBuf], to_ui: &Sender<ToUi>) {
    use hydradragonav::{disinfector, remediation};

    let Some(pl) = pipeline else {
        let _ = to_ui.send(ToUi::Error("engines not loaded".into()));
        return;
    };
    let quar_dir = quarantine_dir(config);

    for path in paths {
        let arenas = pl.arenas_for_file(path);
        let outcome = disinfector::disinfect_file(path, &arenas, &quar_dir);
        let summary = match outcome {
            disinfector::DisinfectOutcome::Neutralized { bytes, .. } => {
                format!("neutralized ({bytes} bytes zeroed)")
            }
            disinfector::DisinfectOutcome::Quarantined { to } => {
                format!("quarantined → {}", to.display())
            }
            disinfector::DisinfectOutcome::Failed { reason } => format!("FAILED: {reason}"),
        };

        // Best-effort trace removal (registry autoruns, services, tasks, …).
        let traces = remediation::find_traces(path);
        let mut applied = 0usize;
        for t in &traces {
            if remediation::apply(t, &quar_dir).is_ok() {
                applied += 1;
            }
        }
        let detail = if applied > 0 {
            format!("{summary}; {applied} trace(s) removed")
        } else {
            summary
        };
        let _ = to_ui.send(ToUi::Cleaned {
            path: path.display().to_string(),
            outcome: detail,
        });
    }
    let _ = to_ui.send(ToUi::Status("Clean complete.".into()));
}

/// The quarantine directory: `<results_cache_dir>/quarantine`, else `./quarantine`.
pub fn quarantine_dir(config: &PipelineConfig) -> PathBuf {
    config
        .results_cache_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("quarantine")
}
