//! Background worker: owns the `Pipeline`, loads engines, and streams scan results
//! to the UI over a channel (mirrors the Win32 GUI's worker-thread architecture,
//! but with channels + a shared cancel flag instead of `PostMessageW`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;

use hydradragonav::pipeline::{Pipeline, PipelineConfig};
use hydradragonav::verdict::{ScanResult, Verdict};

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
    Scan(Vec<PathBuf>),
    Reload(PipelineConfig),
    ClearCache,
    Stop,
}

/// Worker → UI messages.
pub enum ToUi {
    Loaded { signatures: usize },
    Progress { file: String },
    Detection(Box<ResultRow>),
    ScanDone,
    Error(String),
}

/// One detection row shown in the results list. Severity (0–100) drives the colour.
pub struct ResultRow {
    pub path: String,
    pub verdict: Verdict,
    pub threat: String,
    pub detail: String,
    pub sev: u8,
    pub elapsed_ms: u64,
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
    pub fn from_scan(path: &std::path::Path, r: &ScanResult) -> Self {
        // Type/threat detail: join "engine: detail" for each flagging engine.
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
        }
    }
}

/// Worker entry point. Builds the pipeline (showing a loading state), then services
/// scan/cache/reload requests. `cancel` is polled between files to interrupt a scan.
pub fn run(
    mut config: PipelineConfig,
    rx: Receiver<ToWorker>,
    to_ui: Sender<ToUi>,
    cancel: Arc<AtomicBool>,
) {
    let mut pipeline = Pipeline::new(config.clone());
    let _ = to_ui.send(ToUi::Loaded { signatures: pipeline.loaded_signature_count() });

    while let Ok(req) = rx.recv() {
        match req {
            ToWorker::Scan(paths) => {
                cancel.store(false, Ordering::SeqCst);
                let mut last_tick = Instant::now();
                for path in paths {
                    if cancel.load(Ordering::SeqCst) {
                        break;
                    }
                    // Throttle progress updates (~every 200ms) to avoid flooding.
                    if last_tick.elapsed().as_millis() >= 200 {
                        let _ = to_ui.send(ToUi::Progress { file: path.display().to_string() });
                        last_tick = Instant::now();
                    }
                    let result = pipeline.scan_file_cached(&path);
                    if is_threat(result.verdict) {
                        let _ = to_ui.send(ToUi::Detection(Box::new(ResultRow::from_scan(&path, &result))));
                    }
                }
                let _ = to_ui.send(ToUi::ScanDone);
            }
            ToWorker::Reload(new_cfg) => {
                config = new_cfg;
                let _ = to_ui.send(ToUi::Progress { file: "reloading engines…".into() });
                pipeline = Pipeline::new(config.clone());
                let _ = to_ui.send(ToUi::Loaded { signatures: pipeline.loaded_signature_count() });
            }
            ToWorker::ClearCache => {
                pipeline.clear_result_caches();
                let _ = to_ui.send(ToUi::Progress { file: "result cache cleared".into() });
            }
            ToWorker::Stop => break,
        }
    }
}
