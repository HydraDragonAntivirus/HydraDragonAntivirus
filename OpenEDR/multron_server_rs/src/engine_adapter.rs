use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use openedr_static::engine::StaticEngine;
use openedr_static::report::StaticScanReport;
use serde::{Deserialize, Serialize};

pub const ENGINE_NAME: &str = "OpenEDR static";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMessage {
    pub r#type: String, // "result"
    pub id: i64,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub score: f64,
    pub sha256: String,
    pub scan_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub status: String, // "loading" | "ready" | "error"
    pub error: String,
    pub load_ms: i64,
    pub name: String,
}

pub struct EngineAdapter {
    engine: RwLock<Option<Arc<StaticEngine>>>,
    status: RwLock<String>,
    error_msg: RwLock<String>,
    load_ms: AtomicI64,
    work_dir: Option<PathBuf>,
    file_seq: AtomicI64,
}

impl EngineAdapter {
    pub fn new(work_dir: Option<PathBuf>) -> Arc<Self> {
        if let Some(ref dir) = work_dir {
            let _ = std::fs::create_dir_all(dir);
            remove_leftover_uploads(dir);
        }

        Arc::new(Self {
            engine: RwLock::new(None),
            status: RwLock::new("loading".to_string()),
            error_msg: RwLock::new(String::new()),
            load_ms: AtomicI64::new(0),
            work_dir,
            file_seq: AtomicI64::new(0),
        })
    }

    pub fn start_loading(self: &Arc<Self>, custom_rules_dir: Option<PathBuf>) {
        let adapter = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let rules_dir = resolve_rules_dir(custom_rules_dir);
            eprintln!("[engine] loading from: {}", rules_dir.display());

            let engine = StaticEngine::init(&rules_dir);
            let elapsed = started.elapsed().as_millis() as i64;
            adapter.load_ms.store(elapsed, Ordering::Relaxed);

            let engine_arc = Arc::new(engine);

            tokio::spawn(async move {
                let mut eng_lock = adapter.engine.write().await;
                *eng_lock = Some(engine_arc);
                let mut st_lock = adapter.status.write().await;
                *st_lock = "ready".to_string();
            });

            eprintln!("[engine] ready in {} ms", elapsed);
        });
    }

    pub async fn is_ready(&self) -> bool {
        self.status.read().await.as_str() == "ready"
    }

    pub async fn get_status(&self) -> EngineStatus {
        EngineStatus {
            status: self.status.read().await.clone(),
            error: self.error_msg.read().await.clone(),
            load_ms: self.load_ms.load(Ordering::Relaxed),
            name: ENGINE_NAME.to_string(),
        }
    }

    pub async fn scan(&self, data: &[u8], name: &str, sha: &str) -> Result<ResultMessage, String> {
        let engine_arc = {
            let guard = self.engine.read().await;
            guard.clone().ok_or_else(|| "engine not ready".to_string())?
        };

        let started = Instant::now();
        let safe_filename = file_system_name(name);

        // Attempt scan via temporary file if work_dir is configured (allows Authenticode signature verification)
        let report = if let Some(ref dir) = self.work_dir {
            let seq = self.file_seq.fetch_add(1, Ordering::Relaxed);
            let filename = format!("{:08}_{}", seq, safe_filename);
            let path = dir.join(filename);

            let file_scan_res = if std::fs::write(&path, data).is_ok() {
                let rep = engine_arc.scan_file(&path);
                let _ = std::fs::remove_file(&path);
                Some(rep)
            } else {
                None
            };

            match file_scan_res {
                Some(r) if !r.verdict.eq_ignore_ascii_case("Error") => r,
                _ => engine_arc.scan_bytes(data, name),
            }
        } else {
            engine_arc.scan_bytes(data, name)
        };

        if report.verdict.eq_ignore_ascii_case("Error") {
            let err_msg = report
                .detections
                .first()
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "unknown engine error".to_string());
            return Err(err_msg);
        }

        let mut res = build_result(&report, sha);
        res.scan_ms = started.elapsed().as_millis() as i64;
        Ok(res)
    }
}

fn build_result(report: &StaticScanReport, sha: &str) -> ResultMessage {
    let raw_verdict = report.verdict.to_lowercase();
    let verdict = match raw_verdict.as_str() {
        "clean" | "malicious" | "suspicious" | "unknown" => raw_verdict,
        _ => "unknown".to_string(),
    };

    let mut res = ResultMessage {
        r#type: "result".to_string(),
        id: 0,
        verdict,
        threat: None,
        detail: None,
        score: report.max_threat_score as f64,
        sha256: sha.to_string(),
        scan_ms: report.scan_time_ms as i64,
    };

    if !report.detections.is_empty() {
        res.threat = Some(report.detections[0].name.clone());
        let details: Vec<String> = report
            .detections
            .iter()
            .map(|d| format!("{} ({})", d.name, d.layer))
            .collect();
        res.detail = Some(details.join(", "));
    } else if let Some(ref signer) = report.signer_info {
        if signer.is_trusted {
            if let Some(ref name) = signer.signer_name {
                res.detail = Some(format!("Signed by {}", name));
            }
        }
    }

    res
}

fn resolve_rules_dir(custom: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = custom {
        if dir.is_dir() {
            return dir;
        }
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.to_path_buf());
            candidates.push(parent.join("rules"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.clone());
        candidates.push(cwd.join("OpenEDR"));
    }

    candidates.push(PathBuf::from(r"C:\Users\semae\Downloads\OpenMalwareScannerPortable"));
    candidates.push(PathBuf::from(r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\OpenEDR"));

    for c in &candidates {
        if c.join("database").is_dir() || c.join("yara_rules").is_dir() || c.join("models").is_dir() {
            return c.clone();
        }
    }

    PathBuf::from(".")
}

fn remove_leftover_uploads(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.len() >= 9 && name.chars().take(8).all(|c| c.is_ascii_digit()) && name.chars().nth(8) == Some('_') {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

pub fn file_system_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            _ => c,
        })
        .collect()
}
