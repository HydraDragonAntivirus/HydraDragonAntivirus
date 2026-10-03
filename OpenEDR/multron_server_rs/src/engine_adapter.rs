use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use openedr_static::engine::StaticEngine;
use openedr_static::report::{ExtractedObject, StaticScanReport};
use serde::{Deserialize, Serialize};

use crate::cache::{parse_sha, Sha};

pub const ENGINE_NAME: &str = "OpenEDR static";

const EICAR_SHA256: &str = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

/// Optional hash signatures: one SHA-256 per line, optionally `SHA256:ThreatName`.
/// Looked up next to the exe and in the rules folder.
const MALICIOUS_HASH_FILES: &[&str] = &["malicious_sha256.txt", "hash_rules/malicious_sha256.txt"];

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
    /// How the verdict was found: "scan", "cache", "whitelist", "hash", "shared".
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extracted_objects: Vec<ExtractedObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub status: String, // "loading" | "ready" | "error"
    pub error: String,
    pub load_ms: i64,
    pub name: String,
}

pub struct EngineAdapter {
    engine: OnceLock<Arc<StaticEngine>>,
    error_msg: RwLock<String>,
    load_ms: AtomicI64,
    work_dir: Option<PathBuf>,
    file_seq: AtomicI64,
    malicious: RwLock<HashMap<Sha, String>>,
    whitelist_enabled: bool,
    keep_unknown: bool,
    keep_limit_bytes: u64,
    kept_bytes: AtomicU64,
    pub kept_files: AtomicI64,
}

impl EngineAdapter {
    pub fn new(
        work_dir: Option<PathBuf>,
        whitelist_enabled: bool,
        keep_unknown: bool,
        keep_unknown_gb: u64,
    ) -> Arc<Self> {
        let mut kept = (0u64, 0i64);
        if let Some(ref dir) = work_dir {
            let _ = std::fs::create_dir_all(dir);
            kept = remove_leftover_uploads(dir);
        }

        Arc::new(Self {
            engine: OnceLock::new(),
            error_msg: RwLock::new(String::new()),
            load_ms: AtomicI64::new(0),
            work_dir,
            file_seq: AtomicI64::new(0),
            malicious: RwLock::new(HashMap::new()),
            whitelist_enabled,
            keep_unknown,
            keep_limit_bytes: keep_unknown_gb * 1024 * 1024 * 1024,
            kept_bytes: AtomicU64::new(kept.0),
            kept_files: AtomicI64::new(kept.1),
        })
    }

    pub fn start_loading(self: &Arc<Self>, custom_rules_dir: Option<PathBuf>) {
        let adapter = Arc::clone(self);
        std::thread::Builder::new()
            .name("engine-load".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let started = Instant::now();
                let rules_dir = resolve_rules_dir(custom_rules_dir);
                eprintln!("[engine] loading from: {}", rules_dir.display());

                let mut dirs = vec![rules_dir.clone()];
                dirs.push(crate::config::app_dir());
                let hashes = load_malicious_hashes(&dirs);
                if !hashes.is_empty() {
                    eprintln!("[engine] {} malicious SHA-256 signatures loaded", hashes.len());
                }
                *adapter.malicious.write().unwrap() = hashes;

                match std::panic::catch_unwind(|| StaticEngine::init(&rules_dir)) {
                    Ok(engine) => {
                        let elapsed = started.elapsed().as_millis() as i64;
                        adapter.load_ms.store(elapsed, Ordering::Relaxed);
                        if adapter.whitelist_enabled && !engine.benign_whitelist_loaded() {
                            eprintln!("[engine] benign_sha256.xf not found, hash whitelist is off");
                        }
                        let _ = adapter.engine.set(Arc::new(engine));
                        eprintln!("[engine] ready in {} ms", elapsed);
                    }
                    Err(_) => {
                        *adapter.error_msg.write().unwrap() = "engine failed to load (panic in init)".into();
                        eprintln!("[engine] failed to load");
                    }
                }
            })
            .expect("cannot start engine loader");
    }

    pub fn ready(&self) -> bool {
        self.engine.get().is_some()
    }

    pub async fn is_ready(&self) -> bool {
        self.ready()
    }

    pub async fn get_status(&self) -> EngineStatus {
        let error = self.error_msg.read().unwrap().clone();
        let status = if self.ready() {
            "ready"
        } else if !error.is_empty() {
            "error"
        } else {
            "loading"
        };
        EngineStatus {
            status: status.to_string(),
            error,
            load_ms: self.load_ms.load(Ordering::Relaxed),
            name: ENGINE_NAME.to_string(),
        }
    }

    pub fn malicious_hash_count(&self) -> usize {
        self.malicious.read().unwrap().len()
    }

    pub fn whitelist_active(&self) -> bool {
        self.whitelist_enabled && self.engine.get().is_some_and(|e| e.benign_whitelist_loaded())
    }

    /// Verdict from the SHA-256 alone, without the file: hash signatures first (a
    /// malicious hit must win), then the engine's benign whitelist. None = upload needed.
    pub fn hash_lookup(&self, sha: &Sha, sha_hex: &str) -> Option<ResultMessage> {
        if sha_hex == EICAR_SHA256 {
            return Some(hash_result("malicious", Some("EICAR-Test-File"), "EICAR standard antivirus test file (hash)", 1.0, sha_hex, "hash"));
        }
        if let Some(name) = self.malicious.read().unwrap().get(sha) {
            return Some(hash_result("malicious", Some(name.as_str()), "Matched SHA-256 signature", 1.0, sha_hex, "hash"));
        }
        if self.whitelist_enabled {
            if let Some(engine) = self.engine.get() {
                if engine.is_benign(sha_hex) {
                    return Some(hash_result("clean", None, "Known benign file (whitelist)", 0.0, sha_hex, "whitelist"));
                }
            }
        }
        None
    }

    /// Runs on an engine thread. The file is written to the work folder first so the
    /// engine can check its Authenticode signature; it falls back to an in-memory scan.
    pub fn scan_blocking(&self, data: &[u8], name: &str, sha: &str) -> Result<ResultMessage, String> {
        let engine = self.engine.get().ok_or_else(|| "engine not ready".to_string())?;

        let started = Instant::now();
        let safe_filename = file_system_name(name);
        let mut temp_path: Option<PathBuf> = None;

        let report = if let Some(ref dir) = self.work_dir {
            let seq = self.file_seq.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("{:08}_{}", seq % 100_000_000, temp_name(&safe_filename, data)));
            let rep = if std::fs::write(&path, data).is_ok() {
                temp_path = Some(path.clone());
                Some(engine.scan_file(&path))
            } else {
                None
            };
            match rep {
                Some(r) if !r.verdict.eq_ignore_ascii_case("Error") => r,
                _ => engine.scan_bytes(data, name),
            }
        } else {
            engine.scan_bytes(data, name)
        };

        if report.verdict.eq_ignore_ascii_case("Error") {
            if let Some(p) = temp_path {
                let _ = std::fs::remove_file(p);
            }
            let err_msg = report
                .detections
                .first()
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "unknown engine error".to_string());
            return Err(err_msg);
        }

        let mut res = build_result(&report, sha);
        res.scan_ms = started.elapsed().as_millis() as i64;

        self.keep_or_remove(temp_path.as_deref(), data, &res, sha, &safe_filename);
        Ok(res)
    }

    /// Unknown files are kept in the work folder (multron_incoming) as `<SHA256>_<name>`
    /// for later analysis; everything else (clean, and malicious samples, which are never
    /// stored) is deleted. When the scan ran from memory the bytes are written directly.
    fn keep_or_remove(&self, temp: Option<&Path>, data: &[u8], res: &ResultMessage, sha: &str, name: &str) {
        let size = data.len() as u64;
        let keep = self.keep_unknown
            && res.verdict == "unknown"
            && !data.is_empty()
            && self.kept_bytes.load(Ordering::Relaxed) + size <= self.keep_limit_bytes;

        if keep {
            if let Some(dir) = &self.work_dir {
                let name = if name.is_empty() { "file" } else { name };
                let target = dir.join(format!("{}_{}", sha, name));
                let stored = if target.exists() {
                    false
                } else if let Some(p) = temp {
                    std::fs::rename(p, &target).is_ok()
                } else {
                    std::fs::write(&target, data).is_ok()
                };
                if stored {
                    self.kept_bytes.fetch_add(size, Ordering::Relaxed);
                    self.kept_files.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        if let Some(p) = temp {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn hash_result(verdict: &str, threat: Option<&str>, detail: &str, score: f64, sha: &str, source: &str) -> ResultMessage {
    ResultMessage {
        r#type: "result".to_string(),
        id: 0,
        verdict: verdict.to_string(),
        threat: threat.map(|t| t.to_string()),
        detail: Some(detail.to_string()),
        score,
        sha256: sha.to_string(),
        scan_ms: 0,
        source: source.to_string(),
        extracted_objects: Vec::new(),
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
        source: "scan".to_string(),
        extracted_objects: report.extracted_objects.clone(),
    };

    let mut detail_parts = Vec::new();

    if !report.detections.is_empty() {
        res.threat = Some(report.detections[0].name.clone());
        let details: Vec<String> = report
            .detections
            .iter()
            .take(8)
            .map(|d| format!("{} ({})", d.name, d.layer))
            .collect();
        detail_parts.push(details.join(", "));
    } else if let Some(ref signer) = report.signer_info {
        if signer.is_trusted {
            if let Some(ref name) = signer.signer_name {
                detail_parts.push(format!("Signed by {}", name));
            }
        }
    }

    // Explicitly summarize extracted objects (Unicorn unpacked, archives, overlays)
    if !report.extracted_objects.is_empty() {
        let unpacked_count = report.extracted_objects.iter().filter(|o| o.origin_type == "UnpackedPE").count();
        let archive_count = report.extracted_objects.iter().filter(|o| o.origin_type == "ArchiveMember").count();
        let overlay_count = report.extracted_objects.iter().filter(|o| o.origin_type == "Overlay").count();

        let mut summary_tags = Vec::new();
        if unpacked_count > 0 {
            let total_unpacked_bytes: u64 = report.extracted_objects.iter().filter(|o| o.origin_type == "UnpackedPE").map(|o| o.size).sum();
            summary_tags.push(format!("Unicorn Unpacked: {} PE ({} KB)", unpacked_count, (total_unpacked_bytes + 1023) / 1024));
        }
        if archive_count > 0 {
            summary_tags.push(format!("Archive: {} items", archive_count));
        }
        if overlay_count > 0 {
            summary_tags.push(format!("Overlay: {} items", overlay_count));
        }

        if !summary_tags.is_empty() {
            detail_parts.push(format!("[{}]", summary_tags.join(" | ")));
        }
    }

    if !detail_parts.is_empty() {
        res.detail = Some(detail_parts.join(" — "));
    }

    res
}

fn load_malicious_hashes(dirs: &[PathBuf]) -> HashMap<Sha, String> {
    let mut out = HashMap::new();
    for dir in dirs {
        for rel in MALICIOUS_HASH_FILES {
            let Ok(text) = std::fs::read_to_string(dir.join(rel)) else { continue };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (hash, name) = match line.split_once([':', ',', ' ', '\t']) {
                    Some((h, n)) if !n.trim().is_empty() => (h, n.trim()),
                    Some((h, _)) => (h, "HashSignature.Malicious"),
                    None => (line, "HashSignature.Malicious"),
                };
                if let Some(sha) = parse_sha(hash) {
                    out.insert(sha, name.to_string());
                }
            }
        }
    }
    out
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

    for c in &candidates {
        if c.join("database").is_dir() || c.join("yara_rules").is_dir() || c.join("models").is_dir() {
            return c.clone();
        }
    }

    PathBuf::from(".")
}

/// Deletes temp files left by a previous run; returns (bytes, count) of kept unknown files.
fn remove_leftover_uploads(dir: &Path) -> (u64, i64) {
    let mut kept = (0u64, 0i64);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let b = name.as_bytes();
            if b.len() >= 9 && b[..8].iter().all(|c| c.is_ascii_digit()) && b[8] == b'_' {
                let _ = std::fs::remove_file(&path);
            } else if b.len() > 65 && b[64] == b'_' && b[..64].iter().all(|c| c.is_ascii_hexdigit()) {
                kept.0 += entry.metadata().map(|m| m.len()).unwrap_or(0);
                kept.1 += 1;
            }
        }
    }
    kept
}

/// Name used for the temp file. Executables uploaded with a sample extension such as
/// `.vir` get `.exe` so the engine treats them as PE files.
fn temp_name(safe: &str, data: &[u8]) -> String {
    let mut name: String = safe.chars().take(80).collect();
    if name.is_empty() {
        name = "file".into();
    }
    if data.starts_with(b"MZ") {
        let lower = name.to_ascii_lowercase();
        let is_pe_ext = [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi", ".drv", ".com"]
            .iter()
            .any(|e| lower.ends_with(e));
        if !is_pe_ext {
            name.push_str(".exe");
        }
    }
    name
}

pub fn file_system_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            _ => c,
        })
        .collect::<String>()
        .trim_matches(['.', ' '])
        .to_string()
}
