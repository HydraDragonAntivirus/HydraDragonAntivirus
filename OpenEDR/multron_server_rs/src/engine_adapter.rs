use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use openedr_static::engine::StaticEngine;
use openedr_static::report::{ExtractedObject, StaticScanReport};
use openedr_static::signers::BinaryFuse16Filter;
use serde::{Deserialize, Serialize};

use crate::cache::Sha;

pub const ENGINE_NAME: &str = "VirusKov";

const EICAR_SHA256: &str = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

/// Pure Elasticsearch ECS (8.11+) result message for VirusKov.
/// Serializes only standard Elastic Common Schema fields over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMessage {
    pub r#type: String, // "result"
    pub id: i64,
    #[serde(rename = "@timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecs: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub antivirus: Option<serde_json::Value>,
    #[serde(rename = "threat", skip_serializing_if = "Option::is_none")]
    pub threat_indicator: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<serde_json::Value>,

    // Internal engine state fields (not serialized or deserialized - no legacy wire fields)
    #[serde(default, skip)]
    pub verdict: String,
    #[serde(default, skip)]
    pub threat: Option<String>,
    #[serde(default, skip)]
    pub detail: Option<String>,
    #[serde(default, skip)]
    pub score: f64,
    #[serde(default, skip)]
    pub sha256: String,
    #[serde(default, skip)]
    pub scan_ms: i64,
    #[serde(default, skip)]
    pub source: String,
    #[serde(default, skip)]
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
    malicious_xf: RwLock<Option<BinaryFuse16Filter>>,
    whitelist_enabled: bool,
    keep_unknown: bool,
    pub keep_threats: bool,
    pub keep_clean: bool,
    pub compress_low_disk: bool,
    pub low_disk_threshold_bytes: u64,
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
        keep_threats: bool,
        keep_clean: bool,
        compress_low_disk: bool,
        low_disk_gb: u64,
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
            malicious_xf: RwLock::new(None),
            whitelist_enabled,
            keep_unknown,
            keep_threats,
            keep_clean,
            compress_low_disk,
            low_disk_threshold_bytes: low_disk_gb * 1024 * 1024 * 1024,
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

                // Only check xorfilter_rules for XOR filters (.xf) - no .txt hash files
                let xf_dir = rules_dir.join("xorfilter_rules");
                let mut mal_filter = None;
                for cand in &["malicious_sha256.xf", "malware.xf"] {
                    let p = xf_dir.join(cand);
                    if p.is_file() {
                        if let Ok(bytes) = std::fs::read(&p) {
                            if let Some(f) = BinaryFuse16Filter::from_bytes(&bytes) {
                                eprintln!("[engine] {} malicious SHA-256 signatures loaded from XOR filter {}", f.len(), p.display());
                                mal_filter = Some(f);
                                break;
                            }
                        }
                    }
                }
                *adapter.malicious_xf.write().unwrap() = mal_filter;

                match std::panic::catch_unwind(|| StaticEngine::init(&rules_dir)) {
                    Ok(engine) => {
                        let elapsed = started.elapsed().as_millis() as i64;
                        adapter.load_ms.store(elapsed, Ordering::Relaxed);
                        if adapter.whitelist_enabled && !engine.benign_whitelist_loaded() {
                            eprintln!("[engine] benign_sha256.xf not found in xorfilter_rules, hash whitelist is off");
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
        self.malicious_xf
            .read()
            .unwrap()
            .as_ref()
            .map(|f| f.len())
            .unwrap_or(0)
    }

    pub fn whitelist_active(&self) -> bool {
        self.whitelist_enabled && self.engine.get().is_some_and(|e| e.benign_whitelist_loaded())
    }

    /// Verdict from the SHA-256 alone, without the file: hash signatures first (a
    /// malicious hit must win), then the engine's benign whitelist. None = upload needed.
    pub fn hash_lookup(&self, _sha: &Sha, sha_hex: &str) -> Option<ResultMessage> {
        if sha_hex == EICAR_SHA256 {
            return Some(hash_result("malicious", Some("EICAR-Test-File"), "EICAR standard antivirus test file (hash)", 1.0, sha_hex, "hash"));
        }
        if let Some(ref filter) = *self.malicious_xf.read().unwrap() {
            if filter.contains(sha_hex) {
                return Some(hash_result("malicious", Some("Malware.Hash.XorFilter"), "Matched malicious SHA-256 (XOR Filter)", 1.0, sha_hex, "hash"));
            }
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
        if data.is_empty() {
            let res = ResultMessage {
                r#type: "result".to_string(),
                id: 0,
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
                ecs: Some(serde_json::json!({ "version": "9.5.4" })),
                event: Some(serde_json::json!({ "action": "scan_skipped", "kind": "event", "category": ["malware", "file"] })),
                file: Some(serde_json::json!({ "name": name, "size": 0, "hash": { "sha256": sha } })),
                antivirus: Some(serde_json::json!({ "engine": ENGINE_NAME, "verdict": "skipped" })),
                threat_indicator: None,
                rule: None,
                verdict: "skipped".to_string(),
                threat: None,
                detail: Some("0 KB / empty file skipped".to_string()),
                score: 0.0,
                sha256: sha.to_string(),
                scan_ms: started.elapsed().as_millis() as i64,
                source: "scan".to_string(),
                extracted_objects: Vec::new(),
            };
            return Ok(res);
        }

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

    /// Unknown, clean (if keep_clean enabled), and detected threat files (kept by default for false positive inspection)
    /// are kept in the work folder (multron_incoming) as `<SHA256>_<name>`, `clean_<SHA256>_<name>`, or `threat_<SHA256>_<name>`.
    /// When disk space is low, incoming files are automatically compressed using LZMA2 maximum preset (.xz).
    fn keep_or_remove(&self, temp: Option<&Path>, data: &[u8], res: &ResultMessage, sha: &str, name: &str) {
        let size = data.len() as u64;
        let is_threat = res.verdict == "malicious" || res.verdict == "suspicious";
        let is_unknown = res.verdict == "unknown";
        let is_clean = res.verdict == "clean";

        let should_keep = !data.is_empty()
            && ((self.keep_threats && is_threat) || (self.keep_unknown && is_unknown) || (self.keep_clean && is_clean))
            && self.kept_bytes.load(Ordering::Relaxed) + size <= self.keep_limit_bytes;

        if should_keep {
            if let Some(dir) = &self.work_dir {
                let name = if name.is_empty() { "file" } else { name };
                let prefix = if is_threat {
                    "threat_"
                } else if is_clean {
                    "clean_"
                } else {
                    ""
                };
                let low_disk = self.compress_low_disk
                    && is_disk_space_low(
                        dir,
                        self.kept_bytes.load(Ordering::Relaxed),
                        self.keep_limit_bytes,
                        self.low_disk_threshold_bytes,
                    );

                if low_disk {
                    // PC has low disk space: compress with LZMA2 Max (Preset 9) into .xz
                    let target_xz = dir.join(format!("{}{}_{}.xz", prefix, sha, name));
                    if !target_xz.exists() {
                        let comp_res = if let Some(p) = temp {
                            compress_file_lzma2_max(p, &target_xz)
                        } else {
                            compress_bytes_lzma2_max(data, &target_xz)
                        };
                        if let Ok(compressed_len) = comp_res {
                            self.kept_bytes.fetch_add(compressed_len, Ordering::Relaxed);
                            self.kept_files.fetch_add(1, Ordering::Relaxed);
                            if let Some(p) = temp {
                                let _ = std::fs::remove_file(p);
                            }
                            return;
                        }
                    }
                } else {
                    let target = dir.join(format!("{}{}_{}", prefix, sha, name));
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
        }
        if let Some(p) = temp {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn hash_result(verdict: &str, threat: Option<&str>, detail: &str, score: f64, sha: &str, source: &str) -> ResultMessage {
    let is_threat = verdict == "malicious" || verdict == "suspicious";
    let ecs = serde_json::json!({
        "@timestamp": chrono::Utc::now().to_rfc3339(),
        "ecs": { "version": "9.5.4" },
        "event": {
            "kind": if is_threat { "alert" } else { "event" },
            "category": ["malware", "file"],
            "type": if is_threat { vec!["info", "indicator"] } else { vec!["info"] },
            "action": format!("hash_lookup_{}", source),
            "outcome": "success",
            "duration": 0,
        },
        "file": {
            "hash": {
                "sha256": sha,
            }
        },
        "antivirus": {
            "engine": ENGINE_NAME,
            "verdict": verdict,
            "score": score,
            "source": source,
            "detail": detail,
        },
        "rule": {
            "name": threat.unwrap_or(detail),
            "verdict": verdict,
        }
    });

    let threat_indicator = if is_threat {
        Some(serde_json::json!({
            "indicator": {
                "type": "file",
                "name": threat.unwrap_or(detail),
                "confidence": score,
                "file": {
                    "hash": {
                        "sha256": sha,
                    }
                }
            }
        }))
    } else {
        None
    };

    ResultMessage {
        r#type: "result".to_string(),
        id: 0,
        timestamp: ecs.get("@timestamp").and_then(|t| t.as_str()).map(|s| s.to_string()),
        ecs: Some(serde_json::json!({ "version": "9.5.4" })),
        event: ecs.get("event").cloned(),
        file: ecs.get("file").cloned(),
        antivirus: ecs.get("antivirus").cloned(),
        threat_indicator,
        rule: ecs.get("rule").cloned(),
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
        "clean" | "malicious" | "suspicious" | "unknown" | "skipped" => raw_verdict,
        _ => "unknown".to_string(),
    };

    let mut res = ResultMessage {
        r#type: "result".to_string(),
        id: 0,
        timestamp: None,
        ecs: Some(serde_json::json!({ "version": "9.5.4" })),
        event: None,
        file: None,
        antivirus: None,
        threat_indicator: None,
        rule: None,
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

    let mut ecs_val = report.to_ecs_value();
    if let Some(file_obj) = ecs_val.get_mut("file").and_then(|f| f.as_object_mut()) {
        file_obj.insert("hash".to_string(), serde_json::json!({ "sha256": sha }));
    }
    res.timestamp = ecs_val.get("@timestamp").and_then(|t| t.as_str()).map(|s| s.to_string());
    res.ecs = ecs_val.get("ecs").cloned().or_else(|| Some(serde_json::json!({ "version": "9.5.4" })));
    res.event = ecs_val.get("event").cloned();
    res.file = ecs_val.get("file").cloned();
    res.antivirus = ecs_val.get("antivirus").cloned();
    res.threat_indicator = ecs_val.get("threat").cloned();
    res.rule = ecs_val.get("rule").cloned();

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
            candidates.push(parent.join("OpenMalwareScannerPortable"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("OpenMalwareScannerPortable"));
                if let Some(ggparent) = grandparent.parent() {
                    candidates.push(ggparent.join("OpenMalwareScannerPortable"));
                }
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.clone());
        candidates.push(cwd.join("OpenMalwareScannerPortable"));
        candidates.push(cwd.join("OpenEDR"));
    }

    for c in &candidates {
        if c.join("database").is_dir()
            || c.join("yara_rules").is_dir()
            || c.join("models").is_dir()
            || c.join("xorfilter_rules").is_dir()
        {
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
            } else {
                let check_name = name
                    .strip_prefix("threat_")
                    .or_else(|| name.strip_prefix("clean_"))
                    .unwrap_or(name);
                let cb = check_name.as_bytes();
                if cb.len() > 65 && cb[64] == b'_' && cb[..64].iter().all(|c| c.is_ascii_hexdigit()) {
                    kept.0 += entry.metadata().map(|m| m.len()).unwrap_or(0);
                    kept.1 += 1;
                }
            }
        }
    }
    kept
}

fn compress_bytes_lzma2_max(data: &[u8], target_path: &Path) -> std::io::Result<u64> {
    use std::io::Write;
    let file = std::fs::File::create(target_path)?;
    let mut enc = lzma_rust2::XzWriter::new(file, lzma_rust2::XzOptions::with_preset(9))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    enc.write_all(data)?;
    let finished_file = enc.finish()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    finished_file.metadata().map(|m| m.len())
}

fn compress_file_lzma2_max(src_path: &Path, target_path: &Path) -> std::io::Result<u64> {
    use std::io::{Read, Write};
    let mut src = std::fs::File::open(src_path)?;
    let file = std::fs::File::create(target_path)?;
    let mut enc = lzma_rust2::XzWriter::new(file, lzma_rust2::XzOptions::with_preset(9))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        enc.write_all(&buffer[..n])?;
    }
    let finished_file = enc.finish()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    finished_file.metadata().map(|m| m.len())
}

#[cfg(windows)]
fn get_available_disk_space_bytes(dir: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);

    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }

    let mut free_bytes_available: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free_bytes: u64 = 0;

    let ret = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes_available,
            &mut total_bytes,
            &mut total_free_bytes,
        )
    };

    if ret != 0 {
        Some(free_bytes_available)
    } else {
        None
    }
}

#[cfg(not(windows))]
fn get_available_disk_space_bytes(_dir: &Path) -> Option<u64> {
    None
}

fn is_disk_space_low(dir: &Path, kept_bytes: u64, keep_limit_bytes: u64, low_disk_threshold_bytes: u64) -> bool {
    if keep_limit_bytes > 0 && kept_bytes >= (keep_limit_bytes * 8) / 10 {
        return true;
    }
    if let Some(free_bytes) = get_available_disk_space_bytes(dir) {
        if free_bytes <= low_disk_threshold_bytes {
            return true;
        }
    }
    false
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
