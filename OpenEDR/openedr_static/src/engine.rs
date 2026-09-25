use std::path::Path;
use std::time::Instant;
use sha1collisiondetection::Sha1CD;
use sha2::{Sha256, Digest as Sha256Digest};

use crate::apk;
use crate::crypto;
use crate::clam::ClamScanner;
use crate::diagnostics;
use crate::ml::filetype;
use crate::hayabusa_scanner::{HayabusaEventMatch, HayabusaScanner};
use crate::hosts::{self, HostsCheckReport, HostsRestoreReport};
use crate::ml::scanner::MlScanner;
use crate::pe_strings;
use crate::ptm_registry::PuaRegistryMatcher;
use crate::report::{
    DetectionItem, MemoryScanReport, RegistryCheckReport, SignerDetails, StaticScanReport,
};
use crate::signers::{verify_authenticode, SignerDb};
use crate::string_rules::{self, PeStringRules};
use crate::yara::YaraScanner;

/// APK tree-model decision threshold. From `apk_trees.meta.json`
/// (LightGBM 200 trees, valid F1 0.955 / FPR 0.017). Retune on retrain.
/// Web parity (`openedr_web/src/engine.rs::APK_TREE_THRESHOLD`).
pub const APK_TREE_THRESHOLD: f32 = 0.8;

/// Generic whole-buffer ML fallback threshold. Fires only when every other
/// layer (ClamAV/YARA/HydraSig/PE/JS/APK ML) found nothing, so keep it at the
/// Malicious cutoff to hold FPR down. Retune on generic retrain.
pub const GENERIC_TREE_THRESHOLD: f32 = 0.85;

/// Canonical EICAR SHA-256 (standard test file). Web had a typo variant;
/// both are accepted, plus a prefix check so any EICAR build flags.
const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const EICAR_SHA256_WEB_VARIANT: &str =
    "275a021bbfb6489e7341ac665a24224100c9e6029d5b2b6150d9933f3a9d541";
const EICAR_PREFIX: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

pub struct StaticEngine {
    clam: ClamScanner,
    yara: YaraScanner,
    ml: MlScanner,
    signers: SignerDb,
    pua_registry: PuaRegistryMatcher,
    hayabusa: HayabusaScanner,
    string_rules: PeStringRules,
    pub url_engine: crate::url_rules::UrlThreatEngine,
}

impl StaticEngine {
    /// Initialize the static engine using a root directory containing rule subfolders:
    /// - `database/` for ClamAV
    /// - `yara_rules/` for YARA (.yar, .yara, .yrc)
    /// - `models/` for ML models (pe_trees.bin, js_trees.bin, url_trees.bin, apk_trees.bin, *.onnx)
    /// - `signer_rules/` for trusted_signers.yaml, etc.
    /// - `hydradragonsig_rules/` for hydradragonsig string-rule YAML (in-scan HydraSig layer)
    /// - `ptm.local.src` or `ptm/` for PUA registry patterns
    pub fn init(base_dir: &Path) -> Self {
        let base = base_dir.to_path_buf();
        diagnostics::log("init-start", &format!("base={}", base.display()));

        let database_dir = base.join("database");
        let rules_dir = if base.join("yara_rules").is_dir() {
            base.join("yara_rules")
        } else {
            base.join("rules")
        };
        let models_dir = base.join("models");
        let registry_rules_path = if base.join("registry_rules").is_dir() {
            base.join("registry_rules")
        } else if base.join("registry_rules.yaml").is_file() {
            base.join("registry_rules.yaml")
        } else if base.join("registry_rules.yml").is_file() {
            base.join("registry_rules.yml")
        } else if base.join("yara_rules").join("registry_rules").is_dir() {
            base.join("yara_rules").join("registry_rules")
        } else if base.join("rules").join("registry_rules").is_dir() {
            base.join("rules").join("registry_rules")
        } else if base.join("ptm.local.src").is_file() {
            base.join("ptm.local.src")
        } else {
            base.join("yara_rules").join("registry_rules.yaml")
        };

        let clam = ClamScanner::new(&database_dir);
        let yara = YaraScanner::new(&rules_dir);
        let ml = MlScanner::new(&models_dir);
        let signers_dir = base.join("signer_rules");
        let signers = SignerDb::load_from_dir(&signers_dir);
        let pua_registry = PuaRegistryMatcher::load(&registry_rules_path);

        // HydraSig string rules (web parity): hydradragonsig RuleSet evaluated
        // in-scan with FileType tags (PE/APK gating lives in rule data).
        let mut string_rules = PeStringRules::default();
        for dir in [
            base.join("hydradragonsig_rules"),
            base.join("rules").join("hydradragonsig"),
            base.join("yara_rules").join("hydradragonsig_rules"),
        ] {
            if dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file()
                            && p.extension()
                                .and_then(|e| e.to_str())
                                .map_or(false, |e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
                        {
                            if let Ok(text) = std::fs::read_to_string(&p) {
                                let _ = string_rules.load_yaml(&text);
                            }
                        }
                    }
                }
            }
        }

        let hayabusa_dir = if base.join("hayabusa_rules").is_dir() {
            base.join("hayabusa_rules")
        } else if base.join("rules").join("hayabusa").is_dir() {
            base.join("rules").join("hayabusa")
        } else {
            base.join("hayabusa_rules")
        };
        let hayabusa = HayabusaScanner::new(&hayabusa_dir);

        diagnostics::log(
            "engine-status",
            &format!(
                "base={}; clam_dir_exists={}; clam_loaded={}; yara_dir={}; yara_loaded={}; yara_rule_bundles={}; models_dir={}; pe_model_file={}; pe_loaded={}; js_model_file={}; js_loaded={}; url_model_file={}; url_loaded={}; apk_model_file={}; apk_loaded={}; generic_model_file={}; generic_loaded={}; generic_used_for_file_verdict={}; signer_dir={}; signer_counts={}/{}/{}; registry_rules={}; registry_patterns={}; string_rules={}; hayabusa_dir={}; hayabusa_loaded={}",
                base.display(),
                database_dir.is_dir(),
                clam.is_loaded(),
                rules_dir.display(),
                yara.is_loaded(),
                yara.rule_count(),
                models_dir.display(),
                models_dir.join("pe_trees.bin").is_file(),
                ml.pe_loaded(),
                models_dir.join("js_trees.bin").is_file(),
                ml.js_loaded(),
                models_dir.join("url_trees.bin").is_file(),
                ml.url_loaded(),
                models_dir.join("apk_trees.bin").is_file(),
                ml.apk_loaded(),
                models_dir.join("generic_trees.bin").is_file(),
                ml.generic_loaded(),
                ml.generic_used_for_file_verdict(),
                signers_dir.display(),
                signers.pattern_counts().0,
                signers.pattern_counts().1,
                signers.pattern_counts().2,
                registry_rules_path.display(),
                pua_registry.pattern_count(),
                string_rules.pattern_count(),
                hayabusa_dir.display(),
                hayabusa.is_loaded(),
            ),
        );

        Self {
            clam,
            yara,
            ml,
            signers,
            pua_registry,
            hayabusa,
            string_rules,
            url_engine: crate::url_rules::UrlThreatEngine::new(),
        }
    }

    /// Tree-model readiness (web parity: kind 3 = APK).
    pub fn apk_ml_loaded(&self) -> bool {
        self.ml.apk_loaded()
    }

    /// Signer-rule checks — single authority for trusted/malicious/PUA vendor
    /// YAMLs (`signer_rules/`). Backs the `openedr_static_is_*_signer` FFI
    /// consumed by owlyshield_predict (no duplicate YAML parsing there).
    pub fn is_trusted_signer(&self, signer: &str) -> bool {
        self.signers.is_trusted(signer)
    }

    pub fn is_malicious_signer(&self, signer: &str) -> bool {
        self.signers.is_malicious(signer)
    }

    pub fn is_pua_signer(&self, signer: &str) -> bool {
        self.signers.is_pua(signer)
    }

    /// Runtime model load from bytes: kind 0=PE, 1=JS, 2=URL, 3=APK (web parity).
    pub fn load_model(&mut self, kind: u32, data: &[u8]) -> bool {
        self.ml.load_model_bytes(kind, data)
    }

    /// Load one compiled YARA `.yrc` bundle (web parity).
    pub fn load_yara(&mut self, data: &[u8]) -> bool {
        self.yara.load_yrc(data)
    }

    /// Compile one YARA source document (web parity).
    pub fn add_yara_source(&mut self, src: &str) -> bool {
        self.yara.add_source(src)
    }

    /// Load hydradragonsig string-rule YAML (web parity). Returns rule count or -1.
    pub fn set_string_rules(&mut self, yaml: &str) -> i32 {
        self.string_rules.load_yaml(yaml)
    }

    pub fn set_registry_rules(&mut self, yaml: &str) -> i32 {
        self.set_string_rules(yaml)
    }

    /// Scan a Windows EVTX log file for threat events using Hayabusa rules.
    pub fn scan_evtx(&self, path: &Path) -> Vec<HayabusaEventMatch> {
        self.hayabusa.scan_evtx_file(path)
    }

    /// Scan live Windows system event logs (C:\Windows\System32\Winevt\Logs\) using Hayabusa rules.
    pub fn scan_system_events(&self) -> Vec<HayabusaEventMatch> {
        self.hayabusa.scan_system_events()
    }

    /// Scan a file on disk. Evaluates WinTrust signature, ClamAV, YARA, and PE/JS ML.
    pub fn scan_file(&self, path: &Path) -> StaticScanReport {
        let t0 = Instant::now();
        let target_str = path.display().to_string();

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return StaticScanReport {
                    target: target_str,
                    file_size: 0,
                    sha256: String::new(),
                    verdict: "Error".to_string(),
                    max_threat_score: 0.0,
                    detections: vec![DetectionItem {
                        layer: "IO".to_string(),
                        name: format!("Failed to read file: {e}"),
                        score: None,
                        details: None,
                    }],
                    signer_info: None,
                    pua_registry_matches: Vec::new(),
                    scan_time_ms: t0.elapsed().as_millis() as u64,
                };
            }
        };

        self.scan_bytes_internal(&data, &target_str, Some(path), t0)
    }

    /// Scan raw in-memory bytes with optional filename for extension matching.
    pub fn scan_bytes(&self, data: &[u8], file_name: &str) -> StaticScanReport {
        let t0 = Instant::now();
        self.scan_bytes_internal(data, file_name, None, t0)
    }

    /// Scan a live process' committed readable memory (Windows only).
    /// Read-only snapshots via ReadProcessMemory; nothing is executed.
    /// Each region runs ClamAV + YARA (+ PE expert for MZ-start regions).
    /// No unicorn recursion, no signer checks. `max_mb` caps total bytes
    /// read (0 = default 256 MiB).
    pub fn scan_pid(&self, pid: u32, max_mb: u64) -> MemoryScanReport {
        let t0 = Instant::now();
        let mut report = MemoryScanReport {
            pid,
            regions_scanned: 0,
            bytes_scanned: 0,
            verdict: "Unknown".to_string(),
            max_threat_score: 0.0,
            detections: Vec::new(),
            scan_time_ms: 0,
        };
        #[cfg(target_os = "windows")]
        self.scan_pid_windows(pid, max_mb, &mut report);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (pid, max_mb);
            report.verdict = "Error".to_string();
            report.detections.push(DetectionItem {
                layer: "IO".to_string(),
                name: "Memory scan requires Windows".to_string(),
                score: None,
                details: None,
            });
        }
        if report.verdict != "Error" {
            report.verdict = if report.max_threat_score >= 0.85 {
                "Malicious"
            } else if report.max_threat_score >= 0.50 || !report.detections.is_empty() {
                "Suspicious"
            } else {
                "Unknown"
            }
            .to_string();
        }
        report.scan_time_ms = t0.elapsed().as_millis() as u64;
        report
    }

    #[cfg(target_os = "windows")]
    fn scan_pid_windows(&self, pid: u32, max_mb: u64, report: &mut MemoryScanReport) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
            PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
            VirtualQueryEx,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        const DEFAULT_BUDGET_MB: u64 = 256;
        const PER_REGION_CAP: usize = 32 << 20;
        const READ_CHUNK: usize = 1 << 20;

        let mut budget = if max_mb == 0 {
            DEFAULT_BUDGET_MB << 20
        } else {
            max_mb.min(4096) << 20
        };

        let handle: HANDLE = unsafe {
            match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(_) => {
                    report.verdict = "Error".to_string();
                    report.detections.push(DetectionItem {
                        layer: "IO".to_string(),
                        name: "OpenProcess failed (access denied or no such process)".to_string(),
                        score: None,
                        details: None,
                    });
                    return;
                }
            }
        };

        let mut addr: usize = 0;
        loop {
            if budget == 0 {
                break;
            }
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    handle,
                    Some(addr as *const std::ffi::c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if ret == 0 {
                break;
            }
            let base = mbi.BaseAddress as usize;
            let end = match base.checked_add(mbi.RegionSize) {
                Some(e) => e,
                None => break,
            };
            addr = if end <= addr { break } else { end };
            if mbi.State != MEM_COMMIT {
                continue;
            }
            if mbi.Protect == PAGE_NOACCESS {
                continue;
            }
            // PAGE_GUARD is a modifier flag, not a standalone protection.
            if (mbi.Protect.0 & PAGE_GUARD.0) != 0 {
                continue;
            }
            let readable = matches!(
                mbi.Protect,
                PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY
            );
            if !readable {
                continue;
            }
            let take = mbi.RegionSize.min(PER_REGION_CAP).min(budget as usize);
            if take < 4096 {
                continue;
            }
            let mut buf = Vec::with_capacity(take.min(READ_CHUNK));
            let mut read_total = 0usize;
            while read_total < take {
                let step = (take - read_total).min(READ_CHUNK);
                let off = base + read_total;
                let mut chunk = vec![0u8; step];
                let mut got: usize = 0;
                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        off as *const std::ffi::c_void,
                        chunk.as_mut_ptr() as *mut std::ffi::c_void,
                        step,
                        Some(&mut got),
                    )
                };
                if ok.is_err() || got == 0 {
                    break;
                }
                chunk.truncate(got);
                buf.extend_from_slice(&chunk);
                read_total += got;
                if got < step {
                    break;
                }
            }
            if buf.is_empty() {
                continue;
            }
            budget -= buf.len().min(budget as usize) as u64;
            report.regions_scanned += 1;
            report.bytes_scanned += buf.len() as u64;
            let tag = format!("pid:{pid}:0x{base:x}");

            for m in self.clam.scan_bytes(&buf, &tag) {
                report.detections.push(DetectionItem {
                    layer: "Memory_ClamAV".to_string(),
                    name: format!("Memory:{}", m.name),
                    score: Some(1.0),
                    details: Some(format!("ClamAV hit in process memory ({tag})")),
                });
                report.max_threat_score = report.max_threat_score.max(1.0);
            }
            for y_name in self.yara.scan_bytes(&buf) {
                report.detections.push(DetectionItem {
                    layer: "Memory_YARA".to_string(),
                    name: format!("Memory:{y_name}"),
                    score: Some(0.95),
                    details: Some(format!("YARA hit in process memory ({tag})")),
                });
                report.max_threat_score = report.max_threat_score.max(0.95);
            }
            if buf.starts_with(b"MZ") {
                if let Some(prob) = self.ml.predict_pe(&buf) {
                    if prob >= 0.71 {
                        report.detections.push(DetectionItem {
                            layer: "Memory_ML".to_string(),
                            name: "Memory.PE.HighConfidence".to_string(),
                            score: Some(prob),
                            details: Some(format!(
                                "MZ region malware probability: {:.2}% ({tag})",
                                prob * 100.0
                            )),
                        });
                        report.max_threat_score = report.max_threat_score.max(prob);
                    }
                }
            }
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    }

    fn scan_bytes_internal(
        &self,
        data: &[u8],
        target_name: &str,
        disk_path: Option<&Path>,
        start_time: Instant,
    ) -> StaticScanReport {
        let file_size = data.len() as u64;

        let mut sha1_hasher = Sha1CD::default();
        sha1_hasher.update(data);
        let mut sha1_digest = sha1collisiondetection::Output::default();
        let is_sha1_collision = sha1_hasher.finalize_into_dirty_cd(&mut sha1_digest).is_err();

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(data);
        let sha256_hex = hex::encode(sha256_hasher.finalize());

        let mut detections = Vec::new();
        let mut max_score: f32 = 0.0;

        if is_sha1_collision {
            detections.push(DetectionItem {
                layer: "Crypto_Integrity".to_string(),
                name: "Crypto.SHA1.CollisionAttackDetected".to_string(),
                score: Some(1.0),
                details: Some("Marc Stevens sha1dc counter-cryptanalysis detected SHA-1 collision attack (SHAttered / Chosen-Prefix) in payload".to_string()),
            });
            max_score = max_score.max(1.0);
        }

        if let Some(md5_hit) = crypto::detect_md5_collision(data) {
            detections.push(DetectionItem {
                layer: "Crypto_Integrity".to_string(),
                name: md5_hit.name.to_string(),
                score: Some(1.0),
                details: Some(md5_hit.details),
            });
            max_score = max_score.max(1.0);
        }

        // Empty files scan as Unknown (web parity: never Error).
        if data.is_empty() {
            return StaticScanReport {
                target: target_name.to_string(),
                file_size,
                sha256: sha256_hex,
                verdict: "Unknown".to_string(),
                max_threat_score: 0.0,
                detections: Vec::new(),
                signer_info: None,
                pua_registry_matches: Vec::new(),
                scan_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        // File-type gate FIRST: unclassifiable content is not scanned at
        // all — verdict Unknown, straight out. No signer/YARA/ClamAV/ML/unicorn
        // work is spent on it.
        if filetype::detect(data).is_unknown {
            return StaticScanReport {
                target: target_name.to_string(),
                file_size,
                sha256: sha256_hex,
                verdict: "Unknown".to_string(),
                max_threat_score: 0.0,
                detections: Vec::new(),
                signer_info: None,
                pua_registry_matches: Vec::new(),
                scan_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        // 0.1 EICAR (SHA-256 identity + prefix; web had a typo variant — accept both).
        if sha256_hex == EICAR_SHA256
            || sha256_hex == EICAR_SHA256_WEB_VARIANT
            || data.starts_with(EICAR_PREFIX)
        {
            detections.push(DetectionItem {
                layer: "Signature".to_string(),
                name: "EICAR-Test-File".to_string(),
                score: Some(1.0),
                details: Some("EICAR standard antivirus test file".to_string()),
            });
            max_score = max_score.max(1.0);
        }

        // 1. Authenticode & Signer Check
        let mut signer_details = None;
        if let Some(p) = disk_path {
            let (is_signed, is_trusted, signer_name, status, is_catalog_signed) =
                verify_authenticode(p);
            let mut trusted_by_yaml = false;

            if let Some(ref signer) = signer_name {
                if self.signers.is_malicious(signer) {
                    detections.push(DetectionItem {
                        layer: "SignerRule".to_string(),
                        name: format!("MaliciousSigner: {signer}"),
                        score: Some(1.0),
                        details: Some("Matched malicious_vendors.yaml".to_string()),
                    });
                    max_score = max_score.max(1.0);
                } else if self.signers.is_pua(signer) {
                    detections.push(DetectionItem {
                        layer: "SignerRule".to_string(),
                        name: format!("PuaSigner: {signer}"),
                        score: Some(0.85),
                        details: Some("Matched pua_vendors.yaml".to_string()),
                    });
                    max_score = max_score.max(0.85);
                } else if self.signers.is_trusted(signer) {
                    trusted_by_yaml = true;
                }
            }

            signer_details = Some(SignerDetails {
                is_signed,
                is_trusted: is_trusted || trusted_by_yaml,
                signer_name,
                status,
                is_catalog_signed,
            });

            // Fast-path for trusted authenticode binaries with no signer alert
            if (is_trusted || trusted_by_yaml) && detections.is_empty() {
                return StaticScanReport {
                    target: target_name.to_string(),
                    file_size,
                    sha256: sha256_hex,
                    verdict: "Clean".to_string(),
                    max_threat_score: 0.0,
                    detections: Vec::new(),
                    signer_info: signer_details,
                    pua_registry_matches: Vec::new(),
                    scan_time_ms: start_time.elapsed().as_millis() as u64,
                };
            }
        }

        // 2a. APK path (web parity): own forest + heuristics + capped YARA/HydraSig.
        // Runs even without the bundle so APKs never return Error.
        let is_apk_file = apk::is_apk(data, target_name);
        if is_apk_file {
            if let Some(feats) = apk::apk_tree_features(data) {
                if let Some(prob) = self.ml.predict_apk(&feats) {
                    if prob >= APK_TREE_THRESHOLD {
                        detections.push(DetectionItem {
                            layer: "APK_ML".to_string(),
                            name: "HydraDragon.APK.TreeScore".to_string(),
                            score: Some(prob),
                            details: Some(format!(
                                "APK tree-model malware probability: {:.2}%",
                                prob * 100.0
                            )),
                        });
                        max_score = max_score.max(prob);
                    }
                }
            }
            for h in apk::apk_heuristics(data, target_name) {
                detections.push(DetectionItem {
                    layer: "APK_Heuristic".to_string(),
                    name: h.name,
                    score: Some(h.score),
                    details: Some(h.details),
                });
                max_score = max_score.max(h.score);
            }
            // YARA-X over capped manifest+dex bytes (no full-archive OOM).
            let yara_bytes: Option<Vec<u8>> = apk::yara_input(data);
            let yara_slice: &[u8] = yara_bytes.as_deref().unwrap_or_else(|| {
                &data[..data.len().min(8 * 1024 * 1024)]
            });
            for name in self.yara.scan_bytes(yara_slice) {
                detections.push(DetectionItem {
                    layer: "YARA".to_string(),
                    name,
                    score: Some(0.95),
                    details: None,
                });
                max_score = max_score.max(0.95);
            }
            // HydraSig over capped APK strings with APK file-type tags.
            {
                let raw = apk::apk_strings_capped(data);
                let strings: Vec<String> = raw
                    .iter()
                    .map(|s| string_rules::normalize_text(s))
                    .collect();
                for hit in self.string_rules.scan_bytes(
                    yara_slice,
                    target_name,
                    &sha256_hex,
                    &strings,
                    false,
                    true,
                    10,
                ) {
                    let name = if hit.rule.is_empty() {
                        "HydraSig.Match".to_string()
                    } else {
                        hit.rule.clone()
                    };
                    let mut details = hit.title.clone();
                    if let Some(ev) = hit.evidence.first() {
                        details.push_str(" | ");
                        details.push_str(&ev.chars().take(120).collect::<String>());
                    }
                    let score = hit.score as f32 / 100.0;
                    detections.push(DetectionItem {
                        layer: "HydraSig".to_string(),
                        name,
                        score: Some(score),
                        details: Some(details),
                    });
                    max_score = max_score.max(score);
                }
            }
        }

        // 3. ClamAV Engine (native-only; skipped for APKs — APKs use YARA/HydraSig/ML above
        // plus the generic archive rescan below via hydradragonextractor).
        if !is_apk_file {
            let clam_matches = self.clam.scan_bytes(data, target_name);
            for m in clam_matches {
                detections.push(DetectionItem {
                    layer: "ClamAV".to_string(),
                    name: m.name,
                    score: Some(1.0),
                    details: Some(format!("matched view {:?}", m.view)),
                });
                max_score = max_score.max(1.0);
            }
        }

        // 4. YARA-X Engine (capped 32 MB on huge files so giant samples stay panic-free).
        if !is_apk_file {
            let slice: &[u8] = if data.len() > 32 * 1024 * 1024 {
                &data[..32 * 1024 * 1024]
            } else {
                data
            };
            let yara_matches = self.yara.scan_bytes(slice);
            for y_name in yara_matches {
                detections.push(DetectionItem {
                    layer: "YARA".to_string(),
                    name: y_name,
                    score: Some(0.95),
                    details: None,
                });
                max_score = max_score.max(0.95);
            }
        }

        // 4b. hydradragonsig string rules, evaluated by ITS engine (web parity).
        // Executable gating lives in the rules via FileType conditions;
        // the engine only tags the file (validated PE or not). Strings
        // capped to first 16 MB so giant files stay panic-free.
        if !is_apk_file {
            let is_pe = find_valid_embedded_pe(data) == Some(0);
            let capped: &[u8] = if data.len() > 16 * 1024 * 1024 {
                &data[..16 * 1024 * 1024]
            } else {
                data
            };
            let raw = pe_strings::extract_strings(capped);
            let strings: Vec<String> =
                raw.iter().map(|s| string_rules::normalize_text(s)).collect();
            for hit in
                self.string_rules
                    .scan_bytes(data, target_name, &sha256_hex, &strings, is_pe, false, 10)
            {
                let name = if hit.rule.is_empty() {
                    "HydraSig.Match".to_string()
                } else {
                    hit.rule.clone()
                };
                let mut details = hit.title.clone();
                if let Some(ev) = hit.evidence.first() {
                    details.push_str(" | ");
                    details.push_str(&ev.chars().take(120).collect::<String>());
                }
                let score = hit.score as f32 / 100.0;
                detections.push(DetectionItem {
                    layer: "HydraSig".to_string(),
                    name,
                    score: Some(score),
                    details: Some(details),
                });
                max_score = max_score.max(score);
            }
        }

        // 5. Machine Learning (PE / JS) — skipped for APKs (APK forest above).
        if !is_apk_file {
            if data.starts_with(b"MZ") {
                if let Some(prob) = self.ml.predict_pe(data) {
                    if prob >= 0.71 {
                        detections.push(DetectionItem {
                            layer: "PE_ML".to_string(),
                            name: "MalwareNet.PE.HighConfidence".to_string(),
                            score: Some(prob),
                            details: Some(format!("Malware probability: {:.2}%", prob * 100.0)),
                        });
                        max_score = max_score.max(prob);
                    }
                }
            } else if target_name.to_ascii_lowercase().ends_with(".js")
                || target_name.to_ascii_lowercase().ends_with(".mjs")
                || is_js_content(data)
            {
                if let Ok(source) = std::str::from_utf8(data) {
                    if let Some(prob) = self.ml.predict_js(source) {
                        if prob >= 0.75 {
                            detections.push(DetectionItem {
                                layer: "JS_ML".to_string(),
                                name: "MalwareNet.JS.HighConfidence".to_string(),
                                score: Some(prob),
                                details: Some(format!("Malware probability: {:.2}%", prob * 100.0)),
                            });
                            max_score = max_score.max(prob);
                        }
                    }
                }
            }
        }

        // 5b. Generic whole-buffer ML fallback (non-APK only): runs ONLY when
        // every layer above found nothing. Catches non-PE/non-JS payloads
        // (scripts-in-blob, packed blobs, unknown formats) the experts miss.
        if !is_apk_file && detections.is_empty() && max_score < GENERIC_TREE_THRESHOLD
        {
            if let Some(prob) = self.ml.predict_generic_bytes(data) {
                if prob >= GENERIC_TREE_THRESHOLD {
                    detections.push(DetectionItem {
                        layer: "Generic_ML".to_string(),
                        name: "MalwareNet.Generic.HighConfidence".to_string(),
                        score: Some(prob),
                        details: Some(format!(
                            "Generic whole-buffer malware probability: {:.2}%",
                            prob * 100.0
                        )),
                    });
                    max_score = max_score.max(prob);
                }
            }
        }

        // 6. Unicorn PE CPU Emulation & Unpacker (Heuristic analysis)
        if data.starts_with(b"MZ") && data.len() >= 0x1000 {
            if let Ok(sample) = hydradragonunicorn::unpacker::engine::Sample::from_bytes(data) {
                let mut unpacker = hydradragonunicorn::unpacker::engine::UnpackerEngine::new(sample, "memory");
                if unpacker.init_uc().is_ok() {
                    let _ = unpacker.emu();
                    if let Ok(dumped) = unpacker.dump_bytes() {
                        if !dumped.is_empty() && dumped != data {
                            // Rescan emulated unpacked buffer with ClamAV, YARA-X, and ML
                            let unp_clam = self.clam.scan_bytes(&dumped, target_name);
                            for m in unp_clam {
                                detections.push(DetectionItem {
                                    layer: "Unicorn_Unpacker_ClamAV".to_string(),
                                    name: format!("Unpacked:{}", m.name),
                                    score: Some(1.0),
                                    details: Some("Detected inside memory dumped by Unicorn CPU emulation".to_string()),
                                });
                                max_score = max_score.max(1.0);
                            }
                            let unp_yara = self.yara.scan_bytes(&dumped);
                            for y_name in unp_yara {
                                detections.push(DetectionItem {
                                    layer: "Unicorn_Unpacker_YARA".to_string(),
                                    name: format!("Unpacked:{}", y_name),
                                    score: Some(0.95),
                                    details: Some("YARA rule matched on Unicorn emulated unpacked payload".to_string()),
                                });
                                max_score = max_score.max(0.95);
                            }
                            if let Some(prob) = self.ml.predict_pe(&dumped) {
                                if prob >= 0.71 {
                                    detections.push(DetectionItem {
                                        layer: "Unicorn_Unpacker_ML".to_string(),
                                        name: "Unpacked.MalwareNet.PE.HighConfidence".to_string(),
                                        score: Some(prob),
                                        details: Some(format!("Unpacked payload malware probability: {:.2}%", prob * 100.0)),
                                    });
                                    max_score = max_score.max(prob);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 7. Heuristic: Trailing Null Bytes (PE-only — ZIP/APK archives
        // legitimately pad, web parity skips APKs here).
        if !is_apk_file {
            let non_zero_end = data.iter().rposition(|&b| b != 0).map_or(0, |idx| idx + 1);
            let trailing_zeros = data.len() - non_zero_end;
            let is_inflated = (trailing_zeros >= 65536)
                || (data.len() > 1024 * 1024 && trailing_zeros as f64 / data.len() as f64 >= 0.20 && trailing_zeros >= 32768);

        if is_inflated && non_zero_end > 0 {
            detections.push(DetectionItem {
                layer: "Heuristic".to_string(),
                name: "Heuristic.File.InflatedNullPadding".to_string(),
                score: Some(0.80),
                details: Some(format!(
                    "Detected {} KB of trailing 0x00 null padding (stripped {} KB -> {} KB)",
                    trailing_zeros / 1024,
                    data.len() / 1024,
                    non_zero_end / 1024
                )),
            });
            max_score = max_score.max(0.80);

            // Rescan stripped buffer with ClamAV, YARA-X, and ML
            let stripped_data = &data[..non_zero_end];

            let cl_matches = self.clam.scan_bytes(stripped_data, target_name);
            for m in cl_matches {
                detections.push(DetectionItem {
                    layer: "Heuristic_Stripped_ClamAV".to_string(),
                    name: format!("Stripped:{}", m.name),
                    score: Some(1.0),
                    details: Some("Detected inside stripped payload after removing null padding".to_string()),
                });
                max_score = max_score.max(1.0);
            }

            let yr_matches = self.yara.scan_bytes(stripped_data);
            for ym in yr_matches {
                detections.push(DetectionItem {
                    layer: "Heuristic_Stripped_YARA".to_string(),
                    name: format!("Stripped:{}", ym),
                    score: Some(0.95),
                    details: Some("YARA rule matched on stripped payload after removing null padding".to_string()),
                });
                max_score = max_score.max(0.95);
            }

            if stripped_data.starts_with(b"MZ") {
                if let Some(prob) = self.ml.predict_pe(stripped_data) {
                    if prob >= 0.71 {
                        detections.push(DetectionItem {
                            layer: "Heuristic_Stripped_PE_ML".to_string(),
                            name: "Stripped.MalwareNet.PE.HighConfidence".to_string(),
                            score: Some(prob),
                            details: Some(format!("Stripped payload malware probability: {:.2}%", prob * 100.0)),
                        });
                        max_score = max_score.max(prob);
                    }
                }
            }
        }
        }

        // 8. Heuristic: PE Overlay Extraction & Embedded Executable Rescan
        if data.starts_with(b"MZ") && data.len() >= 0x200 {
            if let Ok(pe) = pefile_rs::PE::parse(data) {
                let mut max_pe_offset: usize = 0;
                for sec in &pe.sections {
                    let sec_end = (sec.pointer_to_raw_data + sec.size_of_raw_data) as usize;
                    if sec_end > max_pe_offset {
                        max_pe_offset = sec_end;
                    }
                }
                if pe.optional_header.data_directories.len() > 4 {
                    let sec_dir = &pe.optional_header.data_directories[4]; // Security Directory (Certificate Table)
                    if sec_dir.virtual_address > 0 && sec_dir.size > 0 {
                        let cert_end = (sec_dir.virtual_address + sec_dir.size) as usize;
                        if cert_end > max_pe_offset {
                            max_pe_offset = cert_end;
                        }
                    }
                }

                if max_pe_offset > 0 && max_pe_offset < data.len() {
                    let overlay = &data[max_pe_offset..];
                    if overlay.len() >= 512 {
                        // Validated embedded-PE search: random "MZ" byte pairs inside
                        // compressed SFX payloads (7z/Inno/NSIS) must NOT count.
                        // Require MZ + e_lfanew + PE\0\0 + sane NumberOfSections.
                        let embedded_pe_offset = find_valid_embedded_pe(overlay);
                        let has_embedded_pe = embedded_pe_offset.is_some();
                        let is_sfx_archive = overlay.starts_with(b"PK\x03\x04")
                            || overlay.starts_with(b"7z\xBC\xAF\x27\x1C")
                            || overlay.starts_with(b"Rar!\x1A\x07");

                        // Always rescan overlay content with engines (real detection value).
                        // Standalone heuristic fires ONLY on validated binder (has_embedded_pe).
                        // Legit SFX (7z/Inno/NSIS) and bare large overlays alone are NOT detections.
                        let mut overlay_confirmed = false;

                        let ov_clam = self.clam.scan_bytes(overlay, "overlay.bin");
                        for m in ov_clam {
                            overlay_confirmed = true;
                            detections.push(DetectionItem {
                                layer: "Heuristic_Overlay_ClamAV".to_string(),
                                name: format!("Overlay:{}", m.name),
                                score: Some(1.0),
                                details: Some("Detected inside PE overlay payload".to_string()),
                            });
                            max_score = max_score.max(1.0);
                        }

                        let ov_yara = self.yara.scan_bytes(overlay);
                        for ym in ov_yara {
                            overlay_confirmed = true;
                            detections.push(DetectionItem {
                                layer: "Heuristic_Overlay_YARA".to_string(),
                                name: format!("Overlay:{}", ym),
                                score: Some(0.95),
                                details: Some("YARA rule matched inside PE overlay".to_string()),
                            });
                            max_score = max_score.max(0.95);
                        }

                        // ML on overlay only if it starts with a validated PE image,
                        // or on the validated embedded slice.
                        let ml_target: Option<&[u8]> = if embedded_pe_offset == Some(0) {
                            Some(overlay)
                        } else if let Some(off) = embedded_pe_offset {
                            Some(&overlay[off..])
                        } else {
                            None
                        };
                        if let Some(pe_blob) = ml_target {
                            if pe_blob.starts_with(b"MZ") {
                                if let Some(detail) = hydradragonextractor::heuristics::inspect_pe_rva_trick(pe_blob) {
                                    detections.push(DetectionItem {
                                        layer: "Heuristic_Overlay".to_string(),
                                        name: "HEUR:Win32.Susp.PE.RVATrick".to_string(),
                                        score: Some(0.90),
                                        details: Some(format!("{detail} in overlay PE")),
                                    });
                                    max_score = max_score.max(0.90);
                                }
                                if let Some(prob) = self.ml.predict_pe(pe_blob) {
                                    if prob >= 0.71 {
                                        overlay_confirmed = true;
                                        detections.push(DetectionItem {
                                            layer: "Heuristic_Overlay_PE_ML".to_string(),
                                            name: "Overlay.MalwareNet.PE.HighConfidence".to_string(),
                                            score: Some(prob),
                                            details: Some(format!("Overlay PE malware probability: {:.2}%", prob * 100.0)),
                                        });
                                        max_score = max_score.max(prob);
                                    }
                                }
                            }
                        }

                        // Standalone binder heuristic: validated MZ->PE only.
                        // SFX archives (7z/PK/Rar) without validated PE or engine hit: silent.
                        if has_embedded_pe {
                            let off = embedded_pe_offset.unwrap_or(0);
                            // SFX self-extractors legitimately carry an archive after the stub;
                            // a validated PE deep inside an SFX archive start is still a binder,
                            // but an SFX archive with no engine confirmation is left silent above.
                            // Here we have a real second PE image, so flag it.
                            let _ = (off, is_sfx_archive);
                            detections.push(DetectionItem {
                                layer: "Heuristic_Overlay".to_string(),
                                name: "Heuristic.PE.EmbeddedExecutableOverlay".to_string(),
                                score: Some(0.85),
                                details: Some(format!(
                                    "Validated embedded PE image at overlay offset {} (overlay {} bytes)",
                                    off,
                                    overlay.len()
                                )),
                            });
                            max_score = max_score.max(0.85);
                        } else if overlay_confirmed {
                            // Engine already reported the payload; no extra heuristic needed.
                        } else {
                            // Legit SFX / large overlay with no validated PE and no engine hit: no detection.
                        }
                    }
                }
            }
        }

        // 9. Archive heuristics (encrypted bait, RLO names, PE RVA tricks)
        for hit in hydradragonextractor::heuristics::inspect_archive(data) {
            detections.push(DetectionItem {
                layer: "Heuristic_Archive".to_string(),
                name: hit.name.to_string(),
                score: Some(hit.score),
                details: Some(hit.details),
            });
            max_score = max_score.max(hit.score);
        }
        if data.starts_with(b"MZ") {
            if let Some(detail) = hydradragonextractor::heuristics::inspect_pe_rva_trick(data) {
                detections.push(DetectionItem {
                    layer: "Heuristic_PE".to_string(),
                    name: "HEUR:Win32.Susp.PE.RVATrick".to_string(),
                    score: Some(0.90),
                    details: Some(detail),
                });
                max_score = max_score.max(0.90);
            }
        }

        // 10. Archive Recursive Extraction & Zip Bomb Detection
        if hydradragonextractor::detect_format(data).is_some() {
            match hydradragonextractor::extract_archive_from_bytes(data, false) {
                Ok(entries) => {
                    for entry in entries {
                        let child_clam = self.clam.scan_bytes(&entry.data, &entry.name);
                        for m in child_clam {
                            detections.push(DetectionItem {
                                layer: "Archive_ClamAV".to_string(),
                                name: format!("Archive:{}:{}", entry.name, m.name),
                                score: Some(1.0),
                                details: Some(format!("Extracted file: {}", entry.name)),
                            });
                            max_score = max_score.max(1.0);
                        }
                        let child_yara = self.yara.scan_bytes(&entry.data);
                        for ym in child_yara {
                            detections.push(DetectionItem {
                                layer: "Archive_YARA".to_string(),
                                name: format!("Archive:{}:{}", entry.name, ym),
                                score: Some(0.95),
                                details: Some(format!("Extracted file: {}", entry.name)),
                            });
                            max_score = max_score.max(0.95);
                        }
                        if entry.data.starts_with(b"MZ") {
                            if let Some(prob) = self.ml.predict_pe(&entry.data) {
                                if prob >= 0.71 {
                                    detections.push(DetectionItem {
                                        layer: "Archive_PE_ML".to_string(),
                                        name: format!("Archive:{}:MalwareNet.PE.HighConfidence", entry.name),
                                        score: Some(prob),
                                        details: Some(format!("Child PE malware probability: {:.2}%", prob * 100.0)),
                                    });
                                    max_score = max_score.max(prob);
                                }
                            }
                            if let Some(detail) = hydradragonextractor::heuristics::inspect_pe_rva_trick(&entry.data) {
                                detections.push(DetectionItem {
                                    layer: "Heuristic_Archive".to_string(),
                                    name: "HEUR:Win32.Susp.PE.RVATrick".to_string(),
                                    score: Some(0.90),
                                    details: Some(format!("{} in extracted '{}'", detail, entry.name)),
                                });
                                max_score = max_score.max(0.90);
                            }
                        }
                    }
                }
                Err(err) => {
                    if hydradragonextractor::is_bomb_error(&err) {
                        detections.push(DetectionItem {
                            layer: "Heuristic_Archive".to_string(),
                            name: "Heuristic.Archive.DecompressionBomb.ZipBomb".to_string(),
                            score: Some(1.0),
                            details: Some(format!("Decompression bomb (ZipBomb) detected: {}", err)),
                        });
                        max_score = max_score.max(1.0);
                    }
                }
            }
        }

        // Final Verdict calculation: score-gated only.
        // Low-score standalone heuristics must NOT become Malicious on their own.
        let verdict = if max_score >= 0.85 {
            "Malicious"
        } else if max_score >= 0.50 {
            "Suspicious"
        } else if !detections.is_empty() {
            "Suspicious"
        } else if let Some(ref sig) = signer_details {
            if sig.is_trusted {
                "Clean"
            } else {
                "Unknown"
            }
        } else {
            "Unknown"
        };

        StaticScanReport {
            target: target_name.to_string(),
            file_size,
            sha256: sha256_hex,
            verdict: verdict.to_string(),
            max_threat_score: max_score,
            detections,
            signer_info: signer_details,
            pua_registry_matches: Vec::new(),
            scan_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Check hosts file for tampering, modifications, or security vendor blacklisting.
    pub fn check_hosts(&self, custom_path: Option<&Path>) -> HostsCheckReport {
        hosts::check_hosts_file(custom_path)
    }

    /// Restore the hosts file back to the clean default Microsoft Windows template.
    pub fn restore_hosts(&self, custom_path: Option<&Path>, backup: bool) -> HostsRestoreReport {
        hosts::restore_hosts_file(custom_path, backup)
    }

    /// Check registry path against puaRegPaths from ptm.local.src.
    pub fn check_registry(&self, reg_path: &str) -> RegistryCheckReport {
        let matches = self.pua_registry.matches(reg_path);
        let is_pua = !matches.is_empty();
        RegistryCheckReport {
            query_path: reg_path.to_string(),
            matched_patterns: matches,
            is_pua_autostart: is_pua,
        }
    }

    /// URL score via ML model (openedr_static strictly uses Machine Learning >= 0.90).
    /// Returns (probability, is_malicious, is_whitelisted, is_blacklisted).
    pub fn scan_url(&self, raw_url: &str) -> (f32, bool, bool, bool) {
        let prob = self.ml.predict_url(raw_url).unwrap_or(0.0);
        let is_malicious = prob >= 0.90;
        (prob, is_malicious, false, false)
    }

    pub fn url_model_loaded(&self) -> bool {
        self.ml.url_loaded()
    }

    /// Raw ML-only URL probability (no whitelist/CIDR gating).
    pub fn predict_url_raw(&self, raw_url: &str) -> Option<f32> {
        self.ml.predict_url(raw_url)
    }

    /// Full inspection via Rust YAML Threat Engine + optional page content
    /// (web parity: phishing forms, drainers, webhooks, YARA + JS ML).
    pub fn inspect_url_with_content(
        &self,
        raw_url: &str,
        liveness_code: i32,
        page_content: Option<&str>,
    ) -> crate::url_rules::UrlThreatReport {
        let prob = self.ml.predict_url(raw_url).unwrap_or(0.0);
        let mut report = self.url_engine.inspect(
            raw_url,
            false,
            false,
            prob,
            liveness_code,
            page_content,
        );

        if let Some(body) = page_content {
            // 1. JS ML tree prediction on scripts/content
            if let Some(js_prob) = self.ml.predict_js(body) {
                if js_prob >= 0.75 {
                    report.detections.push(crate::url_rules::UrlRuleHit {
                        rule_id: "CONTENT_JS_ML_MALWARE".to_string(),
                        title: "MalwareNet JS Tree Classification".to_string(),
                        severity: "Malicious".to_string(),
                        score: (js_prob * 100.0).round() as u32,
                        details: format!("Page script classified as malicious by tree model: {:.1}%", js_prob * 100.0),
                    });
                    report.risk_score = report.risk_score.max((js_prob * 100.0).round() as u32);
                    report.verdict = "Malicious".to_string();
                    report.verdict_reason = format!("Content Decision (Malicious): Embedded script identified as malware by JS ML model ({:.1}%).", js_prob * 100.0);
                }
            }

            // 2. YARA-X rules on page content
            let yara_hits = self.yara.scan_bytes(body.as_bytes());
            for hit in yara_hits {
                report.detections.push(crate::url_rules::UrlRuleHit {
                    rule_id: "CONTENT_YARA_SIGNATURE".to_string(),
                    title: format!("YARA Match: {}", hit),
                    severity: "Malicious".to_string(),
                    score: 95,
                    details: format!("Page content matched YARA rule: {}", hit),
                });
                report.risk_score = report.risk_score.max(95);
                report.verdict = "Malicious".to_string();
                report.verdict_reason = format!("Content Decision (Malicious): Page content matched YARA signature ({}).", hit);
            }
        }

        report
    }

    /// Full inspection via Rust YAML Threat Engine (no page content).
    pub fn inspect_url(&self, raw_url: &str, liveness_code: i32) -> crate::url_rules::UrlThreatReport {
        self.inspect_url_with_content(raw_url, liveness_code, None)
    }

    /// Load custom YAML threat rules (web parity). Returns count on success.
    pub fn load_url_rules(&mut self, yaml_str: &str) -> Result<usize, String> {
        self.url_engine.load_yaml(yaml_str)
    }

    /// Add a subdomain to the unwhitelist set at runtime (web parity).
    pub fn add_unwhitelisted_subdomain(&mut self, host: &str) {
        self.url_engine.add_unwhitelisted_subdomain(host);
    }

    /// Check if a host/subdomain is unwhitelisted (web parity).
    pub fn is_unwhitelisted_subdomain(&self, host: &str) -> bool {
        self.url_engine.is_unwhitelisted(host)
    }
}

fn find_valid_embedded_pe(data: &[u8]) -> Option<usize> {
    // Scan for MZ occurrences and validate as real PE images.
    // Prevents random "MZ" byte pairs in compressed SFX data from firing.
    if data.len() < 0x44 {
        return None;
    }
    let mut i = 0usize;
    while i + 0x40 < data.len() {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            let e_off = i + 0x3C;
            if e_off + 4 <= data.len() {
                let e_lfanew = u32::from_le_bytes([data[e_off], data[e_off + 1], data[e_off + 2], data[e_off + 3]]) as usize;
                // e_lfanew is relative to this MZ candidate, must be sane.
                if e_lfanew < 0x04 || e_lfanew > 0x100000 {
                    i += 2;
                    continue;
                }
                let pe_off = i + e_lfanew;
                if pe_off + 6 <= data.len()
                    && data[pe_off] == b'P'
                    && data[pe_off + 1] == b'E'
                    && data[pe_off + 2] == 0
                    && data[pe_off + 3] == 0
                {
                    let num_sections = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]) as usize;
                    if num_sections >= 1 && num_sections <= 96 {
                        // Optional magic check (PE32=0x10b, PE32+=0x20b) when available.
                        let opt_off = pe_off + 24;
                        let valid_opt = if opt_off + 2 <= data.len() {
                            let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
                            magic == 0x10b || magic == 0x20b
                        } else {
                            true
                        };
                        if valid_opt {
                            return Some(i);
                        }
                    }
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn is_js_content(bytes: &[u8]) -> bool {
    let sample = if bytes.len() > 512 { &bytes[..512] } else { bytes };
    if let Ok(s) = std::str::from_utf8(sample) {
        s.contains("function") || s.contains("var ") || s.contains("const ") || s.contains("let ")
    } else {
        false
    }
}


