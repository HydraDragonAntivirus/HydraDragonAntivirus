use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;
use sha1collisiondetection::Sha1CD;
use sha2::{Sha256, Digest as Sha256Digest};

use crate::clam::ClamScanner;
use crate::hayabusa_scanner::{HayabusaEventMatch, HayabusaScanner};
use crate::hosts::{self, HostsCheckReport, HostsRestoreReport};
use crate::ml::scanner::MlScanner;
use crate::ptm_registry::PuaRegistryMatcher;
use crate::report::{DetectionItem, RegistryCheckReport, SignerDetails, StaticScanReport};
use crate::signers::{verify_authenticode, SignerDb};
use crate::yara::YaraScanner;

pub struct StaticEngine {
    clam: ClamScanner,
    yara: YaraScanner,
    ml: MlScanner,
    signers: SignerDb,
    pua_registry: PuaRegistryMatcher,
    hayabusa: HayabusaScanner,
    benign_hashes: HashSet<String>,
}

impl StaticEngine {
    /// Initialize the static engine using a root directory containing rule subfolders:
    /// - `database/` for ClamAV
    /// - `yara_rules/` for YARA (.yar, .yara, .yrc)
    /// - `models/` for ML models (pe_trees.bin, js_trees.bin, url_trees.bin, *.onnx)
    /// - `signer_rules/` for trusted_signers.yaml, etc.
    /// - `hash_rules/` for hash whitelists/rules (benign_sha1.txt, etc.)
    /// - `ptm.local.src` or `ptm/` for PUA registry patterns
    pub fn init(base_dir: &Path) -> Self {
        let base = base_dir.to_path_buf();

        let database_dir = base.join("database");
        let rules_dir = if base.join("yara_rules").is_dir() {
            base.join("yara_rules")
        } else {
            base.join("rules")
        };
        let models_dir = base.join("models");
        let hash_rules_dir = if base.join("hash_rules").is_dir() {
            base.join("hash_rules")
        } else {
            base.join("database")
        };
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
        let mut benign_hashes = HashSet::new();

        // Load SHA-256 hash whitelists from hash_rules/
        let hash_files = [
            hash_rules_dir.join("benign_sha256.txt"),
            base.join("hash_rules").join("benign_sha256.txt"),
            database_dir.join("benign_sha256.txt"),
        ];
        for hpath in &hash_files {
            if let Ok(content) = std::fs::read_to_string(hpath) {
                for line in content.lines() {
                    let trimmed = line.trim().to_lowercase();
                    if trimmed.len() == 64 {
                        benign_hashes.insert(trimmed);
                    }
                }
            }
        }
        if hash_rules_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&hash_rules_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() && p.extension().map_or(false, |ext| ext == "txt" || ext == "hash") {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            for line in content.lines() {
                                let trimmed = line.trim().to_lowercase();
                                if trimmed.len() == 64 {
                                    benign_hashes.insert(trimmed);
                                }
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

        Self {
            clam,
            yara,
            ml,
            signers,
            pua_registry,
            hayabusa,
            benign_hashes,
        }
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
                    sha1: String::new(),
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

    fn scan_bytes_internal(
        &self,
        data: &[u8],
        target_name: &str,
        disk_path: Option<&Path>,
        start_time: Instant,
    ) -> StaticScanReport {
        let file_size = data.len() as u64;

        // Hashes & SHA-1 Collision Detection (Marc Stevens sha1dc / SHAttered counter-cryptanalysis)
        let mut sha1_hasher = Sha1CD::default();
        sha1_hasher.update(data);
        let mut sha1_digest = sha1collisiondetection::Output::default();
        let is_collision_attack = sha1_hasher.finalize_into_dirty_cd(&mut sha1_digest).is_err();
        let sha1_hex = hex::encode(sha1_digest);

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(data);
        let sha256_hex = hex::encode(sha256_hasher.finalize());

        let mut detections = Vec::new();
        let mut max_score: f32 = 0.0;

        // SHA-1 Collision Attack Detection Alert (sha1dc)
        if is_collision_attack {
            detections.push(DetectionItem {
                layer: "Crypto_Integrity".to_string(),
                name: "Crypto.SHA1.CollisionAttackDetected".to_string(),
                score: Some(1.0),
                details: Some("Marc Stevens sha1dc counter-cryptanalysis detected SHA-1 collision attack (SHAttered / Chosen-Prefix) in payload".to_string()),
            });
            max_score = max_score.max(1.0);
        }

        // 0. Fast-Path: Cryptographic SHA-256 Whitelist (Collision immune)
        if self.benign_hashes.contains(&sha256_hex) && !is_collision_attack {
            return StaticScanReport {
                target: target_name.to_string(),
                file_size,
                sha1: sha1_hex,
                sha256: sha256_hex,
                verdict: "Clean".to_string(),
                max_threat_score: 0.0,
                detections: Vec::new(),
                signer_info: None,
                pua_registry_matches: Vec::new(),
                scan_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        // 0.1 EICAR Test File Detection (Single standard SHA-1 hash)
        const EICAR_SHA1: &str = "3395856ce81f2b7382dee72602f798b642f14140";
        if sha1_hex == EICAR_SHA1 || data.starts_with(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") {
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
                    sha1: sha1_hex,
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

        // 3. ClamAV Engine
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

        // 4. YARA-X Engine
        let yara_matches = self.yara.scan_bytes(data);
        for y_name in yara_matches {
            detections.push(DetectionItem {
                layer: "YARA".to_string(),
                name: y_name,
                score: Some(0.95),
                details: None,
            });
            max_score = max_score.max(0.95);
        }

        // 5. Machine Learning (PE / JS)
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
        } else if target_name.ends_with(".js") || target_name.ends_with(".mjs") || is_js_content(data) {
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

        // 7. Heuristic: Trailing Null Bytes (0x00) File Pumping / Inflation Detection & Stripped Rescan
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

        // 9. Archive Recursive Extraction & Zip Bomb Detection
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
            sha1: sha1_hex,
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

    /// Scan a URL using the ONNX LightGBM tree classifier.
    pub fn scan_url(&self, raw_url: &str) -> Option<f32> {
        self.ml.predict_url(raw_url)
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
