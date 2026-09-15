use std::path::{Path, PathBuf};
use std::time::Instant;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha256Digest};

use crate::clam::ClamScanner;
use crate::fls::{FlsClient, FlsVerdict};
use crate::ml::scanner::MlScanner;
use crate::ptm_registry::PuaRegistryMatcher;
use crate::report::{DetectionItem, RegistryCheckReport, SignerDetails, StaticScanReport};
use crate::signers::{verify_authenticode, SignerDb};
use crate::yara::YaraScanner;

pub struct StaticEngine {
    base_dir: PathBuf,
    clam: ClamScanner,
    yara: YaraScanner,
    ml: MlScanner,
    signers: SignerDb,
    pua_registry: PuaRegistryMatcher,
    fls: FlsClient,
}

impl StaticEngine {
    /// Initialize the static engine using a root directory containing rule subfolders:
    /// - `database/` for ClamAV
    /// - `rules/` for YARA (.yar)
    /// - `models/` for Burn ML models (pe_model.mpk, js_model.mpk)
    /// - `signer_rules/` for trusted_signers.yaml, etc.
    /// - `ptm.local.src` or `ptm/` for PUA registry patterns
    pub fn init(base_dir: &Path) -> Self {
        let base = base_dir.to_path_buf();

        let database_dir = base.join("database");
        let rules_dir = base.join("rules");
        let models_dir = base.join("models");
        let registry_rules_path = if base.join("registry_rules.yaml").is_file() {
            base.join("registry_rules.yaml")
        } else if base.join("registry_rules.yml").is_file() {
            base.join("registry_rules.yml")
        } else if base.join("registry_rules").is_dir() {
            base.join("registry_rules")
        } else if base.join("ptm.local.src").is_file() {
            base.join("ptm.local.src")
        } else {
            base.join("rules").join("registry_rules.yaml")
        };

        let clam = ClamScanner::new(&database_dir);
        let yara = YaraScanner::new(&rules_dir);
        let ml = MlScanner::new(&models_dir);
        let signers_dir = base.join("signer_rules");
        let signers = SignerDb::load_from_dir(&signers_dir);
        let pua_registry = PuaRegistryMatcher::load(&registry_rules_path);
        let fls = FlsClient::default();

        Self {
            base_dir: base,
            clam,
            yara,
            ml,
            signers,
            pua_registry,
            fls,
        }
    }

    /// Scan a file on disk. Evaluates WinTrust signature, ClamAV, YARA, PE/JS ML, and Comodo FLS.
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
                    fls_verdict: None,
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

        // Hashes
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(data);
        let sha1_hex = hex::encode(sha1_hasher.finalize());

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(data);
        let sha256_hex = hex::encode(sha256_hasher.finalize());

        let mut detections = Vec::new();
        let mut max_score: f32 = 0.0;

        // 1. Authenticode & Signer Check
        let mut signer_details = None;
        if let Some(p) = disk_path {
            let (is_signed, is_trusted, signer_name, status) = verify_authenticode(p);
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
            });
        }

        // 2. ClamAV Engine
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

        // 3. YARA-X Engine
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

        // 4. Machine Learning (PE / JS)
        if data.starts_with(b"MZ") {
            if let Some(prob) = self.ml.predict_pe(data) {
                if prob >= 0.70 {
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

        // 5. Comodo FLS Lookup
        let fls_res = self.fls.query_sha1(&sha1_hex);
        let fls_str = fls_res.as_str().to_string();
        if fls_res == FlsVerdict::Malicious {
            detections.push(DetectionItem {
                layer: "FLS_Cloud".to_string(),
                name: "ComodoFLS.Malicious".to_string(),
                score: Some(1.0),
                details: Some("Reputation confirmed by Comodo FLS cloud".to_string()),
            });
            max_score = max_score.max(1.0);
        }

        // Final Verdict calculation
        let verdict = if max_score >= 0.85 || !detections.is_empty() {
            "Malicious"
        } else if let Some(ref sig) = signer_details {
            if sig.is_trusted {
                "Clean"
            } else {
                "Unknown"
            }
        } else if fls_res == FlsVerdict::Safe {
            "Clean"
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
            fls_verdict: Some(fls_str),
            pua_registry_matches: Vec::new(),
            scan_time_ms: start_time.elapsed().as_millis() as u64,
        }
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

    /// Query FLS directly for SHA-1
    pub fn check_fls(&self, sha1_hex: &str) -> FlsVerdict {
        self.fls.query_sha1(sha1_hex)
    }
}

fn is_js_content(bytes: &[u8]) -> bool {
    let sample = if bytes.len() > 512 { &bytes[..512] } else { bytes };
    if let Ok(s) = std::str::from_utf8(sample) {
        s.contains("function") || s.contains("var ") || s.contains("const ") || s.contains("let ")
    } else {
        false
    }
}
