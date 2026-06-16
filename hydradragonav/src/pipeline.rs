use std::path::{Path, PathBuf};

use clap::ValueEnum;
use hydradragonstatic::models::FileTypeInfo;
use hydradragonstatic::trusted_signers::TrustedSignerList;
use yara_x::{Compiler, Rules, Scanner as YaraScanner};

use crate::bloom_filter::HashBloomFilter;
use crate::detectiteasy::{DetectItEasyScanner, MAX_DIE_FILE_SIZE, MAX_SCAN_FILE_SIZE};
use crate::hash_scanner::HashScanner;
use crate::scanner::Scanner as ClamavScanner;
use crate::verdict::{EngineResult, ScanResult, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ScanMode {
    #[default]
    Full,
    Files,
}

#[derive(Clone)]
pub struct PipelineConfig {
    pub complist_path: Option<PathBuf>,
    pub bloom_dir: Option<PathBuf>,
    pub yara_rules_dir: Option<PathBuf>,
    pub hydradragonstatic_rules_dir: Option<PathBuf>,
    pub pe_ml_model_path: Option<PathBuf>,
    pub js_ml_model_path: Option<PathBuf>,
    pub clamav_lib: Option<PathBuf>,
    pub clamav_db: Option<PathBuf>,
    pub hayabusa_dir: Option<PathBuf>,
    pub detectiteasy_dir: Option<PathBuf>,
    pub scan_mode: ScanMode,
    pub ml_threshold: f32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            complist_path: None,
            bloom_dir: None,
            yara_rules_dir: None,
            hydradragonstatic_rules_dir: None,
            pe_ml_model_path: None,
            js_ml_model_path: None,
            clamav_lib: None,
            clamav_db: None,
            hayabusa_dir: None,
            detectiteasy_dir: None,
            scan_mode: ScanMode::default(),
            ml_threshold: 0.8,
        }
    }
}

pub struct Pipeline {
    config: PipelineConfig,
    trusted_signers: Option<TrustedSignerList>,
    hash_scanner: Option<HashScanner>,
    yara_rules: Option<Rules>,
    clamav: Option<ClamavScanner>,
    detectiteasy: DetectItEasyScanner,
    hydradragonstatic_rules: Option<hydradragonstatic::rules::RuleSet>,
}

impl Pipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self::new_impl(config, None)
    }

    pub fn new_with_clamav(config: PipelineConfig, clamav: ClamavScanner) -> Self {
        Self::new_impl(config, Some(clamav))
    }

    fn new_impl(config: PipelineConfig, existing_clamav: Option<ClamavScanner>) -> Self {
        let complist_path = config.complist_path.clone();
        let bloom_dir = config.bloom_dir.clone();
        let yara_rules_dir = config.yara_rules_dir.clone();
        let clamav_lib = config.clamav_lib.clone();
        let clamav_db = config.clamav_db.clone();
        let detectiteasy_dir = config.detectiteasy_dir.clone();
        let hydradragonstatic_rules_dir = config.hydradragonstatic_rules_dir.clone();

        let (trusted_signers, hash_scanner, yara_rules, clamav, detectiteasy, hydradragonstatic_rules) =
            std::thread::scope(|s| {
                let t_signers = s.spawn(move || {
                    complist_path
                        .as_ref()
                        .filter(|p| p.exists())
                        .map(|p| TrustedSignerList::load(p))
                });

                let t_hash = s.spawn(move || {
                    bloom_dir.as_ref().filter(|p| p.exists()).map(|dir| {
                        let bloom = HashBloomFilter::with_base_dir(dir.clone());
                        HashScanner::with_bloom(bloom)
                    })
                });

                let t_yara = s.spawn(move || {
                    yara_rules_dir
                        .as_ref()
                        .filter(|p| p.exists())
                        .and_then(|dir| load_yara_rules_from_dir(dir.as_path()))
                });

                let t_clamav = s.spawn(move || {
                    if let Some(c) = existing_clamav {
                        Some(c)
                    } else {
                        clamav_lib
                            .as_ref()
                            .zip(clamav_db.as_ref())
                            .filter(|(lib, _)| lib.exists())
                            .and_then(|(lib, db)| ClamavScanner::new(lib, db).ok())
                    }
                });

                let t_die =
                    s.spawn(move || DetectItEasyScanner::new(detectiteasy_dir.as_deref()));

                let t_hds_rules = s.spawn(move || {
                    hydradragonstatic_rules_dir
                        .as_ref()
                        .filter(|p| p.exists())
                        .map(|dir| dir.join("rules.yaml"))
                        .filter(|p| p.exists())
                        .and_then(|rules_file| {
                            hydradragonstatic::rules::RuleSet::from_yaml_file(&rules_file).ok()
                        })
                });

                (
                    t_signers.join().expect("trusted_signers loader panicked"),
                    t_hash.join().expect("hash_scanner loader panicked"),
                    t_yara.join().expect("yara_rules loader panicked"),
                    t_clamav.join().expect("clamav loader panicked"),
                    t_die.join().expect("detectiteasy loader panicked"),
                    t_hds_rules.join().expect("hydradragonstatic rules loader panicked"),
                )
            });

        Self {
            config,
            trusted_signers,
            hash_scanner,
            yara_rules,
            clamav,
            detectiteasy,
            hydradragonstatic_rules,
        }
    }

    pub fn scan_file(&self, path: &Path) -> ScanResult {
        let mut engines: Vec<EngineResult> = Vec::new();
        let mut yara_x_matches = Vec::new();
        let mut clamav_result = None;
        let mut static_file_type: Option<FileTypeInfo> = None;

        let file_size = match path.metadata() {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                return ScanResult {
                    verdict: Verdict::Clean,
                    threat_name: None,
                    engines: vec![EngineResult {
                        engine: "file_io",
                        verdict: Verdict::Clean,
                        detail: format!("metadata error: {err}"),
                    }],
                    yara_x_matches: Vec::new(),
                    ml_malware_probability: None,
                    clamav_result: None,
                };
            }
        };

        if file_size > MAX_SCAN_FILE_SIZE {
            return ScanResult {
                verdict: Verdict::Clean,
                threat_name: None,
                engines: vec![EngineResult {
                    engine: "size_limit",
                    verdict: Verdict::Clean,
                    detail: format!("skipped: file is over 2 GiB ({file_size} bytes)"),
                }],
                yara_x_matches: Vec::new(),
                ml_malware_probability: None,
                clamav_result: None,
            };
        }

        // --- 1. HASH SCANNER ---
        if let Some(ref scanner) = self.hash_scanner {
            match scanner.compute_and_scan_all(path) {
                Ok(first_result) => {
                    let (verdict, detail) = if first_result == crate::hash_scanner::HashScanResult::Unknown {
                        (Verdict::Clean, "not found".into())
                    } else {
                        // Bloom filters have false positives; re-scan to confirm before trusting
                        match scanner.compute_and_scan_all(path) {
                            Ok(second_result) if second_result == first_result => {
                                match first_result {
                                    crate::hash_scanner::HashScanResult::Whitelisted => {
                                        (Verdict::Trusted, "MD5 whitelisted (confirmed)".into())
                                    }
                                    crate::hash_scanner::HashScanResult::Blacklisted => {
                                        (Verdict::Malware, "Hash blacklisted (confirmed)".into())
                                    }
                                    crate::hash_scanner::HashScanResult::Unknown => unreachable!(),
                                }
                            }
                            _ => (Verdict::Clean, "bloom match not confirmed on re-scan".into()),
                        }
                    };
                    engines.push(EngineResult {
                        engine: "bloom_filter",
                        verdict,
                        detail,
                    });

                    if verdict != Verdict::Clean {
                        return ScanResult {
                            verdict,
                            threat_name: None,
                            engines,
                            yara_x_matches: Vec::new(),
                            ml_malware_probability: None,
                            clamav_result: None,
                        };
                    }
                }
                Err(e) => {
                    engines.push(EngineResult {
                        engine: "bloom_filter",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                    });
                }
            }
        }

        // --- 2. TRUSTED SIGNER ---
        if let Some(ref trusted) = self.trusted_signers {
            let tv = check_trusted_signer(path, trusted);
            engines.push(EngineResult {
                engine: "trusted_signer",
                verdict: tv,
                detail: format!("{:?}", tv),
            });
            if tv == Verdict::Trusted {
                return ScanResult {
                    verdict: Verdict::Trusted,
                    threat_name: None,
                    engines,
                    yara_x_matches: Vec::new(),
                    ml_malware_probability: None,
                    clamav_result: None,
                };
            }
        }

        // --- 3. ML INFERENCE ---
        let ml_verdict = self.run_ml_inference(path);
        if let Some(ref mv) = ml_verdict {
            engines.push(EngineResult {
                engine: "ml",
                verdict: if mv.verdict == Verdict::Clean {
                    Verdict::Trusted
                } else {
                    mv.verdict
                },
                detail: format!("probability={:.4}", mv.probability),
            });

            if mv.verdict == Verdict::Clean {
                return ScanResult {
                    verdict: Verdict::Trusted,
                    threat_name: None,
                    engines,
                    yara_x_matches: Vec::new(),
                    ml_malware_probability: Some(mv.probability),
                    clamav_result: None,
                };
            }

            // SHORT-CIRCUIT: ML detected threat — exit immediately, don't let it
            // fall through and poison the final aggregate verdict at the end
            if matches!(mv.verdict, Verdict::Malware | Verdict::Suspicious) {
                return ScanResult {
                    verdict: mv.verdict,
                    threat_name: Some(format!("ml_detected (p={:.4})", mv.probability)),
                    engines,
                    yara_x_matches: Vec::new(),
                    ml_malware_probability: Some(mv.probability),
                    clamav_result: None,
                };
            }
        }

        // --- 4. STATIC RULES ---
        match &self.hydradragonstatic_rules {
            Some(rules) => match hydradragonstatic::scan_path(
                path,
                &rules,
                &hydradragonstatic::ScanOptions::default(),
            ) {
                Ok(report) => {
                    static_file_type = Some(report.file_type.clone());
                    let hv = match report.verdict {
                        hydradragonstatic::models::Verdict::Clean => Verdict::Clean,
                        hydradragonstatic::models::Verdict::Trusted => Verdict::Trusted,
                        hydradragonstatic::models::Verdict::Pua => Verdict::Pua,
                        hydradragonstatic::models::Verdict::Mining => Verdict::Mining,
                        hydradragonstatic::models::Verdict::Spam => Verdict::Spam,
                        hydradragonstatic::models::Verdict::Abuse => Verdict::Abuse,
                        hydradragonstatic::models::Verdict::Suspicious => Verdict::Suspicious,
                        hydradragonstatic::models::Verdict::Malware => Verdict::Malware,
                    };
                    engines.push(EngineResult {
                        engine: "hydradragonstatic",
                        verdict: hv,
                        detail: report.threat_name.clone().unwrap_or_default(),
                    });
                    
                    // SHORT-CIRCUIT: Any Detection
                    if matches!(hv, Verdict::Malware | Verdict::Abuse | Verdict::Suspicious | Verdict::Spam | Verdict::Mining | Verdict::Pua) {
                        return ScanResult {
                            verdict: hv,
                            threat_name: report.threat_name,
                            engines,
                            yara_x_matches,
                            ml_malware_probability: ml_verdict.as_ref().map(|m| m.probability),
                            clamav_result: None,
                        };
                    }
                }
                Err(e) => {
                    engines.push(EngineResult {
                        engine: "hydradragonstatic",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                    });
                }
            },
            None => {
                engines.push(EngineResult {
                    engine: "hydradragonstatic",
                    verdict: Verdict::Clean,
                    detail: "no hydradragonstatic rules loaded".into(),
                });
            }
        }

        // --- 5. URL / PHISHING BLOOM CHECK ---
        if let Some(ref scanner) = self.hash_scanner {
            let bloom = scanner.bloom();
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.len() <= 1_048_576 {
                    let urls: Vec<String> = content.lines()
                        .filter_map(|line| {
                            let line = line.trim();
                            if !line.contains("://") { return None; }
                            let cleaned = line.trim_end_matches(&[',', '.', ';', ')', ']', '}', '"', '\'']);
                            let url = cleaned.split_whitespace().next().unwrap_or(cleaned);
                            if !url.contains("://") { return None; }
                            Some(url.to_string())
                        })
                        .collect();

                    // first pass — collect candidates
                    let mut phishing_urls: Vec<String> = Vec::new();
                    let mut urlhaus_urls: Vec<String> = Vec::new();
                    for url in &urls {
                        if bloom.is_phishing(url) { phishing_urls.push(url.clone()); }
                        if bloom.is_urlhaus(url) { urlhaus_urls.push(url.clone()); }
                    }

                    // re-scan confirmation — re-read file, retain only confirmed hits
                    if !phishing_urls.is_empty() || !urlhaus_urls.is_empty() {
                        if let Ok(content2) = std::fs::read_to_string(path) {
                            let urls2: Vec<String> = content2.lines()
                                .filter_map(|line| {
                                    let line = line.trim();
                                    if !line.contains("://") { return None; }
                                    let cleaned = line.trim_end_matches(&[',', '.', ';', ')', ']', '}', '"', '\'']);
                                    let url = cleaned.split_whitespace().next().unwrap_or(cleaned);
                                    if !url.contains("://") { return None; }
                                    Some(url.to_string())
                                })
                                .collect();
                            phishing_urls.retain(|u| urls2.iter().any(|u2| u2 == u && bloom.is_phishing(u2)));
                            urlhaus_urls.retain(|u| urls2.iter().any(|u2| u2 == u && bloom.is_urlhaus(u2)));
                        }
                    }

                    if !phishing_urls.is_empty() {
                        engines.push(EngineResult {
                            engine: "phishing_bloom",
                            verdict: Verdict::Phishing,
                            detail: phishing_urls.join(", "),
                        });
                        return ScanResult {
                            verdict: Verdict::Phishing,
                            threat_name: Some("phishing_url".into()),
                            engines,
                            yara_x_matches: Vec::new(),
                            ml_malware_probability: None,
                            clamav_result: None,
                        };
                    }
                    if !urlhaus_urls.is_empty() {
                        engines.push(EngineResult {
                            engine: "urlhaus_bloom",
                            verdict: Verdict::Malware,
                            detail: urlhaus_urls.join(", "),
                        });
                        return ScanResult {
                            verdict: Verdict::Malware,
                            threat_name: Some("urlhaus_url".into()),
                            engines,
                            yara_x_matches: Vec::new(),
                            ml_malware_probability: None,
                            clamav_result: None,
                        };
                    }
                }
            }
        }

        // --- 6. CLAMAV ---
        if let Some(ref clamav) = self.clamav {
            match clamav.scan_file(path) {
                Ok(result) => {
                    if result.is_virus() {
                        clamav_result = Some(result.virus_name.clone());
                        let cv = if result.virus_name.starts_with("PUA.") {
                            Verdict::Pua
                        } else {
                            Verdict::Malware
                        };
                        engines.push(EngineResult {
                            engine: "clamav",
                            verdict: cv,
                            detail: result.virus_name.clone(),
                        });

                        // SHORT-CIRCUIT: ClamAV Detection
                        let final_verdict = Verdict::aggregate(&engines.iter().map(|e| e.verdict).collect::<Vec<_>>());
                        return ScanResult {
                            verdict: final_verdict,
                            threat_name: clamav_result.clone(),
                            engines,
                            yara_x_matches,
                            ml_malware_probability: ml_verdict.map(|m| m.probability),
                            clamav_result,
                        };
                    } else {
                        engines.push(EngineResult {
                            engine: "clamav",
                            verdict: Verdict::Clean,
                            detail: "clean".into(),
                        });
                    }
                }
                Err(e) => {
                    engines.push(EngineResult {
                        engine: "clamav",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                    });
                }
            }
        }

        // --- 7. YARA-X (final confirmation) ---
        if let Some(ref rules) = self.yara_rules {
            match scan_file_yara(path, rules) {
                Ok(matches) => {
                    yara_x_matches = matches.clone();
                    if !matches.is_empty() {
                        engines.push(EngineResult {
                            engine: "yara_x",
                            verdict: Verdict::Suspicious,
                            detail: matches.join(", "),
                        });

                        // DIE gate: suppress yara-only detection on unknown binaries
                        maybe_suppress_yara_only_unknown_binary(
                            path,
                            file_size,
                            &self.detectiteasy,
                            static_file_type.as_ref(),
                            &mut engines,
                            &mut yara_x_matches,
                        );

                        // Short-circuit if still detected after DIE gate
                        let still_detected = engines.iter().any(|e| matches!(e.verdict, Verdict::Malware | Verdict::Abuse | Verdict::Suspicious | Verdict::Spam | Verdict::Mining | Verdict::Pua | Verdict::Phishing));
                        if still_detected {
                            let final_verdict = Verdict::aggregate(&engines.iter().map(|e| e.verdict).collect::<Vec<_>>());
                            return ScanResult {
                                verdict: final_verdict,
                                threat_name: yara_x_matches.first().cloned(),
                                engines,
                                yara_x_matches,
                                ml_malware_probability: ml_verdict.map(|m| m.probability),
                                clamav_result,
                            };
                        }
                    } else {
                        engines.push(EngineResult {
                            engine: "yara_x",
                            verdict: Verdict::Clean,
                            detail: "no matches".into(),
                        });
                    }
                }
                Err(e) => {
                    engines.push(EngineResult {
                        engine: "yara_x",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                    });
                }
            }
        }

        // If we reach the end, no threats were detected across any of the engines
        let engine_verdicts: Vec<Verdict> = engines.iter().map(|e| e.verdict).collect();
        let final_verdict = Verdict::aggregate(&engine_verdicts);

        ScanResult {
            verdict: final_verdict,
            threat_name: None,
            engines,
            yara_x_matches,
            ml_malware_probability: ml_verdict.map(|m| m.probability),
            clamav_result,
        }
    }

    fn run_ml_inference(&self, path: &Path) -> Option<MlVerdict> {
        use burn::module::Module;
        use burn::record::{NamedMpkBytesRecorder, Recorder};
        use burn_ndarray::{NdArray, NdArrayDevice};
        type B = NdArray<f32>;

        let device = NdArrayDevice::default();
        let bytes = std::fs::read(path).ok()?;

        if let Some(model_path) = self.config.pe_ml_model_path.as_ref().filter(|p| p.exists()) {
            let model_bytes = std::fs::read(model_path).ok()?;
            let config = crate::ml::model::MalwareNetConfig::default();
            let record = NamedMpkBytesRecorder::<burn::record::FullPrecisionSettings>::default()
                .load(model_bytes, &device)
                .ok()?;
            let model: crate::ml::model::MalwareNet<B> =
                crate::ml::model::MalwareNet::new(&config, &device).load_record(record);

            if let Some(prob) = crate::ml::inference::predict_pe::<B>(&bytes, &model, &device) {
                let verdict = if prob >= self.config.ml_threshold {
                    Verdict::Malware
                } else if prob >= self.config.ml_threshold * 0.6 {
                    Verdict::Suspicious
                } else {
                    Verdict::Clean
                };
                return Some(MlVerdict { verdict, probability: prob });
            }
        }

        if let Some(model_path) = self.config.js_ml_model_path.as_ref().filter(|p| p.exists()) {
            let model_bytes = std::fs::read(model_path).ok()?;
            let config = crate::ml::model::MalwareNetConfig::default();
            let record = NamedMpkBytesRecorder::<burn::record::FullPrecisionSettings>::default()
                .load(model_bytes, &device)
                .ok()?;
            let model: crate::ml::model::MalwareNet<B> =
                crate::ml::model::MalwareNet::new(&config, &device).load_record(record);

            if let Ok(source) = String::from_utf8(bytes) {
                if let Some(prob) = crate::ml::inference::predict_js::<B>(&source, &model, &device) {
                    let verdict = if prob >= self.config.ml_threshold {
                        Verdict::Malware
                    } else if prob >= self.config.ml_threshold * 0.6 {
                        Verdict::Suspicious
                    } else {
                        Verdict::Clean
                    };
                    return Some(MlVerdict { verdict, probability: prob });
                }
            }
        }

        None
    }
}

struct MlVerdict {
    verdict: Verdict,
    probability: f32,
}

fn maybe_suppress_yara_only_unknown_binary(
    path: &Path,
    file_size: u64,
    detectiteasy: &DetectItEasyScanner,
    file_type: Option<&FileTypeInfo>,
    engines: &mut Vec<EngineResult>,
    yara_x_matches: &mut Vec<String>,
) {
    if yara_x_matches.is_empty() {
        return;
    }

    if file_size > MAX_DIE_FILE_SIZE {
        engines.push(EngineResult {
            engine: "detectiteasy",
            verdict: Verdict::Clean,
            detail: format!("skipped: file is over 100 MiB ({file_size} bytes)"),
        });
        return;
    }

    let Some(file_type) = file_type else {
        return;
    };

    if file_type.is_plain_text || !file_type.is_binary {
        return;
    }
    if file_type.primary != "unknown" {
        return;
    }
    if file_type.is_broken_executable || file_type.is_broken_apk {
        return;
    }

    let only_yara_is_suspicious = engines.iter().all(|engine| {
        if engine.engine == "yara_x" {
            matches!(engine.verdict, Verdict::Suspicious | Verdict::Abuse | Verdict::Malware)
        } else {
            matches!(engine.verdict, Verdict::Clean | Verdict::Trusted)
        }
    });
    if !only_yara_is_suspicious {
        return;
    }

    let die_result = detectiteasy.scan_file(path);
    if !die_result.scan_ok {
        engines.push(EngineResult {
            engine: "detectiteasy",
            verdict: Verdict::Clean,
            detail: format!(
                "gate unavailable: {}",
                die_result
                    .scan_error
                    .unwrap_or_else(|| "unknown error".to_string())
            ),
        });
        return;
    }

    if die_result.is_plain_text {
        engines.push(EngineResult {
            engine: "detectiteasy",
            verdict: Verdict::Clean,
            detail: "plain text; not suppressing yara result".into(),
        });
        return;
    }

    if die_result.is_unknown {
        for engine in engines
            .iter_mut()
            .filter(|engine| engine.engine == "yara_x")
        {
            engine.verdict = Verdict::Clean;
            engine.detail = format!(
                "suppressed yara-only unknown binary: {}",
                yara_x_matches.join(", ")
            );
        }
        yara_x_matches.clear();
        engines.push(EngineResult {
            engine: "detectiteasy",
            verdict: Verdict::Clean,
            detail: "DIE fully unknown; suppressing yara-only unknown binary".into(),
        });
    } else {
        let die_type = die_result
            .file_type
            .unwrap_or_else(|| "identified".to_string());
        engines.push(EngineResult {
            engine: "detectiteasy",
            verdict: Verdict::Clean,
            detail: format!("DIE identified file type: {die_type}"),
        });
    }
}

/// Run hayabusa once on all .evtx files in the standard Windows event log directory.
pub fn scan_hayabusa_once(hayabusa_dir: &Path) -> Vec<String> {
    use std::collections::HashSet;
    use std::process::Command;

    let exe = hayabusa_dir.join("hayabusa-3.9.0-win-x64.exe");
    if !exe.exists() {
        return Vec::new();
    }

    let evtx_dir = Path::new(r"C:\Windows\System32\winevt\Logs");
    if !evtx_dir.exists() {
        return Vec::new();
    }

    let mut all_matches: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    if let Ok(entries) = std::fs::read_dir(evtx_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("evtx") {
                continue;
            }

            let out = match Command::new(&exe)
                .args([
                    "csv-timeline",
                    "--no-wizard",
                    "--quiet",
                    "--file",
                    &path.to_string_lossy(),
                    "--rules",
                    &hayabusa_dir.join("rules").to_string_lossy().into_owned(),
                ])
                .output()
            {
                Ok(o) => o,
                Err(_) => continue,
            };

            let stdout = String::from_utf8_lossy(&out.stdout);
            for (i, line) in stdout.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                let cols: Vec<&str> = line.splitn(6, ',').collect();
                if let Some(title) = cols.get(4) {
                    let t = title.trim().trim_matches('"').to_string();
                    if !t.is_empty() && seen.insert(t.clone()) {
                        all_matches.push(t);
                    }
                }
            }
        }
    }
    all_matches
}

fn load_yara_rules_from_dir(dir: &Path) -> Option<Rules> {
    let mut compiler = Compiler::new();
    let mut compiled_rules: Vec<Rules> = Vec::new();
    let mut found_src = false;

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("yar") => {
                    if let Ok(source) = std::fs::read_to_string(&path) {
                        if compiler.add_source(source.as_str()).is_ok() {
                            found_src = true;
                        }
                    }
                }
                Some("yrc") => {
                    if let Ok(bytes) = std::fs::read(&path) {
                        if let Ok(rules) = Rules::deserialize(&bytes) {
                            compiled_rules.push(rules);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Return first compiled ruleset found (largest coverage), or text-compiled rules
    if let Some(r) = compiled_rules.into_iter().next() {
        return Some(r);
    }
    if found_src {
        Some(compiler.build())
    } else {
        None
    }
}

fn scan_file_yara(path: &Path, rules: &Rules) -> Result<Vec<String>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read error: {}", e))?;
    let mut scanner = YaraScanner::new(rules);
    let results = scanner
        .scan(&data)
        .map_err(|e| format!("scan error: {}", e))?;

    let matches: Vec<String> = results
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect();

    Ok(matches)
}

fn check_trusted_signer(path: &Path, trusted: &TrustedSignerList) -> Verdict {
    // Rely on hydradragonstatic's robust implementation instead of custom FFI
    let sig_info = hydradragonstatic::signature_verification::verify_signature(path);

    if sig_info.is_signed {
        if let Some(signer) = sig_info.signer_name {
            if trusted.is_trusted(&signer) {
                return Verdict::Trusted;
            }
        }
    }

    Verdict::Clean
}
