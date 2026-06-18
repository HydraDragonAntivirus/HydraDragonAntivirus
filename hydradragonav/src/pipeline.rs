use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::ValueEnum;
use hydradragonstatic::models::FileTypeInfo;
use hydradragonstatic::rules::RuleSet;
use yara_x::{Rules, Scanner as YaraScanner};

use burn::record::{NamedMpkBytesRecorder, Recorder};
use burn_ndarray::{NdArray, NdArrayDevice};

use crate::bloom_filter::HashBloomFilter;
use crate::hash_scanner::HashScanner;
use crate::scanner::Scanner as ClamavScanner;
use crate::verdict::{EngineResult, ScanResult, Verdict};

type InferBackend = NdArray<f32>;

/// Maximum file size (in bytes) for content scanning (2 GiB).
const MAX_SCAN_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ScanMode {
    #[default]
    Full,
    Files,
    NonFiles,
}

#[derive(Clone)]
pub struct PipelineConfig {
    pub bloom_dir: Option<PathBuf>,
    pub yara_rules_dir: Option<PathBuf>,
    pub hydradragonstatic_rules_dir: Option<PathBuf>,
    pub pe_ml_model_path: Option<PathBuf>,
    pub js_ml_model_path: Option<PathBuf>,
    pub clamav_lib: Option<PathBuf>,
    pub clamav_db: Option<PathBuf>,
    pub hayabusa_dir: Option<PathBuf>,
    pub scan_mode: ScanMode,
    pub ml_threshold: f32,
    pub clamav_heuristics: bool,
    pub time_engines: bool,
    pub fast_scan: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            bloom_dir: None,
            yara_rules_dir: None,
            hydradragonstatic_rules_dir: None,
            pe_ml_model_path: None,
            js_ml_model_path: None,
            clamav_lib: None,
            clamav_db: None,
            hayabusa_dir: None,
            scan_mode: ScanMode::default(),
            ml_threshold: 0.8,
            clamav_heuristics: false,
            time_engines: false,
            fast_scan: true,
        }
    }
}

pub struct Pipeline {
    config: PipelineConfig,
    hash_scanner: Option<HashScanner>,
    yara_rules: Vec<(String, Rules)>,
    clamav: Option<ClamavScanner>,
    hydradragonstatic_rules: Option<hydradragonstatic::rules::RuleSet>,
    excluded_yara_rules: HashSet<String>,
    pe_ml_model: Option<crate::ml::model::MalwareNet<InferBackend>>,
    js_ml_model: Option<crate::ml::model::MalwareNet<InferBackend>>,
}

impl Pipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self::new_impl(config)
    }

    fn new_impl(config: PipelineConfig) -> Self {
        let existing_clamav: Option<ClamavScanner> = None;
        let bloom_dir = config.bloom_dir.clone();
        let yara_rules_dir = config.yara_rules_dir.clone();
        let clamav_lib = config.clamav_lib.clone();
        let clamav_db = config.clamav_db.clone();
        let hydradragonstatic_rules_dir = config.hydradragonstatic_rules_dir.clone();
        let pe_ml_model_path = config.pe_ml_model_path.clone();
        let js_ml_model_path = config.js_ml_model_path.clone();

        // Load excluded rules line by line
        let mut excluded_yara_rules = HashSet::new();
        let exclusion_file_path = Path::new("excluded_yara_x_rules/excluded_yara_x_rules.txt");
        if exclusion_file_path.exists() {
            if let Ok(file) = File::open(exclusion_file_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        excluded_yara_rules.insert(trimmed.to_string());
                    }
                }
            }
        }

        let (hash_scanner, yara_rules, clamav, hydradragonstatic_rules, pe_ml_model, js_ml_model) =
            std::thread::scope(|s| {
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
                        .map(|dir| load_yara_rules_from_dir(dir.as_path()))
                        .unwrap_or_default()
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

                let t_hds_rules = s.spawn(move || {
                    let dir = hydradragonstatic_rules_dir.as_ref().filter(|p| p.exists());
                    if dir.is_none() {
                        return None;
                    }
                    let dir = dir.unwrap();
                    let mut rules = RuleSet::empty();

                    let rules_file = dir.join("rules.yaml");
                    if rules_file.exists() {
                        if let Ok(loaded) = RuleSet::from_yaml_file(&rules_file) {
                            rules.extend(loaded);
                        }
                    }

                    let trusted_file = dir.join("trusted_signers.yaml");
                    if trusted_file.exists() {
                        if let Ok(loaded) = RuleSet::from_yaml_file(&trusted_file) {
                            rules.extend(loaded);
                        }
                    }

                    if rules.rules().is_empty() { None } else { Some(rules) }
                });

                let t_pe_model = s.spawn(move || {
                    load_ml_model(
                        pe_ml_model_path.as_deref(),
                        crate::ml::model::MalwareNetConfig::default(),
                    )
                });

                let t_js_model = s.spawn(move || {
                    load_ml_model(
                        js_ml_model_path.as_deref(),
                        crate::ml::model::MalwareNetConfig::default_js(),
                    )
                });

                (
                    t_hash.join().expect("hash_scanner loader panicked"),
                    t_yara.join().expect("yara_rules loader panicked"),
                    t_clamav.join().expect("clamav loader panicked"),
                    t_hds_rules.join().expect("hydradragonstatic rules loader panicked"),
                    t_pe_model.join().expect("pe_model loader panicked"),
                    t_js_model.join().expect("js_model loader panicked"),
                )
            });

        Self {
            config,
            hash_scanner,
            yara_rules,
            clamav,
            hydradragonstatic_rules,
            excluded_yara_rules,
            pe_ml_model,
            js_ml_model,
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
                        elapsed_ms: None,
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
                    elapsed_ms: None,
                }],
                yara_x_matches: Vec::new(),
                ml_malware_probability: None,
                clamav_result: None,
            };
        }

        // --- 1. HASH SCANNER ---
        if let Some(ref scanner) = self.hash_scanner {
            let t0 = Instant::now();
            let bloom_outcome = match scanner.compute_and_scan_all(path) {
                Ok(first_result) => {
                    if first_result == crate::hash_scanner::HashScanResult::Unknown {
                        Ok((Verdict::Clean, "not found".into()))
                    } else {
                        match scanner.compute_and_scan_all(path) {
                            Ok(second_result) if second_result == first_result => {
                                match first_result {
                                    crate::hash_scanner::HashScanResult::Whitelisted => {
                                        Ok((Verdict::Trusted, "MD5 whitelisted (confirmed)".into()))
                                    }
                                    crate::hash_scanner::HashScanResult::Blacklisted => {
                                        Ok((Verdict::Malware, "Hash blacklisted (confirmed)".into()))
                                    }
                                    crate::hash_scanner::HashScanResult::Unknown => unreachable!(),
                                }
                            }
                            _ => Ok((Verdict::Clean, "bloom match not confirmed on re-scan".into())),
                        }
                    }
                }
                Err(e) => Err(format!("error: {}", e)),
            };
            let elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
            match bloom_outcome {
                Ok((verdict, detail)) => {
                    engines.push(EngineResult { engine: "bloom_filter", verdict, detail, elapsed_ms });
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
                Err(detail) => {
                    engines.push(EngineResult { engine: "bloom_filter", verdict: Verdict::Clean, detail, elapsed_ms });
                }
            }
        }

        // --- 2. ML INFERENCE ---
        let t0 = Instant::now();
        let ml_verdict = self.run_ml_inference(path);
        let ml_elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
        if let Some(ref mv) = ml_verdict {
            engines.push(EngineResult {
                engine: "ml",
                verdict: mv.verdict,
                detail: format!("probability={:.4}", mv.probability),
                elapsed_ms: ml_elapsed_ms,
            });

            // Any non-Clean ML verdict halts the scan. Trusted returns a clean-style
            // trusted result; every other detection returns with its threat name.
            if mv.verdict == Verdict::Trusted {
                return ScanResult {
                    verdict: Verdict::Trusted,
                    threat_name: None,
                    engines,
                    yara_x_matches: Vec::new(),
                    ml_malware_probability: Some(mv.probability),
                    clamav_result: None,
                };
            }
            if mv.verdict != Verdict::Clean {
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

        // --- 3. STATIC RULES ---
        let t0 = Instant::now();
        match &self.hydradragonstatic_rules {
            Some(rules) => match hydradragonstatic::scan_path(
                path,
                &rules,
                &hydradragonstatic::ScanOptions::default(),
            ) {
                Ok(report) => {
                    let elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
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
                        elapsed_ms,
                    });

                    // DEĞİŞİKLİK BURADA: Eğer static kurallar Trusted dediyse,
                    // alt taraftaki ClamAV/Yara aşamalarına girmeden DOĞRUDAN güvenli sonucu dön!
                    if hv == Verdict::Trusted {
                        return ScanResult {
                            verdict: Verdict::Trusted,
                            threat_name: None,
                            engines,
                            yara_x_matches,
                            ml_malware_probability: ml_verdict.as_ref().map(|m| m.probability),
                            clamav_result: None,
                        };
                    }

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
                    let elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
                    engines.push(EngineResult {
                        engine: "hydradragonstatic",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                        elapsed_ms,
                    });
                }
            },
            None => {
                engines.push(EngineResult {
                    engine: "hydradragonstatic",
                    verdict: Verdict::Clean,
                    detail: "no hydradragonstatic rules loaded".into(),
                    elapsed_ms: None,
                });
            }
        }

        // --- 5. URL / PHISHING BLOOM CHECK ---
        // Reads raw bytes and extracts printable ASCII strings (like `strings` utility)
        // so URLs embedded in PE/binary files are also found, not just text files.
        if let Some(ref scanner) = self.hash_scanner {
            let bloom = scanner.bloom();
            let t0 = Instant::now();
            if let Ok(bytes) = std::fs::read(path) {
                if bytes.len() <= 1_048_576 {
                    let urls = extract_urls_from_bytes(&bytes);

                    let mut phishing_urls: Vec<String> = Vec::new();
                    let mut urlhaus_urls: Vec<String> = Vec::new();
                    for url in &urls {
                        if bloom.is_phishing(url) { phishing_urls.push(url.clone()); }
                        if bloom.is_urlhaus(url) { urlhaus_urls.push(url.clone()); }
                    }

                    let elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
                    if !phishing_urls.is_empty() {
                        engines.push(EngineResult {
                            engine: "phishing_bloom",
                            verdict: Verdict::Phishing,
                            detail: phishing_urls.join(", "),
                            elapsed_ms,
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
                            elapsed_ms,
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
            let t0 = Instant::now();
            match clamav.scan_file(path, self.config.clamav_heuristics) {
                Ok(result) => {
                    let elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
                    if result.is_virus() {
                        clamav_result = Some(result.virus_name.clone());
                        let cv = if result.virus_name.starts_with("PUA.") {
                            Verdict::Pua
                        } else {
                            Verdict::Malware
                        };
                        engines.push(EngineResult { engine: "clamav", verdict: cv, detail: result.virus_name.clone(), elapsed_ms });

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
                        engines.push(EngineResult { engine: "clamav", verdict: Verdict::Clean, detail: "clean".into(), elapsed_ms });
                    }
                }
                Err(e) => {
                    let elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);
                    engines.push(EngineResult { engine: "clamav", verdict: Verdict::Clean, detail: format!("error: {}", e), elapsed_ms });
                }
            }
        }

        // --- 7. YARA-X (final confirmation) ---
        // DetectItEasy is run lazily only when YARA-X produces a detection, since
        // its only consumer is the yara-only-unknown-binary suppression check.
        if self.yara_rules.is_empty() {
            engines.push(EngineResult {
                engine: "yara_x",
                verdict: Verdict::Clean,
                detail: "no rules loaded".into(),
                elapsed_ms: None,
            });
        } else {
            let t0 = Instant::now();
            let mut all_matches: Vec<String> = Vec::new();
            let mut scan_error: Option<String> = None;

            // File type is already known from the hydradragonstatic stage (stage 4),
            // so type-specific ML rulesets are gated on those flags instead of having
            // YARA-X re-detect the type. machine_learning_pe runs only on PE files,
            // machine_learning_js only on JavaScript; all other rulesets always run.
            let is_pe = static_file_type.as_ref().is_some_and(|ft| ft.is_pe);
            let is_js = static_file_type.as_ref().is_some_and(|ft| ft.is_javascript);

            // Read the file once and reuse the buffer across every ruleset.
            match std::fs::read(path) {
                Ok(data) => {
                    for (name, rules) in &self.yara_rules {
                        let applies = match name.as_str() {
                            "machine_learning_pe" => is_pe,
                            "machine_learning_js" => is_js,
                            _ => true,
                        };
                        if !applies {
                            continue;
                        }
                        match scan_bytes_yara(&data, rules, &self.excluded_yara_rules, self.config.fast_scan) {
                            Ok(mut m) => all_matches.append(&mut m),
                            Err(e) => {
                                scan_error = Some(e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    scan_error = Some(format!("read error: {}", e));
                }
            }
            let yara_elapsed_ms = self.config.time_engines.then(|| t0.elapsed().as_millis() as u64);

            if let Some(e) = scan_error {
                engines.push(EngineResult {
                    engine: "yara_x",
                    verdict: Verdict::Clean,
                    detail: format!("error: {}", e),
                    elapsed_ms: yara_elapsed_ms,
                });
            } else if !all_matches.is_empty() {
                yara_x_matches = all_matches.clone();
                let yara_verdict = if all_matches.iter().any(|m| m.contains("_PUA_")) {
                    Verdict::Pua
                } else {
                    Verdict::Malware
                };
                engines.push(EngineResult {
                    engine: "yara_x",
                    verdict: yara_verdict,
                    detail: all_matches.join(", "),
                    elapsed_ms: yara_elapsed_ms,
                });

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
                    elapsed_ms: yara_elapsed_ms,
                });
            }
        }

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
        let device = NdArrayDevice::default();
        let bytes = std::fs::read(path).ok()?;

        if let Some(ref model) = self.pe_ml_model {
            if let Some(prob) = crate::ml::inference::predict_pe::<InferBackend>(&bytes, model, &device) {
                return Some(MlVerdict {
                    verdict: ml_classify(prob, self.config.ml_threshold),
                    probability: prob,
                });
            }
        }

        if let Some(ref model) = self.js_ml_model {
            if let Ok(source) = String::from_utf8(bytes) {
                if let Some(prob) = crate::ml::inference::predict_js::<InferBackend>(&source, model, &device) {
                    return Some(MlVerdict {
                        verdict: ml_classify(prob, self.config.ml_threshold),
                        probability: prob,
                    });
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

fn ml_classify(prob: f32, threshold: f32) -> Verdict {
    if prob >= threshold {
        Verdict::Malware
    } else if prob >= threshold * 0.875 {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

fn load_ml_model(
    path: Option<&Path>,
    config: crate::ml::model::MalwareNetConfig,
) -> Option<crate::ml::model::MalwareNet<InferBackend>> {
    use burn::module::Module;
    let path = path.filter(|p| p.exists())?;
    let bytes = std::fs::read(path).ok()?;
    let device = NdArrayDevice::default();
    let record = NamedMpkBytesRecorder::<burn::record::FullPrecisionSettings>::default()
        .load(bytes, &device)
        .ok()?;
    Some(crate::ml::model::MalwareNet::new(&config, &device).load_record(record))
}

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

    let out = match Command::new(&exe)
        .args([
            "csv-timeline",
            "--no-wizard",
            "--quiet",
            "--directory",
            &evtx_dir.to_string_lossy(),
            "--rules",
            &hayabusa_dir.join("rules").to_string_lossy().into_owned(),
        ])
        .current_dir(hayabusa_dir)
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let mut all_matches: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let stdout = String::from_utf8_lossy(&out.stdout);
    for (i, line) in stdout.lines().enumerate() {
        if i == 0 {
            continue; // skip CSV header
        }
        let cols: Vec<&str> = line.splitn(6, ',').collect();
        if let Some(title) = cols.get(4) {
            let t = title.trim().trim_matches('"').to_string();
            if !t.is_empty() && seen.insert(t.clone()) {
                all_matches.push(t);
            }
        }
    }
    all_matches
}

fn load_yara_rules_from_dir(dir: &Path) -> Vec<(String, Rules)> {
    // Collect .yrc paths first so we can load them in a deterministic, prefix-
    // controllable order. With first-match-wins scanning, order decides which
    // ruleset gets the chance to fire first, so it must not depend on the
    // filesystem's directory-iteration order.
    let mut paths: Vec<PathBuf> = Vec::new();

    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) == Some("yrc") {
                paths.push(path);
            }
        }
    }

    paths.sort();

    let mut loaded: Vec<(String, Rules)> = Vec::new();
    for path in paths {
        // The file stem (e.g. "machine_learning_pe") is the routing key used to
        // gate type-specific rulesets in scan_file.
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        match std::fs::read(&path) {
            Ok(bytes) => match Rules::deserialize(&bytes) {
                Ok(rules) => loaded.push((stem, rules)),
                Err(e) => eprintln!("[YARA] failed to load {}: {}", path.display(), e),
            },
            Err(e) => eprintln!("[YARA] failed to read {}: {}", path.display(), e),
        }
    }

    eprintln!("[YARA] loaded {} ruleset(s) from {}", loaded.len(), dir.display());
    loaded
}

// Scans an already-read byte buffer against one ruleset. Pulling the file read
// out of here lets scan_file read the bytes once and reuse them across every
// ruleset instead of re-reading the file per ruleset.
fn scan_bytes_yara(data: &[u8], rules: &Rules, exclusions: &HashSet<String>, fast_scan: bool) -> Result<Vec<String>, String> {
    let mut scanner = YaraScanner::new(rules);
    if fast_scan {
        scanner.fast_scan(true);
    }
    let results = scanner
        .scan(data)
        .map_err(|e| format!("scan error: {}", e))?;

    let matches: Vec<String> = results
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .filter(|rule_id| !exclusions.contains(rule_id))
        .collect();

    Ok(matches)
}

// Extracts URL-like strings from raw bytes by scanning for printable ASCII runs
// that contain "://" — works on binary files (PE, ELF, etc.) as well as text.
fn extract_urls_from_bytes(bytes: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= 8 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    for token in s.split_whitespace() {
                        if token.contains("://") {
                            let cleaned = token.trim_end_matches(&[',', '.', ';', ')', ']', '}', '"', '\''] as &[char]);
                            if cleaned.len() >= 8 {
                                urls.push(cleaned.to_string());
                            }
                        }
                    }
                }
            }
            current.clear();
        }
    }
    // flush last run
    if current.len() >= 8 {
        if let Ok(s) = std::str::from_utf8(&current) {
            for token in s.split_whitespace() {
                if token.contains("://") {
                    let cleaned = token.trim_end_matches(&[',', '.', ';', ')', ']', '}', '"', '\''] as &[char]);
                    if cleaned.len() >= 8 {
                        urls.push(cleaned.to_string());
                    }
                }
            }
        }
    }
    urls
}


