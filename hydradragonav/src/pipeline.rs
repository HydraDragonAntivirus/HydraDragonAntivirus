use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::ValueEnum;
use fastbloom::AtomicBloomFilter;
use md5::{Digest, Md5};
use hydradragonsig::models::FileTypeInfo;
use hydradragonsig::rules::RuleSet;
use yara_x::{MetaValue, Rules, Scanner as YaraScanner};

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
    pub hydradragonsig_rules_dir: Option<PathBuf>,
    pub pe_ml_model_path: Option<PathBuf>,
    pub js_ml_model_path: Option<PathBuf>,
    pub clamav_db: Option<PathBuf>,
    pub hayabusa_dir: Option<PathBuf>,
    pub scan_mode: ScanMode,
    pub ml_threshold: f32,
    pub clamav_heuristics: bool,
    pub time_engines: bool,
    pub fast_scan: bool,
    /// Directory for the persisted duplicate-dedup result blooms
    /// (`good_results.bloom` / `bad_results.bloom`). `None` = in-memory only.
    pub results_cache_dir: Option<PathBuf>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            bloom_dir: None,
            yara_rules_dir: None,
            hydradragonsig_rules_dir: None,
            pe_ml_model_path: None,
            js_ml_model_path: None,
            clamav_db: None,
            hayabusa_dir: None,
            scan_mode: ScanMode::default(),
            ml_threshold: 0.8,
            clamav_heuristics: false,
            time_engines: false,
            fast_scan: true,
            results_cache_dir: None,
        }
    }
}

pub struct Pipeline {
    config: PipelineConfig,
    hash_scanner: Option<HashScanner>,
    yara_rules: Vec<(String, Rules)>,
    clamav: Option<ClamavScanner>,
    hydradragonsig_rules: Option<hydradragonsig::rules::RuleSet>,
    excluded_yara_rules: HashSet<String>,
    pe_ml_model: Option<crate::ml::model::MalwareNet<InferBackend>>,
    js_ml_model: Option<crate::ml::model::MalwareNet<InferBackend>>,
    // Duplicate-dedup result cache (see `scan_file_cached`). Clean MD5s go into
    // `good_bloom`, malicious MD5s into `bad_bloom` (both fast atomic blooms,
    // `&self` inserts). Persisted to `results_cache_dir` as good_results.bloom /
    // bad_results.bloom when that dir is configured.
    good_bloom: AtomicBloomFilter,
    bad_bloom: AtomicBloomFilter,
    results_cache_dir: Option<PathBuf>,
}

const GOOD_BLOOM_FILE: &str = "good_results.bloom";
const BAD_BLOOM_FILE: &str = "bad_results.bloom";

// Result-cache sizing. Both blooms use a light 1e-4 false-positive rate to keep
// memory small (~1.2 MB each at the rated capacity). False positives are made
// harmless by design: a bad-bloom hit is re-scanned (so a clean file is never
// falsely flagged — see `scan_file_cached`). The rate holds up to ~500k distinct
// files; past that it gradually degrades.
const CACHE_CAPACITY: usize = 500_000;
const CACHE_FP: f64 = 1e-4;

fn fresh_bloom() -> AtomicBloomFilter {
    AtomicBloomFilter::with_false_pos(CACHE_FP).expected_items(CACHE_CAPACITY)
}

/// Loads a result bloom from `dir/name`, or a fresh empty one if absent/corrupt.
fn load_result_bloom(dir: &Option<PathBuf>, name: &str) -> AtomicBloomFilter {
    if let Some(d) = dir {
        let path = d.join(name);
        if let Ok(data) = std::fs::read(&path) {
            if let Ok((bf, _)) = bincode_next::serde::decode_from_slice::<AtomicBloomFilter, _>(
                &data,
                bincode_next::config::standard(),
            ) {
                return bf;
            }
        }
    }
    fresh_bloom()
}

/// Builds a `ScanResult` served from the dedup cache (a single synthetic "cache"
/// engine entry), without re-running any engine.
fn cache_result(verdict: Verdict, threat: Option<String>, detail: &str) -> ScanResult {
    ScanResult {
        verdict,
        threat_name: threat,
        engines: vec![EngineResult {
            engine: "cache",
            verdict,
            detail: detail.to_string(),
            elapsed_ms: Some(0),
        }],
        yara_x_matches: Vec::new(),
        ml_malware_probability: None,
        clamav_result: None,
    }
}

impl Pipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self::new_impl(config)
    }

    fn new_impl(config: PipelineConfig) -> Self {
        let existing_clamav: Option<ClamavScanner> = None;
        let bloom_dir = config.bloom_dir.clone();
        let yara_rules_dir = config.yara_rules_dir.clone();
        let clamav_db = config.clamav_db.clone();
        let hydradragonsig_rules_dir = config.hydradragonsig_rules_dir.clone();
        let pe_ml_model_path = config.pe_ml_model_path.clone();
        let js_ml_model_path = config.js_ml_model_path.clone();
        let results_cache_dir = config.results_cache_dir.clone();

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

        let (hash_scanner, yara_rules, clamav, hydradragonsig_rules, pe_ml_model, js_ml_model) =
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
                        match clamav_db.as_ref() {
                            Some(db) if db.exists() => match ClamavScanner::new(db) {
                                Ok(scanner) => Some(scanner),
                                // Don't let a DB problem silently disable ClamAV —
                                // surface why so it's diagnosable.
                                Err(e) => {
                                    log::error!(
                                        "ClamAV disabled: failed to load database {:?}: {}",
                                        db, e
                                    );
                                    eprintln!(
                                        "[ClamAV] disabled: failed to load database {:?}: {}",
                                        db, e
                                    );
                                    None
                                }
                            },
                            Some(db) => {
                                log::warn!("ClamAV disabled: database path {:?} does not exist", db);
                                None
                            }
                            None => None,
                        }
                    }
                });

                let t_hds_rules = s.spawn(move || {
                    let dir = hydradragonsig_rules_dir.as_ref().filter(|p| p.exists());
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

                    if rules.rules().is_empty() {
                        None
                    } else {
                        Some(rules)
                    }
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
                    t_hds_rules
                        .join()
                        .expect("hydradragonsig rules loader panicked"),
                    t_pe_model.join().expect("pe_model loader panicked"),
                    t_js_model.join().expect("js_model loader panicked"),
                )
            });

        Self {
            config,
            hash_scanner,
            yara_rules,
            clamav,
            hydradragonsig_rules,
            excluded_yara_rules,
            pe_ml_model,
            js_ml_model,
            // Result blooms — loaded from disk if a cache dir is configured.
            good_bloom: load_result_bloom(&results_cache_dir, GOOD_BLOOM_FILE),
            bad_bloom: load_result_bloom(&results_cache_dir, BAD_BLOOM_FILE),
            results_cache_dir,
        }
    }

    /// Like [`scan_file`](Self::scan_file) but transparently deduplicates by file
    /// content (MD5). A file whose hash is in the **good** bloom is served as clean
    /// without re-running the engines (the common case — this is the speed-up). A
    /// hash in the **bad** bloom is RE-SCANNED to confirm: the bloom is only a
    /// hint, never trusted for a detection, so a bloom false positive can never
    /// flag a clean file as malware — it just costs one re-scan. Files over 64 MiB
    /// bypass the cache. The returned [`ScanResult`] matches `scan_file`.
    /// Total signatures/rules loaded across the engines (ClamAV + hydradragonsig
    /// static rules). Shown in the UI when the engine becomes ready.
    pub fn loaded_signature_count(&self) -> usize {
        let clamav = self.clamav.as_ref().map(|c| c.signature_count()).unwrap_or(0);
        let hds = self
            .hydradragonsig_rules
            .as_ref()
            .map(|r| r.rules().len())
            .unwrap_or(0);
        let yara = self.yara_rules.len();
        clamav + hds + yara
    }

    pub fn scan_file_cached(&self, path: &Path) -> ScanResult {
        const CACHE_FILE_MAX: u64 = 64 * 1024 * 1024;

        // Read the file ONCE and reuse the buffer for both the MD5 dedup key and
        // the scan — so a cache miss is no slower than a plain scan.
        let too_big = std::fs::metadata(path)
            .map(|m| m.len() > CACHE_FILE_MAX)
            .unwrap_or(true);
        if let Some(data) = (!too_big).then(|| std::fs::read(path).ok()).flatten() {
            let h: [u8; 16] = Md5::digest(&data).into();
            // Known-good → trust it, skip the engines. Known-bad → re-scan to
            // confirm (the bloom is only a hint, never a detection on its own).
            if !self.bad_bloom.contains(&h) && self.good_bloom.contains(&h) {
                return cache_result(Verdict::Clean, None, "cached clean (dedup)");
            }
            let result = self.scan_loaded(path, &data, h); // reuse the MD5 we computed
            if result.verdict.priority() <= 1 {
                self.good_bloom.insert(&h); // build the bloom while scanning
            } else {
                self.bad_bloom.insert(&h);
            }
            return result;
        }

        // Too large / unreadable to cache — plain single-read scan.
        self.scan_file(path)
    }

    /// Persists the good/bad result blooms to `results_cache_dir` (if configured)
    /// so learned results survive across runs. Cheap to call after a scan batch.
    pub fn save_result_caches(&self) {
        let Some(dir) = &self.results_cache_dir else { return };
        let _ = std::fs::create_dir_all(dir);
        let cfg = bincode_next::config::standard();
        for (bloom, name) in [(&self.good_bloom, GOOD_BLOOM_FILE), (&self.bad_bloom, BAD_BLOOM_FILE)] {
            if let Ok(bytes) = bincode_next::serde::encode_to_vec(bloom, cfg) {
                let _ = std::fs::write(dir.join(name), bytes);
            }
        }
    }

    /// Wipes both result blooms (in memory and on disk). Exposed for an "advanced
    /// settings" reset — NOT recommended, as the scanner then re-scans everything
    /// and forgets every learned good/bad result.
    pub fn clear_result_caches(&mut self) {
        self.good_bloom = fresh_bloom();
        self.bad_bloom = fresh_bloom();
        if let Some(dir) = &self.results_cache_dir {
            let _ = std::fs::remove_file(dir.join(GOOD_BLOOM_FILE));
            let _ = std::fs::remove_file(dir.join(BAD_BLOOM_FILE));
        }
    }

    pub fn scan_file(&self, path: &Path) -> ScanResult {
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

        // Read the file ONCE; every engine then scans this buffer. This speeds up
        // the first scan too (the file used to be read 6-7 times internally).
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(err) => {
                return ScanResult {
                    verdict: Verdict::Clean,
                    threat_name: None,
                    engines: vec![EngineResult {
                        engine: "file_io",
                        verdict: Verdict::Clean,
                        detail: format!("read error: {err}"),
                        elapsed_ms: None,
                    }],
                    yara_x_matches: Vec::new(),
                    ml_malware_probability: None,
                    clamav_result: None,
                };
            }
        };
        let md5: [u8; 16] = Md5::digest(&data).into();
        self.scan_loaded(path, &data, md5)
    }

    /// Core scan over an already-read buffer — one gate (single read), one scanner.
    /// `md5` is the buffer's MD5 digest, computed once by the caller and reused
    /// here (so the bytes are never hashed twice). `path` is used only for labels
    /// and the hydradragonsig identifier; every engine runs from `data`.
    fn scan_loaded(&self, path: &Path, data: &[u8], md5: [u8; 16]) -> ScanResult {
        let mut engines: Vec<EngineResult> = Vec::new();
        let mut yara_x_matches = Vec::new();
        let mut clamav_result = None;
        let mut static_file_type: Option<FileTypeInfo> = None;

        // --- 1. HASH SCANNER (single bloom: md5/sha1/sha256/ssdeep/tlsh) ---
        // Old-style: every signature type sits in one bloom and is matched by
        // exact membership; the matched hash type is reported in the detail.
        if let Some(ref scanner) = self.hash_scanner {
            let t0 = Instant::now();
            let (result, which) = scanner.scan_all_buffer(data, &hex::encode(md5));
            let (verdict, detail) = match result {
                crate::hash_scanner::HashScanResult::Whitelisted => {
                    (Verdict::Trusted, format!("{which} whitelisted"))
                }
                crate::hash_scanner::HashScanResult::Blacklisted => {
                    (Verdict::Malware, format!("{which} blacklisted"))
                }
                crate::hash_scanner::HashScanResult::Unknown => {
                    (Verdict::Clean, "not found".to_string())
                }
            };
            let elapsed_ms = self
                .config
                .time_engines
                .then(|| t0.elapsed().as_millis() as u64);
            engines.push(EngineResult {
                engine: "bloom_filter",
                verdict,
                detail,
                elapsed_ms,
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

        // --- 2. ML INFERENCE ---
        // Detect the file class up front so each model only runs on its own type
        // (the JS model must NOT see XML/HTML/text). Same classifier the static
        // stage uses, so the flags match the YARA ML-ruleset gating below.
        let t0 = Instant::now();
        let ml_file_type = hydradragonsig::scanner::filetype::classify_bytes(path, data);
        let ml_verdict =
            self.run_ml_inference_bytes(data, ml_file_type.is_pe, ml_file_type.is_javascript);
        let ml_elapsed_ms = self
            .config
            .time_engines
            .then(|| t0.elapsed().as_millis() as u64);
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
        match &self.hydradragonsig_rules {
            Some(rules) => {
                // One gate, one scanner: scan the in-memory buffer (no file read).
                let mem_ctx = hydradragonsig::models::MemoryScanContext {
                    buffer: data.to_vec(),
                    identifier: path.display().to_string(),
                    base_address: None,
                };
                match hydradragonsig::scan_memory(
                    &mem_ctx,
                    &rules,
                    &hydradragonsig::ScanOptions::default(),
                ) {
                Ok(report) => {
                    let elapsed_ms = self
                        .config
                        .time_engines
                        .then(|| t0.elapsed().as_millis() as u64);
                    static_file_type = Some(report.file_type.clone());
                    let hv = match report.verdict {
                        hydradragonsig::models::Verdict::Clean => Verdict::Clean,
                        hydradragonsig::models::Verdict::Trusted => Verdict::Trusted,
                        hydradragonsig::models::Verdict::Pua => Verdict::Pua,
                        hydradragonsig::models::Verdict::Suspicious => Verdict::Suspicious,
                        hydradragonsig::models::Verdict::Malware => Verdict::Malware,
                    };
                    engines.push(EngineResult {
                        engine: "hydradragonsig",
                        verdict: hv,
                        detail: report.threat_name.clone().unwrap_or_default(),
                        elapsed_ms,
                    });

                    // A Trusted verdict short-circuits the remaining ClamAV/YARA stages.
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

                    if matches!(
                        hv,
                        Verdict::Malware
                            | Verdict::Suspicious
                            | Verdict::Pua
                    ) {
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
                    let elapsed_ms = self
                        .config
                        .time_engines
                        .then(|| t0.elapsed().as_millis() as u64);
                    engines.push(EngineResult {
                        engine: "hydradragonsig",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                        elapsed_ms,
                    });
                }
                }
            }
            None => {
                engines.push(EngineResult {
                    engine: "hydradragonsig",
                    verdict: Verdict::Clean,
                    detail: "no hydradragonsig rules loaded".into(),
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
            if data.len() <= 1_048_576 {
                {
                    let urls = extract_urls_from_bytes(data);

                    let mut phishing_urls: Vec<String> = Vec::new();
                    let mut urlhaus_urls: Vec<String> = Vec::new();
                    for url in &urls {
                        if bloom.is_phishing(url) {
                            phishing_urls.push(url.clone());
                        }
                        if bloom.is_urlhaus(url) {
                            urlhaus_urls.push(url.clone());
                        }
                    }

                    let elapsed_ms = self
                        .config
                        .time_engines
                        .then(|| t0.elapsed().as_millis() as u64);
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
            match clamav.scan_bytes(data) {
                Ok(result) => {
                    let elapsed_ms = self
                        .config
                        .time_engines
                        .then(|| t0.elapsed().as_millis() as u64);
                    if result.is_virus() {
                        clamav_result = Some(result.virus_name.clone());
                        let cv = if result.virus_name.starts_with("PUA.") {
                            Verdict::Pua
                        } else {
                            Verdict::Malware
                        };
                        engines.push(EngineResult {
                            engine: "clamav",
                            // Tag detections from unofficial third-party databases so
                            // the report/CSV shows e.g. "clamav: Name (unofficial)".
                            verdict: cv,
                            detail: if result.unofficial {
                                format!("{} (unofficial)", result.virus_name)
                            } else {
                                result.virus_name.clone()
                            },
                            elapsed_ms,
                        });

                        let final_verdict = Verdict::aggregate(
                            &engines.iter().map(|e| e.verdict).collect::<Vec<_>>(),
                        );
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
                            elapsed_ms,
                        });
                    }
                }
                Err(e) => {
                    let elapsed_ms = self
                        .config
                        .time_engines
                        .then(|| t0.elapsed().as_millis() as u64);
                    engines.push(EngineResult {
                        engine: "clamav",
                        verdict: Verdict::Clean,
                        detail: format!("error: {}", e),
                        elapsed_ms,
                    });
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
            let mut all_matches: Vec<YaraHit> = Vec::new();
            let mut scan_error: Option<String> = None;

            // File type is already known from the hydradragonsig stage (stage 4),
            // so type-specific ML rulesets are gated on those flags instead of having
            // YARA-X re-detect the type. machine_learning_pe runs only on PE files,
            // machine_learning_js only on JavaScript; all other rulesets always run.
            let is_pe = static_file_type.as_ref().is_some_and(|ft| ft.is_pe);
            let is_js = static_file_type.as_ref().is_some_and(|ft| ft.is_javascript);

            // Reuse the single buffer across every ruleset.
            {
                {
                    for (name, rules) in &self.yara_rules {
                        let applies = match name.as_str() {
                            "machine_learning_pe" => is_pe,
                            "machine_learning_js" => is_js,
                            _ => true,
                        };
                        if !applies {
                            continue;
                        }
                        match scan_bytes_yara(
                            data,
                            rules,
                            &self.excluded_yara_rules,
                            self.config.fast_scan,
                        ) {
                            Ok(mut m) => all_matches.append(&mut m),
                            Err(e) => {
                                scan_error = Some(e);
                                break;
                            }
                        }
                    }
                }
            }
            let yara_elapsed_ms = self
                .config
                .time_engines
                .then(|| t0.elapsed().as_millis() as u64);

            if let Some(e) = scan_error {
                engines.push(EngineResult {
                    engine: "yara_x",
                    verdict: Verdict::Clean,
                    detail: format!("error: {}", e),
                    elapsed_ms: yara_elapsed_ms,
                });
            } else if !all_matches.is_empty() {
                yara_x_matches = yara_hit_names(&all_matches);
                match classify_yara_verdict(&all_matches) {
                    Some(yara_verdict) => {
                        engines.push(EngineResult {
                            engine: "yara_x",
                            verdict: yara_verdict,
                            detail: yara_x_matches.join(", "),
                            elapsed_ms: yara_elapsed_ms,
                        });

                        let still_detected = engines.iter().any(|e| {
                            matches!(
                                e.verdict,
                                Verdict::Malware
                                    | Verdict::Suspicious
                                    | Verdict::Pua
                                    | Verdict::Phishing
                            )
                        });
                        if still_detected {
                            let final_verdict = Verdict::aggregate(
                                &engines.iter().map(|e| e.verdict).collect::<Vec<_>>(),
                            );
                            return ScanResult {
                                verdict: final_verdict,
                                threat_name: yara_x_matches.first().cloned(),
                                engines,
                                yara_x_matches,
                                ml_malware_probability: ml_verdict.map(|m| m.probability),
                                clamav_result,
                            };
                        }
                    }
                    None => {
                        // Only informational (INFO_) rules matched — not a threat.
                        engines.push(EngineResult {
                            engine: "yara_x",
                            verdict: Verdict::Clean,
                            detail: format!("informational: {}", yara_x_matches.join(", ")),
                            elapsed_ms: yara_elapsed_ms,
                        });
                    }
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

    /// Recover the matched signature byte ranges (file offsets) for a file, for
    /// in-place disinfection. Unions ClamAV arenas, YARA-X match ranges, and the
    /// byte ranges of any phishing/URLhaus URLs found by the bloom filters. All
    /// of these engines scan the raw file bytes, so the offsets map to the file.
    ///
    /// All YARA rulesets are run (no per-type gating): over-neutralizing a few
    /// extra suspicious regions in a known-malicious file is harmless.
    pub fn arenas_for_file(&self, path: &Path) -> Vec<(usize, usize)> {
        let mut arenas: Vec<(usize, usize)> = Vec::new();

        // Read the file ONCE; every engine below scans this same buffer.
        let Ok(data) = std::fs::read(path) else {
            return arenas;
        };

        if let Some(ref clamav) = self.clamav {
            // Disinfection must neutralize EVERY malicious region, so collect all
            // matches here — not the first-match-only fast verdict scan.
            if let Ok(result) = clamav.scan_bytes_all(&data) {
                arenas.extend(result.arenas.iter().copied());
            }
        }

        if !self.yara_rules.is_empty() || self.hash_scanner.is_some() {
            for (_name, rules) in &self.yara_rules {
                arenas.extend(scan_bytes_yara_ranges(
                    &data,
                    rules,
                    &self.excluded_yara_rules,
                    self.config.fast_scan,
                ));
            }
            arenas.extend(self.url_bloom_arenas(&data));
        }

        arenas
    }

    /// Locate the byte ranges of any phishing/URLhaus URLs in `data`, mirroring
    /// the pipeline's URL bloom check (same ≤1 MiB gate and URL extraction).
    fn url_bloom_arenas(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut arenas = Vec::new();
        let Some(ref scanner) = self.hash_scanner else {
            return arenas;
        };
        if data.len() > 1_048_576 {
            return arenas;
        }
        let bloom = scanner.bloom();
        for url in extract_urls_from_bytes(data) {
            if bloom.is_phishing(&url) || bloom.is_urlhaus(&url) {
                arenas.extend(find_all_byte_ranges(data, url.as_bytes()));
            }
        }
        arenas
    }

    /// Scan an in-memory byte buffer using all applicable engines.
    /// Skips engines that require a file path (hash scanner, ClamAV).
    pub fn scan_bytes(&self, data: &[u8]) -> ScanResult {
        let mut engines: Vec<EngineResult> = Vec::new();
        let mut yara_x_matches = Vec::new();

        let max_len = MAX_SCAN_FILE_SIZE as usize;
        if data.len() > max_len {
            return ScanResult {
                verdict: Verdict::Clean,
                threat_name: None,
                engines: vec![EngineResult {
                    engine: "size_limit",
                    verdict: Verdict::Clean,
                    detail: format!("skipped: data is over 2 GiB ({} bytes)", data.len()),
                    elapsed_ms: None,
                }],
                yara_x_matches: Vec::new(),
                ml_malware_probability: None,
                clamav_result: None,
            };
        }

        // --- 1. ML INFERENCE ---
        // Gate each model on the detected file class (no path here, so classify
        // from bytes alone) — the JS model must not score non-JS text buffers.
        let t0 = Instant::now();
        let ml_file_type = hydradragonsig::scanner::filetype::classify_bytes_only(data);
        let ml_verdict =
            self.run_ml_inference_bytes(data, ml_file_type.is_pe, ml_file_type.is_javascript);
        let ml_elapsed_ms = self
            .config
            .time_engines
            .then(|| t0.elapsed().as_millis() as u64);
        if let Some(ref mv) = ml_verdict {
            engines.push(EngineResult {
                engine: "ml",
                verdict: mv.verdict,
                detail: format!("probability={:.4}", mv.probability),
                elapsed_ms: ml_elapsed_ms,
            });
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

        // --- 2. STATIC RULES (in-memory) ---
        let mut static_file_type: Option<hydradragonsig::models::FileTypeInfo> = None;
        let t0 = Instant::now();
        match &self.hydradragonsig_rules {
            Some(rules) => {
                let ctx = hydradragonsig::models::MemoryScanContext {
                    buffer: data.to_vec(),
                    identifier: "memory".into(),
                    base_address: None,
                };
                match hydradragonsig::scan_memory(&ctx, rules, &hydradragonsig::ScanOptions::default()) {
                    Ok(report) => {
                        let elapsed_ms = self
                            .config
                            .time_engines
                            .then(|| t0.elapsed().as_millis() as u64);
                        static_file_type = Some(report.file_type.clone());
                        let hv = convert_verdict(&report.verdict);
                        engines.push(EngineResult {
                            engine: "hydradragonsig",
                            verdict: hv,
                            detail: report.threat_name.clone().unwrap_or_default(),
                            elapsed_ms,
                        });
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
                        if matches!(hv, Verdict::Malware | Verdict::Suspicious | Verdict::Pua) {
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
                        let elapsed_ms = self
                            .config
                            .time_engines
                            .then(|| t0.elapsed().as_millis() as u64);
                        engines.push(EngineResult {
                            engine: "hydradragonsig",
                            verdict: Verdict::Clean,
                            detail: format!("error: {}", e),
                            elapsed_ms,
                        });
                    }
                }
            }
            None => {
                engines.push(EngineResult {
                    engine: "hydradragonsig",
                    verdict: Verdict::Clean,
                    detail: "no hydradragonsig rules loaded".into(),
                    elapsed_ms: None,
                });
            }
        }

        // --- 3. URL / PHISHING BLOOM CHECK ---
        if let Some(ref scanner) = self.hash_scanner {
            let bloom = scanner.bloom();
            let t0 = Instant::now();
            if data.len() <= 1_048_576 {
                let urls = extract_urls_from_bytes(data);
                let mut phishing_urls: Vec<String> = Vec::new();
                let mut urlhaus_urls: Vec<String> = Vec::new();
                for url in &urls {
                    if bloom.is_phishing(url) {
                        phishing_urls.push(url.clone());
                    }
                    if bloom.is_urlhaus(url) {
                        urlhaus_urls.push(url.clone());
                    }
                }
                let elapsed_ms = self
                    .config
                    .time_engines
                    .then(|| t0.elapsed().as_millis() as u64);
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

        // --- 4. YARA-X ---
        if self.yara_rules.is_empty() {
            engines.push(EngineResult {
                engine: "yara_x",
                verdict: Verdict::Clean,
                detail: "no rules loaded".into(),
                elapsed_ms: None,
            });
        } else {
            let t0 = Instant::now();
            let mut all_matches: Vec<YaraHit> = Vec::new();
            let mut scan_error: Option<String> = None;
            let is_pe = static_file_type.as_ref().is_some_and(|ft| ft.is_pe);
            let is_js = static_file_type.as_ref().is_some_and(|ft| ft.is_javascript);

            for (name, rules) in &self.yara_rules {
                let applies = match name.as_str() {
                    "machine_learning_pe" => is_pe,
                    "machine_learning_js" => is_js,
                    _ => true,
                };
                if !applies { continue; }
                match scan_bytes_yara(data, rules, &self.excluded_yara_rules, self.config.fast_scan) {
                    Ok(mut m) => all_matches.append(&mut m),
                    Err(e) => { scan_error = Some(e); break; }
                }
            }
            let yara_elapsed_ms = self
                .config
                .time_engines
                .then(|| t0.elapsed().as_millis() as u64);

            if let Some(e) = scan_error {
                engines.push(EngineResult {
                    engine: "yara_x",
                    verdict: Verdict::Clean,
                    detail: format!("error: {}", e),
                    elapsed_ms: yara_elapsed_ms,
                });
            } else if !all_matches.is_empty() {
                yara_x_matches = yara_hit_names(&all_matches);
                match classify_yara_verdict(&all_matches) {
                    Some(yara_verdict) => {
                        engines.push(EngineResult {
                            engine: "yara_x",
                            verdict: yara_verdict,
                            detail: yara_x_matches.join(", "),
                            elapsed_ms: yara_elapsed_ms,
                        });
                        let still_detected = engines.iter().any(|e| matches!(e.verdict, Verdict::Malware | Verdict::Suspicious | Verdict::Pua | Verdict::Phishing));
                        if still_detected {
                            let final_verdict = Verdict::aggregate(&engines.iter().map(|e| e.verdict).collect::<Vec<_>>());
                            return ScanResult {
                                verdict: final_verdict,
                                threat_name: yara_x_matches.first().cloned(),
                                engines,
                                yara_x_matches,
                                ml_malware_probability: ml_verdict.map(|m| m.probability),
                                clamav_result: None,
                            };
                        }
                    }
                    None => {
                        // Only informational (INFO_) rules matched — not a threat.
                        engines.push(EngineResult {
                            engine: "yara_x",
                            verdict: Verdict::Clean,
                            detail: format!("informational: {}", yara_x_matches.join(", ")),
                            elapsed_ms: yara_elapsed_ms,
                        });
                    }
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
            clamav_result: None,
        }
    }

    /// ML inference from an already-read byte buffer.
    /// Run the type-specific ML models, each gated on the detected file class:
    /// the PE model only on PE binaries, the JS model only on JavaScript. Without
    /// the `is_js` gate the JS model would score ANY UTF-8 text file (XML, HTML,
    /// JSON, plain text, …) and could false-positive on it, since
    /// `extract_js_features` returns a feature vector even when the JS parse fails.
    fn run_ml_inference_bytes(&self, bytes: &[u8], is_pe: bool, is_js: bool) -> Option<MlVerdict> {
        let device = NdArrayDevice::default();

        if is_pe {
            if let Some(ref model) = self.pe_ml_model {
                if let Some(prob) =
                    crate::ml::inference::predict_pe::<InferBackend>(bytes, model, &device)
                {
                    return Some(MlVerdict {
                        verdict: ml_classify(prob, self.config.ml_threshold),
                        probability: prob,
                    });
                }
            }
        }

        if is_js {
            if let Some(ref model) = self.js_ml_model {
                if let Ok(source) = String::from_utf8(bytes.to_vec()) {
                    if let Some(prob) =
                        crate::ml::inference::predict_js::<InferBackend>(&source, model, &device)
                    {
                        return Some(MlVerdict {
                            verdict: ml_classify(prob, self.config.ml_threshold),
                            probability: prob,
                        });
                    }
                }
            }
        }

        None
    }
}

/// Internal per-file MlVerdict.
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

/// Convert hydradragonsig's Verdict to hydradragonav's Verdict.
fn convert_verdict(v: &hydradragonsig::models::Verdict) -> Verdict {
    match v {
        hydradragonsig::models::Verdict::Clean => Verdict::Clean,
        hydradragonsig::models::Verdict::Trusted => Verdict::Trusted,
        hydradragonsig::models::Verdict::Pua => Verdict::Pua,
        hydradragonsig::models::Verdict::Suspicious => Verdict::Suspicious,
        hydradragonsig::models::Verdict::Malware => Verdict::Malware,
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

    // Resolve the event-log dir from %SystemRoot% (Windows is not always on C:).
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let evtx_dir = PathBuf::from(system_root)
        .join("System32")
        .join("winevt")
        .join("Logs");
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

    eprintln!(
        "[YARA] loaded {} ruleset(s) from {}",
        loaded.len(),
        dir.display()
    );
    loaded
}

// Scans an already-read byte buffer against one ruleset. Pulling the file read
// out of here lets scan_file read the bytes once and reuse them across every
// ruleset instead of re-reading the file per ruleset.
/// A matched YARA-X rule: its name plus whether its metadata marks it suspicious
/// (e.g. a `severity`/`category = "suspicious"` meta, not just a `SUSP_` name).
pub struct YaraHit {
    pub name: String,
    pub meta_suspicious: bool,
    /// Rule carries `rule_category = "greyware_tool_keyword"` — greyware,
    /// classified as PUA (not malware) to cut false positives.
    pub is_greyware_tool: bool,
}

fn yara_hit_names(hits: &[YaraHit]) -> Vec<String> {
    hits.iter().map(|h| h.name.clone()).collect()
}

fn scan_bytes_yara(
    data: &[u8],
    rules: &Rules,
    exclusions: &HashSet<String>,
    fast_scan: bool,
) -> Result<Vec<YaraHit>, String> {
    let mut scanner = YaraScanner::new(rules);
    if fast_scan {
        scanner.fast_scan(true);
    }
    let results = scanner
        .scan(data)
        .map_err(|e| format!("scan error: {}", e))?;

    let matches: Vec<YaraHit> = results
        .matching_rules()
        .filter(|r| !exclusions.contains(r.identifier()))
        .map(|r| {
            // Flag suspicious if any metadata key or string value says "suspicious".
            let meta_suspicious = r.metadata().into_iter().any(|(key, value)| {
                key.to_ascii_lowercase().contains("suspicious")
                    || matches!(value, MetaValue::String(s)
                        if s.to_ascii_lowercase().contains("suspicious"))
            });
            // `rule_category = "greyware_tool_keyword"` → treat as PUA, not malware.
            let is_greyware_tool = r.metadata().into_iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("rule_category")
                    && matches!(value, MetaValue::String(s)
                        if s.eq_ignore_ascii_case("greyware_tool_keyword"))
            });
            YaraHit {
                name: r.identifier().to_string(),
                meta_suspicious,
                is_greyware_tool,
            }
        })
        .collect();

    Ok(matches)
}

// Collect the byte ranges of every YARA-X pattern match (file-coordinate, since
// the scanner runs over the raw file bytes), skipping excluded rules. Used to
// recover disinfection arenas for YARA-detected threats.
fn scan_bytes_yara_ranges(
    data: &[u8],
    rules: &Rules,
    exclusions: &HashSet<String>,
    fast_scan: bool,
) -> Vec<(usize, usize)> {
    let mut scanner = YaraScanner::new(rules);
    if fast_scan {
        scanner.fast_scan(true);
    }
    let results = match scanner.scan(data) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut arenas = Vec::new();
    for rule in results.matching_rules() {
        if exclusions.contains(rule.identifier()) {
            continue;
        }
        for pattern in rule.patterns() {
            for m in pattern.matches() {
                let range = m.range();
                arenas.push((range.start, range.end));
            }
        }
    }
    arenas
}

/// Classify a set of matched YARA-X rule names into a verdict by naming
/// convention. Returns `None` when every match is purely informational
/// (`INFO_`/`_INFO_`), so such matches are not treated as a detection.
///
/// Markers are matched case-insensitively as any underscore-delimited segment
/// of the rule name (so as a `MARKER_` prefix, `_MARKER_` infix, or `_MARKER`
/// suffix):
///   `INFO`             -> informational (ignored)
///   `SUSP`/`SUSPICIOUS` -> Suspicious
///   `PUA`              -> Pua
///   otherwise          -> Malware
/// When several rules match, the most severe verdict wins.
fn classify_yara_verdict(matches: &[YaraHit]) -> Option<Verdict> {
    let mut verdict: Option<Verdict> = None;
    for hit in matches {
        if let Some(v) = yara_rule_verdict(hit) {
            verdict = Some(match verdict {
                Some(current) if current.priority() >= v.priority() => current,
                _ => v,
            });
        }
    }
    verdict
}

fn yara_rule_verdict(hit: &YaraHit) -> Option<Verdict> {
    // YARA-X matches are Suspicious, PUA, or Malware — no INFO/informational
    // handling (INFO rules live in clean_rules and aren't in the active set).
    // Suspicious if the NAME has a SUSP marker or the rule METADATA says
    // suspicious; PUA on a PUA name marker; otherwise Malware.
    // Greyware (rule_category = "greyware_tool_keyword") is PUA, not malware —
    // checked first so it isn't escalated by a stray marker.
    if hit.is_greyware_tool {
        return Some(Verdict::Pua);
    }
    let lower = hit.name.to_ascii_lowercase();
    if hit.meta_suspicious
        || has_name_marker(&lower, "susp")
        || has_name_marker(&lower, "suspicious")
    {
        return Some(Verdict::Suspicious);
    }
    if has_name_marker(&lower, "pua") {
        return Some(Verdict::Pua);
    }
    Some(Verdict::Malware)
}

/// True if any underscore-delimited segment of `lower_name` equals `token`, so
/// the marker matches as a prefix (`token_…`), infix (`…_token_…`), or suffix
/// (`…_token`). Both arguments must already be lowercase.
fn has_name_marker(lower_name: &str, token: &str) -> bool {
    lower_name.split('_').any(|segment| segment == token)
}

// Find every non-overlapping occurrence of `needle` in `haystack`, returning
// their `[start, end)` byte ranges. Used to map a detected malicious URL string
// back to its position(s) in the file for disinfection.
fn find_all_byte_ranges(haystack: &[u8], needle: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return out;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push((i, i + needle.len()));
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
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
                            let cleaned = token
                                .trim_end_matches(
                                    &[',', '.', ';', ')', ']', '}', '"', '\''] as &[char]
                                );
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
                    let cleaned = token
                        .trim_end_matches(&[',', '.', ';', ')', ']', '}', '"', '\''] as &[char]);
                    if cleaned.len() >= 8 {
                        urls.push(cleaned.to_string());
                    }
                }
            }
        }
    }
    urls
}
