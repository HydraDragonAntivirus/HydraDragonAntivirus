use std::path::{Path, PathBuf};
use std::time::Instant;
use sha1collisiondetection::Sha1CD;
use sha2::{Sha256, Digest as Sha256Digest};

use crate::apk;
use crate::crypto;
use crate::clam::ClamScanner;
use crate::diagnostics;
use crate::embedded_url;
use crate::ml::filetype;
use crate::hayabusa_scanner::{HayabusaEventMatch, HayabusaScanner};
use crate::hosts::{self, HostsCheckReport, HostsRestoreReport};
use crate::ml::scanner::MlScanner;
use crate::pe_strings;
use crate::ptm_registry::PuaRegistryMatcher;
use crate::report::{
    DetectionItem, ExtractedObject, MemoryScanReport, RegistryCheckReport, ScanObject, SignerDetails, StaticScanReport,
};
use crate::signers::{verify_authenticode, BinaryFuse16Filter, SignerDb};
use crate::string_rules::{self, PeStringRules};
use crate::yara::YaraScanner;

/// APK tree-model decision threshold. From `apk_trees.meta.json`
/// (LightGBM 200 trees, valid F1 0.955 / FPR 0.017). Retune on retrain.
/// Web parity (`openedr_web/src/engine.rs::APK_TREE_THRESHOLD`).
pub const APK_TREE_THRESHOLD: f32 = 0.8;

/// PE tree-model decision threshold. Retuned to 0.90 to eliminate false positives
/// on non-standard compilers/tools (MinGW DWARF sections, PyInstaller/decompilers, Lazarus).
pub const PE_TREE_THRESHOLD: f32 = 0.90;

/// JS tree-model decision threshold. Set to 0.85 (Malicious cutoff) to eliminate
/// false positives in the 0.75-0.84 suspicious range on minified/bundled JS files.
pub const JS_TREE_THRESHOLD: f32 = 0.85;

/// Generic whole-buffer ML fallback threshold. Fires only when every other
/// layer (ClamAV/YARA/HydraSig/PE/JS/APK ML) found nothing, so keep it at the
/// Malicious cutoff to hold FPR down. Retune on generic retrain.
pub const GENERIC_TREE_THRESHOLD: f32 = 0.85;

/// Embedded-URL layer threshold: a URL harvested from the file's own bytes must
/// clear this before the file is called a dropper/stager. Same 0.90 bar
/// `StaticEngine::scan_url` applies to a live URL, so the desktop static scan
/// and the live firewall path never disagree about the same string.
pub const EMBEDDED_URL_ML_THRESHOLD: f32 = 0.90;

/// Cap on `Embedded_URL_ML` detections attached to one file. A sample with 300
/// embedded links should not return 300 findings — the cap is enough to triage
/// and the URLs themselves are in the details.
const MAX_EMBEDDED_URL_DETECTIONS: usize = 8;

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
    /// Hayabusa (Sigma) is only used by the EVTX / live-event-log scans, i.e. the
    /// scheduled scan - never by the per-file scan. It was built in init(), so
    /// every service start paid for loading the whole Sigma rule set even though
    /// nothing would use it for hours. Built on first use instead.
    hayabusa_dir: PathBuf,
    hayabusa: std::sync::OnceLock<HayabusaScanner>,
    string_rules: PeStringRules,
    /// Tranco 1M domain/IP whitelist (`.xf`). Gates the embedded-URL layer so a
    /// benign link sitting inside a document never becomes a finding.
    url_whitelist: Option<BinaryFuse16Filter>,
    /// Compiled CIDR whitelist/blacklist tables (`src/cidr_*.bin`, byte-identical
    /// copies of the `openedr_web` tables). The IP half of the same gate.
    cidr_engine: crate::cidr::CidrEngine,
    pub url_engine: crate::url_rules::UrlThreatEngine,
}

impl StaticEngine {
    /// Initialize the static engine using a root directory containing rule subfolders:
    /// - `database/` for ClamAV
    /// - `yara_rules/` for YARA (.yar, .yara, .yrc)
    /// - `models/` for ML models (pe_trees.bin, js_trees.bin, url_trees.bin, apk_trees.bin, *.onnx)
    /// - `signer_rules/` for trusted_signers.yaml, etc.
    /// - `xorfilter_rules/` for benign_sha256.xf (signer+hash benign whitelist)
    ///   and url_whitelist.xf (Tranco 1M domain/IP whitelist for URLs)
    /// - `url_rules/` for url_threat_rules.yaml (loaded, never embedded)
    /// - `hydradragonsig_rules/` for hydradragonsig string-rule YAML (in-scan HydraSig layer)
    /// - `ptm.local.src` or `ptm/` for PUA registry patterns
    pub fn init(base_dir: &Path) -> Self {
        let base = base_dir.to_path_buf();
        diagnostics::log("init-start", &format!("base={}", base.display()));

        // Per-step timing. The whole of init() runs behind a OnceLock, so the
        // first caller of the engine - and every other caller queued behind it -
        // pays for all of it. On a 2-core VM this was measured at ~72s, which
        // is the whole startup stall, so it matters which of these steps is
        // responsible. Logged one line per step to openedr_static_engine.log
        // under the "init-step" event.
        macro_rules! timed {
            ($name:literal, $e:expr) => {{
                let t0 = std::time::Instant::now();
                let v = $e;
                diagnostics::log(
                    "init-step",
                    &format!("{}={}ms", $name, t0.elapsed().as_millis()),
                );
                v
            }};
        }

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

        let hayabusa_dir = if base.join("hayabusa_rules").is_dir() {
            base.join("hayabusa_rules")
        } else if base.join("rules").join("hayabusa").is_dir() {
            base.join("rules").join("hayabusa")
        } else {
            base.join("hayabusa_rules")
        };
        // URL threat rules are data, not code. Two accepted layouts, same as the
        // other rule sets: `url_rules/<file>` first, then `rules/<file>`.
        // A path that exists in neither is still returned so the loader reports
        // it as absent instead of silently skipping the log line.
        let url_rules_file = crate::url_rules::URL_RULES_FILE;
        let url_rules_candidates = [
            base.join(crate::url_rules::URL_RULES_DIR).join(url_rules_file),
            base.join("rules").join(url_rules_file),
        ];
        let url_rules_path = url_rules_candidates
            .iter()
            .find(|p| p.is_file())
            .cloned()
            .unwrap_or_else(|| url_rules_candidates[0].clone());
        let signers_dir = base.join("signer_rules");
        let xf_dir = base.join("xorfilter_rules");

        // These loads are independent of each other and each of them is
        // slow enough to dominate: measured at ~72s in total on a 2-core VM,
        // which is the entire startup stall, because init() sits behind a
        // OnceLock and every caller queues behind it. Loading them sequentially
        // means the wall time is the SUM of the steps; on separate threads it
        // becomes the SLOWEST one. Scoped threads so the path borrows stay tied
        // to this function and nothing has to be 'static or leaked.
        //
        // Hayabusa is deliberately NOT here: see the `hayabusa` field. It is a
        // scheduled-scan component, so paying for it on every boot only slowed
        // startup down.
        let t_scope = std::time::Instant::now();
        let mut string_rules = PeStringRules::default();
        // URL threat rules load on this thread: the document is ~7 KB of YAML,
        // so there is nothing to parallelise, and it has to be finished before
        // the engine is handed out.
        let url_engine = timed!("url_threat_rules", {
            let mut e = crate::url_rules::UrlThreatEngine::new();
            match e.load_from_file(&url_rules_path) {
                Ok(count) => diagnostics::log(
                    "init-step",
                    &format!(
                        "url_threat_rules=loaded ({} rules, {} unwhitelisted)",
                        count,
                        e.unwhitelisted_count()
                    ),
                ),
                Err(err) => diagnostics::log(
                    "init-step",
                    &format!("url_threat_rules=absent ({err}); URL layer falls back to ML only"),
                ),
            }
            e
        });
        let (clam, yara, ml, signers, pua_registry, url_whitelist) = std::thread::scope(|s| {
            let h_clam = s.spawn(|| timed!("clam", ClamScanner::new(&database_dir)));
            let h_yara = s.spawn(|| timed!("yara", YaraScanner::new(&rules_dir)));
            let h_ml = s.spawn(|| timed!("ml_models", MlScanner::new(&models_dir)));
            let h_signers = s.spawn(|| {
                timed!("signer_rules", {
                    let mut db = SignerDb::load_from_dir(&signers_dir);
                    let benign_path = xf_dir.join(crate::signers::BENIGN_XF);
                    if db.load_benign_whitelist(&benign_path) {
                        diagnostics::log(
                            "init-step",
                            "benign_whitelist=loaded (signer+sha256 keys)",
                        );
                    } else {
                        diagnostics::log("init-step", "benign_whitelist=absent");
                    }
                    db
                })
            });
            let h_pua = s.spawn(|| timed!("registry_rules", PuaRegistryMatcher::load(&registry_rules_path)));

            // Tranco 1M domain/IP whitelist. Read on its own thread because it
            // is a ~12 MB `.xf` sitting in the page cache — deserialising it
            // inline would serialise a step that is otherwise parallel.
            let h_url_wl = s.spawn(|| {
                timed!("url_whitelist", {
                    let p = xf_dir.join(crate::signers::URL_WHITELIST_XF);
                    match std::fs::read(&p) {
                        Ok(bytes) => {
                            let filter = BinaryFuse16Filter::from_bytes(&bytes);
                            diagnostics::log(
                                "init-step",
                                &format!(
                                    "url_whitelist={}",
                                    match &filter {
                                        Some(f) => format!("loaded ({} keys)", f.len()),
                                        None => "parse-failed".to_string(),
                                    }
                                ),
                            );
                            filter
                        }
                        Err(_) => {
                            diagnostics::log("init-step", "url_whitelist=absent");
                            None
                        }
                    }
                })
            });

// HydraSig string rules (web parity): hydradragonsig RuleSet evaluated
            // in-scan with FileType tags (PE/APK gating lives in rule data).
            // Runs on this thread while the others load.
            timed!("hydradragonsig_rules", {
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
            });

            (
                h_clam.join().expect("clam loader panicked"),
                h_yara.join().expect("yara loader panicked"),
                h_ml.join().expect("ml loader panicked"),
                h_signers.join().expect("signer loader panicked"),
                h_pua.join().expect("registry rule loader panicked"),
                h_url_wl.join().expect("url whitelist loader panicked"),
            )
        });
        diagnostics::log(
            "init-step",
            &format!("init_total_parallel={}ms", t_scope.elapsed().as_millis()),
        );

        // The embedded-URL layer is gated on `url_loaded()`. Without
        // `models/url_trees.bin` it becomes a silent no-op on every file, which
        // reads as "we scanned and found nothing" rather than "this capability
        // is off", so say so once at init instead.
        if !ml.url_loaded() {
            diagnostics::log(
                "capability-disabled",
                "Embedded_URL_ML: models/url_trees.bin missing or unparseable; \
                 embedded C2/phishing URL detection is OFF for every scan",
            );
        }

        diagnostics::log(
            "engine-status",
            &format!(
                "base={}; clam_dir_exists={}; clam_loaded={}; yara_dir={}; yara_loaded={}; yara_rule_bundles={}; models_dir={}; pe_model_file={}; pe_loaded={}; js_model_file={}; js_loaded={}; url_model_file={}; url_loaded={}; apk_model_file={}; apk_loaded={}; generic_model_file={}; generic_loaded={}; generic_used_for_file_verdict={}; signer_dir={}; signer_counts={}/{}/{}; benign_whitelist={}; url_whitelist_file={}; url_whitelist_loaded={}; registry_rules={}; registry_patterns={}; string_rules={}; hayabusa_dir={}; hayabusa_loaded={}; url_rules_file={}; url_rules={}; url_unwhitelisted_hosts={}",
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
                signers.benign_loaded(),
                xf_dir.join(crate::signers::URL_WHITELIST_XF).is_file(),
                url_whitelist.is_some(),
                registry_rules_path.display(),
                pua_registry.pattern_count(),
                string_rules.pattern_count(),
                hayabusa_dir.display(),
                "deferred",
                url_rules_path.display(),
                url_engine.rule_count(),
                url_engine.unwhitelisted_count(),
            ),
        );

        Self {
            clam,
            yara,
            ml,
            signers,
            pua_registry,
            hayabusa_dir,
            hayabusa: std::sync::OnceLock::new(),
            string_rules,
            url_whitelist,
            cidr_engine: crate::cidr::CidrEngine::new(),
            url_engine,
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

    /// SHA-256 benign-whitelist hit. See `SignerDb::is_benign`.
    pub fn is_benign(&self, sha256_hex: &str) -> bool {
        self.signers.is_benign(sha256_hex)
    }

    /// True when the SHA-256 whitelist `.xf` was loaded at init.
    pub fn benign_whitelist_loaded(&self) -> bool {
        self.signers.benign_loaded()
    }

    /// Install a signer+hash whitelist `.xf` from bytes (web parity:
    /// `web_load_benign_whitelist`).
    pub fn load_benign_whitelist(&mut self, data: &[u8]) -> bool {
        self.signers.set_benign_whitelist(data)
    }

    /// Harvest every `http(s)` URL in `data` and score it with the URL forest.
///
/// `origin` prefixes the layer name so a finding lifted out of an archive entry
/// is not reported as if it came from the parent file; `context` names the
/// container in the details. `inflate` additionally decompresses Flate streams
/// first, which is required for formats that do not store their payload as
/// contiguous bytes — PDF text and Office macro bodies.
///
/// Whitelist-then-ML, nothing else: see the layer 4c comment in
/// `scan_bytes_internal` for why no rule matching happens here.
fn embedded_url_detections(
    &self,
    data: &[u8],
    origin: &str,
    context: &str,
    inflate: bool,
) -> Vec<DetectionItem> {
    if !self.ml.url_loaded() {
        return Vec::new();
    }

    let mut candidates = embedded_url::extract_urls(data);
    if inflate {
        candidates.extend(embedded_url::extract_urls_from_streams(data));
    }

    let mut out: Vec<DetectionItem> = Vec::new();
    let mut scored = 0usize;
    for candidate in candidates {
        let (whitelisted, blacklisted) = self.check_whitelist_blacklist(&candidate.host);
        if whitelisted {
            continue;
        }
        let ml_prob = self.ml.predict_url(&candidate.url).unwrap_or(0.0);
        let (prob, reason) = if blacklisted {
            (1.0f32, " (CIDR blacklist)".to_string())
        } else if ml_prob >= EMBEDDED_URL_ML_THRESHOLD {
            (ml_prob, String::new())
        } else {
            continue;
        };
        out.push(DetectionItem {
            layer: format!("{origin}Embedded_URL_ML"),
            name: "Dropper.EmbeddedC2Url".to_string(),
            score: Some(prob),
            details: Some(format!(
                "URL embedded in {context} scored {:.2}% malicious{reason} (host {}): {}",
                prob * 100.0,
                candidate.host,
                candidate.url.chars().take(200).collect::<String>()
            )),
        });
        scored += 1;
        if scored >= MAX_EMBEDDED_URL_DETECTIONS {
            break;
        }
    }
    out
}

/// Archive members that hide their payload behind a second layer of
/// compression. `word/vbaProject.bin` is an OLE compound file whose streams are
/// themselves deflated, so the raw pass over the extracted member finds nothing;
/// XML parts such as `word/_rels/document.xml.rels` are already plain text once
/// extracted and need no extra pass.
fn entry_is_compressed_document(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".bin") || lower.ends_with(".pdf")
}

/// True when the URL/domain/IP whitelist `.xf` was loaded at init.
    pub fn url_whitelist_loaded(&self) -> bool {
        self.url_whitelist.is_some()
    }

    /// Install the Tranco 1M URL/domain/IP whitelist from bytes (web parity:
    /// `web_load_url_whitelist`).
    pub fn load_url_whitelist(&mut self, data: &[u8]) -> bool {
        match BinaryFuse16Filter::from_bytes(data) {
            Some(f) => {
                self.url_whitelist = Some(f);
                true
            }
            None => false,
        }
    }

    /// Whether `host` is covered by the benign signatures. Returns
    /// `(is_whitelisted, is_blacklisted)`.
    ///
    /// Direct port of `openedr_web::engine::check_whitelist_blacklist`, using the
    /// same data: the CIDR whitelist/blacklist tables (`src/cidr_*.bin`,
    /// byte-identical copies of the web ones) and the Tranco 1M `.xf` filter
    /// (`xorfilter_rules/url_whitelist.xf`). Order matters and is preserved —
    /// blacklist wins over whitelist, and CIDR is consulted before the filter:
    ///
    /// 1. CIDR blacklist.
    /// 2. CIDR whitelist (only when not blacklisted).
    /// 3. `.xf` filter on the host, then on each parent domain.
    ///
    /// Step 3 is skipped when the host is in the `unwhitelist_subdomains`
    /// *include* list from `url_threat_rules.yaml` — that is how
    /// `raw.githubusercontent.com` and friends stay scannable.
    ///
    /// With no `.xf` loaded, step 3 answers `false` for everything: an install
    /// without the filter gets ML rather than a blanket pass.
    pub fn check_whitelist_blacklist(&self, host: &str) -> (bool, bool) {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return (false, false);
        }

        // 1. CIDR blacklist (IPv4 & IPv6).
        if self.cidr_engine.is_blacklisted(&host) {
            return (false, true);
        }
        // 2. CIDR whitelist, unless blacklisted above.
        if self.cidr_engine.is_whitelisted(&host) {
            return (true, false);
        }
        // 3. Tranco 1M `.xf`, unless the host is explicitly unwhitelisted.
        if let Some(filter) = self.url_whitelist.as_ref() {
            if !self.url_engine.is_unwhitelisted(&host) {
                if filter.contains(&host) {
                    return (true, false);
                }
                let parts: Vec<&str> = host.split('.').collect();
                // 1..len-1 walks the parent domains but stops short of the bare
                // TLD — a `.com` entry would whitelist the whole internet.
                for i in 1..parts.len().saturating_sub(1) {
                    if filter.contains(&parts[i..].join(".")) {
                        return (true, false);
                    }
                }
            }
        }
        (false, false)
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

    /// The Hayabusa scanner, built on first use.
    ///
    /// Only the scheduled EVTX scan reaches this, so the Sigma rules are loaded
    /// when that scan runs rather than on every service start. If two callers
    /// race here, OnceLock lets one of them wait - which is fine, because by then
    /// they are both inside the scheduled scan anyway.
    fn hayabusa(&self) -> &HayabusaScanner {
        self.hayabusa
            .get_or_init(|| HayabusaScanner::new(&self.hayabusa_dir))
    }

    /// Scan a Windows EVTX log file for threat events using Hayabusa rules.
    pub fn scan_evtx(&self, path: &Path) -> Vec<HayabusaEventMatch> {
        self.hayabusa().scan_evtx_file(path)
    }

    /// Scan live Windows system event logs (C:\Windows\System32\Winevt\Logs\) using Hayabusa rules.
    pub fn scan_system_events(&self) -> Vec<HayabusaEventMatch> {
        self.hayabusa().scan_system_events()
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
                    extracted_objects: Vec::new(),
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
                    if prob >= PE_TREE_THRESHOLD {
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

    /// Global multi-engine evaluation over any in-memory byte slice.
    /// Evaluates ClamAV, YARA-X, HydraDragonSig (strings + PE imports/exports),
    /// ML models, and embedded URLs uniformly, with automatic origin-prefix tagging.
    fn scan_bytes_core(
        &self,
        bytes: &[u8],
        name: &str,
        origin_prefix: &str,
        layer_prefix: &str,
        detections: &mut Vec<DetectionItem>,
        max_score: &mut f32,
    ) {
        if bytes.is_empty() {
            return;
        }

        let is_pe = bytes.starts_with(b"MZ");
        let is_js = name.to_ascii_lowercase().ends_with(".js")
            || name.to_ascii_lowercase().ends_with(".mjs")
            || is_js_content(bytes);
        let is_pdf = name.to_ascii_lowercase().ends_with(".pdf") || bytes.starts_with(b"%PDF");

        // 1. ClamAV
        for m in self.clam.scan_bytes(bytes, name) {
            let det_name = if origin_prefix.is_empty() {
                m.name
            } else {
                format!("{}{}", origin_prefix, m.name)
            };
            detections.push(DetectionItem {
                layer: format!("{}ClamAV", layer_prefix),
                name: det_name,
                score: Some(1.0),
                details: Some(format!("matched view {:?}", m.view)),
            });
            *max_score = max_score.max(1.0);
        }

        // 2. YARA-X
        let yara_slice: &[u8] = if bytes.len() > 32 * 1024 * 1024 {
            &bytes[..32 * 1024 * 1024]
        } else {
            bytes
        };
        for ym in self.yara.scan_bytes(yara_slice) {
            let det_name = if origin_prefix.is_empty() {
                ym
            } else {
                format!("{}{}", origin_prefix, ym)
            };
            detections.push(DetectionItem {
                layer: format!("{}YARA", layer_prefix),
                name: det_name,
                score: Some(0.95),
                details: None,
            });
            *max_score = max_score.max(0.95);
        }

        // 3. HydraDragonSig (strings + PE imports/exports/sections)
        let capped: &[u8] = if bytes.len() > 16 * 1024 * 1024 {
            &bytes[..16 * 1024 * 1024]
        } else {
            bytes
        };
        let raw = pe_strings::extract_strings(capped);
        let strings: Vec<String> = raw.iter().map(|s| string_rules::normalize_text(s)).collect();
        let sha256_hex = {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hex::encode(hasher.finalize())
        };
        for hit in self.string_rules.scan_bytes(
            bytes,
            name,
            &sha256_hex,
            &strings,
            is_pe,
            false,
            10,
        ) {
            let rule_name = if hit.rule.is_empty() {
                "HydraSig.Match".to_string()
            } else {
                hit.rule.clone()
            };
            let det_name = if origin_prefix.is_empty() {
                rule_name
            } else {
                format!("{}{}", origin_prefix, rule_name)
            };
            let mut details = hit.title.clone();
            if let Some(ev) = hit.evidence.first() {
                details.push_str(" | ");
                details.push_str(&ev.chars().take(120).collect::<String>());
            }
            let score = hit.score as f32 / 100.0;
            detections.push(DetectionItem {
                layer: format!("{}HydraSig", layer_prefix),
                name: det_name,
                score: Some(score),
                details: Some(details),
            });
            *max_score = max_score.max(score);
        }

        // 4. ML (PE / JS)
        if is_pe {
            if let Some(prob) = self.ml.predict_pe(bytes) {
                if prob >= PE_TREE_THRESHOLD {
                    let det_name = if origin_prefix.is_empty() {
                        "MalwareNet.PE.HighConfidence".to_string()
                    } else {
                        format!("{}MalwareNet.PE.HighConfidence", origin_prefix)
                    };
                    detections.push(DetectionItem {
                        layer: format!("{}PE_ML", layer_prefix),
                        name: det_name,
                        score: Some(prob),
                        details: Some(format!("PE malware probability: {:.2}%", prob * 100.0)),
                    });
                    *max_score = max_score.max(prob);
                }
            }
        } else if is_js {
            if let Ok(source) = std::str::from_utf8(bytes) {
                if let Some(prob) = self.ml.predict_js(source) {
                    if prob >= JS_TREE_THRESHOLD {
                        let det_name = if origin_prefix.is_empty() {
                            "MalwareNet.JS.HighConfidence".to_string()
                        } else {
                            format!("{}MalwareNet.JS.HighConfidence", origin_prefix)
                        };
                        detections.push(DetectionItem {
                            layer: format!("{}JS_ML", layer_prefix),
                            name: det_name,
                            score: Some(prob),
                            details: Some(format!("JS malware probability: {:.2}%", prob * 100.0)),
                        });
                        *max_score = max_score.max(prob);
                    }
                }
            }
        }

        // 5. Embedded URLs
        for d in self.embedded_url_detections(bytes, layer_prefix, &format!("payload '{name}'"), is_pdf) {
            *max_score = max_score.max(d.score.unwrap_or(0.0));
            detections.push(d);
        }
    }

    /// Scan a first-class extracted object (archive member, emulated unpacked PE, overlay, or stripped buffer).
    /// Runs all detection engines (ClamAV, YARA-X, HydraDragonSig, ML, embedded URLs, and PE heuristics)
    /// on the in-memory bytes and returns an isolated `ExtractedObject`.
    pub fn scan_object(&self, object: &ScanObject) -> ExtractedObject {
        let mut obj_detections = Vec::new();
        let mut obj_max_score = 0.0f32;

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(&object.bytes);
            hex::encode(hasher.finalize())
        };

        // Multi-engine evaluation on object bytes
        self.scan_bytes_core(
            &object.bytes,
            &object.name,
            "",
            "",
            &mut obj_detections,
            &mut obj_max_score,
        );

        // PE-specific heuristics on the extracted object
        if object.bytes.starts_with(b"MZ") {
            if let Some(detail) = hydradragonextractor::heuristics::inspect_pe_rva_trick(&object.bytes) {
                obj_detections.push(DetectionItem {
                    layer: "Heuristic_PE".to_string(),
                    name: "HEUR:Win32.Susp.PE.RVATrick".to_string(),
                    score: Some(0.90),
                    details: Some(detail),
                });
                obj_max_score = obj_max_score.max(0.90);
            }
        }

        let verdict = if obj_max_score >= 0.85 {
            "Malicious"
        } else if obj_max_score >= 0.50 || !obj_detections.is_empty() {
            "Suspicious"
        } else {
            "Clean"
        };

        ExtractedObject {
            name: object.name.clone(),
            path: object.path.clone(),
            size: object.bytes.len() as u64,
            sha256,
            depth: object.depth,
            origin_type: object.origin_type.clone(),
            verdict: verdict.to_string(),
            max_threat_score: obj_max_score,
            detections: obj_detections,
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
        let mut extracted_objects: Vec<ExtractedObject> = Vec::new();

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
                extracted_objects: Vec::new(),
                scan_time_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        // File-type gate FIRST: unclassifiable content is not scanned at
        // all — verdict Unknown, straight out. No signer/YARA/ClamAV/ML/unicorn
        // work is spent on it. The report is kept because the embedded-URL
        // layer below needs to know whether the format compresses its payload;
        // `detect` is not cheap on a large file (it can parse a PE header), so
        // it is called once per scan rather than twice.
        let file_type = filetype::detect(data);
        if file_type.is_unknown {
            return StaticScanReport {
                target: target_name.to_string(),
                file_size,
                sha256: sha256_hex,
                verdict: "Unknown".to_string(),
                max_threat_score: 0.0,
                detections: Vec::new(),
                signer_info: None,
                pua_registry_matches: Vec::new(),
                extracted_objects: Vec::new(),
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
                } else if is_trusted && self.signers.is_trusted(signer) {
                    trusted_by_yaml = true;
                }
            }

            // 0.2 SHA-256 benign whitelist (BinaryFuse16 `.xf`, web parity).
            // Gated on an empty detection list, so a malicious/PUA signer or a
            // crypto-collision hit above has already pushed a detection and this
            // cannot whitewash the file.
            //
            // It runs here rather than at the top of the function for one reason:
            // the trusted-signer fast-path below must not be able to hide a
            // whitelist hit, so the whitelist is evaluated first.
            let benign_hit = detections.is_empty() && self.is_benign(&sha256_hex);

            // A binary is ONLY treated as trusted if:
            // 1. Its cryptographic signature passed WinVerifyTrust / Catalog verification (is_trusted == true).
            // 2. AND its signer is explicitly verified against trusted_signers.yaml (trusted_by_yaml == true).
            let is_fully_trusted = is_trusted && trusted_by_yaml;

            signer_details = Some(SignerDetails {
                is_signed,
                is_trusted: is_fully_trusted,
                signer_name,
                status,
                is_catalog_signed,
            });

            // A whitelist hit short-circuits the whole scan. Reported as a plain
            // Clean with the signer attached, exactly like the trusted-signer
            // fast-path below, so the caller can still see who published it.
            if benign_hit {
                return StaticScanReport {
                    target: target_name.to_string(),
                    file_size,
                    sha256: sha256_hex,
                    verdict: "Clean".to_string(),
                    max_threat_score: 0.0,
                    detections: Vec::new(),
                    signer_info: signer_details,
                    pua_registry_matches: Vec::new(),
                    extracted_objects: Vec::new(),
                    scan_time_ms: start_time.elapsed().as_millis() as u64,
                };
            }

            // Fast-path ONLY for binaries that are cryptographically valid AND vetted in trusted_signers.yaml
            if is_fully_trusted && detections.is_empty() {
                return StaticScanReport {
                    target: target_name.to_string(),
                    file_size,
                    sha256: sha256_hex,
                    verdict: "Clean".to_string(),
                    max_threat_score: 0.0,
                    detections: Vec::new(),
                    signer_info: signer_details,
                    pua_registry_matches: Vec::new(),
                    extracted_objects: Vec::new(),
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

        // 4c. Embedded-URL C2 / phishing layer. Stage-1 droppers, phishing
        // documents and macro stagers carry a *link*, not a payload: harvest
        // every http(s) URL out of the file's own bytes (ASCII + UTF-16LE) and
        // score it with the same URL forest the live firewall path uses.
        //
        // Placement matters for false positives. This runs after the
        // SHA-256-benign and trusted-signer fast paths above, so a signed,
        // publisher-trusted binary or document can never reach it — only
        // unsigned samples are judged on their links.
        //
        // Two inputs, nothing else:
        //
        // 1. `check_whitelist_blacklist` — the Tranco `.xf`, the CIDR tables and
        //    the `unwhitelist_subdomains` list in url_threat_rules.yaml. A
        //    whitelisted host is skipped outright: a benign link sitting inside
        //    a document is not a finding. A CIDR-blacklisted host is Malicious
        //    on its own, because that is deterministic rather than a guess.
        // 2. The URL ML, at the same 0.90 bar `scan_url` applies to a live URL.
        //
        // No rule matching happens here. The patterns in url_threat_rules.yaml
        // are tuned for a URL a person chose to visit and would fire on every
        // ordinary link inside a document; that judgement belongs to the
        // inspection path (`openedr_static_inspect_url` / the firewall), which
        // has liveness and page content to work with. This layer only answers
        // "is one of these links malicious", and the model answers it.
        //
        // Hosts in `unwhitelist_subdomains` — raw.githubusercontent.com,
        // storage.googleapis.com and the rest — are kept out of the whitelist
        // precisely so they reach step 2. Being listed is not a detection: a
        // GitHub link is scored like any other URL.
        if !is_apk_file {
            let is_pdf = file_type.file_type == filetype::FileKind::Pdf.as_str();
            for d in self.embedded_url_detections(data, "", "the file", is_pdf) {
                max_score = max_score.max(d.score.unwrap_or(0.0));
                detections.push(d);
            }
        }

        // 5. Machine Learning (PE / JS) — skipped for APKs (APK forest above).
        if !is_apk_file {
            if data.starts_with(b"MZ") {
                if let Some(prob) = self.ml.predict_pe(data) {
                    if prob >= PE_TREE_THRESHOLD {
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
                        if prob >= JS_TREE_THRESHOLD {
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
                            let obj = ScanObject::new(
                                format!("{target_name}.unpacked.bin"),
                                format!("{target_name} -> [Unicorn:Unpacked]"),
                                dumped,
                                1,
                                "UnpackedPE",
                            );
                            let extracted = self.scan_object(&obj);

                            max_score = max_score.max(extracted.max_threat_score);
                            for d in &extracted.detections {
                                detections.push(DetectionItem {
                                    layer: format!("Unicorn_Unpacker_{}", d.layer),
                                    name: format!("Unpacked:{}", d.name),
                                    score: d.score,
                                    details: d.details.clone(),
                                });
                            }
                            extracted_objects.push(extracted);
                        }
                    }
                }
            }
        }

        // 7. Heuristic: Trailing Null Bytes — PE files ONLY. Applies to any
        // non-APK buffer today, which false-positives on ordinary
        // preallocated/zero-filled files (sparse installers, LevelDB, sparse
        // images, DB files): they carry legitimate trailing 0x00 runs and
        // scored 0.80 for nothing. Gate on a VALIDATED PE image (MZ + sane
        // e_lfanew + PE\0\0), the only format where a big null tail is a
        // real packer/inflater signal.
        if !is_apk_file && find_valid_embedded_pe(data) == Some(0) {
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

                // Rescan stripped buffer as first-class object
                let stripped_data = data[..non_zero_end].to_vec();
                let obj = ScanObject::new(
                    format!("{target_name}.stripped.bin"),
                    format!("{target_name} -> [StrippedPadding]"),
                    stripped_data,
                    1,
                    "Stripped",
                );
                let extracted = self.scan_object(&obj);

                max_score = max_score.max(extracted.max_threat_score);
                for d in &extracted.detections {
                    detections.push(DetectionItem {
                        layer: format!("Heuristic_Stripped_{}", d.layer),
                        name: format!("Stripped:{}", d.name),
                        score: d.score,
                        details: d.details.clone(),
                    });
                }
                extracted_objects.push(extracted);
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
                        let embedded_pe_offset = find_valid_embedded_pe(overlay);
                        let has_embedded_pe = embedded_pe_offset.is_some();
                        let is_sfx_archive = overlay.starts_with(b"PK\x03\x04")
                            || overlay.starts_with(b"7z\xBC\xAF\x27\x1C")
                            || overlay.starts_with(b"Rar!\x1A\x07");

                        let obj = ScanObject::new(
                            "overlay.bin",
                            format!("{target_name} -> [PE:Overlay]"),
                            overlay.to_vec(),
                            1,
                            "Overlay",
                        );
                        let extracted = self.scan_object(&obj);
                        let overlay_confirmed = !extracted.detections.is_empty();

                        max_score = max_score.max(extracted.max_threat_score);
                        for d in &extracted.detections {
                            detections.push(DetectionItem {
                                layer: format!("Heuristic_Overlay_{}", d.layer),
                                name: format!("Overlay:{}", d.name),
                                score: d.score,
                                details: d.details.clone(),
                            });
                        }
                        extracted_objects.push(extracted);

                        // Standalone binder heuristic: validated MZ->PE only.
                        // SFX archives (7z/PK/Rar) without validated PE or engine hit: silent.
                        if has_embedded_pe {
                            let off = embedded_pe_offset.unwrap_or(0);
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
                        let obj = ScanObject::new(
                            entry.name.clone(),
                            format!("{target_name} -> {}", entry.name),
                            entry.data.clone(),
                            1,
                            "ArchiveMember",
                        );
                        let extracted = self.scan_object(&obj);

                        max_score = max_score.max(extracted.max_threat_score);
                        for d in &extracted.detections {
                            detections.push(DetectionItem {
                                layer: format!("Archive_{}", d.layer),
                                name: format!("Archive:{}:{}", entry.name, d.name),
                                score: d.score,
                                details: d.details.clone(),
                            });
                        }

                        // Also check if child entry itself is a packed PE: run Unicorn once if packed
                        if entry.data.starts_with(b"MZ") && entry.data.len() >= 0x1000 {
                            if let Ok(sub_sample) = hydradragonunicorn::unpacker::engine::Sample::from_bytes(&entry.data) {
                                let mut sub_unpacker = hydradragonunicorn::unpacker::engine::UnpackerEngine::new(sub_sample, "memory");
                                if sub_unpacker.init_uc().is_ok() {
                                    let _ = sub_unpacker.emu();
                                    if let Ok(sub_dumped) = sub_unpacker.dump_bytes() {
                                        if !sub_dumped.is_empty() && sub_dumped != entry.data {
                                            let sub_obj = ScanObject::new(
                                                format!("{}.unpacked.bin", entry.name),
                                                format!("{target_name} -> {} -> [Unicorn:Unpacked]", entry.name),
                                                sub_dumped,
                                                2,
                                                "UnpackedPE",
                                            );
                                            let sub_extracted = self.scan_object(&sub_obj);
                                            max_score = max_score.max(sub_extracted.max_threat_score);
                                            for d in &sub_extracted.detections {
                                                detections.push(DetectionItem {
                                                    layer: format!("Archive_Unpacked_{}", d.layer),
                                                    name: format!("Archive:{}:Unpacked:{}", entry.name, d.name),
                                                    score: d.score,
                                                    details: d.details.clone(),
                                                });
                                            }
                                            extracted_objects.push(sub_extracted);
                                        }
                                    }
                                }
                            }
                        }

                        // Embedded URLs inside the entry. This is the only path
                        // that sees an Office macro body: `word/vbaProject.bin`
                        // and friends are deflated ZIP members, so their URLs
                        // are invisible to the parent-file pass.
                        for d in self.embedded_url_detections(
                            &entry.data,
                            "Archive_",
                            &format!("archive entry '{}'", entry.name),
                            Self::entry_is_compressed_document(&entry.name),
                        ) {
                            max_score = max_score.max(d.score.unwrap_or(0.0));
                            detections.push(d);
                        }

                        extracted_objects.push(extracted);
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
            extracted_objects,
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

    /// URL score via ML model (openedr_static strictly uses Machine Learning >= 0.9).
    /// Returns (probability, is_malicious, is_whitelisted, is_blacklisted).
    pub fn scan_url(&self, raw_url: &str) -> (f32, bool, bool, bool) {
        let prob = self.ml.predict_url(raw_url).unwrap_or(0.0);
        let is_malicious = prob >= 0.9;
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
                if js_prob >= JS_TREE_THRESHOLD {
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


