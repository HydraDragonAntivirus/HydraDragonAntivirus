//! Web-edition scan engine: ML trees (PE/JS/URL/APK) + PE string rules +
//! heuristics.
//!
//! Deliberately NOT included (native-only): ClamAV databases, Unicorn
//! emulation, Hayabusa EVTX, WinTrust/catalog verification, FLS cloud.
//! Disassembly counts arrive from capstone.js via the `_ex` API; without them
//! PE features 51..53 read 0.0 (graceful). APKs are detected by extension /
//! ZIP central directory and scored by our own forest (`apk_trees.bin`, same
//! bundle format and scorer as the PE/JS trees) plus APK heuristics —
//! never `Error`.

use crate::apk;
use crate::ml::scanner::MlScanner;
use crate::pe_strings;
use crate::report::{DetectionItem, StaticScanReport};
use crate::string_rules::{self, PeStringRules};
use crate::yara::YaraScanner;

/// APK tree-model decision threshold. From `apk_trees.meta.json`
/// (LightGBM 200 trees, valid F1 0.955 / FPR 0.017). Retune on retrain.
pub const APK_TREE_THRESHOLD: f32 = 0.8;

pub struct WebEngine {
    ml: MlScanner,
    yara: YaraScanner,
    string_rules: PeStringRules,
    benign_filter: Option<BinaryFuse16Filter>,
    url_whitelist: Option<BinaryFuse16Filter>,
    pub cidr_engine: crate::cidr::CidrEngine,
    pub url_engine: crate::url_rules::UrlThreatEngine,
}

impl WebEngine {
    pub fn new() -> Self {
        Self {
            ml: MlScanner::new(),
            yara: YaraScanner::new(),
            string_rules: PeStringRules::default(),
            benign_filter: None,
            url_whitelist: None,
            cidr_engine: crate::cidr::CidrEngine::new(),
            url_engine: crate::url_rules::UrlThreatEngine::new(),
        }
    }

    /// Tree-model readiness for the demo status lights.
    pub fn apk_ml_loaded(&self) -> bool {
        self.ml.apk_loaded()
    }

    pub fn load_url_whitelist(&mut self, data: &[u8]) -> bool {
        if let Some(f) = BinaryFuse16Filter::from_bytes(data) {
            self.url_whitelist = Some(f);
            true
        } else {
            false
        }
    }

    /// Load BinaryFuse16 SHA-256 benign whitelist (.xf binary, same format as
    /// the URL/domain/IP whitelist). Built offline with `xorfilter_writer`:
    /// `xorfilter_writer benign_sha256.txt benign_sha256.xf`.
    /// Hex lines are folded with the same lowercasing FNV-1a `key()` as the
    /// URL filter, so the .xf is queryable byte-for-byte with `contains()`.
    pub fn load_benign_whitelist(&mut self, data: &[u8]) -> bool {
        if let Some(f) = BinaryFuse16Filter::from_bytes(data) {
            self.benign_filter = Some(f);
            true
        } else {
            false
        }
    }

    /// kind: 0 = PE, 1 = JS, 2 = URL tree bundle.
    pub fn load_model(&mut self, kind: u32, data: &[u8]) -> bool {
        self.ml.load_model(kind, data)
    }

    /// Load one compiled YARA `.yrc` bundle (same bytes as desktop).
    pub fn load_yara(&mut self, data: &[u8]) -> bool {
        self.yara.load_yrc(data)
    }

    /// Compile one YARA source document.
    pub fn add_yara_source(&mut self, src: &str) -> bool {
        self.yara.add_source(src)
    }

    /// Load hydradragonsig string-rule YAML (generic `Rule` documents).
    /// Returns rule count, or -1 on parse error.
    pub fn set_string_rules(&mut self, yaml: &str) -> i32 {
        self.string_rules.load_yaml(yaml)
    }

    pub fn set_registry_rules(&mut self, yaml: &str) -> i32 {
        self.set_string_rules(yaml)
    }

    /// Benign fast-path: BinaryFuse16 `.xf` filter, same query path as the
    /// IP/domain whitelist.
    #[inline]
    pub fn is_benign(&self, sha256_hex: &str) -> bool {
        if let Some(ref f) = self.benign_filter {
            if f.contains(sha256_hex) {
                return true;
            }
        }
        false
    }

    pub fn scan_bytes(
        &self,
        data: &[u8],
        target_name: &str,
        disasm: Option<(u64, u64, u64)>,
    ) -> StaticScanReport {
        let file_size = data.len() as u64;

        let sha256_hex = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(data);
            hex::encode(h.finalize())
        };

        let mut detections = Vec::new();
        let mut max_score: f32 = 0.0;

        // 0. Whitelist fast-path (BinaryFuse16 .xf, same as URL/IP whitelist).
        if self.is_benign(&sha256_hex) {
            return StaticScanReport {
                target: target_name.to_string(),
                file_size,
                sha256: sha256_hex,
                verdict: "Clean".to_string(),
                max_threat_score: 0.0,
                detections: Vec::new(),
                signer_info: None,
                pua_registry_matches: Vec::new(),
                scan_time_ms: 0,
            };
        }

        // 0.1 EICAR (SHA-256 identity; SHA-1 retired desktop-wide).
        const EICAR_SHA256: &str =
            "275a021bbfb6489e7341ac665a24224100c9e6029d5b2b6150d9933f3a9d541";
        if sha256_hex == EICAR_SHA256
            || data.starts_with(
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            )
        {
            detections.push(DetectionItem {
                layer: "Signature".to_string(),
                name: "EICAR-Test-File".to_string(),
                score: Some(1.0),
                details: Some("EICAR standard antivirus test file".to_string()),
            });
            max_score = max_score.max(1.0);
        }

        // Empty files scan as Unknown (never Error / null pointer).
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
                scan_time_ms: 0,
            };
        }

        let is_apk_file = apk::is_apk(data, target_name);

        // 1a. APK path: our own forest (same .bin format and scorer as the
        // PE/JS trees) + heuristics. Runs even when the bundle is absent,
        // so APKs never return Error.
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
            // 2a. YARA-X over capped manifest+dex bytes (no full-archive OOM).
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
            // 3a. HydraSig over capped APK strings with APK file-type tags.
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
        } else {
            // 1. PE / JS tree models (desktop thresholds: 0.71 / 0.75).
            if data.starts_with(b"MZ") {
                if let Some(prob) = self.ml.predict_pe(data, disasm) {
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
            } else if is_js_name(target_name) || is_js_content(data) {
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

            // 2. YARA-X (desktop parity: 0.95 per rule hit), capped so huge
            // files cannot OOM the tab (first 32 MB still catches headers).
            {
                let slice: &[u8] = if data.len() > 32 * 1024 * 1024 {
                    &data[..32 * 1024 * 1024]
                } else {
                    data
                };
                for name in self.yara.scan_bytes(slice) {
                    detections.push(DetectionItem {
                        layer: "YARA".to_string(),
                        name,
                        score: Some(0.95),
                        details: None,
                    });
                    max_score = max_score.max(0.95);
                }
            }

            // 3. hydradragonsig string rules, evaluated by ITS engine.
            // Executable gating lives in the rules via FileType conditions;
            // the engine only tags the file (validated PE or not). Strings
            // are capped to the first 16 MB so giant files stay panic-free.
            {
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
        }

        // 4. Trailing null-padding heuristic (desktop formula; PE-only — ZIP
        // archives legitimately pad, so APKs skip this).
        if !is_apk_file {
            let non_zero_end = data.iter().rposition(|&b| b != 0).map_or(0, |idx| idx + 1);
            let trailing_zeros = data.len() - non_zero_end;
            let is_inflated = (trailing_zeros >= 65536)
                || (data.len() > 1024 * 1024
                    && trailing_zeros as f64 / data.len() as f64 >= 0.20
                    && trailing_zeros >= 32768);
            if is_inflated && non_zero_end > 0 {
                detections.push(DetectionItem {
                    layer: "Heuristic".to_string(),
                    name: "Heuristic.File.InflatedNullPadding".to_string(),
                    score: Some(0.80),
                    details: Some(format!(
                        "Detected {} KB of trailing 0x00 null padding",
                        trailing_zeros / 1024
                    )),
                });
                max_score = max_score.max(0.80);
            }
        }

        // 5. Overlay with validated embedded PE (binder signal, no rescan
        // engines on web — the finding itself carries the score).
        if data.starts_with(b"MZ") {
            if let Some((off, total)) = overlay_stat(data) {
                if total >= 512 && find_valid_embedded_pe(&data[off..]).is_some() {
                    detections.push(DetectionItem {
                        layer: "Heuristic_Overlay".to_string(),
                        name: "Heuristic.PE.EmbeddedExecutableOverlay".to_string(),
                        score: Some(0.85),
                        details: Some(format!(
                            "Validated embedded PE image past section headers (overlay {} bytes)",
                            total
                        )),
                    });
                    max_score = max_score.max(0.85);
                }
            }
        }

        // Verdict gating mirrors desktop.
        let verdict = if max_score >= 0.85 {
            "Malicious"
        } else if max_score >= 0.50 {
            "Suspicious"
        } else if !detections.is_empty() {
            "Suspicious"
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
            signer_info: None, // No WinTrust in browsers.
            pua_registry_matches: Vec::new(),
            scan_time_ms: 0, // No clock on wasm32-unknown-unknown.
        }
    }

    /// Check whether a host matches CIDR blacklist/whitelist or Tranco 1M XOR filter.
    /// Returns (is_whitelisted, is_blacklisted).
    pub fn check_whitelist_blacklist(&self, raw_url: &str) -> (bool, bool) {
        let mut whitelisted = false;
        let mut blacklisted = false;

        if let Some(host) = extract_host(raw_url) {
            // 1. Check CIDR blacklist (IPv4 & IPv6)
            if self.cidr_engine.is_blacklisted(host) {
                blacklisted = true;
            }

            // 2. Check CIDR whitelist (IPv4 & IPv6)
            if !blacklisted && self.cidr_engine.is_whitelisted(host) {
                whitelisted = true;
            }

            // 3. Check XOR filter (BinaryFuse16) for exact domain / IP match
            if !blacklisted && !whitelisted {
                // If subdomain is explicitly unwhitelisted for ML/threat rules, do not whitelist it
                if !self.url_engine.is_unwhitelisted(host) {
                    if let Some(ref filter) = self.url_whitelist {
                        if filter.contains(host) {
                            whitelisted = true;
                        } else {
                            let parts: Vec<&str> = host.split('.').collect();
                            if parts.len() > 2 {
                                for i in 1..parts.len() - 1 {
                                    let parent = parts[i..].join(".");
                                    if filter.contains(&parent) {
                                        whitelisted = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        (whitelisted, blacklisted)
    }

    /// URL score via tree model + Tranco 1M & IP whitelist check + CIDR subnet check.
    /// Returns (probability, is_malicious, is_whitelisted, is_blacklisted).
    pub fn scan_url(&self, raw_url: &str) -> (f32, bool, bool, bool) {
        let (raw_whitelisted, blacklisted) = self.check_whitelist_blacklist(raw_url);
        let is_webhook_abuse = raw_url.contains("/api/webhooks/")
            || raw_url.contains("api.telegram.org")
            || raw_url.contains("/bot");

        let whitelisted = raw_whitelisted && !is_webhook_abuse;

        if blacklisted {
            return (1.0, true, false, true);
        }

        if whitelisted {
            return (0.0, false, true, false);
        }

        let prob = self.ml.predict_url(raw_url).unwrap_or(0.0);
        (prob, prob >= 0.50, false, false)
    }

    /// Full inspection via Rust YAML Threat Engine + optional page content scanning.
    pub fn inspect_url_with_content(
        &self,
        raw_url: &str,
        liveness_code: i32,
        page_content: Option<&str>,
    ) -> crate::url_rules::UrlThreatReport {
        let (raw_whitelisted, blacklisted) = self.check_whitelist_blacklist(raw_url);
        let prob = self.ml.predict_url(raw_url).unwrap_or(0.0);
        let mut report = self.url_engine.inspect(
            raw_url,
            raw_whitelisted,
            blacklisted,
            prob,
            liveness_code,
            page_content,
        );

        // Additional deep content checks (JS ML & YARA) if page content is provided
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

    /// Full inspection via Rust YAML Threat Engine.
    pub fn inspect_url(&self, raw_url: &str, liveness_code: i32) -> crate::url_rules::UrlThreatReport {
        self.inspect_url_with_content(raw_url, liveness_code, None)
    }

    /// Load custom YAML threat rules. Returns count on success.
    pub fn load_url_rules(&mut self, yaml_str: &str) -> Result<usize, String> {
        self.url_engine.load_yaml(yaml_str)
    }

    /// Add a subdomain to the unwhitelist set at runtime.
    pub fn add_unwhitelisted_subdomain(&mut self, host: &str) {
        self.url_engine.add_unwhitelisted_subdomain(host);
    }

    /// Check if a host/subdomain is unwhitelisted.
    pub fn is_unwhitelisted_subdomain(&self, host: &str) -> bool {
        self.url_engine.is_unwhitelisted(host)
    }
}

impl Default for WebEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// End offset of PE section raw data + remaining overlay length.
fn overlay_stat(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let num_sec = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
    let sec_off = e_lfanew + 24 + opt_size;
    let mut max_end = 0usize;
    for i in 0..num_sec.min(96) {
        let off = sec_off + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let raw_size =
            u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]])
                as usize;
        let raw_ptr =
            u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]])
                as usize;
        max_end = max_end.max(raw_ptr.saturating_add(raw_size));
    }
    if max_end > 0 && max_end < data.len() {
        Some((max_end, data.len() - max_end))
    } else {
        None
    }
}

/// Validated embedded-PE search (same rule as desktop overlay fix: MZ +
/// e_lfanew + PE\\0\\0 + sane section count + optional magic).
fn find_valid_embedded_pe(data: &[u8]) -> Option<usize> {
    if data.len() < 0x44 {
        return None;
    }
    let mut i = 0usize;
    while i + 0x40 < data.len() {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            let e_off = i + 0x3C;
            if e_off + 4 <= data.len() {
                let e_lfanew = u32::from_le_bytes([
                    data[e_off],
                    data[e_off + 1],
                    data[e_off + 2],
                    data[e_off + 3],
                ]) as usize;
                if e_lfanew >= 0x04 && e_lfanew <= 0x100000 {
                    let pe_off = i + e_lfanew;
                    if pe_off + 6 <= data.len()
                        && data[pe_off] == b'P'
                        && data[pe_off + 1] == b'E'
                        && data[pe_off + 2] == 0
                        && data[pe_off + 3] == 0
                    {
                        let num_sections =
                            u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]) as usize;
                        if num_sections >= 1 && num_sections <= 96 {
                            let opt_off = pe_off + 24;
                            let valid_opt = if opt_off + 2 <= data.len() {
                                let magic =
                                    u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
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
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn is_js_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".js") || lower.ends_with(".mjs")
}

fn is_js_content(bytes: &[u8]) -> bool {
    let sample = if bytes.len() > 512 { &bytes[..512] } else { bytes };
    if let Ok(s) = std::str::from_utf8(sample) {
        s.contains("function") || s.contains("var ") || s.contains("const ") || s.contains("let ")
    } else {
        false
    }
}

fn extract_host(raw_url: &str) -> Option<&str> {
    let mut s = raw_url.trim();
    if let Some(idx) = s.find("://") {
        s = &s[idx + 3..];
    }
    let host_and_port = s.split(['/', '?', '#']).next()?.trim();
    if host_and_port.is_empty() {
        return None;
    }
    if host_and_port.starts_with('[') {
        if let Some(end_bracket) = host_and_port.find(']') {
            return Some(&host_and_port[..=end_bracket]);
        }
    }
    let host = host_and_port.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

pub struct BinaryFuse16Filter {
    seed: u64,
    seg_len: u32,
    seg_len_mask: u32,
    seg_count_len: u32,
    count: usize,
    fingerprints: Vec<u16>,
}

impl BinaryFuse16Filter {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || bytes[0] != 16 || bytes[1] != 2 {
            return None;
        }
        let seed = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let seg_len = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let seg_len_mask = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let seg_count_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let count = usize::try_from(u64::from_le_bytes(bytes[24..32].try_into().ok()?)).ok()?;
        if 32 + count.checked_mul(2)? > bytes.len() {
            return None;
        }
        let mut fingerprints = Vec::with_capacity(count);
        for i in 0..count {
            let off = 32 + i * 2;
            fingerprints.push(u16::from_le_bytes([bytes[off], bytes[off + 1]]));
        }
        Some(Self {
            seed,
            seg_len,
            seg_len_mask,
            seg_count_len,
            count,
            fingerprints,
        })
    }

    pub fn contains(&self, s: &str) -> bool {
        let k = Self::key(s);
        let hash = Self::mix64(k.wrapping_add(self.seed));
        let f = hash as u16;
        let (h0, h1, h2) = Self::hash_of_hash(hash, self.seg_len, self.seg_len_mask, self.seg_count_len);
        let c = self.count;
        if h0 as usize >= c || h1 as usize >= c || h2 as usize >= c {
            return false;
        }
        let fp = self.fingerprints[h0 as usize] ^ self.fingerprints[h1 as usize] ^ self.fingerprints[h2 as usize];
        f ^ fp == 0
    }

    #[inline(always)]
    fn key(s: &str) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = OFFSET;
        for b in s.bytes() {
            h ^= b.to_ascii_lowercase() as u64;
            h = h.wrapping_mul(PRIME);
        }
        h
    }

    #[inline(always)]
    fn mix64(k: u64) -> u64 {
        const MIX_C1: u64 = 0xff51_afd7_ed55_8ccd;
        let r = (k as u128).wrapping_mul(MIX_C1 as u128);
        (r ^ (r >> 64)) as u64
    }

    #[inline(always)]
    fn hash_of_hash(hash: u64, seg_len: u32, seg_len_mask: u32, seg_count_len: u32) -> (u32, u32, u32) {
        let hi = ((hash as u128 * seg_count_len as u128) >> 64) as u64;
        let h0 = hi as u32;
        let mut h1 = h0 + seg_len;
        let mut h2 = h1 + seg_len;
        h1 ^= ((hash >> 18) as u32) & seg_len_mask;
        h2 ^= (hash as u32) & seg_len_mask;
        (h0, h1, h2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apk::test_helpers::stored_zip;

    fn evil_apk() -> Vec<u8> {
        let manifest =
            b"android.permission.SEND_SMS android.permission.READ_SMS android.permission.RECEIVE_SMS".to_vec();
        let mut dex = vec![0u8; 0x70];
        dex[0..4].copy_from_slice(b"dex\n");
        dex[0x38..0x3c].copy_from_slice(&10u32.to_le_bytes());
        dex[0x58..0x5c].copy_from_slice(&50u32.to_le_bytes());
        dex[0x60..0x64].copy_from_slice(&5u32.to_le_bytes());
        stored_zip(&[("AndroidManifest.xml", &manifest), ("classes.dex", &dex)])
    }

    #[test]
    fn apk_never_returns_error_without_ml() {
        // No APK bundle loaded: heuristics alone must flag, never Error.
        let eng = WebEngine::new();
        assert!(!eng.apk_ml_loaded());
        let rep = eng.scan_bytes(&evil_apk(), "evil.apk", None);
        assert_ne!(rep.verdict, "Error");
        assert!(rep.verdict == "Suspicious" || rep.verdict == "Malicious");
        assert!(rep
            .detections
            .iter()
            .any(|d| d.layer == "APK_Heuristic" && d.name == "APK.SmsTrio"));
    }

    #[test]
    fn apk_garbage_name_returns_invalid_not_error() {
        let eng = WebEngine::new();
        let rep = eng.scan_bytes(b"PK junk, not a zip", "app.apk", None);
        assert_ne!(rep.verdict, "Error");
        assert!(rep
            .detections
            .iter()
            .any(|d| d.name == "APK.InvalidStructure"));
    }

    #[test]
    fn empty_file_scans_unknown_not_error() {
        let eng = WebEngine::new();
        let rep = eng.scan_bytes(&[], "empty.apk", None);
        assert_eq!(rep.verdict, "Unknown");
        assert!(rep.detections.is_empty());
    }

    #[test]
    fn apk_tree_bundle_scores_like_pe_js_trees() {
        // Hand-built 1-tree bundle in the exact .bin format: sms_trio
        // (feature 18) <= 0.5 -> -1.2, else +2.2. Sigmoid(-1.2) ~= 0.23.
        fn node(id: u32, feat: u32, thr: f32, left: u32, right: u32, leaf: bool, w: f32) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&feat.to_le_bytes());
            b.extend_from_slice(&thr.to_le_bytes());
            b.extend_from_slice(&left.to_le_bytes());
            b.extend_from_slice(&right.to_le_bytes());
            b.push(leaf as u8);
            b.extend_from_slice(&w.to_le_bytes());
            b
        }
        let mut bin = Vec::new();
        bin.extend_from_slice(&1u32.to_le_bytes());
        bin.extend_from_slice(&3u32.to_le_bytes());
        bin.extend(node(0, 18, 0.5, 1, 2, false, 0.0));
        bin.extend(node(1, 0, 0.0, 0, 0, true, -1.2));
        bin.extend(node(2, 0, 0.0, 0, 0, true, 2.2));

        let mut eng = WebEngine::new();
        assert!(eng.load_model(3, &bin));
        assert!(eng.apk_ml_loaded());
        assert!(!eng.load_model(99, &bin));

        let evil = eng.scan_bytes(&evil_apk(), "evil.apk", None);
        assert!(evil.detections.iter().any(|d| d.layer == "APK_ML"
            && d.name == "HydraDragon.APK.TreeScore"));

        // Benign-shaped APK: no trio, no perms -> tree gives ~0.23, so no
        // APK_ML detection (heuristics stay silent too).
        let mut dex = vec![0u8; 0x70];
        dex[0..4].copy_from_slice(b"dex\n");
        dex[0x38..0x3c].copy_from_slice(&100u32.to_le_bytes());
        dex[0x58..0x5c].copy_from_slice(&200u32.to_le_bytes());
        dex[0x60..0x64].copy_from_slice(&10u32.to_le_bytes());
        let clean = stored_zip(&[("AndroidManifest.xml", b"plain app no permissions"), ("classes.dex", &dex)]);
        let rep = eng.scan_bytes(&clean, "clean.apk", None);
        assert!(!rep.detections.iter().any(|d| d.layer == "APK_ML"));
    }

    #[test]
    fn apk_loaders_reject_garbage_accept_nothing_crashy() {
        let mut eng = WebEngine::new();
        assert!(!eng.load_model(3, b"nope"));
        assert!(!eng.apk_ml_loaded());
        // Engine still scans fine afterwards.
        let rep = eng.scan_bytes(&evil_apk(), "evil.apk", None);
        assert_ne!(rep.verdict, "Error");
    }
}
