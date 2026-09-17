//! Web-edition scan engine: ML trees + PE string rules + heuristics.
//!
//! Deliberately NOT included (native-only): ClamAV/YARA databases, Unicorn
//! emulation, Hayabusa EVTX, WinTrust/catalog verification, archive
//! extraction, FLS cloud. Disassembly counts arrive from capstone.js via the
//! `_ex` API; without them PE features 51..53 read 0.0 (graceful).

use std::collections::HashSet;

use crate::ml::scanner::MlScanner;
use crate::pe_strings;
use crate::report::{DetectionItem, StaticScanReport};
use crate::string_rules::{self, PeStringRules};
use crate::yara::YaraScanner;

pub struct WebEngine {
    ml: MlScanner,
    yara: YaraScanner,
    string_rules: PeStringRules,
    benign_hashes: HashSet<String>,
    url_whitelist: Option<BinaryFuse16Filter>,
}

impl WebEngine {
    pub fn new() -> Self {
        Self {
            ml: MlScanner::new(),
            yara: YaraScanner::new(),
            string_rules: PeStringRules::default(),
            benign_hashes: HashSet::new(),
            url_whitelist: None,
        }
    }

    pub fn load_url_whitelist(&mut self, data: &[u8]) -> bool {
        if let Some(f) = BinaryFuse16Filter::from_bytes(data) {
            self.url_whitelist = Some(f);
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

    /// Load newline-separated SHA-256 whitelist.
    pub fn set_benign(&mut self, list: &str) -> usize {
        let mut n = 0;
        for line in list.lines() {
            let t = line.trim().to_lowercase();
            if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
                if self.benign_hashes.insert(t) {
                    n += 1;
                }
            }
        }
        n
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

        // 0. Whitelist fast-path.
        if self.benign_hashes.contains(&sha256_hex) {
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

        // 2. YARA-X (desktop parity: 0.95 per rule hit).
        for name in self.yara.scan_bytes(data) {
            detections.push(DetectionItem {
                layer: "YARA".to_string(),
                name,
                score: Some(0.95),
                details: None,
            });
            max_score = max_score.max(0.95);
        }

        // 3. hydradragonsig string rules, evaluated by ITS engine.
        // Executable gating lives in the rules via FileType conditions;
        // the engine only tags the file (validated PE or not).
        {
            let is_pe = find_valid_embedded_pe(data) == Some(0);
            let raw = pe_strings::extract_strings(data);
            let strings: Vec<String> =
                raw.iter().map(|s| string_rules::normalize_text(s)).collect();
            for hit in
                self.string_rules
                    .scan_bytes(data, target_name, &sha256_hex, &strings, is_pe, 10)
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

        // 4. Trailing null-padding heuristic (desktop formula).
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

    /// URL score via tree model + Tranco 1M & IP whitelist check.
    /// Returns (probability, is_malicious, is_whitelisted).
    pub fn scan_url(&self, raw_url: &str) -> (f32, bool, bool) {
        if let Some(ref filter) = self.url_whitelist {
            if let Some(host) = extract_host(raw_url) {
                if filter.contains(host) {
                    return (0.0, false, true);
                }
                let parts: Vec<&str> = host.split('.').collect();
                if parts.len() > 2 {
                    for i in 1..parts.len() - 1 {
                        let parent = parts[i..].join(".");
                        if filter.contains(&parent) {
                            return (0.0, false, true);
                        }
                    }
                }
            }
        }
        let prob = self.ml.predict_url(raw_url).unwrap_or(0.0);
        (prob, prob >= 0.50, false)
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
    if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
        s = rest;
    }
    let host_and_port = s.split(['/', '?', '#']).next()?;
    let host = host_and_port.split(':').next()?;
    let host = host.trim();
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
