//! Thin web adapter over the hydradragonsig rule engine.
//!
//! String rules are evaluated by hydradragonsig's OWN code
//! (`RuleSet::from_yaml_str` + `evaluate_into` + `aggregate_verdict`) —
//! nothing is reimplemented here. Executable gating lives in the RULE DATA
//! as `FileType` conditions, enforced by the engine against the file-type
//! tag this adapter supplies per scan.

use std::collections::BTreeMap;
use std::path::PathBuf;

use hydradragonsig::models::{
    FileTypeInfo, Hashes, ParentInfo, ScanReport, ScanResultCode, ScanStatistics, StringHit as HydraStringHit,
    Verdict,
};
use hydradragonsig::rules::{aggregate_verdict, RuleEvalOptions, RuleSet};

/// One string-rule finding, mapped from hydradragonsig's `Finding`.
#[derive(Debug, Clone)]
pub struct Hit {
    pub rule: String,
    pub title: String,
    pub score: u32,
    pub evidence: Vec<String>,
}

#[derive(Debug, Default)]
pub struct PeStringRules {
    ruleset: Option<RuleSet>,
}

impl PeStringRules {
    /// Load a hydradragonsig `Rule` YAML document. Returns the rule count,
    /// or -1 when the document holds no usable rules.
    pub fn load_yaml(&mut self, yaml: &str) -> i32 {
        match RuleSet::from_yaml_str(yaml) {
            Ok(rs) => {
                // Problems that do not stop loading (unknown keys, invalid regexes...).
                for w in rs.warnings().iter().take(20) {
                    eprintln!("[engine] string rules warning: {w}");
                }
                let n = rs.rules().len();
                if n == 0 {
                    return -1;
                }
                if let Some(cur) = self.ruleset.as_mut() {
                    cur.extend(rs);
                    cur.rules().len() as i32
                } else {
                    self.ruleset = Some(rs);
                    n as i32
                }
            }
            Err(_) => -1,
        }
    }

    /// Drops rules by id (`.ign2` false-positive lists next to the rule files).
    pub fn ignore(&mut self, ids: &std::collections::HashSet<String>) -> usize {
        self.ruleset.as_mut().map_or(0, |rs| rs.remove_ids(ids))
    }

    pub fn pattern_count(&self) -> usize {
        self.ruleset.as_ref().map(|r| r.rules().len()).unwrap_or(0)
    }

    /// Evaluate loaded rules over extracted strings. `is_pe` tags the file
    /// for `FileType` conditions (no other classification is done here).
    /// `is_apk` tags Android packages (APK/ZIP/DEX) the same way.
    /// `parent` is the file this buffer came from (packed original of a Unicorn
    /// dump): it enables the parent-comparison conditions (`has_parent`,
    /// `parent_feature_lte`, `feature_delta_gte`, `new_import_set`).
    pub fn scan_bytes(
        &self,
        data: &[u8],
        target_name: &str,
        sha256_hex: &str,
        strings: &[String],
        is_pe: bool,
        is_apk: bool,
        cap: usize,
        parent: Option<&ParentInfo>,
    ) -> Vec<Hit> {
        self.scan_bytes_with_behavior(
            data,
            target_name,
            sha256_hex,
            strings,
            is_pe,
            is_apk,
            cap,
            parent,
            None,
        )
    }

    /// Evaluate loaded rules over extracted strings and emulated behavior trace.
    pub fn scan_bytes_with_behavior(
        &self,
        data: &[u8],
        target_name: &str,
        sha256_hex: &str,
        strings: &[String],
        is_pe: bool,
        is_apk: bool,
        cap: usize,
        parent: Option<&ParentInfo>,
        behavior: Option<&hydradragonsig::models::BehaviorTrace>,
    ) -> Vec<Hit> {
        let rs = match self.ruleset.as_ref() {
            Some(rs) if (!strings.is_empty() || behavior.is_some()) && cap > 0 => rs,
            _ => return Vec::new(),
        };
        // The PE is parsed and the entropy computed by hydradragonsig only when a
        // rule needs them (imports, sections, entropy...): most scans never do.
        // PE32 / PE32+ comes from the optional header magic.
        let pe = None;
        let bits = if is_pe { pe_bitness(data) } else { None };
        let is_pe32 = bits == Some(32);
        let is_pe64 = bits == Some(64);

        let mut report = ScanReport {
            path: PathBuf::from(target_name),
            // No clock on wasm32-unknown-unknown; epoch is never read by
            // string/filetype conditions, only stamped on the report.
            scanned_at: Default::default(),
            file_size: data.len() as u64,
            entropy: 0.0,
            hashes: Hashes {
                sha256: sha256_hex.to_string(),
                md5: String::new(),
            },
            pe,
            file_type: FileTypeInfo {
                primary: if is_pe {
                    "pe".to_string()
                } else if is_apk {
                    "apk".to_string()
                } else {
                    "unknown".to_string()
                },
                tags: if is_pe {
                    vec!["pe".to_string()]
                } else if is_apk {
                    vec!["apk".to_string(), "zip".to_string(), "archive".to_string()]
                } else {
                    Vec::new()
                },
                extension: None,
                is_plain_text: false,
                is_binary: true,
                is_pe,
                is_pe32,
                is_pe64,
                is_elf: false,
                is_elf32: false,
                is_elf64: false,
                is_macho: false,
                is_apk,
                is_zip: is_apk,
                is_archive: is_apk,
                is_7z: false,
                is_rar: false,
                is_gzip: false,
                is_tar: false,
                is_jar: false,
                is_dex: is_apk,
                is_java_class: false,
                is_pdf: false,
                is_office: false,
                is_microsoft_compound: false,
                is_script: false,
                is_powershell: false,
                is_batch: false,
                is_javascript: false,
                is_vbs: false,
                is_python: false,
                is_broken_executable: false,
                is_broken_apk: false,
                broken_executable_type: None,
            },
            strings: strings
                .iter()
                .map(|s| HydraStringHit {
                    value: s.clone(),
                    offset: 0,
                    encoding: "ascii".to_string(),
                })
                .collect(),
            decoded_strings: Vec::new(),
            env_hits: Vec::new(),
            features: BTreeMap::new(),
            findings: Vec::new(),
            score: 0,
            verdict: Verdict::Clean,
            confidence: 0,
            malware_families: Vec::new(),
            rule_performance: Vec::new(),
            result_code: ScanResultCode::Ok,
            statistics: ScanStatistics::default(),
            archive_members: Vec::new(),
            threat_name: None,
            mitre_techniques: Vec::new(),
            parent: parent.cloned(),
            behavior: behavior.cloned(),
        };
        let options = RuleEvalOptions {
            profile_rules: false,
            parallel_rules: false,
            stop_on_detection: false,
            // The strings are supplied above; decoding / extraction only for
            // conditions that ask for them.
            min_string_len: 0,
            decode_strings: true,
        };
        rs.evaluate_into(&mut report, data, options);
        aggregate_verdict(&mut report);
        report
            .findings
            .iter()
            .take(cap)
            .map(|f| Hit {
                rule: f.rule_id.clone(),
                title: f.title.clone(),
                score: f.score,
                evidence: f.evidence.clone(),
            })
            .collect()
    }
}

/// File byte ranges `[start, end)` behind hydradragonsig evidence lines, for
/// in-place disinfection. Evidence names what matched as "`value` at 0x..":
///
/// * byte patterns (`4D 5A ?? 90`): the offset is exact, the length is the token count;
/// * regexes and text (literal, string_contains, xor'd text, ASCII case-insensitive
///   or UTF-16LE): ONLY when the value is found at the reported offset. Other
///   occurrences are never touched: the same text often also sits somewhere
///   legitimate. Evidence without a real location (offset 0 while the value is
///   elsewhere, e.g. a decoded or stack string) gives no range.
///
/// Values shorter than 4 bytes are skipped (they would wipe headers such as `MZ`).
/// At most `limit` ranges.
pub fn evidence_ranges(data: &[u8], evidence: &[String], limit: usize) -> Vec<(usize, usize)> {
    const MIN_LEN: usize = 4;
    let mut out: Vec<(usize, usize)> = Vec::new();
    for line in evidence {
        for (value, offset) in evidence_items(line) {
            if out.len() >= limit {
                break;
            }
            let lower = line.to_ascii_lowercase();
            let xor_key = lower
                .find("xor(0x")
                .and_then(|i| u8::from_str_radix(lower[i + 6..].split(')').next().unwrap_or(""), 16).ok());
            // Byte pattern: exact offset (xor'd bytes are checked by length only).
            // A value that only looks like hex ("abc123") falls through to text.
            if let Some(len) = hex_pattern_len(&value) {
                let ok = xor_key.is_some() || hex_pattern_matches(data, offset, &value);
                if ok && offset.saturating_add(len) <= data.len() {
                    if len >= MIN_LEN {
                        out.push((offset, offset + len));
                    }
                    continue;
                }
            }
            let Some(at) = data.get(offset..).filter(|r| !r.is_empty()) else { continue };
            if lower.contains("regex") {
                // Anchored at the reported offset: a match elsewhere is not this evidence.
                if let Ok(re) = regex::bytes::Regex::new(&format!("^(?:{value})")) {
                    if let Some(m) = re.find(at).filter(|m| m.end() >= MIN_LEN) {
                        out.push((offset, offset + m.end()));
                    }
                }
            } else if value.len() >= MIN_LEN {
                let ascii: Vec<u8> = match xor_key {
                    Some(k) => value.bytes().map(|b| b ^ k).collect(),
                    None => value.as_bytes().to_vec(),
                };
                let wide: Vec<u8> = value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                let starts = |needle: &[u8], nocase: bool| {
                    at.get(..needle.len()).is_some_and(|w| if nocase { w.eq_ignore_ascii_case(needle) } else { w == needle })
                };
                if starts(&ascii, xor_key.is_none()) {
                    out.push((offset, offset + ascii.len()));
                } else if xor_key.is_none() && starts(&wide, true) {
                    out.push((offset, offset + wide.len()));
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out.truncate(limit);
    out
}

/// "`value` at 0xNN" pairs of one evidence line.
fn evidence_items(line: &str) -> Vec<(String, usize)> {
    let mut items = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("` at 0x") {
        let head = &rest[..at];
        let tail = &rest[at + "` at 0x".len()..];
        let hex: String = tail.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if let (Some(open), Ok(offset)) = (head.rfind('`'), usize::from_str_radix(&hex, 16)) {
            items.push((head[open + 1..].to_string(), offset));
        }
        rest = &tail[hex.len()..];
    }
    items
}

/// Byte count of a plain hex pattern (`4D 5A ?? 90`, `4d5a`), None when `s` is not one.
fn hex_pattern_len(s: &str) -> Option<usize> {
    let tokens = hex_tokens(s)?;
    (!tokens.is_empty()).then_some(tokens.len())
}

fn hex_tokens(s: &str) -> Option<Vec<Option<u8>>> {
    // Rule syntax wraps byte patterns in braces: `{ 4c 5a ?? 4b }`.
    let s = s.trim().trim_start_matches('{').trim_end_matches('}').trim();
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 2 || compact.len() % 2 != 0 {
        return None;
    }
    // A pure-letter word like "dead" or "cafe" is text, not bytes, unless spaced.
    if !s.contains(' ') && !compact.contains("??") && !compact.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    compact
        .as_bytes()
        .chunks(2)
        .map(|p| match p {
            b"??" => Some(None),
            _ => std::str::from_utf8(p).ok().and_then(|h| u8::from_str_radix(h, 16).ok()).map(Some),
        })
        .collect()
}

fn hex_pattern_matches(data: &[u8], offset: usize, pattern: &str) -> bool {
    let Some(tokens) = hex_tokens(pattern) else { return false };
    let Some(window) = data.get(offset..offset.saturating_add(tokens.len())) else { return false };
    window.len() == tokens.len() && tokens.iter().zip(window).all(|(t, b)| t.is_none_or(|t| t == *b))
}

/// 32 or 64 from the PE optional header magic (0x10b / 0x20b).
fn pe_bitness(data: &[u8]) -> Option<u32> {
    let lfanew = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if data.get(lfanew..lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let magic = lfanew.checked_add(24)?;
    match u16::from_le_bytes(data.get(magic..magic + 2)?.try_into().ok()?) {
        0x10b => Some(32),
        0x20b => Some(64),
        _ => None,
    }
}

#[allow(dead_code)]
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Preserves the raw string for exact-case and slash matching in RuleSet.
pub fn normalize_text(s: &str) -> String {
    s.to_string()
}

/// Rule ids listed in the `*.ign2` / `*.ign` files of `dir` (ClamAV ignore-list
/// format: `Name` or `Name:md5` per line, `#` comments, blank lines ignored).
pub fn read_ignore_lists(dir: &std::path::Path) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let p = entry.path();
        let is_ign = p
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("ign2") || e.eq_ignore_ascii_case("ign"));
        if !is_ign {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = line.split(':').next().unwrap_or("").trim();
            if !name.is_empty() {
                out.insert(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod evidence_tests {
    use super::evidence_ranges;

    #[test]
    fn text_bytes_and_regex_evidence() {
        let mut data = b"MZ..http://evil.example/x..EVIL.EXAMPLE..".to_vec();
        data.extend("evil.example".encode_utf16().flat_map(|u| u.to_le_bytes()));
        data.extend([0x4D, 0x5A, 0x90, 0x00, 0x03]);
        let n = data.len();
        let ev = vec!["string_contains `evil.example` at 0x0".to_string()];
        assert!(evidence_ranges(&data, &ev, 64).is_empty(), "text not at its offset: no range, not every occurrence");
        let ev = vec!["string_contains `evil.example` at 0x1b".to_string()];
        assert_eq!(evidence_ranges(&data, &ev, 64), vec![(27, 39)], "only the located occurrence (case-insensitive)");
        let ev = vec!["string_contains `evil.example` at 0x29".to_string()];
        assert_eq!(evidence_ranges(&data, &ev, 64), vec![(41, 65)], "UTF-16LE at its offset");
        let ev = vec![format!("byte_pattern `4D 5A ?? 00` at 0x{:x}", n - 5)];
        assert_eq!(evidence_ranges(&data, &ev, 64), vec![(n - 5, n - 1)]);
        let ev = vec!["byte_pattern `4D 5A 91 00` at 0x0".to_string()];
        assert!(evidence_ranges(&data, &ev, 64).is_empty(), "bytes must match at the offset");
        let ev = vec!["string_regex `http://[a-z.]+/x` at 0x0".to_string()];
        assert!(evidence_ranges(&data, &ev, 64).is_empty(), "regex not matching at its offset");
        let ev = vec!["string_regex `http://[a-z.]+/x` at 0x4".to_string()];
        assert_eq!(evidence_ranges(&data, &ev, 64), vec![(4, 25)]);
        let ev = vec!["literal `MZ` at 0x0".to_string(), "pe imports kernel32".to_string()];
        assert!(evidence_ranges(&data, &ev, 64).is_empty(), "short values and lines without offsets");
        let ev = vec!["`evil.example` at 0x1b, `http://` at 0x4, `EVIL.EXAMPLE` at 0xb".to_string()];
        assert_eq!(evidence_ranges(&data, &ev, 2).len(), 2, "limit");
    }

    #[test]
    fn real_hydradragonsig_evidence() {
        let yaml = r#"
rules:
  - id: TEST-TEXT
    title: "text"
    severity: high
    verdict: malware
    confidence: 90
    score: 90
    logic: any
    conditions:
      - type: string_set
        min: 1
        nocase: true
        values: ['drivers\etc\hosts']
  - id: TEST-BYTES
    title: "bytes"
    severity: high
    verdict: malware
    confidence: 90
    score: 90
    logic: any
    conditions:
      - type: byte_pattern
        pattern: "{ 4c 5a 55 4b ?? 00 }"
"#;
        let mut rules = super::PeStringRules::default();
        assert_eq!(rules.load_yaml(yaml), 2);
        let mut data = b"xxxx C:\\Windows\\System32\\drivers\\etc\\hosts yyyy ".to_vec();
        let text_at = 5 + "C:\\Windows\\System32\\".len();
        let bytes_at = data.len();
        data.extend(b"LZUK\x03\x00tail");
        let strings: Vec<String> = vec![String::from_utf8_lossy(&data[5..bytes_at - 1]).into_owned()];
        let hits = rules.scan_bytes(&data, "x.bin", "00", &strings, false, false, 10, None);
        let mut ranges: Vec<(usize, usize)> =
            hits.iter().flat_map(|h| super::evidence_ranges(&data, &h.evidence, 16)).collect();
        ranges.sort();
        // hydradragonsig locates the string in the file: only that occurrence is used.
        assert_eq!(ranges, vec![(text_at, text_at + "drivers\\etc\\hosts".len()), (bytes_at, bytes_at + 6)], "{hits:?}");
    }

    #[test]
    fn xor_text() {
        let key = 0x41u8;
        let mut data = b"xx".to_vec();
        data.extend(b"payload!".iter().map(|b| b ^ key));
        let ev = vec!["$a xor(0x41) ascii text `payload!` at 0x2".to_string()];
        assert_eq!(evidence_ranges(&data, &ev, 8), vec![(2, 10)]);
    }
}
