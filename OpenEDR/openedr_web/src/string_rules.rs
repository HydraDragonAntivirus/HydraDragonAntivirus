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
    FileTypeInfo, Hashes, ScanReport, ScanResultCode, ScanStatistics, StringHit as HydraStringHit,
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

    pub fn pattern_count(&self) -> usize {
        self.ruleset.as_ref().map(|r| r.rules().len()).unwrap_or(0)
    }

    /// Evaluate loaded rules over extracted strings. `is_pe` tags the file
    /// for `FileType` conditions (no other classification is done here).
    pub fn scan_bytes(
        &self,
        data: &[u8],
        target_name: &str,
        sha256_hex: &str,
        md5_hex: &str,
        strings: &[String],
        is_pe: bool,
        cap: usize,
    ) -> Vec<Hit> {
        let rs = match self.ruleset.as_ref() {
            Some(rs) if !strings.is_empty() && cap > 0 => rs,
            _ => return Vec::new(),
        };
        let mut report = ScanReport {
            path: PathBuf::from(target_name),
            // No clock on wasm32-unknown-unknown; epoch is never read by
            // string/filetype conditions, only stamped on the report.
            scanned_at: Default::default(),
            file_size: data.len() as u64,
            entropy: shannon_entropy(data),
            hashes: Hashes {
                sha256: sha256_hex.to_string(),
                md5: md5_hex.to_string(),
            },
            pe: None,
            file_type: FileTypeInfo {
                primary: if is_pe { "pe".to_string() } else { "unknown".to_string() },
                tags: if is_pe { vec!["pe".to_string()] } else { Vec::new() },
                extension: None,
                is_plain_text: false,
                is_binary: true,
                is_pe,
                is_pe32: false,
                is_pe64: false,
                is_elf: false,
                is_elf32: false,
                is_elf64: false,
                is_macho: false,
                is_apk: false,
                is_zip: false,
                is_archive: false,
                is_7z: false,
                is_rar: false,
                is_gzip: false,
                is_tar: false,
                is_jar: false,
                is_dex: false,
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
        };
        let options = RuleEvalOptions {
            profile_rules: false,
            parallel_rules: false,
            stop_on_detection: false,
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

/// Normalize a raw binary string for matching: lowercase + forward
/// slashes to backslashes.
pub fn normalize_text(s: &str) -> String {
    s.to_lowercase().replace('/', "\\")
}
