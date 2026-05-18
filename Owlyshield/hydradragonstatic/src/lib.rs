pub mod models;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod utils;

use anyhow::{Context, Result};
use models::ScanReport;
use rules::{aggregate_verdict, RuleEvalOptions, RuleSet};
use scanner::{HydraScanner, ScannerConfig};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_size: Option<u64>,
    pub profile_rules: bool,
    pub parallel_rules: bool,
    pub stop_on_detection: bool,
    pub min_string_len: usize,
    pub decode_obfuscated_strings: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: Some(128 * 1024 * 1024),
            profile_rules: false,
            parallel_rules: false,
            stop_on_detection: false,
            min_string_len: 5,
            decode_obfuscated_strings: true,
        }
    }
}

pub fn scan_path(path: &Path, rules: &RuleSet, options: &ScanOptions) -> Result<ScanReport> {
    if let Some(max) = options.max_file_size {
        let meta = std::fs::metadata(path).with_context(|| format!("metadata failed for {}", path.display()))?;
        if meta.len() > max {
            anyhow::bail!("file too large: {} bytes > {} bytes", meta.len(), max);
        }
    }
    let scanner_config = ScannerConfig {
        min_string_len: options.min_string_len,
        decode_obfuscated_strings: options.decode_obfuscated_strings,
    };
    let mut ctx = HydraScanner::scan_with_config(path, &scanner_config)?;
    // Avoid cloning the full input buffer. The report does not serialize raw bytes,
    // so move them out and keep one owned copy for byte-pattern rules.
    let bytes = std::mem::take(&mut ctx.bytes);
    let mut report = report::build_report(ctx);
    rules.evaluate_into(&mut report, &bytes, RuleEvalOptions {
        profile_rules: options.profile_rules,
        parallel_rules: options.parallel_rules,
        stop_on_detection: options.stop_on_detection,
    });
    report.findings.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.rule_id.cmp(&b.rule_id)));
    aggregate_verdict(&mut report);
    Ok(report)
}
