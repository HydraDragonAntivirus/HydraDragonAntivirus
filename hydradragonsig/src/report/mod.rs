use crate::models::{ScanReport, Verdict};
use crate::scanner::ScanContext;
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeMap;

/// Numeric and boolean features of a scan, read by `feature_gte` rule conditions.
/// Rebuilt by the rule engine once it has extracted strings / PE data lazily.
pub fn compute_features(
    strings: usize,
    decoded: usize,
    env_hits: usize,
    entropy: f64,
    file_type: &crate::models::FileTypeInfo,
    pe: Option<&crate::models::PeInfo>,
) -> BTreeMap<String, serde_json::Value> {
    let mut features = BTreeMap::new();
    features.insert("string_count".into(), json!(strings));
    features.insert("decoded_string_count".into(), json!(decoded));
    features.insert("env_hit_count".into(), json!(env_hits));
    features.insert("file_entropy_bits_per_byte".into(), json!(entropy));
    features.insert("file_type_primary".into(), json!(&file_type.primary));
    features.insert("file_type_tags".into(), json!(&file_type.tags));
    features.insert("is_plain_text".into(), json!(file_type.is_plain_text));
    features.insert("is_binary".into(), json!(file_type.is_binary));
    features.insert("is_pe".into(), json!(file_type.is_pe));
    features.insert("is_elf".into(), json!(file_type.is_elf));
    features.insert("is_macho".into(), json!(file_type.is_macho));
    features.insert("is_apk".into(), json!(file_type.is_apk));
    features.insert("is_zip".into(), json!(file_type.is_zip));
    features.insert("is_archive".into(), json!(file_type.is_archive));
    features.insert("is_script".into(), json!(file_type.is_script));
    features.insert("is_broken_executable".into(), json!(file_type.is_broken_executable));
    if let Some(pe) = pe {
        features.insert("pe_import_count".into(), json!(pe.imports.len()));
        features.insert("pe_export_count".into(), json!(pe.exports.len()));
        features.insert("pe_section_count".into(), json!(pe.sections.len()));
        features.insert("pe_suspicious_import_count".into(), json!(pe.suspicious_imports.len()));
        features.insert("pe_likely_packed".into(), json!(pe.likely_packed));
    }
    features
}

/// Recomputes `report.features` from the report's current data.
pub fn refresh_features(report: &mut ScanReport) {
    report.features = compute_features(
        report.strings.len(),
        report.decoded_strings.len(),
        report.env_hits.len(),
        report.entropy,
        &report.file_type,
        report.pe.as_ref(),
    );
}

pub fn build_report(ctx: ScanContext) -> ScanReport {
    let features = compute_features(
        ctx.strings.len(),
        ctx.decoded_strings.len(),
        ctx.env_hits.len(),
        ctx.entropy,
        &ctx.file_type,
        ctx.pe.as_ref(),
    );

    ScanReport {
        path: ctx.path,
        scanned_at: Utc::now(),
        file_size: ctx.file_size,
        entropy: ctx.entropy,
        hashes: ctx.hashes,
        pe: ctx.pe,
        file_type: ctx.file_type,
        strings: ctx.strings,
        decoded_strings: ctx.decoded_strings,
        env_hits: ctx.env_hits,
        features,
        findings: Vec::new(),
        score: 0,
        verdict: Verdict::Clean,
        confidence: 0,
        malware_families: Vec::new(),
        rule_performance: Vec::new(),
        result_code: ctx.result_code,
        statistics: ctx.statistics,
        archive_members: Vec::new(),
        threat_name: None,
        mitre_techniques: Vec::new(), // Initialize empty - will be populated by rule engine
        parent: None,
    }
}
