use crate::models::{ScanReport, Verdict};
use crate::scanner::ScanContext;
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeMap;

pub fn build_report(ctx: ScanContext) -> ScanReport {
    let mut features = BTreeMap::new();
    features.insert("string_count".into(), json!(ctx.strings.len()));
    features.insert(
        "decoded_string_count".into(),
        json!(ctx.decoded_strings.len()),
    );
    features.insert("env_hit_count".into(), json!(ctx.env_hits.len()));
    features.insert("registry_hit_count".into(), json!(ctx.registry_hits.len()));
    features.insert("file_entropy_bits_per_byte".into(), json!(ctx.entropy));
    features.insert("file_type_primary".into(), json!(&ctx.file_type.primary));
    features.insert("file_type_tags".into(), json!(&ctx.file_type.tags));
    features.insert("is_plain_text".into(), json!(ctx.file_type.is_plain_text));
    features.insert("is_binary".into(), json!(ctx.file_type.is_binary));
    features.insert("is_pe".into(), json!(ctx.file_type.is_pe));
    features.insert("is_elf".into(), json!(ctx.file_type.is_elf));
    features.insert("is_macho".into(), json!(ctx.file_type.is_macho));
    features.insert("is_apk".into(), json!(ctx.file_type.is_apk));
    features.insert("is_zip".into(), json!(ctx.file_type.is_zip));
    features.insert("is_archive".into(), json!(ctx.file_type.is_archive));
    features.insert("is_script".into(), json!(ctx.file_type.is_script));
    features.insert(
        "is_broken_executable".into(),
        json!(ctx.file_type.is_broken_executable),
    );
    if let Some(pe) = &ctx.pe {
        features.insert("pe_import_count".into(), json!(pe.imports.len()));
        features.insert(
            "pe_suspicious_import_count".into(),
            json!(pe.suspicious_imports.len()),
        );
        features.insert("pe_likely_packed".into(), json!(pe.likely_packed));
    }

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
        registry_hits: ctx.registry_hits,
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
        signature: ctx.signature,
        mitre_techniques: Vec::new(), // Initialize empty - will be populated by rule engine
    }
}
