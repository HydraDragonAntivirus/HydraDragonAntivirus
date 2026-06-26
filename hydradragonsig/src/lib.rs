pub mod models;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod signature_verification;
pub mod trusted_signers;
pub mod utils;

use anyhow::{Context, Result};
use models::{
    ArchiveMemberResult, CoreData, CoreInitOptions, Finding, MemoryScanContext,
    RegistryScanContext, ScanReport, ScanResultCode, UnpackConfig, Verdict,
};
use rules::{aggregate_verdict, RuleEvalOptions, RuleSet};
use scanner::{HydraScanner, ScanContext, ScannerConfig};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zip::ZipArchive;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_size: Option<u64>,
    pub profile_rules: bool,
    pub parallel_rules: bool,
    pub stop_on_detection: bool,
    pub min_string_len: usize,
    pub decode_obfuscated_strings: bool,
    /// SDK-inspired core initialization options
    pub core_options: CoreInitOptions,
    /// SDK-inspired unpacking configuration
    pub unpack_config: UnpackConfig,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: Some(2048 * 1024 * 1024),
            profile_rules: false,
            parallel_rules: false,
            stop_on_detection: true,
            min_string_len: 5,
            decode_obfuscated_strings: true,
            core_options: CoreInitOptions::default(),
            unpack_config: UnpackConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineCore {
    rules: RuleSet,
    options: ScanOptions,
    core_data: CoreData,
}

impl EngineCore {
    pub fn init(rules: RuleSet, options: ScanOptions) -> Self {
        let core_data = CoreData {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            signature_records: rules.rules().len() as u32,
            initialized: true,
            options: options.core_options.clone(),
        };
        Self {
            rules,
            options,
            core_data,
        }
    }

    pub fn core_data(&self) -> &CoreData {
        &self.core_data
    }

    pub fn set_options(&mut self, options: ScanOptions) {
        self.core_data.options = options.core_options.clone();
        self.options = options;
    }

    pub fn scan_path(&self, path: &Path) -> Result<ScanReport> {
        scan_path(path, &self.rules, &self.options)
    }

    pub fn scan_memory(&self, ctx: &MemoryScanContext) -> Result<ScanReport> {
        scan_memory(ctx, &self.rules, &self.options)
    }

    pub fn scan_registry_key(&self, ctx: &RegistryScanContext) -> Result<ScanReport> {
        scan_registry_key(ctx, &self.rules, &self.options)
    }
}

pub fn scan_path(path: &Path, rules: &RuleSet, options: &ScanOptions) -> Result<ScanReport> {
    if path.to_string_lossy().len() > 32_767 {
        anyhow::bail!("path too long: {}", path.display());
    }
    if let Some(max) = options.max_file_size {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("metadata failed for {}", path.display()))?;
        if meta.len() > max {
            anyhow::bail!("file too large: {} bytes > {} bytes", meta.len(), max);
        }
    }

    let scanner_config = scanner_config(options);
    let ctx = HydraScanner::scan_with_config(path, &scanner_config)?;
    finalize_scan_context(ctx, rules, options, &scanner_config, 0)
}

/// Scan an in-memory buffer without writing it to disk.
pub fn scan_memory(
    ctx: &MemoryScanContext,
    rules: &RuleSet,
    options: &ScanOptions,
) -> Result<ScanReport> {
    let scanner_config = scanner_config(options);
    let scan_ctx = HydraScanner::scan_memory(ctx, &scanner_config)?;
    finalize_scan_context(scan_ctx, rules, options, &scanner_config, 0)
}

/// Like [`scan_memory`] but consumes the context, moving its buffer into the scan
/// instead of cloning it. Use this on hot per-file paths.
pub fn scan_memory_owned(
    ctx: MemoryScanContext,
    rules: &RuleSet,
    options: &ScanOptions,
) -> Result<ScanReport> {
    let scanner_config = scanner_config(options);
    let scan_ctx = HydraScanner::scan_memory_owned(ctx, &scanner_config)?;
    finalize_scan_context(scan_ctx, rules, options, &scanner_config, 0)
}

/// Scan caller-supplied registry key/value text without reading the live registry.
pub fn scan_registry_key(
    ctx: &RegistryScanContext,
    rules: &RuleSet,
    options: &ScanOptions,
) -> Result<ScanReport> {
    let mut bytes = Vec::with_capacity(
        ctx.key.len()
            + ctx.value_name.as_ref().map(|v| v.len()).unwrap_or(0)
            + ctx.value_data.as_ref().map(|v| v.len()).unwrap_or(0)
            + 4,
    );
    bytes.extend_from_slice(ctx.key.as_bytes());
    bytes.push(b'\n');
    if let Some(value_name) = &ctx.value_name {
        bytes.extend_from_slice(value_name.as_bytes());
        bytes.push(b'\n');
    }
    if let Some(value_data) = &ctx.value_data {
        bytes.extend_from_slice(value_data);
    }

    let scanner_config = scanner_config(options);
    let scan_ctx = HydraScanner::scan_bytes(
        bytes,
        PathBuf::from(format!("registry://{}", ctx.key.replace('\\', "/"))),
        &scanner_config,
    )?;
    finalize_scan_context(scan_ctx, rules, options, &scanner_config, 0)
}

fn scanner_config(options: &ScanOptions) -> ScannerConfig {
    ScannerConfig {
        min_string_len: options.min_string_len,
        decode_obfuscated_strings: options.decode_obfuscated_strings,
        decode_config: scanner::strings::DecodeConfig::default(),
        core_options: options.core_options.clone(),
        unpack_config: options.unpack_config.clone(),
    }
}

fn finalize_scan_context(
    mut ctx: ScanContext,
    rules: &RuleSet,
    options: &ScanOptions,
    scanner_config: &ScannerConfig,
    archive_depth: u32,
) -> Result<ScanReport> {
    let post_scan_start = Instant::now();
    let bytes = std::mem::take(&mut ctx.bytes);
    let mut report = report::build_report(ctx);
    evaluate_rules(&mut report, &bytes, rules, options);
    finalize_report_metadata(&mut report, rules, options);

    if should_scan_archive(&report, &bytes, options, archive_depth) {
        let archive_scan = scan_archive_members_from_bytes(
            &report.path,
            &bytes,
            rules,
            options,
            scanner_config,
            archive_depth + 1,
        )?;
        report.archive_members.extend(archive_scan.members);
        report.findings.extend(archive_scan.findings);
        report.statistics.archive_members = report.archive_members.len() as u32;
        report.statistics.files_scanned = 1u32.saturating_add(report.statistics.archive_members);
        finalize_report_metadata(&mut report, rules, options);
    }

    report.statistics.scan_duration_ms = report
        .statistics
        .scan_duration_ms
        .saturating_add(post_scan_start.elapsed().as_millis().min(u64::MAX as u128) as u64);
    Ok(report)
}

fn evaluate_rules(report: &mut ScanReport, bytes: &[u8], rules: &RuleSet, options: &ScanOptions) {
    rules.evaluate_into(
        report,
        bytes,
        RuleEvalOptions {
            profile_rules: options.profile_rules,
            parallel_rules: options.parallel_rules,
            stop_on_detection: options.stop_on_detection,
        },
    );
}

fn finalize_report_metadata(report: &mut ScanReport, rules: &RuleSet, _options: &ScanOptions) {
    report.findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    aggregate_verdict(report);

    report.result_code = ScanResultCode::from_verdict(report.verdict);
    report.statistics.signature_records_used = rules.rules().len() as u32;
    report.statistics.infections_found = report
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.verdict,
                Verdict::Malware | Verdict::Pua
            )
        })
        .count() as u32;
    report.statistics.suspicious_found = report
        .findings
        .iter()
        .filter(|finding| finding.verdict == Verdict::Suspicious)
        .count() as u32;
    report.threat_name = report.findings.first().map(|finding| {
        finding
            .family
            .clone()
            .unwrap_or_else(|| finding.rule_id.clone())
    });
}

fn should_scan_archive(
    report: &ScanReport,
    bytes: &[u8],
    options: &ScanOptions,
    archive_depth: u32,
) -> bool {
    let unpack = &options.unpack_config;
    if !unpack.enable_archives || archive_depth >= unpack.max_archive_depth {
        return false;
    }
    if bytes.len() as u64 > unpack.max_archive_size {
        return false;
    }
    if (unpack.break_on_threat || options.core_options.break_archive_scan)
        && report.result_code.is_infected()
    {
        return false;
    }
    report.file_type.is_zip || report.file_type.is_apk || report.file_type.is_jar
}

#[derive(Debug, Default)]
struct ArchiveScanOutput {
    members: Vec<ArchiveMemberResult>,
    findings: Vec<Finding>,
}

fn scan_archive_members_from_bytes(
    parent_path: &Path,
    bytes: &[u8],
    rules: &RuleSet,
    options: &ScanOptions,
    scanner_config: &ScannerConfig,
    depth: u32,
) -> Result<ArchiveScanOutput> {
    let mut output = ArchiveScanOutput::default();
    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(_) => return Ok(output),
    };

    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .with_context(|| format!("failed to read archive member #{index}"))?;
        if member.is_dir() {
            continue;
        }

        let name = member.name().replace('\\', "/");
        let virtual_path = format!("archive://{}!{}", parent_path.display(), name);
        let size = member.size();
        let member_limit = options
            .max_file_size
            .unwrap_or(options.unpack_config.max_archive_size)
            .min(options.unpack_config.max_archive_size);

        if size > member_limit {
            output.members.push(ArchiveMemberResult {
                name,
                path: virtual_path,
                result_code: ScanResultCode::FileTooLarge,
                threat_name: None,
                size,
                depth,
            });
            continue;
        }

        let mut member_bytes = Vec::with_capacity((size as usize).min(1024 * 1024));
        if member.read_to_end(&mut member_bytes).is_err() {
            output.members.push(ArchiveMemberResult {
                name,
                path: virtual_path,
                result_code: ScanResultCode::OpenError,
                threat_name: None,
                size,
                depth,
            });
            continue;
        }
        if member_bytes.len() as u64 > member_limit {
            output.members.push(ArchiveMemberResult {
                name,
                path: virtual_path,
                result_code: ScanResultCode::FileTooLarge,
                threat_name: None,
                size: member_bytes.len() as u64,
                depth,
            });
            continue;
        }

        let scan_ctx = HydraScanner::scan_bytes(
            member_bytes,
            PathBuf::from(virtual_path.clone()),
            scanner_config,
        )?;
        let member_report = finalize_scan_context(scan_ctx, rules, options, scanner_config, depth)?;
        let result_code = member_report.result_code;
        let threat_name = member_report.threat_name.clone();
        let scanned_size = member_report.file_size;

        output.members.push(ArchiveMemberResult {
            name,
            path: virtual_path.clone(),
            result_code,
            threat_name,
            size: scanned_size,
            depth,
        });
        output
            .members
            .extend(member_report.archive_members.iter().cloned());

        let mut member_findings = member_report.findings.clone();
        prefix_archive_findings(&mut member_findings, &virtual_path);
        output.findings.extend(member_findings);

        if (options.unpack_config.break_on_threat || options.core_options.break_archive_scan)
            && result_code.is_infected()
        {
            break;
        }
    }

    Ok(output)
}

fn prefix_archive_findings(findings: &mut [Finding], virtual_path: &str) {
    for finding in findings {
        finding
            .evidence
            .insert(0, format!("archive_member {}", virtual_path));
    }
}
