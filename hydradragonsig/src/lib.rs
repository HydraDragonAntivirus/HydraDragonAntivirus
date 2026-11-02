pub mod fuzzy;
pub mod models;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod utils;

use anyhow::{Context, Result};
use models::{
    ArchiveMemberResult, BehaviorTrace, CoreData, CoreInitOptions, Finding, MemoryScanContext, ParentInfo,
    ScanReport, ScanResultCode, UnpackConfig, Verdict,
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
    pub compute_hashes: bool,
    pub compute_entropy: bool,
    /// SDK-inspired core initialization options
    pub core_options: CoreInitOptions,
    /// SDK-inspired unpacking configuration
    pub unpack_config: UnpackConfig,
    /// The file this buffer came from (packed original of an unpacked dump,
    /// dropper of an extracted payload). Enables the parent-comparison
    /// conditions; `None` for ordinary scans. Archive members get their
    /// archive as parent automatically.
    pub parent: Option<ParentInfo>,
    /// API trace of the buffer from an emulator run (see `models::BehaviorTrace`).
    /// Enables the `emulated_*` conditions; `None` means they never match.
    pub behavior: Option<BehaviorTrace>,
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
            compute_hashes: false,
            compute_entropy: false,
            core_options: CoreInitOptions::default(),
            unpack_config: UnpackConfig::default(),
            parent: None,
            behavior: None,
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

fn scanner_config(options: &ScanOptions) -> ScannerConfig {
    ScannerConfig {
        min_string_len: options.min_string_len,
        decode_obfuscated_strings: options.decode_obfuscated_strings,
        decode_config: scanner::strings::DecodeConfig::default(),
        core_options: options.core_options.clone(),
        unpack_config: options.unpack_config.clone(),
        lazy_extraction: true,
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
    report.parent = options.parent.clone();
    report.behavior = options.behavior.clone();
    if report.dex.is_none() && (report.file_type.is_dex || crate::scanner::dex::is_dex(&bytes)) {
        report.dex = crate::scanner::dex::parse_dex(&bytes);
    }
    if report.apk.is_none() && report.file_type.is_apk {
        report.apk = crate::scanner::apk::apk_info(&bytes);
    }
    evaluate_rules(&mut report, &bytes, rules, options);
    // Strings / PE data may have been loaded lazily by the rules.
    report::refresh_features(&mut report);
    finalize_report_metadata(&mut report, &bytes, rules, options);

    if should_scan_archive(&report, &bytes, options, archive_depth) {
        // Members are compared against the archive that carried them.
        let member_options = ScanOptions {
            parent: Some(ParentInfo::from_report(&report)),
            ..options.clone()
        };
        let archive_scan = scan_archive_members_from_bytes(
            &report.path,
            &bytes,
            rules,
            &member_options,
            scanner_config,
            archive_depth + 1,
        )?;
        report.archive_members.extend(archive_scan.members);
        report.findings.extend(archive_scan.findings);
        report.statistics.archive_members = report.archive_members.len() as u32;
        report.statistics.files_scanned = 1u32.saturating_add(report.statistics.archive_members);
        finalize_report_metadata(&mut report, &bytes, rules, options);
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
            min_string_len: options.min_string_len,
            decode_strings: options.decode_obfuscated_strings,
        },
    );
}

fn finalize_report_metadata(report: &mut ScanReport, bytes: &[u8], rules: &RuleSet, options: &ScanOptions) {
    if options.compute_hashes && report.hashes.sha256.is_empty() && !bytes.is_empty() {
        report.hashes = crate::utils::hash::hashes(bytes);
    }
    if options.compute_entropy && report.entropy == 0.0 && !bytes.is_empty() {
        report.entropy = crate::utils::entropy::byte_entropy(bytes);
    }
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
    report.file_type.is_zip
        || report.file_type.is_apk
        || report.file_type.is_jar
        || report.file_type.is_microsoft_compound
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
    if scanner::cfb::is_cfb(bytes) {
        return Ok(scan_cfb_members(parent_path, bytes, rules, options, scanner_config, depth));
    }
    let mut output = ArchiveScanOutput::default();
    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(_) => return Ok(output),
    };

    for index in 0..archive.len() {
        // An encrypted or broken member is recorded and skipped: it must not end the
        // scan of the other members (and of the archive itself).
        let entry_name = archive.name_for_index(index).unwrap_or("").replace('\\', "/");
        let mut member = match archive.by_index(index) {
            Ok(m) => m,
            Err(_) => {
                let name = entry_name;
                output.members.push(ArchiveMemberResult {
                    path: format!("archive://{}!{}", parent_path.display(), name),
                    name,
                    result_code: ScanResultCode::OpenError,
                    threat_name: None,
                    size: 0,
                    depth,
                });
                continue;
            }
        };
        if member.is_dir() {
            continue;
        }

        let name = member.name().replace('\\', "/");
        let virtual_path = format!("archive://{}!{}", parent_path.display(), name);
        let size = member.size();
        let member_limit = member_limit(options);

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

        if scan_member(&mut output, name, virtual_path, member_bytes, size, rules, options, scanner_config, depth) {
            break;
        }
    }

    Ok(output)
}

fn member_limit(options: &ScanOptions) -> u64 {
    options
        .max_file_size
        .unwrap_or(options.unpack_config.max_archive_size)
        .min(options.unpack_config.max_archive_size)
}

/// Scan one extracted member and record it. Returns true when the archive scan
/// should stop (a threat was found and break-on-threat is set).
#[allow(clippy::too_many_arguments)]
fn scan_member(
    output: &mut ArchiveScanOutput,
    name: String,
    virtual_path: String,
    member_bytes: Vec<u8>,
    size: u64,
    rules: &RuleSet,
    options: &ScanOptions,
    scanner_config: &ScannerConfig,
    depth: u32,
) -> bool {
    let member_report = match HydraScanner::scan_bytes(member_bytes, PathBuf::from(virtual_path.clone()), scanner_config)
        .and_then(|ctx| finalize_scan_context(ctx, rules, options, scanner_config, depth))
    {
        Ok(r) => r,
        Err(_) => {
            output.members.push(ArchiveMemberResult {
                name,
                path: virtual_path,
                result_code: ScanResultCode::OpenError,
                threat_name: None,
                size,
                depth,
            });
            return false;
        }
    };
    let result_code = member_report.result_code;

    output.members.push(ArchiveMemberResult {
        name,
        path: virtual_path.clone(),
        result_code,
        threat_name: member_report.threat_name.clone(),
        size: member_report.file_size,
        depth,
    });
    output.members.extend(member_report.archive_members.iter().cloned());

    let mut member_findings = member_report.findings;
    prefix_archive_findings(&mut member_findings, &virtual_path);
    output.findings.extend(member_findings);

    (options.unpack_config.break_on_threat || options.core_options.break_archive_scan) && result_code.is_infected()
}

/// Streams of a compound file (OLE2) as members; a `\x01Ole10Native` stream
/// also yields the file it embeds, as `<stream>/<embedded name>`.
fn scan_cfb_members(
    parent_path: &Path,
    bytes: &[u8],
    rules: &RuleSet,
    options: &ScanOptions,
    scanner_config: &ScannerConfig,
    depth: u32,
) -> ArchiveScanOutput {
    let mut output = ArchiveScanOutput::default();
    let limit = member_limit(options);
    let cap = usize::try_from(limit).unwrap_or(usize::MAX);
    let total = usize::try_from(options.unpack_config.max_archive_size).unwrap_or(usize::MAX);
    let Some(streams) = scanner::cfb::read_streams(bytes, cap, total) else {
        return output;
    };
    for stream in streams {
        let virtual_path = format!("archive://{}!{}", parent_path.display(), stream.path);
        if stream.size > limit {
            output.members.push(ArchiveMemberResult {
                name: stream.path,
                path: virtual_path,
                result_code: ScanResultCode::FileTooLarge,
                threat_name: None,
                size: stream.size,
                depth,
            });
            continue;
        }
        let embedded = stream
            .path
            .ends_with("\\x01Ole10Native")
            .then(|| scanner::cfb::ole10native_payload(&stream.data))
            .flatten();
        if scan_member(&mut output, stream.path.clone(), virtual_path, stream.data, stream.size, rules, options, scanner_config, depth) {
            break;
        }
        if let Some((file_name, payload)) = embedded {
            let name = format!("{}/{}", stream.path, file_name);
            let path = format!("archive://{}!{}", parent_path.display(), name);
            let size = payload.len() as u64;
            if scan_member(&mut output, name, path, payload, size, rules, options, scanner_config, depth) {
                break;
            }
        }
    }
    output
}

fn prefix_archive_findings(findings: &mut [Finding], virtual_path: &str) {
    for finding in findings {
        finding
            .evidence
            .insert(0, format!("archive_member {}", virtual_path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(bytes: Vec<u8>, yaml: &str) -> ScanReport {
        let rules = RuleSet::from_yaml_str(yaml).expect("rules");
        assert!(rules.warnings().is_empty(), "{:?}", rules.warnings());
        let ctx = MemoryScanContext { buffer: bytes, identifier: "sample".into(), base_address: None };
        scan_memory(&ctx, &rules, &ScanOptions::default()).expect("scan")
    }

    #[test]
    fn apk_profile_in_report_and_feature_rules() {
        let dex = scanner::dex::tests::build_dex(&["Lcom/foo/Bar;", "onCreate"], &[0], &[0], &[(0, 1)]);
        let manifest = b"\x03\x00\x08\x00 android.permission.SEND_SMS android.permission.READ_SMS android.permission.RECEIVE_SMS ";
        let apk = scanner::apk::tests::zip_of(&[("AndroidManifest.xml", manifest), ("classes.dex", &dex)]);
        let report = scan(
            apk,
            r#"
rules:
  - id: TEST-APK-SMS-TRIO
    title: premium sms permission trio
    severity: high
    verdict: suspicious
    logic: all
    conditions:
      - type: feature_gte
        name: apk_sms_trio
        value: 1
      - type: feature_gte
        name: apk_dex_classes
        value: 1
"#,
        );
        let apk = report.apk.as_ref().expect("apk profile");
        assert_eq!(apk.features.len(), scanner::apk::APK_TREE_FEATURE_COUNT);
        assert_eq!(apk.features["sms_trio"], 1.0);
        assert_eq!(report.features["apk_dex_methods"], serde_json::json!(1.0));
        assert!(report.findings.iter().any(|f| f.rule_id == "TEST-APK-SMS-TRIO"), "{:?}", report.findings);
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["apk"]["features"]["dex_classes"].is_number());
        assert!(json.get("dex").is_none(), "the APK itself is not a DEX");
    }

    #[test]
    fn unknown_apk_feature_is_a_load_warning() {
        let rules = RuleSet::from_yaml_str(
            "rules:\n  - id: X\n    title: x\n    severity: low\n    conditions:\n      - type: feature_gte\n        name: apk_no_such_feature\n        value: 1\n",
        )
        .unwrap();
        assert!(rules.warnings().iter().any(|w| w.contains("apk_no_such_feature")), "{:?}", rules.warnings());
    }

    #[test]
    fn compound_file_streams_and_embedded_objects_are_scanned() {
        let big = vec![0x41u8; 4096];
        let native = scanner::cfb::tests::ole10native("dropper.js", b"var s = new ActiveXObject('WScript.Shell');");
        let file = scanner::cfb::tests::build_cfb(b"plain stream text", &big, &native);

        let report = scan(
            file.clone(),
            r#"
rules:
  - id: TEST-OLE-EMBEDDED-SCRIPT
    title: script embedded through the OLE packager
    severity: high
    verdict: malware
    logic: all
    conditions:
      - type: path_regex
        pattern: "Ole10Native/dropper\\.js$"
      - type: string_contains
        value: "WScript.Shell"
"#,
        );
        let names: Vec<&str> = report.archive_members.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"Big") && names.contains(&"Small"), "{names:?}");
        let finding = report.findings.iter().find(|f| f.rule_id == "TEST-OLE-EMBEDDED-SCRIPT").expect("finding");
        assert!(finding.evidence[0].ends_with("Store/\\x01Ole10Native/dropper.js"), "{:?}", finding.evidence);
        assert_eq!(report.verdict, Verdict::Malware);

        let clean = scan(
            file,
            "rules:\n  - id: NOPE\n    title: x\n    severity: low\n    conditions:\n      - type: string_contains\n        value: \"never-present-marker\"\n",
        );
        assert_eq!(clean.archive_members.len(), 4, "3 streams + 1 embedded file: {:?}", clean.archive_members);
        assert!(clean.findings.is_empty());
    }
}