use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use colored::Colorize;
use hydradragonstatic::scanner::filetype;
use hydradragonstatic::{
    models::{Finding, Severity, Verdict},
    rules::{RuleSet, YamlRulesFile},
    scan_path, ScanOptions,
};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::{prelude::*, ThreadPoolBuilder};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, ValueEnum)]
enum SlowRuleMetric {
    /// Remove based on the slowest single evaluation for a rule.
    Max,
    /// Remove based on average evaluation time across scanned files.
    Avg,
}

#[derive(Debug, Clone)]
struct FpRemoveSelector {
    severities: HashSet<Severity>,
    verdicts: HashSet<Verdict>,
}

impl FpRemoveSelector {
    fn from_tokens(tokens: &[String]) -> Result<Self> {
        let mut severities = HashSet::new();
        let mut verdicts = HashSet::new();
        for token in tokens {
            let normalized = token.trim().to_ascii_lowercase().replace('-', "_");
            if normalized.is_empty() {
                continue;
            }
            match normalized.as_str() {
                "info" | "informational" => {
                    severities.insert(Severity::Info);
                }
                "low" => {
                    severities.insert(Severity::Low);
                }
                "medium" | "med" => {
                    severities.insert(Severity::Medium);
                }
                "high" => {
                    severities.insert(Severity::High);
                }
                "critical" | "crit" => {
                    severities.insert(Severity::Critical);
                }
                "clean" => {
                    verdicts.insert(Verdict::Clean);
                }
                "suspicious" | "sus" => {
                    verdicts.insert(Verdict::Suspicious);
                }
                "malware" | "virus" | "malicious" => {
                    verdicts.insert(Verdict::Malware);
                }
                "all" | "any" => {
                    severities.extend([Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical]);
                    verdicts.extend([Verdict::Clean, Verdict::Suspicious, Verdict::Malware]);
                }
                _ => anyhow::bail!(
                    "unknown --fp-remove-levels value `{}`; use severity levels info,low,medium,high,critical or verdict levels clean,suspicious,malware",
                    token
                ),
            }
        }
        if severities.is_empty() && verdicts.is_empty() {
            anyhow::bail!("--fp-remove-levels is required when --fp-remove is used");
        }
        Ok(Self {
            severities,
            verdicts,
        })
    }

    fn all() -> Self {
        Self {
            severities: [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
            .into_iter()
            .collect(),
            verdicts: [Verdict::Clean, Verdict::Suspicious, Verdict::Malware]
                .into_iter()
                .collect(),
        }
    }

    fn matches(&self, finding: &Finding) -> bool {
        self.matches_rule_meta(finding.severity, finding.verdict)
    }

    fn matches_rule_meta(&self, severity: Severity, verdict: Verdict) -> bool {
        self.severities.contains(&severity) || self.verdicts.contains(&verdict)
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.severities.is_empty() {
            let mut values: Vec<_> = self
                .severities
                .iter()
                .map(|s| format!("{:?}", s).to_ascii_lowercase())
                .collect();
            values.sort();
            parts.push(format!("severity={}", values.join(",")));
        }
        if !self.verdicts.is_empty() {
            let mut values: Vec<_> = self
                .verdicts
                .iter()
                .map(|v| v.label().to_ascii_lowercase())
                .collect();
            values.sort();
            parts.push(format!("verdict={}", values.join(",")));
        }
        parts.join(" ")
    }
}

#[derive(Debug, Parser)]
#[command(name = "hydradragonstatic")]
#[command(
    version,
    about = "HydraDragonStatic deterministic static scanner with external Yamdle rules"
)]
struct Cli {
    /// File(s) or directory root(s) to scan. Multiple roots are supported.
    #[arg(value_name = "PATH", required = true, num_args = 1..)]
    paths: Vec<PathBuf>,

    /// Add an extra scan root without putting it in the positional PATH list.
    /// Useful for alternate/sub-path scans in scripts. Repeatable.
    #[arg(long = "scan-path", alias = "include-path", value_name = "PATH", action = ArgAction::Append)]
    scan_paths: Vec<PathBuf>,

    /// Read additional scan roots from a UTF-8 text file, one path per line.
    /// Empty lines and lines starting with # are ignored. Repeatable.
    #[arg(long = "path-list", value_name = "TXT", action = ArgAction::Append)]
    path_lists: Vec<PathBuf>,

    /// External Yamdle/YAML rule file or directory. Repeat this flag to load multiple packs.
    /// There are no built-in rules; at least one external rule source is required.
    #[arg(short, long, value_name = "YAMDLE", required = true, action = ArgAction::Append)]
    rules: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    output: OutputFormat,

    /// Recursively walk directories and all nested sub-paths.
    #[arg(short = 'R', long)]
    recursive: bool,

    /// Limit recursive directory traversal depth below each root.
    /// 0 means only files directly under the root, 1 means one nested directory level, etc.
    /// Omit for unlimited depth when --recursive is used.
    #[arg(long, value_name = "N")]
    max_depth: Option<usize>,

    /// Follow symlinks while walking directories. Disabled by default to avoid loops and surprises.
    #[arg(long)]
    follow_links: bool,

    /// Include only paths matching this glob-like pattern. Repeatable.
    /// Examples: --include "*.exe" --include "*/System32/*"
    #[arg(long = "include", value_name = "GLOB", action = ArgAction::Append)]
    include_globs: Vec<String>,

    /// Exclude paths matching this glob-like pattern. Repeatable.
    /// Examples: --exclude "*/node_modules/*" --exclude "*.tmp"
    #[arg(long = "exclude", value_name = "GLOB", action = ArgAction::Append)]
    exclude_globs: Vec<String>,

    /// Include only detected file types. Repeatable and comma-separated.
    /// Examples: --include-type pe,elf --include-type apk --include-type text
    #[arg(long = "include-type", alias = "type", value_name = "TYPE", value_delimiter = ',', action = ArgAction::Append)]
    include_types: Vec<String>,

    /// Exclude detected file types. Repeatable and comma-separated.
    /// Examples: --exclude-type archive --exclude-type text
    #[arg(long = "exclude-type", value_name = "TYPE", value_delimiter = ',', action = ArgAction::Append)]
    exclude_types: Vec<String>,

    /// Scan files larger than this many MiB. 0 means no limit.
    #[arg(long, default_value_t = 128)]
    max_mib: u64,

    /// Disable progress bar.
    #[arg(long)]
    no_progress: bool,

    /// Minimum ASCII/UTF-16LE string length to extract. Higher values reduce memory and rule matching cost.
    #[arg(long, default_value_t = 5)]
    min_string_len: usize,

    /// Disable base64/hex/reverse/rot13/xor decoded-string extraction for faster raw signature scans.
    #[arg(long)]
    no_decode: bool,

    /// Include files with no detections in JSON/JSONL output.
    #[arg(long)]
    include_clean: bool,

    /// Evaluate rules in parallel inside each scanned file. Default mode keeps rule evaluation sequential
    /// and parallelizes across files.
    #[arg(long, alias = "parallel-rules")]
    parallel_rules: bool,

    /// Disable file-level parallelism. Useful with --parallel-rules when profiling a large rule pack.
    #[arg(long)]
    no_parallel_files: bool,

    /// Limit Rayon worker threads. 0 uses Rayon default.
    #[arg(long, default_value_t = 0)]
    rule_threads: usize,

    /// Stop rule evaluation for each file as soon as the first rule matches.
    /// With --parallel-rules this keeps the earliest matching rule in rule-file order.
    #[arg(long)]
    stop_on_detection: bool,

    /// Stop scanning the whole input set after the first file with a detection.
    /// This forces deterministic sequential file scanning.
    #[arg(long)]
    stop_scan_on_detection: bool,

    /// Profile every rule and report slow rule evaluations. Alias: --slow-rules.
    #[arg(long, alias = "slow-rules")]
    profile_rules: bool,

    /// Slow rule threshold in milliseconds for pretty output summary.
    #[arg(long, default_value_t = 5)]
    slow_rule_threshold_ms: u64,

    /// Max slow rules to print in pretty output. 0 means no limit.
    #[arg(long, default_value_t = 25)]
    slow_rule_top: usize,

    /// Remove slow rule definitions from the supplied Yamdle/YAML rule files after profiling.
    /// This automatically enables rule profiling.
    #[arg(long)]
    remove_slow_rules: bool,

    /// Severity/verdict filter for slow-rule removal. Comma-separated values:
    /// info,low,medium,high,critical,clean,suspicious,malware,all.
    /// Default is all.
    #[arg(long, value_name = "LEVELS", value_delimiter = ',')]
    remove_slow_rule_levels: Vec<String>,

    /// Metric used by slow-rule removal. `max` removes by worst single evaluation;
    /// `avg` removes by average evaluation time across scanned files.
    #[arg(long, value_enum, default_value_t = SlowRuleMetric::Max)]
    remove_slow_rule_metric: SlowRuleMetric,

    /// Preview slow-rule removals without writing rule files.
    #[arg(long)]
    remove_slow_rules_dry_run: bool,

    /// Do not create .bak copies before rewriting rule files in slow-rule removal mode.
    #[arg(long)]
    remove_slow_rules_no_backup: bool,

    /// False-positive cleanup mode: remove matching rule definitions from the supplied Yamdle/YAML rule files.
    #[arg(long)]
    fp_remove: bool,

    /// Levels to remove in false-positive mode. Comma-separated severity or verdict values:
    /// info,low,medium,high,critical,clean,suspicious,malware,all.
    #[arg(long, value_name = "LEVELS", value_delimiter = ',')]
    fp_remove_levels: Vec<String>,

    /// Preview false-positive removals without writing rule files.
    #[arg(long)]
    fp_remove_dry_run: bool,

    /// Do not create .bak copies before rewriting rule files in false-positive mode.
    #[arg(long)]
    fp_remove_no_backup: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    if cli.rule_threads > 0 {
        ThreadPoolBuilder::new()
            .num_threads(cli.rule_threads)
            .build_global()
            .context("failed to configure Rayon global thread pool")?;
    }

    if cli.fp_remove && cli.fp_remove_levels.is_empty() {
        anyhow::bail!("--fp-remove requires --fp-remove-levels, for example: --fp-remove-levels suspicious,malware");
    }

    let rule_files = collect_rule_files_from_sources(&cli.rules)?;
    let rules = load_external_rules_from_files(&rule_files)?;
    if rules.rules().is_empty() {
        anyhow::bail!(
            "no rules were loaded; pass at least one non-empty Yamdle/YAML rule file with --rules"
        );
    }

    let scan_roots = collect_scan_roots(&cli.paths, &cli.scan_paths, &cli.path_lists)?;
    let include_patterns = compile_glob_patterns(&cli.include_globs)?;
    let exclude_patterns = compile_glob_patterns(&cli.exclude_globs)?;
    let include_types = normalize_type_filters(&cli.include_types)?;
    let exclude_types = normalize_type_filters(&cli.exclude_types)?;
    let files = collect_files_from_roots(
        &scan_roots,
        cli.recursive,
        cli.max_depth,
        cli.follow_links,
        &include_patterns,
        &exclude_patterns,
        &include_types,
        &exclude_types,
    )?;
    if files.is_empty() {
        anyhow::bail!("no files selected for scanning after recursive/path filters");
    }
    let pb = if cli.no_progress || files.len() <= 1 {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar}] {pos}/{len} {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb
    };

    let profiling_enabled = cli.profile_rules || cli.remove_slow_rules;
    let options = ScanOptions {
        max_file_size: if cli.max_mib == 0 {
            None
        } else {
            Some(cli.max_mib * 1024 * 1024)
        },
        profile_rules: profiling_enabled,
        parallel_rules: cli.parallel_rules,
        stop_on_detection: cli.stop_on_detection,
        min_string_len: cli.min_string_len,
        decode_obfuscated_strings: !cli.no_decode,
        core_options: hydradragonstatic::models::CoreInitOptions::default(),
        unpack_config: hydradragonstatic::models::UnpackConfig::default(),
    };

    let use_sequential_files = cli.no_parallel_files || cli.stop_scan_on_detection;
    let reports: Vec<_> = if use_sequential_files {
        let mut out = Vec::new();
        for path in &files {
            pb.set_message(path.display().to_string());
            let result = scan_path(path, &rules, &options);
            pb.inc(1);
            match result {
                Ok(report) => {
                    let detected = !report.findings.is_empty();
                    out.push(report);
                    if cli.stop_scan_on_detection && detected {
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("{} {}: {}", "[ERR]".red(), path.display(), err);
                }
            }
        }
        out
    } else {
        files
            .par_iter()
            .filter_map(|path| {
                pb.set_message(path.display().to_string());
                let result = scan_path(path, &rules, &options);
                pb.inc(1);
                match result {
                    Ok(report) => Some(report),
                    Err(err) => {
                        eprintln!("{} {}: {}", "[ERR]".red(), path.display(), err);
                        None
                    }
                }
            })
            .collect()
    };
    pb.finish_and_clear();

    match cli.output {
        OutputFormat::Pretty => {
            print_pretty(&reports);
            if profiling_enabled {
                print_slow_rule_summary(
                    &reports,
                    cli.slow_rule_threshold_ms.saturating_mul(1_000),
                    cli.slow_rule_top,
                );
            }
        }
        OutputFormat::Json => {
            let visible = filter_reports(&reports, cli.include_clean || profiling_enabled);
            println!("{}", serde_json::to_string_pretty(&visible)?);
        }
        OutputFormat::Jsonl => {
            for report in filter_reports(&reports, cli.include_clean || profiling_enabled) {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
    }

    if cli.remove_slow_rules {
        let selector = if cli.remove_slow_rule_levels.is_empty() {
            FpRemoveSelector::all()
        } else {
            FpRemoveSelector::from_tokens(&cli.remove_slow_rule_levels)?
        };
        apply_slow_rule_removal(
            &rule_files,
            &reports,
            cli.slow_rule_threshold_ms.saturating_mul(1_000),
            &cli.remove_slow_rule_metric,
            &selector,
            cli.remove_slow_rules_dry_run,
            !cli.remove_slow_rules_no_backup,
        )?;
    }

    if cli.fp_remove {
        let selector = FpRemoveSelector::from_tokens(&cli.fp_remove_levels)?;
        let matched_rule_ids = collect_fp_rule_ids(&reports, &selector);
        apply_fp_removal(
            &rule_files,
            &matched_rule_ids,
            &selector,
            cli.fp_remove_dry_run,
            !cli.fp_remove_no_backup,
        )?;
        return Ok(());
    }

    if cli.remove_slow_rules {
        return Ok(());
    }

    let malware = reports.iter().any(|r| r.verdict == Verdict::Malware);
    let detected = reports.iter().any(|r| !r.findings.is_empty());
    if malware {
        std::process::exit(3);
    } else if detected {
        std::process::exit(2);
    }
    Ok(())
}

fn load_external_rules_from_files(files: &[PathBuf]) -> Result<RuleSet> {
    if files.is_empty() {
        anyhow::bail!("no .yaml/.yml rule files found in provided --rules paths");
    }

    let mut out = RuleSet::empty();
    for file in files {
        let pack = RuleSet::from_yaml_file(file)
            .with_context(|| format!("failed to load Yamdle/YAML rules from {}", file.display()))?;
        out.extend(pack);
    }
    Ok(out)
}

fn collect_rule_files_from_sources(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for source in paths {
        files.extend(collect_rule_files(source)?);
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        anyhow::bail!("no .yaml/.yml rule files found in provided --rules paths");
    }
    Ok(files)
}

fn collect_rule_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        anyhow::bail!("rule path does not exist: {}", path.display());
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let is_yaml = entry
            .path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if is_yaml {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn collect_scan_roots(
    positional: &[PathBuf],
    extra: &[PathBuf],
    path_lists: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    roots.extend(positional.iter().cloned());
    roots.extend(extra.iter().cloned());

    for list_file in path_lists {
        let content = std::fs::read_to_string(list_file)
            .with_context(|| format!("failed to read --path-list {}", list_file.display()))?;
        let base = list_file.parent().unwrap_or_else(|| Path::new("."));
        for (line_no, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let candidate = PathBuf::from(line);
            let resolved = if candidate.is_absolute() {
                candidate
            } else {
                base.join(candidate)
            };
            if !resolved.exists() {
                anyhow::bail!(
                    "path-list entry does not exist: {}:{} -> {}",
                    list_file.display(),
                    line_no + 1,
                    resolved.display()
                );
            }
            roots.push(resolved);
        }
    }

    roots.sort();
    roots.dedup();
    if roots.is_empty() {
        anyhow::bail!("no scan paths were provided");
    }
    Ok(roots)
}

fn collect_files_from_roots(
    roots: &[PathBuf],
    recursive: bool,
    max_depth: Option<usize>,
    follow_links: bool,
    include_patterns: &[Regex],
    exclude_patterns: &[Regex],
    include_types: &HashSet<String>,
    exclude_types: &HashSet<String>,
) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let walker_depth = if recursive {
        max_depth.map(|depth| depth.saturating_add(1))
    } else {
        Some(1)
    };

    for root in roots {
        if root.is_file() {
            if path_allowed(root, include_patterns, exclude_patterns)
                && file_type_allowed(root, include_types, exclude_types)?
            {
                out.push(root.clone());
            }
            continue;
        }
        if !root.is_dir() {
            anyhow::bail!("path does not exist: {}", root.display());
        }

        let mut walker = WalkDir::new(root).follow_links(follow_links);
        if let Some(depth) = walker_depth {
            walker = walker.max_depth(depth);
        }

        for entry in walker.into_iter().filter_map(|entry| entry.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path().to_path_buf();
            if path_allowed(&path, include_patterns, exclude_patterns)
                && file_type_allowed(&path, include_types, exclude_types)?
            {
                out.push(path);
            }
        }
    }

    out.sort();
    out.dedup();
    Ok(out)
}

fn path_allowed(path: &Path, include_patterns: &[Regex], exclude_patterns: &[Regex]) -> bool {
    let text = normalize_path_for_match(path);
    let included = include_patterns.is_empty()
        || include_patterns
            .iter()
            .any(|pattern| pattern.is_match(&text));
    let excluded = exclude_patterns
        .iter()
        .any(|pattern| pattern.is_match(&text));
    included && !excluded
}

fn normalize_type_filters(values: &[String]) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for value in values {
        let normalized = filetype::normalize_file_type_alias(value);
        if normalized.is_empty() {
            continue;
        }
        if !filetype::is_known_file_type_alias(&normalized) {
            anyhow::bail!(
                "unknown file type filter `{}`; known types: {}",
                value,
                filetype::known_file_type_aliases().join(", ")
            );
        }
        out.insert(normalized);
    }
    Ok(out)
}

fn file_type_allowed(
    path: &Path,
    include_types: &HashSet<String>,
    exclude_types: &HashSet<String>,
) -> Result<bool> {
    if include_types.is_empty() && exclude_types.is_empty() {
        return Ok(true);
    }

    let info = filetype::classify_path(path)
        .with_context(|| format!("file type classification failed for {}", path.display()))?;
    let included = include_types.is_empty() || include_types.iter().any(|ty| info.matches_type(ty));
    let excluded = exclude_types.iter().any(|ty| info.matches_type(ty));
    Ok(included && !excluded)
}

fn normalize_path_for_match(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn compile_glob_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(&glob_to_regex(pattern))
                .with_context(|| format!("invalid path glob pattern `{}`", pattern))
        })
        .collect()
}

fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::from("(?i)^");
    let has_wildcard = pattern.contains('*') || pattern.contains('?');
    if !has_wildcard {
        regex.push_str(".*");
    }

    for ch in pattern.replace('\\', "/").chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' => {
                regex.push('\\');
                regex.push(ch);
            }
            other => regex.push(other),
        }
    }

    if !has_wildcard {
        regex.push_str(".*");
    }
    regex.push('$');
    regex
}

fn filter_reports(
    reports: &[hydradragonstatic::models::ScanReport],
    include_clean: bool,
) -> Vec<&hydradragonstatic::models::ScanReport> {
    reports
        .iter()
        .filter(|report| include_clean || !report.findings.is_empty())
        .collect()
}

fn collect_fp_rule_ids(
    reports: &[hydradragonstatic::models::ScanReport],
    selector: &FpRemoveSelector,
) -> HashSet<String> {
    let mut ids = HashSet::new();
    for report in reports {
        for finding in &report.findings {
            if selector.matches(finding) {
                ids.insert(finding.rule_id.clone());
            }
        }
    }
    ids
}

fn apply_fp_removal(
    rule_files: &[PathBuf],
    matched_rule_ids: &HashSet<String>,
    selector: &FpRemoveSelector,
    dry_run: bool,
    backup: bool,
) -> Result<()> {
    println!(
        "{} false-positive removal selector: {}",
        if dry_run {
            "[FP-DRY-RUN]".yellow().bold()
        } else {
            "[FP-REMOVE]".red().bold()
        },
        selector.describe()
    );

    if matched_rule_ids.is_empty() {
        println!(
            "{} no matching rules selected for removal",
            "[FP]".green().bold()
        );
        return Ok(());
    }

    let mut total_removed = 0usize;
    for file in rule_files {
        let yaml = std::fs::read_to_string(file)
            .with_context(|| format!("failed to read rule file {}", file.display()))?;
        let mut parsed: YamlRulesFile = yaml_serde::from_str(&yaml)
            .with_context(|| format!("invalid Yamdle/YAML rule file {}", file.display()))?;
        let before = parsed.rules.len();
        let mut removed_here = Vec::new();
        parsed.rules.retain(|rule| {
            let remove = matched_rule_ids.contains(&rule.id);
            if remove {
                removed_here.push(rule.id.clone());
            }
            !remove
        });
        let removed_count = before.saturating_sub(parsed.rules.len());
        if removed_count == 0 {
            continue;
        }
        total_removed += removed_count;
        removed_here.sort();
        println!(
            "{} {} rule(s) from {}: {}",
            if dry_run {
                "would remove".yellow()
            } else {
                "removed".red()
            },
            removed_count,
            file.display(),
            removed_here.join(", ")
        );

        if dry_run {
            continue;
        }

        if backup {
            let backup_path = backup_path_for(file);
            std::fs::copy(file, &backup_path)
                .with_context(|| format!("failed to create backup {}", backup_path.display()))?;
            println!("  backup={}", backup_path.display());
        }

        let rendered = yaml_serde::to_string(&parsed)
            .with_context(|| format!("failed to serialize updated rule file {}", file.display()))?;
        std::fs::write(file, rendered)
            .with_context(|| format!("failed to write updated rule file {}", file.display()))?;
    }

    if total_removed == 0 {
        println!(
            "{} selected detections did not map to writable external rule files",
            "[FP]".yellow().bold()
        );
    } else if dry_run {
        println!(
            "{} {} rule(s) would be removed",
            "[FP-DRY-RUN]".yellow().bold(),
            total_removed
        );
    } else {
        println!(
            "{} {} rule(s) removed from Yamdle/YAML rule files",
            "[FP-REMOVE]".green().bold(),
            total_removed
        );
    }
    Ok(())
}

fn remove_rules_from_files(
    rule_files: &[PathBuf],
    rule_ids: &HashSet<String>,
    dry_run: bool,
    backup: bool,
    label: &str,
) -> Result<()> {
    if rule_ids.is_empty() {
        println!(
            "{} no rule ids selected",
            format!("[{}]", label).yellow().bold()
        );
        return Ok(());
    }

    let mut total_removed = 0usize;
    for file in rule_files {
        let yaml = std::fs::read_to_string(file)
            .with_context(|| format!("failed to read rule file {}", file.display()))?;
        let mut parsed: YamlRulesFile = yaml_serde::from_str(&yaml)
            .with_context(|| format!("invalid Yamdle/YAML rule file {}", file.display()))?;
        let before = parsed.rules.len();
        let mut removed_here = Vec::new();
        parsed.rules.retain(|rule| {
            let remove = rule_ids.contains(&rule.id);
            if remove {
                removed_here.push(rule.id.clone());
            }
            !remove
        });

        let removed_count = before.saturating_sub(parsed.rules.len());
        if removed_count == 0 {
            continue;
        }
        total_removed += removed_count;
        removed_here.sort();
        println!(
            "{} {} rule(s) from {}: {}",
            if dry_run {
                "would remove".yellow()
            } else {
                "removed".red()
            },
            removed_count,
            file.display(),
            removed_here.join(", ")
        );

        if dry_run {
            continue;
        }

        if backup {
            let backup_path = backup_path_for(file);
            std::fs::copy(file, &backup_path)
                .with_context(|| format!("failed to create backup {}", backup_path.display()))?;
            println!("  backup={}", backup_path.display());
        }

        let rendered = yaml_serde::to_string(&parsed)
            .with_context(|| format!("failed to serialize updated rule file {}", file.display()))?;
        std::fs::write(file, rendered)
            .with_context(|| format!("failed to write updated rule file {}", file.display()))?;
    }

    let tag = format!("[{}]", label);
    if total_removed == 0 {
        println!(
            "{} selected rule ids did not map to writable external rule files",
            tag.yellow().bold()
        );
    } else if dry_run {
        println!(
            "{} {} rule(s) would be removed",
            tag.yellow().bold(),
            total_removed
        );
    } else {
        println!(
            "{} {} rule(s) removed from Yamdle/YAML rule files",
            tag.green().bold(),
            total_removed
        );
    }
    Ok(())
}

fn backup_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "rules.yaml".to_string());
    path.with_file_name(format!("{}.bak", file_name))
}

#[derive(Debug, Clone)]
struct SlowRuleAggregate {
    title: String,
    severity: Severity,
    verdict: Verdict,
    evaluations: usize,
    matches: usize,
    total_micros: u128,
    max_micros: u64,
    max_path: String,
    condition_count: usize,
    signature_atom_count: usize,
}

fn aggregate_rule_performance(
    reports: &[hydradragonstatic::models::ScanReport],
) -> HashMap<String, SlowRuleAggregate> {
    let mut aggregates: HashMap<String, SlowRuleAggregate> = HashMap::new();

    for report in reports {
        for perf in &report.rule_performance {
            let entry =
                aggregates
                    .entry(perf.rule_id.clone())
                    .or_insert_with(|| SlowRuleAggregate {
                        title: perf.title.clone(),
                        severity: perf.severity,
                        verdict: perf.verdict,
                        evaluations: 0,
                        matches: 0,
                        total_micros: 0,
                        max_micros: 0,
                        max_path: String::new(),
                        condition_count: perf.condition_count,
                        signature_atom_count: perf.signature_atom_count,
                    });
            entry.evaluations += 1;
            entry.total_micros += perf.elapsed_micros as u128;
            if perf.matched {
                entry.matches += 1;
            }
            if perf.elapsed_micros > entry.max_micros {
                entry.max_micros = perf.elapsed_micros;
                entry.max_path = report.path.display().to_string();
            }
        }
    }

    aggregates
}

fn print_slow_rule_summary(
    reports: &[hydradragonstatic::models::ScanReport],
    threshold_micros: u64,
    top: usize,
) {
    let aggregates = aggregate_rule_performance(reports);

    if aggregates.is_empty() {
        println!(
            "{} rule profiling was enabled, but no rule performance data was collected",
            "[SLOW-RULES]".yellow().bold()
        );
        return;
    }

    let mut rows: Vec<_> = aggregates
        .into_iter()
        .filter(|(_, stat)| threshold_micros == 0 || stat.max_micros >= threshold_micros)
        .collect();

    rows.sort_by(|a, b| {
        b.1.max_micros
            .cmp(&a.1.max_micros)
            .then_with(|| avg_micros(&b.1).cmp(&avg_micros(&a.1)))
            .then_with(|| a.0.cmp(&b.0))
    });

    if top > 0 && rows.len() > top {
        rows.truncate(top);
    }

    if rows.is_empty() {
        println!(
            "{} no rules slower than {:.3} ms",
            "[SLOW-RULES]".green().bold(),
            threshold_micros as f64 / 1000.0
        );
        return;
    }

    println!(
        "{} rules slower than {:.3} ms (showing {}):",
        "[SLOW-RULES]".yellow().bold(),
        threshold_micros as f64 / 1000.0,
        rows.len()
    );

    for (rule_id, stat) in rows {
        println!(
            "  - {} max={:.3}ms avg={:.3}ms evals={} matches={} verdict={} severity={:?}",
            rule_id.cyan().bold(),
            stat.max_micros as f64 / 1000.0,
            avg_micros(&stat) as f64 / 1000.0,
            stat.evaluations,
            stat.matches,
            stat.verdict.label(),
            stat.severity
        );
        println!(
            "      title={} conditions={} atoms={} slowest_file={}",
            stat.title, stat.condition_count, stat.signature_atom_count, stat.max_path
        );
    }
}

fn apply_slow_rule_removal(
    rule_files: &[PathBuf],
    reports: &[hydradragonstatic::models::ScanReport],
    threshold_micros: u64,
    metric: &SlowRuleMetric,
    selector: &FpRemoveSelector,
    dry_run: bool,
    backup: bool,
) -> Result<()> {
    let aggregates = aggregate_rule_performance(reports);
    if aggregates.is_empty() {
        println!(
            "{} no profiling data found; slow-rule removal requires profiling",
            "[SLOW-REMOVE]".yellow().bold()
        );
        return Ok(());
    }

    let mut selected: Vec<(String, SlowRuleAggregate, u64)> = aggregates
        .into_iter()
        .filter_map(|(rule_id, stat)| {
            if !selector.matches_rule_meta(stat.severity, stat.verdict) {
                return None;
            }
            let value = match metric {
                SlowRuleMetric::Max => stat.max_micros,
                SlowRuleMetric::Avg => avg_micros(&stat),
            };
            (threshold_micros == 0 || value >= threshold_micros).then_some((rule_id, stat, value))
        })
        .collect();

    selected.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));

    println!(
        "{} threshold={:.3}ms metric={:?} selector={}",
        if dry_run {
            "[SLOW-REMOVE-DRY-RUN]".yellow().bold()
        } else {
            "[SLOW-REMOVE]".red().bold()
        },
        threshold_micros as f64 / 1000.0,
        metric,
        selector.describe()
    );

    if selected.is_empty() {
        println!(
            "{} no rules selected for removal",
            "[SLOW-REMOVE]".green().bold()
        );
        return Ok(());
    }

    for (rule_id, stat, selected_value) in selected.iter().take(50) {
        println!(
            "  {} {} selected={:.3}ms max={:.3}ms avg={:.3}ms evals={} matches={} verdict={} severity={:?}",
            if dry_run { "would remove".yellow() } else { "remove".red() },
            rule_id.cyan().bold(),
            *selected_value as f64 / 1000.0,
            stat.max_micros as f64 / 1000.0,
            avg_micros(stat) as f64 / 1000.0,
            stat.evaluations,
            stat.matches,
            stat.verdict.label(),
            stat.severity
        );
    }
    if selected.len() > 50 {
        println!("  ... {} more selected slow rule(s)", selected.len() - 50);
    }

    let ids: HashSet<String> = selected
        .into_iter()
        .map(|(rule_id, _, _)| rule_id)
        .collect();
    remove_rules_from_files(rule_files, &ids, dry_run, backup, "SLOW-REMOVE")
}

fn avg_micros(stat: &SlowRuleAggregate) -> u64 {
    if stat.evaluations == 0 {
        0
    } else {
        (stat.total_micros / stat.evaluations as u128).min(u64::MAX as u128) as u64
    }
}

fn print_pretty(reports: &[hydradragonstatic::models::ScanReport]) {
    let mut detections = 0usize;
    for report in reports {
        if report.findings.is_empty() {
            continue;
        }
        detections += 1;
        let badge = match report.verdict {
            Verdict::Malware => "[MALWARE]".red().bold(),
            Verdict::Suspicious => "[SUSPICIOUS]".yellow().bold(),
            Verdict::Clean => "[CLEAN]".green().bold(),
        };
        println!("{} {}", badge, report.path.display());
        println!(
            "  verdict={} confidence={} score={} entropy={:.3} sha256={}",
            report.verdict.label(),
            report.confidence,
            report.score,
            report.entropy,
            report.hashes.sha256
        );
        println!(
            "  type={} tags={}",
            report.file_type.primary,
            report.file_type.tags.join(",")
        );
        if !report.malware_families.is_empty() {
            println!("  families={}", report.malware_families.join(", "));
        }
        if let Some(pe) = &report.pe {
            println!(
                "  pe: arch={} imports={} suspicious_imports={}",
                pe.arch,
                pe.imports.len(),
                pe.suspicious_imports.len()
            );
        }
        for finding in &report.findings {
            let sev = format!("{:?}", finding.severity).to_uppercase();
            println!(
                "  - {} {} verdict={} confidence={} (+{})",
                sev.yellow().bold(),
                finding.title,
                finding.verdict.label(),
                finding.confidence,
                finding.score
            );
            println!("      rule_id={}", finding.rule_id);
            for ev in finding.evidence.iter().take(8) {
                println!("      {}", ev);
            }
        }
        println!();
    }
    if detections == 0 {
        println!("{} no detections", "[OK]".green().bold());
    }
}
