use super::types::*;
use crate::models::{Finding, MitreTechnique, RulePerformance, ScanReport, Verdict};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use memchr::memmem;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, Default)]
pub struct RuleEvalOptions {
    pub profile_rules: bool,
    pub parallel_rules: bool,
    pub stop_on_detection: bool,
}

#[derive(Debug)]
struct ScanView {
    strings_lower: Vec<String>,
    decoded_lower: Vec<String>,
    imports_lower: Vec<String>,
    dlls_lower: Vec<String>,
}

impl ScanView {
    fn new(report: &ScanReport) -> Self {
        // Keep a complete lowercase view so case-insensitive matching stays fast
        // without dropping late strings from large files.
        let strings_lower: Vec<String> = report
            .strings
            .iter()
            .map(|hit| hit.value.to_ascii_lowercase())
            .collect();

        let decoded_lower: Vec<String> = report
            .decoded_strings
            .iter()
            .map(|hit| hit.decoded.to_ascii_lowercase())
            .collect();

        let imports_lower = report
            .pe
            .as_ref()
            .map(|pe| {
                pe.imports
                    .iter()
                    .map(|imp| imp.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        let dlls_lower = report
            .pe
            .as_ref()
            .map(|pe| pe.dlls.iter().map(|dll| dll.to_ascii_lowercase()).collect())
            .unwrap_or_default();

        Self {
            strings_lower,
            decoded_lower,
            imports_lower,
            dlls_lower,
        }
    }
}

static REGEX_CACHE: Lazy<Mutex<HashMap<String, Arc<Regex>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static BYTE_PATTERN_CACHE: Lazy<Mutex<HashMap<String, Arc<CompiledBytePattern>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static STRING_SET_CACHE: Lazy<Mutex<HashMap<String, Arc<AhoCorasick>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// Cache for XOR text atoms: key = "<atom_cache_key>" → AhoCorasick with all key variants pre-built.
/// Patterns are stored as raw bytes (Vec<u8>), indexed so PatternID → (xor_key, variant_label_index).
static XOR_TEXT_AC_CACHE: Lazy<Mutex<HashMap<String, Arc<XorTextAc>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn cached_regex(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(found) = REGEX_CACHE.lock().ok()?.get(pattern).cloned() {
        return Some(found);
    }
    let compiled = Arc::new(Regex::new(pattern).ok()?);
    REGEX_CACHE
        .lock()
        .ok()?
        .insert(pattern.to_string(), compiled.clone());
    Some(compiled)
}

/// Pre-built Aho-Corasick automaton for a single XOR text atom.
/// `meta[i]` = `(xor_key, variant_label)` for the i-th pattern in the automaton.
#[derive(Debug)]
struct XorTextAc {
    ac: AhoCorasick,
    meta: Vec<(u8, &'static str)>,
}

fn xor_text_ac_cache_key(value: &str, wide: bool, lo: u8, hi: u8) -> String {
    format!(
        "xor:{}:{}:{}-{}",
        if wide { "wide" } else { "ascii" },
        value,
        lo,
        hi
    )
}

fn build_xor_text_ac(atom: &SignatureAtom) -> Option<Arc<XorTextAc>> {
    let (lo, hi) = xor_key_range(atom);
    let wide = atom.wide;
    let key = xor_text_ac_cache_key(&atom.value, wide, lo, hi);

    if let Some(found) = XOR_TEXT_AC_CACHE.lock().ok()?.get(&key).cloned() {
        return Some(found);
    }

    let variants = text_atom_plain_xor_variants(atom);
    if variants.is_empty() {
        return None;
    }

    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(variants.len() * (hi - lo + 1) as usize);
    let mut meta: Vec<(u8, &'static str)> = Vec::with_capacity(patterns.capacity());

    for k in lo..=hi {
        for &(label, ref plain) in &variants {
            if plain.is_empty() {
                continue;
            }
            let encoded: Vec<u8> = plain.iter().map(|b| b ^ k).collect();
            patterns.push(encoded);
            meta.push((k, label));
        }
    }

    if patterns.is_empty() {
        return None;
    }

    let ac = AhoCorasickBuilder::new().build(patterns).ok()?;

    let built = Arc::new(XorTextAc { ac, meta });
    XOR_TEXT_AC_CACHE.lock().ok()?.insert(key, built.clone());
    Some(built)
}

fn cached_byte_pattern(pattern: &str) -> Option<Arc<CompiledBytePattern>> {
    if let Some(found) = BYTE_PATTERN_CACHE.lock().ok()?.get(pattern).cloned() {
        return Some(found);
    }
    let compiled = Arc::new(compile_byte_pattern(pattern)?);
    BYTE_PATTERN_CACHE
        .lock()
        .ok()?
        .insert(pattern.to_string(), compiled.clone());
    Some(compiled)
}

fn cached_literal_set(values: &[String], nocase: bool) -> Option<Arc<AhoCorasick>> {
    if values.is_empty() {
        return None;
    }
    let key = literal_set_cache_key(values, nocase);
    if let Some(found) = STRING_SET_CACHE.lock().ok()?.get(&key).cloned() {
        return Some(found);
    }
    let patterns: Vec<String> = if nocase {
        values
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect()
    } else {
        values.to_vec()
    };
    let compiled = Arc::new(AhoCorasickBuilder::new().build(patterns).ok()?);
    STRING_SET_CACHE.lock().ok()?.insert(key, compiled.clone());
    Some(compiled)
}

fn literal_set_cache_key(values: &[String], nocase: bool) -> String {
    let mut key = if nocase { "i:" } else { "s:" }.to_string();
    for value in values {
        key.push_str(value);
        key.push('\u{1f}');
    }
    key
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let file: YamlRulesFile = yaml_serde::from_str(yaml).context("invalid YAML rule file")?;
        let mut rules = file.rules;
        for rule in &rules {
            warm_rule_caches(rule);
        }
        for rule in &mut rules {
            rule.compute_required_types();
        }
        Ok(Self { rules })
    }

    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        Self::from_yaml_file_recursive(path, 0)
    }

    fn from_yaml_file_recursive(path: &Path, depth: u32) -> Result<Self> {
        if depth > 20 {
            anyhow::bail!(
                "Max recursion depth (20) reached! Possible circular include: {}",
                path.display()
            );
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read rule file {}", path.display()))?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut combined_rules = Self::empty();

        // First, handle !include directives
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("!include ") {
                let include_part = if trimmed.starts_with("- ") {
                    trimmed.strip_prefix("- ").unwrap_or(trimmed).trim()
                } else {
                    trimmed
                };

                if let Some(include_path_str) = include_part.strip_prefix("!include ") {
                    let include_path_str = include_path_str.trim();
                    let include_path = parent.join(include_path_str);

                    if include_path.exists() {
                        match Self::from_yaml_file_recursive(&include_path, depth + 1) {
                            Ok(sub_rules) => {
                                combined_rules.extend(sub_rules);
                            }
                            Err(e) => {
                                eprintln!(
                                    "[HydraDragonSig] Warning: Failed to load include {}: {e:#}",
                                    include_path.display(),
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "[HydraDragonSig] Warning: Include path does not exist: {}",
                            include_path.display()
                        );
                    }
                }
            }
        }

        // Now parse the content as YAML, skipping !include lines
        let filtered_content: String = content
            .lines()
            .filter(|line| {
                !line.trim().starts_with("!include") && !line.trim().starts_with("- !include")
            })
            .collect::<Vec<_>>()
            .join("\n");

        if !filtered_content.trim().is_empty() {
            let current_rules = Self::from_yaml_str(&filtered_content)?;
            combined_rules.extend(current_rules);
        }

        Ok(combined_rules)
    }

    pub fn extend(&mut self, other: RuleSet) {
        self.rules.extend(other.rules);
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn evaluate_into(&self, report: &mut ScanReport, bytes: &[u8], options: RuleEvalOptions) {
        let view = ScanView::new(report);
        if options.parallel_rules {
            self.evaluate_parallel_into(report, &view, bytes, options);
        } else {
            self.evaluate_sequential_into(report, &view, bytes, options);
        }
    }

    fn evaluate_sequential_into(
        &self,
        report: &mut ScanReport,
        view: &ScanView,
        bytes: &[u8],
        options: RuleEvalOptions,
    ) {
        for rule in self.rules.iter() {
            let result = evaluate_one_rule(rule, report, view, bytes, options.profile_rules);
            let matched = result.finding.is_some();
            push_rule_eval_result(report, result);
            if options.stop_on_detection && matched {
                break;
            }
        }
    }

    fn evaluate_parallel_into(
        &self,
        report: &mut ScanReport,
        view: &ScanView,
        bytes: &[u8],
        options: RuleEvalOptions,
    ) {
        if options.stop_on_detection {
            // Deterministic first-match mode: returns the earliest matching rule in rule-file order.
            for rule in self.rules.iter() {
                let result = evaluate_one_rule(
                    rule,
                    report,
                    view,
                    bytes,
                    options.profile_rules,
                );
                if result.finding.is_some() {
                    push_rule_eval_result(report, result);
                    return;
                }
            }
            return;
        }

        for rule in self.rules.iter() {
            let result = evaluate_one_rule(
                rule,
                report,
                view,
                bytes,
                options.profile_rules,
            );
            push_rule_eval_result(report, result);
        }
    }
}

fn warm_rule_caches(rule: &Rule) {
    for condition in &rule.conditions {
        match condition {
            RuleCondition::StringRegex { pattern, .. }
            | RuleCondition::ImportRegex { pattern }
            | RuleCondition::DllRegex { pattern }
            | RuleCondition::SectionNameRegex { pattern }
            | RuleCondition::PathRegex { pattern } => {
                let _ = cached_regex(pattern);
            }
            RuleCondition::StringSet {
                values,
                nocase,
                regex: true,
                ..
            } => {
                for value in values {
                    let pattern = if *nocase {
                        format!("(?i){}", value)
                    } else {
                        value.clone()
                    };
                    let _ = cached_regex(&pattern);
                }
            }
            RuleCondition::StringSet {
                values,
                nocase,
                regex: false,
                ..
            } => {
                let _ = cached_literal_set(values, *nocase);
            }
            RuleCondition::RegistryPattern { pattern, nocase } => {
                let pattern = if *nocase {
                    format!("(?i){}", pattern)
                } else {
                    pattern.clone()
                };
                let _ = cached_regex(&pattern);
            }
            RuleCondition::BytePattern { pattern } => {
                let _ = cached_byte_pattern(pattern);
            }
            RuleCondition::ByteSet { patterns, .. } => {
                for pattern in patterns {
                    let _ = cached_byte_pattern(pattern);
                }
            }
            RuleCondition::NativeSignature { atoms, .. } => {
                for atom in atoms {
                    match atom.kind {
                        SignatureAtomKind::Regex => {
                            let pattern = if atom.nocase {
                                format!("(?i){}", atom.value)
                            } else {
                                atom.value.clone()
                            };
                            let _ = cached_regex(&pattern);
                        }
                        SignatureAtomKind::Bytes => {
                            let _ = cached_byte_pattern(&atom.value);
                        }
                        SignatureAtomKind::Text => {
                            // Pre-build the XOR Aho-Corasick automaton at rule load time
                            // so the first scan pays zero construction cost.
                            if atom.xor {
                                let _ = build_xor_text_ac(atom);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
struct RuleEvalResult {
    finding: Option<Finding>,
    performance: Option<RulePerformance>,
}

fn evaluate_one_rule(
    rule: &Rule,
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    profile_rules: bool,
) -> RuleEvalResult {
    let start = profile_rules.then(Instant::now);
    let result = evaluate_rule(rule, report, view, bytes);
    let elapsed_micros = start
        .map(|instant| instant.elapsed().as_micros().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    let matched = result.is_some();

    // Print slow rules when profiling is enabled (like ClamAV's [SLOW-*] output).
    if profile_rules && elapsed_micros >= 20_000 {
        eprintln!(
            "[SLOW-RULE] {}ms {} ({} conditions, {} atoms) matched={}",
            elapsed_micros / 1000,
            rule.id,
            rule.conditions.len(),
            rule_signature_atom_count(rule),
            matched,
        );
    }

    let performance = profile_rules.then(|| RulePerformance {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        verdict: rule.verdict,
        matched,
        condition_count: rule.conditions.len(),
        signature_atom_count: rule_signature_atom_count(rule),
        elapsed_micros,
    });

    // Private rules don't generate findings (YARA-style behavior)
    let finding = if rule.private {
        None
    } else {
        result.map(|evidence| {
            // Convert lightweight MitreMapping entries from the rule definition into
            // full MitreTechnique structs, using the first evidence line as context.
            let evidence_summary = evidence.first().cloned().unwrap_or_default();
            let mitre = rule
                .mitre
                .iter()
                .map(|m| MitreTechnique {
                    id: m.id.clone(),
                    name: m.name.clone(),
                    tactic: m.tactic.clone(),
                    evidence: evidence_summary.clone(),
                    confidence: rule.confidence.min(100),
                })
                .collect::<Vec<_>>();
            Finding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                severity: rule.severity,
                verdict: rule.verdict,
                confidence: rule.confidence.min(100),
                score: rule.score,
                tags: rule.tags.clone(),
                family: rule.family.clone(),
                evidence,
                mitre,
                expected_reverted_value: rule.expected_reverted_value.clone(),
            }
        })
    };

    RuleEvalResult {
        finding,
        performance,
    }
}

fn push_rule_eval_result(report: &mut ScanReport, result: RuleEvalResult) {
    if let Some(performance) = result.performance {
        report.rule_performance.push(performance);
    }
    if let Some(finding) = result.finding {
        // Propagate MITRE techniques to the top-level report, deduplicating by technique ID.
        for technique in &finding.mitre {
            if !report
                .mitre_techniques
                .iter()
                .any(|t| t.id == technique.id)
            {
                report.mitre_techniques.push(technique.clone());
            }
        }
        report.findings.push(finding);
    }
}

fn rule_signature_atom_count(rule: &Rule) -> usize {
    rule.conditions
        .iter()
        .map(|condition| match condition {
            RuleCondition::NativeSignature { atoms, .. } => atoms.len(),
            RuleCondition::StringSet { values, .. } => values.len(),
            RuleCondition::ByteSet { patterns, .. } => patterns.len(),
            RuleCondition::ImportAny { names }
            | RuleCondition::ImportAll { names }
            | RuleCondition::ImportSet { names, .. }
            | RuleCondition::DllAny { names } => names.len(),
            _ => 1,
        })
        .sum()
}

fn evaluate_rule(
    rule: &Rule,
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
) -> Option<Vec<String>> {
    if rule.conditions.is_empty() {
        return None;
    }

    // File-type pre-filter: if the rule requires specific file types, skip
    // files whose type doesn't match.
    if let Some(ref types) = rule.required_types {
        if !types.iter().any(|t| report.file_type.matches_type(t)) {
            return None;
        }
    }

    // Path filter: if the rule specifies a required path, skip files that
    // don't match. Supports %VAR% environment-variable placeholders.
    if let Some(ref required) = rule.required_path {
        if !path_matches_required(&report.path, required) {
            return None;
        }
    }

    match rule.logic {
        RuleLogic::Any => {
            for cond in &rule.conditions {
                if let Some(ev) = evaluate_condition(cond, report, view, bytes) {
                    return Some(vec![ev]);
                }
            }
            None
        }
        RuleLogic::All => {
            let mut evidence = Vec::with_capacity(rule.conditions.len());
            for cond in &rule.conditions {
                let ev = evaluate_condition(cond, report, view, bytes)?;
                evidence.push(ev);
            }
            Some(evidence)
        }
        RuleLogic::Threshold => {
            let needed = rule.threshold.unwrap_or(1).max(1);
            let remaining_total = rule.conditions.len();
            if needed > remaining_total {
                return None;
            }
            let mut evidence = Vec::with_capacity(needed);
            for (idx, cond) in rule.conditions.iter().enumerate() {
                if let Some(ev) = evaluate_condition(cond, report, view, bytes) {
                    evidence.push(ev);
                    if evidence.len() >= needed {
                        return Some(evidence);
                    }
                }
                let remaining = rule.conditions.len().saturating_sub(idx + 1);
                if evidence.len() + remaining < needed {
                    return None;
                }
            }
            None
        }
    }
}

fn evaluate_condition(
    cond: &RuleCondition,
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
) -> Option<String> {
    match cond {
        RuleCondition::StringContains {
            value,
            nocase,
            decoded,
            ascii,
            wide,
            utf8,
            utf16,
        } => {
            let needle = if *nocase { value.to_ascii_lowercase() } else { value.clone() };
            for (idx, hit) in report.strings.iter().enumerate() {
                let enc_ok = match hit.encoding.as_str() {
                    "ascii" => *ascii,
                    "utf16le" => *wide,
                    _ => *ascii,
                };
                if !enc_ok { continue; }
                let hay = if *nocase { view.strings_lower.get(idx)? } else { &hit.value };
                if hay.contains(&needle) {
                    return Some(format!("string_contains `{}` at 0x{:x}", value, hit.offset));
                }
            }
            if *wide || *utf8 || *utf16 {
                for (variant_bytes, label) in encoding_variants(value, *wide, *utf8, *utf16) {
                    if let Some(offset) = find_text_bytes(bytes, &variant_bytes, *nocase, false) {
                        return Some(format!("string_contains {} `{}` at 0x{:x}", label, value, offset));
                    }
                }
            }
            if *decoded {
                let needle_dec = if *nocase { value.to_ascii_lowercase() } else { value.clone() };
                for (idx, hit) in report.decoded_strings.iter().enumerate() {
                    let hay = if *nocase { &view.decoded_lower[idx] } else { &hit.decoded };
                    if hay.contains(&needle_dec) {
                        return Some(format!(
                            "decoded_string_contains `{}` via {}",
                            value, hit.method
                        ));
                    }
                }
            }
            None
        }
        RuleCondition::StringRegex { pattern, decoded } => {
            let re = cached_regex(pattern)?;
            if let Some(hit) = report.strings.iter().find(|s| re.is_match(&s.value)) {
                return Some(format!("string_regex `{}` at 0x{:x}", pattern, hit.offset));
            }
            if *decoded {
                if let Some(hit) = report
                    .decoded_strings
                    .iter()
                    .find(|s| re.is_match(&s.decoded))
                {
                    return Some(format!(
                        "decoded_string_regex `{}` via {}",
                        pattern, hit.method
                    ));
                }
            }
            None
        }
        RuleCondition::StringSet {
            values,
            min,
            nocase,
            decoded,
            regex,
            ascii,
            wide,
            utf8,
            utf16,
        } => {
            let needed = min.unwrap_or(1).max(1);
            if !regex {
                return match_string_set_literals(report, view, bytes, values, needed, *nocase, *decoded, *ascii, *wide, *utf8, *utf16);
            }
            let mut evidence = Vec::new();
            for value in values {
                if let Some(ev) = match_string_value(report, view, value, *nocase, *decoded, *regex)
                {
                    evidence.push(ev);
                }
                if evidence.len() >= needed {
                    return Some(format!(
                        "string_set matched {}/{}: {}",
                        evidence.len(),
                        needed,
                        evidence.join("; ")
                    ));
                }
            }
            None
        }
        RuleCondition::NativeSignature { atoms, expression } => {
            evaluate_native_signature(report, view, bytes, atoms, expression)
        }
        RuleCondition::ImportAny { names } => {
            let pe = report.pe.as_ref()?;
            names.iter().find_map(|name| {
                let needle = name.to_ascii_lowercase();
                view.imports_lower
                    .iter()
                    .position(|imp| imp.ends_with(&needle))
                    .map(|idx| format!("import_any matched {}", pe.imports[idx]))
            })
        }
        RuleCondition::ImportAll { names } => {
            let _pe = report.pe.as_ref()?;
            let found: Vec<_> = names
                .iter()
                .filter(|name| {
                    let needle = name.to_ascii_lowercase();
                    view.imports_lower.iter().any(|imp| imp.ends_with(&needle))
                })
                .cloned()
                .collect();
            (found.len() == names.len()).then(|| format!("import_all matched {}", found.join(", ")))
        }
        RuleCondition::ImportSet { names, min } => {
            let pe = report.pe.as_ref()?;
            let needed = min.unwrap_or(1).max(1);
            let mut found = Vec::new();
            for name in names {
                let needle = name.to_ascii_lowercase();
                if let Some(idx) = view
                    .imports_lower
                    .iter()
                    .position(|imp| imp.ends_with(&needle))
                {
                    found.push(pe.imports[idx].clone());
                }
                if found.len() >= needed {
                    return Some(format!(
                        "import_set matched {}/{}: {}",
                        found.len(),
                        needed,
                        found.join(", ")
                    ));
                }
            }
            None
        }
        RuleCondition::ImportRegex { pattern } => {
            let pe = report.pe.as_ref()?;
            let re = cached_regex(pattern)?;
            pe.imports
                .iter()
                .find(|imp| re.is_match(imp))
                .map(|imp| format!("import_regex `{}` matched {}", pattern, imp))
        }
        RuleCondition::DllAny { names } => {
            let pe = report.pe.as_ref()?;
            names.iter().find_map(|name| {
                let needle = name.to_ascii_lowercase();
                view.dlls_lower
                    .iter()
                    .position(|dll| dll == &needle)
                    .map(|idx| format!("dll_any matched {}", pe.dlls[idx]))
            })
        }
        RuleCondition::DllRegex { pattern } => {
            let pe = report.pe.as_ref()?;
            let re = cached_regex(pattern)?;
            pe.dlls
                .iter()
                .find(|dll| re.is_match(dll))
                .map(|dll| format!("dll_regex `{}` matched {}", pattern, dll))
        }
        RuleCondition::SuspiciousImportCount { min } => {
            let pe = report.pe.as_ref()?;
            (pe.suspicious_imports.len() >= *min).then(|| {
                format!(
                    "suspicious_import_count={} >= {}",
                    pe.suspicious_imports.len(),
                    min
                )
            })
        }
        RuleCondition::FileEntropy { min } => (report.entropy >= *min)
            .then(|| format!("file_entropy={:.3} >= {:.3}", report.entropy, min)),
        RuleCondition::FileSizeGte { bytes } => (report.file_size >= *bytes)
            .then(|| format!("file_size={} >= {}", report.file_size, bytes)),
        RuleCondition::FileSizeLte { bytes } => (report.file_size <= *bytes)
            .then(|| format!("file_size={} <= {}", report.file_size, bytes)),
        RuleCondition::SectionEntropy { min } => {
            let pe = report.pe.as_ref()?;
            pe.sections
                .iter()
                .find(|section| section.entropy >= *min)
                .map(|section| {
                    format!(
                        "section_entropy {}={:.3} >= {:.3}",
                        section.name, section.entropy, min
                    )
                })
        }
        RuleCondition::SectionNameRegex { pattern } => {
            let pe = report.pe.as_ref()?;
            let re = cached_regex(pattern)?;
            pe.sections
                .iter()
                .find(|section| re.is_match(&section.name))
                .map(|section| format!("section_name_regex `{}` matched {}", pattern, section.name))
        }
        RuleCondition::PackedPe => {
            let pe = report.pe.as_ref()?;
            pe.likely_packed
                .then(|| "packed_pe heuristic matched".to_string())
        }
        RuleCondition::EnvReference { min } => {
            let threshold = (*min).max(1);
            (report.env_hits.len() >= threshold)
                .then(|| format!("env_hits={} >= {}", report.env_hits.len(), threshold))
        }
        RuleCondition::RegistryPattern { pattern, nocase } => {
            let compiled_pattern = if *nocase {
                format!("(?i){}", pattern)
            } else {
                pattern.clone()
            };
            let compiled = cached_regex(&compiled_pattern)?;
            report
                .registry_hits
                .iter()
                .find(|hit| compiled.is_match(&hit.key_or_value))
                .map(|hit| format!("registry_pattern matched {}", hit.key_or_value))
        }
        RuleCondition::RegistryHitCount { min } => {
            (report.registry_hits.len() >= *min).then(|| {
                format!(
                    "registry_hit_count={} >= {}",
                    report.registry_hits.len(),
                    min
                )
            })
        }
        RuleCondition::PathRegex { pattern } => {
            let re = cached_regex(pattern)?;
            let path = report.path.to_string_lossy();
            re.is_match(&path)
                .then(|| format!("path_regex matched {}", path))
        }
        RuleCondition::SignatureSignerContains { value, nocase } => {
            if value.is_empty() {
                return None;
            }
            let signature = report.signature.as_ref()?;
            let signer_name = signature.signer_name.as_ref()?;
            let matched = if *nocase {
                signer_name.to_lowercase().contains(&value.to_lowercase())
            } else {
                signer_name.contains(value)
            };
            matched.then(|| {
                format!(
                    "signature_signer_contains `{}` matched `{}`",
                    truncate_for_evidence(value, 120),
                    truncate_for_evidence(signer_name, 120)
                )
            })
        }
        RuleCondition::SignatureIsSigned { value } => {
            let sig = report.signature.as_ref()?;
            (sig.is_signed == *value).then(|| {
                format!("signature_is_signed={} matched", sig.is_signed)
            })
        }
        RuleCondition::SignatureInvalid => {
            let sig = report.signature.as_ref()?;
            sig.invalid_signature.then(|| {
                format!(
                    "signature_invalid: is_signed={} invalid_signature=true HRESULT=0x{:08X}",
                    sig.is_signed, sig.raw_hresult
                )
            })
        }
        RuleCondition::SignatureVerificationFailed => {
            let sig = report.signature.as_ref()?;
            sig.verification_failed.then(|| {
                format!(
                    "signature_verification_failed: is_signed={} HRESULT=0x{:08X}",
                    sig.is_signed, sig.raw_hresult
                )
            })
        }
        RuleCondition::SignatureAnyIssue => {
            let sig = report.signature.as_ref()?;
            let bad = sig.invalid_signature || sig.verification_failed || sig.signature_status_issues;
            bad.then(|| {
                format!(
                    "signature_any_issue: invalid={} verification_failed={} status_issues={} HRESULT=0x{:08X}",
                    sig.invalid_signature, sig.verification_failed, sig.signature_status_issues, sig.raw_hresult
                )
            })
        }
        RuleCondition::SignatureHresultIn { values } => {
            let sig = report.signature.as_ref()?;
            values.contains(&sig.raw_hresult).then(|| {
                format!(
                    "signature_hresult_in: HRESULT=0x{:08X} matched rule list",
                    sig.raw_hresult
                )
            })
        }
        RuleCondition::FileType { values } => values
            .iter()
            .find(|value| report.file_type.matches_type(value))
            .map(|value| {
                format!(
                    "file_type matched {} primary={} tags={}",
                    value,
                    report.file_type.primary,
                    report.file_type.tags.join(",")
                )
            }),
        RuleCondition::HashSha256 { value } => report
            .hashes
            .sha256
            .eq_ignore_ascii_case(value)
            .then(|| "sha256 hash matched".to_string()),
        RuleCondition::HashMd5 { value } => report
            .hashes
            .md5
            .eq_ignore_ascii_case(value)
            .then(|| "md5 hash matched".to_string()),
        RuleCondition::FeatureGte { name, value } => {
            let current = report.features.get(name)?.as_f64()?;
            (current >= *value).then(|| format!("feature {}={} >= {}", name, current, value))
        }
        RuleCondition::BytePattern { pattern } => {
            let compiled = cached_byte_pattern(pattern)?;
            find_byte_pattern(bytes, compiled.as_ref())
                .map(|offset| format!("byte_pattern `{}` at 0x{:x}", pattern, offset))
        }
        RuleCondition::ByteSet { patterns, min } => {
            let needed = min.unwrap_or(1).max(1);
            let mut evidence = Vec::new();
            for pattern in patterns {
                if let Some(compiled) = cached_byte_pattern(pattern) {
                    if let Some(offset) = find_byte_pattern(bytes, compiled.as_ref()) {
                        evidence.push(format!("`{}` at 0x{:x}", pattern, offset));
                    }
                }
                if evidence.len() >= needed {
                    return Some(format!(
                        "byte_set matched {}/{}: {}",
                        evidence.len(),
                        needed,
                        evidence.join("; ")
                    ));
                }
            }
            None
        }
    }
}

fn match_string_set_literals(
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    values: &[String],
    needed: usize,
    nocase: bool,
    decoded: bool,
    ascii: bool,
    wide: bool,
    utf8: bool,
    utf16: bool,
) -> Option<String> {
    let ac = cached_literal_set(values, nocase)?;
    let mut seen = vec![false; values.len()];
    let mut evidence = Vec::with_capacity(needed.min(values.len()));

    for (idx, hit) in report.strings.iter().enumerate() {
        let enc_ok = match hit.encoding.as_str() {
            "ascii" => ascii,
            "utf16le" => wide,
            _ => ascii,
        };
        if !enc_ok { continue; }
        let hay = if nocase {
            view.strings_lower.get(idx)?.as_str()
        } else {
            hit.value.as_str()
        };
        for mat in ac.find_overlapping_iter(hay) {
            let pattern_id = mat.pattern().as_usize();
            if pattern_id >= seen.len() || seen[pattern_id] {
                continue;
            }
            seen[pattern_id] = true;
            evidence.push(format!(
                "literal `{}` at 0x{:x}",
                values
                    .get(pattern_id)
                    .map(String::as_str)
                    .unwrap_or("<pattern>"),
                hit.offset + mat.start()
            ));
            if evidence.len() >= needed {
                return Some(format!(
                    "string_set matched {}/{}: {}",
                    evidence.len(),
                    needed,
                    evidence.join("; ")
                ));
            }
        }
    }

    // Raw-bytes fallback for encoding variants not covered by extracted strings.
    if wide || utf8 || utf16 {
        let already_found: Vec<bool> = seen.clone();
        for (i, value) in values.iter().enumerate() {
            if already_found[i] { continue; }
            for (variant_bytes, label) in encoding_variants(value, wide, utf8, utf16) {
                if let Some(offset) = find_text_bytes(bytes, &variant_bytes, nocase, false) {
                    seen[i] = true;
                    evidence.push(format!(
                        "literal {} `{}` at 0x{:x}",
                        label, value, offset
                    ));
                    if evidence.len() >= needed {
                        return Some(format!(
                            "string_set matched {}/{}: {}",
                            evidence.len(),
                            needed,
                            evidence.join("; ")
                        ));
                    }
                }
            }
        }
    }

    if decoded {
        for (idx, hit) in report.decoded_strings.iter().enumerate() {
            let hay = if nocase {
                view.decoded_lower.get(idx)?.as_str()
            } else {
                hit.decoded.as_str()
            };
            for mat in ac.find_overlapping_iter(hay) {
                let pattern_id = mat.pattern().as_usize();
                if pattern_id >= seen.len() || seen[pattern_id] {
                    continue;
                }
                seen[pattern_id] = true;
                evidence.push(format!(
                    "decoded literal `{}` via {}",
                    values
                        .get(pattern_id)
                        .map(String::as_str)
                        .unwrap_or("<pattern>"),
                    hit.method
                ));
                if evidence.len() >= needed {
                    return Some(format!(
                        "string_set matched {}/{}: {}",
                        evidence.len(),
                        needed,
                        evidence.join("; ")
                    ));
                }
            }
        }
    }

    None
}

fn match_string_value(
    report: &ScanReport,
    view: &ScanView,
    value: &str,
    nocase: bool,
    decoded: bool,
    regex: bool,
) -> Option<String> {
    if regex {
        let pattern = if nocase {
            format!("(?i){}", value)
        } else {
            value.to_string()
        };
        let re = cached_regex(&pattern)?;
        if let Some(hit) = report.strings.iter().find(|s| re.is_match(&s.value)) {
            return Some(format!("regex `{}` at 0x{:x}", value, hit.offset));
        }
        if decoded {
            if let Some(hit) = report
                .decoded_strings
                .iter()
                .find(|s| re.is_match(&s.decoded))
            {
                return Some(format!("decoded regex `{}` via {}", value, hit.method));
            }
        }
        return None;
    }

    if nocase {
        let needle = value.to_ascii_lowercase();
        for (hit, hay) in report.strings.iter().zip(&view.strings_lower) {
            if hay.contains(&needle) {
                return Some(format!("literal `{}` at 0x{:x}", value, hit.offset));
            }
        }
        if decoded {
            for (hit, hay) in report.decoded_strings.iter().zip(&view.decoded_lower) {
                if hay.contains(&needle) {
                    return Some(format!("decoded literal `{}` via {}", value, hit.method));
                }
            }
        }
    } else {
        for hit in &report.strings {
            if hit.value.contains(value) {
                return Some(format!("literal `{}` at 0x{:x}", value, hit.offset));
            }
        }
        if decoded {
            for hit in &report.decoded_strings {
                if hit.decoded.contains(value) {
                    return Some(format!("decoded literal `{}` via {}", value, hit.method));
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
struct AtomMatch {
    matched: bool,
    evidence: Vec<String>,
    offsets: Vec<usize>,
}

fn evaluate_native_signature(
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    atoms: &[SignatureAtom],
    expression: &str,
) -> Option<String> {
    if let Some(result) = evaluate_simple_native_signature(report, view, bytes, atoms, expression) {
        return result;
    }

    let mut atom_hits = HashMap::new();
    for atom in atoms {
        atom_hits.insert(
            atom.id.clone(),
            match_signature_atom(report, view, bytes, atom),
        );
    }

    let matched = evaluate_signature_expression(expression, &atom_hits, report, bytes, atoms);
    if !matched {
        return None;
    }

    let mut evidence = Vec::new();
    evidence.push(format!(
        "native_signature expression matched: {}",
        truncate_for_evidence(expression, 220)
    ));
    for atom in atoms {
        if let Some(hit) = atom_hits.get(&atom.id) {
            if hit.matched {
                let first = hit
                    .evidence
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("${} matched", atom.id));
                evidence.push(first);
            }
        }
        if evidence.len() >= 10 {
            break;
        }
    }
    Some(evidence.join("; "))
}

fn evaluate_simple_native_signature(
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    atoms: &[SignatureAtom],
    expression: &str,
) -> Option<Option<String>> {
    let expr = expression.trim();
    static THEM_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^(any|all|\d+)\s+of\s+them$").unwrap());
    static GROUP_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^(any|all|\d+)\s+of\s*\(\s*([^\)]*\$[^\)]*)\s*\)$").unwrap());

    let (quant, selected): (&str, Vec<&SignatureAtom>) = if let Some(caps) = THEM_RE.captures(expr)
    {
        (caps.get(1).unwrap().as_str(), atoms.iter().collect())
    } else if let Some(caps) = GROUP_RE.captures(expr) {
        let spec = caps.get(2).unwrap().as_str();
        (
            caps.get(1).unwrap().as_str(),
            select_signature_atoms(spec, atoms),
        )
    } else {
        return None;
    };

    if selected.is_empty() {
        return Some(None);
    }

    let needed = match quant.to_ascii_lowercase().as_str() {
        "any" => 1,
        "all" => selected.len(),
        value => value.parse::<usize>().unwrap_or(1).max(1),
    };
    if needed > selected.len() {
        return Some(None);
    }

    let mut hits: Vec<(&SignatureAtom, AtomMatch)> = Vec::with_capacity(needed);
    for (idx, atom) in selected.iter().enumerate() {
        let hit = match_signature_atom(report, view, bytes, atom);
        if hit.matched {
            hits.push((*atom, hit));
            if hits.len() >= needed {
                return Some(Some(native_signature_evidence(expression, &hits)));
            }
        }
        let remaining = selected.len().saturating_sub(idx + 1);
        if hits.len() + remaining < needed {
            return Some(None);
        }
    }

    Some(None)
}

fn select_signature_atoms<'a>(spec: &str, atoms: &'a [SignatureAtom]) -> Vec<&'a SignatureAtom> {
    let mut selected = Vec::new();
    for part in spec.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let part = part.trim_start_matches('$').trim();
        if let Some(prefix) = part.strip_suffix('*') {
            selected.extend(atoms.iter().filter(|atom| atom.id.starts_with(prefix)));
        } else if let Some(atom) = atoms.iter().find(|atom| atom.id == part) {
            selected.push(atom);
        }
    }
    selected
}

fn native_signature_evidence(expression: &str, hits: &[(&SignatureAtom, AtomMatch)]) -> String {
    let mut evidence = Vec::with_capacity(hits.len().min(9) + 1);
    evidence.push(format!(
        "native_signature expression matched: {}",
        truncate_for_evidence(expression, 220)
    ));
    for (atom, hit) in hits.iter().take(9) {
        let first = hit
            .evidence
            .first()
            .cloned()
            .unwrap_or_else(|| format!("${} matched", atom.id));
        evidence.push(first);
    }
    evidence.join("; ")
}

fn match_signature_atom(
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    atom: &SignatureAtom,
) -> AtomMatch {
    // Timeout detection: track start time for slow operation detection
    let start = Instant::now();
    const ATOM_TIMEOUT_MS: u128 = 5000; // 5 second timeout per atom

    let result = match atom.kind {
        SignatureAtomKind::Text => match_text_atom(report, view, bytes, atom),
        SignatureAtomKind::Regex => match_regex_atom(report, atom),
        SignatureAtomKind::Bytes => match_byte_atom(bytes, atom),
    };

    let elapsed = start.elapsed().as_millis();
    if elapsed > ATOM_TIMEOUT_MS {
        log::warn!(
            "Slow atom detected: ${} took {}ms (file_size={} type={})",
            atom.id,
            elapsed,
            bytes.len(),
            match atom.kind {
                SignatureAtomKind::Text => "text",
                SignatureAtomKind::Regex => "regex",
                SignatureAtomKind::Bytes => "bytes",
            }
        );
    }

    result
}

fn match_text_atom(
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    atom: &SignatureAtom,
) -> AtomMatch {
    // Fast normal extracted-string path. This covers ASCII and UTF-16LE strings
    // because the scanner normalizes UTF-16LE into StringHit values.
    let mut out = AtomMatch::default();
    if atom.nocase {
        let needle = atom.value.to_ascii_lowercase();
        for (hit, hay) in report.strings.iter().zip(&view.strings_lower) {
            if let Some(pos) = find_literal(hay, &needle, atom.fullword) {
                out.matched = true;
                out.offsets.push(hit.offset + pos);
                out.evidence.push(format!(
                    "${} text `{}` at 0x{:x}",
                    atom.id,
                    truncate_for_evidence(&atom.value, 80),
                    hit.offset + pos
                ));
                return out;
            }
        }
        if atom.decoded {
            for (hit, hay) in report.decoded_strings.iter().zip(&view.decoded_lower) {
                if find_literal(hay, &needle, atom.fullword).is_some() {
                    out.matched = true;
                    out.evidence.push(format!(
                        "${} decoded text `{}` via {}",
                        atom.id,
                        truncate_for_evidence(&atom.value, 80),
                        hit.method
                    ));
                    return out;
                }
            }
        }
    } else {
        for hit in &report.strings {
            if let Some(pos) = find_literal(&hit.value, &atom.value, atom.fullword) {
                out.matched = true;
                out.offsets.push(hit.offset + pos);
                out.evidence.push(format!(
                    "${} text `{}` at 0x{:x}",
                    atom.id,
                    truncate_for_evidence(&atom.value, 80),
                    hit.offset + pos
                ));
                return out;
            }
        }
        if atom.decoded {
            for hit in &report.decoded_strings {
                if find_literal(&hit.decoded, &atom.value, atom.fullword).is_some() {
                    out.matched = true;
                    out.evidence.push(format!(
                        "${} decoded text `{}` via {}",
                        atom.id,
                        truncate_for_evidence(&atom.value, 80),
                        hit.method
                    ));
                    return out;
                }
            }
        }
    }

    // Raw-byte modifier path for Yamdle equivalents of YARA ascii/wide/xor/base64/base64wide.
    // These are kept here so no external YARA runtime is required.
    let variants = text_atom_raw_variants(atom);
    for (label, needle) in variants {
        if let Some(offset) = find_text_bytes(bytes, &needle, atom.nocase, atom.fullword) {
            out.matched = true;
            out.offsets.push(offset);
            out.evidence.push(format!(
                "${} {} text `{}` at 0x{:x}",
                atom.id,
                label,
                truncate_for_evidence(&atom.value, 80),
                offset
            ));
            return out;
        }
    }

    if atom.xor {
        // YARA-equivalent approach: all XOR key variants are pre-built into a single
        // Aho-Corasick automaton at rule load time. A single O(file_len) scan finds
        // the first matching variant regardless of the key range size, instead of
        // performing O(range × file_len) searches with per-key allocations.
        if let Some(xor_ac) = build_xor_text_ac(atom) {
            // fullword check: AC finds the match position; we then verify word-boundary
            // constraints post-match so AC stays fast (no per-byte fullword logic needed
            // inside the automaton itself).
            let search_result = if atom.fullword {
                xor_ac.ac.find_iter(bytes).find(|mat| {
                    let start = mat.start();
                    let end = mat.end();
                    let len = end - start;
                    byte_word_boundary_at(bytes, start, len)
                })
            } else {
                xor_ac.ac.find(bytes)
            };

            if let Some(mat) = search_result {
                let pid = mat.pattern().as_usize();
                let (key, label) = xor_ac.meta.get(pid).copied().unwrap_or((0, "xor"));
                out.matched = true;
                out.offsets.push(mat.start());
                out.evidence.push(format!(
                    "${} xor(0x{:02x}) {} text `{}` at 0x{:x}",
                    atom.id,
                    key,
                    label,
                    truncate_for_evidence(&atom.value, 80),
                    mat.start()
                ));
                return out;
            }
        }
    }

    if atom.base64 {
        let encoded = general_purpose::STANDARD.encode(atom.value.as_bytes());
        if let Some(offset) = find_text_bytes(bytes, encoded.as_bytes(), atom.nocase, false) {
            out.matched = true;
            out.offsets.push(offset);
            out.evidence.push(format!(
                "${} base64 `{}` at 0x{:x}",
                atom.id,
                truncate_for_evidence(&atom.value, 80),
                offset
            ));
            return out;
        }
    }

    if atom.base64wide {
        let wide = utf16le_bytes(&atom.value);
        let encoded = general_purpose::STANDARD.encode(wide);
        if let Some(offset) = find_text_bytes(bytes, encoded.as_bytes(), atom.nocase, false) {
            out.matched = true;
            out.offsets.push(offset);
            out.evidence.push(format!(
                "${} base64wide `{}` at 0x{:x}",
                atom.id,
                truncate_for_evidence(&atom.value, 80),
                offset
            ));
            return out;
        }
    }

    out
}

fn match_regex_atom(report: &ScanReport, atom: &SignatureAtom) -> AtomMatch {
    let mut out = AtomMatch::default();
    let pattern = if atom.nocase {
        format!("(?i){}", atom.value)
    } else {
        atom.value.clone()
    };
    let Some(re) = cached_regex(&pattern) else {
        return out;
    };
    for hit in &report.strings {
        if re.is_match(&hit.value) {
            out.matched = true;
            out.offsets.push(hit.offset);
            out.evidence.push(format!(
                "${} regex `{}` at 0x{:x}",
                atom.id,
                truncate_for_evidence(&atom.value, 80),
                hit.offset
            ));
            return out;
        }
    }
    if atom.decoded {
        for hit in &report.decoded_strings {
            if re.is_match(&hit.decoded) {
                out.matched = true;
                out.evidence.push(format!(
                    "${} decoded regex `{}` via {}",
                    atom.id,
                    truncate_for_evidence(&atom.value, 80),
                    hit.method
                ));
                return out;
            }
        }
    }
    out
}

fn match_byte_atom(bytes: &[u8], atom: &SignatureAtom) -> AtomMatch {
    let mut out = AtomMatch::default();
    if let Some(pattern) = cached_byte_pattern(&atom.value) {
        if let Some(offset) = find_byte_pattern(bytes, pattern.as_ref()) {
            out.matched = true;
            out.offsets.push(offset);
            out.evidence.push(format!(
                "${} bytes `{}` at 0x{:x}",
                atom.id,
                truncate_for_evidence(&atom.value, 80),
                offset
            ));
            return out;
        }

        if atom.xor {
            let (lo, hi) = xor_key_range(atom);

            // Fast path: if all tokens are exact (no wildcards) the XOR'd pattern is a
            // plain byte string. Build one Aho-Corasick automaton for all key variants
            // and do a single O(file_len) pass — same strategy as text XOR above.
            if pattern.tokens.iter().all(|t| t.mask == 0xff) {
                let plain: Vec<u8> = pattern.tokens.iter().map(|t| t.value).collect();
                let mut variants: Vec<Vec<u8>> = Vec::with_capacity((hi - lo + 1) as usize);
                let mut keys: Vec<u8> = Vec::with_capacity(variants.capacity());
                for k in lo..=hi {
                    let encoded: Vec<u8> = plain.iter().map(|b| b ^ k).collect();
                    variants.push(encoded);
                    keys.push(k);
                }
                if let Ok(ac) = AhoCorasickBuilder::new().build(&variants) {
                    if let Some(mat) = ac.find(bytes) {
                        let key = keys[mat.pattern().as_usize()];
                        out.matched = true;
                        out.offsets.push(mat.start());
                        out.evidence.push(format!(
                            "${} xor(0x{:02x}) bytes `{}` at 0x{:x}",
                            atom.id,
                            key,
                            truncate_for_evidence(&atom.value, 80),
                            mat.start()
                        ));
                        return out;
                    }
                }
            } else {
                // Wildcard pattern: must verify full mask per position.
                // Re-use the same token slice but XOR only the value field — no new
                // Vec<ByteToken> allocation per key; stack-allocate via a fixed buffer
                // using the existing find_byte_pattern logic.
                let tokens_len = pattern.tokens.len();
                let mut xored_tokens: Vec<ByteToken> = pattern.tokens.clone();
                for k in lo..=hi {
                    for (i, src) in pattern.tokens.iter().enumerate() {
                        xored_tokens[i] = ByteToken {
                            value: src.value ^ k,
                            mask: src.mask,
                        };
                    }
                    let xored_pat = CompiledBytePattern::from_tokens(xored_tokens.clone());
                    if let Some(offset) = find_byte_pattern(bytes, &xored_pat) {
                        out.matched = true;
                        out.offsets.push(offset);
                        out.evidence.push(format!(
                            "${} xor(0x{:02x}) bytes `{}` at 0x{:x}",
                            atom.id,
                            k,
                            truncate_for_evidence(&atom.value, 80),
                            offset
                        ));
                        return out;
                    }
                }
                let _ = tokens_len; // suppress unused warning
            }
        }
    }
    out
}

fn text_atom_raw_variants(atom: &SignatureAtom) -> Vec<(&'static str, Vec<u8>)> {
    let mut variants = Vec::new();
    if atom.ascii || !atom.wide {
        variants.push(("ascii", atom.value.as_bytes().to_vec()));
    }
    if atom.wide {
        variants.push(("wide", utf16le_bytes(&atom.value)));
    }
    variants
}

fn text_atom_plain_xor_variants(atom: &SignatureAtom) -> Vec<(&'static str, Vec<u8>)> {
    // YARA `xor` is applied to the encoded string representation. If both ascii
    // and wide are set, both encodings are tried. If neither is specified,
    // ASCII is used as the default practical representation.
    text_atom_raw_variants(atom)
}

fn utf16le_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn utf16be_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

/// Generate raw byte encoding variants for a string value.
/// Returns `(bytes, label)` pairs.
fn encoding_variants(value: &str, wide: bool, utf8: bool, utf16: bool) -> Vec<(Vec<u8>, &'static str)> {
    let mut variants = Vec::new();
    if wide {
        variants.push((utf16le_bytes(value), "wide"));
    }
    if utf8 {
        variants.push((value.as_bytes().to_vec(), "utf8"));
    }
    if utf16 {
        variants.push((utf16be_bytes(value), "utf16"));
    }
    variants
}

fn xor_key_range(atom: &SignatureAtom) -> (u8, u8) {
    let lo = atom.xor_min.unwrap_or(1);
    // YARA default: xor without range = xor(1,255). The previous cap of 32 was a
    // performance workaround that is no longer needed now that we use Aho-Corasick.
    let hi = atom.xor_max.unwrap_or(255);
    if lo <= hi {
        (lo, hi)
    } else {
        (hi, lo)
    }
}

fn find_text_bytes(hay: &[u8], needle: &[u8], nocase: bool, fullword: bool) -> Option<usize> {
    if nocase {
        find_bytes_nocase_ascii(hay, needle, fullword)
    } else {
        find_bytes(hay, needle, fullword)
    }
}

fn find_bytes(hay: &[u8], needle: &[u8], fullword: bool) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    if !fullword {
        return memmem::find(hay, needle);
    }

    let mut search_from = 0usize;
    while search_from < hay.len() {
        let rel = memmem::find(&hay[search_from..], needle)?;
        let pos = search_from + rel;
        if byte_word_boundary_at(hay, pos, needle.len()) {
            return Some(pos);
        }
        search_from = pos + 1;
    }
    None
}

fn find_bytes_nocase_ascii(hay: &[u8], needle: &[u8], fullword: bool) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    let first = needle_lower[0];
    for i in 0..=hay.len() - needle_lower.len() {
        if hay[i].to_ascii_lowercase() != first {
            continue;
        }
        let matched = hay[i..i + needle_lower.len()]
            .iter()
            .zip(needle_lower.iter())
            .all(|(byte, needle)| byte.to_ascii_lowercase() == *needle);
        if matched && (!fullword || byte_word_boundary_at(hay, i, needle_lower.len())) {
            return Some(i);
        }
    }
    None
}

fn byte_word_boundary_at(hay: &[u8], start: usize, len: usize) -> bool {
    let before = start.checked_sub(1).and_then(|i| hay.get(i)).copied();
    let after = hay.get(start + len).copied();
    !is_word_byte(before) && !is_word_byte(after)
}

fn is_word_byte(b: Option<u8>) -> bool {
    b.map(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
        .unwrap_or(false)
}

fn find_literal(hay: &str, needle: &str, fullword: bool) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    if !fullword {
        return hay.find(needle);
    }
    let mut start = 0usize;
    while let Some(pos) = hay[start..].find(needle) {
        let abs = start + pos;
        let before = hay[..abs].chars().next_back();
        let after = hay[abs + needle.len()..].chars().next();
        if !is_word_char(before) && !is_word_char(after) {
            return Some(abs);
        }
        start = abs + needle.len();
    }
    None
}

fn is_word_char(c: Option<char>) -> bool {
    c.map(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        .unwrap_or(false)
}

fn evaluate_signature_expression(
    expression: &str,
    atom_hits: &HashMap<String, AtomMatch>,
    report: &ScanReport,
    bytes: &[u8],
    atoms: &[SignatureAtom],
) -> bool {
    let mut expr = expression.to_string();
    expr = expr.replace('\n', " ").replace('\r', " ");

    expr = replace_group_of(&expr, atom_hits, atoms);
    expr = replace_them_of(&expr, atom_hits, atoms);
    expr = replace_atom_locations(&expr, atom_hits);
    expr = replace_plain_atoms(&expr, atom_hits);
    expr = replace_filesize(&expr, report.file_size);
    expr = replace_magic_uints(&expr, bytes);
    expr = replace_file_type_words(&expr, report, bytes);

    BoolParser::new(&expr).parse_expression()
}

fn replace_group_of(
    expr: &str,
    atom_hits: &HashMap<String, AtomMatch>,
    atoms: &[SignatureAtom],
) -> String {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)\b(any|all|\d+)\s+of\s*\(\s*([^\)]*\$[^\)]*)\s*\)").unwrap());
    let mut out = expr.to_string();
    loop {
        let Some(caps) = RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let quant = caps.get(1).unwrap().as_str();
        let spec = caps.get(2).unwrap().as_str();
        let value = eval_of_spec(quant, spec, atom_hits, atoms);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    out
}

fn replace_them_of(
    expr: &str,
    atom_hits: &HashMap<String, AtomMatch>,
    atoms: &[SignatureAtom],
) -> String {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)\b(any|all|\d+)\s+of\s+them\b").unwrap());
    let mut out = expr.to_string();
    loop {
        let Some(caps) = RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let quant = caps.get(1).unwrap().as_str();
        let value = eval_of_atoms(
            quant,
            atoms.iter().map(|a| a.id.as_str()).collect(),
            atom_hits,
        );
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    out
}

fn replace_atom_locations(expr: &str, atom_hits: &HashMap<String, AtomMatch>) -> String {
    static AT_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\$([A-Za-z0-9_]+)\s+at\s+(0x[0-9a-fA-F]+|\d+)").unwrap());
    static IN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\$([A-Za-z0-9_]+)\s+in\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\.\.\s*(0x[0-9a-fA-F]+|\d+)\s*\)").unwrap()
    });
    let mut out = expr.to_string();
    loop {
        let Some(caps) = IN_RE.captures(&out) else {
            break;
        };
        let m = caps.get(0).unwrap();
        let id = caps.get(1).unwrap().as_str();
        let start = parse_int(caps.get(2).unwrap().as_str()).unwrap_or(0);
        let end = parse_int(caps.get(3).unwrap().as_str()).unwrap_or(0);
        let value = atom_hits
            .get(id)
            .map(|hit| {
                hit.offsets
                    .iter()
                    .any(|off| (*off as u64) >= start && (*off as u64) <= end)
            })
            .unwrap_or(false);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    loop {
        let Some(caps) = AT_RE.captures(&out) else {
            break;
        };
        let m = caps.get(0).unwrap();
        let id = caps.get(1).unwrap().as_str();
        let expected = parse_int(caps.get(2).unwrap().as_str()).unwrap_or(0) as usize;
        let value = atom_hits
            .get(id)
            .map(|hit| hit.offsets.contains(&expected))
            .unwrap_or(false);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    out
}

fn replace_plain_atoms(expr: &str, atom_hits: &HashMap<String, AtomMatch>) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$([A-Za-z0-9_]+)").unwrap());
    let mut out = expr.to_string();
    loop {
        let Some(caps) = RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let id = caps.get(1).unwrap().as_str();
        let value = atom_hits.get(id).map(|hit| hit.matched).unwrap_or(false);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    out
}

fn replace_filesize(expr: &str, file_size: u64) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\bfilesize\s*(<=|>=|==|!=|<|>)\s*(\d+)\s*(KB|MB|GB)?").unwrap()
    });
    let mut out = expr.to_string();
    loop {
        let Some(caps) = RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let op = caps.get(1).unwrap().as_str();
        let mut n = caps.get(2).unwrap().as_str().parse::<u64>().unwrap_or(0);
        match caps
            .get(3)
            .map(|x| x.as_str().to_ascii_uppercase())
            .as_deref()
        {
            Some("KB") => n *= 1024,
            Some("MB") => n *= 1024 * 1024,
            Some("GB") => n *= 1024 * 1024 * 1024,
            _ => {}
        }
        let value = compare_u64(file_size, op, n);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    out
}

fn replace_magic_uints(expr: &str, bytes: &[u8]) -> String {
    static U16_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)uint16\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*==\s*(0x[0-9a-fA-F]+|\d+)")
            .unwrap()
    });
    static U32_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)uint32\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*==\s*(0x[0-9a-fA-F]+|\d+)")
            .unwrap()
    });
    static PE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)uint32\s*\(\s*uint32\s*\(\s*0x3c\s*\)\s*\)\s*==\s*0x4550").unwrap()
    });
    let mut out = expr.to_string();
    loop {
        let Some(m) = PE_RE.find(&out) else { break };
        out.replace_range(m.start()..m.end(), bool_lit(is_pe_magic(bytes)));
    }
    loop {
        let Some(caps) = U16_RE.captures(&out) else {
            break;
        };
        let m = caps.get(0).unwrap();
        let off = parse_int(caps.get(1).unwrap().as_str()).unwrap_or(0) as usize;
        let expected = parse_int(caps.get(2).unwrap().as_str()).unwrap_or(0) as u16;
        let value = read_u16_le(bytes, off)
            .map(|v| v == expected)
            .unwrap_or(false);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    loop {
        let Some(caps) = U32_RE.captures(&out) else {
            break;
        };
        let m = caps.get(0).unwrap();
        let off = parse_int(caps.get(1).unwrap().as_str()).unwrap_or(0) as usize;
        let expected = parse_int(caps.get(2).unwrap().as_str()).unwrap_or(0) as u32;
        let value = read_u32_le(bytes, off)
            .map(|v| v == expected)
            .unwrap_or(false);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }
    out
}

fn replace_file_type_words(expr: &str, report: &ScanReport, bytes: &[u8]) -> String {
    let mut out = expr.to_string();
    for (word, value) in [
        ("Macho", report.file_type.is_macho || is_macho_magic(bytes)),
        ("MachO", report.file_type.is_macho || is_macho_magic(bytes)),
        (
            "PE",
            report.file_type.is_pe || report.pe.is_some() || is_pe_magic(bytes),
        ),
        ("PE32", report.file_type.is_pe32),
        ("PE64", report.file_type.is_pe64),
        (
            "ELF",
            report.file_type.is_elf || bytes.starts_with(b"\x7fELF"),
        ),
        ("ELF32", report.file_type.is_elf32),
        ("ELF64", report.file_type.is_elf64),
        ("APK", report.file_type.is_apk),
        ("ZIP", report.file_type.is_zip),
        ("Archive", report.file_type.is_archive),
        ("JAR", report.file_type.is_jar),
        ("DEX", report.file_type.is_dex),
        ("Text", report.file_type.is_plain_text),
        ("PlainText", report.file_type.is_plain_text),
        ("Script", report.file_type.is_script),
        ("DotNet", is_dotnet_like(report)),
    ] {
        let pattern = format!(r"(?i)\b{}\b", regex::escape(word));
        if let Some(re) = cached_regex(&pattern) {
            out = re.replace_all(&out, bool_lit(value)).to_string();
        }
    }
    out
}

fn eval_of_spec(
    quant: &str,
    spec: &str,
    atom_hits: &HashMap<String, AtomMatch>,
    atoms: &[SignatureAtom],
) -> bool {
    let mut ids = Vec::new();
    for part in spec.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let part = part.trim_start_matches('$').trim();
        if let Some(prefix) = part.strip_suffix('*') {
            ids.extend(
                atoms
                    .iter()
                    .filter(|atom| atom.id.starts_with(prefix))
                    .map(|atom| atom.id.as_str()),
            );
        } else {
            ids.push(part);
        }
    }
    eval_of_atoms(quant, ids, atom_hits)
}

fn eval_of_atoms(quant: &str, ids: Vec<&str>, atom_hits: &HashMap<String, AtomMatch>) -> bool {
    if ids.is_empty() {
        return false;
    }
    let matched = ids
        .iter()
        .filter(|id| atom_hits.get(**id).map(|hit| hit.matched).unwrap_or(false))
        .count();
    match quant.to_ascii_lowercase().as_str() {
        "any" => matched >= 1,
        "all" => matched == ids.len(),
        n => matched >= n.parse::<usize>().unwrap_or(1),
    }
}

fn bool_lit(value: bool) -> &'static str {
    if value {
        " true "
    } else {
        " false "
    }
}

fn compare_u64(lhs: u64, op: &str, rhs: u64) -> bool {
    match op {
        "<" => lhs < rhs,
        "<=" => lhs <= rhs,
        ">" => lhs > rhs,
        ">=" => lhs >= rhs,
        "==" => lhs == rhs,
        "!=" => lhs != rhs,
        _ => false,
    }
}

fn parse_int(text: &str) -> Option<u64> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn is_pe_magic(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    let Some(e_lfanew) = read_u32_le(bytes, 0x3c).map(|v| v as usize) else {
        return false;
    };
    bytes
        .get(e_lfanew..e_lfanew + 4)
        .map(|s| s == b"PE\0\0")
        .unwrap_or(false)
}

fn is_macho_magic(bytes: &[u8]) -> bool {
    let Some(magic) = bytes.get(0..4) else {
        return false;
    };
    magic == [0xfe, 0xed, 0xfa, 0xce].as_slice()
        || magic == [0xce, 0xfa, 0xed, 0xfe].as_slice()
        || magic == [0xfe, 0xed, 0xfa, 0xcf].as_slice()
        || magic == [0xcf, 0xfa, 0xed, 0xfe].as_slice()
}

fn is_dotnet_like(report: &ScanReport) -> bool {
    let Some(pe) = &report.pe else { return false };
    pe.imports.iter().any(|i| {
        i.eq_ignore_ascii_case("mscoree.dll!_CorExeMain")
            || i.to_ascii_lowercase().contains("_corexemain")
    }) || pe
        .dlls
        .iter()
        .any(|dll| dll.eq_ignore_ascii_case("mscoree.dll"))
        || report.strings.iter().any(|s| {
            s.value.contains("BSJB") || s.value.contains("#~") || s.value.contains("mscoree.dll")
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BoolTok {
    True,
    False,
    And,
    Or,
    Not,
    LParen,
    RParen,
}

struct BoolParser {
    tokens: Vec<BoolTok>,
    pos: usize,
}

impl BoolParser {
    fn new(input: &str) -> Self {
        Self {
            tokens: lex_bool(input),
            pos: 0,
        }
    }

    fn parse_expression(&mut self) -> bool {
        self.parse_or()
    }

    fn parse_or(&mut self) -> bool {
        let mut value = self.parse_and();
        while self.match_tok(&BoolTok::Or) {
            value = value || self.parse_and();
        }
        value
    }

    fn parse_and(&mut self) -> bool {
        let mut value = self.parse_not();
        while self.match_tok(&BoolTok::And) {
            value = value && self.parse_not();
        }
        value
    }

    fn parse_not(&mut self) -> bool {
        if self.match_tok(&BoolTok::Not) {
            !self.parse_not()
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> bool {
        if self.match_tok(&BoolTok::True) {
            return true;
        }
        if self.match_tok(&BoolTok::False) {
            return false;
        }
        if self.match_tok(&BoolTok::LParen) {
            let value = self.parse_or();
            let _ = self.match_tok(&BoolTok::RParen);
            return value;
        }
        false
    }

    fn match_tok(&mut self, tok: &BoolTok) -> bool {
        if self.tokens.get(self.pos) == Some(tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

fn lex_bool(input: &str) -> Vec<BoolTok> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<BoolTok>| {
        if word.is_empty() {
            return;
        }
        match word.to_ascii_lowercase().as_str() {
            "true" => tokens.push(BoolTok::True),
            "false" => tokens.push(BoolTok::False),
            "and" => tokens.push(BoolTok::And),
            "or" => tokens.push(BoolTok::Or),
            "not" => tokens.push(BoolTok::Not),
            _ => tokens.push(BoolTok::False),
        }
        word.clear();
    };

    for ch in input.chars() {
        match ch {
            '(' => {
                flush(&mut current, &mut tokens);
                tokens.push(BoolTok::LParen);
            }
            ')' => {
                flush(&mut current, &mut tokens);
                tokens.push(BoolTok::RParen);
            }
            c if c.is_whitespace() => flush(&mut current, &mut tokens),
            c if c.is_ascii_alphanumeric() || c == '_' => current.push(c),
            _ => flush(&mut current, &mut tokens),
        }
    }
    flush(&mut current, &mut tokens);
    tokens
}

#[derive(Debug, Clone, Copy)]
struct ByteToken {
    value: u8,
    mask: u8,
}

#[derive(Debug, Clone)]
struct CompiledBytePattern {
    tokens: Vec<ByteToken>,
    exact: Option<Vec<u8>>,
    anchor: Option<(usize, Vec<u8>)>,
}

impl CompiledBytePattern {
    fn from_tokens(tokens: Vec<ByteToken>) -> Self {
        let exact = tokens
            .iter()
            .all(|token| token.mask == 0xff)
            .then(|| tokens.iter().map(|token| token.value).collect());

        let mut best_start = 0usize;
        let mut best_len = 0usize;
        let mut idx = 0usize;
        while idx < tokens.len() {
            if tokens[idx].mask != 0xff {
                idx += 1;
                continue;
            }
            let start = idx;
            while idx < tokens.len() && tokens[idx].mask == 0xff {
                idx += 1;
            }
            let len = idx - start;
            if len > best_len {
                best_start = start;
                best_len = len;
            }
        }

        let anchor = (best_len > 0).then(|| {
            (
                best_start,
                tokens[best_start..best_start + best_len]
                    .iter()
                    .map(|token| token.value)
                    .collect(),
            )
        });

        Self {
            tokens,
            exact,
            anchor,
        }
    }
}

fn compile_byte_pattern(pattern: &str) -> Option<CompiledBytePattern> {
    let tokens = normalize_hex_tokens(pattern);
    let mut out = Vec::new();
    for token in tokens {
        if token == "?" || token == "??" {
            out.push(ByteToken { value: 0, mask: 0 });
            continue;
        }
        if token.len() != 2 {
            return None;
        }
        let chars: Vec<char> = token.chars().collect();
        let (hi_val, hi_mask) = hex_nibble(chars[0])?;
        let (lo_val, lo_mask) = hex_nibble(chars[1])?;
        out.push(ByteToken {
            value: (hi_val << 4) | lo_val,
            mask: (hi_mask << 4) | lo_mask,
        });
    }

    (!out.is_empty()).then(|| CompiledBytePattern::from_tokens(out))
}

fn normalize_hex_tokens(pattern: &str) -> Vec<String> {
    let text = pattern
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    if !text
        .chars()
        .any(|c| c.is_whitespace() || c == '(' || c == '[')
    {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        return compact
            .as_bytes()
            .chunks(2)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect();
    }

    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        match chars[i] {
            '(' => {
                while i < chars.len() && chars[i] != ')' {
                    i += 1;
                }
                i += 1;
                out.push("??".to_string());
            }
            '[' => {
                i += 1;
                let mut spec = String::new();
                while i < chars.len() && chars[i] != ']' {
                    spec.push(chars[i]);
                    i += 1;
                }
                i += 1;
                let count = spec
                    .split('-')
                    .next()
                    .and_then(|n| n.trim().parse::<usize>().ok())
                    .unwrap_or(0)
                    .min(64);
                for _ in 0..count {
                    out.push("??".to_string());
                }
            }
            '|' => i += 1,
            _ => {
                let mut tok = String::new();
                while i < chars.len()
                    && !chars[i].is_whitespace()
                    && !matches!(chars[i], '(' | ')' | '[' | ']' | '|')
                {
                    tok.push(chars[i]);
                    i += 1;
                }
                if !tok.is_empty() {
                    out.push(tok);
                }
            }
        }
    }
    out
}

fn hex_nibble(c: char) -> Option<(u8, u8)> {
    if c == '?' {
        return Some((0, 0));
    }
    c.to_digit(16).map(|v| (v as u8, 0x0f))
}

fn find_byte_pattern(bytes: &[u8], pattern: &CompiledBytePattern) -> Option<usize> {
    let tokens = pattern.tokens.as_slice();
    if tokens.is_empty() || tokens.len() > bytes.len() {
        return None;
    }

    if let Some(exact) = &pattern.exact {
        return memmem::find(bytes, exact);
    }

    // YARA-X-like atom path: search the longest exact run first, then verify
    // the full wildcard/nibble pattern only at candidate offsets.
    if let Some((anchor_index, anchor)) = &pattern.anchor {
        let mut search_from = 0usize;
        while search_from < bytes.len() {
            let rel = memmem::find(&bytes[search_from..], anchor)?;
            let anchor_pos = search_from + rel;
            if let Some(start) = anchor_pos.checked_sub(*anchor_index) {
                if start + tokens.len() <= bytes.len()
                    && byte_window_matches(&bytes[start..start + tokens.len()], tokens)
                {
                    return Some(start);
                }
            }
            search_from = anchor_pos + 1;
        }
        return None;
    }

    bytes
        .windows(tokens.len())
        .position(|window| byte_window_matches(window, tokens))
}

#[inline]
fn byte_window_matches(window: &[u8], pattern: &[ByteToken]) -> bool {
    window
        .iter()
        .zip(pattern.iter())
        .all(|(byte, token)| (*byte & token.mask) == (token.value & token.mask))
}

fn truncate_for_evidence(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(3);
    let mut out: String = text.chars().take(keep).collect();
    out.push_str("...");
    out
}

pub fn aggregate_verdict(report: &mut ScanReport) {
    report.score = report
        .findings
        .iter()
        .map(|f| f.score)
        .sum::<u32>()
        .min(100);
    report.confidence = report
        .findings
        .iter()
        .map(|f| f.confidence)
        .max()
        .unwrap_or(0);

    report.verdict = if report.findings.iter().any(|f| f.verdict == Verdict::Trusted) {
        Verdict::Trusted
    } else if report.findings.iter().any(|f| f.verdict == Verdict::Malware) {
        Verdict::Malware
    } else if report.findings.iter().any(|f| f.verdict == Verdict::Pua) {
        Verdict::Pua
    } else if report.findings.iter().any(|f| f.verdict == Verdict::Suspicious) {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    let mut families = Vec::new();
    for family in report.findings.iter().filter_map(|f| f.family.as_ref()) {
        if !families
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(family))
        {
            families.push(family.clone());
        }
    }
    report.malware_families = families;
}

/// Resolve `%VAR%` environment-variable placeholders in a path template.
fn resolve_path_template(template: &str) -> String {
    let mut result = template.to_string();
    while let Some(start) = result.find('%') {
        let end = result[start + 1..].find('%').map(|p| start + 1 + p + 1);
        let Some(end) = end else { break };
        let var = &result[start + 1..end - 1];
        if let Ok(val) = std::env::var(var) {
            result.replace_range(start..end, &val);
        } else {
            break;
        }
    }
    result
}

/// Check whether `actual_path` matches the `required` path template.
/// Supports `%VAR%` placeholders. Comparison is case-insensitive on Windows.
fn path_matches_required(actual_path: &std::path::Path, required: &str) -> bool {
    let resolved = resolve_path_template(required);
    let resolved = resolved.replace('/', "\\").trim_end_matches('\\').to_string();
    let actual = actual_path.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_string();
    actual.eq_ignore_ascii_case(&resolved)
}

#[allow(dead_code)]
static _REGEX_COMPILE_GUARD: Lazy<Regex> = Lazy::new(|| Regex::new(".*").unwrap());
