use super::types::*;
use crate::models::{Finding, MitreTechnique, RulePerformance, ScanReport, Verdict};
use daachorse::DoubleArrayAhoCorasick;
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
    exports_lower: Vec<String>,
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

        let exports_lower = report
            .pe
            .as_ref()
            .map(|pe| {
                pe.exports
                    .iter()
                    .map(|exp| exp.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        Self {
            strings_lower,
            decoded_lower,
            imports_lower,
            dlls_lower,
            exports_lower,
        }
    }
}

static REGEX_CACHE: Lazy<Mutex<HashMap<String, Arc<Regex>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static BYTE_PATTERN_CACHE: Lazy<Mutex<HashMap<String, Arc<CompiledBytePattern>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static STRING_SET_CACHE: Lazy<Mutex<HashMap<String, Arc<DoubleArrayAhoCorasick<u32>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// Cache for XOR text atoms: key = "<atom_cache_key>" → daachorse automaton with all key variants pre-built.
/// Patterns are stored as raw bytes (Vec<u8>), value = pattern index → (xor_key, variant_label_index).
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

/// Pre-built daachorse automaton for a single XOR text atom.
/// `meta[i]` = `(xor_key, variant_label)` for the i-th pattern in the automaton.
/// (No Debug: `DoubleArrayAhoCorasick` doesn't implement it; cached by key.)
struct XorTextAc {
    ac: DoubleArrayAhoCorasick<u32>,
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

    let patvals: Vec<(Vec<u8>, u32)> = patterns
        .into_iter()
        .enumerate()
        .map(|(i, p)| (p, i as u32))
        .collect();
    let ac = DoubleArrayAhoCorasick::<u32>::with_values(patvals).ok()?;

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

fn cached_literal_set(values: &[String], nocase: bool) -> Option<Arc<DoubleArrayAhoCorasick<u32>>> {
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
    // value = index into `values` so match results map back to the rule literal.
    // Empty patterns are skipped (they would match everywhere); their `seen`
    // slot simply never fires.
    let patvals: Vec<(Vec<u8>, u32)> = patterns
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.is_empty())
        .map(|(i, p)| (p.as_bytes().to_vec(), i as u32))
        .collect();
    if patvals.is_empty() {
        return None;
    }
    let compiled = Arc::new(DoubleArrayAhoCorasick::<u32>::with_values(patvals).ok()?);
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
            RuleCondition::BytePattern {
                pattern, excludes, ..
            } => {
                let _ = cached_byte_pattern(pattern);
                for exclusion in excludes {
                    let _ = cached_byte_pattern(exclusion);
                }
            }
            RuleCondition::ByteSet {
                patterns, excludes, ..
            } => {
                for pattern in patterns {
                    let _ = cached_byte_pattern(pattern);
                }
                for exclusion in excludes {
                    let _ = cached_byte_pattern(exclusion);
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
                            // Pre-build the XOR daachorse automaton at rule load time
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
            RuleCondition::UnpackerAny { signatures } => signatures.len(),
            RuleCondition::ImageFuzzyHashAny { hashes, .. } => hashes.len(),
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
        RuleCondition::ExportAny { names } => {
            let pe = report.pe.as_ref()?;
            names.iter().find_map(|name| {
                let needle = name.to_ascii_lowercase();
                view.exports_lower
                    .iter()
                    .position(|exp| exp == &needle)
                    .map(|idx| format!("export_any matched {}", pe.exports[idx]))
            })
        }
        RuleCondition::ExportAll { names } => {
            let _pe = report.pe.as_ref()?;
            let found: Vec<_> = names
                .iter()
                .filter(|name| {
                    let needle = name.to_ascii_lowercase();
                    view.exports_lower.iter().any(|exp| exp == &needle)
                })
                .cloned()
                .collect();
            (found.len() == names.len()).then(|| format!("export_all matched {}", found.join(", ")))
        }
        RuleCondition::ExportSet { names, min } => {
            let pe = report.pe.as_ref()?;
            let needed = min.unwrap_or(1).max(1);
            let mut found = Vec::new();
            for name in names {
                let needle = name.to_ascii_lowercase();
                if let Some(idx) = view
                    .exports_lower
                    .iter()
                    .position(|exp| exp == &needle)
                {
                    found.push(pe.exports[idx].clone());
                }
                if found.len() >= needed {
                    return Some(format!(
                        "export_set matched {}/{}: {}",
                        found.len(),
                        needed,
                        found.join(", ")
                    ));
                }
            }
            None
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
        RuleCondition::PathRegex { pattern } => {
            let re = cached_regex(pattern)?;
            let path = report.path.to_string_lossy();
            re.is_match(&path)
                .then(|| format!("path_regex matched {}", path))
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
        RuleCondition::BytePattern {
            pattern,
            scope,
            excludes,
        } => {
            if let Some(hit) = find_excluded_byte(excludes, bytes) {
                let _ = hit;
                return None;
            }
            let compiled = cached_byte_pattern(pattern)?;
            let (start, end) = resolve_scope(bytes.len(), scope.as_ref());
            find_byte_pattern_in(bytes, compiled.as_ref(), start, end)
                .map(|offset| format!("byte_pattern `{}` at 0x{:x}", pattern, offset))
        }
        RuleCondition::ByteSet {
            patterns,
            min,
            scope,
            excludes,
        } => {
            if find_excluded_byte(excludes, bytes).is_some() {
                return None;
            }
            let needed = min.unwrap_or(1).max(1);
            let (start, end) = resolve_scope(bytes.len(), scope.as_ref());
            let mut evidence = Vec::new();
            for pattern in patterns {
                if let Some(compiled) = cached_byte_pattern(pattern)
                    && let Some(offset) = find_byte_pattern_in(bytes, compiled.as_ref(), start, end)
                {
                    evidence.push(format!("`{}` at 0x{:x}", pattern, offset));
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
        RuleCondition::UnpackerAny { signatures } => {
            for signature in signatures {
                let Some(compiled) = cached_byte_pattern(&signature.pattern) else {
                    continue;
                };
                if let Some(offset) = find_byte_pattern(bytes, compiled.as_ref()) {
                    return Some(format!(
                        "unpacker `{}` matched `{}` at 0x{:x}",
                        signature.name, signature.pattern, offset
                    ));
                }
            }
            None
        }
        RuleCondition::ImageFuzzyHashAny { hashes, max_distance } => {
            let Some(actual) = crate::fuzzy::calculate_image(bytes) else {
                return None;
            };
            let limit = max_distance.unwrap_or(0);
            let mut best: Option<(u32, &str)> = None;
            for raw in hashes {
                let Ok(candidate) = parse_image_hash(raw) else {
                    continue;
                };
                let distance = crate::fuzzy::hamming_distance(&actual, &candidate);
                if distance > limit {
                    continue;
                }
                if best.is_none_or(|(current, _)| distance < current) {
                    best = Some((distance, raw));
                }
            }
            best.map(|(distance, raw)| {
                format!(
                    "image pHash {} within {distance} bit(s) of `{raw}`",
                    hex::encode(actual)
                )
            })
        }
        RuleCondition::PeIconAny {
            dhash,
            dhash_max_distance,
            phash,
            phash_max_distance,
            idb,
            idb_groups,
        } => {
            let pe = match pefile_rs::PE::parse(bytes) {
                Ok(pe) => pe,
                Err(_) => return None,
            };
            let icons = crate::rules::icon::extract_icons(&pe);
            if icons.is_empty() {
                return None;
            }

            // A fingerprint only counts if the rule accepts the group it is in.
            let group_ok = |sig: &crate::rules::icon_metric::IconMetric| -> bool {
                if idb_groups.is_empty() {
                    return true;
                }
                idb_groups
                    .iter()
                    .any(|wanted| sig.groups.iter().flatten().any(|g| g == wanted))
            };

            let sigs: Vec<crate::rules::icon_metric::IconMetric> = idb
                .iter()
                .filter_map(|line| crate::rules::icon_metric::parse_idb_line(line).ok())
                .filter(group_ok)
                .collect();

            let dhash_limit = dhash_max_distance.unwrap_or(0);
            let phash_limit = phash_max_distance.unwrap_or(0);
            let mut best: Option<String> = None;

            for icon in &icons {
                let Some(prints) = crate::rules::icon::IconFingerprints::compute(icon) else {
                    continue;
                };

                for wanted in dhash {
                    let Ok(candidate) = parse_dhash(wanted) else {
                        continue;
                    };
                    let distance = crate::rules::icon::dhash_distance(prints.dhash, candidate);
                    if distance <= dhash_limit
                        && best.as_ref().is_none_or(|b| !b.contains("dhash"))
                    {
                        best = Some(format!(
                            "icon dhash {} within {distance} bit(s) of `{wanted}` ({side}x{side})",
                            prints.dhash_hex(),
                            side = icon.side
                        ));
                    }
                }

                for wanted in phash {
                    let Ok(candidate) = parse_image_hash(wanted) else {
                        continue;
                    };
                    let distance =
                        crate::fuzzy::hamming_distance(&prints.phash, &candidate);
                    if distance <= phash_limit
                        && best.as_ref().is_none_or(|b| !b.contains("phash"))
                    {
                        best = Some(format!(
                            "icon phash {} within {distance} bit(s) of `{wanted}` ({side}x{side})",
                            prints.phash_hex(),
                            side = icon.side
                        ));
                    }
                }

                if sigs.is_empty() {
                    continue;
                }
                let Some((width, metrics)) =
                    crate::rules::icon_metric::compute_metrics(icon)
                else {
                    continue;
                };
                let bucket = crate::rules::icon_metric::enginesize(width);
                for sig in &sigs {
                    if sig.size as u32 != width {
                        continue;
                    }
                    if let Some(confidence) = crate::rules::icon_metric::confident_match(
                        width,
                        bucket,
                        &metrics,
                        sig,
                    ) {
                        best = Some(format!(
                            "icon metric `{}` matched at confidence {confidence} ({side}x{side})",
                            sig.name,
                            side = icon.side
                        ));
                        break;
                    }
                }
                if best.is_some() {
                    break;
                }
            }

            best
        }
    }
}

/// Parse a 64-bit dHash written as 16 hex characters.
fn parse_dhash(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("dhash#").unwrap_or(trimmed);
    if hex.len() != 16 {
        return Err(format!("dHash must be 16 hex characters: {trimmed}"));
    }
    u64::from_str_radix(hex, 16).map_err(|_| format!("invalid dHash hex: {trimmed}"))
}

/// Accept a bare 16-hex image hash or a full ClamAV `fuzzy_img#<hex>` subsignature.
fn parse_image_hash(raw: &str) -> Result<[u8; 8], String> {
    let trimmed = raw.trim();
    if trimmed.starts_with("fuzzy_img#") {
        crate::fuzzy::parse_fuzzy_img(trimmed)
    } else {
        crate::fuzzy::parse_fuzzy_img(&format!("fuzzy_img#{trimmed}"))
    }
}

/// Returns the offset of the first known-benign blob that vetoes a byte
/// condition, or `None` when no exclusion is configured or none of them matched.
fn find_excluded_byte(excludes: &[String], bytes: &[u8]) -> Option<usize> {
    for exclusion in excludes {
        if let Some(compiled) = cached_byte_pattern(exclusion) {
            if let Some(offset) = find_byte_pattern(bytes, compiled.as_ref()) {
                return Some(offset);
            }
        }
    }
    None
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
        for mat in ac.find_overlapping_iter(hay.as_bytes()) {
            let pattern_id = mat.value() as usize;
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
            for mat in ac.find_overlapping_iter(hay.as_bytes()) {
                let pattern_id = mat.value() as usize;
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
        // daachorse automaton at rule load time. A single O(file_len) scan finds
        // the first matching variant regardless of the key range size, instead of
        // performing O(range × file_len) searches with per-key allocations.
        if let Some(xor_ac) = build_xor_text_ac(atom) {
            // fullword check: daachorse finds the match position; we then verify word-boundary
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
                xor_ac.ac.find_iter(bytes).next()
            };

            if let Some(mat) = search_result {
                let pid = mat.value() as usize;
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
            // plain byte string. Build one daachorse automaton for all key variants
            // and do a single O(file_len) pass — same strategy as text XOR above.
            if pattern.tokens.iter().all(|t| t.mask == 0xff) {
                let plain: Vec<u8> = pattern.tokens.iter().map(|t| t.value).collect();
                let mut patvals: Vec<(Vec<u8>, u32)> = Vec::with_capacity((hi - lo + 1) as usize);
                let mut keys: Vec<u8> = Vec::with_capacity(patvals.capacity());
                for k in lo..=hi {
                    let encoded: Vec<u8> = plain.iter().map(|b| b ^ k).collect();
                    patvals.push((encoded, keys.len() as u32));
                    keys.push(k);
                }
                if let Ok(ac) = DoubleArrayAhoCorasick::<u32>::with_values(patvals) {
                    if let Some(mat) = ac.find_iter(bytes).next() {
                        let key = keys[mat.value() as usize];
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
    expr = replace_relative_offsets(&expr, atom_hits);
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

/// Relative-offset correlation between two atoms.
///
/// Supported forms, all rewritten to a boolean literal before the boolean
/// parser runs:
///   `$a at $b + 40` / `$a at $b - 4`   readable alias
///   `@a[-4] == @b`, `@a[8] < 0x100`     YARA-compatible anchors
fn replace_relative_offsets(
    expr: &str,
    atom_hits: &HashMap<String, AtomMatch>,
) -> String {
    static ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"\$([A-Za-z0-9_]+)\s+at\s+\$([A-Za-z0-9_]+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)",
        )
        .unwrap()
    });
    static YARA_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"@([A-Za-z0-9_]+)\s*(?:\[\s*([+-]?\d+)?\s*\])?\s*(==|!=|<=|>=|<|>)\s*@([A-Za-z0-9_]+)\s*(?:\[\s*([+-]?\d+)?\s*\])?",
        )
        .unwrap()
    });
    static YARA_NUM_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"@([A-Za-z0-9_]+)\s*(?:\[\s*([+-]?\d+)?\s*\])?\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|\d+)",
        )
        .unwrap()
    });
    let mut out = expr.to_string();

    loop {
        let Some(caps) = YARA_RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let left = caps.get(1).unwrap().as_str();
        let left_delta = caps.get(2).and_then(|c| c.as_str().parse::<i64>().ok()).unwrap_or(0);
        let op = caps.get(3).unwrap().as_str();
        let right = caps.get(4).unwrap().as_str();
        let right_delta = caps.get(5).and_then(|c| c.as_str().parse::<i64>().ok()).unwrap_or(0);
        let value = relative_offsets_match(atom_hits, left, left_delta, right, right_delta, op, None);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }

    loop {
        let Some(caps) = YARA_NUM_RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let id = caps.get(1).unwrap().as_str();
        let delta = caps.get(2).and_then(|c| c.as_str().parse::<i64>().ok()).unwrap_or(0);
        let op = caps.get(3).unwrap().as_str();
        let expected = parse_int(caps.get(4).unwrap().as_str());
        let value = relative_offsets_match(atom_hits, id, delta, "", 0, op, expected);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }

    loop {
        let Some(caps) = ALIAS_RE.captures(&out) else { break };
        let m = caps.get(0).unwrap();
        let left = caps.get(1).unwrap().as_str();
        let right = caps.get(2).unwrap().as_str();
        let sign = if caps.get(3).unwrap().as_str() == "-" { -1i64 } else { 1i64 };
        let magnitude = parse_int(caps.get(4).unwrap().as_str()).unwrap_or(0) as i64;
        let value = relative_offsets_match(atom_hits, left, 0, right, sign * magnitude, "==", None);
        out.replace_range(m.start()..m.end(), bool_lit(value));
    }

    out
}

/// True when some pair of anchor positions satisfies the comparison.
/// With `expected` set the right-hand side is a literal instead of a second atom.
fn relative_offsets_match(
    atom_hits: &HashMap<String, AtomMatch>,
    left: &str,
    left_delta: i64,
    right: &str,
    right_delta: i64,
    op: &str,
    expected: Option<u64>,
) -> bool {
    let Some(hit) = atom_hits.get(left) else {
        return false;
    };
    hit.offsets.iter().any(|lo| {
        let value = *lo as i64 + left_delta;
        if value < 0 {
            return false;
        }
        match expected {
            Some(n) => compare_i64(value, op, n as i64),
            None => {
                let Some(other) = atom_hits.get(right) else {
                    return false;
                };
                other.offsets.iter().any(|ro| {
                    let candidate = *ro as i64 + right_delta;
                    candidate >= 0 && compare_i64(value, op, candidate)
                })
            }
        }
    })
}

fn compare_i64(left: i64, op: &str, right: i64) -> bool {
    match op {
        "==" => left == right,
        "!=" => left != right,
        "<" => left < right,
        "<=" => left <= right,
        ">" => left > right,
        ">=" => left >= right,
        _ => false,
    }
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
    find_byte_pattern_in(bytes, pattern, 0, bytes.len())
}

/// Resolve a [`ByteScope`] against a file size into an absolute `[start, end)` window.
/// Negative offsets count backwards from the end of the file.
fn resolve_scope(len: usize, scope: Option<&ByteScope>) -> (usize, usize) {
    let Some(scope) = scope else {
        return (0, len);
    };
    let anchor = |offset: i64| -> usize {
        if offset < 0 {
            len.saturating_sub(offset.unsigned_abs() as usize)
        } else {
            (offset as usize).min(len)
        }
    };
    let start = scope.start.map(anchor).unwrap_or(0).min(len);
    let end = scope
        .end
        .map(anchor)
        .unwrap_or(len)
        .max(start)
        .min(len);
    (start, end)
}

fn find_byte_pattern_in(
    bytes: &[u8],
    pattern: &CompiledBytePattern,
    start: usize,
    end: usize,
) -> Option<usize> {
    if start >= end {
        return None;
    }
    find_byte_pattern_unscoped(&bytes[start..end], pattern).map(|offset| offset + start)
}

fn find_byte_pattern_unscoped(bytes: &[u8], pattern: &CompiledBytePattern) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(pattern: &str) -> CompiledBytePattern {
        compile_byte_pattern(pattern).expect("pattern must compile")
    }

    fn scope(start: Option<i64>, end: Option<i64>) -> ByteScope {
        ByteScope { start, end }
    }

    #[test]
    fn scope_defaults_to_whole_file() {
        assert_eq!(resolve_scope(100, None), (0, 100));
    }

    #[test]
    fn scope_absolute_range() {
        assert_eq!(resolve_scope(100, Some(&scope(Some(10), Some(20)))), (10, 20));
    }

    #[test]
    fn scope_negative_counts_from_end() {
        // last 16 bytes
        assert_eq!(resolve_scope(100, Some(&scope(Some(-16), None))), (84, 100));
        // everything but the last 16 bytes
        assert_eq!(resolve_scope(100, Some(&scope(None, Some(-16)))), (0, 84));
    }

    #[test]
    fn scope_clamps_and_repairs_inverted_ranges() {
        assert_eq!(resolve_scope(100, Some(&scope(Some(500), Some(900)))), (100, 100));
        assert_eq!(resolve_scope(100, Some(&scope(Some(-500), None))), (0, 100));
        // end before start must not underflow the window
        assert_eq!(resolve_scope(100, Some(&scope(Some(80), Some(20)))), (80, 80));
    }

    #[test]
    fn find_in_window_respects_scope() {
        let bytes = b"AAAA-PAYLOAD-BBBB";
        let needle = pat("50 41 59 4C 4F 41 44");
        // whole file: found
        assert!(find_byte_pattern(bytes, &needle).is_some());
        // window that excludes the hit: not found
        assert!(find_byte_pattern_in(bytes, &needle, 0, 5).is_none());
        // window that contains the hit: found, offset is absolute
        let at = find_byte_pattern_in(bytes, &needle, 5, 12).expect("hit inside window");
        assert_eq!(&bytes[at..at + 7], b"PAYLOAD");
    }

    #[test]
    fn find_in_window_preserves_wildcards() {
        let bytes = b"\x4D\x5A\x90\x00\xE8";
        let needle = pat("4D 5A ?? ?? E8");
        assert_eq!(find_byte_pattern_in(bytes, &needle, 0, 5), Some(0));
        assert_eq!(find_byte_pattern_in(bytes, &needle, 1, 5), None);
    }

    #[test]
    fn exclusion_vetoes_a_matched_pattern() {
        let bytes = b"good-payload-with-known-benign-marker";
        let needle = pat("70 61 79 6C 6F 61 64");
        assert!(find_byte_pattern(bytes, &needle).is_some());
        // no exclusions configured -> no veto
        assert!(find_excluded_byte(&[], bytes).is_none());
        // exclusion present but absent from the file -> no veto
        assert!(find_excluded_byte(&["DEADBEEF".to_string()], bytes).is_none());
        // exclusion present -> veto
        let veto = find_excluded_byte(&["6B 6E 6F 77 6E".to_string()], bytes);
        assert!(veto.is_some());
        assert_eq!(&bytes[veto.unwrap()..veto.unwrap() + 5], b"known");
    }

    #[test]
    fn yaml_scope_and_excludes_deserialize() {
        let yaml = r#"
name: scope-test
version: "1.0"
rules:
  - id: T_SCOPE_0001
    title: overlay payload in last 4 KiB, unless known benign blob present
    severity: high
    verdict: malware
    conditions:
      - type: byte_pattern
        pattern: "{ 50 41 59 4C 4F 41 44 }"
        scope:
          start: -4096
        excludes:
          - "6B 6E 6F 77 6E"
      - type: byte_set
        patterns:
          - "AA BB"
          - "CC DD"
        min: 2
        scope:
          start: 0
          end: 1024
        excludes:
          - "EE FF"
"#;
        let parsed: YamlRulesFile = yaml_serde::from_str(yaml).expect("yaml must parse");
        assert_eq!(parsed.rules.len(), 1);
        let rule = &parsed.rules[0];
        assert_eq!(rule.conditions.len(), 2);

        match &rule.conditions[0] {
            RuleCondition::BytePattern {
                pattern,
                scope,
                excludes,
            } => {
                assert_eq!(pattern, "{ 50 41 59 4C 4F 41 44 }");
                assert_eq!(scope.and_then(|s| s.start), Some(-4096));
                assert_eq!(scope.and_then(|s| s.end), None);
                assert_eq!(excludes, &vec!["6B 6E 6F 77 6E".to_string()]);
            }
            other => panic!("expected BytePattern, got {other:?}"),
        }

        match &rule.conditions[1] {
            RuleCondition::ByteSet {
                patterns,
                min,
                scope,
                excludes,
            } => {
                assert_eq!(patterns.len(), 2);
                assert_eq!(*min, Some(2));
                assert_eq!(scope.and_then(|s| s.start), Some(0));
                assert_eq!(scope.and_then(|s| s.end), Some(1024));
                assert_eq!(excludes, &vec!["EE FF".to_string()]);
            }
            other => panic!("expected ByteSet, got {other:?}"),
        }
    }

    #[test]
    fn yaml_without_scope_still_deserializes() {
        let yaml = r#"
name: back-compat
rules:
  - id: T_OLD_0001
    title: legacy rule, no scope and no excludes
    severity: low
    conditions:
      - type: byte_pattern
        pattern: "4D 5A"
"#;
        let parsed: YamlRulesFile = yaml_serde::from_str(yaml).expect("legacy yaml must still parse");
        match &parsed.rules[0].conditions[0] {
            RuleCondition::BytePattern {
                pattern, scope, excludes, ..
            } => {
                assert_eq!(pattern, "4D 5A");
                assert!(scope.is_none());
                assert!(excludes.is_empty());
            }
            other => panic!("expected BytePattern, got {other:?}"),
        }
    }

    #[test]
    fn parses_generated_malware_pilot_rules() {
        let path = std::path::Path::new("../OpenMalwareScannerPortable/hydradragonsig_rules/malware_pilot_rules.yaml");
        if path.exists() {
            let ruleset = RuleSet::from_yaml_file(path).expect("malware_pilot_rules.yaml must parse cleanly");
            assert!(!ruleset.rules.is_empty(), "Generated ruleset should not be empty");
        }
    }

    fn hits(entries: &[(&str, &[usize])]) -> HashMap<String, AtomMatch> {
        entries
            .iter()
            .map(|(id, offsets)| {
                (
                    (*id).to_string(),
                    AtomMatch {
                        matched: true,
                        evidence: Vec::new(),
                        offsets: offsets.to_vec(),
                    },
                )
            })
            .collect()
    }

    fn eval_expr(expression: &str, atom_hits: &HashMap<String, AtomMatch>) -> bool {
        let report = ScanReport::default();
        evaluate_signature_expression(expression, atom_hits, &report, b"", &[])
    }

    fn eval_cond(cond: &RuleCondition, bytes: &[u8]) -> Option<String> {
        let report = ScanReport::default();
        let view = ScanView::new(&report);
        evaluate_condition(cond, &report, &view, bytes)
    }

    fn unpacker_rules() -> Vec<Rule> {
        let yaml = r#"
name: unpackers
rules:
  - id: T_UNP_0001
    title: packed with a known protector
    severity: medium
    conditions:
      - type: unpacker_any
        signatures:
          - name: UPack
            pattern: "60 E8 ?? ?? ?? ?? 5D"
          - name: ASPack
            pattern: "FF 25"
"#;
        let parsed: YamlRulesFile = yaml_serde::from_str(yaml).expect("unpacker yaml must parse");
        parsed.rules
    }
    #[test]
    fn relative_offset_alias_requires_exact_distance() {
        // $a at 0x100, $b at 0x124
        let atom_hits = hits(&[("a", &[0x100]), ("b", &[0x124])]);

        // $a at $b - 0x24 -> 0x100 == 0x124 - 0x24
        assert!(eval_expr("$a at $b - 0x24", &atom_hits));
        // $b at $a + 0x24 -> 0x124 == 0x100 + 0x24
        assert!(eval_expr("$b at $a + 0x24", &atom_hits));
        // decimal magnitude, same as the hex form
        assert!(eval_expr("$a at $b - 36", &atom_hits));
        // wrong distance in either direction
        assert!(!eval_expr("$a at $b + 0x24", &atom_hits));
        assert!(!eval_expr("$a at $b - 0x25", &atom_hits));
    }

    #[test]
    fn relative_offset_survives_repeated_occurrences() {
        // A pattern occurring many times must not lock onto the first hit only.
        let atom_hits = hits(&[("a", &[0x10, 0x100]), ("b", &[0x200, 0x124])]);

        assert!(eval_expr("$a at $b - 0x24", &atom_hits));
    }

    #[test]
    fn yara_style_anchor_offsets_match() {
        let atom_hits = hits(&[("a", &[0x128]), ("b", &[0x124])]);

        // @a[-4] == @b -> 0x124 == 0x124
        assert!(eval_expr("@a[-4] == @b", &atom_hits));
        // @a[4] == @b -> 0x12c != 0x124
        assert!(!eval_expr("@a[4] == @b", &atom_hits));
        assert!(eval_expr("@a < 0x200", &atom_hits));
        assert!(eval_expr("@a >= 0x128", &atom_hits));
        assert!(!eval_expr("@a > 0x128", &atom_hits));
    }

    #[test]
    fn relative_offset_is_false_when_an_atom_did_not_match() {
        let atom_hits = hits(&[("a", &[0x100])]);

        assert!(!eval_expr("$a at $b + 0x24", &atom_hits));
    }

    #[test]
    fn relative_offset_composes_with_boolean_operators() {
        let atom_hits = hits(&[("a", &[0x100]), ("b", &[0x124])]);

        assert!(eval_expr("$a and $a at $b - 0x24", &atom_hits));
        assert!(eval_expr("($a at $b - 0x24) and ($b at $a + 0x24)", &atom_hits));
        assert!(!eval_expr("($a at $b - 0x24) and ($b at $a - 0x24)", &atom_hits));
    }

    #[test]
    fn unpacker_any_reports_the_first_matching_packer() {
        let parsed = unpacker_rules();
        let RuleCondition::UnpackerAny { signatures } = &parsed[0].conditions[0] else {
            panic!("expected UnpackerAny, got {:?}", parsed[0].conditions[0]);
        };
        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0].name, "UPack");

        let mut data = vec![0u8; 0x40];
        data.extend_from_slice(&[0x60, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x5D]);
        data.resize(0x100, 0);

        let matched = eval_cond(&parsed[0].conditions[0], &data)
            .expect("UPack pattern must match");
        assert!(matched.contains("UPack"), "evidence should name the packer: {matched}");
    }

    #[test]
    fn unpacker_any_does_not_match_clean_bytes() {
        let parsed = unpacker_rules();

        assert!(eval_cond(&parsed[0].conditions[0], &[0u8; 0x100]).is_none());
    }

    #[test]
    fn unpacker_any_ignores_signatures_with_a_bad_pattern() {        let parsed = unpacker_rules();

        let mut data = vec![0xFF, 0x25];
        data.resize(0x100, 0);

        assert!(eval_cond(&parsed[0].conditions[0], &data)
            .expect("second, valid signature must still match")
            .contains("ASPack"));
    }



    fn logo_png() -> Option<Vec<u8>> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/logo.png"
        ))
        .ok()
    }

    fn image_hash_rules(max_distance: Option<u32>) -> Vec<Rule> {
        let dist = match max_distance {
            Some(d) => format!("max_distance: {d}"),
            None => String::new(),
        };
        let yaml = format!(
            r#"
name: image-hashes
rules:
  - id: T_IMG_0001
    title: known artwork
    severity: low
    conditions:
      - type: image_fuzzy_hash_any
        hashes:
          - af2ad01ed42993c7
          - "fuzzy_img#0000000000000000"
        {dist}
"#
        );
        let parsed: YamlRulesFile = yaml_serde::from_str(&yaml).expect("image hash yaml must parse");
        parsed.rules
    }

    #[test]
    fn image_fuzzy_hash_matches_clamav_reference_image() {
        let Some(data) = logo_png() else { return };
        let parsed = image_hash_rules(None);

        let evidence = eval_cond(&parsed[0].conditions[0], &data)
            .expect("logo.png must match its own pHash");

        assert!(
            evidence.contains("af2ad01ed42993c7"),
            "evidence must name the matched hash: {evidence}"
        );
        assert!(
            evidence.contains("within 0 bit"),
            "exact match must report a distance of 0: {evidence}"
        );
    }

    #[test]
    fn image_fuzzy_hash_rejects_non_images() {
        let parsed = image_hash_rules(Some(64));

        let mut pe = vec![0u8; 0x400];
        pe[0] = b'M';
        pe[1] = b'Z';
        assert!(eval_cond(&parsed[0].conditions[0], &pe).is_none());
    }

    #[test]
    fn image_fuzzy_hash_respects_max_distance() {
        let Some(data) = logo_png() else { return };
        // A hash 1 bit away from the real one: must be rejected at distance 0
        // and accepted once tolerance is raised.
        let one_bit_off = "af2ad01ed42993c6";
        let yaml = |d: &str| {
            format!(
                r#"
name: image-hashes
rules:
  - id: T_IMG_0002
    title: known artwork
    severity: low
    conditions:
      - type: image_fuzzy_hash_any
        hashes:
          - {one_bit_off}
        {d}
"#
            )
        };

        let exact: YamlRulesFile = yaml_serde::from_str(&yaml("max_distance: 0")).unwrap();
        assert!(eval_cond(&exact.rules[0].conditions[0], &data).is_none());

        let tolerant: YamlRulesFile = yaml_serde::from_str(&yaml("max_distance: 1")).unwrap();
        let evidence = eval_cond(&tolerant.rules[0].conditions[0], &data)
            .expect("a single differing bit must be tolerated at max_distance 1");
        assert!(evidence.contains("within 1 bit"), "{evidence}");
    }



    fn icon_rules(idb_line: &str) -> Vec<Rule> {
        let idb_block = if idb_line.is_empty() {
            String::new()
        } else {
            format!("          - \"{idb_line}\"\n")
        };
        let yaml = format!(
            r#"
name: pe-icon
rules:
  - id: T_ICON_0001
    title: icon fingerprint
    severity: low
    conditions:
      - type: pe_icon_any
        dhash: ["0000000000000000"]
        dhash_max_distance: 0
        idb:
{idb_block}"#
        );
        let parsed: YamlRulesFile = yaml_serde::from_str(&yaml).expect("pe_icon yaml must parse");
        parsed.rules
    }

    #[test]
    fn pe_icon_matches_via_idb_fingerprint() {
        let Ok(bytes) = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/unit_tests/input/pe_allmatch/test.exe"
        )) else {
            return;
        };
        let idb = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/unit_tests/input/pe_allmatch/weak-sigs/sig00.idb"
        ))
        .unwrap();
        let idb_line = idb.lines().next().unwrap().trim().to_string();
        let rules = icon_rules(&idb_line);

        let evidence = eval_cond(&rules[0].conditions[0], &bytes)
            .expect("test.exe must match its own .idb fingerprint");
        assert!(evidence.contains("IDB_16x16x32"), "{evidence}");
        assert!(evidence.contains("confidence"), "{evidence}");
    }

    #[test]
    fn pe_icon_does_not_match_without_the_right_group() {
        let Ok(bytes) = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../clamav/unit_tests/input/pe_allmatch/test.exe")) else { return };
        let idb_line = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/unit_tests/input/pe_allmatch/weak-sigs/sig00.idb"
        )).unwrap().lines().next().unwrap().trim().to_string();

        // A fingerprint that is present, but the rule only accepts a group the
        // signature is not in.
        let yaml = format!(
            r#"
name: pe-icon
rules:
  - id: T_ICON_0002
    title: wrong group
    severity: low
    conditions:
      - type: pe_icon_any
        dhash: []
        idb:
          - \"{idb_line}\"
        idb_groups: [SOME_OTHER_GROUP]
"#
        );
        let parsed: YamlRulesFile = yaml_serde::from_str(&yaml).expect("must parse");
        assert!(eval_cond(&parsed.rules[0].conditions[0], &bytes).is_none());
    }

    #[test]
    fn pe_icon_ignores_a_non_pe() {
        let rules = icon_rules("nonsense");
        assert!(eval_cond(&rules[0].conditions[0], b"just some text").is_none());
    }


}
