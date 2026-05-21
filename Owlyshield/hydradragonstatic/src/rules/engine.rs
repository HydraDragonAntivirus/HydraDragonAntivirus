use super::types::*;
use crate::models::{Finding, RulePerformance, ScanReport, Verdict};
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use rayon::prelude::*;
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
        // Aggressive limits for blazing fast performance
        let string_limit = report.strings.len().min(2000);
        let decoded_limit = report.decoded_strings.len().min(500);
        
        // Use parallel processing for large string sets
        let strings_lower: Vec<String> = if report.strings.len() > 1000 {
            report
                .strings
                .par_iter()
                .take(string_limit)
                .map(|hit| hit.value.to_ascii_lowercase())
                .collect()
        } else {
            report
                .strings
                .iter()
                .take(string_limit)
                .map(|hit| hit.value.to_ascii_lowercase())
                .collect()
        };
        
        let decoded_lower: Vec<String> = report
            .decoded_strings
            .iter()
            .take(decoded_limit)
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
static BYTE_PATTERN_CACHE: Lazy<Mutex<HashMap<String, Arc<Vec<ByteToken>>>>> =
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

fn cached_byte_pattern(pattern: &str) -> Option<Arc<Vec<ByteToken>>> {
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
        for rule in &file.rules {
            warm_rule_caches(rule);
        }
        Ok(Self { rules: file.rules })
    }

    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read rule file {}", path.display()))?;
        Self::from_yaml_str(&yaml)
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
        for (index, rule) in self.rules.iter().enumerate() {
            let result = evaluate_one_rule(index, rule, report, view, bytes, options.profile_rules);
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
            // Rayon may evaluate some later rules speculatively, but only the first ordered hit is kept.
            let first = {
                let report_ref: &ScanReport = &*report;
                self.rules
                    .par_iter()
                    .enumerate()
                    .find_map_first(|(index, rule)| {
                        let result = evaluate_one_rule(
                            index,
                            rule,
                            report_ref,
                            view,
                            bytes,
                            options.profile_rules,
                        );
                        result.finding.is_some().then_some(result)
                    })
            };
            if let Some(result) = first {
                push_rule_eval_result(report, result);
            }
            return;
        }

        let mut results: Vec<_> = {
            let report_ref: &ScanReport = &*report;
            self.rules
                .par_iter()
                .enumerate()
                .map(|(index, rule)| {
                    evaluate_one_rule(index, rule, report_ref, view, bytes, options.profile_rules)
                })
                .collect()
        };
        results.sort_by_key(|result| result.index);
        for result in results {
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
                        SignatureAtomKind::Text => {}
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
struct RuleEvalResult {
    index: usize,
    finding: Option<Finding>,
    performance: Option<RulePerformance>,
}

fn evaluate_one_rule(
    index: usize,
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

    let finding = result.map(|evidence| Finding {
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
    });

    RuleEvalResult {
        index,
        finding,
        performance,
    }
}

fn push_rule_eval_result(report: &mut ScanReport, result: RuleEvalResult) {
    if let Some(performance) = result.performance {
        report.rule_performance.push(performance);
    }
    if let Some(finding) = result.finding {
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
        } => {
            if *nocase {
                let needle = value.to_ascii_lowercase();
                for (hit, hay) in report.strings.iter().zip(&view.strings_lower) {
                    if hay.contains(&needle) {
                        return Some(format!("string_contains `{}` at 0x{:x}", value, hit.offset));
                    }
                }
                if *decoded {
                    for (hit, hay) in report.decoded_strings.iter().zip(&view.decoded_lower) {
                        if hay.contains(&needle) {
                            return Some(format!(
                                "decoded_string_contains `{}` via {}",
                                value, hit.method
                            ));
                        }
                    }
                }
            } else {
                for hit in &report.strings {
                    if hit.value.contains(value) {
                        return Some(format!("string_contains `{}` at 0x{:x}", value, hit.offset));
                    }
                }
                if *decoded {
                    for hit in &report.decoded_strings {
                        if hit.decoded.contains(value) {
                            return Some(format!(
                                "decoded_string_contains `{}` via {}",
                                value, hit.method
                            ));
                        }
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
        } => {
            let needed = min.unwrap_or(1).max(1);
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
            find_byte_pattern(bytes, compiled.as_slice())
                .map(|offset| format!("byte_pattern `{}` at 0x{:x}", pattern, offset))
        }
        RuleCondition::ByteSet { patterns, min } => {
            let needed = min.unwrap_or(1).max(1);
            let mut evidence = Vec::new();
            for pattern in patterns {
                if let Some(compiled) = cached_byte_pattern(pattern) {
                    if let Some(offset) = find_byte_pattern(bytes, compiled.as_slice()) {
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

fn match_signature_atom(
    report: &ScanReport,
    view: &ScanView,
    bytes: &[u8],
    atom: &SignatureAtom,
) -> AtomMatch {
    match atom.kind {
        SignatureAtomKind::Text => match_text_atom(report, view, bytes, atom),
        SignatureAtomKind::Regex => match_regex_atom(report, atom),
        SignatureAtomKind::Bytes => match_byte_atom(bytes, atom),
    }
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
        let (lo, hi) = xor_key_range(atom);
        for key in lo..=hi {
            for (label, plain) in text_atom_plain_xor_variants(atom) {
                let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
                if let Some(offset) = find_bytes(bytes, &encoded, atom.fullword) {
                    out.matched = true;
                    out.offsets.push(offset);
                    out.evidence.push(format!(
                        "${} xor(0x{:02x}) {} text `{}` at 0x{:x}",
                        atom.id,
                        key,
                        label,
                        truncate_for_evidence(&atom.value, 80),
                        offset
                    ));
                    return out;
                }
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
        if let Some(offset) = find_byte_pattern(bytes, pattern.as_slice()) {
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
            for key in lo..=hi {
                let xored: Vec<ByteToken> = pattern
                    .iter()
                    .map(|token| ByteToken {
                        value: token.value ^ key,
                        mask: token.mask,
                    })
                    .collect();
                if let Some(offset) = find_byte_pattern(bytes, &xored) {
                    out.matched = true;
                    out.offsets.push(offset);
                    out.evidence.push(format!(
                        "${} xor(0x{:02x}) bytes `{}` at 0x{:x}",
                        atom.id,
                        key,
                        truncate_for_evidence(&atom.value, 80),
                        offset
                    ));
                    return out;
                }
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

fn xor_key_range(atom: &SignatureAtom) -> (u8, u8) {
    let lo = atom.xor_min.unwrap_or(1);
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
    for i in 0..=hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle
            && (!fullword || byte_word_boundary_at(hay, i, needle.len()))
        {
            return Some(i);
        }
    }
    None
}

fn find_bytes_nocase_ascii(hay: &[u8], needle: &[u8], fullword: bool) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    for i in 0..=hay.len() - needle_lower.len() {
        if hay[i..i + needle_lower.len()]
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .eq(needle_lower.iter().copied())
            && (!fullword || byte_word_boundary_at(hay, i, needle_lower.len()))
        {
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

fn compile_byte_pattern(pattern: &str) -> Option<Vec<ByteToken>> {
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

    (!out.is_empty()).then_some(out)
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

fn find_byte_pattern(bytes: &[u8], pattern: &[ByteToken]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > bytes.len() {
        return None;
    }

    // Fast path: use the first exact byte as an anchor instead of checking every window.
    // Wildcard-only patterns fall back to the generic matcher.
    if let Some((anchor_index, anchor)) = pattern
        .iter()
        .enumerate()
        .find(|(_, token)| token.mask == 0xff)
    {
        let mut pos = anchor_index;
        while pos < bytes.len() {
            if bytes[pos] == anchor.value {
                let start = pos.saturating_sub(anchor_index);
                if start + pattern.len() <= bytes.len()
                    && byte_window_matches(&bytes[start..start + pattern.len()], pattern)
                {
                    return Some(start);
                }
            }
            pos += 1;
        }
        return None;
    }

    bytes
        .windows(pattern.len())
        .position(|window| byte_window_matches(window, pattern))
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

    // Important: intentionally signature-like. One matched rule with verdict=malware is enough.
    report.verdict = if report
        .findings
        .iter()
        .any(|f| f.verdict == Verdict::Malware)
    {
        Verdict::Malware
    } else if report
        .findings
        .iter()
        .any(|f| f.verdict == Verdict::Suspicious)
    {
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

#[allow(dead_code)]
static _REGEX_COMPILE_GUARD: Lazy<Regex> = Lazy::new(|| Regex::new(".*").unwrap());
