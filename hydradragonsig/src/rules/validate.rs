//! Load-time checks of YAML rule files.
//!
//! Serde accepts unknown keys and the engine used to discover bad regexes or byte
//! patterns only at scan time, where the condition then silently never matched.
//! These checks report such problems when the rules are loaded:
//! [`RuleSet::from_yaml_str`](super::RuleSet::from_yaml_str) keeps the rules and
//! lists the problems in `warnings()`, [`RuleSet::from_yaml_str_strict`] refuses
//! the document.

use super::engine::{byte_pattern_problem, validate_signature_expression};
use super::types::*;
use std::collections::HashSet;

const FILE_KEYS: &[&str] = &["name", "version", "rules"];
const RULE_KEYS: &[&str] = &[
    "id", "title", "description", "severity", "verdict", "confidence", "family", "score", "tags", "mitre", "private",
    "logic", "threshold", "conditions", "file_path", "required_path",
];
const MITRE_KEYS: &[&str] = &["id", "name", "tactic"];
const ATOM_KEYS: &[&str] = &[
    "id", "kind", "value", "nocase", "decoded", "wide", "ascii", "fullword", "xor", "xor_min", "xor_max", "base64",
    "base64wide",
];
const SCOPE_KEYS: &[&str] = &["start", "end"];
const UNPACKER_KEYS: &[&str] = &["name", "pattern"];

/// Keys of every condition type (besides `type`).
pub const CONDITION_KEYS: &[(&str, &[&str])] = &[
    ("string_contains", &["value", "nocase", "decoded", "ascii", "wide", "utf8", "utf16"]),
    ("string_regex", &["pattern", "decoded"]),
    ("string_set", &["values", "min", "nocase", "decoded", "regex", "ascii", "wide", "utf8", "utf16"]),
    ("native_signature", &["atoms", "expression"]),
    ("import_any", &["names"]),
    ("import_all", &["names"]),
    ("import_set", &["names", "min"]),
    ("import_regex", &["pattern"]),
    ("export_any", &["names"]),
    ("export_all", &["names"]),
    ("export_set", &["names", "min"]),
    ("dll_any", &["names"]),
    ("dll_regex", &["pattern"]),
    ("suspicious_import_count", &["min"]),
    ("file_entropy", &["min"]),
    ("file_size_gte", &["bytes"]),
    ("file_size_lte", &["bytes"]),
    ("section_entropy", &["min"]),
    ("section_name_regex", &["pattern"]),
    ("packed_pe", &[]),
    ("env_reference", &["min"]),
    ("path_regex", &["pattern"]),
    ("file_type", &["values"]),
    ("hash_sha256", &["value"]),
    ("hash_md5", &["value"]),
    ("imphash_any", &["values"]),
    ("feature_gte", &["name", "value"]),
    ("feature_lte", &["name", "value"]),
    ("has_parent", &[]),
    ("parent_feature_gte", &["name", "value"]),
    ("parent_feature_lte", &["name", "value"]),
    ("feature_delta_gte", &["name", "value"]),
    ("new_import_set", &["names", "min"]),
    ("byte_pattern", &["pattern", "scope", "excludes"]),
    ("byte_set", &["patterns", "min", "scope", "excludes"]),
    ("rule_match", &["ids", "min"]),
    ("unpacker_any", &["signatures"]),
    ("image_fuzzy_hash_any", &["hashes", "max_distance"]),
    ("pe_icon_any", &["dhash", "dhash_max_distance", "phash", "phash_max_distance", "idb", "idb_groups"]),
];

/// Values accepted by `file_type` conditions.
pub const FILE_TYPES: &[&str] = &[
    "pe", "exe", "dll", "sys", "pe32", "pe64", "broken_pe", "elf", "elf32", "elf64", "broken_elf", "macho", "mach_o",
    "broken_macho", "apk", "android", "broken_apk", "zip", "archive", "7z", "rar", "gzip", "gz", "tar", "asar", "jar",
    "java", "dex", "java_class", "class", "text", "plain", "plain_text", "txt", "script", "powershell", "ps1", "batch",
    "bat", "cmd", "javascript", "js", "vbs", "python", "py", "shell", "pdf", "office", "openxml", "ole", "compound",
    "microsoft_compound", "binary", "unknown", "broken", "broken_executable",
];

/// Names `feature_gte` can read.
pub const FEATURES: &[&str] = &[
    "string_count",
    "decoded_string_count",
    "env_hit_count",
    "file_entropy_bits_per_byte",
    "pe_import_count",
    "pe_export_count",
    "pe_section_count",
    "pe_suspicious_import_count",
];

/// Features a parent summary always carries (`ParentInfo::from_bytes`).
pub const PARENT_FEATURES: &[&str] = &[
    "file_entropy_bits_per_byte",
    "pe_import_count",
    "pe_export_count",
    "pe_section_count",
    "pe_suspicious_import_count",
];

/// Unknown keys anywhere in the document (typos are otherwise ignored by serde).
pub fn unknown_keys(yaml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(doc) = yaml_serde::from_str::<yaml_serde::Value>(yaml) else {
        return out;
    };
    check_keys(&doc, FILE_KEYS, "file", &mut out);
    let Some(rules) = doc.get("rules").and_then(|r| r.as_sequence()) else {
        return out;
    };
    for (i, rule) in rules.iter().enumerate() {
        let rid = rule.get("id").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("#{}", i + 1));
        let at = format!("rule {rid}");
        check_keys(rule, RULE_KEYS, &at, &mut out);
        for m in rule.get("mitre").and_then(|v| v.as_sequence()).into_iter().flatten() {
            check_keys(m, MITRE_KEYS, &format!("{at} mitre"), &mut out);
        }
        for (ci, cond) in rule.get("conditions").and_then(|v| v.as_sequence()).into_iter().flatten().enumerate() {
            let ctype = cond.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let cat = format!("{at} condition {} ({ctype})", ci + 1);
            let Some((_, keys)) = CONDITION_KEYS.iter().find(|(t, _)| *t == ctype) else {
                continue; // serde reports the unknown type
            };
            let mut allowed: Vec<&str> = keys.to_vec();
            allowed.push("type");
            check_keys(cond, &allowed, &cat, &mut out);
            if let Some(scope) = cond.get("scope") {
                check_keys(scope, SCOPE_KEYS, &format!("{cat} scope"), &mut out);
            }
            for atom in cond.get("atoms").and_then(|v| v.as_sequence()).into_iter().flatten() {
                check_keys(atom, ATOM_KEYS, &format!("{cat} atom"), &mut out);
            }
            for sig in cond.get("signatures").and_then(|v| v.as_sequence()).into_iter().flatten() {
                check_keys(sig, UNPACKER_KEYS, &format!("{cat} signature"), &mut out);
            }
        }
    }
    out
}

fn check_keys(v: &yaml_serde::Value, allowed: &[&str], at: &str, out: &mut Vec<String>) {
    let Some(map) = v.as_mapping() else { return };
    for key in map.keys() {
        let k = key.as_str().unwrap_or("<non-string key>");
        if !allowed.contains(&k) {
            out.push(format!("{at}: unknown key `{k}` (ignored)"));
        }
    }
}

/// Problems in the parsed rules. `known_ids` holds the ids of rules loaded before
/// this document (for `rule_match`).
pub fn check_rules(rules: &[Rule], known_ids: &HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for rule in rules {
        let at = format!("rule {}", rule.id);
        let mut p = |msg: String| out.push(format!("{at}: {msg}"));
        if rule.id.trim().is_empty() {
            p("empty id".into());
        }
        if !seen.insert(rule.id.as_str()) || known_ids.contains(&rule.id) {
            p("duplicate id".into());
        }
        if rule.conditions.is_empty() {
            p("no conditions: the rule never matches".into());
        }
        if rule.confidence > 100 {
            p(format!("confidence {} is above 100", rule.confidence));
        }
        match rule.logic {
            RuleLogic::Threshold => match rule.threshold {
                None => p("logic: threshold needs a `threshold` value".into()),
                Some(0) => p("threshold must be at least 1".into()),
                Some(n) if n > rule.conditions.len() => {
                    p(format!("threshold {n} is larger than the {} condition(s): never matches", rule.conditions.len()))
                }
                _ => {}
            },
            _ if rule.threshold.is_some() => p("`threshold` is only used with logic: threshold".into()),
            _ => {}
        }
        for (ci, cond) in rule.conditions.iter().enumerate() {
            for problem in check_condition(cond, rules, &rule.id, known_ids) {
                p(format!("condition {}: {problem}", ci + 1));
            }
        }
    }
    out
}

fn regex_problem(pattern: &str) -> Option<String> {
    regex::Regex::new(pattern).err().map(|e| format!("invalid regex `{pattern}`: {e}"))
}

fn byte_problem(pattern: &str) -> Option<String> {
    byte_pattern_problem(pattern).map(|e| format!("invalid byte pattern `{pattern}`: {e}"))
}

fn list_problems<T: AsRef<str>>(what: &str, items: &[T], min: Option<usize>, out: &mut Vec<String>) {
    if items.is_empty() {
        out.push(format!("empty `{what}` list: never matches"));
    }
    if items.iter().any(|v| v.as_ref().is_empty()) {
        out.push(format!("empty entry in `{what}`"));
    }
    if let Some(m) = min {
        if m == 0 {
            out.push("min: 0 is treated as 1".into());
        } else if m > items.len() {
            out.push(format!("min {m} is larger than the {} entries: never matches", items.len()));
        }
    }
}

fn hex_len(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn check_condition(cond: &RuleCondition, rules: &[Rule], own_id: &str, known_ids: &HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    match cond {
        RuleCondition::StringContains { value, ascii, wide, utf8, utf16, .. } => {
            if value.is_empty() {
                out.push("empty `value`".into());
            }
            if !ascii && !wide && !utf8 && !utf16 {
                out.push("ascii, wide, utf8 and utf16 are all off: never matches".into());
            }
        }
        RuleCondition::StringRegex { pattern, .. } => out.extend(regex_problem(pattern)),
        RuleCondition::StringSet { values, min, regex, ascii, wide, utf8, utf16, nocase, .. } => {
            list_problems("values", values, *min, &mut out);
            if *regex {
                for v in values {
                    let pat = if *nocase { format!("(?i){v}") } else { v.clone() };
                    out.extend(regex_problem(&pat));
                }
            } else if !ascii && !wide && !utf8 && !utf16 {
                out.push("ascii, wide, utf8 and utf16 are all off: never matches".into());
            }
        }
        RuleCondition::NativeSignature { atoms, expression } => {
            let mut ids = HashSet::new();
            for atom in atoms {
                if atom.id.is_empty() || !atom.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    out.push(format!("atom id `{}`: use letters, digits and `_`", atom.id));
                }
                if !ids.insert(atom.id.as_str()) {
                    out.push(format!("duplicate atom id `{}`", atom.id));
                }
                if atom.value.is_empty() {
                    out.push(format!("atom `{}` has an empty value", atom.id));
                }
                match atom.kind {
                    SignatureAtomKind::Regex => {
                        let pat = if atom.nocase { format!("(?i){}", atom.value) } else { atom.value.clone() };
                        out.extend(regex_problem(&pat).map(|e| format!("atom `{}`: {e}", atom.id)));
                    }
                    SignatureAtomKind::Bytes => {
                        out.extend(byte_problem(&atom.value).map(|e| format!("atom `{}`: {e}", atom.id)));
                        if atom.xor && atom.value.contains(['(', '[', '~']) {
                            out.push(format!("atom `{}`: xor works only on fixed-width byte patterns", atom.id));
                        }
                    }
                    SignatureAtomKind::Text => {}
                }
            }
            if let Err(e) = validate_signature_expression(expression, atoms) {
                out.push(format!("expression: {e}"));
            }
        }
        RuleCondition::ImportAny { names } | RuleCondition::ImportAll { names } => list_problems("names", names, None, &mut out),
        RuleCondition::ImportSet { names, min } | RuleCondition::ExportSet { names, min } => {
            list_problems("names", names, *min, &mut out)
        }
        RuleCondition::ExportAny { names } | RuleCondition::ExportAll { names } | RuleCondition::DllAny { names } => {
            list_problems("names", names, None, &mut out)
        }
        RuleCondition::ImportRegex { pattern }
        | RuleCondition::DllRegex { pattern }
        | RuleCondition::SectionNameRegex { pattern }
        | RuleCondition::PathRegex { pattern } => out.extend(regex_problem(pattern)),
        RuleCondition::PeSection {
            name_regex,
            flags_all,
            flags_none,
            entropy_min,
            entropy_max,
            raw_size_min,
            raw_size_max,
            code_xrefs_min,
            has_entry,
            directories_any,
            directories_none,
            directory_share_max,
            ..
        } => {
            if let Some(p) = name_regex {
                out.extend(regex_problem(p));
            }
            for f in flags_all.iter().chain(flags_none) {
                if super::pe_section::flag_value(f).is_none() {
                    let names: Vec<&str> = super::pe_section::FLAGS.iter().map(|(n, _)| *n).collect();
                    out.push(format!("unknown section flag `{f}` (known: {})", names.join(", ")));
                }
            }
            if let Some(m) = directory_share_max {
                if !(0.0..=1.0).contains(m) {
                    out.push(format!("directory_share_max {m} is outside 0..1"));
                }
                if directories_any.is_empty() {
                    out.push("directory_share_max needs directories_any".into());
                }
            }
            for d in directories_any.iter().chain(directories_none) {
                if super::pe_section::directory_index(d).is_none() {
                    out.push(format!("unknown data directory `{d}` (known: {})", super::pe_section::DIRECTORIES.join(", ")));
                }
            }
            for e in [entropy_min, entropy_max].into_iter().flatten() {
                if !(0.0..=8.0).contains(e) {
                    out.push(format!("entropy {e} is outside 0..8"));
                }
            }
            if code_xrefs_min == &Some(0) {
                out.push("code_xrefs_min: 0 always holds".into());
            }
            let empty = name_regex.is_none()
                && flags_all.is_empty()
                && flags_none.is_empty()
                && entropy_min.is_none()
                && entropy_max.is_none()
                && raw_size_min.is_none()
                && raw_size_max.is_none()
                && code_xrefs_min.is_none()
                && has_entry.is_none()
                && directories_any.is_empty()
                && directories_none.is_empty();
            if empty {
                out.push("pe_section without any property matches every PE".into());
            }
        }
        RuleCondition::SuspiciousImportCount { min } if *min == 0 => {
            out.push("min: 0 matches every PE".into());
        }
        RuleCondition::FileEntropy { min } | RuleCondition::SectionEntropy { min } if !(0.0..=8.0).contains(min) => {
            out.push(format!("entropy {min} is outside 0..8"));
        }
        RuleCondition::FileType { values } => {
            list_problems("values", values, None, &mut out);
            for v in values {
                let mut norm = String::new();
                for ch in v.trim().chars() {
                    if ch.is_ascii_alphanumeric() {
                        norm.push(ch.to_ascii_lowercase());
                    } else if !norm.ends_with('_') {
                        norm.push('_');
                    }
                }
                let norm = norm.trim_matches('_').to_string();
                if !FILE_TYPES.contains(&norm.as_str()) {
                    out.push(format!("unknown file type `{v}`"));
                }
            }
        }
        RuleCondition::HashSha256 { value } if !hex_len(value.trim(), 64) => out.push("sha256 must be 64 hex characters".into()),
        RuleCondition::HashMd5 { value } if !hex_len(value.trim(), 32) => out.push("md5 must be 32 hex characters".into()),
        RuleCondition::ImphashAny { values } => {
            list_problems("values", values, None, &mut out);
            for v in values.iter().filter(|v| !hex_len(v.trim(), 32)) {
                out.push(format!("imphash `{v}` must be 32 hex characters"));
            }
        }
        RuleCondition::FeatureGte { name, .. }
        | RuleCondition::FeatureLte { name, .. }
        | RuleCondition::FeatureDeltaGte { name, .. }
            if !FEATURES.contains(&name.as_str()) =>
        {
            out.push(format!("unknown feature `{name}` (known: {})", FEATURES.join(", ")));
        }
        RuleCondition::ParentFeatureGte { name, .. } | RuleCondition::ParentFeatureLte { name, .. }
            if !PARENT_FEATURES.contains(&name.as_str()) =>
        {
            out.push(format!("unknown parent feature `{name}` (known: {})", PARENT_FEATURES.join(", ")));
        }
        RuleCondition::NewImportSet { names, min } => list_problems("names", names, *min, &mut out),
        RuleCondition::FeatureGte { name, .. } if !FEATURES.contains(&name.as_str()) => {
            out.push(format!("unknown feature `{name}` (known: {})", FEATURES.join(", ")));
        }
        RuleCondition::BytePattern { pattern, excludes, .. } => {
            out.extend(byte_problem(pattern));
            out.extend(excludes.iter().filter_map(|e| byte_problem(e)));
        }
        RuleCondition::ByteSet { patterns, min, excludes, .. } => {
            list_problems("patterns", patterns, *min, &mut out);
            out.extend(patterns.iter().filter_map(|e| byte_problem(e)));
            out.extend(excludes.iter().filter_map(|e| byte_problem(e)));
        }
        RuleCondition::RuleMatch { ids, min } => {
            list_problems("ids", ids, *min, &mut out);
            let own_pos = rules.iter().position(|r| r.id == own_id).unwrap_or(usize::MAX);
            for id in ids {
                if id == own_id {
                    out.push("a rule cannot match itself".into());
                    continue;
                }
                let earlier = known_ids.contains(id) || rules.iter().position(|r| &r.id == id).is_some_and(|p| p < own_pos);
                if !earlier {
                    out.push(format!("rule_match `{id}`: no rule with this id comes before this one"));
                }
            }
        }
        RuleCondition::UnpackerAny { signatures } => {
            if signatures.is_empty() {
                out.push("empty `signatures` list: never matches".into());
            }
            out.extend(signatures.iter().filter_map(|s| byte_problem(&s.pattern)));
        }
        RuleCondition::ImageFuzzyHashAny { hashes, .. } => {
            list_problems("hashes", hashes, None, &mut out);
            for h in hashes {
                let t = h.trim();
                let body = if t.starts_with("fuzzy_img#") { t.to_string() } else { format!("fuzzy_img#{t}") };
                if let Err(e) = crate::fuzzy::parse_fuzzy_img(&body) {
                    out.push(format!("image hash `{h}`: {e}"));
                }
            }
        }
        RuleCondition::PeIconAny { dhash, phash, idb, .. } => {
            if dhash.is_empty() && phash.is_empty() && idb.is_empty() {
                out.push("no dhash, phash or idb given: never matches".into());
            }
            for h in dhash {
                let hex = h.trim().strip_prefix("dhash#").unwrap_or(h.trim());
                if !hex_len(hex, 16) {
                    out.push(format!("dhash `{h}` must be 16 hex characters"));
                }
            }
            for h in phash {
                let t = h.trim();
                let body = if t.starts_with("fuzzy_img#") { t.to_string() } else { format!("fuzzy_img#{t}") };
                if let Err(e) = crate::fuzzy::parse_fuzzy_img(&body) {
                    out.push(format!("phash `{h}`: {e}"));
                }
            }
            for line in idb {
                if let Err(e) = crate::rules::icon_metric::parse_idb_line(line) {
                    out.push(format!("idb `{line}`: {e}"));
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every condition type in the key table deserializes, so the table and
    /// `RuleCondition` stay in step.
    #[test]
    fn condition_key_table_matches_types() {
        for (ctype, _) in CONDITION_KEYS {
            let yaml = format!("rules:\n  - id: T\n    title: t\n    severity: low\n    conditions:\n      - type: {ctype}\n{}", sample_fields(ctype));
            let parsed: Result<YamlRulesFile, _> = yaml_serde::from_str(&yaml);
            assert!(parsed.is_ok(), "{ctype}: {:?}", parsed.err());
        }
    }

    fn sample_fields(ctype: &str) -> &'static str {
        match ctype {
            "string_contains" | "hash_sha256" | "hash_md5" => "        value: x\n",
            "string_regex" | "import_regex" | "dll_regex" | "section_name_regex" | "path_regex" | "byte_pattern" => "        pattern: x\n",
            "string_set" | "file_type" | "imphash_any" => "        values: [x]\n",
            "native_signature" => "        atoms: []\n        expression: x\n",
            "suspicious_import_count" | "file_entropy" | "section_entropy" => "        min: 1\n",
            "file_size_gte" | "file_size_lte" => "        bytes: 1\n",
            "feature_gte" | "feature_lte" | "parent_feature_gte" | "parent_feature_lte" | "feature_delta_gte" => {
                "        name: x\n        value: 1\n"
            }
            "byte_set" => "        patterns: [x]\n",
            "rule_match" => "        ids: [x]\n",
            "unpacker_any" => "        signatures: []\n",
            "image_fuzzy_hash_any" => "        hashes: []\n",
            "packed_pe" | "env_reference" | "pe_icon_any" | "has_parent" => "",
            _ => "        names: [x]\n",
        }
    }
}
