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
    "logic", "threshold", "conditions", "file_path", "required_path", "remediation",
];
const MITRE_KEYS: &[&str] = &["id", "name", "tactic"];
const ATOM_KEYS: &[&str] = &[
    "id", "kind", "value", "nocase", "decoded", "wide", "ascii", "fullword", "xor", "xor_min", "xor_max", "base64",
    "base64wide",
];
const SCOPE_KEYS: &[&str] = &["start", "end"];
const UNPACKER_KEYS: &[&str] = &["name", "pattern"];
const STEP_KEYS: &[&str] = &["api", "pattern"];
const BOUND_KEYS: &[&str] = &["feature", "min", "max"];

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
    ("pe_section", &[
        "select", "index", "name", "name_regex", "flags_all", "flags_none", "characteristics", "entropy_min", "entropy_max",
        "raw_size", "raw_size_min", "raw_size_max", "raw_offset", "virtual_address", "virtual_size", "virtual_size_min",
        "virtual_size_max", "md5", "sha1", "sha256", "crc32", "code_xrefs_min", "has_entry", "directories_any",
        "directories_none", "directory_share_max",
    ]),
    ("packed_pe", &[]),
    ("env_reference", &["min"]),
    ("path_regex", &["pattern"]),
    ("file_type", &["values"]),
    ("hash_sha256", &["value"]),
    ("hash_md5", &["value"]),
    ("hash_sha1", &["value"]),
    ("hash_crc32", &["value"]),
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
    ("emulated_api_any", &["names"]),
    ("emulated_arg_regex", &["api", "pattern"]),
    ("emulated_sequence", &["steps", "within"]),
    ("emulated_count_gte", &["api", "min", "distinct"]),
    ("pe_anchor_pattern", &["anchor", "section", "offset", "range", "count", "patterns", "min", "negate", "excludes"]),
    ("byte_repeat", &["anchor", "section", "offset", "length", "min"]),
    ("not_mz", &[]),
    ("authenticode", &["signed", "subject_glob"]),
    ("version_info", &["fields", "absent"]),
    ("resource_match", &["type_glob", "size_min", "size_max", "data_patterns", "min"]),
    ("resource_hash_any", &["values"]),
    ("resources_absent", &[]),
    ("registry_key", &["key", "recursive", "value_pattern"]),
    ("registry_value", &["key", "recursive", "value_regex", "data_regex", "data_hex", "md5", "sha256", "min"]),
    ("clsid", &["guids", "inproc_regex"]),
    ("hosts_entry", &["ip", "host"]),
    ("sector_pattern", &["device", "lba", "count", "patterns", "min", "excludes"]),
    ("path_glob", &["pattern"]),
    ("feature_bounds", &["bounds", "min"]),
    ("pe_sections_summary", &[
        "total_raw_size", "total_raw_size_min", "total_raw_size_max", "md5", "sha1", "sha256", "crc32",
        "count", "count_min", "count_max",
    ]),
    ("export_hash_any", &["values"]),
    ("pe_timestamp", &["value", "hex", "min", "max"]),
    ("file_timestamp", &["equals", "after", "before", "raw_hex", "age_days_min", "age_days_max"]),
    ("file_attributes", &["spec", "required", "forbidden"]),
];

/// Values accepted by `file_type` conditions.
pub const FILE_TYPES: &[&str] = &[
    "pe", "exe", "dll", "sys", "pe32", "pe64", "broken_pe", "elf", "elf32", "elf64", "broken_elf", "macho", "mach_o",
    "broken_macho", "apk", "android", "broken_apk", "pe_no_code", "zip", "archive", "7z", "rar", "gzip", "gz", "tar", "asar", "jar",
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
            for step in cond.get("steps").and_then(|v| v.as_sequence()).into_iter().flatten() {
                check_keys(step, STEP_KEYS, &format!("{cat} step"), &mut out);
            }
            for bound in cond.get("bounds").and_then(|v| v.as_sequence()).into_iter().flatten() {
                check_keys(bound, BOUND_KEYS, &format!("{cat} bound"), &mut out);
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

/// An emulated-API name: `CreateFileW` or `CreateFileW|CopyFileW`.
fn api_problem(api: &str) -> Option<String> {
    api.split('|')
        .any(|n| n.trim().is_empty())
        .then(|| format!("empty API name in `{api}`"))
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
            index,
            name,
            name_regex,
            flags_all,
            flags_none,
            characteristics,
            entropy_min,
            entropy_max,
            raw_size,
            raw_size_min,
            raw_size_max,
            raw_offset,
            virtual_address,
            virtual_size,
            virtual_size_min,
            virtual_size_max,
            md5,
            sha1,
            sha256,
            crc32,
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
            if let Some(m) = md5 && !hex_len(m.trim(), 32) {
                out.push("pe_section md5 must be 32 hex characters".into());
            }
            if let Some(s) = sha1 && !hex_len(s.trim(), 40) {
                out.push("pe_section sha1 must be 40 hex characters".into());
            }
            if let Some(s) = sha256 && !hex_len(s.trim(), 64) {
                out.push("pe_section sha256 must be 64 hex characters".into());
            }
            if let Some(c) = crc32 {
                let clean = c.trim().trim_start_matches("0x").trim_start_matches("0X");
                if !hex_len(clean, 8) {
                    out.push("pe_section crc32 must be 8 hex characters".into());
                }
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
            let empty = index.is_none()
                && name.is_none()
                && name_regex.is_none()
                && flags_all.is_empty()
                && flags_none.is_empty()
                && characteristics.is_none()
                && entropy_min.is_none()
                && entropy_max.is_none()
                && raw_size.is_none()
                && raw_size_min.is_none()
                && raw_size_max.is_none()
                && raw_offset.is_none()
                && virtual_address.is_none()
                && virtual_size.is_none()
                && virtual_size_min.is_none()
                && virtual_size_max.is_none()
                && md5.is_none()
                && sha1.is_none()
                && sha256.is_none()
                && crc32.is_none()
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
        RuleCondition::HashSha1 { value } if !hex_len(value.trim(), 40) => out.push("sha1 must be 40 hex characters".into()),
        RuleCondition::HashCrc32 { value } => {
            let clean = value.trim().trim_start_matches("0x").trim_start_matches("0X");
            if !hex_len(clean, 8) {
                out.push("crc32 must be 8 hex characters".into());
            }
        }
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
        RuleCondition::EmulatedApiAny { names } => list_problems("names", names, None, &mut out),
        RuleCondition::EmulatedArgRegex { api, pattern } => {
            out.extend(api_problem(api));
            out.extend(regex_problem(pattern));
        }
        RuleCondition::EmulatedSequence { steps, within } => {
            if steps.is_empty() {
                out.push("empty `steps` list: never matches".into());
            }
            for (i, st) in steps.iter().enumerate() {
                out.extend(api_problem(&st.api).map(|e| format!("step {}: {e}", i + 1)));
                if let Some(p) = &st.pattern {
                    out.extend(regex_problem(p).map(|e| format!("step {}: {e}", i + 1)));
                }
            }
            if let Some(w) = within {
                if *w + 1 < steps.len() {
                    out.push(format!("within {w} is shorter than the {} steps: never matches", steps.len()));
                }
            }
        }
        RuleCondition::EmulatedCountGte { api, min, .. } => {
            out.extend(api_problem(api));
            if *min == 0 {
                out.push("min: 0 always holds".into());
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
        RuleCondition::PeAnchorPattern {
            anchor,
            section,
            patterns,
            min,
            excludes,
            ..
        } => {
            if super::pe_anchor::parse_anchor_with_section(anchor, *section).is_none() {
                out.push(format!("invalid anchor `{anchor}`"));
            }
            list_problems("patterns", patterns, *min, &mut out);
            for p in patterns {
                if super::pe_anchor::compile(p).is_none() {
                    out.push(format!("invalid anchor hex pattern `{p}`"));
                }
            }
            for e in excludes {
                if super::pe_anchor::compile(e).is_none() {
                    out.push(format!("invalid anchor exclude hex pattern `{e}`"));
                }
            }
        }
        RuleCondition::ByteRepeat {
            anchor,
            section,
            length,
            min,
            ..
        } => {
            if super::pe_anchor::parse_anchor_with_section(anchor, *section).is_none() {
                out.push(format!("invalid anchor `{anchor}`"));
            }
            if *length == 0 {
                out.push("length must be at least 1".into());
            }
            if *min == Some(0) {
                out.push("min: 0 is treated as 1".into());
            }
        }
        RuleCondition::Authenticode {
            signed,
            subject_glob,
        } => {
            if signed.is_none() && subject_glob.as_deref().is_none_or(|s| s.trim().is_empty()) {
                out.push("authenticode needs `signed` or `subject_glob`".into());
            }
        }
        RuleCondition::VersionInfo { fields, absent } => {
            if !*absent && fields.is_empty() {
                out.push("version_info needs `absent: true` or non-empty `fields`".into());
            }
        }
        RuleCondition::ResourceMatch {
            type_glob,
            size_min,
            size_max,
            data_patterns,
            ..
        } => {
            if type_glob.as_deref().is_none_or(|s| s.trim().is_empty())
                && size_min.is_none()
                && size_max.is_none()
                && data_patterns.is_empty()
            {
                out.push("resource_match needs at least one filter".into());
            }
            for p in data_patterns {
                if super::pe_anchor::compile(p).is_none() {
                    out.push(format!("invalid resource hex pattern `{p}`"));
                }
            }
        }
        RuleCondition::ResourceHashAny { values } => {
            list_problems("values", values, None, &mut out);
            for v in values {
                let t = v.trim();
                if !hex_len(t, 32) && !hex_len(t, 64) {
                    out.push(format!(
                        "resource hash `{v}` must be 32 (md5) or 64 (sha256) hex characters"
                    ));
                }
            }
        }
        RuleCondition::RegistryKey {
            key, value_pattern, ..
        } => {
            if key.trim().is_empty() {
                out.push("empty `key`".into());
            }
            if let Some(p) = value_pattern {
                out.extend(regex_problem(p));
            }
        }
        RuleCondition::RegistryValue {
            key,
            value_regex,
            data_regex,
            md5,
            sha256,
            ..
        } => {
            if key.trim().is_empty() {
                out.push("empty `key`".into());
            }
            if let Some(p) = value_regex {
                out.extend(regex_problem(p));
            }
            if let Some(p) = data_regex {
                out.extend(regex_problem(p));
            }
            if let Some(m) = md5
                && !hex_len(m.trim(), 32)
            {
                out.push("md5 must be 32 hex characters".into());
            }
            if let Some(s) = sha256
                && !hex_len(s.trim(), 64)
            {
                out.push("sha256 must be 64 hex characters".into());
            }
        }
        RuleCondition::Clsid { guids, inproc_regex } => {
            list_problems("guids", guids, None, &mut out);
            if let Some(p) = inproc_regex {
                out.extend(regex_problem(p));
            }
        }
        RuleCondition::HostsEntry { ip, host } => {
            if ip.as_deref().is_none_or(|s| s.trim().is_empty())
                && host.as_deref().is_none_or(|s| s.trim().is_empty())
            {
                out.push("hosts_entry needs `ip` or `host`".into());
            }
            if let Some(h) = host {
                out.extend(regex_problem(h));
            }
        }
        RuleCondition::SectorPattern {
            device,
            patterns,
            min,
            excludes,
            ..
        } => {
            if device.trim().is_empty() {
                out.push("empty `device`".into());
            }
            list_problems("patterns", patterns, *min, &mut out);
            for p in patterns {
                if super::pe_anchor::compile(p).is_none() {
                    out.push(format!("invalid sector hex pattern `{p}`"));
                }
            }
            for e in excludes {
                if super::pe_anchor::compile(e).is_none() {
                    out.push(format!("invalid sector exclude hex pattern `{e}`"));
                }
            }
        }
        RuleCondition::PathGlob { pattern } => {
            if pattern.trim().is_empty() {
                out.push("empty `pattern`".into());
            }
        }
        RuleCondition::FeatureBounds { bounds, min } => {
            if bounds.is_empty() {
                out.push("empty `bounds` list: never matches".into());
            }
            if let Some(m) = min
                && *m > bounds.len()
            {
                out.push(format!(
                    "min {m} is larger than the {} bounds: never matches",
                    bounds.len()
                ));
            }
            for b in bounds {
                if !FEATURES.contains(&b.feature.as_str())
                    && !matches!(
                        b.feature.as_str(),
                        "entropy" | "file_entropy" | "size" | "file_size"
                    )
                {
                    out.push(format!(
                        "unknown feature `{}` (known: {})",
                        b.feature,
                        FEATURES.join(", ")
                    ));
                }
                if b.min.is_none() && b.max.is_none() {
                    out.push(format!("feature `{}` bound needs `min` or `max`", b.feature));
                }
            }
        }
        RuleCondition::PeSectionsSummary {
            total_raw_size,
            total_raw_size_min,
            total_raw_size_max,
            md5,
            sha1,
            sha256,
            crc32,
            count,
            count_min,
            count_max,
        } => {
            if total_raw_size.is_none()
                && total_raw_size_min.is_none()
                && total_raw_size_max.is_none()
                && md5.is_none()
                && sha1.is_none()
                && sha256.is_none()
                && crc32.is_none()
                && count.is_none()
                && count_min.is_none()
                && count_max.is_none()
            {
                out.push("pe_sections_summary needs at least one filter".into());
            }
            if let Some(m) = md5 && !hex_len(m.trim(), 32) {
                out.push("pe_sections_summary md5 must be 32 hex characters".into());
            }
            if let Some(s) = sha1 && !hex_len(s.trim(), 40) {
                out.push("pe_sections_summary sha1 must be 40 hex characters".into());
            }
            if let Some(s) = sha256 && !hex_len(s.trim(), 64) {
                out.push("pe_sections_summary sha256 must be 64 hex characters".into());
            }
            if let Some(c) = crc32 {
                let clean = c.trim().trim_start_matches("0x").trim_start_matches("0X");
                if !hex_len(clean, 8) {
                    out.push("pe_sections_summary crc32 must be 8 hex characters".into());
                }
            }
        }
        RuleCondition::ExportHashAny { values } => {
            list_problems("values", values, None, &mut out);
            for v in values.iter().filter(|v| !hex_len(v.trim(), 32)) {
                out.push(format!("export hash `{v}` must be 32 hex characters"));
            }
        }
        RuleCondition::PeTimestamp { value, hex, min, max } => {
            if value.is_none() && hex.is_none() && min.is_none() && max.is_none() {
                out.push("pe_timestamp needs `value`, `hex`, `min` or `max`".into());
            }
            if let Some(h) = hex {
                let clean = h.trim().trim_start_matches("0x").trim_start_matches("0X");
                if u32::from_str_radix(clean, 16).is_err() {
                    out.push(format!("invalid pe_timestamp hex `{h}`"));
                }
            }
        }
        RuleCondition::FileTimestamp {
            equals,
            after,
            before,
            raw_hex,
            age_days_min,
            age_days_max,
        } => {
            if equals.is_none()
                && after.is_none()
                && before.is_none()
                && raw_hex.is_none()
                && age_days_min.is_none()
                && age_days_max.is_none()
            {
                out.push("file_timestamp needs at least one constraint".into());
            }
            if let Some(h) = raw_hex {
                let clean = h.trim().trim_start_matches("0x").trim_start_matches("0X");
                if u32::from_str_radix(clean, 16).is_err() {
                    out.push(format!("invalid file_timestamp raw_hex `{h}`"));
                }
            }
        }
        RuleCondition::FileAttributes {
            spec,
            required,
            forbidden,
        } => {
            if spec.is_none() && required.is_empty() && forbidden.is_empty() {
                out.push("file_attributes needs `spec`, `required` or `forbidden`".into());
            }
            if let Some(s) = spec && super::system_windows::parse_attr_spec(s).is_none() {
                out.push(format!("invalid file_attributes spec `{s}` (use e.g. `A+D-H-L-R-S-`)"));
            }
            for f in required.iter().chain(forbidden) {
                if super::system_windows::attr_flag_value(f).is_none() {
                    out.push(format!("unknown file attribute `{f}`"));
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
            "string_contains" | "hash_sha256" | "hash_md5" | "hash_sha1" | "hash_crc32" => "        value: x\n",
            "string_regex" | "import_regex" | "dll_regex" | "section_name_regex" | "path_regex" | "byte_pattern" | "path_glob" => "        pattern: x\n",
            "string_set" | "file_type" | "imphash_any" | "resource_hash_any" | "export_hash_any" => "        values: [x]\n",
            "native_signature" => "        atoms: []\n        expression: x\n",
            "suspicious_import_count" | "file_entropy" | "section_entropy" => "        min: 1\n",
            "file_size_gte" | "file_size_lte" => "        bytes: 1\n",
            "feature_gte" | "feature_lte" | "parent_feature_gte" | "parent_feature_lte" | "feature_delta_gte" => {
                "        name: x\n        value: 1\n"
            }
            "byte_set" | "pe_anchor_pattern" => "        patterns: [x]\n",
            "byte_repeat" => "        length: 4\n",
            "rule_match" => "        ids: [x]\n",
            "unpacker_any" => "        signatures: []\n",
            "image_fuzzy_hash_any" => "        hashes: []\n",
            "packed_pe" | "env_reference" | "pe_icon_any" | "has_parent" | "pe_section" | "not_mz" | "authenticode" | "version_info" | "resource_match" | "resources_absent" | "hosts_entry" | "pe_sections_summary" | "pe_timestamp" | "file_timestamp" | "file_attributes" => "",
            "registry_key" | "registry_value" => "        key: HKLM\\\\Software\n",
            "clsid" => "        guids: [x]\n",
            "sector_pattern" => "        device: physical0\n        patterns: [4D5A]\n",
            "feature_bounds" => "        bounds: [{feature: string_count, min: 1}]\n",
            "emulated_arg_regex" => "        api: x\n        pattern: x\n",
            "emulated_sequence" => "        steps: [{api: x}]\n",
            "emulated_count_gte" => "        api: x\n        min: 1\n",
            _ => "        names: [x]\n",
        }
    }
}
