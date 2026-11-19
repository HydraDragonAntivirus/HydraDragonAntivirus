//! Analyst signatures in engine formats, kept apart from the shipped databases:
//!
//! * `analyst_signatures/clamav/*.ndb|*.ldb` — ClamAV body / logical signatures,
//!   compiled by `hydradragonclamav` into a small engine of their own.
//! * `analyst_signatures/hydradragonsig/*.yaml` — HydraDragonSig rules (strings,
//!   imports, native expressions...), evaluated by `hydradragonsig` itself.
//! * `analyst_signatures/{signer_rules,registry_rules,url_rules}/*.yaml` and
//!   `analyst_signatures/sigma/*.yml` — rule sets the static engine itself reads.
//!   They are validated here with the engine's own parsers, but only take effect
//!   when the engine is rebuilt (`EngineAdapter::reload_all`).
//!
//! The shipped engine is never touched: these run after the main scan and can only
//! raise a verdict (unknown/clean -> suspicious/malicious), never lower one. Both sets
//! are rebuilt from disk on every save or delete, so edits and deletions apply at once
//! (unlike YARA sources, which can only be appended to the live engine).
//!
//! Every signature name / rule family must follow `naming.rs`
//! (`Category.Platform.Family[.Variant]`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::RwLock;

use hydradragonclamav::scanner::{Engine as ClamEngine, ScanOptions as ClamScanOptions};
use hydradragonsig::models::{MemoryScanContext, Verdict as SigVerdict};
use hydradragonsig::rules::RuleSet;

use crate::naming::normalize_threat_name;

/// What a signature room entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    Yara,
    HydraSig,
    ClamNdb,
    ClamLdb,
    Firewall,
    /// `signer_rules/*.yaml`: Authenticode signer rules (trusted publishers, or
    /// signers to flag). Loaded into the static engine, which needs a rebuild.
    Signer,
    /// `registry_rules/*.yaml`: PUA / persistence registry path lists.
    Registry,
    /// `url_rules/*.yaml`: URL / embedded-link rules.
    Url,
    /// `sigma/*.yml`: Sigma rules run by the Hayabusa event-log scanner.
    Sigma,
}

impl SigKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "yara" => Some(Self::Yara),
            "hydradragonsig" | "sig" => Some(Self::HydraSig),
            "clamav_ndb" | "ndb" => Some(Self::ClamNdb),
            "clamav_ldb" | "ldb" => Some(Self::ClamLdb),
            "firewall" | "fw" | "firewall_rule" => Some(Self::Firewall),
            "signer" | "signer_rules" => Some(Self::Signer),
            "registry" | "registry_rules" => Some(Self::Registry),
            "url" | "url_rules" => Some(Self::Url),
            "sigma" | "hayabusa" => Some(Self::Sigma),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Yara => "yara",
            Self::HydraSig => "hydradragonsig",
            Self::ClamNdb => "clamav_ndb",
            Self::ClamLdb => "clamav_ldb",
            Self::Firewall => "firewall",
            Self::Signer => "signer",
            Self::Registry => "registry",
            Self::Url => "url",
            Self::Sigma => "sigma",
        }
    }
    pub fn folder(self) -> &'static str {
        match self {
            Self::Yara => "yara",
            Self::HydraSig => "hydradragonsig",
            Self::ClamNdb | Self::ClamLdb => "clamav",
            Self::Firewall => "firewall",
            Self::Signer => "signer_rules",
            Self::Registry => "registry_rules",
            Self::Url => "url_rules",
            Self::Sigma => "sigma",
        }
    }
    pub fn ext(self) -> &'static str {
        match self {
            Self::Yara => "yar",
            Self::HydraSig => "yaml",
            Self::ClamNdb => "ndb",
            Self::ClamLdb => "ldb",
            Self::Firewall => "yaml",
            Self::Signer | Self::Registry | Self::Url => "yaml",
            Self::Sigma => "yml",
        }
    }
    pub const ALL: [SigKind; 9] = [
        Self::Yara,
        Self::HydraSig,
        Self::ClamNdb,
        Self::ClamLdb,
        Self::Firewall,
        Self::Signer,
        Self::Registry,
        Self::Url,
        Self::Sigma,
    ];

    /// Rules the static engine only picks up while it is built (startup or a full
    /// reload): saving or deleting one has to trigger `reload_all`.
    pub fn needs_engine_rebuild(self) -> bool {
        matches!(self, Self::Signer | Self::Registry | Self::Url | Self::Sigma)
    }

    /// Kinds whose file name is free-form instead of a threat name: a signer rule
    /// may name a trusted publisher, and registry / URL / Sigma rule sets are not
    /// one detection each, so `Category.Platform.Family` would not fit them.
    pub fn free_name(self) -> bool {
        self.needs_engine_rebuild()
    }

    /// Kinds a retrohunt can run over stored files with a standalone matcher.
    /// Firewall rules see traffic; signer rules need the engine's Authenticode
    /// extraction; registry / URL / Sigma rules judge live events.
    pub fn retrohuntable(self) -> bool {
        matches!(self, Self::Yara | Self::HydraSig | Self::ClamNdb | Self::ClamLdb)
    }

    pub fn path(self, name: &str) -> PathBuf {
        let dir = crate::human_review::analyst_dir().join(self.folder());
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{name}.{}", self.ext()))
    }
}

/// Container members scanned with the analyst signatures: nesting depth, member
/// count per file and largest member, so a crafted archive cannot stall a scan.
const MEMBER_MAX_DEPTH: usize = 3;
const MEMBER_BUDGET: usize = 512;
const MEMBER_MAX_BYTES: usize = 64 * 1024 * 1024;

/// A match from an analyst signature.
#[derive(Debug, Clone)]
pub struct AnalystHit {
    pub engine: &'static str,
    pub name: String,
    pub verdict: &'static str,
}

#[derive(Default)]
pub struct AnalystEngine {
    clam: RwLock<Option<ClamEngine>>,
    sig: RwLock<Option<RuleSet>>,
    companies: RwLock<CompanyLists>,
    /// The company lists were loaded once (the first load is not a change).
    companies_loaded: AtomicBool,
    /// Unix seconds of the last change to the company lists (0: none since start).
    /// Verdicts cached before it that depend on them (XOR-filter hits, allow-listed
    /// signers) are stale: see `ScanServer::known_opts`.
    companies_changed_at: AtomicI64,
}

/// Analyst company (Authenticode signer) lists: `analyst_signatures/companies_allow.txt`
/// and `companies_block.txt`, one signer name per line, matched case-insensitively.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct CompanyLists {
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// The analyst's reason for each entry: the `# ...` after the name in the
    /// list file, keyed by `(lowercased name, "allow"|"block")`. Shown in the
    /// verdict detail, like other analyst signatures show theirs.
    #[serde(skip)]
    pub reasons: std::collections::HashMap<(String, &'static str), String>,
    /// Block list: detection name per entry (`family` in the YAML), same keys.
    #[serde(skip)]
    pub families: std::collections::HashMap<(String, &'static str), String>,
}

/// Decision from the company lists for one file: the matched list entry, the
/// analyst's reason for it (empty when none was written) and, for the block
/// list, the detection name to report (empty: the default name).
pub enum CompanyDecision {
    /// Signer is allow-listed and the signature is cryptographically valid.
    Allow(String, String),
    /// Signer is block-listed (valid signature or not).
    Block(String, String, String),
}

/// Every distinct name a signed file answers to, in the order an analyst is
/// most likely to have written it: the publisher first, then the things behind
/// it. Matching stays whole-line and case-insensitive, exactly as it always was;
/// only the set of candidate strings grew.
fn identity_labels(s: &openedr_static::report::SignerDetails) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in [
        s.signer_name.as_deref(),
        s.issuer.as_deref(),
        s.timestamp_signer.as_deref(),
        s.thumbprint.as_deref(),
    ] {
        let v = v.map(str::trim).filter(|v| !v.is_empty());
        if let Some(v) = v {
            if !out.iter().any(|e| e.eq_ignore_ascii_case(v)) {
                out.push(v.to_string());
            }
        }
    }
    out
}


// ------------------------------------------------------------------ validation

/// Names inside one ClamAV `.ndb` / `.ldb` document (first field of every line).
fn clam_names(kind: SigKind, src: &str) -> Vec<String> {
    let sep = if kind == SigKind::ClamLdb { ';' } else { ':' };
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(sep).next().unwrap_or("").to_string())
        .collect()
}

/// Checks a ClamAV document: every signature name follows the naming convention and
/// the whole file parses with hydradragonclamav. Returns the number of signatures.
pub fn validate_clamav(kind: SigKind, src: &str) -> Result<usize, String> {
    let names = clam_names(kind, src);
    if names.is_empty() {
        return Err("no signature lines".into());
    }
    for n in &names {
        let canon = normalize_threat_name(n).map_err(|e| format!("signature name \"{n}\": {e}"))?;
        if &canon != n {
            return Err(format!("write the signature name in canonical form: {canon}"));
        }
    }
    let mut files = HashMap::new();
    files.insert(format!("check.{}", kind.ext()), src.as_bytes().to_vec());
    let (_engine, report) = ClamEngine::from_bytes_map(&files);
    if let Some(e) = report.errors.first() {
        return Err(format!("line {}: {}", e.source.line, e.message));
    }
    let loaded = report.extended_loaded + report.logical_loaded + report.db_loaded;
    if loaded == 0 {
        return Err("hydradragonclamav loaded no signature from this file".into());
    }
    if loaded < names.len() {
        return Err(format!("only {loaded} of {} signatures were accepted", names.len()));
    }
    Ok(loaded)
}

/// Every `verdict` a HydraDragonSig rule may carry (`hydradragonsig::models::Verdict`,
/// FORMAT.md section 2), lowercase. Also served by `/api/signatures/schema`.
pub const HYDRASIG_VERDICTS: [&str; 5] = ["trusted", "clean", "suspicious", "pua", "malware"];

/// Checks a HydraDragonSig YAML document: it parses, every rule has a `family` in the
/// naming convention and a malware/pua/suspicious verdict. Returns the rule count.
pub fn validate_hydrasig(src: &str) -> Result<usize, String> {
    // The typed parse below rejects an unknown verdict too, but with a serde message
    // that does not name the rule; checking the raw document first tells the analyst
    // which rule and which values are allowed (FORMAT.md section 11).
    if let Ok(doc) = yaml_serde::from_str::<yaml_serde::Value>(src) {
        if let Some(rules) = doc.get("rules").and_then(|v| v.as_sequence()) {
            for (idx, r) in rules.iter().enumerate() {
                let Some(v) = r.get("verdict") else { continue };
                let id = r.get("id").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("#{idx}"));
                let ok = v.as_str().is_some_and(|s| HYDRASIG_VERDICTS.contains(&s.to_ascii_lowercase().as_str()));
                if !ok {
                    return Err(format!("rule {id}: verdict must be one of {}", HYDRASIG_VERDICTS.join(", ")));
                }
            }
        }
    }
    // Strict: unknown keys, invalid regexes / byte patterns / expressions and
    // conditions that can never match are refused instead of silently ignored.
    let rs = RuleSet::from_yaml_str_strict(src).map_err(|e| format!("{e:#}"))?;
    if rs.rules().is_empty() {
        return Err("no rules in the document".into());
    }
    for r in rs.rules() {
        let fam = r.family.as_deref().unwrap_or("");
        if fam.is_empty() {
            return Err(format!("rule {} needs a family, e.g. family: \"Trojan.Win32.Remcos.A\"", r.id));
        }
        let canon = normalize_threat_name(fam).map_err(|e| format!("rule {} family: {e}", r.id))?;
        if canon != fam {
            return Err(format!("rule {}: write the family in canonical form: {canon}", r.id));
        }
    }
    Ok(rs.rules().len())
}


/// Firewall rule `action` values (`owlyshield_predict::firewall::sdk::RuleAction`,
/// snake_case). Also served by `/api/signatures/schema`.
pub const FIREWALL_ACTIONS: [&str; 11] = [
    "traffic_attack",
    "block",
    "allow",
    "ask",
    "terminate",
    "quarantine",
    "kill_and_remove",
    "change_packet",
    "solve_packet",
    "change_request_body",
    "change_response_body",
];
/// `protocol` values (`sdk::RuleProtocol`, lowercase).
pub const FIREWALL_PROTOCOLS: [&str; 7] = ["http", "https", "udp", "tcp", "icmp", "arp", "any"];
/// `condition_logic` values (`sdk::ConditionLogic`, lowercase).
pub const FIREWALL_CONDITION_LOGIC: [&str; 2] = ["and", "or"];
/// `localhost_type` values (`sdk::LocalhostType`, snake_case).
pub const FIREWALL_LOCALHOST_TYPES: [&str; 8] =
    ["loopback", "private_a", "private_b", "private_c", "private", "any", "all", "none"];
/// `encoding` values (`sdk::ContentEncoding`, lowercase).
pub const FIREWALL_ENCODINGS: [&str; 5] = ["base58", "base64", "reverse", "hex", "plain"];

/// Validates a HydraDragon Firewall YAML rule set against the schema the clients
/// deserialize (`owlyshield_predict/src/firewall/sdk.rs`, `SdkRule`). The server does
/// not link the firewall SDK, so the checks mirror its serde types by hand: a value
/// the client cannot parse would make it drop the whole file, so it is refused here
/// instead of being saved and exported.
///
/// Accepts a `rules:` mapping (`SdkRuleFile`) or a top-level list of rules.
pub fn validate_firewall_yaml(src: &str) -> Result<usize, String> {
    let val: yaml_serde::Value = yaml_serde::from_str(src).map_err(|e| format!("YAML parse error: {e}"))?;
    let rules = if let Some(r) = val.get("rules").and_then(|v| v.as_sequence()) {
        r
    } else if let Some(seq) = val.as_sequence() {
        seq
    } else {
        return Err("Firewall YAML must contain either a 'rules:' mapping or a top-level list of rules".into());
    };
    if rules.is_empty() {
        return Err("No rules found in firewall YAML".into());
    }
    // One enum-valued field: absent is fine (serde default), present must be a
    // string from the list (the SDK enums are case-sensitive).
    let one_of = |r: &yaml_serde::Value, idx: usize, key: &str, allowed: &[&str]| -> Result<(), String> {
        match r.get(key) {
            None => Ok(()),
            Some(v) => match v.as_str() {
                Some(s) if allowed.contains(&s) => Ok(()),
                Some(s) => Err(format!("Rule #{idx} has unknown {key} '{s}' (expected {})", allowed.join(", "))),
                None => Err(format!("Rule #{idx}: {key} must be a string ({})", allowed.join(", "))),
            },
        }
    };
    for (idx, r) in rules.iter().enumerate() {
        if !r.is_mapping() {
            return Err(format!("Rule #{idx} is not a mapping"));
        }
        // `SdkRule::name` is required; `id` / `rule_name` are not SDK fields.
        match r.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.trim().is_empty() => {}
            _ => return Err(format!("Rule #{idx} is missing 'name'")),
        }
        one_of(r, idx, "action", &FIREWALL_ACTIONS)?;
        one_of(r, idx, "protocol", &FIREWALL_PROTOCOLS)?;
        one_of(r, idx, "condition_logic", &FIREWALL_CONDITION_LOGIC)?;
        one_of(r, idx, "localhost_type", &FIREWALL_LOCALHOST_TYPES)?;
        one_of(r, idx, "encoding", &FIREWALL_ENCODINGS)?;
        // `RegexMatcher { pattern: String, case_insensitive: bool }`, neither defaulted.
        if let Some(re) = r.get("regex").filter(|v| !v.is_null()) {
            if !re.is_mapping() {
                return Err(format!("Rule #{idx}: regex must be a mapping with pattern and case_insensitive"));
            }
            if re.get("pattern").and_then(|v| v.as_str()).is_none() {
                return Err(format!("Rule #{idx}: regex.pattern must be a string"));
            }
            if re.get("case_insensitive").and_then(|v| v.as_bool()).is_none() {
                return Err(format!("Rule #{idx}: regex.case_insensitive must be true or false"));
            }
        }
    }
    Ok(rules.len())
}

/// File name of a free-named rule (`SigKind::free_name`): letters, digits, `.`, `_`
/// and `-`, at most 100 characters. Only what keeps the name a single safe file name
/// in its folder (no separators, no `..`, no leading dot) is enforced.
pub fn normalize_rule_file_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("the rule needs a file name".into());
    }
    if n.chars().count() > 100 {
        return Err("rule file name over 100 characters".into());
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err("rule file name may only contain letters, digits, '.', '_' and '-'".into());
    }
    if n.starts_with('.') || n.contains("..") {
        return Err("rule file name may not start with '.' or contain '..'".into());
    }
    Ok(n.to_string())
}

/// Signer rules (`signer_rules/*.yaml`), checked by the engine's own parser.
pub fn validate_signer_rules(src: &str) -> Result<usize, String> {
    openedr_static::signers::validate_signer_rules_yaml(src)
}

/// Registry rules (`registry_rules/*.yaml`), checked by the engine's own parser.
pub fn validate_registry_rules(src: &str) -> Result<usize, String> {
    openedr_static::ptm_registry::validate_registry_rules_yaml(src)
}

/// URL rules (`url_rules/*.yaml`), checked by the engine's own parser.
pub fn validate_url_rules(src: &str) -> Result<usize, String> {
    openedr_static::url_rules::validate_url_rules_yaml(src)
}

/// One Sigma rule (`sigma/*.yml`), checked by the Hayabusa scanner's parser.
/// Returns the rule's title.
pub fn validate_sigma(src: &str) -> Result<String, String> {
    openedr_static::hayabusa_scanner::validate_sigma_yaml(src)
}

// ------------------------------------------------------------------ form schema

/// Every HydraDragonSig condition `type` (`hydradragonsig::rules::types::RuleCondition`,
/// `#[serde(tag = "type", rename_all = "snake_case")]`), in declaration order. Kept by
/// hand because the enum has no list of its names; the strict loader still decides,
/// this only feeds the dashboard's form builder.
pub const HYDRASIG_CONDITION_TYPES: [&str; 102] = [
    "string_contains", "string_regex", "string_set", "native_signature", "import_any", "import_all",
    "import_set", "import_regex", "export_any", "export_all", "export_set", "dll_any", "dll_regex",
    "suspicious_import_count", "file_entropy", "file_size_gte", "file_size_lte", "section_entropy",
    "section_name_regex", "pe_section", "packed_pe", "env_reference", "path_regex", "file_type", "hash_sha256",
    "hash_md5", "hash_sha1", "hash_crc32", "imphash_any", "feature_gte", "feature_lte", "has_parent",
    "parent_feature_gte", "parent_feature_lte", "feature_delta_gte", "new_import_set", "byte_pattern",
    "byte_set", "rule_match", "unpacker_any", "emulated_api_any", "emulated_arg_regex", "emulated_sequence",
    "emulated_count_gte", "image_fuzzy_hash_any", "pe_icon_any", "pe_anchor_pattern", "byte_repeat", "bytecode",
    "opcode_pattern", "not_mz", "authenticode", "authentihash_any", "pe_subsystem", "version_info",
    "resource_match", "resource_hash_any", "resources_absent", "registry_key", "registry_value", "clsid",
    "hosts_entry", "sector_pattern", "path_glob", "feature_bounds", "pe_sections_summary", "export_hash_any",
    "pe_timestamp", "file_timestamp", "file_attributes", "domain_blocklist", "dex_string_regex",
    "dex_class_regex", "dex_method_regex", "dex_class_count", "dex_method_count", "dotnet_guid_any",
    "dotnet_type_regex", "dotnet_method_regex", "dotnet_pinvoke_any", "dotnet_pinvoke_set", "dotnet_stream_any",
    "dotnet_user_string_regex", "elf_import_any", "elf_import_set", "elf_import_regex", "elf_export_any",
    "elf_export_set", "elf_needed_any", "elf_section", "elf_segment", "elf_build_id_any", "new_elf_import_set",
    "macho_dylib_any", "macho_sym_any", "macho_sym_regex", "macho_segment", "macho_uuid_any", "macho_signed",
    "macho_entitlement_any", "pdf_keyword", "pdf_stream_match",
];

/// Signer rule condition `type`s the engine reads (`openedr_static::signers`): which
/// certificate field is compared, and how (`_equals` exact, `_contains` substring,
/// thumbprints as 40 hex digits in any separator style).
pub const SIGNER_CONDITION_TYPES: [&str; 8] = [
    "signature_signer_contains",
    "signature_signer_equals",
    "signature_issuer_contains",
    "signature_issuer_equals",
    "signature_timestamp_signer_contains",
    "signature_timestamp_signer_equals",
    "signature_thumbprint_any",
    "signature_thumbprint_equals",
];

/// What the dashboard's rule form builder needs per signature room kind: fields,
/// whether they are required, and the allowed values of every enum-valued field.
/// The values come from the same constants the validators use, so the form cannot
/// offer what the save would refuse. Descriptive only: the validators still decide.
pub fn signatures_schema() -> serde_json::Value {
    use serde_json::json;
    let f = |name: &str, ty: &str, required: bool| json!({ "name": name, "type": ty, "required": required });
    let e = |name: &str, required: bool, values: &[&str]| json!({ "name": name, "type": "enum", "required": required, "values": values });
    let kind_info = |k: SigKind| {
        json!({
            "folder": k.folder(),
            "ext": k.ext(),
            // "threat_name": Category.Platform.Family[.Variant]; "file_name": [A-Za-z0-9._-]{1,100}.
            "name": if k.free_name() { "file_name" } else { "threat_name" },
            "retrohunt": k.retrohuntable(),
            "engine_reload": k.needs_engine_rebuild(),
        })
    };
    let with = |k: SigKind, extra: serde_json::Value| {
        let mut v = kind_info(k);
        if let (Some(o), Some(x)) = (v.as_object_mut(), extra.as_object()) {
            for (key, val) in x {
                o.insert(key.clone(), val.clone());
            }
        }
        v
    };
    let hydrasig_severities = ["info", "low", "medium", "high", "critical"];
    let sigma_levels = ["informational", "low", "medium", "high", "critical"];
    json!({
        "ok": true,
        "naming": {
            "categories": crate::naming::CATEGORIES,
            "platforms": crate::naming::PLATFORMS,
        },
        "kinds": {
            "yara": with(SigKind::Yara, json!({ "format": "yara" })),
            "clamav_ndb": with(SigKind::ClamNdb, json!({ "format": "Name:TargetType:Offset:HexSignature" })),
            "clamav_ldb": with(SigKind::ClamLdb, json!({ "format": "Name;TargetDescription;LogicalExpression;Subsig0;..." })),
            "hydradragonsig": with(SigKind::HydraSig, json!({
                "container": "rules",
                "fields": [
                    f("id", "string", true),
                    f("title", "string", true),
                    f("description", "string", false),
                    e("severity", true, &hydrasig_severities),
                    e("verdict", false, &HYDRASIG_VERDICTS),
                    f("family", "threat_name", true),
                    f("confidence", "integer", false),
                    f("score", "integer", false),
                    f("tags", "string_list", false),
                    f("references", "string_list", false),
                    f("private", "bool", false),
                    e("logic", false, &["any", "all", "threshold"]),
                    f("threshold", "integer", false),
                    f("conditions", "condition_list", true),
                ],
                // As a slice: serde implements Serialize for arrays only up to 32.
                "condition_types": &HYDRASIG_CONDITION_TYPES[..],
            })),
            "firewall": with(SigKind::Firewall, json!({
                "container": "rules",
                "fields": [
                    f("name", "string", true),
                    f("description", "string", false),
                    e("severity", false, &["informational", "low", "medium", "high", "critical"]),
                    f("enabled", "bool", false),
                    f("private", "bool", false),
                    e("protocol", false, &FIREWALL_PROTOCOLS),
                    e("action", false, &FIREWALL_ACTIONS),
                    e("condition_logic", false, &FIREWALL_CONDITION_LOGIC),
                    e("encoding", false, &FIREWALL_ENCODINGS),
                    e("localhost_type", false, &FIREWALL_LOCALHOST_TYPES),
                    f("src_ip", "ip_matcher", false),
                    f("dst_ip", "ip_matcher", false),
                    f("src_port", "port_matcher", false),
                    f("dst_port", "port_matcher", false),
                    f("domain", "domain_matcher", false),
                    f("url", "url_matcher", false),
                    f("content", "content_matcher", false),
                    json!({ "name": "regex", "type": "mapping", "required": false,
                            "fields": [f("pattern", "string", true), f("case_insensitive", "bool", true)] }),
                    f("entropy_threshold", "number", false),
                    f("change_data", "string", false),
                    f("change_request_body", "string", false),
                    f("change_response_body", "string", false),
                    f("http_request_body", "string_list", false),
                    f("http_response_body", "string_list", false),
                    f("depends_on", "string_list", false),
                ],
                "actions": FIREWALL_ACTIONS,
                "protocols": FIREWALL_PROTOCOLS,
                "condition_logic": FIREWALL_CONDITION_LOGIC,
                "localhost_types": FIREWALL_LOCALHOST_TYPES,
                "encodings": FIREWALL_ENCODINGS,
            })),
            "signer": with(SigKind::Signer, json!({
                "container": "rules",
                // As `openedr_static::signers::validate_signer_rules_yaml` checks them:
                // id, title, verdict and one condition are required; `trusted` rules
                // may only use signature_signer_* conditions; thumbprints are 40 hex.
                // family (malware / pua) is the detection name, "title: description"
                // its detail.
                "fields": [
                    f("id", "string", true),
                    f("title", "string", true),
                    f("description", "string", false),
                    e("verdict", true, &["trusted", "malware", "pua"]),
                    f("family", "string", false),
                    e("severity", false, &["info", "low", "medium", "high", "critical"]),
                    f("confidence", "integer", false),
                    f("score", "integer", false),
                    f("tags", "string_list", false),
                    json!({ "name": "conditions", "type": "condition_list", "required": true,
                            "fields": [e("type", true, &SIGNER_CONDITION_TYPES), f("value", "string", true), f("nocase", "bool", false)] }),
                ],
                "condition_types": SIGNER_CONDITION_TYPES,
                "trusted_condition_types": ["signature_signer_contains", "signature_signer_equals"],
            })),
            "registry": with(SigKind::Registry, json!({
                "fields": [
                    f("name", "string", false),
                    f("description", "string", false),
                ],
                // Detailed form: each rule's title / description is returned with a
                // match (`registry_match_detail`, `check_registry` rule_title).
                "container": "rules",
                "rule_fields": [
                    f("id", "string", true),
                    f("title", "string", true),
                    f("description", "string", false),
                    e("severity", false, &["info", "low", "medium", "high", "critical"]),
                    e("verdict", false, &["pua", "malware", "suspicious"]),
                    f("family", "string", false),
                    f("patterns", "string_list", true),
                ],
                // Flat lists of registry path patterns (`*` wildcards), no detail.
                "list_keys": ["pua_reg_paths", "persistence_paths", "suspicious_keys"],
            })),
            "url": with(SigKind::Url, json!({
                "container": "rules",
                "top_level_lists": ["unwhitelist_subdomains", "deterministic_rules"],
                "fields": [
                    f("id", "string", true),
                    f("title", "string", true),
                    f("description", "string", true),
                    // Analyst rules: exactly these two (the verdict logic compares them).
                    e("severity", true, &["Malicious", "Suspicious"]),
                    f("score", "integer", true),
                    f("override_whitelist", "bool", false),
                    f("skip_if_whitelisted", "bool", false),
                    f("conditions", "mapping", true),
                ],
                "condition_keys": [
                    f("url_regex", "regex", false),
                    f("path_regex", "regex", false),
                    f("query_regex", "regex", false),
                    f("body_regex", "regex", false),
                    f("host_regex", "regex", false),
                    f("scheme", "string_list", false),
                    f("ports", "integer_list", false),
                    f("tlds", "string_list", false),
                    f("is_ip", "bool", false),
                    f("cidr_blacklisted", "bool", false),
                    json!({ "name": "liveness", "type": "enum_list", "required": false,
                            "values": ["active", "potentially_up", "potentially_down", "inactive", "unknown"] }),
                    f("content_difference", "bool", false),
                    f("min_difference_percent", "integer", false),
                    f("require_equal_status", "bool", false),
                ],
            })),
            "sigma": with(SigKind::Sigma, json!({
                "fields": [
                    // Hayabusa's own loader validates the rule: it needs author and date too.
                    f("title", "string", true),
                    f("id", "string", true),
                    e("status", false, &["stable", "test", "experimental", "deprecated", "unsupported"]),
                    f("description", "string", false),
                    f("author", "string", true),
                    f("date", "string", true),
                    f("references", "string_list", false),
                    f("tags", "string_list", false),
                    f("logsource", "mapping", true),
                    f("detection", "mapping", true),
                    f("falsepositives", "string_list", false),
                    e("level", true, &sigma_levels),
                ],
                "levels": sigma_levels,
                "statuses": ["stable", "test", "experimental", "deprecated", "unsupported"],
            })),
        },
    })
}

// ------------------------------------------------------------------ runtime

impl AnalystEngine {
    fn read_dir(kind_folder: &str, exts: &[&str]) -> Vec<(String, Vec<u8>)> {
        let dir = crate::human_review::analyst_dir().join(kind_folder);
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                let ok = p.extension().and_then(|x| x.to_str()).is_some_and(|x| exts.contains(&x));
                if !ok {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&p) {
                    out.push((p.file_name().unwrap_or_default().to_string_lossy().into_owned(), bytes));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Rebuilds both analyst engines from disk. Returns a one-line summary.
    pub fn reload(&self) -> String {
        // ClamAV: one in-memory database from every analyst .ndb/.ldb file.
        let clam_files: HashMap<String, Vec<u8>> = Self::read_dir("clamav", &["ndb", "ldb"]).into_iter().collect();
        let clam_count = clam_files.len();
        let (clam, clam_loaded, clam_errors) = if clam_files.is_empty() {
            (None, 0, 0)
        } else {
            let (engine, report) = ClamEngine::from_bytes_map(&clam_files);
            let loaded = report.extended_loaded + report.logical_loaded + report.db_loaded;
            (if loaded > 0 { Some(engine) } else { None }, loaded, report.errors.len())
        };
        *self.clam.write().unwrap() = clam;

        // HydraDragonSig: every analyst YAML document merged into one rule set.
        let mut set: Option<RuleSet> = None;
        let mut sig_failed = Vec::new();
        for (name, bytes) in Self::read_dir("hydradragonsig", &["yaml", "yml"]) {
            match std::str::from_utf8(&bytes).ok().and_then(|s| RuleSet::from_yaml_str(s).ok()) {
                Some(rs) => match set.as_mut() {
                    Some(cur) => cur.extend(rs),
                    None => set = Some(rs),
                },
                None => sig_failed.push(name),
            }
        }
        let sig_rules = set.as_ref().map(|s| s.rules().len()).unwrap_or(0);
        *self.sig.write().unwrap() = set.filter(|s| !s.rules().is_empty());

        // Company lists: `company_signers.yaml` (hand edits picked up here).
        let companies_error = crate::company_signers::reload_from_disk();
        let mut companies = CompanyLists::default();
        for e in crate::company_signers::list() {
            let list: &'static str = if e.list == "allow" { "allow" } else { "block" };
            for n in std::iter::once(&e.name).chain(e.aliases.iter()) {
                let k = (n.to_ascii_lowercase(), list);
                if list == "allow" {
                    companies.allow.push(n.clone());
                } else {
                    companies.block.push(n.clone());
                }
                let detail = match (e.title.trim(), e.reason.trim()) {
                    ("", r) => r.to_string(),
                    (t, "") => t.to_string(),
                    (t, r) => format!("{t}: {r}"),
                };
                if !detail.is_empty() {
                    companies.reasons.insert(k.clone(), detail);
                }
                if !e.family.trim().is_empty() {
                    companies.families.insert(k, e.family.trim().to_string());
                }
            }
        }
        companies.allow.sort_by_key(|n| n.to_ascii_lowercase());
        companies.block.sort_by_key(|n| n.to_ascii_lowercase());
        let (n_allow, n_block) = (companies.allow.len(), companies.block.len());
        {
            let mut cur = self.companies.write().unwrap();
            if *cur != companies && self.companies_loaded.load(Ordering::Relaxed) {
                self.companies_changed_at.store(crate::cache::now_secs(), Ordering::Relaxed);
            }
            *cur = companies;
        }
        self.companies_loaded.store(true, Ordering::Relaxed);

        let msg = format!(
            "companies {n_allow} allowed / {n_block} blocked{}, analyst signatures: clamav {clam_loaded} sigs from {clam_count} files ({clam_errors} errors), hydradragonsig {sig_rules} rules ({} files failed)",
            companies_error.map(|e| format!(" (YAML NOT LOADED: {e})")).unwrap_or_default(),
            sig_failed.len()
        );
        eprintln!("[engine] {msg}");
        msg
    }

    /// Unix seconds of the last change to the company lists (0: none since start).
    pub fn companies_changed_at(&self) -> i64 {
        self.companies_changed_at.load(Ordering::Relaxed)
    }

    pub fn company_lists(&self) -> CompanyLists {
        self.companies.read().unwrap().clone()
    }

    /// Block wins over allow, over everything a signed file can be named by:
    /// publisher, issuing CA, the countersigning authority and the leaf
    /// thumbprint. A compromised CA signs for whatever subject it is asked for,
    /// and a revoked-but-still-trusted leaf has an ordinary-looking publisher,
    /// so matching the publisher alone misses both.
    ///
    /// Allow needs a cryptographically valid signature (`status == "trusted"`:
    /// WinVerifyTrust / catalog passed): a name alone (or a broken signature)
    /// never makes a file clean. Not `is_trusted`: the engine sets that only
    /// when the publisher is also in `signer_rules/trusted_signers.yaml`, so
    /// every company an analyst added that the YAML does not list (Gen Digital
    /// Inc., ...) was never allowed.
    ///
    /// This stays the server's own layer: it does not consult `signer_rules/`
    /// and does not duplicate the engine's `SignerRule` detections.
    pub fn company_decision_for(
        &self,
        s: &openedr_static::report::SignerDetails,
    ) -> Option<CompanyDecision> {
        let labels = identity_labels(s);
        if labels.is_empty() {
            return None;
        }
        let lists = self.companies.read().unwrap();
        let reason = |l: &str, list: &'static str| {
            lists.reasons.get(&(l.to_ascii_lowercase(), list)).cloned().unwrap_or_default()
        };
        for l in &labels {
            if lists.block.iter().any(|c| c.eq_ignore_ascii_case(l)) {
                let family = lists.families.get(&(l.to_ascii_lowercase(), "block")).cloned().unwrap_or_default();
                return Some(CompanyDecision::Block(l.clone(), reason(l, "block"), family));
            }
        }
        let signature_valid = s.is_signed && s.status == "trusted";
        if signature_valid {
            for l in &labels {
                if lists.allow.iter().any(|c| c.eq_ignore_ascii_case(l)) {
                    return Some(CompanyDecision::Allow(l.clone(), reason(l, "allow")));
                }
            }
        }
        None
    }

    /// Runs the analyst signatures over a file and, when it is a container the
    /// extractor can open (archives, NSIS installers, PE self-extractors, ASAR...),
    /// over every member as well, so an installer gets the name and level of what it
    /// carries. Cheap when no analyst signatures exist.
    pub fn scan(&self, data: &[u8], name: &str) -> Vec<AnalystHit> {
        let mut hits = Vec::new();
        if self.clam.read().unwrap().is_none() && self.sig.read().unwrap().is_none() {
            return hits;
        }
        let mut budget = MEMBER_BUDGET;
        self.scan_into(data, name, 0, &mut budget, &mut hits);
        hits
    }

    fn scan_into(&self, data: &[u8], name: &str, depth: usize, budget: &mut usize, hits: &mut Vec<AnalystHit>) {
        for hit in self.scan_one(data, name) {
            if !hits.iter().any(|h| h.engine == hit.engine && h.name == hit.name) {
                hits.push(hit);
            }
        }
        if depth >= MEMBER_MAX_DEPTH || hydradragonextractor::detect_format(data).is_none() {
            return;
        }
        let Ok(members) = ({
            let _t = openedr_static::memtrack::stage("server:analyst_extract");
            hydradragonextractor::extract_archive_from_bytes(data, false)
        }) else {
            return;
        };
        for m in members {
            if *budget == 0 {
                return;
            }
            if m.data.is_empty() || m.data.len() > MEMBER_MAX_BYTES {
                continue;
            }
            *budget -= 1;
            let member_name = format!("{name}/{}", m.name);
            self.scan_into(&m.data, &member_name, depth + 1, budget, hits);
        }
    }

    /// The analyst signatures over one buffer (no container recursion).
    fn scan_one(&self, data: &[u8], name: &str) -> Vec<AnalystHit> {
        let mut hits = Vec::new();
        if let Some(clam) = self.clam.read().unwrap().as_ref() {
            let _t = openedr_static::memtrack::stage("server:analyst_clamav");
            for m in clam.scan_bytes_named(data, if name.is_empty() { "file" } else { name }, ClamScanOptions::default(), &[]) {
                // `PUA.*` signatures are potentially unwanted, not malware (same as the engine).
                let verdict = if m.name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("PUA.")) { "suspicious" } else { "malicious" };
                hits.push(AnalystHit { engine: "clamav", name: m.name, verdict });
            }
        }
        if let Some(rules) = self.sig.read().unwrap().as_ref() {
            let _t = openedr_static::memtrack::stage("server:analyst_sig");
            let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: name.to_string(), base_address: None };
            if let Ok(report) = hydradragonsig::scan_memory_owned(ctx, rules, &hydradragonsig::ScanOptions::default()) {
                let verdict = match report.verdict {
                    SigVerdict::Malware => Some("malicious"),
                    SigVerdict::Pua | SigVerdict::Suspicious => Some("suspicious"),
                    _ => None,
                };
                if let Some(v) = verdict {
                    let name = report.threat_name.clone().unwrap_or_else(|| "Generic.Multi.AnalystRule".into());
                    hits.push(AnalystHit { engine: "hydradragonsig", name, verdict: v });
                }
            }
        }
        hits
    }

    /// Every analyst ClamAV and HydraDragonSig match of `data` (PUA and low ones
    /// included) explained: signature, score, source file / line and its text,
    /// evidence and file byte ranges (at most `max_ranges` per match).
    pub fn explain(&self, data: &[u8], name: &str, max_ranges: usize) -> Vec<openedr_static::engine::MatchExplain> {
        use openedr_static::engine::MatchExplain;
        let mut out = Vec::new();
        let name = if name.is_empty() { "file" } else { name };
        if let Some(clam) = self.clam.read().unwrap().as_ref() {
            for m in clam.scan_bytes_named(data, name, ClamScanOptions::default(), &[]) {
                let raw = m.object_path == name && matches!(m.view, hydradragonclamav::ScanView::Raw);
                let ranges = if raw { clam.match_ranges(data, &m, max_ranges) } else { Vec::new() };
                let pua = m.name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("PUA."));
                out.push(MatchExplain {
                    engine: "Analyst ClamAV",
                    score: if pua { 0.60 } else { 1.0 },
                    kind: format!("{:?}", m.kind),
                    source: Some(m.source.path.display().to_string()),
                    line: Some(m.source.line),
                    definition: openedr_static::clam::database_line(&m.source.path, m.source.line),
                    object_path: Some(m.object_path.clone()),
                    view: Some(format!("{:?}", m.view)),
                    evidence: Vec::new(),
                    ranges,
                    rule: m.name,
                });
            }
        }
        if let Some(rules) = self.sig.read().unwrap().as_ref() {
            let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: name.to_string(), base_address: None };
            if let Ok(report) = hydradragonsig::scan_memory_owned(ctx, rules, &hydradragonsig::ScanOptions::default()) {
                for f in report.findings {
                    out.push(MatchExplain {
                        engine: "Analyst HydraSig",
                        score: f.score as f32 / 100.0,
                        kind: format!("{} ({:?})", f.title, f.verdict),
                        source: None,
                        line: None,
                        definition: (!f.description.is_empty()).then(|| f.description.clone()),
                        object_path: None,
                        view: None,
                        ranges: openedr_static::string_rules::evidence_ranges(data, &f.evidence, max_ranges),
                        evidence: f.evidence,
                        rule: f.rule_id,
                    });
                }
            }
        }
        out
    }

    /// Byte ranges `(engine, signature, start, end)` behind the analyst ClamAV and
    /// HydraDragonSig matches that are malware (not `PUA.*`, not Pua / Suspicious
    /// findings), at most `limit`. For in-place disinfection only.
    pub fn match_ranges(&self, data: &[u8], name: &str, limit: usize) -> Vec<(&'static str, String, usize, usize)> {
        let mut out = Vec::new();
        let name = if name.is_empty() { "file" } else { name };
        if let Some(clam) = self.clam.read().unwrap().as_ref() {
            for m in clam.scan_bytes_named(data, name, ClamScanOptions::default(), &[]) {
                if m.object_path != name {
                    continue; // an extracted member: its offsets are not file offsets
                }
                if m.name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("PUA.")) {
                    continue; // potentially unwanted, not malware (same as `scan`)
                }
                for (s, e) in clam.match_ranges(data, &m, limit.saturating_sub(out.len())) {
                    out.push(("analyst-clamav", m.name.clone(), s, e));
                }
            }
        }
        if let Some(rules) = self.sig.read().unwrap().as_ref() {
            let ctx = MemoryScanContext { buffer: data.to_vec(), identifier: name.to_string(), base_address: None };
            if let Ok(report) = hydradragonsig::scan_memory_owned(ctx, rules, &hydradragonsig::ScanOptions::default()) {
                for f in report.findings.iter().filter(|f| matches!(f.verdict, SigVerdict::Malware)) {
                    let left = limit.saturating_sub(out.len());
                    if left == 0 {
                        break;
                    }
                    for (s, e) in openedr_static::string_rules::evidence_ranges(data, &f.evidence, left) {
                        out.push(("analyst-hydradragonsig", f.rule_id.clone(), s, e));
                    }
                }
            }
        }
        out.truncate(limit);
        out
    }
}
