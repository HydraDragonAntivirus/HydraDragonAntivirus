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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};

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
}

// ------------------------------------------------------------------ signer_rules helpers

/// Default file stem inside `analyst_signatures/signer_rules/` for quick-added
/// Authenticode signer rules from the dashboard right-click menu.
pub const ANALYST_SIGNERS_FILE: &str = "analyst_signers";

/// One-time migration target inside `analyst_signatures/signer_rules/` for legacy
/// `company_signers.yaml` / `company_signers.jsonl` / `companies_*.txt` entries.
pub const MIGRATED_COMPANY_SIGNERS_FILE: &str = "migrated_company_signers";

static SIGNER_RULES_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SignerRuleDoc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default)]
    rules: Vec<SignerRuleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignerRuleEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(default)]
    verdict: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    family: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidence: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default)]
    conditions: Vec<SignerRuleCond>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignerRuleCond {
    #[serde(rename = "type")]
    cond_type: String,
    #[serde(default)]
    value: String,
    #[serde(default = "default_true")]
    nocase: bool,
}

fn default_true() -> bool {
    true
}

/// Request parameters for adding one quick signer rule from the dashboard.
#[derive(Debug, Clone)]
pub struct QuickSignerRuleInput {
    pub verdict: String,
    pub condition_type: String,
    pub value: String,
    pub reason: String,
    pub title: String,
    pub family: String,
}

/// Summary returned after appending a quick signer rule.
#[derive(Debug, Clone)]
pub struct QuickSignerRuleResult {
    pub file_name: String,
    pub path: PathBuf,
    pub rule_id: String,
    pub rule_count: usize,
}

fn normalize_thumbprint_hex(value: &str) -> Result<String, String> {
    let mut hex = String::with_capacity(40);
    for c in value.trim().chars() {
        if c.is_ascii_hexdigit() {
            hex.push(c.to_ascii_lowercase());
        } else if !matches!(c, ':' | ' ' | '-') {
            return Err(format!("thumbprint contains invalid character {c:?}"));
        }
    }
    if hex.len() != 40 {
        return Err(format!("thumbprint must be 40 hex chars (SHA-1), got {}", hex.len()));
    }
    Ok(hex)
}

fn slugify_rule_id(prefix: &str, raw: &str, used: &HashSet<String>) -> String {
    let raw_slug: String = raw
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = raw_slug
        .split('-')
        .filter(|s| !s.is_empty())
        .take(8)
        .collect::<Vec<_>>()
        .join("-");
    let base = format!(
        "{prefix}-{}",
        if slug.is_empty() { "rule" } else { slug.as_str() }
    );
    if !used.contains(&base) {
        return base;
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}-{n}");
        if !used.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

fn default_signer_rule_title(verdict: &str, cond_type: &str, value: &str) -> String {
    let target = if cond_type.starts_with("signature_issuer_") {
        "issuing CA"
    } else if cond_type.starts_with("signature_timestamp_signer_") {
        "TSA"
    } else if cond_type.starts_with("signature_thumbprint_") {
        "certificate"
    } else {
        "publisher"
    };
    match verdict {
        "trusted" => format!("Trusted {target}: {value}"),
        "pua" => format!("PUA {target}: {value}"),
        _ => format!("Malicious {target}: {value}"),
    }
}

fn canonical_verdict(v: &str) -> Option<&'static str> {
    match v.trim().to_ascii_lowercase().as_str() {
        "trusted" => Some("trusted"),
        "malware" | "malicious" => Some("malware"),
        "pua" => Some("pua"),
        _ => None,
    }
}

fn write_signer_rules_doc(path: &Path, doc: &SignerRuleDoc, header: &str) -> Result<usize, String> {
    let yaml_body = yaml_serde::to_string(doc).map_err(|e| format!("failed to serialize signer rules YAML: {e}"))?;
    let full = format!("{header}{yaml_body}");
    let count = validate_signer_rules(&full)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, &full).map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("failed to save {}: {e}", path.display()))?;
    Ok(count)
}

/// Appends one validated Authenticode signer rule into
/// `analyst_signatures/signer_rules/analyst_signers.yaml`.
pub fn append_quick_signer_rule(input: QuickSignerRuleInput) -> Result<QuickSignerRuleResult, String> {
    append_quick_signer_rule_in(&crate::human_review::analyst_dir(), input)
}

fn append_quick_signer_rule_in(analyst_root: &Path, input: QuickSignerRuleInput) -> Result<QuickSignerRuleResult, String> {
    let verdict = canonical_verdict(&input.verdict)
        .ok_or_else(|| "verdict must be 'trusted', 'malware', or 'pua'".to_string())?;
    let raw_cond = input.condition_type.trim();
    let cond_type = if raw_cond.is_empty() {
        "signature_signer_equals"
    } else {
        raw_cond
    };
    if !SIGNER_CONDITION_TYPES.contains(&cond_type) {
        return Err(format!(
            "unsupported signer condition type {cond_type:?} (supported: {})",
            SIGNER_CONDITION_TYPES.join(", ")
        ));
    }
    if verdict == "trusted" && !cond_type.starts_with("signature_signer_") {
        return Err("trusted rules only support publisher conditions (signature_signer_equals / signature_signer_contains)".into());
    }
    if verdict == "pua" && !cond_type.starts_with("signature_signer_") && !cond_type.starts_with("signature_issuer_") {
        return Err("PUA signer rules only support publisher or issuing CA conditions".into());
    }

    let raw_val = input.value.trim();
    if raw_val.is_empty() {
        return Err("certificate field value cannot be empty".into());
    }
    if raw_val.chars().count() > 256 {
        return Err("certificate field value is too long (max 256 chars)".into());
    }
    let value = if cond_type.starts_with("signature_thumbprint_") {
        normalize_thumbprint_hex(raw_val)?
    } else {
        raw_val.to_string()
    };

    let reason = input.reason.trim().to_string();
    if reason.chars().count() < 3 {
        return Err("Reason is mandatory (at least 3 characters)".into());
    }

    let family = if verdict == "trusted" {
        String::new()
    } else {
        input.family.trim().to_string()
    };
    let title = {
        let t = input.title.trim();
        if t.is_empty() {
            default_signer_rule_title(verdict, cond_type, &value)
        } else {
            t.to_string()
        }
    };
    let severity = match verdict {
        "trusted" => "info",
        "pua" => "medium",
        _ => "high",
    }
    .to_string();

    let _guard = SIGNER_RULES_LOCK.lock().unwrap();
    let path = analyst_root.join("signer_rules").join(format!("{ANALYST_SIGNERS_FILE}.yaml"));
    let mut doc = if path.is_file() {
        let src = std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        yaml_serde::from_str::<SignerRuleDoc>(&src)
            .map_err(|e| format!("existing {ANALYST_SIGNERS_FILE}.yaml is invalid ({e}); fix it in Signature Room first"))?
    } else {
        SignerRuleDoc {
            name: Some("Analyst Signer Rules".to_string()),
            version: Some("1".to_string()),
            rules: Vec::new(),
        }
    };
    if doc.name.is_none() {
        doc.name = Some("Analyst Signer Rules".to_string());
    }
    if doc.version.is_none() {
        doc.version = Some("1".to_string());
    }

    let val_lower = value.to_ascii_lowercase();
    for existing in &doc.rules {
        let ex_verdict = canonical_verdict(&existing.verdict).unwrap_or("");
        for cond in &existing.conditions {
            if cond.cond_type == cond_type && cond.value.trim().to_ascii_lowercase() == val_lower {
                if ex_verdict == verdict {
                    return Err(format!(
                        "A {verdict} rule for {cond_type} = \"{value}\" already exists in {ANALYST_SIGNERS_FILE}.yaml (id: {}).",
                        existing.id
                    ));
                }
                return Err(format!(
                    "{cond_type} = \"{value}\" already has verdict \"{ex_verdict}\" in {ANALYST_SIGNERS_FILE}.yaml (id: {}); edit or remove it in Signature Room first.",
                    existing.id
                ));
            }
        }
    }

    let used_ids: HashSet<String> = doc.rules.iter().map(|r| r.id.trim().to_string()).collect();
    let rule_id = slugify_rule_id(&format!("analyst-{verdict}"), &value, &used_ids);
    doc.rules.push(SignerRuleEntry {
        id: rule_id.clone(),
        title,
        description: reason,
        verdict: verdict.to_string(),
        family,
        severity,
        confidence: None,
        score: None,
        tags: Vec::new(),
        conditions: vec![SignerRuleCond {
            cond_type: cond_type.to_string(),
            value,
            nocase: true,
        }],
    });

    const HEADER: &str = "# Analyst Authenticode signer rules managed via quick-add & Signature Room.\n# Loaded into StaticEngine (`openedr_static::signers`).\n";
    let count = write_signer_rules_doc(&path, &doc, HEADER)?;
    Ok(QuickSignerRuleResult {
        file_name: ANALYST_SIGNERS_FILE.to_string(),
        path,
        rule_id,
        rule_count: count,
    })
}

// ------------------------------------------------------------------ legacy company-list migration

#[derive(Debug, Deserialize)]
struct LegacyCompanyYamlFile {
    #[serde(default)]
    rules: Vec<LegacyCompanyYamlRule>,
}

#[derive(Debug, Deserialize)]
struct LegacyCompanyYamlRule {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    conditions: Vec<LegacyCompanyYamlCond>,
}

#[derive(Debug, Deserialize)]
struct LegacyCompanyYamlCond {
    #[serde(rename = "type", default)]
    cond_type: String,
    #[serde(default)]
    value: String,
    #[serde(default = "default_true")]
    nocase: bool,
}

#[derive(Debug, Deserialize)]
struct LegacyCompanyJsonEntry {
    name: String,
    list: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    aliases: Vec<String>,
}

fn legacy_verdict(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "trusted" | "allow" | "clean" => Some("trusted"),
        "malware" | "malicious" | "block" => Some("malware"),
        "pua" => Some("pua"),
        _ => None,
    }
}

fn map_legacy_condition(verdict: &str, raw_type: &str, raw_value: &str, nocase: bool) -> Option<SignerRuleCond> {
    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let t = raw_type.trim();
    if verdict == "trusted" {
        let cond_type = if t == "signature_signer_contains" {
            "signature_signer_contains"
        } else {
            "signature_signer_equals"
        };
        return Some(SignerRuleCond {
            cond_type: cond_type.to_string(),
            value: trimmed.to_string(),
            nocase,
        });
    }
    if t == "signature_thumbprint_equals" || t == "signature_thumbprint_any" {
        if let Ok(hex) = normalize_thumbprint_hex(trimmed) {
            return Some(SignerRuleCond {
                cond_type: t.to_string(),
                value: hex,
                nocase: true,
            });
        }
        return Some(SignerRuleCond {
            cond_type: "signature_signer_equals".to_string(),
            value: trimmed.to_string(),
            nocase,
        });
    }
    if SIGNER_CONDITION_TYPES.contains(&t) {
        return Some(SignerRuleCond {
            cond_type: t.to_string(),
            value: trimmed.to_string(),
            nocase,
        });
    }
    if let Ok(hex) = normalize_thumbprint_hex(trimmed) {
        return Some(SignerRuleCond {
            cond_type: "signature_thumbprint_equals".to_string(),
            value: hex,
            nocase: true,
        });
    }
    Some(SignerRuleCond {
        cond_type: "signature_signer_equals".to_string(),
        value: trimmed.to_string(),
        nocase,
    })
}

fn backup_legacy_path(src: &Path) -> PathBuf {
    let base_name = src
        .file_name()
        .map(|n| format!("{}.migrated", n.to_string_lossy()))
        .unwrap_or_else(|| "legacy.migrated".to_string());
    let first = src.with_file_name(&base_name);
    if !first.exists() {
        return first;
    }
    let mut n = 2usize;
    loop {
        let candidate = src.with_file_name(format!("{base_name}.{n}"));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// One-time migration from legacy `company_signers.yaml`, `company_signers.jsonl`,
/// `companies_allow.txt`, and `companies_block.txt` into
/// `analyst_signatures/signer_rules/migrated_company_signers.yaml`.
/// Runs at engine startup / reload before reading `signer_rules/*.yaml`.
pub fn migrate_legacy_company_lists() {
    migrate_legacy_company_lists_in(&crate::human_review::analyst_dir());
}

fn migrate_legacy_company_lists_in(analyst_root: &Path) {
    use std::io::{BufRead, BufReader};

    let _guard = SIGNER_RULES_LOCK.lock().unwrap();
    let legacy_names = [
        "company_signers.yaml",
        "company_signers.jsonl",
        "companies_allow.txt",
        "companies_block.txt",
    ];
    let present: Vec<PathBuf> = legacy_names
        .iter()
        .map(|n| analyst_root.join(n))
        .filter(|p| p.is_file())
        .collect();
    if present.is_empty() {
        return;
    }

    let mut migrated_rules: Vec<SignerRuleEntry> = Vec::new();
    let mut used_ids: HashSet<String> = HashSet::new();
    let mut seen_keys: HashSet<(String, String, String)> = HashSet::new();

    let dest = analyst_root
        .join("signer_rules")
        .join(format!("{MIGRATED_COMPANY_SIGNERS_FILE}.yaml"));
    let mut doc = if dest.is_file() {
        match std::fs::read_to_string(&dest)
            .map_err(|e| e.to_string())
            .and_then(|s| yaml_serde::from_str::<SignerRuleDoc>(&s).map_err(|e| e.to_string()))
        {
            Ok(existing) => existing,
            Err(e) => {
                eprintln!("[engine] existing {} is invalid ({e}); skipping legacy company migration", dest.display());
                return;
            }
        }
    } else {
        SignerRuleDoc {
            name: Some("Migrated Company Signer Rules".to_string()),
            version: Some("1".to_string()),
            rules: Vec::new(),
        }
    };
    if doc.name.is_none() {
        doc.name = Some("Migrated Company Signer Rules".to_string());
    }
    if doc.version.is_none() {
        doc.version = Some("1".to_string());
    }
    for r in &doc.rules {
        used_ids.insert(r.id.trim().to_string());
        if let Some(v) = canonical_verdict(&r.verdict) {
            for c in &r.conditions {
                seen_keys.insert((v.to_string(), c.cond_type.clone(), c.value.trim().to_ascii_lowercase()));
            }
        }
    }

    let mut push_rule = |verdict: &str, title: String, description: String, family: String, conditions: Vec<SignerRuleCond>| {
        let filtered: Vec<SignerRuleCond> = conditions
            .into_iter()
            .filter(|c| seen_keys.insert((verdict.to_string(), c.cond_type.clone(), c.value.to_ascii_lowercase())))
            .collect();
        if filtered.is_empty() {
            return;
        }
        let primary = &filtered[0];
        let final_title = if title.trim().is_empty() {
            default_signer_rule_title(verdict, &primary.cond_type, &primary.value)
        } else {
            title.trim().to_string()
        };
        let id = slugify_rule_id(&format!("migrated-{verdict}"), &primary.value, &used_ids);
        used_ids.insert(id.clone());
        migrated_rules.push(SignerRuleEntry {
            id,
            title: final_title,
            description: if description.trim().is_empty() {
                "Migrated from legacy company list.".to_string()
            } else {
                description.trim().to_string()
            },
            verdict: verdict.to_string(),
            family: if verdict == "trusted" { String::new() } else { family.trim().to_string() },
            severity: if verdict == "trusted" { "info" } else { "high" }.to_string(),
            confidence: None,
            score: None,
            tags: Vec::new(),
            conditions: filtered,
        });
    };

    let yaml_path = analyst_root.join("company_signers.yaml");
    if yaml_path.is_file() {
        let raw = match std::fs::read_to_string(&yaml_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[engine] could not read {}: {e}; leaving legacy files untouched", yaml_path.display());
                return;
            }
        };
        let parsed: LegacyCompanyYamlFile = match yaml_serde::from_str(&raw) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[engine] legacy company_signers.yaml parse error ({e}); leaving legacy files untouched");
                return;
            }
        };
        for r in parsed.rules {
            let Some(verdict) = legacy_verdict(&r.verdict) else { continue };
            let conds: Vec<SignerRuleCond> = r
                .conditions
                .into_iter()
                .filter_map(|c| map_legacy_condition(verdict, &c.cond_type, &c.value, c.nocase))
                .collect();
            push_rule(verdict, r.title, r.description, r.family, conds);
        }
    } else {
        let jsonl_path = analyst_root.join("company_signers.jsonl");
        let mut legacy_entries: HashMap<(String, String), LegacyCompanyJsonEntry> = HashMap::new();
        if let Ok(f) = std::fs::File::open(&jsonl_path) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                let Some(name) = v["name"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else { continue };
                let Some(list) = v["list"].as_str().and_then(legacy_verdict) else { continue };
                let key = (name.to_ascii_lowercase(), list.to_string());
                if v["removed"].as_bool() == Some(true) {
                    legacy_entries.remove(&key);
                } else if let Ok(mut e) = serde_json::from_value::<LegacyCompanyJsonEntry>(v) {
                    e.name = name;
                    e.list = list.to_string();
                    legacy_entries.insert(key, e);
                }
            }
        }
        for (file_name, verdict) in [("companies_allow.txt", "trusted"), ("companies_block.txt", "malware")] {
            if let Ok(text) = std::fs::read_to_string(analyst_root.join(file_name)) {
                for line in text.lines() {
                    let mut parts = line.splitn(2, '#');
                    let clean = parts.next().unwrap_or("").trim();
                    let comment = parts.next().unwrap_or("").trim();
                    if clean.is_empty() {
                        continue;
                    }
                    let key = (clean.to_ascii_lowercase(), verdict.to_string());
                    legacy_entries.entry(key).or_insert_with(|| LegacyCompanyJsonEntry {
                        name: clean.to_string(),
                        list: verdict.to_string(),
                        reason: comment.to_string(),
                        title: String::new(),
                        family: String::new(),
                        aliases: Vec::new(),
                    });
                }
            }
        }
        let mut entries: Vec<LegacyCompanyJsonEntry> = legacy_entries.into_values().collect();
        entries.sort_by(|a, b| (a.list.as_str(), a.name.to_ascii_lowercase()).cmp(&(b.list.as_str(), b.name.to_ascii_lowercase())));
        for e in entries {
            let conds: Vec<SignerRuleCond> = std::iter::once(e.name)
                .chain(e.aliases)
                .filter_map(|val| map_legacy_condition(&e.list, "", &val, true))
                .collect();
            push_rule(&e.list, e.title, e.reason, e.family, conds);
        }
    }

    let added_count = migrated_rules.len();
    if added_count > 0 {
        doc.rules.extend(migrated_rules);
        const HEADER: &str = "# Automatically migrated from legacy company signer lists into signer_rules/*.yaml.\n";
        if let Err(e) = write_signer_rules_doc(&dest, &doc, HEADER) {
            eprintln!("[engine] failed to write {}: {e}; leaving legacy files untouched", dest.display());
            return;
        }
        eprintln!(
            "[engine] migrated {added_count} legacy company signer rule(s) into signer_rules/{MIGRATED_COMPANY_SIGNERS_FILE}.yaml"
        );
    }

    for src in present {
        let bak = backup_legacy_path(&src);
        if let Err(e) = std::fs::rename(&src, &bak) {
            eprintln!("[engine] warning: could not archive legacy file {}: {e}", src.display());
        }
    }
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

        let msg = format!(
            "analyst signatures: clamav {clam_loaded} sigs from {clam_count} files ({clam_errors} errors), hydradragonsig {sig_rules} rules ({} files failed)",
            sig_failed.len()
        );
        eprintln!("[engine] {msg}");
        msg
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(1);

    fn temp_analyst_dir(tag: &str) -> PathBuf {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("multron_signer_{tag}_{}_{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn quick_add_validates_and_appends_signer_rules() {
        let dir = temp_analyst_dir("quick");

        // 1. Trusted publisher succeeds
        let r1 = append_quick_signer_rule_in(
            &dir,
            QuickSignerRuleInput {
                verdict: "trusted".into(),
                condition_type: "signature_signer_equals".into(),
                value: "Contoso Software Ltd.".into(),
                reason: "Verified clean developer build".into(),
                title: String::new(),
                family: String::new(),
            },
        )
        .expect("trusted rule succeeds");
        assert_eq!(r1.rule_count, 1);

        // 2. Trusted + issuer is rejected
        let err_trust_issuer = append_quick_signer_rule_in(
            &dir,
            QuickSignerRuleInput {
                verdict: "trusted".into(),
                condition_type: "signature_issuer_equals".into(),
                value: "Some Root CA".into(),
                reason: "Bad idea to trust entire CA".into(),
                title: String::new(),
                family: String::new(),
            },
        )
        .unwrap_err();
        assert!(err_trust_issuer.contains("publisher conditions"));

        // 3. PUA + thumbprint is rejected (SignerDb only checks PUA publishers & issuers)
        let err_pua_tp = append_quick_signer_rule_in(
            &dir,
            QuickSignerRuleInput {
                verdict: "pua".into(),
                condition_type: "signature_thumbprint_equals".into(),
                value: "00112233445566778899aabbccddeeff00112233".into(),
                reason: "Unsupported PUA thumbprint".into(),
                title: String::new(),
                family: String::new(),
            },
        )
        .unwrap_err();
        assert!(err_pua_tp.contains("PUA signer rules only support"));

        // 4. Conflicting verdict for same publisher is rejected
        let err_conflict = append_quick_signer_rule_in(
            &dir,
            QuickSignerRuleInput {
                verdict: "malware".into(),
                condition_type: "signature_signer_equals".into(),
                value: "contoso software ltd.".into(),
                reason: "Conflict check".into(),
                title: String::new(),
                family: String::new(),
            },
        )
        .unwrap_err();
        assert!(err_conflict.contains("already has verdict"));

        // 5. Malware thumbprint (colon format normalized to 40 lowercase hex) + PUA issuer
        let r2 = append_quick_signer_rule_in(
            &dir,
            QuickSignerRuleInput {
                verdict: "malware".into(),
                condition_type: "signature_thumbprint_equals".into(),
                value: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD".into(),
                reason: "Stolen leaf cert".into(),
                title: "Revoked leaf".into(),
                family: "Trojan.Win32.StolenCert".into(),
            },
        )
        .expect("malware thumbprint succeeds");
        assert_eq!(r2.rule_count, 2);

        let r3 = append_quick_signer_rule_in(
            &dir,
            QuickSignerRuleInput {
                verdict: "pua".into(),
                condition_type: "signature_issuer_contains".into(),
                value: "Adware Intermediate".into(),
                reason: "Adware bundler CA".into(),
                title: String::new(),
                family: "PUA.Win32.Bundler".into(),
            },
        )
        .expect("pua issuer succeeds");
        assert_eq!(r3.rule_count, 3);

        let saved = std::fs::read_to_string(&r3.path).unwrap();
        assert_eq!(validate_signer_rules(&saved), Ok(3));
        assert!(saved.contains("aabbccddeeff00112233445566778899aabbccdd"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_legacy_txt_and_yaml_into_signer_rules() {
        let dir = temp_analyst_dir("mig_txt");
        std::fs::write(
            dir.join("companies_allow.txt"),
            "Beijing Huorong Network Technology Co., Ltd. # Huorong AV\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("companies_block.txt"),
            "Evil Signer Corp # Fake updater\n00112233445566778899aabbccddeeff00112233 # Leaked leaf\n",
        )
        .unwrap();

        migrate_legacy_company_lists_in(&dir);

        let migrated = dir.join("signer_rules").join(format!("{MIGRATED_COMPANY_SIGNERS_FILE}.yaml"));
        assert!(migrated.is_file());
        let yaml = std::fs::read_to_string(&migrated).unwrap();
        assert_eq!(validate_signer_rules(&yaml), Ok(3));
        assert!(yaml.contains("Beijing Huorong Network Technology Co., Ltd."));
        assert!(yaml.contains("signature_thumbprint_equals"));
        assert!(!dir.join("companies_allow.txt").exists());
        assert!(!dir.join("companies_block.txt").exists());
        assert!(dir.join("companies_allow.txt.migrated").is_file());
        assert!(dir.join("companies_block.txt.migrated").is_file());

        // Second run is a clean no-op
        migrate_legacy_company_lists_in(&dir);
        assert_eq!(validate_signer_rules(&std::fs::read_to_string(&migrated).unwrap()), Ok(3));
        let _ = std::fs::remove_dir_all(&dir);

        // Legacy YAML with family, aliases & invalid-for-trusted condition is normalized safely
        let dir_yaml = temp_analyst_dir("mig_yaml");
        std::fs::write(
            dir_yaml.join("company_signers.yaml"),
            r#"
name: Analyst Company Signer Rules
version: "1"
rules:
  - id: company-block-shady
    title: "Blocked company: Shady Software"
    description: "Bundled adware"
    verdict: malware
    family: "PUA.Win32.Shady"
    conditions:
      - type: signature_signer_equals
        value: "Shady Software Ltd"
        nocase: true
      - type: signature_signer_equals
        value: "Shady Alias LLC"
        nocase: true
"#,
        )
        .unwrap();
        migrate_legacy_company_lists_in(&dir_yaml);
        let out_yaml = dir_yaml.join("signer_rules").join(format!("{MIGRATED_COMPANY_SIGNERS_FILE}.yaml"));
        assert_eq!(validate_signer_rules(&std::fs::read_to_string(&out_yaml).unwrap()), Ok(1));
        assert!(dir_yaml.join("company_signers.yaml.migrated").is_file());
        let _ = std::fs::remove_dir_all(&dir_yaml);
    }

    #[test]
    fn migrate_skips_and_preserves_broken_legacy_yaml() {
        let dir = temp_analyst_dir("mig_broken");
        std::fs::write(dir.join("company_signers.yaml"), "rules: [broken: yaml: :").unwrap();
        migrate_legacy_company_lists_in(&dir);
        assert!(dir.join("company_signers.yaml").is_file());
        assert!(!dir.join("company_signers.yaml.migrated").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repo_trusted_signers_yaml_validates() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../analyst_signatures/signer_rules/trusted_signers.yaml");
        let src = std::fs::read_to_string(&p).expect("read trusted_signers.yaml");
        assert_eq!(validate_signer_rules(&src), Ok(1));
        assert!(src.contains("Beijing Huorong Network Technology Co., Ltd."));
    }
}
