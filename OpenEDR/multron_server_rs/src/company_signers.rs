//! Analyst company (signer) list management with reasons and sample tracking.
//!
//! The lists live in `analyst_signatures/company_signers.yaml`, written in the
//! same rule format as `signer_rules/trusted_signers.yaml` (one rule per
//! company: id, title, description, verdict, family, conditions), so each
//! entry carries its own details into the verdict and can be edited by hand.
//! `company_signers.jsonl` stays the append-only audit log of every change.
//!
//! The old `companies_allow.txt` / `companies_block.txt` lists are read once,
//! when no YAML exists yet, and converted into it; they are left on disk
//! untouched and are not read again.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::{OnceLock, RwLock};

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanySignerEntry {
    /// Signer name as in the Authenticode certificate.
    pub name: String,
    /// "allow" or "block".
    pub list: String,
    /// Reason / justification for allowing or blocking.
    #[serde(default)]
    pub reason: String,
    /// Sample SHA-256 the decision was based on (if any).
    #[serde(default)]
    pub sha256: String,
    /// Optional sample file name.
    #[serde(default)]
    pub sample_name: String,
    /// Analyst identifier.
    #[serde(default)]
    pub analyst: String,
    /// Timestamp added (RFC 3339).
    #[serde(default)]
    pub added: String,
    /// Rule title shown in the verdict (default: "Trusted company: <name>" /
    /// "Blocked company: <name>").
    #[serde(default)]
    pub title: String,
    /// Block list: the detection name to report (default
    /// `Riskware.Multi.BlockedSigner (<name>)`). Unused for the allow list.
    #[serde(default)]
    pub family: String,
    /// More names the same rule matches (extra `conditions` of a hand-written rule).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

// ---------------------------------------------------------------- YAML file

/// One condition of a company rule. Matched as before the YAML: the value
/// equals (case-insensitively) the publisher, the issuing CA, the
/// countersigning authority or the leaf thumbprint of a signed file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlCondition {
    #[serde(rename = "type", default = "default_cond_type")]
    cond_type: String,
    value: String,
    #[serde(default = "default_true")]
    nocase: bool,
}

fn default_cond_type() -> String {
    "signature_signer_equals".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    /// `trusted` (allow list) or `malware` (block list).
    #[serde(default)]
    verdict: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    family: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    analyst: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    added: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sample_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sample_name: String,
    #[serde(default)]
    conditions: Vec<YamlCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlFile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    rules: Vec<YamlRule>,
}

pub const YAML_FILE: &str = "company_signers.yaml";

fn yaml_path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join(YAML_FILE)
}

fn rule_id(name: &str, list: &str) -> String {
    let slug: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let slug = slug.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-");
    format!("company-{list}-{}", if slug.is_empty() { "unnamed".to_string() } else { slug })
}

fn entry_to_rule(e: &CompanySignerEntry) -> YamlRule {
    let allow = e.list == "allow";
    let mut conditions = vec![YamlCondition { cond_type: default_cond_type(), value: e.name.clone(), nocase: true }];
    for a in &e.aliases {
        conditions.push(YamlCondition { cond_type: default_cond_type(), value: a.clone(), nocase: true });
    }
    YamlRule {
        id: rule_id(&e.name, &e.list),
        title: if e.title.trim().is_empty() {
            format!("{} company: {}", if allow { "Trusted" } else { "Blocked" }, e.name)
        } else {
            e.title.clone()
        },
        description: e.reason.clone(),
        verdict: if allow { "trusted".into() } else { "malware".into() },
        family: if allow { String::new() } else { e.family.clone() },
        analyst: e.analyst.clone(),
        added: e.added.clone(),
        sample_sha256: e.sha256.clone(),
        sample_name: e.sample_name.clone(),
        conditions,
    }
}

fn rule_to_entry(r: YamlRule) -> Option<CompanySignerEntry> {
    let list = match r.verdict.trim().to_ascii_lowercase().as_str() {
        "trusted" | "allow" | "clean" => "allow",
        "malware" | "malicious" | "block" => "block",
        _ => return None,
    };
    let mut names = r.conditions.into_iter().map(|c| c.value.trim().to_string()).filter(|v| !v.is_empty());
    let name = names.next()?;
    Some(CompanySignerEntry {
        name,
        list: list.to_string(),
        reason: r.description.trim().to_string(),
        sha256: r.sample_sha256,
        sample_name: r.sample_name,
        analyst: r.analyst,
        added: r.added,
        title: r.title.trim().to_string(),
        family: r.family.trim().to_string(),
        aliases: names.collect(),
    })
}

/// Reads `company_signers.yaml`. `Err` when it exists but does not parse: the
/// caller keeps what it had instead of dropping every list entry.
fn read_yaml() -> Result<Option<HashMap<(String, String), CompanySignerEntry>>, String> {
    let text = match std::fs::read_to_string(yaml_path()) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let file: YamlFile = yaml_serde::from_str(&text).map_err(|e| format!("{YAML_FILE}: {e}"))?;
    let mut m = HashMap::new();
    for r in file.rules {
        if let Some(e) = rule_to_entry(r) {
            m.insert(key(&e.name, &e.list), e);
        }
    }
    Ok(Some(m))
}

fn write_yaml(m: &HashMap<(String, String), CompanySignerEntry>) -> std::io::Result<()> {
    let mut v: Vec<&CompanySignerEntry> = m.values().collect();
    v.sort_by(|a, b| (a.list.as_str(), a.name.to_ascii_lowercase()).cmp(&(b.list.as_str(), b.name.to_ascii_lowercase())));
    let file = YamlFile {
        name: "Analyst Company Signer Rules".to_string(),
        version: "1".to_string(),
        rules: v.into_iter().map(entry_to_rule).collect(),
    };
    let body = yaml_serde::to_string(&file).map_err(|e| std::io::Error::other(e.to_string()))?;
    let header = "# Analyst company (Authenticode signer) rules, same format as signer_rules/*.yaml.\n\
# verdict: trusted -> allow list (needs a valid signature), malware -> block list.\n\
# description is the reason shown in the verdict; family (block only) is the detection name.\n\
# Each condition value matches the publisher, issuing CA, countersigner or thumbprint\n\
# (case-insensitive, whole name). Saved from the dashboard; hand edits are kept.\n";
    let tmp = yaml_path().with_extension("yaml.tmp");
    std::fs::write(&tmp, format!("{header}{body}"))?;
    std::fs::rename(&tmp, yaml_path())
}

fn path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join("company_signers.jsonl")
}

fn entries() -> &'static RwLock<HashMap<(String, String), CompanySignerEntry>> {
    static E: OnceLock<RwLock<HashMap<(String, String), CompanySignerEntry>>> = OnceLock::new();
    E.get_or_init(|| RwLock::new(load()))
}

fn key(name: &str, list: &str) -> (String, String) {
    (name.trim().to_ascii_lowercase(), list.trim().to_ascii_lowercase())
}

fn load() -> HashMap<(String, String), CompanySignerEntry> {
    match read_yaml() {
        Ok(Some(m)) => return m,
        Ok(None) => {}
        Err(e) => {
            // Never fall back to the old lists over a broken YAML: that would
            // silently replace the analyst's rules. Empty until it is fixed.
            eprintln!("[companies] {e}; company lists are empty until it is fixed");
            return HashMap::new();
        }
    }
    let m = load_legacy();
    if !m.is_empty() {
        match write_yaml(&m) {
            Ok(()) => eprintln!(
                "[companies] converted {} entries from companies_*.txt / company_signers.jsonl into {YAML_FILE} (the old files are left as they are)",
                m.len()
            ),
            Err(e) => eprintln!("[companies] could not write {YAML_FILE}: {e}"),
        }
    }
    m
}

/// Re-reads `company_signers.yaml` (hand edits included). A YAML that does
/// not parse keeps the entries already loaded. Returns the error, if any.
pub fn reload_from_disk() -> Option<String> {
    match read_yaml() {
        Ok(Some(m)) => {
            *entries().write().unwrap() = m;
            None
        }
        Ok(None) => None,
        Err(e) => Some(e),
    }
}

/// The pre-YAML lists: `company_signers.jsonl` plus `companies_allow.txt` /
/// `companies_block.txt`. Only read to build the first `company_signers.yaml`.
fn load_legacy() -> HashMap<(String, String), CompanySignerEntry> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path()) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let Some(name) = v["name"].as_str().map(|n| n.trim().to_string()) else { continue };
            let Some(list) = v["list"].as_str().map(|l| l.trim().to_ascii_lowercase()) else { continue };
            if name.is_empty() || (list != "allow" && list != "block") {
                continue;
            }
            let k = (name.to_ascii_lowercase(), list.clone());
            if v["removed"].as_bool() == Some(true) {
                m.remove(&k);
            } else if let Ok(e) = serde_json::from_value::<CompanySignerEntry>(v) {
                m.insert(k, e);
            }
        }
    }
    // Also merge any existing entries from companies_allow.txt and companies_block.txt
    let dir = crate::human_review::analyst_dir();
    for (file, list_name) in [("companies_allow.txt", "allow"), ("companies_block.txt", "block")] {
        if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
            for line in text.lines() {
                let mut parts = line.splitn(2, '#');
                let clean = parts.next().unwrap_or("").trim();
                let comment = parts.next().unwrap_or("").trim();
                if clean.is_empty() {
                    continue;
                }
                let k = (clean.to_ascii_lowercase(), list_name.to_string());
                if !m.contains_key(&k) {
                    m.insert(k, CompanySignerEntry {
                        name: clean.to_string(),
                        list: list_name.to_string(),
                        reason: if !comment.is_empty() { comment.to_string() } else { "Company list entry".to_string() },
                        sha256: String::new(),
                        sample_name: String::new(),
                        analyst: "system".to_string(),
                        added: Utc::now().to_rfc3339(),
                        title: String::new(),
                        family: String::new(),
                        aliases: Vec::new(),
                    });
                }
            }
        }
    }
    m
}

fn append_json(v: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path())?;
    writeln!(f, "{v}")
}

pub fn list() -> Vec<CompanySignerEntry> {
    let g = entries().read().unwrap();
    let mut v: Vec<_> = g.values().cloned().collect();
    v.sort_by(|a, b| b.added.cmp(&a.added));
    v
}

pub fn add(mut entry: CompanySignerEntry) -> Result<CompanySignerEntry, String> {
    let name = entry.name.trim();
    if name.is_empty() {
        return Err("Signer name cannot be empty".into());
    }
    if name.len() > 200 {
        return Err("Signer name is too long (max 200 chars)".into());
    }
    let list = entry.list.trim().to_ascii_lowercase();
    if list != "allow" && list != "block" {
        return Err("List must be 'allow' or 'block'".into());
    }
    let reason = entry.reason.trim();
    if reason.len() < 3 {
        return Err("Please provide a reason (at least 3 characters)".into());
    }
    entry.name = name.to_string();
    entry.list = list.clone();
    entry.reason = reason.to_string();
    if entry.added.is_empty() {
        entry.added = Utc::now().to_rfc3339();
    }

    let other_list = if list == "allow" { "block" } else { "allow" };
    let k = key(&entry.name, &list);
    let other_k = key(&entry.name, other_list);

    let mut guard = entries().write().unwrap();
    if guard.contains_key(&other_k) {
        return Err(format!(
            "Signer '{}' is already in the {}-list. Remove it first.",
            entry.name, other_list
        ));
    }

    let val = serde_json::to_value(&entry).map_err(|e| e.to_string())?;
    append_json(&val).map_err(|e| format!("Failed to persist entry: {e}"))?;
    guard.insert(k, entry.clone());
    write_yaml(&guard).map_err(|e| format!("Failed to update {YAML_FILE}: {e}"))?;

    Ok(entry)
}

pub fn sync_raw_lists(allow: &[String], block: &[String], analyst: &str) -> Result<(), String> {
    let mut guard = entries().write().unwrap();
    let now = Utc::now().to_rfc3339();

    // Remove any items that are no longer in the raw lists
    let allow_set: std::collections::HashSet<String> = allow.iter().map(|s| s.split('#').next().unwrap_or("").trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
    let block_set: std::collections::HashSet<String> = block.iter().map(|s| s.split('#').next().unwrap_or("").trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();

    let mut to_remove = Vec::new();
    for ((name, list), _) in guard.iter() {
        if list == "allow" && !allow_set.contains(name) {
            to_remove.push((name.clone(), list.clone()));
        } else if list == "block" && !block_set.contains(name) {
            to_remove.push((name.clone(), list.clone()));
        }
    }
    for (name, list) in to_remove {
        guard.remove(&(name.clone(), list.clone()));
        let _ = append_json(&serde_json::json!({
            "name": name,
            "list": list,
            "removed": true,
            "removed_at": now,
        }));
    }

    // Add any new items
    for line in allow {
        let mut parts = line.splitn(2, '#');
        let clean = parts.next().unwrap_or("").trim();
        let comment = parts.next().unwrap_or("").trim();
        if clean.is_empty() { continue; }
        let k = (clean.to_ascii_lowercase(), "allow".to_string());
        if !guard.contains_key(&k) {
            let entry = CompanySignerEntry {
                name: clean.to_string(),
                list: "allow".to_string(),
                reason: if !comment.is_empty() { comment.to_string() } else { "Saved from company lists".to_string() },
                sha256: String::new(),
                sample_name: String::new(),
                analyst: analyst.to_string(),
                added: now.clone(),
                title: String::new(),
                family: String::new(),
                aliases: Vec::new(),
            };
            if let Ok(v) = serde_json::to_value(&entry) {
                let _ = append_json(&v);
            }
            guard.insert(k, entry);
        }
    }
    for line in block {
        let mut parts = line.splitn(2, '#');
        let clean = parts.next().unwrap_or("").trim();
        let comment = parts.next().unwrap_or("").trim();
        if clean.is_empty() { continue; }
        let k = (clean.to_ascii_lowercase(), "block".to_string());
        if !guard.contains_key(&k) {
            let entry = CompanySignerEntry {
                name: clean.to_string(),
                list: "block".to_string(),
                reason: if !comment.is_empty() { comment.to_string() } else { "Saved from company lists".to_string() },
                sha256: String::new(),
                sample_name: String::new(),
                analyst: analyst.to_string(),
                added: now.clone(),
                title: String::new(),
                family: String::new(),
                aliases: Vec::new(),
            };
            if let Ok(v) = serde_json::to_value(&entry) {
                let _ = append_json(&v);
            }
            guard.insert(k, entry);
        }
    }

    write_yaml(&guard).map_err(|e| format!("Failed to update {YAML_FILE}: {e}"))
}
