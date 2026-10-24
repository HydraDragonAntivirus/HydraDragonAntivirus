//! Analyst YARA rule classes: what a match of a rule means, set by rule name from the
//! dashboard (e.g. `RAT_VNC` matches remote-access tools that are not malware by
//! themselves → Suspicious instead of Malicious). Wins over the rule's name and
//! metadata (`openedr_static::yara::rule_class`). Kept in
//! `analyst_signatures/yara_rule_classes.jsonl` (append-only: a later line for the same
//! rule replaces the earlier one, `"removed": true` deletes it).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::{OnceLock, RwLock};

use openedr_static::yara::RuleClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleClassEntry {
    /// YARA rule identifier as written by the analyst (matched in any case).
    pub rule: String,
    /// `suspicious`, `pua` or `malware`.
    pub class: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub analyst: String,
    #[serde(default)]
    pub added: String,
}

fn path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join("yara_rule_classes.jsonl")
}

fn entries() -> &'static RwLock<HashMap<String, RuleClassEntry>> {
    static E: OnceLock<RwLock<HashMap<String, RuleClassEntry>>> = OnceLock::new();
    E.get_or_init(|| RwLock::new(load()))
}

fn parse_class(c: &str) -> Option<RuleClass> {
    match c.trim().to_ascii_lowercase().as_str() {
        "suspicious" => Some(RuleClass::Suspicious),
        "pua" => Some(RuleClass::Pua),
        "malware" | "malicious" => Some(RuleClass::Malware),
        _ => None,
    }
}

fn load() -> HashMap<String, RuleClassEntry> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path()) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let Some(key) = v["rule"].as_str().map(|r| r.trim().to_ascii_lowercase()) else { continue };
            if v["removed"].as_bool() == Some(true) {
                m.remove(&key);
            } else if let Ok(e) = serde_json::from_value::<RuleClassEntry>(v) {
                if parse_class(&e.class).is_some() {
                    m.insert(key, e);
                }
            }
        }
    }
    m
}

/// Hands the classes to the engine. Called at start and after every change.
pub fn apply() {
    let g = entries().read().unwrap();
    openedr_static::yara::set_analyst_rule_classes(g.values().filter_map(|e| Some((e.rule.clone(), parse_class(&e.class)?))));
    if !g.is_empty() {
        eprintln!("[yara] {} analyst rule classes in use", g.len());
    }
}

fn append(v: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path())?;
    writeln!(f, "{v}")
}

/// Newest first.
pub fn list() -> Vec<RuleClassEntry> {
    let mut v: Vec<RuleClassEntry> = entries().read().unwrap().values().cloned().collect();
    v.sort_by(|a, b| b.added.cmp(&a.added));
    v
}

/// Sets the class of `rule`. Rule names are YARA identifiers: letters, digits, `_`.
pub fn set(rule: &str, class: &str, note: &str, analyst: &str) -> Result<RuleClassEntry, String> {
    let rule = rule.trim();
    if rule.is_empty() || rule.len() > 128 || !rule.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("rule name: a YARA rule identifier (letters, digits, _)".into());
    }
    let Some(_) = parse_class(class) else {
        return Err("class: suspicious, pua or malware".into());
    };
    let e = RuleClassEntry {
        rule: rule.to_string(),
        class: class.trim().to_ascii_lowercase(),
        note: note.trim().chars().take(500).collect(),
        analyst: analyst.to_string(),
        added: chrono::Utc::now().to_rfc3339(),
    };
    append(&serde_json::to_value(&e).map_err(|x| x.to_string())?).map_err(|x| x.to_string())?;
    entries().write().unwrap().insert(rule.to_ascii_lowercase(), e.clone());
    apply();
    Ok(e)
}

pub fn remove(rule: &str) -> Result<bool, String> {
    let key = rule.trim().to_ascii_lowercase();
    if entries().write().unwrap().remove(&key).is_none() {
        return Ok(false);
    }
    append(&serde_json::json!({ "rule": key, "removed": true })).map_err(|x| x.to_string())?;
    apply();
    Ok(true)
}
