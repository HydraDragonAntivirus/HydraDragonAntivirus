//! Analyst company (signer) list management with reasons and sample tracking.
//! Kept in `analyst_signatures/company_signers.jsonl` (append-only), synced to
//! `analyst_signatures/companies_allow.txt` and `companies_block.txt`.

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

fn sync_text_files(m: &HashMap<(String, String), CompanySignerEntry>) -> std::io::Result<()> {
    let mut allow = Vec::new();
    let mut block = Vec::new();
    for ((_, list), entry) in m.iter() {
        let line = if !entry.reason.trim().is_empty() && entry.reason.trim() != "Company list entry" {
            if !entry.sha256.trim().is_empty() {
                format!("{} # {} (sample: {})", entry.name, entry.reason.trim(), &entry.sha256.trim()[..entry.sha256.trim().len().min(16)])
            } else {
                format!("{} # {}", entry.name, entry.reason.trim())
            }
        } else {
            entry.name.clone()
        };
        if list == "allow" {
            allow.push((entry.name.to_ascii_lowercase(), line));
        } else if list == "block" {
            block.push((entry.name.to_ascii_lowercase(), line));
        }
    }
    allow.sort_by(|a, b| a.0.cmp(&b.0));
    block.sort_by(|a, b| a.0.cmp(&b.0));
    let dir = crate::human_review::analyst_dir();
    let allow_text = allow.into_iter().map(|(_, l)| l).collect::<Vec<_>>().join("\n") + "\n";
    let block_text = block.into_iter().map(|(_, l)| l).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(dir.join("companies_allow.txt"), allow_text)?;
    std::fs::write(dir.join("companies_block.txt"), block_text)
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
    sync_text_files(&guard).map_err(|e| format!("Failed to update text files: {e}"))?;

    Ok(entry)
}

pub fn remove(name: &str, list: &str) -> Result<bool, String> {
    let name = name.trim();
    let list = list.trim().to_ascii_lowercase();
    let k = key(name, &list);
    let mut guard = entries().write().unwrap();
    if guard.remove(&k).is_some() {
        let v = serde_json::json!({
            "name": name,
            "list": list,
            "removed": true,
            "removed_at": Utc::now().to_rfc3339(),
        });
        let _ = append_json(&v);
        let _ = sync_text_files(&guard);
        Ok(true)
    } else {
        Ok(false)
    }
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
            };
            if let Ok(v) = serde_json::to_value(&entry) {
                let _ = append_json(&v);
            }
            guard.insert(k, entry);
        }
    }

    sync_text_files(&guard).map_err(|e| format!("Failed to update text files: {e}"))
}
