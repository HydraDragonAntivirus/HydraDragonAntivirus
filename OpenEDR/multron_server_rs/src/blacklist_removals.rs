//! Blacklist removals / overrides: hashes (SHA-256, MD5, SHA-1) that were removed
//! from the active XOR filter blacklist by an analyst from the dashboard, always with a reason.
//!
//! Kept in `analyst_signatures/blacklist_removals.jsonl` (append-only: a later line for
//! the same hash replaces the earlier one; `"removed": false` restores it to the blacklist).
//!
//! Whitelist always takes precedence over blacklist collisions, and any hash marked
//! as removed here is immediately bypassed in memory by `engine_adapter`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistRemoval {
    pub hash: String,
    pub hash_type: String, // "sha256", "md5", "sha1"
    #[serde(default)]
    pub analyst: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub removed_at: String,
    #[serde(default = "default_true")]
    pub removed: bool,
}

fn default_true() -> bool {
    true
}

fn path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join("blacklist_removals.jsonl")
}

fn removals() -> &'static RwLock<HashMap<String, BlacklistRemoval>> {
    static S: OnceLock<RwLock<HashMap<String, BlacklistRemoval>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(load()))
}

pub fn classify_hash(h: &str) -> Option<&'static str> {
    let h = h.trim();
    if h.chars().all(|c| c.is_ascii_hexdigit()) {
        match h.len() {
            32 => Some("md5"),
            40 => Some("sha1"),
            64 => Some("sha256"),
            _ => None,
        }
    } else {
        None
    }
}

fn load() -> HashMap<String, BlacklistRemoval> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path()) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let Some(hash) = v["hash"].as_str().map(str::to_ascii_lowercase) else { continue };
            if v["removed"].as_bool() == Some(false) {
                m.remove(&hash);
            } else if let Ok(mut r) = serde_json::from_value::<BlacklistRemoval>(v) {
                r.hash = hash.clone();
                m.insert(hash, r);
            }
        }
    }
    if !m.is_empty() {
        eprintln!("[blacklist] {} hash override removals active", m.len());
    }
    m
}

fn append(v: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path())?;
    writeln!(f, "{v}")
}

pub fn is_removed(hash: &str) -> bool {
    let g = removals().read().unwrap();
    !g.is_empty() && g.contains_key(&hash.trim().to_ascii_lowercase())
}

pub fn get(hash: &str) -> Option<BlacklistRemoval> {
    removals().read().unwrap().get(&hash.trim().to_ascii_lowercase()).cloned()
}

/// Newest first.
pub fn list() -> Vec<BlacklistRemoval> {
    let mut v: Vec<BlacklistRemoval> = removals().read().unwrap().values().cloned().collect();
    v.sort_by(|a, b| b.removed_at.cmp(&a.removed_at));
    v
}

/// Removes a hash from the blacklist (records override). Returns Ok(true) on change.
pub fn remove_hash(hash: &str, analyst: &str, reason: &str) -> std::io::Result<bool> {
    let h = hash.trim().to_ascii_lowercase();
    let Some(htype) = classify_hash(&h) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsupported hash format (must be 32, 40, or 64 hex chars)"));
    };
    let mut g = removals().write().unwrap();
    let r = BlacklistRemoval {
        hash: h.clone(),
        hash_type: htype.to_string(),
        analyst: analyst.to_string(),
        reason: reason.trim().chars().take(500).collect(),
        removed_at: chrono::Utc::now().to_rfc3339(),
        removed: true,
    };
    append(&serde_json::to_value(&r).unwrap_or_default())?;
    g.insert(h, r);
    Ok(true)
}

/// Restores a hash to the blacklist by unsetting its removal override.
pub fn restore_hash(hash: &str, analyst: &str) -> std::io::Result<bool> {
    let h = hash.trim().to_ascii_lowercase();
    let mut g = removals().write().unwrap();
    if g.remove(&h).is_none() {
        return Ok(false);
    }
    append(&serde_json::json!({
        "hash": h,
        "removed": false,
        "analyst": analyst,
        "reason": "Restored to blacklist",
        "removed_at": chrono::Utc::now().to_rfc3339()
    }))?;
    Ok(true)
}
