//! Why a file is not kept on the server.
//!
//! A hash can reach the queue without its file: the client only sent the hash, the
//! keep quota was full when it was uploaded (the file was dropped), or offload moved it
//! to another disk. The last two are recorded here, in `kept_missing.jsonl` next to the
//! executable (last line for a hash wins), so the dashboard and VirusKovAlyzer can say
//! which one it was instead of a generic "not kept".

use std::collections::HashMap;
use std::io::Write;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Missing {
    pub sha256: String,
    /// `quota` (dropped at upload) or `offloaded` (moved to `detail`).
    pub reason: String,
    pub detail: String,
    pub at: String,
}

fn path() -> std::path::PathBuf {
    crate::config::app_dir().join("kept_missing.jsonl")
}

fn map() -> &'static RwLock<HashMap<String, Missing>> {
    static MAP: OnceLock<RwLock<HashMap<String, Missing>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(path()) {
            for l in text.lines() {
                if let Ok(x) = serde_json::from_str::<Missing>(l) {
                    m.insert(x.sha256.clone(), x);
                }
            }
        }
        RwLock::new(m)
    })
}

/// Records why the file of `sha` is not kept here (any case).
pub fn record(sha: &str, reason: &str, detail: String) {
    let x = Missing {
        sha256: sha.to_ascii_lowercase(),
        reason: reason.to_string(),
        detail,
        at: chrono::Utc::now().to_rfc3339(),
    };
    if let Ok(line) = serde_json::to_string(&x) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path()) {
            let _ = writeln!(f, "{line}");
        }
    }
    map().write().unwrap().insert(x.sha256.clone(), x);
}

/// A kept file is here again (re-uploaded): forget the old reason.
pub fn clear(sha: &str) {
    let sha = sha.to_ascii_lowercase();
    let had = map().write().unwrap().remove(&sha).is_some();
    if had {
        record(&sha, "kept", String::new());
        map().write().unwrap().remove(&sha);
    }
}

pub fn get(sha: &str) -> Option<Missing> {
    map().read().unwrap().get(&sha.to_ascii_lowercase()).cloned().filter(|m| m.reason != "kept")
}

fn quota_verdict(detail: &str) -> Option<(&str, &str)> {
    let (cat, rest) = detail.split_once(", ")?;
    let v = match cat {
        "xorfilter_malicious" => "malicious",
        "xorfilter_clean" => "clean",
        other => other,
    };
    Some((v, rest))
}

/// `(SHA-256 upper-case hex, verdict)` of quota-dropped files whose recorded category
/// is one of `verdicts`.
pub fn verdict_hashes(verdicts: &[&str]) -> Vec<(String, String)> {
    map()
        .read()
        .unwrap()
        .values()
        .filter(|m| m.reason == "quota")
        .filter_map(|m| {
            let (v, _) = quota_verdict(&m.detail)?;
            verdicts.contains(&v).then(|| (m.sha256.to_ascii_uppercase(), v.to_string()))
        })
        .collect()
}

/// Replaces a non-unknown category in a quota-dropped record's `detail` with `unknown`
/// (keeps `at` and the rest of `detail`).
pub fn set_unknown(sha: &str) -> bool {
    let key = sha.to_ascii_lowercase();
    let updated = {
        let mut g = map().write().unwrap();
        let Some(m) = g.get_mut(&key) else { return false };
        if m.reason != "quota" {
            return false;
        }
        let Some((v, rest)) = quota_verdict(&m.detail) else { return false };
        if v == "unknown" {
            return false;
        }
        m.detail = format!("unknown, {rest}");
        m.clone()
    };
    if let Ok(line) = serde_json::to_string(&updated) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path()) {
            let _ = writeln!(f, "{line}");
        }
    }
    true
}

/// Error text for "this file is not kept on the server".
pub fn explain(sha: &str) -> String {
    if let Some(a) = crate::archived::get(sha) {
        let kind = if a.kind.is_empty() { String::new() } else { format!(", {}", a.kind) };
        return format!("this file is not kept on the server: archived to {} ({}{kind})", a.group, a.category);
    }
    match get(sha) {
        Some(m) if m.reason == "offloaded" => format!("this file is not kept on the server: moved by offload to {} ({})", m.detail, m.at),
        Some(m) if m.reason == "quota" => format!("this file is not kept on the server: dropped at upload, disk low ({}, {})", m.detail, m.at),
        Some(m) => format!("this file is not kept on the server ({}: {})", m.reason, m.detail),
        None => "this file is not kept on the server: never uploaded (the client sent only the hash) or deleted".to_string(),
    }
}
