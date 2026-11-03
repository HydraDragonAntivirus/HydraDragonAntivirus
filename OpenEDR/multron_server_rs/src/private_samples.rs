//! Private samples: files an analyst marked from the dashboard so the public API
//! (`/api/v1/…`) tells only their verdict. Their strings, file names, PE / APK details,
//! indicators and similar files are left out for everyone, researcher API keys
//! included, and the sample itself is never downloadable. The dashboard (local only)
//! still shows everything.
//!
//! Kept in `analyst_signatures/private_samples.jsonl` (append-only: a later line for
//! the same hash replaces the earlier one, `"private": false` makes it public again).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSample {
    pub sha256: String,
    #[serde(default)]
    pub analyst: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub added: String,
}

fn path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join("private_samples.jsonl")
}

fn samples() -> &'static RwLock<HashMap<String, PrivateSample>> {
    static S: OnceLock<RwLock<HashMap<String, PrivateSample>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(load()))
}

fn load() -> HashMap<String, PrivateSample> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path()) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let Some(sha) = v["sha256"].as_str().map(str::to_ascii_lowercase) else { continue };
            if v["private"].as_bool() == Some(false) {
                m.remove(&sha);
            } else if let Ok(s) = serde_json::from_value::<PrivateSample>(v) {
                m.insert(sha, s);
            }
        }
    }
    if !m.is_empty() {
        eprintln!("[private] {} private samples (details hidden from the public API)", m.len());
    }
    m
}

fn append(v: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path())?;
    writeln!(f, "{v}")
}

pub fn is_private(sha256: &str) -> bool {
    let g = samples().read().unwrap();
    !g.is_empty() && g.contains_key(&sha256.trim().to_ascii_lowercase())
}

pub fn get(sha256: &str) -> Option<PrivateSample> {
    samples().read().unwrap().get(&sha256.trim().to_ascii_lowercase()).cloned()
}

/// Newest first.
pub fn list() -> Vec<PrivateSample> {
    let mut v: Vec<PrivateSample> = samples().read().unwrap().values().cloned().collect();
    v.sort_by(|a, b| b.added.cmp(&a.added));
    v
}

/// Marks `sha256` private (or public again). Returns false when nothing changed.
pub fn set(sha256: &str, private: bool, analyst: &str, note: &str) -> std::io::Result<bool> {
    let sha = sha256.trim().to_ascii_lowercase();
    let mut g = samples().write().unwrap();
    if !private {
        if g.remove(&sha).is_none() {
            return Ok(false);
        }
        append(&serde_json::json!({ "sha256": sha, "private": false, "analyst": analyst, "added": chrono::Utc::now().to_rfc3339() }))?;
        return Ok(true);
    }
    let s = PrivateSample {
        sha256: sha.clone(),
        analyst: analyst.to_string(),
        note: note.trim().chars().take(500).collect(),
        added: chrono::Utc::now().to_rfc3339(),
    };
    append(&serde_json::to_value(&s).unwrap_or_default())?;
    g.insert(sha, s);
    Ok(true)
}

/// What a public report keeps of a private sample: what identifies the file
/// (hashes, size, type), nothing taken from its content.
pub fn redact_report(report: &mut serde_json::Value) {
    let Some(o) = report.as_object_mut() else { return };
    o.retain(|k, _| matches!(k.as_str(), "version" | "generated_at" | "size" | "file_type" | "mime" | "hashes"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_report_keeps_no_content() {
        let mut r = serde_json::json!({
            "version": 3, "file_name": "C:\\Users\\a\\secret.exe", "size": 10, "file_type": "PE32", "mime": "application/x-dosexec",
            "entropy": 7.1, "hashes": { "sha256": "ab" }, "pe": { "version_info": { "CompanyName": "X" } },
            "strings": { "ascii": ["password=hunter2"] }, "indicators": [{ "title": "URL http://x" }]
        });
        redact_report(&mut r);
        let mut keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["file_type", "hashes", "mime", "size", "version"]);
    }
}
