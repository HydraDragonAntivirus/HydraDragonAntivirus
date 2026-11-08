//! Samples deleted on request (e.g. the owner of a file asks for it), by hand from the
//! dashboard, always with a reason. Deleting removes the kept file (any category,
//! plain or `.xz`) and its stored static report (strings, file name, PE / APK details),
//! and marks the sample private (`private_samples`). The verdict and telemetry stay:
//! they are not the file. By default a deleted sample is never stored again, nor its
//! report rebuilt, when a client sends the same file later; the dashboard can turn
//! that off ([`set_never_store_again`]), and the same file is then kept again.
//!
//! Copies the server does not manage are not touched: archive folders
//! (`archived_dirs.json`, e.g. another PC) and ML dataset folders. The answer names
//! the archive folder when the sample is remembered there.
//!
//! Every deletion is one line in `analyst_signatures/sample_deletions.jsonl`
//! (append-only): hash, reason, analyst, time and what was removed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};

/// Deleted samples are not stored again (dashboard toggle, on by default).
static NEVER_STORE_AGAIN: AtomicBool = AtomicBool::new(true);

pub fn set_never_store_again(on: bool) {
    NEVER_STORE_AGAIN.store(on, Ordering::Relaxed);
}

pub fn never_store_again() -> bool {
    NEVER_STORE_AGAIN.load(Ordering::Relaxed)
}

/// The file and its report must not be written for this hash: deleted on request
/// while "never store again" is on.
pub fn blocks_storing(sha256: &str) -> bool {
    never_store_again() && is_deleted(sha256)
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleDeletion {
    pub sha256: String,
    pub reason: String,
    #[serde(default)]
    pub analyst: String,
    pub deleted_at: String,
    /// Files removed from disk (kept sample, static report).
    #[serde(default)]
    pub removed: Vec<String>,
}

fn path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join("sample_deletions.jsonl")
}

fn deletions() -> &'static RwLock<HashMap<String, SampleDeletion>> {
    static S: OnceLock<RwLock<HashMap<String, SampleDeletion>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(load()))
}

fn load() -> HashMap<String, SampleDeletion> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path()) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(d) = serde_json::from_str::<SampleDeletion>(&line) {
                m.insert(d.sha256.to_ascii_lowercase(), d);
            }
        }
    }
    if !m.is_empty() {
        eprintln!("[deleted] {} samples deleted on request", m.len());
    }
    m
}

fn append(d: &SampleDeletion) -> std::io::Result<()> {
    let line = serde_json::to_string(d).map_err(std::io::Error::other)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path())?;
    writeln!(f, "{line}")
}

/// The archive folder (`archived_dirs.json`) that still holds a copy, if any: the
/// server does not manage those folders, so the analyst deletes it there by hand.
pub fn archived_copy(sha256: &str) -> Option<String> {
    crate::archived::get(sha256).map(|a| a.path)
}

pub fn is_deleted(sha256: &str) -> bool {
    let g = deletions().read().unwrap();
    !g.is_empty() && g.contains_key(&sha256.trim().to_ascii_lowercase())
}

pub fn get(sha256: &str) -> Option<SampleDeletion> {
    deletions().read().unwrap().get(&sha256.trim().to_ascii_lowercase()).cloned()
}

/// Newest first.
pub fn list() -> Vec<SampleDeletion> {
    let mut v: Vec<SampleDeletion> = deletions().read().unwrap().values().cloned().collect();
    v.sort_by(|a, b| b.deleted_at.cmp(&a.deleted_at));
    v
}

/// Deletes the sample `sha256` as the module docs say. The reason is required.
pub fn delete(engine: &crate::engine_adapter::EngineAdapter, sha256: &str, reason: &str, analyst: &str) -> Result<SampleDeletion, String> {
    let sha = sha256.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid sha256".into());
    }
    let reason: String = reason.trim().chars().take(1000).collect();
    if reason.is_empty() {
        return Err("a reason is required".into());
    }
    // Logged before anything is removed, and remembered at once: a scan of the same
    // file racing this one must not keep it again, and a crash half way leaves the record.
    let mut d = SampleDeletion { sha256: sha.clone(), reason, analyst: analyst.to_string(), deleted_at: chrono::Utc::now().to_rfc3339(), removed: Vec::new() };
    append(&d).map_err(|e| format!("nothing deleted: the log could not be written: {e}"))?;
    deletions().write().unwrap().insert(sha.clone(), d.clone());
    // More than one copy when the same file was kept under two categories.
    for _ in 0..8 {
        let Some(k) = engine.find_kept(&sha.to_ascii_uppercase()) else { break };
        let shown = k.path.display().to_string();
        if engine.forget_kept(&k).is_none() {
            return Err(format!("could not delete {shown}"));
        }
        d.removed.push(shown);
    }
    if let Some(p) = crate::reports::remove(&sha).map_err(|e| format!("could not delete the static report: {e}"))? {
        d.removed.push(p.display().to_string());
    }
    let _ = append(&d);
    deletions().write().unwrap().insert(sha.clone(), d.clone());
    let _ = crate::private_samples::set(&sha, true, analyst, &format!("deleted on request: {}", d.reason));
    Ok(d)
}
