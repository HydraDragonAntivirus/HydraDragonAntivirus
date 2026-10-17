//! Analyst imphash signatures: the import hash of a PE an analyst knows is malicious
//! flags every other PE with the same import table. Made by hand from the dashboard
//! (never automatically), one per imphash, in
//! `analyst_signatures/imphash_signatures.jsonl` (append-only: a later line for the
//! same imphash replaces the earlier one, `"removed": true` deletes it).
//!
//! An import hash is shared by every program built the same way, so a signature is
//! refused when it would flag clean files:
//! - the PE needs at least `MIN_IMPORTS` imports and must not be .NET (every .NET
//!   program has the same one-entry import table);
//! - no clean file may have the imphash: neither the verified benign reference corpus
//!   nor a file with a human clean verdict (its stored static report).
//! At scan time it only raises unknown / possible_clean / suspicious results and never
//! touches a file with a human clean verdict, like the TLSH blacklist.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::sync::{Mutex, OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::threat_intel::ThreatIntelStore;

/// Smallest import table a signature may be made from.
pub const MIN_IMPORTS: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImphashSig {
    pub imphash: String,
    pub threat: String,
    /// The file it was made from.
    pub sha256: String,
    #[serde(default)]
    pub analyst: String,
    #[serde(default)]
    pub imports: usize,
    #[serde(default)]
    pub added: String,
}

fn path() -> std::path::PathBuf {
    crate::human_review::analyst_dir().join("imphash_signatures.jsonl")
}

fn sigs() -> &'static RwLock<HashMap<String, ImphashSig>> {
    static S: OnceLock<RwLock<HashMap<String, ImphashSig>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(load()))
}

fn load() -> HashMap<String, ImphashSig> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path()) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let Some(h) = v["imphash"].as_str().map(str::to_ascii_lowercase) else { continue };
            if v["removed"].as_bool() == Some(true) {
                m.remove(&h);
            } else if let Ok(s) = serde_json::from_value::<ImphashSig>(v) {
                m.insert(h, s);
            }
        }
    }
    if !m.is_empty() {
        eprintln!("[imphash] {} analyst imphash signatures loaded", m.len());
    }
    m
}

fn append(v: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path())?;
    writeln!(f, "{v}")
}

pub fn any() -> bool {
    !sigs().read().unwrap().is_empty()
}

pub fn lookup(imphash: &str) -> Option<ImphashSig> {
    sigs().read().unwrap().get(&imphash.to_ascii_lowercase()).cloned()
}

/// Newest first.
pub fn list() -> Vec<ImphashSig> {
    let mut v: Vec<ImphashSig> = sigs().read().unwrap().values().cloned().collect();
    v.sort_by(|a, b| b.added.cmp(&a.added));
    v
}

pub fn remove(imphash: &str) -> std::io::Result<bool> {
    let h = imphash.trim().to_ascii_lowercase();
    let mut g = sigs().write().unwrap();
    if g.remove(&h).is_none() {
        return Ok(false);
    }
    append(&serde_json::json!({ "imphash": h, "removed": true }))?;
    Ok(true)
}

/// Imphash of each human-clean file's stored report, read once per file.
fn clean_imphashes() -> &'static Mutex<HashMap<String, Option<String>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clean files with this imphash (at most `limit`): (SHA-256, where it is known clean).
pub fn clean_with(ti: &ThreatIntelStore, imphash: &str, limit: usize) -> Vec<(String, &'static str)> {
    let h = imphash.to_ascii_lowercase();
    let mut out: Vec<(String, &'static str)> = ti
        .similarity
        .corpus_imphash_matches(&h, limit)
        .into_iter()
        .map(|s| (s, "benign reference corpus"))
        .collect();
    let clean: HashSet<String> = ti
        .reviews
        .completed_verdicts()
        .into_iter()
        .filter(|(_, v)| v == "clean")
        .map(|(s, _)| s.to_ascii_lowercase())
        .collect();
    let mut cache = clean_imphashes().lock().unwrap();
    for sha in &clean {
        let ih = cache.entry(sha.clone()).or_insert_with(|| {
            crate::reports::load(sha).and_then(|r| r["hashes"]["imphash"].as_str().map(str::to_ascii_lowercase))
        });
        if ih.as_deref() == Some(h.as_str()) && out.len() < limit {
            out.push((sha.clone(), "human clean verdict"));
        }
    }
    out
}

/// Makes the signature of the PE `data` (SHA-256 `sha`) after the checks in the
/// module docs. Returns it, or why it was refused.
pub fn create(ti: &ThreatIntelStore, sha: &str, data: &[u8], threat: &str, analyst: &str) -> Result<ImphashSig, String> {
    let sha = sha.trim().to_ascii_lowercase();
    let threat = crate::naming::normalize_threat_name(threat)?;
    if ti.reviews.completed(&sha).and_then(|r| r.verdict).as_deref() == Some("clean") {
        return Err("this file has a human clean verdict".into());
    }
    let (imphash, imports, dotnet) = crate::analyzer::pe_imphash(data).ok_or("not a PE with an import table")?;
    if dotnet {
        return Err(".NET program: every .NET program has the same import table, use another signature".into());
    }
    if imports < MIN_IMPORTS {
        return Err(format!("only {imports} imports: an import table this small is shared by too many programs (at least {MIN_IMPORTS})"));
    }
    let clean = clean_with(ti, &imphash, 5);
    if !clean.is_empty() {
        let list: Vec<String> = clean.iter().map(|(s, o)| format!("{s} ({o})")).collect();
        return Err(format!("clean files have imphash {imphash}: {}", list.join(", ")));
    }
    let sig = ImphashSig { imphash: imphash.clone(), threat, sha256: sha, analyst: analyst.to_string(), imports, added: chrono::Utc::now().to_rfc3339() };
    append(&serde_json::to_value(&sig).unwrap_or_default()).map_err(|e| format!("could not save: {e}"))?;
    sigs().write().unwrap().insert(imphash, sig.clone());
    Ok(sig)
}
