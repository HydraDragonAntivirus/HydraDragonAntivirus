//! TLSH similarity (fast-tlsh): smart whitelisting with injection guards, and
//! "similar files" for analysts and the website.
//!
//! * Every analysed file's TLSH goes into `tlsh_index.jsonl` (sha256, tlsh, size) and an
//!   in-memory list; a linear scan of a million digests takes a few milliseconds.
//! * Known-malware digests without a hash of their own (e.g. MalwareBazaar's tlsh list)
//!   can be dropped into `analyst_signatures/tlsh_blacklist.txt`, one per line.
//!
//! Smart whitelist: an `unknown` PE becomes `clean` only when it is very close
//! (TLSH distance <= `SMART_WL_MAX_DIST`) to a file an ANALYST marked clean, and
//! `injection_guard` finds no sign that something was added to the clean file:
//! same machine / subsystem / DLL-ness / .NET-ness, same sections with the same
//! permissions, entry point in the same section, no newly packed section, no new
//! dangerous imports, no grown or newly encrypted overlay, same signature presence,
//! similar size, and no new medium/high static indicator. Engine-clean files are
//! never used as references, and the whitelist never overrides a detection.
//!
//! Malware similarity is shown to people only; it never sets a verdict.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Mutex, RwLock};

use serde::Serialize;
use serde_json::Value;
use tlsh::{FuzzyHashType, Tlsh};

use crate::fingerprint::{accept, RefLine, Structure};
pub use crate::fingerprint::SMART_WL_MAX_DIST;
/// "Similar files" shown to people.
pub const SIMILAR_MAX_DIST: u32 = 80;

struct Entry {
    sha256: String,
    tlsh: Tlsh,
    size: u64,
}

struct CorpusRef {
    sha256: String,
    tlsh: Tlsh,
    st: Structure,
}

#[derive(Default)]
pub struct SimilarityIndex {
    /// Verified benign corpus (`analyst_signatures/tlsh_whitelist_refs.jsonl`).
    corpus_refs: RwLock<Vec<CorpusRef>>,
    files: RwLock<Vec<Entry>>,
    seen: RwLock<HashSet<String>>,
    known_malware: RwLock<Vec<Tlsh>>,
    writer: Mutex<Option<std::fs::File>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimilarFile {
    /// Empty for entries from the known-malware TLSH list.
    pub sha256: String,
    pub distance: u32,
    pub tlsh: String,
    pub size: u64,
    /// Filled by the caller from telemetry / human review.
    pub verdict: String,
    pub verdict_source: String,
    pub threat_name: Option<String>,
}

fn index_path() -> std::path::PathBuf {
    crate::config::app_dir().join("tlsh_index.jsonl")
}

impl SimilarityIndex {
    pub fn load() -> Self {
        let idx = SimilarityIndex::default();
        if let Ok(f) = std::fs::File::open(index_path()) {
            let mut files = idx.files.write().unwrap();
            let mut seen = idx.seen.write().unwrap();
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                let (Some(sha), Some(t)) = (v["sha256"].as_str(), v["tlsh"].as_str()) else { continue };
                let Ok(tlsh) = t.parse::<Tlsh>() else { continue };
                if seen.insert(sha.to_ascii_lowercase()) {
                    files.push(Entry { sha256: sha.to_ascii_lowercase(), tlsh, size: v["size"].as_u64().unwrap_or(0) });
                }
            }
        }
        *idx.writer.lock().unwrap() = OpenOptions::new().create(true).append(true).open(index_path()).ok();
        idx.reload_known_malware();
        idx.reload_corpus_refs();
        idx
    }

    /// (Re)reads `analyst_signatures/tlsh_whitelist_refs.jsonl` written by
    /// `tlsh_builder refs` from a verified benign corpus.
    pub fn reload_corpus_refs(&self) -> usize {
        let path = crate::human_review::analyst_dir().join("tlsh_whitelist_refs.jsonl");
        let mut v = Vec::new();
        if let Ok(f) = std::fs::File::open(path) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(r) = serde_json::from_str::<RefLine>(&line) else { continue };
                let Ok(t) = r.tlsh.parse::<Tlsh>() else { continue };
                let Some(st) = r.structure() else { continue };
                v.push(CorpusRef { sha256: r.sha256.to_ascii_lowercase(), tlsh: t, st });
            }
        }
        let n = v.len();
        *self.corpus_refs.write().unwrap() = v;
        eprintln!("[similarity] {n} benign corpus references loaded");
        n
    }

    /// (Re)reads `analyst_signatures/tlsh_blacklist.txt` (one digest per line; extra
    /// comma/tab-separated columns are ignored).
    pub fn reload_known_malware(&self) -> usize {
        let path = crate::human_review::analyst_dir().join("tlsh_blacklist.txt");
        let list: Vec<Tlsh> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let t = l.split([',', '\t', ' ', ':']).find(|p| p.trim().len() >= 70)?.trim();
                let t = if t.len() == 70 { format!("T1{t}") } else { t.to_string() };
                t.to_ascii_uppercase().parse::<Tlsh>().ok()
            })
            .collect();
        let n = list.len();
        *self.known_malware.write().unwrap() = list;
        n
    }

    pub fn len(&self) -> usize {
        self.files.read().unwrap().len()
    }

    pub fn tlsh_of(&self, sha256: &str) -> Option<String> {
        let sha = sha256.to_ascii_lowercase();
        self.files.read().unwrap().iter().find(|e| e.sha256 == sha).map(|e| e.tlsh.to_string())
    }

    /// Adds a file once (called after its static report is built).
    pub fn add(&self, sha256: &str, tlsh: &str, size: u64) {
        let sha = sha256.to_ascii_lowercase();
        let Ok(t) = tlsh.parse::<Tlsh>() else { return };
        if !self.seen.write().unwrap().insert(sha.clone()) {
            return;
        }
        if let Some(f) = self.writer.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{}", serde_json::json!({ "sha256": sha, "tlsh": tlsh, "size": size }));
            let _ = f.flush();
        }
        self.files.write().unwrap().push(Entry { sha256: sha, tlsh: t, size });
    }

    /// Nearest files (not `exclude_sha`), closest first, at most `limit`.
    pub fn nearest(&self, tlsh: &str, max_dist: u32, limit: usize, exclude_sha: &str) -> Vec<SimilarFile> {
        let Ok(q) = tlsh.parse::<Tlsh>() else { return Vec::new() };
        let ex = exclude_sha.to_ascii_lowercase();
        let mut out: Vec<SimilarFile> = self
            .files
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.sha256 != ex)
            .filter_map(|e| {
                let d = q.compare(&e.tlsh);
                (d <= max_dist).then(|| SimilarFile {
                    sha256: e.sha256.clone(),
                    distance: d,
                    tlsh: e.tlsh.to_string(),
                    size: e.size,
                    verdict: String::new(),
                    verdict_source: String::new(),
                    threat_name: None,
                })
            })
            .collect();
        for k in self.known_malware.read().unwrap().iter() {
            let d = q.compare(k);
            if d <= max_dist {
                out.push(SimilarFile {
                    sha256: String::new(),
                    distance: d,
                    tlsh: k.to_string(),
                    size: 0,
                    verdict: "malicious".into(),
                    verdict_source: "tlsh_blacklist".into(),
                    threat_name: None,
                });
            }
        }
        out.sort_by_key(|s| s.distance);
        out.truncate(limit);
        out
    }

    /// Analyst-clean files within the smart-whitelist distance, closest first.
    pub fn clean_references(&self, tlsh: &str, is_clean: impl Fn(&str) -> bool) -> Vec<(String, u32)> {
        let Ok(q) = tlsh.parse::<Tlsh>() else { return Vec::new() };
        let mut v: Vec<(String, u32)> = self
            .files
            .read()
            .unwrap()
            .iter()
            .filter_map(|e| {
                let d = q.compare(&e.tlsh);
                (d <= SMART_WL_MAX_DIST && is_clean(&e.sha256)).then(|| (e.sha256.clone(), d))
            })
            .collect();
        v.sort_by_key(|x| x.1);
        v.truncate(8);
        v
    }
}

// ------------------------------------------------------------------ smart whitelist

/// Decision for one file: Some((reference sha256, distance, description)) when the
/// smart whitelist applies. References are analyst-clean files (their stored static
/// report) and the verified benign corpus (`tlsh_whitelist_refs.jsonl`). PE files use
/// the file TLSH, APKs the DEX TLSH; the guard depends on the kind (`fingerprint::accept`).
pub fn smart_whitelist(
    index: &SimilarityIndex,
    candidate: &Value,
    is_analyst_clean: impl Fn(&str) -> bool,
) -> Option<(String, u32, String)> {
    let hashes = &candidate["hashes"];
    let tlsh = hashes["dex_tlsh"].as_str().or(hashes["tlsh"].as_str())?;
    let cand = Structure::from_report(candidate)?; // PE or APK only
    let q = tlsh.parse::<Tlsh>().ok()?;

    // (distance, sha, structure, origin)
    let mut refs: Vec<(u32, String, Structure, &'static str)> = Vec::new();
    for (sha, d) in index.clean_references(tlsh, is_analyst_clean) {
        if let Some(st) = crate::reports::load(&sha).as_ref().and_then(Structure::from_report) {
            refs.push((d, sha, st, "analyst-verified clean"));
        }
    }
    for r in index.corpus_refs.read().unwrap().iter() {
        let d = q.compare(&r.tlsh);
        if d <= SMART_WL_MAX_DIST {
            refs.push((d, r.sha256.clone(), r.st.clone(), "benign reference corpus"));
        }
    }
    refs.sort_by_key(|r| r.0);
    refs.truncate(16);

    let mut last_reason = String::new();
    for (d, sha, st, origin) in refs {
        match accept(d, &cand, &st) {
            Ok(()) => {
                let what = if matches!(st, Structure::Apk(_)) { "DEX TLSH" } else { "TLSH" };
                return Some((sha.clone(), d, format!("Smart whitelist: {what} distance {d} to {origin} {sha}; structure unchanged")));
            }
            Err(r) => last_reason = r,
        }
    }
    if !last_reason.is_empty() {
        eprintln!("[similarity] smart whitelist refused: {last_reason}");
    }
    None
}

/// Lookup helper for callers that need the verdict map of many hashes at once.
pub type VerdictLookup<'a> = &'a dyn Fn(&str) -> (String, String, Option<String>);

pub fn fill_verdicts(list: &mut [SimilarFile], lookup: VerdictLookup<'_>) {
    let mut cache: HashMap<String, (String, String, Option<String>)> = HashMap::new();
    for s in list.iter_mut().filter(|s| !s.sha256.is_empty()) {
        let v = cache.entry(s.sha256.clone()).or_insert_with(|| lookup(&s.sha256)).clone();
        s.verdict = v.0;
        s.verdict_source = v.1;
        s.threat_name = v.2;
    }
}
