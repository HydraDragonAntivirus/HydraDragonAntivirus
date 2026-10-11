//! TLSH similarity (fast-tlsh): smart whitelisting with injection guards, and
//! "similar files" for analysts and the website.
//!
//! * Every analysed file's TLSH goes into `tlsh_index.jsonl` (sha256, tlsh, size) and an
//!   in-memory list; a linear scan of a million digests takes a few milliseconds.
//! * Known-malware digests without a hash of their own (e.g. MalwareBazaar's tlsh list)
//!   can be dropped into `tlsh_signatures/tlsh_blacklist.txt`, one per line.
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
//! Malware similarity is shown to people only; it never sets a verdict, with one
//! exception: analyst TLSH signatures. A human "malicious" verdict stores the file's
//! TLSH (`tlsh_signatures/analyst_tlsh.jsonl`), and a file the engine does not detect
//! that is within `ANALYST_TLSH_MAX_DIST` of one gets the analyst's threat name. The
//! TLSH is taken with trailing zero bytes stripped, so appending 00 padding to a sample
//! does not hide it.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tlsh::{FuzzyHashType, Tlsh};

use crate::fingerprint::{accept, RefLine, Structure};
pub use crate::fingerprint::SMART_WL_MAX_DIST;
/// "Similar files" shown to people.
pub const SIMILAR_MAX_DIST: u32 = 80;
/// Analyst TLSH signatures: a file this close to an analyst-confirmed malicious file
/// is flagged. Low enough for near-copies (padding, a changed string or resource).
pub const ANALYST_TLSH_MAX_DIST: u32 = 30;
/// ...and its size (padding stripped) must be within this factor of the sample's.
const ANALYST_TLSH_SIZE_FACTOR: f64 = 1.5;

/// One analyst TLSH signature (a line of `analyst_tlsh.jsonl`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystTlsh {
    pub sha256: String,
    pub tlsh: String,
    pub threat: String,
    #[serde(default)]
    pub analyst: String,
    /// Size with trailing zero padding stripped; 0 = unknown (no size check).
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub added: String,
}

struct AnalystSig {
    meta: AnalystTlsh,
    tlsh: Tlsh,
}

/// The file without trailing 0x00 padding.
pub fn trim_trailing_padding(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

fn analyst_tlsh_path() -> std::path::PathBuf {
    tlsh_dir().join("analyst_tlsh.jsonl")
}

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
    /// Verified benign corpus (`tlsh_signatures/tlsh_whitelist_refs.jsonl`).
    corpus_refs: RwLock<Vec<CorpusRef>>,
    /// SHA-256 (lower case) of every corpus reference: exact copies are simply clean.
    corpus_shas: RwLock<HashSet<String>>,
    files: RwLock<Vec<Entry>>,
    seen: RwLock<HashSet<String>>,
    known_malware: RwLock<Vec<Tlsh>>,
    analyst_sigs: RwLock<Vec<AnalystSig>>,
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

/// Generated TLSH data (`tlsh_builder` output), next to the other rule folders and
/// apart from the hand-written analyst signatures.
pub fn tlsh_dir() -> std::path::PathBuf {
    let dir = crate::config::app_dir().join("tlsh_signatures");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// `tlsh_signatures/<name>`; falls back to the old `analyst_signatures/<name>` while
/// only that one exists.
fn tlsh_file(name: &str) -> std::path::PathBuf {
    let new = tlsh_dir().join(name);
    if !new.exists() {
        let old = crate::human_review::analyst_dir().join(name);
        if old.exists() {
            eprintln!("[similarity] using {} (move it to {})", old.display(), new.display());
            return old;
        }
    }
    new
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
        idx.reload_analyst_sigs();
        idx
    }

    /// (Re)reads `analyst_tlsh.jsonl`. It is append-only: a later line for the same
    /// SHA-256 replaces the earlier one, `"removed": true` deletes it.
    pub fn reload_analyst_sigs(&self) -> usize {
        let mut by_sha: HashMap<String, AnalystSig> = HashMap::new();
        if let Ok(f) = std::fs::File::open(analyst_tlsh_path()) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                let Some(sha) = v["sha256"].as_str().map(str::to_ascii_lowercase) else { continue };
                if v["removed"].as_bool() == Some(true) {
                    by_sha.remove(&sha);
                    continue;
                }
                let Ok(meta) = serde_json::from_value::<AnalystTlsh>(v) else { continue };
                let Ok(tlsh) = meta.tlsh.parse::<Tlsh>() else { continue };
                by_sha.insert(sha, AnalystSig { meta, tlsh });
            }
        }
        let n = by_sha.len();
        *self.analyst_sigs.write().unwrap() = by_sha.into_values().collect();
        if n > 0 {
            eprintln!("[similarity] {n} analyst TLSH signatures loaded");
        }
        n
    }

    fn append_analyst_line(v: &Value) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(analyst_tlsh_path()) {
            let _ = writeln!(f, "{v}");
        }
    }

    /// Adds (or replaces) the signature of one analyst-confirmed malicious file.
    pub fn add_analyst_sig(&self, mut meta: AnalystTlsh) -> bool {
        meta.sha256 = meta.sha256.to_ascii_lowercase();
        let Ok(tlsh) = meta.tlsh.parse::<Tlsh>() else { return false };
        let mut sigs = self.analyst_sigs.write().unwrap();
        sigs.retain(|s| s.meta.sha256 != meta.sha256);
        Self::append_analyst_line(&serde_json::to_value(&meta).unwrap_or_default());
        sigs.push(AnalystSig { meta, tlsh });
        true
    }

    /// Drops the signature of `sha256` (its human verdict is no longer malicious).
    pub fn remove_analyst_sig(&self, sha256: &str) -> bool {
        let sha = sha256.to_ascii_lowercase();
        let mut sigs = self.analyst_sigs.write().unwrap();
        let before = sigs.len();
        sigs.retain(|s| s.meta.sha256 != sha);
        let removed = sigs.len() != before;
        if removed {
            Self::append_analyst_line(&serde_json::json!({ "sha256": sha, "removed": true }));
        }
        removed
    }

    /// Closest analyst signature within `ANALYST_TLSH_MAX_DIST` of `data` (padding
    /// stripped), ignoring the file's own signature.
    pub fn analyst_match(&self, data: &[u8], sha256: &str) -> Option<(AnalystTlsh, u32)> {
        let sigs = self.analyst_sigs.read().unwrap();
        if sigs.is_empty() {
            return None;
        }
        let body = trim_trailing_padding(data);
        let q = crate::analyzer::tlsh_digest(body)?.parse::<Tlsh>().ok()?;
        let own = sha256.to_ascii_lowercase();
        let len = body.len() as f64;
        sigs.iter()
            .filter(|s| s.meta.sha256 != own)
            .filter(|s| {
                s.meta.size == 0 || {
                    let sz = s.meta.size as f64;
                    len.max(sz) <= len.min(sz) * ANALYST_TLSH_SIZE_FACTOR
                }
            })
            .map(|s| (s, q.compare(&s.tlsh)))
            .filter(|(_, d)| *d <= ANALYST_TLSH_MAX_DIST)
            .min_by_key(|(_, d)| *d)
            .map(|(s, d)| (s.meta.clone(), d))
    }

    /// (Re)reads `tlsh_signatures/tlsh_whitelist_refs.jsonl` written by
    /// `tlsh_builder refs` from a verified benign corpus.
    pub fn reload_corpus_refs(&self) -> usize {
        let path = tlsh_file("tlsh_whitelist_refs.jsonl");
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
        *self.corpus_shas.write().unwrap() = v.iter().map(|r| r.sha256.clone()).collect();
        *self.corpus_refs.write().unwrap() = v;
        eprintln!("[similarity] {n} benign corpus references loaded");
        n
    }

    /// (Re)reads `tlsh_signatures/tlsh_blacklist.txt` (one digest per line; extra
    /// comma/tab-separated columns are ignored).
    pub fn reload_known_malware(&self) -> usize {
        let path = tlsh_file("tlsh_blacklist.txt");
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

    /// The file itself (same SHA-256) is in the verified benign corpus.
    pub fn in_benign_corpus(&self, sha256: &str) -> bool {
        self.corpus_shas.read().unwrap().contains(&sha256.to_ascii_lowercase())
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
