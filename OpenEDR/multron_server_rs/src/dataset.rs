//! ML training datasets filled from the cloud.
//!
//! `dataset_paths.json` next to the server (see `yarGen/TRAINING_GUIDE.md`) names the
//! same folders the ML and HydraDragonSig training uses:
//!
//! ```json
//! {
//!   "windows_malware":    "C:\\...\\usbdosyalar\\datamaliciousorder",
//!   "windows_clean":      "C:\\...\\usbdosyalar\\data2",
//!   "android_malware":    "C:\\...\\HydraDragonAV-Mobile\\dataset\\malicious",
//!   "android_clean":      "C:\\...\\HydraDragonAV-Mobile\\dataset\\benign",
//!   "javascript_malware": "C:\\...\\usbdosyalar\\javascript\\malicious",
//!   "javascript_clean":   "C:\\...\\usbdosyalar\\javascript\\data2"
//! }
//! ```
//!
//! A file is copied as `<SHA256>.<ext>` into the folder of its platform (APK -> android,
//! PE -> windows, JavaScript -> javascript) and label, ONLY when the label comes from a
//! reliable source, so the models never learn the engine's own mistakes:
//!
//! * an analyst verdict (human review) - malicious or clean;
//! * analyst signatures / the analyst company allow-list;
//! * an exact SHA-256 match in the verified benign reference corpus;
//! * a valid, trusted Authenticode signature with a clean verdict.
//!
//! XOR-filter hash verdicts, ML / heuristic verdicts, TLSH look-alikes
//! (`possible_clean`) and `suspicious` are never copied. Missing keys or an absent file
//! turn that folder (or the whole feature) off.
//!
//! Duplicates are decided by CONTENT, not by name. At start a background thread hashes
//! every file already in the six folders (whatever its name; `dataset_index.jsonl` caches
//! the digests by path + size + modification time, so later starts only hash new or
//! changed files). Then:
//!
//! * the same content already under the same label (any name, any extension) -> nothing
//!   is written;
//! * the same content under the OTHER label:
//!   - a `<SHA256>.<ext>` copy this server wrote -> it is removed and the file is written
//!     under the new label (an analyst flipped the verdict);
//!   - any other file (yours) -> nothing is written or moved: the case goes to
//!     `dataset_conflicts.jsonl` and the dashboard, and you decide. The server never
//!     deletes or moves a file it did not write.
//!
//! Copies that arrive while the index is still being built wait in memory (up to
//! `PENDING_MAX_BYTES`) and are written once it is ready.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::engine_adapter::ResultMessage;

/// Copies waiting for the index, at most this many bytes in memory.
const PENDING_MAX_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DatasetPaths {
    #[serde(default)]
    pub windows_malware: Option<PathBuf>,
    #[serde(default)]
    pub windows_clean: Option<PathBuf>,
    #[serde(default)]
    pub android_malware: Option<PathBuf>,
    #[serde(default)]
    pub android_clean: Option<PathBuf>,
    #[serde(default)]
    pub javascript_malware: Option<PathBuf>,
    #[serde(default)]
    pub javascript_clean: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Android,
    JavaScript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Malware,
    Clean,
}

impl Label {
    fn other(self) -> Self {
        match self {
            Label::Malware => Label::Clean,
            Label::Clean => Label::Malware,
        }
    }
}

pub fn config_path() -> PathBuf {
    crate::config::app_dir().join("dataset_paths.json")
}

impl DatasetPaths {
    fn any(&self) -> bool {
        !self.folders().is_empty()
    }

    pub fn dir(&self, platform: Platform, label: Label) -> Option<&Path> {
        let p = match (platform, label) {
            (Platform::Windows, Label::Malware) => &self.windows_malware,
            (Platform::Windows, Label::Clean) => &self.windows_clean,
            (Platform::Android, Label::Malware) => &self.android_malware,
            (Platform::Android, Label::Clean) => &self.android_clean,
            (Platform::JavaScript, Label::Malware) => &self.javascript_malware,
            (Platform::JavaScript, Label::Clean) => &self.javascript_clean,
        };
        p.as_deref().filter(|p| !p.as_os_str().is_empty())
    }

    /// Every configured folder with its platform and label.
    pub fn folders(&self) -> Vec<(Platform, Label, PathBuf)> {
        let mut out = Vec::new();
        for platform in [Platform::Windows, Platform::Android, Platform::JavaScript] {
            for label in [Label::Malware, Label::Clean] {
                if let Some(d) = self.dir(platform, label) {
                    out.push((platform, label, d.to_path_buf()));
                }
            }
        }
        out
    }
}

/// One file of the datasets.
#[derive(Debug, Clone)]
struct Entry {
    platform: Platform,
    label: Label,
    path: PathBuf,
    /// `<SHA256>.<ext>` written by this server (only those are ever removed).
    ours: bool,
}

/// Line of `dataset_index.jsonl` (digest cache).
#[derive(Debug, Serialize, Deserialize)]
struct CacheLine {
    p: String,
    s: u64,
    m: u64,
    h: String,
}

struct Pending {
    sha: String,
    data: Vec<u8>,
    name: String,
    label: Label,
}

/// What `Dataset::export` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportOutcome {
    Written(PathBuf),
    /// The same content is already under this label (any name).
    AlreadyPresent(PathBuf),
    /// The same content is under the other label in a file this server did not write.
    Conflict(Vec<PathBuf>),
    /// Waiting for the index (written when it is ready).
    Queued,
    /// Not a dataset platform, no folder for it, pending queue full or I/O error.
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatasetStatus {
    pub ready: bool,
    pub indexed_files: u64,
    pub pending: usize,
    pub written: u64,
    pub duplicates_skipped: u64,
    pub conflicts: u64,
}

pub struct Dataset {
    paths: DatasetPaths,
    /// SHA-256 (upper case) -> every dataset file with that content.
    index: Mutex<HashMap<String, Vec<Entry>>>,
    ready: AtomicBool,
    indexed_files: AtomicU64,
    pending: Mutex<(Vec<Pending>, usize)>,
    written: AtomicU64,
    duplicates_skipped: AtomicU64,
    conflicts: AtomicU64,
    tmp_seq: AtomicU64,
    /// Where conflicts and the digest cache go (app_dir normally; a temp dir in tests).
    state_dir: PathBuf,
}

impl Dataset {
    /// `dataset_paths.json` next to the server; None when absent, empty or on the
    /// read-only archive server. Starts the background indexer.
    pub fn load() -> Option<Arc<Self>> {
        if crate::config::is_archive() {
            return None;
        }
        let path = config_path();
        let text = std::fs::read_to_string(&path).ok()?;
        let paths = match serde_json::from_str::<DatasetPaths>(&text) {
            Ok(p) if p.any() => p,
            Ok(_) => return None,
            Err(e) => {
                eprintln!("[dataset] {} ignored: {e}", path.display());
                return None;
            }
        };
        eprintln!("[dataset] ML dataset folders from {}", path.display());
        let ds = Arc::new(Self::new(paths, crate::config::app_dir()));
        let bg = Arc::clone(&ds);
        let _ = std::thread::Builder::new().name("dataset-index".into()).spawn(move || bg.build_index());
        Some(ds)
    }

    fn new(paths: DatasetPaths, state_dir: PathBuf) -> Self {
        Dataset {
            paths,
            index: Mutex::new(HashMap::new()),
            ready: AtomicBool::new(false),
            indexed_files: AtomicU64::new(0),
            pending: Mutex::new((Vec::new(), 0)),
            written: AtomicU64::new(0),
            duplicates_skipped: AtomicU64::new(0),
            conflicts: AtomicU64::new(0),
            tmp_seq: AtomicU64::new(0),
            state_dir,
        }
    }

    pub fn status(&self) -> DatasetStatus {
        DatasetStatus {
            ready: self.ready.load(Ordering::Relaxed),
            indexed_files: self.indexed_files.load(Ordering::Relaxed),
            pending: self.pending.lock().unwrap().0.len(),
            written: self.written.load(Ordering::Relaxed),
            duplicates_skipped: self.duplicates_skipped.load(Ordering::Relaxed),
            conflicts: self.conflicts.load(Ordering::Relaxed),
        }
    }

    /// `dataset_conflicts.jsonl`: one JSON object per conflict, newest last.
    pub fn conflicts_file(&self) -> PathBuf {
        self.state_dir.join("dataset_conflicts.jsonl")
    }

    /// `dataset_index.jsonl`: digest cache (path, size, mtime, SHA-256).
    fn cache_file(&self) -> PathBuf {
        self.state_dir.join("dataset_index.jsonl")
    }

    /// The last `limit` conflicts (newest first) for the dashboard.
    pub fn recent_conflicts(&self, limit: usize) -> Vec<serde_json::Value> {
        let Ok(text) = std::fs::read_to_string(self.conflicts_file()) else { return Vec::new() };
        text.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(limit).collect()
    }

    /// Hashes every file in the configured folders (reusing cached digests), records
    /// the conflicts already in the data, then writes the copies that waited.
    pub fn build_index(&self) {
        let started = std::time::Instant::now();
        let mut cache: HashMap<String, (u64, u64, String)> = HashMap::new();
        if let Ok(f) = std::fs::File::open(self.cache_file()) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(c) = serde_json::from_str::<CacheLine>(&line) {
                    cache.insert(c.p, (c.s, c.m, c.h));
                }
            }
        }
        let mut fresh: Vec<CacheLine> = Vec::new();
        let mut map: HashMap<String, Vec<Entry>> = HashMap::new();
        let mut hashed = 0u64;
        for (platform, label, dir) in self.paths.folders() {
            for path in walk_files(&dir) {
                let Ok(meta) = std::fs::metadata(&path) else { continue };
                let size = meta.len();
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs());
                let key = path.to_string_lossy().into_owned();
                let sha = match cache.get(&key) {
                    Some((s, m, h)) if *s == size && *m == mtime => h.clone(),
                    _ => match sha256_file(&path) {
                        Some(h) => {
                            hashed += 1;
                            h
                        }
                        None => continue,
                    },
                };
                fresh.push(CacheLine { p: key, s: size, m: mtime, h: sha.clone() });
                let ours = is_ours(&path, &sha);
                map.entry(sha).or_default().push(Entry { platform, label, path, ours });
                let n = self.indexed_files.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 20_000 == 0 {
                    eprintln!("[dataset] indexing: {n} files ({hashed} hashed)");
                }
            }
        }
        // Rewrite the cache with what exists now (drops deleted files).
        if let Ok(mut f) = std::fs::File::create(self.cache_file()) {
            for c in &fresh {
                if let Ok(s) = serde_json::to_string(c) {
                    let _ = writeln!(f, "{s}");
                }
            }
        }
        // Conflicts already in the data: the same content under both labels.
        for (sha, entries) in &map {
            for platform in [Platform::Windows, Platform::Android, Platform::JavaScript] {
                let mal: Vec<&Entry> = entries.iter().filter(|e| e.platform == platform && e.label == Label::Malware).collect();
                let cln: Vec<&Entry> = entries.iter().filter(|e| e.platform == platform && e.label == Label::Clean).collect();
                if !mal.is_empty() && !cln.is_empty() {
                    let paths: Vec<PathBuf> = mal.iter().chain(cln.iter()).map(|e| e.path.clone()).collect();
                    self.record_conflict("existing", sha, platform, None, "dataset index", &paths);
                }
            }
        }
        let total = self.indexed_files.load(Ordering::Relaxed);
        *self.index.lock().unwrap() = map;
        self.ready.store(true, Ordering::Relaxed);
        eprintln!(
            "[dataset] index ready: {total} files ({hashed} hashed, {} from cache) in {:.1}s",
            total.saturating_sub(hashed),
            started.elapsed().as_secs_f64()
        );
        let waiting = std::mem::take(&mut self.pending.lock().unwrap().0);
        for p in waiting {
            self.export_indexed(&p.sha, &p.data, &p.name, p.label, "queued");
        }
        self.pending.lock().unwrap().1 = 0;
    }

    /// Copies `data` into the folder for its platform and `label`, by content.
    pub fn export(&self, sha256: &str, data: &[u8], name: &str, label: Label) -> ExportOutcome {
        let Some(platform) = platform_of(data, name) else { return ExportOutcome::Skipped };
        if self.paths.dir(platform, label).is_none() {
            return ExportOutcome::Skipped;
        }
        if !self.ready.load(Ordering::Relaxed) {
            let mut g = self.pending.lock().unwrap();
            // Re-check under the lock: the indexer may have just finished.
            if !self.ready.load(Ordering::Relaxed) {
                if g.1 + data.len() > PENDING_MAX_BYTES {
                    eprintln!("[dataset] pending queue full, {sha256} not copied");
                    return ExportOutcome::Skipped;
                }
                g.1 += data.len();
                g.0.push(Pending { sha: sha256.to_string(), data: data.to_vec(), name: name.to_string(), label });
                return ExportOutcome::Queued;
            }
        }
        self.export_indexed(sha256, data, name, label, "scan")
    }

    fn export_indexed(&self, sha256: &str, data: &[u8], name: &str, label: Label, source: &str) -> ExportOutcome {
        let Some(platform) = platform_of(data, name) else { return ExportOutcome::Skipped };
        let Some(dir) = self.paths.dir(platform, label) else { return ExportOutcome::Skipped };
        let sha = sha256.to_ascii_uppercase();
        // One lock for check + write + index update: two copies of the same file
        // arriving together cannot both be written.
        let mut index = self.index.lock().unwrap();
        let entries = index.entry(sha.clone()).or_default();
        entries.retain(|e| e.path.exists()); // removed by hand since the index was built

        if let Some(e) = entries.iter().find(|e| e.platform == platform && e.label == label) {
            self.duplicates_skipped.fetch_add(1, Ordering::Relaxed);
            return ExportOutcome::AlreadyPresent(e.path.clone());
        }
        let theirs: Vec<PathBuf> = entries
            .iter()
            .filter(|e| e.platform == platform && e.label == label.other() && !e.ours)
            .map(|e| e.path.clone())
            .collect();
        if !theirs.is_empty() {
            drop(index);
            self.record_conflict("label", &sha, platform, Some(label), source, &theirs);
            return ExportOutcome::Conflict(theirs);
        }
        // Our own copy under the other label: the verdict flipped, move it.
        entries.retain(|e| {
            if e.platform == platform && e.label == label.other() && e.ours {
                let _ = std::fs::remove_file(&e.path);
                false
            } else {
                true
            }
        });

        let file = format!("{sha}.{}", extension(platform, name));
        let target = dir.join(&file);
        if std::fs::create_dir_all(dir).is_err() {
            return ExportOutcome::Skipped;
        }
        let tmp = dir.join(format!(
            ".{file}.{}-{}.part",
            std::process::id(),
            self.tmp_seq.fetch_add(1, Ordering::Relaxed)
        ));
        if std::fs::write(&tmp, data).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return ExportOutcome::Skipped;
        }
        if target.exists() || std::fs::rename(&tmp, &target).is_err() {
            let _ = std::fs::remove_file(&tmp);
            if target.exists() {
                // Same name, so same content (the name is the SHA-256).
                entries.push(Entry { platform, label, path: target.clone(), ours: true });
                self.duplicates_skipped.fetch_add(1, Ordering::Relaxed);
                return ExportOutcome::AlreadyPresent(target);
            }
            return ExportOutcome::Skipped;
        }
        entries.push(Entry { platform, label, path: target.clone(), ours: true });
        drop(index);
        self.written.fetch_add(1, Ordering::Relaxed);
        self.indexed_files.fetch_add(1, Ordering::Relaxed);
        if let (Ok(meta), Ok(mut f)) = (
            std::fs::metadata(&target),
            std::fs::OpenOptions::new().create(true).append(true).open(self.cache_file()),
        ) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let line = CacheLine { p: target.to_string_lossy().into_owned(), s: meta.len(), m: mtime, h: sha };
            if let Ok(s) = serde_json::to_string(&line) {
                let _ = writeln!(f, "{s}");
            }
        }
        ExportOutcome::Written(target)
    }

    fn record_conflict(&self, kind: &str, sha: &str, platform: Platform, wanted: Option<Label>, source: &str, paths: &[PathBuf]) {
        self.conflicts.fetch_add(1, Ordering::Relaxed);
        let line = serde_json::json!({
            "time": chrono::Utc::now().to_rfc3339(),
            "kind": kind,
            "sha256": sha,
            "platform": platform,
            "wanted_label": wanted,
            "source": source,
            "files": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        });
        eprintln!("[dataset] label conflict ({kind}) {sha}: {}", line["files"]);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.conflicts_file()) {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// `<SHA256>.<ext>` named after its own content: a copy this server wrote.
fn is_ours(path: &Path, sha_upper: &str) -> bool {
    path.file_stem().and_then(|s| s.to_str()).is_some_and(|s| s.eq_ignore_ascii_case(sha_upper))
}

fn sha256_file(path: &Path) -> Option<String> {
    use hex::ToHex;
    use sha2::Digest;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().encode_hex_upper::<String>())
}

/// Regular files under `dir` (not following links), skipping our `.part` temp files.
fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() && !p.extension().is_some_and(|x| x == "part") {
                out.push(p);
            }
        }
    }
    out
}

/// Label of an engine result when (and only when) it comes from a reliable source.
pub fn reliable_label(res: &ResultMessage) -> Option<(Label, &'static str)> {
    if crate::engine_adapter::is_xorfilter_result(res) {
        return None;
    }
    let ruleset = res.rule.as_ref().and_then(|r| r["ruleset"].as_str()).unwrap_or("");
    match res.verdict.as_str() {
        "malicious" if ruleset.starts_with("analyst/") => Some((Label::Malware, "analyst signature")),
        "clean" if ruleset == "analyst/company_allowlist" => Some((Label::Clean, "analyst company allow-list")),
        "clean" if ruleset == "benign_corpus/sha256" => Some((Label::Clean, "benign reference corpus")),
        "clean" if res.signer.as_ref().is_some_and(|s| s.signed && s.trusted) => Some((Label::Clean, "trusted signature")),
        _ => None,
    }
}

/// Label from an analyst verdict (`suspicious` and the rest are not labels).
pub fn human_label(verdict: &str) -> Option<Label> {
    match verdict {
        "malicious" => Some(Label::Malware),
        "clean" => Some(Label::Clean),
        _ => None,
    }
}

pub fn platform_of(data: &[u8], name: &str) -> Option<Platform> {
    let lower = name.to_ascii_lowercase();
    if data.starts_with(b"PK\x03\x04") {
        let head = &data[..data.len().min(8 * 1024 * 1024)];
        if lower.ends_with(".apk") || (contains(head, b"AndroidManifest.xml") && contains(head, b"classes")) {
            return Some(Platform::Android);
        }
        return None;
    }
    if is_pe(data) {
        return Some(Platform::Windows);
    }
    let js_ext = [".js", ".mjs", ".cjs", ".jse"].iter().any(|e| lower.ends_with(e));
    if js_ext && !data.is_empty() && !data[..data.len().min(4096)].contains(&0) {
        return Some(Platform::JavaScript);
    }
    None
}

fn is_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }
    let off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(off..off.saturating_add(4)) == Some(b"PE\0\0".as_slice())
}

fn extension(platform: Platform, name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    match platform {
        Platform::Android => "apk",
        Platform::JavaScript => "js",
        Platform::Windows => {
            for ext in ["dll", "sys", "scr", "ocx", "cpl", "drv", "efi"] {
                if lower.ends_with(&format!(".{ext}")) {
                    return ext;
                }
            }
            "exe"
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(tag: u8) -> Vec<u8> {
        let mut d = vec![0u8; 0x100];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c] = 0x80;
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0xF0] = tag;
        d
    }

    fn sha(data: &[u8]) -> String {
        use hex::ToHex;
        use sha2::Digest;
        sha2::Sha256::digest(data).encode_hex_upper::<String>()
    }

    fn setup(name: &str) -> (PathBuf, Dataset) {
        let root = std::env::temp_dir().join(format!("multron_dataset_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("mal")).unwrap();
        std::fs::create_dir_all(root.join("clean")).unwrap();
        std::fs::create_dir_all(root.join("state")).unwrap();
        let paths = DatasetPaths {
            windows_malware: Some(root.join("mal")),
            windows_clean: Some(root.join("clean")),
            ..Default::default()
        };
        let ds = Dataset::new(paths, root.join("state"));
        (root, ds)
    }

    #[test]
    fn platforms() {
        assert_eq!(platform_of(&pe(1), "a.dll"), Some(Platform::Windows));
        assert_eq!(platform_of(b"PK\x03\x04...AndroidManifest.xml...classes.dex", "x.zip"), Some(Platform::Android));
        assert_eq!(platform_of(b"PK\x03\x04 plain zip", "x.zip"), None);
        assert_eq!(platform_of(b"var a = 1;", "a.js"), Some(Platform::JavaScript));
        assert_eq!(platform_of(b"var a = 1;", "a.txt"), None);
        assert_eq!(platform_of(b"MZ not a pe", "a.exe"), None);
    }

    #[test]
    fn same_name_different_content_both_kept_same_content_once() {
        let (root, ds) = setup("names");
        ds.build_index();
        let (a, b) = (pe(1), pe(2));
        assert!(matches!(ds.export(&sha(&a), &a, "setup.exe", Label::Clean), ExportOutcome::Written(_)));
        assert!(matches!(ds.export(&sha(&b), &b, "setup.exe", Label::Clean), ExportOutcome::Written(_)), "same name, other hash");
        // Same content again, under another name and extension: not written twice.
        assert!(matches!(ds.export(&sha(&a), &a, "other.dll", Label::Clean), ExportOutcome::AlreadyPresent(_)));
        assert_eq!(std::fs::read_dir(root.join("clean")).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn existing_file_under_any_name_is_a_duplicate() {
        let (root, ds) = setup("existing");
        let a = pe(3);
        std::fs::write(root.join("clean").join("notepad_original_name.exe"), &a).unwrap();
        ds.build_index();
        assert!(matches!(ds.export(&sha(&a), &a, "x.exe", Label::Clean), ExportOutcome::AlreadyPresent(_)));
        assert_eq!(std::fs::read_dir(root.join("clean")).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn user_file_under_other_label_is_reported_not_touched() {
        let (root, ds) = setup("conflict");
        let a = pe(4);
        let theirs = root.join("mal").join("sample.bin");
        std::fs::write(&theirs, &a).unwrap();
        ds.build_index();
        assert!(matches!(ds.export(&sha(&a), &a, "x.exe", Label::Clean), ExportOutcome::Conflict(_)));
        assert!(theirs.exists(), "the user's file is never removed");
        assert_eq!(std::fs::read_dir(root.join("clean")).unwrap().count(), 0, "nothing written");
        let log = std::fs::read_to_string(ds.conflicts_file()).unwrap();
        assert!(log.contains(&sha(&a)) && log.contains("\"kind\":\"label\""));
        assert_eq!(ds.status().conflicts, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn our_copy_moves_when_the_label_flips() {
        let (root, ds) = setup("flip");
        ds.build_index();
        let a = pe(5);
        let ExportOutcome::Written(first) = ds.export(&sha(&a), &a, "x.exe", Label::Clean) else { panic!() };
        assert!(matches!(ds.export(&sha(&a), &a, "x.exe", Label::Malware), ExportOutcome::Written(_)));
        assert!(!first.exists(), "our old copy was removed");
        assert_eq!(std::fs::read_dir(root.join("mal")).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn existing_conflicts_are_reported_and_queue_waits_for_index() {
        let (root, ds) = setup("queue");
        let a = pe(6);
        std::fs::write(root.join("mal").join("m.exe"), &a).unwrap();
        std::fs::write(root.join("clean").join("c.exe"), &a).unwrap();
        let b = pe(7);
        assert_eq!(ds.export(&sha(&b), &b, "b.exe", Label::Clean), ExportOutcome::Queued);
        ds.build_index();
        assert_eq!(ds.status().conflicts, 1, "the same content under both labels already");
        assert!(root.join("clean").join(format!("{}.exe", sha(&b))).exists(), "queued copy written");
        // The digest cache lets a second index reuse the hashes.
        let cache = std::fs::read_to_string(root.join("state").join("dataset_index.jsonl")).unwrap();
        assert_eq!(cache.lines().count(), 3);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn labels_need_a_reliable_source() {
        let mut r: ResultMessage = serde_json::from_value(serde_json::json!({ "type": "result", "id": 0 })).unwrap();
        r.verdict = "malicious".into();
        assert_eq!(reliable_label(&r), None, "plain engine verdict");
        r.rule = Some(serde_json::json!({ "ruleset": "analyst/clamav" }));
        assert_eq!(reliable_label(&r).map(|x| x.0), Some(Label::Malware));
        r.rule = Some(serde_json::json!({ "ruleset": "xorfilter/malicious_sha256" }));
        assert_eq!(reliable_label(&r), None, "xor filter is not reliable");
        r.verdict = "clean".into();
        r.rule = Some(serde_json::json!({ "ruleset": "benign_corpus/sha256" }));
        assert_eq!(reliable_label(&r).map(|x| x.0), Some(Label::Clean));
        assert_eq!(human_label("suspicious"), None);
    }
}
