//! Kept files moved by hand out of the work folder into an archive folder the server
//! does not manage (e.g. `usbdosyalar\clean`: the clean uploads, sorted by type, kept
//! on the main PC so the server disk has room for new data).
//!
//! `archived_dirs.json` next to the server names the folders and the category their
//! files were kept under:
//!
//! ```json
//! [
//!   { "path": "C:\\...\\usbdosyalar\\clean", "category": "clean", "name": "usbdosyalar\\clean" }
//! ]
//! ```
//!
//! Every file there is remembered by its SHA-256 in `kept_archived.jsonl` (append-only,
//! last line of a hash wins): the hash from the `<SHA256>_<name>` file name the server
//! gave it, else from the content; the type from its `<type>/` folder. Entries are never
//! removed, so the files stay counted (dashboard, public dataset statistics) after they
//! are deleted from the archive folder or when it is not reachable (another PC). A
//! sample remembered here is not stored in the work folder again when a client sends
//! it, and the archive mirror does not copy it back into the archive.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::dataset::Platform;

pub const CONFIG_FILE: &str = "archived_dirs.json";
pub const INDEX_FILE: &str = "kept_archived.jsonl";

/// Type folders whose files belong to an ML platform (the same as the trainers'
/// `ARCHIVED_CLEAN_TYPES` in hydradragon_ml_models/dataset_paths.py).
const PLATFORM_KINDS: [(&str, Platform); 5] = [
    ("pe32", Platform::Windows),
    ("pe64", Platform::Windows),
    ("msexe", Platform::Windows),
    ("apk", Platform::Android),
    ("javascript", Platform::JavaScript),
];

/// One folder of `archived_dirs.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ArchivedDir {
    pub path: PathBuf,
    /// Work-folder category its files were kept under (`clean`, `malicious`, ...).
    #[serde(default = "default_category")]
    pub category: String,
    /// Display name (dashboard, public dataset statistics); default: the last two
    /// folder names (`usbdosyalar\clean`).
    #[serde(default)]
    pub name: Option<String>,
}

fn default_category() -> String {
    "clean".to_string()
}

impl ArchivedDir {
    fn display_name(&self) -> String {
        if let Some(n) = self.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            return n.chars().take(48).collect();
        }
        let parts: Vec<String> = self.path.iter().rev().take(2).map(|p| p.to_string_lossy().into_owned()).collect();
        parts.into_iter().rev().collect::<Vec<_>>().join("\\")
    }
}

/// Line of `kept_archived.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedFile {
    /// Upper case.
    pub sha256: String,
    pub category: String,
    /// Type folder (`pe32`, `javascript`, `graphics`, ...); empty when the file was
    /// directly in the archive folder.
    pub kind: String,
    pub size: u64,
    pub path: String,
    /// Display name of its archive folder.
    pub group: String,
    /// When the file arrived there (creation time, else modification time; Unix seconds).
    pub added: u64,
}

impl ArchivedFile {
    pub fn platform(&self) -> Option<Platform> {
        PLATFORM_KINDS.iter().find(|(k, _)| *k == self.kind).map(|(_, p)| *p)
    }
}

fn index_path() -> PathBuf {
    crate::config::app_dir().join(INDEX_FILE)
}

fn read_index(path: &Path) -> HashMap<String, ArchivedFile> {
    let mut m = HashMap::new();
    if let Ok(f) = std::fs::File::open(path) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if let Ok(a) = serde_json::from_str::<ArchivedFile>(&line) {
                m.insert(a.sha256.to_ascii_uppercase(), a);
            }
        }
    }
    m
}

fn store() -> &'static RwLock<HashMap<String, ArchivedFile>> {
    static STORE: OnceLock<RwLock<HashMap<String, ArchivedFile>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(read_index(&index_path())))
}

pub fn get(sha: &str) -> Option<ArchivedFile> {
    store().read().unwrap().get(&sha.to_ascii_uppercase()).cloned()
}

/// The sample was archived from this work-folder category.
pub fn is_archived(sha: &str, category: &str) -> bool {
    store().read().unwrap().get(&sha.to_ascii_uppercase()).is_some_and(|a| a.category == category)
}

/// (SHA-256, category) of every sample remembered in the `kept_archived.jsonl` of
/// another server folder (the archive mirror's target).
pub fn archived_in(server_dir: &Path) -> HashSet<(String, String)> {
    read_index(&server_dir.join(INDEX_FILE)).into_values().map(|a| (a.sha256, a.category)).collect()
}

/// `archived_dirs.json` next to the server (empty when absent or unreadable).
pub fn configured_dirs() -> Vec<ArchivedDir> {
    let path = crate::config::app_dir().join(CONFIG_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else { return Vec::new() };
    match serde_json::from_str::<Vec<ArchivedDir>>(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[archived] {} ignored: {e}", path.display());
            Vec::new()
        }
    }
}

/// `<SHA256>_<name>` (the server's kept-file name): the hash, upper case.
fn sha_from_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let sha = name.get(..64)?;
    (sha.chars().all(|c| c.is_ascii_hexdigit()) && name.as_bytes().get(64) == Some(&b'_')).then(|| sha.to_ascii_uppercase())
}

/// Remembers every file of the folders that is not remembered yet. Folders that are not
/// reachable are skipped (their entries stay). Returns (new entries, files seen).
pub fn index_dirs(dirs: &[ArchivedDir]) -> (u64, u64) {
    let index = index_path();
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&index).ok();
    let (mut added, mut seen) = (0u64, 0u64);
    for dir in dirs {
        if !dir.path.is_dir() {
            eprintln!("[archived] {} is not reachable; its {} remembered files stay counted", dir.path.display(), count_group(&dir.display_name()));
            continue;
        }
        let group = dir.display_name();
        for path in crate::dataset::walk_files(&dir.path, &[]) {
            seen += 1;
            let path_text = path.to_string_lossy().into_owned();
            let named = sha_from_name(&path);
            if let Some(sha) = &named {
                if store().read().unwrap().get(sha).is_some_and(|a| a.path == path_text) {
                    continue;
                }
            }
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if meta.len() == 0 {
                continue;
            }
            let Some(sha) = named.or_else(|| crate::dataset::sha256_file(&path)) else { continue };
            if sha == crate::dataset::EMPTY_SHA256 {
                continue;
            }
            let kind = path
                .strip_prefix(&dir.path)
                .ok()
                .and_then(|rel| {
                    let mut c = rel.components();
                    let first = c.next()?;
                    c.next().map(|_| first.as_os_str().to_string_lossy().to_ascii_lowercase())
                })
                .unwrap_or_default();
            let secs = |t: std::io::Result<std::time::SystemTime>| {
                t.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
            };
            let a = ArchivedFile {
                sha256: sha.clone(),
                category: dir.category.clone(),
                kind,
                size: meta.len(),
                path: path_text,
                group: group.clone(),
                added: match secs(meta.created()) {
                    0 => secs(meta.modified()),
                    c => c,
                },
            };
            if let (Some(f), Ok(line)) = (out.as_mut(), serde_json::to_string(&a)) {
                let _ = writeln!(f, "{line}");
            }
            store().write().unwrap().insert(sha, a);
            added += 1;
            if added % 20_000 == 0 {
                eprintln!("[archived] indexing: {added} new files");
            }
        }
    }
    (added, seen)
}

fn count_group(group: &str) -> usize {
    store().read().unwrap().values().filter(|a| a.group == group).count()
}

/// Indexes the configured folders in the background (normal start, not on the
/// read-only archive server or in standby).
pub fn start() {
    let dirs = configured_dirs();
    if dirs.is_empty() {
        return;
    }
    let _ = std::thread::Builder::new().name("archived-index".into()).spawn(move || {
        let started = std::time::Instant::now();
        let (added, seen) = index_dirs(&dirs);
        eprintln!(
            "[archived] {} remembered files ({added} new, {seen} on disk now) in {:.1}s",
            store().read().unwrap().len(),
            started.elapsed().as_secs_f64()
        );
    });
}

/// Dashboard figures per archive folder: files, GB and files per type (most first).
pub fn counts() -> serde_json::Value {
    #[derive(Default)]
    struct G {
        category: String,
        files: u64,
        bytes: u64,
        kinds: BTreeMap<String, u64>,
    }
    let mut groups: BTreeMap<String, G> = BTreeMap::new();
    for a in store().read().unwrap().values() {
        let g = groups.entry(a.group.clone()).or_default();
        g.category = a.category.clone();
        g.files += 1;
        g.bytes += a.size;
        *g.kinds.entry(if a.kind.is_empty() { "other".to_string() } else { a.kind.clone() }).or_default() += 1;
    }
    let list: Vec<serde_json::Value> = groups
        .into_iter()
        .map(|(name, g)| {
            let mut kinds: Vec<(String, u64)> = g.kinds.into_iter().collect();
            kinds.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            serde_json::json!({
                "name": name,
                "category": g.category,
                "files": g.files,
                "gb": g.bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                "types": kinds,
            })
        })
        .collect();
    serde_json::Value::Array(list)
}

/// Remembered files of an ML platform, for the public dataset statistics.
pub fn dataset_samples() -> Vec<crate::dataset::ArchivedSample> {
    store()
        .read()
        .unwrap()
        .values()
        .filter_map(|a| {
            Some(crate::dataset::ArchivedSample {
                sha256: a.sha256.clone(),
                platform: a.platform()?,
                label: crate::dataset::human_label(&a.category)?,
                added: a.added,
                group: a.group.clone(),
            })
        })
        .collect()
}
