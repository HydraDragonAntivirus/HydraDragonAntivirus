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
//! Every key also takes a source tag, a display name and/or several folders. `"own"` is
//! your own collection, `"public"` a public dataset you downloaded; a plain path is
//! `"own"`. `"name"` (e.g. "F-Droid") shows the folder as its own line in the public
//! statistics, next to the totals (the name is published, the path never is). A
//! configured folder inside another one (`benign\F-Droid` inside `benign`) keeps its
//! own source and name: the outer folder's walk skips it. Folders whose name starts
//! with `.` (`.cache`, `.git`, ...) are never read:
//!
//! ```json
//! {
//!   "windows_malware": [
//!     "C:\\...\\usbdosyalar\\datamaliciousorder",
//!     { "path": "D:\\public\\some_public_set\\malware", "source": "public", "name": "Public set" }
//!   ],
//!   "android_clean": [
//!     { "path": "C:\\...\\dataset\\benign", "source": "own", "name": "Own APKs" },
//!     { "path": "C:\\...\\dataset\\benign\\F-Droid", "source": "public", "name": "F-Droid" }
//!   ],
//!   "windows_clean": { "path": "C:\\...\\usbdosyalar\\data2", "source": "own" }
//! }
//! ```
//!
//! A file is copied as `<SHA256>.<ext>` into the (first "own") folder of its platform
//! (APK -> android, PE -> windows, JavaScript -> javascript) and label, ONLY when the
//! label comes from a reliable source, so the models never learn the engine's own mistakes:
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
//!
//! `Dataset::public_stats` counts the unique hashes per platform and label that are only
//! in "own" folders, only in "public" folders, or in both, plus the last 30 days of
//! additions. It holds counts only - never a folder, file name or hash.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::engine_adapter::ResultMessage;

/// Copies waiting for the index, at most this many bytes in memory.
const PENDING_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Days of additions in `public_stats`.
pub const STATS_DAYS: usize = 30;

/// Backup folders of files taken out of the datasets (`deleted_from_data2_pe`, ...):
/// never indexed or used for training.
pub const BACKUP_PREFIX: &str = "deleted_from_";

/// SHA-256 of an empty file. Empty files carry no sample (a failed copy or download):
/// never indexed, exported, counted or reported as a label conflict.
pub const EMPTY_SHA256: &str = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DatasetPaths {
    #[serde(default)]
    pub windows_malware: FolderList,
    #[serde(default)]
    pub windows_clean: FolderList,
    #[serde(default)]
    pub android_malware: FolderList,
    #[serde(default)]
    pub android_clean: FolderList,
    #[serde(default)]
    pub javascript_malware: FolderList,
    #[serde(default)]
    pub javascript_clean: FolderList,
}

/// Where the files of a folder come from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Your own collection (the default, and where the server writes its copies).
    #[default]
    Own,
    /// A public dataset.
    Public,
}

/// One folder in `dataset_paths.json`: a plain path ("own") or
/// `{ "path", "source", "name" }`. `name` is a display name for the statistics
/// (e.g. "F-Droid"); it is shown on the website, the path never is.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum FolderSpec {
    Path(PathBuf),
    Tagged {
        path: PathBuf,
        #[serde(default)]
        source: Source,
        #[serde(default)]
        name: Option<String>,
    },
}

impl FolderSpec {
    fn into_parts(self) -> ((PathBuf, Source), Option<String>) {
        match self {
            FolderSpec::Path(p) => ((p, Source::Own), None),
            FolderSpec::Tagged { path, source, name } => {
                let name = name.map(|n| n.trim().chars().take(48).collect::<String>()).filter(|n| !n.is_empty());
                ((path, source), name)
            }
        }
    }
}

/// The folders of one platform + label: `null`, one folder or an array of folders,
/// with the display name of each (same order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderList(pub Vec<(PathBuf, Source)>, pub Vec<Option<String>>);

fn folder_list(specs: Vec<FolderSpec>) -> FolderList {
    let (folders, names) = specs.into_iter().map(FolderSpec::into_parts).unzip();
    FolderList(folders, names)
}

impl FolderList {
    #[cfg(test)]
    pub fn own(path: impl Into<PathBuf>) -> Self {
        FolderList(vec![(path.into(), Source::Own)], vec![None])
    }
}

impl<'de> Deserialize<'de> for FolderList {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(FolderSpec),
            Many(Vec<FolderSpec>),
        }
        Ok(match Option::<OneOrMany>::deserialize(d)? {
            None => FolderList::default(),
            Some(OneOrMany::One(f)) => folder_list(vec![f]),
            Some(OneOrMany::Many(v)) => folder_list(v),
        })
    }
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

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::Windows, Platform::Android, Platform::JavaScript];

    /// Key in the public stats.
    pub fn key(self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::Android => "android",
            Platform::JavaScript => "javascript",
        }
    }
}

impl Label {
    pub const ALL: [Label; 2] = [Label::Malware, Label::Clean];

    /// Key in the public stats.
    pub fn key(self) -> &'static str {
        match self {
            Label::Malware => "malware",
            Label::Clean => "clean",
        }
    }

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

    fn list(&self, platform: Platform, label: Label) -> &FolderList {
        match (platform, label) {
            (Platform::Windows, Label::Malware) => &self.windows_malware,
            (Platform::Windows, Label::Clean) => &self.windows_clean,
            (Platform::Android, Label::Malware) => &self.android_malware,
            (Platform::Android, Label::Clean) => &self.android_clean,
            (Platform::JavaScript, Label::Malware) => &self.javascript_malware,
            (Platform::JavaScript, Label::Clean) => &self.javascript_clean,
        }
    }

    /// Folder the server writes its copies to: the first "own" folder of that
    /// platform and label (public datasets are never written to).
    pub fn dir(&self, platform: Platform, label: Label) -> Option<&Path> {
        self.list(platform, label)
            .0
            .iter()
            .find(|(p, s)| *s == Source::Own && !p.as_os_str().is_empty())
            .map(|(p, _)| p.as_path())
    }

    /// Display name of a configured folder (`name` in dataset_paths.json).
    pub fn name_of(&self, platform: Platform, label: Label, dir: &Path) -> Option<String> {
        let l = self.list(platform, label);
        l.0.iter().position(|(p, _)| p == dir).and_then(|i| l.1.get(i).cloned().flatten())
    }

    /// Configured folders of the same platform and label that lie inside `dir`: their
    /// files belong to them (their own source and name), not to `dir`.
    pub fn nested_in(&self, platform: Platform, label: Label, dir: &Path) -> Vec<PathBuf> {
        self.list(platform, label).0.iter().filter(|(p, _)| is_inside(p, dir)).map(|(p, _)| p.clone()).collect()
    }

    /// Every configured folder with its platform, label and source (a folder listed
    /// twice under the same key is walked once).
    pub fn folders(&self) -> Vec<(Platform, Label, Source, PathBuf)> {
        let mut out: Vec<(Platform, Label, Source, PathBuf)> = Vec::new();
        for platform in Platform::ALL {
            for label in Label::ALL {
                for (p, source) in &self.list(platform, label).0 {
                    if p.as_os_str().is_empty() || out.iter().any(|f| f.0 == platform && f.1 == label && f.3 == *p) {
                        continue;
                    }
                    out.push((platform, label, *source, p.clone()));
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
    /// Own collection or public dataset (from the folder).
    source: Source,
    /// When the file arrived (creation time, else modification time; Unix seconds).
    added: u64,
    /// Display name of its folder (statistics), if the folder has one.
    group: Option<Arc<str>>,
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
    /// Files moved to the folder of their human verdict, or removed as duplicates of a
    /// file already there (`dataset_moves.jsonl`).
    pub moved_by_human: u64,
    /// Copies of the same content in the dataset folders removed at indexing.
    pub duplicates_removed: u64,
}

/// Unique hashes by where they are: only own folders, only public folders, both, or
/// only sent by users (scanned by the server, in no dataset folder).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SourceCounts {
    pub own_only: u64,
    pub public_only: u64,
    pub both: u64,
    pub users_only: u64,
}

impl SourceCounts {
    fn bump(&mut self, own: bool, public: bool) {
        match (own, public) {
            (true, true) => self.both += 1,
            (true, false) => self.own_only += 1,
            (false, true) => self.public_only += 1,
            (false, false) => {}
        }
    }

    pub fn total(&self) -> u64 {
        self.own_only + self.public_only + self.both + self.users_only
    }
}

/// One file users sent (threat intel): platform from its file name, label from its
/// verdict (None = unknown, suspicious or possible clean: counted under "all" only).
#[derive(Debug, Clone)]
pub struct UserFile {
    /// SHA-256, any case.
    pub sha256: String,
    pub platform: Option<Platform>,
    pub label: Option<Label>,
    /// First seen (Unix seconds).
    pub added: u64,
}

/// Group name of the files users sent in `PublicStats::groups` (the site translates it).
pub const USERS_GROUP: &str = "@users";

impl UserFile {
    /// From a threat-intel record: effective verdict (human first) and file names.
    pub fn new(sha256: &str, verdict: &str, names: &[String], first_seen: &str) -> Self {
        UserFile {
            sha256: sha256.to_string(),
            platform: names.iter().find_map(|n| platform_of_name(n)),
            label: human_label(verdict),
            added: chrono::DateTime::parse_from_rfc3339(first_seen).map_or(0, |d| d.timestamp().max(0) as u64),
        }
    }
}

/// Platform of a file known only by name (no content): PE, APK or JavaScript extensions.
pub fn platform_of_name(name: &str) -> Option<Platform> {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e)?;
    match ext {
        "exe" | "dll" | "sys" | "scr" | "ocx" | "cpl" | "drv" | "efi" | "mui" | "com" | "ax" | "acm" | "pyd" | "node" => {
            Some(Platform::Windows)
        }
        "apk" | "xapk" | "apks" => Some(Platform::Android),
        "js" | "mjs" | "cjs" | "jse" => Some(Platform::JavaScript),
        _ => None,
    }
}

/// Hashes first seen on one UTC day (`YYYY-MM-DD`), by where they are now.
#[derive(Debug, Clone, Serialize)]
pub struct DayCounts {
    pub date: String,
    #[serde(flatten)]
    pub counts: SourceCounts,
}

/// One platform + label filter (either may be "all").
#[derive(Debug, Clone, Serialize)]
pub struct StatsCell {
    #[serde(flatten)]
    pub counts: SourceCounts,
    pub total: u64,
    /// The last `STATS_DAYS` days, oldest first, zero days included.
    pub daily: Vec<DayCounts>,
}

/// Counts only - no folder, file name or hash. `cells[platform][label]` with
/// platform in all/windows/android/javascript and label in all/malware/clean.
#[derive(Debug, Clone, Serialize)]
pub struct PublicStats {
    pub days: usize,
    pub cells: BTreeMap<&'static str, BTreeMap<&'static str, StatsCell>>,
    /// Per folder display name (`name` in dataset_paths.json; unnamed folders are not
    /// listed): `groups[name][platform][label]`, unique hashes, same filters and days
    /// as `cells`. A hash in two named folders counts in both.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, BTreeMap<&'static str, BTreeMap<&'static str, GroupCell>>>,
}

/// Unique hashes of one named folder group for one platform + label filter.
#[derive(Debug, Clone, Serialize)]
pub struct GroupCell {
    pub total: u64,
    /// The last `STATS_DAYS` days, oldest first (same dates as `cells`).
    pub daily: Vec<u64>,
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
    /// Human verdicts that arrived before the index was ready (applied when it is).
    pending_human: Mutex<Vec<(String, Label)>>,
    /// Files moved to the folder of their human verdict, or removed there as duplicates.
    moved_by_human: AtomicU64,
    /// Copies of the same content (same platform and label) removed by the indexer.
    duplicates_removed: AtomicU64,
    /// Off only in tests that count duplicates on purpose.
    remove_dups: AtomicBool,
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
            pending_human: Mutex::new(Vec::new()),
            moved_by_human: AtomicU64::new(0),
            duplicates_removed: AtomicU64::new(0),
            remove_dups: AtomicBool::new(true),
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
            moved_by_human: self.moved_by_human.load(Ordering::Relaxed),
            duplicates_removed: self.duplicates_removed.load(Ordering::Relaxed),
        }
    }

    /// Copies this server wrote into the dataset folders (`<SHA256>.<ext>`) whose
    /// content is in `kept` (upper-case SHA-256 of the multron_incoming files, which
    /// carry the telemetry): counted (`dry_run`) or moved to the backup folder
    /// (`backup_dir`; nothing is deleted). Files that were in the
    /// dataset folders before (your own and public collections) are never touched.
    /// Each removal is a "duplicate_removed" line in `dataset_moves.jsonl`.
    /// None until the index is ready. Returns (files, bytes).
    pub fn remove_copies_of_kept(&self, kept: &std::collections::HashSet<String>, dry_run: bool) -> Option<(u64, u64)> {
        if !self.ready.load(Ordering::Relaxed) {
            return None;
        }
        let (mut files, mut bytes) = (0u64, 0u64);
        let mut log = if dry_run { None } else { std::fs::OpenOptions::new().create(true).append(true).open(self.moves_file()).ok() };
        let mut index = self.index.lock().unwrap();
        for (sha, entries) in index.iter_mut() {
            if !kept.contains(sha) {
                continue;
            }
            entries.retain(|e| {
                if !e.ours {
                    return true;
                }
                let len = std::fs::metadata(&e.path).map(|m| m.len()).unwrap_or(0);
                if dry_run {
                    files += 1;
                    bytes += len;
                    return true;
                }
                let backup = match self.to_backup(e.platform, e.label, &e.path, sha) {
                    Ok(b) => b,
                    Err(err) => {
                        eprintln!("[dataset] could not move {} to the backup folder: {err}", e.path.display());
                        return true;
                    }
                };
                files += 1;
                bytes += len;
                if let Some(f) = log.as_mut() {
                    let line = serde_json::json!({
                        "time": chrono::Utc::now().to_rfc3339(),
                        "action": "duplicate_removed",
                        "sha256": sha,
                        "platform": e.platform,
                        "from_label": e.label,
                        "to_label": e.label,
                        "from": e.path.display().to_string(),
                        "backup": backup.display().to_string(),
                        "duplicate_of": "multron_incoming",
                        "reason": "copy of a multron_incoming file",
                    });
                    let _ = writeln!(f, "{line}");
                }
                false
            });
        }
        index.retain(|_, v| !v.is_empty());
        drop(index);
        if !dry_run && files > 0 {
            self.indexed_files.fetch_sub(files, Ordering::Relaxed);
            self.duplicates_removed.fetch_add(files, Ordering::Relaxed);
        }
        Some((files, bytes))
    }

    /// Public counts per platform and label (None until the index is ready). `users`:
    /// every file users sent, counted as "users_only" where no dataset folder has it.
    pub fn public_stats(&self, users: &[UserFile]) -> Option<PublicStats> {
        if !self.ready.load(Ordering::Relaxed) {
            return None;
        }
        Some(self.public_stats_at(now_secs(), users))
    }

    /// Every hash is counted once per filter: "own_only" when all its files in the
    /// filter are in own folders, "public_only" when all are in public folders, "both"
    /// otherwise. A hash's day is the earliest arrival of its files in the filter.
    /// A hash users sent that is in no dataset folder of the filter is "users_only"
    /// (day: first seen); all of them also form the `USERS_GROUP` group.
    fn public_stats_at(&self, now: u64, users: &[UserFile]) -> PublicStats {
        const PLATFORMS: [Option<Platform>; 4] =
            [None, Some(Platform::Windows), Some(Platform::Android), Some(Platform::JavaScript)];
        const LABELS: [Option<Label>; 3] = [None, Some(Label::Malware), Some(Label::Clean)];
        let today = now / 86_400;
        let first = today + 1 - STATS_DAYS as u64;
        let mut acc = vec![(SourceCounts::default(), vec![SourceCounts::default(); STATS_DAYS]); 12];
        let mut gacc: BTreeMap<Arc<str>, Vec<(u64, Vec<u64>)>> = BTreeMap::new();
        {
            let index = self.index.lock().unwrap();
            for entries in index.values() {
                // Named groups: earliest arrival per platform x label, per group.
                let mut gcells: Vec<(Arc<str>, [u64; 6])> = Vec::new();
                for e in entries {
                    let Some(g) = e.group.as_ref() else { continue };
                    let i = match gcells.iter().position(|(n, _)| n == g) {
                        Some(i) => i,
                        None => {
                            gcells.push((Arc::clone(g), [u64::MAX; 6]));
                            gcells.len() - 1
                        }
                    };
                    let c = &mut gcells[i].1[platform_idx(e.platform) * 2 + label_idx(e.label)];
                    *c = (*c).min(e.added);
                }
                for (name, cell) in &gcells {
                    let a = gacc.entry(Arc::clone(name)).or_insert_with(|| vec![(0, vec![0; STATS_DAYS]); 12]);
                    for (pi, pf) in PLATFORMS.iter().enumerate() {
                        for (li, lf) in LABELS.iter().enumerate() {
                            let mut added = u64::MAX;
                            for p in Platform::ALL {
                                for l in Label::ALL {
                                    if pf.is_none_or(|x| x == p) && lf.is_none_or(|x| x == l) {
                                        added = added.min(cell[platform_idx(p) * 2 + label_idx(l)]);
                                    }
                                }
                            }
                            if added == u64::MAX {
                                continue;
                            }
                            let slot = &mut a[pi * 3 + li];
                            slot.0 += 1;
                            let day = added / 86_400;
                            if (first..=today).contains(&day) {
                                slot.1[(day - first) as usize] += 1;
                            }
                        }
                    }
                }
                // (in own, in public, earliest arrival) per platform x label.
                let mut cell = [(false, false, u64::MAX); 6];
                for e in entries {
                    let c = &mut cell[platform_idx(e.platform) * 2 + label_idx(e.label)];
                    match e.source {
                        Source::Own => c.0 = true,
                        Source::Public => c.1 = true,
                    }
                    c.2 = c.2.min(e.added);
                }
                for (pi, pf) in PLATFORMS.iter().enumerate() {
                    for (li, lf) in LABELS.iter().enumerate() {
                        let (mut own, mut public, mut added) = (false, false, u64::MAX);
                        for p in Platform::ALL {
                            if pf.is_some_and(|x| x != p) {
                                continue;
                            }
                            for l in Label::ALL {
                                if lf.is_some_and(|x| x != l) {
                                    continue;
                                }
                                let c = cell[platform_idx(p) * 2 + label_idx(l)];
                                own |= c.0;
                                public |= c.1;
                                added = added.min(c.2);
                            }
                        }
                        if !own && !public {
                            continue;
                        }
                        let a = &mut acc[pi * 3 + li];
                        a.0.bump(own, public);
                        let day = added / 86_400;
                        if (first..=today).contains(&day) {
                            a.1[(day - first) as usize].bump(own, public);
                        }
                    }
                }
            }
            // Files users sent. Several records of one hash count once.
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::with_capacity(users.len());
            let mut uacc = vec![(0u64, vec![0u64; STATS_DAYS]); 12];
            for u in users {
                let sha = u.sha256.to_ascii_uppercase();
                if sha == EMPTY_SHA256 || !seen.insert(sha.clone()) {
                    continue;
                }
                let entries = index.get(&sha);
                let day = u.added / 86_400;
                let day = (first..=today).contains(&day).then(|| (day - first) as usize);
                for (pi, pf) in PLATFORMS.iter().enumerate() {
                    if pf.is_some_and(|x| Some(x) != u.platform) {
                        continue;
                    }
                    for (li, lf) in LABELS.iter().enumerate() {
                        if lf.is_some_and(|x| Some(x) != u.label) {
                            continue;
                        }
                        let g = &mut uacc[pi * 3 + li];
                        g.0 += 1;
                        if let Some(d) = day {
                            g.1[d] += 1;
                        }
                        let in_dataset = entries.is_some_and(|es| {
                            es.iter().any(|e| pf.is_none_or(|x| x == e.platform) && lf.is_none_or(|x| x == e.label))
                        });
                        if in_dataset {
                            continue;
                        }
                        let a = &mut acc[pi * 3 + li];
                        a.0.users_only += 1;
                        if let Some(d) = day {
                            a.1[d].users_only += 1;
                        }
                    }
                }
            }
            if !seen.is_empty() {
                gacc.insert(Arc::from(USERS_GROUP), uacc);
            }
        }
        let dates: Vec<String> = (0..STATS_DAYS as u64)
            .map(|i| {
                chrono::DateTime::from_timestamp(((first + i) * 86_400) as i64, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            })
            .collect();
        let mut cells: BTreeMap<&'static str, BTreeMap<&'static str, StatsCell>> = BTreeMap::new();
        for (pi, pf) in PLATFORMS.iter().enumerate() {
            for (li, lf) in LABELS.iter().enumerate() {
                let (counts, days) = &acc[pi * 3 + li];
                let daily = dates
                    .iter()
                    .zip(days)
                    .map(|(date, c)| DayCounts { date: date.clone(), counts: *c })
                    .collect();
                cells.entry(pf.map_or("all", Platform::key)).or_default().insert(
                    lf.map_or("all", Label::key),
                    StatsCell { counts: *counts, total: counts.total(), daily },
                );
            }
        }
        let mut groups: BTreeMap<String, BTreeMap<&'static str, BTreeMap<&'static str, GroupCell>>> = BTreeMap::new();
        for (name, a) in gacc {
            let g = groups.entry(name.to_string()).or_default();
            for (pi, pf) in PLATFORMS.iter().enumerate() {
                for (li, lf) in LABELS.iter().enumerate() {
                    let (total, daily) = &a[pi * 3 + li];
                    if *total == 0 {
                        continue;
                    }
                    g.entry(pf.map_or("all", Platform::key))
                        .or_default()
                        .insert(lf.map_or("all", Label::key), GroupCell { total: *total, daily: daily.clone() });
                }
            }
        }
        PublicStats { days: STATS_DAYS, cells, groups }
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
        text.lines()
            .rev()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| !v["sha256"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(EMPTY_SHA256)))
            .take(limit)
            .collect()
    }

    /// Drops the "existing" conflicts of earlier index builds (each build finds them
    /// again) and lines about empty files; conflicts from exports stay.
    fn prune_conflicts(&self) {
        let path = self.conflicts_file();
        let Ok(text) = std::fs::read_to_string(&path) else { return };
        let kept: Vec<&str> = text
            .lines()
            .filter(|l| {
                serde_json::from_str::<serde_json::Value>(l).is_ok_and(|v| {
                    v["kind"] != "existing" && !v["sha256"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(EMPTY_SHA256))
                })
            })
            .collect();
        if kept.len() != text.lines().count() {
            let mut out = kept.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            let _ = std::fs::write(&path, out);
        }
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
        let mut empty = 0u64;
        for (platform, label, source, dir) in self.paths.folders() {
            // A configured folder inside this one is walked on its own (its source and
            // name win), so its files are not counted twice.
            let nested = self.paths.nested_in(platform, label, &dir);
            let group: Option<Arc<str>> = self.paths.name_of(platform, label, &dir).map(Arc::from);
            for path in walk_files(&dir, &nested) {
                let Ok(meta) = std::fs::metadata(&path) else { continue };
                let size = meta.len();
                if size == 0 {
                    empty += 1;
                    continue;
                }
                let mtime = unix_secs(meta.modified().ok());
                let added = match unix_secs(meta.created().ok()) {
                    0 => mtime,
                    c => c,
                };
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
                map.entry(sha).or_default().push(Entry { platform, label, path, ours, source, added, group: group.clone() });
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
        let removed = if self.remove_dups.load(Ordering::Relaxed) { self.remove_duplicates(&mut map) } else { 0 };
        if removed > 0 {
            eprintln!("[dataset] {removed} duplicate files removed (same content, same platform and label; dataset_moves.jsonl)");
        }
        // Conflicts already in the data: the same content under both labels.
        self.prune_conflicts();
        for (sha, entries) in &map {
            for platform in Platform::ALL {
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
            "[dataset] index ready: {total} files ({hashed} hashed, {} from cache, {empty} empty files skipped) in {:.1}s",
            total.saturating_sub(hashed),
            started.elapsed().as_secs_f64()
        );
        // Human verdicts first: the queued copies then find their files in place.
        let human = std::mem::take(&mut *self.pending_human.lock().unwrap());
        let moved: usize = human.iter().map(|(sha, label)| self.apply_human_verdict(sha, *label)).sum();
        if moved > 0 {
            eprintln!("[dataset] {moved} files moved to the folder of their human verdict (dataset_moves.jsonl)");
        }
        let waiting = std::mem::take(&mut self.pending.lock().unwrap().0);
        for p in waiting {
            self.export_indexed(&p.sha, &p.data, &p.name, p.label, "queued");
        }
        self.pending.lock().unwrap().1 = 0;
    }

    /// Human verdicts (sha256, verdict) for files that may be in the datasets, e.g.
    /// every completed review at start. Returns how many files were moved (0 while the
    /// index is not ready: they are applied when it is).
    pub fn apply_human_verdicts(&self, verdicts: &[(String, String)]) -> usize {
        let labelled = verdicts.iter().filter_map(|(sha, v)| Some((sha.clone(), human_label(v)?)));
        if !self.ready.load(Ordering::Relaxed) {
            let mut g = self.pending_human.lock().unwrap();
            if !self.ready.load(Ordering::Relaxed) {
                g.extend(labelled);
                return 0;
            }
        }
        labelled.map(|(sha, label)| self.apply_human_verdict(&sha, label)).sum()
    }

    /// A human verdict wins over the dataset folders, without loss and without
    /// duplicates: per platform, one file with this content ends up under the verdict's
    /// label. A file under the other label is moved (not copied) to a folder of the
    /// verdict's label: the folder with the same display name if there is one, else
    /// the first own folder. When that label already has the same content, the copy
    /// under the other label is a duplicate and goes to the backup folder instead
    /// (`backup_dir`; nothing is deleted). The file name is kept (" (2)" etc. when the name is
    /// taken by other content); across drives the copy is checked by SHA-256 before
    /// the original is removed. Each step is a line in `dataset_moves.jsonl`: "moved"
    /// (undo: move `to` back to `from`) or "duplicate_removed" (`from` had the same
    /// content as `duplicate_of`). Returns how many files moved or were removed.
    pub fn apply_human_verdict(&self, sha256: &str, label: Label) -> usize {
        let sha = sha256.to_ascii_uppercase();
        if sha == EMPTY_SHA256 {
            return 0;
        }
        if !self.ready.load(Ordering::Relaxed) {
            let mut g = self.pending_human.lock().unwrap();
            if !self.ready.load(Ordering::Relaxed) {
                g.push((sha, label));
                return 0;
            }
        }
        let mut moved = 0;
        let mut index = self.index.lock().unwrap();
        let Some(entries) = index.get_mut(&sha) else { return 0 };
        entries.retain(|e| e.path.exists());
        let mut i = 0;
        while i < entries.len() {
            if entries[i].label != label.other() {
                i += 1;
                continue;
            }
            let platform = entries[i].platform;
            // Already under the verdict's label: this copy is a duplicate.
            if let Some(k) = entries.iter().position(|x| x.platform == platform && x.label == label) {
                let (dup, original) = (entries[i].path.clone(), entries[k].path.clone());
                let backup = match self.to_backup(platform, label.other(), &dup, &sha) {
                    Ok(b) => b,
                    Err(err) => {
                        eprintln!("[dataset] human verdict {sha}: could not move duplicate {} to the backup folder: {err}", dup.display());
                        i += 1;
                        continue;
                    }
                };
                let line = serde_json::json!({
                    "time": chrono::Utc::now().to_rfc3339(),
                    "action": "duplicate_removed",
                    "sha256": sha,
                    "platform": platform,
                    "from_label": label.other(),
                    "to_label": label,
                    "from": dup.display().to_string(),
                    "backup": backup.display().to_string(),
                    "duplicate_of": original.display().to_string(),
                    "reason": "human verdict",
                });
                eprintln!("[dataset] human verdict: {} -> {} (same content as {})", dup.display(), backup.display(), original.display());
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.moves_file()) {
                    let _ = writeln!(f, "{line}");
                }
                entries.remove(i);
                moved += 1;
                continue;
            }
            let e = &mut entries[i];
            i += 1;
            let Some((dir, source, group)) = self.human_target(e.platform, label, e.group.as_deref()) else {
                eprintln!("[dataset] human verdict {sha}: no {} folder for {}; {} left in place", label.key(), e.platform.key(), e.path.display());
                continue;
            };
            let Some(name) = e.path.file_name().map(|n| n.to_os_string()) else { continue };
            let target = match free_name(&dir, Path::new(&name)) {
                Some(t) => t,
                None => continue,
            };
            if let Err(err) = move_verified(&e.path, &target, &sha) {
                eprintln!("[dataset] human verdict {sha}: could not move {}: {err}", e.path.display());
                continue;
            }
            let line = serde_json::json!({
                "time": chrono::Utc::now().to_rfc3339(),
                "action": "moved",
                "sha256": sha,
                "platform": e.platform,
                "from_label": e.label,
                "to_label": label,
                "from": e.path.display().to_string(),
                "to": target.display().to_string(),
                "reason": "human verdict",
            });
            eprintln!("[dataset] human verdict: {} -> {}", e.path.display(), target.display());
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.moves_file()) {
                let _ = writeln!(f, "{line}");
            }
            if let (Ok(meta), Ok(mut f)) = (
                std::fs::metadata(&target),
                std::fs::OpenOptions::new().create(true).append(true).open(self.cache_file()),
            ) {
                let c = CacheLine { p: target.to_string_lossy().into_owned(), s: meta.len(), m: unix_secs(meta.modified().ok()), h: sha.clone() };
                if let Ok(s) = serde_json::to_string(&c) {
                    let _ = writeln!(f, "{s}");
                }
            }
            e.ours = is_ours(&target, &sha);
            e.path = target;
            e.label = label;
            e.source = source;
            e.group = group;
            moved += 1;
        }
        drop(index);
        if moved > 0 {
            self.moved_by_human.fetch_add(moved as u64, Ordering::Relaxed);
            self.drop_conflicts_for(&sha);
        }
        moved
    }

    /// One file per content, platform and label: the other copies are moved to the
    /// backup folder (`backup_dir`, nothing is deleted; the content stays in the kept one). Kept: a public dataset file first (it would come
    /// back with the next download), then a file with its original name over a
    /// `<SHA256>.<ext>` copy this server wrote, then the oldest. Each removal is a
    /// "duplicate_removed" line in `dataset_moves.jsonl`. Same content under two labels
    /// is a conflict, not a duplicate: left alone (a human verdict settles it).
    fn remove_duplicates(&self, map: &mut HashMap<String, Vec<Entry>>) -> usize {
        let mut removed = 0;
        let mut log = std::fs::OpenOptions::new().create(true).append(true).open(self.moves_file()).ok();
        for (sha, entries) in map.iter_mut() {
            if entries.len() < 2 {
                continue;
            }
            for platform in Platform::ALL {
                for label in Label::ALL {
                    let mut same: Vec<usize> =
                        (0..entries.len()).filter(|&i| entries[i].platform == platform && entries[i].label == label).collect();
                    if same.len() < 2 {
                        continue;
                    }
                    same.sort_by_key(|&i| {
                        let e = &entries[i];
                        (e.source != Source::Public, e.ours, e.added, e.path.as_os_str().len())
                    });
                    let keep = entries[same[0]].path.clone();
                    let mut gone: Vec<usize> = Vec::new();
                    for &i in &same[1..] {
                        let dup = &entries[i].path;
                        let backup = match self.to_backup(platform, label, dup, sha) {
                            Ok(b) => b,
                            Err(err) => {
                                eprintln!("[dataset] could not move duplicate {} to the backup folder: {err}", dup.display());
                                continue;
                            }
                        };
                        if let Some(f) = log.as_mut() {
                            let line = serde_json::json!({
                                "time": chrono::Utc::now().to_rfc3339(),
                                "action": "duplicate_removed",
                                "sha256": sha,
                                "platform": platform,
                                "from_label": label,
                                "to_label": label,
                                "from": dup.display().to_string(),
                                "backup": backup.display().to_string(),
                                "duplicate_of": keep.display().to_string(),
                                "reason": "duplicate in dataset",
                            });
                            let _ = writeln!(f, "{line}");
                        }
                        gone.push(i);
                    }
                    removed += gone.len();
                    gone.sort_unstable_by(|a, b| b.cmp(a));
                    for i in gone {
                        entries.remove(i);
                    }
                }
            }
        }
        if removed > 0 {
            self.duplicates_removed.fetch_add(removed as u64, Ordering::Relaxed);
            self.indexed_files.fetch_sub(removed as u64, Ordering::Relaxed);
        }
        removed
    }

    /// Where a file goes for a human verdict: same platform and label, the folder with
    /// the same display name first, else the first own folder, else the first folder.
    fn human_target(&self, platform: Platform, label: Label, group: Option<&str>) -> Option<(PathBuf, Source, Option<Arc<str>>)> {
        let l = self.paths.list(platform, label);
        let folders: Vec<(&PathBuf, Source, Option<&String>)> = l
            .0
            .iter()
            .enumerate()
            .filter(|(_, (p, _))| !p.as_os_str().is_empty())
            .map(|(i, (p, s))| (p, *s, l.1.get(i).and_then(|n| n.as_ref())))
            .collect();
        let pick = group
            .and_then(|g| folders.iter().find(|f| f.2.is_some_and(|n| n == g)))
            .or_else(|| folders.iter().find(|f| f.1 == Source::Own))
            .or_else(|| folders.first())?;
        Some((pick.0.clone(), pick.1, pick.2.map(|n| Arc::from(n.as_str()))))
    }

    /// Backup folder for files taken out of a dataset folder (duplicates): next to the
    /// configured folder they were in, `deleted_from_<folder>_<pe|apk|js>` (e.g.
    /// `usbdosyalar\deleted_from_data2_pe`). Never read by the indexer or the training.
    fn backup_dir(&self, platform: Platform, label: Label, path: &Path) -> PathBuf {
        let root = self
            .paths
            .list(platform, label)
            .0
            .iter()
            .map(|(p, _)| p)
            .filter(|p| !p.as_os_str().is_empty() && is_inside(path, p))
            .max_by_key(|p| p.as_os_str().len())
            .cloned()
            .or_else(|| path.parent().map(Path::to_path_buf))
            .unwrap_or_default();
        let name = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dataset".into());
        let kind = match platform {
            Platform::Windows => "pe",
            Platform::Android => "apk",
            Platform::JavaScript => "js",
        };
        root.parent().unwrap_or(&root).join(format!("{BACKUP_PREFIX}{name}_{kind}"))
    }

    /// Moves a dataset file to its backup folder (nothing is deleted). Returns where.
    fn to_backup(&self, platform: Platform, label: Label, path: &Path, sha_upper: &str) -> Result<PathBuf, String> {
        let dir = self.backup_dir(platform, label, path);
        let name = path.file_name().ok_or("no file name")?;
        let target = free_name(&dir, Path::new(name)).ok_or("no free name in the backup folder")?;
        move_verified(path, &target, sha_upper)?;
        Ok(target)
    }

    /// `dataset_moves.jsonl`: files moved to follow a human verdict.
    pub fn moves_file(&self) -> PathBuf {
        self.state_dir.join("dataset_moves.jsonl")
    }

    /// Conflict lines about a hash a human verdict has settled.
    fn drop_conflicts_for(&self, sha: &str) {
        let path = self.conflicts_file();
        let Ok(text) = std::fs::read_to_string(&path) else { return };
        let kept: Vec<&str> = text
            .lines()
            .filter(|l| {
                !serde_json::from_str::<serde_json::Value>(l)
                    .is_ok_and(|v| v["sha256"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(sha)))
            })
            .collect();
        if kept.len() != text.lines().count() {
            let mut out = kept.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            let _ = std::fs::write(&path, out);
        }
    }

    /// Copies `data` into the folder for its platform and `label`, by content.
    pub fn export(&self, sha256: &str, data: &[u8], name: &str, label: Label) -> ExportOutcome {
        if data.is_empty() {
            return ExportOutcome::Skipped;
        }
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
        let group: Option<Arc<str>> = self.paths.name_of(platform, label, dir).map(Arc::from);
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
                entries.push(Entry { platform, label, path: target.clone(), ours: true, source: Source::Own, added: now_secs(), group: group.clone() });
                self.duplicates_skipped.fetch_add(1, Ordering::Relaxed);
                return ExportOutcome::AlreadyPresent(target);
            }
            return ExportOutcome::Skipped;
        }
        entries.push(Entry { platform, label, path: target.clone(), ours: true, source: Source::Own, added: now_secs(), group: group.clone() });
        drop(index);
        self.written.fetch_add(1, Ordering::Relaxed);
        self.indexed_files.fetch_add(1, Ordering::Relaxed);
        if let (Ok(meta), Ok(mut f)) = (
            std::fs::metadata(&target),
            std::fs::OpenOptions::new().create(true).append(true).open(self.cache_file()),
        ) {
            let mtime = unix_secs(meta.modified().ok());
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

fn platform_idx(p: Platform) -> usize {
    match p {
        Platform::Windows => 0,
        Platform::Android => 1,
        Platform::JavaScript => 2,
    }
}

fn label_idx(l: Label) -> usize {
    match l {
        Label::Malware => 0,
        Label::Clean => 1,
    }
}

fn unix_secs(t: Option<std::time::SystemTime>) -> u64 {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
}

fn now_secs() -> u64 {
    unix_secs(Some(std::time::SystemTime::now()))
}

/// `<SHA256>.<ext>` named after its own content: a copy this server wrote.
/// `dir/name`, or `dir/stem (2).ext`, `(3)`, ... when the name is taken (nothing is
/// ever overwritten).
fn free_name(dir: &Path, name: &Path) -> Option<PathBuf> {
    std::fs::create_dir_all(dir).ok()?;
    let first = dir.join(name);
    if !first.exists() {
        return Some(first);
    }
    let stem = name.file_stem()?.to_string_lossy().into_owned();
    let ext = name.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    (2..10_000).map(|n| dir.join(format!("{stem} ({n}){ext}"))).find(|p| !p.exists())
}

/// Moves `from` to `to` without losing it: a rename, or across drives a copy that is
/// checked (SHA-256) before the original is removed. If the original cannot be removed
/// both copies stay.
fn move_verified(from: &Path, to: &Path, sha_upper: &str) -> Result<(), String> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to).map_err(|e| e.to_string())?;
    match sha256_file(to) {
        Some(h) if h.eq_ignore_ascii_case(sha_upper) => {
            if let Err(e) = std::fs::remove_file(from) {
                eprintln!("[dataset] copied to {} but could not remove {}: {e}", to.display(), from.display());
            }
            Ok(())
        }
        _ => {
            let _ = std::fs::remove_file(to);
            Err("the copy does not match the original".into())
        }
    }
}

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
/// Files under `dir`. Folders whose name starts with `.` (`.cache`, `.git`, ...) and the
/// `skip` folders (configured folders nested in this one) are not entered.
fn walk_files(dir: &Path, skip: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                let n = e.file_name().to_string_lossy().to_ascii_lowercase();
                if n.starts_with('.') || n.starts_with(BACKUP_PREFIX) || skip.iter().any(|s| same_path(s, &p)) {
                    continue;
                }
                stack.push(p);
            } else if ft.is_file() && !p.extension().is_some_and(|x| x == "part") {
                out.push(p);
            }
        }
    }
    out
}

/// Path text for comparisons: `/` separators, no trailing one, lower case (Windows
/// paths are case-insensitive).
fn path_key(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/").trim_end_matches('/').to_lowercase()
}

fn same_path(a: &Path, b: &Path) -> bool {
    path_key(a) == path_key(b)
}

/// `child` is a folder strictly inside `parent`.
fn is_inside(child: &Path, parent: &Path) -> bool {
    let (c, p) = (path_key(child), path_key(parent));
    !p.is_empty() && c.len() > p.len() + 1 && c.starts_with(&p) && c.as_bytes()[p.len()] == b'/'
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

/// Platform of a sample by CONTENT only (the name is never used to decide): an APK
/// is a ZIP holding AndroidManifest.xml and classes*.dex, a PE has a valid PE header,
/// JavaScript is text the HydraDragonSig JS parser (OXC) accepts. A JS file submitted
/// as `.txt` or without an extension still reaches the JS dataset.
pub fn platform_of(data: &[u8], _name: &str) -> Option<Platform> {
    if data.starts_with(b"PK\x03\x04") {
        let head = &data[..data.len().min(8 * 1024 * 1024)];
        if contains(head, b"AndroidManifest.xml") && contains(head, b"classes") {
            return Some(Platform::Android);
        }
        return None;
    }
    if is_pe(data) {
        return Some(Platform::Windows);
    }
    if !data.is_empty() && !data[..data.len().min(4096)].contains(&0) && hydradragonsig::scanner::filetype::is_javascript(data) {
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
            windows_malware: FolderList::own(root.join("mal")),
            windows_clean: FolderList::own(root.join("clean")),
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
        assert_eq!(platform_of(b"var a = 1;", "a.txt"), Some(Platform::JavaScript), "content, not the name");
        assert_eq!(platform_of(b"just some words here", "a.js"), None);
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

    #[test]
    fn old_config_format_is_own() {
        let p: DatasetPaths =
            serde_json::from_str(r#"{ "windows_malware": "C:\\data\\mal", "android_clean": null }"#).unwrap();
        assert_eq!(p.windows_malware, FolderList::own("C:\\data\\mal"));
        assert_eq!(p.android_clean, FolderList::default());
        assert_eq!(p.dir(Platform::Windows, Label::Malware), Some(Path::new("C:\\data\\mal")));
        assert_eq!(p.folders(), vec![(Platform::Windows, Label::Malware, Source::Own, PathBuf::from("C:\\data\\mal"))]);
        assert!(p.any());
    }

    #[test]
    fn new_config_format_sources_and_several_folders() {
        let p: DatasetPaths = serde_json::from_str(
            r#"{
                "windows_malware": [
                    { "path": "pub1", "source": "public" },
                    "own1",
                    { "path": "own2" },
                    { "path": "pub2", "source": "public" },
                    "own1"
                ],
                "windows_clean": { "path": "c", "source": "own" },
                "javascript_clean": [{ "path": "jp", "source": "public" }]
            }"#,
        )
        .unwrap();
        let mal: Vec<_> = p.folders().into_iter().filter(|f| f.1 == Label::Malware).map(|f| (f.2, f.3)).collect();
        assert_eq!(
            mal,
            vec![
                (Source::Public, PathBuf::from("pub1")),
                (Source::Own, PathBuf::from("own1")),
                (Source::Own, PathBuf::from("own2")),
                (Source::Public, PathBuf::from("pub2")),
            ],
            "a folder listed twice is walked once"
        );
        // Copies go to the first own folder, never to a public one.
        assert_eq!(p.dir(Platform::Windows, Label::Malware), Some(Path::new("own1")));
        assert_eq!(p.dir(Platform::Windows, Label::Clean), Some(Path::new("c")));
        assert_eq!(p.dir(Platform::JavaScript, Label::Clean), None);
        assert!(serde_json::from_str::<DatasetPaths>(r#"{ "windows_malware": { "path": "x", "source": "mine" } }"#).is_err());
    }

    /// own + public folders for windows malware / clean and an own android folder.
    fn setup_sources(name: &str) -> (PathBuf, Dataset) {
        let root = std::env::temp_dir().join(format!("multron_dataset_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["mal_own", "mal_pub", "mal_pub2", "clean_own", "clean_pub", "apk_own", "state"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let paths = DatasetPaths {
            windows_malware: FolderList(
                vec![
                    (root.join("mal_pub"), Source::Public),
                    (root.join("mal_own"), Source::Own),
                    (root.join("mal_pub2"), Source::Public),
                ],
                vec![None; 3],
            ),
            windows_clean: FolderList(vec![(root.join("clean_own"), Source::Own), (root.join("clean_pub"), Source::Public)], vec![None; 2]),
            android_malware: FolderList::own(root.join("apk_own")),
            ..Default::default()
        };
        let ds = Dataset::new(paths, root.join("state"));
        (root, ds)
    }

    fn counts(st: &PublicStats, platform: &str, label: &str) -> (u64, u64, u64, u64) {
        let c = &st.cells[platform][label];
        (c.counts.own_only, c.counts.public_only, c.counts.both, c.total)
    }

    #[test]
    fn stats_count_every_hash_once() {
        let (root, ds) = setup_sources("stats");
        ds.remove_dups.store(false, Ordering::Relaxed); // counts copies on purpose
        let (a, b, c, d) = (pe(10), pe(11), pe(12), pe(13));
        // a: own + public malware (and twice in own, under two names) -> both.
        std::fs::write(root.join("mal_own").join("a1.exe"), &a).unwrap();
        std::fs::write(root.join("mal_own").join("a2.bin"), &a).unwrap();
        std::fs::write(root.join("mal_pub").join("a.exe"), &a).unwrap();
        // b: two public malware folders -> public only.
        std::fs::write(root.join("mal_pub").join("b.exe"), &b).unwrap();
        std::fs::write(root.join("mal_pub2").join("b.exe"), &b).unwrap();
        // c: own clean, public malware -> per label one side, all labels both.
        std::fs::write(root.join("clean_own").join("c.exe"), &c).unwrap();
        std::fs::write(root.join("mal_pub").join("c.exe"), &c).unwrap();
        // d: android own.
        std::fs::write(root.join("apk_own").join("d.apk"), &d).unwrap();
        assert!(ds.public_stats(&[]).is_none(), "nothing before the index");
        ds.build_index();
        let st = ds.public_stats(&[]).unwrap();
        assert_eq!(counts(&st, "windows", "malware"), (0, 2, 1, 3));
        assert_eq!(counts(&st, "windows", "clean"), (1, 0, 0, 1));
        assert_eq!(counts(&st, "windows", "all"), (0, 1, 2, 3));
        assert_eq!(counts(&st, "android", "malware"), (1, 0, 0, 1));
        assert_eq!(counts(&st, "android", "clean"), (0, 0, 0, 0));
        assert_eq!(counts(&st, "javascript", "all"), (0, 0, 0, 0));
        assert_eq!(counts(&st, "all", "malware"), (1, 2, 1, 4));
        assert_eq!(counts(&st, "all", "clean"), (1, 0, 0, 1));
        assert_eq!(counts(&st, "all", "all"), (1, 1, 2, 4));
        assert_eq!(st.cells.len(), 4);
        assert!(st.cells.values().all(|m| m.len() == 3));

        // A copy written by the server is "own": e becomes own only.
        let e = pe(14);
        let ExportOutcome::Written(path) = ds.export(&sha(&e), &e, "e.exe", Label::Malware) else { panic!() };
        assert!(path.starts_with(root.join("mal_own")), "written to the own folder, not a public one");
        assert_eq!(counts(&ds.public_stats(&[]).unwrap(), "windows", "malware"), (1, 2, 1, 4));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stats_daily_last_30_days() {
        let (root, ds) = setup_sources("daily");
        ds.remove_dups.store(false, Ordering::Relaxed); // counts copies on purpose
        std::fs::write(root.join("mal_own").join("a.exe"), pe(20)).unwrap();
        std::fs::write(root.join("mal_pub").join("a.exe"), pe(20)).unwrap();
        std::fs::write(root.join("clean_pub").join("b.exe"), pe(21)).unwrap();
        ds.build_index();
        let now = now_secs();
        let st = ds.public_stats_at(now, &[]);
        let cell = &st.cells["all"]["all"];
        assert_eq!(st.days, STATS_DAYS);
        assert_eq!(cell.daily.len(), STATS_DAYS);
        let today = chrono::DateTime::from_timestamp(now as i64, 0).unwrap().format("%Y-%m-%d").to_string();
        let last = cell.daily.last().unwrap();
        assert_eq!(last.date, today, "newest day last");
        assert_eq!((last.counts.own_only, last.counts.public_only, last.counts.both), (0, 1, 1));
        assert!(cell.daily[..STATS_DAYS - 1].iter().all(|d| d.counts.total() == 0));
        assert!(cell.daily.windows(2).all(|w| w[0].date < w[1].date));
        // 40 days later: the totals stay, the files are out of the window.
        let later = ds.public_stats_at(now + 40 * 86_400, &[]);
        assert_eq!(later.cells["all"]["all"].total, 2);
        assert!(later.cells["all"]["all"].daily.iter().all(|d| d.counts.total() == 0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stats_json_has_no_paths_names_or_hashes() {
        let (root, ds) = setup_sources("leak");
        let a = pe(30);
        std::fs::write(root.join("mal_own").join("secret_name.exe"), &a).unwrap();
        std::fs::write(root.join("clean_pub").join("other_secret.exe"), pe(31)).unwrap();
        ds.build_index();
        let json = serde_json::to_string(&ds.public_stats(&[]).unwrap()).unwrap();
        let root_s = root.to_string_lossy();
        assert!(!json.contains(root_s.as_ref()));
        for needle in ["secret_name", "other_secret", "mal_own", "clean_pub", "multron_dataset", ".exe"] {
            assert!(!json.contains(needle), "{needle} leaked");
        }
        assert!(!json.contains(&sha(&a)) && !json.contains(&sha(&a).to_ascii_lowercase()));
        // Only counts, dates and the fixed keys.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let cell = &v["cells"]["windows"]["malware"];
        let mut keys: Vec<&str> = cell.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["both", "daily", "own_only", "public_only", "total", "users_only"]);
        let mut day_keys: Vec<&str> = cell["daily"][0].as_object().unwrap().keys().map(String::as_str).collect();
        day_keys.sort();
        assert_eq!(day_keys, ["both", "date", "own_only", "public_only", "users_only"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_folder_keeps_its_own_source_and_name_and_dot_folders_are_skipped() {
        let root = std::env::temp_dir().join(format!("multron_dataset_nested_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let benign = root.join("dataset").join("benign");
        let fdroid = benign.join("F-Droid");
        for d in [benign.join("Play"), fdroid.join("repo"), fdroid.join(".cache"), benign.join(".git"), root.join("state")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let json = serde_json::json!({
            "android_clean": [
                { "path": benign, "source": "own", "name": "Own benign" },
                { "path": fdroid, "source": "public", "name": "F-Droid" }
            ]
        });
        let paths: DatasetPaths = serde_json::from_value(json).unwrap();
        assert_eq!(paths.name_of(Platform::Android, Label::Clean, &fdroid).as_deref(), Some("F-Droid"));
        assert_eq!(paths.nested_in(Platform::Android, Label::Clean, &benign), vec![fdroid.clone()]);
        assert!(paths.nested_in(Platform::Android, Label::Clean, &fdroid).is_empty());
        std::fs::write(benign.join("Play").join("a.apk"), pe(40)).unwrap();
        std::fs::write(fdroid.join("repo").join("b.apk"), pe(41)).unwrap();
        // Same content in both: own and public -> "both", counted once per group.
        std::fs::write(benign.join("Play").join("c.apk"), pe(42)).unwrap();
        std::fs::write(fdroid.join("repo").join("c.apk"), pe(42)).unwrap();
        // Hidden folders are never read.
        std::fs::write(fdroid.join(".cache").join("x.apk"), pe(43)).unwrap();
        std::fs::write(benign.join(".git").join("y.apk"), pe(44)).unwrap();
        let ds = Dataset::new(paths, root.join("state"));
        ds.remove_dups.store(false, Ordering::Relaxed); // counts copies on purpose
        ds.build_index();
        let st = ds.public_stats(&[]).unwrap();
        assert_eq!(counts(&st, "android", "clean"), (1, 1, 1, 3), "F-Droid files are public, not 'both'");
        assert_eq!(ds.status().indexed_files, 4, "each file indexed once; .cache / .git skipped");
        let g = |name: &str| st.groups[name]["android"]["clean"].total;
        assert_eq!((g("Own benign"), g("F-Droid")), (2, 2));
        assert_eq!(st.groups["F-Droid"]["all"]["all"].total, 2);
        assert_eq!(st.groups["F-Droid"]["android"]["clean"].daily.len(), STATS_DAYS);
        assert!(!st.groups["F-Droid"].contains_key("windows"), "empty filters are left out");
        let json = serde_json::to_string(&st).unwrap();
        assert!(!json.contains("dataset") && !json.contains("repo"), "names only, never paths");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn files_from_users_join_the_totals_once() {
        let (root, ds) = setup_sources("users");
        let (a, b) = (pe(30), pe(31));
        std::fs::write(root.join("mal_own").join("a.exe"), &a).unwrap();
        ds.build_index();
        let now = now_secs();
        let first_seen = chrono::DateTime::from_timestamp(now as i64, 0).unwrap().to_rfc3339();
        let users = vec![
            // Already in the own malware folder: not counted again.
            UserFile::new(&sha(&a), "malicious", &["a.exe".into()], &first_seen),
            UserFile::new(&sha(&b).to_ascii_lowercase(), "malicious", &["b.dll".into()], &first_seen),
            UserFile::new(&sha(&b), "malicious", &["b.dll".into()], &first_seen),
            UserFile::new(&"C".repeat(64), "unknown", &["photo.jpg".into()], &first_seen),
            UserFile::new(&"D".repeat(64), "clean", &["app.apk".into()], "not a date"),
        ];
        let st = ds.public_stats_at(now, &users);
        let c = |p: &str, l: &str| (st.cells[p][l].counts.own_only, st.cells[p][l].counts.users_only, st.cells[p][l].total);
        assert_eq!(c("windows", "malware"), (1, 1, 2), "a once (own), b once (users)");
        assert_eq!(c("all", "all"), (1, 3, 4), "unknown and unnamed platforms count under all");
        assert_eq!(c("android", "clean"), (0, 1, 1));
        assert_eq!(c("android", "malware"), (0, 0, 0));
        assert_eq!(st.cells["all"]["all"].daily.last().unwrap().counts.users_only, 2, "today; the bad date is not");
        assert_eq!(st.groups[USERS_GROUP]["all"]["all"].total, 4, "the users group has every hash they sent");
        assert_eq!(st.groups[USERS_GROUP]["windows"]["malware"].total, 2);
        assert_eq!(platform_of_name("Setup.EXE"), Some(Platform::Windows));
        assert_eq!(platform_of_name("readme"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_files_are_not_samples_or_conflicts() {
        let (root, ds) = setup_sources("empty");
        std::fs::write(root.join("mal_own").join("x.vir"), b"").unwrap();
        std::fs::write(root.join("clean_own").join("y.efi"), b"").unwrap();
        std::fs::write(root.join("state").join("dataset_conflicts.jsonl"), format!(
            "{{\"kind\":\"existing\",\"sha256\":\"{EMPTY_SHA256}\"}}\n{{\"kind\":\"label\",\"sha256\":\"AB\"}}\n"
        )).unwrap();
        ds.build_index();
        assert_eq!(ds.status().indexed_files, 0);
        assert_eq!(ds.status().conflicts, 0, "two empty files under both labels are no conflict");
        let left = ds.recent_conflicts(10);
        assert_eq!(left.len(), 1, "old empty-file line pruned, export conflict kept");
        assert_eq!(left[0]["sha256"], "AB");
        assert_eq!(ds.export(EMPTY_SHA256, b"", "e.exe", Label::Malware), ExportOutcome::Skipped);
        let users = [UserFile::new(&EMPTY_SHA256.to_ascii_lowercase(), "unknown", &[], "")];
        assert_eq!(ds.public_stats(&users).unwrap().cells["all"]["all"].total, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn human_verdict_moves_the_file_to_its_label_without_loss() {
        let (root, ds) = setup_sources("human");
        ds.remove_dups.store(false, Ordering::Relaxed); // counts copies on purpose
        let a = pe(40);
        // Same content: two files in the public malware folders, one name already
        // taken in the own clean folder (different content).
        std::fs::write(root.join("mal_pub").join("x.exe"), &a).unwrap();
        std::fs::write(root.join("mal_pub2").join("y.exe"), &a).unwrap();
        std::fs::write(root.join("clean_own").join("x.exe"), pe(41)).unwrap();
        std::fs::write(root.join("state").join("dataset_conflicts.jsonl"), format!("{{\"kind\":\"label\",\"sha256\":\"{}\"}}\n", sha(&a))).unwrap();
        // Before the index: queued, applied when it is ready.
        assert_eq!(ds.apply_human_verdicts(&[(sha(&a).to_ascii_lowercase(), "clean".into())]), 0);
        ds.build_index();
        assert!(!root.join("mal_pub").join("x.exe").exists() && !root.join("mal_pub2").join("y.exe").exists());
        assert_eq!(std::fs::read(root.join("clean_own").join("x (2).exe")).unwrap(), a, "name taken: suffixed, not overwritten");
        assert!(!root.join("clean_own").join("y.exe").exists(), "second copy: a duplicate, removed");
        assert_eq!(std::fs::read(root.join("clean_own").join("x.exe")).unwrap(), pe(41));
        let clean_files = std::fs::read_dir(root.join("clean_own")).unwrap().count();
        assert_eq!(clean_files, 2, "exactly one file per content");
        assert_eq!(ds.status().moved_by_human, 2);
        assert!(ds.recent_conflicts(10).is_empty(), "settled conflict removed");
        let moves = std::fs::read_to_string(ds.moves_file()).unwrap();
        assert_eq!(moves.lines().count(), 2);
        assert!(moves.contains("\"action\":\"moved\"") && moves.contains("\"action\":\"duplicate_removed\"") && moves.contains("duplicate_of"));
        let st = ds.public_stats(&[]).unwrap();
        assert_eq!(st.cells["windows"]["malware"].total, 0);
        assert_eq!(st.cells["windows"]["clean"].counts.own_only, 2, "x.exe (41) and the moved content");
        // Again, or "suspicious": nothing to do.
        assert_eq!(ds.apply_human_verdict(&sha(&a), Label::Clean), 0);
        assert_eq!(ds.apply_human_verdicts(&[(sha(&a), "suspicious".into())]), 0);
        // Flipped back to malware: the one file moves to the own malware folder.
        assert_eq!(ds.apply_human_verdict(&sha(&a), Label::Malware), 1);
        assert_eq!(std::fs::read(root.join("mal_own").join("x (2).exe")).unwrap(), a);
        // Content already under the verdict's label: the other copy is removed, not moved.
        let (root2, ds2) = setup_sources("human2");
        std::fs::write(root2.join("mal_own").join("m.exe"), &a).unwrap();
        std::fs::write(root2.join("clean_own").join("c.exe"), &a).unwrap();
        ds2.build_index();
        assert_eq!(ds2.apply_human_verdict(&sha(&a), Label::Clean), 1);
        assert!(!root2.join("mal_own").join("m.exe").exists());
        assert_eq!(std::fs::read(root2.join("clean_own").join("c.exe")).unwrap(), a, "the existing copy stays");
        assert_eq!(std::fs::read_dir(root2.join("clean_own")).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&root2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn copies_of_the_same_content_are_removed_once_indexed() {
        let (root, ds) = setup_sources("dups");
        let (a, b, c) = (pe(50), pe(51), pe(52));
        // a: twice in own (original names), once public -> the public one stays.
        std::fs::write(root.join("mal_own").join("Trojan.A.vir"), &a).unwrap();
        std::fs::write(root.join("mal_own").join("Bazaar.A.vir"), &a).unwrap();
        std::fs::write(root.join("mal_pub").join("a.exe"), &a).unwrap();
        // b: an original name and a <SHA>.exe copy the server wrote -> the original stays.
        std::fs::write(root.join("mal_own").join("original.exe"), &b).unwrap();
        std::fs::write(root.join("mal_own").join(format!("{}.exe", sha(&b))), &b).unwrap();
        // c: under both labels -> a conflict, nothing removed.
        std::fs::write(root.join("mal_own").join("c.exe"), &c).unwrap();
        std::fs::write(root.join("clean_own").join("c.exe"), &c).unwrap();
        ds.build_index();
        assert!(root.join("mal_pub").join("a.exe").exists());
        assert!(!root.join("mal_own").join("Trojan.A.vir").exists() && !root.join("mal_own").join("Bazaar.A.vir").exists());
        assert!(root.join("mal_own").join("original.exe").exists());
        assert!(!root.join("mal_own").join(format!("{}.exe", sha(&b))).exists());
        assert!(root.join("mal_own").join("c.exe").exists() && root.join("clean_own").join("c.exe").exists());
        assert_eq!(ds.status().duplicates_removed, 3);
        assert_eq!(ds.status().indexed_files, 4);
        let log = std::fs::read_to_string(ds.moves_file()).unwrap();
        assert_eq!(log.lines().filter(|l| l.contains("\"action\":\"duplicate_removed\"")).count(), 3);
        assert!(log.contains("Trojan.A.vir") && log.contains("duplicate_of"));
        assert_eq!(counts(&ds.public_stats(&[]).unwrap(), "windows", "malware"), (2, 1, 0, 3));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn path_nesting_is_case_and_separator_insensitive() {
        assert!(is_inside(Path::new("C:\\Data\\Benign\\F-Droid"), Path::new("c:/data/benign/")));
        assert!(!is_inside(Path::new("C:\\Data\\Benign2"), Path::new("C:\\Data\\Benign")));
        assert!(!is_inside(Path::new("C:\\Data\\Benign"), Path::new("C:\\Data\\Benign")));
        assert!(same_path(Path::new("C:\\Data\\x\\"), Path::new("c:/data/X")));
    }
}
