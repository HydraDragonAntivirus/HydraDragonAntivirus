//! String whitelist for VirusKovAlyzer, like yarGen's goodware string databases: every
//! string (ASCII and UTF-16LE, at least `MIN_LEN` characters) of every kept file with a
//! human "clean" verdict. The Strings page can hide them and show only the unknown ones.
//!
//! The list follows the human verdicts on its own (checked every minute): new clean
//! files are added, and when a clean verdict is taken back the list is built again
//! without that file. Nothing is written into the ML datasets or the rule folders.
//!
//! Stored in `string_whitelist/` next to the server, so RAM stays small however big it
//! grows (one 64-bit key per string, first 8 bytes of the SHA-256 of its text):
//! - `strings-<generation>.u64`: sorted unique keys, little endian, read from disk;
//! - `strings-<generation>.idx`: first key of every `BLOCK` keys, held in memory;
//! - `whitelist.json`: generation, `MIN_LEN` and the SHA-256 of the files in it.
//!
//! Up to `pending_max` keys of newly added files stay in memory and are merged into a
//! new generation later; after a restart those files are simply read again.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Shortest string in the list (yarGen's minimum); shorter ones are never "known".
pub const MIN_LEN: usize = 6;
/// Keys per index entry (one disk read per lookup of a key in that block).
const BLOCK: usize = 1024;
/// Keys sorted in memory before a run goes to disk while building.
const RUN_KEYS: usize = 8 << 20;
/// New keys held in memory before they are merged into a new generation.
const PENDING_MAX: usize = 2 << 20;
/// At most this many new files are read straight into memory; more make a merge.
const DIRECT_FILES: usize = 200;
const CHECK_EVERY: Duration = Duration::from_secs(60);
/// Files larger than this are not read (the VirusKovAlyzer limit).
const MAX_FILE: usize = crate::alyzer::MAX_OPEN_BYTES as usize;

/// Key of a string's text (the same for its ASCII and UTF-16LE form).
pub fn key(s: &str) -> u64 {
    let d = Sha256::digest(s.as_bytes());
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

/// Sorted unique keys of every string of `data` the list holds.
fn file_keys(data: &[u8]) -> Vec<u64> {
    let mut v = Vec::new();
    crate::alyzer::each_string(data, MIN_LEN, |_, _, s| {
        v.push(key(s));
        true
    });
    v.sort_unstable();
    v.dedup();
    v
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    generation: u64,
    min_len: usize,
    keys: u64,
    files: Vec<String>,
}

/// One generation on disk.
struct Disk {
    generation: u64,
    file: Mutex<File>,
    len: u64,
    index: Vec<u64>,
}

impl Disk {
    fn open(dir: &Path, generation: u64, keys: u64) -> io::Result<Disk> {
        let file = File::open(dir.join(format!("strings-{generation}.u64")))?;
        let len = file.metadata()?.len() / 8;
        let mut raw = Vec::new();
        File::open(dir.join(format!("strings-{generation}.idx")))?.read_to_end(&mut raw)?;
        let index: Vec<u64> = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        if len != keys || index.len() as u64 != len.div_ceil(BLOCK as u64) {
            return Err(io::Error::other("string whitelist files do not match"));
        }
        Ok(Disk { generation, file: Mutex::new(file), len, index })
    }

    /// Which of the sorted `keys` are in this generation.
    fn contains_sorted(&self, keys: &[u64], out: &mut [bool]) -> io::Result<()> {
        let mut f = self.file.lock().unwrap();
        let mut cached: Option<(usize, Vec<u64>)> = None;
        for (k, hit) in keys.iter().zip(out.iter_mut()) {
            let b = self.index.partition_point(|&first| first <= *k);
            if b == 0 {
                continue;
            }
            let b = b - 1;
            if cached.as_ref().map(|(cb, _)| *cb) != Some(b) {
                let start = (b * BLOCK) as u64;
                let n = (self.len - start).min(BLOCK as u64) as usize;
                let mut buf = vec![0u8; n * 8];
                f.seek(SeekFrom::Start(start * 8))?;
                f.read_exact(&mut buf)?;
                cached = Some((b, buf.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()));
            }
            *hit = cached.as_ref().unwrap().1.binary_search(k).is_ok();
        }
        Ok(())
    }
}

/// Sorted keys from a file of little-endian u64 (a run or a generation).
struct KeyReader(BufReader<File>);

impl Iterator for KeyReader {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        let mut b = [0u8; 8];
        self.0.read_exact(&mut b).ok().map(|_| u64::from_le_bytes(b))
    }
}

#[derive(Default)]
struct Files {
    /// In the current generation on disk.
    merged: HashSet<String>,
    /// Read into `pending` (memory only).
    pending: HashSet<String>,
    /// Kept file not found or not readable: tried again at the next full build.
    missing: HashSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub ready: bool,
    pub files: usize,
    pub strings: u64,
    pub min_len: usize,
    pub building: bool,
    pub build_done: u64,
    pub build_total: u64,
}

pub struct StringWhitelist {
    dir: PathBuf,
    disk: RwLock<Option<Arc<Disk>>>,
    /// Sorted unique keys not on disk yet.
    pending: RwLock<Vec<u64>>,
    files: Mutex<Files>,
    loaded: AtomicBool,
    building: AtomicBool,
    build_done: AtomicU64,
    build_total: AtomicU64,
    run_keys: usize,
    pending_max: usize,
}

impl StringWhitelist {
    pub fn new(dir: PathBuf) -> Self {
        StringWhitelist {
            dir,
            disk: RwLock::new(None),
            pending: RwLock::new(Vec::new()),
            files: Mutex::new(Files::default()),
            loaded: AtomicBool::new(false),
            building: AtomicBool::new(false),
            build_done: AtomicU64::new(0),
            build_total: AtomicU64::new(0),
            run_keys: RUN_KEYS,
            pending_max: PENDING_MAX,
        }
    }

    pub fn status(&self) -> Status {
        let f = self.files.lock().unwrap();
        let disk = self.disk.read().unwrap().as_ref().map_or(0, |d| d.len);
        Status {
            ready: self.loaded.load(Ordering::Relaxed),
            files: f.merged.len() + f.pending.len(),
            strings: disk + self.pending.read().unwrap().len() as u64,
            min_len: MIN_LEN,
            building: self.building.load(Ordering::Relaxed),
            build_done: self.build_done.load(Ordering::Relaxed),
            build_total: self.build_total.load(Ordering::Relaxed),
        }
    }

    /// For each string: in the list? Strings shorter than `MIN_LEN` are never.
    pub fn contains_many(&self, strings: &[&str]) -> Vec<bool> {
        let mut out = vec![false; strings.len()];
        let mut keys: Vec<(u64, usize)> =
            strings.iter().enumerate().filter(|(_, s)| s.len() >= MIN_LEN).map(|(i, s)| (key(s), i)).collect();
        if keys.is_empty() {
            return out;
        }
        keys.sort_unstable();
        {
            let p = self.pending.read().unwrap();
            for (k, i) in &keys {
                out[*i] = p.binary_search(k).is_ok();
            }
        }
        let disk = self.disk.read().unwrap().clone();
        if let Some(d) = disk {
            let ks: Vec<u64> = keys.iter().map(|(k, _)| *k).collect();
            let mut hit = vec![false; ks.len()];
            if let Err(e) = d.contains_sorted(&ks, &mut hit) {
                eprintln!("[string-wl] lookup: {e}");
            }
            for ((_, i), h) in keys.iter().zip(hit) {
                out[*i] |= h;
            }
        }
        out
    }

    /// Loads the last generation; leftovers of an interrupted build are removed.
    fn load(&self) {
        let _ = std::fs::create_dir_all(&self.dir);
        let man: Option<Manifest> = std::fs::read(self.dir.join("whitelist.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
        if let Some(m) = man.filter(|m| m.min_len == MIN_LEN) {
            match Disk::open(&self.dir, m.generation, m.keys) {
                Ok(d) => {
                    *self.disk.write().unwrap() = Some(Arc::new(d));
                    self.files.lock().unwrap().merged = m.files.into_iter().collect();
                }
                Err(e) => eprintln!("[string-wl] {e}: building it again"),
            }
        }
        self.remove_old_files();
        self.loaded.store(true, Ordering::Relaxed);
    }

    /// Everything in the folder but the current generation and its manifest (a file
    /// still open for a lookup stays until the next time).
    fn remove_old_files(&self) {
        let cur = self.disk.read().unwrap().as_ref().map(|d| d.generation);
        let keep: Vec<String> = cur.map(|g| vec![format!("strings-{g}.u64"), format!("strings-{g}.idx")]).unwrap_or_default();
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name != "whitelist.json" && !keep.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Brings the list in line with the clean files `desired` (upper-case SHA-256).
    pub fn sync(&self, desired: &HashSet<String>, read: &dyn Fn(&str) -> Option<Vec<u8>>) {
        if !self.loaded.load(Ordering::Relaxed) {
            self.load();
        }
        let (stale, todo) = {
            let f = self.files.lock().unwrap();
            let stale = f.merged.iter().chain(f.pending.iter()).any(|s| !desired.contains(s));
            let todo: Vec<String> = desired
                .iter()
                .filter(|s| !f.merged.contains(*s) && !f.pending.contains(*s) && !f.missing.contains(*s))
                .cloned()
                .collect();
            (stale, todo)
        };
        let result = if stale {
            eprintln!("[string-wl] a clean verdict was taken back: building the string whitelist again");
            let mut all: Vec<String> = desired.iter().cloned().collect();
            all.sort();
            self.files.lock().unwrap().missing.clear();
            self.build(false, all, read)
        } else if todo.is_empty() {
            if self.pending.read().unwrap().len() > self.pending_max { self.build(true, Vec::new(), read) } else { Ok(()) }
        } else if todo.len() <= DIRECT_FILES {
            self.add_pending(&todo, read);
            if self.pending.read().unwrap().len() > self.pending_max { self.build(true, Vec::new(), read) } else { Ok(()) }
        } else {
            let mut todo = todo;
            todo.sort();
            self.build(true, todo, read)
        };
        if let Err(e) = result {
            eprintln!("[string-wl] build failed: {e}");
        }
    }

    fn add_pending(&self, shas: &[String], read: &dyn Fn(&str) -> Option<Vec<u8>>) {
        let mut add = Vec::new();
        let (mut ok, mut missing) = (Vec::new(), Vec::new());
        for sha in shas {
            match read(sha).filter(|d| d.len() <= MAX_FILE) {
                Some(data) => {
                    add.extend(file_keys(&data));
                    ok.push(sha.clone());
                }
                None => missing.push(sha.clone()),
            }
        }
        {
            let mut p = self.pending.write().unwrap();
            p.extend(add);
            p.sort_unstable();
            p.dedup();
        }
        let mut f = self.files.lock().unwrap();
        f.pending.extend(ok);
        f.missing.extend(missing);
    }

    /// A new generation: (the current one and the keys in memory, if `keep`) plus
    /// every string of `shas`. Lookups use the old generation until it is done.
    fn build(&self, keep: bool, shas: Vec<String>, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> io::Result<()> {
        self.remove_old_files();
        self.building.store(true, Ordering::Relaxed);
        self.build_done.store(0, Ordering::Relaxed);
        self.build_total.store(shas.len() as u64, Ordering::Relaxed);
        let r = self.build_inner(keep, shas, read);
        self.building.store(false, Ordering::Relaxed);
        r
    }

    fn build_inner(&self, keep: bool, shas: Vec<String>, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> io::Result<()> {
        let started = std::time::Instant::now();
        let old = self.disk.read().unwrap().clone();
        let generation = old.as_ref().map_or(0, |d| d.generation) + 1;
        let mut runs: Vec<PathBuf> = Vec::new();
        let mut buf: Vec<u64> = Vec::new();
        let (mut ok, mut missing) = (Vec::new(), Vec::new());
        let spill = |buf: &mut Vec<u64>, runs: &mut Vec<PathBuf>| -> io::Result<()> {
            buf.sort_unstable();
            buf.dedup();
            let p = self.dir.join(format!("build-{generation}-{}.run", runs.len()));
            let mut w = BufWriter::new(File::create(&p)?);
            for k in buf.iter() {
                w.write_all(&k.to_le_bytes())?;
            }
            w.flush()?;
            runs.push(p);
            buf.clear();
            Ok(())
        };
        for sha in &shas {
            match read(sha).filter(|d| d.len() <= MAX_FILE) {
                Some(data) => {
                    buf.extend(file_keys(&data));
                    ok.push(sha.clone());
                }
                None => missing.push(sha.clone()),
            }
            self.build_done.fetch_add(1, Ordering::Relaxed);
            if buf.len() >= self.run_keys {
                spill(&mut buf, &mut runs)?;
            }
        }
        buf.sort_unstable();
        buf.dedup();
        // The keys added to memory meanwhile go in too (one writer: this thread).
        let pending: Vec<u64> = if keep { self.pending.read().unwrap().clone() } else { Vec::new() };

        let mut inputs: Vec<Box<dyn Iterator<Item = u64>>> = vec![Box::new(buf.into_iter()), Box::new(pending.into_iter())];
        for p in &runs {
            inputs.push(Box::new(KeyReader(BufReader::new(File::open(p)?))));
        }
        if let (true, Some(d)) = (keep, old.as_ref()) {
            inputs.push(Box::new(KeyReader(BufReader::new(File::open(self.dir.join(format!("strings-{}.u64", d.generation)))?))));
        }
        let keys = merge_to(&self.dir, generation, inputs)?;
        for p in &runs {
            let _ = std::fs::remove_file(p);
        }

        let mut f = self.files.lock().unwrap();
        let mut files: HashSet<String> = if keep { f.merged.iter().chain(f.pending.iter()).cloned().collect() } else { HashSet::new() };
        files.extend(ok);
        let mut list: Vec<String> = files.iter().cloned().collect();
        list.sort();
        let man = Manifest { generation, min_len: MIN_LEN, keys, files: list };
        let tmp = self.dir.join("whitelist.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&man).map_err(io::Error::other)?)?;
        std::fs::rename(&tmp, self.dir.join("whitelist.json"))?;
        let disk = Disk::open(&self.dir, generation, keys)?;
        *self.disk.write().unwrap() = Some(Arc::new(disk));
        self.pending.write().unwrap().clear();
        f.merged = files;
        f.pending.clear();
        f.missing.extend(missing);
        let n = f.merged.len();
        drop(f);
        drop(old);
        self.remove_old_files();
        eprintln!("[string-wl] string whitelist: {keys} strings of {n} clean files ({} s)", started.elapsed().as_secs());
        Ok(())
    }
}

/// k-way merge of sorted inputs into `strings-<generation>.u64` (duplicates dropped) and its
/// index. Returns the number of keys.
fn merge_to(dir: &Path, generation: u64, mut inputs: Vec<Box<dyn Iterator<Item = u64>>>) -> io::Result<u64> {
    let mut data = BufWriter::new(File::create(dir.join(format!("strings-{generation}.u64")))?);
    let mut idx = BufWriter::new(File::create(dir.join(format!("strings-{generation}.idx")))?);
    let mut heap = BinaryHeap::new();
    for (i, it) in inputs.iter_mut().enumerate() {
        if let Some(k) = it.next() {
            heap.push(Reverse((k, i)));
        }
    }
    let (mut n, mut last) = (0u64, None);
    while let Some(Reverse((k, i))) = heap.pop() {
        if last != Some(k) {
            if n % BLOCK as u64 == 0 {
                idx.write_all(&k.to_le_bytes())?;
            }
            data.write_all(&k.to_le_bytes())?;
            n += 1;
            last = Some(k);
        }
        if let Some(next) = inputs[i].next() {
            heap.push(Reverse((next, i)));
        }
    }
    data.flush()?;
    idx.flush()?;
    Ok(n)
}

static GLOBAL: OnceLock<Arc<StringWhitelist>> = OnceLock::new();

pub fn get() -> Option<&'static Arc<StringWhitelist>> {
    GLOBAL.get()
}

/// Starts keeping `string_whitelist/` in line with the human clean verdicts (main
/// server only; the archive server has no kept files to read).
pub fn start(engine: Arc<crate::engine_adapter::EngineAdapter>, ti: Arc<crate::threat_intel::ThreatIntelStore>) {
    let wl = Arc::clone(GLOBAL.get_or_init(|| Arc::new(StringWhitelist::new(crate::config::app_dir().join("string_whitelist")))));
    let _ = std::thread::Builder::new().name("string-wl".into()).spawn(move || {
        // Let the start-up work finish first.
        std::thread::sleep(Duration::from_secs(30));
        loop {
            let desired: HashSet<String> = ti
                .reviews
                .completed_verdicts()
                .into_iter()
                .filter(|(_, v)| v == "clean")
                .map(|(s, _)| s.to_ascii_uppercase())
                .collect();
            wl.sync(&desired, &|sha: &str| engine.read_kept_indexed(sha));
            std::thread::sleep(CHECK_EVERY);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn setup(name: &str) -> (PathBuf, StringWhitelist) {
        let dir = std::env::temp_dir().join(format!("swl_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut wl = StringWhitelist::new(dir.clone());
        wl.run_keys = 3; // several runs on disk
        wl.pending_max = 3;
        (dir, wl)
    }

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn known(wl: &StringWhitelist, s: &[&str]) -> Vec<bool> {
        wl.contains_many(s)
    }

    #[test]
    fn follows_clean_verdicts_on_disk_and_in_memory() {
        let (dir, wl) = setup("follow");
        let mut files: HashMap<String, Vec<u8>> = HashMap::new();
        files.insert("A".into(), b"\x00kernel32.dll\x00GetProcAddress\x00abc\x00".to_vec());
        files.insert("B".into(), b"\x01LoadLibraryW\x02k\x00e\x00r\x00n\x00e\x00l\x00b\x00a\x00s\x00e\x00\x00\x00".to_vec());
        let read = |s: &str| files.get(s).cloned();

        wl.sync(&set(&["A"]), &read);
        assert_eq!(known(&wl, &["kernel32.dll", "GetProcAddress", "abc", "LoadLibraryW"]), [true, true, false, false], "abc is too short");
        assert_eq!(wl.status().files, 1);
        assert!(wl.disk.read().unwrap().is_none(), "a few files go to memory first");

        // B arrives; its UTF-16 string counts as the same text. Memory is over the
        // limit, so a new generation is written.
        wl.sync(&set(&["A", "B"]), &read);
        assert_eq!(known(&wl, &["kernelbase", "LoadLibraryW", "GetProcAddress", "unknown!"]), [true, true, true, false]);
        assert!(wl.disk.read().unwrap().is_some());
        assert!(wl.pending.read().unwrap().is_empty());

        // A restart reads it back from disk.
        let again = StringWhitelist::new(dir.clone());
        again.sync(&set(&["A", "B"]), &read);
        assert_eq!(known(&again, &["kernel32.dll", "kernelbase"]), [true, true]);
        assert_eq!(again.status().files, 2);

        // A's clean verdict is taken back: only B's strings stay.
        again.sync(&set(&["B"]), &read);
        assert_eq!(known(&again, &["kernel32.dll", "kernelbase"]), [false, true]);
        assert_eq!(again.status().files, 1);
        let left: Vec<String> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left.len(), 3, "manifest + one generation, no runs: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_files_are_skipped_until_a_full_build() {
        let (dir, wl) = setup("missing");
        let read = |s: &str| (s == "A").then(|| b"hello world".to_vec());
        wl.sync(&set(&["A", "GONE"]), &read);
        assert_eq!(wl.status().files, 1);
        assert!(wl.files.lock().unwrap().missing.contains("GONE"));
        assert_eq!(known(&wl, &["hello world"]), [true]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn many_files_build_through_runs() {
        let (dir, wl) = setup("many");
        let data: HashMap<String, Vec<u8>> = (0..(DIRECT_FILES + 5)).map(|i| (format!("F{i}"), format!("string number {i}\0shared string").into_bytes())).collect();
        let desired: HashSet<String> = data.keys().cloned().collect();
        wl.sync(&desired, &|s| data.get(s).cloned());
        let st = wl.status();
        assert_eq!((st.files, st.strings), (DIRECT_FILES + 5, DIRECT_FILES as u64 + 6));
        assert_eq!(known(&wl, &["string number 7", "shared string", "string number 999"]), [true, true, false]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
