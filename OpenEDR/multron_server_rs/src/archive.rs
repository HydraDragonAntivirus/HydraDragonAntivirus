//! Backup archive server.
//!
//! Main server (`--archive-mirror` or the dashboard): whenever the target folder is
//! reachable (a share on the archive PC that is not always on), the whole database and
//! every kept file are copied there with the same layout as the server folder: append-
//! only JSON-lines files get only their new bytes, other files are copied when they
//! changed. Nothing is deleted in the target, so files moved away or removed here stay
//! in the archive; the only exception is a second copy of the same sample (a kept file
//! moved to another category here is moved there too, and leftover duplicates removed). A copy goes through `.mirror_tmp/` and is renamed into place.
//!
//! The databases (`LOG_FILES`: telemetry, human verdicts, verdict cache, TLSH index,
//! events) are never replaced in the archive, only added to: the archive can hold more
//! than the main server (it is the main store and the main server starts again with
//! only new, not yet archived data, or a file here was rewritten). New bytes since the
//! last run are appended; a source that is not a continuation of what was copied is
//! appended whole (its lines come after the archive's, and the newest line of a hash
//! wins when the data is read).
//!
//! Archive server (`--archive`, run from that folder): read-only. It loads the data at
//! start and follows the files while it runs (new lines are added, rewritten files are
//! read again), so it is up to date a minute after each mirror run.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config::app_dir;

/// Files directly in the server folder that are mirrored.
pub const MIRROR_FILES: [&str; 6] = [
    "threat_insights.jsonl",
    "multron_cache.jsonl",
    "tlsh_index.jsonl",
    "multron_events.ecs.jsonl",
    "ip_bans.json",
    "sample_api_keys.txt",
];
/// Append-only line databases: added to in the archive, never replaced (see the module docs).
pub const LOG_FILES: [&str; 5] = [
    "threat_insights.jsonl",
    "multron_cache.jsonl",
    "tlsh_index.jsonl",
    "multron_events.ecs.jsonl",
    "analyst_signatures/human_verdicts.jsonl",
];
/// Folders mirrored with everything in them (the work folder is added separately).
pub const MIRROR_DIRS: [&str; 3] = ["analyst_signatures", "tlsh_signatures", "reports"];
/// Written into the target after each complete run; the archive shows it.
pub const MIRROR_STAMP: &str = "archive_mirror.json";
const TMP_DIR: &str = ".mirror_tmp";
const INTERVAL: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------- main side: mirror

#[derive(Default, Clone, Serialize)]
struct MirrorStats {
    running: bool,
    reachable: Option<bool>,
    started_at: Option<String>,
    finished_at: Option<String>,
    last_complete: Option<String>,
    checked: u64,
    copied: u64,
    appended: u64,
    bytes: u64,
    failed: u64,
    /// Kept files that moved to another category on the main server: moved in the
    /// archive too instead of being copied again.
    moved: u64,
    /// Extra copies of the same sample removed (see `dedupe`).
    duplicates_removed: u64,
    duplicate_bytes: u64,
    last_error: String,
    current: String,
}

/// Effective verdict of a hash (human verdict over engine), to pick which copy of a
/// duplicated sample stays.
pub type VerdictOf = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// (length, modified time in ns, `tail_hash` of the copied part for `LOG_FILES`) of a
/// source file when it was last copied. Older state files have only the first two.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
struct SeenFile(u64, u128, #[serde(default)] u64);
type Seen = HashMap<String, SeenFile>;

#[derive(Default)]
pub struct Mirror {
    target: RwLock<String>,
    work_dir: RwLock<Option<PathBuf>>,
    stats: Mutex<MirrorStats>,
    stop: AtomicBool,
    wake: (Mutex<bool>, Condvar),
    seen: Mutex<Option<Seen>>,
    verdict_of: RwLock<Option<VerdictOf>>,
    /// One run or duplicate removal at a time.
    busy: Mutex<()>,
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn mtime_ns(m: &fs::Metadata) -> u128 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos())
}

fn seen_path() -> PathBuf {
    app_dir().join("archive_mirror_state.json")
}

impl Mirror {
    pub fn target(&self) -> String {
        self.target.read().unwrap().clone()
    }

    pub fn set_target(&self, t: &str) {
        let t = t.trim().to_string();
        if t != self.target() {
            // Another folder: everything is compared again.
            *self.seen.lock().unwrap() = Some(Seen::new());
            let _ = fs::remove_file(seen_path());
        }
        *self.target.write().unwrap() = t;
    }

    pub fn set_verdict_lookup(&self, f: VerdictOf) {
        *self.verdict_of.write().unwrap() = Some(f);
    }

    pub fn set_work_dir(&self, d: Option<PathBuf>) {
        *self.work_dir.write().unwrap() = d;
    }

    pub fn status(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self.stats.lock().unwrap().clone()).unwrap_or_default();
        v["target"] = serde_json::json!(self.target());
        v
    }

    /// Starts a run now (or right after the current one).
    pub fn run_now(&self) {
        let (m, c) = &self.wake;
        *m.lock().unwrap() = true;
        c.notify_all();
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Background thread: a run every 5 minutes and on `run_now`.
    pub fn spawn(self: &Arc<Self>, log: impl Fn(String) + Send + 'static) {
        let me = Arc::clone(self);
        let _ = std::thread::Builder::new().name("archive-mirror".into()).spawn(move || {
            // First run shortly after start, when the server is up.
            std::thread::sleep(Duration::from_secs(20));
            let mut was_reachable: Option<bool> = None;
            loop {
                if !me.target().is_empty() {
                    me.stop.store(false, Ordering::Relaxed);
                    let reachable = me.run_once();
                    if was_reachable != Some(reachable) {
                        let s = me.stats.lock().unwrap().clone();
                        log(if reachable {
                            format!("archive mirror: {} copied, {} appended, {:.1} MB, {} failed", s.copied, s.appended, s.bytes as f64 / 1048576.0, s.failed)
                        } else {
                            format!("archive mirror: {} not reachable, will try again", me.target())
                        });
                        was_reachable = Some(reachable);
                    }
                }
                let (m, c) = &me.wake;
                let g = m.lock().unwrap();
                let (mut g, _) = c.wait_timeout_while(g, INTERVAL, |w| !*w).unwrap();
                *g = false;
            }
        });
    }

    /// One pass over everything. False when the target is not reachable.
    pub fn run_once(&self) -> bool {
        let _busy = self.busy.lock().unwrap();
        let target = PathBuf::from(self.target());
        {
            let mut s = self.stats.lock().unwrap();
            *s = MirrorStats { last_complete: s.last_complete.clone(), running: true, started_at: Some(now()), ..Default::default() };
        }
        let finish = |reachable: bool, err: String| {
            let mut s = self.stats.lock().unwrap();
            s.running = false;
            s.reachable = Some(reachable);
            s.finished_at = Some(now());
            s.current.clear();
            if !err.is_empty() {
                s.last_error = err;
            }
        };
        if !target.is_absolute() || !target.is_dir() {
            finish(false, format!("{} is not reachable (archive PC off or share not connected)", target.display()));
            return false;
        }
        if same_dir(&target, &app_dir()) {
            finish(true, "the target is this server's own folder".into());
            return true;
        }
        let tmp = target.join(TMP_DIR);
        if let Err(e) = fs::create_dir_all(&tmp) {
            finish(false, format!("cannot write to {}: {e}", target.display()));
            return false;
        }

        let mut seen = self.seen.lock().unwrap().take().unwrap_or_else(|| {
            fs::read_to_string(seen_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
        });

        let root = app_dir();
        let mut jobs: Vec<(PathBuf, String)> = Vec::new();
        for f in MIRROR_FILES {
            jobs.push((root.join(f), f.to_string()));
        }
        for d in MIRROR_DIRS {
            walk(&root.join(d), d, &mut jobs);
        }
        let work = self.work_dir.read().unwrap().clone().unwrap_or_else(|| root.join("multron_incoming"));
        walk(&work, "multron_incoming", &mut jobs);

        // Samples already in the archive, by SHA-256: a file that moved to another
        // category here is moved there too instead of being copied again.
        let mut archived = index_samples(&target.join("multron_incoming"));
        let mut lost = false;
        for (src, rel) in jobs {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            self.stats.lock().unwrap().current = rel.clone();
            let dst = target.join(&rel);
            if let Some(sha) = rel.strip_prefix("multron_incoming/").and_then(sample_sha) {
                if !dst.exists() {
                    let file_name = rel.rsplit('/').next().unwrap_or("");
                    let src_len = fs::metadata(&src).map(|m| m.len()).ok();
                    let found = archived.get(&sha).and_then(|v| {
                        v.iter().find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == file_name) && fs::metadata(p).map(|m| m.len()).ok() == src_len).cloned()
                    });
                    if let Some(old) = found {
                        if dst.parent().is_some_and(|d| fs::create_dir_all(d).is_ok()) && fs::rename(&old, &dst).is_ok() {
                            if let Some(v) = archived.get_mut(&sha) {
                                v.retain(|p| p != &old);
                                v.push(dst.clone());
                            }
                            self.stats.lock().unwrap().moved += 1;
                        }
                    }
                }
            }
            let prev = seen.get(&rel).copied();
            let r = if LOG_FILES.contains(&rel.as_str()) {
                sync_log(&src, &dst, prev)
            } else {
                sync_file(&src, &dst, &tmp, prev.map(|p| (p.0, p.1))).map(|o| o.map(|(a, b, c, d)| (a, b, c, d, 0)))
            };
            match r {
                Ok(Some((outcome, len, mt, bytes, fp))) => {
                    seen.insert(rel, SeenFile(len, mt, fp));
                    let mut s = self.stats.lock().unwrap();
                    s.checked += 1;
                    s.bytes += bytes;
                    match outcome {
                        Outcome::Same => {}
                        Outcome::Copied => s.copied += 1,
                        Outcome::Appended => s.appended += 1,
                    }
                }
                Ok(None) => {} // source gone
                Err(e) => {
                    let mut s = self.stats.lock().unwrap();
                    s.failed += 1;
                    s.last_error = format!("{rel}: {e}");
                    drop(s);
                    if !target.is_dir() {
                        lost = true;
                        break;
                    }
                }
            }
        }

        let _ = fs::write(seen_path(), serde_json::to_string(&seen).unwrap_or_default());
        *self.seen.lock().unwrap() = Some(seen);
        if lost {
            finish(false, "the target went away during the run".into());
            return false;
        }
        let stopped = self.stop.load(Ordering::Relaxed);
        if !stopped {
            let (n, bytes) = self.dedupe_in(&target, &work);
            {
                let mut s = self.stats.lock().unwrap();
                s.duplicates_removed += n;
                s.duplicate_bytes += bytes;
            }
            let s = self.stats.lock().unwrap().clone();
            let stamp = serde_json::json!({
                "time": now(), "checked": s.checked, "copied": s.copied, "appended": s.appended,
                "bytes": s.bytes, "failed": s.failed, "moved": s.moved, "duplicates_removed": s.duplicates_removed,
            });
            let _ = fs::write(target.join(MIRROR_STAMP), serde_json::to_string_pretty(&stamp).unwrap_or_default());
            self.stats.lock().unwrap().last_complete = Some(now());
        }
        finish(true, if stopped { "stopped".into() } else { String::new() });
        true
    }
}

impl Mirror {
    /// Removes extra copies of the same sample in the archive's `multron_incoming`
    /// (the same SHA-256 in more than one category, or plain and `.xz`). The copy that
    /// stays: the one at the path the main server has it now; otherwise the one in the
    /// folder of its current verdict; otherwise the plain one, then the newest.
    /// Returns (files removed, bytes freed).
    pub fn dedupe_now(&self) -> Result<(u64, u64), String> {
        let _busy = self.busy.try_lock().map_err(|_| "a copy run is going on; duplicates are removed at its end".to_string())?;
        let target = PathBuf::from(self.target());
        if !target.is_absolute() || !target.is_dir() {
            return Err(format!("{} is not reachable", target.display()));
        }
        let work = self.work_dir.read().unwrap().clone().unwrap_or_else(|| app_dir().join("multron_incoming"));
        let r = self.dedupe_in(&target, &work);
        let mut s = self.stats.lock().unwrap();
        s.duplicates_removed += r.0;
        s.duplicate_bytes += r.1;
        Ok(r)
    }

    fn dedupe_in(&self, target: &Path, work: &Path) -> (u64, u64) {
        let incoming = target.join("multron_incoming");
        let here: HashMap<String, PathBuf> = index_samples(work)
            .into_iter()
            .filter_map(|(sha, v)| {
                let p = v.into_iter().next()?;
                let rel = p.strip_prefix(work).ok()?.to_path_buf();
                Some((sha, incoming.join(rel)))
            })
            .collect();
        let verdict_of = self.verdict_of.read().unwrap().clone();
        let (mut removed, mut bytes) = (0u64, 0u64);
        for (sha, copies) in index_samples(&incoming) {
            if copies.len() < 2 {
                continue;
            }
            let keep = here
                .get(&sha)
                .filter(|p| copies.contains(p))
                .cloned()
                .or_else(|| {
                    let cat = crate::engine_adapter::KeptFile::category_for(&verdict_of.as_ref().and_then(|f| f(&sha))?);
                    let in_cat: Vec<&PathBuf> = copies.iter().filter(|p| category_of(p) == Some(cat)).collect();
                    best_copy(&in_cat)
                })
                .or_else(|| best_copy(&copies.iter().collect::<Vec<_>>()));
            let Some(keep) = keep else { continue };
            for p in copies.iter().filter(|p| **p != keep) {
                let len = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                if fs::remove_file(p).is_ok() {
                    removed += 1;
                    bytes += len;
                }
            }
        }
        (removed, bytes)
    }
}

/// SHA-256 (upper case) of a kept sample file name `<SHA256>_<name>[.xz]`.
fn sample_sha(rel_or_name: &str) -> Option<String> {
    let name = rel_or_name.rsplit(['/', '\\']).next()?;
    let sha = name.get(..64)?;
    (sha.chars().all(|c| c.is_ascii_hexdigit()) && name.as_bytes().get(64) == Some(&b'_')).then(|| sha.to_ascii_uppercase())
}

fn category_of(p: &Path) -> Option<&'static str> {
    // `<category>/<name>` or, sorted by type, `<category>/pe|js|apk/<name>`.
    let mut parent = p.parent()?;
    if crate::engine_adapter::kind_dir_of(p).is_some() {
        parent = parent.parent()?;
    }
    let dir = parent.file_name()?.to_string_lossy().to_string();
    crate::engine_adapter::KeptFile::CATEGORIES.into_iter().find(|c| *c == dir)
}

/// Plain over `.xz`, then the newest.
fn best_copy(copies: &[&PathBuf]) -> Option<PathBuf> {
    copies
        .iter()
        .max_by_key(|p| {
            let plain = !p.to_string_lossy().ends_with(".xz");
            let mt = fs::metadata(p).map(|m| mtime_ns(&m)).unwrap_or(0);
            (plain, mt)
        })
        .map(|p| (*p).clone())
}

/// Every kept sample under a work folder (any depth), by SHA-256.
fn index_samples(dir: &Path) -> HashMap<String, Vec<PathBuf>> {
    let mut files = Vec::new();
    walk(dir, "", &mut files);
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (p, rel) in files {
        if let Some(sha) = sample_sha(&rel) {
            out.entry(sha).or_default().push(p);
        }
    }
    out
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn skip_name(name: &str) -> bool {
    name.ends_with(".tmp") || name.ends_with(".part") || name == TMP_DIR
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<(PathBuf, String)>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if skip_name(&name) {
            continue;
        }
        let r = format!("{rel}/{name}");
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&e.path(), &r, out),
            Ok(t) if t.is_file() => out.push((e.path(), r)),
            _ => {}
        }
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Same,
    Copied,
    Appended,
}

/// FNV-1a of the (up to) 4 KB before `len`: recognises the part of a source already
/// copied (0 = nothing copied yet).
fn tail_hash(p: &Path, len: u64) -> io::Result<u64> {
    if len == 0 {
        return Ok(0);
    }
    let n = len.min(4096);
    let mut f = File::open(p)?;
    f.seek(SeekFrom::Start(len - n))?;
    let mut buf = vec![0u8; n as usize];
    f.read_exact(&mut buf)?;
    let mut h: u64 = 0xcbf29ce484222325;
    for b in buf {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    Ok(h.max(1))
}

/// A `LOG_FILES` database: only added to in the archive (see the module docs).
/// Returns (outcome, source length copied, source mtime, bytes written, tail hash).
fn sync_log(src: &Path, dst: &Path, prev: Option<SeenFile>) -> io::Result<Option<(Outcome, u64, u128, u64, u64)>> {
    let Ok(sm) = fs::metadata(src) else { return Ok(None) };
    let (slen, smt) = (sm.len(), mtime_ns(&sm));
    let dlen = fs::metadata(dst).ok().map(|m| m.len());
    let Some(dlen) = dlen else {
        // Not in the archive yet: a plain copy.
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p)?;
        }
        let n = append_from(src, &create(dst)?, 0, slen)?;
        return Ok(Some((Outcome::Copied, slen, smt, n, tail_hash(src, slen)?)));
    };
    // Where this source continues from: what the last run copied, recognised by its
    // tail; on a first run against an archive, the archive's own copy when it is a
    // copy of this source so far.
    let from = match prev {
        Some(SeenFile(plen, pmt, pfp)) if plen == slen && pmt == smt => return Ok(Some((Outcome::Same, slen, smt, 0, pfp))),
        Some(SeenFile(plen, _, pfp)) if pfp != 0 && plen <= slen && tail_hash(src, plen)? == pfp => Some(plen),
        Some(SeenFile(plen, _, 0)) if plen == dlen && dlen <= slen && same_tail(src, dst, dlen)? => Some(dlen),
        None if dlen <= slen && same_tail(src, dst, dlen)? => Some(dlen),
        _ => None,
    };
    let fp = tail_hash(src, slen)?;
    match from {
        Some(f) if f == slen => Ok(Some((Outcome::Same, slen, smt, 0, fp))),
        Some(f) => {
            let n = append_from(src, dst, f, slen)?;
            Ok(Some((Outcome::Appended, slen, smt, n, fp)))
        }
        None => {
            // A new or rewritten source: added whole after the archive's lines.
            if dlen > 0 && !ends_with_newline(dst, dlen)? {
                OpenOptions::new().append(true).open(dst)?.write_all(b"\n")?;
            }
            let n = append_from(src, dst, 0, slen)?;
            Ok(Some((Outcome::Appended, slen, smt, n, fp)))
        }
    }
}

fn create(p: &Path) -> io::Result<PathBuf> {
    File::create(p)?;
    Ok(p.to_path_buf())
}

fn ends_with_newline(p: &Path, len: u64) -> io::Result<bool> {
    let mut f = File::open(p)?;
    f.seek(SeekFrom::Start(len - 1))?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b)?;
    Ok(b[0] == b'\n')
}

/// Copies one file if it changed since `prev` (length, mtime of the source when last
/// copied). Grown files whose already copied part still matches get only the new
/// bytes. Returns None when the source does not exist (any more).
fn sync_file(src: &Path, dst: &Path, tmp_dir: &Path, prev: Option<(u64, u128)>) -> io::Result<Option<(Outcome, u64, u128, u64)>> {
    let Ok(sm) = fs::metadata(src) else { return Ok(None) };
    let (slen, smt) = (sm.len(), mtime_ns(&sm));
    let dm = fs::metadata(dst).ok();
    let dlen = dm.as_ref().map(|m| m.len());
    if prev == Some((slen, smt)) && dlen == Some(slen) {
        return Ok(Some((Outcome::Same, slen, smt, 0)));
    }
    if let Some(dlen) = dlen {
        if dlen == slen && prev.is_none() && same_tail(src, dst, dlen)? {
            // First run against an existing copy (e.g. after a reinstall).
            return Ok(Some((Outcome::Same, slen, smt, 0)));
        }
        if dlen > 0 && dlen < slen && same_tail(src, dst, dlen)? {
            let n = append_from(src, dst, dlen, slen)?;
            return Ok(Some((Outcome::Appended, dlen + n, smt, n)));
        }
    }
    if let Some(p) = dst.parent() {
        fs::create_dir_all(p)?;
    }
    let tmp = tmp_dir.join(format!("{}_{}.part", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())));
    let n = (|| -> io::Result<u64> {
        let mut r = File::open(src)?;
        let mut w = File::create(&tmp)?;
        let n = io::copy(&mut (&mut r).take(slen), &mut w)?;
        w.flush()?;
        drop(w);
        fs::rename(&tmp, dst)?;
        Ok(n)
    })();
    match n {
        Ok(n) => Ok(Some((Outcome::Copied, n, smt, n))),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The last (up to) 4 KB before `len` are the same in both files.
fn same_tail(a: &Path, b: &Path, len: u64) -> io::Result<bool> {
    let n = len.min(4096);
    let read = |p: &Path| -> io::Result<Vec<u8>> {
        let mut f = File::open(p)?;
        f.seek(SeekFrom::Start(len - n))?;
        let mut buf = vec![0u8; n as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    };
    Ok(read(a)? == read(b)?)
}

fn append_from(src: &Path, dst: &Path, from: u64, to: u64) -> io::Result<u64> {
    let mut r = File::open(src)?;
    r.seek(SeekFrom::Start(from))?;
    let mut w = OpenOptions::new().append(true).open(dst)?;
    let n = io::copy(&mut r.take(to - from), &mut w)?;
    w.flush()?;
    Ok(n)
}

// ---------------------------------------------------------------- archive side

/// Follows an append-only JSON-lines file: complete new lines since the last read, or
/// everything again when the file was rewritten (shorter, or the bytes before the
/// last position changed).
pub struct Tail {
    path: PathBuf,
    offset: u64,
    check: Vec<u8>,
    fresh: bool,
}

pub enum TailRead {
    Same,
    New(Vec<String>),
    /// Start over with these lines.
    Reset(Vec<String>),
}

impl Tail {
    pub fn new(path: PathBuf) -> Self {
        Self { path, offset: 0, check: Vec::new(), fresh: true }
    }

    /// Follows only what is added after the first `len` bytes (seamless update: the
    /// file was loaded up to there). Starts at the last complete line before `len`, so
    /// a line being written at that moment is read again (ingesting is idempotent).
    /// Without a line break in the last MiB before `len`, the whole file is read again.
    pub fn after(path: PathBuf, len: u64) -> Self {
        let mut t = Self::new(path);
        let Ok(mut f) = File::open(&t.path) else {
            // Not there yet: whatever appears later is new.
            t.fresh = false;
            return t;
        };
        let start = len.saturating_sub(1 << 20);
        let mut buf = Vec::new();
        if f.seek(SeekFrom::Start(start)).is_err() || (&mut f).take(len - start).read_to_end(&mut buf).is_err() {
            return t;
        }
        match buf.iter().rposition(|&b| b == b'\n') {
            Some(i) => {
                t.offset = start + i as u64 + 1;
                t.check = buf[(i + 1).saturating_sub(64)..=i].to_vec();
                t.fresh = false;
            }
            None if start == 0 => t.fresh = false,
            None => {}
        }
        t
    }

    pub fn read(&mut self) -> TailRead {
        let mut reset = std::mem::take(&mut self.fresh);
        let Ok(mut f) = File::open(&self.path) else {
            if self.offset > 0 || reset {
                self.offset = 0;
                self.check.clear();
                return TailRead::Reset(Vec::new());
            }
            return TailRead::Same;
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            reset = true;
        } else if self.offset > 0 && !self.check.is_empty() {
            let mut buf = vec![0u8; self.check.len()];
            let ok = f.seek(SeekFrom::Start(self.offset - self.check.len() as u64)).is_ok() && f.read_exact(&mut buf).is_ok();
            if !ok || buf != self.check {
                reset = true;
            }
        }
        if reset {
            self.offset = 0;
            self.check.clear();
        }
        let mut buf = Vec::new();
        if len > self.offset && f.seek(SeekFrom::Start(self.offset)).is_ok() {
            let _ = (&mut f).take(len - self.offset).read_to_end(&mut buf);
        }
        let lines = match buf.iter().rposition(|&b| b == b'\n') {
            Some(end) => {
                let chunk = &buf[..=end];
                self.offset += chunk.len() as u64;
                self.check.extend_from_slice(chunk);
                let cut = self.check.len().saturating_sub(64);
                self.check.drain(..cut);
                String::from_utf8_lossy(chunk)
                    .split('\n')
                    .map(|l| l.trim_end_matches('\r'))
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string)
                    .collect()
            }
            None => Vec::new(),
        };
        if reset {
            TailRead::Reset(lines)
        } else if lines.is_empty() {
            TailRead::Same
        } else {
            TailRead::New(lines)
        }
    }
}

/// (length, mtime) of every file under these paths, to see that something changed.
pub(crate) fn fingerprint(paths: &[PathBuf]) -> Vec<(PathBuf, u64, u128)> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut jobs = Vec::new();
            walk(p, "", &mut jobs);
            for (f, _) in jobs {
                if let Ok(m) = fs::metadata(&f) {
                    out.push((f, m.len(), mtime_ns(&m)));
                }
            }
        } else if let Ok(m) = fs::metadata(p) {
            out.push((p.clone(), m.len(), mtime_ns(&m)));
        }
    }
    out.sort();
    out
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ArchiveInfo {
    /// When the main server last finished a mirror run into this folder.
    pub data_as_of: Option<String>,
    pub last_reload: Option<String>,
    pub insights: usize,
}

pub static INFO: RwLock<Option<ArchiveInfo>> = RwLock::new(None);

pub fn info_json() -> serde_json::Value {
    serde_json::to_value(INFO.read().unwrap().clone().unwrap_or_default()).unwrap_or_default()
}

fn stamp_time() -> Option<String> {
    let t = fs::read_to_string(app_dir().join(MIRROR_STAMP)).ok()?;
    serde_json::from_str::<serde_json::Value>(&t).ok()?["time"].as_str().map(str::to_string)
}

/// Archive mode: follows the mirrored files every minute.
pub fn spawn_reloader(server: Arc<crate::scan_server::ScanServer>) {
    let _ = std::thread::Builder::new().name("archive-reload".into()).spawn(move || {
        let ti = Arc::clone(&server.threat_intel);
        let root = app_dir();
        let mut insights = Tail::new(root.join("threat_insights.jsonl"));
        let mut reviews = Tail::new(crate::human_review::analyst_dir().join("human_verdicts.jsonl"));
        let mut cache = Tail::new(root.join("multron_cache.jsonl"));
        let mut tlsh = Tail::new(root.join("tlsh_index.jsonl"));
        let sig_paths = vec![root.join("tlsh_signatures"), crate::human_review::analyst_dir()];
        let mut sig_fp = fingerprint(&sig_paths);
        let bans_path = root.join("ip_bans.json");
        let mut bans_fp = fingerprint(std::slice::from_ref(&bans_path));
        loop {
            let feed = |t: &mut Tail, f: &dyn Fn(&[String], bool)| match t.read() {
                TailRead::Same => {}
                TailRead::New(l) => f(&l, false),
                TailRead::Reset(l) => f(&l, true),
            };
            feed(&mut insights, &|l, r| ti.archive_ingest(l, r));
            feed(&mut reviews, &|l, r| ti.reviews.archive_ingest(l, r));
            feed(&mut cache, &|l, r| server.cache.archive_ingest(l, r));
            feed(&mut tlsh, &|l, r| ti.similarity.archive_ingest_index(l, r));
            let fp = fingerprint(&sig_paths);
            if fp != sig_fp {
                ti.similarity.reload_known_malware();
                ti.similarity.reload_corpus_refs();
                ti.similarity.reload_analyst_sigs();
                sig_fp = fp;
            }
            let fp = fingerprint(std::slice::from_ref(&bans_path));
            if fp != bans_fp {
                server.ip_bans.reload();
                bans_fp = fp;
            }
            *INFO.write().unwrap() = Some(ArchiveInfo {
                data_as_of: stamp_time(),
                last_reload: Some(now()),
                insights: ti.stats().total_unique_hashes,
            });
            std::thread::sleep(Duration::from_secs(60));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("arch_{tag}_{}_{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sync_appends_copies_and_skips() {
        let d = tmpdir("sync");
        let (src, dst, tmp) = (d.join("a.jsonl"), d.join("out/a.jsonl"), d.join("tmp"));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(&src, "one\n").unwrap();
        let r = sync_file(&src, &dst, &tmp, None).unwrap().unwrap();
        assert_eq!(r.0, Outcome::Copied);
        assert_eq!(fs::read_to_string(&dst).unwrap(), "one\n");
        let prev = Some((r.1, r.2));
        assert_eq!(sync_file(&src, &dst, &tmp, prev).unwrap().unwrap().0, Outcome::Same);
        // grown: only the new bytes
        fs::write(&src, "one\ntwo\n").unwrap();
        let r = sync_file(&src, &dst, &tmp, prev).unwrap().unwrap();
        assert_eq!((r.0, r.3), (Outcome::Appended, 4));
        assert_eq!(fs::read_to_string(&dst).unwrap(), "one\ntwo\n");
        // rewritten (compacted): copied again
        fs::write(&src, "ONE\ntwo\nthree\n").unwrap();
        let r = sync_file(&src, &dst, &tmp, Some((r.1, r.2))).unwrap().unwrap();
        assert_eq!(r.0, Outcome::Copied);
        assert_eq!(fs::read_to_string(&dst).unwrap(), "ONE\ntwo\nthree\n");
        assert!(sync_file(&d.join("missing"), &dst, &tmp, None).unwrap().is_none());
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0, "no temp files left");
    }

    #[test]
    fn logs_are_only_added_to() {
        let d = tmpdir("log");
        let (src, dst) = (d.join("threat_insights.jsonl"), d.join("arch/threat_insights.jsonl"));
        // the archive already holds older data than this (fresh) main server
        fs::create_dir_all(d.join("arch")).unwrap();
        fs::write(&dst, "old1\nold2\nold3\n").unwrap();
        fs::write(&src, "new1\n").unwrap();
        let r = sync_log(&src, &dst, None).unwrap().unwrap();
        assert_eq!(r.0, Outcome::Appended);
        assert_eq!(fs::read_to_string(&dst).unwrap(), "old1\nold2\nold3\nnew1\n");
        let prev = Some(SeenFile(r.1, r.2, r.4));
        assert_eq!(sync_log(&src, &dst, prev).unwrap().unwrap().0, Outcome::Same);
        // grown: only the new bytes
        fs::write(&src, "new1\nnew2\n").unwrap();
        let r = sync_log(&src, &dst, prev).unwrap().unwrap();
        assert_eq!((r.0, r.3), (Outcome::Appended, 5));
        assert_eq!(fs::read_to_string(&dst).unwrap(), "old1\nold2\nold3\nnew1\nnew2\n");
        // rewritten here (compacted, or started again): added whole, nothing replaced
        fs::write(&src, "x\n").unwrap();
        let r = sync_log(&src, &dst, Some(SeenFile(r.1, r.2, r.4))).unwrap().unwrap();
        assert_eq!(r.0, Outcome::Appended);
        assert_eq!(fs::read_to_string(&dst).unwrap(), "old1\nold2\nold3\nnew1\nnew2\nx\n");
        // a normal mirror (archive = copy of this file) keeps only appending
        let (s2, d2) = (d.join("b.jsonl"), d.join("arch/b.jsonl"));
        fs::write(&s2, "a\nb\n").unwrap();
        fs::write(&d2, "a\n").unwrap();
        let r = sync_log(&s2, &d2, None).unwrap().unwrap();
        assert_eq!((r.0, fs::read_to_string(&d2).unwrap()), (Outcome::Appended, "a\nb\n".to_string()));
        // older state (no tail hash) whose copy matches: continues
        fs::write(&s2, "a\nb\nc\n").unwrap();
        let r = sync_log(&s2, &d2, Some(SeenFile(4, 1, 0))).unwrap().unwrap();
        assert_eq!((r.0, fs::read_to_string(&d2).unwrap()), (Outcome::Appended, "a\nb\nc\n".to_string()));
        // missing in the archive: copied
        let d3 = d.join("arch/new/c.jsonl");
        assert_eq!(sync_log(&s2, &d3, None).unwrap().unwrap().0, Outcome::Copied);
        assert_eq!(fs::read_to_string(&d3).unwrap(), "a\nb\nc\n");
        // old state files ([len, mtime]) still load
        let old: Seen = serde_json::from_str(r#"{"x.jsonl":[10,20]}"#).unwrap();
        assert_eq!(old["x.jsonl"], SeenFile(10, 20, 0));
    }

    #[test]
    fn tail_follows_and_resets() {
        let d = tmpdir("tail");
        let p = d.join("x.jsonl");
        fs::write(&p, "a\nb\npart").unwrap();
        let mut t = Tail::new(p.clone());
        assert!(matches!(t.read(), TailRead::Reset(l) if l == ["a", "b"]));
        assert!(matches!(t.read(), TailRead::Same));
        fs::write(&p, "a\nb\npartial\nc\n").unwrap();
        assert!(matches!(t.read(), TailRead::New(l) if l == ["partial", "c"]));
        fs::write(&p, "z\n").unwrap();
        assert!(matches!(t.read(), TailRead::Reset(l) if l == ["z"]));
        fs::write(&p, "y\nlonger file now\n").unwrap();
        assert!(matches!(t.read(), TailRead::Reset(l) if l == ["y", "longer file now"]), "same length start changed");
    }

    #[test]
    fn category_move_and_duplicates() {
        let d = tmpdir("dedupe");
        let target = d.join("archive");
        let work = d.join("incoming");
        let sha = "AB".repeat(32);
        fs::create_dir_all(work.join("unknown")).unwrap();
        fs::write(work.join("unknown").join(format!("{sha}_x.exe")), b"MZdata").unwrap();
        fs::create_dir_all(&target).unwrap();
        let m = Mirror::default();
        *m.target.write().unwrap() = target.to_string_lossy().to_string();
        m.set_work_dir(Some(work.clone()));
        assert!(m.run_once());
        // the verdict changed here: the file moved to malicious/
        fs::create_dir_all(work.join("malicious")).unwrap();
        fs::rename(work.join("unknown").join(format!("{sha}_x.exe")), work.join("malicious").join(format!("{sha}_x.exe"))).unwrap();
        assert!(m.run_once());
        let st = m.status();
        assert_eq!(st["moved"], 1, "{st}");
        assert_eq!(st["duplicates_removed"], 0, "moved, not copied: nothing to remove");
        assert!(target.join(format!("multron_incoming/malicious/{sha}_x.exe")).exists());
        assert!(!target.join(format!("multron_incoming/unknown/{sha}_x.exe")).exists());

        // leftovers from older runs (offloaded file, no longer here): verdict decides
        let sha2 = "CD".repeat(32);
        for cat in ["unknown", "suspicious"] {
            fs::create_dir_all(target.join("multron_incoming").join(cat)).unwrap();
            fs::write(target.join("multron_incoming").join(cat).join(format!("{sha2}_y.dll")), b"MZ2").unwrap();
        }
        let want = sha2.clone();
        m.set_verdict_lookup(Arc::new(move |s: &str| (s == want).then(|| "suspicious".to_string())));
        assert_eq!(m.dedupe_now().unwrap().0, 1);
        assert!(target.join(format!("multron_incoming/suspicious/{sha2}_y.dll")).exists());
        assert!(!target.join(format!("multron_incoming/unknown/{sha2}_y.dll")).exists());
        assert_eq!(m.dedupe_now().unwrap().0, 0);
    }

    #[test]
    fn mirror_run_layout() {
        let d = tmpdir("mirror");
        let target = d.join("archive");
        fs::create_dir_all(&target).unwrap();
        let work = d.join("incoming");
        fs::create_dir_all(work.join("malicious")).unwrap();
        fs::write(work.join("malicious").join("AB_x.exe"), b"MZ").unwrap();
        let m = Mirror::default();
        *m.target.write().unwrap() = target.to_string_lossy().to_string();
        m.set_work_dir(Some(work.clone()));
        assert!(m.run_once());
        assert_eq!(fs::read(target.join("multron_incoming/malicious/AB_x.exe")).unwrap(), b"MZ");
        assert!(target.join(MIRROR_STAMP).exists());
        // removed at the source: stays in the archive
        fs::remove_file(work.join("malicious").join("AB_x.exe")).unwrap();
        assert!(m.run_once());
        assert!(target.join("multron_incoming/malicious/AB_x.exe").exists());
        // unreachable target
        *m.target.write().unwrap() = d.join("nope").to_string_lossy().to_string();
        assert!(!m.run_once());
    }
}
