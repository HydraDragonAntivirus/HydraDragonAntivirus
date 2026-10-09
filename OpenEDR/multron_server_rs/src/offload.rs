//! Moving kept files (multron_incoming) to another disk or a network share, e.g. the
//! main PC on the same network (`\\MAINPC\multron_archive`) or an external drive.
//! Automatic when this disk runs low or a keep quota is 80 % full, or by hand from the
//! dashboard for chosen categories. Least useful files go first: clean, then possible
//! clean, malicious, suspicious and unknown last (unknown files are the ones rescans
//! after engine updates settle); oldest first inside a category.
//!
//! Each file is copied to `<target>/<category>/<SHA256>_<name>[.xz]` through a `.part`
//! file, the copy is hashed (decompressed when `.xz`) and must match its SHA-256, and
//! only then is the local file deleted. Moved files are forgotten here: they can no
//! longer be rescanned or shared from this server.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use sha2::{Digest, Sha256};

use crate::engine_adapter::{EngineAdapter, KeptFile, Pressure};

/// Move order: the first category goes first.
const MOVE_ORDER: [&str; 5] = ["clean", "possible_clean", "malicious", "suspicious", "unknown"];

#[derive(Default)]
pub struct Offload {
    /// Target folder; empty = off.
    pub target: RwLock<String>,
    /// Move automatically when space runs low.
    pub auto: AtomicBool,
    running: AtomicBool,
    stop: AtomicBool,
    total: AtomicUsize,
    moved: AtomicUsize,
    failed: AtomicUsize,
    bytes: AtomicU64,
    last_error: Mutex<String>,
    started_at: Mutex<Option<String>>,
    finished_at: Mutex<Option<String>>,
    reason: Mutex<String>,
}

impl Offload {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn target(&self) -> String {
        self.target.read().unwrap().clone()
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "target": self.target(),
            "auto": self.auto.load(Ordering::Relaxed),
            "running": self.is_running(),
            "reason": *self.reason.lock().unwrap(),
            "total": self.total.load(Ordering::Relaxed),
            "moved": self.moved.load(Ordering::Relaxed),
            "failed": self.failed.load(Ordering::Relaxed),
            "gbMoved": self.bytes.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0 * 1024.0),
            "lastError": *self.last_error.lock().unwrap(),
            "startedAt": *self.started_at.lock().unwrap(),
            "finishedAt": *self.finished_at.lock().unwrap(),
        })
    }
}

/// Checks a target folder: absolute, reachable, writable and not the work folder.
pub fn check_target(engine: &EngineAdapter, target: &str) -> Result<PathBuf, String> {
    let t = target.trim();
    if t.is_empty() {
        return Err("no target folder set".into());
    }
    let path = PathBuf::from(t);
    if !path.is_absolute() {
        return Err("the target must be an absolute path, e.g. \\\\MAINPC\\multron_archive or E:\\multron_archive".into());
    }
    std::fs::create_dir_all(&path).map_err(|e| format!("cannot reach {t}: {e}"))?;
    if let Some(work) = engine.work_dir() {
        let same = match (std::fs::canonicalize(work), std::fs::canonicalize(&path)) {
            (Ok(a), Ok(b)) => b.starts_with(&a) || a.starts_with(&b),
            _ => false,
        };
        if same {
            return Err("the target must not be inside the work folder (or contain it)".into());
        }
    }
    let probe = path.join(".multron_write_test");
    std::fs::write(&probe, b"ok").map_err(|e| format!("cannot write to {t}: {e}"))?;
    let _ = std::fs::remove_file(&probe);
    Ok(path)
}

/// SHA-256 (upper-case hex) of a kept file's content, decompressing `.xz` copies.
fn content_sha(path: &Path, xz: bool) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut reader: Box<dyn Read> = if xz {
        Box::new(lzma_rust2::XzReader::new(std::io::BufReader::new(f), false))
    } else {
        Box::new(std::io::BufReader::new(f))
    };
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode_upper(h.finalize()))
}

/// Copies one kept file to the target, verifies it and deletes the local file.
/// Returns the bytes freed here.
fn move_one(engine: &EngineAdapter, target: &Path, k: &KeptFile) -> Result<u64, String> {
    let dir = target.join(k.category);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let dest = dir.join(k.file_name());
    let ok_already = dest.exists() && content_sha(&dest, k.xz).as_deref() == Some(k.sha256.as_str());
    if !ok_already {
        let part = dir.join(format!("{}.part", k.file_name()));
        std::fs::copy(&k.path, &part).map_err(|e| format!("copy {}: {e}", k.file_name()))?;
        if content_sha(&part, k.xz).as_deref() != Some(k.sha256.as_str()) {
            let _ = std::fs::remove_file(&part);
            return Err(format!("{}: the copy does not match its SHA-256", k.file_name()));
        }
        let _ = std::fs::remove_file(&dest);
        std::fs::rename(&part, &dest).map_err(|e| format!("rename {}: {e}", k.file_name()))?;
    }
    engine.forget_kept(k).ok_or_else(|| format!("{}: copied, but the local file could not be deleted", k.file_name()))
}

/// What to move: every kept file of `categories` (by hand), or the oldest files until
/// there is room again (automatic).
pub enum Mode {
    Categories(Vec<String>),
    /// Started because of this pressure; only files that relieve it are moved, until
    /// it is gone.
    UntilRelieved(Pressure),
}

/// Starts moving in the background. Returns how many files are candidates.
pub fn start(engine: &Arc<EngineAdapter>, off: &Arc<Offload>, mode: Mode, log: impl Fn(String) + Send + 'static) -> Result<usize, String> {
    let target = check_target(engine, &off.target())?;
    let mut files = engine.list_kept();
    let reason = match &mode {
        Mode::Categories(cats) => {
            let cats: Vec<&str> = if cats.is_empty() { KeptFile::CATEGORIES.to_vec() } else { cats.iter().map(String::as_str).collect() };
            if let Some(bad) = cats.iter().find(|c| !KeptFile::CATEGORIES.contains(c)) {
                return Err(format!("unknown category {bad}"));
            }
            files.retain(|k| cats.contains(&k.category));
            format!("by hand: {}", cats.join(", "))
        }
        Mode::UntilRelieved(p) => {
            files.retain(|k| p.helped_by(k.category));
            let mut why = Vec::new();
            if p.disk {
                why.push("low disk space");
            }
            if p.clean {
                why.push("clean quota 80 % full");
            }
            if p.shared {
                why.push("keep quota 80 % full");
            }
            format!("automatic: {}", why.join(", "))
        }
    };
    if off.running.swap(true, Ordering::SeqCst) {
        return Err("a move is already running".into());
    }
    // Least useful category first, oldest first inside it.
    let rank = |c: &str| MOVE_ORDER.iter().position(|m| *m == c).unwrap_or(MOVE_ORDER.len());
    let mut dated: Vec<(usize, std::time::SystemTime, KeptFile)> = files
        .into_iter()
        .map(|k| (rank(k.category), std::fs::metadata(&k.path).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH), k))
        .collect();
    dated.sort_by_key(|(r, t, _)| (*r, *t));
    let n = dated.len();
    off.stop.store(false, Ordering::Relaxed);
    off.total.store(n, Ordering::Relaxed);
    off.moved.store(0, Ordering::Relaxed);
    off.failed.store(0, Ordering::Relaxed);
    off.bytes.store(0, Ordering::Relaxed);
    off.last_error.lock().unwrap().clear();
    *off.reason.lock().unwrap() = reason.clone();
    *off.started_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
    *off.finished_at.lock().unwrap() = None;
    let started_by = match mode {
        Mode::UntilRelieved(p) => Some(p),
        Mode::Categories(_) => None,
    };
    log(format!("moving kept files to {} ({reason}): {n} candidates", target.display()));
    let (eng, o) = (Arc::clone(engine), Arc::clone(off));
    let spawned = std::thread::Builder::new().name("offload".into()).spawn(move || {
        let mut failures_in_row = 0;
        for (_, _, k) in dated {
            if o.stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(start) = started_by {
                let now = eng.storage_pressure(true);
                if !now.still(&start) {
                    break;
                }
                // e.g. the clean quota is fine again but the shared one is not: skip clean files.
                if !now.helped_by(k.category) {
                    continue;
                }
            }
            match move_one(&eng, &target, &k) {
                Ok(freed) => {
                    failures_in_row = 0;
                    o.moved.fetch_add(1, Ordering::Relaxed);
                    o.bytes.fetch_add(freed, Ordering::Relaxed);
                }
                Err(e) => {
                    o.failed.fetch_add(1, Ordering::Relaxed);
                    *o.last_error.lock().unwrap() = e;
                    failures_in_row += 1;
                    // Target gone (share offline, disk full): stop instead of failing every file.
                    if failures_in_row >= 5 {
                        break;
                    }
                }
            }
        }
        *o.finished_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
        o.running.store(false, Ordering::SeqCst);
        let err = o.last_error.lock().unwrap().clone();
        log(format!(
            "kept files moved to {}: {} files, {:.2} GB, {} failed{}",
            target.display(),
            o.moved.load(Ordering::Relaxed),
            o.bytes.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0 * 1024.0),
            o.failed.load(Ordering::Relaxed),
            if err.is_empty() { String::new() } else { format!(" (last error: {err})") }
        ));
    });
    if let Err(e) = spawned {
        off.running.store(false, Ordering::SeqCst);
        return Err(format!("cannot start the move thread: {e}"));
    }
    Ok(n)
}

/// Checks once a minute whether an automatic move is needed.
pub fn spawn_watcher(engine: Arc<EngineAdapter>, off: Arc<Offload>, log: impl Fn(String) + Send + Sync + Clone + 'static) {
    let _ = std::thread::Builder::new().name("offload-watch".into()).spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        if !off.auto.load(Ordering::Relaxed) || off.is_running() || off.target().trim().is_empty() {
            continue;
        }
        let p = engine.storage_pressure(false);
        if p.any() {
            let _ = start(&engine, &off, Mode::UntilRelieved(p), log.clone());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moves_and_verifies() {
        let base = std::env::temp_dir().join(format!("offload_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (work, target) = (base.join("work"), base.join("archive"));
        std::fs::create_dir_all(work.join("unknown")).unwrap();
        std::fs::create_dir_all(work.join("clean")).unwrap();
        let data = b"hello offload".to_vec();
        let sha = hex::encode_upper(Sha256::digest(&data));
        std::fs::write(work.join("unknown").join(format!("{sha}_a.exe")), &data).unwrap();
        // A file whose name claims another hash must not be deleted.
        let bad = "A".repeat(64);
        std::fs::write(work.join("clean").join(format!("{bad}_b.exe")), b"other").unwrap();
        let engine = EngineAdapter::new(Some(work.clone()), false, true, 1, true, true, 1, false, 1);
        let off = Arc::new(Offload::default());
        *off.target.write().unwrap() = target.to_string_lossy().into_owned();
        assert!(check_target(&engine, &work.join("x").to_string_lossy()).is_err());
        let n = start(&engine, &off, Mode::Categories(vec![]), |_| {}).unwrap();
        assert_eq!(n, 2);
        while off.is_running() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(off.moved.load(Ordering::Relaxed), 1);
        assert_eq!(off.failed.load(Ordering::Relaxed), 1);
        assert_eq!(std::fs::read(target.join("unknown").join(format!("{sha}_a.exe"))).unwrap(), data);
        assert!(!work.join("unknown").join(format!("{sha}_a.exe")).exists());
        assert!(work.join("clean").join(format!("{bad}_b.exe")).exists());
        assert!(!target.join("clean").join(format!("{bad}_b.exe.part")).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pressure_targets_the_full_quota() {
        let clean_only = Pressure { clean: true, shared: false, disk: false };
        assert!(clean_only.helped_by("clean"));
        assert!(!clean_only.helped_by("unknown"));
        let disk = Pressure { clean: false, shared: false, disk: true };
        assert!(disk.helped_by("unknown") && disk.helped_by("clean"));
        // Shared quota still at 70 % does not keep a clean-quota move going.
        let now = Pressure { clean: false, shared: true, disk: false };
        assert!(!now.still(&clean_only));
        assert!(MOVE_ORDER[0] == "clean" && MOVE_ORDER[4] == "unknown");
    }
}
