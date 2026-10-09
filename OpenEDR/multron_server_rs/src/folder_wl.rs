//! Folder whitelist done by the server: the analyst picks a folder on the server's own
//! disk (the VDS) in the dashboard, the server lists its file types and hashes the
//! chosen ones itself (streaming, 1 MB buffer, so memory stays flat however big the
//! files are). Nothing is uploaded from the browser. The hashes then go through the
//! normal bulk verdict path (dry run + confirmation in the dashboard).
//!
//! The work folder (multron_incoming) and the move target hold files from clients,
//! malware included, so they are never walked.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use sha2::{Digest, Sha256};

/// Upper bound for one folder (files listed or hashed).
pub const MAX_FILES: u64 = 200_000;

#[derive(Default)]
pub struct FolderJob {
    running: AtomicBool,
    stop: AtomicBool,
    total_files: AtomicU64,
    total_bytes: AtomicU64,
    done_files: AtomicU64,
    done_bytes: AtomicU64,
    unreadable: AtomicU64,
    /// Files skipped because they are larger than the size limit.
    too_large: AtomicU64,
    max_bytes: AtomicU64,
    path: Mutex<String>,
    error: Mutex<String>,
    started_at: Mutex<Option<String>>,
    finished_at: Mutex<Option<String>>,
    hashes: Mutex<Vec<String>>,
}

pub static JOB: LazyLock<FolderJob> = LazyLock::new(FolderJob::default);

impl FolderJob {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Unique SHA-256s of the last finished run.
    pub fn hashes(&self) -> Vec<String> {
        self.hashes.lock().unwrap().clone()
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "running": self.is_running(),
            "path": *self.path.lock().unwrap(),
            "totalFiles": self.total_files.load(Ordering::Relaxed),
            "totalBytes": self.total_bytes.load(Ordering::Relaxed),
            "doneFiles": self.done_files.load(Ordering::Relaxed),
            "doneBytes": self.done_bytes.load(Ordering::Relaxed),
            "unreadable": self.unreadable.load(Ordering::Relaxed),
            "tooLarge": self.too_large.load(Ordering::Relaxed),
            "maxMb": self.max_bytes.load(Ordering::Relaxed) / (1024 * 1024),
            "unique": self.hashes.lock().unwrap().len(),
            "error": *self.error.lock().unwrap(),
            "startedAt": *self.started_at.lock().unwrap(),
            "finishedAt": *self.finished_at.lock().unwrap(),
        })
    }
}

/// Folders that must never be whitelisted from (client uploads live there).
pub fn excluded_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for p in [crate::config::app_dir().join("multron_incoming")] {
        if let Ok(c) = std::fs::canonicalize(&p) {
            v.push(c);
        }
    }
    v
}

fn add_excluded(v: &mut Vec<PathBuf>, p: Option<&Path>) {
    if let Some(c) = p.and_then(|p| std::fs::canonicalize(p).ok()) {
        v.push(c);
    }
}

/// Lower-case extension ("" when none).
pub fn ext_of(path: &Path) -> String {
    path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).filter(|e| e.len() <= 12).unwrap_or_default()
}

/// Folder browser for the dashboard: sub-folders of `path`, or the drives / root when
/// `path` is empty.
pub fn list_dir(path: &str) -> Result<serde_json::Value, String> {
    let path = path.trim();
    if path.is_empty() {
        let mut roots = Vec::new();
        #[cfg(windows)]
        for c in b'A'..=b'Z' {
            let d = format!("{}:\\", c as char);
            if Path::new(&d).exists() {
                roots.push(d);
            }
        }
        #[cfg(not(windows))]
        roots.push("/".to_string());
        return Ok(serde_json::json!({ "path": "", "parent": null, "dirs": roots }));
    }
    let p = PathBuf::from(path);
    if !p.is_absolute() {
        return Err("use an absolute path, e.g. C:\\Program Files".into());
    }
    let rd = std::fs::read_dir(&p).map_err(|e| format!("{path}: {e}"))?;
    let mut dirs: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    dirs.sort_by_key(|d| d.to_lowercase());
    dirs.truncate(2000);
    Ok(serde_json::json!({
        "path": p.to_string_lossy(),
        "parent": p.parent().map(|x| x.to_string_lossy().into_owned()),
        "dirs": dirs,
    }))
}

/// Walks `root` (no symlinks / junctions, skips `excluded`), calling `f` for each file.
/// Stops after `MAX_FILES` files or when `stop` returns true.
fn walk(root: &Path, excluded: &[PathBuf], stop: &dyn Fn() -> bool, f: &mut dyn FnMut(&Path, u64)) -> u64 {
    let mut stack = vec![root.to_path_buf()];
    let mut n = 0u64;
    while let Some(dir) = stack.pop() {
        if stop() || n >= MAX_FILES {
            break;
        }
        if let Ok(c) = std::fs::canonicalize(&dir) {
            if excluded.iter().any(|x| c.starts_with(x)) {
                continue;
            }
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                f(&e.path(), len);
                n += 1;
                if n >= MAX_FILES {
                    break;
                }
            }
        }
    }
    n
}

fn check_root(path: &str, extra_excluded: &[Option<&Path>]) -> Result<(PathBuf, Vec<PathBuf>), String> {
    let root = PathBuf::from(path.trim());
    if !root.is_absolute() || !root.is_dir() {
        return Err(format!("{} is not a folder on this server", path.trim()));
    }
    let mut excluded = excluded_dirs();
    for p in extra_excluded {
        add_excluded(&mut excluded, *p);
    }
    let c = std::fs::canonicalize(&root).map_err(|e| e.to_string())?;
    if excluded.iter().any(|x| c.starts_with(x)) {
        return Err("this folder holds files uploaded by clients (malware included); it cannot be whitelisted".into());
    }
    Ok((root, excluded))
}

/// File types in a folder: extension -> files, bytes and files over `max_bytes`
/// (0 = no limit). Metadata only, no hashing.
pub fn scan_types(path: &str, max_bytes: u64, extra_excluded: &[Option<&Path>]) -> Result<serde_json::Value, String> {
    let (root, excluded) = check_root(path, extra_excluded)?;
    let mut by: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let n = walk(&root, &excluded, &|| false, &mut |p, len| {
        let e = by.entry(ext_of(p)).or_default();
        e.0 += 1;
        e.1 += len;
        if max_bytes > 0 && len > max_bytes {
            e.2 += 1;
        }
    });
    let mut types: Vec<serde_json::Value> = by
        .into_iter()
        .map(|(ext, (files, bytes, over))| serde_json::json!({ "ext": ext, "files": files, "bytes": bytes, "tooLarge": over }))
        .collect();
    types.sort_by(|a, b| b["files"].as_u64().cmp(&a["files"].as_u64()));
    Ok(serde_json::json!({ "path": root.to_string_lossy(), "files": n, "capped": n >= MAX_FILES, "types": types }))
}

fn sha256_file(path: &Path, buf: &mut [u8], stop: &AtomicBool) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let n = f.read(buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

/// Starts hashing the files of `exts` ("" = no extension) under `path` in the background.
/// Files larger than `max_bytes` (0 = no limit) are skipped and counted.
pub fn start(path: &str, exts: &[String], max_bytes: u64, extra_excluded: &[Option<&Path>], log: impl Fn(String) + Send + 'static) -> Result<(), String> {
    let (root, excluded) = check_root(path, extra_excluded)?;
    if exts.is_empty() {
        return Err("pick at least one file type".into());
    }
    let job = &*JOB;
    if job.running.swap(true, Ordering::SeqCst) {
        return Err("a folder is already being hashed".into());
    }
    job.stop.store(false, Ordering::Relaxed);
    for a in [&job.total_files, &job.total_bytes, &job.done_files, &job.done_bytes, &job.unreadable, &job.too_large] {
        a.store(0, Ordering::Relaxed);
    }
    job.max_bytes.store(max_bytes, Ordering::Relaxed);
    *job.path.lock().unwrap() = root.to_string_lossy().into_owned();
    job.error.lock().unwrap().clear();
    job.hashes.lock().unwrap().clear();
    *job.started_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
    *job.finished_at.lock().unwrap() = None;
    let exts: HashSet<String> = exts.iter().map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase()).collect();
    let spawned = std::thread::Builder::new().name("folder-whitelist".into()).spawn(move || {
        let job = &*JOB;
        // Pass 1: list, so the dashboard can show progress.
        let mut files: Vec<(PathBuf, u64)> = Vec::new();
        walk(&root, &excluded, &|| job.stop.load(Ordering::Relaxed), &mut |p, len| {
            if exts.contains(&ext_of(p)) {
                if max_bytes > 0 && len > max_bytes {
                    job.too_large.fetch_add(1, Ordering::Relaxed);
                } else {
                    files.push((p.to_path_buf(), len));
                }
            }
        });
        job.total_files.store(files.len() as u64, Ordering::Relaxed);
        job.total_bytes.store(files.iter().map(|f| f.1).sum(), Ordering::Relaxed);
        // Pass 2: hash.
        let mut buf = vec![0u8; 1 << 20];
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (p, len) in files {
            if job.stop.load(Ordering::Relaxed) {
                break;
            }
            match sha256_file(&p, &mut buf, &job.stop) {
                Some(h) => {
                    if seen.insert(h.clone()) {
                        out.push(h);
                    }
                }
                None if !job.stop.load(Ordering::Relaxed) => {
                    job.unreadable.fetch_add(1, Ordering::Relaxed);
                }
                None => {}
            }
            job.done_files.fetch_add(1, Ordering::Relaxed);
            job.done_bytes.fetch_add(len, Ordering::Relaxed);
        }
        if job.stop.load(Ordering::Relaxed) {
            *job.error.lock().unwrap() = "stopped".into();
        } else {
            *job.hashes.lock().unwrap() = out;
        }
        *job.finished_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
        job.running.store(false, Ordering::SeqCst);
        log(format!(
            "folder whitelist: hashed {} files in {} ({} unique, {} unreadable, {} over the size limit)",
            job.done_files.load(Ordering::Relaxed),
            job.path.lock().unwrap(),
            job.hashes.lock().unwrap().len(),
            job.unreadable.load(Ordering::Relaxed),
            job.too_large.load(Ordering::Relaxed)
        ));
    });
    if let Err(e) = spawned {
        job.running.store(false, Ordering::SeqCst);
        return Err(format!("cannot start: {e}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_chosen_types_and_skips_excluded() {
        let base = std::env::temp_dir().join(format!("fwl_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::create_dir_all(base.join("incoming")).unwrap();
        std::fs::write(base.join("a.exe"), b"hello").unwrap();
        std::fs::write(base.join("sub").join("b.DLL"), b"world").unwrap();
        std::fs::write(base.join("c.txt"), b"skip").unwrap();
        std::fs::write(base.join("incoming").join("evil.exe"), b"evil").unwrap();
        let inc = base.join("incoming");
        std::fs::write(base.join("big.exe"), vec![0u8; 2048]).unwrap();
        let t = scan_types(&base.to_string_lossy(), 1024, &[Some(inc.as_path())]).unwrap();
        assert_eq!(t["files"], 4);
        let exe = t["types"].as_array().unwrap().iter().find(|x| x["ext"] == "exe").unwrap().clone();
        assert_eq!(exe["tooLarge"], 1);
        assert!(check_root(&inc.to_string_lossy(), &[Some(inc.as_path())]).is_err());
        start(&base.to_string_lossy(), &["exe".into(), ".dll".into()], 1024, &[Some(inc.as_path())], |_| {}).unwrap();
        while JOB.is_running() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut h = JOB.hashes();
        h.sort();
        let mut want = vec![hex::encode(Sha256::digest(b"hello")), hex::encode(Sha256::digest(b"world"))];
        want.sort();
        assert_eq!(h, want);
        assert_eq!(JOB.status()["tooLarge"], 1);
        let _ = std::fs::remove_dir_all(&base);
    }
}
