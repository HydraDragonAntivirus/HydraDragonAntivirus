// Daemon mode: poll a directory, scan new/changed files, print hits.
// Run: cargo run --example daemon [watchDir]
// NOTE: std has no SHA-256, so unchanged files are skipped by (size, mtime).
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[link(name = "openedr_static")]
extern "C" {
    fn openedr_static_init(base_rules_dir: *const c_char) -> i32;
    fn openedr_static_scan_file(file_path: *const c_char) -> *mut c_char;
    fn openedr_static_free_string(s: *mut c_char);
}

fn scan_verdict(path: &Path) -> Option<(String, Option<String>)> {
    let s = path.to_str()?;
    let c_path = CString::new(s).ok()?;
    let ptr = unsafe { openedr_static_scan_file(c_path.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let json: serde_json::Value = unsafe {
        let text = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        openedr_static_free_string(ptr);
        serde_json::from_str(&text).ok()?
    };
    let verdict = json.get("verdict")?.as_str()?.to_string();
    let name = json
        .get("detections")?
        .as_array()?
        .first()?
        .get("name")?
        .as_str()
        .map(|n| n.to_string());
    Some((verdict, name))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

fn file_key(p: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(p).ok()?;
    let len = meta.len();
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    Some((len, mtime))
}

fn main() {
    const MAX_SIZE: u64 = 48 * 1024 * 1024;
    let flag: HashSet<&str> = ["Malicious", "Suspicious"].into_iter().collect();

    let watch = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs_fallback()
        });
    unsafe {
        openedr_static_init(std::ptr::null());
    }

    let mut seen: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut scanned = 0u64;
    let mut hits = 0u64;
    println!("[*] Watching {:?} - Ctrl+C to stop", watch);
    loop {
        let mut files = Vec::new();
        walk(&watch, &mut files);
        for p in files {
            let key = match file_key(&p) {
                Some(k) if k.0 > 0 && k.0 <= MAX_SIZE => k,
                _ => continue,
            };
            if seen.get(&p) == Some(&key) {
                continue;
            }
            seen.insert(p.clone(), key);
            match scan_verdict(&p) {
                Some((v, name)) => {
                    scanned += 1;
                    if flag.contains(v.as_str()) {
                        hits += 1;
                        println!("[!] {} :: {:?} :: {:?}", v, p, name);
                    }
                }
                None => eprintln!("[-] scan failed {:?}", p),
            }
        }
        println!("[...] scanned={} hits={}", scanned, hits);
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn dirs_fallback() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(|home| PathBuf::from(home).join("Downloads"))
        .unwrap_or_else(|_| PathBuf::from("."))
}
