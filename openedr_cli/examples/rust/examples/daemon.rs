use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use openedr_sdk_example::{default_portable_dir, OpenEdrScanner};

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

fn dirs_fallback() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(|home| PathBuf::from(home).join("Downloads"))
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn main() {
    const MAX_SIZE: u64 = 48 * 1024 * 1024;
    let flag: HashSet<&str> = ["Malicious", "Suspicious"].into_iter().collect();

    let watch = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(dirs_fallback);
    let portable = default_portable_dir();
    let dll = portable.join("openedr_static.dll");
    let scanner = match OpenEdrScanner::load(&dll, Some(&portable)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {e}");
            return;
        }
    };

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
            match scanner.scan_file(&p) {
                Ok(raw) => {
                    scanned += 1;
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                        let verdict = json
                            .get("verdict")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if flag.contains(verdict) {
                            hits += 1;
                            let name = json
                                .get("detections")
                                .and_then(|d| d.as_array())
                                .and_then(|a| a.first())
                                .and_then(|d| d.get("name"))
                                .and_then(|n| n.as_str());
                            println!("[!] {verdict} :: {p:?} :: {name:?}");
                        }
                    }
                }
                Err(_) => eprintln!("[-] scan failed {p:?}"),
            }
        }
        println!("[...] scanned={scanned} hits={hits}");
        std::thread::sleep(Duration::from_secs(2));
    }
}
