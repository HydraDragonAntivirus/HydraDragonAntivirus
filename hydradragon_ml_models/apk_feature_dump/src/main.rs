//! apk_feature_dump — APK ML features with the engine's own extractor.
//!
//!   apk_feature_dump <malicious_dir> <benign_dir> <out.csv> [max_per_class]
//!   apk_feature_dump @<malicious.lst> @<benign.lst> <out.csv> [max_per_class]
//!
//! Uses openedr_static's `apk_tree_features`, so the 58 features train_apk_lgbm.py learns from
//! are byte for byte what the engine computes at scan time:
//! - 0..23: Frozen DEX & Manifest baseline
//! - 24..30: Native ELF architectures (.so) and imported/exported symbols
//! - 31..37: Manifest high-risk capability permissions
//! - 38..46: Dalvik sensitive API calls (reflection, crypto, exec, sms, device ID)
//! - 47..51: Packaging, assets, protector anomalies
//! - 52..57: XOR-filter String ML threat density & hit metrics
//!
//! Pure standard library parallelism (no rayon), 64 MB thread stacks.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use openedr_static::apk::{apk_tree_features, APK_TREE_FEATURE_COUNT, APK_TREE_FEATURE_NAMES};

fn walk(dir: &Path, max: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let name = p.to_string_lossy().to_ascii_lowercase();
                if name.ends_with(".apk") || name.ends_with(".zip") {
                    out.push(p);
                    if out.len() >= max {
                        return out;
                    }
                }
            }
        }
    }
    out
}

/// Files of a folder (`dir`) or of a list file (`@list`), at most `max`.
fn inputs(arg: &str, max: usize) -> Vec<PathBuf> {
    match arg.strip_prefix('@') {
        Some(list) => {
            let text = std::fs::read_to_string(list).unwrap_or_else(|e| {
                eprintln!("cannot read file list {list}: {e}");
                std::process::exit(2);
            });
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .take(max)
                .collect()
        }
        None => walk(Path::new(arg), max),
    }
}

/// Stack size for worker threads. APK ZIP parsing & deobfuscated extraction require ample stack space.
const STACK: usize = 64 * 1024 * 1024;

fn extract(files: &[PathBuf], label: u8) -> Vec<(u8, String, [f32; APK_TREE_FEATURE_COUNT])> {
    if files.is_empty() {
        return Vec::new();
    }
    let total = files.len();
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .min(total)
        .max(1);

    let next_idx = Arc::new(AtomicUsize::new(0));
    let done_count = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<(u8, String, [f32; APK_TREE_FEATURE_COUNT])>>> =
        Arc::new(Mutex::new(Vec::with_capacity(total)));
    let files_arc = Arc::new(files.to_vec());

    let mut handles = Vec::with_capacity(num_threads);
    for _ in 0..num_threads {
        let next_ref = Arc::clone(&next_idx);
        let done_ref = Arc::clone(&done_count);
        let res_ref = Arc::clone(&results);
        let f_ref = Arc::clone(&files_arc);

        let handle = std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(move || {
                let mut local = Vec::with_capacity(512);
                loop {
                    let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= total {
                        break;
                    }
                    let p = &f_ref[idx];
                    let n = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % 500 == 0 || n == total {
                        eprintln!("  label {label}: {n}/{total}");
                    }
                    let Ok(bytes) = std::fs::read(p) else { continue };
                    let Ok(Some(f)) = std::panic::catch_unwind(|| apk_tree_features(&bytes)) else {
                        continue;
                    };
                    local.push((label, p.display().to_string(), f));
                    if local.len() >= 512 {
                        res_ref.lock().unwrap().append(&mut local);
                    }
                }
                if !local.is_empty() {
                    res_ref.lock().unwrap().append(&mut local);
                }
            })
            .expect("spawn worker thread");
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    let mut guard = results.lock().unwrap();
    std::mem::take(&mut *guard)
}

fn main() {
    // Enable the Multron disk whitelist during training extraction:
    openedr_static::ml::pe_string_ml::enable_multron_training_whitelist();
    let worker = std::thread::Builder::new().stack_size(STACK).spawn(run).expect("work thread");
    if worker.join().is_err() {
        std::process::exit(1);
    }
}

fn run() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("usage: apk_feature_dump <malicious_dir|@list> <benign_dir|@list> <out.csv> [max_per_class]");
        std::process::exit(2);
    }
    std::panic::set_hook(Box::new(|_| {})); // corrupted files skip quietly
    let max = a.get(4).and_then(|v| v.parse().ok()).filter(|&m: &usize| m > 0).unwrap_or(usize::MAX);
    let mal = inputs(&a[1], max);
    let ben = inputs(&a[2], max);
    eprintln!("[+] {} malicious, {} benign files", mal.len(), ben.len());
    let mut rows = extract(&mal, 1);
    rows.extend(extract(&ben, 0));

    let mut w = std::io::BufWriter::new(std::fs::File::create(&a[3]).expect("cannot create output"));
    let mut header = String::from("label,path");
    for name in &APK_TREE_FEATURE_NAMES {
        header.push(',');
        header.push_str(name);
    }
    writeln!(w, "{header}").unwrap();
    for (label, path, f) in &rows {
        let vals: Vec<String> = f.iter().map(|v| v.to_string()).collect();
        writeln!(w, "{label},\"{}\",{}", path.replace('"', "'"), vals.join(",")).unwrap();
    }
    w.flush().unwrap();
    let m = rows.iter().filter(|r| r.0 == 1).count();
    eprintln!("[+] wrote {} rows ({} malicious, {} benign; rejected files skipped) to {}", rows.len(), m, rows.len() - m, a[3]);
}
