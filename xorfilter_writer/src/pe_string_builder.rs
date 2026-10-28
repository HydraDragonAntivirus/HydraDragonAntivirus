//! High-speed Rust builder for PE String ML XorFilters (`pe_strings_benign.xf`
//! and `pe_strings_malicious.xf`).
//!
//! Specifically designed for:
//! 1. Full Benign Whitelist Coverage:
//!    - Hardcoded Multron Server Dynamic String Whitelist (`C:\Users\semae\OneDrive\Belgeler\stringwhitelist`,
//!      56.88M+ clean PE strings with `SHA256("pe\0" + s)[..8]` keys).
//!    - All `yarGen/dbs/good-strings-*.db` & `good-exports-*.db` databases (parts 1..9,
//!      `benign_data2`, `benign_apk`, `benign_javascript_data2`).
//!    - All `hydradragon/website/*WhiteList*.csv` files.
//! 2. Full Malicious Dataset Re-Harvesting (158,126+ malware samples):
//!    - Scans the entire `C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder`
//!      (158k+ malware samples) plus `yarGen/dbs/mal-strings-*.db` / `mal-exports-*.db`.
//!    - Enforces strict Whitelist Priority: ANY string present in Multron Server's
//!      56.88M dynamic whitelist OR in `pe_strings_benign.xf` is strictly excluded
//!      from `pe_strings_malicious.xf`.
//!
//! Uses only `std::thread::scope` (no `rayon`).

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use flate2::read::GzDecoder;
use hydradragonxorfilter::{build_bf32_from_keys, build_from_keys, key};
use sha2::{Digest, Sha256};

/// Hardcoded path to the Multron Server dynamic string whitelist directory.
pub const MULTRON_DYNAMIC_STRING_WHITELIST_DIR: &str =
    r"C:\Users\semae\OneDrive\Belgeler\stringwhitelist";

const MIN_STR_LEN: usize = 6;
const MAX_STR_LEN: usize = 160;
const MAX_FILE_READ_BYTES: usize = 2 * 1024 * 1024; // 2 MB cap per sample for fast harvesting
const NUM_SHARDS: usize = 256;

#[inline]
fn is_ident_byte(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

#[inline]
fn valid_string(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < MIN_STR_LEN || b.len() > MAX_STR_LEN {
        return false;
    }
    if b.iter().all(|c| c.is_ascii_whitespace()) {
        return false;
    }
    let first = b[0];
    if b.iter().all(|&c| c == first) {
        return false;
    }
    let alnum = b.iter().filter(|c| c.is_ascii_alphanumeric()).count();
    alnum >= 3
}

/// Multron Server's exact 64-bit key derivation (`multron_server_rs/src/string_wl.rs`):
/// `u64::from_le_bytes(SHA256(b"pe\0" || s.as_bytes())[..8])`
#[inline]
fn multron_pe_string_key(s: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"pe\0");
    h.update(s.as_bytes());
    let d = h.finalize();
    u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Load Multron Server's sorted `.u64` array into memory (`Vec<u64>`) so worker
/// threads can perform lock-free binary searches across all 56.88M keys.
fn load_multron_u64_whitelist() -> Vec<u64> {
    let dir = Path::new(MULTRON_DYNAMIC_STRING_WHITELIST_DIR);
    let meta_path = dir.join("whitelist.json");
    let Ok(meta_text) = std::fs::read_to_string(&meta_path) else {
        eprintln!(
            "[!] Multron whitelist.json not found at {}",
            meta_path.display()
        );
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&meta_text) else {
        return Vec::new();
    };
    let generation = v.get("generation").and_then(|x| x.as_u64()).unwrap_or(0);
    let u64_name = v
        .get("u64_file")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("strings-{generation}.u64"));
    let u64_path = dir.join(&u64_name);

    eprintln!(
        "[*] Loading Multron Server Dynamic Whitelist: {} (gen={})...",
        u64_path.display(),
        generation
    );
    let Ok(mut f) = File::open(&u64_path) else {
        eprintln!("[!] Failed to open {}", u64_path.display());
        return Vec::new();
    };
    let len_bytes = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let count = len_bytes / 8;
    let mut keys: Vec<u64> = vec![0u64; count];
    let byte_slice =
        unsafe { std::slice::from_raw_parts_mut(keys.as_mut_ptr() as *mut u8, count * 8) };
    if let Err(e) = f.read_exact(byte_slice) {
        eprintln!("[!] Failed reading {}: {}", u64_path.display(), e);
        return Vec::new();
    }
    eprintln!(
        "    -> Loaded {} sorted u64 keys ({:.1} MB) from Multron Server whitelist",
        keys.len(),
        (keys.len() * 8) as f64 / (1024.0 * 1024.0)
    );
    keys
}

/// Stream JSON string keys from a gzipped yarGen `.db` file (`{"str": count, ...}`)
/// without allocating a giant HashMap in memory.
fn stream_yargen_gz_db<F>(path: &Path, mut on_string: F) -> usize
where
    F: FnMut(&str),
{
    let Ok(file) = File::open(path) else {
        return 0;
    };
    let gz = GzDecoder::new(BufReader::with_capacity(1 << 20, file));
    let mut reader = BufReader::with_capacity(1 << 20, gz);
    let mut buf = [0u8; 65536];
    let mut in_str = false;
    let mut escaped = false;
    let mut cur = Vec::with_capacity(256);
    let mut count = 0usize;

    loop {
        let Ok(n) = reader.read(&mut buf) else {
            break;
        };
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            if !in_str {
                if b == b'"' {
                    in_str = true;
                    escaped = false;
                    cur.clear();
                }
            } else if escaped {
                let decoded = match b {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'/' => b'/',
                    _ => b,
                };
                if cur.len() <= MAX_STR_LEN + 16 {
                    cur.push(decoded);
                }
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
                if (MIN_STR_LEN..=MAX_STR_LEN).contains(&cur.len()) {
                    if let Ok(s) = std::str::from_utf8(&cur) {
                        if valid_string(s) {
                            on_string(s);
                            count += 1;
                        }
                    }
                }
            } else if cur.len() <= MAX_STR_LEN + 16 {
                cur.push(b);
            }
        }
    }
    count
}

/// Extract printable ASCII and UTF-16LE strings (`len >= 6..=160`) from raw file bytes.
fn extract_pe_strings<F>(bytes: &[u8], mut sink: F)
where
    F: FnMut(&str),
{
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) && (i - start) < MAX_STR_LEN {
                i += 1;
            }
            let len = i - start;
            if len >= MIN_STR_LEN {
                if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                    if valid_string(s) {
                        sink(s);
                    }
                }
            }
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    let mut buf = String::with_capacity(MAX_STR_LEN);
    for align in 0..2 {
        if bytes.len() < align + MIN_STR_LEN * 2 {
            continue;
        }
        let mut j = align;
        while j + 1 < bytes.len() {
            let lo = bytes[j];
            let hi = bytes[j + 1];
            if hi == 0 && is_ident_byte(lo) {
                buf.clear();
                while j + 1 < bytes.len()
                    && bytes[j + 1] == 0
                    && is_ident_byte(bytes[j])
                    && buf.len() < MAX_STR_LEN
                {
                    buf.push(bytes[j] as char);
                    j += 2;
                }
                if buf.len() >= MIN_STR_LEN && valid_string(&buf) {
                    sink(&buf);
                }
                while j + 1 < bytes.len() && bytes[j + 1] == 0 && is_ident_byte(bytes[j]) {
                    j += 2;
                }
            } else {
                j += 2;
            }
        }
    }
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            collect_files_recursive(&p, out);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .max(1)
}

pub fn run_build_pe_string_ml() {
    let t0 = Instant::now();
    let num_threads = worker_count();
    let repo_root = PathBuf::from(r"c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus");
    let yargen_dbs = repo_root.join("yarGen").join("dbs");
    let website_dir = repo_root.join("hydradragon").join("website");
    let out_dir = repo_root.join("hydradragon_ml_models");

    eprintln!("========================================================================");
    eprintln!(
        "  HydraDragon PE String ML Full Filter Builder (std::thread x{} + Multron)",
        num_threads
    );
    eprintln!("========================================================================");

    // -------------------------------------------------------------------------
    // STEP 1: Load Multron Server Dynamic Whitelist (56.88M keys)
    // -------------------------------------------------------------------------
    let multron_u64 = load_multron_u64_whitelist();

    // -------------------------------------------------------------------------
    // STEP 2: Collect ALL Benign Databases (`good-strings-*.db` & `good-exports-*.db` + Website CSVs)
    // -------------------------------------------------------------------------
    let mut good_db_paths: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&yargen_dbs) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if (name.starts_with("good-strings-") || name.starts_with("good-exports-"))
                    && name.ends_with(".db")
                {
                    good_db_paths.push(p);
                }
            }
        }
    }
    good_db_paths.sort();
    eprintln!(
        "[*] Streaming {} yarGen benign string/export databases across {} std threads...",
        good_db_paths.len(),
        num_threads
    );

    let db_idx = AtomicUsize::new(0);
    let ben_db_out: Mutex<Vec<u64>> = Mutex::new(Vec::with_capacity(30_000_000));
    std::thread::scope(|s| {
        for _ in 0..num_threads.min(good_db_paths.len().max(1)) {
            let paths = &good_db_paths;
            let idx_ref = &db_idx;
            let out_ref = &ben_db_out;
            s.spawn(move || {
                loop {
                    let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= paths.len() {
                        break;
                    }
                    let db_path = &paths[i];
                    let mut local = Vec::with_capacity(500_000);
                    let cnt = stream_yargen_gz_db(db_path, |st| {
                        local.push(key(st));
                    });
                    local.sort_unstable();
                    local.dedup();
                    eprintln!(
                        "    [+] {:<42} -> {:>9} strings ({:>9} unique keys)",
                        db_path.file_name().unwrap().to_string_lossy(),
                        cnt,
                        local.len()
                    );
                    out_ref.lock().unwrap().append(&mut local);
                }
            });
        }
    });

    let mut ben_keys = ben_db_out.into_inner().unwrap();

    // Also include Website CSV Whitelists
    if let Ok(entries) = std::fs::read_dir(&website_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.to_ascii_lowercase().contains("whitelist") && name.ends_with(".csv") {
                    if let Ok(f) = File::open(&p) {
                        let r = BufReader::new(f);
                        let mut c = 0usize;
                        for line in r.lines().map_while(Result::ok) {
                            for token in line.split(',') {
                                let t = token.trim().trim_matches('"').trim_matches('\'');
                                if valid_string(t) {
                                    ben_keys.push(key(t));
                                    c += 1;
                                }
                            }
                        }
                        eprintln!("    [+] Website CSV {:<30} -> {:>9} entries", name, c);
                    }
                }
            }
        }
    }

    eprintln!(
        "[*] Sorting and deduplicating {} raw benign keys...",
        ben_keys.len()
    );
    ben_keys.sort_unstable();
    ben_keys.dedup();
    eprintln!(
        "    -> Total unique yarGen + Website benign keys: {} (plus {} Multron Server dynamic keys)",
        ben_keys.len(),
        multron_u64.len()
    );

    // Build `pe_strings_benign.xf` (BinaryFuse16)
    let ben_xf_path = out_dir.join("pe_strings_benign.xf");
    eprintln!(
        "[*] Building BinaryFuse16 filter -> {} ...",
        ben_xf_path.display()
    );
    let ben_xf_bytes =
        build_from_keys(ben_keys.clone()).expect("Failed to build pe_strings_benign.xf");
    std::fs::write(&ben_xf_path, &ben_xf_bytes).expect("Failed to write pe_strings_benign.xf");
    eprintln!(
        "    -> Wrote pe_strings_benign.xf: {:.2} MB ({} keys)",
        ben_xf_bytes.len() as f64 / (1024.0 * 1024.0),
        ben_keys.len()
    );

    // -------------------------------------------------------------------------
    // STEP 3: Harvest Malicious Strings from ALL 158,126+ Malware Samples + DBs
    // -------------------------------------------------------------------------
    let is_whitelisted = |s: &str, xk: u64| -> bool {
        if ben_keys.binary_search(&xk).is_ok() {
            return true;
        }
        if !multron_u64.is_empty() {
            let mk = multron_pe_string_key(s);
            if multron_u64.binary_search(&mk).is_ok() {
                return true;
            }
        }
        false
    };

    // 3a. Collect known malicious strings from `yarGen/dbs/mal-strings-*.db` & `mal-exports-*.db`
    let mut mal_db_paths: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&yargen_dbs) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if (name.starts_with("mal-strings-") || name.starts_with("mal-exports-"))
                    && name.ends_with(".db")
                {
                    mal_db_paths.push(p);
                }
            }
        }
    }
    mal_db_paths.sort();

    eprintln!(
        "[*] Streaming {} yarGen malicious string/export DBs with strict Multron + Benign whitelist filtering...",
        mal_db_paths.len()
    );
    let mal_db_idx = AtomicUsize::new(0);
    let mal_db_out: Mutex<Vec<u64>> = Mutex::new(Vec::with_capacity(15_000_000));
    std::thread::scope(|s| {
        for _ in 0..num_threads.min(mal_db_paths.len().max(1)) {
            let paths = &mal_db_paths;
            let idx_ref = &mal_db_idx;
            let out_ref = &mal_db_out;
            s.spawn(move || {
                loop {
                    let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= paths.len() {
                        break;
                    }
                    let db_path = &paths[i];
                    let mut kept = Vec::with_capacity(500_000);
                    let mut filtered_wl = 0usize;
                    stream_yargen_gz_db(db_path, |st| {
                        let xk = key(st);
                        if is_whitelisted(st, xk) {
                            filtered_wl += 1;
                        } else {
                            kept.push(xk);
                        }
                    });
                    kept.sort_unstable();
                    kept.dedup();
                    eprintln!(
                        "    [+] {:<42} -> kept {:>9} mal keys (removed {:>8} whitelisted)",
                        db_path.file_name().unwrap().to_string_lossy(),
                        kept.len(),
                        filtered_wl
                    );
                    out_ref.lock().unwrap().append(&mut kept);
                }
            });
        }
    });

    let mut final_mal_keys = mal_db_out.into_inner().unwrap();

    // 3b. Scan the ENTIRE 158,126+ malware corpus on disk (`datamaliciousorder` + JS + APK)
    let malware_dirs = [
        PathBuf::from(r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder"),
        PathBuf::from(r"D:\virusler\malicious_javascript_data2"),
        PathBuf::from(r"C:\Users\semae\OneDrive\Belgeler\malicious_apk"),
    ];
    let mut malware_files: Vec<PathBuf> = Vec::with_capacity(180_000);
    for d in &malware_dirs {
        if d.exists() {
            let before = malware_files.len();
            collect_files_recursive(d, &mut malware_files);
            eprintln!(
                "[*] Found {:>7} malware samples in {}",
                malware_files.len() - before,
                d.display()
            );
        }
    }
    eprintln!(
        "[*] Total raw malware files to harvest: {}",
        malware_files.len()
    );

    let shards: Vec<Mutex<Vec<u64>>> = (0..NUM_SHARDS)
        .map(|_| Mutex::new(Vec::with_capacity(250_000)))
        .collect();

    let next_chunk = AtomicUsize::new(0);
    let processed = AtomicUsize::new(0);
    let total_files = malware_files.len();
    let chunk_size = 512usize;

    std::thread::scope(|s| {
        for _ in 0..num_threads {
            let files_ref = &malware_files;
            let shards_ref = &shards;
            let next_ref = &next_chunk;
            let proc_ref = &processed;
            s.spawn(move || {
                let mut shard_bufs: Vec<Vec<u64>> =
                    (0..NUM_SHARDS).map(|_| Vec::with_capacity(512)).collect();
                let mut raw_buf = vec![0u8; MAX_FILE_READ_BYTES];
                let mut file_keys = Vec::with_capacity(2048);

                loop {
                    let start = next_ref.fetch_add(chunk_size, Ordering::Relaxed);
                    if start >= files_ref.len() {
                        break;
                    }
                    let end = (start + chunk_size).min(files_ref.len());
                    let chunk = &files_ref[start..end];

                    for path in chunk {
                        let Ok(mut f) = File::open(path) else {
                            continue;
                        };
                        let mut total_read = 0usize;
                        while total_read < MAX_FILE_READ_BYTES {
                            match f.read(&mut raw_buf[total_read..]) {
                                Ok(0) => break,
                                Ok(n) => total_read += n,
                                Err(_) => break,
                            }
                        }
                        if total_read < MIN_STR_LEN {
                            continue;
                        }

                        file_keys.clear();
                        extract_pe_strings(&raw_buf[..total_read], |st| {
                            let xk = key(st);
                            if !is_whitelisted(st, xk) {
                                file_keys.push(xk);
                            }
                        });

                        file_keys.sort_unstable();
                        file_keys.dedup();

                        for &xk in &file_keys {
                            shard_bufs[(xk as usize) & (NUM_SHARDS - 1)].push(xk);
                        }
                    }

                    for (idx, local_vec) in shard_bufs.iter_mut().enumerate() {
                        if !local_vec.is_empty() {
                            let mut guard = shards_ref[idx].lock().unwrap();
                            guard.extend_from_slice(local_vec);
                            local_vec.clear();
                        }
                    }

                    let done = proc_ref.fetch_add(chunk.len(), Ordering::Relaxed) + chunk.len();
                    if done % 10240 < chunk_size || done >= total_files {
                        eprintln!(
                            "    [harvest] {:>6} / {:>6} malware files processed ({:.1}%)...",
                            done.min(total_files),
                            total_files,
                            (done.min(total_files) as f64 / total_files.max(1) as f64) * 100.0
                        );
                    }
                }
            });
        }
    });

    eprintln!("[*] Reducing 256 shards (keeping strings shared by >= 2 malware samples)...");
    let shard_idx = AtomicUsize::new(0);
    let reduced_out: Mutex<(Vec<u64>, usize, usize)> =
        Mutex::new((Vec::with_capacity(10_000_000), 0, 0));

    std::thread::scope(|s| {
        for _ in 0..num_threads {
            let shards_ref = &shards;
            let idx_ref = &shard_idx;
            let out_ref = &reduced_out;
            s.spawn(move || {
                let mut thread_kept = Vec::new();
                let mut thread_uniq = 0usize;
                let mut thread_multi = 0usize;
                loop {
                    let idx = idx_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= shards_ref.len() {
                        break;
                    }
                    let mut v = std::mem::take(&mut *shards_ref[idx].lock().unwrap());
                    v.sort_unstable();
                    let mut i = 0;
                    while i < v.len() {
                        let k = v[i];
                        let mut j = i + 1;
                        while j < v.len() && v[j] == k {
                            j += 1;
                        }
                        thread_uniq += 1;
                        if (j - i) >= 2 {
                            thread_kept.push(k);
                            thread_multi += 1;
                        }
                        i = j;
                    }
                }
                let mut guard = out_ref.lock().unwrap();
                guard.0.append(&mut thread_kept);
                guard.1 += thread_uniq;
                guard.2 += thread_multi;
            });
        }
    });

    let (mut harvested_keys, total_unique_raw, total_multi_sample) =
        reduced_out.into_inner().unwrap();
    final_mal_keys.append(&mut harvested_keys);

    eprintln!(
        "    -> Raw corpus unique non-whitelisted strings: {} (shared by >=2 malware files: {})",
        total_unique_raw, total_multi_sample
    );

    final_mal_keys.sort_unstable();
    final_mal_keys.dedup();
    eprintln!(
        "    -> Final combined unique malicious string keys: {}",
        final_mal_keys.len()
    );

    // Build `pe_strings_malicious.xf` (BinaryFuse32)
    let mal_xf_path = out_dir.join("pe_strings_malicious.xf");
    eprintln!(
        "[*] Building BinaryFuse32 filter -> {} ...",
        mal_xf_path.display()
    );
    let mal_xf_bytes = build_bf32_from_keys(final_mal_keys.clone())
        .expect("Failed to build pe_strings_malicious.xf");
    std::fs::write(&mal_xf_path, &mal_xf_bytes).expect("Failed to write pe_strings_malicious.xf");
    eprintln!(
        "    -> Wrote pe_strings_malicious.xf: {:.2} MB ({} keys)",
        mal_xf_bytes.len() as f64 / (1024.0 * 1024.0),
        final_mal_keys.len()
    );

    // Sync to all engine model directories
    let sync_dirs = [
        repo_root.join("OpenEDR").join("openedr_static").join("models"),
        repo_root.join("OpenMalwareScannerPortable").join("models"),
        repo_root
            .join("OpenMalwareScannerPortable")
            .join("xorfilter_rules"),
    ];
    for d in &sync_dirs {
        if d.exists() {
            let _ = std::fs::write(d.join("pe_strings_benign.xf"), &ben_xf_bytes);
            let _ = std::fs::write(d.join("pe_strings_malicious.xf"), &mal_xf_bytes);
            eprintln!("    [sync] Updated {}", d.display());
        }
    }

    eprintln!(
        "[+] Completed full PE String ML filter build in {:.1}s!",
        t0.elapsed().as_secs_f64()
    );
}
