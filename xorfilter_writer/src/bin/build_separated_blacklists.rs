use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use hydradragonxorfilter::{build_bf32_from_keys, key, XorFilter};

const ZERO_SIZE_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";
const ZERO_SIZE_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
const ZERO_SIZE_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[inline(always)]
fn is_hex_char(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

#[inline(always)]
fn extract_valid_hex(line: &[u8]) -> Option<&str> {
    let mut s = line;
    while let Some((&first, rest)) = s.split_first() {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    if s.is_empty() || s[0] == b'#' {
        return None;
    }
    let token = if let Some(pos) = s.iter().position(|&b| b == b' ' || b == b',' || b == b':' || b == b'\t' || b == b'|') {
        &s[..pos]
    } else {
        s
    };
    let len = token.len();
    if len != 32 && len != 40 && len != 64 {
        return None;
    }
    if !token.iter().all(|&b| is_hex_char(b)) {
        return None;
    }
    std::str::from_utf8(token).ok()
}

fn load_whitelist_keys(root: &Path) -> HashSet<u64> {
    let mut set = HashSet::with_capacity(3_000_000);
    let allblooms = root.join("allblooms");
    let wl_files = [
        allblooms.join("whitelist").join("benign_sha256.txt"),
        allblooms.join("whitelist").join("RDS_2026.09.1_modern_minimal_delta_sha256.txt"),
        allblooms.join("purged_sha256_false_positives.txt"),
        allblooms.join("purged_md5_false_positives.txt"),
    ];

    for wf in &wl_files {
        if !wf.is_file() {
            continue;
        }
        println!("    - Whitelist file: {}", wf.file_name().unwrap().to_string_lossy());
        if let Ok(f) = File::open(wf) {
            let mut reader = BufReader::with_capacity(512 * 1024, f);
            let mut buf = Vec::with_capacity(128);
            while reader.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
                if let Some(h) = extract_valid_hex(&buf) {
                    if !h.eq_ignore_ascii_case(ZERO_SIZE_SHA256) && !h.eq_ignore_ascii_case(ZERO_SIZE_MD5) {
                        set.insert(key(h));
                    }
                }
                buf.clear();
            }
        }
    }

    // Dataset cache benign entries (SHA-256)
    let cache_file = root.join("hydradragon_ml_models").join("dataset_hash_cache.jsonl");
    if cache_file.is_file() {
        println!("    - Dataset benign cache: dataset_hash_cache.jsonl");
        if let Ok(f) = File::open(&cache_file) {
            let mut reader = BufReader::with_capacity(512 * 1024, f);
            let mut buf = String::with_capacity(512);
            while reader.read_line(&mut buf).unwrap_or(0) > 0 {
                if buf.contains("\"s\":0") {
                    buf.clear();
                    continue;
                }
                let is_benign = buf.contains("benign") || buf.contains("clean") || buf.contains("data2") || buf.contains("normal");
                if is_benign {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&buf) {
                        if let Some(h) = v.get("h").and_then(|h| h.as_str()) {
                            let clean = h.trim();
                            if clean.len() == 64 && !clean.eq_ignore_ascii_case(ZERO_SIZE_SHA256) {
                                set.insert(key(clean));
                            }
                        }
                    }
                }
                buf.clear();
            }
        }
    }

    set
}

fn load_overrides(root: &Path) -> HashSet<u64> {
    let mut set = HashSet::new();
    let override_file = root.join("analyst_signatures").join("blacklist_removals.jsonl");
    if !override_file.is_file() {
        return set;
    }
    if let Ok(f) = File::open(&override_file) {
        let mut reader = BufReader::with_capacity(64 * 1024, f);
        let mut buf = String::with_capacity(256);
        while reader.read_line(&mut buf).unwrap_or(0) > 0 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&buf) {
                let removed = v.get("removed").and_then(|r| r.as_bool()).unwrap_or(true);
                if let Some(h) = v.get("hash").and_then(|h| h.as_str()) {
                    let clean = h.trim();
                    if removed {
                        set.insert(key(clean));
                    } else {
                        set.remove(&key(clean));
                    }
                }
            }
            buf.clear();
        }
    }
    set
}

fn build_single_filter(
    name: &str,
    keys: Vec<u64>,
    sample_hash: &str,
    zero_hash: &str,
    out_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n[*] Compiling BinaryFuse32 for {} ({} raw keys)...", name, keys.len());
    let t0 = Instant::now();
    let bytes = build_bf32_from_keys(keys)
        .map_err(|e| format!("Failed to build {} filter: {e}", name))?;

    fs::create_dir_all(out_path.parent().unwrap())?;
    fs::write(out_path, &bytes)?;

    let elapsed = t0.elapsed().as_secs_f64();
    let sz_mb = bytes.len() as f64 / (1024.0 * 1024.0);
    println!("    [+] Built {}: {} bytes ({:.2} MB) in {:.2}s", name, bytes.len(), sz_mb, elapsed);
    println!("    [+] Saved to: {}", out_path.display());

    // Verify
    let f = XorFilter::from_bytes(&bytes).ok_or("Failed to deserialize filter")?;
    println!("    - Total distinct keys: {}", f.len());
    if !sample_hash.is_empty() {
        let hit = f.contains(sample_hash);
        println!("    - Sample check ({}): {} [PASS: {}]", &sample_hash[..16.min(sample_hash.len())], hit, hit);
        assert!(hit, "Sample hash must be present");
    }
    let zero_hit = f.contains(zero_hash);
    println!("    - 0-size empty check: {} [PASS: {}]", zero_hit, !zero_hit);
    assert!(!zero_hit, "0-size empty hash must NOT be in filter");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_total = Instant::now();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let allblooms = root.join("allblooms");
    let rules_dir = root.join("OpenMalwareScannerPortable").join("xorfilter_rules");

    println!("======================================================================");
    println!(" HydraDragon Antivirus - Separated Blacklist Builder (BinaryFuse32)");
    println!(" Targets: malicious_sha256.xf | malicious_sha1.xf | malicious_md5.xf");
    println!(" 0-Size Safety: ACTIVE | Whitelist Priority (P0): ACTIVE");
    println!(" Archive Safety: C:\\viruskov_archive IS UNTOUCHED");
    println!("======================================================================");

    let zero_keys: HashSet<u64> = [
        key(ZERO_SIZE_MD5),
        key(ZERO_SIZE_SHA1),
        key(ZERO_SIZE_SHA256),
    ].into_iter().collect();

    // 1. Whitelist & Overrides
    println!("[*] Step 1: Loading Whitelist & Analyst Overrides...");
    let whitelist_keys = load_whitelist_keys(&root);
    println!("    [+] Loaded {} whitelist keys", whitelist_keys.len());
    let override_keys = load_overrides(&root);
    println!("    [+] Loaded {} analyst override keys", override_keys.len());

    // 2. Separate key vectors
    let mut sha256_keys: Vec<u64> = Vec::with_capacity(2_000_000);
    let mut sha1_keys: Vec<u64> = Vec::with_capacity(1_500_000);
    let mut md5_keys: Vec<u64> = Vec::with_capacity(45_000_000);

    let mut sample_sha256 = String::new();
    let mut sample_sha1 = String::new();
    let mut sample_md5 = String::new();

    let mut zero_dropped = 0usize;
    let mut wl_dropped = 0usize;
    let mut override_dropped = 0usize;

    // A. SHA-256 Sources
    let sha256_files = vec![
        allblooms.join("sha256.txt"),
        allblooms.join("sha256_db"),
        allblooms.join("sha256amnestytech"),
        allblooms.join("iocemotet"),
        allblooms.join("virussign"),
        allblooms.join("samplesstalkware"),
        allblooms.join("eset"),
    ];

    println!("\n[*] Step 2A: Reading SHA-256 malicious lists...");
    for tf in &sha256_files {
        if !tf.is_file() { continue; }
        let t0 = Instant::now();
        let f = File::open(tf)?;
        let mut reader = BufReader::with_capacity(512 * 1024, f);
        let mut line_buf = Vec::with_capacity(128);
        let mut cnt = 0usize;
        while reader.read_until(b'\n', &mut line_buf)? > 0 {
            if let Some(h) = extract_valid_hex(&line_buf) {
                if h.len() == 64 {
                    let k = key(h);
                    if zero_keys.contains(&k) { zero_dropped += 1; line_buf.clear(); continue; }
                    if whitelist_keys.contains(&k) { wl_dropped += 1; line_buf.clear(); continue; }
                    if override_keys.contains(&k) { override_dropped += 1; line_buf.clear(); continue; }
                    if sample_sha256.is_empty() { sample_sha256 = h.to_ascii_lowercase(); }
                    sha256_keys.push(k);
                    cnt += 1;
                }
            }
            line_buf.clear();
        }
        println!("    - {:<22} ({} entries in {:.2}s)", tf.file_name().unwrap().to_string_lossy(), cnt, t0.elapsed().as_secs_f64());
    }

    // Dataset cache malicious SHA-256
    let cache_file = root.join("hydradragon_ml_models").join("dataset_hash_cache.jsonl");
    if cache_file.is_file() {
        let t0 = Instant::now();
        let f = File::open(&cache_file)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, f);
        let mut buf = String::with_capacity(512);
        let mut cnt = 0usize;
        while reader.read_line(&mut buf)? > 0 {
            if buf.contains("\"s\":0") { zero_dropped += 1; buf.clear(); continue; }
            let is_benign = buf.contains("benign") || buf.contains("clean") || buf.contains("data2") || buf.contains("normal");
            if !is_benign {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&buf) {
                    if let Some(h) = v.get("h").and_then(|h| h.as_str()) {
                        let clean = h.trim();
                        if clean.len() == 64 && !clean.eq_ignore_ascii_case(ZERO_SIZE_SHA256) {
                            let k = key(clean);
                            if !whitelist_keys.contains(&k) && !override_keys.contains(&k) {
                                sha256_keys.push(k);
                                cnt += 1;
                            } else {
                                wl_dropped += 1;
                            }
                        }
                    }
                }
            }
            buf.clear();
        }
        println!("    - dataset_hash_cache.jsonl ({} entries in {:.2}s)", cnt, t0.elapsed().as_secs_f64());
    }

    // B. SHA-1 Sources
    println!("\n[*] Step 2B: Reading SHA-1 malicious lists...");
    let sha1_file = allblooms.join("sha1.txt");
    if sha1_file.is_file() {
        let t0 = Instant::now();
        let f = File::open(&sha1_file)?;
        let mut reader = BufReader::with_capacity(512 * 1024, f);
        let mut line_buf = Vec::with_capacity(128);
        let mut cnt = 0usize;
        while reader.read_until(b'\n', &mut line_buf)? > 0 {
            if let Some(h) = extract_valid_hex(&line_buf) {
                if h.len() == 40 {
                    let k = key(h);
                    if zero_keys.contains(&k) { zero_dropped += 1; line_buf.clear(); continue; }
                    if whitelist_keys.contains(&k) { wl_dropped += 1; line_buf.clear(); continue; }
                    if override_keys.contains(&k) { override_dropped += 1; line_buf.clear(); continue; }
                    if sample_sha1.is_empty() { sample_sha1 = h.to_ascii_lowercase(); }
                    sha1_keys.push(k);
                    cnt += 1;
                }
            }
            line_buf.clear();
        }
        println!("    - sha1.txt                ({} entries in {:.2}s)", cnt, t0.elapsed().as_secs_f64());
    }

    // C. MD5 Sources
    println!("\n[*] Step 2C: Reading MD5 malicious lists (pre-purged clean lists)...");
    let md5_files = vec![
        allblooms.join("md5.txt"),
        allblooms.join("old_hashes").join("md5.txt"),
        allblooms.join("md5_db"),
        allblooms.join("virusshare2026.md5"),
    ];

    for tf in &md5_files {
        if !tf.is_file() { continue; }
        let t0 = Instant::now();
        let f = File::open(tf)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, f);
        let mut line_buf = Vec::with_capacity(128);
        let mut cnt = 0usize;
        while reader.read_until(b'\n', &mut line_buf)? > 0 {
            if let Some(h) = extract_valid_hex(&line_buf) {
                if h.len() == 32 {
                    let k = key(h);
                    if zero_keys.contains(&k) { zero_dropped += 1; line_buf.clear(); continue; }
                    if whitelist_keys.contains(&k) { wl_dropped += 1; line_buf.clear(); continue; }
                    if override_keys.contains(&k) { override_dropped += 1; line_buf.clear(); continue; }
                    if sample_md5.is_empty() { sample_md5 = h.to_ascii_lowercase(); }
                    md5_keys.push(k);
                    cnt += 1;
                }
            }
            line_buf.clear();
        }
        println!("    - {:<22} ({} entries in {:.2}s)", tf.file_name().unwrap().to_string_lossy(), cnt, t0.elapsed().as_secs_f64());
    }

    println!("\n----------------------------------------------------------------------");
    println!("Ingestion Summary:");
    println!("    - 0-size empty excluded:  {}", zero_dropped);
    println!("    - Whitelist collisions:   {} (P0 Whitelist Priority)", wl_dropped);
    println!("    - Analyst overrides:      {}", override_dropped);
    println!("    - SHA-256 keys to build:  {}", sha256_keys.len());
    println!("    - SHA-1   keys to build:  {}", sha1_keys.len());
    println!("    - MD5     keys to build:  {}", md5_keys.len());
    println!("----------------------------------------------------------------------");

    // 3. Build the 3 separate BinaryFuse32 filters
    // A. malicious_sha256.xf
    build_single_filter(
        "SHA-256 Blacklist",
        sha256_keys,
        &sample_sha256,
        ZERO_SIZE_SHA256,
        &rules_dir.join("malicious_sha256.xf"),
    )?;

    // B. malicious_sha1.xf
    build_single_filter(
        "SHA-1 Blacklist",
        sha1_keys,
        &sample_sha1,
        ZERO_SIZE_SHA1,
        &rules_dir.join("malicious_sha1.xf"),
    )?;

    // C. malicious_md5.xf
    build_single_filter(
        "MD5 Blacklist",
        md5_keys,
        &sample_md5,
        ZERO_SIZE_MD5,
        &rules_dir.join("malicious_md5.xf"),
    )?;

    println!("\n======================================================================");
    println!(" All 3 separated BinaryFuse32 filters successfully built in {:.1}s!", start_total.elapsed().as_secs_f64());
    println!(" Output directory: {}", rules_dir.display());
    println!(" C:\\viruskov_archive was NOT touched (intact).");
    println!("======================================================================");

    Ok(())
}
