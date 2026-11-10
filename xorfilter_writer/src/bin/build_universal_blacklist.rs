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
                    if h.len() == 64 && !h.eq_ignore_ascii_case(ZERO_SIZE_SHA256) {
                        set.insert(key(h));
                    }
                }
                buf.clear();
            }
        }
    }

    // Dataset cache benign entries
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_total = Instant::now();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let allblooms = root.join("allblooms");

    println!("======================================================================");
    println!(" HydraDragon Antivirus - High-Performance Universal Blacklist Builder");
    println!(" Algorithm: BinaryFuse32 (SHA-256 + SHA-1 + MD5)");
    println!(" 0-Size Protection: ACTIVE | Whitelist Priority (P0): ACTIVE");
    println!("======================================================================");

    // 0-size hash keys
    let zero_keys: HashSet<u64> = [
        key(ZERO_SIZE_MD5),
        key(ZERO_SIZE_SHA1),
        key(ZERO_SIZE_SHA256),
    ].into_iter().collect();

    // 1. Whitelist & Overrides
    println!("[*] Step 1: Loading Whitelist & Analyst Overrides...");
    let whitelist_keys = load_whitelist_keys(&root);
    println!("    [+] Loaded {} benign whitelist keys", whitelist_keys.len());
    let override_keys = load_overrides(&root);
    println!("    [+] Loaded {} analyst override keys", override_keys.len());

    // 2. Target files: SHA-256, SHA-1, MD5
    let target_files = vec![
        // SHA-256
        (allblooms.join("sha256.txt"), "SHA-256"),
        (allblooms.join("sha256_db"), "SHA-256"),
        (allblooms.join("sha256amnestytech"), "SHA-256"),
        (allblooms.join("iocemotet"), "SHA-256"),
        (allblooms.join("virussign"), "SHA-256"),
        (allblooms.join("samplesstalkware"), "SHA-256"),
        (allblooms.join("eset"), "SHA-256"),
        // SHA-1
        (allblooms.join("sha1.txt"), "SHA-1"),
        // MD5 (Pre-purged clean lists)
        (allblooms.join("md5.txt"), "MD5"),
        (allblooms.join("old_hashes").join("md5.txt"), "MD5"),
        (allblooms.join("md5_db"), "MD5"),
        (allblooms.join("virusshare2026.md5"), "MD5"),
    ];

    println!("[*] Step 2: Ingesting malicious hashes into memory buffer...");
    let mut keys: Vec<u64> = Vec::with_capacity(45_000_000);
    let mut total_lines = 0usize;
    let mut zero_dropped = 0usize;
    let mut wl_dropped = 0usize;
    let mut override_dropped = 0usize;
    let mut counts_by_type = [0usize; 3]; // [md5, sha1, sha256]

    // Sample hashes for verification
    let mut sample_sha256 = String::new();
    let mut sample_sha1 = String::new();
    let mut sample_md5 = String::new();

    for (tf, label) in &target_files {
        if !tf.is_file() {
            continue;
        }
        let t0 = Instant::now();
        let f = File::open(tf)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, f);
        let mut line_buf = Vec::with_capacity(128);
        let mut lines_in_file = 0usize;

        while reader.read_until(b'\n', &mut line_buf)? > 0 {
            lines_in_file += 1;
            if let Some(h) = extract_valid_hex(&line_buf) {
                let k = key(h);
                if zero_keys.contains(&k) {
                    zero_dropped += 1;
                    line_buf.clear();
                    continue;
                }
                if whitelist_keys.contains(&k) {
                    wl_dropped += 1;
                    line_buf.clear();
                    continue;
                }
                if override_keys.contains(&k) {
                    override_dropped += 1;
                    line_buf.clear();
                    continue;
                }
                match h.len() {
                    32 => {
                        counts_by_type[0] += 1;
                        if sample_md5.is_empty() {
                            sample_md5 = h.to_ascii_lowercase();
                        }
                    }
                    40 => {
                        counts_by_type[1] += 1;
                        if sample_sha1.is_empty() {
                            sample_sha1 = h.to_ascii_lowercase();
                        }
                    }
                    64 => {
                        counts_by_type[2] += 1;
                        if sample_sha256.is_empty() {
                            sample_sha256 = h.to_ascii_lowercase();
                        }
                    }
                    _ => {}
                }
                keys.push(k);
            }
            line_buf.clear();
        }
        total_lines += lines_in_file;
        let sz_mb = fs::metadata(tf)?.len() as f64 / (1024.0 * 1024.0);
        println!(
            "    - Read {:<20} ({:>5.1} MB, {:>10} lines) in {:>5.2}s [{}]",
            tf.file_name().unwrap().to_string_lossy(),
            sz_mb,
            lines_in_file,
            t0.elapsed().as_secs_f64(),
            label
        );
    }

    // Dataset cache malicious entries
    let cache_file = root.join("hydradragon_ml_models").join("dataset_hash_cache.jsonl");
    if cache_file.is_file() {
        let t0 = Instant::now();
        let f = File::open(&cache_file)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, f);
        let mut buf = String::with_capacity(512);
        let mut count = 0usize;
        while reader.read_line(&mut buf)? > 0 {
            if buf.contains("\"s\":0") {
                zero_dropped += 1;
                buf.clear();
                continue;
            }
            let is_benign = buf.contains("benign") || buf.contains("clean") || buf.contains("data2") || buf.contains("normal");
            if !is_benign {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&buf) {
                    if let Some(h) = v.get("h").and_then(|h| h.as_str()) {
                        let clean = h.trim();
                        if clean.len() == 64 && !clean.eq_ignore_ascii_case(ZERO_SIZE_SHA256) {
                            let k = key(clean);
                            if !whitelist_keys.contains(&k) && !override_keys.contains(&k) {
                                counts_by_type[2] += 1;
                                keys.push(k);
                                count += 1;
                            } else {
                                wl_dropped += 1;
                            }
                        }
                    }
                }
            }
            buf.clear();
        }
        println!("    - Read dataset_hash_cache.jsonl: {} entries in {:.2}s", count, t0.elapsed().as_secs_f64());
    }

    println!("----------------------------------------------------------------------");
    println!("Ingestion Summary:");
    println!("    - Total lines read:     {:>12}", total_lines);
    println!("    - 0-size empty files:   {:>12} excluded", zero_dropped);
    println!("    - Whitelist collisions: {:>12} excluded (Whitelist Priority P0)", wl_dropped);
    println!("    - Analyst overrides:    {:>12} excluded", override_dropped);
    println!("    - Raw signatures:       {:>12}", keys.len());
    println!("        * SHA-256: {:>12}", counts_by_type[2]);
    println!("        * SHA-1:   {:>12}", counts_by_type[1]);
    println!("        * MD5:     {:>12}", counts_by_type[0]);
    println!("----------------------------------------------------------------------");

    // 3. Compile BinaryFuse32
    println!("[*] Step 3: Compiling BinaryFuse32 filter (hydradragonxorfilter)...");
    let t_build = Instant::now();
    let filter_bytes = build_bf32_from_keys(keys)
        .map_err(|e| format!("BinaryFuse32 build error: {e}"))?;
    println!("    [+] Filter constructed in {:.2}s, size: {} bytes ({:.2} MB)",
        t_build.elapsed().as_secs_f64(),
        filter_bytes.len(),
        filter_bytes.len() as f64 / (1024.0 * 1024.0)
    );

    // 4. Save to destination paths
    println!("[*] Step 4: Writing output files...");
    let dest_portable = root.join("OpenMalwareScannerPortable").join("xorfilter_rules").join("malicious_sha256.xf");
    fs::create_dir_all(dest_portable.parent().unwrap())?;
    fs::write(&dest_portable, &filter_bytes)?;
    println!("    [+] Saved to: {}", dest_portable.display());

    // 5. Verification
    println!("[*] Step 5: Verifying filter roundtrip & 0-size protection...");
    let filter = XorFilter::from_bytes(&filter_bytes)
        .ok_or("Failed to deserialize built filter")?;

    println!("    - Total distinct keys in filter: {}", filter.len());
    println!("    - Fingerprint width: {} bits (BinaryFuse32)", filter.fingerprint_bits());

    // Hit tests
    if !sample_sha256.is_empty() {
        let hit = filter.contains(&sample_sha256);
        println!("    - Sample SHA-256 ({}): {} [PASS: {}]", &sample_sha256[..16], hit, hit);
        assert!(hit, "Sample SHA-256 must match");
    }
    if !sample_sha1.is_empty() {
        let hit = filter.contains(&sample_sha1);
        println!("    - Sample SHA-1   ({}): {} [PASS: {}]", &sample_sha1[..16], hit, hit);
        assert!(hit, "Sample SHA-1 must match");
    }
    if !sample_md5.is_empty() {
        let hit = filter.contains(&sample_md5);
        println!("    - Sample MD5     ({}): {} [PASS: {}]", &sample_md5[..16], hit, hit);
        assert!(hit, "Sample MD5 must match");
    }

    // 0-size safety tests
    let zero_sha256_hit = filter.contains(ZERO_SIZE_SHA256);
    let zero_sha1_hit = filter.contains(ZERO_SIZE_SHA1);
    let zero_md5_hit = filter.contains(ZERO_SIZE_MD5);

    println!("    - 0-size SHA-256 (e3b0c44...): {} [PASS: {}]", zero_sha256_hit, !zero_sha256_hit);
    println!("    - 0-size SHA-1   (da39a3e...): {} [PASS: {}]", zero_sha1_hit, !zero_sha1_hit);
    println!("    - 0-size MD5     (d41d8cd...): {} [PASS: {}]", zero_md5_hit, !zero_md5_hit);

    assert!(!zero_sha256_hit, "0-size SHA-256 must NOT be in blacklist");
    assert!(!zero_sha1_hit, "0-size SHA-1 must NOT be in blacklist");
    assert!(!zero_md5_hit, "0-size MD5 must NOT be in blacklist");

    println!("======================================================================");
    println!(" Universal Blacklist build finished successfully in {:.1}s!", start_total.elapsed().as_secs_f64());
    println!("======================================================================");

    Ok(())
}
