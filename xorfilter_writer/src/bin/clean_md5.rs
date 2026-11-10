use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const ZERO_SIZE_MD5: [u8; 16] = [
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
];

#[inline(always)]
fn trim_bytes(mut b: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = b.split_first() {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = b.split_last() {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

#[inline(always)]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline(always)]
fn parse_hex_md5(s: &[u8]) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_val(s[i * 2])?;
        let lo = hex_val(s[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline(always)]
fn extract_md5(line: &[u8]) -> Option<[u8; 16]> {
    let trimmed = trim_bytes(line);
    if trimmed.is_empty() || trimmed[0] == b'#' {
        return None;
    }
    let token = if let Some(pos) = trimmed.iter().position(|&b| b == b'|' || b == b':' || b == b',' || b == b' ' || b == b'\t') {
        &trimmed[..pos]
    } else {
        trimmed
    };
    parse_hex_md5(token)
}

fn hex_to_string(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_total = Instant::now();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let allblooms = root.join("allblooms");

    println!("======================================================================");
    println!(" HydraDragon Antivirus - High-Performance MD5 Blacklist Cleaner");
    println!(" NSRL 2026.03.1 Autopsy & Benign Whitelist Cross-Purge");
    println!("======================================================================");

    let target_files = vec![
        allblooms.join("md5.txt"),
        allblooms.join("old_hashes").join("md5.txt"),
        allblooms.join("md5_db"),
        allblooms.join("virusshare2026.md5"),
    ];

    // 1. Collect all unique malicious MD5 hashes
    println!("[*] Step 1: Loading malicious MD5 hashes from target lists into memory...");
    let mut malicious_set: HashSet<[u8; 16]> = HashSet::with_capacity(30_000_000);
    let mut total_lines_read = 0usize;

    for tf in &target_files {
        if !tf.is_file() {
            println!("    - File not found: {}", tf.display());
            continue;
        }
        let t_start = Instant::now();
        let f = File::open(tf)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, f);
        let mut line_buf = Vec::with_capacity(128);
        let mut lines_in_file = 0usize;

        while reader.read_until(b'\n', &mut line_buf)? > 0 {
            lines_in_file += 1;
            if let Some(h) = extract_md5(&line_buf) {
                malicious_set.insert(h);
            }
            line_buf.clear();
        }
        total_lines_read += lines_in_file;
        let sz_mb = fs::metadata(tf)?.len() as f64 / (1024.0 * 1024.0);
        println!(
            "    - Loaded {} ({:.1} MB, {:?} lines) in {:.2}s",
            tf.file_name().unwrap().to_string_lossy(),
            sz_mb,
            lines_in_file,
            t_start.elapsed().as_secs_f64()
        );
    }

    println!(
        "[+] Total lines read: {:?}, Unique malicious MD5 hashes: {:?}",
        total_lines_read,
        malicious_set.len()
    );
    println!("----------------------------------------------------------------------");

    // 2. Stream Whitelist Sources and Identify Collisions
    println!("[*] Step 2: Streaming NSRL 2026.03.1 Autopsy and Whitelist databases...");
    let mut conflicts: HashMap<[u8; 16], String> = HashMap::new();

    // Always exclude 0-size empty file
    conflicts.insert(ZERO_SIZE_MD5, "0_size_empty_file".to_string());

    let whitelist_sources = vec![
        (allblooms.join("whitelist").join("NSRL-2026.3-Autopsy").join("NSRLFile-2026.03.1m-computer.txt-md5.idx"), "NSRL_2026.03.1_Computer"),
        (allblooms.join("whitelist").join("NSRL-2026.3-Autopsy").join("NSRL-2026.03.1-Android-Autopsy").join("NSRLFile-2026.03.1-android.txt-md5.idx"), "NSRL_2026.03.1_Android"),
        (allblooms.join("whitelist").join("NSRL-2026.3-Autopsy").join("NSRL-2026.03.1-iOS-Autopsy").join("NSRLFile-2026.03.1-ios.txt-md5.idx"), "NSRL_2026.03.1_iOS"),
        (allblooms.join("whitelist").join("benign_md5.txt"), "benign_md5"),
        (allblooms.join("whitelist.db"), "whitelist_db"),
        (allblooms.join("whitelist.fp"), "whitelist_fp"),
        (allblooms.join("daily.fp"), "daily_fp"),
        (allblooms.join("main.fp"), "main_fp"),
    ];

    for (wf, label) in whitelist_sources {
        if !wf.is_file() {
            continue;
        }
        let t_start = Instant::now();
        let f = File::open(&wf)?;
        let sz_mb = fs::metadata(&wf)?.len() as f64 / (1024.0 * 1024.0);
        let mut reader = BufReader::with_capacity(2 * 1024 * 1024, f);
        let mut line_buf = Vec::with_capacity(128);
        let mut lines = 0usize;
        let mut hits = 0usize;

        while reader.read_until(b'\n', &mut line_buf)? > 0 {
            lines += 1;
            if let Some(h) = extract_md5(&line_buf) {
                if malicious_set.contains(&h) {
                    if !conflicts.contains_key(&h) {
                        conflicts.insert(h, label.to_string());
                        hits += 1;
                    }
                }
            }
            line_buf.clear();
        }

        println!(
            "    - Streamed {} ({:.1} MB, {:?} lines) -> {:?} new collisions found in {:.2}s",
            wf.file_name().unwrap().to_string_lossy(),
            sz_mb,
            lines,
            hits,
            t_start.elapsed().as_secs_f64()
        );
    }

    // Check analyst override removals
    let override_file = root.join("analyst_signatures").join("blacklist_removals.jsonl");
    if override_file.is_file() {
        let f = File::open(&override_file)?;
        let reader = BufReader::new(f);
        let mut ov_hits = 0usize;
        for line in reader.lines() {
            let line = line?;
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if v.get("removed").and_then(|r| r.as_bool()).unwrap_or(true) {
                    if let Some(h_str) = v.get("hash").and_then(|h| h.as_str()) {
                        if let Some(h) = parse_hex_md5(h_str.trim().as_bytes()) {
                            if malicious_set.contains(&h) && !conflicts.contains_key(&h) {
                                let reason = format!("analyst_override:{}", v.get("reason").and_then(|r| r.as_str()).unwrap_or(""));
                                conflicts.insert(h, reason);
                                ov_hits += 1;
                            }
                        }
                    }
                }
            }
        }
        if ov_hits > 0 {
            println!("    - Analyst overrides: {} collisions added", ov_hits);
        }
    }

    println!("----------------------------------------------------------------------");
    println!("[+] Total unique False Positive MD5 collisions identified: {:?}", conflicts.len());
    println!("----------------------------------------------------------------------");

    // 3. Save Purged False Positive Hashes
    let purged_txt = allblooms.join("purged_md5_false_positives.txt");
    let purged_json = allblooms.join("purged_md5_details.json");

    println!("[*] Step 3: Saving purged false positives to file...");
    {
        let mut tf = BufWriter::new(File::create(&purged_txt)?);
        writeln!(tf, "# HydraDragon Antivirus - Purged False-Positive MD5 Hashes")?;
        writeln!(tf, "# Total Purged: {}", conflicts.len())?;
        writeln!(tf, "# Source Whitelists: NSRL 2026.03.1 Autopsy, benign_md5, 0-size, analyst overrides\n")?;

        let mut items = Vec::with_capacity(conflicts.len());
        for (h, reason) in &conflicts {
            let hex_str = hex_to_string(h);
            writeln!(tf, "{}  # {}", hex_str, reason)?;
            items.push(serde_json::json!({
                "hash": hex_str,
                "reason": reason,
            }));
        }

        let mut jf = BufWriter::new(File::create(&purged_json)?);
        serde_json::to_writer_pretty(&mut jf, &serde_json::json!({
            "total_purged": conflicts.len(),
            "items": items,
        }))?;
    }
    println!("    - Text list: {}", purged_txt.display());
    println!("    - JSON log:  {}", purged_json.display());
    println!("----------------------------------------------------------------------");

    // 4. In-place rewrite of target files
    println!("[*] Step 4: Purging false positive collisions from target blacklist files...");
    let mut total_purged_instances = 0usize;

    for tf in &target_files {
        if !tf.is_file() {
            continue;
        }
        let t_start = Instant::now();
        let sz_before = fs::metadata(tf)?.len();
        let tmp_path = tf.with_extension("cleaning_tmp");

        let mut lines_read = 0usize;
        let mut lines_kept = 0usize;
        let mut dropped = 0usize;

        {
            let in_f = File::open(tf)?;
            let mut reader = BufReader::with_capacity(1024 * 1024, in_f);
            let out_f = File::create(&tmp_path)?;
            let mut writer = BufWriter::with_capacity(1024 * 1024, out_f);
            let mut line_buf = Vec::with_capacity(128);

            while reader.read_until(b'\n', &mut line_buf)? > 0 {
                lines_read += 1;
                if let Some(h) = extract_md5(&line_buf) {
                    if conflicts.contains_key(&h) {
                        dropped += 1;
                        line_buf.clear();
                        continue;
                    }
                }
                writer.write_all(&line_buf)?;
                lines_kept += 1;
                line_buf.clear();
            }
            writer.flush()?;
        }

        fs::rename(&tmp_path, tf)?;
        let sz_after = fs::metadata(tf)?.len();
        total_purged_instances += dropped;

        println!(
            "    - {}: Read {:?}, Kept {:?}, Purged {:?} FP in {:.2}s ({:.1} MB -> {:.1} MB)",
            tf.file_name().unwrap().to_string_lossy(),
            lines_read,
            lines_kept,
            dropped,
            t_start.elapsed().as_secs_f64(),
            sz_before as f64 / (1024.0 * 1024.0),
            sz_after as f64 / (1024.0 * 1024.0),
        );
    }

    println!("======================================================================");
    println!("[+] All MD5 blacklist files cleaned successfully!");
    println!("    Unique false-positive hashes purged: {:?}", conflicts.len());
    println!("    Total instance removals across lists: {:?}", total_purged_instances);
    println!("    Total elapsed time: {:.2}s", start_total.elapsed().as_secs_f64());
    println!("======================================================================");

    Ok(())
}
