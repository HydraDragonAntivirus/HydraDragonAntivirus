use bincode_next::serde::encode_to_vec;
use fastbloom::AtomicBloomFilter;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

const FP_RATE: f64 = 1e-4;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: bloom_builder <dir>");
        std::process::exit(1);
    }
    let dir = &args[1];
    if !Path::new(dir).exists() {
        eprintln!("ERROR: Directory not found: {}", dir);
        std::process::exit(1);
    }
    build_blacklist_bloom(dir);
    build_whitelist_bloom(dir);
    build_urlhaus_bloom(dir);
    build_phishing_bloom(dir);
}

fn count_plain_lines(path: &Path) -> usize {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return 0 };
    BufReader::new(file).lines()
        .filter_map(|l| l.ok())
        .filter(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') { return false; }
            let token = t.split_whitespace().next().unwrap_or("");
            is_valid_hash(token)
        })
        .count()
}

fn count_csv_col(path: &Path, col: usize, has_header: bool) -> usize {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return 0 };
    let mut rdr = csv::ReaderBuilder::new().has_headers(has_header).flexible(true).from_reader(file);
    rdr.records()
        .filter_map(|r| r.ok())
        .filter(|r| r.get(col).map(|v| !v.trim().is_empty()).unwrap_or(false))
        .count()
}

fn make_bloom(n: usize) -> Arc<AtomicBloomFilter> {
    Arc::new(AtomicBloomFilter::with_false_pos(FP_RATE).expected_items(n.max(128)))
}

fn save_bloom(bloom: &Arc<AtomicBloomFilter>, out: &str) {
    match encode_to_vec(bloom.as_ref(), bincode_next::config::standard()) {
        Ok(data) => {
            fs::write(out, &data[..]).unwrap_or_else(|e| { eprintln!("ERROR write: {}", e); std::process::exit(1); });
            println!("[+] Written: {} ({} bytes)", out, data.len());
        }
        Err(e) => { eprintln!("ERROR serialize: {}", e); std::process::exit(1); }
    }
}

fn trim_q(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.as_bytes()[0] == b'\'' && s.as_bytes()[s.len()-1] == b'\'' { &s[1..s.len()-1] } else { s }
}

fn is_valid_hash(s: &str) -> bool {
    if s.is_empty() { return false; }
    match s.len() {
        32 | 40 | 64 | 128 => s.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    }
}

// ── blacklist ──────────────────────────────────────────────────────────────

fn build_blacklist_bloom(dir: &str) {
    let path = Path::new(dir);
    println!("[+] Building blacklist bloom...");

    let mut hash_files: Vec<std::path::PathBuf> = Vec::new();
    let csv_path = path.join("full.csv");

    for entry in fs::read_dir(path).unwrap().flatten() {
        let p = entry.path();
        if !p.is_file() { continue; }
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        if fname == "whitelist.db" { continue; }
        if p == csv_path { continue; }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext { "" | "md5" => {} _ => continue }
        hash_files.push(p);
    }

    let has_md5_db = path.join("md5_db").exists();
    let has_sha256_db = path.join("sha256_db").exists();

    let mut total = 0usize;
    if csv_path.exists() {
        let file = match fs::File::open(&csv_path) { Ok(f) => f, Err(_) => return };
        let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(file);
        for result in rdr.records() {
            let r = match result { Ok(r) => r, Err(_) => continue };
            // col 1=sha256, col 2=md5, col 3=sha1, col 12=ssdeep, col 13=tlsh
            // skip sha256 if sha256_db present, skip md5 if md5_db present
            for col in [1usize, 2, 3, 13] {
                if col == 1 && has_sha256_db { continue; }
                if col == 2 && has_md5_db { continue; }
                if let Some(h) = r.get(col) {
                    let h = h.trim().trim_matches('"');
                    if !h.is_empty() && h != "n/a" { total += 1; }
                }
            }
        }
    }
    for p in &hash_files { total += count_plain_lines(p); }

    if total == 0 { println!("[!] No blacklist source files found, skipping"); return; }
    println!("[+] Blacklist expected items: {}", total);
    let bloom = make_bloom(total);

    if csv_path.exists() {
        let file = match fs::File::open(&csv_path) { Ok(f) => f, Err(_) => return };
        let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(file);
        for result in rdr.records() {
            let r = match result { Ok(r) => r, Err(_) => continue };
            for col in [1usize, 2, 3, 13] {
                if let Some(h) = r.get(col) {
                    let h = h.trim().trim_matches('"');
                    if !h.is_empty() && h != "n/a" { bloom.insert(h); }
                }
            }
        }
    }

    for p in &hash_files {
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        let colon = matches!(fname.as_str(), "md5_db" | "sha256_db" | "sslbl" | "virusign");
        let file = match fs::File::open(p) { Ok(f) => f, Err(_) => continue };
        for line in BufReader::new(file).lines().flatten() {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') { continue; }
            // extract first token (before any space/tab/colon separator)
            let raw = if colon {
                line.split(':').next().unwrap_or("").trim().to_string()
            } else {
                line.split_whitespace().next().unwrap_or("").to_string()
            };
            if is_valid_hash(&raw) { bloom.insert(&raw); }
        }
    }

    save_bloom(&bloom, &format!("{}/blacklist.bloom", dir));
}

// ── whitelist ──────────────────────────────────────────────────────────────

fn build_whitelist_bloom(dir: &str) {
    let path = Path::new(dir);
    let db_path = path.join("whitelist.db");

    let mut sql_files: Vec<std::path::PathBuf> = Vec::new();
    let mut fp_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in fs::read_dir(path).unwrap().flatten() {
        let p = entry.path();
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        if fname.starts_with("RDS") && fname.ends_with(".sql") { sql_files.push(p.clone()); }
        if p.extension().and_then(|e| e.to_str()) == Some("fp") { fp_files.push(p); }
    }

    let db_count = if db_path.exists() { count_plain_lines(&db_path) } else { 0 };
    let sql_count: usize = sql_files.iter().map(|p| count_sql_md5(p)).sum();
    let fp_count: usize = fp_files.iter().map(|p| count_fp_lines(p)).sum();
    let total = db_count + sql_count + fp_count;
    println!("[+] Whitelist expected items: {} (db={} sql={} fp={})", total, db_count, sql_count, fp_count);
    let bloom = make_bloom(total);

    if db_path.exists() {
        let file = match fs::File::open(&db_path) { Ok(f) => f, Err(e) => { eprintln!("ERROR: {}", e); return; } };
        for line in BufReader::new(file).lines().flatten() {
            let h = line.trim().to_string();
            if h.is_empty() || h.starts_with('#') { continue; }
            if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) { bloom.insert(&h); }
        }
    }

    for p in &sql_files {
        let content = match fs::read_to_string(p) { Ok(c) => c, Err(_) => continue };
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("INSERT INTO METADATA") { continue; }
            let vs = match line.find("VALUES(") { Some(p) => p + 7, None => continue };
            let ve = match line.rfind(')') { Some(p) => p, None => continue };
            let parts: Vec<&str> = line[vs..ve].split(',').collect();
            if parts.len() < 23 { continue; }
            let md5 = trim_q(parts[20]);
            if !md5.is_empty() && md5.len() == 32 && md5.chars().all(|c| c.is_ascii_hexdigit()) {
                bloom.insert(md5);
            }
        }
    }

    for p in &fp_files {
        // .fp / .sfp format: HashString:FileSize:MalwareName
        let file = match fs::File::open(p) { Ok(f) => f, Err(_) => continue };
        for line in BufReader::new(file).lines().flatten() {
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            let hash = trimmed.split(':').next().unwrap_or("").trim().to_string();
            if is_valid_hash(&hash) { bloom.insert(&hash); }
        }
    }

    save_bloom(&bloom, &format!("{}/whitelist.bloom", dir));
}

fn count_fp_lines(path: &Path) -> usize {
    let file = match fs::File::open(path) { Ok(f) => f, Err(_) => return 0 };
    BufReader::new(file).lines()
        .filter_map(|l| l.ok())
        .filter(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') { return false; }
            let hash = t.split(':').next().unwrap_or("").trim();
            is_valid_hash(hash)
        })
        .count()
}

fn count_sql_md5(path: &std::path::PathBuf) -> usize {
    let content = match fs::read_to_string(path) { Ok(c) => c, Err(_) => return 0 };
    content.lines()
        .filter(|l| l.trim().starts_with("INSERT INTO METADATA"))
        .filter(|l| {
            let l = l.trim();
            let vs = match l.find("VALUES(") { Some(p) => p + 7, None => return false };
            let ve = match l.rfind(')') { Some(p) => p, None => return false };
            let parts: Vec<&str> = l[vs..ve].split(',').collect();
            if parts.len() < 23 { return false; }
            let md5 = trim_q(parts[20]);
            !md5.is_empty() && md5.len() == 32
        })
        .count()
}

// ── urlhaus ────────────────────────────────────────────────────────────────

fn build_urlhaus_bloom(dir: &str) {
    let path = Path::new(dir).join("urlhaus.csv");
    if !path.exists() { println!("[!] urlhaus.csv not found, skipping"); return; }

    let total = count_csv_col(&path, 2, true);
    println!("[+] URLhaus expected items: {}", total);
    let bloom = make_bloom(total);

    let mut rdr = match csv::ReaderBuilder::new().has_headers(true).flexible(true).from_path(&path) {
        Ok(r) => r, Err(e) => { eprintln!("ERROR: {}", e); return; }
    };
    let mut count = 0u64;
    for result in rdr.records() {
        let r = match result { Ok(r) => r, Err(_) => continue };
        if let Some(u) = r.get(2) { let u = u.trim(); if !u.is_empty() { bloom.insert(u); count += 1; } }
    }
    println!("[+] URLhaus inserted: {}", count);
    save_bloom(&bloom, &format!("{}/urlhaus.bloom", dir));
}

// ── phishing ───────────────────────────────────────────────────────────────

fn build_phishing_bloom(dir: &str) {
    let path = Path::new(dir).join("phishing_links.json");
    if !path.exists() { println!("[!] phishing_links.json not found, skipping"); return; }

    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(e) => { eprintln!("ERROR: {}", e); return; } };

    let urls: Vec<String> = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
        parsed.get("data").and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|u| u.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    } else {
        content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
    };

    let total = urls.len();
    println!("[+] Phishing expected items: {}", total);
    let bloom = make_bloom(total);
    for u in &urls { bloom.insert(u.as_str()); }
    save_bloom(&bloom, &format!("{}/phishing.bloom", dir));
}
