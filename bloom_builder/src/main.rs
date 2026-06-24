use bincode_next::serde::encode_to_vec;
use fastbloom::AtomicBloomFilter;
use std::collections::HashSet;
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
    build_url_bloom(dir);
    build_phishing_bloom(dir);
}

fn count_plain_lines(path: &Path) -> usize {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                return false;
            }
            let token = t.split_whitespace().next().unwrap_or("");
            is_valid_hash(token)
        })
        .count()
}

fn make_bloom(n: usize) -> Arc<AtomicBloomFilter> {
    Arc::new(AtomicBloomFilter::with_false_pos(FP_RATE).expected_items(n.max(128)))
}

fn save_bloom(bloom: &Arc<AtomicBloomFilter>, out: &str) {
    match encode_to_vec(bloom.as_ref(), bincode_next::config::standard()) {
        Ok(data) => {
            fs::write(out, &data[..]).unwrap_or_else(|e| {
                eprintln!("ERROR write: {}", e);
                std::process::exit(1);
            });
            println!("[+] Written: {} ({} bytes)", out, data.len());
        }
        Err(e) => {
            eprintln!("ERROR serialize: {}", e);
            std::process::exit(1);
        }
    }
}

fn trim_q(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.as_bytes()[0] == b'\'' && s.as_bytes()[s.len() - 1] == b'\'' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn is_valid_hash(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match s.len() {
        32 | 40 | 64 | 128 => s.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    }
}

// ── blacklist ──────────────────────────────────────────────────────────────

/// Hash type, recognised by content (length / ':' for ssdeep / 'T1' for tlsh).
#[derive(Clone, Copy)]
enum HashKind {
    Md5,
    Sha1,
    Sha256,
    Ssdeep,
    Tlsh,
}

fn classify(h: &str) -> Option<HashKind> {
    let h = h.trim();
    if h.is_empty() || h == "n/a" {
        return None;
    }
    // TLSH: modern digests are "T1" + 70 hex (older variants: bare 70 hex).
    if h.starts_with("T1") || h.starts_with("t1") {
        return Some(HashKind::Tlsh);
    }
    // ssdeep: "blocksize:chunk:doublechunk" — first segment is numeric.
    if h.contains(':') {
        let first = h.split(':').next().unwrap_or("");
        if !first.is_empty() && first.chars().all(|c| c.is_ascii_digit()) {
            return Some(HashKind::Ssdeep);
        }
        return None;
    }
    if h.chars().all(|c| c.is_ascii_hexdigit()) {
        return match h.len() {
            32 => Some(HashKind::Md5),
            40 => Some(HashKind::Sha1),
            64 => Some(HashKind::Sha256),
            70 => Some(HashKind::Tlsh),
            _ => None,
        };
    }
    None
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Pack a 32-char hex MD5 into 16 bytes (compact key for the filter set).
fn md5_to_bytes(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = (hexval(b[2 * i])? << 4) | hexval(b[2 * i + 1])?;
    }
    Some(out)
}

/// Load the VirusShare MD5 list to DROP (the "old" 50%-style list, like ClamAV
/// retiring stale signatures). Returns None when the file is absent.
fn load_virusshare(path: &Path) -> Option<HashSet<[u8; 16]>> {
    let file = fs::File::open(path).ok()?;
    let mut set = HashSet::new();
    for line in BufReader::new(file).lines().flatten() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let tok = t.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        if let Some(b) = md5_to_bytes(&tok) {
            set.insert(b);
        }
    }
    Some(set)
}

/// Write a sorted, one-per-line hash list (deterministic output for git).
fn write_lines(path: &Path, set: &HashSet<String>) {
    let mut v: Vec<&String> = set.iter().collect();
    v.sort_unstable();
    let mut out = String::with_capacity(set.len() * 34);
    for h in v {
        out.push_str(h);
        out.push('\n');
    }
    match fs::write(path, out) {
        Ok(_) => println!("[+] Written: {} ({} lines)", path.display(), set.len()),
        Err(e) => eprintln!("ERROR write {}: {}", path.display(), e),
    }
}

/// Per-type, deduplicated hash buckets collected during the blacklist build.
#[derive(Default)]
struct Buckets {
    md5: HashSet<String>,
    sha1: HashSet<String>,
    sha256: HashSet<String>,
    ssdeep: HashSet<String>,
    tlsh: HashSet<String>,
    /// MD5s present in the VirusShare list — dropped from the bloom, kept aside.
    old_md5: HashSet<String>,
}

impl Buckets {
    fn add(&mut self, raw: &str, vs: &Option<HashSet<[u8; 16]>>) {
        // Normalise hex digests to lowercase (canonical form); ssdeep is left as-is
        // because it is a case-sensitive base64-style string, not hex.
        let h = raw.trim().trim_matches('"');
        match classify(h) {
            Some(HashKind::Md5) => {
                let norm = h.to_ascii_lowercase();
                let is_old = vs
                    .as_ref()
                    .and_then(|s| md5_to_bytes(&norm).map(|b| s.contains(&b)))
                    .unwrap_or(false);
                if is_old {
                    self.old_md5.insert(norm);
                } else {
                    self.md5.insert(norm);
                }
            }
            Some(HashKind::Sha1) => {
                self.sha1.insert(h.to_ascii_lowercase());
            }
            Some(HashKind::Sha256) => {
                self.sha256.insert(h.to_ascii_lowercase());
            }
            Some(HashKind::Ssdeep) => {
                self.ssdeep.insert(h.to_string());
            }
            Some(HashKind::Tlsh) => {
                self.tlsh.insert(h.to_ascii_lowercase());
            }
            None => {}
        }
    }
}

fn build_blacklist_bloom(dir: &str) {
    let path = Path::new(dir);
    println!("[+] Building blacklist bloom...");

    // Optional VirusShare MD5 filter — these are dropped as the "old" list.
    let vs = load_virusshare(&path.join("virusshare_hashes.txt"));
    match &vs {
        Some(s) => println!("[+] VirusShare filter loaded: {} md5(s) to drop", s.len()),
        None => println!("[!] virusshare_hashes.txt not found — no md5 filtering"),
    }

    let mut hash_files: Vec<std::path::PathBuf> = Vec::new();
    let csv_path = path.join("full.csv");

    for entry in fs::read_dir(path).unwrap().flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        if fname == "whitelist.db" || fname == "virusshare_hashes.txt" {
            continue; // whitelist DB / the filter list itself are not blacklist sources
        }
        if p == csv_path {
            continue;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "" | "md5" => {}
            _ => continue,
        }
        hash_files.push(p);
    }

    let mut b = Buckets::default();

    // full.csv: col 1=sha256, 2=md5, 3=sha1, 12=ssdeep, 13=tlsh.
    if csv_path.exists() {
        if let Ok(file) = fs::File::open(&csv_path) {
            let mut rdr = csv::ReaderBuilder::new()
                .has_headers(false)
                .flexible(true)
                .from_reader(file);
            for result in rdr.records() {
                let r = match result {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                for col in [1usize, 2, 3, 12, 13] {
                    if let Some(h) = r.get(col) {
                        b.add(h, &vs);
                    }
                }
            }
        }
    }

    // Plain hash files (md5_db/sha256_db/sslbl/virusign use a ':' separator).
    for p in &hash_files {
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        let colon = matches!(fname.as_str(), "md5_db" | "sha256_db" | "sslbl" | "virusign");
        let file = match fs::File::open(p) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for line in BufReader::new(file).lines().flatten() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let raw = if colon {
                line.split(':').next().unwrap_or("").trim()
            } else {
                line.split_whitespace().next().unwrap_or("")
            };
            b.add(raw, &vs);
        }
    }

    // Fold in the per-type lists we maintain (md5.txt … tlsh.txt) as bloom sources
    // too, so the bloom accumulates them across runs. The original source files are
    // never modified; these generated lists are simply re-read and re-merged.
    for name in ["md5.txt", "sha1.txt", "sha256.txt", "ssdeep.txt", "tlsh.txt"] {
        let tp = path.join(name);
        if let Ok(file) = fs::File::open(&tp) {
            for line in BufReader::new(file).lines().flatten() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                b.add(t, &vs);
            }
        }
    }

    let total = b.md5.len() + b.sha1.len() + b.sha256.len() + b.ssdeep.len() + b.tlsh.len();
    if total == 0 {
        println!("[!] No blacklist source files found, skipping");
        return;
    }
    println!(
        "[+] Blacklist unique: {} (md5={} sha1={} sha256={} ssdeep={} tlsh={}); dropped old md5={}",
        total,
        b.md5.len(),
        b.sha1.len(),
        b.sha256.len(),
        b.ssdeep.len(),
        b.tlsh.len(),
        b.old_md5.len()
    );

    // Bloom: everything EXCEPT the dropped (old) MD5s.
    let bloom = make_bloom(total);
    for h in b
        .md5
        .iter()
        .chain(b.sha1.iter())
        .chain(b.sha256.iter())
        .chain(b.ssdeep.iter())
        .chain(b.tlsh.iter())
    {
        bloom.insert(h.as_str());
    }
    save_bloom(&bloom, &format!("{}/blacklist.bloom", dir));

    // Per-type hash lists for upload (hashes only — no names, no metadata).
    write_lines(&path.join("md5.txt"), &b.md5);
    write_lines(&path.join("sha1.txt"), &b.sha1);
    write_lines(&path.join("sha256.txt"), &b.sha256);
    write_lines(&path.join("ssdeep.txt"), &b.ssdeep);
    write_lines(&path.join("tlsh.txt"), &b.tlsh);

    // The dropped VirusShare MD5s go into old_hashes/ (retired, not in the bloom).
    if !b.old_md5.is_empty() {
        let old_dir = path.join("old_hashes");
        if let Err(e) = fs::create_dir_all(&old_dir) {
            eprintln!("ERROR create {}: {}", old_dir.display(), e);
        }
        write_lines(&old_dir.join("md5.txt"), &b.old_md5);
    }
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
        if fname.starts_with("RDS") && fname.ends_with(".sql") {
            sql_files.push(p.clone());
        }
        if p.extension().and_then(|e| e.to_str()) == Some("fp") {
            fp_files.push(p);
        }
    }

    let db_count = if db_path.exists() {
        count_plain_lines(&db_path)
    } else {
        0
    };
    let sql_count: usize = sql_files.iter().map(|p| count_sql_md5(p)).sum();
    let fp_count: usize = fp_files.iter().map(|p| count_fp_lines(p)).sum();
    let total = db_count + sql_count + fp_count;
    println!(
        "[+] Whitelist expected items: {} (db={} sql={} fp={})",
        total, db_count, sql_count, fp_count
    );
    let bloom = make_bloom(total);

    if db_path.exists() {
        let file = match fs::File::open(&db_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return;
            }
        };
        for line in BufReader::new(file).lines().flatten() {
            let h = line.trim().to_string();
            if h.is_empty() || h.starts_with('#') {
                continue;
            }
            if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                bloom.insert(&h);
            }
        }
    }

    for p in &sql_files {
        let content = match fs::read_to_string(p) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("INSERT INTO METADATA") {
                continue;
            }
            let vs = match line.find("VALUES(") {
                Some(p) => p + 7,
                None => continue,
            };
            let ve = match line.rfind(')') {
                Some(p) => p,
                None => continue,
            };
            let parts: Vec<&str> = line[vs..ve].split(',').collect();
            if parts.len() < 23 {
                continue;
            }
            let md5 = trim_q(parts[20]);
            if !md5.is_empty() && md5.len() == 32 && md5.chars().all(|c| c.is_ascii_hexdigit()) {
                bloom.insert(md5);
            }
        }
    }

    for p in &fp_files {
        // .fp / .sfp format: HashString:FileSize:MalwareName
        let file = match fs::File::open(p) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for line in BufReader::new(file).lines().flatten() {
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let hash = trimmed.split(':').next().unwrap_or("").trim().to_string();
            if is_valid_hash(&hash) {
                bloom.insert(&hash);
            }
        }
    }

    save_bloom(&bloom, &format!("{}/whitelist.bloom", dir));
}

fn count_fp_lines(path: &Path) -> usize {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                return false;
            }
            let hash = t.split(':').next().unwrap_or("").trim();
            is_valid_hash(hash)
        })
        .count()
}

fn count_sql_md5(path: &std::path::PathBuf) -> usize {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    content
        .lines()
        .filter(|l| l.trim().starts_with("INSERT INTO METADATA"))
        .filter(|l| {
            let l = l.trim();
            let vs = match l.find("VALUES(") {
                Some(p) => p + 7,
                None => return false,
            };
            let ve = match l.rfind(')') {
                Some(p) => p,
                None => return false,
            };
            let parts: Vec<&str> = l[vs..ve].split(',').collect();
            if parts.len() < 23 {
                return false;
            }
            let md5 = trim_q(parts[20]);
            !md5.is_empty() && md5.len() == 32
        })
        .count()
}

// ── URL feeds (urlhaus + malwareurl, merged) ─────────────────────────────────

/// One combined URL bloom from BOTH feeds — URLhaus (`urlhaus.csv`, col 2) and the
/// malware-URL list (`MaliciousLinks.txt`). The scanner only ever loads
/// `urlhaus.bloom` (`is_urlhaus`), so merging here means the malware-URL feed is
/// actually used instead of landing in an orphaned `malwareurl.bloom`.
fn build_url_bloom(dir: &str) {
    let path = Path::new(dir);
    let urlhaus_csv = path.join("urlhaus.csv");
    let malicious_txt = path.join("MaliciousLinks.txt");

    let mut urls: HashSet<String> = HashSet::new();

    if urlhaus_csv.exists() {
        match csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_path(&urlhaus_csv)
        {
            Ok(mut rdr) => {
                for result in rdr.records() {
                    if let Ok(r) = result {
                        if let Some(u) = r.get(2) {
                            let u = u.trim();
                            if !u.is_empty() {
                                urls.insert(u.to_string());
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("ERROR urlhaus.csv: {}", e),
        }
    } else {
        println!("[!] urlhaus.csv not found, skipping that feed");
    }

    match fs::read_to_string(&malicious_txt) {
        Ok(content) => {
            for l in content.lines() {
                let l = l.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    urls.insert(l.to_string());
                }
            }
        }
        Err(_) => println!("[!] MaliciousLinks.txt not found, skipping that feed"),
    }

    if urls.is_empty() {
        println!("[!] No URL feeds found, skipping urlhaus bloom");
        return;
    }
    println!("[+] URL bloom (urlhaus + malwareurl) unique items: {}", urls.len());
    let bloom = make_bloom(urls.len());
    for u in &urls {
        bloom.insert(u.as_str());
    }
    save_bloom(&bloom, &format!("{}/malwareurl.bloom", dir));
}

// ── phishing ───────────────────────────────────────────────────────────────

fn build_phishing_bloom(dir: &str) {
    let path = Path::new(dir).join("phishing_links.json");
    if !path.exists() {
        println!("[!] phishing_links.json not found, skipping");
        return;
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return;
        }
    };

    let urls: Vec<String> = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content)
    {
        parsed
            .get("data")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|u| u.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    };

    let total = urls.len();
    println!("[+] Phishing expected items: {}", total);
    let bloom = make_bloom(total);
    for u in &urls {
        bloom.insert(u.as_str());
    }
    save_bloom(&bloom, &format!("{}/phishing.bloom", dir));
}


