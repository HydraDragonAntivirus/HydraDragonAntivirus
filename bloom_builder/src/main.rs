use bincode_next::serde::encode_to_vec;
use fastbloom::AtomicBloomFilter;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

const FP_RATE: f64 = 1e-4;
const EXPECTED_ITEMS: usize = 20_000_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "blacklist" | "bl" => {
            if args.len() < 3 {
                eprintln!("ERROR: Usage: bloom_builder blacklist <hashes_dir> [output.bloom]");
                std::process::exit(1);
            }
            let hashes_dir = &args[2];
            let output = args.get(3).map(|s| s.as_str()).unwrap_or("blacklist.bloom");
            build_blacklist_bloom(hashes_dir, output);
        }
        "whitelist" | "wl" => {
            let all_types = args.iter().any(|a| a == "--all-types");
            let pos_args: Vec<&String> = args.iter().skip(2).filter(|a| !a.starts_with("--")).collect();
            if pos_args.is_empty() {
                eprintln!("ERROR: Usage: bloom_builder whitelist [--all-types] <whitelist.db> [sql_file] [output.bloom]");
                std::process::exit(1);
            }
            let db_path = pos_args[0];
            let sql_file = pos_args.get(1).map(|s| s.as_str());
            let output = pos_args.get(2).map(|s| s.as_str()).unwrap_or("whitelist.bloom");
            build_whitelist_bloom(db_path, sql_file, output, all_types);
        }
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("bloom_builder - Build bloom filters from hash databases");
    println!();
    println!("USAGE:");
    println!("  bloom_builder blacklist <hashes_dir> [output.bloom]");
    println!("  bloom_builder whitelist [--all-types] <whitelist.db> [sql_file] [output.bloom]");
    println!("");
    println!("FLAGS:");
    println!("  --all-types    Include SHA1/SHA256 from SQL (for FP remover bloom)");
    println!();
    println!("COMMANDS:");
    println!("  blacklist (bl)  Build blacklist bloom from hashes directory");
    println!("                  Supports: full.csv, md5_db, sha256_db, tlsh_db,");
    println!("                  virusshare1/2, malshare, malsharesha1/256,");
    println!("                  eset, sslbl, virusign, virussign, iocemotet,");
    println!("                  samplesstalkware, sha256amnestytech");
    println!("  whitelist (wl)  Build whitelist bloom from whitelist.db (MD5 only)");
    println!();
    println!("  Default output: blacklist.bloom / whitelist.bloom");
}

/// Build blacklist bloom from all hash files in the hashes directory
fn build_blacklist_bloom(hashes_dir: &str, output_path: &str) {
    let bloom =
        Arc::new(AtomicBloomFilter::with_false_pos(FP_RATE).expected_items(EXPECTED_ITEMS));

    println!("[+] Building BLACKLIST bloom from: {}", hashes_dir);
    let dir = Path::new(hashes_dir);

    // Process MalwareBazaar full.csv
    let csv_path = dir.join("full.csv");
    if csv_path.exists() {
        process_full_csv(&csv_path, &bloom);
    }

    // Process individual hash files
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let fname = path.file_name().unwrap().to_string_lossy().to_string();
        if fname == "full.csv" {
            continue;
        }

        match fname.as_str() {
            "md5_db" | "sha256_db" | "tlsh_db" | "sslbl" | "virusign" => {
                process_colon_file(&path, &bloom);
            }
            "virusshare1" | "virusshare2" | "virusshare2026.md5" => {
                process_plain_hash_file(&path, &bloom);
            }
            "malshare" => {
                process_plain_hash_file(&path, &bloom);
            }
            _ => {
                process_plain_hash_file(&path, &bloom);
            }
        }
    }

    let count = 0; // AtomicBloomFilter does not expose count
    println!("[+] Blacklist bloom built");

    save_bloom(&bloom, output_path);
}

/// Build whitelist bloom from whitelist.db (MD5 only, one hash per line)
fn build_whitelist_bloom(db_path: &str, sql_file: Option<&str>, output_path: &str, all_types: bool) {
    let bloom = Arc::new(
        AtomicBloomFilter::with_false_pos(FP_RATE).expected_items(EXPECTED_ITEMS),
    );

    let mut count = 0u64;

    println!("[+] Building WHITELIST bloom from: {}", db_path);
    let path = Path::new(db_path);
    if !path.exists() {
        eprintln!("ERROR: Whitelist db not found: {}", db_path);
        std::process::exit(1);
    }

    let file = match fs::File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            eprintln!("ERROR: Cannot open {}: {}", db_path, e);
            std::process::exit(1);
        }
    };

    for line in file.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let hash = line.trim();
        if hash.is_empty() || hash.starts_with('#') {
            continue;
        }
        if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bloom.insert(hash);
            count += 1;
        }
    }
    println!("[+] MD5 hashes from whitelist.db: {}", count);

    if let Some(sql_path) = sql_file {
        println!("[+] Also loading SQL hashes from: {}", sql_path);
        let sql_count = build_whitelist_from_sql(&bloom, sql_path, all_types);
        count += sql_count;
    }

    println!("[+] Total hashes in whitelist bloom: {}", count);
    save_bloom(&bloom, output_path);
}

/// Save bloom filter to file
fn save_bloom(bloom: &Arc<AtomicBloomFilter>, output_path: &str) {
    match encode_to_vec(bloom.as_ref(), bincode_next::config::standard()) {
        Ok(data) => {
            fs::write(output_path, &data[..]).unwrap_or_else(|e| {
                eprintln!("ERROR: Failed to write bloom: {}", e);
                std::process::exit(1);
            });
            println!("[+] Bloom written to: {} ({} bytes)", output_path, data.len());
        }
        Err(e) => {
            eprintln!("ERROR: Failed to serialize bloom: {}", e);
            std::process::exit(1);
        }
    }
}

/// Parse MalwareBazaar CSV: extracts SHA256(1), MD5(2), SHA1(3), SSDEEP(12), TLSH(13)
fn process_full_csv(path: &Path, bloom: &Arc<AtomicBloomFilter>) {
    println!("  [full.csv] Parsing MalwareBazaar...");
    let file = match fs::File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            eprintln!("    ERROR: {}", e);
            return;
        }
    };

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(file);

    let mut count = 0u64;
    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        if count % 100000 == 0 && count > 0 {
            println!("    [full.csv] {} records...", count);
        }

        if let Some(field) = record.get(1) {
            let h = field.trim().trim_matches('"');
            if !h.is_empty() && h.len() == 64 {
                bloom.insert(h);
            }
        }
        if let Some(field) = record.get(2) {
            let h = field.trim().trim_matches('"');
            if !h.is_empty() && h.len() == 32 {
                bloom.insert(h);
            }
        }
        if let Some(field) = record.get(3) {
            let h = field.trim().trim_matches('"');
            if !h.is_empty() && h.len() == 40 {
                bloom.insert(h);
            }
        }
        if let Some(field) = record.get(12) {
            let h = field.trim().trim_matches('"');
            if !h.is_empty() && h != "n/a" {
                bloom.insert(h);
            }
        }
        if let Some(field) = record.get(13) {
            let h = field.trim().trim_matches('"');
            if !h.is_empty() && h != "n/a" {
                bloom.insert(h);
            }
        }

        count += 1;
    }
    println!("    [full.csv] Done: {} records", count);
}

/// Parse colon-separated: `hash:metadata`
fn process_colon_file(path: &Path, bloom: &Arc<AtomicBloomFilter>) {
    let fname = path.file_name().unwrap().to_string_lossy();
    println!("  [{}] Parsing...", fname);

    let file = match fs::File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            eprintln!("    ERROR: {}", e);
            return;
        }
    };

    let mut count = 0u64;
    for line in file.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(hash) = trimmed.split(':').next() {
            let hash = hash.trim();
            if !hash.is_empty() {
                bloom.insert(hash);
                count += 1;
            }
        }
    }
    println!("    [{}] Done: {} hashes", fname, count);
}

/// Parse plain hash files: one hash per line
fn process_plain_hash_file(path: &Path, bloom: &Arc<AtomicBloomFilter>) {
    let fname = path.file_name().unwrap().to_string_lossy();
    println!("  [{}] Parsing...", fname);

    let file = match fs::File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            eprintln!("    ERROR: {}", e);
            return;
        }
    };

    let mut count = 0u64;
    for line in file.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let hash = line.trim();
        if hash.is_empty() {
            continue;
        }
        bloom.insert(hash);
        count += 1;
    }
    println!("    [{}] Done: {} hashes", fname, count);
}

fn build_whitelist_from_sql(bloom: &Arc<AtomicBloomFilter>, sql_path: &str, all_types: bool) -> u64 {
    let content = match fs::read_to_string(sql_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Cannot read SQL file '{}': {}", sql_path, e);
            std::process::exit(1);
        }
    };

    let mut count = 0u64;
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("INSERT INTO METADATA") {
            continue;
        }
        let values_start = match line.find("VALUES(") {
            Some(pos) => pos + 7,
            None => continue,
        };
        let values_end = match line.rfind(')') {
            Some(pos) => pos,
            None => continue,
        };
        let values = &line[values_start..values_end];
        let parts: Vec<&str> = values.split(',').collect();
        if parts.len() < 23 {
            continue;
        }
        let md5 = trim_quotes(parts[20]);
        if !md5.is_empty() && md5.len() == 32 && md5.chars().all(|c| c.is_ascii_hexdigit()) {
            bloom.insert(md5);
            count += 1;
        }
        if all_types {
            let sha1 = trim_quotes(parts[21]);
            let sha256 = trim_quotes(parts[22]);
            if !sha1.is_empty() && sha1.len() == 40 && sha1.chars().all(|c| c.is_ascii_hexdigit()) {
                bloom.insert(sha1);
                count += 1;
            }
            if !sha256.is_empty() && sha256.len() == 64 && sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                bloom.insert(sha256);
                count += 1;
            }
        }
    }
    count
}

fn trim_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.as_bytes()[0] == b'\'' && s.as_bytes()[s.len() - 1] == b'\'' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

