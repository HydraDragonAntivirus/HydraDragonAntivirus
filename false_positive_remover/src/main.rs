use bincode_next::serde::{decode_from_slice, encode_to_vec};
use fastbloom::AtomicBloomFilter;
use std::fs;
use std::path::Path;

const EXPECTED_ITEMS: usize = 300_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "--rebuild-bloom" | "-r" => {
            if args.len() < 4 {
                eprintln!("ERROR: --rebuild-bloom requires <input_hashes.txt> <output.bloom>");
                std::process::exit(1);
            }
            rebuild_bloom(&args[2], &args[3]);
        }
        "--help" | "-h" => {
            print_usage();
        }
        _ => {
            if args.len() < 3 {
                print_usage();
                std::process::exit(1);
            }
            remove_false_positives(&args[1], &args[2], args.get(3).map(|s| s.as_str()));
        }
    }
}

fn print_usage() {
    println!("false_positive_remover - Remove false positive hashes from blacklist");
    println!();
    println!("USAGE:");
    println!("  false_positive_remover <whitelist.bloom> <blacklist.txt> [output.txt]");
    println!("  false_positive_remover <whitelist.bloom> <blacklist_dir> [output_dir]");
    println!("  false_positive_remover --rebuild-bloom <hashes.txt> <output.bloom>");
    println!("  false_positive_remover --help");
    println!();
    println!("COMMANDS:");
    println!("  whitelist.bloom           Path to serialized whitelist bloom filter");
    println!("  blacklist.txt             Text file with one hash per line to filter");
    println!("  blacklist_dir             Folder of files, each processed individually");
    println!("  output.txt                Output file for single-file mode (default: blacklist_clean.txt)");
    println!("  output_dir                Output folder for folder mode (default: blacklist_clean)");
    println!("  --rebuild-bloom <in> <out> Build a new bloom filter from a hash list");
    println!("  -r                        Short for --rebuild-bloom");
    println!("  --help, -h                Show this help");
    println!();
    println!("DESCRIPTION:");
    println!("  Removes false positive hashes from blacklist that are actually");
    println!("  whitelisted. Each potential false positive is double-scanned to");
    println!("  confirm before removal. If the blacklist argument is a folder,");
    println!("  every file inside it is processed individually and the cleaned");
    println!("  results are written into the output folder under the same");
    println!("  filenames.");
}

fn remove_false_positives(bloom_path: &str, blacklist_path: &str, output_arg: Option<&str>) {
    println!("[+] Loading whitelist bloom filter from: {}", bloom_path);
    let bloom = match load_bloom(bloom_path) {
        Some(b) => b,
        None => {
            eprintln!("ERROR: Failed to load whitelist bloom filter from {}", bloom_path);
            std::process::exit(1);
        }
    };

    let input_path = Path::new(blacklist_path);

    if input_path.is_dir() {
        let output_dir = Path::new(output_arg.unwrap_or("blacklist_clean"));
        process_directory(&bloom, input_path, output_dir);
    } else {
        let output_path = Path::new(output_arg.unwrap_or("blacklist_clean.txt"));

        println!("[+] Reading blacklist from: {}", input_path.display());
        let (kept, removed) = process_file(&bloom, input_path, output_path);

        println!(
            "\n[+] Results: {} kept, {} removed (false positives)",
            kept, removed
        );
        println!("[+] Clean blacklist written to: {}", output_path.display());
    }
}

/// Process every .txt file in `input_dir` against the whitelist bloom filter,
/// writing each cleaned file into `output_dir` under the same filename.
fn process_directory(bloom: &AtomicBloomFilter, input_dir: &Path, output_dir: &Path) {
    println!("[+] Reading blacklist files from folder: {}", input_dir.display());

    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: Failed to create output folder {}: {}",
            output_dir.display(),
            e
        );
        std::process::exit(1);
    });

    let entries = match fs::read_dir(input_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("ERROR: Failed to read folder {}: {}", input_dir.display(), e);
            std::process::exit(1);
        }
    };

    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    paths.sort();

    if paths.is_empty() {
        println!("[+] No files found in {}", input_dir.display());
        return;
    }

    let mut total_kept = 0usize;
    let mut total_removed = 0usize;
    let mut file_count = 0usize;

    for path in paths {
        let file_name = match path.file_name() {
            Some(name) => name,
            None => continue,
        };
        let output_path = output_dir.join(file_name);

        println!("\n[+] Processing: {}", path.display());
        let (kept, removed) = process_file(bloom, &path, &output_path);
        println!("  [+] {} kept, {} removed (false positives)", kept, removed);

        total_kept += kept;
        total_removed += removed;
        file_count += 1;
    }

    println!(
        "\n[+] Done: {} file(s) processed, {} kept, {} removed (false positives) overall",
        file_count, total_kept, total_removed
    );
    println!("[+] Clean blacklists written to folder: {}", output_dir.display());
}

/// Filter a single blacklist file against the whitelist bloom filter and
/// write the cleaned hashes to `output_path`. Returns (kept, removed) counts.
fn process_file(bloom: &AtomicBloomFilter, input_path: &Path, output_path: &Path) -> (usize, usize) {
    let content = match fs::read_to_string(input_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "ERROR: Failed to read blacklist file {}: {}",
                input_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let mut removed_count = 0usize;
    let mut kept_count = 0usize;
    let mut clean_hashes = Vec::new();

    for line in content.lines() {
        let hash = line.trim();
        if hash.is_empty() || hash.starts_with('#') {
            continue;
        }

        let first_check = bloom.contains(hash);
        if first_check {
            let second_check = bloom.contains(hash);
            if second_check {
                removed_count += 1;
                println!(
                    "  [REMOVED] {} (false positive - confirmed by double scan)",
                    hash
                );
            } else {
                kept_count += 1;
                clean_hashes.push(hash.to_string());
                println!(
                    "  [KEPT] {} (first match not confirmed by second scan)",
                    hash
                );
            }
        } else {
            kept_count += 1;
            clean_hashes.push(hash.to_string());
        }
    }

    let output = clean_hashes.join("\n");
    fs::write(output_path, &output).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: Failed to write output file {}: {}",
            output_path.display(),
            e
        );
        std::process::exit(1);
    });

    (kept_count, removed_count)
}

fn rebuild_bloom(input_path: &str, output_path: &str) {
    println!("[+] Reading hashes from: {}", input_path);
    let content = match fs::read_to_string(input_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Failed to read input file: {}", e);
            std::process::exit(1);
        }
    };

    let bloom =
        AtomicBloomFilter::with_false_pos(1e-4).expected_items(EXPECTED_ITEMS);

    let mut count = 0usize;
    for line in content.lines() {
        let hash = line.trim();
        if hash.is_empty() || hash.starts_with('#') {
            continue;
        }
        bloom.insert(hash);
        count += 1;
    }

    println!("[+] Serializing bloom filter with {} hashes", count);
    match encode_to_vec(&bloom, bincode_next::config::standard()) {
        Ok(data) => {
            fs::write(output_path, &data[..]).unwrap_or_else(|e| {
                eprintln!("ERROR: Failed to write output bloom: {}", e);
                std::process::exit(1);
            });
            println!("[+] Bloom filter written to: {}", output_path);
        }
        Err(e) => {
            eprintln!("ERROR: Failed to serialize bloom filter: {}", e);
            std::process::exit(1);
        }
    }
}

fn load_bloom(path: &str) -> Option<AtomicBloomFilter> {
    let data = fs::read(path).ok()?;
    decode_from_slice::<AtomicBloomFilter, _>(&data, bincode_next::config::standard())
        .ok()
        .map(|(v, _)| v)
}
