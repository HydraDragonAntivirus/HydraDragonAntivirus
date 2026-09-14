use burn::backend::ndarray::NdArrayDevice;
use owlyshield_ransom::ml::fast_detect::load_ml_model;
use owlyshield_ransom::ml::inference::predict_pe;
use owlyshield_ransom::ml::model::MalwareNetConfig;
use std::path::{Path, PathBuf};

fn walk_files(dir: &Path, max_files: usize) -> Vec<PathBuf> {
    if dir.is_file() {
        return vec![dir.to_path_buf()];
    }
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        if files.len() >= max_files {
            break;
        }
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
                if files.len() >= max_files {
                    break;
                }
            }
        }
    }
    files
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example eval_pe_scanner -- <target_directory> [max_samples]");
        return;
    }

    let target_dir = Path::new(&args[1]);
    let max_samples: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let model_path = manifest_dir.join("models").join("pe_model.mpk");

    println!("[*] Loading PE ML model from: {}", model_path.display());
    let model = load_ml_model(&model_path, MalwareNetConfig::default())
        .expect("Failed to load PE model");
    let device = NdArrayDevice::default();
    println!("[+] PE model loaded successfully!");

    println!("[*] Scanning directory: {} (max {} samples)", target_dir.display(), max_samples);
    let files = walk_files(target_dir, max_samples);
    println!("[*] Found {} candidate files", files.len());

    let mut scanned = 0usize;
    let mut skipped = 0usize;

    let mut b_high = 0usize; // > 50%
    let mut b_susp = 0usize; // 30% - 50%
    let mut b_low  = 0usize; // 10% - 30%
    let mut b_safe = 0usize; // < 10%

    for path in &files {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        if !bytes.starts_with(b"MZ") {
            skipped += 1;
            continue;
        }

        match predict_pe(&bytes, &model, &device) {
            Some(prob) => {
                scanned += 1;
                if prob >= 0.50 {
                    b_high += 1;
                    println!("  [HIGH-MALICIOUS: {:.2}%] {}", prob * 100.0, path.display());
                } else if prob >= 0.30 {
                    b_susp += 1;
                    println!("  [SUSPICIOUS:     {:.2}%] {}", prob * 100.0, path.display());
                } else if prob >= 0.10 {
                    b_low += 1;
                } else {
                    b_safe += 1;
                }
            }
            None => {
                skipped += 1;
            }
        }
    }

    println!("\n================ SCAN SUMMARY ================");
    println!("Target:         {}", target_dir.display());
    println!("Scanned PEs:    {}", scanned);
    println!("  -> High Malicious (>=50%): {} ({:.1}%)", b_high, if scanned > 0 { b_high as f64 / scanned as f64 * 100.0 } else { 0.0 });
    println!("  -> Suspicious     (30-50%):{} ({:.1}%)", b_susp, if scanned > 0 { b_susp as f64 / scanned as f64 * 100.0 } else { 0.0 });
    println!("  -> Low Risk       (10-30%):{} ({:.1}%)", b_low, if scanned > 0 { b_low as f64 / scanned as f64 * 100.0 } else { 0.0 });
    println!("  -> Clean / Safe    (<10%):  {} ({:.1}%)", b_safe, if scanned > 0 { b_safe as f64 / scanned as f64 * 100.0 } else { 0.0 });
    println!("Skipped / Non-PE: {}", skipped);
    println!("==============================================");
}
