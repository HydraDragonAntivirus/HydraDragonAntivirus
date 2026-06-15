use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use burn::backend::ndarray::NdArrayDevice;
use burn::module::{AutodiffModule, Module};
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder};

use owlyshield_ransom::ml::features::JsFeatureVector;
use owlyshield_ransom::ml::pe_features;
use owlyshield_ransom::ml::train::{MalwareNet, MalwareNetConfig, Sample, train_model};

fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk_dir(&path));
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files
}

fn extract_pe_samples(malicious: &[PathBuf], benign: &[PathBuf]) -> Vec<Sample> {
    let total = malicious.len() + benign.len();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut samples = Vec::with_capacity(total);

    for files in [malicious, benign] {
        for path in files {
            let count = counter.fetch_add(1, Ordering::Relaxed);
            eprint!("\rExtracting PE features... {}/{}", count, total);

            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let features = match pe_features::extract_pe_features(&bytes) {
                Some(f) => f,
                None => continue,
            };

            let label = if std::ptr::eq(files, malicious) { 1 } else { 0 };
            samples.push(Sample { features: features.to_array().to_vec(), label });
        }
    }

    eprintln!("\rExtracted {} PE samples", samples.len());
    samples
}

fn parse_flag(args: &[String], flag: &str, default: &str) -> String {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    default.to_string()
}

fn run_pe(args: &[String]) {
    let malicious_dir = parse_flag(args, "--malicious", "");
    let benign_dir = parse_flag(args, "--benign", "");
    let epochs: usize = parse_flag(args, "--epochs", "10").parse().unwrap_or(10);
    let batch_size: usize = parse_flag(args, "--batch", "64").parse().unwrap_or(64);
    let lr: f64 = parse_flag(args, "--lr", "0.001").parse().unwrap_or(0.001);
    let output = parse_flag(args, "--output", "model_pe");

    if malicious_dir.is_empty() || benign_dir.is_empty() {
        eprintln!("Error: --malicious and --benign are required");
        std::process::exit(1);
    }

    let mal_path = Path::new(&malicious_dir);
    let ben_path = Path::new(&benign_dir);

    if !mal_path.is_dir() { eprintln!("Error: malicious directory '{malicious_dir}' not found"); std::process::exit(1); }
    if !ben_path.is_dir() { eprintln!("Error: benign directory '{benign_dir}' not found"); std::process::exit(1); }

    let samples = extract_pe_samples(&walk_dir(mal_path), &walk_dir(ben_path));
    if samples.is_empty() { eprintln!("No valid PE samples"); std::process::exit(1); }

    let num_malicious = samples.iter().filter(|s| s.label == 1).count();
    eprintln!("Samples: {} malicious, {} benign", num_malicious, samples.len() - num_malicious);

    type Backend = burn::backend::NdArray<f32>;
    type ADBackendImpl = burn::backend::Autodiff<Backend>;
    let device = NdArrayDevice::Cpu;

    eprintln!("Training PE model: epochs={epochs}, batch_size={batch_size}, lr={lr}");
    let model: MalwareNet<ADBackendImpl> = train_model::<ADBackendImpl>(
        ADBackendImpl::Device::from(device),
        samples,
        MalwareNetConfig::default(),
        epochs,
        batch_size,
        lr,
    );

    let model_infer: MalwareNet<Backend> = model.valid();
    let recorder = NamedMpkFileRecorder::<FullPrecisionSettings>::new();
    let output_path = Path::new(&output).join("pe_model");
    model_infer.save_file(output_path, &recorder).unwrap();
    eprintln!("Model saved to {}/pe_model.mpk", output);
}

fn run_js(args: &[String]) {
    let malicious_dir = parse_flag(args, "--malicious", "");
    let benign_dir = parse_flag(args, "--benign", "");
    let epochs: usize = parse_flag(args, "--epochs", "10").parse().unwrap_or(10);
    let batch_size: usize = parse_flag(args, "--batch", "64").parse().unwrap_or(64);
    let lr: f64 = parse_flag(args, "--lr", "0.001").parse().unwrap_or(0.001);
    let output = parse_flag(args, "--output", "model_js");

    if malicious_dir.is_empty() || benign_dir.is_empty() {
        eprintln!("Error: --malicious and --benign are required");
        std::process::exit(1);
    }

    let mal_path = Path::new(&malicious_dir);
    let ben_path = Path::new(&benign_dir);

    if !mal_path.is_dir() { eprintln!("Error: malicious directory '{malicious_dir}' not found"); std::process::exit(1); }
    if !ben_path.is_dir() { eprintln!("Error: benign directory '{benign_dir}' not found"); std::process::exit(1); }

    let mal_files = walk_dir(mal_path);
    let ben_files = walk_dir(ben_path);
    eprintln!("Found {} malicious, {} benign files", mal_files.len(), ben_files.len());

    let mut samples = Vec::new();
    let total = mal_files.len() + ben_files.len();
    let mut count = 0usize;

    for (files, label) in [(&mal_files, 1), (&ben_files, 0)] {
        for path in files {
            count += 1;
            eprint!("\rExtracting JS features... {}/{}", count, total);

            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let features = match owlyshield_ransom::ml::js_features::extract_js_features(&source) {
                Some(f) => f,
                None => continue,
            };

            samples.push(Sample { features: features.to_array().to_vec(), label });
        }
    }

    eprintln!("\rExtracted {} JS samples", samples.len());
    if samples.is_empty() { eprintln!("No valid JS samples"); std::process::exit(1); }

    let num_malicious = samples.iter().filter(|s| s.label == 1).count();
    eprintln!("Samples: {} malicious, {} benign", num_malicious, samples.len() - num_malicious);

    type Backend = burn::backend::NdArray<f32>;
    type ADBackendImpl = burn::backend::Autodiff<Backend>;
    let device = NdArrayDevice::Cpu;

    let config = MalwareNetConfig {
        input_dim: JsFeatureVector::LEN,
        ..Default::default()
    };

    eprintln!("Training JS model: epochs={epochs}, batch_size={batch_size}, lr={lr}");
    let model: MalwareNet<ADBackendImpl> = train_model::<ADBackendImpl>(
        ADBackendImpl::Device::from(device),
        samples,
        config,
        epochs,
        batch_size,
        lr,
    );

    let model_infer: MalwareNet<Backend> = model.valid();
    let recorder = NamedMpkFileRecorder::<FullPrecisionSettings>::new();
    let output_path = Path::new(&output).join("js_model");
    model_infer.save_file(output_path, &recorder).unwrap();
    eprintln!("Model saved to {}/js_model.mpk", output);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} pe --malicious <dir> --benign <dir> [--epochs N] [--batch N] [--lr F] [--output <path>]", args[0]);
        eprintln!("  {} js --malicious <dir> --benign <dir> [--epochs N] [--batch N] [--lr F] [--output <path>]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "pe" => run_pe(&args[2..]),
        "js" => run_js(&args[2..]),
        m => { eprintln!("Unknown mode: {m}. Use 'pe' or 'js'."); std::process::exit(1); }
    }
}
