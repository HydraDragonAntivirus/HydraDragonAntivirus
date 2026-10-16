//! js_feature_dump — JavaScript ML features with the engine's own extractor.
//!
//!   js_feature_dump <malicious_dir> <benign_dir> <out.csv> [max_per_class]
//!   js_feature_dump @<malicious.lst> @<benign.lst> <out.csv> [max_per_class]
//!
//! A `@` argument is a UTF-8 list of files, one path per line (train_js_lgbm.py writes
//! them from every folder in dataset_paths.json, duplicates already removed).
//!
//! Includes OpenEDR/openedr_static/src/ml/{features,js_features}.rs by path, so the
//! features train_js_lgbm.py learns from are byte for byte what the engine computes at
//! scan time. Files the extractor rejects (not valid JS) are skipped, as in the engine.
//! No extension filter: every UTF-8 file is offered to the extractor, which decides
//! by content. `max_per_class` 0 (or missing) = unlimited.
//! Output: CSV with `label,path,<51 features>` (label 1 = malicious).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;

// At the crate root: js_features.rs refers to `super::features`.
#[allow(dead_code)]
#[path = "../../../OpenEDR/openedr_static/src/ml/features.rs"]
mod features;
#[allow(dead_code)]
#[path = "../../../OpenEDR/openedr_static/src/ml/js_features.rs"]
mod js_features;

fn walk(dir: &Path, max: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
                if out.len() >= max {
                    return out;
                }
            }
        }
    }
    out
}

/// Files of a folder (`dir`) or of a list file (`@list`), at most `max`.
fn inputs(arg: &str, max: usize) -> Vec<PathBuf> {
    match arg.strip_prefix('@') {
        Some(list) => {
            let text = std::fs::read_to_string(list).unwrap_or_else(|e| {
                eprintln!("cannot read file list {list}: {e}");
                std::process::exit(2);
            });
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .take(max)
                .collect()
        }
        None => walk(Path::new(arg), max),
    }
}

fn extract(files: &[PathBuf], label: u8) -> Vec<(u8, String, [f32; 51])> {
    let done = AtomicUsize::new(0);
    let total = files.len();
    files
        .par_iter()
        .filter_map(|p| {
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 2000 == 0 || n == total {
                eprintln!("  label {label}: {n}/{total}");
            }
            let bytes = std::fs::read(p).ok()?;
            let src = String::from_utf8(bytes).ok()?; // the engine only scores UTF-8 text
            let f = std::panic::catch_unwind(|| js_features::extract_js_features(&src)).ok()??;
            Some((label, p.display().to_string(), f.to_array()))
        })
        .collect()
}

/// Stack for the main work thread and every extraction worker. Deeply nested JS
/// recurses deep in the parser and AST walkers, and a stack overflow cannot be caught
/// (it aborts the process), so give every thread far more than it will use; only the
/// pages actually touched are committed.
const STACK: usize = 512 * 1024 * 1024;

fn main() {
    rayon::ThreadPoolBuilder::new().stack_size(STACK).build_global().expect("thread pool");
    let worker = std::thread::Builder::new().stack_size(STACK).spawn(run).expect("work thread");
    if worker.join().is_err() {
        std::process::exit(1);
    }
}

fn run() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("usage: js_feature_dump <malicious_dir|@list> <benign_dir|@list> <out.csv> [max_per_class]");
        std::process::exit(2);
    }
    std::panic::set_hook(Box::new(|_| {})); // parser panics on odd input: skip the file quietly
    let max = a.get(4).and_then(|v| v.parse().ok()).filter(|&m: &usize| m > 0).unwrap_or(usize::MAX);
    let mal = inputs(&a[1], max);
    let ben = inputs(&a[2], max);
    eprintln!("[+] {} malicious, {} benign files", mal.len(), ben.len());
    let mut rows = extract(&mal, 1);
    rows.extend(extract(&ben, 0));

    let mut w = std::io::BufWriter::new(std::fs::File::create(&a[3]).expect("cannot create output"));
    let mut header = String::from("label,path");
    for name in NAMES {
        header.push(',');
        header.push_str(name);
    }
    writeln!(w, "{header}").unwrap();
    for (label, path, f) in &rows {
        let vals: Vec<String> = f.iter().map(|v| v.to_string()).collect();
        writeln!(w, "{label},\"{}\",{}", path.replace('"', "'"), vals.join(",")).unwrap();
    }
    w.flush().unwrap();
    let m = rows.iter().filter(|r| r.0 == 1).count();
    eprintln!("[+] wrote {} rows ({} malicious, {} benign; rejected files skipped) to {}", rows.len(), m, rows.len() - m, a[3]);
}

/// `JsFeatureVector::to_array` order.
const NAMES: [&str; 51] = [
    "file_size", "entropy", "parse_success", "function_count", "variable_declarations",
    "call_expressions", "member_expressions", "binary_expressions", "conditional_statements",
    "loop_statements", "try_catch_blocks", "array_literals", "object_literals", "max_nesting_depth",
    "eval_usage", "suspicious_call_count", "hex_encoded_strings", "unicode_encoded_strings",
    "char_code_usage", "base64_usage", "escape_usage", "bracket_notation_calls", "obfuscation_score",
    "is_obfuscated", "crypto_references", "network_operations", "file_system_operations",
    "registry_operations", "process_operations", "suspicious_api_calls", "suspicious_score",
    "total_strings", "avg_string_length", "max_string_length", "long_strings_count",
    "base64_like_strings", "url_strings", "hex_strings", "total_lines", "code_lines", "comment_lines",
    "blank_lines", "avg_line_length", "max_line_length", "cyclomatic_complexity", "total_identifiers",
    "short_identifiers", "long_identifiers", "avg_identifier_length", "suspicious_naming",
    "random_like_identifiers",
];
