use std::fs;
use std::path::{Path, PathBuf};
use yara_x::compiler::{Compiler, CompileError};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: hydradragon_yara_x_compile <source_dir> <output_dir>");
        std::process::exit(1);
    }

    let src_dir = Path::new(&args[1]);
    let out_dir = Path::new(&args[2]);

    if !src_dir.is_dir() {
        eprintln!("ERROR: source directory not found: {}", src_dir.display());
        std::process::exit(1);
    }

    fs::create_dir_all(out_dir).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot create output directory: {}", e);
        std::process::exit(1);
    });

    let mut yar_files: Vec<PathBuf> = Vec::new();
    collect_yar_files(src_dir, &mut yar_files);

    if yar_files.is_empty() {
        eprintln!("No .yar files found in {}", src_dir.display());
        std::process::exit(0);
    }

    for path in &yar_files {
        let stem = path.file_stem().unwrap().to_string_lossy();
        let out_path = out_dir.join(format!("{}.yrc", stem));

        if out_path.exists() {
            let src_modified = path.metadata().map(|m| m.modified()).ok().and_then(|r| r.ok()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let out_modified = out_path.metadata().map(|m| m.modified()).ok().and_then(|r| r.ok()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if out_modified >= src_modified {
                eprintln!("[SKIP] {} (up to date)", stem);
                continue;
            }
        }

        eprintln!("[COMPILE] {} -> {}", stem, out_path.display());

        let source = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ERROR] reading {}: {}", path.display(), e);
                continue;
            }
        };

        let mut compiler = Compiler::new();
        if let Err(e) = compiler.add_source(&source) {
            eprintln!("[ERROR] compiling {}: {}", path.display(), e);
            continue;
        }

        let rules = compiler.build();

        let serialized = match rules.serialize() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[ERROR] serializing {}: {}", path.display(), e);
                continue;
            }
        };

        if let Err(e) = fs::write(&out_path, &serialized) {
            eprintln!("[ERROR] writing {}: {}", out_path.display(), e);
            continue;
        }

        eprintln!("[OK] {} ({} bytes)", stem, serialized.len());
    }
}

fn collect_yar_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yar_files(&path, files);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yar") {
            files.push(path);
        }
    }
}
