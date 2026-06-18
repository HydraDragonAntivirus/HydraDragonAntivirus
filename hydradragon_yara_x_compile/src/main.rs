use std::fs;
use std::path::{Path, PathBuf};
use yara_x::Compiler;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let check_only = args.iter().any(|a| a == "--check");

    // Filter out flags for positional args
    let pos_args: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    let need_help = pos_args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h");

    if need_help {
        eprintln!("Usage: hydradragon_yara_x_compile [--check] <source_dir> [<output_dir>]");
        eprintln!();
        eprintln!("  --check       Only validate compilation, do not write .yrc files");
        eprintln!("  <source_dir>  Directory to scan for .yar files (recursive)");
        eprintln!("  <output_dir>  Directory for output .yrc files (required unless --check)");
        std::process::exit(if need_help { 0 } else { 1 });
    }

    let src_dir = Path::new(pos_args[1]);

    if !src_dir.is_dir() {
        eprintln!("ERROR: source directory not found: {}", src_dir.display());
        std::process::exit(1);
    }

    let out_dir = if check_only {
        None
    } else {
        let dir = Path::new(pos_args[2]);
        fs::create_dir_all(dir).unwrap_or_else(|e| {
            eprintln!("ERROR: cannot create output directory: {}", e);
            std::process::exit(1);
        });
        Some(dir.to_path_buf())
    };

    let mut yar_files: Vec<PathBuf> = Vec::new();
    collect_yar_files(src_dir, &mut yar_files);

    if yar_files.is_empty() {
        eprintln!("No .yar files found in {}", src_dir.display());
        std::process::exit(0);
    }

    let mut errors = 0;

    for path in &yar_files {
        let stem = path.file_stem().unwrap().to_string_lossy();

        if let Some(ref out_dir) = out_dir {
            let out_path = out_dir.join(format!("{}.yrc", stem));
            if out_path.exists() {
                let src_modified = path
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                let out_modified = out_path
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                if out_modified >= src_modified {
                    eprintln!("[SKIP] {} (up to date)", stem);
                    continue;
                }
            }
        }

        let source = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ERROR] reading {}: {}", path.display(), e);
                errors += 1;
                continue;
            }
        };

        let mut compiler = Compiler::new();
        if let Err(e) = compiler.add_source(source.as_str()) {
            eprintln!("[ERROR] compiling {}: {}", path.display(), e);
            errors += 1;
            continue;
        }

        let rules = compiler.build();

        if let Some(ref out_dir) = out_dir {
            let out_path = out_dir.join(format!("{}.yrc", stem));
            let serialized = match rules.serialize() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[ERROR] serializing {}: {}", path.display(), e);
                    errors += 1;
                    continue;
                }
            };

            if let Err(e) = fs::write(&out_path, &serialized) {
                eprintln!("[ERROR] writing {}: {}", out_path.display(), e);
                errors += 1;
                continue;
            }

            eprintln!("[OK] {} ({} bytes)", stem, serialized.len());
        } else {
            eprintln!("[OK] {} (valid)", stem);
        }
    }

    if errors > 0 {
        eprintln!("{} / {} files failed", errors, yar_files.len());
        std::process::exit(1);
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
