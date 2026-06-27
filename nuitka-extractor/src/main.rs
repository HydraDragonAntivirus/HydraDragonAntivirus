use std::{
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result};
use nuitka_extractor::NuitkaExtractor;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: nuitka-extractor <filename>");
        std::process::exit(1);
    }

    let path = PathBuf::from(&args[1]);
    let extractor = NuitkaExtractor::open(&path)
        .with_context(|| format!("Failed to open {}", path.display()))?;

    println!("[+] Processing {}", path.display());
    println!(
        "[+] File type: {}",
        match extractor.kind {
            nuitka_extractor::FileKind::Pe => "PE",
            nuitka_extractor::FileKind::Elf => "ELF",
        }
    );
    println!(
        "[+] Payload compression: {}",
        match extractor.compression {
            nuitka_extractor::Compression::None => "false",
            nuitka_extractor::Compression::Zstd => "true",
        }
    );
    println!("[+] Payload size: {} bytes", extractor.payload_size);

    let out_dir = {
        let mut s = path.clone().into_os_string();
        s.push("_extracted");
        PathBuf::from(s)
    };
    fs::create_dir_all(&out_dir)?;
    println!("[+] Beginning extraction...");

    let mut total: u32 = 0;
    for result in extractor.iter_entries()? {
        let entry = result?;
        let out_path = out_dir.join(&entry.name);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&out_path, &entry.data)
            .with_context(|| format!("Failed to write {}", out_path.display()))?;
        total += 1;
    }

    println!("[+] Total files: {total}");
    println!("[+] Successfully extracted to {}", out_dir.display());
    Ok(())
}
