use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Dirs relative to the crate root whose files are hashed and embedded.
const SIG_DIRS: &[&str] = &["yara-x", "bloom_filter", "complist", "database"];

fn hash_dir(base: &Path, dir_name: &str, map: &mut BTreeMap<String, String>) {
    let dir = base.join(dir_name);
    if !dir.exists() {
        return;
    }
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_file())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let rel = format!(
            "{}/{}",
            dir_name,
            path.file_name().unwrap().to_string_lossy()
        );
        map.insert(rel, hash);
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    // Embed icon via Windows resource file
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../hydradragon/assets/HydraDragonAV.ico");
        if let Err(e) = res.compile() {
            eprintln!("winres warning: {e}");
        }
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let base = Path::new(&manifest);
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for dir in SIG_DIRS {
        hash_dir(base, dir, &mut map);
    }

    // Format: count(u32le) | [key_len(u16le) key_bytes hash_bytes(32)]*
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("sig_hashes.bin");
    let mut out = fs::File::create(&out_path).unwrap();
    out.write_all(&(map.len() as u32).to_le_bytes()).unwrap();
    for (key, hex_hash) in &map {
        let kb = key.as_bytes();
        out.write_all(&(kb.len() as u16).to_le_bytes()).unwrap();
        out.write_all(kb).unwrap();
        let raw: Vec<u8> = (0..hex_hash.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_hash[i..i + 2], 16).unwrap())
            .collect();
        out.write_all(&raw).unwrap();
    }
}
