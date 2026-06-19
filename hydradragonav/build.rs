fn main() {
    let yar_path = std::path::Path::new("../unipacker/unipacker/packer_signatures.yar");
    if !yar_path.exists() {
        eprintln!("[build] WARNING: {} not found — packer detection will be unavailable", yar_path.display());
        return;
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Copy the .yar source so the disinfector can compile it at first use
    if let Ok(source) = std::fs::read_to_string(yar_path) {
        std::fs::write(out_dir.join("packer_signatures.yar"), &source).unwrap();
    }

    // Emit a tiny constant that just points to the source file
    let yar_abs = out_dir.join("packer_signatures.yar");
    let src_path = yar_abs.to_string_lossy().replace('\\', "/");
    let content = format!(
        "pub const PACKER_RULES_YAR: &str = include_str!(\"{src_path}\");\n"
    );
    std::fs::write(out_dir.join("packer_rules_bytes.rs"), content).unwrap();

    println!("cargo:rerun-if-changed={}", yar_path.display());
}
