fn main() {
    // Compile packer_signatures.yar → packer_signatures.yrc at build time
    // so the disinfector can embed the compiled rules via include_bytes!
    let yar_path = std::path::Path::new("../unipacker/unipacker/packer_signatures.yar");
    if !yar_path.exists() {
        eprintln!("[build] WARNING: {} not found — packer detection will be unavailable", yar_path.display());
        return;
    }

    let source = match std::fs::read_to_string(yar_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[build] WARNING: failed to read {}: {e}", yar_path.display());
            return;
        }
    };

    let mut compiler = match yara_x::Compiler::new() {
        c => c,
    };
    if let Err(e) = compiler.add_source(&*source) {
        eprintln!("[build] WARNING: failed to compile YARA rules: {e}");
        return;
    }
    let rules = compiler.build();
    let yrc_bytes = match rules.serialize() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[build] WARNING: failed to serialize YARA rules: {e}");
            return;
        }
    };

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("packer_signatures.yrc"), &yrc_bytes).unwrap();

    // Generate a Rust source file that exposes the bytes as a constant
    let bytes_hex: Vec<String> = yrc_bytes.iter().map(|b| format!("{b}")).collect();
    let gen = format!(
        "pub const PACKER_RULES_BYTES: &[u8] = &[{}];",
        bytes_hex.join(", ")
    );
    std::fs::write(out_dir.join("packer_rules_bytes.rs"), gen).unwrap();

    println!("cargo:rerun-if-changed={}", yar_path.display());
}
