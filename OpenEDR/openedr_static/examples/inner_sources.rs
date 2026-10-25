//! How the v2 extractor files the PEs of a folder: content (unpacked / not packed
//! image), emulator failed, extracted, none, or no vector (read only, emulator only).
fn main() {
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().unwrap().parse().unwrap();
    for d in args {
        let mut files: Vec<_> = std::fs::read_dir(&d).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default();
        files.sort();
        let mut c = std::collections::BTreeMap::<&str, usize>::new();
        let mut n = 0;
        for f in files {
            if n >= limit { break; }
            let Ok(data) = std::fs::read(&f) else { continue };
            if !data.starts_with(b"MZ") { continue }
            n += 1;
            let k = match openedr_static::ml::pe_combined::extract_pe_features_v2(&data) {
                None => "no vector (not a PE / no code)",
                Some(v) => match v[136] as u8 { 1 => "unpacked", 4 => "not packed (image)", 3 => "emulator failed", 2 => "extracted", _ => "none" },
            };
            *c.entry(k).or_default() += 1;
        }
        println!("{d}: {n} files {c:?}");
    }
}
