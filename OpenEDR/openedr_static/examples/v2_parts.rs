//! Time of the non-emulation steps of the v2 extractor (read only, emulator only).
fn main() {
    use openedr_static::ml::pe_combined as pc;
    use std::time::{Duration, Instant};
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().unwrap().parse().unwrap();
    for d in args {
        let mut files: Vec<_> = std::fs::read_dir(&d).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default();
        files.sort();
        let names = ["strings(file)", "detect_format", "extract archive", "emulate", "v1(dump)", "strings(dump)", "dotnet_kind x2"];
        let mut t = [Duration::ZERO; 7];
        let mut n = 0;
        for f in files {
            if n >= limit { break; }
            let Ok(data) = std::fs::read(&f) else { continue };
            if !data.starts_with(b"MZ") || !pc::has_code(&data) { continue }
            n += 1;
            let s = Instant::now(); let _ = pc::StringCounts::of(&data); t[0] += s.elapsed();
            let s = Instant::now(); let fmt = hydradragonextractor::detect_format(&data); t[1] += s.elapsed();
            if fmt.is_some() { let s = Instant::now(); let _ = hydradragonextractor::extract_archive_from_bytes(&data, false); t[2] += s.elapsed(); }
            let s = Instant::now(); let emu = pc::emulate(&data); t[3] += s.elapsed();
            if let Some(dump) = emu.as_ref().and_then(|e| e.dump.clone()) {
                let s = Instant::now(); let _ = openedr_static::ml::pe_features::extract_pe_features(&dump); t[4] += s.elapsed();
                let s = Instant::now(); let _ = pc::StringCounts::of(&dump); t[5] += s.elapsed();
                let s = Instant::now(); let _ = (pc::dotnet_kind(&data), pc::dotnet_kind(&dump)); t[6] += s.elapsed();
            }
            pc::forget_emulation();
        }
        println!("{d}: {n} files");
        for (name, x) in names.iter().zip(t) { println!("  {name:16} total {:7.1} s  avg {:6.1} ms", x.as_secs_f64(), x.as_secs_f64() * 1000.0 / n.max(1) as f64); }
    }
}
