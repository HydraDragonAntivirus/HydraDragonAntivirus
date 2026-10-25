//! Steps of the v2 extractor for one file, each announced before it runs (emulator only).
fn main() {
    use std::io::Write;
    use std::time::Instant;
    let p = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&p).unwrap();
    let step = |s: &str| { println!("{s}"); std::io::stdout().flush().unwrap(); Instant::now() };
    let t = step(&format!("size {} bytes; detect_format", data.len()));
    let fmt = hydradragonextractor::detect_format(&data);
    println!("  {:?} in {:?}", fmt, t.elapsed());
    if fmt.is_some() {
        let t = step("extract_archive_from_bytes");
        let r = hydradragonextractor::extract_archive_from_bytes(&data, false);
        println!("  {} entries in {:?}", r.map(|v| v.len()).unwrap_or(0), t.elapsed());
    }
    let t = step("emulate");
    let e = openedr_static::ml::pe_combined::emulate(&data);
    println!("  dump {:?} unpacked {:?} failed {:?} in {:?}", e.as_ref().map(|e| e.dump.as_ref().map(|d| d.len())), e.as_ref().map(|e| e.unpacked), e.as_ref().map(|e| e.failed), t.elapsed());
    let t = step("strings");
    let _ = openedr_static::ml::pe_combined::StringCounts::of(&data);
    println!("  in {:?}", t.elapsed());
}
