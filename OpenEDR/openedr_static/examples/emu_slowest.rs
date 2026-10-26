//! Per-file emulation time over folders (emulator only), slowest first, with how the
//! run ended, bytes executed in the image, API calls and written pages.
fn main() {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().unwrap().parse().unwrap();
    let mut rows = Vec::new();
    for d in args {
        let mut files: Vec<_> = std::fs::read_dir(&d).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default();
        files.sort();
        let mut n = 0;
        for f in files {
            if n >= limit { break; }
            let Ok(data) = std::fs::read(&f) else { continue };
            if !data.starts_with(b"MZ") || !openedr_static::ml::pe_combined::should_unpack(&data) { continue }
            let Ok(sample) = Sample::from_bytes(&data) else { continue };
            let ep = entrypoint(&sample.opt_header);
            let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
            if eng.init_uc().is_err() { continue }
            eng.set_controls(false, false);
            eng.set_end_addr(u64::MAX);
            n += 1;
            let t = std::time::Instant::now();
            let _ = eng.emu_from(ep, 20_000_000, 20_000_000);
            let ms = t.elapsed().as_millis();
            let exec: u64 = eng.sections_executed.values().sum();
            let apis: u64 = eng.apicall_counter.values().sum();
            let pages: u64 = eng.write_targets.iter().map(|(a, b)| (b - a) >> 12).sum();
            let top_api = eng.apicall_counter.iter().max_by_key(|(_, c)| **c).map(|(k, c)| format!("{k}x{c}")).unwrap_or_default();
            rows.push((ms, format!("{ms:6} ms  end {:?}  exec {exec}  apis {apis} (top {top_api})  written pages {pages}  {}", eng.end, f.file_name().unwrap().to_string_lossy())));
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    let total: u128 = rows.iter().map(|r| r.0).sum();
    println!("{} files, total {} ms, slowest 15 = {} ms", rows.len(), total, rows.iter().take(15).map(|r| r.0).sum::<u128>());
    for r in rows.iter().take(15) { println!("{}", r.1); }
}
