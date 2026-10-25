//! Where the v2 feature time goes, per phase, over the PEs of a folder (emulator only).
fn main() {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    use std::time::{Duration, Instant};
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().unwrap().parse().unwrap();
    for d in args {
        let mut files: Vec<_> = std::fs::read_dir(&d).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default();
        files.sort();
        let mut t = [Duration::ZERO; 6];
        let names = ["v1 features", "Sample::from_bytes", "init_uc", "emu_from", "dump_bytes", "whole v2"];
        let (mut n, mut slowest) = (0usize, (Duration::ZERO, String::new()));
        for f in files {
            if n >= limit { break; }
            let Ok(data) = std::fs::read(&f) else { continue };
            if !data.starts_with(b"MZ") || !openedr_static::ml::pe_combined::should_unpack(&data) { continue }
            n += 1;
            let s = Instant::now();
            let _ = openedr_static::ml::pe_features::extract_pe_features(&data);
            t[0] += s.elapsed();
            let s = Instant::now();
            let Ok(sample) = Sample::from_bytes(&data) else { continue };
            t[1] += s.elapsed();
            let ep = entrypoint(&sample.opt_header);
            let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
            let s = Instant::now();
            if eng.init_uc().is_err() { continue }
            t[2] += s.elapsed();
            eng.set_controls(false, false);
            eng.set_end_addr(u64::MAX);
            let s = Instant::now();
            let _ = eng.emu_from(ep, 20_000_000, 20_000_000);
            let e = s.elapsed();
            t[3] += e;
            if e > slowest.0 { slowest = (e, f.file_name().unwrap().to_string_lossy().into_owned()); }
            let s = Instant::now();
            let _ = eng.dump_bytes();
            t[4] += s.elapsed();
            let s = Instant::now();
            let _ = openedr_static::ml::pe_combined::extract_pe_features_v2(&data);
            openedr_static::ml::pe_combined::forget_emulation();
            t[5] += s.elapsed();
        }
        println!("{d}: {n} files");
        for (name, x) in names.iter().zip(t) { println!("  {name:20} total {:7.1} s  avg {:6.1} ms", x.as_secs_f64(), x.as_secs_f64() * 1000.0 / n.max(1) as f64); }
        println!("  slowest emulation {:.1} s: {}", slowest.0.as_secs_f64(), slowest.1);
    }
}
