//! Benchmark: emulates every PE under the folders (inside Unicorn only), same settings
//! as pe_combined. Prints total time and how many ran code they had written.
fn main() {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().unwrap().parse().unwrap();
    let mut files = Vec::new();
    for d in args {
        let mut stack = vec![std::path::PathBuf::from(d)];
        while let Some(p) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for e in rd.flatten() { let q = e.path(); if q.is_dir() { stack.push(q) } else { files.push(q) } }
            }
        }
    }
    files.sort();
    let (mut n, mut wx, mut slow) = (0usize, 0usize, 0usize);
    let t0 = std::time::Instant::now();
    for f in files {
        if n >= limit { break; }
        let Ok(data) = std::fs::read(&f) else { continue };
        if !data.starts_with(b"MZ") || data.len() < 0x1000 || openedr_static::ml::pe_combined::dotnet_kind(&data) != 0 || !openedr_static::ml::pe_combined::should_unpack(&data) { continue }
        let Ok(sample) = Sample::from_bytes(&data) else { continue };
        let ep = entrypoint(&sample.opt_header);
        let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
        if eng.init_uc().is_err() { continue }
        eng.set_controls(false, false);
        eng.set_end_addr(u64::MAX);
        let t = std::time::Instant::now();
        let r = eng.emu_from(ep, 20_000_000, 20_000_000);
        let exec: u64 = eng.sections_executed.values().sum();
        let apis: u64 = eng.apicall_counter.values().sum();
        let why = match &r { Ok(_) => "ok".to_string(), Err(e) => e.to_string().chars().take(70).collect() };
        let stop_api: Vec<_> = if eng.end == hydradragonunicorn::unpacker::engine::EmuEnd::Stopped {
            eng.apicall_counter.keys().filter(|k| !eng.behavior_trace().calls.iter().any(|c| &c.api == *k)).cloned().collect()
        } else { Vec::new() };
        eprintln!("{exec}	{apis}	{}	{why}	{:?}	{}", eng.write_targets.len(), eng.end, stop_api.join(","));
        if t.elapsed().as_millis() > 2000 { slow += 1; }
        n += 1;
        wx += eng.wx_hit.is_some() as usize;
    }
    println!("files {n}, wrote-then-ran {wx}, over 2 s {slow}, total {:.1} s, avg {:.0} ms", t0.elapsed().as_secs_f64(), t0.elapsed().as_millis() as f64 / n.max(1) as f64);
}
