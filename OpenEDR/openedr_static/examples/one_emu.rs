//! One file: emulate with a given per-run time limit (ms) and instruction count, time
//! emu_from and dump_bytes separately (emulator only).
fn main() {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    use std::io::Write;
    use std::time::Instant;
    let mut a = std::env::args().skip(1);
    let p = a.next().unwrap();
    let ms: u64 = a.next().unwrap().parse().unwrap();
    let count: usize = a.next().unwrap().parse().unwrap();
    let data = std::fs::read(&p).unwrap();
    let sample = Sample::from_bytes(&data).unwrap();
    let ep = entrypoint(&sample.opt_header);
    let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
    eng.init_uc().unwrap();
    eng.set_controls(false, false);
    eng.set_end_addr(u64::MAX);
    let t = Instant::now();
    let r = eng.emu_from(ep, ms * 1000, count);
    println!("emu_from {:?} in {:?}; end {:?}; wx {:?}; api calls {}", r.err(), t.elapsed(), eng.end, eng.wx_hit, eng.apicall_counter.values().sum::<u64>());
    std::io::stdout().flush().unwrap();
    let t = Instant::now();
    let d = eng.dump_bytes();
    println!("dump_bytes {:?} in {:?}", d.map(|d| d.len()), t.elapsed());
}
