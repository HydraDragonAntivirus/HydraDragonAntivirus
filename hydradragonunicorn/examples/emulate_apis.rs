//! Drive the unpacker's Unicorn emulation on a single PE and report which Windows
//! APIs it called that are not really emulated yet (the demand list for extending
//! `apicalls::handle_api_call`), plus how the run ended.
//!
//! `emulate_apis <file.exe> [timeout_seconds] [max_million_instructions]`
//!
//! Prints:
//!   - the last API calls before the run ended and how it ended (fault / stop / exit),
//!   - UNIMPLEMENTED: every API that hit the fallback arm, call count, and whether it
//!     is a pure unknown (no spec at all) or a semi-stub (spec exists, constant return),
//!   - the full distinct API-call list.

use std::time::Duration;

use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: emulate_apis <file.exe> [timeout_seconds] [max_million_instructions]");
        std::process::exit(2);
    }
    let path = &args[1];
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
    let max_m: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let timeout_us = secs.saturating_mul(1_000_000);
    let max_insns = max_m.saturating_mul(1_000_000);

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read {path}: {e}");
            std::process::exit(1);
        }
    };
    println!("file: {path} ({} bytes)", data.len());

    let sample = match Sample::from_bytes(&data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("not a PE / parse failed: {e}");
            std::process::exit(1);
        }
    };
    let ep = entrypoint(&sample.opt_header);
    let is_64 = sample.opt_header.magic == 0x20b;
    println!("arch: {}  entrypoint: {:#x}", if is_64 { "x64" } else { "x86" }, ep);

    let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
    if let Err(e) = eng.init_uc() {
        eprintln!("init_uc failed: {e}");
        std::process::exit(1);
    }
    eng.set_controls(false, false);
    eng.set_end_addr(u64::MAX);

    let t = std::time::Instant::now();
    let err = eng.emu_from(ep, timeout_us, max_insns).err().map(|e| e.to_string());
    // Give the packer stub more room to finish unpacking, like unpack_profile does.
    let extended = eng.continue_unpacking(timeout_us, max_insns.saturating_mul(2));
    let elapsed = t.elapsed();

    let calls = eng.behavior_trace().calls.clone();
    let unimpl = eng.unimplemented_apis();

    println!(
        "\n--- run ended in {:?}  insns={}  end={:?}  unpacked={} ---",
        elapsed.min(Duration::from_secs(10_000)),
        eng.live_insn_count().max(eng.insn_count),
        eng.end,
        eng.wx_hit.is_some() || extended
    );
    if let Some(e) = &err {
        println!("emu_from error: {e}");
    }
    if let Some(a) = &eng.stop_api {
        println!("stopped at API: {a}");
    }
    if let Some(f) = &eng.last_fault {
        println!("last fault: addr={:#x} ip={:#x} access={}", f.address, f.instruction, f.access);
    }

    println!("\nlast 12 API calls:");
    for c in calls.iter().rev().take(12).rev() {
        println!("  {}({})", c.api, c.args.join(", "));
    }

    let (cpuid_n, rdtsc_n) = eng.cpu_probe_counts();
    println!("\nCPU fingerprinting: cpuid x{cpuid_n}  rdtsc/rdtscp x{rdtsc_n}");

    let opened = eng.opened_objects();
    println!("\nobjects opened (NtOpenFile/NtOpenSection), in order ({}):", opened.len());
    for o in &opened {
        println!("  {o}");
    }

    println!("\nUNIMPLEMENTED APIs this sample needs ({}):", unimpl.len());
    let mut rows: Vec<(&String, u64, bool)> = unimpl.iter().map(|(k, &(n, p))| (k, n, p)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (name, count, pure) in &rows {
        println!("  {:<40} x{:<6} {}", name, count, if *pure { "UNKNOWN (no spec)" } else { "semi-stub (const ret)" });
    }

    let mut distinct: Vec<&str> = calls.iter().map(|c| c.api.as_str()).collect();
    distinct.sort_unstable();
    distinct.dedup();
    println!("\nall distinct APIs called ({}):", distinct.len());
    println!("  {}", distinct.join(", "));
}
