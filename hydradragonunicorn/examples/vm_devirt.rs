//! CLI tool for static VM/mutation section classification, opt-in trace-based
//! devirtualization, and binary-wide symbolic CFG VM devirtualization/recompilation.
//!
//! Usage:
//!   cargo run --example vm_devirt -- <pe_path> [start_rva_hex] [max_insns] [--dump <out_path>] [--devirt-pe <out_path>] [--max-entries <N>]

use std::env;
use std::fs;
use std::process;

use hydradragonunicorn::unpacker::engine::{entrypoint, parse_pe_bytes, Sample, UnpackerEngine, ENTRY_RETURN_ADDR};
use hydradragonunicorn::unpacker::vm::{detect_vm_sections, DevirtConfig, SectionVmKind};
use hydradragonunicorn::unpacker::vm_devirt::{devirtualize_pe_bytes, BinaryDevirtConfig};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(clean, 16).map_err(|e| format!("invalid hex '{s}': {e}"))
}

fn kind_label(kind: SectionVmKind) -> &'static str {
    match kind {
        SectionVmKind::Normal => "Normal",
        SectionVmKind::Mutated => "Mutated",
        SectionVmKind::Virtualized => "Virtualized",
    }
}

fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {prog} <pe_path> [start_rva_hex] [max_insns] [--dump <out_path>] [--devirt-pe <out_path>] [--max-entries <N>] [--max-blocks <N>] [--max-entry-insns <N>] [--diagnose-bailouts]"
    );
}

fn run_binary_devirt(
    pe_bytes: &[u8],
    out_path: Option<&str>,
    max_entries: usize,
    diagnose_bailouts: bool,
    max_blocks: Option<usize>,
    max_entry_insns: Option<usize>,
) {
    let label = out_path.unwrap_or("<diagnostics-only>");
    println!("\n=== Binary-Wide Symbolic CFG Devirtualization -> {label} ===");
    let defaults = BinaryDevirtConfig::default();
    let dcfg = BinaryDevirtConfig {
        max_entries,
        collect_diagnostics: diagnose_bailouts,
        max_blocks_per_entry: max_blocks.unwrap_or(defaults.max_blocks_per_entry),
        max_total_insns_per_entry: max_entry_insns.unwrap_or(defaults.max_total_insns_per_entry),
        ..defaults
    };
    println!(
        "Limits: max_blocks_per_entry={} max_total_insns_per_entry={}",
        dcfg.max_blocks_per_entry, dcfg.max_total_insns_per_entry
    );
    let (devirt_pe, rep) = match devirtualize_pe_bytes(pe_bytes, dcfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("devirtualize_pe_bytes failed: {e}");
            process::exit(1);
        }
    };

    if let Some(p) = out_path {
        if let Err(e) = fs::write(p, &devirt_pe) {
            eprintln!("Failed to write devirtualized PE {p}: {e}");
            process::exit(1);
        }
    }

    println!(
        "Arch: {} | Discovered entries: {} (vmenter={}, trampoline={}, standalone={})",
        if rep.is_64 { "x64" } else { "x86" },
        rep.discovered_total,
        rep.discovered_vmenters,
        rep.discovered_trampolines,
        rep.discovered_standalone
    );
    println!(
        "Devirtualized & patched: {} (vmenter={}, trampoline={}) ({:.2}%) | Partial: {} | Failed: {}",
        rep.devirtualized_total,
        rep.devirtualized_vmenters,
        rep.devirtualized_trampolines,
        rep.entry_devirt_pct,
        rep.partially_lifted,
        rep.failed
    );
    println!(
        "Eliminated raw VM insns: {} -> Native .devirt insns: {} (reduction: {:.1}%) | Opaque branches folded: {}",
        rep.raw_vm_insns_eliminated,
        rep.recompiled_native_insns,
        rep.code_reduction_pct,
        rep.opaque_branches_folded
    );
    println!(
        "Unique VM bytes visited: {} / {} ({:.3}%) | .devirt section: RVA={:?} size={}",
        rep.unique_vm_bytes_visited,
        rep.total_vm_section_bytes,
        rep.vm_byte_coverage_pct,
        rep.devirt_section_rva.map(|r| format!("{r:#x}")),
        rep.devirt_section_size
    );

    if !rep.bailout_reasons.is_empty() {
        println!("\nTop bailout reasons:");
        for (reason, count) in rep.bailout_reasons.iter().take(15) {
            println!("  {count:5}x  {reason}");
        }
    }

    if diagnose_bailouts {
        println!("\n--- Diagnostic: Bailouts by entry kind (top 25) ---");
        for (kind, reason, count) in rep.bailouts_by_kind.iter().take(25) {
            println!("  {count:5}x  [{kind:?}]  {reason}");
        }

        println!("\n--- Diagnostic: Indirect-jmp IP clusters (top 25) ---");
        for (kind, ip, tag, count) in rep.indirect_jmp_ip_clusters.iter().take(25) {
            println!("  {count:5}x  [{kind:?}] @ {ip:#x}  {tag}");
        }

        println!("\n--- Diagnostic: Bailout samples (up to 35) ---");
        for (kind, patch_rva, bip, reason, detail) in rep.bailout_samples.iter().take(35) {
            println!("  [{kind:?}] patch_rva={patch_rva:#x} @ {bip:#x} [{reason}] => {detail}");
        }
    }

    if !rep.patched_sites.is_empty() {
        if let Ok((_dos, _pe, opt, secs)) = parse_pe_bytes(&devirt_pe) {
            let bitness = if rep.is_64 { 64 } else { 32 };
            let mut formatter = IntelFormatter::new();
            println!("\nSample devirtualized .devirt stubs (first 5):");
            for site in rep.patched_sites.iter().take(5) {
                println!(
                    "  [{:?}] patch_rva={:#x} ({}B) -> stub_rva={:#x} ({} VM -> {} native, {} opaque folded)",
                    site.kind,
                    site.patch_rva,
                    site.patch_size,
                    site.stub_rva,
                    site.raw_vm_insns,
                    site.native_insns,
                    site.opaque_branches_folded
                );
                if let Some(sec) = secs.iter().find(|s| {
                    site.stub_rva >= s.virtual_address
                        && site.stub_rva < s.virtual_address + s.virtual_size.max(s.size_of_raw_data)
                }) {
                    let raw_off = (sec.pointer_to_raw_data + (site.stub_rva - sec.virtual_address)) as usize;
                    let end = (raw_off + 96).min(devirt_pe.len());
                    if raw_off < end {
                        let va = opt.image_base + site.stub_rva as u64;
                        let mut dec = Decoder::with_ip(bitness, &devirt_pe[raw_off..end], va, DecoderOptions::NONE);
                        for _ in 0..15 {
                            if !dec.can_decode() {
                                break;
                            }
                            let ins = dec.decode();
                            if ins.is_invalid() {
                                break;
                            }
                            let mut text = String::new();
                            formatter.format(&ins, &mut text);
                            println!("    {:#014x}: {text}", ins.ip());
                            if matches!(
                                ins.flow_control(),
                                iced_x86::FlowControl::Return | iced_x86::FlowControl::UnconditionalBranch
                            ) && !text.starts_with("jmp 0x") {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("vm_devirt");
    let mut dump_path: Option<String> = None;
    let mut devirt_pe_path: Option<String> = None;
    let mut max_entries: usize = usize::MAX;
    let mut diagnose_bailouts = false;
    let mut max_blocks: Option<usize> = None;
    let mut max_entry_insns: Option<usize> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dump" => {
                i += 1;
                let Some(out) = args.get(i) else {
                    eprintln!("--dump requires an output path");
                    print_usage(prog);
                    process::exit(2);
                };
                dump_path = Some(out.clone());
            }
            "--devirt-pe" => {
                i += 1;
                let Some(out) = args.get(i) else {
                    eprintln!("--devirt-pe requires an output path");
                    print_usage(prog);
                    process::exit(2);
                };
                devirt_pe_path = Some(out.clone());
            }
            "--max-entries" => {
                i += 1;
                let Some(val) = args.get(i).and_then(|v| v.parse::<usize>().ok()) else {
                    eprintln!("--max-entries requires an integer");
                    print_usage(prog);
                    process::exit(2);
                };
                max_entries = val;
            }
            "--diagnose-bailouts" => {
                diagnose_bailouts = true;
            }
            "--max-blocks" | "--max-entry-insns" => {
                let flag = args[i].clone();
                i += 1;
                let Some(val) = args.get(i).and_then(|v| v.parse::<usize>().ok()) else {
                    eprintln!("{flag} requires an integer");
                    print_usage(prog);
                    process::exit(2);
                };
                if flag == "--max-blocks" {
                    max_blocks = Some(val);
                } else {
                    max_entry_insns = Some(val);
                }
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    let Some(path) = positional.first().map(String::as_str) else {
        print_usage(prog);
        process::exit(2);
    };
    let rva_override = positional.get(1).and_then(|s| parse_hex_u64(s).ok());
    let max_insns = positional
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50_000);
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {path}: {e}");
            process::exit(1);
        }
    };

    println!("=== Static VM / Mutation Classification: {path} ===");
    match detect_vm_sections(&bytes) {
        Ok(prof) => {
            println!(
                "Arch: {} | Executable sections: {} | Max VM score: {:.2} | Virtualized: {} | Mutated: {}",
                if prof.is_pe64 { "x64" } else { "x86" },
                prof.executable_sections.len(),
                prof.max_vm_score,
                prof.has_virtualized,
                prof.has_mutated
            );
            for s in &prof.executable_sections {
                let name = if s.name.is_empty() { "<unnamed>" } else { s.name.as_str() };
                println!(
                    "  {name:10} VA={:#010x} size={:9} ent={:.3} cf={:5} ind={:4} ({:.1}%) ctx_save={:3} score={:.2} [{}]",
                    s.virtual_address,
                    s.raw_size,
                    s.entropy,
                    s.control_flow_insns,
                    s.indirect_branches,
                    s.indirect_branch_ratio * 100.0,
                    s.context_save_markers,
                    s.vm_score,
                    kind_label(s.kind)
                );
            }
        }
        Err(e) => {
            eprintln!("detect_vm_sections failed: {e}");
            process::exit(1);
        }
    }

    let only_binary_devirt = (devirt_pe_path.is_some() || diagnose_bailouts)
        && dump_path.is_none()
        && rva_override.is_none();
    if !only_binary_devirt {
        let sample = match Sample::from_bytes(&bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Sample::from_bytes failed: {e}");
                process::exit(1);
            }
        };

        let start = match rva_override {
            Some(rva) => sample.base_addr + rva,
            None => entrypoint(&sample.opt_header),
        };

        let mut eng = UnpackerEngine::new(sample, path).with_trace_mode(true);
        if let Err(e) = eng.init_uc() {
            eprintln!("init_uc failed: {e}");
            process::exit(1);
        }
        let is_64 = eng.is_64();
        if rva_override.is_some() {
            if let Some(uc) = eng.unicorn_mut() {
                if let Ok(rsp) = uc.reg_read(unicorn_engine::RegisterX86::RSP as i32) {
                    let ret_slot = rsp.saturating_sub(if is_64 { 8 } else { 4 });
                    let _ = uc.mem_write(ret_slot, &ENTRY_RETURN_ADDR.to_le_bytes()[..if is_64 { 8 } else { 4 }]);
                    let _ = uc.reg_write(unicorn_engine::RegisterX86::RSP as i32, ret_slot);
                }
            }
        }

        let cfg = DevirtConfig {
            max_insns,
            ..DevirtConfig::default()
        };

        println!("\n=== Trace Devirtualization from {start:#x} (max_insns={max_insns}) ===");
        match eng.devirtualize_trace(start, cfg) {
            Ok(rep) => {
                println!(
                    "Raw insns: {} -> Simplified ops: {} (reduction: {:.1}%) | Exit IP: {:#x} | Harvested PEs: {}",
                    rep.raw_insn_count,
                    rep.kept_insn_count,
                    rep.reduction_pct,
                    rep.end_addr,
                    rep.harvested_pes
                );
                if !rep.dispatcher_ips.is_empty() {
                    println!("Detected VM dispatchers:");
                    for &(ip, hits) in &rep.dispatcher_ips {
                        println!("  dispatcher @ {ip:#x}: {hits} hops");
                    }
                }
                if !rep.api_calls.is_empty() {
                    println!("API calls ({}):", rep.api_calls.len());
                    for c in rep.api_calls.iter().take(25) {
                        println!("  {}({}) -> {:#x}", c.api, c.args.join(", "), c.ret);
                    }
                }
                if !rep.mem_writes.is_empty() {
                    println!("Non-stack coalesced memory writes ({}):", rep.mem_writes.len());
                    for w in rep.mem_writes.iter().take(16) {
                        println!(
                            "  addr={:#x} len={} is_pe={} preview=[{}] strings={:?}",
                            w.addr, w.len, w.is_pe, w.preview_hex, w.ascii_strings
                        );
                    }
                }
                if !rep.decrypted_strings.is_empty() {
                    println!("Decrypted strings ({}):", rep.decrypted_strings.len());
                    for s in rep.decrypted_strings.iter().take(25) {
                        println!("  {s:?}");
                    }
                }
                println!("\nSimplified trace (first 60 ops):");
                for op in rep.simplified_ops.iter().take(60) {
                    println!("  [{:05}] {:#014x} [{:?}] {}", op.index, op.ip, op.kind, op.text);
                }
                if let Some(out_path) = dump_path.as_deref() {
                    println!("\n=== Image Dump: {out_path} ===");
                    if let Err(e) = eng.dump(out_path) {
                        eprintln!("dump failed ({out_path}): {e}");
                        process::exit(1);
                    }
                    let payloads = eng.harvest_written_payloads();
                    let strings = eng.extract_written_strings();
                    println!(
                        "Dumped PE image -> {out_path} | Harvested payloads: {} | Extracted written strings: {}",
                        payloads.len(),
                        strings.len()
                    );
                    for (idx, p) in payloads.iter().enumerate() {
                        println!(
                            "  payload[{idx}]: base={:#x} size={} in_image={} is_pe={}",
                            p.base, p.size, p.in_image, p.is_pe
                        );
                        if !p.in_image {
                            let alloc_path = format!("{out_path}.alloc_{idx}_{:#x}.bin", p.base);
                            if let Err(e) = fs::write(&alloc_path, &p.data) {
                                eprintln!("failed to write payload {alloc_path}: {e}");
                                process::exit(1);
                            }
                            println!("    wrote non-image payload -> {alloc_path}");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("devirtualize_trace stopped with error: {e}");
                process::exit(1);
            }
        }
    }

    if devirt_pe_path.is_some() || diagnose_bailouts {
        let input_for_devirt = if let Some(dp) = dump_path.as_deref() {
            fs::read(dp).unwrap_or(bytes)
        } else {
            bytes
        };
        run_binary_devirt(
            &input_for_devirt,
            devirt_pe_path.as_deref(),
            max_entries,
            diagnose_bailouts,
            max_blocks,
            max_entry_insns,
        );
    }
}
