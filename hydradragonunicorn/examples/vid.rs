//! CLI wrapper for emulator-dumped PE import reconstruction (`unpacker::vid`).
//!
//! Usage:
//!   cargo run --example vid -- <pe_path> [options]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

use hydradragonunicorn::unpacker::vid::{
    emulate_and_dump, parse_rva, rebuild_imports_from_dump, validate_section_name, SectionSelector,
    VidConfig, VidEmulationConfig,
};

fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {prog} <pe_path> [options]
Options:
  --list-sections              List PE sections dumped by the emulator and exit
  --vm-sections <s1>[,<s2>..]  Select 1..=3 VM sections by 1-based index or name (repeatable)
  --section-name <NAME>        Name for the appended import section (default: .vid)
  --output <PATH>              Output PE path (default: <stem>.vid.<ext>)
  --new-entry-rva <RVA>        Override AddressOfEntryPoint (decimal or 0x hex)
  --stop-rva <RVA>             Stop unpacking emulation at RVA (decimal or 0x hex)
  --max-insns <N>              Max instructions for initial emulation (default: 5000000)
  --timeout-secs <S>           Timeout seconds for emulation (default: 30)
  --no-emulate                 Only initialize emulator mappings and dump immediately
  --static-vmp-unpack          Pre-unpack VMProtect LZMA sections statically before emulation
  --allow-no-vm-sections       Rebuild conventional IAT references even if no VM section matched
  --map-on-fault               Auto-map zero pages on unmapped faults during unpacking
  --dump-raw <PATH>            Also write the raw memory-mapped emulator snapshot to <PATH>
  -h, --help                   Show this help text"
    );
}

fn default_output_path(input_path: &Path) -> PathBuf {
    let stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sample");
    let parent = input_path.parent().unwrap_or_else(|| Path::new(""));
    let filename = match input_path.extension().and_then(|e| e.to_str()) {
        Some(ext) if !ext.is_empty() => format!("{stem}.vid.{ext}"),
        _ => format!("{stem}.vid"),
    };
    parent.join(filename)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("vid");
    if args.len() < 2 {
        print_usage(prog);
        process::exit(1);
    }

    let mut pe_path: Option<PathBuf> = None;
    let mut list_sections = false;
    let mut output_path: Option<PathBuf> = None;
    let mut dump_raw_path: Option<PathBuf> = None;
    let mut cfg = VidConfig::default();
    cfg.emulation = VidEmulationConfig::default();

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage(prog);
                return;
            }
            "--list-sections" => list_sections = true,
            "--no-emulate" => cfg.emulation.emulate = false,
            "--static-vmp-unpack" => cfg.emulation.static_vmp_unpack = true,
            "--allow-no-vm-sections" => cfg.allow_no_vm_sections = true,
            "--map-on-fault" => cfg.emulation.map_on_fault = true,
            "--vm-sections" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--vm-sections requires a value");
                    process::exit(1);
                }
                for token in args[i].split(',').filter(|s| !s.is_empty()) {
                    match SectionSelector::from_str(token) {
                        Ok(sel) => cfg.vm_sections.push(sel),
                        Err(err) => {
                            eprintln!("Invalid --vm-sections `{token}`: {err}");
                            process::exit(1);
                        }
                    }
                }
            }
            "--section-name" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--section-name requires a value");
                    process::exit(1);
                };
                match validate_section_name(val) {
                    Ok(name) => cfg.section_name = name,
                    Err(err) => {
                        eprintln!("Invalid --section-name `{val}`: {err}");
                        process::exit(1);
                    }
                }
            }
            "--output" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--output requires a value");
                    process::exit(1);
                };
                if val.is_empty() {
                    eprintln!("--output cannot be empty");
                    process::exit(1);
                }
                output_path = Some(PathBuf::from(val));
            }
            "--dump-raw" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--dump-raw requires a path");
                    process::exit(1);
                };
                dump_raw_path = Some(PathBuf::from(val));
            }
            "--new-entry-rva" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--new-entry-rva requires an RVA");
                    process::exit(1);
                };
                match parse_rva(val) {
                    Ok(rva) => cfg.new_entry_rva = Some(rva),
                    Err(err) => {
                        eprintln!("Invalid --new-entry-rva: {err}");
                        process::exit(1);
                    }
                }
            }
            "--stop-rva" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--stop-rva requires an RVA");
                    process::exit(1);
                };
                match parse_rva(val) {
                    Ok(rva) => cfg.emulation.stop_rva = Some(rva),
                    Err(err) => {
                        eprintln!("Invalid --stop-rva: {err}");
                        process::exit(1);
                    }
                }
            }
            "--max-insns" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--max-insns requires a number");
                    process::exit(1);
                };
                cfg.emulation.max_insns = val.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid --max-insns `{val}`: {e}");
                    process::exit(1);
                });
            }
            "--timeout-secs" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("--timeout-secs requires a number");
                    process::exit(1);
                };
                cfg.emulation.timeout_secs = val.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid --timeout-secs `{val}`: {e}");
                    process::exit(1);
                });
            }
            other if other.starts_with('-') => {
                eprintln!("Unknown option: {other}");
                print_usage(prog);
                process::exit(1);
            }
            path_arg => {
                if pe_path.is_some() {
                    eprintln!("Unexpected positional argument: {path_arg}");
                    process::exit(1);
                }
                pe_path = Some(PathBuf::from(path_arg));
            }
        }
        i += 1;
    }

    let Some(pe_path) = pe_path else {
        print_usage(prog);
        process::exit(1);
    };

    let pe_bytes = match fs::read(&pe_path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("Failed to read `{}`: {err}", pe_path.display());
            process::exit(1);
        }
    };
    let module_name = pe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sample.exe");

    let dump = match emulate_and_dump(&pe_bytes, module_name, &cfg.emulation) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("Emulator dump failed: {err}");
            process::exit(1);
        }
    };

    if let Some(ref raw_out) = dump_raw_path {
        if let Err(err) = fs::write(raw_out, &dump.module_snapshot) {
            eprintln!("Failed to write raw emulator dump `{}`: {err}", raw_out.display());
            process::exit(1);
        }
        println!(
            "Raw emulator snapshot written to {} ({} bytes)",
            raw_out.display(),
            dump.module_snapshot.len()
        );
    }

    println!(
        "Emulator dump: arch={} base=0x{:x} image_size=0x{:x} insns={} end={:?} detected_oep={:?} indexed_exports={}",
        dump.architecture,
        dump.module.base_address,
        dump.module.image_size,
        dump.insn_count,
        dump.emu_end,
        dump.detected_oep_rva.map(|r| format!("0x{r:08x}")),
        dump.export_index.len()
    );

    if list_sections {
        let mut snap = dump.module_snapshot.clone();
        let sections = hydradragonunicorn::unpacker::vid::pe::read_sections(
            &hydradragonunicorn::unpacker::vid::SliceMemory::from_single_module(
                dump.architecture,
                dump.module.base_address,
                snap.clone(),
            ),
            &dump.module,
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to read dumped PE sections: {e}");
            process::exit(1);
        });
        snap.truncate(dump.module_snapshot.len());
        println!(" idx  name      RVA        size       raw_size   entropy");
        for (idx, sec) in sections.iter().enumerate() {
            let ent = hydradragonunicorn::unpacker::vid::pe::section_entropy_from_snapshot(
                &dump.module_snapshot,
                sec,
            )
            .map(|v| format!("{v:.4}"))
            .unwrap_or_else(|| "n/a".to_owned());
            println!(
                " {:>3}  {:<8}  {:08x}   {:08x}   {:08x}   {}",
                idx + 1,
                sec.name,
                sec.virtual_address,
                sec.mapped_size(),
                sec.raw_size,
                ent
            );
        }
        return;
    }

    let out_path = output_path.unwrap_or_else(|| default_output_path(&pe_path));
    if let (Ok(in_can), Ok(out_can)) = (fs::canonicalize(&pe_path), fs::canonicalize(&out_path)) {
        if in_can == out_can {
            eprintln!("Refusing to overwrite input PE `{}`", out_path.display());
            process::exit(1);
        }
    }

    let (rebuilt_bytes, report) = match rebuild_imports_from_dump(&dump, &cfg) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("vid import reconstruction failed: {err}");
            process::exit(1);
        }
    };

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!("Failed to create output directory `{}`: {err}", parent.display());
            process::exit(1);
        }
    }
    if let Err(err) = fs::write(&out_path, &rebuilt_bytes) {
        eprintln!("Failed to write output PE `{}`: {err}", out_path.display());
        process::exit(1);
    }

    println!(
        "VM sections: {:?} | Code roots: {} | Recovered: {} import(s) from {} module(s)",
        report.selected_vm_sections,
        report.code_roots,
        report.recovered_imports,
        report.recovered_modules
    );
    println!(
        "VM transfers: found={} rewritten={} unresolved={} | Conventional patches: {} / {} ref(s)",
        report.vm_transfers_found,
        report.vm_transfers_rewritten,
        report.vm_transfers_unresolved,
        report.pointer_patches_applied,
        report.pointer_references_found
    );
    println!(
        "Output: {} ({} bytes) | Section {} RVA=0x{:08x} | ImportDir=0x{:08x} IAT=0x{:08x} Relocs={}",
        out_path.display(),
        report.output_size,
        report.new_section_name,
        report.new_section_rva,
        report.import_directory_rva,
        report.iat_rva,
        report.base_relocation_fixups
    );
    for w in &report.warnings {
        eprintln!("warning: {w}");
    }
}
