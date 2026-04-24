use crate::modules::prelude::*;
use crate::modules::protos::hydra::*;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction};
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Hydra, ModuleError> {
    let mut hydra = Hydra::new();
    let text = String::from_utf8_lossy(data);
    let text_lower = text.to_lowercase();

    // ─── PE Analysis ───
    if let Ok(pe) = PE::parse(data) {
        let mut pe_proto = Pe::new();
        let mut pe_ml = PeMl::new();
        let mut telemetry = EmulationTelemetry::new();

        // File-level entropy
        pe_ml.set_entropy(calculate_entropy(data));

        // Optional Header — raw passthrough, no decisions
        if let Some(opt) = pe.header.optional_header {
            pe_ml.set_major_linker_version(opt.standard_fields.major_linker_version as u32);
            pe_ml.set_minor_linker_version(opt.standard_fields.minor_linker_version as u32);
            pe_ml.set_size_of_code(opt.standard_fields.size_of_code as u32);
            pe_ml.set_size_of_initialized_data(opt.standard_fields.size_of_initialized_data as u32);
            pe_ml.set_size_of_uninitialized_data(opt.standard_fields.size_of_uninitialized_data as u32);
            pe_ml.set_address_of_entry_point(opt.standard_fields.address_of_entry_point as u32);
            pe_ml.set_base_of_code(opt.standard_fields.base_of_code as u32);

            pe_ml.set_image_base(opt.windows_fields.image_base);
            pe_ml.set_section_alignment(opt.windows_fields.section_alignment);
            pe_ml.set_file_alignment(opt.windows_fields.file_alignment);
            pe_ml.set_major_operating_system_version(opt.windows_fields.major_operating_system_version as u32);
            pe_ml.set_minor_operating_system_version(opt.windows_fields.minor_operating_system_version as u32);
            pe_ml.set_major_image_version(opt.windows_fields.major_image_version as u32);
            pe_ml.set_minor_image_version(opt.windows_fields.minor_image_version as u32);
            pe_ml.set_major_subsystem_version(opt.windows_fields.major_subsystem_version as u32);
            pe_ml.set_minor_subsystem_version(opt.windows_fields.minor_subsystem_version as u32);
            pe_ml.set_size_of_image(opt.windows_fields.size_of_image);
            pe_ml.set_size_of_headers(opt.windows_fields.size_of_headers);
            pe_ml.set_check_sum(opt.windows_fields.check_sum);
            pe_ml.set_subsystem(opt.windows_fields.subsystem as u32);
            pe_ml.set_dll_characteristics(opt.windows_fields.dll_characteristics as u32);
            pe_ml.set_size_of_stack_reserve(opt.windows_fields.size_of_stack_reserve);
            pe_ml.set_size_of_stack_commit(opt.windows_fields.size_of_stack_commit);
            pe_ml.set_size_of_heap_reserve(opt.windows_fields.size_of_heap_reserve);
            pe_ml.set_size_of_heap_commit(opt.windows_fields.size_of_heap_commit);
            pe_ml.set_loader_flags(opt.windows_fields.loader_flags);
            pe_ml.set_number_of_rva_and_sizes(opt.windows_fields.number_of_rva_and_sizes);
        }

        // Section telemetry — raw data per section + collect code sections for CFG
        let mut code_sections: Vec<(u64, Vec<u8>)> = Vec::new();
        for s in &pe.sections {
            let sec_name = s.name().unwrap_or("").to_lowercase();
            let sec_start = s.pointer_to_raw_data as usize;
            let sec_size = s.size_of_raw_data as usize;

            let mut sec_proto = Section::new();
            sec_proto.set_name(sec_name.clone());
            sec_proto.set_raw_size(sec_size as u32);
            sec_proto.set_virtual_size(s.virtual_size);
            sec_proto.set_characteristics(s.characteristics);
            if sec_start + sec_size <= data.len() && sec_size > 0 {
                sec_proto.set_entropy(calculate_entropy(&data[sec_start..sec_start + sec_size]));

                // Collect executable sections for CFG analysis
                if (s.characteristics & 0x20000000) != 0 {
                    code_sections.push((s.virtual_address as u64, data[sec_start..sec_start + sec_size].to_vec()));
                }
            }
            pe_proto.sections.push(sec_proto);
        }
        pe_ml.set_sections_count(pe.sections.len() as u32);

        // Last section raw characteristics
        if let Some(last_sec) = pe.sections.last() {
            pe_ml.set_last_section_characteristics(last_sec.characteristics);
        }

        // CFG raw counters — disassemble ALL code sections, count every branch type
        let mut cfg_total: u32 = 0;
        let mut cfg_jumps: u32 = 0;
        let mut cfg_calls: u32 = 0;
        let mut cfg_rets: u32 = 0;
        for (va, sec_data) in &code_sections {
            let bitness = if pe.is_64 { 64 } else { 32 };
            let mut decoder = Decoder::with_ip(bitness, sec_data, *va, DecoderOptions::NONE);
            let mut instr = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instr);
                cfg_total += 1;
                let flow = instr.flow_control();
                use iced_x86::FlowControl;
                match flow {
                    FlowControl::ConditionalBranch
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch => cfg_jumps += 1,
                    FlowControl::Call
                    | FlowControl::IndirectCall => cfg_calls += 1,
                    FlowControl::Return => cfg_rets += 1,
                    _ => {}
                }
            }
        }
        pe_ml.set_cfg_total_instructions(cfg_total);
        pe_ml.set_cfg_jump_count(cfg_jumps);
        pe_ml.set_cfg_call_count(cfg_calls);
        pe_ml.set_cfg_ret_count(cfg_rets);

        // TLS — raw count via tls_data in data directories
        if let Some(opt) = pe.header.optional_header {
            if let Some(tls_data) = opt.data_directories.get_tls_table() {
                if tls_data.virtual_address != 0 {
                    pe_ml.set_tls_callbacks_count(1); // TLS directory present
                } else {
                    pe_ml.set_tls_callbacks_count(0);
                }
            }
        }

        // Rich Header — raw values, no anomaly scoring
        if let Some(rich) = &pe.header.rich_header {
            // Each record is 8 bytes (comp_id + count), raw data blob
            pe_ml.set_rich_header_entries_count((rich.data.len() / 8) as u32);
            pe_ml.set_rich_header_xor_key(rich.key);
        }

        // Overlay — raw size and entropy
        let mut max_end: usize = 0;
        for s in &pe.sections {
            let end = s.pointer_to_raw_data as usize + s.size_of_raw_data as usize;
            if end > max_end {
                max_end = end;
            }
        }
        if data.len() > max_end {
            let overlay = &data[max_end..];
            pe_ml.set_overlay_size(overlay.len() as u32);
            pe_ml.set_overlay_entropy(calculate_entropy(overlay));
        } else {
            pe_ml.set_overlay_size(0);
        }

        // Import/Export raw counts + raw DLL/function name lists
        pe_ml.set_imports_count(pe.imports.len() as u32);
        pe_ml.set_exports_count(pe.exports.len() as u32);

        let mut dll_set: Vec<String> = Vec::new();
        for import in &pe.imports {
            let dll = import.dll.to_string().to_lowercase();
            let func = import.name.to_string().to_lowercase();
            if !dll_set.contains(&dll) {
                dll_set.push(dll.clone());
                pe_proto.import_dlls.push(dll);
            }
            pe_proto.import_functions.push(func);
        }

        // EP Disassembly — raw mnemonic counters, zero decisions
        let ep = pe.entry;
        let mut ep_code: Vec<u8> = Vec::new();
        let mut ep_instr_count: u32 = 0;
        let mut ep_jump_count: u32 = 0;
        let mut ep_call_count: u32 = 0;
        let mut ep_ret_count: u32 = 0;
        let mut ep_nop_count: u32 = 0;
        let mut ep_cpuid_count: u32 = 0;
        let mut ep_rdtsc_count: u32 = 0;

        for sec in &pe.sections {
            let sec_va = sec.virtual_address as usize;
            let sec_vsz = sec.virtual_size as usize;
            if (ep as usize) >= sec_va && (ep as usize) < sec_va + sec_vsz {
                let offset = sec.pointer_to_raw_data as usize + (ep as usize - sec_va);
                if offset < data.len() {
                    let bitness = if pe.is_64 { 64 } else { 32 };
                    let mut decoder = Decoder::with_ip(bitness, &data[offset..], ep as u64, DecoderOptions::NONE);
                    let mut instr = Instruction::default();
                    while decoder.can_decode() && ep_instr_count < 200 {
                        decoder.decode_out(&mut instr);
                        ep_instr_count += 1;

                        let flow = instr.flow_control();
                        use iced_x86::FlowControl;
                        match flow {
                            FlowControl::ConditionalBranch
                            | FlowControl::UnconditionalBranch
                            | FlowControl::IndirectBranch => ep_jump_count += 1,
                            FlowControl::Call
                            | FlowControl::IndirectCall => ep_call_count += 1,
                            FlowControl::Return => ep_ret_count += 1,
                            _ => {}
                        }

                        use iced_x86::Mnemonic;
                        match instr.mnemonic() {
                            Mnemonic::Nop => ep_nop_count += 1,
                            Mnemonic::Cpuid => ep_cpuid_count += 1,
                            Mnemonic::Rdtsc => ep_rdtsc_count += 1,
                            _ => {}
                        }
                    }

                    // Extract EP code for emulation
                    let limit = std::cmp::min(offset + 1024, data.len());
                    ep_code = data[offset..limit].to_vec();
                }
                break;
            }
        }

        pe_ml.set_ep_instructions_count(ep_instr_count);
        pe_ml.set_ep_jump_count(ep_jump_count);
        pe_ml.set_ep_call_count(ep_call_count);
        pe_ml.set_ep_ret_count(ep_ret_count);
        pe_ml.set_ep_nop_count(ep_nop_count);
        pe_ml.set_ep_cpuid_count(ep_cpuid_count);
        pe_ml.set_ep_rdtsc_count(ep_rdtsc_count);

        // Emulation (Unicorn) — dump raw register state, zero decisions
        if !ep_code.is_empty() {
            let mode = if pe.is_64 { Mode::MODE_64 } else { Mode::MODE_32 };

            if let Ok(mut uc) = Unicorn::new(Arch::X86, mode) {
                let base: u64 = 0x1000000;
                let _ = uc.mem_map(base, 2 * 1024 * 1024, Prot::ALL);
                let _ = uc.mem_write(base, &ep_code);

                let ip_reg = if pe.is_64 {
                    unicorn_engine::RegisterX86::RIP
                } else {
                    unicorn_engine::RegisterX86::EIP
                };
                let _ = uc.reg_write(ip_reg, base);

                let max_insn = 256u64;
                let _ = uc.emu_start(base, base + ep_code.len() as u64, 0, max_insn as usize);

                telemetry.set_executed_instructions(max_insn as u32);

                // Dump final register state — raw values
                if let Ok(v) = uc.reg_read(unicorn_engine::RegisterX86::EAX) {
                    telemetry.set_eax_final(v as u32);
                }
                if let Ok(v) = uc.reg_read(unicorn_engine::RegisterX86::EBX) {
                    telemetry.set_ebx_final(v as u32);
                }
                if let Ok(v) = uc.reg_read(unicorn_engine::RegisterX86::ECX) {
                    telemetry.set_ecx_final(v as u32);
                }
                if let Ok(v) = uc.reg_read(unicorn_engine::RegisterX86::EDX) {
                    telemetry.set_edx_final(v as u32);
                }
            }
        }

        pe_proto.ml = Some(pe_ml).into();
        pe_proto.emulation = Some(telemetry).into();
        hydra.pe = Some(pe_proto).into();
    }

    // ─── JS Analysis — raw counts only ───
    let mut js_ml = JsMl::new();

    js_ml.set_file_size(data.len() as u32);
    js_ml.set_entropy(calculate_entropy(data));
    js_ml.set_total_lines(text.lines().count() as u32);

    // Token counts
    js_ml.set_function_count(
        text.matches("function ").count() as u32 + text.matches("=>").count() as u32,
    );
    js_ml.set_variable_declarations(
        text.matches("var ").count() as u32
            + text.matches("let ").count() as u32
            + text.matches("const ").count() as u32,
    );
    js_ml.set_eval_count(text.matches("eval(").count() as u32);
    js_ml.set_try_catch_count(
        text.matches("try {").count() as u32 + text.matches("catch").count() as u32,
    );
    js_ml.set_loop_count(
        text.matches("for ").count() as u32
            + text.matches("for(").count() as u32
            + text.matches("while ").count() as u32
            + text.matches("while(").count() as u32,
    );
    js_ml.set_conditional_count(
        text.matches("if ").count() as u32
            + text.matches("if(").count() as u32
            + text.matches("switch").count() as u32,
    );

    // Encoding raw counts
    js_ml.set_hex_escape_count(text.matches("\\x").count() as u32);
    js_ml.set_unicode_escape_count(text.matches("\\u").count() as u32);
    js_ml.set_fromcharcode_count(text_lower.matches("string.fromcharcode").count() as u32);

    // API raw counts
    js_ml.set_eval_call_count(text_lower.matches("eval(").count() as u32);
    js_ml.set_wscript_shell_count(text_lower.matches("wscript.shell").count() as u32);
    js_ml.set_activex_count(text_lower.matches("activexobject").count() as u32);
    js_ml.set_adodb_stream_count(text_lower.matches("adodb.stream").count() as u32);
    js_ml.set_http_reference_count(text_lower.matches("http").count() as u32);
    js_ml.set_xmlhttprequest_count(text_lower.matches("xmlhttprequest").count() as u32);
    js_ml.set_fetch_count(text_lower.matches("fetch(").count() as u32);

    // Identifier entropy analysis — raw count + raw average
    let mut high_entropy_ids: u32 = 0;
    let mut total_id_entropy: f64 = 0.0;
    let mut total_ids: u32 = 0;
    for word in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if word.len() > 6 {
            let ent = calculate_entropy(word.as_bytes());
            total_id_entropy += ent;
            total_ids += 1;
            if ent > 3.5 {
                high_entropy_ids += 1;
            }
        }
    }
    js_ml.set_high_entropy_identifiers_count(high_entropy_ids);
    if total_ids > 0 {
        js_ml.set_avg_identifier_entropy(total_id_entropy / total_ids as f64);
    }

    let mut js_proto = Js::new();
    js_proto.ml = Some(js_ml).into();
    hydra.js = Some(js_proto).into();

    Ok(hydra)
}
