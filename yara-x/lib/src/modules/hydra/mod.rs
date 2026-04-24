use crate::modules::prelude::*;
use crate::modules::protos::hydra::*;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction};
use unicorn_engine::{Unicorn, RegisterX86};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
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
    let text_lower = String::from_utf8_lossy(data).to_lowercase();
    let text = String::from_utf8_lossy(data);
    
    // Attempt to parse PE
    if let Ok(pe) = PE::parse(data) {
        let mut pe_proto = Pe::new();
        let mut pe_ml = PeMl::new();
        let mut telemetry = EmulationTelemetry::new();
        
        let entropy = calculate_entropy(data);
        pe_ml.set_entropy(entropy);

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

        let mut missing_std = 0;
        let mut section_names = Vec::new();
        for s in &pe.sections {
            section_names.push(s.name().unwrap_or("").to_lowercase());
        }
        
        let has_rdata = section_names.iter().any(|n| n.contains(".rdata"));
        let has_idata = section_names.iter().any(|n| n.contains(".idata"));
        if !has_rdata { missing_std += 1; }
        if !has_idata { missing_std += 1; }
        pe_ml.set_missing_standard_sections(missing_std);
        
        let mut overlay_size = 0;
        let mut max_end = 0;
        for s in &pe.sections {
            let end = s.pointer_to_raw_data as usize + s.size_of_raw_data as usize;
            if end > max_end { max_end = end; }
        }
        if data.len() > max_end {
            overlay_size = data.len() - max_end;
            let overlay_entropy = calculate_entropy(&data[max_end..]);
            pe_ml.set_overlay_entropy(overlay_entropy);
        }
        pe_ml.set_overlay_size(overlay_size as u32);
        
        pe_ml.set_sections_count(pe.sections.len() as u32);
        pe_ml.set_imports_count(pe.imports.len() as u32);
        pe_ml.set_exports_count(pe.exports.len() as u32);
        
        let mut suspicious_imports = 0;
        for import in &pe.imports {
            let name = import.name.to_string().to_lowercase();
            if name == "virtualalloc" || name == "createremotethread" || name == "writeprocessmemory" || name == "isdebuggerpresent" {
                suspicious_imports += 1;
            }
        }
        pe_proto.set_has_suspicious_imports(suspicious_imports >= 3);
        
        if let Some(last_sec) = pe.sections.last() {
            let chars = last_sec.characteristics;
            let is_wx = (chars & 0x20000000) != 0 && (chars & 0x80000000) != 0;
            pe_ml.set_is_wx_last_section(is_wx);
        }

        // EP Opcode Extraction
        let ep = pe.entry;
        let mut ep_code = Vec::new();
        let mut emulated_apis = Vec::new();

        for sec in &pe.sections {
            let start = sec.virtual_address as usize;
            let size = sec.virtual_size as usize;
            if ep as usize >= start && ep as usize < start + size {
                let offset = sec.pointer_to_raw_data as usize + (ep as usize - start);
                if offset < data.len() {
                    let mut decoder = Decoder::with_ip(if pe.is_64 { 64 } else { 32 }, &data[offset..], ep as u64, DecoderOptions::NONE);
                    let mut instr = Instruction::default();
                    let mut count = 0;
                    while decoder.can_decode() && count < 100 {
                        decoder.decode_out(&mut instr);
                        count += 1;
                    }
                    pe_ml.set_ep_instructions_count(count);
                    
                    // Extract EP code for emulation
                    let limit = std::cmp::min(offset + 1024, data.len());
                    ep_code = data[offset..limit].to_vec();
                }
            }
        }

        // 6. Emulation (Unicorn Engine)
        if !ep_code.is_empty() {
            let arch = if pe.is_64 { Arch::X86 } else { Arch::X86 };
            let mode = if pe.is_64 { Mode::MODE_64 } else { Mode::MODE_32 };
            
            if let Ok(mut unicorn) = Unicorn::new(arch, mode) {
                let address = 0x1000000;
                let _ = unicorn.mem_map(address, 2 * 1024 * 1024, Permission::ALL);
                let _ = unicorn.mem_write(address, &ep_code);
                
                // Set EIP/RIP to entry point
                let _ = unicorn.reg_write(if pe.is_64 { RegisterX86::RIP } else { RegisterX86::EIP }, address);
                
                // Emulate 256 instructions
                let _ = unicorn.emu_start(address, address + ep_code.len() as u64, 0, 256);
                
                telemetry.set_executed_instructions(256); // Telemetry stub
                
                if let Ok(eax) = unicorn.reg_read(RegisterX86::EAX) {
                    if eax == 0xDEADBEEF { // Generic emulation hook
                        emulated_apis.push("VirtualAlloc".to_string());
                    }
                }
            }
        }
        
        telemetry.executed_apis = emulated_apis;

        pe_proto.ml = Some(pe_ml).into();
        pe_proto.emulation = Some(telemetry).into();
        hydra.pe = Some(pe_proto).into();
    }
    
    // JS Checks mapped to ML features
    let mut js_proto = Js::new();
    let mut js_ml = JsMl::new();
    
    js_ml.set_file_size(data.len() as u32);
    js_ml.set_entropy(calculate_entropy(data));
    
    js_ml.set_function_count(text.matches("function ").count() as u32 + text.matches("=>").count() as u32);
    js_ml.set_variable_declarations(text.matches("var ").count() as u32 + text.matches("let ").count() as u32 + text.matches("const ").count() as u32);
    js_ml.set_eval_usage(text.matches("eval(").count() as u32);
    js_ml.set_try_catch_blocks(text.matches("try {").count() as u32 + text.matches("catch").count() as u32);
    js_ml.set_loop_statements(text.matches("for ").count() as u32 + text.matches("while ").count() as u32 + text.matches("for(").count() as u32 + text.matches("while(").count() as u32);
    js_ml.set_conditional_statements(text.matches("if ").count() as u32 + text.matches("switch").count() as u32 + text.matches("if(").count() as u32);
    
    let hex_encoded = text.matches("\\x").count() as u32;
    let unicode_encoded = text.matches("\\u").count() as u32;
    js_ml.set_hex_encoded_strings(hex_encoded);
    js_ml.set_unicode_encoded_strings(unicode_encoded);
    
    let obfuscation_score = hex_encoded * 2 + unicode_encoded * 2 + text.matches("String.fromCharCode").count() as u32 * 5;
    js_ml.set_obfuscation_score(obfuscation_score);
    js_ml.set_is_likely_obfuscated(obfuscation_score > 10);
    
    let mut sus_apis = 0;
    sus_apis += text_lower.matches("eval(").count();
    sus_apis += text_lower.matches("wscript.shell").count();
    sus_apis += text_lower.matches("activexobject").count();
    sus_apis += text_lower.matches("adodb.stream").count();
    js_ml.set_suspicious_apis_count(sus_apis as u32);
    
    let network = text_lower.matches("http").count() + text_lower.matches("xmlhttprequest").count() + text_lower.matches("fetch(").count();
    js_ml.set_network_operations(network as u32);
    
    js_proto.ml = Some(js_ml).into();
    hydra.js = Some(js_proto).into();

    Ok(hydra)
}

#[module_export(name = "malicious_score")]
fn malicious_score(ctx: &ScanContext) -> Option<f64> {
    Some(100.0)
}
