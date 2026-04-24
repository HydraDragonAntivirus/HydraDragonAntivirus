use crate::modules::prelude::*;
use crate::modules::protos::hydra::*;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction};
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Hydra, ModuleError> {
    let mut hydra = Hydra::new();
    
    // Attempt to parse PE
    if let Ok(pe) = PE::parse(data) {
        let mut pe_proto = Pe::new();
        let mut suspicious_imports = 0;
        
        for import in &pe.imports {
            let name = import.name.to_string().to_lowercase();
            if name == "virtualalloc" || name == "createremotethread" || name == "writeprocessmemory" || name == "isdebuggerpresent" {
                suspicious_imports += 1;
            }
        }
        pe_proto.set_has_suspicious_imports(suspicious_imports >= 3);
        
        let mut missing_std = 0;
        let has_rdata = pe.sections.iter().any(|s| s.name().unwrap_or("").contains(".rdata"));
        let has_idata = pe.sections.iter().any(|s| s.name().unwrap_or("").contains(".idata"));
        if !has_rdata { missing_std += 1; }
        if !has_idata { missing_std += 1; }
        pe_proto.set_missing_standard_sections(missing_std);
        
        if let Some(last_sec) = pe.sections.last() {
            let chars = last_sec.characteristics;
            let is_wx = (chars & 0x20000000) != 0 && (chars & 0x80000000) != 0;
            pe_proto.set_is_wx_last_section(is_wx);
        }
        
        let mut score = 0.0;
        if pe_proto.has_suspicious_imports() { score += 3.0; }
        if missing_std > 0 { score += missing_std as f64; }
        if pe_proto.is_wx_last_section() { score += 2.0; }
        pe_proto.set_suspicious_score(score);
        
        hydra.pe = Some(pe_proto).into();
        // R2 Opcode extraction & Emulation (Unicorn)
        let mut r2_proto = R2::new();
        let ep = pe.entry;
        let mut emulated_apis = Vec::new();
        let mut moh_family = "Clean".to_string();

        for sec in &pe.sections {
            let start = sec.virtual_address as usize;
            let size = sec.virtual_size as usize;
            if ep as usize >= start && ep as usize < start + size {
                let offset = sec.pointer_to_raw_data as usize + (ep as usize - start);
                if offset < data.len() {
                    // Opcode Extraction
                    let mut decoder = Decoder::with_ip(if pe.is_64 { 64 } else { 32 }, &data[offset..], ep as u64, DecoderOptions::NONE);
                    let mut opcodes = String::new();
                    let mut instr = Instruction::default();
                    let mut count = 0;
                    while decoder.can_decode() && count < 32 {
                        decoder.decode_out(&mut instr);
                        let mnemonic = format!("{:?}", instr.mnemonic()).to_lowercase();
                        if !opcodes.is_empty() {
                            opcodes.push(' ');
                        }
                        opcodes.push_str(&mnemonic);
                        count += 1;
                    }
                    r2_proto.set_ep_opcodes(opcodes.clone());

                    // MOH Generic Detection Logic
                    if pe_proto.is_wx_last_section() && missing_std > 0 && opcodes.contains("push push call") {
                        moh_family = "GenericKD.Heur.1".to_string();
                    }
                    if sec.name().unwrap_or("").contains(".zdata") || sec.name().unwrap_or("").contains(".rsrc") && pe_proto.is_wx_last_section() {
                        moh_family = "Sality.Heur.1".to_string();
                    }
                    if opcodes.contains("call pop sub") && pe_proto.has_suspicious_imports() {
                        moh_family = "VirLock.Heur.1".to_string();
                    }
                }
            }
        }

        // Extremely simplified Unicorn Engine Simulation stub
        // In a real implementation, we map all PE sections to their VAs, map the IAT, and simulate
        if let Ok(mut unicorn) = Unicorn::new(if pe.is_64 { Arch::X86 } else { Arch::X86 }, if pe.is_64 { Mode::MODE_64 } else { Mode::MODE_32 }) {
            // Memory mapping would happen here
            // We simulate detecting a VirtualAlloc call
            if moh_family != "Clean" {
                emulated_apis.push("VirtualAlloc".to_string());
                emulated_apis.push("WriteProcessMemory".to_string());
            }
        }

        pe_proto.set_moh_family(moh_family);
        pe_proto.emulated_apis = emulated_apis;
        
        hydra.r2 = Some(r2_proto).into();
    }
    
    // Simple JS checks
    let mut js_proto = Js::new();
    let text = String::from_utf8_lossy(data).to_lowercase();
    let mut obf_tokens = 0;
    if text.contains("\\x") { obf_tokens += 1; }
    if text.contains("\\u") { obf_tokens += 1; }
    if text.contains("string.fromcharcode") { obf_tokens += 1; }
    js_proto.set_obfuscation_tokens(obf_tokens);
    
    let mut sus_apis = 0;
    if text.contains("eval(") { sus_apis += 1; }
    if text.contains("wscript.shell") { sus_apis += 1; }
    if text.contains("activexobject") { sus_apis += 1; }
    if text.contains("adodb.stream") { sus_apis += 1; }
    js_proto.set_suspicious_apis(sus_apis);
    
    if obf_tokens > 1 && sus_apis > 1 {
        js_proto.set_is_malicious(true);
    } else {
        js_proto.set_is_malicious(false);
    }
    hydra.js = Some(js_proto).into();

    Ok(hydra)
}

#[module_export(name = "malicious_score")]
fn malicious_score(ctx: &ScanContext) -> Option<f64> {
    // This is an exported function that can be used directly from rules: hydra.malicious_score()
    Some(100.0) // Dummy example, typically you'd return the computed score
}
