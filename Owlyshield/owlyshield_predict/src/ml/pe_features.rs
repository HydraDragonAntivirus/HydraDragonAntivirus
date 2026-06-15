use std::collections::HashMap;
use std::path::Path;

use goblin::pe::PE;
use goblin::Object;

use super::features::PeFeatureVector;

/// Shannon entropy of a byte slice.
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let len = data.len() as f32;
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Extract PE features from a byte buffer using goblin + capstone.
pub fn extract_pe_features(bytes: &[u8]) -> Option<PeFeatureVector> {
    let obj = Object::parse(bytes).ok()?;
    let pe = match obj {
        Object::PE(pe) => pe,
        _ => return None,
    };

    let opt = pe.header.optional_header.as_ref()?;
    let sf = &opt.standard_fields;
    let wf = &opt.windows_fields;

    let sections = &pe.sections;
    let section_count = sections.len() as f32;

    let imports_count = pe.imports.len() as f32;

    let exports_count = pe.exports.iter().filter_map(|e| e.name).count() as f32;

    let size_of_image = wf.size_of_image;

    // Section entropy stats
    let mut entropies: Vec<f32> = sections
        .iter()
        .map(|s| {
            let start = s.pointer_to_raw_data as usize;
            let size = s.size_of_raw_data as usize;
            let data = if start < bytes.len() {
                &bytes[start..(start + size).min(bytes.len())]
            } else {
                &[]
            };
            shannon_entropy(data)
        })
        .collect();
    entropies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sec_entropy_mean = if entropies.is_empty() {
        0.0
    } else {
        entropies.iter().sum::<f32>() / entropies.len() as f32
    };
    let sec_entropy_min = *entropies.first().unwrap_or(&0.0);
    let sec_entropy_max = *entropies.last().unwrap_or(&0.0);

    // Capstone disassembly of sections
    let arch = if pe.header.coff_header.machine == 0x8664 {
        capstone::Arch::X86
    } else {
        capstone::Arch::X86
    };
    let mode = if pe.header.coff_header.machine == 0x8664 {
        capstone::Mode::Mode64
    } else {
        capstone::Mode::Mode32
    };

    let mut total_instructions = 0u64;
    let mut total_add = 0u64;
    let mut total_mov = 0u64;

    for section in sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let code = if start < bytes.len() {
            &bytes[start..(start + size).min(bytes.len())]
        } else {
            continue;
        };
        if code.is_empty() {
            continue;
        }
        let base_addr = pe.image_base.wrapping_add(section.virtual_address as u64);

        if let Ok(cs) = capstone::Capstone::new(arch, mode) {
            if let Ok(insns) = cs.disasm_all(code, base_addr) {
                for insn in insns.iter() {
                    total_instructions += 1;
                    match insn.mnemonic() {
                        Some(m) if m == "add" => total_add += 1,
                        Some(m) if m == "mov" => total_mov += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    let likely_packed = if total_instructions > 0 {
        (total_add > total_mov) as u8 as f32
    } else {
        0.0
    };
    let add_mov_ratio = if total_mov > 0 {
        total_add as f32 / total_mov as f32
    } else {
        0.0
    };
    let instructions_per_kb = if size_of_image > 0 {
        total_instructions as f32 / ((size_of_image as f32) / 1024.0 + 1e-6)
    } else {
        0.0
    };

    // Overlay detection
    let last_section = sections.iter().max_by_key(|s| {
        s.pointer_to_raw_data.saturating_add(s.size_of_raw_data)
    });
    let (overlay_exists, overlay_size) = if let Some(ls) = last_section {
        let pe_end = (ls.pointer_to_raw_data as u64).saturating_add(ls.size_of_raw_data as u64);
        let file_size = bytes.len() as u64;
        if file_size > pe_end {
            (1.0, (file_size - pe_end) as f32)
        } else {
            (0.0, 0.0)
        }
    } else {
        (0.0, 0.0)
    };

    // Rich header detection
    let has_rich_header = detect_rich_header(bytes) as u8 as f32;

    Some(PeFeatureVector {
        size_of_optional_header: pe.header.coff_header.size_of_optional_header as f32,
        major_linker_version: sf.major_linker_version as f32,
        minor_linker_version: sf.minor_linker_version as f32,
        size_of_code: sf.size_of_code as f32,
        size_of_initialized_data: sf.size_of_initialized_data as f32,
        size_of_uninitialized_data: sf.size_of_uninitialized_data as f32,
        address_of_entry_point: sf.address_of_entry_point as f32,
        image_base: pe.image_base as f32,
        subsystem: wf.subsystem as f32,
        dll_characteristics: wf.dll_characteristics as f32,
        size_of_stack_reserve: wf.size_of_stack_reserve as f32,
        size_of_heap_reserve: wf.size_of_heap_reserve as f32,
        checksum: wf.check_sum as f32,
        number_of_rva_and_sizes: wf.number_of_rva_and_sizes as f32,
        size_of_image: size_of_image as f32,
        imports_count,
        exports_count,
        resources_count: 0.0,
        sections_count: section_count,
        sec_entropy_mean,
        sec_entropy_min,
        sec_entropy_max,
        total_instructions: total_instructions as f32,
        total_add_instructions: total_add as f32,
        total_mov_instructions: total_mov as f32,
        is_likely_packed: likely_packed,
        add_mov_ratio,
        instructions_per_kb,
        overlay_exists,
        overlay_size,
        num_tls_callbacks: 0.0,
        num_delay_imports: 0.0,
        num_reloc_entries: 0.0,
        num_reloc_blocks: 0.0,
        num_bound_imports: 0.0,
        num_debug_entries: 0.0,
        cert_size: 0.0,
        has_rich_header,
    })
}

fn detect_rich_header(bytes: &[u8]) -> bool {
    // Simple Rich header detection: look for "Rich" marker
    bytes.windows(4).any(|w| w == b"Rich")
}
