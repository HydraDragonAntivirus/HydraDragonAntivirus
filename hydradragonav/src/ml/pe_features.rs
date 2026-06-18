use capstone::arch::x86::ArchMode as X86Mode;
use capstone::arch::BuildsCapstone;
use goblin::Object;

use super::features::PeFeatureVector;

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

// Maps unbounded counts/sizes into a compact range for the neural network.
// ln(0+1)=0, ln(1000+1)≈6.9, ln(1e9+1)≈20.7 — avoids the billions-scale
// raw values (e.g. image_base=0x140000000) that saturate the network weights.
#[inline]
fn ln1p(x: f32) -> f32 {
    (x + 1.0).ln()
}

// Parses the root IMAGE_RESOURCE_DIRECTORY to count top-level resource types.
fn count_resources(bytes: &[u8], pe: &goblin::pe::PE) -> f32 {
    let opt = match pe.header.optional_header.as_ref() {
        Some(o) => o,
        None => return 0.0,
    };
    let res_dir = match opt.data_directories.get_resource_table() {
        Some(d) if d.virtual_address > 0 && d.size >= 16 => d,
        _ => return 0.0,
    };
    let rva = res_dir.virtual_address as usize;
    let section = pe.sections.iter().find(|s| {
        let start = s.virtual_address as usize;
        let end = start + s.virtual_size as usize;
        rva >= start && rva < end
    });
    let section = match section {
        Some(s) => s,
        None => return 0.0,
    };
    let offset = rva
        .wrapping_sub(section.virtual_address as usize)
        .wrapping_add(section.pointer_to_raw_data as usize);
    if offset + 16 > bytes.len() {
        return 0.0;
    }
    let num_named = u16::from_le_bytes([bytes[offset + 12], bytes[offset + 13]]);
    let num_id = u16::from_le_bytes([bytes[offset + 14], bytes[offset + 15]]);
    (num_named as u32 + num_id as u32) as f32
}

// Parses IMAGE_BASE_RELOCATION blocks and returns (num_blocks, num_entries).
fn count_relocations(bytes: &[u8], pe: &goblin::pe::PE) -> (f32, f32) {
    let opt = match pe.header.optional_header.as_ref() {
        Some(o) => o,
        None => return (0.0, 0.0),
    };
    let reloc_dir = match opt.data_directories.get_base_relocation_table() {
        Some(d) if d.virtual_address > 0 && d.size >= 8 => d,
        _ => return (0.0, 0.0),
    };
    let rva = reloc_dir.virtual_address as usize;
    let section = pe.sections.iter().find(|s| {
        let start = s.virtual_address as usize;
        let end = start + s.virtual_size as usize;
        rva >= start && rva < end
    });
    let section = match section {
        Some(s) => s,
        None => return (0.0, 0.0),
    };
    let base = rva
        .wrapping_sub(section.virtual_address as usize)
        .wrapping_add(section.pointer_to_raw_data as usize);
    let table_end = base + reloc_dir.size as usize;
    if table_end > bytes.len() {
        return (0.0, 0.0);
    }

    let mut offset = base;
    let mut num_blocks = 0u32;
    let mut num_entries = 0u32;
    while offset + 8 <= table_end {
        let block_size = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        if block_size < 8 {
            break;
        }
        num_blocks += 1;
        num_entries += (block_size - 8) / 2;
        offset += block_size as usize;
    }
    (num_blocks as f32, num_entries as f32)
}

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

    let mode = if pe.header.coff_header.machine == 0x8664 {
        X86Mode::Mode64
    } else {
        X86Mode::Mode32
    };

    let mut total_instructions = 0u64;
    let mut total_add = 0u64;
    let mut total_mov = 0u64;

    if let Ok(cs) = capstone::Capstone::new().x86().mode(mode).build() {
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
        (total_add as f32 / total_mov as f32).min(10.0)
    } else {
        0.0
    };
    let instructions_per_kb = if size_of_image > 0 {
        (total_instructions as f32 / (size_of_image as f32 / 1024.0 + 1e-6)).min(1000.0)
    } else {
        0.0
    };

    let last_section = sections
        .iter()
        .max_by_key(|s| s.pointer_to_raw_data.saturating_add(s.size_of_raw_data));
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

    let has_rich_header = detect_rich_header(bytes) as u8 as f32;

    // Previously hardcoded to 0.0 — now computed using goblin 0.10.x API.
    let resources_count = count_resources(bytes, &pe);

    let num_tls_callbacks = pe.tls_data.as_ref().map(|t| t.callbacks.len()).unwrap_or(0) as f32;

    // goblin 0.10.x ImportData only exposes raw bytes; use the data directory
    // size to estimate delay import count (each IMAGE_DELAY_LOAD_INFO = 32 bytes).
    let num_delay_imports = opt
        .data_directories
        .get_delay_import_descriptor()
        .filter(|d| d.virtual_address > 0 && d.size >= 32)
        .map(|d| (d.size / 32) as f32)
        .unwrap_or(0.0);

    let (num_reloc_blocks, num_reloc_entries) = count_relocations(bytes, &pe);

    // Bound import directory size / 8 bytes per BOUND_IMPORT_DESCRIPTOR.
    let num_bound_imports = opt
        .data_directories
        .get_bound_import_table()
        .filter(|d| d.virtual_address > 0 && d.size >= 8)
        .map(|d| (d.size / 8) as f32)
        .unwrap_or(0.0);

    // Count how many distinct debug record types are present (goblin 0.10.x
    // parses each debug type into its own Option field instead of a Vec).
    let num_debug_entries = pe
        .debug_data
        .as_ref()
        .map(|d| {
            d.codeview_pdb70_debug_info.is_some() as u32
                + d.codeview_pdb20_debug_info.is_some() as u32
                + d.vcfeature_info.is_some() as u32
                + d.ex_dll_characteristics_info.is_some() as u32
                + d.repro_info.is_some() as u32
                + d.pogo_info.is_some() as u32
        })
        .unwrap_or(0) as f32;

    // pe.certificates is Vec<AttributeCertificate<'_>> in goblin 0.10.x.
    let cert_size = pe
        .certificates
        .iter()
        .map(|c| c.certificate.len())
        .sum::<usize>() as f32;

    // Entropy is already bounded [0, 8] — no log needed.
    // Boolean flags and small-range counts (subsystem 0-17, sections 0-96) stay raw.
    // Ratios (add_mov_ratio, instructions_per_kb) are capped above, so stay raw.
    // Everything else uses ln(x+1) to collapse the multi-million/billion-scale values.
    Some(PeFeatureVector {
        size_of_optional_header: pe.header.coff_header.size_of_optional_header as f32,
        major_linker_version: sf.major_linker_version as f32,
        minor_linker_version: sf.minor_linker_version as f32,
        size_of_code: ln1p(sf.size_of_code as f32),
        size_of_initialized_data: ln1p(sf.size_of_initialized_data as f32),
        size_of_uninitialized_data: ln1p(sf.size_of_uninitialized_data as f32),
        address_of_entry_point: ln1p(sf.address_of_entry_point as f32),
        image_base: ln1p(pe.image_base as f32),
        subsystem: wf.subsystem as f32,
        dll_characteristics: wf.dll_characteristics as f32,
        size_of_stack_reserve: ln1p(wf.size_of_stack_reserve as f32),
        size_of_heap_reserve: ln1p(wf.size_of_heap_reserve as f32),
        checksum: ln1p(wf.check_sum as f32),
        number_of_rva_and_sizes: wf.number_of_rva_and_sizes as f32,
        size_of_image: ln1p(size_of_image as f32),
        imports_count: ln1p(imports_count),
        exports_count: ln1p(exports_count),
        resources_count: ln1p(resources_count),
        sections_count: section_count,
        overlay_exists,
        overlay_size: ln1p(overlay_size),
        sec_entropy_mean,
        sec_entropy_min,
        sec_entropy_max,
        total_instructions: ln1p(total_instructions as f32),
        total_add_instructions: ln1p(total_add as f32),
        total_mov_instructions: ln1p(total_mov as f32),
        is_likely_packed: likely_packed,
        add_mov_ratio,
        instructions_per_kb,
        num_tls_callbacks,
        num_delay_imports,
        num_reloc_entries: ln1p(num_reloc_entries),
        num_reloc_blocks: ln1p(num_reloc_blocks),
        num_bound_imports,
        num_debug_entries,
        cert_size: ln1p(cert_size),
        has_rich_header,
    })
}

fn detect_rich_header(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == b"Rich")
}
