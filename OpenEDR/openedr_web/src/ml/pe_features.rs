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

#[inline]
fn ln1p(x: f32) -> f32 {
    if x.is_nan() || x <= 0.0 {
        0.0
    } else {
        (x + 1.0).ln()
    }
}

// Lenient Pure-Rust PE Parser matching Python pefile
#[derive(Debug, Clone, Default)]
struct DataDir {
    size: u32,
}

#[derive(Debug, Clone, Default)]
struct Section {
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

#[derive(Debug, Clone, Default)]
struct ParsedPe {
    machine: u16,
    characteristics: u16,
    size_of_optional_header: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    num_rva_and_sizes: u32,
    data_dirs: Vec<DataDir>,
    sections: Vec<Section>,
}

fn parse_pe_lenient(data: &[u8]) -> Option<ParsedPe> {
    if data.len() < 64 {
        return None;
    }

    let e_magic = u16::from_le_bytes([data[0], data[1]]);
    if e_magic != 0x5A4D && e_magic != 0x4D5A {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() {
        return None;
    }

    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let fh = e_lfanew + 4;
    let machine = u16::from_le_bytes([data[fh], data[fh + 1]]);
    let number_of_sections = u16::from_le_bytes([data[fh + 2], data[fh + 3]]);
    let size_of_optional_header = u16::from_le_bytes([data[fh + 16], data[fh + 17]]);
    let characteristics = u16::from_le_bytes([data[fh + 18], data[fh + 19]]);

    let mut pe = ParsedPe {
        machine,
        characteristics,
        size_of_optional_header,
        ..Default::default()
    };

    let opt = fh + 20;
    if size_of_optional_header > 0 && opt + 2 <= data.len() {
        let magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
        let is_64 = magic == 0x20B;

        if opt + 28 <= data.len() {
            pe.major_linker_version = data[opt + 2];
            pe.minor_linker_version = data[opt + 3];
            pe.size_of_code = u32::from_le_bytes([data[opt + 4], data[opt + 5], data[opt + 6], data[opt + 7]]);
            pe.size_of_initialized_data = u32::from_le_bytes([data[opt + 8], data[opt + 9], data[opt + 10], data[opt + 11]]);
            pe.size_of_uninitialized_data = u32::from_le_bytes([data[opt + 12], data[opt + 13], data[opt + 14], data[opt + 15]]);
            pe.address_of_entry_point = u32::from_le_bytes([data[opt + 16], data[opt + 17], data[opt + 18], data[opt + 19]]);
        }

        if !is_64 && opt + 68 <= data.len() {
            pe.image_base = u32::from_le_bytes([data[opt + 28], data[opt + 29], data[opt + 30], data[opt + 31]]) as u64;
            pe.section_alignment = u32::from_le_bytes([data[opt + 32], data[opt + 33], data[opt + 34], data[opt + 35]]);
            pe.file_alignment = u32::from_le_bytes([data[opt + 36], data[opt + 37], data[opt + 38], data[opt + 39]]);
            pe.major_os_version = u16::from_le_bytes([data[opt + 40], data[opt + 41]]);
            pe.minor_os_version = u16::from_le_bytes([data[opt + 42], data[opt + 43]]);
            pe.major_image_version = u16::from_le_bytes([data[opt + 44], data[opt + 45]]);
            pe.minor_image_version = u16::from_le_bytes([data[opt + 46], data[opt + 47]]);
            pe.major_subsystem_version = u16::from_le_bytes([data[opt + 48], data[opt + 49]]);
            pe.minor_subsystem_version = u16::from_le_bytes([data[opt + 50], data[opt + 51]]);
            pe.size_of_image = u32::from_le_bytes([data[opt + 56], data[opt + 57], data[opt + 58], data[opt + 59]]);
            pe.size_of_headers = u32::from_le_bytes([data[opt + 60], data[opt + 61], data[opt + 62], data[opt + 63]]);
            pe.checksum = u32::from_le_bytes([data[opt + 64], data[opt + 65], data[opt + 66], data[opt + 67]]);

            if opt + 96 <= data.len() {
                pe.subsystem = u16::from_le_bytes([data[opt + 68], data[opt + 69]]);
                pe.dll_characteristics = u16::from_le_bytes([data[opt + 70], data[opt + 71]]);
                pe.size_of_stack_reserve = u32::from_le_bytes([data[opt + 72], data[opt + 73], data[opt + 74], data[opt + 75]]) as u64;
                pe.size_of_stack_commit = u32::from_le_bytes([data[opt + 76], data[opt + 77], data[opt + 78], data[opt + 79]]) as u64;
                pe.size_of_heap_reserve = u32::from_le_bytes([data[opt + 80], data[opt + 81], data[opt + 82], data[opt + 83]]) as u64;
                pe.size_of_heap_commit = u32::from_le_bytes([data[opt + 84], data[opt + 85], data[opt + 86], data[opt + 87]]) as u64;
                pe.loader_flags = u32::from_le_bytes([data[opt + 88], data[opt + 89], data[opt + 90], data[opt + 91]]);
                pe.num_rva_and_sizes = u32::from_le_bytes([data[opt + 92], data[opt + 93], data[opt + 94], data[opt + 95]]);

                let dd_start = opt + 96;
                let count = pe.num_rva_and_sizes.min(16) as usize;
                for i in 0..count {
                    let cur = dd_start + i * 8;
                    if cur + 8 <= data.len() {
                        let size = u32::from_le_bytes([data[cur + 4], data[cur + 5], data[cur + 6], data[cur + 7]]);
                        pe.data_dirs.push(DataDir { size });
                    }
                }
            }
        } else if is_64 && opt + 108 <= data.len() {
            pe.image_base = u64::from_le_bytes([
                data[opt + 24], data[opt + 25], data[opt + 26], data[opt + 27],
                data[opt + 28], data[opt + 29], data[opt + 30], data[opt + 31],
            ]);
            pe.section_alignment = u32::from_le_bytes([data[opt + 32], data[opt + 33], data[opt + 34], data[opt + 35]]);
            pe.file_alignment = u32::from_le_bytes([data[opt + 36], data[opt + 37], data[opt + 38], data[opt + 39]]);
            pe.major_os_version = u16::from_le_bytes([data[opt + 40], data[opt + 41]]);
            pe.minor_os_version = u16::from_le_bytes([data[opt + 42], data[opt + 43]]);
            pe.major_image_version = u16::from_le_bytes([data[opt + 44], data[opt + 45]]);
            pe.minor_image_version = u16::from_le_bytes([data[opt + 46], data[opt + 47]]);
            pe.major_subsystem_version = u16::from_le_bytes([data[opt + 48], data[opt + 49]]);
            pe.minor_subsystem_version = u16::from_le_bytes([data[opt + 50], data[opt + 51]]);
            pe.size_of_image = u32::from_le_bytes([data[opt + 56], data[opt + 57], data[opt + 58], data[opt + 59]]);
            pe.size_of_headers = u32::from_le_bytes([data[opt + 60], data[opt + 61], data[opt + 62], data[opt + 63]]);
            pe.checksum = u32::from_le_bytes([data[opt + 64], data[opt + 65], data[opt + 66], data[opt + 67]]);
            pe.subsystem = u16::from_le_bytes([data[opt + 68], data[opt + 69]]);
            pe.dll_characteristics = u16::from_le_bytes([data[opt + 70], data[opt + 71]]);
            pe.size_of_stack_reserve = u64::from_le_bytes([
                data[opt + 72], data[opt + 73], data[opt + 74], data[opt + 75],
                data[opt + 76], data[opt + 77], data[opt + 78], data[opt + 79],
            ]);
            pe.size_of_stack_commit = u64::from_le_bytes([
                data[opt + 80], data[opt + 81], data[opt + 82], data[opt + 83],
                data[opt + 84], data[opt + 85], data[opt + 86], data[opt + 87],
            ]);
            pe.size_of_heap_reserve = u64::from_le_bytes([
                data[opt + 88], data[opt + 89], data[opt + 90], data[opt + 91],
                data[opt + 92], data[opt + 93], data[opt + 94], data[opt + 95],
            ]);
            pe.size_of_heap_commit = u64::from_le_bytes([
                data[opt + 96], data[opt + 97], data[opt + 98], data[opt + 99],
                data[opt + 100], data[opt + 101], data[opt + 102], data[opt + 103],
            ]);
            pe.loader_flags = u32::from_le_bytes([data[opt + 104], data[opt + 105], data[opt + 106], data[opt + 107]]);

            if opt + 112 <= data.len() {
                pe.num_rva_and_sizes = u32::from_le_bytes([data[opt + 108], data[opt + 109], data[opt + 110], data[opt + 111]]);
                let dd_start = opt + 112;
                let count = pe.num_rva_and_sizes.min(16) as usize;
                for i in 0..count {
                    let cur = dd_start + i * 8;
                    if cur + 8 <= data.len() {
                        let size = u32::from_le_bytes([data[cur + 4], data[cur + 5], data[cur + 6], data[cur + 7]]);
                        pe.data_dirs.push(DataDir { size });
                    }
                }
            }
        }
    }

    let sec_offset = opt + size_of_optional_header as usize;
    let num_sec = number_of_sections.min(96) as usize;
    for i in 0..num_sec {
        let cur = sec_offset + i * 40;
        if cur + 40 > data.len() {
            break;
        }
        let size_of_raw_data = u32::from_le_bytes([data[cur + 16], data[cur + 17], data[cur + 18], data[cur + 19]]);
        let pointer_to_raw_data = u32::from_le_bytes([data[cur + 20], data[cur + 21], data[cur + 22], data[cur + 23]]);

        pe.sections.push(Section {
            size_of_raw_data,
            pointer_to_raw_data,
        });
    }

    Some(pe)
}

pub fn extract_pe_features(bytes: &[u8]) -> Option<PeFeatureVector> {
    extract_pe_features_with_disasm(bytes, None)
}

/// `disasm` = `(total_instructions, total_add, total_mov)` precomputed
/// outside wasm (e.g. capstone.js in the browser). `None` zeroes indices
/// 51..53; the tree ensemble substitutes 0.0 for missing features.
pub fn extract_pe_features_with_disasm(
    bytes: &[u8],
    disasm: Option<(u64, u64, u64)>,
) -> Option<PeFeatureVector> {
    let pe = parse_pe_lenient(bytes)?;

    let sections = &pe.sections;
    let section_count = sections.len() as f32;
    let size_of_image = pe.size_of_image;

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

    // Web/WASM edition: no disassembler available in-Rust (capstone is
    // native-only). Counts arrive from capstone.js via the `_ex` scan API;
    // without them indices 51..53 stay 0.0 and the tree ensemble degrades
    // gracefully instead of breaking model compatibility.
    let (total_instructions, total_add, total_mov) = disasm.unwrap_or((0, 0, 0));

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

    // Data Directory entries (Standard 16 entries)
    let get_dd = |idx: usize| pe.data_dirs.get(idx).cloned().unwrap_or_default();

    let exp = get_dd(0);
    let imp = get_dd(1);
    let res = get_dd(2);
    let exc = get_dd(3);
    let cert = get_dd(4);
    let reloc = get_dd(5);
    let debug = get_dd(6);
    let tls = get_dd(9);
    let load_cfg = get_dd(10);
    let bound_imp = get_dd(11);
    let iat = get_dd(12);
    let delay_imp = get_dd(13);
    let clr = get_dd(14);

    let export_table_size = exp.size as f32;
    let import_table_size = imp.size as f32;
    let resource_table_size = res.size as f32;
    let exception_table_size = exc.size as f32;
    let certificate_table_size = cert.size as f32;
    let base_relocation_table_size = reloc.size as f32;
    let debug_table_size = debug.size as f32;
    let tls_table_size = tls.size as f32;
    let load_config_table_size = load_cfg.size as f32;
    let bound_import_table_size = bound_imp.size as f32;
    let iat_table_size = iat.size as f32;
    let delay_import_table_size = delay_imp.size as f32;
    let clr_runtime_header_size = clr.size as f32;

    let imports_count = if imp.size >= 20 { (imp.size / 20) as f32 } else { 0.0 };
    let exports_count = if exp.size >= 40 { (exp.size / 40) as f32 } else { 0.0 };
    let resources_count = if res.size >= 16 { (res.size / 16) as f32 } else { 0.0 };
    let num_delay_imports = if delay_imp.size >= 32 { (delay_imp.size / 32) as f32 } else { 0.0 };
    let num_bound_imports = if bound_imp.size >= 8 { (bound_imp.size / 8) as f32 } else { 0.0 };
    let num_debug_entries = if debug.size >= 28 { (debug.size / 28) as f32 } else { 0.0 };
    let num_reloc_blocks = if reloc.size >= 8 { (reloc.size / 8) as f32 } else { 0.0 };
    let num_reloc_entries = if reloc.size >= 8 { ((reloc.size - 8) / 2) as f32 } else { 0.0 };
    let num_tls_callbacks = if tls.size >= 24 { 1.0 } else { 0.0 };
    let cert_size = cert.size as f32;

    Some(PeFeatureVector {
        size_of_optional_header: ln1p(pe.size_of_optional_header as f32),
        coff_characteristics: ln1p(pe.characteristics as f32),
        machine: ln1p(pe.machine as f32),
        major_linker_version: pe.major_linker_version as f32,
        minor_linker_version: pe.minor_linker_version as f32,
        size_of_code: ln1p(pe.size_of_code as f32),
        size_of_initialized_data: ln1p(pe.size_of_initialized_data as f32),
        size_of_uninitialized_data: ln1p(pe.size_of_uninitialized_data as f32),
        address_of_entry_point: ln1p(pe.address_of_entry_point as f32),
        image_base: ln1p(pe.image_base as f32),
        section_alignment: ln1p(pe.section_alignment as f32),
        file_alignment: ln1p(pe.file_alignment as f32),
        major_operating_system_version: pe.major_os_version as f32,
        minor_operating_system_version: pe.minor_os_version as f32,
        major_image_version: pe.major_image_version as f32,
        minor_image_version: pe.minor_image_version as f32,
        major_subsystem_version: pe.major_subsystem_version as f32,
        minor_subsystem_version: pe.minor_subsystem_version as f32,
        size_of_image: ln1p(size_of_image as f32),
        size_of_headers: ln1p(pe.size_of_headers as f32),
        checksum: ln1p(pe.checksum as f32),
        subsystem: pe.subsystem as f32,
        dll_characteristics: ln1p(pe.dll_characteristics as f32),
        size_of_stack_reserve: ln1p(pe.size_of_stack_reserve as f32),
        size_of_stack_commit: ln1p(pe.size_of_stack_commit as f32),
        size_of_heap_reserve: ln1p(pe.size_of_heap_reserve as f32),
        size_of_heap_commit: ln1p(pe.size_of_heap_commit as f32),
        loader_flags: ln1p(pe.loader_flags as f32),
        number_of_rva_and_sizes: ln1p(pe.num_rva_and_sizes as f32),
        export_table_size: ln1p(export_table_size),
        import_table_size: ln1p(import_table_size),
        resource_table_size: ln1p(resource_table_size),
        exception_table_size: ln1p(exception_table_size),
        certificate_table_size: ln1p(certificate_table_size),
        base_relocation_table_size: ln1p(base_relocation_table_size),
        debug_table_size: ln1p(debug_table_size),
        tls_table_size: ln1p(tls_table_size),
        load_config_table_size: ln1p(load_config_table_size),
        bound_import_table_size: ln1p(bound_import_table_size),
        iat_table_size: ln1p(iat_table_size),
        delay_import_table_size: ln1p(delay_import_table_size),
        clr_runtime_header_size: ln1p(clr_runtime_header_size),
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
