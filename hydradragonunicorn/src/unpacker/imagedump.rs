use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Write};
use unicorn_engine::Unicorn;

use crate::unpacker::error::{UnpackerError, UnpackerResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IMAGE_SIZEOF_SHORT_NAME: usize = 8;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;

const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;

const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;

const IMAGE_SNAP_BY_ORDINAL: u32 = 0x80000000;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl Section {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(IMAGE_SIZEOF_SECTION_HEADER);
        let mut w = Cursor::new(&mut buf);

        let name_bytes = self.name.as_bytes();
        let mut name_arr = [0u8; IMAGE_SIZEOF_SHORT_NAME];
        let copy_len = name_bytes.len().min(IMAGE_SIZEOF_SHORT_NAME);
        name_arr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        let _ = w.write_all(&name_arr);
        let _ = w.write_u32::<LittleEndian>(self.virtual_size);
        let _ = w.write_u32::<LittleEndian>(self.virtual_address);
        let _ = w.write_u32::<LittleEndian>(self.size_of_raw_data);
        let _ = w.write_u32::<LittleEndian>(self.pointer_to_raw_data);
        let _ = w.write_u32::<LittleEndian>(self.pointer_to_relocations);
        let _ = w.write_u32::<LittleEndian>(self.pointer_to_linenumbers);
        let _ = w.write_u16::<LittleEndian>(self.number_of_relocations);
        let _ = w.write_u16::<LittleEndian>(self.number_of_linenumbers);
        let _ = w.write_u32::<LittleEndian>(self.characteristics);
        buf
    }
}

#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
    pub dll_name: String,
    pub imports: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DumpContext {
    pub virtualmemorysize: u64,
    pub hook_addr: u64,
    pub ntp: HashMap<String, (bool, bool, bool)>,
    pub dllname_to_functionlist: HashMap<String, Vec<(String, u64)>>,
    pub allocated_chunks: Vec<(u64, u64)>,
    pub original_imports: Vec<ImportDescriptor>,
    pub sections: Vec<Section>,
}

impl DumpContext {
    pub fn new(
        virtualmemorysize: u64,
        hook_addr: u64,
    ) -> Self {
        Self {
            virtualmemorysize,
            hook_addr,
            ntp: HashMap::new(),
            dllname_to_functionlist: HashMap::new(),
            allocated_chunks: Vec::new(),
            original_imports: Vec::new(),
            sections: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// PE header parsing helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], offset: usize) -> u16 {
    let mut r = Cursor::new(&data[offset..offset + 2]);
    r.read_u16::<LittleEndian>().unwrap_or(0)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    let mut r = Cursor::new(&data[offset..offset + 4]);
    r.read_u32::<LittleEndian>().unwrap_or(0)
}

fn write_u16(data: &mut [u8], offset: usize, val: u16) {
    let mut w = Cursor::new(&mut data[offset..offset + 2]);
    let _ = w.write_u16::<LittleEndian>(val);
}

fn write_u32(data: &mut [u8], offset: usize, val: u32) {
    let mut w = Cursor::new(&mut data[offset..offset + 4]);
    let _ = w.write_u32::<LittleEndian>(val);
}

fn pe_signature_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = read_u32(data, 0x3C) as usize;
    if e_lfanew + 4 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    Some(e_lfanew)
}

/// Parse PE headers and return (optional_header_offset, is_pe32plus, number_of_sections,
/// size_of_optional_header, sections_end_offset)
fn parse_pe_headers(
    data: &[u8],
) -> Option<(usize, bool, u16, u16, usize)> {
    let sig_offset = pe_signature_offset(data)?;
    let coff_offset = sig_offset + 4;

    let machine = read_u16(data, coff_offset);
    let is_supported_machine = matches!(
        machine,
        0x14c | 0x8664 | 0x1c0 | 0x1c2 | 0x1c4 | 0xaa64 | 0xa641 | 0xa64e
    );
    if !is_supported_machine {
        return None;
    }

    let number_of_sections = read_u16(data, coff_offset + 2);
    let size_of_optional_header = read_u16(data, coff_offset + 16);

    let optional_header_offset = coff_offset + 20;

    if optional_header_offset + 2 > data.len() {
        return None;
    }

    let magic = read_u16(data, optional_header_offset);
    let is_pe32plus = match magic {
        PE32_MAGIC => false,
        PE32_PLUS_MAGIC => true,
        _ => return None,
    };

    let sections_end = optional_header_offset + size_of_optional_header as usize;

    Some((optional_header_offset, is_pe32plus, number_of_sections, size_of_optional_header, sections_end))
}

fn read_section_headers(data: &[u8], section_hdr_offset: usize, count: u16) -> Vec<Section> {
    let mut sections = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = section_hdr_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
        if off + IMAGE_SIZEOF_SECTION_HEADER > data.len() {
            break;
        }
        let name_raw = &data[off..off + IMAGE_SIZEOF_SHORT_NAME];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(IMAGE_SIZEOF_SHORT_NAME);
        let name = String::from_utf8_lossy(&name_raw[..name_end]).to_string();

        sections.push(Section {
            name,
            virtual_size: read_u32(data, off + 8),
            virtual_address: read_u32(data, off + 12),
            size_of_raw_data: read_u32(data, off + 16),
            pointer_to_raw_data: read_u32(data, off + 20),
            pointer_to_relocations: read_u32(data, off + 24),
            pointer_to_linenumbers: read_u32(data, off + 28),
            number_of_relocations: read_u16(data, off + 32),
            number_of_linenumbers: read_u16(data, off + 34),
            characteristics: read_u32(data, off + 36),
        });
    }
    sections
}

fn align_up(val: u32, align: u32) -> u32 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Section fix-ups
// ---------------------------------------------------------------------------

/// Fix section sizes and raw pointers for a virtual-memory PE image dump where
/// each section's raw data sits at its `VirtualAddress` in the buffer.
pub fn fix_sections(data: &mut [u8], file_align: u32) -> UnpackerResult<()> {
    let (opt_hdr_off, _, number_of_sections, _, sections_end) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;

    let align_val = file_align.max(0x200);
    if opt_hdr_off + 40 <= data.len() {
        write_u32(data, opt_hdr_off + 36, align_val);
    }

    let section_hdr_offset = sections_end;

    for i in 0..number_of_sections as usize {
        let off = section_hdr_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
        if off + IMAGE_SIZEOF_SECTION_HEADER > data.len() {
            break;
        }

        let curr_va = read_u32(data, off + 12);
        let curr_vs = read_u32(data, off + 8);

        let next_raw_size = if i + 1 < number_of_sections as usize {
            let next_off = section_hdr_offset + (i + 1) * IMAGE_SIZEOF_SECTION_HEADER;
            let next_va = read_u32(data, next_off + 12);
            let raw_size = next_va.saturating_sub(curr_va);
            align_up(raw_size, align_val)
        } else {
            align_up(curr_vs, align_val)
        };
        let max_avail = (data.len().saturating_sub(curr_va as usize)) as u32;
        let clamped_raw = next_raw_size.min(max_avail);

        write_u32(data, off + 16, clamped_raw);
        write_u32(data, off + 20, if clamped_raw == 0 { 0 } else { curr_va });
    }

    Ok(())
}

/// Restore memory protections from tracking data into section characteristics.
pub fn fix_section_mem_protections(
    data: &mut [u8],
    allocated_chunks: &[(u64, u64)],
    base_addr: u64,
) -> UnpackerResult<()> {
    let (_, _, number_of_sections, _, sections_end) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;

    let section_hdr_offset = sections_end;

    for i in 0..number_of_sections as usize {
        let off = section_hdr_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
        if off + IMAGE_SIZEOF_SECTION_HEADER > data.len() {
            break;
        }

        let curr_va = read_u32(data, off + 12) as u64;
        let curr_vs = read_u32(data, off + 8) as u64;
        let section_start = base_addr + curr_va;
        let section_end = section_start + curr_vs;

        let mut prot = IMAGE_SCN_MEM_READ;

        for &(chunk_start, chunk_end) in allocated_chunks {
            if chunk_start >= section_start && chunk_end <= section_end {
                if chunk_end - chunk_start >= 0x1000 {
                    prot |= IMAGE_SCN_MEM_WRITE;
                }
            }
        }

        let characteristics = read_u32(data, off + 36);
        let new_char = characteristics | prot | IMAGE_SCN_CNT_INITIALIZED_DATA;
        write_u32(data, off + 36, new_char);
    }

    Ok(())
}

/// Add a new section header to the PE.
pub fn add_section(
    data: &mut Vec<u8>,
    name: &str,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
) -> UnpackerResult<()> {
    let (_, _, _, _, sections_end) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;

    let new_section = Section {
        name: name.to_string(),
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics,
    };

    let section_bytes = new_section.to_bytes();

    // Find actual end of section headers
    let (_, _, old_num_sections, _, _) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let coff_offset = pe_signature_offset(data).unwrap() + 4;

    // Update number of sections
    write_u16(data, coff_offset + 2, old_num_sections + 1);

    // Append section header at end
    let section_hdr_offset = sections_end + old_num_sections as usize * IMAGE_SIZEOF_SECTION_HEADER;
    if section_hdr_offset + IMAGE_SIZEOF_SECTION_HEADER > data.len() {
        data.resize(section_hdr_offset + IMAGE_SIZEOF_SECTION_HEADER, 0);
    }
    let slice = &mut data[section_hdr_offset..section_hdr_offset + IMAGE_SIZEOF_SECTION_HEADER];
    slice.copy_from_slice(&section_bytes[..IMAGE_SIZEOF_SECTION_HEADER]);

    Ok(())
}

/// Convert allocated memory chunks to section headers.
pub fn chunk_to_image_section_hdr(
    chunks: &[(u64, u64)],
    base_addr: u64,
    sections: &mut Vec<Section>,
) {
    for (i, &(start, end)) in chunks.iter().enumerate() {
        let size = end.saturating_sub(start);
        if size == 0 {
            continue;
        }
        let rva = start.saturating_sub(base_addr) as u32;
        let name = format!(".uc{:02x}", i);

        let mut characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
        if size >= 0x1000 {
            characteristics |= IMAGE_SCN_MEM_WRITE;
        }

        sections.push(Section {
            name,
            virtual_size: size as u32,
            virtual_address: rva,
            size_of_raw_data: size as u32,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics,
        });
    }
}

// ---------------------------------------------------------------------------
// Import rebuilding
// ---------------------------------------------------------------------------

/// Find IAT entries in the dumped binary.
/// Scans the binary for RVAs that fall within the import address table range.
pub fn find_iat(
    data: &[u8],
    import_rvas: &[(u32, u32)],
) -> Vec<(usize, u32)> {
    let mut found = Vec::new();

    if data.len() < 4 {
        return found;
    }

    // Search every 4-byte aligned position for pointers into the IAT
    let word_count = data.len() / 4;
    for i in 0..word_count {
        let off = i * 4;
        let val = read_u32(data, off);
        for &(iat_start, iat_end) in import_rvas {
            if val >= iat_start && val < iat_end {
                found.push((off, val));
                break;
            }
        }
    }

    found
}

/// Write patched import addresses into the binary.
pub fn patch_iat(data: &mut [u8], patches: &[(usize, u32)]) {
    for &(offset, value) in patches {
        if offset + 4 <= data.len() {
            write_u32(data, offset, value);
        }
    }
}

/// Fix imports by rebuilding the IAT using tracked function addresses.
/// This creates new import descriptors in a new section and patches the data directory.
pub fn fix_imports_by_rebuilding(
    data: &mut Vec<u8>,
    ctx: &DumpContext,
    image_size: u32,
    section_alignment: u32,
    file_alignment: u32,
) -> UnpackerResult<Vec<ImportDescriptor>> {
    if ctx.dllname_to_functionlist.is_empty() {
        return Ok(ctx.original_imports.clone());
    }

    let (opt_hdr_off, is_pe64, _, _, _) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;

    let data_dir_offset = if is_pe64 {
        opt_hdr_off + 112
    } else {
        opt_hdr_off + 96
    };

    let import_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
    let iat_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_IAT * 8;

    // Place new import section at the end of virtual address space
    let import_section_rva = align_up(image_size, section_alignment);

    #[derive(Clone, Copy)]
    enum ThunkSpec {
        Ordinal(u16),
        Named(u32), // relative offset into hint_name_data
    }

    #[derive(Default)]
    struct DllImportData {
        dll_name_bytes: Vec<u8>,
        hint_name_data: Vec<u8>,
        thunk_specs: Vec<ThunkSpec>,
    }

    let mut dll_pairs: Vec<(&String, &Vec<(String, u64)>)> = ctx
        .dllname_to_functionlist
        .iter()
        .filter(|(_, fns)| !fns.is_empty())
        .collect();
    dll_pairs.sort_by(|a, b| a.0.cmp(b.0));

    let mut dll_entries: Vec<(String, DllImportData)> = Vec::new();

    for (dll_name, functions) in dll_pairs {
        let mut dll = DllImportData::default();

        // DLL name (null-terminated, 2-byte aligned)
        dll.dll_name_bytes = dll_name.as_bytes().to_vec();
        dll.dll_name_bytes.push(0);
        if dll.dll_name_bytes.len() % 2 != 0 {
            dll.dll_name_bytes.push(0);
        }

        // Build hint/name entries (relative to `hint_name_data` start) and thunk specs
        for (func_name, _func_addr) in functions {
            if func_name.starts_with("ord_") {
                let ordinal: u16 = func_name[4..].parse().unwrap_or(0);
                dll.thunk_specs.push(ThunkSpec::Ordinal(ordinal));
            } else {
                let rel_off = dll.hint_name_data.len() as u32;
                let _ = dll.hint_name_data.write_u16::<LittleEndian>(0); // hint
                dll.hint_name_data.extend_from_slice(func_name.as_bytes());
                dll.hint_name_data.push(0);
                if dll.hint_name_data.len() % 2 != 0 {
                    dll.hint_name_data.push(0);
                }
                dll.thunk_specs.push(ThunkSpec::Named(rel_off));
            }
        }

        dll_entries.push((dll_name.clone(), dll));
    }

    let num_dlls = dll_entries.len();
    if num_dlls == 0 {
        return Ok(ctx.original_imports.clone());
    }

    let ptr_size: u32 = if is_pe64 { 8 } else { 4 };

    // Layout within `.import` section:
    // [descriptor_1..descriptor_N][zero_descriptor]
    // [iat_1..iat_N]             (contiguous -> valid IMAGE_DIRECTORY_ENTRY_IAT)
    // [oft_1..oft_N]             (INT arrays)
    // [dll_name_1 + hint_name_1 .. dll_name_N + hint_name_N]
    let descriptors_size = (num_dlls + 1) * 20;

    struct LayoutEntry {
        iat_offset: u32,
        oft_offset: u32,
        dll_name_offset: u32,
        hint_name_offset: u32,
        desc_idx: usize,
    }

    let mut cur = align_up(descriptors_size as u32, ptr_size);
    let iat_block_start = cur;
    let mut iat_offsets = Vec::with_capacity(num_dlls);
    for (_, dll) in &dll_entries {
        iat_offsets.push(cur);
        cur += ((dll.thunk_specs.len() as u32) + 1) * ptr_size;
    }
    let iat_block_size = cur - iat_block_start;

    let mut oft_offsets = Vec::with_capacity(num_dlls);
    for (_, dll) in &dll_entries {
        oft_offsets.push(cur);
        cur += ((dll.thunk_specs.len() as u32) + 1) * ptr_size;
    }

    let mut layout: Vec<LayoutEntry> = Vec::with_capacity(num_dlls);
    for (idx, (_dll_name, dll)) in dll_entries.iter().enumerate() {
        let dll_name_offset = cur;
        cur += dll.dll_name_bytes.len() as u32;

        let hint_name_offset = cur;
        cur += dll.hint_name_data.len() as u32;

        layout.push(LayoutEntry {
            iat_offset: iat_offsets[idx],
            oft_offset: oft_offsets[idx],
            dll_name_offset,
            hint_name_offset,
            desc_idx: idx,
        });
    }

    let section_data_size = cur as usize;
    let mut section_data = vec![0u8; section_data_size];

    // Write descriptors, IAT, OFT, DLL names, and hint/name strings with true RVAs
    for entry in &layout {
        let desc_off = entry.desc_idx * 20;
        let dll = &dll_entries[entry.desc_idx].1;

        let oft_rva = import_section_rva + entry.oft_offset;
        let name_rva = import_section_rva + entry.dll_name_offset;
        let iat_rva = import_section_rva + entry.iat_offset;

        write_u32(&mut section_data, desc_off, oft_rva);
        write_u32(&mut section_data, desc_off + 4, 0);
        write_u32(&mut section_data, desc_off + 8, 0);
        write_u32(&mut section_data, desc_off + 12, name_rva);
        write_u32(&mut section_data, desc_off + 16, iat_rva);

        let name_start = entry.dll_name_offset as usize;
        section_data[name_start..name_start + dll.dll_name_bytes.len()].copy_from_slice(&dll.dll_name_bytes);

        let hint_start = entry.hint_name_offset as usize;
        section_data[hint_start..hint_start + dll.hint_name_data.len()].copy_from_slice(&dll.hint_name_data);

        let hint_rva_base = import_section_rva + entry.hint_name_offset;
        let mut oft_cur = entry.oft_offset as usize;
        let mut iat_cur = entry.iat_offset as usize;
        for spec in &dll.thunk_specs {
            if is_pe64 {
                let val64 = match *spec {
                    ThunkSpec::Ordinal(ord) => 0x8000_0000_0000_0000u64 | ord as u64,
                    ThunkSpec::Named(rel) => (hint_rva_base + rel) as u64,
                };
                (&mut section_data[oft_cur..oft_cur + 8]).write_u64::<LittleEndian>(val64).ok();
                (&mut section_data[iat_cur..iat_cur + 8]).write_u64::<LittleEndian>(val64).ok();
                oft_cur += 8;
                iat_cur += 8;
            } else {
                let val32 = match *spec {
                    ThunkSpec::Ordinal(ord) => IMAGE_SNAP_BY_ORDINAL | ord as u32,
                    ThunkSpec::Named(rel) => hint_rva_base + rel,
                };
                write_u32(&mut section_data, oft_cur, val32);
                write_u32(&mut section_data, iat_cur, val32);
                oft_cur += 4;
                iat_cur += 4;
            }
        }
        // Null-terminated thunks are already zero-initialized in `section_data`.
    }

    // Now add the section to the PE
    let (_, _, _, _, sections_end) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let num_sections = read_u16(data, pe_signature_offset(data).unwrap() + 6);

    let section_hdr_offset = sections_end;
    let last_section_raw_end = if num_sections > 0 {
        let last_off = section_hdr_offset + (num_sections as usize - 1) * IMAGE_SIZEOF_SECTION_HEADER;
        let last_raw_ptr = read_u32(data, last_off + 20);
        let last_raw_size = read_u32(data, last_off + 16);
        last_raw_ptr.saturating_add(last_raw_size)
    } else {
        0x1000
    };

    let data_end_u32 = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let append_base = last_section_raw_end.max(data_end_u32).max(import_section_rva.min(data_end_u32));
    let new_raw_pointer = align_up(append_base, file_alignment);
    let raw_data_len = section_data.len() as u32;
    let new_raw_size = align_up(raw_data_len, file_alignment);

    // Pad to alignment
    section_data.resize(new_raw_size as usize, 0);

    // Add section header
    let section_char = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    add_section(
        data,
        ".import",
        raw_data_len,
        import_section_rva,
        new_raw_size,
        new_raw_pointer,
        section_char,
    )?;

    // Ensure buffer is large enough and write data
    let needed = new_raw_pointer as usize + new_raw_size as usize;
    if data.len() < needed {
        data.resize(needed, 0);
    }

    let dest = &mut data[new_raw_pointer as usize..new_raw_pointer as usize + section_data.len()];
    dest.copy_from_slice(&section_data);

    // Update data directories & SizeOfImage
    write_u32(data, import_dir_offset, import_section_rva);
    write_u32(data, import_dir_offset + 4, (num_dlls as u32 + 1) * 20);

    write_u32(data, iat_dir_offset, import_section_rva + iat_block_start);
    write_u32(data, iat_dir_offset + 4, iat_block_size);

    let new_size_of_image = align_up(import_section_rva.saturating_add(new_raw_size), section_alignment);
    if opt_hdr_off + 60 <= data.len() {
        write_u32(data, opt_hdr_off + 56, new_size_of_image);
    }

    // Build result descriptors
    let mut result = Vec::new();
    for (i, (dll_name, _dll)) in dll_entries.iter().enumerate() {
        if let Some(entry) = layout.get(i) {
            let oft_rva = import_section_rva + entry.oft_offset;
            let name_rva = import_section_rva + entry.dll_name_offset;
            let iat_rva = import_section_rva + entry.iat_offset;
            result.push(ImportDescriptor {
                characteristics: oft_rva,
                time_date_stamp: 0,
                forwarder_chain: 0,
                name: name_rva,
                first_thunk: iat_rva,
                dll_name: dll_name.clone(),
                imports: Vec::new(),
            });
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------

/// Generate and write a PE checksum using the standard Win32 `CheckSumMappedFile`
/// 16-bit end-around-carry algorithm plus file size.
pub fn fix_checksum(data: &mut [u8]) -> UnpackerResult<()> {
    if data.len() < 64 {
        return Err(UnpackerError::InvalidPeFile("file too small for PE headers".into()));
    }

    let sig_offset = pe_signature_offset(data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot find PE signature".into()))?;
    let coff_offset = sig_offset + 4;

    let is_pe64 = {
        let optional_header_offset = coff_offset + 20;
        if optional_header_offset + 2 > data.len() {
            return Err(UnpackerError::InvalidPeFile("optional header too small".into()));
        }
        let magic = read_u16(data, optional_header_offset);
        magic == PE32_PLUS_MAGIC
    };

    // Checksum location in optional header
    let checksum_offset = if is_pe64 {
        // PE32+: optional_header + 64 (offset of CheckSum field)
        coff_offset + 20 + 64
    } else {
        // PE32: optional_header + 64
        coff_offset + 20 + 64
    };

    // Zero out the existing checksum
    write_u32(data, checksum_offset, 0);

    // Compute Win32 PE checksum: 16-bit carry-folded word sum, then add file size.
    let len = data.len();
    let mut checksum: u32 = 0;
    let mut i = 0;

    while i + 2 <= len {
        checksum += read_u16(data, i) as u32;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        i += 2;
    }
    if i < len {
        checksum += data[i] as u32;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);

    let final_checksum = checksum.wrapping_add(len as u32);
    write_u32(data, checksum_offset, final_checksum);

    Ok(())
}

// ---------------------------------------------------------------------------
// Add import section API (high-level)
// ---------------------------------------------------------------------------

/// Add a section for import data with the given characteristics.
pub fn add_import_section_api(
    data: &mut Vec<u8>,
    virtual_address: u32,
    virtual_size: u32,
    raw_data: &[u8],
    file_alignment: u32,
) -> UnpackerResult<()> {
    let raw_size = align_up(raw_data.len() as u32, file_alignment);

    // Find where the last section's raw data ends
    let (_, _, num_sections, _, sections_end) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let section_hdr_offset = sections_end;

    let new_raw_ptr = if num_sections > 0 {
        let last_off = section_hdr_offset + (num_sections as usize - 1) * IMAGE_SIZEOF_SECTION_HEADER;
        let last_raw_ptr = read_u32(data, last_off + 20);
        let last_raw_size = read_u32(data, last_off + 16);
        align_up(last_raw_ptr + last_raw_size, file_alignment)
    } else {
        0x400
    };

    let characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    let mut padded_data = raw_data.to_vec();
    padded_data.resize(raw_size as usize, 0);

    // Ensure buffer is large enough
    let needed = (new_raw_ptr + raw_size) as usize;
    if data.len() < needed {
        data.resize(needed, 0);
    }

    // Write raw data
    let dest = &mut data[new_raw_ptr as usize..new_raw_ptr as usize + padded_data.len()];
    dest.copy_from_slice(&padded_data);

    // Add section header
    add_section(
        data,
        ".idata",
        virtual_size,
        virtual_address,
        raw_size,
        new_raw_ptr,
        characteristics,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Main dump function
// ---------------------------------------------------------------------------

/// Shared builder for dumping emulated PE memory into a valid PE image buffer.
fn build_dump_bytes(
    uc: &Unicorn<()>,
    base_addr: u64,
    virtualmemorysize: u64,
    ctx: &DumpContext,
) -> UnpackerResult<(Vec<u8>, u32)> {
    let mem_size = virtualmemorysize as usize;
    let mut image_data = vec![0u8; mem_size];

    uc.mem_read(base_addr, &mut image_data)
        .map_err(|e| UnpackerError::EmulatorError(format!("failed to read emulated memory: {e}")))?;

    let (opt_hdr_off, is_pe64, num_sections, _, section_hdr_offset) = parse_pe_headers(&image_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers from emulated memory".into()))?;

    let section_alignment = read_u32(&image_data, opt_hdr_off + 32).max(0x200);
    let sections = read_section_headers(&image_data, section_hdr_offset, num_sections);

    let actual_image_size = {
        let max_end = sections
            .iter()
            .map(|s| s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data)))
            .max()
            .unwrap_or(0);
        align_up(max_end, section_alignment)
    };

    let keep_len = (actual_image_size as usize).min(image_data.len());
    let mut pe_data = if keep_len > 0 {
        image_data[..keep_len].to_vec()
    } else {
        image_data
    };
    if (actual_image_size as usize) > pe_data.len() && actual_image_size <= (virtualmemorysize as u32) {
        pe_data.resize(actual_image_size as usize, 0);
    }

    // 1. Fix OEP from current instruction pointer
    let ip = match uc.get_arch() {
        unicorn_engine::unicorn_const::Arch::X86 => {
            if is_pe64 {
                uc.reg_read(unicorn_engine::RegisterX86::RIP)
                    .map_err(|e| UnpackerError::EmulatorError(format!("failed to read RIP: {e}")))? as u64
            } else {
                uc.reg_read(unicorn_engine::RegisterX86::EIP)
                    .map_err(|e| UnpackerError::EmulatorError(format!("failed to read EIP: {e}")))? as u64
            }
        }
        unicorn_engine::unicorn_const::Arch::ARM => {
            uc.reg_read(unicorn_engine::RegisterARM::PC)
                .map_err(|e| UnpackerError::EmulatorError(format!("failed to read PC: {e}")))? as u64
        }
        unicorn_engine::unicorn_const::Arch::ARM64 => {
            uc.reg_read(unicorn_engine::RegisterARM64::PC)
                .map_err(|e| UnpackerError::EmulatorError(format!("failed to read PC: {e}")))? as u64
        }
        _ => base_addr,
    };

    let oep_rva = if ip >= base_addr && ip < base_addr + (actual_image_size as u64) {
        (ip - base_addr) as u32
    } else {
        read_u32(&pe_data, opt_hdr_off + 16)
    };
    write_u32(&mut pe_data, opt_hdr_off + 16, oep_rva);

    // 2. Fix section sizes & raw pointers to match virtual layout (FileAlignment = section_alignment)
    fix_sections(&mut pe_data, section_alignment)?;

    // 3. Fix section memory protections
    fix_section_mem_protections(&mut pe_data, &ctx.allocated_chunks, base_addr)?;

    // 4-5. Imports, certificate / relocations, checksum
    finish_dump(&mut pe_data, ctx, actual_image_size, section_alignment, section_alignment)?;

    Ok((pe_data, oep_rva))
}

/// Main entry point - reads emulated state and writes PE to disk.
pub fn dump_image(
    uc: &Unicorn<()>,
    base_addr: u64,
    virtualmemorysize: u64,
    ctx: &DumpContext,
    file_path: &str,
) -> UnpackerResult<()> {
    let (pe_data, oep_rva) = build_dump_bytes(uc, base_addr, virtualmemorysize, ctx)?;

    let mut file = std::fs::File::create(file_path)?;
    file.write_all(&pe_data)?;
    file.flush()?;

    log::info!(
        "Dumped PE image to {} (size: {}, OEP: {:#x})",
        file_path,
        pe_data.len(),
        oep_rva
    );

    Ok(())
}

/// Same as `dump_image` but returns the bytes instead of writing to a file.
pub fn dump_image_to_bytes(
    uc: &Unicorn<()>,
    base_addr: u64,
    virtualmemorysize: u64,
    ctx: &DumpContext,
) -> UnpackerResult<Vec<u8>> {
    let (pe_data, oep_rva) = build_dump_bytes(uc, base_addr, virtualmemorysize, ctx)?;

    log::info!(
        "Dumped PE image to memory (size: {}, OEP: {:#x})",
        pe_data.len(),
        oep_rva
    );

    Ok(pe_data)
}

/// The last steps of a dump: imports rebuilt from `ctx` in a new section, the
/// certificate and relocation directories cleared (they do not fit an image dump),
/// relocations marked stripped, the checksum recomputed.
fn finish_dump(
    pe_data: &mut Vec<u8>,
    ctx: &DumpContext,
    image_size: u32,
    section_alignment: u32,
    file_alignment: u32,
) -> UnpackerResult<()> {
    let _new_imports = fix_imports_by_rebuilding(pe_data, ctx, image_size, section_alignment, file_alignment)?;

    let (opt_hdr_off, is_pe64, _, _, _) = parse_pe_headers(pe_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers for checksum fix".into()))?;
    let data_dir_offset = if is_pe64 { opt_hdr_off + 112 } else { opt_hdr_off + 96 };
    let security_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if security_dir_offset + 8 <= pe_data.len() {
        write_u32(pe_data, security_dir_offset, 0);
        write_u32(pe_data, security_dir_offset + 4, 0);
    }

    let coff_offset = pe_signature_offset(pe_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("no PE signature".into()))?
        + 4;
    let characteristics = read_u16(pe_data, coff_offset + 18);
    write_u16(pe_data, coff_offset + 18, characteristics | IMAGE_FILE_RELOCS_STRIPPED);

    let reloc_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
    if reloc_dir_offset + 8 <= pe_data.len() {
        write_u32(pe_data, reloc_dir_offset, 0);
        write_u32(pe_data, reloc_dir_offset + 4, 0);
    }

    fix_checksum(pe_data)
}

/// Returns `(next_section_rva, section_alignment)` for appending a new section to `data`.
pub fn next_section_rva(data: &[u8]) -> UnpackerResult<(u32, u32)> {
    let (opt_hdr_off, _, num_sections, _, section_hdr_offset) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let section_alignment = read_u32(data, opt_hdr_off + 32).max(0x200);
    let sections = read_section_headers(data, section_hdr_offset, num_sections);
    let max_end = sections
        .iter()
        .map(|s| s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data)))
        .max()
        .unwrap_or(section_alignment);
    Ok((align_up(max_end.max(section_alignment), section_alignment), section_alignment))
}

/// Appends a section with explicit `characteristics` to `data`, updates
/// `SizeOfImage` and section headers, clears stale Authenticode signature directory if
/// present, recomputes the PE checksum, and returns the new section's RVA.
pub fn append_section_with_chars(
    data: &mut Vec<u8>,
    name: &str,
    section_bytes: &[u8],
    characteristics: u32,
) -> UnpackerResult<u32> {
    let (opt_hdr_off, is_pe64, num_sections, _, section_hdr_offset) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let section_alignment = read_u32(data, opt_hdr_off + 32).max(0x200);
    let file_alignment = read_u32(data, opt_hdr_off + 36).max(0x200);
    let size_of_headers = read_u32(data, opt_hdr_off + 60);
    let sections = read_section_headers(data, section_hdr_offset, num_sections);

    let new_hdr_end = section_hdr_offset + (num_sections as usize + 1) * IMAGE_SIZEOF_SECTION_HEADER;
    let min_raw_ptr = sections
        .iter()
        .filter(|s| s.pointer_to_raw_data > 0)
        .map(|s| s.pointer_to_raw_data as usize)
        .min()
        .unwrap_or(data.len());
    if new_hdr_end > min_raw_ptr {
        return Err(UnpackerError::InvalidPeFile(format!(
            "insufficient PE header headroom for {name} section: need {new_hdr_end:#x}, first section raw data at {min_raw_ptr:#x}"
        )));
    }
    if new_hdr_end > size_of_headers as usize {
        write_u32(data, opt_hdr_off + 60, align_up(new_hdr_end as u32, file_alignment).min(min_raw_ptr as u32));
    }

    let (va, _) = next_section_rva(data)?;
    let virtual_size = section_bytes.len().max(1) as u32;
    let raw_size = align_up(virtual_size, file_alignment);
    let raw_ptr = if file_alignment == section_alignment {
        va
    } else {
        let max_raw_end = sections
            .iter()
            .filter(|s| s.pointer_to_raw_data > 0)
            .map(|s| s.pointer_to_raw_data.saturating_add(s.size_of_raw_data))
            .max()
            .unwrap_or(size_of_headers)
            .max(size_of_headers);
        align_up(max_raw_end, file_alignment)
    };

    let num_dirs_off = if is_pe64 { opt_hdr_off + 108 } else { opt_hdr_off + 92 };
    let num_dirs = if num_dirs_off + 4 <= data.len() {
        read_u32(data, num_dirs_off) as usize
    } else {
        0
    };
    let data_dir_offset = if is_pe64 { opt_hdr_off + 112 } else { opt_hdr_off + 96 };
    let security_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if num_dirs > IMAGE_DIRECTORY_ENTRY_SECURITY && security_dir_offset + 8 <= data.len() {
        let sec_off = read_u32(data, security_dir_offset);
        let sec_sz = read_u32(data, security_dir_offset + 4);
        if sec_sz > 0
            && sec_off >= raw_ptr
            && (sec_off as usize).saturating_add(sec_sz as usize) == data.len()
        {
            data.truncate(sec_off as usize);
        }
        write_u32(data, security_dir_offset, 0);
        write_u32(data, security_dir_offset + 4, 0);
    }

    let needed = (raw_ptr + raw_size) as usize;
    if data.len() < needed {
        data.resize(needed, 0);
    }
    data[raw_ptr as usize..raw_ptr as usize + section_bytes.len()].copy_from_slice(section_bytes);
    if raw_size as usize > section_bytes.len() {
        data[raw_ptr as usize + section_bytes.len()..needed].fill(0);
    }

    add_section(
        data,
        name,
        virtual_size,
        va,
        raw_size,
        raw_ptr,
        characteristics,
    )?;

    let new_image_size = align_up(va.saturating_add(virtual_size), section_alignment);
    write_u32(data, opt_hdr_off + 56, new_image_size);

    fix_checksum(data)?;
    Ok(va)
}

/// Appends an executable, readable code section (e.g. `.devirt`) to `data`, updates
/// `SizeOfImage` and section headers, clears stale Authenticode signature directory if
/// present, recomputes the PE checksum, and returns the new section's RVA.
pub fn append_code_section(
    data: &mut Vec<u8>,
    name: &str,
    code_bytes: &[u8],
) -> UnpackerResult<u32> {
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    append_section_with_chars(
        data,
        name,
        code_bytes,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )
}

/// Builds a fresh `.import` section from deduplicated `(dll_name, functions)` pairs,
/// updates `IMAGE_DIRECTORY_ENTRY_IMPORT` and `IMAGE_DIRECTORY_ENTRY_IAT`, and returns
/// `(import_section_rva, slot_map)` mapping `(dll_lower, func_name)` -> `.import` IAT RVA.
pub fn rebuild_import_section_with_map(
    data: &mut Vec<u8>,
    imports: &[(String, Vec<String>)],
) -> UnpackerResult<(u32, HashMap<(String, String), u32>)> {
    let (_, is_pe64, _, _, _) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let (import_section_rva, _) = next_section_rva(data)?;

    // Merge duplicate DLLs case-insensitively while preserving first original casing.
    let mut merged: HashMap<String, (String, Vec<String>, std::collections::HashSet<String>)> = HashMap::new();
    let mut dll_order: Vec<String> = Vec::new();
    for (dll_name, funcs) in imports {
        if funcs.is_empty() {
            continue;
        }
        let key = dll_name.to_ascii_lowercase();
        let entry = merged.entry(key.clone()).or_insert_with(|| {
            dll_order.push(key);
            (dll_name.clone(), Vec::new(), std::collections::HashSet::new())
        });
        for f in funcs {
            if entry.2.insert(f.clone()) {
                entry.1.push(f.clone());
            }
        }
    }
    dll_order.sort();

    if dll_order.is_empty() {
        return Ok((0, HashMap::new()));
    }

    #[derive(Clone, Copy)]
    enum ThunkSpec {
        Ordinal(u16),
        Named(u32),
    }

    struct DllData {
        dll_lower: String,
        dll_name_bytes: Vec<u8>,
        hint_name_data: Vec<u8>,
        func_names: Vec<String>,
        thunk_specs: Vec<ThunkSpec>,
    }

    let mut dll_entries = Vec::with_capacity(dll_order.len());
    for dll_lower in dll_order {
        let (orig_name, funcs, _) = merged.remove(&dll_lower).unwrap();
        if funcs.is_empty() {
            continue;
        }
        let mut dll_name_bytes = orig_name.into_bytes();
        dll_name_bytes.push(0);
        if dll_name_bytes.len() % 2 != 0 {
            dll_name_bytes.push(0);
        }
        let mut hint_name_data = Vec::new();
        let mut thunk_specs = Vec::with_capacity(funcs.len());
        let mut func_names = Vec::with_capacity(funcs.len());
        for f in funcs {
            if let Some(rest) = f.strip_prefix("ord_") {
                if let Ok(ord) = rest.parse::<u16>() {
                    thunk_specs.push(ThunkSpec::Ordinal(ord));
                    func_names.push(f);
                    continue;
                }
            }
            let rel_off = hint_name_data.len() as u32;
            let _ = hint_name_data.write_u16::<LittleEndian>(0);
            hint_name_data.extend_from_slice(f.as_bytes());
            hint_name_data.push(0);
            if hint_name_data.len() % 2 != 0 {
                hint_name_data.push(0);
            }
            thunk_specs.push(ThunkSpec::Named(rel_off));
            func_names.push(f);
        }
        dll_entries.push(DllData {
            dll_lower,
            dll_name_bytes,
            hint_name_data,
            func_names,
            thunk_specs,
        });
    }

    let num_dlls = dll_entries.len();
    let ptr_size: u32 = if is_pe64 { 8 } else { 4 };
    let descriptors_size = (num_dlls + 1) * 20;
    let mut cur = align_up(descriptors_size as u32, ptr_size);
    let iat_block_start = cur;
    let mut iat_offsets = Vec::with_capacity(num_dlls);
    for dll in &dll_entries {
        iat_offsets.push(cur);
        cur += ((dll.thunk_specs.len() as u32) + 1) * ptr_size;
    }
    let iat_block_size = cur - iat_block_start;

    let mut oft_offsets = Vec::with_capacity(num_dlls);
    for dll in &dll_entries {
        oft_offsets.push(cur);
        cur += ((dll.thunk_specs.len() as u32) + 1) * ptr_size;
    }

    let mut name_offsets = Vec::with_capacity(num_dlls);
    let mut hint_offsets = Vec::with_capacity(num_dlls);
    for dll in &dll_entries {
        name_offsets.push(cur);
        cur += dll.dll_name_bytes.len() as u32;
        hint_offsets.push(cur);
        cur += dll.hint_name_data.len() as u32;
    }

    let mut section_data = vec![0u8; cur as usize];
    let mut slot_map: HashMap<(String, String), u32> = HashMap::new();

    for (idx, dll) in dll_entries.iter().enumerate() {
        let desc_off = idx * 20;
        let oft_rva = import_section_rva + oft_offsets[idx];
        let name_rva = import_section_rva + name_offsets[idx];
        let iat_rva = import_section_rva + iat_offsets[idx];

        write_u32(&mut section_data, desc_off, oft_rva);
        write_u32(&mut section_data, desc_off + 12, name_rva);
        write_u32(&mut section_data, desc_off + 16, iat_rva);

        let n_off = name_offsets[idx] as usize;
        section_data[n_off..n_off + dll.dll_name_bytes.len()].copy_from_slice(&dll.dll_name_bytes);
        let h_off = hint_offsets[idx] as usize;
        section_data[h_off..h_off + dll.hint_name_data.len()].copy_from_slice(&dll.hint_name_data);

        let hint_rva_base = import_section_rva + hint_offsets[idx];
        let mut oft_cur = oft_offsets[idx] as usize;
        let mut iat_cur = iat_offsets[idx] as usize;
        for (f_idx, spec) in dll.thunk_specs.iter().enumerate() {
            slot_map.insert(
                (dll.dll_lower.clone(), dll.func_names[f_idx].clone()),
                import_section_rva + iat_cur as u32,
            );
            if is_pe64 {
                let val64 = match *spec {
                    ThunkSpec::Ordinal(ord) => 0x8000_0000_0000_0000u64 | ord as u64,
                    ThunkSpec::Named(rel) => (hint_rva_base + rel) as u64,
                };
                (&mut section_data[oft_cur..oft_cur + 8]).write_u64::<LittleEndian>(val64).ok();
                (&mut section_data[iat_cur..iat_cur + 8]).write_u64::<LittleEndian>(val64).ok();
                oft_cur += 8;
                iat_cur += 8;
            } else {
                let val32 = match *spec {
                    ThunkSpec::Ordinal(ord) => IMAGE_SNAP_BY_ORDINAL | ord as u32,
                    ThunkSpec::Named(rel) => hint_rva_base + rel,
                };
                write_u32(&mut section_data, oft_cur, val32);
                write_u32(&mut section_data, iat_cur, val32);
                oft_cur += 4;
                iat_cur += 4;
            }
        }
    }

    let appended_rva = append_section_with_chars(
        data,
        ".import",
        &section_data,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
    )?;
    if appended_rva != import_section_rva {
        return Err(UnpackerError::General(format!(
            ".import RVA mismatch: predicted {import_section_rva:#x}, got {appended_rva:#x}"
        )));
    }

    let (opt_hdr_off2, is_pe64_2, _, _, _) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let data_dir_offset = if is_pe64_2 { opt_hdr_off2 + 112 } else { opt_hdr_off2 + 96 };
    let import_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
    let iat_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_IAT * 8;
    if iat_dir_offset + 8 <= data.len() {
        write_u32(data, import_dir_offset, import_section_rva);
        write_u32(data, import_dir_offset + 4, descriptors_size as u32);
        write_u32(data, iat_dir_offset, import_section_rva + iat_block_start);
        write_u32(data, iat_dir_offset + 4, iat_block_size);
    }
    fix_checksum(data)?;

    Ok((import_section_rva, slot_map))
}

/// Disables ASLR (`DYNAMIC_BASE` | `HIGH_ENTROPY_VA`), marks relocations stripped, and
/// clears `BASERELOC` + `SECURITY` data directories while preserving `RESOURCE`, `EXCEPTION`,
/// `TLS`, and `LOAD_CONFIG`.
pub fn disable_aslr_and_strip_relocs(data: &mut Vec<u8>) -> UnpackerResult<()> {
    let (opt_hdr_off, is_pe64, _, _, _) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let sig_offset = pe_signature_offset(data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("no PE signature".into()))?;
    let coff_offset = sig_offset + 4;

    if opt_hdr_off + 72 <= data.len() {
        let dll_chars = read_u16(data, opt_hdr_off + 70);
        write_u16(data, opt_hdr_off + 70, dll_chars & !0x0060u16);
    }
    if coff_offset + 20 <= data.len() {
        let file_chars = read_u16(data, coff_offset + 18);
        write_u16(data, coff_offset + 18, file_chars | IMAGE_FILE_RELOCS_STRIPPED);
    }
    let data_dir_offset = if is_pe64 { opt_hdr_off + 112 } else { opt_hdr_off + 96 };
    for dir_idx in [IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_BASERELOC] {
        let off = data_dir_offset + dir_idx * 8;
        if off + 8 <= data.len() {
            write_u32(data, off, 0);
            write_u32(data, off + 4, 0);
        }
    }
    fix_checksum(data)
}

/// Ensures every section containing any RVA in `rvas` has `IMAGE_SCN_MEM_WRITE`.
/// Returns how many section headers were modified.
pub fn mark_sections_writable_for_rvas(data: &mut [u8], rvas: &[u32]) -> UnpackerResult<usize> {
    if rvas.is_empty() {
        return Ok(0);
    }
    let (_, _, num_sections, _, section_hdr_offset) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let mut modified = 0usize;
    for i in 0..num_sections as usize {
        let off = section_hdr_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
        if off + IMAGE_SIZEOF_SECTION_HEADER > data.len() {
            break;
        }
        let vs = read_u32(data, off + 8);
        let va = read_u32(data, off + 12);
        let rsz = read_u32(data, off + 16);
        let span = vs.max(rsz);
        if span == 0 {
            continue;
        }
        if rvas.iter().any(|&rva| rva >= va && rva < va.saturating_add(span)) {
            let chars = read_u32(data, off + 36);
            if (chars & IMAGE_SCN_MEM_WRITE) == 0 {
                write_u32(data, off + 36, chars | IMAGE_SCN_MEM_WRITE);
                modified += 1;
            }
        }
    }
    Ok(modified)
}

/// Sets `OptionalHeader.AddressOfEntryPoint` to `ep_rva`.
pub fn set_entry_point(data: &mut [u8], ep_rva: u32) -> UnpackerResult<()> {
    let (opt_hdr_off, _, _, _, _) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    if opt_hdr_off + 20 > data.len() {
        return Err(UnpackerError::InvalidPeFile("optional header too short for entry point".into()));
    }
    write_u32(data, opt_hdr_off + 16, ep_rva);
    Ok(())
}

/// A PE file from a memory image (offset = RVA) that a static unpacker rebuilt (UPX):
/// the entry point set to `oep_rva`, every section's raw data where it is in memory
/// (raw offset = RVA, file alignment = section alignment), then the same imports and
/// fixups as an emulator dump ([`dump_image_to_bytes`]). `imports`: DLL name to its
/// functions (`ord_N` for an ordinal; the addresses are not used).
pub fn image_to_pe(
    mut image: Vec<u8>,
    oep_rva: u32,
    imports: HashMap<String, Vec<(String, u64)>>,
) -> UnpackerResult<Vec<u8>> {
    let (opt_hdr_off, _, num_sections, _, section_hdr_offset) =
        parse_pe_headers(&image).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;
    let section_alignment = read_u32(&image, opt_hdr_off + 32).max(0x200);
    write_u32(&mut image, opt_hdr_off + 16, oep_rva);
    write_u32(&mut image, opt_hdr_off + 36, section_alignment);
    let image_len = image.len() as u32;
    for i in 0..num_sections as usize {
        let off = section_hdr_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
        if off + IMAGE_SIZEOF_SECTION_HEADER > image.len() {
            break;
        }
        let va = read_u32(&image, off + 12);
        let vs = read_u32(&image, off + 8);
        let raw = align_up(vs, section_alignment).min(image_len.saturating_sub(va));
        write_u32(&mut image, off + 16, raw);
        write_u32(&mut image, off + 20, if raw == 0 { 0 } else { va });
    }
    let image_size = align_up(image_len, section_alignment);
    image.resize(image_size as usize, 0);
    let mut ctx = DumpContext::new(image_size as u64, 0);
    ctx.dllname_to_functionlist = imports;
    finish_dump(&mut image, &ctx, image_size, section_alignment, section_alignment)?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_pe(is_pe64: bool) -> Vec<u8> {
        let mut pe = vec![0u8; 0x3000];
        pe[0..2].copy_from_slice(b"MZ");
        write_u32(&mut pe, 0x3C, 0x80);
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        write_u16(&mut pe, coff, if is_pe64 { 0x8664 } else { 0x14C }); // Machine
        write_u16(&mut pe, coff + 2, 2); // NumberOfSections
        let opt_size: u16 = if is_pe64 { 240 } else { 224 };
        write_u16(&mut pe, coff + 16, opt_size);
        write_u16(&mut pe, coff + 18, 0x22); // Characteristics

        let opt = coff + 20;
        write_u16(&mut pe, opt, if is_pe64 { PE32_PLUS_MAGIC } else { PE32_MAGIC });
        write_u32(&mut pe, opt + 16, 0x1000); // AddressOfEntryPoint
        write_u32(&mut pe, opt + 32, 0x1000); // SectionAlignment
        write_u32(&mut pe, opt + 36, 0x200); // FileAlignment (disk alignment differs from VA)
        write_u32(&mut pe, opt + 56, 0x3000); // SizeOfImage
        write_u32(&mut pe, opt + 60, 0x400); // SizeOfHeaders
        write_u32(&mut pe, opt + if is_pe64 { 108 } else { 92 }, 16); // NumberOfRvaAndSizes

        let sec_hdr = opt + opt_size as usize;
        // .text at VA 0x1000, deliberately stale disk PointerToRawData=0x400
        pe[sec_hdr..sec_hdr + 5].copy_from_slice(b".text");
        write_u32(&mut pe, sec_hdr + 8, 0x200);
        write_u32(&mut pe, sec_hdr + 12, 0x1000);
        write_u32(&mut pe, sec_hdr + 16, 0x200);
        write_u32(&mut pe, sec_hdr + 20, 0x400);
        write_u32(&mut pe, sec_hdr + 36, 0x60000020);

        // .rdata at VA 0x2000, deliberately stale disk PointerToRawData=0x600
        let sec1 = sec_hdr + 40;
        pe[sec1..sec1 + 6].copy_from_slice(b".rdata");
        write_u32(&mut pe, sec1 + 8, 0x100);
        write_u32(&mut pe, sec1 + 12, 0x2000);
        write_u32(&mut pe, sec1 + 16, 0x200);
        write_u32(&mut pe, sec1 + 20, 0x600);
        write_u32(&mut pe, sec1 + 36, 0x40000040);

        pe
    }

    fn rva_to_raw_virtual(rva: u32) -> usize {
        // Because FileAlignment == SectionAlignment == 0x1000 and PointerToRawData == VirtualAddress
        rva as usize
    }

    fn read_cstr(pe: &[u8], off: usize) -> String {
        let end = pe[off..].iter().position(|&b| b == 0).unwrap_or(0);
        String::from_utf8_lossy(&pe[off..off + end]).into_owned()
    }

    fn verify_rebuilt_imports(is_pe64: bool) {
        let mut pe = build_minimal_pe(is_pe64);
        fix_sections(&mut pe, 0x1000).unwrap();

        let (opt_off, parsed64, num_secs, _, sec_hdr) = parse_pe_headers(&pe).unwrap();
        assert_eq!(parsed64, is_pe64);
        assert_eq!(read_u32(&pe, opt_off + 36), 0x1000);
        for i in 0..num_secs as usize {
            let off = sec_hdr + i * 40;
            assert_eq!(read_u32(&pe, off + 20), read_u32(&pe, off + 12));
        }

        let mut ctx = DumpContext::new(0x3000, 0);
        ctx.dllname_to_functionlist.insert(
            "kernel32.dll".to_string(),
            vec![("VirtualAlloc".to_string(), 0), ("ord_42".to_string(), 0)],
        );
        ctx.dllname_to_functionlist.insert(
            "ntdll.dll".to_string(),
            vec![("NtClose".to_string(), 0)],
        );

        finish_dump(&mut pe, &ctx, 0x3000, 0x1000, 0x1000).unwrap();

        let (opt_off, _, num_secs2, _, sec_hdr2) = parse_pe_headers(&pe).unwrap();
        assert_eq!(num_secs2, 3);
        let imp_sec = read_section_headers(&pe, sec_hdr2, num_secs2).pop().unwrap();
        assert_eq!(imp_sec.name, ".import");
        assert_eq!(imp_sec.virtual_address, 0x3000);
        assert_eq!(imp_sec.pointer_to_raw_data, 0x3000);
        assert!(read_u32(&pe, opt_off + 56) >= 0x4000);

        let dd_off = if is_pe64 { opt_off + 112 } else { opt_off + 96 };
        let imp_rva = read_u32(&pe, dd_off + 8);
        let imp_sz = read_u32(&pe, dd_off + 12);
        let iat_dir_rva = read_u32(&pe, dd_off + 12 * 8);
        let iat_dir_sz = read_u32(&pe, dd_off + 12 * 8 + 4);
        assert_eq!(imp_rva, 0x3000);
        assert_eq!(imp_sz, 3 * 20);
        assert!(iat_dir_rva > imp_rva && iat_dir_sz > 0);

        let mut recovered: Vec<(String, Vec<String>)> = Vec::new();
        for idx in 0..2usize {
            let d = rva_to_raw_virtual(imp_rva) + idx * 20;
            let oft = read_u32(&pe, d);
            let name_rva = read_u32(&pe, d + 12);
            let ft = read_u32(&pe, d + 16);
            assert!(oft >= imp_rva);
            assert!(ft >= iat_dir_rva && ft < iat_dir_rva + iat_dir_sz);
            let dll_name = read_cstr(&pe, rva_to_raw_virtual(name_rva));
            let mut funcs = Vec::new();
            let mut cursor_oft = rva_to_raw_virtual(oft);
            let mut cursor_iat = rva_to_raw_virtual(ft);
            loop {
                if is_pe64 {
                    let v_oft = u64::from_le_bytes(pe[cursor_oft..cursor_oft + 8].try_into().unwrap());
                    let v_iat = u64::from_le_bytes(pe[cursor_iat..cursor_iat + 8].try_into().unwrap());
                    assert_eq!(v_oft, v_iat);
                    if v_oft == 0 {
                        break;
                    }
                    if (v_oft & (1u64 << 63)) != 0 {
                        funcs.push(format!("ord_{}", v_oft & 0xFFFF));
                    } else {
                        let hn = rva_to_raw_virtual(v_oft as u32);
                        funcs.push(read_cstr(&pe, hn + 2));
                    }
                    cursor_oft += 8;
                    cursor_iat += 8;
                } else {
                    let v_oft = read_u32(&pe, cursor_oft);
                    let v_iat = read_u32(&pe, cursor_iat);
                    assert_eq!(v_oft, v_iat);
                    if v_oft == 0 {
                        break;
                    }
                    if (v_oft & IMAGE_SNAP_BY_ORDINAL) != 0 {
                        funcs.push(format!("ord_{}", v_oft & 0xFFFF));
                    } else {
                        let hn = rva_to_raw_virtual(v_oft);
                        funcs.push(read_cstr(&pe, hn + 2));
                    }
                    cursor_oft += 4;
                    cursor_iat += 4;
                }
            }
            recovered.push((dll_name, funcs));
        }

        assert_eq!(
            recovered,
            vec![
                ("kernel32.dll".to_string(), vec!["VirtualAlloc".to_string(), "ord_42".to_string()]),
                ("ntdll.dll".to_string(), vec!["NtClose".to_string()]),
            ]
        );
    }

    #[test]
    fn rebuild_imports_and_fix_sections_pe64() {
        verify_rebuilt_imports(true);
    }

    #[test]
    fn rebuild_imports_and_fix_sections_pe32() {
        verify_rebuilt_imports(false);
    }

    #[test]
    fn append_code_section_updates_headers_and_preserves_va_eq_rptr() {
        // Case 1: Virtual-aligned PE64 (FileAlignment == SectionAlignment == 0x1000)
        let mut pe64 = build_minimal_pe(true);
        let (opt64, _, _, _, sec_off64) = parse_pe_headers(&pe64).unwrap();
        write_u32(&mut pe64, opt64 + 36, 0x1000);
        fix_sections(&mut pe64, 0x1000).unwrap();
        let (expected_rva, _) = next_section_rva(&pe64).unwrap();
        assert_eq!(expected_rva, 0x3000);
        let code = [0x48u8, 0x31, 0xC0, 0xC3]; // xor rax, rax; ret
        let rva64 = append_code_section(&mut pe64, ".devirt", &code).unwrap();
        assert_eq!(rva64, 0x3000);
        let (_, _, nsec64, _, _) = parse_pe_headers(&pe64).unwrap();
        assert_eq!(nsec64, 3);
        let added64 = read_section_headers(&pe64, sec_off64, nsec64).pop().unwrap();
        assert_eq!(added64.name, ".devirt");
        assert_eq!(added64.virtual_address, 0x3000);
        assert_eq!(added64.pointer_to_raw_data, 0x3000);
        assert_eq!(added64.characteristics & 0x6000_0020, 0x6000_0020);
        assert_eq!(read_u32(&pe64, opt64 + 56), 0x4000);
        assert_eq!(&pe64[0x3000..0x3004], &code);

        // Case 2: Disk-aligned PE32 (FileAlignment = 0x200, SectionAlignment = 0x1000)
        let mut pe32 = build_minimal_pe(false);
        let rva32 = append_code_section(&mut pe32, ".devirt", &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]).unwrap();
        assert_eq!(rva32, 0x3000);
        let (opt32, _, nsec32, _, sec_off32) = parse_pe_headers(&pe32).unwrap();
        assert_eq!(nsec32, 3);
        let added32 = read_section_headers(&pe32, sec_off32, nsec32).pop().unwrap();
        assert_eq!(added32.virtual_address, 0x3000);
        assert_eq!(added32.pointer_to_raw_data, 0x800);
        assert_eq!(added32.size_of_raw_data, 0x200);
        assert_eq!(read_u32(&pe32, opt32 + 56), 0x4000);
    }

    #[test]
    fn fix_checksum_matches_win32_carry_folded_pe_checksum() {
        let mut pe = build_minimal_pe(true);
        if pe.len() % 2 != 0 {
            pe.push(0);
        }
        let (opt, _, _, _, _) = parse_pe_headers(&pe).unwrap();
        let cksum_off = opt + 64;
        // Put non-zero data inside `.text` raw body so accumulator > 0 before carry-folding.
        pe[0x400] = 0x34;
        pe[0x401] = 0x12;

        fix_checksum(&mut pe).unwrap();
        let ck0 = read_u32(&pe, cksum_off);
        // Checksum calculation must zero CheckSum field first and be idempotent.
        fix_checksum(&mut pe).unwrap();
        assert_eq!(read_u32(&pe, cksum_off), ck0);

        // In 16-bit end-around-carry arithmetic, appending `0xFFFF` words preserves the folded sum
        // when accumulator > 0, so only `+len` (+8) changes (unfolded sum would add 4 * 0xFFFF).
        let mut pe_ffff = pe.clone();
        pe_ffff.extend_from_slice(&[0xFFu8; 8]);
        fix_checksum(&mut pe_ffff).unwrap();
        assert_eq!(read_u32(&pe_ffff, cksum_off), ck0 + 8);

        // Odd-length tail byte must fold properly.
        let mut pe_odd = pe.clone();
        pe_odd.push(0xAB);
        fix_checksum(&mut pe_odd).unwrap();
        let s0 = ck0 - pe.len() as u32;
        let s1 = ((s0 + 0xAB) & 0xFFFF) + ((s0 + 0xAB) >> 16);
        let s2 = (s1 & 0xFFFF) + (s1 >> 16);
        assert_eq!(read_u32(&pe_odd, cksum_off), s2 + pe_odd.len() as u32);

        // Stale Authenticode certificate tail at EOF is truncated cleanly when `.devirt` is appended.
        let mut pe_signed = build_minimal_pe(true);
        pe_signed.truncate(0x800); // Match disk layout where `.rdata` ends at 0x600 + 0x200 = 0x800
        let cert_off = pe_signed.len() as u32;
        let cert_sz = 0x1200u32;
        pe_signed.extend(std::iter::repeat(0xA5u8).take(cert_sz as usize));
        let sec_dir_off = opt + 112 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
        write_u32(&mut pe_signed, sec_dir_off, cert_off);
        write_u32(&mut pe_signed, sec_dir_off + 4, cert_sz);
        append_code_section(&mut pe_signed, ".devirt", &[0xC3]).unwrap();
        assert_eq!(read_u32(&pe_signed, sec_dir_off), 0);
        assert_eq!(read_u32(&pe_signed, sec_dir_off + 4), 0);
        assert_eq!(pe_signed.len(), cert_off as usize + 0x200);
    }

    #[test]
    fn rebuild_import_section_with_map_and_reloc_helpers_work() {
        let mut pe = build_minimal_pe(true);
        let (opt_off, _, _, _, sec_off) = parse_pe_headers(&pe).unwrap();
        write_u32(&mut pe, opt_off + 36, 0x1000);
        fix_sections(&mut pe, 0x1000).unwrap();
        // Simulate ASLR + Exception/TLS/Basereloc dirs
        write_u16(&mut pe, opt_off + 70, 0x8160);
        let dd_off = opt_off + 112;
        write_u32(&mut pe, dd_off + 3 * 8, 0x2100); // EXCEPTION
        write_u32(&mut pe, dd_off + 3 * 8 + 4, 0x24);
        write_u32(&mut pe, dd_off + 5 * 8, 0x2200); // BASERELOC
        write_u32(&mut pe, dd_off + 5 * 8 + 4, 0x10);
        write_u32(&mut pe, dd_off + 9 * 8, 0x2300); // TLS
        write_u32(&mut pe, dd_off + 9 * 8 + 4, 0x28);

        let imports = vec![
            (
                "KERNEL32.dll".to_string(),
                vec!["GetProcAddress".to_string(), "ExitProcess".to_string()],
            ),
            (
                "kernel32.dll".to_string(),
                vec!["GetProcAddress".to_string(), "ord_12".to_string()],
            ),
        ];
        let (imp_rva, slot_map) = rebuild_import_section_with_map(&mut pe, &imports).unwrap();
        assert_eq!(imp_rva, 0x3000);
        assert_eq!(slot_map.len(), 3);
        let gp_slot = slot_map[&("kernel32.dll".into(), "GetProcAddress".into())];
        let ep_slot = slot_map[&("kernel32.dll".into(), "ExitProcess".into())];
        let ord_slot = slot_map[&("kernel32.dll".into(), "ord_12".into())];
        assert!(gp_slot > imp_rva && ep_slot > imp_rva && ord_slot > imp_rva);

        disable_aslr_and_strip_relocs(&mut pe).unwrap();
        assert_eq!(read_u16(&pe, opt_off + 70) & 0x0060, 0);
        assert_eq!(read_u32(&pe, dd_off + 5 * 8), 0); // BASERELOC cleared
        assert_eq!(read_u32(&pe, dd_off + 3 * 8), 0x2100); // EXCEPTION preserved
        assert_eq!(read_u32(&pe, dd_off + 9 * 8), 0x2300); // TLS preserved

        let modified = mark_sections_writable_for_rvas(&mut pe, &[0x1010]).unwrap();
        assert_eq!(modified, 1);
        assert_ne!(read_u32(&pe, sec_off + 36) & IMAGE_SCN_MEM_WRITE, 0);

        set_entry_point(&mut pe, 0x1234).unwrap();
        assert_eq!(read_u32(&pe, opt_off + 16), 0x1234);
    }
}
