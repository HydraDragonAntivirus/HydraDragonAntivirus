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
    if machine != 0x14c && machine != 0x8664 {
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

/// Fix section sizes based on virtual addresses.
/// SizeOfRawData = next_section.VirtualAddress - current_section.VirtualAddress
/// (rounded to file alignment).
pub fn fix_sections(data: &mut [u8], file_align: u32) -> UnpackerResult<()> {
    let (_, _, number_of_sections, _, sections_end) =
        parse_pe_headers(data).ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers".into()))?;

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
            align_up(raw_size, file_align)
        } else {
            align_up(curr_vs, file_align)
        };

        write_u32(data, off + 16, next_raw_size);
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

    // Collect per-DLL data: name bytes, hint/name entries, and IAT entries
    #[derive(Default)]
    struct DllImportData {
        dll_name_bytes: Vec<u8>,
        hint_name_data: Vec<u8>,
        iat_data: Vec<u8>,
    }

    let mut dll_entries: Vec<(String, DllImportData)> = Vec::new();

    for (dll_name, functions) in &ctx.dllname_to_functionlist {
        if functions.is_empty() {
            continue;
        }

        let mut dll = DllImportData::default();

        // DLL name (null-terminated)
        dll.dll_name_bytes = dll_name.as_bytes().to_vec();
        dll.dll_name_bytes.push(0);

        // Build hint/name entries and IAT entries
        let mut iat_entries: Vec<u32> = Vec::new();

        for (func_name, _func_addr) in functions {
            if func_name.starts_with("ord_") {
                let ordinal: u16 = func_name[4..].parse().unwrap_or(0);
                let ordinal_entry = IMAGE_SNAP_BY_ORDINAL | ordinal as u32;
                iat_entries.push(ordinal_entry);
            } else {
                let mut entry = Vec::new();
                let _ = entry.write_u16::<LittleEndian>(0); // hint
                entry.extend_from_slice(func_name.as_bytes());
                entry.push(0);
                if entry.len() % 2 != 0 {
                    entry.push(0);
                }

                // RVA of this hint/name entry within the section
                let name_rva_in_section = dll.dll_name_bytes.len() as u32 + dll.hint_name_data.len() as u32;
                iat_entries.push(name_rva_in_section);
                dll.hint_name_data.extend_from_slice(&entry);
            }
        }

        // IAT (null-terminated)
        for entry in &iat_entries {
            let _ = dll.iat_data.write_u32::<LittleEndian>(*entry);
        }
        let _ = dll.iat_data.write_u32::<LittleEndian>(0u32);

        dll_entries.push((dll_name.clone(), dll));
    }

    let num_dlls = dll_entries.len();
    if num_dlls == 0 {
        return Ok(ctx.original_imports.clone());
    }

    // Layout:
    // [descriptor_1..descriptor_N][zero_descriptor]
    // [dll1_name][dll1_hint_name][dll1_iat]
    // [dll2_name][dll2_hint_name][dll2_iat]
    // ...
    let descriptors_size = (num_dlls + 1) * 20;

    // Calculate component offsets within the section
    struct LayoutEntry {
        dll_name_offset: u32,
        hint_name_offset: u32,
        iat_offset: u32,
        desc_idx: usize,
    }

    let mut layout: Vec<LayoutEntry> = Vec::new();
    let mut cur = descriptors_size as u32;

    for (_dll_name, dll) in &dll_entries {
        let dll_name_offset = cur;
        cur += dll.dll_name_bytes.len() as u32;

        let hint_name_offset = cur;
        cur += dll.hint_name_data.len() as u32;

        let iat_offset = cur;
        cur += dll.iat_data.len() as u32;

        layout.push(LayoutEntry {
            dll_name_offset,
            hint_name_offset,
            iat_offset,
            desc_idx: layout.len(),
        });
    }

    let section_data_size = cur as usize;

    // Build the section data
    let mut section_data = vec![0u8; section_data_size];

    // Write descriptors with correct RVAs
    for entry in &layout {
        let desc_off = entry.desc_idx * 20;

        // OriginalFirstThunk -> hint/name table RVA
        let oft_rva = import_section_rva + entry.hint_name_offset;
        write_u32(&mut section_data, desc_off, oft_rva);
        // time_date_stamp
        write_u32(&mut section_data, desc_off + 4, 0);
        // forwarder_chain
        write_u32(&mut section_data, desc_off + 8, 0);
        // name RVA
        let name_rva = import_section_rva + entry.dll_name_offset;
        write_u32(&mut section_data, desc_off + 12, name_rva);
        // first_thunk RVA
        let iat_rva = import_section_rva + entry.iat_offset;
        write_u32(&mut section_data, desc_off + 16, iat_rva);
    }
    // Last descriptor is all-zeros (terminator) — already zero-initialized

    // Write DLL names, hint/name data, and IAT data
    for entry in &layout {
        let dll = &dll_entries[entry.desc_idx].1;

        let name_start = entry.dll_name_offset as usize;
        let name_end = name_start + dll.dll_name_bytes.len();
        section_data[name_start..name_end].copy_from_slice(&dll.dll_name_bytes);

        let hint_start = entry.hint_name_offset as usize;
        let hint_end = hint_start + dll.hint_name_data.len();
        section_data[hint_start..hint_end].copy_from_slice(&dll.hint_name_data);

        let iat_start = entry.iat_offset as usize;
        let iat_end = iat_start + dll.iat_data.len();
        section_data[iat_start..iat_end].copy_from_slice(&dll.iat_data);
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
        last_raw_ptr + last_raw_size
    } else {
        0x1000
    };

    let new_raw_pointer = align_up(last_section_raw_end, file_alignment);
    let new_raw_size = align_up(section_data.len() as u32, file_alignment);

    // Pad to alignment
    section_data.resize(new_raw_size as usize, 0);

    // Add section header
    let section_char = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    add_section(
        data,
        ".import",
        section_data.len() as u32,
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

    // Update data directories
    write_u32(data, import_dir_offset, import_section_rva);
    write_u32(data, import_dir_offset + 4, (num_dlls as u32 + 1) * 20);

    // IAT directory
    let first_iat_rva = if let Some(e) = layout.first() {
        import_section_rva + e.iat_offset
    } else {
        import_section_rva
    };
    write_u32(data, iat_dir_offset, first_iat_rva);
    write_u32(data, iat_dir_offset + 4, section_data.len() as u32);

    // Build result descriptors
    let mut result = Vec::new();
    for (i, (dll_name, _dll)) in dll_entries.iter().enumerate() {
        if let Some(entry) = layout.get(i) {
            let oft_rva = import_section_rva + entry.hint_name_offset;
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

/// Generate and write a PE checksum.
/// Uses the standard PE checksum algorithm (sum of all words in the file,
/// then add file size).
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

    // Compute checksum: sum of all words in the file, then add file size
    let len = data.len();
    let mut checksum: u64 = 0;
    let mut i = 0;

    while i < len {
        if i + 2 <= len {
            let word = read_u16(data, i) as u64;
            checksum = checksum.wrapping_add(word);
            i += 2;
        } else {
            let byte = data[i] as u64;
            checksum = checksum.wrapping_add(byte);
            i += 1;
        }
    }

    // Add file size
    checksum = checksum.wrapping_add(len as u64);

    // Store 32-bit checksum
    let final_checksum = (checksum & 0xFFFF_FFFF) as u32;
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

/// Main entry point - reads emulated state and writes PE to disk.
///
/// # Arguments
///
/// * `uc` - The Unicorn emulator instance
/// * `base_addr` - Base address of the emulated PE
/// * `virtualmemorysize` - Size of virtual memory
/// * `ctx` - Dump context with tracked imports, allocations, etc.
/// * `file_path` - Output file path
pub fn dump_image(
    uc: &Unicorn<()>,
    base_addr: u64,
    virtualmemorysize: u64,
    ctx: &DumpContext,
    file_path: &str,
) -> UnpackerResult<()> {
    // Read the full emulated memory into a buffer
    let mem_size = virtualmemorysize as usize;
    let mut image_data = vec![0u8; mem_size];

    uc.mem_read(base_addr, &mut image_data)
        .map_err(|e| UnpackerError::EmulatorError(format!("failed to read emulated memory: {e}")))?;

    // Parse PE headers to determine format
    let (opt_hdr_off, is_pe64, _, _, _) = parse_pe_headers(&image_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers from emulated memory".into()))?;

    // Get section alignment and file alignment from optional header
    let (section_alignment, file_alignment, _image_size) = if is_pe64 {
        // PE32+ optional header layout:
        // +0: magic(2)
        // +2: major_linker_version(1), minor_linker_version(1)
        // +4: size_of_code(4)
        // +8: size_of_initialized_data(4)
        // +12: size_of_uninitialized_data(4)
        // +16: address_of_entry_point(4)
        // +20: base_of_code(4)
        // +24: image_base(8)
        // +32: section_alignment(4)
        // +36: file_alignment(4)
        // ...
        let section_alignment = read_u32(&image_data, opt_hdr_off + 32);
        let file_alignment = read_u32(&image_data, opt_hdr_off + 36);
        let image_size = read_u32(&image_data, opt_hdr_off + 56);
        (section_alignment, file_alignment, image_size)
    } else {
        // PE32 optional header layout:
        // +0: magic(2)
        // +2: major_linker_version(1), minor_linker_version(1)
        // +4: size_of_code(4)
        // +8: size_of_initialized_data(4)
        // +12: size_of_uninitialized_data(4)
        // +16: address_of_entry_point(4)
        // +20: base_of_code(4)
        // +24: base_of_data(4)
        // +28: image_base(4)
        // +32: section_alignment(4)
        // +36: file_alignment(4)
        // ...
        let section_alignment = read_u32(&image_data, opt_hdr_off + 32);
        let file_alignment = read_u32(&image_data, opt_hdr_off + 36);
        let image_size = read_u32(&image_data, opt_hdr_off + 56);
        (section_alignment, file_alignment, image_size)
    };

    // Determine the real size of the image (highest section end)
    let section_hdr_offset = {
        let sig_offset = pe_signature_offset(&image_data).unwrap();
        let coff_offset = sig_offset + 4;
        let size_of_opt_hdr = read_u16(&image_data, coff_offset + 16);
        (coff_offset + 20 + size_of_opt_hdr as usize) as usize
    };

    let num_sections = read_u16(&image_data, pe_signature_offset(&image_data).unwrap() + 6);
    let sections = read_section_headers(&image_data, section_hdr_offset, num_sections);

    // Calculate actual image size from sections
    let actual_image_size = {
        let max_end = sections
            .iter()
            .map(|s| s.virtual_address.saturating_add(s.virtual_size))
            .max()
            .unwrap_or(0);
        align_up(max_end, section_alignment)
    };

    // Determine the raw data size needed
    let raw_size = {
        // Find the last section
        if let Some(last) = sections.last() {
            (last.pointer_to_raw_data + last.size_of_raw_data) as usize
        } else {
            0
        }
    };

    // Trim buffer to actual used size
    let mut pe_data = Vec::new();
    if raw_size > 0 && raw_size <= image_data.len() {
        pe_data.extend_from_slice(&image_data[..raw_size]);
    } else {
        pe_data = image_data;
    }

    // 1. Fix OEP: read current instruction pointer and write to address_of_entry_point
    let ip = if is_pe64 {
        uc.reg_read(unicorn_engine::RegisterX86::RIP)
            .map_err(|e| UnpackerError::EmulatorError(format!("failed to read RIP: {e}")))? as u64
    } else {
        uc.reg_read(unicorn_engine::RegisterX86::EIP)
            .map_err(|e| UnpackerError::EmulatorError(format!("failed to read EIP: {e}")))? as u64
    };

    let oep_rva = (ip - base_addr) as u32;
    write_u32(&mut pe_data, opt_hdr_off + 16, oep_rva);

    // 2. Fix section sizes
    fix_sections(&mut pe_data, file_alignment)?;

    // 3. Fix section memory protections
    fix_section_mem_protections(&mut pe_data, &ctx.allocated_chunks, base_addr)?;

    // 4. Fix imports
    let _new_imports = fix_imports_by_rebuilding(
        &mut pe_data,
        ctx,
        actual_image_size,
        section_alignment,
        file_alignment,
    )?;

    // 5. Fix checksum
    // Clear the security data directory (usually contains cert, not relevant for dumped binaries)
    let (opt_hdr_off, is_pe64, _, _, _) = parse_pe_headers(&pe_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers for checksum fix".into()))?;
    let data_dir_offset = if is_pe64 { opt_hdr_off + 112 } else { opt_hdr_off + 96 };
    let security_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if security_dir_offset + 8 <= pe_data.len() {
        write_u32(&mut pe_data, security_dir_offset, 0);
        write_u32(&mut pe_data, security_dir_offset + 4, 0);
    }

    // Clear relocation table flag (relocs are stripped in the dumped image)
    let coff_offset = pe_signature_offset(&pe_data).unwrap() + 4;
    let characteristics = read_u16(&pe_data, coff_offset + 18);
    write_u16(&mut pe_data, coff_offset + 18, characteristics | IMAGE_FILE_RELOCS_STRIPPED);

    // Also clear the reloc data directory
    let reloc_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
    if reloc_dir_offset + 8 <= pe_data.len() {
        write_u32(&mut pe_data, reloc_dir_offset, 0);
        write_u32(&mut pe_data, reloc_dir_offset + 4, 0);
    }

    fix_checksum(&mut pe_data)?;

    // 6. Write to file
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
    // Read the full emulated memory into a buffer
    let mem_size = virtualmemorysize as usize;
    let mut image_data = vec![0u8; mem_size];

    uc.mem_read(base_addr, &mut image_data)
        .map_err(|e| UnpackerError::EmulatorError(format!("failed to read emulated memory: {e}")))?;

    // Parse PE headers to determine format
    let (opt_hdr_off, is_pe64, _, _, _) = parse_pe_headers(&image_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers from emulated memory".into()))?;

    // Get section alignment and file alignment from optional header
    let (section_alignment, file_alignment, _image_size) = if is_pe64 {
        let section_alignment = read_u32(&image_data, opt_hdr_off + 32);
        let file_alignment = read_u32(&image_data, opt_hdr_off + 36);
        let image_size = read_u32(&image_data, opt_hdr_off + 56);
        (section_alignment, file_alignment, image_size)
    } else {
        let section_alignment = read_u32(&image_data, opt_hdr_off + 32);
        let file_alignment = read_u32(&image_data, opt_hdr_off + 36);
        let image_size = read_u32(&image_data, opt_hdr_off + 56);
        (section_alignment, file_alignment, image_size)
    };

    // Determine the real size of the image (highest section end)
    let section_hdr_offset = {
        let sig_offset = pe_signature_offset(&image_data).unwrap();
        let coff_offset = sig_offset + 4;
        let size_of_opt_hdr = read_u16(&image_data, coff_offset + 16);
        (coff_offset + 20 + size_of_opt_hdr as usize) as usize
    };

    let num_sections = read_u16(&image_data, pe_signature_offset(&image_data).unwrap() + 6);
    let sections = read_section_headers(&image_data, section_hdr_offset, num_sections);

    // Calculate actual image size from sections
    let actual_image_size = {
        let max_end = sections
            .iter()
            .map(|s| s.virtual_address.saturating_add(s.virtual_size))
            .max()
            .unwrap_or(0);
        align_up(max_end, section_alignment)
    };

    // Determine the raw data size needed
    let raw_size = {
        if let Some(last) = sections.last() {
            (last.pointer_to_raw_data + last.size_of_raw_data) as usize
        } else {
            0
        }
    };

    // Trim buffer to actual used size
    let mut pe_data = Vec::new();
    if raw_size > 0 && raw_size <= image_data.len() {
        pe_data.extend_from_slice(&image_data[..raw_size]);
    } else {
        pe_data = image_data;
    }

    // 1. Fix OEP
    let ip = if is_pe64 {
        uc.reg_read(unicorn_engine::RegisterX86::RIP)
            .map_err(|e| UnpackerError::EmulatorError(format!("failed to read RIP: {e}")))? as u64
    } else {
        uc.reg_read(unicorn_engine::RegisterX86::EIP)
            .map_err(|e| UnpackerError::EmulatorError(format!("failed to read EIP: {e}")))? as u64
    };

    let oep_rva = (ip - base_addr) as u32;
    write_u32(&mut pe_data, opt_hdr_off + 16, oep_rva);

    // 2. Fix section sizes
    fix_sections(&mut pe_data, file_alignment)?;

    // 3. Fix section memory protections
    fix_section_mem_protections(&mut pe_data, &ctx.allocated_chunks, base_addr)?;

    // 4. Fix imports
    let _new_imports = fix_imports_by_rebuilding(
        &mut pe_data,
        ctx,
        actual_image_size,
        section_alignment,
        file_alignment,
    )?;

    // 5. Fix checksum
    let (opt_hdr_off, is_pe64, _, _, _) = parse_pe_headers(&pe_data)
        .ok_or_else(|| UnpackerError::InvalidPeFile("cannot parse PE headers for checksum fix".into()))?;
    let data_dir_offset = if is_pe64 { opt_hdr_off + 112 } else { opt_hdr_off + 96 };
    let security_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if security_dir_offset + 8 <= pe_data.len() {
        write_u32(&mut pe_data, security_dir_offset, 0);
        write_u32(&mut pe_data, security_dir_offset + 4, 0);
    }

    let coff_offset = pe_signature_offset(&pe_data).unwrap() + 4;
    let characteristics = read_u16(&pe_data, coff_offset + 18);
    write_u16(&mut pe_data, coff_offset + 18, characteristics | IMAGE_FILE_RELOCS_STRIPPED);

    let reloc_dir_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
    if reloc_dir_offset + 8 <= pe_data.len() {
        write_u32(&mut pe_data, reloc_dir_offset, 0);
        write_u32(&mut pe_data, reloc_dir_offset + 4, 0);
    }

    fix_checksum(&mut pe_data)?;

    log::info!(
        "Dumped PE image to memory (size: {}, OEP: {:#x})",
        pe_data.len(),
        oep_rva
    );

    Ok(pe_data)
}
