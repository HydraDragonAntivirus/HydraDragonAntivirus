//! Rust port of `vmpunpacker.cpp` — a VMProtect-style section unpacker.
//!
//! The packer leaves some sections "virtual" (SizeOfRawData == 0 &&
//! PointerToRawData == 0 && not UNINITIALIZED_DATA) and stores, just before a
//! sequence of those sections' RVAs, a `PACKER_INFO[]` array of `{Src, Dst}` u32
//! pairs. Entry `[0]` points at the 5-byte LZMA properties; entries `[1..=N]`
//! point at the LZMA-compressed data (`Src`) to decompress into the image at `Dst`.
//!
//! Detection works the same way: if the `{wildcard, RVA}` pattern for the virtual
//! sections is found, the file is one of these packed executables.
//!
//! If the file has NO such virtual sections, there is nothing to unpack — the
//! original (headers + raw sections mapped to their RVAs) is returned unchanged.

use std::io::Read;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const PACKER_INFO_SIZE: usize = 8; // two u32
const LZMA_PROPERTIES_SIZE: usize = 5;

#[inline]
fn rd_u16(d: &[u8], off: usize) -> Result<u16, String> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("u16 read out of bounds at 0x{off:x}"))
}
#[inline]
fn rd_u32(d: &[u8], off: usize) -> Result<u32, String> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("u32 read out of bounds at 0x{off:x}"))
}

/// One section's parsed fields plus the byte offset of its header (so the unpacked
/// image's copy of the header can be rewritten in place).
#[derive(Clone, Copy)]
struct Section {
    header_off: usize,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

struct Pe {
    num_sections: u16,
    size_of_image: u32,
    size_of_headers: u32,
    sections: Vec<Section>,
}

fn parse_pe(data: &[u8]) -> Result<Pe, String> {
    if rd_u16(data, 0)? != IMAGE_DOS_SIGNATURE {
        return Err("Invalid DOS signature".into());
    }
    let e_lfanew = rd_u32(data, 0x3C)? as usize;
    if rd_u32(data, e_lfanew)? != IMAGE_NT_SIGNATURE {
        return Err("Invalid NT signature".into());
    }
    let file_header = e_lfanew + 4;
    let num_sections = rd_u16(data, file_header + 2)?;
    let size_of_optional = rd_u16(data, file_header + 16)? as usize;
    let opt = file_header + 20; // OptionalHeader start
    // SizeOfImage / SizeOfHeaders sit at the same offset for PE32 and PE32+.
    let size_of_image = rd_u32(data, opt + 56)?;
    let size_of_headers = rd_u32(data, opt + 60)?;

    let sec_base = opt + size_of_optional;
    let mut sections = Vec::with_capacity(num_sections as usize);
    for i in 0..num_sections as usize {
        let h = sec_base + i * 40;
        if h + 40 > data.len() {
            return Err("Section header out of bounds".into());
        }
        sections.push(Section {
            header_off: h,
            virtual_size: rd_u32(data, h + 8)?,
            virtual_address: rd_u32(data, h + 12)?,
            size_of_raw_data: rd_u32(data, h + 16)?,
            pointer_to_raw_data: rd_u32(data, h + 20)?,
            characteristics: rd_u32(data, h + 36)?,
        });
    }
    Ok(Pe {
        num_sections,
        size_of_image,
        size_of_headers,
        sections,
    })
}

/// PE RVA → raw file offset (mirrors `RVAtoRawOffset`).
fn rva_to_raw(pe: &Pe, rva: u32, file_size: usize, ctx: &str) -> Result<usize, String> {
    if rva < pe.size_of_headers {
        if rva as usize >= file_size {
            return Err(format!("RVAtoRawOffset ({ctx}): header RVA 0x{rva:x} out of file bounds"));
        }
        return Ok(rva as usize);
    }
    for s in &pe.sections {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
            if s.pointer_to_raw_data == 0 {
                return Err(format!("RVAtoRawOffset ({ctx}): RVA 0x{rva:x} in a section with no raw data"));
            }
            let off_in_section = rva - s.virtual_address;
            if off_in_section >= s.size_of_raw_data {
                return Err(format!("RVAtoRawOffset ({ctx}): RVA 0x{rva:x} in the virtual-only part of a section"));
            }
            let raw = s.pointer_to_raw_data + off_in_section;
            if raw as usize >= file_size {
                return Err(format!("RVAtoRawOffset ({ctx}): raw offset 0x{raw:x} out of file bounds"));
            }
            return Ok(raw as usize);
        }
    }
    Err(format!("RVAtoRawOffset ({ctx}): RVA 0x{rva:x} not found in any section"))
}

/// `FindPattern` with `0xFF` as a wildcard byte (mirrors the C++).
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    'outer: for i in 0..=data.len() - pattern.len() {
        for (j, &p) in pattern.iter().enumerate() {
            if p != 0xFF && data[i + j] != p {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

/// The virtual sections (SizeOfRawData==0 && PointerToRawData==0 && not
/// UNINITIALIZED_DATA) whose RVAs form the search pattern, in section order.
fn virtual_sections(pe: &Pe) -> Vec<&Section> {
    pe.sections
        .iter()
        .filter(|s| {
            s.size_of_raw_data == 0
                && s.pointer_to_raw_data == 0
                && (s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0
        })
        .collect()
}

/// The `{wildcard u32, VirtualAddress u32}` byte pattern for the virtual sections.
fn rva_pattern_bytes(virt: &[&Section]) -> Vec<u8> {
    let mut p = Vec::with_capacity(virt.len() * PACKER_INFO_SIZE);
    for s in virt {
        p.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // Src placeholder (wildcard)
        p.extend_from_slice(&s.virtual_address.to_le_bytes()); // Dst == VA
    }
    p
}

/// Locate the `PACKER_INFO[]` array. Returns `(array_file_offset, entry_count)`
/// where entry `[0]` is the LZMA props and `[1..=count]` are the data blocks, or
/// `None` if the file has no virtual sections / the pattern isn't present.
fn locate_packer_info(data: &[u8], pe: &Pe) -> Option<(usize, usize)> {
    let virt = virtual_sections(pe);
    if virt.is_empty() {
        return None; // nothing to unpack
    }
    let pattern = rva_pattern_bytes(&virt);
    let m = find_pattern(data, &pattern)?;
    if m < PACKER_INFO_SIZE {
        return None;
    }
    let array_off = m - PACKER_INFO_SIZE; // PACKER_INFO[0] precedes the matched run
    // The array spans [0..=count] = count+1 entries; bounds-check it.
    let count = virt.len();
    let end = array_off + (count + 1) * PACKER_INFO_SIZE;
    if end > data.len() {
        return None;
    }
    Some((array_off, count))
}

/// True if `data` is one of these LZMA-packed executables.
pub fn detect(data: &[u8]) -> bool {
    parse_pe(data)
        .ok()
        .and_then(|pe| locate_packer_info(data, &pe))
        .is_some()
}

#[inline]
fn packer_entry(data: &[u8], array_off: usize, idx: usize) -> Result<(u32, u32), String> {
    let off = array_off + idx * PACKER_INFO_SIZE;
    Ok((rd_u32(data, off)?, rd_u32(data, off + 4)?)) // (Src, Dst)
}

/// Unpack the PE. Copies headers + raw sections to their RVAs, then LZMA-decodes
/// each block into the image. If there are no virtual sections to fill, the mapped
/// image is returned without an unpack step.
pub fn unpack(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("Packed PE data is empty.".into());
    }
    let pe = parse_pe(data)?;
    let file_size = data.len();
    let soi = pe.size_of_image as usize;
    let soh = pe.size_of_headers as usize;
    if soh > file_size || soh > soi {
        return Err("Invalid SizeOfHeaders.".into());
    }

    let mut image = vec![0u8; soi];
    // Copy the PE headers.
    image[..soh].copy_from_slice(&data[..soh]);

    // Map each section's raw data to its RVA, and rewrite the section header in the
    // unpacked image (PointerToRawData = VirtualAddress; SizeOfRawData = VirtualSize).
    for s in &pe.sections {
        if s.pointer_to_raw_data != 0 && s.size_of_raw_data > 0 {
            let src = s.pointer_to_raw_data as usize;
            let len = s.size_of_raw_data as usize;
            let dst = s.virtual_address as usize;
            if src + len <= file_size && dst + len <= soi {
                image[dst..dst + len].copy_from_slice(&data[src..src + len]);
            } else {
                eprintln!(
                    "Warning: section data out of bounds (raw 0x{:x}+0x{:x}, va 0x{:x}); skipping copy",
                    s.pointer_to_raw_data, s.size_of_raw_data, s.virtual_address
                );
            }
        }
        // Rewrite header copy: PointerToRawData = VA, SizeOfRawData = VirtualSize|raw.
        if s.header_off + 40 <= image.len() {
            image[s.header_off + 20..s.header_off + 24].copy_from_slice(&s.virtual_address.to_le_bytes());
            let new_raw_size = if s.virtual_size > 0 { s.virtual_size } else { s.size_of_raw_data };
            image[s.header_off + 16..s.header_off + 20].copy_from_slice(&new_raw_size.to_le_bytes());
        }
    }

    // No virtual sections / no PACKER_INFO → nothing to LZMA-unpack.
    let Some((array_off, count)) = locate_packer_info(data, &pe) else {
        return Ok(image);
    };
    let _ = pe.num_sections;

    // Entry [0] = LZMA properties (5 bytes: props byte + u32 LE dict size).
    let (props_src, props_dst) = packer_entry(data, array_off, 0)?;
    let props_raw = rva_to_raw(&pe, props_src, file_size, "LZMA Props")?;
    if props_raw + LZMA_PROPERTIES_SIZE > file_size {
        return Err("LZMA properties extend beyond file".into());
    }
    if props_dst as usize != LZMA_PROPERTIES_SIZE {
        eprintln!(
            "Warning: PACKER_INFO[0].Dst (props size) is {props_dst}, standard is {LZMA_PROPERTIES_SIZE}."
        );
    }
    let props = &data[props_raw..props_raw + LZMA_PROPERTIES_SIZE];
    let props_byte = props[0];
    let dict_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);

    // Decode each compressed block [1..=count] into the image at its Dst RVA.
    for idx in 1..=count {
        let (src_rva, dst_rva) = packer_entry(data, array_off, idx)?;
        let src_raw = rva_to_raw(&pe, src_rva, file_size, &format!("Block {idx} data"))?;
        if dst_rva as usize >= soi {
            return Err(format!("Block {idx}: Dst RVA 0x{dst_rva:x} out of image bounds"));
        }
        let dst = dst_rva as usize;
        let avail = soi - dst;

        // Raw LZMA1: props byte + dict size, decode until the end marker (we don't
        // know the exact size up front, so cap at the section's available space).
        let mut reader = lzma_rust2::LzmaReader::new_with_props(
            std::io::Cursor::new(&data[src_raw..]),
            u64::MAX,
            props_byte,
            dict_size,
            None,
        )
        .map_err(|e| format!("Block {idx}: LZMA init failed: {e}"))?;

        let mut written = 0usize;
        loop {
            if written >= avail {
                break;
            }
            let n = reader
                .read(&mut image[dst + written..dst + avail])
                .map_err(|e| format!("Block {idx}: LZMA decode failed: {e}"))?;
            if n == 0 {
                break; // end-of-stream
            }
            written += n;
        }
    }

    Ok(image)
}
