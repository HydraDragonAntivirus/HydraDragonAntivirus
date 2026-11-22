//! Rust port of `vmpunpacker.cpp` — a VMProtect-style section unpacker.
//!
//! The packer leaves some sections "virtual" (SizeOfRawData == 0 &&
//! PointerToRawData == 0 && not UNINITIALIZED_DATA) and stores, just before a
//! sequence of those sections' RVAs, a `PACKER_INFO[]` array of `{Src, Dst}` u32
//! pairs. Entry `[0]` points at the 5-byte LZMA properties; entries `[1..=N]`
//! point at the LZMA-compressed data (`Src`) to decompress into the image at `Dst`.
//!
//! Detection works the same way: if the `{wildcard, RVA}` pattern for the virtual
//! sections is found, and the array before it points at valid LZMA properties and
//! at raw file data, the file is one of these packed executables. The pattern alone
//! is not enough: for one virtual section it is any 4 bytes and one RVA, which turns
//! up somewhere in nearly every PE.
//!
//! If the file has NO such virtual sections, there is nothing to unpack — the
//! original (headers + raw sections mapped to their RVAs) is returned unchanged.

use std::collections::HashMap;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE32 with a raw `.text` (raw 0x400, VA 0x1000) and one virtual section at VA
    /// 0x2000; `text` goes into `.text`.
    fn pe_with_virtual_section(text: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 0x400 + 0x200];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3c] = 0x80;
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // sections
        d[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // optional header size
        let opt = 0x98;
        d[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        let s = opt + 0xe0;
        // .text: VirtualSize, VA, SizeOfRawData, PointerToRawData
        for (i, v) in [0x200u32, 0x1000, 0x200, 0x400].iter().enumerate() {
            d[s + 8 + i * 4..s + 12 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        // virtual section: VirtualSize 0x1000 at VA 0x2000, no raw data
        let v = s + 40;
        d[v + 8..v + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        d[v + 12..v + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        d[0x400..0x400 + text.len()].copy_from_slice(text);
        d
    }

    #[test]
    fn pattern_alone_is_not_a_packed_file() {
        // "any 4 bytes + 0x2000" preceded by text (".fbi..."): what an unpacked PE
        // with one virtual section looks like. Not detected, and unpacking maps the
        // sections instead of failing on the text read as an RVA.
        let mut text = Vec::new();
        text.extend_from_slice(b".fbi.exe"); // PACKER_INFO[0] would be read from here
        text.extend_from_slice(&[1, 2, 3, 4]);
        text.extend_from_slice(&0x2000u32.to_le_bytes());
        let d = pe_with_virtual_section(&text);
        assert!(!detect(&d));
        let image = unpack(&d).expect("mapped, not an error");
        assert_eq!(&image[0x1000..0x1008], b".fbi.exe");
    }

    #[test]
    fn real_table_is_detected() {
        // [0] = props at RVA 0x1020 (5 bytes: 0x5d, 64 KiB); [1] = block at RVA 0x1030
        // into the virtual section's RVA 0x2000.
        let mut text = vec![0u8; 0x40];
        text[0..4].copy_from_slice(&0x1020u32.to_le_bytes());
        text[4..8].copy_from_slice(&5u32.to_le_bytes());
        text[8..12].copy_from_slice(&0x1030u32.to_le_bytes());
        text[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
        text[0x20] = 0x5d;
        text[0x21..0x25].copy_from_slice(&0x10000u32.to_le_bytes());
        let d = pe_with_virtual_section(&text);
        assert!(detect(&d));
    }

    #[test]
    fn vmp38_encrypted_dst_table_is_detected_and_unpacked() {
        // Build a PE32 with 2 virtual sections (VA 0x2000 and 0x3000) and one raw `.vmp` section
        // at VA 0x1000, Raw 0x400 containing a VMP 3.8+ PACKER_INFO table:
        //   +0x00: props_rva: u32
        //   +0x04: (src_rva_0, scrambled_dst_0)
        //   +0x0c: (src_rva_1, scrambled_dst_1)
        // followed by raw LZMA1 properties (5d 00 00 01 00 = lc3/lp0/pb2, dict 64 KiB)
        // and two real raw LZMA1 streams (encoding "VMP38_SEC0" and "VMP38_SEC1").
        let sec0_lzma: &[u8] = &[
            0x00, 0x20, 0x90, 0x84, 0x76, 0xba, 0x8a, 0x75, 0xcf, 0xb8, 0xd6, 0xe3, 0x83, 0xff,
            0xfd, 0x00, 0x30, 0x00,
        ];
        let sec1_lzma: &[u8] = &[
            0x00, 0x18, 0x8c, 0x82, 0xb6, 0xc4, 0x11, 0x34, 0x5c, 0x53, 0xbd, 0xa7, 0x1f, 0xff,
            0xfc, 0xff, 0xe0, 0x00,
        ];
        let mut pe = vec![0u8; 0x400 + 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        pe[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        let opt = 0x98;
        pe[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());

        let sh = opt + 0xe0;
        // [0] virtual .text at VA 0x1000
        pe[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // [1] virtual .rdata at VA 0x2000
        let sh1 = sh + 40;
        pe[sh1 + 8..sh1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sh1 + 12..sh1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        // [2] raw .vmp at VA 0x3000, Raw 0x400, Size 0x200
        let sh2 = sh + 80;
        pe[sh2 + 8..sh2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh2 + 12..sh2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        pe[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh2 + 20..sh2 + 24].copy_from_slice(&0x400u32.to_le_bytes());

        // Populate .vmp at raw 0x400 (RVA 0x3000):
        // props at +0x40 (RVA 0x3040)
        // stream0 at +0x60 (RVA 0x3060)
        // stream1 at +0xA0 (RVA 0x30A0)
        pe[0x400..0x404].copy_from_slice(&0x3040u32.to_le_bytes());
        pe[0x404..0x408].copy_from_slice(&0x3060u32.to_le_bytes());
        pe[0x408..0x40c].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // scrambled dst 0
        pe[0x40c..0x410].copy_from_slice(&0x30A0u32.to_le_bytes());
        pe[0x410..0x414].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes()); // scrambled dst 1

        pe[0x440] = 0x5d;
        pe[0x441..0x445].copy_from_slice(&0x10000u32.to_le_bytes());
        pe[0x460..0x460 + sec0_lzma.len()].copy_from_slice(sec0_lzma);
        pe[0x4a0..0x4a0 + sec1_lzma.len()].copy_from_slice(sec1_lzma);

        assert!(detect(&pe), "VMP 3.8+ encrypted-Dst table should be detected");
        let unpacked = unpack(&pe).expect("VMP 3.8+ unpack should succeed");
        assert_eq!(&unpacked[0x1000..0x1008], b"ABCDEFGH");
        assert_eq!(&unpacked[0x2000..0x2008], b"12345678");
    }
}

struct PackerTable {
    props_rva: u32,
    blocks: Vec<(u32, u32)>, // (src_rva, dst_rva)
}

#[inline]
fn is_valid_lzma_props(p: &[u8]) -> bool {
    if p.len() < LZMA_PROPERTIES_SIZE || p[0] >= 9 * 5 * 5 {
        return false;
    }
    let dict = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
    (4096..=0x0400_0000).contains(&dict) && dict.is_power_of_two()
}

/// `FindPattern` with `0xFF` as a wildcard byte (mirrors the C++), from `from` on.
fn find_pattern(data: &[u8], pattern: &[u8], from: usize) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() || from > data.len() - pattern.len() {
        return None;
    }
    // Anchor on the first fully fixed 4-byte group (the patterns here are wildcard u32 +
    // RVA u32 pairs): one u32 compare per offset instead of the byte loop below, which
    // ran over every file the emulator loads.
    if let Some(g) = (0..pattern.len() / 4).find(|g| pattern[g * 4..g * 4 + 4].iter().all(|&b| b != 0xFF)) {
        let at = g * 4;
        let anchor = u32::from_le_bytes(pattern[at..at + 4].try_into().unwrap());
        let last = data.len() - pattern.len();
        let mut i = from;
        while i <= last {
            if u32::from_le_bytes(data[i + at..i + at + 4].try_into().unwrap()) == anchor
                && pattern.iter().enumerate().all(|(j, &p)| p == 0xFF || data[i + j] == p)
            {
                return Some(i);
            }
            i += 1;
        }
        return None;
    }
    'outer: for i in from..=data.len() - pattern.len() {
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

/// Locate the `PACKER_INFO` table (either classic VMP 3.x `{wildcard, dst_rva}` or
/// VMP 3.8+ encrypted-Dst `{props_rva, (src_rva, enc_dst)...}`). Returns `None` if the
/// file has no virtual sections or neither table format is valid.
fn locate_packer_info(data: &[u8], pe: &Pe) -> Option<PackerTable> {
    let virt = virtual_sections(pe);
    if virt.is_empty() {
        return None; // nothing to unpack
    }
    let pattern = rva_pattern_bytes(&virt);
    let count = virt.len();
    // Path 1: Classic VMP 3.x `{wildcard, dst_rva}` sequence.
    let mut from = 0;
    while let Some(m) = find_pattern(data, &pattern, from) {
        from = m + 1;
        if m < PACKER_INFO_SIZE {
            continue;
        }
        let array_off = m - PACKER_INFO_SIZE; // PACKER_INFO[0] precedes the matched run
        // The array spans [0..=count] = count+1 entries; bounds-check it.
        if array_off + (count + 1) * PACKER_INFO_SIZE <= data.len()
            && packer_info_valid(data, pe, array_off, count)
        {
            let props_rva = rd_u32(data, array_off).ok()?;
            let mut blocks = Vec::with_capacity(count);
            for i in 1..=count {
                blocks.push(packer_entry(data, array_off, i).ok()?);
            }
            return Some(PackerTable { props_rva, blocks });
        }
    }

    // Path 2: VMP 3.8+ encrypted-Dst table: `props_rva: u32`, then N * `(src_rva: u32, enc_dst: u32)`.
    locate_packer_info_vmp38(data, pe, &virt)
}

fn locate_packer_info_vmp38(data: &[u8], pe: &Pe, virt: &[&Section]) -> Option<PackerTable> {
    let mut bloom16 = [0u64; 1024];
    let mut props_map: HashMap<u32, (u8, u32)> = HashMap::new();
    for s in &pe.sections {
        if s.pointer_to_raw_data == 0 || s.size_of_raw_data < LZMA_PROPERTIES_SIZE as u32 {
            continue;
        }
        let raw_start = s.pointer_to_raw_data as usize;
        let max_raw = data.len().saturating_sub(raw_start);
        let usable = (s.size_of_raw_data as usize)
            .min(s.virtual_size as usize)
            .min(max_raw);
        if usable < LZMA_PROPERTIES_SIZE {
            continue;
        }
        let sec_slice = &data[raw_start..raw_start + usable];
        for off in 0..=usable - LZMA_PROPERTIES_SIZE {
            let p = &sec_slice[off..off + LZMA_PROPERTIES_SIZE];
            if is_valid_lzma_props(p) {
                let rva = s.virtual_address.saturating_add(off as u32);
                if rva_to_raw(pe, rva, data.len(), "").is_ok() {
                    let dict_size = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    props_map.insert(rva, (p[0], dict_size));
                    let p16 = (rva & 0xFFFF) as usize;
                    bloom16[p16 >> 6] |= 1u64 << (p16 & 63);
                }
            }
        }
    }
    if props_map.is_empty() {
        return None;
    }

    let count = virt.len();
    let table_tail_bytes = count.checked_mul(PACKER_INFO_SIZE)?;
    let mut scratch = [0u8; 64];
    let mut src_rvas = Vec::with_capacity(count);
    let mut raw_offs = Vec::with_capacity(count);

    for s in &pe.sections {
        if s.pointer_to_raw_data == 0 || s.size_of_raw_data < 4 {
            continue;
        }
        let raw_start = s.pointer_to_raw_data as usize;
        let max_raw = data.len().saturating_sub(raw_start);
        let sec_len = (s.size_of_raw_data as usize).min(max_raw);
        if raw_start + 4 + table_tail_bytes > data.len() || sec_len < 4 {
            continue;
        }
        let end_in_sec = (sec_len - 4).min(data.len() - 4 - table_tail_bytes - raw_start);
        for off in 0..=end_in_sec {
            let ref_off = raw_start + off;
            let p16 = u16::from_le_bytes([data[ref_off], data[ref_off + 1]]) as usize;
            if (bloom16[p16 >> 6] & (1u64 << (p16 & 63))) == 0 {
                continue;
            }
            let val = u32::from_le_bytes(data[ref_off..ref_off + 4].try_into().ok()?);
            let Some(&(props_byte, dict_size)) = props_map.get(&val) else {
                continue;
            };
            src_rvas.clear();
            raw_offs.clear();
            let mut ok = true;
            for i in 0..count {
                let entry_off = ref_off + 4 + i * PACKER_INFO_SIZE;
                let Ok(src_rva) = rd_u32(data, entry_off) else {
                    ok = false;
                    break;
                };
                if src_rvas.contains(&src_rva) {
                    ok = false;
                    break;
                }
                let Ok(raw_i) = rva_to_raw(pe, src_rva, data.len(), "") else {
                    ok = false;
                    break;
                };
                if data.get(raw_i).copied() != Some(0x00) {
                    ok = false;
                    break;
                }
                src_rvas.push(src_rva);
                raw_offs.push(raw_i);
            }
            if !ok {
                continue;
            }
            // Trial-decode a small prefix of every stream so false positives are impossible.
            let all_decode = raw_offs.iter().all(|&raw_i| {
                lzma_rust2::LzmaReader::new_with_props(
                    std::io::Cursor::new(&data[raw_i..]),
                    u64::MAX,
                    props_byte,
                    dict_size,
                    None,
                )
                .ok()
                .and_then(|mut r| r.read(&mut scratch).ok())
                .is_some_and(|n| n > 0)
            });
            if all_decode {
                let blocks = src_rvas
                    .iter()
                    .copied()
                    .zip(virt.iter().map(|vs| vs.virtual_address))
                    .collect();
                return Some(PackerTable {
                    props_rva: val,
                    blocks,
                });
            }
        }
    }

    None
}

/// Whether the array at `array_off` is a real `PACKER_INFO[]`: entry `[0]` points at
/// raw file data holding valid LZMA1 properties (lc/lp/pb byte below 9*5*5, a
/// dictionary of at least 4 KiB) and every block's `Src` points at raw file data.
fn packer_info_valid(data: &[u8], pe: &Pe, array_off: usize, count: usize) -> bool {
    let raw_at = |rva: u32| rva_to_raw(pe, rva, data.len(), "").ok();
    let Some(props) = packer_entry(data, array_off, 0)
        .ok()
        .and_then(|(src, _)| raw_at(src))
        .and_then(|raw| data.get(raw..raw + LZMA_PROPERTIES_SIZE))
    else {
        return false;
    };
    if props[0] >= 9 * 5 * 5 || u32::from_le_bytes([props[1], props[2], props[3], props[4]]) < 4096 {
        return false;
    }
    (1..=count).all(|i| packer_entry(data, array_off, i).ok().and_then(|(src, _)| raw_at(src)).is_some())
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

/// Metadata and decompressed payload for one packed virtual section stream.
#[derive(Debug, Clone)]
pub struct UnpackedStream {
    pub props_rva: u32,
    pub src_rva: u32,
    pub dst_rva: u32,
    pub bytes: Vec<u8>,
}

fn decode_lzma_into(
    src_slice: &[u8],
    props_byte: u8,
    dict_size: u32,
    block_num: usize,
    dst_slice: &mut [u8],
) -> Result<usize, String> {
    let mut reader = lzma_rust2::LzmaReader::new_with_props(
        std::io::Cursor::new(src_slice),
        u64::MAX,
        props_byte,
        dict_size,
        None,
    )
    .map_err(|e| format!("Block {block_num}: LZMA init failed: {e}"))?;

    let mut written = 0usize;
    let avail = dst_slice.len();
    loop {
        if written >= avail {
            break;
        }
        let n = reader
            .read(&mut dst_slice[written..avail])
            .map_err(|e| format!("Block {block_num}: LZMA decode failed: {e}"))?;
        if n == 0 {
            break;
        }
        written += n;
    }
    Ok(written)
}

fn read_table_props(data: &[u8], pe: &Pe, table: &PackerTable) -> Result<(u8, u32), String> {
    let file_size = data.len();
    let props_raw = rva_to_raw(pe, table.props_rva, file_size, "LZMA Props")?;
    if props_raw + LZMA_PROPERTIES_SIZE > file_size {
        return Err("LZMA properties extend beyond file".into());
    }
    let props = &data[props_raw..props_raw + LZMA_PROPERTIES_SIZE];
    Ok((props[0], u32::from_le_bytes([props[1], props[2], props[3], props[4]])))
}

/// Locates the VMProtect `PACKER_INFO` table and decompresses each virtual section,
/// returning `(props_rva, src_rva, dst_rva, unpacked_bytes)` per stream.
/// Returns `Ok(Vec::new())` if the PE has no VMProtect virtual sections.
pub fn unpack_streams(data: &[u8]) -> Result<Vec<UnpackedStream>, String> {
    if data.is_empty() {
        return Err("Packed PE data is empty.".into());
    }
    let pe = parse_pe(data)?;
    let Some(table) = locate_packer_info(data, &pe) else {
        return Ok(Vec::new());
    };
    let (props_byte, dict_size) = read_table_props(data, &pe, &table)?;
    let soi = pe.size_of_image as usize;
    let file_size = data.len();

    let mut streams = Vec::with_capacity(table.blocks.len());
    for (idx, &(src_rva, dst_rva)) in table.blocks.iter().enumerate() {
        let block_num = idx + 1;
        let src_raw = rva_to_raw(&pe, src_rva, file_size, &format!("Block {block_num} data"))?;
        if dst_rva as usize >= soi {
            return Err(format!("Block {block_num}: Dst RVA 0x{dst_rva:x} out of image bounds"));
        }
        let sec_cap = pe
            .sections
            .iter()
            .find(|s| s.virtual_address == dst_rva)
            .map(|s| s.virtual_size as usize)
            .filter(|&v| v > 0)
            .unwrap_or_else(|| soi - dst_rva as usize)
            .min(soi - dst_rva as usize);
        let mut out = vec![0u8; sec_cap];
        let written = decode_lzma_into(&data[src_raw..], props_byte, dict_size, block_num, &mut out)?;
        out.truncate(written);
        streams.push(UnpackedStream {
            props_rva: table.props_rva,
            src_rva,
            dst_rva,
            bytes: out,
        });
    }
    Ok(streams)
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
    let Some(table) = locate_packer_info(data, &pe) else {
        return Ok(image);
    };
    let _ = pe.num_sections;

    // LZMA properties (5 bytes: props byte + u32 LE dict size).
    let (props_byte, dict_size) = read_table_props(data, &pe, &table)?;

    // Decode each compressed block into the image at its Dst RVA.
    for (idx, &(src_rva, dst_rva)) in table.blocks.iter().enumerate() {
        let block_num = idx + 1;
        let src_raw = rva_to_raw(&pe, src_rva, file_size, &format!("Block {block_num} data"))?;
        if dst_rva as usize >= soi {
            return Err(format!("Block {block_num}: Dst RVA 0x{dst_rva:x} out of image bounds"));
        }
        let dst = dst_rva as usize;
        let avail = soi - dst;
        decode_lzma_into(
            &data[src_raw..],
            props_byte,
            dict_size,
            block_num,
            &mut image[dst..dst + avail],
        )?;
    }

    Ok(image)
}
