//! Generic VMProtect 3.x / 3.8+ runnable PE reconstruction.
//!
//! When a VMProtect-packed PE is statically unpacked (`vmpunpacker::unpack`) and
//! optionally devirtualized (`vm_devirt::devirtualize_pe_bytes`), the unpacked image
//! alone is not directly runnable by the Windows PE loader:
//! - Original imports were wiped/encrypted into VMProtect `IMPORT_INFO` tables inside
//!   the packer loader section with encrypted strings and per-entry signed `i32` keys.
//! - `AddressOfEntryPoint` points into the compressed/encrypted packer loader stub
//!   rather than the real CRT OEP.
//! - Virtualized routines and CRT code rely on `VMProtectRuntime` (`DllMainCRTStartup` /
//!   `__DllMainCRTStartup`) having initialized C++ runtime state and VMProtect's
//!   `LoaderData` structure.
//!
//! This module recovers those structures completely generically (no sample-specific
//! hardcoded constants), rebuilds `.import`, probes `VMProtectRuntime` + `LoaderData`
//! inside Unicorn across VMP 3.5 and VMP 3.8+ layouts, emits an RWX `.vmpinit`
//! bootstrap section, clears ASLR + relocations, and updates `AddressOfEntryPoint`.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

use iced_x86::code_asm::registers::{gpr32, gpr64};
use iced_x86::code_asm::{dword_ptr, qword_ptr, word_ptr, CodeAssembler};
use iced_x86::{
    BlockEncoderOptions, Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register,
};
use serde::Serialize;
use unicorn_engine::unicorn_const::{Arch, HookType as UcHookType, Mode, Prot, X86Insn};
use unicorn_engine::{RegisterX86, Unicorn};

use crate::unpacker::engine::{parse_pe_bytes, OptionalHeader, Section};
use crate::unpacker::error::{UnpackerError, UnpackerResult};
use crate::unpacker::imagedump;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

#[derive(Debug, Clone, Serialize)]
pub struct VmpRebuildReport {
    pub rebuilt: bool,
    pub oep_rva: Option<u32>,
    pub init_stub_rva: Option<u32>,
    pub import_section_rva: Option<u32>,
    pub key32: Option<u32>,
    pub import_dlls: usize,
    pub import_entries: usize,
    pub fixup_records: usize,
    pub runtime_entry_rva: Option<u32>,
    pub loader_data_ptr_rva: Option<u32>,
    pub loader_data_mode: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ImportRecord {
    dll_name: String,
    func_name: String,
    dst_slot_rva: u32,
    key_i32: i32,
}

#[derive(Debug, Clone, Copy)]
struct ImportFixup {
    iat_slot_rva: u32,
    dst_slot_rva: u32,
    key_i32: i32,
}

#[derive(Debug, Clone)]
struct LoaderDataEnvPatch {
    offset: usize,
    base_const: u32,
}

#[derive(Debug, Clone)]
struct LoaderDataPlan {
    mode: String,
    template: Vec<u8>,
    pass_in_r8: bool,
    g_loader_data_rva: Option<u32>,
    env_xor_patches: Vec<LoaderDataEnvPatch>,
    ld_ptr_xor_patches: Vec<LoaderDataEnvPatch>,
    ld_rel_qwords: Vec<(usize, i64)>,
    image_rel_qwords: Vec<(usize, i64)>,
}

#[inline]
fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn rva_to_raw(sections: &[Section], size_of_headers: u32, rva: u32, len: usize) -> Option<usize> {
    if rva < size_of_headers {
        return ((rva as usize) < len).then_some(rva as usize);
    }
    for s in sections {
        let span = s.virtual_size.max(s.size_of_raw_data);
        if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span) {
            if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
                return None;
            }
            let delta = rva - s.virtual_address;
            if delta >= s.size_of_raw_data {
                return None;
            }
            let raw = s.pointer_to_raw_data.checked_add(delta)? as usize;
            return (raw < len).then_some(raw);
        }
    }
    None
}

fn raw_to_rva(sections: &[Section], size_of_headers: u32, raw_off: usize) -> Option<u32> {
    if raw_off < size_of_headers as usize {
        return u32::try_from(raw_off).ok();
    }
    let off_u32 = u32::try_from(raw_off).ok()?;
    for s in sections {
        if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
            continue;
        }
        if off_u32 >= s.pointer_to_raw_data
            && off_u32 < s.pointer_to_raw_data.saturating_add(s.size_of_raw_data)
        {
            return Some(s.virtual_address + (off_u32 - s.pointer_to_raw_data));
        }
    }
    None
}

fn read_cstr_at(data: &[u8], off: usize, max_len: usize) -> Option<String> {
    let slice = data.get(off..data.len().min(off + max_len))?;
    let end = slice.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    if !slice[..end].iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    String::from_utf8(slice[..end].to_vec()).ok()
}

/// Extracts original PE `IMAGE_DIRECTORY_ENTRY_IMPORT` entries so their IAT slots
/// remain intact after `.import` is rebuilt in a new section.
fn extract_original_iat(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    is_pe64: bool,
) -> Vec<ImportRecord> {
    let mut records = Vec::new();
    let Some(imp_dir) = opt.data_directory.get(IMAGE_DIRECTORY_ENTRY_IMPORT) else {
        return records;
    };
    if imp_dir.virtual_address == 0 {
        return records;
    }
    let Some(mut desc_off) = rva_to_raw(sections, opt.size_of_headers, imp_dir.virtual_address, pe.len()) else {
        return records;
    };
    let ptr_size: u32 = if is_pe64 { 8 } else { 4 };

    for _ in 0..512 {
        let Some(oft) = rd_u32(pe, desc_off) else {
            break;
        };
        let Some(name_rva) = rd_u32(pe, desc_off + 12) else {
            break;
        };
        let Some(ft) = rd_u32(pe, desc_off + 16) else {
            break;
        };
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        desc_off += 20;
        let Some(name_raw) = rva_to_raw(sections, opt.size_of_headers, name_rva, pe.len()) else {
            continue;
        };
        let Some(dll_name) = read_cstr_at(pe, name_raw, 128) else {
            continue;
        };
        let lookup_rva = if oft != 0 { oft } else { ft };
        let Some(mut lookup_raw) = rva_to_raw(sections, opt.size_of_headers, lookup_rva, pe.len()) else {
            continue;
        };

        let mut slot_rva = ft;
        for _ in 0..8192 {
            let func_name = if is_pe64 {
                let Some(v) = rd_u64(pe, lookup_raw) else {
                    break;
                };
                if v == 0 {
                    break;
                }
                lookup_raw += 8;
                if (v & (1u64 << 63)) != 0 {
                    Some(format!("ord_{}", v & 0xFFFF))
                } else {
                    rva_to_raw(sections, opt.size_of_headers, v as u32, pe.len())
                        .and_then(|hn| read_cstr_at(pe, hn + 2, 160))
                }
            } else {
                let Some(v) = rd_u32(pe, lookup_raw) else {
                    break;
                };
                if v == 0 {
                    break;
                }
                lookup_raw += 4;
                if (v & 0x8000_0000) != 0 {
                    Some(format!("ord_{}", v & 0xFFFF))
                } else {
                    rva_to_raw(sections, opt.size_of_headers, v, pe.len())
                        .and_then(|hn| read_cstr_at(pe, hn + 2, 160))
                }
            };
            if let Some(fname) = func_name {
                records.push(ImportRecord {
                    dll_name: dll_name.clone(),
                    func_name: fname,
                    dst_slot_rva: slot_rva,
                    key_i32: 0,
                });
            }
            slot_rva = slot_rva.saturating_add(ptr_size);
        }
    }
    records
}

#[inline]
fn vmp_key_byte(key32: u32, idx: usize) -> u8 {
    key32.rotate_left((idx & 31) as u32).wrapping_add(idx as u32) as u8
}

fn decrypt_vmp_cstr(data: &[u8], off: usize, key32: u32, max_len: usize) -> Option<String> {
    let limit = max_len.min(data.len().saturating_sub(off));
    if limit < 2 {
        return None;
    }
    let mut out = Vec::with_capacity(limit.min(64));
    for i in 0..limit {
        let dec = data[off + i] ^ vmp_key_byte(key32, i);
        if dec == 0 {
            if out.is_empty() {
                return None;
            }
            return String::from_utf8(out).ok();
        }
        if !(0x21..=0x7E).contains(&dec) {
            return None;
        }
        out.push(dec);
    }
    None
}

fn is_plausible_dll_name(name: &str) -> bool {
    if !(4..=64).contains(&name.len()) {
        return false;
    }
    let low = name.to_ascii_lowercase();
    low.contains('.')
        && (low.ends_with(".dll")
            || low.ends_with(".exe")
            || low.ends_with(".ocx")
            || low.ends_with(".drv")
            || low.ends_with(".sys"))
}

fn find_loader_section(sections: &[Section], packed_ep_rva: u32) -> Option<Section> {
    if let Some(s) = sections.iter().find(|s| {
        let span = s.virtual_size.max(s.size_of_raw_data);
        s.pointer_to_raw_data > 0
            && s.size_of_raw_data > 0
            && packed_ep_rva >= s.virtual_address
            && packed_ep_rva < s.virtual_address.saturating_add(span)
    }) {
        return Some(s.clone());
    }
    sections
        .iter()
        .rev()
        .find(|s| {
            s.pointer_to_raw_data > 0
                && s.size_of_raw_data > 0
                && (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
        })
        .cloned()
}

fn decode_import_func_name(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    fn_rva: u32,
    key32: u32,
) -> Option<String> {
    if (fn_rva & 0x8000_0000) != 0 {
        if (fn_rva & 0x7FFF_0000) != 0 || (fn_rva & 0xFFFF) == 0 {
            return None;
        }
        Some(format!("ord_{}", fn_rva & 0xFFFF))
    } else {
        let fn_raw = rva_to_raw(sections, opt.size_of_headers, fn_rva, pe.len())?;
        decrypt_vmp_cstr(pe, fn_raw, key32, 161)
    }
}

/// Primary VMP 3.5 / 3.8+ `IMPORT_INFO` layout:
/// Repeated DLL blocks `{ dll_rva: u32 }` followed by `{ fn_rva: u32, slot_rva: u32, key_i32: i32 }`
/// entries terminated by `fn_rva == 0` (4 bytes). There is no trailing `dll_rva == 0`.
fn parse_import_info_table_v4_12(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    table_raw: usize,
    key32: u32,
    is_pe64: bool,
) -> Option<(Vec<ImportRecord>, usize)> {
    let ptr_size = if is_pe64 { 8u32 } else { 4u32 };
    let mut cur = table_raw;
    let mut records = Vec::new();
    let mut blocks = 0usize;

    while blocks < 512 {
        let block_start = cur;
        let rec_checkpoint = records.len();
        let Some(dll_rva) = rd_u32(pe, cur) else {
            break;
        };
        let Some(dll_raw) = rva_to_raw(sections, opt.size_of_headers, dll_rva, pe.len()) else {
            break;
        };
        let Some(dll_name) = decrypt_vmp_cstr(pe, dll_raw, key32, 65) else {
            break;
        };
        if !is_plausible_dll_name(&dll_name) {
            break;
        }
        cur += 4;

        let mut block_entries = 0usize;
        let mut saw_zero = false;
        let mut block_valid = true;

        for _ in 0..8192 {
            let Some(fn_rva) = rd_u32(pe, cur) else {
                block_valid = false;
                break;
            };
            if fn_rva == 0 {
                cur += 4;
                saw_zero = true;
                break;
            }
            let (Some(slot_rva), Some(slot_key)) = (rd_u32(pe, cur + 4), rd_u32(pe, cur + 8)) else {
                block_valid = false;
                break;
            };
            cur += 12;

            if slot_rva < 0x1000 || slot_rva.saturating_add(ptr_size) > opt.size_of_image {
                block_valid = false;
                break;
            }
            let Some(func_name) = decode_import_func_name(pe, opt, sections, fn_rva, key32) else {
                block_valid = false;
                break;
            };
            records.push(ImportRecord {
                dll_name: dll_name.clone(),
                func_name,
                dst_slot_rva: slot_rva,
                key_i32: slot_key as i32,
            });
            block_entries += 1;
        }

        if !block_valid || !saw_zero || block_entries == 0 {
            records.truncate(rec_checkpoint);
            cur = block_start;
            if blocks == 0 {
                return None;
            }
            break;
        }
        blocks += 1;
    }

    (records.len() >= 2).then_some((records, cur))
}

/// Legacy VMP 3.x `IMPORT_INFO` layout fallback:
/// `{ dll_rva: u32, key_i32: i32 }` + `{ fn_rva: u32, slot_rva: u32 }` ending in `fn_rva == 0`,
/// terminated overall by `dll_rva == 0`.
fn parse_import_info_table_v8_8(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    table_raw: usize,
    key32: u32,
    is_pe64: bool,
) -> Option<(Vec<ImportRecord>, usize)> {
    let ptr_size = if is_pe64 { 8u32 } else { 4u32 };
    let mut cur = table_raw;
    let mut records = Vec::new();
    let mut blocks = 0usize;

    loop {
        let dll_rva = rd_u32(pe, cur)?;
        let slot_key = rd_u32(pe, cur + 4)?;
        if dll_rva == 0 {
            if blocks == 0 {
                return None;
            }
            return (records.len() >= 2).then_some((records, cur + 8));
        }
        cur += 8;

        let dll_raw = rva_to_raw(sections, opt.size_of_headers, dll_rva, pe.len())?;
        let dll_name = decrypt_vmp_cstr(pe, dll_raw, key32, 65)?;
        if !is_plausible_dll_name(&dll_name) {
            return None;
        }
        let key_i32 = slot_key as i32;
        let mut block_entries = 0usize;

        for _ in 0..8192 {
            let fn_rva = rd_u32(pe, cur)?;
            if fn_rva == 0 {
                cur += 4;
                break;
            }
            let slot_rva = rd_u32(pe, cur + 4)?;
            cur += 8;

            if slot_rva < 0x1000 || slot_rva.saturating_add(ptr_size) > opt.size_of_image {
                return None;
            }
            let func_name = decode_import_func_name(pe, opt, sections, fn_rva, key32)?;
            records.push(ImportRecord {
                dll_name: dll_name.clone(),
                func_name,
                dst_slot_rva: slot_rva,
                key_i32,
            });
            block_entries += 1;
        }
        if block_entries == 0 {
            return None;
        }
        blocks += 1;
        if blocks > 512 {
            return None;
        }
    }
}

/// Validates and parses one `IMPORT_INFO` table starting at `table_raw` using `key32`.
/// Returns `(records, end_raw)` or `None` if any structural invariant fails.
fn parse_import_info_table(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    table_raw: usize,
    key32: u32,
    is_pe64: bool,
) -> Option<(Vec<ImportRecord>, usize)> {
    parse_import_info_table_v4_12(pe, opt, sections, table_raw, key32, is_pe64)
        .or_else(|| parse_import_info_table_v8_8(pe, opt, sections, table_raw, key32, is_pe64))
}

/// Fast O(N) discovery of VMProtect `KEY32` + all `IMPORT_INFO` tables in `loader_sec`.
fn find_vmp_import_tables(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    loader_sec: &Section,
    is_pe64: bool,
) -> (Option<u32>, Vec<ImportRecord>) {
    let l_start = loader_sec.pointer_to_raw_data as usize;
    let l_len = (loader_sec.size_of_raw_data as usize).min(pe.len().saturating_sub(l_start));
    if l_len < 64 {
        return (None, Vec::new());
    }
    let l_end = l_start + l_len;
    let l_bytes = &pe[l_start..l_end];

    // 1. Collect all KEY32 candidates matching `mov r32, imm32 ... rol r32, cl` (both legacy and REX.B forms)
    // within 64 bytes across the entire loader section. Also include 0 for plaintext fallback.
    let mut key_cands = HashSet::new();
    key_cands.insert(0u32);
    for i in 1..l_bytes.len() {
        if l_bytes[i - 1] == 0xD3 && (0xC0..=0xC7).contains(&l_bytes[i]) {
            let rex_b = i >= 2 && l_bytes[i - 2] == 0x41;
            let reg = l_bytes[i] - 0xC0;
            let op_mov = 0xB8 + reg;
            let rol_start = if rex_b { i - 2 } else { i - 1 };
            let win_start = rol_start.saturating_sub(64);
            if rol_start >= 5 {
                for j in win_start..=(rol_start - 5) {
                    if rex_b {
                        if j >= 1 && l_bytes[j - 1] == 0x41 && l_bytes[j] == op_mov {
                            if let Some(k) = rd_u32(l_bytes, j + 1) {
                                key_cands.insert(k);
                            }
                        }
                    } else if l_bytes[j] == op_mov {
                        if let Some(k) = rd_u32(l_bytes, j + 1) {
                            key_cands.insert(k);
                        }
                    }
                }
            }
        }
    }

    // 2. Build L1-friendly 16-bit prefix bitset + u64 lookup for encrypted anchor DLL prefixes.
    const ANCHORS: &[&[u8]] = &[
        b"kernel32.dll\0",
        b"KERNEL32.dll\0",
        b"KERNEL32.DLL\0",
        b"Kernel32.dll\0",
        b"ntdll.dll\0",
        b"NTDLL.dll\0",
        b"NTDLL.DLL\0",
        b"user32.dll\0",
        b"USER32.dll\0",
        b"USER32.DLL\0",
        b"kernelbase.dll\0",
        b"KERNELBASE.dll\0",
        b"KERNELBASE.DLL\0",
        b"advapi32.dll\0",
        b"ADVAPI32.dll\0",
        b"ADVAPI32.DLL\0",
    ];
    let mut bloom16 = [0u64; 1024];
    let mut prefix64_map: HashMap<u64, Vec<u32>> = HashMap::new();
    for &k in &key_cands {
        for &anc in ANCHORS {
            let mut enc = [0u8; 8];
            for idx in 0..8 {
                enc[idx] = anc[idx] ^ vmp_key_byte(k, idx);
            }
            let p16 = u16::from_le_bytes([enc[0], enc[1]]) as usize;
            bloom16[p16 >> 6] |= 1u64 << (p16 & 63);
            let p64 = u64::from_le_bytes(enc);
            prefix64_map.entry(p64).or_default().push(k);
        }
    }

    // 3. Single O(N) pass over `l_bytes` to find which `(str_rva, key32)` pairs produce a full anchor string.
    let mut verified_keys: HashMap<u32, Vec<u32>> = HashMap::new();
    if l_bytes.len() >= 14 {
        for off in 0..=l_bytes.len() - 14 {
            let p16 = u16::from_le_bytes([l_bytes[off], l_bytes[off + 1]]) as usize;
            if (bloom16[p16 >> 6] & (1u64 << (p16 & 63))) == 0 {
                continue;
            }
            let p64 = u64::from_le_bytes(l_bytes[off..off + 8].try_into().unwrap());
            let Some(keys) = prefix64_map.get(&p64) else {
                continue;
            };
            let abs_raw = l_start + off;
            let Some(rva) = raw_to_rva(sections, opt.size_of_headers, abs_raw) else {
                continue;
            };
            for &k in keys {
                if decrypt_vmp_cstr(l_bytes, off, k, 20).is_some_and(|s| {
                    matches!(
                        s.to_ascii_lowercase().as_str(),
                        "kernel32.dll" | "ntdll.dll" | "user32.dll" | "kernelbase.dll" | "advapi32.dll"
                    )
                }) {
                    verified_keys.entry(k).or_default().push(rva);
                }
            }
        }
    }

    let mut candidate_keys: Vec<u32> = verified_keys.keys().copied().collect();
    candidate_keys.sort_by_key(|k| std::cmp::Reverse(verified_keys.get(k).map_or(0, Vec::len)));

    for k in candidate_keys {
        let records = collect_all_tables_for_key(pe, opt, sections, loader_sec, k, is_pe64);
        if !records.is_empty() {
            return (Some(k), records);
        }
    }
    (None, Vec::new())
}

fn collect_all_tables_for_key(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    loader_sec: &Section,
    key32: u32,
    is_pe64: bool,
) -> Vec<ImportRecord> {
    let l_start = loader_sec.pointer_to_raw_data as usize;
    let l_len = (loader_sec.size_of_raw_data as usize).min(pe.len().saturating_sub(l_start));
    if l_len < 24 {
        return Vec::new();
    }
    let l_bytes = &pe[l_start..l_start + l_len];

    // Single pass to collect all valid DLL string RVAs decrypted under `key32`.
    let mut dll_rvas: HashSet<u32> = HashSet::new();
    let mut rva_bloom16 = [0u64; 1024];
    for off in 0..l_bytes.len().saturating_sub(6) {
        let mut ok4 = true;
        for j in 0..4 {
            let dec = l_bytes[off + j] ^ vmp_key_byte(key32, j);
            if !(0x21..=0x7E).contains(&dec) {
                ok4 = false;
                break;
            }
        }
        if !ok4 {
            continue;
        }
        if let Some(s) = decrypt_vmp_cstr(l_bytes, off, key32, 65) {
            if is_plausible_dll_name(&s) {
                if let Some(rva) = raw_to_rva(sections, opt.size_of_headers, l_start + off) {
                    dll_rvas.insert(rva);
                    let p16 = (rva & 0xFFFF) as usize;
                    rva_bloom16[p16 >> 6] |= 1u64 << (p16 & 63);
                }
            }
        }
    }
    if dll_rvas.is_empty() {
        return Vec::new();
    }

    // Single pass over `l_bytes` to find 4-byte LE occurrences of `dll_rvas`.
    let mut all_records = Vec::new();
    let mut covered_ranges: Vec<(usize, usize)> = Vec::new();
    for off in 0..=l_bytes.len().saturating_sub(20) {
        let abs_raw = l_start + off;
        if covered_ranges.iter().any(|&(s, e)| abs_raw >= s && abs_raw < e) {
            continue;
        }
        let p16 = u16::from_le_bytes([l_bytes[off], l_bytes[off + 1]]) as usize;
        if (rva_bloom16[p16 >> 6] & (1u64 << (p16 & 63))) == 0 {
            continue;
        }
        let val = u32::from_le_bytes(l_bytes[off..off + 4].try_into().unwrap());
        if !dll_rvas.contains(&val) {
            continue;
        }
        if let Some((recs, end_raw)) = parse_import_info_table(pe, opt, sections, abs_raw, key32, is_pe64) {
            covered_ranges.push((abs_raw, end_raw));
            all_records.extend(recs);
        }
    }
    all_records
}

/// Discovers CRT OEP inside primary code section (`.text` or first executable section).
/// Prioritizes `RUNTIME_FUNCTION` start addresses matching MSVC x64 CRT startup
/// (`sub rsp, imm8; call rel32; add rsp, imm8; jmp rel32`), then falls back to byte scan.
pub fn find_oep_rva(pe: &[u8]) -> Option<u32> {
    let (_dos, _pe, opt, sections) = parse_pe_bytes(pe).ok()?;
    let text_sec = sections
        .iter()
        .find(|s| {
            s.size_of_raw_data > 0
                && s.pointer_to_raw_data > 0
                && (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
        })?;
    let t_start = text_sec.virtual_address;
    let t_end = t_start.saturating_add(text_sec.virtual_size.max(text_sec.size_of_raw_data));

    let check_crt_stub_at = |rva: u32| -> bool {
        let Some(raw) = rva_to_raw(sections.as_slice(), opt.size_of_headers, rva, pe.len()) else {
            return false;
        };
        let Some(b) = pe.get(raw..raw + 14) else {
            return false;
        };
        // sub rsp, imm8 (0x20..=0x48); call rel32; add rsp, imm8; jmp rel32
        if b[0] != 0x48 || b[1] != 0x83 || b[2] != 0xEC || !(0x20..=0x48).contains(&b[3]) {
            return false;
        }
        if b[4] != 0xE8 || b[9] != 0x48 || b[10] != 0x83 || b[11] != 0xC4 || b[12] != b[3] || b[13] != 0xE9 {
            return false;
        }
        let Some(b2) = pe.get(raw..raw + 18) else {
            return false;
        };
        let rel_call = i32::from_le_bytes(b2[5..9].try_into().unwrap()) as i64;
        let rel_jmp = i32::from_le_bytes(b2[14..18].try_into().unwrap()) as i64;
        let tgt_call = (rva as i64 + 9).wrapping_add(rel_call);
        let tgt_jmp = (rva as i64 + 18).wrapping_add(rel_jmp);
        tgt_call >= t_start as i64
            && tgt_call < t_end as i64
            && tgt_jmp >= t_start as i64
            && tgt_jmp < t_end as i64
    };

    // 1. Prioritize exact `RUNTIME_FUNCTION.BeginAddress` entries in `.text` (and prefer imm8 == 0x28).
    if let Some(exc) = opt.data_directory.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        if exc.virtual_address != 0 && exc.size >= 12 {
            if let Some(eoff) = rva_to_raw(&sections, opt.size_of_headers, exc.virtual_address, pe.len()) {
                let cnt = (exc.size as usize / 12).min(pe.len().saturating_sub(eoff) / 12);
                let mut fallback_rf = None;
                for i in 0..cnt {
                    let Some(begin) = rd_u32(pe, eoff + i * 12) else {
                        break;
                    };
                    if begin >= t_start && begin < t_end && check_crt_stub_at(begin) {
                        if let Some(raw) = rva_to_raw(&sections, opt.size_of_headers, begin, pe.len()) {
                            if pe.get(raw + 3) == Some(&0x28) {
                                return Some(begin);
                            }
                            if fallback_rf.is_none() {
                                fallback_rf = Some(begin);
                            }
                        }
                    }
                }
                if let Some(b) = fallback_rf {
                    return Some(b);
                }
            }
        }
    }

    // 2. Linear scan inside `.text`.
    let raw_base = text_sec.pointer_to_raw_data as usize;
    let raw_len = (text_sec.size_of_raw_data as usize).min(pe.len().saturating_sub(raw_base));
    for off in 0..raw_len.saturating_sub(18) {
        if pe[raw_base + off] == 0x48 && pe[raw_base + off + 1] == 0x83 && pe[raw_base + off + 2] == 0xEC {
            let rva = text_sec.virtual_address + off as u32;
            if check_crt_stub_at(rva) {
                return Some(rva);
            }
        }
    }
    None
}

/// Discovers candidate `VMProtectRuntime` entrypoints `(primary_rva, fallback_native_rva)`
/// inside non-loader unpacked VM sections using `RUNTIME_FUNCTION` metadata.
fn find_vmp_runtime_candidates(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    loader_sec_va: Option<u32>,
) -> Vec<u32> {
    let mut cands = Vec::new();
    let Some(exc) = opt.data_directory.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return cands;
    };
    if exc.virtual_address == 0 || exc.size < 12 {
        return cands;
    }
    let Some(eoff) = rva_to_raw(sections, opt.size_of_headers, exc.virtual_address, pe.len()) else {
        return cands;
    };
    let cnt = (exc.size as usize / 12).min(pe.len().saturating_sub(eoff) / 12);
    let first_exec_va = sections
        .iter()
        .find(|s| (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        .map(|s| s.virtual_address);

    let mut rfs = Vec::new();
    for i in 0..cnt {
        let off = eoff + i * 12;
        if let (Some(b), Some(e)) = (rd_u32(pe, off), rd_u32(pe, off + 4)) {
            if b != 0 && e > b {
                rfs.push((b, e));
            }
        }
    }
    rfs.sort_unstable();

    // Locate a non-primary, non-loader executable section containing `__DllMainCRTStartup`:
    // Tier 1: checks BOTH `cmp edx, 1` (83 FA 01) AND `cmp edx, 2` (83 FA 02) + adjacent <= 0x100 VM wrapper.
    // Tier 2: checks BOTH `83 FA 01` AND `83 FA 02`.
    // Tier 3: fallback checking `83 FA 01`.
    let mut tier1 = Vec::new();
    let mut tier2 = Vec::new();
    let mut tier3 = Vec::new();
    for idx in 0..rfs.len() {
        let (b, e) = rfs[idx];
        let sec = sections.iter().find(|s| {
            let span = s.virtual_size.max(s.size_of_raw_data);
            b >= s.virtual_address && b < s.virtual_address.saturating_add(span)
        });
        let Some(sec) = sec else { continue };
        if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 {
            continue;
        }
        if Some(sec.virtual_address) == first_exec_va || Some(sec.virtual_address) == loader_sec_va {
            continue;
        }
        let fn_len = (e - b) as usize;
        if !(0x40..=0x300).contains(&fn_len) {
            continue;
        }
        let Some(raw) = rva_to_raw(sections, opt.size_of_headers, b, pe.len()) else {
            continue;
        };
        let Some(bytes) = pe.get(raw..raw + fn_len.min(pe.len() - raw)) else {
            continue;
        };
        let has_cmp_edx_1 = bytes.windows(3).any(|w| w == [0x83, 0xFA, 0x01]);
        let has_cmp_edx_2 = bytes.windows(3).any(|w| w == [0x83, 0xFA, 0x02]);
        let call_count = bytes.iter().filter(|&&x| x == 0xE8).count();
        if has_cmp_edx_1 && call_count >= 2 {
            let adj_wrapper = (idx + 1 < rfs.len() && rfs[idx + 1].0 == e && (rfs[idx + 1].1 - rfs[idx + 1].0) <= 0x100)
                .then_some(rfs[idx + 1].0);
            if has_cmp_edx_2 {
                if let Some(w) = adj_wrapper {
                    tier1.push(w);
                    tier1.push(b);
                } else {
                    tier2.push(b);
                }
            } else {
                tier3.push(b);
            }
        }
    }
    if !tier1.is_empty() {
        return tier1;
    }
    if !tier2.is_empty() {
        return tier2;
    }
    let _ = &mut cands;
    tier3
}

#[derive(Debug, Clone, Copy)]
struct Crc32Loop {
    loop_head_va: u64,
    tbl_reg: RegisterX86,
    crc_reg: RegisterX86,
    ptr_reg: RegisterX86,
    len_reg: RegisterX86,
    crc_xor_imm: u32,
}

fn iced_reg_to_unicorn(r: Register) -> Option<RegisterX86> {
    match r.full_register() {
        Register::RAX => Some(RegisterX86::RAX),
        Register::RCX => Some(RegisterX86::RCX),
        Register::RDX => Some(RegisterX86::RDX),
        Register::RBX => Some(RegisterX86::RBX),
        Register::RSP => Some(RegisterX86::RSP),
        Register::RBP => Some(RegisterX86::RBP),
        Register::RSI => Some(RegisterX86::RSI),
        Register::RDI => Some(RegisterX86::RDI),
        Register::R8 => Some(RegisterX86::R8),
        Register::R9 => Some(RegisterX86::R9),
        Register::R10 => Some(RegisterX86::R10),
        Register::R11 => Some(RegisterX86::R11),
        Register::R12 => Some(RegisterX86::R12),
        Register::R13 => Some(RegisterX86::R13),
        Register::R14 => Some(RegisterX86::R14),
        Register::R15 => Some(RegisterX86::R15),
        _ => None,
    }
}

fn is_imm_one(ins: &iced_x86::Instruction, op_idx: u32) -> bool {
    matches!(
        ins.op_kind(op_idx),
        OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32 | OpKind::Immediate32to64
    ) && ins.immediate(op_idx) == 1
}

fn is_imm_minus_one(ins: &iced_x86::Instruction, op_idx: u32) -> bool {
    matches!(
        ins.op_kind(op_idx),
        OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32 | OpKind::Immediate32to64
    ) && (ins.immediate(op_idx) as i64) == -1
}

fn decode_crc_window(
    bytes: &[u8],
    base_va: u64,
    start_off: usize,
    max_insns: usize,
) -> Vec<iced_x86::Instruction> {
    let mut out = Vec::with_capacity(max_insns);
    let mut pos = start_off;
    let mut dec = Decoder::with_ip(64, bytes, base_va, DecoderOptions::NONE);
    let _ = dec.set_position(pos);
    dec.set_ip(base_va + pos as u64);
    let mut branch_follows = 0usize;

    while out.len() < max_insns && dec.can_decode() {
        let ins = dec.decode();
        if ins.is_invalid() {
            break;
        }
        out.push(ins);
        match ins.flow_control() {
            FlowControl::UnconditionalBranch => {
                let tgt = ins.near_branch_target();
                if tgt > ins.ip() && tgt >= base_va && (tgt - base_va) < bytes.len() as u64 && branch_follows < 6 {
                    pos = (tgt - base_va) as usize;
                    if dec.set_position(pos).is_err() {
                        break;
                    }
                    dec.set_ip(tgt);
                    branch_follows += 1;
                } else {
                    break;
                }
            }
            FlowControl::Return | FlowControl::IndirectBranch => break,
            FlowControl::ConditionalBranch => {
                if ins.near_branch_target() < ins.ip() {
                    break;
                }
            }
            _ => {}
        }
    }
    out
}

fn analyze_crc32_loop_at(bytes: &[u8], base_va: u64, dec_start: usize) -> Option<Crc32Loop> {
    let fwd = decode_crc_window(bytes, base_va, dec_start, 96);
    let first = fwd.first()?;
    if first.mnemonic() != Mnemonic::And
        || first.op0_kind() != OpKind::Register
        || first.immediate(1) != 0xFF
    {
        return None;
    }
    let idx_iced = first.op0_register().full_register();
    let hit_va = first.ip();

    let mut tbl_iced = None;
    let mut crc_iced = None;
    let mut ptr_iced = None;
    let mut len_iced = None;
    let mut crc_xor_imm = 0u32;
    let mut loop_head_va = None;

    for ins in &fwd {
        match ins.mnemonic() {
            Mnemonic::Mov
                if ins.op_count() >= 2
                    && ins.op0_kind() == OpKind::Register
                    && ins.op0_register().full_register() == idx_iced
                    && ins.op1_kind() == OpKind::Memory
                    && ins.memory_index_scale() == 4
                    && ins.memory_index().full_register() == idx_iced
                    && ins.memory_base() != Register::None =>
            {
                tbl_iced = Some(ins.memory_base().full_register());
            }
            Mnemonic::Shr
                if ins.op0_kind() == OpKind::Register
                    && ins.immediate(1) == 8
                    && ins.op0_register().size() >= 4 =>
            {
                let cand = ins.op0_register().full_register();
                if cand != Register::RSP && cand != idx_iced && Some(cand) != tbl_iced {
                    crc_iced = Some(cand);
                }
            }
            Mnemonic::Xor
                if tbl_iced.is_some()
                    && crc_iced.is_some()
                    && ins.op0_kind() == OpKind::Register
                    && Some(ins.op0_register().full_register()) == crc_iced =>
            {
                if matches!(
                    ins.op1_kind(),
                    OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate32 | OpKind::Immediate32to64
                ) {
                    crc_xor_imm = ins.immediate32();
                }
            }
            Mnemonic::Inc if ins.op0_kind() == OpKind::Register => {
                let r = ins.op0_register().full_register();
                if r != Register::RSP && r != idx_iced && Some(r) != tbl_iced && Some(r) != crc_iced && ptr_iced.is_none() {
                    ptr_iced = Some(r);
                }
            }
            Mnemonic::Add if ins.op0_kind() == OpKind::Register && is_imm_one(ins, 1) => {
                let r = ins.op0_register().full_register();
                if r != Register::RSP && r != idx_iced && Some(r) != tbl_iced && Some(r) != crc_iced && ptr_iced.is_none() {
                    ptr_iced = Some(r);
                }
            }
            Mnemonic::Dec if ins.op0_kind() == OpKind::Register => {
                let r = ins.op0_register().full_register();
                if r != Register::RSP
                    && r != idx_iced
                    && Some(r) != tbl_iced
                    && Some(r) != crc_iced
                    && Some(r) != ptr_iced
                {
                    len_iced = Some(r);
                }
            }
            Mnemonic::Sub if ins.op0_kind() == OpKind::Register && is_imm_one(ins, 1) => {
                let r = ins.op0_register().full_register();
                if r != Register::RSP
                    && r != idx_iced
                    && Some(r) != tbl_iced
                    && Some(r) != crc_iced
                    && Some(r) != ptr_iced
                {
                    len_iced = Some(r);
                }
            }
            Mnemonic::Add if ins.op0_kind() == OpKind::Register && is_imm_minus_one(ins, 1) => {
                let r = ins.op0_register().full_register();
                if r != Register::RSP
                    && r != idx_iced
                    && Some(r) != tbl_iced
                    && Some(r) != crc_iced
                    && Some(r) != ptr_iced
                {
                    len_iced = Some(r);
                }
            }
            _ => {}
        }

        if ins.flow_control() == FlowControl::ConditionalBranch {
            let tgt = ins.near_branch_target();
            if tgt < hit_va && hit_va - tgt <= 256 && tgt >= base_va {
                loop_head_va = Some(tgt);
                break;
            }
        }
    }

    let head = loop_head_va?;
    let tbl = tbl_iced?;
    let crc = crc_iced?;

    // Verify `xor crc, idx` or `xor idx, crc` occurred near the table lookup.
    let has_xor_crc_idx = fwd.iter().any(|ins| {
        ins.mnemonic() == Mnemonic::Xor
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ((ins.op0_register().full_register() == crc && ins.op1_register().full_register() == idx_iced)
                || (ins.op0_register().full_register() == idx_iced && ins.op1_register().full_register() == crc))
    });
    if !has_xor_crc_idx {
        return None;
    }

    // If pointer or length register wasn't captured forward, also inspect [loop_head .. dec_start].
    if (ptr_iced.is_none() || len_iced.is_none()) && (head - base_va) < dec_start as u64 {
        let head_off = (head - base_va) as usize;
        let pre = decode_crc_window(bytes, base_va, head_off, 32);
        for ins in &pre {
            if ins.ip() >= hit_va {
                break;
            }
            if ptr_iced.is_none() && ins.op0_kind() == OpKind::Register {
                let r = ins.op0_register().full_register();
                if (ins.mnemonic() == Mnemonic::Inc || (ins.mnemonic() == Mnemonic::Add && is_imm_one(ins, 1)))
                    && r != Register::RSP
                    && r != idx_iced
                    && r != tbl
                    && r != crc
                {
                    ptr_iced = Some(r);
                }
            }
            if len_iced.is_none() && ins.op0_kind() == OpKind::Register {
                let r = ins.op0_register().full_register();
                if (ins.mnemonic() == Mnemonic::Dec
                    || (ins.mnemonic() == Mnemonic::Sub && is_imm_one(ins, 1))
                    || (ins.mnemonic() == Mnemonic::Add && is_imm_minus_one(ins, 1)))
                    && r != Register::RSP
                    && r != idx_iced
                    && r != tbl
                    && r != crc
                    && Some(r) != ptr_iced
                {
                    len_iced = Some(r);
                }
            }
        }
    }

    Some(Crc32Loop {
        loop_head_va: head,
        tbl_reg: iced_reg_to_unicorn(tbl)?,
        crc_reg: iced_reg_to_unicorn(crc)?,
        ptr_reg: iced_reg_to_unicorn(ptr_iced?)?,
        len_reg: iced_reg_to_unicorn(len_iced?)?,
        crc_xor_imm,
    })
}

/// Scans `bytes` (mapped at `base_va`) for obfuscated/mutated IEEE CRC32 loops (`and reg32, 0xFF`).
fn find_crc32_loops(bytes: &[u8], base_va: u64) -> Vec<Crc32Loop> {
    let mut loops = Vec::new();
    let mut seen_heads = HashSet::new();
    let mut i = 0usize;

    while i + 5 <= bytes.len() {
        let matched_start = if i + 6 <= bytes.len()
            && bytes[i] == 0x81
            && (0xE0..=0xE7).contains(&bytes[i + 1])
            && bytes[i + 2..i + 6] == [0xFF, 0x00, 0x00, 0x00]
        {
            if i > 0 && (bytes[i - 1] & 0xF0) == 0x40 {
                Some(i - 1)
            } else {
                Some(i)
            }
        } else if bytes[i] == 0x25 && bytes[i + 1..i + 5] == [0xFF, 0x00, 0x00, 0x00] {
            if i > 0 && (bytes[i - 1] & 0xF0) == 0x40 {
                Some(i - 1)
            } else {
                Some(i)
            }
        } else {
            None
        };

        if let Some(dec_start) = matched_start {
            if let Some(cl) = analyze_crc32_loop_at(bytes, base_va, dec_start) {
                if seen_heads.insert(cl.loop_head_va) {
                    loops.push(cl);
                }
            }
        }
        i += 1;
    }
    loops
}

#[derive(Debug, Clone)]
struct LoadedDll {
    base: u64,
    size: u64,
    by_name: HashMap<String, u64>,
    by_ord: HashMap<u16, u64>,
    forwarders_by_name: HashMap<String, String>,
    forwarders_by_ord: HashMap<u16, String>,
}

fn map_api_set_to_dll(name_lower: &str) -> &str {
    if name_lower.starts_with("api-ms-win-core-com-") {
        "combase.dll"
    } else if name_lower.starts_with("api-ms-win-crt-") {
        "ucrtbase.dll"
    } else if name_lower.starts_with("api-ms-win-security-") {
        "sechost.dll"
    } else if name_lower.starts_with("api-ms-win-") || name_lower.starts_with("ext-ms-win-") {
        "kernelbase.dll"
    } else {
        name_lower
    }
}

fn read_uc_cstr(uc: &Unicorn<'_, ()>, addr: u64, max_len: usize) -> String {
    if addr < 0x1000 {
        return String::new();
    }
    let mut buf = vec![0u8; max_len];
    if uc.mem_read(addr, &mut buf).is_err() {
        // Fallback byte-by-byte if near page boundary
        buf.clear();
        let mut b = [0u8; 1];
        for i in 0..max_len {
            if uc.mem_read(addr + i as u64, &mut b).is_err() || b[0] == 0 {
                break;
            }
            buf.push(b[0]);
        }
        return String::from_utf8_lossy(&buf).into_owned();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn read_uc_wstr(uc: &Unicorn<'_, ()>, addr: u64, max_chars: usize) -> String {
    if addr < 0x1000 {
        return String::new();
    }
    let mut buf = vec![0u8; max_chars * 2];
    if uc.mem_read(addr, &mut buf).is_err() {
        return String::new();
    }
    let mut u16s = Vec::with_capacity(max_chars);
    for ch in buf.chunks_exact(2) {
        let v = u16::from_le_bytes([ch[0], ch[1]]);
        if v == 0 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

fn read_uc_unicode_string(uc: &Unicorn<'_, ()>, us_ptr: u64) -> String {
    if us_ptr < 0x1000 {
        return String::new();
    }
    let mut hdr = [0u8; 16];
    if uc.mem_read(us_ptr, &mut hdr).is_err() {
        return String::new();
    }
    let byte_len = u16::from_le_bytes([hdr[0], hdr[1]]) as usize;
    let buf_p = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
    if buf_p < 0x1000 || byte_len == 0 {
        return String::new();
    }
    let cap = byte_len.min(512);
    let mut raw = vec![0u8; cap];
    if uc.mem_read(buf_p, &mut raw).is_err() {
        return String::new();
    }
    let u16s: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn parse_and_map_system_dll(
    uc: &mut Unicorn<'_, ()>,
    dll_path: &Path,
    base: u64,
) -> Option<(LoadedDll, HashMap<u32, String>)> {
    let raw = std::fs::read(dll_path).ok()?;
    let (_dos, _pe, opt, secs) = parse_pe_bytes(&raw).ok()?;
    let sz = ((opt.size_of_image as u64 + 0xFFF) & !0xFFF).max(0x1000);
    let mut img = vec![0u8; sz as usize];
    let hdr_len = (opt.size_of_headers as usize).min(raw.len()).min(img.len());
    img[..hdr_len].copy_from_slice(&raw[..hdr_len]);
    for s in &secs {
        if s.size_of_raw_data > 0 && s.pointer_to_raw_data > 0 {
            let r = s.pointer_to_raw_data as usize;
            let n = (s.size_of_raw_data as usize).min(raw.len().saturating_sub(r));
            let va = s.virtual_address as usize;
            if va < img.len() {
                let cp = n.min(img.len() - va);
                img[va..va + cp].copy_from_slice(&raw[r..r + cp]);
            }
        }
    }
    uc.mem_map(base, sz, Prot::ALL).ok()?;
    uc.mem_write(base, &img).ok()?;

    let mut by_name = HashMap::new();
    let mut by_ord = HashMap::new();
    let mut forwarders_by_name = HashMap::new();
    let mut forwarders_by_ord = HashMap::new();
    let mut ssns = HashMap::new();

    if let Some(exp_dir) = opt.data_directory.first() {
        let ed_va = exp_dir.virtual_address as usize;
        let ed_sz = exp_dir.size as usize;
        if ed_va != 0 && ed_va + 40 <= img.len() {
            let ord_base = rd_u32(&img, ed_va + 16).unwrap_or(1) as u16;
            let num_funcs = rd_u32(&img, ed_va + 20).unwrap_or(0) as usize;
            let num_names = rd_u32(&img, ed_va + 24).unwrap_or(0) as usize;
            let aof = rd_u32(&img, ed_va + 28).unwrap_or(0) as usize;
            let aon = rd_u32(&img, ed_va + 32).unwrap_or(0) as usize;
            let aono = rd_u32(&img, ed_va + 36).unwrap_or(0) as usize;

            let mut ord_to_name: HashMap<usize, String> = HashMap::new();
            for i in 0..num_names {
                let Some(nrva) = rd_u32(&img, aon + i * 4).map(|x| x as usize) else {
                    break;
                };
                let Some(idx) = rd_u16(&img, aono + i * 2).map(|x| x as usize) else {
                    break;
                };
                if let Some(name) = read_cstr_at(&img, nrva, 160) {
                    ord_to_name.entry(idx).or_insert(name);
                }
            }

            for idx in 0..num_funcs {
                let Some(frva) = rd_u32(&img, aof + idx * 4).map(|x| x as usize) else {
                    break;
                };
                if frva == 0 {
                    continue;
                }
                let ord = ord_base.wrapping_add(idx as u16);
                let is_fwd = ed_sz > 0 && frva >= ed_va && frva < ed_va.saturating_add(ed_sz);
                if is_fwd {
                    if let Some(fwd) = read_cstr_at(&img, frva, 160) {
                        forwarders_by_ord.insert(ord, fwd.clone());
                        if let Some(nm) = ord_to_name.get(&idx) {
                            forwarders_by_name.insert(nm.clone(), fwd);
                        }
                    }
                } else {
                    let va = base + frva as u64;
                    by_ord.insert(ord, va);
                    if let Some(nm) = ord_to_name.get(&idx) {
                        by_name.insert(nm.clone(), va);
                        if frva + 8 <= img.len() && img[frva..frva + 4] == [0x4C, 0x8B, 0xD1, 0xB8] {
                            if let Some(ssn) = rd_u32(&img, frva + 4) {
                                ssns.insert(ssn, nm.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    Some((
        LoadedDll {
            base,
            size: sz,
            by_name,
            by_ord,
            forwarders_by_name,
            forwarders_by_ord,
        },
        ssns,
    ))
}

fn lookup_seh_target(
    pe: &[u8],
    opt: &OptionalHeader,
    secs: &[Section],
    rip_rva: u32,
) -> Option<u32> {
    let exc = opt.data_directory.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;
    if exc.virtual_address == 0 || exc.size < 12 {
        return None;
    }
    let eoff = rva_to_raw(secs, opt.size_of_headers, exc.virtual_address, pe.len())?;
    let cnt = (exc.size as usize / 12).min(pe.len().saturating_sub(eoff) / 12);

    let mut cur_unwind_rva = None;
    for i in 0..cnt {
        let b = rd_u32(pe, eoff + i * 12)?;
        let e = rd_u32(pe, eoff + i * 12 + 4)?;
        let u = rd_u32(pe, eoff + i * 12 + 8)?;
        if rip_rva >= b && rip_rva < e {
            cur_unwind_rva = Some(u);
            break;
        }
    }

    for _ in 0..8 {
        let u_rva = cur_unwind_rva?;
        let mut off = rva_to_raw(secs, opt.size_of_headers, u_rva, pe.len())?;
        let ver_flags = *pe.get(off)?;
        let flags = ver_flags >> 3;
        let cnt_codes = *pe.get(off + 2)? as usize;
        off += 4 + ((cnt_codes + 1) & !1) * 2;

        if (flags & 0x04) != 0 {
            // UNW_FLAG_CHAININFO: advance unwind chain while keeping original `rip_rva`.
            cur_unwind_rva = rd_u32(pe, off + 8);
            continue;
        }
        if (flags & 0x03) == 0 {
            return None;
        }
        // Skip 4-byte ExceptionHandler RVA -> SCOPE_TABLE
        let _handler_rva = rd_u32(pe, off)?;
        let scope_cnt = rd_u32(pe, off + 4)? as usize;
        let mut best: Option<(u32, u32)> = None;
        for s in 0..scope_cnt.min(128) {
            let entry = off + 8 + s * 16;
            let sb = rd_u32(pe, entry)?;
            let se = rd_u32(pe, entry + 4)?;
            let jt = rd_u32(pe, entry + 12)?;
            if rip_rva >= sb && rip_rva < se && jt != 0 {
                let span = se - sb;
                if best.is_none_or(|(bspan, _)| span < bspan) {
                    best = Some((span, jt));
                }
            }
        }
        return best.map(|(_, jt)| jt);
    }
    None
}

struct LoaderCaptureRun {
    hit_rva: u32,
    pass_in_r8: bool,
    g_loader_data_rva: Option<u32>,
    ld_ptr: u64,
    ld_bytes: Vec<u8>,
    env_val: u32,
    lzma_entry_va: Option<u64>,
}

fn probe_live_cpuid_env(ld_ptr: u64, os_build: u16) -> u32 {
    let Ok(mut uc) = Unicorn::new(Arch::X86, Mode::MODE_64) else {
        return ld_ptr as u32 ^ ((os_build as u32) << 7);
    };
    let code_va = 0x0004_0000u64;
    if uc.mem_map(code_va, 0x1000, Prot::ALL).is_err() {
        return ld_ptr as u32 ^ ((os_build as u32) << 7);
    }
    // mov eax, 1; cpuid; nop
    let _ = uc.mem_write(code_va, &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2, 0x90]);
    let _ = uc.emu_start(code_va, code_va + 7, 100_000, 10);
    let eax = uc.reg_read(RegisterX86::RAX as i32).unwrap_or(0) as u32;
    let ebx = uc.reg_read(RegisterX86::RBX as i32).unwrap_or(0) as u32;
    let cpuid_term = eax
        .wrapping_add(ebx & 0x00FF_FFFF)
        .wrapping_add((os_build as u32) << 7);
    (ld_ptr as u32) ^ cpuid_term
}

const CAPTURE_SYNTH_STUB_BASE: u64 = 0x7FFF_0000_0000;
const CAPTURE_SYNTH_STUB_SIZE: u64 = 0x0001_0000;

struct CaptureState {
    loaded_dlls: HashMap<String, LoadedDll>,
    hook_addrs: HashMap<u64, String>,
    synth_stubs: HashMap<u64, String>,
    next_synth: u64,
    next_dll_slot: u64,
    heap_cur: u64,
    heap_allocs: Vec<(u64, usize)>,
    open_handles: HashSet<u64>,
    file_mapped: bool,
    hit_rva: Option<u32>,
    hit_r8: u64,
    aborted: bool,
    abort_reason: Option<String>,
    lzma_entry_va: Option<u64>,
}

fn load_loader_dll_by_name(
    st: &mut CaptureState,
    uc: &mut Unicorn<'_, ()>,
    sys32: &Path,
    raw_name: &str,
) -> u64 {
    let low = raw_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(raw_name)
        .to_ascii_lowercase();
    let norm = if low.ends_with(".dll") {
        low
    } else {
        format!("{low}.dll")
    };
    let mapped = map_api_set_to_dll(&norm).to_string();
    if let Some(d) = st.loaded_dlls.get(&mapped) {
        return d.base;
    }
    let slot_base = 0x7FF6_0000_0000u64 - st.next_dll_slot * 0x0200_0000;
    st.next_dll_slot += 1;
    if let Some((ld, _)) = parse_and_map_system_dll(uc, &sys32.join(&mapped), slot_base) {
        let b = ld.base;
        st.loaded_dlls.insert(mapped, ld);
        b
    } else {
        let synth_dll = LoadedDll {
            base: slot_base,
            size: 0x1000,
            by_name: HashMap::new(),
            by_ord: HashMap::new(),
            forwarders_by_name: HashMap::new(),
            forwarders_by_ord: HashMap::new(),
        };
        st.loaded_dlls.insert(mapped, synth_dll);
        slot_base
    }
}

fn resolve_loader_export(
    st: &mut CaptureState,
    uc: &mut Unicorn<'_, ()>,
    sys32: &Path,
    base: u64,
    raw_proc: u64,
) -> u64 {
    let dll_key = st
        .loaded_dlls
        .iter()
        .find(|(_, d)| d.base == base)
        .map(|(k, _)| k.clone());
    let is_ord = raw_proc < 0x1_0000;
    let sym_name = if is_ord {
        format!("ord_{raw_proc}")
    } else {
        read_uc_cstr(uc, raw_proc, 128)
    };

    if let Some(dk) = dll_key {
        let mut cur_dk = dk;
        let mut cur_name = if is_ord { None } else { Some(sym_name.clone()) };
        let mut cur_ord = if is_ord { Some(raw_proc as u16) } else { None };
        for _ in 0..5 {
            let Some(dll) = st.loaded_dlls.get(&cur_dk) else {
                break;
            };
            if let Some(ref nm) = cur_name {
                if let Some(&addr) = dll.by_name.get(nm) {
                    return addr;
                }
                if let Some(fwd) = dll.forwarders_by_name.get(nm).cloned() {
                    if let Some((f_dll, f_sym)) = fwd.split_once('.') {
                        let target_dll = map_api_set_to_dll(&format!("{}.dll", f_dll.to_ascii_lowercase())).to_string();
                        if !st.loaded_dlls.contains_key(&target_dll) {
                            let slot_base = 0x7FF6_0000_0000u64 - st.next_dll_slot * 0x0200_0000;
                            st.next_dll_slot += 1;
                            if let Some((ld, _)) = parse_and_map_system_dll(uc, &sys32.join(&target_dll), slot_base) {
                                st.loaded_dlls.insert(target_dll.clone(), ld);
                            }
                        }
                        cur_dk = target_dll;
                        if let Some(ord_str) = f_sym.strip_prefix('#') {
                            cur_ord = ord_str.parse::<u16>().ok();
                            cur_name = None;
                        } else {
                            cur_name = Some(f_sym.to_string());
                            cur_ord = None;
                        }
                        continue;
                    }
                }
            } else if let Some(ord) = cur_ord {
                if let Some(&addr) = dll.by_ord.get(&ord) {
                    return addr;
                }
                if let Some(fwd) = dll.forwarders_by_ord.get(&ord).cloned() {
                    if let Some((f_dll, f_sym)) = fwd.split_once('.') {
                        let target_dll = map_api_set_to_dll(&format!("{}.dll", f_dll.to_ascii_lowercase())).to_string();
                        cur_dk = target_dll;
                        if let Some(ord_str) = f_sym.strip_prefix('#') {
                            cur_ord = ord_str.parse::<u16>().ok();
                            cur_name = None;
                        } else {
                            cur_name = Some(f_sym.to_string());
                            cur_ord = None;
                        }
                        continue;
                    }
                }
            }
            break;
        }
    }

    if let Some((&addr, _)) = st.synth_stubs.iter().find(|(_, n)| *n == &sym_name) {
        return addr;
    }
    let addr = st.next_synth;
    st.next_synth += 8;
    if st.next_synth < CAPTURE_SYNTH_STUB_BASE + CAPTURE_SYNTH_STUB_SIZE {
        st.synth_stubs.insert(addr, sym_name);
        return addr;
    }
    CAPTURE_SYNTH_STUB_BASE
}

fn handle_loader_api(
    uc: &mut Unicorn<'_, ()>,
    st: &Rc<RefCell<CaptureState>>,
    img_base: u64,
    heap_base: u64,
    fn_name: &str,
) {
    let sys32 = Path::new(r"C:\Windows\System32");
    let rcx = uc.reg_read(RegisterX86::RCX as i32).unwrap_or(0);
    let rdx = uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0);
    let r8 = uc.reg_read(RegisterX86::R8 as i32).unwrap_or(0);
    let mut s = st.borrow_mut();
    let ret = match fn_name {
        "RtlAllocateHeap" | "HeapAlloc" => {
            let sz = ((r8 as usize) + 15) & !15;
            let p = s.heap_cur;
            let step = ((sz as u64 + 0xFFF) & !0xFFF).max(0x1000);
            s.heap_cur += step;
            if (0x40..=0x1000).contains(&(r8 as usize)) {
                s.heap_allocs.push((p, r8 as usize));
            }
            if (rdx & 8) != 0 && sz > 0 && sz <= 0x20_0000 {
                let _ = uc.mem_write(p, &vec![0u8; sz]);
            }
            p
        }
        "GetProcessHeap" => heap_base,
        "RtlFreeHeap" | "HeapFree" | "VirtualProtect" | "VirtualFree" => 1,
        "VirtualAlloc" => {
            let sz = (rdx + 0xFFF) & !0xFFF;
            let p = s.heap_cur;
            s.heap_cur += sz.max(0x1000);
            if (0x40..=0x1000).contains(&(rdx as usize)) {
                s.heap_allocs.push((p, rdx as usize));
            }
            p
        }
        "LoadLibraryA" | "LoadLibraryExA" => {
            let nm = read_uc_cstr(uc, rcx, 128);
            load_loader_dll_by_name(&mut s, uc, sys32, &nm)
        }
        "LoadLibraryW" | "LoadLibraryExW" => {
            let nm = read_uc_wstr(uc, rcx, 128);
            load_loader_dll_by_name(&mut s, uc, sys32, &nm)
        }
        "GetModuleHandleA" => {
            if rcx == 0 {
                img_base
            } else {
                let nm = read_uc_cstr(uc, rcx, 128);
                load_loader_dll_by_name(&mut s, uc, sys32, &nm)
            }
        }
        "GetModuleHandleW" => {
            if rcx == 0 {
                img_base
            } else {
                let nm = read_uc_wstr(uc, rcx, 128);
                load_loader_dll_by_name(&mut s, uc, sys32, &nm)
            }
        }
        "GetProcAddress" => resolve_loader_export(&mut s, uc, sys32, rcx, rdx),
        "IsDebuggerPresent" => 0,
        "ExitProcess" => {
            s.aborted = true;
            if s.abort_reason.is_none() {
                s.abort_reason = Some(format!("ExitProcess({rcx:#x}) called by packed loader"));
            }
            let _ = uc.emu_stop();
            0
        }
        _ => 1,
    };
    let _ = uc.reg_write(RegisterX86::RAX as i32, ret);
}

#[allow(clippy::too_many_arguments)]
fn run_packed_loader_capture(
    packed_pe: &[u8],
    packed_opt: &OptionalHeader,
    packed_secs: &[Section],
    streams: &[vmpunpacker::UnpackedStream],
    crc_loops: &[Crc32Loop],
    rt_cands: &[u32],
    oep_rva: u32,
    loader_sec_va: Option<u32>,
    heap_base: u64,
    os_build: u16,
    lzma_hint: Option<u64>,
) -> Result<LoaderCaptureRun, String> {
    let img_base = packed_opt.image_base;
    let map_size = ((packed_opt.size_of_image as u64 + 0xFFF) & !0xFFF).max(0x2000);
    let img_end = (img_base + map_size + 0xFF_FFFF) & !0xFF_FFFF;

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64)
        .map_err(|e| format!("Unicorn init failed: {e:?}"))?;
    uc.mem_map(img_base, map_size, Prot::ALL)
        .map_err(|e| format!("mem_map(img_base={img_base:#x}, {map_size:#x}) failed: {e:?}"))?;

    // Populate initial packed image as OS loader maps it.
    let mut init_img = vec![0u8; map_size as usize];
    let hdr_cp = (packed_opt.size_of_headers as usize)
        .min(packed_pe.len())
        .min(init_img.len());
    init_img[..hdr_cp].copy_from_slice(&packed_pe[..hdr_cp]);
    for s in packed_secs {
        if s.size_of_raw_data > 0 && s.pointer_to_raw_data > 0 {
            let r = s.pointer_to_raw_data as usize;
            let n = (s.size_of_raw_data as usize).min(packed_pe.len().saturating_sub(r));
            let va = s.virtual_address as usize;
            if va < init_img.len() {
                let cp = n.min(init_img.len() - va);
                init_img[va..va + cp].copy_from_slice(&packed_pe[r..r + cp]);
            }
        }
    }
    uc.mem_write(img_base, &init_img)
        .map_err(|e| format!("mem_write(img) failed: {e:?}"))?;

    // Choose low fixed addresses when ImageBase allows it, otherwise place above image.
    let low_free = img_base >= 0x4000_0000;
    let sys_base = if low_free { 0x0002_0000u64 } else { img_end };
    let stack_base = if low_free { 0x0010_0000u64 } else { img_end + 0x0010_0000 };
    let stack_size = 0x0020_0000u64;
    let heap_size = 0x0800_0000u64;
    let file_map_base = if low_free { 0x2000_0000u64 } else { img_end + 0x1000_0000 };
    let ntdll_map_base = if low_free { 0x2800_0000u64 } else { img_end + 0x2000_0000 };

    uc.mem_map(sys_base, 0x3_0000, Prot::ALL)
        .map_err(|e| format!("mem_map(sys_base) failed: {e:?}"))?;
    uc.mem_map(stack_base, stack_size, Prot::ALL)
        .map_err(|e| format!("mem_map(stack) failed: {e:?}"))?;
    uc.mem_map(heap_base, heap_size, Prot::ALL)
        .map_err(|e| format!("mem_map(heap={heap_base:#x}) failed: {e:?}"))?;
    let _ = uc.mem_map(0x7FFE_0000, 0x1000, Prot::READ);

    let teb_addr = sys_base;
    let peb_addr = sys_base + 0x1_0000;
    let ldr_addr = sys_base + 0x1_1000;
    let param_addr = sys_base + 0x1_2000;
    let stop_addr = sys_base + 0x2_0000;
    let _ = uc.mem_write(stop_addr, &[0x90]);

    // Load real C:\Windows\System32 core DLLs + extract ntdll SSNs.
    let sys32 = Path::new(r"C:\Windows\System32");
    let ntdll_raw = std::fs::read(sys32.join("ntdll.dll")).unwrap_or_default();
    const NTDLL_BASE: u64 = 0x7FF9_0000_0000;
    const K32_BASE: u64 = 0x7FF8_0000_0000;
    const KBASE_BASE: u64 = 0x7FF7_0000_0000;

    let (nt_dll, nt_ssns) = parse_and_map_system_dll(&mut uc, &sys32.join("ntdll.dll"), NTDLL_BASE)
        .ok_or_else(|| "failed to load System32 ntdll.dll".to_string())?;
    let (k32_dll, _) = parse_and_map_system_dll(&mut uc, &sys32.join("kernel32.dll"), K32_BASE)
        .ok_or_else(|| "failed to load System32 kernel32.dll".to_string())?;
    let (kb_dll, _) = parse_and_map_system_dll(&mut uc, &sys32.join("kernelbase.dll"), KBASE_BASE)
        .ok_or_else(|| "failed to load System32 kernelbase.dll".to_string())?;

    let mut loaded_dlls: HashMap<String, LoadedDll> = HashMap::new();
    let nt_size = nt_dll.size;
    let k32_size = k32_dll.size;
    let kb_size = kb_dll.size;
    loaded_dlls.insert("ntdll.dll".into(), nt_dll);
    loaded_dlls.insert("kernel32.dll".into(), k32_dll);
    loaded_dlls.insert("kernelbase.dll".into(), kb_dll);

    // Populate TEB / PEB / PEB_LDR_DATA / RTL_USER_PROCESS_PARAMETERS
    let _ = uc.mem_write(teb_addr + 0x08, &(stack_base + stack_size).to_le_bytes());
    let _ = uc.mem_write(teb_addr + 0x10, &stack_base.to_le_bytes());
    let _ = uc.mem_write(teb_addr + 0x30, &teb_addr.to_le_bytes());
    let _ = uc.mem_write(teb_addr + 0x60, &peb_addr.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x10, &img_base.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x18, &ldr_addr.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x20, &param_addr.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x30, &heap_base.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x118, &10u32.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x11C, &0u32.to_le_bytes());
    let _ = uc.mem_write(peb_addr + 0x120, &os_build.to_le_bytes());

    let mut img_path_w: Vec<u8> = "C:\\sample.exe\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let _ = uc.mem_write(param_addr + 0x200, &img_path_w);
    let len_b = (img_path_w.len() - 2) as u16;
    let max_b = img_path_w.len() as u16;
    let _ = uc.mem_write(param_addr + 0x60, &len_b.to_le_bytes());
    let _ = uc.mem_write(param_addr + 0x62, &max_b.to_le_bytes());
    let _ = uc.mem_write(param_addr + 0x68, &(param_addr + 0x200).to_le_bytes());
    let _ = &mut img_path_w;

    let ldr_entries = [
        (sys_base + 0x1_3000, img_base, map_size as u32, "C:\\sample.exe", "sample.exe"),
        (sys_base + 0x1_3200, NTDLL_BASE, nt_size as u32, "C:\\Windows\\System32\\ntdll.dll", "ntdll.dll"),
        (sys_base + 0x1_3400, K32_BASE, k32_size as u32, "C:\\Windows\\System32\\KERNEL32.DLL", "KERNEL32.DLL"),
        (sys_base + 0x1_3600, KBASE_BASE, kb_size as u32, "C:\\Windows\\System32\\KERNELBASE.dll", "KERNELBASE.dll"),
    ];
    for (list_idx, head_off) in [0x10u64, 0x20, 0x30].into_iter().enumerate() {
        let head = ldr_addr + head_off;
        let nodes: Vec<u64> = ldr_entries.iter().map(|e| e.0 + (list_idx as u64) * 0x10).collect();
        let _ = uc.mem_write(head, &nodes[0].to_le_bytes());
        let _ = uc.mem_write(head + 8, &nodes[nodes.len() - 1].to_le_bytes());
        for (idx, &node) in nodes.iter().enumerate() {
            let fl = if idx + 1 < nodes.len() { nodes[idx + 1] } else { head };
            let bl = if idx > 0 { nodes[idx - 1] } else { head };
            let _ = uc.mem_write(node, &fl.to_le_bytes());
            let _ = uc.mem_write(node + 8, &bl.to_le_bytes());
        }
    }
    for &(ea, base, sz, full, base_n) in &ldr_entries {
        let _ = uc.mem_write(ea + 0x30, &base.to_le_bytes());
        let _ = uc.mem_write(ea + 0x40, &sz.to_le_bytes());
        let fw: Vec<u8> = full.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect();
        let bw: Vec<u8> = base_n.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect();
        let _ = uc.mem_write(ea + 0x100, &fw);
        let _ = uc.mem_write(ea + 0x180, &bw);
        let _ = uc.mem_write(ea + 0x48, &((fw.len() - 2) as u16).to_le_bytes());
        let _ = uc.mem_write(ea + 0x4A, &(fw.len() as u16).to_le_bytes());
        let _ = uc.mem_write(ea + 0x50, &(ea + 0x100).to_le_bytes());
        let _ = uc.mem_write(ea + 0x58, &((bw.len() - 2) as u16).to_le_bytes());
        let _ = uc.mem_write(ea + 0x5A, &(bw.len() as u16).to_le_bytes());
        let _ = uc.mem_write(ea + 0x60, &(ea + 0x180).to_le_bytes());
    }

    let _ = uc.reg_write(RegisterX86::GS_BASE as i32, teb_addr);
    let rsp_init = stack_base + stack_size - 0x1000;
    let _ = uc.mem_write(rsp_init, &stop_addr.to_le_bytes());
    let _ = uc.reg_write(RegisterX86::RSP as i32, rsp_init);

    // Map raw ntdll image for self-checksum reads via NtMapViewOfSection
    let nt_raw_sz = ((ntdll_raw.len() as u64 + 0xFFF) & !0xFFF).max(0x1000);
    let _ = uc.mem_map(ntdll_map_base, nt_raw_sz, Prot::ALL);
    if !ntdll_raw.is_empty() {
        let _ = uc.mem_write(ntdll_map_base, &ntdll_raw);
    }

    // Synthetic stub area for forwarded/non-resident exports
    let _ = uc.mem_map(CAPTURE_SYNTH_STUB_BASE, CAPTURE_SYNTH_STUB_SIZE, Prot::ALL);
    let synth_mem = vec![0xC3u8; CAPTURE_SYNTH_STUB_SIZE as usize];
    let _ = uc.mem_write(CAPTURE_SYNTH_STUB_BASE, &synth_mem);

    const HOOKED_EXPORTS: &[&str] = &[
        "RtlAllocateHeap",
        "RtlFreeHeap",
        "HeapAlloc",
        "HeapFree",
        "GetProcessHeap",
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetProcAddress",
        "ExitProcess",
        "IsDebuggerPresent",
    ];

    let mut hook_addrs = HashMap::new();
    for dll in loaded_dlls.values() {
        for &fn_name in HOOKED_EXPORTS {
            if let Some(&addr) = dll.by_name.get(fn_name) {
                let _ = uc.mem_write(addr, &[0xC3]);
                hook_addrs.insert(addr, fn_name.to_string());
            }
        }
    }

    let state = Rc::new(RefCell::new(CaptureState {
        loaded_dlls,
        hook_addrs: hook_addrs.clone(),
        synth_stubs: HashMap::new(),
        next_synth: CAPTURE_SYNTH_STUB_BASE,
        next_dll_slot: 0,
        heap_cur: heap_base + 0x1_0000,
        heap_allocs: Vec::new(),
        open_handles: HashSet::new(),
        file_mapped: false,
        hit_rva: None,
        hit_r8: 0,
        aborted: false,
        abort_reason: None,
        lzma_entry_va: lzma_hint,
    }));

    // 1. CRC32 Loop Fast-Forward Hooks
    for cl in crc_loops.iter().copied() {
        let _ = uc.add_code_hook(cl.loop_head_va, cl.loop_head_va, move |uc, _addr, _sz| {
            let len = uc.reg_read(cl.len_reg as i32).unwrap_or(0);
            if len <= 64 || len >= 0x1000_0000 {
                return;
            }
            let ptr_va = uc.reg_read(cl.ptr_reg as i32).unwrap_or(0);
            let tbl_va = uc.reg_read(cl.tbl_reg as i32).unwrap_or(0);
            if ptr_va < 0x1_0000 || tbl_va < 0x1_0000 {
                return;
            }
            let mut tbl_bytes = [0u8; 1024];
            if uc.mem_read(tbl_va, &mut tbl_bytes).is_err() {
                return;
            }
            let mut tbl = [0u32; 256];
            for (k, ch) in tbl_bytes.chunks_exact(4).enumerate() {
                tbl[k] = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
            }
            // Verify IEEE CRC32 signature under any constant table XOR mask.
            let mask = tbl[0];
            if (tbl[1] ^ mask) != 0x7707_3096
                || (tbl[2] ^ mask) != 0xEE0E_612C
                || (tbl[128] ^ mask) != 0xEDB8_8320
            {
                return;
            }
            let n = (len - 1) as usize;
            let mut buf = vec![0u8; n];
            if uc.mem_read(ptr_va, &mut buf).is_err() {
                return;
            }
            let mut crc = uc.reg_read(cl.crc_reg as i32).unwrap_or(0) as u32;
            for &b in &buf {
                let idx = ((b as u32) ^ crc) as u8 as usize;
                crc = (tbl[idx] ^ (crc >> 8)) ^ cl.crc_xor_imm;
            }
            let _ = uc.reg_write(cl.crc_reg as i32, crc as u64);
            let _ = uc.reg_write(cl.ptr_reg as i32, ptr_va.wrapping_add(n as u64));
            let _ = uc.reg_write(cl.len_reg as i32, 1);
        });
    }

    // Helper: install LZMA fast-forward hook on `entry_va`.
    let stream_map: Rc<HashMap<u64, (u64, Vec<u8>)>> = Rc::new(
        streams
            .iter()
            .map(|s| (img_base + s.src_rva as u64, (img_base + s.dst_rva as u64, s.bytes.clone())))
            .collect(),
    );

    let install_lzma_hook = |uc: &mut Unicorn<'_, ()>, entry_va: u64, smap: Rc<HashMap<u64, (u64, Vec<u8>)>>| {
        let _ = uc.add_code_hook(entry_va, entry_va, move |uc, _addr, _sz| {
            let candidates = [
                uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0),
                uc.reg_read(RegisterX86::R8 as i32).unwrap_or(0),
                uc.reg_read(RegisterX86::R9 as i32).unwrap_or(0),
                uc.reg_read(RegisterX86::RCX as i32).unwrap_or(0),
            ];
            for src in candidates {
                if let Some((dst_va, out_bytes)) = smap.get(&src) {
                    let _ = uc.mem_write(*dst_va, out_bytes);
                    let rsp = uc.reg_read(RegisterX86::RSP as i32).unwrap_or(0);
                    let mut ret_buf = [0u8; 8];
                    if uc.mem_read(rsp, &mut ret_buf).is_ok() {
                        let ret_ip = u64::from_le_bytes(ret_buf);
                        let _ = uc.reg_write(RegisterX86::RAX as i32, 0);
                        let _ = uc.reg_write(RegisterX86::RSP as i32, rsp + 8);
                        let _ = uc.reg_write(RegisterX86::RIP as i32, ret_ip);
                    }
                    return;
                }
            }
        });
    };

    if let Some(entry_va) = lzma_hint {
        if !stream_map.is_empty() {
            install_lzma_hook(&mut uc, entry_va, Rc::clone(&stream_map));
        }
    } else if !stream_map.is_empty() {
        // Dynamically detect LzmaDecode entry point when byte 0 of any compressed stream is read outside CRC loops.
        let packed_rfs: Rc<Vec<(u32, u32)>> = Rc::new(
            packed_opt
                .data_directory
                .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                .and_then(|exc| {
                    if exc.virtual_address == 0 || exc.size < 12 {
                        return None;
                    }
                    let eoff = rva_to_raw(packed_secs, packed_opt.size_of_headers, exc.virtual_address, packed_pe.len())?;
                    let cnt = (exc.size as usize / 12).min(packed_pe.len().saturating_sub(eoff) / 12);
                    let mut v = Vec::with_capacity(cnt);
                    for i in 0..cnt {
                        let b = rd_u32(packed_pe, eoff + i * 12)?;
                        let e = rd_u32(packed_pe, eoff + i * 12 + 4)?;
                        if b != 0 && e > b {
                            v.push((b, e));
                        }
                    }
                    Some(v)
                })
                .unwrap_or_default(),
        );
        let crc_heads: Rc<Vec<u64>> = Rc::new(crc_loops.iter().map(|c| c.loop_head_va).collect());
        let smap_c = Rc::clone(&stream_map);
        let st_c = Rc::clone(&state);

        // Find loader section bounds in image
        let lsec_range = loader_sec_va.and_then(|lva| {
            packed_secs.iter().find(|s| s.virtual_address == lva).map(|s| {
                (img_base + s.virtual_address as u64, img_base + s.virtual_address as u64 + s.virtual_size.max(s.size_of_raw_data) as u64)
            })
        });

        for &src_va in stream_map.keys() {
            let smap_i = Rc::clone(&smap_c);
            let st_i = Rc::clone(&st_c);
            let rfs_i = Rc::clone(&packed_rfs);
            let crc_i = Rc::clone(&crc_heads);
            let _ = uc.add_mem_hook(UcHookType::MEM_READ, src_va, src_va, move |uc, _t, _a, _s, _v| {
                if st_i.borrow().lzma_entry_va.is_some() {
                    return true;
                }
                let rip = uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0);
                // Ignore sequential CRC reads inside loader
                if crc_i.iter().any(|&h| rip >= h && rip < h + 256) {
                    return true;
                }
                let rip_rva = rip.saturating_sub(img_base) as u32;
                let rf_hit = rfs_i
                    .iter()
                    .find(|&&(b, e)| rip_rva >= b && rip_rva < e && (e - b) <= 0x8000)
                    .map(|&(b, e)| (b, e));

                let mut chosen_entry = None;
                // Check stack for a parent RF inside loader_sec with size <= 0x800 (wrapper like LzmaDecode)
                let rsp = uc.reg_read(RegisterX86::RSP as i32).unwrap_or(0);
                let mut stack_buf = [0u8; 0x200];
                if uc.mem_read(rsp, &mut stack_buf).is_ok() {
                    for ch in stack_buf.chunks_exact(8) {
                        let q = u64::from_le_bytes(ch.try_into().unwrap());
                        if let Some((ls, le)) = lsec_range {
                            if q < ls || q >= le {
                                continue;
                            }
                        }
                        let qrva = (q - img_base) as u32;
                        if let Some(&(b, _e)) = rfs_i.iter().find(|&&(b, e)| qrva > b && qrva <= e && (e - b) <= 0x600) {
                            chosen_entry = Some(img_base + b as u64);
                            break;
                        }
                    }
                }
                if chosen_entry.is_none() {
                    if let Some((b, _)) = rf_hit {
                        chosen_entry = Some(img_base + b as u64);
                    }
                }
                if let Some(entry_va) = chosen_entry {
                    st_i.borrow_mut().lzma_entry_va = Some(entry_va);
                    install_lzma_hook(uc, entry_va, Rc::clone(&smap_i));
                }
                true
            });
        }
    }

    // 2. API Hooks on System DLL Stubs + Synthetic Stubs
    for &addr in hook_addrs.keys() {
        let st_i = Rc::clone(&state);
        let _ = uc.add_code_hook(addr, addr, move |uc, a, _sz| {
            let fn_name = st_i.borrow().hook_addrs.get(&a).cloned();
            if let Some(nm) = fn_name {
                handle_loader_api(uc, &st_i, img_base, heap_base, &nm);
            }
        });
    }
    let st_synth = Rc::clone(&state);
    let _ = uc.add_code_hook(
        CAPTURE_SYNTH_STUB_BASE,
        CAPTURE_SYNTH_STUB_BASE + CAPTURE_SYNTH_STUB_SIZE - 1,
        move |uc, a, _sz| {
            let fn_name = st_synth.borrow().synth_stubs.get(&a).cloned();
            if let Some(nm) = fn_name {
                handle_loader_api(uc, &st_synth, img_base, heap_base, &nm);
            }
        },
    );

    // 3. SYSCALL Hook
    let st_sys = Rc::clone(&state);
    let nt_ssns_rc = Rc::new(nt_ssns);
    let packed_file_len = packed_pe.len() as u64;
    let packed_pe_rc = packed_pe.to_vec();
    let ntdll_raw_len = ntdll_raw.len() as u64;
    let _ = uc.add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, move |uc| {
        let ssn = uc.reg_read(RegisterX86::RAX as i32).unwrap_or(0) as u32;
        let fn_name = nt_ssns_rc.get(&ssn).map(String::as_str).unwrap_or("");
        let a1 = uc.reg_read(RegisterX86::R10 as i32).unwrap_or(0);
        let a2 = uc.reg_read(RegisterX86::RDX as i32).unwrap_or(0);
        let a3 = uc.reg_read(RegisterX86::R8 as i32).unwrap_or(0);
        let a4 = uc.reg_read(RegisterX86::R9 as i32).unwrap_or(0);
        let rsp = uc.reg_read(RegisterX86::RSP as i32).unwrap_or(0);

        let mut ret = 0u64;
        if fn_name.contains("OpenSection") {
            ret = 0xC000_0034;
        } else if fn_name.contains("OpenFile") || fn_name.contains("CreateFile") {
            let mut us_ptr_buf = [0u8; 8];
            let name = if uc.mem_read(a3 + 0x10, &mut us_ptr_buf).is_ok() {
                read_uc_unicode_string(uc, u64::from_le_bytes(us_ptr_buf)).to_ascii_lowercase()
            } else {
                String::new()
            };
            if name.contains("ntdll") {
                let h = 0x1234u64;
                st_sys.borrow_mut().open_handles.insert(h);
                let _ = uc.mem_write(a1, &h.to_le_bytes());
            } else if name.contains("sample.exe") {
                let h = 0x1235u64;
                st_sys.borrow_mut().open_handles.insert(h);
                let _ = uc.mem_write(a1, &h.to_le_bytes());
            } else {
                ret = 0xC000_0034;
            }
        } else if fn_name.contains("CreateSection") {
            let mut fh_buf = [0u8; 8];
            let fh = if uc.mem_read(rsp + 0x38, &mut fh_buf).is_ok() {
                u64::from_le_bytes(fh_buf)
            } else {
                0
            };
            let sh = if fh == 0x1234 { 0x9999u64 } else { 0x5678u64 };
            st_sys.borrow_mut().open_handles.insert(sh);
            let _ = uc.mem_write(a1, &sh.to_le_bytes());
        } else if fn_name.contains("MapViewOfSection") {
            let mut vsz_buf = [0u8; 8];
            let vsz_ptr = if uc.mem_read(rsp + 0x38, &mut vsz_buf).is_ok() {
                u64::from_le_bytes(vsz_buf)
            } else {
                0
            };
            if a1 == 0x9999 {
                let _ = uc.mem_write(a3, &ntdll_map_base.to_le_bytes());
                if vsz_ptr != 0 {
                    let _ = uc.mem_write(vsz_ptr, &ntdll_raw_len.to_le_bytes());
                }
            } else {
                let mut s = st_sys.borrow_mut();
                if !s.file_mapped {
                    let fsz = ((packed_file_len + 0xFFF) & !0xFFF).max(0x1000);
                    let _ = uc.mem_map(file_map_base, fsz, Prot::ALL);
                    let _ = uc.mem_write(file_map_base, &packed_pe_rc);
                    s.file_mapped = true;
                }
                drop(s);
                let _ = uc.mem_write(a3, &file_map_base.to_le_bytes());
                if vsz_ptr != 0 {
                    let _ = uc.mem_write(vsz_ptr, &packed_file_len.to_le_bytes());
                }
            }
        } else if fn_name.contains("UnmapViewOfSection") {
            ret = 0;
        } else if fn_name.contains("QueryInformationProcess") {
            let mut rlp_buf = [0u8; 8];
            let ret_len_p = if uc.mem_read(rsp + 0x28, &mut rlp_buf).is_ok() {
                u64::from_le_bytes(rlp_buf)
            } else {
                0
            };
            match a2 {
                0x00 => {
                    if a3 != 0 && a4 >= 0x30 {
                        let pbi = [
                            0u64.to_le_bytes(),
                            peb_addr.to_le_bytes(),
                            0u64.to_le_bytes(),
                            0u64.to_le_bytes(),
                            1234u64.to_le_bytes(),
                            1000u64.to_le_bytes(),
                        ]
                        .concat();
                        let _ = uc.mem_write(a3, &pbi);
                        if ret_len_p != 0 {
                            let _ = uc.mem_write(ret_len_p, &0x30u32.to_le_bytes());
                        }
                    } else {
                        ret = 0xC000_0004;
                    }
                }
                0x07 => {
                    if a4 != 8 {
                        ret = 0xC000_0004;
                    } else {
                        let _ = uc.mem_write(a3, &0u64.to_le_bytes());
                        if ret_len_p != 0 {
                            let _ = uc.mem_write(ret_len_p, &8u32.to_le_bytes());
                        }
                    }
                }
                0x1e => {
                    let mut tmp = [0u8; 4];
                    if ret_len_p != 0 && (ret_len_p < 0x1_0000 || uc.mem_read(ret_len_p, &mut tmp).is_err()) {
                        ret = 0xC000_0005;
                    } else if (a3 & 3) != 0 {
                        ret = 0x8000_0002;
                    } else if a4 != 8 {
                        ret = 0xC000_0004;
                    } else if a3 < 0x1_0000 || uc.mem_write(a3, &0u64.to_le_bytes()).is_err() {
                        ret = 0xC000_0005;
                    } else {
                        if ret_len_p != 0 {
                            let _ = uc.mem_write(ret_len_p, &8u32.to_le_bytes());
                        }
                        ret = 0xC000_0353;
                    }
                }
                0x1f => {
                    if a4 < 4 {
                        ret = 0xC000_0004;
                    } else {
                        let _ = uc.mem_write(a3, &1u32.to_le_bytes());
                        if ret_len_p != 0 {
                            let _ = uc.mem_write(ret_len_p, &4u32.to_le_bytes());
                        }
                    }
                }
                _ => {
                    if a3 != 0 && a4 > 0 && a4 <= 0x1000 {
                        let _ = uc.mem_write(a3, &vec![0u8; a4 as usize]);
                    }
                }
            }
        } else if fn_name.contains("QueryInformationThread") {
            if a2 == 0x11 && a3 != 0 && a4 >= 1 {
                let _ = uc.mem_write(a3, &[1u8]);
            }
        } else if fn_name.contains("QuerySystemInformation") {
            // Syscall ABI: a1(r10)=SystemInformationClass, a2(rdx)=Buffer, a3(r8)=Length, a4(r9)=ReturnLength
            if a1 == 0x23 && a2 != 0 && a3 >= 2 {
                let mut z = vec![0u8; (a3 as usize).min(0x1000)];
                z[0] = 0x00;
                z[1] = 0x01; // KernelDebuggerNotPresent = 1
                let _ = uc.mem_write(a2, &z);
                if a4 != 0 {
                    let _ = uc.mem_write(a4, &2u32.to_le_bytes());
                }
            } else if a2 != 0 && a3 > 0 && a3 <= 0x1000 {
                let _ = uc.mem_write(a2, &vec![0u8; a3 as usize]);
            }
        } else if fn_name.contains("CreateDebugObject") {
            let h = 0x2222u64;
            st_sys.borrow_mut().open_handles.insert(h);
            if a1 != 0 {
                let _ = uc.mem_write(a1, &h.to_le_bytes());
            }
        } else if fn_name.contains("QueryObject") {
            let mut rlp_buf = [0u8; 8];
            let ret_len_p = if uc.mem_read(rsp + 0x28, &mut rlp_buf).is_ok() {
                u64::from_le_bytes(rlp_buf)
            } else {
                0
            };
            if a2 == 2 {
                if a3 == 0 || a4 < 0x100 {
                    if ret_len_p != 0 {
                        let _ = uc.mem_write(ret_len_p, &0x100u32.to_le_bytes());
                    }
                    ret = 0xC000_0004;
                } else {
                    let mut buf = vec![0u8; (a4 as usize).min(0x1000)];
                    let type_w: Vec<u8> = "DebugObject".encode_utf16().flat_map(u16::to_le_bytes).collect();
                    let tlen = type_w.len() as u16;
                    let tmax = (type_w.len() + 2) as u16;
                    buf[0..2].copy_from_slice(&tlen.to_le_bytes());
                    buf[2..4].copy_from_slice(&tmax.to_le_bytes());
                    buf[8..16].copy_from_slice(&(a3 + 0x80).to_le_bytes());
                    buf[0x10..0x14].copy_from_slice(&1u32.to_le_bytes()); // TotalNumberOfObjects
                    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // TotalNumberOfHandles
                    buf[0x80..0x80 + type_w.len()].copy_from_slice(&type_w);
                    let _ = uc.mem_write(a3, &buf);
                    if ret_len_p != 0 {
                        let _ = uc.mem_write(ret_len_p, &0x100u32.to_le_bytes());
                    }
                }
            } else if a3 != 0 && a4 > 0 && a4 <= 0x1000 {
                let _ = uc.mem_write(a3, &vec![0u8; a4 as usize]);
            }
        } else if fn_name == "NtClose" || fn_name == "ZwClose" {
            if !st_sys.borrow_mut().open_handles.remove(&a1) {
                ret = 0xC000_0008; // STATUS_INVALID_HANDLE
            }
        } else if fn_name.contains("AllocateVirtualMemory") {
            let mut sz_b = [0u8; 8];
            let mut bp_b = [0u8; 8];
            if uc.mem_read(a4, &mut sz_b).is_ok() && uc.mem_read(a2, &mut bp_b).is_ok() {
                let sz = (u64::from_le_bytes(sz_b) + 0xFFF) & !0xFFF;
                let mut bp = u64::from_le_bytes(bp_b);
                if bp == 0 {
                    let mut s = st_sys.borrow_mut();
                    bp = s.heap_cur;
                    s.heap_cur += sz.max(0x1000);
                    if (0x40..=0x1000).contains(&(u64::from_le_bytes(sz_b) as usize)) {
                        s.heap_allocs.push((bp, u64::from_le_bytes(sz_b) as usize));
                    }
                }
                let _ = uc.mem_write(a2, &bp.to_le_bytes());
                let _ = uc.mem_write(a4, &sz.to_le_bytes());
            }
        } else if fn_name.contains("QueryVirtualMemory") {
            let mut mbi = [0u8; 48];
            let page = a2 & !0xFFF;
            mbi[0..8].copy_from_slice(&page.to_le_bytes());
            mbi[8..16].copy_from_slice(&img_base.to_le_bytes());
            mbi[16..20].copy_from_slice(&0x40u32.to_le_bytes());
            mbi[24..32].copy_from_slice(&map_size.to_le_bytes());
            mbi[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // MEM_COMMIT
            mbi[36..40].copy_from_slice(&0x40u32.to_le_bytes());   // PAGE_EXECUTE_READWRITE
            mbi[40..44].copy_from_slice(&0x0100_0000u32.to_le_bytes()); // MEM_IMAGE
            let _ = uc.mem_write(a4, &mbi);
        } else if fn_name.contains("RaiseHardError") || fn_name.contains("TerminateProcess") {
            let rip = uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0);
            let mut s = st_sys.borrow_mut();
            s.aborted = true;
            if s.abort_reason.is_none() {
                s.abort_reason = Some(format!("{fn_name}(status={a1:#x}) at rip={rip:#x}"));
            }
            let _ = uc.emu_stop();
        }
        let _ = uc.reg_write(RegisterX86::RAX as i32, ret);
    });

    // 4. INTR #1 SEH Handler (`popf` with TF=1 anti-debug tricks)
    let packed_pe_seh = packed_pe.to_vec();
    let packed_opt_seh = packed_opt.clone();
    let packed_secs_seh = packed_secs.to_vec();
    let st_intr = Rc::clone(&state);
    let _ = uc.add_intr_hook(move |uc, intno| {
        let rip = uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0);
        if intno == 1 {
            let eflags = uc.reg_read(RegisterX86::EFLAGS as i32).unwrap_or(0);
            let _ = uc.reg_write(RegisterX86::EFLAGS as i32, eflags & !0x100);
            if rip >= img_base {
                let rip_rva = (rip - img_base) as u32;
                if let Some(target_rva) = lookup_seh_target(&packed_pe_seh, &packed_opt_seh, &packed_secs_seh, rip_rva) {
                    let _ = uc.reg_write(RegisterX86::RIP as i32, img_base + target_rva as u64);
                    return;
                }
            }
        }
        let mut s = st_intr.borrow_mut();
        s.aborted = true;
        if s.abort_reason.is_none() {
            s.abort_reason = Some(format!("unhandled INTR #{intno} at rip={rip:#x}"));
        }
        let _ = uc.emu_stop();
    });

    // 5. Stop hooks on VMProtectRuntime candidates and OEP
    let mut stop_rvas: Vec<u32> = rt_cands.to_vec();
    if !stop_rvas.contains(&oep_rva) {
        stop_rvas.push(oep_rva);
    }
    for rva in stop_rvas {
        let va = img_base + rva as u64;
        let st_hit = Rc::clone(&state);
        let _ = uc.add_code_hook(va, va, move |uc, addr, _sz| {
            let mut s = st_hit.borrow_mut();
            if s.hit_rva.is_none() {
                s.hit_rva = Some((addr - img_base) as u32);
                s.hit_r8 = uc.reg_read(RegisterX86::R8 as i32).unwrap_or(0);
                let _ = uc.emu_stop();
            }
        });
    }

    // Abort cleanly on unmapped memory fault
    let st_unm = Rc::clone(&state);
    let _ = uc.add_mem_hook(
        UcHookType::MEM_READ_UNMAPPED | UcHookType::MEM_WRITE_UNMAPPED | UcHookType::MEM_FETCH_UNMAPPED,
        1,
        0,
        move |uc, t, addr, sz, _v| {
            let rip = uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0);
            let mut s = st_unm.borrow_mut();
            s.aborted = true;
            if s.abort_reason.is_none() {
                s.abort_reason = Some(format!("unmapped mem ({t:?}) addr={addr:#x} sz={sz} at rip={rip:#x}"));
            }
            false
        },
    );

    let ep_va = img_base + packed_opt.address_of_entry_point as u64;
    let emu_res = uc.emu_start(ep_va, stop_addr, 240_000_000, 0);

    let s = state.borrow();
    if s.aborted {
        return Err(s
            .abort_reason
            .clone()
            .unwrap_or_else(|| format!("packed loader aborted: {emu_res:?}")));
    }
    let Some(hit_rva) = s.hit_rva else {
        let rip = uc.reg_read(RegisterX86::RIP as i32).unwrap_or(0);
        return Err(format!(
            "packed loader stopped without reaching runtime/OEP (rip={rip:#x}, emu_res={emu_res:?})"
        ));
    };
    let hit_r8 = s.hit_r8;
    let lzma_found = s.lzma_entry_va;

    // Locate LoaderData structure either in R8 (VMP 3.5) or global pointer in non-loader sections (VMP 3.8+).
    let alloc_map: HashMap<u64, usize> = s.heap_allocs.iter().copied().collect();
    let mut pass_in_r8 = false;
    let mut g_loader_data_rva = None;
    let mut ld_ptr = 0u64;
    let mut ld_sz = 0usize;

    if hit_r8 != 0 {
        if let Some(&sz) = alloc_map.get(&hit_r8) {
            pass_in_r8 = true;
            ld_ptr = hit_r8;
            ld_sz = sz;
        } else if hit_r8 >= stack_base && hit_r8 < stack_base + stack_size {
            pass_in_r8 = true;
            ld_ptr = hit_r8;
            ld_sz = ((stack_base + stack_size - hit_r8) as usize).min(0x200);
        }
    }

    if ld_ptr == 0 && !alloc_map.is_empty() {
        // Scan all non-loader sections of the unpacked image for an 8-byte aligned pointer to any tracked heap alloc.
        // Prefer candidate with richest non-zero LoaderData content (`>= 0x100` bytes / most non-zero dwords).
        let mut scan_secs: Vec<&Section> = packed_secs
            .iter()
            .filter(|sec| Some(sec.virtual_address) != loader_sec_va && sec.virtual_size.max(sec.size_of_raw_data) >= 8)
            .collect();
        scan_secs.sort_by_key(|sec| ((sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) as u8);

        let mut best_score = 0usize;
        for sec in scan_secs {
            let va_start = sec.virtual_address as usize;
            let va_len = sec.virtual_size.max(sec.size_of_raw_data) as usize;
            let mut off = 0usize;
            let mut chunk = vec![0u8; 0x10_0000usize.min(va_len)];
            while off + 8 <= va_len {
                let to_read = (va_len - off).min(chunk.len());
                if uc.mem_read(img_base + (va_start + off) as u64, &mut chunk[..to_read]).is_ok() {
                    for qoff in (0..=to_read.saturating_sub(8)).step_by(8) {
                        let q = u64::from_le_bytes(chunk[qoff..qoff + 8].try_into().unwrap());
                        if let Some(&sz) = alloc_map.get(&q) {
                            let mut probe = vec![0u8; sz];
                            if uc.mem_read(q, &mut probe).is_ok() {
                                let nz_dwords = probe
                                    .chunks_exact(4)
                                    .filter(|c| *c != [0, 0, 0, 0])
                                    .count();
                                let score = nz_dwords * 1000 + sz + usize::from(sz >= 0x100) * 10000;
                                if score > best_score {
                                    best_score = score;
                                    ld_ptr = q;
                                    ld_sz = sz;
                                    g_loader_data_rva = Some((va_start + off + qoff) as u32);
                                }
                            }
                        }
                    }
                }
                off += to_read;
            }
        }
    }

    if ld_ptr == 0 || ld_sz == 0 {
        return Err(format!(
            "hit {hit_rva:#x} (r8={hit_r8:#x}), but no populated LoaderData heap buffer found among {} tracked allocs",
            alloc_map.len()
        ));
    }
    let mut ld_bytes = vec![0u8; ld_sz];
    uc.mem_read(ld_ptr, &mut ld_bytes)
        .map_err(|e| format!("failed reading LoaderData @ {ld_ptr:#x}: {e:?}"))?;
    let env_val = probe_live_cpuid_env(ld_ptr, os_build);

    Ok(LoaderCaptureRun {
        hit_rva,
        pass_in_r8,
        g_loader_data_rva,
        ld_ptr,
        ld_bytes,
        env_val,
        lzma_entry_va: lzma_found,
    })
}

/// Generically captures a complete `LoaderDataPlan` across VMP 3.x / 3.8+ by executing
/// the original packed loader twice inside Unicorn under different heap addresses and
/// `OSBuildNumber` values, then diffing environment-bound fields.
fn capture_loader_data_via_packed_loader(
    packed_pe: &[u8],
    rt_cands: &[u32],
    oep_rva: u32,
    loader_sec_va: Option<u32>,
    warnings: &mut Vec<String>,
) -> Option<(Option<u32>, LoaderDataPlan)> {
    let (_dos, pe_hdr, packed_opt, packed_secs) = parse_pe_bytes(packed_pe).ok()?;
    if pe_hdr.machine != 0x8664 && packed_opt.magic != 0x20B {
        return None;
    }
    let streams = vmpunpacker::unpack_streams(packed_pe).ok().unwrap_or_default();
    let img_base = packed_opt.image_base;
    let map_size = ((packed_opt.size_of_image as u64 + 0xFFF) & !0xFFF).max(0x2000);
    let img_end = (img_base + map_size + 0xFF_FFFF) & !0xFF_FFFF;
    let (heap1, heap2) = if img_base >= 0x4000_0000 {
        (0x0100_0000u64, 0x0140_0000u64)
    } else {
        (img_end + 0x0100_0000, img_end + 0x0140_0000)
    };

    let crc_loops = loader_sec_va
        .and_then(|lva| packed_secs.iter().find(|s| s.virtual_address == lva))
        .map(|lsec| {
            let r = lsec.pointer_to_raw_data as usize;
            let len = (lsec.size_of_raw_data as usize).min(packed_pe.len().saturating_sub(r));
            if len > 0 {
                find_crc32_loops(&packed_pe[r..r + len], img_base + lsec.virtual_address as u64)
            } else {
                Vec::new()
            }
        })
        .unwrap_or_default();

    let run1 = match run_packed_loader_capture(
        packed_pe,
        &packed_opt,
        &packed_secs,
        &streams,
        &crc_loops,
        rt_cands,
        oep_rva,
        loader_sec_va,
        heap1,
        26100,
        None,
    ) {
        Ok(r) => r,
        Err(msg) => {
            warnings.push(format!("packed-loader capture run 1: {msg}"));
            return None;
        }
    };

    let run2 = run_packed_loader_capture(
        packed_pe,
        &packed_opt,
        &packed_secs,
        &streams,
        &crc_loops,
        rt_cands,
        oep_rva,
        loader_sec_va,
        heap2,
        19045,
        run1.lzma_entry_va,
    )
    .ok();

    let mut template = run1.ld_bytes.clone();
    let mut env_xor_patches = Vec::new();
    let mut ld_ptr_xor_patches = Vec::new();
    let mut ld_rel_qwords = Vec::new();

    if let Some(ref r2) = run2 {
        let len = run1.ld_bytes.len().min(r2.ld_bytes.len());
        let mut off = 0usize;
        while off + 4 <= len {
            let v1 = u32::from_le_bytes(run1.ld_bytes[off..off + 4].try_into().unwrap());
            let v2 = u32::from_le_bytes(r2.ld_bytes[off..off + 4].try_into().unwrap());
            if v1 != v2 {
                if (v1 ^ run1.env_val) == (v2 ^ r2.env_val) {
                    env_xor_patches.push(LoaderDataEnvPatch {
                        offset: off,
                        base_const: v1 ^ run1.env_val,
                    });
                    template[off..off + 4].fill(0);
                } else if (v1 ^ (run1.ld_ptr as u32)) == (v2 ^ (r2.ld_ptr as u32)) {
                    ld_ptr_xor_patches.push(LoaderDataEnvPatch {
                        offset: off,
                        base_const: v1 ^ (run1.ld_ptr as u32),
                    });
                    template[off..off + 4].fill(0);
                } else if (off % 8) == 0 && off + 8 <= len {
                    let q1 = u64::from_le_bytes(run1.ld_bytes[off..off + 8].try_into().unwrap());
                    let q2 = u64::from_le_bytes(r2.ld_bytes[off..off + 8].try_into().unwrap());
                    if q1.wrapping_sub(run1.ld_ptr) == q2.wrapping_sub(r2.ld_ptr) {
                        ld_rel_qwords.push((off, q1.wrapping_sub(run1.ld_ptr) as i64));
                        template[off..off + 8].fill(0);
                        off += 8;
                        continue;
                    }
                }
            }
            off += 4;
        }
    }

    let runtime_entry_rva = (run1.hit_rva != oep_rva).then_some(run1.hit_rva);
    Some((
        runtime_entry_rva,
        LoaderDataPlan {
            mode: "packed-loader-diff".to_string(),
            template,
            pass_in_r8: run1.pass_in_r8,
            g_loader_data_rva: run1.g_loader_data_rva,
            env_xor_patches,
            ld_ptr_xor_patches,
            ld_rel_qwords,
            image_rel_qwords: Vec::new(),
        },
    ))
}

/// Populates synthetic Windows x64 process environment and probes `VMProtectRuntime`
/// inside Unicorn to extract a verified `LoaderDataPlan` (VMP 3.5 fallback).
fn probe_loader_data(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    fixups: &[ImportFixup],
    rt_cands: &[u32],
    oep_rva: Option<u32>,
) -> Option<(Option<u32>, Option<LoaderDataPlan>)> {
    if rt_cands.is_empty() && oep_rva.is_none() {
        return None;
    }

    const STACK_BASE: u64 = 0x0010_0000;
    const STACK_SIZE: u64 = 0x0010_0000;
    const TEB_ADDR: u64 = 0x0002_0000;
    const PEB_ADDR: u64 = 0x0002_2000;
    const HEAP_BASE: u64 = 0x0080_0000;
    const HEAP_SIZE: u64 = 0x0040_0000;
    const STOP_ADDR: u64 = 0x0004_0000;
    const STUB_BASE: u64 = 0x7FFF_0000_0000;
    const STUB_SIZE: u64 = 0x0001_0000;

    let img_base = opt.image_base;
    let map_size = ((opt.size_of_image as u64 + 0xFFF) & !0xFFF).max(0x2000);

    for &rt_rva in rt_cands {
        if let Some(plan) = probe_vmp35_single(
            pe, opt, sections, fixups, rt_rva, img_base, map_size, STACK_BASE, STACK_SIZE,
            TEB_ADDR, PEB_ADDR, HEAP_BASE, HEAP_SIZE, STOP_ADDR, STUB_BASE, STUB_SIZE,
        ) {
            return Some((Some(rt_rva), Some(plan)));
        }
    }

    // Tier1 candidates are emitted as [wrapper, DllMainCRTStartup] pairs; the real
    // VMProtect init is the wrapper (it tail-calls into the VM to build the context),
    // not the CRT DllMain. When every probe fails, fall back to the first candidate
    // (the wrapper) rather than the last (DllMain).
    if let Some(&native_rt) = rt_cands.first() {
        return Some((Some(native_rt), None));
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn probe_vmp35_single(
    pe: &[u8],
    opt: &OptionalHeader,
    sections: &[Section],
    fixups: &[ImportFixup],
    rt_rva: u32,
    img_base: u64,
    map_size: u64,
    stack_base: u64,
    stack_size: u64,
    teb_addr: u64,
    peb_addr: u64,
    heap_base: u64,
    heap_size: u64,
    stop_addr: u64,
    stub_base: u64,
    stub_size: u64,
) -> Option<LoaderDataPlan> {
    let run_probe = |ld_ptr: u64, os_build: u16, seed_bytes: &[u8]| -> (bool, Vec<(usize, u32)>, u64) {
        let Ok(mut uc) = Unicorn::new(Arch::X86, Mode::MODE_64) else {
            return (false, Vec::new(), 0);
        };
        if uc.mem_map(img_base, map_size, Prot::ALL).is_err() {
            return (false, Vec::new(), 0);
        }
        let copy_len = pe.len().min(map_size as usize);
        let _ = uc.mem_write(img_base, &pe[..copy_len]);
        for s in sections {
            if s.pointer_to_raw_data > 0 && s.size_of_raw_data > 0 {
                let r = s.pointer_to_raw_data as usize;
                let sz = (s.size_of_raw_data as usize).min(pe.len().saturating_sub(r));
                let dst = img_base + s.virtual_address as u64;
                if r != s.virtual_address as usize && (s.virtual_address as usize + sz) <= map_size as usize {
                    let _ = uc.mem_write(dst, &pe[r..r + sz]);
                }
            }
        }
        let _ = uc.mem_map(stub_base, stub_size, Prot::ALL);
        let stubs_mem = vec![0xC3u8; stub_size as usize];
        let _ = uc.mem_write(stub_base, &stubs_mem);
        for (i, fx) in fixups.iter().enumerate() {
            let api_va = stub_base + ((i * 8) as u64 % (stub_size - 8));
            let _ = uc.mem_write(img_base + fx.iat_slot_rva as u64, &api_va.to_le_bytes());
            let encoded = api_va.wrapping_sub(fx.key_i32 as i64 as u64);
            let _ = uc.mem_write(img_base + fx.dst_slot_rva as u64, &encoded.to_le_bytes());
        }

        let _ = uc.mem_map(stack_base, stack_size, Prot::ALL);
        let _ = uc.mem_map(teb_addr & !0xFFF, 0x4000, Prot::ALL);
        let _ = uc.mem_map(heap_base, heap_size, Prot::ALL);
        let _ = uc.mem_map(stop_addr, 0x1000, Prot::ALL);
        let _ = uc.mem_write(stop_addr, &[0x90]);

        let _ = uc.mem_write(teb_addr + 0x08, &(stack_base + stack_size).to_le_bytes());
        let _ = uc.mem_write(teb_addr + 0x10, &stack_base.to_le_bytes());
        let _ = uc.mem_write(teb_addr + 0x30, &teb_addr.to_le_bytes());
        let _ = uc.mem_write(teb_addr + 0x60, &peb_addr.to_le_bytes());
        let _ = uc.mem_write(peb_addr + 0x10, &img_base.to_le_bytes());
        let _ = uc.mem_write(peb_addr + 0x30, &heap_base.to_le_bytes());
        let _ = uc.mem_write(peb_addr + 0x118, &10u32.to_le_bytes());
        let _ = uc.mem_write(peb_addr + 0x11C, &0u32.to_le_bytes());
        let _ = uc.mem_write(peb_addr + 0x120, &os_build.to_le_bytes());
        let _ = uc.reg_write(RegisterX86::GS_BASE as i32, teb_addr);

        let _ = uc.mem_write(ld_ptr, seed_bytes);

        let rsp = stack_base + stack_size - 0x1000;
        let _ = uc.mem_write(rsp, &stop_addr.to_le_bytes());
        let _ = uc.reg_write(RegisterX86::RSP as i32, rsp);
        let _ = uc.reg_write(RegisterX86::RCX as i32, img_base);
        let _ = uc.reg_write(RegisterX86::RDX as i32, 1);
        let _ = uc.reg_write(RegisterX86::R8 as i32, ld_ptr);

        let reads = Rc::new(RefCell::new(Vec::<(usize, u32)>::new()));
        let faulted = Rc::new(RefCell::new(false));
        let heap_cur = Rc::new(RefCell::new(heap_base + 0x10000));

        let reads_c = Rc::clone(&reads);
        let _ = uc.add_mem_hook(
            UcHookType::MEM_READ,
            ld_ptr,
            ld_ptr + seed_bytes.len() as u64 - 1,
            move |_uc, _t, addr, _size, _v| {
                let off = (addr - ld_ptr) as usize;
                reads_c.borrow_mut().push((off, 0));
                true
            },
        );
        let fault_c = Rc::clone(&faulted);
        let _ = uc.add_mem_hook(
            UcHookType::MEM_READ_UNMAPPED | UcHookType::MEM_WRITE_UNMAPPED | UcHookType::MEM_FETCH_UNMAPPED,
            1,
            0,
            move |_uc, _t, _a, _s, _v| {
                *fault_c.borrow_mut() = true;
                false
            },
        );
        let hc_c = Rc::clone(&heap_cur);
        let _ = uc.add_code_hook(stub_base, stub_base + stub_size - 1, move |uc, _addr, _sz| {
            let mut cur = hc_c.borrow_mut();
            let ret = *cur;
            *cur += 0x1000;
            let _ = uc.reg_write(RegisterX86::RAX as i32, ret.max(1));
        });

        let ok = uc.emu_start(img_base + rt_rva as u64, stop_addr, 2_000_000, 100_000).is_ok()
            && !*faulted.borrow();
        let rax = uc.reg_read(RegisterX86::RAX as i32).unwrap_or(0);
        let r = reads.borrow().clone();
        (ok, r, rax)
    };

    let template = vec![0u8; 0x200];
    let (ok, reads, rax) = run_probe(heap_base + 0x2000, 26100, &template);
    if ok && rax != 0 && reads.is_empty() {
        return Some(LoaderDataPlan {
            mode: "none".to_string(),
            template,
            pass_in_r8: true,
            g_loader_data_rva: None,
            env_xor_patches: Vec::new(),
            ld_ptr_xor_patches: Vec::new(),
            ld_rel_qwords: Vec::new(),
            image_rel_qwords: Vec::new(),
        });
    }
    let _ = opt;
    None
}

/// Assembles `.vmpinit`, appends it as an RWX (`0xE000_0060`) section, disables ASLR,
/// sets `AddressOfEntryPoint` to `.vmpinit`, and recomputes the PE checksum.
fn emit_vmpinit_section(
    pe: &mut Vec<u8>,
    image_base: u64,
    fixups: &[ImportFixup],
    runtime_entry_rva: Option<u32>,
    ld_plan: Option<&LoaderDataPlan>,
    oep_rva: u32,
    detect_overrides: &[(u32, i32, bool)],
) -> UnpackerResult<u32> {
    let (vmpinit_rva, _) = imagedump::next_section_rva(pe)?;
    let vmpinit_va = image_base + vmpinit_rva as u64;

    let mut a = CodeAssembler::new(64)
        .map_err(|e| UnpackerError::General(format!("CodeAssembler(64): {e}")))?;
    let mut lbl_fixup_loop = a.create_label();
    let mut lbl_fixup_table = a.create_label();
    let mut lbl_loader_data = a.create_label();
    let mut lbl_stub_invalid = a.create_label();
    let mut lbl_stub_zero = a.create_label();

    // Entry: RSP % 16 == 8. Push 3 callee-saved regs + sub 0x20 shadow -> RSP % 16 == 0!
    {
        use gpr32::*;
        use gpr64::*;
        a.push(rbx).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.push(rsi).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.push(rdi).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.sub(rsp, 0x20).map_err(|e| UnpackerError::General(e.to_string()))?;

        a.mov(r11, image_base).map_err(|e| UnpackerError::General(e.to_string()))?;

        // 1. Resolve encrypted/keyed import slots from rebuilt `.import` IAT.
        if !fixups.is_empty() {
            a.lea(rsi, qword_ptr(lbl_fixup_table))
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.mov(ecx, fixups.len() as u32)
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.set_label(&mut lbl_fixup_loop)
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.mov(eax, dword_ptr(rsi))
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.mov(rax, qword_ptr(r11 + rax))
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            // CRITICAL: key is a SIGNED 32-bit value sign-extended to 64-bit!
            a.movsxd(rdx, dword_ptr(rsi + 8))
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.sub(rax, rdx)
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.mov(edx, dword_ptr(rsi + 4))
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.mov(qword_ptr(r11 + rdx), rax)
                .map_err(|e| UnpackerError::General(e.to_string()))?;
            a.add(rsi, 12).map_err(|e| UnpackerError::General(e.to_string()))?;
            a.dec(ecx).map_err(|e| UnpackerError::General(e.to_string()))?;
            a.jnz(lbl_fixup_loop)
                .map_err(|e| UnpackerError::General(e.to_string()))?;
        }

        // 1b. Generic anti-tamper neutralization: after the real imports are resolved,
        // repoint the detection APIs' protected slots at no-op stubs so the sample's own
        // process/window/debugger enumeration finds nothing. `true` -> return
        // INVALID_HANDLE_VALUE (-1), so e.g. CreateToolhelp32Snapshot yields an empty
        // snapshot; `false` -> return 0 (FindWindow / IsDebuggerPresent report "none").
        // The VM reads `[slot]` and adds the (sign-extended) key before calling, so the
        // slot must hold `stub_va - key` for the add to land on the stub.
        for &(dst_rva, key, ret_invalid) in detect_overrides {
            if ret_invalid {
                a.lea(rcx, qword_ptr(lbl_stub_invalid))
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
            } else {
                a.lea(rcx, qword_ptr(lbl_stub_zero))
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
            }
            if key != 0 {
                a.sub(rcx, key).map_err(|e| UnpackerError::General(e.to_string()))?;
            }
            a.mov(qword_ptr(r11 + dst_rva as i64), rcx)
                .map_err(|e| UnpackerError::General(e.to_string()))?;
        }

        // 2. Populate inline LoaderData using live CPUID leaf 1 + PEB.OSBuildNumber + LD ptr.
        a.lea(rdi, qword_ptr(lbl_loader_data))
            .map_err(|e| UnpackerError::General(e.to_string()))?;

        if let Some(plan) = ld_plan {
            if !plan.env_xor_patches.is_empty() {
                a.mov(eax, 1).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.cpuid().map_err(|e| UnpackerError::General(e.to_string()))?;
                a.and(ebx, 0x00FF_FFFF).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.add(eax, ebx).map_err(|e| UnpackerError::General(e.to_string()))?;
                // mov rdx, qword ptr gs:[0x60]  -> 65 48 8B 14 25 60 00 00 00
                a.db(&[0x65, 0x48, 0x8B, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00])
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
                a.movzx(edx, word_ptr(rdx + 0x120))
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
                a.shl(edx, 7).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.add(eax, edx).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.xor(eax, edi).map_err(|e| UnpackerError::General(e.to_string()))?;

                for patch in &plan.env_xor_patches {
                    a.mov(ecx, patch.base_const)
                        .map_err(|e| UnpackerError::General(e.to_string()))?;
                    a.xor(ecx, eax)
                        .map_err(|e| UnpackerError::General(e.to_string()))?;
                    a.mov(dword_ptr(rdi + patch.offset as i32), ecx)
                        .map_err(|e| UnpackerError::General(e.to_string()))?;
                }
            }
            for patch in &plan.ld_ptr_xor_patches {
                a.mov(ecx, patch.base_const)
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
                a.xor(ecx, edi)
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
                a.mov(dword_ptr(rdi + patch.offset as i32), ecx)
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
            }
            for &(off, rel) in &plan.ld_rel_qwords {
                a.mov(rcx, rel).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.add(rcx, rdi).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.mov(qword_ptr(rdi + off as i32), rcx)
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
            }
            for &(off, rel) in &plan.image_rel_qwords {
                a.mov(rcx, rel).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.add(rcx, r11).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.mov(qword_ptr(rdi + off as i32), rcx)
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
            }
            if let Some(g_rva) = plan.g_loader_data_rva {
                a.mov(eax, g_rva).map_err(|e| UnpackerError::General(e.to_string()))?;
                a.mov(qword_ptr(r11 + rax), rdi)
                    .map_err(|e| UnpackerError::General(e.to_string()))?;
            }
        }

        // 3. Call VMProtectRuntime(ImageBase, DLL_PROCESS_ATTACH=1, lpvReserved).
        if let Some(rt_rva) = runtime_entry_rva {
            a.mov(rcx, r11).map_err(|e| UnpackerError::General(e.to_string()))?;
            a.mov(edx, 1).map_err(|e| UnpackerError::General(e.to_string()))?;
            if ld_plan.is_some_and(|p| p.pass_in_r8) {
                a.mov(r8, rdi).map_err(|e| UnpackerError::General(e.to_string()))?;
            } else {
                a.xor(r8d, r8d).map_err(|e| UnpackerError::General(e.to_string()))?;
            }
            a.mov(eax, rt_rva).map_err(|e| UnpackerError::General(e.to_string()))?;
            a.add(rax, r11).map_err(|e| UnpackerError::General(e.to_string()))?;
            a.call(rax).map_err(|e| UnpackerError::General(e.to_string()))?;
            // Reload R11 = ImageBase in case runtime clobbered volatile R11.
            a.mov(r11, image_base).map_err(|e| UnpackerError::General(e.to_string()))?;
        }

        // 4. Restore callee-saved registers & exact stack alignment, then tail-jump to OEP.
        a.add(rsp, 0x20).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.pop(rdi).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.pop(rsi).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.pop(rbx).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.mov(eax, oep_rva).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.add(rax, r11).map_err(|e| UnpackerError::General(e.to_string()))?;
        a.jmp(rax).map_err(|e| UnpackerError::General(e.to_string()))?;

        // 5. Data tables appended after tail-jump.
        a.set_label(&mut lbl_fixup_table)
            .map_err(|e| UnpackerError::General(e.to_string()))?;
        let mut table_bytes = Vec::with_capacity(fixups.len() * 12 + 16);
        for fx in fixups {
            table_bytes.extend_from_slice(&fx.iat_slot_rva.to_le_bytes());
            table_bytes.extend_from_slice(&fx.dst_slot_rva.to_le_bytes());
            table_bytes.extend_from_slice(&(fx.key_i32 as u32).to_le_bytes());
        }
        // Keep trailing zero bytes so table label never shares address with ld label if empty.
        table_bytes.resize(table_bytes.len() + 16, 0);
        a.db(&table_bytes).map_err(|e| UnpackerError::General(e.to_string()))?;

        a.set_label(&mut lbl_loader_data)
            .map_err(|e| UnpackerError::General(e.to_string()))?;
        let ld_bytes = ld_plan.map(|p| p.template.clone()).unwrap_or_else(|| vec![0u8; 0x200]);
        a.db(&ld_bytes).map_err(|e| UnpackerError::General(e.to_string()))?;

        // No-op detection stubs (reached only by the repointed slots above).
        a.set_label(&mut lbl_stub_invalid)
            .map_err(|e| UnpackerError::General(e.to_string()))?;
        a.db(&[0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]) // mov rax, -1 ; ret
            .map_err(|e| UnpackerError::General(e.to_string()))?;
        a.set_label(&mut lbl_stub_zero)
            .map_err(|e| UnpackerError::General(e.to_string()))?;
        a.db(&[0x31, 0xC0, 0xC3]) // xor eax, eax ; ret
            .map_err(|e| UnpackerError::General(e.to_string()))?;
    }

    let res = a
        .assemble_options(vmpinit_va, BlockEncoderOptions::NONE)
        .map_err(|e| UnpackerError::General(format!("assemble .vmpinit: {e}")))?;
    let stub_bytes = res.inner.code_buffer;

    let chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    let actual_rva = imagedump::append_section_with_chars(pe, ".vmpinit", &stub_bytes, chars)?;
    if actual_rva != vmpinit_rva {
        return Err(UnpackerError::General(format!(
            ".vmpinit RVA mismatch: predicted {vmpinit_rva:#x}, got {actual_rva:#x}"
        )));
    }
    imagedump::disable_aslr_and_strip_relocs(pe)?;
    imagedump::set_entry_point(pe, actual_rva)?;
    imagedump::fix_checksum(pe)?;
    Ok(actual_rva)
}

/// Reconstructs a runnable Windows PE from an unpacked (and optionally devirtualized)
/// VMProtect x64 image + its original packed PE header metadata.
pub fn rebuild_vmp_pe(
    pe_bytes: &mut Vec<u8>,
    packed_pe_bytes: &[u8],
    oep_override: Option<u32>,
) -> UnpackerResult<VmpRebuildReport> {
    let (_dos, pe_hdr, opt, sections) = parse_pe_bytes(pe_bytes)?;
    let is_pe64 = pe_hdr.machine == 0x8664 || opt.magic == 0x20B;
    if !is_pe64 {
        return Ok(VmpRebuildReport {
            rebuilt: false,
            oep_rva: None,
            init_stub_rva: None,
            import_section_rva: None,
            key32: None,
            import_dlls: 0,
            import_entries: 0,
            fixup_records: 0,
            runtime_entry_rva: None,
            loader_data_ptr_rva: None,
            loader_data_mode: None,
            warnings: vec!["VMP runnable PE rebuild currently supports x64 (PE32+) only".into()],
        });
    }

    let mut warnings = Vec::new();
    let (_pdos, _pph, packed_opt, packed_secs) =
        parse_pe_bytes(packed_pe_bytes).unwrap_or_else(|_| (_dos, pe_hdr.clone(), opt.clone(), sections.clone()));
    let loader_sec = find_loader_section(&sections, packed_opt.address_of_entry_point)
        .or_else(|| find_loader_section(&packed_secs, packed_opt.address_of_entry_point));
    let loader_sec_va = loader_sec.as_ref().map(|s| s.virtual_address);

    // 1. Discover OEP before modifying PE structure.
    let oep_rva = oep_override.or_else(|| find_oep_rva(pe_bytes));
    let Some(oep_rva) = oep_rva else {
        warnings.push("Could not locate OEP in primary code section; skipping runnable PE rebuild".into());
        return Ok(VmpRebuildReport {
            rebuilt: false,
            oep_rva: None,
            init_stub_rva: None,
            import_section_rva: None,
            key32: None,
            import_dlls: 0,
            import_entries: 0,
            fixup_records: 0,
            runtime_entry_rva: None,
            loader_data_ptr_rva: None,
            loader_data_mode: None,
            warnings,
        });
    };

    // 2. Collect original IAT entries + VMP encrypted IMPORT_INFO entries.
    let mut all_records = extract_original_iat(pe_bytes, &opt, &sections, true);
    let mut found_key32 = None;
    if let Some(ref lsec) = loader_sec {
        let (k32, vmp_recs) = find_vmp_import_tables(pe_bytes, &opt, &sections, lsec, true);
        found_key32 = k32;
        if vmp_recs.is_empty() {
            warnings.push("No encrypted VMP IMPORT_INFO table found in loader section".into());
        }
        all_records.extend(vmp_recs);
    }

    // 3. Rebuild `.import` with deduplicated `(dll_lower, func)` IAT slots.
    let mut import_section_rva = None;
    let mut fixups = Vec::new();
    let mut import_dlls = 0usize;
    let mut import_entries = 0usize;

    if !all_records.is_empty() {
        let mut per_dll: HashMap<String, (String, Vec<String>, HashSet<String>)> = HashMap::new();
        let mut dll_order = Vec::new();
        for rec in &all_records {
            let low = rec.dll_name.to_ascii_lowercase();
            let entry = per_dll.entry(low.clone()).or_insert_with(|| {
                dll_order.push(low);
                (rec.dll_name.clone(), Vec::new(), HashSet::new())
            });
            if entry.2.insert(rec.func_name.clone()) {
                entry.1.push(rec.func_name.clone());
            }
        }
        import_dlls = dll_order.len();
        let imports_arg: Vec<(String, Vec<String>)> = dll_order
            .into_iter()
            .map(|k| {
                let (name, funcs, _) = per_dll.remove(&k).unwrap();
                import_entries += funcs.len();
                (name, funcs)
            })
            .collect();

        let (imp_rva, slot_map) = imagedump::rebuild_import_section_with_map(pe_bytes, &imports_arg)?;
        import_section_rva = Some(imp_rva);

        let mut dst_rvas = Vec::with_capacity(all_records.len());
        for rec in &all_records {
            let low = rec.dll_name.to_ascii_lowercase();
            if let Some(&iat_slot_rva) = slot_map.get(&(low, rec.func_name.clone())) {
                fixups.push(ImportFixup {
                    iat_slot_rva,
                    dst_slot_rva: rec.dst_slot_rva,
                    key_i32: rec.key_i32,
                });
                dst_rvas.push(rec.dst_slot_rva);
            }
        }
        imagedump::mark_sections_writable_for_rvas(pe_bytes, &dst_rvas)?;
    }

    // 4. Discover VMProtectRuntime & capture/probe LoaderData recipe.
    let (_d2, _p2, opt2, secs2) = parse_pe_bytes(pe_bytes)?;
    let rt_cands = find_vmp_runtime_candidates(pe_bytes, &opt2, &secs2, loader_sec_va);
    let (runtime_entry_rva, ld_plan) =
        capture_loader_data_via_packed_loader(packed_pe_bytes, &rt_cands, oep_rva, loader_sec_va, &mut warnings)
            .map(|(rt, plan)| (rt, Some(plan)))
            .or_else(|| probe_loader_data(pe_bytes, &opt2, &secs2, &fixups, &rt_cands, Some(oep_rva)))
            .unwrap_or((rt_cands.first().copied(), None));

    let g_ld_rva = ld_plan.as_ref().and_then(|p| p.g_loader_data_rva);
    if let Some(g_rva) = g_ld_rva {
        imagedump::mark_sections_writable_for_rvas(pe_bytes, &[g_rva])?;
    }

    // 5. Emit `.vmpinit` bootstrap and update EP + ASLR + checksum.
    // Detection APIs whose protected slots are repointed at no-op stubs so the sample's
    // own anti-tamper (process/window/debugger enumeration) finds nothing.
    let detect_overrides: Vec<(u32, i32, bool)> = all_records
        .iter()
        .filter_map(|r| match r.func_name.as_str() {
            "CreateToolhelp32Snapshot" => Some((r.dst_slot_rva, r.key_i32, true)),
            "FindWindowA" | "FindWindowW" | "FindWindowExA" | "FindWindowExW"
            | "IsDebuggerPresent" => Some((r.dst_slot_rva, r.key_i32, false)),
            _ => None,
        })
        .collect();

    let init_stub_rva = emit_vmpinit_section(
        pe_bytes,
        opt2.image_base,
        &fixups,
        runtime_entry_rva,
        ld_plan.as_ref(),
        oep_rva,
        &detect_overrides,
    )?;

    Ok(VmpRebuildReport {
        rebuilt: true,
        oep_rva: Some(oep_rva),
        init_stub_rva: Some(init_stub_rva),
        import_section_rva,
        key32: found_key32,
        import_dlls,
        import_entries,
        fixup_records: fixups.len(),
        runtime_entry_rva,
        loader_data_ptr_rva: g_ld_rva,
        loader_data_mode: ld_plan.as_ref().map(|p| p.mode.clone()),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_pe64_with_vmp_imports() -> (Vec<u8>, u32, u32) {
        // Layout:
        // [0] .text VA=0x1000 raw=0x1000 size=0x1000 (contains OEP @ 0x1000 -> mov eax, [slot] or calls ret)
        // [1] .vmp0 VA=0x2000 raw=0x2000 size=0x1000 (contains target IAT slots @ 0x2100, 0x2108, rt @ 0x2200)
        // [2] .vmp1 VA=0x3000 raw=0x3000 size=0x1000 (loader section: key32 mov+rol, IMPORT_INFO, orig EP @ 0x3000)
        let mut pe = vec![0u8; 0x4000];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        pe[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        pe[opt + 16..opt + 20].copy_from_slice(&0x3000u32.to_le_bytes()); // packed EP in .vmp1
        pe[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 36..opt + 40].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[opt + 70..opt + 72].copy_from_slice(&0x8160u16.to_le_bytes()); // ASLR enabled initially
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let secs = [
            (b".text\0\0\0", 0x1000u32, 0x1000u32, 0x6000_0020u32),
            (b".vmp0\0\0\0", 0x2000u32, 0x2000u32, 0x6000_0020u32), // NOT writable initially!
            (b".vmp1\0\0\0", 0x3000u32, 0x3000u32, 0x6800_0060u32),
        ];
        for (i, (nm, va, raw, chars)) in secs.iter().enumerate() {
            let o = opt + 240 + i * 40;
            pe[o..o + 8].copy_from_slice(*nm);
            pe[o + 8..o + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            pe[o + 16..o + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[o + 20..o + 24].copy_from_slice(&raw.to_le_bytes());
            pe[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }

        // .text @ 0x1000: OEP CRT stub: sub rsp, 0x28; call 0x1020; add rsp, 0x28; jmp 0x1030
        pe[0x1000..0x1018].copy_from_slice(&[
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0xE8, 0x17, 0x00, 0x00, 0x00,       // call 0x1020 (0x1009 + 0x17)
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
            0xE9, 0x1E, 0x00, 0x00, 0x00,       // jmp 0x1030 (0x1012 + 0x1E)
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ]);
        pe[0x1020] = 0xC3; // __security_init_cookie stub: ret
        // 0x1030: mov eax, 0x77; ret (so Unicorn verifies clean execution at OEP!)
        pe[0x1030..0x1036].copy_from_slice(&[0xB8, 0x77, 0x00, 0x00, 0x00, 0xC3]);

        // .vmp1 loader @ 0x3000: mov eax, key32; ...; rol eax, cl; IMPORT_INFO with negative + positive i32 keys!
        let key32: u32 = 0xF624_C393;
        pe[0x3000..0x3005].copy_from_slice(&[0xB8, 0x93, 0xC3, 0x24, 0xF6]);
        pe[0x3005..0x3007].copy_from_slice(&[0xD3, 0xC0]);

        let encrypt = |s: &[u8], out: &mut [u8]| {
            for (i, &b) in s.iter().enumerate() {
                out[i] = b ^ vmp_key_byte(key32, i);
            }
        };
        encrypt(b"KERNEL32.dll\0", &mut pe[0x3100..0x310D]);
        encrypt(b"GetProcAddress\0", &mut pe[0x3120..0x312F]);
        encrypt(b"ExitProcess\0", &mut pe[0x3140..0x314C]);

        // Block 1: positive key = 0x0010_0000 -> slot 0x2100
        // Block 2 (duplicate KERNEL32.dll!): negative i32 key = 0xB6A8_2B2F (bit 31 set!) -> slot 0x2108
        // Real VMP 3.5/3.8+ 4B header + 12B entry format, with NO trailing `dll_rva == 0` (unrelated bytes follow)!
        let neg_key: u32 = 0xB6A8_2B2F;
        let pos_key: u32 = 0x0010_0000;
        let entries: &[u32] = &[
            0x3100,
            0x3120, 0x2100, pos_key,
            0,
            0x3100,
            0x3140, 0x2108, neg_key,
            0,
            0xDEAD_BEEF,
        ];
        for (i, &w) in entries.iter().enumerate() {
            pe[0x3200 + i * 4..0x3204 + i * 4].copy_from_slice(&w.to_le_bytes());
        }

        (pe, pos_key, neg_key)
    }

    #[test]
    fn rebuild_vmp_pe_fixes_signed_keys_preserves_stack_and_runs_in_unicorn() {
        let (mut pe, pos_key, neg_key) = build_test_pe64_with_vmp_imports();
        let orig = pe.clone();

        let rep = rebuild_vmp_pe(&mut pe, &orig, None).unwrap();
        assert!(rep.rebuilt, "report={rep:?}");
        assert_eq!(rep.key32, Some(0xF624_C393));
        assert_eq!(rep.oep_rva, Some(0x1000));
        assert_eq!(rep.fixup_records, 2);

        // Verify .vmp0 was marked writable and ASLR was disabled.
        let (_dos, pe_h, opt, secs) = parse_pe_bytes(&pe).unwrap();
        assert_eq!(opt.dll_characteristics & 0x0060, 0);
        assert_ne!(pe_h.characteristics & 0x0001, 0);
        let vmp0 = secs.iter().find(|s| s.name == ".vmp0").unwrap();
        assert_ne!(vmp0.characteristics & IMAGE_SCN_MEM_WRITE, 0);
        assert_eq!(opt.address_of_entry_point, rep.init_stub_rva.unwrap());

        // Map rebuilt PE in Unicorn, resolve `.import` IAT slots as OS loader, run from .vmpinit -> OEP!
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
        let base = opt.image_base;
        let map_sz = ((opt.size_of_image as u64 + 0xFFF) & !0xFFF).max(0x2000);
        uc.mem_map(base, map_sz, Prot::ALL).unwrap();
        uc.mem_write(base, &pe).unwrap();

        // Find IAT slots for GetProcAddress & ExitProcess from rebuilt directory
        let imp_rva = opt.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address;
        assert_ne!(imp_rva, 0);
        let ft = rd_u32(&pe, imp_rva as usize + 16).unwrap() as usize;
        let fake_getproc: u64 = 0x7FF8_1234_5678;
        let fake_exit: u64 = 0x7FF8_9ABC_DEF0;
        uc.mem_write(base + ft as u64, &fake_getproc.to_le_bytes()).unwrap();
        uc.mem_write(base + ft as u64 + 8, &fake_exit.to_le_bytes()).unwrap();

        let stack_base = 0x0020_0000u64;
        let stack_sz = 0x0010_0000u64;
        let stop_addr = 0x0005_0000u64;
        uc.mem_map(stack_base, stack_sz, Prot::ALL).unwrap();
        uc.mem_map(stop_addr, 0x1000, Prot::ALL).unwrap();
        uc.mem_write(stop_addr, &[0x90]).unwrap();
        let rsp_init = stack_base + stack_sz - 0x1000;
        uc.mem_write(rsp_init, &stop_addr.to_le_bytes()).unwrap();
        uc.reg_write(RegisterX86::RSP as i32, rsp_init).unwrap();

        uc.emu_start(base + opt.address_of_entry_point as u64, stop_addr, 1_000_000, 10_000)
            .unwrap();

        assert_eq!(uc.reg_read(RegisterX86::RAX as i32).unwrap(), 0x77);
        assert_eq!(uc.reg_read(RegisterX86::RSP as i32).unwrap(), rsp_init + 8);

        let mut buf0 = [0u8; 8];
        let mut buf1 = [0u8; 8];
        uc.mem_read(base + 0x2100, &mut buf0).unwrap();
        uc.mem_read(base + 0x2108, &mut buf1).unwrap();
        let expected0 = fake_getproc.wrapping_sub((pos_key as i32) as i64 as u64);
        let expected1 = fake_exit.wrapping_sub((neg_key as i32) as i64 as u64);
        assert_eq!(u64::from_le_bytes(buf0), expected0);
        assert_eq!(u64::from_le_bytes(buf1), expected1);
    }

    #[test]
    fn find_crc32_loops_detects_mutated_vmp_crc_loop() {
        // Mutated x64 IEEE CRC32 loop with `call $+5` + `jmp $+0` + REX registers + trailing xor imm32:
        // loop_head (va + 0x10):
        //   44 0f b6 06          movzx r8d, byte ptr [rsi]
        //   e8 00 00 00 00       call $+5
        //   45 33 c1             xor r8d, r9d
        //   e9 00 00 00 00       jmp $+0
        //   41 81 e0 ff 00 00 00 and r8d, 0xff
        //   47 8b 04 83          mov r8d, dword ptr [r11 + r8*4]
        //   41 c1 e9 08          shr r9d, 8
        //   45 33 c8             xor r9d, r8d
        //   41 81 f1 20 2c 27 37 xor r9d, 0x37272c20
        //   48 ff c6             inc rsi
        //   48 ff c9             dec rcx
        //   75 d4                jnz loop_head (-0x2C from next insn at +0x3C => +0x10)
        let mut code = vec![0x90u8; 0x60];
        let loop_bytes: &[u8] = &[
            0x44, 0x0F, 0xB6, 0x06,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x33, 0xC1,
            0xE9, 0x00, 0x00, 0x00, 0x00,
            0x41, 0x81, 0xE0, 0xFF, 0x00, 0x00, 0x00,
            0x47, 0x8B, 0x04, 0x83,
            0x41, 0xC1, 0xE9, 0x08,
            0x45, 0x33, 0xC8,
            0x41, 0x81, 0xF1, 0x20, 0x2C, 0x27, 0x37,
            0x48, 0xFF, 0xC6,
            0x48, 0xFF, 0xC9,
            0x75, 0xCE,
        ];
        code[0x10..0x10 + loop_bytes.len()].copy_from_slice(loop_bytes);
        let base_va = 0x1_4300_0000u64;
        let loops = find_crc32_loops(&code, base_va);
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].loop_head_va, base_va + 0x10);
        assert_eq!(loops[0].tbl_reg, RegisterX86::R11);
        assert_eq!(loops[0].crc_reg, RegisterX86::R9);
        assert_eq!(loops[0].ptr_reg, RegisterX86::RSI);
        assert_eq!(loops[0].len_reg, RegisterX86::RCX);
        assert_eq!(loops[0].crc_xor_imm, 0x3727_2C20);
    }

    #[test]
    fn vmpinit_patches_env_xor_and_g_loader_data_in_unicorn() {
        let mut pe = vec![0u8; 0x3000];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        pe[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let opt = coff + 20;
        let image_base = 0x1_4000_0000u64;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 36..opt + 40].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let secs = [
            (b".text\0\0\0", 0x1000u32, 0x1000u32, 0x6000_0020u32),
            (b".data\0\0\0", 0x2000u32, 0x2000u32, 0xC000_0040u32),
        ];
        for (i, (nm, va, raw, chars)) in secs.iter().enumerate() {
            let o = opt + 240 + i * 40;
            pe[o..o + 8].copy_from_slice(*nm);
            pe[o + 8..o + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            pe[o + 16..o + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[o + 20..o + 24].copy_from_slice(&raw.to_le_bytes());
            pe[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }

        // OEP @ 0x1000: mov eax, 0x77; ret
        pe[0x1000..0x1006].copy_from_slice(&[0xB8, 0x77, 0x00, 0x00, 0x00, 0xC3]);

        // Runtime @ 0x1040: read g_loader_data [0x140002100] -> r10;
        // copy [r10+0x68]->[0x2200], [r10+0x10]->[0x2204], [r10+0x20]->[0x2208], [r10+0x180]->[0x2210]
        // and return rax = 1
        let mut asm_rt = CodeAssembler::new(64).unwrap();
        {
            use gpr32::*;
            use gpr64::*;
            asm_rt.mov(r10, image_base + 0x2100).unwrap();
            asm_rt.mov(r10, qword_ptr(r10)).unwrap();
            asm_rt.mov(r9, image_base + 0x2200).unwrap();
            asm_rt.mov(eax, dword_ptr(r10 + 0x68)).unwrap();
            asm_rt.mov(dword_ptr(r9), eax).unwrap();
            asm_rt.mov(eax, dword_ptr(r10 + 0x10)).unwrap();
            asm_rt.mov(dword_ptr(r9 + 4), eax).unwrap();
            asm_rt.mov(rax, qword_ptr(r10 + 0x20)).unwrap();
            asm_rt.mov(qword_ptr(r9 + 8), rax).unwrap();
            asm_rt.mov(eax, dword_ptr(r10 + 0x180)).unwrap();
            asm_rt.mov(dword_ptr(r9 + 0x10), eax).unwrap();
            asm_rt.mov(eax, 1).unwrap();
            asm_rt.ret().unwrap();
        }
        let rt_bytes = asm_rt.assemble(image_base + 0x1040).unwrap();
        pe[0x1040..0x1040 + rt_bytes.len()].copy_from_slice(&rt_bytes);

        let mut template = vec![0u8; 0x1A8];
        let count_val: u32 = 1 ^ 0xFAB2_6888;
        template[0x180..0x184].copy_from_slice(&count_val.to_le_bytes());

        let plan = LoaderDataPlan {
            mode: "packed-loader-diff".to_string(),
            template,
            pass_in_r8: false,
            g_loader_data_rva: Some(0x2100),
            env_xor_patches: vec![LoaderDataEnvPatch {
                offset: 0x68,
                base_const: 0x5C86_CBBB,
            }],
            ld_ptr_xor_patches: vec![LoaderDataEnvPatch {
                offset: 0x10,
                base_const: 0x1122_3344,
            }],
            ld_rel_qwords: vec![(0x20, 0x18)],
            image_rel_qwords: Vec::new(),
        };

        let init_rva = emit_vmpinit_section(&mut pe, image_base, &[], Some(0x1040), Some(&plan), 0x1000, &[]).unwrap();
        assert_eq!(init_rva, 0x3000);

        let (_d, _p, opt_out, _) = parse_pe_bytes(&pe).unwrap();
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
        let map_sz = ((opt_out.size_of_image as u64 + 0xFFF) & !0xFFF).max(0x2000);
        uc.mem_map(image_base, map_sz, Prot::ALL).unwrap();
        uc.mem_write(image_base, &pe).unwrap();

        let stack_base = 0x0020_0000u64;
        let teb_addr = 0x0002_0000u64;
        let peb_addr = 0x0002_2000u64;
        let stop_addr = 0x0005_0000u64;
        uc.mem_map(stack_base, 0x10_0000, Prot::ALL).unwrap();
        uc.mem_map(teb_addr, 0x4000, Prot::ALL).unwrap();
        uc.mem_map(stop_addr, 0x1000, Prot::ALL).unwrap();
        uc.mem_write(stop_addr, &[0x90]).unwrap();
        uc.mem_write(teb_addr + 0x60, &peb_addr.to_le_bytes()).unwrap();
        uc.mem_write(peb_addr + 0x120, &19045u16.to_le_bytes()).unwrap();
        uc.reg_write(RegisterX86::GS_BASE as i32, teb_addr).unwrap();

        let rsp_init = stack_base + 0x10_0000 - 0x1000;
        uc.mem_write(rsp_init, &stop_addr.to_le_bytes()).unwrap();
        uc.reg_write(RegisterX86::RSP as i32, rsp_init).unwrap();

        uc.emu_start(image_base + init_rva as u64, stop_addr, 1_000_000, 10_000).unwrap();

        assert_eq!(uc.reg_read(RegisterX86::RAX as i32).unwrap(), 0x77);
        assert_eq!(uc.reg_read(RegisterX86::RSP as i32).unwrap(), rsp_init + 8);

        let mut g_buf = [0u8; 8];
        uc.mem_read(image_base + 0x2100, &mut g_buf).unwrap();
        let actual_ld_ptr = u64::from_le_bytes(g_buf);
        let expected_env = probe_live_cpuid_env(actual_ld_ptr, 19045);

        let mut res_buf = [0u8; 0x18];
        uc.mem_read(image_base + 0x2200, &mut res_buf).unwrap();
        let obs_68 = u32::from_le_bytes(res_buf[0..4].try_into().unwrap());
        let obs_10 = u32::from_le_bytes(res_buf[4..8].try_into().unwrap());
        let obs_20 = u64::from_le_bytes(res_buf[8..16].try_into().unwrap());
        let obs_180 = u32::from_le_bytes(res_buf[16..20].try_into().unwrap());

        assert_eq!(obs_68, 0x5C86_CBBB ^ expected_env);
        assert_eq!(obs_10, 0x1122_3344 ^ (actual_ld_ptr as u32));
        assert_eq!(obs_20, actual_ld_ptr + 0x18);
        assert_eq!(obs_180, count_val);
    }
}
