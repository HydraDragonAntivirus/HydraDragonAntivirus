//! `pe_section` condition: properties of one chosen PE section.
//!
//! Nothing here knows a malware family. A rule picks a section (`any`, `last`,
//! `entry`) and lists what must hold for it: name, characteristics flags, entropy,
//! raw size, direct code references from the other executable sections (decoded
//! with iced-x86), whether it holds the entry point, and which data directories
//! point into it. File infectors, packers and protectors are then described in
//! YAML (FORMAT.md 5.2).

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

use super::types::{PeSectionSelect, RuleCondition};
use crate::models::{PeInfo, PeSectionInfo};

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Section flag names accepted in `flags_all` / `flags_none`.
pub const FLAGS: &[(&str, u32)] = &[
    ("code", IMAGE_SCN_CNT_CODE),
    ("initialized_data", 0x0000_0040),
    ("uninitialized_data", 0x0000_0080),
    ("discardable", 0x0200_0000),
    ("not_cached", 0x0400_0000),
    ("not_paged", 0x0800_0000),
    ("shared", 0x1000_0000),
    ("execute", IMAGE_SCN_MEM_EXECUTE),
    ("read", 0x4000_0000),
    ("write", 0x8000_0000),
];

/// Data directory names accepted in `directories_any` (index = IMAGE_DIRECTORY_ENTRY_*).
pub const DIRECTORIES: &[&str] = &[
    "export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
    "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr",
];

/// Bytes of code decoded per executable section when counting `code_xrefs_min`.
const MAX_SWEEP_BYTES: usize = 16 * 1024 * 1024;

pub fn flag_value(name: &str) -> Option<u32> {
    FLAGS.iter().find(|(n, _)| n.eq_ignore_ascii_case(name.trim())).map(|(_, v)| *v)
}

pub fn directory_index(name: &str) -> Option<usize> {
    DIRECTORIES.iter().position(|n| n.eq_ignore_ascii_case(name.trim()))
}

fn span(s: &PeSectionInfo) -> (u64, u64) {
    (s.virtual_address, s.virtual_address + s.virtual_size.max(s.raw_size))
}

fn contains(s: &PeSectionInfo, rva: u64) -> bool {
    let (lo, hi) = span(s);
    rva >= lo && rva < hi
}

/// Direct near `call` / `jmp` / `jcc` instructions in the other executable sections
/// whose target lies in `target` (linear sweep).
fn code_xrefs_into(pe: &PeInfo, bytes: &[u8], target: &PeSectionInfo, need: usize) -> usize {
    let bitness = if pe.is_64 { 64 } else { 32 };
    let (lo, hi) = span(target);
    let mut found = 0;
    for s in &pe.sections {
        if std::ptr::eq(s, target) || s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) == 0 {
            continue;
        }
        let start = s.raw_offset as usize;
        if start >= bytes.len() {
            continue;
        }
        let end = start.saturating_add(s.raw_size as usize).min(bytes.len()).min(start + MAX_SWEEP_BYTES);
        let ip = pe.image_base.wrapping_add(s.virtual_address);
        let mut dec = Decoder::with_ip(bitness, &bytes[start..end], ip, DecoderOptions::NONE);
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.is_invalid() || ins.op_count() != 1 {
                continue;
            }
            let near = matches!(ins.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64);
            let branch = matches!(
                ins.flow_control(),
                FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
            );
            if near && branch {
                let rva = ins.near_branch_target().wrapping_sub(pe.image_base);
                if rva >= lo && rva < hi {
                    found += 1;
                    if found >= need {
                        return found;
                    }
                }
            }
        }
    }
    found
}

/// Why `s` passes every key of the condition, or None.
fn check(cond: &RuleCondition, pe: &PeInfo, bytes: &[u8], s: &PeSectionInfo) -> Option<String> {
    let RuleCondition::PeSection {
        name,
        name_regex,
        flags_all,
        flags_none,
        characteristics,
        entropy_min,
        entropy_max,
        raw_size,
        raw_size_min,
        raw_size_max,
        raw_offset,
        virtual_address,
        virtual_size,
        virtual_size_min,
        virtual_size_max,
        md5,
        sha1,
        sha256,
        crc32,
        code_xrefs_min,
        has_entry,
        directories_any,
        directories_none,
        directory_share_max,
        ..
    } = cond
    else {
        return None;
    };
    let mut why = vec![format!("section {}", if s.name.is_empty() { "<empty>" } else { &s.name })];
    if let Some(exact) = name {
        if s.name != *exact {
            return None;
        }
    }
    if let Some(p) = name_regex {
        if !super::engine::cached_regex(p)?.is_match(&s.name) {
            return None;
        }
    }
    if let Some(want_chars) = characteristics {
        if s.characteristics != *want_chars {
            return None;
        }
        why.push(format!("characteristics=0x{:08x}", s.characteristics));
    }
    for f in flags_all {
        if s.characteristics & flag_value(f)? == 0 {
            return None;
        }
    }
    for f in flags_none {
        if s.characteristics & flag_value(f)? != 0 {
            return None;
        }
    }
    if !flags_all.is_empty() || !flags_none.is_empty() {
        why.push(format!("flags=0x{:08x}", s.characteristics));
    }
    if entropy_min.is_some_and(|m| s.entropy < m) || entropy_max.is_some_and(|m| s.entropy > m) {
        return None;
    }
    if entropy_min.is_some() || entropy_max.is_some() {
        why.push(format!("entropy={:.3}", s.entropy));
    }
    if raw_size.is_some_and(|want| s.raw_size != want)
        || raw_size_min.is_some_and(|m| s.raw_size < m)
        || raw_size_max.is_some_and(|m| s.raw_size > m)
    {
        return None;
    }
    if raw_size.is_some() || raw_size_min.is_some() || raw_size_max.is_some() {
        why.push(format!("raw_size={}", s.raw_size));
    }
    if let Some(want_off) = raw_offset {
        if s.raw_offset != *want_off {
            return None;
        }
        why.push(format!("raw_offset=0x{:x}", s.raw_offset));
    }
    if let Some(want_va) = virtual_address {
        if s.virtual_address != *want_va {
            return None;
        }
        why.push(format!("virtual_address=0x{:x}", s.virtual_address));
    }
    if virtual_size.is_some_and(|want| s.virtual_size != want)
        || virtual_size_min.is_some_and(|m| s.virtual_size < m)
        || virtual_size_max.is_some_and(|m| s.virtual_size > m)
    {
        return None;
    }
    if virtual_size.is_some() || virtual_size_min.is_some() || virtual_size_max.is_some() {
        why.push(format!("virtual_size=0x{:x}", s.virtual_size));
    }
    if md5.is_some() || sha1.is_some() || sha256.is_some() || crc32.is_some() {
        let start = (s.raw_offset as usize).min(bytes.len());
        let end = start.saturating_add(s.raw_size as usize).min(bytes.len());
        let raw_slice = &bytes[start..end];
        if let Some(want) = md5 {
            let got = crate::utils::hash::md5_hex(raw_slice);
            if !got.eq_ignore_ascii_case(want.trim()) {
                return None;
            }
            why.push(format!("md5={got}"));
        }
        if let Some(want) = sha1 {
            let got = crate::utils::hash::sha1_hex(raw_slice);
            if !got.eq_ignore_ascii_case(want.trim()) {
                return None;
            }
            why.push(format!("sha1={got}"));
        }
        if let Some(want) = sha256 {
            let got = crate::utils::hash::sha256_hex(raw_slice);
            if !got.eq_ignore_ascii_case(want.trim()) {
                return None;
            }
            why.push(format!("sha256={got}"));
        }
        if let Some(want) = crc32 {
            let clean = want.trim().trim_start_matches("0x").trim_start_matches("0X");
            let got = crate::utils::hash::crc32_hex(raw_slice);
            if !got.eq_ignore_ascii_case(clean) {
                return None;
            }
            why.push(format!("crc32={got}"));
        }
    }
    if let Some(want) = has_entry {
        if contains(s, pe.entry) != *want {
            return None;
        }
        why.push(format!("entry_point_inside={want}"));
    }
    let inside = |d: &String| {
        directory_index(d)
            .and_then(|i| pe.data_directories.get(i))
            .is_some_and(|&(rva, size)| size > 0 && contains(s, rva as u64))
    };
    if directories_none.iter().any(inside) {
        return None;
    }
    if !directories_any.is_empty() {
        let hit = directories_any.iter().find(|d| inside(d))?;
        why.push(format!("directory {hit} inside"));
        if let Some(max) = directory_share_max {
            let (lo, hi) = span(s);
            let covered: u64 = directories_any
                .iter()
                .filter(|d| inside(d))
                .filter_map(|d| directory_index(d).and_then(|i| pe.data_directories.get(i)))
                .map(|&(_, size)| size as u64)
                .sum();
            let share = covered as f64 / (hi - lo).max(1) as f64;
            if share > *max {
                return None;
            }
            why.push(format!("directory_share={share:.4}"));
        }
    }
    if let Some(min) = code_xrefs_min {
        let n = code_xrefs_into(pe, bytes, s, (*min).max(1));
        if n < *min {
            return None;
        }
        why.push(format!("code_xrefs>={n}"));
    }
    Some(why.join(" "))
}

pub fn evaluate(cond: &RuleCondition, pe: &PeInfo, bytes: &[u8]) -> Option<String> {
    let RuleCondition::PeSection { select, index, .. } = cond else { return None };
    if let Some(idx) = index {
        let s = pe.sections.get(*idx)?;
        let found = check(cond, pe, bytes, s)?;
        return Some(format!("pe_section index={idx}: {found}"));
    }
    let found = match select {
        PeSectionSelect::Any => pe.sections.iter().find_map(|s| check(cond, pe, bytes, s)),
        PeSectionSelect::Last => pe.sections.last().and_then(|s| check(cond, pe, bytes, s)),
        PeSectionSelect::Entry => pe
            .sections
            .iter()
            .find(|s| contains(s, pe.entry))
            .and_then(|s| check(cond, pe, bytes, s)),
    }?;
    let which = match select {
        PeSectionSelect::Any => "any",
        PeSectionSelect::Last => "last",
        PeSectionSelect::Entry => "entry",
    };
    Some(format!("pe_section {which}: {found}"))
}

/// Evaluate `pe_sections_summary`: aggregate size, count and concatenated hashes
/// across all sections in table order (`size[sections]`, `md5[sections]`, `crc32[sections]`).
pub fn evaluate_sections_summary(cond: &RuleCondition, pe: &PeInfo, bytes: &[u8]) -> Option<String> {
    let RuleCondition::PeSectionsSummary {
        total_raw_size,
        total_raw_size_min,
        total_raw_size_max,
        md5,
        sha1,
        sha256,
        crc32,
        count,
        count_min,
        count_max,
    } = cond
    else {
        return None;
    };

    let n = pe.sections.len();
    if count.is_some_and(|want| n != want)
        || count_min.is_some_and(|min| n < min)
        || count_max.is_some_and(|max| n > max)
    {
        return None;
    }

    let total_size: u64 = pe.sections.iter().map(|s| s.raw_size).sum();
    if total_raw_size.is_some_and(|want| total_size != want)
        || total_raw_size_min.is_some_and(|min| total_size < min)
        || total_raw_size_max.is_some_and(|max| total_size > max)
    {
        return None;
    }

    let mut why = vec![format!("sections={n} total_raw_size={total_size}")];
    if md5.is_some() || sha1.is_some() || sha256.is_some() || crc32.is_some() {
        let mut concat = Vec::with_capacity((total_size as usize).min(bytes.len()));
        for s in &pe.sections {
            if s.raw_size == 0 {
                continue;
            }
            let start = (s.raw_offset as usize).min(bytes.len());
            let end = start.saturating_add(s.raw_size as usize).min(bytes.len());
            concat.extend_from_slice(&bytes[start..end]);
        }
        if let Some(want) = md5 {
            let got = crate::utils::hash::md5_hex(&concat);
            if !got.eq_ignore_ascii_case(want.trim()) {
                return None;
            }
            why.push(format!("md5={got}"));
        }
        if let Some(want) = sha1 {
            let got = crate::utils::hash::sha1_hex(&concat);
            if !got.eq_ignore_ascii_case(want.trim()) {
                return None;
            }
            why.push(format!("sha1={got}"));
        }
        if let Some(want) = sha256 {
            let got = crate::utils::hash::sha256_hex(&concat);
            if !got.eq_ignore_ascii_case(want.trim()) {
                return None;
            }
            why.push(format!("sha256={got}"));
        }
        if let Some(want) = crc32 {
            let clean = want.trim().trim_start_matches("0x").trim_start_matches("0X");
            let got = crate::utils::hash::crc32_hex(&concat);
            if !got.eq_ignore_ascii_case(clean) {
                return None;
            }
            why.push(format!("crc32={got}"));
        }
    }

    Some(format!("pe_sections_summary: {}", why.join(" ")))
}

/// Evaluate `export_hash_any` (`md5[exports]`): checks both the lower-case
/// comma-joined export symbol list MD5 (empty exports = `d41d8cd98f00b204e9800998ecf8427e`)
/// and the raw export directory slice MD5.
pub fn evaluate_export_hash_any(values: &[String], pe: &PeInfo, bytes: &[u8]) -> Option<String> {
    let joined_lower = pe
        .exports
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    let sym_md5 = crate::utils::hash::md5_hex(joined_lower.as_bytes());
    let sym_exact_md5 = crate::utils::hash::md5_hex(pe.exports.join(",").as_bytes());
    let raw_dir_md5 = pe
        .data_directories
        .first()
        .copied()
        .and_then(|(rva, size)| {
            if size == 0 {
                return Some(crate::utils::hash::md5_hex(b""));
            }
            let off = super::pe_extra::rva_file_offset(pe, bytes, rva as u64)?;
            let end = off.saturating_add(size as usize).min(bytes.len());
            Some(crate::utils::hash::md5_hex(&bytes[off..end]))
        });

    for want in values {
        let w = want.trim();
        if sym_md5.eq_ignore_ascii_case(w)
            || sym_exact_md5.eq_ignore_ascii_case(w)
            || raw_dir_md5.as_deref().is_some_and(|r| r.eq_ignore_ascii_case(w))
        {
            return Some(format!("export_hash_any matched {}", w.to_ascii_lowercase()));
        }
    }
    None
}
