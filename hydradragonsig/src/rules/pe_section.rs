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
        name_regex,
        flags_all,
        flags_none,
        entropy_min,
        entropy_max,
        raw_size_min,
        raw_size_max,
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
    if let Some(p) = name_regex {
        if !super::engine::cached_regex(p)?.is_match(&s.name) {
            return None;
        }
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
    if raw_size_min.is_some_and(|m| s.raw_size < m) || raw_size_max.is_some_and(|m| s.raw_size > m) {
        return None;
    }
    if raw_size_min.is_some() || raw_size_max.is_some() {
        why.push(format!("raw_size={}", s.raw_size));
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
    let RuleCondition::PeSection { select, .. } = cond else { return None };
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
