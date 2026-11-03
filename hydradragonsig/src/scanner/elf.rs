//! Structural ELF parser (32/64-bit, little/big endian) for the `elf_*`
//! conditions: header, sections, program headers, dynamic tags, symbols,
//! `NT_GNU_BUILD_ID` and toolchain hints.
//!
//! Every count and string is capped and every read is bounds-checked; a
//! truncated or hostile file yields what could be read, never a panic.

use super::bin::Reader;
use serde::{Deserialize, Serialize};

const MAX_SECTIONS: usize = 4096;
const MAX_SEGMENTS: usize = 4096;
const MAX_SYMBOLS: usize = 65_536;
const MAX_DYN_ENTRIES: usize = 16_384;
const MAX_NAME: usize = 4096;
/// Report caps of the symbol / library lists.
pub const MAX_NAMES: usize = 32_768;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
const SHT_SYMTAB: u32 = 2;
const SHT_NOTE: u32 = 7;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const NT_GNU_BUILD_ID: u32 = 3;

/// Section flag names of `elf_section` (`flags_all` / `flags_none`).
pub const SECTION_FLAGS: &[(&str, u64)] = &[("write", SHF_WRITE), ("alloc", SHF_ALLOC), ("exec", SHF_EXECINSTR)];
/// Segment flag names of `elf_segment`.
pub const SEGMENT_FLAGS: &[(&str, u64)] = &[
    ("r", PF_R as u64),
    ("read", PF_R as u64),
    ("w", PF_W as u64),
    ("write", PF_W as u64),
    ("x", PF_X as u64),
    ("exec", PF_X as u64),
];
/// Segment type names of `elf_segment` `seg_type`.
pub const SEGMENT_TYPES: &[(&str, u32)] = &[
    ("null", 0),
    ("load", PT_LOAD),
    ("dynamic", PT_DYNAMIC),
    ("interp", PT_INTERP),
    ("note", PT_NOTE),
    ("shlib", 5),
    ("phdr", 6),
    ("tls", 7),
    ("gnu_eh_frame", 0x6474_e550),
    ("gnu_stack", PT_GNU_STACK),
    ("gnu_relro", 0x6474_e552),
    ("gnu_property", 0x6474_e553),
];

pub fn section_flag(name: &str) -> Option<u64> {
    let n = name.trim().to_ascii_lowercase();
    SECTION_FLAGS.iter().find(|(f, _)| *f == n).map(|(_, v)| *v)
}

pub fn segment_flag(name: &str) -> Option<u64> {
    let n = name.trim().to_ascii_lowercase();
    SEGMENT_FLAGS.iter().find(|(f, _)| *f == n).map(|(_, v)| *v)
}

/// `load`, `gnu_stack`, ... or a number (`0x6474e551`).
pub fn segment_type(name: &str) -> Option<u32> {
    let n = name.trim().to_ascii_lowercase();
    let n = n.strip_prefix("pt_").unwrap_or(&n);
    if let Some((_, v)) = SEGMENT_TYPES.iter().find(|(t, _)| *t == n) {
        return Some(*v);
    }
    match n.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => n.parse().ok(),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ElfSection {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub offset: u64,
    pub size: u64,
    pub addr: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ElfSegment {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// ELF structure read by the `elf_*` conditions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ElfInfo {
    pub is_64: bool,
    pub little_endian: bool,
    /// `rel`, `exec`, `dyn`, `core` or the number.
    pub e_type: String,
    /// `x86`, `x86_64`, `arm`, `aarch64`, `mips`, `riscv`, ... or the number.
    pub machine: String,
    pub e_machine: u16,
    pub entry: u64,
    /// File offset of `entry` (through the `PT_LOAD` segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_offset: Option<u64>,
    /// No `.symtab`.
    pub stripped: bool,
    pub sections: Vec<ElfSection>,
    pub segments: Vec<ElfSegment>,
    pub needed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpaths: Vec<String>,
    /// Undefined (imported) symbols.
    pub imports: Vec<String>,
    /// Defined global / weak symbols.
    pub exports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    pub is_go_binary: bool,
    pub is_rust_binary: bool,
}

impl ElfInfo {
    /// Load segments that are both writable and executable.
    pub fn rwx_segment_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| s.p_type == PT_LOAD && s.flags & (PF_W | PF_X) == (PF_W | PF_X))
            .count()
    }

    /// File offset of a virtual address inside a `PT_LOAD` segment's file bytes.
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<u64> {
        self.segments.iter().filter(|s| s.p_type == PT_LOAD).find_map(|s| {
            let rel = vaddr.checked_sub(s.vaddr)?;
            (rel < s.filesz).then(|| s.offset.checked_add(rel)).flatten()
        })
    }

    /// The section holding the entry point.
    pub fn entry_section(&self) -> Option<usize> {
        self.sections.iter().position(|s| {
            s.flags & SHF_ALLOC != 0 && s.size > 0 && self.entry >= s.addr && self.entry - s.addr < s.size
        })
    }
}

pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}

fn machine_name(m: u16) -> String {
    match m {
        2 => "sparc",
        3 => "x86",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        22 => "s390",
        40 => "arm",
        43 => "sparcv9",
        50 => "ia64",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        258 => "loongarch",
        _ => return format!("{m}"),
    }
    .to_string()
}

fn type_name(t: u16) -> String {
    match t {
        1 => "rel",
        2 => "exec",
        3 => "dyn",
        4 => "core",
        _ => return format!("{t}"),
    }
    .to_string()
}

fn push_capped(list: &mut Vec<String>, value: String) {
    if list.len() < MAX_NAMES && !value.is_empty() && !list.contains(&value) {
        list.push(value);
    }
}

/// Parse an ELF file. `None` when the header itself is unreadable.
pub fn parse_elf(bytes: &[u8]) -> Option<ElfInfo> {
    if !is_elf(bytes) {
        return None;
    }
    let is_64 = match bytes.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let r = Reader::new(bytes, little);
    let (entry, phoff, shoff, phentsize_at, ehsize) = if is_64 { (r.u64(24)?, r.u64(32)?, r.u64(40)?, 54u64, 64u64) } else {
        (u64::from(r.u32(24)?), u64::from(r.u32(28)?), u64::from(r.u32(32)?), 42u64, 52u64)
    };
    if (bytes.len() as u64) < ehsize {
        return None;
    }
    let e_type = r.u16(16)?;
    let e_machine = r.u16(18)?;
    let phentsize = u64::from(r.u16(phentsize_at)?);
    let phnum = usize::from(r.u16(phentsize_at + 2)?);
    let shentsize = u64::from(r.u16(phentsize_at + 4)?);
    let shnum = usize::from(r.u16(phentsize_at + 6)?);
    let shstrndx = usize::from(r.u16(phentsize_at + 8)?);

    let mut info = ElfInfo {
        is_64,
        little_endian: little,
        e_type: type_name(e_type),
        machine: machine_name(e_machine),
        e_machine,
        entry,
        ..Default::default()
    };

    // Program headers.
    let min_ph = if is_64 { 56 } else { 32 };
    if phoff != 0 && phentsize >= min_ph {
        for i in 0..phnum.min(MAX_SEGMENTS) {
            let Some(at) = phoff.checked_add(i as u64 * phentsize) else { break };
            let seg = if is_64 {
                ElfSegment {
                    p_type: match r.u32(at) { Some(v) => v, None => break },
                    flags: r.u32(at + 4).unwrap_or(0),
                    offset: r.u64(at + 8).unwrap_or(0),
                    vaddr: r.u64(at + 16).unwrap_or(0),
                    filesz: r.u64(at + 32).unwrap_or(0),
                    memsz: r.u64(at + 40).unwrap_or(0),
                }
            } else {
                ElfSegment {
                    p_type: match r.u32(at) { Some(v) => v, None => break },
                    offset: u64::from(r.u32(at + 4).unwrap_or(0)),
                    vaddr: u64::from(r.u32(at + 8).unwrap_or(0)),
                    filesz: u64::from(r.u32(at + 16).unwrap_or(0)),
                    memsz: u64::from(r.u32(at + 20).unwrap_or(0)),
                    flags: r.u32(at + 24).unwrap_or(0),
                }
            };
            info.segments.push(seg);
        }
    }
    info.entry_offset = info.vaddr_to_offset(entry);

    // Section headers and their names.
    let min_sh = if is_64 { 64 } else { 40 };
    if shoff != 0 && shentsize >= min_sh {
        let mut name_offs = Vec::new();
        for i in 0..shnum.min(MAX_SECTIONS) {
            let Some(at) = shoff.checked_add(i as u64 * shentsize) else { break };
            let Some(name_off) = r.u32(at) else { break };
            name_offs.push(u64::from(name_off));
            let sh_type = r.u32(at + 4).unwrap_or(0);
            let (flags, addr, offset, size) = if is_64 {
                (r.u64(at + 8).unwrap_or(0), r.u64(at + 16).unwrap_or(0), r.u64(at + 24).unwrap_or(0), r.u64(at + 32).unwrap_or(0))
            } else {
                (
                    u64::from(r.u32(at + 8).unwrap_or(0)),
                    u64::from(r.u32(at + 12).unwrap_or(0)),
                    u64::from(r.u32(at + 16).unwrap_or(0)),
                    u64::from(r.u32(at + 20).unwrap_or(0)),
                )
            };
            info.sections.push(ElfSection { name: String::new(), sh_type, flags, offset, size, addr });
        }
        // Names resolve once the section name table is known.
        let names_at = info.sections.get(shstrndx).map(|s| (s.offset, s.size));
        for (s, off) in info.sections.iter_mut().zip(name_offs) {
            s.name = match names_at {
                Some((base, size)) if off < size => r.cstr(base.saturating_add(off), MAX_NAME.min((size - off) as usize)).unwrap_or_default(),
                _ => String::new(),
            };
        }
    }
    let links: Vec<u32> = if shoff != 0 && shentsize >= min_sh {
        (0..info.sections.len())
            .map(|i| r.u32(shoff + i as u64 * shentsize + if is_64 { 40 } else { 24 }).unwrap_or(0))
            .collect()
    } else {
        Vec::new()
    };
    info.stripped = !info.sections.iter().any(|s| s.sh_type == SHT_SYMTAB);

    // Interpreter.
    if let Some(seg) = info.segments.iter().find(|s| s.p_type == PT_INTERP) {
        info.interpreter = r.cstr(seg.offset, (seg.filesz as usize).min(MAX_NAME)).filter(|s| !s.is_empty());
    }

    read_dynamic(&r, &mut info, &links);
    read_symbols(&r, &mut info, &links);
    read_build_id(&r, &mut info);

    info.is_go_binary = info.sections.iter().any(|s| matches!(s.name.as_str(), ".gopclntab" | ".go.buildinfo" | ".note.go.buildid"))
        || memchr::memmem::find(bytes, b"\xff Go buildinf:").is_some();
    info.is_rust_binary = info
        .imports
        .iter()
        .chain(&info.exports)
        .any(|s| s.contains("rust_begin_unwind") || s.contains("rust_panic") || s.contains("__rust_"))
        || memchr::memmem::find(bytes, b"/rustc/").is_some();
    Some(info)
}

/// String table (offset, size) of the `.dynamic` / `PT_DYNAMIC` entries.
fn read_dynamic(r: &Reader, info: &mut ElfInfo, links: &[u32]) {
    let ent = if info.is_64 { 16 } else { 8 };
    let (dyn_off, dyn_size, link) = match info.sections.iter().position(|s| s.sh_type == SHT_DYNAMIC) {
        Some(i) => (info.sections[i].offset, info.sections[i].size, links.get(i).copied()),
        None => match info.segments.iter().find(|s| s.p_type == PT_DYNAMIC) {
            Some(s) => (s.offset, s.filesz, None),
            None => return,
        },
    };
    let mut entries = Vec::new();
    for i in 0..(dyn_size / ent).min(MAX_DYN_ENTRIES as u64) {
        let at = dyn_off.saturating_add(i * ent);
        let (Some(tag), Some(val)) = (r.word(at, info.is_64), r.word(at + ent / 2, info.is_64)) else { break };
        if tag == 0 {
            break;
        }
        entries.push((tag, val));
    }
    let strtab = link
        .and_then(|l| info.sections.get(l as usize))
        .map(|s| (s.offset, s.size))
        .or_else(|| {
            let addr = entries.iter().find(|(t, _)| *t == DT_STRTAB)?.1;
            let size = entries.iter().find(|(t, _)| *t == DT_STRSZ).map_or(u64::MAX, |e| e.1);
            Some((info.vaddr_to_offset(addr)?, size))
        });
    let Some((str_off, str_size)) = strtab else { return };
    let string = |off: u64| -> String {
        if off >= str_size {
            return String::new();
        }
        r.cstr(str_off.saturating_add(off), MAX_NAME).unwrap_or_default()
    };
    for (tag, val) in entries {
        match tag {
            DT_NEEDED => push_capped(&mut info.needed, string(val)),
            DT_RPATH | DT_RUNPATH => push_capped(&mut info.rpaths, string(val)),
            _ => {}
        }
    }
}

/// Imports and exports from `.dynsym`, or `.symtab` when there is no `.dynsym`.
fn read_symbols(r: &Reader, info: &mut ElfInfo, links: &[u32]) {
    let table = info
        .sections
        .iter()
        .position(|s| s.sh_type == SHT_DYNSYM)
        .or_else(|| info.sections.iter().position(|s| s.sh_type == SHT_SYMTAB));
    let Some(ti) = table else { return };
    let (sym_off, sym_size) = (info.sections[ti].offset, info.sections[ti].size);
    let Some(strtab) = links.get(ti).and_then(|l| info.sections.get(*l as usize)) else { return };
    let (str_off, str_size) = (strtab.offset, strtab.size);
    let ent = if info.is_64 { 24 } else { 16 };
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    // Entry 0 is the null symbol.
    for i in 1..(sym_size / ent).min(MAX_SYMBOLS as u64) {
        let at = sym_off.saturating_add(i * ent);
        let Some(name) = r.u32(at).map(u64::from) else { break };
        let (st_info, shndx) = if info.is_64 { (r.u8(at + 4), r.u16(at + 6)) } else { (r.u8(at + 12), r.u16(at + 14)) };
        let (Some(st_info), Some(shndx)) = (st_info, shndx) else { break };
        if name == 0 || name >= str_size {
            continue;
        }
        let bind = st_info >> 4;
        let kind = st_info & 0xf;
        let Some(n) = r.cstr(str_off.saturating_add(name), MAX_NAME) else { continue };
        if shndx == 0 {
            if kind != 4 && kind != 3 {
                push_capped(&mut imports, n);
            }
        } else if (bind == 1 || bind == 2) && (kind == 1 || kind == 2) {
            push_capped(&mut exports, n);
        }
    }
    info.imports = imports;
    info.exports = exports;
}

fn read_build_id(r: &Reader, info: &mut ElfInfo) {
    let notes: Vec<(u64, u64)> = info
        .sections
        .iter()
        .filter(|s| s.sh_type == SHT_NOTE)
        .map(|s| (s.offset, s.size))
        .chain(info.segments.iter().filter(|s| s.p_type == PT_NOTE).map(|s| (s.offset, s.filesz)))
        .take(64)
        .collect();
    for (off, size) in notes {
        let end = off.saturating_add(size);
        let mut at = off;
        for _ in 0..256 {
            if at.saturating_add(12) > end {
                break;
            }
            let (Some(namesz), Some(descsz), Some(kind)) = (r.u32(at), r.u32(at + 4), r.u32(at + 8)) else { break };
            let name_at = at + 12;
            let desc_at = name_at + u64::from(namesz).next_multiple_of(4);
            let next = desc_at.saturating_add(u64::from(descsz).next_multiple_of(4));
            if next > end || next <= at {
                break;
            }
            if kind == NT_GNU_BUILD_ID && r.slice(name_at, u64::from(namesz)) == Some(b"GNU\0".as_slice()) && descsz <= 64
                && let Some(desc) = r.slice(desc_at, u64::from(descsz))
            {
                info.build_id = Some(hex::encode(desc));
                return;
            }
            at = next;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Little-endian 64-bit ELF: `.dynstr`, `.dynsym` (imports `mprotect`,
    /// `dlopen`, export `run_payload`), `.dynamic` (`DT_NEEDED libc.so.6`,
    /// `libdl.so.2`), a GNU build-id note, an RWX `PT_LOAD` with a BSS gap,
    /// `PT_GNU_STACK` with `X`, and a `.text` section holding the entry point.
    pub fn build_elf64(imports: &[&str]) -> Vec<u8> {
        let mut dynstr = vec![0u8];
        fn add(s: &str, t: &mut Vec<u8>) -> u32 {
            let at = t.len() as u32;
            t.extend_from_slice(s.as_bytes());
            t.push(0);
            at
        }
        let libc = add("libc.so.6", &mut dynstr);
        let libdl = add("libdl.so.2", &mut dynstr);
        let import_names: Vec<u32> = imports.iter().map(|s| add(s, &mut dynstr)).collect();
        let export = add("run_payload", &mut dynstr);
        let mut shstr = vec![0u8];
        let names: Vec<u32> = [".text", ".dynstr", ".dynsym", ".dynamic", ".note.gnu.build-id", ".shstrtab"]
            .iter()
            .map(|n| add(n, &mut shstr))
            .collect();

        let mut dynsym = vec![0u8; 24];
        for n in &import_names {
            let mut e = vec![0u8; 24];
            e[0..4].copy_from_slice(&n.to_le_bytes());
            e[4] = 0x12; // GLOBAL FUNC
            dynsym.extend(e);
        }
        let mut e = vec![0u8; 24];
        e[0..4].copy_from_slice(&export.to_le_bytes());
        e[4] = 0x12;
        e[6..8].copy_from_slice(&1u16.to_le_bytes());
        dynsym.extend(e);

        let mut dynamic = Vec::new();
        for (t, v) in [(DT_NEEDED, libc as u64), (DT_NEEDED, libdl as u64), (0, 0)] {
            dynamic.extend(t.to_le_bytes());
            dynamic.extend(v.to_le_bytes());
        }
        let mut note = Vec::new();
        note.extend(4u32.to_le_bytes());
        note.extend(8u32.to_le_bytes());
        note.extend(NT_GNU_BUILD_ID.to_le_bytes());
        note.extend(b"GNU\0");
        note.extend([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
        let text = vec![0x90u8; 32];

        let mut out = vec![0u8; 64];
        let phoff = out.len() as u64;
        out.extend(vec![0u8; 56 * 2]);
        fn place(data: &[u8], out: &mut Vec<u8>) -> u64 {
            let at = out.len() as u64;
            out.extend_from_slice(data);
            while !out.len().is_multiple_of(8) {
                out.push(0);
            }
            at
        }
        let text_at = place(&text, &mut out);
        let dynstr_at = place(&dynstr, &mut out);
        let dynsym_at = place(&dynsym, &mut out);
        let dynamic_at = place(&dynamic, &mut out);
        let note_at = place(&note, &mut out);
        let shstr_at = place(&shstr, &mut out);
        let shoff = out.len() as u64;
        let base = 0x400000u64;
        let sections = [
            (0, 0u32, 0u64, 0u64, 0u64, 0u32),
            (names[0], 1, SHF_ALLOC | SHF_EXECINSTR, text_at, text.len() as u64, 0),
            (names[1], 3, SHF_ALLOC, dynstr_at, dynstr.len() as u64, 0),
            (names[2], SHT_DYNSYM, SHF_ALLOC, dynsym_at, dynsym.len() as u64, 2),
            (names[3], SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynamic_at, dynamic.len() as u64, 2),
            (names[4], SHT_NOTE, SHF_ALLOC, note_at, note.len() as u64, 0),
            (names[5], 3, 0, shstr_at, shstr.len() as u64, 0),
        ];
        for (name, ty, flags, off, size, link) in sections {
            let mut sh = vec![0u8; 64];
            sh[0..4].copy_from_slice(&name.to_le_bytes());
            sh[4..8].copy_from_slice(&ty.to_le_bytes());
            sh[8..16].copy_from_slice(&flags.to_le_bytes());
            sh[16..24].copy_from_slice(&(if flags & SHF_ALLOC != 0 { base + off } else { 0 }).to_le_bytes());
            sh[24..32].copy_from_slice(&off.to_le_bytes());
            sh[32..40].copy_from_slice(&size.to_le_bytes());
            sh[40..44].copy_from_slice(&link.to_le_bytes());
            out.extend(sh);
        }
        let file_len = out.len() as u64;
        // PT_LOAD RWX over the whole file with a 64 KiB BSS gap, then PT_GNU_STACK RWX.
        for (i, (ty, flags, filesz, memsz)) in
            [(PT_LOAD, PF_R | PF_W | PF_X, file_len, file_len + 0x10000), (PT_GNU_STACK, PF_R | PF_W | PF_X, 0, 0)].into_iter().enumerate()
        {
            let at = phoff as usize + i * 56;
            out[at..at + 4].copy_from_slice(&ty.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            out[at + 16..at + 24].copy_from_slice(&(if ty == PT_LOAD { base } else { 0 }).to_le_bytes());
            out[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            out[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;
        out[16..18].copy_from_slice(&3u16.to_le_bytes());
        out[18..20].copy_from_slice(&62u16.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..32].copy_from_slice(&(base + text_at).to_le_bytes());
        out[32..40].copy_from_slice(&phoff.to_le_bytes());
        out[40..48].copy_from_slice(&shoff.to_le_bytes());
        out[52..54].copy_from_slice(&64u16.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&2u16.to_le_bytes());
        out[58..60].copy_from_slice(&64u16.to_le_bytes());
        out[60..62].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        out[62..64].copy_from_slice(&6u16.to_le_bytes());
        out
    }

    #[test]
    fn parses_the_synthetic_elf() {
        let elf = parse_elf(&build_elf64(&["mprotect", "dlopen"])).unwrap();
        assert!(elf.is_64 && elf.little_endian);
        assert_eq!((elf.e_type.as_str(), elf.machine.as_str()), ("dyn", "x86_64"));
        assert_eq!(elf.needed, vec!["libc.so.6", "libdl.so.2"]);
        assert_eq!(elf.imports, vec!["mprotect", "dlopen"]);
        assert_eq!(elf.exports, vec!["run_payload"]);
        assert_eq!(elf.build_id.as_deref(), Some("deadbeef01020304"));
        assert_eq!(elf.rwx_segment_count(), 1);
        assert!(elf.stripped);
        assert_eq!(elf.sections[elf.entry_section().unwrap()].name, ".text");
        assert_eq!(elf.entry_offset, Some(elf.sections[1].offset));
    }

    #[test]
    fn hostile_headers_do_not_panic() {
        let good = build_elf64(&["mprotect"]);
        for cut in [0, 5, 16, 63, 64, 200, good.len() / 2, good.len() - 1] {
            let _ = parse_elf(&good[..cut]);
        }
        let mut bad = good.clone();
        bad[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        bad[32..40].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        let elf = parse_elf(&bad).unwrap();
        assert!(elf.sections.is_empty() && elf.segments.is_empty());
        let mut flip = good;
        for b in flip.iter_mut().skip(64).step_by(7) {
            *b = 0xff;
        }
        let _ = parse_elf(&flip);
    }
}
