//! Disassembler for VirusKovAlyzer: x86 / x64 with iced-x86, ARM (A32), Thumb and
//! ARM64 with yaxpeax-arm (both pure Rust). Knows the layout of PE, ELF and Mach-O
//! files (architecture, image base, entry point, sections / segments) so code is shown
//! at its virtual address; any other file is decoded as raw bytes from offset 0.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};
use serde::Serialize;
use yaxpeax_arch::{Decoder as _, Reader, U8Reader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X64,
    Arm,
    Thumb,
    Arm64,
}

impl Arch {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "x86" | "x32" | "i386" => Arch::X86,
            "x64" | "x86_64" | "amd64" => Arch::X64,
            "arm" | "a32" | "armv7" => Arch::Arm,
            "thumb" | "t32" => Arch::Thumb,
            "arm64" | "aarch64" | "a64" => Arch::Arm64,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    pub name: String,
    pub va: u64,
    pub vsize: u64,
    pub offset: u64,
    pub file_size: u64,
    pub exec: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Layout {
    /// "PE", "ELF", "Mach-O" or "raw".
    pub format: &'static str,
    /// From the header; None when unknown (raw data).
    pub arch: Option<Arch>,
    pub image_base: u64,
    /// Entry point virtual address.
    pub entry: Option<u64>,
    pub regions: Vec<Region>,
    /// PE import address table: slot address -> "dll!function" (or "dll!#ordinal").
    #[serde(skip)]
    pub imports: std::collections::HashMap<u64, String>,
}

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

impl Layout {
    pub fn of(data: &[u8]) -> Layout {
        let mut l = pe(data).or_else(|| elf(data)).or_else(|| macho(data)).unwrap_or(Layout {
            format: "raw",
            arch: None,
            image_base: 0,
            entry: None,
            regions: Vec::new(),
            imports: Default::default(),
        });
        if l.format == "PE" {
            l.imports = pe_imports(data, &l);
        }
        l
    }

    /// Virtual address of a file offset (headers map to the image base for PE).
    pub fn off_to_va(&self, off: u64) -> u64 {
        for r in &self.regions {
            if off >= r.offset && off < r.offset + r.file_size {
                return r.va + (off - r.offset);
            }
        }
        if self.format == "PE" && self.regions.iter().all(|r| off < r.offset || r.file_size == 0) {
            return self.image_base + off;
        }
        // Outside every region: show the file offset.
        off
    }

    /// File offset of a virtual address, if that address is backed by file bytes.
    pub fn va_to_off(&self, va: u64) -> Option<u64> {
        for r in &self.regions {
            let size = r.vsize.max(r.file_size);
            if va >= r.va && va < r.va + size {
                let delta = va - r.va;
                return (delta < r.file_size).then_some(r.offset + delta);
            }
        }
        if self.format == "PE" && va >= self.image_base {
            let off = va - self.image_base;
            let first = self.regions.iter().filter(|r| r.file_size > 0).map(|r| r.offset).min().unwrap_or(u64::MAX);
            if off < first {
                return Some(off);
            }
        }
        if self.format == "raw" {
            return Some(va);
        }
        None
    }
}

fn pe(d: &[u8]) -> Option<Layout> {
    if d.get(0..2)? != b"MZ" {
        return None;
    }
    let nt = u32le(d, 0x3c)? as usize;
    if d.get(nt..nt + 4)? != b"PE\0\0" {
        return None;
    }
    let machine = u16le(d, nt + 4)?;
    let nsec = u16le(d, nt + 6)? as usize;
    let opt_size = u16le(d, nt + 20)? as usize;
    let opt = nt + 24;
    let magic = u16le(d, opt)?;
    let entry_rva = u32le(d, opt + 16)? as u64;
    let image_base = if magic == 0x20b { u64le(d, opt + 24)? } else { u32le(d, opt + 28)? as u64 };
    let arch = match machine {
        0x14c => Some(Arch::X86),
        0x8664 => Some(Arch::X64),
        0xaa64 => Some(Arch::Arm64),
        0x1c0 => Some(Arch::Arm),
        0x1c2 | 0x1c4 => Some(Arch::Thumb),
        _ => None,
    };
    let mut regions = Vec::new();
    let st = opt + opt_size;
    for i in 0..nsec.min(96) {
        let s = st + i * 40;
        let Some(raw) = d.get(s..s + 8) else { break };
        let name = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
        let ch = u32le(d, s + 36).unwrap_or(0);
        regions.push(Region {
            name,
            vsize: u32le(d, s + 8).unwrap_or(0) as u64,
            va: image_base + u32le(d, s + 12).unwrap_or(0) as u64,
            file_size: u32le(d, s + 16).unwrap_or(0) as u64,
            offset: u32le(d, s + 20).unwrap_or(0) as u64,
            exec: ch & 0x2000_0020 != 0,
        });
    }
    // ARMNT entry points have the Thumb bit set.
    let entry_rva = if arch == Some(Arch::Thumb) { entry_rva & !1 } else { entry_rva };
    Some(Layout { format: "PE", arch, image_base, entry: (entry_rva != 0).then_some(image_base + entry_rva), regions, imports: Default::default() })
}

fn elf(d: &[u8]) -> Option<Layout> {
    if d.get(0..4)? != b"\x7fELF" || *d.get(5)? != 1 {
        return None; // little-endian only
    }
    let is64 = *d.get(4)? == 2;
    let machine = u16le(d, 18)?;
    let (entry, phoff, phentsize, phnum) = if is64 {
        (u64le(d, 24)?, u64le(d, 32)? as usize, u16le(d, 54)? as usize, u16le(d, 56)? as usize)
    } else {
        (u32le(d, 24)? as u64, u32le(d, 28)? as usize, u16le(d, 42)? as usize, u16le(d, 44)? as usize)
    };
    let arch = match machine {
        3 => Some(Arch::X86),
        0x3e => Some(Arch::X64),
        0xb7 => Some(Arch::Arm64),
        0x28 => Some(if entry & 1 == 1 { Arch::Thumb } else { Arch::Arm }),
        _ => None,
    };
    let mut regions = Vec::new();
    for i in 0..phnum.min(256) {
        let p = phoff + i * phentsize;
        if u32le(d, p) != Some(1) {
            continue; // PT_LOAD only
        }
        let (flags, offset, vaddr, filesz, memsz) = if is64 {
            (u32le(d, p + 4)?, u64le(d, p + 8)?, u64le(d, p + 16)?, u64le(d, p + 32)?, u64le(d, p + 40)?)
        } else {
            (u32le(d, p + 24)?, u32le(d, p + 4)? as u64, u32le(d, p + 8)? as u64, u32le(d, p + 16)? as u64, u32le(d, p + 20)? as u64)
        };
        let perm = format!("{}{}{}", if flags & 4 != 0 { 'r' } else { '-' }, if flags & 2 != 0 { 'w' } else { '-' }, if flags & 1 != 0 { 'x' } else { '-' });
        regions.push(Region { name: format!("LOAD{} {perm}", regions.len()), va: vaddr, vsize: memsz, offset, file_size: filesz, exec: flags & 1 != 0 });
    }
    let image_base = regions.iter().map(|r| r.va).min().unwrap_or(0);
    Some(Layout { format: "ELF", arch, image_base, entry: (entry != 0).then_some(entry & !1), regions, imports: Default::default() })
}

fn macho(d: &[u8]) -> Option<Layout> {
    let magic = u32le(d, 0)?;
    let is64 = match magic {
        0xfeed_facf => true,
        0xfeed_face => false,
        _ => return None,
    };
    let cputype = u32le(d, 4)?;
    let arch = match cputype {
        7 => Some(Arch::X86),
        0x0100_0007 => Some(Arch::X64),
        12 => Some(Arch::Arm),
        0x0100_000c => Some(Arch::Arm64),
        _ => None,
    };
    let ncmds = u32le(d, 16)? as usize;
    let mut p = if is64 { 32 } else { 28 };
    let mut regions = Vec::new();
    let mut entryoff = None;
    for _ in 0..ncmds.min(512) {
        let cmd = u32le(d, p)?;
        let size = u32le(d, p + 4)? as usize;
        if size < 8 {
            break;
        }
        match cmd {
            0x19 => {
                let name = String::from_utf8_lossy(d.get(p + 8..p + 24)?).trim_end_matches('\0').to_string();
                let prot = u32le(d, p + 60)?;
                regions.push(Region { name, va: u64le(d, p + 24)?, vsize: u64le(d, p + 32)?, offset: u64le(d, p + 40)?, file_size: u64le(d, p + 48)?, exec: prot & 4 != 0 });
            }
            0x1 => {
                let name = String::from_utf8_lossy(d.get(p + 8..p + 24)?).trim_end_matches('\0').to_string();
                let prot = u32le(d, p + 44)?;
                regions.push(Region { name, va: u32le(d, p + 24)? as u64, vsize: u32le(d, p + 28)? as u64, offset: u32le(d, p + 32)? as u64, file_size: u32le(d, p + 36)? as u64, exec: prot & 4 != 0 });
            }
            0x8000_0028 => entryoff = u64le(d, p + 8),
            _ => {}
        }
        p += size;
    }
    regions.retain(|r| r.vsize > 0 || r.file_size > 0);
    let image_base = regions.iter().find(|r| r.offset == 0 && r.file_size > 0).map(|r| r.va).unwrap_or(0);
    let entry = entryoff.and_then(|off| regions.iter().find(|r| off >= r.offset && off < r.offset + r.file_size).map(|r| r.va + off - r.offset));
    Some(Layout { format: "Mach-O", arch, image_base, entry, regions, imports: Default::default() })
}

/// Import address table of a PE: every IAT slot address -> "dll!name".
fn pe_imports(d: &[u8], l: &Layout) -> std::collections::HashMap<u64, String> {
    let mut out = std::collections::HashMap::new();
    let (Some(nt), true) = (u32le(d, 0x3c).map(|v| v as usize), l.format == "PE") else { return out };
    let opt = nt + 24;
    let is64 = u16le(d, opt) == Some(0x20b);
    // Data directory 1 = imports.
    let dirs = opt + if is64 { 112 } else { 96 };
    let Some(imp_rva) = u32le(d, dirs + 8) else { return out };
    if imp_rva == 0 {
        return out;
    }
    let off_of = |rva: u64| l.va_to_off(l.image_base + rva).map(|o| o as usize);
    let cstr = |o: usize| -> String {
        d.get(o..).map(|s| s.iter().take(256).take_while(|b| **b != 0).map(|b| *b as char).collect()).unwrap_or_default()
    };
    let Some(mut desc) = off_of(imp_rva as u64) else { return out };
    for _ in 0..4096 {
        let (Some(oft), Some(name_rva), Some(ft)) = (u32le(d, desc), u32le(d, desc + 12), u32le(d, desc + 16)) else { break };
        if name_rva == 0 && ft == 0 {
            break;
        }
        let dll = off_of(name_rva as u64).map(cstr).unwrap_or_default().to_ascii_lowercase();
        let lookup = if oft != 0 { oft } else { ft };
        if let Some(mut t) = off_of(lookup as u64) {
            let step = if is64 { 8 } else { 4 };
            for i in 0..65_536u64 {
                let v = if is64 { u64le(d, t) } else { u32le(d, t).map(|x| x as u64) };
                let Some(v) = v else { break };
                if v == 0 {
                    break;
                }
                let by_ordinal = if is64 { v >> 63 == 1 } else { v >> 31 == 1 };
                let func = if by_ordinal {
                    format!("#{}", v & 0xffff)
                } else {
                    off_of(v & 0x7fff_ffff).map(|o| cstr(o + 2)).unwrap_or_default()
                };
                out.insert(l.image_base + ft as u64 + i * step, format!("{dll}!{func}"));
                t += step as usize;
            }
        }
        desc += 20;
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    pub offset: u64,
    pub va: u64,
    pub bytes: String,
    pub text: String,
    /// "call", "jmp", "jcc", "ret" or "" for anything else.
    pub flow: &'static str,
    /// Branch / call target, or the address a RIP-relative operand points at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    /// Imported function the instruction calls / jumps to / loads ("kernel32.dll!CreateFileW").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

const MAX_INSNS: usize = 2000;

/// Decodes `count` instructions starting at file offset `start` (shown at the
/// address the layout gives that offset).
pub fn disassemble(data: &[u8], layout: &Layout, arch: Arch, start: u64, count: usize) -> Vec<Insn> {
    let count = count.clamp(1, MAX_INSNS);
    let start = (start as usize).min(data.len());
    // Never run past the region the start offset is in (into the next section).
    let end = layout
        .regions
        .iter()
        .find(|r| start as u64 >= r.offset && (start as u64) < r.offset + r.file_size)
        .map(|r| (r.offset + r.file_size) as usize)
        .unwrap_or(data.len())
        .min(data.len());
    let va = layout.off_to_va(start as u64);
    let code = &data[start..end];
    match arch {
        Arch::X86 | Arch::X64 => {
            let mut v = x86(code, start as u64, va, if arch == Arch::X64 { 64 } else { 32 }, count);
            if !layout.imports.is_empty() {
                name_imports(data, layout, arch, &mut v);
            }
            v
        }
        Arch::Arm64 => arm64(code, start as u64, va, count),
        Arch::Arm | Arch::Thumb => arm32(code, start as u64, va, arch == Arch::Thumb, count),
    }
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn x86(code: &[u8], off: u64, va: u64, bits: u32, count: usize) -> Vec<Insn> {
    let mut dec = Decoder::with_ip(bits, code, va, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_first_operand_char_index(8);
    fmt.options_mut().set_space_after_operand_separator(true);
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_branch_leading_zeros(false);
    let mut out = Vec::new();
    let mut insn = iced_x86::Instruction::default();
    while dec.can_decode() && out.len() < count {
        let pos = dec.position();
        dec.decode_out(&mut insn);
        let len = insn.len().max(1);
        let bytes = &code[pos..(pos + len).min(code.len())];
        let mut text = String::new();
        if insn.is_invalid() {
            text = format!("db {:#04x}", code[pos]);
        } else {
            fmt.format(&insn, &mut text);
        }
        let (flow, target) = match insn.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => ("call", near_target(&insn)),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => ("jmp", near_target(&insn)),
            FlowControl::ConditionalBranch => ("jcc", near_target(&insn)),
            FlowControl::Return => ("ret", None),
            _ => ("", insn.is_ip_rel_memory_operand().then(|| insn.ip_rel_memory_address())),
        };
        out.push(Insn { offset: off + pos as u64, va: insn.ip(), bytes: hex_bytes(bytes), text, flow, target, symbol: None });
    }
    out
}

/// Memory operand address of `[abs]` / `[rip+x]` (no base / index register).
fn mem_address(insn: &iced_x86::Instruction) -> Option<u64> {
    if insn.is_ip_rel_memory_operand() {
        return Some(insn.ip_rel_memory_address());
    }
    let has_mem = (0..insn.op_count()).any(|i| insn.op_kind(i) == OpKind::Memory);
    (has_mem && insn.memory_base() == iced_x86::Register::None && insn.memory_index() == iced_x86::Register::None)
        .then(|| insn.memory_displacement64())
}

/// Adds the imported function name to calls / jumps / loads through the IAT, and to
/// direct calls of `jmp [IAT]` thunks.
fn name_imports(data: &[u8], layout: &Layout, arch: Arch, insns: &mut [Insn]) {
    let bits = if arch == Arch::X64 { 64 } else { 32 };
    for ins in insns.iter_mut() {
        let mut dec = Decoder::with_ip(bits, data.get(ins.offset as usize..).unwrap_or(&[]), ins.va, DecoderOptions::NONE);
        let i = dec.decode();
        let mut sym = mem_address(&i).and_then(|a| layout.imports.get(&a).cloned());
        if sym.is_none() && (ins.flow == "call" || ins.flow == "jmp") {
            // call thunk -> jmp [IAT]
            if let Some(t) = ins.target.and_then(|t| layout.va_to_off(t)) {
                let mut td = Decoder::with_ip(bits, data.get(t as usize..).unwrap_or(&[]), ins.target.unwrap(), DecoderOptions::NONE);
                let ti = td.decode();
                if ti.flow_control() == FlowControl::IndirectBranch {
                    sym = mem_address(&ti).and_then(|a| layout.imports.get(&a).cloned());
                }
            }
        }
        if let Some(s) = sym {
            ins.text.push_str(&format!("  ; {s}"));
            ins.symbol = Some(s);
        }
    }
}

fn near_target(insn: &iced_x86::Instruction) -> Option<u64> {
    match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Some(insn.near_branch_target()),
        _ => insn.is_ip_rel_memory_operand().then(|| insn.ip_rel_memory_address()),
    }
}

/// `$+0x10` / `$-0x8` in yaxpeax text -> absolute address.
fn rel_target(text: &str, va: u64) -> Option<u64> {
    let i = text.find('$')?;
    let rest = &text[i + 1..];
    let (neg, rest) = match rest.chars().next()? {
        '+' => (false, &rest[1..]),
        '-' => (true, &rest[1..]),
        _ => return None,
    };
    let hex = rest.strip_prefix("0x")?;
    let n: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    let v = u64::from_str_radix(&n, 16).ok()?;
    Some(if neg { va.wrapping_sub(v) } else { va.wrapping_add(v) })
}

fn arm_flow(text: &str) -> &'static str {
    let m = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    let m = m.trim_end_matches(".w").trim_end_matches(".n");
    match m {
        "bl" | "blx" | "blr" => "call",
        "ret" | "eret" => "ret",
        "b" | "br" | "bx" => "jmp",
        _ if m.starts_with("b.") || m.starts_with("cb") || m.starts_with("tb") => "jcc",
        _ if m.starts_with('b') && m.len() == 3 && !matches!(m, "bic" | "bfi" | "bfc" | "brk" | "bkpt") => "jcc", // beq, bne, ...
        _ => "",
    }
}

fn arm64(code: &[u8], off: u64, va: u64, count: usize) -> Vec<Insn> {
    let dec = yaxpeax_arm::armv8::a64::InstDecoder::default();
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= code.len() && out.len() < count {
        let addr = va + pos as u64;
        let bytes = &code[pos..pos + 4];
        let mut r = U8Reader::new(bytes);
        let text = match dec.decode(&mut r) {
            Ok(i) => i.to_string(),
            Err(_) => format!(".word {:#010x}", u32::from_le_bytes(bytes.try_into().unwrap())),
        };
        let flow = arm_flow(&text);
        let target = if flow.is_empty() && !text.starts_with("adr") { None } else { rel_target(&text, addr) };
        out.push(Insn { offset: off + pos as u64, va: addr, bytes: hex_bytes(bytes), text, flow, target, symbol: None });
        pos += 4;
    }
    out
}

fn arm32(code: &[u8], off: u64, va: u64, thumb: bool, count: usize) -> Vec<Insn> {
    let dec = if thumb { yaxpeax_arm::armv7::InstDecoder::default_thumb() } else { yaxpeax_arm::armv7::InstDecoder::default() };
    let step = if thumb { 2 } else { 4 };
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + step <= code.len() && out.len() < count {
        let addr = va + pos as u64;
        let mut r = U8Reader::new(&code[pos..]);
        let (text, len) = match dec.decode(&mut r) {
            Ok(i) => {
                let n = <U8Reader as Reader<u32, u8>>::total_offset(&mut r) as usize;
                (i.to_string(), n.max(step))
            }
            Err(_) => (format!(".inst {}", hex_bytes(&code[pos..pos + step])), step),
        };
        let len = len.min(code.len() - pos);
        let flow = arm_flow(&text);
        // A32 offsets already include the PC+8 bias; Thumb ones are relative to PC+4
        // (and BLX to ARM code to PC+4 aligned down to 4).
        let base = if !thumb {
            addr
        } else if text.starts_with("blx") {
            (addr + 4) & !3
        } else {
            addr + 4
        };
        let target = if flow.is_empty() { None } else { rel_target(&text, base) };
        out.push(Insn { offset: off + pos as u64, va: addr, bytes: hex_bytes(&code[pos..pos + len]), text, flow, target, symbol: None });
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> Layout {
        Layout { format: "raw", arch: None, image_base: 0, entry: None, regions: Vec::new(), imports: Default::default() }
    }

    #[test]
    fn x64_branches() {
        // push rbp; call +5; jne -2; ret
        let code = [0x55, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x75, 0xfe, 0xc3];
        let v = disassemble(&code, &raw(), Arch::X64, 0, 10);
        assert_eq!(v.len(), 4);
        assert!(v[0].text.starts_with("push"), "{}", v[0].text);
        assert_eq!((v[1].flow, v[1].target), ("call", Some(6)));
        assert_eq!((v[2].flow, v[2].target), ("jcc", Some(6)));
        assert_eq!(v[3].flow, "ret");
    }

    #[test]
    fn arm64_and_arm() {
        // nop; bl +8; ret
        let code = [0x1f, 0x20, 0x03, 0xd5, 0x02, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6];
        let v = disassemble(&code, &raw(), Arch::Arm64, 0, 10);
        assert_eq!(v[0].text, "nop");
        assert_eq!((v[1].flow, v[1].target), ("call", Some(4 + 8)));
        assert_eq!(v[2].flow, "ret");
        // A32: b . (branch to itself)
        let v = disassemble(&[0xfe, 0xff, 0xff, 0xea], &raw(), Arch::Arm, 0, 1);
        assert_eq!((v[0].flow, v[0].target), ("jmp", Some(0)), "{}", v[0].text);
        // Thumb: bx lr
        let v = disassemble(&[0x70, 0x47], &raw(), Arch::Thumb, 0, 1);
        assert!(v[0].text.starts_with("bx"), "{}", v[0].text);
        // Thumb: b.n . (0xe7fe) branches to itself; bl.w with imm 0x45c2 from PC+4
        let v = disassemble(&[0xfe, 0xe7], &raw(), Arch::Thumb, 0, 1);
        assert_eq!(v[0].target, Some(0), "{}", v[0].text);
        let v = disassemble(&[0x04, 0xf0, 0xe1, 0xfa], &raw(), Arch::Thumb, 0, 1);
        assert_eq!(v[0].target, Some(4 + 0x45c2), "{}", v[0].text);
    }

    #[test]
    fn pe_layout() {
        let mut d = vec![0u8; 0x400];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3c] = 0x80;
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        d[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let opt = 0x98;
        d[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        d[opt + 16..opt + 20].copy_from_slice(&0x1010u32.to_le_bytes());
        d[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        let s = opt + 0xf0;
        d[s..s + 5].copy_from_slice(b".text");
        d[s + 8..s + 12].copy_from_slice(&0x100u32.to_le_bytes());
        d[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        d[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
        d[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        d[s + 36..s + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let l = Layout::of(&d);
        assert_eq!((l.format, l.arch, l.entry), ("PE", Some(Arch::X64), Some(0x1_4000_1010)));
        assert_eq!(l.va_to_off(0x1_4000_1010), Some(0x210));
        assert_eq!(l.off_to_va(0x210), 0x1_4000_1010);
        assert_eq!(l.va_to_off(0x1_4000_0080), Some(0x80), "headers");
    }
}
