//! `opcode_pattern` condition: x86 / x64 and AArch64 instruction patterns over disassembled code.
//!
//! A pattern is a list of steps separated by `;` or new lines. A step is one
//! instruction: a mnemonic (`mov`, alternatives `mov|lea`, glob `j*`, `*` = any
//! instruction), optionally followed by operand patterns separated by `,`. An operand
//! pattern is `reg`, `mem`, `imm`, `*`, or a glob (`*`, `?`) over the operand as the
//! Intel formatter writes it: lower case, numbers in hex (`0x5a`), spaces ignored,
//! `byte ptr [eax+4]` (the size may be left out: `[eax+*]`), alternatives with `|`. Without operands any
//! operands match; with them, the operand count must be the same. A step `[n]`,
//! `[n-m]` or `[n-]` lets n..m other instructions come in between (at most 64).
//!
//! Matching works on what the bytes decode to, so every encoding of an instruction
//! (`89 D8` and `8B C3` are both `mov eax,ebx`) and every register choice a glob
//! allows match the same step. The region is decoded once per scan (iced-x86 linear
//! sweep) into a compact list of (mnemonic, offset, length); operands are only
//! formatted for instructions whose mnemonic already fits.
//!
//! `arch: arm64` (or `auto` on an AArch64 PE / ELF / Mach-O) decodes A64 words
//! with [`super::arm64`]; operands are written as that module describes
//! (`[sp,#-0x10]!` in a pattern reads as `[sp,-0x10]!`).
//!
//! `mode: cfg` decodes from the region start along the control flow instead of
//! linearly: conditional branches (and with `follow_calls` direct calls) open
//! new blocks, an unconditional direct `jmp` / `b` continues at its target as if
//! the code were contiguous (the jump itself is left out), and decoding stops
//! after a return, an indirect branch, an invalid instruction or code already
//! decoded. Each such run is matched on its own, so junk bytes after a jump and
//! code split into islands match like straight-line code. `max_blocks` (256,
//! at most 2048) and `max_insns` (8192, at most 65536) bound the walk.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, MemorySizeOptions, Mnemonic, OpKind};

use super::arm64;
use super::pe_anchor::{self, AnchorKind};
use super::pe_section::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use super::types::RuleCondition;
use crate::models::PeInfo;
use crate::scanner::{elf::ElfInfo, macho::MachoInfo};

/// Most instructions one gap step may skip.
pub const MAX_GAP: usize = 64;
/// Most bytes decoded per region (`max_bytes` is capped to it).
pub const MAX_REGION_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_ENTRY_BYTES: usize = 4096;
const DEFAULT_REGION_BYTES: usize = 4 * 1024 * 1024;
const MAX_STEPS: usize = 64;
/// Step checks one pattern may spend on one region (bounds patterns with many gaps).
const MATCH_BUDGET: usize = 4_000_000;
/// Instructions of a match written to the finding.
const SHOWN: usize = 8;
/// `mode: cfg` budgets: defaults and caps.
pub const DEFAULT_MAX_BLOCKS: usize = 256;
pub const MAX_MAX_BLOCKS: usize = 2048;
pub const DEFAULT_MAX_INSNS: usize = 8192;
pub const MAX_MAX_INSNS: usize = 65536;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// Instruction set of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    /// x86 with this bitness (16, 32, 64).
    X86(u32),
    Arm64,
}

#[derive(Debug, Clone, PartialEq)]
enum OpPat {
    Any,
    Reg,
    Mem,
    Imm,
    /// `|`-separated alternatives.
    Glob(Vec<String>),
}

#[derive(Debug, Clone)]
enum Step {
    /// `mnemonics: None` = any instruction; `operands: None` = any operands.
    /// Mnemonic ids are iced `Mnemonic` values (x86) or `arm64::MNEMONICS` indexes.
    Insn { mnemonics: Option<Vec<u16>>, operands: Option<Vec<OpPat>> },
    Gap { min: usize, max: usize },
}

#[derive(Debug)]
pub struct Compiled {
    steps: Vec<Step>,
}

/// Every mnemonic with its lower-case name, for globs over mnemonics.
fn mnemonic_names() -> &'static [(Mnemonic, String)] {
    static NAMES: OnceLock<Vec<(Mnemonic, String)>> = OnceLock::new();
    NAMES.get_or_init(|| {
        Mnemonic::values()
            .filter(|m| *m != Mnemonic::INVALID)
            .map(|m| (m, format!("{m:?}").to_ascii_lowercase()))
            .collect()
    })
}

/// `*` (any run) and `?` (one character) glob, whole string.
fn glob(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pat[p..].iter().all(|&c| c == b'*')
}

fn normalize(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase()
}

/// AArch64 operand text: no spaces, no `#`, lower case.
fn normalize_arm(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && *c != '#').collect::<String>().to_ascii_lowercase()
}

/// Mnemonics matching one `|`-separated mnemonic glob list.
pub fn mnemonic_set(spec: &str) -> Result<Vec<Mnemonic>, String> {
    let mut out = Vec::new();
    for alt in spec.split('|').map(|a| a.trim().to_ascii_lowercase()).filter(|a| !a.is_empty()) {
        let before = out.len();
        out.extend(mnemonic_names().iter().filter(|(_, n)| glob(alt.as_bytes(), n.as_bytes())).map(|(m, _)| *m));
        if out.len() == before {
            return Err(format!("unknown mnemonic `{alt}`"));
        }
    }
    if out.is_empty() {
        return Err(format!("empty mnemonic `{spec}`"));
    }
    out.sort_unstable_by_key(|m| *m as u32);
    out.dedup();
    Ok(out)
}

/// AArch64 mnemonics matching one `|`-separated glob list.
pub fn arm64_mnemonic_set(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for alt in spec.split('|').map(|a| a.trim().to_ascii_lowercase()).filter(|a| !a.is_empty()) {
        let before = out.len();
        out.extend(
            arm64::MNEMONICS.iter().enumerate().filter(|(_, n)| glob(alt.as_bytes(), n.as_bytes())).map(|(i, _)| i as u16),
        );
        if out.len() == before {
            return Err(format!("unknown arm64 mnemonic `{alt}`"));
        }
    }
    if out.is_empty() {
        return Err(format!("empty mnemonic `{spec}`"));
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn mnemonic_ids(spec: &str, arm: bool) -> Result<Vec<u16>, String> {
    if arm {
        arm64_mnemonic_set(spec)
    } else {
        Ok(mnemonic_set(spec)?.into_iter().map(|m| m as u16).collect())
    }
}

fn parse_gap(inner: &str) -> Result<Step, String> {
    let num = |s: &str| s.trim().parse::<usize>().map_err(|_| format!("invalid gap `[{inner}]`"));
    let (min, max) = match inner.split_once('-') {
        None => {
            let n = num(inner)?;
            (n, n)
        }
        Some((a, b)) => (
            if a.trim().is_empty() { 0 } else { num(a)? },
            if b.trim().is_empty() { MAX_GAP } else { num(b)? },
        ),
    };
    if min > max || max > MAX_GAP {
        return Err(format!("gap `[{inner}]` must be n-m with n <= m <= {MAX_GAP}"));
    }
    Ok(Step::Gap { min, max })
}

/// Operands of a step, split at commas outside `[...]`.
fn split_operands(rest: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in rest.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&rest[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&rest[start..]);
    out
}

/// Compiles an x86 pattern (module notes), or says what is wrong with it.
pub fn compile(pattern: &str) -> Result<Compiled, String> {
    compile_for(pattern, false)
}

/// Compiles an AArch64 pattern.
pub fn compile_arm64(pattern: &str) -> Result<Compiled, String> {
    compile_for(pattern, true)
}

fn compile_for(pattern: &str, arm: bool) -> Result<Compiled, String> {
    let mut steps = Vec::new();
    for raw in pattern.split([';', '\n']).map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            steps.push(parse_gap(inner)?);
            continue;
        }
        let (mn, rest) = match raw.find(char::is_whitespace) {
            Some(i) => (&raw[..i], raw[i..].trim()),
            None => (raw, ""),
        };
        let mnemonics = if mn == "*" { None } else { Some(mnemonic_ids(mn, arm)?) };
        let operands = if rest.is_empty() {
            None
        } else {
            Some(
                split_operands(rest)
                    .into_iter()
                    .map(|o| match (if arm { normalize_arm(o) } else { normalize(o) }).as_str() {
                        "" => Err(format!("empty operand in `{raw}`")),
                        "*" => Ok(OpPat::Any),
                        "reg" => Ok(OpPat::Reg),
                        "mem" => Ok(OpPat::Mem),
                        "imm" => Ok(OpPat::Imm),
                        g => Ok(OpPat::Glob(g.split('|').map(str::to_string).collect())),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        };
        steps.push(Step::Insn { mnemonics, operands });
    }
    if !steps.iter().any(|s| matches!(s, Step::Insn { .. })) {
        return Err("no instruction step".into());
    }
    if steps.len() > MAX_STEPS {
        return Err(format!("more than {MAX_STEPS} steps"));
    }
    Ok(Compiled { steps })
}

fn cached(pattern: &str, arm: bool) -> Option<Arc<Compiled>> {
    static CACHE: LazyLock<Mutex<HashMap<(String, bool), Option<Arc<Compiled>>>>> = LazyLock::new(Default::default);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    c.entry((pattern.to_string(), arm)).or_insert_with(|| compile_for(pattern, arm).ok().map(Arc::new)).clone()
}

/// Where code is decoded: file bytes `start..end`, address of `start`, instruction set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    start: usize,
    end: usize,
    ip: u64,
    arch: Arch,
}

/// The executable headers `opcode_pattern` reads.
#[derive(Clone, Copy, Default)]
pub struct Exe<'a> {
    pub pe: Option<&'a PeInfo>,
    pub elf: Option<&'a ElfInfo>,
    pub macho: Option<&'a MachoInfo>,
}

/// `arch` / `bitness` of a condition: an explicit choice, or None for `auto`.
fn explicit_arch(arch: Option<&str>, bitness: Option<u32>) -> Option<Arch> {
    match arch.map(|a| a.trim().to_ascii_lowercase()).as_deref() {
        Some("arm64" | "aarch64") => Some(Arch::Arm64),
        Some("x64" | "x86_64" | "amd64") => Some(Arch::X86(64)),
        Some("x86" | "i386") => Some(Arch::X86(bitness.filter(|b| *b != 64).unwrap_or(32))),
        _ => None,
    }
}

pub fn valid_arch(arch: &str) -> bool {
    matches!(arch.trim().to_ascii_lowercase().as_str(), "auto" | "x86" | "i386" | "x64" | "x86_64" | "amd64" | "arm64" | "aarch64")
}

pub fn valid_mode(mode: &str) -> bool {
    matches!(mode.trim().to_ascii_lowercase().as_str(), "linear" | "cfg")
}

/// PE `FileHeader.Machine`.
fn pe_machine(bytes: &[u8]) -> Option<u16> {
    let at = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let m = bytes.get(at.checked_add(4)?..at.checked_add(6)?)?;
    (bytes.get(at..at + 4)? == b"PE\0\0").then(|| u16::from_le_bytes([m[0], m[1]]))
}

/// The regions a `region` value names (several for `code`), or None when this file
/// has no such region (not a PE / ELF / Mach-O, no such section).
///
/// Without an `arch` key (`auto_detect` false) only the PE regions exist and a
/// PE is always decoded as x86 of its own bitness, as before `arch` existed;
/// with it, an AArch64 PE decodes as `arm64` and ELF / Mach-O files have
/// `entry` and `code` regions too.
fn regions(region: &str, max_bytes: Option<usize>, chosen: Option<Arch>, auto_detect: bool, bitness: Option<u32>, exe: Exe, bytes: &[u8]) -> Option<Vec<Region>> {
    let len = bytes.len();
    let pe = exe.pe;
    let pe_bits = pe.map(|p| if p.is_64 { 64 } else { 32 });
    let pe_arch = pe.map(|p| {
        if auto_detect && pe_machine(bytes) == Some(IMAGE_FILE_MACHINE_ARM64) { Arch::Arm64 } else { Arch::X86(if p.is_64 { 64 } else { 32 }) }
    });
    let exe = if auto_detect { exe } else { Exe { pe, ..Exe::default() } };
    let elf_arch = exe.elf.map(|e| if e.e_machine == 183 { Arch::Arm64 } else { Arch::X86(if e.is_64 { 64 } else { 32 }) });
    let max = |default: usize| max_bytes.unwrap_or(default).clamp(1, MAX_REGION_BYTES);
    let span = |start: usize, limit: usize| (start < len).then(|| (start, start.saturating_add(limit).min(len)));
    let pick = |native: Arch| chosen.unwrap_or(native);
    let raw_arch = chosen.unwrap_or(Arch::X86(bitness.or(pe_bits).unwrap_or(32)));
    let lower = region.trim().to_ascii_lowercase();
    let out = match lower.as_str() {
        "entry" | "ep" | "%ep%" => {
            if let Some(pe) = pe {
                let off = pe_anchor::entry_file_offset(pe, len as u64)? as usize;
                let (start, end) = span(off, max(DEFAULT_ENTRY_BYTES))?;
                vec![Region { start, end, ip: pe.image_base.wrapping_add(pe.entry), arch: pick(pe_arch?) }]
            } else if let Some(elf) = exe.elf {
                let (start, end) = span(usize::try_from(elf.entry_offset?).ok()?, max(DEFAULT_ENTRY_BYTES))?;
                vec![Region { start, end, ip: elf.entry, arch: pick(elf_arch?) }]
            } else {
                exe.macho?
                    .slices
                    .iter()
                    .filter_map(|s| {
                        let off = s.entry_offset?;
                        let (start, end) = span(usize::try_from(off).ok()?, max(DEFAULT_ENTRY_BYTES))?;
                        let rel = off.checked_sub(s.offset)?;
                        let seg = s.segments.iter().find(|g| rel >= g.fileoff && rel - g.fileoff < g.filesize)?;
                        let arch = if s.cputype == crate::scanner::macho::CPU_TYPE_ARM64 { Arch::Arm64 } else { Arch::X86(if s.is_64 { 64 } else { 32 }) };
                        Some(Region { start, end, ip: seg.vmaddr.wrapping_add(rel - seg.fileoff), arch: pick(arch) })
                    })
                    .collect()
            }
        }
        "code" => {
            if let Some(pe) = pe {
                pe.sections
                    .iter()
                    .filter(|s| s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0 && s.raw_size > 0)
                    .filter_map(|s| {
                        let (start, end) = span(s.raw_offset as usize, (s.raw_size as usize).min(max(DEFAULT_REGION_BYTES)))?;
                        Some(Region { start, end, ip: pe.image_base.wrapping_add(s.virtual_address), arch: pick(pe_arch?) })
                    })
                    .collect()
            } else if let Some(elf) = exe.elf {
                elf.sections
                    .iter()
                    .filter(|s| s.flags & crate::scanner::elf::SHF_EXECINSTR != 0 && s.size > 0 && s.sh_type != 8)
                    .filter_map(|s| {
                        let (start, end) = span(usize::try_from(s.offset).ok()?, usize::try_from(s.size).ok()?.min(max(DEFAULT_REGION_BYTES)))?;
                        Some(Region { start, end, ip: s.addr, arch: pick(elf_arch?) })
                    })
                    .collect()
            } else {
                // Mach-O sections holding instructions (S_ATTR_PURE / SOME_INSTRUCTIONS).
                exe.macho?
                    .slices
                    .iter()
                    .flat_map(|sl| sl.sections.iter().map(move |s| (sl, s)))
                    .filter(|(_, s)| s.flags & 0x8000_0400 != 0 && s.size > 0)
                    .filter_map(|(sl, s)| {
                        let off = sl.offset.checked_add(s.offset)?;
                        let (start, end) = span(usize::try_from(off).ok()?, usize::try_from(s.size).ok()?.min(max(DEFAULT_REGION_BYTES)))?;
                        let seg = sl.segments.iter().find(|g| s.offset >= g.fileoff && s.offset - g.fileoff < g.filesize.max(1))?;
                        let arch = if sl.cputype == crate::scanner::macho::CPU_TYPE_ARM64 { Arch::Arm64 } else { Arch::X86(if sl.is_64 { 64 } else { 32 }) };
                        Some(Region { start, end, ip: seg.vmaddr.wrapping_add(s.offset - seg.fileoff), arch: pick(arch) })
                    })
                    .collect()
            }
        }
        "overlay" | "%eope%" => {
            let off = pe_anchor::resolve(AnchorKind::Overlay, 0, pe, len as u64)? as usize;
            let (start, end) = span(off, max(DEFAULT_REGION_BYTES))?;
            vec![Region { start, end, ip: 0, arch: raw_arch }]
        }
        "file" => {
            let (start, end) = span(0, max(DEFAULT_REGION_BYTES))?;
            vec![Region { start, end, ip: 0, arch: raw_arch }]
        }
        _ => {
            let AnchorKind::Section(n) = pe_anchor::parse_anchor(region)? else {
                return None;
            };
            let pe = pe?;
            let s = pe.sections.get(n.checked_sub(1)? as usize)?;
            let (start, end) = span(s.raw_offset as usize, (s.raw_size as usize).min(max(DEFAULT_REGION_BYTES)))?;
            vec![Region { start, end, ip: pe.image_base.wrapping_add(s.virtual_address), arch: pick(pe_arch?) }]
        }
    };
    Some(out)
}

/// Whether `region` is a value `regions` understands (for validation).
pub fn valid_region(region: &str) -> bool {
    matches!(region.trim().to_ascii_lowercase().as_str(), "entry" | "ep" | "%ep%" | "code" | "overlay" | "%eope%" | "file")
        || matches!(pe_anchor::parse_anchor(region), Some(AnchorKind::Section(_)))
}

#[derive(Clone, Copy)]
struct Entry {
    /// iced `Mnemonic` (x86) or `arm64::MNEMONICS` index.
    mnemonic: u16,
    /// From the region start (`mode: cfg`: from the file start).
    offset: u32,
    len: u8,
}

/// `mode: cfg` budgets of a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CfgLimits {
    max_blocks: usize,
    max_insns: usize,
    follow_calls: bool,
    follow_jumps: bool,
}

/// The decoded instructions of one region.
pub struct Listing {
    region: Region,
    entries: Vec<Entry>,
    /// Address of each entry (`mode: cfg`); empty means `region.ip + offset`.
    ips: Vec<u64>,
    /// Runs of `entries` matched separately (`mode: cfg`); empty means one run.
    runs: Vec<(usize, usize)>,
}

fn invalid_id(arch: Arch) -> u16 {
    match arch {
        Arch::X86(_) => Mnemonic::INVALID as u16,
        Arch::Arm64 => arm64::unknown_id(),
    }
}

fn arm_word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn decode(bytes: &[u8], r: Region) -> Listing {
    let mut entries = Vec::new();
    match r.arch {
        Arch::X86(bitness) => {
            if let Ok(mut d) = Decoder::try_with_ip(bitness, &bytes[r.start..r.end], r.ip, DecoderOptions::NONE) {
                entries.reserve((r.end - r.start) / 4);
                let mut ins = Instruction::default();
                let mut offset = 0u32;
                while d.can_decode() {
                    d.decode_out(&mut ins);
                    entries.push(Entry { mnemonic: ins.mnemonic() as u16, offset, len: ins.len() as u8 });
                    offset += ins.len() as u32;
                }
            }
        }
        Arch::Arm64 => {
            entries.reserve((r.end - r.start) / 4);
            let mut at = r.start;
            while let Some(w) = arm_word(&bytes[..r.end], at) {
                let ip = r.ip.wrapping_add((at - r.start) as u64);
                let mnemonic = arm64::mnemonic_id(arm64::decode(w, ip).mnemonic);
                entries.push(Entry { mnemonic, offset: (at - r.start) as u32, len: 4 });
                at += 4;
            }
        }
    }
    Listing { region: r, entries, ips: Vec::new(), runs: Vec::new() }
}

/// One decoded instruction for the control-flow walk.
struct Step1 {
    mnemonic: u16,
    len: usize,
    flow: arm64::Flow,
}

fn decode_one(bytes: &[u8], off: usize, ip: u64, arch: Arch) -> Option<Step1> {
    match arch {
        Arch::Arm64 => {
            let i = arm64::decode(arm_word(bytes, off)?, ip);
            (i.mnemonic != "unknown").then(|| Step1 { mnemonic: arm64::mnemonic_id(i.mnemonic), len: 4, flow: i.flow })
        }
        Arch::X86(bitness) => {
            let end = bytes.len().min(off.checked_add(16)?);
            let mut d = Decoder::try_with_ip(bitness, bytes.get(off..end)?, ip, DecoderOptions::NONE).ok()?;
            let ins = d.decode();
            if ins.is_invalid() {
                return None;
            }
            let direct = ins.op_count() == 1 && matches!(ins.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64);
            let target = ins.near_branch_target();
            let flow = match ins.flow_control() {
                FlowControl::UnconditionalBranch if direct => arm64::Flow::Jump(target),
                FlowControl::ConditionalBranch if direct => arm64::Flow::CondJump(target),
                FlowControl::Call if direct => arm64::Flow::Call(target),
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt
                    if ins.mnemonic() != Mnemonic::Int && ins.mnemonic() != Mnemonic::Into =>
                {
                    arm64::Flow::End
                }
                FlowControl::Exception => arm64::Flow::End,
                _ if matches!(ins.mnemonic(), Mnemonic::Hlt | Mnemonic::Ud2 | Mnemonic::Int3) => arm64::Flow::End,
                _ => arm64::Flow::Next,
            };
            Some(Step1 { mnemonic: ins.mnemonic() as u16, len: ins.len(), flow })
        }
    }
}

/// How addresses map to file offsets for the control-flow walk.
#[derive(Clone, Copy)]
struct AddressMap<'a> {
    exe: Exe<'a>,
    region: Region,
    len: usize,
}

impl AddressMap<'_> {
    fn offset(&self, ip: u64) -> Option<usize> {
        let off = if let Some(pe) = self.exe.pe {
            let rva = ip.checked_sub(pe.image_base)?;
            pe.sections.iter().find_map(|s| {
                let rel = rva.checked_sub(s.virtual_address)?;
                (rel < s.raw_size && s.raw_size > 0).then(|| s.raw_offset.checked_add(rel)).flatten()
            })?
        } else if let Some(elf) = self.exe.elf {
            elf.vaddr_to_offset(ip)?
        } else if let Some(m) = self.exe.macho {
            m.slices.iter().find_map(|sl| {
                sl.segments.iter().find_map(|g| {
                    let rel = ip.checked_sub(g.vmaddr)?;
                    (rel < g.filesize).then(|| sl.offset.checked_add(g.fileoff)?.checked_add(rel)).flatten()
                })
            })?
        } else {
            // A raw region: addresses stay inside it.
            let rel = ip.checked_sub(self.region.ip)?;
            let off = (self.region.start as u64).checked_add(rel)?;
            (off < self.region.end as u64).then_some(off)?
        };
        let off = usize::try_from(off).ok()?;
        (off < self.len && off <= u32::MAX as usize).then_some(off)
    }
}

/// Edges of a control-flow walk: (address of the branch, direct target).
type Edges = Vec<(u64, u64)>;

/// Walk the code from `start` along the control flow (module notes).
fn walk(bytes: &[u8], map: AddressMap, start: u64, arch: Arch, limits: CfgLimits) -> (Listing, Edges) {
    let mut listing = Listing { region: Region { start: 0, end: bytes.len(), ip: 0, arch }, entries: Vec::new(), ips: Vec::new(), runs: Vec::new() };
    let mut edges = Vec::new();
    let mut queue = VecDeque::from([start]);
    let mut seen: HashSet<u64> = HashSet::new();
    let mut blocks = 0usize;
    while let Some(first) = queue.pop_front() {
        if seen.contains(&first) {
            continue;
        }
        if blocks >= limits.max_blocks || listing.entries.len() >= limits.max_insns {
            break;
        }
        blocks += 1;
        let run_start = listing.entries.len();
        let mut ip = first;
        loop {
            if listing.entries.len() >= limits.max_insns || !seen.insert(ip) {
                break;
            }
            let Some(off) = map.offset(ip) else { break };
            let Some(step) = decode_one(bytes, off, ip, arch) else { break };
            let next = ip.wrapping_add(step.len as u64);
            let push = |listing: &mut Listing| {
                listing.entries.push(Entry { mnemonic: step.mnemonic, offset: off as u32, len: step.len as u8 });
                listing.ips.push(ip);
            };
            match step.flow {
                arm64::Flow::Next => {
                    push(&mut listing);
                    ip = next;
                }
                arm64::Flow::CondJump(t) => {
                    push(&mut listing);
                    edges.push((ip, t));
                    queue.push_back(t);
                    ip = next;
                }
                arm64::Flow::Call(t) => {
                    push(&mut listing);
                    edges.push((ip, t));
                    if limits.follow_calls {
                        queue.push_back(t);
                    }
                    ip = next;
                }
                arm64::Flow::Jump(t) => {
                    edges.push((ip, t));
                    if limits.follow_jumps {
                        // The jump joins its target to this run.
                        if blocks >= limits.max_blocks {
                            break;
                        }
                        blocks += 1;
                        ip = t;
                    } else {
                        push(&mut listing);
                        queue.push_back(t);
                        break;
                    }
                }
                arm64::Flow::End => {
                    push(&mut listing);
                    break;
                }
            }
        }
        if listing.entries.len() > run_start {
            listing.runs.push((run_start, listing.entries.len()));
        }
    }
    (listing, edges)
}

/// Direct `call` / `jmp` / `jcc` edges reachable from the entry point of an x86
/// PE (for `pe_section` `cfg_xrefs`), followed through calls.
pub fn pe_cfg_edges(pe: &PeInfo, bytes: &[u8]) -> Edges {
    if pe_machine(bytes) == Some(IMAGE_FILE_MACHINE_ARM64) {
        return Vec::new();
    }
    let arch = Arch::X86(if pe.is_64 { 64 } else { 32 });
    let region = Region { start: 0, end: bytes.len(), ip: 0, arch };
    let map = AddressMap { exe: Exe { pe: Some(pe), ..Exe::default() }, region, len: bytes.len() };
    let limits = CfgLimits { max_blocks: MAX_MAX_BLOCKS, max_insns: MAX_MAX_INSNS, follow_calls: true, follow_jumps: true };
    walk(bytes, map, pe.image_base.wrapping_add(pe.entry), arch, limits).1
}

/// Regions decoded in this scan, shared by every `opcode_pattern` condition,
/// keyed by region, instruction set and mode.
#[derive(Default)]
pub struct ListingCache(Mutex<Vec<(Option<CfgLimits>, Arc<Listing>)>>);

impl std::fmt::Debug for ListingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.0.lock().map_or(0, |l| l.len());
        write!(f, "ListingCache({n} regions)")
    }
}

impl ListingCache {
    fn get(&self, bytes: &[u8], r: Region, cfg: Option<(CfgLimits, Exe)>) -> Arc<Listing> {
        let key = cfg.map(|(l, _)| l);
        let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, found)) = l.iter().find(|(k, x)| *k == key && x.region_key() == r) {
            return Arc::clone(found);
        }
        let new = Arc::new(match cfg {
            None => decode(bytes, r),
            Some((limits, exe)) => {
                let map = AddressMap { exe, region: r, len: bytes.len() };
                let mut listing = walk(bytes, map, r.ip, r.arch, limits).0;
                listing.region = r;
                listing
            }
        });
        l.push((key, Arc::clone(&new)));
        new
    }
}

impl Listing {
    /// The region this listing was decoded for (cache key).
    fn region_key(&self) -> Region {
        self.region
    }

    /// File offset and address of entry `i`.
    fn place(&self, i: usize) -> (usize, u64) {
        let e = self.entries[i];
        if self.ips.is_empty() {
            (self.region.start + e.offset as usize, self.region.ip.wrapping_add(e.offset as u64))
        } else {
            (e.offset as usize, self.ips[i])
        }
    }

    fn runs(&self) -> Vec<(usize, usize)> {
        if self.ips.is_empty() { vec![(0, self.entries.len())] } else { self.runs.clone() }
    }
}

fn is_mem(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

fn is_imm(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// Kind of the formatter's operand `i` (formatter and instruction number operands differently).
fn op_kind(fmt: &mut IntelFormatter, ins: &Instruction, i: usize) -> Option<OpKind> {
    fmt.get_instruction_operand(ins, i as u32).ok().flatten().map(|o| ins.op_kind(o))
}

fn formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_small_hex_numbers_in_decimal(false);
    o.set_leading_zeros(false);
    o.set_branch_leading_zeros(false);
    o.set_show_branch_size(false);
    o.set_space_after_operand_separator(false);
    o.set_memory_size_options(MemorySizeOptions::Always);
    f
}

struct Matcher<'a> {
    listing: &'a Listing,
    bytes: &'a [u8],
    /// Indexes into `listing.entries` left after `skip`.
    order: Vec<u32>,
    fmt: IntelFormatter,
    text: String,
    budget: usize,
}

impl Matcher<'_> {
    fn instruction(&self, idx: usize) -> Instruction {
        let e = self.listing.entries[idx];
        let (s, ip) = self.listing.place(idx);
        let Arch::X86(bitness) = self.listing.region.arch else { return Instruction::default() };
        let mut d = Decoder::with_ip(bitness, &self.bytes[s..s + e.len as usize], ip, DecoderOptions::NONE);
        d.decode()
    }

    fn arm_instruction(&self, idx: usize) -> arm64::Insn {
        let (s, ip) = self.listing.place(idx);
        arm64::decode(arm_word(self.bytes, s).unwrap_or(0), ip)
    }

    fn operands_match(&mut self, ins: &Instruction, pats: &[OpPat]) -> bool {
        if self.fmt.operand_count(ins) as usize != pats.len() {
            return false;
        }
        for (i, p) in pats.iter().enumerate() {
            let ok = match p {
                OpPat::Any => true,
                OpPat::Reg => op_kind(&mut self.fmt, ins, i) == Some(OpKind::Register),
                OpPat::Mem => op_kind(&mut self.fmt, ins, i).is_some_and(is_mem),
                OpPat::Imm => op_kind(&mut self.fmt, ins, i).is_some_and(is_imm),
                OpPat::Glob(g) => {
                    self.text.clear();
                    if self.fmt.format_operand(ins, &mut self.text, i as u32).is_err() {
                        return false;
                    }
                    let t = normalize(&self.text);
                    let bare = t.find("ptr").map(|at| &t[at + 3..]);
                    g.iter().any(|g| glob(g.as_bytes(), t.as_bytes()) || bare.is_some_and(|b| glob(g.as_bytes(), b.as_bytes())))
                }
            };
            if !ok {
                return false;
            }
        }
        true
    }

    fn arm_operands_match(ins: &arm64::Insn, pats: &[OpPat]) -> bool {
        ins.ops.len() == pats.len()
            && ins.ops.iter().zip(pats).all(|((text, kind), p)| match p {
                OpPat::Any => true,
                OpPat::Reg => *kind == arm64::OpKind::Reg,
                OpPat::Mem => *kind == arm64::OpKind::Mem,
                OpPat::Imm => *kind == arm64::OpKind::Imm,
                OpPat::Glob(g) => g.iter().any(|g| glob(g.as_bytes(), text.as_bytes())),
            })
    }

    fn step_matches(&mut self, step: &Step, pos: usize) -> bool {
        let Step::Insn { mnemonics, operands } = step else { return false };
        let idx = self.order[pos] as usize;
        let e = self.listing.entries[idx];
        if e.mnemonic == invalid_id(self.listing.region.arch) || mnemonics.as_ref().is_some_and(|m| m.binary_search(&e.mnemonic).is_err()) {
            return false;
        }
        match operands {
            None => true,
            Some(p) if self.listing.region.arch == Arch::Arm64 => Self::arm_operands_match(&self.arm_instruction(idx), p),
            Some(p) => {
                let ins = self.instruction(idx);
                self.operands_match(&ins, p)
            }
        }
    }

    /// Position after the match of `steps` starting at `pos`.
    fn match_from(&mut self, steps: &[Step], pos: usize) -> Option<usize> {
        let Some(step) = steps.first() else { return Some(pos) };
        if self.budget == 0 {
            return None;
        }
        self.budget -= 1;
        match step {
            Step::Gap { min, max } => {
                for skip in *min..=*max {
                    if pos + skip > self.order.len() {
                        break;
                    }
                    if let Some(end) = self.match_from(&steps[1..], pos + skip) {
                        return Some(end);
                    }
                }
                None
            }
            Step::Insn { .. } => {
                if pos >= self.order.len() || !self.step_matches(step, pos) {
                    return None;
                }
                self.match_from(&steps[1..], pos + 1)
            }
        }
    }

    /// First match: (positions start..end in `order`).
    fn find(&mut self, c: &Compiled) -> Option<(usize, usize)> {
        // Leading gaps only move the start; trailing ones only need room.
        let lead = c.steps.iter().take_while(|s| matches!(s, Step::Gap { .. })).count();
        let lead_min: usize = c.steps[..lead].iter().map(|s| if let Step::Gap { min, .. } = s { *min } else { 0 }).sum();
        let steps = &c.steps[lead..];
        for start in lead_min..self.order.len() {
            if self.budget == 0 {
                return None;
            }
            if !self.step_matches(&steps[0], start) {
                self.budget = self.budget.saturating_sub(1);
                continue;
            }
            if let Some(end) = self.match_from(steps, start) {
                return Some((start, end));
            }
        }
        None
    }

    fn describe(&mut self, start: usize, end: usize) -> String {
        let mut parts = Vec::new();
        for pos in start..end.min(start + SHOWN) {
            let idx = self.order[pos] as usize;
            if self.listing.region.arch == Arch::Arm64 {
                parts.push(arm64::format(&self.arm_instruction(idx)));
                continue;
            }
            let ins = self.instruction(idx);
            self.text.clear();
            self.fmt.format(&ins, &mut self.text);
            parts.push(self.text.clone());
        }
        if end - start > SHOWN {
            parts.push("...".into());
        }
        parts.join("; ")
    }
}

/// File offset and text of the first match of `c` in `listing`.
fn find_in(listing: &Listing, bytes: &[u8], c: &Compiled, skip: &[u16]) -> Option<(usize, String)> {
    let mut budget = MATCH_BUDGET;
    for (from, to) in listing.runs() {
        let order = (from as u32..to as u32).filter(|&i| !skip.contains(&listing.entries[i as usize].mnemonic)).collect();
        let mut m = Matcher { listing, bytes, order, fmt: formatter(), text: String::new(), budget };
        let found = m.find(c);
        budget = m.budget;
        if let Some((start, end)) = found {
            let at = listing.place(m.order[start] as usize).0;
            return Some((at, m.describe(start, end)));
        }
        if budget == 0 {
            break;
        }
    }
    None
}

pub fn evaluate(cond: &RuleCondition, exe: Exe, bytes: &[u8], cache: &ListingCache) -> Option<String> {
    let RuleCondition::OpcodePattern { pattern, patterns, min, region, max_bytes, bitness, skip, mode, arch, max_blocks, max_insns, follow_calls, follow_jumps } =
        cond
    else {
        return None;
    };
    let all: Vec<&String> = pattern.iter().chain(patterns.iter()).collect();
    if all.is_empty() {
        return None;
    }
    let chosen = explicit_arch(arch.as_deref(), *bitness);
    let regions = regions(region, *max_bytes, chosen, arch.is_some(), *bitness, exe, bytes)?;
    if regions.is_empty() {
        return None;
    }
    let cfg = mode.as_deref().is_some_and(|m| m.trim().eq_ignore_ascii_case("cfg")).then(|| CfgLimits {
        max_blocks: max_blocks.unwrap_or(DEFAULT_MAX_BLOCKS).clamp(1, MAX_MAX_BLOCKS),
        max_insns: max_insns.unwrap_or(DEFAULT_MAX_INSNS).clamp(1, MAX_MAX_INSNS),
        follow_calls: *follow_calls,
        follow_jumps: follow_jumps.unwrap_or(true),
    });
    let needed = min.unwrap_or(1).max(1);
    let mut matched = 0usize;
    let mut detail = Vec::new();
    for p in &all {
        let found = regions.iter().find_map(|r| {
            let arm = r.arch == Arch::Arm64;
            let c = cached(p, arm)?;
            let skip: Vec<u16> = skip.iter().filter_map(|s| mnemonic_ids(s, arm).ok()).flatten().collect();
            let listing = cache.get(bytes, *r, cfg.map(|l| (l, exe)));
            find_in(&listing, bytes, &c, &skip)
        });
        if let Some((at, text)) = found {
            matched += 1;
            if detail.len() < 4 {
                detail.push(format!("`{p}` at 0x{at:x}: {text}"));
            }
        }
    }
    let how = if cfg.is_some() { format!("{region}, cfg") } else { region.clone() };
    (matched >= needed).then(|| format!("opcode_pattern matched {matched}/{needed} ({how}): {}", detail.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cond(pattern: &str, bits: u32, skip: &[&str]) -> RuleCondition {
        RuleCondition::OpcodePattern {
            pattern: Some(pattern.to_string()),
            patterns: Vec::new(),
            min: None,
            region: "file".into(),
            max_bytes: None,
            bitness: Some(bits),
            skip: skip.iter().map(|s| s.to_string()).collect(),
            mode: None,
            arch: None,
            max_blocks: None,
            max_insns: None,
            follow_calls: false,
            follow_jumps: None,
        }
    }

    fn run(code: &[u8], bits: u32, pattern: &str, skip: &[&str]) -> Option<String> {
        evaluate(&cond(pattern, bits, skip), Exe::default(), code, &ListingCache::default())
    }

    // xor byte ptr [eax],0x5a ; inc eax ; loop -6
    const XOR_LOOP: &[u8] = &[0x80, 0x30, 0x5A, 0x40, 0xE2, 0xFA];

    #[test]
    fn matches_steps_operands_and_classes() {
        assert!(run(XOR_LOOP, 32, "xor byte ptr [eax], 0x5a; inc eax; loop *", &[]).is_some());
        assert!(run(XOR_LOOP, 32, "xor [*], imm; inc reg; loop", &[]).is_some());
        assert!(run(XOR_LOOP, 32, "xor mem, imm; dec reg", &[]).is_none());
        assert!(run(XOR_LOOP, 32, "xor reg, imm", &[]).is_none(), "memory operand is not reg");
        assert!(run(XOR_LOOP, 32, "xor|add *, *; *; j*|loop*", &[]).is_some());
        assert!(run(XOR_LOOP, 32, "xor [ecx]|[eax], 0x1|0x5a; inc ebx|eax", &[]).is_some());
        assert!(run(XOR_LOOP, 32, "xor [ecx]|[edx], *", &[]).is_none());
    }

    #[test]
    fn every_encoding_of_an_instruction_matches() {
        // mov eax,ebx as 89 D8 and as 8B C3, then ret
        assert!(run(&[0x89, 0xD8, 0xC3], 32, "mov eax, ebx; ret", &[]).is_some());
        assert!(run(&[0x8B, 0xC3, 0xC3], 32, "mov eax, ebx; ret", &[]).is_some());
    }

    #[test]
    fn gaps_and_skip() {
        // push ebp ; nop ; nop ; mov ebp,esp ; sub esp,0x10
        let code = [0x55, 0x90, 0x90, 0x89, 0xE5, 0x83, 0xEC, 0x10];
        assert!(run(&code, 32, "push ebp; mov ebp, esp", &[]).is_none());
        assert!(run(&code, 32, "push ebp; mov ebp, esp", &["nop"]).is_some());
        assert!(run(&code, 32, "push ebp; [1-2]; mov ebp, esp", &[]).is_some());
        assert!(run(&code, 32, "push ebp; [0-1]; mov ebp, esp", &[]).is_none());
        assert!(run(&code, 32, "push ebp; [-]; sub esp, 0x10", &[]).is_some());
    }

    #[test]
    fn bitness_changes_the_decoding() {
        // 48 89 D8: mov rax,rbx in 64-bit, dec eax; mov eax,ebx in 32-bit
        assert!(run(&[0x48, 0x89, 0xD8], 64, "mov rax, rbx", &[]).is_some());
        assert!(run(&[0x48, 0x89, 0xD8], 32, "dec eax; mov eax, ebx", &[]).is_some());
    }

    #[test]
    fn compile_errors() {
        assert!(compile("movx eax, ebx").is_err());
        assert!(compile("[3-1]; nop").is_err());
        assert!(compile("[2]").is_err());
        assert!(compile("[0-65]; nop").is_err());
        assert!(compile("mov eax,").is_err());
        assert!(compile("j*; [2-]; call *").is_ok());
        assert!(compile_arm64("stp x29, x30, [sp, #-0x10]!; ldrb|ldr *, mem; b.* *").is_ok());
        assert!(compile_arm64("movx x0, x1").is_err());
        assert!(compile("stp x29, x30, [sp]").is_err(), "not an x86 mnemonic");
    }

    #[test]
    fn glob_basics() {
        assert!(glob(b"[e?x+*]", b"[eax+0x4]"));
        assert!(glob(b"*", b""));
        assert!(!glob(b"e?x", b"eaxx"));
    }

    /// x86 stub split into islands: `push ebp; jmp L1; <junk>; L1: mov ebp,esp;
    /// jmp L2; <junk>; L2: xor byte ptr [eax],0x5a; inc eax; loop L2; ret`.
    fn jump_islands() -> Vec<u8> {
        let mut c = vec![0x55, 0xEB, 0x03, 0xFF, 0xFF, 0xFF]; // push ebp; jmp +3; junk
        c.extend([0x89, 0xE5, 0xEB, 0x02, 0xFF, 0xFF]); // mov ebp,esp; jmp +2; junk
        c.extend([0x80, 0x30, 0x5A, 0x40, 0xE2, 0xFA, 0xC3]); // xor [eax],0x5a; inc eax; loop -6; ret
        c
    }

    #[test]
    fn cfg_mode_follows_jumps_over_junk() {
        let code = jump_islands();
        let pattern = "push ebp; mov ebp, esp; xor byte ptr [eax], 0x5a; inc eax; loop *";
        assert!(run(&code, 32, pattern, &[]).is_none(), "linear sweep sees the jumps and junk");
        let mut c = cond(pattern, 32, &[]);
        if let RuleCondition::OpcodePattern { mode, .. } = &mut c {
            *mode = Some("cfg".into());
        }
        let hit = evaluate(&c, Exe::default(), &code, &ListingCache::default()).expect("cfg match");
        assert!(hit.contains("cfg") && hit.contains("at 0x0"), "{hit}");
        // Without following jumps the runs stop at each jump.
        if let RuleCondition::OpcodePattern { follow_jumps, .. } = &mut c {
            *follow_jumps = Some(false);
        }
        assert!(evaluate(&c, Exe::default(), &code, &ListingCache::default()).is_none());
    }

    #[test]
    fn cfg_walk_is_bounded() {
        // A chain of 5000 `jmp +0` (EB 00) stops at the block budget.
        let code = [0xEBu8, 0x00].repeat(5000);
        let region = Region { start: 0, end: code.len(), ip: 0, arch: Arch::X86(32) };
        let map = AddressMap { exe: Exe::default(), region, len: code.len() };
        let limits = CfgLimits { max_blocks: 64, max_insns: 100, follow_calls: true, follow_jumps: true };
        let (listing, edges) = walk(&code, map, 0, Arch::X86(32), limits);
        assert!(listing.entries.is_empty() && edges.len() <= 65, "{}", edges.len());
        // Loops end at code already decoded.
        let (listing, _) = walk(&[0x40, 0xEB, 0xFD], map, 0, Arch::X86(32), limits);
        assert_eq!(listing.entries.len(), 1);
    }

    /// AArch64: prologue, then an XOR decryptor loop.
    pub fn arm64_decryptor() -> Vec<u8> {
        [
            0xa9bf7bfdu32, // stp x29, x30, [sp, #-16]!
            0x910003fd,    // mov x29, sp
            0x39400008,    // ldrb w8, [x0]
            0x4a010108,    // eor w8, w8, w1
            0x38001408,    // strb w8, [x0], #1
            0xf1000442,    // subs x2, x2, #1
            0x54ffff81,    // b.ne <ldrb>
            0xa8c17bfd,    // ldp x29, x30, [sp], #16
            0xd65f03c0,    // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
    }

    #[test]
    fn arm64_patterns() {
        let code = arm64_decryptor();
        let arm = |pattern: &str, mode: Option<&str>| {
            let mut c = cond(pattern, 64, &[]);
            if let RuleCondition::OpcodePattern { arch, mode: m, .. } = &mut c {
                *arch = Some("arm64".into());
                *m = mode.map(str::to_string);
            }
            evaluate(&c, Exe::default(), &code, &ListingCache::default())
        };
        let decryptor = "stp x29, x30, [sp, #-0x10]!; [0-4]; eor w*, w*, w*; [0-2]; b.ne *";
        let hit = arm(decryptor, None).expect("linear");
        assert!(hit.contains("stp x29,x30,[sp,-0x10]!"), "{hit}");
        assert!(arm(decryptor, Some("cfg")).is_some());
        assert!(arm("ldrb reg, mem; eor reg, reg, reg; strb w8, [x0], 0x1; subs x2, x2, imm; b* *", None).is_some());
        assert!(arm("eor x*, x*, x*", None).is_none(), "32-bit registers");
        assert!(run(&code, 64, "eor *, *, *", &[]).is_none(), "x86 decoding of the same bytes");
    }
}
