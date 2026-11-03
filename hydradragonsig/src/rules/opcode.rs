//! `opcode_pattern` condition: x86 / x64 instruction patterns over disassembled code.
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

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, MemorySizeOptions, Mnemonic, OpKind};

use super::pe_anchor::{self, AnchorKind};
use super::pe_section::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use super::types::RuleCondition;
use crate::models::PeInfo;

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
    Insn { mnemonics: Option<Vec<Mnemonic>>, operands: Option<Vec<OpPat>> },
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

/// Compiles a pattern (module notes), or says what is wrong with it.
pub fn compile(pattern: &str) -> Result<Compiled, String> {
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
        let mnemonics = if mn == "*" { None } else { Some(mnemonic_set(mn)?) };
        let operands = if rest.is_empty() {
            None
        } else {
            Some(
                rest.split(',')
                    .map(|o| match normalize(o).as_str() {
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

fn cached(pattern: &str) -> Option<Arc<Compiled>> {
    static CACHE: LazyLock<Mutex<HashMap<String, Option<Arc<Compiled>>>>> = LazyLock::new(Default::default);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    c.entry(pattern.to_string()).or_insert_with(|| compile(pattern).ok().map(Arc::new)).clone()
}

/// Where code is decoded: file bytes `start..end`, address of `start`, bitness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    start: usize,
    end: usize,
    ip: u64,
    bitness: u32,
}

/// The regions a `region` value names (several for `code`), or None when this file
/// has no such region (not a PE, no such section).
fn regions(region: &str, max_bytes: Option<usize>, bitness: Option<u32>, pe: Option<&PeInfo>, len: usize) -> Option<Vec<Region>> {
    let pe_bits = pe.map(|p| if p.is_64 { 64 } else { 32 });
    let max = |default: usize| max_bytes.unwrap_or(default).clamp(1, MAX_REGION_BYTES);
    let span = |start: usize, limit: usize| (start < len).then(|| (start, start.saturating_add(limit).min(len)));
    let lower = region.trim().to_ascii_lowercase();
    let out = match lower.as_str() {
        "entry" | "ep" | "%ep%" => {
            let pe = pe?;
            let off = pe_anchor::entry_file_offset(pe, len as u64)? as usize;
            let (start, end) = span(off, max(DEFAULT_ENTRY_BYTES))?;
            vec![Region { start, end, ip: pe.image_base.wrapping_add(pe.entry), bitness: pe_bits? }]
        }
        "code" => {
            let pe = pe?;
            pe.sections
                .iter()
                .filter(|s| s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0 && s.raw_size > 0)
                .filter_map(|s| {
                    let (start, end) = span(s.raw_offset as usize, (s.raw_size as usize).min(max(DEFAULT_REGION_BYTES)))?;
                    Some(Region { start, end, ip: pe.image_base.wrapping_add(s.virtual_address), bitness: pe_bits? })
                })
                .collect()
        }
        "overlay" | "%eope%" => {
            let off = pe_anchor::resolve(AnchorKind::Overlay, 0, pe, len as u64)? as usize;
            let (start, end) = span(off, max(DEFAULT_REGION_BYTES))?;
            vec![Region { start, end, ip: 0, bitness: bitness.or(pe_bits).unwrap_or(32) }]
        }
        "file" => {
            let (start, end) = span(0, max(DEFAULT_REGION_BYTES))?;
            vec![Region { start, end, ip: 0, bitness: bitness.or(pe_bits).unwrap_or(32) }]
        }
        _ => {
            let AnchorKind::Section(n) = pe_anchor::parse_anchor(region)? else {
                return None;
            };
            let pe = pe?;
            let s = pe.sections.get(n.checked_sub(1)? as usize)?;
            let (start, end) = span(s.raw_offset as usize, (s.raw_size as usize).min(max(DEFAULT_REGION_BYTES)))?;
            vec![Region { start, end, ip: pe.image_base.wrapping_add(s.virtual_address), bitness: pe_bits? }]
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
    mnemonic: Mnemonic,
    /// From the region start.
    offset: u32,
    len: u8,
}

/// The decoded instructions of one region.
pub struct Listing {
    region: Region,
    entries: Vec<Entry>,
}

fn decode(bytes: &[u8], r: Region) -> Listing {
    let mut entries = Vec::new();
    if let Ok(mut d) = Decoder::try_with_ip(r.bitness, &bytes[r.start..r.end], r.ip, DecoderOptions::NONE) {
        entries.reserve((r.end - r.start) / 4);
        let mut ins = Instruction::default();
        let mut offset = 0u32;
        while d.can_decode() {
            d.decode_out(&mut ins);
            entries.push(Entry { mnemonic: ins.mnemonic(), offset, len: ins.len() as u8 });
            offset += ins.len() as u32;
        }
    }
    Listing { region: r, entries }
}

/// Regions decoded in this scan, shared by every `opcode_pattern` condition.
#[derive(Default)]
pub struct ListingCache(Mutex<Vec<Arc<Listing>>>);

impl std::fmt::Debug for ListingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.0.lock().map_or(0, |l| l.len());
        write!(f, "ListingCache({n} regions)")
    }
}

impl ListingCache {
    fn get(&self, bytes: &[u8], r: Region) -> Arc<Listing> {
        let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = l.iter().find(|x| x.region == r) {
            return Arc::clone(found);
        }
        let new = Arc::new(decode(bytes, r));
        l.push(Arc::clone(&new));
        new
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
    fn instruction(&self, e: Entry) -> Instruction {
        let r = self.listing.region;
        let s = r.start + e.offset as usize;
        let mut d = Decoder::with_ip(r.bitness, &self.bytes[s..s + e.len as usize], r.ip.wrapping_add(e.offset as u64), DecoderOptions::NONE);
        d.decode()
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

    fn step_matches(&mut self, step: &Step, pos: usize) -> bool {
        let Step::Insn { mnemonics, operands } = step else { return false };
        let e = self.listing.entries[self.order[pos] as usize];
        if e.mnemonic == Mnemonic::INVALID || mnemonics.as_ref().is_some_and(|m| m.binary_search_by_key(&(e.mnemonic as u32), |x| *x as u32).is_err()) {
            return false;
        }
        match operands {
            None => true,
            Some(p) => {
                let ins = self.instruction(e);
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
            let ins = self.instruction(self.listing.entries[self.order[pos] as usize]);
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
fn find_in(listing: &Listing, bytes: &[u8], c: &Compiled, skip: &[Mnemonic]) -> Option<(usize, String)> {
    let order = (0..listing.entries.len() as u32)
        .filter(|&i| !skip.contains(&listing.entries[i as usize].mnemonic))
        .collect();
    let mut m = Matcher { listing, bytes, order, fmt: formatter(), text: String::new(), budget: MATCH_BUDGET };
    let (start, end) = m.find(c)?;
    let at = listing.region.start + listing.entries[m.order[start] as usize].offset as usize;
    Some((at, m.describe(start, end)))
}

pub fn evaluate(cond: &RuleCondition, pe: Option<&PeInfo>, bytes: &[u8], cache: &ListingCache) -> Option<String> {
    let RuleCondition::OpcodePattern { pattern, patterns, min, region, max_bytes, bitness, skip } = cond else {
        return None;
    };
    let all: Vec<&String> = pattern.iter().chain(patterns.iter()).collect();
    if all.is_empty() {
        return None;
    }
    let regions = regions(region, *max_bytes, *bitness, pe, bytes.len())?;
    if regions.is_empty() {
        return None;
    }
    let skip: Vec<Mnemonic> = skip.iter().filter_map(|s| mnemonic_set(s).ok()).flatten().collect();
    let listings: Vec<Arc<Listing>> = regions.iter().map(|r| cache.get(bytes, *r)).collect();
    let needed = min.unwrap_or(1).max(1);
    let mut matched = 0usize;
    let mut detail = Vec::new();
    for p in &all {
        let Some(c) = cached(p) else { continue };
        if let Some((at, text)) = listings.iter().find_map(|l| find_in(l, bytes, &c, &skip)) {
            matched += 1;
            if detail.len() < 4 {
                detail.push(format!("`{p}` at 0x{at:x}: {text}"));
            }
        }
    }
    (matched >= needed).then(|| format!("opcode_pattern matched {matched}/{needed} ({region}): {}", detail.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &[u8], bits: u32, pattern: &str, skip: &[&str]) -> Option<String> {
        let cond = RuleCondition::OpcodePattern {
            pattern: Some(pattern.to_string()),
            patterns: Vec::new(),
            min: None,
            region: "file".into(),
            max_bytes: None,
            bitness: Some(bits),
            skip: skip.iter().map(|s| s.to_string()).collect(),
        };
        evaluate(&cond, None, code, &ListingCache::default())
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
    }

    #[test]
    fn glob_basics() {
        assert!(glob(b"[e?x+*]", b"[eax+0x4]"));
        assert!(glob(b"*", b""));
        assert!(!glob(b"e?x", b"eaxx"));
    }
}
