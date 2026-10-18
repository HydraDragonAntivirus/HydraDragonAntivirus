//! Generic detection of classic file infectors by emulation ("generic decryption").
//!
//! A polymorphic infector changes its body on every infection, but it must still
//! (1) get control from the host and (2) decrypt its body before running it. Both
//! are visible without knowing the family:
//!
//! * **Control transfer.** Either the entry point lies in the appended (last)
//!   section, or the entry point is left alone and a `call`/`jmp rel32` somewhere in
//!   the host's code was patched to point into that section (EPO, entry-point
//!   obscuring). Host code never calls into a trailing section on its own.
//! * **Self-decryption.** Emulated from that transfer, the body writes to a page and
//!   then executes from it (write-execute). The decrypted bytes in memory are the
//!   same for every copy of the virus, so the engine scans them with the ordinary
//!   signature layers: a family signature written for the decrypted body matches
//!   every infected file.
//!
//! Packers also write-then-execute, but they do it from the entry point and replace
//! the host code; an infector leaves the host's code section intact. `InfectorFinding`
//! reports which case was seen and the caller decides how to score it.

use crate::unpacker::engine::{entrypoint, Sample, UnpackerEngine};

/// What emulation found.
#[derive(Debug, Clone)]
pub struct InfectorFinding {
    /// Absolute address emulation started at.
    pub start: u64,
    /// Started at a host `call`/`jmp` that targets the trailing section (EPO),
    /// not at the entry point.
    pub from_epo: bool,
    /// Address of that host instruction (EPO) or the entry point.
    pub transfer_from: u64,
    /// First address executed from a page the emulated code had written.
    pub wx_addr: u64,
    /// Start (absolute VA) of `body`.
    pub body_va: u64,
    /// Decrypted memory: the written range that contains `wx_addr` (capped).
    pub body: Vec<u8>,
    /// The host's first executable section still has raw data and normal entropy
    /// (an infector leaves it alone; a packer replaces it).
    pub host_code_intact: bool,
}

/// Bytes of decrypted body returned at most.
const MAX_BODY: u64 = 4 * 1024 * 1024;
/// EPO candidates tried at most (each is a separate emulation).
const MAX_EPO_CANDIDATES: usize = 6;
/// Per-candidate limits.
const TIMEOUT_US: u64 = 2_000_000;
const MAX_INSTRUCTIONS: usize = 20_000_000;
/// Trailing section smaller than this is not a virus body.
const MIN_BODY_RAW: u32 = 2048;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut c = [0u64; 256];
    for &x in b {
        c[x as usize] += 1;
    }
    let n = b.len() as f64;
    c.iter().filter(|&&v| v > 0).map(|&v| {
        let p = v as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Cheap pre-check, no emulation: does the file have a trailing section the
/// entry point or a host `call`/`jmp rel32` jumps into? Returns the start
/// addresses to emulate (entry point first when it is in that section).
pub fn transfer_candidates(sample: &Sample) -> Vec<(u64, bool, u64)> {
    let secs = &sample.sections;
    let Some((li, last)) = secs.iter().enumerate().max_by_key(|(_, s)| s.virtual_address) else {
        return Vec::new();
    };
    if last.size_of_raw_data < MIN_BODY_RAW || secs.len() < 2 {
        return Vec::new();
    }
    // The body is code or encrypted code: an executable or near-random trailing
    // section. Plain .reloc / .rsrc tails are skipped without emulating.
    let raw = &sample.raw_bytes;
    let loff = last.pointer_to_raw_data as usize;
    let lend = (loff + last.size_of_raw_data as usize).min(raw.len());
    let exec = last.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0;
    if loff >= lend || !(exec || entropy(&raw[loff..lend.min(loff + (1 << 20))]) >= 7.0) {
        return Vec::new();
    }
    let base = sample.base_addr;
    let lo = base + last.virtual_address as u64;
    let hi = lo + (last.virtual_size.max(last.size_of_raw_data)) as u64;
    let ep = entrypoint(&sample.opt_header);
    let mut out = Vec::new();
    if ep >= lo && ep < hi {
        out.push((ep, false, ep));
    }
    for (i, s) in secs.iter().enumerate() {
        if i == li || s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
            continue;
        }
        let off = s.pointer_to_raw_data as usize;
        let len = (s.size_of_raw_data as usize).min(raw.len().saturating_sub(off));
        let code = &raw[off..off + len];
        let sva = base + s.virtual_address as u64;
        let mut k = 0usize;
        while k + 5 <= code.len() && out.len() < MAX_EPO_CANDIDATES + 1 {
            let op = code[k];
            if op == 0xE8 || op == 0xE9 {
                let rel = i32::from_le_bytes([code[k + 1], code[k + 2], code[k + 3], code[k + 4]]) as i64;
                let at = sva + k as u64;
                let target = (at as i64 + 5 + rel) as u64;
                if target >= lo && target < hi {
                    out.push((at, true, at));
                    k += 5;
                    continue;
                }
            }
            k += 1;
        }
    }
    let is64 = sample_is_64(raw);
    for head in jump_chain_heads(sample, is64) {
        if out.len() > MAX_EPO_CANDIDATES {
            break;
        }
        if !out.iter().any(|c| c.0 == head) {
            out.push((head, true, head));
        }
    }
    out
}

/// Fragments a jump-chained decryptor is cut into are at most this long.
const CHAIN_FRAG_MAX_INSNS: usize = 6;
/// Hops needed before a chain counts as one. Compiler output does not link four
/// tiny fragments with unconditional jumps in a row.
const CHAIN_MIN_HOPS: usize = 4;
const CHAIN_MAX_HOPS: usize = 64;

/// EPO without a direct jump into the virus section: the decryptor is cut into
/// tiny fragments scattered over cavities of the host's code and linked with
/// `jmp`; it decrypts the trailing section and reaches it with a computed `call`.
/// Returns the first fragment of every such chain (the address the patched host
/// `jmp` goes to).
fn jump_chain_heads(sample: &Sample, is64: bool) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};
    use std::collections::{HashMap, HashSet};
    let raw = &sample.raw_bytes;
    let base = sample.base_addr;
    let bits = if is64 { 64 } else { 32 };
    // (va, bytes) of every executable section but the trailing one.
    let last_va = sample.sections.iter().map(|s| s.virtual_address).max().unwrap_or(0);
    let code: Vec<(u64, &[u8])> = sample
        .sections
        .iter()
        .filter(|s| s.virtual_address != last_va && s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0)
        .filter_map(|s| {
            let off = s.pointer_to_raw_data as usize;
            let len = (s.size_of_raw_data as usize).min(raw.len().saturating_sub(off));
            (len > 0).then(|| (base + s.virtual_address as u64, &raw[off..off + len]))
        })
        .collect();
    let bytes_at = |va: u64| -> Option<&[u8]> {
        code.iter().find(|(s, b)| va >= *s && va < *s + b.len() as u64).map(|(s, b)| &b[(va - s) as usize..])
    };
    // Next fragment of the chain from `va`, if `va` starts a short fragment ending
    // in an unconditional direct jmp (no call/ret/branch in between).
    let next = |va: u64| -> Option<u64> {
        let b = bytes_at(va)?;
        let mut d = Decoder::with_ip(bits, &b[..b.len().min(96)], va, DecoderOptions::NONE);
        for _ in 0..CHAIN_FRAG_MAX_INSNS {
            if !d.can_decode() {
                return None;
            }
            let i = d.decode();
            if i.is_invalid() {
                return None;
            }
            match i.flow_control() {
                FlowControl::Next => {}
                FlowControl::UnconditionalBranch if i.is_jmp_short_or_near() => return Some(i.near_branch_target()),
                // A conditional jump as the last real instruction is still part of
                // the junk; the chain continues at the jcc target.
                _ => return None,
            }
        }
        None
    };
    // Targets of every jmp rel32 in host code.
    let mut targets: Vec<u64> = Vec::new();
    for (sva, b) in &code {
        let mut k = 0usize;
        while k + 5 <= b.len() {
            if b[k] == 0xE9 {
                let rel = i32::from_le_bytes([b[k + 1], b[k + 2], b[k + 3], b[k + 4]]) as i64;
                targets.push((*sva as i64 + k as i64 + 5 + rel) as u64);
            }
            k += 1;
        }
    }
    let mut chain_len: HashMap<u64, usize> = HashMap::new();
    let mut inner: HashSet<u64> = HashSet::new();
    for &t in &targets {
        if chain_len.contains_key(&t) || bytes_at(t).is_none() {
            continue;
        }
        let mut cur = t;
        let mut hops = 0usize;
        let mut seen = HashSet::new();
        while hops < CHAIN_MAX_HOPS {
            let Some(n) = next(cur) else { break };
            if !seen.insert(n) {
                break;
            }
            hops += 1;
            inner.insert(n);
            cur = n;
        }
        chain_len.insert(t, hops);
    }
    let mut heads: Vec<(u64, usize)> = chain_len
        .into_iter()
        .filter(|&(t, h)| h >= CHAIN_MIN_HOPS && !inner.contains(&t))
        .collect();
    heads.sort_by(|a, b| b.1.cmp(&a.1));
    heads.into_iter().take(MAX_EPO_CANDIDATES).map(|(t, _)| t).collect()
}

fn host_code_intact(sample: &Sample) -> bool {
    let raw = &sample.raw_bytes;
    let first_code = sample
        .sections
        .iter()
        .filter(|s| s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0)
        .min_by_key(|s| s.virtual_address);
    let Some(s) = first_code else { return false };
    if s.size_of_raw_data < 512 {
        return false;
    }
    let off = s.pointer_to_raw_data as usize;
    let end = (off + s.size_of_raw_data as usize).min(raw.len());
    off < end && entropy(&raw[off..end.min(off + (1 << 20))]) < 7.2
}

/// Scratch memory the general registers point into before emulation: in the real
/// process they hold host pointers, and polymorphic junk code reads through them.
const SCRATCH: u64 = 0x3000_0000;
const SCRATCH_SIZE: u64 = 0x20_0000;

pub fn sample_is_64(data: &[u8]) -> bool {
    data.get(0x3c..0x40)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .and_then(|o| data.get(o + 24..o + 26))
        .map_or(false, |m| m == [0x0b, 0x02])
}

pub fn seed_registers(eng: &mut UnpackerEngine, is64: bool) {
    use unicorn_engine::{RegisterX86 as R, unicorn_const::Prot};
    let Some(uc) = eng.unicorn_mut() else { return };
    if uc.mem_map(SCRATCH, SCRATCH_SIZE, Prot::READ | Prot::WRITE).is_err() {
        return;
    }
    let mid = SCRATCH + SCRATCH_SIZE / 2;
    let regs: &[R] = if is64 {
        &[R::RAX, R::RBX, R::RCX, R::RDX, R::RSI, R::RDI, R::RBP, R::R8, R::R9, R::R10, R::R11, R::R12, R::R13, R::R14, R::R15]
    } else {
        &[R::EAX, R::EBX, R::ECX, R::EDX, R::ESI, R::EDI, R::EBP]
    };
    for r in regs {
        let _ = uc.reg_write(*r as i32, mid);
    }
}

/// Emulate every transfer candidate until one decrypts itself. `None` when the
/// file has no candidate or nothing wrote-then-executed.
pub fn find_self_decrypting_body(data: &[u8]) -> Option<InfectorFinding> {
    let sample = Sample::from_bytes(data).ok()?;
    let cands = transfer_candidates(&sample);
    if cands.is_empty() {
        return None;
    }
    let intact = host_code_intact(&sample);
    for (start, from_epo, transfer_from) in cands {
        let Ok(s) = Sample::from_bytes(data) else { continue };
        let mut eng = UnpackerEngine::new(s, "memory");
        if eng.init_uc().is_err() {
            continue;
        }
        eng.set_controls(true, false);
        eng.set_end_addr(u64::MAX);
        eng.set_map_on_fault(true);
        seed_registers(&mut eng, sample_is_64(data));
        let _ = eng.emu_from(start, TIMEOUT_US, MAX_INSTRUCTIONS);
        let Some(wx) = eng.wx_hit else { continue };
        let (rlo, rhi) = eng
            .write_targets
            .iter()
            .copied()
            .find(|&(a, b)| wx >= a && wx < b)
            .unwrap_or((wx & !0xfff, (wx & !0xfff) + 0x1000));
        let len = (rhi - rlo).min(MAX_BODY) as usize;
        let body = eng
            .unicorn_mut()
            .and_then(|uc| uc.mem_read_as_vec(rlo, len).ok())
            .unwrap_or_default();
        return Some(InfectorFinding {
            start,
            from_epo,
            transfer_from,
            wx_addr: wx,
            body_va: rlo,
            body,
            host_code_intact: intact,
        });
    }
    None
}
