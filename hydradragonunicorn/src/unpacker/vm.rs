//! Static VM/mutation section classifier and opt-in trace-based VM
//! devirtualizer built on top of Unicorn + `iced-x86`.
//!
//! Designed for two complementary use cases:
//! 1. Fast static pre-classification of executable sections (`detect_vm_sections`)
//!    so the scanner and analysts see whether a section is normal compiler code,
//!    mutated, or threaded-VM virtualized before spending emulation budget.
//! 2. Opt-in dynamic trace simplification (`UnpackerEngine::devirtualize_trace`)
//!    that captures single-step execution, identifies indirect-branch VM
//!    dispatchers, removes dead stack/flag/register stores, folds obfuscated
//!    constant chains, resolves indirect jumps, and coalesces non-stack memory
//!    writes (recovered payloads, decrypted strings/URLs, APIs).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use hydradragonsig::models::ApiCall;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    IntelFormatter, Mnemonic, OpKind as IcedOpKind, Register,
};
use serde::Serialize;
use unicorn_engine::unicorn_const::HookType as UcHookType;
use unicorn_engine::RegisterX86;

use crate::unpacker::apicalls;
use crate::unpacker::engine::{
    collect_strings_from_bytes, parse_pe_bytes, ENTRY_RETURN_ADDR, SEH64_RETURN_ADDR,
    SEH_RETURN_ADDR, STACK_ADDR, STACK_SIZE,
};
use crate::unpacker::error::{UnpackerError, UnpackerResult};
use crate::unpacker::UnpackerEngine;

const MAX_STATIC_SAMPLE_BYTES: usize = 256 * 1024;
const HOOK_REGION_SIZE: u64 = 0x10_0000;

// ---------------------------------------------------------------------------
// 1. Static VM / Mutation Section Classifier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SectionVmKind {
    Normal,
    Mutated,
    Virtualized,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionVmInfo {
    pub name: String,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub indirect_branch_ratio: f64,
    pub control_flow_insns: usize,
    pub indirect_branches: usize,
    pub context_save_markers: usize,
    pub protector_name_hint: bool,
    pub vm_score: f64,
    pub kind: SectionVmKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct VmProfile {
    pub is_pe64: bool,
    pub executable_sections: Vec<SectionVmInfo>,
    pub has_virtualized: bool,
    pub has_mutated: bool,
    pub max_vm_score: f64,
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn is_protector_section_name(name: &str) -> Option<f64> {
    let low = name.trim().to_ascii_lowercase();
    if low.starts_with(".vmp")
        || low.starts_with("vmp")
        || low.contains("themida")
        || low.contains("winlice")
        || low.contains("enigma")
        || low.contains("obsidium")
        || low.contains("oreans")
    {
        return Some(0.45);
    }
    None
}

fn is_stack_base_reg(reg: Register) -> bool {
    matches!(reg, Register::RSP | Register::RBP | Register::ESP | Register::EBP)
}

fn is_context_save_insn(ins: &Instruction) -> bool {
    match ins.mnemonic() {
        Mnemonic::Pushfd | Mnemonic::Pushfq | Mnemonic::Pushad => true,
        Mnemonic::Push => ins.op0_kind() == IcedOpKind::Register,
        Mnemonic::Mov | Mnemonic::Movups | Mnemonic::Movaps | Mnemonic::Movdqu | Mnemonic::Movdqa => {
            ins.op0_kind() == IcedOpKind::Memory
                && is_stack_base_reg(ins.memory_base())
                && ins.op1_kind() == IcedOpKind::Register
        }
        _ => false,
    }
}

fn score_vm_window(
    sec: &crate::unpacker::engine::Section,
    sample: &[u8],
    base_ip: u64,
    bitness: u32,
    name_bonus: Option<f64>,
    unnamed_large_bonus: Option<f64>,
    protector_name_hint: bool,
) -> SectionVmInfo {
    let entropy = shannon_entropy(sample);
    let mut decoder = Decoder::with_ip(bitness, sample, base_ip, DecoderOptions::NONE);
    let mut control_flow_insns = 0usize;
    let mut indirect_branches = 0usize;
    let mut context_save_markers = 0usize;
    let mut save_run = 0usize;

    while decoder.can_decode() {
        let ins = decoder.decode();
        match ins.flow_control() {
            FlowControl::Next => {}
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                control_flow_insns += 1;
                indirect_branches += 1;
            }
            _ => {
                control_flow_insns += 1;
            }
        }

        if matches!(ins.mnemonic(), Mnemonic::Pushfd | Mnemonic::Pushfq | Mnemonic::Pushad) {
            context_save_markers += 1;
            save_run = 0;
        } else if is_context_save_insn(&ins) {
            save_run += 1;
            if save_run == 4 {
                context_save_markers += 1;
            }
        } else {
            save_run = 0;
        }
    }

    let indirect_branch_ratio = if control_flow_insns > 0 {
        indirect_branches as f64 / control_flow_insns as f64
    } else {
        0.0
    };

    let mut score = name_bonus.or(unnamed_large_bonus).unwrap_or(0.0);
    score += (indirect_branch_ratio * 2.5).min(0.45);
    score += (context_save_markers as f64 / 20.0).min(0.20);
    if entropy >= 6.4 {
        score += 0.10;
    }
    let vm_score = score.clamp(0.0, 1.0);

    let kind = if vm_score >= 0.55 {
        SectionVmKind::Virtualized
    } else if vm_score >= 0.30 {
        SectionVmKind::Mutated
    } else {
        SectionVmKind::Normal
    };

    SectionVmInfo {
        name: sec.name.clone(),
        virtual_address: sec.virtual_address,
        raw_size: sec.size_of_raw_data,
        entropy,
        indirect_branch_ratio,
        control_flow_insns,
        indirect_branches,
        context_save_markers,
        protector_name_hint,
        vm_score,
        kind,
    }
}

/// Statically inspects executable PE sections and scores each one for code mutation
/// or threaded-VM virtualization. For sections larger than 256 KiB, samples head,
/// midpoint, and tail windows and takes the highest-scoring window so sections that
/// start with CRT/data (e.g. VMP 3.8+ `L3G0`) are still classified accurately.
pub fn detect_vm_sections(pe_bytes: &[u8]) -> UnpackerResult<VmProfile> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    let (_dos, pe, opt, sections) = parse_pe_bytes(pe_bytes)?;
    let is_pe64 = pe.machine == 0x8664 || opt.magic == 0x20B;
    let bitness = if is_pe64 { 64 } else { 32 };

    let mut executable_sections = Vec::new();
    let mut has_virtualized = false;
    let mut has_mutated = false;
    let mut max_vm_score = 0.0f64;

    for sec in &sections {
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 || sec.size_of_raw_data == 0 {
            continue;
        }
        let raw_start = sec.pointer_to_raw_data as usize;
        if raw_start >= pe_bytes.len() {
            continue;
        }
        let raw_end = raw_start.saturating_add(sec.size_of_raw_data as usize).min(pe_bytes.len());
        let sec_bytes = &pe_bytes[raw_start..raw_end];

        let name_bonus = is_protector_section_name(&sec.name);
        let unnamed_large_bonus = if sec.name.trim().is_empty() && sec.size_of_raw_data > 128 * 1024 {
            Some(0.25)
        } else {
            None
        };
        let protector_name_hint = name_bonus.is_some() || unnamed_large_bonus.is_some();

        let base_ip = opt.image_base + sec.virtual_address as u64;
        let info = if sec_bytes.len() <= MAX_STATIC_SAMPLE_BYTES {
            score_vm_window(
                sec,
                sec_bytes,
                base_ip,
                bitness,
                name_bonus,
                unnamed_large_bonus,
                protector_name_hint,
            )
        } else {
            let head_end = (96 * 1024).min(sec_bytes.len());
            let mid_start = (sec_bytes.len() / 2).saturating_sub(48 * 1024);
            let mid_end = (mid_start + 96 * 1024).min(sec_bytes.len());
            let tail_start = sec_bytes.len().saturating_sub(64 * 1024);
            let windows = [
                (0usize, head_end),
                (mid_start, mid_end),
                (tail_start, sec_bytes.len()),
            ];
            windows
                .into_iter()
                .filter(|(a, b)| b > a)
                .map(|(a, b)| {
                    score_vm_window(
                        sec,
                        &sec_bytes[a..b],
                        base_ip + a as u64,
                        bitness,
                        name_bonus,
                        unnamed_large_bonus,
                        protector_name_hint,
                    )
                })
                .max_by(|a, b| a.vm_score.total_cmp(&b.vm_score))
                .unwrap_or_else(|| {
                    score_vm_window(
                        sec,
                        sec_bytes,
                        base_ip,
                        bitness,
                        name_bonus,
                        unnamed_large_bonus,
                        protector_name_hint,
                    )
                })
        };

        match info.kind {
            SectionVmKind::Virtualized => has_virtualized = true,
            SectionVmKind::Mutated => has_mutated = true,
            SectionVmKind::Normal => {}
        }
        if info.vm_score > max_vm_score {
            max_vm_score = info.vm_score;
        }
        executable_sections.push(info);
    }

    Ok(VmProfile {
        is_pe64,
        executable_sections,
        has_virtualized,
        has_mutated,
        max_vm_score,
    })
}

// ---------------------------------------------------------------------------
// 2. Trace-Based VM Devirtualizer Data Structures & Pure Simplification Passes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct DevirtConfig {
    pub max_insns: usize,
    pub timeout_ms: u64,
    pub collapse_dispatchers: bool,
    pub strip_dead_stores: bool,
    pub fold_constants: bool,
}

impl Default for DevirtConfig {
    fn default() -> Self {
        Self {
            max_insns: 50_000,
            timeout_ms: 5_000,
            collapse_dispatchers: true,
            strip_dead_stores: true,
            fold_constants: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PureAluOp {
    MovImm,
    AddImm,
    SubImm,
    XorImm,
    SelfXorZero,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemWriteEvent {
    pub addr: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    pub index: usize,
    pub ip: u64,
    pub mnemonic: String,
    pub disasm: String,
    pub reads_regs: Vec<String>,
    pub writes_regs: Vec<(String, bool)>,
    pub reads_flags: bool,
    pub writes_flags: bool,
    pub mem_writes: Vec<MemWriteEvent>,
    pub concrete_dst: Option<(String, u64)>,
    pub next_ip: Option<u64>,
    pub is_indirect_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    pub is_api_or_sys: bool,
    pub pure_alu: Option<(String, PureAluOp, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OpKind {
    AssignConst,
    Instr,
    MemWrite,
    ApiCall,
    IndirectBranchResolved,
    VmDispatchSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimplifiedOp {
    pub index: usize,
    pub ip: u64,
    pub kind: OpKind,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoalescedWrite {
    pub addr: u64,
    pub in_stack: bool,
    pub len: usize,
    pub preview_hex: String,
    pub ascii_strings: Vec<String>,
    pub is_pe: bool,
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VmTraceReport {
    pub start_addr: u64,
    pub end_addr: u64,
    pub is_64: bool,
    pub raw_insn_count: usize,
    pub kept_insn_count: usize,
    pub reduction_pct: f64,
    pub dispatcher_ips: Vec<(u64, usize)>,
    pub simplified_ops: Vec<SimplifiedOp>,
    pub mem_writes: Vec<CoalescedWrite>,
    pub api_calls: Vec<ApiCall>,
    pub decrypted_strings: Vec<String>,
    pub harvested_pes: usize,
}

fn is_stack_addr(addr: u64) -> bool {
    addr >= STACK_ADDR && addr < STACK_ADDR + STACK_SIZE
}

/// Canonicalizes x86/x64 registers to their architectural parent name paired with
/// whether a write to this register zeroes/overwrites the full architectural slot.
pub fn canon_reg(reg: Register) -> Option<(&'static str, bool)> {
    match reg {
        Register::RAX | Register::EAX => Some(("RAX", true)),
        Register::AX | Register::AL | Register::AH => Some(("RAX", false)),
        Register::RBX | Register::EBX => Some(("RBX", true)),
        Register::BX | Register::BL | Register::BH => Some(("RBX", false)),
        Register::RCX | Register::ECX => Some(("RCX", true)),
        Register::CX | Register::CL | Register::CH => Some(("RCX", false)),
        Register::RDX | Register::EDX => Some(("RDX", true)),
        Register::DX | Register::DL | Register::DH => Some(("RDX", false)),
        Register::RSI | Register::ESI => Some(("RSI", true)),
        Register::SI | Register::SIL => Some(("RSI", false)),
        Register::RDI | Register::EDI => Some(("RDI", true)),
        Register::DI | Register::DIL => Some(("RDI", false)),
        Register::RBP | Register::EBP => Some(("RBP", true)),
        Register::BP | Register::BPL => Some(("RBP", false)),
        Register::RSP | Register::ESP => Some(("RSP", true)),
        Register::SP | Register::SPL => Some(("RSP", false)),
        Register::R8 | Register::R8D => Some(("R8", true)),
        Register::R8W | Register::R8L => Some(("R8", false)),
        Register::R9 | Register::R9D => Some(("R9", true)),
        Register::R9W | Register::R9L => Some(("R9", false)),
        Register::R10 | Register::R10D => Some(("R10", true)),
        Register::R10W | Register::R10L => Some(("R10", false)),
        Register::R11 | Register::R11D => Some(("R11", true)),
        Register::R11W | Register::R11L => Some(("R11", false)),
        Register::R12 | Register::R12D => Some(("R12", true)),
        Register::R12W | Register::R12L => Some(("R12", false)),
        Register::R13 | Register::R13D => Some(("R13", true)),
        Register::R13W | Register::R13L => Some(("R13", false)),
        Register::R14 | Register::R14D => Some(("R14", true)),
        Register::R14W | Register::R14L => Some(("R14", false)),
        Register::R15 | Register::R15D => Some(("R15", true)),
        Register::R15W | Register::R15L => Some(("R15", false)),
        Register::XMM0 | Register::YMM0 | Register::ZMM0 => Some(("XMM0", true)),
        Register::XMM1 | Register::YMM1 | Register::ZMM1 => Some(("XMM1", true)),
        Register::XMM2 | Register::YMM2 | Register::ZMM2 => Some(("XMM2", true)),
        Register::XMM3 | Register::YMM3 | Register::ZMM3 => Some(("XMM3", true)),
        Register::XMM4 | Register::YMM4 | Register::ZMM4 => Some(("XMM4", true)),
        Register::XMM5 | Register::YMM5 | Register::ZMM5 => Some(("XMM5", true)),
        Register::XMM6 | Register::YMM6 | Register::ZMM6 => Some(("XMM6", true)),
        Register::XMM7 | Register::YMM7 | Register::ZMM7 => Some(("XMM7", true)),
        Register::XMM8 | Register::YMM8 | Register::ZMM8 => Some(("XMM8", true)),
        Register::XMM9 | Register::YMM9 | Register::ZMM9 => Some(("XMM9", true)),
        Register::XMM10 | Register::YMM10 | Register::ZMM10 => Some(("XMM10", true)),
        Register::XMM11 | Register::YMM11 | Register::ZMM11 => Some(("XMM11", true)),
        Register::XMM12 | Register::YMM12 | Register::ZMM12 => Some(("XMM12", true)),
        Register::XMM13 | Register::YMM13 | Register::ZMM13 => Some(("XMM13", true)),
        Register::XMM14 | Register::YMM14 | Register::ZMM14 => Some(("XMM14", true)),
        Register::XMM15 | Register::YMM15 | Register::ZMM15 => Some(("XMM15", true)),
        _ => None,
    }
}

fn read_canon_reg_val<'a>(uc: &unicorn_engine::Unicorn<'a, ()>, reg: Register) -> Option<u64> {
    let uc_reg = match canon_reg(reg)?.0 {
        "RAX" => RegisterX86::RAX,
        "RBX" => RegisterX86::RBX,
        "RCX" => RegisterX86::RCX,
        "RDX" => RegisterX86::RDX,
        "RSI" => RegisterX86::RSI,
        "RDI" => RegisterX86::RDI,
        "RBP" => RegisterX86::RBP,
        "RSP" => RegisterX86::RSP,
        "R8" => RegisterX86::R8,
        "R9" => RegisterX86::R9,
        "R10" => RegisterX86::R10,
        "R11" => RegisterX86::R11,
        "R12" => RegisterX86::R12,
        "R13" => RegisterX86::R13,
        "R14" => RegisterX86::R14,
        "R15" => RegisterX86::R15,
        _ => return None,
    };
    let full = uc.reg_read(uc_reg as i32).ok()?;
    let val = match reg {
        Register::AH | Register::BH | Register::CH | Register::DH => (full >> 8) & 0xFF,
        r if r.size() == 1 => full & 0xFF,
        r if r.size() == 2 => full & 0xFFFF,
        r if r.size() == 4 => full & 0xFFFF_FFFF,
        _ => full,
    };
    Some(val)
}

fn detect_pure_alu(ins: &Instruction) -> Option<(String, PureAluOp, u64)> {
    if ins.op0_kind() != IcedOpKind::Register {
        return None;
    }
    let (dst, _) = canon_reg(ins.op0_register())?;
    if dst == "RSP" {
        return None;
    }
    let op = match ins.mnemonic() {
        Mnemonic::Mov if ins.op1_kind().is_immediate() => {
            (PureAluOp::MovImm, ins.immediate(1))
        }
        Mnemonic::Xor
            if ins.op1_kind() == IcedOpKind::Register && ins.op0_register() == ins.op1_register() =>
        {
            (PureAluOp::SelfXorZero, 0)
        }
        Mnemonic::Add if ins.op1_kind().is_immediate() => (PureAluOp::AddImm, ins.immediate(1)),
        Mnemonic::Sub if ins.op1_kind().is_immediate() => (PureAluOp::SubImm, ins.immediate(1)),
        Mnemonic::Xor if ins.op1_kind().is_immediate() => (PureAluOp::XorImm, ins.immediate(1)),
        _ => return None,
    };
    Some((dst.to_string(), op.0, op.1))
}

trait OpKindExt {
    fn is_immediate(self) -> bool;
}

impl OpKindExt for IcedOpKind {
    fn is_immediate(self) -> bool {
        matches!(
            self,
            IcedOpKind::Immediate8
                | IcedOpKind::Immediate16
                | IcedOpKind::Immediate32
                | IcedOpKind::Immediate64
                | IcedOpKind::Immediate8to16
                | IcedOpKind::Immediate8to32
                | IcedOpKind::Immediate8to64
                | IcedOpKind::Immediate32to64
        )
    }
}

/// Pass 1: Identifies indirect-branch IPs hit at least 3 times as VM handler dispatchers.
pub fn find_dispatcher_ips(steps: &[TraceStep]) -> Vec<(u64, usize)> {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for s in steps {
        if s.is_indirect_branch {
            *counts.entry(s.ip).or_insert(0) += 1;
        }
    }
    let mut dispatchers: Vec<(u64, usize)> = counts
        .into_iter()
        .filter(|&(_, c)| c >= 3)
        .collect();
    dispatchers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    dispatchers
}

/// Pass 2: Backward liveness & dead-store elimination.
/// Pins API calls, non-stack memory writes, remaining uncollapsed branches, and the final
/// return register `RAX`, dropping dead flag writes and overwritten scratch/dispatcher setup.
pub fn strip_dead_stores(
    steps: &[TraceStep],
    dispatcher_set: &HashSet<u64>,
    collapse_dispatchers: bool,
) -> Vec<bool> {
    let n = steps.len();
    let mut keep = vec![false; n];
    if n == 0 {
        return keep;
    }

    let mut live_regs: HashSet<String> = HashSet::new();
    live_regs.insert("RAX".to_string());
    let mut live_flags = false;

    for (idx, step) in steps.iter().enumerate().rev() {
        let is_collapsed_disp = collapse_dispatchers
            && step.is_indirect_branch
            && dispatcher_set.contains(&step.ip);
        if is_collapsed_disp {
            continue;
        }

        let has_non_stack_write = step.mem_writes.iter().any(|w| !is_stack_addr(w.addr));
        let pinned = step.is_api_or_sys
            || has_non_stack_write
            || step.is_call
            || step.is_ret
            || (step.is_indirect_branch && !collapse_dispatchers);

        let writes_live_reg = step.writes_regs.iter().any(|(r, _)| live_regs.contains(r));
        let writes_live_flags = step.writes_flags && live_flags;
        let is_mem_write_any = !step.mem_writes.is_empty();

        // Drop stack-frame pushes/pops whose registers are dead unless they preserve RAX.
        let keep_step = if pinned || writes_live_reg || writes_live_flags {
            true
        } else if is_mem_write_any && has_non_stack_write {
            true
        } else {
            false
        };

        if !keep_step {
            continue;
        }

        keep[idx] = true;

        // Kill registers cleanly overwritten by full-width assignments before adding reads.
        for (reg, full_kill) in &step.writes_regs {
            if *full_kill {
                live_regs.remove(reg);
            }
        }
        if step.writes_flags && !step.reads_flags {
            live_flags = false;
        }

        for r in &step.reads_regs {
            live_regs.insert(r.clone());
        }
        if step.reads_flags {
            live_flags = true;
        }
    }

    keep
}

fn eval_pure_alu(prev: Option<u64>, op: PureAluOp, imm: u64) -> Option<u64> {
    match op {
        PureAluOp::MovImm => Some(imm),
        PureAluOp::SelfXorZero => Some(0),
        PureAluOp::AddImm => Some(prev?.wrapping_add(imm)),
        PureAluOp::SubImm => Some(prev?.wrapping_sub(imm)),
        PureAluOp::XorImm => Some(prev? ^ imm),
    }
}

/// Coalesces contiguous non-stack memory writes in trace order and extracts readable strings / PE markers.
pub fn coalesce_mem_writes(steps: &[TraceStep]) -> (Vec<CoalescedWrite>, Vec<String>) {
    let mut regions: Vec<(u64, Vec<u8>)> = Vec::new();
    for s in steps {
        for w in &s.mem_writes {
            if w.bytes.is_empty() || is_stack_addr(w.addr) {
                continue;
            }
            if let Some(last) = regions.last_mut() {
                let end = last.0.saturating_add(last.1.len() as u64);
                if w.addr == end && last.1.len() + w.bytes.len() <= 1024 * 1024 {
                    last.1.extend_from_slice(&w.bytes);
                    continue;
                } else if w.addr >= last.0 && w.addr + (w.bytes.len() as u64) <= end {
                    let rel = (w.addr - last.0) as usize;
                    last.1[rel..rel + w.bytes.len()].copy_from_slice(&w.bytes);
                    continue;
                }
            }
            regions.push((w.addr, w.bytes.clone()));
        }
    }

    let mut seen_str = HashSet::new();
    let mut high_signal = Vec::new();
    let mut normal = Vec::new();
    let mut out = Vec::with_capacity(regions.len());

    for (addr, bytes) in regions {
        let mut reg_seen = HashSet::new();
        let mut reg_high = Vec::new();
        let mut reg_norm = Vec::new();
        collect_strings_from_bytes(&bytes, &mut reg_seen, &mut reg_high, &mut reg_norm);
        reg_high.extend(reg_norm);
        collect_strings_from_bytes(&bytes, &mut seen_str, &mut high_signal, &mut normal);

        let preview_len = bytes.len().min(48);
        let preview_hex = bytes[..preview_len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let is_pe = bytes.len() >= 0x40 && &bytes[..2] == b"MZ";

        out.push(CoalescedWrite {
            addr,
            in_stack: false,
            len: bytes.len(),
            preview_hex,
            ascii_strings: reg_high,
            is_pe,
            bytes,
        });
    }

    high_signal.extend(normal);
    high_signal.truncate(512);
    (out, high_signal)
}

/// Runs dispatcher detection, backward liveness dead-store elimination, and constant
/// folding/indirect branch resolution over a captured trace.
pub fn simplify_trace(
    steps: &[TraceStep],
    api_calls: &[ApiCall],
    is_64: bool,
    start_addr: u64,
    end_addr: u64,
    harvested_pes: usize,
    cfg: &DevirtConfig,
) -> VmTraceReport {
    let raw_insn_count = steps.len();
    let dispatcher_ips = find_dispatcher_ips(steps);
    let dispatcher_set: HashSet<u64> = dispatcher_ips.iter().map(|&(ip, _)| ip).collect();

    let keep = if cfg.strip_dead_stores {
        strip_dead_stores(steps, &dispatcher_set, cfg.collapse_dispatchers)
    } else {
        steps
            .iter()
            .map(|s| !(cfg.collapse_dispatchers && s.is_indirect_branch && dispatcher_set.contains(&s.ip)))
            .collect()
    };

    let (mem_writes, decrypted_strings) = coalesce_mem_writes(steps);

    let mut simplified_ops = Vec::new();
    let mut emitted_disp = HashSet::new();
    let mut api_idx = 0usize;

    // Pass 3: Constant chain folding & resolved branch formatting
    let mut const_regs: HashMap<String, (u64, usize, u64)> = HashMap::new(); // reg -> (val, start_idx, start_ip)
    let mut kept_insn_count = 0usize;

    let flush_const = |reg: &str,
                       const_regs: &mut HashMap<String, (u64, usize, u64)>,
                       ops: &mut Vec<SimplifiedOp>| {
        if let Some((val, idx, ip)) = const_regs.remove(reg) {
            ops.push(SimplifiedOp {
                index: idx,
                ip,
                kind: OpKind::AssignConst,
                text: format!("{reg} = {val:#x}"),
            });
        }
    };

    for (idx, step) in steps.iter().enumerate() {
        if cfg.collapse_dispatchers && step.is_indirect_branch && dispatcher_set.contains(&step.ip) {
            if emitted_disp.insert(step.ip) {
                let hits = dispatcher_ips
                    .iter()
                    .find(|&&(ip, _)| ip == step.ip)
                    .map(|&(_, c)| c)
                    .unwrap_or(0);
                simplified_ops.push(SimplifiedOp {
                    index: step.index,
                    ip: step.ip,
                    kind: OpKind::VmDispatchSummary,
                    text: format!("vm_dispatcher @ {:#x} ({hits} hops collapsed)", step.ip),
                });
            }
            continue;
        }

        if !keep[idx] {
            continue;
        }

        // Flush any pending folded constant registers read by this non-foldable step.
        if cfg.fold_constants {
            if let Some((ref dst, op, imm)) = step.pure_alu {
                if !step.is_api_or_sys && step.mem_writes.is_empty() {
                    let prev_val = const_regs.get(dst).map(|&(v, _, _)| v);
                    let evaluated = eval_pure_alu(prev_val, op, imm)
                        .or_else(|| step.concrete_dst.as_ref().filter(|(r, _)| r == dst).map(|&(_, v)| v));
                    if let Some(val) = evaluated {
                        let entry = const_regs.entry(dst.clone()).or_insert((val, step.index, step.ip));
                        entry.0 = val;
                        kept_insn_count += 1;
                        continue;
                    }
                }
            }

            let mut to_flush: Vec<String> = step
                .reads_regs
                .iter()
                .filter(|r| const_regs.contains_key(r.as_str()))
                .cloned()
                .collect();
            to_flush.sort();
            to_flush.dedup();
            for r in to_flush {
                flush_const(&r, &mut const_regs, &mut simplified_ops);
            }
            for (wreg, _) in &step.writes_regs {
                const_regs.remove(wreg);
            }
        }

        kept_insn_count += 1;

        if step.is_api_or_sys {
            let text = if let Some(call) = api_calls.get(api_idx) {
                api_idx += 1;
                format!("{}({}) -> {:#x}", call.api, call.args.join(", "), call.ret)
            } else {
                step.disasm.clone()
            };
            simplified_ops.push(SimplifiedOp {
                index: step.index,
                ip: step.ip,
                kind: OpKind::ApiCall,
                text,
            });
            continue;
        }

        if !step.mem_writes.is_empty() {
            let summary = step
                .mem_writes
                .iter()
                .map(|w| {
                    let hx = w
                        .bytes
                        .iter()
                        .take(16)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let scope = if is_stack_addr(w.addr) { "stack" } else { "mem" };
                    format!("{scope}[{:#x}] <- [{}]", w.addr, hx)
                })
                .collect::<Vec<_>>()
                .join("; ");
            simplified_ops.push(SimplifiedOp {
                index: step.index,
                ip: step.ip,
                kind: OpKind::MemWrite,
                text: format!("{}  ; {summary}", step.disasm),
            });
            continue;
        }

        if step.is_indirect_branch {
            let target_str = step
                .next_ip
                .map(|t| format!(" /* -> {t:#x} */"))
                .unwrap_or_default();
            simplified_ops.push(SimplifiedOp {
                index: step.index,
                ip: step.ip,
                kind: OpKind::IndirectBranchResolved,
                text: format!("{}{target_str}", step.disasm),
            });
            continue;
        }

        let text = if let Some((ref dst, val)) = step.concrete_dst {
            format!("{}  ; {dst}={val:#x}", step.disasm)
        } else {
            step.disasm.clone()
        };
        simplified_ops.push(SimplifiedOp {
            index: step.index,
            ip: step.ip,
            kind: OpKind::Instr,
            text,
        });
    }

    if cfg.fold_constants {
        let mut leftover: Vec<String> = const_regs.keys().cloned().collect();
        leftover.sort();
        for r in leftover {
            flush_const(&r, &mut const_regs, &mut simplified_ops);
        }
    }

    let kept_output_ops = simplified_ops.len().min(kept_insn_count.max(simplified_ops.len()));
    let effective_kept = simplified_ops.len();
    let _ = kept_output_ops;
    let reduction_pct = if raw_insn_count > 0 {
        100.0 * (1.0 - (effective_kept as f64 / raw_insn_count as f64)).max(0.0)
    } else {
        0.0
    };

    VmTraceReport {
        start_addr,
        end_addr,
        is_64,
        raw_insn_count,
        kept_insn_count: effective_kept,
        reduction_pct,
        dispatcher_ips,
        simplified_ops,
        mem_writes,
        api_calls: api_calls.to_vec(),
        decrypted_strings,
        harvested_pes,
    }
}

struct TraceCapture {
    steps: Vec<TraceStep>,
    pending_dst: Option<(usize, Register, String)>,
    pending_writes: Vec<MemWriteEvent>,
    max_insns: usize,
    deadline: Instant,
    bitness: u32,
    hook_addr: u64,
    dll_map: HashMap<String, Vec<(String, u64)>>,
    info_factory: InstructionInfoFactory,
    formatter: IntelFormatter,
}

impl UnpackerEngine {
    /// Runs an opt-in single-instruction trace capture from `start`, removes temporary hooks,
    /// and executes VM dispatcher detection, backward dead-store elimination, constant folding,
    /// and non-stack payload coalescing.
    pub fn devirtualize_trace(
        &mut self,
        start: u64,
        cfg: DevirtConfig,
    ) -> UnpackerResult<VmTraceReport> {
        let is_64 = self.is_64();
        let bitness = if is_64 { 64 } else { 32 };
        let dll_map = self.sample.dllname_to_functionlist.clone();
        let hook_addr = self.hook_addr;

        let capture = Rc::new(RefCell::new(TraceCapture {
            steps: Vec::new(),
            pending_dst: None,
            pending_writes: Vec::new(),
            max_insns: cfg.max_insns.max(1),
            deadline: Instant::now() + Duration::from_millis(cfg.timeout_ms.max(1)),
            bitness,
            hook_addr,
            dll_map,
            info_factory: InstructionInfoFactory::new(),
            formatter: IntelFormatter::new(),
        }));

        let (code_hook_id, mem_hook_id) = {
            let uc = self
                .uc
                .as_mut()
                .ok_or_else(|| UnpackerError::EmulatorError("engine not initialized".into()))?;

            let cap_mem = Rc::clone(&capture);
            let mem_hook = uc
                .add_mem_hook(UcHookType::MEM_WRITE, 0, u64::MAX, move |_uc, _t, addr, size, value| {
                    if let Ok(mut c) = cap_mem.try_borrow_mut() {
                        let byte_len = size.clamp(1, 8);
                        let bytes = value.to_le_bytes()[..byte_len].to_vec();
                        c.pending_writes.push(MemWriteEvent { addr, bytes });
                    }
                    true
                })
                .map_err(|e| UnpackerError::EmulatorError(format!("devirt mem hook: {e:?}")))?;

            let cap_code = Rc::clone(&capture);
            let code_hook = uc
                .add_code_hook(1, 0, move |uc, addr, size| {
                    if addr == SEH_RETURN_ADDR
                        || addr == SEH64_RETURN_ADDR
                        || addr == ENTRY_RETURN_ADDR
                    {
                        return;
                    }
                    let Ok(mut c) = cap_code.try_borrow_mut() else {
                        return;
                    };

                    // Finalize concrete destination & memory writes from previous step
                    if let Some((prev_idx, reg, reg_name)) = c.pending_dst.take() {
                        let val = read_canon_reg_val(uc, reg);
                        if let Some(prev) = c.steps.get_mut(prev_idx) {
                            if let Some(v) = val {
                                prev.concrete_dst = Some((reg_name, v));
                            }
                        }
                    }
                    let mut writes = std::mem::take(&mut c.pending_writes);
                    if let Some(prev) = c.steps.last_mut() {
                        if !writes.is_empty() {
                            prev.mem_writes.append(&mut writes);
                        }
                        if prev.next_ip.is_none() {
                            prev.next_ip = Some(addr);
                        }
                    }

                    if c.steps.len() >= c.max_insns || Instant::now() >= c.deadline {
                        let _ = uc.emu_stop();
                        return;
                    }

                    if addr >= c.hook_addr && addr < c.hook_addr + HOOK_REGION_SIZE {
                        let (api_opt, _dll_opt) =
                            apicalls::resolve_api_and_dll(addr, &c.dll_map);
                        let api_name = api_opt.unwrap_or_else(|| format!("stub_{addr:#x}"));
                        let step_idx = c.steps.len();
                        c.steps.push(TraceStep {
                            index: step_idx,
                            ip: addr,
                            mnemonic: "api_call".to_string(),
                            disasm: format!("call {api_name}"),
                            reads_regs: Vec::new(),
                            writes_regs: vec![("RAX".to_string(), true)],
                            reads_flags: false,
                            writes_flags: false,
                            mem_writes: Vec::new(),
                            concrete_dst: None,
                            next_ip: None,
                            is_indirect_branch: false,
                            is_call: true,
                            is_ret: false,
                            is_api_or_sys: true,
                            pure_alu: None,
                        });
                        return;
                    }

                    let read_len = (size as usize).clamp(1, 15);
                    let mut buf = [0u8; 15];
                    if uc.mem_read(addr, &mut buf[..read_len]).is_err() {
                        return;
                    }
                    let mut dec = Decoder::with_ip(c.bitness, &buf[..read_len], addr, DecoderOptions::NONE);
                    let ins = dec.decode();
                    if ins.is_invalid() {
                        return;
                    }

                    let mut disasm = String::new();
                    c.formatter.format(&ins, &mut disasm);

                    let info = c.info_factory.info(&ins);
                    let mut reads_regs = Vec::new();
                    let mut writes_regs = Vec::new();
                    let mut primary_write_reg: Option<(Register, String)> = None;

                    for used in info.used_registers() {
                        if let Some((canon, full_kill)) = canon_reg(used.register()) {
                            let cname = canon.to_string();
                            let acc = used.access();
                            if acc.reads() && !reads_regs.contains(&cname) {
                                reads_regs.push(cname.clone());
                            }
                            if acc.writes() {
                                if !writes_regs.iter().any(|(r, _)| r == &cname) {
                                    writes_regs.push((cname.clone(), full_kill));
                                }
                                if primary_write_reg.is_none() && cname != "RSP" {
                                    primary_write_reg = Some((used.register(), cname));
                                }
                            }
                        }
                    }

                    let reads_flags = ins.rflags_read() != 0;
                    let writes_flags = ins.rflags_modified() != 0;
                    let flow = ins.flow_control();
                    let is_indirect_branch = matches!(flow, FlowControl::IndirectBranch | FlowControl::IndirectCall);
                    let is_call = matches!(flow, FlowControl::Call | FlowControl::IndirectCall);
                    let is_ret = flow == FlowControl::Return;
                    let is_api_or_sys = matches!(
                        ins.mnemonic(),
                        Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int | Mnemonic::Int3
                    );
                    let pure_alu = detect_pure_alu(&ins);
                    let mnemonic = format!("{:?}", ins.mnemonic()).to_ascii_lowercase();

                    let step_idx = c.steps.len();
                    c.steps.push(TraceStep {
                        index: step_idx,
                        ip: addr,
                        mnemonic,
                        disasm,
                        reads_regs,
                        writes_regs,
                        reads_flags,
                        writes_flags,
                        mem_writes: Vec::new(),
                        concrete_dst: None,
                        next_ip: None,
                        is_indirect_branch,
                        is_call,
                        is_ret,
                        is_api_or_sys,
                        pure_alu,
                    });

                    if !is_call && !is_ret && !is_api_or_sys {
                        if let Some((reg, rname)) = primary_write_reg {
                            c.pending_dst = Some((step_idx, reg, rname));
                        }
                    }
                })
                .map_err(|e| UnpackerError::EmulatorError(format!("devirt code hook: {e:?}")))?;

            (code_hook, mem_hook)
        };

        let prev_limits = self.swap_run_limits(u64::MAX, false, false);
        let run_res = self.emu_from(
            start,
            cfg.timeout_ms.saturating_mul(1000),
            cfg.max_insns,
        );
        self.swap_run_limits(prev_limits.0, prev_limits.1, prev_limits.2);

        // Always remove temporary hooks and finalize trailing captured step
        if let Some(uc) = self.uc.as_mut() {
            let _ = uc.remove_hook(code_hook_id);
            let _ = uc.remove_hook(mem_hook_id);

            let mut c = capture.borrow_mut();
            let exit_ip = uc
                .reg_read(if is_64 { RegisterX86::RIP } else { RegisterX86::EIP } as i32)
                .unwrap_or(start);
            if let Some((prev_idx, reg, reg_name)) = c.pending_dst.take() {
                let val = read_canon_reg_val(uc, reg);
                if let Some(prev) = c.steps.get_mut(prev_idx) {
                    if let Some(v) = val {
                        prev.concrete_dst = Some((reg_name, v));
                    }
                }
            }
            let mut writes = std::mem::take(&mut c.pending_writes);
            if let Some(prev) = c.steps.last_mut() {
                if !writes.is_empty() {
                    prev.mem_writes.append(&mut writes);
                }
                if prev.next_ip.is_none() {
                    prev.next_ip = Some(exit_ip);
                }
            }
        }

        // Ignore benign instruction-budget stop; propagate actual emulator errors only if nothing ran
        if let Err(e) = run_res {
            if capture.borrow().steps.is_empty() {
                return Err(e);
            }
        }

        let exit_ip = self.ip().unwrap_or(start);
        let harvested_pes = self.harvest_written_payloads().iter().filter(|p| p.is_pe).count();
        let api_calls = self.api_trace().to_vec();
        let steps = capture.borrow().steps.clone();

        Ok(simplify_trace(
            &steps,
            &api_calls,
            is_64,
            start,
            exit_ip,
            harvested_pes,
            &cfg,
        ))
    }
}

trait OpAccessExt {
    fn reads(self) -> bool;
    fn writes(self) -> bool;
}

impl OpAccessExt for iced_x86::OpAccess {
    fn reads(self) -> bool {
        matches!(
            self,
            iced_x86::OpAccess::Read
                | iced_x86::OpAccess::CondRead
                | iced_x86::OpAccess::ReadWrite
                | iced_x86::OpAccess::ReadCondWrite
        )
    }

    fn writes(self) -> bool {
        matches!(
            self,
            iced_x86::OpAccess::Write
                | iced_x86::OpAccess::CondWrite
                | iced_x86::OpAccess::ReadWrite
                | iced_x86::OpAccess::ReadCondWrite
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpacker::engine::Sample;

    fn make_x64_pe_two_sections(sec0: &[u8], sec1: &[u8], sec1_name: &[u8; 8]) -> Vec<u8> {
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
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        pe[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let s0 = opt + 240;
        pe[s0..s0 + 5].copy_from_slice(b".text");
        pe[s0 + 8..s0 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[s0 + 12..s0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[s0 + 16..s0 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[s0 + 20..s0 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        pe[s0 + 36..s0 + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        let s1 = s0 + 40;
        pe[s1..s1 + 8].copy_from_slice(sec1_name);
        pe[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[s1 + 16..s1 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[s1 + 20..s1 + 24].copy_from_slice(&0x1400u32.to_le_bytes());
        pe[s1 + 36..s1 + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        pe[0x400..0x400 + sec0.len().min(0x1000)].copy_from_slice(&sec0[..sec0.len().min(0x1000)]);
        pe[0x1400..0x1400 + sec1.len().min(0x1000)].copy_from_slice(&sec1[..sec1.len().min(0x1000)]);
        pe
    }

    #[test]
    fn static_classifier_distinguishes_vm_section_from_linear_code() {
        // Normal linear code: repeated `xor eax, eax; add eax, 1; cmp eax, 2; je +0; ret`
        let linear: Vec<u8> = [0x31, 0xC0, 0x83, 0xC0, 0x01, 0x83, 0xF8, 0x02, 0x74, 0x00, 0xC3]
            .repeat(64);
        // VM-like section: `pushfq; push rbx; push rcx; push rdx; push rsi; jmp rax` repeated
        let vm_like: Vec<u8> = [0x9C, 0x53, 0x51, 0x52, 0x56, 0xFF, 0xE0].repeat(64);

        let pe = make_x64_pe_two_sections(&linear, &vm_like, b".vmp0\0\0\0");
        let prof = detect_vm_sections(&pe).unwrap();
        assert_eq!(prof.executable_sections.len(), 2);
        let s0 = &prof.executable_sections[0];
        let s1 = &prof.executable_sections[1];
        assert_eq!(s0.kind, SectionVmKind::Normal);
        assert_eq!(s1.kind, SectionVmKind::Virtualized);
        assert!(s1.vm_score > s0.vm_score + 0.4);
    }

    #[test]
    fn mba_constant_folding_and_dead_store_elimination_collapse_noise() {
        let step = |idx: usize,
                    dst: &str,
                    op: PureAluOp,
                    imm: u64,
                    reads: &[&str],
                    disasm: &str| TraceStep {
            index: idx,
            ip: 0x1000 + (idx as u64 * 4),
            mnemonic: "alu".to_string(),
            disasm: disasm.to_string(),
            reads_regs: reads.iter().map(|s| s.to_string()).collect(),
            writes_regs: vec![(dst.to_string(), true)],
            reads_flags: false,
            writes_flags: true,
            mem_writes: Vec::new(),
            concrete_dst: None,
            next_ip: None,
            is_indirect_branch: false,
            is_call: false,
            is_ret: false,
            is_api_or_sys: false,
            pure_alu: Some((dst.to_string(), op, imm)),
        };

        let trace = vec![
            // Dead scratch assignments to RCX that never reach RAX or memory
            step(0, "RCX", PureAluOp::MovImm, 0x1111, &[], "mov rcx, 0x1111"),
            step(1, "RCX", PureAluOp::XorImm, 0x2222, &["RCX"], "xor rcx, 0x2222"),
            // Obfuscated constant computation into RAX: (((0x10 ^ 0x42) + 0x5) - 0x2) = 0x55
            step(2, "RAX", PureAluOp::MovImm, 0x10, &[], "mov rax, 0x10"),
            step(3, "RAX", PureAluOp::XorImm, 0x42, &["RAX"], "xor rax, 0x42"),
            step(4, "RAX", PureAluOp::AddImm, 0x05, &["RAX"], "add rax, 0x05"),
            step(5, "RAX", PureAluOp::SubImm, 0x02, &["RAX"], "sub rax, 0x02"),
            // Return uses RAX
            TraceStep {
                index: 6,
                ip: 0x1018,
                mnemonic: "ret".to_string(),
                disasm: "ret".to_string(),
                reads_regs: vec!["RAX".to_string()],
                writes_regs: Vec::new(),
                reads_flags: false,
                writes_flags: false,
                mem_writes: Vec::new(),
                concrete_dst: None,
                next_ip: None,
                is_indirect_branch: false,
                is_call: false,
                is_ret: true,
                is_api_or_sys: false,
                pure_alu: None,
            },
        ];

        let report = simplify_trace(&trace, &[], true, 0x1000, 0x1018, 0, &DevirtConfig::default());
        assert_eq!(report.raw_insn_count, 7);
        assert_eq!(report.kept_insn_count, 2); // `RAX = 0x55` + `ret`
        assert!(report.simplified_ops.iter().any(|o| o.kind == OpKind::AssignConst && o.text == "RAX = 0x55"));
    }

    #[test]
    fn e2e_threaded_vm_trace_recovers_decrypted_url_and_collapses_dispatcher() {
        // Construct a real x64 tiny PE implementing a miniature threaded-code VM at VA 0x140001000:
        //
        // Bytecode stream (in sec1 @ VA 0x140002100): sequence of 1-byte encrypted chars, 0-terminated.
        // Target output buffer (in sec1 @ VA 0x140002200): non-stack PE data buffer.
        // Handler table (in sec1 @ VA 0x140002000): [h_xor_store, h_done] (each u64 VA)
        //
        // VM entry @ VA 0x140001000 (EP RVA = 0x1000):
        //   push rbx; push rsi; push rdi; push r12   (context save)
        //   lea rsi, [rip + disp -> 0x2100]          (VM PC -> bytecode)
        //   lea rdi, [rip + disp -> 0x2200]          (out buffer)
        //   lea rbx, [rip + disp -> 0x2000]          (handler table)
        //   xor r12d, r12d                           (noise counter)
        // dispatch: (0x140001020)
        //   movzx eax, byte ptr [rsi]                (0f b6 06)
        //   test eax, eax                            (85 c0)
        //   setz r12b                                (41 0f 94 c4) -> handler idx 0 or 1
        //   movzx edx, r12b                          (41 0f b6 d4)
        //   mov rax, [rbx + rdx*8]                   (48 8b 04 d3) -> fetch handler VA
        //   jmp rax                                  (ff e0)       -> DISPATCHER HOP!
        // h_xor_store: (0x140001040)
        //   movzx ecx, byte ptr [rsi]                (0f b6 0e)
        //   xor ecx, 0x5A                            (83 f1 5a)
        //   xor edx, edx                             (dead scratch)
        //   add edx, 0x1234                          (dead scratch)
        //   mov byte ptr [rdi], cl                   (88 0f)       -> observable non-stack write!
        //   inc rsi                                  (48 ff c6)
        //   inc rdi                                  (48 ff c7)
        //   jmp dispatch (0x140001020)
        // h_done: (0x140001060)
        //   pop r12; pop rdi; pop rsi; pop rbx
        //   mov eax, 1
        //   ret
        let mut sec0 = vec![0x90u8; 0x200];
        let entry: &[u8] = &[
            0x53, 0x56, 0x57, 0x41, 0x54,             // push rbx; rsi; rdi; r12 (5 bytes @ 0x00)
            0x48, 0x8D, 0x35, 0xF4, 0x10, 0x00, 0x00, // lea rsi, [rip + 0x10f4] -> 0x1000+12+0x10f4 = 0x2100 (7 bytes @ 0x05..0x0C)
            0x48, 0x8D, 0x3D, 0xED, 0x11, 0x00, 0x00, // lea rdi, [rip + 0x11ed] -> 0x1000+19+0x11ed = 0x2200 (7 bytes @ 0x0C..0x13)
            0x48, 0x8D, 0x1D, 0xE6, 0x0F, 0x00, 0x00, // lea rbx, [rip + 0x0fe6] -> 0x1000+26+0x0fe6 = 0x2000 (7 bytes @ 0x13..0x1A)
            0x45, 0x31, 0xE4,                         // xor r12d, r12d (3 bytes @ 0x1A..0x1D)
            0xEB, 0x01,                               // jmp +1 -> 0x20 (2 bytes @ 0x1D..0x1F)
        ];
        sec0[0..entry.len()].copy_from_slice(entry);

        let dispatch: &[u8] = &[
            0x0F, 0xB6, 0x06,                         // movzx eax, byte ptr [rsi]
            0x85, 0xC0,                               // test eax, eax
            0x41, 0x0F, 0x94, 0xC4,                   // sete r12b
            0x41, 0x0F, 0xB6, 0xD4,                   // movzx edx, r12b
            0x48, 0x8B, 0x04, 0xD3,                   // mov rax, [rbx + rdx*8]
            0xFF, 0xE0,                               // jmp rax (@ RVA 0x1031)
        ];
        sec0[0x20..0x20 + dispatch.len()].copy_from_slice(dispatch);

        let h_xor_store: &[u8] = &[
            0x0F, 0xB6, 0x0E,                         // movzx ecx, byte ptr [rsi]
            0x83, 0xF1, 0x5A,                         // xor ecx, 0x5A
            0x31, 0xD2,                               // xor edx, edx (dead scratch)
            0x81, 0xC2, 0x34, 0x12, 0x00, 0x00,       // add edx, 0x1234 (dead scratch)
            0x88, 0x0F,                               // mov byte ptr [rdi], cl
            0x48, 0xFF, 0xC6,                         // inc rsi
            0x48, 0xFF, 0xC7,                         // inc rdi
            0xEB, 0xC8,                               // jmp 0x20: target = 0x40+24-56 = 0x20! (0x40+24=0x58; 0x20 - 0x58 = -0x38 = 0xC8)
        ];
        sec0[0x40..0x40 + h_xor_store.len()].copy_from_slice(h_xor_store);

        let h_done: &[u8] = &[
            0x41, 0x5C, 0x5F, 0x5E, 0x5B,             // pop r12; rdi; rsi; rbx
            0xB8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
            0xC3,                                     // ret
        ];
        sec0[0x60..0x60 + h_done.len()].copy_from_slice(h_done);

        let mut sec1 = vec![0u8; 0x400];
        let base = 0x1_4000_0000u64;
        // Handler table at sec1+0x000 (VA 0x140002000)
        sec1[0..8].copy_from_slice(&(base + 0x1040).to_le_bytes());
        sec1[8..16].copy_from_slice(&(base + 0x1060).to_le_bytes());

        // XOR-0x5A encoded payload at sec1+0x100 (VA 0x140002100)
        let secret = b"https://c2.example/payload";
        for (i, &b) in secret.iter().enumerate() {
            sec1[0x100 + i] = b ^ 0x5A;
        }
        sec1[0x100 + secret.len()] = 0;

        let pe = make_x64_pe_two_sections(&sec0, &sec1, b".textvm\0");
        let sample = Sample::from_bytes(&pe).unwrap();
        let mut eng = UnpackerEngine::new(sample, "mem").with_trace_mode(true);
        eng.init_uc().unwrap();

        // Call via call_function setup so RET returns to ENTRY_RETURN_ADDR cleanly?
        // Push ENTRY_RETURN_ADDR on stack cleanly before devirtualize_trace:
        {
            let uc = eng.unicorn_mut().unwrap();
            let rsp = uc.reg_read(RegisterX86::RSP as i32).unwrap() - 8;
            uc.mem_write(rsp, &ENTRY_RETURN_ADDR.to_le_bytes()).unwrap();
            uc.reg_write(RegisterX86::RSP as i32, rsp).unwrap();
        }

        let report = eng
            .devirtualize_trace(base + 0x1000, DevirtConfig::default())
            .unwrap();

        assert!(
            report.dispatcher_ips.iter().any(|&(ip, c)| ip == base + 0x1031 && c == secret.len() + 1),
            "expected VM dispatcher at {:#x} with {} hits, got {:?}",
            base + 0x1031,
            secret.len() + 1,
            report.dispatcher_ips
        );
        assert!(
            report.reduction_pct >= 40.0 && report.kept_insn_count < report.raw_insn_count,
            "expected >=40% reduction, got raw={} kept={} ({:.1}%)",
            report.raw_insn_count,
            report.kept_insn_count,
            report.reduction_pct
        );
        assert!(
            report.decrypted_strings.iter().any(|s| s == "https://c2.example/payload"),
            "expected decrypted URL in {:?}",
            report.decrypted_strings
        );
        assert!(
            report.mem_writes.iter().any(|w| w.addr == base + 0x2200 && w.bytes == secret),
            "expected coalesced write of decrypted payload at {:#x}, got {:?}",
            base + 0x2200,
            report.mem_writes
        );
    }
}
