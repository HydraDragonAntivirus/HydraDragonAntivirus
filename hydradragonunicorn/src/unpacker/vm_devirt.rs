//! Binary-wide symbolic CFG VM devirtualizer and native x86/x64 recompiler.
//!
//! Pipeline:
//! 1. Static discovery (`discover_vm_entries`): scans primary host sections (such as `.text`)
//!    for cross-section `vmenter` calls/jumps and indirect-branch trampolines targeting VM /
//!    obfuscated sections classified by [`crate::unpacker::vm::detect_vm_sections`].
//! 2. Symbolic CFG lifting (`lift_vm_entry_cfg`): executes each entry across concrete and
//!    symbolic paths inside [`ExprArena`] + [`SymStack`], unfolding unrolled context-copy loops,
//!    simplifying MBA arithmetic and opaque predicates, resolving `cmovcc` indirect jumps, and
//!    recording only genuinely observable side effects.
//! 3. Soundness gate & native recompilation (`compile_devirt_section`): rejects any CFG with
//!    bailouts, unresolved aliases, modified XMM state, or `Opaque` live outputs; re-compiles
//!    verified CFGs into `.devirt` via `iced_x86::code_asm::CodeAssembler`, verifies decoded
//!    machine code, patches original host sites, and computes honest binary coverage stats.

use std::collections::{HashMap, HashSet, VecDeque};

use iced_x86::code_asm::registers::{gpr16, gpr32, gpr64, gpr8, xmm};
use iced_x86::code_asm::{
    byte_ptr, dword_ptr, ptr, qword_ptr, word_ptr, AsmMemoryOperand, AsmRegister16,
    AsmRegister32, AsmRegister64, AsmRegister8, AsmRegisterXmm, CodeAssembler, CodeLabel,
};
use iced_x86::{
    BlockEncoderOptions, ConditionCode, Decoder, DecoderOptions, FlowControl, Formatter,
    Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};
use serde::Serialize;

use crate::unpacker::engine::{parse_pe_bytes, Section as PeSection};
use crate::unpacker::error::{UnpackerError, UnpackerResult};
use crate::unpacker::imagedump;
use crate::unpacker::vm::{detect_vm_sections, SectionVmKind};
use crate::unpacker::vm_ir::{
    width_mask, ArchReg, CondPred, ExprArena, ExprId, ExprNode, RegSlice, StackSpace, SymStack,
};

// ---------------------------------------------------------------------------
// Public configuration & report structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BinaryDevirtConfig {
    pub max_entries: usize,
    pub max_blocks_per_entry: usize,
    pub max_insns_per_block: usize,
    pub max_total_insns_per_entry: usize,
    pub max_inline_depth: usize,
    pub include_trampolines: bool,
    pub include_vmenters: bool,
    pub extra_entry_rvas: Vec<u32>,
    /// Recompile a function up to the point the lifter cannot go on (a jump whose
    /// target depends on run-time data, an instruction it does not model, the
    /// block/instruction budget) and continue in the original code there
    /// (`IrTerm::ExitToVm`). Off: such functions are rejected, so every patched
    /// function is fully native.
    pub allow_vm_exits: bool,
    pub collect_diagnostics: bool,
}

impl Default for BinaryDevirtConfig {
    fn default() -> Self {
        Self {
            max_entries: usize::MAX,
            max_blocks_per_entry: 64,
            max_insns_per_block: 4_000,
            max_total_insns_per_entry: 25_000,
            max_inline_depth: 8,
            include_trampolines: true,
            include_vmenters: true,
            extra_entry_rvas: Vec::new(),
            allow_vm_exits: true,
            collect_diagnostics: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum VmEntryKind {
    CrossSectionVmEnter,
    IndirectBranchTrampoline,
    StandaloneVmStub,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredEntry {
    pub kind: VmEntryKind,
    pub patch_rva: u32,
    pub patch_size: usize,
    pub is_call: bool,
    pub lift_start_rva: u32,
    pub target_rva: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchedSiteInfo {
    pub kind: VmEntryKind,
    pub patch_rva: u32,
    pub patch_size: usize,
    pub stub_rva: u32,
    pub raw_vm_insns: usize,
    pub native_insns: usize,
    pub opaque_branches_folded: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryDevirtReport {
    pub is_64: bool,
    pub discovered_total: usize,
    pub discovered_vmenters: usize,
    pub discovered_trampolines: usize,
    pub discovered_standalone: usize,
    pub devirtualized_total: usize,
    pub devirtualized_vmenters: usize,
    pub devirtualized_trampolines: usize,
    pub partially_lifted: usize,
    /// Of the devirtualized functions: those that hand control back to the original
    /// code somewhere (`IrTerm::ExitToVm`); the rest are fully native.
    pub hybrid_vm_exits: usize,
    pub failed: usize,
    pub entry_devirt_pct: f64,
    pub raw_vm_insns_eliminated: usize,
    pub recompiled_native_insns: usize,
    pub code_reduction_pct: f64,
    pub opaque_branches_folded: usize,
    pub unique_vm_bytes_visited: usize,
    pub total_vm_section_bytes: usize,
    pub vm_byte_coverage_pct: f64,
    pub devirt_section_rva: Option<u32>,
    pub devirt_section_size: usize,
    pub bailout_reasons: Vec<(String, usize)>,
    pub bailouts_by_kind: Vec<(VmEntryKind, String, usize)>,
    pub bailout_samples: Vec<(VmEntryKind, u32, u64, String, String)>,
    pub indirect_jmp_ip_clusters: Vec<(VmEntryKind, u64, String, usize)>,
    pub patched_sites: Vec<PatchedSiteInfo>,
}

// ---------------------------------------------------------------------------
// PE Image View & Static Section Metadata
// ---------------------------------------------------------------------------

struct SectionMeta {
    name_lower: String,
    va: u32,
    vsz: u32,
    raw_size: u32,
    is_exec: bool,
    is_ro_const: bool,
    is_primary_host: bool,
    is_vm_section: bool,
}

pub struct PeImageView {
    pub image_base: u64,
    pub image_size: u64,
    pub bitness: u32,
    pub entry_point_rva: u32,
    image_mem: Vec<u8>,
    sections: Vec<SectionMeta>,
    pdata_primary_ranges: Vec<(u32, u32)>,
    mutable_ro_ranges: Vec<(u32, u32)>,
    total_vm_section_bytes: usize,
}

impl PeImageView {
    pub fn from_pe_bytes(pe_bytes: &[u8]) -> UnpackerResult<Self> {
        let (_dos, pe, opt, raw_secs) = parse_pe_bytes(pe_bytes)?;
        let is_64 = pe.machine == 0x8664 || opt.magic == 0x20B;
        let bitness = if is_64 { 64 } else { 32 };
        if !is_64 && pe.machine != 0x14C {
            return Err(UnpackerError::InvalidPeFile(format!(
                "unsupported architecture machine={:#x} for x86/x64 devirtualization",
                pe.machine
            )));
        }

        let sec_align = opt.section_alignment.max(0x1000);
        let max_va_end = raw_secs
            .iter()
            .map(|s| s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data)))
            .max()
            .unwrap_or(opt.size_of_image)
            .max(opt.size_of_image);
        let mapped_len = ((max_va_end as usize + sec_align as usize - 1) & !(sec_align as usize - 1))
            .max(0x2000);

        let mut image_mem = vec![0u8; mapped_len];
        let hdr_copy = (opt.size_of_headers as usize).min(pe_bytes.len()).min(mapped_len);
        image_mem[..hdr_copy].copy_from_slice(&pe_bytes[..hdr_copy]);
        for s in &raw_secs {
            if s.size_of_raw_data == 0 || s.pointer_to_raw_data == 0 {
                continue;
            }
            let src_start = s.pointer_to_raw_data as usize;
            let dst_start = s.virtual_address as usize;
            if src_start >= pe_bytes.len() || dst_start >= mapped_len {
                continue;
            }
            let copy_len = (s.size_of_raw_data as usize)
                .min(pe_bytes.len() - src_start)
                .min(mapped_len - dst_start);
            image_mem[dst_start..dst_start + copy_len]
                .copy_from_slice(&pe_bytes[src_start..src_start + copy_len]);
        }

        let vm_prof = detect_vm_sections(pe_bytes)?;
        let exec_count = vm_prof.executable_sections.len();

        // Pick primary host section: prefer section containing OEP, else `.text`/`.code`
        let primary_va = raw_secs
            .iter()
            .find(|s| {
                (s.characteristics & 0x2000_0000) != 0
                    && opt.address_of_entry_point >= s.virtual_address
                    && opt.address_of_entry_point
                        < s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data))
            })
            .map(|s| s.virtual_address)
            .or_else(|| {
                vm_prof
                    .executable_sections
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(".text") || s.name.eq_ignore_ascii_case(".code"))
                    .map(|s| s.virtual_address)
            })
            .or_else(|| vm_prof.executable_sections.first().map(|s| s.virtual_address));

        let mut total_vm_section_bytes = 0usize;
        let sections: Vec<SectionMeta> = raw_secs
            .iter()
            .map(|s| {
                let name_lower = s.name.trim().to_ascii_lowercase();
                let is_exec = (s.characteristics & 0x2000_0000) != 0;
                let is_write = (s.characteristics & 0x8000_0000) != 0;
                let prof = vm_prof
                    .executable_sections
                    .iter()
                    .find(|v| v.virtual_address == s.virtual_address);
                let is_primary_host = is_exec && Some(s.virtual_address) == primary_va && exec_count > 1;
                let is_vm_section = if exec_count <= 1 {
                    is_exec && prof.is_some_and(|v| v.kind != SectionVmKind::Normal)
                } else {
                    is_exec
                        && !is_primary_host
                        && (prof.is_some_and(|v| v.kind != SectionVmKind::Normal)
                            || (s.name.trim().is_empty() && s.size_of_raw_data > 16 * 1024))
                };
                if is_vm_section {
                    total_vm_section_bytes += s.virtual_size.max(s.size_of_raw_data) as usize;
                }
                let is_ro_const = (!is_write && name_lower != ".data" && name_lower != ".bss")
                    || (is_exec && !is_write)
                    || is_vm_section
                    || name_lower == ".rdata";

                SectionMeta {
                    name_lower,
                    va: s.virtual_address,
                    vsz: s.virtual_size,
                    raw_size: s.size_of_raw_data,
                    is_exec,
                    is_ro_const,
                    is_primary_host,
                    is_vm_section,
                }
            })
            .collect();

        // Parse .pdata RUNTIME_FUNCTION ranges inside primary host sections (PE64)
        let mut pdata_primary_ranges = Vec::new();
        if is_64 {
            if let Some(exc) = opt.data_directory.get(3).filter(|d| d.virtual_address != 0 && d.size >= 12) {
                let start = exc.virtual_address as usize;
                let end = start.saturating_add(exc.size as usize).min(image_mem.len());
                let mut cur = start;
                while cur + 12 <= end {
                    let beg = u32::from_le_bytes(image_mem[cur..cur + 4].try_into().unwrap());
                    let func_end = u32::from_le_bytes(image_mem[cur + 4..cur + 8].try_into().unwrap());
                    cur += 12;
                    if func_end > beg
                        && sections
                            .iter()
                            .any(|s| s.is_primary_host && beg >= s.va && func_end <= s.va + s.vsz.max(s.raw_size))
                    {
                        pdata_primary_ranges.push((beg, func_end));
                    }
                }
            }
        }
        pdata_primary_ranges.sort_unstable();

        let mut mutable_ro_ranges = Vec::new();
        for dir_idx in [12usize, 10usize] {
            if let Some(dir) = opt.data_directory.get(dir_idx) {
                if dir.virtual_address != 0 && dir.size != 0 {
                    mutable_ro_ranges.push((
                        dir.virtual_address,
                        dir.virtual_address.saturating_add(dir.size),
                    ));
                }
            }
        }

        Ok(Self {
            image_base: opt.image_base,
            image_size: mapped_len as u64,
            bitness,
            entry_point_rva: opt.address_of_entry_point,
            image_mem,
            sections,
            pdata_primary_ranges,
            mutable_ro_ranges,
            total_vm_section_bytes,
        })
    }

    #[inline]
    pub fn va_to_rva(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        if rva < self.image_mem.len() as u64 {
            Some(rva as usize)
        } else {
            None
        }
    }

    fn section_at_va(&self, va: u64) -> Option<&SectionMeta> {
        let rva = self.va_to_rva(va)? as u32;
        self.sections
            .iter()
            .find(|s| rva >= s.va && rva < s.va.saturating_add(s.vsz.max(s.raw_size)))
    }

    #[inline]
    pub fn is_in_vm_section(&self, va: u64) -> bool {
        self.section_at_va(va).is_some_and(|s| s.is_vm_section)
    }

    #[inline]
    pub fn is_executable_va(&self, va: u64) -> bool {
        self.section_at_va(va).is_some_and(|s| s.is_exec)
    }

    pub fn read_ro_bytes(&self, va: u64, len: usize) -> Option<&[u8]> {
        let sec = self.section_at_va(va)?;
        if !sec.is_ro_const && sec.name_lower != ".rdata" {
            return None;
        }
        let rva = self.va_to_rva(va)?;
        let end = rva.checked_add(len)?;
        let sec_end = (sec.va + sec.vsz.max(sec.raw_size)) as usize;
        if end <= sec_end && end <= self.image_mem.len() {
            if self
                .mutable_ro_ranges
                .iter()
                .any(|&(lo, hi)| (rva as u32) < hi && (end as u32) > lo)
            {
                return None;
            }
            Some(&self.image_mem[rva..end])
        } else {
            None
        }
    }

    pub fn read_exec_slice(&self, va: u64, max_len: usize) -> Option<&[u8]> {
        let sec = self.section_at_va(va)?;
        if !sec.is_exec {
            return None;
        }
        let rva = self.va_to_rva(va)?;
        let sec_end = ((sec.va + sec.vsz.max(sec.raw_size)) as usize).min(self.image_mem.len());
        if rva >= sec_end {
            return None;
        }
        Some(&self.image_mem[rva..sec_end.min(rva + max_len)])
    }

    pub fn decode_insn(&self, va: u64) -> Option<Instruction> {
        let bytes = self.read_exec_slice(va, 15)?;
        if bytes.is_empty() {
            return None;
        }
        let mut dec = Decoder::with_ip(self.bitness, bytes, va, DecoderOptions::NONE);
        let ins = dec.decode();
        if ins.is_invalid() || ins.len() == 0 {
            None
        } else {
            Some(ins)
        }
    }

    pub fn read_ro_scalar(&self, va: u64, width: u8) -> Option<u64> {
        let b = self.read_ro_bytes(va, width as usize)?;
        Some(match width {
            1 => b[0] as u64,
            2 => u16::from_le_bytes([b[0], b[1]]) as u64,
            4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64,
            8 => u64::from_le_bytes(b[..8].try_into().ok()?),
            _ => return None,
        })
    }
}

fn pe_rva_to_raw(sections: &[PeSection], rva: u32, file_len: usize) -> Option<usize> {
    for s in sections {
        let span = s.virtual_size.max(s.size_of_raw_data);
        if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span) {
            if s.pointer_to_raw_data == 0 {
                return None;
            }
            let raw = s.pointer_to_raw_data.checked_add(rva - s.virtual_address)? as usize;
            if raw < file_len {
                return Some(raw);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Static Discovery of VM Entry Sites & Trampolines
// ---------------------------------------------------------------------------

enum StubClassify {
    Trampoline,
    VmEnter,
    Unknown,
}

fn classify_vm_target(view: &PeImageView, target_va: u64) -> StubClassify {
    let mut va = target_va;
    let mut visited = HashSet::new();
    let mut insns = Vec::with_capacity(24);
    for _ in 0..24 {
        if !visited.insert(va) {
            break;
        }
        let Some(ins) = view.decode_insn(va) else {
            break;
        };
        let flow = ins.flow_control();
        let next_va = va + ins.len() as u64;
        insns.push(ins);
        match flow {
            FlowControl::UnconditionalBranch => {
                let t = ins.near_branch_target();
                if t != 0 && view.is_in_vm_section(t) && insns.len() < 16 {
                    va = t;
                    continue;
                }
                break;
            }
            FlowControl::Next => {
                va = next_va;
            }
            FlowControl::IndirectBranch => {
                if insns.len() <= 14 && is_short_trampoline_sequence(&insns) {
                    return StubClassify::Trampoline;
                }
                return StubClassify::VmEnter;
            }
            FlowControl::Return if insns.len() <= 8 => {
                if insns.iter().any(|i| i.mnemonic() == Mnemonic::Push) {
                    return StubClassify::Trampoline;
                }
                return StubClassify::VmEnter;
            }
            _ => break,
        }
    }

    if let Some(first) = insns.first() {
        if looks_like_vmenter_prologue(first, &insns) {
            return StubClassify::VmEnter;
        }
    }
    StubClassify::Unknown
}

fn is_short_trampoline_sequence(insns: &[Instruction]) -> bool {
    let has_big_alloc = insns.iter().any(|ins| {
        (ins.mnemonic() == Mnemonic::Lea || ins.mnemonic() == Mnemonic::Sub)
            && ins.op0_register() == Register::RSP
    });
    !has_big_alloc && insns.len() <= 12
}

fn looks_like_vmenter_prologue(first: &Instruction, insns: &[Instruction]) -> bool {
    if (first.mnemonic() == Mnemonic::Lea || first.mnemonic() == Mnemonic::Sub)
        && matches!(first.op0_register(), Register::RSP | Register::ESP)
    {
        return true;
    }
    if first.mnemonic() == Mnemonic::Pushfq || first.mnemonic() == Mnemonic::Pushfd || first.mnemonic() == Mnemonic::Pushad {
        return true;
    }
    if first.mnemonic() == Mnemonic::Push && insns.iter().filter(|i| i.mnemonic() == Mnemonic::Push).count() >= 2 {
        return true;
    }
    false
}

fn is_safe_trampoline_prefix(ins: &Instruction) -> bool {
    if ins.flow_control() != FlowControl::Next {
        return false;
    }
    matches!(
        ins.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Lea
            | Mnemonic::Xor
            | Mnemonic::Nop
    ) && (0..ins.op_count()).all(|i| ins.op_kind(i) != OpKind::Memory || ins.mnemonic() == Mnemonic::Lea)
}

fn decode_function_ranges(
    view: &PeImageView,
    sec: &SectionMeta,
) -> (Vec<Instruction>, HashSet<u32>, HashSet<u32>) {
    let sec_start = view.image_base + sec.va as u64;
    let sec_end_rva = sec.va.saturating_add(sec.vsz.max(sec.raw_size));
    let mut func_insns = Vec::new();
    let mut covered = HashSet::new();
    let mut branch_targets = HashSet::new();

    for &(beg, end) in &view.pdata_primary_ranges {
        if beg < sec.va || end > sec_end_rva {
            continue;
        }
        let va_start = view.image_base + beg as u64;
        let len = (end - beg) as usize;
        if let Some(slice) = view.read_exec_slice(va_start, len) {
            let mut dec = Decoder::with_ip(view.bitness, slice, va_start, DecoderOptions::NONE);
            while dec.can_decode() {
                let ins = dec.decode();
                if ins.is_invalid() {
                    continue;
                }
                let rva = (ins.ip() - view.image_base) as u32;
                covered.insert(rva);
                if matches!(
                    ins.flow_control(),
                    FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
                ) {
                    let t = ins.near_branch_target();
                    if let Some(trva) = view.va_to_rva(t) {
                        branch_targets.insert(trva as u32);
                    }
                }
                func_insns.push(ins);
            }
        }
    }
    let _ = sec_start;
    (func_insns, covered, branch_targets)
}

/// Discovers VM entry stubs and indirect-branch trampolines across primary host sections.
pub fn discover_vm_entries(view: &PeImageView, cfg: &BinaryDevirtConfig) -> Vec<DiscoveredEntry> {
    let mut entries = Vec::new();
    let mut seen_patch_rvas = HashSet::new();

    let primary_secs: Vec<&SectionMeta> = view
        .sections
        .iter()
        .filter(|s| s.is_primary_host)
        .collect();

    for sec in primary_secs {
        let (pdata_insns, covered_starts, branch_targets) = decode_function_ranges(view, sec);

        // 1. Inspect instruction stream decoded cleanly from `.pdata` functions
        for w_idx in 0..pdata_insns.len() {
            let ins = pdata_insns[w_idx];
            let flow = ins.flow_control();
            if !matches!(flow, FlowControl::UnconditionalBranch | FlowControl::Call) {
                continue;
            }
            let dst = ins.near_branch_target();
            if dst == 0 || !view.is_in_vm_section(dst) {
                continue;
            }
            let rva = (ins.ip() - view.image_base) as u32;
            let ins_len = ins.len();
            if ins_len < 5 {
                continue;
            }
            let target_rva = (dst - view.image_base) as u32;
            let is_call = flow == FlowControl::Call;

            match classify_vm_target(view, dst) {
                StubClassify::Trampoline if cfg.include_trampolines && !is_call => {
                    // Walk back up to 4 setup instructions inside the same linear block
                    let mut start_idx = w_idx;
                    let jmp_end_rva = rva + ins_len as u32;
                    for back in 1..=4 {
                        if w_idx < back {
                            break;
                        }
                        let cand = pdata_insns[w_idx - back];
                        let prev = pdata_insns[w_idx - back + 1];
                        let cand_rva = (cand.ip() - view.image_base) as u32;
                        let prev_rva = (prev.ip() - view.image_base) as u32;
                        if cand_rva + cand.len() as u32 != prev_rva {
                            break;
                        }
                        if branch_targets.contains(&prev_rva) {
                            break;
                        }
                        // Ensure no interior byte of cand is a branch target
                        if ((cand_rva + 1)..prev_rva).any(|b| branch_targets.contains(&b)) {
                            break;
                        }
                        if !is_safe_trampoline_prefix(&cand) {
                            break;
                        }
                        start_idx = w_idx - back;
                    }
                    let patch_rva = (pdata_insns[start_idx].ip() - view.image_base) as u32;
                    let patch_size = (jmp_end_rva - patch_rva) as usize;
                    if seen_patch_rvas.insert(patch_rva) {
                        entries.push(DiscoveredEntry {
                            kind: VmEntryKind::IndirectBranchTrampoline,
                            patch_rva,
                            patch_size,
                            is_call: false,
                            lift_start_rva: patch_rva,
                            target_rva,
                        });
                    }
                }
                StubClassify::VmEnter if cfg.include_vmenters => {
                    let mut patch_rva = rva;
                    let mut patch_size = ins_len;
                    let mut lift_start_rva = target_rva;
                    if w_idx > 0 && view.bitness == 32 {
                        let prev = pdata_insns[w_idx - 1];
                        let prev_rva = (prev.ip() - view.image_base) as u32;
                        if prev.mnemonic() == Mnemonic::Push
                            && prev.op0_kind().is_imm()
                            && prev_rva + prev.len() as u32 == rva
                            && !branch_targets.contains(&rva)
                        {
                            patch_rva = prev_rva;
                            patch_size = prev.len() + ins_len;
                            lift_start_rva = prev_rva;
                        }
                    }
                    if seen_patch_rvas.insert(patch_rva) {
                        entries.push(DiscoveredEntry {
                            kind: VmEntryKind::CrossSectionVmEnter,
                            patch_rva,
                            patch_size,
                            is_call,
                            lift_start_rva,
                            target_rva,
                        });
                    }
                }
                _ => {}
            }
        }

        // 2. Scan gaps not in `.pdata` (leaf / un-registered routines) for E8/E9 -> VM section
        let sec_rva_start = sec.va as usize;
        let sec_rva_end = (sec.va.saturating_add(sec.raw_size) as usize).min(view.image_mem.len());
        if sec_rva_end > sec_rva_start + 5 {
            let mut pos = sec_rva_start;
            while pos + 5 <= sec_rva_end {
                let op = view.image_mem[pos];
                if op == 0xE8 || op == 0xE9 {
                    let rva = pos as u32;
                    if !covered_starts.contains(&rva) && !seen_patch_rvas.contains(&rva) {
                        let rel = i32::from_le_bytes(view.image_mem[pos + 1..pos + 5].try_into().unwrap());
                        let dst = (view.image_base + rva as u64 + 5).wrapping_add_signed(rel as i64);
                        if view.is_in_vm_section(dst) {
                            let target_rva = (dst - view.image_base) as u32;
                            let is_call = op == 0xE8;
                            match classify_vm_target(view, dst) {
                                StubClassify::VmEnter if cfg.include_vmenters => {
                                    if seen_patch_rvas.insert(rva) {
                                        entries.push(DiscoveredEntry {
                                            kind: VmEntryKind::CrossSectionVmEnter,
                                            patch_rva: rva,
                                            patch_size: 5,
                                            is_call,
                                            lift_start_rva: target_rva,
                                            target_rva,
                                        });
                                    }
                                    pos += 5;
                                    continue;
                                }
                                StubClassify::Trampoline if cfg.include_trampolines && !is_call => {
                                    // Scan backwards inside the uncovered region for a clean `[mov..., test/cmp, cmovcc]` prefix ending at `rva`
                                    let max_back = (pos - sec_rva_start).min(48);
                                    let mut best_start = pos;
                                    for back in (2..=max_back).rev() {
                                        let cand_pos = pos - back;
                                        let slice = &view.image_mem[cand_pos..pos];
                                        let mut dec = Decoder::with_ip(
                                            view.bitness,
                                            slice,
                                            view.image_base + cand_pos as u64,
                                            DecoderOptions::NONE,
                                        );
                                        let mut all_safe = true;
                                        let mut cnt = 0usize;
                                        while dec.can_decode() {
                                            let di = dec.decode();
                                            if di.is_invalid() || !is_safe_trampoline_prefix(&di) {
                                                all_safe = false;
                                                break;
                                            }
                                            cnt += 1;
                                        }
                                        if all_safe && cnt > 0 && cnt <= 6 && dec.position() == slice.len() {
                                            best_start = cand_pos;
                                            break;
                                        }
                                    }
                                    let patch_rva = best_start as u32;
                                    let patch_size = (pos - best_start) + 5;
                                    if seen_patch_rvas.insert(patch_rva) {
                                        entries.push(DiscoveredEntry {
                                            kind: VmEntryKind::IndirectBranchTrampoline,
                                            patch_rva,
                                            patch_size,
                                            is_call: false,
                                            lift_start_rva: patch_rva,
                                            target_rva,
                                        });
                                    }
                                    pos += 5;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                pos += 1;
            }
        }
    }

    for &rva in &cfg.extra_entry_rvas {
        if !seen_patch_rvas.contains(&rva) {
            seen_patch_rvas.insert(rva);
            entries.push(DiscoveredEntry {
                kind: VmEntryKind::StandaloneVmStub,
                patch_rva: rva,
                patch_size: 5,
                is_call: false,
                lift_start_rva: rva,
                target_rva: rva,
            });
        }
    }

    entries.sort_by_key(|e| e.patch_rva);
    if entries.len() > cfg.max_entries {
        entries.truncate(cfg.max_entries);
    }
    entries
}

trait OpKindImmExt {
    fn is_imm(self) -> bool;
}

impl OpKindImmExt for OpKind {
    fn is_imm(self) -> bool {
        matches!(
            self,
            OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        )
    }
}

// ---------------------------------------------------------------------------
// Symbolic CFG Lifter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum IrEffect {
    Store {
        addr: ExprId,
        width: u8,
        value: ExprId,
        mem_ver_after: u32,
    },
    AtomicCmpXchg {
        lock: bool,
        addr: ExprId,
        width: u8,
        expected_rax: ExprId,
        desired: ExprId,
        mem_ver_after: u32,
    },
    AtomicRmw {
        lock: bool,
        op: AtomicOpKind,
        addr: ExprId,
        width: u8,
        src: ExprId,
        mem_ver_after: u32,
    },
    WriteCr8 {
        val: ExprId,
        cr8_ver_after: u32,
    },
    CallNative {
        call_id: u32,
        target_va: u64,
        rsp_delta: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOpKind {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Inc,
    Dec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidCallTarget {
    DirectVa(u64),
    CallerStackSlot(i64),
    IndirectRipMem(u64),
    IndirectReg(ArchReg),
}

#[derive(Debug, Clone)]
pub enum IrTerm {
    CondBranch {
        cond: ExprId,
        taken_block: usize,
        fallthrough_block: usize,
    },
    MidCall {
        target: MidCallTarget,
        rsp_delta: i64,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
        pending_caller_stores: Vec<(i64, ExprId)>,
        cont_block: usize,
    },
    ExitRet {
        rsp_delta: i64,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
        pending_caller_stores: Vec<(i64, ExprId)>,
    },
    ExitJmp {
        target_va: u64,
        rsp_delta: i64,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
        pending_caller_stores: Vec<(i64, ExprId)>,
    },
    ExitCall {
        target_va: u64,
        ret_va: u64,
        rsp_delta: i64,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
        pending_caller_stores: Vec<(i64, ExprId)>,
    },
    ExitAddJmp {
        reg: ArchReg,
        disp: i64,
        rsp_delta: i64,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
    },
    ExitIndirectMem {
        rsp_disp: i64,
        rsp_delta: i64,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
        pending_caller_stores: Vec<(i64, ExprId)>,
    },
    /// Hand control back to the original code at `va` with the state the original
    /// had there: every register, the written stack slots (the VM's aligned frame
    /// included, see `VmExit`), RSP and - when the code at `va` can read them - the
    /// status flags. The instruction at `va` then runs as it always did. Used where
    /// the lifter cannot go on: a jump whose target depends on run-time data, an
    /// instruction it does not model, the block/instruction budget. The function is
    /// recompiled up to there instead of rejected; the report counts such functions
    /// as `hybrid_vm_exits`.
    ExitToVm {
        va: u64,
        exit: Box<VmExit>,
        final_regs: [ExprId; 16],
        final_xmms: [(ExprId, ExprId); 16],
    },
    Bailout(String),
}

/// How `IrTerm::ExitToVm` rebuilds the state at its target. All offsets are from the
/// entry RSP (`StackBase`).
///
/// 1. Every value is computed first, while the input registers are intact: written
///    caller-stack slots go to their places; the VM's aligned-frame slots (`and rsp,
///    -16` frames, whose padding is only known at run time) and the flag operands go
///    to a temporary area below everything else (`temp_stores`, `flags`), all as
///    ordinary pending stores with RSP lowered to `rsp_delta` - nothing live is ever
///    below RSP.
/// 2. The final registers are set.
/// 3. With two registers saved, the aligned bases are recomputed with the same `and`
///    the VM ran (`bases`), the temporary values are copied to their aligned slots,
///    the last flag-setting operation is replayed on the saved operands, RSP becomes
///    its final value (only `mov`/`lea`/`pop` from here on: the flags stay) and the
///    code jumps to the target.
#[derive(Debug, Clone)]
pub struct VmExit {
    /// RSP (from the entry RSP) while values are computed: below the temporary area.
    pub rsp_delta: i64,
    /// Caller-stack slots and temporary slots, both as `(offset, value)`.
    pub pending: Vec<(i64, ExprId)>,
    /// Aligned slots: `(temporary offset, base index, offset from that base, kept
    /// bytes)`. Bit `j` of the last field set: byte `j` of the slot was never written
    /// and keeps what memory holds; only the other bytes are stored (0 = whole qword).
    pub temp_stores: Vec<(i64, u32, i64, u8)>,
    /// `AlignedBase(i)` = `(parent + off) & mask`, parent the caller stack or an
    /// earlier aligned base.
    pub bases: Vec<(StackSpace, i64, u64)>,
    /// Final RSP: `bases[i] + final_off`, or `entry + final_off` for `None`.
    pub final_base: Option<u32>,
    pub final_off: i64,
    /// Status flags to recreate; `None` when the code at the target overwrites them
    /// before reading any.
    pub flags: Option<FlagsReplay>,
}

/// The last flag-setting operation, replayed on its saved operands (temporary
/// offsets) at the very end of a `VmExit`.
#[derive(Debug, Clone, Copy)]
pub enum FlagsReplay {
    /// `cmp a, b` (also stands for `sub` / `neg`: same flags).
    Cmp { a: i64, b: i64, width: u8 },
    /// `test a, a` (the flags of `and` / `or` / `xor` / `test` results).
    Test { a: i64, width: u8 },
    /// `add a, b`.
    Add { a: i64, b: i64, width: u8 },
}

#[derive(Debug, Clone)]
pub struct LiftedBlock {
    pub id: usize,
    pub entry_va: u64,
    pub effects: Vec<IrEffect>,
    pub term: IrTerm,
}

#[derive(Debug, Clone)]
pub struct LiftedFunction {
    pub entry: DiscoveredEntry,
    pub is_entry_call: bool,
    pub arena: ExprArena,
    pub blocks: Vec<LiftedBlock>,
    pub raw_vm_insns: usize,
    pub opaque_branches_folded: usize,
    pub visited_byte_addrs: HashSet<u64>,
    pub first_bailout: Option<String>,
    pub bailout_detail: Option<(u64, String)>,
}

fn fmt_iced_insn(ins: &Instruction) -> String {
    let mut fmt = IntelFormatter::new();
    let mut s = String::new();
    fmt.format(ins, &mut s);
    s
}

fn expr_brief(arena: &ExprArena, id: ExprId, depth: u8) -> String {
    fn rec(arena: &ExprArena, id: ExprId, depth: u8, out: &mut String) {
        if out.len() >= 156 {
            return;
        }
        if depth > 3 {
            out.push_str("..");
            return;
        }
        let d = depth + 1;
        match arena.get(id) {
            ExprNode::Const(c) => out.push_str(&format!("{c:#x}")),
            ExprNode::RegIn(r) => out.push_str(r.as_str()),
            ExprNode::XmmIn(idx, hi) => out.push_str(&format!("xmm{idx}_{}", if *hi { "hi" } else { "lo" })),
            ExprNode::StackBase => out.push_str("StackBase"),
            ExprNode::AlignedBase(n) => out.push_str(&format!("AlignedBase({n})")),
            ExprNode::CallRet { call_id, reg } => out.push_str(&format!("CallRet({call_id},{})", reg.as_str())),
            ExprNode::Load { addr, width, mem_ver } => {
                out.push_str(&format!("Load{width}@v{mem_ver}("));
                rec(arena, *addr, d, out);
                out.push(')');
            }
            ExprNode::Add(a, b) => {
                out.push_str("Add(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Sub(a, b) => {
                out.push_str("Sub(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Mul(a, b) => {
                out.push_str("Mul(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::And(a, b) => {
                out.push_str("And(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Or(a, b) => {
                out.push_str("Or(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Xor(a, b) => {
                out.push_str("Xor(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Shl(a, b) => {
                out.push_str("Shl(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Shr(a, b) => {
                out.push_str("Shr(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Sar(a, b) => {
                out.push_str("Sar(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Rol(a, b) => {
                out.push_str("Rol(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Ror(a, b) => {
                out.push_str("Ror(");
                rec(arena, *a, d, out);
                out.push(',');
                rec(arena, *b, d, out);
                out.push(')');
            }
            ExprNode::Not(a) => {
                out.push_str("Not(");
                rec(arena, *a, d, out);
                out.push(')');
            }
            ExprNode::Neg(a) => {
                out.push_str("Neg(");
                rec(arena, *a, d, out);
                out.push(')');
            }
            ExprNode::SExt { val, from_bits } => {
                out.push_str(&format!("SExt{from_bits}("));
                rec(arena, *val, d, out);
                out.push(')');
            }
            ExprNode::Cmp { pred, lhs, rhs } => {
                out.push_str(&format!("Cmp({pred:?},"));
                rec(arena, *lhs, d, out);
                out.push(',');
                rec(arena, *rhs, d, out);
                out.push(')');
            }
            ExprNode::Select { cond, if_true, if_false } => {
                out.push_str("Select(");
                rec(arena, *cond, d, out);
                out.push(',');
                rec(arena, *if_true, d, out);
                out.push(',');
                rec(arena, *if_false, d, out);
                out.push(')');
            }
            ExprNode::EntryFlag(cc) => out.push_str(&format!("EntryFlag({cc})")),
            ExprNode::Cr8Read(v) => out.push_str(&format!("Cr8Read({v})")),
            ExprNode::Opaque(n) => out.push_str(&format!("Opaque({n})")),
        }
    }
    let mut s = String::new();
    rec(arena, id, depth, &mut s);
    if s.len() > 160 {
        s.truncate(157);
        s.push_str("...");
    }
    s
}

fn expr_flags_tag(arena: &ExprArena, id: ExprId) -> String {
    let top = match arena.get(id) {
        ExprNode::Const(_) => "Const",
        ExprNode::RegIn(_) => "RegIn",
        ExprNode::XmmIn(..) => "XmmIn",
        ExprNode::StackBase => "StackBase",
        ExprNode::AlignedBase(_) => "AlignedBase",
        ExprNode::CallRet { .. } => "CallRet",
        ExprNode::Load { .. } => "Load",
        ExprNode::Add(..) => "Add",
        ExprNode::Sub(..) => "Sub",
        ExprNode::Mul(..) => "Mul",
        ExprNode::And(..) => "And",
        ExprNode::Or(..) => "Or",
        ExprNode::Xor(..) => "Xor",
        ExprNode::Shl(..) => "Shl",
        ExprNode::Shr(..) => "Shr",
        ExprNode::Sar(..) => "Sar",
        ExprNode::Rol(..) => "Rol",
        ExprNode::Ror(..) => "Ror",
        ExprNode::Not(_) => "Not",
        ExprNode::Neg(_) => "Neg",
        ExprNode::SExt { .. } => "SExt",
        ExprNode::Cmp { .. } => "Cmp",
        ExprNode::Select { .. } => "Select",
        ExprNode::EntryFlag(_) => "EntryFlag",
        ExprNode::Cr8Read(_) => "Cr8Read",
        ExprNode::Opaque(_) => "Opaque",
    };
    let mut op = false;
    let mut ab = false;
    let mut ld = false;
    let mut sel = false;
    let mut cmp = false;
    let mut reg = false;
    let mut xm = false;
    let mut sb = false;
    let mut cr8 = false;
    let mut ef = false;
    let mut stack = vec![id];
    let mut seen = HashSet::new();
    while let Some(cur) = stack.pop() {
        if seen.len() >= 512 || !seen.insert(cur) {
            continue;
        }
        match arena.get(cur) {
            ExprNode::Opaque(_) => op = true,
            ExprNode::AlignedBase(_) => ab = true,
            ExprNode::RegIn(_) => reg = true,
            ExprNode::XmmIn(..) => xm = true,
            ExprNode::StackBase => sb = true,
            ExprNode::Cr8Read(_) => cr8 = true,
            ExprNode::EntryFlag(_) => ef = true,
            ExprNode::Load { addr, .. } => {
                ld = true;
                stack.push(*addr);
            }
            ExprNode::Select { cond, if_true, if_false } => {
                sel = true;
                stack.push(*cond);
                stack.push(*if_true);
                stack.push(*if_false);
            }
            ExprNode::Cmp { lhs, rhs, .. } => {
                cmp = true;
                stack.push(*lhs);
                stack.push(*rhs);
            }
            ExprNode::Not(a) | ExprNode::Neg(a) | ExprNode::SExt { val: a, .. } => stack.push(*a),
            ExprNode::Add(a, b)
            | ExprNode::Sub(a, b)
            | ExprNode::Mul(a, b)
            | ExprNode::And(a, b)
            | ExprNode::Or(a, b)
            | ExprNode::Xor(a, b)
            | ExprNode::Shl(a, b)
            | ExprNode::Shr(a, b)
            | ExprNode::Sar(a, b)
            | ExprNode::Rol(a, b)
            | ExprNode::Ror(a, b) => {
                stack.push(*a);
                stack.push(*b);
            }
            _ => {}
        }
    }
    let kb_bool = (arena.known_bits(id).0 & !1u64) == !1u64;
    format!(
        "top={top} op={} ab={} ld={} sel={} cmp={} reg={} xmm={} sb={} cr8={} ef={} kb_bool={}",
        u8::from(op),
        u8::from(ab),
        u8::from(ld),
        u8::from(sel),
        u8::from(cmp),
        u8::from(reg),
        u8::from(xm),
        u8::from(sb),
        u8::from(cr8),
        u8::from(ef),
        u8::from(kb_bool),
    )
}

fn entry_cc_to_u8(cc: ConditionCode) -> Option<u8> {
    match cc {
        ConditionCode::e => Some(0),
        ConditionCode::ne => Some(1),
        ConditionCode::b => Some(2),
        ConditionCode::ae => Some(3),
        ConditionCode::be => Some(4),
        ConditionCode::a => Some(5),
        ConditionCode::s => Some(6),
        ConditionCode::ns => Some(7),
        ConditionCode::l => Some(8),
        ConditionCode::ge => Some(9),
        ConditionCode::le => Some(10),
        ConditionCode::g => Some(11),
        ConditionCode::o => Some(12),
        ConditionCode::no => Some(13),
        _ => None,
    }
}

fn as_direct_entry_flag(arena: &ExprArena, id: ExprId) -> Option<u8> {
    match arena.get(id) {
        ExprNode::EntryFlag(c) if *c <= 13 => Some(*c),
        ExprNode::Cmp { pred: CondPred::Ne, lhs, rhs } if arena.as_const(*rhs) == Some(0) => {
            if let ExprNode::EntryFlag(c) = arena.get(*lhs) {
                if *c <= 13 {
                    return Some(*c);
                }
            }
            None
        }
        ExprNode::Cmp { pred: CondPred::Eq, lhs, rhs } if arena.as_const(*rhs) == Some(0) => {
            if let ExprNode::EntryFlag(c) = arena.get(*lhs) {
                if *c <= 13 {
                    return Some(*c ^ 1);
                }
            }
            None
        }
        ExprNode::Xor(a, b) if arena.as_const(*b) == Some(1) => {
            if let ExprNode::EntryFlag(c) = arena.get(*a) {
                if *c <= 13 {
                    return Some(*c ^ 1);
                }
            }
            None
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FlagState {
    Entry,
    Unknown,
    SubCmp { lhs: ExprId, rhs: ExprId, width: u8 },
    TestBitwise { val: ExprId, width: u8 },
    Add { lhs: ExprId, rhs: ExprId, res: ExprId, width: u8 },
    IncDec { res: ExprId, cf: Option<bool>, width: u8 },
    CarryExpr(ExprId),
}

#[derive(Debug, Clone)]
struct SymState {
    ip: u64,
    regs: [ExprId; 16],
    xmms: [(ExprId, ExprId); 16],
    stack: SymStack,
    flags: FlagState,
    saved_rflags: Vec<(ExprId, FlagState)>,
    entry_flags_clobbered: bool,
    mem_ver: u32,
    cr8_ver: u32,
    mem_cache: HashMap<ExprId, (u8, ExprId)>,
    next_aligned_id: u32,
    /// How each `AlignedBase(id)` was made (index = id): RSP was `parent + off` and
    /// `and rsp, mask` aligned it. Lets an exit rebuild the aligned frame at run time
    /// (`IrTerm::ExitToVm`), where the alignment padding is only known then.
    aligned_defs: Vec<(StackSpace, i64, u64)>,
    inline_depth: usize,
    cum_rsp_offset: i64,
    entry_caller_slot_versions: HashMap<i64, ExprId>,
}

impl SymState {
    fn new(arena: &mut ExprArena, start_va: u64, is_call: bool, ret_va_if_call: u64) -> Self {
        let mut regs = [ExprId(0); 16];
        for r in ArchReg::ALL {
            regs[r.idx()] = if r == ArchReg::Rsp {
                arena.stack_base()
            } else {
                arena.reg_in(r)
            };
        }
        let mut xmms = [(ExprId(0), ExprId(0)); 16];
        for i in 0..16u8 {
            xmms[i as usize] = (arena.xmm_in(i, false), arena.xmm_in(i, true));
        }
        let stack = SymStack::new();
        let mut entry_caller_slot_versions = HashMap::new();
        if is_call {
            let ret_id = arena.const_u64(ret_va_if_call);
            let mut st = stack;
            st.write_scalar(arena, StackSpace::CallerStack, 0, 8, ret_id, 0);
            entry_caller_slot_versions.insert(0, ret_id);
            return Self {
                ip: start_va,
                regs,
                xmms,
                stack: st,
                flags: FlagState::Entry,
                saved_rflags: Vec::new(),
                entry_flags_clobbered: false,
                mem_ver: 0,
                cr8_ver: 0,
                mem_cache: HashMap::new(),
                next_aligned_id: 0,
                aligned_defs: Vec::new(),
                inline_depth: 0,
                cum_rsp_offset: 0,
                entry_caller_slot_versions,
            };
        }
        Self {
            ip: start_va,
            regs,
            xmms,
            stack,
            flags: FlagState::Entry,
            saved_rflags: Vec::new(),
            entry_flags_clobbered: false,
            mem_ver: 0,
            cr8_ver: 0,
            mem_cache: HashMap::new(),
            next_aligned_id: 0,
            aligned_defs: Vec::new(),
            inline_depth: 0,
            cum_rsp_offset: 0,
            entry_caller_slot_versions,
        }
    }

    #[inline]
    fn set_flags(&mut self, flags: FlagState) {
        self.flags = flags;
    }

    #[inline]
    fn reg_full(&self, r: ArchReg) -> ExprId {
        self.regs[r.idx()]
    }

    #[inline]
    fn read_reg(&self, arena: &mut ExprArena, bitness: u32, r: ArchReg, slice: RegSlice) -> ExprId {
        arena.read_slice(bitness, self.regs[r.idx()], slice)
    }

    #[inline]
    fn write_reg(&mut self, arena: &mut ExprArena, r: ArchReg, slice: RegSlice, val: ExprId) {
        self.regs[r.idx()] = arena.write_slice(self.regs[r.idx()], slice, val);
    }

    fn eval_cond_code(&self, arena: &mut ExprArena, cc: ConditionCode) -> Option<ExprId> {
        let zero = arena.const_u64(0);
        match &self.flags {
            FlagState::SubCmp { lhs, rhs, width } => {
                let w = *width;
                let la = arena.zext_mask(*lhs, w);
                let rb = arena.zext_mask(*rhs, w);
                let sa = arena.sext(*lhs, w * 8);
                let sb = arena.sext(*rhs, w * 8);
                match cc {
                    ConditionCode::e => Some(arena.cmp(CondPred::Eq, la, rb)),
                    ConditionCode::ne => Some(arena.cmp(CondPred::Ne, la, rb)),
                    ConditionCode::b => Some(arena.cmp(CondPred::Ult, la, rb)),
                    ConditionCode::be => Some(arena.cmp(CondPred::Ule, la, rb)),
                    ConditionCode::a => Some(arena.cmp(CondPred::Ugt, la, rb)),
                    ConditionCode::ae => Some(arena.cmp(CondPred::Uge, la, rb)),
                    ConditionCode::l => Some(arena.cmp(CondPred::Slt, sa, sb)),
                    ConditionCode::le => Some(arena.cmp(CondPred::Sle, sa, sb)),
                    ConditionCode::g => Some(arena.cmp(CondPred::Sgt, sa, sb)),
                    ConditionCode::ge => Some(arena.cmp(CondPred::Sge, sa, sb)),
                    ConditionCode::s => {
                        let diff = arena.sub(la, rb);
                        let sd = arena.sext(diff, w * 8);
                        Some(arena.cmp(CondPred::Slt, sd, zero))
                    }
                    ConditionCode::ns => {
                        let diff = arena.sub(la, rb);
                        let sd = arena.sext(diff, w * 8);
                        Some(arena.cmp(CondPred::Sge, sd, zero))
                    }
                    ConditionCode::o | ConditionCode::no => {
                        let diff = arena.sub(la, rb);
                        let xor_lr = arena.xor(la, rb);
                        let xor_ld = arena.xor(la, diff);
                        let ov_raw = arena.and(xor_lr, xor_ld);
                        let sign_bit = 1u64 << (w * 8 - 1);
                        let ov = arena.and_const(ov_raw, sign_bit);
                        let pred = if cc == ConditionCode::o { CondPred::Ne } else { CondPred::Eq };
                        Some(arena.cmp(pred, ov, zero))
                    }
                    _ => None,
                }
            }
            FlagState::TestBitwise { val, width } => {
                let w = *width;
                let zv = arena.zext_mask(*val, w);
                let sv = arena.sext(*val, w * 8);
                match cc {
                    ConditionCode::e => Some(arena.cmp(CondPred::Eq, zv, zero)),
                    ConditionCode::ne => Some(arena.cmp(CondPred::Ne, zv, zero)),
                    ConditionCode::b => Some(arena.const_u64(0)),  // CF=0
                    ConditionCode::ae => Some(arena.const_u64(1)), // CF=0
                    ConditionCode::be => Some(arena.cmp(CondPred::Eq, zv, zero)), // CF=0
                    ConditionCode::a => Some(arena.cmp(CondPred::Ne, zv, zero)),  // CF=0
                    ConditionCode::l | ConditionCode::s => Some(arena.cmp(CondPred::Slt, sv, zero)),
                    ConditionCode::ge | ConditionCode::ns => Some(arena.cmp(CondPred::Sge, sv, zero)),
                    ConditionCode::le => Some(arena.cmp(CondPred::Sle, sv, zero)),
                    ConditionCode::g => Some(arena.cmp(CondPred::Sgt, sv, zero)),
                    ConditionCode::o => Some(arena.const_u64(0)),
                    ConditionCode::no => Some(arena.const_u64(1)),
                    _ => None,
                }
            }
            FlagState::Add { lhs, rhs, res, width } => {
                let w = *width;
                let zr = arena.zext_mask(*res, w);
                let sr = arena.sext(*res, w * 8);
                let zl = arena.zext_mask(*lhs, w);
                let zrhs = arena.zext_mask(*rhs, w);
                if let (Some(a), Some(b)) = (arena.as_const(zl), arena.as_const(zrhs)) {
                    let mask = width_mask(w);
                    let sum = (a as u128) + (b as u128);
                    let cf = (sum >> (w * 8)) != 0;
                    let r_val = (sum as u64) & mask;
                    let zf = r_val == 0;
                    let sign_bit = 1u64 << (w * 8 - 1);
                    let sf = (r_val & sign_bit) != 0;
                    let of = (((a ^ r_val) & (b ^ r_val)) & sign_bit) != 0;
                    let taken = match cc {
                        ConditionCode::e => zf,
                        ConditionCode::ne => !zf,
                        ConditionCode::b => cf,
                        ConditionCode::ae => !cf,
                        ConditionCode::be => cf || zf,
                        ConditionCode::a => !cf && !zf,
                        ConditionCode::s => sf,
                        ConditionCode::ns => !sf,
                        ConditionCode::l => sf != of,
                        ConditionCode::ge => sf == of,
                        ConditionCode::le => zf || (sf != of),
                        ConditionCode::g => !zf && (sf == of),
                        ConditionCode::o => of,
                        ConditionCode::no => !of,
                        _ => return None,
                    };
                    return Some(arena.const_u64(if taken { 1 } else { 0 }));
                }
                match cc {
                    ConditionCode::e => Some(arena.cmp(CondPred::Eq, zr, zero)),
                    ConditionCode::ne => Some(arena.cmp(CondPred::Ne, zr, zero)),
                    ConditionCode::b => Some(arena.cmp(CondPred::Ult, zr, zl)),
                    ConditionCode::ae => Some(arena.cmp(CondPred::Uge, zr, zl)),
                    ConditionCode::be => {
                        let cf = arena.cmp(CondPred::Ult, zr, zl);
                        let zf = arena.cmp(CondPred::Eq, zr, zero);
                        Some(arena.or(cf, zf))
                    }
                    ConditionCode::a => {
                        let ncf = arena.cmp(CondPred::Uge, zr, zl);
                        let nzf = arena.cmp(CondPred::Ne, zr, zero);
                        Some(arena.and(ncf, nzf))
                    }
                    ConditionCode::s => Some(arena.cmp(CondPred::Slt, sr, zero)),
                    ConditionCode::ns => Some(arena.cmp(CondPred::Sge, sr, zero)),
                    ConditionCode::o | ConditionCode::no => {
                        let sign_bit = 1u64 << (w * 8 - 1);
                        let xl = arena.xor(zl, zr);
                        let xr = arena.xor(zrhs, zr);
                        let ov_raw = arena.and(xl, xr);
                        let ov = arena.and_const(ov_raw, sign_bit);
                        let pred = if cc == ConditionCode::o { CondPred::Ne } else { CondPred::Eq };
                        Some(arena.cmp(pred, ov, zero))
                    }
                    ConditionCode::l | ConditionCode::ge | ConditionCode::le | ConditionCode::g => {
                        let sign_bit = 1u64 << (w * 8 - 1);
                        let sbit = arena.and_const(zr, sign_bit);
                        let sf = arena.cmp(CondPred::Ne, sbit, zero);
                        let xl = arena.xor(zl, zr);
                        let xr = arena.xor(zrhs, zr);
                        let ov_raw = arena.and(xl, xr);
                        let ov = arena.and_const(ov_raw, sign_bit);
                        let of = arena.cmp(CondPred::Ne, ov, zero);
                        let sl = arena.xor(sf, of);
                        match cc {
                            ConditionCode::l => Some(sl),
                            ConditionCode::ge => Some(arena.xor_const(sl, 1)),
                            ConditionCode::le => {
                                let zf = arena.cmp(CondPred::Eq, zr, zero);
                                Some(arena.or(zf, sl))
                            }
                            _ => {
                                let nzf = arena.cmp(CondPred::Ne, zr, zero);
                                let sge = arena.xor_const(sl, 1);
                                Some(arena.and(nzf, sge))
                            }
                        }
                    }
                    _ => None,
                }
            }
            FlagState::IncDec { res, cf, width } => {
                let w = *width;
                let zr = arena.zext_mask(*res, w);
                let sr = arena.sext(*res, w * 8);
                match cc {
                    ConditionCode::e => Some(arena.cmp(CondPred::Eq, zr, zero)),
                    ConditionCode::ne => Some(arena.cmp(CondPred::Ne, zr, zero)),
                    ConditionCode::s => Some(arena.cmp(CondPred::Slt, sr, zero)),
                    ConditionCode::ns => Some(arena.cmp(CondPred::Sge, sr, zero)),
                    ConditionCode::b => cf.map(|v| arena.const_u64(u64::from(v))),
                    ConditionCode::ae => cf.map(|v| arena.const_u64(u64::from(!v))),
                    _ => None,
                }
            }
            FlagState::CarryExpr(bit) => match cc {
                ConditionCode::b => Some(*bit),
                ConditionCode::ae => Some(arena.xor_const(*bit, 1)),
                _ => None,
            },
            FlagState::Entry => {
                if !self.entry_flags_clobbered && self.cum_rsp_offset == 0 {
                    entry_cc_to_u8(cc).map(|c| arena.entry_flag(c))
                } else {
                    None
                }
            }
            FlagState::Unknown => None,
        }
    }

    fn known_cf(&self, arena: &mut ExprArena) -> Option<bool> {
        let id = self.eval_cond_code(arena, ConditionCode::b)?;
        arena.as_const(id).map(|v| v != 0)
    }

    fn collect_pending_caller_stores(&self, final_rsp_delta: i64) -> Vec<(i64, ExprId)> {
        let mut out = Vec::new();
        for (&(space, off), &val) in &self.stack.slots {
            if space == StackSpace::CallerStack && off >= final_rsp_delta {
                if self.entry_caller_slot_versions.get(&off) == Some(&val) {
                    continue;
                }
                out.push((off, val));
            }
        }
        out.sort_by_key(|&(off, _)| off);
        out
    }
}

fn eval_mem_ea(state: &SymState, arena: &mut ExprArena, bitness: u32, ins: &Instruction, next_ip: u64) -> ExprId {
    if matches!(ins.memory_segment(), Register::FS | Register::GS) {
        return arena.opaque();
    }
    if ins.is_ip_rel_memory_operand() {
        let va = ins.ip_rel_memory_address();
        let masked = if ins.memory_base() == Register::EIP || bitness == 32 {
            va & 0xFFFF_FFFF
        } else {
            va
        };
        return arena.const_u64(masked);
    }
    let mut base_expr = match ins.memory_base() {
        Register::None => arena.const_u64(0),
        Register::RIP => arena.const_u64(next_ip),
        Register::EIP => arena.const_u64(next_ip & 0xFFFF_FFFF),
        r => match ArchReg::from_iced(r) {
            Some((ar, sl)) => state.read_reg(arena, bitness, ar, sl),
            None => return arena.opaque(),
        },
    };
    if ins.memory_index() != Register::None {
        let Some((ir, isl)) = ArchReg::from_iced(ins.memory_index()) else {
            return arena.opaque();
        };
        let idx = state.read_reg(arena, bitness, ir, isl);
        let scale = ins.memory_index_scale() as u64;
        let scaled = if scale > 1 {
            let sc = arena.const_u64(scale);
            arena.mul(idx, sc)
        } else {
            idx
        };
        base_expr = arena.add(base_expr, scaled);
    }
    let disp = ins.memory_displacement64();
    if disp != 0 {
        base_expr = arena.add_const(base_expr, disp);
    }
    if bitness == 32 {
        arena.and_const(base_expr, 0xFFFF_FFFF)
    } else {
        base_expr
    }
}

fn read_memory_expr(
    view: &PeImageView,
    state: &mut SymState,
    arena: &mut ExprArena,
    addr: ExprId,
    width: u8,
) -> ExprId {
    read_memory_expr_depth(view, state, arena, addr, width, 0)
}

fn read_memory_expr_depth(
    view: &PeImageView,
    state: &mut SymState,
    arena: &mut ExprArena,
    addr: ExprId,
    width: u8,
    depth: u8,
) -> ExprId {
    if let Some((space, off)) = arena.as_stack_offset(addr) {
        return state.stack.read_scalar(arena, space, off, width, state.mem_ver);
    }
    if let Some(&(cached_w, cached_v)) = state.mem_cache.get(&addr) {
        if cached_w == width {
            return cached_v;
        }
    }
    if let Some(va) = arena.as_const(addr) {
        if let Some(ro_val) = view.read_ro_scalar(va, width) {
            return arena.const_u64(ro_val);
        }
    }
    // Up to three predicates deep (8 slots): a handler table on the VM's own stack is
    // indexed by several booleans at once.
    if depth < 3 {
        if let Some((cond, ea1, ea0)) = try_resolve_select_mem_pair(arena, addr) {
            if is_pure_nonfaulting_read_addr(arena, view, ea1, width)
                && is_pure_nonfaulting_read_addr(arena, view, ea0, width)
            {
                let v1 = read_memory_expr_depth(view, state, arena, ea1, width, depth + 1);
                let v0 = read_memory_expr_depth(view, state, arena, ea0, width, depth + 1);
                return arena.select(cond, v1, v0);
            }
        }
    }
    arena.load(addr, width, state.mem_ver)
}

fn write_memory_expr(
    state: &mut SymState,
    arena: &mut ExprArena,
    effects: &mut Vec<IrEffect>,
    addr: ExprId,
    width: u8,
    val: ExprId,
) {
    let masked = arena.zext_mask(val, width);
    if let Some((space, off)) = arena.as_stack_offset(addr) {
        if space == StackSpace::CallerStack && off >= 0 {
            // Visible caller frame write -> update SymStack AND invalidate non-stack alias cache?
            // Keeping it in SymStack AND flushing if it exits prevents redundant stores if later popped/overwritten,
            // UNLESS non-stack symbolic pointer aliases `[rsp+...]`. Simply recording in SymStack AND bumping mem_ver:
            state.stack.write_scalar(arena, space, off, width, masked, state.mem_ver);
            state.mem_ver += 1;
            return;
        }
        state.stack.write_scalar(arena, space, off, width, masked, state.mem_ver);
        return;
    }
    if arena.as_const(addr).is_none() {
        if let Some((cond, ea1, ea0)) = try_resolve_select_mem_pair(arena, addr) {
            if let (Some((sp1, off1)), Some((sp0, off0))) = (
                is_internal_stack_addr(arena, ea1),
                is_internal_stack_addr(arena, ea0),
            ) {
                if (sp1, off1) == (sp0, off0) {
                    state.stack.write_scalar(arena, sp1, off1, width, masked, state.mem_ver);
                    return;
                }
                let old1 = state.stack.read_scalar(arena, sp1, off1, width, state.mem_ver);
                let old0 = state.stack.read_scalar(arena, sp0, off0, width, state.mem_ver);
                let new1 = arena.select(cond, masked, old1);
                let new0 = arena.select(cond, old0, masked);
                state.stack.write_scalar(arena, sp1, off1, width, new1, state.mem_ver);
                state.stack.write_scalar(arena, sp0, off0, width, new0, state.mem_ver);
                return;
            }
        }
    }

    state.mem_ver += 1;
    // Conservatively invalidate cached non-const mem loads on write to unknown/alias addresses
    if arena.as_const(addr).is_some() {
        let mut to_drop = Vec::new();
        for &k in state.mem_cache.keys() {
            if arena.as_const(k).is_none() || k == addr {
                to_drop.push(k);
            }
        }
        for k in to_drop {
            state.mem_cache.remove(&k);
        }
    } else {
        state.mem_cache.clear();
    }
    state.mem_cache.insert(addr, (width, masked));
    effects.push(IrEffect::Store {
        addr,
        width,
        value: masked,
        mem_ver_after: state.mem_ver,
    });
}

fn op_width_bytes(ins: &Instruction, bitness: u32, op_idx: u32) -> u8 {
    match ins.op_kind(op_idx) {
        OpKind::Register => {
            if let Some((_, sl)) = ArchReg::from_iced(ins.op_register(op_idx)) {
                ArchReg::slice_bits(sl) / 8
            } else {
                (bitness / 8) as u8
            }
        }
        OpKind::Memory => ins.memory_size().size().clamp(1, 8) as u8,
        _ => (bitness / 8) as u8,
    }
}

fn read_operand(
    view: &PeImageView,
    state: &mut SymState,
    arena: &mut ExprArena,
    ins: &Instruction,
    next_ip: u64,
    op_idx: u32,
) -> Option<ExprId> {
    match ins.op_kind(op_idx) {
        OpKind::Register => {
            let (ar, sl) = ArchReg::from_iced(ins.op_register(op_idx))?;
            Some(state.read_reg(arena, view.bitness, ar, sl))
        }
        OpKind::Memory => {
            let w = ins.memory_size().size() as u8;
            if w == 0 || w > 8 {
                return None;
            }
            let ea = eval_mem_ea(state, arena, view.bitness, ins, next_ip);
            Some(read_memory_expr(view, state, arena, ea, w))
        }
        k if k.is_imm() => Some(arena.const_u64(ins.immediate(op_idx))),
        _ => None,
    }
}

fn read_xmm_pair(
    view: &PeImageView,
    state: &mut SymState,
    arena: &mut ExprArena,
    ins: &Instruction,
    next_ip: u64,
    op_idx: u32,
) -> Option<(ExprId, ExprId)> {
    match ins.op_kind(op_idx) {
        OpKind::Register => {
            ArchReg::xmm_index(ins.op_register(op_idx)).map(|s| state.xmms[s as usize])
        }
        OpKind::Memory => {
            let ea = eval_mem_ea(state, arena, view.bitness, ins, next_ip);
            if let Some((space, off)) = arena.as_stack_offset(ea) {
                Some(state.stack.read_xmm(arena, space, off, state.mem_ver))
            } else {
                let lo = read_memory_expr(view, state, arena, ea, 8);
                let ea8 = arena.add_const(ea, 8);
                let hi = read_memory_expr(view, state, arena, ea8, 8);
                Some((lo, hi))
            }
        }
        _ => None,
    }
}

fn next_ip_reenters_vm(view: &PeImageView, mut ip: u64) -> bool {
    if view.is_in_vm_section(ip) {
        return true;
    }
    for _ in 0..4 {
        let Some(ins) = view.decode_insn(ip) else {
            return false;
        };
        let next = ip + ins.len() as u64;
        match ins.flow_control() {
            FlowControl::UnconditionalBranch => {
                let t = ins.near_branch_target();
                return t != 0 && view.is_in_vm_section(t);
            }
            FlowControl::Call => {
                let t = ins.near_branch_target();
                return t != 0 && view.is_in_vm_section(t);
            }
            FlowControl::Next => {
                ip = next;
            }
            _ => return false,
        }
    }
    false
}

fn write_operand(
    state: &mut SymState,
    arena: &mut ExprArena,
    effects: &mut Vec<IrEffect>,
    bitness: u32,
    ins: &Instruction,
    next_ip: u64,
    op_idx: u32,
    val: ExprId,
) -> bool {
    match ins.op_kind(op_idx) {
        OpKind::Register => {
            let Some((ar, sl)) = ArchReg::from_iced(ins.op_register(op_idx)) else {
                return false;
            };
            state.write_reg(arena, ar, sl, val);
            true
        }
        OpKind::Memory => {
            let w = ins.memory_size().size() as u8;
            if w == 0 || w > 8 {
                return false;
            }
            let ea = eval_mem_ea(state, arena, bitness, ins, next_ip);
            write_memory_expr(state, arena, effects, ea, w, val);
            true
        }
        _ => false,
    }
}

fn eval_cond_for_mnemonic(state: &SymState, arena: &mut ExprArena, m: Mnemonic) -> Option<ExprId> {
    let cc = match m {
        Mnemonic::Cmova | Mnemonic::Seta | Mnemonic::Ja => ConditionCode::a,
        Mnemonic::Cmovae | Mnemonic::Setae | Mnemonic::Jae => ConditionCode::ae,
        Mnemonic::Cmovb | Mnemonic::Setb | Mnemonic::Jb => ConditionCode::b,
        Mnemonic::Cmovbe | Mnemonic::Setbe | Mnemonic::Jbe => ConditionCode::be,
        Mnemonic::Cmove | Mnemonic::Sete | Mnemonic::Je => ConditionCode::e,
        Mnemonic::Cmovne | Mnemonic::Setne | Mnemonic::Jne => ConditionCode::ne,
        Mnemonic::Cmovg | Mnemonic::Setg | Mnemonic::Jg => ConditionCode::g,
        Mnemonic::Cmovge | Mnemonic::Setge | Mnemonic::Jge => ConditionCode::ge,
        Mnemonic::Cmovl | Mnemonic::Setl | Mnemonic::Jl => ConditionCode::l,
        Mnemonic::Cmovle | Mnemonic::Setle | Mnemonic::Jle => ConditionCode::le,
        Mnemonic::Cmovs | Mnemonic::Sets | Mnemonic::Js => ConditionCode::s,
        Mnemonic::Cmovns | Mnemonic::Setns | Mnemonic::Jns => ConditionCode::ns,
        Mnemonic::Cmovo | Mnemonic::Seto | Mnemonic::Jo => ConditionCode::o,
        Mnemonic::Cmovno | Mnemonic::Setno | Mnemonic::Jno => ConditionCode::no,
        _ => return None,
    };
    state.eval_cond_code(arena, cc)
}

/// Decomposes a multi-boolean polynomial indirect branch target (up to 5 `{0, 1}` variables)
/// into a reduced Shannon-ordered `Select` BDD after verifying every combination is executable.
/// Status flags are dead at `va`: following the original code from there (straight
/// line and unconditional jumps), every status flag is overwritten before any is
/// read. `false` when that cannot be shown.
fn flags_dead_at(view: &PeImageView, mut va: u64) -> bool {
    use iced_x86::RflagsBits;
    const STATUS: u32 = RflagsBits::OF | RflagsBits::SF | RflagsBits::ZF | RflagsBits::AF | RflagsBits::CF | RflagsBits::PF;
    let mut live = STATUS;
    for _ in 0..64 {
        let Some(ins) = view.decode_insn(va) else { return false };
        if ins.rflags_read() & live != 0 {
            return false;
        }
        live &= !(ins.rflags_written() | ins.rflags_cleared() | ins.rflags_set() | ins.rflags_undefined());
        if live == 0 {
            return true;
        }
        match ins.flow_control() {
            FlowControl::Next => va += ins.len() as u64,
            FlowControl::UnconditionalBranch if ins.near_branch_target() != 0 => va = ins.near_branch_target(),
            _ => return false,
        }
    }
    false
}

/// A qword of an aligned slot that was read before it was written (an `Opaque`
/// placeholder for the unknown memory) and then partly overwritten:
/// `Or(And(Opaque, keep_mask), written)`, possibly nested. Returns the value with the
/// unknown part zeroed and the bytes (bit per byte) that still hold the original
/// memory, or `None` for any other shape (bit-level masks, the unknown value mixed
/// into the written bytes, more than one unknown).
fn split_partly_written_slot(arena: &mut ExprArena, val: ExprId) -> Option<(ExprId, u8)> {
    fn opaques(arena: &ExprArena, id: ExprId, out: &mut Vec<ExprId>, seen: &mut HashSet<ExprId>) {
        if !seen.insert(id) || out.len() > 1 {
            return;
        }
        let node = arena.get(id);
        if matches!(node, ExprNode::Opaque(_)) {
            out.push(id);
            return;
        }
        let mut kids = Vec::new();
        push_expr_children(node, &mut kids);
        for k in kids {
            opaques(arena, k, out, seen);
        }
    }
    fn byte_mask(m: u64) -> Option<u8> {
        let mut out = 0u8;
        for j in 0..8 {
            match (m >> (8 * j)) & 0xFF {
                0xFF => out |= 1 << j,
                0 => {}
                _ => return None,
            }
        }
        Some(out)
    }
    fn known_zero_bytes(arena: &ExprArena, id: ExprId) -> u8 {
        let z = arena.known_bits(id).0;
        let mut out = 0u8;
        for j in 0..8 {
            if (z >> (8 * j)) & 0xFF == 0xFF {
                out |= 1 << j;
            }
        }
        out
    }
    /// (value with the unknown zeroed, bytes that are the unknown's) - as an
    /// expression that only exists for the planner, so it is rebuilt as a tree of
    /// existing node ids where possible.
    fn split(arena: &ExprArena, id: ExprId, unknown: ExprId) -> Option<(Option<ExprId>, u8)> {
        if id == unknown {
            return Some((None, 0xFF));
        }
        match arena.get(id) {
            ExprNode::And(a, b) => {
                let (x, m) = if let Some(m) = arena.as_const(*b) { (*a, m) } else { (*b, arena.as_const(*a)?) };
                let bm = byte_mask(m)?;
                let (rest, keep) = split(arena, x, unknown)?;
                // Bytes the mask clears are written (as 0); the others stay as they were.
                match rest {
                    // `x & m` with x the unknown alone: the written part is zero.
                    None => Some((None, keep & bm)),
                    Some(r) if keep == 0 => Some((Some(id).filter(|_| r == x), 0)),
                    Some(_) => None,
                }
            }
            ExprNode::Or(a, b) => {
                let (ra, ka) = split(arena, *a, unknown)?;
                let (rb, kb) = split(arena, *b, unknown)?;
                // A byte may hold the unknown on one side only, and the other side must
                // be known zero there.
                if ka & kb != 0 {
                    return None;
                }
                if ka != 0 && rb.is_some_and(|r| known_zero_bytes(arena, r) & ka != ka) {
                    return None;
                }
                if kb != 0 && ra.is_some_and(|r| known_zero_bytes(arena, r) & kb != kb) {
                    return None;
                }
                let rest = match (ra, rb) {
                    (None, r) | (r, None) => r,
                    (Some(_), Some(_)) => {
                        // Both sides written: only when neither holds the unknown.
                        if ka == 0 && kb == 0 {
                            Some(id)
                        } else {
                            return None;
                        }
                    }
                };
                Some((rest, ka | kb))
            }
            _ => {
                let mut v = Vec::new();
                opaques(arena, id, &mut v, &mut HashSet::new());
                if v.is_empty() { Some((Some(id), 0)) } else { None }
            }
        }
    }

    let mut found = Vec::new();
    opaques(arena, val, &mut found, &mut HashSet::new());
    let [unknown] = found[..] else { return None };
    let (rest, keep) = split(arena, val, unknown)?;
    if keep == 0 || keep == 0xFF {
        return None;
    }
    // Nothing written besides the cleared bytes: store zeros there.
    let rest = match rest {
        Some(r) => r,
        None => arena.const_u64(0),
    };
    Some((rest, keep))
}

/// `IrTerm::ExitToVm` to `va` for the current state, or `None` when the state cannot
/// be rebuilt there (RSP is neither a fixed entry offset nor on an aligned frame,
/// the frame cannot be described, live flags of a kind that cannot be replayed).
fn plan_vm_exit(state: &SymState, arena: &mut ExprArena, view: &PeImageView, va: u64) -> Option<VmExit> {
    const GAP: i64 = 64;
    if view.bitness != 64 || !view.is_executable_va(va) {
        return None;
    }
    let (final_base, final_off) = match arena.as_stack_offset(state.regs[ArchReg::Rsp.idx()])? {
        (StackSpace::CallerStack, off) => (None, off),
        (StackSpace::AlignedScratch(k), off) => (Some(k), off),
    };
    let bases = state.aligned_defs.clone();
    if bases.len() != state.next_aligned_id as usize || final_base.is_some_and(|k| k as usize >= bases.len()) {
        return None;
    }
    // Lowest address (from the entry RSP) each aligned base can have.
    let mut lower: Vec<i64> = Vec::with_capacity(bases.len());
    for &(parent, off, mask) in &bases {
        let align = (!mask).checked_add(1)? as i64;
        if !(2..=256).contains(&align) {
            return None;
        }
        let parent_lower = match parent {
            StackSpace::CallerStack => 0,
            StackSpace::AlignedScratch(p) => *lower.get(p as usize)?,
        };
        lower.push(parent_lower.checked_add(off)?.checked_sub(align - 1)?);
    }

    let mut caller: Vec<(i64, ExprId)> = Vec::new();
    let mut aligned: Vec<(u32, i64, ExprId, u8)> = Vec::new();
    for (&(space, off), &val) in &state.stack.slots {
        match space {
            StackSpace::CallerStack => {
                if state.entry_caller_slot_versions.get(&off) != Some(&val) {
                    caller.push((off, val));
                }
            }
            StackSpace::AlignedScratch(k) => {
                // Read but never written: the memory already holds it.
                if matches!(arena.get(val), ExprNode::Opaque(_)) {
                    continue;
                }
                // Partly written: store only the written bytes (a value that still
                // depends on unknown memory stays as it is and fails the soundness check).
                let (v, keep) = split_partly_written_slot(arena, val).unwrap_or((val, 0));
                aligned.push((k, off, v, keep));
            }
        }
    }
    caller.sort_by_key(|&(o, _)| o);
    aligned.sort_by_key(|&(k, o, _, _)| (k, o));

    // Flags: dead at the target, or replayed from the last flag-setting operation.
    let flag_vals: Vec<ExprId>;
    let flags_kind: Option<(u8, u8)>; // (0 cmp / 1 test / 2 add, width)
    if flags_dead_at(view, va) {
        flag_vals = Vec::new();
        flags_kind = None;
    } else {
        match &state.flags {
            FlagState::SubCmp { lhs, rhs, width } => {
                flag_vals = vec![*lhs, *rhs];
                flags_kind = Some((0, *width));
            }
            FlagState::TestBitwise { val, width } => {
                flag_vals = vec![*val];
                flags_kind = Some((1, *width));
            }
            FlagState::Add { lhs, rhs, width, .. } => {
                flag_vals = vec![*lhs, *rhs];
                flags_kind = Some((2, *width));
            }
            _ => return None,
        }
        if !matches!(flags_kind, Some((_, 1 | 2 | 4 | 8))) {
            return None;
        }
    }

    let mut lowest = 0i64;
    for &(o, _) in &caller {
        lowest = lowest.min(o);
    }
    for &(k, o, _, _) in &aligned {
        lowest = lowest.min(lower[k as usize].checked_add(o)?);
    }
    let final_lower = match final_base {
        Some(k) => lower[k as usize].checked_add(final_off)?,
        None => final_off,
    };
    lowest = lowest.min(final_lower.checked_sub(GAP)?);
    let temp_end = lowest.checked_sub(GAP)?;
    let temp_start = temp_end.checked_sub(8 * (aligned.len() + flag_vals.len()) as i64)?;
    let rsp_delta = (temp_start - 16).div_euclid(16) * 16;
    if rsp_delta < -0x4000_0000 {
        return None;
    }

    let mut pending = caller;
    let mut temp_stores = Vec::with_capacity(aligned.len());
    let mut t = temp_start;
    for &(k, o, val, keep) in &aligned {
        pending.push((t, val));
        temp_stores.push((t, k, o, keep));
        t += 8;
    }
    let mut flag_offs = Vec::with_capacity(flag_vals.len());
    for &v in &flag_vals {
        pending.push((t, v));
        flag_offs.push(t);
        t += 8;
    }
    let flags = flags_kind.map(|(kind, width)| match kind {
        0 => FlagsReplay::Cmp { a: flag_offs[0], b: flag_offs[1], width },
        1 => FlagsReplay::Test { a: flag_offs[0], width },
        _ => FlagsReplay::Add { a: flag_offs[0], b: flag_offs[1], width },
    });
    Some(VmExit { rsp_delta, pending, temp_stores, bases, final_base, final_off, flags })
}

/// `ExitToVm` to `va` when VM exits are on and the state can be rebuilt there,
/// otherwise the bailout.
fn exit_to_vm_or_bailout(
    cfg: &BinaryDevirtConfig,
    state: &SymState,
    arena: &mut ExprArena,
    view: &PeImageView,
    va: u64,
    reason: String,
) -> IrTerm {
    if cfg.allow_vm_exits {
        if let Some(exit) = plan_vm_exit(state, arena, view, va) {
            return IrTerm::ExitToVm { va, exit: Box::new(exit), final_regs: state.regs, final_xmms: state.xmms };
        }
    }
    IrTerm::Bailout(reason)
}

/// Jump-target rewrite: inside `Select(c, t, f)` the condition is known, so `t` is
/// rewritten with `c = 1` and `f` with `c = 0`; when `c` is `y == K` the true arm also
/// gets `y = K` (`y != K`: the false arm). The arms of a dispatcher jump repeat the
/// dispatcher test (`Or(..) == 0`) and multiply by it, so in each arm that part
/// becomes a constant and the leaf turns into a real target. Nested selects are
/// specialised too (a few levels; jump targets only, not every `select`, as the
/// rewrite walks the arm).
fn specialize_select_arms(arena: &mut ExprArena, id: ExprId, depth: u8) -> ExprId {
    const MAX_DEPTH: u8 = 4;
    let ExprNode::Select { cond, if_true, if_false } = arena.get(id).clone() else {
        return id;
    };
    if depth > MAX_DEPTH {
        return id;
    }
    let one = arena.const_u64(1);
    let zero = arena.const_u64(0);
    let mut t = arena.substitute(if_true, cond, one);
    let mut f = arena.substitute(if_false, cond, zero);
    if let ExprNode::Cmp { pred, lhs, rhs } = arena.get(cond).clone() {
        if arena.as_const(lhs).is_none() && arena.as_const(rhs).is_some() {
            match pred {
                CondPred::Eq => t = arena.substitute(t, lhs, rhs),
                CondPred::Ne => f = arena.substitute(f, lhs, rhs),
                _ => {}
            }
        }
    }
    let t = specialize_select_arms(arena, t, depth + 1);
    let f = specialize_select_arms(arena, f, depth + 1);
    if t == if_true && f == if_false {
        return id;
    }
    arena.select(cond, t, f)
}

/// Jump-target rewrite: `x + b * k` with `b` known to be 0 or 1 becomes
/// `Select(b, x + k, x)`, and the arms are rewritten again, so a sum with several
/// predicated displacements turns into a `Select` tree that `parse_select_tree` can
/// split into conditional branches.
///
/// `try_decompose_bool_mux_target` already models `Mul(Cmp, k)`, but only when every
/// leaf of the sum is boolean: one non-boolean term (`x` above: a register-derived
/// base, a load) makes it give up, and the jump stayed `unresolved_indirect_jmp`. The
/// leaves here are left to the usual checks (`all_select_leaves_valid`); a leaf that
/// is still not a constant just fails there instead.
///
/// Done only on a jump target, not in `ExprArena::mul`: as `Mul` the products keep
/// cancelling in linear sums (`b*k + b*(-k)`), which a `Select` would not.
fn hoist_bool_product_select(arena: &mut ExprArena, id: ExprId, depth: u8) -> Option<ExprId> {
    const MAX_DEPTH: u8 = 6;
    if depth > MAX_DEPTH {
        return None;
    }
    let is_bool = |arena: &ExprArena, x: ExprId| (arena.known_bits(x).0 & !1u64) == !1u64;
    let sel = match arena.get(id).clone() {
        ExprNode::Mul(a, b) => {
            let (cond, k) = if arena.as_const(b).is_some() && is_bool(arena, a) {
                (a, b)
            } else if arena.as_const(a).is_some() && is_bool(arena, b) {
                (b, a)
            } else {
                return None;
            };
            let zero = arena.const_u64(0);
            arena.select(cond, k, zero)
        }
        ExprNode::Add(a, b) => {
            let (inner, rest) = match hoist_bool_product_select(arena, a, depth + 1) {
                Some(sa) => (sa, b),
                None => (hoist_bool_product_select(arena, b, depth + 1)?, a),
            };
            let ExprNode::Select { cond, if_true, if_false } = arena.get(inner).clone() else {
                return None;
            };
            let t = arena.add(if_true, rest);
            let f = arena.add(if_false, rest);
            arena.select(cond, t, f)
        }
        _ => return None,
    };
    // Further boolean products inside the arms become nested selects.
    let ExprNode::Select { cond, if_true, if_false } = arena.get(sel).clone() else {
        return Some(sel);
    };
    let t = hoist_bool_product_select(arena, if_true, depth + 1).unwrap_or(if_true);
    let f = hoist_bool_product_select(arena, if_false, depth + 1).unwrap_or(if_false);
    Some(arena.select(cond, t, f))
}

/// Boolean atoms a jump-target polynomial may have (2^n evaluations, every one must
/// land on executable code). Dispatchers with several predicated displacements per
/// arm carry 6-10 atoms; 5 left all of them `unresolved_indirect_jmp`.
const MAX_MUX_VARS: usize = 10;
/// Expression nodes walked while collecting the atoms (the arms of such dispatchers
/// are a few hundred nodes).
const MAX_MUX_VISITS: usize = 2048;

fn try_decompose_bool_mux_target(
    arena: &mut ExprArena,
    view: &PeImageView,
    root: ExprId,
) -> Option<ExprId> {
    fn is_bool_expr(arena: &ExprArena, id: ExprId) -> bool {
        (arena.known_bits(id).0 & !1u64) == !1u64
    }

    fn merge_vars(mut a: Vec<ExprId>, b: &[ExprId]) -> Option<Vec<ExprId>> {
        for &v in b {
            if !a.contains(&v) {
                a.push(v);
                if a.len() > MAX_MUX_VARS {
                    return None;
                }
            }
        }
        Some(a)
    }

    fn collect_bool_vars(
        arena: &ExprArena,
        id: ExprId,
        memo: &mut HashMap<ExprId, Option<Vec<ExprId>>>,
        visits: &mut usize,
    ) -> Option<Vec<ExprId>> {
        if let Some(cached) = memo.get(&id) {
            return cached.clone();
        }
        if *visits >= MAX_MUX_VISITS {
            return None;
        }
        *visits += 1;
        let res = match arena.get(id) {
            ExprNode::Const(_) => Some(Vec::new()),
            ExprNode::Cmp { .. } | ExprNode::EntryFlag(_) => Some(vec![id]),
            ExprNode::And(a, b) if arena.as_const(*a) == Some(1) || arena.as_const(*b) == Some(1) => {
                // `vm_ir::and` already strips `& 1` from known booleans, so remaining `& 1` masks a non-boolean leaf.
                Some(vec![id])
            }
            ExprNode::Neg(a) | ExprNode::Not(a) | ExprNode::SExt { val: a, .. } => {
                collect_bool_vars(arena, *a, memo, visits).or_else(|| {
                    if is_bool_expr(arena, id) {
                        Some(vec![id])
                    } else {
                        None
                    }
                })
            }
            ExprNode::Add(a, b)
            | ExprNode::Sub(a, b)
            | ExprNode::Mul(a, b)
            | ExprNode::And(a, b)
            | ExprNode::Or(a, b)
            | ExprNode::Xor(a, b)
            | ExprNode::Shl(a, b)
            | ExprNode::Shr(a, b)
            | ExprNode::Sar(a, b)
            | ExprNode::Rol(a, b)
            | ExprNode::Ror(a, b) => collect_bool_vars(arena, *a, memo, visits)
                .and_then(|va| {
                    collect_bool_vars(arena, *b, memo, visits).and_then(|vb| merge_vars(va, &vb))
                })
                .or_else(|| {
                    if is_bool_expr(arena, id) {
                        Some(vec![id])
                    } else {
                        None
                    }
                }),
            ExprNode::Select { cond, if_true, if_false } => {
                collect_bool_vars(arena, *cond, memo, visits)
                    .and_then(|vc| {
                        collect_bool_vars(arena, *if_true, memo, visits)
                            .and_then(|vt| merge_vars(vc, &vt))
                    })
                    .and_then(|vct| {
                        collect_bool_vars(arena, *if_false, memo, visits)
                            .and_then(|vf| merge_vars(vct, &vf))
                    })
                    .or_else(|| {
                        if is_bool_expr(arena, id) {
                            Some(vec![id])
                        } else {
                            None
                        }
                    })
            }
            _ => {
                if is_bool_expr(arena, id) {
                    Some(vec![id])
                } else {
                    None
                }
            }
        };
        memo.insert(id, res.clone());
        res
    }

    fn eval_poly(
        arena: &ExprArena,
        id: ExprId,
        vars: &[ExprId],
        mask: usize,
        memo: &mut HashMap<ExprId, u64>,
    ) -> Option<u64> {
        if let Some(&v) = memo.get(&id) {
            return Some(v);
        }
        if let Some(pos) = vars.iter().position(|&v| v == id) {
            let val = ((mask >> pos) & 1) as u64;
            memo.insert(id, val);
            return Some(val);
        }
        let val = match arena.get(id) {
            ExprNode::Const(c) => *c,
            ExprNode::Neg(a) => eval_poly(arena, *a, vars, mask, memo)?.wrapping_neg(),
            ExprNode::Not(a) => !eval_poly(arena, *a, vars, mask, memo)?,
            ExprNode::SExt { val: a, from_bits } => {
                let x = eval_poly(arena, *a, vars, mask, memo)?;
                if *from_bits >= 64 || *from_bits == 0 {
                    x
                } else {
                    let sh = 64 - (*from_bits as u32);
                    (((x << sh) as i64) >> sh) as u64
                }
            }
            ExprNode::Add(a, b) => eval_poly(arena, *a, vars, mask, memo)?
                .wrapping_add(eval_poly(arena, *b, vars, mask, memo)?),
            ExprNode::Sub(a, b) => eval_poly(arena, *a, vars, mask, memo)?
                .wrapping_sub(eval_poly(arena, *b, vars, mask, memo)?),
            ExprNode::Mul(a, b) => eval_poly(arena, *a, vars, mask, memo)?
                .wrapping_mul(eval_poly(arena, *b, vars, mask, memo)?),
            ExprNode::And(a, b) => {
                eval_poly(arena, *a, vars, mask, memo)? & eval_poly(arena, *b, vars, mask, memo)?
            }
            ExprNode::Or(a, b) => {
                eval_poly(arena, *a, vars, mask, memo)? | eval_poly(arena, *b, vars, mask, memo)?
            }
            ExprNode::Xor(a, b) => {
                eval_poly(arena, *a, vars, mask, memo)? ^ eval_poly(arena, *b, vars, mask, memo)?
            }
            ExprNode::Shl(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                va.wrapping_shl((vb & 63) as u32)
            }
            ExprNode::Shr(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                va.wrapping_shr((vb & 63) as u32)
            }
            ExprNode::Sar(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                ((va as i64).wrapping_shr((vb & 63) as u32)) as u64
            }
            ExprNode::Rol(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                va.rotate_left((vb & 63) as u32)
            }
            ExprNode::Ror(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                va.rotate_right((vb & 63) as u32)
            }
            ExprNode::Select { cond, if_true, if_false } => {
                let c = eval_poly(arena, *cond, vars, mask, memo)?;
                if c != 0 {
                    eval_poly(arena, *if_true, vars, mask, memo)?
                } else {
                    eval_poly(arena, *if_false, vars, mask, memo)?
                }
            }
            _ => return None,
        };
        memo.insert(id, val);
        Some(val)
    }

    fn slice_const(vals: &[u64], remaining: &[usize], base_mask: usize) -> Option<u64> {
        let first = vals[base_mask];
        let count = 1usize << remaining.len();
        for sub in 1..count {
            let mut m = base_mask;
            for (bi, &var_idx) in remaining.iter().enumerate() {
                if (sub >> bi) & 1 != 0 {
                    m |= 1 << var_idx;
                }
            }
            if vals[m] != first {
                return None;
            }
        }
        Some(first)
    }

    fn build_bdd(
        arena: &mut ExprArena,
        vars: &[ExprId],
        vals: &[u64],
        remaining: &[usize],
        base_mask: usize,
    ) -> ExprId {
        if let Some(c) = slice_const(vals, remaining, base_mask) {
            return arena.const_u64(c);
        }
        let mut best_pos = 0usize;
        let mut best_score = 0u8;
        for (pos, &v_idx) in remaining.iter().enumerate() {
            let rest: Vec<usize> = remaining.iter().copied().filter(|&x| x != v_idx).collect();
            let s = u8::from(slice_const(vals, &rest, base_mask).is_some())
                + u8::from(slice_const(vals, &rest, base_mask | (1 << v_idx)).is_some());
            if s > best_score {
                best_score = s;
                best_pos = pos;
                if s == 2 {
                    break;
                }
            }
        }
        let chosen = remaining[best_pos];
        let rest: Vec<usize> = remaining.iter().copied().filter(|&x| x != chosen).collect();
        let f = build_bdd(arena, vars, vals, &rest, base_mask);
        let t = build_bdd(arena, vars, vals, &rest, base_mask | (1 << chosen));
        if t == f {
            t
        } else {
            arena.select(vars[chosen], t, f)
        }
    }

    let mut memo = HashMap::new();
    let mut visits = 0usize;
    let vars = collect_bool_vars(arena, root, &mut memo, &mut visits)?;
    if vars.is_empty() || vars.len() > MAX_MUX_VARS {
        return None;
    }

    let combos = 1usize << vars.len();
    let mut vals = Vec::with_capacity(combos);
    for mask in 0..combos {
        let mut eval_memo = HashMap::new();
        let va = eval_poly(arena, root, &vars, mask, &mut eval_memo)?;
        if !view.is_executable_va(va) {
            return None;
        }
        vals.push(va);
    }

    let remaining: Vec<usize> = (0..vars.len()).collect();
    Some(build_bdd(arena, &vars, &vals, &remaining, 0))
}

#[derive(Clone, Copy)]
enum SelectArm {
    ConstVa { expr: ExprId, va: u64 },
    RegDisp { expr: ExprId, reg: ArchReg, disp: i64 },
}

enum SelectTree {
    Leaf(SelectArm),
    Branch {
        cond: ExprId,
        if_true: Box<SelectTree>,
        if_false: Box<SelectTree>,
    },
}

fn parse_select_tree(
    arena: &ExprArena,
    id: ExprId,
    jmp_arch_reg: Option<ArchReg>,
    depth: u8,
) -> Option<SelectTree> {
    if depth < 5 {
        if let ExprNode::Select { cond, if_true, if_false } = arena.get(id) {
            let t = parse_select_tree(arena, *if_true, jmp_arch_reg, depth + 1)?;
            let f = parse_select_tree(arena, *if_false, jmp_arch_reg, depth + 1)?;
            return Some(SelectTree::Branch {
                cond: *cond,
                if_true: Box::new(t),
                if_false: Box::new(f),
            });
        }
    }
    if let Some(va) = arena.as_const(id) {
        return Some(SelectTree::Leaf(SelectArm::ConstVa { expr: id, va }));
    }
    if let ExprNode::Add(b, d) = arena.get(id) {
        if let (ExprNode::RegIn(_), Some(disp), Some(jr)) =
            (arena.get(*b), arena.as_const(*d), jmp_arch_reg)
        {
            return Some(SelectTree::Leaf(SelectArm::RegDisp {
                expr: id,
                reg: jr,
                disp: disp as i64,
            }));
        }
    }
    None
}

fn all_select_leaves_valid(
    tree: &SelectTree,
    view: &PeImageView,
    rsp_delta_opt: Option<i64>,
) -> bool {
    match tree {
        SelectTree::Leaf(SelectArm::ConstVa { va, .. }) => {
            view.is_in_vm_section(*va) || rsp_delta_opt.is_some() || view.is_executable_va(*va)
        }
        SelectTree::Leaf(SelectArm::RegDisp { .. }) => rsp_delta_opt.is_some(),
        SelectTree::Branch { if_true, if_false, .. } => {
            all_select_leaves_valid(if_true, view, rsp_delta_opt)
                && all_select_leaves_valid(if_false, view, rsp_delta_opt)
        }
    }
}

fn count_select_tree_blocks(tree: &SelectTree) -> usize {
    match tree {
        SelectTree::Leaf(_) => 1,
        SelectTree::Branch { if_true, if_false, .. } => {
            1 + count_select_tree_blocks(if_true) + count_select_tree_blocks(if_false)
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
struct StateDedupKey {
    ip: u64,
    regs: [ExprId; 16],
    xmms: [(ExprId, ExprId); 16],
    stack_slots: Vec<((StackSpace, i64), ExprId)>,
    flags: FlagState,
    saved_rflags: Vec<(ExprId, FlagState)>,
    cum_rsp_offset: i64,
    inline_depth: usize,
    entry_flags_clobbered: bool,
    mem_ver: u32,
    cr8_ver: u32,
    mem_cache: Vec<(ExprId, (u8, ExprId))>,
    entry_caller_slots: Vec<(i64, ExprId)>,
    aligned_defs: Vec<(StackSpace, i64, u64)>,
}

fn make_state_dedup_key(s: &SymState) -> StateDedupKey {
    let mut stack_slots: Vec<((StackSpace, i64), ExprId)> =
        s.stack.slots.iter().map(|(&k, &v)| (k, v)).collect();
    stack_slots.sort_unstable_by_key(|&(k, _)| {
        (
            match k.0 {
                StackSpace::CallerStack => (0u8, 0u32),
                StackSpace::AlignedScratch(id) => (1u8, id),
            },
            k.1,
        )
    });
    let mut mem_cache: Vec<(ExprId, (u8, ExprId))> =
        s.mem_cache.iter().map(|(&k, &v)| (k, v)).collect();
    mem_cache.sort_unstable_by_key(|&(k, _)| k.0);
    let mut entry_caller_slots: Vec<(i64, ExprId)> = s
        .entry_caller_slot_versions
        .iter()
        .map(|(&k, &v)| (k, v))
        .collect();
    entry_caller_slots.sort_unstable_by_key(|&(k, _)| k);
    StateDedupKey {
        ip: s.ip,
        regs: s.regs,
        xmms: s.xmms,
        stack_slots,
        flags: s.flags.clone(),
        saved_rflags: s.saved_rflags.clone(),
        cum_rsp_offset: s.cum_rsp_offset,
        inline_depth: s.inline_depth,
        entry_flags_clobbered: s.entry_flags_clobbered,
        mem_ver: s.mem_ver,
        cr8_ver: s.cr8_ver,
        aligned_defs: s.aligned_defs.clone(),
        mem_cache,
        entry_caller_slots,
    }
}

fn enqueue_vm_block(
    b_state: SymState,
    blocks: &mut Vec<Option<LiftedBlock>>,
    queue: &mut VecDeque<(usize, SymState)>,
    state_block_cache: &mut HashMap<StateDedupKey, usize>,
) -> usize {
    let key = make_state_dedup_key(&b_state);
    if let Some(&existing_id) = state_block_cache.get(&key) {
        return existing_id;
    }
    let bid = blocks.len();
    blocks.push(None);
    state_block_cache.insert(key, bid);
    queue.push_back((bid, b_state));
    bid
}

fn subst_flag_state(
    arena: &mut ExprArena,
    flags: &mut FlagState,
    from: ExprId,
    to: ExprId,
    memo: &mut HashMap<ExprId, ExprId>,
) {
    match flags {
        FlagState::SubCmp { lhs, rhs, .. } => {
            *lhs = arena.substitute_memo(*lhs, from, to, memo);
            *rhs = arena.substitute_memo(*rhs, from, to, memo);
        }
        FlagState::TestBitwise { val, .. } => {
            *val = arena.substitute_memo(*val, from, to, memo);
        }
        FlagState::Add { lhs, rhs, res, .. } => {
            *lhs = arena.substitute_memo(*lhs, from, to, memo);
            *rhs = arena.substitute_memo(*rhs, from, to, memo);
            *res = arena.substitute_memo(*res, from, to, memo);
        }
        FlagState::IncDec { res, .. } => {
            *res = arena.substitute_memo(*res, from, to, memo);
        }
        FlagState::CarryExpr(e) => {
            *e = arena.substitute_memo(*e, from, to, memo);
        }
        FlagState::Entry | FlagState::Unknown => {}
    }
}

fn specialize_sym_state(arena: &mut ExprArena, state: &mut SymState, cond: ExprId, taken: bool) {
    state.entry_flags_clobbered = true;
    state.saved_rflags.retain(|(_, fl)| !matches!(fl, FlagState::Entry));
    let repl = arena.const_u64(u64::from(taken));
    let mut pairs = vec![(cond, repl)];
    if let Some(cc) = as_direct_entry_flag(arena, cond) {
        let t_val = arena.const_u64(u64::from(taken));
        let f_val = arena.const_u64(u64::from(!taken));
        let ef_pos = arena.entry_flag(cc);
        let ef_neg = arena.entry_flag(cc ^ 1);
        pairs.push((ef_pos, t_val));
        pairs.push((ef_neg, f_val));
    }
    match arena.get(cond).clone() {
        ExprNode::Cmp { pred: CondPred::Eq, lhs, rhs } if taken => {
            if arena.as_const(rhs).is_some() {
                pairs.push((lhs, rhs));
            } else if arena.as_const(lhs).is_some() {
                pairs.push((rhs, lhs));
            }
        }
        ExprNode::Cmp { pred: CondPred::Ne, lhs, rhs } if !taken => {
            if arena.as_const(rhs).is_some() {
                pairs.push((lhs, rhs));
            } else if arena.as_const(lhs).is_some() {
                pairs.push((rhs, lhs));
            }
        }
        ExprNode::Cmp { pred: CondPred::Eq, lhs, rhs } if !taken && arena.as_const(rhs) == Some(0) => {
            if (arena.known_bits(lhs).0 & !1u64) == !1u64 {
                let one = arena.const_u64(1);
                pairs.push((lhs, one));
            }
        }
        ExprNode::Cmp { pred: CondPred::Ne, lhs, rhs } if taken && arena.as_const(rhs) == Some(0) => {
            if (arena.known_bits(lhs).0 & !1u64) == !1u64 {
                let one = arena.const_u64(1);
                pairs.push((lhs, one));
            }
        }
        _ => {}
    }
    for (from, to) in pairs {
        if from == to {
            continue;
        }
        let mut memo = HashMap::new();
        for r in &mut state.regs {
            *r = arena.substitute_memo(*r, from, to, &mut memo);
        }
        for x in &mut state.xmms {
            x.0 = arena.substitute_memo(x.0, from, to, &mut memo);
            x.1 = arena.substitute_memo(x.1, from, to, &mut memo);
        }
        for v in state.stack.slots.values_mut() {
            *v = arena.substitute_memo(*v, from, to, &mut memo);
        }
        let old_cache: Vec<(ExprId, (u8, ExprId))> = state.mem_cache.drain().collect();
        for (k, (w, v)) in old_cache {
            let nk = arena.substitute_memo(k, from, to, &mut memo);
            let nv = arena.substitute_memo(v, from, to, &mut memo);
            state.mem_cache.insert(nk, (w, nv));
        }
        subst_flag_state(arena, &mut state.flags, from, to, &mut memo);
        for (_, fl) in &mut state.saved_rflags {
            subst_flag_state(arena, fl, from, to, &mut memo);
        }
    }
}

fn try_split_select_mem_addr(arena: &mut ExprArena, ea: ExprId) -> Option<ExprId> {
    if let ExprNode::Select { cond, if_true, if_false } = arena.get(ea) {
        if arena.as_stack_offset(*if_true).is_some()
            || arena.as_stack_offset(*if_false).is_some()
            || (arena.as_const(*if_true).is_some() && arena.as_const(*if_false).is_some())
        {
            return Some(*cond);
        }
    }
    fn collect_cand_bools(arena: &ExprArena, id: ExprId, depth: u8, out: &mut Vec<ExprId>) {
        if depth > 4 || out.len() >= 4 {
            return;
        }
        match arena.get(id) {
            ExprNode::Add(a, b)
            | ExprNode::Sub(a, b)
            | ExprNode::And(a, b)
            | ExprNode::Or(a, b)
            | ExprNode::Xor(a, b) => {
                collect_cand_bools(arena, *a, depth + 1, out);
                collect_cand_bools(arena, *b, depth + 1, out);
            }
            ExprNode::Neg(x) => {
                if arena.as_const(*x).is_none()
                    && (arena.known_bits(*x).0 & !1u64) == !1u64
                    && !out.contains(x)
                {
                    out.push(*x);
                }
                collect_cand_bools(arena, *x, depth + 1, out);
            }
            ExprNode::Mul(a, b) => {
                for &side in &[*a, *b] {
                    if arena.as_const(side).is_none()
                        && (arena.known_bits(side).0 & !1u64) == !1u64
                        && !out.contains(&side)
                    {
                        out.push(side);
                    }
                }
                collect_cand_bools(arena, *a, depth + 1, out);
                collect_cand_bools(arena, *b, depth + 1, out);
            }
            _ => {}
        }
    }
    let mut cands = Vec::new();
    collect_cand_bools(arena, ea, 0, &mut cands);
    if cands.is_empty() {
        return None;
    }
    let zero = arena.const_u64(0);
    let one = arena.const_u64(1);
    for c in cands {
        let ea0 = arena.substitute(ea, c, zero);
        let ea1 = arena.substitute(ea, c, one);
        if ea0 != ea1
            && (arena.as_stack_offset(ea0).is_some()
                || arena.as_stack_offset(ea1).is_some()
                || (arena.as_const(ea0).is_some() && arena.as_const(ea1).is_some()))
        {
            return Some(c);
        }
    }
    None
}

fn try_resolve_select_mem_pair(arena: &mut ExprArena, ea: ExprId) -> Option<(ExprId, ExprId, ExprId)> {
    if let ExprNode::Select { cond, if_true, if_false } = arena.get(ea).clone() {
        return Some((cond, if_true, if_false));
    }
    if let Some(c) = try_split_select_mem_addr(arena, ea) {
        let one = arena.const_u64(1);
        let zero = arena.const_u64(0);
        let ea1 = arena.substitute(ea, c, one);
        let ea0 = arena.substitute(ea, c, zero);
        if ea1 != ea0 && ea1 != ea && ea0 != ea {
            return Some((c, ea1, ea0));
        }
    }
    None
}

#[inline]
fn is_pure_nonfaulting_read_addr(arena: &ExprArena, view: &PeImageView, addr: ExprId, width: u8) -> bool {
    arena.as_stack_offset(addr).is_some()
        || arena.as_const(addr).is_some_and(|va| view.read_ro_scalar(va, width).is_some())
}

#[inline]
fn is_internal_stack_addr(arena: &ExprArena, addr: ExprId) -> Option<(StackSpace, i64)> {
    arena
        .as_stack_offset(addr)
        .filter(|&(sp, off)| matches!(sp, StackSpace::AlignedScratch(_)) || off < 0)
}

#[allow(clippy::too_many_arguments)]
fn materialize_select_node(
    node: &SelectTree,
    cur_ip: u64,
    jmp_arch_reg: Option<ArchReg>,
    rsp_delta_opt: Option<i64>,
    state: &SymState,
    view: &PeImageView,
    arena: &mut ExprArena,
    blocks: &mut Vec<Option<LiftedBlock>>,
    queue: &mut VecDeque<(usize, SymState)>,
    state_block_cache: &mut HashMap<StateDedupKey, usize>,
) -> usize {
    match node {
        SelectTree::Branch { cond, if_true, if_false } => {
            let bid = blocks.len();
            blocks.push(None);
            let mut s_t = state.clone();
            specialize_sym_state(arena, &mut s_t, *cond, true);
            let mut s_f = state.clone();
            specialize_sym_state(arena, &mut s_f, *cond, false);
            let taken_block = materialize_select_node(
                if_true,
                cur_ip,
                jmp_arch_reg,
                rsp_delta_opt,
                &s_t,
                view,
                arena,
                blocks,
                queue,
                state_block_cache,
            );
            let fallthrough_block = materialize_select_node(
                if_false,
                cur_ip,
                jmp_arch_reg,
                rsp_delta_opt,
                &s_f,
                view,
                arena,
                blocks,
                queue,
                state_block_cache,
            );
            blocks[bid] = Some(LiftedBlock {
                id: bid,
                entry_va: cur_ip,
                effects: Vec::new(),
                term: IrTerm::CondBranch {
                    cond: *cond,
                    taken_block,
                    fallthrough_block,
                },
            });
            bid
        }
        SelectTree::Leaf(arm) => {
            let mut s2 = state.clone();
            match *arm {
                SelectArm::ConstVa { expr, va } => {
                    if let Some(jr) = jmp_arch_reg {
                        s2.regs[jr.idx()] = expr;
                    }
                    s2.ip = va;
                    if view.is_in_vm_section(va)
                        || (rsp_delta_opt.is_none() && view.is_executable_va(va))
                    {
                        enqueue_vm_block(s2, blocks, queue, state_block_cache)
                    } else {
                        let bid = blocks.len();
                        blocks.push(None);
                        let rsp_delta = rsp_delta_opt.unwrap();
                        let pending = s2.collect_pending_caller_stores(rsp_delta);
                        blocks[bid] = Some(LiftedBlock {
                            id: bid,
                            entry_va: va,
                            effects: Vec::new(),
                            term: IrTerm::ExitJmp {
                                target_va: va,
                                rsp_delta,
                                final_regs: s2.regs,
                                final_xmms: s2.xmms,
                                pending_caller_stores: pending,
                            },
                        });
                        bid
                    }
                }
                SelectArm::RegDisp { expr, reg, disp } => {
                    if let Some(jr) = jmp_arch_reg {
                        s2.regs[jr.idx()] = expr;
                    }
                    let bid = blocks.len();
                    blocks.push(None);
                    let rsp_delta = rsp_delta_opt.unwrap();
                    blocks[bid] = Some(LiftedBlock {
                        id: bid,
                        entry_va: cur_ip,
                        effects: Vec::new(),
                        term: IrTerm::ExitAddJmp {
                            reg,
                            disp,
                            rsp_delta,
                            final_regs: s2.regs,
                            final_xmms: s2.xmms,
                        },
                    });
                    bid
                }
            }
        }
    }
}

fn check_pure_rsp_delta(arena: &ExprArena, rsp: ExprId) -> Option<i64> {
    match arena.as_stack_offset(rsp) {
        Some((StackSpace::CallerStack, delta)) => Some(delta),
        _ => None,
    }
}

/// Symbolically lifts an entire VM entry CFG (supporting multiple conditional paths).
pub fn lift_vm_entry_cfg(
    view: &PeImageView,
    entry: &DiscoveredEntry,
    cfg: &BinaryDevirtConfig,
) -> LiftedFunction {
    let mut arena = ExprArena::default();
    let start_va = view.image_base + entry.lift_start_rva as u64;
    let fake_ret_va = view.image_base + entry.patch_rva as u64 + entry.patch_size as u64;
    let init_state = SymState::new(&mut arena, start_va, entry.is_call, fake_ret_va);

    let mut blocks: Vec<Option<LiftedBlock>> = vec![None];
    let mut queue: VecDeque<(usize, SymState)> = VecDeque::new();
    queue.push_back((0, init_state));

    let word_bytes: u8 = if view.bitness == 64 { 8 } else { 4 };
    let mut raw_vm_insns = 0usize;
    let mut opaque_branches_folded = 0usize;
    let mut visited_byte_addrs = HashSet::new();
    let mut first_bailout = None;
    let mut bailout_detail: Option<(u64, String)> = None;
    let mut state_block_cache: HashMap<StateDedupKey, usize> = HashMap::new();

    while let Some((block_id, mut state)) = queue.pop_front() {
        let entry_va = state.ip;
        let mut effects = Vec::new();
        let mut block_insns = 0usize;
        let mut ip_visit_counts: HashMap<u64, usize> = HashMap::new();
        let mut last_cur_ip: u64;
        let mut last_ins: Option<Instruction>;
        let mut pending_diag_detail: Option<String> = None;

        let term = loop {
            last_cur_ip = state.ip;
            if block_insns >= cfg.max_insns_per_block || raw_vm_insns >= cfg.max_total_insns_per_entry {
                last_ins = None;
                break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, state.ip, "insn_budget_exceeded".into());
            }

            let cur_ip = state.ip;
            let count = ip_visit_counts.entry(cur_ip).or_insert(0);
            *count += 1;
            if *count > 96 {
                last_ins = None;
                break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "loop_iteration_limit".into());
            }

            let Some(ins) = view.decode_insn(cur_ip) else {
                last_ins = None;
                break IrTerm::Bailout("decode_failed".into());
            };
            last_ins = Some(ins);
            let next_ip = cur_ip + ins.len() as u64;

            // Count VM bytes/insns inside VM sections or while executing inside an aligned/shifted VM context frame
            let in_vm = view.is_in_vm_section(cur_ip);
            let dirty_rsp = check_pure_rsp_delta(&arena, state.reg_full(ArchReg::Rsp)).is_none();
            if in_vm || dirty_rsp {
                raw_vm_insns += 1;
            }
            if in_vm {
                for b in cur_ip..next_ip {
                    visited_byte_addrs.insert(b);
                }
            }
            block_insns += 1;
            state.ip = next_ip;

            let m = ins.mnemonic();
            let flow = ins.flow_control();

            // Check LOCK prefix
            if ins.has_lock_prefix() {
                let w = ins.memory_size().size() as u8;
                if w == 0 || w > 8 || ins.op0_kind() != OpKind::Memory {
                    break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_lock_{m:?}"));
                }
                let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                match m {
                    Mnemonic::Cmpxchg => {
                        let Some(src) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                            break IrTerm::Bailout("lock_cmpxchg_src".into());
                        };
                        let expected_rax = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, RegSlice::Full64);
                        state.mem_ver += 1;
                        state.mem_cache.clear();
                        effects.push(IrEffect::AtomicCmpXchg {
                            lock: true,
                            addr: ea,
                            width: w,
                            expected_rax,
                            desired: arena.zext_mask(src, w),
                            mem_ver_after: state.mem_ver,
                        });
                        let new_rax = arena.opaque();
                        let sl = if w == 8 { RegSlice::Full64 } else if w == 4 { RegSlice::Low32 } else if w == 2 { RegSlice::Low16 } else { RegSlice::Low8 };
                        state.write_reg(&mut arena, ArchReg::Rax, sl, new_rax);
                        state.set_flags(FlagState::Unknown);
                        continue;
                    }
                    Mnemonic::Inc | Mnemonic::Dec => {
                        let aop = if m == Mnemonic::Inc {
                            AtomicOpKind::Inc
                        } else {
                            AtomicOpKind::Dec
                        };
                        state.mem_ver += 1;
                        state.mem_cache.clear();
                        effects.push(IrEffect::AtomicRmw {
                            lock: true,
                            op: aop,
                            addr: ea,
                            width: w,
                            src: arena.const_u64(1),
                            mem_ver_after: state.mem_ver,
                        });
                        state.set_flags(FlagState::Unknown);
                        continue;
                    }
                    Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor => {
                        let Some(src) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                            break IrTerm::Bailout(format!("lock_{m:?}_src"));
                        };
                        let aop = match m {
                            Mnemonic::Add => AtomicOpKind::Add,
                            Mnemonic::Sub => AtomicOpKind::Sub,
                            Mnemonic::And => AtomicOpKind::And,
                            Mnemonic::Or => AtomicOpKind::Or,
                            _ => AtomicOpKind::Xor,
                        };
                        state.mem_ver += 1;
                        state.mem_cache.clear();
                        effects.push(IrEffect::AtomicRmw {
                            lock: true,
                            op: aop,
                            addr: ea,
                            width: w,
                            src: arena.zext_mask(src, w),
                            mem_ver_after: state.mem_ver,
                        });
                        state.set_flags(FlagState::Unknown);
                        continue;
                    }
                    _ => break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_lock_{m:?}")),
                }
            }

            // Control-flow handlers
            match flow {
                FlowControl::UnconditionalBranch => {
                    let t = ins.near_branch_target();
                    if t == 0 {
                        break IrTerm::Bailout("zero_jmp_target".into());
                    }
                    if view.is_in_vm_section(t) {
                        state.ip = t;
                        continue;
                    }
                    if let Some(rsp_delta) = check_pure_rsp_delta(&arena, state.reg_full(ArchReg::Rsp)) {
                        let pending = state.collect_pending_caller_stores(rsp_delta);
                        break IrTerm::ExitJmp {
                            target_va: t,
                            rsp_delta,
                            final_regs: state.regs,
                            final_xmms: state.xmms,
                            pending_caller_stores: pending,
                        };
                    } else if view.is_executable_va(t) {
                        state.ip = t;
                        continue;
                    } else {
                        let bname = if entry.kind == VmEntryKind::IndirectBranchTrampoline {
                            "trampoline_jmp_dirty_rsp"
                        } else {
                            "exit_jmp_dirty_rsp"
                        };
                        break IrTerm::Bailout(bname.into());
                    }
                }
                FlowControl::ConditionalBranch => {
                    let taken_va = ins.near_branch_target();
                    let Some(cond) = eval_cond_for_mnemonic(&state, &mut arena, m) else {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_jcc_{m:?}"));
                    };
                    if let Some(c) = arena.as_const(cond) {
                        opaque_branches_folded += 1;
                        state.ip = if c != 0 { taken_va } else { next_ip };
                        continue;
                    }
                    // Symbolic conditional branch: validate exitability before allocating block slots
                    let taken_in_vm = view.is_in_vm_section(taken_va);
                    let fall_in_vm = view.is_in_vm_section(next_ip);
                    let rsp_delta_opt = check_pure_rsp_delta(&arena, state.reg_full(ArchReg::Rsp));
                    let can_route = |va: u64, in_vm: bool| -> bool {
                        in_vm
                            || rsp_delta_opt.is_some()
                            || view.is_executable_va(va)
                    };
                    if !can_route(taken_va, taken_in_vm) || !can_route(next_ip, fall_in_vm) {
                        break IrTerm::Bailout("branch_exit_dirty_rsp".into());
                    }

                    if blocks.len() + 2 > cfg.max_blocks_per_entry {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "max_blocks_exceeded".into());
                    }

                    let taken_state = state.clone();
                    let fall_state = state;

                    let mut spawn_branch_arm = |mut b_state: SymState, bva: u64, in_vm: bool, is_taken: bool| -> usize {
                        b_state.ip = bva;
                        specialize_sym_state(&mut arena, &mut b_state, cond, is_taken);
                        if in_vm || (rsp_delta_opt.is_none() && view.is_executable_va(bva)) {
                            enqueue_vm_block(b_state, &mut blocks, &mut queue, &mut state_block_cache)
                        } else {
                            let bid = blocks.len();
                            let rsp_delta = rsp_delta_opt.unwrap();
                            let pending = b_state.collect_pending_caller_stores(rsp_delta);
                            blocks.push(Some(LiftedBlock {
                                id: bid,
                                entry_va: bva,
                                effects: Vec::new(),
                                term: IrTerm::ExitJmp {
                                    target_va: bva,
                                    rsp_delta,
                                    final_regs: b_state.regs,
                                    final_xmms: b_state.xmms,
                                    pending_caller_stores: pending,
                                },
                            }));
                            bid
                        }
                    };
                    let taken_id = spawn_branch_arm(taken_state, taken_va, taken_in_vm, true);
                    let fall_id = spawn_branch_arm(fall_state, next_ip, fall_in_vm, false);

                    break IrTerm::CondBranch {
                        cond,
                        taken_block: taken_id,
                        fallthrough_block: fall_id,
                    };
                }
                FlowControl::IndirectBranch => {
                    let Some(mut target_expr) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("indirect_jmp_operand".into());
                    };
                    let rsp_delta_opt = check_pure_rsp_delta(&arena, state.reg_full(ArchReg::Rsp));
                    if let Some(va) = arena.as_const(target_expr) {
                        if view.is_in_vm_section(va) {
                            state.ip = va;
                            continue;
                        }
                        if let Some(rsp_delta) = rsp_delta_opt {
                            let pending = state.collect_pending_caller_stores(rsp_delta);
                            break IrTerm::ExitJmp {
                                target_va: va,
                                rsp_delta,
                                final_regs: state.regs,
                                final_xmms: state.xmms,
                                pending_caller_stores: pending,
                            };
                        } else if view.is_executable_va(va) {
                            state.ip = va;
                            continue;
                        } else {
                            break IrTerm::Bailout("indirect_exit_dirty_rsp".into());
                        }
                    }
                    let jmp_arch_reg = if ins.op0_kind() == OpKind::Register {
                        ArchReg::from_iced(ins.op0_register()).map(|(r, _)| r)
                    } else {
                        None
                    };
                    // Decompose multi-boolean polynomial muxes into reduced `Select` BDDs before splitting
                    if !matches!(arena.get(target_expr), ExprNode::Select { .. }) {
                        let rewritten = try_decompose_bool_mux_target(&mut arena, view, target_expr)
                            .or_else(|| hoist_bool_product_select(&mut arena, target_expr, 0));
                        if let Some(decomposed) = rewritten {
                            target_expr = decomposed;
                            if let Some(jr) = jmp_arch_reg {
                                state.regs[jr.idx()] = decomposed;
                            }
                        }
                    }
                    if matches!(arena.get(target_expr), ExprNode::Select { .. }) {
                        let specialized = specialize_select_arms(&mut arena, target_expr, 0);
                        if specialized != target_expr {
                            target_expr = specialized;
                            if let Some(jr) = jmp_arch_reg {
                                state.regs[jr.idx()] = specialized;
                            }
                        }
                    }
                    if let Some(va) = arena.as_const(target_expr) {
                        if view.is_in_vm_section(va) {
                            state.ip = va;
                            continue;
                        }
                        if let Some(rsp_delta) = rsp_delta_opt {
                            let pending = state.collect_pending_caller_stores(rsp_delta);
                            break IrTerm::ExitJmp {
                                target_va: va,
                                rsp_delta,
                                final_regs: state.regs,
                                final_xmms: state.xmms,
                                pending_caller_stores: pending,
                            };
                        } else if view.is_executable_va(va) {
                            state.ip = va;
                            continue;
                        } else {
                            break IrTerm::Bailout("indirect_exit_dirty_rsp".into());
                        }
                    }
                    // Recursively split nested `Select` trees (up to depth 4) into CFG conditional branches
                    if let Some(SelectTree::Branch { cond, if_true, if_false }) =
                        parse_select_tree(&arena, target_expr, jmp_arch_reg, 0)
                    {
                        if !all_select_leaves_valid(&if_true, view, rsp_delta_opt)
                            || !all_select_leaves_valid(&if_false, view, rsp_delta_opt)
                        {
                            break IrTerm::Bailout("select_exit_dirty_rsp".into());
                        }
                        let needed = count_select_tree_blocks(&if_true) + count_select_tree_blocks(&if_false);
                        if blocks.len() + needed > cfg.max_blocks_per_entry {
                            break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "max_blocks_exceeded".into());
                        }
                        let mut s_t = state.clone();
                        specialize_sym_state(&mut arena, &mut s_t, cond, true);
                        let mut s_f = state.clone();
                        specialize_sym_state(&mut arena, &mut s_f, cond, false);
                        let taken_id = materialize_select_node(
                            &if_true,
                            cur_ip,
                            jmp_arch_reg,
                            rsp_delta_opt,
                            &s_t,
                            view,
                            &mut arena,
                            &mut blocks,
                            &mut queue,
                            &mut state_block_cache,
                        );
                        let fall_id = materialize_select_node(
                            &if_false,
                            cur_ip,
                            jmp_arch_reg,
                            rsp_delta_opt,
                            &s_f,
                            view,
                            &mut arena,
                            &mut blocks,
                            &mut queue,
                            &mut state_block_cache,
                        );
                        break IrTerm::CondBranch {
                            cond,
                            taken_block: taken_id,
                            fallthrough_block: fall_id,
                        };
                    }
                    // Check `Add(RegIn(r), Const(disp))` relative indirect trampoline
                    if let ExprNode::Add(base_id, disp_id) = arena.get(target_expr).clone() {
                        if let (ExprNode::RegIn(_), Some(disp), Some(jr)) =
                            (arena.get(base_id).clone(), arena.as_const(disp_id), jmp_arch_reg)
                        {
                            if let Some(rsp_delta) = rsp_delta_opt {
                                break IrTerm::ExitAddJmp {
                                    reg: jr,
                                    disp: disp as i64,
                                    rsp_delta,
                                    final_regs: state.regs,
                                    final_xmms: state.xmms,
                                };
                            }
                        }
                    }
                    // Check tail-call indirect memory jump via caller stack slot: e.g. `jmp qword ptr [rsp + 8]`
                    if ins.op0_kind() == OpKind::Memory {
                        if let Some(rsp_delta) = rsp_delta_opt {
                            let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                            if let Some((StackSpace::CallerStack, slot_off)) = arena.as_stack_offset(ea) {
                                if slot_off >= rsp_delta {
                                    let pending = state.collect_pending_caller_stores(rsp_delta);
                                    break IrTerm::ExitIndirectMem {
                                        rsp_disp: slot_off - rsp_delta,
                                        rsp_delta,
                                        final_regs: state.regs,
                                        final_xmms: state.xmms,
                                        pending_caller_stores: pending,
                                    };
                                }
                            }
                        }
                    }
                    // Unresolvable target: let the original `jmp` run (exit to it).
                    if let t @ IrTerm::ExitToVm { .. } =
                        exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, String::new())
                    {
                        break t;
                    }
                    if cfg.collect_diagnostics && bailout_detail.is_none() {
                        let tag = expr_flags_tag(&arena, target_expr);
                        let brief = expr_brief(&arena, target_expr, 0);
                        let ins_str = fmt_iced_insn(&ins);
                        pending_diag_detail = Some(format!(
                            "{ins_str} | {tag} | rsp_clean={} blks={} insns={} | expr={brief}",
                            rsp_delta_opt.is_some(),
                            blocks.len(),
                            raw_vm_insns
                        ));
                    }
                    break IrTerm::Bailout("unresolved_indirect_jmp".into());
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    let target_expr = if flow == FlowControl::Call {
                        arena.const_u64(ins.near_branch_target())
                    } else {
                        match read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) {
                            Some(e) => e,
                            None => break IrTerm::Bailout("indirect_call_operand".into()),
                        }
                    };
                    let rsp_delta_opt = check_pure_rsp_delta(&arena, state.reg_full(ArchReg::Rsp));

                    if let Some(target_va) = arena.as_const(target_expr) {
                        if view.is_in_vm_section(target_va)
                            || (rsp_delta_opt.is_none() && view.is_executable_va(target_va))
                        {
                            if state.inline_depth >= cfg.max_inline_depth {
                                break IrTerm::Bailout("max_inline_depth".into());
                            }
                            let new_rsp = arena.sub_const(state.reg_full(ArchReg::Rsp), word_bytes as u64);
                            state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                            let ret_const = arena.const_u64(next_ip);
                            write_memory_expr(&mut state, &mut arena, &mut effects, new_rsp, word_bytes, ret_const);
                            state.inline_depth += 1;
                            state.ip = target_va;
                            continue;
                        }
                    }

                    if state.inline_depth == 0 {
                        if let Some(rsp_delta) = rsp_delta_opt {
                            if next_ip_reenters_vm(view, next_ip) {
                                let mid_target = if let Some(va) = arena.as_const(target_expr) {
                                    Some(MidCallTarget::DirectVa(va))
                                } else if ins.op0_kind() == OpKind::Memory {
                                    let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                                    if let Some((StackSpace::CallerStack, slot_off)) = arena.as_stack_offset(ea) {
                                        if slot_off >= rsp_delta {
                                            Some(MidCallTarget::CallerStackSlot(slot_off - rsp_delta))
                                        } else {
                                            None
                                        }
                                    } else {
                                        arena.as_const(ea).map(MidCallTarget::IndirectRipMem)
                                    }
                                } else if ins.op0_kind() == OpKind::Register {
                                    ArchReg::from_iced(ins.op0_register()).map(|(r, _)| MidCallTarget::IndirectReg(r))
                                } else {
                                    None
                                };

                                if let Some(target) = mid_target {
                                    if blocks.len() + 1 > cfg.max_blocks_per_entry {
                                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "max_blocks_exceeded".into());
                                    }
                                    let cont_id = blocks.len();
                                    blocks.push(None);
                                    let mut cont_state = SymState::new(&mut arena, next_ip, false, fake_ret_va);
                                    cont_state.cum_rsp_offset = state.cum_rsp_offset + rsp_delta;
                                    cont_state.entry_flags_clobbered = true;
                                    queue.push_back((cont_id, cont_state));
                                    let pending = state.collect_pending_caller_stores(rsp_delta);
                                    break IrTerm::MidCall {
                                        target,
                                        rsp_delta,
                                        final_regs: state.regs,
                                        final_xmms: state.xmms,
                                        pending_caller_stores: pending,
                                        cont_block: cont_id,
                                    };
                                }
                            }
                        }
                    }

                    let Some(target_va) = arena.as_const(target_expr) else {
                        break IrTerm::Bailout("unresolved_indirect_call".into());
                    };
                    let Some(rsp_delta) = rsp_delta_opt else {
                        break IrTerm::Bailout("exit_call_dirty_rsp".into());
                    };
                    let pending = state.collect_pending_caller_stores(rsp_delta);
                    break IrTerm::ExitCall {
                        target_va,
                        ret_va: next_ip,
                        rsp_delta,
                        final_regs: state.regs,
                        final_xmms: state.xmms,
                        pending_caller_stores: pending,
                    };
                }
                FlowControl::Return => {
                    let rsp = state.reg_full(ArchReg::Rsp);
                    let ret_val = read_memory_expr(view, &mut state, &mut arena, rsp, word_bytes);
                    let imm_pop = if ins.op_count() > 0 && ins.op0_kind().is_imm() {
                        ins.immediate(0)
                    } else {
                        0
                    };
                    let new_rsp = arena.add_const(rsp, (word_bytes as u64) + imm_pop);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);

                    if let Some(ret_va) = arena.as_const(ret_val) {
                        if state.inline_depth > 0 {
                            state.inline_depth -= 1;
                        }
                        if entry.is_call && ret_va == fake_ret_va && imm_pop == 0 {
                            let Some(rsp_delta) = check_pure_rsp_delta(&arena, new_rsp) else {
                                break IrTerm::Bailout("ret_dirty_rsp".into());
                            };
                            let pending = state.collect_pending_caller_stores(rsp_delta);
                            break IrTerm::ExitRet {
                                rsp_delta,
                                final_regs: state.regs,
                                final_xmms: state.xmms,
                                pending_caller_stores: pending,
                            };
                        }
                        if view.is_in_vm_section(ret_va) {
                            state.ip = ret_va;
                            continue;
                        }
                        if let Some(rsp_delta) = check_pure_rsp_delta(&arena, new_rsp) {
                            let pending = state.collect_pending_caller_stores(rsp_delta);
                            break IrTerm::ExitJmp {
                                target_va: ret_va,
                                rsp_delta,
                                final_regs: state.regs,
                                final_xmms: state.xmms,
                                pending_caller_stores: pending,
                            };
                        } else if view.is_executable_va(ret_va) {
                            state.ip = ret_va;
                            continue;
                        } else {
                            break IrTerm::Bailout("ret_exit_dirty_rsp".into());
                        }
                    }
                    if imm_pop == 0 && state.inline_depth == 0 {
                        if let (Some(rsp_delta), ExprNode::Load { addr, width, .. }) =
                            (check_pure_rsp_delta(&arena, new_rsp), arena.get(ret_val))
                        {
                            let ret_off = rsp_delta - (word_bytes as i64);
                            let lo_slot = ret_off & !7;
                            let hi_slot = (ret_off + (word_bytes as i64) - 1) & !7;
                            if *width == word_bytes
                                && ret_off >= 0
                                && arena.as_stack_offset(*addr) == Some((StackSpace::CallerStack, ret_off))
                                && !state.stack.slots.contains_key(&(StackSpace::CallerStack, lo_slot))
                                && !state.stack.slots.contains_key(&(StackSpace::CallerStack, hi_slot))
                            {
                                let pending = state.collect_pending_caller_stores(rsp_delta);
                                break IrTerm::ExitRet {
                                    rsp_delta,
                                    final_regs: state.regs,
                                    final_xmms: state.xmms,
                                    pending_caller_stores: pending,
                                };
                            }
                        }
                    }
                    if cfg.collect_diagnostics && bailout_detail.is_none() {
                        let ins_str = fmt_iced_insn(&ins);
                        let rv = expr_brief(&arena, ret_val, 0);
                        let rs = expr_brief(&arena, new_rsp, 0);
                        pending_diag_detail = Some(format!("{ins_str} | ret_val={rv} | rsp={rs}"));
                    }
                    break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "unresolved_ret".into());
                }
                FlowControl::Next => {
                    let is_non_access = matches!(
                        m,
                        Mnemonic::Lea
                            | Mnemonic::Nop
                            | Mnemonic::Prefetch
                            | Mnemonic::Prefetcht0
                            | Mnemonic::Prefetcht1
                            | Mnemonic::Prefetcht2
                            | Mnemonic::Prefetchnta
                            | Mnemonic::Prefetchw
                            | Mnemonic::Prefetchwt1
                    );
                    let has_mem_op = (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory);
                    if has_mem_op && !is_non_access && blocks.len() + 2 <= cfg.max_blocks_per_entry {
                        let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                        if arena.as_stack_offset(ea).is_none() && arena.as_const(ea).is_none() {
                            let is_xmm_mem = matches!(
                                m,
                                Mnemonic::Movups
                                    | Mnemonic::Movaps
                                    | Mnemonic::Movdqu
                                    | Mnemonic::Movdqa
                                    | Mnemonic::Punpcklqdq
                                    | Mnemonic::Punpckhqdq
                                    | Mnemonic::Pshufd
                            );
                            let mem_writes = ins.op0_kind() == OpKind::Memory
                                && !matches!(m, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt | Mnemonic::Push);
                            let w = ins.memory_size().size() as u8;
                            let mut handled_branchlessly = false;
                            if !is_xmm_mem && (1..=8).contains(&w) {
                                if let Some((_, ea1, ea0)) = try_resolve_select_mem_pair(&mut arena, ea) {
                                    handled_branchlessly = if !mem_writes {
                                        is_pure_nonfaulting_read_addr(&arena, view, ea1, w)
                                            && is_pure_nonfaulting_read_addr(&arena, view, ea0, w)
                                    } else {
                                        is_internal_stack_addr(&arena, ea1).is_some()
                                            && is_internal_stack_addr(&arena, ea0).is_some()
                                    };
                                }
                            }
                            if !handled_branchlessly {
                                if let Some(cond) = try_split_select_mem_addr(&mut arena, ea) {
                                    let mut s_t = state.clone();
                                    s_t.ip = cur_ip;
                                    specialize_sym_state(&mut arena, &mut s_t, cond, true);
                                    let mut s_f = state.clone();
                                    s_f.ip = cur_ip;
                                    specialize_sym_state(&mut arena, &mut s_f, cond, false);
                                    let ea_t = eval_mem_ea(&s_t, &mut arena, view.bitness, &ins, next_ip);
                                    let ea_f = eval_mem_ea(&s_f, &mut arena, view.bitness, &ins, next_ip);
                                    if ea_t != ea && ea_f != ea {
                                        let taken_id = enqueue_vm_block(
                                            s_t,
                                            &mut blocks,
                                            &mut queue,
                                            &mut state_block_cache,
                                        );
                                        let fall_id = enqueue_vm_block(
                                            s_f,
                                            &mut blocks,
                                            &mut queue,
                                            &mut state_block_cache,
                                        );
                                        break IrTerm::CondBranch {
                                            cond,
                                            taken_block: taken_id,
                                            fallthrough_block: fall_id,
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
                other => break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_flow_{other:?}_{m:?}")),
            }

            // Regular instructions (FlowControl::Next)
            match m {
                Mnemonic::Nop | Mnemonic::Pause | Mnemonic::Endbr64 | Mnemonic::Endbr32 => {}
                Mnemonic::Clc => state.set_flags(FlagState::CarryExpr(arena.const_u64(0))),
                Mnemonic::Stc => state.set_flags(FlagState::CarryExpr(arena.const_u64(1))),
                Mnemonic::Cld | Mnemonic::Std => {}

                Mnemonic::Mov => {
                    if view.bitness == 64
                        && ins.op1_kind() == OpKind::Register
                        && ins.op1_register() == Register::CR8
                    {
                        let val = arena.cr8_read(state.cr8_ver);
                        if !write_operand(
                            &mut state,
                            &mut arena,
                            &mut effects,
                            view.bitness,
                            &ins,
                            next_ip,
                            0,
                            val,
                        ) {
                            break IrTerm::Bailout("mov_cr8_dst".into());
                        }
                    } else if view.bitness == 64
                        && ins.op0_kind() == OpKind::Register
                        && ins.op0_register() == Register::CR8
                    {
                        let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                            break IrTerm::Bailout("mov_cr8_src".into());
                        };
                        state.cr8_ver += 1;
                        effects.push(IrEffect::WriteCr8 {
                            val,
                            cr8_ver_after: state.cr8_ver,
                        });
                    } else {
                        let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                            break IrTerm::Bailout("mov_src".into());
                        };
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, val) {
                            break IrTerm::Bailout("mov_dst".into());
                        }
                    }
                }
                Mnemonic::Movzx => {
                    let src_w = op_width_bytes(&ins, view.bitness, 1);
                    let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("movzx_src".into());
                    };
                    let masked = arena.zext_mask(val, src_w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, masked) {
                        break IrTerm::Bailout("movzx_dst".into());
                    }
                }
                Mnemonic::Movsx | Mnemonic::Movsxd => {
                    let src_w = op_width_bytes(&ins, view.bitness, 1);
                    let dst_w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("movsx_src".into());
                    };
                    let ext = arena.sext(val, src_w * 8);
                    let final_v = arena.zext_mask(ext, dst_w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, final_v) {
                        break IrTerm::Bailout("movsx_dst".into());
                    }
                }
                Mnemonic::Cdqe => {
                    let eax = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, RegSlice::Low32);
                    let r = arena.sext(eax, 32);
                    state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Full64, r);
                }
                Mnemonic::Cwde => {
                    let ax_v = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, RegSlice::Low16);
                    let r = arena.sext(ax_v, 16);
                    state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Low32, r);
                }
                Mnemonic::Cdq => {
                    let eax = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, RegSlice::Low32);
                    let s = arena.sext(eax, 32);
                    let sign = arena.shr_const(s, 32);
                    state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Low32, sign);
                }
                Mnemonic::Cqo => {
                    let rax_v = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, RegSlice::Full64);
                    let sh = arena.const_u64(63);
                    let sign = arena.sar(rax_v, sh);
                    state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Full64, sign);
                }
                Mnemonic::Bswap => {
                    if ins.op0_kind() != OpKind::Register {
                        break IrTerm::Bailout("bswap_op".into());
                    }
                    let Some((ar, sl)) = ArchReg::from_iced(ins.op0_register()) else {
                        break IrTerm::Bailout("bswap_reg".into());
                    };
                    let v = state.read_reg(&mut arena, view.bitness, ar, sl);
                    let res = match (arena.as_const(v), sl) {
                        (Some(c), RegSlice::Low32) => arena.const_u64((c as u32).swap_bytes() as u64),
                        (Some(c), RegSlice::Full64) => arena.const_u64(c.swap_bytes()),
                        _ => arena.opaque(),
                    };
                    state.write_reg(&mut arena, ar, sl, res);
                }
                Mnemonic::Lea => {
                    let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, ea) {
                        break IrTerm::Bailout("lea_dst".into());
                    }
                }
                Mnemonic::Xchg => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(v0) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("xchg_op0".into());
                    };
                    let Some(v1) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("xchg_op1".into());
                    };
                    let m0 = arena.zext_mask(v0, w);
                    let m1 = arena.zext_mask(v1, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, m1)
                        || !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 1, m0)
                    {
                        break IrTerm::Bailout("xchg_write".into());
                    }
                }
                Mnemonic::Push => {
                    let w = if ins.op0_kind() == OpKind::Register {
                        op_width_bytes(&ins, view.bitness, 0).max(word_bytes)
                    } else {
                        word_bytes
                    };
                    let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("push_op".into());
                    };
                    let new_rsp = arena.sub_const(state.reg_full(ArchReg::Rsp), w as u64);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                    write_memory_expr(&mut state, &mut arena, &mut effects, new_rsp, w, val);
                }
                Mnemonic::Pop => {
                    let w = op_width_bytes(&ins, view.bitness, 0).max(word_bytes);
                    let old_rsp = state.reg_full(ArchReg::Rsp);
                    let val = read_memory_expr(view, &mut state, &mut arena, old_rsp, w);
                    let new_rsp = arena.add_const(old_rsp, w as u64);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, val) {
                        break IrTerm::Bailout("pop_dst".into());
                    }
                }
                Mnemonic::Pushfq | Mnemonic::Pushfd => {
                    let rfl = arena.opaque();
                    if !matches!(state.flags, FlagState::Unknown)
                        && (!matches!(state.flags, FlagState::Entry) || !state.entry_flags_clobbered)
                    {
                        if state.saved_rflags.len() >= 8 {
                            state.saved_rflags.remove(0);
                        }
                        state.saved_rflags.push((rfl, state.flags.clone()));
                    }
                    let new_rsp = arena.sub_const(state.reg_full(ArchReg::Rsp), word_bytes as u64);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                    write_memory_expr(&mut state, &mut arena, &mut effects, new_rsp, word_bytes, rfl);
                }
                Mnemonic::Popfq | Mnemonic::Popfd => {
                    let old_rsp = state.reg_full(ArchReg::Rsp);
                    let val = read_memory_expr(view, &mut state, &mut arena, old_rsp, word_bytes);
                    let new_rsp = arena.add_const(old_rsp, word_bytes as u64);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                    let restored = state
                        .saved_rflags
                        .iter()
                        .rev()
                        .find(|(id, _)| *id == val)
                        .map(|(_, fl)| fl.clone());
                    match restored {
                        Some(FlagState::Entry) if !state.entry_flags_clobbered => {
                            state.set_flags(FlagState::Entry);
                        }
                        Some(fl) if !matches!(fl, FlagState::Entry) => {
                            state.set_flags(fl);
                        }
                        _ => {
                            state.set_flags(FlagState::Unknown);
                        }
                    }
                }

                // Conditional Moves & SetCC
                Mnemonic::Cmova
                | Mnemonic::Cmovae
                | Mnemonic::Cmovb
                | Mnemonic::Cmovbe
                | Mnemonic::Cmove
                | Mnemonic::Cmovne
                | Mnemonic::Cmovg
                | Mnemonic::Cmovge
                | Mnemonic::Cmovl
                | Mnemonic::Cmovle
                | Mnemonic::Cmovs
                | Mnemonic::Cmovns
                | Mnemonic::Cmovo
                | Mnemonic::Cmovno => {
                    let Some(cond) = eval_cond_for_mnemonic(&state, &mut arena, m) else {
                        break IrTerm::Bailout(format!("cmov_unknown_flags_{m:?}"));
                    };
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(dst_v) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("cmov_dst_read".into());
                    };
                    let Some(src_v) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("cmov_src_read".into());
                    };
                    let m_src = arena.zext_mask(src_v, w);
                    let m_dst = arena.zext_mask(dst_v, w);
                    let sel = arena.select(cond, m_src, m_dst);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, sel) {
                        break IrTerm::Bailout("cmov_write".into());
                    }
                }
                Mnemonic::Seta
                | Mnemonic::Setae
                | Mnemonic::Setb
                | Mnemonic::Setbe
                | Mnemonic::Sete
                | Mnemonic::Setne
                | Mnemonic::Setg
                | Mnemonic::Setge
                | Mnemonic::Setl
                | Mnemonic::Setle
                | Mnemonic::Sets
                | Mnemonic::Setns
                | Mnemonic::Seto
                | Mnemonic::Setno => {
                    let Some(cond) = eval_cond_for_mnemonic(&state, &mut arena, m) else {
                        break IrTerm::Bailout(format!("setcc_unknown_flags_{m:?}"));
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, cond) {
                        break IrTerm::Bailout("setcc_write".into());
                    }
                }

                // Comparisons
                Mnemonic::Cmp => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("cmp_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("cmp_rhs".into());
                    };
                    let mrhs = if ins.op1_kind().is_imm() && w < 8 {
                        arena.zext_mask(rhs, w)
                    } else {
                        rhs
                    };
                    state.set_flags(FlagState::SubCmp { lhs, rhs: mrhs, width: w });
                }
                Mnemonic::Test => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("test_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("test_rhs".into());
                    };
                    let ml = arena.zext_mask(lhs, w);
                    let mr = arena.zext_mask(rhs, w);
                    let val = arena.and(ml, mr);
                    state.set_flags(FlagState::TestBitwise { val, width: w });
                }

                // ALU binary / unary
                Mnemonic::Add | Mnemonic::Adc => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("add_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("add_rhs".into());
                    };
                    let mut sum_rhs = rhs;
                    if m == Mnemonic::Adc {
                        match state.known_cf(&mut arena) {
                            Some(false) => {}
                            Some(true) => sum_rhs = arena.add_const(rhs, 1),
                            None => {
                                let res = arena.opaque();
                                if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                    break IrTerm::Bailout("adc_write".into());
                                }
                                state.set_flags(FlagState::Unknown);
                                continue;
                            }
                        }
                    }
                    let sum = arena.add(lhs, sum_rhs);
                    let res = arena.zext_mask(sum, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("add_write".into());
                    }
                    state.set_flags(FlagState::Add { lhs, rhs: sum_rhs, res, width: w });
                }
                Mnemonic::Sub | Mnemonic::Sbb => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("sub_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("sub_rhs".into());
                    };
                    let mut sub_rhs = rhs;
                    if m == Mnemonic::Sbb {
                        match state.known_cf(&mut arena) {
                            Some(false) => {}
                            Some(true) => sub_rhs = arena.add_const(rhs, 1),
                            None => {
                                if let Some(cf_expr) = state.eval_cond_code(&mut arena, ConditionCode::b) {
                                    if ins.op0_kind() == OpKind::Register
                                        && ins.op1_kind() == OpKind::Register
                                        && ins.op0_register() == ins.op1_register()
                                    {
                                        // sbb reg, reg -> -CF
                                        let neg_cf = arena.neg(cf_expr);
                                        let res = arena.zext_mask(neg_cf, w);
                                        let _ = write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res);
                                        state.set_flags(FlagState::Unknown);
                                        continue;
                                    }
                                }
                                let res = arena.opaque();
                                if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                    break IrTerm::Bailout("sbb_write".into());
                                }
                                state.set_flags(FlagState::Unknown);
                                continue;
                            }
                        }
                    }
                    let diff = arena.sub(lhs, sub_rhs);
                    let res = arena.zext_mask(diff, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("sub_write".into());
                    }
                    state.set_flags(FlagState::SubCmp { lhs, rhs: sub_rhs, width: w });
                }
                Mnemonic::Inc | Mnemonic::Dec => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("incdec_op".into());
                    };
                    let res_full = if m == Mnemonic::Inc {
                        arena.add_const(lhs, 1)
                    } else {
                        arena.sub_const(lhs, 1)
                    };
                    let res = arena.zext_mask(res_full, w);
                    let prev_cf = state.known_cf(&mut arena);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("incdec_write".into());
                    }
                    state.set_flags(FlagState::IncDec { res, cf: prev_cf, width: w });
                }
                Mnemonic::Neg => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("neg_op".into());
                    };
                    let zero = arena.const_u64(0);
                    let neg_v = arena.neg(lhs);
                    let res = arena.zext_mask(neg_v, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("neg_write".into());
                    }
                    state.set_flags(FlagState::SubCmp { lhs: zero, rhs: lhs, width: w });
                }
                Mnemonic::Not => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("not_op".into());
                    };
                    let not_v = arena.not(lhs);
                    let res = arena.zext_mask(not_v, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("not_write".into());
                    }
                }
                Mnemonic::And => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("and_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("and_rhs".into());
                    };
                    // Detect `and rsp, -16` stack frame alignment!
                    if ins.op0_kind() == OpKind::Register
                        && ArchReg::from_iced(ins.op0_register()).is_some_and(|(r, _)| r == ArchReg::Rsp)
                        && arena.as_const(rhs).is_some_and(|m_val| {
                            let s = m_val as i64;
                            s < 0 && s >= -256 && s.abs().count_ones() == 1
                        })
                        && arena.as_stack_offset(lhs).is_some()
                    {
                        let aid = state.next_aligned_id;
                        state.next_aligned_id += 1;
                        if let (Some((parent, poff)), Some(mask)) = (arena.as_stack_offset(lhs), arena.as_const(rhs)) {
                            debug_assert_eq!(state.aligned_defs.len(), aid as usize);
                            state.aligned_defs.push((parent, poff, mask));
                        }
                        let abase = arena.aligned_base(aid);
                        state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, abase);
                        state.set_flags(FlagState::Unknown);
                        continue;
                    }
                    let and_v = arena.and(lhs, rhs);
                    let res = arena.zext_mask(and_v, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("and_write".into());
                    }
                    state.set_flags(FlagState::TestBitwise { val: res, width: w });
                }
                Mnemonic::Or => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("or_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("or_rhs".into());
                    };
                    let or_v = arena.or(lhs, rhs);
                    let res = arena.zext_mask(or_v, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("or_write".into());
                    }
                    state.set_flags(FlagState::TestBitwise { val: res, width: w });
                }
                Mnemonic::Xor => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let res = if ins.op0_kind() == OpKind::Register
                        && ins.op1_kind() == OpKind::Register
                        && ins.op0_register() == ins.op1_register()
                    {
                        arena.const_u64(0)
                    } else {
                        let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                            break IrTerm::Bailout("xor_lhs".into());
                        };
                        let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                            break IrTerm::Bailout("xor_rhs".into());
                        };
                        let xor_v = arena.xor(lhs, rhs);
                        arena.zext_mask(xor_v, w)
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("xor_write".into());
                    }
                    state.set_flags(FlagState::TestBitwise { val: res, width: w });
                }
                Mnemonic::Imul => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    match ins.op_count() {
                        1 => {
                            let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                                break IrTerm::Bailout("imul1_op".into());
                            };
                            let rax_v = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, if w == 8 { RegSlice::Full64 } else { RegSlice::Low32 });
                            if let (Some(a), Some(b)) = (arena.as_const(rax_v), arena.as_const(rhs)) {
                                if w == 8 {
                                    let prod = (a as i64 as i128).wrapping_mul(b as i64 as i128);
                                    let lo = arena.const_u64(prod as u64);
                                    let hi = arena.const_u64((prod >> 64) as u64);
                                    state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Full64, lo);
                                    state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Full64, hi);
                                } else {
                                    let prod = (a as i32 as i64).wrapping_mul(b as i32 as i64);
                                    let lo = arena.const_u64((prod as u32) as u64);
                                    let hi = arena.const_u64(((prod >> 32) as u32) as u64);
                                    state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Low32, lo);
                                    state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Low32, hi);
                                }
                            } else {
                                let mv = arena.mul(rax_v, rhs);
                                let lo = arena.zext_mask(mv, w);
                                let hi = arena.opaque();
                                let sl = if w == 8 { RegSlice::Full64 } else { RegSlice::Low32 };
                                state.write_reg(&mut arena, ArchReg::Rax, sl, lo);
                                state.write_reg(&mut arena, ArchReg::Rdx, sl, hi);
                            }
                        }
                        2 => {
                            let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                                break IrTerm::Bailout("imul2_lhs".into());
                            };
                            let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                                break IrTerm::Bailout("imul2_rhs".into());
                            };
                            let mv = arena.mul(lhs, rhs);
                            let res = arena.zext_mask(mv, w);
                            if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                break IrTerm::Bailout("imul2_write".into());
                            }
                        }
                        3 => {
                            let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                                break IrTerm::Bailout("imul3_lhs".into());
                            };
                            let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 2) else {
                                break IrTerm::Bailout("imul3_rhs".into());
                            };
                            let mv = arena.mul(lhs, rhs);
                            let res = arena.zext_mask(mv, w);
                            if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                break IrTerm::Bailout("imul3_write".into());
                            }
                        }
                        _ => break IrTerm::Bailout("imul_opcount".into()),
                    }
                    state.set_flags(FlagState::Unknown);
                }
                Mnemonic::Mul => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("mul_op".into());
                    };
                    let sl = if w == 8 { RegSlice::Full64 } else { RegSlice::Low32 };
                    let rax_v = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, sl);
                    if let (Some(a), Some(b)) = (arena.as_const(rax_v), arena.as_const(rhs)) {
                        if w == 8 {
                            let prod = (a as u128) * (b as u128);
                            let lo = arena.const_u64(prod as u64);
                            let hi = arena.const_u64((prod >> 64) as u64);
                            state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Full64, lo);
                            state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Full64, hi);
                        } else {
                            let prod = ((a as u32) as u64) * ((b as u32) as u64);
                            let lo = arena.const_u64((prod as u32) as u64);
                            let hi = arena.const_u64((prod >> 32) as u64);
                            state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Low32, lo);
                            state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Low32, hi);
                        }
                    } else {
                        let mv = arena.mul(rax_v, rhs);
                        let lo = arena.zext_mask(mv, w);
                        let hi = arena.opaque();
                        state.write_reg(&mut arena, ArchReg::Rax, sl, lo);
                        state.write_reg(&mut arena, ArchReg::Rdx, sl, hi);
                    }
                    state.set_flags(FlagState::Unknown);
                }
                Mnemonic::Shl | Mnemonic::Sal | Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Rol | Mnemonic::Ror => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let bits = (w as u32) * 8;
                    let mask_cnt = if w == 8 { 63u64 } else { 31u64 };
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("shift_lhs".into());
                    };
                    let cnt_raw = if ins.op_count() == 1 {
                        arena.const_u64(1)
                    } else {
                        match read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) {
                            Some(c) => c,
                            None => break IrTerm::Bailout("shift_cnt".into()),
                        }
                    };
                    let cnt_masked = arena.and_const(cnt_raw, mask_cnt);
                    let res = if w == 8 {
                        match m {
                            Mnemonic::Shl | Mnemonic::Sal => arena.shl(lhs, cnt_masked),
                            Mnemonic::Shr => arena.shr(lhs, cnt_masked),
                            Mnemonic::Sar => arena.sar(lhs, cnt_masked),
                            Mnemonic::Rol => arena.rol(lhs, cnt_masked),
                            _ => arena.ror(lhs, cnt_masked),
                        }
                    } else if let (Some(lv), Some(cv)) = (arena.as_const(lhs), arena.as_const(cnt_masked)) {
                        let c = (cv & 31) as u32;
                        let r = match (m, w) {
                            (Mnemonic::Shl | Mnemonic::Sal, _) => lv.wrapping_shl(c),
                            (Mnemonic::Shr, 4) => ((lv as u32).wrapping_shr(c)) as u64,
                            (Mnemonic::Shr, 2) => ((lv as u16).wrapping_shr(c)) as u64,
                            (Mnemonic::Shr, 1) => ((lv as u8).wrapping_shr(c)) as u64,
                            (Mnemonic::Sar, 4) => ((lv as i32).wrapping_shr(c)) as u32 as u64,
                            (Mnemonic::Sar, 2) => ((lv as i16).wrapping_shr(c)) as u16 as u64,
                            (Mnemonic::Sar, 1) => ((lv as i8).wrapping_shr(c)) as u8 as u64,
                            (Mnemonic::Rol, 4) => (lv as u32).rotate_left(c) as u64,
                            (Mnemonic::Rol, 2) => (lv as u16).rotate_left(c) as u64,
                            (Mnemonic::Rol, 1) => (lv as u8).rotate_left(c) as u64,
                            (Mnemonic::Ror, 4) => (lv as u32).rotate_right(c) as u64,
                            (Mnemonic::Ror, 2) => (lv as u16).rotate_right(c) as u64,
                            (Mnemonic::Ror, 1) => (lv as u8).rotate_right(c) as u64,
                            _ => lv,
                        };
                        let rc = arena.const_u64(r);
                        arena.zext_mask(rc, w)
                    } else {
                        match m {
                            Mnemonic::Shl | Mnemonic::Sal => {
                                let sv = arena.shl(lhs, cnt_masked);
                                arena.zext_mask(sv, w)
                            }
                            Mnemonic::Shr => {
                                let ml = arena.zext_mask(lhs, w);
                                arena.shr(ml, cnt_masked)
                            }
                            Mnemonic::Sar => {
                                let sl = arena.sext(lhs, bits as u8);
                                let sv = arena.sar(sl, cnt_masked);
                                arena.zext_mask(sv, w)
                            }
                            _ => arena.opaque(),
                        }
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("shift_write".into());
                    }
                    state.set_flags(FlagState::TestBitwise { val: res, width: w });
                }

                // Bit test/scan & modify
                Mnemonic::Bt => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("bt_lhs".into());
                    };
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("bt_rhs".into());
                    };
                    let bit_idx = if w == 8 { 63 } else { 31 };
                    let b_masked = arena.and_const(rhs, bit_idx);
                    let shifted = arena.shr(lhs, b_masked);
                    let bit = arena.and_const(shifted, 1);
                    state.set_flags(FlagState::CarryExpr(bit));
                }
                Mnemonic::Btr | Mnemonic::Bts | Mnemonic::Btc => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    if !matches!(w, 2 | 4 | 8) {
                        break IrTerm::Bailout("bt_width".into());
                    }
                    let bits = (w as u64) * 8;
                    let Some(rhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("bt_rhs".into());
                    };
                    let idx_expr = if ins.op0_kind() == OpKind::Memory {
                        let Some(rc) = arena.as_const(rhs) else {
                            break IrTerm::Bailout("bt_mem_reg".into());
                        };
                        if ins.op1_kind().is_imm() {
                            arena.const_u64(rc & (bits - 1))
                        } else if rc < bits {
                            arena.const_u64(rc)
                        } else {
                            break IrTerm::Bailout("bt_mem_reg".into());
                        }
                    } else {
                        arena.and_const(rhs, bits - 1)
                    };
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("bt_lhs".into());
                    };
                    let lhs_m = arena.zext_mask(lhs, w);
                    let bit_mask = if let Some(b) = arena.as_const(idx_expr) {
                        arena.const_u64(1u64 << b)
                    } else {
                        let one = arena.const_u64(1);
                        arena.shl(one, idx_expr)
                    };
                    let new_val = match m {
                        Mnemonic::Btr => {
                            let nb = arena.not(bit_mask);
                            let cleared = arena.and(lhs_m, nb);
                            arena.zext_mask(cleared, w)
                        }
                        Mnemonic::Bts => {
                            let set = arena.or(lhs_m, bit_mask);
                            arena.zext_mask(set, w)
                        }
                        _ => {
                            let tog = arena.xor(lhs_m, bit_mask);
                            arena.zext_mask(tog, w)
                        }
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, new_val) {
                        break IrTerm::Bailout("bt_write".into());
                    }
                    let shifted = if let Some(b) = arena.as_const(idx_expr) {
                        arena.shr_const(lhs_m, b)
                    } else {
                        arena.shr(lhs_m, idx_expr)
                    };
                    let old_bit = arena.and_const(shifted, 1);
                    state.set_flags(FlagState::CarryExpr(old_bit));
                }
                Mnemonic::Shld | Mnemonic::Shrd => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    if !matches!(w, 2 | 4 | 8) {
                        break IrTerm::Bailout("shld_width".into());
                    }
                    let bits = (w as u64) * 8;
                    let mask_cnt = if w == 8 { 63u64 } else { 31u64 };
                    let Some(cnt_raw) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 2) else {
                        break IrTerm::Bailout("shld_cnt".into());
                    };
                    let Some(cnt_v) = arena.as_const(cnt_raw) else {
                        break IrTerm::Bailout("shld_nonconst_cnt".into());
                    };
                    let c = cnt_v & mask_cnt;
                    if c == 0 {
                        continue;
                    }
                    if w == 2 && c > 16 {
                        break IrTerm::Bailout("shld_cnt16".into());
                    }
                    let Some(dst_v) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("shld_dst".into());
                    };
                    let Some(src_v) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("shld_src".into());
                    };
                    let dm = arena.zext_mask(dst_v, w);
                    let sm = arena.zext_mask(src_v, w);
                    let res = if c == bits {
                        sm
                    } else if m == Mnemonic::Shld {
                        let hi = arena.shl_const(dm, c);
                        let lo = arena.shr_const(sm, bits - c);
                        let comb = arena.or(hi, lo);
                        arena.zext_mask(comb, w)
                    } else {
                        let lo = arena.shr_const(dm, c);
                        let hi = arena.shl_const(sm, bits - c);
                        let comb = arena.or(lo, hi);
                        arena.zext_mask(comb, w)
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("shld_write".into());
                    }
                    state.set_flags(FlagState::TestBitwise { val: res, width: w });
                }
                Mnemonic::Bsf | Mnemonic::Bsr => {
                    let w = op_width_bytes(&ins, view.bitness, 1);
                    let Some(src) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("bitscan_src".into());
                    };
                    let masked = arena.zext_mask(src, w);
                    if let Some(v) = arena.as_const(masked) {
                        if v == 0 {
                            state.set_flags(FlagState::TestBitwise { val: arena.const_u64(0), width: w });
                        } else {
                            let bit = if m == Mnemonic::Bsf {
                                v.trailing_zeros() as u64
                            } else {
                                63 - v.leading_zeros() as u64
                            };
                            let b = arena.const_u64(bit);
                            let _ = write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, b);
                            state.set_flags(FlagState::TestBitwise { val: masked, width: w });
                        }
                    } else {
                        let o = arena.opaque();
                        let _ = write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, o);
                        state.set_flags(FlagState::Unknown);
                    }
                }

                // 16-byte XMM vector stack context save/restore/copy + zeroing + unpack/shuffle/scalar
                Mnemonic::Movups | Mnemonic::Movaps | Mnemonic::Movdqu | Mnemonic::Movdqa => {
                    match (ins.op0_kind(), ins.op1_kind()) {
                        (OpKind::Register, OpKind::Register | OpKind::Memory) => {
                            let Some(d) = ArchReg::xmm_index(ins.op0_register()) else {
                                break IrTerm::Bailout("xmm_load_dst".into());
                            };
                            let Some(pair) = read_xmm_pair(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                                break IrTerm::Bailout("xmm_load_src".into());
                            };
                            state.xmms[d as usize] = pair;
                        }
                        (OpKind::Memory, OpKind::Register) => {
                            let Some(s) = ArchReg::xmm_index(ins.op1_register()) else {
                                break IrTerm::Bailout("xmm_store_src".into());
                            };
                            let xval = state.xmms[s as usize];
                            let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                            if let Some((space, off)) = arena.as_stack_offset(ea) {
                                state.stack.write_xmm(&mut arena, space, off, xval, state.mem_ver);
                                if space == StackSpace::CallerStack && off >= 0 {
                                    state.mem_ver += 1;
                                }
                            } else {
                                write_memory_expr(&mut state, &mut arena, &mut effects, ea, 8, xval.0);
                                let ea8 = arena.add_const(ea, 8);
                                write_memory_expr(&mut state, &mut arena, &mut effects, ea8, 8, xval.1);
                            }
                        }
                        _ => break IrTerm::Bailout("xmm_mov_ops".into()),
                    }
                }
                Mnemonic::Punpcklqdq | Mnemonic::Punpckhqdq => {
                    let (Some(d), Some(src)) = (
                        (ins.op0_kind() == OpKind::Register)
                            .then(|| ArchReg::xmm_index(ins.op0_register()))
                            .flatten(),
                        read_xmm_pair(view, &mut state, &mut arena, &ins, next_ip, 1),
                    ) else {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_{m:?}"));
                    };
                    if m == Mnemonic::Punpcklqdq {
                        state.xmms[d as usize].1 = src.0;
                    } else {
                        let old_hi = state.xmms[d as usize].1;
                        state.xmms[d as usize] = (old_hi, src.1);
                    }
                }
                Mnemonic::Pshufd => {
                    let (Some(d), Some(src)) = (
                        (ins.op0_kind() == OpKind::Register)
                            .then(|| ArchReg::xmm_index(ins.op0_register()))
                            .flatten(),
                        read_xmm_pair(view, &mut state, &mut arena, &ins, next_ip, 1),
                    ) else {
                        break IrTerm::Bailout("unsupported_Pshufd".into());
                    };
                    let imm = ins.immediate8();
                    if imm == 0xE4 {
                        state.xmms[d as usize] = src;
                    } else {
                        let mut lane = |idx: u8| -> ExprId {
                            let q = if (idx & 2) == 0 { src.0 } else { src.1 };
                            if (idx & 1) == 0 {
                                arena.and_const(q, 0xFFFF_FFFF)
                            } else {
                                arena.shr_const(q, 32)
                            }
                        };
                        let l0 = lane(imm & 3);
                        let l1 = lane((imm >> 2) & 3);
                        let l2 = lane((imm >> 4) & 3);
                        let l3 = lane((imm >> 6) & 3);
                        let l1s = arena.shl_const(l1, 32);
                        let l3s = arena.shl_const(l3, 32);
                        state.xmms[d as usize] = (arena.or(l0, l1s), arena.or(l2, l3s));
                    }
                }
                Mnemonic::Movsd => {
                    if ins.op_count() != 2 {
                        break IrTerm::Bailout("unsupported_Movsd".into());
                    }
                    match (ins.op0_kind(), ins.op1_kind()) {
                        (OpKind::Register, OpKind::Register) => {
                            let (Some(d), Some(s)) = (
                                ArchReg::xmm_index(ins.op0_register()),
                                ArchReg::xmm_index(ins.op1_register()),
                            ) else {
                                break IrTerm::Bailout("unsupported_Movsd".into());
                            };
                            state.xmms[d as usize].0 = state.xmms[s as usize].0;
                        }
                        (OpKind::Register, OpKind::Memory) => {
                            let Some(d) = ArchReg::xmm_index(ins.op0_register()) else {
                                break IrTerm::Bailout("unsupported_Movsd".into());
                            };
                            let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                            let v = read_memory_expr(view, &mut state, &mut arena, ea, 8);
                            let z = arena.const_u64(0);
                            state.xmms[d as usize] = (v, z);
                        }
                        (OpKind::Memory, OpKind::Register) => {
                            let Some(s) = ArchReg::xmm_index(ins.op1_register()) else {
                                break IrTerm::Bailout("unsupported_Movsd".into());
                            };
                            let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                            let v = state.xmms[s as usize].0;
                            write_memory_expr(&mut state, &mut arena, &mut effects, ea, 8, v);
                        }
                        _ => break IrTerm::Bailout("unsupported_Movsd".into()),
                    }
                }
                Mnemonic::Movss => {
                    match (ins.op0_kind(), ins.op1_kind()) {
                        (OpKind::Register, OpKind::Register) => {
                            let (Some(d), Some(s)) = (
                                ArchReg::xmm_index(ins.op0_register()),
                                ArchReg::xmm_index(ins.op1_register()),
                            ) else {
                                break IrTerm::Bailout("unsupported_Movss".into());
                            };
                            let s_lo32 = arena.and_const(state.xmms[s as usize].0, 0xFFFF_FFFF);
                            let d_hi32 = arena.and_const(state.xmms[d as usize].0, !0xFFFF_FFFFu64);
                            state.xmms[d as usize].0 = arena.or(d_hi32, s_lo32);
                        }
                        (OpKind::Register, OpKind::Memory) => {
                            let Some(d) = ArchReg::xmm_index(ins.op0_register()) else {
                                break IrTerm::Bailout("unsupported_Movss".into());
                            };
                            let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                            let v = read_memory_expr(view, &mut state, &mut arena, ea, 4);
                            let z = arena.const_u64(0);
                            state.xmms[d as usize] = (arena.zext_mask(v, 4), z);
                        }
                        (OpKind::Memory, OpKind::Register) => {
                            let Some(s) = ArchReg::xmm_index(ins.op1_register()) else {
                                break IrTerm::Bailout("unsupported_Movss".into());
                            };
                            let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                            let v = arena.zext_mask(state.xmms[s as usize].0, 4);
                            write_memory_expr(&mut state, &mut arena, &mut effects, ea, 4, v);
                        }
                        _ => break IrTerm::Bailout("unsupported_Movss".into()),
                    }
                }
                Mnemonic::Movlhps | Mnemonic::Movhlps => {
                    if ins.op0_kind() == OpKind::Register && ins.op1_kind() == OpKind::Register {
                        if let (Some(d), Some(s)) = (
                            ArchReg::xmm_index(ins.op0_register()),
                            ArchReg::xmm_index(ins.op1_register()),
                        ) {
                            if m == Mnemonic::Movlhps {
                                state.xmms[d as usize].1 = state.xmms[s as usize].0;
                            } else {
                                state.xmms[d as usize].0 = state.xmms[s as usize].1;
                            }
                            continue;
                        }
                    }
                    break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_{m:?}"));
                }
                Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd => {
                    if ins.op0_kind() == OpKind::Register && ins.op1_kind() == OpKind::Register {
                        if let (Some(d), Some(s)) = (ArchReg::xmm_index(ins.op0_register()), ArchReg::xmm_index(ins.op1_register())) {
                            if d == s {
                                let z = arena.const_u64(0);
                                state.xmms[d as usize] = (z, z);
                            } else {
                                let a = state.xmms[d as usize];
                                let b = state.xmms[s as usize];
                                state.xmms[d as usize] = (arena.xor(a.0, b.0), arena.xor(a.1, b.1));
                            }
                            continue;
                        }
                    }
                    break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_{m:?}"));
                }
                Mnemonic::Movq | Mnemonic::Movd => {
                    let w = if m == Mnemonic::Movq { 8u8 } else { 4u8 };
                    if ins.op0_kind() == OpKind::Register {
                        if let Some(d) = ArchReg::xmm_index(ins.op0_register()) {
                            let v_opt = if ins.op1_kind() == OpKind::Register {
                                if let Some(s) = ArchReg::xmm_index(ins.op1_register()) {
                                    Some(state.xmms[s as usize].0)
                                } else {
                                    read_operand(view, &mut state, &mut arena, &ins, next_ip, 1)
                                }
                            } else {
                                read_operand(view, &mut state, &mut arena, &ins, next_ip, 1)
                            };
                            let Some(v) = v_opt else {
                                break IrTerm::Bailout("movq_src".into());
                            };
                            let z = arena.const_u64(0);
                            state.xmms[d as usize] = (arena.zext_mask(v, w), z);
                            continue;
                        }
                    }
                    if ins.op1_kind() == OpKind::Register {
                        if let Some(s) = ArchReg::xmm_index(ins.op1_register()) {
                            let lo = arena.zext_mask(state.xmms[s as usize].0, w);
                            if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, lo) {
                                break IrTerm::Bailout("movq_dst".into());
                            }
                            continue;
                        }
                    }
                    break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_{m:?}"));
                }

                _ => break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, format!("unsupported_{m:?}")),
            }
        };

        if first_bailout.is_none() {
            if let IrTerm::Bailout(ref reason) = term {
                first_bailout = Some(reason.clone());
                if cfg.collect_diagnostics && bailout_detail.is_none() {
                    let detail = pending_diag_detail.take().unwrap_or_else(|| {
                        let ins_str = last_ins
                            .as_ref()
                            .map(fmt_iced_insn)
                            .unwrap_or_else(|| "<no_insn>".to_string());
                        format!("{ins_str} | blks={} insns={raw_vm_insns}", blocks.len())
                    });
                    bailout_detail = Some((last_cur_ip, detail));
                }
            }
        }
        blocks[block_id] = Some(LiftedBlock {
            id: block_id,
            entry_va,
            effects,
            term,
        });
    }

    let final_blocks: Vec<LiftedBlock> = blocks
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            b.unwrap_or_else(|| {
                if first_bailout.is_none() {
                    first_bailout = Some("unfilled_block".into());
                }
                LiftedBlock {
                    id: i,
                    entry_va: start_va,
                    effects: Vec::new(),
                    term: IrTerm::Bailout("unfilled_block".into()),
                }
            })
        })
        .collect();

    LiftedFunction {
        entry: entry.clone(),
        is_entry_call: entry.is_call,
        arena,
        blocks: final_blocks,
        raw_vm_insns,
        opaque_branches_folded,
        visited_byte_addrs,
        first_bailout,
        bailout_detail,
    }
}

// ---------------------------------------------------------------------------
// Soundness Gate & X86/X64 Recompiler (`CodeAssembler`)
// ---------------------------------------------------------------------------

#[inline]
fn to_asm_xmm(idx: u8) -> AsmRegisterXmm {
    use xmm::*;
    match idx {
        0 => xmm0,
        1 => xmm1,
        2 => xmm2,
        3 => xmm3,
        4 => xmm4,
        5 => xmm5,
        6 => xmm6,
        7 => xmm7,
        8 => xmm8,
        9 => xmm9,
        10 => xmm10,
        11 => xmm11,
        12 => xmm12,
        13 => xmm13,
        14 => xmm14,
        _ => xmm15,
    }
}

#[inline]
fn to_asm64(r: ArchReg) -> AsmRegister64 {
    use gpr64::*;
    match r {
        ArchReg::Rax => rax,
        ArchReg::Rcx => rcx,
        ArchReg::Rdx => rdx,
        ArchReg::Rbx => rbx,
        ArchReg::Rsp => rsp,
        ArchReg::Rbp => rbp,
        ArchReg::Rsi => rsi,
        ArchReg::Rdi => rdi,
        ArchReg::R8 => r8,
        ArchReg::R9 => r9,
        ArchReg::R10 => r10,
        ArchReg::R11 => r11,
        ArchReg::R12 => r12,
        ArchReg::R13 => r13,
        ArchReg::R14 => r14,
        ArchReg::R15 => r15,
    }
}

#[inline]
fn to_asm32(r: ArchReg) -> AsmRegister32 {
    use gpr32::*;
    match r {
        ArchReg::Rax => eax,
        ArchReg::Rcx => ecx,
        ArchReg::Rdx => edx,
        ArchReg::Rbx => ebx,
        ArchReg::Rsp => esp,
        ArchReg::Rbp => ebp,
        ArchReg::Rsi => esi,
        ArchReg::Rdi => edi,
        ArchReg::R8 => r8d,
        ArchReg::R9 => r9d,
        ArchReg::R10 => r10d,
        ArchReg::R11 => r11d,
        ArchReg::R12 => r12d,
        ArchReg::R13 => r13d,
        ArchReg::R14 => r14d,
        ArchReg::R15 => r15d,
    }
}

#[inline]
fn to_asm16(r: ArchReg) -> AsmRegister16 {
    use gpr16::*;
    match r {
        ArchReg::Rax => ax,
        ArchReg::Rcx => cx,
        ArchReg::Rdx => dx,
        ArchReg::Rbx => bx,
        ArchReg::Rsp => sp,
        ArchReg::Rbp => bp,
        ArchReg::Rsi => si,
        ArchReg::Rdi => di,
        ArchReg::R8 => r8w,
        ArchReg::R9 => r9w,
        ArchReg::R10 => r10w,
        ArchReg::R11 => r11w,
        ArchReg::R12 => r12w,
        ArchReg::R13 => r13w,
        ArchReg::R14 => r14w,
        ArchReg::R15 => r15w,
    }
}

#[inline]
fn to_asm8_lo(r: ArchReg) -> AsmRegister8 {
    use gpr8::*;
    match r {
        ArchReg::Rax => al,
        ArchReg::Rcx => cl,
        ArchReg::Rdx => dl,
        ArchReg::Rbx => bl,
        ArchReg::Rsp => spl,
        ArchReg::Rbp => bpl,
        ArchReg::Rsi => sil,
        ArchReg::Rdi => dil,
        ArchReg::R8 => r8b,
        ArchReg::R9 => r9b,
        ArchReg::R10 => r10b,
        ArchReg::R11 => r11b,
        ArchReg::R12 => r12b,
        ArchReg::R13 => r13b,
        ArchReg::R14 => r14b,
        ArchReg::R15 => r15b,
    }
}

fn mem_disp(bitness: u32, base: ArchReg, disp: i64, width: u8) -> AsmMemoryOperand {
    let base_op = if bitness == 64 {
        ptr(to_asm64(base))
    } else {
        ptr(to_asm32(base))
    } + disp;
    match width {
        1 => byte_ptr(base_op),
        2 => word_ptr(base_op),
        4 => dword_ptr(base_op),
        8 => qword_ptr(base_op),
        _ => base_op,
    }
}

fn validate_function_soundness(func: &LiftedFunction, view: &PeImageView) -> Result<(), String> {
    let bitness = view.bitness;
    let word_bytes: u8 = if bitness == 64 { 8 } else { 4 };
    if let Some(ref b) = func.first_bailout {
        return Err(b.clone());
    }

    let check_expr_clean = |e: ExprId,
                            ctx: &str,
                            stores: &[StoreRecord],
                            all_aliasing: bool,
                            max_ver: u32,
                            max_cr8_ver: u32|
     -> Result<(), String> {
        if func.arena.contains_opaque(e) {
            return Err(format!("opaque_in_{ctx}"));
        }
        if expr_contains_entry_flag(&func.arena, e) {
            return Err("entry_flag_beyond_block0".into());
        }
        if expr_has_aliasing_stale_load(&func.arena, view, e, stores, all_aliasing, max_ver) {
            return Err("load_across_aliasing_store".into());
        }
        if expr_has_stale_cr8(&func.arena, e, max_cr8_ver) {
            return Err("cr8_stale_read".into());
        }
        Ok(())
    };

    let check_xmms = |xmms: &[(ExprId, ExprId); 16],
                      pending: &[(i64, ExprId)],
                      stores: &[StoreRecord],
                      all_aliasing: bool,
                      max_ver: u32,
                      max_cr8_ver: u32|
     -> Result<(), String> {
        for (i, &(lo, hi)) in xmms.iter().enumerate() {
            let expected_lo = ExprNode::XmmIn(i as u8, false);
            let expected_hi = ExprNode::XmmIn(i as u8, true);
            if *func.arena.get(lo) != expected_lo || *func.arena.get(hi) != expected_hi {
                if bitness != 64 {
                    return Err("modified_xmm_at_exit".into());
                }
                check_expr_clean(lo, "xmm_out", stores, all_aliasing, max_ver, max_cr8_ver)?;
                check_expr_clean(hi, "xmm_out", stores, all_aliasing, max_ver, max_cr8_ver)?;
                if expr_loads_overlapping_caller_slots(&func.arena, lo, pending, word_bytes)
                    || expr_loads_overlapping_caller_slots(&func.arena, hi, pending, word_bytes)
                {
                    return Err("load_across_aliasing_store".into());
                }
            }
        }
        Ok(())
    };

    // Propagate alias-aware store sets, `mem_ver`, and `cr8_ver` across CFG edges.
    let n_blocks = func.blocks.len();
    let mut entry_stores: Vec<Vec<StoreRecord>> = vec![Vec::new(); n_blocks];
    let mut entry_all_aliasing: Vec<bool> = vec![false; n_blocks];
    let mut entry_max_ver: Vec<u32> = vec![0u32; n_blocks];
    let mut entry_cr8_ver: Vec<u32> = vec![0u32; n_blocks];

    let mut work = VecDeque::new();
    work.push_back(0usize);
    let mut visited_ver = HashSet::new();
    visited_ver.insert(0usize);
    while let Some(bi) = work.pop_front() {
        let mut cur_stores = entry_stores[bi].clone();
        let mut cur_all_aliasing = entry_all_aliasing[bi];
        let mut cur_max_ver = entry_max_ver[bi];
        let mut cur_cr8_ver = entry_cr8_ver[bi];
        let block = &func.blocks[bi];
        for eff in &block.effects {
            match eff {
                IrEffect::Store { addr, width, value, mem_ver_after } => {
                    check_expr_clean(*addr, "store_addr", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    check_expr_clean(*value, "store_val", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    let sr = StoreRecord { addr: *addr, width: *width, ver_after: *mem_ver_after };
                    cur_max_ver = cur_max_ver.max(*mem_ver_after);
                    if !cur_all_aliasing && !cur_stores.contains(&sr) {
                        if cur_stores.len() >= 64 {
                            cur_all_aliasing = true;
                            cur_stores.clear();
                        } else {
                            cur_stores.push(sr);
                        }
                    }
                }
                IrEffect::AtomicCmpXchg { addr, width, expected_rax, desired, mem_ver_after, .. } => {
                    check_expr_clean(*addr, "cmpxchg_addr", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    check_expr_clean(*expected_rax, "cmpxchg_expected", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    check_expr_clean(*desired, "cmpxchg_desired", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    let sr = StoreRecord { addr: *addr, width: *width, ver_after: *mem_ver_after };
                    cur_max_ver = cur_max_ver.max(*mem_ver_after);
                    if !cur_all_aliasing && !cur_stores.contains(&sr) {
                        if cur_stores.len() >= 64 {
                            cur_all_aliasing = true;
                            cur_stores.clear();
                        } else {
                            cur_stores.push(sr);
                        }
                    }
                }
                IrEffect::AtomicRmw { addr, width, src, mem_ver_after, .. } => {
                    check_expr_clean(*addr, "atomic_addr", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    check_expr_clean(*src, "atomic_src", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    let sr = StoreRecord { addr: *addr, width: *width, ver_after: *mem_ver_after };
                    cur_max_ver = cur_max_ver.max(*mem_ver_after);
                    if !cur_all_aliasing && !cur_stores.contains(&sr) {
                        if cur_stores.len() >= 64 {
                            cur_all_aliasing = true;
                            cur_stores.clear();
                        } else {
                            cur_stores.push(sr);
                        }
                    }
                }
                IrEffect::WriteCr8 { val, cr8_ver_after } => {
                    check_expr_clean(*val, "write_cr8", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                    cur_cr8_ver = cur_cr8_ver.max(*cr8_ver_after);
                }
                IrEffect::CallNative { .. } => {
                    return Err("call_native_in_block".into());
                }
            }
        }

        let reg_limit = if bitness == 64 { 16 } else { 8 };
        let check_exit_state = |final_xmms: &[(ExprId, ExprId); 16],
                                pending: &[(i64, ExprId)],
                                final_regs: &[ExprId; 16],
                                stores: &[StoreRecord],
                                all_aliasing: bool,
                                max_ver: u32,
                                max_cr8_ver: u32|
         -> Result<(), String> {
            check_xmms(final_xmms, pending, stores, all_aliasing, max_ver, max_cr8_ver)?;
            for &(_, val) in pending {
                check_expr_clean(val, "caller_store", stores, all_aliasing, max_ver, max_cr8_ver)?;
            }
            for r in &ArchReg::ALL[..reg_limit] {
                if *r == ArchReg::Rsp {
                    continue;
                }
                let e = final_regs[r.idx()];
                check_expr_clean(e, r.as_str(), stores, all_aliasing, max_ver, max_cr8_ver)?;
                if expr_loads_overlapping_caller_slots(&func.arena, e, pending, word_bytes) {
                    return Err("load_across_aliasing_store".into());
                }
            }
            Ok(())
        };

        match &block.term {
            IrTerm::Bailout(r) => return Err(r.clone()),
            IrTerm::CondBranch { cond, taken_block, fallthrough_block } => {
                if !(bi == 0 && block.effects.is_empty() && as_direct_entry_flag(&func.arena, *cond).is_some()) {
                    check_expr_clean(*cond, "branch_cond", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
                }
                for &succ in &[*taken_block, *fallthrough_block] {
                    let mut changed = visited_ver.insert(succ);
                    if cur_max_ver > entry_max_ver[succ] {
                        entry_max_ver[succ] = cur_max_ver;
                        changed = true;
                    }
                    if cur_cr8_ver > entry_cr8_ver[succ] {
                        entry_cr8_ver[succ] = cur_cr8_ver;
                        changed = true;
                    }
                    if cur_all_aliasing {
                        if !entry_all_aliasing[succ] {
                            entry_all_aliasing[succ] = true;
                            entry_stores[succ].clear();
                            changed = true;
                        }
                    } else if !entry_all_aliasing[succ] {
                        for st in &cur_stores {
                            if !entry_stores[succ].contains(st) {
                                if entry_stores[succ].len() >= 64 {
                                    entry_all_aliasing[succ] = true;
                                    entry_stores[succ].clear();
                                    changed = true;
                                    break;
                                }
                                entry_stores[succ].push(*st);
                                changed = true;
                            }
                        }
                    }
                    if changed {
                        work.push_back(succ);
                    }
                }
            }
            IrTerm::ExitRet { final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitIndirectMem { final_regs, final_xmms, pending_caller_stores, .. } => {
                check_exit_state(
                    final_xmms,
                    pending_caller_stores,
                    final_regs,
                    &cur_stores,
                    cur_all_aliasing,
                    cur_max_ver,
                    cur_cr8_ver,
                )?;
            }
            IrTerm::ExitJmp { target_va, final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitCall { target_va, final_regs, final_xmms, pending_caller_stores, .. } => {
                if !view.is_executable_va(*target_va) {
                    return Err("exit_target_not_executable".into());
                }
                check_exit_state(
                    final_xmms,
                    pending_caller_stores,
                    final_regs,
                    &cur_stores,
                    cur_all_aliasing,
                    cur_max_ver,
                    cur_cr8_ver,
                )?;
            }
            IrTerm::ExitAddJmp { final_regs, final_xmms, .. } => {
                check_exit_state(
                    final_xmms,
                    &[],
                    final_regs,
                    &cur_stores,
                    cur_all_aliasing,
                    cur_max_ver,
                    cur_cr8_ver,
                )?;
            }
            IrTerm::ExitToVm { va, exit, final_regs, final_xmms } => {
                if bitness != 64 {
                    return Err("vm_exit_32bit".into());
                }
                if !view.is_executable_va(*va) {
                    return Err("exit_target_not_executable".into());
                }
                check_exit_state(
                    final_xmms,
                    &exit.pending,
                    final_regs,
                    &cur_stores,
                    cur_all_aliasing,
                    cur_max_ver,
                    cur_cr8_ver,
                )?;
                // The pending stores go out one after another: a value must not read a
                // slot another one has already overwritten.
                for (i, &(_, val)) in exit.pending.iter().enumerate() {
                    let others: Vec<(i64, ExprId)> = exit
                        .pending
                        .iter()
                        .enumerate()
                        .filter(|&(j, _)| j != i)
                        .map(|(_, &p)| p)
                        .collect();
                    if expr_loads_overlapping_caller_slots(&func.arena, val, &others, word_bytes) {
                        return Err("load_across_aliasing_store".into());
                    }
                }
            }
            IrTerm::MidCall { target, final_regs, final_xmms, pending_caller_stores, cont_block, .. } => {
                if let MidCallTarget::DirectVa(va) = target {
                    if !view.is_executable_va(*va) {
                        return Err("exit_target_not_executable".into());
                    }
                }
                check_exit_state(
                    final_xmms,
                    pending_caller_stores,
                    final_regs,
                    &cur_stores,
                    cur_all_aliasing,
                    cur_max_ver,
                    cur_cr8_ver,
                )?;
                if visited_ver.insert(*cont_block) {
                    work.push_back(*cont_block);
                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct StoreRecord {
    addr: ExprId,
    width: u8,
    ver_after: u32,
}

fn split_sym_base_off(arena: &ExprArena, id: ExprId) -> (ExprId, i128) {
    match arena.get(id) {
        ExprNode::Add(lhs, rhs) => {
            if let Some(c) = arena.as_const(*rhs) {
                ( *lhs, (c as i64) as i128 )
            } else if let Some(c) = arena.as_const(*lhs) {
                ( *rhs, (c as i64) as i128 )
            } else {
                (id, 0)
            }
        }
        ExprNode::Sub(lhs, rhs) => {
            if let Some(c) = arena.as_const(*rhs) {
                ( *lhs, -((c as i64) as i128) )
            } else {
                (id, 0)
            }
        }
        _ => (id, 0),
    }
}

fn addrs_may_alias(arena: &ExprArena, view: &PeImageView, a: ExprId, aw: u8, b: ExprId, bw: u8) -> bool {
    if let (Some(va), Some(vb)) = (arena.as_const(a), arena.as_const(b)) {
        return (va as u128) < (vb as u128) + (bw as u128)
            && (vb as u128) < (va as u128) + (aw as u128);
    }
    match (arena.as_stack_offset(a), arena.as_stack_offset(b)) {
        (Some((sa, oa)), Some((sb, ob))) => {
            return if sa == sb {
                (oa as i128) < (ob as i128) + (bw as i128)
                    && (ob as i128) < (oa as i128) + (aw as i128)
            } else {
                true
            };
        }
        (Some(_), None) => {
            if let Some(vb) = arena.as_const(b) {
                let end = view.image_base.saturating_add(view.image_size);
                if vb >= view.image_base && vb < end {
                    return false;
                }
            }
        }
        (None, Some(_)) => {
            if let Some(va) = arena.as_const(a) {
                let end = view.image_base.saturating_add(view.image_size);
                if va >= view.image_base && va < end {
                    return false;
                }
            }
        }
        (None, None) => {}
    }
    let (base_a, off_a) = split_sym_base_off(arena, a);
    let (base_b, off_b) = split_sym_base_off(arena, b);
    if base_a == base_b && (off_a - off_b).abs() < (1i128 << 40) {
        return off_a < off_b + (bw as i128) && off_b < off_a + (aw as i128);
    }
    true
}

fn push_expr_children(node: &ExprNode, st: &mut Vec<ExprId>) {
    match node {
        ExprNode::Load { addr, .. } | ExprNode::Not(addr) | ExprNode::Neg(addr) | ExprNode::SExt { val: addr, .. } => {
            st.push(*addr);
        }
        ExprNode::Add(a, b)
        | ExprNode::Sub(a, b)
        | ExprNode::Mul(a, b)
        | ExprNode::And(a, b)
        | ExprNode::Or(a, b)
        | ExprNode::Xor(a, b)
        | ExprNode::Shl(a, b)
        | ExprNode::Shr(a, b)
        | ExprNode::Sar(a, b)
        | ExprNode::Rol(a, b)
        | ExprNode::Ror(a, b)
        | ExprNode::Cmp { lhs: a, rhs: b, .. } => {
            st.push(*a);
            st.push(*b);
        }
        ExprNode::Select { cond, if_true, if_false } => {
            st.push(*cond);
            st.push(*if_true);
            st.push(*if_false);
        }
        _ => {}
    }
}

fn expr_has_aliasing_stale_load(
    arena: &ExprArena,
    view: &PeImageView,
    root: ExprId,
    stores: &[StoreRecord],
    all_aliasing: bool,
    max_ver: u32,
) -> bool {
    if max_ver == 0 {
        return false;
    }
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if let ExprNode::Load { mem_ver, addr, width } = node {
            if all_aliasing {
                if *mem_ver < max_ver {
                    return true;
                }
            } else if stores
                .iter()
                .any(|sr| *mem_ver < sr.ver_after && addrs_may_alias(arena, view, *addr, *width, sr.addr, sr.width))
            {
                return true;
            }
        }
        push_expr_children(node, &mut st);
    }
    false
}

fn expr_loads_overlapping_caller_slots(
    arena: &ExprArena,
    root: ExprId,
    pending_caller_stores: &[(i64, ExprId)],
    word_bytes: u8,
) -> bool {
    if pending_caller_stores.is_empty() {
        return false;
    }
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if let ExprNode::Load { addr, width, .. } = node {
            if let Some((StackSpace::CallerStack, loff)) = arena.as_stack_offset(*addr) {
                for &(soff, _) in pending_caller_stores {
                    if (loff as i128) < (soff as i128) + (word_bytes as i128)
                        && (soff as i128) < (loff as i128) + (*width as i128)
                    {
                        return true;
                    }
                }
            }
        }
        push_expr_children(node, &mut st);
    }
    false
}

fn expr_contains_entry_flag(arena: &ExprArena, root: ExprId) -> bool {
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if matches!(node, ExprNode::EntryFlag(_)) {
            return true;
        }
        push_expr_children(node, &mut st);
    }
    false
}

fn expr_has_stale_cr8(arena: &ExprArena, root: ExprId, max_cr8_ver: u32) -> bool {
    if max_cr8_ver == 0 {
        return false;
    }
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if let ExprNode::Cr8Read(v) = node {
            if *v < max_cr8_ver {
                return true;
            }
        }
        push_expr_children(node, &mut st);
    }
    false
}

/// Codegen environment tracking where saved `RegIn(r)` values currently live on stack vs hardware regs.
struct CodegenCtx<'a> {
    bitness: u32,
    word_bytes: i64,
    arena: &'a ExprArena,
    /// Stack byte depth pushed relative to initial entry `StackBase` (`rsp = StackBase - rsp_depth`).
    rsp_depth: i64,
    /// `rsp_depth` value where each pushed `RegIn(r)` lives on stack (`slot_va = StackBase - saved_depth`).
    saved_regs: HashMap<ArchReg, i64>,
    scratch: [ArchReg; 3],
    eval_steps: usize,
}

impl<'a> CodegenCtx<'a> {
    fn emit_mov_imm(&self, a: &mut CodeAssembler, dst: ArchReg, val: u64) -> Result<(), String> {
        if self.bitness == 64 {
            a.mov(to_asm64(dst), val).map_err(|e| e.to_string())
        } else {
            a.mov(to_asm32(dst), val as u32).map_err(|e| e.to_string())
        }
    }

    fn emit_mov_reg(&self, a: &mut CodeAssembler, dst: ArchReg, src: ArchReg) -> Result<(), String> {
        if dst == src {
            return Ok(());
        }
        if self.bitness == 64 {
            a.mov(to_asm64(dst), to_asm64(src)).map_err(|e| e.to_string())
        } else {
            a.mov(to_asm32(dst), to_asm32(src)).map_err(|e| e.to_string())
        }
    }

    fn emit_push(&mut self, a: &mut CodeAssembler, reg: ArchReg) -> Result<(), String> {
        if self.bitness == 64 {
            a.push(to_asm64(reg)).map_err(|e| e.to_string())?;
        } else {
            a.push(to_asm32(reg)).map_err(|e| e.to_string())?;
        }
        self.rsp_depth += self.word_bytes;
        Ok(())
    }

    fn emit_pop(&mut self, a: &mut CodeAssembler, reg: ArchReg) -> Result<(), String> {
        if self.bitness == 64 {
            a.pop(to_asm64(reg)).map_err(|e| e.to_string())?;
        } else {
            a.pop(to_asm32(reg)).map_err(|e| e.to_string())?;
        }
        self.rsp_depth -= self.word_bytes;
        Ok(())
    }

    fn emit_rsp_adjust(&mut self, a: &mut CodeAssembler, target_delta_from_base: i64) -> Result<(), String> {
        // Currently HW RSP = StackBase - rsp_depth. Desired HW RSP = StackBase + target_delta_from_base.
        let diff = target_delta_from_base + self.rsp_depth;
        if diff == 0 {
            return Ok(());
        }
        let Ok(abs_i32) = i32::try_from(diff.abs()) else {
            return Err("rsp_delta_out_of_i32".into());
        };
        if diff > 0 {
            if self.bitness == 64 {
                a.add(gpr64::rsp, abs_i32).map_err(|e| e.to_string())?;
            } else {
                a.add(gpr32::esp, abs_i32).map_err(|e| e.to_string())?;
            }
        } else if self.bitness == 64 {
            a.sub(gpr64::rsp, abs_i32).map_err(|e| e.to_string())?;
        } else {
            a.sub(gpr32::esp, abs_i32).map_err(|e| e.to_string())?;
        }
        self.rsp_depth = -target_delta_from_base;
        Ok(())
    }

    fn read_reg_in(&self, a: &mut CodeAssembler, dst: ArchReg, src: ArchReg) -> Result<(), String> {
        if src == ArchReg::Rsp {
            return self.emit_stack_base_addr(a, dst, 0, None);
        }
        if let Some(&saved_depth) = self.saved_regs.get(&src) {
            // Saved slot is at StackBase - saved_depth; current HW RSP is StackBase - rsp_depth
            // So offset from current HW RSP is (rsp_depth - saved_depth)
            let rel = self.rsp_depth - saved_depth;
            let mem = mem_disp(self.bitness, ArchReg::Rsp, rel, self.word_bytes as u8);
            if self.bitness == 64 {
                a.mov(to_asm64(dst), mem).map_err(|e| e.to_string())
            } else {
                a.mov(to_asm32(dst), mem).map_err(|e| e.to_string())
            }
        } else {
            self.emit_mov_reg(a, dst, src)
        }
    }

    fn emit_stack_base_addr(
        &self,
        a: &mut CodeAssembler,
        dst: ArchReg,
        off: i64,
        tmp: Option<ArchReg>,
    ) -> Result<(), String> {
        let rel = self.rsp_depth + off;
        if rel == 0 {
            self.emit_mov_reg(a, dst, ArchReg::Rsp)
        } else if let Ok(d32) = i32::try_from(rel) {
            let m = if self.bitness == 64 {
                ptr(gpr64::rsp) + d32
            } else {
                ptr(gpr32::esp) + d32
            };
            if self.bitness == 64 {
                a.lea(to_asm64(dst), m).map_err(|e| e.to_string())
            } else {
                a.lea(to_asm32(dst), m).map_err(|e| e.to_string())
            }
        } else {
            self.emit_mov_reg(a, dst, ArchReg::Rsp)?;
            self.emit_alu_imm(a, AluOp::Add, dst, rel as u64, tmp)
        }
    }

    fn emit_alu_imm(
        &self,
        a: &mut CodeAssembler,
        op: AluOp,
        dst: ArchReg,
        imm: u64,
        tmp: Option<ArchReg>,
    ) -> Result<(), String> {
        if self.bitness == 32 {
            let v = imm as i32;
            return match op {
                AluOp::Add => a.add(to_asm32(dst), v),
                AluOp::Sub => a.sub(to_asm32(dst), v),
                AluOp::And => a.and(to_asm32(dst), v),
                AluOp::Or => a.or(to_asm32(dst), v),
                AluOp::Xor => a.xor(to_asm32(dst), v),
                AluOp::Mul => a.imul_3(to_asm32(dst), to_asm32(dst), v),
            }
            .map_err(|e| e.to_string());
        }
        if let Ok(v32) = i32::try_from(imm as i64) {
            return match op {
                AluOp::Add => a.add(to_asm64(dst), v32),
                AluOp::Sub => a.sub(to_asm64(dst), v32),
                AluOp::And => a.and(to_asm64(dst), v32),
                AluOp::Or => a.or(to_asm64(dst), v32),
                AluOp::Xor => a.xor(to_asm64(dst), v32),
                AluOp::Mul => a.imul_3(to_asm64(dst), to_asm64(dst), v32),
            }
            .map_err(|e| e.to_string());
        }
        let Some(t) = tmp else {
            return Err("need_temp_for_imm64".into());
        };
        if t == dst {
            return Err("temp_equals_dst".into());
        }
        a.mov(to_asm64(t), imm).map_err(|e| e.to_string())?;
        self.emit_alu_reg(a, op, dst, t)
    }

    fn emit_alu_reg(&self, a: &mut CodeAssembler, op: AluOp, dst: ArchReg, rhs: ArchReg) -> Result<(), String> {
        if self.bitness == 64 {
            match op {
                AluOp::Add => a.add(to_asm64(dst), to_asm64(rhs)),
                AluOp::Sub => a.sub(to_asm64(dst), to_asm64(rhs)),
                AluOp::And => a.and(to_asm64(dst), to_asm64(rhs)),
                AluOp::Or => a.or(to_asm64(dst), to_asm64(rhs)),
                AluOp::Xor => a.xor(to_asm64(dst), to_asm64(rhs)),
                AluOp::Mul => a.imul_2(to_asm64(dst), to_asm64(rhs)),
            }
        } else {
            match op {
                AluOp::Add => a.add(to_asm32(dst), to_asm32(rhs)),
                AluOp::Sub => a.sub(to_asm32(dst), to_asm32(rhs)),
                AluOp::And => a.and(to_asm32(dst), to_asm32(rhs)),
                AluOp::Or => a.or(to_asm32(dst), to_asm32(rhs)),
                AluOp::Xor => a.xor(to_asm32(dst), to_asm32(rhs)),
                AluOp::Mul => a.imul_2(to_asm32(dst), to_asm32(rhs)),
            }
        }
        .map_err(|e| e.to_string())
    }

    fn eval_expr_into(
        &mut self,
        a: &mut CodeAssembler,
        expr: ExprId,
        dst: ArchReg,
        spill_reg: ArchReg,
    ) -> Result<(), String> {
        self.eval_steps += 1;
        if self.eval_steps > 2048 {
            return Err("expr_too_complex".into());
        }
        if dst == spill_reg {
            return Err("codegen_dst_eq_spill".into());
        }
        match self.arena.get(expr).clone() {
            ExprNode::Const(v) => self.emit_mov_imm(a, dst, v),
            ExprNode::RegIn(r) => self.read_reg_in(a, dst, r),
            ExprNode::StackBase => self.emit_stack_base_addr(a, dst, 0, Some(spill_reg)),
            ExprNode::Not(x) => {
                self.eval_expr_into(a, x, dst, spill_reg)?;
                if self.bitness == 64 {
                    a.not(to_asm64(dst)).map_err(|e| e.to_string())
                } else {
                    a.not(to_asm32(dst)).map_err(|e| e.to_string())
                }
            }
            ExprNode::Neg(x) => {
                self.eval_expr_into(a, x, dst, spill_reg)?;
                if self.bitness == 64 {
                    a.neg(to_asm64(dst)).map_err(|e| e.to_string())
                } else {
                    a.neg(to_asm32(dst)).map_err(|e| e.to_string())
                }
            }
            ExprNode::SExt { val, from_bits } => {
                self.eval_expr_into(a, val, dst, spill_reg)?;
                match from_bits {
                    8 => {
                        if self.bitness == 64 {
                            a.movsx(to_asm64(dst), to_asm8_lo(dst))
                        } else {
                            a.movsx(to_asm32(dst), to_asm8_lo(dst))
                        }
                        .map_err(|e| e.to_string())
                    }
                    16 => {
                        if self.bitness == 64 {
                            a.movsx(to_asm64(dst), to_asm16(dst))
                        } else {
                            a.movsx(to_asm32(dst), to_asm16(dst))
                        }
                        .map_err(|e| e.to_string())
                    }
                    32 if self.bitness == 64 => {
                        a.movsxd(to_asm64(dst), to_asm32(dst)).map_err(|e| e.to_string())
                    }
                    _ => Ok(()),
                }
            }
            ExprNode::Load { addr, width, .. } => {
                if let Some((StackSpace::CallerStack, off)) = self.arena.as_stack_offset(addr) {
                    let rel = self.rsp_depth + off;
                    let m = mem_disp(self.bitness, ArchReg::Rsp, rel, width);
                    self.emit_load_from_mem(a, dst, m, width)
                } else {
                    self.eval_expr_into(a, addr, dst, spill_reg)?;
                    let m = mem_disp(self.bitness, dst, 0, width);
                    self.emit_load_from_mem(a, dst, m, width)
                }
            }
            ExprNode::Add(lhs, rhs)
            | ExprNode::Sub(lhs, rhs)
            | ExprNode::Mul(lhs, rhs)
            | ExprNode::And(lhs, rhs)
            | ExprNode::Or(lhs, rhs)
            | ExprNode::Xor(lhs, rhs) => {
                let op = match self.arena.get(expr) {
                    ExprNode::Add(..) => AluOp::Add,
                    ExprNode::Sub(..) => AluOp::Sub,
                    ExprNode::Mul(..) => AluOp::Mul,
                    ExprNode::And(..) => AluOp::And,
                    ExprNode::Or(..) => AluOp::Or,
                    _ => AluOp::Xor,
                };
                if op == AluOp::Add {
                    if let Some((StackSpace::CallerStack, off)) = self.arena.as_stack_offset(expr) {
                        return self.emit_stack_base_addr(a, dst, off, Some(spill_reg));
                    }
                }
                if let Some(imm) = self.arena.as_const(rhs) {
                    self.eval_expr_into(a, lhs, dst, spill_reg)?;
                    if op == AluOp::Add && (imm as i64) < 0 && i32::try_from(-(imm as i64)).is_ok() {
                        return self.emit_alu_imm(a, AluOp::Sub, dst, imm.wrapping_neg(), Some(spill_reg));
                    }
                    return self.emit_alu_imm(a, op, dst, imm, Some(spill_reg));
                }
                self.eval_expr_into(a, lhs, dst, spill_reg)?;
                self.emit_push(a, dst)?;
                self.eval_expr_into(a, rhs, spill_reg, dst)?;
                // `dst` is on top of stack; pop into tmp `dst` or wait: we want `dst = lhs`, `rhs` in `spill_reg`!
                // Pop saved `lhs` back into `dst` safely!
                self.emit_pop(a, dst)?;
                self.emit_alu_reg(a, op, dst, spill_reg)
            }
            ExprNode::Shl(lhs, rhs)
            | ExprNode::Shr(lhs, rhs)
            | ExprNode::Sar(lhs, rhs)
            | ExprNode::Rol(lhs, rhs)
            | ExprNode::Ror(lhs, rhs) => {
                let node = self.arena.get(expr).clone();
                let bitness = self.bitness;
                let emit_shift_cl = |a: &mut CodeAssembler, target: ArchReg| -> Result<(), String> {
                    if bitness == 64 {
                        match node {
                            ExprNode::Shl(..) => a.shl(to_asm64(target), gpr8::cl),
                            ExprNode::Shr(..) => a.shr(to_asm64(target), gpr8::cl),
                            ExprNode::Sar(..) => a.sar(to_asm64(target), gpr8::cl),
                            ExprNode::Rol(..) => a.rol(to_asm64(target), gpr8::cl),
                            _ => a.ror(to_asm64(target), gpr8::cl),
                        }
                    } else {
                        match node {
                            ExprNode::Shl(..) => a.shl(to_asm32(target), gpr8::cl),
                            ExprNode::Shr(..) => a.shr(to_asm32(target), gpr8::cl),
                            ExprNode::Sar(..) => a.sar(to_asm32(target), gpr8::cl),
                            ExprNode::Rol(..) => a.rol(to_asm32(target), gpr8::cl),
                            _ => a.ror(to_asm32(target), gpr8::cl),
                        }
                    }
                    .map_err(|e| e.to_string())
                };
                if let Some(cnt) = self.arena.as_const(rhs) {
                    let c = (cnt & 63) as u32;
                    self.eval_expr_into(a, lhs, dst, spill_reg)?;
                    if bitness == 64 {
                        match node {
                            ExprNode::Shl(..) => a.shl(to_asm64(dst), c),
                            ExprNode::Shr(..) => a.shr(to_asm64(dst), c),
                            ExprNode::Sar(..) => a.sar(to_asm64(dst), c),
                            ExprNode::Rol(..) => a.rol(to_asm64(dst), c),
                            _ => a.ror(to_asm64(dst), c),
                        }
                    } else {
                        match node {
                            ExprNode::Shl(..) => a.shl(to_asm32(dst), c),
                            ExprNode::Shr(..) => a.shr(to_asm32(dst), c),
                            ExprNode::Sar(..) => a.sar(to_asm32(dst), c),
                            ExprNode::Rol(..) => a.rol(to_asm32(dst), c),
                            _ => a.ror(to_asm32(dst), c),
                        }
                    }
                    .map_err(|e| e.to_string())
                } else if dst == ArchReg::Rcx {
                    self.eval_expr_into(a, lhs, spill_reg, ArchReg::Rcx)?;
                    self.emit_push(a, spill_reg)?;
                    self.eval_expr_into(a, rhs, ArchReg::Rcx, spill_reg)?;
                    self.emit_pop(a, spill_reg)?;
                    emit_shift_cl(a, spill_reg)?;
                    self.emit_mov_reg(a, ArchReg::Rcx, spill_reg)
                } else if spill_reg == ArchReg::Rcx {
                    self.eval_expr_into(a, lhs, dst, ArchReg::Rcx)?;
                    self.emit_push(a, dst)?;
                    self.eval_expr_into(a, rhs, ArchReg::Rcx, dst)?;
                    self.emit_pop(a, dst)?;
                    emit_shift_cl(a, dst)
                } else {
                    self.eval_expr_into(a, lhs, dst, spill_reg)?;
                    self.emit_push(a, dst)?;
                    self.eval_expr_into(a, rhs, spill_reg, dst)?;
                    self.emit_pop(a, dst)?;
                    self.emit_push(a, ArchReg::Rcx)?;
                    self.emit_mov_reg(a, ArchReg::Rcx, spill_reg)?;
                    emit_shift_cl(a, dst)?;
                    self.emit_pop(a, ArchReg::Rcx)
                }
            }
            ExprNode::Cmp { pred, lhs, rhs } => {
                let mut l_then = a.create_label();
                let mut l_done = a.create_label();
                self.emit_branch_on_cmp(a, pred, lhs, rhs, &mut l_then, spill_reg, dst)?;
                self.emit_mov_imm(a, dst, 0)?;
                a.jmp(l_done).map_err(|e| e.to_string())?;
                a.set_label(&mut l_then).map_err(|e| e.to_string())?;
                a.zero_bytes().map_err(|e| e.to_string())?;
                self.emit_mov_imm(a, dst, 1)?;
                a.set_label(&mut l_done).map_err(|e| e.to_string())?;
                a.zero_bytes().map_err(|e| e.to_string())?;
                Ok(())
            }
            ExprNode::Select { cond, if_true, if_false } => {
                let mut l_true = a.create_label();
                let mut l_done = a.create_label();
                self.emit_branch_on_cond(a, cond, &mut l_true, dst, spill_reg)?;
                self.eval_expr_into(a, if_false, dst, spill_reg)?;
                a.jmp(l_done).map_err(|e| e.to_string())?;
                a.set_label(&mut l_true).map_err(|e| e.to_string())?;
                a.zero_bytes().map_err(|e| e.to_string())?;
                self.eval_expr_into(a, if_true, dst, spill_reg)?;
                a.set_label(&mut l_done).map_err(|e| e.to_string())?;
                a.zero_bytes().map_err(|e| e.to_string())?;
                Ok(())
            }
            ExprNode::Cr8Read(_) => {
                if self.bitness != 64 {
                    return Err("cr8_requires_64bit".into());
                }
                use iced_x86::code_asm::registers::cr::cr8;
                a.mov(to_asm64(dst), cr8).map_err(|e| e.to_string())
            }
            ExprNode::EntryFlag(_) => Err("unlowerable_entry_flag".into()),
            ExprNode::XmmIn(idx, hi) => {
                if self.bitness != 64 || idx >= 16 {
                    return Err("unlowerable_xmm_in".into());
                }
                let x = to_asm_xmm(idx);
                if !hi {
                    a.movq(to_asm64(dst), x).map_err(|e| e.to_string())
                } else {
                    a.lea(gpr64::rsp, ptr(gpr64::rsp) - 16).map_err(|e| e.to_string())?;
                    a.movdqu(ptr(gpr64::rsp), x).map_err(|e| e.to_string())?;
                    a.mov(to_asm64(dst), qword_ptr(gpr64::rsp + 8)).map_err(|e| e.to_string())?;
                    a.lea(gpr64::rsp, ptr(gpr64::rsp) + 16).map_err(|e| e.to_string())
                }
            }
            ExprNode::Opaque(_) => Err("unlowerable_opaque".into()),
            ExprNode::AlignedBase(_) => Err("unlowerable_aligned_base".into()),
            ExprNode::CallRet { .. } => Err("unlowerable_call_ret".into()),
        }
    }

    fn emit_load_from_mem(
        &self,
        a: &mut CodeAssembler,
        dst: ArchReg,
        m: AsmMemoryOperand,
        width: u8,
    ) -> Result<(), String> {
        match (self.bitness, width) {
            (64, 8) => a.mov(to_asm64(dst), m),
            (64, 4) | (32, 4) => a.mov(to_asm32(dst), m),
            (_, 2) => a.movzx(to_asm32(dst), m),
            (_, 1) => a.movzx(to_asm32(dst), m),
            _ => return Err(format!("unsupported_load_width_{width}")),
        }
        .map_err(|e| e.to_string())
    }

    fn emit_store_to_mem(
        &self,
        a: &mut CodeAssembler,
        m: AsmMemoryOperand,
        val_reg: ArchReg,
        width: u8,
    ) -> Result<(), String> {
        match (self.bitness, width) {
            (64, 8) => a.mov(m, to_asm64(val_reg)),
            (64, 4) | (32, 4) => a.mov(m, to_asm32(val_reg)),
            (_, 2) => a.mov(m, to_asm16(val_reg)),
            (_, 1) => a.mov(m, to_asm8_lo(val_reg)),
            _ => return Err(format!("unsupported_store_width_{width}")),
        }
        .map_err(|e| e.to_string())
    }

    fn emit_branch_on_cmp(
        &mut self,
        a: &mut CodeAssembler,
        pred: CondPred,
        lhs: ExprId,
        rhs: ExprId,
        target_lbl: &mut CodeLabel,
        tmp0: ArchReg,
        tmp1: ArchReg,
    ) -> Result<(), String> {
        self.eval_steps += 1;
        if self.eval_steps > 2048 {
            return Err("expr_too_complex".into());
        }
        // Compute lhs into tmp0, compare against imm32 or rhs in tmp1
        if let Some(imm) = self.arena.as_const(rhs) {
            self.eval_expr_into(a, lhs, tmp0, tmp1)?;
            if imm == 0 && matches!(pred, CondPred::Eq | CondPred::Ne) {
                if self.bitness == 64 {
                    a.test(to_asm64(tmp0), to_asm64(tmp0)).map_err(|e| e.to_string())?;
                } else {
                    a.test(to_asm32(tmp0), to_asm32(tmp0)).map_err(|e| e.to_string())?;
                }
            } else if let Ok(v32) = i32::try_from(imm as i64) {
                if self.bitness == 64 {
                    a.cmp(to_asm64(tmp0), v32).map_err(|e| e.to_string())?;
                } else {
                    a.cmp(to_asm32(tmp0), v32).map_err(|e| e.to_string())?;
                }
            } else {
                self.emit_mov_imm(a, tmp1, imm)?;
                a.cmp(to_asm64(tmp0), to_asm64(tmp1)).map_err(|e| e.to_string())?;
            }
        } else {
            self.eval_expr_into(a, lhs, tmp0, tmp1)?;
            self.emit_push(a, tmp0)?;
            self.eval_expr_into(a, rhs, tmp1, tmp0)?;
            self.emit_pop(a, tmp0)?;
            if self.bitness == 64 {
                a.cmp(to_asm64(tmp0), to_asm64(tmp1)).map_err(|e| e.to_string())?;
            } else {
                a.cmp(to_asm32(tmp0), to_asm32(tmp1)).map_err(|e| e.to_string())?;
            }
        }

        let lbl = *target_lbl;
        match pred {
            CondPred::Eq => a.je(lbl),
            CondPred::Ne => a.jne(lbl),
            CondPred::Ult => a.jb(lbl),
            CondPred::Ule => a.jbe(lbl),
            CondPred::Ugt => a.ja(lbl),
            CondPred::Uge => a.jae(lbl),
            CondPred::Slt => a.jl(lbl),
            CondPred::Sle => a.jle(lbl),
            CondPred::Sgt => a.jg(lbl),
            CondPred::Sge => a.jge(lbl),
        }
        .map_err(|e| e.to_string())
    }

    fn emit_branch_on_cond(
        &mut self,
        a: &mut CodeAssembler,
        cond: ExprId,
        target_lbl: &mut CodeLabel,
        tmp0: ArchReg,
        tmp1: ArchReg,
    ) -> Result<(), String> {
        self.eval_steps += 1;
        if self.eval_steps > 2048 {
            return Err("expr_too_complex".into());
        }
        if let ExprNode::Cmp { pred, lhs, rhs } = self.arena.get(cond).clone() {
            return self.emit_branch_on_cmp(a, pred, lhs, rhs, target_lbl, tmp0, tmp1);
        }
        self.eval_expr_into(a, cond, tmp0, tmp1)?;
        if self.bitness == 64 {
            a.test(to_asm64(tmp0), to_asm64(tmp0)).map_err(|e| e.to_string())?;
        } else {
            a.test(to_asm32(tmp0), to_asm32(tmp0)).map_err(|e| e.to_string())?;
        }
        a.jne(*target_lbl).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Mul,
}

fn collect_read_regs_into(arena: &ExprArena, expr: ExprId, out: &mut HashSet<ArchReg>) {
    let mut seen = HashSet::new();
    let mut st = vec![expr];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        match arena.get(id) {
            ExprNode::RegIn(r) => {
                out.insert(*r);
            }
            ExprNode::Load { addr, .. } | ExprNode::Not(addr) | ExprNode::Neg(addr) | ExprNode::SExt { val: addr, .. } => {
                st.push(*addr);
            }
            ExprNode::Add(a, b)
            | ExprNode::Sub(a, b)
            | ExprNode::Mul(a, b)
            | ExprNode::And(a, b)
            | ExprNode::Or(a, b)
            | ExprNode::Xor(a, b)
            | ExprNode::Shl(a, b)
            | ExprNode::Shr(a, b)
            | ExprNode::Sar(a, b)
            | ExprNode::Rol(a, b)
            | ExprNode::Ror(a, b)
            | ExprNode::Cmp { lhs: a, rhs: b, .. } => {
                st.push(*a);
                st.push(*b);
            }
            ExprNode::Select { cond, if_true, if_false } => {
                st.push(*cond);
                st.push(*if_true);
                st.push(*if_false);
            }
            _ => {}
        }
    }
}

fn pick_three_scratch_regs(bitness: u32, avoid: &HashSet<ArchReg>) -> [ArchReg; 3] {
    let pool = if bitness == 64 {
        &[
            ArchReg::R10, ArchReg::R11, ArchReg::R9, ArchReg::R8, ArchReg::Rax, ArchReg::Rcx,
            ArchReg::Rdx, ArchReg::Rbx, ArchReg::Rbp, ArchReg::Rsi, ArchReg::Rdi, ArchReg::R12,
            ArchReg::R13, ArchReg::R14, ArchReg::R15,
        ][..]
    } else {
        &[
            ArchReg::Rax, ArchReg::Rcx, ArchReg::Rdx, ArchReg::Rbx, ArchReg::Rsi, ArchReg::Rdi,
            ArchReg::Rbp,
        ][..]
    };
    let mut picked = Vec::with_capacity(3);
    for &r in pool {
        if !avoid.contains(&r) {
            picked.push(r);
            if picked.len() == 3 {
                break;
            }
        }
    }
    for &r in pool {
        if picked.len() == 3 {
            break;
        }
        if !picked.contains(&r) {
            picked.push(r);
        }
    }
    [picked[0], picked[1], picked[2]]
}

fn emit_block_effects(
    a: &mut CodeAssembler,
    ctx: &mut CodegenCtx<'_>,
    effects: &[IrEffect],
) -> Result<(), String> {
    let [w0, w1, w2] = ctx.scratch;
    for eff in effects {
        match eff {
            IrEffect::Store { addr, width, value, .. } => {
                ctx.eval_expr_into(a, *value, w0, w2)?;
                if let Some((StackSpace::CallerStack, off)) = ctx.arena.as_stack_offset(*addr) {
                    let rel = ctx.rsp_depth + off;
                    let m = mem_disp(ctx.bitness, ArchReg::Rsp, rel, *width);
                    ctx.emit_store_to_mem(a, m, w0, *width)?;
                } else {
                    ctx.emit_push(a, w0)?;
                    ctx.eval_expr_into(a, *addr, w1, w2)?;
                    ctx.emit_pop(a, w0)?;
                    let m = mem_disp(ctx.bitness, w1, 0, *width);
                    ctx.emit_store_to_mem(a, m, w0, *width)?;
                }
            }
            IrEffect::AtomicCmpXchg { lock, addr, width, expected_rax, desired, .. } => {
                ctx.eval_expr_into(a, *addr, w1, w2)?;
                ctx.emit_push(a, w1)?;
                ctx.eval_expr_into(a, *desired, w0, w2)?;
                ctx.emit_push(a, w0)?;
                // `RAX` must hold `expected_rax` for `cmpxchg [w1], w0`
                let need_save_rax = w0 == ArchReg::Rax || w1 == ArchReg::Rax;
                if need_save_rax {
                    return Err("cmpxchg_scratch_conflict".into());
                }
                ctx.eval_expr_into(a, *expected_rax, ArchReg::Rax, w2)?;
                ctx.emit_pop(a, w0)?;
                ctx.emit_pop(a, w1)?;
                let m = mem_disp(ctx.bitness, w1, 0, *width);
                if *lock {
                    match (ctx.bitness, *width) {
                        (64, 8) => a.lock().cmpxchg(m, to_asm64(w0)),
                        (_, 4) => a.lock().cmpxchg(m, to_asm32(w0)),
                        (_, 2) => a.lock().cmpxchg(m, to_asm16(w0)),
                        (_, 1) => a.lock().cmpxchg(m, to_asm8_lo(w0)),
                        _ => return Err("cmpxchg_width".into()),
                    }
                    .map_err(|e| e.to_string())?;
                } else {
                    match (ctx.bitness, *width) {
                        (64, 8) => a.cmpxchg(m, to_asm64(w0)),
                        (_, 4) => a.cmpxchg(m, to_asm32(w0)),
                        (_, 2) => a.cmpxchg(m, to_asm16(w0)),
                        (_, 1) => a.cmpxchg(m, to_asm8_lo(w0)),
                        _ => return Err("cmpxchg_width".into()),
                    }
                    .map_err(|e| e.to_string())?;
                }
            }
            IrEffect::AtomicRmw { lock, op, addr, width, src, .. } => {
                if !matches!((ctx.bitness, *width), (64, 8) | (_, 4) | (_, 2) | (_, 1)) {
                    return Err("atomic_width".into());
                }
                match op {
                    AtomicOpKind::Inc | AtomicOpKind::Dec => {
                        ctx.eval_expr_into(a, *addr, w1, w2)?;
                        let m = mem_disp(ctx.bitness, w1, 0, *width);
                        let target = if *lock { a.lock() } else { &mut *a };
                        match op {
                            AtomicOpKind::Inc => target.inc(m),
                            AtomicOpKind::Dec => target.dec(m),
                            _ => unreachable!(),
                        }
                        .map_err(|e| e.to_string())?;
                    }
                    AtomicOpKind::Add
                    | AtomicOpKind::Sub
                    | AtomicOpKind::And
                    | AtomicOpKind::Or
                    | AtomicOpKind::Xor => {
                        ctx.eval_expr_into(a, *addr, w1, w2)?;
                        ctx.emit_push(a, w1)?;
                        ctx.eval_expr_into(a, *src, w0, w2)?;
                        ctx.emit_pop(a, w1)?;
                        let m = mem_disp(ctx.bitness, w1, 0, *width);
                        let target = if *lock { a.lock() } else { &mut *a };
                        match (op, ctx.bitness, *width) {
                            (AtomicOpKind::Add, 64, 8) => target.add(m, to_asm64(w0)),
                            (AtomicOpKind::Add, _, 4) => target.add(m, to_asm32(w0)),
                            (AtomicOpKind::Add, _, 2) => target.add(m, to_asm16(w0)),
                            (AtomicOpKind::Add, _, 1) => target.add(m, to_asm8_lo(w0)),
                            (AtomicOpKind::Sub, 64, 8) => target.sub(m, to_asm64(w0)),
                            (AtomicOpKind::Sub, _, 4) => target.sub(m, to_asm32(w0)),
                            (AtomicOpKind::Sub, _, 2) => target.sub(m, to_asm16(w0)),
                            (AtomicOpKind::Sub, _, 1) => target.sub(m, to_asm8_lo(w0)),
                            (AtomicOpKind::And, 64, 8) => target.and(m, to_asm64(w0)),
                            (AtomicOpKind::And, _, 4) => target.and(m, to_asm32(w0)),
                            (AtomicOpKind::And, _, 2) => target.and(m, to_asm16(w0)),
                            (AtomicOpKind::And, _, 1) => target.and(m, to_asm8_lo(w0)),
                            (AtomicOpKind::Or, 64, 8) => target.or(m, to_asm64(w0)),
                            (AtomicOpKind::Or, _, 4) => target.or(m, to_asm32(w0)),
                            (AtomicOpKind::Or, _, 2) => target.or(m, to_asm16(w0)),
                            (AtomicOpKind::Or, _, 1) => target.or(m, to_asm8_lo(w0)),
                            (AtomicOpKind::Xor, 64, 8) => target.xor(m, to_asm64(w0)),
                            (AtomicOpKind::Xor, _, 4) => target.xor(m, to_asm32(w0)),
                            (AtomicOpKind::Xor, _, 2) => target.xor(m, to_asm16(w0)),
                            (AtomicOpKind::Xor, _, 1) => target.xor(m, to_asm8_lo(w0)),
                            _ => return Err("atomic_width".into()),
                        }
                        .map_err(|e| e.to_string())?;
                    }
                }
            }
            IrEffect::WriteCr8 { val, .. } => {
                if ctx.bitness != 64 {
                    return Err("cr8_requires_64bit".into());
                }
                ctx.eval_expr_into(a, *val, w0, w2)?;
                use iced_x86::code_asm::registers::cr::cr8;
                a.mov(cr8, to_asm64(w0)).map_err(|e| e.to_string())?;
            }
            IrEffect::CallNative { .. } => return Err("call_native_in_block".into()),
        }
    }
    Ok(())
}

fn expr_safe_in_place(arena: &ExprArena, expr: ExprId, dst_reg: ArchReg) -> bool {
    match arena.get(expr) {
        ExprNode::RegIn(_) | ExprNode::XmmIn(_, _) => true,
        ExprNode::Not(x) | ExprNode::Neg(x) | ExprNode::SExt { val: x, .. } => {
            expr_safe_in_place(arena, *x, dst_reg)
        }
        ExprNode::Add(lhs, rhs)
        | ExprNode::Sub(lhs, rhs)
        | ExprNode::Mul(lhs, rhs)
        | ExprNode::And(lhs, rhs)
        | ExprNode::Or(lhs, rhs)
        | ExprNode::Xor(lhs, rhs)
        | ExprNode::Shl(lhs, rhs)
        | ExprNode::Shr(lhs, rhs)
        | ExprNode::Sar(lhs, rhs)
        | ExprNode::Rol(lhs, rhs)
        | ExprNode::Ror(lhs, rhs)
            if arena.as_const(*rhs).is_some() =>
        {
            expr_safe_in_place(arena, *lhs, dst_reg)
        }
        _ => {
            let mut reads = HashSet::new();
            collect_read_regs_into(arena, expr, &mut reads);
            !reads.contains(&dst_reg)
        }
    }
}

fn expr_uses_spill(arena: &ExprArena, bitness: u32, expr: ExprId) -> bool {
    match arena.get(expr) {
        ExprNode::Const(_)
        | ExprNode::RegIn(_)
        | ExprNode::XmmIn(_, _)
        | ExprNode::StackBase
        | ExprNode::Cr8Read(_)
        | ExprNode::EntryFlag(_) => false,
        ExprNode::Not(x) | ExprNode::Neg(x) | ExprNode::SExt { val: x, .. } => {
            expr_uses_spill(arena, bitness, *x)
        }
        ExprNode::Load { addr, .. } => {
            if matches!(arena.as_stack_offset(*addr), Some((StackSpace::CallerStack, _))) {
                false
            } else {
                expr_uses_spill(arena, bitness, *addr)
            }
        }
        ExprNode::Add(lhs, rhs)
        | ExprNode::Sub(lhs, rhs)
        | ExprNode::Mul(lhs, rhs)
        | ExprNode::And(lhs, rhs)
        | ExprNode::Or(lhs, rhs)
        | ExprNode::Xor(lhs, rhs) => {
            if matches!(arena.get(expr), ExprNode::Add(..)) {
                if let Some((StackSpace::CallerStack, off)) = arena.as_stack_offset(expr) {
                    return i32::try_from(off).is_err();
                }
            }
            if let Some(imm) = arena.as_const(*rhs) {
                if bitness == 64 {
                    let is_neg_add = matches!(arena.get(expr), ExprNode::Add(..))
                        && (imm as i64) < 0
                        && i32::try_from(-(imm as i64)).is_ok();
                    if !is_neg_add && i32::try_from(imm as i64).is_err() {
                        return true;
                    }
                }
                expr_uses_spill(arena, bitness, *lhs)
            } else {
                true
            }
        }
        ExprNode::Shl(lhs, rhs)
        | ExprNode::Shr(lhs, rhs)
        | ExprNode::Sar(lhs, rhs)
        | ExprNode::Rol(lhs, rhs)
        | ExprNode::Ror(lhs, rhs) => {
            arena.as_const(*rhs).is_none() || expr_uses_spill(arena, bitness, *lhs)
        }
        _ => true,
    }
}

/// The tail of `IrTerm::ExitToVm` (see `VmExit`). On entry every register holds its
/// final value and RSP is `entry + exit.rsp_delta`; the temporary values sit at their
/// offsets above it.
fn emit_vm_exit(a: &mut CodeAssembler, exit: &VmExit, target: u64) -> Result<(), String> {
    use gpr64::{rax, rcx, rsp};
    let err = |e: iced_x86::IcedError| e.to_string();
    let d32 = |v: i64| i32::try_from(v).map_err(|_| "vm_exit_disp".to_string());
    let nb = exit.bases.len() as i64;
    a.push(rax).map_err(err)?;
    a.push(rcx).map_err(err)?;
    // Recompute each aligned base exactly as the VM did; keep them on the stack.
    for (k, &(parent, off, mask)) in exit.bases.iter().enumerate() {
        let depth = 16 + 8 * k as i64; // bytes pushed so far
        match parent {
            StackSpace::CallerStack => {
                // entry + off == rsp + depth + (off - rsp_delta)
                a.lea(rax, ptr(rsp) + d32(depth + off - exit.rsp_delta)?).map_err(err)?;
            }
            StackSpace::AlignedScratch(p) => {
                // base p was pushed (k - 1 - p) slots above the top
                let at = 8 * (k as i64 - 1 - p as i64);
                if at < 0 {
                    return Err("vm_exit_base_order".into());
                }
                a.mov(rax, qword_ptr(rsp + d32(at)?)).map_err(err)?;
                a.lea(rax, ptr(rax) + d32(off)?).map_err(err)?;
            }
        }
        let m32 = i32::try_from(mask as i64).map_err(|_| "vm_exit_mask".to_string())?;
        a.and(rax, m32).map_err(err)?;
        a.push(rax).map_err(err)?;
    }
    let depth = 16 + 8 * nb;
    let base_at = |k: u32| 8 * (nb - 1 - k as i64);
    let temp = |t: i64| d32(depth + t - exit.rsp_delta);
    // Copy the temporary values into the aligned slots.
    for &(t, k, o, keep) in &exit.temp_stores {
        a.mov(rax, qword_ptr(rsp + d32(base_at(k))?)).map_err(err)?;
        if keep == 0 {
            a.mov(rcx, qword_ptr(rsp + temp(t)?)).map_err(err)?;
            a.mov(qword_ptr(rax + d32(o)?), rcx).map_err(err)?;
        } else {
            // Only the written bytes; the kept ones are the original memory.
            for j in 0..8i64 {
                if keep & (1 << j) == 0 {
                    a.mov(gpr8::cl, byte_ptr(rsp + temp(t + j)?)).map_err(err)?;
                    a.mov(byte_ptr(rax + d32(o + j)?), gpr8::cl).map_err(err)?;
                }
            }
        }
    }
    // Replay the last flag-setting operation. Only mov / lea / pop / jmp follow.
    if let Some(f) = exit.flags {
        let (a_off, b_off, width) = match f {
            FlagsReplay::Cmp { a, b, width } | FlagsReplay::Add { a, b, width } => (a, Some(b), width),
            FlagsReplay::Test { a, width } => (a, None, width),
        };
        a.mov(rax, qword_ptr(rsp + temp(a_off)?)).map_err(err)?;
        if let Some(b) = b_off {
            a.mov(rcx, qword_ptr(rsp + temp(b)?)).map_err(err)?;
        }
        match (f, width) {
            (FlagsReplay::Cmp { .. }, 8) => a.cmp(rax, rcx),
            (FlagsReplay::Cmp { .. }, 4) => a.cmp(gpr32::eax, gpr32::ecx),
            (FlagsReplay::Cmp { .. }, 2) => a.cmp(gpr16::ax, gpr16::cx),
            (FlagsReplay::Cmp { .. }, _) => a.cmp(gpr8::al, gpr8::cl),
            (FlagsReplay::Add { .. }, 8) => a.add(rax, rcx),
            (FlagsReplay::Add { .. }, 4) => a.add(gpr32::eax, gpr32::ecx),
            (FlagsReplay::Add { .. }, 2) => a.add(gpr16::ax, gpr16::cx),
            (FlagsReplay::Add { .. }, _) => a.add(gpr8::al, gpr8::cl),
            (FlagsReplay::Test { .. }, 8) => a.test(rax, rax),
            (FlagsReplay::Test { .. }, 4) => a.test(gpr32::eax, gpr32::eax),
            (FlagsReplay::Test { .. }, 2) => a.test(gpr16::ax, gpr16::ax),
            (FlagsReplay::Test { .. }, _) => a.test(gpr8::al, gpr8::al),
        }
        .map_err(err)?;
    }
    // RSP = final value; the final RAX rides on the new stack top.
    match exit.final_base {
        Some(k) => {
            a.mov(rax, qword_ptr(rsp + d32(base_at(k))?)).map_err(err)?;
            a.lea(rax, ptr(rax) + d32(exit.final_off)?).map_err(err)?;
        }
        None => {
            a.lea(rax, ptr(rsp) + d32(depth + exit.final_off - exit.rsp_delta)?).map_err(err)?;
        }
    }
    a.mov(rcx, qword_ptr(rsp + d32(8 * nb + 8)?)).map_err(err)?; // final RAX
    a.mov(qword_ptr(rax - 8), rcx).map_err(err)?;
    a.mov(rcx, qword_ptr(rsp + d32(8 * nb)?)).map_err(err)?; // final RCX
    a.lea(rsp, ptr(rax) - 8).map_err(err)?;
    a.pop(rax).map_err(err)?;
    a.jmp(target).map_err(err)
}

fn emit_block_outputs_and_jump(
    a: &mut CodeAssembler,
    bitness: u32,
    arena: &ExprArena,
    effects: &[IrEffect],
    pending_caller_stores: &[(i64, ExprId)],
    final_regs: &[ExprId; 16],
    final_xmms: &[(ExprId, ExprId); 16],
    rsp_delta_target: i64,
    pre_ret_pop: bool,
    extra_reg_read: Option<ArchReg>,
    emit_term_fn: impl FnOnce(&mut CodeAssembler, &CodegenCtx<'_>) -> Result<(), String>,
) -> Result<(), String> {
    let reg_limit = if bitness == 64 { 16 } else { 8 };
    let word_bytes = if bitness == 64 { 8i64 } else { 4i64 };

    let mut modified: Vec<(ArchReg, ExprId)> = Vec::new();
    let mut read_inputs: HashSet<ArchReg> = HashSet::new();
    for &r in &ArchReg::ALL[..reg_limit] {
        if r == ArchReg::Rsp {
            continue;
        }
        let expr = final_regs[r.idx()];
        if *arena.get(expr) != ExprNode::RegIn(r) {
            modified.push((r, expr));
            collect_read_regs_into(arena, expr, &mut read_inputs);
        }
    }
    let mut modified_xmms: Vec<(u8, (ExprId, ExprId))> = Vec::new();
    for (i, &(lo, hi)) in final_xmms.iter().enumerate() {
        if *arena.get(lo) != ExprNode::XmmIn(i as u8, false)
            || *arena.get(hi) != ExprNode::XmmIn(i as u8, true)
        {
            if bitness != 64 {
                return Err("modified_xmm_32bit".into());
            }
            modified_xmms.push((i as u8, (lo, hi)));
            collect_read_regs_into(arena, lo, &mut read_inputs);
            collect_read_regs_into(arena, hi, &mut read_inputs);
        }
    }
    if let Some(er) = extra_reg_read {
        read_inputs.insert(er);
    }
    for eff in effects {
        match eff {
            IrEffect::Store { addr, value, .. } => {
                collect_read_regs_into(arena, *addr, &mut read_inputs);
                collect_read_regs_into(arena, *value, &mut read_inputs);
            }
            IrEffect::AtomicCmpXchg { addr, expected_rax, desired, .. } => {
                collect_read_regs_into(arena, *addr, &mut read_inputs);
                collect_read_regs_into(arena, *expected_rax, &mut read_inputs);
                collect_read_regs_into(arena, *desired, &mut read_inputs);
            }
            IrEffect::AtomicRmw { addr, src, .. } => {
                collect_read_regs_into(arena, *addr, &mut read_inputs);
                collect_read_regs_into(arena, *src, &mut read_inputs);
            }
            IrEffect::WriteCr8 { val, .. } => {
                collect_read_regs_into(arena, *val, &mut read_inputs);
            }
            IrEffect::CallNative { .. } => {}
        }
    }
    for &(_, val) in pending_caller_stores {
        collect_read_regs_into(arena, val, &mut read_inputs);
    }

    let mut avoid = read_inputs.clone();
    for &(r, _) in &modified {
        avoid.insert(r);
    }
    // For AtomicCmpXchg avoid using Rax as w0/w1
    if effects.iter().any(|e| matches!(e, IrEffect::AtomicCmpXchg { .. })) {
        avoid.insert(ArchReg::Rax);
    }
    let scratch = pick_three_scratch_regs(bitness, &avoid);

    let direct_plan: Vec<bool> = modified
        .iter()
        .enumerate()
        .map(|(idx, &(dst_reg, expr))| {
            if scratch.contains(&dst_reg) || !expr_safe_in_place(arena, expr, dst_reg) {
                return false;
            }
            let mut remaining_reads: HashSet<ArchReg> = HashSet::new();
            for &(_, later_expr) in &modified[idx + 1..] {
                collect_read_regs_into(arena, later_expr, &mut remaining_reads);
            }
            !remaining_reads.contains(&dst_reg)
        })
        .collect();

    let need_w0 = !pending_caller_stores.is_empty()
        || !effects.is_empty()
        || !modified_xmms.is_empty()
        || direct_plan.iter().any(|&d| !d);
    let need_w1 = effects.iter().any(|e| match e {
        IrEffect::Store { addr, .. } => {
            !matches!(arena.as_stack_offset(*addr), Some((StackSpace::CallerStack, _)))
        }
        IrEffect::AtomicCmpXchg { .. } | IrEffect::AtomicRmw { .. } => true,
        _ => false,
    });
    let need_w2 = pending_caller_stores
        .iter()
        .any(|&(_, v)| expr_uses_spill(arena, bitness, v))
        || effects.iter().any(|e| match e {
            IrEffect::Store { addr, value, .. } => {
                expr_uses_spill(arena, bitness, *value)
                    || (!matches!(arena.as_stack_offset(*addr), Some((StackSpace::CallerStack, _)))
                        && expr_uses_spill(arena, bitness, *addr))
            }
            IrEffect::AtomicCmpXchg { .. } => true,
            IrEffect::AtomicRmw { addr, src, .. } => {
                expr_uses_spill(arena, bitness, *addr) || expr_uses_spill(arena, bitness, *src)
            }
            IrEffect::WriteCr8 { val, .. } => expr_uses_spill(arena, bitness, *val),
            IrEffect::CallNative { .. } => false,
        })
        || modified
            .iter()
            .any(|&(_, expr)| expr_uses_spill(arena, bitness, expr))
        || modified_xmms
            .iter()
            .any(|&(_, (lo, hi))| expr_uses_spill(arena, bitness, lo) || expr_uses_spill(arena, bitness, hi));
    let need_scratch = [need_w0, need_w1, need_w2];

    let mut ctx = CodegenCtx {
        bitness,
        word_bytes,
        arena,
        rsp_depth: 0,
        saved_regs: HashMap::new(),
        scratch,
        eval_steps: 0,
    };

    let final_hw_rsp_delta = if pre_ret_pop {
        rsp_delta_target - word_bytes
    } else {
        rsp_delta_target
    };
    if final_hw_rsp_delta < 0 {
        ctx.emit_rsp_adjust(a, final_hw_rsp_delta)?;
    }

    // Save only scratch registers that this block actually uses AND that must survive
    // (either preserved across the exit or still needed as inputs later in the block).
    let modified_set: HashSet<ArchReg> = modified.iter().map(|&(r, _)| r).collect();
    let mut entry_pushed: Vec<(ArchReg, bool)> = Vec::new();
    let scratch_copy = ctx.scratch;
    for (si, &s) in scratch_copy.iter().enumerate() {
        if !need_scratch[si] {
            continue;
        }
        let needs_preserve = !modified_set.contains(&s);
        let needs_for_read = read_inputs.contains(&s);
        if needs_preserve || needs_for_read {
            ctx.emit_push(a, s)?;
            ctx.saved_regs.insert(s, ctx.rsp_depth);
            entry_pushed.push((s, needs_preserve));
        }
    }

    // Emit caller-frame stack stores (`off >= rsp_delta_target`)
    for &(off, val) in pending_caller_stores {
        let [w0, _, w2] = ctx.scratch;
        ctx.eval_expr_into(a, val, w0, w2)?;
        let rel = ctx.rsp_depth + off;
        let m = mem_disp(ctx.bitness, ArchReg::Rsp, rel, word_bytes as u8);
        ctx.emit_store_to_mem(a, m, w0, word_bytes as u8)?;
    }
    emit_block_effects(a, &mut ctx, effects)?;

    let [w0, _, w2] = ctx.scratch;
    let mut pushed_xmms: Vec<u8> = Vec::new();
    for &(xmm_idx, (lo, hi)) in &modified_xmms {
        ctx.eval_expr_into(a, hi, w0, w2)?;
        ctx.emit_push(a, w0)?;
        ctx.eval_expr_into(a, lo, w0, w2)?;
        ctx.emit_push(a, w0)?;
        pushed_xmms.push(xmm_idx);
    }

    // Evaluate all modified architectural registers directly when acyclic,
    // falling back to stack-pushed staging otherwise.
    let mut pushed_outputs: Vec<ArchReg> = Vec::new();
    for (idx, &(dst_reg, expr)) in modified.iter().enumerate() {
        if direct_plan[idx] {
            ctx.eval_expr_into(a, expr, dst_reg, w2)?;
        } else {
            ctx.eval_expr_into(a, expr, w0, w2)?;
            ctx.emit_push(a, w0)?;
            pushed_outputs.push(dst_reg);
        }
    }

    // Pop evaluated outputs into their target hardware registers (LIFO)
    for dst_reg in pushed_outputs.into_iter().rev() {
        ctx.emit_pop(a, dst_reg)?;
    }
    for xmm_idx in pushed_xmms.into_iter().rev() {
        a.movdqu(to_asm_xmm(xmm_idx), ptr(gpr64::rsp))
            .map_err(|e| e.to_string())?;
        a.lea(gpr64::rsp, ptr(gpr64::rsp) + 16)
            .map_err(|e| e.to_string())?;
        ctx.rsp_depth -= 16;
    }

    // Restore preserved scratch entries; discard non-preserved scratch slots via flag-preserving `lea rsp`
    for &(er, restore) in entry_pushed.iter().rev() {
        if restore {
            ctx.emit_pop(a, er)?;
        } else {
            if ctx.bitness == 64 {
                a.lea(gpr64::rsp, ptr(gpr64::rsp) + ctx.word_bytes as i32)
                    .map_err(|e| e.to_string())?;
            } else {
                a.lea(gpr32::esp, ptr(gpr32::esp) + ctx.word_bytes as i32)
                    .map_err(|e| e.to_string())?;
            }
            ctx.rsp_depth -= ctx.word_bytes;
        }
    }

    ctx.emit_rsp_adjust(a, final_hw_rsp_delta)?;
    emit_term_fn(a, &ctx)
}

fn compile_function_into_asm(
    a: &mut CodeAssembler,
    bitness: u32,
    func: &LiftedFunction,
    entry_lbl: &mut CodeLabel,
) -> Result<(), String> {
    a.set_label(entry_lbl).map_err(|e| e.to_string())?;
    a.zero_bytes().map_err(|e| e.to_string())?;

    let mut block_lbls: Vec<CodeLabel> = (0..func.blocks.len())
        .map(|_| a.create_label())
        .collect();

    for (bi, block) in func.blocks.iter().enumerate() {
        if bi > 0 {
            a.set_label(&mut block_lbls[bi]).map_err(|e| e.to_string())?;
            a.zero_bytes().map_err(|e| e.to_string())?;
        }

        match &block.term {
            IrTerm::CondBranch { cond, taken_block, fallthrough_block } => {
                if bi == 0 && block.effects.is_empty() {
                    if let Some(cc_u8) = as_direct_entry_flag(&func.arena, *cond) {
                        let t_lbl = block_lbls[*taken_block];
                        let f_lbl = block_lbls[*fallthrough_block];
                        match cc_u8 {
                            0 => a.je(t_lbl),
                            1 => a.jne(t_lbl),
                            2 => a.jb(t_lbl),
                            3 => a.jae(t_lbl),
                            4 => a.jbe(t_lbl),
                            5 => a.ja(t_lbl),
                            6 => a.js(t_lbl),
                            7 => a.jns(t_lbl),
                            8 => a.jl(t_lbl),
                            9 => a.jge(t_lbl),
                            10 => a.jle(t_lbl),
                            11 => a.jg(t_lbl),
                            12 => a.jo(t_lbl),
                            _ => a.jno(t_lbl),
                        }
                        .map_err(|e| e.to_string())?;
                        a.jmp(f_lbl).map_err(|e| e.to_string())?;
                        continue;
                    }
                }
                // Evaluate block effects (preserving all inputs) then branch
                let mut avoid = HashSet::new();
                collect_read_regs_into(&func.arena, *cond, &mut avoid);
                for eff in &block.effects {
                    match eff {
                        IrEffect::Store { addr, value, .. } => {
                            collect_read_regs_into(&func.arena, *addr, &mut avoid);
                            collect_read_regs_into(&func.arena, *value, &mut avoid);
                        }
                        IrEffect::AtomicCmpXchg { addr, expected_rax, desired, .. } => {
                            collect_read_regs_into(&func.arena, *addr, &mut avoid);
                            collect_read_regs_into(&func.arena, *expected_rax, &mut avoid);
                            collect_read_regs_into(&func.arena, *desired, &mut avoid);
                            avoid.insert(ArchReg::Rax);
                        }
                        IrEffect::AtomicRmw { addr, src, .. } => {
                            collect_read_regs_into(&func.arena, *addr, &mut avoid);
                            collect_read_regs_into(&func.arena, *src, &mut avoid);
                        }
                        IrEffect::WriteCr8 { val, .. } => {
                            collect_read_regs_into(&func.arena, *val, &mut avoid);
                        }
                        IrEffect::CallNative { .. } => {}
                    }
                }
                let scratch = pick_three_scratch_regs(bitness, &avoid);
                let mut ctx = CodegenCtx {
                    bitness,
                    word_bytes: if bitness == 64 { 8 } else { 4 },
                    arena: &func.arena,
                    rsp_depth: 0,
                    saved_regs: HashMap::new(),
                    scratch,
                    eval_steps: 0,
                };
                // Save scratch registers used by `cond`/`effects`
                let mut pushed_sc = Vec::new();
                let sc_slice = if block.effects.is_empty() {
                    &scratch[..2]
                } else {
                    &scratch[..3]
                };
                for &s in sc_slice {
                    ctx.emit_push(a, s)?;
                    ctx.saved_regs.insert(s, ctx.rsp_depth);
                    pushed_sc.push(s);
                }
                emit_block_effects(a, &mut ctx, &block.effects)?;
                // Compute condition `0/1` into `scratch[2]`? No, emit_branch_on_cond uses flags then restores scratch BEFORE jcc!
                let mut l_taken_tramp = a.create_label();
                ctx.emit_branch_on_cond(a, *cond, &mut l_taken_tramp, scratch[0], scratch[1])?;
                // Fallthrough path: restore scratch & jump to fallthrough block
                for &s in pushed_sc.iter().rev() {
                    ctx.emit_pop(a, s)?;
                }
                let fall_lbl = block_lbls[*fallthrough_block];
                a.jmp(fall_lbl).map_err(|e| e.to_string())?;
                // Taken path: restore scratch (keep flags not needed at target!) & jump to taken block
                a.set_label(&mut l_taken_tramp).map_err(|e| e.to_string())?;
                a.zero_bytes().map_err(|e| e.to_string())?;
                for &s in pushed_sc.iter().rev() {
                    // Restore `RSP` increment without touching stack? No, `pop` restores `s` AND `RSP`!
                    if bitness == 64 {
                        a.pop(to_asm64(s)).map_err(|e| e.to_string())?;
                    } else {
                        a.pop(to_asm32(s)).map_err(|e| e.to_string())?;
                    }
                }
                let t_lbl = block_lbls[*taken_block];
                a.jmp(t_lbl).map_err(|e| e.to_string())?;
            }
            IrTerm::ExitRet { rsp_delta, final_regs, final_xmms, pending_caller_stores, .. } => {
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    true,
                    None,
                    |asm, _| asm.ret().map_err(|e| e.to_string()),
                )?;
            }
            IrTerm::ExitJmp { target_va, rsp_delta, final_regs, final_xmms, pending_caller_stores, .. } => {
                let tva = *target_va;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    false,
                    None,
                    |asm, _| asm.jmp(tva).map_err(|e| e.to_string()),
                )?;
            }
            IrTerm::ExitCall { target_va, ret_va, rsp_delta, final_regs, final_xmms, pending_caller_stores, .. } => {
                let tva = *target_va;
                let rva = *ret_va;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    false,
                    None,
                    |asm, ctx| {
                        // Push `ret_va` and jump directly to `target_va`
                        if ctx.bitness == 64 {
                            if let Ok(r32) = i32::try_from(rva as i64) {
                                asm.push(r32).map_err(|e| e.to_string())?;
                            } else {
                                let hi = (rva >> 32) as u32 as i32;
                                let lo = rva as u32 as i32;
                                asm.sub(gpr64::rsp, 8).map_err(|e| e.to_string())?;
                                asm.mov(dword_ptr(gpr64::rsp), lo).map_err(|e| e.to_string())?;
                                asm.mov(dword_ptr(gpr64::rsp + 4), hi).map_err(|e| e.to_string())?;
                            }
                        } else {
                            asm.push(rva as i32).map_err(|e| e.to_string())?;
                        }
                        asm.jmp(tva).map_err(|e| e.to_string())
                    },
                )?;
            }
            IrTerm::ExitAddJmp { reg, rsp_delta, final_regs, final_xmms, .. } => {
                let dst_reg = *reg;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    &[],
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    false,
                    Some(dst_reg),
                    |asm, ctx| {
                        // `final_regs[dst_reg]` already materialized `dst_reg = RegIn + disp`
                        if ctx.bitness == 64 {
                            asm.jmp(to_asm64(dst_reg)).map_err(|e| e.to_string())
                        } else {
                            asm.jmp(to_asm32(dst_reg)).map_err(|e| e.to_string())
                        }
                    },
                )?;
            }
            IrTerm::ExitToVm { va, exit, final_regs, final_xmms } => {
                if bitness != 64 {
                    return Err("vm_exit_32bit".into());
                }
                let target = *va;
                let exit = exit.as_ref().clone();
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    &exit.pending,
                    final_regs,
                    final_xmms,
                    exit.rsp_delta,
                    false,
                    None,
                    |asm, _| emit_vm_exit(asm, &exit, target),
                )?;
            }
            IrTerm::ExitIndirectMem { rsp_disp, rsp_delta, final_regs, final_xmms, pending_caller_stores, .. } => {
                let d32 = i32::try_from(*rsp_disp).map_err(|_| "exit_ind_mem_disp_i32".to_string())?;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    false,
                    None,
                    |asm, ctx| {
                        let m = mem_disp(ctx.bitness, ArchReg::Rsp, d32 as i64, ctx.word_bytes as u8);
                        asm.jmp(m).map_err(|e| e.to_string())
                    },
                )?;
            }
            IrTerm::MidCall { target, rsp_delta, final_regs, final_xmms, pending_caller_stores, cont_block, .. } => {
                let target = *target;
                let c_lbl = block_lbls[*cont_block];
                let extra_read = match target {
                    MidCallTarget::IndirectReg(r) => Some(r),
                    _ => None,
                };
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    false,
                    extra_read,
                    |asm, ctx| {
                        match target {
                            MidCallTarget::DirectVa(va) => asm.call(va),
                            MidCallTarget::CallerStackSlot(disp) => {
                                let d32 = i32::try_from(disp).map_err(|_| "midcall_disp_i32".to_string())?;
                                let m = mem_disp(ctx.bitness, ArchReg::Rsp, d32 as i64, ctx.word_bytes as u8);
                                asm.call(m)
                            }
                            MidCallTarget::IndirectRipMem(mem_va) => {
                                if ctx.bitness == 64 {
                                    asm.call(qword_ptr(Register::RIP) + (mem_va as i64))
                                } else {
                                    asm.call(dword_ptr(mem_va as u32 as i64))
                                }
                            }
                            MidCallTarget::IndirectReg(r) => {
                                if ctx.bitness == 64 {
                                    asm.call(to_asm64(r))
                                } else {
                                    asm.call(to_asm32(r))
                                }
                            }
                        }
                        .map_err(|e| e.to_string())?;
                        asm.jmp(c_lbl).map_err(|e| e.to_string())
                    },
                )?;
            }
            IrTerm::Bailout(r) => return Err(r.clone()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Top-Level Binary Devirtualization Pipeline
// ---------------------------------------------------------------------------

pub fn devirtualize_pe_bytes(
    pe_bytes: &[u8],
    cfg: BinaryDevirtConfig,
) -> UnpackerResult<(Vec<u8>, BinaryDevirtReport)> {
    let view = PeImageView::from_pe_bytes(pe_bytes)?;
    let discovered = discover_vm_entries(&view, &cfg);

    let discovered_total = discovered.len();
    let discovered_vmenters = discovered
        .iter()
        .filter(|e| e.kind == VmEntryKind::CrossSectionVmEnter)
        .count();
    let discovered_trampolines = discovered
        .iter()
        .filter(|e| e.kind == VmEntryKind::IndirectBranchTrampoline)
        .count();
    let discovered_standalone = discovered
        .iter()
        .filter(|e| e.kind == VmEntryKind::StandaloneVmStub)
        .count();

    let mut bailout_counts: HashMap<String, usize> = HashMap::new();
    let mut bailout_kind_counts: HashMap<(VmEntryKind, String), usize> = HashMap::new();
    let mut bailout_sample_counts: HashMap<(VmEntryKind, String), usize> = HashMap::new();
    let mut bailout_samples: Vec<(VmEntryKind, u32, u64, String, String)> = Vec::new();
    let mut ij_clusters: HashMap<(VmEntryKind, u64, String), usize> = HashMap::new();
    let mut visited_vm_bytes: HashSet<u64> = HashSet::new();
    let mut partially_lifted = 0usize;
    let mut failed = 0usize;

    let mut compiled_funcs: Vec<(LiftedFunction, Vec<u8>)> = Vec::new();
    let (next_rva, _) = imagedump::next_section_rva(pe_bytes)?;
    let devirt_base_va = view.image_base + next_rva as u64;

    for entry in &discovered {
        let lifted = lift_vm_entry_cfg(&view, entry, &cfg);
        visited_vm_bytes.extend(&lifted.visited_byte_addrs);

        let mut record_bailout = |reason: String, lifted_ref: &LiftedFunction, post_lift: bool| {
            if post_lift || lifted_ref.raw_vm_insns > 0 {
                partially_lifted += 1;
            } else {
                failed += 1;
            }
            *bailout_counts.entry(reason.clone()).or_insert(0) += 1;
            *bailout_kind_counts.entry((entry.kind, reason.clone())).or_insert(0) += 1;
            if cfg.collect_diagnostics {
                let (bip, detail) = lifted_ref.bailout_detail.as_ref().map_or_else(
                    || {
                        (
                            view.image_base + entry.target_rva as u64,
                            format!(
                                "post_lift({reason}) blks={} insns={}",
                                lifted_ref.blocks.len(),
                                lifted_ref.raw_vm_insns
                            ),
                        )
                    },
                    |(ip, d)| (*ip, d.clone()),
                );
                if reason == "unresolved_indirect_jmp" {
                    let mut parts = detail.splitn(3, " | ");
                    let p0 = parts.next().unwrap_or("");
                    let p1 = parts.next().unwrap_or("");
                    let tag_and_insn = if p1.is_empty() {
                        p0.to_string()
                    } else {
                        format!("{p0} | {p1}")
                    };
                    *ij_clusters.entry((entry.kind, bip, tag_and_insn)).or_insert(0) += 1;
                }
                let sc = bailout_sample_counts.entry((entry.kind, reason.clone())).or_insert(0);
                if *sc < 4 && bailout_samples.len() < 60 {
                    *sc += 1;
                    bailout_samples.push((entry.kind, entry.patch_rva, bip, reason, detail));
                }
            }
        };

        if let Err(reason) = validate_function_soundness(&lifted, &view) {
            record_bailout(reason, &lifted, false);
            continue;
        }

        // Compile standalone test snippet first to verify encodability and check instruction reduction
        let mut test_asm = CodeAssembler::new(view.bitness)
            .map_err(|e| UnpackerError::General(format!("CodeAssembler: {e}")))?;
        let mut test_lbl = test_asm.create_label();
        if let Err(err) = compile_function_into_asm(&mut test_asm, view.bitness, &lifted, &mut test_lbl) {
            record_bailout(format!("codegen_{err}"), &lifted, true);
            continue;
        }
        let Ok(test_res) = test_asm.assemble_options(devirt_base_va, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS) else {
            record_bailout("asm_encode_failed".into(), &lifted, true);
            continue;
        };

        // Decode emitted bytes to ensure 100% valid instructions & count native instruction count
        let buf = test_res.inner.code_buffer;
        let mut dec = Decoder::with_ip(view.bitness, &buf, devirt_base_va, DecoderOptions::NONE);
        let mut native_insns = 0usize;
        let mut invalid = false;
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.is_invalid() {
                invalid = true;
                break;
            }
            native_insns += 1;
        }
        if invalid || native_insns == 0 {
            record_bailout("invalid_emitted_insn".into(), &lifted, true);
            continue;
        }

        // Enforce genuine code reduction on VM enters, and on anything that hands
        // control back to the VM (a stub that only re-enters the VM is no gain).
        let has_vm_exit = lifted.blocks.iter().any(|b| matches!(b.term, IrTerm::ExitToVm { .. }));
        if (entry.kind == VmEntryKind::CrossSectionVmEnter || has_vm_exit)
            && (native_insns >= lifted.raw_vm_insns || (has_vm_exit && lifted.raw_vm_insns == 0))
        {
            record_bailout("no_code_reduction".into(), &lifted, true);
            continue;
        }

        compiled_funcs.push((lifted, buf));
    }

    // Re-assemble all sound stubs cleanly into one shared `.devirt` section so internal jumps stay compact
    let mut out_pe = pe_bytes.to_vec();
    let mut devirt_section_rva = None;
    let mut devirt_section_size = 0usize;
    let mut patched_sites = Vec::new();
    let mut devirtualized_vmenters = 0usize;
    let mut hybrid_vm_exits = 0usize;
    let mut devirtualized_trampolines = 0usize;
    let mut raw_vm_insns_eliminated = 0usize;
    let mut recompiled_native_insns = 0usize;
    let mut opaque_branches_folded = 0usize;

    if !compiled_funcs.is_empty() {
        let mut master_asm = CodeAssembler::new(view.bitness)
            .map_err(|e| UnpackerError::General(format!("CodeAssembler: {e}")))?;
        let mut stub_labels = Vec::with_capacity(compiled_funcs.len());
        let mut stub_native_counts = Vec::with_capacity(compiled_funcs.len());

        for (lifted, buf_preview) in &compiled_funcs {
            let mut dec = Decoder::with_ip(view.bitness, buf_preview, devirt_base_va, DecoderOptions::NONE);
            let mut n_cnt = 0usize;
            while dec.can_decode() {
                let _ = dec.decode();
                n_cnt += 1;
            }
            stub_native_counts.push(n_cnt);

            let mut lbl = master_asm.create_label();
            compile_function_into_asm(&mut master_asm, view.bitness, lifted, &mut lbl)
                .map_err(|e| UnpackerError::General(format!("master compile failed: {e}")))?;
            stub_labels.push(lbl);
        }

        let asm_res = master_asm
            .assemble_options(devirt_base_va, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .map_err(|e| UnpackerError::General(format!("master assemble failed: {e}")))?;
        let section_bytes = asm_res.inner.code_buffer.clone();
        devirt_section_size = section_bytes.len();

        let appended_rva = imagedump::append_code_section(&mut out_pe, ".devirt", &section_bytes)?;
        if appended_rva != next_rva {
            return Err(UnpackerError::General(format!(
                ".devirt RVA mismatch: predicted {next_rva:#x}, got {appended_rva:#x}"
            )));
        }
        devirt_section_rva = Some(appended_rva);

        let (_dos, _pe, _opt, out_secs) = parse_pe_bytes(&out_pe)?;
        for (idx, (lifted, _)) in compiled_funcs.iter().enumerate() {
            let stub_va = asm_res
                .label_ip(&stub_labels[idx])
                .map_err(|e| UnpackerError::General(format!("label_ip: {e}")))?;
            let stub_rva = (stub_va - view.image_base) as u32;
            let e = &lifted.entry;

            if e.patch_size >= 5 {
                let Some(raw_off) = pe_rva_to_raw(&out_secs, e.patch_rva, out_pe.len()) else {
                    continue;
                };
                if raw_off + e.patch_size > out_pe.len() {
                    continue;
                }
                let rel32 = (stub_rva as i64 - (e.patch_rva as i64 + 5)) as i32;
                out_pe[raw_off] = if e.is_call { 0xE8 } else { 0xE9 };
                out_pe[raw_off + 1..raw_off + 5].copy_from_slice(&rel32.to_le_bytes());
                for b in &mut out_pe[raw_off + 5..raw_off + e.patch_size] {
                    *b = 0x90;
                }
            }

            let n_insns = stub_native_counts[idx];
            raw_vm_insns_eliminated += lifted.raw_vm_insns;
            recompiled_native_insns += n_insns;
            opaque_branches_folded += lifted.opaque_branches_folded;
            if lifted.blocks.iter().any(|b| matches!(b.term, IrTerm::ExitToVm { .. })) {
                hybrid_vm_exits += 1;
            }
            match e.kind {
                VmEntryKind::CrossSectionVmEnter => devirtualized_vmenters += 1,
                VmEntryKind::IndirectBranchTrampoline => devirtualized_trampolines += 1,
                VmEntryKind::StandaloneVmStub => {}
            }
            patched_sites.push(PatchedSiteInfo {
                kind: e.kind,
                patch_rva: e.patch_rva,
                patch_size: e.patch_size,
                stub_rva,
                raw_vm_insns: lifted.raw_vm_insns,
                native_insns: n_insns,
                opaque_branches_folded: lifted.opaque_branches_folded,
            });
        }

        imagedump::fix_checksum(&mut out_pe)?;
    }

    let devirtualized_total = patched_sites.len();
    let entry_devirt_pct = if discovered_total > 0 {
        100.0 * (devirtualized_total as f64) / (discovered_total as f64)
    } else {
        0.0
    };
    let code_reduction_pct = if raw_vm_insns_eliminated > 0 {
        100.0 * (1.0 - (recompiled_native_insns as f64 / raw_vm_insns_eliminated as f64)).max(0.0)
    } else {
        0.0
    };
    let unique_vm_bytes_visited = visited_vm_bytes.len();
    let vm_byte_coverage_pct = if view.total_vm_section_bytes > 0 {
        100.0 * (unique_vm_bytes_visited as f64) / (view.total_vm_section_bytes as f64)
    } else {
        0.0
    };

    let mut bailout_reasons: Vec<(String, usize)> = bailout_counts.into_iter().collect();
    bailout_reasons.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut bailouts_by_kind: Vec<(VmEntryKind, String, usize)> = bailout_kind_counts
        .into_iter()
        .map(|((k, r), c)| (k, r, c))
        .collect();
    bailouts_by_kind.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)).then_with(|| a.1.cmp(&b.1)));

    let mut indirect_jmp_ip_clusters: Vec<(VmEntryKind, u64, String, usize)> = ij_clusters
        .into_iter()
        .map(|((k, ip, tag), c)| (k, ip, tag, c))
        .collect();
    indirect_jmp_ip_clusters.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)).then_with(|| a.1.cmp(&b.1)));
    indirect_jmp_ip_clusters.truncate(30);

    Ok((
        out_pe,
        BinaryDevirtReport {
            is_64: view.bitness == 64,
            discovered_total,
            discovered_vmenters,
            discovered_trampolines,
            discovered_standalone,
            devirtualized_total,
            devirtualized_vmenters,
            devirtualized_trampolines,
            partially_lifted,
            hybrid_vm_exits,
            failed,
            entry_devirt_pct,
            raw_vm_insns_eliminated,
            recompiled_native_insns,
            code_reduction_pct,
            opaque_branches_folded,
            unique_vm_bytes_visited,
            total_vm_section_bytes: view.total_vm_section_bytes,
            vm_byte_coverage_pct,
            devirt_section_rva,
            devirt_section_size,
            bailout_reasons,
            bailouts_by_kind,
            bailout_samples,
            indirect_jmp_ip_clusters,
            patched_sites,
        },
    ))
}

// ---------------------------------------------------------------------------
// Tests (Unit + End-to-End Unicorn Semantic Equivalence)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpacker::engine::{Sample, UnpackerEngine};
    use unicorn_engine::RegisterX86;

    fn assemble_at(bitness: u32, va: u64, build: impl FnOnce(&mut CodeAssembler) -> Result<(), iced_x86::IcedError>) -> Vec<u8> {
        let mut a = CodeAssembler::new(bitness).unwrap();
        build(&mut a).unwrap();
        a.assemble(va).unwrap()
    }

    fn build_two_exec_pe64(text_code: &[u8], vmp_code: &[u8], oep_rva: u32) -> Vec<u8> {
        // Sections:
        // [0] .text  VA=0x1000, rptr=0x0400, size=0x1000
        // [1] .vmp0  VA=0x2000, rptr=0x1400, size=0x1000
        // [2] .data  VA=0x3000, rptr=0x2400, size=0x1000
        let mut pe = vec![0u8; 0x3400];
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
        pe[opt + 16..opt + 20].copy_from_slice(&oep_rva.to_le_bytes());
        pe[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        pe[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let secs = [
            (b".text\0\0\0", 0x1000u32, 0x0400u32, 0x6000_0020u32),
            (b".vmp0\0\0\0", 0x2000u32, 0x1400u32, 0x6000_0020u32),
            (b".data\0\0\0", 0x3000u32, 0x2400u32, 0xC000_0040u32),
        ];
        for (i, (nm, va, rptr, sec_chars)) in secs.iter().enumerate() {
            let o = opt + 240 + i * 40;
            pe[o..o + 8].copy_from_slice(*nm);
            pe[o + 8..o + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            pe[o + 16..o + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            pe[o + 20..o + 24].copy_from_slice(&rptr.to_le_bytes());
            pe[o + 36..o + 40].copy_from_slice(&sec_chars.to_le_bytes());
        }

        pe[0x400..0x400 + text_code.len().min(0x1000)].copy_from_slice(&text_code[..text_code.len().min(0x1000)]);
        pe[0x1400..0x1400 + vmp_code.len().min(0x1000)].copy_from_slice(&vmp_code[..vmp_code.len().min(0x1000)]);
        pe
    }

    #[test]
    fn e2e_context_frame_vm_and_trampoline_devirt_equivalence() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        // Build `.text`:
        // 0x1000: fn1 wrapper: jmp vmenter_stub (@ 0x2000)
        // 0x1020: fn2 trampoline test:
        //   mov r10, 0x1050 (branch 0 target in .text)
        //   mov r11, 0x1060 (branch 1 target in .text)
        //   test eax, eax
        //   cmovne r10, r11
        //   jmp tramp_stub (@ 0x2200)
        // 0x1050: mov eax, 0x1111; ret
        // 0x1060: mov eax, 0x2222; ret
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn1 = assemble_at(64, base + 0x1000, |a| {
            a.jmp(base + 0x2000)
        });
        text_sec[0..fn1.len()].copy_from_slice(&fn1);

        let fn2 = assemble_at(64, base + 0x1020, |a| {
            // Compute RVAs relative to `.data`/base via table offset
            a.mov(r10, 0x0050i64)?;
            a.mov(r11, 0x0060i64)?;
            a.test(eax, eax)?;
            a.cmovne(r10, r11)?;
            a.jmp(base + 0x2200)
        });
        text_sec[0x20..0x20 + fn2.len()].copy_from_slice(&fn2);

        let t0 = assemble_at(64, base + 0x1050, |a| {
            a.mov(eax, 0x1111)?;
            a.ret()
        });
        text_sec[0x50..0x50 + t0.len()].copy_from_slice(&t0);

        let t1 = assemble_at(64, base + 0x1060, |a| {
            a.mov(eax, 0x2222)?;
            a.ret()
        });
        text_sec[0x60..0x60 + t1.len()].copy_from_slice(&t1);

        // Build `.vmp0`:
        // 0x2000: context-frame VM stub:
        //   lea rsp, [rsp - 0x1C0]
        //   call ctx_save (0x2100)
        //   mov rax, [r12 + 0x20]         ; load input RCX
        //   ; Opaque predicate: (rax * (rax - 1)) & 1 -> always 0
        //   lea r8, [rax - 1]
        //   imul r8, rax
        //   and r8, 1
        //   ; MBA addition: rdx = (rax ^ 0x42) + 2*(rax & 0x42)  (= rax + 0x42)
        //   mov rdx, rax
        //   xor rdx, 0x42
        //   mov r9, rax
        //   and r9, 0x42
        //   shl r9, 1
        //   add rdx, r9
        //   ; Conditional branch on RCX > 10: write 0xCAFE or 0xBEEF to global [base + 0x3000]
        //   cmp rax, 10
        //   ja branch_hi
        //   add rdx, 100
        //   mov qword_ptr(0x140003000), 0xBEEF
        //   jmp exit_vm
        // branch_hi:
        //   add rdx, r8                   ; + 0 (opaque!)
        //   add rdx, 200
        //   mov qword_ptr(0x140003000), 0xCAFE
        // exit_vm:
        //   mov [r12 + 0x10], rdx         ; return RAX = rdx via restored slot
        //   call ctx_restore (0x2140)
        //   lea rsp, [rsp + 0x1C0]
        //   ret
        let mut vmp_sec = vec![0xCCu8; 0x300];
        let mut vm_asm = {
            use gpr64::*;
            use xmm::*;
            let mut vm_asm = CodeAssembler::new(64).unwrap();
            let mut lbl_hi = vm_asm.create_label();
            let mut lbl_exit = vm_asm.create_label();
            let mut lbl_save = vm_asm.create_label();
            let mut lbl_rest = vm_asm.create_label();

            // Main VM stub
            vm_asm.lea(rsp, ptr(rsp) - 0x1C0).unwrap();
            vm_asm.call(lbl_save).unwrap();
            vm_asm.mov(rax, qword_ptr(r12 + 0x20)).unwrap();
            vm_asm.lea(r8, ptr(rax) - 1).unwrap();
            vm_asm.imul_2(r8, rax).unwrap();
            vm_asm.and(r8, 1).unwrap();

            // MBA: (rax ^ 0x42) + ((rax & 0x42) << 1) == rax + 0x42
            vm_asm.mov(rdx, rax).unwrap();
            vm_asm.xor(rdx, 0x42).unwrap();
            vm_asm.mov(r9, rax).unwrap();
            vm_asm.and(r9, 0x42).unwrap();
            vm_asm.shl(r9, 1).unwrap();
            vm_asm.add(rdx, r9).unwrap();

            // Global pointer in r10 -> 0x1_4000_3000
            vm_asm.mov(r10, base + 0x3000).unwrap();
            vm_asm.cmp(rax, 10).unwrap();
            vm_asm.ja(lbl_hi).unwrap();
            vm_asm.add(rdx, 100).unwrap();
            vm_asm.mov(dword_ptr(r10), 0xBEEFu32 as i32).unwrap();
            vm_asm.jmp(lbl_exit).unwrap();

            vm_asm.set_label(&mut lbl_hi).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.add(rdx, r8).unwrap();
            vm_asm.add(rdx, 200).unwrap();
            vm_asm.mov(dword_ptr(r10), 0xCAFEu32 as i32).unwrap();

            vm_asm.set_label(&mut lbl_exit).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.mov(qword_ptr(r12 + 0x10), rdx).unwrap();
            vm_asm.call(lbl_rest).unwrap();
            vm_asm.lea(rsp, ptr(rsp) + 0x1C0).unwrap();
            vm_asm.ret().unwrap();

            // ctx_save: [rsp+8..]: save rax(+0x10), rcx(+0x20), rbx(+0x30), r12(+0x40), xmm3(+0x50..0x60), rdx/r8/r9/r10(+0x60..0x80), r12 = rsp+8
            vm_asm.set_label(&mut lbl_save).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x18), rax).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x28), rcx).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x38), rbx).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x48), r12).unwrap();
            vm_asm.movups(ptr(rsp + 0x58), xmm3).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x68), rdx).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x70), r8).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x78), r9).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x80), r10).unwrap();
            vm_asm.lea(r12, ptr(rsp) + 8).unwrap();
            vm_asm.ret().unwrap();

            // ctx_restore: restore from r12 (= rsp + 8 inside frame)
            vm_asm.set_label(&mut lbl_rest).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.mov(r10, qword_ptr(r12 + 0x78)).unwrap();
            vm_asm.mov(r9, qword_ptr(r12 + 0x70)).unwrap();
            vm_asm.mov(r8, qword_ptr(r12 + 0x68)).unwrap();
            vm_asm.mov(rdx, qword_ptr(r12 + 0x60)).unwrap();
            vm_asm.movups(xmm3, ptr(r12 + 0x50)).unwrap();
            vm_asm.mov(rbx, qword_ptr(r12 + 0x30)).unwrap();
            vm_asm.mov(rcx, qword_ptr(r12 + 0x20)).unwrap();
            vm_asm.mov(rax, qword_ptr(r12 + 0x10)).unwrap();
            vm_asm.mov(r12, qword_ptr(r12 + 0x40)).unwrap();
            vm_asm.ret().unwrap();
            vm_asm
        };

        let vm_bytes = vm_asm.assemble(base + 0x2000).unwrap();
        vmp_sec[..vm_bytes.len()].copy_from_slice(&vm_bytes);

        // Build trampoline at 0x2200: push rax; lea rax, [rip -> 0x140001000]; lea r10, [r10+rax]; pop rax; jmp r10
        let tr_bytes = assemble_at(64, base + 0x2200, |tr_asm| {
            use gpr64::*;
            tr_asm.push(rax)?;
            tr_asm.mov(rax, base + 0x1000)?;
            tr_asm.lea(r10, ptr(r10 + rax))?;
            tr_asm.pop(rax)?;
            tr_asm.jmp(r10)
        });
        vmp_sec[0x200..0x200 + tr_bytes.len()].copy_from_slice(&tr_bytes);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();

        assert_eq!(report.discovered_total, 2, "expected 1 vmenter + 1 trampoline, got {report:?}");
        assert_eq!(
            report.devirtualized_total, 2,
            "expected both sites devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );
        assert!(report.devirt_section_rva.is_some());
        assert!(report.recompiled_native_insns < report.raw_vm_insns_eliminated);
        assert!(report.opaque_branches_folded == 0 || report.raw_vm_insns_eliminated > 15);

        // Verify semantic equivalence in Unicorn between original PE and devirtualized PE!
        let run_case = |pe_bytes: &[u8], rva: u32, rcx_in: u64, rax_in: u64| -> (u64, u64, u64, u32, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            let rsp_before = {
                let uc = eng.unicorn_mut().unwrap();
                uc.reg_write(RegisterX86::RBX as i32, 0x1122_3344_5566_7788).unwrap();
                uc.reg_write(RegisterX86::R12 as i32, 0x8877_6655_4433_2211).unwrap();
                uc.reg_write(RegisterX86::RCX as i32, rcx_in).unwrap();
                uc.reg_write(RegisterX86::RAX as i32, rax_in).unwrap();
                uc.reg_read(RegisterX86::RSP as i32).unwrap()
            };
            let ret = eng.call_function(base + rva as u64, &[rcx_in], 100_000, 2_000).unwrap();
            let uc = eng.unicorn_mut().unwrap();
            let rsp_after = uc.reg_read(RegisterX86::RSP as i32).unwrap();
            let rbx_after = uc.reg_read(RegisterX86::RBX as i32).unwrap();
            let r12_after = uc.reg_read(RegisterX86::R12 as i32).unwrap();
            let mut mem_buf = [0u8; 4];
            uc.mem_read(base + 0x3000, &mut mem_buf).unwrap();
            (ret, rbx_after, r12_after, u32::from_le_bytes(mem_buf), rsp_after.wrapping_sub(rsp_before))
        };

        // Branch 1: RCX = 5 (<= 10) -> RAX = 5 + 0x42 + 100, global = 0xBEEF
        assert_eq!(run_case(&orig_pe, 0x1000, 5, 0), run_case(&devirt_pe, 0x1000, 5, 0));
        // Branch 2: RCX = 25 (> 10) -> RAX = 25 + 0x42 + 200, global = 0xCAFE
        assert_eq!(run_case(&orig_pe, 0x1000, 25, 0), run_case(&devirt_pe, 0x1000, 25, 0));

        // Check trampolines (fn2 uses EAX=0 vs EAX=1 via raw RIP run)
        let run_tramp = |pe_bytes: &[u8], eax_in: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.reg_write(RegisterX86::RAX as i32, eax_in).unwrap();
            }
            eng.call_function(base + 0x1020, &[], 100_000, 2_000).unwrap();
            eng.unicorn_mut().unwrap().reg_read(RegisterX86::RAX as i32).unwrap()
        };
        assert_eq!(run_tramp(&orig_pe, 0), 0x1111);
        assert_eq!(run_tramp(&devirt_pe, 0), 0x1111);
        assert_eq!(run_tramp(&orig_pe, 1), 0x2222);
        assert_eq!(run_tramp(&devirt_pe, 1), 0x2222);
    }

    #[test]
    fn rip_relative_trampoline_and_midcall_devirt_equivalence() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        // `.text`:
        // 0x1000: fn1 -> mov r10, 0x40; jmp vmp_trampoline (0x2000)
        // 0x1020: helper(ecx) -> lea eax, [rcx + 0x10]; ret
        // 0x1040: trampoline target -> mov eax, 0x7777; ret
        // 0x1060: fn2(ecx) -> push helper_va; call vmenter (0x2100); pop rdx; ret
        // 0x1080: intra-VM `.text` continuation -> add [r12+0x20], 5; jmp via rax back to 0x2120
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn1 = assemble_at(64, base + 0x1000, |a| {
            a.mov(r10, 0x40i64)?;
            a.jmp(base + 0x2000)
        });
        text_sec[0..fn1.len()].copy_from_slice(&fn1);

        let helper = assemble_at(64, base + 0x1020, |a| {
            a.lea(eax, ptr(rcx) + 0x10)?;
            a.ret()
        });
        text_sec[0x20..0x20 + helper.len()].copy_from_slice(&helper);

        let t40 = assemble_at(64, base + 0x1040, |a| {
            a.mov(eax, 0x7777)?;
            a.ret()
        });
        text_sec[0x40..0x40 + t40.len()].copy_from_slice(&t40);

        let fn2 = assemble_at(64, base + 0x1060, |a| {
            a.mov(rax, base + 0x1020)?;
            a.push(rax)?;
            a.call(base + 0x2100)?;
            a.pop(rdx)?;
            a.ret()
        });
        text_sec[0x60..0x60 + fn2.len()].copy_from_slice(&fn2);

        // `.vmp0`:
        // 0x2000: RIP-relative trampoline: push r14; lea r14, [rip -> 0x140001000]; lea r10, [r10+r14]; pop r14; jmp r10
        let mut vmp_sec = vec![0xCCu8; 0x400];
        let tramp = assemble_at(64, base + 0x2000, |a| {
            a.push(r14)?;
            a.lea(r14, ptr(Register::RIP) + (base + 0x1000) as i64)?;
            a.lea(r10, ptr(r10 + r14))?;
            a.pop(r14)?;
            a.jmp(r10)
        });
        vmp_sec[..tramp.len()].copy_from_slice(&tramp);

        // 0x2100: context-frame VM stub with intra-VM `.text` hop + MidCall (`call qword ptr [rsp+8]`)
        let mut vm_asm = CodeAssembler::new(64).unwrap();
        let mut lbl_mid = vm_asm.create_label();
        let mut lbl_save = vm_asm.create_label();
        let mut lbl_rest = vm_asm.create_label();
        {
            // Block 0 entry @ 0x2100
            vm_asm.lea(rsp, ptr(rsp) - 0x1C0).unwrap();
            vm_asm.call(lbl_save).unwrap();
            vm_asm.and(rsp, -0x10i32).unwrap();
            vm_asm.sub(rsp, 8).unwrap();
            vm_asm.jmp(base + 0x1080).unwrap();

            // Mid entry reached via indirect jump from `.text` continuation @ 0x1080
            vm_asm.set_label(&mut lbl_mid).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.mov(rsp, r12).unwrap();
            vm_asm.call(lbl_rest).unwrap();
            vm_asm.lea(rsp, ptr(rsp) + 0x1C0).unwrap();
            vm_asm.call(qword_ptr(rsp + 8)).unwrap();
            // Post-MidCall continuation
            vm_asm.lea(rsp, ptr(rsp) - 0x1C0).unwrap();
            vm_asm.call(lbl_save).unwrap();
            vm_asm.and(rsp, -0x10i32).unwrap();
            vm_asm.sub(rsp, 8).unwrap();
            vm_asm.mov(rdx, qword_ptr(r12 + 0x10)).unwrap();
            vm_asm.add(rdx, 0x100).unwrap();
            vm_asm.mov(qword_ptr(r12 + 0x10), rdx).unwrap();
            vm_asm.mov(rsp, r12).unwrap();
            vm_asm.call(lbl_rest).unwrap();
            vm_asm.lea(rsp, ptr(rsp) + 0x1C0).unwrap();
            vm_asm.ret().unwrap();

            vm_asm.set_label(&mut lbl_save).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x18), rax).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x28), rcx).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x38), rdx).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x48), rbx).unwrap();
            vm_asm.mov(qword_ptr(rsp + 0x58), r12).unwrap();
            vm_asm.lea(r12, ptr(rsp) + 8).unwrap();
            vm_asm.ret().unwrap();

            vm_asm.set_label(&mut lbl_rest).unwrap();
            vm_asm.zero_bytes().unwrap();
            vm_asm.mov(rbx, qword_ptr(r12 + 0x40)).unwrap();
            vm_asm.mov(rdx, qword_ptr(r12 + 0x30)).unwrap();
            vm_asm.mov(rcx, qword_ptr(r12 + 0x20)).unwrap();
            vm_asm.mov(rax, qword_ptr(r12 + 0x10)).unwrap();
            vm_asm.mov(r12, qword_ptr(r12 + 0x50)).unwrap();
            vm_asm.ret().unwrap();
        }
        let vm_res = vm_asm
            .assemble_options(base + 0x2100, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();
        let mid_va = vm_res.label_ip(&lbl_mid).unwrap();
        let vm_bytes = vm_res.inner.code_buffer;
        vmp_sec[0x100..0x100 + vm_bytes.len()].copy_from_slice(&vm_bytes);

        let cont_text = assemble_at(64, base + 0x1080, |a| {
            a.mov(rax, qword_ptr(r12 + 0x20))?;
            a.add(rax, 5)?;
            a.mov(qword_ptr(r12 + 0x20), rax)?;
            a.mov(rax, mid_va)?;
            a.jmp(rax)
        });
        text_sec[0x80..0x80 + cont_text.len()].copy_from_slice(&cont_text);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1060);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();

        assert_eq!(report.discovered_total, 2, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 2,
            "expected both RIP trampoline & MidCall vmenter devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );
        assert!(report.devirt_section_rva.is_some());

        let run_fn1 = |pe_bytes: &[u8]| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[], 100_000, 2_000).unwrap()
        };
        assert_eq!(run_fn1(&orig_pe), 0x7777);
        assert_eq!(run_fn1(&devirt_pe), 0x7777);

        let run_fn2 = |pe_bytes: &[u8], rcx_in: u64| -> (u64, u64, u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            let rsp_before = {
                let uc = eng.unicorn_mut().unwrap();
                uc.reg_write(RegisterX86::RBX as i32, 0x1234_5678_9ABC_DEF0).unwrap();
                uc.reg_write(RegisterX86::R12 as i32, 0x0FED_CBA9_8765_4321).unwrap();
                uc.reg_read(RegisterX86::RSP as i32).unwrap()
            };
            let ret = eng.call_function(base + 0x1060, &[rcx_in], 100_000, 2_000).unwrap();
            let uc = eng.unicorn_mut().unwrap();
            let rsp_after = uc.reg_read(RegisterX86::RSP as i32).unwrap();
            let rbx_after = uc.reg_read(RegisterX86::RBX as i32).unwrap();
            let r12_after = uc.reg_read(RegisterX86::R12 as i32).unwrap();
            (ret, rbx_after, r12_after, rsp_after.wrapping_sub(rsp_before))
        };
        let orig_res = run_fn2(&orig_pe, 42);
        assert_eq!(orig_res.0, 42 + 5 + 0x10 + 0x100);
        assert_eq!(run_fn2(&devirt_pe, 42), orig_res);
    }

    #[test]
    fn select_arms_specialise_by_their_condition() {
        let base = 0x1_4000_0000u64;
        let mut arena = ExprArena::default();
        // Dispatcher shape: c = (v == 0); target = Select(c, v * K + T1, v * K + T2)
        let rcx = arena.reg_in(ArchReg::Rcx);
        let rdx = arena.reg_in(ArchReg::Rdx);
        let v = arena.or(rcx, rdx);
        let zero = arena.const_u64(0);
        let c = arena.cmp(CondPred::Eq, v, zero);
        let k = arena.const_u64(0x94ad9);
        let vk = arena.mul(v, k);
        let t = arena.add_const(vk, base + 0x100);
        let f = arena.add_const(vk, base + 0x200);
        let sel = arena.select(c, t, f);
        let spec = specialize_select_arms(&mut arena, sel, 0);
        let ExprNode::Select { if_true, .. } = arena.get(spec).clone() else { panic!("still a Select") };
        assert_eq!(arena.as_const(if_true), Some(base + 0x100), "v == 0 in the true arm makes it a constant");
    }

    #[test]
    fn bool_product_with_non_bool_base_hoists_to_select() {
        let base = 0x1_4000_0000u64;
        let mut arena = ExprArena::default();
        // target = (load-ish non-boolean x) + (rcx == 7) * 0x40 + base
        let r8_in = arena.reg_in(ArchReg::R8);
        let x = arena.shr_const(r8_in, 60); // not boolean
        let rcx_in = arena.reg_in(ArchReg::Rcx);
        let seven = arena.const_u64(7);
        let c = arena.cmp(CondPred::Eq, rcx_in, seven);
        let k = arena.const_u64(0x40);
        let prod = arena.mul(c, k);
        let x_plus = arena.add(x, prod);
        let target = arena.add_const(x_plus, base);

        let dummy_pe = build_two_exec_pe64(&[], &[], 0x1000);
        let view = PeImageView::from_pe_bytes(&dummy_pe).unwrap();
        assert!(
            try_decompose_bool_mux_target(&mut arena, &view, target).is_none(),
            "the polynomial decomposer must still reject a non-boolean term"
        );

        let hoisted = hoist_bool_product_select(&mut arena, target, 0).expect("x + b*k must hoist");
        let ExprNode::Select { cond, if_true, if_false } = arena.get(hoisted).clone() else {
            panic!("expected a Select, got {:?}", arena.get(hoisted));
        };
        assert_eq!(cond, c);
        let x_base = arena.add_const(x, base);
        let x_base_k = arena.add_const(x, base + 0x40);
        assert_eq!(if_false, x_base, "false arm is x + base");
        assert_eq!(if_true, x_base_k, "true arm is x + base + k");

        // No boolean product: nothing to hoist.
        assert!(hoist_bool_product_select(&mut arena, x_base, 0).is_none());
    }

    #[test]
    fn multi_bool_poly_mux_decomposes_to_three_way_select() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        // 1. Direct unit test of `try_decompose_bool_mux_target`
        let dummy_pe = build_two_exec_pe64(&[], &[], 0x1000);
        let view = PeImageView::from_pe_bytes(&dummy_pe).unwrap();
        let mut arena = ExprArena::default();
        let v0 = base + 0x1050;
        let v1 = base + 0x1070;
        let v2 = base + 0x1030;
        let rcx_in = arena.reg_in(ArchReg::Rcx);
        let r8_in = arena.reg_in(ArchReg::R8);
        let b0 = arena.and_const(rcx_in, 1);
        let b1 = arena.and_const(r8_in, 1);
        let one = arena.const_u64(1);
        let one_minus_b0 = arena.sub(one, b0);
        let d1_c = arena.const_u64(v1 - v0);
        let d0_c = arena.const_u64(v0 - v2);
        let d1_b1 = arena.mul(d1_c, b1);
        let t1 = arena.mul(d1_b1, one_minus_b0);
        let t0 = arena.mul(d0_c, b0);
        let base_c = arena.const_u64(v0);
        let base_plus_t1 = arena.add(base_c, t1);
        let poly = arena.sub(base_plus_t1, t0);

        let decomposed = try_decompose_bool_mux_target(&mut arena, &view, poly)
            .expect("3-way boolean polynomial should decompose");
        let tree = parse_select_tree(&arena, decomposed, None, 0)
            .expect("decomposed expression should form a SelectTree");
        fn collect_leaf_vas(t: &SelectTree, out: &mut Vec<u64>) {
            match t {
                SelectTree::Leaf(SelectArm::ConstVa { va, .. }) => out.push(*va),
                SelectTree::Leaf(SelectArm::RegDisp { .. }) => {}
                SelectTree::Branch { if_true, if_false, .. } => {
                    collect_leaf_vas(if_true, out);
                    collect_leaf_vas(if_false, out);
                }
            }
        }
        let mut leaves = Vec::new();
        collect_leaf_vas(&tree, &mut leaves);
        assert_eq!(leaves.len(), 3, "redundant b1 branch when b0=1 should fold");
        assert!(leaves.contains(&v0) && leaves.contains(&v1) && leaves.contains(&v2));

        // Non-executable leaf must be rejected
        let bad_c = arena.const_u64(base + 0x9000);
        let c16 = arena.const_u64(0x10);
        let bad_delta = arena.mul(c16, b0);
        let bad_poly = arena.add(bad_c, bad_delta);
        assert!(try_decompose_bool_mux_target(&mut arena, &view, bad_poly).is_none());

        // 2. End-to-end PE64 + Unicorn equivalence test: 3-way boolean poly + variable shift `shl r11, cl`
        let mut text_sec = vec![0xCCu8; 0x200];
        let entry_code = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[0..entry_code.len()].copy_from_slice(&entry_code);

        let leaf_v2 = assemble_at(64, v2, |a| {
            a.lea(rax, ptr(r11) + 0x3000)?;
            a.ret()
        });
        text_sec[0x30..0x30 + leaf_v2.len()].copy_from_slice(&leaf_v2);

        let leaf_v0 = assemble_at(64, v0, |a| {
            a.lea(rax, ptr(r11) + 0x1000)?;
            a.ret()
        });
        text_sec[0x50..0x50 + leaf_v0.len()].copy_from_slice(&leaf_v0);

        let leaf_v1 = assemble_at(64, v1, |a| {
            a.lea(rax, ptr(r11) + 0x2000)?;
            a.ret()
        });
        text_sec[0x70..0x70 + leaf_v1.len()].copy_from_slice(&leaf_v1);

        let mut vmp_sec = vec![0xCCu8; 0x600];
        let vm_stub = assemble_at(64, base + 0x2000, |a| {
            // Simulate VM dispatcher obfuscation overhead (opaque zero + MBA identities -> folds to 0)
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(qword_ptr(rsp + 0x18), rdx)?;
            a.mov(qword_ptr(rsp + 0x20), r8)?;
            a.xor(r9, r9)?;
            for _ in 0..8 {
                // Opaque zero #1: (rcx * (rcx - 1)) & 1 == 0
                a.mov(rax, qword_ptr(rsp + 0x10))?;
                a.lea(r10, ptr(rax) - 1)?;
                a.imul_2(r10, rax)?;
                a.and(r10, 1)?;
                a.add(r9, r10)?;
                // Opaque zero #2 (MBA add): ((rdx ^ r8) + 2*(rdx & r8)) - (rdx + r8) == 0
                a.mov(r10, qword_ptr(rsp + 0x18))?;
                a.mov(r11, qword_ptr(rsp + 0x20))?;
                a.mov(rax, r10)?;
                a.xor(rax, r11)?;
                a.and(r10, r11)?;
                a.shl(r10, 1)?;
                a.add(rax, r10)?;
                a.sub(rax, qword_ptr(rsp + 0x18))?;
                a.sub(rax, qword_ptr(rsp + 0x20))?;
                a.add(r9, rax)?;
            }
            // b0 = rcx & 1 (+ opaque 0); 1 - b0 -> r10
            a.mov(r10, qword_ptr(rsp + 0x10))?;
            a.xor(r10, r9)?;
            a.add(r9, r10)?;
            a.and(r9, 1)?;
            a.mov(r10, 1u64)?;
            a.sub(r10, r9)?;
            // b1 = r8 & 1 -> rax; rax = (v1 - v0) * b1 * (1 - b0)
            a.mov(rax, qword_ptr(rsp + 0x20))?;
            a.and(rax, 1)?;
            a.imul_2(rax, r10)?;
            a.imul_3(rax, rax, (v1 - v0) as i32)?;
            // r10 = v0 + (v1 - v0) * b1 * (1 - b0) - (v0 - v2) * b0
            a.mov(r10, v0)?;
            a.add(r10, rax)?;
            a.imul_3(r9, r9, (v0 - v2) as i32)?;
            a.sub(r10, r9)?;
            // Variable-count shift: r11 = 3u64 << (rdx & 7)
            a.mov(rcx, qword_ptr(rsp + 0x18))?;
            a.and(ecx, 7)?;
            a.mov(r11, 3u64)?;
            a.shl(r11, gpr8::cl)?;
            a.add(rsp, 0x40)?;
            a.jmp(r10)
        });
        vmp_sec[..vm_stub.len()].copy_from_slice(&vm_stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected 3-way bool poly VM stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], a0: u64, a1: u64, a2: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[a0, a1, a2], 100_000, 2_000).unwrap()
        };

        for (rcx_in, rdx_in, r8_in, expected) in [
            (0u64, 1u64, 0u64, 0x1000u64 + (3 << 1)),
            (0u64, 2u64, 1u64, 0x2000u64 + (3 << 2)),
            (1u64, 3u64, 0u64, 0x3000u64 + (3 << 3)),
            (1u64, 4u64, 1u64, 0x3000u64 + (3 << 4)),
            (0x10u64, 9u64, 0x11u64, 0x2000u64 + (3 << 1)),
        ] {
            assert_eq!(run_case(&orig_pe, rcx_in, rdx_in, r8_in), expected);
            assert_eq!(run_case(&devirt_pe, rcx_in, rdx_in, r8_in), expected);
        }
    }

    #[test]
    fn entry_flag_cmovne_trampoline_e2e() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.cmp(rcx, 5)?;
            a.push(rax)?;
            a.pop(rax)?;
            a.jmp(base + 0x2000)
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let eq_leaf = assemble_at(64, base + 0x1030, |a| {
            a.mov(eax, 0xAAAAu32)?;
            a.ret()
        });
        text_sec[0x30..0x30 + eq_leaf.len()].copy_from_slice(&eq_leaf);

        let ne_leaf = assemble_at(64, base + 0x1050, |a| {
            a.mov(eax, 0xBBBBu32)?;
            a.ret()
        });
        text_sec[0x50..0x50 + ne_leaf.len()].copy_from_slice(&ne_leaf);

        let fn1 = assemble_at(64, base + 0x1070, |a| {
            a.cmp(rcx, 5)?;
            a.jmp(base + 0x2000)
        });
        text_sec[0x70..0x70 + fn1.len()].copy_from_slice(&fn1);

        let mut vmp_sec = vec![0xCCu8; 0x200];
        let tramp = assemble_at(64, base + 0x2000, |a| {
            a.pushfq()?;
            a.push(r10)?;
            a.add(r10, 1)?;
            a.pop(r10)?;
            a.popfq()?;
            a.mov(rax, base + 0x1030)?;
            a.mov(rdx, base + 0x1050)?;
            a.cmovne(rax, rdx)?;
            a.jmp(rax)
        });
        vmp_sec[..tramp.len()].copy_from_slice(&tramp);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 2, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 2,
            "expected EntryFlag and SubCmp cmovne trampolines devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], rva: u32, rcx_in: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + rva as u64, &[rcx_in], 100_000, 2_000).unwrap()
        };

        for rva in [0x1000u32, 0x1070u32] {
            assert_eq!(run_case(&orig_pe, rva, 5), 0xAAAA);
            assert_eq!(run_case(&devirt_pe, rva, 5), 0xAAAA);
            assert_eq!(run_case(&orig_pe, rva, 9), 0xBBBB);
            assert_eq!(run_case(&devirt_pe, rva, 9), 0xBBBB);
        }
    }

    #[test]
    fn unresolvable_jmp_reg_exits_back_to_vm_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        // Junk that folds away, then a handler address taken from an input register
        // (`rdx & 0x20`: not a boolean, so no decomposition can resolve it).
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x20)?;
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.add(rax, 0x10)?;
            a.mov(r8, rdx)?;
            a.and(r8, 0x20)?;
            a.add(rsp, 0x20)?;
            a.mov(r10, base + 0x2300)?;
            a.add(r10, r8)?;
            a.jmp(r10)
        });
        assert!(stub.len() < 0x300, "stub overlaps the handlers");
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let h0 = assemble_at(64, base + 0x2300, |a| {
            a.add(rax, 1)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[0x300..0x300 + h0.len()].copy_from_slice(&h0);
        let h1 = assemble_at(64, base + 0x2320, |a| {
            a.add(rax, 2)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[0x320..0x320 + h1.len()].copy_from_slice(&h1);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);

        // Without VM exits the jump stays unresolved and nothing is patched.
        let strict = BinaryDevirtConfig { allow_vm_exits: false, ..BinaryDevirtConfig::default() };
        let (_, strict_rep) = devirtualize_pe_bytes(&orig_pe, strict).unwrap();
        assert_eq!(strict_rep.devirtualized_total, 0, "got {strict_rep:?}");

        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected the stub recompiled up to its VM exit, bailouts: {:?}",
            report.bailout_reasons
        );
        assert_eq!(report.hybrid_vm_exits, 1);

        let run_case = |pe_bytes: &[u8], rcx_in: u64, rdx_in: u64| -> (u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            let rsp_before = eng.unicorn_mut().unwrap().reg_read(RegisterX86::RSP as i32).unwrap();
            let ret = eng.call_function(base + 0x1000, &[rcx_in, rdx_in], 100_000, 2_000).unwrap();
            let rsp_after = eng.unicorn_mut().unwrap().reg_read(RegisterX86::RSP as i32).unwrap();
            (ret, rsp_after.wrapping_sub(rsp_before))
        };
        for (rcx_in, rdx_in) in [(5u64, 0u64), (5, 0x20), (100, 0xffff_ffdf), (100, 0xffff_ffff)] {
            let orig = run_case(&orig_pe, rcx_in, rdx_in);
            let want = rcx_in + 0x10 + if rdx_in & 0x20 != 0 { 2 } else { 1 };
            assert_eq!(orig.0, want, "original, rdx={rdx_in:#x}");
            assert_eq!(run_case(&devirt_pe, rcx_in, rdx_in), orig, "devirtualized, rdx={rdx_in:#x}");
        }
    }

    #[test]
    fn unresolvable_jmp_on_aligned_vm_frame_exits_back_to_vm_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        // Same function entered 8 bytes lower: the alignment padding differs.
        let fn1 = assemble_at(64, base + 0x1080, |a| {
            a.call(base + 0x1000)?;
            a.ret()
        });
        text_sec[0x80..0x80 + fn1.len()].copy_from_slice(&fn1);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        // VM entry: frame pointer, aligned frame, context slots, then a handler address
        // from an input register (`rdx & 0x20`, unresolvable) with RSP still aligned.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(qword_ptr(rsp + 0x18), 0x77)?;
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.mov(r8, rdx)?;
            a.and(r8, 0x20)?;
            a.mov(r10, base + 0x2300)?;
            a.add(r10, r8)?;
            a.jmp(r10)
        });
        assert!(stub.len() < 0x300, "stub overlaps the handlers");
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        // Handlers: original VM code reading the aligned frame the exit rebuilt.
        for (off, add) in [(0x300usize, 1i32), (0x320, 2)] {
            let h = assemble_at(64, base + 0x2000 + off as u64, |a| {
                a.mov(rax, qword_ptr(rsp + 0x10))?;
                a.add(rax, qword_ptr(rsp + 0x18))?;
                a.add(rax, add)?;
                a.mov(rsp, rbp)?;
                a.pop(rbp)?;
                a.pop(rbx)?;
                a.jmp(base + 0x1040)
            });
            vmp_sec[off..off + h.len()].copy_from_slice(&h);
        }

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected the aligned-frame stub recompiled up to its VM exit, bailouts: {:?}",
            report.bailout_reasons
        );
        assert_eq!(report.hybrid_vm_exits, 1);

        let run_case = |pe_bytes: &[u8], entry: u64, rcx_in: u64, rdx_in: u64| -> (u64, u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            let (rsp_before, _) = {
                let uc = eng.unicorn_mut().unwrap();
                uc.reg_write(RegisterX86::RBP as i32, 0xB0B0_0000_1111).unwrap();
                uc.reg_write(RegisterX86::RBX as i32, 0xB1B1_0000_2222).unwrap();
                (uc.reg_read(RegisterX86::RSP as i32).unwrap(), ())
            };
            let ret = eng.call_function(entry, &[rcx_in, rdx_in], 100_000, 2_000).unwrap();
            let uc = eng.unicorn_mut().unwrap();
            let rbp_after = uc.reg_read(RegisterX86::RBP as i32).unwrap();
            let rsp_after = uc.reg_read(RegisterX86::RSP as i32).unwrap();
            (ret, rbp_after, rsp_after.wrapping_sub(rsp_before))
        };
        for entry in [base + 0x1000, base + 0x1080] {
            for (rcx_in, rdx_in) in [(5u64, 0u64), (5, 0x20), (0x1234, 0xffff_ffdf), (0x1234, 0xffff_ffff)] {
                let orig = run_case(&orig_pe, entry, rcx_in, rdx_in);
                let want = rcx_in + 0x77 + if rdx_in & 0x20 != 0 { 2 } else { 1 };
                assert_eq!(orig.0, want, "original, entry={entry:#x} rdx={rdx_in:#x}");
                assert_eq!(orig.1, 0xB0B0_0000_1111, "original keeps rbp");
                assert_eq!(
                    run_case(&devirt_pe, entry, rcx_in, rdx_in),
                    orig,
                    "devirtualized, entry={entry:#x} rdx={rdx_in:#x}"
                );
            }
        }
    }

    /// A VM entry on an aligned frame: `cmp rcx, 5`, a `cpuid` the lifter does not
    /// model (exit there; `cpuid` keeps the flags), then `jb` on the `cmp` flags.
    /// `junk` folding pairs make the recompiled part worth patching.
    fn build_cpuid_flags_stub(base: u64, junk: i32) -> Vec<u8> {
        use gpr64::*;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x1000];
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut low = a.create_label();
            let mut tail = a.create_label();
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(rax, rcx)?;
            for k in 0..junk {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.cmp(rcx, 5)?;
            a.mov(r9, 0x1234u64)?;
            a.cpuid()?;
            a.jb(low)?;
            a.mov(rax, qword_ptr(rsp + 0x10))?;
            a.add(rax, 100)?;
            a.jmp(tail)?;
            a.set_label(&mut low)?;
            a.mov(rax, qword_ptr(rsp + 0x10))?;
            a.add(rax, 200)?;
            a.set_label(&mut tail)?;
            a.mov(rsp, rbp)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        assert!(stub.len() < vmp_sec.len());
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000)
    }

    fn run_rcx_case(pe_bytes: &[u8], entry: u64, rcx_in: u64) -> (u64, u64, u64, u64) {
        let s = Sample::from_bytes(pe_bytes).unwrap();
        let mut eng = UnpackerEngine::new(s, "mem");
        eng.init_uc().unwrap();
        let rsp_before = {
            let uc = eng.unicorn_mut().unwrap();
            uc.reg_write(RegisterX86::RBP as i32, 0xB0B0_0000_1111).unwrap();
            uc.reg_write(RegisterX86::RBX as i32, 0xB1B1_0000_2222).unwrap();
            uc.reg_read(RegisterX86::RSP as i32).unwrap()
        };
        let ret = eng.call_function(entry, &[rcx_in], 200_000, 2_000).unwrap();
        let uc = eng.unicorn_mut().unwrap();
        (
            ret,
            uc.reg_read(RegisterX86::RBP as i32).unwrap(),
            uc.reg_read(RegisterX86::RBX as i32).unwrap(),
            uc.reg_read(RegisterX86::RSP as i32).unwrap().wrapping_sub(rsp_before),
        )
    }

    #[test]
    fn exit_before_unmodelled_insn_replays_live_flags_e2e() {
        let base = 0x1_4000_0000u64;
        let orig_pe = build_cpuid_flags_stub(base, 30);

        let strict = BinaryDevirtConfig { allow_vm_exits: false, ..BinaryDevirtConfig::default() };
        let (_, strict_rep) = devirtualize_pe_bytes(&orig_pe, strict).unwrap();
        assert_eq!(strict_rep.devirtualized_total, 0, "got {strict_rep:?}");

        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for rcx_in in [0u64, 4, 5, 6, 0x1234, u64::MAX] {
            let orig = run_rcx_case(&orig_pe, base + 0x1000, rcx_in);
            let want = rcx_in.wrapping_add(if rcx_in < 5 { 200 } else { 100 });
            assert_eq!(orig.0, want, "original, rcx={rcx_in:#x}");
            assert_eq!(run_rcx_case(&devirt_pe, base + 0x1000, rcx_in), orig, "devirtualized, rcx={rcx_in:#x}");
        }
    }

    #[test]
    fn exit_at_instruction_budget_continues_in_vm_e2e() {
        let base = 0x1_4000_0000u64;
        // 200 folding pairs, budget 300: the exit lands inside the junk.
        let orig_pe = build_cpuid_flags_stub(base, 200);
        let cfg = BinaryDevirtConfig { max_total_insns_per_entry: 300, ..BinaryDevirtConfig::default() };
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, cfg).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for rcx_in in [3u64, 9] {
            let orig = run_rcx_case(&orig_pe, base + 0x1000, rcx_in);
            assert_eq!(run_rcx_case(&devirt_pe, base + 0x1000, rcx_in), orig, "rcx={rcx_in}");
        }
    }

    #[test]
    fn partly_written_aligned_slot_is_stored_bytewise_on_vm_exit_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            // Read the slot first (its old content is unknown), then write 4 of its bytes.
            a.mov(r11, qword_ptr(rsp + 0x20))?;
            a.mov(r11, 0u64)?;
            a.mov(dword_ptr(rsp + 0x20), gpr32::ecx)?;
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.mov(r8, rdx)?;
            a.and(r8, 0x20)?;
            a.mov(r10, base + 0x2300)?;
            a.add(r10, r8)?;
            a.jmp(r10)
        });
        assert!(stub.len() < 0x300);
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        for (off, add) in [(0x300usize, 1i32), (0x320, 2)] {
            let h = assemble_at(64, base + 0x2000 + off as u64, |a| {
                a.mov(gpr32::eax, dword_ptr(rsp + 0x20))?;
                a.add(rax, add)?;
                a.mov(rsp, rbp)?;
                a.pop(rbp)?;
                a.pop(rbx)?;
                a.jmp(base + 0x1040)
            });
            vmp_sec[off..off + h.len()].copy_from_slice(&h);
        }
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for (rcx_in, rdx_in) in [(7u64, 0u64), (7, 0x20), (0xdead_beef_1234_5678, 0x20)] {
            let run = |pe: &[u8]| {
                let s = Sample::from_bytes(pe).unwrap();
                let mut eng = UnpackerEngine::new(s, "mem");
                eng.init_uc().unwrap();
                eng.call_function(base + 0x1000, &[rcx_in, rdx_in], 100_000, 2_000).unwrap()
            };
            let want = (rcx_in & 0xffff_ffff) + if rdx_in & 0x20 != 0 { 2 } else { 1 };
            assert_eq!(run(&orig_pe), want);
            assert_eq!(run(&devirt_pe), want);
        }
    }

    #[test]
    fn mid_function_epilog_add_rsp_ret_e2e() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.push(rbx)?;
            a.sub(rsp, 0x20)?;
            a.mov(rbx, 0xDEADu64)?;
            a.mov(eax, ecx)?;
            a.add(eax, 7)?;
            a.jmp(base + 0x2000)
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let mut vmp_sec = vec![0xCCu8; 0x200];
        let tramp = assemble_at(64, base + 0x2000, |a| {
            a.push(r10)?;
            a.xor(r10, r10)?;
            a.pop(r10)?;
            a.add(rsp, 0x20)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..tramp.len()].copy_from_slice(&tramp);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected mid-function epilog ret devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], rcx_in: u64| -> (u64, u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            let rsp_before = {
                let uc = eng.unicorn_mut().unwrap();
                uc.reg_write(RegisterX86::RBX as i32, 0xCAFE_BABE_1234_5678).unwrap();
                uc.reg_read(RegisterX86::RSP as i32).unwrap()
            };
            let ret = eng.call_function(base + 0x1000, &[rcx_in], 100_000, 2_000).unwrap();
            let uc = eng.unicorn_mut().unwrap();
            let rbx_after = uc.reg_read(RegisterX86::RBX as i32).unwrap();
            let rsp_after = uc.reg_read(RegisterX86::RSP as i32).unwrap();
            (ret, rbx_after, rsp_after.wrapping_sub(rsp_before))
        };

        let orig = run_case(&orig_pe, 42);
        assert_eq!(orig, (49, 0xCAFE_BABE_1234_5678, (-0x1000i64) as u64));
        assert_eq!(run_case(&devirt_pe, 42), orig);
    }

    #[test]
    fn predicated_select_addr_and_disjoint_global_store_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), 0x1111i32)?;
            a.mov(qword_ptr(rsp + 0x20), 0x2222i32)?;
            a.mov(r8, rcx)?;
            for _ in 0..12 {
                a.lea(r9, ptr(rcx) - 1)?;
                a.imul_2(r9, rcx)?;
                a.and(r9, 1)?;
                a.add(r8, r9)?;
            }
            a.and(r8, 1)?;
            a.lea(rax, ptr(rsp) + 0x10)?;
            a.lea(rdx, ptr(rsp) + 0x20)?;
            a.sub(rdx, rax)?;
            a.imul_2(rdx, r8)?;
            a.add(rax, rdx)?;
            a.mov(r9, qword_ptr(rax))?;
            a.mov(r10, base + 0x3010)?;
            a.mov(r10, qword_ptr(r10))?;
            a.mov(r11, base + 0x3000)?;
            a.mov(qword_ptr(r11), r9)?;
            a.lea(rax, ptr(r9 + r10))?;
            a.add(rsp, 0x40)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected predicated Select-addr & disjoint global stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], rcx_in: u64| -> (u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.mem_write(base + 0x3000, &0u64.to_le_bytes()).unwrap();
                uc.mem_write(base + 0x3010, &0x5555u64.to_le_bytes()).unwrap();
            }
            let ret = eng.call_function(base + 0x1000, &[rcx_in], 100_000, 2_000).unwrap();
            let mut g1 = [0u8; 8];
            eng.unicorn_mut().unwrap().mem_read(base + 0x3000, &mut g1).unwrap();
            (ret, u64::from_le_bytes(g1))
        };

        assert_eq!(run_case(&orig_pe, 0), (0x6666, 0x1111));
        assert_eq!(run_case(&devirt_pe, 0), (0x6666, 0x1111));
        assert_eq!(run_case(&orig_pe, 1), (0x7777, 0x2222));
        assert_eq!(run_case(&devirt_pe, 1), (0x7777, 0x2222));
    }

    #[test]
    fn lock_inc_dec_and_sub_seto_e2e() {
        use gpr32::*;
        use gpr64::*;
        use gpr8::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x28)?;
            a.mov(qword_ptr(rsp + 0x10), r10)?;
            for _ in 0..12 {
                a.lea(r10, ptr(r8) - 1)?;
                a.imul_2(r10, r8)?;
                a.and(r10, 1)?;
                a.add(r8, r10)?;
            }
            a.lock().inc(dword_ptr(rcx))?;
            a.lock().dec(qword_ptr(rdx))?;
            a.sub(r8, r9)?;
            a.seto(al)?;
            a.movzx(eax, al)?;
            a.mov(r10, qword_ptr(rsp + 0x10))?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected lock inc/dec + sub/seto stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], x: u64, y: u64| -> (u64, u32, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.mem_write(base + 0x3000, &10u32.to_le_bytes()).unwrap();
                uc.mem_write(base + 0x3008, &100u64.to_le_bytes()).unwrap();
            }
            let ret = eng
                .call_function(base + 0x1000, &[base + 0x3000, base + 0x3008, x, y], 100_000, 2_000)
                .unwrap();
            let uc = eng.unicorn_mut().unwrap();
            let mut m32 = [0u8; 4];
            let mut m64 = [0u8; 8];
            uc.mem_read(base + 0x3000, &mut m32).unwrap();
            uc.mem_read(base + 0x3008, &mut m64).unwrap();
            (ret, u32::from_le_bytes(m32), u64::from_le_bytes(m64))
        };

        assert_eq!(run_case(&orig_pe, 50, 20), (0, 11, 99));
        assert_eq!(run_case(&devirt_pe, 50, 20), (0, 11, 99));
        assert_eq!(run_case(&orig_pe, i64::MIN as u64, 1), (1, 11, 99));
        assert_eq!(run_case(&devirt_pe, i64::MIN as u64, 1), (1, 11, 99));
    }

    #[test]
    fn branchless_predicated_stack_keeps_single_block_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x800];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x80)?;
            a.mov(qword_ptr(rsp + 0x50), r8)?;
            a.mov(qword_ptr(rsp + 0x58), r9)?;
            a.mov(qword_ptr(rsp + 0x60), r10)?;
            a.mov(qword_ptr(rsp + 0x68), r11)?;
            a.mov(qword_ptr(rsp + 0x70), rdx)?;

            for k in 0i32..6 {
                a.mov(qword_ptr(rsp + 0x10 + k * 8), (k + 1) * 100)?;
            }
            a.xor(gpr32::eax, gpr32::eax)?;
            a.mov(qword_ptr(rsp + 0x40), rax)?;
            a.mov(qword_ptr(rsp + 0x48), rax)?;

            a.mov(r9, rcx)?;
            for _ in 0..28 {
                a.lea(r8, ptr(rcx) - 1)?;
                a.imul_2(r8, rcx)?;
                a.and(r8, 1)?;
                a.add(r9, r8)?;
            }

            a.xor(gpr32::edx, gpr32::edx)?;
            for k in 0u32..6 {
                a.mov(r10, r9)?;
                if k > 0 {
                    a.shr(r10, k)?;
                }
                a.and(r10, 1)?;

                // Predicated internal stack write: dummy [rsp+0x48] vs [rsp+0x10+k*8]
                a.lea(r11, ptr(rsp) + 0x48)?;
                a.lea(r8, ptr(rsp) + (0x10 + (k as i32) * 8))?;
                a.sub(r8, r11)?;
                a.imul_2(r8, r10)?;
                a.add(r11, r8)?;
                a.mov(rax, ((k as i64) + 1) * 1000)?;
                a.add(qword_ptr(r11), rax)?;

                // Predicated internal stack read: zero [rsp+0x40] vs [rsp+0x10+k*8]
                a.lea(r11, ptr(rsp) + 0x40)?;
                a.lea(r8, ptr(rsp) + (0x10 + (k as i32) * 8))?;
                a.sub(r8, r11)?;
                a.imul_2(r8, r10)?;
                a.add(r11, r8)?;
                a.add(rdx, qword_ptr(r11))?;
            }

            a.mov(rax, rdx)?;
            a.mov(r8, qword_ptr(rsp + 0x50))?;
            a.mov(r9, qword_ptr(rsp + 0x58))?;
            a.mov(r10, qword_ptr(rsp + 0x60))?;
            a.mov(r11, qword_ptr(rsp + 0x68))?;
            a.mov(rdx, qword_ptr(rsp + 0x70))?;
            a.add(rsp, 0x80)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let view = PeImageView::from_pe_bytes(&orig_pe).unwrap();
        let cfg = BinaryDevirtConfig::default();
        let entries = discover_vm_entries(&view, &cfg);
        assert_eq!(entries.len(), 1);
        let lifted = lift_vm_entry_cfg(&view, &entries[0], &cfg);
        assert_eq!(
            lifted.blocks.len(),
            1,
            "predicated internal stack reads/writes must stay single-block without 2^6 explosion"
        );

        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, cfg).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected single-block predicated stack stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], rcx_in: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[rcx_in], 100_000, 2_000).unwrap()
        };

        for mask in [0b00_0000u64, 0b10_1010, 0b01_0101, 0b11_1111] {
            let expected: u64 = (0..6u64)
                .filter(|&k| ((mask >> k) & 1) != 0)
                .map(|k| (k + 1) * 1100)
                .sum();
            assert_eq!(run_case(&orig_pe, mask), expected);
            assert_eq!(run_case(&devirt_pe, mask), expected);
        }
    }

    #[test]
    fn modified_xmm_exit_and_xmm_in_to_gpr_e2e() {
        use gpr64::*;
        use xmm::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.mov(rax, base + 0x3000)?;
            a.movups(xmm0, ptr(rax))?;
            a.mov(rax, base + 0x3010)?;
            a.movups(xmm1, ptr(rax))?;
            a.movups(xmm2, xmm0)?;
            a.jmp(base + 0x2000)
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let epilog = assemble_at(64, base + 0x1060, |a| {
            a.mov(rcx, base + 0x3020)?;
            a.movups(ptr(rcx), xmm0)?;
            a.mov(rcx, base + 0x3030)?;
            a.movups(ptr(rcx), xmm1)?;
            a.mov(rcx, base + 0x3040)?;
            a.movups(ptr(rcx), xmm2)?;
            a.ret()
        });
        text_sec[0x60..0x60 + epilog.len()].copy_from_slice(&epilog);

        let mut vmp_sec = vec![0xCCu8; 0x600];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x30), r10)?;
            for _ in 0..10 {
                a.lea(r10, ptr(rcx) - 1)?;
                a.imul_2(r10, rcx)?;
                a.and(r10, 1)?;
                a.add(rcx, r10)?;
            }
            a.movups(ptr(rsp + 0x15), xmm1)?;
            a.mov(rax, qword_ptr(rsp + 0x1D))?;
            a.movaps(xmm1, xmm0)?;
            a.movups(xmm0, ptr(rsp + 0x15))?;
            a.pxor(xmm2, xmm2)?;
            a.mov(r10, qword_ptr(rsp + 0x30))?;
            a.add(rsp, 0x40)?;
            a.jmp(base + 0x1060)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_total, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_total, 1,
            "expected modified XMM & XmmIn->GPR stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let x0_bytes: [u8; 16] = [
            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
            0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0,
        ];
        let x1_bytes: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10,
        ];
        let expected_rax = u64::from_le_bytes(x1_bytes[8..16].try_into().unwrap());

        let run_case = |pe_bytes: &[u8]| -> (u64, [u8; 16], [u8; 16], [u8; 16]) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.mem_write(base + 0x3000, &x0_bytes).unwrap();
                uc.mem_write(base + 0x3010, &x1_bytes).unwrap();
                uc.mem_write(base + 0x3020, &[0xAAu8; 48]).unwrap();
            }
            let ret = eng.call_function(base + 0x1000, &[42], 100_000, 2_000).unwrap();
            let uc = eng.unicorn_mut().unwrap();
            let mut o0 = [0u8; 16];
            let mut o1 = [0u8; 16];
            let mut o2 = [0u8; 16];
            uc.mem_read(base + 0x3020, &mut o0).unwrap();
            uc.mem_read(base + 0x3030, &mut o1).unwrap();
            uc.mem_read(base + 0x3040, &mut o2).unwrap();
            (ret, o0, o1, o2)
        };

        let expected = (expected_rax, x1_bytes, x0_bytes, [0u8; 16]);
        assert_eq!(run_case(&orig_pe), expected);
        assert_eq!(run_case(&devirt_pe), expected);
    }
}
