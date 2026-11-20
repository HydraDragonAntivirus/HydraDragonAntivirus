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

use iced_x86::code_asm::registers::{gpr16, gpr32, gpr64, gpr8};
#[cfg(test)]
use iced_x86::code_asm::registers::xmm;
use iced_x86::code_asm::{
    byte_ptr, dword_ptr, ptr, qword_ptr, word_ptr, AsmMemoryOperand, AsmRegister16,
    AsmRegister32, AsmRegister64, AsmRegister8, CodeAssembler, CodeLabel,
};
use iced_x86::{
    BlockEncoderOptions, ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction,
    Mnemonic, OpKind, Register,
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    Bailout(String),
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
}

#[derive(Debug, Clone)]
enum FlagState {
    Entry,
    Unknown,
    SubCmp { lhs: ExprId, rhs: ExprId, width: u8 },
    TestBitwise { val: ExprId, width: u8 },
    Add { lhs: ExprId, rhs: ExprId, res: ExprId, width: u8 },
    IncDec { res: ExprId, cf: Option<bool>, width: u8 },
    CarryOnly { cf: bool },
}

#[derive(Debug, Clone)]
struct SymState {
    ip: u64,
    regs: [ExprId; 16],
    xmms: [(ExprId, ExprId); 16],
    stack: SymStack,
    flags: FlagState,
    entry_rflags_expr: Option<ExprId>,
    mem_ver: u32,
    mem_cache: HashMap<ExprId, (u8, ExprId)>,
    next_aligned_id: u32,
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
                entry_rflags_expr: None,
                mem_ver: 0,
                mem_cache: HashMap::new(),
                next_aligned_id: 0,
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
            entry_rflags_expr: None,
            mem_ver: 0,
            mem_cache: HashMap::new(),
            next_aligned_id: 0,
            inline_depth: 0,
            cum_rsp_offset: 0,
            entry_caller_slot_versions,
        }
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
                    ConditionCode::s => Some(arena.cmp(CondPred::Slt, sr, zero)),
                    ConditionCode::ns => Some(arena.cmp(CondPred::Sge, sr, zero)),
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
            FlagState::CarryOnly { cf } => match cc {
                ConditionCode::b => Some(arena.const_u64(u64::from(*cf))),
                ConditionCode::ae => Some(arena.const_u64(u64::from(!*cf))),
                _ => None,
            },
            FlagState::Entry | FlagState::Unknown => None,
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

/// Decomposes a multi-boolean polynomial indirect branch target (up to 4 `{0, 1}` variables)
/// into a reduced `Select` BDD after verifying every combination resolves to an executable VA.
fn try_decompose_bool_mux_target(
    arena: &mut ExprArena,
    view: &PeImageView,
    root: ExprId,
) -> Option<ExprId> {
    fn is_bool_expr(arena: &ExprArena, id: ExprId) -> bool {
        (arena.known_bits(id).0 & !1u64) == !1u64
    }

    fn push_var(vars: &mut Vec<ExprId>, id: ExprId) -> bool {
        if !vars.contains(&id) {
            vars.push(id);
        }
        vars.len() <= 4
    }

    fn collect_bool_vars(
        arena: &ExprArena,
        id: ExprId,
        vars: &mut Vec<ExprId>,
        failed: &mut HashSet<ExprId>,
        visits: &mut usize,
    ) -> bool {
        if vars.contains(&id) {
            return true;
        }
        if failed.contains(&id) || *visits >= 96 {
            return false;
        }
        *visits += 1;
        match arena.get(id) {
            ExprNode::Const(_) => true,
            ExprNode::Cmp { .. } => push_var(vars, id),
            ExprNode::And(a, b) if arena.as_const(*a) == Some(1) || arena.as_const(*b) == Some(1) => {
                // `vm_ir::and` already strips `& 1` from known booleans, so remaining `& 1` masks a non-boolean leaf.
                push_var(vars, id)
            }
            ExprNode::Neg(a) | ExprNode::Not(a) | ExprNode::SExt { val: a, .. } => {
                let saved = vars.len();
                if collect_bool_vars(arena, *a, vars, failed, visits) {
                    true
                } else {
                    vars.truncate(saved);
                    if is_bool_expr(arena, id) {
                        push_var(vars, id)
                    } else {
                        failed.insert(id);
                        false
                    }
                }
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
            | ExprNode::Ror(a, b) => {
                let saved = vars.len();
                if collect_bool_vars(arena, *a, vars, failed, visits)
                    && collect_bool_vars(arena, *b, vars, failed, visits)
                {
                    true
                } else {
                    vars.truncate(saved);
                    if is_bool_expr(arena, id) {
                        push_var(vars, id)
                    } else {
                        failed.insert(id);
                        false
                    }
                }
            }
            ExprNode::Select { cond, if_true, if_false } => {
                let saved = vars.len();
                if collect_bool_vars(arena, *cond, vars, failed, visits)
                    && collect_bool_vars(arena, *if_true, vars, failed, visits)
                    && collect_bool_vars(arena, *if_false, vars, failed, visits)
                {
                    true
                } else {
                    vars.truncate(saved);
                    if is_bool_expr(arena, id) {
                        push_var(vars, id)
                    } else {
                        failed.insert(id);
                        false
                    }
                }
            }
            _ => {
                if is_bool_expr(arena, id) {
                    push_var(vars, id)
                } else {
                    failed.insert(id);
                    false
                }
            }
        }
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

    fn build_bdd(
        arena: &mut ExprArena,
        vars: &[ExprId],
        vals: &[u64],
        var_idx: usize,
        base_mask: usize,
    ) -> ExprId {
        if var_idx == vars.len() {
            return arena.const_u64(vals[base_mask]);
        }
        let f = build_bdd(arena, vars, vals, var_idx + 1, base_mask);
        let t = build_bdd(arena, vars, vals, var_idx + 1, base_mask | (1 << var_idx));
        if t == f {
            t
        } else {
            arena.select(vars[var_idx], t, f)
        }
    }

    let mut vars = Vec::new();
    let mut failed = HashSet::new();
    let mut visits = 0usize;
    if !collect_bool_vars(arena, root, &mut vars, &mut failed, &mut visits)
        || vars.is_empty()
        || vars.len() > 4
    {
        return None;
    }

    let combos = 1usize << vars.len();
    let mut vals = Vec::with_capacity(combos);
    for mask in 0..combos {
        let mut memo = HashMap::new();
        let va = eval_poly(arena, root, &vars, mask, &mut memo)?;
        if !view.is_executable_va(va) {
            return None;
        }
        vals.push(va);
    }

    Some(build_bdd(arena, &vars, &vals, 0, 0))
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
    if depth < 4 {
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

#[allow(clippy::too_many_arguments)]
fn materialize_select_node(
    node: &SelectTree,
    cur_ip: u64,
    jmp_arch_reg: Option<ArchReg>,
    rsp_delta_opt: Option<i64>,
    state: &SymState,
    view: &PeImageView,
    blocks: &mut Vec<Option<LiftedBlock>>,
    queue: &mut VecDeque<(usize, SymState)>,
) -> usize {
    let bid = blocks.len();
    blocks.push(None);
    match node {
        SelectTree::Branch { cond, if_true, if_false } => {
            let taken_block = materialize_select_node(
                if_true,
                cur_ip,
                jmp_arch_reg,
                rsp_delta_opt,
                state,
                view,
                blocks,
                queue,
            );
            let fallthrough_block = materialize_select_node(
                if_false,
                cur_ip,
                jmp_arch_reg,
                rsp_delta_opt,
                state,
                view,
                blocks,
                queue,
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
                        queue.push_back((bid, s2));
                    } else {
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
                    }
                }
                SelectArm::RegDisp { expr, reg, disp } => {
                    if let Some(jr) = jmp_arch_reg {
                        s2.regs[jr.idx()] = expr;
                    }
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
                }
            }
        }
    }
    bid
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

    while let Some((block_id, mut state)) = queue.pop_front() {
        let entry_va = state.ip;
        let mut effects = Vec::new();
        let mut block_insns = 0usize;
        let mut ip_visit_counts: HashMap<u64, usize> = HashMap::new();

        let term = loop {
            if block_insns >= cfg.max_insns_per_block || raw_vm_insns >= cfg.max_total_insns_per_entry {
                break IrTerm::Bailout("insn_budget_exceeded".into());
            }

            let cur_ip = state.ip;
            let count = ip_visit_counts.entry(cur_ip).or_insert(0);
            *count += 1;
            if *count > 96 {
                break IrTerm::Bailout("loop_iteration_limit".into());
            }

            let Some(ins) = view.decode_insn(cur_ip) else {
                break IrTerm::Bailout("decode_failed".into());
            };
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
                    break IrTerm::Bailout(format!("unsupported_lock_{m:?}"));
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
                        state.flags = FlagState::Unknown;
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
                        state.flags = FlagState::Unknown;
                        continue;
                    }
                    _ => break IrTerm::Bailout(format!("unsupported_lock_{m:?}")),
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
                        break IrTerm::Bailout(format!("unsupported_jcc_{m:?}"));
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

                    let needed = blocks.len() + 2;
                    if needed > cfg.max_blocks_per_entry {
                        break IrTerm::Bailout("max_blocks_exceeded".into());
                    }
                    let taken_id = blocks.len();
                    blocks.push(None);
                    let fall_id = blocks.len();
                    blocks.push(None);

                    let mut taken_state = state.clone();
                    taken_state.ip = taken_va;
                    let mut fall_state = state;
                    fall_state.ip = next_ip;

                    for (bid, mut b_state, bva, in_vm) in [
                        (taken_id, taken_state, taken_va, taken_in_vm),
                        (fall_id, fall_state, next_ip, fall_in_vm),
                    ] {
                        if in_vm || (rsp_delta_opt.is_none() && view.is_executable_va(bva)) {
                            b_state.ip = bva;
                            queue.push_back((bid, b_state));
                        } else {
                            let rsp_delta = rsp_delta_opt.unwrap();
                            let pending = b_state.collect_pending_caller_stores(rsp_delta);
                            blocks[bid] = Some(LiftedBlock {
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
                            });
                        }
                    }

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
                        if let Some(decomposed) = try_decompose_bool_mux_target(&mut arena, view, target_expr) {
                            target_expr = decomposed;
                            if let Some(jr) = jmp_arch_reg {
                                state.regs[jr.idx()] = decomposed;
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
                            break IrTerm::Bailout("max_blocks_exceeded".into());
                        }
                        let taken_id = materialize_select_node(
                            &if_true,
                            cur_ip,
                            jmp_arch_reg,
                            rsp_delta_opt,
                            &state,
                            view,
                            &mut blocks,
                            &mut queue,
                        );
                        let fall_id = materialize_select_node(
                            &if_false,
                            cur_ip,
                            jmp_arch_reg,
                            rsp_delta_opt,
                            &state,
                            view,
                            &mut blocks,
                            &mut queue,
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
                                        break IrTerm::Bailout("max_blocks_exceeded".into());
                                    }
                                    let cont_id = blocks.len();
                                    blocks.push(None);
                                    let mut cont_state = SymState::new(&mut arena, next_ip, false, fake_ret_va);
                                    cont_state.cum_rsp_offset = state.cum_rsp_offset + rsp_delta;
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
                    let expected_ret_off = -state.cum_rsp_offset;
                    if let ExprNode::Load { addr, .. } = arena.get(ret_val) {
                        if arena.as_stack_offset(*addr) == Some((StackSpace::CallerStack, expected_ret_off))
                            && imm_pop == 0
                        {
                            let Some(rsp_delta) = check_pure_rsp_delta(&arena, new_rsp) else {
                                break IrTerm::Bailout("ret_caller_dirty_rsp".into());
                            };
                            let pending = state.collect_pending_caller_stores(rsp_delta);
                            break IrTerm::ExitRet {
                                rsp_delta,
                                final_regs: state.regs,
                                final_xmms: state.xmms,
                                pending_caller_stores: pending,
                            };
                        }
                    }
                    break IrTerm::Bailout("unresolved_ret".into());
                }
                FlowControl::Next => {}
                other => break IrTerm::Bailout(format!("unsupported_flow_{other:?}_{m:?}")),
            }

            // Regular instructions (FlowControl::Next)
            match m {
                Mnemonic::Nop | Mnemonic::Pause | Mnemonic::Endbr64 | Mnemonic::Endbr32 => {}
                Mnemonic::Clc => state.flags = FlagState::CarryOnly { cf: false },
                Mnemonic::Stc => state.flags = FlagState::CarryOnly { cf: true },
                Mnemonic::Cld | Mnemonic::Std => {}

                Mnemonic::Mov => {
                    let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("mov_src".into());
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, val) {
                        break IrTerm::Bailout("mov_dst".into());
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
                    let rfl = if matches!(state.flags, FlagState::Entry) {
                        let e = arena.opaque();
                        state.entry_rflags_expr = Some(e);
                        e
                    } else {
                        arena.opaque()
                    };
                    let new_rsp = arena.sub_const(state.reg_full(ArchReg::Rsp), word_bytes as u64);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                    write_memory_expr(&mut state, &mut arena, &mut effects, new_rsp, word_bytes, rfl);
                }
                Mnemonic::Popfq | Mnemonic::Popfd => {
                    let old_rsp = state.reg_full(ArchReg::Rsp);
                    let val = read_memory_expr(view, &mut state, &mut arena, old_rsp, word_bytes);
                    let new_rsp = arena.add_const(old_rsp, word_bytes as u64);
                    state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, new_rsp);
                    if state.entry_rflags_expr == Some(val) {
                        state.flags = FlagState::Entry;
                    } else {
                        state.flags = FlagState::Unknown;
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
                    state.flags = FlagState::SubCmp { lhs, rhs: mrhs, width: w };
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
                    state.flags = FlagState::TestBitwise { val, width: w };
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
                                state.flags = FlagState::Unknown;
                                continue;
                            }
                        }
                    }
                    let sum = arena.add(lhs, sum_rhs);
                    let res = arena.zext_mask(sum, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("add_write".into());
                    }
                    state.flags = FlagState::Add { lhs, rhs: sum_rhs, res, width: w };
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
                                        state.flags = FlagState::Unknown;
                                        continue;
                                    }
                                }
                                let res = arena.opaque();
                                if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                    break IrTerm::Bailout("sbb_write".into());
                                }
                                state.flags = FlagState::Unknown;
                                continue;
                            }
                        }
                    }
                    let diff = arena.sub(lhs, sub_rhs);
                    let res = arena.zext_mask(diff, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("sub_write".into());
                    }
                    state.flags = FlagState::SubCmp { lhs, rhs: sub_rhs, width: w };
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
                    state.flags = FlagState::IncDec { res, cf: prev_cf, width: w };
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
                    state.flags = FlagState::SubCmp { lhs: zero, rhs: lhs, width: w };
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
                        let abase = arena.aligned_base(aid);
                        state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, abase);
                        state.flags = FlagState::Unknown;
                        continue;
                    }
                    let and_v = arena.and(lhs, rhs);
                    let res = arena.zext_mask(and_v, w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("and_write".into());
                    }
                    state.flags = FlagState::TestBitwise { val: res, width: w };
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
                    state.flags = FlagState::TestBitwise { val: res, width: w };
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
                    state.flags = FlagState::TestBitwise { val: res, width: w };
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
                    state.flags = FlagState::Unknown;
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
                    state.flags = FlagState::Unknown;
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
                    state.flags = FlagState::TestBitwise { val: res, width: w };
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
                    if let Some(bv) = arena.as_const(bit) {
                        state.flags = FlagState::CarryOnly { cf: bv != 0 };
                    } else {
                        state.flags = FlagState::Unknown;
                    }
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
                    if let Some(b) = arena.as_const(idx_expr) {
                        let shifted = arena.shr_const(lhs_m, b);
                        let old_bit = arena.and_const(shifted, 1);
                        if let Some(bv) = arena.as_const(old_bit) {
                            state.flags = FlagState::CarryOnly { cf: bv != 0 };
                        } else {
                            state.flags = FlagState::Unknown;
                        }
                    } else {
                        state.flags = FlagState::Unknown;
                    }
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
                    state.flags = FlagState::TestBitwise { val: res, width: w };
                }
                Mnemonic::Bsf | Mnemonic::Bsr => {
                    let w = op_width_bytes(&ins, view.bitness, 1);
                    let Some(src) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("bitscan_src".into());
                    };
                    let masked = arena.zext_mask(src, w);
                    if let Some(v) = arena.as_const(masked) {
                        if v == 0 {
                            state.flags = FlagState::TestBitwise { val: arena.const_u64(0), width: w };
                        } else {
                            let bit = if m == Mnemonic::Bsf {
                                v.trailing_zeros() as u64
                            } else {
                                63 - v.leading_zeros() as u64
                            };
                            let b = arena.const_u64(bit);
                            let _ = write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, b);
                            state.flags = FlagState::TestBitwise { val: masked, width: w };
                        }
                    } else {
                        let o = arena.opaque();
                        let _ = write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, o);
                        state.flags = FlagState::Unknown;
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
                        break IrTerm::Bailout(format!("unsupported_{m:?}"));
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
                    break IrTerm::Bailout(format!("unsupported_{m:?}"));
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
                    break IrTerm::Bailout(format!("unsupported_{m:?}"));
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
                    break IrTerm::Bailout(format!("unsupported_{m:?}"));
                }

                _ => break IrTerm::Bailout(format!("unsupported_{m:?}")),
            }
        };

        if first_bailout.is_none() {
            if let IrTerm::Bailout(ref reason) = term {
                first_bailout = Some(reason.clone());
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
    }
}

// ---------------------------------------------------------------------------
// Soundness Gate & X86/X64 Recompiler (`CodeAssembler`)
// ---------------------------------------------------------------------------

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
    if let Some(ref b) = func.first_bailout {
        return Err(b.clone());
    }

    let check_expr = |e: ExprId, ctx: &str| -> Result<(), String> {
        if func.arena.contains_opaque(e) {
            return Err(format!("opaque_in_{ctx}"));
        }
        Ok(())
    };

    let check_xmms = |xmms: &[(ExprId, ExprId); 16]| -> Result<(), String> {
        for (i, &(lo, hi)) in xmms.iter().enumerate() {
            let expected_lo = ExprNode::XmmIn(i as u8, false);
            let expected_hi = ExprNode::XmmIn(i as u8, true);
            if *func.arena.get(lo) != expected_lo || *func.arena.get(hi) != expected_hi {
                return Err("modified_xmm_at_exit".into());
            }
        }
        Ok(())
    };

    // Propagate max `mem_ver` across CFG edges so stale loads across predecessor stores are caught.
    let mut entry_store_ver = vec![0u32; func.blocks.len()];
    let mut work = VecDeque::new();
    work.push_back(0usize);
    let mut visited_ver = HashSet::new();
    visited_ver.insert(0usize);
    while let Some(bi) = work.pop_front() {
        let cur_v = entry_store_ver[bi];
        let mut max_store_ver = cur_v;
        let block = &func.blocks[bi];
        for eff in &block.effects {
            match eff {
                IrEffect::Store { addr, value, mem_ver_after, .. } => {
                    check_expr(*addr, "store_addr")?;
                    check_expr(*value, "store_val")?;
                    if expr_has_stale_load(&func.arena, *addr, max_store_ver)
                        || expr_has_stale_load(&func.arena, *value, max_store_ver)
                    {
                        return Err("load_across_aliasing_store".into());
                    }
                    max_store_ver = max_store_ver.max(*mem_ver_after);
                }
                IrEffect::AtomicCmpXchg { addr, expected_rax, desired, mem_ver_after, .. } => {
                    check_expr(*addr, "cmpxchg_addr")?;
                    check_expr(*expected_rax, "cmpxchg_expected")?;
                    check_expr(*desired, "cmpxchg_desired")?;
                    max_store_ver = max_store_ver.max(*mem_ver_after);
                }
                IrEffect::AtomicRmw { addr, src, mem_ver_after, .. } => {
                    check_expr(*addr, "atomic_addr")?;
                    check_expr(*src, "atomic_src")?;
                    max_store_ver = max_store_ver.max(*mem_ver_after);
                }
                IrEffect::CallNative { .. } => {
                    return Err("call_native_in_block".into());
                }
            }
        }

        let reg_limit = if bitness == 64 { 16 } else { 8 };
        let check_exit_state = |final_xmms: &[(ExprId, ExprId); 16],
                                pending: &[(i64, ExprId)],
                                final_regs: &[ExprId; 16]|
         -> Result<(), String> {
            check_xmms(final_xmms)?;
            for &(_, val) in pending {
                check_expr(val, "caller_store")?;
                if expr_has_stale_load(&func.arena, val, max_store_ver) {
                    return Err("load_across_aliasing_store".into());
                }
            }
            for r in &ArchReg::ALL[..reg_limit] {
                if *r == ArchReg::Rsp {
                    continue;
                }
                let e = final_regs[r.idx()];
                check_expr(e, r.as_str())?;
                if expr_has_stale_load(&func.arena, e, max_store_ver) {
                    return Err("load_across_aliasing_store".into());
                }
            }
            Ok(())
        };

        match &block.term {
            IrTerm::Bailout(r) => return Err(r.clone()),
            IrTerm::CondBranch { cond, taken_block, fallthrough_block } => {
                check_expr(*cond, "branch_cond")?;
                if expr_has_stale_load(&func.arena, *cond, max_store_ver) {
                    return Err("load_across_aliasing_store".into());
                }
                for &succ in &[*taken_block, *fallthrough_block] {
                    if max_store_ver > entry_store_ver[succ] || visited_ver.insert(succ) {
                        entry_store_ver[succ] = entry_store_ver[succ].max(max_store_ver);
                        work.push_back(succ);
                    }
                }
            }
            IrTerm::ExitRet { final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitIndirectMem { final_regs, final_xmms, pending_caller_stores, .. } => {
                check_exit_state(final_xmms, pending_caller_stores, final_regs)?;
            }
            IrTerm::ExitJmp { target_va, final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitCall { target_va, final_regs, final_xmms, pending_caller_stores, .. } => {
                if !view.is_executable_va(*target_va) {
                    return Err("exit_target_not_executable".into());
                }
                check_exit_state(final_xmms, pending_caller_stores, final_regs)?;
            }
            IrTerm::ExitAddJmp { final_regs, final_xmms, .. } => {
                check_exit_state(final_xmms, &[], final_regs)?;
            }
            IrTerm::MidCall { target, final_regs, final_xmms, pending_caller_stores, cont_block, .. } => {
                if let MidCallTarget::DirectVa(va) = target {
                    if !view.is_executable_va(*va) {
                        return Err("exit_target_not_executable".into());
                    }
                }
                check_exit_state(final_xmms, pending_caller_stores, final_regs)?;
                if visited_ver.insert(*cont_block) {
                    work.push_back(*cont_block);
                }
            }
        }
    }

    Ok(())
}

fn expr_has_stale_load(arena: &ExprArena, root: ExprId, max_store_ver: u32) -> bool {
    if max_store_ver == 0 {
        return false;
    }
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        match arena.get(id) {
            ExprNode::Load { mem_ver, addr, .. } => {
                // Non-stack load strictly older than a store in this block
                if *mem_ver < max_store_ver && !matches!(arena.get(*addr), ExprNode::StackBase) {
                    return true;
                }
                st.push(*addr);
            }
            ExprNode::Not(a) | ExprNode::Neg(a) | ExprNode::SExt { val: a, .. } => st.push(*a),
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
            return self.emit_stack_base_addr(a, dst, 0);
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

    fn emit_stack_base_addr(&self, a: &mut CodeAssembler, dst: ArchReg, off: i64) -> Result<(), String> {
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
            self.emit_alu_imm(a, AluOp::Add, dst, rel as u64, None)
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
            ExprNode::StackBase => self.emit_stack_base_addr(a, dst, 0),
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
                        return self.emit_stack_base_addr(a, dst, off);
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
            ExprNode::Opaque(_) | ExprNode::AlignedBase(_) | ExprNode::XmmIn(_, _) | ExprNode::CallRet { .. } => {
                Err("unlowerable_expr_node".into())
            }
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
            IrEffect::AtomicRmw { .. } => return Err("atomic_rmw_not_lowered".into()),
            IrEffect::CallNative { .. } => return Err("call_native_in_block".into()),
        }
    }
    Ok(())
}

fn expr_safe_in_place(arena: &ExprArena, expr: ExprId, dst_reg: ArchReg) -> bool {
    match arena.get(expr) {
        ExprNode::RegIn(_) => true,
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
        ExprNode::Const(_) | ExprNode::RegIn(_) | ExprNode::StackBase => false,
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
            if matches!(arena.get(expr), ExprNode::Add(..))
                && matches!(arena.as_stack_offset(expr), Some((StackSpace::CallerStack, _)))
            {
                return false;
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

fn emit_block_outputs_and_jump(
    a: &mut CodeAssembler,
    bitness: u32,
    arena: &ExprArena,
    effects: &[IrEffect],
    pending_caller_stores: &[(i64, ExprId)],
    final_regs: &[ExprId; 16],
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
            _ => {}
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
        || direct_plan.iter().any(|&d| !d);
    let need_w1 = effects.iter().any(|e| match e {
        IrEffect::Store { addr, .. } => {
            !matches!(arena.as_stack_offset(*addr), Some((StackSpace::CallerStack, _)))
        }
        IrEffect::AtomicCmpXchg { .. } => true,
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
            _ => false,
        })
        || modified
            .iter()
            .any(|&(_, expr)| expr_uses_spill(arena, bitness, expr));
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

    // Evaluate all modified architectural registers directly when acyclic,
    // falling back to stack-pushed staging otherwise.
    let [w0, _, w2] = ctx.scratch;
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
                // Evaluate block effects (preserving all inputs) then branch
                let mut avoid = HashSet::new();
                collect_read_regs_into(&func.arena, *cond, &mut avoid);
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
            IrTerm::ExitRet { rsp_delta, final_regs, pending_caller_stores, .. } => {
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    *rsp_delta,
                    true,
                    None,
                    |asm, _| asm.ret().map_err(|e| e.to_string()),
                )?;
            }
            IrTerm::ExitJmp { target_va, rsp_delta, final_regs, pending_caller_stores, .. } => {
                let tva = *target_va;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    *rsp_delta,
                    false,
                    None,
                    |asm, _| asm.jmp(tva).map_err(|e| e.to_string()),
                )?;
            }
            IrTerm::ExitCall { target_va, ret_va, rsp_delta, final_regs, pending_caller_stores, .. } => {
                let tva = *target_va;
                let rva = *ret_va;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
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
            IrTerm::ExitAddJmp { reg, rsp_delta, final_regs, .. } => {
                let dst_reg = *reg;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    &[],
                    final_regs,
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
            IrTerm::ExitIndirectMem { rsp_disp, rsp_delta, final_regs, pending_caller_stores, .. } => {
                let d32 = i32::try_from(*rsp_disp).map_err(|_| "exit_ind_mem_disp_i32".to_string())?;
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &func.arena,
                    &block.effects,
                    pending_caller_stores,
                    final_regs,
                    *rsp_delta,
                    false,
                    None,
                    |asm, ctx| {
                        let m = mem_disp(ctx.bitness, ArchReg::Rsp, d32 as i64, ctx.word_bytes as u8);
                        asm.jmp(m).map_err(|e| e.to_string())
                    },
                )?;
            }
            IrTerm::MidCall { target, rsp_delta, final_regs, pending_caller_stores, cont_block, .. } => {
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
    let mut visited_vm_bytes: HashSet<u64> = HashSet::new();
    let mut partially_lifted = 0usize;
    let mut failed = 0usize;

    let mut compiled_funcs: Vec<(LiftedFunction, Vec<u8>)> = Vec::new();
    let (next_rva, _) = imagedump::next_section_rva(pe_bytes)?;
    let devirt_base_va = view.image_base + next_rva as u64;

    for entry in &discovered {
        let lifted = lift_vm_entry_cfg(&view, entry, &cfg);
        visited_vm_bytes.extend(&lifted.visited_byte_addrs);

        if let Err(reason) = validate_function_soundness(&lifted, &view) {
            if lifted.raw_vm_insns > 0 {
                partially_lifted += 1;
            } else {
                failed += 1;
            }
            *bailout_counts.entry(reason).or_insert(0) += 1;
            continue;
        }

        // Compile standalone test snippet first to verify encodability and check instruction reduction
        let mut test_asm = CodeAssembler::new(view.bitness)
            .map_err(|e| UnpackerError::General(format!("CodeAssembler: {e}")))?;
        let mut test_lbl = test_asm.create_label();
        if let Err(err) = compile_function_into_asm(&mut test_asm, view.bitness, &lifted, &mut test_lbl) {
            partially_lifted += 1;
            *bailout_counts.entry(format!("codegen_{err}")).or_insert(0) += 1;
            continue;
        }
        let Ok(test_res) = test_asm.assemble_options(devirt_base_va, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS) else {
            partially_lifted += 1;
            *bailout_counts.entry("asm_encode_failed".into()).or_insert(0) += 1;
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
            partially_lifted += 1;
            *bailout_counts.entry("invalid_emitted_insn".into()).or_insert(0) += 1;
            continue;
        }

        // Enforce genuine code reduction on VM enters
        if entry.kind == VmEntryKind::CrossSectionVmEnter
            && lifted.raw_vm_insns > 0
            && native_insns >= lifted.raw_vm_insns
        {
            partially_lifted += 1;
            *bailout_counts.entry("no_code_reduction".into()).or_insert(0) += 1;
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
}
