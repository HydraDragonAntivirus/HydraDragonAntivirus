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
    /// A recompiled VM enter, or anything that hands control back to the VM, must
    /// replace at least this many VM instructions: less is a stub that only re-enters
    /// the VM.
    pub min_vm_insns_replaced: usize,
    /// Upper bound on the recompiled code, in percent of the VM instructions it
    /// replaces. Native code that every VM exit fills the VM context from is often
    /// larger than the VM path it replaces, and still what an analyst wants to read;
    /// this only stops pathological growth.
    pub max_code_growth_percent: usize,
    pub collect_diagnostics: bool,
    /// Reconstruct a directly runnable PE after devirtualization (`.import`, CRT OEP,
    /// `VMProtectRuntime` + `LoaderData` init, `.vmpinit` bootstrap, ASLR disabled).
    pub rebuild_runnable_pe: bool,
    /// Optional explicit OEP RVA override when rebuilding a runnable PE.
    pub oep_rva: Option<u32>,
}

impl Default for BinaryDevirtConfig {
    fn default() -> Self {
        Self {
            max_entries: usize::MAX,
            max_blocks_per_entry: 64,
            max_insns_per_block: 4_000,
            max_total_insns_per_entry: 25_000,
            max_inline_depth: 512,
            include_trampolines: true,
            include_vmenters: true,
            extra_entry_rvas: Vec::new(),
            allow_vm_exits: true,
            min_vm_insns_replaced: 8,
            max_code_growth_percent: 400,
            collect_diagnostics: false,
            rebuild_runnable_pe: true,
            oep_rva: None,
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
    pub vmp_rebuild: Option<crate::unpacker::vmp_rebuild::VmpRebuildReport>,
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

        // Pick primary host section: use the OEP section if it is `.text`/`.code` or
        // classified Normal; otherwise (e.g. VMProtect OEP redirected into a VM/packer
        // section), prefer an executable `.text`/`.code` section with raw data.
        let oep_sec = raw_secs.iter().find(|s| {
            (s.characteristics & 0x2000_0000) != 0
                && opt.address_of_entry_point >= s.virtual_address
                && opt.address_of_entry_point
                    < s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data))
        });
        let oep_prof_kind = oep_sec.and_then(|s| {
            vm_prof
                .executable_sections
                .iter()
                .find(|v| v.virtual_address == s.virtual_address)
                .map(|v| v.kind)
        });
        let text_sec_va = vm_prof
            .executable_sections
            .iter()
            .find(|s| {
                s.raw_size > 0
                    && (s.name.eq_ignore_ascii_case(".text") || s.name.eq_ignore_ascii_case(".code"))
            })
            .map(|s| s.virtual_address);
        let primary_va = match oep_sec {
            Some(s)
                if s.name.trim().eq_ignore_ascii_case(".text")
                    || s.name.trim().eq_ignore_ascii_case(".code")
                    || oep_prof_kind == Some(SectionVmKind::Normal) =>
            {
                Some(s.virtual_address)
            }
            _ => text_sec_va
                .or_else(|| oep_sec.map(|s| s.virtual_address))
                .or_else(|| vm_prof.executable_sections.first().map(|s| s.virtual_address)),
        };

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
    pub fn is_in_primary_host(&self, va: u64) -> bool {
        self.section_at_va(va).is_some_and(|s| s.is_primary_host)
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

    pub fn add_mutable_ro_va(&mut self, va: u64, len: u32) -> bool {
        let Some(rva) = self.va_to_rva(va).and_then(|r| u32::try_from(r).ok()) else {
            return false;
        };
        let end = rva.saturating_add(len);
        if self
            .mutable_ro_ranges
            .iter()
            .any(|&(lo, hi)| lo <= rva && hi >= end)
        {
            return false;
        }
        self.mutable_ro_ranges.push((rva, end));
        true
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
    let mut insns = Vec::with_capacity(40);
    let mut in_vm_calls = 0usize;
    for _ in 0..40 {
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
                if t != 0 && view.is_in_vm_section(t) && insns.len() < 32 {
                    va = t;
                    continue;
                }
                if t != 0 && view.is_in_primary_host(t) && insns.len() <= 16 {
                    return StubClassify::Trampoline;
                }
                break;
            }
            FlowControl::Call => {
                let t = ins.near_branch_target();
                if t != 0 && view.is_in_vm_section(t) && insns.len() < 32 {
                    in_vm_calls += 1;
                    va = t;
                    continue;
                }
                break;
            }
            FlowControl::Next => {
                va = next_va;
            }
            FlowControl::IndirectBranch => {
                if insns.len() <= 14 && in_vm_calls == 0 && is_short_trampoline_sequence(&insns) {
                    return StubClassify::Trampoline;
                }
                return StubClassify::VmEnter;
            }
            FlowControl::Return if insns.len() <= 8 => {
                if in_vm_calls == 0 && insns.iter().any(|i| i.mnemonic() == Mnemonic::Push) {
                    return StubClassify::Trampoline;
                }
                return StubClassify::VmEnter;
            }
            _ => break,
        }
    }

    if !insns.is_empty() && looks_like_vmenter_prologue(&insns, in_vm_calls) {
        return StubClassify::VmEnter;
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

fn looks_like_vmenter_prologue(insns: &[Instruction], in_vm_calls: usize) -> bool {
    if insns.iter().any(|i| {
        ((i.mnemonic() == Mnemonic::Lea || i.mnemonic() == Mnemonic::Sub)
            && matches!(i.op0_register(), Register::RSP | Register::ESP))
            || matches!(
                i.mnemonic(),
                Mnemonic::Pushfq | Mnemonic::Pushfd | Mnemonic::Pushad
            )
    }) {
        return true;
    }
    if insns.iter().filter(|i| i.mnemonic() == Mnemonic::Push).count() >= 2 {
        return true;
    }
    if in_vm_calls >= 1
        && insns.iter().any(|i| {
            matches!(i.mnemonic(), Mnemonic::Push | Mnemonic::Pop)
                || (i.mnemonic() == Mnemonic::Xchg
                    && (i.op0_kind() == OpKind::Memory || i.op1_kind() == OpKind::Memory))
                || (matches!(
                    i.mnemonic(),
                    Mnemonic::Add | Mnemonic::Sub | Mnemonic::Lea | Mnemonic::Mov
                ) && matches!(i.op0_register(), Register::RSP | Register::ESP))
        })
    {
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
        /// Its outputs (`ExprNode::EffectOut`): RFLAGS and RAX after it.
        out_id: u32,
    },
    AtomicRmw {
        lock: bool,
        op: AtomicOpKind,
        addr: ExprId,
        width: u8,
        src: ExprId,
        mem_ver_after: u32,
        /// Its output (`ExprNode::EffectOut`): RFLAGS after it.
        out_id: u32,
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
    ExitComputedJmp {
        target: ExprId,
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
    /// Aligned slots written straight in step 3, without a temporary: `(base index,
    /// offset from that base, value)` - a constant, or a register that holds the value
    /// as its final one.
    pub direct_stores: Vec<(u32, i64, DirectVal)>,
    /// Per base: the temporary offset of its run-time part (`ExprNode::AlignedDyn`),
    /// computed with the other values and added before the `and`.
    pub base_dyn: Vec<Option<i64>>,
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

/// A value `VmExit` step 3 can store as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectVal {
    Imm(u64),
    /// Holds the value as its final value (never RAX / RCX / RSP: step 3 uses them).
    Reg(ArchReg),
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
    /// `push a; popfq`: the flags are still the entry ones, `a` holds the saved RFLAGS.
    Popf { a: i64 },
}

#[derive(Debug, Clone)]
pub struct LiftedBlock {
    pub id: usize,
    pub entry_va: u64,
    pub effects: Vec<IrEffect>,
    pub term: IrTerm,
    /// What `AlignedBase(i)` is in this block (index = i, as `SymState::aligned_defs`):
    /// ids are per path, so blocks of different paths may give one id different frames.
    pub aligned_defs: Vec<(StackSpace, i64, u64)>,
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
    pub folded_vm_qword_addrs: Vec<u64>,
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
            ExprNode::EntryRflags => out.push_str("EntryRflags"),
            ExprNode::AlignedBase(n) => out.push_str(&format!("AlignedBase({n})")),
            ExprNode::EffectOut { id, what } => out.push_str(&format!("EffectOut({id},{what})")),
            ExprNode::AlignedDyn(n, x) => {
                out.push_str(&format!("AlignedDyn({n},"));
                rec(arena, *x, d, out);
                out.push(')');
            }
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
            ExprNode::MulHiU(a, b) | ExprNode::MulHiS(a, b) => {
                out.push_str(if matches!(arena.get(id), ExprNode::MulHiS(..)) { "MulHiS(" } else { "MulHiU(" });
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
        ExprNode::EntryRflags => "EntryRflags",
        ExprNode::AlignedBase(_) => "AlignedBase",
        ExprNode::AlignedDyn(..) => "AlignedDyn",
        ExprNode::EffectOut { .. } => "EffectOut",
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
        ExprNode::MulHiU(..) => "MulHiU",
        ExprNode::MulHiS(..) => "MulHiS",
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
            ExprNode::AlignedDyn(_, x) => {
                ab = true;
                stack.push(*x);
            }
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
            | ExprNode::Ror(a, b)
            | ExprNode::MulHiU(a, b)
            | ExprNode::MulHiS(a, b) => {
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
        ConditionCode::p => Some(14),
        ConditionCode::np => Some(15),
        _ => None,
    }
}

fn as_direct_entry_flag(arena: &ExprArena, id: ExprId) -> Option<u8> {
    match arena.get(id) {
        ExprNode::EntryFlag(c) if *c <= 15 => Some(*c),
        ExprNode::Cmp { pred: CondPred::Ne, lhs, rhs } if arena.as_const(*rhs) == Some(0) => {
            if let ExprNode::EntryFlag(c) = arena.get(*lhs) {
                if *c <= 15 {
                    return Some(*c);
                }
            }
            None
        }
        ExprNode::Cmp { pred: CondPred::Eq, lhs, rhs } if arena.as_const(*rhs) == Some(0) => {
            if let ExprNode::EntryFlag(c) = arena.get(*lhs) {
                if *c <= 15 {
                    return Some(*c ^ 1);
                }
            }
            None
        }
        ExprNode::Xor(a, b) if arena.as_const(*b) == Some(1) => {
            if let ExprNode::EntryFlag(c) = arena.get(*a) {
                if *c <= 15 {
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
    /// The flags are the bits of this RFLAGS value (captured at run time after an
    /// atomic operation: `ExprNode::EffectOut`).
    Rflags(ExprId),
    /// Full RFLAGS word restored via `popfq` from a non-frame-saved value (e.g. a
    /// caller-saved RFLAGS stack slot). Carries its own system bits (unlike `Rflags`,
    /// which comes from an in-stub `EffectOut` inheriting the frame's entry system bits).
    PoppedRflags(ExprId),
    CarryExpr(ExprId),
}

#[derive(Debug, Clone)]
struct SymState {
    ip: u64,
    regs: [ExprId; 16],
    xmms: [(ExprId, ExprId); 16],
    stack: SymStack,
    flags: FlagState,
    saved_rflags: Vec<(ExprId, FlagState, bool, Option<ExprId>)>,
    known_rflags_bits: Option<(ExprId, u64, u64)>,
    entry_flags_clobbered: bool,
    mem_ver: u32,
    cr8_ver: u32,
    mem_cache: HashMap<ExprId, (u8, ExprId)>,
    next_aligned_id: u32,
    /// How each `AlignedBase(id)` was made (index = id): RSP was `parent + off` and
    /// `and rsp, mask` aligned it. Lets an exit rebuild the aligned frame at run time
    /// (`IrTerm::ExitToVm`), where the alignment padding is only known then.
    aligned_defs: Vec<(StackSpace, i64, u64)>,
    /// The run-time part of each aligned frame's base (`ExprNode::AlignedDyn`), by id.
    aligned_dyn: Vec<Option<ExprId>>,
    /// `stack address & mask` values memory was read or written through as plain
    /// memory (`note_stack_mask_access`): such a value becomes an aligned frame only
    /// while nothing went through it that way (`adopt_rsp_alignment`).
    stack_masks_accessed: HashSet<ExprId>,
    /// RFLAGS bits other than the status flags (DF, IF, TF, ...) may differ from the
    /// frame's entry RFLAGS (`cld` / `std`, a `popfq` of a value not saved here).
    system_flags_changed: bool,
    /// Full RFLAGS expression supplying non-status (`!0x8D5`) bits when `system_flags_changed`
    /// is true (`None` = unknown system bits).
    system_rflags: Option<ExprId>,
    inline_depth: usize,
    cum_rsp_offset: i64,
    entry_caller_slot_versions: HashMap<i64, ExprId>,
    folded_vm_qword_addrs: HashSet<u64>,
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
                known_rflags_bits: None,
                entry_flags_clobbered: false,
                mem_ver: 0,
                cr8_ver: 0,
                mem_cache: HashMap::new(),
                next_aligned_id: 0,
                aligned_defs: Vec::new(),
                aligned_dyn: Vec::new(),
                stack_masks_accessed: HashSet::new(),
                system_flags_changed: false,
                system_rflags: None,
                inline_depth: 0,
                cum_rsp_offset: 0,
                entry_caller_slot_versions,
                folded_vm_qword_addrs: HashSet::new(),
            };
        }
        Self {
            ip: start_va,
            regs,
            xmms,
            stack,
            flags: FlagState::Entry,
            saved_rflags: Vec::new(),
            known_rflags_bits: None,
            entry_flags_clobbered: false,
            mem_ver: 0,
            cr8_ver: 0,
            mem_cache: HashMap::new(),
            next_aligned_id: 0,
            aligned_defs: Vec::new(),
            aligned_dyn: Vec::new(),
            stack_masks_accessed: HashSet::new(),
            system_flags_changed: false,
            system_rflags: None,
            inline_depth: 0,
            cum_rsp_offset: 0,
            entry_caller_slot_versions,
            folded_vm_qword_addrs: HashSet::new(),
        }
    }

    #[inline]
    fn set_flags(&mut self, flags: FlagState) {
        self.flags = flags;
        self.known_rflags_bits = None;
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
                    ConditionCode::p | ConditionCode::np => {
                        let diff = arena.sub(la, rb);
                        let pf = parity_flag(arena, diff);
                        Some(if cc == ConditionCode::p { pf } else { arena.xor_const(pf, 1) })
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
                    ConditionCode::p | ConditionCode::np => {
                        let pf = parity_flag(arena, zv);
                        Some(if cc == ConditionCode::p { pf } else { arena.xor_const(pf, 1) })
                    }
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
                    let pf = ((r_val as u8).count_ones() & 1) == 0;
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
                        ConditionCode::p => pf,
                        ConditionCode::np => !pf,
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
                    ConditionCode::p | ConditionCode::np => {
                        let pf = parity_flag(arena, zr);
                        Some(if cc == ConditionCode::p { pf } else { arena.xor_const(pf, 1) })
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
                    ConditionCode::p | ConditionCode::np => {
                        let pf = parity_flag(arena, zr);
                        Some(if cc == ConditionCode::p { pf } else { arena.xor_const(pf, 1) })
                    }
                    _ => None,
                }
            }
            FlagState::Rflags(v) | FlagState::PoppedRflags(v) => {
                let rf = *v;
                if let Some((base_rf, kz, ko)) = self.known_rflags_bits {
                    if (kz | ko) != 0 && unwrap_masked_rflags_base(arena, rf) == base_rf {
                        let mut masked = rf;
                        if kz != 0 {
                            masked = arena.and_const(masked, !kz);
                        }
                        if ko != 0 {
                            masked = arena.or_const(masked, ko);
                        }
                        if let Some(c) = rflags_cond(arena, masked, cc) {
                            if arena.as_const(c).is_some() {
                                return Some(c);
                            }
                        }
                    }
                }
                rflags_cond(arena, rf, cc)
            }
            FlagState::CarryExpr(bit) => match cc {
                ConditionCode::b => Some(*bit),
                ConditionCode::ae => Some(arena.xor_const(*bit, 1)),
                _ => None,
            },
            FlagState::Entry => {
                if !self.entry_flags_clobbered && self.cum_rsp_offset == 0 {
                    // Block 0 can still branch on the hardware flags directly.
                    entry_cc_to_u8(cc).map(|c| arena.entry_flag(c))
                } else {
                    // Anywhere else: the bits of the frame's saved entry RFLAGS.
                    let entry_rf = arena.entry_rflags();
                    if let Some((base_rf, kz, ko)) = self.known_rflags_bits {
                        if (kz | ko) != 0 && base_rf == entry_rf {
                            let mut masked = entry_rf;
                            if kz != 0 {
                                masked = arena.and_const(masked, !kz);
                            }
                            if ko != 0 {
                                masked = arena.or_const(masked, ko);
                            }
                            if let Some(c) = rflags_cond(arena, masked, cc) {
                                if arena.as_const(c).is_some() {
                                    return Some(c);
                                }
                            }
                        }
                    }
                    entry_rflags_cond(arena, cc)
                }
            }
            FlagState::Unknown => None,
        }
    }

    /// A condition as a value (`setcc`, `cmov`, `adc`, `sbb`): like `eval_cond_code`,
    /// but entry flags always come from the saved RFLAGS - the `EntryFlag` form only
    /// lowers as block 0's own branch, not inside an expression.
    fn cond_value(&self, arena: &mut ExprArena, cc: ConditionCode) -> Option<ExprId> {
        if matches!(self.flags, FlagState::Entry) {
            return entry_rflags_cond(arena, cc);
        }
        self.eval_cond_code(arena, cc)
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

/// RFLAGS after the last status-flag operation, for `pushfq`: the status flags from
/// that operation, every other bit from the frame's entry RFLAGS (unless those may have
/// changed). After `cmp` / `sub` / `neg` and `add` all six status flags are defined.
/// After the logical operations AF is architecturally undefined: it is taken as 0, what
/// Intel and AMD processors (and the emulators) produce.
fn composed_rflags(state: &SymState, arena: &mut ExprArena) -> Option<ExprId> {
    if let FlagState::PoppedRflags(v) = &state.flags {
        // Non-canonical constants (e.g. `push 0; popfq; pushfq`) have hardware-masked
        // reserved/privilege bits that depend on CPL; reject them conservatively, while
        // forwarding canonical constants and symbolic caller-saved RFLAGS slots.
        if let Some(c) = arena.as_const(*v) {
            if (c & !0x0024_4DD5u64) != 0x202u64 {
                return None;
            }
        }
        return Some(*v);
    }
    if let FlagState::Rflags(v) = &state.flags {
        if !state.system_flags_changed {
            return Some(*v);
        }
        return None;
    }
    let sys_base = if !state.system_flags_changed {
        arena.entry_rflags()
    } else if let Some(sr) = state.system_rflags {
        sr
    } else {
        return None;
    };
    match &state.flags {
        FlagState::Entry => {
            if !state.system_flags_changed {
                Some(arena.entry_rflags())
            } else {
                None
            }
        }
        FlagState::TestBitwise { val, width } => {
            let res = arena.zext_mask(*val, *width);
            let zf = state.eval_cond_code(arena, ConditionCode::e)?;
            let sf = state.eval_cond_code(arena, ConditionCode::s)?;
            let pf = parity_flag(arena, res);
            // CF = OF = 0; AF = 0 (see above).
            Some(rflags_from_status(arena, sys_base, [None, Some(pf), None, Some(zf), Some(sf), None]))
        }
        FlagState::SubCmp { .. } | FlagState::Add { .. } => {
            let (l, r, res) = match &state.flags {
                FlagState::SubCmp { lhs, rhs, width } => {
                    let la = arena.zext_mask(*lhs, *width);
                    let rb = arena.zext_mask(*rhs, *width);
                    let d = arena.sub(la, rb);
                    let res = arena.zext_mask(d, *width);
                    (la, rb, res)
                }
                FlagState::Add { lhs, rhs, res, width } => {
                    let la = arena.zext_mask(*lhs, *width);
                    let rb = arena.zext_mask(*rhs, *width);
                    let rr = arena.zext_mask(*res, *width);
                    (la, rb, rr)
                }
                _ => unreachable!(),
            };
            let cf = state.eval_cond_code(arena, ConditionCode::b)?;
            let pf = parity_flag(arena, res);
            let zf = state.eval_cond_code(arena, ConditionCode::e)?;
            let sf = state.eval_cond_code(arena, ConditionCode::s)?;
            let of = state.eval_cond_code(arena, ConditionCode::o)?;
            // AF: the carry out of bit 3 = bit 4 of lhs ^ rhs ^ result.
            let x1 = arena.xor(l, r);
            let x2 = arena.xor(x1, res);
            let x3 = arena.shr_const(x2, 4);
            let af = arena.and_const(x3, 1);
            Some(rflags_from_status(arena, sys_base, [Some(cf), Some(pf), Some(af), Some(zf), Some(sf), Some(of)]))
        }
        _ => None,
    }
}

/// PF: an even number of set bits in the low byte of `res`.
fn parity_flag(arena: &mut ExprArena, res: ExprId) -> ExprId {
    let lo = arena.and_const(res, 0xFF);
    let f4 = arena.shr_const(lo, 4);
    let x4 = arena.xor(lo, f4);
    let f2 = arena.shr_const(x4, 2);
    let x2 = arena.xor(x4, f2);
    let f1 = arena.shr_const(x2, 1);
    let x1 = arena.xor(x2, f1);
    let odd = arena.and_const(x1, 1);
    arena.xor_const(odd, 1)
}

/// `base_rflags` with CF, PF, AF, ZF, SF, OF replaced (`None`: 0).
fn rflags_from_status(arena: &mut ExprArena, base_rflags: ExprId, flags: [Option<ExprId>; 6]) -> ExprId {
    const STATUS: u64 = 0x8D5; // CF PF AF ZF SF OF
    let mut v = arena.and_const(base_rflags, !STATUS);
    for (bit, f) in [0u64, 2, 4, 6, 7, 11].into_iter().zip(flags) {
        if let Some(f) = f {
            let b = arena.and_const(f, 1);
            let sh = arena.shl_const(b, bit);
            v = arena.or(v, sh);
        }
    }
    v
}

/// A condition code read from the frame's saved entry RFLAGS (`ExprNode::EntryRflags`):
/// CF bit 0, PF bit 2, ZF bit 6, SF bit 7, OF bit 11.
fn entry_rflags_cond(arena: &mut ExprArena, cc: ConditionCode) -> Option<ExprId> {
    let rf = arena.entry_rflags();
    rflags_cond(arena, rf, cc)
}

/// A condition code read from the bits of an RFLAGS value.
fn rflags_cond(arena: &mut ExprArena, rf: ExprId, cc: ConditionCode) -> Option<ExprId> {
    let bit = |arena: &mut ExprArena, n: u64| {
        let s = arena.shr_const(rf, n);
        arena.and_const(s, 1)
    };
    let cf = bit(arena, 0);
    let pf = bit(arena, 2);
    let zf = bit(arena, 6);
    let sf = bit(arena, 7);
    let of = bit(arena, 11);
    Some(match cc {
        ConditionCode::b => cf,
        ConditionCode::ae => arena.xor_const(cf, 1),
        ConditionCode::e => zf,
        ConditionCode::ne => arena.xor_const(zf, 1),
        ConditionCode::be => arena.or(cf, zf),
        ConditionCode::a => {
            let x = arena.or(cf, zf);
            arena.xor_const(x, 1)
        }
        ConditionCode::s => sf,
        ConditionCode::ns => arena.xor_const(sf, 1),
        ConditionCode::p => pf,
        ConditionCode::np => arena.xor_const(pf, 1),
        ConditionCode::o => of,
        ConditionCode::no => arena.xor_const(of, 1),
        ConditionCode::l => arena.xor(sf, of),
        ConditionCode::ge => {
            let x = arena.xor(sf, of);
            arena.xor_const(x, 1)
        }
        ConditionCode::le => {
            let x = arena.xor(sf, of);
            arena.or(zf, x)
        }
        ConditionCode::g => {
            let x = arena.xor(sf, of);
            let le = arena.or(zf, x);
            arena.xor_const(le, 1)
        }
        _ => return None,
    })
}

/// RDX (EDX) of a one-operand `mul` / `imul` of width `w`: a `MulHi` node for 64 bits,
/// plain arithmetic on the extended operands for 32 bits (the product fits in 64).
fn mul_high_half(arena: &mut ExprArena, a: ExprId, b: ExprId, w: u8, signed: bool) -> ExprId {
    if w == 8 {
        return arena.mul_hi(a, b, signed);
    }
    let (xa, xb) = if signed {
        (arena.sext(a, 32), arena.sext(b, 32))
    } else {
        (arena.zext_mask(a, 4), arena.zext_mask(b, 4))
    };
    let prod = arena.mul(xa, xb);
    let hi = arena.shr_const(prod, 32);
    arena.zext_mask(hi, 4)
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

/// The `stack address & -2^k` subexpressions of `addr` (`SymState::stack_masks_accessed`).
fn note_stack_mask_access(state: &mut SymState, arena: &ExprArena, addr: ExprId) {
    let mut st = vec![(addr, 0u8)];
    while let Some((id, d)) = st.pop() {
        if d > 8 {
            continue;
        }
        let frame_like = as_stack_mask(arena, id).is_some()
            || matches!(arena.get(id), ExprNode::And(_, m) if arena.as_const(*m).is_some_and(is_frame_mask));
        if frame_like {
            state.stack_masks_accessed.insert(id);
            continue;
        }
        let mut ch = Vec::new();
        push_expr_children(arena.get(id), &mut ch);
        st.extend(ch.into_iter().map(|c| (c, d + 1)));
    }
}

/// `x & mask` with `x` a stack address and `mask` a negative power of two (at most 256
/// in size): an aligned frame base, as `and rsp, mask` makes one.
fn as_stack_mask(arena: &ExprArena, id: ExprId) -> Option<((StackSpace, i64), u64)> {
    let ExprNode::And(x, m) = arena.get(id) else { return None };
    let mask = arena.as_const(*m)?;
    if !is_frame_mask(mask) {
        return None;
    }
    Some((arena.as_stack_offset(*x)?, mask))
}

fn is_frame_mask(mask: u64) -> bool {
    let sm = mask as i64;
    sm < 0 && sm >= -256 && sm.abs().count_ones() == 1
}

/// A stack address plus a run-time value: `(space, off)` and the value. Only a value
/// that reads no memory and nothing unknown (it is evaluated wherever the frame's base
/// is, and by a VM exit), on the caller stack or a frame of fixed position.
fn split_dynamic_stack_addr(state: &SymState, arena: &mut ExprArena, x: ExprId) -> Option<((StackSpace, i64), ExprId)> {
    // `x` as a sum: exactly one stack base (added), constants, and the rest.
    fn terms(arena: &ExprArena, id: ExprId, neg: bool, depth: u8, out: &mut Vec<(bool, ExprId)>, k: &mut i64) -> bool {
        if depth > 16 || out.len() > 32 {
            return false;
        }
        if let Some(c) = arena.as_const(id) {
            *k = if neg { k.wrapping_sub(c as i64) } else { k.wrapping_add(c as i64) };
            return true;
        }
        match arena.get(id) {
            ExprNode::Add(a, b) => terms(arena, *a, neg, depth + 1, out, k) && terms(arena, *b, neg, depth + 1, out, k),
            ExprNode::Sub(a, b) => terms(arena, *a, neg, depth + 1, out, k) && terms(arena, *b, !neg, depth + 1, out, k),
            ExprNode::Neg(a) => terms(arena, *a, !neg, depth + 1, out, k),
            _ => {
                out.push((neg, id));
                true
            }
        }
    }
    let mut parts = Vec::new();
    let mut k = 0i64;
    if !terms(arena, x, false, 0, &mut parts, &mut k) {
        return None;
    }
    let is_base = |arena: &ExprArena, id: ExprId| matches!(arena.get(id), ExprNode::StackBase | ExprNode::AlignedBase(_));
    let mut bases = parts.iter().filter(|&&(_, id)| is_base(arena, id));
    let &(base_neg, base) = bases.next()?;
    if base_neg || bases.next().is_some() {
        return None;
    }
    let mut dyn_off: Option<ExprId> = None;
    for &(neg, id) in parts.iter().filter(|&&(_, id)| id != base) {
        let t = if neg { arena.neg(id) } else { id };
        dyn_off = Some(match dyn_off {
            None => t,
            Some(acc) => arena.add(acc, t),
        });
    }
    let dyn_off = dyn_off?;
    let (space, off0) = arena.as_stack_offset(base)?;
    let off = off0.wrapping_add(k);
    if let StackSpace::AlignedScratch(p) = space {
        if state.aligned_dyn.get(p as usize).copied().flatten().is_some() {
            return None;
        }
    }
    if arena.as_const(dyn_off).is_some() || !dynamic_part_ok(arena, dyn_off) {
        return None;
    }
    Some(((space, off), dyn_off))
}

/// No load, unknown, call result, flags or frame base inside.
fn dynamic_part_ok(arena: &ExprArena, root: ExprId) -> bool {
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if matches!(
            node,
            ExprNode::Load { .. }
                | ExprNode::Opaque(_)
                | ExprNode::CallRet { .. }
                | ExprNode::Cr8Read(_)
                | ExprNode::EntryFlag(_)
                | ExprNode::AlignedBase(_)
                | ExprNode::AlignedDyn(..)
                | ExprNode::StackBase
        ) {
            return false;
        }
        push_expr_children(node, &mut st);
    }
    seen.len() <= 256
}

/// RSP became `(stack address & mask) + c` through a copy (`mov rax, rsp; and rax,
/// -16; mov rsp, rax`): the same frame alignment as `and rsp, mask`. The masked value
/// becomes a new `AlignedBase` everywhere in the state, unless memory was already
/// accessed through it as plain memory (those accesses would not be in the frame's
/// slots).
fn adopt_rsp_alignment(state: &mut SymState, arena: &mut ExprArena) -> bool {
    let rsp = state.regs[ArchReg::Rsp.idx()];
    if arena.as_stack_offset(rsp).is_some() {
        return false;
    }
    let masked = match arena.get(rsp).clone() {
        ExprNode::Add(a, b) if arena.as_const(b).is_some() => a,
        ExprNode::Add(a, b) if arena.as_const(a).is_some() => b,
        _ => rsp,
    };
    let (parent, poff, mask, dyn_off) = match as_stack_mask(arena, masked) {
        Some(((p, o), m)) => (p, o, m, None),
        None => {
            let ExprNode::And(x, m) = arena.get(masked).clone() else { return false };
            let Some(mask) = arena.as_const(m).filter(|&mk| is_frame_mask(mk)) else { return false };
            let Some(((p, o), d)) = split_dynamic_stack_addr(state, arena, x) else { return false };
            (p, o, mask, Some(d))
        }
    };
    if state.stack_masks_accessed.contains(&masked) || state.aligned_defs.len() != state.next_aligned_id as usize {
        return false;
    }
    if let StackSpace::AlignedScratch(p) = parent {
        if p as usize >= state.aligned_defs.len() {
            return false;
        }
    }
    let aid = state.next_aligned_id;
    state.next_aligned_id += 1;
    state.aligned_defs.push((parent, poff, mask));
    state.aligned_dyn.push(dyn_off);
    // A run-time base has no known place below the entry RSP: its unwritten slots stay
    // unknown.
    if parent == StackSpace::CallerStack && dyn_off.is_none() {
        state.stack.note_aligned_frame(aid, poff);
    }
    let abase = match dyn_off {
        Some(d) => arena.aligned_dyn(aid, d),
        None => arena.aligned_base(aid),
    };
    substitute_in_state(arena, state, masked, abase);
    true
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
    if let Some((space, off)) = stack_slot_addr(arena, addr) {
        return state.stack.read_scalar(arena, space, off, width, state.mem_ver);
    }
    note_stack_mask_access(state, arena, addr);
    if let Some(&(cached_w, cached_v)) = state.mem_cache.get(&addr) {
        if cached_w == width {
            return cached_v;
        }
    }
    if let Some(va) = arena.as_const(addr) {
        if let Some(ro_val) = view.read_ro_scalar(va, width) {
            if width == 8 && view.is_in_vm_section(va) {
                state.folded_vm_qword_addrs.insert(va);
            }
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
    if let Some((space, off)) = stack_slot_addr(arena, addr) {
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
                // A caller-frame slot is written like an unconditional one (above).
                let visible = is_caller_frame_slot(sp1, off1) || is_caller_frame_slot(sp0, off0);
                if (sp1, off1) == (sp0, off0) {
                    state.stack.write_scalar(arena, sp1, off1, width, masked, state.mem_ver);
                } else {
                    // Each arm keeps its old value where the other one is written.
                    let old1 = state.stack.read_scalar(arena, sp1, off1, width, state.mem_ver);
                    let old0 = state.stack.read_scalar(arena, sp0, off0, width, state.mem_ver);
                    let new1 = arena.select(cond, masked, old1);
                    let new0 = arena.select(cond, old0, masked);
                    state.stack.write_scalar(arena, sp1, off1, width, new1, state.mem_ver);
                    state.stack.write_scalar(arena, sp0, off0, width, new0, state.mem_ver);
                }
                if visible {
                    state.mem_ver += 1;
                }
                return;
            }
        }
    }

    note_stack_mask_access(state, arena, addr);
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
            if let Some((space, off)) = stack_slot_addr(arena, ea) {
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
    eval_cond_for_mnemonic_as(state, arena, m, false)
}

/// `as_value`: the condition is used as a value (`setcc` / `cmov`), see `SymState::cond_value`.
fn eval_cond_for_mnemonic_as(state: &SymState, arena: &mut ExprArena, m: Mnemonic, as_value: bool) -> Option<ExprId> {
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
        Mnemonic::Cmovp | Mnemonic::Setp | Mnemonic::Jp => ConditionCode::p,
        Mnemonic::Cmovnp | Mnemonic::Setnp | Mnemonic::Jnp => ConditionCode::np,
        _ => return None,
    };
    if as_value {
        state.cond_value(arena, cc)
    } else {
        state.eval_cond_code(arena, cc)
    }
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
/// Signed range a value can take, for the shapes a run-time stack shift has (a masked
/// or shifted amount, its negation, sums); `None` when it is not bounded that way.
fn value_range(arena: &ExprArena, id: ExprId, depth: u8) -> Option<(i64, i64)> {
    if depth > 12 {
        return None;
    }
    if let Some(c) = arena.as_const(id) {
        return Some((c as i64, c as i64));
    }
    // Non-negative and bounded: known-zero high bits, or an upper bound through the
    // bit operations a shift amount is built from.
    let (zeros, _) = arena.known_bits(id);
    let top = 64 - zeros.leading_ones();
    if top < 40 {
        return Some((0, ((1u128 << top) - 1) as i64));
    }
    if let Some(ub) = unsigned_bound(arena, id, depth) {
        if ub < 1 << 40 {
            return Some((0, ub as i64));
        }
    }
    match arena.get(id) {
        ExprNode::Neg(x) => {
            let (lo, hi) = value_range(arena, *x, depth + 1)?;
            Some((hi.checked_neg()?, lo.checked_neg()?))
        }
        ExprNode::Add(a, b) => {
            let (al, ah) = value_range(arena, *a, depth + 1)?;
            let (bl, bh) = value_range(arena, *b, depth + 1)?;
            Some((al.checked_add(bl)?, ah.checked_add(bh)?))
        }
        ExprNode::Sub(a, b) => {
            let (al, ah) = value_range(arena, *a, depth + 1)?;
            let (bl, bh) = value_range(arena, *b, depth + 1)?;
            Some((al.checked_sub(bh)?, ah.checked_sub(bl)?))
        }
        _ => None,
    }
}

/// An upper bound of a value read as unsigned, through masks, shifts, bit operations,
/// sums and selections; `None` when there is none short of 2^64.
fn unsigned_bound(arena: &ExprArena, id: ExprId, depth: u8) -> Option<u64> {
    if depth > 16 {
        return None;
    }
    if let Some(c) = arena.as_const(id) {
        return Some(c);
    }
    let (zeros, _) = arena.known_bits(id);
    let from_bits = if zeros.leading_ones() > 0 { Some(u64::MAX >> zeros.leading_ones()) } else { None };
    let fill = |x: u64| if x == 0 { 0 } else { u64::MAX >> x.leading_zeros() };
    let b = |x: ExprId| unsigned_bound(arena, x, depth + 1);
    let r = match arena.get(id) {
        ExprNode::And(x, y) => match (b(*x), b(*y)) {
            (Some(p), Some(q)) => Some(p.min(q)),
            (Some(p), None) | (None, Some(p)) => Some(p),
            (None, None) => None,
        },
        ExprNode::Or(x, y) | ExprNode::Xor(x, y) => Some(fill(b(*x)?.max(b(*y)?))),
        ExprNode::Add(x, y) => b(*x)?.checked_add(b(*y)?),
        ExprNode::Shl(x, c) => {
            let s = arena.as_const(*c)?;
            let v = b(*x)?;
            if s >= 64 || v.leading_zeros() < s as u32 {
                None
            } else {
                Some(v << s)
            }
        }
        ExprNode::Shr(x, c) => {
            let s = arena.as_const(*c)?;
            Some(if s >= 64 { 0 } else { b(*x)? >> s })
        }
        ExprNode::Mul(x, y) => b(*x)?.checked_mul(b(*y)?),
        ExprNode::Cmp { .. } => Some(1),
        ExprNode::Select { if_true, if_false, .. } => Some(b(*if_true)?.max(b(*if_false)?)),
        _ => None,
    };
    match (r, from_bits) {
        (Some(p), Some(q)) => Some(p.min(q)),
        (r, q) => r.or(q),
    }
}

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
    if state.aligned_dyn.len() != bases.len() {
        return None;
    }
    // Lowest address (from the entry RSP) each aligned base can have; a run-time part
    // counts with the lowest value it can take (`value_range`).
    let mut lower: Vec<i64> = Vec::with_capacity(bases.len());
    for (k, &(parent, off, mask)) in bases.iter().enumerate() {
        let align = (!mask).checked_add(1)? as i64;
        if !(2..=256).contains(&align) {
            return None;
        }
        let parent_lower = match parent {
            StackSpace::CallerStack => 0,
            StackSpace::AlignedScratch(p) => *lower.get(p as usize)?,
        };
        let dyn_lo = match state.aligned_dyn[k] {
            Some(d) => {
                let (lo, _) = value_range(arena, d, 0)?;
                if lo < -(1 << 24) {
                    return None;
                }
                lo
            }
            None => 0,
        };
        lower.push(parent_lower.checked_add(off)?.checked_add(dyn_lo)?.checked_sub(align - 1)?);
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
    let flags_kind: Option<(u8, u8)>; // (0 cmp / 1 test / 2 add / 3 popf, width)
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
            FlagState::Entry => {
                // The frame's entry RFLAGS, saved where the frame began.
                flag_vals = vec![arena.entry_rflags()];
                flags_kind = Some((3, 8));
            }
            FlagState::Rflags(v) | FlagState::PoppedRflags(v) => {
                flag_vals = vec![*v];
                flags_kind = Some((3, 8));
            }
            _ => return None,
        }
        if !matches!(flags_kind, Some((_, 1 | 2 | 4 | 8))) {
            return None;
        }
        // `popfq` puts back every bit: the system ones are the frame's entry ones, wrong
        // once the VM changed them (`cld` / `std`, ...), unless `PoppedRflags` carries
        // the popped value's own system bits explicitly.
        if matches!(flags_kind, Some((3, _)))
            && state.system_flags_changed
            && !matches!(state.flags, FlagState::PoppedRflags(_))
        {
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
    let n_dyn = state.aligned_dyn.iter().filter(|d| d.is_some()).count();
    let temp_start = temp_end.checked_sub(8 * (aligned.len() + flag_vals.len() + n_dyn) as i64)?;
    let rsp_delta = (temp_start - 16).div_euclid(16) * 16;
    if rsp_delta < -0x4000_0000 {
        return None;
    }

    let mut pending = caller;
    let mut temp_stores = Vec::with_capacity(aligned.len());
    let mut direct_stores = Vec::new();
    let mut t = temp_start;
    for &(k, o, val, keep) in &aligned {
        if keep == 0 {
            if let Some(c) = arena.as_const(val) {
                direct_stores.push((k, o, DirectVal::Imm(c)));
                continue;
            }
            let held = ArchReg::ALL[..16]
                .iter()
                .copied()
                .find(|&r| !matches!(r, ArchReg::Rax | ArchReg::Rcx | ArchReg::Rsp) && state.regs[r.idx()] == val);
            if let Some(r) = held {
                direct_stores.push((k, o, DirectVal::Reg(r)));
                continue;
            }
        }
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
    let mut base_dyn = Vec::with_capacity(bases.len());
    for d in &state.aligned_dyn {
        base_dyn.push(match *d {
            Some(v) => {
                pending.push((t, v));
                t += 8;
                Some(t - 8)
            }
            None => None,
        });
    }
    let flags = flags_kind.map(|(kind, width)| match kind {
        0 => FlagsReplay::Cmp { a: flag_offs[0], b: flag_offs[1], width },
        1 => FlagsReplay::Test { a: flag_offs[0], width },
        2 => FlagsReplay::Add { a: flag_offs[0], b: flag_offs[1], width },
        _ => FlagsReplay::Popf { a: flag_offs[0] },
    });
    Some(VmExit { rsp_delta, pending, temp_stores, direct_stores, base_dyn, bases, final_base, final_off, flags })
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
            | ExprNode::Ror(a, b)
            | ExprNode::MulHiU(a, b)
            | ExprNode::MulHiS(a, b) => collect_bool_vars(arena, *a, memo, visits)
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
            ExprNode::MulHiU(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                (((va as u128) * (vb as u128)) >> 64) as u64
            }
            ExprNode::MulHiS(a, b) => {
                let va = eval_poly(arena, *a, vars, mask, memo)?;
                let vb = eval_poly(arena, *b, vars, mask, memo)?;
                (((va as i64 as i128) * (vb as i64 as i128)) >> 64) as u64
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
    saved_rflags: Vec<ExprId>,
    cum_rsp_offset: i64,
    inline_depth: usize,
    entry_flags_clobbered: bool,
    mem_ver: u32,
    cr8_ver: u32,
    mem_cache: Vec<(ExprId, (u8, ExprId))>,
    entry_caller_slots: Vec<(i64, ExprId)>,
    aligned_defs: Vec<(StackSpace, i64, u64)>,
    aligned_dyn: Vec<Option<ExprId>>,
    system_flags_changed: bool,
    system_rflags: Option<ExprId>,
    /// Paths that differ in these read the same slot differently later on.
    fresh_aligned: Vec<(u32, i64)>,
    stack_masks_accessed: Vec<ExprId>,
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
        saved_rflags: s.saved_rflags.iter().map(|&(r, _, _, _)| r).collect(),
        cum_rsp_offset: s.cum_rsp_offset,
        inline_depth: s.inline_depth,
        entry_flags_clobbered: s.entry_flags_clobbered,
        mem_ver: s.mem_ver,
        cr8_ver: s.cr8_ver,
        aligned_defs: s.aligned_defs.clone(),
        aligned_dyn: s.aligned_dyn.clone(),
        system_flags_changed: s.system_flags_changed,
        system_rflags: s.system_rflags,
        fresh_aligned: {
            let mut v: Vec<(u32, i64)> = s.stack.fresh_aligned.iter().map(|(&k, &o)| (k, o)).collect();
            v.sort_unstable();
            v
        },
        stack_masks_accessed: {
            let mut v: Vec<ExprId> = s.stack_masks_accessed.iter().copied().collect();
            v.sort_unstable();
            v
        },
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
        FlagState::CarryExpr(e) | FlagState::Rflags(e) | FlagState::PoppedRflags(e) => {
            *e = arena.substitute_memo(*e, from, to, memo);
        }
        FlagState::Entry | FlagState::Unknown => {}
    }
}

fn as_rflags_bit(arena: &ExprArena, id: ExprId) -> Option<(ExprId, u64)> {
    let ExprNode::And(inner, m) = arena.get(id) else {
        return None;
    };
    if arena.as_const(*m) != Some(1) {
        return None;
    }
    if let ExprNode::Shr(rf, sh) = arena.get(*inner) {
        if let Some(n) = arena.as_const(*sh) {
            if n < 64 {
                return Some((*rf, n));
            }
        }
        return None;
    }
    Some((*inner, 0))
}

fn unwrap_masked_rflags_base(arena: &ExprArena, mut id: ExprId) -> ExprId {
    for _ in 0..8 {
        match arena.get(id) {
            ExprNode::And(a, b) | ExprNode::Or(a, b) => {
                if arena.as_const(*b).is_some() {
                    id = *a;
                } else if arena.as_const(*a).is_some() {
                    id = *b;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    id
}

/// Extracts `(target_rflags, known_zero_mask, known_one_mask)` implied by taking or
/// falling through `cond`. `target_rflags == None` means the frame's entry RFLAGS.
fn extract_rflags_bit_constraints(
    arena: &ExprArena,
    cond: ExprId,
    taken: bool,
) -> Option<(Option<ExprId>, u64, u64)> {
    if let Some(cc) = as_direct_entry_flag(arena, cond) {
        let eff_cc = if taken { cc } else { cc ^ 1 };
        let (kz, ko) = match eff_cc {
            0 => (0, 1u64 << 6),                   // e: ZF=1
            1 => (1u64 << 6, 0),                   // ne: ZF=0
            2 => (0, 1u64 << 0),                   // b: CF=1
            3 => (1u64 << 0, 0),                   // ae: CF=0
            5 => ((1u64 << 0) | (1u64 << 6), 0),   // a: CF=0 & ZF=0
            6 => (0, 1u64 << 7),                   // s: SF=1
            7 => (1u64 << 7, 0),                   // ns: SF=0
            11 => (1u64 << 6, 0),                  // g: ZF=0 & SF==OF
            12 => (0, 1u64 << 11),                 // o: OF=1
            13 => (1u64 << 11, 0),                 // no: OF=0
            14 => (0, 1u64 << 2),                  // p: PF=1
            15 => (1u64 << 2, 0),                  // np: PF=0
            _ => return None,
        };
        return Some((None, kz, ko));
    }

    let mut cur = cond;
    let mut truth = taken;
    for _ in 0..4 {
        match arena.get(cur) {
            ExprNode::Xor(x, k) if arena.as_const(*k) == Some(1) => {
                cur = *x;
                truth = !truth;
            }
            ExprNode::Cmp { pred: CondPred::Eq, lhs, rhs } if arena.as_const(*rhs) == Some(0) => {
                cur = *lhs;
                truth = !truth;
            }
            ExprNode::Cmp { pred: CondPred::Ne, lhs, rhs } if arena.as_const(*rhs) == Some(0) => {
                cur = *lhs;
            }
            _ => break,
        }
    }

    if let Some((rf, bit)) = as_rflags_bit(arena, cur) {
        let mask = 1u64 << bit;
        return Some((Some(rf), if truth { 0 } else { mask }, if truth { mask } else { 0 }));
    }

    if !truth {
        if let ExprNode::Or(a, b) = arena.get(cur) {
            match (as_rflags_bit(arena, *a), as_rflags_bit(arena, *b)) {
                (Some((rf1, b1)), Some((rf2, b2))) if rf1 == rf2 => {
                    return Some((Some(rf1), (1u64 << b1) | (1u64 << b2), 0));
                }
                (Some((rf1, b1)), _) => return Some((Some(rf1), 1u64 << b1, 0)),
                (_, Some((rf2, b2))) => return Some((Some(rf2), 1u64 << b2, 0)),
                _ => {}
            }
        }
    }

    None
}

fn specialize_sym_state(arena: &mut ExprArena, state: &mut SymState, cond: ExprId, taken: bool) {
    state.entry_flags_clobbered = true;
    state.saved_rflags.retain(|(_, fl, _, _)| !matches!(fl, FlagState::Entry));
    if let Some((rf_opt, kz, ko)) = extract_rflags_bit_constraints(arena, cond, taken) {
        if (kz | ko) != 0 {
            let entry_rf = arena.entry_rflags();
            let target_base = rf_opt
                .map(|r| unwrap_masked_rflags_base(arena, r))
                .unwrap_or(entry_rf);
            let matches_cur_flags = match &state.flags {
                FlagState::Entry => target_base == entry_rf,
                FlagState::Rflags(rf) | FlagState::PoppedRflags(rf) => {
                    unwrap_masked_rflags_base(arena, *rf) == target_base
                }
                _ => false,
            };
            if matches_cur_flags {
                match &mut state.known_rflags_bits {
                    Some((base, prev_kz, prev_ko)) if *base == target_base => {
                        *prev_kz = (*prev_kz & !ko) | kz;
                        *prev_ko = (*prev_ko & !kz) | ko;
                    }
                    _ => {
                        state.known_rflags_bits = Some((target_base, kz, ko));
                    }
                }
            }
        }
    }
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
        substitute_in_state(arena, state, from, to);
    }
}

/// Replaces `from` by `to` in every value of the state.
fn substitute_in_state(arena: &mut ExprArena, state: &mut SymState, from: ExprId, to: ExprId) {
    {
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
        for (_, fl, _, sys_rf) in &mut state.saved_rflags {
            subst_flag_state(arena, fl, from, to, &mut memo);
            if let Some(sr) = sys_rf {
                *sr = arena.substitute_memo(*sr, from, to, &mut memo);
            }
        }
        if let Some((ref mut base_rf, _, _)) = state.known_rflags_bits {
            *base_rf = arena.substitute_memo(*base_rf, from, to, &mut memo);
        }
        if let Some(ref mut sr) = state.system_rflags {
            *sr = arena.substitute_memo(*sr, from, to, &mut memo);
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

/// A two-way address the lifter resolves without a branch (see the memory-operand
/// handling of `FlowControl::Next`): a read of two plain slots / read-only constants, or
/// a write to two stack slots.
fn select_access_stays_on_stack(arena: &mut ExprArena, view: &PeImageView, ea: ExprId, ins: &Instruction, m: Mnemonic) -> bool {
    let w = ins.memory_size().size() as u8;
    if !(1..=8).contains(&w) {
        return false;
    }
    let Some((_, ea1, ea0)) = try_resolve_select_mem_pair(arena, ea) else {
        return false;
    };
    let mem_writes = ins.op0_kind() == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt);
    let reads_ok = is_pure_nonfaulting_read_addr(arena, view, ea1, w) && is_pure_nonfaulting_read_addr(arena, view, ea0, w);
    if mem_writes {
        // read-modify-write too: both arms must be slots.
        is_internal_stack_addr(arena, ea1).is_some() && is_internal_stack_addr(arena, ea0).is_some()
    } else {
        reads_ok
    }
}

/// A stack slot the symbolic stack models: the VM's own (aligned frames, below the
/// entry RSP) and the caller's frame alike (a caller-frame write also bumps `mem_ver`,
/// see `write_memory_expr`).
#[inline]
fn is_internal_stack_addr(arena: &ExprArena, addr: ExprId) -> Option<(StackSpace, i64)> {
    stack_slot_addr(arena, addr)
}

/// Farthest a stack slot the symbolic stack models lies from its base: frames are
/// far smaller. Beyond it (a garbage pointer, a dead handler's computation) an address
/// relative to the stack is plain memory.
const MAX_STACK_SLOT_OFFSET: i64 = 1 << 20;

/// `as_stack_offset`, for the addresses the symbolic stack models as slots.
fn stack_slot_addr(arena: &ExprArena, addr: ExprId) -> Option<(StackSpace, i64)> {
    arena.as_stack_offset(addr).filter(|&(_, off)| off.abs() < MAX_STACK_SLOT_OFFSET)
}

/// A write there is visible to the caller (and to pointers into its frame).
#[inline]
fn is_caller_frame_slot(sp: StackSpace, off: i64) -> bool {
    sp == StackSpace::CallerStack && off >= 0
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
                aligned_defs: state.aligned_defs.clone(),
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
                            aligned_defs: s2.aligned_defs.clone(),
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
                        aligned_defs: s2.aligned_defs.clone(),
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

/// Computes exact `(width*8 + 1)`-bit rotate-through-carry (`rcl`/`rcr`).
fn eval_rotate_through_carry(
    is_rcl: bool,
    width_bytes: u8,
    lhs: u64,
    count_masked: u64,
    cf_in: bool,
) -> (u64, bool) {
    let bits = (width_bytes as u32) * 8;
    let val_mask = width_mask(width_bytes);
    let masked_lhs = lhs & val_mask;
    let rem = (count_masked as u32) % (bits + 1);
    if rem == 0 {
        return (masked_lhs, cf_in);
    }
    let total_bits = bits + 1;
    let wide_mask = (1u128 << total_bits) - 1;
    let w_val = (masked_lhs as u128) | ((u128::from(cf_in)) << bits);
    let rotated = if is_rcl {
        ((w_val << rem) | (w_val >> (total_bits - rem))) & wide_mask
    } else {
        ((w_val >> rem) | (w_val << (total_bits - rem))) & wide_mask
    };
    let res = (rotated & (val_mask as u128)) as u64;
    let cf_out = ((rotated >> bits) & 1) != 0;
    (res, cf_out)
}

/// Symbolic byte-swap for 32-bit or 64-bit values when constant folding is unavailable.
fn symbolic_bswap(arena: &mut ExprArena, v: ExprId, width: u8) -> ExprId {
    match width {
        4 => {
            let b0 = arena.and_const(v, 0xFF);
            let b1 = arena.and_const(v, 0xFF00);
            let b2s = arena.shr_const(v, 8);
            let b2 = arena.and_const(b2s, 0xFF00);
            let b3s = arena.shr_const(v, 24);
            let b3 = arena.and_const(b3s, 0xFF);
            let p0 = arena.shl_const(b0, 24);
            let p1 = arena.shl_const(b1, 8);
            let lo = arena.or(p0, p1);
            let hi = arena.or(b2, b3);
            arena.or(lo, hi)
        }
        8 => {
            let lo32 = symbolic_bswap(arena, v, 4);
            let hi_raw = arena.shr_const(v, 32);
            let hi32 = symbolic_bswap(arena, hi_raw, 4);
            let lo_up = arena.shl_const(lo32, 32);
            arena.or(lo_up, hi32)
        }
        _ => arena.opaque(),
    }
}

/// Symbolically lifts an entire VM entry CFG (supporting multiple conditional paths).
pub fn lift_vm_entry_cfg(
    view: &PeImageView,
    entry: &DiscoveredEntry,
    cfg: &BinaryDevirtConfig,
) -> LiftedFunction {
    lift_vm_entry_cfg_inner(view, entry, cfg, false)
}

fn lift_vm_entry_cfg_inner(
    view: &PeImageView,
    entry: &DiscoveredEntry,
    cfg: &BinaryDevirtConfig,
    fallback_nonexec_ret_to_vm: bool,
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
    let mut folded_vm_qword_set = HashSet::new();
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
        // The aligned frames of this block's path (`LiftedBlock::aligned_defs`).
        let mut block_aligned = state.aligned_defs.clone();

        let term = loop {
            last_cur_ip = state.ip;
            if view.bitness == 64 && adopt_rsp_alignment(&mut state, &mut arena) {
                block_aligned = state.aligned_defs.clone();
            }
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
                        let out_id = arena.new_effect_id();
                        effects.push(IrEffect::AtomicCmpXchg {
                            lock: true,
                            addr: ea,
                            width: w,
                            expected_rax,
                            desired: arena.zext_mask(src, w),
                            mem_ver_after: state.mem_ver,
                            out_id,
                        });
                        // RAX and the flags as the instruction left them, taken from it
                        // (a separate read of the memory could see another value).
                        let new_rax = if view.bitness == 64 { arena.effect_out(out_id, 1) } else { arena.opaque() };
                        state.write_reg(&mut arena, ArchReg::Rax, RegSlice::Full64, new_rax);
                        if view.bitness == 64 {
                            let rf = arena.effect_out(out_id, 0);
                            state.set_flags(FlagState::Rflags(rf));
                        } else {
                            state.set_flags(FlagState::Unknown);
                        }
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
                        // `inc` / `dec` keep CF: the one before them, not what the
                        // recompiled code happens to have in the flags then.
                        let prev_cf = state.eval_cond_code(&mut arena, ConditionCode::b);
                        let out_id = arena.new_effect_id();
                        effects.push(IrEffect::AtomicRmw {
                            lock: true,
                            op: aop,
                            addr: ea,
                            width: w,
                            src: arena.const_u64(1),
                            mem_ver_after: state.mem_ver,
                            out_id,
                        });
                        state.set_flags(if view.bitness == 64 {
                            let rf = arena.effect_out(out_id, 0);
                            let no_cf = arena.and_const(rf, !1u64);
                            let cf = prev_cf.unwrap_or_else(|| arena.opaque());
                            let cf1 = arena.and_const(cf, 1);
                            FlagState::Rflags(arena.or(no_cf, cf1))
                        } else {
                            FlagState::Unknown
                        });
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
                        let out_id = arena.new_effect_id();
                        effects.push(IrEffect::AtomicRmw {
                            lock: true,
                            op: aop,
                            addr: ea,
                            width: w,
                            src: arena.zext_mask(src, w),
                            mem_ver_after: state.mem_ver,
                            out_id,
                        });
                        state.set_flags(if view.bitness == 64 {
                            FlagState::Rflags(arena.effect_out(out_id, 0))
                        } else {
                            FlagState::Unknown
                        });
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

                    folded_vm_qword_set.extend(state.folded_vm_qword_addrs.drain());
                    let taken_state = state.clone();
                    let fall_state = state.clone();

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
                                aligned_defs: b_state.aligned_defs.clone(),
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
                        if entry.is_call
                            && ret_va == fake_ret_va
                            && imm_pop == 0
                            && check_pure_rsp_delta(&arena, new_rsp) == Some(word_bytes as i64)
                        {
                            let rsp_delta = word_bytes as i64;
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
                            if fallback_nonexec_ret_to_vm && !view.is_executable_va(ret_va) {
                                // Restore pre-ret RSP so jumping back to `cur_ip` (`ret`) executes the
                                // original `ret` with identical machine state.
                                state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, rsp);
                                break exit_to_vm_or_bailout(
                                    cfg,
                                    &state,
                                    &mut arena,
                                    view,
                                    cur_ip,
                                    "exit_target_not_executable".into(),
                                );
                            }
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
                    if imm_pop == 0 {
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
                        if !arena.contains_opaque(ret_val) {
                            if let Some(rsp_delta) = check_pure_rsp_delta(&arena, new_rsp) {
                                let pending = state.collect_pending_caller_stores(rsp_delta);
                                break IrTerm::ExitComputedJmp {
                                    target: ret_val,
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
                    // Still an address in an aligned frame but no fixed slot (the block
                    // budget is spent, or it is no two-way choice): the frame's memory is
                    // only symbolic here, so hand this instruction back to the VM.
                    if has_mem_op && !is_non_access && !matches!(m, Mnemonic::Push | Mnemonic::Pop) {
                        let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                        if arena.as_stack_offset(ea).is_none()
                            && expr_contains_aligned_base(&arena, ea)
                            && !select_access_stays_on_stack(&mut arena, view, ea, &ins, m)
                        {
                            break exit_to_vm_or_bailout(
                                cfg,
                                &state,
                                &mut arena,
                                view,
                                cur_ip,
                                "aligned_frame_symbolic_access".into(),
                            );
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
                Mnemonic::Cmc => {
                    if let Some(cf) = state.cond_value(&mut arena, ConditionCode::b) {
                        let inv = arena.xor_const(cf, 1);
                        let bit = arena.and_const(inv, 1);
                        state.set_flags(FlagState::CarryExpr(bit));
                    } else {
                        state.set_flags(FlagState::Unknown);
                    }
                }
                Mnemonic::Cld => {
                    state.system_flags_changed = true;
                    state.system_rflags = None;
                    if let FlagState::PoppedRflags(v) = state.flags {
                        state.flags = FlagState::PoppedRflags(arena.and_const(v, !0x400u64));
                    }
                }
                Mnemonic::Std => {
                    state.system_flags_changed = true;
                    state.system_rflags = None;
                    if let FlagState::PoppedRflags(v) = state.flags {
                        let df = arena.const_u64(0x400u64);
                        state.flags = FlagState::PoppedRflags(arena.or(v, df));
                    }
                }

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
                        // An operand it does not model (a control or debug register, ...):
                        // nothing is changed yet, so the original runs this instruction.
                        let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                            break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "mov_src".into());
                        };
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, val) {
                            break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "mov_dst".into());
                        }
                    }
                }
                Mnemonic::Movzx => {
                    let src_w = op_width_bytes(&ins, view.bitness, 1);
                    let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "movzx_src".into());
                    };
                    let masked = arena.zext_mask(val, src_w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, masked) {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "movzx_dst".into());
                    }
                }
                Mnemonic::Movsx | Mnemonic::Movsxd => {
                    let src_w = op_width_bytes(&ins, view.bitness, 1);
                    let dst_w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(val) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "movsx_src".into());
                    };
                    let ext = arena.sext(val, src_w * 8);
                    let final_v = arena.zext_mask(ext, dst_w);
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, final_v) {
                        break exit_to_vm_or_bailout(cfg, &state, &mut arena, view, cur_ip, "movsx_dst".into());
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
                Mnemonic::Cwd => {
                    let ax_v = state.read_reg(&mut arena, view.bitness, ArchReg::Rax, RegSlice::Low16);
                    let s = arena.sext(ax_v, 16);
                    let sign = arena.shr_const(s, 16);
                    let mask = arena.zext_mask(sign, 2);
                    state.write_reg(&mut arena, ArchReg::Rdx, RegSlice::Low16, mask);
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
                        (None, RegSlice::Low32) => symbolic_bswap(&mut arena, v, 4),
                        (None, RegSlice::Full64) => symbolic_bswap(&mut arena, v, 8),
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
                Mnemonic::Xadd => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(v0) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("xadd_op0".into());
                    };
                    let Some(v1) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("xadd_op1".into());
                    };
                    let m0 = arena.zext_mask(v0, w);
                    let m1 = arena.zext_mask(v1, w);
                    let sum = arena.add(m0, m1);
                    let res = arena.zext_mask(sum, w);
                    // Intel SDM XADD order: TEMP = DST + SRC; SRC = DST; DST = TEMP.
                    // Writing op1 (SRC) before op0 (DST) preserves self-aliasing `xadd r, r` (`r = 2*r`),
                    // and computing a memory op0's EA beforehand prevents op1 writes from shifting the EA.
                    if ins.op0_kind() == OpKind::Memory {
                        let ea = eval_mem_ea(&state, &mut arena, view.bitness, &ins, next_ip);
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 1, m0) {
                            break IrTerm::Bailout("xadd_write".into());
                        }
                        write_memory_expr(&mut state, &mut arena, &mut effects, ea, w, res);
                    } else if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 1, m0)
                        || !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res)
                    {
                        break IrTerm::Bailout("xadd_write".into());
                    }
                    state.set_flags(FlagState::Add { lhs: m0, rhs: m1, res, width: w });
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
                    // Flags untouched since this frame began (function entry or a native
                    // call's return): the value is the frame's entry RFLAGS, which the
                    // recompiled code saves there (VM enters `pushfq` first thing; as an
                    // unknown value, every exit that writes the VM context was rejected).
                    // `entry_flags_clobbered` is about the hardware flags in later blocks,
                    // not about the value, so it does not matter here.
                    let rfl = if view.bitness == 64 && matches!(state.flags, FlagState::Entry) && !state.system_flags_changed {
                        arena.entry_rflags()
                    } else if let Some(v) = (view.bitness == 64).then(|| composed_rflags(&state, &mut arena)).flatten() {
                        v
                    } else {
                        arena.opaque()
                    };
                    if !matches!(state.flags, FlagState::Unknown)
                        && (!matches!(state.flags, FlagState::Entry) || !state.entry_flags_clobbered)
                    {
                        if state.saved_rflags.len() >= 8 {
                            state.saved_rflags.remove(0);
                        }
                        state.saved_rflags.push((
                            rfl,
                            state.flags.clone(),
                            state.system_flags_changed,
                            state.system_rflags,
                        ));
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
                        .find(|(id, _, _, _)| *id == val)
                        .map(|(_, fl, sys_ch, sys_rf)| (fl.clone(), *sys_ch, *sys_rf));
                    // A value this frame pushed (or its entry RFLAGS) keeps its system bits;
                    // anything else sets `system_rflags` to the popped word if it is a direct
                    // caller-stack slot or canonical constant and the entry is still on its
                    // initial straight-line block (`blocks.len() == 1`).
                    if *arena.get(val) == ExprNode::EntryRflags {
                        state.system_flags_changed = false;
                        state.system_rflags = None;
                    } else if let Some((_, sys_ch, sys_rf)) = restored {
                        state.system_flags_changed = sys_ch;
                        state.system_rflags = sys_rf;
                    } else {
                        state.system_flags_changed = true;
                        let is_clean_sys_base = blocks.len() == 1
                            && match arena.get(val) {
                                ExprNode::Const(c) => (*c & !0x0024_4DD5u64) == 0x202u64,
                                ExprNode::EntryRflags | ExprNode::RegIn(_) => true,
                                ExprNode::Load { addr, .. } => {
                                    arena.as_stack_offset(*addr).is_some_and(|(sp, off)| {
                                        sp == StackSpace::CallerStack && off >= 0
                                    })
                                }
                                _ => false,
                            };
                        if view.bitness == 64 && is_clean_sys_base {
                            state.system_rflags = Some(val);
                        } else {
                            state.system_rflags = None;
                        }
                    }
                    match restored.map(|(fl, _, _)| fl) {
                        _ if *arena.get(val) == ExprNode::EntryRflags => {
                            // The frame's saved entry RFLAGS put back.
                            state.set_flags(FlagState::Entry);
                        }
                        Some(FlagState::Entry) if !state.entry_flags_clobbered => {
                            state.set_flags(FlagState::Entry);
                        }
                        Some(fl) if !matches!(fl, FlagState::Entry) => {
                            state.set_flags(fl);
                        }
                        _ if view.bitness == 64 && !arena.contains_opaque(val) => {
                            state.set_flags(FlagState::PoppedRflags(val));
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
                | Mnemonic::Cmovno
                | Mnemonic::Cmovp
                | Mnemonic::Cmovnp => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let Some(dst_v) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("cmov_dst_read".into());
                    };
                    let Some(src_v) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) else {
                        break IrTerm::Bailout("cmov_src_read".into());
                    };
                    let m_src = arena.zext_mask(src_v, w);
                    let m_dst = arena.zext_mask(dst_v, w);
                    let sel = if let Some(cond) = eval_cond_for_mnemonic_as(&state, &mut arena, m, true) {
                        arena.select(cond, m_src, m_dst)
                    } else if m_src == m_dst {
                        m_dst
                    } else {
                        arena.opaque()
                    };
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
                | Mnemonic::Setno
                | Mnemonic::Setp
                | Mnemonic::Setnp => {
                    let cond = eval_cond_for_mnemonic_as(&state, &mut arena, m, true)
                        .unwrap_or_else(|| arena.opaque());
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
                                // Carry known only as an expression (`cmp` / `add` operands,
                                // the saved entry RFLAGS): lhs + rhs + CF, and the carry out
                                // exactly - not the `Add` flags, whose CF would be wrong
                                // for a carry-in of 1 and r == lhs.
                                let Some(cf_in) = state.cond_value(&mut arena, ConditionCode::b) else {
                                    let res = arena.opaque();
                                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                        break IrTerm::Bailout("adc_write".into());
                                    }
                                    state.set_flags(FlagState::Unknown);
                                    continue;
                                };
                                let zl = arena.zext_mask(lhs, w);
                                let zrh = arena.zext_mask(rhs, w);
                                let s1 = arena.add(zl, zrh);
                                let s2 = arena.add(s1, cf_in);
                                let res = arena.zext_mask(s2, w);
                                if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                    break IrTerm::Bailout("adc_write".into());
                                }
                                // CF' = r < lhs  |  (CF & r == lhs)
                                let lt = arena.cmp(CondPred::Ult, res, zl);
                                let eq = arena.cmp(CondPred::Eq, res, zl);
                                let ceq = arena.and(cf_in, eq);
                                let cf_out = arena.or(lt, ceq);
                                state.set_flags(FlagState::CarryExpr(cf_out));
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
                                if let Some(cf_expr) = state.cond_value(&mut arena, ConditionCode::b) {
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
                                // Borrow known only as an expression: lhs - rhs - CF, and the
                                // borrow out exactly.
                                let Some(cf_in) = state.cond_value(&mut arena, ConditionCode::b) else {
                                    let res = arena.opaque();
                                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                        break IrTerm::Bailout("sbb_write".into());
                                    }
                                    state.set_flags(FlagState::Unknown);
                                    continue;
                                };
                                let zl = arena.zext_mask(lhs, w);
                                let zrh = arena.zext_mask(rhs, w);
                                let d1 = arena.sub(zl, zrh);
                                let d2 = arena.sub(d1, cf_in);
                                let res = arena.zext_mask(d2, w);
                                if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                                    break IrTerm::Bailout("sbb_write".into());
                                }
                                // CF' = lhs < rhs  |  (CF & lhs == rhs)
                                let lt = arena.cmp(CondPred::Ult, zl, zrh);
                                let eq = arena.cmp(CondPred::Eq, zl, zrh);
                                let ceq = arena.and(cf_in, eq);
                                let cf_out = arena.or(lt, ceq);
                                state.set_flags(FlagState::CarryExpr(cf_out));
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
                    // Detect `and rsp, -16` stack frame alignment! (Done on a copy that
                    // becomes RSP later: `adopt_rsp_alignment`.)
                    if ins.op0_kind() == OpKind::Register
                        && ArchReg::from_iced(ins.op0_register()).is_some_and(|(r, _)| r == ArchReg::Rsp)
                        && arena.as_const(rhs).is_some_and(|m_val| {
                            let s = m_val as i64;
                            s < 0 && s >= -256 && s.abs().count_ones() == 1
                        })
                        && arena.as_stack_offset(lhs).is_some()
                    {
                        // Re-aligning an already aligned frame: with `AlignedBase(p)` a
                        // multiple of 2^k >= the new alignment, `(AlignedBase(p) + off) & mask`
                        // is exactly `AlignedBase(p) + (off & mask)` - the same frame, not a
                        // new unknown base whose slots would all read as unknown.
                        if let (Some((StackSpace::AlignedScratch(p), poff)), Some(mask)) =
                            (arena.as_stack_offset(lhs), arena.as_const(rhs))
                        {
                            let parent_mask = state.aligned_defs.get(p as usize).map(|d| d.2 as i64);
                            let parent_fixed = state.aligned_dyn.get(p as usize).copied().flatten().is_none();
                            if parent_fixed && parent_mask.is_some_and(|pm| pm <= mask as i64) {
                                let pb = arena.aligned_base(p);
                                let off = arena.const_u64((poff & mask as i64) as u64);
                                let nb = arena.add(pb, off);
                                state.write_reg(&mut arena, ArchReg::Rsp, RegSlice::Full64, nb);
                                state.set_flags(FlagState::Unknown);
                                continue;
                            }
                        }
                        let aid = state.next_aligned_id;
                        state.next_aligned_id += 1;
                        if let (Some((parent, poff)), Some(mask)) = (arena.as_stack_offset(lhs), arena.as_const(rhs)) {
                            debug_assert_eq!(state.aligned_defs.len(), aid as usize);
                            state.aligned_defs.push((parent, poff, mask));
                            state.aligned_dyn.push(None);
                            block_aligned = state.aligned_defs.clone();
                            if parent == StackSpace::CallerStack {
                                state.stack.note_aligned_frame(aid, poff);
                            }
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
                                let hi = mul_high_half(&mut arena, rax_v, rhs, w, true);
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
                        let hi = mul_high_half(&mut arena, rax_v, rhs, w, false);
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
                            Mnemonic::Rol | Mnemonic::Ror => {
                                let bits_u64 = bits as u64;
                                let ml = arena.zext_mask(lhs, w);
                                let c = arena.and_const(cnt_raw, bits_u64 - 1);
                                if let Some(cv) = arena.as_const(c) {
                                    if cv == 0 {
                                        ml
                                    } else if m == Mnemonic::Rol {
                                        let hi = arena.shl_const(ml, cv);
                                        let lo = arena.shr_const(ml, bits_u64 - cv);
                                        let comb = arena.or(hi, lo);
                                        arena.zext_mask(comb, w)
                                    } else {
                                        let lo = arena.shr_const(ml, cv);
                                        let hi = arena.shl_const(ml, bits_u64 - cv);
                                        let comb = arena.or(lo, hi);
                                        arena.zext_mask(comb, w)
                                    }
                                } else {
                                    let bm1 = arena.const_u64(bits_u64 - 1);
                                    let inv_m1 = arena.sub(bm1, c);
                                    if m == Mnemonic::Rol {
                                        let hi = arena.shl(ml, c);
                                        let ml1 = arena.shr_const(ml, 1);
                                        let lo = arena.shr(ml1, inv_m1);
                                        let comb = arena.or(hi, lo);
                                        arena.zext_mask(comb, w)
                                    } else {
                                        let lo = arena.shr(ml, c);
                                        let ml1 = arena.shl_const(ml, 1);
                                        let hi = arena.shl(ml1, inv_m1);
                                        let comb = arena.or(lo, hi);
                                        arena.zext_mask(comb, w)
                                    }
                                }
                            }
                            _ => arena.opaque(),
                        }
                    };
                    if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                        break IrTerm::Bailout("shift_write".into());
                    }
                    state.set_flags(FlagState::TestBitwise { val: res, width: w });
                }
                Mnemonic::Rcl | Mnemonic::Rcr => {
                    let w = op_width_bytes(&ins, view.bitness, 0);
                    let mask_cnt = if w == 8 { 63u64 } else { 31u64 };
                    let Some(lhs) = read_operand(view, &mut state, &mut arena, &ins, next_ip, 0) else {
                        break IrTerm::Bailout("rc_lhs".into());
                    };
                    let cnt_raw = if ins.op_count() == 1 {
                        arena.const_u64(1)
                    } else {
                        match read_operand(view, &mut state, &mut arena, &ins, next_ip, 1) {
                            Some(c) => c,
                            None => break IrTerm::Bailout("rc_cnt".into()),
                        }
                    };
                    let cnt_masked = arena.and_const(cnt_raw, mask_cnt);
                    if arena.as_const(cnt_masked) == Some(0) {
                        continue;
                    }
                    if let (Some(lv), Some(cv), Some(cf_in)) = (
                        arena.as_const(lhs),
                        arena.as_const(cnt_masked),
                        state.known_cf(&mut arena),
                    ) {
                        let (res_u64, cf_out) =
                            eval_rotate_through_carry(m == Mnemonic::Rcl, w, lv, cv, cf_in);
                        let res = arena.const_u64(res_u64);
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                            break IrTerm::Bailout("rc_write".into());
                        }
                        state.set_flags(FlagState::CarryExpr(arena.const_u64(u64::from(cf_out))));
                    } else if let (Some(cv), Some(cf_in)) = (
                        arena.as_const(cnt_masked),
                        state.cond_value(&mut arena, ConditionCode::b),
                    ) {
                        let bits = (w as u64) * 8;
                        let r = cv % (bits + 1);
                        let ml = arena.zext_mask(lhs, w);
                        let cf1 = arena.and_const(cf_in, 1);
                        let (res, cf_out) = if r == 0 {
                            (ml, cf1)
                        } else if m == Mnemonic::Rcl {
                            let cf_s = arena.shr_const(ml, bits - r);
                            let cf_out = arena.and_const(cf_s, 1);
                            let mut acc = arena.shl_const(cf1, r - 1);
                            if r < bits {
                                let hi = arena.shl_const(ml, r);
                                acc = arena.or(acc, hi);
                            }
                            if r > 1 {
                                let lo = arena.shr_const(ml, bits + 1 - r);
                                acc = arena.or(acc, lo);
                            }
                            (arena.zext_mask(acc, w), cf_out)
                        } else {
                            let cf_s = arena.shr_const(ml, r - 1);
                            let cf_out = arena.and_const(cf_s, 1);
                            let mut acc = arena.shl_const(cf1, bits - r);
                            if r < bits {
                                let lo = arena.shr_const(ml, r);
                                acc = arena.or(acc, lo);
                            }
                            if r > 1 {
                                let hi = arena.shl_const(ml, bits + 1 - r);
                                acc = arena.or(acc, hi);
                            }
                            (arena.zext_mask(acc, w), cf_out)
                        };
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, res) {
                            break IrTerm::Bailout("rc_write".into());
                        }
                        state.set_flags(FlagState::CarryExpr(cf_out));
                    } else {
                        let opq = arena.opaque();
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, opq) {
                            break IrTerm::Bailout("rc_write".into());
                        }
                        state.set_flags(FlagState::Unknown);
                    }
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
                        // Architecturally undefined on 16-bit operands when count > 16; emit opaque so dead
                        // VMProtect junk vanishes while any live use is still rejected by soundness validation.
                        let opq = arena.opaque();
                        if !write_operand(&mut state, &mut arena, &mut effects, view.bitness, &ins, next_ip, 0, opq) {
                            break IrTerm::Bailout("shld_write".into());
                        }
                        state.set_flags(FlagState::Unknown);
                        continue;
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
                            if let Some((space, off)) = stack_slot_addr(&arena, ea) {
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
        folded_vm_qword_set.extend(&state.folded_vm_qword_addrs);
        blocks[block_id] = Some(LiftedBlock {
            id: block_id,
            entry_va,
            effects,
            term,
            aligned_defs: block_aligned,
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
                    aligned_defs: Vec::new(),
                }
            })
        })
        .collect();

    let mut folded_vm_qword_addrs: Vec<u64> = folded_vm_qword_set.into_iter().collect();
    folded_vm_qword_addrs.sort_unstable();

    LiftedFunction {
        entry: entry.clone(),
        is_entry_call: entry.is_call,
        arena,
        blocks: final_blocks,
        raw_vm_insns,
        opaque_branches_folded,
        visited_byte_addrs,
        folded_vm_qword_addrs,
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

/// Every expression a lifted function computes: effects, branch conditions, exit
/// registers and stores.
fn function_root_exprs(func: &LiftedFunction) -> Vec<ExprId> {
    func.blocks.iter().flat_map(block_root_exprs).collect()
}

/// The expressions one block computes (see `function_root_exprs`).
fn block_root_exprs(b: &LiftedBlock) -> Vec<ExprId> {
    let mut roots = Vec::new();
    {
        for e in &b.effects {
            match e {
                IrEffect::Store { addr, value, .. } => roots.extend([*addr, *value]),
                IrEffect::AtomicCmpXchg { addr, expected_rax, desired, .. } => roots.extend([*addr, *expected_rax, *desired]),
                IrEffect::AtomicRmw { addr, src, .. } => roots.extend([*addr, *src]),
                IrEffect::WriteCr8 { val, .. } => roots.push(*val),
                IrEffect::CallNative { .. } => {}
            }
        }
        let (regs, xmms, pending): (Option<&[ExprId; 16]>, Option<&[(ExprId, ExprId); 16]>, &[(i64, ExprId)]) = match &b.term {
            IrTerm::CondBranch { cond, .. } => {
                roots.push(*cond);
                (None, None, &[])
            }
            IrTerm::MidCall { final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitRet { final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitJmp { final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitCall { final_regs, final_xmms, pending_caller_stores, .. }
            | IrTerm::ExitIndirectMem { final_regs, final_xmms, pending_caller_stores, .. } => {
                (Some(final_regs), Some(final_xmms), pending_caller_stores.as_slice())
            }
            IrTerm::ExitComputedJmp { target, final_regs, final_xmms, pending_caller_stores, .. } => {
                roots.push(*target);
                (Some(final_regs), Some(final_xmms), pending_caller_stores.as_slice())
            }
            IrTerm::ExitAddJmp { final_regs, final_xmms, .. } => (Some(final_regs), Some(final_xmms), &[]),
            IrTerm::ExitToVm { exit, final_regs, final_xmms, .. } => {
                (Some(final_regs), Some(final_xmms), exit.pending.as_slice())
            }
            IrTerm::Bailout(_) => (None, None, &[]),
        };
        if let Some(r) = regs {
            roots.extend(r.iter().copied());
        }
        if let Some(x) = xmms {
            for &(lo, hi) in x {
                roots.extend([lo, hi]);
            }
        }
        roots.extend(pending.iter().map(|&(_, v)| v));
    }
    roots
}

fn expr_contains_node(arena: &ExprArena, root: ExprId, want: &ExprNode) -> bool {
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if node == want {
            return true;
        }
        push_expr_children(node, &mut st);
    }
    false
}

/// The function reads the entry RFLAGS somewhere, so its prologue must save them.
fn function_uses_entry_rflags(func: &LiftedFunction) -> bool {
    function_root_exprs(func)
        .into_iter()
        .any(|r| expr_contains_node(&func.arena, r, &ExprNode::EntryRflags))
}

fn validate_function_soundness(func: &LiftedFunction, view: &PeImageView) -> Result<(), String> {
    let bitness = view.bitness;
    if let Some(ref b) = func.first_bailout {
        return Err(b.clone());
    }
    // A frame's entry RFLAGS live at `StackBase - 8` (see `compile_function_into_asm`);
    // an exit whose stores overwrite them reads them first (`emit_block_outputs_and_jump`).
    if function_uses_entry_rflags(func) && bitness != 64 {
        return Err("entry_rflags_32bit".into());
    }

    // The VM's aligned frames (`AlignedBase`) live only as symbolic slots: their
    // memory is written out by `ExitToVm` alone. Their address is fine as a value there
    // and in a branch condition (nothing reads through it before the frame is in
    // memory); a load or store through it, or the address reaching memory, a native
    // call or any other exit, is not.
    for b in &func.blocks {
        let has_ab = |e: ExprId| expr_contains_aligned_base(&func.arena, e);
        for eff in &b.effects {
            if effect_exprs(eff).into_iter().any(has_ab) {
                return Err("aligned_frame_escapes".into());
            }
        }
        let allowed = matches!(b.term, IrTerm::CondBranch { .. } | IrTerm::ExitToVm { .. });
        for r in block_root_exprs(b) {
            if !has_ab(r) {
                continue;
            }
            if !allowed {
                return Err("aligned_frame_escapes".into());
            }
            if expr_loads_through_aligned_base(&func.arena, r) {
                return Err("aligned_frame_load".into());
            }
        }
    }

    // `(mem_ver, all-aliasing)` at the start of the block being checked.
    let block_start: std::cell::Cell<(u32, bool)> = std::cell::Cell::new((0, false));
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
        // Loads against stores: the codegen reads every load before the first store
        // that follows it on the path, in its own block (`CodegenCtx::spills`) or for
        // later blocks into the frame's pinned slots (`plan_pinned_loads`).
        let _ = (stores, all_aliasing, max_ver, &block_start);
        // CR8 reads: read before a later CR8 write, like loads (`emit_block_effects`).
        let _ = max_cr8_ver;
        Ok(())
    };

    let check_xmms = |xmms: &[(ExprId, ExprId); 16],
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
        block_start.set((entry_max_ver[bi], entry_all_aliasing[bi]));
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
            check_xmms(final_xmms, stores, all_aliasing, max_ver, max_cr8_ver)?;
            for &(_, val) in pending {
                check_expr_clean(val, "caller_store", stores, all_aliasing, max_ver, max_cr8_ver)?;
            }
            for r in &ArchReg::ALL[..reg_limit] {
                if *r == ArchReg::Rsp {
                    continue;
                }
                let e = final_regs[r.idx()];
                check_expr_clean(e, r.as_str(), stores, all_aliasing, max_ver, max_cr8_ver)?;
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
            IrTerm::ExitComputedJmp { target, final_regs, final_xmms, pending_caller_stores, .. } => {
                check_expr_clean(*target, "jmp_target", &cur_stores, cur_all_aliasing, cur_max_ver, cur_cr8_ver)?;
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
                // Values reading slots the pending stores overwrite are read before
                // them (`emit_block_outputs_and_jump`).
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
        ExprNode::Load { addr, .. } | ExprNode::Not(addr) | ExprNode::Neg(addr) | ExprNode::SExt { val: addr, .. } | ExprNode::AlignedDyn(_, addr) => {
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
        | ExprNode::MulHiU(a, b)
        | ExprNode::MulHiS(a, b)
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

fn expr_contains_aligned_base(arena: &ExprArena, root: ExprId) -> bool {
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if matches!(node, ExprNode::AlignedBase(_) | ExprNode::AlignedDyn(..)) {
            return true;
        }
        push_expr_children(node, &mut st);
    }
    false
}

/// A load whose address is in an aligned frame.
fn expr_loads_through_aligned_base(arena: &ExprArena, root: ExprId) -> bool {
    let mut seen = HashSet::new();
    let mut st = vec![root];
    while let Some(id) = st.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = arena.get(id);
        if let ExprNode::Load { addr, .. } = node {
            if expr_contains_aligned_base(arena, *addr) {
                return true;
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
    /// Loads already read and pushed, by the `rsp_depth` after their push: a later
    /// store of the block could change what they read (see `emit_block_effects`).
    spills: HashMap<ExprId, i64>,
    /// Loads already read into the frame's pinned slots on this path, by slot depth
    /// (`StackBase - depth`; see `plan_pinned_loads`).
    pinned: HashMap<ExprId, i64>,
    /// `scratch[2]` is saved (or free) and may be clobbered as a spill register.
    spill_free: bool,
    /// The block's aligned frames (`LiftedBlock::aligned_defs`).
    aligned: &'a [(StackSpace, i64, u64)],
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

    /// `AlignedBase(k)` = `(parent + off) & mask` as the VM computed it on the block's
    /// path (`LiftedBlock::aligned_defs`): the same StackBase, so the same address (see
    /// `validate_function_soundness` for where it may appear).
    fn emit_aligned_base(
        &mut self,
        a: &mut CodeAssembler,
        k: u32,
        dyn_off: Option<ExprId>,
        dst: ArchReg,
        spill_reg: ArchReg,
        depth: u8,
    ) -> Result<(), String> {
        if self.bitness != 64 || depth > 8 {
            return Err("unlowerable_aligned_base".into());
        }
        let Some(&(parent, off, mask)) = self.aligned.get(k as usize) else {
            return Err("unlowerable_aligned_base".into());
        };
        // `(parent + off + dyn) & mask`; the run-time part first, kept on the stack.
        if let Some(x) = dyn_off {
            self.eval_expr_into(a, x, dst, spill_reg)?;
            self.emit_push(a, dst)?;
        }
        match parent {
            StackSpace::CallerStack => self.emit_stack_base_addr(a, dst, off, Some(spill_reg))?,
            StackSpace::AlignedScratch(p) => {
                // A frame aligned on a run-time frame is not made (`aligned_frame_def`).
                self.emit_aligned_base(a, p, None, dst, spill_reg, depth + 1)?;
                if off != 0 {
                    self.emit_alu_imm(a, AluOp::Add, dst, off as u64, Some(spill_reg))?;
                }
            }
        }
        if dyn_off.is_some() {
            self.emit_pop(a, spill_reg)?;
            self.emit_alu_reg(a, AluOp::Add, dst, spill_reg)?;
        }
        self.emit_alu_imm(a, AluOp::And, dst, mask, Some(spill_reg))
    }

    /// Evaluated by one load or move that uses no other register (so it can go into
    /// the spill register while the destination holds a value).
    fn is_leaf(&self, id: ExprId) -> bool {
        if self.spills.contains_key(&id) || self.pinned.contains_key(&id) {
            return true;
        }
        match self.arena.get(id) {
            ExprNode::Const(_) | ExprNode::XmmIn(..) => true,
            ExprNode::RegIn(r) => *r != ArchReg::Rsp,
            ExprNode::EntryRflags => self.bitness == 64,
            ExprNode::Load { addr, .. } => {
                matches!(self.arena.as_stack_offset(*addr), Some((StackSpace::CallerStack, off))
                    if i32::try_from(self.rsp_depth + off).is_ok())
            }
            _ => false,
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

    /// `dst = dst op leaf` (`is_leaf`): straight from its stack slot when it is a qword
    /// there, otherwise through `spill_reg`.
    fn emit_alu_leaf(
        &mut self,
        a: &mut CodeAssembler,
        op: AluOp,
        dst: ArchReg,
        leaf: ExprId,
        spill_reg: ArchReg,
    ) -> Result<(), String> {
        if self.bitness == 64 {
            let at = self.spills.get(&leaf).or_else(|| self.pinned.get(&leaf)).map(|&d| self.rsp_depth - d);
            let slot = at.or_else(|| match self.arena.get(leaf) {
                ExprNode::Load { addr, width: 8, .. } => match self.arena.as_stack_offset(*addr) {
                    Some((StackSpace::CallerStack, off)) => Some(self.rsp_depth + off),
                    _ => None,
                },
                _ => None,
            });
            if let Some(rel) = slot.and_then(|r| i32::try_from(r).ok()) {
                let m = qword_ptr(gpr64::rsp + rel);
                let d = to_asm64(dst);
                return match op {
                    AluOp::Add => a.add(d, m),
                    AluOp::Sub => a.sub(d, m),
                    AluOp::And => a.and(d, m),
                    AluOp::Or => a.or(d, m),
                    AluOp::Xor => a.xor(d, m),
                    AluOp::Mul => a.imul_2(d, m),
                }
                .map_err(|e| e.to_string());
            }
        }
        self.eval_expr_into(a, leaf, spill_reg, dst)?;
        self.emit_alu_reg(a, op, dst, spill_reg)
    }

    fn eval_expr_into(
        &mut self,
        a: &mut CodeAssembler,
        expr: ExprId,
        dst: ArchReg,
        spill_reg: ArchReg,
    ) -> Result<(), String> {
        self.eval_steps += 1;
        if self.eval_steps > MAX_EVAL_STEPS {
            return Err("expr_too_complex".into());
        }
        if dst == spill_reg {
            return Err("codegen_dst_eq_spill".into());
        }
        if let Some(&at) = self.spills.get(&expr).or_else(|| self.pinned.get(&expr)) {
            // Read earlier, before a store that could have changed it.
            let rel = self.rsp_depth - at;
            let m = mem_disp(self.bitness, ArchReg::Rsp, rel, self.word_bytes as u8);
            return if self.bitness == 64 {
                a.mov(to_asm64(dst), m)
            } else {
                a.mov(to_asm32(dst), m)
            }
            .map_err(|e| e.to_string());
        }
        match self.arena.get(expr).clone() {
            ExprNode::Const(v) => self.emit_mov_imm(a, dst, v),
            ExprNode::RegIn(r) => self.read_reg_in(a, dst, r),
            ExprNode::StackBase => self.emit_stack_base_addr(a, dst, 0, Some(spill_reg)),
            // Saved by the function prologue at `StackBase - 8` (see `compile_function_into_asm`).
            ExprNode::EntryRflags => {
                if self.bitness != 64 {
                    return Err("entry_rflags_32bit".into());
                }
                let rel = i32::try_from(self.rsp_depth - 8).map_err(|_| "entry_rflags_disp".to_string())?;
                a.mov(to_asm64(dst), qword_ptr(gpr64::rsp + rel)).map_err(|e| e.to_string())
            }
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
                let near = match self.arena.as_stack_offset(addr) {
                    Some((StackSpace::CallerStack, off)) => i32::try_from(self.rsp_depth + off).ok(),
                    _ => None,
                };
                if let Some(rel) = near {
                    let m = mem_disp(self.bitness, ArchReg::Rsp, rel as i64, width);
                    self.emit_load_from_mem(a, dst, m, width)
                } else {
                    // Any other address, a caller-stack one too far for a displacement
                    // included: computed into `dst`, then read.
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
                // An operand read in one instruction without a scratch register goes
                // straight into `spill_reg` after the other one: no push / pop of `dst`
                // (either side for the commutative operations).
                if self.is_leaf(rhs) {
                    self.eval_expr_into(a, lhs, dst, spill_reg)?;
                    return self.emit_alu_leaf(a, op, dst, rhs, spill_reg);
                }
                if op != AluOp::Sub && self.is_leaf(lhs) {
                    self.eval_expr_into(a, rhs, dst, spill_reg)?;
                    return self.emit_alu_leaf(a, op, dst, lhs, spill_reg);
                }
                self.eval_expr_into(a, lhs, dst, spill_reg)?;
                self.emit_push(a, dst)?;
                self.eval_expr_into(a, rhs, spill_reg, dst)?;
                // `dst` is on top of stack; pop into tmp `dst` or wait: we want `dst = lhs`, `rhs` in `spill_reg`!
                // Pop saved `lhs` back into `dst` safely!
                self.emit_pop(a, dst)?;
                self.emit_alu_reg(a, op, dst, spill_reg)
            }
            ExprNode::MulHiU(x, y) | ExprNode::MulHiS(x, y) => {
                // RDX of `mul` / `imul` r/m64. Both operands go on the stack, RAX/RDX are
                // saved around the multiply, the high half replaces the first operand's
                // slot and is popped into `dst` last (so `dst` may be RAX or RDX).
                if self.bitness != 64 {
                    return Err("mulhi_32bit".into());
                }
                let signed = matches!(self.arena.get(expr), ExprNode::MulHiS(..));
                self.eval_expr_into(a, x, dst, spill_reg)?;
                self.emit_push(a, dst)?;
                self.eval_expr_into(a, y, dst, spill_reg)?;
                self.emit_push(a, dst)?;
                let e = |e: iced_x86::IcedError| e.to_string();
                a.push(gpr64::rax).map_err(e)?;
                a.push(gpr64::rdx).map_err(e)?;
                a.mov(gpr64::rax, qword_ptr(gpr64::rsp + 24)).map_err(e)?;
                if signed {
                    a.imul(qword_ptr(gpr64::rsp + 16)).map_err(e)?;
                } else {
                    a.mul(qword_ptr(gpr64::rsp + 16)).map_err(e)?;
                }
                a.mov(qword_ptr(gpr64::rsp + 24), gpr64::rdx).map_err(e)?;
                a.pop(gpr64::rdx).map_err(e)?;
                a.pop(gpr64::rax).map_err(e)?;
                a.lea(gpr64::rsp, ptr(gpr64::rsp) + 8).map_err(e)?;
                self.rsp_depth -= 8;
                self.emit_pop(a, dst)
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
            ExprNode::AlignedBase(k) => self.emit_aligned_base(a, k, None, dst, spill_reg, 0),
            ExprNode::AlignedDyn(k, x) => self.emit_aligned_base(a, k, Some(x), dst, spill_reg, 0),
            // Stored by its effect (`emit_block_effects`) and read from there.
            ExprNode::EffectOut { .. } => Err("effect_out_unavailable".into()),
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
        if self.eval_steps > MAX_EVAL_STEPS {
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
        if self.eval_steps > MAX_EVAL_STEPS {
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
            ExprNode::Load { addr, .. } | ExprNode::Not(addr) | ExprNode::Neg(addr) | ExprNode::SExt { val: addr, .. } | ExprNode::AlignedDyn(_, addr) => {
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
            | ExprNode::MulHiU(a, b)
            | ExprNode::MulHiS(a, b)
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

/// Right after an atomic instruction: its outputs that something reads
/// (`ExprNode::EffectOut`) into their pinned slots - RFLAGS (through `tmp`), and RAX
/// after `cmpxchg` (`with_rax`). Only `mov` / `pushfq` / `pop`: the flags stay.
fn store_effect_outputs(
    a: &mut CodeAssembler,
    ctx: &mut CodegenCtx<'_>,
    frame: &BlockFrame<'_>,
    out_id: u32,
    tmp: ArchReg,
    with_rax: bool,
) -> Result<(), String> {
    let slot = |what: u8| {
        ctx.arena
            .find(&ExprNode::EffectOut { id: out_id, what })
            .and_then(|n| frame.pin_slots.get(&n).map(|&d| (n, d)))
    };
    let rflags = slot(0);
    let rax = if with_rax { slot(1) } else { None };
    if (rflags.is_some() || rax.is_some()) && ctx.bitness != 64 {
        return Err("effect_out_32bit".into());
    }
    if let Some((n, d)) = rax {
        let m = mem_disp(64, ArchReg::Rsp, ctx.rsp_depth - d, 8);
        ctx.emit_store_to_mem(a, m, ArchReg::Rax, 8)?;
        ctx.pinned.insert(n, d);
    }
    if let Some((n, d)) = rflags {
        a.pushfq().map_err(|e| e.to_string())?;
        a.pop(to_asm64(tmp)).map_err(|e| e.to_string())?;
        let m = mem_disp(64, ArchReg::Rsp, ctx.rsp_depth - d, 8);
        ctx.emit_store_to_mem(a, m, tmp, 8)?;
        ctx.pinned.insert(n, d);
    }
    Ok(())
}

/// Expressions an effect evaluates.
fn effect_exprs(e: &IrEffect) -> Vec<ExprId> {
    match e {
        IrEffect::Store { addr, value, .. } => vec![*addr, *value],
        IrEffect::AtomicCmpXchg { addr, expected_rax, desired, .. } => vec![*addr, *expected_rax, *desired],
        IrEffect::AtomicRmw { addr, src, .. } => vec![*addr, *src],
        IrEffect::WriteCr8 { val, .. } => vec![*val],
        IrEffect::CallNative { .. } => Vec::new(),
    }
}

/// Memory version after an effect that writes memory.
fn effect_store_ver(e: &IrEffect) -> Option<u32> {
    match e {
        IrEffect::Store { mem_ver_after, .. }
        | IrEffect::AtomicCmpXchg { mem_ver_after, .. }
        | IrEffect::AtomicRmw { mem_ver_after, .. } => Some(*mem_ver_after),
        IrEffect::WriteCr8 { .. } | IrEffect::CallNative { .. } => None,
    }
}

/// The frame a block runs in (see `compile_function_into_asm`).
struct BlockFrame<'p> {
    /// RSP at the block's start is `StackBase - base_depth`.
    base_depth: i64,
    /// The frame's entry RFLAGS are at `StackBase - 8`.
    rflags_saved: bool,
    /// Pinned slots of the function (`plan_pinned_loads`), by load.
    pin_slots: &'p HashMap<ExprId, i64>,
    /// `mem_ver` after the last memory-writing effect before the block, on its paths.
    start_ver: u32,
    /// `cr8_ver` after the last CR8 write before the block.
    start_cr8_ver: u32,
    /// Loads read by the blocks reachable from this one.
    succ_loads: &'p [ExprId],
    /// Values computed into their slots at the end of this block (`plan_hoisted`).
    hoist_here: &'p [ExprId],
    /// Values a dominating block already put in their slots.
    hoist_active: &'p [ExprId],
    /// The block's aligned frames.
    aligned: &'p [(StackSpace, i64, u64)],
}

impl BlockFrame<'_> {
    /// Pinned loads already read at the block's start: every pinned load read before
    /// the last store on the way here (`plan_pinned_loads`).
    fn active_pinned(&self, arena: &ExprArena) -> HashMap<ExprId, i64> {
        let mut m: HashMap<ExprId, i64> = self
            .pin_slots
            .iter()
            .filter(|&(&l, _)| match arena.get(l) {
                ExprNode::Load { mem_ver, .. } => *mem_ver < self.start_ver,
                ExprNode::Cr8Read(v) => *v < self.start_cr8_ver,
                _ => false,
            })
            .map(|(&l, &d)| (l, d))
            .collect();
        for h in self.hoist_active {
            if let Some(&d) = self.pin_slots.get(h) {
                m.insert(*h, d);
            }
        }
        m
    }
}

/// Where loads that a later block reads live once a store has come between.
struct PinPlan {
    /// Load -> slot depth (`StackBase - depth`), for each load some store of an earlier
    /// block (on a path to a block reading it) comes after.
    slots: HashMap<ExprId, i64>,
    /// Per block: `mem_ver` after the last memory-writing effect before it.
    start_ver: Vec<u32>,
    /// Per block: `cr8_ver` after the last CR8 write before it.
    start_cr8_ver: Vec<u32>,
    /// Per block: every load the blocks reachable from it read.
    succ_loads: Vec<Vec<ExprId>>,
    /// Per block: values to compute into their slots at its end, ascending ids.
    hoist_at: Vec<Vec<ExprId>>,
    /// Per block: values a strict dominator has computed (`hoist_at`).
    hoist_active: Vec<Vec<ExprId>>,
}

/// Upper bound on pinned slots of a function (2 KiB of stack: a kernel thread has
/// 24 KiB in all).
const MAX_PINNED_LOADS: usize = 256;

/// Upper bound on expression nodes the codegen evaluates in one block (shared ones
/// are computed once, `precompute_shared`; this only stops runaway blocks).
const MAX_EVAL_STEPS: usize = 32_768;

/// Every block evaluates its values from the entry state, lazily, so a load an earlier
/// block made reads memory only where it is used - after any store of the blocks in
/// between. Such a load is read right before the first store that follows it on the
/// path (`emit_block_effects`, same place as the in-block spills) into a slot of a
/// per-frame area below the saved RFLAGS (`base0` = bytes above it), which stays
/// allocated for the whole frame.
///
/// A store with `mem_ver_after = w` captures every load the later blocks read with
/// `mem_ver < w`. At a block's start the captured ones are the pinned loads with
/// `mem_ver` below the version after the last store before it (`start_ver`); a block
/// reached with two different such versions is rejected.
fn plan_pinned_loads(func: &LiftedFunction, view: &PeImageView, base0: i64) -> Result<PinPlan, String> {
    let n = func.blocks.len();
    let succs = |b: &LiftedBlock| -> Vec<usize> {
        match &b.term {
            IrTerm::CondBranch { taken_block, fallthrough_block, .. } => vec![*taken_block, *fallthrough_block],
            _ => Vec::new(),
        }
    };
    let own_loads: Vec<HashSet<ExprId>> = func
        .blocks
        .iter()
        .map(|b| {
            let mut out = HashSet::new();
            let mut seen = HashSet::new();
            let mut st = block_root_exprs(b);
            while let Some(id) = st.pop() {
                if !seen.insert(id) {
                    continue;
                }
                let node = func.arena.get(id);
                if matches!(node, ExprNode::Load { .. } | ExprNode::Cr8Read(_)) {
                    out.insert(id);
                }
                push_expr_children(node, &mut st);
            }
            out
        })
        .collect();
    let mut succ_loads: Vec<Vec<ExprId>> = Vec::with_capacity(n);
    for b in &func.blocks {
        let mut reached = HashSet::new();
        let mut st = succs(b);
        let mut loads = HashSet::new();
        while let Some(x) = st.pop() {
            if !reached.insert(x) {
                continue;
            }
            loads.extend(own_loads[x].iter().copied());
            st.extend(succs(&func.blocks[x]));
        }
        let mut v: Vec<ExprId> = loads.into_iter().collect();
        v.sort_unstable();
        succ_loads.push(v);
    }
    let mut pinned: Vec<ExprId> = Vec::new();
    let mut is_pinned = HashSet::new();
    // Only loads some such store may overwrite: the others read the same in any block.
    let store_of = |e: &IrEffect| -> Option<(ExprId, u8)> {
        match e {
            IrEffect::Store { addr, width, .. }
            | IrEffect::AtomicCmpXchg { addr, width, .. }
            | IrEffect::AtomicRmw { addr, width, .. } => Some((*addr, *width)),
            _ => None,
        }
    };
    for (bi, b) in func.blocks.iter().enumerate() {
        for eff in &b.effects {
            if let (Some(w), Some((saddr, sw))) = (effect_store_ver(eff), store_of(eff)) {
                for &l in &succ_loads[bi] {
                    let ExprNode::Load { addr, width, mem_ver } = func.arena.get(l) else { continue };
                    if *mem_ver < w
                        && !is_pinned.contains(&l)
                        && addrs_may_alias(&func.arena, view, *addr, *width, saddr, sw)
                    {
                        is_pinned.insert(l);
                        pinned.push(l);
                    }
                }
            }
        }
    }
    // CR8 reads a later CR8 write of the way could change.
    for (bi, b) in func.blocks.iter().enumerate() {
        for eff in &b.effects {
            if let IrEffect::WriteCr8 { cr8_ver_after, .. } = eff {
                for &l in &succ_loads[bi] {
                    if matches!(func.arena.get(l), ExprNode::Cr8Read(v) if *v < *cr8_ver_after) && is_pinned.insert(l) {
                        pinned.push(l);
                    }
                }
            }
        }
    }
    if pinned.len() > MAX_PINNED_LOADS {
        return Err("pinned_limit".into());
    }
    pinned.sort_unstable();
    let slots: HashMap<ExprId, i64> = pinned
        .iter()
        .enumerate()
        .map(|(i, &l)| (l, base0 + 8 * (i as i64 + 1)))
        .collect();

    // Version after the last store (CR8 write) before each block.
    let start_ver = start_versions(func, effect_store_ver, !slots.is_empty())?;
    let start_cr8_ver = start_versions(
        func,
        |e| match e {
            IrEffect::WriteCr8 { cr8_ver_after, .. } => Some(*cr8_ver_after),
            _ => None,
        },
        !slots.is_empty(),
    )?;
    let mut slots = slots;
    // Atomic effects' outputs something reads (`ExprNode::EffectOut`): a slot each,
    // stored by the effect, read below it (its block's later part and the blocks it
    // dominates, `plan_hoisted`).
    let mut used_outs: HashSet<ExprId> = HashSet::new();
    for b in &func.blocks {
        let mut seen = HashSet::new();
        let mut st = block_root_exprs(b);
        while let Some(id) = st.pop() {
            if !seen.insert(id) {
                continue;
            }
            let node = func.arena.get(id);
            if matches!(node, ExprNode::EffectOut { .. }) {
                used_outs.insert(id);
            }
            push_expr_children(node, &mut st);
        }
    }
    let mut outs_at: Vec<Vec<ExprId>> = vec![Vec::new(); n];
    for (bi, b) in func.blocks.iter().enumerate() {
        for eff in &b.effects {
            let out_id = match eff {
                IrEffect::AtomicCmpXchg { out_id, .. } | IrEffect::AtomicRmw { out_id, .. } => *out_id,
                _ => continue,
            };
            for what in [0u8, 1] {
                if let Some(nd) = func.arena.find(&ExprNode::EffectOut { id: out_id, what }) {
                    if used_outs.contains(&nd) && !slots.contains_key(&nd) {
                        let depth = base0 + 8 * (slots.len() as i64 + 1);
                        slots.insert(nd, depth);
                        outs_at[bi].push(nd);
                    }
                }
            }
        }
    }
    if slots.len() > MAX_PINNED_LOADS {
        return Err("pinned_limit".into());
    }
    let (hoist_at, mut hoist_active) = plan_hoisted(func, base0, &mut slots);
    // Outputs of a strict dominator's effects are in their slots.
    add_dominated(func, &outs_at, &mut hoist_active);
    Ok(PinPlan {
        slots,
        start_ver,
        start_cr8_ver,
        succ_loads,
        hoist_at,
        hoist_active,
    })
}

/// `hoist_active[x]` += `at[d]` for every strict dominator `d` of `x`.
fn add_dominated(func: &LiftedFunction, at: &[Vec<ExprId>], hoist_active: &mut [Vec<ExprId>]) {
    if at.iter().all(|v| v.is_empty()) {
        return;
    }
    let dom = dominator_sets(func);
    for (x, d) in dom.iter().enumerate() {
        for &y in d {
            if y != x {
                hoist_active[x].extend(at[y].iter().copied());
            }
        }
        hoist_active[x].sort_unstable();
        hoist_active[x].dedup();
    }
}

/// Dominator sets over the branch edges (each frame rooted where nothing enters by a
/// branch). Empty sets for a CFG with a cycle.
fn dominator_sets(func: &LiftedFunction) -> Vec<HashSet<usize>> {
    let n = func.blocks.len();
    let succs = |b: &LiftedBlock| -> Vec<usize> {
        match &b.term {
            IrTerm::CondBranch { taken_block, fallthrough_block, .. } => vec![*taken_block, *fallthrough_block],
            _ => Vec::new(),
        }
    };
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (bi, b) in func.blocks.iter().enumerate() {
        for sx in succs(b) {
            preds[sx].push(bi);
        }
    }
    let mut indeg: Vec<usize> = preds.iter().map(|p| p.len()).collect();
    let mut order: Vec<usize> = Vec::with_capacity(n);
    let mut q: VecDeque<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    while let Some(x) = q.pop_front() {
        order.push(x);
        for sx in succs(&func.blocks[x]) {
            indeg[sx] -= 1;
            if indeg[sx] == 0 {
                q.push_back(sx);
            }
        }
    }
    let mut dom: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    if order.len() != n {
        return dom;
    }
    for &x in &order {
        let mut d: Option<HashSet<usize>> = None;
        for &p in &preds[x] {
            d = Some(match d {
                None => dom[p].clone(),
                Some(cur) => cur.intersection(&dom[p]).copied().collect(),
            });
        }
        let mut d = d.unwrap_or_default();
        d.insert(x);
        dom[x] = d;
    }
    dom
}

/// Values worth computing once for several blocks: every block evaluates from the entry
/// state, so a VM-context value that many exits store is otherwise rebuilt in each of
/// them. A subexpression used by two or more blocks is computed at the end of their
/// nearest common dominator (a branch block, same frame) into a slot of the pinned
/// area (`slots`, after the loads) and read from there below it.
///
/// Only values that read no memory and nothing a native call changes: they are computed
/// on every path through that block, also on those that would not need them. No
/// aligned-frame addresses either: blocks further down may give an id another frame.
/// Per block: the version `write` gives after the last such effect on the way to it
/// (0 at a frame's start); `strict`: different versions on two ways are an error.
fn start_versions(func: &LiftedFunction, write: impl Fn(&IrEffect) -> Option<u32>, strict: bool) -> Result<Vec<u32>, String> {
    let n = func.blocks.len();
    let succs = |b: &LiftedBlock| -> Vec<usize> {
        match &b.term {
            IrTerm::CondBranch { taken_block, fallthrough_block, .. } => vec![*taken_block, *fallthrough_block],
            _ => Vec::new(),
        }
    };
    let mut start: Vec<Option<u32>> = vec![None; n];
    if n > 0 {
        start[0] = Some(0);
    }
    for b in &func.blocks {
        if let IrTerm::MidCall { cont_block, .. } = &b.term {
            // A new frame: nothing of the old one is read there.
            start[*cont_block] = Some(0);
        }
    }
    let mut work: VecDeque<usize> = (0..n).filter(|&i| start[i].is_some()).collect();
    while let Some(bi) = work.pop_front() {
        let Some(mut v) = start[bi] else { continue };
        for eff in &func.blocks[bi].effects {
            if let Some(w) = write(eff) {
                v = w;
            }
        }
        for sx in succs(&func.blocks[bi]) {
            match start[sx] {
                None => {
                    start[sx] = Some(v);
                    work.push_back(sx);
                }
                Some(old) if old != v && strict => return Err("pinned_ver_merge".into()),
                Some(_) => {}
            }
        }
    }
    Ok(start.into_iter().map(|v| v.unwrap_or(0)).collect())
}

fn plan_hoisted(func: &LiftedFunction, base0: i64, slots: &mut HashMap<ExprId, i64>) -> (Vec<Vec<ExprId>>, Vec<Vec<ExprId>>) {
    const MIN_COST: u32 = 4;
    let n = func.blocks.len();
    let empty = || (vec![Vec::new(); n], vec![Vec::new(); n]);
    let budget = MAX_PINNED_LOADS.saturating_sub(slots.len());
    if n < 2 || budget == 0 {
        return empty();
    }
    let arena = &func.arena;
    let dom = dominator_sets(func);
    if dom.iter().all(|d| d.is_empty()) {
        return empty(); // a cycle
    }
    fn pure(arena: &ExprArena, id: ExprId, memo: &mut HashMap<ExprId, bool>) -> bool {
        if let Some(&v) = memo.get(&id) {
            return v;
        }
        let node = arena.get(id);
        let mut ok = !matches!(
            node,
            ExprNode::Load { .. }
                | ExprNode::CallRet { .. }
                | ExprNode::Cr8Read(_)
                | ExprNode::EntryFlag(_)
                | ExprNode::Opaque(_)
                | ExprNode::AlignedBase(_)
                | ExprNode::AlignedDyn(..)
        );
        if ok {
            let mut ch = Vec::new();
            push_expr_children(node, &mut ch);
            ok = ch.into_iter().all(|c| pure(arena, c, memo));
        }
        memo.insert(id, ok);
        ok
    }
    let mut pure_memo: HashMap<ExprId, bool> = HashMap::new();
    // Which blocks use each node.
    let mut users: HashMap<ExprId, Vec<usize>> = HashMap::new();
    for (bi, b) in func.blocks.iter().enumerate() {
        let mut seen = HashSet::new();
        let mut st = block_root_exprs(b);
        while let Some(id) = st.pop() {
            if !seen.insert(id) {
                continue;
            }
            users.entry(id).or_default().push(bi);
            push_expr_children(arena.get(id), &mut st);
        }
    }
    // Tree cost (children are interned before their parents: ascending ids).
    let mut ids: Vec<ExprId> = users.keys().copied().collect();
    ids.sort_unstable();
    let mut cost: HashMap<ExprId, u32> = HashMap::new();
    for &id in &ids {
        let mut ch = Vec::new();
        push_expr_children(arena.get(id), &mut ch);
        let c = ch.iter().fold(1u32, |acc, x| acc.saturating_add(cost.get(x).copied().unwrap_or(1)));
        cost.insert(id, c);
    }
    // (benefit, node, block): the nearest common dominator must be a branch block.
    let mut cands: Vec<(u64, ExprId, usize)> = Vec::new();
    for &id in &ids {
        let us = &users[&id];
        let c = cost[&id];
        if us.len() < 2 || c < MIN_COST || arena.as_stack_offset(id).is_some() || !pure(arena, id, &mut pure_memo) {
            continue;
        }
        let mut common: HashSet<usize> = dom[us[0]].clone();
        for &u in &us[1..] {
            common = common.intersection(&dom[u]).copied().collect();
        }
        let Some(&at) = common.iter().max_by_key(|&&x| dom[x].len()) else { continue };
        let IrTerm::CondBranch { cond, .. } = &func.blocks[at].term else { continue };
        // Block 0 branching on the hardware entry flags directly computes nothing
        // (`compile_function_into_asm`): no room for values there.
        if at == 0 && func.blocks[0].effects.is_empty() && as_direct_entry_flag(arena, *cond).is_some() {
            continue;
        }
        cands.push(((c as u64) * (us.len() as u64 - 1), id, at));
    }
    cands.sort_unstable_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    cands.truncate(budget);
    let mut hoist_at: Vec<Vec<ExprId>> = vec![Vec::new(); n];
    let mut next = slots.len() as i64;
    for &(_, id, at) in &cands {
        next += 1;
        slots.insert(id, base0 + 8 * next);
        hoist_at[at].push(id);
    }
    for v in &mut hoist_at {
        v.sort_unstable();
    }
    let mut hoist_active: Vec<Vec<ExprId>> = vec![Vec::new(); n];
    for x in 0..n {
        for &d in &dom[x] {
            if d != x {
                hoist_active[x].extend(hoist_at[d].iter().copied());
            }
        }
        hoist_active[x].sort_unstable();
    }
    (hoist_at, hoist_active)
}

/// Subexpressions `roots` use more than once (each use re-evaluates them: the
/// codegen walks the expression DAG as a tree), worth computing once and pushing
/// (`precompute_shared`). Ascending ids: children are interned before their parents,
/// so each one only uses ones before it.
///
/// Only what is evaluated anyway: a `Select` arm runs only when chosen, so a node
/// reached through arms alone is taken only when it reads no memory (a load there may
/// be guarded by the condition).
fn shared_subexprs(ctx: &CodegenCtx<'_>, roots: &[ExprId]) -> Vec<(ExprId, u64)> {
    shared_subexprs_in(ctx.arena, roots, |id| ctx.spills.contains_key(&id) || ctx.pinned.contains_key(&id))
}

/// `shared_subexprs`, with `done` the values already on the stack.
fn shared_subexprs_in(arena: &ExprArena, roots: &[ExprId], done: impl Fn(ExprId) -> bool) -> Vec<(ExprId, u64)> {
    let children = |id: ExprId, out: &mut Vec<ExprId>| push_expr_children(arena.get(id), out);
    // References (over every path, arms included) and unconditional reach.
    let mut refs: HashMap<ExprId, u32> = HashMap::new();
    let mut uncond: HashSet<ExprId> = HashSet::new();
    let mut st: Vec<(ExprId, bool)> = roots.iter().map(|&r| (r, true)).collect();
    while let Some((id, u)) = st.pop() {
        let c = refs.entry(id).or_insert(0);
        *c += 1;
        let first = *c == 1;
        let newly_uncond = u && uncond.insert(id);
        if done(id) || !(first || newly_uncond) {
            continue;
        }
        if let ExprNode::Select { cond, if_true, if_false } = arena.get(id) {
            if first {
                st.push((*cond, u));
            } else if !uncond.contains(cond) {
                st.push((*cond, true));
                if let Some(c) = refs.get_mut(cond) {
                    *c -= 1; // same edge, only spreading `uncond`
                }
            }
            if first {
                st.push((*if_true, false));
                st.push((*if_false, false));
            }
            continue;
        }
        let mut ch = Vec::new();
        children(id, &mut ch);
        for x in ch {
            // Revisiting only to spread `uncond`: count each edge once.
            if first {
                st.push((x, u));
            } else if !uncond.contains(&x) {
                st.push((x, true));
                if let Some(c) = refs.get_mut(&x) {
                    *c -= 1; // the push above counts again
                }
            }
        }
    }
    let mut ids: Vec<ExprId> = refs.keys().copied().collect();
    ids.sort_unstable();
    let mut cost: HashMap<ExprId, u32> = HashMap::new();
    let mut reads_mem: HashMap<ExprId, bool> = HashMap::new();
    let mut chosen: Vec<(ExprId, u64)> = Vec::new();
    let mut chosen_set: HashSet<ExprId> = HashSet::new();
    for id in ids {
        if done(id) {
            cost.insert(id, 1);
            reads_mem.insert(id, false);
            continue;
        }
        let node = arena.get(id);
        let mut ch = Vec::new();
        children(id, &mut ch);
        let mut c: u32 = 1;
        let mut m = matches!(node, ExprNode::Load { .. });
        for x in &ch {
            c = c.saturating_add(if chosen_set.contains(x) { 1 } else { cost.get(x).copied().unwrap_or(1) });
            m |= reads_mem.get(x).copied().unwrap_or(true);
        }
        cost.insert(id, c);
        reads_mem.insert(id, m);
        let trivial = matches!(
            node,
            ExprNode::Const(_) | ExprNode::RegIn(_) | ExprNode::StackBase | ExprNode::XmmIn(..) | ExprNode::EntryRflags
        ) || arena.as_stack_offset(id).is_some();
        let r = refs.get(&id).copied().unwrap_or(0);
        if r >= 2 && c >= 3 && !trivial && (uncond.contains(&id) || !m) {
            // Evaluations saved: its cost for every use after the first.
            chosen.push((id, c as u64 * (r as u64 - 1)));
            chosen_set.insert(id);
        }
    }
    chosen
}

/// Computes `shared_subexprs(roots)` once each and pushes them (`CodegenCtx::spills`),
/// as far as the spill budget goes. Only where every load the roots read is already
/// safe to read: its block's earlier stores have captured the older ones.
fn precompute_shared(a: &mut CodeAssembler, ctx: &mut CodegenCtx<'_>, roots: &[ExprId]) -> Result<(), String> {
    let [w0, _, w2] = ctx.scratch;
    // The block's spill budget (a kernel thread has 24 KiB of stack), less a reserve
    // for the loads later stores make it read early (`emit_block_effects`): the
    // subexpressions that save the most evaluation get it.
    let room = MAX_BLOCK_SPILLS.saturating_sub(SPILL_RESERVE_FOR_LOADS).saturating_sub(ctx.spills.len());
    let mut picked: Vec<(ExprId, u64)> = shared_subexprs(ctx, roots)
        .into_iter()
        .filter(|&(id, _)| ctx.spill_free || !expr_uses_spill(ctx.arena, ctx.bitness, id))
        .collect();
    if picked.len() > room {
        picked.sort_unstable_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
        picked.truncate(room);
        picked.sort_unstable_by_key(|&(id, _)| id);
    }
    for (id, _) in picked {
        ctx.eval_expr_into(a, id, w0, w2)?;
        ctx.emit_push(a, w0)?;
        ctx.spills.insert(id, ctx.rsp_depth);
    }
    Ok(())
}

/// Upper bound on loads pushed in one block (each is a qword of stack).
const MAX_BLOCK_SPILLS: usize = 256;

/// Spill slots `precompute_shared` leaves to loads read early.
const SPILL_RESERVE_FOR_LOADS: usize = 64;

/// `effects` in order. `later` are the expressions the block evaluates after them
/// (exit registers and stores, the branch condition).
///
/// Before each effect that writes memory, every load that is still to be used - by a
/// later effect or by `later` - and that read memory before this write
/// (`mem_ver < mem_ver_after`) is evaluated now and pushed (`CodegenCtx::spills`):
/// the codegen evaluates expressions lazily, after the writes, and the write could
/// change what the load saw. No alias analysis here: every such load is kept, which
/// is always correct. Spills stay on the stack until the block's end.
fn emit_block_effects(
    a: &mut CodeAssembler,
    ctx: &mut CodegenCtx<'_>,
    frame: &BlockFrame<'_>,
    effects: &[IrEffect],
    later: &[ExprId],
) -> Result<(), String> {
    let [w0, w1, w2] = ctx.scratch;
    for (i, eff) in effects.iter().enumerate() {
        // A memory write makes older loads stale, a CR8 write older CR8 reads.
        let writes = match eff {
            IrEffect::WriteCr8 { cr8_ver_after, .. } => Some((true, *cr8_ver_after)),
            _ => effect_store_ver(eff).map(|v| (false, v)),
        };
        if let Some((cr8, ver)) = writes {
            let stale = |node: &ExprNode| match (cr8, node) {
                (false, ExprNode::Load { mem_ver, .. }) => *mem_ver < ver,
                (true, ExprNode::Cr8Read(v)) => *v < ver,
                _ => false,
            };
            let mut roots: Vec<ExprId> = effects[i + 1..].iter().flat_map(effect_exprs).collect();
            roots.extend_from_slice(later);
            let mut loads: Vec<ExprId> = Vec::new();
            // Reads of the blocks this one can reach that this write may change.
            for &l in frame.succ_loads {
                if frame.pin_slots.contains_key(&l) && !ctx.pinned.contains_key(&l) && !ctx.spills.contains_key(&l) {
                    if stale(ctx.arena.get(l)) {
                        loads.push(l);
                    }
                }
            }
            let mut seen = HashSet::new();
            while let Some(id) = roots.pop() {
                if !seen.insert(id) || ctx.spills.contains_key(&id) || ctx.pinned.contains_key(&id) {
                    continue;
                }
                let node = ctx.arena.get(id);
                if stale(node) {
                    loads.push(id);
                    continue; // its address is evaluated with it
                }
                push_expr_children(node, &mut roots);
            }
            loads.sort_unstable();
            loads.dedup();
            for l in loads {
                if let Some(&depth) = frame.pin_slots.get(&l) {
                    // Read again by a later block: into its pinned slot.
                    ctx.eval_expr_into(a, l, w0, w2)?;
                    let m = mem_disp(ctx.bitness, ArchReg::Rsp, ctx.rsp_depth - depth, ctx.word_bytes as u8);
                    ctx.emit_store_to_mem(a, m, w0, ctx.word_bytes as u8)?;
                    ctx.pinned.insert(l, depth);
                    continue;
                }
                if ctx.spills.len() >= MAX_BLOCK_SPILLS {
                    return Err("spill_limit".into());
                }
                ctx.eval_expr_into(a, l, w0, w2)?;
                ctx.emit_push(a, w0)?;
                ctx.spills.insert(l, ctx.rsp_depth);
            }
        }
        precompute_shared(a, ctx, &effect_exprs(eff))?;
        match eff {
            IrEffect::Store { addr, width, value, .. } => {
                ctx.eval_expr_into(a, *value, w0, w2)?;
                let near = match ctx.arena.as_stack_offset(*addr) {
                    Some((StackSpace::CallerStack, off)) => i32::try_from(ctx.rsp_depth + off).ok(),
                    _ => None,
                };
                if let Some(rel) = near {
                    let m = mem_disp(ctx.bitness, ArchReg::Rsp, rel as i64, *width);
                    ctx.emit_store_to_mem(a, m, w0, *width)?;
                } else {
                    ctx.emit_push(a, w0)?;
                    ctx.eval_expr_into(a, *addr, w1, w2)?;
                    ctx.emit_pop(a, w0)?;
                    let m = mem_disp(ctx.bitness, w1, 0, *width);
                    ctx.emit_store_to_mem(a, m, w0, *width)?;
                }
            }
            IrEffect::AtomicCmpXchg { lock, addr, width, expected_rax, desired, out_id, .. } => {
                // `RAX` must hold `expected_rax` for `cmpxchg [w1], w0`
                let need_save_rax = w0 == ArchReg::Rax || w1 == ArchReg::Rax || w2 == ArchReg::Rax;
                if need_save_rax {
                    return Err("cmpxchg_scratch_conflict".into());
                }
                // RAX keeps its value for the rest of the block (it is an input).
                if ctx.bitness == 64 {
                    a.push(gpr64::rax).map_err(|e| e.to_string())?;
                } else {
                    a.push(gpr32::eax).map_err(|e| e.to_string())?;
                }
                ctx.rsp_depth += ctx.word_bytes;
                ctx.eval_expr_into(a, *addr, w1, w2)?;
                ctx.emit_push(a, w1)?;
                ctx.eval_expr_into(a, *desired, w0, w2)?;
                ctx.emit_push(a, w0)?;
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
                store_effect_outputs(a, ctx, frame, *out_id, w1, true)?;
                if ctx.bitness == 64 {
                    a.pop(gpr64::rax).map_err(|e| e.to_string())?;
                } else {
                    a.pop(gpr32::eax).map_err(|e| e.to_string())?;
                }
                ctx.rsp_depth -= ctx.word_bytes;
            }
            IrEffect::AtomicRmw { lock, op, addr, width, src, out_id, .. } => {
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
                store_effect_outputs(a, ctx, frame, *out_id, w1, false)?;
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
            // A caller-stack slot within a displacement is read straight off RSP.
            if matches!(arena.as_stack_offset(*addr), Some((StackSpace::CallerStack, off)) if off.abs() < 1 << 30) {
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
        // The run-time part, computed with the other values (`VmExit::base_dyn`).
        if let Some(t) = exit.base_dyn.get(k).copied().flatten() {
            a.add(rax, qword_ptr(rsp + d32(depth + t - exit.rsp_delta)?)).map_err(err)?;
        }
        let m32 = i32::try_from(mask as i64).map_err(|_| "vm_exit_mask".to_string())?;
        a.and(rax, m32).map_err(err)?;
        a.push(rax).map_err(err)?;
    }
    let depth = 16 + 8 * nb;
    let base_at = |k: u32| 8 * (nb - 1 - k as i64);
    let temp = |t: i64| d32(depth + t - exit.rsp_delta);
    // Copy the temporary values into the aligned slots (RAX = the slot's base, loaded
    // when it changes), then the direct ones.
    let mut in_rax: Option<u32> = None;
    let load_base = |a: &mut CodeAssembler, k: u32, in_rax: &mut Option<u32>| -> Result<(), String> {
        if *in_rax != Some(k) {
            a.mov(rax, qword_ptr(rsp + d32(base_at(k))?)).map_err(err)?;
            *in_rax = Some(k);
        }
        Ok(())
    };
    for &(k, o, v) in &exit.direct_stores {
        load_base(a, k, &mut in_rax)?;
        match v {
            DirectVal::Imm(c) => {
                if let Ok(i) = i32::try_from(c as i64) {
                    a.mov(qword_ptr(rax + d32(o)?), i).map_err(err)?;
                } else {
                    a.mov(rcx, c).map_err(err)?;
                    a.mov(qword_ptr(rax + d32(o)?), rcx).map_err(err)?;
                }
            }
            DirectVal::Reg(r) => a.mov(qword_ptr(rax + d32(o)?), to_asm64(r)).map_err(err)?,
        }
    }
    for &(t, k, o, keep) in &exit.temp_stores {
        load_base(a, k, &mut in_rax)?;
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
    if let Some(FlagsReplay::Popf { a: t }) = exit.flags {
        a.push(qword_ptr(rsp + temp(t)?)).map_err(err)?;
        a.popfq().map_err(err)?;
    } else if let Some(f) = exit.flags {
        let (a_off, b_off, width) = match f {
            FlagsReplay::Cmp { a, b, width } | FlagsReplay::Add { a, b, width } => (a, Some(b), width),
            FlagsReplay::Test { a, width } => (a, None, width),
            FlagsReplay::Popf { .. } => unreachable!("handled above"),
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
            (FlagsReplay::Popf { .. }, _) => unreachable!("handled above"),
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
    frame: &BlockFrame<'_>,
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
    let base_depth = frame.base_depth;

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
    // Shared subexpressions are computed into `scratch[0]` with `scratch[2]` spare.
    let has_shared = {
        let mut roots: Vec<ExprId> = pending_caller_stores.iter().map(|&(_, v)| v).collect();
        roots.extend(modified.iter().map(|&(_, e)| e));
        for &(_, (lo, hi)) in &modified_xmms {
            roots.extend([lo, hi]);
        }
        roots.extend(effects.iter().flat_map(effect_exprs));
        let active = frame.active_pinned(arena);
        !shared_subexprs_in(arena, &roots, |id| active.contains_key(&id)).is_empty()
    };
    let need_w0 = need_w0 || has_shared;
    let need_w2 = need_w2 || has_shared;
    let need_scratch = [need_w0, need_w1, need_w2];

    let mut ctx = CodegenCtx {
        bitness,
        word_bytes,
        arena,
        rsp_depth: base_depth,
        saved_regs: HashMap::new(),
        scratch,
        eval_steps: 0,
        spills: HashMap::new(),
        pinned: frame.active_pinned(arena),
        spill_free: need_w2,
        aligned: frame.aligned,
    };

    let final_hw_rsp_delta = if pre_ret_pop {
        rsp_delta_target - word_bytes
    } else {
        rsp_delta_target
    };
    // Only ever lower RSP here: the frame's saved RFLAGS and pinned slots stay above
    // it while values are computed. It reaches its final value at the very end.
    if final_hw_rsp_delta < -base_depth {
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

    // Memory effects first, in program order: loads that a later write could change
    // are read before it (see `emit_block_effects`). Then the caller-frame slots, which
    // hold the final values (an effect writing the same slot comes before them).
    let mut later: Vec<ExprId> = pending_caller_stores.iter().map(|&(_, v)| v).collect();
    later.extend(modified.iter().map(|&(_, e)| e));
    for &(_, (lo, hi)) in &modified_xmms {
        later.extend([lo, hi]);
    }
    emit_block_effects(a, &mut ctx, frame, effects, &later)?;

    // A caller-frame store over a pinned slot would change it before the values that
    // read it are computed: move those to the pushed spills (below RSP's final value
    // and every store) first.
    let mut overwritten: Vec<(ExprId, i64)> = ctx
        .pinned
        .iter()
        .filter(|&(_, &d)| {
            pending_caller_stores
                .iter()
                .any(|&(off, _)| off < -d + ctx.word_bytes && -d < off + word_bytes)
        })
        .map(|(&l, &d)| (l, d))
        .collect();
    overwritten.sort_unstable();
    for (l, _) in overwritten {
        let [w0, _, w2] = ctx.scratch;
        ctx.eval_expr_into(a, l, w0, w2)?;
        ctx.emit_push(a, w0)?;
        ctx.pinned.remove(&l);
        ctx.spills.insert(l, ctx.rsp_depth);
    }
    // The frame's saved entry RFLAGS (`StackBase - 8`) under a pending store: read
    // them now for every value still to be computed.
    if frame.rflags_saved && pending_caller_stores.iter().any(|&(o, _)| o > -16 - word_bytes && o < 0) {
        let mut st: Vec<ExprId> = later.clone();
        let mut seen = HashSet::new();
        let mut found = None;
        while let Some(id) = st.pop() {
            if !seen.insert(id) || ctx.spills.contains_key(&id) || ctx.pinned.contains_key(&id) {
                continue;
            }
            let node = ctx.arena.get(id);
            if *node == ExprNode::EntryRflags {
                found = Some(id);
                break;
            }
            push_expr_children(node, &mut st);
        }
        if let Some(id) = found {
            let [w0, _, w2] = ctx.scratch;
            ctx.eval_expr_into(a, id, w0, w2)?;
            ctx.emit_push(a, w0)?;
            ctx.spills.insert(id, ctx.rsp_depth);
        }
    }

    // Caller-frame slots the pending stores below overwrite: every value still to be
    // computed (other stores, registers, XMMs) that reads one reads it now, before
    // the first of them. All effects are done, so these reads see what they should.
    if !pending_caller_stores.is_empty() {
        let overlaps = |loff: i64, w: u8| {
            pending_caller_stores
                .iter()
                .any(|&(off, _)| loff < off + word_bytes && off < loff + w as i64)
        };
        let mut st: Vec<ExprId> = later.clone();
        let mut seen = HashSet::new();
        let mut loads: Vec<ExprId> = Vec::new();
        while let Some(id) = st.pop() {
            if !seen.insert(id) || ctx.spills.contains_key(&id) || ctx.pinned.contains_key(&id) {
                continue;
            }
            let node = ctx.arena.get(id);
            if let ExprNode::Load { addr, width, .. } = node {
                if let Some((StackSpace::CallerStack, loff)) = ctx.arena.as_stack_offset(*addr) {
                    if overlaps(loff, *width) {
                        loads.push(id);
                        continue;
                    }
                }
            }
            push_expr_children(node, &mut st);
        }
        loads.sort_unstable();
        let [w0, _, w2] = ctx.scratch;
        for l in loads {
            if ctx.spills.len() >= MAX_BLOCK_SPILLS {
                return Err("spill_limit".into());
            }
            ctx.eval_expr_into(a, l, w0, w2)?;
            ctx.emit_push(a, w0)?;
            ctx.spills.insert(l, ctx.rsp_depth);
        }
    }

    // Shared subexpressions of the outputs, once each (all stores are done).
    if need_w0 {
        precompute_shared(a, &mut ctx, &later)?;
    }

    // Emit caller-frame stack stores (`off >= rsp_delta_target`). With the entry
    // RFLAGS saved at `StackBase - 8`, the stores over `[-16, 0)` go last, after every
    // other value (that may read the saved RFLAGS) has been computed.
    let over_saved = |off: i64| frame.rflags_saved && off > -16 - word_bytes && off < 0;
    let ordered: Vec<(i64, ExprId)> = pending_caller_stores
        .iter()
        .copied()
        .filter(|&(o, _)| !over_saved(o))
        .chain(pending_caller_stores.iter().copied().filter(|&(o, _)| over_saved(o)))
        .collect();
    for &(off, val) in &ordered {
        let [w0, _, w2] = ctx.scratch;
        let rel = i64::from(i32::try_from(ctx.rsp_depth + off).map_err(|_| "caller_slot_disp".to_string())?);
        let m = mem_disp(ctx.bitness, ArchReg::Rsp, rel, word_bytes as u8);
        if ctx.bitness == 64 && !ctx.spills.contains_key(&val) && !ctx.pinned.contains_key(&val) {
            // A constant, or an input register that still holds it: one store.
            match ctx.arena.get(val) {
                ExprNode::Const(c) if i32::try_from(*c as i64).is_ok() => {
                    a.mov(m, *c as i64 as i32).map_err(|e| e.to_string())?;
                    continue;
                }
                ExprNode::RegIn(r)
                    if *r != ArchReg::Rsp && !ctx.saved_regs.contains_key(r) && !ctx.scratch.contains(r) =>
                {
                    ctx.emit_store_to_mem(a, m, *r, 8)?;
                    continue;
                }
                _ => {}
            }
        }
        ctx.eval_expr_into(a, val, w0, w2)?;
        ctx.emit_store_to_mem(a, m, w0, word_bytes as u8)?;
    }

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

    // Drop the spilled loads (flag-preserving `lea rsp`); they sit above the entry pushes.
    if !ctx.spills.is_empty() {
        let bytes = ctx.spills.len() as i64 * ctx.word_bytes;
        let d = i32::try_from(bytes).map_err(|_| "spill_disp".to_string())?;
        if ctx.bitness == 64 {
            a.lea(gpr64::rsp, ptr(gpr64::rsp) + d).map_err(|e| e.to_string())?;
        } else {
            a.lea(gpr32::esp, ptr(gpr32::esp) + d).map_err(|e| e.to_string())?;
        }
        ctx.rsp_depth -= bytes;
        ctx.spills.clear();
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
    view: &PeImageView,
    entry_lbl: &mut CodeLabel,
) -> Result<(), String> {
    a.set_label(entry_lbl).map_err(|e| e.to_string())?;
    a.zero_bytes().map_err(|e| e.to_string())?;

    // Keep the entry RFLAGS for the whole function when anything reads them
    // (`ExprNode::EntryRflags`): `pushfq` leaves them at `StackBase - 8`, and RSP
    // stays 16 below the entry RSP between blocks (every block starts at that depth).
    // Neither instruction changes the flags, so block 0 still sees the entry flags.
    // Every frame (the function entry and each native call's return, where
    // `SymState::new` starts over) saves its RFLAGS the same way, so in every block
    // RSP is 16 below the frame's `StackBase` and `EntryRflags` is at `StackBase - 8`.
    let saves_rflags = bitness == 64 && function_uses_entry_rflags(func);
    if saves_rflags {
        a.pushfq().map_err(|e| e.to_string())?;
        a.lea(gpr64::rsp, ptr(gpr64::rsp) - 8).map_err(|e| e.to_string())?;
    }
    // Below them, each frame keeps the pinned loads (`plan_pinned_loads`).
    let base0: i64 = if saves_rflags { 16 } else { 0 };
    let plan = plan_pinned_loads(func, view, base0)?;
    if !plan.slots.is_empty() && bitness != 64 {
        return Err("pinned_32bit".into());
    }
    let pin_bytes = 8 * plan.slots.len() as i64;
    let pin_d = i32::try_from(pin_bytes).map_err(|_| "pinned_disp".to_string())?;
    if pin_bytes > 0 {
        a.lea(gpr64::rsp, ptr(gpr64::rsp) - pin_d).map_err(|e| e.to_string())?;
    }

    let mut block_lbls: Vec<CodeLabel> = (0..func.blocks.len())
        .map(|_| a.create_label())
        .collect();

    for (bi, block) in func.blocks.iter().enumerate() {
        if bi > 0 {
            a.set_label(&mut block_lbls[bi]).map_err(|e| e.to_string())?;
            a.zero_bytes().map_err(|e| e.to_string())?;
        }
        let base_depth: i64 = base0 + pin_bytes;
        let frame = BlockFrame {
            base_depth,
            rflags_saved: saves_rflags,
            pin_slots: &plan.slots,
            start_ver: plan.start_ver[bi],
            start_cr8_ver: plan.start_cr8_ver[bi],
            succ_loads: &plan.succ_loads[bi],
            hoist_here: &plan.hoist_at[bi],
            hoist_active: &plan.hoist_active[bi],
            aligned: &block.aligned_defs,
        };

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
                            13 => a.jno(t_lbl),
                            14 => a.jp(t_lbl),
                            _ => a.jnp(t_lbl),
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
                    rsp_depth: base_depth,
                    saved_regs: HashMap::new(),
                    scratch,
                    eval_steps: 0,
                    spills: HashMap::new(),
                    pinned: frame.active_pinned(&func.arena),
                    spill_free: false,
                    aligned: &block.aligned_defs,
                };
                // `scratch[2]` too when effects or shared subexpressions need it.
                let want_w2 = !block.effects.is_empty()
                    || !frame.hoist_here.is_empty()
                    || !shared_subexprs(&ctx, &[*cond]).is_empty();
                ctx.spill_free = want_w2;
                // Save scratch registers used by `cond`/`effects`
                let mut pushed_sc = Vec::new();
                let sc_slice = if want_w2 { &scratch[..3] } else { &scratch[..2] };
                for &s in sc_slice {
                    ctx.emit_push(a, s)?;
                    ctx.saved_regs.insert(s, ctx.rsp_depth);
                    pushed_sc.push(s);
                }
                emit_block_effects(a, &mut ctx, &frame, &block.effects, &[*cond])?;
                // Values the blocks below share: into their slots (`plan_hoisted`).
                precompute_shared(a, &mut ctx, frame.hoist_here)?;
                for &h in frame.hoist_here {
                    if ctx.pinned.contains_key(&h) {
                        continue;
                    }
                    let depth = frame.pin_slots[&h];
                    ctx.eval_expr_into(a, h, scratch[0], scratch[2])?;
                    let m = mem_disp(ctx.bitness, ArchReg::Rsp, ctx.rsp_depth - depth, ctx.word_bytes as u8);
                    ctx.emit_store_to_mem(a, m, scratch[0], ctx.word_bytes as u8)?;
                    ctx.pinned.insert(h, depth);
                }
                precompute_shared(a, &mut ctx, &[*cond])?;
                // Compute condition `0/1` into `scratch[2]`? No, emit_branch_on_cond uses flags then restores scratch BEFORE jcc!
                let mut l_taken_tramp = a.create_label();
                ctx.emit_branch_on_cond(a, *cond, &mut l_taken_tramp, scratch[0], scratch[1])?;
                // Spilled loads sit above the scratch pushes: dropped on both paths.
                let spill_bytes = ctx.spills.len() as i64 * ctx.word_bytes;
                let spill_d = i32::try_from(spill_bytes).map_err(|_| "spill_disp".to_string())?;
                let drop_spills = |a: &mut CodeAssembler| -> Result<(), String> {
                    if spill_d == 0 {
                        return Ok(());
                    }
                    if bitness == 64 {
                        a.lea(gpr64::rsp, ptr(gpr64::rsp) + spill_d).map_err(|e| e.to_string())
                    } else {
                        a.lea(gpr32::esp, ptr(gpr32::esp) + spill_d).map_err(|e| e.to_string())
                    }
                };
                // Fallthrough path: restore scratch & jump to fallthrough block
                drop_spills(a)?;
                ctx.rsp_depth -= spill_bytes;
                ctx.spills.clear();
                for &s in pushed_sc.iter().rev() {
                    ctx.emit_pop(a, s)?;
                }
                let fall_lbl = block_lbls[*fallthrough_block];
                a.jmp(fall_lbl).map_err(|e| e.to_string())?;
                // Taken path: restore scratch (keep flags not needed at target!) & jump to taken block
                a.set_label(&mut l_taken_tramp).map_err(|e| e.to_string())?;
                a.zero_bytes().map_err(|e| e.to_string())?;
                drop_spills(a)?;
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
                    &frame,
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
                    &frame,
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
                    &frame,
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
                    &frame,
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
                    &frame,
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
                    &frame,
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
            IrTerm::ExitComputedJmp { target, rsp_delta, final_regs, final_xmms, pending_caller_stores } => {
                let word_bytes = if bitness == 64 { 8i64 } else { 4i64 };
                let mut pending_with_target = Vec::with_capacity(pending_caller_stores.len() + 1);
                pending_with_target.push((*rsp_delta - word_bytes, *target));
                pending_with_target.extend_from_slice(pending_caller_stores);
                emit_block_outputs_and_jump(
                    a,
                    bitness,
                    &frame,
                    &func.arena,
                    &block.effects,
                    &pending_with_target,
                    final_regs,
                    final_xmms,
                    *rsp_delta,
                    true,
                    None,
                    |asm, _| asm.ret().map_err(|e| e.to_string()),
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
                    &frame,
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
                        if saves_rflags {
                            // The continuation is a new frame: save its entry RFLAGS.
                            asm.pushfq().map_err(|e| e.to_string())?;
                            asm.lea(gpr64::rsp, ptr(gpr64::rsp) - 8).map_err(|e| e.to_string())?;
                        }
                        if pin_bytes > 0 {
                            asm.lea(gpr64::rsp, ptr(gpr64::rsp) - pin_d).map_err(|e| e.to_string())?;
                        }
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

fn test_compile_entry(
    view: &PeImageView,
    lifted: &LiftedFunction,
    cfg: &BinaryDevirtConfig,
    devirt_base_va: u64,
) -> UnpackerResult<Result<Vec<u8>, String>> {
    let mut test_asm = CodeAssembler::new(view.bitness)
        .map_err(|e| UnpackerError::General(format!("CodeAssembler: {e}")))?;
    let mut test_lbl = test_asm.create_label();
    if let Err(err) = compile_function_into_asm(&mut test_asm, view.bitness, lifted, view, &mut test_lbl) {
        return Ok(Err(format!("codegen_{err}")));
    }
    let Ok(test_res) = test_asm.assemble_options(devirt_base_va, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS) else {
        return Ok(Err("asm_encode_failed".into()));
    };

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
        return Ok(Err("invalid_emitted_insn".into()));
    }

    let has_vm_exit = lifted.blocks.iter().any(|b| matches!(b.term, IrTerm::ExitToVm { .. }));
    if lifted.entry.kind == VmEntryKind::CrossSectionVmEnter || has_vm_exit {
        if lifted.raw_vm_insns < cfg.min_vm_insns_replaced {
            return Ok(Err("too_little_vm_code".into()));
        }
        if native_insns.saturating_mul(100) > lifted.raw_vm_insns.saturating_mul(cfg.max_code_growth_percent) {
            return Ok(Err("code_growth_limit".into()));
        }
    }

    Ok(Ok(buf))
}

pub fn devirtualize_pe_bytes(
    pe_bytes: &[u8],
    cfg: BinaryDevirtConfig,
) -> UnpackerResult<(Vec<u8>, BinaryDevirtReport)> {
    let unpacked_owned: Option<Vec<u8>> = if !pe_bytes.is_empty() && vmpunpacker::detect(pe_bytes) {
        vmpunpacker::unpack(pe_bytes).ok()
    } else {
        None
    };
    let working_pe: &[u8] = unpacked_owned.as_deref().unwrap_or(pe_bytes);

    let mut view = PeImageView::from_pe_bytes(working_pe)?;
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
    let (next_rva, _) = imagedump::next_section_rva(working_pe)?;
    let devirt_base_va = view.image_base + next_rva as u64;
    let collect_diagnostics = cfg.collect_diagnostics;

    let mut record_bailout = |entry: &DiscoveredEntry, reason: String, lifted_ref: &LiftedFunction, post_lift: bool, image_base: u64| {
        if post_lift || lifted_ref.raw_vm_insns > 0 {
            partially_lifted += 1;
        } else {
            failed += 1;
        }
        *bailout_counts.entry(reason.clone()).or_insert(0) += 1;
        *bailout_kind_counts.entry((entry.kind, reason.clone())).or_insert(0) += 1;
        if collect_diagnostics {
            let (bip, detail) = lifted_ref.bailout_detail.as_ref().map_or_else(
                || {
                    (
                        image_base + entry.target_rva as u64,
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

    let mut dynamic_vm_slots: HashSet<u64> = HashSet::new();

    let lift_with_dynamic_slots = |view: &mut PeImageView,
                                   entry: &DiscoveredEntry,
                                   dyn_slots: &mut HashSet<u64>,
                                   visited: &mut HashSet<u64>|
     -> (LiftedFunction, Result<(), String>) {
        let mut lifted = lift_vm_entry_cfg(view, entry, &cfg);
        visited.extend(&lifted.visited_byte_addrs);
        let mut sound = validate_function_soundness(&lifted, view);
        for _ in 0..8 {
            if sound.as_ref().err().map(String::as_str) != Some("exit_target_not_executable")
                || lifted.folded_vm_qword_addrs.is_empty()
            {
                break;
            }
            let mut added = false;
            for &va in &lifted.folded_vm_qword_addrs {
                if view.add_mutable_ro_va(va, 8) {
                    dyn_slots.insert(va);
                    added = true;
                }
            }
            if !added {
                break;
            }
            lifted = lift_vm_entry_cfg(view, entry, &cfg);
            visited.extend(&lifted.visited_byte_addrs);
            sound = validate_function_soundness(&lifted, view);
        }
        if sound.as_ref().err().map(String::as_str) == Some("exit_target_not_executable")
            && cfg.allow_vm_exits
        {
            lifted = lift_vm_entry_cfg_inner(view, entry, &cfg, true);
            visited.extend(&lifted.visited_byte_addrs);
            sound = validate_function_soundness(&lifted, view);
        }
        (lifted, sound)
    };

    for entry in &discovered {
        let (lifted, sound) = lift_with_dynamic_slots(&mut view, entry, &mut dynamic_vm_slots, &mut visited_vm_bytes);
        if let Err(reason) = sound {
            record_bailout(entry, reason, &lifted, false, view.image_base);
            continue;
        }
        match test_compile_entry(&view, &lifted, &cfg, devirt_base_va)? {
            Ok(buf) => compiled_funcs.push((lifted, buf)),
            Err(reason) => record_bailout(entry, reason, &lifted, true, view.image_base),
        }
    }

    if !dynamic_vm_slots.is_empty() {
        for (lifted, buf) in std::mem::take(&mut compiled_funcs) {
            if !lifted.folded_vm_qword_addrs.iter().any(|va| dynamic_vm_slots.contains(va)) {
                compiled_funcs.push((lifted, buf));
                continue;
            }
            let entry = lifted.entry.clone();
            let (relifted, sound) = lift_with_dynamic_slots(&mut view, &entry, &mut dynamic_vm_slots, &mut visited_vm_bytes);
            if let Err(reason) = sound {
                record_bailout(&entry, reason, &relifted, false, view.image_base);
                continue;
            }
            match test_compile_entry(&view, &relifted, &cfg, devirt_base_va)? {
                Ok(new_buf) => compiled_funcs.push((relifted, new_buf)),
                Err(reason) => record_bailout(&entry, reason, &relifted, true, view.image_base),
            }
        }
    }

    // Re-assemble all sound stubs cleanly into one shared `.devirt` section so internal jumps stay compact
    let mut out_pe = working_pe.to_vec();
    if unpacked_owned.is_some() {
        let (_dos, _pe, opt, _secs) = parse_pe_bytes(&out_pe)?;
        imagedump::fix_sections(&mut out_pe, opt.section_alignment)?;
    }
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
            compile_function_into_asm(&mut master_asm, view.bitness, lifted, &view, &mut lbl)
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

    let vmp_rebuild = if cfg.rebuild_runnable_pe && (unpacked_owned.is_some() || cfg.oep_rva.is_some()) {
        let rep = crate::unpacker::vmp_rebuild::rebuild_vmp_pe(&mut out_pe, pe_bytes, cfg.oep_rva)?;
        imagedump::fix_checksum(&mut out_pe)?;
        Some(rep)
    } else {
        None
    };

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
            vmp_rebuild,
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
    fn aligned_frame_pointer_in_a_register_survives_the_vm_exit_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        // Entered 8 bytes lower too: the alignment padding differs.
        let fn1 = assemble_at(64, base + 0x1080, |a| {
            a.call(base + 0x1000)?;
            a.ret()
        });
        text_sec[0x80..0x80 + fn1.len()].copy_from_slice(&fn1);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // r12 points into the aligned frame (a VM context pointer) at the VM exit.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(qword_ptr(rsp + 0x18), 0x77)?;
            a.lea(r12, ptr(rsp + 0x10))?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
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
        for (off, add) in [(0x300usize, 1i32), (0x320, 2)] {
            let h = assemble_at(64, base + 0x2000 + off as u64, |a| {
                a.mov(rax, qword_ptr(r12))?;
                a.add(rax, qword_ptr(r12 + 8))?;
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
        for entry in [base + 0x1000, base + 0x1080] {
            for (c, d) in [(5u64, 0u64), (5, 0x20), (0xdead_beef_0000_0001, 0x20)] {
                let run = |pe: &[u8]| {
                    let s = Sample::from_bytes(pe).unwrap();
                    let mut eng = UnpackerEngine::new(s, "mem");
                    eng.init_uc().unwrap();
                    eng.call_function(entry, &[c, d], 100_000, 2_000).unwrap()
                };
                let want = c.wrapping_add(0x77).wrapping_add(if d & 0x20 != 0 { 2 } else { 1 });
                assert_eq!(run(&orig_pe), want, "original {entry:#x} {c:#x} {d:#x}");
                assert_eq!(run(&devirt_pe), want, "devirtualized {entry:#x} {c:#x} {d:#x}");
            }
        }
    }

    #[test]
    fn predicated_store_to_aligned_slot_or_caller_home_slot_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        // The caller's home slot gets a known value first.
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.sub(rsp, 0x28)?;
            a.mov(qword_ptr(rsp + 0x08), 0x500)?;
            a.call(base + 0x1100)?;
            a.add(rax, qword_ptr(rsp + 0x08))?;
            a.add(rsp, 0x28)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let callee = assemble_at(64, base + 0x1100, |a| a.jmp(base + 0x2000));
        text_sec[0x100..0x100 + callee.len()].copy_from_slice(&callee);
        let exit_ret = assemble_at(64, base + 0x1140, |a| a.ret());
        text_sec[0x140..0x140 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // [r9] = rcx, r9 = an aligned slot or the caller's home slot (entry + 0x10).
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), 3)?;
            a.lea(r9, ptr(rsp + 0x10))?;
            a.lea(r10, ptr(rbp + 0x20))?;
            a.test(gpr8::dl, 1)?;
            a.cmovz(r9, r10)?;
            a.mov(qword_ptr(r9), rcx)?;
            a.mov(rax, qword_ptr(rsp + 0x10))?;
            // The VM puts its scratch registers back: no frame pointer leaves.
            a.xor(gpr32::r9d, gpr32::r9d)?;
            a.xor(gpr32::r10d, gpr32::r10d)?;
            for k in 0..40i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.mov(rsp, rbp)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1140)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for (c, d) in [(7u64, 1u64), (7, 0), (0xdead_beef, 3), (0xdead_beef, 2)] {
            // dl odd: the aligned slot gets rcx (rax = rcx + 0x500); even: the home slot
            // does (rax = 3 + rcx).
            let want = if d & 1 != 0 { c + 0x500 } else { 3 + c };
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want, "original {c:#x} {d:#x}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "devirtualized {c:#x} {d:#x}");
        }
    }

    #[test]
    fn indexed_access_into_aligned_frame_exits_back_to_vm_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // A VM register file on the aligned frame read with an index from the input:
        // four possible slots, no fixed one - the VM runs that read itself.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            for k in 0..4i32 {
                a.mov(qword_ptr(rsp + k * 8), (k + 1) * 100)?;
            }
            a.mov(qword_ptr(rsp + 0x20), rcx)?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.mov(r8, rdx)?;
            a.and(r8, 3)?;
            a.mov(rax, qword_ptr(rsp + r8 * 8))?;
            a.add(rax, qword_ptr(rsp + 0x20))?;
            a.mov(rsp, rbp)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for (c, d) in [(7u64, 0u64), (7, 1), (0xdead_beef, 2), (1, 7)] {
            let want = ((d & 3) + 1) * 100 + c;
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want, "original {c:#x} {d:#x}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "devirtualized {c:#x} {d:#x}");
        }
    }

    #[test]
    fn same_aligned_frame_id_on_two_paths_with_different_frames_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let fn1 = assemble_at(64, base + 0x1080, |a| {
            a.call(base + 0x1000)?;
            a.ret()
        });
        text_sec[0x80..0x80 + fn1.len()].copy_from_slice(&fn1);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // One path pushes once more before `and rsp, -16`: the first aligned frame of
        // each path (id 0) comes from a different RSP.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut aligned = a.create_label();
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.test(gpr8::dl, 2)?;
            a.jz(aligned)?;
            a.push(rax)?;
            a.set_label(&mut aligned)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(qword_ptr(rsp + 0x18), 0x77)?;
            a.lea(r12, ptr(rsp + 0x10))?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
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
        for (off, add) in [(0x300usize, 1i32), (0x320, 2)] {
            let h = assemble_at(64, base + 0x2000 + off as u64, |a| {
                a.mov(rax, qword_ptr(r12))?;
                a.add(rax, qword_ptr(r12 + 8))?;
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
        for entry in [base + 0x1000, base + 0x1080] {
            for (c, d) in [(5u64, 0u64), (5, 2), (9, 0x20), (0xdead_beef_0000_0001, 0x22)] {
                let run = |pe: &[u8]| {
                    let s = Sample::from_bytes(pe).unwrap();
                    let mut eng = UnpackerEngine::new(s, "mem");
                    eng.init_uc().unwrap();
                    eng.call_function(entry, &[c, d], 100_000, 2_000).unwrap()
                };
                let want = c.wrapping_add(0x77).wrapping_add(if d & 0x20 != 0 { 2 } else { 1 });
                assert_eq!(run(&orig_pe), want, "original {entry:#x} {c:#x} {d:#x}");
                assert_eq!(run(&devirt_pe), want, "devirtualized {entry:#x} {c:#x} {d:#x}");
            }
        }
    }

    #[test]
    fn aligned_frame_pointer_leaving_through_a_plain_exit_is_rejected() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // The frame's contents never reach memory outside `ExitToVm`: a pointer to it in
        // a register at an ordinary exit would point at whatever is there.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.lea(r12, ptr(rsp + 0x10))?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.mov(rsp, rbp)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (_, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 0);
        assert!(
            report.bailout_reasons.iter().any(|(r, _)| r.contains("aligned_frame_escapes")),
            "bailouts: {:?}",
            report.bailout_reasons
        );
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
    fn unwritten_aligned_slots_below_entry_are_undefined_not_unknown_e2e() {
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
            // A VM register never written: its stale value goes to r10 (a dead output).
            a.mov(r10, qword_ptr(rsp + 0x28))?;
            // Partly written slot, read back whole and masked: only the written bytes count.
            a.mov(dword_ptr(rsp + 0x20), gpr32::ecx)?;
            a.mov(rax, qword_ptr(rsp + 0x20))?;
            for k in 0..60i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.shl(rax, 32)?;
            a.shr(rax, 32)?;
            a.add(rax, rdx)?;
            a.mov(rsp, rbp)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 0);
        for (c, d) in [(7u64, 1u64), (0xdead_beef_1234_5678, 0x20), (u64::MAX, 0)] {
            let want = (c & 0xffff_ffff) + d;
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want);
        }
    }

    #[test]
    fn aligned_frame_over_stack_written_before_is_still_free_e2e() {
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
            // Scratch below RSP, written and released before the frame is aligned.
            a.sub(rsp, 0x80)?;
            for k in 0..16i32 {
                a.mov(qword_ptr(rsp + k * 8), rcx)?;
            }
            a.add(rsp, 0x80)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(r10, qword_ptr(rsp + 0x28))?;
            a.mov(dword_ptr(rsp + 0x20), gpr32::ecx)?;
            a.mov(rax, qword_ptr(rsp + 0x20))?;
            for k in 0..60i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.shl(rax, 32)?;
            a.shr(rax, 32)?;
            a.add(rax, rdx)?;
            a.mov(rsp, rbp)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for (c, d) in [(7u64, 1u64), (0xdead_beef_1234_5678, 0x20)] {
            let want = (c & 0xffff_ffff) + d;
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want);
        }
    }

    /// Runs `entry` with `rcx`/`rdx` and the given entry CF; returns rax, rbx, rbp, the
    /// RSP difference and the final CF.
    fn run_with_cf(pe_bytes: &[u8], entry: u64, rcx_in: u64, rdx_in: u64, cf: bool) -> (u64, u64, u64, u64, u64) {
        let s = Sample::from_bytes(pe_bytes).unwrap();
        let mut eng = UnpackerEngine::new(s, "mem");
        eng.init_uc().unwrap();
        let rsp_before = {
            let uc = eng.unicorn_mut().unwrap();
            uc.reg_write(RegisterX86::RBP as i32, 0xB0B0_0000_1111).unwrap();
            uc.reg_write(RegisterX86::RBX as i32, 0xB1B1_0000_2222).unwrap();
            let fl = uc.reg_read(RegisterX86::EFLAGS as i32).unwrap();
            uc.reg_write(RegisterX86::EFLAGS as i32, if cf { fl | 1 } else { fl & !1 }).unwrap();
            uc.reg_read(RegisterX86::RSP as i32).unwrap()
        };
        let ret = eng.call_function(entry, &[rcx_in, rdx_in], 200_000, 2_000).unwrap();
        let uc = eng.unicorn_mut().unwrap();
        (
            ret,
            uc.reg_read(RegisterX86::RBX as i32).unwrap(),
            uc.reg_read(RegisterX86::RBP as i32).unwrap(),
            uc.reg_read(RegisterX86::RSP as i32).unwrap().wrapping_sub(rsp_before),
            uc.reg_read(RegisterX86::EFLAGS as i32).unwrap() & 1,
        )
    }

    #[test]
    fn vm_context_with_pushfq_is_rebuilt_on_vm_exit_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        // vmenter: the entry flags go into the context first, then an aligned frame.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.pushfq()?;
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
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
        // Handlers restore the pushed flags and use the entry CF.
        for (off, add) in [(0x300usize, 1i32), (0x320, 2)] {
            let h = assemble_at(64, base + 0x2000 + off as u64, |a| {
                a.mov(rax, qword_ptr(rsp + 0x10))?;
                a.add(rax, add)?;
                a.mov(rsp, rbp)?;
                a.pop(rbp)?;
                a.pop(rbx)?;
                a.popfq()?;
                a.adc(rax, 0)?;
                a.jmp(base + 0x1040)
            });
            vmp_sec[off..off + h.len()].copy_from_slice(&h);
        }
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for cf in [false, true] {
            for (rcx_in, rdx_in) in [(7u64, 0u64), (7, 0x20)] {
                let orig = run_with_cf(&orig_pe, base + 0x1000, rcx_in, rdx_in, cf);
                let want = rcx_in + if rdx_in & 0x20 != 0 { 2 } else { 1 } + cf as u64;
                assert_eq!(orig.0, want, "original cf={cf} rdx={rdx_in:#x}");
                assert_eq!(run_with_cf(&devirt_pe, base + 0x1000, rcx_in, rdx_in, cf), orig, "devirtualized cf={cf} rdx={rdx_in:#x}");
            }
        }
    }

    #[test]
    fn exit_with_untouched_entry_flags_restores_them_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        // Nothing before `cpuid` touches the flags (lea only); `jc` reads the entry CF.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut carry = a.create_label();
            let mut tail = a.create_label();
            a.lea(rsp, ptr(rsp) - 0x20)?;
            a.mov(qword_ptr(rsp + 0x10), rbx)?;
            a.mov(r9, rcx)?; // cpuid clobbers rax/rbx/rcx/rdx
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.lea(rax, ptr(rax) + (k + 3))?;
                a.lea(rax, ptr(rax) - (k + 3))?;
            }
            a.cpuid()?;
            a.jc(carry)?;
            a.mov(rax, r9)?;
            a.add(rax, 10)?;
            a.jmp(tail)?;
            a.set_label(&mut carry)?;
            a.mov(rax, r9)?;
            a.add(rax, 20)?;
            a.set_label(&mut tail)?;
            a.mov(rbx, qword_ptr(rsp + 0x10))?;
            a.lea(rsp, ptr(rsp) + 0x20)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for cf in [false, true] {
            let orig = run_with_cf(&orig_pe, base + 0x1000, 100, 0, cf);
            assert_eq!(orig.0, 100 + if cf { 20 } else { 10 }, "original cf={cf}");
            let dev = run_with_cf(&devirt_pe, base + 0x1000, 100, 0, cf);
            // cpuid clobbers rbx/rcx/rdx in both; compare rax, rbx, rsp and CF.
            assert_eq!((dev.0, dev.1, dev.3, dev.4), (orig.0, orig.1, orig.3, orig.4), "devirtualized cf={cf}");
        }
    }

    #[test]
    fn pushfq_context_with_native_midcall_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        // Native helper the VM calls: rax = rcx * 3 + 1.
        let helper = assemble_at(64, base + 0x1100, |a| {
            a.lea(rax, ptr(rcx + rcx * 2) + 1)?;
            a.ret()
        });
        text_sec[0x100..0x100 + helper.len()].copy_from_slice(&helper);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.pushfq()?;
            a.push(rbx)?;
            a.sub(rsp, 0x28)?;
            a.mov(rbx, rcx)?;
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.call(base + 0x1100)?;
            a.add(rax, rbx)?;
            a.add(rsp, 0x28)?;
            a.pop(rbx)?;
            a.popfq()?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for cf in [false, true] {
            for rcx_in in [2u64, 1000] {
                let orig = run_with_cf(&orig_pe, base + 0x1000, rcx_in, 0, cf);
                assert_eq!(orig.0, rcx_in * 4 + 1, "original");
                let dev = run_with_cf(&devirt_pe, base + 0x1000, rcx_in, 0, cf);
                assert_eq!((dev.0, dev.1, dev.2, dev.3), (orig.0, orig.1, orig.2, orig.3), "devirtualized cf={cf} rcx={rcx_in}");
            }
        }
    }

    #[test]
    fn exit_after_native_call_restores_callee_flags_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        // Native helper: CF = (rcx < 50), rax = rcx.
        let helper = assemble_at(64, base + 0x1100, |a| {
            a.mov(rax, rcx)?;
            a.cmp(rcx, 50)?;
            a.ret()
        });
        text_sec[0x100..0x100 + helper.len()].copy_from_slice(&helper);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut carry = a.create_label();
            let mut tail = a.create_label();
            a.pushfq()?;
            a.push(rbx)?;
            a.sub(rsp, 0x28)?;
            a.mov(r9, rcx)?;
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.call(base + 0x1100)?;
            // Continuation: flags are the helper's; nothing touches them before jc.
            for k in 0..20i32 {
                a.lea(r10, ptr(r9) + (k + 1))?;
            }
            a.cpuid()?;
            a.jc(carry)?;
            a.lea(rax, ptr(r9) + 1000)?;
            a.jmp(tail)?;
            a.set_label(&mut carry)?;
            a.lea(rax, ptr(r9) + 2000)?;
            a.set_label(&mut tail)?;
            a.add(rsp, 0x28)?;
            a.pop(rbx)?;
            a.popfq()?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for cf in [false, true] {
            for rcx_in in [10u64, 90] {
                let orig = run_with_cf(&orig_pe, base + 0x1000, rcx_in, 0, cf);
                assert_eq!(orig.0, rcx_in + if rcx_in < 50 { 2000 } else { 1000 }, "original");
                let dev = run_with_cf(&devirt_pe, base + 0x1000, rcx_in, 0, cf);
                // cpuid clobbers rbx inside, but rbx is restored from the stack.
                assert_eq!((dev.0, dev.1, dev.2, dev.3, dev.4), orig, "devirtualized cf={cf} rcx={rcx_in}");
            }
        }
    }

    fn run_with_flags(pe_bytes: &[u8], entry: u64, rcx_in: u64, rdx_in: u64, set: u64, clear: u64) -> u64 {
        let s = Sample::from_bytes(pe_bytes).unwrap();
        let mut eng = UnpackerEngine::new(s, "mem");
        eng.init_uc().unwrap();
        {
            let uc = eng.unicorn_mut().unwrap();
            let fl = uc.reg_read(RegisterX86::EFLAGS as i32).unwrap();
            uc.reg_write(RegisterX86::EFLAGS as i32, (fl | set) & !clear).unwrap();
        }
        eng.call_function(entry, &[rcx_in, rdx_in], 200_000, 2_000).unwrap()
    }

    #[test]
    fn adc_sbb_with_symbolic_carry_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x28)?;
            a.mov(r11, rcx)?;
            for k in 0..30i32 {
                a.add(r11, k + 3)?;
                a.sub(r11, k + 3)?;
            }
            // carry of rcx + rdx
            a.mov(rax, rcx)?;
            a.xor(r8, r8)?;
            a.add(rax, rdx)?;
            a.adc(r8, 0)?;
            // borrow of rcx - rdx
            a.mov(r10, rcx)?;
            a.xor(r9, r9)?;
            a.sub(r10, rdx)?;
            a.sbb(r9, 0)?;
            a.imul_3(r8, r8, 10)?;
            a.sub(r8, r9)?;
            a.mov(rax, r8)?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for (c, d) in [(1u64, 2u64), (u64::MAX, 1), (5, 9), (u64::MAX, u64::MAX), (0, 0), (1 << 63, 1 << 63)] {
            let want = (c.checked_add(d).is_none() as u64) * 10 + (c < d) as u64;
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want, "original {c:#x} {d:#x}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "devirtualized {c:#x} {d:#x}");
        }
    }

    #[test]
    fn mul_imul_high_half_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x1000];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x28)?;
            a.mov(r11, rcx)?;
            for k in 0..120i32 {
                a.add(r11, k + 3)?;
                a.sub(r11, k + 3)?;
            }
            a.mov(r10, rdx)?;
            // unsigned 64-bit high half
            a.mov(rax, rcx)?;
            a.mul(r10)?;
            a.mov(r8, rdx)?;
            // signed 64-bit high half
            a.mov(rax, rcx)?;
            a.imul(r10)?;
            a.mov(r9, rdx)?;
            // unsigned 32-bit high half (EDX)
            a.mov(gpr32::eax, gpr32::ecx)?;
            a.mul(gpr32::r10d)?;
            a.mov(gpr32::r11d, gpr32::edx)?;
            // signed 32-bit high half
            a.mov(gpr32::eax, gpr32::ecx)?;
            a.imul(gpr32::r10d)?;
            // rax = hiU * 3 + hiS ^ (hi32u << 32) ^ hi32s
            a.imul_3(r8, r8, 3)?;
            a.add(r8, r9)?;
            a.shl(r11, 32)?;
            a.xor(r8, r11)?;
            a.mov(gpr32::edx, gpr32::edx)?;
            a.xor(r8, rdx)?;
            a.mov(rax, r8)?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 0);
        for (c, d) in [
            (1u64, 2u64),
            (u64::MAX, 3),
            (0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321),
            (u64::MAX, u64::MAX),
            (0, 7),
            (1 << 63, 1 << 63),
            (0xffff_ffff, 0x8000_0001),
        ] {
            let hu = ((c as u128 * d as u128) >> 64) as u64;
            let hs = (((c as i64 as i128) * (d as i64 as i128)) >> 64) as u64;
            let h32u = ((c as u32 as u64 * d as u32 as u64) >> 32) as u32 as u64;
            let h32s = (((c as u32 as i32 as i64) * (d as u32 as i32 as i64)) >> 32) as u32 as u64;
            let want = hu.wrapping_mul(3).wrapping_add(hs) ^ (h32u << 32) ^ h32s;
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want, "original {c:#x} {d:#x}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "devirtualized {c:#x} {d:#x}");
        }
    }

    #[test]
    fn entry_flags_read_as_values_beyond_block0_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut zero_path = a.create_label();
            let mut tail = a.create_label();
            a.lea(rsp, ptr(rsp) - 0x28)?;
            a.mov(rax, rcx)?;
            for k in 0..30i32 {
                a.lea(rax, ptr(rax) + (k + 3))?;
                a.lea(rax, ptr(rax) - (k + 3))?;
            }
            a.jz(zero_path)?;
            a.setc(gpr8::dl)?;
            a.movzx(gpr32::edx, gpr8::dl)?;
            a.lea(rax, ptr(rax + rdx) + 100)?;
            a.jmp(tail)?;
            a.set_label(&mut zero_path)?;
            a.setc(gpr8::dl)?;
            a.movzx(gpr32::edx, gpr8::dl)?;
            a.lea(rax, ptr(rax + rdx) + 200)?;
            a.set_label(&mut tail)?;
            a.lea(rsp, ptr(rsp) + 0x28)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        const CF: u64 = 1;
        const ZF: u64 = 1 << 6;
        for (cf, zf) in [(false, false), (true, false), (false, true), (true, true)] {
            let set = if cf { CF } else { 0 } | if zf { ZF } else { 0 };
            let clear = (CF | ZF) & !set;
            let want = 1000 + cf as u64 + if zf { 200 } else { 100 };
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, 1000, 0, set, clear), want, "original cf={cf} zf={zf}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, 1000, 0, set, clear), want, "devirtualized cf={cf} zf={zf}");
        }
    }

    #[test]
    fn load_used_after_possibly_aliasing_store_is_read_first_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // rax = [rcx] read BEFORE `[rdx] = 77`, r9 = [rcx] after it; rcx may equal rdx.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.sub(rsp, 0x28)?;
            a.mov(r11, rcx)?;
            for k in 0..30i32 {
                a.add(r11, k + 3)?;
                a.sub(r11, k + 3)?;
            }
            a.mov(rax, qword_ptr(rcx))?;
            a.mov(qword_ptr(rdx), 77)?;
            a.mov(r9, qword_ptr(rcx))?;
            a.lea(rax, ptr(rax + r9 * 2))?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        let run = |pe: &[u8], p_load: u64, p_store: u64| -> (u64, u64) {
            let s = Sample::from_bytes(pe).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.mem_write(base + 0x3000, &5u64.to_le_bytes()).unwrap();
                uc.mem_write(base + 0x3010, &9u64.to_le_bytes()).unwrap();
            }
            let ret = eng.call_function(base + 0x1000, &[p_load, p_store], 100_000, 2_000).unwrap();
            let mut b = [0u8; 8];
            eng.unicorn_mut().unwrap().mem_read(p_store, &mut b).unwrap();
            (ret, u64::from_le_bytes(b))
        };
        // Aliasing: 5 + 77 * 2; disjoint: 5 + 5 * 2.
        for (pl, ps, want) in [(base + 0x3000, base + 0x3000, 159u64), (base + 0x3000, base + 0x3010, 15)] {
            assert_eq!(run(&orig_pe, pl, ps), (want, 77), "original");
            assert_eq!(run(&devirt_pe, pl, ps), (want, 77), "devirtualized");
        }
    }

    #[test]
    fn load_used_in_a_later_block_after_an_aliasing_store_is_pinned_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x1000];
        // rax = [rcx] in block 0; a branch block then stores `[rdx]` (rcx may equal rdx)
        // and branches again; the exits use rax and [rcx] read after the store.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut other = a.create_label();
            let mut tail = a.create_label();
            let mut tail2 = a.create_label();
            a.sub(rsp, 0x28)?;
            a.mov(r11, rcx)?;
            for k in 0..200i32 {
                a.add(r11, k + 3)?;
                a.sub(r11, k + 3)?;
            }
            a.mov(rax, qword_ptr(rcx))?;
            a.test(gpr8::dl, 0x10)?;
            a.jnz(other)?;
            a.mov(qword_ptr(rdx), 88)?;
            a.test(gpr8::cl, 8)?;
            a.jnz(tail2)?;
            a.mov(r9, qword_ptr(rcx))?;
            a.jmp(tail)?;
            a.set_label(&mut tail2)?;
            a.mov(r9, qword_ptr(rcx))?;
            a.add(r9, 1000)?;
            a.jmp(tail)?;
            a.set_label(&mut other)?;
            a.mov(qword_ptr(rdx), 99)?;
            a.test(gpr8::cl, 8)?;
            a.jnz(tail2)?;
            a.mov(r9, qword_ptr(rcx))?;
            a.set_label(&mut tail)?;
            a.lea(rax, ptr(rax + r9 * 2))?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        let run = |pe: &[u8], p_load: u64, p_store: u64| -> (u64, u64) {
            let s = Sample::from_bytes(pe).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.mem_write(base + 0x3000, &5u64.to_le_bytes()).unwrap();
                uc.mem_write(base + 0x3010, &9u64.to_le_bytes()).unwrap();
            }
            let ret = eng.call_function(base + 0x1000, &[p_load, p_store], 100_000, 2_000).unwrap();
            let mut b = [0u8; 8];
            eng.unicorn_mut().unwrap().mem_read(p_store, &mut b).unwrap();
            (ret, u64::from_le_bytes(b))
        };
        for (pl, ps, want) in [
            // aliasing, stores 88: 5 + 88 * 2
            (base + 0x3000, base + 0x3000, (181u64, 88u64)),
            // disjoint, stores 99: 5 + 5 * 2
            (base + 0x3000, base + 0x3010, (15, 99)),
            // aliasing at 0x3010, stores 99: 9 + 99 * 2
            (base + 0x3010, base + 0x3010, (207, 99)),
            // load at 0x3008 (bit 3 set): 0 + (88 + 1000) * 2 with the store aliasing
            (base + 0x3008, base + 0x3008, (2176, 88)),
        ] {
            assert_eq!(run(&orig_pe, pl, ps), want, "original {pl:#x} {ps:#x}");
            assert_eq!(run(&devirt_pe, pl, ps), want, "devirtualized {pl:#x} {ps:#x}");
        }
    }

    #[test]
    fn shared_subexpressions_are_computed_once_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x1000];
        // x = x * x + (x ^ [rdx]) fourteen times: a small DAG, a tree of millions of
        // nodes. A branch on the result and a guarded load in a select arm too.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut big = a.create_label();
            let mut tail = a.create_label();
            a.sub(rsp, 0x28)?;
            a.mov(r11, rcx)?;
            for k in 0..440i32 {
                a.add(r11, k % 60 + 3)?;
                a.sub(r11, k % 60 + 3)?;
            }
            a.mov(r8, rcx)?;
            for _ in 0..14 {
                a.mov(rax, r8)?;
                a.imul_2(rax, rax)?;
                a.mov(r9, qword_ptr(rdx))?;
                a.xor(r9, r8)?;
                a.add(rax, r9)?;
                a.mov(r8, rax)?;
            }
            a.cmp(r8, 1000)?;
            a.ja(big)?;
            a.mov(rax, r8)?;
            a.jmp(tail)?;
            a.set_label(&mut big)?;
            a.lea(rax, ptr(r8 + r8 * 2))?;
            a.set_label(&mut tail)?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        assert!(stub.len() <= vmp_sec.len());
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        let run = |pe: &[u8], c: u64, m: u64| -> u64 {
            let s = Sample::from_bytes(pe).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.unicorn_mut().unwrap().mem_write(base + 0x3000, &m.to_le_bytes()).unwrap();
            eng.call_function(base + 0x1000, &[c, base + 0x3000], 200_000, 2_000).unwrap()
        };
        for (c, m) in [(0u64, 0u64), (1, 2), (3, 0xdead_beef), (u64::MAX, 7)] {
            let mut x = c;
            for _ in 0..14 {
                x = x.wrapping_mul(x).wrapping_add(x ^ m);
            }
            let want = if x > 1000 { x.wrapping_mul(3) } else { x };
            assert_eq!(run(&orig_pe, c, m), want, "original {c:#x} {m:#x}");
            assert_eq!(run(&devirt_pe, c, m), want, "devirtualized {c:#x} {m:#x}");
        }
    }

    #[test]
    fn value_shared_by_several_exits_is_computed_once_above_them_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x1000];
        // x = f(rcx) (no memory), then three exits after two branches each use x;
        // one branch condition uses it too, the other one does not.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut l1 = a.create_label();
            let mut l2 = a.create_label();
            let mut done = a.create_label();
            a.sub(rsp, 0x28)?;
            a.mov(r11, rcx)?;
            for k in 0..300i32 {
                a.add(r11, k % 60 + 3)?;
                a.sub(r11, k % 60 + 3)?;
            }
            a.mov(r8, rcx)?;
            for k in 0..6i32 {
                a.imul_2(r8, r8)?;
                a.xor(r8, rcx)?;
                a.add(r8, k + 1)?;
            }
            a.test(gpr8::dl, 1)?;
            a.jnz(l1)?;
            a.mov(rax, r8)?;
            a.add(rax, 10)?;
            a.jmp(done)?;
            a.set_label(&mut l1)?;
            a.cmp(r8, rdx)?;
            a.jb(l2)?;
            a.lea(rax, ptr(r8 + 20))?;
            a.jmp(done)?;
            a.set_label(&mut l2)?;
            a.lea(rax, ptr(r8 + r8 * 2))?;
            a.set_label(&mut done)?;
            a.add(rsp, 0x28)?;
            a.jmp(base + 0x1040)
        });
        assert!(stub.len() <= vmp_sec.len());
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for (c, d) in [(3u64, 0u64), (3, 1), (0, u64::MAX), (0x1234_5678, 0xffff_ffff_ffff_fff1), (u64::MAX, 7)] {
            let mut x = c;
            for k in 0..6u64 {
                x = x.wrapping_mul(x) ^ c;
                x = x.wrapping_add(k + 1);
            }
            let want = if d & 1 == 0 {
                x.wrapping_add(10)
            } else if x < d {
                x.wrapping_mul(3)
            } else {
                x.wrapping_add(20)
            };
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want, "original {c:#x} {d:#x}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "devirtualized {c:#x} {d:#x}");
        }
    }

    #[test]
    fn exit_values_read_caller_slots_before_the_exit_overwrites_them_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        // The caller fills its home slots, calls, then reads them back.
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.sub(rsp, 0x28)?;
            // Callee's home slots 1 and 2 (entry + 8 / + 0x10).
            a.mov(qword_ptr(rsp), 0x500)?;
            a.mov(qword_ptr(rsp + 0x08), 0x600)?;
            a.call(base + 0x1100)?;
            a.shl(rax, 16)?;
            a.add(rax, qword_ptr(rsp))?;
            a.shl(rax, 16)?;
            a.add(rax, qword_ptr(rsp + 0x08))?;
            a.add(rsp, 0x28)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let callee = assemble_at(64, base + 0x1100, |a| a.jmp(base + 0x2000));
        text_sec[0x100..0x100 + callee.len()].copy_from_slice(&callee);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // rax = old home slot 1; home slot 1 = rcx; home slot 2 = old home slot 1 + 1.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rax, qword_ptr(rsp + 0x18))?;
            a.mov(r8, rax)?;
            for k in 0..40i32 {
                a.add(r8, k + 3)?;
                a.sub(r8, k + 3)?;
            }
            a.mov(qword_ptr(rsp + 0x18), rcx)?;
            a.add(r8, 1)?;
            a.mov(qword_ptr(rsp + 0x20), r8)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for c in [7u64, 123] {
            // rax = 0x500, home 1 = rcx, home 2 = 0x501.
            let want = (((0x500 << 16) + c) << 16) + 0x501;
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, 0, 0, 0), want, "original {c}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, 0, 0, 0), want, "devirtualized {c}");
        }
    }

    #[test]
    fn leaf_operands_from_registers_and_caller_slots_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.sub(rsp, 0x28)?;
            a.mov(r8, 0x1234_5678_9abc_def0u64)?;
            a.mov(qword_ptr(rsp), r8)?; // callee's home 1
            a.mov(qword_ptr(rsp + 0x08), 0x77)?; // callee's home 2
            a.call(base + 0x1100)?;
            a.add(rsp, 0x28)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let callee = assemble_at(64, base + 0x1100, |a| a.jmp(base + 0x2000));
        text_sec[0x100..0x100 + callee.len()].copy_from_slice(&callee);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // Non-commutative with a leaf on the left (rcx - (h1 * rdx)), leaves on both
        // sides, a caller-slot qword as the right operand of every operation.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(r8, qword_ptr(rsp + 0x18))?; // h1
            a.mov(r9, qword_ptr(rsp + 0x20))?; // h2
            for k in 0..40i32 {
                a.add(r9, k + 3)?;
                a.sub(r9, k + 3)?;
            }
            a.mov(r10, r8)?;
            a.imul_2(r10, rdx)?;
            a.mov(rax, rcx)?;
            a.sub(rax, r10)?; // rcx - h1 * rdx
            a.mov(r11, rcx)?;
            a.xor(r11, rdx)?;
            a.and(r11, r8)?; // (rcx ^ rdx) & h1
            a.add(rax, r11)?;
            a.mov(r10, r9)?;
            a.sub(r10, rcx)?; // h2 - rcx
            a.or(r10, rdx)?;
            a.xor(rax, r10)?;
            a.sub(rax, r9)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        let h1 = 0x1234_5678_9abc_def0u64;
        let h2 = 0x77u64;
        for (c, d) in [(5u64, 3u64), (u64::MAX, 0x8000_0000_0000_0001), (0, 0), (0xdead_beef, 0x1_0000_0001)] {
            let mut r = c.wrapping_sub(h1.wrapping_mul(d));
            r = r.wrapping_add((c ^ d) & h1);
            r ^= h2.wrapping_sub(c) | d;
            r = r.wrapping_sub(h2);
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), r, "original {c:#x} {d:#x}");
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), r, "devirtualized {c:#x} {d:#x}");
        }
    }

    #[test]
    fn code_size_rule_allows_bounded_growth_and_stops_the_rest() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // A short VM path into an aligned frame whose exit back to the VM has to fill
        // the frame: more native instructions than the VM ran, well within 4x.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            for k in 0..6i32 {
                a.mov(qword_ptr(rsp + k * 8), rcx)?;
                a.add(rcx, k + 1)?;
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
                a.mov(rax, qword_ptr(rsp + 0x28))?;
                a.add(rax, add)?;
                a.mov(rsp, rbp)?;
                a.pop(rbp)?;
                a.pop(rbx)?;
                a.jmp(base + 0x1040)
            });
            vmp_sec[off..off + h.len()].copy_from_slice(&h);
        }
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        // Default: accepted although larger than the VM path.
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        let f = &report.patched_sites[0];
        assert!(f.native_insns > f.raw_vm_insns, "not a growth case: {} vs {}", f.native_insns, f.raw_vm_insns);
        for (c, d) in [(5u64, 0u64), (5, 0x20), (0xdead_beef, 0x20)] {
            // Slot 5 holds rcx + 1 + 2 + 3 + 4 + 5.
            let want = c.wrapping_add(15).wrapping_add(if d & 0x20 != 0 { 2 } else { 1 });
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0), want);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want);
        }
        // A tighter cap rejects it, and so does a minimum it does not reach.
        let tight = BinaryDevirtConfig { max_code_growth_percent: 100, ..BinaryDevirtConfig::default() };
        let (_, report) = devirtualize_pe_bytes(&orig_pe, tight).unwrap();
        assert_eq!(report.devirtualized_total, 0);
        assert!(report.bailout_reasons.iter().any(|(r, _)| r.contains("code_growth_limit")), "{:?}", report.bailout_reasons);
        let big_min = BinaryDevirtConfig { min_vm_insns_replaced: 10_000, ..BinaryDevirtConfig::default() };
        let (_, report) = devirtualize_pe_bytes(&orig_pe, big_min).unwrap();
        assert_eq!(report.devirtualized_total, 0);
        assert!(report.bailout_reasons.iter().any(|(r, _)| r.contains("too_little_vm_code")), "{:?}", report.bailout_reasons);
    }

    #[test]
    fn far_stack_relative_load_is_computed_not_displaced_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // RSP + a constant beyond any displacement, read only on a path not taken
        // here (in a VM: a dead handler slot): it must still assemble.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut skip = a.create_label();
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.cmp(rdx, 0x1234)?;
            a.jne(skip)?;
            a.mov(r9, 0x7000_0000_0000u64)?;
            a.mov(rax, qword_ptr(rsp + r9))?;
            a.mov(qword_ptr(rsp + r9 + 8), rcx)?;
            a.set_label(&mut skip)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for c in [5u64, 0xdead_beef] {
            assert_eq!(run_with_flags(&orig_pe, base + 0x1000, c, 0, 0, 0), c);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, 0, 0, 0), c);
        }
    }

    #[test]
    fn frame_aligned_on_a_copy_then_moved_into_rsp_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let fn1 = assemble_at(64, base + 0x1080, |a| {
            a.call(base + 0x1000)?;
            a.ret()
        });
        text_sec[0x80..0x80 + fn1.len()].copy_from_slice(&fn1);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // `mov rax, rsp; and rax, -16; mov rsp, rax` instead of `and rsp, -16`, then
        // a VM exit that must rebuild the frame.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.lea(rax, ptr(rsp) - 0x40)?;
            a.and(rax, -16)?;
            a.mov(rsp, rax)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(qword_ptr(rsp + 0x18), 0x77)?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
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
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for entry in [base + 0x1000, base + 0x1080] {
            for (c, d) in [(5u64, 0u64), (5, 0x20), (0xdead_beef_0000_0001, 0x20)] {
                let run = |pe: &[u8]| {
                    let s = Sample::from_bytes(pe).unwrap();
                    let mut eng = UnpackerEngine::new(s, "mem");
                    eng.init_uc().unwrap();
                    eng.call_function(entry, &[c, d], 100_000, 2_000).unwrap()
                };
                let want = c.wrapping_add(0x77).wrapping_add(if d & 0x20 != 0 { 2 } else { 1 });
                assert_eq!(run(&orig_pe), want, "original {entry:#x} {c:#x} {d:#x}");
                assert_eq!(run(&devirt_pe), want, "devirtualized {entry:#x} {c:#x} {d:#x}");
            }
        }
    }

    #[test]
    fn pushfq_after_cmp_and_add_is_computed_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // RFLAGS after `cmp ecx, edx` and after `add cl, dl`, whole (system bits too),
        // combined into rax.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(r11, rcx)?;
            for k in 0..40i32 {
                a.add(r11, k + 3)?;
                a.sub(r11, k + 3)?;
            }
            a.cmp(gpr32::ecx, gpr32::edx)?;
            a.pushfq()?;
            a.pop(rax)?;
            a.mov(r8, rcx)?;
            a.add(gpr8::r8b, gpr8::dl)?;
            a.pushfq()?;
            a.pop(r9)?;
            a.shl(r9, 32)?;
            a.xor(rax, r9)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for (c, d) in [
            (5u64, 5u64),
            (5, 6),
            (0x8000_0000, 1),
            (0x7fff_ffff, 0xffff_ffff),
            (0x0f, 0x01),
            (0x10, 0x01),
            (0xff, 0x01),
            (0x7f, 0x01),
            (0x80, 0x80),
        ] {
            let want = run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "{c:#x} {d:#x}");
        }
    }

    #[test]
    fn frame_shifted_by_a_run_time_amount_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let fn1 = assemble_at(64, base + 0x1080, |a| {
            a.call(base + 0x1000)?;
            a.ret()
        });
        text_sec[0x80..0x80 + fn1.len()].copy_from_slice(&fn1);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // The frame goes `rdx & 0xf0` further down before the alignment, so its place
        // is known only at run time; then a VM exit has to rebuild it.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.mov(r9, rdx)?;
            a.and(r9, 0xf0)?;
            a.mov(rax, rsp)?;
            a.sub(rax, r9)?;
            a.sub(rax, 0x40)?;
            a.and(rax, -16)?;
            a.mov(rsp, rax)?;
            a.mov(qword_ptr(rsp + 0x10), rcx)?;
            a.mov(qword_ptr(rsp + 0x18), 0x77)?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
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
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for entry in [base + 0x1000, base + 0x1080] {
            for (c, d) in [(5u64, 0u64), (5, 0x20), (9, 0xf0), (0xdead_beef_0000_0001, 0x7f)] {
                let run = |pe: &[u8]| {
                    let s = Sample::from_bytes(pe).unwrap();
                    let mut eng = UnpackerEngine::new(s, "mem");
                    eng.init_uc().unwrap();
                    eng.call_function(entry, &[c, d], 100_000, 2_000).unwrap()
                };
                let want = c.wrapping_add(0x77).wrapping_add(if d & 0x20 != 0 { 2 } else { 1 });
                assert_eq!(run(&orig_pe), want, "original {entry:#x} {c:#x} {d:#x}");
                assert_eq!(run(&devirt_pe), want, "devirtualized {entry:#x} {c:#x} {d:#x}");
            }
        }
    }

    #[test]
    fn pushfq_after_logical_ops_is_computed_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // RFLAGS after `test rcx, rdx` and after `xor r8b, dl`, combined into rax.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(r11, rcx)?;
            for k in 0..40i32 {
                a.add(r11, k + 3)?;
                a.sub(r11, k + 3)?;
            }
            a.test(rcx, rdx)?;
            a.pushfq()?;
            a.pop(rax)?;
            a.mov(r8, rcx)?;
            a.xor(gpr8::r8b, gpr8::dl)?;
            a.pushfq()?;
            a.pop(r9)?;
            a.shl(r9, 32)?;
            a.xor(rax, r9)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for (c, d) in [(5u64, 5u64), (5, 2), (0x8000_0000_0000_0000, u64::MAX), (0, 7), (0x81, 0x80), (0xff, 0x0f)] {
            let want = run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want, "{c:#x} {d:#x}");
        }
    }

    #[test]
    fn entry_rflags_read_by_an_exit_that_overwrites_their_slot_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // r9 = the entry RFLAGS; the VM's own pushes sit where the recompiled code keeps
        // them (`StackBase - 8`), and the exit back to the VM writes those pushes.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.pushfq()?;
            a.pop(r9)?;
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rbp, rsp)?;
            a.and(rsp, -16)?;
            a.sub(rsp, 0x40)?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
                a.lea(rax, ptr(rax) + (k + 3))?;
                a.lea(rax, ptr(rax) - (k + 3))?;
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
                a.mov(rax, r9)?;
                a.and(rax, 0x8d5)?;
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
        const CF: u64 = 1;
        const ZF: u64 = 1 << 6;
        for (set, clear) in [(CF, ZF), (ZF, CF), (CF | ZF, 0), (0, CF | ZF)] {
            for d in [0u64, 0x20] {
                let want = run_with_flags(&orig_pe, base + 0x1000, 7, d, set, clear);
                assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, 7, d, set, clear), want, "{set:#x} {clear:#x} {d:#x}");
            }
        }
    }

    #[test]
    fn atomic_results_and_flags_come_from_the_instruction_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // [rdx] is a lock word: `lock cmpxchg` with rcx expected, a branch on ZF, the
        // old value from RAX; then `lock inc` / `lock or` and their flags via pushfq.
        // r12 = the entry RAX afterwards (it must survive the cmpxchg).
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut taken = a.create_label();
            let mut done = a.create_label();
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(r12, rax)?;
            for k in 0..40i32 {
                a.add(r12, k + 3)?;
                a.sub(r12, k + 3)?;
            }
            a.mov(r11, rax)?;
            a.mov(rax, rcx)?;
            a.mov(rbx, 0x77u64)?;
            a.lock().cmpxchg(qword_ptr(rdx), rbx)?;
            a.mov(r9, rax)?; // old value
            a.jz(taken)?;
            a.mov(r10, 1000u64)?;
            a.jmp(done)?;
            a.set_label(&mut taken)?;
            a.mov(r10, 2000u64)?;
            a.set_label(&mut done)?;
            a.lock().inc(dword_ptr(rdx + 8))?;
            a.pushfq()?;
            a.pop(r8)?;
            a.and(r8, 0x8d5)?;
            a.lock().or(qword_ptr(rdx + 16), rcx)?;
            a.pushfq()?;
            a.pop(rbx)?;
            a.and(rbx, 0x8d5)?;
            a.shl(rbx, 12)?;
            // rax = old + r10 + (inc flags << 32) + (or flags << 44) + r11 * 0 (kept)
            a.mov(rax, r8)?;
            a.shl(rax, 32)?;
            a.add(rax, r9)?;
            a.add(rax, r10)?;
            a.shl(rbx, 32)?;
            a.add(rax, rbx)?;
            a.sub(r11, r12)?; // 0 if RAX survived
            a.add(rax, r11)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        let run = |pe: &[u8], c: u64, lock_word: u64, counter: u32, bits: u64| -> (u64, [u8; 24]) {
            let s = Sample::from_bytes(pe).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            let p = base + 0x3000;
            {
                let uc = eng.unicorn_mut().unwrap();
                uc.mem_write(p, &lock_word.to_le_bytes()).unwrap();
                uc.mem_write(p + 8, &(counter as u64).to_le_bytes()).unwrap();
                uc.mem_write(p + 16, &bits.to_le_bytes()).unwrap();
                uc.reg_write(RegisterX86::RAX as i32, 0x5555).unwrap();
            }
            let r = eng.call_function(base + 0x1000, &[c, p], 100_000, 2_000).unwrap();
            let mut m = [0u8; 24];
            eng.unicorn_mut().unwrap().mem_read(p, &mut m).unwrap();
            (r, m)
        };
        for (c, lock_word, counter, bits) in [
            (0u64, 0u64, 0u32, 0u64),
            (0, 1, 0xffff_ffff, 0),
            (5, 5, 0x7fff_ffff, 0x8000_0000_0000_0000),
            (9, 5, 0x0f, 0),
        ] {
            let want = run(&orig_pe, c, lock_word, counter, bits);
            assert_eq!(run(&devirt_pe, c, lock_word, counter, bits), want, "{c:#x} {lock_word:#x} {counter:#x} {bits:#x}");
        }
    }

    #[test]
    fn mov_with_an_unmodelled_register_exits_back_to_vm_e2e() {
        use gpr64::*;
        use iced_x86::code_asm::registers::segment::ds;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // A segment register read mid-way (a control register in a driver): the
        // original runs it and the rest.
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(rax, rcx)?;
            for k in 0..40i32 {
                a.add(rax, k + 3)?;
                a.sub(rax, k + 3)?;
            }
            a.add(rax, rdx)?;
            a.mov(gpr16::r9w, ds)?;
            a.movzx(gpr32::r9d, gpr16::r9w)?;
            a.add(rax, r9)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        assert_eq!(report.hybrid_vm_exits, 1);
        for (c, d) in [(5u64, 7u64), (u64::MAX, 2)] {
            let want = run_with_flags(&orig_pe, base + 0x1000, c, d, 0, 0);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, c, d, 0, 0), want);
        }
    }

    #[test]
    fn cr8_read_before_a_later_cr8_write_keeps_its_value_e2e() {
        use gpr64::*;
        use iced_x86::code_asm::registers::cr::cr8;
        let base = 0x1_4000_0000u64;
        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| a.jmp(base + 0x2000));
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let exit_ret = assemble_at(64, base + 0x1040, |a| a.ret());
        text_sec[0x40..0x40 + exit_ret.len()].copy_from_slice(&exit_ret);
        let mut vmp_sec = vec![0xCCu8; 0x400];
        // The old IRQL read first, used after a raise in this block and after another
        // in a later block: it must be the value from before both.
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut skip = a.create_label();
            a.push(rbx)?;
            a.push(rbp)?;
            a.mov(r10, rcx)?;
            for k in 0..40i32 {
                a.add(r10, k + 3)?;
                a.sub(r10, k + 3)?;
            }
            a.mov(r8, cr8)?;
            a.mov(r9, 2u64)?;
            a.mov(cr8, r9)?;
            a.test(gpr8::dl, 1)?;
            a.jz(skip)?;
            a.mov(r9, 13u64)?;
            a.mov(cr8, r9)?;
            a.set_label(&mut skip)?;
            a.mov(rax, cr8)?;
            a.shl(rax, 8)?;
            a.add(rax, r8)?;
            a.mov(cr8, r8)?;
            a.pop(rbp)?;
            a.pop(rbx)?;
            a.jmp(base + 0x1040)
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);
        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.devirtualized_total, 1, "bailouts: {:?}", report.bailout_reasons);
        for d in [0u64, 1] {
            let want = run_with_flags(&orig_pe, base + 0x1000, 7, d, 0, 0);
            assert_eq!(run_with_flags(&devirt_pe, base + 0x1000, 7, d, 0, 0), want, "{d}");
        }
        // The emulator does not keep CR8 (reads give 0), so check the order in the code
        // itself: the old value is read before the first write.
        let site = &report.patched_sites[0];
        let s2 = Sample::from_bytes(&devirt_pe).unwrap();
        let mut eng = UnpackerEngine::new(s2, "mem");
        eng.init_uc().unwrap();
        // As much of the stub as is mapped.
        let mut len = 0x2000usize;
        let mut code = vec![0u8; len];
        while eng.unicorn_mut().unwrap().mem_read(base + site.stub_rva as u64, &mut code[..len]).is_err() {
            len /= 2;
            assert!(len >= 0x40, "stub not mapped");
        }
        code.truncate(len);
        let mut dec = Decoder::with_ip(64, &code, base + site.stub_rva as u64, DecoderOptions::NONE);
        let (mut first_read, mut first_write) = (None, None);
        for (i, ins) in (&mut dec).into_iter().take(2000).enumerate() {
            if ins.mnemonic() == Mnemonic::Mov && ins.op1_kind() == OpKind::Register && ins.op1_register() == Register::CR8 {
                first_read.get_or_insert(i);
            }
            if ins.mnemonic() == Mnemonic::Mov && ins.op0_kind() == OpKind::Register && ins.op0_register() == Register::CR8 {
                first_write.get_or_insert(i);
            }
        }
        assert!(
            matches!((first_read, first_write), (Some(r), Some(w)) if r < w),
            "read {first_read:?} write {first_write:?}"
        );
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

    #[test]
    fn redirected_oep_in_vm_section_and_chained_call_vmenter_e2e() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.mov(rax, rcx)?;
            a.push(rsi)?;
            a.call(base + 0x2000)?;
            a.add(rax, 100)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        // Chained call VM entry inside `.vmp0` + dummy OEP at 0x2400 so PE OEP
        // points into `.vmp0` instead of `.text`.
        let mut vmp_sec = vec![0xCCu8; 0x600];
        let stub_entry = assemble_at(64, base + 0x2000, |a| {
            a.pop(rsi)?;
            a.call(base + 0x2080)
        });
        vmp_sec[..stub_entry.len()].copy_from_slice(&stub_entry);

        let stub_body = assemble_at(64, base + 0x2080, |a| {
            a.pushfq()?;
            a.push(r10)?;
            a.xchg(qword_ptr(rsp + 24), rsi)?;
            for _ in 0..8 {
                a.lea(r10, ptr(rcx) - 1)?;
                a.imul_2(r10, rcx)?;
                a.and(r10, 1)?;
                a.add(rax, r10)?;
            }
            a.add(rax, 42)?;
            a.pop(r10)?;
            a.popfq()?;
            a.lea(rsp, ptr(rsp + 8))?;
            a.ret()
        });
        vmp_sec[0x80..0x80 + stub_body.len()].copy_from_slice(&stub_body);

        let fake_oep = assemble_at(64, base + 0x2400, |a| {
            a.xor(eax, eax)?;
            a.ret()
        });
        vmp_sec[0x400..0x400 + fake_oep.len()].copy_from_slice(&fake_oep);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x2400);
        let view = PeImageView::from_pe_bytes(&orig_pe).unwrap();
        assert!(view.is_in_primary_host(base + 0x1000), ".text must be primary host even when OEP is in .vmp0");
        assert!(view.is_in_vm_section(base + 0x2000), ".vmp0 must be VM section");

        let cfg = BinaryDevirtConfig::default();
        let entries = discover_vm_entries(&view, &cfg);
        assert_eq!(entries.len(), 1, "expected 1 chained-call VM entry, got {entries:?}");
        assert_eq!(entries[0].kind, VmEntryKind::CrossSectionVmEnter);

        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, cfg).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected chained-call VM entry devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], arg: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[arg], 100_000, 2_000).unwrap()
        };

        for x in [0u64, 7, 123, 0xdead_beef] {
            let expected = x.wrapping_add(42 + 100);
            assert_eq!(run_case(&orig_pe, x), expected);
            assert_eq!(run_case(&devirt_pe, x), expected);
        }
    }

    #[test]
    fn vmp_import_slot_dynamic_relift_and_computed_jmp_e2e() {
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let import_key = 0x3c6b_36e8u64;
        let slot_va = base + 0x2300;
        let api_va = base + 0x1080;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.call(base + 0x2000)?;
            a.db(&[0xCC])?;
            a.add(rax, 100)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let api_fn = assemble_at(64, api_va, |a| {
            a.lea(rax, ptr(rcx + 77))?;
            a.ret()
        });
        text_sec[0x80..0x80 + api_fn.len()].copy_from_slice(&api_fn);

        let mut vmp_sec = vec![0xCCu8; 0x600];
        // Pre-loader garbage non-executable slot inside `.vmp0`
        vmp_sec[0x300..0x308].copy_from_slice(&0x1a52_768e_5881_4227u64.to_le_bytes());

        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rdx)?;
            a.pushfq()?;
            a.add(qword_ptr(rsp + 16), 1)?;
            a.lea(rdx, ptr(rcx) - 1)?;
            a.imul_2(rdx, rcx)?;
            a.and(rdx, 1)?;
            a.mov(rdx, slot_va)?;
            a.mov(rdx, qword_ptr(rdx))?;
            a.add(rdx, import_key as i32)?;
            a.not(rdx)?;
            a.not(rdx)?;
            a.neg(rdx)?;
            a.neg(rdx)?;
            a.xchg(qword_ptr(rsp + 8), rdx)?;
            a.popfq()?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected VM import slot entry devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );
        assert_eq!(report.hybrid_vm_exits, 0, "got {report:?}");

        let patched_slot = api_va.wrapping_sub(import_key);
        let sentinel_rdx = 0x55AA_1234_5678_9ABCu64;

        let run_case = |pe_bytes: &[u8], arg: u64| -> (u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.unicorn_mut()
                .unwrap()
                .mem_write(slot_va, &patched_slot.to_le_bytes())
                .unwrap();
            let ret = eng
                .call_function(base + 0x1000, &[arg, sentinel_rdx], 100_000, 2_000)
                .unwrap();
            let rdx_after = eng.unicorn_mut().unwrap().reg_read(RegisterX86::RDX as i32).unwrap();
            (ret, rdx_after)
        };

        for x in [0u64, 5, 1234] {
            let expected = (x.wrapping_add(77 + 100), sentinel_rdx);
            assert_eq!(run_case(&orig_pe, x), expected);
            assert_eq!(run_case(&devirt_pe, x), expected);
        }
    }

    #[test]
    fn dead_setcc_cmov_cmc_rcr_junk_eliminated_e2e() {
        use gpr16::*;
        use gpr32::*;
        use gpr64::*;
        use gpr8::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.call(base + 0x2000)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rdx)?;
            a.push(r11)?;
            a.bt(rax, rcx)?;
            a.setle(dl)?;
            a.cmovl(r11w, r10w)?;
            a.cmc()?;
            a.rcr(r11, cl)?;
            a.mov(r11d, 0x81)?;
            a.stc()?;
            a.cmc()?;
            a.cmc()?;
            a.rcl(r11b, 1)?;
            a.movzx(r11d, r11b)?;
            a.adc(r11d, 10)?;
            a.lea(rax, ptr(rcx + r11 + 41))?;
            a.pop(r11)?;
            a.pop(rdx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected dead setcc/cmov/cmc/rcr stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );

        let run_case = |pe_bytes: &[u8], arg: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[arg], 100_000, 2_000).unwrap()
        };

        for x in [0u64, 1, 7, 42] {
            let expected = x.wrapping_add(55);
            assert_eq!(run_case(&orig_pe, x), expected);
            assert_eq!(run_case(&devirt_pe, x), expected);
        }
    }

    #[test]
    fn popfq_caller_slot_to_pushfq_and_bswap_rol_cwd_shrd16_cmovnp_e2e() {
        use gpr16::*;
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.cmp(ecx, 10)?;
            a.std()?;
            a.pushfq()?;
            a.cld()?;
            a.call(base + 0x2000)?;
            a.pop(r9)?;
            a.add(rax, r9)?;
            a.add(rax, rsi)?;
            a.add(rax, rdx)?;
            a.add(rax, r8)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(r10)?;
            a.push(r11)?;
            a.push(qword_ptr(rsp + 32))?;
            a.popfq()?;
            a.cld()?;
            a.pushfq()?;
            a.pop(rax)?;
            a.mov(qword_ptr(rsp + 32), rax)?;
            a.mov(r10d, 0xAA01)?;
            a.mov(r11d, 0xBB02)?;
            a.cmovnp(r10w, r11w)?;
            a.shl(r10, 16)?;
            a.rcr(r8, 1)?;
            a.add(r10, r8)?;
            a.shrd(bx, di, 0x1B)?;
            a.mov(eax, ecx)?;
            a.ror(ax, 5)?;
            a.rol(ax, 0x11)?;
            a.mov(edx, 0x1234_5678)?;
            a.cwd()?;
            a.mov(esi, ecx)?;
            a.add(esi, 0x1122_3344)?;
            a.bswap(esi)?;
            a.shl(rsi, 32)?;
            a.or(rsi, rcx)?;
            a.bswap(rsi)?;
            a.shl(rax, 32)?;
            a.or(rax, rdx)?;
            a.xor(rax, r10)?;
            a.pop(r11)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let cfg = BinaryDevirtConfig {
            max_code_growth_percent: 1500,
            ..BinaryDevirtConfig::default()
        };
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, cfg).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected Stage 3 patterns stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );
        assert!(report.bailout_reasons.is_empty(), "{:?}", report.bailout_reasons);

        let run_case = |pe_bytes: &[u8], x: u64, r8_seed: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[x, 0, r8_seed], 100_000, 2_000)
                .unwrap()
        };

        for (x, r8_seed) in [
            (5u64, 0x0123_4567_89AB_CDEFu64),
            (12u64, 0xFEDC_BA98_7654_3210u64),
            (0x0008_0008u64, 1u64),
            (0x0001_0010u64, 0x8000_0000_0000_0000u64),
        ] {
            let want = run_case(&orig_pe, x, r8_seed);
            let got = run_case(&devirt_pe, x, r8_seed);
            assert_eq!(got, want, "mismatch for x={x:#x} r8_seed={r8_seed:#x}");
        }
    }

    #[test]
    fn xadd_reg_self_alias_and_mem_flags_e2e() {
        use gpr16::*;
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.call(base + 0x2000)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(r10)?;
            a.push(r11)?;
            a.sub(rsp, 0x20)?;
            a.mov(r11d, ecx)?;
            a.mov(ebx, edx)?;
            a.xadd(r11d, ebx)?;
            a.mov(r10d, 0)?;
            a.adc(r10, 0)?;
            a.shl(r11, 1)?;
            a.xor(r11, rbx)?;
            a.shl(r10, 33)?;
            a.xor(r10, r11)?;
            a.xadd(r8w, r8w)?;
            a.xor(r10, r8)?;
            a.mov(qword_ptr(rsp + 8), rcx)?;
            a.lea(rax, ptr(rdx + 0x1234))?;
            a.xadd(qword_ptr(rsp + 8), rax)?;
            a.adc(rax, qword_ptr(rsp + 8))?;
            a.xor(rax, r10)?;
            a.add(rsp, 0x20)?;
            a.pop(r11)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected xadd stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );
        assert!(report.bailout_reasons.is_empty(), "{:?}", report.bailout_reasons);

        let run_case = |pe_bytes: &[u8], x: u64, y: u64, z: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[x, y, z], 100_000, 2_000)
                .unwrap()
        };

        for (x, y, z) in [
            (0x10u64, 0x20u64, 0xABCD_0001_0002_0003u64),
            (0xFFFF_FFF0u64, 0x20u64, 0x1234_5678_9ABC_8001u64),
            (u64::MAX - 5, 10u64, 0xFFFF_FFFF_FFFF_FFFFu64),
        ] {
            let want = run_case(&orig_pe, x, y, z);
            let got = run_case(&devirt_pe, x, y, z);
            assert_eq!(got, want, "mismatch for x={x:#x} y={y:#x} z={z:#x}");
        }
    }

    #[test]
    fn popfq_then_add_pushfq_preserves_caller_system_rflags_e2e() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.cmp(ecx, 10)?;
            a.std()?;
            a.pushfq()?;
            a.cld()?;
            a.sub(rsp, 8)?;
            a.call(base + 0x2000)?;
            a.pop(r9)?;
            a.pop(r8)?;
            a.shl(rax, 32)?;
            a.mov(ecx, r9d)?;
            a.or(rax, rcx)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            a.push(rbx)?;
            a.push(r10)?;
            a.push(r11)?;
            a.push(qword_ptr(rsp + 40))?;
            a.popfq()?;
            a.add(ecx, 0x25)?;
            a.and(ecx, 0xFF)?;
            a.pushfq()?;
            a.pop(rax)?;
            a.mov(qword_ptr(rsp + 32), rax)?;
            a.cld()?;
            a.mov(eax, ecx)?;
            a.add(eax, 0x100)?;
            a.pop(r11)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let cfg = BinaryDevirtConfig {
            max_code_growth_percent: 1500,
            ..BinaryDevirtConfig::default()
        };
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, cfg).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected popfq+add+pushfq stub devirtualized, bailouts: {:?}",
            report.bailout_reasons
        );
        assert!(report.bailout_reasons.is_empty(), "{:?}", report.bailout_reasons);

        let run_case = |pe_bytes: &[u8], x: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[x], 100_000, 2_000).unwrap()
        };

        for x in [5u64, 10, 0xDB, 0xFFFF_FFFF] {
            let want = run_case(&orig_pe, x);
            let got = run_case(&devirt_pe, x);
            assert_ne!(want & 0x400, 0, "expected DF=1 in composed RFLAGS for x={x:#x}");
            assert_eq!(got, want, "mismatch for x={x:#x}");
        }
    }

    #[test]
    fn dead_nonexec_ret_branch_falls_back_to_vm_exit_e2e() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;
        let slot_va = base + 0x2300;
        let api_va = base + 0x1080;
        let import_key = 0x12A_1180u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.call(base + 0x2000)?;
            a.add(rax, 100)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);
        let api_fn = assemble_at(64, api_va, |a| {
            a.lea(rax, ptr(rcx + 77))?;
            a.ret()
        });
        text_sec[0x80..0x80 + api_fn.len()].copy_from_slice(&api_fn);

        let mut vmp_sec = vec![0xCCu8; 0x600];
        vmp_sec[0x300..0x308].copy_from_slice(&0x1a52_768e_5881_4227u64.to_le_bytes());

        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut dead_lbl = a.create_label();
            a.push(rdx)?;
            a.pushfq()?;
            a.cmp(ecx, 0xDEAD)?;
            a.je(dead_lbl)?;
            for _ in 0..4 {
                a.lea(rdx, ptr(rcx) - 1)?;
                a.imul_2(rdx, rcx)?;
                a.and(rdx, 1)?;
            }
            a.mov(rdx, slot_va)?;
            a.mov(rdx, qword_ptr(rdx))?;
            a.add(rdx, import_key as i32)?;
            a.xchg(qword_ptr(rsp + 8), rdx)?;
            a.popfq()?;
            a.ret()?;
            a.set_label(&mut dead_lbl)?;
            a.zero_bytes()?;
            a.mov(rdx, 0x13FF0_0000u64)?;
            a.xchg(qword_ptr(rsp + 8), rdx)?;
            a.popfq()?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, BinaryDevirtConfig::default()).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected dead nonexec-ret stub devirtualized with ExitToVm fallback, bailouts: {:?}",
            report.bailout_reasons
        );
        assert_eq!(report.hybrid_vm_exits, 1, "expected 1 hybrid VM exit arm, got {report:?}");

        let patched_slot = api_va.wrapping_sub(import_key);
        let sentinel_rdx = 0x55AA_1234_5678_9ABCu64;

        let run_case = |pe_bytes: &[u8], arg: u64| -> (u64, u64) {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.unicorn_mut()
                .unwrap()
                .mem_write(slot_va, &patched_slot.to_le_bytes())
                .unwrap();
            let ret = eng
                .call_function(base + 0x1000, &[arg, sentinel_rdx], 100_000, 2_000)
                .unwrap();
            let rdx_after = eng.unicorn_mut().unwrap().reg_read(RegisterX86::RDX as i32).unwrap();
            (ret, rdx_after)
        };

        for x in [0u64, 5, 1234] {
            let expected = (x.wrapping_add(77 + 100), sentinel_rdx);
            assert_eq!(run_case(&orig_pe, x), expected);
            assert_eq!(run_case(&devirt_pe, x), expected);
        }
    }

    #[test]
    fn entry_rflags_branch_refines_flags_for_repeated_jcc_e2e() {
        use gpr32::*;
        use gpr64::*;
        let base = 0x1_4000_0000u64;

        let mut text_sec = vec![0xCCu8; 0x200];
        let fn0 = assemble_at(64, base + 0x1000, |a| {
            a.push(rdx)?;
            a.popfq()?;
            a.call(base + 0x2000)?;
            a.ret()
        });
        text_sec[..fn0.len()].copy_from_slice(&fn0);

        let mut vmp_sec = vec![0xCCu8; 0x400];
        let stub = assemble_at(64, base + 0x2000, |a| {
            let mut live_arm = a.create_label();
            let mut zf_arm = a.create_label();
            let mut zf_done = a.create_label();

            a.push(rbx)?;
            a.push(r10)?;
            a.mov(ebx, ecx)?;
            for _ in 0..6 {
                a.lea(rbx, ptr(rbx) + 1)?;
            }
            a.jns(live_arm)?;

            a.je(zf_arm)?;

            // SF == 1 && ZF == 0
            a.lea(eax, ptr(rcx) + 0x200)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()?;

            // SF == 1 && ZF == 1: redundant `je zf_done` must fold via path-refined ZF=1.
            a.set_label(&mut zf_arm)?;
            a.zero_bytes()?;
            a.not(rbx)?;
            a.not(rbx)?;
            a.je(zf_done)?;

            // Impossible fallthrough: would fail validation with `opaque_in_caller_store` if not folded.
            a.mov(rbx, 0x14000_1000u64)?;
            a.push(rbx)?;
            a.popfq()?;
            a.pushfq()?;
            a.pop(rbx)?;
            a.mov(qword_ptr(rsp + 16), rbx)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()?;

            a.set_label(&mut zf_done)?;
            a.zero_bytes()?;
            a.lea(eax, ptr(rcx) + 0x300)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()?;

            // SF == 0
            a.set_label(&mut live_arm)?;
            a.zero_bytes()?;
            a.lea(eax, ptr(rcx) + 0x100)?;
            a.pop(r10)?;
            a.pop(rbx)?;
            a.ret()
        });
        vmp_sec[..stub.len()].copy_from_slice(&stub);

        let orig_pe = build_two_exec_pe64(&text_sec, &vmp_sec, 0x1000);
        let dcfg = BinaryDevirtConfig {
            collect_diagnostics: true,
            ..BinaryDevirtConfig::default()
        };
        let (devirt_pe, report) = devirtualize_pe_bytes(&orig_pe, dcfg).unwrap();
        assert_eq!(report.discovered_vmenters, 1, "got {report:?}");
        assert_eq!(
            report.devirtualized_vmenters, 1,
            "expected repeated entry-flag branch stub devirtualized, bailouts: {:?}, samples: {:?}",
            report.bailout_reasons,
            report.bailout_samples
        );
        assert!(report.bailout_reasons.is_empty(), "{:?}", report.bailout_reasons);
        assert!(
            report.opaque_branches_folded >= 1,
            "expected redundant je folded, got {:?}",
            report.opaque_branches_folded
        );

        let run_case = |pe_bytes: &[u8], ecx_val: u64, rflags_val: u64| -> u64 {
            let s = Sample::from_bytes(pe_bytes).unwrap();
            let mut eng = UnpackerEngine::new(s, "mem");
            eng.init_uc().unwrap();
            eng.call_function(base + 0x1000, &[ecx_val, rflags_val], 100_000, 2_000)
                .unwrap()
        };

        for (x, rflags, want) in [
            (5u64, 0x202u64, 0x105u64), // SF=0, ZF=0
            (5u64, 0x242u64, 0x105u64), // SF=0, ZF=1
            (5u64, 0x282u64, 0x205u64), // SF=1, ZF=0
            (5u64, 0x2C2u64, 0x305u64), // SF=1, ZF=1
        ] {
            assert_eq!(run_case(&orig_pe, x, rflags), want, "orig mismatch for rflags={rflags:#x}");
            assert_eq!(run_case(&devirt_pe, x, rflags), want, "devirt mismatch for rflags={rflags:#x}");
        }
    }
}
