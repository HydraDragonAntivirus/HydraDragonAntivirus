//! PE-aware passes: code-referenced strings and stack-built strings.
//!
//! Both passes disassemble the executable sections of a PE with iced-x86. The
//! whole module is best-effort: if pefile-rs cannot parse the file as a PE,
//! we simply return without touching `out`, leaving the ASCII/wide results from
//! the linear scan untouched.

use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use pefile_rs::PE;

use crate::scan::decode_at;
use crate::{ExtractOptions, ExtractedString, StringKind, is_printable_ascii};

/// A single section laid out so we can map virtual addresses back to file offsets.
struct CodeSection<'a> {
    /// File offset of the section's raw data.
    file_off: usize,
    /// Raw bytes of the section (borrowed from the file buffer).
    bytes: &'a [u8],
    /// Virtual address (RVA + image base) of the section start.
    va: u64,
    /// Whether this section is executable and should be disassembled.
    is_exec: bool,
}

/// Run the PE code-ref and stack-string passes, appending to `out`.
///
/// `known` is the set of plain ASCII/wide texts already found, used to dedup
/// code-ref hits that merely re-discover an existing run.
pub(crate) fn scan_pe(
    data: &[u8],
    opts: &ExtractOptions,
    min_len: usize,
    known: &HashSet<&str>,
    out: &mut Vec<ExtractedString>,
) {
    // Parse only as PE; anything else is out of scope here.
    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return,
    };

    let image_base = pe.optional_header.image_base;
    let bitness = if pe.is_64bit { 64 } else { 32 };

    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;

    let mut sections: Vec<CodeSection> = Vec::new();
    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start >= data.len() || size == 0 {
            continue;
        }
        let end = (start + size).min(data.len());
        let is_exec = section.is_executable()
            || (section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0);
        sections.push(CodeSection {
            file_off: start,
            bytes: &data[start..end],
            va: image_base.wrapping_add(section.virtual_address as u64),
            is_exec,
        });
    }

    if sections.is_empty() {
        return;
    }

    let mut emitted: HashSet<String> = HashSet::new();

    let is_arm32 = matches!(pe.file_header.machine, 0x01c0 | 0x01c2 | 0x01c4);
    let is_arm64 = pe.file_header.machine == 0xaa64;

    if is_arm64 {
        use yaxpeax_arch::{Decoder, U8Reader};
        let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
        for section in &sections {
            if !section.is_exec || section.bytes.is_empty() {
                continue;
            }
            let mut offset = 0;
            while offset + 4 <= section.bytes.len() {
                let slice = &section.bytes[offset..];
                let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut reader = U8Reader::new(slice);
                    decoder.decode(&mut reader)
                }));
                if let Ok(Ok(inst)) = decoded {
                    if opts.code_refs {
                        let curr_va = section.va.wrapping_add(offset as u64);
                        arm64_code_ref(&inst, curr_va, data, &sections, min_len, known, &mut emitted, out);
                    }
                    offset += 4;
                } else {
                    offset += 4;
                }
            }
        }
    } else if is_arm32 {
        use yaxpeax_arch::{Decoder, Reader, U8Reader};
        // Windows ARMNT (0x1c4) and THUMB (0x1c2) images are Thumb-2 code; only
        // 0x1c0 is A32. Decoding Thumb as A32 reads garbage.
        let thumb = pe.file_header.machine != 0x01c0;
        let decoder = if thumb {
            yaxpeax_arm::armv7::InstDecoder::default_thumb()
        } else {
            yaxpeax_arm::armv7::InstDecoder::default()
        };
        let step = if thumb { 2 } else { 4 };
        for section in &sections {
            if !section.is_exec || section.bytes.is_empty() {
                continue;
            }
            let mut offset = 0;
            while offset + step <= section.bytes.len() {
                let slice = &section.bytes[offset..];
                // yaxpeax-arm 0.5 panics on A32 LDRD/STRD with Rt = 15 (an
                // unpredictable encoding): treat it as undecodable instead of
                // unwinding (and printing a panic message) for every such word.
                if !thumb && a32_ldrd_strd_rt15(slice) {
                    offset += 2;
                    continue;
                }
                let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut reader = U8Reader::new(slice);
                    decoder
                        .decode(&mut reader)
                        .map(|inst| (inst, <U8Reader as Reader<u32, u8>>::total_offset(&mut reader) as usize))
                }));
                if let Ok(Ok((inst, len))) = decoded {
                    if opts.code_refs {
                        let curr_va = section.va.wrapping_add(offset as u64);
                        arm32_code_ref(&inst, curr_va, thumb, data, &sections, min_len, known, &mut emitted, out);
                    }
                    offset += if thumb { len.max(2) } else { 4 };
                } else {
                    offset += 2;
                }
            }
        }
    } else {
        for section in &sections {
            if !section.is_exec || section.bytes.is_empty() {
                continue;
            }

            // One decoding pass, nothing stored per instruction (a .NET or large
            // native image decodes to millions of instructions). Code references are
            // emitted as found; stack-string runs and opcode tags are collected and
            // emitted after the section, in the same order as separate passes would.
            let mut decoder =
                Decoder::with_ip(bitness, section.bytes, section.va, DecoderOptions::NONE);
            let mut insn = Instruction::default();
            let mut stack = StackStrings::default();
            let mut patterns = OpcodePatterns::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut insn);
                if opts.code_refs {
                    code_ref_for_insn(&insn, data, &sections, min_len, known, &mut emitted, out);
                }
                if opts.stack_strings {
                    stack.step(&insn, min_len);
                }
                if opts.opcode_patterns {
                    patterns.step(&insn);
                }
            }
            if opts.stack_strings {
                stack.finish(min_len);
                for run in stack.runs {
                    emit_stack_run(&run, min_len, known, &mut emitted, out);
                }
            }
            for (tag, offset) in patterns.tags {
                if emitted.insert(tag.to_string()) {
                    out.push(ExtractedString { text: tag.to_string(), kind: StringKind::OpcodePattern, offset: Some(offset) });
                }
            }
        }
    }
}

/// Inspect one instruction's memory operands for a reference to string data.
fn code_ref_for_insn(
    insn: &Instruction,
    data: &[u8],
    sections: &[CodeSection],
    min_len: usize,
    known: &HashSet<&str>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    let op_count = insn.op_count();
    for op_idx in 0..op_count {
        if insn.op_kind(op_idx) != OpKind::Memory {
            continue;
        }

        let target_va: Option<u64> = if insn.is_ip_rel_memory_operand() {
            Some(insn.ip_rel_memory_address())
        } else if insn.memory_base() == Register::None && insn.memory_index() == Register::None {
            let disp = insn.memory_displacement64();
            if disp > 0 {
                Some(disp)
            } else {
                None
            }
        } else {
            None
        };

        let Some(va) = target_va else { continue };

        let Some(off) = va_to_file_off(va, sections, data.len()) else {
            continue;
        };

        if let Some((text, kind)) = decode_at(data, off, min_len) {
            if known.contains(text.as_str()) || !emitted.insert(text.clone()) {
                continue;
            }
            let _ = kind;
            out.push(ExtractedString {
                text,
                kind: StringKind::CodeRef,
                offset: Some(off),
            });
        }
    }
}

/// Recovers strings built on the stack via immediate-to-memory `mov` runs, one
/// instruction at a time. `runs` collects the candidate texts (long enough) in order.
#[derive(Default)]
struct StackStrings {
    fragments: Vec<(Register, i64, u8)>,
    runs: Vec<String>,
}

impl StackStrings {
    fn step(&mut self, insn: &Instruction, min_len: usize) {
        if insn.mnemonic() != Mnemonic::Mov || insn.op_count() != 2 || insn.op0_kind() != OpKind::Memory {
            self.finish(min_len);
            return;
        }
        let base = insn.memory_base();
        if base == Register::None || insn.memory_index() != Register::None {
            self.finish(min_len);
            return;
        }
        let (imm, width) = match insn.op1_kind() {
            OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => (insn.immediate8() as u64, 1),
            OpKind::Immediate16 => (insn.immediate16() as u64, 2),
            OpKind::Immediate32 | OpKind::Immediate32to64 => (insn.immediate32() as u64, 4),
            OpKind::Immediate64 => (insn.immediate64(), 8),
            _ => {
                self.finish(min_len);
                return;
            }
        };
        let mut bytes = [0u8; 8];
        for (i, slot) in bytes.iter_mut().enumerate().take(width) {
            *slot = ((imm >> (8 * i)) & 0xff) as u8;
            if !is_printable_ascii(*slot) {
                self.finish(min_len);
                return;
            }
        }
        let disp = insn.memory_displacement64() as i64;
        for (i, &b) in bytes.iter().enumerate().take(width) {
            self.fragments.push((base, disp + i as i64, b));
        }
    }

    /// The end of a `mov` run: reconstruct its strings.
    fn finish(&mut self, min_len: usize) {
        if self.fragments.is_empty() {
            return;
        }
        let frags = &mut self.fragments;
        frags.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let push = |run: &str, runs: &mut Vec<String>| {
            if run.chars().count() >= min_len {
                runs.push(run.to_string());
            }
        };
        let mut i = 0;
        while i < frags.len() {
            let base = frags[i].0;
            let mut run = String::new();
            let mut prev_disp: Option<i64> = None;
            while i < frags.len() && frags[i].0 == base {
                let (_, disp, byte) = frags[i];
                match prev_disp {
                    Some(p) if disp == p => {
                        run.pop();
                        run.push(byte as char);
                    }
                    Some(p) if disp == p + 1 => run.push(byte as char),
                    Some(_) => {
                        push(&run, &mut self.runs);
                        run.clear();
                        run.push(byte as char);
                    }
                    None => run.push(byte as char),
                }
                prev_disp = Some(disp);
                i += 1;
            }
            push(&run, &mut self.runs);
        }
        frags.clear();
    }
}

/// Emit a reconstructed stack run if it is long enough and new.
fn emit_stack_run(
    run: &str,
    min_len: usize,
    known: &HashSet<&str>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    if run.chars().count() < min_len {
        return;
    }
    let text = run.to_string();
    if known.contains(text.as_str()) || !emitted.insert(text.clone()) {
        return;
    }
    out.push(ExtractedString {
        text,
        kind: StringKind::StackString,
        offset: None,
    });
}

/// Map a virtual address back to a file offset, if it lands inside a known section range.
fn va_to_file_off(va: u64, sections: &[CodeSection], data_len: usize) -> Option<usize> {
    for s in sections {
        let start = s.va;
        let end = s.va.wrapping_add(s.bytes.len() as u64);
        if va >= start && va < end {
            let rel = (va - start) as usize;
            let off = s.file_off + rel;
            if off < data_len {
                return Some(off);
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn arm64_code_ref(
    inst: &yaxpeax_arm::armv8::a64::Instruction,
    curr_va: u64,
    data: &[u8],
    sections: &[CodeSection],
    min_len: usize,
    known: &HashSet<&str>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    use yaxpeax_arm::armv8::a64::{Opcode, Operand};
    match inst.opcode {
        Opcode::LDR | Opcode::ADR | Opcode::ADRP => {
            for op in &[inst.operands[1], inst.operands[2]] {
                if let Operand::PCOffset(offset) = op {
                    let target_va = if inst.opcode == Opcode::ADRP {
                        ((curr_va & !0xfff) as i64).wrapping_add(*offset) as u64
                    } else {
                        (curr_va as i64).wrapping_add(*offset) as u64
                    };
                    if let Some(off) = va_to_file_off(target_va, sections, data.len()) {
                        if let Some((text, kind)) = decode_at(data, off, min_len) {
                            if !known.contains(text.as_str()) && emitted.insert(text.clone()) {
                                let _ = kind;
                                out.push(ExtractedString {
                                    text,
                                    kind: StringKind::CodeRef,
                                    offset: Some(off),
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn arm32_code_ref(
    inst: &yaxpeax_arm::armv7::Instruction,
    curr_va: u64,
    thumb: bool,
    data: &[u8],
    sections: &[CodeSection],
    min_len: usize,
    known: &HashSet<&str>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    use yaxpeax_arm::armv7::{Opcode, Operand};
    if inst.opcode == Opcode::LDR {
        for op in &[inst.operands[1], inst.operands[2]] {
            let offset_opt = match op {
                Operand::RegDerefPreindexOffset(reg, imm, add, _) if reg.number() == 15 => {
                    Some(if *add { *imm as i64 } else { -(*imm as i64) })
                }
                Operand::RegDerefPostindexOffset(reg, imm, add, _) if reg.number() == 15 => {
                    Some(if *add { *imm as i64 } else { -(*imm as i64) })
                }
                _ => None,
            };
            if let Some(disp) = offset_opt {
                // PC reads as the instruction + 8 in A32, and as the instruction + 4
                // aligned down to 4 for Thumb literal loads.
                let pc = if thumb { (curr_va + 4) & !3 } else { curr_va + 8 };
                let target_va = pc.wrapping_add(disp as u64);
                if let Some(off) = va_to_file_off(target_va, sections, data.len()) {
                    // The literal is usually the string's address (a literal pool
                    // entry), not the text itself: follow it once.
                    let found = decode_at(data, off, min_len).map(|t| (t, off)).or_else(|| {
                        let p = data.get(off..off + 4)?;
                        let ptr = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as u64;
                        let to = va_to_file_off(ptr, sections, data.len())?;
                        decode_at(data, to, min_len).map(|t| (t, to))
                    });
                    if let Some(((text, _kind), at)) = found {
                        if !known.contains(text.as_str()) && emitted.insert(text.clone()) {
                            out.push(ExtractedString {
                                text,
                                kind: StringKind::CodeRef,
                                offset: Some(at),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Characteristic or obfuscated opcode patterns (PEB lookup, direct syscalls, API
/// hashing), one instruction at a time. `tags` lists them in the order a pass over
/// the section in instruction order finds them (an API-hash ROR/ROL counts at its
/// own address when an ADD/XOR follows within 3 instructions).
#[derive(Default)]
struct OpcodePatterns {
    tags: Vec<(&'static str, usize)>,
    /// ROR/ROL instructions waiting for an ADD/XOR: (address, instructions left).
    pending_ror: Vec<(usize, u8)>,
}

impl OpcodePatterns {
    /// Only the first of each tag can be emitted (the text is the dedup key).
    fn push(&mut self, (tag, ip): (&'static str, usize)) {
        if !self.tags.iter().any(|t| t.0 == tag) {
            self.tags.push((tag, ip));
        }
    }

    fn step(&mut self, insn: &Instruction) {
        let m = insn.mnemonic();
        // A ROR/ROL before this one, with this instruction in its window.
        if !self.pending_ror.is_empty() {
            if m == Mnemonic::Add || m == Mnemonic::Xor {
                let ip = self.pending_ror[0].0;
                self.push(("opc:api_hash_ror", ip));
                self.pending_ror.remove(0);
            }
            for p in &mut self.pending_ror {
                p.1 -= 1;
            }
            self.pending_ror.retain(|p| p.1 > 0);
        }
        // 1. PEB lookup: fs:[0x30] in x86 or gs:[0x60] in x64
        if insn.op_count() >= 2 && insn.op1_kind() == OpKind::Memory {
            let seg = insn.segment_prefix();
            let disp = insn.memory_displacement64();
            if (seg == Register::FS && (disp == 0x30 || disp == 0x18)) || (seg == Register::GS && (disp == 0x60 || disp == 0x30)) {
                self.push(("opc:peb_lookup", insn.ip() as usize));
            }
        }
        // 2. Direct Syscall / Sysenter stub
        if m == Mnemonic::Syscall || m == Mnemonic::Sysenter {
            self.push(("opc:direct_syscall", insn.ip() as usize));
        }
        // 3. API Hashing ROR/ROL loop
        if m == Mnemonic::Ror || m == Mnemonic::Rol {
            self.pending_ror.push((insn.ip() as usize, 3));
        }
    }
}

/// A32 LDRD / STRD (register or immediate) with Rt = 15, outside the unconditional
/// space: yaxpeax-arm 0.5 panics on these ("register number out of range" for Rt+1).
fn a32_ldrd_strd_rt15(bytes: &[u8]) -> bool {
    let Some(w) = bytes.get(..4) else { return false };
    let w = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    (w & 0x0e10_00d0) == 0x0000_00d0 && (w >> 12) & 0xf == 15 && w >> 28 != 0xf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a32_ldrd_rt15_is_recognised() {
        // ldrd r15, [r0, #0] (cond AL): yaxpeax-arm 0.5 panics on this word
        assert!(a32_ldrd_strd_rt15(&0xe1c0_f0d0u32.to_le_bytes()));
        // strd r15, [r0, r1]
        assert!(a32_ldrd_strd_rt15(&0xe180_f0f1u32.to_le_bytes()));
        // ldrd r2, [r0] and the unconditional space are not
        assert!(!a32_ldrd_strd_rt15(&0xe1c0_20d0u32.to_le_bytes()));
        assert!(!a32_ldrd_strd_rt15(&0xf1c0_f0d0u32.to_le_bytes()));
        assert!(!a32_ldrd_strd_rt15(&[0xd0, 0xf0]));
    }
}
