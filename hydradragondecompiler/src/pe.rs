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
struct CodeSection {
    /// File offset of the section's raw data.
    file_off: usize,
    /// Raw bytes of the section.
    bytes: Vec<u8>,
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
    known: &HashSet<String>,
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
            bytes: data[start..end].to_vec(),
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
                let mut reader = U8Reader::new(&section.bytes[offset..]);
                if let Ok(inst) = decoder.decode(&mut reader) {
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
        use yaxpeax_arch::{Decoder, U8Reader};
        let decoder = yaxpeax_arm::armv7::InstDecoder::default();
        for section in &sections {
            if !section.is_exec || section.bytes.is_empty() {
                continue;
            }
            let mut offset = 0;
            while offset + 2 <= section.bytes.len() {
                let mut reader = U8Reader::new(&section.bytes[offset..]);
                if let Ok(inst) = decoder.decode(&mut reader) {
                    if opts.code_refs {
                        let curr_va = section.va.wrapping_add(offset as u64);
                        arm32_code_ref(&inst, curr_va, data, &sections, min_len, known, &mut emitted, out);
                    }
                    offset += 4;
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

            let mut decoder =
                Decoder::with_ip(bitness, &section.bytes, section.va, DecoderOptions::NONE);

            let mut insns: Vec<Instruction> = Vec::new();
            while decoder.can_decode() {
                let mut insn = Instruction::default();
                decoder.decode_out(&mut insn);
                insns.push(insn);
            }

            if opts.code_refs {
                for insn in &insns {
                    code_ref_for_insn(
                        insn, data, &sections, min_len, known, &mut emitted, out,
                    );
                }
            }

            if opts.stack_strings {
                stack_strings_in_section(
                    &insns,
                    min_len,
                    known,
                    &mut emitted,
                    out,
                );
            }

            if opts.opcode_patterns {
                detect_opcode_patterns(&insns, &mut emitted, out);
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
    known: &HashSet<String>,
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
            if known.contains(&text) || !emitted.insert(text.clone()) {
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

/// Recover strings built on the stack via immediate-to-memory `mov` runs.
fn stack_strings_in_section(
    insns: &[Instruction],
    min_len: usize,
    known: &HashSet<String>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    let mut fragments: Vec<(Register, i64, u8)> = Vec::new();

    let flush = |frags: &mut Vec<(Register, i64, u8)>,
                 emitted: &mut HashSet<String>,
                 out: &mut Vec<ExtractedString>| {
        if frags.is_empty() {
            return;
        }
        reconstruct_stack_string(frags, min_len, known, emitted, out);
        frags.clear();
    };

    for insn in insns {
        if insn.mnemonic() != Mnemonic::Mov {
            flush(&mut fragments, emitted, out);
            continue;
        }

        if insn.op_count() != 2 || insn.op0_kind() != OpKind::Memory {
            flush(&mut fragments, emitted, out);
            continue;
        }

        let base = insn.memory_base();
        let index = insn.memory_index();
        if base == Register::None || index != Register::None {
            flush(&mut fragments, emitted, out);
            continue;
        }

        let (imm, width) = match insn.op1_kind() {
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64 => (insn.immediate8() as u64, 1),
            OpKind::Immediate16 => (insn.immediate16() as u64, 2),
            OpKind::Immediate32 | OpKind::Immediate32to64 => (insn.immediate32() as u64, 4),
            OpKind::Immediate64 => (insn.immediate64(), 8),
            _ => {
                flush(&mut fragments, emitted, out);
                continue;
            }
        };

        let mut all_printable = true;
        let mut bytes = [0u8; 8];
        for (i, slot) in bytes.iter_mut().enumerate().take(width) {
            *slot = ((imm >> (8 * i)) & 0xff) as u8;
            if !is_printable_ascii(*slot) {
                all_printable = false;
                break;
            }
        }
        if !all_printable {
            flush(&mut fragments, emitted, out);
            continue;
        }

        let disp = insn.memory_displacement64() as i64;
        for (i, &b) in bytes.iter().enumerate().take(width) {
            fragments.push((base, disp + i as i64, b));
        }
    }

    flush(&mut fragments, emitted, out);
}

/// Reconstruct one or more strings from collected `(base, disp, byte)` fragments.
fn reconstruct_stack_string(
    frags: &mut [(Register, i64, u8)],
    min_len: usize,
    known: &HashSet<String>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    frags.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

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
                Some(p) if disp == p + 1 => {
                    run.push(byte as char);
                }
                Some(_) => {
                    emit_stack_run(&run, min_len, known, emitted, out);
                    run.clear();
                    run.push(byte as char);
                }
                None => run.push(byte as char),
            }
            prev_disp = Some(disp);
            i += 1;
        }
        emit_stack_run(&run, min_len, known, emitted, out);
    }
}

/// Emit a reconstructed stack run if it is long enough and new.
fn emit_stack_run(
    run: &str,
    min_len: usize,
    known: &HashSet<String>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    if run.chars().count() < min_len {
        return;
    }
    let text = run.to_string();
    if known.contains(&text) || !emitted.insert(text.clone()) {
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
    known: &HashSet<String>,
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
                            if !known.contains(&text) && emitted.insert(text.clone()) {
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
    data: &[u8],
    sections: &[CodeSection],
    min_len: usize,
    known: &HashSet<String>,
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
                let target_va = (curr_va + 8).wrapping_add(disp as u64);
                if let Some(off) = va_to_file_off(target_va, sections, data.len()) {
                    if let Some((text, kind)) = decode_at(data, off, min_len) {
                        if !known.contains(&text) && emitted.insert(text.clone()) {
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
}

/// Detect characteristic or obfuscated opcode patterns (PEB lookup, direct syscalls, API hashing).
fn detect_opcode_patterns(
    insns: &[Instruction],
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    let mut i = 0;
    while i < insns.len() {
        let insn = &insns[i];

        // 1. PEB lookup: fs:[0x30] in x86 or gs:[0x60] in x64
        if insn.op_count() >= 2 && insn.op1_kind() == OpKind::Memory {
            let seg = insn.segment_prefix();
            let disp = insn.memory_displacement64();
            if (seg == Register::FS && (disp == 0x30 || disp == 0x18))
                || (seg == Register::GS && (disp == 0x60 || disp == 0x30))
            {
                let tag = "opc:peb_lookup".to_string();
                if emitted.insert(tag.clone()) {
                    out.push(ExtractedString {
                        text: tag,
                        kind: StringKind::OpcodePattern,
                        offset: Some(insn.ip() as usize),
                    });
                }
            }
        }

        // 2. Direct Syscall / Sysenter stub
        if insn.mnemonic() == Mnemonic::Syscall || insn.mnemonic() == Mnemonic::Sysenter {
            let tag = "opc:direct_syscall".to_string();
            if emitted.insert(tag.clone()) {
                out.push(ExtractedString {
                    text: tag,
                    kind: StringKind::OpcodePattern,
                    offset: Some(insn.ip() as usize),
                });
            }
        }

        // 3. API Hashing ROR/ROL loop
        if insn.mnemonic() == Mnemonic::Ror || insn.mnemonic() == Mnemonic::Rol {
            let end_look = (i + 4).min(insns.len());
            for next in &insns[i + 1..end_look] {
                if next.mnemonic() == Mnemonic::Add || next.mnemonic() == Mnemonic::Xor {
                    let tag = "opc:api_hash_ror".to_string();
                    if emitted.insert(tag.clone()) {
                        out.push(ExtractedString {
                            text: tag,
                            kind: StringKind::OpcodePattern,
                            offset: Some(insn.ip() as usize),
                        });
                    }
                    break;
                }
            }
        }

        i += 1;
    }
}


