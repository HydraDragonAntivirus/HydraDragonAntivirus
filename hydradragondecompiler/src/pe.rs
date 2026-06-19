//! PE-aware passes: code-referenced strings and stack-built strings.
//!
//! Both passes disassemble the executable sections of a PE with capstone. The
//! whole module is best-effort: if goblin cannot parse the file as a PE, or
//! capstone cannot be built, we simply return without touching `out`, leaving the
//! ASCII/wide results from the linear scan untouched.

use std::collections::HashSet;

use capstone::Capstone;
use capstone::arch::ArchOperand;
use capstone::arch::BuildsCapstone;
use capstone::arch::x86::{ArchMode as X86Mode, X86OperandType};
use goblin::Object;

use crate::scan::decode_at;
use crate::{ExtractOptions, ExtractedString, StringKind};

/// A single executable section laid out so we can map virtual addresses back to
/// file offsets.
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
    // Parse only as PE; anything else (ELF, archive, raw) is out of scope here.
    let pe = match Object::parse(data) {
        Ok(Object::PE(pe)) => pe,
        _ => return,
    };

    let image_base = pe.image_base;

    // Pick bitness from the optional header magic / goblin's is_64 flag.
    let mode = if pe.is_64 {
        X86Mode::Mode64
    } else {
        X86Mode::Mode32
    };

    // Build capstone with detail enabled so operands are populated. Bail out
    // quietly on any failure.
    let cs = match Capstone::new().x86().mode(mode).detail(true).build() {
        Ok(cs) => cs,
        Err(_) => return,
    };

    // Collect every section that has raw data on disk. We disassemble the
    // executable ones, but a code reference usually points into .rdata/.data,
    // so all sections participate in virtual-address-to-file-offset mapping.
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
        let is_exec =
            section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
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

    // Track texts emitted by these passes so the two passes don't fight and we
    // don't re-emit something already in `known`.
    let mut emitted: HashSet<String> = HashSet::new();

    for section in &sections {
        if !section.is_exec {
            continue;
        }
        let insns = match cs.disasm_all(&section.bytes, section.va) {
            Ok(insns) => insns,
            Err(_) => continue,
        };

        if opts.code_refs {
            for insn in insns.iter() {
                code_ref_for_insn(
                    &cs, insn, section.va, data, &sections, min_len, known, &mut emitted, out,
                );
            }
        }

        if opts.stack_strings {
            stack_strings_in_section(
                &cs,
                &insns,
                min_len,
                known,
                &mut emitted,
                out,
            );
        }
    }
}

/// Inspect one instruction's memory operands for a reference to string data.
#[allow(clippy::too_many_arguments)]
fn code_ref_for_insn(
    cs: &Capstone,
    insn: &capstone::Insn,
    _section_va: u64,
    data: &[u8],
    sections: &[CodeSection],
    min_len: usize,
    known: &HashSet<String>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    let detail = match cs.insn_detail(insn) {
        Ok(d) => d,
        Err(_) => return,
    };

    for op in detail.arch_detail().operands() {
        let ArchOperand::X86Operand(x86) = op else {
            continue;
        };
        let X86OperandType::Mem(mem) = x86.op_type else {
            continue;
        };

        // We only resolve absolute and RIP-relative references; anything indexed
        // by a non-RIP base/index register is data-dependent and skipped.
        let base = mem.base();
        let index = mem.index();
        let disp = mem.disp();

        let target_va: Option<u64> = if base.0 == 0 && index.0 == 0 {
            // Absolute address: disp is the virtual address directly.
            if disp > 0 { Some(disp as u64) } else { None }
        } else if index.0 == 0 && is_rip(cs, base) {
            // RIP-relative: VA = address of next instruction + disp.
            let next = insn.address().wrapping_add(insn.bytes().len() as u64);
            Some(next.wrapping_add(disp as u64))
        } else {
            None
        };

        let Some(va) = target_va else { continue };

        // Map the VA back to a file offset inside one of our sections.
        let Some(off) = va_to_file_off(va, sections, data.len()) else {
            continue;
        };

        if let Some((text, kind)) = decode_at(data, off, min_len) {
            // Only emit as CodeRef if it isn't an exact text already found by the
            // plain ASCII/wide passes, and hasn't been emitted by us yet.
            if known.contains(&text) || !emitted.insert(text.clone()) {
                continue;
            }
            // Carry forward the underlying decode kind only for offset purposes;
            // the kind reported is CodeRef so callers know how it was found.
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
///
/// We look for consecutive `mov [reg +/- disp], imm` instructions whose
/// immediate bytes are printable, group them by base register, order them by
/// displacement, and reconstruct the byte sequence. Byte / word / dword
/// immediates are all handled.
fn stack_strings_in_section(
    cs: &Capstone,
    insns: &capstone::Instructions,
    min_len: usize,
    known: &HashSet<String>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    // (base register id, displacement) -> printable byte. We keep a flat list and
    // flush it whenever the moves stop being part of a string build.
    let mut fragments: Vec<(u16, i64, u8)> = Vec::new();

    let flush = |frags: &mut Vec<(u16, i64, u8)>,
                 emitted: &mut HashSet<String>,
                 out: &mut Vec<ExtractedString>| {
        if frags.is_empty() {
            return;
        }
        reconstruct_stack_string(frags, min_len, known, emitted, out);
        frags.clear();
    };

    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        if mnemonic != "mov" {
            // A non-mov breaks the current build; flush what we have.
            flush(&mut fragments, emitted, out);
            continue;
        }

        let detail = match cs.insn_detail(insn) {
            Ok(d) => d,
            Err(_) => {
                flush(&mut fragments, emitted, out);
                continue;
            }
        };
        let ops: Vec<ArchOperand> = detail.arch_detail().operands();
        if ops.len() != 2 {
            flush(&mut fragments, emitted, out);
            continue;
        }

        // Destination is operand 0, source is operand 1 for AT&T-style capstone
        // ordering used here (Intel syntax, dest first).
        let (ArchOperand::X86Operand(dst), ArchOperand::X86Operand(src)) =
            (ops[0].clone(), ops[1].clone())
        else {
            flush(&mut fragments, emitted, out);
            continue;
        };

        let (X86OperandType::Mem(mem), X86OperandType::Imm(imm)) =
            (dst.op_type, src.op_type)
        else {
            flush(&mut fragments, emitted, out);
            continue;
        };

        // Require a simple [base + disp] destination on the stack.
        let base = mem.base();
        if base.0 == 0 || mem.index().0 != 0 {
            flush(&mut fragments, emitted, out);
            continue;
        }

        // Spread the immediate over the operand's byte width and append each
        // printable byte at its displacement. Width is inferred from the
        // immediate magnitude, capped at 8 bytes.
        let width = imm_width(imm);
        let mut all_printable = true;
        let mut bytes = [0u8; 8];
        for (i, slot) in bytes.iter_mut().enumerate().take(width) {
            *slot = ((imm as u64) >> (8 * i)) as u8;
            if !crate::is_printable_ascii(*slot) {
                all_printable = false;
                break;
            }
        }
        if !all_printable {
            flush(&mut fragments, emitted, out);
            continue;
        }

        let disp = mem.disp();
        for (i, &b) in bytes.iter().enumerate().take(width) {
            fragments.push((base.0, disp + i as i64, b));
        }
    }

    flush(&mut fragments, emitted, out);
}

/// Reconstruct one or more strings from collected `(base, disp, byte)` fragments.
fn reconstruct_stack_string(
    frags: &mut [(u16, i64, u8)],
    min_len: usize,
    known: &HashSet<String>,
    emitted: &mut HashSet<String>,
    out: &mut Vec<ExtractedString>,
) {
    // Group by base register, then walk displacements in order; a gap of more
    // than one byte ends the current run.
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
                    // Duplicate write to the same slot; keep the later one.
                    run.pop();
                    run.push(byte as char);
                }
                Some(p) if disp == p + 1 => {
                    run.push(byte as char);
                }
                Some(_) => {
                    // Discontinuity: emit the run so far and start fresh.
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

/// Infer the byte width of an immediate from its magnitude (1, 2, 4, or 8).
fn imm_width(imm: i64) -> usize {
    let u = imm as u64;
    if u <= 0xff {
        1
    } else if u <= 0xffff {
        2
    } else if u <= 0xffff_ffff {
        4
    } else {
        8
    }
}

/// True if `reg` is the instruction pointer (rip/eip/ip) for RIP-relative refs.
fn is_rip(cs: &Capstone, reg: capstone::RegId) -> bool {
    matches!(
        cs.reg_name(reg).as_deref(),
        Some("rip") | Some("eip") | Some("ip")
    )
}

/// Map a virtual address back to a file offset, if it lands inside a known
/// executable or data range we captured. We search our executable sections; for
/// data sections we approximate by also accepting any VA that resolves within
/// the captured section bytes.
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
