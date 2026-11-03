//! Self-contained AArch64 (A64) decoder for `opcode_pattern` `arch: arm64`.
//!
//! Every instruction is one little-endian 32-bit word, so decoding never reads
//! past the word it is given. Covered: branches (B, BL, B.cond, CBZ/CBNZ,
//! TBZ/TBNZ, BR/BLR/RET), exceptions and hints (SVC, BRK, HLT, NOP, HINT,
//! MRS/MSR), data processing with immediates (ADR/ADRP, ADD/SUB, logical,
//! MOVZ/MOVN/MOVK, bitfield, EXTR) and registers (logical, ADD/SUB shifted and
//! extended, ADC/SBC, CCMP/CCMN, CSEL family, MADD/MSUB family, UDIV/SDIV and
//! variable shifts, RBIT/REV/CLZ/CLS), and integer loads / stores (literal,
//! pair, unsigned offset, pre/post-index, unscaled, register offset). Anything
//! else decodes as `unknown`. The common aliases are used (`mov`, `cmp`,
//! `cmn`, `tst`, `mvn`, `neg`, `mul`, `lsl`, `lsr`, `asr`, `ror`, `cset`).
//!
//! Operands are written lower case without spaces or `#`: registers `x0`,
//! `w1`, `sp`, `xzr`; immediates in hex (`0x10`, `-0x10`); memory `[x0]`,
//! `[x0,0x10]`, `[sp,-0x10]!` (a post-index offset is a separate immediate);
//! branch targets as absolute hex addresses.

/// How an instruction continues the control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    Jump(u64),
    CondJump(u64),
    Call(u64),
    /// Indirect branch or return: the block ends.
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Reg,
    Mem,
    Imm,
    Label,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    pub mnemonic: &'static str,
    pub ops: Vec<(String, OpKind)>,
    pub flow: Flow,
}

/// Every mnemonic the decoder emits (for pattern validation and ids), sorted.
pub const MNEMONICS: &[&str] = &[
    "adc", "adcs", "add", "adds", "adr", "adrp", "and", "ands", "asr", "b", "b.al", "b.eq", "b.ge", "b.gt", "b.hi",
    "b.hs", "b.le", "b.lo", "b.ls", "b.lt", "b.mi", "b.ne", "b.nv", "b.pl", "b.vc", "b.vs", "bfm", "bic", "bics", "bl",
    "blr", "br", "brk", "cbnz", "cbz", "ccmn", "ccmp", "cls", "clz", "cmn", "cmp", "csel", "cset", "csinc", "csinv",
    "csneg", "eon", "eor", "extr", "hint", "hlt", "hvc", "ldp", "ldpsw", "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh",
    "ldrsw", "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw", "lsl", "lsr", "madd", "mneg", "mov", "movk",
    "movn", "movz", "mrs", "msr", "msub", "mul", "mvn", "neg", "negs", "nop", "orn", "orr", "prfm", "rbit", "ret",
    "rev", "rev16", "rev32", "ror", "sbc", "sbcs", "sbfm", "sdiv", "sev", "smaddl", "smc", "smulh", "stp", "str",
    "strb", "strh", "stur", "sturb", "sturh", "sub", "subs", "svc", "sxtb", "sxth", "sxtw", "sys", "tbnz", "tbz", "tst",
    "ubfm", "udiv", "umaddl", "umulh", "unknown", "uxtb", "uxth", "wfe", "wfi", "yield",
];

/// Id of a mnemonic (index in [`MNEMONICS`]).
pub fn mnemonic_id(name: &str) -> u16 {
    MNEMONICS.binary_search(&name).map_or(unknown_id(), |i| i as u16)
}

pub fn unknown_id() -> u16 {
    MNEMONICS.binary_search(&"unknown").map_or(0, |i| i as u16)
}

fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

fn sext(v: u64, width: u32) -> i64 {
    let shift = 64 - width;
    ((v << shift) as i64) >> shift
}

fn hex(v: i64) -> String {
    if v < 0 { format!("-0x{:x}", v.unsigned_abs()) } else { format!("0x{v:x}") }
}

/// General register `n`: 31 is the stack pointer when `sp`, else the zero register.
fn reg(n: u32, wide: bool, sp: bool) -> (String, OpKind) {
    let text = match (n, wide, sp) {
        (31, true, true) => "sp".to_string(),
        (31, false, true) => "wsp".to_string(),
        (31, true, false) => "xzr".to_string(),
        (31, false, false) => "wzr".to_string(),
        (n, true, _) => format!("x{n}"),
        (n, false, _) => format!("w{n}"),
    };
    (text, OpKind::Reg)
}

fn imm(v: i64) -> (String, OpKind) {
    (hex(v), OpKind::Imm)
}

fn other(s: impl Into<String>) -> (String, OpKind) {
    (s.into(), OpKind::Other)
}

const CONDS: [&str; 16] = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];
const SHIFTS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];
const EXTENDS: [&str; 8] = ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"];

fn insn(mnemonic: &'static str, ops: Vec<(String, OpKind)>) -> Insn {
    Insn { mnemonic, ops, flow: Flow::Next }
}

fn unknown() -> Insn {
    insn("unknown", Vec::new())
}

/// Decode one instruction word at address `pc`.
pub fn decode(w: u32, pc: u64) -> Insn {
    match bits(w, 28, 25) {
        0b1000 | 0b1001 => dp_imm(w, pc),
        0b1010 | 0b1011 => branch_sys(w, pc),
        0b0100 | 0b0110 | 0b1100 | 0b1110 => load_store(w, pc),
        0b0101 | 0b1101 => dp_reg(w),
        _ => unknown(),
    }
}

/// ARM ARM `DecodeBitMasks` for logical immediates; None when reserved.
fn bitmask(n: u32, imms: u32, immr: u32, wide: bool) -> Option<u64> {
    let x = (n << 6) | (!imms & 0x3f);
    if x == 0 {
        return None;
    }
    let len = 31 - x.leading_zeros();
    if len < 1 || (!wide && n == 1) {
        return None;
    }
    let size = 1u32 << len;
    let levels = size - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let welem: u64 = if s + 1 == 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    let mask = if size == 64 { u64::MAX } else { (1u64 << size) - 1 };
    let rotated = if r == 0 { welem } else { ((welem >> r) | (welem << (size - r))) & mask };
    let mut out = 0u64;
    let mut at = 0;
    while at < 64 {
        out |= rotated << at;
        at += size;
    }
    Some(if wide { out } else { out & 0xffff_ffff })
}

fn dp_imm(w: u32, pc: u64) -> Insn {
    let sf = bits(w, 31, 31) == 1;
    let rd = bits(w, 4, 0);
    let rn = bits(w, 9, 5);
    match bits(w, 25, 23) {
        0b000 | 0b001 => {
            let imm = sext(u64::from((bits(w, 23, 5) << 2) | bits(w, 30, 29)), 21);
            if bits(w, 31, 31) == 0 {
                insn("adr", vec![reg(rd, true, false), (hex(pc.wrapping_add(imm as u64) as i64), OpKind::Label)])
            } else {
                let target = (pc & !0xfff).wrapping_add((imm << 12) as u64);
                insn("adrp", vec![reg(rd, true, false), (hex(target as i64), OpKind::Label)])
            }
        }
        0b010 => {
            let (op, s) = (bits(w, 30, 30), bits(w, 29, 29));
            let mut value = i64::from(bits(w, 21, 10));
            if bits(w, 22, 22) == 1 {
                value <<= 12;
            }
            let d = reg(rd, sf, s == 0);
            let n = reg(rn, sf, true);
            match (op, s) {
                (0, 0) if value == 0 && (rd == 31 || rn == 31) => insn("mov", vec![d, n]),
                (0, 1) if rd == 31 => insn("cmn", vec![n, imm(value)]),
                (1, 1) if rd == 31 => insn("cmp", vec![n, imm(value)]),
                _ => insn(["add", "adds", "sub", "subs"][(op * 2 + s) as usize], vec![d, n, imm(value)]),
            }
        }
        0b100 => {
            let opc = bits(w, 30, 29);
            let Some(v) = bitmask(bits(w, 22, 22), bits(w, 15, 10), bits(w, 21, 16), sf) else { return unknown() };
            let v = if sf { v as i64 } else { i64::from(v as u32) };
            let d = reg(rd, sf, opc != 3);
            let n = reg(rn, sf, false);
            match opc {
                1 if rn == 31 => insn("mov", vec![d, imm(v)]),
                3 if rd == 31 => insn("tst", vec![n, imm(v)]),
                _ => insn(["and", "orr", "eor", "ands"][opc as usize], vec![d, n, imm(v)]),
            }
        }
        0b101 => {
            let hw = bits(w, 22, 21);
            if !sf && hw > 1 {
                return unknown();
            }
            let value = u64::from(bits(w, 20, 5));
            let shift = hw * 16;
            let d = reg(rd, sf, false);
            match bits(w, 30, 29) {
                0 => {
                    let v = !(value << shift);
                    let v = if sf { v as i64 } else { i64::from(v as u32 as i32) };
                    insn("mov", vec![d, imm(v)])
                }
                2 => insn("mov", vec![d, imm((value << shift) as i64)]),
                3 => {
                    let mut ops = vec![d, imm(value as i64)];
                    if shift != 0 {
                        ops.push(other(format!("lsl{shift}")));
                    }
                    insn("movk", ops)
                }
                _ => unknown(),
            }
        }
        0b110 => {
            let opc = bits(w, 30, 29);
            let (immr, imms) = (bits(w, 21, 16), bits(w, 15, 10));
            let top = if sf { 63 } else { 31 };
            if (bits(w, 22, 22) == 1) != sf || immr > top || imms > top {
                return unknown();
            }
            let d = reg(rd, sf, false);
            let n = reg(rn, sf, false);
            match opc {
                0 if imms == top => insn("asr", vec![d, n, imm(i64::from(immr))]),
                0 if immr == 0 && matches!(imms, 7 | 15 | 31) => {
                    insn(match imms { 7 => "sxtb", 15 => "sxth", _ => "sxtw" }, vec![d, reg(rn, false, false)])
                }
                2 if imms == top => insn("lsr", vec![d, n, imm(i64::from(immr))]),
                2 if imms + 1 == immr => insn("lsl", vec![d, n, imm(i64::from(top - imms))]),
                2 if immr == 0 && matches!(imms, 7 | 15) && !sf => {
                    insn(if imms == 7 { "uxtb" } else { "uxth" }, vec![d, reg(rn, false, false)])
                }
                0..=2 => insn(["sbfm", "bfm", "ubfm"][opc as usize], vec![d, n, imm(i64::from(immr)), imm(i64::from(imms))]),
                _ => unknown(),
            }
        }
        _ => {
            if bits(w, 30, 29) != 0 || bits(w, 21, 21) != 0 {
                return unknown();
            }
            let rm = bits(w, 20, 16);
            let lsb = i64::from(bits(w, 15, 10));
            if rn == rm {
                insn("ror", vec![reg(rd, sf, false), reg(rn, sf, false), imm(lsb)])
            } else {
                insn("extr", vec![reg(rd, sf, false), reg(rn, sf, false), reg(rm, sf, false), imm(lsb)])
            }
        }
    }
}

fn branch_sys(w: u32, pc: u64) -> Insn {
    let target = |imm: i64| pc.wrapping_add(imm as u64);
    let label = |t: u64| (hex(t as i64), OpKind::Label);
    if bits(w, 30, 26) == 0b00101 {
        let t = target(sext(u64::from(bits(w, 25, 0)) << 2, 28));
        return if bits(w, 31, 31) == 0 {
            Insn { mnemonic: "b", ops: vec![label(t)], flow: Flow::Jump(t) }
        } else {
            Insn { mnemonic: "bl", ops: vec![label(t)], flow: Flow::Call(t) }
        };
    }
    if bits(w, 30, 25) == 0b011010 {
        let t = target(sext(u64::from(bits(w, 23, 5)) << 2, 21));
        let m = if bits(w, 24, 24) == 0 { "cbz" } else { "cbnz" };
        return Insn { mnemonic: m, ops: vec![reg(bits(w, 4, 0), bits(w, 31, 31) == 1, false), label(t)], flow: Flow::CondJump(t) };
    }
    if bits(w, 30, 25) == 0b011011 {
        let t = target(sext(u64::from(bits(w, 18, 5)) << 2, 16));
        let bit = (bits(w, 31, 31) << 5) | bits(w, 23, 19);
        let m = if bits(w, 24, 24) == 0 { "tbz" } else { "tbnz" };
        return Insn { mnemonic: m, ops: vec![reg(bits(w, 4, 0), bit >= 32, false), imm(i64::from(bit)), label(t)], flow: Flow::CondJump(t) };
    }
    if bits(w, 31, 24) == 0b0101_0100 && bits(w, 4, 4) == 0 {
        let t = target(sext(u64::from(bits(w, 23, 5)) << 2, 21));
        let m = ["b.eq", "b.ne", "b.hs", "b.lo", "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv"]
            [bits(w, 3, 0) as usize];
        let flow = if m == "b.al" { Flow::Jump(t) } else { Flow::CondJump(t) };
        return Insn { mnemonic: m, ops: vec![label(t)], flow };
    }
    if bits(w, 31, 24) == 0b1101_0100 {
        let code = imm(i64::from(bits(w, 20, 5)));
        let (m, flow) = match (bits(w, 23, 21), bits(w, 1, 0)) {
            (0, 1) => ("svc", Flow::Next),
            (0, 2) => ("hvc", Flow::Next),
            (0, 3) => ("smc", Flow::Next),
            (1, 0) => ("brk", Flow::End),
            (2, 0) => ("hlt", Flow::End),
            _ => return unknown(),
        };
        return Insn { mnemonic: m, ops: vec![code], flow };
    }
    if bits(w, 31, 22) == 0b11_0101_0100 {
        if w & 0xffff_f01f == 0xd503_201f {
            let m = match bits(w, 11, 5) {
                0 => "nop",
                1 => "yield",
                2 => "wfe",
                3 => "wfi",
                4 => "sev",
                _ => "hint",
            };
            let ops = if m == "hint" { vec![imm(i64::from(bits(w, 11, 5)))] } else { Vec::new() };
            return insn(m, ops);
        }
        let sysreg = other(format!("s{}_{}_c{}_c{}_{}", bits(w, 20, 19), bits(w, 18, 16), bits(w, 15, 12), bits(w, 11, 8), bits(w, 7, 5)));
        return match (bits(w, 21, 20), bits(w, 21, 21)) {
            (0b11, _) => insn("mrs", vec![reg(bits(w, 4, 0), true, false), sysreg]),
            (0b01, _) => insn("msr", vec![sysreg, reg(bits(w, 4, 0), true, false)]),
            _ => insn("sys", Vec::new()),
        };
    }
    if bits(w, 31, 25) == 0b110_1011 {
        let n = reg(bits(w, 9, 5), true, false);
        return match bits(w, 24, 21) {
            0 => Insn { mnemonic: "br", ops: vec![n], flow: Flow::End },
            1 => insn("blr", vec![n]),
            2 => Insn { mnemonic: "ret", ops: if bits(w, 9, 5) == 30 { Vec::new() } else { vec![n] }, flow: Flow::End },
            _ => Insn { mnemonic: "unknown", ops: Vec::new(), flow: Flow::End },
        };
    }
    unknown()
}

fn mem(base: u32, offset: i64, writeback: bool) -> (String, OpKind) {
    let b = reg(base, true, true).0;
    let text = match (offset, writeback) {
        (0, false) => format!("[{b}]"),
        (o, false) => format!("[{b},{}]", hex(o)),
        (o, true) => format!("[{b},{}]!", hex(o)),
    };
    (text, OpKind::Mem)
}

fn load_store(w: u32, pc: u64) -> Insn {
    if bits(w, 26, 26) == 1 {
        return unknown(); // SIMD & FP registers
    }
    let rt = bits(w, 4, 0);
    let rn = bits(w, 9, 5);
    // Load register (literal).
    if bits(w, 29, 27) == 0b011 && bits(w, 25, 24) == 0 {
        let t = pc.wrapping_add((sext(u64::from(bits(w, 23, 5)), 19) << 2) as u64);
        let label = (hex(t as i64), OpKind::Label);
        return match bits(w, 31, 30) {
            0 => insn("ldr", vec![reg(rt, false, false), label]),
            1 => insn("ldr", vec![reg(rt, true, false), label]),
            2 => insn("ldrsw", vec![reg(rt, true, false), label]),
            _ => insn("prfm", vec![imm(i64::from(rt)), label]),
        };
    }
    // Load / store pair.
    if bits(w, 29, 27) == 0b101 {
        let opc = bits(w, 31, 30);
        let load = bits(w, 22, 22) == 1;
        let (m, wide, scale) = match (opc, load) {
            (0, false) => ("stp", false, 2),
            (0, true) => ("ldp", false, 2),
            (1, true) => ("ldpsw", true, 2),
            (2, false) => ("stp", true, 3),
            (2, true) => ("ldp", true, 3),
            _ => return unknown(),
        };
        let off = sext(u64::from(bits(w, 21, 15)), 7) << scale;
        let (r1, r2) = (reg(rt, wide, false), reg(bits(w, 14, 10), wide, false));
        return match bits(w, 24, 23) {
            1 => insn(m, vec![r1, r2, mem(rn, 0, false), imm(off)]),
            3 => insn(m, vec![r1, r2, mem(rn, off, true)]),
            _ => insn(m, vec![r1, r2, mem(rn, off, false)]),
        };
    }
    if bits(w, 29, 27) != 0b111 {
        return unknown();
    }
    let size = bits(w, 31, 30);
    let opc = bits(w, 23, 22);
    // (store name, load name, signed-64 name, signed-32 name)
    let names: [(&str, &str); 4] = match size {
        0 => [("strb", "sturb"), ("ldrb", "ldurb"), ("ldrsb", "ldursb"), ("ldrsb", "ldursb")],
        1 => [("strh", "sturh"), ("ldrh", "ldurh"), ("ldrsh", "ldursh"), ("ldrsh", "ldursh")],
        2 => [("str", "stur"), ("ldr", "ldur"), ("ldrsw", "ldursw"), ("unknown", "unknown")],
        _ => [("str", "stur"), ("ldr", "ldur"), ("prfm", "prfm"), ("unknown", "unknown")],
    };
    let (normal, unscaled) = names[opc as usize];
    if normal == "unknown" {
        return unknown();
    }
    let wide = match opc {
        0 | 1 => size == 3,
        2 => true,
        _ => false,
    };
    let t = if normal == "prfm" { imm(i64::from(rt)) } else { reg(rt, wide, false) };
    if bits(w, 25, 24) == 1 {
        let off = i64::from(bits(w, 21, 10)) << size;
        return insn(normal, vec![t, mem(rn, off, false)]);
    }
    if bits(w, 25, 24) != 0 {
        return unknown();
    }
    if bits(w, 21, 21) == 1 {
        if bits(w, 11, 10) != 0b10 {
            return unknown();
        }
        let option = bits(w, 15, 13);
        let rm = reg(bits(w, 20, 16), option & 1 == 1, false).0;
        let base = reg(rn, true, true).0;
        let amount = if bits(w, 12, 12) == 1 { size } else { 0 };
        let text = match (option, amount) {
            (0b011, 0) => format!("[{base},{rm}]"),
            (0b011, a) => format!("[{base},{rm},lsl{a}]"),
            (o, 0) => format!("[{base},{rm},{}]", EXTENDS[o as usize]),
            (o, a) => format!("[{base},{rm},{}{a}]", EXTENDS[o as usize]),
        };
        return insn(normal, vec![t, (text, OpKind::Mem)]);
    }
    let off = sext(u64::from(bits(w, 20, 12)), 9);
    match bits(w, 11, 10) {
        0 => insn(unscaled, vec![t, mem(rn, off, false)]),
        1 => insn(normal, vec![t, mem(rn, 0, false), imm(off)]),
        3 => insn(normal, vec![t, mem(rn, off, true)]),
        _ => unknown(),
    }
}

fn dp_reg(w: u32) -> Insn {
    let sf = bits(w, 31, 31) == 1;
    let (rd, rn, rm) = (bits(w, 4, 0), bits(w, 9, 5), bits(w, 20, 16));
    let r = |n: u32| reg(n, sf, false);
    let shifted = |mut ops: Vec<(String, OpKind)>| {
        let amount = bits(w, 15, 10);
        if amount != 0 {
            ops.push(other(format!("{}{amount}", SHIFTS[bits(w, 23, 22) as usize])));
        }
        ops
    };
    match bits(w, 28, 24) {
        0b01010 => {
            let opc = bits(w, 30, 29);
            let n = bits(w, 21, 21);
            let m = ["and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"][(opc * 2 + n) as usize];
            match m {
                "orr" if rn == 31 && bits(w, 15, 10) == 0 => insn("mov", vec![r(rd), r(rm)]),
                "orn" if rn == 31 => insn("mvn", shifted(vec![r(rd), r(rm)])),
                "ands" if rd == 31 => insn("tst", shifted(vec![r(rn), r(rm)])),
                _ => insn(m, shifted(vec![r(rd), r(rn), r(rm)])),
            }
        }
        0b01011 => {
            let (op, s) = (bits(w, 30, 30), bits(w, 29, 29));
            let base = ["add", "adds", "sub", "subs"][(op * 2 + s) as usize];
            if bits(w, 21, 21) == 1 {
                // Extended register: Rd / Rn may be SP.
                let option = bits(w, 15, 13);
                let shift = bits(w, 12, 10);
                let ext = if shift == 0 { EXTENDS[option as usize].to_string() } else { format!("{}{shift}", EXTENDS[option as usize]) };
                let ops = vec![reg(rd, sf, s == 0), reg(rn, sf, true), reg(rm, option & 3 == 3, false), other(ext)];
                return insn(base, ops);
            }
            if bits(w, 23, 22) == 3 {
                return unknown();
            }
            match (op, s) {
                (1, 1) if rd == 31 => insn("cmp", shifted(vec![r(rn), r(rm)])),
                (0, 1) if rd == 31 => insn("cmn", shifted(vec![r(rn), r(rm)])),
                (1, 0) if rn == 31 => insn("neg", shifted(vec![r(rd), r(rm)])),
                (1, 1) if rn == 31 => insn("negs", shifted(vec![r(rd), r(rm)])),
                _ => insn(base, shifted(vec![r(rd), r(rn), r(rm)])),
            }
        }
        0b11011 => {
            let ra = bits(w, 14, 10);
            match (bits(w, 23, 21), bits(w, 15, 15)) {
                (0, 0) if ra == 31 => insn("mul", vec![r(rd), r(rn), r(rm)]),
                (0, 1) if ra == 31 => insn("mneg", vec![r(rd), r(rn), r(rm)]),
                (0, o) => insn(if o == 0 { "madd" } else { "msub" }, vec![r(rd), r(rn), r(rm), r(ra)]),
                (1, 0) if sf => insn("smaddl", vec![r(rd), reg(rn, false, false), reg(rm, false, false), r(ra)]),
                (2, 0) if sf => insn("smulh", vec![r(rd), r(rn), r(rm)]),
                (5, 0) if sf => insn("umaddl", vec![r(rd), reg(rn, false, false), reg(rm, false, false), r(ra)]),
                (6, 0) if sf => insn("umulh", vec![r(rd), r(rn), r(rm)]),
                _ => unknown(),
            }
        }
        0b11010 => match bits(w, 23, 21) {
            0 => insn(["adc", "adcs", "sbc", "sbcs"][(bits(w, 30, 30) * 2 + bits(w, 29, 29)) as usize], vec![r(rd), r(rn), r(rm)]),
            2 => {
                let m = if bits(w, 30, 30) == 0 { "ccmn" } else { "ccmp" };
                let second = if bits(w, 11, 11) == 1 { imm(i64::from(rm)) } else { r(rm) };
                insn(m, vec![r(rn), second, imm(i64::from(bits(w, 3, 0))), other(CONDS[bits(w, 15, 12) as usize])])
            }
            4 => {
                let cond = bits(w, 15, 12);
                match (bits(w, 30, 30), bits(w, 11, 10)) {
                    (0, 1) if rn == 31 && rm == 31 && cond < 14 => insn("cset", vec![r(rd), other(CONDS[(cond ^ 1) as usize])]),
                    (o, op2) if op2 < 2 => {
                        let m = ["csel", "csinc", "csinv", "csneg"][(o * 2 + op2) as usize];
                        insn(m, vec![r(rd), r(rn), r(rm), other(CONDS[cond as usize])])
                    }
                    _ => unknown(),
                }
            }
            6 => {
                let opcode = bits(w, 15, 10);
                if bits(w, 30, 30) == 0 {
                    let m = match opcode {
                        0b000010 => "udiv",
                        0b000011 => "sdiv",
                        0b001000 => "lsl",
                        0b001001 => "lsr",
                        0b001010 => "asr",
                        0b001011 => "ror",
                        _ => return unknown(),
                    };
                    insn(m, vec![r(rd), r(rn), r(rm)])
                } else {
                    let m = match (opcode, sf) {
                        (0, _) => "rbit",
                        (1, _) => "rev16",
                        (2, false) | (3, true) => "rev",
                        (2, true) => "rev32",
                        (4, _) => "clz",
                        (5, _) => "cls",
                        _ => return unknown(),
                    };
                    insn(m, vec![r(rd), r(rn)])
                }
            }
            _ => unknown(),
        },
        _ => unknown(),
    }
}

/// Text of an instruction (`mnemonic op, op`), for evidence.
pub fn format(i: &Insn) -> String {
    if i.ops.is_empty() {
        return i.mnemonic.to_string();
    }
    format!("{} {}", i.mnemonic, i.ops.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(w: u32, pc: u64) -> String {
        format(&decode(w, pc))
    }

    #[test]
    fn mnemonic_table_is_sorted_and_complete() {
        assert!(MNEMONICS.windows(2).all(|p| p[0] < p[1]));
        assert_ne!(mnemonic_id("stp"), unknown_id());
    }

    #[test]
    fn decodes_common_instructions() {
        for (w, want) in [
            (0xa9bf7bfd, "stp x29,x30,[sp,-0x10]!"),
            (0x910003fd, "mov x29,sp"),
            (0x39400008, "ldrb w8,[x0]"),
            (0x4a010108, "eor w8,w8,w1"),
            (0x38001408, "strb w8,[x0],0x1"),
            (0xf1000442, "subs x2,x2,0x1"),
            (0xa8c17bfd, "ldp x29,x30,[sp],0x10"),
            (0xd65f03c0, "ret"),
            (0xd503201f, "nop"),
            (0xaa0103e0, "mov x0,x1"),
            (0xd2800540, "mov x0,0x2a"),
            (0x12001c00, "and w0,w0,0xff"),
            (0xeb01001f, "cmp x0,x1"),
            (0xd4000001, "svc 0x0"),
            (0xf9400421, "ldr x1,[x1,0x8]"),
            (0xb8617800, "ldr w0,[x0,x1,lsl2]"),
            (0x1ac10800, "udiv w0,w0,w1"),
            (0x9b017c00, "mul x0,x0,x1"),
            (0xd37ff800, "lsl x0,x0,0x1"),
            (0x1a9f17e0, "cset w0,eq"),
            (0xf81f0fe0, "str x0,[sp,-0x10]!"),
            (0x00000000, "unknown"),
        ] {
            assert_eq!(text(w, 0x1000), want, "{w:08x}");
        }
    }

    #[test]
    fn branches_and_flow() {
        let b = decode(0x14000004, 0x1000);
        assert_eq!((format(&b).as_str(), b.flow), ("b 0x1010", Flow::Jump(0x1010)));
        let bl = decode(0x97ffffff, 0x1000);
        assert_eq!(bl.flow, Flow::Call(0xffc));
        let bne = decode(0x54ffff81, 0x1010);
        assert_eq!((bne.mnemonic, bne.flow), ("b.ne", Flow::CondJump(0x1000)));
        assert_eq!(decode(0xb4000040, 0x1000).flow, Flow::CondJump(0x1008));
        assert_eq!(decode(0x36000040, 0x1000).mnemonic, "tbz");
        assert_eq!(decode(0xd61f0200, 0).flow, Flow::End);
        assert_eq!(decode(0xd63f0200, 0).flow, Flow::Next);
        assert_eq!(decode(0xd4200000, 0).mnemonic, "brk");
        assert_eq!(text(0x90000000, 0x12345), "adrp x0,0x12000");
    }

    #[test]
    fn every_word_decodes_without_panicking() {
        let mut w = 0x9e37_79b9u32;
        for _ in 0..200_000 {
            w = w.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let i = decode(w, u64::MAX - 4);
            assert!(MNEMONICS.binary_search(&i.mnemonic).is_ok(), "{w:08x} {}", i.mnemonic);
        }
    }
}
