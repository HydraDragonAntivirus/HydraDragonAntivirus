//! Interned symbolic Expression DAG, algebraic/MBA/opaque-predicate simplifier,
//! and lossless symbolic stack model for x86/x64 VM devirtualization.

use std::collections::{HashMap, HashSet};

use iced_x86::Register;

/// Architectural x86/x64 general-purpose registers canonicalized to their 64-bit parent slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ArchReg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegSlice {
    Full64,
    Low32,
    Low16,
    Low8,
    High8,
}

impl ArchReg {
    pub const ALL: [ArchReg; 16] = [
        ArchReg::Rax,
        ArchReg::Rcx,
        ArchReg::Rdx,
        ArchReg::Rbx,
        ArchReg::Rsp,
        ArchReg::Rbp,
        ArchReg::Rsi,
        ArchReg::Rdi,
        ArchReg::R8,
        ArchReg::R9,
        ArchReg::R10,
        ArchReg::R11,
        ArchReg::R12,
        ArchReg::R13,
        ArchReg::R14,
        ArchReg::R15,
    ];

    #[inline]
    pub fn idx(self) -> usize {
        self as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ArchReg::Rax => "rax",
            ArchReg::Rcx => "rcx",
            ArchReg::Rdx => "rdx",
            ArchReg::Rbx => "rbx",
            ArchReg::Rsp => "rsp",
            ArchReg::Rbp => "rbp",
            ArchReg::Rsi => "rsi",
            ArchReg::Rdi => "rdi",
            ArchReg::R8 => "r8",
            ArchReg::R9 => "r9",
            ArchReg::R10 => "r10",
            ArchReg::R11 => "r11",
            ArchReg::R12 => "r12",
            ArchReg::R13 => "r13",
            ArchReg::R14 => "r14",
            ArchReg::R15 => "r15",
        }
    }

    pub fn from_iced(reg: Register) -> Option<(ArchReg, RegSlice)> {
        use ArchReg::*;
        use RegSlice::*;
        Some(match reg {
            Register::RAX => (Rax, Full64),
            Register::EAX => (Rax, Low32),
            Register::AX => (Rax, Low16),
            Register::AL => (Rax, Low8),
            Register::AH => (Rax, High8),

            Register::RCX => (Rcx, Full64),
            Register::ECX => (Rcx, Low32),
            Register::CX => (Rcx, Low16),
            Register::CL => (Rcx, Low8),
            Register::CH => (Rcx, High8),

            Register::RDX => (Rdx, Full64),
            Register::EDX => (Rdx, Low32),
            Register::DX => (Rdx, Low16),
            Register::DL => (Rdx, Low8),
            Register::DH => (Rdx, High8),

            Register::RBX => (Rbx, Full64),
            Register::EBX => (Rbx, Low32),
            Register::BX => (Rbx, Low16),
            Register::BL => (Rbx, Low8),
            Register::BH => (Rbx, High8),

            Register::RSP => (Rsp, Full64),
            Register::ESP => (Rsp, Low32),
            Register::SP => (Rsp, Low16),
            Register::SPL => (Rsp, Low8),

            Register::RBP => (Rbp, Full64),
            Register::EBP => (Rbp, Low32),
            Register::BP => (Rbp, Low16),
            Register::BPL => (Rbp, Low8),

            Register::RSI => (Rsi, Full64),
            Register::ESI => (Rsi, Low32),
            Register::SI => (Rsi, Low16),
            Register::SIL => (Rsi, Low8),

            Register::RDI => (Rdi, Full64),
            Register::EDI => (Rdi, Low32),
            Register::DI => (Rdi, Low16),
            Register::DIL => (Rdi, Low8),

            Register::R8 => (R8, Full64),
            Register::R8D => (R8, Low32),
            Register::R8W => (R8, Low16),
            Register::R8L => (R8, Low8),

            Register::R9 => (R9, Full64),
            Register::R9D => (R9, Low32),
            Register::R9W => (R9, Low16),
            Register::R9L => (R9, Low8),

            Register::R10 => (R10, Full64),
            Register::R10D => (R10, Low32),
            Register::R10W => (R10, Low16),
            Register::R10L => (R10, Low8),

            Register::R11 => (R11, Full64),
            Register::R11D => (R11, Low32),
            Register::R11W => (R11, Low16),
            Register::R11L => (R11, Low8),

            Register::R12 => (R12, Full64),
            Register::R12D => (R12, Low32),
            Register::R12W => (R12, Low16),
            Register::R12L => (R12, Low8),

            Register::R13 => (R13, Full64),
            Register::R13D => (R13, Low32),
            Register::R13W => (R13, Low16),
            Register::R13L => (R13, Low8),

            Register::R14 => (R14, Full64),
            Register::R14D => (R14, Low32),
            Register::R14W => (R14, Low16),
            Register::R14L => (R14, Low8),

            Register::R15 => (R15, Full64),
            Register::R15D => (R15, Low32),
            Register::R15W => (R15, Low16),
            Register::R15L => (R15, Low8),

            _ => return None,
        })
    }

    pub fn xmm_index(reg: Register) -> Option<u8> {
        match reg {
            Register::XMM0 => Some(0),
            Register::XMM1 => Some(1),
            Register::XMM2 => Some(2),
            Register::XMM3 => Some(3),
            Register::XMM4 => Some(4),
            Register::XMM5 => Some(5),
            Register::XMM6 => Some(6),
            Register::XMM7 => Some(7),
            Register::XMM8 => Some(8),
            Register::XMM9 => Some(9),
            Register::XMM10 => Some(10),
            Register::XMM11 => Some(11),
            Register::XMM12 => Some(12),
            Register::XMM13 => Some(13),
            Register::XMM14 => Some(14),
            Register::XMM15 => Some(15),
            _ => None,
        }
    }

    pub fn slice_bits(slice: RegSlice) -> u8 {
        match slice {
            RegSlice::Full64 => 64,
            RegSlice::Low32 => 32,
            RegSlice::Low16 => 16,
            RegSlice::Low8 | RegSlice::High8 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CondPred {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

impl CondPred {
    /// The predicate that holds for swapped operands: `a < b` is `b > a`.
    pub fn swap_operands(self) -> Self {
        match self {
            CondPred::Eq => CondPred::Eq,
            CondPred::Ne => CondPred::Ne,
            CondPred::Ult => CondPred::Ugt,
            CondPred::Ule => CondPred::Uge,
            CondPred::Ugt => CondPred::Ult,
            CondPred::Uge => CondPred::Ule,
            CondPred::Slt => CondPred::Sgt,
            CondPred::Sle => CondPred::Sge,
            CondPred::Sgt => CondPred::Slt,
            CondPred::Sge => CondPred::Sle,
        }
    }

    pub fn invert(self) -> Self {
        match self {
            CondPred::Eq => CondPred::Ne,
            CondPred::Ne => CondPred::Eq,
            CondPred::Ult => CondPred::Uge,
            CondPred::Ule => CondPred::Ugt,
            CondPred::Ugt => CondPred::Ule,
            CondPred::Uge => CondPred::Ult,
            CondPred::Slt => CondPred::Sge,
            CondPred::Sle => CondPred::Sgt,
            CondPred::Sgt => CondPred::Sle,
            CondPred::Sge => CondPred::Slt,
        }
    }

    pub fn eval(self, a: u64, b: u64) -> bool {
        match self {
            CondPred::Eq => a == b,
            CondPred::Ne => a != b,
            CondPred::Ult => a < b,
            CondPred::Ule => a <= b,
            CondPred::Ugt => a > b,
            CondPred::Uge => a >= b,
            CondPred::Slt => (a as i64) < (b as i64),
            CondPred::Sle => (a as i64) <= (b as i64),
            CondPred::Sgt => (a as i64) > (b as i64),
            CondPred::Sge => (a as i64) >= (b as i64),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExprId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackSpace {
    CallerStack,
    AlignedScratch(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExprNode {
    Const(u64),
    RegIn(ArchReg),
    XmmIn(u8, bool),
    StackBase,
    AlignedBase(u32),
    /// RFLAGS as they were when the lifted code was entered (what a `pushfq` stores
    /// before anything changed the flags). The recompiled code saves them on entry.
    EntryRflags,
    CallRet { call_id: u32, reg: ArchReg },
    Load { addr: ExprId, width: u8, mem_ver: u32 },
    Add(ExprId, ExprId),
    Sub(ExprId, ExprId),
    Mul(ExprId, ExprId),
    And(ExprId, ExprId),
    Or(ExprId, ExprId),
    Xor(ExprId, ExprId),
    Shl(ExprId, ExprId),
    Shr(ExprId, ExprId),
    Sar(ExprId, ExprId),
    Rol(ExprId, ExprId),
    Ror(ExprId, ExprId),
    /// High 64 bits of the 128-bit unsigned product (`mul r/m64` -> RDX).
    MulHiU(ExprId, ExprId),
    /// High 64 bits of the 128-bit signed product (`imul r/m64` -> RDX).
    MulHiS(ExprId, ExprId),
    Not(ExprId),
    Neg(ExprId),
    SExt { val: ExprId, from_bits: u8 },
    Cmp { pred: CondPred, lhs: ExprId, rhs: ExprId },
    Select { cond: ExprId, if_true: ExprId, if_false: ExprId },
    EntryFlag(u8),
    Cr8Read(u32),
    Opaque(u32),
}

#[derive(Debug, Clone)]
pub struct ExprArena {
    nodes: Vec<ExprNode>,
    intern: HashMap<ExprNode, ExprId>,
    next_opaque: u32,
    max_nodes: usize,
    select_dist_depth: u8,
    /// What each `AlignedBase(id)` is: `(parent, off, mask)`, RSP = `parent + off`
    /// then `and rsp, mask`. Ids are per path, so one id may mean different frames on
    /// different paths: `None` then.
    aligned_defs: HashMap<u32, Option<(StackSpace, i64, u64)>>,
}

impl Default for ExprArena {
    fn default() -> Self {
        Self::new(32_768)
    }
}

#[inline]
pub fn width_mask(width_bytes: u8) -> u64 {
    match width_bytes {
        0 => 0,
        1..=7 => (1u64 << (width_bytes * 8)) - 1,
        _ => u64::MAX,
    }
}

#[inline]
pub fn sign_extend_u64(val: u64, from_bits: u8) -> u64 {
    match from_bits {
        8 => (val as u8 as i8 as i64) as u64,
        16 => (val as u16 as i16 as i64) as u64,
        32 => (val as u32 as i32 as i64) as u64,
        _ => val,
    }
}

impl ExprArena {
    pub fn new(max_nodes: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(256),
            intern: HashMap::with_capacity(256),
            next_opaque: 0,
            max_nodes: max_nodes.max(256),
            select_dist_depth: 0,
            aligned_defs: HashMap::new(),
        }
    }

    #[inline]
    pub fn get(&self, id: ExprId) -> &ExprNode {
        &self.nodes[id.0 as usize]
    }

    #[inline]
    pub fn as_const(&self, id: ExprId) -> Option<u64> {
        match self.get(id) {
            ExprNode::Const(v) => Some(*v),
            _ => None,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    fn intern_node(&mut self, node: ExprNode) -> ExprId {
        if let Some(&id) = self.intern.get(&node) {
            return id;
        }
        if !matches!(
            node,
            ExprNode::Const(_)
                | ExprNode::RegIn(_)
                | ExprNode::XmmIn(_, _)
                | ExprNode::StackBase
                | ExprNode::EntryRflags
                | ExprNode::AlignedBase(_)
                | ExprNode::EntryFlag(_)
                | ExprNode::Cr8Read(_)
                | ExprNode::Opaque(_)
        ) && self.nodes.len() >= self.max_nodes
        {
            return self.opaque();
        }
        let id = ExprId(self.nodes.len() as u32);
        self.intern.insert(node.clone(), id);
        self.nodes.push(node);
        id
    }

    pub fn const_u64(&mut self, v: u64) -> ExprId {
        self.intern_node(ExprNode::Const(v))
    }

    pub fn reg_in(&mut self, r: ArchReg) -> ExprId {
        self.intern_node(ExprNode::RegIn(r))
    }

    pub fn xmm_in(&mut self, idx: u8, is_hi64: bool) -> ExprId {
        self.intern_node(ExprNode::XmmIn(idx, is_hi64))
    }

    pub fn stack_base(&mut self) -> ExprId {
        self.intern_node(ExprNode::StackBase)
    }

    pub fn entry_rflags(&mut self) -> ExprId {
        self.intern_node(ExprNode::EntryRflags)
    }

    /// Records how `AlignedBase(id)` was made on some path (see `aligned_defs`).
    pub fn note_aligned_def(&mut self, id: u32, def: (StackSpace, i64, u64)) {
        let e = self.aligned_defs.entry(id).or_insert(Some(def));
        if *e != Some(def) {
            *e = None;
        }
    }

    /// How `AlignedBase(id)` was made, when every path agrees.
    pub fn aligned_def(&self, id: u32) -> Option<(StackSpace, i64, u64)> {
        self.aligned_defs.get(&id).copied().flatten()
    }

    pub fn aligned_base(&mut self, id: u32) -> ExprId {
        self.intern_node(ExprNode::AlignedBase(id))
    }

    pub fn entry_flag(&mut self, cc: u8) -> ExprId {
        self.intern_node(ExprNode::EntryFlag(cc))
    }

    pub fn cr8_read(&mut self, ver: u32) -> ExprId {
        self.intern_node(ExprNode::Cr8Read(ver))
    }

    pub fn call_ret(&mut self, call_id: u32, reg: ArchReg) -> ExprId {
        self.intern_node(ExprNode::CallRet { call_id, reg })
    }

    pub fn opaque(&mut self) -> ExprId {
        let oid = self.next_opaque;
        self.next_opaque += 1;
        let node = ExprNode::Opaque(oid);
        let id = ExprId(self.nodes.len() as u32);
        self.intern.insert(node.clone(), id);
        self.nodes.push(node);
        id
    }

    pub fn load(&mut self, addr: ExprId, width: u8, mem_ver: u32) -> ExprId {
        self.intern_node(ExprNode::Load {
            addr,
            width,
            mem_ver,
        })
    }

    pub fn load_stack(&mut self, off: i64, width: u8, mem_ver: u32) -> ExprId {
        let sb = self.stack_base();
        let addr = self.add_signed(sb, off);
        self.load(addr, width, mem_ver)
    }

    #[inline]
    fn order_pair(&self, a: ExprId, b: ExprId) -> (ExprId, ExprId) {
        match (self.as_const(a), self.as_const(b)) {
            (Some(_), None) => (b, a),
            (None, Some(_)) => (a, b),
            _ if a.0 <= b.0 => (a, b),
            _ => (b, a),
        }
    }

    /// Computes conservative bit-level knowledge `(known_zeros, known_ones)` for an expression.
    pub fn known_bits(&self, id: ExprId) -> (u64, u64) {
        let mut budget = 64u16;
        self.known_bits_depth(id, 0, &mut budget)
    }

    fn known_bits_depth(&self, id: ExprId, depth: u8, budget: &mut u16) -> (u64, u64) {
        match self.get(id) {
            ExprNode::Const(v) => return (!*v, *v),
            ExprNode::Cmp { .. } | ExprNode::EntryFlag(_) => return (!1u64, 0),
            ExprNode::Cr8Read(_) => return (!0xFu64, 0),
            _ => {}
        }
        if depth > 24 || *budget == 0 {
            return (0, 0);
        }
        *budget -= 1;
        let d = depth + 1;
        match self.get(id) {
            ExprNode::Not(x) => {
                let (z, o) = self.known_bits_depth(*x, d, budget);
                (o, z)
            }
            ExprNode::And(a, b) => {
                let (za, oa) = self.known_bits_depth(*a, d, budget);
                let (zb, ob) = self.known_bits_depth(*b, d, budget);
                (za | zb, oa & ob)
            }
            ExprNode::Or(a, b) => {
                let (za, oa) = self.known_bits_depth(*a, d, budget);
                let (zb, ob) = self.known_bits_depth(*b, d, budget);
                (za & zb, oa | ob)
            }
            ExprNode::Xor(a, b) => {
                let (za, oa) = self.known_bits_depth(*a, d, budget);
                let (zb, ob) = self.known_bits_depth(*b, d, budget);
                ((za & zb) | (oa & ob), (za & ob) | (oa & zb))
            }
            ExprNode::Shl(a, b) => {
                if let Some(sh) = self.as_const(*b) {
                    let s = (sh & 63) as u32;
                    let (za, oa) = self.known_bits_depth(*a, d, budget);
                    let low_zeros = if s == 0 { 0 } else { (1u64 << s) - 1 };
                    (za.wrapping_shl(s) | low_zeros, oa.wrapping_shl(s))
                } else {
                    (0, 0)
                }
            }
            ExprNode::Shr(a, b) => {
                if let Some(sh) = self.as_const(*b) {
                    let s = (sh & 63) as u32;
                    let (za, oa) = self.known_bits_depth(*a, d, budget);
                    let hi_zeros = if s == 0 { 0 } else { !((1u64 << (64 - s)) - 1) };
                    (za.wrapping_shr(s) | hi_zeros, oa.wrapping_shr(s))
                } else {
                    (0, 0)
                }
            }
            ExprNode::Mul(a, b) => {
                let (za, _) = self.known_bits_depth(*a, d, budget);
                let (zb, _) = self.known_bits_depth(*b, d, budget);
                let tz = (za.trailing_ones() + zb.trailing_ones()).min(64);
                let mut z = if tz >= 64 {
                    u64::MAX
                } else if tz == 0 {
                    0
                } else {
                    (1u64 << tz) - 1
                };
                // x * (x + odd) is always even
                if self.is_consecutive_parity_pair(*a, *b) {
                    z |= 1;
                }
                (z, 0)
            }
            ExprNode::Select { if_true, if_false, .. } => {
                let (zt, ot) = self.known_bits_depth(*if_true, d, budget);
                let (zf, of) = self.known_bits_depth(*if_false, d, budget);
                (zt & zf, ot & of)
            }
            _ => (0, 0),
        }
    }

    fn is_consecutive_parity_pair(&self, a: ExprId, b: ExprId) -> bool {
        let check = |x: ExprId, y: ExprId| -> bool {
            match self.get(y) {
                ExprNode::Add(inner, rhs) => {
                    *inner == x && matches!(self.as_const(*rhs), Some(k) if (k & 1) == 1)
                }
                _ => false,
            }
        };
        check(a, b) || check(b, a)
    }

    pub fn not(&mut self, x: ExprId) -> ExprId {
        if let Some(v) = self.as_const(x) {
            return self.const_u64(!v);
        }
        match self.get(x).clone() {
            ExprNode::Not(inner) => inner,
            ExprNode::Neg(inner) => {
                // ~(-x) == x - 1
                self.sub_const(inner, 1)
            }
            ExprNode::Cmp { pred, lhs, rhs } => {
                // Keep Cmp inverted? Wait: ~Cmp is bitwise invert (all 64 bits), not boolean invert!
                // Wait: only invert Cmp on logical boolean test or XOR 1, not bitwise NOT.
                let _ = (pred, lhs, rhs);
                self.intern_node(ExprNode::Not(x))
            }
            _ => self.intern_node(ExprNode::Not(x)),
        }
    }

    pub fn neg(&mut self, x: ExprId) -> ExprId {
        if let Some(v) = self.as_const(x) {
            return self.const_u64(v.wrapping_neg());
        }
        match self.get(x).clone() {
            ExprNode::Neg(inner) => inner,
            ExprNode::Not(inner) => {
                // -(~x) == x + 1
                self.add_const(inner, 1)
            }
            _ => self.intern_node(ExprNode::Neg(x)),
        }
    }

    pub fn add_const(&mut self, a: ExprId, c: u64) -> ExprId {
        let rhs = self.const_u64(c);
        self.add(a, rhs)
    }

    pub fn add_signed(&mut self, a: ExprId, off: i64) -> ExprId {
        self.add_const(a, off as u64)
    }

    pub fn sub_const(&mut self, a: ExprId, c: u64) -> ExprId {
        self.add_const(a, c.wrapping_neg())
    }

    pub fn and_const(&mut self, a: ExprId, m: u64) -> ExprId {
        let rhs = self.const_u64(m);
        self.and(a, rhs)
    }

    pub fn or_const(&mut self, a: ExprId, m: u64) -> ExprId {
        let rhs = self.const_u64(m);
        self.or(a, rhs)
    }

    pub fn xor_const(&mut self, a: ExprId, c: u64) -> ExprId {
        let rhs = self.const_u64(c);
        self.xor(a, rhs)
    }

    pub fn shl_const(&mut self, a: ExprId, s: u64) -> ExprId {
        let rhs = self.const_u64(s);
        self.shl(a, rhs)
    }

    pub fn shr_const(&mut self, a: ExprId, s: u64) -> ExprId {
        let rhs = self.const_u64(s);
        self.shr(a, rhs)
    }

    pub fn add(&mut self, raw_a: ExprId, raw_b: ExprId) -> ExprId {
        let (a, b) = self.order_pair(raw_a, raw_b);
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.wrapping_add(cb));
        }
        if let Some(0) = self.as_const(b) {
            return a;
        }
        if a == b {
            // x + x -> x * 2 helps consecutive folding only if not needed as Add, wait:
            // keep (x + (-x)) = 0 cleanly first.
        }
        let na = self.get(a).clone();
        let nb = self.get(b).clone();

        // x + (-x) -> 0
        if matches!(nb, ExprNode::Neg(inner) if inner == a)
            || matches!(na, ExprNode::Neg(inner) if inner == b)
        {
            return self.const_u64(0);
        }
        // x + (-y) -> x - y
        if let ExprNode::Neg(y) = nb {
            return self.sub(a, y);
        }
        if let ExprNode::Neg(y) = na {
            return self.sub(b, y);
        }
        // x + ~x -> -1
        if matches!(nb, ExprNode::Not(inner) if inner == a)
            || matches!(na, ExprNode::Not(inner) if inner == b)
        {
            return self.const_u64(u64::MAX);
        }

        // Reassociate (x + c1) + c2 -> x + (c1 + c2)
        if let (ExprNode::Add(x, c1_id), Some(c2)) = (&na, self.as_const(b)) {
            if let Some(c1) = self.as_const(*c1_id) {
                return self.add_const(*x, c1.wrapping_add(c2));
            }
        }
        // Distribute Select over constant addition: Select(c, x, y) + k -> Select(c, x + k, y + k)
        if self.select_dist_depth < 3 {
            if let (ExprNode::Select { cond, if_true, if_false }, Some(k)) = (&na, self.as_const(b)) {
                self.select_dist_depth += 1;
                let t = self.add_const(*if_true, k);
                let f = self.add_const(*if_false, k);
                self.select_dist_depth -= 1;
                return self.select(*cond, t, f);
            }
        }
        // (x - y) + y -> x
        if let ExprNode::Sub(x, y) = na {
            if y == b {
                return x;
            }
        }
        if let ExprNode::Sub(x, y) = nb {
            if y == a {
                return x;
            }
        }
        // (~x) + c -> (c - 1) - x when helpful? Actually (~x) + 1 == -x!
        if let (ExprNode::Not(x), Some(1)) = (&na, self.as_const(b)) {
            return self.neg(*x);
        }

        // MBA: (x ^ y) + 2*(x & y) -> x + y  AND  (x ^ y) + ((x & y) << 1) -> x + y
        if let Some(res) = self.match_mba_add_xor_and(a, b).or_else(|| self.match_mba_add_xor_and(b, a)) {
            return res;
        }
        // MBA: (x | y) + (x & y) -> x + y
        if let (ExprNode::Or(ox, oy), ExprNode::And(ax, ay)) = (&na, &nb) {
            if (ox == ax && oy == ay) || (ox == ay && oy == ax) {
                return self.add(*ox, *oy);
            }
        }
        if let (ExprNode::And(ax, ay), ExprNode::Or(ox, oy)) = (&na, &nb) {
            if (ox == ax && oy == ay) || (ox == ay && oy == ax) {
                return self.add(*ox, *oy);
            }
        }

        if let Some(simplified) = self.try_simplify_linear_sum(a, b, false) {
            return simplified;
        }

        self.intern_node(ExprNode::Add(a, b))
    }

    fn collect_linear_terms(
        &self,
        id: ExprId,
        coeff: u64,
        depth: u8,
        terms: &mut Vec<(ExprId, u64)>,
        const_sum: &mut u64,
        const_count: &mut usize,
    ) -> bool {
        if coeff == 0 {
            return true;
        }
        if depth >= 12 {
            if terms.len() >= 24 {
                return false;
            }
            terms.push((id, coeff));
            return true;
        }
        match self.get(id) {
            ExprNode::Const(c) => {
                *const_count += 1;
                *const_sum = const_sum.wrapping_add(c.wrapping_mul(coeff));
                true
            }
            ExprNode::Neg(x) => {
                self.collect_linear_terms(*x, coeff.wrapping_neg(), depth + 1, terms, const_sum, const_count)
            }
            ExprNode::Add(x, y) => {
                self.collect_linear_terms(*x, coeff, depth + 1, terms, const_sum, const_count)
                    && self.collect_linear_terms(*y, coeff, depth + 1, terms, const_sum, const_count)
            }
            ExprNode::Sub(x, y) => {
                self.collect_linear_terms(*x, coeff, depth + 1, terms, const_sum, const_count)
                    && self.collect_linear_terms(*y, coeff.wrapping_neg(), depth + 1, terms, const_sum, const_count)
            }
            ExprNode::Mul(x, y) => {
                if let Some(k) = self.as_const(*y) {
                    self.collect_linear_terms(*x, coeff.wrapping_mul(k), depth + 1, terms, const_sum, const_count)
                } else if let Some(k) = self.as_const(*x) {
                    self.collect_linear_terms(*y, coeff.wrapping_mul(k), depth + 1, terms, const_sum, const_count)
                } else {
                    if terms.len() >= 24 {
                        return false;
                    }
                    terms.push((id, coeff));
                    true
                }
            }
            _ => {
                if terms.len() >= 24 {
                    return false;
                }
                terms.push((id, coeff));
                true
            }
        }
    }

    fn try_simplify_linear_sum(&mut self, a: ExprId, b: ExprId, sub_b: bool) -> Option<ExprId> {
        let mut terms: Vec<(ExprId, u64)> = Vec::new();
        let mut const_sum = 0u64;
        let mut const_count = 0usize;
        if !self.collect_linear_terms(a, 1, 0, &mut terms, &mut const_sum, &mut const_count) {
            return None;
        }
        let b_coeff = if sub_b { u64::MAX } else { 1 };
        if !self.collect_linear_terms(b, b_coeff, 0, &mut terms, &mut const_sum, &mut const_count) {
            return None;
        }

        terms.sort_unstable_by_key(|&(id, _)| id.0);
        let mut merged: Vec<(ExprId, u64)> = Vec::with_capacity(terms.len());
        let mut merged_any = false;
        for (id, coeff) in terms {
            if let Some((prev_id, prev_coeff)) = merged.last_mut() {
                if *prev_id == id {
                    *prev_coeff = prev_coeff.wrapping_add(coeff);
                    merged_any = true;
                    continue;
                }
            }
            merged.push((id, coeff));
        }

        if !(merged_any || const_count >= 2 || (const_count >= 1 && const_sum == 0)) {
            return None;
        }

        let mut pos: Vec<ExprId> = Vec::new();
        let mut neg: Vec<ExprId> = Vec::new();
        for (id, coeff) in merged {
            if coeff == 0 {
                continue;
            } else if coeff == 1 {
                pos.push(id);
            } else if coeff == u64::MAX {
                neg.push(id);
            } else {
                let k_id = self.const_u64(coeff);
                let (mx, my) = self.order_pair(id, k_id);
                pos.push(self.intern_node(ExprNode::Mul(mx, my)));
            }
        }

        let mut acc: Option<ExprId> = None;
        for id in pos {
            acc = Some(match acc {
                None => id,
                Some(cur) => {
                    let (x, y) = self.order_pair(cur, id);
                    self.intern_node(ExprNode::Add(x, y))
                }
            });
        }
        for id in neg {
            acc = Some(match acc {
                None => self.intern_node(ExprNode::Neg(id)),
                Some(cur) => self.intern_node(ExprNode::Sub(cur, id)),
            });
        }

        Some(match acc {
            None => self.const_u64(const_sum),
            Some(cur) => {
                if const_sum == 0 {
                    cur
                } else {
                    let c_id = self.const_u64(const_sum);
                    self.intern_node(ExprNode::Add(cur, c_id))
                }
            }
        })
    }

    fn match_mba_add_xor_and(&mut self, maybe_xor: ExprId, maybe_mul_or_shl: ExprId) -> Option<ExprId> {
        let ExprNode::Xor(xa, xb) = self.get(maybe_xor).clone() else {
            return None;
        };
        let and_pair = match self.get(maybe_mul_or_shl).clone() {
            ExprNode::Mul(lhs, rhs) if self.as_const(rhs) == Some(2) => lhs,
            ExprNode::Shl(lhs, rhs) if self.as_const(rhs) == Some(1) => lhs,
            _ => return None,
        };
        let ExprNode::And(aa, ab) = self.get(and_pair).clone() else {
            return None;
        };
        if (xa == aa && xb == ab) || (xa == ab && xb == aa) {
            Some(self.add(xa, xb))
        } else {
            None
        }
    }

    pub fn sub(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.wrapping_sub(cb));
        }
        if let Some(cb) = self.as_const(b) {
            // Canonicalize `x - const` as `x + (-const)`
            return self.add_const(a, cb.wrapping_neg());
        }
        if self.as_const(a) == Some(0) {
            return self.neg(b);
        }
        if self.as_const(a) == Some(u64::MAX) {
            return self.not(b);
        }
        if a == b {
            return self.const_u64(0);
        }
        let na = self.get(a).clone();
        let nb = self.get(b).clone();

        if let ExprNode::Neg(y) = nb {
            return self.add(a, y);
        }
        // (x + c1) - x -> c1, (x + y) - y -> x, (x + y) - x -> y
        if let ExprNode::Add(ax, ay) = na {
            if ax == b {
                return ay;
            }
            if ay == b {
                return ax;
            }
        }
        // x - (x + c) -> -c, x - (x + y) -> -y
        if let ExprNode::Add(bx, by) = nb {
            if bx == a {
                return self.neg(by);
            }
            if by == a {
                return self.neg(bx);
            }
        }
        // x - (x - y) -> y
        if let ExprNode::Sub(bx, by) = nb {
            if bx == a {
                return by;
            }
        }
        // (x | y) - (x & y) -> x ^ y
        if let (ExprNode::Or(ox, oy), ExprNode::And(ax, ay)) = (&na, &nb) {
            if (ox == ax && oy == ay) || (ox == ay && oy == ax) {
                return self.xor(*ox, *oy);
            }
        }
        // (x + y) - (x | y) -> x & y
        if let (ExprNode::Add(ax, ay), ExprNode::Or(ox, oy)) = (&na, &nb) {
            if (ax == ox && ay == oy) || (ax == oy && ay == ox) {
                return self.and(*ax, *ay);
            }
        }
        // (c1 - x) or similar when a is const and b is Add(x, c2): c1 - (x + c2) = (c1 - c2) - x
        if let (Some(c1), ExprNode::Add(x, c2_id)) = (self.as_const(a), &nb) {
            if let Some(c2) = self.as_const(*c2_id) {
                let nc = self.const_u64(c1.wrapping_sub(c2));
                return self.sub(nc, *x);
            }
        }

        if let Some(simplified) = self.try_simplify_linear_sum(a, b, true) {
            return simplified;
        }

        self.intern_node(ExprNode::Sub(a, b))
    }

    pub fn mul(&mut self, raw_a: ExprId, raw_b: ExprId) -> ExprId {
        let (a, b) = self.order_pair(raw_a, raw_b);
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.wrapping_mul(cb));
        }
        match self.as_const(b) {
            Some(0) => return self.const_u64(0),
            Some(1) => return a,
            Some(u64::MAX) => return self.neg(a),
            _ => {}
        }
        let na = self.get(a).clone();
        if let (ExprNode::Mul(x, c1_id), Some(c2)) = (&na, self.as_const(b)) {
            if let Some(c1) = self.as_const(*c1_id) {
                let c = self.const_u64(c1.wrapping_mul(c2));
                return self.mul(*x, c);
            }
        }
        self.intern_node(ExprNode::Mul(a, b))
    }

    /// High half of the 128-bit product of two 64-bit values (`signed`: `imul`).
    pub fn mul_hi(&mut self, raw_a: ExprId, raw_b: ExprId, signed: bool) -> ExprId {
        let (a, b) = self.order_pair(raw_a, raw_b);
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            let hi = if signed {
                (((ca as i64 as i128) * (cb as i64 as i128)) >> 64) as u64
            } else {
                (((ca as u128) * (cb as u128)) >> 64) as u64
            };
            return self.const_u64(hi);
        }
        match self.as_const(b) {
            Some(0) => return self.const_u64(0),
            // x * 1: the high half is 0 unsigned, the sign of x signed.
            Some(1) if !signed => return self.const_u64(0),
            Some(1) => return self.sar_const_63(a),
            _ => {}
        }
        self.intern_node(if signed { ExprNode::MulHiS(a, b) } else { ExprNode::MulHiU(a, b) })
    }

    fn sar_const_63(&mut self, a: ExprId) -> ExprId {
        let s = self.const_u64(63);
        self.sar(a, s)
    }

    pub fn and(&mut self, raw_a: ExprId, raw_b: ExprId) -> ExprId {
        let (a, b) = self.order_pair(raw_a, raw_b);
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca & cb);
        }
        // cmp & !cmp == 0
        if self.are_complementary_cmps(a, b) {
            return self.const_u64(0);
        }
        if let Some(m) = self.as_const(b) {
            if m == 0 {
                return self.const_u64(0);
            }
            if m == u64::MAX {
                return a;
            }
            let (za, _) = self.known_bits(a);
            if (za & m) == m {
                return self.const_u64(0);
            }
            if (!m & za) == !m {
                return a;
            }
        }
        if a == b {
            return a;
        }
        let na = self.get(a).clone();
        let nb = self.get(b).clone();

        // x & ~x -> 0
        if matches!(nb, ExprNode::Not(inner) if inner == a)
            || matches!(na, ExprNode::Not(inner) if inner == b)
        {
            return self.const_u64(0);
        }
        // (x & c1) & c2 -> x & (c1 & c2)
        if let (ExprNode::And(x, c1_id), Some(c2)) = (&na, self.as_const(b)) {
            if let Some(c1) = self.as_const(*c1_id) {
                return self.and_const(*x, c1 & c2);
            }
        }
        // (x & m) & m -> x & m (redundant)
        if let ExprNode::And(x, y) = na {
            if x == b || y == b {
                return a;
            }
        }
        // Known-zero mask distribution across Or: (x | y) & m -> x & m if (known_zeros(y) & m) == m
        if let (ExprNode::Or(ox, oy), Some(m)) = (&na, self.as_const(b)) {
            let (ox, oy) = (*ox, *oy);
            let (zx, _) = self.known_bits(ox);
            let (zy, _) = self.known_bits(oy);
            if (zy & m) == m {
                return self.and_const(ox, m);
            }
            if (zx & m) == m {
                return self.and_const(oy, m);
            }
        }
        // Known-zero mask distribution across Shr(Or, const):
        // ((x | y) >> s) & m -> (x >> s) & m if (known_zeros(y) & (m << s)) == (m << s)
        if let (ExprNode::Shr(inner, cnt_id), Some(m)) = (&na, self.as_const(b)) {
            let (inner, cnt_id) = (*inner, *cnt_id);
            if let Some(s) = self.as_const(cnt_id) {
                if s < 64 && m <= (u64::MAX >> s) {
                    if let ExprNode::Or(ox, oy) = self.get(inner).clone() {
                        let sm = m << s;
                        let (zx, _) = self.known_bits(ox);
                        let (zy, _) = self.known_bits(oy);
                        if (zy & sm) == sm {
                            let sh = self.shr_const(ox, s);
                            return self.and_const(sh, m);
                        }
                        if (zx & sm) == sm {
                            let sh = self.shr_const(oy, s);
                            return self.and_const(sh, m);
                        }
                    }
                }
            }
        }
        // Select(c, x, y) & m -> Select(c, x & m, y & m)
        if self.select_dist_depth < 3 {
            if let (ExprNode::Select { cond, if_true, if_false }, Some(m)) = (&na, self.as_const(b)) {
                self.select_dist_depth += 1;
                let t = self.and_const(*if_true, m);
                let f = self.and_const(*if_false, m);
                self.select_dist_depth -= 1;
                return self.select(*cond, t, f);
            }
        }
        self.intern_node(ExprNode::And(a, b))
    }

    /// `x` and `y` are comparisons that are exact opposites (`a == b` / `a != b`,
    /// `a < b` / `b <= a`, ...): one is 1 exactly when the other is 0. VM handlers
    /// build opaque branch conditions as `cmp | !cmp`, which is always 1.
    fn are_complementary_cmps(&self, x: ExprId, y: ExprId) -> bool {
        let (ExprNode::Cmp { pred: p, lhs: a, rhs: b }, ExprNode::Cmp { pred: q, lhs: c, rhs: d }) =
            (self.get(x), self.get(y))
        else {
            return false;
        };
        (c == a && d == b && *q == p.invert()) || (c == b && d == a && *q == p.invert().swap_operands())
    }

    pub fn or(&mut self, raw_a: ExprId, raw_b: ExprId) -> ExprId {
        let (a, b) = self.order_pair(raw_a, raw_b);
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca | cb);
        }
        // cmp | !cmp == 1 (a tautology the VM uses as an opaque predicate)
        if self.are_complementary_cmps(a, b) {
            return self.const_u64(1);
        }
        if let Some(m) = self.as_const(b) {
            if m == 0 {
                return a;
            }
            if m == u64::MAX {
                return self.const_u64(u64::MAX);
            }
            let (za, oa) = self.known_bits(a);
            if (oa & m) == m {
                return a;
            }
            if ((oa | m) == u64::MAX) && (za & !m == 0) {
                // normal
            }
        }
        if a == b {
            return a;
        }
        // Known-bits absorption, for any operands (not only a constant mask): when
        // every bit `b` can set is already a known 1 of `a`, `a | b == a`, and the
        // other way round. VM handlers OR a boolean into a value whose bit 0 is
        // already set (`Or(Cmp, 1)`, `Or(x | 1, cmp & cmp)`); left in place, the
        // value looked non-constant and jump targets built from it stayed opaque.
        {
            let (za, oa) = self.known_bits(a);
            let (zb, ob) = self.known_bits(b);
            if (!zb & !oa) == 0 {
                return a;
            }
            if (!za & !ob) == 0 {
                return b;
            }
        }
        let na = self.get(a).clone();
        let nb = self.get(b).clone();

        // x | ~x -> -1
        if matches!(nb, ExprNode::Not(inner) if inner == a)
            || matches!(na, ExprNode::Not(inner) if inner == b)
        {
            return self.const_u64(u64::MAX);
        }
        // (x | c1) | c2 -> x | (c1 | c2)
        if let (ExprNode::Or(x, c1_id), Some(c2)) = (&na, self.as_const(b)) {
            if let Some(c1) = self.as_const(*c1_id) {
                return self.or_const(*x, c1 | c2);
            }
        }
        // (x & m1) | (x & m2) -> x & (m1 | m2)
        if let (ExprNode::And(x1, m1_id), ExprNode::And(x2, m2_id)) = (&na, &nb) {
            if x1 == x2 {
                if let (Some(m1), Some(m2)) = (self.as_const(*m1_id), self.as_const(*m2_id)) {
                    return self.and_const(*x1, m1 | m2);
                }
            }
        }
        // x | (x & m) -> x
        if matches!(na, ExprNode::And(x, _) if x == b) {
            return b;
        }
        if matches!(nb, ExprNode::And(x, _) if x == a) {
            return a;
        }
        // MBA: (a & b) | (a & ~b) -> a
        if let Some(r) = self.match_mba_or_and_not(a, b) {
            return r;
        }
        // MBA: (a & ~b) | (~a & b) -> a ^ b
        if let Some(r) = self.match_mba_or_xor_from_ands(a, b) {
            return r;
        }
        // MBA: (a ^ b) | (a & b) -> a | b
        if let Some(r) = self.match_mba_or_xor_and(a, b).or_else(|| self.match_mba_or_xor_and(b, a)) {
            return r;
        }
        // Select(c, x, y) | m -> Select(c, x | m, y | m)
        if self.select_dist_depth < 3 {
            if let (ExprNode::Select { cond, if_true, if_false }, Some(m)) = (&na, self.as_const(b)) {
                self.select_dist_depth += 1;
                let t = self.or_const(*if_true, m);
                let f = self.or_const(*if_false, m);
                self.select_dist_depth -= 1;
                return self.select(*cond, t, f);
            }
        }
        self.intern_node(ExprNode::Or(a, b))
    }

    fn match_mba_or_and_not(&mut self, a: ExprId, b: ExprId) -> Option<ExprId> {
        let (ExprNode::And(x1, x2), ExprNode::And(y1, y2)) = (self.get(a).clone(), self.get(b).clone()) else {
            return None;
        };
        let is_not_pair = |u: ExprId, v: ExprId| -> bool {
            matches!(self.get(u), ExprNode::Not(n) if *n == v)
                || matches!(self.get(v), ExprNode::Not(n) if *n == u)
        };
        if x1 == y1 && is_not_pair(x2, y2) {
            return Some(x1);
        }
        if x1 == y2 && is_not_pair(x2, y1) {
            return Some(x1);
        }
        if x2 == y1 && is_not_pair(x1, y2) {
            return Some(x2);
        }
        if x2 == y2 && is_not_pair(x1, y1) {
            return Some(x2);
        }
        None
    }

    fn match_mba_or_xor_from_ands(&mut self, a: ExprId, b: ExprId) -> Option<ExprId> {
        let (ExprNode::And(x1, x2), ExprNode::And(y1, y2)) = (self.get(a).clone(), self.get(b).clone()) else {
            return None;
        };
        let is_not_of = |cand_not: ExprId, base: ExprId| matches!(self.get(cand_not), ExprNode::Not(n) if *n == base);
        let pairs = [(x1, x2, y1, y2), (x1, x2, y2, y1), (x2, x1, y1, y2), (x2, x1, y2, y1)];
        for (p, nq, np, q) in pairs {
            if is_not_of(nq, q) && is_not_of(np, p) {
                return Some(self.xor(p, q));
            }
        }
        None
    }

    fn match_mba_or_xor_and(&mut self, maybe_xor: ExprId, maybe_and: ExprId) -> Option<ExprId> {
        let (ExprNode::Xor(xa, xb), ExprNode::And(aa, ab)) = (self.get(maybe_xor).clone(), self.get(maybe_and).clone()) else {
            return None;
        };
        if (xa == aa && xb == ab) || (xa == ab && xb == aa) {
            Some(self.or(xa, xb))
        } else {
            None
        }
    }

    pub fn xor(&mut self, raw_a: ExprId, raw_b: ExprId) -> ExprId {
        let (a, b) = self.order_pair(raw_a, raw_b);
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca ^ cb);
        }
        // cmp ^ !cmp == 1
        if self.are_complementary_cmps(a, b) {
            return self.const_u64(1);
        }
        if let Some(m) = self.as_const(b) {
            if m == 0 {
                return a;
            }
            if m == u64::MAX {
                return self.not(a);
            }
        }
        if a == b {
            return self.const_u64(0);
        }
        let na = self.get(a).clone();
        let nb = self.get(b).clone();

        // x ^ ~x -> -1
        if matches!(nb, ExprNode::Not(inner) if inner == a)
            || matches!(na, ExprNode::Not(inner) if inner == b)
        {
            return self.const_u64(u64::MAX);
        }
        // (x ^ c1) ^ c2 -> x ^ (c1 ^ c2)
        if let (ExprNode::Xor(x, c1_id), Some(c2)) = (&na, self.as_const(b)) {
            if let Some(c1) = self.as_const(*c1_id) {
                return self.xor_const(*x, c1 ^ c2);
            }
        }
        // (x ^ y) ^ y -> x ; (x ^ y) ^ x -> y
        if let ExprNode::Xor(x, y) = na {
            if y == b {
                return x;
            }
            if x == b {
                return y;
            }
        }
        if let ExprNode::Xor(x, y) = nb {
            if y == a {
                return x;
            }
            if x == a {
                return y;
            }
        }
        // Cmp ^ 1 -> Cmp.invert()
        if let (ExprNode::Cmp { pred, lhs, rhs }, Some(1)) = (&na, self.as_const(b)) {
            return self.cmp(pred.invert(), *lhs, *rhs);
        }
        // Select(c, x, y) ^ k -> Select(c, x ^ k, y ^ k)
        if self.select_dist_depth < 3 {
            if let (ExprNode::Select { cond, if_true, if_false }, Some(k)) = (&na, self.as_const(b)) {
                self.select_dist_depth += 1;
                let t = self.xor_const(*if_true, k);
                let f = self.xor_const(*if_false, k);
                self.select_dist_depth -= 1;
                return self.select(*cond, t, f);
            }
        }

        self.intern_node(ExprNode::Xor(a, b))
    }

    pub fn shl(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.wrapping_shl((cb & 63) as u32));
        }
        if self.as_const(a) == Some(0) {
            return self.const_u64(0);
        }
        if let Some(cb) = self.as_const(b) {
            let s = cb & 63;
            if s == 0 {
                return a;
            }
            match self.get(a).clone() {
                ExprNode::Shr(inner, s2_id) if self.as_const(s2_id) == Some(s) => {
                    return self.and_const(inner, u64::MAX.wrapping_shl(s as u32));
                }
                ExprNode::And(x, m_id) => {
                    if let Some(m) = self.as_const(m_id) {
                        if let ExprNode::Shr(inner, s2_id) = self.get(x).clone() {
                            if self.as_const(s2_id) == Some(s) {
                                return self.and_const(inner, m.wrapping_shl(s as u32));
                            }
                        }
                    }
                }
                ExprNode::Shl(inner, s2_id) => {
                    if let Some(s2) = self.as_const(s2_id) {
                        let tot = s + (s2 & 63);
                        return if tot >= 64 {
                            self.const_u64(0)
                        } else {
                            self.shl_const(inner, tot)
                        };
                    }
                }
                _ => {}
            }
            let norm = self.const_u64(s);
            return self.intern_node(ExprNode::Shl(a, norm));
        }
        self.intern_node(ExprNode::Shl(a, b))
    }

    pub fn shr(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.wrapping_shr((cb & 63) as u32));
        }
        if self.as_const(a) == Some(0) {
            return self.const_u64(0);
        }
        if let Some(cb) = self.as_const(b) {
            let s = cb & 63;
            if s == 0 {
                return a;
            }
            match self.get(a).clone() {
                ExprNode::Shl(inner, s2_id) if self.as_const(s2_id) == Some(s) => {
                    return self.and_const(inner, u64::MAX >> s);
                }
                ExprNode::Shr(inner, s2_id) => {
                    if let Some(s2) = self.as_const(s2_id) {
                        let tot = s + (s2 & 63);
                        return if tot >= 64 {
                            self.const_u64(0)
                        } else {
                            self.shr_const(inner, tot)
                        };
                    }
                }
                ExprNode::And(x, c_id) => {
                    if let Some(c) = self.as_const(c_id) {
                        let sx = self.shr_const(x, s);
                        return self.and_const(sx, c >> s);
                    }
                }
                _ => {}
            }
            let norm = self.const_u64(s);
            return self.intern_node(ExprNode::Shr(a, norm));
        }
        self.intern_node(ExprNode::Shr(a, b))
    }

    pub fn sar(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(((ca as i64).wrapping_shr((cb & 63) as u32)) as u64);
        }
        if let Some(cb) = self.as_const(b) {
            if (cb & 63) == 0 {
                return a;
            }
            let norm = self.const_u64(cb & 63);
            return self.intern_node(ExprNode::Sar(a, norm));
        }
        self.intern_node(ExprNode::Sar(a, b))
    }

    pub fn rol(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.rotate_left((cb & 63) as u32));
        }
        if let Some(cb) = self.as_const(b) {
            let s = cb & 63;
            if s == 0 {
                return a;
            }
            if let ExprNode::Rol(inner, prev_b) = self.get(a).clone() {
                if let Some(ps) = self.as_const(prev_b) {
                    let sum_c = self.const_u64((ps + s) & 63);
                    return self.rol(inner, sum_c);
                }
            }
            let norm = self.const_u64(s);
            return self.intern_node(ExprNode::Rol(a, norm));
        }
        self.intern_node(ExprNode::Rol(a, b))
    }

    pub fn ror(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if let (Some(ca), Some(cb)) = (self.as_const(a), self.as_const(b)) {
            return self.const_u64(ca.rotate_right((cb & 63) as u32));
        }
        if let Some(cb) = self.as_const(b) {
            let s = cb & 63;
            if s == 0 {
                return a;
            }
            let inv_c = self.const_u64((64 - s) & 63);
            return self.rol(a, inv_c);
        }
        self.intern_node(ExprNode::Ror(a, b))
    }

    pub fn sext(&mut self, val: ExprId, from_bits: u8) -> ExprId {
        if from_bits >= 64 {
            return val;
        }
        if let Some(c) = self.as_const(val) {
            return self.const_u64(sign_extend_u64(c, from_bits));
        }
        if let ExprNode::SExt { val: inner, from_bits: b1 } = self.get(val).clone() {
            if b1 <= from_bits {
                return self.sext(inner, b1);
            }
        }
        self.intern_node(ExprNode::SExt { val, from_bits })
    }

    pub fn zext_mask(&mut self, val: ExprId, width_bytes: u8) -> ExprId {
        if width_bytes >= 8 {
            val
        } else {
            self.and_const(val, width_mask(width_bytes))
        }
    }

    fn extract_two_valued_state_key(&self, id: ExprId) -> Option<(ExprId, u64, u64)> {
        match self.get(id) {
            ExprNode::Select { cond, if_true, if_false } => {
                let k_t = self.as_const(*if_true)?;
                let k_f = self.as_const(*if_false)?;
                Some((*cond, k_t, k_f))
            }
            ExprNode::Add(mul_id, base_id) => {
                let base = self.as_const(*base_id)?;
                if let ExprNode::Mul(c_id, d_id) = self.get(*mul_id) {
                    let delta = self.as_const(*d_id)?;
                    if (self.known_bits(*c_id).0 & !1u64) == !1u64 {
                        return Some((*c_id, base.wrapping_add(delta), base));
                    }
                }
                None
            }
            ExprNode::Mul(c_id, d_id) => {
                let delta = self.as_const(*d_id)?;
                if (self.known_bits(*c_id).0 & !1u64) == !1u64 {
                    return Some((*c_id, delta, 0));
                }
                None
            }
            _ => None,
        }
    }

    pub fn cmp(&mut self, pred: CondPred, lhs: ExprId, rhs: ExprId) -> ExprId {
        if let (Some(a), Some(b)) = (self.as_const(lhs), self.as_const(rhs)) {
            return self.const_u64(if pred.eval(a, b) { 1 } else { 0 });
        }
        if lhs == rhs {
            let res = matches!(
                pred,
                CondPred::Eq | CondPred::Ule | CondPred::Uge | CondPred::Sle | CondPred::Sge
            );
            return self.const_u64(if res { 1 } else { 0 });
        }
        // Eq / Ne against a constant: move the constants of the left side over, so
        // `(y + k1) == k2` reads `y == k2 - k1` (and `y ^ k1`, `y - k1`, `-y`, `~y`
        // likewise). VM dispatchers compare `Or(..) + K == K`, which is `Or(..) == 0`;
        // in normal form the same test is recognised wherever it appears, and the
        // `Select` arms can be specialised by it.
        if matches!(pred, CondPred::Eq | CondPred::Ne) {
            let (l, r) = if self.as_const(lhs).is_some() { (rhs, lhs) } else { (lhs, rhs) };
            if let Some(k2) = self.as_const(r) {
                let moved = match self.get(l).clone() {
                    ExprNode::Add(y, k) => self.as_const(k).map(|k1| (y, k2.wrapping_sub(k1))),
                    ExprNode::Sub(y, k) => self.as_const(k).map(|k1| (y, k2.wrapping_add(k1))),
                    ExprNode::Xor(y, k) => self.as_const(k).map(|k1| (y, k2 ^ k1)),
                    ExprNode::Neg(y) => Some((y, k2.wrapping_neg())),
                    ExprNode::Not(y) => Some((y, !k2)),
                    _ => None,
                };
                if let Some((y, k)) = moved {
                    let kc = self.const_u64(k);
                    return self.cmp(pred, y, kc);
                }
                if l != lhs {
                    return self.cmp(pred, l, r);
                }
            }
        }
        // `(x + c) == x` (c != 0) is false; `(x + c) != x` is true
        let is_offset_pair = |a: ExprId, b: ExprId| -> bool {
            matches!(self.get(a), ExprNode::Add(x, k) if *x == b && matches!(self.as_const(*k), Some(c) if c != 0))
        };
        if matches!(pred, CondPred::Eq | CondPred::Ne)
            && (is_offset_pair(lhs, rhs) || is_offset_pair(rhs, lhs))
        {
            return self.const_u64(if pred == CondPred::Ne { 1 } else { 0 });
        }
        // Fold `Cmp(Eq, Cmp(p, a, b), 0)` -> `Cmp(p.invert(), a, b)`
        // Fold `Cmp(Ne, Cmp(p, a, b), 0)` -> `Cmp(p, a, b)`
        if let (ExprNode::Cmp { pred: ip, lhs: il, rhs: ir }, Some(0)) =
            (self.get(lhs).clone(), self.as_const(rhs))
        {
            if pred == CondPred::Eq {
                return self.cmp(ip.invert(), il, ir);
            }
            if pred == CondPred::Ne {
                return self.cmp(ip, il, ir);
            }
        }
        if let (Some(0), ExprNode::Cmp { pred: ip, lhs: il, rhs: ir }) =
            (self.as_const(lhs), self.get(rhs).clone())
        {
            if pred == CondPred::Eq {
                return self.cmp(ip.invert(), il, ir);
            }
            if pred == CondPred::Ne {
                return self.cmp(ip, il, ir);
            }
        }

        // Collapse threshold comparisons on 2-valued state keys (`Select(c, k_t, k_f)` or `base + delta * bool_c`)
        if let Some(thresh) = self.as_const(rhs) {
            if let Some((cond, k_t, k_f)) = self.extract_two_valued_state_key(lhs) {
                let t_bit = pred.eval(k_t, thresh);
                let f_bit = pred.eval(k_f, thresh);
                if t_bit == f_bit {
                    return self.const_u64(u64::from(t_bit));
                }
                let is_bool01 = (self.known_bits(cond).0 & !1u64) == !1u64;
                if t_bit && !f_bit {
                    return if is_bool01 {
                        cond
                    } else {
                        let z = self.const_u64(0);
                        self.cmp(CondPred::Ne, cond, z)
                    };
                }
                return if is_bool01 {
                    self.xor_const(cond, 1)
                } else {
                    let z = self.const_u64(0);
                    self.cmp(CondPred::Eq, cond, z)
                };
            }
        }

        // Known-bits proof on unsigned zero/sign comparisons when possible
        let (zl, ol) = self.known_bits(lhs);
        if let Some(0) = self.as_const(rhs) {
            if ol != 0 && pred == CondPred::Eq {
                return self.const_u64(0);
            }
            if ol != 0 && pred == CondPred::Ne {
                return self.const_u64(1);
            }
            let _ = zl;
        }

        self.intern_node(ExprNode::Cmp { pred, lhs, rhs })
    }

    pub fn select(&mut self, cond: ExprId, mut if_true: ExprId, mut if_false: ExprId) -> ExprId {
        if let Some(c) = self.as_const(cond) {
            return if c != 0 { if_true } else { if_false };
        }
        // A select on the same condition inside one of the arms can only take that
        // arm's side: Select(c, Select(c, a, b), d) -> Select(c, a, d) and
        // Select(c, d, Select(c, a, b)) -> Select(c, d, b). Predicated stack reads
        // and writes that share one predicate nest exactly like this, one level per
        // access; left as they were, codegen emitted every unreachable level (a
        // 232-instruction VM stub came out as 920 native instructions). `cond` is
        // hash-consed, so an id comparison is enough.
        while let ExprNode::Select { cond: c2, if_true: t2, .. } = *self.get(if_true) {
            if c2 != cond {
                break;
            }
            if_true = t2;
        }
        while let ExprNode::Select { cond: c2, if_false: f2, .. } = *self.get(if_false) {
            if c2 != cond {
                break;
            }
            if_false = f2;
        }
        if if_true == if_false {
            return if_true;
        }
        self.intern_node(ExprNode::Select {
            cond,
            if_true,
            if_false,
        })
    }

    pub fn read_slice(&mut self, bitness: u32, full: ExprId, slice: RegSlice) -> ExprId {
        match slice {
            RegSlice::Full64 => full,
            RegSlice::Low32 if bitness == 32 => full,
            RegSlice::Low32 => self.and_const(full, 0xFFFF_FFFF),
            RegSlice::Low16 => self.and_const(full, 0xFFFF),
            RegSlice::Low8 => self.and_const(full, 0xFF),
            RegSlice::High8 => {
                let s = self.shr_const(full, 8);
                self.and_const(s, 0xFF)
            }
        }
    }

    pub fn write_slice(&mut self, prev_full: ExprId, slice: RegSlice, val: ExprId) -> ExprId {
        match slice {
            RegSlice::Full64 => val,
            RegSlice::Low32 => self.and_const(val, 0xFFFF_FFFF),
            RegSlice::Low16 => {
                let hi = self.and_const(prev_full, !0xFFFFu64);
                let lo = self.and_const(val, 0xFFFF);
                self.or(hi, lo)
            }
            RegSlice::Low8 => {
                let hi = self.and_const(prev_full, !0xFFu64);
                let lo = self.and_const(val, 0xFF);
                self.or(hi, lo)
            }
            RegSlice::High8 => {
                let keep = self.and_const(prev_full, !0xFF00u64);
                let lo = self.and_const(val, 0xFF);
                let mid = self.shl_const(lo, 8);
                self.or(keep, mid)
            }
        }
    }

    pub fn as_stack_offset(&self, id: ExprId) -> Option<(StackSpace, i64)> {
        match self.get(id) {
            ExprNode::StackBase => Some((StackSpace::CallerStack, 0)),
            ExprNode::AlignedBase(bid) => Some((StackSpace::AlignedScratch(*bid), 0)),
            ExprNode::Add(base, off_id) => {
                let k = self.as_const(*off_id)? as i64;
                match self.get(*base) {
                    ExprNode::StackBase => Some((StackSpace::CallerStack, k)),
                    ExprNode::AlignedBase(bid) => Some((StackSpace::AlignedScratch(*bid), k)),
                    _ => None,
                }
            }
            ExprNode::Sub(base, off_id) => {
                let k = self.as_const(*off_id)? as i64;
                match self.get(*base) {
                    ExprNode::StackBase => Some((StackSpace::CallerStack, k.wrapping_neg())),
                    ExprNode::AlignedBase(bid) => Some((StackSpace::AlignedScratch(*bid), k.wrapping_neg())),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn contains_opaque(&self, root: ExprId) -> bool {
        let mut seen = HashSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            match self.get(id) {
                ExprNode::Opaque(_) => return true,
                ExprNode::Const(_)
                | ExprNode::RegIn(_)
                | ExprNode::XmmIn(_, _)
                | ExprNode::StackBase
                | ExprNode::EntryRflags
                | ExprNode::AlignedBase(_)
                | ExprNode::CallRet { .. }
                | ExprNode::EntryFlag(_)
                | ExprNode::Cr8Read(_) => {}
                ExprNode::Load { addr, .. } | ExprNode::Not(addr) | ExprNode::Neg(addr) | ExprNode::SExt { val: addr, .. } => {
                    stack.push(*addr);
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
                    stack.push(*a);
                    stack.push(*b);
                }
                ExprNode::Select { cond, if_true, if_false } => {
                    stack.push(*cond);
                    stack.push(*if_true);
                    stack.push(*if_false);
                }
            }
        }
        false
    }

    /// Substitutes all occurrences of `from` with `to` inside `root`, rebuilding through simplifying constructors.
    pub fn substitute(&mut self, root: ExprId, from: ExprId, to: ExprId) -> ExprId {
        if from == to {
            return root;
        }
        let mut memo = HashMap::new();
        self.substitute_memo(root, from, to, &mut memo)
    }

    pub fn substitute_memo(
        &mut self,
        id: ExprId,
        from: ExprId,
        to: ExprId,
        memo: &mut HashMap<ExprId, ExprId>,
    ) -> ExprId {
        if from == to || id == from {
            return if id == from { to } else { id };
        }
        if let Some(&mapped) = memo.get(&id) {
            return mapped;
        }
        if memo.len() >= 2048 {
            return id;
        }
        let node = self.get(id).clone();
        let res = match node {
            ExprNode::Const(_)
            | ExprNode::RegIn(_)
            | ExprNode::XmmIn(_, _)
            | ExprNode::StackBase
            | ExprNode::EntryRflags
            | ExprNode::AlignedBase(_)
            | ExprNode::CallRet { .. }
            | ExprNode::EntryFlag(_)
            | ExprNode::Cr8Read(_)
            | ExprNode::Opaque(_) => id,
            ExprNode::Not(a) => {
                let na = self.substitute_memo(a, from, to, memo);
                if na == a { id } else { self.not(na) }
            }
            ExprNode::Neg(a) => {
                let na = self.substitute_memo(a, from, to, memo);
                if na == a { id } else { self.neg(na) }
            }
            ExprNode::SExt { val, from_bits } => {
                let nv = self.substitute_memo(val, from, to, memo);
                if nv == val { id } else { self.sext(nv, from_bits) }
            }
            ExprNode::Load { addr, width, mem_ver } => {
                let na = self.substitute_memo(addr, from, to, memo);
                if na == addr { id } else { self.load(na, width, mem_ver) }
            }
            ExprNode::Add(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.add(na, nb) }
            }
            ExprNode::Sub(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.sub(na, nb) }
            }
            ExprNode::Mul(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.mul(na, nb) }
            }
            ExprNode::And(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.and(na, nb) }
            }
            ExprNode::Or(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.or(na, nb) }
            }
            ExprNode::Xor(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.xor(na, nb) }
            }
            ExprNode::Shl(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.shl(na, nb) }
            }
            ExprNode::Shr(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.shr(na, nb) }
            }
            ExprNode::Sar(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.sar(na, nb) }
            }
            ExprNode::Rol(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.rol(na, nb) }
            }
            ExprNode::MulHiU(a, b) | ExprNode::MulHiS(a, b) => {
                let signed = matches!(self.get(id), ExprNode::MulHiS(..));
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.mul_hi(na, nb, signed) }
            }
            ExprNode::Ror(a, b) => {
                let na = self.substitute_memo(a, from, to, memo);
                let nb = self.substitute_memo(b, from, to, memo);
                if na == a && nb == b { id } else { self.ror(na, nb) }
            }
            ExprNode::Cmp { pred, lhs, rhs } => {
                let nl = self.substitute_memo(lhs, from, to, memo);
                let nr = self.substitute_memo(rhs, from, to, memo);
                if nl == lhs && nr == rhs { id } else { self.cmp(pred, nl, nr) }
            }
            ExprNode::Select { cond, if_true, if_false } => {
                let nc = self.substitute_memo(cond, from, to, memo);
                let nt = self.substitute_memo(if_true, from, to, memo);
                let nf = self.substitute_memo(if_false, from, to, memo);
                if nc == cond && nt == if_true && nf == if_false {
                    id
                } else {
                    self.select(nc, nt, nf)
                }
            }
        };
        memo.insert(id, res);
        res
    }
}

/// Byte-accurate symbolic stack model supporting 8-byte fast path, 1/2/4-byte sub-slots,
/// arbitrary unaligned cross-qword reads/writes, and 16-byte XMM vector moves.
#[derive(Debug, Clone)]
pub struct SymStack {
    pub slots: HashMap<(StackSpace, i64), ExprId>,
    /// Aligned frames (`AlignedScratch(id)`) made from RSP = caller-stack offset
    /// `poff`: their slots below the aligned base lie below RSP at that moment, free
    /// stack whatever was written there before (an interrupt may overwrite it). Dropped
    /// when a caller-stack write lands below `poff` later (it could be the same memory,
    /// now inside the frame).
    pub fresh_aligned: HashMap<u32, i64>,
}

impl Default for SymStack {
    fn default() -> Self {
        Self::new()
    }
}

impl SymStack {
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            fresh_aligned: HashMap::new(),
        }
    }

    fn read_qword(
        &mut self,
        arena: &mut ExprArena,
        space: StackSpace,
        slot_off: i64,
        mem_ver: u32,
    ) -> ExprId {
        if let Some(&v) = self.slots.get(&(space, slot_off)) {
            return v;
        }
        let expr = match space {
            StackSpace::CallerStack => arena.load_stack(slot_off, 8, mem_ver),
            StackSpace::AlignedScratch(id) => {
                // Below the frame's entry RSP and never written since: the memory there
                // was free stack when the frame began, so its content is undefined (an
                // interrupt could have overwritten it). Any value is one the original
                // could have read; 0 keeps partly written slots exact for their
                // written bytes. Otherwise unknown.
                // `base <= poff <= 0`: a slot wholly below the base ends at or below `poff`,
                // under everything the frame had pushed and under the entry RSP.
                let below_entry =
                    slot_off + 8 <= 0 && self.fresh_aligned.get(&id).is_some_and(|&poff| poff <= 0);
                let v = if below_entry {
                    arena.const_u64(0)
                } else {
                    arena.opaque()
                };
                self.slots.insert((space, slot_off), v);
                v
            }
        };
        expr
    }

    pub fn read_scalar(
        &mut self,
        arena: &mut ExprArena,
        space: StackSpace,
        off: i64,
        width: u8,
        mem_ver: u32,
    ) -> ExprId {
        let w = width.clamp(1, 8);
        let slot_off = off.div_euclid(8) * 8;
        let byte_in_slot = off.rem_euclid(8) as u32;

        if w == 8 && byte_in_slot == 0 {
            return self.read_qword(arena, space, slot_off, mem_ver);
        }

        if byte_in_slot + (w as u32) <= 8 {
            let q = self.read_qword(arena, space, slot_off, mem_ver);
            let shift = (byte_in_slot * 8) as u64;
            let slot_mask = width_mask(w) << shift;
            let masked = arena.and_const(q, slot_mask);
            return if shift == 0 {
                masked
            } else {
                arena.shr_const(masked, shift)
            };
        }

        // Cross-qword unaligned read: stitch low and high slices cleanly.
        let lo_bytes = (8 - byte_in_slot) as u8;
        let hi_bytes = w - lo_bytes;
        let lo = self.read_scalar(arena, space, off, lo_bytes, mem_ver);
        let hi = self.read_scalar(arena, space, off + lo_bytes as i64, hi_bytes, mem_ver);
        let hi_shl = arena.shl_const(hi, (lo_bytes as u64) * 8);
        arena.or(lo, hi_shl)
    }

    pub fn write_scalar(
        &mut self,
        arena: &mut ExprArena,
        space: StackSpace,
        off: i64,
        width: u8,
        val: ExprId,
        mem_ver: u32,
    ) {
        let w = width.clamp(1, 8);
        let slot_off = off.div_euclid(8) * 8;
        let byte_in_slot = off.rem_euclid(8) as u32;
        if space == StackSpace::CallerStack && !self.fresh_aligned.is_empty() {
            self.fresh_aligned.retain(|_, poff| slot_off >= *poff);
        }

        if w == 8 && byte_in_slot == 0 {
            self.slots.insert((space, slot_off), val);
            return;
        }

        if byte_in_slot + (w as u32) <= 8 {
            let prev = self.read_qword(arena, space, slot_off, mem_ver);
            let shift = (byte_in_slot * 8) as u64;
            let val_mask = width_mask(w);
            let slot_mask = val_mask << shift;
            let cleared = arena.and_const(prev, !slot_mask);
            let masked_val = arena.and_const(val, val_mask);
            let inserted = if shift == 0 {
                masked_val
            } else {
                arena.shl_const(masked_val, shift)
            };
            let combined = arena.or(cleared, inserted);
            self.slots.insert((space, slot_off), combined);
            return;
        }

        // Cross-qword unaligned write
        let lo_bytes = (8 - byte_in_slot) as u8;
        let hi_bytes = w - lo_bytes;
        self.write_scalar(arena, space, off, lo_bytes, val, mem_ver);
        let hi_val = arena.shr_const(val, (lo_bytes as u64) * 8);
        self.write_scalar(arena, space, off + lo_bytes as i64, hi_bytes, hi_val, mem_ver);
    }

    /// Records a new aligned frame made from RSP = caller-stack offset `poff` (see
    /// `fresh_aligned`). Caller-stack values written below `poff` earlier do not
    /// matter: RSP has since gone above them, so that memory is free stack too.
    pub fn note_aligned_frame(&mut self, id: u32, poff: i64) {
        self.fresh_aligned.insert(id, poff);
    }

    pub fn read_xmm(
        &mut self,
        arena: &mut ExprArena,
        space: StackSpace,
        off: i64,
        mem_ver: u32,
    ) -> (ExprId, ExprId) {
        let lo = self.read_scalar(arena, space, off, 8, mem_ver);
        let hi = self.read_scalar(arena, space, off + 8, 8, mem_ver);
        (lo, hi)
    }

    pub fn write_xmm(
        &mut self,
        arena: &mut ExprArena,
        space: StackSpace,
        off: i64,
        val: (ExprId, ExprId),
        mem_ver: u32,
    ) {
        self.write_scalar(arena, space, off, 8, val.0, mem_ver);
        self.write_scalar(arena, space, off + 8, 8, val.1, mem_ver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_aligned_slots_read_zero_only_below_entry_and_until_aliased() {
        let mut ar = ExprArena::default();
        let al = StackSpace::AlignedScratch(0);
        // Frame aligned from RSP = entry - 0x10: slots below the base are free stack.
        let mut st = SymStack::new();
        st.note_aligned_frame(0, -0x10);
        let z = st.read_scalar(&mut ar, al, -0x20, 8, 0);
        assert_eq!(ar.as_const(z), Some(0));
        // At or above the base it could be the pushed registers: unknown.
        let up = st.read_scalar(&mut ar, al, 0, 8, 0);
        assert!(ar.contains_opaque(up));
        // A caller-stack write below `poff` may be the same memory: no longer fresh.
        let mut st2 = SymStack::new();
        st2.note_aligned_frame(0, -0x10);
        let v = ar.reg_in(ArchReg::Rcx);
        st2.write_scalar(&mut ar, StackSpace::CallerStack, -0x40, 8, v, 0);
        let u = st2.read_scalar(&mut ar, al, -0x20, 8, 0);
        assert!(ar.contains_opaque(u));
        // Aligned from above the entry RSP: the slot may be the caller's frame.
        let mut st3 = SymStack::new();
        st3.note_aligned_frame(0, 0x20);
        let c = st3.read_scalar(&mut ar, al, -0x20, 8, 0);
        assert!(ar.contains_opaque(c));
        // Written below `poff` before the frame (RSP has gone back above it since):
        // free stack as well.
        let mut st4 = SymStack::new();
        st4.write_scalar(&mut ar, StackSpace::CallerStack, -0x30, 8, v, 0);
        st4.note_aligned_frame(0, -0x10);
        let d = st4.read_scalar(&mut ar, al, -0x20, 8, 0);
        assert_eq!(ar.as_const(d), Some(0));
    }

    #[test]
    fn or_absorbs_by_known_bits_and_cmp_moves_constants() {
        let mut ar = ExprArena::default();
        let rcx = ar.reg_in(ArchReg::Rcx);
        let rdx = ar.reg_in(ArchReg::Rdx);
        let seven = ar.const_u64(7);
        let c = ar.cmp(CondPred::Eq, rcx, seven);
        let one = ar.const_u64(1);
        // Cmp | 1 == 1
        let o = ar.or(c, one);
        assert_eq!(ar.as_const(o), Some(1));
        // (x | 1) | (cmp & cmp) == x | 1
        let x1 = ar.or(rdx, one);
        let c2 = ar.cmp(CondPred::Ult, rdx, seven);
        let cc = ar.and(c, c2);
        let o2 = ar.or(x1, cc);
        assert_eq!(o2, x1);
        // nothing known: stays an Or
        let o3 = ar.or(rcx, rdx);
        assert!(matches!(ar.get(o3), ExprNode::Or(..)));

        // (y + K) == K  ->  y == 0
        let k = ar.const_u64(0xa2ce_8c06_44a8_8de0);
        let y = ar.or(rcx, rdx);
        let yk = ar.add(y, k);
        let e = ar.cmp(CondPred::Eq, yk, k);
        let zero = ar.const_u64(0);
        let want = ar.cmp(CondPred::Eq, y, zero);
        assert_eq!(e, want);
        // (y ^ K1) != K2  ->  y != K1 ^ K2, constant on the left too
        let k1 = ar.const_u64(0x55);
        let k2 = ar.const_u64(0x0f);
        let yx = ar.xor(y, k1);
        let ne = ar.cmp(CondPred::Ne, k2, yx);
        let k12 = ar.const_u64(0x55 ^ 0x0f);
        let want_ne = ar.cmp(CondPred::Ne, y, k12);
        assert_eq!(ne, want_ne);
    }

    #[test]
    fn complementary_cmps_fold_to_constants() {
        let mut ar = ExprArena::default();
        let rcx = ar.reg_in(ArchReg::Rcx);
        let rdx = ar.reg_in(ArchReg::Rdx);
        let k = ar.const_u64(0x34be_9087_0652_2217);
        let s = ar.sub(rcx, rdx);
        let eq = ar.cmp(CondPred::Eq, s, k);
        let ne = ar.cmp(CondPred::Ne, s, k);
        let or = ar.or(eq, ne);
        let and = ar.and(eq, ne);
        let xor = ar.xor(ne, eq);
        assert_eq!(ar.as_const(or), Some(1), "x==k | x!=k is always 1");
        assert_eq!(ar.as_const(and), Some(0), "x==k & x!=k is always 0");
        assert_eq!(ar.as_const(xor), Some(1), "x==k ^ x!=k is always 1");

        // swapped operands: a < b is the opposite of b <= a
        let lt = ar.cmp(CondPred::Ult, rcx, rdx);
        let le_swapped = ar.cmp(CondPred::Ule, rdx, rcx);
        let o2 = ar.or(lt, le_swapped);
        assert_eq!(ar.as_const(o2), Some(1));
        // not complementary: stays symbolic
        let gt = ar.cmp(CondPred::Ugt, rcx, rdx);
        let o3 = ar.or(lt, gt);
        assert_eq!(ar.as_const(o3), None);
    }

    #[test]
    fn mba_identities_and_opaque_predicates_collapse() {
        let mut a = ExprArena::default();
        let x = a.reg_in(ArchReg::Rcx);
        let y = a.reg_in(ArchReg::Rdx);

        // (x ^ y) + 2*(x & y) == x + y
        let c2 = a.const_u64(2);
        let xor_xy = a.xor(x, y);
        let and_xy = a.and(x, y);
        let mul_2 = a.mul(and_xy, c2);
        let mba1 = a.add(xor_xy, mul_2);
        assert_eq!(mba1, a.add(x, y));

        // (x ^ y) + ((x & y) << 1) == x + y
        let shl_1 = a.shl_const(and_xy, 1);
        assert_eq!(a.add(xor_xy, shl_1), a.add(x, y));

        // (x | y) - (x & y) == x ^ y
        let or_xy = a.or(x, y);
        assert_eq!(a.sub(or_xy, and_xy), xor_xy);

        // (x + y) - (x | y) == x & y
        let sum_xy = a.add(x, y);
        assert_eq!(a.sub(sum_xy, or_xy), and_xy);

        // (x & ~y) | (~x & y) == x ^ y
        let nx = a.not(x);
        let ny = a.not(y);
        let t1 = a.and(x, ny);
        let t2 = a.and(nx, y);
        assert_eq!(a.or(t1, t2), xor_xy);

        // (x & y) | (x & ~y) == x
        assert_eq!(a.or(and_xy, t1), x);

        // Opaque predicate: (x * (x - 1)) & 1 == 0
        let xm1 = a.sub_const(x, 1);
        let prod = a.mul(x, xm1);
        let parity = a.and_const(prod, 1);
        assert_eq!(a.as_const(parity), Some(0));

        // EAC rolling-key pattern: ((c1 ^ x) + k1 - (c2 ^ x)) * (x & 0) + r -> r
        let k_zero = a.and_const(x, 0);
        let z_prod = a.mul(mba1, k_zero);
        let final_expr = a.add(z_prod, y);
        assert_eq!(final_expr, y);

        // Rolling XOR & ADD reassociation
        let x1 = a.xor_const(x, 0xAAAA_5555);
        let x2 = a.xor_const(x1, 0xAAAA_5555);
        assert_eq!(x2, x);
        let a1 = a.add_const(x, 0x100);
        let a2 = a.sub_const(a1, 0x100);
        assert_eq!(a2, x);

        // Select distribution + Cmp(and(..., 0xff)) collapse
        let c10 = a.const_u64(10);
        let cmp = a.cmp(CondPred::Ugt, x, c10);
        let zext_cmp = a.and_const(cmp, 0xFF);
        assert_eq!(zext_cmp, cmp);
        let t_branch = a.const_u64(0x1000);
        let f_branch = a.const_u64(0x2000);
        let sel = a.select(cmp, t_branch, f_branch);
        let reloc_sel = a.add_const(sel, 0x1_4000_0000);
        let exp_t = a.const_u64(0x1_4000_1000);
        let exp_f = a.const_u64(0x1_4000_2000);
        let exp_sel = a.select(cmp, exp_t, exp_f);
        assert_eq!(reloc_sel, exp_sel);
    }

    #[test]
    fn sym_stack_preserves_unaligned_xmm_and_sub_qword_slots() {
        let mut a = ExprArena::default();
        let mut st = SymStack::new();
        let sp = StackSpace::CallerStack;

        let rbx = a.reg_in(ArchReg::Rbx);
        let rcx = a.reg_in(ArchReg::Rcx);
        let xmm3 = (a.xmm_in(3, false), a.xmm_in(3, true));

        // Simulate ctx_save writing GPRs at -0x98, -0x88 and unaligned 16-byte XMM at -0xA8
        st.write_scalar(&mut a, sp, -0x98, 8, rbx, 0);
        st.write_scalar(&mut a, sp, -0x88, 8, rcx, 0);
        st.write_xmm(&mut a, sp, -0xA8, xmm3, 0);

        // Copy loop (like epstain.sys 0x373b2d): movups from -0xA8..-0x78 into -0x1A8..-0x178
        for step in (0..=0x20).step_by(0x10) {
            let v = st.read_xmm(&mut a, sp, -0xA8 + step, 0);
            st.write_xmm(&mut a, sp, -0x1A8 + step, v, 0);
        }

        // Restore GPRs & XMM from shifted frame
        assert_eq!(st.read_xmm(&mut a, sp, -0x1A8, 0), xmm3);
        assert_eq!(st.read_scalar(&mut a, sp, -0x198, 8, 0), rbx);
        assert_eq!(st.read_scalar(&mut a, sp, -0x188, 8, 0), rcx);

        // Sub-qword write/read round-trip (dword + word + byte)
        let d_val = a.const_u64(0x1122_3344);
        let w_val = a.const_u64(0xAABB);
        st.write_scalar(&mut a, sp, -0x40, 4, d_val, 0);
        st.write_scalar(&mut a, sp, -0x3C, 2, w_val, 0);
        assert_eq!(st.read_scalar(&mut a, sp, -0x40, 4, 0), d_val);
        assert_eq!(st.read_scalar(&mut a, sp, -0x3C, 2, 0), w_val);
        assert_eq!(st.read_scalar(&mut a, sp, -0x3F, 1, 0), a.const_u64(0x33));
    }

    #[test]
    fn linear_sum_cancels_obfuscated_stack_frame_offsets() {
        let mut a = ExprArena::default();
        let sb = a.stack_base();
        let ab = a.aligned_base(0);
        let rsi = a.reg_in(ArchReg::Rsi);

        // ((StackBase + rsi) + ((AlignedBase - 0x10) - StackBase - rsi + 0x54e93451eb5e5c2f)) + 0xab16cbae14a1a3d1
        let lhs = a.add(sb, rsi);
        let t1 = a.sub_const(ab, 0x10);
        let t2 = a.sub(t1, sb);
        let t3 = a.sub(t2, rsi);
        let t4 = a.add_const(t3, 0x54e9_3451_eb5e_5c2f);
        let combined = a.add(lhs, t4);
        let collapsed = a.add_const(combined, 0xab16_cbae_14a1_a3d1);

        assert_eq!(a.as_stack_offset(collapsed), Some((StackSpace::AlignedScratch(0), -0x10)));
    }

    #[test]
    fn weighted_linear_zero_and_state_key_cmp_collapse() {
        let mut a = ExprArena::default();
        let rcx = a.reg_in(ArchReg::Rcx);
        let c10 = a.const_u64(10);
        let b = a.cmp(CondPred::Ugt, rcx, c10);

        // Weighted linear sum: (0x270f125b1bbee887 + 0x820ed57c4ad8c58e * b) + (0xd8f0eda4e4411751 + 0x7df12a83b5273a72 * b) == -0x28
        let k1 = a.const_u64(0x820e_d57c_4ad8_c58e);
        let k2 = a.const_u64(0x7df1_2a83_b527_3a72);
        let m1 = a.mul(b, k1);
        let m2 = a.mul(b, k2);
        let p1 = a.add_const(m1, 0x270f_125b_1bbe_e887);
        let p2 = a.add_const(m2, 0xd8f0_eda4_e441_1751);
        let sum = a.add(p1, p2);
        assert_eq!(a.as_const(sum), Some(0xffff_ffff_ffff_ffd8));

        // 2-valued arithmetic state-key threshold comparisons collapse directly back to `b` / `!b` / const
        let delta = a.const_u64(0x1000);
        let scaled = a.mul(b, delta);
        let key = a.add_const(scaled, 0x1000); // b ? 0x2000 : 0x1000
        let th_mid = a.const_u64(0x1500);
        let th_hi = a.const_u64(0x3000);
        let cmp_gt = a.cmp(CondPred::Ugt, key, th_mid);
        let cmp_lt = a.cmp(CondPred::Ult, key, th_mid);
        let exp_le = a.cmp(CondPred::Ule, rcx, c10);
        let cmp_hi = a.cmp(CondPred::Ugt, key, th_hi);
        assert_eq!(cmp_gt, b);
        assert_eq!(cmp_lt, exp_le);
        assert_eq!(a.as_const(cmp_hi), Some(0));

        // 40-deep shared Select DAG followed by mask/add completes without exponential blowup
        let mut s = a.reg_in(ArchReg::Rax);
        for _ in 0..40 {
            let p = a.add_const(s, 1);
            s = a.select(b, p, s);
        }
        let masked = a.and_const(s, 0xFFFF_FFFF);
        let shifted = a.add_const(masked, 0x1234);
        assert!(a.as_const(shifted).is_none());
    }

    #[test]
    fn sym_stack_unaligned_byte_writes_on_aligned_scratch_do_not_leak_opaque() {
        let mut a = ExprArena::default();
        let mut stack = SymStack::new();
        let rax = a.reg_in(ArchReg::Rax);
        let rbx = a.reg_in(ArchReg::Rbx);
        let rcx = a.reg_in(ArchReg::Rcx);
        let c1 = a.const_u64(1);
        let c2 = a.const_u64(2);
        let c3 = a.const_u64(3);
        let b0 = a.cmp(CondPred::Eq, rax, c1);
        let b1 = a.cmp(CondPred::Eq, rbx, c2);
        let b2 = a.cmp(CondPred::Eq, rcx, c3);

        let sp = StackSpace::AlignedScratch(0);
        stack.write_scalar(&mut a, sp, -9, 1, b0, 0);
        stack.write_scalar(&mut a, sp, -11, 1, b1, 0);
        stack.write_scalar(&mut a, sp, -10, 1, b2, 0);

        for (off, expected) in [(-9, b0), (-11, b1), (-10, b2)] {
            let v = stack.read_scalar(&mut a, sp, off, 1, 0);
            assert!(!a.contains_opaque(v), "slot {off} leaked Opaque: {:?}", a.get(v));
            assert_eq!(a.known_bits(v).0 & !1u64, !1u64);
            assert_eq!(v, expected);
        }

        // Verify substitute collapses boolean-guarded polynomial cleanly
        let delta = a.const_u64(0x100);
        let prod = a.mul(b0, delta);
        let expr = a.add_const(prod, 0x4000);
        let zero = a.const_u64(0);
        let one = a.const_u64(1);
        let s0 = a.substitute(expr, b0, zero);
        assert_eq!(a.as_const(s0), Some(0x4000));
        let s1 = a.substitute(expr, b0, one);
        assert_eq!(a.as_const(s1), Some(0x4100));
    }

    #[test]
    fn sym_stack_unaligned_all_offsets_round_trip_without_leak() {
        for rem in 1i64..8 {
            let mut a = ExprArena::default();
            let xmm12 = a.xmm_in(12, false);
            let samples = [
                a.const_u64(0x140002B67),
                a.stack_base(),
                a.reg_in(ArchReg::Rcx),
                a.xmm_in(3, false),
            ];
            for &val in &samples {
                let mut stack = SymStack::new();
                stack.write_scalar(&mut a, StackSpace::CallerStack, -0x10, 8, xmm12, 0);
                stack.write_scalar(&mut a, StackSpace::CallerStack, -0x18 + rem, 8, val, 0);
                let got = stack.read_scalar(&mut a, StackSpace::CallerStack, -0x18 + rem, 8, 0);
                assert_eq!(got, val, "unaligned offset rem={rem} failed round-trip: {:?}", a.get(got));
            }
        }
    }
}
