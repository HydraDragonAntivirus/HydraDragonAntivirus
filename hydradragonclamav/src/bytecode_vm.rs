//! ClamBC bytecode virtual machine.
//!
//! **Phase 1 — faithful decoder of the `.cbc` program format.**
//!
//! ClamAV bytecode is a compiled program (ClamAV's own bytecode, derived from
//! LLVM) that runs in a VM to make complex detection decisions. The textual
//! `.cbc` body is a nibble-armored encoding: every "digit" byte is `0x60 | nib`
//! (`` ` ``=0, `a`=1 … `o`=15). This module ports ClamAV's reader
//! (`clamav/libclamav/bytecode.c`: `readNumber`/`readOperand`/`parse*`) into the
//! in-memory program model used by the interpreter.
//!
//! Decoder only — execution lives in the interpreter phase. A decoded program is
//! not a detection by itself: its trigger logical signature gates it and the
//! program body makes the verdict (see [`crate::bytecode`]).

// ---------------------------------------------------------------------------
// Opcodes (clambc.h `enum bc_opcode`)
// ---------------------------------------------------------------------------
pub const OP_BC_ADD: u16 = 1;
pub const OP_BC_SUB: u16 = 2;
pub const OP_BC_MUL: u16 = 3;
pub const OP_BC_UDIV: u16 = 4;
pub const OP_BC_SDIV: u16 = 5;
pub const OP_BC_UREM: u16 = 6;
pub const OP_BC_SREM: u16 = 7;
pub const OP_BC_SHL: u16 = 8;
pub const OP_BC_LSHR: u16 = 9;
pub const OP_BC_ASHR: u16 = 10;
pub const OP_BC_AND: u16 = 11;
pub const OP_BC_OR: u16 = 12;
pub const OP_BC_XOR: u16 = 13;
pub const OP_BC_TRUNC: u16 = 14;
pub const OP_BC_SEXT: u16 = 15;
pub const OP_BC_ZEXT: u16 = 16;
pub const OP_BC_BRANCH: u16 = 17;
pub const OP_BC_JMP: u16 = 18;
pub const OP_BC_RET: u16 = 19;
pub const OP_BC_RET_VOID: u16 = 20;
pub const OP_BC_ICMP_EQ: u16 = 21;
pub const OP_BC_ICMP_NE: u16 = 22;
pub const OP_BC_ICMP_UGT: u16 = 23;
pub const OP_BC_ICMP_UGE: u16 = 24;
pub const OP_BC_ICMP_ULT: u16 = 25;
pub const OP_BC_ICMP_ULE: u16 = 26;
pub const OP_BC_ICMP_SGT: u16 = 27;
pub const OP_BC_ICMP_SGE: u16 = 28;
pub const OP_BC_ICMP_SLE: u16 = 29;
pub const OP_BC_ICMP_SLT: u16 = 30;
pub const OP_BC_SELECT: u16 = 31;
pub const OP_BC_CALL_DIRECT: u16 = 32;
pub const OP_BC_CALL_API: u16 = 33;
pub const OP_BC_COPY: u16 = 34;
pub const OP_BC_GEP1: u16 = 35;
pub const OP_BC_GEPZ: u16 = 36;
pub const OP_BC_GEPN: u16 = 37;
pub const OP_BC_STORE: u16 = 38;
pub const OP_BC_LOAD: u16 = 39;
pub const OP_BC_MEMSET: u16 = 40;
pub const OP_BC_MEMCPY: u16 = 41;
pub const OP_BC_MEMMOVE: u16 = 42;
pub const OP_BC_MEMCMP: u16 = 43;
pub const OP_BC_ISBIGENDIAN: u16 = 44;
pub const OP_BC_ABORT: u16 = 45;
pub const OP_BC_BSWAP16: u16 = 46;
pub const OP_BC_BSWAP32: u16 = 47;
pub const OP_BC_BSWAP64: u16 = 48;
pub const OP_BC_PTRDIFF32: u16 = 49;
pub const OP_BC_PTRTOINT64: u16 = 50;
pub const OP_BC_INVALID: u16 = 51;

/// Fixed operand counts per opcode (clambc.h `operand_counts[]`), index 0 unused.
const OPERAND_COUNTS: [u8; 51] = [
    0, // (unused)
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // ADD..XOR
    1, 1, 1, // TRUNC..ZEXT
    3, 1, 1, 0, // BRANCH, JMP, RET, RET_VOID
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // ICMP
    3, // SELECT
    0, 0, // CALL_DIRECT, CALL_API (variable)
    2, // COPY
    3, 3, 0, 2, 1, // GEP1, GEPZ, GEPN, STORE, LOAD
    3, 3, 3, 3, // MEM*
    0, // ISBIGENDIAN
    0, 1, 1, 1, 2, 1, // ABORT, BSWAP16/32/64, PTRDIFF32, PTRTOINT64
];

/// First non-static type id (clambc.h `BC_START_TID`).
pub const BC_START_TID: u16 = 69;
/// Static types occupy ids 65..69 (the four pointer-to-int types).
const NUM_STATIC_TYPES: usize = 4;
/// Supported `.cbc` format levels (clambc.h `BC_FORMAT_096` / `BC_FORMAT_LEVEL`).
const BC_FORMAT_096: u64 = 6;
const BC_FORMAT_LEVEL: u64 = 7;
const HEADER_MAGIC1: u64 = 0x53e5_493e_9f3d_1c30;
const HEADER_MAGIC2: u64 = 42;

// ---------------------------------------------------------------------------
// Program model (bytecode_priv.h structs)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Function,
    PackedStruct,
    Struct,
    Array,
    Pointer,
}

#[derive(Clone, Debug)]
pub struct BcType {
    pub kind: TypeKind,
    pub num_elements: u32,
    pub contained: Vec<u16>,
    pub size: u32,
    pub align: u32,
}

/// The decoded operands of an instruction (the `cli_bc_inst` union).
#[derive(Clone, Debug)]
pub enum Ops {
    None,
    Unary(u32),
    Binop([u32; 2]),
    Three([u32; 3]),
    /// TRUNC/SEXT/ZEXT (`cli_bc_cast`).
    Cast { source: u32, mask: u64, size: u8 },
    Branch { condition: u32, br_true: u16, br_false: u16 },
    Jump(u16),
    /// CALL_DIRECT / CALL_API.
    Call { funcid: u16, is_api: bool, ops: Vec<u32> },
    /// GEPN: `ops[0]` is a raw number (element count), the rest are operands.
    GepN(Vec<u32>),
}

#[derive(Clone, Debug)]
pub struct BcInst {
    pub opcode: u16,
    pub ty: u16,
    pub dest: u32,
    pub interp_op: u8,
    pub ops: Ops,
}

#[derive(Clone, Debug, Default)]
pub struct BcBB {
    pub insts: Vec<BcInst>,
}

#[derive(Clone, Debug, Default)]
pub struct BcFunc {
    pub num_args: u8,
    pub num_locals: u32,
    pub num_insts: u32,
    pub num_values: u32,
    pub num_constants: u32,
    pub return_type: u16,
    /// arg+local types; bit 0x8000 marks a pointer local.
    pub types: Vec<u16>,
    pub bbs: Vec<BcBB>,
    pub constants: Vec<u64>,
    /// Stack-frame byte size (`numBytes`), computed by the interpreter prep pass.
    pub num_bytes: u32,
    insn_idx: u32,
}

impl BcFunc {
    fn optype(&self, op: u32) -> i16 {
        let n = self.num_args as u32 + self.num_locals;
        if op >= n {
            0
        } else {
            (self.types[op as usize] & 0x7fff) as i16
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Bc {
    pub format_level: u64,
    pub kind: u64,
    pub min_func: u64,
    pub max_func: u64,
    pub num_types: u32,
    pub num_func: u32,
    pub start_tid: u16,
    pub types: Vec<BcType>,
    pub funcs: Vec<BcFunc>,
    /// API ids this program declares it uses (`uses_apis` bitset), recorded so the
    /// interpreter can validate `CALL_API` targets.
    pub uses_apis: Vec<u32>,
    /// Declared API calls as `(id, name)` for later prototype binding.
    pub apis: Vec<(u32, String)>,
    pub globals: Vec<Vec<u64>>,
    pub global_tys: Vec<u16>,
    pub lsig: Option<String>,
    pub hook_name: Option<String>,
    /// True when the program was skipped (unsupported format/API/global level).
    pub skipped: bool,
    /// Interpreter prep results (filled by [`Bc::prepare_interpreter`]).
    pub num_global_bytes: u32,
    pub global_bytes: Vec<u8>,
    pub prepared: bool,
}

/// ClamAV engine functionality level (`CL_FLEVEL` in others.h). Signatures whose
/// required f-level falls outside `[min,max]` are skipped at load.
pub const ENGINE_FLEVEL: u32 = 240;

// Predefined globals (clambc.h `enum bc_global`).
const FIRST_GLOBAL: u64 = 0x8000;
const LAST_GLOBAL: u64 = 0x8006;
/// `cli_apicall_maxglobal` == `_LAST_GLOBAL`.
const APICALL_MAXGLOBAL: u64 = LAST_GLOBAL;

// ---------------------------------------------------------------------------
// Nibble-armored readers (bytecode.c readNumber / readFixedNumber / ...)
// ---------------------------------------------------------------------------

/// Cursor over one decoded line. The reader mutates the line in place exactly as
/// ClamAV does (`p[*off] |= 0x20` to re-tag constant operands), so it owns a
/// mutable byte slice.
struct Reader<'a> {
    buf: &'a mut [u8],
    off: usize,
    ok: bool,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Reader { buf, off: 0, ok: true }
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn at(&self, i: usize) -> u8 {
        self.buf.get(i).copied().unwrap_or(0)
    }

    /// `readNumber`: variable-length nibble integer. First byte `0x60+count` gives
    /// the nibble count; each following byte is `0x60|nibble`, little-endian.
    fn read_number(&mut self) -> u64 {
        if !self.ok || self.off >= self.buf.len() {
            self.ok = false;
            return 0;
        }
        let p0 = self.buf[self.off];
        let lim = p0.wrapping_sub(0x60) as usize;
        if lim > 0x10 {
            self.ok = false;
            return 0;
        }
        let newoff = self.off + lim + 1;
        if newoff > self.len() {
            self.ok = false;
            return 0;
        }
        if p0 == 0x60 {
            self.off = newoff;
            return 0;
        }
        let mut n: u64 = 0;
        let mut shift = 0u32;
        for i in (self.off + 1)..newoff {
            let v = self.buf[i];
            if (v & 0xf0) != 0x60 {
                self.ok = false;
                return 0;
            }
            n |= ((v & 0xf) as u64) << shift;
            shift += 4;
        }
        self.off = newoff;
        n
    }

    /// `readFixedNumber`: exactly `width` nibble bytes.
    fn read_fixed(&mut self, width: usize) -> u64 {
        let newoff = self.off + width;
        if newoff > self.len() {
            self.ok = false;
            return 0;
        }
        let mut n: u64 = 0;
        let mut shift = 0u32;
        for i in self.off..newoff {
            let v = self.buf[i];
            if (v & 0xf0) != 0x60 {
                self.ok = false;
                return 0;
            }
            n |= ((v & 0xf) as u64) << shift;
            shift += 4;
        }
        self.off = newoff;
        n
    }

    /// `readData`: `|` then a nibble length `l`, then `2*l` nibble bytes → `l`
    /// raw bytes (low nibble first).
    fn read_data(&mut self) -> Option<Vec<u8>> {
        if self.at(self.off) != b'|' {
            self.ok = false;
            return None;
        }
        self.off += 1;
        let l = self.read_number() as usize;
        if !self.ok {
            return None;
        }
        if l == 0 {
            return Some(Vec::new());
        }
        let newoff = self.off + 2 * l;
        if newoff > self.len() {
            self.ok = false;
            return None;
        }
        let mut out = Vec::with_capacity(l);
        let mut i = self.off;
        while i < newoff {
            let v0 = self.buf[i];
            let v1 = self.buf[i + 1];
            if (v0 & 0xf0) != 0x60 || (v1 & 0xf0) != 0x60 {
                self.ok = false;
                return None;
            }
            out.push((v0 & 0xf) | ((v1 & 0xf) << 4));
            i += 2;
        }
        self.off = newoff;
        Some(out)
    }

    /// `readString`: data that must be NUL-terminated; the NUL is stripped.
    fn read_string(&mut self) -> Option<String> {
        let data = self.read_data()?;
        if data.is_empty() {
            return Some(String::new());
        }
        if *data.last().unwrap() != 0 {
            self.ok = false;
            return None;
        }
        Some(String::from_utf8_lossy(&data[..data.len() - 1]).into_owned())
    }

    fn read_type_id(&mut self, bc: &Bc) -> u16 {
        let t = self.read_number();
        if !self.ok {
            return u16::MAX;
        }
        if t >= (bc.num_types + bc.start_tid as u32) as u64 {
            self.ok = false;
            return u16::MAX;
        }
        t as u16
    }

    fn read_bb_id(&mut self, num_bb: usize) -> u16 {
        let id = self.read_number() as usize;
        if id == 0 || id >= num_bb {
            self.ok = false;
            return u16::MAX;
        }
        id as u16
    }
}

/// `readOperand`: either a value reference (index `< numValues`) or an inline
/// constant (first byte tagged `0x4X`/`0x50`). A constant is appended to the
/// function's constant pool and addressed as `numValues + constIndex`. A type of
/// 0 marks a global variable, returned as `0x80000000 | value`.
fn read_operand(r: &mut Reader, func: &mut BcFunc) -> u32 {
    let b = r.at(r.off);
    if (b & 0xf0) == 0x40 || b == 0x50 {
        // Re-tag the constant marker so read_number sees a valid number byte.
        r.buf[r.off] |= 0x20;
        let v = r.read_number();
        let ty = 8 * r.read_fixed(1);
        if ty == 0 {
            // Global variable reference.
            return 0x8000_0000 | (v as u32);
        }
        // Truncate the constant to its declared type width (matches ClamAV's
        // type-correct store on big-endian hosts).
        let stored = if ty <= 8 {
            v & 0xff
        } else if ty <= 16 {
            v & 0xffff
        } else if ty <= 32 {
            v & 0xffff_ffff
        } else {
            v
        };
        func.constants.push(stored);
        let idx = func.num_values + func.num_constants;
        func.num_constants += 1;
        return idx;
    }
    let v = r.read_number();
    if !r.ok {
        return u32::MAX;
    }
    if v >= func.num_values as u64 {
        r.ok = false;
        return u32::MAX;
    }
    v as u32
}

// ---------------------------------------------------------------------------
// Line parsers (bytecode.c parseHeader / parseTypes / ... )
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum DecodeError {
    Malformed(String),
    /// Program intentionally skipped (unsupported format / API / flevel).
    Skip(String),
}

type DResult<T> = Result<T, DecodeError>;

fn malformed(msg: impl Into<String>) -> DecodeError {
    DecodeError::Malformed(msg.into())
}

/// Parse the `ClamBC` header line, populating metadata and `num_types/num_func`.
/// Returns the declared per-line buffer length.
fn parse_header(bc: &mut Bc, line: &mut [u8]) -> DResult<usize> {
    if !line.starts_with(b"ClamBC") {
        return Err(malformed("missing ClamBC magic"));
    }
    let mut r = Reader::new(line);
    r.off = b"ClamBC".len();

    bc.format_level = r.read_number();
    if !r.ok {
        return Err(malformed("bad format level"));
    }
    if bc.format_level != BC_FORMAT_096 && bc.format_level != BC_FORMAT_LEVEL {
        return Err(DecodeError::Skip(format!(
            "unsupported format level {}",
            bc.format_level
        )));
    }
    let _timestamp = r.read_number();
    let _sigmaker = r.read_string();
    let _target_exclude = r.read_number();
    bc.kind = r.read_number();
    bc.min_func = r.read_number();
    bc.max_func = r.read_number();
    let _maxresource = r.read_number();
    let _compiler = r.read_string();
    bc.num_types = r.read_number() as u32;
    bc.num_func = r.read_number() as u32;
    if !r.ok {
        return Err(malformed("invalid bytecode header"));
    }
    let magic1 = r.read_number();
    let magic2 = r.read_fixed(2);
    if !r.ok || magic1 != HEADER_MAGIC1 || magic2 != HEADER_MAGIC2 {
        return Err(malformed("header magic mismatch"));
    }
    if r.at(r.off) != b':' {
        return Err(malformed("expected ':' after header magic"));
    }
    r.off += 1;
    // The remainder is a decimal line-length.
    let rest = &r.buf[r.off..];
    let s = std::str::from_utf8(rest).map_err(|_| malformed("bad line length"))?;
    let linelen: usize = s
        .trim()
        .parse()
        .map_err(|_| malformed("invalid line length"))?;

    bc.funcs = vec![BcFunc::default(); bc.num_func as usize];
    bc.types = vec![
        BcType {
            kind: TypeKind::Pointer,
            num_elements: 0,
            contained: Vec::new(),
            size: 0,
            align: 0,
        };
        bc.num_types as usize
    ];
    Ok(linelen)
}

/// Parse the logical-signature trigger line (`name;TDB;expr;subsigs…`).
fn parse_lsig(bc: &mut Bc, line: &[u8]) {
    let text = String::from_utf8_lossy(line).into_owned();
    if text.contains(';') {
        bc.lsig = Some(text);
    } else {
        bc.hook_name = Some(text);
    }
}

/// Static types: ids 65..69 are pointer-to-{i8,i16,i32,i64}.
fn add_static_types(bc: &mut Bc) {
    const CONTAINED: [u16; NUM_STATIC_TYPES] = [8, 16, 32, 64];
    for (i, c) in CONTAINED.iter().enumerate() {
        if i < bc.types.len() {
            bc.types[i] = BcType {
                kind: TypeKind::Pointer,
                num_elements: 1,
                contained: vec![*c],
                size: 8,
                align: 8,
            };
        }
    }
}

fn parse_types(bc: &mut Bc, line: &mut [u8]) -> DResult<()> {
    if line.first() != Some(&b'T') {
        return Err(malformed("invalid types header"));
    }
    let mut r = Reader::new(line);
    r.off = 1;
    bc.start_tid = r.read_fixed(2) as u16;
    if bc.start_tid != BC_START_TID {
        return Err(DecodeError::Skip("type start id mismatch".into()));
    }
    add_static_types(bc);
    let first = (BC_START_TID - 65) as usize;
    let last = bc.num_types.saturating_sub(1) as usize;
    for i in first..last {
        let t = r.read_fixed(1);
        if !r.ok {
            return Err(malformed("error reading type kind"));
        }
        match t {
            1 => {
                let ne = r.read_number() as u32;
                let mut contained = Vec::with_capacity(ne as usize);
                for _ in 0..ne {
                    contained.push(r.read_type_id(bc));
                }
                if !r.ok || ne == 0 {
                    return Err(malformed("error parsing function type"));
                }
                bc.types[i] = BcType {
                    kind: TypeKind::Function,
                    num_elements: ne,
                    contained,
                    size: 8,
                    align: 8,
                };
            }
            2 | 3 => {
                let ne = r.read_number() as u32;
                let mut contained = Vec::with_capacity(ne as usize);
                for _ in 0..ne {
                    contained.push(r.read_type_id(bc));
                }
                if !r.ok {
                    return Err(malformed("error parsing struct type"));
                }
                bc.types[i] = BcType {
                    kind: if t == 2 {
                        TypeKind::PackedStruct
                    } else {
                        TypeKind::Struct
                    },
                    num_elements: ne,
                    contained,
                    size: 0,
                    align: 8,
                };
            }
            4 | 5 => {
                let (kind, num_elements) = if t == 4 {
                    let ne = r.read_number() as u32;
                    (TypeKind::Array, ne)
                } else {
                    (TypeKind::Pointer, 1)
                };
                let contained = vec![r.read_type_id(bc)];
                if !r.ok {
                    return Err(malformed("error parsing array/pointer type"));
                }
                let (size, align) = if t == 5 {
                    (8, 8)
                } else {
                    (0, 0) // array sizes resolved in the second pass
                };
                bc.types[i] = BcType {
                    kind,
                    num_elements,
                    contained,
                    size,
                    align,
                };
            }
            other => return Err(malformed(format!("invalid type kind {other}"))),
        }
    }
    // Second pass: resolve array sizes/alignment now that all types exist.
    for i in first..last {
        if bc.types[i].kind == TypeKind::Array {
            let inner = bc.types[i].contained.first().copied().unwrap_or(0);
            let elsize = type_size(bc, inner);
            bc.types[i].size = bc.types[i].num_elements * elsize;
            bc.types[i].align = type_align(bc, inner);
        }
    }
    Ok(())
}

/// `typesize` (bytecode.c:276) — byte size of a type id. The `0x8000` alloca flag
/// is masked off; integer widths 1..64 map to 1/2/4/8 bytes; struct/array sizes
/// are computed from their components.
fn type_size(bc: &Bc, tid: u16) -> u32 {
    let t = tid & 0x7fff;
    if t == 0 {
        return 0;
    }
    if t <= 8 {
        return 1;
    }
    if t <= 16 {
        return 2;
    }
    if t <= 32 {
        return 4;
    }
    if t <= 64 {
        return 8;
    }
    let ty = match bc.types.get((t - 65) as usize) {
        Some(ty) => ty,
        None => return 0,
    };
    if ty.size != 0 {
        return ty.size;
    }
    match ty.kind {
        TypeKind::Struct | TypeKind::PackedStruct => {
            ty.contained.iter().map(|&c| type_size(bc, c)).sum()
        }
        TypeKind::Array => ty.num_elements * type_size(bc, ty.contained.first().copied().unwrap_or(0)),
        _ => 0,
    }
}

/// `typealign` (bytecode.c:313).
fn type_align(bc: &Bc, tid: u16) -> u32 {
    let t = tid & 0x7fff;
    if t <= 64 {
        let s = type_size(bc, t);
        return if s != 0 { s } else { 1 };
    }
    bc.types
        .get((t - 65) as usize)
        .map(|ty| ty.align)
        .unwrap_or(1)
        .max(1)
}

/// Number of leaf components of a type (used to size constant global initializers).
fn type_components(bc: &Bc, id: u16) -> Option<u32> {
    if id <= 64 {
        return Some(1);
    }
    let ty = bc.types.get((id - 65) as usize)?;
    match ty.kind {
        TypeKind::Function => None,
        TypeKind::Pointer => Some(2),
        TypeKind::Struct | TypeKind::PackedStruct => {
            let mut sum = 0;
            for &c in &ty.contained {
                sum += type_components(bc, c)?;
            }
            Some(sum)
        }
        TypeKind::Array => Some(type_components(bc, ty.contained[0])? * ty.num_elements),
    }
}

fn parse_apis(bc: &mut Bc, line: &mut [u8]) -> DResult<()> {
    if line.first() != Some(&b'E') {
        return Err(malformed("invalid api header"));
    }
    let mut r = Reader::new(line);
    r.off = 1;
    let _maxapi = r.read_number();
    if !r.ok {
        return Err(malformed("bad maxapi"));
    }
    let calls = r.read_number();
    if !r.ok {
        return Err(malformed("bad api call count"));
    }
    for _ in 0..calls {
        let id = r.read_number() as u32;
        let _tid = r.read_type_id(bc);
        let name = r.read_string();
        if !r.ok {
            return Err(malformed("bad api declaration"));
        }
        // API ids start from 1.
        let id0 = id.wrapping_sub(1);
        bc.uses_apis.push(id0);
        bc.apis.push((id0, name.unwrap_or_default()));
    }
    Ok(())
}

fn read_constant(bc_globals: &mut Vec<u64>, comp: u32, r: &mut Reader) {
    // Zero initializer: marker bytes 0x40 0x60.
    if r.at(r.off) == 0x40 && r.at(r.off + 1) == 0x60 {
        for _ in 0..comp {
            bc_globals.push(0);
        }
        r.off += 2;
        return;
    }
    let mut j = 0u32;
    while r.ok && r.at(r.off) != 0x60 {
        if j >= comp {
            r.ok = false;
            return;
        }
        r.buf[r.off] |= 0x20;
        bc_globals.push(r.read_number());
        j += 1;
    }
    if r.ok && j != comp {
        r.ok = false;
        return;
    }
    r.off += 1; // skip the 0x60 terminator
}

fn parse_globals(bc: &mut Bc, line: &mut [u8]) -> DResult<()> {
    if line.first() != Some(&b'G') {
        return Err(malformed("invalid globals header"));
    }
    // Read into locals first to avoid borrowing `bc` mutably and immutably at once.
    let num_types = bc.num_types;
    let start_tid = bc.start_tid;
    let mut tys = Vec::new();
    let mut globals: Vec<Vec<u64>> = Vec::new();
    {
        let mut r = Reader::new(line);
        r.off = 1;
        let _maxglobal = r.read_number();
        let numglobals = r.read_number();
        if !r.ok {
            return Err(malformed("bad globals header"));
        }
        for _ in 0..numglobals {
            let tid = {
                let t = r.read_number();
                if !r.ok || t >= (num_types + start_tid as u32) as u64 {
                    r.ok = false;
                    0
                } else {
                    t as u16
                }
            };
            let comp = type_components(bc, tid).ok_or_else(|| malformed("bad global type"))?;
            let mut g = Vec::new();
            read_constant(&mut g, comp, &mut r);
            if !r.ok {
                return Err(malformed("bad global constant"));
            }
            tys.push(tid);
            globals.push(g);
        }
        if r.off != r.len() {
            return Err(malformed("trailing garbage in globals"));
        }
    }
    bc.global_tys = tys;
    bc.globals = globals;
    Ok(())
}

fn parse_function_header(bc: &mut Bc, fn_idx: usize, line: &mut [u8]) -> DResult<()> {
    if fn_idx >= bc.num_func as usize {
        return Err(malformed("more functions than declared"));
    }
    if line.first() != Some(&b'A') {
        return Err(malformed("invalid function arguments header"));
    }
    let num_types = bc.num_types;
    let start_tid = bc.start_tid;
    let mut func = BcFunc::default();
    {
        let mut r = Reader::new(line);
        r.off = 1;
        func.num_args = r.read_fixed(1) as u8;
        func.return_type = {
            let t = r.read_number();
            if !r.ok || t >= (num_types + start_tid as u32) as u64 {
                r.ok = false;
                u16::MAX
            } else {
                t as u16
            }
        };
        if r.at(r.off) != b'L' {
            return Err(malformed("invalid function locals header"));
        }
        r.off += 1;
        func.num_locals = r.read_number() as u32;
        if !r.ok {
            return Err(malformed("invalid arg/local count"));
        }
        let all_locals = func.num_args as u32 + func.num_locals;
        for _ in 0..all_locals {
            let mut t = r.read_number() as u16;
            if r.read_fixed(1) != 0 {
                t |= 0x8000;
            }
            func.types.push(t);
        }
        if !r.ok {
            return Err(malformed("invalid local types"));
        }
        if r.at(r.off) != b'F' {
            return Err(malformed("invalid function body header"));
        }
        r.off += 1;
        func.num_insts = r.read_number() as u32;
        if !r.ok {
            return Err(malformed("invalid instruction count"));
        }
        func.num_values = func.num_args as u32 + func.num_locals;
        func.num_constants = 0;
        func.insn_idx = 0;
        let num_bb = r.read_number() as usize;
        if !r.ok {
            return Err(malformed("invalid basic block count"));
        }
        func.bbs = vec![BcBB::default(); num_bb];
    }
    bc.funcs[fn_idx] = func;
    Ok(())
}

fn parse_bb(bc: &mut Bc, fn_idx: usize, bb_idx: usize, line: &mut [u8]) -> DResult<()> {
    if line.first() != Some(&b'B') {
        return Err(malformed("invalid basic block header"));
    }
    let num_bb = bc.funcs[fn_idx].bbs.len();
    if bb_idx >= num_bb {
        return Err(malformed("too many basic blocks"));
    }
    // Operate on a detached function to allow read_operand(&mut func).
    let mut func = std::mem::take(&mut bc.funcs[fn_idx]);
    let result = parse_bb_inner(bc, &mut func, bb_idx, num_bb, line);
    bc.funcs[fn_idx] = func;
    result
}

fn parse_bb_inner(
    bc: &Bc,
    func: &mut BcFunc,
    bb_idx: usize,
    num_bb: usize,
    line: &mut [u8],
) -> DResult<()> {
    let mut insts: Vec<BcInst> = Vec::new();
    let mut r = Reader::new(line);
    r.off = 1;
    let mut last = false;
    while !last {
        let mut ty: u16;
        let dest: u32;
        if r.at(r.off) == b'T' {
            last = true;
            r.off += 1;
            ty = 0;
            dest = 0;
        } else {
            ty = r.read_number() as u16;
            dest = r.read_number() as u32;
        }
        let opcode = r.read_fixed(2) as u16;
        if !r.ok {
            return Err(malformed("invalid type or operand"));
        }
        if opcode >= OP_BC_INVALID {
            return Err(malformed(format!("invalid opcode {opcode}")));
        }

        let ops = decode_inst_ops(&mut r, bc, func, opcode, &mut ty, num_bb)?;
        if !r.ok {
            return Err(malformed("invalid instruction operands"));
        }

        // interp_op: opcode*5 + size-class (bytecode.c parseBB tail).
        let mut interp_op = (opcode as u32 * 5) as u8;
        if ty > 1 {
            if ty <= 8 {
                interp_op = interp_op.wrapping_add(1);
            } else if ty <= 16 {
                interp_op = interp_op.wrapping_add(2);
            } else if ty <= 32 {
                interp_op = interp_op.wrapping_add(3);
            } else if ty <= 65 {
                interp_op = interp_op.wrapping_add(4);
            }
        }

        insts.push(BcInst {
            opcode,
            ty,
            dest,
            interp_op,
            ops,
        });
    }

    // 'E' terminates the last BB of the function.
    if bb_idx + 1 == num_bb {
        if r.at(r.off) != b'E' {
            return Err(malformed("missing basic block terminator"));
        }
        r.off += 1;
    }
    // Optional debug-node section ('D').
    if r.at(r.off) == b'D' {
        r.off += 3;
        let num = r.read_number();
        if !r.ok {
            return Err(malformed("bad dbg node count"));
        }
        for _ in 0..num {
            let _ = r.read_number();
        }
        if !r.ok {
            return Err(malformed("bad dbg node"));
        }
    }
    if r.off != r.len() {
        return Err(malformed("trailing garbage in basic block"));
    }

    func.insn_idx += insts.len() as u32;
    func.bbs[bb_idx].insts = insts;
    Ok(())
}

/// Decode one instruction's operands, mirroring bytecode.c parseBB's switch.
fn decode_inst_ops(
    r: &mut Reader,
    bc: &Bc,
    func: &mut BcFunc,
    opcode: u16,
    ty: &mut u16,
    num_bb: usize,
) -> DResult<Ops> {
    let ops = match opcode {
        OP_BC_JMP => Ops::Jump(r.read_bb_id(num_bb)),
        OP_BC_RET => {
            *ty = r.read_number() as u16;
            Ops::Unary(read_operand(r, func))
        }
        OP_BC_BRANCH => {
            let condition = read_operand(r, func);
            let br_true = r.read_bb_id(num_bb);
            let br_false = r.read_bb_id(num_bb);
            Ops::Branch {
                condition,
                br_true,
                br_false,
            }
        }
        OP_BC_CALL_API | OP_BC_CALL_DIRECT => {
            let num_op = r.read_fixed(1) as usize;
            let is_api = opcode == OP_BC_CALL_API;
            // funcid: validated against num_func / uses_apis.
            let raw = r.read_number();
            let funcid = raw.wrapping_sub(1) as u16;
            if is_api {
                if r.ok && !bc.uses_apis.contains(&(funcid as u32)) {
                    r.ok = false;
                }
            } else if r.ok && (funcid as u32) >= bc.num_func {
                r.ok = false;
            }
            let mut ops = Vec::with_capacity(num_op);
            for _ in 0..num_op {
                ops.push(read_operand(r, func));
            }
            Ops::Call { funcid, is_api, ops }
        }
        OP_BC_ZEXT | OP_BC_SEXT | OP_BC_TRUNC => {
            let source = read_operand(r, func);
            let mut mask = func.types.get(source as usize).copied().unwrap_or(0) as u64;
            let size = if mask == 1 {
                0
            } else if mask <= 8 {
                1
            } else if mask <= 16 {
                2
            } else if mask <= 32 {
                3
            } else {
                4
            };
            if opcode != OP_BC_SEXT {
                mask = if mask != 64 { (1u64 << mask) - 1 } else { !0u64 };
            }
            Ops::Cast { source, mask, size }
        }
        OP_BC_GEP1 | OP_BC_GEPZ => {
            let a = r.read_number() as u32;
            let b = read_operand(r, func);
            let c = read_operand(r, func);
            Ops::Three([a, b, c])
        }
        OP_BC_GEPN => {
            let num_op = r.read_fixed(1) as usize;
            let mut ops = Vec::with_capacity(num_op + 2);
            ops.push(r.read_number() as u32);
            for _ in 0..(num_op + 1) {
                ops.push(read_operand(r, func));
            }
            Ops::GepN(ops)
        }
        OP_BC_STORE => {
            let a = read_operand(r, func);
            let b = read_operand(r, func);
            let t = func.optype(a);
            if t != 0 {
                *ty = t as u16;
            }
            Ops::Binop([a, b])
        }
        OP_BC_COPY => {
            let a = read_operand(r, func);
            let b = read_operand(r, func);
            *ty = func.optype(b) as u16;
            Ops::Binop([a, b])
        }
        op if (OP_BC_ICMP_EQ..=OP_BC_ICMP_SLT).contains(&op) => {
            // ICMP: instruction type must be read before the operands.
            *ty = r.read_number() as u16;
            decode_fixed_ops(r, func, opcode)
        }
        _ => decode_fixed_ops(r, func, opcode),
    };
    Ok(ops)
}

/// Decode the fixed-arity operand tail (operand_counts[opcode]).
fn decode_fixed_ops(r: &mut Reader, func: &mut BcFunc, opcode: u16) -> Ops {
    match OPERAND_COUNTS[opcode as usize] {
        0 => Ops::None,
        1 => Ops::Unary(read_operand(r, func)),
        2 => {
            let a = read_operand(r, func);
            let b = read_operand(r, func);
            Ops::Binop([a, b])
        }
        3 => {
            let a = read_operand(r, func);
            let b = read_operand(r, func);
            let c = read_operand(r, func);
            Ops::Three([a, b, c])
        }
        _ => {
            r.ok = false;
            Ops::None
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level decode driver (bytecode.c cli_bytecode_load state machine)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Lsig,
    Types,
    Apis,
    Globals,
    MdOptHeader,
    FuncHeader,
    Bb,
    Skip,
}

/// Decode a full `.cbc` program text into a [`Bc`]. Returns `Ok(None)` for a
/// cleanly-skipped program (unsupported format/API/global level), `Err` for a
/// malformed one.
pub fn decode_bytecode(text: &str) -> DResult<Option<Bc>> {
    let mut lines = text.lines();
    let mut bc = Bc::default();

    let first = lines.next().ok_or_else(|| malformed("empty bytecode"))?;
    let mut header = first.as_bytes().to_vec();
    let mut state;
    match parse_header(&mut bc, &mut header) {
        Ok(_) => state = State::Lsig,
        Err(DecodeError::Skip(_)) => {
            bc.skipped = true;
            state = State::Skip;
        }
        Err(e) => return Err(e),
    }

    let mut current_func = 0usize;
    let mut bb = 0usize;

    for raw in lines {
        let mut line = raw.as_bytes().to_vec();
        match state {
            State::Lsig => {
                parse_lsig(&mut bc, &line);
                state = State::Types;
            }
            State::Types => {
                parse_types(&mut bc, &mut line)?;
                state = State::Apis;
            }
            State::Apis => match parse_apis(&mut bc, &mut line) {
                Ok(()) => state = State::Globals,
                Err(DecodeError::Skip(_)) => {
                    bc.skipped = true;
                    state = State::Skip;
                }
                Err(e) => return Err(e),
            },
            State::Globals => match parse_globals(&mut bc, &mut line) {
                Ok(()) => state = State::MdOptHeader,
                Err(DecodeError::Skip(_)) => {
                    bc.skipped = true;
                    state = State::Skip;
                }
                Err(e) => return Err(e),
            },
            State::MdOptHeader => {
                // Optional debug-metadata line(s); skip and stay in this state,
                // mirroring ClamAV's PARSE_MD_OPT_HEADER (which keeps its state on
                // 'D' and falls through to function-header handling otherwise).
                if line.first() == Some(&b'D') {
                    continue;
                }
                if line.first() == Some(&b'S') {
                    break;
                }
                parse_function_header(&mut bc, current_func, &mut line)?;
                bb = 0;
                state = State::Bb;
            }
            State::FuncHeader => {
                if line.first() == Some(&b'S') {
                    break;
                }
                parse_function_header(&mut bc, current_func, &mut line)?;
                bb = 0;
                state = State::Bb;
            }
            State::Bb => {
                parse_bb(&mut bc, current_func, bb, &mut line)?;
                bb += 1;
                if bb >= bc.funcs[current_func].bbs.len() {
                    state = State::FuncHeader;
                    current_func += 1;
                }
            }
            State::Skip => {
                if line.first() == Some(&b'S') {
                    break;
                }
            }
        }
    }

    if bc.skipped {
        return Ok(None);
    }
    if current_func != bc.num_func as usize {
        return Err(malformed(format!(
            "loaded {current_func} functions, declared {}",
            bc.num_func
        )));
    }
    Ok(Some(bc))
}

// ---------------------------------------------------------------------------
// Phase 2a — interpreter prep pass (bytecode.c cli_bytecode_prepare_interpreter)
// ---------------------------------------------------------------------------

#[inline]
fn align_up(v: u32, align: u32) -> u32 {
    if align <= 1 {
        v
    } else {
        (v + align - 1) & !(align - 1)
    }
}

/// Compose a tagged interpreter pointer: `(id << 32) | offset` (bytecode.c
/// `ptr_compose`).
fn ptr_compose(id: i32, offset: u32) -> u64 {
    ((id as i64 as u64) << 32) | offset as u64
}

/// Byte size pointed to by a pointer type id, for GEP1 (bytecode.c
/// `get_geptypesize`). Returns -1 on an invalid type.
fn get_geptypesize(bc: &Bc, tid: u16) -> i64 {
    if tid as u32 >= bc.num_types + 65 || tid <= 64 {
        return -1;
    }
    let ty = &bc.types[(tid - 65) as usize];
    if ty.kind != TypeKind::Pointer {
        return -1;
    }
    type_size(bc, ty.contained.first().copied().unwrap_or(0)) as i64
}

/// Resolve a struct GEPZ field index to a byte offset, rewriting the constant
/// in place (bytecode.c `calc_gepz`). Returns -1 on error, 0 if not a struct, 1
/// if the constant was rewritten.
fn calc_gepz(bc: &Bc, consts: &mut [u64], num_values: u32, tid: u16, op: u32) -> i32 {
    if tid as u32 >= bc.num_types + 65 || tid <= 65 {
        return -1;
    }
    let ty = &bc.types[(tid - 65) as usize];
    let inner = ty.contained.first().copied().unwrap_or(0);
    if ty.kind != TypeKind::Pointer || inner < 65 {
        return -1;
    }
    let ty2 = &bc.types[(inner - 65) as usize];
    if ty2.kind != TypeKind::Struct && ty2.kind != TypeKind::PackedStruct {
        return 0;
    }
    let idx = (op - num_values) as usize;
    let gepoff = match consts.get(idx) {
        Some(v) => *v as u32,
        None => return -1,
    };
    if gepoff >= ty2.num_elements {
        return -1;
    }
    let mut off = 0u32;
    for i in 0..gepoff as usize {
        off += type_size(bc, ty2.contained[i]);
    }
    consts[idx] = off as u64;
    1
}

impl Bc {
    /// Lay out each function's stack frame, build the global byte buffer, and
    /// rewrite every operand from a value index to a byte offset — the form the
    /// interpreter executes. Mirrors `cli_bytecode_prepare_interpreter`.
    pub fn prepare_interpreter(&mut self) -> DResult<()> {
        if self.skipped {
            return Ok(());
        }

        // 1) Global layout: each global at an aligned offset in `global_bytes`.
        let mut gmap = vec![0u32; self.globals.len()];
        let mut ngb = 0u32;
        for j in 0..self.global_tys.len() {
            let ty = self.global_tys[j];
            let align = type_align(self, ty);
            ngb = align_up(ngb, align);
            gmap[j] = ngb;
            ngb += type_size(self, ty);
        }
        self.num_global_bytes = ngb;
        let mut gb = vec![0u8; ngb as usize];

        // 2) Initialize global constants (pointers and integer arrays).
        let bcglobalid = (APICALL_MAXGLOBAL - FIRST_GLOBAL + 2) as i32;
        for j in 0..self.globals.len() {
            let tid = self.global_tys[j];
            if tid < 65 {
                continue;
            }
            let ty = self.types[(tid - 65) as usize].clone();
            match ty.kind {
                TypeKind::Pointer => {
                    let g = &self.globals[j];
                    if g.len() < 2 {
                        continue;
                    }
                    let ptr = if g[1] >= FIRST_GLOBAL {
                        ptr_compose((g[1] - FIRST_GLOBAL + 1) as i32, g[0] as u32)
                    } else {
                        if g[1] > self.globals.len() as u64 {
                            continue;
                        }
                        let gi = g[1] as usize;
                        let base = gmap.get(gi).copied().unwrap_or(0);
                        ptr_compose(bcglobalid, base + g[0] as u32)
                    };
                    let off = gmap[j] as usize;
                    if off + 8 <= gb.len() {
                        gb[off..off + 8].copy_from_slice(&ptr.to_le_bytes());
                    }
                }
                TypeKind::Array => {
                    let inner = ty.contained.first().copied().unwrap_or(0);
                    let elsize = type_size(self, inner) as usize;
                    let off = gmap[j] as usize;
                    let g = &self.globals[j];
                    for i in 0..ty.num_elements as usize {
                        let v = g.get(i).copied().unwrap_or(0);
                        let p = off + i * elsize;
                        match elsize {
                            1 if p < gb.len() => gb[p] = v as u8,
                            2 if p + 2 <= gb.len() => {
                                gb[p..p + 2].copy_from_slice(&(v as u16).to_le_bytes())
                            }
                            4 if p + 4 <= gb.len() => {
                                gb[p..p + 4].copy_from_slice(&(v as u32).to_le_bytes())
                            }
                            8 if p + 8 <= gb.len() => {
                                gb[p..p + 8].copy_from_slice(&v.to_le_bytes())
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        self.global_bytes = gb;

        // 3) Per-function value layout + operand remapping.
        let num_func = self.funcs.len();
        for i in 0..num_func {
            let mut func = std::mem::take(&mut self.funcs[i]);
            let res = prepare_func(self, &mut func, &gmap);
            self.funcs[i] = func;
            res?;
        }
        self.prepared = true;
        Ok(())
    }
}

fn prepare_func(bc: &Bc, func: &mut BcFunc, gmap: &[u32]) -> DResult<()> {
    let num_values = func.num_values;
    let num_constants = func.num_constants;
    let map_len = (num_values + num_constants) as usize;
    let mut map = vec![0u32; map_len];
    let mut num_bytes = 0u32;
    for j in 0..num_values as usize {
        let ty = func.types.get(j).copied().unwrap_or(0);
        let align = type_align(bc, ty);
        num_bytes = align_up(num_bytes, align);
        map[j] = num_bytes;
        num_bytes += type_size(bc, ty);
    }
    num_bytes = align_up(num_bytes, 8);
    for j in 0..num_constants as usize {
        map[num_values as usize + j] = num_bytes;
        num_bytes += 8;
    }
    func.num_bytes = num_bytes;

    let types = func.types.clone();
    // Constants are read/rewritten by GEPZ; detach to avoid aliasing func.bbs.
    let mut consts = std::mem::take(&mut func.constants);

    // MAP: value/constant index → byte offset, or global (high-bit tagged).
    let map_op = |val: u32| -> DResult<u32> {
        if val & 0x8000_0000 != 0 {
            let o = (val & 0x7fff_ffff) as usize;
            let goff = *gmap.get(o).ok_or_else(|| malformed("global out of range"))?;
            return Ok(0x8000_0000 | goff);
        }
        let o = val as usize;
        let off = *map.get(o).ok_or_else(|| malformed("operand out of range"))?;
        Ok(off)
    };
    // MAPPTR: a pointer-typed local becomes a stack-pointer (0x40000000 tag).
    let mapptr_op = |val: u32| -> DResult<u32> {
        if val < num_values && (types.get(val as usize).copied().unwrap_or(0) & 0x8000) != 0 {
            let off = *map
                .get(val as usize)
                .ok_or_else(|| malformed("ptr operand out of range"))?;
            return Ok(off | 0x4000_0000);
        }
        map_op(val)
    };

    let mut result: DResult<()> = Ok(());
    'outer: for bb in &mut func.bbs {
        for inst in &mut bb.insts {
            if (inst.dest as usize) < map.len() {
                inst.dest = map[inst.dest as usize];
            }
            let r = remap_inst(inst, bc, &types, &mut consts, num_values, &map_op, &mapptr_op);
            if let Err(e) = r {
                result = Err(e);
                break 'outer;
            }
        }
    }
    func.constants = consts;
    result
}

#[allow(clippy::too_many_arguments)]
fn remap_inst(
    inst: &mut BcInst,
    bc: &Bc,
    types: &[u16],
    consts: &mut [u64],
    num_values: u32,
    map_op: &dyn Fn(u32) -> DResult<u32>,
    mapptr_op: &dyn Fn(u32) -> DResult<u32>,
) -> DResult<()> {
    match inst.opcode {
        OP_BC_ADD..=OP_BC_XOR
        | OP_BC_ICMP_EQ..=OP_BC_ICMP_SLT
        | OP_BC_COPY
        | OP_BC_STORE => {
            if let Ops::Binop(b) = &mut inst.ops {
                b[0] = map_op(b[0])?;
                b[1] = map_op(b[1])?;
            }
        }
        OP_BC_SEXT | OP_BC_ZEXT | OP_BC_TRUNC => {
            if let Ops::Cast { source, .. } = &mut inst.ops {
                *source = map_op(*source)?;
            }
        }
        OP_BC_BRANCH => {
            if let Ops::Branch { condition, .. } = &mut inst.ops {
                *condition = map_op(*condition)?;
            }
        }
        OP_BC_JMP => {}
        OP_BC_RET | OP_BC_BSWAP16 | OP_BC_BSWAP32 | OP_BC_BSWAP64 => {
            if let Ops::Unary(u) = &mut inst.ops {
                *u = map_op(*u)?;
            }
        }
        OP_BC_PTRTOINT64 => {
            if let Ops::Unary(u) = &mut inst.ops {
                *u = mapptr_op(*u)?;
            }
        }
        OP_BC_SELECT => {
            if let Ops::Three(t) = &mut inst.ops {
                t[0] = map_op(t[0])?;
                t[1] = map_op(t[1])?;
                t[2] = map_op(t[2])?;
            }
        }
        OP_BC_CALL_API | OP_BC_CALL_DIRECT => {
            if let Ops::Call { funcid, is_api, ops } = &mut inst.ops {
                if !*is_api {
                    if *funcid as u32 >= bc.num_func {
                        return Err(malformed("call funcid out of range"));
                    }
                    if ops.len() != bc.funcs[*funcid as usize].num_args as usize {
                        return Err(malformed("call arg count mismatch"));
                    }
                } else if ops.len() > 5 {
                    return Err(malformed("api call has too many args"));
                }
                for o in ops.iter_mut() {
                    *o = mapptr_op(*o)?;
                }
            }
        }
        OP_BC_LOAD => {
            if let Ops::Unary(u) = &mut inst.ops {
                *u = mapptr_op(*u)?;
            }
        }
        OP_BC_GEP1 => {
            if let Ops::Three(t) = &mut inst.ops {
                if t[1] & 0x8000_0000 != 0
                    || (types.get(t[1] as usize).copied().unwrap_or(0) & 0x8000) != 0
                {
                    return Err(malformed("gep1 of alloca is not allowed"));
                }
                t[1] = map_op(t[1])?;
                t[2] = map_op(t[2])?;
                let gts = get_geptypesize(bc, t[0] as u16);
                if gts < 0 {
                    return Err(malformed("gep1 invalid type"));
                }
                t[0] = gts as u32;
            }
        }
        OP_BC_GEPZ => {
            if let Ops::Three(t) = &mut inst.ops {
                let is_ptr = t[1] & 0x8000_0000 != 0
                    || (types.get(t[1] as usize).copied().unwrap_or(0) & 0x8000) != 0;
                inst.interp_op = if is_ptr {
                    5 * (inst.interp_op / 5)
                } else {
                    5 * (inst.interp_op / 5) + 3
                };
                t[1] = map_op(t[1])?;
                if calc_gepz(bc, consts, num_values, t[0] as u16, t[2]) == -1 {
                    return Err(malformed("gepz invalid"));
                }
                t[2] = map_op(t[2])?;
            }
        }
        OP_BC_MEMSET | OP_BC_MEMCPY | OP_BC_MEMMOVE | OP_BC_MEMCMP => {
            if let Ops::Three(t) = &mut inst.ops {
                t[0] = mapptr_op(t[0])?;
                t[1] = mapptr_op(t[1])?;
                t[2] = map_op(t[2])?;
            }
        }
        OP_BC_PTRDIFF32 => {
            if let Ops::Binop(b) = &mut inst.ops {
                b[0] = mapptr_op(b[0])?;
                b[1] = mapptr_op(b[1])?;
            }
        }
        OP_BC_RET_VOID | OP_BC_ISBIGENDIAN | OP_BC_ABORT => {}
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4 — execution context (the `cli_bc_ctx` fields the VM/API touch)
// ---------------------------------------------------------------------------

/// PE section info exposed to `get_pe_section` (`struct cli_exe_section`, 9×u32).
#[derive(Clone, Copy, Debug, Default)]
pub struct PeSection {
    pub rva: u32,
    pub vsz: u32,
    pub raw: u32,
    pub rsz: u32,
    pub chr: u32,
    pub urva: u32,
    pub uvsz: u32,
    pub uraw: u32,
    pub ursz: u32,
}

/// Execution context for a bytecode run: the scanned buffer, the trigger's
/// match counts/offsets, and PE info — the data ClamAV exposes via `ctx->hooks`
/// and the file APIs. `virname` is the detection result a program sets via
/// `setvirusname`.
pub struct BcCtx<'a> {
    pub file: &'a [u8],
    pub file_size: u32,
    pub off: u32,
    pub virname: Option<String>,
    pub lsigcnt: [u32; 64],
    pub lsigoff: [u32; 64],
    pub kind: u16,
    pub sections: Vec<PeSection>,
    pub nsections: u16,
    pub hdr_size: u32,
    pub ep: u32,
    /// Cap on executed opcodes (DoS bound, replaces ClamAV's wall-clock timeout).
    pub max_ops: u64,
}

impl<'a> BcCtx<'a> {
    pub fn new(file: &'a [u8]) -> Self {
        BcCtx {
            file,
            file_size: file.len() as u32,
            off: 0,
            virname: None,
            lsigcnt: [0; 64],
            lsigoff: [0; 64],
            kind: 0,
            sections: Vec::new(),
            nsections: 0,
            hdr_size: 0,
            ep: 0,
            max_ops: 50_000_000,
        }
    }

    fn read_file(&self, off: u32, buf: &mut [u8]) -> usize {
        let off = off as usize;
        if off >= self.file.len() {
            return 0;
        }
        let n = buf.len().min(self.file.len() - off);
        buf[..n].copy_from_slice(&self.file[off..off + n]);
        n
    }
}

// ---------------------------------------------------------------------------
// Phase 3 — API table (exact id→kind→idx from bytecode_api_decl.c)
// ---------------------------------------------------------------------------

/// `(kind, idx)` per API id, in the exact order of `cli_apicalls[]`. The bytecode
/// references APIs by this id, so the ordering must match libclamav.
const API_TABLE: [(u8, u8); 107] = [
    (0, 0), (1, 0), (1, 1), (0, 1), (1, 2), (1, 3), (2, 0), (1, 4), (1, 5), (1, 6),
    (1, 7), (1, 8), (1, 9), (1, 10), (2, 1), (1, 11), (2, 2), (3, 0), (2, 3), (1, 12),
    (4, 0), (2, 4), (2, 5), (5, 0), (0, 2), (0, 3), (0, 4), (2, 6), (2, 7), (2, 8),
    (2, 9), (2, 10), (6, 0), (0, 5), (2, 11), (6, 1), (0, 6), (2, 12), (7, 0), (2, 13),
    (2, 14), (2, 15), (2, 16), (2, 17), (2, 18), (0, 7), (7, 1), (7, 2), (7, 3), (7, 4),
    (8, 0), (0, 8), (1, 13), (1, 14), (1, 15), (1, 16), (0, 9), (9, 0), (9, 1), (9, 2),
    (9, 3), (2, 19), (6, 2), (2, 20), (9, 4), (5, 1), (5, 2), (5, 3), (5, 4), (2, 21),
    (2, 22), (1, 17), (9, 5), (9, 6), (8, 1), (7, 5), (5, 5), (5, 6), (2, 23), (2, 24),
    (2, 25), (6, 3), (2, 26), (2, 27), (0, 10), (2, 28), (5, 7), (5, 8), (8, 2), (5, 9),
    (5, 10), (5, 11), (9, 7), (2, 29), (2, 30), (0, 11), (2, 31), (9, 8), (2, 32), (2, 33),
    (1, 18), (0, 12), (2, 34), (2, 35), (0, 13), (2, 36), (2, 37),
];

// ---------------------------------------------------------------------------
// Phase 2b — interpreter (bytecode_vm.c cli_vm_execute)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum VmError {
    Bytecode(String),
    Timeout,
}

/// Fixed glob region ids (1-based), mirroring `ptr_register_glob_fixedid`.
const GID_MATCH_COUNTS: usize = 1;
const GID_KIND: usize = 2;
const GID_PEDATA: usize = 4;
const GID_FILESIZE: usize = 5;
const GID_MATCH_OFFSETS: usize = 6;
const GID_GLOBALBYTES: usize = 7; // APICALL_MAXGLOBAL - FIRST_GLOBAL + 2

struct Frame {
    func: usize,
    stack: usize,
    bb: usize,
    inst: usize,
    ret_dest: u32,
}

struct Vm<'a, 'c> {
    bc: &'a Bc,
    ctx: &'a mut BcCtx<'c>,
    /// Stack-frame value buffers; composed stack id `-n` → `stacks[n-1]`.
    stacks: Vec<Vec<u8>>,
    /// Global regions; composed glob id `n` → `globs[n-1]`.
    globs: Vec<Vec<u8>>,
    ops_done: u64,
}

#[inline]
fn read_le(buf: &[u8], off: usize, n: usize) -> Option<u64> {
    let s = buf.get(off..off + n)?;
    let mut v = 0u64;
    for (i, b) in s.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    Some(v)
}

#[inline]
fn write_le(buf: &mut [u8], off: usize, n: usize, val: u64) -> bool {
    match buf.get_mut(off..off + n) {
        Some(s) => {
            for (i, b) in s.iter_mut().enumerate() {
                *b = (val >> (8 * i)) as u8;
            }
            true
        }
        None => false,
    }
}

/// Sign-extend the low `bits` of `v` to i64 (ClamAV `SIGNEXT`).
#[inline]
fn signext(v: u64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        return v as i64;
    }
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

impl<'a, 'c> Vm<'a, 'c> {
    /// READN: read `n` bytes from a tagged operand offset — globalBytes when the
    /// 0x80000000 bit is set, else the current frame's values.
    fn read_op(&self, cur: usize, p: u32, n: usize) -> Result<u64, VmError> {
        if p & 0x8000_0000 != 0 {
            let pg = (p & 0x7fff_ffff) as usize;
            if pg == 0 {
                return Ok(0);
            }
            return read_le(&self.globs[GID_GLOBALBYTES - 1], pg, n)
                .ok_or_else(|| VmError::Bytecode("global read OOB".into()));
        }
        read_le(&self.stacks[cur], p as usize, n)
            .ok_or_else(|| VmError::Bytecode("value read OOB".into()))
    }

    fn read_op_sc(&self, cur: usize, p: u32, sc: u8) -> Result<u64, VmError> {
        match sc {
            0 => Ok(self.read_op(cur, p, 1)? & 1),
            1 => self.read_op(cur, p, 1),
            2 => self.read_op(cur, p, 2),
            3 => self.read_op(cur, p, 4),
            _ => self.read_op(cur, p, 8),
        }
    }

    /// WRITE: store to the current frame's values at `dest` (never globals).
    fn write_dest(&mut self, cur: usize, dest: u32, n: usize, val: u64) -> Result<(), VmError> {
        if write_le(&mut self.stacks[cur], dest as usize, n, val) {
            Ok(())
        } else {
            Err(VmError::Bytecode("value write OOB".into()))
        }
    }

    /// Resolve a composed pointer `(id<<32)|off` to `(is_glob, region_index, off)`,
    /// bounds-checked for `size` bytes (`ptr_torealptr`).
    fn resolve(&self, iptr: i64, size: usize) -> Result<(bool, usize, usize), VmError> {
        let id = (iptr >> 32) as i32;
        let off = (iptr as u32) as usize;
        if id == 0 {
            return Err(VmError::Bytecode("null pointer".into()));
        }
        let (is_glob, idx, region_len) = if id < 0 {
            let i = (-id - 1) as usize;
            let len = self
                .stacks
                .get(i)
                .map(|s| s.len())
                .ok_or_else(|| VmError::Bytecode("bad stack ptr".into()))?;
            (false, i, len)
        } else {
            let i = (id - 1) as usize;
            let len = self
                .globs
                .get(i)
                .map(|s| s.len())
                .ok_or_else(|| VmError::Bytecode("bad glob ptr".into()))?;
            (true, i, len)
        };
        if off < region_len && size <= region_len && off + size <= region_len {
            Ok((is_glob, idx, off))
        } else {
            Err(VmError::Bytecode("pointer out of bounds".into()))
        }
    }

    /// READPOP: resolve a pointer operand to `(is_glob, idx, off)`. A 0x40000000
    /// tag means a pointer into the current frame; otherwise the operand holds a
    /// composed pointer to read and resolve.
    fn resolve_pop(
        &self,
        cur: usize,
        p: u32,
        size: usize,
    ) -> Result<(bool, usize, usize), VmError> {
        if p & 0x4000_0000 != 0 {
            let off = (p & 0xbfff_ffff) as usize;
            let len = self.stacks[cur].len();
            if off < len && off + size <= len {
                return Ok((false, cur, off));
            }
            return Err(VmError::Bytecode("stack ptr OOB".into()));
        }
        let iptr = self.read_op(cur, p, 8)? as i64;
        self.resolve(iptr, size)
    }

    fn region_bytes(&self, is_glob: bool, idx: usize) -> &[u8] {
        if is_glob {
            &self.globs[idx]
        } else {
            &self.stacks[idx]
        }
    }
    fn region_bytes_mut(&mut self, is_glob: bool, idx: usize) -> &mut [u8] {
        if is_glob {
            &mut self.globs[idx]
        } else {
            &mut self.stacks[idx]
        }
    }

    fn execute(&mut self, entry_func: usize) -> Result<i64, VmError> {
        // Allocate the entry frame and register it as stack region 0.
        let f0 = &self.bc.funcs[entry_func];
        let mut frame_values = vec![0u8; f0.num_bytes as usize];
        // Constants live at the top of the frame (last numConstants*8 bytes).
        let cstart = f0.num_bytes as usize - (f0.num_constants as usize) * 8;
        for (k, c) in f0.constants.iter().enumerate() {
            write_le(&mut frame_values, cstart + k * 8, 8, *c);
        }
        self.stacks.push(frame_values);
        let mut frame = Frame {
            func: entry_func,
            stack: 0,
            bb: 0,
            inst: 0,
            ret_dest: 0,
        };
        let mut call_stack: Vec<Frame> = Vec::new();
        let mut last_ret: i64 = 0;

        loop {
            self.ops_done += 1;
            if self.ops_done > self.ctx.max_ops {
                return Err(VmError::Timeout);
            }
            let cur = frame.stack;
            let inst = self.bc.funcs[frame.func].bbs[frame.bb].insts[frame.inst].clone();
            let sc = inst.interp_op % 5;

            let mut control_flow = false;
            match inst.opcode {
                OP_BC_ADD..=OP_BC_XOR => {
                    self.exec_binop(cur, &inst, sc)?;
                }
                OP_BC_ICMP_EQ..=OP_BC_ICMP_SLT => {
                    self.exec_icmp(cur, &inst, sc)?;
                }
                OP_BC_SEXT | OP_BC_ZEXT | OP_BC_TRUNC => {
                    self.exec_cast(cur, &inst)?;
                }
                OP_BC_SELECT => {
                    if let Ops::Three(t) = inst.ops {
                        let c = self.read_op_sc(cur, t[0], 0)?;
                        let (a, b, n) = match sc {
                            0 | 1 => (self.read_op(cur, t[1], 1)?, self.read_op(cur, t[2], 1)?, 1),
                            2 => (self.read_op(cur, t[1], 2)?, self.read_op(cur, t[2], 2)?, 2),
                            3 => (self.read_op(cur, t[1], 4)?, self.read_op(cur, t[2], 4)?, 4),
                            _ => (self.read_op(cur, t[1], 8)?, self.read_op(cur, t[2], 8)?, 8),
                        };
                        self.write_dest(cur, inst.dest, n, if c != 0 { a } else { b })?;
                    }
                }
                OP_BC_COPY => {
                    if let Ops::Binop(b) = inst.ops {
                        let n = [1usize, 1, 2, 4, 8][sc as usize];
                        let v = self.read_op_sc(cur, b[0], sc)?;
                        self.write_dest(cur, b[1], n, v)?;
                    }
                }
                OP_BC_BRANCH => {
                    if let Ops::Branch {
                        condition,
                        br_true,
                        br_false,
                    } = inst.ops
                    {
                        let c = self.read_op(cur, condition, 1)? & 1;
                        frame.bb = if c != 0 { br_true } else { br_false } as usize;
                        frame.inst = 0;
                        control_flow = true;
                    }
                }
                OP_BC_JMP => {
                    if let Ops::Jump(t) = inst.ops {
                        frame.bb = t as usize;
                        frame.inst = 0;
                        control_flow = true;
                    }
                }
                OP_BC_RET => {
                    let v = self.read_op_sc(cur, unary(&inst.ops), sc)?;
                    last_ret = v as i64;
                    let n = [1usize, 1, 2, 4, 8][sc as usize];
                    match call_stack.pop() {
                        Some(caller) => {
                            self.write_dest(caller.stack, frame.ret_dest, n, v)?;
                            frame = caller;
                            control_flow = true;
                        }
                        None => return Ok(last_ret),
                    }
                }
                OP_BC_RET_VOID => match call_stack.pop() {
                    Some(caller) => {
                        frame = caller;
                        control_flow = true;
                    }
                    None => return Ok(last_ret),
                },
                OP_BC_ISBIGENDIAN => {
                    self.write_dest(cur, inst.dest, 1, 0)?;
                }
                OP_BC_LOAD => {
                    let n = [1usize, 1, 2, 4, 8][sc as usize];
                    let (g, idx, off) = self.resolve_pop(cur, unary(&inst.ops), n)?;
                    let v = read_le(self.region_bytes(g, idx), off, n).unwrap_or(0);
                    self.write_dest(cur, inst.dest, n, v)?;
                }
                OP_BC_STORE => {
                    if let Ops::Binop(b) = inst.ops {
                        let n = [1usize, 1, 2, 4, 8][sc as usize];
                        let iptr = self.read_op(cur, b[1], 8)? as i64;
                        let (g, idx, off) = self.resolve(iptr, n)?;
                        let v = self.read_op_sc(cur, b[0], sc)?;
                        write_le(self.region_bytes_mut(g, idx), off, n, v);
                    }
                }
                OP_BC_GEPZ | OP_BC_GEP1 => {
                    self.exec_gep(cur, &inst, sc)?;
                }
                OP_BC_MEMCMP | OP_BC_MEMCPY | OP_BC_MEMMOVE | OP_BC_MEMSET => {
                    self.exec_mem(cur, &inst)?;
                }
                OP_BC_BSWAP16 => {
                    let v = self.read_op(cur, unary(&inst.ops), 2)? as u16;
                    self.write_dest(cur, inst.dest, 2, v.swap_bytes() as u64)?;
                }
                OP_BC_BSWAP32 => {
                    let v = self.read_op(cur, unary(&inst.ops), 4)? as u32;
                    self.write_dest(cur, inst.dest, 4, v.swap_bytes() as u64)?;
                }
                OP_BC_BSWAP64 => {
                    let v = self.read_op(cur, unary(&inst.ops), 8)?;
                    self.write_dest(cur, inst.dest, 8, v.swap_bytes())?;
                }
                OP_BC_PTRDIFF32 => {
                    if let Ops::Binop(b) = inst.ops {
                        let p1 = self.ptr_value(cur, b[0])?;
                        let p2 = self.ptr_value(cur, b[1])?;
                        let diff = if (p1 >> 32) != (p2 >> 32) {
                            0x4000_0000u32
                        } else {
                            (p1 as u32).wrapping_sub(p2 as u32)
                        };
                        self.write_dest(cur, inst.dest, 4, diff as u64)?;
                    }
                }
                OP_BC_PTRTOINT64 => {
                    let p = self.ptr_value(cur, unary(&inst.ops))?;
                    self.write_dest(cur, inst.dest, 8, p as u64)?;
                }
                OP_BC_CALL_DIRECT => {
                    self.exec_call_direct(&mut frame, &mut call_stack, &inst)?;
                    control_flow = true;
                }
                OP_BC_CALL_API => {
                    self.exec_call_api(cur, &inst)?;
                }
                OP_BC_ABORT => {
                    return Err(VmError::Bytecode("abort".into()));
                }
                _ => return Err(VmError::Bytecode(format!("opcode {} unimpl", inst.opcode))),
            }

            if !control_flow {
                frame.inst += 1;
            }
        }
    }

    fn exec_binop(&mut self, cur: usize, inst: &BcInst, sc: u8) -> Result<(), VmError> {
        let b = if let Ops::Binop(b) = inst.ops { b } else { return Ok(()) };
        let op0 = self.read_op_sc(cur, b[0], sc)?;
        let op1 = self.read_op_sc(cur, b[1], sc)?;
        let bits = [1u32, 8, 16, 32, 64][sc as usize];
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let s0 = signext(op0, bits);
        let s1 = signext(op1, bits);
        let res: u64 = match inst.opcode {
            OP_BC_ADD => op0.wrapping_add(op1),
            OP_BC_SUB => op0.wrapping_sub(op1),
            OP_BC_MUL => op0.wrapping_mul(op1),
            OP_BC_UDIV => {
                if op1 == 0 {
                    return Err(VmError::Bytecode("udiv by 0".into()));
                }
                op0 / op1
            }
            OP_BC_SDIV => {
                if op1 == 0 {
                    return Err(VmError::Bytecode("sdiv by 0".into()));
                }
                s0.wrapping_div(s1) as u64
            }
            OP_BC_UREM => {
                if op1 == 0 {
                    return Err(VmError::Bytecode("urem by 0".into()));
                }
                op0 % op1
            }
            OP_BC_SREM => {
                if op1 == 0 {
                    return Err(VmError::Bytecode("srem by 0".into()));
                }
                s0.wrapping_rem(s1) as u64
            }
            OP_BC_SHL => op0.wrapping_shl(op1 as u32),
            OP_BC_LSHR => op0.wrapping_shr(op1 as u32),
            OP_BC_ASHR => signext(op0, bits).wrapping_shr(op1 as u32) as u64,
            OP_BC_AND => op0 & op1,
            OP_BC_OR => op0 | op1,
            OP_BC_XOR => op0 ^ op1,
            _ => unreachable!(),
        };
        let wn = [1usize, 1, 2, 4, 8][sc as usize];
        self.write_dest(cur, inst.dest, wn, res & mask)
    }

    fn exec_icmp(&mut self, cur: usize, inst: &BcInst, sc: u8) -> Result<(), VmError> {
        let b = if let Ops::Binop(b) = inst.ops { b } else { return Ok(()) };
        let op0 = self.read_op_sc(cur, b[0], sc)?;
        let op1 = self.read_op_sc(cur, b[1], sc)?;
        let bits = [1u32, 8, 16, 32, 64][sc as usize];
        let s0 = signext(op0, bits);
        let s1 = signext(op1, bits);
        let res = match inst.opcode {
            OP_BC_ICMP_EQ => op0 == op1,
            OP_BC_ICMP_NE => op0 != op1,
            OP_BC_ICMP_UGT => op0 > op1,
            OP_BC_ICMP_UGE => op0 >= op1,
            OP_BC_ICMP_ULT => op0 < op1,
            OP_BC_ICMP_ULE => op0 <= op1,
            OP_BC_ICMP_SGT => s0 > s1,
            OP_BC_ICMP_SGE => s0 >= s1,
            OP_BC_ICMP_SLE => s0 <= s1,
            OP_BC_ICMP_SLT => s0 < s1,
            _ => unreachable!(),
        };
        self.write_dest(cur, inst.dest, 1, res as u64)
    }

    fn exec_cast(&mut self, cur: usize, inst: &BcInst) -> Result<(), VmError> {
        let (source, mask, size) = if let Ops::Cast { source, mask, size } = inst.ops {
            (source, mask, size)
        } else {
            return Ok(());
        };
        // The cast reads its source at the source's size class, then writes the
        // dest at the instruction's size class.
        let src_n = [1usize, 1, 2, 4, 8][size as usize];
        let raw = self.read_op(cur, source, src_n)?;
        let dsc = inst.interp_op % 5;
        let wn = [1usize, 1, 2, 4, 8][dsc as usize];
        let val = match inst.opcode {
            OP_BC_SEXT => {
                let bits = [1u32, 8, 16, 32, 64][size as usize];
                signext(raw, bits) as u64
            }
            // ZEXT / TRUNC: value is just the (masked) raw bits.
            _ => {
                if mask != 0 {
                    raw & mask
                } else {
                    raw
                }
            }
        };
        self.write_dest(cur, inst.dest, wn, val)
    }

    fn exec_gep(&mut self, cur: usize, inst: &BcInst, sc: u8) -> Result<(), VmError> {
        let t = if let Ops::Three(t) = inst.ops { t } else { return Ok(()) };
        let off = self.read_op(cur, t[2], 4)? as i32;
        let stackid = -(cur as i64 + 1);
        let elsize = if inst.opcode == OP_BC_GEP1 { t[0] as i32 } else { 1 };
        if sc == 0 {
            // pointer into the current frame (alloca): compose(stackid, base+off)
            let base = t[1] as i64;
            let off2 = (off * elsize) as i64;
            let iptr = ((stackid) << 32) | ((base + off2) as u32 as i64);
            self.write_dest(cur, inst.dest, 8, iptr as u64)?;
        } else {
            let ptr = self.read_op(cur, t[1], 8)?;
            let delta = (off * elsize) as i64 as u64;
            let lo = (ptr & 0xffff_ffff).wrapping_add(delta) & 0xffff_ffff;
            let iptr = (ptr & 0xffff_ffff_0000_0000) | lo;
            self.write_dest(cur, inst.dest, 8, iptr)?;
        }
        Ok(())
    }

    fn exec_mem(&mut self, cur: usize, inst: &BcInst) -> Result<(), VmError> {
        let t = if let Ops::Three(t) = inst.ops { t } else { return Ok(()) };
        match inst.opcode {
            OP_BC_MEMSET => {
                let len = self.read_op(cur, t[2], 8)? as usize;
                let val = self.read_op(cur, t[1], 4)? as u8;
                let (g, idx, off) = self.resolve_pop(cur, t[0], len)?;
                let region = self.region_bytes_mut(g, idx);
                for b in &mut region[off..off + len] {
                    *b = val;
                }
            }
            OP_BC_MEMCMP => {
                let len = self.read_op(cur, t[2], 4)? as usize;
                let (g1, i1, o1) = self.resolve_pop(cur, t[0], len)?;
                let (g2, i2, o2) = self.resolve_pop(cur, t[1], len)?;
                let a = self.region_bytes(g1, i1)[o1..o1 + len].to_vec();
                let b = &self.region_bytes(g2, i2)[o2..o2 + len];
                let res: i32 = match a.as_slice().cmp(b) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                self.write_dest(cur, inst.dest, 4, res as u32 as u64)?;
            }
            OP_BC_MEMCPY | OP_BC_MEMMOVE => {
                let n = if inst.opcode == OP_BC_MEMCPY { 4 } else { 8 };
                let len = self.read_op(cur, t[2], n)? as usize;
                let (g1, i1, o1) = self.resolve_pop(cur, t[0], len)?;
                let (g2, i2, o2) = self.resolve_pop(cur, t[1], len)?;
                let src = self.region_bytes(g2, i2)[o2..o2 + len].to_vec();
                self.region_bytes_mut(g1, i1)[o1..o1 + len].copy_from_slice(&src);
            }
            _ => {}
        }
        Ok(())
    }

    /// Value of a pointer operand (for PTRDIFF/PTRTOINT): a 0x40000000-tagged
    /// operand composes a stack pointer; otherwise it's a stored composed ptr.
    fn ptr_value(&self, cur: usize, p: u32) -> Result<i64, VmError> {
        if p & 0x4000_0000 != 0 {
            let off = (p & 0xbfff_ffff) as i64;
            Ok(((-(cur as i64 + 1)) << 32) | off)
        } else {
            Ok(self.read_op(cur, p, 8)? as i64)
        }
    }

    fn exec_call_direct(
        &mut self,
        frame: &mut Frame,
        call_stack: &mut Vec<Frame>,
        inst: &BcInst,
    ) -> Result<(), VmError> {
        let (funcid, ops) = if let Ops::Call { funcid, ops, .. } = &inst.ops {
            (*funcid as usize, ops.clone())
        } else {
            return Err(VmError::Bytecode("bad call".into()));
        };
        if call_stack.len() > 10000 {
            return Err(VmError::Bytecode("stack depth exceeded".into()));
        }
        let target = &self.bc.funcs[funcid];
        let mut newvals = vec![0u8; target.num_bytes as usize];
        // constants at top
        let cstart = target.num_bytes as usize - (target.num_constants as usize) * 8;
        for (k, c) in target.constants.iter().enumerate() {
            write_le(&mut newvals, cstart + k * 8, 8, *c);
        }
        // copy args from caller frame to sequential offsets in the new frame
        let cur = frame.stack;
        let mut j = 0usize;
        let arg_types: Vec<u16> = target.types[..target.num_args as usize].to_vec();
        for (i, &aty) in arg_types.iter().enumerate() {
            let sz = type_size(self.bc, aty) as usize;
            let opnd = ops[i];
            let v = if opnd & 0x4000_0000 != 0 {
                // alloca pointer arg → composed stack pointer value
                (((-(cur as i64 + 1)) << 32) | (opnd & 0xbfff_ffff) as i64) as u64
            } else {
                read_le(&self.stacks[cur], opnd as usize, sz).unwrap_or(0)
            };
            match sz {
                1 => {
                    newvals[j] = v as u8;
                    j += 1;
                }
                2 => {
                    j = (j + 1) & !1;
                    write_le(&mut newvals, j, 2, v);
                    j += 2;
                }
                4 => {
                    j = (j + 3) & !3;
                    write_le(&mut newvals, j, 4, v);
                    j += 4;
                }
                8 => {
                    j = (j + 7) & !7;
                    write_le(&mut newvals, j, 8, v);
                    j += 8;
                }
                _ => {}
            }
        }
        let new_stack = self.stacks.len();
        self.stacks.push(newvals);
        // save caller, advancing its instruction past the call
        let mut caller = Frame {
            func: frame.func,
            stack: frame.stack,
            bb: frame.bb,
            inst: frame.inst + 1,
            ret_dest: frame.ret_dest,
        };
        std::mem::swap(&mut caller, frame);
        frame.func = funcid;
        frame.stack = new_stack;
        frame.bb = 0;
        frame.inst = 0;
        frame.ret_dest = inst.dest;
        call_stack.push(caller);
        Ok(())
    }

    /// API dispatch (the implemented core; others safe-default to 0/null).
    fn exec_call_api(&mut self, cur: usize, inst: &BcInst) -> Result<(), VmError> {
        let (api_id, ops) = if let Ops::Call { funcid, ops, .. } = &inst.ops {
            (*funcid as usize, ops.clone())
        } else {
            return Err(VmError::Bytecode("bad api call".into()));
        };
        let (kind, _idx) = API_TABLE.get(api_id).copied().unwrap_or((255, 0));
        let dest = inst.dest;

        // Helper closures can't borrow self mutably twice; inline per-API below.
        match api_id {
            // read(buf*, size) — fill buf from file at ctx.off
            1 => {
                let size = self.read_op(cur, ops[1], 4)? as i32;
                if size < 0 {
                    self.write_dest(cur, dest, 4, (-1i32) as u32 as u64)?;
                    return Ok(());
                }
                let (g, idx, off) = self.resolve_pop(cur, ops[0], size as usize)?;
                let mut tmp = vec![0u8; size as usize];
                let n = self.ctx.read_file(self.ctx.off, &mut tmp);
                self.region_bytes_mut(g, idx)[off..off + n].copy_from_slice(&tmp[..n]);
                self.ctx.off += n as u32;
                self.write_dest(cur, dest, 4, n as u32 as u64)?;
            }
            // write — not persisted here; report bytes "written".
            2 => {
                let size = self.read_op(cur, ops[1], 4)? as u32;
                self.write_dest(cur, dest, 4, size as u64)?;
            }
            // seek(pos, whence)
            3 => {
                let pos = self.read_op(cur, ops[0], 4)? as i32;
                let whence = self.read_op(cur, ops[1], 4)? as u32;
                let off: i64 = match whence {
                    0 => pos as i64,
                    1 => self.ctx.off as i64 + pos as i64,
                    2 => self.ctx.file_size as i64 + pos as i64,
                    _ => -1,
                };
                if off < 0 || off > self.ctx.file_size as i64 {
                    self.write_dest(cur, dest, 4, (-1i32) as u32 as u64)?;
                } else {
                    self.ctx.off = off as u32;
                    self.write_dest(cur, dest, 4, off as u64)?;
                }
            }
            // setvirusname(name*, len)
            4 => {
                let len = self.read_op(cur, ops[1], 4)? as usize;
                let (g, idx, off) = self.resolve_pop(cur, ops[0], 1)?;
                let region = self.region_bytes(g, idx);
                let bytes = &region[off..];
                let end = bytes
                    .iter()
                    .take(len.max(1).min(bytes.len()))
                    .position(|&b| b == 0)
                    .unwrap_or_else(|| bytes.len().min(len.max(64)));
                self.ctx.virname = Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
                self.write_dest(cur, dest, 4, 0)?;
            }
            // debug_print_str / debug_print_uint / traces → no-op
            5 | 6 | 8..=13 | 53 | 54 => {
                self.write_dest(cur, dest, 4, 0)?;
            }
            // pe_rawaddr(rva)
            14 => {
                let rva = self.read_op(cur, ops[0], 4)? as u32;
                let raw = cli_rawaddr(rva, &self.ctx.sections, self.ctx.hdr_size, self.ctx.file_size);
                self.write_dest(cur, dest, 4, raw as u64)?;
            }
            // file_find(data*, len)
            15 => {
                let len = self.read_op(cur, ops[1], 4)? as u32;
                let r = self.file_find(cur, ops[0], len, self.ctx.file_size as i32)?;
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // file_byteat(off)
            16 => {
                let off = self.read_op(cur, ops[0], 4)? as u32;
                let mut b = [0u8; 1];
                let r = if self.ctx.read_file(off, &mut b) == 1 {
                    b[0] as i32
                } else {
                    -1
                };
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // malloc(size) → new glob region
            17 => {
                let size = self.read_op(cur, ops[0], 4)? as usize;
                let ptr = if size == 0 || size > 0x1000_0000 {
                    0i64
                } else {
                    self.globs.push(vec![0u8; size]);
                    ((self.globs.len() as i64) << 32) | 0
                };
                self.write_dest(cur, dest, 8, ptr as u64)?;
            }
            // get_pe_section(section*, num)
            19 => {
                let num = self.read_op(cur, ops[1], 4)? as usize;
                let r = if num < self.ctx.sections.len() {
                    let s = self.ctx.sections[num];
                    let (g, idx, off) = self.resolve_pop(cur, ops[0], 36)?;
                    let region = self.region_bytes_mut(g, idx);
                    for (k, v) in [
                        s.rva, s.vsz, s.raw, s.rsz, s.chr, s.urva, s.uvsz, s.uraw, s.ursz,
                    ]
                    .iter()
                    .enumerate()
                    {
                        write_le(region, off + k * 4, 4, *v as u64);
                    }
                    0i32
                } else {
                    -1
                };
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // read_number(radix) — read an integer of the given radix at ctx.off
            22 => {
                let r = self.read_number()?;
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // memstr(h*, hs, n*, ns)
            50 => {
                let hs = self.read_op(cur, ops[1], 4)? as i32;
                let ns = self.read_op(cur, ops[3], 4)? as i32;
                let r = if hs < 0 || ns < 0 {
                    -1
                } else {
                    let (g1, i1, o1) = self.resolve_pop(cur, ops[0], hs as usize)?;
                    let (g2, i2, o2) = self.resolve_pop(cur, ops[2], ns as usize)?;
                    let h = self.region_bytes(g1, i1)[o1..o1 + hs as usize].to_vec();
                    let n = &self.region_bytes(g2, i2)[o2..o2 + ns as usize];
                    match find_sub(&h, n) {
                        Some(p) => p as i32,
                        None => -1,
                    }
                };
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // hex2ui(ah, bh)
            51 => {
                let ah = self.read_op(cur, ops[0], 4)? as u8;
                let bh = self.read_op(cur, ops[1], 4)? as u8;
                let r = match (hex_nibble(ah), hex_nibble(bh)) {
                    (Some(h), Some(l)) => ((h << 4) | l) as i32,
                    _ => -1,
                };
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // atoi(str*, len)
            52 => {
                let len = self.read_op(cur, ops[1], 4)? as i32;
                let r = if len < 0 {
                    -1
                } else {
                    let (g, idx, off) = self.resolve_pop(cur, ops[0], len as usize)?;
                    bc_atoi(&self.region_bytes(g, idx)[off..off + len as usize])
                };
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // file_find_limit(data*, len, limit)
            64 => {
                let len = self.read_op(cur, ops[1], 4)? as u32;
                let limit = self.read_op(cur, ops[2], 4)? as i32;
                let r = self.file_find(cur, ops[0], len, limit)?;
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            // engine_functionality_level / dconf_level
            65 | 66 => {
                self.write_dest(cur, dest, 4, ENGINE_FLEVEL as u64)?;
            }
            // ilog2(a,b)
            45 => {
                let a = self.read_op(cur, ops[0], 4)? as u32;
                let b = self.read_op(cur, ops[1], 4)? as u32;
                let r = bc_ilog2(a, b);
                self.write_dest(cur, dest, 4, r as u32 as u64)?;
            }
            _ => {
                // Unimplemented API: safe default. Pointer-returning kinds (3,6)
                // get a null pointer; everything else gets 0.
                let wn = if kind == 3 || kind == 6 { 8 } else { 4 };
                self.write_dest(cur, dest, wn, 0)?;
            }
        }
        Ok(())
    }

    fn file_find(&mut self, cur: usize, data_op: u32, len: u32, limit: i32) -> Result<i32, VmError> {
        if len == 0 || len > 1024 || limit <= 0 {
            return Ok(-1);
        }
        let (g, idx, off) = self.resolve_pop(cur, data_op, len as usize)?;
        let needle = self.region_bytes(g, idx)[off..off + len as usize].to_vec();
        let start = self.ctx.off as usize;
        let end = (limit as usize).min(self.ctx.file.len());
        if start >= end {
            return Ok(-1);
        }
        match find_sub(&self.ctx.file[start..end], &needle) {
            Some(p) => Ok((start + p) as i32),
            None => Ok(-1),
        }
    }

    fn read_number(&mut self) -> Result<i32, VmError> {
        // Skip to the next digit, then parse a decimal run (radix 10 is the
        // overwhelmingly common case in real signatures).
        let file = self.ctx.file;
        let mut i = self.ctx.off as usize;
        while i < file.len() && !file[i].is_ascii_digit() {
            i += 1;
        }
        if i >= file.len() {
            self.ctx.off = file.len() as u32;
            return Ok(-1);
        }
        let mut n: i64 = 0;
        while i < file.len() && file[i].is_ascii_digit() {
            n = n * 10 + (file[i] - b'0') as i64;
            i += 1;
            if n > i64::from(i32::MAX) {
                break;
            }
        }
        self.ctx.off = i as u32;
        Ok(n as i32)
    }
}

#[inline]
fn unary(ops: &Ops) -> u32 {
    match ops {
        Ops::Unary(u) => *u,
        Ops::Binop(b) => b[0],
        _ => 0,
    }
}

fn hex_nibble(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

fn bc_atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < s.len() && s[i] == b'+' {
        i += 1;
    }
    if i >= s.len() || s[i] == b'-' || !s[i].is_ascii_digit() {
        return -1;
    }
    let mut n: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        n = n * 10 + (s[i] - b'0') as i64;
        i += 1;
    }
    n as i32
}

fn bc_ilog2(a: u32, b: u32) -> i32 {
    // ClamAV ilog2 returns floor(log2(a/b) * 65536) style scaled value; the exact
    // formula is rarely depended on. Approximate with integer log2 ratio.
    if b == 0 {
        return 0;
    }
    let r = a as f64 / b as f64;
    if r <= 0.0 {
        0
    } else {
        (r.log2() * 65536.0) as i32
    }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `cli_rawaddr` — translate an RVA to a file (raw) offset using the sections.
fn cli_rawaddr(rva: u32, sections: &[PeSection], hdr_size: u32, fsize: u32) -> u32 {
    const PE_INVALID_RVA: u32 = 0xffff_ffff;
    if rva < hdr_size {
        return if rva < fsize { rva } else { PE_INVALID_RVA };
    }
    for s in sections {
        if rva >= s.rva && rva < s.rva.saturating_add(s.vsz.max(s.rsz)) {
            let off = s.raw.saturating_add(rva - s.rva);
            return if off < fsize { off } else { PE_INVALID_RVA };
        }
    }
    PE_INVALID_RVA
}

impl Bc {
    /// Run this (prepared) bytecode against `ctx`, executing the entrypoint
    /// (function 0). Registers the ctx globals (match counts/offsets, filesize,
    /// kind, pedata) and globalBytes, then interprets. Returns the entrypoint's
    /// return value; a detection is signalled via `ctx.virname`.
    pub fn run(&self, ctx: &mut BcCtx) -> Result<i64, VmError> {
        if !self.prepared || self.skipped || self.funcs.is_empty() {
            return Err(VmError::Bytecode("bytecode not runnable".into()));
        }
        // Build the global regions (1-based ids; index 0 == id 1).
        let mut globs: Vec<Vec<u8>> = vec![Vec::new(); GID_GLOBALBYTES];
        let mut mc = vec![0u8; 256];
        let mut mo = vec![0u8; 256];
        for i in 0..64 {
            write_le(&mut mc, i * 4, 4, ctx.lsigcnt[i] as u64);
            write_le(&mut mo, i * 4, 4, ctx.lsigoff[i] as u64);
        }
        globs[GID_MATCH_COUNTS - 1] = mc;
        globs[GID_MATCH_OFFSETS - 1] = mo;
        globs[GID_KIND - 1] = (ctx.kind).to_le_bytes().to_vec();
        globs[GID_FILESIZE - 1] = ctx.file_size.to_le_bytes().to_vec();
        // pedata: a region large enough for in-struct reads, with the key fields
        // (offset, ep, nsections, hdr_size are the common ones) populated.
        let mut pedata = vec![0u8; 512];
        write_le(&mut pedata, 0, 4, 0); // offset
        write_le(&mut pedata, 4, 4, ctx.ep as u64); // ep (file offset)
        write_le(&mut pedata, 8, 2, ctx.nsections as u64); // nsections
        globs[GID_PEDATA - 1] = pedata;
        globs[GID_GLOBALBYTES - 1] = self.global_bytes.clone();

        let mut vm = Vm {
            bc: self,
            ctx,
            stacks: Vec::new(),
            globs,
            ops_done: 0,
        };
        vm.execute(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a value in ClamBC's nibble format (for testing the readers).
    fn enc_number(n: u64) -> Vec<u8> {
        if n == 0 {
            return vec![0x60];
        }
        let mut nibbles = Vec::new();
        let mut v = n;
        while v != 0 {
            nibbles.push((v & 0xf) as u8);
            v >>= 4;
        }
        let mut out = vec![0x60 + nibbles.len() as u8];
        for nib in nibbles {
            out.push(0x60 | nib);
        }
        out
    }

    #[test]
    fn read_number_roundtrips() {
        for n in [0u64, 1, 5, 15, 16, 255, 256, 0xdead_beef, u32::MAX as u64] {
            let mut buf = enc_number(n);
            let mut r = Reader::new(&mut buf);
            let got = r.read_number();
            assert!(r.ok, "reader failed for {n}");
            assert_eq!(got, n, "roundtrip mismatch for {n}");
            assert_eq!(r.off, r.len(), "did not consume all bytes for {n}");
        }
    }

    #[test]
    fn read_fixed_and_data() {
        // fixed width 2 encoding of 42 = nibbles [a, 2] -> 0x6a 0x62
        let mut buf = vec![0x6a, 0x62];
        let mut r = Reader::new(&mut buf);
        assert_eq!(r.read_fixed(2), 42);

        // data: '|' + len(3) + 3 bytes (0xAB, 0xCD, 0xEF) low-nibble-first
        let mut data = vec![b'|'];
        data.extend(enc_number(3));
        for b in [0xABu8, 0xCD, 0xEF] {
            data.push(0x60 | (b & 0xf));
            data.push(0x60 | (b >> 4));
        }
        let mut r = Reader::new(&mut data);
        assert_eq!(r.read_data().unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn rejects_invalid_number_tag() {
        let mut buf = vec![0x10, 0x20]; // first byte far out of 0x60 range
        let mut r = Reader::new(&mut buf);
        let _ = r.read_number();
        assert!(!r.ok);
    }

    #[test]
    fn prepare_lays_out_stack_and_remaps_operands() {
        // One function: 2 i32 locals (values 0,1) + 1 constant.
        // Layout: v0@0 (i32), v1@4 (i32), pad to 8, const@8 → numBytes 16.
        // map = [0, 4, 8]. An ADD v0 = v1 + const(idx 2) remaps to dest 0,
        // operands [4, 8].
        let add = BcInst {
            opcode: OP_BC_ADD,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_ADD as u8 * 5 + 3,
            ops: Ops::Binop([1, 2]),
        };
        let mut bc = Bc {
            num_func: 1,
            funcs: vec![BcFunc {
                num_args: 0,
                num_locals: 2,
                num_insts: 1,
                num_values: 2,
                num_constants: 1,
                return_type: 32,
                types: vec![32, 32],
                bbs: vec![BcBB { insts: vec![add] }],
                constants: vec![7],
                num_bytes: 0,
                insn_idx: 1,
            }],
            ..Bc::default()
        };
        bc.prepare_interpreter().expect("prepare should succeed");
        let f = &bc.funcs[0];
        assert_eq!(f.num_bytes, 16);
        let inst = &f.bbs[0].insts[0];
        assert_eq!(inst.dest, 0);
        match &inst.ops {
            Ops::Binop(b) => assert_eq!(*b, [4, 8]),
            other => panic!("expected binop, got {other:?}"),
        }
    }

    fn one_func_bc(insts: Vec<BcInst>, constants: Vec<u64>, num_locals: u32) -> Bc {
        let num_values = num_locals;
        Bc {
            num_func: 1,
            funcs: vec![BcFunc {
                num_args: 0,
                num_locals,
                num_insts: insts.len() as u32,
                num_values,
                num_constants: constants.len() as u32,
                return_type: 32,
                types: vec![32; num_locals as usize],
                bbs: vec![BcBB { insts }],
                constants,
                num_bytes: 0,
                insn_idx: 0,
            }],
            ..Bc::default()
        }
    }

    #[test]
    fn executes_arithmetic_and_returns() {
        // result = const5 + const7; return result.  (values: 0=result; consts 1,2)
        let add = BcInst {
            opcode: OP_BC_ADD,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_ADD as u8 * 5 + 3,
            ops: Ops::Binop([1, 2]),
        };
        let ret = BcInst {
            opcode: OP_BC_RET,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_RET as u8 * 5 + 3,
            ops: Ops::Unary(0),
        };
        let mut bc = one_func_bc(vec![add, ret], vec![5, 7], 1);
        bc.prepare_interpreter().unwrap();
        let mut ctx = BcCtx::new(&[]);
        assert_eq!(bc.run(&mut ctx).unwrap(), 12);
    }

    #[test]
    fn executes_file_byteat_api() {
        // result = file_byteat(0); return result.  const 0 is value index 1.
        let call = BcInst {
            opcode: OP_BC_CALL_API,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_CALL_API as u8 * 5,
            ops: Ops::Call {
                funcid: 16, // file_byteat
                is_api: true,
                ops: vec![1],
            },
        };
        let ret = BcInst {
            opcode: OP_BC_RET,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_RET as u8 * 5 + 3,
            ops: Ops::Unary(0),
        };
        let mut bc = one_func_bc(vec![call, ret], vec![0], 1);
        bc.prepare_interpreter().unwrap();
        let mut ctx = BcCtx::new(b"ABC");
        assert_eq!(bc.run(&mut ctx).unwrap(), 0x41); // 'A'
    }

    #[test]
    fn branch_selects_correct_value() {
        // if (const1 < const2) return 111 else return 222.
        // values: 0 = cmp result (i8). consts: 1=1, 2=2, 3=111, 4=222.
        let icmp = BcInst {
            opcode: OP_BC_ICMP_ULT,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_ICMP_ULT as u8 * 5 + 3,
            ops: Ops::Binop([1, 2]),
        };
        let branch = BcInst {
            opcode: OP_BC_BRANCH,
            ty: 0,
            dest: 0,
            interp_op: OP_BC_BRANCH as u8 * 5,
            ops: Ops::Branch {
                condition: 0,
                br_true: 1,
                br_false: 2,
            },
        };
        let ret_t = BcInst {
            opcode: OP_BC_RET,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_RET as u8 * 5 + 3,
            ops: Ops::Unary(3),
        };
        let ret_f = BcInst {
            opcode: OP_BC_RET,
            ty: 32,
            dest: 0,
            interp_op: OP_BC_RET as u8 * 5 + 3,
            ops: Ops::Unary(4),
        };
        let mut bc = one_func_bc(vec![], vec![1, 2, 111, 222], 1);
        // three basic blocks: entry (icmp+branch), true, false
        bc.funcs[0].bbs = vec![
            BcBB {
                insts: vec![icmp, branch],
            },
            BcBB { insts: vec![ret_t] },
            BcBB { insts: vec![ret_f] },
        ];
        bc.funcs[0].num_insts = 4;
        bc.prepare_interpreter().unwrap();
        let mut ctx = BcCtx::new(&[]);
        assert_eq!(bc.run(&mut ctx).unwrap(), 111);
    }
}
