// unpacker/recipe.rs — the unpack steps of an unpacker signature and their
// interpreter (format: UNPACK_FORMAT.md).
//
// A recipe is a small program over the file: integer variables, named byte
// buffers (`file` is the input), and steps that find, read, cut, decrypt and
// decompress data, branch and loop, emulate the stub until something happens
// and read its memory. `emit` / `dump` give the unpacked payload(s). Any step
// that cannot do what it says fails the recipe; the caller then uses its
// generic way.

use crate::unpacker::codecs::{self, Codec};
use crate::unpacker::engine::{entrypoint, Sample, StopHit, Stops, UnpackerEngine};
use crate::unpacker::expr::{Env, Expr};
use hydradragonsig::models::BehaviorTrace;
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, HashMap};

/// Bytes one buffer may hold.
const MAX_BUFFER: usize = 256 << 20;
/// Bytes all payloads of one run may hold together.
const MAX_OUTPUT: usize = 512 << 20;
/// Steps one run may execute (loops included).
const MAX_STEPS: u64 = 2_000_000;
/// Default iteration bound of `repeat`.
const DEFAULT_REPEAT: u64 = 100_000;
/// API arguments `run_until` stores as `arg0..` when it stops at an API.
const API_ARGS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    // --- data -------------------------------------------------------------
    /// Offset of a hex pattern in a buffer (`??` = any byte).
    Find(Find),
    /// An integer field of a buffer.
    Read(Read),
    /// A slice of a buffer as a new buffer.
    Take(Take),
    /// Assign variables: `set: {pos: "pos + 4", n: 0}` (in order).
    Set(BTreeMap<String, Expr>),
    /// Fail the recipe unless the expression is not 0.
    Check(Expr),
    /// The raw data and header fields of a PE section.
    Section(SectionStep),
    /// The data of a PE resource.
    Resource(ResourceStep),
    // --- transforms -------------------------------------------------------
    Decompress(Decompress),
    Xor(KeyOp),
    /// Byte-wise add / subtract of a repeating key.
    Add(KeyOp),
    Sub(KeyOp),
    /// Rotate every byte left / right.
    Rol(Rotate),
    Ror(Rotate),
    Rc4(KeyOp),
    Base64(BufOp),
    Reverse(BufOp),
    /// Concatenate buffers.
    Join(Join),
    // --- flow -------------------------------------------------------------
    If(If),
    /// Alternatives: the first one that does not fail is kept (its variables,
    /// buffers and payloads); the others leave no trace.
    Try(Vec<Vec<Step>>),
    Repeat(Repeat),
    // --- output -----------------------------------------------------------
    /// A buffer is an unpacked payload.
    Emit(String),
    // --- emulation (not inside `try` / `repeat`) --------------------------
    /// Emulate from the current instruction until one of the conditions holds;
    /// stops BEFORE that instruction. Sets `ip`, and `arg0..arg7` at an API.
    RunUntil(RunUntil),
    /// Emulated memory as a buffer (a VirtualAlloc'd payload, a decrypted
    /// section).
    Mem(Mem),
    /// Set the instruction pointer: the entry point of the next `dump`.
    SetOep(Oep),
    /// The memory image (entry point = instruction pointer, imports rebuilt) is
    /// an unpacked payload.
    Dump,
    /// The allocated memory region the code runs in (the instruction pointer's
    /// when it is outside the image, else the first write-execute outside it) is a
    /// payload: a PE mapped there dumped like the image, else the raw region.
    DumpAlloc,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Find {
    #[serde(rename = "in", default = "file")]
    pub buf: String,
    pub pattern: String,
    /// Search from this offset.
    #[serde(default)]
    pub from: Option<Expr>,
    /// Only a match whose `offset + match` is a multiple of this counts.
    #[serde(default)]
    pub align: Option<u64>,
    /// Added to the match (`-4`: the field before the pattern).
    #[serde(default)]
    pub offset: i64,
    #[serde(rename = "as")]
    pub var: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Read {
    #[serde(rename = "in", default = "file")]
    pub buf: String,
    pub at: Expr,
    #[serde(rename = "type")]
    pub ty: IntType,
    #[serde(default)]
    pub big_endian: bool,
    #[serde(rename = "as")]
    pub var: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Take {
    #[serde(rename = "in", default = "file")]
    pub buf: String,
    #[serde(default)]
    pub at: Option<Expr>,
    /// Default: to the end of the buffer.
    #[serde(default)]
    pub len: Option<Expr>,
    #[serde(rename = "as")]
    pub out: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionStep {
    #[serde(default)]
    pub name: Option<String>,
    /// 0-based index in the section table.
    #[serde(default)]
    pub index: Option<usize>,
    /// Buffer with the raw data; variables `<as>_off`, `<as>_size`, `<as>_rva`,
    /// `<as>_vsize`, `<as>_flags`.
    #[serde(rename = "as")]
    pub out: String,
}

/// A resource type / name: a number (`10` = RT_RCDATA) or a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResKey {
    Id(u32),
    Name(String),
}

impl<'de> Deserialize<'de> for ResKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Id(u32),
            Name(String),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Id(n) => ResKey::Id(n),
            Raw::Name(s) => ResKey::Name(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceStep {
    /// Default: any type.
    #[serde(rename = "type", default)]
    pub ty: Option<ResKey>,
    /// Default: any name.
    #[serde(default)]
    pub name: Option<ResKey>,
    /// Of the matching resources (in directory order), take the n-th. Default 0.
    #[serde(default)]
    pub nth: usize,
    #[serde(rename = "as")]
    pub out: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decompress {
    #[serde(rename = "in")]
    pub buf: String,
    /// One codec, or a list tried in order.
    #[serde(deserialize_with = "one_or_many")]
    pub method: Vec<Codec>,
    /// Exact output size when the format does not store it.
    #[serde(default)]
    pub size: Option<Expr>,
    /// Name of a variable that gets the index of the codec that worked.
    #[serde(default)]
    pub method_as: Option<String>,
    #[serde(rename = "as", default)]
    pub out: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyOp {
    #[serde(rename = "in")]
    pub buf: String,
    /// Hex key bytes: `"6B 65 79"`.
    #[serde(default)]
    pub key: Option<String>,
    /// The key is this buffer.
    #[serde(default)]
    pub key_buf: Option<String>,
    /// Skip this many bytes (they stay as they are).
    #[serde(default)]
    pub from: Option<Expr>,
    #[serde(rename = "as", default)]
    pub out: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotate {
    #[serde(rename = "in")]
    pub buf: String,
    pub bits: Expr,
    #[serde(rename = "as", default)]
    pub out: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BufOp {
    #[serde(rename = "in")]
    pub buf: String,
    #[serde(rename = "as", default)]
    pub out: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Join {
    pub parts: Vec<String>,
    #[serde(rename = "as")]
    pub out: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct If {
    pub cond: Expr,
    #[serde(default)]
    pub then: Vec<Step>,
    #[serde(rename = "else", default)]
    pub otherwise: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repeat {
    #[serde(rename = "while")]
    pub cond: Expr,
    /// Most iterations; reaching it fails the recipe.
    #[serde(default)]
    pub max: Option<u64>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunUntil {
    /// Executing a page this run has written.
    #[serde(default)]
    pub write_execute: bool,
    /// Calling one of these APIs (stop at its stub, before the call).
    #[serde(default)]
    pub api: Vec<String>,
    /// Entering one of these sections.
    #[serde(default)]
    pub section: Vec<String>,
    /// A basic block starting with one of these hex patterns.
    #[serde(default)]
    pub ip_pattern: Vec<String>,
    /// No condition stops inside these sections (the stub's own).
    #[serde(default)]
    pub outside: Vec<String>,
    #[serde(default)]
    pub max_instructions: Option<u64>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mem {
    /// Virtual address.
    pub at: Expr,
    pub len: Expr,
    #[serde(rename = "as")]
    pub out: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Oep {
    /// Where the last `run_until` stopped.
    Ip,
    Rva(Expr),
    Va(Expr),
}

fn file() -> String {
    "file".into()
}

fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Codec>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        One(Codec),
        Many(Vec<Codec>),
    }
    Ok(match Raw::deserialize(d)? {
        Raw::One(c) => vec![c],
        Raw::Many(v) => v,
    })
}

// ---------------------------------------------------------------------------
// Load-time checks
// ---------------------------------------------------------------------------

/// A recipe gives a payload somewhere (`emit` / `dump`), keeps emulation out of
/// `try` / `repeat` (an alternative that fails could not undo it), and every
/// pattern / key parses.
pub fn check(steps: &[Step]) -> Result<(), String> {
    fn walk(steps: &[Step], in_alt: bool, out: &mut bool) -> Result<(), String> {
        for (i, s) in steps.iter().enumerate() {
            let at = |e: String| format!("step {}: {e}", i + 1);
            match s {
                Step::Find(f) => {
                    pattern(&f.pattern).map_err(at)?;
                    if f.align == Some(0) {
                        return Err(at("align 0".into()));
                    }
                }
                Step::Section(s) if s.name.is_none() == s.index.is_none() => {
                    return Err(at("section: give name or index".into()));
                }
                Step::Decompress(d) if d.method.is_empty() => return Err(at("decompress: no method".into())),
                Step::Xor(k) | Step::Add(k) | Step::Sub(k) | Step::Rc4(k) => {
                    match (&k.key, &k.key_buf) {
                        (Some(h), None) => {
                            let key = hex(h).map_err(at)?;
                            if key.is_empty() {
                                return Err(at("empty key".into()));
                            }
                        }
                        (None, Some(_)) => {}
                        _ => return Err(at("give key or key_buf".into())),
                    }
                }
                Step::If(f) => {
                    walk(&f.then, in_alt, out).map_err(at)?;
                    walk(&f.otherwise, in_alt, out).map_err(at)?;
                }
                Step::Try(alts) => {
                    if alts.is_empty() {
                        return Err(at("try: no alternative".into()));
                    }
                    for a in alts {
                        walk(a, true, out).map_err(at)?;
                    }
                }
                Step::Repeat(r) => walk(&r.steps, true, out).map_err(at)?,
                Step::Emit(_) => *out = true,
                Step::RunUntil(_) | Step::Mem(_) | Step::SetOep(_) | Step::Dump | Step::DumpAlloc if in_alt => {
                    return Err(at("emulation steps cannot be inside try / repeat".into()));
                }
                Step::RunUntil(r) => {
                    if !r.write_execute && r.api.is_empty() && r.section.is_empty() && r.ip_pattern.is_empty() {
                        return Err(at("run_until without a condition".into()));
                    }
                    for p in &r.ip_pattern {
                        pattern(p).map_err(at)?;
                    }
                }
                Step::Dump | Step::DumpAlloc => *out = true,
                _ => {}
            }
        }
        Ok(())
    }
    let mut out = false;
    walk(steps, false, &mut out)?;
    if !out {
        return Err("the recipe never gives a payload (emit / dump)".into());
    }
    Ok(())
}

fn pattern(s: &str) -> Result<Vec<Option<u8>>, String> {
    let p = crate::disinfect::rules::parse_hex_pattern(s.trim().trim_start_matches('{').trim_end_matches('}'))?;
    if p.is_empty() || p[0].is_none() {
        return Err(format!("pattern {s:?} must start with a fixed byte"));
    }
    Ok(p)
}

fn hex(s: &str) -> Result<Vec<u8>, String> {
    crate::disinfect::rules::parse_hex_pattern(s)?
        .into_iter()
        .map(|b| b.ok_or_else(|| format!("wildcard in key {s:?}")))
        .collect()
}

// ---------------------------------------------------------------------------
// Interpreter
// ---------------------------------------------------------------------------

/// The unpacked payloads, or why the recipe does not fit the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Unpacked(Vec<Vec<u8>>),
    Failed(String),
}

/// Budget an emulation step gets when the recipe does not give one.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_instructions: usize,
    pub timeout_us: u64,
}

struct State<'a> {
    file: &'a [u8],
    pe: Option<pefile_rs::PE>,
    ints: HashMap<String, i128>,
    bufs: HashMap<String, Vec<u8>>,
    out: Vec<Vec<u8>>,
    out_bytes: usize,
    steps: u64,
    eng: Option<UnpackerEngine>,
    budget: Budget,
}

impl Env for State<'_> {
    fn var(&self, name: &str) -> Option<i128> {
        self.ints.get(name).copied()
    }

    fn buf_len(&self, name: &str) -> Option<usize> {
        if name == "file" { Some(self.file.len()) } else { self.bufs.get(name).map(Vec::len) }
    }

    fn call(&self, name: &str, args: &[i128]) -> Result<i128, String> {
        let pe = || self.pe.as_ref().ok_or_else(|| format!("{name}: not a PE"));
        let one = || match args {
            [a] => u32::try_from(*a).map_err(|_| format!("{name}: {a} is out of range")),
            _ => Err(format!("{name} takes one argument")),
        };
        match name {
            "rva2off" => pe()?.get_offset_from_rva(one()?).map(|o| o as i128).map_err(|e| format!("rva2off: {e}")),
            "off2rva" => pe()?.get_rva_from_offset(one()? as usize).map(|r| r as i128).map_err(|e| format!("off2rva: {e}")),
            "min" | "max" => match args {
                [a, b] => Ok(if name == "min" { *a.min(b) } else { *a.max(b) }),
                _ => Err(format!("{name} takes two arguments")),
            },
            _ => Err(format!("unknown function {name}()")),
        }
    }
}

/// Runs `steps` over `data`. The trace is the API calls of the emulated steps.
pub fn run(data: &[u8], steps: &[Step], budget: Budget) -> (Outcome, BehaviorTrace) {
    let pe = pefile_rs::PE::parse(data).ok();
    let mut ints = HashMap::from([("file_size".to_string(), data.len() as i128)]);
    if let Some(pe) = &pe {
        let ep = pe.optional_header.address_of_entry_point as i128;
        let overlay = pe
            .sections
            .iter()
            .map(|s| s.pointer_to_raw_data as i128 + s.size_of_raw_data as i128)
            .max()
            .unwrap_or(0)
            .min(data.len() as i128);
        ints.insert("entry_rva".into(), ep);
        ints.insert("image_base".into(), pe.optional_header.image_base as i128);
        ints.insert("size_of_image".into(), pe.optional_header.size_of_image as i128);
        ints.insert("overlay".into(), overlay);
        ints.insert("is_64".into(), pe.is_64bit as i128);
        ints.insert("sections".into(), pe.sections.len() as i128);
    }
    let mut st = State { file: data, pe, ints, bufs: HashMap::new(), out: Vec::new(), out_bytes: 0, steps: 0, eng: None, budget };
    let result = st.block(steps);
    let trace = st.eng.as_ref().map(|e| e.behavior_trace().clone()).unwrap_or_default();
    let outcome = match result {
        Err(e) => Outcome::Failed(e),
        Ok(()) if st.out.is_empty() => Outcome::Failed("no payload".into()),
        Ok(()) => Outcome::Unpacked(st.out),
    };
    (outcome, trace)
}

impl State<'_> {
    fn block(&mut self, steps: &[Step]) -> Result<(), String> {
        for (i, s) in steps.iter().enumerate() {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err(format!("more than {MAX_STEPS} steps"));
            }
            self.step(s).map_err(|e| format!("step {} ({}): {e}", i + 1, name(s)))?;
        }
        Ok(())
    }

    fn eval(&self, e: &Expr) -> Result<i128, String> {
        e.eval(self)
    }

    fn usize(&self, e: &Expr) -> Result<usize, String> {
        let v = self.eval(e)?;
        usize::try_from(v).map_err(|_| format!("{v} is not an offset / size"))
    }

    fn buf(&self, name: &str) -> Result<&[u8], String> {
        if name == "file" {
            return Ok(self.file);
        }
        self.bufs.get(name).map(Vec::as_slice).ok_or_else(|| format!("buffer `{name}` is not set"))
    }

    fn put(&mut self, name: &str, data: Vec<u8>) -> Result<(), String> {
        if name == "file" {
            return Err("`file` is the input and cannot be replaced".into());
        }
        if data.len() > MAX_BUFFER {
            return Err(format!("buffer `{name}` would hold {} bytes", data.len()));
        }
        self.bufs.insert(name.to_string(), data);
        Ok(())
    }

    fn set(&mut self, name: &str, v: i128) {
        self.ints.insert(name.to_string(), v);
    }

    fn key(&self, k: &KeyOp) -> Result<Vec<u8>, String> {
        let key = match (&k.key, &k.key_buf) {
            (Some(h), _) => hex(h)?,
            (None, Some(b)) => self.buf(b)?.to_vec(),
            _ => return Err("no key".into()),
        };
        if key.is_empty() { Err("empty key".into()) } else { Ok(key) }
    }

    /// `f` over the bytes of `k.buf` from `k.from`, into `k.out` (default: in place).
    fn transform(&mut self, buf: &str, from: Option<&Expr>, out: Option<&String>, f: impl FnOnce(&mut [u8]) -> Result<(), String>) -> Result<(), String> {
        let from = from.map(|e| self.usize(e)).transpose()?.unwrap_or(0);
        let mut data = self.buf(buf)?.to_vec();
        f(data.get_mut(from..).ok_or_else(|| format!("from {from} is past the end of `{buf}`"))?)?;
        self.put(out.map_or(buf, String::as_str), data)
    }

    fn step(&mut self, s: &Step) -> Result<(), String> {
        match s {
            Step::Find(f) => {
                let pat = pattern(&f.pattern)?;
                let from = f.from.as_ref().map(|e| self.usize(e)).transpose()?.unwrap_or(0);
                let data = self.buf(&f.buf)?;
                let hit = (from..data.len().saturating_sub(pat.len() - 1))
                    .filter(|&i| pat.iter().zip(&data[i..]).all(|(p, b)| p.is_none_or(|p| p == *b)))
                    .map(|i| i as i128 + f.offset as i128)
                    .find(|&at| at >= 0 && f.align.is_none_or(|a| at % a as i128 == 0))
                    .ok_or("pattern not found")?;
                self.set(&f.var, hit);
            }
            Step::Read(r) => {
                let at = self.usize(&r.at)?;
                let size = match r.ty {
                    IntType::U8 | IntType::I8 => 1,
                    IntType::U16 | IntType::I16 => 2,
                    IntType::U32 | IntType::I32 => 4,
                    IntType::U64 | IntType::I64 => 8,
                };
                let bytes = self.buf(&r.buf)?.get(at..at + size).ok_or_else(|| format!("{size} bytes at {at} are past the end of `{}`", r.buf))?;
                let mut b = [0u8; 8];
                for (i, &x) in bytes.iter().enumerate() {
                    b[if r.big_endian { size - 1 - i } else { i }] = x;
                }
                let u = u64::from_le_bytes(b);
                let v = match r.ty {
                    IntType::I8 => u as u8 as i8 as i128,
                    IntType::I16 => u as u16 as i16 as i128,
                    IntType::I32 => u as u32 as i32 as i128,
                    IntType::I64 => u as i64 as i128,
                    _ => u as i128,
                };
                self.set(&r.var, v);
            }
            Step::Take(t) => {
                let at = t.at.as_ref().map(|e| self.usize(e)).transpose()?.unwrap_or(0);
                let data = self.buf(&t.buf)?;
                let len = match &t.len {
                    Some(e) => self.usize(e)?,
                    None => data.len().checked_sub(at).ok_or_else(|| format!("{at} is past the end of `{}`", t.buf))?,
                };
                let part = data.get(at..at.checked_add(len).ok_or("overflow")?).ok_or_else(|| format!("{len} bytes at {at} are past the end of `{}` ({} bytes)", t.buf, data.len()))?;
                let part = part.to_vec();
                self.put(&t.out, part)?;
            }
            Step::Set(vars) => {
                for (k, e) in vars {
                    let v = self.eval(e).map_err(|err| format!("{k}: {err}"))?;
                    self.set(k, v);
                }
            }
            Step::Check(e) => {
                if self.eval(e)? == 0 {
                    return Err("check failed".into());
                }
            }
            Step::Section(s) => {
                let pe = self.pe.as_ref().ok_or("not a PE")?;
                let sec = match (&s.name, s.index) {
                    (Some(n), _) => pe.sections.iter().find(|x| x.name.trim_end_matches('\0') == n),
                    (None, Some(i)) => pe.sections.get(i),
                    _ => None,
                }
                .ok_or("no such section")?
                .clone();
                let data = sec.get_data(self.file).to_vec();
                for (suffix, v) in [
                    ("off", sec.pointer_to_raw_data),
                    ("size", sec.size_of_raw_data),
                    ("rva", sec.virtual_address),
                    ("vsize", sec.virtual_size),
                    ("flags", sec.characteristics),
                ] {
                    self.set(&format!("{}_{suffix}", s.out), v as i128);
                }
                self.put(&s.out, data)?;
            }
            Step::Resource(r) => {
                let data = self.resource(r)?;
                self.put(&r.out, data)?;
            }
            Step::Decompress(d) => {
                let size = d.size.as_ref().map(|e| self.usize(e)).transpose()?;
                let data = self.buf(&d.buf)?;
                let mut errors = Vec::new();
                let mut done = None;
                for (i, &c) in d.method.iter().enumerate() {
                    match codecs::decompress(c, data, size, MAX_BUFFER) {
                        Ok(out) => {
                            done = Some((i, out));
                            break;
                        }
                        Err(e) => errors.push(e),
                    }
                }
                let (i, out) = done.ok_or_else(|| errors.join("; "))?;
                if let Some(v) = &d.method_as {
                    self.set(v, i as i128);
                }
                self.put(d.out.as_deref().unwrap_or(&d.buf), out)?;
            }
            Step::Xor(k) | Step::Add(k) | Step::Sub(k) => {
                let key = self.key(k)?;
                let op = match s {
                    Step::Xor(_) => |b: u8, k: u8| b ^ k,
                    Step::Add(_) => |b: u8, k: u8| b.wrapping_add(k),
                    _ => |b: u8, k: u8| b.wrapping_sub(k),
                };
                self.transform(&k.buf, k.from.as_ref(), k.out.as_ref(), |d| {
                    for (i, b) in d.iter_mut().enumerate() {
                        *b = op(*b, key[i % key.len()]);
                    }
                    Ok(())
                })?;
            }
            Step::Rc4(k) => {
                let key = self.key(k)?;
                self.transform(&k.buf, k.from.as_ref(), k.out.as_ref(), |d| {
                    let plain = codecs::rc4(&key, d)?;
                    d.copy_from_slice(&plain);
                    Ok(())
                })?;
            }
            Step::Rol(r) | Step::Ror(r) => {
                let bits = (self.eval(&r.bits)?.rem_euclid(8)) as u32;
                let left = matches!(s, Step::Rol(_));
                self.transform(&r.buf, None, r.out.as_ref(), |d| {
                    for b in d {
                        *b = if left { b.rotate_left(bits) } else { b.rotate_right(bits) };
                    }
                    Ok(())
                })?;
            }
            Step::Base64(b) => {
                let out = codecs::base64(self.buf(&b.buf)?)?;
                self.put(b.out.as_deref().unwrap_or(&b.buf), out)?;
            }
            Step::Reverse(b) => {
                let mut out = self.buf(&b.buf)?.to_vec();
                out.reverse();
                self.put(b.out.as_deref().unwrap_or(&b.buf), out)?;
            }
            Step::Join(j) => {
                let mut out = Vec::new();
                for p in &j.parts {
                    out.extend_from_slice(self.buf(p)?);
                }
                self.put(&j.out, out)?;
            }
            Step::If(f) => {
                if self.eval(&f.cond)? != 0 {
                    self.block(&f.then)?;
                } else {
                    self.block(&f.otherwise)?;
                }
            }
            Step::Try(alts) => {
                let mut errors = Vec::new();
                for (i, alt) in alts.iter().enumerate() {
                    let saved = (self.ints.clone(), self.bufs.clone(), self.out.len(), self.out_bytes);
                    match self.block(alt) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            errors.push(format!("alternative {}: {e}", i + 1));
                            (self.ints, self.bufs) = (saved.0, saved.1);
                            self.out.truncate(saved.2);
                            self.out_bytes = saved.3;
                        }
                    }
                }
                return Err(errors.join(" | "));
            }
            Step::Repeat(r) => {
                let max = r.max.unwrap_or(DEFAULT_REPEAT);
                let mut n = 0;
                while self.eval(&r.cond)? != 0 {
                    n += 1;
                    if n > max {
                        return Err(format!("still repeating after {max} iterations"));
                    }
                    self.block(&r.steps).map_err(|e| format!("iteration {n}: {e}"))?;
                }
            }
            Step::Emit(name) => {
                let data = self.buf(name)?.to_vec();
                if data.is_empty() {
                    return Err(format!("buffer `{name}` is empty"));
                }
                self.emit(data)?;
            }
            Step::RunUntil(r) => self.run_until(r)?,
            Step::Mem(m) => {
                let (at, len) = (self.eval(&m.at)?, self.usize(&m.len)?);
                if len > MAX_BUFFER {
                    return Err(format!("{len} bytes is over the limit"));
                }
                let at = u64::try_from(at).map_err(|_| format!("bad address {at}"))?;
                let data = self.engine()?.read_mem(at, len).ok_or_else(|| format!("{len} bytes at {at:#x} are not mapped"))?;
                self.put(&m.out, data)?;
            }
            Step::SetOep(o) => {
                let target = match o {
                    Oep::Ip => self.engine()?.ip().ok_or("no instruction pointer")? as i128,
                    Oep::Rva(e) => self.engine()?.sample.base_addr as i128 + self.eval(e)?,
                    Oep::Va(e) => self.eval(e)?,
                };
                let e = self.engine()?;
                let (base, size) = (e.sample.base_addr as i128, e.sample.virtualmemorysize as i128);
                if target < base || target >= base + size {
                    return Err(format!("entry point {target:#x} is outside the image"));
                }
                e.set_ip(target as u64);
            }
            Step::Dump => {
                let image = self.engine()?.dump_bytes().map_err(|e| e.to_string())?;
                if image.is_empty() {
                    return Err("empty dump".into());
                }
                self.emit(image)?;
            }
            Step::DumpAlloc => {
                let e = self.engine()?;
                let (base, size) = (e.sample.base_addr, e.sample.virtualmemorysize);
                let at = e.ip().filter(|&ip| ip < base || ip >= base + size).or(e.wx_alloc_hit).ok_or("no code ran in allocated memory")?;
                let p = e.region_payload(at).ok_or_else(|| format!("{at:#x} is not mapped"))?;
                self.emit(p.pe.unwrap_or(p.memory))?;
            }
        }
        Ok(())
    }

    fn emit(&mut self, data: Vec<u8>) -> Result<(), String> {
        self.out_bytes += data.len();
        if self.out_bytes > MAX_OUTPUT {
            return Err(format!("payloads over {MAX_OUTPUT} bytes"));
        }
        self.out.push(data);
        Ok(())
    }

    /// The emulator, started on the file at its entry point on first use.
    fn engine(&mut self) -> Result<&mut UnpackerEngine, String> {
        if self.eng.is_none() {
            let sample = Sample::from_bytes(self.file).map_err(|e| e.to_string())?;
            let ep = entrypoint(&sample.opt_header);
            let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
            eng.init_uc().map_err(|e| e.to_string())?;
            eng.set_controls(false, false);
            eng.set_end_addr(u64::MAX);
            eng.set_ip(ep);
            self.eng = Some(eng);
        }
        Ok(self.eng.as_mut().expect("set above"))
    }

    fn run_until(&mut self, r: &RunUntil) -> Result<(), String> {
        let patterns = r.ip_pattern.iter().map(|p| pattern(p)).collect::<Result<Vec<_>, _>>()?;
        let max = r.max_instructions.map_or(self.budget.max_instructions, |n| n as usize);
        let timeout = r.timeout_ms.map_or(self.budget.timeout_us, |ms| ms.saturating_mul(1000));
        let e = self.engine()?;
        e.set_stops(Stops {
            write_execute: r.write_execute,
            apis: r.api.clone(),
            sections: r.section.clone(),
            patterns,
            outside: r.outside.clone(),
        });
        let from = e.ip().unwrap_or(0);
        let err = e.emu_from(from, timeout, max).err();
        e.set_stops(Stops::default());
        let Some(hit) = e.stop_hit.clone() else {
            return Err(match (&err, &e.stop_api) {
                (_, Some(api)) => format!("stopped at {api}"),
                (Some(err), _) => err.to_string(),
                _ => format!("{:?} before the condition", e.end),
            });
        };
        e.set_ip(hit.address());
        let args = matches!(hit, StopHit::Api(..)).then(|| e.api_args(API_ARGS));
        self.set("ip", hit.address() as i128);
        for (i, a) in args.into_iter().flatten().enumerate() {
            self.set(&format!("arg{i}"), a as i128);
        }
        Ok(())
    }

    fn resource(&self, r: &ResourceStep) -> Result<Vec<u8>, String> {
        use pefile_rs::ResourceEntry;
        let pe = self.pe.as_ref().ok_or("not a PE")?;
        let root = pe.resources.as_ref().ok_or("no resources")?;
        let fits = |key: &Option<ResKey>, id: u32, name: &Option<String>| match key {
            None => true,
            Some(ResKey::Id(want)) => name.is_none() && id == *want,
            Some(ResKey::Name(want)) => name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(want)),
        };
        // type -> name -> language -> data
        let mut found = Vec::new();
        for (tid, tname, t) in &root.entries {
            let ResourceEntry::Directory(t) = t else { continue };
            if !fits(&r.ty, *tid, tname) {
                continue;
            }
            for (nid, nname, n) in &t.entries {
                if !fits(&r.name, *nid, nname) {
                    continue;
                }
                match n {
                    ResourceEntry::Data(d) => found.push(d.clone()),
                    ResourceEntry::Directory(langs) => {
                        found.extend(langs.entries.iter().filter_map(|(_, _, l)| match l {
                            ResourceEntry::Data(d) => Some(d.clone()),
                            ResourceEntry::Directory(_) => None,
                        }));
                    }
                }
            }
        }
        let d = found.get(r.nth).ok_or("no such resource")?;
        let off = pe.get_offset_from_rva(d.offset_to_data).map_err(|e| e.to_string())?;
        self.file
            .get(off..off + d.size as usize)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| "resource data is past the end of the file".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const BUDGET: Budget = Budget { max_instructions: 1000, timeout_us: 1_000_000 };

    #[derive(Deserialize)]
    struct Doc {
        #[serde(deserialize_with = "yaml_serde::with::singleton_map_recursive::deserialize")]
        unpack: Vec<Step>,
    }

    fn steps(yaml: &str) -> Vec<Step> {
        let doc: Doc = yaml_serde::from_str(yaml).unwrap_or_else(|e| panic!("{e}\n{yaml}"));
        check(&doc.unpack).unwrap_or_else(|e| panic!("{e}\n{yaml}"));
        doc.unpack
    }

    fn unpacked(data: &[u8], yaml: &str) -> Vec<Vec<u8>> {
        match run(data, &steps(yaml), BUDGET).0 {
            Outcome::Unpacked(p) => p,
            Outcome::Failed(e) => panic!("{e}"),
        }
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    /// A made-up container: junk, magic "PKD!" at a 16-byte boundary, a block
    /// count, then blocks `[u32 len | 0x80000000 if zlib][bytes XOR 0x5A]`.
    fn container(blocks: &[(&[u8], bool)]) -> Vec<u8> {
        let mut f = b"stub stub stub PKD! not aligned..".to_vec();
        f.resize(48, 0xCC);
        f.extend_from_slice(b"PKD!");
        f.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        for (data, compressed) in blocks {
            let mut body = if *compressed { zlib(data) } else { data.to_vec() };
            body.iter_mut().for_each(|b| *b ^= 0x5A);
            let len = body.len() as u32 | if *compressed { 0x8000_0000 } else { 0 };
            f.extend_from_slice(&len.to_le_bytes());
            f.extend_from_slice(&body);
        }
        f
    }

    const CONTAINER_RECIPE: &str = r#"
unpack:
  - find: {pattern: "50 4B 44 21", align: 16, as: hdr}
  - read: {at: hdr + 4, type: u32, as: count}
  - set: {pos: hdr + 8, i: 0}
  - repeat:
      while: i < count
      steps:
        - read: {at: pos, type: u32, as: n}
        - take: {at: pos + 4, len: n & 0x7fffffff, as: block}
        - xor: {in: block, key: "5A"}
        - if:
            cond: (n & 0x80000000) != 0
            then:
              - decompress: {in: block, method: [lzma, zlib]}
        - emit: block
        - set: {pos: pos + 4 + (n & 0x7fffffff), i: i + 1}
"#;

    #[test]
    fn container_of_framed_blocks() {
        let text = b"the second file, compressed, repeated repeated repeated".repeat(8);
        let file = container(&[(b"MZ first file", false), (&text, true)]);
        assert_eq!(unpacked(&file, CONTAINER_RECIPE), vec![b"MZ first file".to_vec(), text]);
    }

    #[test]
    fn a_step_that_cannot_happen_fails_the_recipe() {
        let mut file = container(&[(b"abc", false)]);
        let last = file.len() - 1;
        file.truncate(last); // block runs past the end
        let (outcome, _) = run(&file, &steps(CONTAINER_RECIPE), BUDGET);
        let Outcome::Failed(e) = outcome else { panic!("{outcome:?}") };
        assert!(e.contains("past the end"), "{e}");
        let (outcome, _) = run(b"no magic here", &steps(CONTAINER_RECIPE), BUDGET);
        assert!(matches!(outcome, Outcome::Failed(e) if e.contains("not found")));
    }

    #[test]
    fn try_keeps_only_the_alternative_that_worked() {
        let data = b"ab".repeat(8);
        let out = unpacked(
            &data,
            r#"
unpack:
  - try:
    - - take: {at: 0, len: 2, as: x}
      - emit: x
      - check: 0
    - - set: {n: 3}
      - take: {at: 0, len: n, as: y}
      - emit: y
  - check: n == 3
"#,
        );
        assert_eq!(out, vec![b"aba".to_vec()]);
    }

    #[test]
    fn transforms() {
        let out = unpacked(
            b"aGVsbG8=",
            r#"
unpack:
  - base64: {in: file, as: a}
  - reverse: {in: a, as: b}
  - join: {parts: [a, b], as: c}
  - rol: {in: c, bits: 3, as: d}
  - ror: {in: d, bits: 3}
  - add: {in: d, key: "01", from: 5}
  - sub: {in: d, key: "01", from: 5}
  - rc4: {in: d, key: "4B 65 79", as: e}
  - check: len(e) == 10
  - take: {in: e, at: 0, len: 3, as: k_unused}
  - rc4: {in: e, key_buf: d, from: 0}
  - rc4: {in: e, key_buf: d}
  - rc4: {in: e, key: "4B 65 79"}
  - emit: e
"#,
        );
        assert_eq!(out, vec![b"helloolleh".to_vec()]);
    }

    #[test]
    fn reads_and_expressions() {
        let data = [0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF];
        let out = unpacked(
            &data,
            r#"
unpack:
  - read: {at: 0, type: u16, as: le}
  - read: {at: 0, type: u16, big_endian: true, as: be}
  - read: {at: 4, type: i32, as: neg}
  - read: {at: 4, type: u32, as: pos}
  - check: le == 0x0201 && be == 0x0102 && neg == -1 && pos == 0xFFFFFFFF
  - check: file_size == 8 && min(le, be) == 0x0102 && max(le, be) == 0x0201
  - take: {at: file_size - 4, as: tail}
  - emit: tail
"#,
        );
        assert_eq!(out, vec![vec![0xFF; 4]]);
    }

    #[test]
    fn loops_and_steps_are_bounded() {
        let (outcome, _) = run(b"x", &steps("unpack:\n  - repeat: {while: 1, max: 10, steps: [{set: {a: 1}}]}\n  - emit: file\n"), BUDGET);
        assert!(matches!(outcome, Outcome::Failed(e) if e.contains("after 10 iterations")));
        let (outcome, _) = run(b"x", &steps("unpack:\n  - repeat: {while: 1, max: 100000000, steps: [{set: {a: 1}}]}\n  - emit: file\n"), BUDGET);
        assert!(matches!(outcome, Outcome::Failed(e) if e.contains("steps")));
    }

    /// PE32 at 0x400000: `.text` (0x1000) holds a stub that XORs the 8 bytes at
    /// `.data` (0x2000) with 0x5A and jumps there; `.data` holds `mov eax, 42;
    /// ret; nop; nop` XORed with 0x5A.
    fn xor_packed_pe() -> Vec<u8> {
        const ORIGINAL: [u8; 8] = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];
        let stub = [
            0xBE, 0x00, 0x20, 0x40, 0x00, // mov esi, 0x402000
            0xB9, 0x08, 0x00, 0x00, 0x00, // mov ecx, 8
            0x80, 0x36, 0x5A, //             xor byte [esi], 0x5A
            0x46, //                         inc esi
            0xE2, 0xFA, //                   loop xor
            0xE9, 0xEB, 0x0F, 0x00, 0x00, // jmp 0x402000
        ];
        let packed: Vec<u8> = ORIGINAL.iter().map(|b| b ^ 0x5A).collect();
        let sections: [(&str, u32, &[u8], u32); 2] = [(".text", 0x1000, &stub, 0x6000_0020), (".data", 0x2000, &packed, 0xE000_0020)];
        let put32 = |d: &mut Vec<u8>, o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let mut d = vec![0u8; 0x200];
        d[..2].copy_from_slice(b"MZ");
        put32(&mut d, 0x3C, 0x40);
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        let (coff, opt) = (0x44, 0x58);
        d[coff..coff + 2].copy_from_slice(&0x14Cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        d[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
        d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        put32(&mut d, opt + 16, 0x1000);
        put32(&mut d, opt + 28, 0x40_0000);
        put32(&mut d, opt + 32, 0x1000);
        put32(&mut d, opt + 36, 0x200);
        put32(&mut d, opt + 56, 0x3000);
        put32(&mut d, opt + 60, 0x200);
        d[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
        put32(&mut d, opt + 92, 16);
        for (i, (name, rva, data, chars)) in sections.iter().enumerate() {
            let t = opt + 0xE0 + i * 40;
            let raw = d.len() as u32;
            d[t..t + name.len()].copy_from_slice(name.as_bytes());
            put32(&mut d, t + 8, data.len() as u32);
            put32(&mut d, t + 12, *rva);
            put32(&mut d, t + 16, 0x200);
            put32(&mut d, t + 20, raw);
            put32(&mut d, t + 36, *chars);
            let mut s = data.to_vec();
            s.resize(0x200, 0);
            d.extend_from_slice(&s);
        }
        d
    }

    /// PE32 at 0x400000 importing kernel32!VirtualAlloc. Its stub allocates
    /// 0x3000 bytes, copies the `payload` from `.data` (0x402000) there XORing
    /// every byte with `key`, and jumps to `allocation + entry`.
    fn alloc_loader_pe(payload: &[u8], key: u8, entry: u32) -> Vec<u8> {
        let mut stub = vec![0x6A, 0x40, 0x68, 0x00, 0x30, 0x00, 0x00, 0x68, 0x00, 0x30, 0x00, 0x00, 0x6A, 0x00]; // VirtualAlloc(0, 0x3000, 0x3000, 0x40)
        stub.extend_from_slice(&[0xFF, 0x15, 0x50, 0x50, 0x40, 0x00]); // call [0x405050]
        stub.extend_from_slice(&[0x89, 0xC3, 0x89, 0xC7]); // mov ebx, eax / mov edi, eax
        stub.extend_from_slice(&[0xBE, 0x00, 0x20, 0x40, 0x00]); // mov esi, 0x402000
        stub.push(0xB9); // mov ecx, len
        stub.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        stub.extend_from_slice(&[0xAC, 0x34, key, 0xAA, 0xE2, 0xFA]); // lodsb / xor al, key / stosb / loop
        stub.extend_from_slice(&[0x81, 0xC3]); // add ebx, entry
        stub.extend_from_slice(&entry.to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xE3]); // jmp ebx
        let packed: Vec<u8> = payload.iter().map(|b| b ^ key).collect();

        let mut idata = vec![0u8; 0x80];
        let put = |d: &mut Vec<u8>, o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut idata, 0x00, 0x5040); // OriginalFirstThunk
        put(&mut idata, 0x0C, 0x5060); // Name
        put(&mut idata, 0x10, 0x5050); // FirstThunk
        put(&mut idata, 0x40, 0x5070); // ILT
        put(&mut idata, 0x50, 0x5070); // IAT
        idata[0x60..0x6C].copy_from_slice(b"kernel32.dll");
        idata[0x72..0x7E].copy_from_slice(b"VirtualAlloc");

        let sections: [(&str, u32, &[u8], u32); 3] =
            [(".text", 0x1000, &stub, 0x6000_0020), (".data", 0x2000, &packed, 0xC000_0040), (".idata", 0x5000, &idata, 0xC000_0040)];
        let mut d = vec![0u8; 0x200];
        d[..2].copy_from_slice(b"MZ");
        put(&mut d, 0x3C, 0x40);
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        let (coff, opt) = (0x44, 0x58);
        d[coff..coff + 2].copy_from_slice(&0x14Cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        d[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
        d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        put(&mut d, opt + 16, 0x1000);
        put(&mut d, opt + 28, 0x40_0000);
        put(&mut d, opt + 32, 0x1000);
        put(&mut d, opt + 36, 0x200);
        put(&mut d, opt + 56, 0x6000);
        put(&mut d, opt + 60, 0x200);
        d[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
        put(&mut d, opt + 92, 16);
        put(&mut d, opt + 96 + 8, 0x5000); // import directory
        put(&mut d, opt + 96 + 12, 40);
        for (i, (name, rva, data, chars)) in sections.iter().enumerate() {
            let t = opt + 0xE0 + i * 40;
            let raw_size = (data.len() as u32).div_ceil(0x200) * 0x200;
            let raw = d.len() as u32;
            d[t..t + name.len()].copy_from_slice(name.as_bytes());
            put(&mut d, t + 8, data.len() as u32);
            put(&mut d, t + 12, *rva);
            put(&mut d, t + 16, raw_size);
            put(&mut d, t + 20, raw);
            put(&mut d, t + 36, *chars);
            let mut s = data.to_vec();
            s.resize(raw_size as usize, 0);
            d.extend_from_slice(&s);
        }
        d
    }

    /// A PE as a loader maps it: headers in the first page, `mov eax, 42; ret` at
    /// RVA 0x1000 (its entry point), SizeOfImage 0x2000.
    fn mapped_image() -> Vec<u8> {
        let mut m = vec![0u8; 0x2000];
        m[..2].copy_from_slice(b"MZ");
        m[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        m[0x40..0x44].copy_from_slice(b"PE\0\0");
        m[0x44..0x46].copy_from_slice(&0x14Cu16.to_le_bytes());
        m[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        m[0x54..0x56].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt = 0x58;
        m[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        m[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        m[opt + 28..opt + 32].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        m[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        m[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        m[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        m[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        m[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        let t = opt + 0xE0;
        m[t..t + 5].copy_from_slice(b".text");
        m[t + 8..t + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        m[t + 12..t + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        m[t + 16..t + 20].copy_from_slice(&0x200u32.to_le_bytes());
        m[t + 20..t + 24].copy_from_slice(&0x200u32.to_le_bytes());
        m[t + 36..t + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        m[0x1000..0x1006].copy_from_slice(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        m
    }

    fn emulate(pe: &[u8]) -> UnpackerEngine {
        let sample = Sample::from_bytes(pe).unwrap();
        let ep = entrypoint(&sample.opt_header);
        let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
        eng.init_uc().unwrap();
        eng.set_controls(false, false);
        eng.set_end_addr(u64::MAX);
        let _ = eng.emu_from(ep, 5_000_000, 200_000);
        eng
    }

    #[test]
    fn code_decrypted_into_allocated_memory_is_a_write_execute() {
        let shellcode = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];
        let mut eng = emulate(&alloc_loader_pe(&shellcode, 0x5A, 0));
        let base = crate::unpacker::apicalls::ALLOC_BASE;
        assert_eq!(eng.wx_alloc_hit, Some(base));
        assert!(eng.wx_hit.is_some());
        let p = eng.alloc_payload().unwrap();
        assert_eq!((p.base, p.entry), (base, base));
        assert_eq!(&p.memory[..8], shellcode);
        assert!(p.pe.is_none());

        // An image-only packer (no allocation) has no allocated payload.
        assert_eq!(emulate(&xor_packed_pe()).wx_alloc_hit, None);
    }

    #[test]
    fn a_stub_still_unpacking_gets_more_budget() {
        // Too small a budget to finish the copy loop: written allocated memory, no
        // write-execute yet, so the run goes on and reaches the payload.
        let pe = alloc_loader_pe(&mapped_image(), 0, 0x1000);
        let sample = Sample::from_bytes(&pe).unwrap();
        let ep = entrypoint(&sample.opt_header);
        let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
        eng.init_uc().unwrap();
        eng.set_controls(false, false);
        eng.set_end_addr(u64::MAX);
        let _ = eng.emu_from(ep, 5_000_000, 2_000);
        assert!(eng.wx_hit.is_none() && eng.wrote_code());
        assert!(eng.continue_unpacking(5_000_000, 200_000));
        assert_eq!(eng.wx_alloc_hit, Some(crate::unpacker::apicalls::ALLOC_BASE + 0x1000));

        // A program that only computes (no code written) gets no extension.
        let mut plain = emulate(&xor_packed_pe());
        assert!(!plain.continue_unpacking(5_000_000, 200_000), "already unpacked: nothing to continue");
        assert!(plain.wx_hit.is_some());
    }

    #[test]
    fn a_pe_mapped_into_allocated_memory_is_dumped_as_a_pe() {
        let mut eng = emulate(&alloc_loader_pe(&mapped_image(), 0, 0x1000));
        let base = crate::unpacker::apicalls::ALLOC_BASE;
        assert_eq!(eng.wx_alloc_hit, Some(base + 0x1000));
        let pe = eng.alloc_payload().unwrap().pe.expect("the mapped PE");
        assert!(pe.starts_with(b"MZ"));
        assert_eq!(u32::from_le_bytes(pe[0x68..0x6C].try_into().unwrap()), 0x1000, "entry point = where it jumped");

        // The same through a recipe.
        let out = unpacked(&alloc_loader_pe(&mapped_image(), 0, 0x1000), "unpack:\n  - run_until: {write_execute: true, max_instructions: 200000}\n  - check: ip == 0x20001000\n  - dump_alloc\n");
        assert!(out[0].starts_with(b"MZ") && out[0].len() >= 0x400, "{} bytes", out[0].len());
    }

    #[test]
    fn emulation_steps_unpack_a_self_decrypting_stub() {
        let pe = xor_packed_pe();
        let recipe = r#"
unpack:
  - section: {name: .data, as: d}
  - run_until: {write_execute: true, outside: [.text]}
  - check: ip == image_base + d_rva
  - mem: {at: ip, len: 8, as: code}
  - emit: code
  - set_oep: ip
  - dump
"#;
        let out = unpacked(&pe, recipe);
        assert_eq!(out[0], [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90]);
        let dump = &out[1];
        assert!(dump.starts_with(b"MZ"));
        assert_eq!(u32::from_le_bytes(dump[0x68..0x6C].try_into().unwrap()), 0x2000, "dump entry point = the decrypted code");

        // The same stub never calls an API: a recipe waiting for one fails.
        let (outcome, _) = run(&pe, &steps("unpack:\n  - run_until: {api: [VirtualProtect], max_instructions: 200}\n  - dump\n"), BUDGET);
        assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
    }

    #[test]
    fn section_and_pe_values() {
        let pe = xor_packed_pe();
        let out = unpacked(
            &pe,
            r#"
unpack:
  - section: {name: .data, as: d}
  - check: d_rva == 0x2000 && d_vsize == 8 && d_off == rva2off(0x2000) && off2rva(d_off) == 0x2000
  - check: entry_rva == 0x1000 && image_base == 0x400000 && sections == 2 && overlay == file_size
  - take: {in: d, at: 0, len: d_vsize, as: packed}
  - xor: {in: packed, key: "5A"}
  - emit: packed
"#,
        );
        assert_eq!(out, vec![vec![0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90]]);
    }

    #[test]
    fn pe_values_need_a_pe() {
        let (outcome, _) = run(b"plain text", &steps("unpack:\n  - section: {name: .text, as: s}\n  - emit: s\n"), BUDGET);
        assert!(matches!(outcome, Outcome::Failed(e) if e.contains("not a PE")));
        let (outcome, _) = run(b"plain text", &steps("unpack:\n  - set: {o: rva2off(0x1000)}\n  - emit: file\n"), BUDGET);
        assert!(matches!(outcome, Outcome::Failed(e) if e.contains("not a PE")));
    }
}

fn name(s: &Step) -> &'static str {
    match s {
        Step::Find(_) => "find",
        Step::Read(_) => "read",
        Step::Take(_) => "take",
        Step::Set(_) => "set",
        Step::Check(_) => "check",
        Step::Section(_) => "section",
        Step::Resource(_) => "resource",
        Step::Decompress(_) => "decompress",
        Step::Xor(_) => "xor",
        Step::Add(_) => "add",
        Step::Sub(_) => "sub",
        Step::Rol(_) => "rol",
        Step::Ror(_) => "ror",
        Step::Rc4(_) => "rc4",
        Step::Base64(_) => "base64",
        Step::Reverse(_) => "reverse",
        Step::Join(_) => "join",
        Step::If(_) => "if",
        Step::Try(_) => "try",
        Step::Repeat(_) => "repeat",
        Step::Emit(_) => "emit",
        Step::RunUntil(_) => "run_until",
        Step::Mem(_) => "mem",
        Step::SetOep(_) => "set_oep",
        Step::Dump => "dump",
        Step::DumpAlloc => "dump_alloc",
    }
}
