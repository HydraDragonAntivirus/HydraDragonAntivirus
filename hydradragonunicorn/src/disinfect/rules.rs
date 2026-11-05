// disinfect/rules.rs — YAML disinfection definitions (format: DISINFECT_FORMAT.md).
//
// One definition per virus: how to RECOGNISE it (byte signatures, checked on
// emulated memory so encrypted / polymorphic droppers are seen after they
// decrypt), how to RECOVER the host (stored original entry point and bytes, or
// by following the virus back into the host and diffing what it restored),
// and how to CUT it out (truncate, drop its section, zero its body).

use serde::Deserialize;
use std::path::Path;
use std::sync::OnceLock;

/// Definitions shipped with the engine (compiled in).
const BUILTIN_YAML: &str = include_str!("../../disinfect_rules/default.yaml");

// ---------------------------------------------------------------------------
// YAML format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u32>,
    #[serde(default)]
    viruses: Vec<VirusRule>,
}

/// One virus definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirusRule {
    /// Threat name reported for the file (`W32.Sality.PE`).
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub arch: ArchFilter,
    #[serde(default)]
    pub locate: Locate,
    /// Basic blocks emulated before giving up (0 = engine default).
    #[serde(default)]
    pub max_blocks: u64,
    /// All parts must match, offsets relative to the virus start.
    pub signatures: Vec<SigPart>,
    /// Size of the virus body from its start. Default: to the end of its section.
    #[serde(default)]
    pub body_size: Option<u64>,
    pub recover: Recover,
    #[serde(default)]
    pub cleanup: Vec<Cleanup>,
    /// Recompute the PE checksum when the file had one (system files and drivers do).
    #[serde(default = "yes")]
    pub fix_checksum: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchFilter {
    #[default]
    Any,
    X86,
    X64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Locate {
    /// Signatures are checked at the start of every emulated basic block.
    #[default]
    Emulate,
    /// Signatures are checked only at the entry point (still on emulated memory).
    EntryPoint,
    /// Signatures are scanned across mapped executable sections before entry-point emulation (EPO / API-blocked infectors).
    SectionScan,
    /// Signatures are scanned in the last section's mapped memory before entry-point emulation (appender infectors).
    LastSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigPart {
    #[serde(default)]
    pub offset: u64,
    /// Hex bytes, `??` = any byte: `"E8 00 00 00 00 5D ?? C5"`.
    pub hex: String,
}

/// One argument passed to `Recover::CallFunction` (x86 stack; x64 RCX, RDX, R8, R9 + stack).
/// Give exactly one of `addr`, `value`, or `scratch`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallArg {
    /// Address computed from the virus body / image.
    #[serde(default)]
    pub addr: Option<AddrExpr>,
    /// Constant or integer read from the virus body.
    #[serde(default)]
    pub value: Option<ValueExpr>,
    /// Map a zeroed read-write scratch buffer of this byte size (`1..=1 MiB`) and pass its VA.
    #[serde(default)]
    pub scratch: Option<u64>,
}

/// How the host is recovered once the virus is recognised.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Recover {
    /// Detection only: the file is reported, never repaired.
    None,
    /// The virus keeps the original entry point (and stolen bytes) in its body.
    /// When `oep` is omitted (EPO infectors), the PE's existing entry point is kept.
    Stored {
        #[serde(default)]
        oep: Option<AddrExpr>,
        #[serde(default)]
        restore: Vec<RestoreBlock>,
    },
    /// Let the virus run until it jumps back into the host: that address is the
    /// original entry point, and whatever it wrote into the host's executable
    /// sections on the way is the restored original code.
    EmulateToHost {
        #[serde(default = "default_max_restore")]
        max_restore_bytes: u64,
    },
    /// Call a specific decryptor / host-restore function inside the virus with Unicorn
    /// (`UnpackerEngine::call_function`) until it returns, then read the decrypted OEP /
    /// restore blocks (from the virus body or a `scratch` argument) and/or diff what the
    /// function wrote back into the host's executable sections.
    CallFunction {
        func: AddrExpr,
        #[serde(default)]
        args: Vec<CallArg>,
        #[serde(default = "default_call_insns")]
        max_instructions: u64,
        #[serde(default = "default_call_timeout_ms")]
        timeout_ms: u64,
        /// Optional OEP (evaluated after `func` returns; omitted = keep existing PE entry point).
        #[serde(default)]
        oep: Option<AddrExpr>,
        #[serde(default)]
        restore: Vec<RestoreBlock>,
        /// Also capture bytes `func` wrote into the host's executable sections (outside the virus body).
        #[serde(default)]
        diff_host: bool,
        #[serde(default = "default_max_restore")]
        max_restore_bytes: u64,
    },
}

fn default_max_restore() -> u64 {
    0x4000
}
fn default_call_insns() -> u64 {
    500_000
}
fn default_call_timeout_ms() -> u64 {
    2_000
}

/// An address computed from the virus body. `value` is read at
/// `virus_start + offset` (`size` bytes, little endian) and XORed with `xor`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddrExpr {
    pub mode: AddrMode,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "four")]
    pub size: u8,
    #[serde(default)]
    pub add: i64,
    #[serde(default)]
    pub xor: u64,
}

fn four() -> u8 {
    4
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrMode {
    /// `virus_start + add` (nothing is read).
    VirusOffset,
    /// `value + add` (a VA).
    Absolute,
    /// `image_base + value + add`.
    Rva,
    /// `virus_start + add + value` (value sign-extended).
    Relative,
    /// `virus_start + add - value`.
    RelativeBack,
    /// `call_ret + add` (`call_function` only: return value in EAX / RAX as VA).
    ReturnVa,
    /// `image_base + call_ret + add` (`call_function` only: return value in EAX / RAX as RVA).
    ReturnRva,
}

/// A number: either `value`, or read at `virus_start + offset`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueExpr {
    #[serde(default)]
    pub value: Option<u64>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default = "four")]
    pub size: u8,
    #[serde(default)]
    pub xor: u64,
}

/// Original bytes the virus keeps in its body (or decrypted into a `scratch` buffer).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBlock {
    /// Where they go back. Default: the recovered original entry point.
    #[serde(default)]
    pub to: Option<AddrExpr>,
    /// Where they are, relative to the virus start (or to the `scratch` buffer when `scratch_index` is set).
    #[serde(default)]
    pub data_offset: u64,
    /// Read from the `args[scratch_index]` scratch buffer instead of `virus_start` (`call_function` only).
    #[serde(default)]
    pub scratch_index: Option<usize>,
    pub size: ValueExpr,
    /// Byte at `virus_start + offset`; zero = nothing stored (patient zero).
    #[serde(default)]
    pub present_flag: Option<ValueExpr>,
    /// A size below this means nothing was stored (patient zero).
    #[serde(default = "one")]
    pub min_size: u64,
    #[serde(default = "default_max_block")]
    pub max_size: u64,
    /// Repeating XOR key over the stored bytes, hex.
    #[serde(default)]
    pub xor_key: Option<String>,
}

fn one() -> u64 {
    1
}
fn default_max_block() -> u64 {
    0x1000
}

/// What is cut out of the file after the host is restored (in order).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Cleanup {
    /// Cut the file at the file offset of this address; section headers are fixed,
    /// sections wholly after the cut are removed.
    TruncateAt { at: AddrExpr },
    /// The section holding the virus start is removed (must be the last one).
    RemoveVirusSection,
    /// The virus body (`body_size`, else to the end of its section) is zeroed.
    ZeroBody,
}

// ---------------------------------------------------------------------------
// Compiled rules
// ---------------------------------------------------------------------------

/// One pattern byte: matches a byte `b` when `b & mask == value`. `??` has mask 0,
/// `4?` mask 0xF0 (high nibble 4), `?A` mask 0x0F, a plain byte mask 0xFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexByte {
    pub value: u8,
    pub mask: u8,
}

impl HexByte {
    pub const ANY: Self = Self { value: 0, mask: 0 };

    pub const fn exact(b: u8) -> Self {
        Self { value: b, mask: 0xFF }
    }

    pub fn matches(self, b: u8) -> bool {
        b & self.mask == self.value
    }

    /// The byte, when no part of it is a wildcard.
    pub fn fixed(self) -> Option<u8> {
        (self.mask == 0xFF).then_some(self.value)
    }
}

/// A signature part with its bytes parsed.
#[derive(Debug, Clone)]
pub struct CompiledSig {
    pub offset: u64,
    pub bytes: Vec<HexByte>,
}

/// A validated definition.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: VirusRule,
    pub sigs: Vec<CompiledSig>,
    /// Bytes to read at a candidate start to check every signature part.
    pub sig_span: usize,
    /// First fixed `(offset, byte)` across `sigs`, used to jump quickly during section scans.
    pub anchor: (usize, u8),
    pub xor_keys: Vec<Option<Vec<u8>>>,
}

impl CompiledRule {
    /// All signature parts match `buf` (read at the candidate virus start).
    pub fn matches(&self, buf: &[u8]) -> bool {
        self.sigs.iter().all(|s| {
            let o = s.offset as usize;
            buf.len() >= o + s.bytes.len()
                && s.bytes.iter().zip(&buf[o..]).all(|(p, b)| p.matches(*b))
        })
    }

    /// First offset in `buf` where every signature part matches.
    pub fn scan_slice(&self, buf: &[u8]) -> Option<usize> {
        if buf.len() < self.sig_span {
            return None;
        }
        let limit = buf.len() - self.sig_span;
        let (anchor_off, anchor_byte) = self.anchor;
        let mut pos = 0usize;
        while pos <= limit {
            let rel = buf[pos + anchor_off..=limit + anchor_off]
                .iter()
                .position(|&b| b == anchor_byte)?;
            pos += rel;
            if self.matches(&buf[pos..]) {
                return Some(pos);
            }
            pos += 1;
        }
        None
    }
}

/// A set of virus definitions.
#[derive(Debug, Clone, Default)]
pub struct DisinfectRules {
    pub rules: Vec<CompiledRule>,
}

impl DisinfectRules {
    /// The definitions compiled into the engine (`disinfect_rules/default.yaml`).
    pub fn builtin() -> &'static DisinfectRules {
        static RULES: OnceLock<DisinfectRules> = OnceLock::new();
        RULES.get_or_init(|| {
            DisinfectRules::from_yaml_str(BUILTIN_YAML)
                .unwrap_or_else(|e| panic!("built-in disinfect_rules/default.yaml is invalid: {e}"))
        })
    }

    /// Parse and validate a YAML definition file.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, String> {
        let file: RuleFile = yaml_serde::from_str(yaml).map_err(|e| format!("invalid YAML: {e}"))?;
        let mut rules = Vec::with_capacity(file.viruses.len());
        for r in file.viruses {
            rules.push(compile(r)?);
        }
        Ok(Self { rules })
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The built-in definitions plus the ones in `path` (same name: the file wins).
    pub fn builtin_with_file(path: &Path) -> Result<Self, String> {
        let mut out = Self::builtin().clone();
        out.extend(Self::from_file(path)?);
        Ok(out)
    }

    /// Add definitions; one with an existing name replaces it.
    pub fn extend(&mut self, other: DisinfectRules) {
        for r in other.rules {
            self.rules.retain(|x| !x.rule.name.eq_ignore_ascii_case(&r.rule.name));
            self.rules.push(r);
        }
    }

    /// Only the definition(s) with this name.
    pub fn only(&self, name: &str) -> DisinfectRules {
        DisinfectRules {
            rules: self.rules.iter().filter(|r| r.rule.name.eq_ignore_ascii_case(name)).cloned().collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// `"E8 00 ?? 5D"` (spaces optional, `?`/`??` = wildcard).
/// Hex bytes with wildcards: `??` any byte, `4?` / `?A` a nibble wildcard.
pub fn parse_hex_pattern(s: &str) -> Result<Vec<HexByte>, String> {
    let compact: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() % 2 != 0 {
        return Err(format!("odd number of hex digits in {s:?}"));
    }
    let nibble = |c: char| -> Option<(u8, u8)> {
        if c == '?' { Some((0, 0)) } else { c.to_digit(16).map(|d| (d as u8, 0xF)) }
    };
    compact
        .chunks(2)
        .map(|p| match (nibble(p[0]), nibble(p[1])) {
            (Some((hv, hm)), Some((lv, lm))) => Ok(HexByte { value: hv << 4 | lv, mask: hm << 4 | lm }),
            _ => Err(format!("bad hex byte {}{} in {s:?}", p[0], p[1])),
        })
        .collect()
}

fn check_size(what: &str, size: u8) -> Result<(), String> {
    match size {
        1 | 2 | 4 | 8 => Ok(()),
        _ => Err(format!("{what}: size must be 1, 2, 4 or 8 (got {size})")),
    }
}

fn check_value(what: &str, v: &ValueExpr) -> Result<(), String> {
    check_size(what, v.size)?;
    match (v.value, v.offset) {
        (Some(_), None) | (None, Some(_)) => Ok(()),
        _ => Err(format!("{what}: give exactly one of `value` or `offset`")),
    }
}

fn check_addr(what: &str, a: &AddrExpr, allow_return: bool) -> Result<(), String> {
    check_size(what, a.size)?;
    if !allow_return && matches!(a.mode, AddrMode::ReturnVa | AddrMode::ReturnRva) {
        return Err(format!("{what}: `return_va` / `return_rva` is only valid after `call_function`"));
    }
    Ok(())
}

fn compile_restore_blocks(
    restore: &[RestoreBlock],
    allow_return: bool,
    call_args: Option<&[CallArg]>,
    err: &impl Fn(String) -> String,
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut xor_keys = Vec::with_capacity(restore.len());
    for (i, r) in restore.iter().enumerate() {
        check_value(&format!("restore[{i}].size"), &r.size).map_err(err)?;
        if let Some(f) = &r.present_flag {
            check_value(&format!("restore[{i}].present_flag"), f).map_err(err)?;
        }
        if let Some(t) = &r.to {
            check_addr(&format!("restore[{i}].to"), t, allow_return).map_err(err)?;
        }
        if let Some(idx) = r.scratch_index {
            let Some(args) = call_args else {
                return Err(err(format!("restore[{i}].scratch_index is only valid in `call_function`")));
            };
            let Some(cap) = args.get(idx).and_then(|a| a.scratch) else {
                return Err(err(format!("restore[{i}].scratch_index={idx} does not refer to a `scratch` argument")));
            };
            if r.data_offset >= cap {
                return Err(err(format!("restore[{i}].data_offset 0x{:x} is outside scratch[{idx}] ({cap} bytes)", r.data_offset)));
            }
        }
        if r.max_size == 0 || r.max_size > 0x10_0000 {
            return Err(err(format!("restore[{i}].max_size must be 1..=1 MiB")));
        }
        let key = match &r.xor_key {
            Some(k) => {
                let k: Option<Vec<u8>> = parse_hex_pattern(k).map_err(err)?.into_iter().map(HexByte::fixed).collect();
                match k {
                    Some(k) if !k.is_empty() => Some(k),
                    _ => return Err(err(format!("restore[{i}].xor_key must be plain hex bytes"))),
                }
            }
            None => None,
        };
        xor_keys.push(key);
    }
    Ok(xor_keys)
}

fn compile(rule: VirusRule) -> Result<CompiledRule, String> {
    let name = rule.name.trim();
    if name.is_empty() {
        return Err("a definition has no name".into());
    }
    let err = |m: String| format!("{name}: {m}");
    if rule.signatures.is_empty() {
        return Err(err("no signatures: a virus is only disinfected when it is recognised".into()));
    }
    let mut sigs = Vec::new();
    let mut span = 0usize;
    let mut concrete = 0usize;
    let mut anchor: Option<(usize, u8)> = None;
    for s in &rule.signatures {
        let bytes = parse_hex_pattern(&s.hex).map_err(&err)?;
        if bytes.is_empty() {
            return Err(err("empty signature".into()));
        }
        if anchor.is_none() {
            anchor = bytes
                .iter()
                .enumerate()
                .find_map(|(i, b)| b.fixed().map(|v| (s.offset as usize + i, v)));
        }
        concrete += bytes.iter().filter(|b| b.fixed().is_some()).count();
        span = span.max(s.offset as usize + bytes.len());
        sigs.push(CompiledSig { offset: s.offset, bytes });
    }
    // A short signature would "recognise" ordinary code and cut a clean program.
    if concrete < 16 {
        return Err(err(format!("signatures have {concrete} fixed bytes, at least 16 are required")));
    }
    if span > 0x10000 {
        return Err(err("signature span over 64 KiB".into()));
    }
    let anchor = anchor.expect("concrete >= 16 implies at least one fixed byte");
    let is_call_fn = matches!(rule.recover, Recover::CallFunction { .. });
    let mut xor_keys = Vec::new();
    match &rule.recover {
        Recover::None => {}
        Recover::Stored { oep, restore } => {
            if oep.is_none() && restore.is_empty() {
                return Err(err("recover.stored needs `oep` or at least one `restore` block".into()));
            }
            if let Some(o) = oep {
                check_addr("recover.oep", o, false).map_err(&err)?;
            }
            xor_keys = compile_restore_blocks(restore, false, None, &err)?;
        }
        Recover::EmulateToHost { max_restore_bytes } => {
            if *max_restore_bytes > 0x10_0000 {
                return Err(err("max_restore_bytes over 1 MiB".into()));
            }
        }
        Recover::CallFunction {
            func,
            args,
            max_instructions,
            timeout_ms,
            oep,
            restore,
            diff_host,
            max_restore_bytes,
        } => {
            check_addr("recover.func", func, false).map_err(&err)?;
            if args.len() > 8 {
                return Err(err("call_function supports at most 8 arguments".into()));
            }
            for (i, a) in args.iter().enumerate() {
                let kinds = usize::from(a.addr.is_some()) + usize::from(a.value.is_some()) + usize::from(a.scratch.is_some());
                if kinds != 1 {
                    return Err(err(format!("args[{i}]: give exactly one of `addr`, `value` or `scratch`")));
                }
                if let Some(ad) = &a.addr {
                    check_addr(&format!("args[{i}].addr"), ad, false).map_err(&err)?;
                }
                if let Some(val) = &a.value {
                    check_value(&format!("args[{i}].value"), val).map_err(&err)?;
                }
                if let Some(sz) = a.scratch {
                    if sz == 0 || sz > 0x10_0000 {
                        return Err(err(format!("args[{i}].scratch must be 1..=1 MiB")));
                    }
                }
            }
            if *max_instructions == 0 || *max_instructions > 50_000_000 {
                return Err(err("max_instructions must be 1..=50_000_000".into()));
            }
            if *timeout_ms == 0 || *timeout_ms > 30_000 {
                return Err(err("timeout_ms must be 1..=30_000".into()));
            }
            if *diff_host && *max_restore_bytes > 0x10_0000 {
                return Err(err("max_restore_bytes over 1 MiB".into()));
            }
            if oep.is_none() && restore.is_empty() && !*diff_host {
                return Err(err("call_function needs `oep`, `restore`, or `diff_host: true`".into()));
            }
            if let Some(o) = oep {
                check_addr("recover.oep", o, true).map_err(&err)?;
            }
            xor_keys = compile_restore_blocks(restore, true, Some(args), &err)?;
        }
    }
    if !matches!(rule.recover, Recover::None) && rule.cleanup.is_empty() {
        return Err(err("a repair needs at least one cleanup action to remove the virus".into()));
    }
    for c in &rule.cleanup {
        if let Cleanup::TruncateAt { at } = c {
            check_addr("cleanup.truncate_at", at, is_call_fn).map_err(&err)?;
        }
    }
    Ok(CompiledRule { rule, sigs, sig_span: span, anchor, xor_keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_load() {
        let r = DisinfectRules::builtin();
        assert!(r.rules.iter().any(|r| r.rule.name == "W32.Sality.PE"));
    }

    #[test]
    fn hex_pattern() {
        assert_eq!(parse_hex_pattern("E8 ?? 5d").unwrap(), vec![HexByte::exact(0xE8), HexByte::ANY, HexByte::exact(0x5D)]);
        let n = parse_hex_pattern("7? ?d").unwrap();
        assert_eq!(n, vec![HexByte { value: 0x70, mask: 0xF0 }, HexByte { value: 0x0D, mask: 0x0F }]);
        assert!(n[0].matches(0x7D) && !n[0].matches(0x8D) && n[1].matches(0xFD) && !n[1].matches(0xFE));
        assert!(parse_hex_pattern("E8 0").is_err());
        assert!(parse_hex_pattern("ZZ").is_err());
    }

    #[test]
    fn short_signature_is_refused() {
        let y = r#"
viruses:
  - name: Too.Short
    signatures: [{hex: "E8 00 00 00 00"}]
    recover: {method: none}
"#;
        assert!(DisinfectRules::from_yaml_str(y).unwrap_err().contains("at least 16"));
    }

    #[test]
    fn repair_without_cleanup_is_refused() {
        let y = r#"
viruses:
  - name: No.Cleanup
    signatures: [{hex: "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"}]
    recover: {method: emulate_to_host}
"#;
        assert!(DisinfectRules::from_yaml_str(y).unwrap_err().contains("cleanup"));
    }

    #[test]
    fn call_function_validation_catches_invalid_modes_and_args() {
        let bad_return = r#"
viruses:
  - name: Bad.ReturnMode
    signatures: [{hex: "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"}]
    recover:
      method: stored
      oep: {mode: return_va}
    cleanup: [{action: remove_virus_section}]
"#;
        assert!(DisinfectRules::from_yaml_str(bad_return).unwrap_err().contains("call_function"));

        let bad_scratch = r#"
viruses:
  - name: Bad.ScratchIdx
    signatures: [{hex: "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"}]
    recover:
      method: call_function
      func: {mode: virus_offset, add: 0x10}
      args: [{value: {value: 4}}]
      restore:
        - {scratch_index: 0, size: {value: 4}}
    cleanup: [{action: remove_virus_section}]
"#;
        assert!(DisinfectRules::from_yaml_str(bad_scratch).unwrap_err().contains("scratch"));

        let empty_call = r#"
viruses:
  - name: Bad.EmptyCall
    signatures: [{hex: "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"}]
    recover:
      method: call_function
      func: {mode: virus_offset, add: 0x10}
    cleanup: [{action: remove_virus_section}]
"#;
        assert!(DisinfectRules::from_yaml_str(empty_call).unwrap_err().contains("diff_host"));
    }
}
