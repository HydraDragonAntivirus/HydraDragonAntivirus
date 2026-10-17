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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigPart {
    #[serde(default)]
    pub offset: u64,
    /// Hex bytes, `??` = any byte: `"E8 00 00 00 00 5D ?? C5"`.
    pub hex: String,
}

/// How the host is recovered once the virus is recognised.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Recover {
    /// Detection only: the file is reported, never repaired.
    None,
    /// The virus keeps the original entry point (and stolen bytes) in its body.
    Stored {
        oep: AddrExpr,
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
}

fn default_max_restore() -> u64 {
    0x4000
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

/// Original bytes the virus keeps in its body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBlock {
    /// Where they go back. Default: the recovered original entry point.
    #[serde(default)]
    pub to: Option<AddrExpr>,
    /// Where they are, relative to the virus start.
    pub data_offset: u64,
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

/// A signature part with its bytes parsed (`None` = wildcard).
#[derive(Debug, Clone)]
pub struct CompiledSig {
    pub offset: u64,
    pub bytes: Vec<Option<u8>>,
}

/// A validated definition.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: VirusRule,
    pub sigs: Vec<CompiledSig>,
    /// Bytes to read at a candidate start to check every signature part.
    pub sig_span: usize,
    pub xor_keys: Vec<Option<Vec<u8>>>,
}

impl CompiledRule {
    /// All signature parts match `buf` (read at the candidate virus start).
    pub fn matches(&self, buf: &[u8]) -> bool {
        self.sigs.iter().all(|s| {
            let o = s.offset as usize;
            buf.len() >= o + s.bytes.len()
                && s.bytes.iter().zip(&buf[o..]).all(|(p, b)| p.is_none_or(|p| p == *b))
        })
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
pub fn parse_hex_pattern(s: &str) -> Result<Vec<Option<u8>>, String> {
    let compact: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() % 2 != 0 {
        return Err(format!("odd number of hex digits in {s:?}"));
    }
    compact
        .chunks(2)
        .map(|p| match p {
            ['?', '?'] => Ok(None),
            [a, b] => u8::from_str_radix(&format!("{a}{b}"), 16)
                .map(Some)
                .map_err(|_| format!("bad hex byte {a}{b} in {s:?}")),
            _ => unreachable!(),
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
    for s in &rule.signatures {
        let bytes = parse_hex_pattern(&s.hex).map_err(&err)?;
        if bytes.is_empty() {
            return Err(err("empty signature".into()));
        }
        concrete += bytes.iter().filter(|b| b.is_some()).count();
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
    let mut xor_keys = Vec::new();
    match &rule.recover {
        Recover::None => {}
        Recover::Stored { oep, restore } => {
            check_size("recover.oep", oep.size).map_err(&err)?;
            for (i, r) in restore.iter().enumerate() {
                check_value(&format!("restore[{i}].size"), &r.size).map_err(&err)?;
                if let Some(f) = &r.present_flag {
                    check_value(&format!("restore[{i}].present_flag"), f).map_err(&err)?;
                }
                if let Some(t) = &r.to {
                    check_size(&format!("restore[{i}].to"), t.size).map_err(&err)?;
                }
                if r.max_size == 0 || r.max_size > 0x10_0000 {
                    return Err(err(format!("restore[{i}].max_size must be 1..=1 MiB")));
                }
                let key = match &r.xor_key {
                    Some(k) => {
                        let k: Option<Vec<u8>> = parse_hex_pattern(k).map_err(&err)?.into_iter().collect();
                        match k {
                            Some(k) if !k.is_empty() => Some(k),
                            _ => return Err(err(format!("restore[{i}].xor_key must be plain hex bytes"))),
                        }
                    }
                    None => None,
                };
                xor_keys.push(key);
            }
        }
        Recover::EmulateToHost { max_restore_bytes } => {
            if *max_restore_bytes > 0x10_0000 {
                return Err(err("max_restore_bytes over 1 MiB".into()));
            }
        }
    }
    if !matches!(rule.recover, Recover::None) && rule.cleanup.is_empty() {
        return Err(err("a repair needs at least one cleanup action to remove the virus".into()));
    }
    for c in &rule.cleanup {
        if let Cleanup::TruncateAt { at } = c {
            check_size("cleanup.truncate_at", at.size).map_err(&err)?;
        }
    }
    Ok(CompiledRule { rule, sigs, sig_span: span, xor_keys })
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
        assert_eq!(parse_hex_pattern("E8 ?? 5d").unwrap(), vec![Some(0xE8), None, Some(0x5D)]);
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
}
