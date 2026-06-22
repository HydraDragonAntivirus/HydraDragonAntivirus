use crate::database::{OffsetAnchor, OffsetSpec, SourceLocation};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};
use regex::bytes::{Regex, RegexBuilder};
use std::sync::{Arc, OnceLock};

/// A PCRE subsignature regex compiled **lazily**, on first trigger.
///
/// The Rust `regex` crate compiles each pattern into a 30–50 KB NFA/DFA at build
/// time. ClamAV instead compiles every PCRE to pcre2 bytecode (~4 KB each) at
/// load, costing ~170 MB for a full DB; the `regex` crate would cost ~700 MB the
/// same way — the single biggest memory consumer. But a PCRE subsignature only
/// runs when its trigger (a body subsignature) matches, which is rare. So we keep
/// only the (small) source text resident and compile on first use — the vast
/// majority are never compiled, so resident PCRE memory drops to a few MB and DB
/// load no longer pays to compile tens of thousands of regexes.
///
/// `source` already has any inline flags baked in (`(?ims…)`), so a plain
/// `Regex::new` reproduces the original `RegexBuilder` configuration. A compile
/// failure (e.g. the default 10 MB size limit, or an unsupported construct) is
/// cached as `None` and treated as "never matches" — identical in effect to the
/// old behaviour of dropping such a signature as unsupported.
#[derive(Clone, Debug)]
pub struct LazyRegex {
    source: Arc<str>,
    compiled: Arc<OnceLock<Option<Regex>>>,
}

impl LazyRegex {
    fn new(source: String) -> Self {
        LazyRegex {
            source: Arc::from(source),
            compiled: Arc::new(OnceLock::new()),
        }
    }

    /// The compiled regex, compiling it on first call. `None` if it can't compile.
    pub fn get(&self) -> Option<&Regex> {
        self.compiled
            .get_or_init(|| RegexBuilder::new(&self.source).build().ok())
            .as_ref()
    }

    pub fn is_match(&self, data: &[u8]) -> bool {
        self.get().map_or(false, |re| re.is_match(data))
    }
}

#[derive(Clone, Debug)]
pub struct LogicalSignature {
    pub name: String,
    pub target: Option<u32>,
    /// `FileSize:min-max` TDB constraint, if present. The scanned object's length
    /// must fall in `[min, max]` for the signature to fire.
    pub file_size: Option<(u64, u64)>,
    /// `Container:CL_TYPE_X` TDB constraint — the signature only fires when the
    /// scanned object's IMMEDIATE parent container is of this type (ClamAV's
    /// `recursion_stack_get_type(-2)`). `CL_TYPE_ANY` means "any container".
    pub container: Option<String>,
    /// `NumberOfSections:min-max` TDB constraint — the PE's section count must be
    /// in `[min, max]`.
    pub nos: Option<(u32, u32)>,
    /// True when the TDB attribute block carries a constraint we cannot yet
    /// evaluate (IconGroup1/2, HandlerType, Intermediates, …). Such a signature
    /// gates its match on context we don't have, so matching its body alone would
    /// FALSE-POSITIVE on every file that satisfies the body — we skip it, exactly
    /// as ClamAV only applies it when the gate holds.
    pub tdb_unsupported: bool,
    pub expression: LogicalExpr,
    pub subsignatures: Vec<Subsignature>,
    pub source: SourceLocation,
}

#[derive(Clone, Debug)]
pub enum Subsignature {
    Body {
        offset: OffsetSpec,
        patterns: Vec<Pattern>,
    },
    /// `Trigger/PCRE/Flags` — the regex runs only when `trigger` evaluates true.
    /// The regex is compiled lazily on first trigger (see [`LazyRegex`]).
    Pcre {
        trigger: LogicalExpr,
        regex: LazyRegex,
        global: bool,
    },
    /// `subsigid_trigger(offset#byte_options#comparisons)` — reads bytes relative
    /// to the trigger subsignature's match and compares them numerically.
    ByteCompare {
        spec: ByteCompareSpec,
    },
    Unsupported {
        reason: String,
    },
}

/// How the bytes read by a byte-compare subsignature are interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteReadType {
    /// ASCII hexadecimal digits.
    HexAscii,
    /// ASCII decimal digits.
    DecimalAscii,
    /// ASCII with automatic base detection (`0x` hex, leading `0` octal, else decimal).
    Auto,
    /// Raw little-endian binary integer.
    BinaryLe,
    /// Raw big-endian binary integer.
    BinaryBe,
}

#[derive(Clone, Debug)]
pub struct ByteCompareSpec {
    pub trigger_subsig: usize,
    /// `+1` for `>>` (forward), `-1` for `<<` (backward).
    pub offset_sign: i64,
    pub offset_value: usize,
    pub read_type: ByteReadType,
    pub exact: bool,
    pub num_bytes: usize,
    /// One or two `(op, value)` comparisons; all must hold.
    pub comparisons: Vec<(CompareOp, u64)>,
}

/// Transient recursive form built by the parser, then flattened into the
/// compact `LogicalExpr` (index arena). Not stored.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ExprTree {
    Subsig(usize),
    And(Box<ExprTree>, Box<ExprTree>),
    Or(Box<ExprTree>, Box<ExprTree>),
    Compare {
        expr: Box<ExprTree>,
        op: CompareOp,
        hits: usize,
        distinct: Option<usize>,
    },
}

/// A logical expression stored as a flat post-order array of nodes that
/// reference children by index — no per-node `Box`, so 2.6M nodes cost one
/// allocation per signature instead of millions. The root is the last node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalExpr {
    nodes: Box<[ExprNode]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExprNode {
    Subsig(u32),
    And(u32, u32),
    Or(u32, u32),
    Compare {
        expr: u32,
        op: CompareOp,
        hits: u32,
        distinct: Option<u32>,
    },
}

impl LogicalExpr {
    fn from_tree(tree: &ExprTree) -> Self {
        let mut nodes = Vec::new();
        flatten_tree(tree, &mut nodes);
        LogicalExpr {
            nodes: nodes.into_boxed_slice(),
        }
    }
}

/// Append `tree` to `nodes` in post-order (children before parents) and return
/// the index of its root node.
fn flatten_tree(tree: &ExprTree, nodes: &mut Vec<ExprNode>) -> u32 {
    let node = match tree {
        ExprTree::Subsig(i) => ExprNode::Subsig(*i as u32),
        ExprTree::And(a, b) => {
            let ai = flatten_tree(a, nodes);
            let bi = flatten_tree(b, nodes);
            ExprNode::And(ai, bi)
        }
        ExprTree::Or(a, b) => {
            let ai = flatten_tree(a, nodes);
            let bi = flatten_tree(b, nodes);
            ExprNode::Or(ai, bi)
        }
        ExprTree::Compare {
            expr,
            op,
            hits,
            distinct,
        } => {
            let ei = flatten_tree(expr, nodes);
            ExprNode::Compare {
                expr: ei,
                op: *op,
                hits: *hits as u32,
                distinct: distinct.map(|d| d as u32),
            }
        }
    };
    let idx = nodes.len() as u32;
    nodes.push(node);
    idx
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompareOp {
    Equal,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalStats {
    pub matched: bool,
    pub hits: usize,
    pub distinct: usize,
}

pub fn parse_logical_signature(
    line: &str,
    source: SourceLocation,
) -> Result<(LogicalSignature, Vec<String>), String> {
    let parts = line.split(';').collect::<Vec<_>>();
    if parts.len() < 4 {
        return Err("logical signature needs name;target-block;expression;subsigs".to_string());
    }

    let expression = LogicalExpr::from_tree(&ExprParser::new(parts[2]).parse()?);
    let target = parse_target(parts[1]);
    let tdb = parse_tdb(parts[1]);
    let (file_size, container, nos, tdb_unsupported) =
        (tdb.file_size, tdb.container, tdb.nos, tdb.unsupported);
    let mut warnings = Vec::new();
    if tdb_unsupported {
        warnings.push(format!(
            "logical signature '{}' has a TDB constraint that can't be evaluated; skipped to avoid false positives",
            parts[0]
        ));
    }
    let mut subsignatures = Vec::new();
    for raw in parts.iter().skip(3) {
        if raw.trim().is_empty() {
            continue;
        }
        let (subsignature, warning) = parse_subsignature(raw);
        if let Some(warning) = warning {
            warnings.push(warning);
        }
        subsignatures.push(subsignature);
    }

    Ok((
        LogicalSignature {
            name: parts[0].to_string(),
            target,
            file_size,
            container,
            nos,
            tdb_unsupported,
            expression,
            subsignatures,
            source,
        },
        warnings,
    ))
}

/// Parsed TDB attribute constraints (ClamAV's target description block).
#[derive(Default)]
struct Tdb {
    file_size: Option<(u64, u64)>,
    container: Option<String>,
    nos: Option<(u32, u32)>,
    unsupported: bool,
}

/// Parse the TDB attribute block (`Engine:51-255,Target:1,Container:CL_TYPE_ZIP,
/// FileSize:1-2000,NumberOfSections:2-4,…`). We evaluate the constraints we have
/// the context for — `FileSize` (object length), `Container` (immediate parent
/// container type), `NumberOfSections` (PE section count) — and treat `Target`
/// (handled separately) and `Engine` (a ClamAV functionality-level gate, not a
/// file-content gate) as always-applicable. Anything else (`IconGroup1/2`,
/// `HandlerType`, `Intermediates`, `EntryPoint`, …) gates the match on context we
/// don't have yet, so the signature is marked unsupported and skipped rather than
/// matched on its body alone (which false-positives).
fn parse_tdb(block: &str) -> Tdb {
    let mut tdb = Tdb::default();
    for item in block.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (key, val) = item.split_once(':').unwrap_or((item, ""));
        match key {
            "Target" | "Engine" => {}
            "FileSize" => match parse_num_range(val) {
                Some(range) => tdb.file_size = Some(range),
                None => tdb.unsupported = true,
            },
            "Container" if !val.is_empty() => tdb.container = Some(val.to_string()),
            "NumberOfSections" => match parse_num_range(val) {
                Some((lo, hi)) => tdb.nos = Some((lo as u32, hi as u32)),
                None => tdb.unsupported = true,
            },
            _ => tdb.unsupported = true,
        }
    }
    tdb
}

/// Parse a ClamAV numeric range field: `n`, `n-m`, `-m`, or `n-`.
fn parse_num_range(raw: &str) -> Option<(u64, u64)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some((lo, hi)) = raw.split_once('-') {
        let lo = if lo.is_empty() { 0 } else { lo.parse().ok()? };
        let hi = if hi.is_empty() { u64::MAX } else { hi.parse().ok()? };
        if hi < lo {
            return None;
        }
        Some((lo, hi))
    } else {
        let n = raw.parse().ok()?;
        Some((n, n))
    }
}

impl LogicalExpr {
    pub fn eval(&self, counts: &[usize]) -> EvalStats {
        if self.nodes.is_empty() {
            return EvalStats::default();
        }
        self.eval_at(self.nodes.len() - 1, counts)
    }

    fn eval_at(&self, idx: usize, counts: &[usize]) -> EvalStats {
        match self.nodes[idx] {
            ExprNode::Subsig(index) => {
                let hits = counts.get(index as usize).copied().unwrap_or(0);
                EvalStats {
                    matched: hits > 0,
                    hits,
                    distinct: usize::from(hits > 0),
                }
            }
            ExprNode::And(a, b) => {
                let left = self.eval_at(a as usize, counts);
                let right = self.eval_at(b as usize, counts);
                EvalStats {
                    matched: left.matched && right.matched,
                    hits: left.hits + right.hits,
                    distinct: left.distinct + right.distinct,
                }
            }
            ExprNode::Or(a, b) => {
                let left = self.eval_at(a as usize, counts);
                let right = self.eval_at(b as usize, counts);
                EvalStats {
                    matched: left.matched || right.matched,
                    hits: left.hits + right.hits,
                    distinct: left.distinct + right.distinct,
                }
            }
            ExprNode::Compare {
                expr,
                op,
                hits,
                distinct,
            } => {
                let stats = self.eval_at(expr as usize, counts);
                let hits = hits as usize;
                let hits_match = match op {
                    CompareOp::Equal => stats.hits == hits,
                    CompareOp::Greater => stats.hits > hits,
                    CompareOp::GreaterEqual => stats.hits >= hits,
                    CompareOp::Less => stats.hits < hits,
                    CompareOp::LessEqual => stats.hits <= hits,
                };
                let distinct_match = distinct.map_or(true, |min| stats.distinct >= min as usize);
                EvalStats {
                    matched: hits_match && distinct_match,
                    hits: stats.hits,
                    distinct: stats.distinct,
                }
            }
        }
    }
}

fn parse_target(block: &str) -> Option<u32> {
    block.split(',').find_map(|item| {
        item.strip_prefix("Target:")
            .and_then(|raw| raw.parse::<u32>().ok())
    })
}

fn parse_subsignature(raw: &str) -> (Subsignature, Option<String>) {
    if raw.starts_with("fuzzy_img#") {
        return unsupported(
            raw,
            "image fuzzy hash subsignatures are not file-body signatures",
        );
    }
    if raw.starts_with("${") {
        return unsupported(raw, "macro subsignatures are not expanded yet");
    }
    if looks_like_byte_compare(raw) {
        return match parse_byte_compare(raw) {
            Ok(spec) => (
                Subsignature::ByteCompare { spec },
                None,
            ),
            Err(err) => unsupported(raw, &err),
        };
    }
    if looks_like_pcre(raw) {
        return match parse_pcre(raw) {
            Ok((trigger, regex, global)) => (
                Subsignature::Pcre {
                    trigger,
                    regex,
                    global,
                },
                None,
            ),
            Err(err) => unsupported(raw, &err),
        };
    }
    if raw.contains('#') {
        return unsupported(raw, "hash-like subsignature is unsupported");
    }

    let (body_with_offset, modifier_text) = match raw.rsplit_once("::") {
        Some((body, modifiers)) => (body, modifiers),
        None => (raw, ""),
    };

    let modifiers = match Modifiers::parse(modifier_text) {
        Ok(modifiers) => modifiers,
        Err(err) => return unsupported(raw, &err),
    };

    let (offset, body) = match body_with_offset.split_once(':') {
        Some((candidate, body)) if looks_like_offset(candidate) => {
            (OffsetSpec::parse(candidate), body)
        }
        _ => (OffsetSpec::any(), body_with_offset),
    };

    let mut warning = None;
    if matches!(
        offset.anchor,
        OffsetAnchor::VersionInfo | OffsetAnchor::MacroGroup(_) | OffsetAnchor::Unsupported(_)
    ) {
        warning = Some(format!(
            "subsignature offset '{}' is not scannable yet",
            raw
        ));
    }

    match compile_pattern_variants(body, modifiers) {
        Ok(patterns) => (
            Subsignature::Body { offset, patterns },
            warning,
        ),
        Err(err) => unsupported(raw, &format!("invalid body pattern: {err}")),
    }
}

// ---------------------------------------------------------------------------
// PCRE subsignatures: Trigger/PCRE/Flags
// ---------------------------------------------------------------------------

fn looks_like_pcre(raw: &str) -> bool {
    raw.contains('/')
}

fn parse_pcre(raw: &str) -> Result<(LogicalExpr, LazyRegex, bool), String> {
    let first = raw
        .find('/')
        .ok_or_else(|| "PCRE subsignature missing '/'".to_string())?;
    let trigger_str = &raw[..first];
    let rest = &raw[first + 1..];
    let (pattern_raw, flags) = match rest.rfind('/') {
        Some(last) => (&rest[..last], &rest[last + 1..]),
        None => (rest, ""),
    };
    if pattern_raw.is_empty() {
        return Err("PCRE subsignature has an empty regex".to_string());
    }

    let trigger_tree = ExprParser::new(trigger_str)
        .parse()
        .map_err(|e| format!("PCRE trigger expression: {e}"))?;
    let trigger = LogicalExpr::from_tree(&trigger_tree);

    // ClamAV escapes forward slashes inside the regex as "\/"; undo that, then
    // translate ClamAV/PCRE dialect quirks (unknown escapes, literal '[' in a
    // class, non-quantifier braces) into syntax Rust's regex crate accepts.
    let pattern = crate::database::sanitize_clamav_regex(&pattern_raw.replace("\\/", "/"));

    // Bake the supported flags into the source as an inline group `(?ims…)` so the
    // lazily-built regex reproduces the original `RegexBuilder` configuration
    // without us having to store the flags separately. `g` (global) is not a
    // regex flag — it selects find-all vs is-match at scan time. r/e/A/E
    // (offset/anchoring tuning) and any unknown flag are ignored as before. The
    // default 10 MB compiled-size cap still applies at lazy-build time.
    let mut global = false;
    let mut inline = String::new();
    for ch in flags.chars() {
        match ch {
            'g' => global = true,
            'i' | 's' | 'm' | 'x' | 'U' => inline.push(ch),
            _ => {}
        }
    }
    let source = if inline.is_empty() {
        pattern
    } else {
        format!("(?{inline}){pattern}")
    };
    Ok((trigger, LazyRegex::new(source), global))
}

// ---------------------------------------------------------------------------
// Byte-compare subsignatures: subsigid_trigger(offset#byte_options#comparisons)
// ---------------------------------------------------------------------------

fn looks_like_byte_compare(raw: &str) -> bool {
    let Some(open) = raw.find('(') else {
        return false;
    };
    if open == 0 || !raw.ends_with(')') {
        return false;
    }
    if !raw[..open].bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let inside = &raw[open + 1..raw.len() - 1];
    inside.matches('#').count() == 2
}

fn parse_byte_compare(raw: &str) -> Result<ByteCompareSpec, String> {
    let open = raw
        .find('(')
        .ok_or_else(|| "byte-compare missing '('".to_string())?;
    let trigger_subsig = raw[..open]
        .parse::<usize>()
        .map_err(|_| "byte-compare trigger must be a subsignature index".to_string())?;
    let inside = &raw[open + 1..raw.len() - 1];
    let parts: Vec<&str> = inside.split('#').collect();
    if parts.len() != 3 {
        return Err("byte-compare needs offset#byte_options#comparisons".to_string());
    }

    let (offset_sign, offset_rest) = if let Some(rest) = parts[0].strip_prefix(">>") {
        (1i64, rest)
    } else if let Some(rest) = parts[0].strip_prefix("<<") {
        (-1i64, rest)
    } else {
        return Err("byte-compare offset must start with '>>' or '<<'".to_string());
    };
    let offset_value = parse_int_token(offset_rest)
        .ok_or_else(|| "byte-compare offset is not a number".to_string())? as usize;

    let (read_type, exact, num_bytes) = parse_byte_options(parts[1])?;

    let comparisons = parts[2]
        .split(',')
        .map(parse_byte_comparison)
        .collect::<Result<Vec<_>, _>>()?;
    if comparisons.is_empty() || comparisons.len() > 2 {
        return Err("byte-compare needs one or two comparisons".to_string());
    }

    Ok(ByteCompareSpec {
        trigger_subsig,
        offset_sign,
        offset_value,
        read_type,
        exact,
        num_bytes,
        comparisons,
    })
}

fn parse_byte_options(raw: &str) -> Result<(ByteReadType, bool, usize), String> {
    let mut chars = raw.chars().peekable();
    let base = chars
        .next()
        .ok_or_else(|| "byte-compare options are empty".to_string())?;
    let mut endian_big = false;
    // endianness only meaningful for binary, but tolerate it for all bases
    if matches!(chars.peek(), Some('l' | 'b')) {
        endian_big = chars.next() == Some('b');
    }
    let exact = if chars.peek() == Some(&'e') {
        chars.next();
        true
    } else {
        false
    };
    let num_str: String = chars.collect();
    let num_bytes = parse_int_token(&num_str)
        .ok_or_else(|| "byte-compare byte count is not a number".to_string())?
        as usize;
    if num_bytes == 0 {
        return Err("byte-compare byte count must be > 0".to_string());
    }

    let read_type = match base {
        'h' => ByteReadType::HexAscii,
        'd' => ByteReadType::DecimalAscii,
        'a' => ByteReadType::Auto,
        'i' => {
            if endian_big {
                ByteReadType::BinaryBe
            } else {
                ByteReadType::BinaryLe
            }
        }
        other => return Err(format!("unknown byte-compare type '{other}'")),
    };
    if matches!(read_type, ByteReadType::BinaryLe | ByteReadType::BinaryBe) && num_bytes > 8 {
        return Err("binary byte-compare supports at most 8 bytes".to_string());
    }
    Ok((read_type, exact, num_bytes))
}

fn parse_byte_comparison(raw: &str) -> Result<(CompareOp, u64), String> {
    let mut chars = raw.chars();
    let op = match chars.next() {
        Some('<') => CompareOp::Less,
        Some('>') => CompareOp::Greater,
        Some('=') => CompareOp::Equal,
        _ => return Err("byte-compare comparison must start with <, > or =".to_string()),
    };
    let value_str: String = chars.collect();
    let value = parse_int_token(value_str.trim())
        .ok_or_else(|| "byte-compare comparison value is not a number".to_string())?;
    Ok((op, value))
}

/// Parse a hex (`0x..`) or decimal integer token.
fn parse_int_token(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u64>().ok()
    }
}

impl ByteCompareSpec {
    /// Evaluate this byte-compare against `data`, anchored at the offset where
    /// the trigger subsignature matched. Returns true if all comparisons hold.
    pub fn evaluate(&self, data: &[u8], trigger_offset: usize) -> bool {
        let pos = if self.offset_sign >= 0 {
            trigger_offset.checked_add(self.offset_value)
        } else {
            trigger_offset.checked_sub(self.offset_value)
        };
        let Some(pos) = pos else {
            return false;
        };
        let Some(value) = self.read_value(data, pos) else {
            return false;
        };
        self.comparisons.iter().all(|(op, rhs)| match op {
            CompareOp::Less => value < *rhs,
            CompareOp::Greater => value > *rhs,
            CompareOp::Equal => value == *rhs,
            CompareOp::LessEqual => value <= *rhs,
            CompareOp::GreaterEqual => value >= *rhs,
        })
    }

    fn read_value(&self, data: &[u8], pos: usize) -> Option<u64> {
        let slice = data.get(pos..pos.checked_add(self.num_bytes)?)?;
        match self.read_type {
            ByteReadType::BinaryLe => {
                let mut value: u64 = 0;
                for (i, b) in slice.iter().enumerate() {
                    value |= (*b as u64) << (8 * i);
                }
                Some(value)
            }
            ByteReadType::BinaryBe => {
                let mut value: u64 = 0;
                for b in slice {
                    value = (value << 8) | (*b as u64);
                }
                Some(value)
            }
            ByteReadType::HexAscii | ByteReadType::DecimalAscii | ByteReadType::Auto => {
                let text = std::str::from_utf8(slice).ok()?;
                self.parse_ascii_value(text)
            }
        }
    }

    fn parse_ascii_value(&self, text: &str) -> Option<u64> {
        let trimmed = text.trim();
        match self.read_type {
            ByteReadType::HexAscii => {
                let digits = take_valid(trimmed, self.exact, |c| c.is_ascii_hexdigit())?;
                u64::from_str_radix(&digits, 16).ok()
            }
            ByteReadType::DecimalAscii => {
                let digits = take_valid(trimmed, self.exact, |c| c.is_ascii_digit())?;
                digits.parse::<u64>().ok()
            }
            ByteReadType::Auto => {
                if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    let digits = take_valid(hex, self.exact, |c| c.is_ascii_hexdigit())?;
                    u64::from_str_radix(&digits, 16).ok()
                } else if let Some(oct) = trimmed.strip_prefix('0').filter(|s| !s.is_empty()) {
                    let digits = take_valid(oct, self.exact, |c| ('0'..='7').contains(&c))?;
                    u64::from_str_radix(&digits, 8).ok()
                } else {
                    let digits = take_valid(trimmed, self.exact, |c| c.is_ascii_digit())?;
                    digits.parse::<u64>().ok()
                }
            }
            ByteReadType::BinaryLe | ByteReadType::BinaryBe => None,
        }
    }
}

fn take_valid(text: &str, exact: bool, valid: impl Fn(char) -> bool) -> Option<String> {
    if exact {
        if !text.is_empty() && text.chars().all(|c| valid(c)) {
            Some(text.to_string())
        } else {
            None
        }
    } else {
        let digits: String = text.chars().take_while(|c| valid(*c)).collect();
        if digits.is_empty() {
            None
        } else {
            Some(digits)
        }
    }
}

fn unsupported(raw: &str, reason: &str) -> (Subsignature, Option<String>) {
    let _ = raw;
    (
        Subsignature::Unsupported {
            reason: reason.to_string(),
        },
        Some(reason.to_string()),
    )
}

fn looks_like_offset(raw: &str) -> bool {
    if raw == "*" || raw.parse::<usize>().is_ok() || raw.contains(',') {
        return true;
    }
    let upper = raw.to_ascii_uppercase();
    upper.starts_with("EOF-")
        || upper == "EP"
        || upper.starts_with("EP+")
        || upper.starts_with("EP-")
        || upper.starts_with("SE")
        || upper == "SL"
        || upper.starts_with("SL+")
        || upper.starts_with("SL-")
        || (upper.starts_with('S')
            && upper[1..]
                .chars()
                .next()
                .map_or(false, |ch| ch.is_ascii_digit()))
        || upper == "VI"
        || raw.starts_with('$')
}

struct ExprParser {
    chars: Vec<char>,
    pos: usize,
}

impl ExprParser {
    fn new(raw: &str) -> Self {
        let raw = strip_expression_anchor(raw);
        Self {
            chars: raw.chars().collect(),
            pos: 0,
        }
    }

    fn parse(mut self) -> Result<ExprTree, String> {
        let expr = self.parse_or()?;
        self.skip_ws();
        if self.pos != self.chars.len() {
            return Err(format!(
                "unexpected logical expression token '{}'",
                self.chars[self.pos]
            ));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<ExprTree, String> {
        let mut expr = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.peek() != Some('|') {
                break;
            }
            self.pos += 1;
            let right = self.parse_and()?;
            expr = ExprTree::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<ExprTree, String> {
        let mut expr = self.parse_postfix()?;
        loop {
            self.skip_ws();
            if self.peek() != Some('&') {
                break;
            }
            self.pos += 1;
            let right = self.parse_postfix()?;
            expr = ExprTree::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_postfix(&mut self) -> Result<ExprTree, String> {
        let mut expr = self.parse_primary()?;
        self.skip_ws();
        let op = match self.peek() {
            Some('=') if self.peek_next() == Some('=') => {
                self.pos += 2;
                Some(CompareOp::Equal)
            }
            Some('=') => {
                self.pos += 1;
                Some(CompareOp::Equal)
            }
            Some('>') if self.peek_next() == Some('=') => {
                self.pos += 2;
                Some(CompareOp::GreaterEqual)
            }
            Some('>') => {
                self.pos += 1;
                Some(CompareOp::Greater)
            }
            Some('<') if self.peek_next() == Some('=') => {
                self.pos += 2;
                Some(CompareOp::LessEqual)
            }
            Some('<') => {
                self.pos += 1;
                Some(CompareOp::Less)
            }
            _ => None,
        };
        if let Some(op) = op {
            let hits = self.parse_number()?;
            let distinct = if self.peek() == Some(',') {
                self.pos += 1;
                Some(self.parse_number()?)
            } else {
                None
            };
            expr = ExprTree::Compare {
                expr: Box::new(expr),
                op,
                hits,
                distinct,
            };
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<ExprTree, String> {
        self.skip_ws();
        match self.peek() {
            Some('(') => {
                self.pos += 1;
                let expr = self.parse_or()?;
                self.skip_ws();
                if self.peek() != Some(')') {
                    return Err("unterminated logical expression group".to_string());
                }
                self.pos += 1;
                Ok(expr)
            }
            Some(ch) if ch.is_ascii_digit() => {
                let index = self.parse_number()?;
                self.skip_index_suffix();
                Ok(ExprTree::Subsig(index))
            }
            Some(other) => Err(format!("unexpected logical expression token '{other}'")),
            None => Err("unexpected end of logical expression".to_string()),
        }
    }

    fn parse_number(&mut self) -> Result<usize, String> {
        self.skip_ws();
        let start = self.pos;
        while self.peek().map_or(false, |ch| ch.is_ascii_digit()) {
            self.pos += 1;
        }
        if start == self.pos {
            return Err("expected decimal number".to_string());
        }
        self.chars[start..self.pos]
            .iter()
            .collect::<String>()
            .parse::<usize>()
            .map_err(|_| "invalid decimal number".to_string())
    }

    fn skip_ws(&mut self) {
        while self.peek().map_or(false, |ch| ch.is_whitespace()) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }

    fn skip_index_suffix(&mut self) {
        while self.peek().map_or(false, |ch| ch.is_ascii_alphabetic()) {
            self.pos += 1;
        }
        if self.peek() == Some(',') {
            let checkpoint = self.pos;
            self.pos += 1;
            let mut saw_digit = false;
            while self
                .peek()
                .map_or(false, |ch| ch.is_ascii_digit() || ch == '-')
            {
                saw_digit = saw_digit || self.peek().map_or(false, |ch| ch.is_ascii_digit());
                self.pos += 1;
            }
            if !saw_digit {
                self.pos = checkpoint;
            }
        }
    }
}

fn strip_expression_anchor(raw: &str) -> &str {
    let Some((candidate, rest)) = raw.split_once(':') else {
        return raw;
    };
    let upper = candidate.to_ascii_uppercase();
    let looks_like_anchor = candidate.parse::<usize>().is_ok()
        || candidate == "*"
        || upper.starts_with("EOF-")
        || upper == "EP"
        || upper.starts_with("EP+")
        || upper.starts_with("EP-")
        || upper.starts_with('S')
        || upper == "SL"
        || upper.starts_with("SL+")
        || upper.starts_with("SL-");
    if looks_like_anchor {
        rest
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SourceLocation {
        SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ldb")),
            line: 1,
        }
    }

    #[test]
    fn parses_and_evaluates_logic() {
        let (sig, warnings) = parse_logical_signature(
            "Test;Target:0;((0|1|2)>2,2)&3;4141;4242;4343;4444",
            source(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert!(sig.expression.eval(&[1, 0, 2, 1]).matched);
        assert!(!sig.expression.eval(&[1, 0, 0, 1]).matched);
    }

    #[test]
    fn accepts_index_suffix_used_by_legacy_rules() {
        let (sig, _) =
            parse_logical_signature("Test;Target:0;(0&1i)|2;4141;4242;4343", source()).unwrap();
        assert!(sig.expression.eval(&[1, 1, 0]).matched);
    }

    #[test]
    fn accepts_database_expression_extensions() {
        let (anchored, _) =
            parse_logical_signature("Test;Target:0;0:0&1;4141;4242", source()).unwrap();
        assert!(anchored.expression.eval(&[1, 1]).matched);

        let (relative, _) =
            parse_logical_signature("Test;Target:0;0,1-4&1,1-4&2=1;4141;4242;4343", source())
                .unwrap();
        assert!(relative.expression.eval(&[1, 1, 1]).matched);

        let (comparisons, _) =
            parse_logical_signature("Test;Target:0;(0>=2)&(1==1);4141;4242", source()).unwrap();
        assert!(comparisons.expression.eval(&[2, 1]).matched);
    }

    #[test]
    fn parses_and_evaluates_byte_compare() {
        let (sub, warning) = parse_subsignature("0(>>4#il2#>0)");
        assert!(warning.is_none(), "unexpected warning: {warning:?}");
        match sub {
            Subsignature::ByteCompare { spec, .. } => {
                assert_eq!(spec.trigger_subsig, 0);
                assert_eq!(spec.offset_sign, 1);
                assert_eq!(spec.offset_value, 4);
                assert_eq!(spec.num_bytes, 2);
                assert!(matches!(spec.read_type, ByteReadType::BinaryLe));
                // 2 LE bytes at offset 4 = 0x0005 = 5 > 0.
                assert!(spec.evaluate(b"SIZE\x05\x00", 0));
                // 0x0000 = 0 is not > 0.
                assert!(!spec.evaluate(b"SIZE\x00\x00", 0));
            }
            other => panic!("expected byte-compare, got {other:?}"),
        }
    }

    #[test]
    fn evaluates_ascii_byte_compare() {
        // 4 ASCII hex digits at offset 0 == 0x00ff.
        let (sub, _) = parse_subsignature("0(>>0#he4#=255)");
        let Subsignature::ByteCompare { spec, .. } = sub else {
            panic!("expected byte-compare");
        };
        assert!(spec.evaluate(b"00ff", 0));
        assert!(!spec.evaluate(b"00fe", 0));
    }

    #[test]
    fn parses_pcre_subsignature_with_flags() {
        let (sub, warning) = parse_subsignature("0/ab.c/i");
        assert!(warning.is_none(), "unexpected warning: {warning:?}");
        match sub {
            Subsignature::Pcre { regex, global, .. } => {
                assert!(!global);
                assert!(regex.is_match(b"xxAByCzz"));
            }
            other => panic!("expected PCRE, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_pcre_is_inert_not_a_false_match() {
        // Backreferences aren't supported by the regex crate. With lazy
        // compilation the subsig is accepted at load (no upfront compile, no
        // warning), but the regex fails to compile on first use and is treated as
        // "never matches" — detection-equivalent to the old Unsupported handling.
        let (sub, warning) = parse_subsignature(r"0/(a)\1/");
        assert!(warning.is_none());
        match sub {
            Subsignature::Pcre { regex, .. } => {
                assert!(regex.get().is_none(), "invalid regex must fail to compile");
                assert!(!regex.is_match(b"aa"));
            }
            other => panic!("expected PCRE subsig, got {other:?}"),
        }
    }
}
