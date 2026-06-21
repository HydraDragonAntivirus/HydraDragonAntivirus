use crate::database::{OffsetAnchor, OffsetSpec, SourceLocation};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};
use regex::bytes::{Regex, RegexBuilder};

#[derive(Clone, Debug)]
pub struct LogicalSignature {
    pub name: String,
    pub target: Option<u32>,
    pub expression: LogicalExpr,
    pub subsignatures: Vec<Subsignature>,
    pub source: SourceLocation,
}

#[derive(Clone, Debug)]
pub enum Subsignature {
    Body {
        offset: OffsetSpec,
        patterns: Vec<Pattern>,
        raw: String,
    },
    /// `Trigger/PCRE/Flags` — the regex runs only when `trigger` evaluates true.
    Pcre {
        trigger: LogicalExpr,
        regex: Regex,
        global: bool,
        raw: String,
    },
    /// `subsigid_trigger(offset#byte_options#comparisons)` — reads bytes relative
    /// to the trigger subsignature's match and compares them numerically.
    ByteCompare {
        spec: ByteCompareSpec,
        raw: String,
    },
    Unsupported {
        reason: String,
        raw: String,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalExpr {
    Subsig(usize),
    And(Box<LogicalExpr>, Box<LogicalExpr>),
    Or(Box<LogicalExpr>, Box<LogicalExpr>),
    Compare {
        expr: Box<LogicalExpr>,
        op: CompareOp,
        hits: usize,
        distinct: Option<usize>,
    },
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

    let expression = ExprParser::new(parts[2]).parse()?;
    let target = parse_target(parts[1]);
    let mut warnings = Vec::new();
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
            expression,
            subsignatures,
            source,
        },
        warnings,
    ))
}

impl LogicalExpr {
    pub fn eval(&self, counts: &[usize]) -> EvalStats {
        match self {
            LogicalExpr::Subsig(index) => {
                let hits = counts.get(*index).copied().unwrap_or(0);
                EvalStats {
                    matched: hits > 0,
                    hits,
                    distinct: usize::from(hits > 0),
                }
            }
            LogicalExpr::And(left, right) => {
                let left = left.eval(counts);
                let right = right.eval(counts);
                EvalStats {
                    matched: left.matched && right.matched,
                    hits: left.hits + right.hits,
                    distinct: left.distinct + right.distinct,
                }
            }
            LogicalExpr::Or(left, right) => {
                let left = left.eval(counts);
                let right = right.eval(counts);
                EvalStats {
                    matched: left.matched || right.matched,
                    hits: left.hits + right.hits,
                    distinct: left.distinct + right.distinct,
                }
            }
            LogicalExpr::Compare {
                expr,
                op,
                hits,
                distinct,
            } => {
                let stats = expr.eval(counts);
                let hits_match = match op {
                    CompareOp::Equal => stats.hits == *hits,
                    CompareOp::Greater => stats.hits > *hits,
                    CompareOp::GreaterEqual => stats.hits >= *hits,
                    CompareOp::Less => stats.hits < *hits,
                    CompareOp::LessEqual => stats.hits <= *hits,
                };
                let distinct_match = distinct.map_or(true, |min| stats.distinct >= min);
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
                Subsignature::ByteCompare {
                    spec,
                    raw: raw.to_string(),
                },
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
                    raw: raw.to_string(),
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
            Subsignature::Body {
                offset,
                patterns,
                raw: raw.to_string(),
            },
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

fn parse_pcre(raw: &str) -> Result<(LogicalExpr, Regex, bool), String> {
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

    let trigger = ExprParser::new(trigger_str)
        .parse()
        .map_err(|e| format!("PCRE trigger expression: {e}"))?;

    // ClamAV escapes forward slashes inside the regex as "\/"; undo that, then
    // translate ClamAV/PCRE dialect quirks (unknown escapes, literal '[' in a
    // class, non-quantifier braces) into syntax Rust's regex crate accepts.
    let pattern = crate::database::sanitize_clamav_regex(&pattern_raw.replace("\\/", "/"));

    let mut global = false;
    let mut builder = RegexBuilder::new(&pattern);
    // ClamAV ships some large compiled regexes; raise the default 10 MB cap so
    // they aren't rejected for size alone (64 MB compiled program).
    builder.size_limit(64 * 1024 * 1024);
    for ch in flags.chars() {
        match ch {
            'g' => global = true,
            'i' => {
                builder.case_insensitive(true);
            }
            's' => {
                builder.dot_matches_new_line(true);
            }
            'm' => {
                builder.multi_line(true);
            }
            'x' => {
                builder.ignore_whitespace(true);
            }
            'U' => {
                builder.swap_greed(true);
            }
            // r/e/A/E (offset/anchoring tuning) and any unknown flag: best-effort ignore.
            _ => {}
        }
    }
    let regex = builder
        .build()
        .map_err(|e| format!("unsupported PCRE regex: {e}"))?;
    Ok((trigger, regex, global))
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
    (
        Subsignature::Unsupported {
            reason: reason.to_string(),
            raw: raw.to_string(),
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

    fn parse(mut self) -> Result<LogicalExpr, String> {
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

    fn parse_or(&mut self) -> Result<LogicalExpr, String> {
        let mut expr = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.peek() != Some('|') {
                break;
            }
            self.pos += 1;
            let right = self.parse_and()?;
            expr = LogicalExpr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<LogicalExpr, String> {
        let mut expr = self.parse_postfix()?;
        loop {
            self.skip_ws();
            if self.peek() != Some('&') {
                break;
            }
            self.pos += 1;
            let right = self.parse_postfix()?;
            expr = LogicalExpr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_postfix(&mut self) -> Result<LogicalExpr, String> {
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
            expr = LogicalExpr::Compare {
                expr: Box::new(expr),
                op,
                hits,
                distinct,
            };
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<LogicalExpr, String> {
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
                Ok(LogicalExpr::Subsig(index))
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
    use std::path::PathBuf;

    fn source() -> SourceLocation {
        SourceLocation {
            path: PathBuf::from("test.ldb"),
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
    fn unsupported_pcre_becomes_unsupported_subsig() {
        // Backreferences are not supported by the regex engine.
        let (sub, warning) = parse_subsignature(r"0/(a)\1/");
        assert!(warning.is_some());
        assert!(matches!(sub, Subsignature::Unsupported { .. }));
    }
}
