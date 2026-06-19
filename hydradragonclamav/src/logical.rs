use crate::database::{OffsetAnchor, OffsetSpec, SourceLocation};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};

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
    Unsupported {
        reason: String,
        raw: String,
    },
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
    if raw.contains("(>>") || raw.contains("(<<") || raw.contains('#') {
        return unsupported(raw, "byte-compare or hash-like subsignature is unsupported");
    }
    if raw.contains('/') {
        return unsupported(
            raw,
            "PCRE subsignatures are not implemented in this Rust body engine",
        );
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
}
