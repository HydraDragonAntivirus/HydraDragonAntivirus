use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Modifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
}

impl Modifiers {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut modifiers = Self::default();
        for ch in raw.chars() {
            match ch {
                'i' => modifiers.nocase = true,
                'w' => modifiers.wide = true,
                'a' => modifiers.ascii = true,
                'f' => modifiers.fullword = true,
                other => return Err(format!("unsupported subsignature modifier '{other}'")),
            }
        }
        Ok(modifiers)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pattern {
    tokens: Vec<Token>,
    /// Backing storage for `Token::Literal` runs (exact byte sequences), stored
    /// once contiguously instead of one token per byte.
    lits: Box<[u8]>,
    fullword: bool,
    /// The longest required literal as an `(off, len)` slice of `lits` — used as
    /// a fast pre-check / prefilter atom. Stored as an offset (not a byte copy)
    /// since the bytes already live in `lits`.
    required_literal: Option<(u32, u32)>,
}

// Memory: there are hundreds of thousands of signatures, each a `Vec<Token>`,
// so `Token` is kept small. Jump bounds are `u32` (ClamAV jumps are tiny) and
// the large alternation variant is boxed, so a token is ~16 bytes instead of
// ~56 — a literal byte costs ~16 B rather than bloating to the widest variant.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Byte(ByteMatcher),
    /// A run of exact, case-sensitive bytes, stored once in the pattern's `lits`
    /// arena and referenced by offset+length (8 bytes) instead of one ~16-byte
    /// `Byte` token per byte. This is the key memory win.
    Literal {
        off: u32,
        len: u32,
    },
    AnyBytes {
        min: u32,
        max: Option<u32>,
    },
    Boundary(Boundary),
    Alternates(Box<Alternates>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Alternates {
    branches: Vec<Vec<Token>>,
    negated: bool,
    negated_width: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boundary {
    Word,
    Newline,
    NonAlphaNum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteMatcher {
    mask: u8,
    value: u8,
    nocase: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchRange {
    pub start: usize,
    pub end: usize,
}

pub fn compile_pattern_variants(raw: &str, modifiers: Modifiers) -> Result<Vec<Pattern>, String> {
    let mut parser = Parser::new(raw, modifiers.nocase);
    let tokens = parser.parse_all()?;
    let mut variants = Vec::new();

    if !modifiers.wide || modifiers.ascii {
        variants.push(Pattern::new(tokens.clone(), modifiers.fullword));
    }

    if modifiers.wide {
        variants.push(Pattern::new(to_wide_tokens(&tokens), modifiers.fullword));
    }

    Ok(variants)
}

impl Pattern {
    fn new(tokens: Vec<Token>, fullword: bool) -> Self {
        let (tokens, lits) = compact_tokens(tokens);
        let required_literal = longest_required_literal(&tokens);
        Self {
            tokens,
            lits: lits.into_boxed_slice(),
            fullword,
            required_literal,
        }
    }

    pub fn is_match(&self, data: &[u8]) -> bool {
        !self.find_all(data, &[(0, data.len())], 1).is_empty()
    }

    /// The pattern's longest required literal substring (case-sensitive, exact
    /// bytes), if any. The pattern cannot match unless this appears in the data,
    /// so it's usable as an Aho-Corasick prefilter atom. `None` when the pattern
    /// has no usable literal (e.g. fully wildcard or nocase).
    pub fn required_atom(&self) -> Option<&[u8]> {
        self.required_literal
            .map(|(off, len)| &self.lits[off as usize..(off + len) as usize])
    }

    pub fn find_all(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
    ) -> Vec<MatchRange> {
        if limit == 0 {
            return Vec::new();
        }
        if let Some((off, len)) = self.required_literal {
            let required = &self.lits[off as usize..(off + len) as usize];
            if !contains_subslice(data, required) {
                return Vec::new();
            }
        }

        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for &(start, end) in ranges {
            let start = start.min(data.len());
            let end = end.min(data.len());
            if start > end {
                continue;
            }
            for pos in start..=end {
                if let Some(match_end) = self.match_from(data, pos) {
                    if self.fullword && !is_fullword(data, pos, match_end) {
                        continue;
                    }
                    if seen.insert((pos, match_end)) {
                        out.push(MatchRange {
                            start: pos,
                            end: match_end,
                        });
                        if out.len() >= limit {
                            return out;
                        }
                    }
                }
            }
        }
        out
    }

    fn match_from(&self, data: &[u8], start: usize) -> Option<usize> {
        match_tokens(&self.tokens, &self.lits, data, 0, start, 0)
    }
}

fn match_tokens(
    tokens: &[Token],
    lits: &[u8],
    data: &[u8],
    token_index: usize,
    pos: usize,
    depth: usize,
) -> Option<usize> {
    if depth > 2048 {
        return None;
    }
    if token_index == tokens.len() {
        return Some(pos);
    }

    match &tokens[token_index] {
        Token::Byte(byte) => {
            if pos < data.len() && byte.matches(data[pos]) {
                match_tokens(tokens, lits, data, token_index + 1, pos + 1, depth + 1)
            } else {
                None
            }
        }
        Token::Literal { off, len } => {
            let lit = &lits[*off as usize..(*off + *len) as usize];
            let end = pos + lit.len();
            if end <= data.len() && &data[pos..end] == lit {
                match_tokens(tokens, lits, data, token_index + 1, end, depth + 1)
            } else {
                None
            }
        }
        Token::AnyBytes { min, max } => {
            let min_pos = pos.checked_add(*min as usize)?;
            if min_pos > data.len() {
                return None;
            }
            let max_len = max
                .map(|m| m as usize)
                .unwrap_or_else(|| data.len().saturating_sub(pos));
            let max_pos = pos.saturating_add(max_len).min(data.len());
            for next in min_pos..=max_pos {
                if let Some(end) = match_tokens(tokens, lits, data, token_index + 1, next, depth + 1)
                {
                    return Some(end);
                }
            }
            None
        }
        Token::Boundary(Boundary::Word) => {
            if is_word_boundary(data, pos) {
                match_tokens(tokens, lits, data, token_index + 1, pos, depth + 1)
            } else {
                None
            }
        }
        Token::Boundary(Boundary::Newline) => {
            if pos == 0
                || pos == data.len()
                || data.get(pos.wrapping_sub(1)) == Some(&b'\r')
                || data.get(pos.wrapping_sub(1)) == Some(&b'\n')
            {
                match_tokens(tokens, lits, data, token_index + 1, pos, depth + 1)
            } else {
                None
            }
        }
        Token::Boundary(Boundary::NonAlphaNum) => {
            if pos < data.len() && !data[pos].is_ascii_alphanumeric() {
                match_tokens(tokens, lits, data, token_index + 1, pos + 1, depth + 1)
            } else {
                None
            }
        }
        Token::Alternates(alt) => {
            let Alternates {
                branches,
                negated,
                negated_width,
            } = alt.as_ref();
            // Alternation branches aren't compacted, so they contain no
            // `Literal` tokens and don't use `lits` (an empty slice is fine).
            if *negated {
                let width = (*negated_width)?;
                if pos + width > data.len() {
                    return None;
                }
                let matched = branches.iter().any(|branch| {
                    match_tokens(branch, &[], data, 0, pos, depth + 1) == Some(pos + width)
                });
                if !matched {
                    match_tokens(tokens, lits, data, token_index + 1, pos + width, depth + 1)
                } else {
                    None
                }
            } else {
                for branch in branches {
                    if let Some(branch_end) = match_tokens(branch, &[], data, 0, pos, depth + 1) {
                        if let Some(end) =
                            match_tokens(tokens, lits, data, token_index + 1, branch_end, depth + 1)
                        {
                            return Some(end);
                        }
                    }
                }
                None
            }
        }
    }
}

impl ByteMatcher {
    fn exact(value: u8, nocase: bool) -> Self {
        Self {
            mask: 0xff,
            value,
            nocase,
        }
    }

    fn matches(self, byte: u8) -> bool {
        if self.mask == 0xff && self.nocase && self.value.is_ascii_alphabetic() {
            byte.to_ascii_lowercase() == self.value.to_ascii_lowercase()
        } else {
            (byte & self.mask) == self.value
        }
    }

    fn exact_value(self) -> Option<u8> {
        if self.mask == 0xff && !self.nocase {
            Some(self.value)
        } else {
            None
        }
    }
}

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    nocase: bool,
    raw: &'a str,
}

impl<'a> Parser<'a> {
    fn new(raw: &'a str, nocase: bool) -> Self {
        Self {
            chars: raw.chars().collect(),
            pos: 0,
            nocase,
            raw,
        }
    }

    fn parse_all(&mut self) -> Result<Vec<Token>, String> {
        let tokens = self.parse_sequence(false)?;
        if self.pos != self.chars.len() {
            return Err(format!(
                "unexpected character '{}' in pattern",
                self.chars[self.pos]
            ));
        }
        Ok(tokens)
    }

    fn parse_sequence(&mut self, stop_for_alt: bool) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();
        while self.pos < self.chars.len() {
            let ch = self.chars[self.pos];
            if stop_for_alt && (ch == '|' || ch == ')') {
                break;
            }
            match ch {
                '*' => {
                    self.pos += 1;
                    tokens.push(Token::AnyBytes { min: 0, max: None });
                }
                '{' => tokens.push(self.parse_braced_range()?),
                '[' => tokens.push(self.parse_bracket_range()?),
                '!' if self.peek(1) == Some('(') => {
                    self.pos += 1;
                    tokens.push(self.parse_alternate(true)?);
                }
                '(' => tokens.push(self.parse_paren()?),
                '?' => tokens.push(self.parse_byte_pair()?),
                _ if is_hex(ch) => tokens.push(self.parse_byte_pair()?),
                _ if ch.is_whitespace() => self.pos += 1,
                _ => return Err(format!("unsupported token '{ch}' in {}", self.raw)),
            }
        }
        Ok(tokens)
    }

    fn parse_paren(&mut self) -> Result<Token, String> {
        if self.peek(1) == Some('B') && self.peek(2) == Some(')') {
            self.pos += 3;
            return Ok(Token::Boundary(Boundary::Word));
        }
        if self.peek(1) == Some('L') && self.peek(2) == Some(')') {
            self.pos += 3;
            return Ok(Token::Boundary(Boundary::Newline));
        }
        if self.peek(1) == Some('W') && self.peek(2) == Some(')') {
            self.pos += 3;
            return Ok(Token::Boundary(Boundary::NonAlphaNum));
        }
        self.parse_alternate(false)
    }

    fn parse_alternate(&mut self, negated: bool) -> Result<Token, String> {
        self.expect('(')?;
        let mut branches = Vec::new();
        loop {
            let branch = self.parse_sequence(true)?;
            branches.push(branch);
            match self.peek(0) {
                Some('|') => self.pos += 1,
                Some(')') => {
                    self.pos += 1;
                    break;
                }
                Some(other) => return Err(format!("unexpected alternate token '{other}'")),
                None => return Err("unterminated alternate".to_string()),
            }
        }

        let negated_width = if negated {
            let widths = branches
                .iter()
                .map(|branch| fixed_width(branch))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| "negated alternates must have fixed widths".to_string())?;
            if widths.iter().all(|width| *width == widths[0]) {
                Some(widths[0])
            } else {
                return Err("negated alternates must have equal fixed widths".to_string());
            }
        } else {
            None
        };

        Ok(Token::Alternates(Box::new(Alternates {
            branches,
            negated,
            negated_width,
        })))
    }

    fn parse_braced_range(&mut self) -> Result<Token, String> {
        self.expect('{')?;
        let content = self.read_until('}')?;
        let (min, max) = parse_range_content(&content)?;
        Ok(Token::AnyBytes {
            min: min as u32,
            max: max.map(|m| m as u32),
        })
    }

    fn parse_bracket_range(&mut self) -> Result<Token, String> {
        self.expect('[')?;
        let content = self.read_until(']')?;
        let (min, max) = parse_range_content(&content)?;
        Ok(Token::AnyBytes {
            min: min as u32,
            max: Some(max.unwrap_or(min) as u32),
        })
    }

    fn parse_byte_pair(&mut self) -> Result<Token, String> {
        let high = self
            .peek(0)
            .ok_or_else(|| "missing high nibble".to_string())?;
        let low = self
            .peek(1)
            .ok_or_else(|| "missing low nibble".to_string())?;

        if !(is_hex(high) || high == '?') || !(is_hex(low) || low == '?') {
            return Err(format!("invalid byte token '{high}{low}'"));
        }

        self.pos += 2;
        let matcher = match (high, low) {
            ('?', '?') => ByteMatcher {
                mask: 0x00,
                value: 0x00,
                nocase: false,
            },
            ('?', lo) => ByteMatcher {
                mask: 0x0f,
                value: hex_value(lo)?,
                nocase: false,
            },
            (hi, '?') => ByteMatcher {
                mask: 0xf0,
                value: hex_value(hi)? << 4,
                nocase: false,
            },
            (hi, lo) => ByteMatcher::exact((hex_value(hi)? << 4) | hex_value(lo)?, self.nocase),
        };
        Ok(Token::Byte(matcher))
    }

    fn read_until(&mut self, end: char) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.chars.len() && self.chars[self.pos] != end {
            self.pos += 1;
        }
        if self.pos == self.chars.len() {
            return Err(format!("unterminated range, expected '{end}'"));
        }
        let content: String = self.chars[start..self.pos].iter().collect();
        self.pos += 1;
        Ok(content)
    }

    fn expect(&mut self, ch: char) -> Result<(), String> {
        match self.peek(0) {
            Some(found) if found == ch => {
                self.pos += 1;
                Ok(())
            }
            Some(found) => Err(format!("expected '{ch}', found '{found}'")),
            None => Err(format!("expected '{ch}', found end of pattern")),
        }
    }

    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }
}

fn parse_range_content(content: &str) -> Result<(usize, Option<usize>), String> {
    if let Some(rest) = content.strip_prefix('-') {
        let max = parse_usize(rest)?;
        return Ok((0, Some(max)));
    }
    if let Some(rest) = content.strip_suffix('-') {
        let min = parse_usize(rest)?;
        return Ok((min, None));
    }
    if let Some((left, right)) = content.split_once('-') {
        let min = parse_usize(left)?;
        let max = parse_usize(right)?;
        if max < min {
            return Err(format!("invalid range '{content}'"));
        }
        return Ok((min, Some(max)));
    }
    let exact = parse_usize(content)?;
    Ok((exact, Some(exact)))
}

fn parse_usize(raw: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|_| format!("invalid decimal number '{raw}'"))
}

fn fixed_width(tokens: &[Token]) -> Option<usize> {
    let mut width = 0usize;
    for token in tokens {
        match token {
            Token::Literal { len, .. } => width += *len as usize,
            Token::Byte(_) | Token::Boundary(Boundary::NonAlphaNum) => width += 1,
            Token::Boundary(Boundary::Word) | Token::Boundary(Boundary::Newline) => {}
            Token::AnyBytes {
                min,
                max: Some(max),
            } if min == max => width += *min as usize,
            Token::Alternates(alt) if !alt.negated => {
                let branch_widths = alt
                    .branches
                    .iter()
                    .map(|branch| fixed_width(branch))
                    .collect::<Option<Vec<_>>>()?;
                if branch_widths.iter().all(|item| *item == branch_widths[0]) {
                    width += branch_widths[0];
                } else {
                    return None;
                }
            }
            Token::Alternates(alt) if alt.negated_width.is_some() => {
                width += alt.negated_width.unwrap()
            }
            _ => return None,
        }
    }
    Some(width)
}

fn to_wide_tokens(tokens: &[Token]) -> Vec<Token> {
    let mut out = Vec::new();
    for token in tokens {
        match token {
            Token::Byte(byte) => {
                out.push(Token::Byte(*byte));
                if byte.exact_value().is_some() {
                    out.push(Token::Byte(ByteMatcher::exact(0, false)));
                }
            }
            Token::Alternates(alt) => {
                let branches = alt
                    .branches
                    .iter()
                    .map(|branch| to_wide_tokens(branch))
                    .collect::<Vec<_>>();
                let negated_width = if alt.negated {
                    branches.first().and_then(|branch| fixed_width(branch))
                } else {
                    alt.negated_width
                };
                out.push(Token::Alternates(Box::new(Alternates {
                    branches,
                    negated: alt.negated,
                    negated_width,
                })));
            }
            other => out.push(other.clone()),
        }
    }
    out
}

/// Merge runs of consecutive exact, case-sensitive bytes into a single
/// `Token::Literal` referencing a shared `lits` arena, instead of one ~16-byte
/// `Token::Byte` per byte. Runs of length 1 stay `Token::Byte` (a `Literal`
/// would only add 8 bytes for no gain). Alternation branches are left as-is.
fn compact_tokens(tokens: Vec<Token>) -> (Vec<Token>, Vec<u8>) {
    let mut out: Vec<Token> = Vec::with_capacity(tokens.len());
    let mut lits: Vec<u8> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for token in tokens {
        if let Token::Byte(byte) = &token {
            if let Some(value) = byte.exact_value() {
                run.push(value);
                continue;
            }
        }
        flush_run(&mut run, &mut lits, &mut out);
        out.push(token);
    }
    flush_run(&mut run, &mut lits, &mut out);
    out.shrink_to_fit();
    (out, lits)
}

fn flush_run(run: &mut Vec<u8>, lits: &mut Vec<u8>, out: &mut Vec<Token>) {
    match run.len() {
        0 => {}
        1 => {
            out.push(Token::Byte(ByteMatcher::exact(run[0], false)));
            run.clear();
        }
        n => {
            let off = lits.len() as u32;
            lits.extend_from_slice(run);
            out.push(Token::Literal {
                off,
                len: n as u32,
            });
            run.clear();
        }
    }
}

fn longest_required_literal(tokens: &[Token]) -> Option<(u32, u32)> {
    // After compaction, each maximal exact run ≥ 2 bytes is a single `Literal`;
    // return the longest as an (off, len) slice of the pattern's `lits`.
    tokens
        .iter()
        .filter_map(|t| match t {
            Token::Literal { off, len } => Some((*off, *len)),
            _ => None,
        })
        .max_by_key(|(_, len)| *len)
        .filter(|(_, len)| *len >= 2)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    // SIMD substring search — far faster than the naive O(n·m) window scan, and
    // this runs once per signature per file (the hot pre-filter check).
    memchr::memmem::find(haystack, needle).is_some()
}

fn is_fullword(data: &[u8], start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|idx| data.get(idx))
        .map_or(false, |byte| byte.is_ascii_alphanumeric());
    let after = data
        .get(end)
        .map_or(false, |byte| byte.is_ascii_alphanumeric());
    !before && !after
}

fn is_word_boundary(data: &[u8], pos: usize) -> bool {
    if pos == 0 || pos == data.len() {
        return true;
    }
    let left = data
        .get(pos - 1)
        .map_or(false, |byte| byte.is_ascii_alphanumeric());
    let right = data
        .get(pos)
        .map_or(false, |byte| byte.is_ascii_alphanumeric());
    left != right
}

fn is_hex(ch: char) -> bool {
    ch.is_ascii_hexdigit()
}

fn hex_value(ch: char) -> Result<u8, String> {
    ch.to_digit(16)
        .map(|value| value as u8)
        .ok_or_else(|| format!("invalid hex nibble '{ch}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(raw: &str) -> Pattern {
        compile_pattern_variants(raw, Modifiers::default())
            .unwrap()
            .remove(0)
    }

    #[test]
    fn exact_and_wildcards_match() {
        assert!(one("4142??44").is_match(b"xxABZDyy"));
        assert!(one("41?2").is_match(&[0x41, 0xa2]));
        assert!(one("4?42").is_match(b"AB"));
    }

    #[test]
    fn ranges_and_star_match() {
        assert!(one("41{2-4}42").is_match(b"AxxB"));
        assert!(one("41{-2}42").is_match(b"AB"));
        assert!(one("41*42").is_match(b"A much larger gap B"));
    }

    #[test]
    fn alternates_and_negated_alternates_match() {
        assert!(one("41(42|43)44").is_match(b"ACD"));
        assert!(one("41!(42|43)44").is_match(b"AZD"));
        assert!(!one("41!(42|43)44").is_match(b"ABD"));
    }

    #[test]
    fn modifiers_match_nocase_wide_and_fullword() {
        let nocase = compile_pattern_variants(
            "68656c6c6f",
            Modifiers {
                nocase: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert!(nocase.is_match(b"HELLO"));

        let wide = compile_pattern_variants(
            "6869",
            Modifiers {
                wide: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert!(wide.is_match(b"h\0i\0"));

        let fullword = compile_pattern_variants(
            "6869",
            Modifiers {
                fullword: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert!(fullword.is_match(b" hi "));
        assert!(!fullword.is_match(b"this"));
    }
}
