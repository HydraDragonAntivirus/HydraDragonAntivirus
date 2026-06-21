use std::collections::HashSet;

/// Sentinel for an open-ended `AnyBytes` gap (`*` or `{n-}`), stored in
/// `Token::AnyBytes::max` so the field can be a plain `u32`.
const UNBOUNDED: u32 = u32::MAX;

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
    /// `Box<[Token]>`, not `Vec<Token>`: the token list is fixed after
    /// compaction, so dropping the unused capacity word saves 8 bytes on every
    /// one of the hundreds of thousands of patterns.
    tokens: Box<[Token]>,
    /// Backing storage for `Token::Literal` runs (exact byte sequences) AND the
    /// case-folded `nocase` atom, stored once contiguously instead of one token
    /// per byte / a separate per-pattern allocation.
    lits: Box<[u8]>,
    fullword: bool,
    /// The longest required literal as an `(off, len)` slice of `lits` — used as
    /// a fast pre-check / prefilter atom. Stored as an offset (not a byte copy)
    /// since the bytes already live in `lits`.
    required_literal: Option<(u32, u32)>,
    /// Fixed byte width of the pattern tokens that precede the required literal,
    /// when every preceding token is fixed-width. Enables ClamAV-style anchored
    /// verification: locate each occurrence of the literal in the data and try
    /// matching the whole pattern only at `occurrence - required_prefix`, instead
    /// of attempting a match at every byte offset. `None` when a preceding token
    /// is variable-width (`*`, `{n-m}`, …) — then we fall back to a window scan.
    required_prefix: Option<u32>,
    /// A case-folded (lowercased) literal atom usable as a prefilter hint for
    /// `nocase` patterns, stored as an `(off, len)` slice of `lits` (no separate
    /// allocation). `nocase` bytes never form a `Token::Literal` (see
    /// `ByteMatcher::exact_value`), so `required_literal`/`required_atom` are
    /// always `None` for them — without this, every nocase signature would be
    /// invisible to the Aho-Corasick prefilter and have to be evaluated on
    /// every single scan regardless of buffer content.
    required_atom_nocase: Option<(u32, u32)>,
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
        /// Maximum gap, or `UNBOUNDED` (`u32::MAX`) for an open `*`/`{n-}` gap.
        /// A plain `u32` (not `Option<u32>`) keeps `Token` at 12 bytes instead
        /// of 16 — across millions of tokens that's a meaningful resident cut.
        max: u32,
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
        let (tokens, mut lits) = compact_tokens(tokens);
        let (required_literal, required_prefix) = longest_required_literal(&tokens);
        // Fold the case-folded nocase atom into the same `lits` arena (appended
        // after the exact-literal bytes; existing `required_literal` offsets stay
        // valid) instead of giving each nocase pattern its own heap allocation.
        let required_atom_nocase = longest_nocase_run(&tokens).map(|run| {
            let off = lits.len() as u32;
            let len = run.len() as u32;
            lits.extend_from_slice(&run);
            (off, len)
        });
        Self {
            tokens: tokens.into_boxed_slice(),
            lits: lits.into_boxed_slice(),
            fullword,
            required_literal,
            required_prefix,
            required_atom_nocase,
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

    /// A case-folded (lowercased) required atom for `nocase` patterns, usable
    /// as a prefilter hint against a lowercased copy of the scanned buffer.
    /// `None` for patterns that already have a case-sensitive `required_atom`,
    /// or that have no run of ≥2 fixed bytes at all (e.g. fully wildcard).
    pub fn required_atom_nocase(&self) -> Option<&[u8]> {
        self.required_atom_nocase
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

        // ClamAV-style anchored verification (matcher-ac.c `bp = i + 1 - depth`):
        // when the required literal has a fixed-width prefix, jump to each
        // occurrence of the literal and only try matching the whole pattern at
        // `occurrence - prefix`. This avoids the catastrophic per-byte scan over
        // the entire buffer (millions of `match_from` calls) that dominates the
        // cost on large files once a sig is a prefilter candidate.
        if let (Some((off, len)), Some(prefix)) = (self.required_literal, self.required_prefix) {
            let required = &self.lits[off as usize..(off + len) as usize];
            let prefix = prefix as usize;
            let mut from = 0usize;
            while from + required.len() <= data.len() {
                let Some(rel) = memchr::memmem::find(&data[from..], required) else {
                    break;
                };
                let occurrence = from + rel;
                from = occurrence + 1; // allow overlapping occurrences
                let Some(start) = occurrence.checked_sub(prefix) else {
                    continue;
                };
                if !pos_in_ranges(start, ranges, data.len()) {
                    continue;
                }
                if let Some(match_end) = self.match_from(data, start) {
                    if self.fullword && !is_fullword(data, start, match_end) {
                        continue;
                    }
                    if seen.insert((start, match_end)) {
                        out.push(MatchRange {
                            start,
                            end: match_end,
                        });
                        if out.len() >= limit {
                            return out;
                        }
                    }
                }
            }
            return out;
        }

        // A pattern whose very first token is an unbounded `*` (min=0,
        // max=None) explores, from any starting position X, every later
        // position as the end of that gap. That search space strictly
        // shrinks as X increases, so if `match_from(data, X)` fails, every
        // `match_from(data, X')` for X' > X is searching a subset and must
        // also fail. Once that happens we can stop scanning immediately
        // instead of grinding through the rest of the buffer.
        //
        // Without this, the per-position fallback loop below combined with
        // the (also per-position) wildcard search inside `match_from`
        // degrades to O(n^2): for body subsignatures with a leading
        // wildcard — a very common ClamAV idiom ("literal anywhere") — this
        // is what turns a sub-second scan into a many-minute one on large
        // files once the signature's required-literal prefilter check
        // passes but the position it actually occurs at is far from the
        // start of the buffer.
        let unbounded_leading_wildcard =
            matches!(self.tokens.first(), Some(Token::AnyBytes { min: 0, max }) if *max == UNBOUNDED);

        // Anchor the fallback on the first token's concrete byte(s) when we can,
        // so we only try positions where the pattern could actually start —
        // `memchr` instead of probing every offset. This is what keeps `nocase`
        // patterns fast: their bytes never compact into a `Literal`, so they have
        // no `required_literal` to anchor the fast path above and would otherwise
        // scan the whole buffer for every candidate (the dominant scan cost).
        let first_byte_anchor = match self.tokens.first() {
            Some(Token::Byte(byte)) => byte.anchor_bytes(),
            _ => None,
        };

        for &(start, end) in ranges {
            let start = start.min(data.len());
            let end = end.min(data.len());
            if start > end {
                continue;
            }

            if let Some((b1, b2)) = first_byte_anchor {
                // Only positions where the first byte matches (both cases for a
                // nocase letter). `match_from` re-checks that byte cheaply.
                let hay_end = (end + 1).min(data.len());
                let hay = &data[start..hay_end];
                let try_pos = |pos: usize,
                               out: &mut Vec<MatchRange>,
                               seen: &mut HashSet<(usize, usize)>|
                 -> bool {
                    if let Some(match_end) = self.match_from(data, pos) {
                        if self.fullword && !is_fullword(data, pos, match_end) {
                            return false;
                        }
                        if seen.insert((pos, match_end)) {
                            out.push(MatchRange { start: pos, end: match_end });
                            return out.len() >= limit;
                        }
                    }
                    false
                };
                match b2 {
                    Some(b2) => {
                        for rel in memchr::memchr2_iter(b1, b2, hay) {
                            if try_pos(start + rel, &mut out, &mut seen) {
                                return out;
                            }
                        }
                    }
                    None => {
                        for rel in memchr::memchr_iter(b1, hay) {
                            if try_pos(start + rel, &mut out, &mut seen) {
                                return out;
                            }
                        }
                    }
                }
                continue;
            }

            // No anchorable first token (leading wildcard/boundary/masked byte) —
            // probe each position. The unbounded-leading-`*` early-out keeps this
            // from going quadratic.
            for pos in start..=end {
                match self.match_from(data, pos) {
                    Some(match_end) => {
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
                    None if unbounded_leading_wildcard => break,
                    None => {}
                }
            }
        }
        out
    }

    /// Like [`find_all`](Self::find_all), but verifies the pattern ONLY at the
    /// prefilter-provided atom offsets in `hints` (buffer positions where this
    /// pattern's required-literal atom occurred), instead of re-running a
    /// whole-buffer `memmem` scan. This is the "offset-threading" fast path: the
    /// shared Aho-Corasick prefilter already located every occurrence of the
    /// atom, so a candidate signature is verified at those few positions in O(1)
    /// each rather than rescanning megabytes per candidate — the change that
    /// turns a multi-second per-candidate scan into a handful of probes.
    ///
    /// Falls back to the full [`find_all`](Self::find_all) when the pattern
    /// can't be anchored to its literal: no `required_literal` (e.g. a `nocase`
    /// pattern, whose bytes never compact to a `Literal`), or the literal sits
    /// behind a variable-width token so `required_prefix` is `None`. There the
    /// hints don't pin the match start, so a full scan is required to stay
    /// complete.
    ///
    /// Correctness: `hints` must contain EVERY offset where the atom occurs (the
    /// prefilter records all occurrences, not just the first). Because the atom
    /// is a prefix of `required_literal`, every occurrence of the full literal is
    /// among `hints`; we re-confirm the full literal and run `match_from` at
    /// `occurrence - prefix`, exactly as the anchored `find_all` path does. The
    /// produced match set is therefore identical to `find_all` — offset-threading
    /// changes only *where we look*, never *what matches*, so detection is
    /// preserved. `ranges` and `fullword` are still enforced.
    pub fn find_all_at(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
        hints: &[u32],
    ) -> Vec<MatchRange> {
        if limit == 0 {
            return Vec::new();
        }
        // Only an atom-anchored pattern can be verified from hints alone. Without
        // a fixed-width prefix to the required literal, the hint offset doesn't
        // determine the match start, so we must do the full window scan.
        let (Some((off, len)), Some(prefix)) = (self.required_literal, self.required_prefix)
        else {
            return self.find_all(data, ranges, limit);
        };
        let required = &self.lits[off as usize..(off + len) as usize];
        let required_len = required.len();
        let prefix = prefix as usize;

        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for &hint in hints {
            let occurrence = hint as usize;
            // The indexed atom is only the literal's (<=16-byte) prefix; confirm
            // the FULL required literal is actually present at this offset before
            // attempting the (more expensive) whole-pattern match.
            let Some(lit_end) = occurrence.checked_add(required_len) else {
                continue;
            };
            if lit_end > data.len() || &data[occurrence..lit_end] != required {
                continue;
            }
            let Some(start) = occurrence.checked_sub(prefix) else {
                continue;
            };
            if !pos_in_ranges(start, ranges, data.len()) {
                continue;
            }
            if let Some(match_end) = self.match_from(data, start) {
                if self.fullword && !is_fullword(data, start, match_end) {
                    continue;
                }
                if seen.insert((start, match_end)) {
                    out.push(MatchRange {
                        start,
                        end: match_end,
                    });
                    if out.len() >= limit {
                        return out;
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
            let max_len = if *max == UNBOUNDED {
                data.len().saturating_sub(pos)
            } else {
                *max as usize
            };
            let max_pos = pos.saturating_add(max_len).min(data.len());
            if min_pos > max_pos {
                return None;
            }

            // Fast path: when the token right after the wildcard is a fixed
            // literal/byte, jump straight to its occurrences via memchr
            // instead of probing every byte position in the gap. Without
            // this, a body subsignature with multiple wildcard gaps (the
            // common ClamAV `AAAA*BBBB*CCCC` shape) degrades to O(n) work
            // per gap, nested per gap — O(n^2) or worse for a single
            // anchor occurrence on large files. Jumping to literal
            // occurrences instead makes each gap O(occurrences of the next
            // anchor), which is what keeps multi-wildcard body sigs fast.
            match tokens.get(token_index + 1) {
                Some(Token::Literal { off, len }) => {
                    let lit = &lits[*off as usize..(*off + *len) as usize];
                    let mut search_from = min_pos;
                    loop {
                        if search_from > max_pos || search_from + lit.len() > data.len() {
                            return None;
                        }
                        let Some(rel) = memchr::memmem::find(&data[search_from..], lit) else {
                            return None;
                        };
                        let candidate = search_from + rel;
                        if candidate > max_pos {
                            return None;
                        }
                        if let Some(end) = match_tokens(
                            tokens,
                            lits,
                            data,
                            token_index + 2,
                            candidate + lit.len(),
                            depth + 1,
                        ) {
                            return Some(end);
                        }
                        search_from = candidate + 1;
                    }
                }
                Some(Token::Byte(byte)) if byte.exact_value().is_some() => {
                    let target = byte.exact_value().unwrap();
                    let mut search_from = min_pos;
                    loop {
                        if search_from > max_pos || search_from >= data.len() {
                            return None;
                        }
                        let scan_end = (max_pos + 1).min(data.len());
                        let Some(rel) = memchr::memchr(target, &data[search_from..scan_end])
                        else {
                            return None;
                        };
                        let candidate = search_from + rel;
                        if let Some(end) = match_tokens(
                            tokens,
                            lits,
                            data,
                            token_index + 2,
                            candidate + 1,
                            depth + 1,
                        ) {
                            return Some(end);
                        }
                        search_from = candidate + 1;
                    }
                }
                _ => {
                    // Rare: next token is itself variable-width (boundary,
                    // alternation, another wildcard) — no single byte/literal
                    // to jump to, so fall back to per-position probing.
                    for next in min_pos..=max_pos {
                        if let Some(end) =
                            match_tokens(tokens, lits, data, token_index + 1, next, depth + 1)
                        {
                            return Some(end);
                        }
                    }
                    None
                }
            }
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

    /// Like `exact_value`, but also accepts `nocase` bytes (the byte still
    /// matches exactly one value modulo case at scan time; only the *prefilter
    /// atom* derived from it needs case-folding, via `longest_nocase_run`).
    fn exact_value_any_case(self) -> Option<u8> {
        if self.mask == 0xff {
            Some(self.value)
        } else {
            None
        }
    }

    /// The literal byte value(s) this matcher accepts, for anchoring a scan with
    /// `memchr`. Returns `(b, None)` for an exact byte, `(lower, Some(upper))`
    /// for a case-insensitive letter, or `None` when the matcher is masked
    /// (nibble wildcard `?`) and can't be reduced to one or two concrete bytes.
    fn anchor_bytes(self) -> Option<(u8, Option<u8>)> {
        if self.mask != 0xff {
            return None;
        }
        if self.nocase && self.value.is_ascii_alphabetic() {
            Some((
                self.value.to_ascii_lowercase(),
                Some(self.value.to_ascii_uppercase()),
            ))
        } else {
            Some((self.value, None))
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
                    tokens.push(Token::AnyBytes {
                        min: 0,
                        max: UNBOUNDED,
                    });
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
            max: max.map(|m| m as u32).unwrap_or(UNBOUNDED),
        })
    }

    fn parse_bracket_range(&mut self) -> Result<Token, String> {
        self.expect('[')?;
        let content = self.read_until(']')?;
        let (min, max) = parse_range_content(&content)?;
        Ok(Token::AnyBytes {
            min: min as u32,
            max: max.unwrap_or(min) as u32,
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
            Token::AnyBytes { min, max } if min == max && *max != UNBOUNDED => {
                width += *min as usize
            }
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

/// Longest run of ≥2 consecutive fixed bytes (mask=0xff, any case), folded to
/// lowercase, for use as a prefilter atom on `nocase` patterns. `nocase`
/// bytes never compact into `Token::Literal` (matching must stay
/// case-insensitive at scan time), so they survive as individual
/// `Token::Byte`s — this just scans those runs and case-folds them, entirely
/// separately from the exact-match `tokens`/`lits` used by `match_tokens`.
fn longest_nocase_run(tokens: &[Token]) -> Option<Vec<u8>> {
    let mut best: Vec<u8> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for token in tokens {
        let byte_value = match token {
            Token::Byte(byte) => byte.exact_value_any_case(),
            _ => None,
        };
        match byte_value {
            Some(value) => run.push(value.to_ascii_lowercase()),
            None => {
                if run.len() > best.len() {
                    best = std::mem::take(&mut run);
                } else {
                    run.clear();
                }
            }
        }
    }
    if run.len() > best.len() {
        best = run;
    }
    if best.len() >= 2 {
        Some(best)
    } else {
        None
    }
}

/// Choose the required-literal atom and, when possible, the fixed byte width of
/// the pattern tokens before it (its anchor offset).
///
/// We deliberately prefer the longest literal that has a **fixed-width prefix**
/// over a longer literal sitting behind a wildcard. A fixed prefix lets
/// `find_all` jump straight to each `memmem` occurrence and verify the whole
/// pattern at `occurrence - prefix` (ClamAV's anchored match), instead of
/// scanning every byte of the buffer. Only patterns whose every ≥2-byte literal
/// is preceded by a variable-width token (e.g. a leading `*`) fall back to the
/// per-byte scan; those are rare.
///
/// Returns `((off, len) into lits, prefix_width)`. `prefix_width` is `None` only
/// when no literal has a fixed-width prefix (then the caller still uses the
/// returned literal as a coarse `memmem` pre-check before the byte scan).
fn longest_required_literal(tokens: &[Token]) -> (Option<(u32, u32)>, Option<u32>) {
    // After compaction, each maximal exact run ≥ 2 bytes is a single `Literal`.
    let mut anchored: Option<(u32, u32, u32)> = None; // (off, len, prefix) — fixed prefix
    let mut longest_any: Option<(u32, u32)> = None; // longest ≥2 literal, any prefix
    let mut prefix_acc: Option<u32> = Some(0); // running fixed width from pattern start

    for token in tokens {
        if let Token::Literal { off, len } = token {
            if *len >= 2 {
                if longest_any.map_or(true, |(_, bl)| *len > bl) {
                    longest_any = Some((*off, *len));
                }
                if let Some(prefix) = prefix_acc {
                    if anchored.map_or(true, |(_, bl, _)| *len > bl) {
                        anchored = Some((*off, *len, prefix));
                    }
                }
            }
        }
        // Advance the running prefix width; becomes None on the first
        // variable-width token, disabling anchoring for later literals.
        prefix_acc = prefix_acc.and_then(|w| single_token_width(token).map(|tw| w + tw as u32));
    }

    match anchored {
        Some((off, len, prefix)) => (Some((off, len)), Some(prefix)),
        None => (longest_any, None),
    }
}

/// Fixed byte width a single token always consumes, or `None` if variable-width.
fn single_token_width(token: &Token) -> Option<usize> {
    match token {
        Token::Literal { len, .. } => Some(*len as usize),
        Token::Byte(_) | Token::Boundary(Boundary::NonAlphaNum) => Some(1),
        Token::Boundary(Boundary::Word) | Token::Boundary(Boundary::Newline) => Some(0),
        Token::AnyBytes { min, max } if min == max && *max != UNBOUNDED => Some(*min as usize),
        Token::Alternates(alt) if !alt.negated => {
            let widths = alt
                .branches
                .iter()
                .map(|branch| fixed_width(branch))
                .collect::<Option<Vec<_>>>()?;
            if widths.iter().all(|w| *w == widths[0]) {
                Some(widths[0])
            } else {
                None
            }
        }
        Token::Alternates(alt) if alt.negated_width.is_some() => alt.negated_width,
        _ => None,
    }
}

fn pos_in_ranges(pos: usize, ranges: &[(usize, usize)], data_len: usize) -> bool {
    ranges.iter().any(|&(start, end)| {
        let start = start.min(data_len);
        let end = end.min(data_len);
        pos >= start && pos <= end
    })
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
