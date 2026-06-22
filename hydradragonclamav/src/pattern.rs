/// Sentinel for an open-ended `AnyBytes` gap (`*` or `{n-}`), stored in
/// `Token::AnyBytes::max` so the field can be a plain `u32`.
/// Packed into 29 bits when stored in Token (bits 35-63). Same semantics as
/// `u32::MAX` but fits the 29-bit field_b slot.
const UNBOUNDED: u32 = 0x1FFF_FFFF;

/// Largest start-position window `find_all_at` will probe per literal occurrence
/// when the required literal sits behind bounded gaps (no fixed prefix). Keeps a
/// pathological `{-100000}` gap from turning offset-threading back into a buffer
/// scan; such a literal falls back to the normal `find_all` path instead.
const MAX_PREFIX_WINDOW: usize = 4096;

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

/// Sentinel for "no anchor prefix" stored in the `u32` prefix fields below, so
/// they don't pay an `Option` discriminant word. Real prefixes are tiny, so
/// `u32::MAX` can never collide with a genuine value.
const NO_PREFIX: u32 = u32::MAX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pattern {
    /// Packed tokens (u64 each — 8 bytes instead of 16).
    tokens: Box<[Token]>,
    lits: Box<[u8]>,
    /// Alternation branches indexed by `Token::TAG_ALTERNATES` data. `Box<[_]>`,
    /// not `Vec`, to drop the capacity word on every pattern (empty for the vast
    /// majority, which have no alternation).
    alternates: Box<[Alternates]>,
    /// Fixed prefix widths, `NO_PREFIX` when absent — plain `u32` instead of
    /// `Option<u32>` so each costs 4 bytes, not 8. Read via `required_prefix()` /
    /// `required_prefix_nocase()`.
    required_prefix: u32,
    required_prefix_nocase: u32,
    required_literal: Option<(u32, u32)>,
    fullword: bool,
}

/// Packed into 8 bytes (u64) — half the 16-byte enum, saving ~720MB across
/// ~90M tokens in a full ClamAV database.
/// Layout: bits 0-2 = tag, bits 3-34 = field_a (u32), bits 35-63 = field_b (u32 masked 29b).
#[derive(Clone, Copy, Eq, PartialEq)]
struct Token(u64);

impl Token {
    const TAG_BYTE: u64 = 0;
    const TAG_LITERAL: u64 = 1;
    const TAG_LITNOCASE: u64 = 2;
    const TAG_ANYBYTES: u64 = 3;
    const TAG_BOUNDARY: u64 = 4;
    const TAG_ALTERNATES: u64 = 5;

    fn tag(self) -> u64 { self.0 & 0x7 }
    fn a(self) -> u32 { (self.0 >> 3) as u32 }
    fn b(self) -> u32 { (self.0 >> 35) as u32 }

    fn byte(mask: u8, value: u8, nocase: bool) -> Self {
        let data = (mask as u64) | ((value as u64) << 8) | ((nocase as u64) << 16);
        Token((data << 3) | Self::TAG_BYTE)
    }
    fn as_byte(self) -> Option<(u8, u8, bool)> {
        (self.tag() == Self::TAG_BYTE).then(|| {
            let d = self.a();
            (d as u8, (d >> 8) as u8, (d >> 16) != 0)
        })
    }

    fn literal(off: u32, len: u32) -> Self {
        Token((off as u64) << 3 | (len as u64) << 35 | Self::TAG_LITERAL)
    }
    fn as_literal(self) -> Option<(u32, u32)> {
        (self.tag() == Self::TAG_LITERAL).then(|| (self.a(), self.b()))
    }

    fn litnocase(off: u32, len: u32) -> Self {
        Token((off as u64) << 3 | (len as u64) << 35 | Self::TAG_LITNOCASE)
    }
    fn as_litnocase(self) -> Option<(u32, u32)> {
        (self.tag() == Self::TAG_LITNOCASE).then(|| (self.a(), self.b()))
    }

    fn any_bytes(min: u32, max: u32) -> Self {
        Token((min as u64) << 3 | (max as u64) << 35 | Self::TAG_ANYBYTES)
    }
    fn as_any_bytes(self) -> Option<(u32, u32)> {
        (self.tag() == Self::TAG_ANYBYTES).then(|| (self.a(), self.b()))
    }

    fn boundary(kind: Boundary) -> Self {
        Token((kind as u64) << 3 | Self::TAG_BOUNDARY)
    }
    fn as_boundary(self) -> Option<Boundary> {
        (self.tag() == Self::TAG_BOUNDARY).then(|| match self.a() {
            0 => Boundary::Word,
            1 => Boundary::Newline,
            _ => Boundary::NonAlphaNum,
        })
    }

    fn alternates(idx: u32) -> Self {
        Token((idx as u64) << 3 | Self::TAG_ALTERNATES)
    }
    fn as_alternates(self) -> Option<u32> {
        (self.tag() == Self::TAG_ALTERNATES).then(|| self.a())
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.tag() {
            Self::TAG_BYTE => {
                let (m, v, n) = self.as_byte().unwrap();
                write!(f, "Byte({:#04x}, {:#04x}, nocase={n})", m, v)
            }
            Self::TAG_LITERAL => {
                let (off, len) = self.as_literal().unwrap();
                write!(f, "Literal {{ off: {off}, len: {len} }}")
            }
            Self::TAG_LITNOCASE => {
                let (off, len) = self.as_litnocase().unwrap();
                write!(f, "LitNocase {{ off: {off}, len: {len} }}")
            }
            Self::TAG_ANYBYTES => {
                let (min, max) = self.as_any_bytes().unwrap();
                write!(f, "AnyBytes {{ min: {min}, max: {max} }}")
            }
            Self::TAG_BOUNDARY => {
                let b = self.as_boundary().unwrap();
                write!(f, "Boundary({b:?})")
            }
            Self::TAG_ALTERNATES => {
                let idx = self.as_alternates().unwrap();
                write!(f, "Alternates({idx})")
            }
            _ => write!(f, "Token({:#018x})", self.0),
        }
    }
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

/// Aggregated pattern memory, for `--mem-stats` profiling.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemStats {
    pub patterns: usize,
    pub token_bytes: usize,
    pub lit_bytes: usize,
    pub struct_bytes: usize,
    pub n_byte: usize,
    pub n_literal: usize,
    pub n_litnocase: usize,
    pub n_anybytes: usize,
    pub n_boundary: usize,
    pub n_alternates: usize,
}

impl MemStats {
    pub fn add(&mut self, o: &MemStats) {
        self.patterns += o.patterns;
        self.token_bytes += o.token_bytes;
        self.lit_bytes += o.lit_bytes;
        self.struct_bytes += o.struct_bytes;
        self.n_byte += o.n_byte;
        self.n_literal += o.n_literal;
        self.n_litnocase += o.n_litnocase;
        self.n_anybytes += o.n_anybytes;
        self.n_boundary += o.n_boundary;
        self.n_alternates += o.n_alternates;
    }
    pub fn total_bytes(&self) -> usize {
        self.token_bytes + self.lit_bytes + self.struct_bytes
    }
    pub fn tokens(&self) -> usize {
        self.n_byte + self.n_literal + self.n_litnocase + self.n_anybytes + self.n_boundary + self.n_alternates
    }
}

fn tally_tokens(tokens: &[Token], s: &mut MemStats) {
    for t in tokens {
        match t.tag() {
            Token::TAG_BYTE => s.n_byte += 1,
            Token::TAG_LITERAL => s.n_literal += 1,
            Token::TAG_LITNOCASE => s.n_litnocase += 1,
            Token::TAG_ANYBYTES => s.n_anybytes += 1,
            Token::TAG_BOUNDARY => s.n_boundary += 1,
            Token::TAG_ALTERNATES => s.n_alternates += 1,
            _ => {}
        }
    }
}

pub fn compile_pattern_variants(raw: &str, modifiers: Modifiers) -> Result<Vec<Pattern>, String> {
    let mut parser = Parser::new(raw, modifiers.nocase);
    let (tokens, alternates) = parser.parse_all()?;
    let mut variants = Vec::new();

    if !modifiers.wide || modifiers.ascii {
        variants.push(Pattern::new(tokens.clone(), alternates.clone(), modifiers.fullword));
    }

    if modifiers.wide {
        let (wide_tokens, wide_alts) = to_wide_tokens(&tokens, &alternates);
        variants.push(Pattern::new(wide_tokens, wide_alts, modifiers.fullword));
    }

    Ok(variants)
}

impl Pattern {
    fn new(tokens: Vec<Token>, mut alternates: Vec<Alternates>, fullword: bool) -> Self {
        let (tokens, lits) = compact_tokens(tokens);
        // Shrink alternates branch Vecs (parser grows them geometrically; each
        // branch is tiny and the slack is per-branch Vec overhead × branches ×
        // alternates × signatures).
        for alt in &mut alternates {
            for branch in &mut alt.branches {
                branch.shrink_to_fit();
            }
        }
        alternates.shrink_to_fit();
        let (required_literal, required_prefix) = best_required_literal(&tokens, &lits, &alternates);
        let required_prefix_nocase = if required_literal.is_none() {
            nocase_anchor(&tokens, &lits, &alternates).and_then(|(_, prefix)| prefix)
        } else {
            None
        };
        Self {
            tokens: tokens.into_boxed_slice(),
            lits: lits.into_boxed_slice(),
            alternates: alternates.into_boxed_slice(),
            required_prefix: required_prefix.unwrap_or(NO_PREFIX),
            required_prefix_nocase: required_prefix_nocase.unwrap_or(NO_PREFIX),
            required_literal,
            fullword,
        }
    }

    #[inline]
    fn required_prefix(&self) -> Option<u32> {
        (self.required_prefix != NO_PREFIX).then_some(self.required_prefix)
    }

    #[inline]
    fn required_prefix_nocase(&self) -> Option<u32> {
        (self.required_prefix_nocase != NO_PREFIX).then_some(self.required_prefix_nocase)
    }

    pub fn is_match(&self, data: &[u8]) -> bool {
        !self.find_all(data, &[(0, data.len())], 1).is_empty()
    }

    /// Resident heap bytes owned by this pattern, and a per-tag token tally, for
    /// memory profiling (`--mem-stats`). Counts the boxed token/lits arenas, the
    /// alternates Vec and its (uncompacted) branch tokens, recursively.
    pub fn mem_stats(&self) -> MemStats {
        let mut s = MemStats::default();
        s.patterns = 1;
        s.token_bytes += self.tokens.len() * std::mem::size_of::<Token>();
        s.lit_bytes += self.lits.len();
        s.struct_bytes += std::mem::size_of::<Pattern>();
        tally_tokens(&self.tokens, &mut s);
        for alt in &self.alternates {
            s.struct_bytes += std::mem::size_of::<Alternates>();
            for branch in &alt.branches {
                s.struct_bytes += std::mem::size_of::<Vec<Token>>();
                s.token_bytes += branch.len() * std::mem::size_of::<Token>();
                tally_tokens(branch, &mut s);
            }
        }
        s
    }

    /// The pattern's longest required literal substring (case-sensitive, exact
    /// bytes), if any. The pattern cannot match unless this appears in the data,
    /// so it's usable as an Aho-Corasick prefilter atom. `None` when the pattern
    /// has no usable literal (e.g. fully wildcard or nocase).
    pub fn required_atom(&self) -> Option<&[u8]> {
        self.required_literal
            .map(|(off, len)| &self.lits[off as usize..(off + len) as usize])
    }

    /// A case-folded (lowercased) required atom for `nocase` patterns, usable as a
    /// prefilter hint against a lowercased copy of the scanned buffer. Computed
    /// on demand (only ever called once, at prefilter build time) so the bytes
    /// cost no resident memory. `None` for patterns that have a case-sensitive
    /// `required_atom`, or no run of ≥2 fixed bytes (e.g. fully wildcard).
    pub fn required_atom_nocase(&self) -> Option<Vec<u8>> {
        if self.required_literal.is_some() {
            return None; // case-sensitive: use required_atom() instead
        }
        nocase_anchor(&self.tokens, &self.lits, &self.alternates).map(|(atom, _)| atom)
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

        // ClamAV-style anchored verification (matcher-ac.c `bp = i + 1 - depth`):
        // when the required literal has a fixed-width prefix, jump to each
        // occurrence of the literal and only try matching the whole pattern at
        // `occurrence - prefix`.
        if let (Some((off, len)), Some(prefix)) = (self.required_literal, self.required_prefix()) {
            let required = &self.lits[off as usize..(off + len) as usize];
            let prefix = prefix as usize;
            let mut from = 0usize;
            while from + required.len() <= data.len() {
                let Some(rel) = memchr::memmem::find(&data[from..], required) else {
                    break;
                };
                let occurrence = from + rel;
                from = occurrence + 1;
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
                    out.push(MatchRange { start, end: match_end });
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
            return out;
        }

        let unbounded_leading_wildcard = self
            .tokens
            .first()
            .is_some_and(|t| t.as_any_bytes().is_some_and(|(min, max)| min == 0 && max == UNBOUNDED));

        let first_byte_anchor = match self.tokens.first() {
            Some(t) if t.tag() == Token::TAG_BYTE => {
                let (mask, value, nocase) = t.as_byte().unwrap();
                let bm = ByteMatcher { mask, value, nocase };
                bm.anchor_bytes()
            }
            Some(t) if t.tag() == Token::TAG_LITNOCASE => {
                let (off, _) = t.as_litnocase().unwrap();
                let b = self.lits[off as usize];
                if b.is_ascii_alphabetic() {
                    Some((b.to_ascii_lowercase(), Some(b.to_ascii_uppercase())))
                } else {
                    Some((b, None))
                }
            }
            _ => None,
        };

        for &(start, end) in ranges {
            let start = start.min(data.len());
            let end = end.min(data.len());
            if start > end {
                continue;
            }

            if let Some((b1, b2)) = first_byte_anchor {
                let hay_end = (end + 1).min(data.len());
                let hay = &data[start..hay_end];
                let try_pos = |pos: usize, out: &mut Vec<MatchRange>| -> bool {
                    if let Some(match_end) = self.match_from(data, pos) {
                        if self.fullword && !is_fullword(data, pos, match_end) {
                            return false;
                        }
                        let c = (pos, match_end);
                        if out.last().map(|m| (m.start, m.end)) != Some(c) {
                            out.push(MatchRange { start: pos, end: match_end });
                            return out.len() >= limit;
                        }
                    }
                    false
                };
                match b2 {
                    Some(b2) => {
                        for rel in memchr::memchr2_iter(b1, b2, hay) {
                            if try_pos(start + rel, &mut out) {
                                return out;
                            }
                        }
                    }
                    None => {
                        for rel in memchr::memchr_iter(b1, hay) {
                            if try_pos(start + rel, &mut out) {
                                return out;
                            }
                        }
                    }
                }
                continue;
            }

            for pos in start..=end {
                match self.match_from(data, pos) {
                    Some(match_end) => {
                        if self.fullword && !is_fullword(data, pos, match_end) {
                            continue;
                        }
                        let c = (pos, match_end);
                        if out.last().map(|m| (m.start, m.end)) != Some(c) {
                            out.push(MatchRange { start: pos, end: match_end });
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
        let Some((off, len)) = self.required_literal else {
            // No case-sensitive anchor. A `nocase` pattern can still be threaded
            // on its case-folded atom (hints are positions in the lowercased
            // buffer, which share coordinates with the original).
            if let Some(prefix_nocase) = self.required_prefix_nocase() {
                return self.find_all_at_nocase(data, ranges, limit, hints, prefix_nocase as usize);
            }
            return self.find_all(data, ranges, limit);
        };
        // The match start lies in a window relative to the literal occurrence.
        // Fixed prefix → a single position (`occurrence - prefix`). Otherwise the
        // preceding tokens may be bounded gaps (e.g. `(a|b)…{-50}LIT` — extremely
        // common in phishing/spam sigs): try the SMALL window
        // `[occurrence - maxprefix, occurrence - minprefix]` rather than scanning
        // the whole buffer. Only when a preceding token is genuinely unbounded
        // (leading `*`) or the window would be huge do we fall back to a full scan.
        let (minp, maxp) = match self.required_prefix() {
            Some(p) => (p as usize, p as usize),
            None => match self.prefix_bounds_to(off) {
                Some((mn, mx)) if (mx as usize) <= MAX_PREFIX_WINDOW => (mn as usize, mx as usize),
                _ => return self.find_all(data, ranges, limit),
            },
        };
        let required = &self.lits[off as usize..(off + len) as usize];
        let required_len = required.len();

        let mut out = Vec::new();
        let mut last_start = None;
        for &hint in hints {
            let occurrence = hint as usize;
            let Some(lit_end) = occurrence.checked_add(required_len) else {
                continue;
            };
            if lit_end > data.len() || &data[occurrence..lit_end] != required {
                continue;
            }
            let start_hi = occurrence.saturating_sub(minp);
            let start_lo = occurrence.saturating_sub(maxp);
            for start in start_lo..=start_hi {
                if !pos_in_ranges(start, ranges, data.len()) {
                    continue;
                }
                if last_start == Some(start) {
                    continue;
                }
                last_start = Some(start);
                if let Some(match_end) = self.match_from(data, start) {
                    if self.fullword && !is_fullword(data, start, match_end) {
                        continue;
                    }
                    out.push(MatchRange { start, end: match_end });
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }

    fn find_all_at_nocase(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
        hints: &[u32],
        prefix: usize,
    ) -> Vec<MatchRange> {
        let mut out = Vec::new();
        let mut last_start = None;
        for &hint in hints {
            let occurrence = hint as usize;
            let Some(start) = occurrence.checked_sub(prefix) else {
                continue;
            };
            if !pos_in_ranges(start, ranges, data.len()) {
                continue;
            }
            if last_start == Some(start) {
                continue;
            }
            last_start = Some(start);
            if let Some(match_end) = self.match_from(data, start) {
                if self.fullword && !is_fullword(data, start, match_end) {
                    continue;
                }
                out.push(MatchRange { start, end: match_end });
                if out.len() >= limit {
                    return out;
                }
            }
        }
        out
    }

    fn match_from(&self, data: &[u8], start: usize) -> Option<usize> {
        match_tokens(&self.tokens, &self.lits, data, 0, start, 0, &self.alternates)
    }

    /// The `(min, max)` total byte width of the tokens before the `Literal` at
    /// `target_off`, or `None` if any preceding token is unbounded (a leading
    /// `*` / `{n-}`). Used by `find_all_at` to anchor a literal that sits behind
    /// bounded gaps: the match start is then in `[occurrence-max, occurrence-min]`.
    fn prefix_bounds_to(&self, target_off: u32) -> Option<(u32, u32)> {
        let mut min = 0u32;
        let mut max = 0u32;
        for &token in self.tokens.iter() {
            if token.tag() == Token::TAG_LITERAL && token.as_literal().unwrap().0 == target_off {
                return Some((min, max));
            }
            let (tmin, tmax) = token_width_bounds(token, &self.alternates)?;
            min = min.saturating_add(tmin);
            max = max.saturating_add(tmax);
        }
        None
    }
}

/// `(min, max)` byte width a single token can consume, or `None` if unbounded.
fn token_width_bounds(token: Token, alternates: &[Alternates]) -> Option<(u32, u32)> {
    match token.tag() {
        Token::TAG_LITERAL | Token::TAG_LITNOCASE => Some((token.b(), token.b())),
        Token::TAG_BYTE => Some((1, 1)),
        Token::TAG_BOUNDARY => match token.as_boundary().unwrap() {
            Boundary::NonAlphaNum => Some((1, 1)),
            Boundary::Word | Boundary::Newline => Some((0, 0)),
        },
        Token::TAG_ANYBYTES => {
            let (min, max) = token.as_any_bytes().unwrap();
            if max == UNBOUNDED { None } else { Some((min, max)) }
        }
        Token::TAG_ALTERNATES => {
            let idx = token.as_alternates().unwrap() as usize;
            let alt = &alternates[idx];
            if !alt.negated {
                let mut lo = u32::MAX;
                let mut hi = 0u32;
                for branch in &alt.branches {
                    let w = fixed_width(branch, alternates)? as u32;
                    lo = lo.min(w);
                    hi = hi.max(w);
                }
                Some((lo, hi))
            } else if let Some(w) = alt.negated_width {
                Some((w as u32, w as u32))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// True when the token at `idx` ends the pattern or is an unbounded gap (`*` /
/// `{n-}`). In that case a literal matched just before it can be taken greedily
/// (leftmost): nothing downstream constrains *where* that literal must sit, so a
/// failed continuation can never be rescued by a later occurrence. Used to switch
/// off backtracking in the wildcard fast paths (see `match_tokens`).
fn open_ended_after(tokens: &[Token], idx: usize) -> bool {
    tokens.get(idx).map_or(true, |t| {
        t.as_any_bytes().is_some_and(|(_, max)| max == UNBOUNDED)
    })
}

fn match_tokens(
    tokens: &[Token],
    lits: &[u8],
    data: &[u8],
    token_index: usize,
    pos: usize,
    depth: usize,
    alternates: &[Alternates],
) -> Option<usize> {
    if depth > 2048 {
        return None;
    }
    let mut token_index = token_index;
    let mut pos = pos;
    loop {
        if token_index == tokens.len() {
            return Some(pos);
        }

        let tok = tokens[token_index];
        let tag = tok.tag();

        if tag == Token::TAG_BYTE {
            let (mask, value, nocase) = tok.as_byte().unwrap();
            if pos < data.len() {
                let bm = ByteMatcher { mask, value, nocase };
                if bm.matches(data[pos]) {
                    token_index += 1;
                    pos += 1;
                    continue;
                }
            }
            return None;
        }

        if tag == Token::TAG_LITERAL {
            let (off, len) = tok.as_literal().unwrap();
            let lit = &lits[off as usize..(off + len) as usize];
            let end = pos + lit.len();
            if end <= data.len() && &data[pos..end] == lit {
                token_index += 1;
                pos = end;
                continue;
            }
            return None;
        }

        if tag == Token::TAG_LITNOCASE {
            let (off, len) = tok.as_litnocase().unwrap();
            let lit = &lits[off as usize..(off + len) as usize];
            let end = pos + lit.len();
            if end <= data.len()
                && data[pos..end]
                    .iter()
                    .zip(lit)
                    .all(|(d, l)| d.to_ascii_lowercase() == *l)
            {
                token_index += 1;
                pos = end;
                continue;
            }
            return None;
        }

        if tag == Token::TAG_ANYBYTES {
            let (min, max) = tok.as_any_bytes().unwrap();
            let min_pos = pos.checked_add(min as usize)?;
            if min_pos > data.len() {
                return None;
            }
            let max_len = if max == UNBOUNDED {
                data.len().saturating_sub(pos)
            } else {
                max as usize
            };
            let max_pos = pos.saturating_add(max_len).min(data.len());
            if min_pos > max_pos {
                return None;
            }

            let next_tok = tokens.get(token_index + 1);

            // Fast path: literal after wildcard
            if let Some(nt) = next_tok {
                if nt.tag() == Token::TAG_LITERAL {
                    let (n_off, n_len) = nt.as_literal().unwrap();
                    let lit = &lits[n_off as usize..(n_off + n_len) as usize];
                    let greedy = open_ended_after(tokens, token_index + 2);
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
                            tokens, lits, data, token_index + 2, candidate + lit.len(), depth, alternates,
                        ) {
                            return Some(end);
                        }
                        if greedy {
                            return None;
                        }
                        search_from = candidate + 1;
                    }
                }

                // LitNocase after wildcard
                if nt.tag() == Token::TAG_LITNOCASE {
                    let (n_off, n_len) = nt.as_litnocase().unwrap();
                    let lit = &lits[n_off as usize..(n_off + n_len) as usize];
                    let first = lit[0];
                    let (b1, b2) = if first.is_ascii_alphabetic() {
                        (first, Some(first.to_ascii_uppercase()))
                    } else {
                        (first, None)
                    };
                    let greedy = open_ended_after(tokens, token_index + 2);
                    let mut search_from = min_pos;
                    loop {
                        if search_from > max_pos || search_from + lit.len() > data.len() {
                            return None;
                        }
                        let scan_end = (max_pos + 1).min(data.len());
                        if search_from >= scan_end {
                            return None;
                        }
                        let hay = &data[search_from..scan_end];
                        let rel = match b2 {
                            Some(b2) => memchr::memchr2(b1, b2, hay),
                            None => memchr::memchr(b1, hay),
                        };
                        let Some(rel) = rel else { return None };
                        let candidate = search_from + rel;
                        let cend = candidate + lit.len();
                        if cend <= data.len()
                            && data[candidate..cend]
                                .iter()
                                .zip(lit)
                                .all(|(d, l)| d.to_ascii_lowercase() == *l)
                        {
                            if let Some(e) = match_tokens(
                                tokens, lits, data, token_index + 2, cend, depth, alternates,
                            ) {
                                return Some(e);
                            }
                            if greedy { return None; }
                        }
                        search_from = candidate + 1;
                    }
                }

                // Byte after wildcard (with anchor)
                if nt.tag() == Token::TAG_BYTE {
                    let (nmask, nval, nnocase) = nt.as_byte().unwrap();
                    let bm = ByteMatcher { mask: nmask, value: nval, nocase: nnocase };
                    if let Some((b1, b2)) = bm.anchor_bytes() {
                        let greedy = open_ended_after(tokens, token_index + 2);
                        let mut search_from = min_pos;
                        loop {
                            if search_from > max_pos || search_from >= data.len() {
                                return None;
                            }
                            let scan_end = (max_pos + 1).min(data.len());
                            let hay = &data[search_from..scan_end];
                            let rel = match b2 {
                                Some(b2) => memchr::memchr2(b1, b2, hay),
                                None => memchr::memchr(b1, hay),
                            };
                            let Some(rel) = rel else { return None };
                            let candidate = search_from + rel;
                            if let Some(end) = match_tokens(
                                tokens, lits, data, token_index + 2, candidate + 1, depth, alternates,
                            ) {
                                return Some(end);
                            }
                            if greedy { return None; }
                            search_from = candidate + 1;
                        }
                    }
                }
            }

            // Fallback per-position probe
            for next in min_pos..=max_pos {
                if let Some(end) = match_tokens(
                    tokens, lits, data, token_index + 1, next, depth, alternates,
                ) {
                    return Some(end);
                }
            }
            return None;
        }

        if tag == Token::TAG_BOUNDARY {
            match tok.as_boundary().unwrap() {
                Boundary::Word => {
                    if is_word_boundary(data, pos) {
                        token_index += 1;
                        continue;
                    }
                    return None;
                }
                Boundary::Newline => {
                    if pos == 0 || pos == data.len()
                        || data.get(pos.wrapping_sub(1)) == Some(&b'\r')
                        || data.get(pos.wrapping_sub(1)) == Some(&b'\n')
                    {
                        token_index += 1;
                        continue;
                    }
                    return None;
                }
                Boundary::NonAlphaNum => {
                    if pos < data.len() && !data[pos].is_ascii_alphanumeric() {
                        token_index += 1;
                        pos += 1;
                        continue;
                    }
                    return None;
                }
            }
        }

        if tag == Token::TAG_ALTERNATES {
            let idx = tok.as_alternates().unwrap() as usize;
            let alt = &alternates[idx];
            if alt.negated {
                let width = alt.negated_width?;
                if pos + width > data.len() {
                    return None;
                }
                let matched = alt.branches.iter().any(|branch| {
                    match_tokens(branch, &[], data, 0, pos, depth + 1, &[]) == Some(pos + width)
                });
                if !matched {
                    return match_tokens(tokens, lits, data, token_index + 1, pos + width, depth, alternates);
                }
                return None;
            }
            for branch in &alt.branches {
                if let Some(branch_end) = match_tokens(branch, &[], data, 0, pos, depth + 1, &[]) {
                    if let Some(end) = match_tokens(tokens, lits, data, token_index + 1, branch_end, depth, alternates) {
                        return Some(end);
                    }
                }
            }
            return None;
        }

        return None;
    }
}

impl ByteMatcher {
    fn matches(self, byte: u8) -> bool {
        if self.mask == 0xff && self.nocase && self.value.is_ascii_alphabetic() {
            byte.to_ascii_lowercase() == self.value.to_ascii_lowercase()
        } else {
            (byte & self.mask) == self.value
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
    alternates: Vec<Alternates>,
}

impl<'a> Parser<'a> {
    fn new(raw: &'a str, nocase: bool) -> Self {
        Self {
            chars: raw.chars().collect(),
            pos: 0,
            nocase,
            raw,
            alternates: Vec::new(),
        }
    }

    fn parse_all(&mut self) -> Result<(Vec<Token>, Vec<Alternates>), String> {
        let tokens = self.parse_sequence(false)?;
        if self.pos != self.chars.len() {
            return Err(format!(
                "unexpected character '{}' in pattern",
                self.chars[self.pos]
            ));
        }
        Ok((tokens, std::mem::take(&mut self.alternates)))
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
                    tokens.push(Token::any_bytes(0, UNBOUNDED));
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
            return Ok(Token::boundary(Boundary::Word));
        }
        if self.peek(1) == Some('L') && self.peek(2) == Some(')') {
            self.pos += 3;
            return Ok(Token::boundary(Boundary::Newline));
        }
        if self.peek(1) == Some('W') && self.peek(2) == Some(')') {
            self.pos += 3;
            return Ok(Token::boundary(Boundary::NonAlphaNum));
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
                .map(|branch| fixed_width(branch, &self.alternates))
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

        let idx = self.alternates.len() as u32;
        self.alternates.push(Alternates { branches, negated, negated_width });
        Ok(Token::alternates(idx))
    }

    fn parse_braced_range(&mut self) -> Result<Token, String> {
        self.expect('{')?;
        let content = self.read_until('}')?;
        let (min, max) = parse_range_content(&content)?;
        Ok(Token::any_bytes(min as u32, max.map(|m| m as u32).unwrap_or(UNBOUNDED)))
    }

    fn parse_bracket_range(&mut self) -> Result<Token, String> {
        self.expect('[')?;
        let content = self.read_until(']')?;
        let (min, max) = parse_range_content(&content)?;
        Ok(Token::any_bytes(min as u32, max.unwrap_or(min) as u32))
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
        let (mask, value, nocase) = match (high, low) {
            ('?', '?') => (0x00, 0x00, false),
            ('?', lo) => (0x0f, hex_value(lo)?, false),
            (hi, '?') => (0xf0, hex_value(hi)? << 4, false),
            (hi, lo) => {
                let v = (hex_value(hi)? << 4) | hex_value(lo)?;
                (0xff, v, self.nocase)
            }
        };
        Ok(Token::byte(mask, value, nocase))
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

fn fixed_width(tokens: &[Token], alternates: &[Alternates]) -> Option<usize> {
    let mut width = 0usize;
    for &token in tokens {
        let tag = token.tag();
        if tag == Token::TAG_LITERAL || tag == Token::TAG_LITNOCASE {
            let (_, len) = if tag == Token::TAG_LITERAL {
                token.as_literal().unwrap()
            } else {
                token.as_litnocase().unwrap()
            };
            width += len as usize;
        } else if tag == Token::TAG_BYTE || (tag == Token::TAG_BOUNDARY && token.as_boundary().unwrap() == Boundary::NonAlphaNum) {
            width += 1;
        } else if tag == Token::TAG_BOUNDARY {
            // Word or Newline — zero width
        } else if tag == Token::TAG_ANYBYTES {
            let (min, max) = token.as_any_bytes().unwrap();
            if min == max && max != UNBOUNDED {
                width += min as usize;
            } else {
                return None;
            }
        } else if tag == Token::TAG_ALTERNATES {
            let idx = token.as_alternates().unwrap() as usize;
            let alt = &alternates[idx];
            if !alt.negated {
                let branch_widths = alt
                    .branches
                    .iter()
                    .map(|branch| fixed_width(branch, alternates))
                    .collect::<Option<Vec<_>>>()?;
                if branch_widths.iter().all(|item| *item == branch_widths[0]) {
                    width += branch_widths[0];
                } else {
                    return None;
                }
            } else if alt.negated_width.is_some() {
                width += alt.negated_width.unwrap();
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(width)
}

fn to_wide_tokens(
    tokens: &[Token],
    alternates: &[Alternates],
) -> (Vec<Token>, Vec<Alternates>) {
    let mut out = Vec::new();
    let mut alt_out = Vec::new();
    for &token in tokens {
        let tag = token.tag();
        if tag == Token::TAG_BYTE {
            out.push(token);
            out.push(Token::byte(0xff, 0x00, false));
        } else if tag == Token::TAG_ALTERNATES {
            let idx = token.as_alternates().unwrap() as usize;
            let alt = &alternates[idx];
            let branches = alt
                .branches
                .iter()
                .map(|branch| to_wide_tokens(branch, alternates).0)
                .collect::<Vec<_>>();
            let negated_width = if alt.negated {
                branches.first().and_then(|branch| fixed_width(branch, &[]))
            } else {
                alt.negated_width
            };
            let new_idx = alt_out.len() as u32;
            alt_out.push(Alternates {
                branches,
                negated: alt.negated,
                negated_width,
            });
            out.push(Token::alternates(new_idx));
        } else {
            // Boundary, AnyBytes — none contain sub-tokens needing widening.
            // Also catches the invariant: to_wide_tokens runs before compact_tokens
            // so we must never see Literal/LitNocase here.
            debug_assert!(
                tag != Token::TAG_LITERAL && tag != Token::TAG_LITNOCASE,
                "to_wide_tokens received a compacted token"
            );
            out.push(token);
        }
    }
    (out, alt_out)
}

/// Merge runs of consecutive exact, case-sensitive bytes into a single
/// `Token::Literal` referencing a shared `lits` arena, instead of one ~16-byte
/// `Token::Byte` per byte. Runs of length 1 stay `Token::Byte` (a `Literal`
/// would only add 8 bytes for no gain). Alternation branches are left as-is.
///
/// Also collapses gaps: a full-wildcard `??` parses to `Token::byte(0,0)`, i.e.
/// one 8-byte token *per wildcard byte* (`Byte(0x00,0x00)` matches every byte —
/// `(b & 0) == 0` — so it is exactly an `AnyBytes` of width 1). A run of `N`
/// such bytes, or several adjacent explicit `{m}`/`*` gaps, are folded into a
/// single `AnyBytes{min,max}`. This is the semantic identity of `????…` and
/// `{N}`; without it a long `??` run cost one token each (the 3000-`?` test
/// alone would resident 24 KB for one gap). Widths are additive and unchanged,
/// so prefix/anchor accounting (`single_token_width`) is preserved exactly.
fn compact_tokens(tokens: Vec<Token>) -> (Vec<Token>, Vec<u8>) {
    let mut out: Vec<Token> = Vec::with_capacity(tokens.len());
    let mut lits: Vec<u8> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut run_nocase = false;
    // Pending coalesced gap `(min, max)` from consecutive `??`/`AnyBytes` tokens.
    let mut gap: Option<(u32, u32)> = None;
    for token in tokens {
        if token.tag() == Token::TAG_BYTE {
            let (mask, value, nocase) = token.as_byte().unwrap();
            if mask == 0xff && !nocase {
                flush_gap(&mut gap, &mut out);
                if !run.is_empty() && run_nocase {
                    flush_run(&mut run, run_nocase, &mut lits, &mut out);
                }
                run_nocase = false;
                run.push(value);
                continue;
            }
            if mask == 0xff && nocase {
                flush_gap(&mut gap, &mut out);
                if !run.is_empty() && !run_nocase {
                    flush_run(&mut run, run_nocase, &mut lits, &mut out);
                }
                run_nocase = true;
                run.push(value.to_ascii_lowercase());
                continue;
            }
            if mask == 0x00 {
                // `??` — full-byte wildcard, identical to a 1-wide `AnyBytes`.
                flush_run(&mut run, run_nocase, &mut lits, &mut out);
                add_gap(&mut gap, 1, 1);
                continue;
            }
        }
        if let Some((min, max)) = token.as_any_bytes() {
            flush_run(&mut run, run_nocase, &mut lits, &mut out);
            add_gap(&mut gap, min, max);
            continue;
        }
        flush_run(&mut run, run_nocase, &mut lits, &mut out);
        flush_gap(&mut gap, &mut out);
        out.push(token);
    }
    flush_run(&mut run, run_nocase, &mut lits, &mut out);
    flush_gap(&mut gap, &mut out);
    out.shrink_to_fit();
    (out, lits)
}

/// Accumulate one more gap onto the pending coalesced gap. Widths add; an
/// `UNBOUNDED` max stays unbounded (consecutive variable gaps compose).
fn add_gap(gap: &mut Option<(u32, u32)>, min: u32, max: u32) {
    *gap = Some(match *gap {
        None => (min, max),
        Some((pmin, pmax)) => {
            let nmax = if pmax == UNBOUNDED || max == UNBOUNDED {
                UNBOUNDED
            } else {
                pmax.saturating_add(max)
            };
            (pmin.saturating_add(min), nmax)
        }
    });
}

fn flush_gap(gap: &mut Option<(u32, u32)>, out: &mut Vec<Token>) {
    if let Some((min, max)) = gap.take() {
        out.push(Token::any_bytes(min, max));
    }
}

fn flush_run(run: &mut Vec<u8>, nocase: bool, lits: &mut Vec<u8>, out: &mut Vec<Token>) {
    match run.len() {
        0 => {}
        1 => {
            out.push(Token::byte(0xff, run[0], nocase));
            run.clear();
        }
        n => {
            let off = lits.len() as u32;
            lits.extend_from_slice(run);
            let token = if nocase {
                Token::litnocase(off, n as u32)
            } else {
                Token::literal(off, n as u32)
            };
            out.push(token);
            run.clear();
        }
    }
}

/// The longest run of ≥2 consecutive fixed bytes (mask=0xff, any case), folded
/// to lowercase, plus the fixed byte width *before* that run (its anchor offset),
/// for use as a prefilter atom + threading anchor on `nocase` patterns.
///
/// `nocase` bytes never compact into `Token::Literal` (matching must stay
/// case-insensitive at scan time), so they survive as individual `Token::Byte`s —
/// this scans those runs, case-folds them, and tracks how many fixed bytes
/// precede the chosen run. The prefix is `Some(w)` only when every token before
/// the run is fixed-width (so `find_all_at` can anchor at `offset - w`); `None`
/// when something variable-width precedes it (then we fall back to a full scan).
/// Returns `None` when there is no `LitNocase` run of ≥2 bytes (e.g. fully
/// wildcard). `nocase` exact runs are compacted into `LitNocase` (already stored
/// lowercased), so this just picks the longest such run and the fixed byte width
/// before it (the threading anchor); `None` prefix when a variable-width token
/// precedes it.
fn nocase_anchor(tokens: &[Token], lits: &[u8], alternates: &[Alternates]) -> Option<(Vec<u8>, Option<u32>)> {
    let mut best: Option<(u32, u32, Option<u32>)> = None;
    let mut acc: Option<u32> = Some(0);
    for &token in tokens {
        if token.tag() == Token::TAG_LITNOCASE {
            let (off, len) = token.as_litnocase().unwrap();
            if len >= 2 && best.map_or(true, |(_, blen, _)| len > blen) {
                best = Some((off, len, acc));
            }
        }
        acc = acc.and_then(|w| single_token_width(token, alternates).map(|tw| w + tw as u32));
    }
    best.map(|(off, len, prefix)| {
        (
            lits[off as usize..(off + len) as usize].to_vec(),
            prefix,
        )
    })
}

/// Choose the required-literal atom (the substring that MUST appear for the
/// pattern to match, used both as the Aho-Corasick prefilter atom and the
/// verification anchor) and, when it has one, the fixed byte width of the tokens
/// before it (so `find_all`/`find_all_at` can anchor at `occurrence - prefix`).
///
/// We pick the **most selective** literal by a rarity score, NOT simply the
/// longest or the first fixed-prefix one. A short, ubiquitous literal like
/// `00 00 00` (3 zero bytes) occurs millions of times in a real PE's zero
/// padding; anchoring on it overflows the prefilter and forces a whole-buffer
/// `memmem` that finds those millions of hits — the dominant scan cost on real
/// binaries. Penalizing low-entropy atoms (and rewarding length + byte
/// diversity) makes us anchor on a rare substring instead, exactly as ClamAV's
/// atom selection does. A fixed-width prefix is a tiebreak bonus (it can be
/// offset-threaded), but selectivity wins — a rare literal behind a `*` still
/// beats a common one at the front.
///
/// Returns `((off, len) into lits, prefix_width)`. `prefix_width` is `None` when
/// the chosen literal sits behind a variable-width token (then the caller uses
/// it as a coarse `memmem` pre-check / anchor before the window scan).
fn best_required_literal(tokens: &[Token], lits: &[u8], alternates: &[Alternates]) -> (Option<(u32, u32)>, Option<u32>) {
    // After compaction, each maximal exact run ≥ 2 bytes is a single `Literal`.
    let mut best: Option<(i64, u32, u32, Option<u32>)> = None; // (score, off, len, prefix)
    let mut prefix_acc: Option<u32> = Some(0); // running fixed width from pattern start

    for &token in tokens {
        if token.tag() == Token::TAG_LITERAL {
            let (off, len) = token.as_literal().unwrap();
            if len >= 2 {
                let bytes = &lits[off as usize..(off + len) as usize];
                let score = literal_score(bytes, prefix_acc.is_some());
                if best.map_or(true, |(bs, ..)| score > bs) {
                    best = Some((score, off, len, prefix_acc));
                }
            }
        }
        // Advance the running prefix width; becomes None on the first
        // variable-width token, disabling anchoring for later literals.
        prefix_acc = prefix_acc.and_then(|w| single_token_width(token, alternates).map(|tw| w + tw as u32));
    }

    match best {
        Some((_, off, len, prefix)) => (Some((off, len)), prefix),
        None => (None, None),
    }
}

/// Selectivity score for a candidate prefilter atom (higher = rarer/better).
/// Length dominates; byte diversity helps; an all-same-byte run (e.g. `000000`,
/// `ffffff`) is heavily penalized because it occurs millions of times in real
/// binaries and makes a useless atom that overflows to a whole-buffer scan. A
/// fixed-width prefix earns a small bonus (it can be offset-threaded).
fn literal_score(bytes: &[u8], has_fixed_prefix: bool) -> i64 {
    let mut seen = [false; 256];
    let mut distinct = 0i64;
    for &b in bytes {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    let mut score = bytes.len() as i64 * 8 + distinct * 4;
    if distinct == 1 {
        score -= 1000; // all-same-byte: avoid unless it's the only literal
    }
    if has_fixed_prefix {
        score += 2;
    }
    score
}

/// Fixed byte width a single token always consumes, or `None` if variable-width.
fn single_token_width(token: Token, alternates: &[Alternates]) -> Option<usize> {
    let tag = token.tag();
    if tag == Token::TAG_LITERAL || tag == Token::TAG_LITNOCASE {
        let (_, len) = if tag == Token::TAG_LITERAL {
            token.as_literal().unwrap()
        } else {
            token.as_litnocase().unwrap()
        };
        Some(len as usize)
    } else if tag == Token::TAG_BYTE || (tag == Token::TAG_BOUNDARY && token.as_boundary().unwrap() == Boundary::NonAlphaNum) {
        Some(1)
    } else if tag == Token::TAG_BOUNDARY {
        Some(0) // Word or Newline
    } else if tag == Token::TAG_ANYBYTES {
        let (min, max) = token.as_any_bytes().unwrap();
        if min == max && max != UNBOUNDED { Some(min as usize) } else { None }
    } else if tag == Token::TAG_ALTERNATES {
        let idx = token.as_alternates().unwrap() as usize;
        let alt = &alternates[idx];
        if !alt.negated {
            let widths = alt
                .branches
                .iter()
                .map(|branch| fixed_width(branch, alternates))
                .collect::<Option<Vec<_>>>()?;
            if widths.iter().all(|w| *w == widths[0]) { Some(widths[0]) } else { None }
        } else if alt.negated_width.is_some() {
            alt.negated_width
        } else {
            None
        }
    } else {
        None
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

    #[test]
    fn wide_widens_nibble_wildcard_and_nocase_bytes() {
        // ClamAV's 'w' interleaves a NUL after EVERY element, including the
        // nibble-wildcard `??` — `cafe??babe` widens to ca 00 fe 00 ?? 00 ba 00 be 00.
        let wide_wild = compile_pattern_variants(
            "cafe??babe",
            Modifiers {
                wide: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert!(wide_wild.is_match(&[
            0xca, 0x00, 0xfe, 0x00, 0x99, 0x00, 0xba, 0x00, 0xbe, 0x00,
        ]));
        // A non-widened (missing NUL after `??`) sequence must NOT match.
        assert!(!wide_wild.is_match(&[0xca, 0x00, 0xfe, 0x00, 0x99, 0xba, 0x00, 0xbe, 0x00]));

        // 'i'+'w' together: each exact byte stays nocase, each followed by a NUL.
        let wide_nocase = compile_pattern_variants(
            "4141",
            Modifiers {
                nocase: true,
                wide: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert!(wide_nocase.is_match(&[0x61, 0x00, 0x41, 0x00])); // "a\0A\0"
    }

    #[test]
    fn nocase_run_compacts_to_one_token() {
        // A 5-byte nocase pattern must compact to a SINGLE LitNocase token (plus
        // its 5 lowercased bytes in `lits`) — not 5 separate ~12-byte Token::Byte.
        let p = compile_pattern_variants(
            "68656c6c6f", // "hello"
            Modifiers {
                nocase: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert_eq!(p.tokens.len(), 1, "nocase run should be one token");
        assert!(p.tokens[0].tag() == Token::TAG_LITNOCASE && p.tokens[0].as_litnocase().unwrap().1 == 5);
        assert_eq!(p.lits.len(), 5);
        // And it still matches case-insensitively.
        assert!(p.is_match(b"xxHeLLoyy"));
        assert!(p.is_match(b"hello"));
        assert!(!p.is_match(b"world"));
    }

    #[test]
    fn nocase_literal_after_wildcard_matches() {
        // "hello*world" nocase → [LitNocase("hello"), AnyBytes{*}, LitNocase("world")].
        // Exercises the LitNocase arm of the AnyBytes fast path (68=h…6f=o, 2a=*,
        // 77=w…64=d via the '*' wildcard token).
        let pat = compile_pattern_variants(
            "68656c6c6f*776f726c64",
            Modifiers {
                nocase: true,
                ..Modifiers::default()
            },
        )
        .unwrap()
        .remove(0);
        assert!(pat.is_match(b"xxHeLLo________WoRLDyy"));
        assert!(pat.is_match(b"hello world"));
        assert!(!pat.is_match(b"hello there")); // "world" absent
        assert!(!pat.is_match(b"hell0 world")); // "hello" absent (0 not o)
    }

    #[test]
    fn wildcard_run_collapses_to_one_gap_token() {
        // `????????` (4 full-wildcard bytes) is semantically `{4}`. It must
        // compact to a SINGLE AnyBytes token, not 4 Token::Byte(0,0) — the
        // resident-memory win for wildcard-run-heavy signatures.
        let p = one("41????????42"); // A {4} B
        assert_eq!(
            p.tokens.len(),
            3,
            "expected [Byte(41), AnyBytes{{4,4}}, Byte(42)], got {:?}",
            p.tokens
        );
        assert_eq!(p.tokens[1].as_any_bytes(), Some((4, 4)));
        // And it matches exactly like the equivalent `{4}` braced gap.
        assert!(p.is_match(b"AwxyzB")); // 4 gap bytes: w x y z
        assert!(one("41{4}42").is_match(b"AwxyzB"));
        assert!(!p.is_match(b"AwxyB")); // only 3 gap bytes

        // Adjacent gaps also coalesce: `*` then `??` → one AnyBytes{1,UNBOUNDED}.
        let q = one("41*??42");
        assert_eq!(q.tokens.len(), 3, "got {:?}", q.tokens);
        assert_eq!(q.tokens[1].as_any_bytes(), Some((1, UNBOUNDED)));
    }

    #[test]
    fn long_nibble_wildcard_run_still_matches() {
        // A pattern with > 2048 `??` tokens must match (the recursion cap counts
        // only alternation nesting now, not linear advancement).
        let raw = "41".to_string() + &"??".repeat(3000) + "42";
        let pat = one(&raw);
        let mut data = vec![0u8; 3002];
        data[0] = 0x41;
        data[3001] = 0x42;
        assert!(pat.is_match(&data));
    }
}
