use std::collections::HashSet;

/// Sentinel for an open-ended `AnyBytes` gap (`*` or `{n-}`), stored in
/// `Token::AnyBytes::max` so the field can be a plain `u32`.
const UNBOUNDED: u32 = u32::MAX;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pattern {
    /// `Box<[Token]>`, not `Vec<Token>`: the token list is fixed after
    /// compaction, so dropping the unused capacity word saves 8 bytes on every
    /// one of the hundreds of thousands of patterns.
    tokens: Box<[Token]>,
    /// Backing storage for `Token::Literal` runs (exact byte sequences), stored
    /// once contiguously instead of one token per byte.
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
    /// For a `nocase` pattern (which has no case-sensitive `required_literal`):
    /// the fixed byte width before its case-folded prefilter atom (the longest
    /// run of fixed bytes), when that prefix is fixed-width. `Some(p)` lets
    /// `find_all_at` thread the nocase atom's offsets just like a case-sensitive
    /// literal — verify the whole pattern at `atom_offset - p` instead of a
    /// per-candidate full-buffer scan (the big win on large files, since ClamAV
    /// databases are full of nocase signatures). `None` for case-sensitive
    /// patterns, or nocase patterns whose atom sits behind a variable-width token.
    /// The atom *bytes* are NOT stored — they're recomputed once at prefilter
    /// build time (see `required_atom_nocase`), so they cost no resident memory.
    required_prefix_nocase: Option<u32>,
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
        let (tokens, lits) = compact_tokens(tokens);
        let (required_literal, required_prefix) = best_required_literal(&tokens, &lits);
        // For nocase patterns (no case-sensitive literal), record only the
        // fixed-width prefix to the nocase atom so `find_all_at` can anchor on it.
        // The atom bytes themselves are recomputed at prefilter build time
        // (`required_atom_nocase`), never stored — keeps every Pattern smaller.
        let required_prefix_nocase = if required_literal.is_none() {
            nocase_anchor(&tokens).and_then(|(_, prefix)| prefix)
        } else {
            None
        };
        Self {
            tokens: tokens.into_boxed_slice(),
            lits: lits.into_boxed_slice(),
            fullword,
            required_literal,
            required_prefix,
            required_prefix_nocase,
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

    /// A case-folded (lowercased) required atom for `nocase` patterns, usable as a
    /// prefilter hint against a lowercased copy of the scanned buffer. Computed
    /// on demand (only ever called once, at prefilter build time) so the bytes
    /// cost no resident memory. `None` for patterns that have a case-sensitive
    /// `required_atom`, or no run of ≥2 fixed bytes (e.g. fully wildcard).
    pub fn required_atom_nocase(&self) -> Option<Vec<u8>> {
        if self.required_literal.is_some() {
            return None; // case-sensitive: use required_atom() instead
        }
        nocase_anchor(&self.tokens).map(|(atom, _)| atom)
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
        let Some((off, len)) = self.required_literal else {
            // No case-sensitive anchor. A `nocase` pattern can still be threaded
            // on its case-folded atom (hints are positions in the lowercased
            // buffer, which share coordinates with the original).
            if let Some(prefix_nocase) = self.required_prefix_nocase {
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
        let (minp, maxp) = match self.required_prefix {
            Some(p) => (p as usize, p as usize),
            None => match self.prefix_bounds_to(off) {
                Some((mn, mx)) if (mx as usize) <= MAX_PREFIX_WINDOW => (mn as usize, mx as usize),
                _ => return self.find_all(data, ranges, limit),
            },
        };
        let required = &self.lits[off as usize..(off + len) as usize];
        let required_len = required.len();

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
            let start_hi = occurrence.saturating_sub(minp);
            let start_lo = occurrence.saturating_sub(maxp);
            for start in start_lo..=start_hi {
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
        }
        out
    }

    /// Offset-threaded verification for a `nocase` pattern. `hints` are positions
    /// in the lowercased buffer where the pattern's case-folded atom occurred;
    /// since lowercasing is length-preserving they are valid offsets in `data`
    /// too. The atom sits `prefix` fixed bytes into the pattern, so the whole
    /// pattern is verified (case-insensitively, via `match_from`) at
    /// `occurrence - prefix`. Complete because the prefilter records every atom
    /// occurrence; match set identical to the full `find_all` first-byte scan.
    fn find_all_at_nocase(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
        hints: &[u32],
        prefix: usize,
    ) -> Vec<MatchRange> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for &hint in hints {
            let occurrence = hint as usize;
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

    /// The `(min, max)` total byte width of the tokens before the `Literal` at
    /// `target_off`, or `None` if any preceding token is unbounded (a leading
    /// `*` / `{n-}`). Used by `find_all_at` to anchor a literal that sits behind
    /// bounded gaps: the match start is then in `[occurrence-max, occurrence-min]`.
    fn prefix_bounds_to(&self, target_off: u32) -> Option<(u32, u32)> {
        let mut min = 0u32;
        let mut max = 0u32;
        for token in self.tokens.iter() {
            if let Token::Literal { off, .. } = token {
                if *off == target_off {
                    return Some((min, max));
                }
            }
            let (tmin, tmax) = token_width_bounds(token)?;
            min = min.saturating_add(tmin);
            max = max.saturating_add(tmax);
        }
        None
    }
}

/// `(min, max)` byte width a single token can consume, or `None` if unbounded.
/// Like `single_token_width` but admits bounded ranges (`{n-m}`) and
/// variable-width alternations, returning their span instead of requiring a
/// single fixed width.
fn token_width_bounds(token: &Token) -> Option<(u32, u32)> {
    match token {
        Token::Literal { len, .. } => Some((*len, *len)),
        Token::Byte(_) | Token::Boundary(Boundary::NonAlphaNum) => Some((1, 1)),
        Token::Boundary(Boundary::Word) | Token::Boundary(Boundary::Newline) => Some((0, 0)),
        Token::AnyBytes { max, .. } if *max == UNBOUNDED => None,
        Token::AnyBytes { min, max } => Some((*min, *max)),
        Token::Alternates(alt) if !alt.negated => {
            let mut lo = u32::MAX;
            let mut hi = 0u32;
            for branch in &alt.branches {
                let w = fixed_width(branch)? as u32;
                lo = lo.min(w);
                hi = hi.max(w);
            }
            Some((lo, hi))
        }
        Token::Alternates(alt) if alt.negated_width.is_some() => {
            let w = alt.negated_width.unwrap() as u32;
            Some((w, w))
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
    match tokens.get(idx) {
        None => true,
        Some(Token::AnyBytes { max, .. }) => *max == UNBOUNDED,
        _ => false,
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
    // ClamAV's branch matcher (ac_forward/backward_match_branch) advances the
    // linear spine of a pattern with an explicit `for` loop and only recurses for
    // the genuinely-recursive dimension — alternation nesting. We mirror that:
    // Byte/Literal/Boundary advance `token_index`/`pos` IN PLACE inside this loop
    // (no recursion, so a sub-signature with thousands of `??`/nocase tokens can
    // never overflow the stack or hit an arbitrary token-count cap), while only
    // wildcard backtracking and alternation branches recurse. `depth` therefore
    // counts only alternation nesting, exactly like the C comment "recursion depth
    // = number of alternate specials"; the cap is pure DoS protection.
    if depth > 2048 {
        return None;
    }
    let mut token_index = token_index;
    let mut pos = pos;
    loop {
        if token_index == tokens.len() {
            return Some(pos);
        }

        match &tokens[token_index] {
            Token::Byte(byte) => {
                if pos < data.len() && byte.matches(data[pos]) {
                    token_index += 1;
                    pos += 1;
                    continue;
                }
                return None;
            }
            Token::Literal { off, len } => {
                let lit = &lits[*off as usize..(*off + *len) as usize];
                let end = pos + lit.len();
                if end <= data.len() && &data[pos..end] == lit {
                    token_index += 1;
                    pos = end;
                    continue;
                }
                return None;
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
                    // Greedy short-circuit: when what follows the literal is
                    // open-ended (end of pattern, or another unbounded gap), the
                    // LEFTMOST literal occurrence is provably sufficient — a later
                    // occurrence only shrinks the remaining search window, so if
                    // the first fails, all later ones fail too. This turns the
                    // catastrophic `*a*b*c` nested product (O(occ(a)·occ(b)·…))
                    // into O(occ(a)+occ(b)+…), the difference between a 7-second
                    // signature and a microsecond one. When the next token is
                    // fixed-width-constrained (e.g. `*a{5}b`), we must still
                    // backtrack, so greedy is off.
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
                            tokens,
                            lits,
                            data,
                            token_index + 2,
                            candidate + lit.len(),
                            depth,
                        ) {
                            return Some(end);
                        }
                        if greedy {
                            return None;
                        }
                        search_from = candidate + 1;
                    }
                }
                // `anchor_bytes()` (not `exact_value()`): the latter is `None`
                // for `nocase` bytes, so case-insensitive patterns' wildcard gaps
                // used to fall through to the slow per-position probe below — and
                // `nocase + *` (a case-insensitive string with a gap) is one of
                // the most common ClamAV idioms. `anchor_bytes` jumps via memchr2
                // over both case variants instead.
                Some(Token::Byte(byte)) if byte.anchor_bytes().is_some() => {
                    let (b1, b2) = byte.anchor_bytes().unwrap();
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
                        let Some(rel) = rel else {
                            return None;
                        };
                        let candidate = search_from + rel;
                        if let Some(end) = match_tokens(
                            tokens,
                            lits,
                            data,
                            token_index + 2,
                            candidate + 1,
                            depth,
                        ) {
                            return Some(end);
                        }
                        if greedy {
                            return None;
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
                            match_tokens(tokens, lits, data, token_index + 1, next, depth)
                        {
                            return Some(end);
                        }
                    }
                    return None;
                }
            }
        }
        Token::Boundary(Boundary::Word) => {
            if is_word_boundary(data, pos) {
                token_index += 1;
                continue;
            }
            return None;
        }
        Token::Boundary(Boundary::Newline) => {
            if pos == 0
                || pos == data.len()
                || data.get(pos.wrapping_sub(1)) == Some(&b'\r')
                || data.get(pos.wrapping_sub(1)) == Some(&b'\n')
            {
                token_index += 1;
                continue;
            }
            return None;
        }
        Token::Boundary(Boundary::NonAlphaNum) => {
            if pos < data.len() && !data[pos].is_ascii_alphanumeric() {
                token_index += 1;
                pos += 1;
                continue;
            }
            return None;
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
                // Branch sub-matches are the genuinely-recursive dimension →
                // charge depth here; the linear continuation after the special does not.
                let matched = branches.iter().any(|branch| {
                    match_tokens(branch, &[], data, 0, pos, depth + 1) == Some(pos + width)
                });
                if !matched {
                    return match_tokens(tokens, lits, data, token_index + 1, pos + width, depth);
                }
                return None;
            }
            for branch in branches {
                if let Some(branch_end) = match_tokens(branch, &[], data, 0, pos, depth + 1) {
                    if let Some(end) =
                        match_tokens(tokens, lits, data, token_index + 1, branch_end, depth)
                    {
                        return Some(end);
                    }
                }
            }
            return None;
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
                // ClamAV's WIDE option (readdb.c sigopts 'w') widens the ENTIRE
                // pattern to UTF-16LE by interleaving a NUL high byte after EVERY
                // element — including nibble-wildcard (`?X`/`X?`/`??`) and nocase
                // bytes, not just exact case-sensitive ones. The injected NUL is
                // always an exact case-sensitive 0x00 (the `%02x`=00 high byte), so
                // downstream literal compaction still works.
                out.push(Token::Byte(*byte));
                out.push(Token::Byte(ByteMatcher::exact(0, false)));
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
/// Returns `None` when there is no run of ≥2 fixed bytes (e.g. fully wildcard).
fn nocase_anchor(tokens: &[Token]) -> Option<(Vec<u8>, Option<u32>)> {
    let mut best: Vec<u8> = Vec::new();
    let mut best_prefix: Option<u32> = None;
    let mut run: Vec<u8> = Vec::new();
    let mut run_prefix: Option<u32> = Some(0); // fixed width before the current run
    let mut acc: Option<u32> = Some(0); // running fixed width from pattern start
    for token in tokens {
        let byte_value = match token {
            Token::Byte(byte) => byte.exact_value_any_case(),
            _ => None,
        };
        match byte_value {
            Some(value) => {
                if run.is_empty() {
                    run_prefix = acc; // width accumulated before this run starts
                }
                run.push(value.to_ascii_lowercase());
            }
            None => {
                if run.len() > best.len() {
                    best = std::mem::take(&mut run);
                    best_prefix = run_prefix;
                } else {
                    run.clear();
                }
            }
        }
        acc = acc.and_then(|w| single_token_width(token).map(|tw| w + tw as u32));
    }
    if run.len() > best.len() {
        best = run;
        best_prefix = run_prefix;
    }
    if best.len() >= 2 {
        Some((best, best_prefix))
    } else {
        None
    }
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
fn best_required_literal(tokens: &[Token], lits: &[u8]) -> (Option<(u32, u32)>, Option<u32>) {
    // After compaction, each maximal exact run ≥ 2 bytes is a single `Literal`.
    let mut best: Option<(i64, u32, u32, Option<u32>)> = None; // (score, off, len, prefix)
    let mut prefix_acc: Option<u32> = Some(0); // running fixed width from pattern start

    for token in tokens {
        if let Token::Literal { off, len } = token {
            if *len >= 2 {
                let bytes = &lits[*off as usize..(*off + *len) as usize];
                let score = literal_score(bytes, prefix_acc.is_some());
                if best.map_or(true, |(bs, ..)| score > bs) {
                    best = Some((score, *off, *len, prefix_acc));
                }
            }
        }
        // Advance the running prefix width; becomes None on the first
        // variable-width token, disabling anchoring for later literals.
        prefix_acc = prefix_acc.and_then(|w| single_token_width(token).map(|tw| w + tw as u32));
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
