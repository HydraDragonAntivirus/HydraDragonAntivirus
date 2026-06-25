// Pattern representation using ClamAV-compatible u16 instructions plus a
// special table for `()` alternations / `(B)(L)(W)` boundaries, mirroring
// ClamAV's cli_ac_patt + cli_ac_special model (matcher-ac.c). Variable-length
// gaps ({n-m}, *, [a-b]) are approximated by their minimum width here; exact
// width / partno-splitting is handled at the database level (ClamAV sigid/partno).

use std::fmt;

// ClamAV-compatible u16 instruction metadata bits (mirrors cli_ac_patt flags).
pub const CLI_MATCH_CHAR: u16 = 0x0000;
pub const CLI_MATCH_NOCASE: u16 = 0x0100;
pub const CLI_MATCH_IGNORE: u16 = 0x0200;
pub const CLI_MATCH_NIBBLE_HIGH: u16 = 0x0300;
pub const CLI_MATCH_NIBBLE_LOW: u16 = 0x0400;
pub const CLI_MATCH_SPECIAL: u16 = 0x0700;
pub const CLI_MATCH_METADATA: u16 = 0x0f00;

/// Max recursive-matcher steps per `match_at` attempt (see `match_at`). One step
/// = one `match_rec` entry. A legitimate match needs at most a few thousand even
/// for gappy patterns; this ceiling only fires on multiplicative gap backtracking,
/// keeping any single position's work bounded (~a few ms) instead of unbounded.
const MATCH_FUEL_BUDGET: u64 = 2_000;

/// Max recursive-matcher steps for ONE signature's whole verification on a buffer
/// (`find_all`/`find_all_anchored`/`find_all_at` share a single counter across all
/// probed positions). High enough that an honest full scan of a multi-megabyte
/// buffer completes (≈ one step per position plus light verification), but it caps
/// the multiplicative blow-up of a pattern that backtracks at many positions, so a
/// single signature can never dominate the scan.
const SIG_FUEL_BUDGET: u64 = 64_000;

/// Match a single u16 instruction against a data byte.
#[inline]
fn match_byte(inst: u16, byte: u8) -> bool {
    match inst & CLI_MATCH_METADATA {
        CLI_MATCH_CHAR => (inst & 0xff) as u8 == byte,
        CLI_MATCH_NOCASE => (inst & 0xff) as u8 == byte.to_ascii_lowercase(),
        CLI_MATCH_IGNORE => true,
        CLI_MATCH_NIBBLE_HIGH => ((inst & 0xf0) as u8) == (byte & 0xf0),
        CLI_MATCH_NIBBLE_LOW => ((inst & 0x0f) as u8) == (byte & 0x0f),
        _ => false,
    }
}

/// Parse a hex string (with `??` wildcards and nibble masks) into u16 instructions.
fn hex_to_u16(hex: &str) -> Result<Vec<u16>, String> {
    let h = hex.as_bytes();
    let mut out = Vec::with_capacity(h.len() / 2);
    let mut i = 0;
    while i + 1 < h.len() {
        let hi = h[i];
        let lo = h[i + 1];
        let inst = if hi == b'(' && lo == b')' {
            // `()` placeholder emitted by extract_specials for an alternation /
            // boundary / gap. One CLI_MATCH_SPECIAL indexes the next entry of the
            // special table (mirrors ClamAV's special_pattern counter).
            CLI_MATCH_SPECIAL
        } else if hi == b'?' && lo == b'?' {
            CLI_MATCH_IGNORE
        } else if hi == b'?' {
            let lo_v = u8::from_str_radix(std::str::from_utf8(&[lo]).unwrap(), 16)
                .map_err(|_| format!("bad nibble '{:?}'", lo))?;
            CLI_MATCH_NIBBLE_LOW | lo_v as u16
        } else if lo == b'?' {
            let hi_v = u8::from_str_radix(std::str::from_utf8(&[hi]).unwrap(), 16)
                .map_err(|_| format!("bad nibble '{:?}'", hi))? << 4;
            CLI_MATCH_NIBBLE_HIGH | hi_v as u16
        } else {
            let byte = u8::from_str_radix(
                std::str::from_utf8(&[hi, lo]).unwrap(),
                16,
            )
            .map_err(|_| format!("bad hex byte '{:?}{:?}'", hi as char, lo as char))?;
            CLI_MATCH_CHAR | byte as u16
        };
        out.push(inst);
        i += 2;
    }
    Ok(out)
}

/// Signature modifiers parsed from the `::` suffix (nocase, wide, fullword, ascii).
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

/// An inline `()` special — an alternation or a boundary marker. Indexed in
/// order of `CLI_MATCH_SPECIAL` instructions in the pattern (ClamAV's
/// `special_table` / `special_pattern` counter).
#[derive(Clone, Debug)]
pub enum Special {
    /// `(2e|2f|40)` — every branch is one byte (ClamAV `AC_SPECIAL_ALT_CHAR`).
    /// `bytes` is sorted for binary search.
    AltChar { bytes: Vec<u8>, negative: bool },
    /// `(dead|beef)` — every branch is the same multi-byte length
    /// (`AC_SPECIAL_ALT_STR_FIXED`).
    AltStrFixed { strs: Vec<Vec<u8>>, len: usize, negative: bool },
    /// `(aa|bbbb)` — branches of differing length, possibly with `??`/nibble
    /// wildcards, stored as u16 instruction streams (`AC_SPECIAL_ALT_STR`).
    AltStr { branches: Vec<Vec<u16>>, min: usize, negative: bool },
    /// `(B)`/`(L)`/`(W)` appearing inline — approximated as a zero-width pass.
    Boundary,
    /// A variable-width gap: `*` / `{n-m}` / `{n-}` / `{-m}` — consume between
    /// `min` and `max` arbitrary bytes (`max == UNBOUNDED_GAP` for open-ended).
    /// Matched with backtracking (ClamAV splits these across `partno` parts;
    /// we keep them inline in one pattern, same semantics).
    Gap { min: usize, max: usize },
}

/// Open-ended gap maximum (`*` / `{n-}`): capped at the remaining buffer at match time.
const UNBOUNDED_GAP: usize = usize::MAX;

impl Special {
    /// Minimum bytes this special consumes — used to bound the scan window.
    fn min_width(&self) -> usize {
        match self {
            Special::AltChar { .. } => 1,
            Special::AltStrFixed { len, .. } => *len,
            Special::AltStr { min, .. } => *min,
            Special::Boundary => 0,
            Special::Gap { min, .. } => *min,
        }
    }

    /// Maximum bytes this special can consume (`UNBOUNDED_GAP` for an open gap).
    /// Used with `min_width` to bound the byte distance from a pattern's start to a
    /// later literal when that literal is anchored despite a variable-width element
    /// before it (see `Pattern::literal_prefix_range`).
    fn max_width(&self) -> usize {
        match self {
            Special::AltChar { .. } => 1,
            Special::AltStrFixed { len, .. } => *len,
            Special::AltStr { branches, negative, min } => {
                if *negative {
                    *min // negated alternations match a fixed `min` width
                } else {
                    branches.iter().map(|b| b.len()).max().unwrap_or(*min)
                }
            }
            Special::Boundary => 0,
            Special::Gap { max, .. } => *max,
        }
    }

    /// Exact bytes this special always consumes, or `None` when variable-width.
    /// Used to decide whether the byte distance from the pattern start to a later
    /// literal is constant (so the scan can anchor on that literal). A negated
    /// alternation is matched as fixed `min`-width (see `match_rec`); a positive
    /// `AltStr` has branches of differing length and a `Gap` is open — both vary.
    fn fixed_width(&self) -> Option<usize> {
        match self {
            Special::AltChar { .. } => Some(1),
            Special::AltStrFixed { len, .. } => Some(*len),
            Special::AltStr { min, negative, .. } => negative.then_some(*min),
            Special::Boundary => Some(0),
            Special::Gap { .. } => None,
        }
    }

    /// `wide` ('w') interleaves a NUL after every element, branches included.
    fn widened(&self) -> Special {
        match self {
            Special::AltChar { bytes, negative } => Special::AltStrFixed {
                strs: bytes.iter().map(|&b| vec![b, 0u8]).collect(),
                len: 2,
                negative: *negative,
            },
            Special::AltStrFixed { strs, negative, .. } => {
                let wstrs: Vec<Vec<u8>> = strs
                    .iter()
                    .map(|s| {
                        let mut v = Vec::with_capacity(s.len() * 2);
                        for &b in s {
                            v.push(b);
                            v.push(0);
                        }
                        v
                    })
                    .collect();
                let len = wstrs.first().map_or(0, |s| s.len());
                Special::AltStrFixed { strs: wstrs, len, negative: *negative }
            }
            Special::AltStr { branches, negative, .. } => {
                let wb: Vec<Vec<u16>> = branches
                    .iter()
                    .map(|br| {
                        let mut v = Vec::with_capacity(br.len() * 2);
                        for &bi in br {
                            v.push(bi);
                            v.push(0x0000);
                        }
                        v
                    })
                    .collect();
                let min = wb.iter().map(|b| b.len()).min().unwrap_or(0);
                Special::AltStr { branches: wb, min, negative: *negative }
            }
            Special::Boundary => Special::Boundary,
            // A gap is a byte-count; widening fixed elements doesn't change it.
            Special::Gap { min, max } => Special::Gap { min: *min, max: *max },
        }
    }
}

/// Bytes that fit inline in [`Instructions::Inline`] without a heap allocation.
/// Sized so the enum stays 24 bytes (same as a `Box<[u8]>` variant + tag), so the
/// `Pattern` struct does NOT grow — short pure-literal patterns (the vast majority)
/// then cost zero per-pattern allocations, eliminating ~millions of tiny `Box`es
/// and the allocator overhead/fragmentation they incur.
pub const INLINE_CAP: usize = 22;

#[derive(Clone, Debug)]
pub enum Instructions {
    /// A pure-literal pattern of `len` bytes stored inline (no allocation).
    Inline { buf: [u8; INLINE_CAP], len: u8 },
    Pure(Box<[u8]>),
    Complex(Box<[u16]>),
}

impl Default for Instructions {
    fn default() -> Self {
        Instructions::Inline { buf: [0; INLINE_CAP], len: 0 }
    }
}

impl Instructions {
    /// Build pure-literal instructions, storing them inline when they fit.
    #[inline]
    pub fn pure(bytes: Vec<u8>) -> Self {
        if bytes.len() <= INLINE_CAP {
            let mut buf = [0u8; INLINE_CAP];
            buf[..bytes.len()].copy_from_slice(&bytes);
            Instructions::Inline { buf, len: bytes.len() as u8 }
        } else {
            Instructions::Pure(bytes.into_boxed_slice())
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Instructions::Inline { len, .. } => *len as usize,
            Instructions::Pure(b) => b.len(),
            Instructions::Complex(b) => b.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get_u16(&self, index: usize) -> u16 {
        match self {
            Instructions::Inline { buf, .. } => buf[index] as u16,
            Instructions::Pure(b) => b[index] as u16,
            Instructions::Complex(b) => b[index],
        }
    }
}

/// A compiled pattern: a sequence of ClamAV uint16_t instructions plus its
/// `()` special table.
#[derive(Clone)]
pub struct Pattern {
    /// Space-efficient instruction storage: Box<[u8]> for pure literals,
    /// Box<[u16]> only when wildcards/specials are present.
    pub instructions: Instructions,
    pub specials: Box<[Special]>,
    pub best_literal_offset: u16,
    pub best_literal_len: u16,
    pub fullword: bool,
}

impl Default for Pattern {
    fn default() -> Self {
        Self {
            instructions: Instructions::default(),
            specials: Box::default(),
            best_literal_offset: u16::MAX,
            best_literal_len: 0,
            fullword: false,
        }
    }
}

impl Pattern {
    /// Get the best literal offset and length if present.
    #[inline]
    pub fn best_literal(&self) -> Option<(usize, usize)> {
        if self.best_literal_offset == u16::MAX {
            None
        } else {
            Some((self.best_literal_offset as usize, self.best_literal_len as usize))
        }
    }

    /// Create a Pattern from parsed instructions with no specials.
    pub fn from_instructions(inst: Vec<u16>, fullword: bool) -> Self {
        Self::from_parsed(inst, Vec::new(), fullword)
    }

    /// Create a Pattern from parsed instructions and special table.
    /// Converts Vecs to exact-fit Box<[T]> — eliminates overcapacity.
    pub fn from_parsed(inst: Vec<u16>, specials: Vec<Special>, fullword: bool) -> Self {
        let best_literal = Self::compute_best_literal(&inst);
        let instructions = if inst.iter().all(|&ins| (ins & CLI_MATCH_METADATA) == CLI_MATCH_CHAR) {
            // Pure literal → store inline when short (no per-pattern allocation).
            Instructions::pure(inst.iter().map(|&ins| (ins & 0xff) as u8).collect())
        } else {
            Instructions::Complex(inst.into_boxed_slice())
        };
        let (best_literal_offset, best_literal_len) = match best_literal {
            Some((off, len)) => (off as u16, len as u16),
            None => (u16::MAX, 0),
        };
        Self {
            instructions,
            specials: specials.into_boxed_slice(),
            best_literal_offset,
            best_literal_len,
            fullword,
        }
    }

    /// Pick the most *selective* fixed-byte (`CLI_MATCH_CHAR`) literal run for
    /// prefilter use — not merely the longest. Selectivity, not length, is what
    /// keeps the prefilter's candidate set small: a 3-byte run of `00` occurs in
    /// nearly every page of an executable (zero padding) and would make its
    /// signature a candidate on every scan, while a 3-byte run of *diverse* bytes
    /// after a gap (e.g. `02 FC 8A`) occurs rarely. ClamAV's `filtering.c`
    /// (`filter_add_static`) makes the same call when choosing a subpattern: it
    /// heavily penalises `0000`/`ffff` and favours diverse, longer runs. Crucially
    /// every `CLI_MATCH_CHAR` run is *required* (it lies outside any alternation),
    /// so picking any of them — including one *after* a gap — never changes the
    /// match set; it only changes which literal the prefilter indexes and the
    /// verification threads on. The score is deliberately file-type-agnostic
    /// (length + byte diversity, minus penalties for degenerate runs) rather than
    /// assuming non-printable bytes are rare — in a PE code section they are not.
    fn compute_best_literal(inst: &[u16]) -> Option<(usize, usize)> {
        let mut best_score = i32::MIN;
        let mut best: Option<(usize, usize)> = None;
        let mut run_start: usize = 0;
        let mut run_len = 0usize;
        let mut in_run = false;

        let consider = |start: usize, len: usize, best: &mut Option<(usize, usize)>, best_score: &mut i32| {
            if len < 2 {
                return;
            }
            let score = Self::literal_run_score(inst, start, len);
            if score > *best_score {
                *best_score = score;
                *best = Some((start, len));
            }
        };

        for (i, &ins) in inst.iter().enumerate() {
            let meta = ins & CLI_MATCH_METADATA;
            if meta == CLI_MATCH_CHAR {
                if !in_run {
                    run_start = i;
                    run_len = 0;
                    in_run = true;
                }
                run_len += 1;
            } else {
                if in_run {
                    consider(run_start, run_len, &mut best, &mut best_score);
                }
                in_run = false;
                run_len = 0;
            }
        }
        if in_run {
            consider(run_start, run_len, &mut best, &mut best_score);
        }
        best
    }

    /// Selectivity score for a fixed-byte run `inst[start..start+len]` (see
    /// [`compute_best_literal`]). Higher = rarer in real data. Length is the main
    /// signal (longer literals are rarer), with a diversity bonus and heavy
    /// penalties for the runs that are common in *every* binary regardless of
    /// type: all-zero, all-`0xff`, and single-byte-repeated (NOP sleds `9090…`,
    /// fill bytes `cccc…`). Mirrors the intent of `filtering.c`'s `0000`/`ffff`
    /// penalties without copying its file-content-specific weighting.
    fn literal_run_score(inst: &[u16], start: usize, len: usize) -> i32 {
        // Only the first MAX-atom bytes are ever indexed, but the full run length
        // still indicates how anchorable/verifiable the match is, so score on it.
        let mut seen = [false; 256];
        let mut distinct = 0i32;
        let mut all_zero = true;
        let mut all_ff = true;
        let first = (inst[start] & 0xff) as u8;
        let mut all_same = true;
        for i in 0..len {
            let b = (inst[start + i] & 0xff) as u8;
            if !seen[b as usize] {
                seen[b as usize] = true;
                distinct += 1;
            }
            if b != 0x00 {
                all_zero = false;
            }
            if b != 0xff {
                all_ff = false;
            }
            if b != first {
                all_same = false;
            }
        }
        let mut score = len as i32 * 6 + (distinct - 1) * 3;
        if all_zero || all_ff {
            score -= 1000; // occurs in essentially every executable page
        } else if all_same {
            score -= 500; // repeated-byte fill (NOP sled, padding)
        }
        score
    }

    /// Parse a hex string into u16 instructions (like cli_hex2ui).
    pub fn parse_hex(hex: &str) -> Result<Vec<u16>, String> {
        hex_to_u16(hex)
    }

    /// Check if the pattern matches anywhere in `data`.
    pub fn is_match(&self, data: &[u8]) -> bool {
        !self.find_all(data, &[(0, data.len())], 1).is_empty()
    }

    /// Minimum bytes a successful match consumes (specials may consume >1 byte
    /// each); used to bound the scan window.
    fn min_match_len(&self) -> usize {
        let mut n = 0usize;
        let mut sidx = 0usize;
        let len = self.instructions.len();
        for i in 0..len {
            let inst = self.instructions.get_u16(i);
            if (inst & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                n += self.specials.get(sidx).map_or(1, |s| s.min_width());
                sidx += 1;
            } else {
                n += 1;
            }
        }
        n
    }

    /// Maximum bytes a successful match can consume, or `None` when unbounded (an
    /// open `*`/`{n-}` gap, or a variable alternation whose longest branch can't be
    /// bounded). A safe UPPER bound: a match containing a byte at position `p`
    /// starts no earlier than `p - max_match_len`. Used to size the windows that
    /// restrict an OR-indexed signature's subsig scans to the prefilter's atom
    /// offsets (so a too-small bound can never drop a match).
    pub fn max_match_len(&self) -> Option<usize> {
        let mut n = 0usize;
        let mut sidx = 0usize;
        let len = self.instructions.len();
        for i in 0..len {
            let inst = self.instructions.get_u16(i);
            if (inst & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                let w = self.specials.get(sidx).map_or(1, |s| s.max_width());
                if w == UNBOUNDED_GAP {
                    return None;
                }
                n = n.checked_add(w)?;
                sidx += 1;
            } else {
                n += 1;
            }
        }
        Some(n)
    }

    /// Candidate pattern starts implied by literal occurrences `hints` (positions
    /// of the best literal), given the `[min_prefix, max_prefix]` byte distance
    /// from a match start to that literal. Sorted + deduped so overlapping windows
    /// aren't verified twice. Shared by `find_all` (self-found occurrences) and
    /// `find_all_at` (prefilter-supplied hints).
    fn collect_starts(
        &self,
        hints: impl Iterator<Item = usize>,
        min_prefix: usize,
        max_prefix: usize,
    ) -> Vec<usize> {
        let mut starts: Vec<usize> = Vec::new();
        for q in hints {
            let lo = q.saturating_sub(max_prefix);
            let hi = q.saturating_sub(min_prefix);
            for s in lo..=hi {
                starts.push(s);
            }
        }
        starts.sort_unstable();
        starts.dedup();
        starts
    }

    /// Verify the pattern at each candidate `start` (ascending), collecting in-range
    /// matches. The in-range predicate matches `find_all`'s `max_pos` exactly (start
    /// in `[rs, max(rs, re - min_len)]`). Adjacent duplicate starts are skipped, so
    /// a sorted start sequence is verified at most once per position.
    fn verify_starts(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
        starts: impl Iterator<Item = usize>,
    ) -> Vec<MatchRange> {
        let fuel = std::cell::Cell::new(SIG_FUEL_BUDGET);
        let mut out = Vec::new();
        let min_len = self.min_match_len().max(1);
        let mut last: Option<usize> = None;
        for start in starts {
            if last == Some(start) {
                continue;
            }
            last = Some(start);
            if fuel.get() == 0 {
                return out;
            }
            if let Some(match_end) = self.match_rec(data, start, 0, 0, &fuel) {
                if self.fullword && !is_fullword(data, start, match_end) {
                    continue;
                }
                if !ranges.iter().any(|&(rs, re)| {
                    let max_pos = re.saturating_sub(min_len).max(rs);
                    start >= rs && start <= max_pos
                }) {
                    continue;
                }
                out.push(MatchRange {
                    start,
                    end: match_end,
                });
                if out.len() >= limit {
                    return out;
                }
            }
        }
        out
    }

    /// Find all match ranges in `data` within the given ranges.
    pub fn find_all(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
    ) -> Vec<MatchRange> {
        if limit == 0 || self.instructions.is_empty() {
            return Vec::new();
        }
        let min_len = self.min_match_len().max(1);

        // Fast path: anchor on the best constant-offset run via SIMD substring
        // search and verify only where it occurs. (The prefilter-threaded
        // `find_all_at` handles the post-gap-literal case; here, full scans of
        // non-threaded subsigs are better served by the streaming anchored search
        // than by materialising every literal occurrence.)
        if let Some((prefix, needle)) = self.best_anchor() {
            return self.find_all_anchored(data, ranges, min_len, limit, prefix, &needle);
        }

        // No constant-offset anchor was found (every fixed byte sits behind a
        // variable-width gap/alternation). But we can still anchor on ANY fixed
        // byte in the pattern using SIMD `memchr` — far cheaper than probing every
        // buffer position. Find the rarest fixed byte as the search needle.
        //
        // NOTE: `byte_off` is an INSTRUCTION INDEX, not a byte offset. It's passed
        // to `prefix_range_to` which correctly translates it to a byte-offset range.
        // The search window and candidate-start logic below use the *byte* offsets
        // (`min_pre`/`max_pre`), never the raw instruction index.
        let any_byte = self.find_any_fixed_byte();
        if let Some((byte_off, byte_val, nocase)) = any_byte {
            let (min_pre, max_pre) = match self.prefix_range_to(byte_off) {
                Some(r) => r,
                None => return Vec::new(),
            };
            // If the prefix range is unbounded (open gap before the byte), fall
            // back to brute-force — the candidate start explosion per occurrence
            // would dwarf a simple position walk.
            if max_pre.saturating_sub(min_pre) > 4096 {
                return self.find_all_fallback_bruteforce(data, ranges, min_len, limit);
            }
            let fuel = std::cell::Cell::new(SIG_FUEL_BUDGET);
            let mut out = Vec::new();
            let b_lo = byte_val.to_ascii_lowercase();
            let b_up = byte_val.to_ascii_uppercase();
            for &(start, end) in ranges {
                let start = start.min(data.len());
                let end = end.min(data.len());
                if start > end {
                    continue;
                }
                let max_pos = end.saturating_sub(min_len).max(start);
                // The byte can appear anywhere from `start + min_pre` to
                // `max_pos + max_pre` (byte-offset prefix range).
                let lo = (start + min_pre).min(data.len());
                let hi = (max_pos.saturating_add(max_pre).saturating_add(1)).min(data.len());
                if lo >= hi {
                    continue;
                }
                let mut search = lo;
                while search < hi {
                    if fuel.get() == 0 {
                        return out;
                    }
                    let rel = if nocase && b_lo != b_up {
                        memchr::memchr2(b_lo, b_up, &data[search..hi])
                    } else {
                        memchr::memchr(byte_val, &data[search..hi])
                    };
                    let Some(rel) = rel else { break };
                    let occ = search + rel;
                    search = occ + 1;
                    let cand_lo = occ.saturating_sub(max_pre);
                    let cand_hi = occ.saturating_sub(min_pre);
                    for pos in cand_lo..=cand_hi {
                        if pos > max_pos {
                            break;
                        }
                        if pos < start {
                            continue;
                        }
                        if fuel.get() == 0 {
                            return out;
                        }
                        if let Some(match_end) = self.match_rec(data, pos, 0, 0, &fuel) {
                            if self.fullword && !is_fullword(data, pos, match_end) {
                                continue;
                            }
                            let c = (pos, match_end);
                            if out.last().map(|m: &MatchRange| (m.start, m.end)) != Some(c) {
                                out.push(MatchRange { start: pos, end: match_end });
                                if out.len() >= limit {
                                    return out;
                                }
                            }
                        }
                    }
                }
            }
            return out;
        }
        // Truly no fixed byte at all (all-wildcard). Such patterns are
        // extremely rare; delegate to the bounded brute-force fallback.
        self.find_all_fallback_bruteforce(data, ranges, min_len, limit)
    }

    /// A required fixed needle and its constant byte distance from the pattern
    /// start, used to anchor a full scan (`find_all_anchored`): the scan searches
    /// for the needle and only verifies there. The needle is the **most selective**
    /// constant-offset fixed-byte run — *not* merely the longest. Selectivity, not
    /// length, is what bounds the work: a 3-byte run of `00` occurs in nearly every
    /// page of an executable (zero padding) and would trigger millions of verifies,
    /// while a single uncommon opcode byte occurs far less. Each maximal run of
    /// fixed bytes lying before the first variable-width element (open gap /
    /// unequal-length alternation — past which the offset isn't constant) is scored
    /// by summing per-byte rarity, and the highest-scoring run wins. `None` only
    /// when no fixed byte has a constant offset (all-wildcard / nibble-only, or
    /// every fixed byte sits behind a gap) — those must scan every position.
    fn best_anchor(&self) -> Option<(usize, Vec<(u8, bool)>)> {
        // A run is a maximal sequence of constant-offset bytes that must match: each
        // is either an exact byte (`CLI_MATCH_CHAR`, `is_nocase=false`) or a
        // case-insensitive byte (`CLI_MATCH_NOCASE`, `true`). Including nocase bytes
        // is what keeps nocase / wide literals out of the every-position fallback —
        // without it a `::i` literal has no anchor and `find_all` brute-forces
        // `match_rec` at all ~N positions (the dominant scan cost on large files).
        let mut best: Option<(u32, usize, Vec<(u8, bool)>)> = None; // (score, offset, run)
        let mut run: Vec<(u8, bool)> = Vec::new();
        let mut run_off = 0usize;
        let mut bytes = 0usize;
        let mut sidx = 0usize;
        for i in 0..self.instructions.len() {
            let inst = self.instructions.get_u16(i);
            match inst & CLI_MATCH_METADATA {
                CLI_MATCH_CHAR | CLI_MATCH_NOCASE => {
                    if run.is_empty() {
                        run_off = bytes;
                    }
                    run.push((
                        (inst & 0xff) as u8,
                        (inst & CLI_MATCH_METADATA) == CLI_MATCH_NOCASE,
                    ));
                    bytes += 1;
                    continue;
                }
                CLI_MATCH_SPECIAL => {
                    let Some(w) = self.specials.get(sidx)?.fixed_width() else {
                        consider_anchor(run_off, &run, &mut best);
                        break; // variable width — no constant offset past here
                    };
                    bytes += w;
                    sidx += 1;
                }
                _ => bytes += 1, // wildcard / nibble — breaks the run, one fixed byte
            }
            consider_anchor(run_off, &run, &mut best);
            run.clear();
        }
        consider_anchor(run_off, &run, &mut best);
        best.map(|(_, off, needle)| (off, needle))
    }

    /// The `[min, max]` byte distance from the pattern start to its best literal,
    /// accounting for variable-width elements (gaps / unequal alternations) that
    /// precede it. `min == max` exactly when `literal_byte_prefix` is `Some` (the
    /// constant-offset fast case). `max == usize::MAX` when an open `*`/`{n-}` gap
    /// precedes the literal (then the distance is unbounded and hint anchoring is
    /// not worthwhile). `None` when there is no best literal at all.
    ///
    /// Used by `find_all_at` to anchor on a *selective* literal that sits after a
    /// bounded gap (e.g. polymorphic `e8??000000{-50}8a02…` virus bodies): the
    /// literal's hint positions are few, and each implies a small, bounded set of
    /// candidate pattern starts — far fewer probes than a full scan that would
    /// anchor on a common leading byte.
    /// The `[min, max]` prefix range to the atom the PREFILTER actually indexes:
    /// the exact `best_literal` if present, else the lowercased `nocase_run`. This
    /// lets `find_all_at` thread nocase patterns (keyword subsigs) at their hint
    /// positions instead of falling back to a whole-buffer scan.
    fn atom_prefix_range(&self) -> Option<(usize, usize)> {
        let off = match self.best_literal() {
            Some((o, _)) => o,
            None => self.nocase_run()?.0,
        };
        self.prefix_range_to(off)
    }

    /// `[min, max]` byte distance from the pattern start to instruction `lit_off`.
    fn prefix_range_to(&self, lit_off: usize) -> Option<(usize, usize)> {
        let mut min = 0usize;
        let mut max = 0usize;
        let mut sidx = 0usize;
        for i in 0..lit_off {
            let inst = self.instructions.get_u16(i);
            if (inst & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                let sp = match self.specials.get(sidx) {
                    Some(sp) => sp,
                    None => return None,
                };
                min += sp.min_width();
                max = max.saturating_add(sp.max_width());
                sidx += 1;
            } else {
                min += 1;
                max = max.saturating_add(1); // saturating: stay UNBOUNDED past an open gap
            }
        }
        Some((min, max))
    }

    /// Full-scan verification anchored on a required fixed `needle` that always
    /// sits exactly `byte_prefix` bytes into any match: find every (overlapping)
    /// occurrence of the needle with a SIMD search, then run `match_at` at
    /// `occurrence - byte_prefix`. Equivalent result to the naive every-position
    /// loop but only probes positions where the needle actually appears. The
    /// caller guarantees the byte distance to the needle is constant (no
    /// variable-width element precedes it), so the anchoring is exact.
    fn find_all_anchored(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        min_len: usize,
        limit: usize,
        byte_prefix: usize,
        needle: &[(u8, bool)],
    ) -> Vec<MatchRange> {
        if needle.is_empty() {
            return Vec::new();
        }
        let fuel = std::cell::Cell::new(SIG_FUEL_BUDGET);
        let mut out = Vec::new();
        let mut last_start: Option<usize> = None;

        // All-exact run → search the whole literal with SIMD memmem (most
        // selective). A run containing a case-insensitive byte can't memmem, so
        // anchor on its single most-selective byte, found case-insensitively with
        // memchr2; `match_rec` (which itself handles nocase/wide) then verifies the
        // full match, so the result is identical to the every-position fallback.
        let all_exact = needle.iter().all(|&(_, nc)| !nc);
        let exact: Vec<u8> = needle.iter().map(|&(b, _)| b).collect();
        let (anc_idx, anc_byte, anc_nocase) = needle
            .iter()
            .enumerate()
            .max_by_key(|&(_, &(b, nc))| byte_weight(b, nc))
            .map(|(i, &(b, nc))| (i, b, nc))
            .expect("needle non-empty");
        let anc_lo = anc_byte.to_ascii_lowercase();
        let anc_up = anc_byte.to_ascii_uppercase();

        for &(start, end) in ranges {
            let start = start.min(data.len());
            let end = end.min(data.len());
            if start > end {
                continue;
            }
            let max_pos = end.saturating_sub(min_len).max(start);
            // Offset from match start to the searched element, and its length.
            let (search_off, search_len) = if all_exact {
                (byte_prefix, exact.len())
            } else {
                (byte_prefix + anc_idx, 1)
            };
            let lo = (start + search_off).min(data.len());
            let hi = max_pos
                .saturating_add(search_off)
                .saturating_add(search_len)
                .min(data.len());
            if lo >= hi {
                continue;
            }
            let window = &data[lo..hi];
            let mut from = 0usize;
            while from < window.len() {
                let rel = if all_exact {
                    memchr::memmem::find(&window[from..], &exact)
                } else if anc_nocase && anc_lo != anc_up {
                    memchr::memchr2(anc_lo, anc_up, &window[from..])
                } else {
                    memchr::memchr(anc_byte, &window[from..])
                };
                let Some(rel) = rel else {
                    break;
                };
                let occ = lo + from + rel;
                from += rel + 1;
                let Some(pos) = occ.checked_sub(search_off) else {
                    continue;
                };
                if pos < start || pos > max_pos || last_start == Some(pos) {
                    continue;
                }
                last_start = Some(pos);
                // Nocase anchoring matched only a single byte; verify the WHOLE
                // needle inline (case-insensitively) before the costlier `match_rec`.
                // Without this, a one-letter anchor of a nocase keyword (e.g. `p` of
                // `powershell`) fires `match_rec` at its tens-of-thousands of buffer
                // occurrences; the inline check rejects all but true needle matches.
                // (`all_exact` already SIMD-matched the full needle, so skip it there.)
                if !all_exact {
                    let ns = pos + byte_prefix;
                    if ns + needle.len() > data.len() {
                        continue;
                    }
                    let ok = needle.iter().enumerate().all(|(k, &(b, nc))| {
                        let d = data[ns + k];
                        if nc {
                            d.to_ascii_lowercase() == b
                        } else {
                            d == b
                        }
                    });
                    if !ok {
                        continue;
                    }
                }
                if fuel.get() == 0 {
                    return out;
                }
                if let Some(match_end) = self.match_rec(data, pos, 0, 0, &fuel) {
                    if self.fullword && !is_fullword(data, pos, match_end) {
                        continue;
                    }
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
        out
    }

    /// Find all matches using prefilter hints (positions of a required literal).
    /// Respects `ranges` to enforce offset spec restrictions.
    pub fn find_all_at(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        limit: usize,
        hints: &[u32],
    ) -> Vec<MatchRange> {
        if limit == 0 || hints.is_empty() || self.instructions.is_empty() {
            return Vec::new();
        }
        // Each hint is an occurrence of this pattern's prefilter atom (its best
        // literal). A match places that literal at the hint, so the pattern START
        // lies in `[hint - max_prefix, hint - min_prefix]`, where the prefix range
        // is the byte distance from the pattern start to the literal (constant when
        // nothing variable precedes it; a bounded interval when a `{n-m}` gap or an
        // unequal alternation does). We verify `match_rec` at each candidate start.
        //
        // This is what lets a *selective* literal that sits AFTER a bounded gap
        // anchor the scan — e.g. polymorphic `e8??000000{-50}8a02…` virus bodies,
        // whose only good literal (`8a02`) follows the gap. Previously such patterns
        // fell back to a full scan that anchored on the common leading `e8` byte and
        // backtracked the gaps at every one of its ~tens-of-thousands of positions.
        let (min_prefix, max_prefix) = match self.atom_prefix_range() {
            Some(r) => r,
            None => return self.find_all(data, ranges, limit),
        };
        let span = max_prefix - min_prefix; // max >= min by construction
        // Constant-offset atom (the common case): the prefilter's hints are already
        // sorted + unique, so `start = hint - prefix` is too — verify them directly
        // without materialising and sorting a starts vector.
        if span == 0 {
            return self.verify_starts(
                data,
                ranges,
                limit,
                hints.iter().filter_map(|&h| (h as usize).checked_sub(min_prefix)),
            );
        }
        // When the literal sits behind an open/wide gap the start set explodes; a
        // full scan with its own anchor is then better. Bound the top-level probes.
        const MAX_PROBES: usize = 16_384;
        if hints.len().saturating_mul(span.saturating_add(1)) > MAX_PROBES {
            return self.find_all(data, ranges, limit);
        }
        let starts = self.collect_starts(hints.iter().map(|&h| h as usize), min_prefix, max_prefix);
        self.verify_starts(data, ranges, limit, starts.into_iter())
    }

    /// Find ANY fixed (CHAR or NOCASE) byte in the instruction stream, returning
    /// `(instruction_offset, byte_value, is_nocase)`. Used as a SIMD anchor when
    /// `best_anchor()` has no constant-offset run (all fixed bytes are behind a
    /// gap/alternation). Prefers the rarest byte by a simple heuristic.
    fn find_any_fixed_byte(&self) -> Option<(usize, u8, bool)> {
        let mut best: Option<(usize, u8, bool, u32)> = None; // (off, byte, nocase, weight)
        let mut sidx = 0usize;
        for i in 0..self.instructions.len() {
            let inst = self.instructions.get_u16(i);
            let meta = inst & CLI_MATCH_METADATA;
            if meta == CLI_MATCH_CHAR || meta == CLI_MATCH_NOCASE {
                let b = (inst & 0xff) as u8;
                let nc = meta == CLI_MATCH_NOCASE;
                let w = byte_weight(b, nc);
                if best.as_ref().map_or(true, |&(_, _, _, bw)| w < bw) {
                    best = Some((i, b, nc, w));
                }
            } else if meta == CLI_MATCH_SPECIAL {
                let sp = match self.specials.get(sidx) {
                    Some(sp) => sp,
                    None => break,
                };
                // Fixed-width specials don't break the search for a byte anchor
                // (they consume a known width). Only skip variable-width ones.
                if sp.fixed_width().is_none() {
                    sidx += 1;
                    continue;
                }
                sidx += 1;
            }
        }
        best.map(|(off, b, nc, _)| (off, b, nc))
    }

    /// Brute-force verification over every position in `ranges`, bounded by
    /// `SIG_FUEL_BUDGET`. Used as a last-resort fallback when no fixed byte
    /// anchor is available or the prefix range is too wide for memchr anchoring.
    fn find_all_fallback_bruteforce(
        &self,
        data: &[u8],
        ranges: &[(usize, usize)],
        min_len: usize,
        limit: usize,
    ) -> Vec<MatchRange> {
        let fuel = std::cell::Cell::new(SIG_FUEL_BUDGET);
        let mut out = Vec::new();
        for &(start, end) in ranges {
            let start = start.min(data.len());
            let end = end.min(data.len());
            if start > end {
                continue;
            }
            let max_pos = end.saturating_sub(min_len).max(start);
            for pos in start..=max_pos {
                if fuel.get() == 0 {
                    return out;
                }
                if let Some(match_end) = self.match_rec(data, pos, 0, 0, &fuel) {
                    if self.fullword && !is_fullword(data, pos, match_end) {
                        continue;
                    }
                    let c = (pos, match_end);
                    if out.last().map(|m: &MatchRange| (m.start, m.end)) != Some(c) {
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

    /// Try to match the pattern at a specific position in data.
    /// Returns the end position (exclusive) on success, or None.
    pub fn match_at(&self, data: &[u8], start: usize) -> Option<usize> {
        // Bound the backtracking work for one match attempt. A pattern with
        // several unbounded gaps (`a*b*c…`) can otherwise backtrack
        // multiplicatively — each gap re-scans the buffer for every position the
        // next gap tried — turning one `match_at` into minutes on a large file.
        // ClamAV sidesteps this by splitting on gaps and matching parts via its
        // automaton; here we keep the inline matcher but cap its steps. The budget
        // is far above any legitimate match, so a real detection always completes;
        // only pathological backtracking is cut (returning "no match" at this one
        // position, exactly as the position-by-position scan would eventually).
        let fuel = std::cell::Cell::new(MATCH_FUEL_BUDGET);
        self.match_rec(data, start, 0, 0, &fuel)
    }

    /// Recursive matcher: `dpos` = data position, `ipos` = instruction index,
    /// `sidx` = next special-table index. Recursion only branches for
    /// variable-width `AltStr` alternations; everything else advances linearly.
    /// `fuel` bounds total recursion steps for one `match_at` (see there).
    fn match_rec(
        &self,
        data: &[u8],
        mut dpos: usize,
        mut ipos: usize,
        mut sidx: usize,
        fuel: &std::cell::Cell<u64>,
    ) -> Option<usize> {
        let remaining = fuel.get();
        if remaining == 0 {
            return None; // budget exhausted — abort this backtracking branch
        }
        fuel.set(remaining - 1);
        let pat = &self.instructions;
        let pat_len = pat.len();
        while ipos < pat_len {
            let inst = pat.get_u16(ipos);
            if (inst & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                let sp = self.specials.get(sidx)?;
                match sp {
                    Special::Boundary => {
                        ipos += 1;
                        sidx += 1;
                    }
                    Special::AltChar { bytes, negative } => {
                        if dpos >= data.len() {
                            return None;
                        }
                        let hit = bytes.binary_search(&data[dpos]).is_ok();
                        if hit == *negative {
                            return None;
                        }
                        dpos += 1;
                        ipos += 1;
                        sidx += 1;
                    }
                    Special::AltStrFixed { strs, len, negative } => {
                        if dpos + *len > data.len() {
                            return None;
                        }
                        let slice = &data[dpos..dpos + *len];
                        let hit = strs.iter().any(|s| s.as_slice() == slice);
                        if hit == *negative {
                            return None;
                        }
                        dpos += *len;
                        ipos += 1;
                        sidx += 1;
                    }
                    Special::Gap { min, max } => {
                        if dpos + *min > data.len() {
                            return None;
                        }
                        let hi = (*max).min(data.len() - dpos);
                        // Fast path: a gap immediately followed by one or more fixed
                        // bytes — jump to each occurrence of that whole literal *run*
                        // (not just its first byte) with a SIMD search, instead of
                        // trying every gap width. Using the full run as the needle is
                        // far more selective than a single byte; that selectivity is
                        // what stops a gappy pattern (`…{gap}/link.html`) from probing
                        // thousands of false positions per gap and blowing up.
                        if ipos + 1 < pat_len && !data.is_empty() {
                            // Collect the fixed run after the gap — exact (CHAR) and
                            // case-insensitive (NOCASE) bytes — so a gap followed by a
                            // nocase literal (`…*Content::i`) is jumped to by SIMD
                            // search, not probed at every gap width. Without this,
                            // such patterns fall to the O(buffer-per-occurrence)
                            // general path below (the dominant doc-malware cost).
                            let mut run: Vec<(u8, bool)> = Vec::new();
                            let mut j = ipos + 1;
                            while j < pat_len && run.len() < 64 {
                                let e = pat.get_u16(j);
                                let meta = e & CLI_MATCH_METADATA;
                                if meta == CLI_MATCH_CHAR || meta == CLI_MATCH_NOCASE {
                                    run.push(((e & 0xff) as u8, meta == CLI_MATCH_NOCASE));
                                    j += 1;
                                } else {
                                    break;
                                }
                            }
                            if !run.is_empty() {
                                let all_exact = run.iter().all(|&(_, nc)| !nc);
                                let exact: Vec<u8> = run.iter().map(|&(b, _)| b).collect();
                                let (b0, nc0) = run[0];
                                let b0_lo = b0.to_ascii_lowercase();
                                let b0_up = b0.to_ascii_uppercase();
                                let lo = dpos + *min;
                                // The run must START in the gap window and fully fit.
                                let last_start =
                                    (dpos + hi).min(data.len().saturating_sub(run.len()));
                                if lo > last_start {
                                    return None;
                                }
                                let mut search = lo;
                                while search <= last_start {
                                    if fuel.get() == 0 {
                                        return None;
                                    }
                                    let rel = if all_exact {
                                        memchr::memmem::find(
                                            &data[search..last_start + run.len()],
                                            &exact,
                                        )
                                    } else if nc0 && b0_lo != b0_up {
                                        memchr::memchr2(b0_lo, b0_up, &data[search..=last_start])
                                    } else {
                                        memchr::memchr(b0, &data[search..=last_start])
                                    };
                                    let Some(rel) = rel else {
                                        break;
                                    };
                                    let p = search + rel;
                                    search = p + 1;
                                    // Verify the full (nocase-aware) run before recursing.
                                    let ok = all_exact
                                        || run.iter().enumerate().all(|(k, &(b, nc))| {
                                            let d = data[p + k];
                                            if nc {
                                                d.to_ascii_lowercase() == b
                                            } else {
                                                d == b
                                            }
                                        });
                                    if ok {
                                        if let Some(end) =
                                            self.match_rec(data, p, ipos + 1, sidx + 1, fuel)
                                        {
                                            return Some(end);
                                        }
                                    }
                                }
                                return None;
                            }
                        }
                        // General path: try each width, recurse for the remainder.
                        for w in *min..=hi {
                            if fuel.get() == 0 {
                                return None;
                            }
                            if let Some(end) = self.match_rec(data, dpos + w, ipos + 1, sidx + 1, fuel)
                            {
                                return Some(end);
                            }
                        }
                        return None;
                    }
                    Special::AltStr { branches, min, negative } => {
                        if *negative {
                            // ClamAV negated alternations are fixed width; use min.
                            let w = *min;
                            if dpos + w > data.len() {
                                return None;
                            }
                            let any = branches.iter().any(|br| {
                                br.len() == w
                                    && br
                                        .iter()
                                        .enumerate()
                                        .all(|(k, &bi)| match_byte(bi, data[dpos + k]))
                            });
                            if any {
                                return None;
                            }
                            dpos += w;
                            ipos += 1;
                            sidx += 1;
                        } else {
                            for br in branches {
                                let blen = br.len();
                                if dpos + blen <= data.len()
                                    && br
                                        .iter()
                                        .enumerate()
                                        .all(|(k, &bi)| match_byte(bi, data[dpos + k]))
                                {
                                    if let Some(end) =
                                        self.match_rec(data, dpos + blen, ipos + 1, sidx + 1, fuel)
                                    {
                                        return Some(end);
                                    }
                                }
                            }
                            return None;
                        }
                    }
                }
            } else {
                if dpos >= data.len() || !match_byte(inst, data[dpos]) {
                    return None;
                }
                dpos += 1;
                ipos += 1;
            }
        }
        Some(dpos)
    }

    /// Memory stats for this pattern.
    pub fn mem_stats(&self) -> MemStats {
        let mut s = MemStats::default();
        s.patterns = 1;
        s.token_bytes += match &self.instructions {
            Instructions::Inline { .. } => 0, // stored in the struct, no heap bytes
            Instructions::Pure(b) => b.len(),
            Instructions::Complex(b) => b.len() * 2,
        };
        s.struct_bytes += std::mem::size_of::<Pattern>();
        let len = self.instructions.len();
        for i in 0..len {
            let inst = self.instructions.get_u16(i);
            let meta = inst & CLI_MATCH_METADATA;
            match meta {
                CLI_MATCH_CHAR | CLI_MATCH_NOCASE => s.n_byte += 1,
                CLI_MATCH_IGNORE => s.n_anybytes += 1,
                CLI_MATCH_NIBBLE_HIGH | CLI_MATCH_NIBBLE_LOW => s.n_anybytes += 1,
                CLI_MATCH_SPECIAL => s.n_alternates += 1,
                _ => {}
            }
        }
        s
    }

    /// Could this pattern's required atom occur in the buffer the `filter` was built
    /// from? `false` only when the atom is provably absent (so the pattern cannot
    /// match) — never a false negative. Uses the exact `best_literal`, or the
    /// lowercased `nocase_run` for nocase patterns; conservatively `true` when the
    /// pattern has no usable atom. Allocation-free (atoms are ≤16 bytes).
    pub fn atom_maybe_present(&self, filter: &crate::presence::PresenceFilter) -> bool {
        let mut buf = [0u8; 16];
        if let Some((off, len)) = self.best_literal() {
            let n = len.min(16);
            for k in 0..n {
                buf[k] = (self.instructions.get_u16(off + k) & 0xff) as u8;
            }
            return filter.maybe(&buf[..n], false);
        }
        if let Some((off, len)) = self.nocase_run() {
            let n = len.min(16);
            for k in 0..n {
                buf[k] = ((self.instructions.get_u16(off + k) & 0xff) as u8).to_ascii_lowercase();
            }
            return filter.maybe(&buf[..n], true);
        }
        true
    }

    /// The longest fixed byte sequence for prefilter use (reconstructed on demand).
    pub fn required_atom(&self) -> Option<Vec<u8>> {
        self.best_literal().map(|(off, len)| {
            (0..len)
                .map(|i| (self.instructions.get_u16(off + i) & 0xff) as u8)
                .collect()
        })
    }

    /// Case-folded atom for nocase prefilter (longest CHAR/NOCASE run, lowered).
    pub fn required_atom_nocase(&self) -> Option<Vec<u8>> {
        self.nocase_run().map(|(start, len)| {
            (0..len)
                .map(|i| (self.instructions.get_u16(start + i) & 0xff) as u8)
                .map(|byte| byte.to_ascii_lowercase())
                .collect()
        })
    }

    /// `(offset, len)` of the longest `CHAR|NOCASE` run (≥2) — the run the prefilter
    /// indexes (lowercased) as a pattern's nocase atom. Used to anchor/thread nocase
    /// patterns, which have no exact `best_literal`.
    fn nocase_run(&self) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut in_run = false;
        let len = self.instructions.len();
        for i in 0..len {
            let meta = self.instructions.get_u16(i) & CLI_MATCH_METADATA;
            if meta == CLI_MATCH_CHAR || meta == CLI_MATCH_NOCASE {
                if !in_run {
                    run_start = i;
                    run_len = 0;
                    in_run = true;
                }
                run_len += 1;
            } else {
                if in_run && run_len >= 2 && best.map_or(true, |(_, blen)| run_len > blen) {
                    best = Some((run_start, run_len));
                }
                in_run = false;
            }
        }
        if in_run && run_len >= 2 && best.map_or(true, |(_, blen)| run_len > blen) {
            best = Some((run_start, run_len));
        }
        best
    }

    /// Find a fixed-byte literal from the pattern for prefilter use.
    pub fn find_literal(&self) -> Option<(Vec<u8>, usize)> {
        self.best_literal().map(|(off, len)| {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (self.instructions.get_u16(off + i) & 0xff) as u8)
                .collect();
            (bytes, off)
        })
    }
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pattern({} inst, {} specials, fullword={})",
            self.instructions.len(),
            self.specials.len(),
            self.fullword
        )
    }
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

/// A match range result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchRange {
    pub start: usize,
    pub end: usize,
}

/// Compile a hex signature string into Pattern variants (handles modifiers).
pub fn compile_pattern_variants(raw: &str, modifiers: Modifiers) -> Result<Vec<Pattern>, String> {
    let mut variants = Vec::new();

    if !modifiers.wide || modifiers.ascii {
        let (inst, specials) = parse_with_modifiers(raw, modifiers.nocase, false)?;
        variants.push(Pattern::from_parsed(inst, specials, modifiers.fullword));
    }

    if modifiers.wide {
        let (inst, specials) = parse_with_modifiers(raw, modifiers.nocase, true)?;
        variants.push(Pattern::from_parsed(inst, specials, modifiers.fullword));
    }

    Ok(variants)
}

/// Parse a hex signature into (instructions, special_table), applying the
/// nocase and wide options. `()` alternations and `[a-b]` ranges are extracted
/// first; `{n-m}`/`*` gaps are then expanded to their minimum `??` width.
fn parse_with_modifiers(raw: &str, nocase: bool, wide: bool) -> Result<(Vec<u16>, Vec<Special>), String> {
    // extract_specials handles `()` alternations, `[a-b]`, and `*`/`{n-m}` gaps,
    // leaving only hex / `??` / nibble tokens plus `()` special placeholders.
    let (extracted, specials) = extract_specials(raw)?;
    let mut base = hex_to_u16(&extracted)?;

    if nocase {
        for inst in &mut base {
            if (*inst & CLI_MATCH_METADATA) == CLI_MATCH_CHAR {
                let byte = (*inst & 0xff) as u8;
                *inst = byte.to_ascii_lowercase() as u16 | CLI_MATCH_NOCASE;
            }
        }
    }

    if wide {
        let mut wide_inst = Vec::with_capacity(base.len() * 2);
        let mut wide_spec = Vec::with_capacity(specials.len());
        let mut si = 0;
        for &inst in &base {
            if (inst & CLI_MATCH_METADATA) == CLI_MATCH_SPECIAL {
                wide_inst.push(inst);
                if let Some(sp) = specials.get(si) {
                    wide_spec.push(sp.widened());
                }
                si += 1;
            } else {
                wide_inst.push(inst);
                wide_inst.push(0x0000); // NUL byte (exact match)
            }
        }
        return Ok((wide_inst, wide_spec));
    }

    Ok((base, specials))
}

/// Extract `()` alternations / `(B)(L)(W)` markers into a special table and
/// `[a-b]` ranges into minimum-width `??` gaps, replacing each `()` with a `()`
/// placeholder that `hex_to_u16` turns into one `CLI_MATCH_SPECIAL`. `{n-m}`/`*`
/// are left for `expand_wildcards`. Whitespace is dropped.
fn extract_specials(raw: &str) -> Result<(String, Vec<Special>), String> {
    let b = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut specials = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b'!' | b'(' => {
                let negative = c == b'!';
                if negative {
                    if b.get(i + 1) != Some(&b'(') {
                        return Err("'!' not followed by '(' in pattern".to_string());
                    }
                    i += 1; // skip '!'
                }
                // b[i] == '(' — find the matching ')'
                let mut depth = 1;
                let mut j = i + 1;
                while j < b.len() {
                    match b[j] {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if depth != 0 {
                    return Err("missing closing parenthesis in pattern".to_string());
                }
                let content = raw[i + 1..j].trim();
                i = j + 1;
                if content == "B" || content == "L" || content == "W" {
                    specials.push(Special::Boundary);
                } else {
                    specials.push(parse_alternation(content, negative)?);
                }
                out.push_str("()");
            }
            b'[' => {
                let close = raw[i..]
                    .find(']')
                    .map(|x| i + x)
                    .ok_or_else(|| "missing closing square bracket".to_string())?;
                let min = gap_min(&raw[i + 1..close]);
                for _ in 0..min {
                    out.push_str("??");
                }
                i = close + 1;
            }
            b'*' => {
                specials.push(Special::Gap { min: 0, max: UNBOUNDED_GAP });
                out.push_str("()");
                i += 1;
            }
            b'{' => {
                let close = raw[i..]
                    .find('}')
                    .map(|x| i + x)
                    .ok_or_else(|| "missing closing brace".to_string())?;
                let (min, max) = gap_range(&raw[i + 1..close]);
                if max == Some(min) {
                    // Exact `{n}` — cheaper as n literal `??` than a backtracking gap.
                    for _ in 0..min {
                        out.push_str("??");
                    }
                } else {
                    specials.push(Special::Gap { min, max: max.unwrap_or(UNBOUNDED_GAP) });
                    out.push_str("()");
                }
                i = close + 1;
            }
            _ if c.is_ascii_whitespace() => i += 1,
            _ => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    Ok((out, specials))
}

/// Parse a `|`-separated alternation body into a [`Special`].
fn parse_alternation(content: &str, negative: bool) -> Result<Special, String> {
    let alts: Vec<&str> = content.split('|').collect();
    // An empty branch (`(aa|)`) makes the alternation optional — ClamAV allows it.
    // It is handled by the generic `AltStr` matcher, where a zero-length branch
    // matches zero-width, so we exclude the fixed-width fast paths in that case.
    let has_empty = alts.iter().any(|a| a.is_empty());
    let all_hex = !has_empty
        && alts
            .iter()
            .all(|a| a.len() % 2 == 0 && a.bytes().all(|c| c.is_ascii_hexdigit()));
    let all_single = all_hex && alts.iter().all(|a| a.len() == 2);
    let all_same = all_hex && alts.iter().all(|a| a.len() == alts[0].len());

    if all_single {
        let mut bytes: Vec<u8> = alts
            .iter()
            .filter_map(|a| u8::from_str_radix(a, 16).ok())
            .collect();
        bytes.sort_unstable();
        bytes.dedup();
        Ok(Special::AltChar { bytes, negative })
    } else if all_same {
        let len = alts[0].len() / 2;
        let mut strs = Vec::with_capacity(alts.len());
        for a in &alts {
            strs.push(hex_bytes(a)?);
        }
        Ok(Special::AltStrFixed { strs, len, negative })
    } else {
        // Generic branches (varying length and/or wildcards) → u16 streams.
        let mut branches = Vec::with_capacity(alts.len());
        let mut min = usize::MAX;
        for a in &alts {
            let processed = expand_wildcards(a);
            let u = hex_to_u16(&processed)?;
            min = min.min(u.len());
            branches.push(u);
        }
        Ok(Special::AltStr {
            branches,
            min: if min == usize::MAX { 0 } else { min },
            negative,
        })
    }
}

fn hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let h = hex.as_bytes();
    if h.len() % 2 != 0 {
        return Err(format!("odd-length hex branch '{hex}'"));
    }
    (0..h.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&hex[k..k + 2], 16).map_err(|_| format!("bad hex '{hex}'")))
        .collect()
}

/// Parse a `{...}` gap body into `(min, max)` where `max == None` means
/// open-ended: `n` → `(n, Some(n))`, `n-m` → `(n, Some(m))`, `n-` → `(n, None)`,
/// `-m` → `(0, Some(m))`.
fn gap_range(content: &str) -> (usize, Option<usize>) {
    let content = content.trim();
    if let Some(dash) = content.find('-') {
        let left = content[..dash].trim();
        let right = content[dash + 1..].trim();
        let min = if left.is_empty() { 0 } else { left.parse().unwrap_or(0) };
        let max = if right.is_empty() { None } else { Some(right.parse().unwrap_or(min)) };
        (min, max)
    } else {
        let n = content.parse().unwrap_or(0);
        (n, Some(n))
    }
}

/// Minimum width of a `{...}` / `[...]` gap body.
fn gap_min(content: &str) -> usize {
    if let Some(dash) = content.find('-') {
        let left = content[..dash].trim();
        if left.is_empty() {
            1 // {-m}/[-m] → at least 1
        } else {
            left.parse::<usize>().unwrap_or(1)
        }
    } else {
        content.trim().parse::<usize>().unwrap_or(1)
    }
}

/// Expand `*` and `{n}`/`{n-m}`/`{-m}` wildcard syntax into `??` byte pairs
/// (minimum width). `()` placeholders and hex are passed through untouched.
fn expand_wildcards(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            out.push_str("??");
            i += 1;
        } else if bytes[i] == b'{' {
            let close = match raw[i..].find('}') {
                Some(c) => i + c,
                None => {
                    out.push('{');
                    i += 1;
                    continue;
                }
            };
            for _ in 0..gap_min(&raw[i + 1..close]) {
                out.push_str("??");
            }
            i = close + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

// ── Utility functions ─────────────────────────────────────────────────────

/// Score a candidate anchor run (`best_anchor`) by summed per-byte rarity and
/// keep it if it beats the current best. A run starting at byte offset `off`.
/// Approximate per-byte rarity (~ -log2 frequency in executables). Filler bytes
/// score low (poor anchors); arbitrary bytes score high. A nocase byte is searched
/// as two cases, so it's slightly less selective — discounted below.
fn byte_weight(b: u8, nocase: bool) -> u32 {
    let base: u32 = match b {
        0x00 => 1,
        0xff => 2,
        0x90 | 0xcc => 3,
        0x20..=0x7e => 5, // printable: common in text-bearing files
        _ => 8,
    };
    if nocase {
        base.saturating_sub(1).max(1)
    } else {
        base
    }
}

fn consider_anchor(
    off: usize,
    run: &[(u8, bool)],
    best: &mut Option<(u32, usize, Vec<(u8, bool)>)>,
) {
    if run.is_empty() {
        return;
    }
    let score: u32 = run.iter().map(|&(b, nc)| byte_weight(b, nc)).sum();
    if best.as_ref().is_none_or(|(bs, _, _)| score > *bs) {
        *best = Some((score, off, run.to_vec()));
    }
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

// ── Tests ─────────────────────────────────────────────────────────────────
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
    fn single_byte_alternation_matches() {
        // (2e|2f|40) — one-byte alternation (ALT_CHAR). Matches '.', '/', or '@'.
        let p = one("41(2e|2f|40)42");
        assert!(p.is_match(b"A.B"));
        assert!(p.is_match(b"A/B"));
        assert!(p.is_match(b"A@B"));
        assert!(!p.is_match(b"A,B"));
    }

    #[test]
    fn multibyte_alternation_matches() {
        // (dead|beef) — fixed-width 2-byte alternation (ALT_STR_FIXED).
        let p = one("41(dead|beef)42");
        assert!(p.is_match(&[0x41, 0xde, 0xad, 0x42]));
        assert!(p.is_match(&[0x41, 0xbe, 0xef, 0x42]));
        assert!(!p.is_match(&[0x41, 0xde, 0xef, 0x42]));
    }

    #[test]
    fn varying_length_alternation_matches() {
        // (aa|bbbb) — 1-byte vs 2-byte branch (ALT_STR), needs backtracking.
        let p = one("41(aa|bbbb)42");
        assert!(p.is_match(&[0x41, 0xaa, 0x42]));
        assert!(p.is_match(&[0x41, 0xbb, 0xbb, 0x42]));
        assert!(!p.is_match(&[0x41, 0xcc, 0x42]));
    }

    #[test]
    fn variable_gaps_match() {
        // `*` — any number of bytes between A and B.
        let star = one("41*42");
        assert!(star.is_match(b"AB"));
        assert!(star.is_match(b"A much longer gap B"));
        assert!(!star.is_match(b"A no bee"));

        // `{2-4}` — between 2 and 4 bytes.
        let r = one("41{2-4}42");
        assert!(!r.is_match(b"AxB")); // 1 gap byte — too few
        assert!(r.is_match(b"AxxB")); // 2
        assert!(r.is_match(b"AxxxxB")); // 4
        assert!(!r.is_match(b"AxxxxxB")); // 5 — too many

        // `{2-}` — at least 2 bytes; `{-3}` — at most 3.
        assert!(one("41{2-}42").is_match(b"AxxxxxB"));
        assert!(!one("41{2-}42").is_match(b"AxB"));
        assert!(one("41{-3}42").is_match(b"AB"));
        assert!(!one("41{-3}42").is_match(b"AxxxxB"));

        // Exact `{3}` stays exact.
        assert!(one("41{3}42").is_match(b"AxxxB"));
        assert!(!one("41{3}42").is_match(b"AxxB"));
    }

    #[test]
    fn negated_alternation_matches() {
        // !(2e|2f) — match any byte that is NOT 0x2e/0x2f.
        let p = one("41!(2e|2f)42");
        assert!(p.is_match(b"AXB"));
        assert!(!p.is_match(b"A.B"));
        assert!(!p.is_match(b"A/B"));
    }

    #[test]
    fn modifiers_match_nocase_wide_and_fullword() {
        let nocase = compile_pattern_variants(
            "68656c6c6f",
            Modifiers { nocase: true, ..Modifiers::default() },
        ).unwrap().remove(0);
        assert!(nocase.is_match(b"HELLO"));

        let wide = compile_pattern_variants(
            "6869",
            Modifiers { wide: true, ..Modifiers::default() },
        ).unwrap().remove(0);
        assert!(wide.is_match(b"h\0i\0"));

        let fullword = compile_pattern_variants(
            "6869",
            Modifiers { fullword: true, ..Modifiers::default() },
        ).unwrap().remove(0);
        assert!(fullword.is_match(b" hi "));
        assert!(!fullword.is_match(b"this"));
    }

    #[test]
    fn wide_widens_nibble_wildcard_and_nocase_bytes() {
        let wide_wild = compile_pattern_variants(
            "cafe??babe",
            Modifiers { wide: true, ..Modifiers::default() },
        ).unwrap().remove(0);
        assert!(wide_wild.is_match(&[
            0xca, 0x00, 0xfe, 0x00, 0x99, 0x00, 0xba, 0x00, 0xbe, 0x00,
        ]));
        assert!(!wide_wild.is_match(&[0xca, 0x00, 0xfe, 0x00, 0x99, 0xba, 0x00, 0xbe, 0x00]));
    }

    #[test]
    fn long_nibble_wildcard_run_still_matches() {
        let raw = "41".to_string() + &"??".repeat(3000) + "42";
        let pat = one(&raw);
        let mut data = vec![0u8; 3002];
        data[0] = 0x41;
        data[3001] = 0x42;
        assert!(pat.is_match(&data));
    }
}
