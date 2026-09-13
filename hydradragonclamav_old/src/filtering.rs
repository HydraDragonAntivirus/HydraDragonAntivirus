//! Shift-or 2-gram filter — a faithful Rust port of ClamAV's `libclamav/filtering.c`
//! ("A fast filter for static patterns", Török Edvin).
//!
//! The filter retains an *approximation* of a set of patterns: it can report a
//! false positive (a position that looks like a possible match but isn't), but
//! **never a false negative** — every real occurrence of a registered pattern is
//! reported. It is a bit-parallel shift-or automaton over overlapping
//! little-endian 2-grams, with a second `end` table marking where a pattern may
//! finish. See the long comment block in the C source for the algorithm.
//!
//! Port scope: `filter_search`/`filter_search_ext` (the `__hot__` runtime path)
//! are byte-exact to the C. `filter_add_static` ports ClamAV's subpattern-choice
//! heuristic (`filtering.c:186`). The wildcard-aware `filter_add_acpatt`
//! (`filtering.c:427`) is approximated by feeding a pattern's longest fixed
//! literal run (`Pattern::required_atom`) through `filter_add_static` — the run is
//! exactly the "best static subpattern" `filter_add_acpatt` would extract, so the
//! no-false-negative property is preserved.
//!
//! Correctness of the no-false-negative property is independent of *which* valid
//! contiguous subpattern is registered: `filter_search` looks for the registered
//! run of 2-grams, so any real occurrence of the source pattern (which contains
//! that run) drives the automaton to a reported match. The scoring only affects
//! filter *quality* (false-positive rate), never soundness.

/// `#define MAXSOPATLEN 8` — the shift-or state is a `u8`, so 8 tracked states.
const MAXSOPATLEN: usize = 8;
/// `#define MAX_CHOICES 8`.
const MAX_CHOICES: usize = 8;
/// `#define MAXPATLEN 255`.
const MAXPATLEN: usize = 255;

/// The two 64 KiB bit-tables (`struct filter`). `b[q]` has a 0 bit at position `p`
/// when 2-gram `q` may appear at offset `p` of a pattern; `end[q]` has a 0 bit at
/// position `p` when 2-gram `q` may *end* a pattern at that offset. Boxed: 128 KiB
/// is too large for the stack.
pub struct Filter {
    b: Box<[u8; 65536]>,
    end: Box<[u8; 65536]>,
    /// Whether any pattern was successfully registered. An empty filter would
    /// reject everything (sound), but we treat it as "disabled" so callers fall
    /// back to a normal scan rather than skipping work.
    loaded: bool,
}

/// `cli_readint16` — little-endian 16-bit read.
#[inline]
fn readint16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

impl Filter {
    /// `filter_init`: every bit set (no 2-gram registered yet).
    pub fn new() -> Self {
        Filter {
            b: Box::new([0xff; 65536]),
            end: Box::new([0xff; 65536]),
            loaded: false,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// `filter_isset`: is 2-gram `val` registered at position `pos`? (bit cleared)
    #[inline]
    fn isset(&self, pos: usize, val: u16) -> bool {
        self.b[val as usize] & (1 << pos) == 0
    }

    /// `filter_set_atpos`: register 2-gram `val` at position `pos` (clear the bit).
    #[inline]
    fn set_atpos(&mut self, pos: usize, val: u16) {
        self.b[val as usize] &= !(1u8 << pos);
    }

    /// `filter_end_isset`.
    #[inline]
    fn end_isset(&self, pos: usize, a: u16) -> bool {
        self.end[a as usize] & (1 << pos) == 0
    }

    /// `filter_set_end`.
    #[inline]
    fn set_end(&mut self, pos: usize, a: u16) {
        self.end[a as usize] &= !(1u8 << pos);
    }

    /// `filter_add_static` (filtering.c:186): register a static byte pattern,
    /// choosing the best `MAXSOPATLEN`-byte subpattern by ClamAV's heuristic. The
    /// scoring is done in `i64` to mirror C's signed-int promotion without unsigned
    /// wraparound. Returns the registered length (`j + 2`) or `None` (`len < 2`).
    pub fn add_static(&mut self, pattern: &[u8]) -> Option<usize> {
        let mut len = pattern.len();
        if len > MAXPATLEN {
            len = MAXPATLEN;
        }
        if len < 2 {
            return None;
        }

        // `if (len > 4) { maxlen = len - 4; if (maxlen == 1) maxlen = 2; } else maxlen = 2;`
        let maxlen = if len > 4 {
            let m = len - 4;
            if m == 1 {
                2
            } else {
                m
            }
        } else {
            2
        };

        let mut best: i64 = 0xffff_ffff;
        let mut best_pos = 0usize;
        let mut j = 0usize;
        // `for (j = 0; (best < 100 && j < MAX_CHOICES) || (j < maxlen); j++)`
        while (best < 100 && j < MAX_CHOICES) || j < maxlen {
            if j + 2 > len {
                break;
            }
            let mut num: i64 = MAXSOPATLEN as i64;
            let mut k = j;
            // `for (k = j; k < len - 1 && (k - j < MAXSOPATLEN); k++)`
            let mut q = 0u16;
            while k < len - 1 && (k - j) < MAXSOPATLEN {
                q = readint16(pattern, k);
                num += if self.isset(k - j, q) {
                    0
                } else {
                    (MAXSOPATLEN - (k - j)) as i64
                };
                if (k == j || k == j + 1) && (q == 0x0000 || q == 0xffff) {
                    num += if k == j { 10000 } else { 1000 };
                }
                k += 1;
            }
            // `num += 10 * (filter_end_isset(m, k - j - 1, q) ? 0 : 1);`
            num += 10 * if self.end_isset(k - j - 1, q) { 0 } else { 1 };
            // `num += 5 * (MAXSOPATLEN - (k - j));`
            num += 5 * (MAXSOPATLEN as i64 - (k - j) as i64);
            // `if (k - j + 1 < 4) num += 200;`
            if k - j + 1 < 4 {
                num += 200;
            }
            // `num -= (2 * MAXSOPATLEN - (k + 1 + j)) * (k - j) / 2;`
            num -= (2 * MAXSOPATLEN as i64 - (k as i64 + 1 + j as i64)) * (k - j) as i64 / 2;

            if num < best {
                best = num;
                best_pos = j;
            }
            j += 1;
        }

        debug_assert!(best_pos < len - 1);
        let pattern = &pattern[best_pos..];
        let mut len = len - best_pos;
        if len > MAXSOPATLEN {
            len = MAXSOPATLEN;
        }

        // Shift-or preprocessing: register every overlapping 2-gram.
        let mut q = 0u16;
        let mut j = 0usize;
        while j < len - 1 {
            q = readint16(pattern, j);
            self.set_atpos(j, q);
            j += 1;
        }
        // Mark the pattern end at the last registered position.
        if j > 0 {
            j -= 1;
            self.set_end(j, q);
        }
        self.loaded = true;
        Some(j + 2)
    }

    /// `filter_search` (filtering.c:746, `__hot__`): scan `data`, returning an
    /// approximate match start position, or `-1` when no registered pattern can
    /// occur. Byte-exact to the C.
    pub fn search(&self, data: &[u8]) -> i64 {
        if data.len() < 2 {
            return -1;
        }
        let mut state: u8 = !0;
        for j in 0..data.len() - 1 {
            let q0 = readint16(data, j) as usize;
            state = (state << 1) | self.b[q0];
            let match_end = state | self.end[q0];
            if match_end != 0xff {
                return if j >= MAXSOPATLEN {
                    (j - MAXSOPATLEN) as i64
                } else {
                    0
                };
            }
        }
        -1
    }

    /// `filter_search_ext` (filtering.c:718, `__hot__`): like `search` but reports
    /// the exact position `j` of the first possible match end. Returns `None` on no
    /// match. Byte-exact to the C.
    pub fn search_ext(&self, data: &[u8]) -> Option<usize> {
        if data.len() < 2 {
            return None;
        }
        let mut state: u8 = !0;
        for j in 0..data.len() - 1 {
            let q0 = readint16(data, j) as usize;
            state = (state << 1) | self.b[q0];
            let match_state_end = state | self.end[q0];
            if match_state_end != 0xff {
                return Some(j);
            }
        }
        None
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_pattern_is_found() {
        let mut f = Filter::new();
        f.add_static(b"malware_marker").unwrap();
        // The exact pattern, embedded in a buffer, must be reported (no FN).
        let mut data = vec![0u8; 100];
        data.extend_from_slice(b"...malware_marker...");
        assert!(f.search(&data) >= 0);
        assert!(f.search_ext(&data).is_some());
    }

    #[test]
    fn unrelated_buffer_is_rejected() {
        let mut f = Filter::new();
        f.add_static(b"this_is_a_long_unique_pattern").unwrap();
        // A buffer sharing no 2-gram run with the pattern should be rejected
        // (this is allowed to false-positive, but a clearly-different buffer
        // exercises the reject path).
        let data = vec![0xABu8; 4096];
        assert_eq!(f.search(&data), -1);
    }

    #[test]
    fn no_false_negative_across_offsets() {
        // The pattern must be found regardless of its alignment in the buffer —
        // 2-grams are overlapping precisely so a match can start at any position.
        let mut f = Filter::new();
        f.add_static(b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04").unwrap();
        for pad in 0..16usize {
            let mut data = vec![0u8; pad];
            data.extend_from_slice(b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04");
            data.extend_from_slice(&[0u8; 32]);
            assert!(
                f.search(&data) >= 0,
                "pattern at offset {pad} must be reported"
            );
        }
    }

    #[test]
    fn too_short_pattern_rejected() {
        let mut f = Filter::new();
        assert_eq!(f.add_static(b"x"), None);
        assert!(!f.is_loaded());
    }

    #[test]
    fn multiple_patterns_all_found() {
        let mut f = Filter::new();
        f.add_static(b"alpha_pattern_one").unwrap();
        f.add_static(b"beta_pattern_two").unwrap();
        f.add_static(b"gamma_pattern_three").unwrap();
        for p in [
            &b"xx alpha_pattern_one xx"[..],
            &b"yy beta_pattern_two yy"[..],
            &b"zz gamma_pattern_three zz"[..],
        ] {
            assert!(f.search(p) >= 0, "{:?} must be found", p);
        }
    }
}
