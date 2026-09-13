//! Per-scan 3-gram presence bitset — a cheap, NO-false-negative pre-check that a
//! subsignature's literal could occur in the buffer.
//!
//! A non-gate body subsignature's atom isn't indexed in the prefilter, so today it
//! is found (or proven absent) by a whole-buffer `memmem`/`memchr` scan — paid once
//! per such subsig of every gate-passing candidate. Most of those atoms are
//! *absent*, yet still cost a full buffer pass to discover that. This filter
//! answers "could this literal be present?" in O(atom length) bitset lookups: if
//! any 3-gram of the atom is provably absent from the buffer, the literal cannot
//! occur and the scan is skipped.
//!
//! A 3-gram (3 bytes) is a 24-bit value, so the bitset is indexed DIRECTLY (one bit
//! per distinct 3-gram, 2^24 bits = 2 MiB) — no hashing, hence no hash collisions
//! and no false positives beyond the inherent "all 3-grams present but not
//! contiguous". A separate lowercased bitset serves nocase atoms.

pub struct PresenceFilter {
    exact: Vec<u64>,
    nocase: Vec<u64>,
}

const BITS: usize = 1 << 24; // one bit per 3-gram value
const WORDS: usize = BITS / 64;

#[inline]
fn gram3(a: u8, b: u8, c: u8) -> usize {
    (a as usize) | ((b as usize) << 8) | ((c as usize) << 16)
}
#[inline]
fn set(bits: &mut [u64], i: usize) {
    bits[i >> 6] |= 1u64 << (i & 63);
}
#[inline]
fn get(bits: &[u64], i: usize) -> bool {
    bits[i >> 6] & (1u64 << (i & 63)) != 0
}

impl PresenceFilter {
    /// Build the exact + lowercased 3-gram bitsets from `data`. Returns `None` for
    /// buffers small enough that a full scan is already cheap (so tiny archive
    /// children never pay the build cost).
    pub fn build(data: &[u8]) -> Option<Self> {
        const MIN_LEN: usize = 64 * 1024;
        if data.len() < MIN_LEN {
            return None;
        }
        let mut exact = vec![0u64; WORDS];
        let mut nocase = vec![0u64; WORDS];
        // Single pass, lowercasing each byte once (not per overlapping window).
        let mut l0 = data[0].to_ascii_lowercase();
        let mut l1 = data[1].to_ascii_lowercase();
        for i in 2..data.len() {
            let l2 = data[i].to_ascii_lowercase();
            set(&mut exact, gram3(data[i - 2], data[i - 1], data[i]));
            set(&mut nocase, gram3(l0, l1, l2));
            l0 = l1;
            l1 = l2;
        }
        Some(PresenceFilter { exact, nocase })
    }

    /// Could `atom` occur in the buffer? Returns `false` ONLY when some 3-gram of
    /// `atom` is absent — so the literal provably cannot appear (never a false
    /// negative). Conservatively `true` for atoms shorter than 3 bytes (not
    /// filterable). `nocase` selects the lowercased bitset; the caller must pass an
    /// already-lowercased atom in that case.
    pub fn maybe(&self, atom: &[u8], nocase: bool) -> bool {
        if atom.len() < 3 {
            return true;
        }
        let bits = if nocase { &self.nocase } else { &self.exact };
        atom.windows(3).all(|w| get(bits, gram3(w[0], w[1], w[2])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_and_absent() {
        let mut data = vec![0u8; 100_000];
        data.extend_from_slice(b"the_malware_marker_string");
        let pf = PresenceFilter::build(&data).unwrap();
        // Present literal → maybe true.
        assert!(pf.maybe(b"malware_marker", false));
        // A literal sharing no 3-gram with the buffer → false (skip scan).
        assert!(!pf.maybe(b"\xDE\xAD\xBE\xEF\x11\x22", false));
        // Nocase: uppercase data, lowercased atom.
        let mut d2 = vec![0u8; 100_000];
        d2.extend_from_slice(b"CertUtil.exe");
        let pf2 = PresenceFilter::build(&d2).unwrap();
        assert!(pf2.maybe(b"certutil", true)); // lowercased atom matches lowercased buffer
        assert!(!pf2.maybe(b"powershell", true));
    }

    #[test]
    fn no_false_negative_on_every_substring() {
        // Every substring of the buffer must report maybe=true (soundness).
        let mut data: Vec<u8> = (0..70_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        // ensure >= MIN_LEN
        while data.len() < 64 * 1024 + 100 { data.push(0); }
        let pf = PresenceFilter::build(&data).unwrap();
        for start in (0..data.len() - 8).step_by(97) {
            let atom = &data[start..start + 8];
            assert!(pf.maybe(atom, false), "false negative at {start}");
        }
    }

    #[test]
    fn small_buffer_no_filter() {
        assert!(PresenceFilter::build(b"short").is_none());
    }
}
