/// MD5 / SHA-1 collision-attack detectors.
///
/// SHA-1 uses Marc Stevens' sha1dc (counter-cryptanalysis of SHAttered /
/// chosen-prefix). MD5 uses published-collision fingerprints plus the
/// HashClash fastcoll / unicoll message-block differentials so a single
/// crafted sample that embeds a colliding pair is caught without hashing
/// the file as MD5 for identity.

/// First 16 bytes of Wang Xiaoyun's 2004 identical-prefix MD5 collision (M0).
const WANG2004_PREFIX: &[u8] = &[
    0xd1, 0x31, 0xdd, 0x02, 0xc5, 0xe6, 0xee, 0xc4, 0x69, 0x3d, 0x9a, 0x06, 0x98, 0xaf, 0xf9, 0x5c,
];

fn le_word(block: &[u8], i: usize) -> u32 {
    let o = i * 4;
    u32::from_le_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]])
}

fn xor_words_equal_except(a: &[u8], b: &[u8], diffs: &[(usize, u32)]) -> bool {
    if a.len() < 64 || b.len() < 64 {
        return false;
    }
    for i in 0..16 {
        let d = le_word(a, i) ^ le_word(b, i);
        match diffs.iter().find(|(idx, _)| *idx == i) {
            Some((_, expected)) => {
                if d != *expected {
                    return false;
                }
            }
            None => {
                if d != 0 {
                    return false;
                }
            }
        }
    }
    true
}

/// HashClash fastcoll: δM4 = 2^31, δM11 = 2^15, δM14 = 2^31.
fn is_fastcoll_pair(a: &[u8], b: &[u8]) -> bool {
    xor_words_equal_except(a, b, &[(4, 0x8000_0000), (11, 0x0000_8000), (14, 0x8000_0000)])
}

/// HashClash unicoll (single-block): δM8 = 2^31, rest equal — used as a
/// near-collision step in chosen-prefix constructions (Flame-class).
fn is_unicoll_pair(a: &[u8], b: &[u8]) -> bool {
    xor_words_equal_except(a, b, &[(8, 0x8000_0000)])
}

/// Real HashClash collision blocks look random (high entropy). Installer
/// binaries contain long zero / 0xFF padding runs where 15 equal words +
/// a single high-bit flip happens by chance (e.g. 64x 0x00 next to
/// 32x 0x00 + 0x80000000 + 28x 0x00 at offset 7816704 of a 72MB
/// installer). Gate the differential match on block plausibility so
/// such padding is never reported as a collision attack.
fn plausible_block(block: &[u8]) -> bool {
    debug_assert!(block.len() == 64);
    // At least 25% non-zero bytes (random block: ~63.75).
    let nonzero = block.iter().filter(|&&b| b != 0).count();
    if nonzero < 16 {
        return false;
    }
    // At least 16 distinct byte values (random block: ~57).
    // Sort-free distinct count over 256 values.
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in block {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    if distinct < 16 {
        return false;
    }
    // Bit population away from extremes (random block: ~256).
    let pop: u32 = block.iter().map(|b| b.count_ones()).sum();
    if pop < 64 || pop > 448 {
        return false;
    }
    // No long run of a single repeated byte (random block: never 16x).
    let mut run = 1usize;
    for w in block.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run >= 16 {
                return false;
            }
        } else {
            run = 1;
        }
    }
    true
}

fn plausible_pair(a: &[u8], b: &[u8]) -> bool {
    plausible_block(a) && plausible_block(b)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub struct CollisionFinding {
    pub name: &'static str,
    pub details: String,
}

pub fn detect_md5_collision(data: &[u8]) -> Option<CollisionFinding> {
    if data.len() >= 16 && contains(data, WANG2004_PREFIX) {
        return Some(CollisionFinding {
            name: "Crypto.MD5.CollisionAttack.Wang2004",
            details: "Published Wang 2004 identical-prefix MD5 collision block".to_string(),
        });
    }

    if data.len() < 128 {
        return None;
    }
    let mut off = 0usize;
    while off + 128 <= data.len() {
        let a = &data[off..off + 64];
        let b = &data[off + 64..off + 128];
        if is_fastcoll_pair(a, b) {
            if plausible_pair(a, b) {
                return Some(CollisionFinding {
                    name: "Crypto.MD5.CollisionAttack.Fastcoll",
                    details: format!(
                        "HashClash fastcoll MD5 block pair at offset {off} (δM4=2^31, δM11=2^15, δM14=2^31)"
                    ),
                });
            }
        } else if is_unicoll_pair(a, b) {
            if plausible_pair(a, b) {
                return Some(CollisionFinding {
                    name: "Crypto.MD5.CollisionAttack.Unicoll",
                    details: format!("HashClash unicoll MD5 near-collision pair at offset {off} (δM8=2^31)"),
                });
            }
        }
        off += 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic high-entropy 64-byte block (mimics real HashClash
    /// collision blocks). xorshift64* — passes `plausible_block`.
    fn deterministic_block(seed: u64) -> [u8; 64] {
        let mut x = seed;
        let mut out = [0u8; 64];
        for i in 0..64 {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            let v = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u8;
            // Avoid exact 0 so nonzero count stays maximal; still ~uniform.
            out[i] = if v == 0 { 0x5A } else { v };
        }
        // Break any accidental 16x run (practically impossible, but cheap).
        for i in 2..64 {
            if out[i] == out[i - 1] && out[i] == out[i - 2] {
                out[i] ^= 0x3C;
                if out[i] == 0 {
                    out[i] = 0xA5;
                }
            }
        }
        out
    }

    #[test]
    fn wang_prefix_hits() {
        let mut buf = vec![0u8; 64];
        buf[..16].copy_from_slice(WANG2004_PREFIX);
        let hit = detect_md5_collision(&buf).unwrap();
        assert!(hit.name.contains("Wang2004"));
    }

    #[test]
    fn fastcoll_pair_hits() {
        let a = deterministic_block(0x1234_5678_9ABC_DEF1);
        assert!(plausible_block(&a));
        let mut b = a;
        // δM4 = 2^31, δM11 = 2^15, δM14 = 2^31 (LE byte flips).
        b[4 * 4 + 3] ^= 0x80;
        b[11 * 4 + 1] ^= 0x80;
        b[14 * 4 + 3] ^= 0x80;
        assert!(plausible_block(&b));
        let mut data = Vec::from(a);
        data.extend_from_slice(&b);
        let hit = detect_md5_collision(&data).unwrap();
        assert!(hit.name.contains("Fastcoll"));
    }

    #[test]
    fn unicoll_pair_hits_when_plausible() {
        let a = deterministic_block(0x0BAD_F00D_CAFE_1234);
        assert!(plausible_block(&a));
        let mut b = a;
        b[8 * 4 + 3] ^= 0x80; // δM8 = 2^31
        assert!(plausible_block(&b));
        let mut data = Vec::from(a);
        data.extend_from_slice(&b);
        let hit = detect_md5_collision(&data).unwrap();
        assert!(hit.name.contains("Unicoll"));
    }

    /// Regression: IncendiumInstaller.exe offset 7816704 — 64x 0x00 next
    /// to 32x 0x00 + 0x80000000 + 28x 0x00. Must NOT report.
    #[test]
    fn zero_padding_unicoll_rejected() {
        let a = [0u8; 64];
        let mut b = [0u8; 64];
        b[8 * 4 + 3] = 0x80;
        assert!(is_unicoll_pair(&a, &b));
        assert!(!plausible_pair(&a, &b));
        let mut data = Vec::from(a);
        data.extend_from_slice(&b);
        assert!(detect_md5_collision(&data).is_none());
    }

    #[test]
    fn zero_padding_fastcoll_rejected() {
        let a = [0u8; 64];
        let mut b = [0u8; 64];
        b[4 * 4 + 3] = 0x80;
        b[11 * 4 + 1] = 0x80;
        b[14 * 4 + 3] = 0x80;
        assert!(is_fastcoll_pair(&a, &b));
        let mut data = Vec::from(a);
        data.extend_from_slice(&b);
        assert!(detect_md5_collision(&data).is_none());
    }

    #[test]
    fn ff_padding_unicoll_rejected() {
        let a = [0xFFu8; 64];
        let mut b = [0xFFu8; 64];
        b[8 * 4 + 3] ^= 0x80; // 0xFF -> 0x7F, diff still 2^31
        assert!(is_unicoll_pair(&a, &b));
        let mut data = Vec::from(a);
        data.extend_from_slice(&b);
        assert!(detect_md5_collision(&data).is_none());
    }

    #[test]
    fn random_bytes_clean() {
        let data = (0u8..200).collect::<Vec<_>>();
        assert!(detect_md5_collision(&data).is_none());
    }
}
