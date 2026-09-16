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
            return Some(CollisionFinding {
                name: "Crypto.MD5.CollisionAttack.Fastcoll",
                details: format!(
                    "HashClash fastcoll MD5 block pair at offset {off} (δM4=2^31, δM11=2^15, δM14=2^31)"
                ),
            });
        }
        if is_unicoll_pair(a, b) {
            return Some(CollisionFinding {
                name: "Crypto.MD5.CollisionAttack.Unicoll",
                details: format!("HashClash unicoll MD5 near-collision pair at offset {off} (δM8=2^31)"),
            });
        }
        off += 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wang_prefix_hits() {
        let mut buf = vec![0u8; 64];
        buf[..16].copy_from_slice(WANG2004_PREFIX);
        let hit = detect_md5_collision(&buf).unwrap();
        assert!(hit.name.contains("Wang2004"));
    }

    #[test]
    fn fastcoll_pair_hits() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        a[4 * 4 + 3] = 0x00;
        b[4 * 4 + 3] = 0x80;
        a[11 * 4 + 1] = 0x00;
        b[11 * 4 + 1] = 0x80;
        a[14 * 4 + 3] = 0x00;
        b[14 * 4 + 3] = 0x80;
        let mut data = Vec::from(a);
        data.extend_from_slice(&b);
        let hit = detect_md5_collision(&data).unwrap();
        assert!(hit.name.contains("Fastcoll"));
    }

    #[test]
    fn random_bytes_clean() {
        let data = (0u8..200).collect::<Vec<_>>();
        assert!(detect_md5_collision(&data).is_none());
    }
}
