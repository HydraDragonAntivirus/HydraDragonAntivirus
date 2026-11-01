use crate::models::Hashes;
use digest::Digest;
use md5::Md5;
use sha2::Sha256;

pub fn hashes(bytes: &[u8]) -> Hashes {
    Hashes {
        sha256: sha256_hex(bytes),
        md5: md5_hex(bytes),
        sha1: sha1_hex(bytes),
        crc32: crc32_hex(bytes),
    }
}

pub fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(Md5::digest(bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn crc32_hex(bytes: &[u8]) -> String {
    format!("{:08x}", crc32(bytes))
}

/// IEEE 802.3 CRC-32 (polynomial 0xEDB88320, reflected).
pub fn crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                if c & 1 != 0 {
                    c = 0xEDB8_8320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };

    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[idx];
    }
    !crc
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(sha1(bytes))
}

/// FIPS 180-4 SHA-1 digest.
pub fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        sha1_compress(&mut h0, &mut h1, &mut h2, &mut h3, &mut h4, chunk);
    }

    let rem = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    if rem.len() < 56 {
        tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_compress(&mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &tail[..64]);
    } else {
        tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
        sha1_compress(&mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &tail[..64]);
        sha1_compress(&mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &tail[64..128]);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn sha1_compress(h0: &mut u32, h1: &mut u32, h2: &mut u32, h3: &mut u32, h4: &mut u32, block: &[u8]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = *h0;
    let mut b = *h1;
    let mut c = *h2;
    let mut d = *h3;
    let mut e = *h4;

    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
            _ => (b ^ c ^ d, 0xCA62_C1D6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    *h0 = h0.wrapping_add(a);
    *h1 = h1.wrapping_add(b);
    *h2 = h2.wrapping_add(c);
    *h3 = h3.wrapping_add(d);
    *h4 = h4.wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_and_sha1_match_standard_vectors() {
        assert_eq!(crc32_hex(b""), "00000000");
        assert_eq!(crc32_hex(b"123456789"), "cbf43926");
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }
}
