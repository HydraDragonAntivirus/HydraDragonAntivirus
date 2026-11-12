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
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize()
}

/// Incremental SHA-1, for digests over non-contiguous ranges (the Authenticode
/// image hash skips the checksum and the security directory entry).
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            h: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let [h0, h1, h2, h3, h4] = &mut self.h;
        sha1_compress(h0, h1, h2, h3, h4, block);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for chunk in blocks {
            self.compress(chunk);
        }
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total.wrapping_mul(8);
        let rem = self.buf_len;
        let mut tail = [0u8; 128];
        tail[..rem].copy_from_slice(&self.buf[..rem]);
        tail[rem] = 0x80;
        if rem < 56 {
            tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
            self.compress(&tail[..64]);
        } else {
            tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
            self.compress(&tail[..64]);
            self.compress(&tail[64..128]);
        }
        let mut out = [0u8; 20];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn sha1_compress(h0: &mut u32, h1: &mut u32, h2: &mut u32, h3: &mut u32, h4: &mut u32, block: &[u8]) {
    let mut w = [0u32; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        let off = i * 4;
        *word = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
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

    #[test]
    fn streaming_sha1_matches_one_shot_for_every_split() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128, 300] {
            let want = sha1(&data[..len]);
            for split in 0..=len {
                let mut h = Sha1::new();
                h.update(&data[..split]);
                h.update(&data[split..len]);
                assert_eq!(h.finalize(), want, "len {len} split {split}");
            }
        }
    }
}
