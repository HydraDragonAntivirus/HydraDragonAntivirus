//! Password-protected ZIP for sharing samples (MalwareBazaar convention: password
//! `infected`). Single stored entry with traditional PKWARE (ZipCrypto) encryption, so
//! Windows Explorer, 7-Zip and Python's zipfile can all open it. No extra crates.

use crate::analyzer::{crc32, crc32_step};

pub const SAMPLE_PASSWORD: &[u8] = b"infected";

struct Keys(u32, u32, u32);

impl Keys {
    fn new(password: &[u8]) -> Self {
        let mut k = Keys(0x1234_5678, 0x2345_6789, 0x3456_7890);
        for &b in password {
            k.update(b);
        }
        k
    }
    fn update(&mut self, b: u8) {
        self.0 = crc32_step(self.0, b);
        self.1 = self.1.wrapping_add(self.0 & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
        self.2 = crc32_step(self.2, (self.1 >> 24) as u8);
    }
    fn stream_byte(&self) -> u8 {
        let t = (self.2 | 2) & 0xFFFF;
        ((t.wrapping_mul(t ^ 1)) >> 8) as u8
    }
    fn encrypt(&mut self, p: u8) -> u8 {
        let c = p ^ self.stream_byte();
        self.update(p);
        c
    }
}

fn dos_time_date() -> (u16, u16) {
    use chrono::{Datelike, Timelike};
    let n = chrono::Utc::now();
    let time = ((n.hour() as u16) << 11) | ((n.minute() as u16) << 5) | ((n.second() as u16) / 2);
    let year = (n.year() - 1980).clamp(0, 127) as u16;
    let date = (year << 9) | ((n.month() as u16) << 5) | n.day() as u16;
    (time, date)
}

/// Builds a one-file ZIP: `entry_name` containing `data`, encrypted with `password`.
pub fn build(entry_name: &str, data: &[u8], password: &[u8]) -> Vec<u8> {
    let crc = crc32(data);
    let name = entry_name.as_bytes();
    let (time, date) = dos_time_date();

    // 12-byte encryption header: 11 pseudo-random bytes + high byte of the CRC.
    let mut seed = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1))
        ^ (crc as u64).rotate_left(17);
    let mut header = [0u8; 12];
    for b in header.iter_mut().take(11) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed >> 24) as u8;
    }
    header[11] = (crc >> 24) as u8;

    let mut keys = Keys::new(password);
    let mut payload = Vec::with_capacity(12 + data.len());
    payload.extend(header.iter().map(|&b| keys.encrypt(b)));
    payload.extend(data.iter().map(|&b| keys.encrypt(b)));
    let comp = payload.len() as u32;
    let uncomp = data.len() as u32;

    let mut out = Vec::with_capacity(payload.len() + 128 + name.len() * 2);
    let le16 = |v: &mut Vec<u8>, x: u16| v.extend_from_slice(&x.to_le_bytes());
    let le32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());

    // local file header
    le32(&mut out, 0x0403_4b50);
    le16(&mut out, 20); // version needed
    le16(&mut out, 0x0001); // encrypted
    le16(&mut out, 0); // stored
    le16(&mut out, time);
    le16(&mut out, date);
    le32(&mut out, crc);
    le32(&mut out, comp);
    le32(&mut out, uncomp);
    le16(&mut out, name.len() as u16);
    le16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(&payload);

    // central directory
    let cd_start = out.len() as u32;
    le32(&mut out, 0x0201_4b50);
    le16(&mut out, 20); // made by
    le16(&mut out, 20); // needed
    le16(&mut out, 0x0001);
    le16(&mut out, 0);
    le16(&mut out, time);
    le16(&mut out, date);
    le32(&mut out, crc);
    le32(&mut out, comp);
    le32(&mut out, uncomp);
    le16(&mut out, name.len() as u16);
    le16(&mut out, 0); // extra
    le16(&mut out, 0); // comment
    le16(&mut out, 0); // disk
    le16(&mut out, 0); // internal attrs
    le32(&mut out, 0); // external attrs
    le32(&mut out, 0); // local header offset
    out.extend_from_slice(name);
    let cd_size = out.len() as u32 - cd_start;

    // end of central directory
    le32(&mut out, 0x0605_4b50);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 1);
    le16(&mut out, 1);
    le32(&mut out, cd_size);
    le32(&mut out, cd_start);
    le16(&mut out, 0);
    out
}
