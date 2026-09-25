//! Generic whole-buffer string/entropy features (20 inputs for `generic_trees.bin`).
//!
//! No file-type parsing: works on any bytes (PE, script, archive, raw blob).
//! Feature order is part of the model contract — do NOT reorder without
//! retraining (`train_generic_lgbm.py`):
//! ```text
//!  0 ln1p(file_len)
//!  1 overall_entropy (0..8)
//!  2 printable_ratio (0..1)
//!  3 zero_ratio (0..1)
//!  4 high_byte_ratio (>=0x80, 0..1)
//!  5 ln1p(string_count)      (ASCII runs >= 5)
//!  6 avg_string_len
//!  7 ln1p(max_string_len)
//!  8 ln1p(long_strings)      (len >= 64)
//!  9 ln1p(url_like)          (strings containing "://" or "http")
//! 10 ln1p(base64_like)       (len >= 20, base64 charset)
//! 11 ln1p(hex_like)          (len >= 16, hex charset, digit+letter mix)
//! 12 ln1p(suspicious_kw)     (powershell/cmd/mimikatz/... hits in strings)
//! 13 mz_header (0/1)
//! 14 pe_signature (0/1, "PE\0\0" with sane e_lfanew)
//! 15 script_keywords (0/1, eval/<script/powershell/wscript/cscript)
//! 16 archive_magic (0/1, PK\x03\x04 / 7z / Rar! / MZ already covered)
//! 17 high_entropy_block_ratio (fraction of 1 KiB blocks with entropy > 7.0)
//! 18 trailing_zero_ratio (trailing 0x00 / file_len)
//! 19 mean_byte_norm (mean byte / 255)
//! ```
//!
//! All outputs are finite (no NaN/inf). Extraction is capped to the first
//! 8 MiB so giant files stay fast and panic-free; feature 0 still uses the
//! real length and feature 18 uses the real tail.

use super::scanner::GENERIC_FEATURE_COUNT;

const CAP: usize = 8 * 1024 * 1024;
const BLOCK: usize = 1024;

#[inline]
fn ln1p(x: f32) -> f32 {
    if !x.is_finite() || x <= 0.0 {
        0.0
    } else {
        (x + 1.0).ln()
    }
}

#[inline]
fn clamp01(x: f32) -> f32 {
    if !x.is_finite() {
        0.0
    } else if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let len = data.len() as f32;
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut e = 0.0f32;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        e -= p * p.log2();
    }
    if e.is_finite() { e } else { 0.0 }
}

#[inline]
fn is_print(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\t' | b'\r' | b'\n')
}

fn is_base64_like(s: &[u8]) -> bool {
    if s.len() < 20 {
        return false;
    }
    let mut eq_seen = false;
    for &b in s {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                if eq_seen {
                    return false;
                }
            }
            b'=' => eq_seen = true,
            _ => return false,
        }
    }
    true
}

fn is_hex_like(s: &[u8]) -> bool {
    if s.len() < 16 {
        return false;
    }
    let mut digits = 0u32;
    let mut letters = 0u32;
    for &b in s {
        match b {
            b'0'..=b'9' => digits += 1,
            b'a'..=b'f' | b'A'..=b'F' => letters += 1,
            _ => return false,
        }
    }
    digits > 0 && letters > 0
}

fn lower_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn extract_generic_features(data: &[u8]) -> [f32; GENERIC_FEATURE_COUNT] {
    if data.is_empty() {
        return [0.0; GENERIC_FEATURE_COUNT];
    }
    let total_len = data.len();
    let buf: &[u8] = if data.len() > CAP { &data[..CAP] } else { data };
    let n = buf.len() as f32;

    // Single pass: byte stats.
    let mut printable = 0u64;
    let mut zeros = 0u64;
    let mut high = 0u64;
    let mut sum = 0u64;
    for &b in buf {
        sum += b as u64;
        if b == 0 {
            zeros += 1;
        }
        if b >= 0x80 {
            high += 1;
        }
        if is_print(b) {
            printable += 1;
        }
    }
    let entropy = shannon_entropy(buf);
    let printable_ratio = clamp01(printable as f32 / n);
    let zero_ratio = clamp01(zeros as f32 / n);
    let high_ratio = clamp01(high as f32 / n);
    let mean_norm = clamp01((sum as f32 / n) / 255.0);

    // String scan over capped buffer (ASCII runs >= 5, lowercased inline).
    let mut string_count = 0u32;
    let mut total_slen = 0u64;
    let mut max_slen = 0u32;
    let mut long_strings = 0u32;
    let mut url_like = 0u32;
    let mut b64_like = 0u32;
    let mut hex_like = 0u32;
    let mut susp_kw = 0u32;
    let mut cur: Vec<u8> = Vec::with_capacity(128);

    // Lowercase suspicious markers (checked against lowercased runs).
    const SUSP: &[&[u8]] = &[
        b"powershell", b"cmd.exe", b"mimikatz", b"meterpreter", b"cobalt",
        b"invoke-", b"downloadstring", b"frombase64", b"createobject",
        b"wscript", b"cscript", b"regsvr32", b"rundll32", b"psexec",
        b"sekurlsa", b"lsass", b"amsi", b"etw", b"vssadmin",
        b"bcdedit", b"wevtutil",
    ];

    let mut flush = |cur: &mut Vec<u8>| {
        if cur.len() < 5 {
            cur.clear();
            return;
        }
        string_count += 1;
        total_slen += cur.len() as u64;
        max_slen = max_slen.max(cur.len() as u32);
        if cur.len() >= 64 {
            long_strings += 1;
        }
        if lower_contains(cur, b"://") || lower_contains(cur, b"http") {
            url_like += 1;
        }
        if is_base64_like(cur) {
            b64_like += 1;
        }
        if is_hex_like(cur) {
            hex_like += 1;
        }
        for kw in SUSP {
            if lower_contains(cur, kw) {
                susp_kw += 1;
                break;
            }
        }
        cur.clear();
    };

    for &b in buf {
        if is_print(b) {
            cur.push(if b.is_ascii_uppercase() { b + 32 } else { b });
            if cur.len() > 4096 {
                flush(&mut cur);
            }
        } else {
            if !cur.is_empty() {
                flush(&mut cur);
            }
        }
    }
    if !cur.is_empty() {
        flush(&mut cur);
    }

    let avg_slen = if string_count > 0 {
        total_slen as f32 / string_count as f32
    } else {
        0.0
    };

    // Magic / keyword flags on capped head (cheap, no allocation).
    let mz_header = if buf.len() >= 2 && &buf[0..2] == b"MZ" { 1.0 } else { 0.0 };
    let mut pe_sig = 0.0;
    if buf.len() >= 64 && &buf[0..2] == b"MZ" {
        let e = u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;
        if e + 6 <= buf.len() && &buf[e..e + 4] == b"PE\0\0" {
            let nsec = u16::from_le_bytes([buf[e + 4], buf[e + 5]]) as usize;
            if nsec <= 96 {
                pe_sig = 1.0;
            }
        }
    }
    // Lowercased head scan for script keywords (bounded).
    let head_scan = &buf[..buf.len().min(65536)];
    let mut lower_head: Vec<u8> = Vec::with_capacity(head_scan.len().min(65536));
    for &b in head_scan {
        lower_head.push(if b.is_ascii_uppercase() { b + 32 } else { b });
    }
    let script_kw = if lower_contains(&lower_head, b"eval(")
        || lower_contains(&lower_head, b"<script")
        || lower_contains(&lower_head, b"powershell")
        || lower_contains(&lower_head, b"wscript")
        || lower_contains(&lower_head, b"cscript")
    {
        1.0
    } else {
        0.0
    };
    let archive_magic = if buf.len() >= 4
        && (&buf[0..4] == b"PK\x03\x04"
            || &buf[0..4] == b"PK\x05\x06"
            || &buf[0..4] == b"PK\x07\x08"
            || (buf.len() >= 6 && &buf[0..6] == b"7z\xBC\xAF\x27\x1C")
            || (buf.len() >= 7 && &buf[0..7] == b"Rar!\x1A\x07"))
    {
        1.0
    } else {
        0.0
    };

    // High-entropy 1 KiB blocks.
    let mut hot = 0u32;
    let mut blocks = 0u32;
    let mut off = 0usize;
    while off < buf.len() {
        let end = (off + BLOCK).min(buf.len());
        blocks += 1;
        if shannon_entropy(&buf[off..end]) > 7.0 {
            hot += 1;
        }
        off = end;
    }
    let hot_ratio = if blocks > 0 { clamp01(hot as f32 / blocks as f32) } else { 0.0 };

    // Trailing-zero ratio on the REAL file (not capped).
    let nz = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let trailing = data.len().saturating_sub(nz) as f32;
    let trailing_ratio = clamp01(trailing / total_len as f32);

    let mut out = [0.0f32; GENERIC_FEATURE_COUNT];
    out[0] = ln1p(total_len as f32);
    out[1] = entropy;
    out[2] = printable_ratio;
    out[3] = zero_ratio;
    out[4] = high_ratio;
    out[5] = ln1p(string_count as f32);
    out[6] = avg_slen;
    out[7] = ln1p(max_slen as f32);
    out[8] = ln1p(long_strings as f32);
    out[9] = ln1p(url_like as f32);
    out[10] = ln1p(b64_like as f32);
    out[11] = ln1p(hex_like as f32);
    out[12] = ln1p(susp_kw as f32);
    out[13] = mz_header;
    out[14] = pe_sig;
    out[15] = script_kw;
    out[16] = archive_magic;
    out[17] = hot_ratio;
    out[18] = trailing_ratio;
    out[19] = mean_norm;
    for v in out.iter_mut() {
        if !v.is_finite() {
            *v = 0.0;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zeros() {
        assert_eq!(extract_generic_features(&[]), [0.0; GENERIC_FEATURE_COUNT]);
    }

    #[test]
    fn finite_and_sane() {
        let f = extract_generic_features(b"MZ\x90\x00powershell http://example.com AAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(f.len(), GENERIC_FEATURE_COUNT);
        assert!(f.iter().all(|v| v.is_finite()));
        assert_eq!(f[13], 1.0);
        assert!(f[5] > 0.0);
    }
}
