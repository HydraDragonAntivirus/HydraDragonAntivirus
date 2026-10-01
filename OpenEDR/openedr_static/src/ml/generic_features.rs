//! Generic whole-buffer pure byte, padding & entropy evasion features (20 inputs for `generic_trees.bin`).
//!
//! NO string keywords, NO hardcoded keyword lists, NO regexes.
//! Pure byte statistics, null-padding ratios, global & chunk-level Shannon entropy.
//!
//! Feature contract (matches `train_generic_lgbm.py` EXACTLY):
//! ```text
//!  0  len_log              ln1p(total_len)
//!  1  content_len_log      ln1p(stripped_len)
//!  2  whole_entropy        Shannon entropy of whole buffer (0..8)
//!  3  content_entropy      Shannon entropy of stripped buffer (0..8)
//!  4  entropy_delta        max(0, whole_entropy - content_entropy)
//!  5  padding_ratio        0x00 count / total_len (whole buffer)
//!  6  trailing_pad_ratio   trailing 0x00 run / total_len
//!  7  lead_pad_ratio       leading 0x00 run / total_len
//!  8  stripped_zero_ratio  0x00 count in stripped / stripped_len
//!  9  mean_byte_norm       mean(all_bytes) / 255.0
//! 10  std_byte_norm        stddev(all_bytes) / 128.0
//! 11  printable_ratio      printable ASCII / stripped_len
//! 12  high_byte_ratio      bytes >= 0x80 / stripped_len
//! 13  control_byte_ratio   control bytes / stripped_len
//! 14  chunk_entropy_var    variance of Shannon entropy across 4KB chunks
//! 15  max_chunk_entropy    max entropy among 4KB chunks
//! 16  min_chunk_entropy    min entropy among 4KB chunks
//! 17  has_mz               1.0 if starts with b"MZ" else 0.0
//! 18  has_pe_sig           1.0 if PE signature valid else 0.0
//! 19  has_zip_magic        1.0 if starts with b"PK\x03\x04" else 0.0
//! ```

use super::scanner::GENERIC_FEATURE_COUNT;

const CAP: usize = 8 * 1024 * 1024;
const CHUNK_SIZE: usize = 4096;

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

pub fn extract_generic_features(data: &[u8]) -> [f32; GENERIC_FEATURE_COUNT] {
    if data.len() < 2 {
        return [0.0; GENERIC_FEATURE_COUNT];
    }
    let total_len = data.len();
    let buf: &[u8] = if data.len() > CAP { &data[..CAP] } else { data };
    let n = buf.len() as f32;

    // 1. Whole buffer stats
    let mut counts = [0u64; 256];
    let mut byte_sum = 0u64;
    for &b in buf {
        counts[b as usize] += 1;
        byte_sum += b as u64;
    }

    let zero_count = counts[0];
    let padding_ratio = clamp01(zero_count as f32 / n);

    let trailing = data.iter().rev().take_while(|&&b| b == 0).count();
    let trailing_pad_ratio = clamp01(trailing as f32 / total_len as f32);

    let leading = data.iter().take(65536).take_while(|&&b| b == 0).count();
    let lead_pad_ratio = clamp01(leading as f32 / total_len as f32);

    let mean_b = byte_sum as f32 / n;
    let mean_byte_norm = clamp01(mean_b / 255.0);

    let mut var_b = 0.0f32;
    for (b, &c) in counts.iter().enumerate() {
        if c > 0 {
            let diff = b as f32 - mean_b;
            var_b += (diff * diff) * (c as f32);
        }
    }
    let std_byte_norm = clamp01((var_b / n).sqrt() / 128.0);
    let whole_entropy = shannon_entropy(buf);

    // 2. Stripped buffer stats (strip trailing nulls)
    let mut real_end = buf.len();
    while real_end > 0 && buf[real_end - 1] == 0 {
        real_end -= 1;
    }
    let stripped = if real_end > 0 { &buf[..real_end] } else { &buf[..buf.len().min(64)] };
    let sn = stripped.len() as f32;

    let content_entropy = shannon_entropy(stripped);
    let entropy_delta = {
        let d = whole_entropy - content_entropy;
        if d > 0.0 && d.is_finite() { d } else { 0.0 }
    };

    let mut s_counts = [0u64; 256];
    let mut printable = 0u64;
    let mut high_bytes = 0u64;
    let mut ctrl_bytes = 0u64;
    for &b in stripped {
        s_counts[b as usize] += 1;
        if is_print(b) {
            printable += 1;
        }
        if b >= 0x80 {
            high_bytes += 1;
        }
        if b < 0x20 && b != 0 && b != b'\t' && b != b'\r' && b != b'\n' {
            ctrl_bytes += 1;
        }
    }

    let stripped_zero_ratio = clamp01(s_counts[0] as f32 / sn);
    let printable_ratio = clamp01(printable as f32 / sn);
    let high_byte_ratio = clamp01(high_bytes as f32 / sn);
    let control_byte_ratio = clamp01(ctrl_bytes as f32 / sn);

    // 3. Chunk-level entropy profiling across 4KB blocks
    let mut chunk_ents = Vec::with_capacity((stripped.len() / CHUNK_SIZE) + 1);
    let mut offset = 0;
    while offset < stripped.len() {
        let end = (offset + CHUNK_SIZE).min(stripped.len());
        let chunk = &stripped[offset..end];
        if chunk.len() >= 256 {
            chunk_ents.push(shannon_entropy(chunk));
        }
        offset = end;
    }

    let (chunk_entropy_var, max_chunk_entropy, min_chunk_entropy) = if !chunk_ents.is_empty() {
        let avg_ce = chunk_ents.iter().sum::<f32>() / chunk_ents.len() as f32;
        let var_ce = chunk_ents.iter().map(|&ce| (ce - avg_ce) * (ce - avg_ce)).sum::<f32>() / chunk_ents.len() as f32;
        let max_ce = chunk_ents.iter().cloned().fold(0.0f32, f32::max);
        let min_ce = chunk_ents.iter().cloned().fold(8.0f32, f32::min);
        (var_ce, max_ce, min_ce)
    } else {
        (0.0, content_entropy, content_entropy)
    };

    // 4. Binary format markers (cheap, header only)
    let has_mz = if data.len() >= 2 && &data[0..2] == b"MZ" { 1.0 } else { 0.0 };
    let mut has_pe = 0.0;
    if has_mz == 1.0 && data.len() >= 64 {
        let e = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if e + 6 <= data.len() && &data[e..e + 4] == b"PE\0\0" {
            let nsec = u16::from_le_bytes([data[e + 4], data[e + 5]]) as usize;
            if nsec <= 96 {
                has_pe = 1.0;
            }
        }
    }
    let has_zip = if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" { 1.0 } else { 0.0 };

    // Assemble 20 features
    let mut out = [0.0f32; GENERIC_FEATURE_COUNT];
    out[0]  = ln1p(total_len as f32);
    out[1]  = ln1p(sn);
    out[2]  = whole_entropy;
    out[3]  = content_entropy;
    out[4]  = entropy_delta;
    out[5]  = padding_ratio;
    out[6]  = trailing_pad_ratio;
    out[7]  = lead_pad_ratio;
    out[8]  = stripped_zero_ratio;
    out[9]  = mean_byte_norm;
    out[10] = std_byte_norm;
    out[11] = printable_ratio;
    out[12] = high_byte_ratio;
    out[13] = control_byte_ratio;
    out[14] = chunk_entropy_var;
    out[15] = max_chunk_entropy;
    out[16] = min_chunk_entropy;
    out[17] = has_mz;
    out[18] = has_pe;
    out[19] = has_zip;
    out
}
