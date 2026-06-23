//! Image fuzzy hash (perceptual pHash) — a faithful port of ClamAV's own Rust
//! implementation in `libclamav_rust/src/fuzzy_hash.rs`
//! (`fuzzy_hash_calculate_image`). It uses the same crates (`image`, `rustdct`)
//! and the same steps, so the resulting 64-bit hash is byte-identical to the
//! values stored in `fuzzy_img#<hash>` logical subsignatures.
//!
//! Algorithm (matching ClamAV, which itself reproduces the Python `imagehash`
//! `phash()`):
//!   1. decode the image (auto-detect: PNG/JPEG/GIF/BMP/WebP/...),
//!   2. drop alpha, custom grayscale with ITU-R 601-2 luma coefficients (the
//!      Pillow "L" conversion), rounding rather than truncating,
//!   3. resize to 32x32 with Lanczos3,
//!   4. 2-D DCT-2 (columns then rows, each result doubled to match
//!      `scipy.fftpack.dct`),
//!   5. take the top-left 8x8 low-frequency block,
//!   6. threshold each value against the 64-value median → 64 bits,
//!   7. pack big-endian into 8 bytes.
//!
//! Only an exact (hamming distance 0) match is supported — same limitation as
//! ClamAV's current `fuzzy_hash_check`.

use image::{imageops::FilterType::Lanczos3, DynamicImage, GrayImage, Luma};
use rustdct::DctPlanner;

/// ITU-R 601-2 luma coefficients (Pillow's "L" conversion), matching ClamAV.
/// `L = R*299/1000 + G*587/1000 + B*114/1000`.
const SRGB_LUMA: [f32; 3] = [299.0 / 1000.0, 587.0 / 1000.0, 114.0 / 1000.0];

#[inline]
fn rgb_to_luma(rgb: &[u8]) -> u8 {
    let l = SRGB_LUMA[0] * rgb[0] as f32
        + SRGB_LUMA[1] * rgb[1] as f32
        + SRGB_LUMA[2] * rgb[2] as f32;
    l.round() as u8
}

/// In-place 32x32 transpose into `output` (replaces the `transpose` crate).
#[inline]
fn transpose32(input: &[f32], output: &mut [f32]) {
    for i in 0..32 {
        for j in 0..32 {
            output[j * 32 + i] = input[i * 32 + j];
        }
    }
}

/// Compute the 64-bit image fuzzy hash of `buffer`, or `None` if it is not a
/// decodable image. Byte order matches ClamAV's `fuzzy_img#` hash exactly.
pub fn calculate_image(buffer: &[u8]) -> Option<[u8; 8]> {
    // The `image` decoders can panic on malformed input — guard like ClamAV does.
    let loaded = std::panic::catch_unwind(|| image::load_from_memory(buffer));
    let og_image = match loaded {
        Ok(Ok(img)) => img,
        _ => return None,
    };

    // Drop the alpha channel (if any).
    let buff_rgb8 = og_image.to_rgb8();

    // Custom grayscale: ITU-R 601-2 coefficients, rounded (matches ClamAV/Pillow).
    let (width, height) = buff_rgb8.dimensions();
    let mut gray = GrayImage::new(width, height);
    for (x, y, pixel) in buff_rgb8.enumerate_pixels() {
        gray.put_pixel(x, y, Luma([rgb_to_luma(&pixel.0)]));
    }

    // Shrink to 32x32 (1024 pixels) with Lanczos3.
    let image_gs = DynamicImage::ImageLuma8(gray);
    let image_small = DynamicImage::resize_exact(&image_gs, 32, 32, Lanczos3);

    // Pixels as f32.
    let mut imgbuff_f32 = image_small.to_luma32f().into_raw();
    if imgbuff_f32.len() != 1024 {
        return None;
    }

    // --- 2-D DCT-2 in place, matching ClamAV exactly. ---
    let dct2 = DctPlanner::new().plan_dct2(32);
    let buffer1: &mut [f32] = imgbuff_f32.as_mut_slice();
    let buffer2: &mut [f32] = &mut [0.0; 1024];

    // Transpose so we run DCT on the columns first.
    transpose32(buffer1, buffer2);
    for (row_in, row_out) in buffer2.chunks_mut(32).zip(buffer1.chunks_mut(32)) {
        dct2.process_dct2_with_scratch(row_in, row_out);
    }
    // Double to match scipy.fftpack.dct() (as ClamAV notes).
    buffer2.iter_mut().for_each(|f| *f *= 2.0);

    // Transpose back and run DCT on the rows.
    transpose32(buffer2, buffer1);
    for (row_in, row_out) in buffer1.chunks_mut(32).zip(buffer2.chunks_mut(32)) {
        dct2.process_dct2_with_scratch(row_in, row_out);
    }
    buffer1.iter_mut().for_each(|f| *f *= 2.0);

    // Top-left 8x8 low-frequency block of the 32x32 DCT array.
    let dct_low_freq: Vec<f32> = buffer1
        .chunks(32)
        .take(8)
        .flat_map(|row| row.iter().take(8).copied())
        .collect();
    if dct_low_freq.len() != 64 {
        return None;
    }

    // Median of the 64 low-frequency values.
    let mut sorted = dct_low_freq.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = (sorted[31] + sorted[32]) / 2.0;

    // Threshold to bits, then pack big-endian into 8 bytes (ClamAV's packing:
    // for each 8-bit chunk, the first bit is the MSB).
    let mut hash = [0u8; 8];
    for (ci, chunk) in dct_low_freq.chunks(8).enumerate() {
        let mut byte = 0u8;
        for (n, &val) in chunk.iter().rev().enumerate() {
            if val > median {
                byte |= 1 << n;
            }
        }
        hash[ci] = byte;
    }
    Some(hash)
}

/// Parse a `fuzzy_img#<hex>[#<distance>]` subsignature into its 8-byte hash.
/// Returns `Err(reason)` for an unknown algorithm, a malformed hash, or a
/// non-zero hamming distance (which ClamAV itself does not support yet).
pub fn parse_fuzzy_img(raw: &str) -> Result<[u8; 8], String> {
    let mut parts = raw.split('#');
    let algorithm = parts.next().unwrap_or("");
    if algorithm != "fuzzy_img" {
        return Err(format!("unknown fuzzy hash algorithm: {algorithm}"));
    }
    let hash = parts.next().ok_or_else(|| "missing fuzzy hash".to_string())?;
    let distance: u32 = match parts.next() {
        Some(d) => d
            .parse()
            .map_err(|_| format!("invalid hamming distance: {d}"))?,
        None => 0,
    };
    if distance != 0 {
        return Err("non-zero hamming distances are not supported".to_string());
    }
    if hash.len() != 16 {
        return Err("image fuzzy hash must be 16 hex characters".to_string());
    }
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("invalid hash hex: {hash}"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        // ClamAV's logo.png test vector.
        assert_eq!(
            parse_fuzzy_img("fuzzy_img#af2ad01ed42993c7").unwrap(),
            [0xaf, 0x2a, 0xd0, 0x1e, 0xd4, 0x29, 0x93, 0xc7]
        );
        // Explicit zero distance is allowed.
        assert!(parse_fuzzy_img("fuzzy_img#af2ad01ed42993c7#0").is_ok());
    }

    #[test]
    fn parse_rejects() {
        // Non-zero hamming distance (ClamAV doesn't support it yet).
        assert!(parse_fuzzy_img("fuzzy_img#af2ad01ed42993c7#1").is_err());
        // Wrong hash length (ClamAV: "must be 16 characters").
        assert!(parse_fuzzy_img("fuzzy_img#abcdef").is_err());
        // Unknown algorithm.
        assert!(parse_fuzzy_img("fuzzy_xyz#af2ad01ed42993c7").is_err());
        // Non-hex.
        assert!(parse_fuzzy_img("fuzzy_img#zzzzzzzzzzzzzzzz").is_err());
    }
}
