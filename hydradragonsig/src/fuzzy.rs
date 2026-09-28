//! Image fuzzy hash (perceptual pHash), byte-identical to the `fuzzy_img#<hash>`
//! logical subsignatures in ClamAV's signature databases.
//!
//! Ported from `hydradragonclamav/src/fuzzy.rs`, which is itself a faithful port
//! of ClamAV's `libclamav_rust/src/fuzzy_hash.rs` (`fuzzy_hash_calculate_image`).
//! Same crates (`image`, `rustdct`), same steps, so the 64-bit hash equals the
//! values ClamAV stores:
//!
//!   1. decode the image (PNG/JPEG/GIF/BMP/WebP/...),
//!   2. drop alpha, grayscale with ITU-R 601-2 luma coefficients (Pillow's "L"),
//!      rounding rather than truncating,
//!   3. resize to 32x32 with Lanczos3,
//!   4. 2-D DCT-II (columns then rows, each result doubled to match
//!      `scipy.fftpack.dct`),
//!   5. take the top-left 8x8 low-frequency block,
//!   6. threshold each value against the 64-value median -> 64 bits,
//!   7. pack big-endian into 8 bytes.
//!
//! Only an exact (hamming distance 0) match is supported, matching ClamAV's
//! current `fuzzy_hash_check`.

use image::{imageops::FilterType::Lanczos3, DynamicImage, GrayImage, Luma};
use rustdct::DctPlanner;

/// ITU-R 601-2 luma coefficients (Pillow's "L" conversion), matching ClamAV:
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

/// Quick check: is `buffer` plausibly an image the `image` crate can decode?
///
/// Without this, every scanned binary would be handed to `image::load_from_memory`,
/// which spends hundreds of milliseconds proving that a large blob matches no
/// known magic.
fn plausible_image_magic(buffer: &[u8]) -> bool {
    const MAGIC_LEN: usize = 8;
    if buffer.len() < MAGIC_LEN {
        return false;
    }
    let m = &buffer[..MAGIC_LEN];
    // PNG, JPEG, GIF, BMP, WebP, TIFF, ICO, PNM (PBM/PGM/PPM), AVIF
    m.starts_with(b"\x89PNG\r\n\x1a\n")
        || m.starts_with(b"\xff\xd8\xff")
        || m.starts_with(b"GIF8")
        || m.starts_with(b"BM")
        || m.starts_with(b"RIFF")
        || m.starts_with(b"II*\x00")
        || m.starts_with(b"MM\x00*")
        || m.starts_with(b"\x00\x00\x00\x0c") // ICO
        || m.starts_with(b"P")
        || m.starts_with(b"ftyp")
        || m.starts_with(b"\x00\x00\x00\x1c") // AVIF-ish
}

/// Compute the 64-bit image fuzzy hash of `buffer`, or `None` if it is not a
/// decodable image. Byte order matches ClamAV's `fuzzy_img#` hash exactly.
pub fn calculate_image(buffer: &[u8]) -> Option<[u8; 8]> {
    // Reject non-image data before handing it to the `image` crate, which is
    // slow to reject large buffers that happen not to be images.
    if !plausible_image_magic(buffer) {
        return None;
    }
    if buffer.len() > 50_000_000 {
        return None; // real images are rarely this large; skip to avoid OOM/timeout
    }
    // The `image` decoders can panic on malformed input - guard like ClamAV does.
    let loaded = std::panic::catch_unwind(|| image::load_from_memory(buffer));
    let og_image = match loaded {
        Ok(Ok(img)) => img,
        _ => return None,
    };

    let rgb = og_image.to_rgb8();
    let (width, height) = rgb.dimensions();
    let mut pixels = Vec::with_capacity((width * height) as usize);
    for pixel in rgb.pixels() {
        pixels.extend_from_slice(&pixel.0);
    }
    calculate_rgb(&pixels, width, height)
}

/// Perceptual hash of already-decoded 8-bit RGB pixels.
///
/// This is the same computation [`calculate_image`] performs, split out so that
/// images which never existed as a file - a PE's embedded icon, an icon inside
/// an archive member - can be hashed with the identical code path and therefore
/// produce ClamAV-compatible values.
pub fn calculate_rgb(pixels: &[u8], width: u32, height: u32) -> Option<[u8; 8]> {
    if width == 0 || height == 0 {
        return None;
    }
    let expected = (width as usize).saturating_mul(height as usize).saturating_mul(3);
    if pixels.len() < expected {
        return None;
    }

    // Custom grayscale: ITU-R 601-2 coefficients, rounded (matches ClamAV/Pillow).
    let mut gray = GrayImage::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let at = ((y as usize) * (width as usize) + (x as usize)) * 3;
            let l = rgb_to_luma(&pixels[at..at + 3]);
            gray.put_pixel(x, y, Luma([l]));
        }
    }

    // Shrink to 32x32 (1024 pixels) with Lanczos3.
    let image_gs = DynamicImage::ImageLuma8(gray);
    let image_small = DynamicImage::resize_exact(&image_gs, 32, 32, Lanczos3);

    // Pixels as f32.
    let mut imgbuff_f32 = image_small.to_luma32f().into_raw();
    if imgbuff_f32.len() != 1024 {
        return None;
    }

    // --- 2-D DCT-II in place, matching ClamAV exactly. ---
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

/// Hamming distance between two fuzzy hashes.
pub fn hamming_distance(a: &[u8; 8], b: &[u8; 8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
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

    #[test]
    fn hamming_distance_counts_differing_bits() {
        assert_eq!(hamming_distance(&[0; 8], &[0; 8]), 0);
        assert_eq!(hamming_distance(&[0xff; 8], &[0x00; 8]), 64);
        assert_eq!(hamming_distance(&[0b1010_1010; 8], &[0; 8]), 4 * 8);
    }

    #[test]
    fn non_image_bytes_are_rejected_without_decoding() {
        // A PE header is large but not an image; the magic fast-path must reject it.
        let mut pe = vec![0u8; 0x400];
        pe[0] = b'M';
        pe[1] = b'Z';
        assert!(calculate_image(&pe).is_none());
        assert!(calculate_image(b"MZ").is_none());
        assert!(calculate_image(&[]).is_none());
    }

    /// Cross-check against ClamAV: the hash of `clamav/logo.png` is the value
    /// ClamAV's own test suite asserts for that file.
    #[test]
    fn matches_clamav_reference_hash() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../clamav/logo.png");
        let Ok(bytes) = std::fs::read(path) else {
            // The ClamAV source tree is not always present next to the crate.
            return;
        };
        let hash = calculate_image(&bytes).expect("logo.png must decode");
        assert_eq!(hex::encode(hash), "af2ad01ed42993c7");
    }
}
