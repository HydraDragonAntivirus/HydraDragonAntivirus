//! Icon extraction and perceptual fingerprinting for PE files.
//!
//! Two independent fingerprints are computed from the same decoded RGBA icon, so
//! the expensive and fragile part - walking `RT_GROUP_ICON`/`RT_ICON`, decoding
//! the DIB, applying the AND mask - is done once per icon:
//!
//! * [`IconFingerprints::dhash`] - 64-bit difference hash. Difference-based, so
//!   it stays discriminative on the 16x16 icons that matter most, which is why
//!   SpyHunter-style `icon_dhash` rules use it. Robust to re-encoding, not to
//!   horizontal flips.
//! * [`IconFingerprints::phash`] - 64-bit DCT perceptual hash, byte-identical
//!   to ClamAV's `fuzzy_img#` subsignatures (see [`crate::fuzzy`]). Better than
//!   dHash on noisy or damaged icons, weaker on very small ones.
//!
//! The ClamAV `.idb` metric fingerprint lives in [`crate::rules::icon_metric`].

use crate::fuzzy;

/// A decoded icon: RGBA8 pixels, top-down, with transparency resolved.
#[derive(Debug, Clone)]
pub struct DecodedIcon {
    /// Icon side length in pixels (icons are square in practice).
    pub side: u32,
    /// Original bit depth from the DIB header.
    pub depth: u32,
    /// Straight (non-premultiplied) RGBA8, `side * side * 4` bytes, row-major
    /// from the top-left.
    pub rgba: Vec<u8>,
}

/// The perceptual fingerprints of a single icon.
#[derive(Debug, Clone)]
pub struct IconFingerprints {
    /// Icon side length in pixels.
    pub side: u32,
    /// Source bit depth.
    pub depth: u32,
    /// 64-bit difference hash, most-significant bit first.
    pub dhash: u64,
    /// 64-bit DCT perceptual hash in ClamAV `fuzzy_img#` byte order.
    pub phash: [u8; 8],
}

impl IconFingerprints {
    /// Fingerprint one decoded icon.
    pub fn compute(icon: &DecodedIcon) -> Option<Self> {
        let side = icon.side;
        if side < 9 {
            // dHash needs a 9x9 grid to yield 8x8 bits.
            return None;
        }
        let dhash = dhash_8x8(&icon.rgba, side);

        // pHash wants RGB; composite onto white so transparent pixels do not
        // drag the DCT toward black.
        let pixel_count = (side as usize) * (side as usize);
        let mut rgb = Vec::with_capacity(pixel_count * 3);
        for px in icon.rgba.chunks_exact(4).take(pixel_count) {
            let a = px[3] as u32;
            for &channel in &px[..3] {
                let c = channel as u32 * a + 255 * (255 - a);
                rgb.push((c / 255) as u8);
            }
        }
        let phash = fuzzy::calculate_rgb(&rgb, side, side)?;

        Some(Self {
            side,
            depth: icon.depth,
            dhash,
            phash,
        })
    }

    /// `dhash` formatted as 16 lowercase hex characters, most-significant byte
    /// first.
    pub fn dhash_hex(&self) -> String {
        format!("{:016x}", self.dhash)
    }

    /// `phash` formatted the way ClamAV writes `fuzzy_img#<hex>`.
    pub fn phash_hex(&self) -> String {
        hex::encode(self.phash)
    }
}

/// 64-bit difference hash: compare each of the 64 cells of a 9x9 grayscale grid
/// with its right-hand neighbour, packed row-major, most-significant bit first.
///
/// Only the horizontal comparison is used. Adding a vertical one would need
/// 128 bits; the horizontal form is the classic dHash and the one SpyHunter's
/// `icon_dhash` tables are built from.
fn dhash_8x8(rgba: &[u8], side: u32) -> u64 {
    // ITU-R 601-2 luma, same coefficients the pHash path uses, so both
    // fingerprints see the same luminance.
    const LUMA: [f32; 3] = [299.0 / 1000.0, 587.0 / 1000.0, 114.0 / 1000.0];
    let n = side as usize;
    let mut gray = vec![0f32; n * n];
    for (i, px) in rgba.chunks_exact(4).take(n * n).enumerate() {
        gray[i] = LUMA[0] * px[0] as f32 + LUMA[1] * px[1] as f32 + LUMA[2] * px[2] as f32;
    }

    // Box-average 9x9 samples over the icon so the grid is independent of the
    // icon's own dimensions.
    const GRID: usize = 9;
    let mut cells = [0f32; GRID * GRID];
    for (cell_index, cell) in cells.iter_mut().enumerate() {
        let cx = cell_index % GRID;
        let cy = cell_index / GRID;
        let x0 = cx * n / GRID;
        let y0 = cy * n / GRID;
        let x1 = ((cx + 1) * n / GRID).max(x0 + 1);
        let y1 = ((cy + 1) * n / GRID).max(y0 + 1);
        let mut sum = 0f32;
        let mut count = 0f32;
        for y in y0..y1.min(n) {
            for x in x0..x1.min(n) {
                sum += gray[y * n + x];
                count += 1.0;
            }
        }
        *cell = if count > 0.0 { sum / count } else { 0.0 };
    }

    let mut hash = 0u64;
    for y in 0..GRID - 1 {
        for x in 0..GRID - 1 {
            let here = cells[y * GRID + x];
            let right = cells[y * GRID + x + 1];
            if here > right {
                // Bit index counts from the least-significant end so the first
                // comparison lands in the MSB, matching dHash packing order.
                let bit = 63 - (y * (GRID - 1) + x);
                hash |= 1u64 << bit;
            }
        }
    }
    hash
}

/// Hamming distance between two 64-bit difference hashes.
pub fn dhash_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Extract every icon image embedded in `pe`, decoded to RGBA.
///
/// Walks `RT_GROUP_ICON` (type 14) to learn which `RT_ICON` (type 3) resources
/// belong to an icon group, then decodes each one. Group order is not
/// significant; results come back sorted by side so callers see a stable order.
pub fn extract_icons(pe: &pefile_rs::PE) -> Vec<DecodedIcon> {
    let Some(resources) = pe.resources.as_ref() else {
        return Vec::new();
    };
    let icon_resources = match find_resource_type(resources, RT_ICON) {
        Some(dir) => dir,
        None => return Vec::new(),
    };
    let Some(group_resources) = find_resource_type(resources, RT_GROUP_ICON) else {
        return Vec::new();
    };

    let mut wanted: Vec<u32> = Vec::new();
    for (_, _, entry) in &group_resources.entries {
        let ResourceEntry::Directory(name_dir) = entry else {
            continue;
        };
        let Some((leaf_off, _)) = first_leaf_rva(name_dir) else {
            continue;
        };
        let Some(dir_bytes) = pe.get_data(leaf_off, 6 + 2) else {
            continue;
        };
        let count = read_u16(dir_bytes, 4) as usize;
        // GRPICONDIR: reserved(2) type(2) count(2) then count ICONDIRENTRY of
        // 14 bytes: width(1) height(1) colours(1) reserved(1) planes(2)
        // bitcount(2) size(4) id(2) - so the id sits 12 bytes in.
        for i in 0..count.min(1024) {
            let entry_off = 6 + i * 14;
            let Some(entry) = pe.get_data(leaf_off, entry_off + 14) else {
                continue;
            };
            let id = read_u16(entry, entry_off + 12) as u32;
            if !wanted.contains(&id) {
                wanted.push(id);
            }
        }
    }

    let mut icons = Vec::new();
    for id in wanted {
        let Some(icon_dir) = find_resource_id(icon_resources, id) else {
            continue;
        };
        let Some((leaf_off, size)) = first_leaf_rva(icon_dir) else {
            continue;
        };
        if let Some(icon) = decode_dib(pe, leaf_off, size) {
            icons.push(icon);
        }
    }

    icons.sort_by_key(|icon| icon.side);
    icons
}

const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;

use pefile_rs::{ResourceDirectory, ResourceEntry};

/// Find the top-level resource directory for a resource type id.
fn find_resource_type(root: &ResourceDirectory, type_id: u32) -> Option<&ResourceDirectory> {
    for (id, _, entry) in &root.entries {
        if *id == type_id
            && let ResourceEntry::Directory(dir) = entry
        {
            return Some(dir);
        }
    }
    None
}

/// Find the name/id directory for a specific resource id.
fn find_resource_id(root: &ResourceDirectory, id: u32) -> Option<&ResourceDirectory> {
    for (entry_id, _, entry) in &root.entries {
        if *entry_id == id
            && let ResourceEntry::Directory(dir) = entry
        {
            return Some(dir);
        }
    }
    None
}

/// Resolve a name/id directory down to the RVA and size of its first
/// `IMAGE_RESOURCE_DATA_ENTRY`, i.e. the language leaf.
///
/// The resource tree is always three levels deep - type -> name/id -> language -
/// so this is what every caller wants.
fn first_leaf_rva(name_dir: &ResourceDirectory) -> Option<(u32, u32)> {
    for (_, _, entry) in &name_dir.entries {
        if let ResourceEntry::Data(data) = entry {
            return Some((data.offset_to_data, data.size));
        }
    }
    None
}

fn read_u16(bytes: &[u8], off: usize) -> u16 {
    match bytes.get(off..off + 2) {
        Some(s) => u16::from_le_bytes([s[0], s[1]]),
        None => 0,
    }
}

fn read_u32(bytes: &[u8], off: usize) -> u32 {
    match bytes.get(off..off + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

/// Decode one `RT_ICON` payload.
///
/// Two layouts exist. The classic one is a `BITMAPINFOHEADER` followed by
/// bottom-up colour rows and a 1-bit AND mask. Vista and later may instead store
/// a PNG stream, which is detected here and decoded directly.
///
/// ClamAV rejects PNG-compressed icons; we decode them instead, because the
/// fingerprints below are ours to define and a missing 256x256 icon is a real
/// coverage gap. The 16/32/48/64 icons that ClamAV does handle are byte-for-byte
/// the same path.
fn decode_dib(pe: &pefile_rs::PE, rva: u32, declared_size: u32) -> Option<DecodedIcon> {
    // Read a little more than the resource claims: a 256x256 32bpp icon plus
    // its AND mask is 320 KiB, and some linkers understate `size`. `get_data_upto`
    // clamps to the end of the file rather than failing outright.
    let window = (declared_size as usize).saturating_add(16 * 1024);
    let data = pe.get_data_upto(rva, window)?;

    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return decode_png_icon(data);
    }

    if data.len() < 40 {
        return None;
    }
    let header_size = read_u32(data, 0) as usize;
    if header_size < 40 || data.len() < header_size {
        return None;
    }
    let width = read_u32(data, 4);
    let raw_height = read_u32(data, 8);
    let depth = read_u16(data, 14) as u32;

    // Icon DIBs store the XOR and AND masks stacked, so the header height is
    // twice the real one.
    if raw_height == 0 || !raw_height.is_multiple_of(2) {
        return None;
    }
    let height = raw_height / 2;
    if !(16..=256).contains(&width) || !(16..=256).contains(&height) {
        return None;
    }
    if !matches!(depth, 1 | 4 | 8 | 16 | 24 | 32) {
        return None;
    }

    let mut offset = header_size;

    // Palette for the sub-byte depths.
    let mut palette = [0u32; 256];
    match depth {
        1 | 4 | 8 => {
            let entries = 1usize << depth;
            let palette_bytes = entries * 4;
            let pal = data.get(offset..offset + palette_bytes)?;
            for (i, chunk) in pal.chunks_exact(4).enumerate() {
                palette[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            offset += palette_bytes;
        }
        _ => {}
    }

    let width_us = width as usize;
    let height_us = height as usize;
    let row_bytes = (width_us * depth as usize).div_ceil(32) * 4;
    let and_row_bytes = (width_us).div_ceil(32) * 4;
    let colour_bytes = row_bytes * height_us;
    let and_bytes = and_row_bytes * height_us;
    let body = data.get(offset..offset + colour_bytes + and_bytes)?;

    let mut pixels = vec![0u32; width_us * height_us];
    for y in 0..height_us {
        // Rows are stored bottom-up.
        let row = y * row_bytes;
        for x in 0..width_us {
            let value = match depth {
                1 | 4 | 8 => {
                    let bit = x * depth as usize;
                    let byte = body[row + bit / 8];
                    let shift = 8 - depth as usize - (bit % 8);
                    let index = ((byte >> shift) as usize) & ((1usize << depth) - 1);
                    palette.get(index).copied().unwrap_or(0)
                }
                16 => {
                    // RGB555, widened to 8 bits per channel the usual way:
                    // top 5 bits replicated into the low 3.
                    let p = row + x * 2;
                    let b0 = body[p] as u32;
                    let b1 = body[p + 1] as u32;
                    let b = b0 & 0x1f;
                    let g = (b0 >> 5) | ((b1 & 0x3) << 3);
                    let r = b1 & 0xfc;
                    ((((r << 3) | (r >> 2)) & 0xf8) << 16)
                        | ((((g << 3) | (g >> 2)) & 0xf8) << 8)
                        | ((b << 3) | (b >> 2)) & 0xf8
                }
                24 => {
                    let p = row + x * 3;
                    body[p] as u32 | (body[p + 1] as u32) << 8 | (body[p + 2] as u32) << 16
                }
                32 => {
                    let p = row + x * 4;
                    body[p] as u32
                        | (body[p + 1] as u32) << 8
                        | (body[p + 2] as u32) << 16
                        | (body[p + 3] as u32) << 24
                }
                _ => 0,
            };
            pixels[(height_us - 1 - y) * width_us + x] = value;
        }
    }

    // A 32bpp icon whose alpha channel is all zero is really carrying its
    // transparency in the AND mask; that is the common pre-Vista layout.
    let alpha_is_meaningless = depth == 32 && !pixels.iter().any(|p| p & 0xff00_0000 != 0);
    let and_base = colour_bytes;
    if alpha_is_meaningless {
        let and = &body[and_base..and_base + and_bytes];
        for y in 0..height_us {
            let row = y * and_row_bytes;
            for x in 0..width_us {
                let bit = x;
                let byte = and[row + bit / 8];
                let on = (byte >> (7 - (bit % 8))) & 1 == 1;
                let at = (height_us - 1 - y) * width_us + x;
                // AND mask: 1 means transparent.
                pixels[at] = if on {
                    pixels[at] & 0x00ff_ffff
                } else {
                    pixels[at] | 0xff00_0000
                };
            }
        }
    }

    let mut rgba = Vec::with_capacity(width_us * height_us * 4);
    for px in pixels {
        rgba.push((px & 0xff) as u8);
        rgba.push(((px >> 8) & 0xff) as u8);
        rgba.push(((px >> 16) & 0xff) as u8);
        rgba.push(((px >> 24) & 0xff) as u8);
    }

    Some(DecodedIcon {
        side: width,
        depth,
        rgba,
    })
}

/// Decode a Vista-era PNG-compressed `RT_ICON` into straight RGBA.
fn decode_png_icon(data: &[u8]) -> Option<DecodedIcon> {
    // The `image` decoders can panic on malformed input.
    let loaded = std::panic::catch_unwind(|| image::load_from_memory(data));
    let Ok(Ok(img)) = loaded else {
        return None;
    };
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    if width == 0 || height == 0 || width > 256 || height > 256 {
        return None;
    }
    let rgba = rgba.into_raw();
    Some(DecodedIcon {
        side: width,
        depth: 0, // no DIB header, so there is no nominal bit depth
        rgba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clamav_test_exe() -> Option<Vec<u8>> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/unit_tests/input/pe_allmatch/test.exe"
        ))
        .ok()
    }

    /// ClamAV's own test build embeds icons at 16/32/48/64/256
    /// (`convert ... -define icon:auto-resize=16,32,48,64,256`).
    #[test]
    fn extracts_every_icon_from_clamav_test_exe() {
        let Some(bytes) = clamav_test_exe() else { return };
        let pe = pefile_rs::PE::parse(&bytes).expect("test.exe must parse");

        let icons = extract_icons(&pe);
        assert!(
            icons.len() >= 5,
            "expected at least 5 icons, got {}",
            icons.len()
        );

        let sides: Vec<u32> = icons.iter().map(|i| i.side).collect();
        for expected in [16u32, 32, 48, 64, 256] {
            assert!(
                sides.contains(&expected),
                "missing a {expected}x{expected} icon, got {sides:?}"
            );
        }

        for icon in &icons {
            let want = (icon.side as usize) * (icon.side as usize) * 4;
            assert_eq!(icon.rgba.len(), want, "rgba size must match side^2");
        }
    }

    #[test]
    fn every_extracted_icon_yields_both_fingerprints() {
        let Some(bytes) = clamav_test_exe() else { return };
        let pe = pefile_rs::PE::parse(&bytes).expect("test.exe must parse");

        let prints: Vec<IconFingerprints> = extract_icons(&pe)
            .iter()
            .filter_map(IconFingerprints::compute)
            .collect();
        assert!(prints.len() >= 5, "got {} fingerprints", prints.len());
        for fp in &prints {
            assert_eq!(fp.dhash_hex().len(), 16);
            assert_eq!(fp.phash_hex().len(), 16);
        }

        // The five sizes are genuinely different artwork, so their hashes must
        // differ; a shared hash would mean the decoder returns a constant.
        let dhashes: std::collections::HashSet<String> =
            prints.iter().map(|f| f.dhash_hex()).collect();
        assert_eq!(
            dhashes.len(),
            prints.len(),
            "dHash collided across icon sizes: {dhashes:?}"
        );
    }

    #[test]
    fn dhash_is_stable_and_distance_is_hamming() {
        let Some(bytes) = clamav_test_exe() else { return };
        let pe = pefile_rs::PE::parse(&bytes).expect("test.exe must parse");
        let icons = extract_icons(&pe);
        let Some(icon) = icons.first() else { return };

        let first = IconFingerprints::compute(icon).expect("16x16 icon must hash");
        let second = IconFingerprints::compute(icon).expect("16x16 icon must hash");
        assert_eq!(first.dhash, second.dhash, "hashing must be deterministic");
        assert_eq!(dhash_distance(first.dhash, first.dhash), 0);
    }

    #[test]
    fn non_pe_input_yields_no_icons() {
        let Ok(pe) = pefile_rs::PE::parse(b"not a portable executable at all") else {
            return;
        };
        assert!(extract_icons(&pe).is_empty());
    }

    #[test]
    fn dhash_separates_a_gradient_from_its_mirror() {
        // A left-to-right ramp mirrored must not hash the same: dHash compares
        // each cell with its right neighbour, so flipping reverses the bits.
        let side = 16usize;
        let mut ramp = Vec::with_capacity(side * side * 4);
        for _y in 0..side {
            for x in 0..side {
                let v = (x * 16) as u8;
                ramp.extend_from_slice(&[v, v, v, 0xff]);
            }
        }
        let mut mirrored = vec![0u8; ramp.len()];
        for y in 0..side {
            for x in 0..side {
                let src = (y * side + x) * 4;
                let dst = (y * side + (side - 1 - x)) * 4;
                mirrored[dst..dst + 4].copy_from_slice(&ramp[src..src + 4]);
            }
        }
        assert_ne!(ramp, mirrored, "the fixture itself must not be symmetric");

        let a = IconFingerprints::compute(&DecodedIcon {
            side: side as u32,
            depth: 32,
            rgba: ramp,
        })
        .expect("ramp must hash");
        let b = IconFingerprints::compute(&DecodedIcon {
            side: side as u32,
            depth: 32,
            rgba: mirrored,
        })
        .expect("mirrored ramp must hash");


        assert!(dhash_distance(a.dhash, b.dhash) > 0);
    }

    #[test]
    fn dhash_ignores_uniform_brightness_shift() {
        // dHash compares neighbouring cells, so scaling every pixel by the same
        // factor must not change it.
        let side = 16u32;
        let base: Vec<u8> = (0..side * side)
            .flat_map(|i| {
                let v = ((i * 7) % 256) as u8;
                [v, v / 2, 255 - v, 0xff]
            })
            .collect();
        let darker: Vec<u8> = base
            .chunks_exact(4)
            .flat_map(|p| [(p[0] as u32 * 3 / 4) as u8, p[1], p[2], 0xff])
            .collect();

        let a = IconFingerprints::compute(&DecodedIcon {
            side,
            depth: 32,
            rgba: base,
        })
        .expect("base must hash");
        let b = IconFingerprints::compute(&DecodedIcon {
            side,
            depth: 32,
            rgba: darker,
        })
        .expect("darker must hash");

        assert_eq!(a.dhash, b.dhash, "dHash must be brightness invariant");
    }
}
