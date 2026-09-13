//! PE icon matcher — a faithful port of ClamAV's `pe_icons.c` (the `USE_FLOATS`
//! build path): walk `RT_GROUP_ICON`/`RT_ICON` resources, decode the icon bitmap,
//! scale it, compute the `getmetrics` fingerprint, and compare against the loaded
//! `.idb` fingerprints (`matchpoint`) within the group set a signature requests.
//!
//! This evaluates a logical signature's `IconGroup1`/`IconGroup2` TDB constraint
//! (`matchicon` in matcher.c): the constraint holds iff some icon in the PE
//! matches an `.idb` fingerprint belonging to the requested groups.

use crate::icon::{IconMatcher, IconMetric};
use crate::pe::Section;

// ---- low-level reads + RVA mapping (ClamAV cli_rawaddr) --------------------

#[inline]
fn ru16(data: &[u8], off: u32) -> Option<u16> {
    let o = off as usize;
    data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
#[inline]
fn ru32(data: &[u8], off: u32) -> Option<u32> {
    let o = off as usize;
    data.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn cli_rawaddr(rva: u32, sections: &[Section], hdr_size: u32, fsize: usize) -> Option<u32> {
    if rva < hdr_size {
        if (rva as usize) >= fsize {
            return None;
        }
        return Some(rva);
    }
    for s in sections.iter().rev() {
        let rsz = s.raw_size as u32;
        if rsz != 0 && s.virtual_address <= rva && rsz > (rva - s.virtual_address) {
            return Some((rva - s.virtual_address).wrapping_add(s.raw_start as u32));
        }
    }
    None
}

/// Port of ClamAV `findres`: collect the data-entry RVAs (`res_rva + lang_offs`)
/// of every resource matching `by_type` (and `by_name`, or `0xffffffff` for any),
/// capped at 64.
fn find_resources(
    data: &[u8],
    res_rva: u32,
    sections: &[Section],
    hdr_size: u32,
    by_type: u32,
    by_name: u32,
) -> Vec<u32> {
    let fsize = data.len();
    let mut leaves = Vec::new();
    let Some(resdir) = cli_rawaddr(res_rva, sections, hdr_size, fsize) else {
        return leaves;
    };
    if data.get(resdir as usize..resdir as usize + 16).is_none() {
        return leaves;
    }
    let mut type_entry = resdir + 16 + (ru16(data, resdir + 12).unwrap_or(0) as u32) * 8;
    let mut type_cnt = ru16(data, resdir + 14).unwrap_or(0);
    while type_cnt > 0 {
        type_cnt -= 1;
        let (Some(typ), Some(type_offs)) = (ru32(data, type_entry), ru32(data, type_entry + 4))
        else {
            return leaves;
        };
        if typ == by_type && (type_offs >> 31) != 0 {
            let Some(rd2) =
                cli_rawaddr(res_rva + (type_offs & 0x7fff_ffff), sections, hdr_size, fsize)
            else {
                return leaves;
            };
            if data.get(rd2 as usize..rd2 as usize + 16).is_none() {
                return leaves;
            }
            let named = ru16(data, rd2 + 12).unwrap_or(0);
            let (mut name_entry, mut name_cnt) = if by_name == 0xffff_ffff {
                (rd2 + 16, named as u32 + ru16(data, rd2 + 14).unwrap_or(0) as u32)
            } else {
                // skip named, iterate id entries only
                (rd2 + 16 + named as u32 * 8, ru16(data, rd2 + 14).unwrap_or(0) as u32)
            };
            while name_cnt > 0 {
                name_cnt -= 1;
                let (Some(name), Some(name_offs)) =
                    (ru32(data, name_entry), ru32(data, name_entry + 4))
                else {
                    return leaves;
                };
                if (by_name == 0xffff_ffff || name == by_name) && (name_offs >> 31) != 0 {
                    let Some(rd3) = cli_rawaddr(
                        res_rva + (name_offs & 0x7fff_ffff),
                        sections,
                        hdr_size,
                        fsize,
                    ) else {
                        return leaves;
                    };
                    if data.get(rd3 as usize..rd3 as usize + 16).is_none() {
                        return leaves;
                    }
                    let mut lang_cnt = ru16(data, rd3 + 12).unwrap_or(0) as u32
                        + ru16(data, rd3 + 14).unwrap_or(0) as u32;
                    let mut lang_entry = rd3 + 16;
                    while lang_cnt > 0 {
                        lang_cnt -= 1;
                        let Some(lang_offs) = ru32(data, lang_entry + 4) else {
                            return leaves;
                        };
                        if (lang_offs >> 31) == 0 {
                            leaves.push(res_rva + lang_offs);
                            if leaves.len() == 64 {
                                return leaves;
                            }
                        }
                        lang_entry += 8;
                    }
                }
                name_entry += 8;
            }
            return leaves;
        }
        type_entry += 8;
    }
    leaves
}

// ---- color math (USE_FLOATS path) -----------------------------------------

#[inline]
fn hsv(c: u32) -> (u32, u32, u32, u32, u32, u32) {
    let r = (c >> 16) & 0xff;
    let g = (c >> 8) & 0xff;
    let b = c & 0xff;
    let min = r.min(g.min(b));
    let max = r.max(g.max(b));
    let v = max;
    let delta = max - min;
    let s = if delta == 0 { 0 } else { 255 * delta / max };
    (r, g, b, s, v, delta)
}

fn lab(r: f64, g: f64, b: f64) -> (f64, f64, f64) {
    let conv = |mut c: f64| -> f64 {
        c /= 255.0;
        if c > 0.04045 {
            c = ((c + 0.055) / 1.055).powf(2.4);
        } else {
            c /= 12.92;
        }
        c * 100.0
    };
    let r = conv(r);
    let g = conv(g);
    let b = conv(b);
    let mut x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 95.047;
    let mut y = (r * 0.2126 + g * 0.7152 + b * 0.0722) / 100.000;
    let mut z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 108.883;
    let f = |t: f64| if t > 0.008856 { t.powf(1.0 / 3.0) } else { 7.787 * t + 16.0 / 116.0 };
    x = f(x);
    y = f(y);
    z = f(z);
    (116.0 * y - 16.0, 500.0 * (x - y), 200.0 * (y - z))
}

fn labdiff(rgb: u32) -> f64 {
    const L1: f64 = 53.192777691077211;
    const A1: f64 = 0.0031420942181448197;
    const B1: f64 = -0.0062075877844014471;
    let r = ((rgb >> 16) & 0xff) as f64;
    let g = ((rgb >> 8) & 0xff) as f64;
    let b = (rgb & 0xff) as f64;
    let (l2, a2, b2) = lab(r, g, b);
    ((L1 - l2).powi(2) + (A1 - a2).powi(2) + (B1 - b2).powi(2)).sqrt()
}

// ---- getmetrics -----------------------------------------------------------

/// Computed fingerprint (ClamAV `struct icomtr`), same fields as [`IconMetric`].
#[derive(Default)]
struct Metrics {
    color_avg: [u32; 3],
    color_x: [u32; 3],
    color_y: [u32; 3],
    gray_avg: [u32; 3],
    gray_x: [u32; 3],
    gray_y: [u32; 3],
    bright_avg: [u32; 3],
    bright_x: [u32; 3],
    bright_y: [u32; 3],
    dark_avg: [u32; 3],
    dark_x: [u32; 3],
    dark_y: [u32; 3],
    edge_avg: [u32; 3],
    edge_x: [u32; 3],
    edge_y: [u32; 3],
    noedge_avg: [u32; 3],
    noedge_x: [u32; 3],
    noedge_y: [u32; 3],
    rsum: u32,
    gsum: u32,
    bsum: u32,
    ccount: u32,
}

const GAUSSK: [u32; 3] = [1, 2, 1];

/// Port of `getmetrics`. `imagedata` is `side*side` ARGB pixels (modified in place).
fn getmetrics(side: u32, imagedata: &mut [u32]) -> Metrics {
    let side = side as usize;
    let ksize = side / 4;
    let mut res = Metrics::default();
    let mut col = vec![0u32; side * side]; // tmp[..]
    let mut light = vec![0u32; side * side]; // tmp[side*side..]

    // color presence helper
    let count_color = |res: &mut Metrics, r: u32, g: u32, b: u32, delta: u32| {
        res.ccount += 1;
        res.rsum += (100 - 100 * (g as i32 - b as i32).unsigned_abs() as i32 / delta as i32) as u32;
        res.gsum += (100 - 100 * (r as i32 - b as i32).unsigned_abs() as i32 / delta as i32) as u32;
        res.bsum += (100 - 100 * (r as i32 - g as i32).unsigned_abs() as i32 / delta as i32) as u32;
    };

    for y in 0..=side - ksize {
        for x in 0..=side - ksize {
            let mut colsum;
            let mut lightsum;
            if x == 0 && y == 0 {
                colsum = 0;
                lightsum = 0;
                for yk in 0..ksize {
                    for xk in 0..ksize {
                        let (r, g, b, s, v, delta) = hsv(imagedata[yk * side + xk]);
                        colsum += ((s * s * v) as f64).sqrt() as u32;
                        lightsum += v;
                        if s > 85 && v > 85 {
                            count_color(&mut res, r, g, b, delta);
                        }
                    }
                }
            } else if x != 0 {
                colsum = col[y * side + x - 1];
                lightsum = light[y * side + x - 1];
                for yk in 0..ksize {
                    let (_, _, _, s, v, _) = hsv(imagedata[(y + yk) * side + x - 1]);
                    colsum -= ((s * s * v) as f64).sqrt() as u32;
                    lightsum -= v;
                    let (r, g, b, s, v, delta) = hsv(imagedata[(y + yk) * side + x + ksize - 1]);
                    colsum += ((s * s * v) as f64).sqrt() as u32;
                    lightsum += v;
                    if (y == 0 || yk == ksize - 1) && s > 85 && v > 85 {
                        count_color(&mut res, r, g, b, delta);
                    }
                }
            } else {
                colsum = col[(y - 1) * side];
                lightsum = light[(y - 1) * side];
                for xk in 0..ksize {
                    let (_, _, _, s, v, _) = hsv(imagedata[(y - 1) * side + xk]);
                    colsum -= ((s * s * v) as f64).sqrt() as u32;
                    lightsum -= v;
                    let (r, g, b, s, v, delta) = hsv(imagedata[(y + ksize - 1) * side + xk]);
                    colsum += ((s * s * v) as f64).sqrt() as u32;
                    lightsum += v;
                    if s > 85 && v > 85 {
                        count_color(&mut res, r, g, b, delta);
                    }
                }
            }
            col[y * side + x] = colsum;
            light[y * side + x] = lightsum;
        }
    }

    // top-3 non-overlapping areas for color/gray/bright/dark
    let overlap = |x: usize, y: usize, xs: &[u32; 3], ys: &[u32; 3], n: usize| -> bool {
        for j in 0..n {
            if x + ksize > xs[j] as usize
                && x < xs[j] as usize + ksize
                && y + ksize > ys[j] as usize
                && y < ys[j] as usize + ksize
            {
                return true;
            }
        }
        false
    };
    for i in 0..3 {
        res.gray_avg[i] = 0xffff_ffff;
        res.dark_avg[i] = 0xffff_ffff;
        for y in 0..side - ksize {
            for x in 0..side - 1 - ksize {
                let colsum = col[y * side + x];
                let lightsum = light[y * side + x];
                if colsum > res.color_avg[i] && !overlap(x, y, &res.color_x, &res.color_y, i) {
                    res.color_avg[i] = colsum;
                    res.color_x[i] = x as u32;
                    res.color_y[i] = y as u32;
                }
                if colsum < res.gray_avg[i] && !overlap(x, y, &res.gray_x, &res.gray_y, i) {
                    res.gray_avg[i] = colsum;
                    res.gray_x[i] = x as u32;
                    res.gray_y[i] = y as u32;
                }
                if lightsum > res.bright_avg[i] && !overlap(x, y, &res.bright_x, &res.bright_y, i) {
                    res.bright_avg[i] = lightsum;
                    res.bright_x[i] = x as u32;
                    res.bright_y[i] = y as u32;
                }
                if lightsum < res.dark_avg[i] && !overlap(x, y, &res.dark_x, &res.dark_y, i) {
                    res.dark_avg[i] = lightsum;
                    res.dark_x[i] = x as u32;
                    res.dark_y[i] = y as u32;
                }
            }
        }
    }
    let k2 = (ksize * ksize) as u32;
    for i in 0..3 {
        res.color_avg[i] /= k2;
        res.gray_avg[i] /= k2;
        res.bright_avg[i] /= k2;
        res.dark_avg[i] /= k2;
    }
    let mut bwonly = false;
    if res.ccount * 100 / side as u32 / side as u32 > 5 {
        res.rsum /= res.ccount;
        res.gsum /= res.ccount;
        res.bsum /= res.ccount;
        res.ccount = res.ccount * 100 / side as u32 / side as u32;
    } else {
        res.ccount = 0;
        res.rsum = 0;
        res.gsum = 0;
        res.bsum = 0;
        bwonly = true;
    }

    // Sobel edge detection (USE_FLOATS): labdiff → gradients → normalize
    let mut sobel = vec![0f64; side * side];
    for i in 0..side * side {
        sobel[i] = labdiff(imagedata[i]);
    }
    let mut imax = 0u32;
    for y in 1..side - 1 {
        for x in 1..side - 1 {
            let gx = sobel[(y - 1) * side + (x - 1)] + sobel[y * side + (x - 1)] * 2.0
                + sobel[(y + 1) * side + (x - 1)]
                - sobel[(y - 1) * side + (x + 1)]
                - sobel[y * side + (x + 1)] * 2.0
                - sobel[(y + 1) * side + (x + 1)];
            let gy = sobel[(y - 1) * side + (x - 1)] + sobel[(y - 1) * side + x] * 2.0
                + sobel[(y - 1) * side + (x + 1)]
                - sobel[(y + 1) * side + (x - 1)]
                - sobel[(y + 1) * side + x] * 2.0
                - sobel[(y + 1) * side + (x + 1)];
            let sob = (gx * gx + gy * gy).sqrt() as u32;
            col[y * side + x] = sob;
            if sob > imax {
                imax = sob;
            }
        }
    }
    if imax != 0 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let c = col[y * side + x] * 255 / imax;
                imagedata[y * side + x] = 0xff00_0000 | c | (c << 8) | (c << 16);
            }
        }
    }
    // black borders
    for x in 0..side {
        imagedata[x] = 0xff00_0000;
        imagedata[(side - 1) * side + x] = 0xff00_0000;
    }
    for y in 0..side {
        imagedata[y * side] = 0xff00_0000;
        imagedata[y * side + side - 1] = 0xff00_0000;
    }

    // gaussian blur (separable 1-2-1), horizontal then vertical
    for y in 1..side - 1 {
        for x in 1..side - 1 {
            let mut sum = 0u32;
            let mut tot = 0u32;
            let lo = (x as i32).min(1);
            let hi = ((side - 1 - x) as i32).min(1);
            for disp in -lo..=hi {
                let c = imagedata[y * side + (x as i32 + disp) as usize] & 0xff;
                sum += c * GAUSSK[(disp + 1) as usize];
                tot += GAUSSK[(disp + 1) as usize];
            }
            sum /= tot;
            imagedata[y * side + x] &= 0xff;
            imagedata[y * side + x] |= sum << 8;
        }
    }
    for y in 1..side - 1 {
        for x in 1..side - 1 {
            let mut sum = 0u32;
            let mut tot = 0u32;
            let lo = (y as i32).min(1);
            let hi = ((side - 1 - y) as i32).min(1);
            for disp in -lo..=hi {
                let c = (imagedata[(y as i32 + disp) as usize * side + x] >> 8) & 0xff;
                sum += c * GAUSSK[(disp + 1) as usize];
                tot += GAUSSK[(disp + 1) as usize];
            }
            sum /= tot;
            imagedata[y * side + x] = 0xff00_0000 | sum | (sum << 8) | (sum << 16);
        }
    }

    // edge area sums (sliding window of the blurred edge map)
    for y in 0..=side - ksize {
        for x in 0..=side - 1 - ksize {
            let mut sum;
            if x == 0 && y == 0 {
                sum = 0;
                for yk in 0..ksize {
                    for xk in 0..ksize {
                        sum += imagedata[(y + yk) * side + x + xk] & 0xff;
                    }
                }
            } else if x != 0 {
                sum = col[y * side + x - 1];
                for yk in 0..ksize {
                    sum -= imagedata[(y + yk) * side + x - 1] & 0xff;
                    sum += imagedata[(y + yk) * side + x + ksize - 1] & 0xff;
                }
            } else {
                sum = col[(y - 1) * side];
                for xk in 0..ksize {
                    sum -= imagedata[(y - 1) * side + xk] & 0xff;
                    sum += imagedata[(y + ksize - 1) * side + xk] & 0xff;
                }
            }
            col[y * side + x] = sum;
        }
    }

    // best/worst 3 (or 6 when bwonly) edged areas
    let nareas = 3 * (bwonly as usize + 1);
    let mut edge_avg = [0u32; 6];
    let mut edge_x = [0u32; 6];
    let mut edge_y = [0u32; 6];
    let mut noedge_avg = [0u32; 6];
    let mut noedge_x = [0u32; 6];
    let mut noedge_y = [0u32; 6];
    for i in 0..nareas {
        edge_avg[i] = 0;
        noedge_avg[i] = 0xffff_ffff;
        for y in 0..side - ksize {
            for x in 0..side - 1 - ksize {
                let sum = col[y * side + x];
                let ov = |xs: &[u32; 6], ys: &[u32; 6]| -> bool {
                    for j in 0..i {
                        if x + ksize > xs[j] as usize
                            && x < xs[j] as usize + ksize
                            && y + ksize > ys[j] as usize
                            && y < ys[j] as usize + ksize
                        {
                            return true;
                        }
                    }
                    false
                };
                if sum > edge_avg[i] && !ov(&edge_x, &edge_y) {
                    edge_avg[i] = sum;
                    edge_x[i] = x as u32;
                    edge_y[i] = y as u32;
                }
                if sum < noedge_avg[i] && !ov(&noedge_x, &noedge_y) {
                    noedge_avg[i] = sum;
                    noedge_x[i] = x as u32;
                    noedge_y[i] = y as u32;
                }
            }
        }
    }
    for i in 0..3 {
        res.edge_avg[i] = edge_avg[i] / k2;
        res.edge_x[i] = edge_x[i];
        res.edge_y[i] = edge_y[i];
        res.noedge_avg[i] = noedge_avg[i] / k2;
        res.noedge_x[i] = noedge_x[i];
        res.noedge_y[i] = noedge_y[i];
    }
    if bwonly {
        for i in 0..3 {
            res.color_avg[i] = edge_avg[i + 3] / k2;
            res.color_x[i] = edge_x[i + 3];
            res.color_y[i] = edge_y[i + 3];
            res.gray_avg[i] = noedge_avg[i + 3] / k2;
            res.gray_x[i] = edge_x[i + 3];
            res.gray_y[i] = edge_y[i + 3];
        }
    }
    res
}

// ---- matchpoint -----------------------------------------------------------

fn matchpoint(
    side: u32,
    x1: &[u32; 3],
    y1: &[u32; 3],
    avg1: &[u32; 3],
    x2: &[u32; 3],
    y2: &[u32; 3],
    avg2: &[u32; 3],
    max: u32,
) -> u32 {
    let ksize = side / 4;
    let mut matchv = 0u32;
    for i in 0..3 {
        let mut best = 0u32;
        for j in 0..3 {
            let diffx = x1[i] as i32 - x2[j] as i32;
            let diffy = y1[i] as i32 - y2[j] as i32;
            let mut diff = ((diffx * diffx + diffy * diffy) as f64).sqrt() as u32;
            if diff > ksize * 3 / 4 || (avg1[i] as i32 - avg2[j] as i32).unsigned_abs() > max / 5 {
                continue;
            }
            diff = 100 - diff * 60 / (ksize * 3 / 4);
            if diff > best {
                best = diff;
            }
        }
        matchv += best;
    }
    matchv / 3
}

#[allow(clippy::too_many_arguments)]
fn matchbwpoint(
    side: u32,
    x1a: &[u32; 3],
    y1a: &[u32; 3],
    avg1a: &[u32; 3],
    x1b: &[u32; 3],
    y1b: &[u32; 3],
    avg1b: &[u32; 3],
    x2a: &[u32; 3],
    y2a: &[u32; 3],
    avg2a: &[u32; 3],
    x2b: &[u32; 3],
    y2b: &[u32; 3],
    avg2b: &[u32; 3],
) -> u32 {
    let ksize = side / 4;
    let mut x1 = [0u32; 6];
    let mut y1 = [0u32; 6];
    let mut a1 = [0u32; 6];
    let mut x2 = [0u32; 6];
    let mut y2 = [0u32; 6];
    let mut a2 = [0u32; 6];
    for i in 0..3 {
        x1[i] = x1a[i];
        y1[i] = y1a[i];
        a1[i] = avg1a[i];
        x2[i] = x2a[i];
        y2[i] = y2a[i];
        a2[i] = avg2a[i];
        x1[i + 3] = x1b[i];
        y1[i + 3] = y1b[i];
        a1[i + 3] = avg1b[i];
        x2[i + 3] = x2b[i];
        y2[i + 3] = y2b[i];
        a2[i + 3] = avg2b[i];
    }
    let mut matchv = 0u32;
    for i in 0..6 {
        let mut best = 0u32;
        for j in 0..6 {
            let diffx = x1[i] as i32 - x2[j] as i32;
            let diffy = y1[i] as i32 - y2[j] as i32;
            let mut diff = ((diffx * diffx + diffy * diffy) as f64).sqrt() as u32;
            if diff > ksize * 3 / 4 || (a1[i] as i32 - a2[j] as i32).unsigned_abs() > 255 / 5 {
                continue;
            }
            diff = 100 - diff * 60 / (ksize * 3 / 4);
            if diff > best {
                best = diff;
            }
        }
        matchv += best;
    }
    matchv / 6
}

// ---- group set ------------------------------------------------------------

/// Which icon groups a signature requests (ClamAV `icon_groupset`), 256 bits each.
struct GroupSet {
    v: [[u64; 4]; 2],
}

impl GroupSet {
    /// Build from `IconGroup1`/`IconGroup2` names; `None`/`"*"` selects all groups
    /// (ClamAV passes `grp ? grp : "*"`).
    fn build(matcher: &IconMatcher, grp1: Option<&str>, grp2: Option<&str>) -> Self {
        let mut v = [[0u64; 4]; 2];
        for (t, grp) in [grp1, grp2].into_iter().enumerate() {
            match grp {
                None | Some("*") => v[t] = [!0; 4],
                Some(name) => {
                    if let Some(idx) = matcher.group_names[t].iter().position(|g| g == name) {
                        v[t][idx / 64] |= 1u64 << (idx % 64);
                    }
                }
            }
        }
        GroupSet { v }
    }

    #[inline]
    fn contains(&self, t: usize, group: u32) -> bool {
        let (i, j) = ((group / 64) as usize, group % 64);
        i < 4 && (self.v[t][i] & (1u64 << j)) != 0
    }
}

// ---- parseicon + orchestration --------------------------------------------

/// Decode an icon bitmap at `rva`, compute its metrics, and test it against the
/// `.idb` set within `set`. Returns `true` on a confident match (ClamAV CL_VIRUS).
fn parseicon(
    data: &[u8],
    rva: u32,
    sections: &[Section],
    hdr_size: u32,
    matcher: &IconMatcher,
    set: &GroupSet,
) -> bool {
    let fsize = data.len();
    let Some(leaf_off) = cli_rawaddr(rva, sections, hdr_size, fsize) else {
        return false;
    };
    let Some(data_rva) = ru32(data, leaf_off) else {
        return false;
    };
    let Some(mut icoff) = cli_rawaddr(data_rva, sections, hdr_size, fsize) else {
        return false;
    };
    // BMP header (40-byte BITMAPINFOHEADER).
    let Some(sz) = ru32(data, icoff) else {
        return false;
    };
    if (sz as usize) < 40 {
        return false;
    }
    let (Some(w), Some(h), Some(depth)) =
        (ru32(data, icoff + 4), ru32(data, icoff + 8), ru16(data, icoff + 14))
    else {
        return false;
    };
    icoff += sz; // seek past v4/v5 header
    let mut width = w;
    let mut height = h / 2;
    let depth = depth as u32;
    if width > 256 || height > 256 || width < 16 || height < 16 {
        return false;
    }
    if width < height * 3 / 4 || height < width * 3 / 4 {
        return false;
    }
    let mut scalemode = 2u32;
    if width == height {
        if width == 16 || width == 24 || width == 32 {
            scalemode = 0;
        } else if width % 32 == 0 || width % 24 == 0 {
            scalemode = 1;
        }
    }

    // palette (depths 1/4/8); PNG (depth 0) unsupported, like ClamAV.
    let mut palette: Vec<u32> = Vec::new();
    match depth {
        1 | 4 | 8 => {
            let n = 1usize << depth;
            let pbytes = n * 4;
            let pstart = icoff as usize;
            let Some(pal) = data.get(pstart..pstart + pbytes) else {
                return false;
            };
            palette = pal.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
            icoff += pbytes as u32;
        }
        16 | 24 | 32 => {}
        _ => return false,
    }

    let scanlinesz = 4 * (width * depth / 32) + 4 * (((width * depth) % 32 != 0) as u32);
    let mut andlinesz =
        ((depth & 0x1f != 0) as u32) * (4 * (width / 32) + 4 * ((width % 32 != 0) as u32));

    let need = (height * (scanlinesz + andlinesz)) as usize;
    if data.get(icoff as usize..icoff as usize + need).is_none() {
        return false;
    }
    let mut imagedata = vec![0u32; (width * height) as usize];
    let base = icoff as usize;

    // decode pixels (rows are bottom-up; flip vertically)
    for y in 0..height {
        let mut x_off = base + (y * scanlinesz) as usize;
        match depth {
            1 | 4 | 8 => {
                let mut have = 0u32;
                let mut c = 0u8;
                for x in 0..width {
                    if have == 0 {
                        c = data[x_off];
                        x_off += 1;
                        have = 8;
                    }
                    have -= depth;
                    let idx = ((c as u32 >> have) & ((1 << depth) - 1)) as usize;
                    let px = palette.get(idx).copied().unwrap_or(0);
                    imagedata[((height - 1 - y) * width + x) as usize] = px;
                }
            }
            16 => {
                for x in 0..width {
                    let b0 = data[x_off] as u32;
                    let b1 = data[x_off + 1] as u32;
                    let mut b = b0 & 0x1f;
                    let mut g = (b0 >> 5) | ((b1 & 0x3) << 3);
                    let mut r = b1 & 0xfc;
                    b = (b << 3) | (b >> 2);
                    g = ((g << 3) | (g >> 2)) << 11;
                    r = ((r << 3) | (r >> 2)) << 17;
                    imagedata[((height - 1 - y) * width + x) as usize] = r | g | b;
                    x_off += 2;
                }
            }
            24 => {
                for x in 0..width {
                    let c = data[x_off] as u32
                        | ((data[x_off + 1] as u32) << 8)
                        | ((data[x_off + 2] as u32) << 16);
                    imagedata[((height - 1 - y) * width + x) as usize] = c;
                    x_off += 3;
                }
            }
            32 => {
                for x in 0..width {
                    let a = (data[x_off + 3] as u32) << 24;
                    imagedata[((height - 1 - y) * width + x) as usize] = data[x_off] as u32
                        | ((data[x_off + 1] as u32) << 8)
                        | ((data[x_off + 2] as u32) << 16)
                        | a;
                    x_off += 4;
                }
            }
            _ => return false,
        }
    }

    let mut special_32_is_32 = false;
    if depth == 32 {
        special_32_is_32 = imagedata.iter().any(|c| (c & 0xff00_0000) != 0);
    }

    // AND mask → alpha
    let and_base = base + (height * scanlinesz) as usize;
    if depth == 32 && !special_32_is_32 {
        andlinesz = 4 * (width / 32) + 4 * ((width % 32 != 0) as u32);
        let andneed = (height * andlinesz) as usize;
        if data.get(and_base..and_base + andneed).is_none() {
            for px in imagedata.iter_mut() {
                *px |= 0xff00_0000;
            }
            special_32_is_32 = true;
        }
    }
    if (depth & 0x1f) != 0 || !special_32_is_32 {
        for y in 0..height {
            let mut x_off = and_base + (y * andlinesz) as usize;
            let mut have = 0u32;
            let mut c = 0u8;
            for x in 0..width {
                if have == 0 {
                    c = data.get(x_off).copied().unwrap_or(0);
                    x_off += 1;
                    have = 8;
                }
                have -= 1;
                let bit = (c as u32 >> have) & 1;
                imagedata[((height - 1 - y) * width + x) as usize] |=
                    if bit == 0 { 0xff00_0000 } else { 0 };
            }
        }
    }

    // alpha blend over white
    for px in imagedata.iter_mut() {
        let c = *px;
        let a = c >> 24;
        let r = (c >> 16) & 0xff;
        let g = (c >> 8) & 0xff;
        let b = c & 0xff;
        let r = 0xff - a + a * r / 0xff;
        let g = 0xff - a + a * g / 0xff;
        let b = 0xff - a + a * b / 0xff;
        *px = 0xff00_0000 | (r << 16) | (g << 8) | b;
    }

    // scale to 16/24/32
    match scalemode {
        0 => {}
        1 => {
            while width > 32 {
                for y in (0..height).step_by(2) {
                    for x in (0..width).step_by(2) {
                        let c1 = imagedata[(y * width + x) as usize];
                        let c2 = imagedata[(y * width + x + 1) as usize];
                        let c3 = imagedata[((y + 1) * width + x) as usize];
                        let c4 = imagedata[((y + 1) * width + x + 1) as usize];
                        let m1 = (((c1 ^ c2) & 0xfefe_fefe) >> 1) + (c1 & c2);
                        let m2 = (((c3 ^ c4) & 0xfefe_fefe) >> 1) + (c3 & c4);
                        imagedata[(y / 2 * (width / 2) + x / 2) as usize] =
                            (((m1 ^ m2) & 0xfefe_fefe) >> 1) + (m1 & m2);
                    }
                }
                width /= 2;
                height /= 2;
            }
        }
        _ => {
            let aw = |a: i32| a.unsigned_abs();
            let newsize = if aw(width as i32 - 32) + aw(height as i32 - 32)
                < aw(width as i32 - 24) + aw(height as i32 - 24)
            {
                32u32
            } else if aw(width as i32 - 24) + aw(height as i32 - 24)
                < aw(width as i32 - 16) + aw(height as i32 - 16)
            {
                24
            } else {
                16
            };
            let scalex = width as f64 / newsize as f64;
            let scaley = height as f64 / newsize as f64;
            let mut newdata = vec![0u32; (newsize * newsize) as usize];
            for y in 0..newsize {
                let oldy = (y as f64 * scaley) as u32 * width;
                for x in 0..newsize {
                    let sx = (x as f64 * scalex + 0.5) as u32;
                    newdata[(y * newsize + x) as usize] = imagedata[(oldy + sx) as usize];
                }
            }
            imagedata = newdata;
            width = newsize;
            height = newsize;
        }
    }
    let _ = height;

    let metrics = getmetrics(width, &mut imagedata);
    let enginesize = ((width >> 3) - 2) as usize;
    if enginesize >= 3 {
        return false;
    }

    for icon in &matcher.icons[enginesize] {
        if !set.contains(0, icon.group[0]) || !set.contains(1, icon.group[1]) {
            continue;
        }
        if icon_confident(width, enginesize, &metrics, icon) {
            return true;
        }
    }
    false
}

/// The per-candidate confidence test from `parseicon` (the match loop body).
fn icon_confident(width: u32, enginesize: usize, m: &Metrics, ic: &IconMetric) -> bool {
    let (mut color, mut gray) = (0u32, 0u32);
    let bwmatch;
    let edge;
    let noedge;
    let mut positivematch = 64 + 4 * (2 - enginesize as u32);
    if m.ccount == 0 && ic.ccount == 0 {
        edge = matchbwpoint(
            width, &m.edge_x, &m.edge_y, &m.edge_avg, &m.color_x, &m.color_y, &m.color_avg,
            &ic.edge_x, &ic.edge_y, &ic.edge_avg, &ic.color_x, &ic.color_y, &ic.color_avg,
        );
        noedge = matchbwpoint(
            width, &m.noedge_x, &m.noedge_y, &m.noedge_avg, &m.gray_x, &m.gray_y, &m.gray_avg,
            &ic.noedge_x, &ic.noedge_y, &ic.noedge_avg, &ic.gray_x, &ic.gray_y, &ic.gray_avg,
        );
        bwmatch = true;
    } else {
        edge = matchpoint(width, &m.edge_x, &m.edge_y, &m.edge_avg, &ic.edge_x, &ic.edge_y, &ic.edge_avg, 255);
        noedge = matchpoint(width, &m.noedge_x, &m.noedge_y, &m.noedge_avg, &ic.noedge_x, &ic.noedge_y, &ic.noedge_avg, 255);
        if m.ccount != 0 && ic.ccount != 0 {
            color = matchpoint(width, &m.color_x, &m.color_y, &m.color_avg, &ic.color_x, &ic.color_y, &ic.color_avg, 4072);
            gray = matchpoint(width, &m.gray_x, &m.gray_y, &m.gray_avg, &ic.gray_x, &ic.gray_y, &ic.gray_avg, 4072);
        }
        bwmatch = false;
    }
    let bright = matchpoint(width, &m.bright_x, &m.bright_y, &m.bright_avg, &ic.bright_x, &ic.bright_y, &ic.bright_avg, 255);
    let dark = matchpoint(width, &m.dark_x, &m.dark_y, &m.dark_avg, &ic.dark_x, &ic.dark_y, &ic.dark_avg, 255);

    let spread = |a: u32, b: u32| -> u32 {
        let d = (a as i32 - b as i32).unsigned_abs() * 10;
        if d < 100 { 100 - d } else { 0 }
    };
    let reds = spread(m.rsum, ic.rsum);
    let greens = spread(m.gsum, ic.gsum);
    let blues = spread(m.bsum, ic.bsum);
    let ccount = spread(m.ccount, ic.ccount);
    let colors = (reds + greens + blues + ccount) / 4;

    let confidence = if bwmatch {
        positivematch = 70;
        (bright + dark + edge * 2 + noedge) / 6
    } else {
        (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6
    };
    confidence >= positivematch
}

/// Walk one group-icon directory (RT_GROUP_ICON leaf) and test each member icon.
#[allow(clippy::too_many_arguments)]
fn groupiconscan(
    data: &[u8],
    grva: u32,
    res_rva: u32,
    sections: &[Section],
    hdr_size: u32,
    matcher: &IconMatcher,
    set: &GroupSet,
) -> bool {
    let fsize = data.len();
    let Some(leaf_off) = cli_rawaddr(grva, sections, hdr_size, fsize) else {
        return false;
    };
    let Some(gsz0) = ru32(data, leaf_off + 4) else {
        return false;
    };
    if gsz0 <= 6 {
        return false;
    }
    let Some(grp_rva) = ru32(data, leaf_off) else {
        return false;
    };
    let Some(raddr) = cli_rawaddr(grp_rva, sections, hdr_size, fsize) else {
        return false;
    };
    if data.get(raddr as usize..raddr as usize + gsz0 as usize).is_none() {
        return false;
    }
    let Some(idcount) = ru16(data, raddr + 4) else {
        return false;
    };
    let mut icnt = idcount as u32;
    let mut pos = raddr + 6;
    let mut gsz = gsz0 - 6;
    while icnt > 0 && gsz >= 14 {
        if let Some(id) = ru16(data, pos + 12) {
            for irva in find_resources(data, res_rva, sections, hdr_size, 3, id as u32) {
                if parseicon(data, irva, sections, hdr_size, matcher, set) {
                    return true;
                }
            }
        }
        pos += 14;
        gsz -= 14;
        icnt -= 1;
    }
    false
}

/// Evaluate a logical signature's `IconGroup1/2` constraint against a PE's icons.
/// Returns `true` iff some icon matches an `.idb` fingerprint in the requested
/// groups (ClamAV `matchicon` returning CL_VIRUS).
pub fn matchicon(
    data: &[u8],
    sections: &[Section],
    hdr_size: u32,
    res_rva: u32,
    matcher: &IconMatcher,
    grp1: Option<&str>,
    grp2: Option<&str>,
) -> bool {
    if matcher.is_empty() || res_rva == 0 {
        return false;
    }
    let set = GroupSet::build(matcher, grp1, grp2);
    for grva in find_resources(data, res_rva, sections, hdr_size, 14, 0xffff_ffff) {
        if groupiconscan(data, grva, res_rva, sections, hdr_size, matcher, &set) {
            return true;
        }
    }
    false
}
