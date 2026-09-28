//! ClamAV `.idb` icon fingerprinting.
//!
//! This is a faithful port of ClamAV's `pe_icons.c` (the `USE_FLOATS` build
//! path), taken from `hydradragonclamav/src/{icon.rs,icon_match.rs}`:
//!
//! * [`compute_metrics`] is `getmetrics`. The icon is alpha-blended over white,
//!   reduced to a 16/24/32 pixel square, and reduced to a 62-byte fingerprint:
//!   per-feature channel averages and x/y centroids for six feature classes
//!   (colour, gray, bright, dark, edge, no-edge) plus an RGB spread and colour
//!   count summary. The edge features come from a Sobel pass over CIE-Lab
//!   distance, normalised and Gaussian blurred.
//! * [`parse_idb_line`] is `cli_loadidb`. It accepts a whole `.idb` line
//!   (`Name:Group1:Group2:<124 hex chars>`) verbatim, so fingerprints can be
//!   pasted straight out of a ClamAV signature database into a rule.
//! * [`confident_match`] is `icon_confident`, a 0-100 confidence score built
//!   from nine independent point comparisons.
//!
//! Keeping the arithmetic byte-identical is the whole point: a fingerprint
//! lifted from a real `.idb` has to compare against a freshly computed one, and
//! the thresholds (`4072`, `255 / 5`, `ksize * 3 / 4`, `64 + 4 * (2 - size)`)
//! are only meaningful relative to ClamAV's own numbers.

use super::icon::DecodedIcon;

/// A loaded `.idb` fingerprint: the metrics plus the groups it belongs to.
#[derive(Debug, Clone)]
pub struct IconMetric {
    /// Signature name from the `.idb` line.
    pub name: String,
    /// `IconGroup1`/`IconGroup2` as written in the `.idb` line.
    pub groups: [Option<String>; 2],
    /// Icon side length: 16, 24 or 32.
    pub size: u8,
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

/// The computed fingerprint of one icon, in the same field layout.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
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

// ---- colour helpers --------------------------------------------------------

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
    // These three are ClamAV's own Lab reference point, copied digit for digit.
    // `excessive_precision` is wrong here: trimming the literal would change the
    // value and with it every `.idb` comparison.
    #[allow(clippy::excessive_precision)]
    const L1: f64 = 53.192777691077211;
    #[allow(clippy::excessive_precision)]
    const A1: f64 = 0.0031420942181448197;
    #[allow(clippy::excessive_precision)]
    const B1: f64 = -0.0062075877844014471;
    let r = ((rgb >> 16) & 0xff) as f64;
    let g = ((rgb >> 8) & 0xff) as f64;
    let b = (rgb & 0xff) as f64;
    let (l2, a2, b2) = lab(r, g, b);
    ((L1 - l2).powi(2) + (A1 - a2).powi(2) + (B1 - b2).powi(2)).sqrt()
}

// ---- getmetrics -----------------------------------------------------------

/// Port of ClamAV's `getmetrics`. `imagedata` is `side*side` ARGB pixels and is
/// used as scratch space, exactly as upstream.
fn getmetrics(side: u32, imagedata: &mut [u32]) -> Metrics {
    let side = side as usize;
    let ksize = side / 4;
    let mut res = Metrics::default();
    let mut col = vec![0u32; side * side];
    let mut light = vec![0u32; side * side];

    #[allow(clippy::needless_range_loop)]
    fn count_color(res: &mut Metrics, r: u32, g: u32, b: u32, delta: u32) {
        res.ccount += 1;
        res.rsum += (100 - 100 * (g as i32 - b as i32).unsigned_abs() as i32 / delta as i32) as u32;
        res.gsum += (100 - 100 * (r as i32 - b as i32).unsigned_abs() as i32 / delta as i32) as u32;
        res.bsum += (100 - 100 * (r as i32 - g as i32).unsigned_abs() as i32 / delta as i32) as u32;
    }

    for y in 0..=side - ksize {
        for x in 0..=side - ksize {
            let colsum;
            let lightsum;
            if x == 0 && y == 0 {
                let mut cs = 0;
                let mut ls = 0;
                for yk in 0..ksize {
                    for xk in 0..ksize {
                        let (r, g, b, s, v, delta) = hsv(imagedata[yk * side + xk]);
                        cs += ((s * s * v) as f64).sqrt() as u32;
                        ls += v;
                        if s > 85 && v > 85 {
                            count_color(&mut res, r, g, b, delta);
                        }
                    }
                }
                colsum = cs;
                lightsum = ls;
            } else if x != 0 {
                let mut cs = col[y * side + x - 1];
                let mut ls = light[y * side + x - 1];
                for yk in 0..ksize {
                    let (_, _, _, s, v, _) = hsv(imagedata[(y + yk) * side + x - 1]);
                    cs -= ((s * s * v) as f64).sqrt() as u32;
                    ls -= v;
                    let (r, g, b, s, v, delta) = hsv(imagedata[(y + yk) * side + x + ksize - 1]);
                    cs += ((s * s * v) as f64).sqrt() as u32;
                    ls += v;
                    if (y == 0 || yk == ksize - 1) && s > 85 && v > 85 {
                        count_color(&mut res, r, g, b, delta);
                    }
                }
                colsum = cs;
                lightsum = ls;
            } else {
                let mut cs = col[(y - 1) * side];
                let mut ls = light[(y - 1) * side];
                for xk in 0..ksize {
                    let (_, _, _, s, v, _) = hsv(imagedata[(y - 1) * side + xk]);
                    cs -= ((s * s * v) as f64).sqrt() as u32;
                    ls -= v;
                    let (r, g, b, s, v, delta) = hsv(imagedata[(y + ksize - 1) * side + xk]);
                    cs += ((s * s * v) as f64).sqrt() as u32;
                    ls += v;
                    if s > 85 && v > 85 {
                        count_color(&mut res, r, g, b, delta);
                    }
                }
                colsum = cs;
                lightsum = ls;
            }
            col[y * side + x] = colsum;
            light[y * side + x] = lightsum;
        }
    }

    // Top-3 non-overlapping areas for colour / gray / bright / dark.
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

    // Sobel edge detection over CIE-Lab distance, then normalise.
    let mut sobel = vec![0f64; side * side];
    for (i, px) in imagedata.iter().take(side * side).enumerate() {
        sobel[i] = labdiff(*px);
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
    // A flat icon has no gradient, so `imax` stays 0 and ClamAV skips the
    // normalisation entirely rather than dividing by it. `checked_div` would
    // silently produce 0 here and change the blurred edge map.
    #[allow(clippy::manual_checked_ops)]
    if imax != 0 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let c = col[y * side + x] * 255 / imax;
                imagedata[y * side + x] = 0xff00_0000 | c | (c << 8) | (c << 16);
            }
        }
    }
    // Black borders, as upstream: the blur must not bleed off the edges.
    for x in 0..side {
        imagedata[x] = 0xff00_0000;
        imagedata[(side - 1) * side + x] = 0xff00_0000;
    }
    for y in 0..side {
        imagedata[y * side] = 0xff00_0000;
        imagedata[y * side + side - 1] = 0xff00_0000;
    }

    // Separable 1-2-1 Gaussian blur, horizontal then vertical.
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

    // Edge area sums, slid over the blurred edge map.
    for y in 0..=side - ksize {
        for x in 0..=side - 1 - ksize {
            let sum;
            if x == 0 && y == 0 {
                let mut s = 0;
                for yk in 0..ksize {
                    for xk in 0..ksize {
                        s += imagedata[(y + yk) * side + x + xk] & 0xff;
                    }
                }
                sum = s;
            } else if x != 0 {
                let mut s = col[y * side + x - 1];
                for yk in 0..ksize {
                    s -= imagedata[(y + yk) * side + x - 1] & 0xff;
                    s += imagedata[(y + yk) * side + x + ksize - 1] & 0xff;
                }
                sum = s;
            } else {
                let mut s = col[(y - 1) * side];
                for xk in 0..ksize {
                    s -= imagedata[(y - 1) * side + xk] & 0xff;
                    s += imagedata[(y + ksize - 1) * side + xk] & 0xff;
                }
                sum = s;
            }
            col[y * side + x] = sum;
        }
    }

    // Best/worst `nareas` edged areas (6 when the icon is effectively greyscale).
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

// ---- matching --------------------------------------------------------------

// Argument list mirrors ClamAV's matchpoint; reshaping it would obscure the mapping.
#[allow(clippy::too_many_arguments)]
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
    // Flatten the two 3-element halves into the 6-element arrays the comparison
    // loop walks. `split_at` would not help: the halves are interleaved (a0,a1,a2
    // then b0,b1,b2), not concatenated.
    #[allow(clippy::manual_memcpy)]
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

/// ClamAV's `icon_confident`: 0-100 confidence that a computed fingerprint and a
/// stored `.idb` fingerprint describe the same artwork.
///
/// The pass threshold is 72 for a 16px icon, 68 for 24px and 64 for 32px -
/// bigger engines tolerate more difference because their fingerprints carry more
/// resolution.
pub fn confident_match(width: u32, enginesize: usize, m: &Metrics, ic: &IconMetric) -> Option<u32> {
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
        100u32.saturating_sub(d)
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
    (confidence >= positivematch).then_some(confidence)
}

// ---- .idb parsing ----------------------------------------------------------

/// Parse a ClamAV `.idb` line: `Name:Group1:Group2:<124 hex chars>`.
///
/// The whole line may be pasted verbatim out of a signature database, so rules
/// stay interoperable with real `.idb` data.
pub fn parse_idb_line(line: &str) -> Result<IconMetric, String> {
    let tokens: Vec<&str> = line.trim().split(':').collect();
    if tokens.len() != 4 {
        return Err("malformed icon signature (wrong token count)".to_string());
    }
    if tokens[3].len() != 124 {
        return Err("malformed icon signature (wrong length)".to_string());
    }
    let mut hash = [0u8; 124];
    for (i, c) in tokens[3].bytes().enumerate() {
        hash[i] = match (c as char).to_digit(16) {
            Some(v) => v as u8,
            None => return Err("malformed icon signature (bad chars)".to_string()),
        };
    }

    let size = ((hash[0] as u32) << 4) + hash[1] as u32;
    if size != 32 && size != 24 && size != 16 {
        return Err("malformed icon signature (bad size)".to_string());
    }
    let bound = size - size / 8; // centroids must stay within this
    let h = &hash[2..];
    let mut p = 0usize;

    // [feature][avg/x/y][candidate]
    let mut feat: [[[u32; 3]; 3]; 6] = [[[0; 3]; 3]; 6];

    // The i index walks the three candidates while p advances in lockstep,
    // exactly as cli_loadidb does; separating them would not preserve the layout.
    #[allow(clippy::needless_range_loop)]
    // colour(0) + gray(1): avg is 3 nibbles (may reach 4072), x/y 2 each.
    for (f, label) in [(0usize, "color"), (1, "gray")] {
        for i in 0..3 {
            let a = ((h[p] as u32) << 8) | ((h[p + 1] as u32) << 4) | h[p + 2] as u32;
            let x = ((h[p + 3] as u32) << 4) | h[p + 4] as u32;
            let y = ((h[p + 5] as u32) << 4) | h[p + 6] as u32;
            if a > 4072 || x > bound || y > bound {
                return Err(format!("malformed icon signature (bad {label} data)"));
            }
            feat[f][0][i] = a;
            feat[f][1][i] = x;
            feat[f][2][i] = y;
            p += 7;
        }
    }

    #[allow(clippy::needless_range_loop)]
    // bright(2) dark(3) edge(4) noedge(5): avg 2 nibbles, x/y 2 each.
    for (f, label) in [(2usize, "bright"), (3, "dark"), (4, "edge"), (5, "noedge")] {
        for i in 0..3 {
            let a = ((h[p] as u32) << 4) | h[p + 1] as u32;
            let x = ((h[p + 2] as u32) << 4) | h[p + 3] as u32;
            let y = ((h[p + 4] as u32) << 4) | h[p + 5] as u32;
            if x > bound || y > bound {
                return Err(format!("malformed icon signature (bad {label} data)"));
            }
            feat[f][0][i] = a;
            feat[f][1][i] = x;
            feat[f][2][i] = y;
            p += 6;
        }
    }

    let rsum = ((h[p] as u32) << 4) | h[p + 1] as u32;
    let gsum = ((h[p + 2] as u32) << 4) | h[p + 3] as u32;
    let bsum = ((h[p + 4] as u32) << 4) | h[p + 5] as u32;
    let ccount = ((h[p + 6] as u32) << 4) | h[p + 7] as u32;
    if rsum + gsum + bsum > 103 || ccount > 100 {
        return Err("malformed icon signature (bad spread data)".to_string());
    }

    let group = [
        Some(tokens[1].to_string()).filter(|g| !g.is_empty() && g != "*"),
        Some(tokens[2].to_string()).filter(|g| !g.is_empty() && g != "*"),
    ];

    Ok(IconMetric {
        name: tokens[0].to_string(),
        groups: group,
        size: size as u8,
        color_avg: feat[0][0],
        color_x: feat[0][1],
        color_y: feat[0][2],
        gray_avg: feat[1][0],
        gray_x: feat[1][1],
        gray_y: feat[1][2],
        bright_avg: feat[2][0],
        bright_x: feat[2][1],
        bright_y: feat[2][2],
        dark_avg: feat[3][0],
        dark_x: feat[3][1],
        dark_y: feat[3][2],
        edge_avg: feat[4][0],
        edge_x: feat[4][1],
        edge_y: feat[4][2],
        noedge_avg: feat[5][0],
        noedge_x: feat[5][1],
        noedge_y: feat[5][2],
        rsum,
        gsum,
        bsum,
        ccount,
    })
}

// ---- front end -------------------------------------------------------------

/// Compute the ClamAV `.idb` fingerprint of a decoded icon.
///
/// Returns `None` for geometry ClamAV does not score, and the reduced side
/// length (16, 24 or 32) alongside the metrics.
pub fn compute_metrics(icon: &DecodedIcon) -> Option<(u32, Metrics)> {
    let mut width = icon.side;
    let mut height = width;
    if !(16..=256).contains(&width) || !(16..=256).contains(&height) {
        return None;
    }
    // A wildly non-square icon is not what this fingerprint was built for.
    if width < height * 3 / 4 || height < width * 3 / 4 {
        return None;
    }

    let mut scale_mode = 2u32;
    if width == height {
        if width == 16 || width == 24 || width == 32 {
            scale_mode = 0;
        } else if width.is_multiple_of(32) || width.is_multiple_of(24) {
            scale_mode = 1;
        }
    }

    // RGBA -> ARGB.
    let pixels = (width as usize) * (height as usize);
    let mut imagedata: Vec<u32> = Vec::with_capacity(pixels);
    for px in icon.rgba.chunks_exact(4).take(pixels) {
        imagedata.push(
            ((px[3] as u32) << 24) | ((px[0] as u32) << 16) | ((px[1] as u32) << 8) | px[2] as u32,
        );
    }

    // Alpha-blend over white so a transparent background reads as paper.
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

    match scale_mode {
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
        }
    }

    if !matches!(width, 16 | 24 | 32) {
        return None;
    }
    let metrics = getmetrics(width, &mut imagedata);
    Some((width, metrics))
}

/// ClamAV's engine-size bucket for a reduced icon side length: 16 -> 0, 24 -> 1,
/// 32 -> 2. ClamAV stores its `.idb` fingerprints in these buckets.
pub fn enginesize(width: u32) -> usize {
    (width >> 3) as usize - 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::icon::extract_icons;

    fn clamav_test_exe() -> Option<Vec<u8>> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/unit_tests/input/pe_allmatch/test.exe"
        ))
        .ok()
    }

    fn idb_lines() -> Vec<String> {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clamav/unit_tests/input/pe_allmatch/weak-sigs"
        );
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<_> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "idb"))
            .collect();
        names.sort();
        names
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .flat_map(|text| {
                text.lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Ground truth from `clamav/unit_tests/input/pe_allmatch/`.
    ///
    /// That directory pairs `test.exe` (icons at 16/32/48/64/256) with
    /// `weak-sigs/sig00..03.idb` and states in its README that the logical
    /// signatures `PE_ICON_1` and `PE_ICON_2` must be FOUND. Those logical
    /// signatures are `.ldb` files that only request `IconGroup1/2 =
    /// TEST_ICON_GROUP_1/2`; every `.idb` line belongs to both groups. So the
    /// expectation reduces to: a fingerprint from `weak-sigs/` has to match an
    /// icon in `test.exe`, otherwise ClamAV reports NOT_FOUND.
    #[test]
    fn clamav_idb_signatures_match_test_exe() {
        let (Some(bytes), lines) = (clamav_test_exe(), idb_lines()) else {
            return;
        };
        assert!(!lines.is_empty(), "no .idb files found");

        let pe = pefile_rs::PE::parse(&bytes).expect("test.exe must parse");
        let icons = extract_icons(&pe);
        assert!(!icons.is_empty(), "test.exe must yield icons");

        let sigs: Vec<IconMetric> = lines
            .iter()
            .filter_map(|l| parse_idb_line(l).ok())
            .collect();
        assert!(!sigs.is_empty(), "at least one .idb line must parse");

        let mut hits: Vec<(String, u32, u32)> = Vec::new(); // name, confidence, icon side
        for icon in &icons {
            let Some((width, metrics)) = compute_metrics(icon) else {
                continue;
            };
            for sig in &sigs {
                if sig.size as u32 != width {
                    continue;
                }
                if let Some(c) = confident_match(width, enginesize(width), &metrics, sig) {
                    hits.push((sig.name.clone(), c, icon.side));
                }
            }
        }

        assert!(
            !hits.is_empty(),
            "no .idb signature matched test.exe; the port is broken"
        );

        // PE_ICON_1 is satisfied when a fingerprint in TEST_ICON_GROUP_1 matches,
        // PE_ICON_2 when one in TEST_ICON_GROUP_2 does. That is exactly how
        // ClamAV resolves an IconGroup constraint, so express the assertion the
        // same way instead of looking for the .ldb name in .idb output.
        for (group_index, ldb_name) in
            [(0usize, "PE_ICON_1"), (1, "PE_ICON_2")]
        {
            let in_group = |name: &str| {
                sigs.iter()
                    .find(|s| s.name == name)
                    .and_then(|s| s.groups[group_index].as_deref())
                    .is_some()
            };
            assert!(
                hits.iter().any(|(n, _, _)| in_group(n)),
                "{ldb_name} requires a matching fingerprint in group {group_index}, got {hits:?}"
            );
        }
    }

    /// A fingerprint must match the icon size it was computed from, and only
    /// that one. The 32x32 and 64x64 icons both reduce to the 32px engine
    /// bucket, so if the scaling or the metrics were off they would either match
    /// each other's signature or both match the same one.
    #[test]
    fn a_signature_matches_only_its_own_icon_size() {
        let (Some(bytes), lines) = (clamav_test_exe(), idb_lines()) else {
            return;
        };
        let pe = pefile_rs::PE::parse(&bytes).expect("test.exe must parse");
        let icons = extract_icons(&pe);
        let sigs: Vec<IconMetric> = lines.iter().filter_map(|l| parse_idb_line(l).ok()).collect();

        // The 32x32 icon and the 64x64 icon both land in the 32px bucket.
        let metrics_for = |side: u32| {
            icons
                .iter()
                .find(|i| i.side == side)
                .and_then(compute_metrics)
        };
        let (Some((w32, m32)), Some((w64, m64))) = (metrics_for(32), metrics_for(64)) else {
            return;
        };
        assert_eq!(w32, 32);
        assert_eq!(w64, 32, "the 64px icon must reduce into the 32px bucket");

        let matched_by = |m: &Metrics| -> Vec<String> {
            sigs.iter()
                .filter(|s| s.size as u32 == w32)
                .filter(|s| confident_match(w32, enginesize(w32), m, s).is_some())
                .map(|s| s.name.clone())
                .collect()
        };
        let from_32 = matched_by(&m32);
        let from_64 = matched_by(&m64);

        assert!(
            from_32.iter().any(|n| n.contains("32x32")),
            "the 32x32 icon must match IDB_32x32x32, got {from_32:?}"
        );
        assert!(
            from_64.iter().any(|n| n.contains("64x64")),
            "the 64x64 icon must match IDB_64x64x32, got {from_64:?}"
        );
        assert!(
            !from_32.iter().any(|n| n.contains("64x64")) && !from_64.iter().any(|n| n.contains("32x32")),
            "the two 32px-bucket icons must not match each other's signature \
             (32px icon -> {from_32:?}, 64px icon -> {from_64:?})"
        );
    }

    /// A stored fingerprint must match the icon it was computed from, at a
    /// confidence at or above the pass threshold.
    #[test]
    fn a_signature_matches_its_own_icon_at_the_threshold() {
        let Some(bytes) = clamav_test_exe() else { return };
        let pe = pefile_rs::PE::parse(&bytes).expect("test.exe must parse");
        let Some(icon) = extract_icons(&pe).into_iter().next() else {
            return;
        };
        let Some((width, metrics)) = compute_metrics(&icon) else {
            return;
        };

        // Build a signature that is exactly the computed metrics by round-tripping
        // through the .idb encoder.
        let encoded = encode_metrics(width, &metrics);
        let line = format!("T_SELF:{width}:*:{encoded}");
        let sig = parse_idb_line(&line).expect("self-encoded metric must parse");

        let confidence = confident_match(width, enginesize(width), &metrics, &sig)
            .expect("a signature must match its own icon");
        let threshold = if metrics_ccount_is_zero(&metrics) {
            70
        } else {
            64 + 4 * (2 - enginesize(width) as u32)
        };
        assert!(confidence >= threshold, "{confidence} < {threshold}");
    }

    fn metrics_ccount_is_zero(m: &Metrics) -> bool {
        m.ccount == 0
    }

    /// Serialise computed metrics back into the 124-nibble `.idb` form so a
    /// fingerprint can be written into a rule file.
    pub fn encode_metrics(size: u32, m: &Metrics) -> String {
        let mut nibbles: Vec<u8> = Vec::with_capacity(124);
        fn push(nibbles: &mut Vec<u8>, v: u32) {
            nibbles.push((v & 0xf) as u8);
        }

        push(&mut nibbles, size >> 4);
        push(&mut nibbles, size);

        for (avg, x, y) in [
            (&m.color_avg, &m.color_x, &m.color_y),
            (&m.gray_avg, &m.gray_x, &m.gray_y),
        ] {
            for i in 0..3 {
                let a = avg[i].min(4072);
                push(&mut nibbles, a >> 8);
                push(&mut nibbles, a >> 4);
                push(&mut nibbles, a);
                push(&mut nibbles, x[i] >> 4);
                push(&mut nibbles, x[i]);
                push(&mut nibbles, y[i] >> 4);
                push(&mut nibbles, y[i]);
            }
        }
        for (avg, x, y) in [
            (&m.bright_avg, &m.bright_x, &m.bright_y),
            (&m.dark_avg, &m.dark_x, &m.dark_y),
            (&m.edge_avg, &m.edge_x, &m.edge_y),
            (&m.noedge_avg, &m.noedge_x, &m.noedge_y),
        ] {
            for i in 0..3 {
                let a = avg[i];
                push(&mut nibbles, a >> 4);
                push(&mut nibbles, a);
                push(&mut nibbles, x[i] >> 4);
                push(&mut nibbles, x[i]);
                push(&mut nibbles, y[i] >> 4);
                push(&mut nibbles, y[i]);
            }
        }
        for v in [m.rsum, m.gsum, m.bsum, m.ccount] {
            push(&mut nibbles, v >> 4);
            push(&mut nibbles, v);
        }

        assert_eq!(nibbles.len(), 124, "the .idb fingerprint is 124 nibbles");
        nibbles.iter().map(|n| format!("{n:x}")).collect()
    }

    #[test]
    fn parse_rejects_malformed_idb_lines() {
        assert!(parse_idb_line("nope").is_err());
        assert!(parse_idb_line("a:b:c").is_err());
        assert!(parse_idb_line("a:b:c:abcd").is_err());
        // 124 chars but a size that is not 16/24/32.
        let bad_size = "a:b:c:".to_string() + &"0".repeat(122);
        assert!(parse_idb_line(&bad_size).is_err());
        // 124 chars, size 0x10, but a non-hex digit later on.
        let bad_hex = format!("a:b:c:{}zzzz", "0".repeat(120));
        assert!(parse_idb_line(&bad_hex).is_err());
    }

    #[test]
    fn enginesize_buckets_match_clamav() {
        assert_eq!(enginesize(16), 0);
        assert_eq!(enginesize(24), 1);
        assert_eq!(enginesize(32), 2);
    }
}
