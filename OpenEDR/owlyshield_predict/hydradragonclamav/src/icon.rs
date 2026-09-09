//! ClamAV icon signatures (`.idb`), ported from `cli_loadidb` (readdb.c:1320) and
//! the `struct icomtr` / `struct icon_matcher` model (others.h:208).
//!
//! Each `.idb` line is `Name:Group1:Group2:Metric` where `Metric` is a fixed
//! 124-nibble (62-byte) fuzzy-image fingerprint of a PE icon: per-channel
//! averages and x/y centroids for colour, gray, bright, dark, edge and no-edge
//! features, plus an RGB spread/colour-count summary. ClamAV computes the same
//! fingerprint from a scanned PE's icons (`pe_icons.c::getmetrics`) and matches
//! within a tolerance.
//!
//! **This module implements the loader faithfully** — every metric is parsed and
//! stored byte-exactly (same field decode and bound checks as `cli_loadidb`),
//! bucketed by icon size, with interned group names. The image *matcher*
//! (`getmetrics` / `matchpoint` over PE-extracted icons) is the separate heavy
//! port tracked for follow-up; until then these signatures are loaded and counted
//! rather than silently dropped.

use crate::database::SourceLocation;

/// One icon fingerprint (`struct icomtr`). Triple-valued features hold three
/// candidate centroids each, as ClamAV stores them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IconMetric {
    pub name: String,
    /// Indices into `IconMatcher::group_names[0]` and `[1]`.
    pub group: [u32; 2],
    pub color_avg: [u32; 3],
    pub color_x: [u32; 3],
    pub color_y: [u32; 3],
    pub gray_avg: [u32; 3],
    pub gray_x: [u32; 3],
    pub gray_y: [u32; 3],
    pub bright_avg: [u32; 3],
    pub bright_x: [u32; 3],
    pub bright_y: [u32; 3],
    pub dark_avg: [u32; 3],
    pub dark_x: [u32; 3],
    pub dark_y: [u32; 3],
    pub edge_avg: [u32; 3],
    pub edge_x: [u32; 3],
    pub edge_y: [u32; 3],
    pub noedge_avg: [u32; 3],
    pub noedge_x: [u32; 3],
    pub noedge_y: [u32; 3],
    pub rsum: u32,
    pub gsum: u32,
    pub bsum: u32,
    pub ccount: u32,
    pub source: SourceLocation,
}

/// All loaded icon signatures (`struct icon_matcher`). `icons[e]` holds the
/// fingerprints for engine-size bucket `e` (`(size>>3) - 2`: 16→0, 24→1, 32→2);
/// `group_names[t]` interns the type-`t` group labels referenced by `group[t]`.
#[derive(Debug, Default)]
pub struct IconMatcher {
    pub icons: [Vec<IconMetric>; 3],
    pub group_names: [Vec<String>; 2],
}

impl IconMatcher {
    pub fn is_empty(&self) -> bool {
        self.icons.iter().all(|b| b.is_empty())
    }

    /// Total icon fingerprints loaded across all size buckets.
    pub fn len(&self) -> usize {
        self.icons.iter().map(Vec::len).sum()
    }

    /// Intern a group name for type `t` (0 or 1), returning its index.
    fn intern_group(&mut self, t: usize, name: &str) -> u32 {
        if let Some(i) = self.group_names[t].iter().position(|g| g == name) {
            return i as u32;
        }
        self.group_names[t].push(name.to_string());
        (self.group_names[t].len() - 1) as u32
    }

    /// Parse and store one `.idb` line. Returns `Ok(())` on success; the error
    /// messages mirror `cli_loadidb`'s malformed-hash diagnostics.
    pub fn add_line(&mut self, line: &str, source: SourceLocation) -> Result<(), String> {
        let tokens: Vec<&str> = line.split(':').collect();
        if tokens.len() != ICO_TOKENS {
            return Err("malformed icon signature (wrong token count)".to_string());
        }
        if tokens[3].len() != 124 {
            return Err("malformed icon signature (wrong length)".to_string());
        }
        // Decode 124 hex chars to 124 nibble values (0..=15).
        let mut hash = [0u8; 124];
        for (i, c) in tokens[3].bytes().enumerate() {
            hash[i] = match (c as char).to_digit(16) {
                Some(v) => v as u8,
                None => return Err("malformed icon signature (bad chars)".to_string()),
            };
        }

        // First byte = icon side length; only 16/24/32 are valid.
        let size = ((hash[0] as u32) << 4) + hash[1] as u32;
        if size != 32 && size != 24 && size != 16 {
            return Err("malformed icon signature (bad size)".to_string());
        }
        let enginesize = ((size >> 3) - 2) as usize;
        let bound = size - size / 8; // centroid x/y must stay within this
        let h = &hash[2..];
        let mut p = 0usize; // nibble cursor into `h`

        // Feature centroids, filled below then moved into the metric.
        let mut feat: [[[u32; 3]; 3]; 6] = [[[0; 3]; 3]; 6]; // [feature][avg/x/y][candidate]

        // colour(0) + gray(1): avg = 3 nibbles (≤4072), x/y = 2 nibbles each.
        // (Index `i` walks the three candidates while `p` advances in lockstep.)
        #[allow(clippy::needless_range_loop)]
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

        // bright(2) dark(3) edge(4) noedge(5): avg = 2 nibbles (no bound), x/y = 2.
        #[allow(clippy::needless_range_loop)]
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

        // spread/colour-count summary.
        let rsum = ((h[p] as u32) << 4) | h[p + 1] as u32;
        let gsum = ((h[p + 2] as u32) << 4) | h[p + 3] as u32;
        let bsum = ((h[p + 4] as u32) << 4) | h[p + 5] as u32;
        let ccount = ((h[p + 6] as u32) << 4) | h[p + 7] as u32;
        if rsum + gsum + bsum > 103 || ccount > 100 {
            return Err("malformed icon signature (bad spread data)".to_string());
        }

        let group = [self.intern_group(0, tokens[1]), self.intern_group(1, tokens[2])];
        self.icons[enginesize].push(IconMetric {
            name: tokens[0].to_string(),
            group,
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
            source,
        });
        Ok(())
    }
}

/// `.idb` field count: `Name:Group1:Group2:Metric` (ClamAV `ICO_TOKENS`).
const ICO_TOKENS: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn src() -> SourceLocation {
        SourceLocation {
            path: Arc::from(PathBuf::from("daily.idb").as_path()),
            line: 1,
        }
    }

    #[test]
    fn parses_real_idb_line() {
        // First line of the shipped daily.idb (size byte 0x18 = 24 → bucket 1).
        let line = "Win.Trojan.GenericIE-1:MS:IE:18bee030cbde0e0696d090f08b000019f10113de0006fe0000fb0600f60006cb0807d00211d5100c78100e710a116808090800001600091a06003f00252f";
        let mut m = IconMatcher::default();
        m.add_line(line, src()).expect("should parse");
        assert_eq!(m.len(), 1);
        assert_eq!(m.icons[1].len(), 1); // 24px bucket
        let metric = &m.icons[1][0];
        assert_eq!(metric.name, "Win.Trojan.GenericIE-1");
        assert_eq!(m.group_names[0], vec!["MS"]);
        assert_eq!(m.group_names[1], vec!["IE"]);
    }

    #[test]
    fn rejects_wrong_length() {
        let mut m = IconMatcher::default();
        assert!(m.add_line("N:G1:G2:1234", src()).is_err());
    }

    #[test]
    fn rejects_wrong_token_count() {
        let mut m = IconMatcher::default();
        let metric = "18".to_string() + &"0".repeat(122);
        assert!(m.add_line(&format!("N:G1:{metric}"), src()).is_err());
    }

    #[test]
    fn rejects_bad_size_byte() {
        // size byte 0xff = 255 (not 16/24/32).
        let line = "N:G1:G2:ff".to_string() + &"0".repeat(122);
        let mut m = IconMatcher::default();
        assert!(m.add_line(&line, src()).is_err());
    }

    #[test]
    fn interns_groups_once() {
        // Two 16px icons (size byte 0x10) sharing group "A"/"B" → one entry each.
        let body = "0".repeat(122);
        let l1 = format!("Sig1:A:B:10{body}");
        let l2 = format!("Sig2:A:B:10{body}");
        let mut m = IconMatcher::default();
        m.add_line(&l1, src()).unwrap();
        m.add_line(&l2, src()).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.group_names[0], vec!["A"]);
        assert_eq!(m.group_names[1], vec!["B"]);
        assert_eq!(m.icons[0].len(), 2); // both in 16px bucket
    }
}
