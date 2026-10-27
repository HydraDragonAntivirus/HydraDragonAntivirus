//! Anchored byte-pattern and repeating-block conditions (`pe_anchor_pattern`,
//! `byte_repeat`).
//!
//! An anchor names a *file offset*:
//! * `absolute` - offset 0 (moved with `offset`).
//! * `entry`    - the PE's entry point translated to its raw file offset (`%EP%`).
//! * `section`  - raw start of the 1-based PE section `section` (`%PE1%`..`%PEN%`).
//! * `overlay`  - end of the last section with raw data: start of the overlay
//!   appended data (`%EOPE%`).
//!
//! Hex patterns use the wildcard byte `??` (any value) and `!!` (any
//! *non-zero* value), plus YARA-style nibble wildcards (`4?` = high nibble 4,
//! low nibble anything). `!!` matches one byte that must exist and must not be
//! a NUL (prevents matching only padding).
//!
//! `byte_repeat`: the first `length` bytes at the anchor must appear again
//! (`min` times, default 1) elsewhere in the file, marking self-similar
//! encrypted payload blocks.

use crate::models::PeInfo;

/// What an anchor resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorKind {
    Absolute,
    /// Entry point (`%EP%`), raw file offset.
    Entry,
    /// 1-based section number (`%PEN%`), raw file offset.
    Section(u32),
    /// First byte after the last section (`%EOPE%`).
    Overlay,
    /// End of file (`%EOF%`).
    Eof,
}

/// YAML fields of a `pe_anchor_pattern` / `byte_repeat` condition that locate the
/// anchor: `anchor`, optional `section`, optional signed `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorRef {
    pub kind: AnchorKind,
    /// Signed shift from the anchor (`%PE3% + 12` -> section 3, offset +12).
    pub offset: i64,
}

/// Parse the YAML `anchor` string (`absolute`, `entry`, `section`, `overlay`, `eof`).
/// Shorthand spellings `%EP%`, `%EOPE%`, `%EOF%` and `%PE5%` are accepted too; `PE5` needs the number.
pub fn parse_anchor(anchor: &str) -> Option<AnchorKind> {
    let lower = anchor.trim().to_ascii_lowercase();
    match lower.as_str() {
        "absolute" | "abs" | "file" | "0" => return Some(AnchorKind::Absolute),
        "entry" | "ep" | "%ep%" => return Some(AnchorKind::Entry),
        "overlay" | "eope" | "%eope%" => return Some(AnchorKind::Overlay),
        "eof" | "%eof%" => return Some(AnchorKind::Eof),
        _ => {}
    }
    if let Some(rest) = lower
        .strip_prefix("section_")
        .or_else(|| lower.strip_prefix("pe_"))
        .or_else(|| {
            lower
                .strip_prefix("%pe")
                .and_then(|r| r.strip_suffix('%'))
        })
        .or_else(|| if lower.starts_with("pe") { lower.strip_prefix("pe") } else { None })
    {
        return rest.parse::<u32>().ok().filter(|n| *n > 0).map(AnchorKind::Section);
    }
    None
}

/// Resolve `(anchor, section)` from YAML where `anchor: section` + `section: 3`
/// or `anchor: section_3` / `%PE3%` are both accepted.
pub fn parse_anchor_with_section(anchor: &str, section: Option<u32>) -> Option<AnchorKind> {
    let lower = anchor.trim().to_ascii_lowercase();
    if matches!(lower.as_str(), "section" | "pe" | "sec") {
        return section.filter(|n| *n > 0).map(AnchorKind::Section);
    }
    if lower.is_empty()
        && let Some(n) = section.filter(|n| *n > 0)
    {
        return Some(AnchorKind::Section(n));
    }
    parse_anchor(anchor)
}

/// Resolve an anchor against the parsed PE and the raw file, to a signed byte
/// offset (`None` when the PE cannot provide it, e.g. a bogus section number).
pub fn resolve(kind: AnchorKind, offset: i64, pe: Option<&PeInfo>, file_len: u64) -> Option<i64> {
    let base: i64 = match kind {
        AnchorKind::Absolute => 0,
        AnchorKind::Overlay => {
            let pe = pe?;
            let end = pe
                .sections
                .iter()
                .filter(|s| s.raw_offset > 0)
                .map(|s| s.raw_offset + s.raw_size)
                .max()?;
            Some(end).filter(|end| *end <= file_len)? as i64
        }
        AnchorKind::Section(i) => {
            let pe = pe?;
            let s = pe.sections.get(i.checked_sub(1)? as usize)?;
            if s.raw_offset > file_len {
                return None;
            }
            // A section without raw data has no position; refuse rather than
            // matching padding around offset 0.
            (s.raw_offset > 0).then_some(s.raw_offset as i64)?
        }
        AnchorKind::Entry => {
            let pe = pe?;
            entry_file_offset(pe, file_len)? as i64
        }
        AnchorKind::Eof => file_len as i64,
    };
    Some(base + offset)
}

/// Raw file offset of the entry point: RVA -> owning section -> pointer to raw.
pub fn entry_file_offset(pe: &PeInfo, file_len: u64) -> Option<u64> {
    let rva = pe.entry;
    for s in &pe.sections {
        let vs = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(vs) {
            let delta = rva - s.virtual_address;
            let raw = s.raw_offset.saturating_add(delta);
            return (raw < file_len).then_some(raw);
        }
    }
    None
}

/// One byte of a compiled hex pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteUnit {
    /// Fixed byte value.
    Byte(u8),
    /// High nibble fixed, low nibble anything (`5?`).
    Nibble(u8),
    /// Low nibble fixed, high nibble anything (`?5`).
    NibbleLow(u8),
    /// Any byte (`??`).
    Any,
    /// Any non-zero byte (`!!`).
    AnyNonZero,
}

/// Compile a hex pattern: `"57 8B 10 75 56 8B C8 ?? 4? !!"`.
/// Hex characters (with `??`, `!!`, `4?`) are read two at a time; separators and
/// case do not matter. `None` when the text is not a valid whitespace-padded hex
/// pattern.
pub fn compile(pattern: &str) -> Option<Vec<ByteUnit>> {
    let cleaned: Vec<char> = pattern.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    let mut units = Vec::new();
    for chunk in cleaned.chunks(2) {
        match *chunk {
            ['?', '?'] => units.push(ByteUnit::Any),
            ['!', '!'] => units.push(ByteUnit::AnyNonZero),
            [hi, '?'] if hi.is_ascii_hexdigit() => {
                units.push(ByteUnit::Nibble(hi.to_digit(16).unwrap() as u8))
            }
            ['?', lo] if lo.is_ascii_hexdigit() => {
                units.push(ByteUnit::NibbleLow(lo.to_digit(16).unwrap() as u8))
            }
            [hi, lo] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => units.push(ByteUnit::Byte(
                ((hi.to_digit(16).unwrap() as u8) << 4) | lo.to_digit(16).unwrap() as u8,
            )),
            _ => return None,
        }
    }
    Some(units)
}

fn unit_matches(unit: ByteUnit, byte: u8) -> bool {
    match unit {
        ByteUnit::Byte(v) => byte == v,
        ByteUnit::Nibble(hi) => (byte >> 4) == hi,
        ByteUnit::NibbleLow(lo) => (byte & 0x0f) == lo,
        ByteUnit::Any => true,
        ByteUnit::AnyNonZero => byte != 0,
    }
}

/// Find `units` in `range`, returning its offset relative to `range.start`.
/// `range` is the resolved anchor window (already clamped by the caller).
pub fn find_in_range(units: &[ByteUnit], range: &[u8]) -> Option<usize> {
    find_from(units, range, 0)
}

/// Count occurrences of `units` in `range` (non-overlapping, first-wins).
pub fn count_in_range(units: &[ByteUnit], range: &[u8]) -> usize {
    let mut count = 0;
    let mut from = 0usize;
    while let Some(pos) = find_from(units, range, from) {
        count += 1;
        from = pos + units.len().max(1);
    }
    count
}

fn find_from(units: &[ByteUnit], range: &[u8], from: usize) -> Option<usize> {
    if units.is_empty() || range.len() < units.len() || from > range.len() - units.len() {
        return None;
    }
    'outer: for start in from..=(range.len() - units.len()) {
        for (i, unit) in units.iter().enumerate() {
            if !unit_matches(*unit, range[start + i]) {
                continue 'outer;
            }
        }
        return Some(start);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_parse() {
        assert_eq!(parse_anchor("entry"), Some(AnchorKind::Entry));
        assert_eq!(parse_anchor("%EP%"), Some(AnchorKind::Entry));
        assert_eq!(parse_anchor("section_3"), Some(AnchorKind::Section(3)));
        assert_eq!(parse_anchor("pe5"), Some(AnchorKind::Section(5)));
        assert_eq!(parse_anchor("overlay"), Some(AnchorKind::Overlay));
        assert_eq!(parse_anchor("absolute"), Some(AnchorKind::Absolute));
        assert_eq!(parse_anchor("nonsense"), None);
        assert_eq!(parse_anchor("section_0"), None);
    }

    #[test]
    fn hex_patterns_compile() {
        let units = compile("57 8B ?? 4? !!").unwrap();
        assert_eq!(units.len(), 5);
        assert_eq!(units[0], ByteUnit::Byte(0x57));
        assert_eq!(units[2], ByteUnit::Any);
        assert_eq!(units[3], ByteUnit::Nibble(4));
        assert_eq!(units[4], ByteUnit::AnyNonZero);
        assert!(compile("").is_none());
        assert!(compile("xyz").is_none());
        assert!(compile("5").is_none());
    }

    #[test]
    fn range_search() {
        let units = compile("41 42").unwrap();
        assert_eq!(find_from(&units, b"xxABCDAB", 0), Some(2));
        assert_eq!(find_in_range(&units, b"xxABCDAB"), Some(2));
        assert_eq!(count_in_range(&units, b"xxABCDAB"), 2);
        assert_eq!(count_in_range(&compile("00 00").unwrap(), b"\0\0AB\0\0"), 2);
    }
}
