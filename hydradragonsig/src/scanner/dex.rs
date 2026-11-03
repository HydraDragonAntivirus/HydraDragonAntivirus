//! Structural Dalvik executable (DEX) parser: header counts, the string
//! table, class definitions and method references.
//!
//! Ported from the OpenEDR static engine's APK module (`openedr_static/src/apk.rs`).
//! `parse_dex_string_table` / `parse_dex_method_signatures` / `dex_counts` keep
//! that module's limits and output byte-for-byte, so the APK feature vector in
//! [`super::apk`] matches what the OpenEDR forests were trained on.
//! [`parse_dex`] builds the report view ([`DexInfo`]) on top, with full-length
//! strings (the ported table drops entries shorter than 4 bytes, which loses
//! short type descriptors) and dotted Java class names.
//!
//! Every read is bounds-checked; hostile headers yield `None` / empty output,
//! never a panic.

use crate::models::DexInfo;

const DEX_HEADER_LEN: usize = 0x70;
const OFF_STRING_IDS_SIZE: usize = 0x38;
const OFF_STRING_IDS_OFF: usize = 0x3c;
const OFF_TYPE_IDS_SIZE: usize = 0x40;
const OFF_TYPE_IDS_OFF: usize = 0x44;
const OFF_METHOD_IDS_SIZE: usize = 0x58;
const OFF_METHOD_IDS_OFF: usize = 0x5c;
const OFF_CLASS_DEFS_SIZE: usize = 0x60;
const OFF_CLASS_DEFS_OFF: usize = 0x64;
const CLASS_DEF_ITEM_LEN: usize = 32;
const METHOD_ID_ITEM_LEN: usize = 8;

/// String-table entries the ported table reads (OpenEDR parity).
const PORTED_STRING_CAP: usize = 15_000;
/// Method references the ported signature walk reads (OpenEDR parity).
const PORTED_METHOD_CAP: usize = 15_000;
/// Bytes read per string entry.
const MAX_STRING_BYTES: usize = 512;
/// Header sanity limits.
const MAX_STRING_IDS: usize = 200_000;
const MAX_METHOD_IDS: usize = 200_000;
/// Report caps.
pub const MAX_CLASS_NAMES: usize = 32_000;
pub const MAX_METHOD_NAMES: usize = 30_000;

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

/// `dex\n` magic plus a complete 0x70-byte header.
pub fn is_dex(buf: &[u8]) -> bool {
    buf.len() >= DEX_HEADER_LEN && buf.starts_with(b"dex\n")
}

/// `(class_defs, string_ids, method_ids)` from the header, `None` for a
/// non-DEX or a header with implausible counts.
pub fn dex_counts(buf: &[u8]) -> Option<(u32, u32, u32)> {
    if !is_dex(buf) {
        return None;
    }
    let string_ids = read_u32_le(buf, OFF_STRING_IDS_SIZE)?;
    let method_ids = read_u32_le(buf, OFF_METHOD_IDS_SIZE)?;
    let class_defs = read_u32_le(buf, OFF_CLASS_DEFS_SIZE)?;
    if string_ids > 10_000_000 || method_ids > 10_000_000 || class_defs > 5_000_000 {
        return None;
    }
    Some((class_defs, string_ids, method_ids))
}

/// Unsigned LEB128 at `off`: `(value, offset past it)`. At most 5 bytes.
pub(crate) fn read_uleb128(buf: &[u8], mut off: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let b = *buf.get(off)?;
        off += 1;
        result |= ((b & 0x7f) as u32).checked_shl(shift).unwrap_or(0);
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    Some((result, off))
}

/// One `string_data_item`: skip the UTF-16 length, read up to the NUL
/// (at most 512 bytes). `None` when the entry points outside the file.
fn string_at(buf: &[u8], data_off: usize) -> Option<&[u8]> {
    let (_utf16_len, start) = read_uleb128(buf, data_off)?;
    if start >= buf.len() {
        return None;
    }
    let max_read = (buf.len() - start).min(MAX_STRING_BYTES);
    let slice = &buf[start..start + max_read];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some(&slice[..end])
}

fn decode(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn string_ids(buf: &[u8]) -> Option<(usize, usize)> {
    if !is_dex(buf) {
        return None;
    }
    let size = read_u32_le(buf, OFF_STRING_IDS_SIZE)? as usize;
    let off = read_u32_le(buf, OFF_STRING_IDS_OFF)? as usize;
    if size > MAX_STRING_IDS || (size > 0 && off >= buf.len()) {
        return None;
    }
    Some((size, off))
}

/// The DEX string table as the OpenEDR APK model reads it: the first 15 000
/// entries, entries shorter than 4 bytes kept as empty strings (so indices stay
/// aligned with `string_ids`), entries pointing outside the file skipped.
pub fn parse_dex_string_table(buf: &[u8]) -> Option<Vec<String>> {
    let (size, ids_off) = string_ids(buf)?;
    let mut strings = Vec::with_capacity(size.min(PORTED_STRING_CAP));
    for i in 0..size.min(PORTED_STRING_CAP) {
        let Some(data_off) = read_u32_le(buf, ids_off + i * 4).map(|v| v as usize) else {
            break;
        };
        let Some(bytes) = string_at(buf, data_off) else {
            continue;
        };
        strings.push(if bytes.len() >= 4 { decode(bytes) } else { String::new() });
    }
    Some(strings)
}

/// Every string-table entry (up to the header limit), full length, index-aligned
/// with `string_ids`: an entry pointing outside the file becomes `""`.
fn parse_full_string_table(buf: &[u8]) -> Option<Vec<String>> {
    let (size, ids_off) = string_ids(buf)?;
    let mut strings = Vec::with_capacity(size.min(1 << 16));
    for i in 0..size {
        let Some(data_off) = read_u32_le(buf, ids_off + i * 4).map(|v| v as usize) else {
            break;
        };
        strings.push(string_at(buf, data_off).map(decode).unwrap_or_default());
    }
    Some(strings)
}

/// Type descriptor of `type_ids[idx]`.
fn type_descriptor<'a>(buf: &[u8], strings: &'a [String], idx: usize) -> Option<&'a str> {
    let size = read_u32_le(buf, OFF_TYPE_IDS_SIZE)? as usize;
    let off = read_u32_le(buf, OFF_TYPE_IDS_OFF)? as usize;
    if idx >= size {
        return None;
    }
    let desc_idx = read_u32_le(buf, off.checked_add(idx.checked_mul(4)?)?)? as usize;
    strings.get(desc_idx).map(String::as_str)
}

/// `Lclass;->name` for each `method_ids` entry, as the OpenEDR APK model reads
/// them (first 15 000 entries, `strings` from [`parse_dex_string_table`]).
/// Entries whose class or name index is out of range are skipped.
pub fn parse_dex_method_signatures(buf: &[u8], strings: &[String]) -> Vec<String> {
    method_refs(buf, strings, PORTED_METHOD_CAP, |class, name| format!("{class}->{name}"))
}

fn method_refs(
    buf: &[u8],
    strings: &[String],
    cap: usize,
    render: impl Fn(&str, &str) -> String,
) -> Vec<String> {
    let mut methods = Vec::new();
    if !is_dex(buf) {
        return methods;
    }
    let (Some(size), Some(off)) = (
        read_u32_le(buf, OFF_METHOD_IDS_SIZE).map(|v| v as usize),
        read_u32_le(buf, OFF_METHOD_IDS_OFF).map(|v| v as usize),
    ) else {
        return methods;
    };
    let Some(type_off) = read_u32_le(buf, OFF_TYPE_IDS_OFF).map(|v| v as usize) else {
        return methods;
    };
    if size > MAX_METHOD_IDS || off >= buf.len() || type_off >= buf.len() {
        return methods;
    }
    for i in 0..size.min(cap) {
        let item = off + i * METHOD_ID_ITEM_LEN;
        let Some(class_idx) = read_u16_le(buf, item).map(|v| v as usize) else { break };
        let Some(name_idx) = read_u32_le(buf, item + 4).map(|v| v as usize) else { break };
        let Some(class) = type_descriptor(buf, strings, class_idx) else { continue };
        let Some(name) = strings.get(name_idx).map(String::as_str) else { continue };
        if !class.is_empty() && !name.is_empty() {
            methods.push(render(class, name));
        }
    }
    methods
}

/// `Lcom/foo/Bar;` -> `com.foo.Bar`; array and primitive descriptors are kept as written.
pub fn descriptor_to_java(desc: &str) -> String {
    match desc.strip_prefix('L').and_then(|d| d.strip_suffix(';')) {
        Some(inner) => inner.replace('/', "."),
        None => desc.to_string(),
    }
}

/// Dotted names of the classes defined in this DEX (`class_defs`), at most
/// [`MAX_CLASS_NAMES`].
fn parse_class_names(buf: &[u8], strings: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let (Some(size), Some(off)) = (
        read_u32_le(buf, OFF_CLASS_DEFS_SIZE).map(|v| v as usize),
        read_u32_le(buf, OFF_CLASS_DEFS_OFF).map(|v| v as usize),
    ) else {
        return out;
    };
    if size > 5_000_000 || (size > 0 && off >= buf.len()) {
        return out;
    }
    for i in 0..size.min(MAX_CLASS_NAMES) {
        let Some(class_idx) = read_u32_le(buf, off + i * CLASS_DEF_ITEM_LEN) else { break };
        if let Some(desc) = type_descriptor(buf, strings, class_idx as usize) && !desc.is_empty() {
            out.push(descriptor_to_java(desc));
        }
    }
    out
}

/// Parsed DEX plus its full string table (kept out of the report: rules read
/// it through `dex_string_regex`).
pub struct ParsedDex {
    pub info: DexInfo,
    pub strings: Vec<String>,
}

/// Header counts, defined class names and referenced methods
/// (`com.foo.Bar->name`). `None` when `buf` is not a DEX.
pub fn parse_dex(buf: &[u8]) -> Option<DexInfo> {
    parse_dex_full(buf).map(|p| p.info)
}

pub fn parse_dex_full(buf: &[u8]) -> Option<ParsedDex> {
    let (classes, strings_count, methods) = dex_counts(buf)?;
    let strings = parse_full_string_table(buf).unwrap_or_default();
    let class_names = parse_class_names(buf, &strings);
    let method_names = method_refs(buf, &strings, MAX_METHOD_NAMES, |class, name| {
        format!("{}->{}", descriptor_to_java(class), name)
    });
    Some(ParsedDex {
        info: DexInfo {
            classes: classes as usize,
            strings: strings_count as usize,
            methods: methods as usize,
            class_names,
            method_names,
        },
        strings,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimal DEX: `strings` in the string table, `types` as indices into it,
    /// `classes` as type indices (class_defs), `methods` as (type idx, name idx).
    pub(crate) fn build_dex(strings: &[&str], types: &[u32], classes: &[u32], methods: &[(u16, u32)]) -> Vec<u8> {
        let mut buf = vec![0u8; DEX_HEADER_LEN];
        buf[0..8].copy_from_slice(b"dex\n035\0");
        let put = |buf: &mut Vec<u8>, at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());

        let string_ids_off = buf.len();
        buf.resize(string_ids_off + strings.len() * 4, 0);
        let type_ids_off = buf.len();
        buf.resize(type_ids_off + types.len() * 4, 0);
        let method_ids_off = buf.len();
        buf.resize(method_ids_off + methods.len() * METHOD_ID_ITEM_LEN, 0);
        let class_defs_off = buf.len();
        buf.resize(class_defs_off + classes.len() * CLASS_DEF_ITEM_LEN, 0);

        for (i, s) in strings.iter().enumerate() {
            let data_off = buf.len() as u32;
            put(&mut buf, string_ids_off + i * 4, data_off);
            let mut n = s.encode_utf16().count() as u32;
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    buf.push(byte);
                    break;
                }
                buf.push(byte | 0x80);
            }
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        for (i, t) in types.iter().enumerate() {
            put(&mut buf, type_ids_off + i * 4, *t);
        }
        for (i, (class_idx, name_idx)) in methods.iter().enumerate() {
            let at = method_ids_off + i * METHOD_ID_ITEM_LEN;
            buf[at..at + 2].copy_from_slice(&class_idx.to_le_bytes());
            put(&mut buf, at + 4, *name_idx);
        }
        for (i, c) in classes.iter().enumerate() {
            put(&mut buf, class_defs_off + i * CLASS_DEF_ITEM_LEN, *c);
        }

        put(&mut buf, OFF_STRING_IDS_SIZE, strings.len() as u32);
        put(&mut buf, OFF_STRING_IDS_OFF, string_ids_off as u32);
        put(&mut buf, OFF_TYPE_IDS_SIZE, types.len() as u32);
        put(&mut buf, OFF_TYPE_IDS_OFF, type_ids_off as u32);
        put(&mut buf, OFF_METHOD_IDS_SIZE, methods.len() as u32);
        put(&mut buf, OFF_METHOD_IDS_OFF, method_ids_off as u32);
        put(&mut buf, OFF_CLASS_DEFS_SIZE, classes.len() as u32);
        put(&mut buf, OFF_CLASS_DEFS_OFF, class_defs_off as u32);
        buf
    }

    fn sample() -> Vec<u8> {
        build_dex(&["Lcom/foo/Bar;", "android/receiver", "onCreate", "V"], &[0, 3], &[0], &[(0, 2), (1, 2)])
    }

    #[test]
    fn header_counts_and_magic() {
        let dex = sample();
        assert_eq!(dex_counts(&dex), Some((1, 4, 2)));
        assert!(dex_counts(b"dex\n").is_none(), "short header");
        let mut bad = dex.clone();
        bad[0] = b'x';
        assert!(dex_counts(&bad).is_none());
        assert!(parse_dex(&bad).is_none());
    }

    #[test]
    fn uleb128_limits() {
        assert_eq!(read_uleb128(&[0x05], 0), Some((5, 1)));
        assert_eq!(read_uleb128(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(read_uleb128(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0), Some((u32::MAX, 5)));
        assert!(read_uleb128(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01], 0).is_none(), "more than 5 bytes");
        assert!(read_uleb128(&[0x80], 0).is_none(), "truncated");
    }

    #[test]
    fn ported_string_table_keeps_openedr_semantics() {
        let strings = parse_dex_string_table(&sample()).unwrap();
        assert_eq!(strings, vec!["Lcom/foo/Bar;", "android/receiver", "onCreate", ""]);
    }

    #[test]
    fn string_ids_out_of_bounds_and_oversized() {
        let mut dex = sample();
        let bad_off = (dex.len() as u32 + 10).to_le_bytes();
        dex[OFF_STRING_IDS_OFF..OFF_STRING_IDS_OFF + 4].copy_from_slice(&bad_off);
        assert!(parse_dex_string_table(&dex).is_none());
        let mut dex = sample();
        dex[OFF_STRING_IDS_SIZE..OFF_STRING_IDS_SIZE + 4].copy_from_slice(&300_000u32.to_le_bytes());
        assert!(parse_dex_string_table(&dex).is_none());
    }

    #[test]
    fn method_signatures_ok_and_out_of_range() {
        let dex = sample();
        let strings = parse_dex_string_table(&dex).unwrap();
        // Type 1 ("V") maps to a short string: skipped like OpenEDR does.
        assert_eq!(parse_dex_method_signatures(&dex, &strings), vec!["Lcom/foo/Bar;->onCreate"]);

        let bad = build_dex(&["Lcom/foo/Bar;", "onCreate"], &[0], &[0], &[(7, 1), (0, 99), (0, 1)]);
        let strings = parse_dex_string_table(&bad).unwrap();
        assert_eq!(parse_dex_method_signatures(&bad, &strings), vec!["Lcom/foo/Bar;->onCreate"]);
    }

    #[test]
    fn parse_dex_report_view() {
        let info = parse_dex(&sample()).unwrap();
        assert_eq!((info.classes, info.strings, info.methods), (1, 4, 2));
        assert_eq!(info.class_names, vec!["com.foo.Bar"]);
        assert_eq!(info.method_names, vec!["com.foo.Bar->onCreate", "V->onCreate"]);
    }

    #[test]
    fn truncated_tables_never_panic() {
        let dex = sample();
        for cut in DEX_HEADER_LEN..dex.len() {
            let _ = parse_dex_full(&dex[..cut]);
            let _ = parse_dex_string_table(&dex[..cut]);
        }
    }

    #[test]
    fn descriptor_conversion() {
        assert_eq!(descriptor_to_java("Lcom/foo/Bar;"), "com.foo.Bar");
        assert_eq!(descriptor_to_java("[I"), "[I");
    }
}
