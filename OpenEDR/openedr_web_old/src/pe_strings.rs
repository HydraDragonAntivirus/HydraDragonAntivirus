//! Raw string extraction from binary blobs (ASCII + UTF-16LE).
//!
//! Feeds [`super::string_rules`] with searchable text. Lowercases ASCII
//! A-Z inline so matching is a plain substring search.

/// Minimum run length that counts as a string.
pub const MIN_LEN: usize = 5;

/// Extract lowercased ASCII and UTF-16LE strings of at least `MIN_LEN` chars.
pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    extract_ascii(data, &mut out);
    extract_utf16le(data, &mut out);
    out
}

fn push_lower(out: &mut Vec<String>, buf: &[u8]) {
    if buf.len() < MIN_LEN {
        return;
    }
    let mut s = Vec::with_capacity(buf.len());
    for &b in buf {
        s.push(if b.is_ascii_uppercase() { b + 32 } else { b });
    }
    if let Ok(text) = std::str::from_utf8(&s) {
        out.push(text.to_string());
    }
}

fn is_print(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\t' | b'\r' | b'\n')
}

fn extract_ascii(data: &[u8], out: &mut Vec<String>) {
    let mut start = None::<usize>;
    for (i, &b) in data.iter().enumerate() {
        if is_print(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            push_lower(out, &data[s..i]);
        }
    }
    if let Some(s) = start {
        push_lower(out, &data[s..]);
    }
}

fn extract_utf16le(data: &[u8], out: &mut Vec<String>) {
    // Printable-ASCII word followed by 0x00, repeated.
    let mut buf: Vec<u8> = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if hi == 0 && is_print(lo) && lo != 0 {
            buf.push(lo);
            i += 2;
        } else {
            if !buf.is_empty() {
                push_lower(out, &buf);
                buf.clear();
            }
            i += 1;
        }
    }
    if !buf.is_empty() {
        push_lower(out, &buf);
    }
}
