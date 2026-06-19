//! Linear ASCII and UTF-16LE scanning over a raw byte buffer.
//!
//! These two passes do not need to understand the file format at all; they walk
//! the bytes and emit runs that look like text. They are also reused by the PE
//! code-ref pass to decode the bytes at a referenced address.

use crate::{ExtractedString, StringKind, is_printable_ascii};

/// Emit every contiguous run of printable ASCII of length >= `min_len`.
pub(crate) fn scan_ascii(data: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let mut start = 0usize;
    let mut i = 0usize;
    while i < data.len() {
        if is_printable_ascii(data[i]) {
            if i == start || !is_printable_ascii(data[i - 1]) {
                start = i;
            }
            i += 1;
            continue;
        }
        flush_ascii(data, start, i, min_len, out);
        i += 1;
        start = i;
    }
    flush_ascii(data, start, data.len(), min_len, out);
}

/// Helper: emit `data[start..end]` as an ASCII string if it is long enough.
fn flush_ascii(
    data: &[u8],
    start: usize,
    end: usize,
    min_len: usize,
    out: &mut Vec<ExtractedString>,
) {
    if end <= start {
        return;
    }
    let run = &data[start..end];
    if run.len() < min_len {
        return;
    }
    if let Ok(text) = std::str::from_utf8(run) {
        out.push(ExtractedString {
            text: text.to_string(),
            kind: StringKind::Ascii,
            offset: Some(start),
        });
    }
}

/// Emit every run of `printable_ascii, 0x00` UTF-16LE pairs of length
/// (in characters) >= `min_len`.
pub(crate) fn scan_wide(data: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let mut i = 0usize;
    while i + 1 < data.len() {
        if is_printable_ascii(data[i]) && data[i + 1] == 0x00 {
            let start = i;
            let mut text = String::new();
            while i + 1 < data.len() && is_printable_ascii(data[i]) && data[i + 1] == 0x00 {
                text.push(data[i] as char);
                i += 2;
            }
            if text.chars().count() >= min_len {
                out.push(ExtractedString {
                    text,
                    kind: StringKind::Wide,
                    offset: Some(start),
                });
            }
        } else {
            i += 1;
        }
    }
}

/// Decode the bytes starting at `data[off..]` as an ASCII or UTF-16LE string,
/// returning the text if it reaches `min_len` printable characters before a
/// terminator. Used by the code-ref pass to read a referenced target.
pub(crate) fn decode_at(data: &[u8], off: usize, min_len: usize) -> Option<(String, StringKind)> {
    if off >= data.len() {
        return None;
    }

    // Try ASCII first: a NUL-terminated or run-bounded printable sequence.
    let mut ascii = String::new();
    let mut j = off;
    while j < data.len() && is_printable_ascii(data[j]) {
        ascii.push(data[j] as char);
        j += 1;
    }
    if ascii.chars().count() >= min_len {
        return Some((ascii, StringKind::Ascii));
    }

    // Try UTF-16LE.
    let mut wide = String::new();
    let mut k = off;
    while k + 1 < data.len() && is_printable_ascii(data[k]) && data[k + 1] == 0x00 {
        wide.push(data[k] as char);
        k += 2;
    }
    if wide.chars().count() >= min_len {
        return Some((wide, StringKind::Wide));
    }

    None
}
