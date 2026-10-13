//! Linear ASCII and UTF-16LE scanning over a raw byte buffer.
//!
//! These two passes do not need to understand the file format at all; they walk
//! the bytes and emit runs that look like text. They are also reused by the PE
//! code-ref pass to decode the bytes at a referenced address.

use crate::{ExtractedString, StringKind, is_printable_ascii};

/// Emit every contiguous run of printable ASCII of length >= `min_len`.
pub(crate) fn scan_ascii(data: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let n = data.len();
    let mut i = 0usize;
    while i < n {
        while i < n && !is_printable_ascii(data[i]) {
            i += 1;
        }
        let start = i;
        while i < n && is_printable_ascii(data[i]) {
            i += 1;
        }
        if i - start >= min_len {
            // Printable ASCII is always valid UTF-8.
            let text: String = data[start..i].iter().map(|&b| b as char).collect();
            out.push(ExtractedString { text, kind: StringKind::Ascii, offset: Some(start) });
        }
    }
}

/// Emit every run of `printable_ascii, 0x00` UTF-16LE pairs of length
/// (in characters) >= `min_len`.
pub(crate) fn scan_wide(data: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let n = data.len();
    let mut i = 0usize;
    while i + 1 < n {
        if is_printable_ascii(data[i]) && data[i + 1] == 0x00 {
            let start = i;
            while i + 1 < n && is_printable_ascii(data[i]) && data[i + 1] == 0x00 {
                i += 2;
            }
            if (i - start) / 2 >= min_len {
                let text: String = data[start..i].iter().step_by(2).map(|&b| b as char).collect();
                out.push(ExtractedString { text, kind: StringKind::Wide, offset: Some(start) });
            }
        } else {
            i += 1;
        }
    }
}

/// Decode the bytes starting at `data[off..]` as an ASCII or UTF-16LE string,
/// returning the text if it reaches `min_len` printable characters before a
/// terminator. Used by the code-ref pass to read a referenced target (most targets
/// are not text, so the length is measured before anything is allocated).
pub(crate) fn decode_at(data: &[u8], off: usize, min_len: usize) -> Option<(String, StringKind)> {
    if off >= data.len() {
        return None;
    }

    // Try ASCII first: a NUL-terminated or run-bounded printable sequence.
    let tail = &data[off..];
    let n = tail.iter().position(|&b| !is_printable_ascii(b)).unwrap_or(tail.len());
    if n >= min_len {
        return Some((tail[..n].iter().map(|&b| b as char).collect(), StringKind::Ascii));
    }

    // Try UTF-16LE.
    let mut k = 0;
    while k + 1 < tail.len() && is_printable_ascii(tail[k]) && tail[k + 1] == 0x00 {
        k += 2;
    }
    if k / 2 >= min_len {
        return Some((tail[..k].iter().step_by(2).map(|&b| b as char).collect(), StringKind::Wide));
    }

    None
}
