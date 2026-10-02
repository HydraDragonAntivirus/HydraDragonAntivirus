//! Deep string extraction from binary blobs (ASCII + UTF-16LE + CodeRef + StackStrings)
//! backed by pure-Rust [`hydradragondecompiler`].
//!
//! Feeds [`super::string_rules`] with searchable text preserving original case.

use hydradragondecompiler::{extract_strings as decompile_strings, ExtractOptions};

/// Minimum run length that counts as a string.
pub const MIN_LEN: usize = 4;

/// Extract ASCII, UTF-16LE, PE code-referenced strings, and stack strings.
pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let opts = ExtractOptions {
        min_len: MIN_LEN,
        ascii: true,
        wide: true,
        code_refs: true,
        stack_strings: true,
        opcode_patterns: true,
        max_strings: 50_000,
    };
    let recovered = decompile_strings(data, &opts);
    recovered.into_iter().map(|s| s.text).collect()
}

fn push_string(out: &mut Vec<String>, buf: &[u8]) {
    if buf.len() < MIN_LEN {
        return;
    }
    if let Ok(text) = std::str::from_utf8(buf) {
        out.push(text.to_string());
    }
}

pub fn is_print(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\t' | b'\r' | b'\n')
}

pub fn extract_ascii(data: &[u8], out: &mut Vec<String>) {
    let mut start = None::<usize>;
    for (i, &b) in data.iter().enumerate() {
        if is_print(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            push_string(out, &data[s..i]);
        }
    }
    if let Some(s) = start {
        push_string(out, &data[s..]);
    }
}

pub fn extract_utf16le(data: &[u8], out: &mut Vec<String>) {
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
                push_string(out, &buf);
                buf.clear();
            }
            i += 1;
        }
    }
    if !buf.is_empty() {
        push_string(out, &buf);
    }
}
