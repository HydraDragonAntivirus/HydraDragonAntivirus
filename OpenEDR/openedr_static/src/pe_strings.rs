//! Deep string extraction from binary blobs (ASCII + UTF-16LE + CodeRef + StackStrings)
//! backed by pure-Rust [`hydradragondecompiler`].
//!
//! Feeds [`super::string_rules`] with searchable text preserving original case.

/// Minimum run length that counts as a string.
pub const MIN_LEN: usize = 4;

/// Extract ASCII, UTF-16LE, PE code-referenced strings, and stack strings.
/// The disassembly is shared with the PE string ML ([`crate::decompiled_strings`]).
/// The part of a file HydraSig takes strings from: the same bytes the PE string ML
/// disassembles for the file itself (`pe_combined`, `INNER_MAX_BYTES`). With a
/// different cap (it was 16 MB) the two read different buffers for a larger file,
/// so the shared disassembly (`decompiled_strings`) missed and the code was
/// disassembled twice.
pub fn decompile_slice(data: &[u8]) -> &[u8] {
    &data[..data.len().min(crate::ml::pe_combined::INNER_MAX_BYTES)]
}

pub fn extract_strings(data: &[u8]) -> Vec<String> {
    crate::decompiled_strings::hydrasig(data)
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
