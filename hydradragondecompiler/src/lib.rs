//! `hydradragondecompiler` — a "decompiler-lite" string extractor.
//!
//! The goal is to pull *more* strings out of a binary (especially a Windows PE
//! executable) than a naive `strings` tool would, so those strings can be fed
//! into HydraDragon's malware scanning. We do this with four passes:
//!
//! 1. **ASCII** — contiguous runs of printable ASCII bytes.
//! 2. **Wide** — UTF-16LE runs (`printable, 0x00` pairs), which `strings`
//!    without `-e l` would miss.
//! 3. **Code references** — for PE files we disassemble executable sections and
//!    follow memory operands (absolute or RIP-relative) to data the code points
//!    at; if the target bytes form a printable string we recover it. This finds
//!    strings that are referenced by address even when the surrounding bytes are
//!    not a clean ASCII run.
//! 4. **Stack strings** — sequences of immediate-to-memory `mov` instructions
//!    that build a string byte-by-byte on the stack. These never appear as a
//!    contiguous run in the file at all, so a plain scanner cannot see them.
//!
//! Everything beyond the ASCII/wide passes is best-effort: if goblin or capstone
//! fails for any reason we simply skip the code-ref/stack passes and still return
//! the ASCII and wide results.

mod pe;
mod scan;

use std::path::Path;

use serde::Serialize;

/// How a string was recovered from the binary.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub enum StringKind {
    /// Contiguous printable ASCII run.
    Ascii,
    /// UTF-16LE run decoded to a `String`.
    Wide,
    /// String the code references by address (absolute or RIP-relative).
    CodeRef,
    /// String assembled on the stack via immediate-to-memory moves.
    StackString,
}

/// A single recovered string.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ExtractedString {
    /// The decoded string text.
    pub text: String,
    /// How the string was recovered.
    pub kind: StringKind,
    /// File offset of the string when known (ASCII/wide always know it; code-ref
    /// knows it when the target maps to a section on disk; stack strings do not).
    pub offset: Option<usize>,
}

/// Knobs controlling which passes run and how aggressive they are.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Minimum length (in characters) for a string to be reported.
    pub min_len: usize,
    /// Run the ASCII pass.
    pub ascii: bool,
    /// Run the UTF-16LE wide pass.
    pub wide: bool,
    /// Run the code-reference pass (PE only).
    pub code_refs: bool,
    /// Run the stack-string pass (PE only).
    pub stack_strings: bool,
    /// Hard cap on the number of strings returned.
    pub max_strings: usize,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            min_len: 4,
            ascii: true,
            wide: true,
            code_refs: true,
            stack_strings: true,
            max_strings: 100_000,
        }
    }
}

/// Errors returned by [`extract_from_path`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Read a file and extract strings from it.
pub fn extract_from_path(path: &Path, opts: &ExtractOptions) -> Result<Vec<ExtractedString>, Error> {
    let data = std::fs::read(path)?;
    Ok(extract_strings(&data, opts))
}

/// Extract strings from an in-memory buffer.
///
/// See the crate docs for the four passes. The result is deduplicated by
/// `(kind, text)`, sorted deterministically by `(offset, text)`, and capped at
/// `opts.max_strings`.
pub fn extract_strings(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    let min_len = opts.min_len.max(1);
    let mut out: Vec<ExtractedString> = Vec::new();

    if opts.ascii {
        scan::scan_ascii(data, min_len, &mut out);
    }
    if opts.wide {
        scan::scan_wide(data, min_len, &mut out);
    }

    // Code-ref and stack-string passes need a PE. They are wrapped so any
    // goblin/capstone failure just leaves the ASCII/wide results intact.
    if opts.code_refs || opts.stack_strings {
        // The text of plain ASCII/wide finds, so code-ref strings that merely
        // re-discover an already-listed run get deduped away.
        let known: std::collections::HashSet<String> =
            out.iter().map(|s| s.text.clone()).collect();
        pe::scan_pe(data, opts, min_len, &known, &mut out);
    }

    dedup_sort_cap(&mut out, opts.max_strings);
    out
}

/// Deduplicate by `(kind, text)`, sort by `(offset, text)`, and cap the length.
fn dedup_sort_cap(out: &mut Vec<ExtractedString>, max_strings: usize) {
    let mut seen: std::collections::HashSet<(StringKindTag, String)> =
        std::collections::HashSet::new();
    out.retain(|s| seen.insert((StringKindTag::from(&s.kind), s.text.clone())));

    out.sort_by(|a, b| {
        // `None` offsets (stack strings) sort after known offsets.
        let oa = a.offset.unwrap_or(usize::MAX);
        let ob = b.offset.unwrap_or(usize::MAX);
        oa.cmp(&ob).then_with(|| a.text.cmp(&b.text))
    });

    if out.len() > max_strings {
        out.truncate(max_strings);
    }
}

/// Cheap, hashable tag for `StringKind` used only for dedup keys.
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
enum StringKindTag {
    Ascii,
    Wide,
    CodeRef,
    StackString,
}

impl From<&StringKind> for StringKindTag {
    fn from(k: &StringKind) -> Self {
        match k {
            StringKind::Ascii => StringKindTag::Ascii,
            StringKind::Wide => StringKindTag::Wide,
            StringKind::CodeRef => StringKindTag::CodeRef,
            StringKind::StackString => StringKindTag::StackString,
        }
    }
}

/// True for printable ASCII (0x20..=0x7e) plus tab.
#[inline]
pub(crate) fn is_printable_ascii(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7e).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_extraction_finds_embedded_string() {
        // A buffer with binary noise around a recognizable C2 string.
        let mut data = vec![0x00, 0x01, 0x02, 0xff, 0xfe];
        data.extend_from_slice(b"MALWARE_C2_STRING");
        data.extend_from_slice(&[0x00, 0x80, 0x90]);

        let opts = ExtractOptions::default();
        let found = extract_strings(&data, &opts);

        assert!(
            found
                .iter()
                .any(|s| s.kind == StringKind::Ascii && s.text == "MALWARE_C2_STRING"),
            "expected to recover MALWARE_C2_STRING as ASCII, got: {found:?}"
        );

        // Offset should point at the 'M'.
        let hit = found
            .iter()
            .find(|s| s.text == "MALWARE_C2_STRING")
            .unwrap();
        assert_eq!(hit.offset, Some(5));
    }

    #[test]
    fn wide_extraction_decodes_utf16le() {
        // UTF-16LE encoding of "Wide\\String" surrounded by noise.
        let mut data = vec![0xaa, 0xbb];
        for ch in "WideString".chars() {
            data.push(ch as u8);
            data.push(0x00);
        }
        data.extend_from_slice(&[0xcc, 0xdd]);

        let opts = ExtractOptions::default();
        let found = extract_strings(&data, &opts);

        assert!(
            found
                .iter()
                .any(|s| s.kind == StringKind::Wide && s.text == "WideString"),
            "expected to recover WideString as Wide, got: {found:?}"
        );
    }

    #[test]
    fn min_len_filters_short_runs() {
        // "abc" is length 3; with min_len 4 it must be filtered out, with 3 kept.
        let data = b"\x00abc\x00".to_vec();

        let mut opts = ExtractOptions::default();
        opts.wide = false;
        opts.code_refs = false;
        opts.stack_strings = false;

        opts.min_len = 4;
        let found = extract_strings(&data, &opts);
        assert!(
            !found.iter().any(|s| s.text == "abc"),
            "min_len 4 should drop 'abc', got: {found:?}"
        );

        opts.min_len = 3;
        let found = extract_strings(&data, &opts);
        assert!(
            found.iter().any(|s| s.text == "abc"),
            "min_len 3 should keep 'abc', got: {found:?}"
        );
    }

    #[test]
    fn dedup_collapses_identical_kind_text() {
        // Two identical ASCII runs of the same text must collapse to one entry
        // per (kind, text).
        let mut data = Vec::new();
        data.extend_from_slice(b"REPEATED");
        data.push(0x00);
        data.extend_from_slice(b"REPEATED");
        data.push(0x00);

        let mut opts = ExtractOptions::default();
        opts.wide = false;
        opts.code_refs = false;
        opts.stack_strings = false;

        let found = extract_strings(&data, &opts);
        let count = found
            .iter()
            .filter(|s| s.kind == StringKind::Ascii && s.text == "REPEATED")
            .count();
        assert_eq!(count, 1, "expected exactly one deduped entry, got: {found:?}");
    }

    #[test]
    fn max_strings_caps_output() {
        // Many distinct short runs; cap to 2.
        let mut data = Vec::new();
        for tag in ["AAAA", "BBBB", "CCCC", "DDDD"] {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }

        let mut opts = ExtractOptions::default();
        opts.wide = false;
        opts.code_refs = false;
        opts.stack_strings = false;
        opts.max_strings = 2;

        let found = extract_strings(&data, &opts);
        assert!(found.len() <= 2, "expected at most 2 strings, got: {found:?}");
    }
}
