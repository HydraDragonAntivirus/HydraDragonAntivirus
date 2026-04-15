// src-tauri/src/strings.rs
// Extract printable ASCII and wide-char strings from a binary.
// Minimum configurable length; supports ASCII and UTF-16LE ("wide") strings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub enum StringKind {
    Ascii,
    Wide,
}

impl Serialize for StringKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self { StringKind::Ascii => "ASCII", StringKind::Wide => "Wide" })
    }
}

impl<'de> Deserialize<'de> for StringKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match String::deserialize(d)?.as_str() {
            "Wide" => StringKind::Wide,
            _      => StringKind::Ascii,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: u64,
    pub kind:   StringKind,
    pub value:  String,
    pub length: usize,
}

/// Returns `true` for bytes that belong to a printable ASCII string.
#[inline]
fn is_printable(b: u8) -> bool {
    (b >= 0x20 && b < 0x7F) || b == b'\t' || b == b'\r' || b == b'\n'
}

/// Extract ASCII strings of at least `min_len` characters.
pub fn extract_ascii(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        if is_printable(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let run = &data[s..i];
            if run.len() >= min_len {
                results.push(ExtractedString {
                    offset: s as u64,
                    kind:   StringKind::Ascii,
                    value:  String::from_utf8_lossy(run)
                        .chars()
                        .filter(|c| !c.is_control() || *c == '\t')
                        .collect(),
                    length: run.len(),
                });
            }
        }
    }

    // Handle string ending at EOF
    if let Some(s) = start {
        let run = &data[s..];
        if run.len() >= min_len {
            results.push(ExtractedString {
                offset: s as u64,
                kind:   StringKind::Ascii,
                value:  String::from_utf8_lossy(run)
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\t')
                    .collect(),
                length: run.len(),
            });
        }
    }

    results
}

/// Extract UTF-16LE ("wide") strings of at least `min_len` characters.
/// Windows executables commonly store API names and URLs in wide format.
pub fn extract_wide(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    if data.len() < 2 {
        return results;
    }

    let mut start: Option<usize> = None;
    let mut chars: Vec<char>     = Vec::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        // Wide ASCII range: lo is printable, hi == 0x00
        if hi == 0x00 && is_printable(lo) {
            if start.is_none() {
                start = Some(i);
            }
            chars.push(lo as char);
            i += 2;
        } else {
            if let Some(s) = start.take() {
                if chars.len() >= min_len {
                    results.push(ExtractedString {
                        offset: s as u64,
                        kind:   StringKind::Wide,
                        value:  chars.iter().collect(),
                        length: chars.len(),
                    });
                }
            }
            chars.clear();
            i += 1; // Only advance by 1 so we don't skip a valid pair
        }
    }

    // Handle wide string at EOF
    if let Some(s) = start {
        if chars.len() >= min_len {
            results.push(ExtractedString {
                offset: s as u64,
                kind:   StringKind::Wide,
                value:  chars.iter().collect(),
                length: chars.len(),
            });
        }
    }

    results
}

/// Convenience: extract both kinds and sort by offset.
pub fn extract_all(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut all = extract_ascii(data, min_len);
    all.extend(extract_wide(data, min_len));
    all.sort_by_key(|s| s.offset);
    all
}
