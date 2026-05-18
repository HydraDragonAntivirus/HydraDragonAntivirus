use crate::models::{DecodedString, StringHit};
use crate::utils::text::{is_mostly_printable, rot13, truncate_middle};
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static B64_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9+/]{12,}={0,2}$").unwrap());
static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:0x)?[0-9a-fA-F]{10,}$").unwrap());
static URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)https?://|ftp://|wss?://").unwrap());
static POWERSHELL_HINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(powershell|pwsh|frombase64string|-enc|-encodedcommand|iex|invoke-expression)").unwrap());

pub fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    let mut out = Vec::new();
    extract_ascii(bytes, min_len, &mut out);
    extract_utf16le(bytes, min_len, &mut out);
    out.sort_by_key(|s| s.offset);
    out
}

fn extract_ascii(bytes: &[u8], min_len: usize, out: &mut Vec<StringHit>) {
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        let printable = b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b);
        if printable {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                let value = String::from_utf8_lossy(&bytes[s..i]).to_string();
                out.push(StringHit { value, offset: s, encoding: "ascii".into() });
            }
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= min_len {
            out.push(StringHit { value: String::from_utf8_lossy(&bytes[s..]).to_string(), offset: s, encoding: "ascii".into() });
        }
    }
}

fn extract_utf16le(bytes: &[u8], min_len: usize, out: &mut Vec<StringHit>) {
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let start = i;
        let mut words = Vec::new();
        while i + 1 < bytes.len() {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if hi == 0 && (lo == b'\t' || lo == b'\n' || lo == b'\r' || (0x20..=0x7e).contains(&lo)) {
                words.push(lo as u16);
                i += 2;
            } else {
                break;
            }
        }
        if words.len() >= min_len {
            let value = String::from_utf16_lossy(&words);
            out.push(StringHit { value, offset: start, encoding: "utf16le".into() });
        }
        i = if i == start { i + 2 } else { i + 2 };
    }
}

pub fn decode_obfuscated_strings(strings: &[StringHit]) -> Vec<DecodedString> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for hit in strings.iter().filter(|s| s.value.len() <= 4096) {
        let raw = hit.value.trim_matches('\0').trim();
        if raw.len() < 6 {
            continue;
        }

        maybe_push_reverse(raw, &mut out, &mut seen);
        maybe_push_rot13(raw, &mut out, &mut seen);
        maybe_push_base64(raw, &mut out, &mut seen);
        maybe_push_hex(raw, &mut out, &mut seen);
        maybe_push_xor(raw.as_bytes(), raw, &mut out, &mut seen);
    }
    out
}

fn push_decoded(method: &str, source: &str, decoded: String, out: &mut Vec<DecodedString>, seen: &mut HashSet<String>) {
    if decoded.len() < 4 || !is_mostly_printable(decoded.as_bytes()) {
        return;
    }
    let key = format!("{method}:{decoded}");
    if seen.insert(key) {
        out.push(DecodedString {
            method: method.to_string(),
            source: truncate_middle(source, 128),
            decoded: truncate_middle(decoded.trim(), 512),
        });
    }
}

fn maybe_push_base64(raw: &str, out: &mut Vec<DecodedString>, seen: &mut HashSet<String>) {
    let cleaned = raw.trim();
    if cleaned.len() % 4 != 0 || !B64_RE.is_match(cleaned) {
        return;
    }
    if let Ok(bytes) = general_purpose::STANDARD.decode(cleaned) {
        if let Ok(text) = String::from_utf8(bytes) {
            push_decoded("base64", raw, text, out, seen);
        }
    }
}

fn maybe_push_hex(raw: &str, out: &mut Vec<DecodedString>, seen: &mut HashSet<String>) {
    let mut cleaned = raw.trim();
    if let Some(stripped) = cleaned.strip_prefix("0x") {
        cleaned = stripped;
    }
    if cleaned.len() % 2 != 0 || !HEX_RE.is_match(cleaned) {
        return;
    }
    if let Ok(bytes) = hex::decode(cleaned) {
        if let Ok(text) = String::from_utf8(bytes) {
            push_decoded("hex", raw, text, out, seen);
        }
    }
}

fn maybe_push_reverse(raw: &str, out: &mut Vec<DecodedString>, seen: &mut HashSet<String>) {
    let reversed: String = raw.chars().rev().collect();
    if URL_RE.is_match(&reversed) || POWERSHELL_HINT_RE.is_match(&reversed) || reversed.contains(".exe") || reversed.contains("HKEY_") {
        push_decoded("reverse", raw, reversed, out, seen);
    }
}

fn maybe_push_rot13(raw: &str, out: &mut Vec<DecodedString>, seen: &mut HashSet<String>) {
    let decoded = rot13(raw);
    if URL_RE.is_match(&decoded) || POWERSHELL_HINT_RE.is_match(&decoded) || decoded.contains(".exe") {
        push_decoded("rot13", raw, decoded, out, seen);
    }
}

fn maybe_push_xor(bytes: &[u8], raw: &str, out: &mut Vec<DecodedString>, seen: &mut HashSet<String>) {
    if bytes.len() < 8 || bytes.len() > 256 {
        return;
    }

    // Reuse one buffer for all 255 keys. The old implementation allocated a new
    // Vec for every candidate key, which is expensive on large string tables.
    let mut decoded_bytes = vec![0u8; bytes.len()];
    for key in 1u8..=255u8 {
        for (dst, src) in decoded_bytes.iter_mut().zip(bytes.iter()) {
            *dst = *src ^ key;
        }
        if !is_mostly_printable(&decoded_bytes) {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(&decoded_bytes) {
            if URL_RE.is_match(text) || POWERSHELL_HINT_RE.is_match(text) || text.contains(".exe") || text.contains("cmd") {
                push_decoded(&format!("xor_0x{key:02x}"), raw, text.to_string(), out, seen);
                break;
            }
        }
    }
}
