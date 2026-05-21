use crate::models::{DecodedString, StringHit};
use crate::utils::text::{is_mostly_printable, rot13, truncate_middle};
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static B64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9+/]{12,}={0,2}$").unwrap()
});
static HEX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:0x)?[0-9a-fA-F]{10,}$").unwrap()
});
static URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)https?://|ftp://|wss?://").unwrap()
});
static POWERSHELL_HINT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(powershell|pwsh|frombase64string|-enc|-encodedcommand|iex|invoke-expression)",
    )
    .unwrap()
});

pub struct ExtractConfig {
    pub min_len: usize,
}

pub struct DecodeConfig {
    /// Keywords that flag a string as HTTP-related.
    pub http_keywords: Vec<String>,
    /// Keywords that flag a string as shell/cmd-related.
    pub cmd_keywords: Vec<String>,
    /// Keywords that flag a string as executable-related.
    pub exe_keywords: Vec<String>,
    /// Keywords that flag a string as registry-related.
    pub reg_keywords: Vec<String>,
    /// Strings shorter than this are skipped unless a keyword matches.
    pub suspicious_short_threshold: usize,
    /// Maximum strings consumed from input.
    pub input_limit: usize,
    /// Maximum decoded results emitted.
    pub output_limit: usize,
    /// Accepted raw string length range [min, max].
    pub raw_len_range: (usize, usize),
    /// Accepted base64 candidate length range [min, max].
    pub b64_len_range: (usize, usize),
    /// Accepted hex candidate length range [min, max].
    pub hex_len_range: (usize, usize),
    /// Accepted XOR candidate length range [min, max].
    pub xor_len_range: (usize, usize),
    /// Minimum decoded string length to keep.
    pub decoded_min_len: usize,
    /// Truncation limit for the source field.
    pub source_trunc: usize,
    /// Truncation limit for the decoded field.
    pub decoded_trunc: usize,
}

pub fn extract_strings(bytes: &[u8], cfg: &ExtractConfig) -> Vec<StringHit> {
    let cap = (bytes.len() / 100).min(50_000);
    let mut out = Vec::with_capacity(cap);
    extract_ascii(bytes, cfg.min_len, &mut out);
    extract_utf16le(bytes, cfg.min_len, &mut out);
    out.sort_unstable_by_key(|s| s.offset);
    out.shrink_to_fit();
    out
}

pub fn decode_obfuscated_strings(strings: &[StringHit], cfg: &DecodeConfig) -> Vec<DecodedString> {
    let limit = strings.len().min(cfg.input_limit);
    let mut out = Vec::with_capacity(limit / 10);
    let mut seen = HashSet::with_capacity(limit / 5);

    let (raw_min, raw_max) = cfg.raw_len_range;

    for hit in strings
        .iter()
        .take(limit)
        .filter(|s| s.value.len() >= raw_min && s.value.len() <= cfg.output_limit)
    {
        let raw = hit.value.trim_matches('\0').trim();
        if raw.len() < raw_min || raw.len() > raw_max {
            continue;
        }

        let has_http = cfg.http_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_cmd  = cfg.cmd_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_exe  = cfg.exe_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_reg  = cfg.reg_keywords.iter().any(|kw| raw.contains(kw.as_str()));

        if !(has_http || has_cmd || has_exe || has_reg)
            && raw.len() < cfg.suspicious_short_threshold
        {
            continue;
        }

        if has_http || has_cmd || has_exe {
            maybe_push_reverse(raw, &cfg.exe_keywords, &mut out, &mut seen);
            maybe_push_rot13(raw, &cfg.exe_keywords, &mut out, &mut seen);
        }

        let (b64_min, b64_max) = cfg.b64_len_range;
        if raw.len() >= b64_min && raw.len() <= b64_max && is_base64_alphabet(raw.as_bytes()) {
            maybe_push_base64(raw, cfg, &mut out, &mut seen);
        }

        let (hex_min, hex_max) = cfg.hex_len_range;
        if raw.len() >= hex_min && raw.len() <= hex_max && is_hex_alphabet(raw.as_bytes()) {
            maybe_push_hex(raw, cfg, &mut out, &mut seen);
        }

        let (xor_min, xor_max) = cfg.xor_len_range;
        if (has_cmd || has_exe) && raw.len() >= xor_min && raw.len() <= xor_max {
            maybe_push_xor(raw.as_bytes(), raw, &cfg.exe_keywords, &cfg.cmd_keywords, cfg, &mut out, &mut seen);
        }

        if out.len() >= cfg.output_limit {
            break;
        }
    }
    out.shrink_to_fit();
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
                out.push(StringHit {
                    value: String::from_utf8_lossy(&bytes[s..i]).into_owned(),
                    offset: s,
                    encoding: "ascii".into(),
                });
            }
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= min_len {
            out.push(StringHit {
                value: String::from_utf8_lossy(&bytes[s..]).into_owned(),
                offset: s,
                encoding: "ascii".into(),
            });
        }
    }
}

fn extract_utf16le(bytes: &[u8], min_len: usize, out: &mut Vec<StringHit>) {
    let mut i = 0usize;
    let mut words: Vec<u16> = Vec::with_capacity(256);

    while i + 1 < bytes.len() {
        let start = i;
        words.clear();

        while i + 1 < bytes.len() {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if hi == 0
                && (lo == b'\t' || lo == b'\n' || lo == b'\r' || (0x20..=0x7e).contains(&lo))
            {
                words.push(lo as u16);
                i += 2;
            } else {
                break;
            }
        }

        if words.len() >= min_len {
            out.push(StringHit {
                value: String::from_utf16_lossy(&words),
                offset: start,
                encoding: "utf16le".into(),
            });
        }

        if i == start {
            i += 2;
        }
    }
}

fn push_decoded(
    method: &str,
    source: &str,
    decoded: String,
    cfg: &DecodeConfig,
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    if decoded.len() < cfg.decoded_min_len || !is_mostly_printable(decoded.as_bytes()) {
        return;
    }
    let mut key = String::with_capacity(method.len() + 1 + decoded.len());
    key.push_str(method);
    key.push(':');
    key.push_str(&decoded);
    if seen.insert(key) {
        out.push(DecodedString {
            method: method.to_string(),
            source: truncate_middle(source, cfg.source_trunc),
            decoded: truncate_middle(decoded.trim(), cfg.decoded_trunc),
        });
    }
}

fn maybe_push_base64(
    raw: &str,
    cfg: &DecodeConfig,
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    let cleaned = raw.trim();
    if !B64_RE.is_match(cleaned) {
        return;
    }
    let result = if cleaned.len() % 4 == 0 {
        general_purpose::STANDARD.decode(cleaned)
    } else {
        general_purpose::STANDARD_NO_PAD.decode(cleaned)
    };
    if let Ok(bytes) = result {
        if let Ok(text) = String::from_utf8(bytes) {
            push_decoded("base64", raw, text, cfg, out, seen);
        }
    }
}

fn maybe_push_hex(
    raw: &str,
    cfg: &DecodeConfig,
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    let mut cleaned = raw.trim();
    if let Some(stripped) = cleaned.strip_prefix("0x") {
        cleaned = stripped;
    }
    if cleaned.len() % 2 != 0 || !HEX_RE.is_match(cleaned) {
        return;
    }
    if let Ok(bytes) = hex::decode(cleaned) {
        if let Ok(text) = String::from_utf8(bytes) {
            push_decoded("hex", raw, text, cfg, out, seen);
        }
    }
}

fn maybe_push_reverse(
    raw: &str,
    exe_keywords: &[String],
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    let reversed: String = raw.chars().rev().collect();
    let hits_keyword = exe_keywords.iter().any(|kw| reversed.contains(kw.as_str()));
    if URL_RE.is_match(&reversed) || POWERSHELL_HINT_RE.is_match(&reversed) || hits_keyword {
        // push_decoded needs cfg; caller must pass it — refactor to pass cfg here too if needed
        // For now we reuse a minimal inline push since cfg isn't threaded here
        let mut key = String::with_capacity("reverse".len() + 1 + reversed.len());
        key.push_str("reverse:");
        key.push_str(&reversed);
        if seen.insert(key) {
            out.push(DecodedString {
                method: "reverse".to_string(),
                source: truncate_middle(raw, 128),
                decoded: truncate_middle(reversed.trim(), 512),
            });
        }
    }
}

fn maybe_push_rot13(
    raw: &str,
    exe_keywords: &[String],
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    let decoded = rot13(raw);
    let hits_keyword = exe_keywords.iter().any(|kw| decoded.contains(kw.as_str()));
    if URL_RE.is_match(&decoded) || POWERSHELL_HINT_RE.is_match(&decoded) || hits_keyword {
        let mut key = String::with_capacity("rot13".len() + 1 + decoded.len());
        key.push_str("rot13:");
        key.push_str(&decoded);
        if seen.insert(key) {
            out.push(DecodedString {
                method: "rot13".to_string(),
                source: truncate_middle(raw, 128),
                decoded: truncate_middle(decoded.trim(), 512),
            });
        }
    }
}

fn maybe_push_xor(
    bytes: &[u8],
    raw: &str,
    exe_keywords: &[String],
    cmd_keywords: &[String],
    cfg: &DecodeConfig,
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    let (xor_min, xor_max) = cfg.xor_len_range;
    if bytes.len() < xor_min || bytes.len() > xor_max {
        return;
    }
    let mut buf = vec![0u8; bytes.len()];
    for key in 1u8..=255u8 {
        for (dst, &src) in buf.iter_mut().zip(bytes.iter()) {
            *dst = src ^ key;
        }
        if !is_mostly_printable(&buf) {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(&buf) {
            let hits = URL_RE.is_match(text)
                || POWERSHELL_HINT_RE.is_match(text)
                || exe_keywords.iter().any(|kw| text.contains(kw.as_str()))
                || cmd_keywords.iter().any(|kw| text.contains(kw.as_str()));
            if hits {
                push_decoded(
                    &format!("xor_0x{key:02x}"),
                    raw,
                    text.to_string(),
                    cfg,
                    out,
                    seen,
                );
                break;
            }
        }
    }
}

#[inline(always)]
fn is_base64_alphabet(b: &[u8]) -> bool {
    b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
}

#[inline(always)]
fn is_hex_alphabet(b: &[u8]) -> bool {
    b.iter().all(|&c| c.is_ascii_hexdigit())
}
