use crate::models::{DecodedString, StringHit};
use crate::utils::text::truncate_middle;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)https?://|ftp://|wss?://").unwrap());
static POWERSHELL_HINT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(powershell|pwsh|frombase64string|-enc|-encodedcommand|iex|invoke-expression)")
        .unwrap()
});
static B64_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9+/]{12,}={0,2}$").unwrap());
static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:0x)?[0-9a-fA-F]{10,}$").unwrap());

pub struct ExtractConfig {
    pub min_len: usize,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self { min_len: 5 }
    }
}

#[derive(Debug, Clone)]
pub struct DecodeConfig {
    pub http_keywords: Vec<String>,
    pub cmd_keywords: Vec<String>,
    pub exe_keywords: Vec<String>,
    pub reg_keywords: Vec<String>,
    pub suspicious_short_threshold: usize,
    pub input_limit: usize,
    pub output_limit: usize,
    pub raw_len_range: (usize, usize),
    pub b64_len_range: (usize, usize),
    pub hex_len_range: (usize, usize),
    pub decoded_min_len: usize,
    pub source_trunc: usize,
    pub decoded_trunc: usize,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            http_keywords: vec!["http".into()],
            cmd_keywords: vec!["cmd".into(), "powershell".into()],
            exe_keywords: vec![".exe".into(), ".dll".into()],
            reg_keywords: vec!["HKEY".into(), "Registry".into()],
            suspicious_short_threshold: 32,
            input_limit: 3_000,
            output_limit: 500,
            raw_len_range: (10, 256),
            b64_len_range: (16, 200),
            hex_len_range: (20, 128),
            decoded_min_len: 4,
            source_trunc: 128,
            decoded_trunc: 512,
        }
    }
}

// Public API.

pub fn extract_strings(bytes: &[u8], cfg: &ExtractConfig) -> Vec<StringHit> {
    let cap = (bytes.len() / 100).min(50_000);
    let mut out = Vec::with_capacity(cap);
    extract_ascii(bytes, cfg.min_len, &mut out);
    extract_utf16le(bytes, cfg.min_len, &mut out);
    out.sort_unstable_by_key(|s| s.offset);
    out.shrink_to_fit();
    out
}

/// Scans strings as-is — no decoding, no transformation.
/// Tags each string with its detected encoding type and moves on.
pub fn classify_strings(strings: &[StringHit], cfg: &DecodeConfig) -> Vec<DecodedString> {
    let limit = strings.len().min(cfg.input_limit);
    let mut out = Vec::with_capacity(limit / 10);
    let mut seen = HashSet::with_capacity(limit / 5);

    let (raw_min, raw_max) = cfg.raw_len_range;

    for hit in strings.iter().take(limit) {
        let raw = hit.value.trim_matches('\0').trim();
        if raw.len() < raw_min || raw.len() > raw_max {
            continue;
        }

        let has_http = cfg.http_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_cmd = cfg.cmd_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_exe = cfg.exe_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_reg = cfg.reg_keywords.iter().any(|kw| raw.contains(kw.as_str()));
        let has_url = URL_RE.is_match(raw);
        let has_ps = POWERSHELL_HINT_RE.is_match(raw);

        // Detect encoding type purely by shape of the raw string.
        let (b64_min, b64_max) = cfg.b64_len_range;
        let (hex_min, hex_max) = cfg.hex_len_range;

        let encoding = if raw.len() >= b64_min
            && raw.len() <= b64_max
            && is_base64_alphabet(raw.as_bytes())
            && B64_RE.is_match(raw)
        {
            Some("base64")
        } else if raw.len() >= hex_min
            && raw.len() <= hex_max
            && is_hex_alphabet(raw.as_bytes())
            && HEX_RE.is_match(raw.trim_start_matches("0x"))
        {
            Some("hex")
        } else {
            None
        };

        // Only keep it if it looks encoded OR contains suspicious plaintext.
        let is_suspicious = has_http || has_cmd || has_exe || has_reg || has_url || has_ps;
        let is_encoded = encoding.is_some();

        if !is_suspicious && !is_encoded {
            if raw.len() < cfg.suspicious_short_threshold {
                continue;
            }
        }

        let method = encoding.unwrap_or("plaintext");
        flag(method, raw, cfg, &mut out, &mut seen);

        if out.len() >= cfg.output_limit {
            break;
        }
    }

    out.shrink_to_fit();
    out
}

// Keep old name as alias so mod.rs doesn't break.
pub fn decode_obfuscated_strings(strings: &[StringHit], cfg: &DecodeConfig) -> Vec<DecodedString> {
    classify_strings(strings, cfg)
}

// Extractors.

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
            if hi == 0 && (lo == b'\t' || lo == b'\n' || lo == b'\r' || (0x20..=0x7e).contains(&lo))
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

// Classification helper.

fn flag(
    method: &str,
    raw: &str,
    cfg: &DecodeConfig,
    out: &mut Vec<DecodedString>,
    seen: &mut HashSet<String>,
) {
    if raw.len() < cfg.decoded_min_len {
        return;
    }
    let mut key = String::with_capacity(method.len() + 1 + raw.len());
    key.push_str(method);
    key.push(':');
    key.push_str(raw);
    if seen.insert(key) {
        out.push(DecodedString {
            method: method.to_string(),
            source: truncate_middle(raw, cfg.source_trunc),
            decoded: truncate_middle(raw.trim(), cfg.decoded_trunc),
        });
    }
}

// Alphabet checks.

#[inline(always)]
fn is_base64_alphabet(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
}

#[inline(always)]
fn is_hex_alphabet(b: &[u8]) -> bool {
    b.iter().all(|&c| c.is_ascii_hexdigit())
}
