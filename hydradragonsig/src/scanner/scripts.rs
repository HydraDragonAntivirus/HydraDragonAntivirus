//! Script/IL-type preprocessing: extracts readable text from script-obfuscated
//! payloads so the `decoded` string conditions act as script rules too. Runs
//! on the extracted strings before the generic base64/hex pass
//! ([`crate::scanner::strings`]) and adds the focused decoder families:
//!
//! * PowerShell `-EncodedCommand` / `-enc` / `-e <base64>` (UTF-16LE by
//!   default), and `FromBase64String("...")` payloads (UTF-8 or UTF-16LE).
//! * JScript/browser `atob("...")`.
//! * VBScript/JScript `Chr(n)` concatenation chains.
//!
//! Outputs reuse the `DecodedString` layout (`method` names the decoder), so
//! downstream conditions, features and evidence stay uniform.
use crate::models::{DecodedString, StringHit};
use crate::utils::text::truncate_middle;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

pub struct ScriptDecodeConfig {
    pub input_limit: usize,
    pub output_limit: usize,
    pub decoded_min_len: usize,
    pub source_trunc: usize,
    pub decoded_trunc: usize,
}

impl Default for ScriptDecodeConfig {
    fn default() -> Self {
        Self {
            input_limit: 50_000,
            output_limit: 2_000,
            decoded_min_len: 8,
            source_trunc: 128,
            decoded_trunc: 512,
        }
    }
}

/// `-EncodedCommand` / `-enc` / `-e ` followed by a bare base64 token.
static PS_ENCODED_COMMAND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:^|[\s"'`])(?:-|/|%)(?:encodedcommand|enc|e)\s+([A-Za-z0-9+/=]{12,})"#)
        .unwrap()
});
static PS_FROM_BASE64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)FromBase64String\s*\(\s*["']([A-Za-z0-9+/=]{12,})["']"#).unwrap()
});
static JS_ATOB_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\batob\s*\(\s*["']([A-Za-z0-9+/=]{12,})["']"#).unwrap()
});
/// Whole `Chr(n)&Chr(n)...` run (3+ members).
static VBS_CHAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)chrw?\s*\(\s*\d+\s*\)(?:(?:\s*|&|\+|,)+chrw?\s*\(\s*\d+\s*\)){2,}"#).unwrap()
});
static CHN_CALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)chrw?\s*\(\s*(\d+)\s*\)"#).unwrap());

/// Base64 of a script argument may carry inner whitespace; strip it.
fn b64_clean(token: &str) -> String {
    token
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
}

fn flag(
    method: &str,
    source: &str,
    decoded: &str,
    cfg: &ScriptDecodeConfig,
    seen: &mut HashSet<(String, String)>,
    out: &mut Vec<DecodedString>,
) {
    let decoded = decoded.trim().replace(['\r', '\n'], " ");
    if decoded.chars().count() < cfg.decoded_min_len {
        return;
    }
    let key = (method.to_string(), decoded.clone());
    if seen.insert(key) {
        out.push(DecodedString {
            method: method.to_string(),
            source: truncate_middle(source, cfg.source_trunc),
            decoded: truncate_middle(&decoded, cfg.decoded_trunc),
        });
    }
}

/// Runs every script decoder over the extracted strings.
pub fn script_decoded_strings(strings: &[StringHit], cfg: &ScriptDecodeConfig) -> Vec<DecodedString> {
    let mut out: Vec<DecodedString> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for hit in strings.iter().take(cfg.input_limit) {
        let raw = hit.value.as_str();

        for cap in PS_ENCODED_COMMAND_RE.captures_iter(raw) {
            if let Some(token) = cap.get(1) {
                if let Some(text) = crate::scanner::strings::decode_base64(&b64_clean(token.as_str()))
                    .as_deref()
                    .and_then(crate::scanner::strings::readable_text)
                {
                    flag("ps_encodedcommand", raw, &text, cfg, &mut seen, &mut out);
                }
            }
        }

        for (re, method) in [(&*PS_FROM_BASE64_RE, "ps_frombase64string"), (&*JS_ATOB_RE, "js_atob")] {
            for cap in re.captures_iter(raw) {
                if let Some(token) = cap.get(1) {
                    if let Some(text) = crate::scanner::strings::decode_base64(&b64_clean(token.as_str()))
                        .as_deref()
                        .and_then(crate::scanner::strings::readable_text)
                    {
                        flag(method, raw, &text, cfg, &mut seen, &mut out);
                    }
                }
            }
        }

        for chain in VBS_CHAIN_RE.find_iter(raw) {
            let chars: String = CHN_CALL_RE
                .find_iter(chain.as_str())
                .filter_map(|m| {
                    let value = m.as_str();
                    let digits = &value[value.find('(')? + 1..value.rfind(')')?];
                    digits.trim().parse::<u32>().ok().and_then(char::from_u32)
                })
                .collect();
            flag("vbs_chr_chain", chain.as_str(), &chars, cfg, &mut seen, &mut out);
        }

        if out.len() >= cfg.output_limit {
            break;
        }
    }

    out.shrink_to_fit();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(value: &str) -> StringHit {
        StringHit {
            value: value.into(),
            offset: 0,
            encoding: "ascii".into(),
        }
    }

    #[test]
    fn decodes_script_payloads() {
        let strings = [
            hit("powershell -nop -enc aQBuAHYAbwBpAGMAZQAgAHIAZQBtAGkAbgBkAGUAcgAgAC0ALQB0AGkAbQBlAHMAdABhAG0AcAAgADIAMAAyADYA"),
            hit("[Convert]::FromBase64String(\"Y2RuLWFsZXJ0LXJ1bm5lciBib290\")"),
            hit("(new String(Chr(100)&Chr(111)&Chr(119)&Chr(110)&Chr(108)&Chr(111)&Chr(97)&Chr(100)&Chr(45)&Chr(112)&Chr(97)&Chr(121)&Chr(108)&Chr(111)&Chr(99)))"),
            hit("no payload here"),
        ];
        let out = script_decoded_strings(&strings, &ScriptDecodeConfig::default());
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(out.iter().any(|d| d.method == "ps_encodedcommand" && d.decoded == "invoice reminder --timestamp 2026"));
        assert!(out.iter().any(|d| d.method == "ps_frombase64string" && d.decoded == "cdn-alert-runner boot"));
        assert!(out.iter().any(|d| d.method == "vbs_chr_chain" && d.decoded == "download-payloc"));
    }

    #[test]
    fn skips_short_and_binary_decodes() {
        let strings = [hit("x -e aGVsbG8="), hit("FromBase64String(\"dfkYe1982\")")];
        assert!(script_decoded_strings(&strings, &ScriptDecodeConfig::default()).is_empty());
    }
}
