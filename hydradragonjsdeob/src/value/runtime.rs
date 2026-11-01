//! Browser runtime APIs in pure Rust: atob, btoa, escape, unescape.
//!
//! These are NOT ECMAScript spec — they're Web API / browser globals.
//! Implemented in Rust for fast-path evaluation without Node.js.

use super::JsValue;

/// Evaluate a browser runtime function.
pub fn call(func: &str, args: &[JsValue]) -> Option<JsValue> {
    let s = match args.first()? {
        JsValue::String(s) => s.as_str(),
        _ => return None,
    };
    let result = match func {
        "atob" => atob(s)?,
        "btoa" => btoa(s)?,
        "escape" => escape(s),
        "unescape" => unescape(s)?,
        _ => return None,
    };
    Some(JsValue::String(result))
}

/// Base64 decode (browser `atob`). Latin-1 semantics.
fn atob(input: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(input).ok()?;
    Some(bytes.iter().map(|&b| b as char).collect())
}

/// Base64 encode (browser `btoa`). Only accepts Latin-1 characters.
fn btoa(input: &str) -> Option<String> {
    if input.chars().any(|c| c as u32 > 0xFF) {
        return None; // InvalidCharacterError
    }
    use base64::Engine as _;
    let bytes: Vec<u8> = input.chars().map(|c| c as u8).collect();
    Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
}

/// Percent-encode (browser `escape`). Encodes non-ASCII and special chars.
fn escape(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '@' | '*' | '_' | '+' | '-' | '.' | '/' => {
                result.push(c);
            }
            c if (c as u32) <= 0xFF => {
                result.push_str(&format!("%{:02X}", c as u32));
            }
            c => {
                result.push_str(&format!("%u{:04X}", c as u32));
            }
        }
    }
    result
}

/// Percent-decode (browser `unescape`).
fn unescape(input: &str) -> Option<String> {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            if i + 6 <= chars.len() && chars[i + 1] == 'u' {
                // %uXXXX — try to decode, pass through on failure
                let hex: String = chars[i+2..i+6].iter().collect();
                if let Some(code) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    result.push(code);
                    i += 6;
                    continue;
                }
            }
            if i + 3 <= chars.len() {
                // %XX — try to decode, pass through on failure
                let hex: String = chars[i+1..i+3].iter().collect();
                if let Ok(code) = u8::from_str_radix(&hex, 16) {
                    result.push(code as char);
                    i += 3;
                    continue;
                }
            }
            // Malformed — pass through the %
            result.push('%');
            i += 1;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }

    #[test]
    fn test_atob() {
        assert_eq!(call("atob", &[s("SGVsbG8=")]), Some(s("Hello")));
        assert_eq!(call("atob", &[s("dGVzdA==")]), Some(s("test")));
    }

    #[test]
    fn test_btoa() {
        assert_eq!(call("btoa", &[s("Hello")]), Some(s("SGVsbG8=")));
        assert_eq!(call("btoa", &[s("test")]), Some(s("dGVzdA==")));
    }

    #[test]
    fn test_roundtrip() {
        let original = "Hello, World!";
        let encoded = btoa(original).unwrap();
        let decoded = atob(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_escape() {
        assert_eq!(call("escape", &[s("hello world")]), Some(s("hello%20world")));
        assert_eq!(call("escape", &[s("abc")]), Some(s("abc")));
    }

    #[test]
    fn test_unescape() {
        assert_eq!(call("unescape", &[s("hello%20world")]), Some(s("hello world")));
        assert_eq!(call("unescape", &[s("%u0041")]), Some(s("A")));
    }

    #[test]
    fn test_unescape_boundary() {
        // %uXXXX at end of string — regression for bounds check
        assert_eq!(call("unescape", &[s("%u0042")]), Some(s("B")));
        // Truncated %u at end should not panic
        assert_eq!(call("unescape", &[s("abc%u004")]), Some(s("abc%u004")));
    }
}
