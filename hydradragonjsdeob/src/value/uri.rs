//! URI encoding/decoding functions.

use super::JsValue;

/// Evaluate global URI function: `encodeURI`, `decodeURI`, etc.
pub fn call(func: &str, args: &[JsValue]) -> Option<JsValue> {
    let s = match args.first()? {
        JsValue::String(s) => s.as_str(),
        _ => return None,
    };
    let result = match func {
        "encodeURI" => encode_uri(s),
        "decodeURI" => decode_uri(s)?,
        "encodeURIComponent" => encode_uri_component(s),
        "decodeURIComponent" => decode_uri_component(s)?,
        _ => return None,
    };
    Some(JsValue::String(result))
}

fn encode_uri(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        if is_uri_unescaped(b) || is_uri_reserved(b) || b == b'#' {
            result.push(b as char);
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}

fn encode_uri_component(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        if is_uri_unescaped(b) {
            result.push(b as char);
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}

fn decode_uri(s: &str) -> Option<String> {
    percent_decode(s, true)
}

fn decode_uri_component(s: &str) -> Option<String> {
    percent_decode(s, false)
}

fn percent_decode(s: &str, preserve_reserved: bool) -> Option<String> {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            let byte = (hi << 4) | lo;
            if preserve_reserved && (is_uri_reserved(byte) || byte == b'#') {
                result.push('%');
                result.push(bytes[i + 1] as char);
                result.push(bytes[i + 2] as char);
            } else {
                result.push(byte as char);
            }
            i += 3;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    Some(result)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn is_uri_unescaped(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')')
}

fn is_uri_reserved(b: u8) -> bool {
    matches!(b, b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',')
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }

    #[test]
    fn test_encode_uri_component() {
        assert_eq!(call("encodeURIComponent", &[s("hello world")]), Some(s("hello%20world")));
        assert_eq!(call("encodeURIComponent", &[s("a=1&b=2")]), Some(s("a%3D1%26b%3D2")));
    }

    #[test]
    fn test_decode_uri_component() {
        assert_eq!(call("decodeURIComponent", &[s("hello%20world")]), Some(s("hello world")));
        assert_eq!(call("decodeURIComponent", &[s("a%3D1%26b%3D2")]), Some(s("a=1&b=2")));
    }

    #[test]
    fn test_encode_uri() {
        assert_eq!(call("encodeURI", &[s("https://example.com/path?q=hello world")]),
            Some(s("https://example.com/path?q=hello%20world")));
    }

    #[test]
    fn test_decode_uri() {
        assert_eq!(call("decodeURI", &[s("https://example.com/path?q=hello%20world")]),
            Some(s("https://example.com/path?q=hello world")));
    }
}
