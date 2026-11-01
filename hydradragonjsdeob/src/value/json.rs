//! JSON.parse / JSON.stringify on JsValue.

use super::JsValue;

/// `JSON.stringify(value)` for primitive values.
pub fn stringify(val: &JsValue) -> Option<JsValue> {
    let s = match val {
        JsValue::Number(n) => {
            if n.is_nan() || n.is_infinite() { "null".to_string() }
            else { super::coerce::number_to_string(*n) }
        }
        JsValue::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        JsValue::Boolean(b) => b.to_string(),
        JsValue::Null => "null".to_string(),
        JsValue::Undefined => return Some(JsValue::Undefined), // undefined → undefined (omitted)
    };
    Some(JsValue::String(s))
}

/// `JSON.parse(string)` for simple values.
pub fn parse(s: &str) -> Option<JsValue> {
    let trimmed = s.trim();
    match trimmed {
        "null" => Some(JsValue::Null),
        "true" => Some(JsValue::Boolean(true)),
        "false" => Some(JsValue::Boolean(false)),
        _ if trimmed.starts_with('"') && trimmed.ends_with('"') => {
            let inner = &trimmed[1..trimmed.len()-1];
            Some(JsValue::String(json_unescape(inner)))
        }
        _ => {
            trimmed.parse::<f64>().ok().map(JsValue::Number)
        }
    }
}

/// Process JSON escape sequences in correct order.
fn json_unescape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('b') => result.push('\u{0008}'),
                Some('f') => result.push('\u{000C}'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                        }
                    }
                }
                Some(other) => { result.push('\\'); result.push(other); }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(v: f64) -> JsValue { JsValue::Number(v) }
    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }

    #[test]
    fn test_stringify() {
        assert_eq!(stringify(&n(42.0)), Some(s("42")));
        assert_eq!(stringify(&s("hello")), Some(s("\"hello\"")));
        assert_eq!(stringify(&JsValue::Boolean(true)), Some(s("true")));
        assert_eq!(stringify(&JsValue::Null), Some(s("null")));
        assert_eq!(stringify(&n(f64::NAN)), Some(s("null")));
    }

    #[test]
    fn test_parse() {
        assert_eq!(parse("42"), Some(n(42.0)));
        assert_eq!(parse("\"hello\""), Some(s("hello")));
        assert_eq!(parse("true"), Some(JsValue::Boolean(true)));
        assert_eq!(parse("null"), Some(JsValue::Null));
    }

    #[test]
    fn test_parse_escape_sequences() {
        assert_eq!(parse("\"hello\\nworld\""), Some(s("hello\nworld")));
        assert_eq!(parse("\"tab\\there\""), Some(s("tab\there")));
        assert_eq!(parse("\"back\\\\slash\""), Some(s("back\\slash")));
        assert_eq!(parse("\"quote\\\"inside\""), Some(s("quote\"inside")));
    }

    #[test]
    fn test_parse_unicode_escape() {
        assert_eq!(parse("\"\\u0041\""), Some(s("A")));
    }
}
