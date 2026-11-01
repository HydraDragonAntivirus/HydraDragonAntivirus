//! Number methods and global numeric functions.

use super::JsValue;
use super::coerce::{string_to_number, to_number};

/// Evaluate `Number.method(args)` or `Number(value)`.
pub fn call(method: &str, args: &[JsValue]) -> Option<JsValue> {
    match method {
        "isNaN" => Some(JsValue::Boolean(matches!(args.first(), Some(JsValue::Number(n)) if n.is_nan()))),
        "isFinite" => Some(JsValue::Boolean(matches!(args.first(), Some(JsValue::Number(n)) if n.is_finite()))),
        "isInteger" => Some(JsValue::Boolean(matches!(args.first(), Some(JsValue::Number(n)) if n.is_finite() && n.fract() == 0.0))),
        "isSafeInteger" => Some(JsValue::Boolean(matches!(args.first(), Some(JsValue::Number(n)) if n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0))),
        "parseInt" => parse_int(args),
        "parseFloat" => parse_float(args),
        _ => None,
    }
}

/// `Number(value)` constructor coercion (without `new`).
pub fn coerce(args: &[JsValue]) -> JsValue {
    match args.first() {
        None => JsValue::Number(0.0),
        Some(v) => JsValue::Number(to_number(v)),
    }
}

/// Global `parseInt(string, radix?)`.
pub fn parse_int(args: &[JsValue]) -> Option<JsValue> {
    let s = args.first().map(super::coerce::to_string)?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Some(JsValue::Number(f64::NAN));
    }

    let radix = args.get(1).map(|v| to_number(v) as i32).unwrap_or(0);

    // Auto-detect radix
    let (num_str, base) = if radix == 0 || radix == 16 {
        if let Some(rest) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
            (rest, 16)
        } else {
            (trimmed, if radix == 0 { 10 } else { radix })
        }
    } else {
        (trimmed, radix)
    };

    if !(2..=36).contains(&base) {
        return Some(JsValue::Number(f64::NAN));
    }

    // Parse as many valid digits as possible
    let valid: String = num_str.chars()
        .take_while(|c| c.is_digit(base as u32))
        .collect();

    if valid.is_empty() {
        return Some(JsValue::Number(f64::NAN));
    }

    i64::from_str_radix(&valid, base as u32)
        .map(|v| JsValue::Number(v as f64))
        .ok()
        .or(Some(JsValue::Number(f64::NAN)))
}

/// Global `parseFloat(string)`.
pub fn parse_float(args: &[JsValue]) -> Option<JsValue> {
    let s = args.first().map(super::coerce::to_string)?;
    Some(JsValue::Number(string_to_number(&s)))
}

/// Global `isNaN(value)`.
pub fn global_is_nan(args: &[JsValue]) -> Option<JsValue> {
    let n = args.first().map(to_number).unwrap_or(f64::NAN);
    Some(JsValue::Boolean(n.is_nan()))
}

/// Global `isFinite(value)`.
pub fn global_is_finite(args: &[JsValue]) -> Option<JsValue> {
    let n = args.first().map(to_number).unwrap_or(f64::NAN);
    Some(JsValue::Boolean(n.is_finite()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(v: f64) -> JsValue { JsValue::Number(v) }
    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }

    #[test]
    fn test_parse_int() {
        assert_eq!(parse_int(&[s("42")]), Some(n(42.0)));
        assert_eq!(parse_int(&[s("0xff")]), Some(n(255.0)));
        assert_eq!(parse_int(&[s("11"), n(2.0)]), Some(n(3.0)));
        assert_eq!(parse_int(&[s("  123abc")]), Some(n(123.0)));
        assert!(matches!(parse_int(&[s("abc")]), Some(JsValue::Number(v)) if v.is_nan()));
    }

    #[test]
    fn test_parse_float() {
        assert_eq!(parse_float(&[s("3.14")]), Some(n(3.14)));
        assert_eq!(parse_float(&[s("  42  ")]), Some(n(42.0)));
    }

    #[test]
    fn test_number_static() {
        assert_eq!(call("isNaN", &[n(f64::NAN)]), Some(JsValue::Boolean(true)));
        assert_eq!(call("isNaN", &[n(42.0)]), Some(JsValue::Boolean(false)));
        assert_eq!(call("isFinite", &[n(42.0)]), Some(JsValue::Boolean(true)));
        assert_eq!(call("isFinite", &[n(f64::INFINITY)]), Some(JsValue::Boolean(false)));
        assert_eq!(call("isInteger", &[n(5.0)]), Some(JsValue::Boolean(true)));
        assert_eq!(call("isInteger", &[n(5.5)]), Some(JsValue::Boolean(false)));
    }

    #[test]
    fn test_coerce() {
        assert_eq!(coerce(&[s("42")]), n(42.0));
        assert_eq!(coerce(&[JsValue::Boolean(true)]), n(1.0));
        assert_eq!(coerce(&[]), n(0.0));
    }

    #[test]
    fn test_global_is_nan() {
        assert_eq!(global_is_nan(&[s("abc")]), Some(JsValue::Boolean(true)));
        assert_eq!(global_is_nan(&[n(42.0)]), Some(JsValue::Boolean(false)));
    }
}
