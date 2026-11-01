//! ECMAScript type coercion: ToNumber, ToString, ToBoolean.

use super::JsValue;

// ============================================================================
// ToNumber
// ============================================================================

/// ECMAScript `ToNumber` on a primitive value.
pub fn to_number(val: &JsValue) -> f64 {
    match val {
        JsValue::Number(n) => *n,
        JsValue::Boolean(true) => 1.0,
        JsValue::Boolean(false) => 0.0,
        JsValue::Null => 0.0,
        JsValue::Undefined => f64::NAN,
        JsValue::String(s) => string_to_number(s),
    }
}

/// Parse a string to a number following ECMAScript rules.
pub fn string_to_number(s: &str) -> f64 {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return 0.0;
    }

    // Hex
    if let Some(rest) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return i64::from_str_radix(rest, 16)
            .map(|v| v as f64)
            .unwrap_or(f64::NAN);
    }
    // Octal
    if let Some(rest) = trimmed.strip_prefix("0o").or_else(|| trimmed.strip_prefix("0O")) {
        return i64::from_str_radix(rest, 8)
            .map(|v| v as f64)
            .unwrap_or(f64::NAN);
    }
    // Binary
    if let Some(rest) = trimmed.strip_prefix("0b").or_else(|| trimmed.strip_prefix("0B")) {
        return i64::from_str_radix(rest, 2)
            .map(|v| v as f64)
            .unwrap_or(f64::NAN);
    }
    // Special values
    match trimmed {
        "Infinity" | "+Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ => trimmed.parse::<f64>().unwrap_or(f64::NAN),
    }
}

// ============================================================================
// ToString
// ============================================================================

/// ECMAScript `ToString` on a primitive value.
pub fn to_string(val: &JsValue) -> String {
    match val {
        JsValue::Number(n) => number_to_string(*n),
        JsValue::String(s) => s.clone(),
        JsValue::Boolean(b) => b.to_string(),
        JsValue::Null => "null".to_string(),
        JsValue::Undefined => "undefined".to_string(),
    }
}

/// Format a number as JavaScript would.
///
/// Handles NaN, Infinity, -0, integers, floats.
pub fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        "NaN".to_string()
    } else if n.is_infinite() {
        if n.is_sign_positive() {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        }
    } else if n == 0.0 {
        "0".to_string()
    } else if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

// ============================================================================
// ToBoolean
// ============================================================================

/// ECMAScript `ToBoolean` on a primitive value.
#[inline]
pub fn to_boolean(val: &JsValue) -> bool {
    val.is_truthy()
}

// ============================================================================
// ToInt32 / ToUint32
// ============================================================================

/// ECMAScript `ToInt32` — used by bitwise operators.
/// Follows ECMA-262 §7.1.6 exactly.
pub fn to_int32(val: &JsValue) -> i32 {
    let n = to_number(val);

    // Step 2: If number is NaN, +0, -0, +∞, or -∞, return +0
    if n.is_nan() || n.is_infinite() || n == 0.0 {
        return 0;
    }

    // Step 3: Let int be truncate(n)
    let int_val = n.trunc();

    // Step 4: Let int32bit be int modulo 2^32
    // Rust's rem_euclid gives the correct mathematical modulo (always positive)
    const TWO_POW_32: f64 = 4294967296.0; // 2^32
    let int32bit = int_val.rem_euclid(TWO_POW_32);

    // Step 5: If int32bit >= 2^31, return int32bit - 2^32, otherwise return int32bit
    const TWO_POW_31: f64 = 2147483648.0; // 2^31
    if int32bit >= TWO_POW_31 {
        (int32bit - TWO_POW_32) as i32
    } else {
        int32bit as i32
    }
}

/// ECMAScript `ToUint32` — used by `>>>`.
/// Follows ECMA-262 §7.1.7 exactly.
pub fn to_uint32(val: &JsValue) -> u32 {
    let n = to_number(val);

    // Step 2: If number is NaN, +0, -0, +∞, or -∞, return +0
    if n.is_nan() || n.is_infinite() || n == 0.0 {
        return 0;
    }

    // Step 3: Let int be truncate(n)
    let int_val = n.trunc();

    // Step 4: Let int32bit be int modulo 2^32
    const TWO_POW_32: f64 = 4294967296.0;
    let int32bit = int_val.rem_euclid(TWO_POW_32);

    // Step 5: Return int32bit
    int32bit as u32
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_number() {
        assert_eq!(to_number(&JsValue::Number(42.0)), 42.0);
        assert_eq!(to_number(&JsValue::Boolean(true)), 1.0);
        assert_eq!(to_number(&JsValue::Boolean(false)), 0.0);
        assert_eq!(to_number(&JsValue::Null), 0.0);
        assert!(to_number(&JsValue::Undefined).is_nan());
        assert_eq!(to_number(&JsValue::String("".into())), 0.0);
        assert_eq!(to_number(&JsValue::String("42".into())), 42.0);
        assert_eq!(to_number(&JsValue::String("  3.14  ".into())), 3.14);
        assert!(to_number(&JsValue::String("abc".into())).is_nan());
        assert_eq!(to_number(&JsValue::String("0xff".into())), 255.0);
        assert_eq!(to_number(&JsValue::String("0o77".into())), 63.0);
        assert_eq!(to_number(&JsValue::String("0b1010".into())), 10.0);
        assert_eq!(to_number(&JsValue::String("Infinity".into())), f64::INFINITY);
        assert_eq!(to_number(&JsValue::String("-Infinity".into())), f64::NEG_INFINITY);
    }

    #[test]
    fn test_number_to_string() {
        assert_eq!(number_to_string(42.0), "42");
        assert_eq!(number_to_string(-5.0), "-5");
        assert_eq!(number_to_string(3.14), "3.14");
        assert_eq!(number_to_string(0.0), "0");
        assert_eq!(number_to_string(-0.0), "0");
        assert_eq!(number_to_string(f64::NAN), "NaN");
        assert_eq!(number_to_string(f64::INFINITY), "Infinity");
        assert_eq!(number_to_string(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(number_to_string(1e15), "1000000000000000");
    }

    #[test]
    fn test_to_string() {
        assert_eq!(to_string(&JsValue::Number(42.0)), "42");
        assert_eq!(to_string(&JsValue::Boolean(true)), "true");
        assert_eq!(to_string(&JsValue::Null), "null");
        assert_eq!(to_string(&JsValue::Undefined), "undefined");
        assert_eq!(to_string(&JsValue::String("hello".into())), "hello");
    }

    #[test]
    fn test_to_int32() {
        assert_eq!(to_int32(&JsValue::Number(42.0)), 42);
        assert_eq!(to_int32(&JsValue::Number(-1.0)), -1);
        assert_eq!(to_int32(&JsValue::Number(4294967296.0)), 0); // 2^32 wraps
        assert_eq!(to_int32(&JsValue::Number(f64::NAN)), 0);
        assert_eq!(to_int32(&JsValue::Number(f64::INFINITY)), 0);
    }

    #[test]
    fn test_to_uint32() {
        assert_eq!(to_uint32(&JsValue::Number(42.0)), 42);
        assert_eq!(to_uint32(&JsValue::Number(-1.0)), 4294967295); // wraps
        assert_eq!(to_uint32(&JsValue::Number(f64::NAN)), 0);
    }
}
