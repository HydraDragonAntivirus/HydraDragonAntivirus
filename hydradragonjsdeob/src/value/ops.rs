//! JavaScript operators on JsValue: arithmetic, comparison, bitwise, shift.

use super::JsValue;
use super::coerce::{to_int32, to_number, to_string, to_uint32};

// ============================================================================
// Arithmetic
// ============================================================================

/// JavaScript `+` operator. Handles number addition AND string concatenation.
pub fn add(left: &JsValue, right: &JsValue) -> JsValue {
    // String concatenation if either operand is a string.
    if matches!(left, JsValue::String(_)) || matches!(right, JsValue::String(_)) {
        let ls = to_string(left);
        let rs = to_string(right);
        return JsValue::String(ls + &rs);
    }
    JsValue::Number(to_number(left) + to_number(right))
}

/// JavaScript `-`.
pub fn sub(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(to_number(left) - to_number(right))
}

/// JavaScript `*`.
pub fn mul(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(to_number(left) * to_number(right))
}

/// JavaScript `/`.
pub fn div(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(to_number(left) / to_number(right))
}

/// JavaScript `%`.
pub fn rem(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(to_number(left) % to_number(right))
}

/// JavaScript `**`.
pub fn exp(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(to_number(left).powf(to_number(right)))
}

// ============================================================================
// Comparison
// ============================================================================

/// JavaScript `===` (strict equality).
pub fn strict_eq(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Boolean(strict_eq_bool(left, right))
}

/// Internal: strict equality as bool.
pub fn strict_eq_bool(left: &JsValue, right: &JsValue) -> bool {
    match (left, right) {
        (JsValue::Number(a), JsValue::Number(b)) => {
            // NaN !== NaN, but -0 === +0
            if a.is_nan() || b.is_nan() {
                return false;
            }
            a == b
        }
        (JsValue::String(a), JsValue::String(b)) => a == b,
        (JsValue::Boolean(a), JsValue::Boolean(b)) => a == b,
        (JsValue::Null, JsValue::Null) => true,
        (JsValue::Undefined, JsValue::Undefined) => true,
        _ => false, // Different types → not strictly equal
    }
}

/// JavaScript `!==`.
pub fn strict_ne(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Boolean(!strict_eq_bool(left, right))
}

/// JavaScript `<` (abstract relational comparison).
pub fn lt(left: &JsValue, right: &JsValue) -> Option<JsValue> {
    abstract_compare(left, right).map(JsValue::Boolean)
}

/// JavaScript `>`.
pub fn gt(left: &JsValue, right: &JsValue) -> Option<JsValue> {
    abstract_compare(right, left).map(JsValue::Boolean)
}

/// JavaScript `<=`.
pub fn le(left: &JsValue, right: &JsValue) -> Option<JsValue> {
    abstract_compare(right, left).map(|r| JsValue::Boolean(!r))
}

/// JavaScript `>=`.
pub fn ge(left: &JsValue, right: &JsValue) -> Option<JsValue> {
    abstract_compare(left, right).map(|r| JsValue::Boolean(!r))
}

/// Abstract relational comparison. Returns Some(true) if left < right,
/// Some(false) if not, None if undefined (NaN involved).
fn abstract_compare(left: &JsValue, right: &JsValue) -> Option<bool> {
    // Both strings: lexicographic
    if let (JsValue::String(a), JsValue::String(b)) = (left, right) {
        return Some(a < b);
    }
    // Otherwise: numeric comparison
    let a = to_number(left);
    let b = to_number(right);
    if a.is_nan() || b.is_nan() {
        return None; // undefined
    }
    Some(a < b)
}

// ============================================================================
// Bitwise
// ============================================================================

/// JavaScript `&`.
pub fn bit_and(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(f64::from(to_int32(left) & to_int32(right)))
}

/// JavaScript `|`.
pub fn bit_or(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(f64::from(to_int32(left) | to_int32(right)))
}

/// JavaScript `^`.
pub fn bit_xor(left: &JsValue, right: &JsValue) -> JsValue {
    JsValue::Number(f64::from(to_int32(left) ^ to_int32(right)))
}

// ============================================================================
// Shift
// ============================================================================

/// JavaScript `<<`.
pub fn shl(left: &JsValue, right: &JsValue) -> JsValue {
    let l = to_int32(left);
    let r = to_uint32(right) & 0x1F;
    JsValue::Number(f64::from(l << r))
}

/// JavaScript `>>` (signed).
pub fn shr(left: &JsValue, right: &JsValue) -> JsValue {
    let l = to_int32(left);
    let r = to_uint32(right) & 0x1F;
    JsValue::Number(f64::from(l >> r))
}

/// JavaScript `>>>` (unsigned).
pub fn ushr(left: &JsValue, right: &JsValue) -> JsValue {
    let l = to_uint32(left);
    let r = to_uint32(right) & 0x1F;
    JsValue::Number(f64::from(l >> r))
}

// ============================================================================
// Unary
// ============================================================================

/// JavaScript unary `-`.
pub fn neg(val: &JsValue) -> JsValue {
    JsValue::Number(-to_number(val))
}

/// JavaScript unary `+`.
pub fn pos(val: &JsValue) -> JsValue {
    JsValue::Number(to_number(val))
}

/// JavaScript `!`.
pub fn not(val: &JsValue) -> JsValue {
    JsValue::Boolean(val.is_falsy())
}

/// JavaScript `~` (bitwise NOT).
pub fn bit_not(val: &JsValue) -> JsValue {
    JsValue::Number(f64::from(!to_int32(val)))
}

/// JavaScript `typeof`.
pub fn type_of(val: &JsValue) -> JsValue {
    JsValue::String(val.type_of().to_string())
}

/// JavaScript `void`.
pub fn void_op(_val: &JsValue) -> JsValue {
    JsValue::Undefined
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn n(v: f64) -> JsValue { JsValue::Number(v) }
    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }
    fn b(v: bool) -> JsValue { JsValue::Boolean(v) }

    #[test]
    fn test_add_numbers() {
        assert_eq!(add(&n(1.0), &n(2.0)), n(3.0));
        assert_eq!(add(&n(-1.0), &n(1.0)), n(0.0));
    }

    #[test]
    fn test_add_string_concat() {
        assert_eq!(add(&s("hello"), &s(" world")), s("hello world"));
        assert_eq!(add(&s("x"), &n(1.0)), s("x1"));
        assert_eq!(add(&n(1.0), &s("x")), s("1x"));
        assert_eq!(add(&s(""), &JsValue::Null), s("null"));
        assert_eq!(add(&s(""), &b(true)), s("true"));
    }

    #[test]
    fn test_arithmetic() {
        assert_eq!(sub(&n(5.0), &n(3.0)), n(2.0));
        assert_eq!(mul(&n(3.0), &n(4.0)), n(12.0));
        assert_eq!(div(&n(10.0), &n(3.0)), n(10.0 / 3.0));
        assert_eq!(rem(&n(10.0), &n(3.0)), n(1.0));
        assert_eq!(exp(&n(2.0), &n(10.0)), n(1024.0));
    }

    #[test]
    fn test_strict_equality() {
        assert_eq!(strict_eq(&n(1.0), &n(1.0)), b(true));
        assert_eq!(strict_eq(&n(1.0), &n(2.0)), b(false));
        assert_eq!(strict_eq(&s("a"), &s("a")), b(true));
        assert_eq!(strict_eq(&n(1.0), &s("1")), b(false)); // different types
        assert_eq!(strict_eq(&JsValue::Null, &JsValue::Null), b(true));
        assert_eq!(strict_eq(&JsValue::Null, &JsValue::Undefined), b(false));
        // NaN !== NaN
        assert_eq!(strict_eq(&n(f64::NAN), &n(f64::NAN)), b(false));
    }

    #[test]
    fn test_comparison() {
        assert_eq!(lt(&n(1.0), &n(2.0)), Some(b(true)));
        assert_eq!(gt(&n(2.0), &n(1.0)), Some(b(true)));
        assert_eq!(le(&n(1.0), &n(1.0)), Some(b(true)));
        assert_eq!(ge(&n(1.0), &n(1.0)), Some(b(true)));
        // String comparison
        assert_eq!(lt(&s("a"), &s("b")), Some(b(true)));
        assert_eq!(gt(&s("b"), &s("a")), Some(b(true)));
        // NaN comparison is undefined
        assert_eq!(lt(&n(f64::NAN), &n(1.0)), None);
    }

    #[test]
    fn test_bitwise() {
        assert_eq!(bit_and(&n(255.0), &n(15.0)), n(15.0));
        assert_eq!(bit_or(&n(240.0), &n(15.0)), n(255.0));
        assert_eq!(bit_xor(&n(255.0), &n(15.0)), n(240.0));
    }

    #[test]
    fn test_shift() {
        assert_eq!(shl(&n(1.0), &n(8.0)), n(256.0));
        assert_eq!(shr(&n(256.0), &n(4.0)), n(16.0));
        assert_eq!(ushr(&n(-1.0), &n(0.0)), n(4294967295.0));
    }

    #[test]
    fn test_unary() {
        assert_eq!(neg(&n(5.0)), n(-5.0));
        assert_eq!(pos(&s("42")), n(42.0));
        assert_eq!(not(&b(true)), b(false));
        assert_eq!(not(&n(0.0)), b(true));
        assert_eq!(bit_not(&n(0.0)), n(-1.0));
        assert_eq!(type_of(&n(1.0)), s("number"));
        assert_eq!(void_op(&n(1.0)), JsValue::Undefined);
    }
}
