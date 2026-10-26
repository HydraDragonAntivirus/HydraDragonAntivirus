//! BinaryExpression folding — all binary operators.
//!
//! `1 + 2` → `3`, `"a" + "b"` → `"ab"`, `5 & 3` → `1`, `1 === 1` → `true`.

use oxc::ast::ast::{BinaryOperator, Expression};

use oxc_traverse::TraverseCtx;

use crate::ast::{create, extract};
use crate::value::{JsValue, ops};

/// Try to fold a BinaryExpression. Returns `Some(1)` if folded.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::BinaryExpression(bin) = &*expr else {
        return None;
    };

    let left = extract::js_value(&bin.left)?;
    let right = extract::js_value(&bin.right)?;

    let result = match bin.operator {
        // Arithmetic
        BinaryOperator::Addition => Some(ops::add(&left, &right))
            .filter(|v| !matches!(v, JsValue::String(s) if s.len() > crate::value::MAX_STRING_LEN)),
        BinaryOperator::Subtraction => Some(ops::sub(&left, &right)),
        BinaryOperator::Multiplication => Some(ops::mul(&left, &right)),
        BinaryOperator::Division => {
            // Don't fold division by zero to Infinity — leave it for the runtime
            if let JsValue::Number(r) = &right {
                if *r == 0.0 { return None; }
            }
            Some(ops::div(&left, &right))
        }
        BinaryOperator::Remainder => {
            if let JsValue::Number(r) = &right {
                if *r == 0.0 { return None; }
            }
            Some(ops::rem(&left, &right))
        }
        BinaryOperator::Exponential => Some(ops::exp(&left, &right)),

        // Comparison
        BinaryOperator::StrictEquality => Some(ops::strict_eq(&left, &right)),
        BinaryOperator::StrictInequality => Some(ops::strict_ne(&left, &right)),
        BinaryOperator::LessThan => ops::lt(&left, &right),
        BinaryOperator::GreaterThan => ops::gt(&left, &right),
        BinaryOperator::LessEqualThan => ops::le(&left, &right),
        BinaryOperator::GreaterEqualThan => ops::ge(&left, &right),

        // Bitwise
        BinaryOperator::BitwiseAnd => Some(ops::bit_and(&left, &right)),
        BinaryOperator::BitwiseOR => Some(ops::bit_or(&left, &right)),
        BinaryOperator::BitwiseXOR => Some(ops::bit_xor(&left, &right)),

        // Shift
        BinaryOperator::ShiftLeft => Some(ops::shl(&left, &right)),
        BinaryOperator::ShiftRight => Some(ops::shr(&left, &right)),
        BinaryOperator::ShiftRightZeroFill => Some(ops::ushr(&left, &right)),

        // Don't fold: ==, !=, in, instanceof (need type coercion or runtime info)
        _ => None,
    }?;

    // Don't fold if result is NaN from non-obvious operations
    // (NaN from arithmetic is expected, but NaN from string→number coercion is confusing)
    if let JsValue::Number(n) = &result {
        if n.is_nan() && !matches!(left, JsValue::Number(_)) {
            return None;
        }
    }

    *expr = create::from_js_value(&result, &ctx.ast);
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_arithmetic() {
        assert!(fold("1 + 2;").contains("3"));
        assert!(fold("10 - 3;").contains("7"));
        assert!(fold("3 * 4;").contains("12"));
        assert!(fold("10 / 2;").contains("5"));
        assert!(fold("10 % 3;").contains("1"));
        assert!(fold("2 ** 10;").contains("1024"));
    }

    #[test]
    fn test_string_concat() {
        assert!(fold("\"hello\" + \" world\";").contains("\"hello world\""));
        assert!(fold("\"x\" + 1;").contains("\"x1\""));
    }

    #[test]
    fn test_comparison() {
        assert!(fold("1 === 1;").contains("true"));
        assert!(fold("1 === 2;").contains("false"));
        assert!(fold("1 !== 2;").contains("true"));
        assert!(fold("1 < 2;").contains("true"));
        assert!(fold("2 > 1;").contains("true"));
        assert!(fold("1 <= 1;").contains("true"));
        assert!(fold("1 >= 1;").contains("true"));
    }

    #[test]
    fn test_bitwise() {
        assert!(fold("255 & 15;").contains("15"));
        assert!(fold("240 | 15;").contains("255"));
        assert!(fold("255 ^ 15;").contains("240"));
    }

    #[test]
    fn test_shift() {
        assert!(fold("1 << 8;").contains("256"));
        assert!(fold("256 >> 4;").contains("16"));
    }

    #[test]
    fn test_division_by_zero_not_folded() {
        let result = fold("1 / 0;");
        assert!(result.contains("/"), "division by zero should not fold: {result}");
    }
}
