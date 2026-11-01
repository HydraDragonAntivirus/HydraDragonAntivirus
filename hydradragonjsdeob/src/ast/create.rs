//! AST expression constructors. Allocates in the arena via AstBuilder.

use oxc::allocator::GetAllocator;
use oxc::ast::builder::AstBuilder;
use oxc::ast::ast::{Expression, NumberBase, UnaryOperator};
use oxc::span::SPAN;

use crate::value::JsValue;

// ============================================================================
// Primitive constructors
// ============================================================================

/// Create a number literal expression.
///
/// Handles negative numbers by wrapping in unary negation.
/// Handles negative zero correctly.
pub fn make_number<'a>(value: f64, ast: &AstBuilder<'a>) -> Expression<'a> {
    if value == 0.0 && value.is_sign_negative() {
        // -0: must be unary negation of 0
        let inner = Expression::new_numeric_literal(SPAN, 0.0, None, NumberBase::Decimal, ast);
        return Expression::new_unary_expression(SPAN, UnaryOperator::UnaryNegation, inner, ast);
    }
    if value.is_sign_negative() && !value.is_nan() {
        let inner = Expression::new_numeric_literal(SPAN, value.abs(), None, NumberBase::Decimal, ast);
        return Expression::new_unary_expression(SPAN, UnaryOperator::UnaryNegation, inner, ast);
    }
    Expression::new_numeric_literal(SPAN, value, None, NumberBase::Decimal, ast)
}

/// Create a string literal expression.
#[inline]
pub fn make_string<'a>(value: &str, ast: &AstBuilder<'a>) -> Expression<'a> {
    Expression::new_string_literal(SPAN, ast.allocator().alloc_str(value), None, ast)
}

/// Create a boolean literal expression.
#[inline]
pub fn make_boolean<'a>(value: bool, ast: &AstBuilder<'a>) -> Expression<'a> {
    Expression::new_boolean_literal(SPAN, value, ast)
}

/// Create a null literal expression.
#[inline]
pub fn make_null<'a>(ast: &AstBuilder<'a>) -> Expression<'a> {
    Expression::new_null_literal(SPAN, ast)
}

/// Create an `undefined` expression (identifier reference).
#[inline]
pub fn make_undefined<'a>(ast: &AstBuilder<'a>) -> Expression<'a> {
    Expression::new_identifier(SPAN, "undefined", ast)
}

// ============================================================================
// JsValue → Expression
// ============================================================================

/// Convert a JsValue to an AST Expression. Allocates in the arena.
pub fn from_js_value<'a>(value: &JsValue, ast: &AstBuilder<'a>) -> Expression<'a> {
    match value {
        JsValue::Number(n) => make_number(*n, ast),
        JsValue::String(s) => make_string(s, ast),
        JsValue::Boolean(b) => make_boolean(*b, ast),
        JsValue::Null => make_null(ast),
        JsValue::Undefined => make_undefined(ast),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::extract;
    use oxc::allocator::Allocator;

    #[test]
    fn test_make_number_positive() {
        let alloc = Allocator::default();
        let ast = AstBuilder::new(&alloc);
        let expr = make_number(42.0, &ast);
        assert_eq!(extract::number(&expr), Some(42.0));
    }

    #[test]
    fn test_make_number_negative() {
        let alloc = Allocator::default();
        let ast = AstBuilder::new(&alloc);
        let expr = make_number(-5.0, &ast);
        assert_eq!(extract::number(&expr), Some(-5.0));
    }

    #[test]
    fn test_make_number_negative_zero() {
        let alloc = Allocator::default();
        let ast = AstBuilder::new(&alloc);
        let expr = make_number(-0.0, &ast);
        let val = extract::number(&expr).unwrap();
        assert!(val.is_sign_negative());
        assert_eq!(val, 0.0);
    }

    #[test]
    fn test_make_string() {
        let alloc = Allocator::default();
        let ast = AstBuilder::new(&alloc);
        let expr = make_string("hello", &ast);
        assert_eq!(extract::string(&expr), Some("hello"));
    }

    #[test]
    fn test_make_boolean() {
        let alloc = Allocator::default();
        let ast = AstBuilder::new(&alloc);
        assert_eq!(extract::boolean(&make_boolean(true, &ast)), Some(true));
        assert_eq!(extract::boolean(&make_boolean(false, &ast)), Some(false));
    }

    #[test]
    fn test_roundtrip_js_value() {
        let alloc = Allocator::default();
        let ast = AstBuilder::new(&alloc);

        let cases = [
            JsValue::Number(42.0),
            JsValue::Number(-7.0),
            JsValue::String("test".into()),
            JsValue::Boolean(true),
            JsValue::Null,
        ];

        for val in &cases {
            let expr = from_js_value(val, &ast);
            let extracted = extract::js_value(&expr);
            assert_eq!(extracted.as_ref(), Some(val), "roundtrip failed for {val:?}");
        }
    }
}
