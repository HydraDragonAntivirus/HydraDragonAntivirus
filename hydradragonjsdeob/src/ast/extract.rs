//! Zero-copy value extraction from AST expressions.
//!
//! These borrow from the arena — no heap allocation on the hot path.
//! All handle `ParenthesizedExpression` recursively.

use oxc::ast::ast::{ArrayExpressionElement, Expression, UnaryOperator};

use tracing::trace;

use crate::value::JsValue;

// ============================================================================
// Zero-copy extractors (borrow from arena)
// ============================================================================

/// Extract a string from an expression. Zero-copy — borrows from arena.
#[inline]
pub fn string<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    match expr {
        Expression::StringLiteral(lit) => Some(lit.value.as_str()),
        Expression::ParenthesizedExpression(p) => string(&p.expression),
        _ => None,
    }
}

/// Extract a number from an expression. Handles unary +/-, Infinity, NaN.
#[inline]
pub fn number(expr: &Expression) -> Option<f64> {
    match expr {
        Expression::NumericLiteral(lit) => Some(lit.value),
        Expression::Identifier(id) if id.name == "Infinity" => Some(f64::INFINITY),
        Expression::Identifier(id) if id.name == "NaN" => Some(f64::NAN),
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::UnaryNegation => number(&u.argument).map(|v| -v),
            UnaryOperator::UnaryPlus => number(&u.argument),
            _ => None,
        },
        Expression::ParenthesizedExpression(p) => number(&p.expression),
        _ => None,
    }
}

/// Extract a boolean from an expression.
#[inline]
pub fn boolean(expr: &Expression) -> Option<bool> {
    match expr {
        Expression::BooleanLiteral(lit) => Some(lit.value),
        Expression::ParenthesizedExpression(p) => boolean(&p.expression),
        _ => None,
    }
}

/// Check if expression is `null`.
#[inline]
pub fn is_null(expr: &Expression) -> bool {
    match expr {
        Expression::NullLiteral(_) => true,
        Expression::ParenthesizedExpression(p) => is_null(&p.expression),
        _ => false,
    }
}

/// Check if expression is `undefined`.
#[inline]
pub fn is_undefined(expr: &Expression) -> bool {
    match expr {
        Expression::Identifier(id) if id.name == "undefined" => true,
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::Void => true,
        Expression::ParenthesizedExpression(p) => is_undefined(&p.expression),
        _ => false,
    }
}

// ============================================================================
// Owned extractor (heap-allocates for cross-pass storage)
// ============================================================================

/// Extract an owned `JsValue` from an expression.
///
/// Use this when storing values in maps (constant propagation, eval cache).
/// For single-traversal folding, prefer `string()`, `number()`, `boolean()`.
pub fn js_value(expr: &Expression) -> Option<JsValue> {
    match expr {
        Expression::NumericLiteral(lit) => Some(JsValue::Number(lit.value)),
        Expression::StringLiteral(lit) => Some(JsValue::String(lit.value.to_string())),
        Expression::BooleanLiteral(lit) => Some(JsValue::Boolean(lit.value)),
        Expression::NullLiteral(_) => Some(JsValue::Null),
        Expression::Identifier(id) if id.name == "undefined" => Some(JsValue::Undefined),
        Expression::Identifier(id) if id.name == "Infinity" => Some(JsValue::Number(f64::INFINITY)),
        Expression::Identifier(id) if id.name == "NaN" => Some(JsValue::Number(f64::NAN)),
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::UnaryNegation => {
                if let Some(JsValue::Number(n)) = js_value(&u.argument) {
                    Some(JsValue::Number(-n))
                } else {
                    None
                }
            }
            UnaryOperator::UnaryPlus => {
                if let Some(JsValue::Number(n)) = js_value(&u.argument) {
                    Some(JsValue::Number(n))
                } else {
                    None
                }
            }
            _ => None,
        },
        Expression::ParenthesizedExpression(p) => js_value(&p.expression),
        _ => None,
    }
}

// ============================================================================
// Array element extraction
// ============================================================================

/// Extract all elements from an array expression.
///
/// Returns `None` if the array contains spread or holes.
/// Logs a trace message when spread/elision is encountered.
pub fn array_elements<'a>(expr: &'a Expression<'a>) -> Option<Vec<&'a Expression<'a>>> {
    match expr {
        Expression::ArrayExpression(arr) => {
            let mut elements = Vec::with_capacity(arr.elements.len());
            for elem in &arr.elements {
                match elem {
                    ArrayExpressionElement::SpreadElement(_) => {
                        trace!("array_elements: skipping array with spread element");
                        return None;
                    }
                    ArrayExpressionElement::Elision(_) => {
                        trace!("array_elements: skipping array with hole/elision");
                        return None;
                    }
                    _ => elements.push(elem.as_expression()?),
                }
            }
            Some(elements)
        }
        Expression::ParenthesizedExpression(p) => array_elements(&p.expression),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use oxc::allocator::Allocator;
    use oxc::parser::Parser;
    use oxc::span::SourceType;

    fn parse_expr<'a>(alloc: &'a Allocator, src: &'a str) -> Expression<'a> {
        Parser::new(alloc, src, SourceType::mjs())
            .parse_expression()
            .unwrap()
    }

    #[test]
    fn test_string() {
        let a = Allocator::default();
        assert_eq!(string(&parse_expr(&a, "\"hello\"")), Some("hello"));
        assert_eq!(string(&parse_expr(&a, "(\"world\")")), Some("world"));
        assert_eq!(string(&parse_expr(&a, "42")), None);
    }

    #[test]
    fn test_number() {
        let a = Allocator::default();
        assert_eq!(number(&parse_expr(&a, "42")), Some(42.0));
        assert_eq!(number(&parse_expr(&a, "-5")), Some(-5.0));
        assert_eq!(number(&parse_expr(&a, "+3")), Some(3.0));
        assert_eq!(number(&parse_expr(&a, "(42)")), Some(42.0));
        assert_eq!(number(&parse_expr(&a, "\"x\"")), None);
    }

    #[test]
    fn test_boolean() {
        let a = Allocator::default();
        assert_eq!(boolean(&parse_expr(&a, "true")), Some(true));
        assert_eq!(boolean(&parse_expr(&a, "false")), Some(false));
        assert_eq!(boolean(&parse_expr(&a, "42")), None);
    }

    #[test]
    fn test_null_undefined() {
        let a = Allocator::default();
        assert!(is_null(&parse_expr(&a, "null")));
        assert!(!is_null(&parse_expr(&a, "42")));
        assert!(is_undefined(&parse_expr(&a, "undefined")));
        assert!(is_undefined(&parse_expr(&a, "void 0")));
    }

    #[test]
    fn test_js_value() {
        let a = Allocator::default();
        assert_eq!(js_value(&parse_expr(&a, "42")), Some(JsValue::Number(42.0)));
        assert_eq!(js_value(&parse_expr(&a, "\"hi\"")), Some(JsValue::String("hi".into())));
        assert_eq!(js_value(&parse_expr(&a, "true")), Some(JsValue::Boolean(true)));
        assert_eq!(js_value(&parse_expr(&a, "null")), Some(JsValue::Null));
        assert_eq!(js_value(&parse_expr(&a, "undefined")), Some(JsValue::Undefined));
        assert_eq!(js_value(&parse_expr(&a, "-5")), Some(JsValue::Number(-5.0)));
        assert_eq!(js_value(&parse_expr(&a, "foo")), None);
    }

    #[test]
    fn test_array_elements() {
        let a = Allocator::default();
        let expr = parse_expr(&a, "[1, 2, 3]");
        let elems = array_elements(&expr).unwrap();
        assert_eq!(elems.len(), 3);
        assert_eq!(number(elems[0]), Some(1.0));
        assert_eq!(number(elems[2]), Some(3.0));
    }

    #[test]
    fn test_array_with_spread_returns_none() {
        let a = Allocator::default();
        let expr = parse_expr(&a, "[1, ...x]");
        assert!(array_elements(&expr).is_none());
    }
}
