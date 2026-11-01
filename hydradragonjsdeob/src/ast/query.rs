//! Expression predicates: is_literal, is_truthy, is_side_effect_free.

use oxc::ast::ast::{
    ArrayExpressionElement, Expression, ObjectPropertyKind, PropertyKey, UnaryOperator,
};

// ============================================================================
// Truthiness
// ============================================================================

/// Determine truthiness of an expression at compile time.
///
/// Returns `Some(true)` for truthy, `Some(false)` for falsy, `None` if unknown.
pub fn is_truthy(expr: &Expression) -> Option<bool> {
    match expr {
        Expression::BooleanLiteral(lit) => Some(lit.value),
        Expression::NumericLiteral(lit) => Some(lit.value != 0.0 && !lit.value.is_nan()),
        Expression::StringLiteral(lit) => Some(!lit.value.is_empty()),
        Expression::NullLiteral(_) => Some(false),
        Expression::Identifier(id) if id.name == "undefined" => Some(false),
        Expression::Identifier(id) if id.name == "NaN" => Some(false),
        Expression::ArrayExpression(_) | Expression::ObjectExpression(_) => Some(true),
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => Some(true),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            is_truthy(&u.argument).map(|v| !v)
        }
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::Void => Some(false),
        Expression::ParenthesizedExpression(p) => is_truthy(&p.expression),
        Expression::SequenceExpression(seq) => seq.expressions.last().and_then(is_truthy),
        _ => None,
    }
}

// ============================================================================
// Literal check
// ============================================================================

/// Check if an expression is a simple literal value.
///
/// Returns true for: numbers, strings, booleans, null, undefined,
/// unary +/- on literals, parenthesized literals, literal arrays.
pub fn is_literal(expr: &Expression) -> bool {
    match expr {
        Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::Identifier(id) if id.name == "undefined" => true,
        Expression::UnaryExpression(u)
            if matches!(
                u.operator,
                UnaryOperator::UnaryNegation | UnaryOperator::UnaryPlus
            ) =>
        {
            is_literal(&u.argument)
        }
        Expression::ParenthesizedExpression(p) => is_literal(&p.expression),
        Expression::ArrayExpression(arr) => arr.elements.iter().all(|el| match el {
            ArrayExpressionElement::SpreadElement(_) | ArrayExpressionElement::Elision(_) => false,
            _ => el.as_expression().is_some_and(is_literal),
        }),
        _ => false,
    }
}

// ============================================================================
// Side-effect analysis
// ============================================================================

/// Check if an expression is side-effect free.
///
/// Side-effect free expressions can be safely removed or duplicated
/// without changing program behavior.
pub fn is_side_effect_free(expr: &Expression) -> bool {
    match expr {
        // Literals
        Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_) => true,

        // Reading a variable
        Expression::Identifier(_) | Expression::ThisExpression(_) => true,

        // Defining (not calling) a function
        Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_) => true,

        // Template literals without tag
        Expression::TemplateLiteral(t) => t.expressions.iter().all(is_side_effect_free),

        // Unary (except delete)
        Expression::UnaryExpression(u) => {
            u.operator != UnaryOperator::Delete && is_side_effect_free(&u.argument)
        }

        // Binary, logical, conditional, sequence
        Expression::BinaryExpression(b) => {
            is_side_effect_free(&b.left) && is_side_effect_free(&b.right)
        }
        Expression::LogicalExpression(l) => {
            is_side_effect_free(&l.left) && is_side_effect_free(&l.right)
        }
        Expression::ConditionalExpression(c) => {
            is_side_effect_free(&c.test)
                && is_side_effect_free(&c.consequent)
                && is_side_effect_free(&c.alternate)
        }
        Expression::SequenceExpression(s) => s.expressions.iter().all(is_side_effect_free),
        Expression::ParenthesizedExpression(p) => is_side_effect_free(&p.expression),

        // Array/object literals with side-effect-free elements
        Expression::ArrayExpression(arr) => arr.elements.iter().all(|el| match el {
            ArrayExpressionElement::SpreadElement(s) => is_side_effect_free(&s.argument),
            ArrayExpressionElement::Elision(_) => true,
            _ => el.as_expression().is_some_and(is_side_effect_free),
        }),
        Expression::ObjectExpression(obj) => obj.properties.iter().all(|prop| match prop {
            ObjectPropertyKind::ObjectProperty(p) => {
                let key_safe = matches!(
                    &p.key,
                    PropertyKey::StaticIdentifier(_)
                        | PropertyKey::StringLiteral(_)
                        | PropertyKey::NumericLiteral(_)
                );
                key_safe && is_side_effect_free(&p.value)
            }
            ObjectPropertyKind::SpreadProperty(s) => is_side_effect_free(&s.argument),
        }),

        // Property access (aggressive — can throw on null, but acceptable for deobfuscation)
        Expression::StaticMemberExpression(m) => !m.optional && is_side_effect_free(&m.object),
        Expression::ComputedMemberExpression(m) => {
            !m.optional && is_side_effect_free(&m.object) && is_side_effect_free(&m.expression)
        }

        // Everything else: calls, assignments, new, await, yield, update, etc.
        _ => false,
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
    fn test_truthy() {
        let a = Allocator::default();
        assert_eq!(is_truthy(&parse_expr(&a, "true")), Some(true));
        assert_eq!(is_truthy(&parse_expr(&a, "1")), Some(true));
        assert_eq!(is_truthy(&parse_expr(&a, "\"x\"")), Some(true));
        assert_eq!(is_truthy(&parse_expr(&a, "[]")), Some(true));
        assert_eq!(is_truthy(&parse_expr(&a, "false")), Some(false));
        assert_eq!(is_truthy(&parse_expr(&a, "0")), Some(false));
        assert_eq!(is_truthy(&parse_expr(&a, "\"\"")), Some(false));
        assert_eq!(is_truthy(&parse_expr(&a, "null")), Some(false));
        assert_eq!(is_truthy(&parse_expr(&a, "undefined")), Some(false));
        assert_eq!(is_truthy(&parse_expr(&a, "x")), None);
    }

    #[test]
    fn test_truthy_negation() {
        let a = Allocator::default();
        assert_eq!(is_truthy(&parse_expr(&a, "!true")), Some(false));
        assert_eq!(is_truthy(&parse_expr(&a, "!false")), Some(true));
        assert_eq!(is_truthy(&parse_expr(&a, "!0")), Some(true));
    }

    #[test]
    fn test_truthy_void() {
        let a = Allocator::default();
        assert_eq!(is_truthy(&parse_expr(&a, "void 0")), Some(false));
    }

    #[test]
    fn test_is_literal() {
        let a = Allocator::default();
        assert!(is_literal(&parse_expr(&a, "42")));
        assert!(is_literal(&parse_expr(&a, "\"x\"")));
        assert!(is_literal(&parse_expr(&a, "true")));
        assert!(is_literal(&parse_expr(&a, "null")));
        assert!(is_literal(&parse_expr(&a, "undefined")));
        assert!(is_literal(&parse_expr(&a, "-5")));
        assert!(is_literal(&parse_expr(&a, "[1, 2, 3]")));
        assert!(!is_literal(&parse_expr(&a, "x")));
        assert!(!is_literal(&parse_expr(&a, "foo()")));
    }

    #[test]
    fn test_side_effect_free_literals() {
        let a = Allocator::default();
        assert!(is_side_effect_free(&parse_expr(&a, "42")));
        assert!(is_side_effect_free(&parse_expr(&a, "\"hello\"")));
        assert!(is_side_effect_free(&parse_expr(&a, "true")));
        assert!(is_side_effect_free(&parse_expr(&a, "null")));
    }

    #[test]
    fn test_side_effect_free_operators() {
        let a = Allocator::default();
        assert!(is_side_effect_free(&parse_expr(&a, "1 + 2")));
        assert!(is_side_effect_free(&parse_expr(&a, "a && b")));
        assert!(is_side_effect_free(&parse_expr(&a, "x ? y : z")));
        assert!(is_side_effect_free(&parse_expr(&a, "-5")));
        assert!(is_side_effect_free(&parse_expr(&a, "typeof x")));
    }

    #[test]
    fn test_side_effect_calls_are_effectful() {
        let a = Allocator::default();
        assert!(!is_side_effect_free(&parse_expr(&a, "foo()")));
        assert!(!is_side_effect_free(&parse_expr(&a, "console.log(x)")));
    }

    #[test]
    fn test_side_effect_assignments_effectful() {
        let a = Allocator::default();
        assert!(!is_side_effect_free(&parse_expr(&a, "x = 1")));
    }

    #[test]
    fn test_side_effect_delete_effectful() {
        let a = Allocator::default();
        assert!(!is_side_effect_free(&parse_expr(&a, "delete x.y")));
    }

    #[test]
    fn test_side_effect_member_access() {
        let a = Allocator::default();
        assert!(is_side_effect_free(&parse_expr(&a, "x.y")));
        assert!(is_side_effect_free(&parse_expr(&a, "x[0]")));
    }

    #[test]
    fn test_side_effect_function_def_pure() {
        let a = Allocator::default();
        assert!(is_side_effect_free(&parse_expr(&a, "function() {}")));
        assert!(is_side_effect_free(&parse_expr(&a, "() => {}")));
    }
}
