//! LogicalExpression folding — &&, ||, ??.
//!
//! Short-circuit semantics: `true && x` → `x`, `false || y` → `y`.

use oxc::allocator::GetAllocator;
use oxc::allocator::TakeIn;
use oxc::ast::ast::Expression;
use oxc::syntax::operator::LogicalOperator;

use oxc_traverse::TraverseCtx;

use crate::ast::{extract, query};

/// Try to fold a LogicalExpression. Returns `Some(1)` if folded.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::LogicalExpression(logical) = &*expr else {
        return None;
    };

    let allocator = &ctx.ast.allocator();

    match logical.operator {
        LogicalOperator::Or => {
            let truthy = query::is_truthy(&logical.left)?;
            let Expression::LogicalExpression(logical) = expr else { return None; };
            // true || x → true (short-circuit: left is returned)
            // false || x → x
            *expr = if truthy {
                logical.left.take_in(allocator)
            } else {
                logical.right.take_in(allocator)
            };
        }
        LogicalOperator::And => {
            let truthy = query::is_truthy(&logical.left)?;
            let Expression::LogicalExpression(logical) = expr else { return None; };
            // true && x → x
            // false && x → false (short-circuit: left is returned)
            *expr = if truthy {
                logical.right.take_in(allocator)
            } else {
                logical.left.take_in(allocator)
            };
        }
        LogicalOperator::Coalesce => {
            // null ?? x → x, undefined ?? x → x, void 0 ?? x → x
            // <non-nullish> ?? x → <non-nullish>
            let left_is_nullish = extract::is_null(&logical.left) || extract::is_undefined(&logical.left);
            if !left_is_nullish {
                // For non-nullish, we need to know the value is definitely not null/undefined
                // Only fold if it's a literal we can analyze
                if !is_definitely_non_nullish(&logical.left) {
                    return None;
                }
            }
            let Expression::LogicalExpression(logical) = expr else { return None; };
            *expr = if left_is_nullish {
                logical.right.take_in(allocator)
            } else {
                logical.left.take_in(allocator)
            };
        }
    }

    Some(1)
}

/// Check if an expression is definitely not null or undefined.
fn is_definitely_non_nullish(expr: &Expression) -> bool {
    match expr {
        Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::ArrayExpression(_)
        | Expression::ObjectExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_) => true,
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "Infinity" | "NaN")
        }
        Expression::ParenthesizedExpression(p) => is_definitely_non_nullish(&p.expression),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_or() {
        assert!(fold("true || x;").contains("true"));
        assert!(fold("false || 42;").contains("42"));
        assert!(fold("0 || \"fallback\";").contains("\"fallback\""));
        assert!(fold("\"truthy\" || x;").contains("\"truthy\""));
    }

    #[test]
    fn test_and() {
        assert!(fold("true && 42;").contains("42"));
        assert!(fold("false && x;").contains("false"));
        assert!(fold("1 && \"yes\";").contains("\"yes\""));
        assert!(fold("0 && x;").contains("0"));
    }

    #[test]
    fn test_nullish() {
        assert!(fold("null ?? \"default\";").contains("\"default\""));
        assert!(fold("undefined ?? 42;").contains("42"));
        assert!(fold("0 ?? \"default\";").contains("0"));
    }
}
