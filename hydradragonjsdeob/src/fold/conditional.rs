//! ConditionalExpression folding — ternary operator.
//!
//! `true ? a : b` → `a`, `false ? a : b` → `b`.

use oxc::allocator::GetAllocator;
use oxc::allocator::TakeIn;
use oxc::ast::ast::Expression;

use oxc_traverse::TraverseCtx;

use crate::ast::query;

/// Try to fold a ConditionalExpression. Returns `Some(1)` if folded.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::ConditionalExpression(cond) = &*expr else {
        return None;
    };

    let truthy = query::is_truthy(&cond.test)?;
    let allocator = &ctx.ast.allocator();

    let Expression::ConditionalExpression(cond) = expr else {
        return None;
    };

    *expr = if truthy {
        cond.consequent.take_in(allocator)
    } else {
        cond.alternate.take_in(allocator)
    };

    Some(1)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_true_branch() {
        assert!(fold("true ? 42 : 0;").contains("42"));
        assert!(fold("1 ? \"yes\" : \"no\";").contains("\"yes\""));
    }

    #[test]
    fn test_false_branch() {
        assert!(fold("false ? 42 : 0;").contains("0"));
        assert!(fold("0 ? \"yes\" : \"no\";").contains("\"no\""));
        assert!(fold("\"\" ? \"yes\" : \"no\";").contains("\"no\""));
        assert!(fold("null ? \"yes\" : \"no\";").contains("\"no\""));
    }

    #[test]
    fn test_unknown_not_folded() {
        let result = fold("x ? 1 : 2;");
        assert!(result.contains("?"), "unknown test should not fold: {result}");
    }
}
