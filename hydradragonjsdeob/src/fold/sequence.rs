//! SequenceExpression folding.
//!
//! `(a, b, 42)` → `42` when all prefix expressions are side-effect-free.

use oxc::allocator::GetAllocator;
use oxc::allocator::TakeIn;
use oxc::ast::ast::Expression;

use oxc_traverse::TraverseCtx;

use crate::ast::query;

/// Try to fold a SequenceExpression. Returns `Some(1)` if folded.
///
/// **Why `take_in` and not `clone_in`:** `clone_in` strips `scope_id` /
/// `symbol_id` / `reference_id` from the cloned subtree. If the last element
/// of the sequence is (or contains) a `Function`, `BlockStatement`, etc., the
/// next `traverse_mut` walk panics at `walk.rs:walk_function` when it
/// `unwrap()`s a missing `scope_id`. `take_in` *moves* the node out
/// in-place, preserving all semantic IDs — see the OXC maintainer guidance
/// in oxc-project/oxc#13195. Real-world hit: recaptcha `botguard_pretty.js`
/// crashed here on second iteration before this fix.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    // Read-only validation phase — release the borrow before mutating.
    {
        let Expression::SequenceExpression(seq) = &*expr else {
            return None;
        };
        if seq.expressions.len() <= 1 {
            return None;
        }
        let len = seq.expressions.len();
        let all_prefix_pure = seq.expressions[..len - 1]
            .iter()
            .all(query::is_side_effect_free);
        if !all_prefix_pure {
            return None;
        }
    }

    // Move the last element out — preserves scope_id / symbol_id / reference_id.
    let last = {
        let Expression::SequenceExpression(seq) = &mut *expr else {
            return None;
        };
        seq.expressions.last_mut()?.take_in(&ctx.ast.allocator())
    };
    *expr = last;
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_pure_prefix() {
        // (1, 2, 42) → 42
        let result = fold("(1, 2, 42);");
        assert!(result.contains("42"), "should fold to last: {result}");
        assert!(!result.contains(","), "should not have comma: {result}");
    }

    #[test]
    fn test_effectful_prefix_not_folded() {
        // (foo(), 42) — foo() has side effects, don't fold
        let result = fold("(foo(), 42);");
        assert!(result.contains(","), "effectful prefix should not fold: {result}");
    }

    #[test]
    fn test_single_element_not_folded() {
        let result = fold("(42);");
        assert!(result.contains("42"), "single element unchanged: {result}");
    }
}
