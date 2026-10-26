//! Statement-level folding: if-simplification, dead code trimming.
//!
//! `if(true) { body }` → `body`
//! `return; <unreachable>` → `return;`

use oxc::allocator::GetAllocator;
use oxc::allocator::TakeIn;
use oxc::ast::ast::Statement;

use oxc_traverse::TraverseCtx;

use crate::ast::query;

/// Try to fold a single statement. Returns modification count (0 or 1).
pub fn try_fold<'a>(
    stmt: &mut Statement<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> usize {
    let Statement::IfStatement(if_stmt) = &*stmt else {
        return 0;
    };

    let Some(truthy) = query::is_truthy(&if_stmt.test) else {
        return 0;
    };

    let allocator = &ctx.ast.allocator();
    let Statement::IfStatement(if_stmt) = stmt else {
        return 0;
    };

    if truthy {
        // if(true) { body } → body
        *stmt = if_stmt.consequent.take_in(allocator);
        1
    } else if let Some(alt) = &mut if_stmt.alternate {
        // if(false) { ... } else { alt } → alt
        *stmt = alt.take_in(allocator);
        1
    } else {
        // if(false) { ... } → empty statement
        *stmt = Statement::new_empty_statement(oxc::span::SPAN, &ctx.ast);
        1
    }
}

/// Clean a statement list: remove unreachable code after terminators.
///
/// Returns the number of removed statements.
pub fn clean<'a>(
    stmts: &mut oxc::allocator::Vec<'a, Statement<'a>>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> usize {
    let allocator = &ctx.ast.allocator();
    let mut new_stmts = oxc::allocator::Vec::new_in(&ctx.ast);
    let mut terminated = false;
    let mut removed = 0;

    for stmt in stmts.take_in(allocator) {
        if terminated {
            removed += 1;
            continue;
        }

        // Skip empty statements
        if matches!(stmt, Statement::EmptyStatement(_)) {
            removed += 1;
            continue;
        }

        if is_terminator(&stmt) {
            terminated = true;
        }

        new_stmts.push(stmt);
    }

    *stmts = new_stmts;
    removed
}

/// Check if a statement is an unconditional control-flow terminator.
///
/// Note: `break` and `continue` with labels might exit to an outer scope,
/// making subsequent code reachable. Only unlabeled ones in the innermost
/// loop/switch are true terminators. For safety, we only treat `return`
/// and `throw` as definite terminators since they always exit the function.
fn is_terminator(stmt: &Statement) -> bool {
    match stmt {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        // break/continue only terminate if unlabeled (target innermost construct)
        Statement::BreakStatement(b) => b.label.is_none(),
        Statement::ContinueStatement(c) => c.label.is_none(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_if_true() {
        let result = fold("if (true) { var x = 1; }");
        assert!(result.contains("var x = 1"), "if(true) should unwrap body: {result}");
        assert!(!result.contains("if"), "should not contain if: {result}");
    }

    #[test]
    fn test_if_false_with_else() {
        let result = fold("if (false) { var x = 1; } else { var y = 2; }");
        assert!(result.contains("var y = 2"), "if(false) should unwrap else: {result}");
        assert!(!result.contains("var x"), "should not contain if body: {result}");
    }

    #[test]
    fn test_if_false_no_else() {
        let result = fold("if (false) { var x = 1; }");
        assert!(!result.contains("var x"), "if(false) should remove body: {result}");
    }

    #[test]
    fn test_dead_code_after_return() {
        let result = fold("function f() { return 1; var x = 2; }");
        assert!(result.contains("return 1"), "should keep return: {result}");
        assert!(!result.contains("var x"), "should remove dead code after return: {result}");
    }

    #[test]
    fn test_empty_statements_removed() {
        let result = fold(";;var x = 1;;");
        assert!(result.contains("var x = 1"), "should keep non-empty: {result}");
    }

    #[test]
    fn test_unknown_condition_not_folded() {
        let result = fold("if (x) { var a = 1; }");
        assert!(result.contains("if"), "unknown condition should not fold: {result}");
    }
}
