//! UnaryExpression folding — all unary operators.
//!
//! `typeof "x"` → `"string"`, `!true` → `false`, `void 0` → `undefined`.

use oxc::ast::ast::{Expression, UnaryOperator};

use oxc_traverse::TraverseCtx;

use crate::ast::{create, extract};
use crate::value::{JsValue, ops};

/// Try to fold a UnaryExpression. Returns `Some(1)` if folded.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else {
        return None;
    };

    match unary.operator {
        UnaryOperator::Typeof => fold_typeof(expr, ctx),
        UnaryOperator::Void => fold_void(expr, ctx),
        UnaryOperator::LogicalNot => fold_not(expr, ctx),
        UnaryOperator::BitwiseNot => fold_bitnot(expr, ctx),
        UnaryOperator::UnaryNegation => fold_neg(expr, ctx),
        UnaryOperator::UnaryPlus => fold_pos(expr, ctx),
        UnaryOperator::Delete => None, // Side effect — never fold
    }
}

fn fold_typeof<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else { return None; };
    let val = extract::js_value(&unary.argument)?;
    let result = ops::type_of(&val);
    *expr = create::from_js_value(&result, &ctx.ast);
    Some(1)
}

fn fold_void<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else { return None; };
    // void <expr> → undefined, but only if the argument is side-effect-free
    if !crate::ast::query::is_side_effect_free(&unary.argument) {
        return None;
    }
    *expr = create::make_undefined(&ctx.ast);
    Some(1)
}

fn fold_not<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else { return None; };
    // !<expr> → true/false if truthiness is known
    let truthy = crate::ast::query::is_truthy(&unary.argument)?;
    *expr = create::make_boolean(!truthy, &ctx.ast);
    Some(1)
}

fn fold_bitnot<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else { return None; };
    let val = extract::js_value(&unary.argument)?;
    let result = ops::bit_not(&val);
    *expr = create::from_js_value(&result, &ctx.ast);
    Some(1)
}

fn fold_neg<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else { return None; };
    // Only fold -<literal> when the argument is a non-number that coerces
    // (e.g., -true → -1). Don't fold -42 → -42 (already a literal).
    let val = extract::js_value(&unary.argument)?;
    if matches!(val, JsValue::Number(_)) {
        return None; // -42 is already a leaf literal handled by extract::number
    }
    let result = ops::neg(&val);
    *expr = create::from_js_value(&result, &ctx.ast);
    Some(1)
}

fn fold_pos<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::UnaryExpression(unary) = &*expr else { return None; };
    // +<expr> → ToNumber(expr) when the argument is a non-number literal
    let val = extract::js_value(&unary.argument)?;
    if matches!(val, JsValue::Number(_)) {
        return None; // +42 is already a leaf
    }
    let result = ops::pos(&val);
    *expr = create::from_js_value(&result, &ctx.ast);
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_typeof() {
        assert!(fold("typeof \"hello\";").contains("\"string\""));
        assert!(fold("typeof 42;").contains("\"number\""));
        assert!(fold("typeof true;").contains("\"boolean\""));
        assert!(fold("typeof null;").contains("\"object\""));
        assert!(fold("typeof undefined;").contains("\"undefined\""));
    }

    #[test]
    fn test_void() {
        let result = fold("void 0;");
        assert!(result.contains("undefined"), "void 0 → undefined: {result}");
    }

    #[test]
    fn test_not() {
        assert!(fold("!true;").contains("false"));
        assert!(fold("!false;").contains("true"));
        assert!(fold("!0;").contains("true"));
        assert!(fold("!1;").contains("false"));
        assert!(fold("!\"\";").contains("true"));
        assert!(fold("!\"x\";").contains("false"));
    }

    #[test]
    fn test_bitnot() {
        assert!(fold("~0;").contains("-1"));
        assert!(fold("~-1;").contains("0"));
    }

    #[test]
    fn test_pos_coercion() {
        assert!(fold("+true;").contains("1"));
        assert!(fold("+false;").contains("0"));
        assert!(fold("+\"\";").contains("0"));
    }

    #[test]
    fn test_neg_coercion() {
        assert!(fold("-true;").contains("-1"));
    }

    #[test]
    fn test_delete_not_folded() {
        let result = fold("delete x.y;");
        assert!(result.contains("delete"), "delete should not fold: {result}");
    }
}
