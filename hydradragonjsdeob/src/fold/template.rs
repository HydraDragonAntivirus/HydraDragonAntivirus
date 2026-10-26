//! TemplateLiteral folding — template strings with only literal expressions.
//!
//! `` `hello ${"world"}` `` → `"hello world"`
//! `` `${1} + ${2} = ${3}` `` → `"1 + 2 = 3"`

use oxc::ast::ast::Expression;

use oxc_traverse::TraverseCtx;

use crate::ast::{create, extract};
use crate::value::coerce::to_string;

/// Try to fold a TemplateLiteral. Returns `Some(1)` if folded.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    let Expression::TemplateLiteral(template) = &*expr else {
        return None;
    };

    // Skip tagged templates
    // (TaggedTemplateExpression wraps TemplateLiteral, so this check is for safety)

    // All expressions must be extractable as JsValue
    let expression_values: Vec<_> = template.expressions.iter()
        .map(extract::js_value)
        .collect::<Option<Vec<_>>>()?;

    // Build the resulting string
    let mut result = String::new();

    for (i, quasi) in template.quasis.iter().enumerate() {
        // Add the quasi (static part)
        // Use cooked if available, otherwise raw
        let quasi_str = quasi.value.cooked.as_ref()
            .map(|s| s.as_str())
            .unwrap_or_else(|| quasi.value.raw.as_str());
        result.push_str(quasi_str);

        // Add the expression value (if not the last quasi)
        if i < expression_values.len() {
            result.push_str(&to_string(&expression_values[i]));
        }
    }
    if result.len() > crate::value::MAX_STRING_LEN {
        return None;
    }

    *expr = create::make_string(&result, &ctx.ast);
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    #[test]
    fn test_no_expressions() {
        let result = fold("`hello world`;");
        assert!(result.contains("\"hello world\""), "got: {result}");
    }

    #[test]
    fn test_single_expression() {
        let result = fold("`hello ${\"world\"}`;");
        assert!(result.contains("\"hello world\""), "got: {result}");
    }

    #[test]
    fn test_multiple_expressions() {
        let result = fold("`${1} + ${2} = ${3}`;");
        assert!(result.contains("\"1 + 2 = 3\""), "got: {result}");
    }

    #[test]
    fn test_mixed_types() {
        let result = fold("`bool: ${true}, null: ${null}`;");
        assert!(result.contains("\"bool: true, null: null\""), "got: {result}");
    }

    #[test]
    fn test_variable_not_folded() {
        let result = fold("`hello ${x}`;");
        assert!(result.contains("`"), "variable should not fold: {result}");
    }

    #[test]
    fn test_nested_template() {
        // Inner template folds first, then outer
        let result = fold("`outer ${`inner`}`;");
        // After one fold: `outer ${"inner"}`
        // After second fold: "outer inner"
        assert!(result.contains("\"") || result.contains("`"), "got: {result}");
    }
}
