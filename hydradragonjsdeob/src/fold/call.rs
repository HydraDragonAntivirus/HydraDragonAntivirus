//! CallExpression folding — built-in method calls and global function calls.
//!
//! `"abc".toUpperCase()` → `"ABC"`, `Math.floor(1.7)` → `1`, `atob("SGVsbG8=")` → `"Hello"`.
//!
//! Dispatch: AST callee pattern → extract args → value/ computation → AST result.

use oxc::ast::ast::{Argument, Expression};

use oxc_traverse::TraverseCtx;
use tracing::trace;

use crate::ast::{create, extract};
use crate::value::{self, JsValue};

/// Try to fold a CallExpression. Returns `Some(1)` if folded.
pub fn try_fold<'a>(
    expr: &mut Expression<'a>,
    ctx: &mut TraverseCtx<'a, ()>,
) -> Option<usize> {
    // Compute the result while borrowing expr immutably.
    let result = compute_call_result(expr)?;

    // Now mutate — the immutable borrow is dropped.
    *expr = create::from_js_value(&result, &ctx.ast);
    Some(1)
}

/// Compute the folded result of a CallExpression without mutating it.
fn compute_call_result(expr: &Expression) -> Option<JsValue> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };

    // No spread arguments.
    if call.arguments.iter().any(|a| matches!(a, Argument::SpreadElement(_))) {
        trace!("call folding: skipping call with spread argument");
        return None;
    }

    match &call.callee {
        // Method call: obj.method(args)
        Expression::StaticMemberExpression(member) => {
            let method = member.property.name.as_str();
            compute_method_result(&member.object, method, &call.arguments)
        }
        // Global function call: func(args)
        Expression::Identifier(ident) => {
            compute_global_result(ident.name.as_str(), &call.arguments)
        }
        _ => None,
    }
}

// ============================================================================
// Method calls: obj.method(args)
// ============================================================================

fn compute_method_result(
    object: &Expression,
    method: &str,
    args: &[Argument<'_>],
) -> Option<JsValue> {
    // String literal method: "abc".toUpperCase()
    if let Some(s) = extract::string(object) {
        let js_args = extract_args(args)?;
        return value::string::call(s, method, &js_args);
    }

    // Identifier object: Math.floor(), JSON.parse(), Number.isNaN(), String.fromCharCode()
    if let Expression::Identifier(obj_id) = object {
        return compute_static_result(obj_id.name.as_str(), method, args);
    }

    // Array literal method: [1,2,3].join(",")
    if let Some(elements) = extract::array_elements(object) {
        let arr: Vec<JsValue> = elements.iter().filter_map(|e| extract::js_value(e)).collect();
        if arr.len() != elements.len() {
            return None;
        }
        let js_args = extract_args(args)?;
        return value::array::call(&arr, method, &js_args);
    }

    None
}

fn compute_static_result(
    object_name: &str,
    method: &str,
    args: &[Argument<'_>],
) -> Option<JsValue> {
    let js_args = extract_args(args)?;

    match object_name {
        "Math" => value::math::call(method, &js_args),
        "Number" => value::number::call(method, &js_args),
        "String" => match method {
            "fromCharCode" => value::string::from_char_code(&js_args),
            "fromCodePoint" => value::string::from_code_point(&js_args),
            _ => None,
        },
        "JSON" => match method {
            "stringify" => value::json::stringify(js_args.first()?),
            "parse" => {
                let s = match js_args.first()? {
                    JsValue::String(s) => s.as_str(),
                    _ => return None,
                };
                value::json::parse(s)
            }
            _ => None,
        },
        _ => None,
    }
}

fn compute_global_result(
    func_name: &str,
    args: &[Argument<'_>],
) -> Option<JsValue> {
    let js_args = extract_args(args)?;

    match func_name {
        // Number functions
        "parseInt" => value::number::parse_int(&js_args),
        "parseFloat" => value::number::parse_float(&js_args),
        "isNaN" => value::number::global_is_nan(&js_args),
        "isFinite" => value::number::global_is_finite(&js_args),

        // Constructor coercion (without new)
        "Number" => Some(value::number::coerce(&js_args)),
        "String" => {
            let s = js_args.first().map(value::coerce::to_string).unwrap_or_default();
            Some(JsValue::String(s))
        }
        "Boolean" => {
            let b = js_args.first().map(|v| v.is_truthy()).unwrap_or(false);
            Some(JsValue::Boolean(b))
        }

        // URI functions
        "encodeURI" | "decodeURI" | "encodeURIComponent" | "decodeURIComponent" => {
            value::uri::call(func_name, &js_args)
        }

        // Browser runtime APIs
        "atob" | "btoa" | "escape" | "unescape" => {
            value::runtime::call(func_name, &js_args)
        }

        _ => None,
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Extract all arguments as JsValue. Returns None if any argument is not extractable.
fn extract_args(args: &[Argument<'_>]) -> Option<Vec<JsValue>> {
    args.iter()
        .map(|a| a.as_expression().and_then(extract::js_value))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::test_utils::fold;

    // String methods
    #[test]
    fn test_string_to_upper() {
        assert!(fold("\"hello\".toUpperCase();").contains("\"HELLO\""));
    }

    #[test]
    fn test_string_to_lower() {
        assert!(fold("\"HELLO\".toLowerCase();").contains("\"hello\""));
    }

    #[test]
    fn test_string_trim() {
        assert!(fold("\"  hi  \".trim();").contains("\"hi\""));
    }

    #[test]
    fn test_string_char_at() {
        assert!(fold("\"abc\".charAt(1);").contains("\"b\""));
    }

    #[test]
    fn test_string_char_code_at() {
        assert!(fold("\"A\".charCodeAt(0);").contains("65"));
    }

    #[test]
    fn test_string_slice() {
        assert!(fold("\"hello\".slice(1, 3);").contains("\"el\""));
    }

    #[test]
    fn test_string_index_of() {
        assert!(fold("\"hello\".indexOf(\"ll\");").contains("2"));
    }

    #[test]
    fn test_string_includes() {
        assert!(fold("\"hello\".includes(\"ell\");").contains("true"));
    }

    #[test]
    fn test_string_repeat() {
        assert!(fold("\"ab\".repeat(3);").contains("\"ababab\""));
    }

    #[test]
    fn test_string_replace() {
        assert!(fold("\"aabb\".replace(\"aa\", \"XX\");").contains("\"XXbb\""));
    }

    #[test]
    fn test_string_pad_start() {
        assert!(fold("\"5\".padStart(3, \"0\");").contains("\"005\""));
    }

    // String static methods
    #[test]
    fn test_string_from_char_code() {
        assert!(fold("String.fromCharCode(72, 101, 108, 108, 111);").contains("\"Hello\""));
    }

    // Math methods
    #[test]
    fn test_math_floor() {
        assert!(fold("Math.floor(1.7);").contains("1"));
    }

    #[test]
    fn test_math_ceil() {
        assert!(fold("Math.ceil(1.1);").contains("2"));
    }

    #[test]
    fn test_math_abs() {
        assert!(fold("Math.abs(-5);").contains("5"));
    }

    #[test]
    fn test_math_pow() {
        assert!(fold("Math.pow(2, 10);").contains("1024"));
    }

    #[test]
    fn test_math_max() {
        assert!(fold("Math.max(1, 3, 2);").contains("3"));
    }

    // Global functions
    #[test]
    fn test_parse_int() {
        assert!(fold("parseInt(\"42\");").contains("42"));
    }

    #[test]
    fn test_parse_int_radix() {
        assert!(fold("parseInt(\"ff\", 16);").contains("255"));
    }

    #[test]
    fn test_is_nan() {
        assert!(fold("isNaN(\"abc\");").contains("true"));
        assert!(fold("isNaN(42);").contains("false"));
    }

    // Constructor coercion
    #[test]
    fn test_number_coerce() {
        assert!(fold("Number(\"42\");").contains("42"));
        assert!(fold("Number(true);").contains("1"));
    }

    #[test]
    fn test_string_coerce() {
        assert!(fold("String(42);").contains("\"42\""));
        assert!(fold("String(true);").contains("\"true\""));
    }

    #[test]
    fn test_boolean_coerce() {
        assert!(fold("Boolean(1);").contains("true"));
        assert!(fold("Boolean(0);").contains("false"));
    }

    // URI functions
    #[test]
    fn test_encode_uri_component() {
        assert!(fold("encodeURIComponent(\"hello world\");").contains("\"hello%20world\""));
    }

    #[test]
    fn test_decode_uri_component() {
        assert!(fold("decodeURIComponent(\"hello%20world\");").contains("\"hello world\""));
    }

    // Runtime APIs
    #[test]
    fn test_atob() {
        assert!(fold("atob(\"SGVsbG8=\");").contains("\"Hello\""));
    }

    #[test]
    fn test_btoa() {
        assert!(fold("btoa(\"Hello\");").contains("\"SGVsbG8=\""));
    }

    // Array methods
    #[test]
    fn test_array_join() {
        assert!(fold("[1, 2, 3].join(\",\");").contains("\"1,2,3\""));
    }

    #[test]
    fn test_array_index_of() {
        assert!(fold("[1, 2, 3].indexOf(2);").contains("1"));
    }

    #[test]
    fn test_array_includes() {
        assert!(fold("[1, 2, 3].includes(2);").contains("true"));
    }

    // Non-foldable
    #[test]
    fn test_unknown_function_not_folded() {
        let result = fold("foo(42);");
        assert!(result.contains("foo"), "unknown function should not fold: {result}");
    }

    #[test]
    fn test_variable_arg_not_folded() {
        let result = fold("parseInt(x);");
        assert!(result.contains("parseInt"), "variable arg should not fold: {result}");
    }

    // Number static methods
    #[test]
    fn test_number_is_nan() {
        assert!(fold("Number.isNaN(NaN);").contains("true"));
    }

    #[test]
    fn test_number_is_finite() {
        assert!(fold("Number.isFinite(42);").contains("true"));
    }

    // JSON
    #[test]
    fn test_json_parse() {
        assert!(fold("JSON.parse(\"42\");").contains("42"));
    }

    #[test]
    fn test_json_stringify() {
        assert!(fold("JSON.stringify(42);").contains("\"42\""));
    }
}
