//! Array.prototype method evaluation.
//!
//! Operates on `Vec<JsValue>` (extracted from AST ArrayExpression by fold/call.rs).

use super::JsValue;
use super::coerce::{to_number, to_string};

/// Evaluate `[...].method(args)`.
pub fn call(this: &[JsValue], method: &str, args: &[JsValue]) -> Option<JsValue> {
    match method {
        "join" => join(this, args),
        "indexOf" => index_of(this, args),
        "lastIndexOf" => last_index_of(this, args),
        "includes" => includes(this, args),
        "at" => at(this, args),
        "toString" => join(this, &[]),
        "concat" => concat(this, args),
        "reverse" => reverse(this),
        "flat" => flat(this),
        _ => None,
    }
}

/// Array property access: `.length`, `[index]`.
pub fn property(this: &[JsValue], prop: &str) -> Option<JsValue> {
    if prop == "length" {
        return Some(JsValue::Number(this.len() as f64));
    }
    if let Ok(idx) = prop.parse::<usize>() {
        return this.get(idx).cloned();
    }
    None
}

fn join(this: &[JsValue], args: &[JsValue]) -> Option<JsValue> {
    let sep = args.first().map(to_string).unwrap_or_else(|| ",".to_string());
    let parts: Vec<String> = this.iter().map(|v| match v {
        JsValue::Null | JsValue::Undefined => String::new(),
        other => to_string(other),
    }).collect();
    Some(JsValue::String(parts.join(&sep)))
}

fn index_of(this: &[JsValue], args: &[JsValue]) -> Option<JsValue> {
    let search = args.first()?;
    let from = args.get(1).map(|v| to_number(v) as i32).unwrap_or(0).max(0) as usize;
    for (i, item) in this.iter().enumerate().skip(from) {
        if super::ops::strict_eq_bool(item, search) {
            return Some(JsValue::Number(i as f64));
        }
    }
    Some(JsValue::Number(-1.0))
}

fn last_index_of(this: &[JsValue], args: &[JsValue]) -> Option<JsValue> {
    let search = args.first()?;
    for (i, item) in this.iter().enumerate().rev() {
        if super::ops::strict_eq_bool(item, search) {
            return Some(JsValue::Number(i as f64));
        }
    }
    Some(JsValue::Number(-1.0))
}

fn includes(this: &[JsValue], args: &[JsValue]) -> Option<JsValue> {
    let search = args.first()?;
    let from = args.get(1).map(|v| to_number(v) as i32).unwrap_or(0).max(0) as usize;
    let found = this.iter().skip(from).any(|item| super::ops::strict_eq_bool(item, search));
    Some(JsValue::Boolean(found))
}

fn at(this: &[JsValue], args: &[JsValue]) -> Option<JsValue> {
    let idx = args.first().map(|v| to_number(v) as i32).unwrap_or(0);
    let len = this.len() as i32;
    let resolved = if idx < 0 { len + idx } else { idx };
    if resolved < 0 || resolved >= len {
        return Some(JsValue::Undefined);
    }
    this.get(resolved as usize).cloned()
}

fn concat(this: &[JsValue], args: &[JsValue]) -> Option<JsValue> {
    // Returns None — JsValue has no Array variant. fold/call.rs handles AST creation.
    let _ = (this, args);
    None
}

fn reverse(this: &[JsValue]) -> Option<JsValue> {
    let _ = this;
    None // Mutating — fold/call.rs handles AST creation for reversed array.
}

fn flat(this: &[JsValue]) -> Option<JsValue> {
    let _ = this;
    None // Complex — skip for now.
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(v: f64) -> JsValue { JsValue::Number(v) }
    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }

    #[test]
    fn test_join() {
        let arr = [s("a"), s("b"), s("c")];
        assert_eq!(call(&arr, "join", &[s(",")]), Some(s("a,b,c")));
        assert_eq!(call(&arr, "join", &[s("")]), Some(s("abc")));
        assert_eq!(call(&arr, "join", &[]), Some(s("a,b,c")));
    }

    #[test]
    fn test_index_of() {
        let arr = [n(1.0), n(2.0), n(3.0), n(2.0)];
        assert_eq!(call(&arr, "indexOf", &[n(2.0)]), Some(n(1.0)));
        assert_eq!(call(&arr, "indexOf", &[n(5.0)]), Some(n(-1.0)));
    }

    #[test]
    fn test_includes() {
        let arr = [n(1.0), n(2.0), n(3.0)];
        assert_eq!(call(&arr, "includes", &[n(2.0)]), Some(JsValue::Boolean(true)));
        assert_eq!(call(&arr, "includes", &[n(5.0)]), Some(JsValue::Boolean(false)));
    }

    #[test]
    fn test_at() {
        let arr = [s("a"), s("b"), s("c")];
        assert_eq!(call(&arr, "at", &[n(0.0)]), Some(s("a")));
        assert_eq!(call(&arr, "at", &[n(-1.0)]), Some(s("c")));
        assert_eq!(call(&arr, "at", &[n(5.0)]), Some(JsValue::Undefined));
    }

    #[test]
    fn test_property_length() {
        let arr = [n(1.0), n(2.0), n(3.0)];
        assert_eq!(property(&arr, "length"), Some(n(3.0)));
    }

    #[test]
    fn test_bracket_access() {
        let arr = [s("x"), s("y")];
        assert_eq!(property(&arr, "0"), Some(s("x")));
        assert_eq!(property(&arr, "1"), Some(s("y")));
    }

    #[test]
    fn test_join_with_null() {
        let arr = [s("a"), JsValue::Null, s("c")];
        assert_eq!(call(&arr, "join", &[s(",")]), Some(s("a,,c")));
    }

    #[test]
    fn test_to_string() {
        let arr = [n(1.0), n(2.0), n(3.0)];
        assert_eq!(call(&arr, "toString", &[]), Some(s("1,2,3")));
    }
}
