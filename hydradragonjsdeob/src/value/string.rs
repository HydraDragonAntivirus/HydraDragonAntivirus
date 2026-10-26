//! String.prototype method evaluation.
//!
//! Pure Rust implementations of JavaScript string methods.
//! Input: `&str` + method name + args. Output: `Option<JsValue>`.

use super::JsValue;
use super::coerce::to_int32;

// ============================================================================
// Method dispatch
// ============================================================================

/// Evaluate a string method call: `"abc".method(args)`.
pub fn call(this: &str, method: &str, args: &[JsValue]) -> Option<JsValue> {
    match method {
        "charAt" => char_at(this, args),
        "charCodeAt" => char_code_at(this, args),
        "codePointAt" => code_point_at(this, args),
        "at" => at(this, args),
        "indexOf" => index_of(this, args),
        "lastIndexOf" => last_index_of(this, args),
        "includes" => includes(this, args),
        "startsWith" => starts_with(this, args),
        "endsWith" => ends_with(this, args),
        "slice" => slice(this, args),
        "substring" => substring(this, args),
        "substr" => substr(this, args),
        "toUpperCase" | "toLocaleUpperCase" => Some(JsValue::String(this.to_uppercase())),
        "toLowerCase" | "toLocaleLowerCase" => Some(JsValue::String(this.to_lowercase())),
        "trim" => Some(JsValue::String(this.trim().to_string())),
        "trimStart" | "trimLeft" => Some(JsValue::String(this.trim_start().to_string())),
        "trimEnd" | "trimRight" => Some(JsValue::String(this.trim_end().to_string())),
        "repeat" => repeat(this, args),
        "padStart" => pad_start(this, args),
        "padEnd" => pad_end(this, args),
        "replace" => replace(this, args),
        "concat" => concat(this, args),
        "toString" | "valueOf" => Some(JsValue::String(this.to_string())),
        _ => None,
    }
}

/// String property access: `.length`, `[index]`.
pub fn property(this: &str, prop: &str) -> Option<JsValue> {
    if prop == "length" {
        let len: usize = this.chars().map(|c| if c as u32 > 0xFFFF { 2 } else { 1 }).sum();
        return Some(JsValue::Number(len as f64));
    }
    if let Ok(idx) = prop.parse::<usize>() {
        return this.chars().nth(idx).map(|c| JsValue::String(c.to_string()));
    }
    None
}

// ============================================================================
// Static methods
// ============================================================================

/// `String.fromCharCode(...codes)`.
pub fn from_char_code(args: &[JsValue]) -> Option<JsValue> {
    let mut result = String::new();
    for arg in args {
        let code = to_int32(arg) as u16;
        result.push(char::from_u32(code as u32).unwrap_or('\u{FFFD}'));
    }
    Some(JsValue::String(result))
}

/// `String.fromCodePoint(...codes)`.
pub fn from_code_point(args: &[JsValue]) -> Option<JsValue> {
    let mut result = String::new();
    for arg in args {
        let code = to_int32(arg);
        if !(0..=0x10FFFF).contains(&code) { return None; }
        result.push(char::from_u32(code as u32)?);
    }
    Some(JsValue::String(result))
}

// ============================================================================
// Instance methods
// ============================================================================

fn char_at(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let idx = arg_int(args, 0, 0) as usize;
    Some(JsValue::String(this.chars().nth(idx).map_or(String::new(), |c| c.to_string())))
}

fn char_code_at(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let idx = arg_int(args, 0, 0) as usize;
    Some(this.chars().nth(idx).map_or(JsValue::Number(f64::NAN), |c| JsValue::Number(c as u32 as f64)))
}

fn code_point_at(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let idx = arg_int(args, 0, 0) as usize;
    Some(this.chars().nth(idx).map_or(JsValue::Undefined, |c| JsValue::Number(c as u32 as f64)))
}

fn at(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let idx = arg_int(args, 0, 0);
    let len = this.chars().count() as i32;
    let resolved = if idx < 0 { len + idx } else { idx };
    if resolved < 0 || resolved >= len {
        return Some(JsValue::Undefined);
    }
    this.chars().nth(resolved as usize).map(|c| JsValue::String(c.to_string()))
}

fn index_of(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let search = arg_str(args, 0)?;
    let from = arg_int(args, 1, 0).max(0) as usize;
    if from > this.len() {
        return Some(JsValue::Number(-1.0));
    }
    Some(JsValue::Number(this[from..].find(&*search).map_or(-1.0, |p| (p + from) as f64)))
}

fn last_index_of(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let search = arg_str(args, 0)?;
    Some(JsValue::Number(this.rfind(&*search).map_or(-1.0, |p| p as f64)))
}

fn includes(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let search = arg_str(args, 0)?;
    let from = arg_int(args, 1, 0).max(0) as usize;
    if from > this.len() {
        return Some(JsValue::Boolean(false));
    }
    Some(JsValue::Boolean(this[from..].contains(&*search)))
}

fn starts_with(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let search = arg_str(args, 0)?;
    let pos = arg_int(args, 1, 0).max(0) as usize;
    if pos > this.len() { return Some(JsValue::Boolean(false)); }
    Some(JsValue::Boolean(this[pos..].starts_with(&*search)))
}

fn ends_with(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let search = arg_str(args, 0)?;
    Some(JsValue::Boolean(this.ends_with(&*search)))
}

fn slice(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let len = this.chars().count() as i32;
    let start = resolve_index(arg_int(args, 0, 0), len);
    let end = resolve_index(arg_int(args, 1, len), len);
    if start >= end { return Some(JsValue::String(String::new())); }
    Some(JsValue::String(this.chars().skip(start as usize).take((end - start) as usize).collect()))
}

fn substring(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let len = this.chars().count() as i32;
    let mut start = arg_int(args, 0, 0).clamp(0, len);
    let mut end = arg_int(args, 1, len).clamp(0, len);
    if start > end { std::mem::swap(&mut start, &mut end); }
    Some(JsValue::String(this.chars().skip(start as usize).take((end - start) as usize).collect()))
}

fn substr(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let len = this.chars().count() as i32;
    let start = resolve_index(arg_int(args, 0, 0), len);
    let count = arg_int(args, 1, len).max(0);
    if start >= len || count <= 0 { return Some(JsValue::String(String::new())); }
    Some(JsValue::String(this.chars().skip(start as usize).take(count as usize).collect()))
}

fn repeat(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let count = arg_int(args, 0, 0);
    if !(0..=10_000).contains(&count) { return None; }
    Some(JsValue::String(this.repeat(count as usize)))
}

fn pad_start(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let target_len = arg_int(args, 0, 0) as usize;
    let fill = arg_str(args, 1).unwrap_or_else(|| " ".to_string());
    if this.len() >= target_len || fill.is_empty() { return Some(JsValue::String(this.to_string())); }
    let padding: String = fill.chars().cycle().take(target_len - this.len()).collect();
    Some(JsValue::String(format!("{padding}{this}")))
}

fn pad_end(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let target_len = arg_int(args, 0, 0) as usize;
    let fill = arg_str(args, 1).unwrap_or_else(|| " ".to_string());
    if this.len() >= target_len || fill.is_empty() { return Some(JsValue::String(this.to_string())); }
    let padding: String = fill.chars().cycle().take(target_len - this.len()).collect();
    Some(JsValue::String(format!("{this}{padding}")))
}

fn replace(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let search = arg_str(args, 0)?;
    let replacement = arg_str(args, 1)?;
    Some(JsValue::String(this.replacen(&*search, &replacement, 1)))
}

fn concat(this: &str, args: &[JsValue]) -> Option<JsValue> {
    let mut result = this.to_string();
    for arg in args {
        result.push_str(&super::coerce::to_string(arg));
    }
    Some(JsValue::String(result))
}

// ============================================================================
// Helpers
// ============================================================================

fn arg_int(args: &[JsValue], index: usize, default: i32) -> i32 {
    args.get(index).map_or(default, super::coerce::to_int32)
}

fn arg_str(args: &[JsValue], index: usize) -> Option<String> {
    args.get(index).map(super::coerce::to_string)
}

fn resolve_index(idx: i32, len: i32) -> i32 {
    if idx < 0 { (len + idx).max(0) } else { idx.min(len) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> JsValue { JsValue::String(v.into()) }
    fn n(v: f64) -> JsValue { JsValue::Number(v) }

    #[test]
    fn test_char_at() {
        assert_eq!(call("abc", "charAt", &[n(0.0)]), Some(s("a")));
        assert_eq!(call("abc", "charAt", &[n(5.0)]), Some(s("")));
    }

    #[test]
    fn test_char_code_at() {
        assert_eq!(call("A", "charCodeAt", &[n(0.0)]), Some(n(65.0)));
    }

    #[test]
    fn test_index_of() {
        assert_eq!(call("hello world", "indexOf", &[s("world")]), Some(n(6.0)));
        assert_eq!(call("hello", "indexOf", &[s("x")]), Some(n(-1.0)));
    }

    #[test]
    fn test_includes() {
        assert_eq!(call("hello", "includes", &[s("ell")]), Some(JsValue::Boolean(true)));
        assert_eq!(call("hello", "includes", &[s("xyz")]), Some(JsValue::Boolean(false)));
    }

    #[test]
    fn test_slice() {
        assert_eq!(call("hello", "slice", &[n(1.0), n(3.0)]), Some(s("el")));
        assert_eq!(call("hello", "slice", &[n(-3.0)]), Some(s("llo")));
    }

    #[test]
    fn test_case() {
        assert_eq!(call("Hello", "toUpperCase", &[]), Some(s("HELLO")));
        assert_eq!(call("Hello", "toLowerCase", &[]), Some(s("hello")));
    }

    #[test]
    fn test_trim() {
        assert_eq!(call("  hi  ", "trim", &[]), Some(s("hi")));
    }

    #[test]
    fn test_repeat() {
        assert_eq!(call("ab", "repeat", &[n(3.0)]), Some(s("ababab")));
    }

    #[test]
    fn test_pad() {
        assert_eq!(call("5", "padStart", &[n(3.0), s("0")]), Some(s("005")));
        assert_eq!(call("5", "padEnd", &[n(3.0), s("0")]), Some(s("500")));
    }

    #[test]
    fn test_replace() {
        assert_eq!(call("aabbcc", "replace", &[s("bb"), s("XX")]), Some(s("aaXXcc")));
        assert_eq!(call("abab", "replace", &[s("ab"), s("X")]), Some(s("Xab")));
    }

    #[test]
    fn test_from_char_code() {
        assert_eq!(from_char_code(&[n(72.0), n(101.0), n(108.0), n(108.0), n(111.0)]), Some(s("Hello")));
    }

    #[test]
    fn test_at() {
        assert_eq!(call("abc", "at", &[n(0.0)]), Some(s("a")));
        assert_eq!(call("abc", "at", &[n(-1.0)]), Some(s("c")));
    }

    #[test]
    fn test_property_length() {
        assert_eq!(property("hello", "length"), Some(n(5.0)));
    }

    #[test]
    fn test_bracket_access() {
        assert_eq!(property("abc", "0"), Some(s("a")));
        assert_eq!(property("abc", "2"), Some(s("c")));
    }
}
