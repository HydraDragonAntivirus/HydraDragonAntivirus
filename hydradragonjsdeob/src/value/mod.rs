//! Layer 0: Pure JavaScript value computation.
//!
//! No OXC. No allocation. No AST. Just values in, values out.
//! Every higher layer depends on this. This depends on nothing.

pub mod ops;
pub mod coerce;
pub mod string;
pub mod array;
pub mod math;
pub mod number;
pub mod json;
pub mod uri;
pub mod runtime;

// ============================================================================
// Types
// ============================================================================

/// Compact JavaScript primitive value.
///
/// Owned, lifetime-free. Use for storing values across traversals
/// (constant propagation maps, eval caches).
///
/// For zero-copy extraction within a single traversal, use
/// `ast::extract::string()`, `ast::extract::number()` etc. instead.
#[derive(Debug, Clone, PartialEq)]
pub enum JsValue {
    Number(f64),
    String(String),
    Boolean(bool),
    Null,
    Undefined,
}

// ============================================================================
// Display
// ============================================================================

impl std::fmt::Display for JsValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{}", coerce::number_to_string(*n)),
            Self::String(s) => write!(f, "{s}"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Null => write!(f, "null"),
            Self::Undefined => write!(f, "undefined"),
        }
    }
}

// ============================================================================
// Truthiness
// ============================================================================

impl JsValue {
    /// JavaScript falsy check.
    ///
    /// Falsy values: `false`, `0`, `-0`, `NaN`, `""`, `null`, `undefined`.
    #[inline]
    pub fn is_falsy(&self) -> bool {
        match self {
            Self::Boolean(false) | Self::Null | Self::Undefined => true,
            Self::Number(n) => *n == 0.0 || n.is_nan(),
            Self::String(s) => s.is_empty(),
            Self::Boolean(true) => false,
        }
    }

    /// JavaScript truthy check.
    #[inline]
    pub fn is_truthy(&self) -> bool {
        !self.is_falsy()
    }

    /// JavaScript `typeof` result.
    #[inline]
    pub fn type_of(&self) -> &'static str {
        match self {
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Boolean(_) => "boolean",
            Self::Null => "object",
            Self::Undefined => "undefined",
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falsy_values() {
        assert!(JsValue::Boolean(false).is_falsy());
        assert!(JsValue::Number(0.0).is_falsy());
        assert!(JsValue::Number(-0.0).is_falsy());
        assert!(JsValue::Number(f64::NAN).is_falsy());
        assert!(JsValue::String(String::new()).is_falsy());
        assert!(JsValue::Null.is_falsy());
        assert!(JsValue::Undefined.is_falsy());
    }

    #[test]
    fn test_truthy_values() {
        assert!(JsValue::Boolean(true).is_truthy());
        assert!(JsValue::Number(1.0).is_truthy());
        assert!(JsValue::Number(-1.0).is_truthy());
        assert!(JsValue::String("x".into()).is_truthy());
        assert!(JsValue::String("false".into()).is_truthy());
    }

    #[test]
    fn test_typeof() {
        assert_eq!(JsValue::Number(1.0).type_of(), "number");
        assert_eq!(JsValue::String("x".into()).type_of(), "string");
        assert_eq!(JsValue::Boolean(true).type_of(), "boolean");
        assert_eq!(JsValue::Null.type_of(), "object");
        assert_eq!(JsValue::Undefined.type_of(), "undefined");
    }

    #[test]
    fn test_display() {
        assert_eq!(JsValue::Number(42.0).to_string(), "42");
        assert_eq!(JsValue::Number(-0.5).to_string(), "-0.5");
        assert_eq!(JsValue::String("hello".into()).to_string(), "hello");
        assert_eq!(JsValue::Boolean(true).to_string(), "true");
        assert_eq!(JsValue::Null.to_string(), "null");
        assert_eq!(JsValue::Undefined.to_string(), "undefined");
    }
}
