//! Immutable strings for the telemetry records.
//!
//! An `IStr` is 16 B inline (a `String` is 24 B) and cheap to clone. It used to point
//! at one shared copy of each value, kept for the life of the process: right while
//! every record stayed in memory, a leak once records come and go (SQLite holds them
//! and only the ones in use are read): every value read once stayed. On disk and in
//! JSON it is the same plain string, so the file format does not change.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IStr(Arc<str>);

impl IStr {
    pub fn new(s: &str) -> Self {
        IStr(Arc::from(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// For `#[serde(skip_serializing_if = "IStr::is_empty")]` (a path, not a method call).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for IStr {
    fn default() -> Self {
        IStr::new("")
    }
}

impl Deref for IStr {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for IStr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for IStr {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for IStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl From<&str> for IStr {
    fn from(s: &str) -> Self {
        IStr::new(s)
    }
}

impl From<String> for IStr {
    fn from(s: String) -> Self {
        IStr::new(&s)
    }
}

impl From<&String> for IStr {
    fn from(s: &String) -> Self {
        IStr::new(s)
    }
}

impl From<IStr> for String {
    fn from(s: IStr) -> Self {
        s.0.to_string()
    }
}

impl PartialEq<str> for IStr {
    fn eq(&self, o: &str) -> bool {
        &*self.0 == o
    }
}

impl PartialEq<&str> for IStr {
    fn eq(&self, o: &&str) -> bool {
        &*self.0 == *o
    }
}

impl PartialEq<String> for IStr {
    fn eq(&self, o: &String) -> bool {
        &*self.0 == o.as_str()
    }
}

impl PartialEq<IStr> for str {
    fn eq(&self, o: &IStr) -> bool {
        self == &*o.0
    }
}

impl PartialEq<IStr> for &str {
    fn eq(&self, o: &IStr) -> bool {
        *self == &*o.0
    }
}

impl PartialEq<IStr> for String {
    fn eq(&self, o: &IStr) -> bool {
        self.as_str() == &*o.0
    }
}

impl Serialize for IStr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Looks the text up without a temporary String (`visit_str` gets the input or
        // serde_json's unescape buffer).
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = IStr;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<IStr, E> {
                Ok(IStr::new(s))
            }
        }
        d.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_values_compare_equal_and_json_is_unchanged() {
        let a = IStr::new("malicious");
        let b: IStr = serde_json::from_str("\"malicious\"").unwrap();
        assert_eq!(a, b);
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"malicious\"");
        assert!(a == "malicious" && "malicious" == a && a == "malicious".to_string());
        let esc: IStr = serde_json::from_str("\"C:\\\\Users\"").unwrap();
        assert_eq!(esc.as_str(), "C:\\Users");
    }
}
