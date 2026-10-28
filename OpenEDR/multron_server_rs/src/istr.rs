//! Shared, immutable strings for the telemetry kept in memory.
//!
//! `threat_insights.jsonl` repeats a few values over and over: 5 verdicts, ~150 client
//! IPs and some ten thousand folders for hundreds of thousands of files. As `String`s each
//! copy had its own allocation (24 B inline + the text + the allocator's header); an
//! `IStr` with a value already in memory points at that copy (16 B inline, nothing
//! more). On disk and in JSON it is the same plain string, so the file format does not
//! change. Values are kept for the life of the process (the set only grows, as the
//! telemetry it serves does).

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IStr(Arc<str>);

fn pool() -> &'static Mutex<HashSet<Arc<str>>> {
    static POOL: OnceLock<Mutex<HashSet<Arc<str>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashSet::new()))
}

impl IStr {
    pub fn new(s: &str) -> Self {
        let mut p = pool().lock().unwrap();
        if let Some(a) = p.get(s) {
            return IStr(Arc::clone(a));
        }
        let a: Arc<str> = Arc::from(s);
        p.insert(Arc::clone(&a));
        IStr(a)
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
    fn equal_values_share_one_copy_and_json_is_unchanged() {
        let a = IStr::new("malicious");
        let b: IStr = serde_json::from_str("\"malicious\"").unwrap();
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"malicious\"");
        assert!(a == "malicious" && "malicious" == a && a == "malicious".to_string());
        let esc: IStr = serde_json::from_str("\"C:\\\\Users\"").unwrap();
        assert_eq!(esc.as_str(), "C:\\Users");
    }
}
