//! The SHA-256 of a telemetry entry, kept as its 32 bytes.
//!
//! Every entry carried its hash twice: as the map key (`[u8; 32]`) and as 64 hex
//! characters (`String`: 24 B inline + ~80 B of heap). A `HexSha` keeps the bytes and
//! whether the text was lower or upper case, and writes the same text back; a value that
//! is not 64 hex digits of one case stays as it was, so the file never changes.
//! `text()` gives the hex on the stack, usable wherever a `&str` is wanted.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::istr::IStr;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum HexSha {
    Lower([u8; 32]),
    Upper([u8; 32]),
    /// Not 64 hex digits of one case: kept as text.
    Raw(IStr),
}

/// The hex text of a `HexSha`, on the stack (derefs to `&str`).
pub enum HexText {
    Hex([u8; 64]),
    Raw(IStr),
}

impl Deref for HexText {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            // Only ASCII hex digits are ever written into the buffer.
            HexText::Hex(b) => std::str::from_utf8(b).unwrap_or_default(),
            HexText::Raw(s) => s,
        }
    }
}

impl HexSha {
    pub fn new(s: &str) -> Self {
        let lower = s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let upper = s.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
        let mut bytes = [0u8; 32];
        if s.len() == 64 && (lower || upper) && hex::decode_to_slice(s, &mut bytes).is_ok() {
            return if lower { HexSha::Lower(bytes) } else { HexSha::Upper(bytes) };
        }
        HexSha::Raw(IStr::new(s))
    }

    pub fn text(&self) -> HexText {
        let (bytes, digits) = match self {
            HexSha::Lower(b) => (b, b"0123456789abcdef"),
            HexSha::Upper(b) => (b, b"0123456789ABCDEF"),
            HexSha::Raw(s) => return HexText::Raw(s.clone()),
        };
        let mut out = [0u8; 64];
        for (i, b) in bytes.iter().enumerate() {
            out[2 * i] = digits[(b >> 4) as usize];
            out[2 * i + 1] = digits[(b & 15) as usize];
        }
        HexText::Hex(out)
    }

    pub fn to_ascii_lowercase(&self) -> String {
        self.text().to_ascii_lowercase()
    }

    pub fn to_ascii_uppercase(&self) -> String {
        self.text().to_ascii_uppercase()
    }

    pub fn to_lowercase(&self) -> String {
        self.to_ascii_lowercase()
    }
}

impl Default for HexSha {
    fn default() -> Self {
        HexSha::Raw(IStr::default())
    }
}

impl fmt::Display for HexSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

impl fmt::Debug for HexSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.text(), f)
    }
}

impl From<&str> for HexSha {
    fn from(s: &str) -> Self {
        HexSha::new(s)
    }
}

impl From<String> for HexSha {
    fn from(s: String) -> Self {
        HexSha::new(&s)
    }
}

impl PartialEq<&str> for HexSha {
    fn eq(&self, o: &&str) -> bool {
        &*self.text() == *o
    }
}

impl Serialize for HexSha {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for HexSha {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = HexSha;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a SHA-256 string")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<HexSha, E> {
                Ok(HexSha::new(s))
            }
        }
        d.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_text_exactly() {
        let lo = "ab".repeat(32);
        let up = "CD".repeat(32);
        let mixed = format!("Ab{}", "ab".repeat(31));
        assert!(matches!(HexSha::new(&lo), HexSha::Lower(_)));
        assert!(matches!(HexSha::new(&up), HexSha::Upper(_)));
        for t in [lo.as_str(), up.as_str(), mixed.as_str(), "", "not a hash", &"a".repeat(63)] {
            let h: HexSha = serde_json::from_str(&format!("\"{t}\"")).unwrap();
            assert_eq!(&*h.text(), t);
            assert_eq!(serde_json::to_string(&h).unwrap(), format!("\"{t}\""));
        }
        assert!(matches!(HexSha::new(&mixed), HexSha::Raw(_)));
        assert_eq!(HexSha::new(&up).to_ascii_lowercase(), "cd".repeat(32));
        assert!(std::mem::size_of::<HexSha>() <= 40);
    }
}
