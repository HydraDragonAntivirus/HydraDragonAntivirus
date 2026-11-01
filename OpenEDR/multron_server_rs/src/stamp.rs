//! Timestamps of the telemetry kept in memory.
//!
//! `threat_insights.jsonl` holds two RFC 3339 times per file and two per sighting,
//! written by `Utc::now().to_rfc3339()` ("2026-10-09T15:51:33.443392800+00:00"). As a
//! `String` each took 24 B inline plus ~51 B of heap; a `Stamp` keeps the instant as
//! nanoseconds (16 B, no heap). A text is stored that way only when formatting the
//! instant back gives exactly the same text; anything else (another offset or digit
//! count, a placeholder) stays as it was, so no value ever changes on disk or in JSON.

use std::cmp::Ordering;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::istr::IStr;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Stamp {
    /// Nanoseconds since 1970 (UTC); formats back to the text it was read from.
    Utc(i64),
    /// A text that does not round-trip through `Utc`.
    Raw(IStr),
}

fn format_nanos(n: i64) -> String {
    DateTime::<Utc>::from_timestamp_nanos(n).to_rfc3339()
}

impl Stamp {
    pub fn new(s: &str) -> Self {
        if let Some(n) = DateTime::parse_from_rfc3339(s).ok().and_then(|d| d.timestamp_nanos_opt()) {
            if format_nanos(n) == s {
                return Stamp::Utc(n);
            }
        }
        Stamp::Raw(IStr::new(s))
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Stamp::Raw(s) if s.is_empty())
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        match self {
            Stamp::Raw(s) => s.starts_with(prefix),
            Stamp::Utc(n) => format_nanos(*n).starts_with(prefix),
        }
    }
}

impl Default for Stamp {
    fn default() -> Self {
        Stamp::Raw(IStr::default())
    }
}

/// Two times in the `Utc` form compare as instants (the text they came from sorted the
/// same way); otherwise as text, as the `String`s did.
impl Ord for Stamp {
    fn cmp(&self, o: &Self) -> Ordering {
        match (self, o) {
            (Stamp::Utc(a), Stamp::Utc(b)) => a.cmp(b),
            _ => self.to_string().cmp(&o.to_string()),
        }
    }
}

impl PartialOrd for Stamp {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stamp::Utc(n) => f.write_str(&format_nanos(*n)),
            Stamp::Raw(s) => f.write_str(s),
        }
    }
}

impl fmt::Debug for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.to_string(), f)
    }
}

impl From<&str> for Stamp {
    fn from(s: &str) -> Self {
        Stamp::new(s)
    }
}

impl From<String> for Stamp {
    fn from(s: String) -> Self {
        Stamp::new(&s)
    }
}

impl PartialEq<&str> for Stamp {
    fn eq(&self, o: &&str) -> bool {
        self.to_string() == *o
    }
}

impl Serialize for Stamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Stamp::Utc(n) => s.serialize_str(&format_nanos(*n)),
            Stamp::Raw(t) => s.serialize_str(t),
        }
    }
}

impl<'de> Deserialize<'de> for Stamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Stamp;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a time string")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Stamp, E> {
                Ok(Stamp::new(s))
            }
        }
        d.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_text_and_orders_by_time() {
        for t in ["2026-10-09T15:51:33.443392800+00:00", "2026-10-09T15:51:33.485502+00:00", "2026-10-10T13:21:46.607+00:00", "2026-10-10T13:21:46+00:00"] {
            let s = Stamp::new(t);
            assert!(matches!(s, Stamp::Utc(_)), "{t}");
            assert_eq!(s.to_string(), t);
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{t}\""));
        }
        // Not the to_rfc3339 form: kept as text, unchanged.
        for t in ["2026-10-09T15:51:33Z", "2026-10-09T18:51:33.400+03:00", "t2", ""] {
            let s: Stamp = serde_json::from_str(&format!("\"{t}\"")).unwrap();
            assert!(matches!(s, Stamp::Raw(_)), "{t}");
            assert_eq!(s.to_string(), t);
        }
        assert!(Stamp::new("2026-10-09T15:51:33.485502+00:00") < Stamp::new("2026-10-09T15:51:33.5+00:00".replace(".5", ".500001").as_str()));
        assert!(Stamp::new("2026-10-09T15:51:33.443392800+00:00").starts_with("2026-10-09"));
        assert!(Stamp::new("").is_empty() && !Stamp::new("2026-10-10T13:21:46+00:00").is_empty());
        assert_eq!(std::mem::size_of::<Stamp>(), 16);
    }
}
