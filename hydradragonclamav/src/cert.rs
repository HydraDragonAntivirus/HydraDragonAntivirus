//! ClamAV certificate trust/block rules (`.crb`), ported from `cli_loadcrt`
//! (readdb.c:3323) and the `cli_crt` model.
//!
//! Each `.crb` line is a `;`-separated Authenticode certificate record:
//! ```text
//! name;trusted;subject;serial;pubkey;exp;codesign;timesign;certsign;notbefore;comment[;minFL[;maxFL]]
//! ```
//! ClamAV uses these during PE Authenticode verification: a PE whose signing
//! certificate chains to a **trusted** entry is allow-listed, and one chaining to
//! a **blocked** entry is detected. `name`/`comment` are end-user labels; the
//! exponent is ignored (hardcoded to 65537).
//!
//! **This module implements the loader faithfully** — every record is parsed and
//! stored byte-exactly (same `;`-tokenization, SHA-1 validation and f-level gating
//! as `cli_loadcrt`). The Authenticode *verification* engine (PKCS#7 parsing of a
//! PE's security directory + RSA signature/chain validation) is the separate heavy
//! follow-up; until then these certs are loaded and counted, not silently dropped.
//!
//! `.cat` Authenticode catalogs are binary PKCS#7 (`asn1_load_mscat`) and remain
//! deferred/counted — a different, binary parser from this text loader.

use crate::database::SourceLocation;

/// SHA-1 hash length in bytes (`SHA1_HASH_SIZE`).
const SHA1_LEN: usize = 20;

/// `name;trusted;subject;serial;pubkey;exp;codesign;timesign;certsign;notbefore;comment[;minFL[;maxFL]]`
/// — ClamAV `CRT_TOKENS`.
const CRT_TOKENS: usize = 13;

/// One certificate trust/block record (`cli_crt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertEntry {
    /// End-user label (`name`); kept for citation though ClamAV ignores it.
    pub name: String,
    /// `true` when the cert is blocked (`trusted == 0` → `isBlocked`).
    pub blocked: bool,
    /// SHA-1 of the certificate subject.
    pub subject: [u8; SHA1_LEN],
    /// SHA-1 of the serial, or `None` when the field was empty (`ignore_serial`).
    pub serial: Option<[u8; SHA1_LEN]>,
    /// RSA public-key modulus bytes (`pubkey`).
    pub pubkey: Vec<u8>,
    pub code_sign: bool,
    pub time_sign: bool,
    pub cert_sign: bool,
    /// `notbefore` validity epoch, if specified.
    pub not_before: Option<i64>,
    pub source: SourceLocation,
}

/// Loaded `.crb` certificate trust/block database (`crtmgr`).
#[derive(Debug, Default)]
pub struct CertTrustDb {
    pub certs: Vec<CertEntry>,
}

impl CertTrustDb {
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Parse and store one `.crb` line. Returns `Ok(true)` if added, `Ok(false)`
    /// if skipped by functionality-level gating, or `Err` if malformed. `flevel`
    /// is the engine functionality level (`cl_retflevel`).
    pub fn add_line(
        &mut self,
        line: &str,
        source: SourceLocation,
        flevel: u32,
    ) -> Result<bool, String> {
        let tokens: Vec<&str> = line.split(';').collect();
        // ClamAV accepts CRT_TOKENS-2 ..= CRT_TOKENS fields.
        if tokens.len() < CRT_TOKENS - 2 || tokens.len() > CRT_TOKENS {
            return Err(format!("invalid number of tokens: {}", tokens.len()));
        }

        // Optional functionality-level gating (minFL at CRT_TOKENS-2, maxFL last).
        if tokens.len() > CRT_TOKENS - 2 {
            let min_fl = tokens[CRT_TOKENS - 2]
                .trim()
                .parse::<u32>()
                .map_err(|_| "invalid minimum feature level".to_string())?;
            if min_fl > flevel {
                return Ok(false);
            }
            if tokens.len() == CRT_TOKENS {
                let max_fl = tokens[CRT_TOKENS - 1]
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| "invalid maximum feature level".to_string())?;
                if max_fl < flevel {
                    return Ok(false);
                }
            }
        }

        let blocked = match tokens[1] {
            "1" => false, // trusted
            "0" => true,  // blocked
            _ => return Err("invalid trust specification (expected 0 or 1)".to_string()),
        };

        let subject = parse_sha1(tokens[2], "subject")?;
        let serial = if tokens[3].is_empty() {
            None
        } else {
            Some(parse_sha1(tokens[3], "serial")?)
        };
        let pubkey = hex_bytes(tokens[4]).map_err(|_| "cannot convert public key".to_string())?;

        let code_sign = parse_bool(tokens[6], "code sign")?;
        let time_sign = parse_bool(tokens[7], "time sign")?;
        let cert_sign = parse_bool(tokens[8], "cert sign")?;
        let not_before = match tokens.get(9).map(|s| s.trim()).unwrap_or("") {
            "" => None,
            s => Some(s.parse::<i64>().map_err(|_| "invalid notbefore".to_string())?),
        };

        self.certs.push(CertEntry {
            name: tokens[0].to_string(),
            blocked,
            subject,
            serial,
            pubkey,
            code_sign,
            time_sign,
            cert_sign,
            not_before,
            source,
        });
        Ok(true)
    }
}

/// A `0`/`1` Authenticode flag field.
fn parse_bool(tok: &str, what: &str) -> Result<bool, String> {
    match tok {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(format!("invalid {what} specification (expected 0 or 1)")),
    }
}

/// Parse a 40-char (20-byte) ASCII SHA-1, validating length like `set_sha1`.
fn parse_sha1(token: &str, what: &str) -> Result<[u8; SHA1_LEN], String> {
    if token.len() != 2 * SHA1_LEN {
        return Err(format!("{what} is not the appropriate length for a SHA1 Hash"));
    }
    let bytes = hex_bytes(token).map_err(|_| format!("cannot convert {what} to binary"))?;
    let mut out = [0u8; SHA1_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode an even-length ASCII hex string to bytes.
fn hex_bytes(s: &str) -> Result<Vec<u8>, ()> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).ok_or(())?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or(())?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn src() -> SourceLocation {
        SourceLocation {
            path: Arc::from(PathBuf::from("daily.crb").as_path()),
            line: 1,
        }
    }

    // A blocked cert (trusted=0) from daily.crb, trimmed pubkey for brevity.
    const BLOCKED: &str = "25f222ab-1;0;4a532974c46ae5048824c6da8cfb8e163705b693;1d80f656104b69a763a5d40db6abe01546b88861;ABCD;010001;1;0;0;;aeroscantov_sample";
    // A trusted CA with empty serial (ignore_serial).
    const TRUSTED: &str = "Trusted.CA-1;1;9a02278e9cb12876c47ab0bc75dd694e72d1b2bc;;00d62b;010001;0;1;1;;";

    #[test]
    fn parses_blocked_cert() {
        let mut db = CertTrustDb::default();
        assert_eq!(db.add_line(BLOCKED, src(), 100).unwrap(), true);
        let c = &db.certs[0];
        assert!(c.blocked);
        assert_eq!(c.subject[0], 0x4a);
        assert!(c.serial.is_some());
        assert!(c.code_sign && !c.time_sign && !c.cert_sign);
    }

    #[test]
    fn parses_trusted_cert_with_empty_serial() {
        let mut db = CertTrustDb::default();
        assert!(db.add_line(TRUSTED, src(), 100).unwrap());
        let c = &db.certs[0];
        assert!(!c.blocked); // trusted
        assert_eq!(c.serial, None); // ignore_serial
        assert!(!c.code_sign && c.time_sign && c.cert_sign);
    }

    #[test]
    fn flevel_gates_min() {
        // minFL field present (12 tokens) and above engine flevel → skipped.
        let line = format!("{BLOCKED};999");
        let mut db = CertTrustDb::default();
        assert_eq!(db.add_line(&line, src(), 100).unwrap(), false);
        assert!(db.is_empty());
    }

    #[test]
    fn rejects_bad_trust_flag() {
        let bad = BLOCKED.replacen(";0;", ";9;", 1);
        let mut db = CertTrustDb::default();
        assert!(db.add_line(&bad, src(), 100).is_err());
    }

    #[test]
    fn rejects_bad_subject_length() {
        let bad = "n;1;abcd;;00;010001;1;1;1;;";
        let mut db = CertTrustDb::default();
        assert!(db.add_line(bad, src(), 100).is_err());
    }
}
