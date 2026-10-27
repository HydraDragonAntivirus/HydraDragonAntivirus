//! Domain / IP threat-intel blocklists (`xorfilter_rules/<list>.xf`), built from the
//! `hydradragon/website` lists by `OpenEDR/scripts/build_all_threat_intel.py`.
//!
//! Only BinaryFuse32 files are accepted: a false match in a blocklist flags a clean
//! site, and BinaryFuse16 gives one in 65 536 lookups (one in ~4.3 billion for BF32).
//! A BF16 file under one of these names is ignored and logged.
//!
//! The caller asks only for hosts that are not whitelisted (Tranco 1M, CIDR
//! whitelist): a popular site never turns malicious through a list entry. CDN address
//! space is already left out of the IP list at build time.

use std::path::Path;

use crate::signers::BinaryFuse32Filter;

/// (file stem, category shown in the detection, severity). Phishing and malware
/// lists convict; the noisier ones (abuse, spam, mining, mail, the IP list that also
/// holds spam / brute-force senders) only make a URL suspicious.
pub const LISTS: [(&str, &str, &str); 7] = [
    ("phishing", "Phishing", "Malicious"),
    ("malware", "Malware", "Malicious"),
    ("abuse", "Abuse", "Suspicious"),
    ("mining", "Mining", "Suspicious"),
    ("spam", "Spam", "Suspicious"),
    ("malicious_mail", "MaliciousMail", "Suspicious"),
    ("ipmalware", "MaliciousIP", "Suspicious"),
];

struct IntelList {
    category: &'static str,
    severity: &'static str,
    filter: BinaryFuse32Filter,
}

#[derive(Default)]
pub struct DomainIntel {
    lists: Vec<IntelList>,
}

/// A host found on a list: the category, its severity and the listed name (the host
/// itself or a parent domain).
#[derive(Debug, Clone, PartialEq)]
pub struct IntelHit {
    pub category: &'static str,
    pub severity: &'static str,
    pub listed: String,
}

impl DomainIntel {
    /// Loads every list of `LISTS` present in `dir`; returns the engine and a log line.
    pub fn load_from_dir(dir: &Path) -> (Self, String) {
        let mut lists = Vec::new();
        let mut log = Vec::new();
        for (stem, category, severity) in LISTS {
            let Ok(bytes) = std::fs::read(dir.join(format!("{stem}.xf"))) else { continue };
            match BinaryFuse32Filter::from_bytes(&bytes) {
                Some(filter) => {
                    log.push(format!("{stem}={}", filter.len()));
                    lists.push(IntelList { category, severity, filter });
                }
                None => log.push(format!("{stem}=rejected (not BinaryFuse32)")),
            }
        }
        // Convicting lists first: a host on both a phishing and a spam list is phishing.
        lists.sort_by_key(|l| l.severity != "Malicious");
        let line = if log.is_empty() { "absent".to_string() } else { log.join(", ") };
        (Self { lists }, line)
    }

    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }

    /// The first list holding `host` (lower case, no trailing dot). A domain also
    /// matches through its parents (`a.evil.example` through `evil.example`), never
    /// through a bare TLD; an IP address matches only itself.
    pub fn lookup(&self, host: &str) -> Option<IntelHit> {
        if self.lists.is_empty() || host.is_empty() {
            return None;
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let names: Vec<String> = if bare.parse::<std::net::IpAddr>().is_ok() {
            vec![bare.to_string()]
        } else {
            let parts: Vec<&str> = host.split('.').collect();
            (0..parts.len().saturating_sub(1)).map(|i| parts[i..].join(".")).collect()
        };
        for l in &self.lists {
            if let Some(n) = names.iter().find(|n| l.filter.contains(n)) {
                return Some(IntelHit { category: l.category, severity: l.severity, listed: n.clone() });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tests/data/domain_intel: phishing.xf (BF32: evil-login.example, 203.0.113.7),
    /// spam.xf (BF32: spammy.example, evil-login.example), malware.xf (BF16: rejected).
    #[test]
    fn lists_parents_severity_and_bf16_rejected() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("data").join("domain_intel");
        let (intel, line) = DomainIntel::load_from_dir(&dir);
        assert!(line.contains("malware=rejected"), "{line}");

        let hit = intel.lookup("evil-login.example").unwrap();
        assert_eq!((hit.category, hit.severity), ("Phishing", "Malicious"), "phishing wins over spam");
        let hit = intel.lookup("www.evil-login.example").unwrap();
        assert_eq!(hit.listed, "evil-login.example", "matched through the parent");
        assert_eq!(intel.lookup("spammy.example").unwrap().severity, "Suspicious");
        assert_eq!(intel.lookup("203.0.113.7").unwrap().category, "Phishing");

        assert_eq!(intel.lookup("payload.example"), None, "BF16 list is not used");
        assert_eq!(intel.lookup("example"), None, "never through a bare TLD");
        assert_eq!(intel.lookup("203.0.113.8"), None);
        assert_eq!(intel.lookup("clean.example"), None);
    }
}
