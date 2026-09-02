//! Trusted Signers YAML rule parser and matcher for Owlyshield/OpenEDR.
//!
//! Loads `trusted_signers.yaml` (Yamdle format) without requiring hydradragonsig,
//! caching the parsed signer patterns in memory for high-performance zero-allocation matching.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TrustedSignersFile {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub rules: Vec<TrustedSignerRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustedSignerRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub conditions: Vec<SignerCondition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerCondition {
    #[serde(rename = "type")]
    pub cond_type: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub nocase: bool,
}

#[derive(Debug, Clone)]
pub struct SignerPattern {
    pub value: String,
    pub nocase: bool,
    pub is_exact: bool,
}

pub struct SignerRuleMatcher {
    patterns: Vec<SignerPattern>,
}

pub type TrustedSignerMatcher = SignerRuleMatcher;

impl SignerRuleMatcher {
    /// Create an empty matcher.
    pub fn empty() -> Self {
        Self { patterns: Vec::new() }
    }

    /// Load from YAML string.
    pub fn from_yaml_str(yaml_content: &str) -> Result<Self, serde_yaml::Error> {
        let file: TrustedSignersFile = serde_yaml::from_str(yaml_content)?;
        let mut patterns = Vec::new();

        for rule in file.rules {
            for cond in rule.conditions {
                if (cond.cond_type == "signature_signer_contains" || cond.cond_type == "signature_signer_equals")
                    && !cond.value.is_empty()
                {
                    let is_exact = cond.cond_type == "signature_signer_equals";
                    let pattern = if cond.nocase {
                        cond.value.to_lowercase()
                    } else {
                        cond.value
                    };
                    patterns.push(SignerPattern {
                        value: pattern,
                        nocase: cond.nocase,
                        is_exact,
                    });
                }
            }
        }

        Ok(Self { patterns })
    }

    /// Load from file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let matcher = Self::from_yaml_str(&content)?;
        Ok(matcher)
    }

    /// Check if the given signer name matches any rule pattern.
    pub fn matches(&self, signer_name: &str) -> bool {
        if self.patterns.is_empty() || signer_name.is_empty() {
            return false;
        }

        let signer_lower = signer_name.to_lowercase();

        for pattern in &self.patterns {
            if pattern.is_exact {
                if pattern.nocase {
                    if signer_lower == pattern.value {
                        return true;
                    }
                } else {
                    if signer_name == pattern.value {
                        return true;
                    }
                }
            } else {
                if pattern.nocase {
                    if signer_lower.contains(&pattern.value) {
                        return true;
                    }
                } else {
                    if signer_name.contains(&pattern.value) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if the given signer name matches (alias for matches).
    pub fn is_trusted(&self, signer_name: &str) -> bool {
        self.matches(signer_name)
    }

    pub fn count(&self) -> usize {
        self.patterns.len()
    }
}

static TRUSTED_MATCHER: OnceLock<SignerRuleMatcher> = OnceLock::new();
static MALICIOUS_MATCHER: OnceLock<SignerRuleMatcher> = OnceLock::new();
static PUA_MATCHER: OnceLock<SignerRuleMatcher> = OnceLock::new();

/// Resolve the single canonical path to a vendor rule YAML file.
pub fn resolve_rule_file_path(filename: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK") {
            if let Ok(p) = key.get_value::<String, _>("TRUSTED_SIGNERS_PATH") {
                let path = PathBuf::from(p).join(filename);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }

    let canonical_path = PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\trusted_signer_rules").join(filename);
    if canonical_path.is_file() {
        return Some(canonical_path);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let relative_path = exe_dir.join("trusted_signer_rules").join(filename);
            if relative_path.is_file() {
                return Some(relative_path);
            }
        }
    }

    Some(canonical_path)
}

/// Resolve the single canonical path to `trusted_signers.yaml`.
pub fn resolve_trusted_signers_path() -> Option<PathBuf> {
    resolve_rule_file_path("trusted_signers.yaml")
}

fn load_matcher_or_empty(filename: &str, log_prefix: &str) -> SignerRuleMatcher {
    if let Some(path) = resolve_rule_file_path(filename) {
        crate::Logging::info(&format!("[{}] Loading rules from: {}", log_prefix, path.display()));
        match SignerRuleMatcher::from_file(&path) {
            Ok(m) => {
                crate::Logging::info(&format!(
                    "[{}] Loaded {} signer patterns from {}",
                    log_prefix, m.count(), path.display()
                ));
                return m;
            }
            Err(e) => {
                crate::Logging::error(&format!(
                    "[{}] Failed to parse YAML from {}: {}",
                    log_prefix, path.display(), e
                ));
            }
        }
    } else {
        crate::Logging::warning(&format!("[{}] No {} file found in search paths", log_prefix, filename));
    }
    SignerRuleMatcher::empty()
}

/// Global accessor for the trusted signers matcher (cached via OnceLock).
pub fn trusted_matcher() -> &'static SignerRuleMatcher {
    TRUSTED_MATCHER.get_or_init(|| load_matcher_or_empty("trusted_signers.yaml", "TrustedSigners"))
}

/// Global accessor for backward compatibility.
pub fn global_matcher() -> &'static SignerRuleMatcher {
    trusted_matcher()
}

/// Global accessor for malicious vendors matcher.
pub fn malicious_matcher() -> &'static SignerRuleMatcher {
    MALICIOUS_MATCHER.get_or_init(|| load_matcher_or_empty("malicious_vendors.yaml", "MaliciousVendors"))
}

/// Global accessor for PUA vendors matcher.
pub fn pua_matcher() -> &'static SignerRuleMatcher {
    PUA_MATCHER.get_or_init(|| load_matcher_or_empty("pua_vendors.yaml", "PuaVendors"))
}

/// Check if a signer is known malicious from `malicious_vendors.yaml`.
pub fn is_malicious_vendor(signer_name: &str) -> bool {
    malicious_matcher().matches(signer_name)
}

/// Check if a signer is known PUA/adware from `pua_vendors.yaml`.
pub fn is_pua_vendor(signer_name: &str) -> bool {
    pua_matcher().matches(signer_name)
}

/// Check if a signer string is trusted according to `trusted_signers.yaml`.
/// If the signer matches malicious vendors or PUA vendors, it is strictly NOT trusted.
pub fn is_trusted_signer(signer_name: &str) -> bool {
    if is_malicious_vendor(signer_name) || is_pua_vendor(signer_name) {
        return false;
    }
    trusted_matcher().matches(signer_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_parsing_and_matching() {
        let yaml_sample = r#"
name: Test Rules
version: "1"
rules:
  - id: test-001
    title: Test Rule
    conditions:
      - type: signature_signer_contains
        value: "Microsoft Corporation"
        nocase: true
      - type: signature_signer_contains
        value: "Google Inc."
        nocase: true
"#;
        let matcher = SignerRuleMatcher::from_yaml_str(yaml_sample).unwrap();
        assert_eq!(matcher.count(), 2);
        assert!(matcher.matches("Microsoft Corporation"));
        assert!(matcher.matches("CN=microsoft corporation, O=Microsoft Corporation"));
        assert!(matcher.matches("Google Inc."));
        assert!(!matcher.matches("Malicious Hacker Ltd"));
    }
}
