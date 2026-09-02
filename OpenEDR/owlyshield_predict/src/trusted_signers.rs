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
}

pub struct TrustedSignerMatcher {
    patterns: Vec<SignerPattern>,
}

impl TrustedSignerMatcher {
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
                if cond.cond_type == "signature_signer_contains" && !cond.value.is_empty() {
                    let pattern = if cond.nocase {
                        cond.value.to_lowercase()
                    } else {
                        cond.value
                    };
                    patterns.push(SignerPattern {
                        value: pattern,
                        nocase: cond.nocase,
                    });
                }
            }
        }

        crate::Logging::info(&format!(
            "[TrustedSigners] Loaded {} signer patterns from YAML",
            patterns.len()
        ));

        Ok(Self { patterns })
    }

    /// Load from file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let matcher = Self::from_yaml_str(&content)?;
        Ok(matcher)
    }

    /// Check if the given signer name matches any trusted signer rule.
    pub fn is_trusted(&self, signer_name: &str) -> bool {
        if self.patterns.is_empty() || signer_name.is_empty() {
            return false;
        }

        let signer_lower = signer_name.to_lowercase();

        for pattern in &self.patterns {
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

        false
    }

    pub fn count(&self) -> usize {
        self.patterns.len()
    }
}

static MATCHER: OnceLock<TrustedSignerMatcher> = OnceLock::new();

/// Resolve the single canonical path to `trusted_signers.yaml`.
pub fn resolve_trusted_signers_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK") {
            if let Ok(p) = key.get_value::<String, _>("TRUSTED_SIGNERS_PATH") {
                let path = PathBuf::from(p).join("trusted_signers.yaml");
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }

    let canonical_path = PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\trusted_signer_rules\trusted_signers.yaml");
    if canonical_path.is_file() {
        return Some(canonical_path);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let relative_path = exe_dir.join("trusted_signer_rules").join("trusted_signers.yaml");
            if relative_path.is_file() {
                return Some(relative_path);
            }
        }
    }

    Some(canonical_path)
}

/// Global accessor for the trusted signers matcher (cached via OnceLock).
pub fn global_matcher() -> &'static TrustedSignerMatcher {
    MATCHER.get_or_init(|| {
        if let Some(path) = resolve_trusted_signers_path() {
            crate::Logging::info(&format!("[TrustedSigners] Loading rules from: {}", path.display()));
            match TrustedSignerMatcher::from_file(&path) {
                Ok(m) => return m,
                Err(e) => {
                    crate::Logging::error(&format!(
                        "[TrustedSigners] Failed to parse YAML from {}: {}",
                        path.display(), e
                    ));
                }
            }
        } else {
            crate::Logging::warning("[TrustedSigners] No trusted_signers.yaml file found in search paths");
        }
        TrustedSignerMatcher::empty()
    })
}

/// Check if a signer string is trusted according to `trusted_signers.yaml`.
pub fn is_trusted_signer(signer_name: &str) -> bool {
    global_matcher().is_trusted(signer_name)
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
        let matcher = TrustedSignerMatcher::from_yaml_str(yaml_sample).unwrap();
        assert_eq!(matcher.count(), 2);
        assert!(matcher.is_trusted("Microsoft Corporation"));
        assert!(matcher.is_trusted("CN=microsoft corporation, O=Microsoft Corporation"));
        assert!(matcher.is_trusted("Google Inc."));
        assert!(!matcher.is_trusted("Malicious Hacker Ltd"));
    }
}
