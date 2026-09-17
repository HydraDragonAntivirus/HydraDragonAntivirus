//! PE-embedded registry/persistence indicator rules (web edition).
//!
//! The desktop `check_registry` API (registry path -> PUA verdict) has no
//! meaning in a browser: there is no registry to query. Instead the SAME
//! rule patterns (`pua_reg_paths` / `persistence_paths` / `suspicious_keys`
//! from `registry_rules/*.yaml`) are scanned as **strings inside PE files**:
//! malware droppers commonly carry their autostart keys, CLSIDs and service
//! names as plaintext. Semantics mirror `ptm_registry::wildcard_match`
//! exactly (core `*...*` containment on lowercased, slash-normalized text).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegistryRuleFile {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub pua_reg_paths: Vec<String>,
    #[serde(default)]
    pub persistence_paths: Vec<String>,
    #[serde(default)]
    pub suspicious_keys: Vec<String>,
}

/// A single string-rule hit: the rule pattern plus a sample of matched text.
#[derive(Debug, Clone)]
pub struct StringHit {
    pub pattern: String,
    pub sample: String,
}

#[derive(Debug, Clone, Default)]
pub struct PeStringRules {
    patterns: Vec<String>,
}

impl PeStringRules {
    pub fn new(patterns: Vec<String>) -> Self {
        let normalized = patterns
            .into_iter()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect();
        Self {
            patterns: normalized,
        }
    }

    /// Load from a YAML rules document (same schema as desktop
    /// `registry_rules/*.yaml`). Returns the pattern count, or -1 on error.
    pub fn load_yaml(&mut self, yaml: &str) -> i32 {
        let mut pats = match serde_yaml::from_str::<RegistryRuleFile>(yaml) {
            Ok(f) => {
                let mut v = f.pua_reg_paths;
                v.extend(f.persistence_paths);
                v.extend(f.suspicious_keys);
                v
            }
            Err(_) => match serde_yaml::from_str::<Vec<String>>(yaml) {
                Ok(list) => list,
                Err(_) => return -1,
            },
        };
        let mut all = std::mem::take(&mut self.patterns);
        all.append(&mut pats);
        *self = Self::new(all);
        self.patterns.len() as i32
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Scan lowercased PE strings. At most `cap` hits, in rule order.
    pub fn scan(&self, strings: &[String], cap: usize) -> Vec<StringHit> {
        let mut hits = Vec::new();
        if self.patterns.is_empty() || strings.is_empty() || cap == 0 {
            return hits;
        }
        'rules: for pat in &self.patterns {
            let core = pat.trim_matches('*');
            if core.len() < 4 {
                continue;
            }
            for s in strings {
                let hit = if pat.starts_with('*') && pat.ends_with('*') {
                    s.contains(core)
                } else if pat.starts_with('*') {
                    s.ends_with(core)
                } else if pat.ends_with('*') {
                    s.starts_with(core)
                } else {
                    s.as_str() == core
                };
                if hit {
                    hits.push(StringHit {
                        pattern: pat.clone(),
                        sample: truncate(s, 96),
                    });
                    if hits.len() >= cap {
                        break 'rules;
                    }
                    break;
                }
            }
        }
        hits
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Normalize a raw binary string the way the desktop matcher normalizes
/// registry queries: lowercase + forward slashes to backslashes.
pub fn normalize_text(s: &str) -> String {
    s.to_lowercase().replace('/', "\\")
}
