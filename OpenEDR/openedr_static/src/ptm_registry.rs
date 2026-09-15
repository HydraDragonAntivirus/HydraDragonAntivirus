use std::path::Path;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
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

/// Wildcard pattern matcher supporting YAML rule definitions and legacy ptm.local.src
#[derive(Debug, Clone, Default)]
pub struct PuaRegistryMatcher {
    patterns: Vec<String>,
}

impl PuaRegistryMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        let normalized = patterns
            .into_iter()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect();
        Self { patterns: normalized }
    }

    /// Load from a YAML file (`registry_rules.yaml` / `registry_rules.yml`) or fallback to `ptm.local.src`
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }

        if path.is_dir() {
            return Self::load_from_dir(path);
        }

        Self::load_from_file(path)
    }

    /// Load from a specific file (YAML or fallback PTM)
    pub fn load_from_file(path: &Path) -> Self {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if ext == "yaml" || ext == "yml" {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(rule_file) = serde_yaml::from_str::<RegistryRuleFile>(&content) {
                    let mut pats = rule_file.pua_reg_paths;
                    pats.extend(rule_file.persistence_paths);
                    pats.extend(rule_file.suspicious_keys);
                    return Self::new(pats);
                }
                // Also support plain list in YAML: - "pattern"
                if let Ok(list) = serde_yaml::from_str::<Vec<String>>(&content) {
                    return Self::new(list);
                }
            }
        }

        // Fallback: parse as ptm.local.src
        if let Ok(content) = std::fs::read_to_string(path) {
            return Self::parse_ptm_content(&content);
        }

        Self::default()
    }

    /// Load all `.yaml`/`.yml` registry rules in a directory
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut patterns = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                    if ext == "yaml" || ext == "yml" {
                        let sub = Self::load_from_file(&p);
                        patterns.extend(sub.patterns);
                    }
                }
            }
        }
        Self::new(patterns)
    }

    /// Backward-compatible parser for legacy ptm.local.src if provided
    pub fn parse_ptm_content(content: &str) -> Self {
        let mut patterns = Vec::new();
        if let Some(start_idx) = content.find("\"puaRegPaths\":") {
            let slice = &content[start_idx..];
            if let Some(arr_start) = slice.find('[') {
                if let Some(arr_end) = slice[arr_start..].find(']') {
                    let array_text = &slice[arr_start..arr_start + arr_end + 1];
                    let mut clean_json = String::new();
                    for line in array_text.lines() {
                        let line_trim = line.trim();
                        if line_trim.starts_with("//") {
                            continue;
                        }
                        if let Some(idx) = line.find("//") {
                            clean_json.push_str(&line[..idx]);
                        } else {
                            clean_json.push_str(line);
                        }
                        clean_json.push('\n');
                    }

                    if let Ok(arr) = serde_json::from_str::<Vec<String>>(&clean_json) {
                        patterns = arr;
                    }
                }
            }
        }

        Self::new(patterns)
    }

    /// Checks if a registry path matches any configured registry rule pattern.
    pub fn matches(&self, reg_path: &str) -> Vec<String> {
        if self.patterns.is_empty() || reg_path.is_empty() {
            return Vec::new();
        }

        let query = reg_path.to_lowercase().replace('/', "\\");
        let mut hits = Vec::new();

        for pat in &self.patterns {
            if wildcard_match(pat, &query) {
                hits.push(pat.clone());
            }
        }

        hits
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Matches glob wildcard patterns like `*software\classes\*` against target text.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.trim_matches('*');
    if pattern.starts_with('*') && pattern.ends_with('*') {
        text.contains(pat)
    } else if pattern.starts_with('*') {
        text.ends_with(pat)
    } else if pattern.ends_with('*') {
        text.starts_with(pat)
    } else {
        text == pat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_matcher() {
        let yaml = r#"
name: PUA Registry Indicators
pua_reg_paths:
  - "*software\\classes\\appid\\abengine.exe*"
  - "*clsid\\{0a0ddbd3-6641-40b9-873f-bbdd26d6c14e}*"
persistence_paths:
  - "*software\\microsoft\\windows\\currentversion\\run\\malware*"
"#;
        let rule_file: RegistryRuleFile = serde_yaml::from_str(yaml).unwrap();
        let mut pats = rule_file.pua_reg_paths;
        pats.extend(rule_file.persistence_paths);
        let matcher = PuaRegistryMatcher::new(pats);

        assert_eq!(
            matcher.matches(r"HKLM\SOFTWARE\Classes\AppID\abengine.exe\val").len(),
            1
        );
        assert_eq!(
            matcher.matches(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\malware").len(),
            1
        );
    }
}
