use std::path::Path;
use std::sync::Arc;
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
    /// Detailed form: patterns grouped under a rule that carries its own
    /// title/description, so a hit can say which rule fired. Optional and
    /// additive - the flat lists above keep loading exactly as before.
    #[serde(default)]
    pub rules: Vec<RegistryRuleDef>,
}

/// One rule of the detailed form. Every field defaults so a foreign document
/// that happens to have a `rules:` key (the PUM `registry_value` rules, say)
/// still parses here and simply contributes no patterns, as it did before
/// this field existed. Analyst documents are held to the strict shape by
/// [`validate_registry_rules_yaml`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistryRuleDef {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// `info` / `low` / `medium` / `high` / `critical`.
    #[serde(default)]
    pub severity: String,
    /// `pua` / `malware` / `suspicious`.
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub family: String,
    /// Glob patterns, same syntax as the flat lists (`*` at either end).
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Metadata of the detailed rule a pattern came from, shared by all of the
/// rule's patterns.
#[derive(Debug, Clone, Default)]
pub struct RegistryRuleMeta {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub verdict: String,
    pub family: Option<String>,
}

const REGISTRY_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];
const REGISTRY_VERDICTS: &[&str] = &["pua", "malware", "suspicious"];

/// Validate an analyst registry-rule document. The flat lists are accepted as
/// they are; every entry of `rules:` must have a non-empty `id` and `title`, a
/// `severity` of info|low|medium|high|critical, a `verdict` of
/// pua|malware|suspicious and at least one non-empty pattern. A document that
/// yields no pattern at all is an error, since it would load as a silent no-op.
///
/// Returns the number of patterns the document contributes.
pub fn validate_registry_rules_yaml(src: &str) -> Result<usize, String> {
    let file: RegistryRuleFile =
        serde_yaml::from_str(src).map_err(|e| format!("YAML parse error: {e}"))?;
    let mut seen = std::collections::HashSet::new();
    for (idx, rule) in file.rules.iter().enumerate() {
        let id = rule.id.trim();
        if id.is_empty() {
            return Err(format!("rule #{}: missing `id`", idx + 1));
        }
        if !seen.insert(id.to_string()) {
            return Err(format!("rule {id}: duplicate `id`"));
        }
        if rule.title.trim().is_empty() {
            return Err(format!("rule {id}: missing `title`"));
        }
        let sev = rule.severity.trim().to_ascii_lowercase();
        if !REGISTRY_SEVERITIES.contains(&sev.as_str()) {
            return Err(format!(
                "rule {id}: `severity` must be one of {}, got {:?}",
                REGISTRY_SEVERITIES.join("|"),
                rule.severity
            ));
        }
        let verdict = rule.verdict.trim().to_ascii_lowercase();
        if !REGISTRY_VERDICTS.contains(&verdict.as_str()) {
            return Err(format!(
                "rule {id}: `verdict` must be one of {}, got {:?}",
                REGISTRY_VERDICTS.join("|"),
                rule.verdict
            ));
        }
        if rule.patterns.is_empty() {
            return Err(format!("rule {id}: needs at least one pattern"));
        }
        if let Some(i) = rule.patterns.iter().position(|p| p.trim().is_empty()) {
            return Err(format!("rule {id}: pattern #{} is empty", i + 1));
        }
    }
    let count = PuaRegistryMatcher::from_rule_file(file).pattern_count();
    if count == 0 {
        return Err("document contains no registry patterns".to_string());
    }
    Ok(count)
}

/// Wildcard pattern matcher supporting YAML rule definitions and legacy ptm.local.src
#[derive(Debug, Clone, Default)]
pub struct PuaRegistryMatcher {
    patterns: Vec<String>,
    /// Parallel to `patterns`: the detailed rule each pattern came from, `None`
    /// for flat-list / ptm patterns. Kept as a side vector so `patterns()` stays
    /// the plain `&[String]` its callers already use.
    metas: Vec<Option<Arc<RegistryRuleMeta>>>,
}

impl PuaRegistryMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        let mut m = Self::default();
        for p in patterns {
            m.push(&p, None);
        }
        m
    }

    /// Normalize and add one pattern; empty patterns are dropped as `new` always did.
    fn push(&mut self, pattern: &str, meta: Option<Arc<RegistryRuleMeta>>) {
        let p = pattern.trim().to_lowercase();
        if !p.is_empty() {
            self.patterns.push(p);
            self.metas.push(meta);
        }
    }

    /// Flat lists first (the historical order), then the detailed rules.
    fn from_rule_file(rule_file: RegistryRuleFile) -> Self {
        let mut pats = rule_file.pua_reg_paths;
        pats.extend(rule_file.persistence_paths);
        pats.extend(rule_file.suspicious_keys);
        let mut m = Self::new(pats);
        for rule in rule_file.rules {
            let family = rule.family.trim();
            let meta = Arc::new(RegistryRuleMeta {
                id: rule.id.trim().to_string(),
                title: rule.title.trim().to_string(),
                description: rule.description.trim().to_string(),
                severity: rule.severity.trim().to_ascii_lowercase(),
                verdict: rule.verdict.trim().to_ascii_lowercase(),
                family: (!family.is_empty()).then(|| family.to_string()),
            });
            for p in &rule.patterns {
                m.push(p, Some(meta.clone()));
            }
        }
        m
    }

    /// Append everything `other` holds (patterns and their metadata).
    pub fn extend(&mut self, other: PuaRegistryMatcher) {
        self.patterns.extend(other.patterns);
        self.metas.extend(other.metas);
    }

    /// Validate an analyst document ([`validate_registry_rules_yaml`]) and
    /// append its patterns. All-or-nothing. Returns the pattern count added.
    pub fn add_rules_yaml(&mut self, src: &str) -> Result<usize, String> {
        validate_registry_rules_yaml(src)?;
        let file: RegistryRuleFile =
            serde_yaml::from_str(src).map_err(|e| format!("YAML parse error: {e}"))?;
        let added = Self::from_rule_file(file);
        let n = added.pattern_count();
        self.extend(added);
        Ok(n)
    }

    /// Metadata of the first detailed rule whose pattern matches `reg_path`.
    /// Flat-list patterns carry none and are skipped, so a flat hit earlier in
    /// the list does not hide a detailed rule that also matches.
    pub fn match_detail(&self, reg_path: &str) -> Option<Arc<RegistryRuleMeta>> {
        if self.patterns.is_empty() || reg_path.is_empty() {
            return None;
        }
        let query = reg_path.to_lowercase().replace('/', "\\");
        self.patterns
            .iter()
            .zip(&self.metas)
            .find_map(|(pat, meta)| match meta {
                Some(m) if wildcard_match(pat, &query) => Some(m.clone()),
                _ => None,
            })
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
                if let Some(m) = Self::from_yaml_str(&content) {
                    return m;
                }
            }
        }

        // Fallback: parse as ptm.local.src
        if let Ok(content) = std::fs::read_to_string(path) {
            return Self::parse_ptm_content(&content);
        }

        Self::default()
    }

    /// Parse one registry-rule YAML document: the rule-file mapping, or a plain
    /// list of patterns (`- "pattern"`). `None` when it is neither. Lenient
    /// (the shipped-file loader); analyst input goes through
    /// [`validate_registry_rules_yaml`].
    pub fn from_yaml_str(content: &str) -> Option<Self> {
        if let Ok(rule_file) = serde_yaml::from_str::<RegistryRuleFile>(content) {
            return Some(Self::from_rule_file(rule_file));
        }
        // Also support plain list in YAML: - "pattern"
        if let Ok(list) = serde_yaml::from_str::<Vec<String>>(content) {
            return Some(Self::new(list));
        }
        None
    }

    /// Load all `.yaml`/`.yml` registry rules in a directory
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut all = Self::default();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                    if ext == "yaml" || ext == "yml" {
                        all.extend(Self::load_from_file(&p));
                    }
                }
            }
        }
        all
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

    pub fn patterns(&self) -> &[String] {
        &self.patterns
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

    const DETAILED: &str = r#"
pua_reg_paths:
  - "*software\\flatpua*"
rules:
  - id: reg-1
    title: "Fake optimizer autorun"
    description: "Run key written by the FakeOpt installer"
    severity: high
    verdict: pua
    family: "PUA.FakeOpt"
    patterns:
      - "*currentversion\\run\\fakeopt*"
"#;

    #[test]
    fn validate_registry_rules_accepts_detailed_and_flat() {
        assert_eq!(validate_registry_rules_yaml(DETAILED), Ok(2));
    }

    #[test]
    fn validate_registry_rules_rejects_bad_rules() {
        let bad_sev = "rules:\n  - id: r1\n    title: T\n    severity: severe\n    verdict: pua\n    patterns: [\"*x*\"]\n";
        assert!(validate_registry_rules_yaml(bad_sev).unwrap_err().contains("severity"));
        let no_pat = "rules:\n  - id: r2\n    title: T\n    severity: low\n    verdict: malware\n    patterns: []\n";
        assert!(validate_registry_rules_yaml(no_pat).unwrap_err().contains("pattern"));
        let bad_verdict = "rules:\n  - id: r3\n    title: T\n    severity: low\n    verdict: trusted\n    patterns: [\"*x*\"]\n";
        assert!(validate_registry_rules_yaml(bad_verdict).unwrap_err().contains("verdict"));
        assert!(validate_registry_rules_yaml("name: empty\n").is_err());
    }

    #[test]
    fn add_rules_yaml_appends_with_detail() {
        let mut m = PuaRegistryMatcher::new(vec!["*software\\shipped*".to_string()]);
        assert_eq!(m.add_rules_yaml(DETAILED), Ok(2));
        assert_eq!(m.pattern_count(), 3);
        let path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\FakeOpt";
        assert_eq!(m.matches(path).len(), 1);
        let meta = m.match_detail(path).expect("detailed rule");
        assert_eq!(meta.title, "Fake optimizer autorun");
        assert!(m.match_detail(r"HKLM\Software\FlatPua").is_none(), "flat patterns carry no detail");
        assert!(!m.matches(r"HKLM\Software\Shipped\x").is_empty(), "shipped patterns kept");
    }

    #[test]
    fn shipped_pua_registry_rules_avoid_explorer_and_windows_fps() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("registry_rules/pua_registry_rules.yaml");
        let m = PuaRegistryMatcher::load_from_file(&p);
        assert!(m.pattern_count() > 1000, "loaded pattern count: {}", m.pattern_count());

        for fp_key in [
            r"HKCU\Software\Microsoft\Internet Explorer\Toolbar\ShellBrowser",
            r"HKCU\Software\Microsoft\Internet Explorer\Toolbar\WebBrowser",
            r"HKLM\Software\BitLocker",
            r"HKCU\Software\IME",
            r"HKCU\Software\StoreApps",
            r"HKLM\Software\Classes\Android",
            r"HKLM\Software\APNs",
        ] {
            assert!(
                m.matches(fp_key).is_empty(),
                "false positive match on {fp_key}: {:?}",
                m.matches(fp_key)
            );
        }

        for pua_key in [
            r"HKCU\Software\BabylonToolbar\Prefs",
            r"HKCU\Software\BI",
            r"HKCU\Software\BI\Config",
            r"HKLM\SOFTWARE\Classes\AppID\abengine.exe",
        ] {
            assert!(
                !m.matches(pua_key).is_empty(),
                "expected PUA match missing on {pua_key}"
            );
        }
    }
}
