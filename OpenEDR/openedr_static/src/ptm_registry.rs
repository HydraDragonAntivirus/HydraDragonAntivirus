use std::path::Path;

/// Simple wildcard pattern matcher supporting `*` and case-insensitive comparison.
#[derive(Debug, Clone)]
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

    /// Load puaRegPaths directly from ptm.local.src if found in rule dir
    pub fn from_ptm_local_src(path: &Path) -> Self {
        if !path.is_file() {
            return Self { patterns: Vec::new() };
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self { patterns: Vec::new() },
        };

        Self::parse_ptm_content(&content)
    }

    pub fn parse_ptm_content(content: &str) -> Self {
        let mut patterns = Vec::new();
        // Extract array under "puaRegPaths": [ ... ]
        if let Some(start_idx) = content.find("\"puaRegPaths\":") {
            let slice = &content[start_idx..];
            if let Some(arr_start) = slice.find('[') {
                if let Some(arr_end) = slice[arr_start..].find(']') {
                    let array_text = &slice[arr_start..arr_start + arr_end + 1];
                    // Clean C++ style comments if any before json parsing
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

    /// Checks if a registry path matches any puaRegPaths pattern.
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
    fn test_pua_matcher() {
        let pats = vec![
            r"*software\classes\appid\abengine.exe*".to_string(),
            r"*clsid\{0a0ddbd3-6641-40b9-873f-bbdd26d6c14e}*".to_string(),
        ];
        let matcher = PuaRegistryMatcher::new(pats);

        assert_eq!(
            matcher.matches(r"HKLM\SOFTWARE\Classes\AppID\abengine.exe\val").len(),
            1
        );
        assert_eq!(
            matcher.matches(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run").len(),
            0
        );
    }
}
