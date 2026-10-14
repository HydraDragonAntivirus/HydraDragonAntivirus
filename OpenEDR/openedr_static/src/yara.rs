use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScanner {
    rules: Vec<Rules>,
    /// Rule names turned off by `*.ign2` / `*.ign` false-positive lists in the rules
    /// folder (ClamAV ignore-list format). Their matches are dropped.
    ignored: std::collections::HashSet<String>,
}

impl YaraScanner {
    pub fn new(rules_dir: &Path) -> Self {
        if !rules_dir.is_dir() {
            return Self { rules: Vec::new(), ignored: Default::default() };
        }

        let mut compiler = Compiler::new();
        let mut source_count = 0;
        let mut loaded_rules = Vec::new();

        if let Ok(entries) = std::fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    if ext.eq_ignore_ascii_case("yrc") {
                        // Compiled YARA-X rule file
                        if let Ok(bytes) = std::fs::read(&path) {
                            if let Ok(r) = Rules::deserialize(&bytes) {
                                loaded_rules.push(r);
                            }
                        }
                    } else if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                        if let Ok(src) = std::fs::read_to_string(&path) {
                            if compiler.add_source(src.as_str()).is_ok() {
                                source_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if source_count > 0 {
            let compiled = compiler.build();
            loaded_rules.push(compiled);
        }

        Self { rules: loaded_rules, ignored: crate::string_rules::read_ignore_lists(rules_dir) }
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        if self.rules.is_empty() || data.is_empty() {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for rules in &self.rules {
            let mut scanner = Scanner::new(rules);
            if let Ok(results) = scanner.scan(data) {
                for m in results.matching_rules() {
                    if !self.ignored.contains(m.identifier()) {
                        hits.push(m.identifier().to_string());
                    }
                }
            }
        }

        hits
    }

    /// Rule name and file byte range `[start, end)` of every pattern match (rules
    /// turned off by the `.ign2` lists are skipped), at most `limit`. For in-place
    /// disinfection; condition-only rules have no ranges.
    pub fn match_ranges(&self, data: &[u8], limit: usize) -> Vec<(String, usize, usize)> {
        let mut out = Vec::new();
        if data.is_empty() {
            return out;
        }
        for rules in &self.rules {
            let mut scanner = Scanner::new(rules);
            let Ok(results) = scanner.scan(data) else { continue };
            for rule in results.matching_rules() {
                if self.ignored.contains(rule.identifier()) {
                    continue;
                }
                for pattern in rule.patterns() {
                    for m in pattern.matches() {
                        if out.len() >= limit {
                            return out;
                        }
                        let r = m.range();
                        if r.start < r.end {
                            out.push((rule.identifier().to_string(), r.start, r.end));
                        }
                    }
                }
            }
        }
        out
    }

    pub fn is_loaded(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Load one compiled `.yrc` bundle (web parity: same bytes as desktop).
    /// Returns false when bytes don't parse.
    pub fn load_yrc(&mut self, data: &[u8]) -> bool {
        match Rules::deserialize(data) {
            Ok(r) => {
                self.rules.push(r);
                true
            }
            Err(_) => false,
        }
    }

    /// Compile one `.yar` source document and append it (web parity).
    /// Returns false on syntax error.
    pub fn add_source(&mut self, src: &str) -> bool {
        let mut compiler = Compiler::new();
        if compiler.add_source(src).is_err() {
            return false;
        }
        self.rules.push(compiler.build());
        true
    }

    /// How many rule names the `.ign2` lists turn off.
    pub fn ignored_count(&self) -> usize {
        self.ignored.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}
