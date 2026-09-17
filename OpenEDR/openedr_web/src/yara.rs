//! YARA-X scanning for the web edition (same engine + API shape as desktop).
//!
//! Rules arrive as bytes from JS: either a compiled `.yrc` bundle
//! (e.g. desktop `valhalla-rules.yrc`) via [`YaraScanner::load_yrc`], or
//! plain `.yar` source via [`YaraScanner::add_source`].

use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScanner {
    rules: Vec<Rules>,
}

impl YaraScanner {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load one compiled `.yrc` bundle. Returns false when bytes don't parse.
    pub fn load_yrc(&mut self, data: &[u8]) -> bool {
        match Rules::deserialize(data) {
            Ok(r) => {
                self.rules.push(r);
                true
            }
            Err(_) => false,
        }
    }

    /// Compile one `.yar` source document and append it. Returns false on
    /// syntax error.
    pub fn add_source(&mut self, src: &str) -> bool {
        let mut compiler = Compiler::new();
        if compiler.add_source(src).is_err() {
            return false;
        }
        self.rules.push(compiler.build());
        true
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
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
                    hits.push(m.identifier().to_string());
                }
            }
        }
        hits
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}
