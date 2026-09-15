use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScanner {
    rules: Vec<Rules>,
}

impl YaraScanner {
    pub fn new(rules_dir: &Path) -> Self {
        if !rules_dir.is_dir() {
            return Self { rules: Vec::new() };
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

        Self { rules: loaded_rules }
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        if self.rules.is_empty() {
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

    pub fn is_loaded(&self) -> bool {
        !self.rules.is_empty()
    }
}
