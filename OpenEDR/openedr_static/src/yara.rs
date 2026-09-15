use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScanner {
    rules: Option<Rules>,
}

impl YaraScanner {
    pub fn new(rules_dir: &Path) -> Self {
        if !rules_dir.is_dir() {
            return Self { rules: None };
        }

        let mut compiler = Compiler::new();
        let mut loaded = 0;

        if let Ok(entries) = std::fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                        if let Ok(src) = std::fs::read_to_string(&path) {
                            if compiler.add_source(src.as_str()).is_ok() {
                                loaded += 1;
                            }
                        }
                    }
                }
            }
        }

        if loaded > 0 {
            let rules = compiler.build();
            Self { rules: Some(rules) }
        } else {
            Self { rules: None }
        }
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        let Some(ref rules) = self.rules else {
            return Vec::new();
        };

        let mut scanner = Scanner::new(rules);
        let mut hits = Vec::new();

        if let Ok(results) = scanner.scan(data) {
            for m in results.matching_rules() {
                hits.push(m.identifier().to_string());
            }
        }

        hits
    }

    pub fn is_loaded(&self) -> bool {
        self.rules.is_some()
    }
}
