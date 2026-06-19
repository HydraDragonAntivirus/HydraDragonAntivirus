use std::path::Path;

/// PUA registry key patterns loaded from reglist.txt.
#[derive(Debug, Clone)]
pub struct PuaRegistryList {
    patterns: Vec<PuaRegistryPattern>,
}

#[derive(Debug, Clone)]
pub struct PuaRegistryPattern {
    pub key: String,
    pub hive: String,
}

impl PuaRegistryList {
    /// Load from reglist.txt (UTF-8, pipe-delimited: `key|hive|path`).
    pub fn load<P: AsRef<Path>>(path: P) -> Self {
        let content = match std::fs::read_to_string(path.as_ref()) {
            Ok(c) => c,
            Err(_) => return Self { patterns: Vec::new() },
        };

        let patterns = content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() < 3 {
                    return None;
                }
                Some(PuaRegistryPattern {
                    key: parts[2].to_lowercase(),
                    hive: parts[1].to_lowercase(),
                })
            })
            .collect();

        Self { patterns }
    }

    /// Check if a registry key path matches any PUA pattern.
    pub fn is_pua(&self, hive: &str, key: &str) -> bool {
        let lower_hive = hive.to_lowercase();
        let lower_key = key.to_lowercase();
        self.patterns.iter().any(|p| {
            p.hive == lower_hive && lower_key.starts_with(&p.key)
        })
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

impl Default for PuaRegistryList {
    fn default() -> Self {
        Self { patterns: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_pua_registry_patterns() {
        let dir = std::env::temp_dir().join("hydradragon_test_reglist");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("reglist.txt");

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "key|hkcu|Software\\InstallCore").unwrap();
        writeln!(file, "key|hkml|SOFTWARE\\Classes\\CLSID\\{ABC}").unwrap();
        file.flush().unwrap();

        let list = PuaRegistryList::load(&path);
        assert!(list.is_pua("hkcu", r"Software\InstallCore\SomeSubKey"));
        assert!(list.is_pua("hkml", r"SOFTWARE\Classes\CLSID\{ABC}"));
        assert!(!list.is_pua("hkcu", r"Software\Microsoft\Windows"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_empty_list() {
        let list = PuaRegistryList::default();
        assert!(!list.is_pua("hkcu", "test"));
        assert!(list.is_empty());
    }
}
