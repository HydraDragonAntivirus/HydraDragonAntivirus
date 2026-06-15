use std::path::Path;

/// Trusted signer list loaded from complist.txt (UTF-16, one company per line).
#[derive(Debug, Clone)]
pub struct TrustedSignerList {
    /// Normalised (lowercased) company names for case-insensitive matching.
    signers: Vec<String>,
}

impl TrustedSignerList {
    /// Load from a UTF-16-encoded text file with one trusted company name per line.
    /// Returns an empty list if the file cannot be read.
    pub fn load<P: AsRef<Path>>(path: P) -> Self {
        let content = match std::fs::read(path.as_ref()) {
            Ok(bytes) => {
                let utf16: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .skip_while(|&c| c == 0xFEFF) // skip BOM
                    .take_while(|&c| c != 0)       // stop at null
                    .collect();
                String::from_utf16_lossy(&utf16)
            }
            Err(_) => return Self { signers: Vec::new() },
        };

        let signers: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|line| !line.is_empty())
            .collect();

        Self { signers }
    }

    /// Check if a signer name matches any trusted signer in the list.
    /// Performs case-insensitive substring matching.
    pub fn is_trusted(&self, signer_name: &str) -> bool {
        let lower_name = signer_name.to_lowercase();
        self.signers
            .iter()
            .any(|entry| lower_name.contains(entry))
    }

    pub fn len(&self) -> usize {
        self.signers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }
}

impl Default for TrustedSignerList {
    fn default() -> Self {
        Self { signers: Vec::new() }
    }
}

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
    fn test_trusted_signers_from_utf16() {
        let dir = std::env::temp_dir().join("hydradragon_test_complist");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("complist.txt");

        let mut content: Vec<u16> = Vec::new();
        content.push(0xFEFF); // BOM
        for c in "Microsoft Corporation\nNVIDIA Corporation\n".encode_utf16() {
            content.push(c);
        }
        let bytes: Vec<u8> = content
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        std::fs::write(&path, bytes).unwrap();

        let list = TrustedSignerList::load(&path);
        assert!(list.is_trusted("Microsoft Corporation"));
        assert!(list.is_trusted("NVIDIA Corporation"));
        assert!(!list.is_trusted("ACME Corp"));

        let _ = std::fs::remove_dir_all(dir);
    }

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
        let list = TrustedSignerList::default();
        assert!(!list.is_trusted("Microsoft"));
        assert!(list.is_empty());

        let list = PuaRegistryList::default();
        assert!(!list.is_pua("hkcu", "test"));
        assert!(list.is_empty());
    }
}
