/// Extension whitelist loader module
/// Dynamically loads whitelisted file extensions from extensions.txt
use std::fs;
use std::path::Path;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct ExtensionWhitelist {
    extensions: Arc<RwLock<HashSet<String>>>,
    file_path: String,
}

impl ExtensionWhitelist {
    /// Create a new ExtensionWhitelist instance
    pub fn new(file_path: impl Into<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let path = file_path.into();
        let extensions = Arc::new(RwLock::new(HashSet::new()));
        
        let whitelist = ExtensionWhitelist {
            extensions,
            file_path: path,
        };
        
        whitelist.reload()?;
        Ok(whitelist)
    }
    
    /// Reload extensions from file
    pub fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !Path::new(&self.file_path).exists() {
            return Err(format!("Extension whitelist file not found: {}", self.file_path).into());
        }
        
        let content = fs::read_to_string(&self.file_path)?;
        let mut exts = self.extensions.write().unwrap();
        exts.clear();
        
        for line in content.lines() {
            let ext = line.trim().trim_matches('"');
            if !ext.is_empty() {
                exts.insert(ext.to_lowercase());
            }
        }
        
        log::info!("Loaded {} whitelisted extensions from {}", exts.len(), self.file_path);
        Ok(())
    }
    
    /// Check if an extension is whitelisted
    pub fn is_whitelisted(&self, extension: &str) -> bool {
        let exts = self.extensions.read().unwrap();
        exts.contains(&extension.to_lowercase().trim_start_matches('.'))
    }
    
    /// Get all whitelisted extensions
    pub fn get_extensions(&self) -> Vec<String> {
        let exts = self.extensions.read().unwrap();
        exts.iter().cloned().collect()
    }
    
    /// Get count of whitelisted extensions
    pub fn count(&self) -> usize {
        let exts = self.extensions.read().unwrap();
        exts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_whitelisted() {
        // This would need a test file
        // For now, just verify the struct compiles
    }
}
