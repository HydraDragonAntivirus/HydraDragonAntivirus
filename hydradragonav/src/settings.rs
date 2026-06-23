//! User settings for right-click / CLI scan defaults.
//! Loaded from `settings.toml` next to the executable.
//! If the file doesn't exist, defaults are used (Files-only for right-click).

use std::path::Path;

use serde::Deserialize;

use crate::pipeline::ScanCategory;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    /// Default scan categories when none are specified on the CLI.
    /// Empty = all categories enabled.
    #[serde(default)]
    pub default_categories: Vec<String>,

    /// Whether to include registry scanning when right-click scanning a file.
    /// When true, `Registry` and `Pum` categories are added alongside `Files`
    /// for single-file scans invoked via the Explorer context menu.
    #[serde(default)]
    pub scan_with_registry: bool,

    /// Whether to include memory scanning when right-click scanning a file.
    #[serde(default)]
    pub scan_with_memory: bool,

    /// Whether to include Sigma/Hayabusa scanning when right-click scanning a file.
    #[serde(default)]
    pub scan_with_sigma: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_categories: Vec::new(),
            scan_with_registry: false,
            scan_with_memory: false,
            scan_with_sigma: false,
        }
    }
}

impl Settings {
    /// Load settings from `settings.toml` in the given directory.
    /// If the file doesn't exist, returns defaults.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("settings.toml");
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                toml::from_str(&content).unwrap_or_else(|e| {
                    eprintln!("[Settings] Failed to parse {}: {e}. Using defaults.", path.display());
                    Self::default()
                })
            }
            Err(_) => Self::default(),
        }
    }

    /// Build the effective scan categories for a right-click / context-menu scan.
    /// When a single file is scanned via right-click, the base category is `Files`.
    /// Additional categories are added based on `scan_with_registry`, `scan_with_memory`, etc.
    pub fn context_menu_categories(&self) -> Vec<ScanCategory> {
        let mut cats = vec![ScanCategory::Files];
        if self.scan_with_registry {
            cats.push(ScanCategory::Registry);
            cats.push(ScanCategory::Pum);
        }
        if self.scan_with_memory {
            cats.push(ScanCategory::Memory);
        }
        if self.scan_with_sigma {
            cats.push(ScanCategory::Sigma);
        }
        cats
    }
}
