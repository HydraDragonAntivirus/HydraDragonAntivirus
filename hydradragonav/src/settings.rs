//! User settings for right-click / CLI scan defaults.
//! Loaded from `settings/settings.json` (or `.toml` for backwards compat)
//! inside the executable's directory. If none exists, defaults are used.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Additional directories to exclude from scanning (relative or absolute paths).
    /// HydraDragonAV's own config/rules/database directories are always excluded
    /// automatically; this extends that list.
    #[serde(default)]
    pub excluded_dirs: Vec<String>,

    /// Specific files to exclude from scanning (absolute or relative paths).
    /// Relative paths are resolved relative to the application directory.
    #[serde(default)]
    pub excluded_files: Vec<String>,

    /// UI theme name (e.g. "dark", "light"). Used by GUI frontends.
    #[serde(default)]
    pub theme: Option<String>,

    /// Maximum file size in MiB to scan. Files larger than this are skipped.
    /// Defaults to 650 MiB when `None`.
    #[serde(default)]
    pub max_file_size_mb: Option<u64>,

    /// Consecutive null-byte run length (in MiB) that triggers a "file bloat"
    /// Suspicious verdict. Defaults to 50 MiB when `None`.
    #[serde(default)]
    pub max_bloat_mb: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_categories: Vec::new(),
            scan_with_registry: false,
            scan_with_memory: false,
            scan_with_sigma: false,
            excluded_dirs: Vec::new(),
            excluded_files: Vec::new(),
            theme: None,
            max_file_size_mb: None,
            max_bloat_mb: None,
        }
    }
}

impl Settings {
    /// Path to the settings directory under the application directory.
    pub fn settings_dir(app_dir: &Path) -> std::path::PathBuf {
        app_dir.join("settings")
    }

    /// Load settings from `settings/settings.json` (or `.toml` fallback).
    /// If no file exists, returns defaults.
    pub fn load(dir: &Path) -> Self {
        // Primary: settings/settings.json
        let settings_dir = Self::settings_dir(dir);
        let json_path = settings_dir.join("settings.json");
        if json_path.exists() {
            return match std::fs::read_to_string(&json_path) {
                Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
                    eprintln!("[Settings] Failed to parse {}: {e}. Using defaults.", json_path.display());
                    Self::default()
                }),
                Err(_) => Self::default(),
            };
        }

        // Secondary: settings/settings.toml
        let toml_path = settings_dir.join("settings.toml");
        if toml_path.exists() {
            return match std::fs::read_to_string(&toml_path) {
                Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                    eprintln!("[Settings] Failed to parse {}: {e}. Using defaults.", toml_path.display());
                    Self::default()
                }),
                Err(_) => Self::default(),
            };
        }

        // Tertiary (legacy): settings.toml next to the executable
        let legacy = dir.join("settings.toml");
        if legacy.exists() {
            return match std::fs::read_to_string(&legacy) {
                Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                    eprintln!("[Settings] Failed to parse {}: {e}. Using defaults.", legacy.display());
                    Self::default()
                }),
                Err(_) => Self::default(),
            };
        }

        Self::default()
    }

}
