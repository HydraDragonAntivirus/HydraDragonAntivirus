use std::sync::OnceLock;
use std::path::{Path, PathBuf};
use crate::config::{Config, Param};

pub static REPORT_DIR: OnceLock<PathBuf> = OnceLock::new();
pub static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static RULES_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static UTILS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static NOVELTY_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Initialize global path variables from the configuration
pub fn init_globals(config: &Config) {
    let report_dir = config.get_param(Param::ReportDir)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("reports"));
    REPORT_DIR.set(report_dir).ok();

    let config_path = config.get_param(Param::ConfigPath)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config"));
    CONFIG_PATH.set(config_path).ok();
    
    let rules_path = config.get_param(Param::RulesPath)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rules"));
    RULES_PATH.set(rules_path).ok();

    let utils_path = config.get_param(Param::UtilsPath)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("utils"));
    UTILS_PATH.set(utils_path).ok();

    let novelty_path = config.get_param(Param::NoveltyPath)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("novelty"));
    NOVELTY_PATH.set(novelty_path).ok();
}

/// Shorthand to get report directory
pub fn report_dir() -> &'static Path {
    REPORT_DIR.get().map(|p| p.as_path()).expect("Globals not initialized")
}

/// Shorthand to get config directory/path
pub fn config_path() -> &'static Path {
    CONFIG_PATH.get().map(|p| p.as_path()).expect("Globals not initialized")
}

/// Shorthand to get rules directory
pub fn rules_path() -> &'static Path {
    RULES_PATH.get().map(|p| p.as_path()).expect("Globals not initialized")
}
