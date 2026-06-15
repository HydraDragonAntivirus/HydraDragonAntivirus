use crate::config::{Config, Param};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub static REPORTS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static RULES_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static UTILS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static NOVELTY_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static BLOOM_FILTER_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Initialize global path variables from the configuration
pub fn init_globals(config: &Config) {
    let report_dir = config
        .get_param(Param::ReportDir)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("reports"));
    if let Err(e) = std::fs::create_dir_all(&report_dir) {
        eprintln!(
            "[globals] Failed to create report dir {:?}: {}",
            &report_dir, e
        );
    }
    REPORTS_PATH.set(report_dir).ok();

    let config_path = config
        .get_param(Param::ConfigPath)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config"));
    CONFIG_PATH.set(config_path).ok();

    let rules_path_str = config.get_param(Param::RulesPath)
        .filter(|s| !s.trim().is_empty())
        .expect("Critical: RULES_PATH must be set in HKLM\\SOFTWARE\\Owlyshield (Registry-only mode enforced)");

    let rules_path = PathBuf::from(rules_path_str);

    if !rules_path.exists() {
        panic!(
            "Critical: The path specified in the Registry for RULES_PATH does not exist: {:?}",
            rules_path
        );
    }

    RULES_PATH.set(rules_path).ok();

    let utils_path = config
        .get_param(Param::UtilsPath)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("utils"));
    UTILS_PATH.set(utils_path).ok();

    let novelty_path = config
        .get_param(Param::NoveltyPath)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("novelty"));
    NOVELTY_PATH.set(novelty_path).ok();

    let bloom_filter_path = config
        .get_param(Param::BloomFilterPath)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\hydradragon\Owlyshield\bloom_filter")
        });
    BLOOM_FILTER_PATH.set(bloom_filter_path).ok();
}

/// Shorthand to get report directory
pub fn report_dir() -> &'static Path {
    REPORTS_PATH
        .get()
        .map(|p| p.as_path())
        .expect("Globals not initialized")
}

/// Shorthand to get config directory/path
#[allow(dead_code)]
pub fn config_path() -> &'static Path {
    CONFIG_PATH
        .get()
        .map(|p| p.as_path())
        .expect("Globals not initialized")
}

/// Shorthand to get rules directory
#[allow(dead_code)]
pub fn rules_path() -> &'static Path {
    RULES_PATH
        .get()
        .map(|p| p.as_path())
        .expect("Globals not initialized")
}

/// Shorthand to get the bloom filter directory (containing whitelist.bloom / blacklist.bloom)
#[allow(dead_code)]
pub fn bloom_filter_path() -> &'static Path {
    BLOOM_FILTER_PATH
        .get()
        .map(|p| p.as_path())
        .expect("Globals not initialized")
}
