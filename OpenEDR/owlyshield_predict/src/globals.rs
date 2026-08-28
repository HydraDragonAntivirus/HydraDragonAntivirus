use crate::config::{Config, Param};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub static REPORTS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static UTILS_PATH: OnceLock<PathBuf> = OnceLock::new();

/// True when the user paused protection from the tray UI. Backed by
/// HKLM\SOFTWARE\Owlyshield!PROTECTION_PAUSED; re-read at most once per
/// second so the toggle applies within ~2 seconds without a restart.
/// While paused only detection *actions* are suppressed (quarantine/kill);
/// monitoring, telemetry and event flow keep running.
pub static PROTECTION_PAUSED: AtomicBool = AtomicBool::new(false);
static LAST_PAUSE_CHECK_MS: AtomicU64 = AtomicU64::new(0);

/// Returns true when protection enforcement is paused in memory.
pub fn is_protection_paused() -> bool {
    crate::ffi::is_protection_stopped()
}

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

    let utils_path = config
        .get_param(Param::UtilsPath)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("utils"));
    UTILS_PATH.set(utils_path).ok();
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
