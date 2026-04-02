//! Logging system for signaturemonster

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

pub struct Logger {
    pub log_path: PathBuf,
}

impl Logger {
    pub fn new() -> Self {
        let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("signaturemonster.exe"));
        path.set_extension("log");
        Self { log_path: path }
    }

    pub fn log(&self, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let log_line = format!("[{}] {}\n", timestamp, message);
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

pub static LOGGER: std::sync::LazyLock<Logger> = std::sync::LazyLock::new(Logger::new);

pub fn log_event(message: &str) {
    LOGGER.log(message);
}
