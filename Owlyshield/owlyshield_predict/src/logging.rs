use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use chrono::{DateTime, Local};
use log::{error, warn, info, debug};
use crate::utils::LOG_TIME_FORMAT;
use crate::config::ConfigReader;
#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};

#[derive(Copy, Clone)]
enum Status {
    Start,    // Program starting
    Stop,     // Program stopping
    Alert,    // Program detected a malware
    Warning,  // Warning in program execution
    Error,    // Error in program execution
    Novelty,  // Notice a novelty
    Info,     // General information
    Debug,    // Debug-level message
}

impl Status {
    fn to_str(&self) -> &str {
        match self {
            Status::Start => "START",
            Status::Stop => "STOP",
            Status::Alert => "ALERT",
            Status::Warning => "WARNING",
            Status::Error => "ERROR",
            Status::Novelty => "NOVELTY",
            Status::Info => "INFO",
            Status::Debug => "DEBUG",
        }
    }
}

pub struct Logging;

impl Logging {
    #[cfg(target_os = "windows")]
    fn open_windows_log_file(dir: &Path) -> std::io::Result<std::fs::File> {
        std::fs::create_dir_all(dir)?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .open(dir.join("owlyshield.log"))
    }

    #[cfg(not(target_os = "windows"))]
    fn open_log_file(dir: &Path) -> std::io::Result<std::fs::File> {
        std::fs::create_dir_all(dir)?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(dir.join("owlyshield.log"))
    }

    #[cfg(target_os = "windows")]
    fn candidate_log_dirs(dir: &str) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let configured = PathBuf::from(dir);
        if !configured.as_os_str().is_empty() {
            dirs.push(configured);
        }

        if let Some(program_data) = std::env::var_os("ProgramData") {
            dirs.push(
                PathBuf::from(program_data)
                    .join("HydraDragonAntivirus")
                    .join("hydradragon")
                    .join("Owlyshield")
                    .join("log"),
            );
        }

        dirs.push(std::env::temp_dir().join("owlyshield"));
        dirs
    }

    #[cfg(not(target_os = "windows"))]
    fn candidate_log_dirs(dir: &str) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let configured = PathBuf::from(dir);
        if !configured.as_os_str().is_empty() {
            dirs.push(configured);
        }

        dirs.push(std::env::temp_dir().join("owlyshield"));
        dirs
    }

    #[cfg(target_os = "windows")]
    fn should_write_to_file(status: Status, message: &str) -> bool {
        if matches!(status, Status::Debug) {
            return false;
        }

        if matches!(status, Status::Info) {
            return !message.starts_with("[DIAG] API HOOKING EVENT")
                && !message.starts_with("[DIAG] KERNEL EVENT")
                && !message.starts_with("[DIAG] EVENT RECEIVED")
                && !message.starts_with("[API HOOKING EVENT]");
        }

        true
    }

    #[cfg(not(target_os = "windows"))]
    fn should_write_to_file(_status: Status, _message: &str) -> bool {
        true
    }

    #[cfg(target_os = "windows")]
    pub fn init() {
        let log_source = "Owlyshield Ransom Rust";
        winlog::register(log_source);
        winlog::init(log_source).unwrap_or(());
    }

    #[cfg(target_os = "linux")]
    pub fn init() {

    }

    /// Log the program start event
    pub fn start() {
        Logging::log(Status::Start, "");
    }

    /// Log the program stop event
    pub fn stop() {
        Logging::log(Status::Stop, "");
    }

    /// Log the detection of malware or suspicious activity
    pub fn alert(message: &str) {
        Logging::log(Status::Alert, message);
    }

    /// Log a warning in the program execution
    pub fn warning(message: &str) {
        Logging::log(Status::Warning, message);
    }

    /// Log an error in the program execution
    pub fn error(message: &str) {
        Logging::log(Status::Error, message);
    }

    /// Notice a novelty
    pub fn novelty(message: &str) {
        Logging::log(Status::Novelty, message);
    }

    /// Log general information
    pub fn info(message: &str) {
        Logging::log(Status::Info, message);
    }

    /// Log debug information
    pub fn debug(message: &str) {
        Logging::log(Status::Debug, message);
    }

    #[cfg(target_os = "windows")]
    fn log(status: Status, message: &str) {
        if Self::should_write_to_file(status, message) {
            Self::log_in_file(status, message, ConfigReader::read_param_from_registry("LOG_PATH", r"SOFTWARE\Owlyshield").as_str());
        }

        match status {
            Status::Alert | Status::Warning | Status::Novelty => { 
                warn!("{}: {}", status.to_str(), message); 
            },
            Status::Error => {
                error!("{}: {}", status.to_str(), message);
            },
            Status::Debug => {
                debug!("{}: {}", status.to_str(), message);
            },
            _ => {
                if message.is_empty() {
                    info!("{}", status.to_str());
                } else {
                    info!("{}: {}", status.to_str(), message);
                }
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn log(status: Status, message: &str) {
        let dir: &str = "/var/log/owlyshield";
        Self::log_in_file(status, message, dir);
    }

    fn log_in_file(status: Status, message: &str, dir: &str) {
        let now = (DateTime::from(SystemTime::now()) as DateTime<Local>)
            .format(LOG_TIME_FORMAT)
            .to_string();

        let comment = if message.is_empty() {
            format!("{} localhost owlyshield[{}]: {}", now, std::process::id(), status.to_str())
        } else {
            format!("{} localhost owlyshield[{}]: {}: {}", now, std::process::id(), status.to_str(), message)
        };

        let mut last_error: Option<(PathBuf, std::io::Error)> = None;

        for log_dir in Self::candidate_log_dirs(dir) {
            #[cfg(target_os = "windows")]
            let open_result = Self::open_windows_log_file(&log_dir);

            #[cfg(not(target_os = "windows"))]
            let open_result = Self::open_log_file(&log_dir);

            match open_result {
                Ok(mut file) => {
                    if let Err(e) = writeln!(file, "{comment}") {
                        eprintln!("Couldn't write to log file {}: {}", log_dir.display(), e);
                    }
                    return;
                }
                Err(e) => {
                    last_error = Some((log_dir, e));
                }
            }
        }

        if let Some((path, err)) = last_error {
            eprintln!("Couldn't open any log file. Last path {} failed: {}", path.display(), err);
        }
    }
}
