use crate::config::ConfigReader;
use log::{debug, error, info, warn};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::prelude::*;

use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use windows::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};

/// Structured JSONL entry appended to `owlyshield.jsonl`. Mirrors the firewall's
/// `LogEntry` shape so Filebeat / Logstash / Elasticsearch can index both files
/// with one pipeline.
#[derive(Debug, Clone, Serialize)]
struct JsonlLogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: String,
    pub message: String,
}

static VERBOSE_LOGGING: AtomicBool = AtomicBool::new(false);

/// Whether verbose logging is enabled (read from HKLM\SOFTWARE\Owlyshield\VERBOSE_LOGGING).
pub fn is_verbose_logging_enabled() -> bool {
    VERBOSE_LOGGING.load(Ordering::Relaxed)
}

#[derive(Copy, Clone)]
enum Status {
    Start,   // Program starting
    Stop,    // Program stopping
    Alert,   // Program detected a malware
    Warning, // Warning in program execution
    Error,   // Error in program execution
    Info,    // General information
    Debug,   // Debug-level message
}

impl Status {
    fn to_str(&self) -> &str {
        match self {
            Status::Start => "START",
            Status::Stop => "STOP",
            Status::Alert => "ALERT",
            Status::Warning => "WARNING",
            Status::Error => "ERROR",
            Status::Info => "INFO",
            Status::Debug => "DEBUG",
        }
    }
}

pub struct Logging;

/// Pop a trailing `owlyshield` segment so the JSONL file lands at the log root
/// instead of inside a dedicated subdirectory (see `owlyshield_log_dir`).
fn normalize_owlyshield_log_dir(mut dir: PathBuf) -> PathBuf {
    if dir
        .file_name()
        .and_then(|n| n.to_str())
        .map_or(false, |s| s.eq_ignore_ascii_case("owlyshield"))
    {
        dir.pop();
    }
    dir
}

impl Logging {
    fn open_windows_log_file(dir: &Path) -> std::io::Result<std::fs::File> {
        std::fs::create_dir_all(dir)?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .open(dir.join("owlyshield.jsonl"))
    }

    /// Resolve the log directory that holds `owlyshield.jsonl`.
    ///
    /// The installer sets `LOG_PATH` to `...\edrsvc\log\owlyshield` (a dedicated
    /// subdirectory). Popping the `owlyshield` segment keeps the file at the log
    /// root (`C:\ProgramData\edrsvc\log\owlyshield.jsonl`), next to the firewall's
    /// `firewall_activity.jsonl`, so only one JSONL file is ever created and
    /// Filebeat / Logstash can tail both from the same folder.
    pub fn owlyshield_log_dir() -> PathBuf {
        let configured = ConfigReader::read_param_from_registry("LOG_PATH", r"SOFTWARE\Owlyshield");
        if !configured.trim().is_empty() {
            return normalize_owlyshield_log_dir(PathBuf::from(configured.trim()));
        }
        if let Some(program_data) = std::env::var_os("ProgramData") {
            return PathBuf::from(program_data).join("edrsvc").join("log");
        }
        PathBuf::from("C:\\ProgramData\\edrsvc\\log")
    }

    pub fn owlyshield_jsonl_path() -> PathBuf {
        Self::owlyshield_log_dir().join("owlyshield.jsonl")
    }

    pub fn init() {
        use registry::{Hive, Security};
        if let Ok(regkey) = Hive::LocalMachine.open(r"SOFTWARE\Owlyshield", Security::Read) {
            if let Ok(val) = regkey.value("VERBOSE_LOGGING") {
                let val_str = val.to_string();
                let clean_str = val_str.trim_matches('\0').trim().to_lowercase();
                let is_verbose = clean_str == "1" || clean_str == "true";
                VERBOSE_LOGGING.store(is_verbose, Ordering::Relaxed);
            }
        }
        crate::config::init_trust_comodo_cloud();
        crate::config::init_monitor_all_apis();
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

    /// Log general information
    pub fn info(message: &str) {
        Logging::log(Status::Info, message);
    }

    /// Log debug information
    pub fn debug(message: &str) {
        Logging::log(Status::Debug, message);
    }

    fn log(status: Status, message: &str) {
        if (matches!(status, Status::Debug) || matches!(status, Status::Info))
            && !is_verbose_logging_enabled()
        {
            return;
        }

        Self::log_in_file(
            status,
            message,
            ConfigReader::read_param_from_registry("LOG_PATH", r"SOFTWARE\Owlyshield").as_str(),
        );

        match status {
            Status::Alert | Status::Warning => {
                warn!("{}: {}", status.to_str(), message);
            }
            Status::Error => {
                error!("{}: {}", status.to_str(), message);
            }
            Status::Debug => {
                debug!("{}: {}", status.to_str(), message);
            }
            _ => {
                if message.is_empty() {
                    info!("{}", status.to_str());
                } else {
                    info!("{}: {}", status.to_str(), message);
                }
            }
        }
    }

    fn log_in_file(status: Status, message: &str, _dir: &str) {
        let now_millis = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = JsonlLogEntry {
            id: format!(
                "owlyshield-{}-{}",
                now_millis,
                status.to_str().to_lowercase()
            ),
            timestamp: now_millis,
            level: status.to_str().to_string(),
            message: message.to_string(),
        };

        let Ok(line) = serde_json::to_string(&entry) else {
            return;
        };

        let path = Self::owlyshield_jsonl_path();
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }
        }

        match Self::open_windows_log_file(path.parent().unwrap_or(&path)) {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{line}") {
                    eprintln!("Couldn't write to log file {}: {}", path.display(), e);
                }
            }
            Err(e) => {
                eprintln!("Couldn't open log file {}: {}", path.display(), e);
            }
        }
    }
}
