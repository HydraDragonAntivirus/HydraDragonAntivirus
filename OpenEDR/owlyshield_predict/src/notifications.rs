use std::io::Write;

use serde::Serialize;

use crate::Logging;
use crate::config::Config;

/// Structured event appended to `owlyshield.jsonl` (JSONL), so the same
/// Elasticsearch pipeline that consumes `firewall_activity.jsonl` can index
/// Owlyshield detection events.
#[derive(Debug, Clone, Serialize)]
pub struct OwlyshieldLogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: String,
    pub event: String,
    pub message: String,
    pub report_path: String,
}

impl OwlyshieldLogEntry {
    pub fn alert(message: &str, report_path: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            id: format!("owlyshield-alert-{}", now),
            timestamp: now,
            level: "ALERT".to_string(),
            event: "MALWARE_DETECTED".to_string(),
            message: message.to_string(),
            report_path: report_path.to_string(),
        }
    }
}

/// Append one JSON line to `owlyshield.jsonl`. Failures are silent on purpose:
/// a logging hiccup must never break detection handling.
pub fn log_jsonl(entry: &OwlyshieldLogEntry) {
    let path = crate::logging::Logging::owlyshield_jsonl_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let Ok(line) = serde_json::to_string(entry) else {
        return;
    };

    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };

    let _ = writeln!(file, "{line}");
}

#[cfg(feature = "service")]
pub fn notify(_config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    log_jsonl(&OwlyshieldLogEntry::alert(message, report_path));

    Ok(())
}

#[cfg(not(feature = "service"))]
pub fn notify(_config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    Logging::alert(message);
    log_jsonl(&OwlyshieldLogEntry::alert(message, report_path));

    Ok(())
}
