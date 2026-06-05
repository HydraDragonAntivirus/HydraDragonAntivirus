use std::path::PathBuf;

use crate::threat_response_settings::ThreatResponseSettings;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SanctumSettings {
    #[serde(default)]
    pub common_scan_areas: Vec<PathBuf>,
    #[serde(default = "default_extension_source_mode")]
    pub extension_source_mode: String,
    #[serde(default = "default_minimal_scan_timeout_ms")]
    pub minimal_scan_timeout_ms: u64,
    #[serde(default = "default_deep_scan_timeout_ms")]
    pub deep_scan_timeout_ms: u64,
    #[serde(default = "default_late_child_scan_grace_ms")]
    pub late_child_scan_grace_ms: u64,
    #[serde(default)]
    pub threat_response: ThreatResponseSettings,

    // ---- Suricata settings (configurable from Sanctum GUI) ----
    /// Path to suricata.exe. Empty string = use built-in default.
    #[serde(default)]
    pub suricata_exe_path: String,
    /// Path to suricata.yaml config. Empty string = use built-in default.
    #[serde(default)]
    pub suricata_config_path: String,
    /// Directory where Suricata writes eve.json. Empty string = use built-in default.
    #[serde(default)]
    pub suricata_log_dir: String,
    /// Whether Suricata monitoring is enabled.
    #[serde(default = "default_true")]
    pub suricata_enabled: bool,

    // ---- Hayabusa settings (configurable from Sanctum GUI) ----
    /// Path to hayabusa executable. Empty string = auto-detect.
    #[serde(default)]
    pub hayabusa_exe_path: String,
    /// Scan interval in seconds.
    #[serde(default = "default_hayabusa_scan_interval_secs")]
    pub hayabusa_scan_interval_secs: u64,
    /// Minimum alert level to report ("critical", "high", "medium", "low").
    #[serde(default = "default_hayabusa_min_level")]
    pub hayabusa_min_level: String,
    /// Time offset passed to Hayabusa (e.g. "60s", "5m").
    #[serde(default = "default_hayabusa_time_offset")]
    pub hayabusa_time_offset: String,
    /// Whether Hayabusa scanning is enabled.
    #[serde(default = "default_true")]
    pub hayabusa_enabled: bool,
}

pub fn default_extension_source_mode() -> String {
    "feedback".to_string()
}

pub fn default_minimal_scan_timeout_ms() -> u64 {
    30_000
}

pub fn default_deep_scan_timeout_ms() -> u64 {
    180_000
}

pub fn default_late_child_scan_grace_ms() -> u64 {
    30_000
}

pub fn default_true() -> bool {
    true
}

pub fn default_hayabusa_scan_interval_secs() -> u64 {
    30
}

pub fn default_hayabusa_min_level() -> String {
    "critical".to_string()
}

pub fn default_hayabusa_time_offset() -> String {
    "60s".to_string()
}

impl Default for SanctumSettings {
    fn default() -> Self {
        Self {
            common_scan_areas: Vec::new(),
            extension_source_mode: default_extension_source_mode(),
            minimal_scan_timeout_ms: default_minimal_scan_timeout_ms(),
            deep_scan_timeout_ms: default_deep_scan_timeout_ms(),
            late_child_scan_grace_ms: default_late_child_scan_grace_ms(),
            threat_response: ThreatResponseSettings::default(),
            suricata_exe_path: String::new(),
            suricata_config_path: String::new(),
            suricata_log_dir: String::new(),
            suricata_enabled: true,
            hayabusa_exe_path: String::new(),
            hayabusa_scan_interval_secs: default_hayabusa_scan_interval_secs(),
            hayabusa_min_level: default_hayabusa_min_level(),
            hayabusa_time_offset: default_hayabusa_time_offset(),
            hayabusa_enabled: true,
        }
    }
}
