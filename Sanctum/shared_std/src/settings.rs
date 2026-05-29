use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use crate::threat_response_settings::ThreatResponseSettings;

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

impl Default for SanctumSettings {
    fn default() -> Self {
        Self {
            common_scan_areas: Vec::new(),
            extension_source_mode: default_extension_source_mode(),
            minimal_scan_timeout_ms: default_minimal_scan_timeout_ms(),
            deep_scan_timeout_ms: default_deep_scan_timeout_ms(),
            late_child_scan_grace_ms: default_late_child_scan_grace_ms(),
            threat_response: ThreatResponseSettings::default(),
        }
    }
}
