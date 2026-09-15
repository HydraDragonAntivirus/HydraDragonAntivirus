use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionItem {
    pub layer: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerDetails {
    pub is_signed: bool,
    pub is_trusted: bool,
    pub signer_name: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticScanReport {
    pub target: String,
    pub file_size: u64,
    pub sha1: String,
    pub sha256: String,
    pub verdict: String, // "Malicious", "Clean", "Suspicious", "Unknown"
    pub max_threat_score: f32,
    pub detections: Vec<DetectionItem>,
    pub signer_info: Option<SignerDetails>,
    pub fls_verdict: Option<String>,
    pub pua_registry_matches: Vec<String>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCheckReport {
    pub query_path: String,
    pub matched_patterns: Vec<String>,
    pub is_pua_autostart: bool,
}
