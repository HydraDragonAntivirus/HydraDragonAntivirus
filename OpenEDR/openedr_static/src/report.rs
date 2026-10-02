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
    #[serde(default)]
    pub is_catalog_signed: bool,
}

/// A first-class in-memory object to be scanned by the engine.
#[derive(Debug, Clone)]
pub struct ScanObject {
    pub name: String,
    pub path: String,
    pub bytes: Vec<u8>,
    pub depth: u32,
    pub origin_type: String, // "ArchiveMember", "UnpackedPE", "Overlay", "Stripped"
}

impl ScanObject {
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        bytes: Vec<u8>,
        depth: u32,
        origin_type: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            bytes,
            depth,
            origin_type: origin_type.into(),
        }
    }
}

/// A scanned child object (archive member, emulated unpacked payload, overlay, or stripped padding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedObject {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub depth: u32,
    pub origin_type: String, // "ArchiveMember", "UnpackedPE", "Overlay", "Stripped"
    pub verdict: String,
    pub max_threat_score: f32,
    pub detections: Vec<DetectionItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticScanReport {
    pub target: String,
    pub file_size: u64,
    pub sha256: String,
    pub verdict: String, // "Malicious", "Clean", "Suspicious", "Unknown"
    pub max_threat_score: f32,
    pub detections: Vec<DetectionItem>,
    pub signer_info: Option<SignerDetails>,
    pub pua_registry_matches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extracted_objects: Vec<ExtractedObject>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanReport {
    pub pid: u32,
    pub regions_scanned: u64,
    pub bytes_scanned: u64,
    pub verdict: String, // "Malicious", "Suspicious", "Unknown", "Error"
    pub max_threat_score: f32,
    pub detections: Vec<DetectionItem>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCheckReport {
    pub query_path: String,
    pub matched_patterns: Vec<String>,
    pub is_pua_autostart: bool,
}
