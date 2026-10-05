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

fn format_iso8601_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let z = (days as i64) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
}

impl StaticScanReport {
    /// Convert the report into Elastic Common Schema (ECS 8.x) JSON object.
    /// Perfectly suited for direct ingestion into Elasticsearch / Logstash / Kibana.
    pub fn to_ecs_value(&self) -> serde_json::Value {
        let path = std::path::Path::new(&self.target);
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        let raw_verdict = self.verdict.to_lowercase();
        let is_malicious = raw_verdict == "malicious";
        let is_suspicious = raw_verdict == "suspicious";
        let is_threat = is_malicious || is_suspicious;

        let event_kind = if is_threat { "alert" } else { "event" };
        let primary_detection = self.detections.first();

        let mut code_sig_json = serde_json::json!({
            "exists": self.signer_info.as_ref().map(|s| s.is_signed).unwrap_or(false),
            "signed": self.signer_info.as_ref().map(|s| s.is_signed).unwrap_or(false),
            "trusted": self.signer_info.as_ref().map(|s| s.is_trusted).unwrap_or(false),
        });
        if let Some(ref sig) = self.signer_info {
            if let Some(ref sub) = sig.signer_name {
                code_sig_json["subject_name"] = serde_json::json!(sub);
            }
            code_sig_json["status"] = serde_json::json!(sig.status);
            code_sig_json["catalog_signed"] = serde_json::json!(sig.is_catalog_signed);
        }

        let mut doc = serde_json::json!({
            "@timestamp": format_iso8601_now(),
            "ecs": { "version": "8.11.0" },
            "event": {
                "kind": event_kind,
                "category": ["malware", "file"],
                "type": if is_threat { vec!["info", "indicator"] } else { vec!["info"] },
                "action": "static_analysis",
                "outcome": if raw_verdict == "error" { "failure" } else { "success" },
                "duration": (self.scan_time_ms as u128) * 1_000_000,
            },
            "file": {
                "path": self.target,
                "name": file_name,
                "extension": extension,
                "size": self.file_size,
                "hash": {
                    "sha256": self.sha256,
                },
                "code_signature": code_sig_json,
            },
            "antivirus": {
                "engine": "VirusKov Engine",
                "verdict": raw_verdict,
                "score": self.max_threat_score,
                "scan_time_ms": self.scan_time_ms,
                "detections_count": self.detections.len(),
                "detections": self.detections,
                "pua_registry_matches": self.pua_registry_matches,
                "extracted_objects_count": self.extracted_objects.len(),
                "extracted_objects": self.extracted_objects,
            }
        });

        if let Some(det) = primary_detection {
            doc["rule"] = serde_json::json!({
                "name": det.name,
                "category": det.layer,
            });
            if is_threat {
                doc["threat"] = serde_json::json!({
                    "indicator": {
                        "type": "file",
                        "name": det.name,
                        "confidence": det.score.unwrap_or(self.max_threat_score),
                        "file": {
                            "hash": {
                                "sha256": self.sha256,
                            }
                        }
                    }
                });
            }
        }

        doc
    }

    /// Serialize report into an ECS-compliant JSON string.
    pub fn to_ecs_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_ecs_value())
    }

    /// Serialize report into an ECS-compliant pretty JSON string.
    pub fn to_ecs_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.to_ecs_value())
    }
}
