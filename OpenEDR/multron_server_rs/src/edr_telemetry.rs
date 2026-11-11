use axum::extract::{Path as AxumPath, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use crate::dashboard::AppState;
use crate::events::Event;

const MAX_STORED_BEHAVIORS: usize = 1000;
const MAX_STORED_FLOWS: usize = 3000;
const MAX_STORED_THREATS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsSummary {
    pub ops_read: u64,
    pub ops_written: u64,
    pub ops_open: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub entropy_read: f64,
    pub entropy_written: f64,
    pub files_renamed_count: usize,
    pub files_read_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorTelemetryPayload {
    pub machine_id: String,
    pub timestamp: u64,
    pub pid: u32,
    pub gid: u64,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    pub detection: String,
    pub source: String,
    pub risk_score: f32,
    pub indicators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops_summary: Option<OpsSummary>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBehavior {
    pub id: u64,
    pub timestamp: u64,
    pub time_iso: String,
    pub machine_id: String,
    pub pid: u32,
    pub gid: u64,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub sha256: String,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub detection: String,
    pub source: String,
    pub risk_score: f32,
    pub verdict: String,
    pub threat_name: Option<String>,
    pub indicators: Vec<String>,
    pub ops_summary: Option<OpsSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlowRecord {
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFlow {
    pub id: u64,
    pub timestamp: u64,
    pub time_iso: String,
    pub machine_id: String,
    pub pid: u32,
    pub process_name: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlowBatch {
    pub machine_id: String,
    pub flows: Vec<NetworkFlowRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub sha256: String,
    pub file_name: String,
    pub original_path: String,
    pub detection: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredThreat {
    pub id: u64,
    pub timestamp: u64,
    pub time_iso: String,
    pub sha256: String,
    pub file_name: String,
    pub original_path: String,
    pub detection: String,
    pub source: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EdrStats {
    pub total_behaviors: u64,
    pub malicious_behaviors: u64,
    pub suspicious_behaviors: u64,
    pub clean_behaviors: u64,
    pub total_flows: u64,
    pub total_threats: u64,
}

#[derive(Default)]
struct EdrStoreInner {
    next_id: u64,
    behaviors: VecDeque<StoredBehavior>,
    flows: VecDeque<StoredFlow>,
    threats: VecDeque<StoredThreat>,
    stats: EdrStats,
}

pub struct EdrTelemetryStore {
    inner: RwLock<EdrStoreInner>,
}

impl Default for EdrTelemetryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrTelemetryStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(EdrStoreInner::default()),
        }
    }

    pub fn add_behavior(&self, payload: BehaviorTelemetryPayload, verdict: String, threat_name: Option<String>) {
        if let Ok(mut g) = self.inner.write() {
            g.next_id += 1;
            let id = g.next_id;
            let time_iso = Utc::now().to_rfc3339();

            g.stats.total_behaviors += 1;
            match verdict.as_str() {
                "malicious" => g.stats.malicious_behaviors += 1,
                "suspicious" => g.stats.suspicious_behaviors += 1,
                _ => g.stats.clean_behaviors += 1,
            }

            let item = StoredBehavior {
                id,
                timestamp: payload.timestamp,
                time_iso,
                machine_id: payload.machine_id,
                pid: payload.pid,
                gid: payload.gid,
                process_name: payload.process_name,
                exe_path: payload.exe_path,
                command_line: payload.command_line,
                sha256: payload.sha256,
                parent_pid: payload.parent_pid,
                parent_name: payload.parent_name,
                detection: payload.detection,
                source: payload.source,
                risk_score: payload.risk_score,
                verdict,
                threat_name,
                indicators: payload.indicators,
                ops_summary: payload.ops_summary,
            };

            g.behaviors.push_front(item);
            if g.behaviors.len() > MAX_STORED_BEHAVIORS {
                g.behaviors.pop_back();
            }
        }
    }

    pub fn add_flows(&self, machine_id: &str, flows: &[NetworkFlowRecord]) {
        if flows.is_empty() {
            return;
        }
        if let Ok(mut g) = self.inner.write() {
            let time_iso = Utc::now().to_rfc3339();
            for f in flows {
                g.next_id += 1;
                g.stats.total_flows += 1;
                let item = StoredFlow {
                    id: g.next_id,
                    timestamp: f.timestamp,
                    time_iso: time_iso.clone(),
                    machine_id: machine_id.to_string(),
                    pid: f.pid,
                    process_name: f.process_name.clone(),
                    src_ip: f.src_ip.clone(),
                    src_port: f.src_port,
                    dst_ip: f.dst_ip.clone(),
                    dst_port: f.dst_port,
                    protocol: f.protocol.clone(),
                    hostname: f.hostname.clone(),
                };
                g.flows.push_front(item);
                if g.flows.len() > MAX_STORED_FLOWS {
                    g.flows.pop_back();
                }
            }
        }
    }

    pub fn add_threat(&self, report: &ThreatReport) {
        if let Ok(mut g) = self.inner.write() {
            g.next_id += 1;
            g.stats.total_threats += 1;
            let time_iso = Utc::now().to_rfc3339();
            let item = StoredThreat {
                id: g.next_id,
                timestamp: Utc::now().timestamp() as u64,
                time_iso,
                sha256: report.sha256.clone(),
                file_name: report.file_name.clone(),
                original_path: report.original_path.clone(),
                detection: report.detection.clone(),
                source: report.source.clone(),
                pid: report.pid,
            };
            g.threats.push_front(item);
            if g.threats.len() > MAX_STORED_THREATS {
                g.threats.pop_back();
            }
        }
    }

    pub fn get_stats(&self) -> EdrStats {
        self.inner.read().map(|g| g.stats.clone()).unwrap_or_default()
    }

    pub fn get_behaviors(&self, limit: usize, risk_filter: Option<&str>, q: Option<&str>) -> Vec<StoredBehavior> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        let q_lower = q.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
        let risk_lower = risk_filter.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty() && s != "all");

        guard
            .behaviors
            .iter()
            .filter(|b| {
                if let Some(ref r) = risk_lower {
                    if !b.verdict.eq_ignore_ascii_case(r) {
                        return false;
                    }
                }
                if let Some(ref search) = q_lower {
                    let matches = b.process_name.to_lowercase().contains(search)
                        || b.exe_path.to_lowercase().contains(search)
                        || b.command_line.to_lowercase().contains(search)
                        || b.detection.to_lowercase().contains(search)
                        || b.machine_id.to_lowercase().contains(search)
                        || b.pid.to_string().contains(search)
                        || b.sha256.to_lowercase().contains(search);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_flows(&self, limit: usize, q: Option<&str>) -> Vec<StoredFlow> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        let q_lower = q.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());

        guard
            .flows
            .iter()
            .filter(|f| {
                if let Some(ref search) = q_lower {
                    let matches = f.process_name.to_lowercase().contains(search)
                        || f.src_ip.contains(search)
                        || f.dst_ip.contains(search)
                        || f.protocol.to_lowercase().contains(search)
                        || f.machine_id.to_lowercase().contains(search)
                        || f.hostname.as_deref().map_or(false, |h| h.to_lowercase().contains(search))
                        || f.pid.to_string().contains(search);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_threats(&self, limit: usize) -> Vec<StoredThreat> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        guard.threats.iter().take(limit).cloned().collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct TelemetryQuery {
    pub limit: Option<usize>,
    pub risk: Option<String>,
    pub q: Option<String>,
}

/// Handler for POST /api/v1/edr/telemetry/behavior
pub async fn handle_edr_telemetry_behavior(
    State(app): State<Arc<AppState>>,
    Json(payload): Json<BehaviorTelemetryPayload>,
) -> impl IntoResponse {
    let is_malicious = payload.risk_score >= 0.75 || (!payload.detection.is_empty() && payload.detection != "Clean");
    let is_suspicious = payload.risk_score >= 0.40 || !payload.indicators.is_empty();

    let verdict = if is_malicious {
        "malicious"
    } else if is_suspicious {
        "suspicious"
    } else {
        "clean"
    };

    let action = if is_malicious {
        "ask" // Prompt user on Pascal HIPS
    } else if is_suspicious {
        "ask"
    } else {
        "allow"
    };

    let threat_name = if !payload.detection.is_empty() && payload.detection != "Clean" {
        Some(payload.detection.clone())
    } else if let Some(first_indicator) = payload.indicators.first() {
        let clean_ind = first_indicator
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>();
        Some(format!("EDR.Behavior.{}", clean_ind.trim_matches('_')))
    } else if is_malicious {
        if !payload.source.is_empty() && payload.source != "generic" {
            Some(format!("EDR.Threat.{}", payload.source))
        } else {
            Some("EDR.Behavior.Malicious".to_string())
        }
    } else if is_suspicious {
        Some("EDR.Behavior.Suspicious".to_string())
    } else {
        None
    };

    let indicators_str = if payload.indicators.is_empty() {
        "none".to_string()
    } else {
        payload.indicators.join(", ")
    };

    let detail_str = format!(
        "score:{:.2} indicators:[{}] cmd:{}",
        payload.risk_score, indicators_str, payload.command_line
    );

    // Save into dedicated EDR store
    app.edr_telemetry.add_behavior(payload.clone(), verdict.to_string(), threat_name.clone());

    // Also push to Live Feed EventLog
    app.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_behavior".to_string(),
        session: None,
        client: Some(format!("PID:{}", payload.pid)),
        verdict: Some(verdict.to_string()),
        file: Some(format!("{} (PID:{})", payload.process_name, payload.pid)),
        size: None,
        ms: None,
        threat: threat_name.clone(),
        detail: Some(detail_str),
        sha256: if !payload.sha256.is_empty() {
            Some(payload.sha256.clone())
        } else {
            None
        },
        message: Some(format!(
            "Host:{} Source:{} Exe:{}",
            payload.machine_id, payload.source, payload.exe_path
        )),
        origin_type: Some("EDR-Behavior".to_string()),
    });

    Json(serde_json::json!({
        "status": "ok",
        "verdict": verdict,
        "threat_name": threat_name,
        "action": action,
        "confidence": payload.risk_score,
        "reason": format!("Evaluated by Multron Server EDR engine (score: {:.2})", payload.risk_score),
        "need_sample": is_malicious
    }))
}

/// Handler for POST /api/v1/edr/telemetry/network-flows
pub async fn handle_edr_telemetry_network_flows(
    State(app): State<Arc<AppState>>,
    Json(batch): Json<NetworkFlowBatch>,
) -> impl IntoResponse {
    let count = batch.flows.len();

    // Store in structured telemetry store
    app.edr_telemetry.add_flows(&batch.machine_id, &batch.flows);

    // Log sample flows in EventLog (at most 5 to avoid flooding)
    for flow in batch.flows.iter().take(5) {
        let detail_str = format!(
            "{}:{} -> {}:{} ({})",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
        );

        app.events.add(Event {
            seq: 0,
            time: Utc::now(),
            kind: "edr_flow".to_string(),
            session: None,
            client: Some(format!("PID:{}", flow.pid)),
            verdict: Some("flow".to_string()),
            file: Some(format!("{} (PID:{})", flow.process_name, flow.pid)),
            size: None,
            ms: None,
            threat: flow.hostname.clone(),
            detail: Some(detail_str),
            sha256: None,
            message: Some(format!("Host:{}", batch.machine_id)),
            origin_type: Some("EDR-Network".to_string()),
        });
    }

    Json(serde_json::json!({
        "status": "ok",
        "ingested": count
    }))
}

/// Handler for POST /api/v1/edr/telemetry/threat and POST /api/v1/edr/report
pub async fn handle_edr_telemetry_threat(
    State(app): State<Arc<AppState>>,
    Json(report): Json<ThreatReport>,
) -> impl IntoResponse {
    app.edr_telemetry.add_threat(&report);

    app.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_threat".to_string(),
        session: None,
        client: Some(format!("PID:{}", report.pid.unwrap_or(0))),
        verdict: Some("malicious".to_string()),
        file: Some(report.file_name.clone()),
        size: None,
        ms: None,
        threat: Some(report.detection.clone()),
        detail: Some(format!("source:{} path:{}", report.source, report.original_path)),
        sha256: Some(report.sha256.clone()),
        message: None,
        origin_type: Some("EDR-Threat".to_string()),
    });

    Json(serde_json::json!({
        "status": "ok",
        "need_sample": false,
        "message": "Threat recorded by Multron Server"
    }))
}

/// Handler for POST /api/v1/edr/telemetry/report
pub async fn handle_edr_telemetry_report(
    State(app): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let host = payload
        .get("machine_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    app.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_report".to_string(),
        session: None,
        client: Some(host.to_string()),
        verdict: Some("info".to_string()),
        file: Some("System Diagnostic Report".to_string()),
        size: None,
        ms: None,
        threat: None,
        detail: Some(format!("System diagnostic report from {}", host)),
        sha256: None,
        message: None,
        origin_type: Some("EDR-Diagnostic".to_string()),
    });

    Json(serde_json::json!({
        "status": "ok",
        "need_sample": false,
        "message": "Diagnostic report received"
    }))
}

/// Handler for POST /api/v1/edr/upload/:sha256 (sample upload)
pub async fn handle_edr_upload(
    State(app): State<Arc<AppState>>,
    AxumPath(sha256): AxumPath<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let len = body.len();
    app.events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_threat".to_string(),
        session: None,
        client: None,
        verdict: Some("malicious".to_string()),
        file: Some(format!("Sample Upload ({len} bytes)")),
        size: Some(len as i64),
        ms: None,
        threat: Some("Sample.Received".to_string()),
        detail: Some(format!("Received uploaded sample {sha256}")),
        sha256: Some(sha256.clone()),
        message: None,
        origin_type: Some("EDR-Sample".to_string()),
    });

    Json(serde_json::json!({
        "status": "ok",
        "sha256": sha256,
        "bytes_received": len
    }))
}

/// Handler for GET /api/v1/edr/telemetry/stats
pub async fn handle_get_edr_stats(
    State(app): State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(app.edr_telemetry.get_stats())
}

/// Handler for GET /api/v1/edr/telemetry/behaviors
pub async fn handle_get_edr_behaviors(
    State(app): State<Arc<AppState>>,
    Query(query): Query<TelemetryQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).min(500);
    let items = app.edr_telemetry.get_behaviors(limit, query.risk.as_deref(), query.q.as_deref());
    Json(serde_json::json!({
        "total": items.len(),
        "behaviors": items
    }))
}

/// Handler for GET /api/v1/edr/telemetry/flows
pub async fn handle_get_edr_flows(
    State(app): State<Arc<AppState>>,
    Query(query): Query<TelemetryQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(200).min(1000);
    let items = app.edr_telemetry.get_flows(limit, query.q.as_deref());
    Json(serde_json::json!({
        "total": items.len(),
        "flows": items
    }))
}

/// Handler for GET /api/v1/edr/telemetry/threats
pub async fn handle_get_edr_threats(
    State(app): State<Arc<AppState>>,
    Query(query): Query<TelemetryQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).min(500);
    let items = app.edr_telemetry.get_threats(limit);
    Json(serde_json::json!({
        "total": items.len(),
        "threats": items
    }))
}
