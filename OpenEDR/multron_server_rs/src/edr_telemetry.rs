use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::AppState;
use crate::events::Event;

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
    for flow in &batch.flows {
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

/// Handler for POST /api/v1/edr/telemetry/threat
pub async fn handle_edr_telemetry_threat(
    State(app): State<Arc<AppState>>,
    Json(report): Json<ThreatReport>,
) -> impl IntoResponse {
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
        "status": "ok"
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
        "status": "ok"
    }))
}
