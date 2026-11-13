use axum::extract::{Path as AxumPath, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use crate::dashboard::AppState;
use crate::events::{Event, EventLog};

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

/// The live telemetry: the newest records in memory (what the dashboard polls) and,
/// when opened with [`EdrTelemetryStore::open`], every record kept in SQLite
/// (`edr_db`), read back at start and asked for searches and filters.
pub struct EdrTelemetryStore {
    inner: RwLock<EdrStoreInner>,
    db: Option<crate::edr_db::EdrDb>,
}

impl Default for EdrTelemetryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrTelemetryStore {
    /// A store that keeps only the in-memory window (nothing survives a restart).
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(EdrStoreInner::default()),
            db: None,
        }
    }

    /// A store backed by the SQLite history at `path`: the newest records and the
    /// totals are read back from it. When it cannot be opened the store runs in
    /// memory only, as before, and says so.
    pub fn open(path: &std::path::Path) -> Self {
        let db = match crate::edr_db::EdrDb::open(path) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("[EDR] telemetry history {} unavailable ({e}); keeping it in memory only", path.display());
                return Self::new();
            }
        };
        let mut inner = EdrStoreInner::default();
        match db.stats() {
            Ok(stats) => inner.stats = stats,
            Err(e) => eprintln!("[EDR] could not count the telemetry history: {e}"),
        }
        match db.behaviors(MAX_STORED_BEHAVIORS, None, None) {
            Ok(rows) => inner.behaviors = rows.into(),
            Err(e) => eprintln!("[EDR] could not read stored behaviors: {e}"),
        }
        match db.flows(MAX_STORED_FLOWS, None) {
            Ok(rows) => inner.flows = rows.into(),
            Err(e) => eprintln!("[EDR] could not read stored flows: {e}"),
        }
        match db.threats(MAX_STORED_THREATS) {
            Ok(rows) => inner.threats = rows.into(),
            Err(e) => eprintln!("[EDR] could not read stored threats: {e}"),
        }
        // A record that fails to reach the database takes its id from this counter;
        // keep it past the stored ones.
        inner.next_id = [
            inner.behaviors.front().map(|b| b.id),
            inner.flows.front().map(|f| f.id),
            inner.threats.front().map(|t| t.id),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0);
        Self {
            inner: RwLock::new(inner),
            db: Some(db),
        }
    }

    /// The record's id: its row id in the history, or the next in-memory id when
    /// there is no history (or the write failed; the record then stays live in memory).
    fn assign_id(g: &mut EdrStoreInner, written: Option<rusqlite::Result<u64>>, what: &str) -> u64 {
        match written {
            Some(Ok(id)) => {
                g.next_id = g.next_id.max(id);
                id
            }
            Some(Err(e)) => {
                eprintln!("[EDR] could not store {what} in the telemetry history: {e}");
                g.next_id += 1;
                g.next_id
            }
            None => {
                g.next_id += 1;
                g.next_id
            }
        }
    }

    pub fn add_behavior(&self, payload: BehaviorTelemetryPayload, verdict: String, threat_name: Option<String>) {
        if let Ok(mut g) = self.inner.write() {
            let time_iso = Utc::now().to_rfc3339();

            g.stats.total_behaviors += 1;
            match verdict.as_str() {
                "malicious" => g.stats.malicious_behaviors += 1,
                "suspicious" => g.stats.suspicious_behaviors += 1,
                _ => g.stats.clean_behaviors += 1,
            }

            let mut item = StoredBehavior {
                id: 0,
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

            let written = self.db.as_ref().map(|db| db.insert_behavior(&item));
            item.id = Self::assign_id(&mut g, written, "a behavior");
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
            let mut items: Vec<StoredFlow> = flows
                .iter()
                .map(|f| StoredFlow {
                    id: 0,
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
                })
                .collect();
            let stored = match self.db.as_ref().map(|db| db.insert_flows(&mut items)) {
                Some(Ok(())) => true,
                Some(Err(e)) => {
                    eprintln!("[EDR] could not store {} flows in the telemetry history: {e}", items.len());
                    false
                }
                None => false,
            };
            for mut item in items {
                g.stats.total_flows += 1;
                if stored {
                    g.next_id = g.next_id.max(item.id);
                } else {
                    g.next_id += 1;
                    item.id = g.next_id;
                }
                g.flows.push_front(item);
                if g.flows.len() > MAX_STORED_FLOWS {
                    g.flows.pop_back();
                }
            }
        }
    }

    pub fn add_threat(&self, report: &ThreatReport) {
        if let Ok(mut g) = self.inner.write() {
            g.stats.total_threats += 1;
            let time_iso = Utc::now().to_rfc3339();
            let mut item = StoredThreat {
                id: 0,
                timestamp: Utc::now().timestamp() as u64,
                time_iso,
                sha256: report.sha256.clone(),
                file_name: report.file_name.clone(),
                original_path: report.original_path.clone(),
                detection: report.detection.clone(),
                source: report.source.clone(),
                pid: report.pid,
            };
            let written = self.db.as_ref().map(|db| db.insert_threat(&item));
            item.id = Self::assign_id(&mut g, written, "a threat report");
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
        let q_lower = q.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
        let risk_lower = risk_filter.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty() && s != "all");

        // A filter or a search looks through the whole history; the newest records
        // alone are the in-memory window.
        let wants_history = q_lower.is_some() || risk_lower.is_some() || limit > MAX_STORED_BEHAVIORS;
        if let Some(db) = self.db.as_ref().filter(|_| wants_history) {
            match db.behaviors(limit, risk_lower.as_deref(), q_lower.as_deref()) {
                Ok(rows) => return rows,
                Err(e) => eprintln!("[EDR] behavior history query failed ({e}); answering from memory"),
            }
        }

        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

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
        let q_lower = q.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());

        if let Some(db) = self.db.as_ref().filter(|_| q_lower.is_some() || limit > MAX_STORED_FLOWS) {
            match db.flows(limit, q_lower.as_deref()) {
                Ok(rows) => return rows,
                Err(e) => eprintln!("[EDR] flow history query failed ({e}); answering from memory"),
            }
        }

        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

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
        if let Some(db) = self.db.as_ref().filter(|_| limit > MAX_STORED_THREATS) {
            match db.threats(limit) {
                Ok(rows) => return rows,
                Err(e) => eprintln!("[EDR] threat history query failed ({e}); answering from memory"),
            }
        }
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
    Json(ingest_behavior(&app.edr_telemetry, &app.events, payload))
}

/// Records one behavior record (EDR store + live feed) and returns the verdict
/// the client acts on. Shared by the dashboard and the public API routes.
/// Sources whose detection name is the title of a matched rule with a severity
/// of its own, carried in `risk_score` (Sigma level: critical 1.0, high 0.85,
/// medium 0.6, anything lower 0.3). For every other source a detection name is
/// a verdict the agent already acted on.
const GRADED_DETECTION_SOURCES: &[&str] = &["sigma_event_log"];

const MALICIOUS_RISK_SCORE: f32 = 0.75;
const SUSPICIOUS_RISK_SCORE: f32 = 0.40;

/// `(is_malicious, is_suspicious)` of a behavior report.
///
/// A named detection is malicious, except from a graded source: there the name
/// only says which rule matched, so the severity decides and a low / medium
/// match is suspicious, not malicious.
fn behavior_severity(payload: &BehaviorTelemetryPayload) -> (bool, bool) {
    let named_detection = !payload.detection.is_empty() && payload.detection != "Clean";
    let graded = GRADED_DETECTION_SOURCES.iter().any(|s| payload.source.eq_ignore_ascii_case(s));

    let is_malicious = payload.risk_score >= MALICIOUS_RISK_SCORE || (named_detection && !graded);
    let is_suspicious =
        payload.risk_score >= SUSPICIOUS_RISK_SCORE || !payload.indicators.is_empty() || (named_detection && graded);
    (is_malicious, is_suspicious)
}

pub fn ingest_behavior(store: &EdrTelemetryStore, events: &EventLog, payload: BehaviorTelemetryPayload) -> serde_json::Value {
    let (is_malicious, is_suspicious) = behavior_severity(&payload);

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
    store.add_behavior(payload.clone(), verdict.to_string(), threat_name.clone());

    // Also push to Live Feed EventLog
    events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_behavior".to_string(),
        session: None,
        client: Some(format!("PID:{}", payload.pid)),
        verdict: Some(verdict.to_string()),
        file: Some(format!("{} (PID:{})", payload.process_name, payload.pid)),
        size: None,
        ms: None,
        items: None,
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

    serde_json::json!({
        "status": "ok",
        "verdict": verdict,
        "threat_name": threat_name,
        "action": action,
        "confidence": payload.risk_score,
        "reason": format!("Evaluated by Multron Server EDR engine (score: {:.2})", payload.risk_score),
        "need_sample": is_malicious
    })
}

/// Handler for POST /api/v1/edr/telemetry/network-flows
pub async fn handle_edr_telemetry_network_flows(
    State(app): State<Arc<AppState>>,
    Json(batch): Json<NetworkFlowBatch>,
) -> impl IntoResponse {
    Json(ingest_flows(&app.edr_telemetry, &app.events, &batch))
}

/// Records a batch of network flows (EDR store + at most 5 live-feed lines).
pub fn ingest_flows(store: &EdrTelemetryStore, events: &EventLog, batch: &NetworkFlowBatch) -> serde_json::Value {
    let count = batch.flows.len();

    // Store in structured telemetry store
    store.add_flows(&batch.machine_id, &batch.flows);

    // Log sample flows in EventLog (at most 5 to avoid flooding)
    for flow in batch.flows.iter().take(5) {
        let detail_str = format!(
            "{}:{} -> {}:{} ({})",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
        );

        events.add(Event {
            seq: 0,
            time: Utc::now(),
            kind: "edr_flow".to_string(),
            session: None,
            client: Some(format!("PID:{}", flow.pid)),
            verdict: Some("flow".to_string()),
            file: Some(format!("{} (PID:{})", flow.process_name, flow.pid)),
            size: None,
            ms: None,
            items: None,
            threat: flow.hostname.clone(),
            detail: Some(detail_str),
            sha256: None,
            message: Some(format!("Host:{}", batch.machine_id)),
            origin_type: Some("EDR-Network".to_string()),
        });
    }

    serde_json::json!({
        "status": "ok",
        "ingested": count
    })
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
        items: None,
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
    Json(ingest_system_report(&app.events, &payload))
}

/// Records a system diagnostic report (live feed). Shared by the dashboard's
/// /api/v1/edr/telemetry/report and the public /api/v1/edr/telemetry/system.
pub fn ingest_system_report(events: &EventLog, payload: &serde_json::Value) -> serde_json::Value {
    let host = payload
        .get("machine_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_report".to_string(),
        session: None,
        client: Some(host.to_string()),
        verdict: Some("info".to_string()),
        file: Some("System Diagnostic Report".to_string()),
        size: None,
        ms: None,
        items: None,
        threat: None,
        detail: Some(format!("System diagnostic report from {}", host)),
        sha256: None,
        message: None,
        origin_type: Some("EDR-Diagnostic".to_string()),
    });

    serde_json::json!({
        "status": "ok",
        "need_sample": false,
        "message": "Diagnostic report received"
    })
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
        items: None,
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

// ------------------------------------------------------------------ kill chains
// Unknown-process kill chain events from OpenEDR clients in training mode
// (owlyshield_predict/src/killchain_upload.rs): each distinct event shape once, with
// how often it occurred, merged across machines. Kept for good, like the rest of the
// EDR history; the kill chain trainer reads them back with the export below.

/// Decompressed size a kill chain upload may have.
pub const KILLCHAIN_MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;
/// Records / repeat counts one upload may carry.
const KILLCHAIN_MAX_ITEMS: usize = 20_000;

#[derive(Debug, Deserialize)]
pub struct KillchainRecord {
    pub key: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub raw: serde_json::Value,
    #[serde(default = "one")]
    pub count: u64,
}

fn one() -> u64 {
    1
}

#[derive(Debug, Deserialize)]
pub struct KillchainBatch {
    #[serde(default)]
    pub machine_id: String,
    #[serde(default)]
    pub records: Vec<KillchainRecord>,
    #[serde(default)]
    pub counts: std::collections::BTreeMap<String, u64>,
}

/// A client key: 16 lowercase hex digits.
fn valid_killchain_key(k: &str) -> bool {
    k.len() == 16 && k.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The request body as JSON bytes: brotli-decoded when `brotli`, never more than
/// `KILLCHAIN_MAX_JSON_BYTES` (a decompression bomb stops there).
pub fn killchain_body(body: &[u8], brotli: bool) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    let limit = KILLCHAIN_MAX_JSON_BYTES + 1;
    let n = if brotli {
        brotli_decompressor::Decompressor::new(body, 4096)
            .take(limit)
            .read_to_end(&mut out)
            .map_err(|e| format!("brotli decompression failed: {e}"))?
    } else {
        body.take(limit).read_to_end(&mut out).map_err(|e| e.to_string())?
    };
    if n as u64 > KILLCHAIN_MAX_JSON_BYTES {
        return Err("upload larger than 64 MB decompressed".into());
    }
    Ok(out)
}

impl EdrTelemetryStore {
    /// Merges a kill chain upload into the history. Err when there is no history
    /// database (the data is not kept in memory) or the write failed.
    pub fn ingest_killchain(&self, batch: &KillchainBatch) -> Result<(u64, u64), String> {
        let db = self.db.as_ref().ok_or("no EDR telemetry database")?;
        if batch.records.len() + batch.counts.len() > KILLCHAIN_MAX_ITEMS {
            return Err(format!("more than {KILLCHAIN_MAX_ITEMS} items in one upload"));
        }
        let machine = batch.machine_id.chars().take(128).collect::<String>();
        let records: Vec<(String, u64, String)> = batch
            .records
            .iter()
            .filter(|r| valid_killchain_key(&r.key))
            .map(|r| {
                // The stored event is an edrsvc log line, so the trainer reads exported
                // rows exactly like its local unknown_killchain_*.jsonl files.
                let line = serde_json::json!({
                    "date": r.date,
                    "time": r.time,
                    "exe": r.exe,
                    "event": r.event,
                    "details": r.details,
                    "raw": r.raw,
                    "machine_id": machine,
                });
                (r.key.clone(), r.count.max(1), line.to_string())
            })
            .collect();
        let counts: Vec<(String, u64)> = batch
            .counts
            .iter()
            .filter(|(k, _)| valid_killchain_key(k))
            .map(|(k, c)| (k.clone(), *c))
            .collect();
        db.merge_killchain(&machine, &Utc::now().to_rfc3339(), &records, &counts)
            .map_err(|e| e.to_string())
    }

    /// (distinct event shapes, events they stand for); zeros without a database.
    pub fn killchain_totals(&self) -> (u64, u64) {
        self.db.as_ref().and_then(|db| db.killchain_totals().ok()).unwrap_or((0, 0))
    }

    /// Every stored kill chain event as JSON lines (see `EdrDb::export_killchain`).
    pub fn export_killchain(&self) -> Result<(Vec<u8>, u64), String> {
        let db = self.db.as_ref().ok_or("no EDR telemetry database")?;
        let mut out = Vec::new();
        let n = db.export_killchain(&mut out).map_err(|e| e.to_string())?;
        Ok((out, n))
    }
}

/// Handler for GET /api/v1/edr/telemetry/killchain/stats
pub async fn handle_get_killchain_stats(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let (shapes, events) = app.edr_telemetry.killchain_totals();
    Json(serde_json::json!({ "shapes": shapes, "events": events }))
}

/// Handler for GET /api/v1/edr/telemetry/killchain/export: the kill chain training
/// set as JSON lines (`train_kc_hybrid.py <file>` reads it).
pub async fn handle_export_killchain(State(app): State<Arc<AppState>>) -> axum::response::Response {
    let store = Arc::clone(&app.edr_telemetry);
    let result = tokio::task::spawn_blocking(move || store.export_killchain()).await;
    match result {
        Ok(Ok((body, _))) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/x-ndjson"),
                (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"killchain_events.jsonl\""),
            ],
            body,
        )
            .into_response(),
        Ok(Err(e)) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn killchain_uploads_merge_by_key() {
        let p = std::env::temp_dir().join(format!("edr_db_{}_killchain.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let store = EdrTelemetryStore::open(&p);
        let rec = |key: &str, count| KillchainRecord {
            key: key.into(),
            date: "20261114".into(),
            time: "01:02:03.004".into(),
            exe: "%systemroot%\\system32\\svchost.exe".into(),
            event: "LLE_FILE_MAP_READ".into(),
            details: " [File: C:\\x.dll]".into(),
            raw: serde_json::json!({"accessMask": 2}),
            count,
        };
        let first = KillchainBatch {
            machine_id: "m1".into(),
            records: vec![rec("00000000000000aa", 3), rec("not-a-key", 1)],
            counts: Default::default(),
        };
        assert_eq!(store.ingest_killchain(&first).unwrap(), (1, 0), "invalid keys are dropped");
        let second = KillchainBatch {
            machine_id: "m2".into(),
            records: vec![rec("00000000000000aa", 2), rec("00000000000000bb", 1)],
            counts: [("00000000000000aa".to_string(), 5)].into(),
        };
        assert_eq!(store.ingest_killchain(&second).unwrap(), (1, 1));
        assert_eq!(store.killchain_totals(), (2, 3 + 2 + 5 + 1));
        let (body, n) = store.export_killchain().unwrap();
        assert_eq!(n, 2);
        let first_row: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&body).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(first_row["event"], "LLE_FILE_MAP_READ");
        assert_eq!(first_row["raw"]["accessMask"], 2);
        assert_eq!(first_row["machines"], 2, "seen on two machines");
        assert_eq!(first_row["machine_id"], "m1", "the first event is kept");
        drop(store);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn killchain_body_is_bounded() {
        assert!(killchain_body(b"{}", false).is_ok());
        assert!(killchain_body(b"not brotli", true).is_err());
    }

    fn report(source: &str, detection: &str, risk_score: f32, indicators: &[&str]) -> BehaviorTelemetryPayload {
        BehaviorTelemetryPayload {
            machine_id: "m".to_string(),
            timestamp: 0,
            pid: 1,
            gid: 0,
            process_name: "p.exe".to_string(),
            exe_path: r"C:\p.exe".to_string(),
            command_line: String::new(),
            sha256: String::new(),
            parent_pid: None,
            parent_name: None,
            detection: detection.to_string(),
            source: source.to_string(),
            risk_score,
            indicators: indicators.iter().map(|s| s.to_string()).collect(),
            ops_summary: None,
            details: serde_json::Value::Null,
        }
    }

    #[test]
    fn sigma_matches_are_graded_by_their_level() {
        let sigma = |score| report("sigma_event_log", "Sigma.Some.Rule", score, &["Sigma Level: x"]);
        // critical / high: malicious
        assert_eq!(behavior_severity(&sigma(1.0)), (true, true));
        assert_eq!(behavior_severity(&sigma(0.85)), (true, true));
        // medium / low: suspicious, not malicious
        assert_eq!(behavior_severity(&sigma(0.6)), (false, true));
        assert_eq!(behavior_severity(&sigma(0.3)), (false, true));
    }

    #[test]
    fn a_named_detection_from_any_other_source_is_malicious() {
        assert!(behavior_severity(&report("openedr_detnotif", "MLE_GODMODE_ACTIVITY", 1.0, &[])).0);
        // Even with a low score: the agent already acted on the verdict.
        assert!(behavior_severity(&report("ransomware", "Ransom.Generic", 0.1, &[])).0);
    }

    #[test]
    fn reports_without_a_detection_follow_the_score_and_the_indicators() {
        assert_eq!(behavior_severity(&report("generic", "", 0.1, &[])), (false, false));
        assert_eq!(behavior_severity(&report("generic", "Clean", 0.1, &[])), (false, false));
        assert_eq!(behavior_severity(&report("generic", "", 0.5, &[])), (false, true));
        assert_eq!(behavior_severity(&report("generic", "", 0.1, &["x"])), (false, true));
        assert_eq!(behavior_severity(&report("generic", "", 0.9, &[])), (true, true));
    }

    fn tmp_db(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("edr_db_{}_{name}.db", std::process::id()));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", p.display()));
        }
        p
    }

    fn flow(dst_ip: &str) -> NetworkFlowRecord {
        NetworkFlowRecord {
            timestamp: 0,
            pid: 7,
            process_name: "Net.exe".to_string(),
            src_ip: "10.0.0.1".to_string(),
            src_port: 5000,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            protocol: "TCP".to_string(),
            hostname: None,
        }
    }

    #[test]
    fn history_survives_a_restart_and_searches_past_the_memory_window() {
        let path = tmp_db("restart");
        {
            let store = EdrTelemetryStore::open(&path);
            let events = EventLog::new(false);
            let mut old = report("generic", "", 0.9, &[]);
            old.process_name = "OldDropper.exe".to_string();
            ingest_behavior(&store, &events, old);
            for _ in 0..MAX_STORED_BEHAVIORS {
                ingest_behavior(&store, &events, report("generic", "", 0.1, &[]));
            }
            store.add_flows("m", &[flow("1.2.3.4"), flow("5.6.7.8")]);
            store.add_threat(&ThreatReport {
                sha256: "ab".repeat(32),
                file_name: "x.exe".to_string(),
                original_path: r"C:\x.exe".to_string(),
                detection: "Trojan.X".to_string(),
                source: "edr".to_string(),
                pid: None,
                details: serde_json::Value::Null,
            });
            // The first behavior has left the memory window but a search still finds it.
            assert!(store.inner.read().unwrap().behaviors.iter().all(|b| b.process_name != "OldDropper.exe"));
            let found = store.get_behaviors(10, None, Some("olddropper"));
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].verdict, "malicious");
        }

        let store = EdrTelemetryStore::open(&path);
        let stats = store.get_stats();
        let total = MAX_STORED_BEHAVIORS as u64 + 1;
        assert_eq!(
            (stats.total_behaviors, stats.malicious_behaviors, stats.clean_behaviors, stats.total_flows, stats.total_threats),
            (total, 1, total - 1, 2, 1)
        );
        assert_eq!(store.get_behaviors(5, None, None).len(), 5);
        assert_eq!(store.get_behaviors(5, Some("malicious"), None).len(), 1);
        let flows = store.get_flows(10, None);
        assert_eq!(flows.iter().map(|f| f.dst_ip.as_str()).collect::<Vec<_>>(), ["5.6.7.8", "1.2.3.4"]);
        assert_eq!(store.get_flows(10, Some("5.6.7")).len(), 1);
        assert_eq!(store.get_threats(10)[0].detection, "Trojan.X");

        // New records continue the ids after the stored ones.
        let before = store.get_behaviors(1, None, None)[0].id;
        store.add_behavior(report("generic", "", 0.1, &[]), "clean".to_string(), None);
        assert!(store.get_behaviors(1, None, None)[0].id > before);
    }

    #[test]
    fn ingest_counts_a_medium_sigma_match_as_suspicious() {
        let store = EdrTelemetryStore::new();
        let events = EventLog::new(false);
        let body = ingest_behavior(&store, &events, report("sigma_event_log", "Sigma.Some.Rule", 0.6, &["Sigma Level: medium"]));
        assert_eq!(body["verdict"], "suspicious");
        assert_eq!(body["need_sample"], false);
        let stats = store.get_stats();
        assert_eq!((stats.malicious_behaviors, stats.suspicious_behaviors, stats.clean_behaviors), (0, 1, 0));
    }
}
