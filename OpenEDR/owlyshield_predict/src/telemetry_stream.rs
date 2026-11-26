//! Lossless, unlimited raw EDR & Agent SysOps telemetry uploader targeting
//! VirusKov (`POST /api/v1/edr/telemetry/events` with `Content-Encoding: br`).
//!
//! Unlike `killchain_upload.rs` (which deduplicates events by shape for ML training),
//! this stream preserves every enriched `LLE_*` / `MLE_*` event and every
//! `AGENT_*` lifecycle event verbatim with no deduplication and no retention cap.
//! Opt-out only when `OWLY_EDR_EVENTS_UPLOAD=0` is set in the environment.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::logging::Logging;

pub const TELEMETRY_EVENTS_PATH: &str = "/api/v1/edr/telemetry/events";

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const BATCH_MAX_RECORDS: usize = 500;
const BATCH_MAX_BYTES: usize = 2 * 1024 * 1024;
const SYNC_SYSOP_TIMEOUT_MS: u32 = 3000;
const ENRICH_QUEUE_CAPACITY: usize = 65_536;

static STARTED: AtomicBool = AtomicBool::new(false);
static LAST_STATUS: AtomicU32 = AtomicU32::new(200);
static ENRICH_TX: OnceLock<SyncSender<RawTelemetryJob>> = OnceLock::new();

struct RawTelemetryJob {
    event_type: String,
    exe_path: String,
    pid_override: Option<u32>,
    details: Option<String>,
    raw: serde_json::Value,
    hash_files: bool,
    forward_to_killchain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEventRecord {
    pub timestamp: u64,
    pub time_iso: String,
    pub event_type: String,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct EdrEventBatch<'a> {
    machine_id: &'a str,
    events: &'a [EdrEventRecord],
}

#[derive(Default)]
struct StreamState {
    pending: VecDeque<(EdrEventRecord, usize)>,
    total_bytes: usize,
    in_flight: bool,
    flush_requested: bool,
}

struct StreamSync {
    state: Mutex<StreamState>,
    wake: Condvar,
    drained: Condvar,
}

fn sync_hub() -> &'static StreamSync {
    static HUB: OnceLock<StreamSync> = OnceLock::new();
    HUB.get_or_init(|| StreamSync {
        state: Mutex::new(StreamState::default()),
        wake: Condvar::new(),
        drained: Condvar::new(),
    })
}

fn is_disabled() -> bool {
    std::env::var("OWLY_EDR_EVENTS_UPLOAD").is_ok_and(|v| {
        let t = v.trim();
        t == "0" || t.eq_ignore_ascii_case("false")
    })
}

fn basename_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or("").to_string()
}

fn extract_pid_from_raw(raw: &serde_json::Value) -> u32 {
    raw.get("process")
        .and_then(|p| p.get("pid"))
        .or_else(|| raw.get("sourceProcessPid"))
        .or_else(|| raw.get("pid"))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

fn build_record(
    event_type: &str,
    exe_path: &str,
    pid_override: Option<u32>,
    details: Option<&str>,
    raw: serde_json::Value,
) -> (EdrEventRecord, usize) {
    let now = chrono::Utc::now();
    let pid = pid_override.unwrap_or_else(|| extract_pid_from_raw(&raw));
    let mut process_name = basename_of(exe_path);
    if process_name.is_empty() {
        process_name = raw
            .get("process")
            .and_then(|p| p.get("imageFile"))
            .and_then(|f| f.get("path"))
            .or_else(|| raw.get("process").and_then(|p| p.get("name")))
            .and_then(|v| v.as_str())
            .map(basename_of)
            .unwrap_or_default();
    }
    let est_bytes = 96
        + event_type.len()
        + exe_path.len()
        + process_name.len()
        + details.map_or(0, str::len)
        + raw.to_string().len();

    let rec = EdrEventRecord {
        timestamp: now.timestamp().max(0) as u64,
        time_iso: now.to_rfc3339(),
        event_type: event_type.to_string(),
        pid,
        process_name,
        exe_path: exe_path.to_string(),
        details: details.filter(|d| !d.is_empty()).map(str::to_string),
        raw,
    };
    (rec, est_bytes)
}

fn log_outcome(res: &Result<(u32, Vec<u8>), String>) {
    let code = match res {
        Ok((st, _)) => *st,
        Err(_) => 0,
    };
    if LAST_STATUS.swap(code, Ordering::Relaxed) == code {
        return;
    }
    match res {
        Ok((st, _)) if (200..300).contains(st) => {
            Logging::info("[Telemetry Stream] Raw EDR event delivery recovered (HTTP 200)");
        }
        Ok((st, body)) => {
            let text = String::from_utf8_lossy(&body[..body.len().min(256)]);
            Logging::warning(&format!(
                "[Telemetry Stream] Server returned HTTP {st}: {text}"
            ));
        }
        Err(e) => {
            Logging::warning(&format!("[Telemetry Stream] Delivery failed: {e}"));
        }
    }
}

enum SendOutcome {
    Ok,
    Retry,
    TooLarge,
    DropBadPayload,
}

fn send_batch(records: &[EdrEventRecord], timeout_ms: Option<u32>) -> SendOutcome {
    if records.is_empty() || is_disabled() {
        return SendOutcome::Ok;
    }
    let machine_id = crate::edr_feedback::get_machine_guid();
    let batch = EdrEventBatch {
        machine_id: &machine_id,
        events: records,
    };
    let Ok(json_bytes) = serde_json::to_vec(&batch) else {
        return SendOutcome::DropBadPayload;
    };
    let (content_encoding, body) = match crate::edr_feedback::compress_brotli(&json_bytes) {
        Ok(br) => (Some("br"), br),
        Err(_) => (None, json_bytes),
    };
    let res = match timeout_ms {
        Some(ms) => crate::edr_feedback::post_to_server_timeout(
            TELEMETRY_EVENTS_PATH,
            "application/json",
            content_encoding,
            &body,
            ms,
        ),
        None => crate::edr_feedback::post_to_server(
            TELEMETRY_EVENTS_PATH,
            "application/json",
            content_encoding,
            &body,
        ),
    };
    log_outcome(&res);
    match res {
        Ok((st, _)) if (200..300).contains(&st) => SendOutcome::Ok,
        Ok((413, _)) if records.len() > 1 => SendOutcome::TooLarge,
        Ok((400, _)) => SendOutcome::DropBadPayload,
        _ => SendOutcome::Retry,
    }
}

fn enqueue_record(rec: EdrEventRecord, est_bytes: usize) {
    start();
    let hub = sync_hub();
    let Ok(mut g) = hub.state.lock() else {
        return;
    };
    g.total_bytes = g.total_bytes.saturating_add(est_bytes);
    g.pending.push_back((rec, est_bytes));
    if g.pending.len() >= BATCH_MAX_RECORDS || g.total_bytes >= BATCH_MAX_BYTES {
        hub.wake.notify_all();
    }
}

pub(crate) fn extract_best_file_path(raw: &serde_json::Value, exe_path: &str) -> Option<String> {
    const POINTERS: &[&str] = &[
        "/file/abstractPath",
        "/file/rawPath",
        "/file/path",
        "/file/uniquePath",
        "/file/renameTarget",
        "/driver_path",
        "/driver/image",
        "/process/imageFile/abstractPath",
        "/process/imageFile/rawPath",
        "/process/imageFile/path",
        "/image_path",
    ];
    for ptr in POINTERS {
        if let Some(s) = raw.pointer(ptr).and_then(|v| v.as_str()) {
            if !s.is_empty() && s != "<undefined>" {
                return Some(s.to_string());
            }
        }
    }
    if !exe_path.is_empty() {
        return Some(exe_path.to_string());
    }
    None
}

fn extract_registry_path(raw: &serde_json::Value) -> Option<String> {
    for ptr in [
        "/registry/abstractPath",
        "/registry/rawPath",
        "/registry/path",
    ] {
        if let Some(s) = raw.pointer(ptr).and_then(|v| v.as_str()) {
            if !s.is_empty() && s != "<undefined>" {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn extract_registry_value_name(raw: &serde_json::Value) -> String {
    raw.pointer("/registry/name")
        .or_else(|| raw.pointer("/registry/valueName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn extract_registry_data_str(raw: &serde_json::Value) -> String {
    raw.pointer("/registry/data")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn parse_zone_identifier_ini(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut zone_id = None;
    let mut referrer = None;
    let mut host_url = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(v) = t
            .strip_prefix("ZoneId=")
            .or_else(|| t.strip_prefix("zoneid="))
        {
            zone_id = Some(v.trim().to_string());
        } else if let Some(v) = t
            .strip_prefix("ReferrerUrl=")
            .or_else(|| t.strip_prefix("referrerurl="))
        {
            referrer = Some(v.trim().to_string());
        } else if let Some(v) = t
            .strip_prefix("HostUrl=")
            .or_else(|| t.strip_prefix("hosturl="))
        {
            host_url = Some(v.trim().to_string());
        }
    }
    (zone_id, referrer, host_url)
}

pub(crate) fn should_hash_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "LLE_PROCESS_CREATE"
            | "LLE_IMAGE_LOAD"
            | "LLE_DRIVER_LOAD"
            | "LLE_FILE_CREATE"
            | "LLE_FILE_DATA_CHANGE"
            | "LLE_FILE_RENAME"
            | "FILE_DOWNLOADED"
            | "DRIVER_LOADED"
            | "DRIVER_MODIFIED"
            | "SANCTUM_HVCI_BLOCK"
            | "MBR_SECTOR0_RAW_WRITE"
            | "LLE_DISK_RAW_WRITE_ACCESS"
    ) || event_type.starts_with("MLE_")
}

fn derive_high_signal_events(
    event_type: &str,
    exe_path: &str,
    pid_override: Option<u32>,
    raw: &mut serde_json::Value,
    hash_fn: &dyn Fn(&str) -> Option<crate::pe_hashes::FileHashes>,
    motw_fn: &mut dyn FnMut(&str) -> Option<String>,
) -> Vec<RawTelemetryJob> {
    let mut derived = Vec::new();
    let pid = pid_override.unwrap_or_else(|| extract_pid_from_raw(raw));

    if let Some(obj) = raw.as_object_mut() {
        if event_type == "LLE_NAMED_PIPE_SERVER_CREATE" {
            obj.entry("pipe_op")
                .or_insert_with(|| serde_json::json!("create"));
        } else if event_type == "LLE_NAMED_PIPE_CREATE" {
            obj.entry("pipe_op")
                .or_insert_with(|| serde_json::json!("connect"));
        }
    }

    if event_type == "LLE_PROCESS_CREATE" {
        if let Some(img) = extract_best_file_path(raw, exe_path) {
            if pid > 4 {
                crate::windows_telemetry::enqueue_tampering_check(pid, img);
            }
        }
    }

    let file_path = extract_best_file_path(raw, exe_path);
    if should_hash_event(event_type) && raw.get("hashes").is_none() {
        if let Some(ref p) = file_path {
            if !p.to_ascii_lowercase().ends_with(":zone.identifier") {
                if let Some(h) = hash_fn(p) {
                    if let Some(obj) = raw.as_object_mut() {
                        if let Ok(hv) = serde_json::to_value(h) {
                            obj.insert("hashes".to_string(), hv);
                        }
                    }
                }
            }
        }
    }

    // 1. Mark-of-the-Web (:Zone.Identifier ADS) -> FILE_DOWNLOADED
    if matches!(
        event_type,
        "LLE_FILE_CREATE" | "LLE_FILE_DATA_CHANGE" | "LLE_FILE_CLOSE"
    ) {
        if let Some(ref p) = file_path {
            if p.to_ascii_lowercase().ends_with(":zone.identifier") {
                if let Some(ini_text) = motw_fn(p) {
                    let (zone_id, referrer, host_url) = parse_zone_identifier_ini(&ini_text);
                    let base_path = &p[..p.len() - ":zone.identifier".len()];
                    let hashes = hash_fn(base_path);
                    derived.push(RawTelemetryJob {
                        event_type: "FILE_DOWNLOADED".to_string(),
                        exe_path: exe_path.to_string(),
                        pid_override: (pid > 0).then_some(pid),
                        details: Some(
                            host_url
                                .clone()
                                .or_else(|| referrer.clone())
                                .unwrap_or_else(|| base_path.to_string()),
                        ),
                        raw: serde_json::json!({
                            "file_path": base_path,
                            "zone_id": zone_id,
                            "referrer_url": referrer,
                            "url": host_url,
                            "hashes": hashes,
                            "source": "motw_ads",
                        }),
                        hash_files: false,
                        forward_to_killchain: true,
                    });
                }
            } else if p.to_ascii_lowercase().ends_with(".sys")
                && matches!(event_type, "LLE_FILE_DATA_CHANGE" | "LLE_FILE_RENAME")
            {
                let hashes = hash_fn(p);
                derived.push(RawTelemetryJob {
                    event_type: "DRIVER_MODIFIED".to_string(),
                    exe_path: exe_path.to_string(),
                    pid_override: (pid > 0).then_some(pid),
                    details: Some(format!("Driver image modified: {p}")),
                    raw: serde_json::json!({
                        "driver_path": p,
                        "hashes": hashes,
                        "source": "kernel_file_sys_corr",
                    }),
                    hash_files: false,
                    forward_to_killchain: true,
                });
            } else if p
                .to_ascii_lowercase()
                .contains("\\windows\\system32\\tasks\\")
                || p.to_ascii_lowercase().contains("\\windows\\tasks\\")
            {
                let task_evt = match event_type {
                    "LLE_FILE_CREATE" => Some("SCHEDULED_TASK_CREATE"),
                    "LLE_FILE_DATA_CHANGE" => Some("SCHEDULED_TASK_MODIFY"),
                    _ => None,
                };
                if let Some(te) = task_evt {
                    derived.push(RawTelemetryJob {
                        event_type: te.to_string(),
                        exe_path: exe_path.to_string(),
                        pid_override: (pid > 0).then_some(pid),
                        details: Some(p.clone()),
                        raw: serde_json::json!({
                            "task_name": p,
                            "source": "kernel_task_file_corr",
                        }),
                        hash_files: false,
                        forward_to_killchain: true,
                    });
                }
            } else if p.to_ascii_lowercase().contains("\\system32\\grouppolicy")
                && matches!(event_type, "LLE_FILE_CREATE" | "LLE_FILE_DATA_CHANGE")
            {
                derived.push(RawTelemetryJob {
                    event_type: "GROUP_POLICY_MODIFY".to_string(),
                    exe_path: exe_path.to_string(),
                    pid_override: (pid > 0).then_some(pid),
                    details: Some(p.clone()),
                    raw: serde_json::json!({
                        "path": p,
                        "source": "kernel_gpo_file_corr",
                    }),
                    hash_files: false,
                    forward_to_killchain: true,
                });
            }
        }
    }

    if event_type == "LLE_FILE_DELETE" {
        if let Some(ref p) = file_path {
            let lower = p.to_ascii_lowercase();
            if lower.contains("\\windows\\system32\\tasks\\")
                || lower.contains("\\windows\\tasks\\")
            {
                derived.push(RawTelemetryJob {
                    event_type: "SCHEDULED_TASK_DELETE".to_string(),
                    exe_path: exe_path.to_string(),
                    pid_override: (pid > 0).then_some(pid),
                    details: Some(p.clone()),
                    raw: serde_json::json!({
                        "task_name": p,
                        "source": "kernel_task_file_corr",
                    }),
                    hash_files: false,
                    forward_to_killchain: true,
                });
            }
        }
    }

    // 2. Registry High-Signal Correlators (Services, Drivers, Scheduled Tasks, Group Policy)
    if event_type.starts_with("LLE_REGISTRY_") {
        if let Some(reg_path) = extract_registry_path(raw) {
            let lower = reg_path.to_ascii_lowercase();
            if let Some(idx) = lower.find("\\services\\") {
                let after = &reg_path[idx + "\\services\\".len()..];
                let svc_name = after.split('\\').next().unwrap_or("").to_string();
                let is_root_svc = !svc_name.is_empty() && !after.contains('\\');
                if !svc_name.is_empty() && !svc_name.eq_ignore_ascii_case("enum") {
                    match event_type {
                        "LLE_REGISTRY_KEY_CREATE" if is_root_svc => {
                            derived.push(RawTelemetryJob {
                                event_type: "SERVICE_CREATE".to_string(),
                                exe_path: exe_path.to_string(),
                                pid_override: (pid > 0).then_some(pid),
                                details: Some(format!("Service key created: {svc_name}")),
                                raw: serde_json::json!({
                                    "service_name": svc_name,
                                    "registry_path": reg_path,
                                    "source": "kernel_reg_corr",
                                }),
                                hash_files: false,
                                forward_to_killchain: true,
                            });
                        }
                        "LLE_REGISTRY_KEY_DELETE" if is_root_svc => {
                            derived.push(RawTelemetryJob {
                                event_type: "SERVICE_DELETE".to_string(),
                                exe_path: exe_path.to_string(),
                                pid_override: (pid > 0).then_some(pid),
                                details: Some(format!("Service key deleted: {svc_name}")),
                                raw: serde_json::json!({
                                    "service_name": svc_name,
                                    "registry_path": reg_path,
                                    "source": "kernel_reg_corr",
                                }),
                                hash_files: false,
                                forward_to_killchain: true,
                            });
                        }
                        "LLE_REGISTRY_VALUE_SET" | "LLE_REGISTRY_VALUE_DELETE" => {
                            let val_name = extract_registry_value_name(raw);
                            let val_lower = val_name.to_ascii_lowercase();
                            if matches!(
                                val_lower.as_str(),
                                "imagepath"
                                    | "servicedll"
                                    | "start"
                                    | "type"
                                    | "objectname"
                                    | "failurecommand"
                            ) {
                                let data_str = extract_registry_data_str(raw);
                                derived.push(RawTelemetryJob {
                                    event_type: "SERVICE_MODIFY".to_string(),
                                    exe_path: exe_path.to_string(),
                                    pid_override: (pid > 0).then_some(pid),
                                    details: Some(format!("Service {svc_name} {val_name} changed")),
                                    raw: serde_json::json!({
                                        "service_name": svc_name,
                                        "value_name": val_name,
                                        "value_data": data_str,
                                        "registry_path": reg_path,
                                        "source": "kernel_reg_corr",
                                    }),
                                    hash_files: false,
                                    forward_to_killchain: true,
                                });
                                if val_lower == "imagepath"
                                    && data_str.to_ascii_lowercase().contains(".sys")
                                {
                                    derived.push(RawTelemetryJob {
                                        event_type: "DRIVER_MODIFIED".to_string(),
                                        exe_path: exe_path.to_string(),
                                        pid_override: (pid > 0).then_some(pid),
                                        details: Some(format!(
                                            "Driver service ImagePath updated: {svc_name} -> {data_str}"
                                        )),
                                        raw: serde_json::json!({
                                            "service_name": svc_name,
                                            "driver_path": data_str,
                                            "registry_path": reg_path,
                                            "source": "kernel_reg_corr",
                                        }),
                                        hash_files: false,
                                        forward_to_killchain: true,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else if lower.contains("\\schedule\\taskcache\\tree\\") {
                let task_evt = match event_type {
                    "LLE_REGISTRY_KEY_CREATE" => Some("SCHEDULED_TASK_CREATE"),
                    "LLE_REGISTRY_VALUE_SET" => Some("SCHEDULED_TASK_MODIFY"),
                    "LLE_REGISTRY_KEY_DELETE" => Some("SCHEDULED_TASK_DELETE"),
                    _ => None,
                };
                if let Some(te) = task_evt {
                    derived.push(RawTelemetryJob {
                        event_type: te.to_string(),
                        exe_path: exe_path.to_string(),
                        pid_override: (pid > 0).then_some(pid),
                        details: Some(reg_path.clone()),
                        raw: serde_json::json!({
                            "task_name": reg_path,
                            "source": "kernel_task_reg_corr",
                        }),
                        hash_files: false,
                        forward_to_killchain: true,
                    });
                }
            } else if (lower.contains("\\software\\policies\\")
                || lower.contains("\\currentversion\\policies\\"))
                && matches!(
                    event_type,
                    "LLE_REGISTRY_KEY_CREATE"
                        | "LLE_REGISTRY_VALUE_SET"
                        | "LLE_REGISTRY_KEY_DELETE"
                        | "LLE_REGISTRY_VALUE_DELETE"
                )
            {
                derived.push(RawTelemetryJob {
                    event_type: "GROUP_POLICY_MODIFY".to_string(),
                    exe_path: exe_path.to_string(),
                    pid_override: (pid > 0).then_some(pid),
                    details: Some(reg_path.clone()),
                    raw: serde_json::json!({
                        "registry_path": reg_path,
                        "value_name": extract_registry_value_name(raw),
                        "source": "kernel_gpo_reg_corr",
                    }),
                    hash_files: false,
                    forward_to_killchain: true,
                });
            }
        }
    }

    derived
}

fn read_motw_ads_bounded(raw_path: &str) -> Option<String> {
    let norm = crate::pe_hashes::normalize_windows_path(raw_path)?;
    let data = std::fs::read(&norm).ok()?;
    let cap = data.len().min(16 * 1024);
    Some(String::from_utf8_lossy(&data[..cap]).into_owned())
}

fn forward_if_eligible(forward: bool, rec: &EdrEventRecord) {
    if forward {
        crate::killchain_upload::submit_edr_event(
            &rec.event_type,
            &rec.exe_path,
            rec.details.as_deref(),
            &rec.raw,
        );
    }
}

fn dispatch_or_fallback(job: RawTelemetryJob) {
    let fallback = if let Some(tx) = ENRICH_TX.get() {
        match tx.try_send(job) {
            Ok(()) => return,
            Err(mpsc::TrySendError::Full(j)) | Err(mpsc::TrySendError::Disconnected(j)) => j,
        }
    } else {
        job
    };
    let (rec, sz) = build_record(
        &fallback.event_type,
        &fallback.exe_path,
        fallback.pid_override,
        fallback.details.as_deref(),
        fallback.raw,
    );
    forward_if_eligible(fallback.forward_to_killchain, &rec);
    enqueue_record(rec, sz);
}

fn run_enricher_loop(rx: mpsc::Receiver<RawTelemetryJob>) {
    let mut motw_seen: HashMap<String, Instant> = HashMap::new();
    let hash_cb = |p: &str| crate::pe_hashes::compute_file_hashes_cached(p);

    while let Ok(mut job) = rx.recv() {
        let mut motw_cb = |p: &str| -> Option<String> {
            let now = Instant::now();
            if motw_seen.len() > 2048 {
                motw_seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(5));
            }
            let key = p.to_ascii_lowercase();
            if let Some(prev) = motw_seen.get(&key) {
                if now.duration_since(*prev) < Duration::from_secs(2) {
                    return None;
                }
            }
            let content = read_motw_ads_bounded(p)?;
            motw_seen.insert(key, now);
            Some(content)
        };

        let derived = if job.hash_files {
            derive_high_signal_events(
                &job.event_type,
                &job.exe_path,
                job.pid_override,
                &mut job.raw,
                &hash_cb,
                &mut motw_cb,
            )
        } else {
            Vec::new()
        };

        let (rec, sz) = build_record(
            &job.event_type,
            &job.exe_path,
            job.pid_override,
            job.details.as_deref(),
            job.raw,
        );
        crate::edr_rules::evaluate_and_dispatch_event(&rec);
        forward_if_eligible(job.forward_to_killchain, &rec);
        enqueue_record(rec, sz);

        for d in derived {
            let (d_rec, d_sz) = build_record(
                &d.event_type,
                &d.exe_path,
                d.pid_override,
                d.details.as_deref(),
                d.raw,
            );
            crate::edr_rules::evaluate_and_dispatch_event(&d_rec);
            forward_if_eligible(d.forward_to_killchain, &d_rec);
            enqueue_record(d_rec, d_sz);
        }
    }
}

/// Starts the background lossless EDR event uploader and enrichment worker (once).
pub fn start() {
    if is_disabled() {
        return;
    }
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let (etx, erx) = mpsc::sync_channel::<RawTelemetryJob>(ENRICH_QUEUE_CAPACITY);
    let _ = ENRICH_TX.set(etx);
    let _ = std::thread::Builder::new()
        .name("edr-telemetry-enrich".into())
        .spawn(move || run_enricher_loop(erx));
    let _ = std::thread::Builder::new()
        .name("edr-events-uploader".into())
        .spawn(run_uploader_loop);
}

fn pop_next_batch(state: &mut StreamState, max_records: usize) -> Vec<(EdrEventRecord, usize)> {
    let cap = max_records.max(1);
    let mut out = Vec::with_capacity(state.pending.len().min(cap));
    let mut batch_bytes = 0usize;
    while out.len() < cap {
        if let Some((_, sz)) = state.pending.front() {
            if !out.is_empty() && batch_bytes + *sz > BATCH_MAX_BYTES {
                break;
            }
        } else {
            break;
        }
        if let Some((rec, sz)) = state.pending.pop_front() {
            state.total_bytes = state.total_bytes.saturating_sub(sz);
            batch_bytes += sz;
            out.push((rec, sz));
        }
    }
    out
}

fn requeue_front(state: &mut StreamState, batch: Vec<(EdrEventRecord, usize)>) {
    for (rec, sz) in batch.into_iter().rev() {
        state.total_bytes = state.total_bytes.saturating_add(sz);
        state.pending.push_front((rec, sz));
    }
}

fn run_uploader_loop() {
    let hub = sync_hub();
    let mut backoff = Duration::from_secs(0);
    let mut dynamic_cap = BATCH_MAX_RECORDS;
    loop {
        let batch_items = {
            let Ok(mut g) = hub.state.lock() else {
                return;
            };
            while g.pending.is_empty() && !g.flush_requested {
                g = match hub.wake.wait(g) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            if !g.pending.is_empty()
                && !g.flush_requested
                && g.pending.len() < BATCH_MAX_RECORDS
                && g.total_bytes < BATCH_MAX_BYTES
            {
                match hub.wake.wait_timeout_while(g, FLUSH_INTERVAL, |st| {
                    !st.flush_requested
                        && st.pending.len() < BATCH_MAX_RECORDS
                        && st.total_bytes < BATCH_MAX_BYTES
                }) {
                    Ok((guard, _)) => g = guard,
                    Err(poisoned) => g = poisoned.into_inner().0,
                }
            }
            let taken = pop_next_batch(&mut g, dynamic_cap);
            if taken.is_empty() {
                g.flush_requested = false;
                hub.drained.notify_all();
                continue;
            }
            g.in_flight = true;
            taken
        };

        let records: Vec<EdrEventRecord> = batch_items.iter().map(|(r, _)| r.clone()).collect();
        let outcome = send_batch(&records, None);

        let sleep_dur = {
            let Ok(mut g) = hub.state.lock() else {
                return;
            };
            g.in_flight = false;
            match outcome {
                SendOutcome::Ok | SendOutcome::DropBadPayload => {
                    backoff = Duration::from_secs(0);
                    dynamic_cap = BATCH_MAX_RECORDS;
                    if g.pending.is_empty() {
                        g.flush_requested = false;
                        hub.drained.notify_all();
                    }
                    Duration::from_secs(0)
                }
                SendOutcome::TooLarge => {
                    dynamic_cap = (batch_items.len() / 2).max(1);
                    requeue_front(&mut g, batch_items);
                    Duration::from_millis(200)
                }
                SendOutcome::Retry => {
                    requeue_front(&mut g, batch_items);
                    backoff = match backoff.as_secs() {
                        0 => Duration::from_secs(2),
                        2 => Duration::from_secs(5),
                        5 => Duration::from_secs(15),
                        _ => Duration::from_secs(30),
                    };
                    g.flush_requested = false;
                    hub.drained.notify_all();
                    backoff
                }
            }
        };

        if !sleep_dur.is_zero() {
            std::thread::sleep(sleep_dur);
        }
    }
}

/// Submits a raw enriched OpenEDR event (`LLE_*` / `MLE_*`) to the non-blocking enrichment
/// pipeline (hashes, MOTW downloads, service/task/GPO correlators) and then to the lossless uploader.
pub fn submit_raw(event_type: &str, exe_path: &str, details: Option<&str>, raw: serde_json::Value) {
    if is_disabled() || event_type.trim().is_empty() {
        return;
    }
    start();
    // Sanctum / Hypervisor / MBR raw events aren't sent via edrsvc's AppendToTrainingDataset,
    // so forward them to kill chain; LLE_/MLE_ already reach owlyshield_killchain_submit directly.
    let forward_to_killchain = !event_type.starts_with("LLE_")
        && !event_type.starts_with("MLE_")
        && !event_type.starts_with("AGENT_");
    dispatch_or_fallback(RawTelemetryJob {
        event_type: event_type.to_string(),
        exe_path: exe_path.to_string(),
        pid_override: None,
        details: details.map(str::to_string),
        raw,
        hash_files: true,
        forward_to_killchain,
    });
}

/// Submits a pre-built structured event (ETW, EventLog push, PnP, driver diff, WMI, VSS, TAMPERING,
/// or TLS proxy FILE_DOWNLOADED) through the lossless stream without blocking callers.
pub fn submit_structured(
    event_type: &str,
    pid: Option<u32>,
    exe_path: Option<String>,
    details: Option<String>,
    raw: serde_json::Value,
) {
    if is_disabled() || event_type.trim().is_empty() {
        return;
    }
    start();
    let exe = exe_path.unwrap_or_default();
    let needs_hash = should_hash_event(event_type) && raw.get("hashes").is_none();
    let forward_to_killchain = !event_type.starts_with("AGENT_");
    dispatch_or_fallback(RawTelemetryJob {
        event_type: event_type.to_string(),
        exe_path: exe,
        pid_override: pid,
        details,
        raw,
        hash_files: needs_hash,
        forward_to_killchain,
    });
}

/// Submits an `AGENT_*` lifecycle/SysOps event (`AGENT_START`, `AGENT_STOP`, `AGENT_INSTALL`,
/// `AGENT_UNINSTALL`, `AGENT_ERROR`, `AGENT_KEEPALIVE`).
/// When `sync_flush` is true, sends immediately with a bounded 3s WinHTTP timeout before returning
/// (falling back to the async queue if delivery fails while the service stays alive).
pub fn submit_sysop(event_type: &str, message: &str, details: serde_json::Value, sync_flush: bool) {
    if is_disabled() || event_type.trim().is_empty() {
        return;
    }
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let pid = std::process::id();
    let (rec, sz) = build_record(event_type, &exe_path, Some(pid), Some(message), details);
    if sync_flush {
        if matches!(
            send_batch(std::slice::from_ref(&rec), Some(SYNC_SYSOP_TIMEOUT_MS)),
            SendOutcome::Ok
        ) {
            return;
        }
    }
    enqueue_record(rec, sz);
}

/// Requests an immediate flush and waits up to `timeout` for pending events to drain.
pub fn flush_now(timeout: Duration) {
    if !STARTED.load(Ordering::SeqCst) {
        return;
    }
    let hub = sync_hub();
    let Ok(mut g) = hub.state.lock() else {
        return;
    };
    if g.pending.is_empty() && !g.in_flight {
        return;
    }
    g.flush_requested = true;
    hub.wake.notify_all();
    let deadline = std::time::Instant::now() + timeout;
    while !g.pending.is_empty() || g.in_flight {
        let Some(rem) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        if rem.is_zero() {
            break;
        }
        g = match hub.drained.wait_timeout(g, rem) {
            Ok((guard, res)) => {
                if res.timed_out() {
                    break;
                }
                guard
            }
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossless_queue_preserves_every_duplicate_event_and_requeues_in_order() {
        let mut st = StreamState::default();
        let (r1, s1) = build_record(
            "LLE_FILE_CREATE",
            r"C:\Windows\notepad.exe",
            Some(101),
            Some("first"),
            serde_json::json!({"seq": 1}),
        );
        let (r2, s2) = build_record(
            "LLE_FILE_CREATE",
            r"C:\Windows\notepad.exe",
            Some(101),
            Some("first"),
            serde_json::json!({"seq": 1}),
        );
        let (r3, s3) = build_record(
            "LLE_PROCESS_CREATE",
            r"C:\Windows\cmd.exe",
            Some(202),
            None,
            serde_json::json!({"seq": 2}),
        );
        st.total_bytes = s1 + s2 + s3;
        st.pending.push_back((r1, s1));
        st.pending.push_back((r2, s2));
        st.pending.push_back((r3, s3));

        let taken = pop_next_batch(&mut st, BATCH_MAX_RECORDS);
        assert_eq!(taken.len(), 3, "duplicates must never be collapsed");
        assert!(st.pending.is_empty());
        assert_eq!(st.total_bytes, 0);

        // Simulate transient network failure -> requeue front preserves exact order before newer items
        let (r4, s4) = build_record(
            "AGENT_ERROR",
            r"C:\edrsvc.exe",
            Some(303),
            Some("err"),
            serde_json::json!({"seq": 3}),
        );
        st.total_bytes += s4;
        st.pending.push_back((r4, s4));
        requeue_front(&mut st, taken);

        let order: Vec<&str> = st
            .pending
            .iter()
            .map(|(r, _)| r.event_type.as_str())
            .collect();
        assert_eq!(
            order,
            [
                "LLE_FILE_CREATE",
                "LLE_FILE_CREATE",
                "LLE_PROCESS_CREATE",
                "AGENT_ERROR"
            ]
        );
    }

    #[test]
    fn sysop_record_extracts_process_name_and_details() {
        let (rec, _) = build_record(
            "AGENT_STOP",
            r"C:\Program Files\HydraDragonAntivirus\OpenEDR\edrsvc.exe",
            Some(999),
            Some("service shutdown"),
            serde_json::json!({"reason": "scm_stop"}),
        );
        assert_eq!(rec.event_type, "AGENT_STOP");
        assert_eq!(rec.pid, 999);
        assert_eq!(rec.process_name, "edrsvc.exe");
        assert_eq!(rec.details.as_deref(), Some("service shutdown"));
        assert_eq!(rec.raw["reason"], "scm_stop");
    }

    #[test]
    fn enrich_correlators_cover_motw_service_driver_task_gpo_and_pipes() {
        let fake_hash = |_p: &str| {
            Some(crate::pe_hashes::FileHashes {
                md5: "00112233445566778899aabbccddeeff".to_string(),
                sha1: "a".repeat(40),
                sha256: "b".repeat(64),
                imphash: Some("fedcba9876543210fedcba9876543210".to_string()),
                size: 4096,
            })
        };
        let mut fake_motw = |_p: &str| {
            Some("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/\r\nHostUrl=https://cdn.example.org/payload.exe\r\n".to_string())
        };

        // 1. MOTW :Zone.Identifier -> FILE_DOWNLOADED with base file hashes
        let mut raw_motw = serde_json::json!({
            "file": { "abstractPath": r"C:\Users\alice\Downloads\payload.exe:Zone.Identifier" }
        });
        let motw_derived = derive_high_signal_events(
            "LLE_FILE_DATA_CHANGE",
            r"C:\Program Files\Chrome\chrome.exe",
            Some(444),
            &mut raw_motw,
            &fake_hash,
            &mut fake_motw,
        );
        assert_eq!(motw_derived.len(), 1);
        assert_eq!(motw_derived[0].event_type, "FILE_DOWNLOADED");
        assert_eq!(
            motw_derived[0].raw["url"],
            "https://cdn.example.org/payload.exe"
        );
        assert_eq!(
            motw_derived[0].raw["hashes"]["imphash"],
            "fedcba9876543210fedcba9876543210"
        );

        // 2. Service ImagePath=.sys -> SERVICE_MODIFY + DRIVER_MODIFIED
        let mut raw_svc = serde_json::json!({
            "registry": {
                "abstractPath": r"HKLM\SYSTEM\CurrentControlSet\Services\EvilDrv",
                "name": "ImagePath",
                "data": r"\??\C:\Windows\Temp\evil.sys"
            }
        });
        let svc_derived = derive_high_signal_events(
            "LLE_REGISTRY_VALUE_SET",
            r"C:\Windows\System32\sc.exe",
            Some(555),
            &mut raw_svc,
            &fake_hash,
            &mut fake_motw,
        );
        let types: Vec<&str> = svc_derived.iter().map(|d| d.event_type.as_str()).collect();
        assert_eq!(types, ["SERVICE_MODIFY", "DRIVER_MODIFIED"]);

        // 3. Pipe tagging
        let mut raw_pipe = serde_json::json!({"file": {"rawPath": r"\evil_pipe"}});
        let _ = derive_high_signal_events(
            "LLE_NAMED_PIPE_SERVER_CREATE",
            r"C:\evil.exe",
            Some(666),
            &mut raw_pipe,
            &fake_hash,
            &mut fake_motw,
        );
        assert_eq!(raw_pipe["pipe_op"], "create");
    }
}
