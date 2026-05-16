use hydradragon_shared::{TlsInspectionMode, TlsProxyConfig};
use js_sys::Reflect;
use leptos::*;
use leptos::{event_target_checked, event_target_value};
// Assuming imports work.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use wasm_bindgen::prelude::*;

mod wiki;
use wiki::RulesWiki;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> JsValue;

    // For window control in alert mode
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "window"])]
    async fn getCurrentWindow() -> JsValue;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "window"])]
    async fn closeWindow() -> JsValue;
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub details_json: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingApp {
    pub process_id: u32,
    pub name: String,
    pub path: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub hostname: Option<String>,
    pub reason: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub alert_source: Option<String>,
    #[serde(default)]
    pub alert_kind: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub decision_key: Option<String>,
    #[serde(default)]
    pub full_url: Option<String>,
    #[serde(default)]
    pub http_method: Option<String>,
    #[serde(default)]
    pub http_path: Option<String>,
    #[serde(default)]
    pub http_user_agent: Option<String>,
    #[serde(default)]
    pub http_content_type: Option<String>,
    #[serde(default)]
    pub http_referer: Option<String>,
    #[serde(default)]
    pub http_request_body: Option<String>,
    #[serde(default)]
    pub http_response_body: Option<String>,
    #[serde(default)]
    pub payload_sample: Option<String>,
    #[serde(default)]
    pub detected_file_type: Option<String>,
    #[serde(default)]
    pub packet_json: Option<String>,
    #[serde(default = "default_queue_position")]
    pub queue_position: usize,
    #[serde(default = "default_queue_total")]
    pub queue_total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawPacket {
    pub id: String,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub length: usize,
    pub payload_hex: String,
    pub payload_preview: String,
    pub summary: String,
    // Process Correlation
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
    // SDK/Rule Context
    pub action: String,
    pub rule: String,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyHttpEvent {
    pub id: String,
    pub timestamp: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub full_url: String,
    pub status: u16,
    #[serde(default)]
    pub request_headers: HashMap<String, String>,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub referer: Option<String>,
    pub response_content_type: Option<String>,
    pub response_content_length: Option<String>,
    pub request_body: Option<String>,
    pub request_body_truncated: bool,
    #[serde(default)]
    pub response_body: Option<String>,
    #[serde(default)]
    pub response_body_truncated: bool,
}

fn build_raw_packet_log_entry(pkt: &RawPacket) -> LogEntry {
    let action_lower = pkt.action.to_ascii_lowercase();
    let level = if action_lower.contains("block")
        || action_lower.contains("deny")
        || action_lower.contains("quarantine")
        || action_lower.contains("terminate")
        || action_lower.contains("kill")
    {
        LogLevel::Warning
    } else {
        LogLevel::Info
    };

    LogEntry {
        id: format!("packet-log-{}", pkt.id),
        timestamp: pkt.timestamp,
        level,
        message: format!(
            "PACKET {}:{} -> {}:{} [{}] pid={} action={} rule={}",
            pkt.src_ip,
            pkt.src_port,
            pkt.dst_ip,
            pkt.dst_port,
            match pkt.protocol {
                Protocol::TCP => "TCP",
                Protocol::UDP => "UDP",
                Protocol::ICMP => "ICMP",
                Protocol::Raw(_) => "RAW",
            },
            pkt.process_id,
            pkt.action,
            if pkt.rule.trim().is_empty() {
                "-"
            } else {
                &pkt.rule
            }
        ),
        source: Some("packet".to_string()),
        details_json: serde_json::to_string_pretty(pkt).ok(),
    }
}

fn build_proxy_log_entry(ev: &ProxyHttpEvent) -> LogEntry {
    let level = if ev.status >= 400 {
        LogLevel::Warning
    } else {
        LogLevel::Info
    };

    LogEntry {
        id: format!("http-log-{}", ev.id),
        timestamp: ev.timestamp,
        level,
        message: format!("HTTP {} {} -> {}", ev.method, ev.full_url, ev.status),
        source: Some("http".to_string()),
        details_json: serde_json::to_string_pretty(ev).ok(),
    }
}

const ACTIVITY_GRAPH_POINTS: usize = 24;
const ACTIVITY_GRAPH_INTERVAL_MS: u64 = 2000;
const ACTIVITY_GRAPH_WIDTH: f64 = 600.0;
const ACTIVITY_GRAPH_HEIGHT: f64 = 150.0;
const ACTIVITY_GRAPH_TOP_PADDING: f64 = 18.0;
const ACTIVITY_GRAPH_BOTTOM_PADDING: f64 = 18.0;

#[derive(Clone, Copy, Debug, Default)]
struct ActivitySnapshot {
    logs: usize,
    raw_packets: usize,
    proxy_events: usize,
    prompts: usize,
}

impl ActivitySnapshot {
    fn delta_units(self, previous: Self) -> u32 {
        self.logs.saturating_sub(previous.logs) as u32
            + self.raw_packets.saturating_sub(previous.raw_packets) as u32
            + self.proxy_events.saturating_sub(previous.proxy_events) as u32
            + self.prompts.saturating_sub(previous.prompts) as u32
    }
}

fn activity_graph_points(samples: &[u32]) -> Vec<(f64, f64)> {
    if samples.is_empty() {
        return Vec::new();
    }

    let max_value = samples.iter().copied().max().unwrap_or(0).max(1) as f64;
    let usable_height =
        ACTIVITY_GRAPH_HEIGHT - ACTIVITY_GRAPH_TOP_PADDING - ACTIVITY_GRAPH_BOTTOM_PADDING;
    let step_x = if samples.len() > 1 {
        ACTIVITY_GRAPH_WIDTH / (samples.len() - 1) as f64
    } else {
        ACTIVITY_GRAPH_WIDTH
    };

    samples
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let normalized = (*value as f64) / max_value;
            let x = index as f64 * step_x;
            let y = ACTIVITY_GRAPH_TOP_PADDING + (1.0 - normalized) * usable_height;
            (x, y)
        })
        .collect()
}

fn build_activity_line_path(samples: &[u32]) -> String {
    let points = activity_graph_points(samples);
    if points.is_empty() {
        let baseline = ACTIVITY_GRAPH_HEIGHT - ACTIVITY_GRAPH_BOTTOM_PADDING;
        return format!("M0,{baseline:.1} L{ACTIVITY_GRAPH_WIDTH:.1},{baseline:.1}");
    }

    let mut path = format!("M{:.1},{:.1}", points[0].0, points[0].1);
    for (x, y) in points.iter().skip(1) {
        path.push_str(&format!(" L{:.1},{:.1}", x, y));
    }
    path
}

fn build_activity_fill_path(samples: &[u32]) -> String {
    let points = activity_graph_points(samples);
    let baseline = ACTIVITY_GRAPH_HEIGHT - ACTIVITY_GRAPH_BOTTOM_PADDING;
    if points.is_empty() {
        return format!("M0,{baseline:.1} L{ACTIVITY_GRAPH_WIDTH:.1},{baseline:.1} Z");
    }

    let mut path = format!("M{:.1},{baseline:.1}", points[0].0);
    for (x, y) in &points {
        path.push_str(&format!(" L{:.1},{:.1}", x, y));
    }
    if let Some((last_x, _)) = points.last() {
        path.push_str(&format!(" L{last_x:.1},{baseline:.1} Z"));
    }
    path
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessInventoryEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub name: String,
    pub path: String,
    pub observed_by_firewall: bool,
    pub suspicious: bool,
    pub pending_alert: bool,
    pub decision: Option<String>,
    #[serde(default)]
    pub cloud_trusted: bool,
    #[serde(default)]
    pub openedr_verdict: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct ProcessExplorerRow {
    pid: u32,
    parent_pid: u32,
    thread_count: u32,
    name: String,
    path: String,
    kind: String,
    observed_by_firewall: bool,
    suspicious: bool,
    pending_alert: bool,
    decision: Option<String>,
    cloud_trusted: bool,
    openedr_verdict: Option<String>,
    packet_count: usize,
    blocked_packet_count: usize,
    last_activity: Option<u64>,
    recent_targets: Vec<String>,
    matched_rules: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct HexCell {
    absolute_index: usize,
    hex: String,
    ascii: String,
    highlighted: bool,
    label: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct HexLine {
    offset: usize,
    cells: Vec<HexCell>,
}

fn normalize_process_identity(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn classify_process_kind(name: &str, path: &str) -> String {
    let name_lc = normalize_process_identity(name);
    let path_lc = normalize_process_identity(path);

    if matches!(
        name_lc.as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "opera.exe"
            | "vivaldi.exe"
            | "waterfox.exe"
            | "librewolf.exe"
            | "iexplore.exe"
    ) {
        return "Browsers".to_string();
    }

    if matches!(
        name_lc.as_str(),
        "svchost.exe"
            | "services.exe"
            | "lsass.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "csrss.exe"
            | "smss.exe"
            | "spoolsv.exe"
    ) {
        return "Services".to_string();
    }

    if path_lc.contains("\\windowsapps\\") {
        return "Windows Apps".to_string();
    }

    if path_lc.starts_with("c:\\windows\\") || path_lc == "system" {
        return "Windows".to_string();
    }

    "Applications".to_string()
}

fn decision_badge_label(decision: Option<&str>) -> Option<String> {
    decision.map(|value| match value {
        "allow" => "ALLOW".to_string(),
        "block" => "BLOCK".to_string(),
        "deny" => "DENY".to_string(),
        "pending" => "PENDING".to_string(),
        "allow_once" => "ALLOW ONCE".to_string(),
        other => other.to_ascii_uppercase(),
    })
}

fn openedr_verdict_badge(verdict: Option<&str>) -> Option<(String, String, String)> {
    let label = verdict?.trim();
    if label.is_empty() {
        return None;
    }

    let normalized = label.to_ascii_lowercase().replace(['_', '-'], " ");
    let display = match normalized.as_str() {
        "safe" | "possible safe" | "possibly safe" => "OpenEDR: Possible Safe",
        "unknown" => "OpenEDR: Unknown",
        "fail" | "failed" => "OpenEDR: Fail",
        "unrecognized" | "unrecognised" => "OpenEDR: Unrecognized",
        "malware" | "malicious" => "OpenEDR: Malware",
        _ => "OpenEDR: Unrecognized",
    };

    let colors = match display {
        "OpenEDR: Possible Safe" => ("rgba(34, 197, 94, 0.16)", "#22c55e"),
        "OpenEDR: Unknown" => ("rgba(245, 158, 11, 0.18)", "#f59e0b"),
        "OpenEDR: Fail" => ("rgba(245, 158, 11, 0.18)", "#f59e0b"),
        "OpenEDR: Malware" => ("rgba(239, 68, 68, 0.20)", "#ef4444"),
        _ => ("rgba(148, 163, 184, 0.18)", "#cbd5e1"),
    };

    Some((display.to_string(), colors.0.to_string(), colors.1.to_string()))
}

fn is_owlyshield_log_entry(log: &LogEntry) -> bool {
    let source = log
        .source
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let message = log.message.to_ascii_lowercase();

    source.contains("owlyshield")
        || message.contains("owlyshield")
        || message.contains("hips")
        || message.contains("behavior")
        || message.contains("report generation")
}

fn compact_log_message(message: &str, max_len: usize) -> String {
    let trimmed = message.trim();
    if trimmed.chars().count() <= max_len {
        return trimmed.to_string();
    }

    let shortened = trimmed
        .chars()
        .take(max_len.saturating_sub(1))
        .collect::<String>();
    format!("{}...", shortened)
}

fn format_file_size_bytes(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;

    let value = size as f64;
    if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.2} KB", value / KB)
    } else {
        format!("{size} B")
    }
}

fn format_unix_timestamp(ts: Option<u64>) -> String {
    ts.map(|secs| {
        let millis = secs as f64 * 1000.0;
        js_sys::Date::new(&JsValue::from_f64(millis))
            .to_locale_string("en-GB", &JsValue::UNDEFINED)
            .as_string()
            .unwrap_or_else(|| secs.to_string())
    })
    .unwrap_or_else(|| "Unknown".to_string())
}

fn build_process_rows(
    processes: &[ProcessInventoryEntry],
    packets: &[RawPacket],
) -> Vec<ProcessExplorerRow> {
    let mut rows = Vec::with_capacity(processes.len());

    for process in processes {
        let mut packet_count = 0usize;
        let mut blocked_packet_count = 0usize;
        let mut last_activity: Option<u64> = None;
        let mut recent_targets = Vec::new();
        let mut matched_rules = Vec::new();

        for packet in packets.iter().rev() {
            if packet.process_id != process.pid {
                continue;
            }

            packet_count += 1;
            last_activity = Some(
                last_activity.map_or(packet.timestamp, |current| current.max(packet.timestamp)),
            );

            let action_lc = packet.action.to_ascii_lowercase();
            if action_lc.contains("block")
                || action_lc.contains("deny")
                || action_lc.contains("quarantine")
                || action_lc.contains("terminate")
                || action_lc.contains("kill")
            {
                blocked_packet_count += 1;
            }

            let target = packet
                .hostname
                .clone()
                .unwrap_or_else(|| format!("{}:{}", packet.dst_ip, packet.dst_port));
            if !recent_targets.iter().any(|existing| existing == &target) {
                recent_targets.push(target);
            }

            let rule = packet.rule.trim();
            if !rule.is_empty() && !matched_rules.iter().any(|existing| existing == rule) {
                matched_rules.push(rule.to_string());
            }

            if recent_targets.len() >= 8 && matched_rules.len() >= 8 {
                break;
            }
        }

        rows.push(ProcessExplorerRow {
            pid: process.pid,
            parent_pid: process.parent_pid,
            thread_count: process.thread_count,
            name: process.name.clone(),
            path: process.path.clone(),
            kind: classify_process_kind(&process.name, &process.path),
            observed_by_firewall: process.observed_by_firewall,
            suspicious: process.suspicious,
            pending_alert: process.pending_alert,
            decision: process.decision.clone(),
            cloud_trusted: process.cloud_trusted,
            openedr_verdict: process.openedr_verdict.clone(),
            packet_count,
            blocked_packet_count,
            last_activity,
            recent_targets,
            matched_rules,
        });
    }

    rows.sort_by(|a, b| {
        b.pending_alert
            .cmp(&a.pending_alert)
            .then_with(|| b.suspicious.cmp(&a.suspicious))
            .then_with(|| b.blocked_packet_count.cmp(&a.blocked_packet_count))
            .then_with(|| b.packet_count.cmp(&a.packet_count))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows
}

fn process_matches_filter(row: &ProcessExplorerRow, filter: &str, query: &str) -> bool {
    let filter_ok = match filter {
        "pending" => row.pending_alert,
        "suspicious" => row.suspicious,
        "active" => row.packet_count > 0,
        "browsers" => row.kind == "Browsers",
        "services" => row.kind == "Services",
        "windows" => row.kind == "Windows" || row.kind == "Windows Apps",
        _ => true,
    };

    if !filter_ok {
        return false;
    }

    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }

    row.name.to_ascii_lowercase().contains(&query)
        || row.path.to_ascii_lowercase().contains(&query)
        || row.pid.to_string().contains(&query)
        || row
            .openedr_verdict
            .as_ref()
            .is_some_and(|verdict| verdict.to_ascii_lowercase().contains(&query))
        || row
            .matched_rules
            .iter()
            .any(|rule| rule.to_ascii_lowercase().contains(&query))
        || row
            .recent_targets
            .iter()
            .any(|target| target.to_ascii_lowercase().contains(&query))
}

fn decode_packet_bytes(payload_hex: &str) -> Vec<u8> {
    let hex_only = payload_hex
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    let mut bytes = Vec::new();
    let mut index = 0;
    while index + 1 < hex_only.len() {
        if let Ok(byte) = u8::from_str_radix(&hex_only[index..index + 2], 16) {
            bytes.push(byte);
        }
        index += 2;
    }
    bytes
}

fn packet_match_tokens(packet: &RawPacket) -> Vec<String> {
    const STOPWORDS: &[&str] = &[
        "sdk",
        "rule",
        "blocked",
        "allow",
        "allowed",
        "pending",
        "traffic",
        "packet",
        "terminated",
        "quarantined",
        "decision",
        "attack",
        "detected",
        "proxy",
    ];

    let mut tokens = Vec::new();

    if let Some(hostname) = packet.hostname.as_ref() {
        tokens.push(hostname.clone());
        for piece in hostname
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_')
        {
            if piece.len() >= 4 {
                tokens.push(piece.to_string());
            }
        }
    }

    tokens.push(packet.dst_ip.clone());

    for piece in packet.rule.split(|ch: char| {
        !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' && ch != ':'
    }) {
        let trimmed = piece.trim();
        let lowered = trimmed.to_ascii_lowercase();
        if trimmed.len() >= 4 && !STOPWORDS.iter().any(|word| *word == lowered) {
            tokens.push(trimmed.to_string());
        }
    }

    let mut deduped = Vec::new();
    for token in tokens {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.len() < 4 {
            continue;
        }
        if !deduped
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&token))
        {
            deduped.push(token);
        }
        if deduped.len() >= 8 {
            break;
        }
    }
    deduped
}

fn find_packet_match_spans(bytes: &[u8], packet: &RawPacket) -> Vec<(usize, usize, String)> {
    let mut spans = Vec::new();

    for token in packet_match_tokens(packet) {
        let needle = token.as_bytes();
        if needle.is_empty() || needle.len() > bytes.len() {
            continue;
        }

        for start in 0..=bytes.len().saturating_sub(needle.len()) {
            let matched = bytes[start..start + needle.len()]
                .iter()
                .zip(needle.iter())
                .all(|(left, right)| left.to_ascii_lowercase() == right.to_ascii_lowercase());
            if matched {
                spans.push((start, start + needle.len(), token.clone()));
            }
        }
    }

    spans.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    spans
}

fn build_packet_hex_lines(packet: &RawPacket) -> (Vec<HexLine>, Vec<String>) {
    let bytes = decode_packet_bytes(&packet.payload_hex);
    let spans = find_packet_match_spans(&bytes, packet);
    let mut labels = Vec::new();

    let mut markers: HashMap<usize, String> = HashMap::new();
    for (start, end, label) in &spans {
        if !labels.iter().any(|existing| existing == label) {
            labels.push(label.clone());
        }
        for index in *start..*end {
            markers.entry(index).or_insert_with(|| label.clone());
        }
    }

    let mut lines = Vec::new();
    for (line_index, chunk) in bytes.chunks(16).enumerate() {
        let mut cells = Vec::new();
        for (cell_index, byte) in chunk.iter().enumerate() {
            let absolute_index = line_index * 16 + cell_index;
            let label = markers.get(&absolute_index).cloned();
            cells.push(HexCell {
                absolute_index,
                hex: format!("{:02X}", byte),
                ascii: if byte.is_ascii_graphic() {
                    (*byte as char).to_string()
                } else {
                    ".".to_string()
                },
                highlighted: label.is_some(),
                label,
            });
        }
        lines.push(HexLine {
            offset: line_index * 16,
            cells,
        });
    }

    (lines, labels)
}

/// A body changer rule managed through the GUI.
/// Serialised into rules.yaml as an SDK rule with action change_request_body
/// or change_response_body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BodyChangerRule {
    pub id: String, // client-side UUID for keying
    pub name: String,
    pub enabled: bool,
    /// "request" or "response"
    pub target: String,
    /// URL substring to match (goes into url matcher)
    pub url_pattern: String,
    /// HTTP method to match, empty = any
    pub method_pattern: String,
    /// The replacement body text
    pub replacement: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OwlyshieldRuleFileEntry {
    pub name: String,
    pub path: String,
    pub selected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwlyshieldRulesDirectoryView {
    pub directory: String,
    pub selected_path: Option<String>,
    pub files: Vec<OwlyshieldRuleFileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OwlyshieldReportFileEntry {
    pub name: String,
    pub path: String,
    pub selected: bool,
    pub modified_ts: Option<u64>,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwlyshieldReportsDirectoryView {
    pub directory: String,
    pub selected_path: Option<String>,
    pub files: Vec<OwlyshieldReportFileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FirewallQuarantineFileEntry {
    pub name: String,
    pub path: String,
    pub modified_ts: Option<u64>,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallQuarantineDirectoryView {
    pub directory: String,
    pub files: Vec<FirewallQuarantineFileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineRuntimeStatus {
    pub active: bool,
    pub status: String,
    pub mitm_enabled: bool,
    pub windows_root_trust_ready: bool,
    pub firefox_policy_ready: bool,
    pub mitm_bypass_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResolveArgs {
    name: String,
    decision: String,
}

#[derive(Copy, Clone, PartialEq)]
enum AppView {
    Dashboard,
    Processes,
    Rules,
    Owlyshield,
    Logs,
    PacketReader,
    HttpInspector,
    Settings,
    Exclusions,
}

#[derive(Clone, Copy, PartialEq)]
enum SettingsSubTab {
    General,
    About,
    Help,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AppDecision {
    Allow,
    Block,
    Pending,
    AllowOnce,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    #[serde(default)]
    pub block: bool,
    #[serde(default)]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub remote_ips: Vec<String>,
    #[serde(default)]
    pub remote_ports: Vec<u16>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub hostname_pattern: Option<String>,
    #[serde(default)]
    pub url_pattern: Option<String>,
    #[serde(default)]
    pub file_types: Vec<String>,
    #[serde(default)]
    pub terminate: bool,
    #[serde(default)]
    pub quarantine: bool,
    #[serde(default)]
    pub kill_and_remove: bool,
    #[serde(default)]
    pub ask_user: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionView {
    TrafficAttack,
    Block,
    Allow,
    Ask,
    ChangePacket,
    SolvePacket,
    ChangeRequestBody,
    ChangeResponseBody,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdkRuleView {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    pub action: RuleActionView,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub encoding: String,
    #[serde(default)]
    pub condition_logic: String,
    #[serde(default)]
    pub change_request_body: Option<String>,
    #[serde(default)]
    pub change_response_body: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallSettings {
    #[serde(default)]
    pub app_decisions: HashMap<String, AppDecision>,
    #[serde(default)]
    pub kernel_block_paths: Vec<String>,
    #[serde(default)]
    pub website_path: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default)]
    pub late_blocking_mode: bool,
    #[serde(default)]
    pub headless_mode: bool,
    #[serde(default)]
    pub log_mode: bool,
    #[serde(default)]
    pub show_blocked_only: bool,
    #[serde(default)]
    pub no_alert_mode: bool,
    #[serde(default = "default_true")]
    pub save_all_logs: bool,
    #[serde(default = "default_true")]
    pub prune_old_logs: bool,
    #[serde(default = "default_max_visible_logs")]
    pub max_visible_logs: usize,
    #[serde(default = "default_prune_http_history")]
    pub prune_http_history: bool,
    #[serde(default = "default_max_visible_http_history")]
    pub max_visible_http_events: usize,
    #[serde(default)]
    pub log_full_bodies: bool,
    #[serde(default)]
    pub tls_proxy: TlsProxyConfig,
    pub metadata: HashMap<String, String>,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "2.0.0".to_string());
        metadata.insert(
            "description".to_string(),
            "HydraDragon Next-Gen Firewall Configuration".to_string(),
        );
        metadata.insert("theme".to_string(), "cyberpunk".to_string());

        Self {
            app_decisions: HashMap::new(),
            kernel_block_paths: Vec::new(),
            website_path: String::new(),
            rules: Vec::new(),
            late_blocking_mode: false,
            headless_mode: false,
            log_mode: false,
            show_blocked_only: false,
            no_alert_mode: false,
            save_all_logs: true,
            prune_old_logs: true,
            max_visible_logs: default_max_visible_logs(),
            prune_http_history: default_prune_http_history(),
            max_visible_http_events: default_max_visible_http_history(),
            log_full_bodies: false,
            tls_proxy: TlsProxyConfig::default(),
            metadata,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_visible_logs() -> usize {
    2000
}

fn default_prune_http_history() -> bool {
    true
}

fn default_max_visible_http_history() -> usize {
    5000
}

fn metadata_to_editor_string(metadata: &HashMap<String, String>) -> String {
    let mut entries = metadata.iter().collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_metadata_editor_string(value: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    for line in value.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((key, entry_value)) = trimmed.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                metadata.insert(key.to_string(), entry_value.trim().to_string());
            }
        }
    }
    metadata
}

fn default_queue_position() -> usize {
    1
}

fn default_queue_total() -> usize {
    1
}

#[component]
pub fn App() -> impl IntoView {
    let (logs, set_logs) = create_signal(Vec::<LogEntry>::new());
    let (selected_log, set_selected_log) = create_signal(Option::<LogEntry>::None);
    let (blocked_count, set_blocked_count) = create_signal(0usize);
    let (_threats_count, set_threats_count) = create_signal(0usize);
    let (allowed_count, set_allowed_count) = create_signal(0usize);
    let (total_count, set_total_count) = create_signal(0usize);
    let (raw_packet_count, set_raw_packet_count) = create_signal(0usize);
    let (proxy_event_count, set_proxy_event_count) = create_signal(0usize);
    let (prompt_count, set_prompt_count) = create_signal(0usize);

    // Navigation State
    let (current_view, set_current_view) = create_signal(AppView::Dashboard);
    let (raw_packets, set_raw_packets) = create_signal(Vec::<RawPacket>::new());
    let (selected_packet, set_selected_packet) = create_signal(Option::<RawPacket>::None);
    let (proxy_events, set_proxy_events) = create_signal(Vec::<ProxyHttpEvent>::new());
    let (selected_proxy_event, set_selected_proxy_event) =
        create_signal(Option::<ProxyHttpEvent>::None);
    let (process_inventory, set_process_inventory) =
        create_signal(Vec::<ProcessInventoryEntry>::new());
    let (selected_process_pid, set_selected_process_pid) = create_signal(Option::<u32>::None);
    let (process_filter, set_process_filter) = create_signal("all".to_string());
    let (process_search, set_process_search) = create_signal(String::new());
    let (is_dark, set_is_dark) = create_signal(true);

    let (sdk_rules, set_sdk_rules) = create_signal(Vec::<SdkRuleView>::new());
    let (body_changers, set_body_changers) = create_signal(Vec::<BodyChangerRule>::new());
    // Fields for the body changer editor form
    let (bc_edit_id, set_bc_edit_id) = create_signal(Option::<String>::None);
    let (bc_name, set_bc_name) = create_signal(String::new());
    let (bc_target, set_bc_target) = create_signal("request".to_string());
    let (bc_url_pattern, set_bc_url_pattern) = create_signal(String::new());
    let (bc_method_pattern, set_bc_method_pattern) = create_signal(String::new());
    let (bc_replacement, set_bc_replacement) = create_signal(String::new());
    let (bc_enabled, set_bc_enabled) = create_signal(true);
    let (show_bc_form, set_show_bc_form) = create_signal(false);

    let (pending_app, set_pending_app) = create_signal(Option::<PendingApp>::None);
    let (app_decisions, set_app_decisions) = create_signal(HashMap::<String, AppDecision>::new());

    // Window Mode Detection
    let (is_alert, set_is_alert) = create_signal({
        if let Some(win) = web_sys::window() {
            if let Ok(search) = win.location().search() {
                search.contains("mode=alert")
            } else {
                false
            }
        } else {
            false
        }
    });

    spawn_local(async move {
        // If in alert mode, try to fetch the active alert immediately
        if let Some(win) = web_sys::window() {
            if let Ok(search) = win.location().search() {
                if search.contains("mode=alert") {
                    let res = invoke("get_active_alert", JsValue::NULL).await;
                    if let Ok(app_opt) = serde_wasm_bindgen::from_value::<Option<PendingApp>>(res) {
                        if let Some(app) = app_opt {
                            set_pending_app.set(Some(app));
                        }
                    }
                }
            }
        }

        // Fallback or secondary confirmation via Label
        let win = getCurrentWindow().await;
        if !win.is_undefined() && !win.is_null() {
            if let Ok(label) = Reflect::get(&win, &"label".into()) {
                if let Some(l) = label.as_string() {
                    if l == "firewall-alert" {
                        set_is_alert.set(true);
                    }
                }
            }
        }
    });

    let _resolve_decision = move |name: String, decision: String| {
        let name_lower = name.clone();
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&ResolveArgs {
                name: name_lower,
                decision,
            })
            .unwrap();
            let _ = invoke("resolve_app_decision", args).await;

            // If in alert window, close it after decision
            let _ = invoke("close_window", JsValue::NULL).await;

            set_pending_app.set(None);
        });
    };

    let (settings, set_settings) = create_signal(FirewallSettings::default());
    let (settings_raw, set_settings_raw) = create_signal(String::new());
    let (settings_raw_status, set_settings_raw_status) = create_signal(String::new());

    let (show_editor, set_show_editor) = create_signal(false);
    let (rules_raw_content, set_rules_raw_content) = create_signal(String::new());
    let (_validation_result, set_validation_result) =
        create_signal(String::from("Ready to validate."));
    let (show_owlyshield_editor, set_show_owlyshield_editor) = create_signal(false);
    let (owlyshield_rules_content, set_owlyshield_rules_content) = create_signal(String::new());
    let (owlyshield_rules_directory, set_owlyshield_rules_directory) = create_signal(String::new());
    let (owlyshield_rule_files, set_owlyshield_rule_files) =
        create_signal(Vec::<OwlyshieldRuleFileEntry>::new());
    let (selected_owlyshield_rule_path, set_selected_owlyshield_rule_path) =
        create_signal(Option::<String>::None);
    let (owlyshield_rules_status, set_owlyshield_rules_status) = create_signal(String::new());
    let (owlyshield_report_content, set_owlyshield_report_content) = create_signal(String::new());
    let (owlyshield_reports_directory, set_owlyshield_reports_directory) =
        create_signal(String::new());
    let (owlyshield_report_files, set_owlyshield_report_files) =
        create_signal(Vec::<OwlyshieldReportFileEntry>::new());
    let (selected_owlyshield_report_path, set_selected_owlyshield_report_path) =
        create_signal(Option::<String>::None);
    let (owlyshield_report_status, set_owlyshield_report_status) = create_signal(String::new());
    let (firewall_quarantine_directory, set_firewall_quarantine_directory) =
        create_signal(String::new());
    let (firewall_quarantine_files, set_firewall_quarantine_files) =
        create_signal(Vec::<FirewallQuarantineFileEntry>::new());

    // Settings Navigation
    let (settings_sub_tab, set_settings_sub_tab) = create_signal(SettingsSubTab::General);
    let (readme_content, set_readme_content) = create_signal(String::new());

    let fetch_readme = move || {
        spawn_local(async move {
            let res = invoke("get_readme_content", JsValue::NULL).await;
            if let Ok(content) = serde_wasm_bindgen::from_value::<String>(res) {
                set_readme_content.set(content);
            }
        });
    };

    let fetch_sdk_rules = move || {
        spawn_local(async move {
            let args = js_sys::Object::new();
            let val = invoke("get_sdk_rules", args.into()).await;
            let rules: Vec<SdkRuleView> = serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_sdk_rules.set(rules);
        });
    };

    let fetch_body_changers = move || {
        spawn_local(async move {
            let val = invoke("get_body_changers", JsValue::NULL).await;
            let rules: Vec<BodyChangerRule> =
                serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_body_changers.set(rules);
        });
    };

    let save_body_changers_fn = move |rules: Vec<BodyChangerRule>| {
        spawn_local(async move {
            let args =
                serde_wasm_bindgen::to_value(&serde_json::json!({ "rules": rules })).unwrap();
            let _ = invoke("save_body_changers", args).await;
            let val = invoke("get_body_changers", JsValue::NULL).await;
            let updated: Vec<BodyChangerRule> =
                serde_wasm_bindgen::from_value(val).unwrap_or_default();
            set_body_changers.set(updated);
        });
    };

    let fetch_rules_raw = move || {
        spawn_local(async move {
            let args = js_sys::Object::new();
            let val = invoke("get_rules_content", args.into()).await;
            if let Ok(s) = serde_wasm_bindgen::from_value::<String>(val) {
                set_rules_raw_content.set(s);
            }
        });
    };

    let save_owlyshield_rules = move || {
        let content = owlyshield_rules_content.get();
        let selected_path = selected_owlyshield_rule_path.get();
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            if let Some(ref path) = selected_path {
                js_sys::Reflect::set(&args, &"path".into(), &path.clone().into()).unwrap();
            }
            match invoke("save_owlyshield_rules_raw", args.into())
                .await
                .as_string()
            {
                Some(error_message) if !error_message.is_empty() => {
                    set_owlyshield_rules_status.set(format!("Save returned: {}", error_message));
                }
                _ => {
                    set_owlyshield_rules_status.set("Owlyshield rule file saved.".to_string());
                }
            }
        });
    };

    let fetch_app_decisions = move || {
        spawn_local(async move {
            let res = invoke("get_app_decisions", JsValue::NULL).await;
            if let Ok(decisions) =
                serde_wasm_bindgen::from_value::<HashMap<String, AppDecision>>(res)
            {
                set_app_decisions.set(decisions);
            }
        });
    };

    let fetch_settings = move || {
        spawn_local(async move {
            let res = invoke("get_settings", JsValue::NULL).await;
            if let Ok(current_settings) = serde_wasm_bindgen::from_value::<FirewallSettings>(res) {
                let raw = serde_json::to_string_pretty(&current_settings).unwrap_or_default();
                if let Some(theme) = current_settings.metadata.get("theme") {
                    set_is_dark.set(theme != "white" && theme != "light");
                }
                set_settings.set(current_settings);
                set_settings_raw.set(raw);
                set_settings_raw_status.set(String::new());
            }
        });
    };

    let fetch_saved_logs = move || {
        spawn_local(async move {
            let res = invoke("get_saved_logs", JsValue::NULL).await;
            if let Ok(saved_logs) = serde_wasm_bindgen::from_value::<Vec<LogEntry>>(res) {
                if !saved_logs.is_empty() {
                    set_logs.set(saved_logs);
                }
            }
        });
    };

    let fetch_process_inventory = move || {
        spawn_local(async move {
            let res = invoke("get_process_inventory", JsValue::NULL).await;
            if let Ok(processes) = serde_wasm_bindgen::from_value::<Vec<ProcessInventoryEntry>>(res)
            {
                set_process_inventory.set(processes);
            }
        });
    };

    let request_owlyshield_report = move || {
        let requested_at = js_sys::Date::now() as u64;
        set_current_view.set(AppView::Owlyshield);
        set_owlyshield_report_status.set(
            "Report generation requested. Refresh the report list after Owlyshield finishes writing the new report."
                .to_string(),
        );
        set_logs.update(|entries| {
            entries.insert(
                0,
                LogEntry {
                    id: format!("manual-report-{}", requested_at),
                    timestamp: requested_at,
                    level: LogLevel::Info,
                    message: "Requested Owlyshield advanced report generation from the firewall UI"
                        .to_string(),
                    source: Some("ui".to_string()),
                    details_json: None,
                },
            );
        });
        spawn_local(async move {
            let _ = invoke("generate_owlyshield_report", JsValue::NULL).await;
        });
    };

    let save_rules_raw = move || {
        let content = rules_raw_content.get();
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            let _ = invoke("save_rules_content", args.into()).await;
            fetch_sdk_rules();
            set_show_editor.set(false);
        });
    };

    let validate_rules_raw = move || {
        let content = rules_raw_content.get();
        set_validation_result.set("Validating...".to_string());
        spawn_local(async move {
            let args = js_sys::Object::new();
            js_sys::Reflect::set(&args, &"content".into(), &content.into()).unwrap();
            let res = invoke("validate_rules_content", args.into()).await;
            if let Some(msg) = res.as_string() {
                set_validation_result.set(msg);
            }
        });
    };

    let remove_decision_action = move |name: String| {
        let normalized_name = name.to_ascii_lowercase();
        set_app_decisions.update(|decisions| {
            decisions.remove(&normalized_name);
        });
        set_settings.update(|settings| {
            settings.app_decisions.remove(&normalized_name);
        });
        spawn_local(async move {
            let args =
                serde_wasm_bindgen::to_value(&serde_json::json!({ "name": normalized_name }))
                    .unwrap();
            let _ = invoke("remove_app_decision", args).await;
            fetch_app_decisions();
            fetch_settings();
        });
    };

    let clear_all_decisions = move || {
        set_app_decisions.set(HashMap::new());
        set_settings.update(|settings| {
            settings.app_decisions.clear();
        });
        spawn_local(async move {
            let _ = invoke("clear_app_decisions", JsValue::NULL).await;
            fetch_app_decisions();
            fetch_settings();
        });
    };

    let (_confirm_quit, _set_confirm_quit) = create_signal(false);
    let (_new_rule_name, _set_new_rule_name) = create_signal(String::new());
    let (_new_rule_desc, _set_new_rule_desc) = create_signal(String::new());
    let (_new_rule_ips, _set_new_rule_ips) = create_signal(String::new());
    let (_new_rule_ports, _set_new_rule_ports) = create_signal(String::new());
    let (_new_rule_protocol, _set_new_rule_protocol) = create_signal("Any".to_string());
    let (_new_rule_block, _set_new_rule_block) = create_signal(true);
    let (_validation_error, _set_validation_error) = create_signal(Option::<String>::None);
    let (_console_output, _set_console_output) = create_signal(Vec::<String>::new());
    let (_is_compiling, _set_is_compiling) = create_signal(false);
    let (_active_tab, _set_active_tab) = create_signal("rule".to_string());
    let (saved_status, set_saved_status) = create_signal(false);
    let (engine_status, set_engine_status) = create_signal("Initializing Engine...".to_string());
    let (engine_active, set_engine_active) = create_signal(false);
    let (mitm_enabled, set_mitm_enabled) = create_signal(false);
    let (windows_root_trust_ready, set_windows_root_trust_ready) = create_signal(false);
    let (firefox_policy_ready, set_firefox_policy_ready) = create_signal(false);
    let (mitm_bypass_count, set_mitm_bypass_count) = create_signal(0usize);
    let (settings_loaded, set_settings_loaded) = create_signal(false);
    let (graph_data, set_graph_data) = create_signal(vec![0u32; ACTIVITY_GRAPH_POINTS]);
    let (last_activity_snapshot, set_last_activity_snapshot) =
        create_signal(ActivitySnapshot::default());

    create_effect(move |_| {
        if let Some(document) = web_sys::window().and_then(|w| w.document()) {
            if let Some(body) = document.body() {
                if is_dark.get() {
                    let _ = body.class_list().remove_1("light-theme");
                } else {
                    let _ = body.class_list().add_1("light-theme");
                }
            }
        }
    });

    let activity_line_path = create_memo(move |_| build_activity_line_path(&graph_data.get()));
    let activity_fill_path = create_memo(move |_| build_activity_fill_path(&graph_data.get()));
    let current_activity_rate = create_memo(move |_| {
        let latest = graph_data.get().last().copied().unwrap_or_default() as f64;
        latest / (ACTIVITY_GRAPH_INTERVAL_MS as f64 / 1000.0)
    });
    let peak_activity_rate = create_memo(move |_| {
        let peak = graph_data.get().iter().copied().max().unwrap_or_default() as f64;
        peak / (ACTIVITY_GRAPH_INTERVAL_MS as f64 / 1000.0)
    });
    let process_rows =
        create_memo(move |_| build_process_rows(&process_inventory.get(), &raw_packets.get()));
    let filtered_process_rows = create_memo(move |_| {
        let filter = process_filter.get();
        let query = process_search.get();
        process_rows
            .get()
            .into_iter()
            .filter(|row| process_matches_filter(row, &filter, &query))
            .collect::<Vec<_>>()
    });
    let selected_process = create_memo(move |_| {
        let selected_pid = selected_process_pid.get();
        selected_pid.and_then(|pid| process_rows.get().into_iter().find(|row| row.pid == pid))
    });
    let owlyshield_activity_logs = create_memo(move |_| {
        logs.get()
            .into_iter()
            .filter(is_owlyshield_log_entry)
            .take(10)
            .collect::<Vec<_>>()
    });

    create_effect(move |_| match current_view.get() {
        AppView::Processes => {
            fetch_process_inventory();
        }
        AppView::Rules | AppView::Owlyshield => {
            fetch_sdk_rules();
            fetch_rules_raw();
            fetch_body_changers();
            fetch_saved_logs();
            spawn_local(async move {
                let val = invoke("list_owlyshield_rules_files", JsValue::NULL).await;
                match serde_wasm_bindgen::from_value::<OwlyshieldRulesDirectoryView>(val) {
                    Ok(view) => {
                        let fallback_selected = view.files.first().map(|file| file.path.clone());
                        let selected_path = view.selected_path.clone().or(fallback_selected);
                        set_owlyshield_rules_directory.set(view.directory);
                        set_owlyshield_rule_files.set(view.files);
                        set_selected_owlyshield_rule_path.set(selected_path.clone());
                        if let Some(path) = selected_path {
                            let args = js_sys::Object::new();
                            js_sys::Reflect::set(&args, &"path".into(), &path.into()).unwrap();
                            let raw = invoke("get_owlyshield_rules_raw", args.into()).await;
                            match serde_wasm_bindgen::from_value::<String>(raw) {
                                Ok(content) => {
                                    set_owlyshield_rules_content.set(content);
                                    set_owlyshield_rules_status.set(String::new());
                                }
                                Err(_) => {
                                    set_owlyshield_rules_content.set(String::new());
                                    set_owlyshield_rules_status.set(
                                        "Failed to load the selected Owlyshield rule file."
                                            .to_string(),
                                    );
                                }
                            }
                        } else {
                            set_owlyshield_rules_content.set(String::new());
                            set_owlyshield_rules_status.set(
                                "No YAML rule files were found in the Owlyshield rules directory."
                                    .to_string(),
                            );
                        }
                    }
                    Err(_) => {
                        set_owlyshield_rule_files.set(Vec::new());
                        set_selected_owlyshield_rule_path.set(None);
                        set_owlyshield_rules_content.set(String::new());
                        set_owlyshield_rules_status
                            .set("Failed to enumerate the Owlyshield rules directory.".to_string());
                    }
                }
            });
            spawn_local(async move {
                let val = invoke("list_owlyshield_report_files", JsValue::NULL).await;
                match serde_wasm_bindgen::from_value::<OwlyshieldReportsDirectoryView>(val) {
                    Ok(view) => {
                        let fallback_selected = view.files.first().map(|file| file.path.clone());
                        let selected_path = view.selected_path.clone().or(fallback_selected);
                        set_owlyshield_reports_directory.set(view.directory);
                        set_owlyshield_report_files.set(view.files);
                        set_selected_owlyshield_report_path.set(selected_path.clone());
                        if let Some(path) = selected_path {
                            let args = js_sys::Object::new();
                            js_sys::Reflect::set(&args, &"path".into(), &path.into()).unwrap();
                            let raw = invoke("get_owlyshield_report_raw", args.into()).await;
                            match serde_wasm_bindgen::from_value::<String>(raw) {
                                Ok(content) => {
                                    set_owlyshield_report_content.set(content);
                                    if owlyshield_report_status
                                        .get_untracked()
                                        .starts_with("Report generation requested.")
                                    {
                                        set_owlyshield_report_status
                                            .set("Owlyshield report list refreshed.".to_string());
                                    }
                                }
                                Err(_) => {
                                    set_owlyshield_report_content.set(String::new());
                                    set_owlyshield_report_status.set(
                                        "Failed to load the selected Owlyshield report."
                                            .to_string(),
                                    );
                                }
                            }
                        } else {
                            set_owlyshield_report_content.set(String::new());
                            set_owlyshield_report_status.set(
                                "No Owlyshield reports were found in the reports directory."
                                    .to_string(),
                            );
                        }
                    }
                    Err(_) => {
                        set_owlyshield_report_files.set(Vec::new());
                        set_selected_owlyshield_report_path.set(None);
                        set_owlyshield_report_content.set(String::new());
                        set_owlyshield_report_status.set(
                            "Failed to enumerate the Owlyshield reports directory.".to_string(),
                        );
                    }
                }
            });
            spawn_local(async move {
                let val = invoke("list_firewall_quarantine_files", JsValue::NULL).await;
                match serde_wasm_bindgen::from_value::<FirewallQuarantineDirectoryView>(val) {
                    Ok(view) => {
                        set_firewall_quarantine_directory.set(view.directory);
                        set_firewall_quarantine_files.set(view.files);
                    }
                    Err(_) => {
                        set_firewall_quarantine_directory.set(String::new());
                        set_firewall_quarantine_files.set(Vec::new());
                    }
                }
            });
        }
        AppView::Logs => {
            fetch_saved_logs();
        }
        AppView::Exclusions => {
            fetch_app_decisions();
        }
        AppView::Settings => {
            fetch_settings();
            fetch_readme();
        }
        _ => {}
    });

    create_effect(move |_| {
        let rows = filtered_process_rows.get();
        let selected = selected_process_pid.get();
        match rows.first() {
            Some(first_row) if !rows.iter().any(|row| Some(row.pid) == selected) => {
                set_selected_process_pid.set(Some(first_row.pid));
            }
            None if selected.is_some() => {
                set_selected_process_pid.set(None);
            }
            _ => {}
        }
    });

    create_effect(move |_| {
        set_interval(
            move || {
                let snapshot = ActivitySnapshot {
                    logs: total_count.get_untracked(),
                    raw_packets: raw_packet_count.get_untracked(),
                    proxy_events: proxy_event_count.get_untracked(),
                    prompts: prompt_count.get_untracked(),
                };
                let previous = last_activity_snapshot.get_untracked();
                let delta = snapshot.delta_units(previous);
                set_last_activity_snapshot.set(snapshot);
                set_graph_data.update(|values| {
                    values.push(delta);
                    if values.len() > ACTIVITY_GRAPH_POINTS {
                        values.remove(0);
                    }
                });
            },
            Duration::from_millis(ACTIVITY_GRAPH_INTERVAL_MS),
        );
    });

    create_effect(move |_| {
        let closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(entry) = serde_json::from_value::<LogEntry>(payload_obj.clone()) {
                        set_logs.update(|l| {
                            l.push(entry.clone());
                            let current_settings = settings.get_untracked();
                            if current_settings.prune_old_logs {
                                let keep = current_settings.max_visible_logs.max(1);
                                if l.len() > keep {
                                    let remove_count = l.len() - keep;
                                    l.drain(0..remove_count);
                                }
                            }
                        });
                        set_total_count.update(|n| *n += 1);
                        if entry.message.contains("ACTIVE") || entry.message.contains("Engine") {
                            set_engine_status.set(entry.message.clone());
                            if entry.message.contains("ACTIVE") {
                                set_engine_active.set(true);
                            }
                        }
                        match entry.level {
                            LogLevel::Warning | LogLevel::Error => {
                                let message_lower = entry.message.to_lowercase();
                                if message_lower.starts_with("blocked:")
                                    || message_lower.contains("proxy intercept blocked")
                                    || message_lower.contains("access denied")
                                {
                                    set_blocked_count.update(|n| *n += 1);
                                }
                                if entry.message.contains("Malicious") {
                                    set_threats_count.update(|n| *n += 1);
                                }
                            }
                            LogLevel::Success => {
                                set_allowed_count.update(|n| *n += 1);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move {
            let _ = listen("log", &closure).await;
            closure.forget();
        });

        let ask_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(app) = serde_json::from_value::<PendingApp>(payload_obj.clone()) {
                        set_prompt_count.update(|count| *count += 1);
                        set_pending_app.set(Some(app));
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move {
            let _ = listen("ask_app_decision", &ask_closure).await;
            ask_closure.forget();
        });

        let raw_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(pkt) = serde_json::from_value::<RawPacket>(payload_obj.clone()) {
                        let current_settings = settings.get_untracked();
                        if current_settings.show_blocked_only && !pkt.action.eq_ignore_ascii_case("block") {
                            return;
                        }
                        let pkt_log = build_raw_packet_log_entry(&pkt);
                        set_raw_packet_count.update(|count| *count += 1);
                        set_raw_packets.update(|p| {
                            p.push(pkt);
                            if p.len() > 100 {
                                p.remove(0);
                            }
                        });
                        set_logs.update(|l| {
                            l.push(pkt_log);
                            if current_settings.prune_old_logs {
                                let keep = current_settings.max_visible_logs.max(1);
                                if l.len() > keep {
                                    let remove_count = l.len() - keep;
                                    l.drain(0..remove_count);
                                }
                            }
                        });
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move {
            let _ = listen("raw_packet", &raw_closure).await;
            raw_closure.forget();
        });

        let proxy_closure = Closure::wrap(Box::new(move |event: JsValue| {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<serde_json::Value>(event) {
                if let Some(payload_obj) = payload.get("payload") {
                    if let Ok(ev) = serde_json::from_value::<ProxyHttpEvent>(payload_obj.clone()) {
                        let current_settings = settings.get_untracked();
                        if current_settings.show_blocked_only {
                            return;
                        }
                        let http_log = build_proxy_log_entry(&ev);
                        set_proxy_event_count.update(|count| *count += 1);
                        set_proxy_events.update(|p| {
                            p.push(ev);
                            if current_settings.prune_http_history {
                                let keep = current_settings.max_visible_http_events.max(1);
                                if p.len() > keep {
                                    let remove_count = p.len() - keep;
                                    p.drain(0..remove_count);
                                }
                            }
                        });
                        set_logs.update(|l| {
                            l.push(http_log);
                            if current_settings.prune_old_logs {
                                let keep = current_settings.max_visible_logs.max(1);
                                if l.len() > keep {
                                    let remove_count = l.len() - keep;
                                    l.drain(0..remove_count);
                                }
                            }
                        });
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        spawn_local(async move {
            let _ = listen("proxy_http", &proxy_closure).await;
            proxy_closure.forget();
        });
    });

    {
        let refresh_engine_state = move || {
            spawn_local(async move {
                let window = web_sys::window().unwrap();
                let is_tauri = js_sys::Reflect::has(&window, &"__TAURI__".into()).unwrap_or(false);

                if !is_tauri {
                    set_engine_status
                        .set("Non-Tauri Browser Environment (Backend Unreachable)".to_string());
                    return;
                }

                let res = invoke("get_engine_runtime_status", JsValue::NULL).await;
                if let Ok(status) = serde_wasm_bindgen::from_value::<EngineRuntimeStatus>(res) {
                    set_engine_active.set(status.active);
                    set_engine_status.set(status.status);
                    set_mitm_enabled.set(status.mitm_enabled);
                    set_windows_root_trust_ready.set(status.windows_root_trust_ready);
                    set_firefox_policy_ready.set(status.firefox_policy_ready);
                    set_mitm_bypass_count.set(status.mitm_bypass_count);
                    if status.active && !settings_loaded.get_untracked() {
                        fetch_settings();
                        fetch_saved_logs();
                        set_settings_loaded.set(true);
                    }
                    if current_view.get_untracked() == AppView::Processes {
                        fetch_process_inventory();
                    }
                }
            });
        };

        refresh_engine_state();
        set_interval(refresh_engine_state, Duration::from_millis(1000));
    }

    let save_settings_action = move || {
        spawn_local(async move {
            let s = settings.get();
            let args = serde_wasm_bindgen::to_value(&s).unwrap();
            let _ = invoke("save_settings", args).await;
            set_settings_raw.set(serde_json::to_string_pretty(&s).unwrap_or_default());
            set_settings_raw_status.set("Saved GUI settings".to_string());
            fetch_settings();
            fetch_saved_logs();
            set_saved_status.set(true);
            set_timeout(move || set_saved_status.set(false), Duration::from_secs(2));
        });
    };

    let apply_raw_settings_action = move || {
        let raw = settings_raw.get();
        match serde_json::from_str::<FirewallSettings>(&raw) {
            Ok(parsed) => {
                set_settings.set(parsed.clone());
                set_settings_raw_status.set("Applying raw settings...".to_string());
                spawn_local(async move {
                    let args = serde_wasm_bindgen::to_value(&parsed).unwrap();
                    let _ = invoke("save_settings", args).await;
                    set_settings_raw.set(serde_json::to_string_pretty(&parsed).unwrap_or_default());
                    set_settings_raw_status.set("Raw settings applied".to_string());
                    fetch_settings();
                    fetch_saved_logs();
                    set_saved_status.set(true);
                    set_timeout(move || set_saved_status.set(false), Duration::from_secs(2));
                });
            }
            Err(error) => {
                set_settings_raw_status.set(format!("Invalid JSON: {}", error));
            }
        }
    };

    let update_path = move |path: String| {
        set_settings.update(|s| s.website_path = path);
    };

    view! {
        {move || if is_alert.get() {
            view! { <AlertWindow pending_app=pending_app set_pending_app=set_pending_app /> }.into_view()
        } else {
            view! {
                <div class={move || if is_dark.get() { "app-container" } else { "app-container light-theme" }}>

                    <aside>
                        <div class="logo-area">
                            <div class="logo-icon">
                                <img src="assets/HydraDragonAV.png?v=2" class="logo-dragon-img" alt="" />
                                <img src="assets/HydraDragonAV.png?v=2" class="logo-dragon-img logo-glitch-r" alt="" aria-hidden="true" />
                                <img src="assets/HydraDragonAV.png?v=2" class="logo-dragon-img logo-glitch-c" alt="" aria-hidden="true" />
                                <div class="logo-scanlines"></div>
                            </div>
                            <div>
                                <div class="logo-text">"HYDRADRAGON"</div>
                                <div class="logo-sub">"Firewall v0.1.0"</div>
                            </div>
                        </div>
                        <nav>
                            <div class="nav-group-label">"MONITOR"</div>
                            <a href="#" class={move || if current_view.get() == AppView::Dashboard { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Dashboard); }>
                               <span class="nav-icon">"⬡"</span>"Dashboard"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Processes { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Processes); }>
                               <span class="nav-icon">"◈"</span>"Processes"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Logs { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Logs); }>
                               <span class="nav-icon">"≋"</span>"Network Activity"
                            </a>

                            <div class="nav-group-label">"ANALYSIS"</div>
                            <a href="#" class={move || if current_view.get() == AppView::PacketReader { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::PacketReader); }>
                               <span class="nav-icon">"⬡"</span>"Packet Reader"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::HttpInspector { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::HttpInspector); }>
                               <span class="nav-icon">"◈"</span>"HTTP Inspector"
                            </a>

                            <div class="nav-group-label">"PROTECTION"</div>
                            <a href="#" class={move || if current_view.get() == AppView::Rules { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Rules); }>
                               <span class="nav-icon">"⬡"</span>"Protection Rules"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Owlyshield { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Owlyshield); }>
                               <span class="nav-icon">"◈"</span>"Owlyshield"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Exclusions { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Exclusions); }>
                               <span class="nav-icon">"≋"</span>"Exclusions"
                            </a>
                            <a href="#" class={move || if current_view.get() == AppView::Settings { "nav-item active" } else { "nav-item" }}
                               on:click=move |ev| { ev.prevent_default(); set_current_view.set(AppView::Settings); }>
                               <span class="nav-icon">"⬡"</span>"Settings"
                            </a>

                        </nav>
                    </aside>

                    <main>

                        <header style="display: flex; justify-content: space-between; align-items: center">
                            <h2 style="margin: 0; font-weight: 800; font-size: 28px">
                                {move || match current_view.get() {
                                    AppView::Dashboard => "Security Overview",
                                    AppView::Processes => "Process Explorer",
                                    AppView::Rules => "Protection Rules",
                                    AppView::Owlyshield => "Owlyshield Manager",
                                    AppView::Logs => "Network Activity",
                                    AppView::PacketReader => "Packet Inspection",
                                    AppView::HttpInspector => "HTTP Inspector",
                                    AppView::Exclusions => "Exclusions Management",
                                    AppView::Settings => "System Settings",
                                }}
                            </h2>
                            <div style="display: flex; align-items: center; gap: 16px">
                                <button
                                    class="theme-toggle-btn"
                                    on:click=move |_| {
                                        let new_dark = !is_dark.get();
                                        set_is_dark.set(new_dark);
                                        set_settings.update(|s| {
                                            s.metadata.insert("theme".to_string(), if new_dark { "cyberpunk".to_string() } else { "white".to_string() });
                                        });
                                        save_settings_action();
                                    }
                                    title="Toggle Theme"
                                >
                                    {move || if is_dark.get() { "☼" } else { "☾" }}
                                </button>
                                <span style={move || if engine_active.get() { "color: var(--accent-green); font-weight: 600; font-size: 14px" } else { "color: var(--accent-yellow); font-weight: 600; font-size: 14px" }}>
                                    {move || if engine_active.get() { "● SYSTEM SECURE" } else { "○ INITIALIZING..." }}
                                </span>
                            </div>
                        </header>


                        {move || match current_view.get() {
                            AppView::Dashboard => view! {
                                <div class="dashboard-grid">
                                    <div class="dash-col-main">
                                        <div class="glass-card status-card hero-status-card">
                                            <div class="status-hero">
                                                <div class="status-hero-left">
                                                    <div class="status-aura-container">
                                                        <div class="status-aura"></div>
                                                        <div class={move || if engine_active.get() { "status-shield-main secure" } else { "status-shield-main" }}>
                                                            <div class="status-shield-inner">
                                                                <span class="shield-check">
                                                                    {move || if engine_active.get() { "✓" } else { "!" }}
                                                                </span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="status-hero-right">
                                                    <h2 class="status-hero-title">
                                                        {move || if engine_active.get() { "Your system is secure" } else { "System is initializing" }}
                                                    </h2>
                                                    <div class="status-hero-features">
                                                        <div class="feature-item">
                                                            <span class="dot">"●"</span>
                                                            "Real-time monitoring active"
                                                        </div>
                                                        <div class="feature-item">
                                                            <span class="dot">"●"</span>
                                                            "Network rules enforced"
                                                        </div>
                                                        <div class="feature-item">
                                                            <span class="dot">"●"</span>
                                                            "Threat intelligence synchronized"
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                             <div class="traffic-graph-container">
                                                <svg width="100%" height="150" viewBox="0 0 600 150" class="traffic-svg">
                                                    <defs>
                                                        <linearGradient id="grad1" x1="0%" y1="0%" x2="0%" y2="100%">
                                                            <stop offset="0%" style="stop-color:var(--accent-blue);stop-opacity:0.6" />
                                                            <stop offset="100%" style="stop-color:var(--accent-blue);stop-opacity:0" />
                                                        </linearGradient>
                                                        <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                                                            <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(0, 207, 255, 0.1)" stroke-width="1"/>
                                                        </pattern>
                                                    </defs>
                                                    <rect width="100%" height="100%" fill="url(#grid)" />
                                                    <path
                                                        d=move || activity_fill_path.get()
                                                        fill="url(#grad1)"
                                                        stroke="none"
                                                    />
                                                    <path
                                                        d=move || activity_line_path.get()
                                                        fill="none"
                                                        stroke="var(--accent-blue)"
                                                        stroke-width="3"
                                                        stroke-linejoin="round"
                                                        stroke-linecap="round"
                                                        style="filter: drop-shadow(0 0 8px var(--accent-blue))"
                                                    />
                                                </svg>
                                            <div class="graph-overlay" style="position: absolute; top: 20px; right: 20px; text-align: right">
                                                <div class="traffic-stat">
                                                    <span class="label">"LIVE ACTIVITY"</span>
                                                    <span class="value" style="color:var(--accent-blue)">
                                                        {move || format!("{:.1} evt/s", current_activity_rate.get())}
                                                    </span>
                                                    <span class="label">{move || format!("Peak {:.1} evt/s", peak_activity_rate.get())}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                         <div class="glass-card logs-section">
                                            <div class="section-header">
                                                <h3 style="margin: 0; font-size: 16px; font-weight: 700">"Real-time Intelligence"</h3>
                                                <span style={move || if engine_active.get() { "font-size: 12px; color: var(--accent-green)" } else { "font-size: 12px; color: var(--t-muted)" }}>
                                                    {move || engine_status.get()}
                                                </span>
                                            </div>
                                            <div class="logs-viewport">
                                                <For
                                                    each={move || logs.get()}
                                                    key={|log_item| log_item.id.clone()}
                                                    children={move |log_item| {
                                                        let ts = log_item.timestamp % 100000;
                                                        let msg = log_item.message.clone();
                                                        let level_class = match log_item.level {
                                                            LogLevel::Info => "lvl-info",
                                                            LogLevel::Success => "lvl-success",
                                                            LogLevel::Warning => "lvl-warning",
                                                            LogLevel::Error => "lvl-error",
                                                            _ => "lvl-info",
                                                        };
                                                        view! {
                                                            <div class={format!("log-row {}", level_class)}>
                                                                <span class="log-time">"[" {ts} "]"</span>
                                                                <span class="log-msg">{msg}</span>
                                                            </div>
                                                        }
                                                    }}
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    <div class="dash-col-side">
                                         <div class="glass-card stat-item-compact">
                                            <h4>"Total Traffic"</h4>
                                            <div class="stat-value">{move || total_count.get()}</div>
                                        </div>
                                        <div class="glass-card stat-item-compact">
                                            <h4>"Blocked"</h4>
                                            <div class="stat-value" style="color: var(--accent-red)">{move || blocked_count.get()}</div>
                                        </div>
                                        <div class="glass-card stat-item-compact">
                                            <h4>"Allowed"</h4>
                                            <div class="stat-value" style="color: var(--accent-green)">{move || allowed_count.get()}</div>
                                        </div>
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Processes => {
                                let all_rows = process_rows.get();
                                let rows = filtered_process_rows.get();
                                let selected_pid = selected_process_pid.get();
                                let selected = selected_process.get();
                                let active_alert_for_selected = pending_app
                                    .get()
                                    .filter(|alert| Some(alert.process_id) == selected.as_ref().map(|row| row.pid));
                                let categories = vec![
                                    ("all".to_string(), format!("All ({})", all_rows.len())),
                                    ("pending".to_string(), format!("Pending ({})", all_rows.iter().filter(|row| row.pending_alert).count())),
                                    ("suspicious".to_string(), format!("Suspicious ({})", all_rows.iter().filter(|row| row.suspicious).count())),
                                    ("active".to_string(), format!("Active Network ({})", all_rows.iter().filter(|row| row.packet_count > 0).count())),
                                    ("browsers".to_string(), format!("Browsers ({})", all_rows.iter().filter(|row| row.kind == "Browsers").count())),
                                    ("services".to_string(), format!("Services ({})", all_rows.iter().filter(|row| row.kind == "Services").count())),
                                    (
                                        "windows".to_string(),
                                        format!(
                                            "Windows ({})",
                                            all_rows
                                                .iter()
                                                .filter(|row| row.kind == "Windows" || row.kind == "Windows Apps")
                                                .count()
                                        ),
                                    ),
                                ];

                                let detail_view = match selected {
                                    Some(row) => {
                                        let decision_text = decision_badge_label(row.decision.as_deref())
                                            .unwrap_or_else(|| "UNDECIDED".to_string());
                                        let openedr_verdict_text = row
                                            .openedr_verdict
                                            .clone()
                                            .unwrap_or_else(|| "No verdict".to_string());
                                        let recent_targets_view = if row.recent_targets.is_empty() {
                                            view! { <div class="process-detail-empty">"No observed remote targets yet."</div> }.into_view()
                                        } else {
                                            let targets = row.recent_targets.clone();
                                            view! {
                                                <div class="process-tag-cloud">
                                                    <For
                                                        each={move || targets.clone()}
                                                        key={|target| target.clone()}
                                                        children={move |target| view! { <span class="process-tag">{target}</span> }}
                                                    />
                                                </div>
                                            }.into_view()
                                        };
                                        let matched_rules_view = if row.matched_rules.is_empty() {
                                            view! {
                                                <div class="process-detail-empty">
                                                    "No packet-side rules have matched this process in the current session."
                                                </div>
                                            }.into_view()
                                        } else {
                                            let matched_rules = row.matched_rules.clone();
                                            view! {
                                                <div class="process-detail-list">
                                                    <For
                                                        each={move || matched_rules.clone()}
                                                        key={|rule| rule.clone()}
                                                        children={move |rule| view! { <div class="process-detail-list-item">{rule}</div> }}
                                                    />
                                                </div>
                                            }.into_view()
                                        };
                                        let alert_view = if let Some(alert) = active_alert_for_selected {
                                            let alert_target = alert.target.clone().unwrap_or_else(|| format!("{}:{}", alert.dst_ip, alert.dst_port));
                                            let alert_reason = alert.reason.clone().unwrap_or_else(|| "Prompt pending user decision".to_string());
                                            view! {
                                                <div class="process-detail-card alert">
                                                    <div class="process-detail-section-title">"Active Prompt"</div>
                                                    <div class="detail-row"><span class="detail-label">"Target"</span><span class="detail-value">{alert_target}</span></div>
                                                    <div class="detail-row"><span class="detail-label">"Reason"</span><span class="detail-value">{alert_reason}</span></div>
                                                </div>
                                            }.into_view()
                                        } else {
                                            view! {}.into_view()
                                        };

                                        view! {
                                            <div class="process-detail-stack">
                                                <div>
                                                    <div class="process-detail-heading">{row.name.clone()}</div>
                                                    <div class="process-detail-subheading">
                                                        {format!("PID {} - Parent {} - {}", row.pid, row.parent_pid, row.kind)}
                                                    </div>
                                                </div>
                                                <div class="process-detail-grid">
                                                    <div class="process-detail-card">
                                                        <div class="detail-row"><span class="detail-label">"Path"</span><span class="detail-value">{row.path.clone()}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"Threads"</span><span class="detail-value">{row.thread_count}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"Decision"</span><span class="detail-value">{decision_text}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"OpenEDR Verdict"</span><span class="detail-value">{openedr_verdict_text}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"Firewall Observed"</span><span class="detail-value">{if row.observed_by_firewall { "Yes" } else { "No" }}</span></div>
                                                    </div>
                                                    <div class="process-detail-card">
                                                        <div class="detail-row"><span class="detail-label">"Packets Seen"</span><span class="detail-value">{row.packet_count}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"Blocked / Denied"</span><span class="detail-value">{row.blocked_packet_count}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"Pending Alert"</span><span class="detail-value">{if row.pending_alert { "Yes" } else { "No" }}</span></div>
                                                        <div class="detail-row"><span class="detail-label">"Suspicious"</span><span class="detail-value">{if row.suspicious { "Yes" } else { "No" }}</span></div>
                                                    </div>
                                                </div>
                                                <div class="process-detail-card">
                                                    <div class="process-detail-section-title">"Recent Targets"</div>
                                                    {recent_targets_view}
                                                </div>
                                                <div class="process-detail-card">
                                                    <div class="process-detail-section-title">"Matched Rules / Reasons"</div>
                                                    {matched_rules_view}
                                                </div>
                                                {alert_view}
                                            </div>
                                        }.into_view()
                                    }
                                    None => view! {
                                        <div class="process-detail-empty">
                                            "Select a process to inspect its live packet activity, pending prompts, and matched rule context."
                                        </div>
                                    }.into_view(),
                                };

                                view! {
                                    <div class="process-explorer-grid">
                                        <div class="glass-card process-category-rail">
                                            <div class="process-pane-title">"Categories"</div>
                                            <div class="process-category-list">
                                                <For
                                                    each={move || categories.clone()}
                                                    key={|(key, _)| key.clone()}
                                                    children={move |(key, label)| {
                                                        let is_active = process_filter.get() == key;
                                                        let key_for_click = key.clone();
                                                        view! {
                                                            <button
                                                                class={if is_active { "process-category-chip active" } else { "process-category-chip" }}
                                                                on:click=move |_| set_process_filter.set(key_for_click.clone())
                                                            >
                                                                {label}
                                                            </button>
                                                        }
                                                    }}
                                                />
                                            </div>
                                        </div>
                                        <div class="glass-card process-list-pane">
                                            <div class="section-header" style="margin-bottom: 14px">
                                                <div>
                                                    <h3 style="margin: 0">"Observed Processes"</h3>
                                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px">
                                                        {format!("{} total, {} currently visible", all_rows.len(), rows.len())}
                                                    </div>
                                                </div>
                                                <button
                                                    class="btn-primary"
                                                    style="padding: 6px 14px; font-size: 11px"
                                                    on:click=move |_| fetch_process_inventory()
                                                >
                                                    "Refresh"
                                                </button>
                                            </div>
                                            <input
                                                type="text"
                                                class="process-search-input"
                                                placeholder="Search by name, PID, path, rule, or target..."
                                                prop:value=move || process_search.get()
                                                on:input=move |ev| set_process_search.set(event_target_value(&ev))
                                            />
                                            <div class="logs-viewport" style="margin-top: 14px">
                                                <For
                                                    each={move || rows.clone()}
                                                    key={|row| row.pid}
                                                    children={move |row| {
                                                        let is_selected = Some(row.pid) == selected_pid;
                                                        let pid = row.pid;
                                                        let status_badges = {
                                                            let mut badges = Vec::new();
                                                            if row.pending_alert {
                                                                badges.push(("PENDING".to_string(), "rgba(245, 158, 11, 0.18)".to_string(), "#f59e0b".to_string()));
                                                            }
                                                            if row.suspicious {
                                                                badges.push(("SUSPICIOUS".to_string(), "rgba(239, 68, 68, 0.18)".to_string(), "#ef4444".to_string()));
                                                            }
                                                            if row.observed_by_firewall {
                                                                badges.push(("OBSERVED".to_string(), "rgba(62, 148, 255, 0.18)".to_string(), "#60a5fa".to_string()));
                                                            }
                                                            if let Some(decision) = decision_badge_label(row.decision.as_deref()) {
                                                                badges.push((decision, "rgba(0, 255, 136, 0.12)".to_string(), "#00ff88".to_string()));
                                                            }
                                                            if let Some(openedr_badge) = openedr_verdict_badge(row.openedr_verdict.as_deref()) {
                                                                badges.push(openedr_badge);
                                                            } else if row.cloud_trusted {
                                                                badges.push(("OpenEDR: Possible Safe".to_string(), "rgba(34, 197, 94, 0.16)".to_string(), "#22c55e".to_string()));
                                                            }
                                                            badges
                                                        };
                                                        view! {
                                                            <button
                                                                class={if is_selected { "process-row-card selected" } else { "process-row-card" }}
                                                                on:click=move |_| set_selected_process_pid.set(Some(pid))
                                                            >
                                                                <div class="process-row-top">
                                                                    <div>
                                                                        <div class="process-row-title">{row.name.clone()}</div>
                                                                        <div class="process-row-subtitle">
                                                                            {format!("PID {} - Parent {} - {} threads - {}", row.pid, row.parent_pid, row.thread_count, row.kind)}
                                                                        </div>
                                                                    </div>
                                                                    <div class="process-row-metrics">
                                                                        <span>{format!("{} pkt", row.packet_count)}</span>
                                                                        <span>{format!("{} blocked", row.blocked_packet_count)}</span>
                                                                    </div>
                                                                </div>
                                                                <div class="process-row-path">{row.path.clone()}</div>
                                                                <div class="process-badge-row">
                                                                    <For
                                                                        each={move || status_badges.clone()}
                                                                        key={|(label, _, _)| label.clone()}
                                                                        children={move |(label, bg, fg)| view! {
                                                                            <span class="process-inline-badge" style={format!("background: {}; color: {}", bg, fg)}>
                                                                                {label}
                                                                            </span>
                                                                        }}
                                                                    />
                                                                </div>
                                                            </button>
                                                        }
                                                    }}
                                                />
                                            </div>
                                        </div>
                                        <div class="glass-card process-detail-pane">
                                            <div class="process-pane-title">"Details"</div>
                                            {detail_view}
                                        </div>
                                    </div>
                                }.into_view()
                            },
                            /*
                            AppView::Processes => {
                                let all_rows = process_rows.get();
                                let rows = filtered_process_rows.get();
                                let selected_pid = selected_process_pid.get();
                                let selected = selected_process.get();
                                let active_alert_for_selected = pending_app
                                    .get()
                                    .filter(|alert| Some(alert.process_id) == selected.as_ref().map(|row| row.pid));
                                let categories = vec![
                                    ("all".to_string(), format!("All ({})", all_rows.len())),
                                    (
                                        "pending".to_string(),
                                        format!(
                                            "Pending ({})",
                                            all_rows.iter().filter(|row| row.pending_alert).count()
                                        ),
                                    ),
                                    (
                                        "suspicious".to_string(),
                                        format!(
                                            "Suspicious ({})",
                                            all_rows.iter().filter(|row| row.suspicious).count()
                                        ),
                                    ),
                                    (
                                        "active".to_string(),
                                        format!(
                                            "Active Network ({})",
                                            all_rows.iter().filter(|row| row.packet_count > 0).count()
                                        ),
                                    ),
                                    (
                                        "browsers".to_string(),
                                        format!(
                                            "Browsers ({})",
                                            all_rows.iter().filter(|row| row.kind == "Browsers").count()
                                        ),
                                    ),
                                    (
                                        "services".to_string(),
                                        format!(
                                            "Services ({})",
                                            all_rows.iter().filter(|row| row.kind == "Services").count()
                                        ),
                                    ),
                                    (
                                        "windows".to_string(),
                                        format!(
                                            "Windows ({})",
                                            all_rows
                                                .iter()
                                                .filter(|row| row.kind == "Windows" || row.kind == "Windows Apps")
                                                .count()
                                        ),
                                    ),
                                ];

                                view! {
                                    <div class="process-explorer-grid">
                                        <div class="glass-card process-category-rail">
                                            <div class="process-pane-title">"Categories"</div>
                                            <div class="process-category-list">
                                                <For
                                                    each={move || categories.clone()}
                                                    key={|(key, _)| key.clone()}
                                                    children={move |(key, label)| {
                                                        let is_active = process_filter.get() == key;
                                                        let key_for_click = key.clone();
                                                        view! {
                                                            <button
                                                                class={if is_active { "process-category-chip active" } else { "process-category-chip" }}
                                                                on:click=move |_| set_process_filter.set(key_for_click.clone())
                                                            >
                                                                {label}
                                                            </button>
                                                        }
                                                    }}
                                                />
                                            </div>
                                        </div>

                                        <div class="glass-card process-list-pane">
                                            <div class="section-header" style="margin-bottom: 14px">
                                                <div>
                                                    <h3 style="margin: 0">"Observed Processes"</h3>
                                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px">
                                                        {format!("{} total, {} currently visible", all_rows.len(), rows.len())}
                                                    </div>
                                                </div>
                                                <button
                                                    class="btn-primary"
                                                    style="padding: 6px 14px; font-size: 11px"
                                                    on:click=move |_| fetch_process_inventory()
                                                >
                                                    "Refresh"
                                                </button>
                                            </div>
                                            <input
                                                type="text"
                                                class="process-search-input"
                                                placeholder="Search by name, PID, path, rule, or target..."
                                                prop:value=move || process_search.get()
                                                on:input=move |ev| set_process_search.set(event_target_value(&ev))
                                            />
                                            <div class="logs-viewport" style="margin-top: 14px">
                                                <For
                                                    each={move || rows.clone()}
                                                    key={|row| row.pid}
                                                    children={move |row| {
                                                        let is_selected = Some(row.pid) == selected_pid;
                                                        let pid = row.pid;
                                                        let status_badges = {
                                                            let mut badges = Vec::new();
                                                            if row.pending_alert {
                                                                badges.push(("PENDING".to_string(), "rgba(245, 158, 11, 0.18)".to_string(), "#f59e0b".to_string()));
                                                            }
                                                            if row.suspicious {
                                                                badges.push(("SUSPICIOUS".to_string(), "rgba(239, 68, 68, 0.18)".to_string(), "#ef4444".to_string()));
                                                            }
                                                            if row.observed_by_firewall {
                                                                badges.push(("OBSERVED".to_string(), "rgba(62, 148, 255, 0.18)".to_string(), "#60a5fa".to_string()));
                                                            }
                                                            if let Some(decision) = decision_badge_label(row.decision.as_deref()) {
                                                                badges.push((decision, "rgba(0, 255, 136, 0.12)".to_string(), "#00ff88".to_string()));
                                                            }
                                                            if let Some(openedr_badge) = openedr_verdict_badge(row.openedr_verdict.as_deref()) {
                                                                badges.push(openedr_badge);
                                                            } else if row.cloud_trusted {
                                                                badges.push(("OpenEDR: Possible Safe".to_string(), "rgba(34, 197, 94, 0.16)".to_string(), "#22c55e".to_string()));
                                                            }
                                                            badges
                                                        };
                                                        view! {
                                                            <button
                                                                class={if is_selected { "process-row-card selected" } else { "process-row-card" }}
                                                                on:click=move |_| set_selected_process_pid.set(Some(pid))
                                                            >
                                                                <div class="process-row-top">
                                                                    <div>
                                                                        <div class="process-row-title">{row.name.clone()}</div>
                                                                        <div class="process-row-subtitle">
                                                                            {format!("PID {} • Parent {} • {} threads • {}", row.pid, row.parent_pid, row.thread_count, row.kind)}
                                                                        </div>
                                                                    </div>
                                                                    <div class="process-row-metrics">
                                                                        <span>{format!("{} pkt", row.packet_count)}</span>
                                                                        <span>{format!("{} blocked", row.blocked_packet_count)}</span>
                                                                    </div>
                                                                </div>
                                                                <div class="process-row-path">{row.path.clone()}</div>
                                                                <div class="process-badge-row">
                                                                    <For
                                                                        each={move || status_badges.clone()}
                                                                        key={|(label, _, _)| label.clone()}
                                                                        children={move |(label, bg, fg)| view! {
                                                                            <span class="process-inline-badge" style={format!("background: {}; color: {}", bg, fg)}>
                                                                                {label}
                                                                            </span>
                                                                        }}
                                                                    />
                                                                </div>
                                                            </button>
                                                        }
                                                    }}
                                                />
                                            </div>
                                        </div>

                                        <div class="glass-card process-detail-pane">
                                            <div class="process-pane-title">"Details"</div>
                                            {match selected {
                                                Some(row) => {
                                                    let decision_label = decision_badge_label(row.decision.as_deref());
                                                    let openedr_verdict_label = row
                                                        .openedr_verdict
                                                        .clone()
                                                        .unwrap_or_else(|| "No verdict".to_string());
                                                    view! {
                                                        <div class="process-detail-stack">
                                                            <div>
                                                                <div class="process-detail-heading">{row.name.clone()}</div>
                                                                <div class="process-detail-subheading">
                                                                    {format!("PID {} • Parent {} • {}", row.pid, row.parent_pid, row.kind)}
                                                                </div>
                                                            </div>

                                                            <div class="process-detail-grid">
                                                                <div class="process-detail-card">
                                                                    <div class="detail-row"><span class="detail-label">"Path"</span><span class="detail-value">{row.path.clone()}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Threads"</span><span class="detail-value">{row.thread_count}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Decision"</span><span class="detail-value">{decision_label.unwrap_or_else(|| "UNDECIDED".to_string())}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"OpenEDR Verdict"</span><span class="detail-value">{openedr_verdict_label}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Firewall Observed"</span><span class="detail-value">{if row.observed_by_firewall { "Yes" } else { "No" }}</span></div>
                                                                </div>
                                                                <div class="process-detail-card">
                                                                    <div class="detail-row"><span class="detail-label">"Packets Seen"</span><span class="detail-value">{row.packet_count}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Blocked / Denied"</span><span class="detail-value">{row.blocked_packet_count}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Pending Alert"</span><span class="detail-value">{if row.pending_alert { "Yes" } else { "No" }}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Suspicious"</span><span class="detail-value">{if row.suspicious { "Yes" } else { "No" }}</span></div>
                                                                </div>
                                                            </div>

                                                            <div class="process-detail-card">
                                                                <div class="process-detail-section-title">"Recent Targets"</div>
                                                                {if row.recent_targets.is_empty() {
                                                                    view! { <div class="process-detail-empty">"No observed remote targets yet."</div> }
                                                                } else {
                                                                    view! {
                                                                        <div class="process-tag-cloud">
                                                                            <For
                                                                                each={move || row.recent_targets.clone()}
                                                                                key={|target| target.clone()}
                                                                                children={move |target| view! { <span class="process-tag">{target}</span> }}
                                                                            />
                                                                        </div>
                                                                    }
                                                                }}
                                                            </div>

                                                            <div class="process-detail-card">
                                                                <div class="process-detail-section-title">"Matched Rules / Reasons"</div>
                                                                {if row.matched_rules.is_empty() {
                                                                    view! { <div class="process-detail-empty">"No packet-side rules have matched this process in the current session."</div> }
                                                                } else {
                                                                    view! {
                                                                        <div class="process-detail-list">
                                                                            <For
                                                                                each={move || row.matched_rules.clone()}
                                                                                key={|rule| rule.clone()}
                                                                                children={move |rule| view! { <div class="process-detail-list-item">{rule}</div> }}
                                                                            />
                                                                        </div>
                                                                    }
                                                                }}
                                                            </div>

                                                            {active_alert_for_selected.map(|alert| view! {
                                                                <div class="process-detail-card alert">
                                                                    <div class="process-detail-section-title">"Active Prompt"</div>
                                                                    <div class="detail-row"><span class="detail-label">"Target"</span><span class="detail-value">{alert.target.clone().unwrap_or_else(|| format!("{}:{}", alert.dst_ip, alert.dst_port))}</span></div>
                                                                    <div class="detail-row"><span class="detail-label">"Reason"</span><span class="detail-value">{alert.reason.clone().unwrap_or_else(|| "Prompt pending user decision".to_string())}</span></div>
                                                                </div>
                                                            })}
                                                        </div>
                                                    }.into_view()
                                                }
                                                None => view! {
                                                    <div class="process-detail-empty">
                                                        "Select a process to inspect its live packet activity, pending prompts, and matched rule context."
                                                    </div>
                                                }.into_view(),
                                            }}
                                        </div>
                                    </div>
                                }.into_view()
                            },

                            */
                            AppView::Rules => view! {
                                <div style="height: calc(100vh - 120px); display: flex; flex-direction: column; gap: 0">
                                    // ── Tab Bar ──────────────────────────────────────────────
                                    <div style="display: flex; border-bottom: 1px solid #333; margin-bottom: 12px">
                                        <button
                                            class={move || if !show_editor.get() && !show_bc_form.get() && !show_owlyshield_editor.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_editor.set(false); set_show_bc_form.set(false); set_show_owlyshield_editor.set(false); }>
                                            "Rules Wiki"
                                        </button>
                                        <button
                                            class={move || if show_editor.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_editor.set(true); set_show_bc_form.set(false); set_show_owlyshield_editor.set(false); fetch_rules_raw(); }>
                                            "Edit YAML"
                                        </button>
                                        <button
                                            class={move || if show_bc_form.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_show_bc_form.set(true); set_show_editor.set(false); set_show_owlyshield_editor.set(false); fetch_body_changers(); }>
                                            "Body Changer"
                                        </button>
                                        <button
                                            class={move || if show_owlyshield_editor.get() { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| {
                                                set_show_owlyshield_editor.set(true);
                                                set_show_editor.set(false);
                                                set_show_bc_form.set(false);
                                                spawn_local(async move {
                                                    let val = invoke("list_owlyshield_rules_files", JsValue::NULL).await;
                                                    match serde_wasm_bindgen::from_value::<OwlyshieldRulesDirectoryView>(val) {
                                                        Ok(view) => {
                                                            let fallback_selected = view.files.first().map(|file| file.path.clone());
                                                            let selected_path = view.selected_path.clone().or(fallback_selected);
                                                            set_owlyshield_rules_directory.set(view.directory);
                                                            set_owlyshield_rule_files.set(view.files);
                                                            set_selected_owlyshield_rule_path.set(selected_path.clone());
                                                            if let Some(path) = selected_path {
                                                                let args = js_sys::Object::new();
                                                                js_sys::Reflect::set(&args, &"path".into(), &path.into()).unwrap();
                                                                let raw = invoke("get_owlyshield_rules_raw", args.into()).await;
                                                                match serde_wasm_bindgen::from_value::<String>(raw) {
                                                                    Ok(content) => {
                                                                        set_owlyshield_rules_content.set(content);
                                                                        set_owlyshield_rules_status.set(String::new());
                                                                    }
                                                                    Err(_) => {
                                                                        set_owlyshield_rules_content.set(String::new());
                                                                        set_owlyshield_rules_status.set("Failed to load the selected Owlyshield rule file.".to_string());
                                                                    }
                                                                }
                                                            } else {
                                                                set_owlyshield_rules_content.set(String::new());
                                                                set_owlyshield_rules_status.set("No YAML rule files were found in the Owlyshield rules directory.".to_string());
                                                            }
                                                        }
                                                        Err(_) => {
                                                            set_owlyshield_rule_files.set(Vec::new());
                                                            set_selected_owlyshield_rule_path.set(None);
                                                            set_owlyshield_rules_content.set(String::new());
                                                            set_owlyshield_rules_status.set("Failed to enumerate the Owlyshield rules directory.".to_string());
                                                        }
                                                    }
                                                });
                                            }>
                                            "Owlyshield Rules"
                                        </button>
                                        // save/validate buttons for YAML tabs
                                        {move || if show_editor.get() {
                                            view! {
                                                <div style="margin-left: auto; display: flex; gap: 10px; align-items: center">
                                                    <button class="btn-secondary" on:click=move |_| validate_rules_raw()> "Validate" </button>
                                                    <button class="btn-primary" on:click=move |_| save_rules_raw()> "Save" </button>
                                                </div>
                                            }.into_view()
                                        } else if show_owlyshield_editor.get() {
                                            view! {
                                                <div style="margin-left: auto; display: flex; gap: 10px; align-items: center">
                                                    <button class="btn-primary" on:click=move |_| save_owlyshield_rules()> "Save" </button>
                                                </div>
                                            }.into_view()
                                        } else { view!{}.into_view() }}
                                    </div>

                                    // ── Tab Content ──────────────────────────────────────────
                                    <div style="flex: 1; overflow: hidden">
                                    {move || if show_editor.get() {
                                        view! {
                                            <textarea class="glass-card" style="width: 100%; height: 100%; box-sizing: border-box; padding: 20px; font-family: monospace; resize: none"
                                                prop:value=move || rules_raw_content.get()
                                                on:input=move |ev| set_rules_raw_content.set(event_target_value(&ev)) />
                                        }.into_view()
                                    } else if show_owlyshield_editor.get() {
                                        view! {
                                            <div style="display: flex; flex-direction: column; height: 100%; gap: 8px">
                                                <div class="glass-card" style="padding: 12px 16px; font-size: 12px; color: var(--text-muted); display: flex; flex-direction: column; gap: 10px">
                                                    <div>
                                                        "Editing Owlyshield behavioral rules — directory resolved from "
                                                        <code style="color: var(--accent-blue)">"SOFTWARE\\Owlyshield → RULES_PATH"</code>
                                                    </div>
                                                    <div style="display: flex; gap: 12px; align-items: end; flex-wrap: wrap">
                                                        <div class="input-group" style="margin: 0; min-width: 280px; flex: 1">
                                                            <label style="margin-bottom: 6px">"Rules file"</label>
                                                            <select
                                                                prop:value=move || selected_owlyshield_rule_path.get().unwrap_or_default()
                                                                prop:disabled=move || owlyshield_rule_files.get().is_empty()
                                                                on:change=move |ev| {
                                                                    let selected = event_target_value(&ev);
                                                                    set_selected_owlyshield_rule_path.set(Some(selected.clone()));
                                                                    spawn_local(async move {
                                                                        let args = js_sys::Object::new();
                                                                        js_sys::Reflect::set(&args, &"path".into(), &selected.into()).unwrap();
                                                                        let raw = invoke("get_owlyshield_rules_raw", args.into()).await;
                                                                        match serde_wasm_bindgen::from_value::<String>(raw) {
                                                                            Ok(content) => {
                                                                                set_owlyshield_rules_content.set(content);
                                                                                set_owlyshield_rules_status.set(String::new());
                                                                            }
                                                                            Err(_) => {
                                                                                set_owlyshield_rules_content.set(String::new());
                                                                                set_owlyshield_rules_status.set("Failed to load the selected Owlyshield rule file.".to_string());
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                            >
                                                                <For
                                                                    each={move || owlyshield_rule_files.get()}
                                                                    key={|file| file.path.clone()}
                                                                    children={move |file| view! {
                                                                        <option value={file.path.clone()}>{file.name.clone()}</option>
                                                                    }}
                                                                />
                                                            </select>
                                                        </div>
                                                        <button class="btn-secondary" on:click=move |_| {
                                                            spawn_local(async move {
                                                                let val = invoke("list_owlyshield_rules_files", JsValue::NULL).await;
                                                                match serde_wasm_bindgen::from_value::<OwlyshieldRulesDirectoryView>(val) {
                                                                    Ok(view) => {
                                                                        let fallback_selected = view.files.first().map(|file| file.path.clone());
                                                                        let selected_path = view.selected_path.clone().or(fallback_selected);
                                                                        set_owlyshield_rules_directory.set(view.directory);
                                                                        set_owlyshield_rule_files.set(view.files);
                                                                        set_selected_owlyshield_rule_path.set(selected_path.clone());
                                                                        if let Some(path) = selected_path {
                                                                            let args = js_sys::Object::new();
                                                                            js_sys::Reflect::set(&args, &"path".into(), &path.into()).unwrap();
                                                                            let raw = invoke("get_owlyshield_rules_raw", args.into()).await;
                                                                            match serde_wasm_bindgen::from_value::<String>(raw) {
                                                                                Ok(content) => {
                                                                                    set_owlyshield_rules_content.set(content);
                                                                                    set_owlyshield_rules_status.set(String::new());
                                                                                }
                                                                                Err(_) => {
                                                                                    set_owlyshield_rules_content.set(String::new());
                                                                                    set_owlyshield_rules_status.set("Failed to load the selected Owlyshield rule file.".to_string());
                                                                                }
                                                                            }
                                                                        } else {
                                                                            set_owlyshield_rules_content.set(String::new());
                                                                            set_owlyshield_rules_status.set("No YAML rule files were found in the Owlyshield rules directory.".to_string());
                                                                        }
                                                                    }
                                                                    Err(_) => {
                                                                        set_owlyshield_rule_files.set(Vec::new());
                                                                        set_selected_owlyshield_rule_path.set(None);
                                                                        set_owlyshield_rules_content.set(String::new());
                                                                        set_owlyshield_rules_status.set("Failed to enumerate the Owlyshield rules directory.".to_string());
                                                                    }
                                                                }
                                                            });
                                                        }>
                                                            "Refresh Files"
                                                        </button>
                                                    </div>
                                                    <div>
                                                        <strong>"Directory: "</strong>
                                                        <code style="color: var(--accent-blue)">{move || owlyshield_rules_directory.get()}</code>
                                                    </div>
                                                    <div>
                                                        <strong>"Selected file: "</strong>
                                                        <code style="color: var(--accent-blue)">
                                                            {move || selected_owlyshield_rule_path.get().unwrap_or_else(|| "No file selected".to_string())}
                                                        </code>
                                                    </div>
                                                    {move || if !owlyshield_rules_status.get().is_empty() {
                                                        view! {
                                                            <div style="color: var(--accent-orange)">{owlyshield_rules_status.get()}</div>
                                                        }.into_view()
                                                    } else {
                                                        view! {}.into_view()
                                                    }}
                                                </div>
                                                <textarea class="glass-card" style="flex: 1; width: 100%; box-sizing: border-box; padding: 20px; font-family: monospace; resize: none"
                                                    prop:value=move || owlyshield_rules_content.get()
                                                    on:input=move |ev| set_owlyshield_rules_content.set(event_target_value(&ev)) />
                                            </div>
                                        }.into_view()
                                    } else if show_bc_form.get() {
                                        // ── Body Changer Panel ────────────────────────────────
                                        view! {
                                            <div style="display: flex; gap: 15px; height: 100%; overflow: hidden">
                                                // Left: list
                                                <div class="glass-card" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column">
                                                    <div class="section-header">
                                                        <h3 style="margin: 0; color: var(--t-primary)">"Body Changer Rules"</h3>
                                                        <button class="btn-primary" style="padding: 5px 14px; font-size: 12px"
                                                            on:click=move |_| {
                                                                // Clear the form for a new rule
                                                                set_bc_edit_id.set(None);
                                                                set_bc_name.set(String::new());
                                                                set_bc_target.set("request".to_string());
                                                                set_bc_url_pattern.set(String::new());
                                                                set_bc_method_pattern.set(String::new());
                                                                set_bc_replacement.set(String::new());
                                                                set_bc_enabled.set(true);
                                                            }>"+ New Rule"</button>
                                                    </div>
                                                    <div style="flex: 1; overflow-y: auto">
                                                        <For
                                                            each={move || body_changers.get()}
                                                            key={|r| r.id.clone()}
                                                            children={move |rule| {
                                                                let r2 = rule.clone();
                                                                let r3 = rule.clone();
                                                                let target_label = if rule.target == "response" { "Response" } else { "Request" };
                                                                let target_color = if rule.target == "response" { "#a78bfa" } else { "#60a5fa" };
                                                                view! {
                                                                    <div class="log-row lvl-info"
                                                                        style="display: flex; justify-content: space-between; align-items: center; cursor: pointer"
                                                                        on:click=move |_| {
                                                                            set_bc_edit_id.set(Some(r2.id.clone()));
                                                                            set_bc_name.set(r2.name.clone());
                                                                            set_bc_target.set(r2.target.clone());
                                                                            set_bc_url_pattern.set(r2.url_pattern.clone());
                                                                            set_bc_method_pattern.set(r2.method_pattern.clone());
                                                                            set_bc_replacement.set(r2.replacement.clone());
                                                                            set_bc_enabled.set(r2.enabled);
                                                                        }>
                                                                        <div style="display: flex; align-items: center; gap: 8px; flex: 1; overflow: hidden">
                                                                            <span style={format!("color: {}; font-size: 11px; font-weight: 700; min-width: 60px", target_color)}>{target_label}</span>
                                                                            <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{rule.name.clone()}</span>
                                                                            {if !rule.url_pattern.is_empty() {
                                                                                view! { <span style="color: var(--text-muted); font-size: 10px; margin-left: 4px">{rule.url_pattern.clone()}</span> }.into_view()
                                                                            } else { view!{}.into_view() }}
                                                                        </div>
                                                                        <div style="display: flex; align-items: center; gap: 6px">
                                                                            {if !rule.enabled { view! { <span style="color: #888; font-size: 10px">"disabled"</span> }.into_view() } else { view!{}.into_view() }}
                                                                            <button
                                                                                style="background: var(--accent-red); border: none; border-radius: 3px; color: white; padding: 2px 8px; font-size: 11px; cursor: pointer"
                                                                                on:click=move |ev| {
                                                                                    ev.stop_propagation();
                                                                                    let id = r3.id.clone();
                                                                                    let mut updated = body_changers.get();
                                                                                    updated.retain(|r| r.id != id);
                                                                                    save_body_changers_fn(updated);
                                                                                }>"Delete"</button>
                                                                        </div>
                                                                    </div>
                                                                }
                                                            }}
                                                        />
                                                    </div>
                                                </div>

                                                // Right: edit form
                                                <div class="glass-card" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; padding: 20px">
                                                    <h3 style="margin: 0">
                                                        {move || if bc_edit_id.get().is_some() { "Edit Rule" } else { "New Rule" }}
                                                    </h3>
                                                    <div class="input-group">
                                                        <label>"Rule Name"</label>
                                                        <input type="text" placeholder="My Body Changer"
                                                            prop:value=move || bc_name.get()
                                                            on:input=move |ev| set_bc_name.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Target"</label>
                                                        <select
                                                            on:change=move |ev| set_bc_target.set(event_target_value(&ev))>
                                                            <option value="request" selected={move || bc_target.get() == "request"}>"Request Body"</option>
                                                            <option value="response" selected={move || bc_target.get() == "response"}>"Response Body"</option>
                                                        </select>
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"URL Pattern (substring match, empty = all)"</label>
                                                        <input type="text" placeholder="example.com/api"
                                                            prop:value=move || bc_url_pattern.get()
                                                            on:input=move |ev| set_bc_url_pattern.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"HTTP Method (e.g. POST, empty = any)"</label>
                                                        <input type="text" placeholder="POST"
                                                            prop:value=move || bc_method_pattern.get()
                                                            on:input=move |ev| set_bc_method_pattern.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Replacement Body"</label>
                                                        <textarea
                                                            style="font-family: monospace; min-height: 120px; resize: vertical; padding: 8px"
                                                            placeholder=r#"{"key":"value"}"#
                                                            prop:value=move || bc_replacement.get()
                                                            on:input=move |ev| set_bc_replacement.set(event_target_value(&ev)) />
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 8px">
                                                            <input type="checkbox"
                                                                prop:checked=move || bc_enabled.get()
                                                                on:change=move |ev| set_bc_enabled.set(event_target_checked(&ev)) />
                                                            "Enabled"
                                                        </label>
                                                    </div>
                                                    <div style="display: flex; gap: 10px; margin-top: 8px">
                                                        <button class="btn-primary" on:click=move |_| {
                                                            let name = bc_name.get();
                                                            if name.trim().is_empty() { return; }
                                                            let id = bc_edit_id.get()
                                                                .unwrap_or_else(|| {
                                                                    // simple unique id: timestamp millis
                                                                    js_sys::Date::now().to_bits().to_string()
                                                                });
                                                            let new_rule = BodyChangerRule {
                                                                id: id.clone(),
                                                                name,
                                                                enabled: bc_enabled.get(),
                                                                target: bc_target.get(),
                                                                url_pattern: bc_url_pattern.get(),
                                                                method_pattern: bc_method_pattern.get(),
                                                                replacement: bc_replacement.get(),
                                                            };
                                                            let mut updated = body_changers.get();
                                                            if let Some(pos) = updated.iter().position(|r| r.id == id) {
                                                                updated[pos] = new_rule;
                                                            } else {
                                                                updated.push(new_rule);
                                                            }
                                                            save_body_changers_fn(updated);
                                                            // Reset form
                                                            set_bc_edit_id.set(None);
                                                            set_bc_name.set(String::new());
                                                            set_bc_url_pattern.set(String::new());
                                                            set_bc_method_pattern.set(String::new());
                                                            set_bc_replacement.set(String::new());
                                                            set_bc_enabled.set(true);
                                                        }>"Save Rule"</button>
                                                        <button class="btn-secondary" on:click=move |_| {
                                                            set_bc_edit_id.set(None);
                                                            set_bc_name.set(String::new());
                                                            set_bc_url_pattern.set(String::new());
                                                            set_bc_method_pattern.set(String::new());
                                                            set_bc_replacement.set(String::new());
                                                            set_bc_enabled.set(true);
                                                        }>"Clear"</button>
                                                    </div>
                                                </div>
                                            </div>
                                        }.into_view()
                                    } else {
                                        view! {
                                            <div style="display: flex; flex-direction: column; gap: 15px; height: 100%; overflow: hidden">
                                                <div class="glass-card" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column">
                                                    <div class="section-header">
                                                        <h3 style="margin: 0; color: var(--t-primary)">"Active SDK Rules"</h3>
                                                        <span style="font-size: 11px; opacity: 0.6">"Real-time Behavioral Enforcement"</span>
                                                    </div>
                                                    <div style="padding: 15px; flex: 1; overflow-y: auto">
                                                        <For
                                                            each={move || sdk_rules.get()}
                                                            key={|r| r.name.clone()}
                                                            children={move |rule| {
                                                                let bg = if rule.enabled { "rgba(96, 165, 250, 0.05)" } else { "rgba(0,0,0,0.2)" };
                                                                let border = if rule.enabled { "1px solid rgba(96, 165, 250, 0.2)" } else { "1px solid rgba(255,255,255,0.05)" };
                                                                view! {
                                                                    <div style={format!("background: {}; border: {}; border-radius: 8px; padding: 15px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 8px", bg, border)}>
                                                                        <div style="display: flex; justify-content: space-between; align-items: flex-start">
                                                                            <div>
                                                                                <h4 style="margin: 0; color: var(--text-bright); font-size: 14px">{rule.name.clone()}</h4>
                                                                                <p style="margin: 4px 0 0 0; font-size: 12px; color: var(--text-muted)">{rule.description.clone()}</p>
                                                                            </div>
                                                                            <div style="display: flex; gap: 8px">
                                                                                <span class={format!("badge {}", if rule.enabled { "badge-success" } else { "badge-secondary" })}>
                                                                                    {if rule.enabled { "ENABLED" } else { "DISABLED" }}
                                                                                </span>
                                                                                <span class="badge" style="background: var(--accent-blue); color: white">
                                                                                    {format!("{:?}", rule.action)}
                                                                                </span>
                                                                            </div>
                                                                        </div>
                                                                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 5px; font-size: 11px; opacity: 0.8">
                                                                            <div>"Protocol: " <span style="color: var(--accent-orange)">{rule.protocol.clone()}</span></div>
                                                                            <div>"Logic: " <span style="color: var(--accent-blue)">{rule.condition_logic.clone()}</span></div>
                                                                            <div>"Encoding: " <span style="color: #a78bfa">{rule.encoding.clone()}</span></div>
                                                                        </div>
                                                                        {if rule.change_request_body.is_some() || rule.change_response_body.is_some() {
                                                                            view! {
                                                                                <div style="margin-top: 5px; padding: 8px; background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 10px; font-family: monospace">
                                                                                    <div style="color: #60a5fa">"⚡ BODY MODIFICATION ACTIVE"</div>
                                                                                </div>
                                                                            }.into_view()
                                                                        } else { view!{}.into_view() }}
                                                                    </div>
                                                                }
                                                            }}
                                                        />
                                                    </div>
                                                </div>
                                                <RulesWiki />
                                            </div>
                                        }.into_view()
                                    }}
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Owlyshield => view! {
                                <div style="height: calc(100vh - 120px); display: flex; gap: 16px; min-height: 0;">
                                    <div style="width: 360px; min-width: 320px; display: flex; flex-direction: column; gap: 14px; min-height: 0; overflow-y: auto; padding-right: 4px;">
                                        <div class="glass-card" style="padding: 18px; display: flex; flex-direction: column; gap: 12px;">
                                            <div class="section-header" style="padding: 0; border: none;">
                                                <h3 style="margin: 0; color: var(--t-primary)">"Owlyshield Report Manager"</h3>
                                            </div>
                                            <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.55;">
                                                "Advanced reports are requested from the firewall GUI, but generation is handled by the Owlyshield backend."
                                            </p>
                                            <button class="btn-primary" style="width: 100%;" on:click=move |_| request_owlyshield_report()>
                                                "Generate Advanced Report"
                                            </button>
                                            <div style="padding: 12px; border-radius: 10px; background: rgba(15, 23, 42, 0.48); border: 1px solid rgba(96, 165, 250, 0.16); font-size: 12px; line-height: 1.5;">
                                                <div><strong>"Reports directory: "</strong>{move || owlyshield_reports_directory.get()}</div>
                                                <div style="margin-top: 6px;"><strong>"Latest report: "</strong>{move || selected_owlyshield_report_path.get().unwrap_or_else(|| "No report selected".to_string())}</div>
                                                <div style="margin-top: 6px;"><strong>"Rules directory: "</strong>{move || owlyshield_rules_directory.get()}</div>
                                                {move || if !owlyshield_report_status.get().is_empty() {
                                                    view! {
                                                        <div style="margin-top: 8px; color: var(--accent-orange);">{owlyshield_report_status.get()}</div>
                                                    }.into_view()
                                                } else {
                                                    view! {}.into_view()
                                                }}
                                            </div>
                                        </div>

                                        <div class="glass-card" style="padding: 18px; display: flex; flex-direction: column; gap: 10px;">
                                            <div class="section-header" style="padding: 0; border: none;">
                                                <h3 style="margin: 0;">"Prompt & Decode Defaults"</h3>
                                            </div>
                                            <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.55;">
                                                "Owlyshield now treats `ask_user: true` rules as deny-while-asking by default. Keep `suspend_while_ask: true` only on rules where you want the process paused."
                                            </p>
                                            <div style="font-size: 12px; line-height: 1.6; color: var(--text-muted);">
                                                <div>"Decoded match sources: plain, base64, base58, hex, reverse"</div>
                                                <div>"JSON matching now checks decoded request/response bodies instead of only preview text."</div>
                                            </div>
                                            <pre style="margin: 0; background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 8px; padding: 12px; font-size: 11px; color: #a5d6ff; overflow-x: auto;">"response:
  ask_user: true
  suspend_while_ask: false
  deny_while_ask: true"</pre>
                                        </div>
                                    </div>

                                    <div style="flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 12px; min-height: 0;">
                                        <div class="glass-card" style="padding: 14px 16px; font-size: 12px; color: var(--text-muted); display: flex; flex-direction: column; gap: 10px;">
                                            <div class="section-header" style="padding: 0; border: none;">
                                                <h3 style="margin: 0; color: var(--t-primary)">"Generated Report Browser"</h3>
                                                <div style="display: flex; gap: 8px;">
                                                    <button class="btn-secondary" on:click=move |_| set_current_view.set(AppView::Rules)>
                                                        "Open Rules Editor"
                                                    </button>
                                                    <button class="btn-secondary" on:click=move |_| {
                                                        spawn_local(async move {
                                                            let val = invoke("list_owlyshield_report_files", JsValue::NULL).await;
                                                            match serde_wasm_bindgen::from_value::<OwlyshieldReportsDirectoryView>(val) {
                                                                Ok(view) => {
                                                                    let fallback_selected = view.files.first().map(|file| file.path.clone());
                                                                    let selected_path = view.selected_path.clone().or(fallback_selected);
                                                                    set_owlyshield_reports_directory.set(view.directory);
                                                                    set_owlyshield_report_files.set(view.files);
                                                                    set_selected_owlyshield_report_path.set(selected_path.clone());
                                                                    if let Some(path) = selected_path {
                                                                        let args = js_sys::Object::new();
                                                                        js_sys::Reflect::set(&args, &"path".into(), &path.into()).unwrap();
                                                                        let raw = invoke("get_owlyshield_report_raw", args.into()).await;
                                                                        match serde_wasm_bindgen::from_value::<String>(raw) {
                                                                            Ok(content) => {
                                                                                set_owlyshield_report_content.set(content);
                                                                                set_owlyshield_report_status.set("Owlyshield report list refreshed.".to_string());
                                                                            }
                                                                            Err(_) => {
                                                                                set_owlyshield_report_content.set(String::new());
                                                                                set_owlyshield_report_status.set("Failed to load the selected Owlyshield report.".to_string());
                                                                            }
                                                                        }
                                                                    } else {
                                                                        set_owlyshield_report_content.set(String::new());
                                                                        set_owlyshield_report_status.set("No Owlyshield reports were found in the reports directory.".to_string());
                                                                    }
                                                                }
                                                                Err(_) => {
                                                                    set_owlyshield_report_files.set(Vec::new());
                                                                    set_selected_owlyshield_report_path.set(None);
                                                                    set_owlyshield_report_content.set(String::new());
                                                                    set_owlyshield_report_status.set("Failed to enumerate the Owlyshield reports directory.".to_string());
                                                                }
                                                            }
                                                        });
                                                    }>
                                                        "Refresh Reports"
                                                    </button>
                                                </div>
                                            </div>
                                            <div>
                                                <strong>"Directory: "</strong>
                                                <code style="color: var(--accent-blue)">{move || owlyshield_reports_directory.get()}</code>
                                            </div>
                                            <div style="display: flex; gap: 16px; flex-wrap: wrap;">
                                                <div><strong>"Reports: "</strong>{move || owlyshield_report_files.get().len().to_string()}</div>
                                                <div><strong>"Selected: "</strong>{move || selected_owlyshield_report_path.get().unwrap_or_else(|| "None".to_string())}</div>
                                            </div>
                                        </div>

                                        <div style="flex: 1; min-height: 0; display: flex; gap: 14px;">
                                            <div class="glass-card" style="width: 320px; min-width: 280px; display: flex; flex-direction: column; min-height: 0;">
                                                <div class="section-header">
                                                    <h3 style="margin: 0; color: var(--t-primary)">"Reports"</h3>
                                                    <span style="font-size: 11px; opacity: 0.7;">{move || owlyshield_report_files.get().len().to_string()}</span>
                                                </div>
                                                <div style="padding: 12px; display: flex; flex-direction: column; gap: 8px; overflow-y: auto; min-height: 0;">
                                                    <For
                                                        each={move || owlyshield_report_files.get()}
                                                        key={|file| file.path.clone()}
                                                        children={move |file| {
                                                            let file_path = file.path.clone();
                                                            let active_path = file_path.clone();
                                                            let report_name = file.name.clone();
                                                            let modified = format_unix_timestamp(file.modified_ts);
                                                            let size_label = format_file_size_bytes(file.size_bytes);
                                                            view! {
                                                                <button
                                                                    style=move || {
                                                                        let active = selected_owlyshield_report_path.get().as_deref() == Some(active_path.as_str());
                                                                        if active {
                                                                            "text-align: left; width: 100%; padding: 12px; border-radius: 10px; border: 1px solid rgba(96, 165, 250, 0.35); background: rgba(59, 130, 246, 0.14); color: var(--text-bright); cursor: pointer;"
                                                                        } else {
                                                                            "text-align: left; width: 100%; padding: 12px; border-radius: 10px; border: 1px solid rgba(148, 163, 184, 0.12); background: rgba(15, 23, 42, 0.48); color: var(--text-bright); cursor: pointer;"
                                                                        }
                                                                    }
                                                                    on:click=move |_| {
                                                                        let selected = file_path.clone();
                                                                        set_selected_owlyshield_report_path.set(Some(selected.clone()));
                                                                        spawn_local(async move {
                                                                            let args = js_sys::Object::new();
                                                                            js_sys::Reflect::set(&args, &"path".into(), &selected.into()).unwrap();
                                                                            let raw = invoke("get_owlyshield_report_raw", args.into()).await;
                                                                            match serde_wasm_bindgen::from_value::<String>(raw) {
                                                                                Ok(content) => {
                                                                                    set_owlyshield_report_content.set(content);
                                                                                    set_owlyshield_report_status.set(String::new());
                                                                                }
                                                                                Err(_) => {
                                                                                    set_owlyshield_report_content.set(String::new());
                                                                                    set_owlyshield_report_status.set("Failed to load the selected Owlyshield report.".to_string());
                                                                                }
                                                                            }
                                                                        });
                                                                    }>
                                                                    <div style="font-size: 12px; font-weight: 700; margin-bottom: 4px;">{report_name}</div>
                                                                    <div style="font-size: 11px; color: var(--text-muted);">{modified}</div>
                                                                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">{size_label}</div>
                                                                </button>
                                                            }
                                                        }}
                                                    />
                                                    {move || if owlyshield_report_files.get().is_empty() {
                                                        view! {
                                                            <div style="padding: 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.35); color: var(--text-muted); font-size: 12px;">
                                                                "No generated reports are available yet."
                                                            </div>
                                                        }.into_view()
                                                    } else {
                                                        view! {}.into_view()
                                                    }}
                                                </div>
                                            </div>

                                            <div class="glass-card" style="flex: 1; min-width: 0; display: flex; flex-direction: column; min-height: 0;">
                                                <div class="section-header">
                                                    <h3 style="margin: 0; color: var(--t-primary)">"Report Details"</h3>
                                                    <span style="font-size: 11px; opacity: 0.7;">
                                                        {move || selected_owlyshield_report_path.get().unwrap_or_else(|| "No report selected".to_string())}
                                                    </span>
                                                </div>
                                                <div style="padding: 14px; min-height: 0; flex: 1; overflow: auto;">
                                                    {move || if owlyshield_report_content.get().trim().is_empty() {
                                                        view! {
                                                            <div style="padding: 14px; border-radius: 8px; background: rgba(15, 23, 42, 0.35); color: var(--text-muted); font-size: 12px;">
                                                                "Select a generated report to inspect the full Owlyshield output."
                                                            </div>
                                                        }.into_view()
                                                    } else {
                                                        view! {
                                                            <pre style="margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font-family: Consolas, 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.5; color: #d6e2f0;">{move || owlyshield_report_content.get()}</pre>
                                                        }.into_view()
                                                    }}
                                                </div>
                                            </div>
                                        </div>

                                        <div style="display: flex; gap: 14px; min-height: 280px; max-height: 340px;">
                                            <div class="glass-card" style="flex: 1; min-width: 0; display: flex; flex-direction: column; min-height: 0;">
                                                <div class="section-header">
                                                    <h3 style="margin: 0; color: var(--t-primary)">"Quarantine Manager"</h3>
                                                </div>
                                                <div style="padding: 14px; display: flex; flex-direction: column; gap: 10px; min-height: 0; overflow: hidden;">
                                                    <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.55;">
                                                        "Recent files currently stored in the firewall quarantine directory."
                                                    </p>
                                                    <div style="font-size: 11px; color: var(--text-muted); overflow-wrap: anywhere;">
                                                        {move || firewall_quarantine_directory.get()}
                                                    </div>
                                                    <div style="display: flex; flex-direction: column; gap: 8px; overflow-y: auto; min-height: 0; padding-right: 4px;">
                                                        <For
                                                            each={move || firewall_quarantine_files.get()}
                                                            key={|file| file.path.clone()}
                                                            children={move |file| view! {
                                                                <div style="padding: 10px 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(248, 113, 113, 0.14);">
                                                                    <div style="font-size: 12px; font-weight: 700; margin-bottom: 4px;">{file.name.clone()}</div>
                                                                    <div style="font-size: 11px; color: var(--accent-orange); margin-bottom: 2px;">{format_unix_timestamp(file.modified_ts)}</div>
                                                                    <div style="font-size: 11px; color: var(--text-muted);">{format_file_size_bytes(file.size_bytes)}</div>
                                                                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; overflow-wrap: anywhere;">{compact_log_message(&file.path, 96)}</div>
                                                                </div>
                                                            }}
                                                        />
                                                        {move || if firewall_quarantine_files.get().is_empty() {
                                                            view! {
                                                                <div style="padding: 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.35); color: var(--text-muted); font-size: 12px;">
                                                                    "No quarantined files are currently present."
                                                                </div>
                                                            }.into_view()
                                                        } else {
                                                            view! {}.into_view()
                                                        }}
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="glass-card" style="flex: 1; min-width: 0; display: flex; flex-direction: column; min-height: 0;">
                                                <div class="section-header">
                                                    <h3 style="margin: 0; color: var(--t-primary)">"Owlyshield Activity"</h3>
                                                </div>
                                                <div style="padding: 14px; display: flex; flex-direction: column; gap: 10px; min-height: 0; overflow: hidden;">
                                                    <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.55;">
                                                        "Recent Owlyshield-specific backend events collected by the firewall UI."
                                                    </p>
                                                    <div style="display: flex; flex-direction: column; gap: 8px; overflow-y: auto; min-height: 0; padding-right: 4px;">
                                                        <For
                                                            each={move || owlyshield_activity_logs.get()}
                                                            key={|log| log.id.clone()}
                                                            children={move |log| view! {
                                                                <div style="padding: 10px 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(96, 165, 250, 0.14);">
                                                                    <div style="font-size: 11px; color: var(--accent-blue); margin-bottom: 4px;">{format!("Event {}", log.timestamp % 100000)}</div>
                                                                    <div style="font-size: 12px; line-height: 1.5;">{compact_log_message(&log.message, 110)}</div>
                                                                </div>
                                                            }}
                                                        />
                                                        {move || if owlyshield_activity_logs.get().is_empty() {
                                                            view! {
                                                                <div style="padding: 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.35); color: var(--text-muted); font-size: 12px;">
                                                                    "No Owlyshield-specific activity has been logged yet."
                                                                </div>
                                                            }.into_view()
                                                        } else {
                                                            view! {}.into_view()
                                                        }}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Exclusions => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card" style="width: 100%; display: flex; flex-direction: column; min-height: 0; overflow: hidden">
                                        <div class="section-header">
                                            <h3 style="color: var(--t-primary)">"Allowed Applications"</h3>
                                            <button class="btn-primary" style="background: var(--accent-red)" on:click=move |_| clear_all_decisions()> "REMOVE ALL" </button>
                                        </div>
                                        <div class="exclusions-list" style="min-height: 0; overflow-y: auto;">
                                            <For
                                                each={move || {
                                                    let mut rows = app_decisions
                                                        .get()
                                                        .into_iter()
                                                        .collect::<Vec<_>>();
                                                    rows.sort_by(|a, b| a.0.cmp(&b.0));
                                                    rows
                                                }}
                                                key={|(name, _)| name.clone()}
                                                children={move |(name, decision)| {
                                                    let n = name.clone();
                                                    view! {
                                                        <div class="exclusion-item" style="display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #333">
                                                            <span>{n.clone()} " (" {format!("{:?}", decision)} ")"</span>
                                                            <button on:click=move |_| remove_decision_action(n.clone())> "Remove" </button>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Logs => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card dash-col-main" style="flex: 2; overflow-y: auto">
                                        <div class="section-header">
                                            <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: var(--t-primary)">"Network Activity Log"</h3>
                                            <button
                                                class="btn-primary"
                                                style="padding: 5px 15px; font-size: 11px"
                                                on:click=move |_| {
                                                    set_logs.set(Vec::new());
                                                    set_selected_log.set(None);
                                                }
                                            >
                                                "Clear Screen"
                                            </button>
                                        </div>
                                        <div class="logs-viewport">
                                            <For
                                                each={move || logs.get().into_iter().rev().collect::<Vec<_>>()}
                                                key={|log_entry| log_entry.id.clone()}
                                                children={move |log_entry| {
                                                    let ts = log_entry.timestamp % 100000;
                                                    let msg = log_entry.message.clone();
                                                    let log_selected = log_entry.clone();
                                                    let source_badge = log_entry.source.clone().unwrap_or_else(|| "log".to_string());
                                                    let level_class = match log_entry.level {
                                                        LogLevel::Info => "lvl-info",
                                                        LogLevel::Success => "lvl-success",
                                                        LogLevel::Warning => "lvl-warning",
                                                        LogLevel::Error => "lvl-error",
                                                        _ => "lvl-info",
                                                    };
                                                    view! {
                                                        <div
                                                            class={format!("log-row {}", level_class)}
                                                            style="cursor: pointer"
                                                            on:click=move |_| set_selected_log.set(Some(log_selected.clone()))
                                                        >
                                                            <span class="log-time">"[" {ts} "]"</span>
                                                            <span
                                                                style="font-size: 10px; font-weight: 700; color: var(--accent-blue); min-width: 58px; text-transform: uppercase; margin-right: 8px;"
                                                            >
                                                                {source_badge}
                                                            </span>
                                                            <span class="log-msg">{msg}</span>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                    <div class="glass-card dash-col-side" style="flex: 1; overflow-y: auto">
                                        <h3 style="color: var(--t-primary)">"Log Details"</h3>
                                        {move || match selected_log.get() {
                                            Some(entry) => view! {
                                                <div style="font-size: 12px; display: flex; flex-direction: column; gap: 10px">
                                                    <div><strong>"Source: "</strong>{entry.source.clone().unwrap_or_else(|| "log".to_string())}</div>
                                                    <div><strong>"Timestamp: "</strong>{entry.timestamp}</div>
                                                    <div><strong>"Message: "</strong>{entry.message.clone()}</div>
                                                    {entry.details_json.clone().map(|json| view! {
                                                        <div>
                                                            <div style="margin-top: 8px"><strong>"JSON Details"</strong></div>
                                                            <div style="background: var(--bg-deep); border: 1px solid var(--border-main); padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; word-break: break-all; white-space: pre-wrap; max-height: 520px; overflow-y: auto">
                                                                {json}
                                                            </div>
                                                        </div>
                                                    }).unwrap_or_else(|| view! {
                                                        <div style="color: var(--text-muted)">"No structured JSON details for this entry."</div>
                                                    })}
                                                </div>
                                            }.into_view(),
                                            None => view! {
                                                <div style="color: var(--text-muted)">
                                                    "Select a log entry to inspect full packet or HTTP JSON details, including request and response bodies when available."
                                                </div>
                                            }.into_view(),
                                        }}
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::PacketReader => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card dash-col-main" style="flex: 2; overflow-y: auto">
                                        <div class="section-header">
                                            <h3 style="color: var(--t-primary)">"Live Packet Stream"</h3>
                                            <button class="btn-primary" style="padding: 5px 15px; font-size: 11px" on:click=move |_| set_raw_packets.set(Vec::new())> "Clear" </button>
                                        </div>
                                        <div class="logs-viewport">
                                            <For
                                                each={move || raw_packets.get().into_iter().rev().collect::<Vec<_>>()}
                                                key={|p_item| p_item.id.clone()}
                                                children={move |p_item| {
                                                    let p_selected = p_item.clone();
                                                    let p_summary = p_item.summary.clone();
                                                    let p_src = p_item.src_ip.clone();
                                                    let p_dst = p_item.dst_ip.clone();
                                                    let p_src_port = p_item.src_port;
                                                    let p_dst_port = p_item.dst_port;
                                                    view! {
                                                        <div class="log-row lvl-info" style="cursor: pointer" on:click=move |_| set_selected_packet.set(Some(p_selected.clone()))>
                                                            <span class="log-time">{format!("{}:{} -> {}:{}", p_src, p_src_port, p_dst, p_dst_port)}</span>
                                                            <span class="log-msg">{p_summary}</span>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                    <div class="glass-card dash-col-side" style="flex: 1">
                                        <h3 style="color: var(--t-primary)">"Packet Inspection"</h3>
                                        {move || match selected_packet.get() {
                                            Some(p) => {
                                                let (hex_lines, matched_markers) = build_packet_hex_lines(&p);
                                                let process_display = if !p.process_path.trim().is_empty() && p.process_path != "Unknown" {
                                                    p.process_path.clone()
                                                } else {
                                                    p.process_name.clone()
                                                };
                                                let matched_markers_view = if matched_markers.is_empty() {
                                                    view! {
                                                        <div style="color: var(--text-muted)">
                                                            "No rule or hostname token could be mapped back into the captured payload bytes."
                                                        </div>
                                                    }.into_view()
                                                } else {
                                                    matched_markers
                                                        .into_iter()
                                                        .map(|marker| {
                                                            view! {
                                                                <span class="process-tag" style="background: rgba(245, 158, 11, 0.12); color: #fbbf24;">
                                                                    {marker}
                                                                </span>
                                                            }
                                                        })
                                                        .collect_view()
                                                };
                                                let hex_view = hex_lines
                                                    .into_iter()
                                                    .map(|line| {
                                                        let offset = line.offset;
                                                        let hex_cells_view = line
                                                            .cells
                                                            .iter()
                                                            .map(|cell| {
                                                                let title = cell.label.clone().unwrap_or_default();
                                                                let cell_class = if cell.highlighted { "hex-byte hit" } else { "hex-byte" };
                                                                view! {
                                                                    <span class=cell_class title=title>{cell.hex.clone()}</span>
                                                                }
                                                            })
                                                            .collect_view();
                                                        let ascii_cells_view = line
                                                            .cells
                                                            .iter()
                                                            .map(|cell| {
                                                                let title = cell.label.clone().unwrap_or_default();
                                                                let cell_class = if cell.highlighted { "hex-ascii hit" } else { "hex-ascii" };
                                                                view! {
                                                                    <span class=cell_class title=title>{cell.ascii.clone()}</span>
                                                                }
                                                            })
                                                            .collect_view();
                                                        view! {
                                                            <div class="hex-line">
                                                                <span class="hex-offset">{format!("{:08X}", offset)}</span>
                                                                <div class="hex-byte-group">{hex_cells_view}</div>
                                                                <div class="hex-ascii-group">{ascii_cells_view}</div>
                                                            </div>
                                                        }
                                                    })
                                                    .collect_view();

                                                view! {
                                                    <div style="font-size: 12px; display: flex; flex-direction: column; gap: 10px">
                                                        <div><strong>"Time:"</strong> {p.timestamp}</div>
                                                        <div><strong>"Direction:"</strong> {format!("{:?} -> {:?}", p.src_ip, p.dst_ip)}</div>
                                                        <div><strong>"Process:"</strong> {process_display}</div>
                                                        <div><strong>"PID:"</strong> {p.process_id}</div>
                                                        <div><strong>"Action:"</strong> {p.action.clone()}</div>
                                                        <div><strong>"Rule:"</strong> {if p.rule.trim().is_empty() { "None".to_string() } else { p.rule.clone() }}</div>
                                                        {p.hostname.clone().map(|host| view! { <div><strong>"Hostname:"</strong> {host}</div> })}
                                                        <div style="margin-top: 10px"><strong>"Matched Payload Markers:"</strong></div>
                                                        <div class="process-tag-cloud">{matched_markers_view}</div>
                                                        <div style="margin-top: 10px"><strong>"Payload Hex / ASCII Map:"</strong></div>
                                                        <div class="hex-view-shell">{hex_view}</div>
                                                    </div>
                                                }.into_view()
                                            }
                                            None => view! { <div style="color: var(--text-muted)">"Select a packet to inspect"</div> }.into_view(),
                                        }}
                                    </div>
                                </div>
                            }.into_view(),
                            /*
                            AppView::PacketReader => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card dash-col-main" style="flex: 2; overflow-y: auto">
                                        <div class="section-header">
                                            <h3>"Live Packet Stream"</h3>
                                            <button class="btn-primary" style="padding: 5px 15px; font-size: 11px" on:click=move |_| set_raw_packets.set(Vec::new())> "Clear" </button>
                                        </div>
                                        <div class="logs-viewport">
                                            <For
                                                each={move || raw_packets.get().into_iter().rev().collect::<Vec<_>>()}
                                                key={|p_item| p_item.id.clone()}
                                                children={move |p_item| {
                                                    let p_selected = p_item.clone();
                                                    let p_summary = p_item.summary.clone();
                                                    let p_src = p_item.src_ip.clone();
                                                    let p_dst = p_item.dst_ip.clone();
                                                    let p_src_port = p_item.src_port;
                                                    let p_dst_port = p_item.dst_port;
                                                    view! {
                                                        <div class="log-row lvl-info" style="cursor: pointer" on:click=move |_| set_selected_packet.set(Some(p_selected.clone()))>
                                                            <span class="log-time">{format!("{}:{} -> {}:{}", p_src, p_src_port, p_dst, p_dst_port)}</span>
                                                            <span class="log-msg">{p_summary}</span>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                    <div class="glass-card dash-col-side" style="flex: 1">
                                        <h3>"Packet Inspection"</h3>
                                        {move || match selected_packet.get() {
                                            Some(p) => {
                                                let (hex_lines, matched_markers) = build_packet_hex_lines(&p);
                                                let process_display = if !p.process_path.trim().is_empty() && p.process_path != "Unknown" {
                                                    p.process_path.clone()
                                                } else {
                                                    p.process_name.clone()
                                                };
                                                view! {
                                                    <div style="font-size: 12px; display: flex; flex-direction: column; gap: 10px">
                                                        <div><strong>"Time:"</strong> {p.timestamp}</div>
                                                        <div><strong>"Direction:"</strong> {format!("{:?} -> {:?}", p.src_ip, p.dst_ip)}</div>
                                                        <div><strong>"Process:"</strong> {process_display}</div>
                                                        <div><strong>"PID:"</strong> {p.process_id}</div>
                                                        <div><strong>"Action:"</strong> {p.action.clone()}</div>
                                                        <div><strong>"Rule:"</strong> {if p.rule.trim().is_empty() { "None".to_string() } else { p.rule.clone() }}</div>
                                                        {p.hostname.clone().map(|host| view! { <div><strong>"Hostname:"</strong> {host}</div> })}
                                                        <div style="margin-top: 10px"><strong>"Matched Payload Markers:"</strong></div>
                                                        {if matched_markers.is_empty() {
                                                            view! { <div style="color: var(--text-muted)">"No rule/hostname token could be mapped back into the captured payload bytes."</div> }
                                                        } else {
                                                            view! {
                                                                <div class="process-tag-cloud">
                                                                    <For
                                                                        each={move || matched_markers.clone()}
                                                                        key={|marker| marker.clone()}
                                                                        children={move |marker| view! { <span class="process-tag" style="background: rgba(245, 158, 11, 0.12); color: #fbbf24;">{marker}</span> }}
                                                                    />
                                                                </div>
                                                            }
                                                        }}
                                                        <div style="margin-top: 10px"><strong>"Payload Hex / ASCII Map:"</strong></div>
                                                        <div class="hex-view-shell">
                                                            <For
                                                                each={move || hex_lines.clone()}
                                                                key={|line| line.offset}
                                                                children={move |line| {
                                                                    let offset = line.offset;
                                                                    let hex_cells = line.cells.clone();
                                                                    let ascii_cells = line.cells.clone();
                                                                    view! {
                                                                    <div class="hex-line">
                                                                        <span class="hex-offset">{format!("{:08X}", offset)}</span>
                                                                        <div class="hex-byte-group">
                                                                            <For
                                                                                each={move || hex_cells.clone()}
                                                                                key={|cell| cell.absolute_index}
                                                                                children={move |cell| {
                                                                                    let title = cell.label.clone().unwrap_or_default();
                                                                                    view! {
                                                                                        <span
                                                                                            class={if cell.highlighted { "hex-byte hit" } else { "hex-byte" }}
                                                                                            title=title
                                                                                        >
                                                                                            {cell.hex.clone()}
                                                                                        </span>
                                                                                    }
                                                                                }}
                                                                            />
                                                                        </div>
                                                                        <div class="hex-ascii-group">
                                                                            <For
                                                                                each={move || ascii_cells.clone()}
                                                                                key={|cell| cell.absolute_index}
                                                                                children={move |cell| {
                                                                                    let title = cell.label.clone().unwrap_or_default();
                                                                                    view! {
                                                                                        <span
                                                                                            class={if cell.highlighted { "hex-ascii hit" } else { "hex-ascii" }}
                                                                                            title=title
                                                                                        >
                                                                                            {cell.ascii.clone()}
                                                                                        </span>
                                                                                    }
                                                                                }}
                                                                            />
                                                                        </div>
                                                                    </div>
                                                                }}
                                                            />
                                                        </div>
                                                    </div>
                                                }.into_view()
                                            }
                                            None => view! { <div style="color: var(--text-muted)">"Select a packet to inspect"</div> }.into_view(),
                                        }}
                                    </div>
                                </div>
                            }.into_view(),

                            */
                            AppView::HttpInspector => view! {
                                <div class="dashboard-grid" style="height: calc(100vh - 120px)">
                                    <div class="glass-card dash-col-main" style="flex: 2; overflow-y: auto">
                                        <div class="section-header">
                                            <h3 style="color: var(--t-primary)">"HTTP Traffic (TLS Proxy)"</h3>
                                            <button class="btn-primary" style="padding: 5px 15px; font-size: 11px"
                                                on:click=move |_| { set_proxy_events.set(Vec::new()); set_selected_proxy_event.set(None); }>
                                                "Clear"
                                            </button>
                                        </div>
                                        <div class="logs-viewport">
                                            <For
                                                each={move || proxy_events.get().into_iter().rev().collect::<Vec<_>>()}
                                                key={|e| e.id.clone()}
                                                children={move |ev| {
                                                    let ev_sel = ev.clone();
                                                    let badge_color = if ev.status < 300 { "#22c55e" } else if ev.status < 400 { "#f59e0b" } else { "#ef4444" };
                                                    let method_color = match ev.method.as_str() { "POST" | "PUT" | "PATCH" => "#f59e0b", "DELETE" => "#ef4444", _ => "#60a5fa" };
                                                    view! {
                                                        <div class="log-row lvl-info" style="cursor: pointer"
                                                            on:click=move |_| set_selected_proxy_event.set(Some(ev_sel.clone()))>
                                                            <span class="log-time" style={format!("color: {}; font-weight: 700; min-width: 50px", method_color)}>{ev.method.clone()}</span>
                                                            <span class="log-msg" style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{ev.full_url.clone()}</span>
                                                            <span style={format!("color: {}; font-size: 11px; margin-left: 8px", badge_color)}>{ev.status}</span>
                                                        </div>
                                                    }
                                                }}
                                            />
                                        </div>
                                    </div>
                                    <div class="glass-card dash-col-side" style="flex: 1; overflow-y: auto">
                                        <h3 style="color: var(--t-primary)">"Request Detail"</h3>
                                        {move || match selected_proxy_event.get() {
                                            None => view! { <div style="color: var(--text-muted)">"Select a request to inspect"</div> }.into_view(),
                                            Some(ev) => view! {
                                                <div style="font-size: 12px; display: flex; flex-direction: column; gap: 8px">
                                                    <div><strong>"URL: "</strong>{ev.full_url.clone()}</div>
                                                    <div><strong>"Status: "</strong>{ev.status}</div>
                                                    {ev.content_type.clone().map(|ct| view! { <div><strong>"Content-Type: "</strong>{ct}</div> })}
                                                    {ev.user_agent.clone().map(|ua| view! { <div><strong>"User-Agent: "</strong>{ua}</div> })}
                                                    {ev.referer.clone().map(|r| view! { <div><strong>"Referer: "</strong>{r}</div> })}
                                                    {ev.response_content_type.clone().map(|ct| view! { <div><strong>"Response Content-Type: "</strong>{ct}</div> })}
                                                    {ev.response_content_length.clone().map(|cl| view! { <div><strong>"Response Content-Length: "</strong>{cl}</div> })}
                                                    {ev.request_body.clone().map(|body| view! {
                                                        <div>
                                                            <div style="margin-top: 8px">
                                                                <strong>"Request Body"</strong>
                                                                {if ev.request_body_truncated { " (truncated at 64 KB)" } else { "" }}
                                                                ":"
                                                            </div>
                                                            <div style="background: var(--bg-deep); border: 1px solid var(--border-main); padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; word-break: break-all; white-space: pre-wrap; max-height: 200px; overflow-y: auto">
                                                                {body}
                                                            </div>
                                                        </div>
                                                    })}
                                                    {ev.response_body.clone().map(|body| view! {
                                                        <div>
                                                            <div style="margin-top: 8px">
                                                                <strong>"Response Body"</strong>
                                                                {if ev.response_body_truncated { " (truncated at 64 KB)" } else { "" }}
                                                                ":"
                                                            </div>
                                                            <div style="background: var(--bg-deep); border: 1px solid var(--border-main); padding: 10px; border-radius: 4px; font-family: monospace; font-size: 11px; word-break: break-all; white-space: pre-wrap; max-height: 200px; overflow-y: auto">
                                                                {body}
                                                            </div>
                                                        </div>
                                                    })}
                                                </div>
                                            }.into_view(),
                                        }}
                                    </div>
                                </div>
                            }.into_view(),

                            AppView::Settings => view! {
                                <div style="height: calc(100vh - 120px); display: flex; flex-direction: column; gap: 0">
                                    // ── Tab Bar ──────────────────────────────────────────────
                                    <div style="display: flex; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 12px">
                                        <button
                                            class={move || if settings_sub_tab.get() == SettingsSubTab::General { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_settings_sub_tab.set(SettingsSubTab::General); }>
                                            "General"
                                        </button>
                                        <button
                                            class={move || if settings_sub_tab.get() == SettingsSubTab::About { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_settings_sub_tab.set(SettingsSubTab::About); fetch_readme(); }>
                                            "About"
                                        </button>
                                        <button
                                            class={move || if settings_sub_tab.get() == SettingsSubTab::Help { "nav-item active" } else { "nav-item" }}
                                            style="padding: 8px 18px; border-radius: 4px 4px 0 0"
                                            on:click=move |_| { set_settings_sub_tab.set(SettingsSubTab::Help); fetch_readme(); }>
                                            "Help"
                                        </button>
                                    </div>

                                    <div style="flex: 1; overflow-y: auto">
                                        {move || match settings_sub_tab.get() {
                                            SettingsSubTab::General => view! {
                                                <div class="glass-card" style="width: 100%; min-height: 0">
                                                    <h3 style="color: var(--t-primary)">"System Settings"</h3>
                                                    <p style="margin: 0 0 18px 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                        "The normal GUI stays active. Raw JSON is available below, and saving from this page now preserves the extra settings fields instead of dropping them."
                                                    </p>
                                                    <div class="input-group" style="padding: 14px; border: 1px solid rgba(96, 165, 250, 0.18); border-radius: 10px; background: rgba(96, 165, 250, 0.05)">
                                                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || {
                                                                    let cfg = settings.get().tls_proxy;
                                                                    cfg.mode == TlsInspectionMode::TlsProxy && cfg.auto_start
                                                                }
                                                                on:change=move |ev| {
                                                                    let enabled = event_target_checked(&ev);
                                                                    set_settings.update(|s| {
                                                                        if enabled {
                                                                            s.tls_proxy.mode = TlsInspectionMode::TlsProxy;
                                                                            s.tls_proxy.auto_start = true;
                                                                        } else {
                                                                            s.tls_proxy.mode = TlsInspectionMode::MetadataOnly;
                                                                            s.tls_proxy.auto_start = false;
                                                                        }
                                                                    });
                                                                }
                                                            />
                                                            "Enable embedded MITM/TLS proxy interception"
                                                        </label>
                                                        <p style="margin: 0 0 10px 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "Turning this off keeps the firewall running but clears the Windows proxy and stops HTTPS interception."
                                                        </p>
                                                        <div class="input-group" style="margin-bottom: 10px">
                                                            <label>"TLS visibility mode"</label>
                                                            <select
                                                                prop:value=move || match settings.get().tls_proxy.mode {
                                                                    TlsInspectionMode::MetadataOnly => "metadata_only".to_string(),
                                                                    TlsInspectionMode::TlsProxy => "tls_proxy".to_string(),
                                                                }
                                                                on:change=move |ev| {
                                                                    let mode = event_target_value(&ev);
                                                                    set_settings.update(|s| {
                                                                        if mode == "tls_proxy" {
                                                                            s.tls_proxy.mode = TlsInspectionMode::TlsProxy;
                                                                            if !s.tls_proxy.auto_start {
                                                                                s.tls_proxy.auto_start = true;
                                                                            }
                                                                        } else {
                                                                            s.tls_proxy.mode = TlsInspectionMode::MetadataOnly;
                                                                            s.tls_proxy.auto_start = false;
                                                                        }
                                                                    });
                                                                }
                                                            >
                                                                <option value="metadata_only">"Metadata only"</option>
                                                                <option value="tls_proxy">"Embedded MITM proxy"</option>
                                                            </select>
                                                        </div>
                                                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 10px;">
                                                            <div class="input-group" style="margin: 0">
                                                                <label>"MITM listen host"</label>
                                                                <input
                                                                    type="text"
                                                                    prop:value=move || settings.get().tls_proxy.listen_host.clone()
                                                                    on:input=move |ev| {
                                                                        set_settings.update(|s| {
                                                                            s.tls_proxy.listen_host = event_target_value(&ev);
                                                                        });
                                                                    }
                                                                />
                                                            </div>
                                                            <div class="input-group" style="margin: 0">
                                                                <label>"MITM listen port"</label>
                                                                <input
                                                                    type="number"
                                                                    min="1"
                                                                    max="65535"
                                                                    prop:value=move || settings.get().tls_proxy.listen_port.to_string()
                                                                    on:input=move |ev| {
                                                                        if let Ok(value) = event_target_value(&ev).parse::<u16>() {
                                                                            set_settings.update(|s| s.tls_proxy.listen_port = value.max(1));
                                                                        }
                                                                    }
                                                                />
                                                            </div>
                                                        </div>
                                                        <div class="input-group">
                                                            <label style="display: flex; align-items: center; gap: 10px">
                                                                <input
                                                                    type="checkbox"
                                                                    prop:checked=move || settings.get().tls_proxy.block_quic_udp_443
                                                                    on:change=move |ev| {
                                                                        let enabled = event_target_checked(&ev);
                                                                        set_settings.update(|s| s.tls_proxy.block_quic_udp_443 = enabled);
                                                                    }
                                                                    disabled=move || settings.get().tls_proxy.mode != TlsInspectionMode::TlsProxy
                                                                />
                                                                "Block QUIC/UDP 443 while MITM proxy mode is active"
                                                            </label>
                                                        </div>
                                                        <div class="input-group" style="padding: 14px; border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 10px; background: rgba(245, 158, 11, 0.08)">
                                                            <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px">
                                                                <input
                                                                    type="checkbox"
                                                                    prop:checked=move || settings.get().tls_proxy.cert_install_consent
                                                                    on:change=move |ev| {
                                                                        let enabled = event_target_checked(&ev);
                                                                        set_settings.update(|s| s.tls_proxy.cert_install_consent = enabled);
                                                                    }
                                                                    disabled=move || settings.get().tls_proxy.mode != TlsInspectionMode::TlsProxy
                                                                />
                                                                <span style="font-weight: 600">"I consent to automatic certificate installation for MITM interception"</span>
                                                            </label>
                                                            <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                                <strong style="color: var(--accent-orange)">"Security Notice: "</strong>
                                                                "Enabling this allows HydraDragon to automatically install its root certificate into your system's trust store (Windows Root and Firefox). This enables HTTPS interception but also means the firewall can decrypt your encrypted traffic. Only enable if you understand and accept this. Without consent, browsers will show certificate warnings until you manually install the certificate or disable MITM mode."
                                                            </p>
                                                        </div>
                                                        <div class="input-group" style="margin-top: 10px">
                                                            <label>"MITM bypass hosts/domains"</label>
                                                            <textarea
                                                                style="min-height: 110px; width: 100%; box-sizing: border-box; padding: 10px; resize: vertical"
                                                                prop:value=move || settings.get().tls_proxy.bypass_hosts.join("\n")
                                                                on:input=move |ev| {
                                                                    let value = event_target_value(&ev);
                                                                    let entries = value
                                                                        .split(['\n', '\r', ',', ';'])
                                                                        .filter_map(|item| {
                                                                            let trimmed = item.trim();
                                                                            if trimmed.is_empty() {
                                                                                None
                                                                            } else {
                                                                                Some(trimmed.to_string())
                                                                            }
                                                                        })
                                                                        .collect::<Vec<_>>();
                                                                    set_settings.update(|s| s.tls_proxy.bypass_hosts = entries);
                                                                }
                                                            />
                                                            <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                                "One host, domain, or pattern per line. Matching targets bypass the embedded MITM proxy through Windows proxy override rules."
                                                            </p>
                                                        </div>
                                                        <div style="margin-top: 12px; padding: 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.55); border: 1px solid rgba(148, 163, 184, 0.18);">
                                                            <div style="font-size: 12px; font-weight: 700; margin-bottom: 8px;">"MITM Trust Status"</div>
                                                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; font-size: 12px;">
                                                                <div>
                                                                    <strong>"Mode: "</strong>
                                                                    {move || if mitm_enabled.get() { "Embedded MITM active" } else { "MITM disabled / metadata only" }}
                                                                </div>
                                                                <div>
                                                                    <strong>"Windows trust: "</strong>
                                                                    {move || if windows_root_trust_ready.get() { "Ready" } else { "Not ready" }}
                                                                </div>
                                                                <div>
                                                                    <strong>"Firefox trust: "</strong>
                                                                    {move || if firefox_policy_ready.get() { "Ready" } else { "Not ready" }}
                                                                </div>
                                                                <div>
                                                                    <strong>"Bypass entries: "</strong>
                                                                    {move || mitm_bypass_count.get().to_string()}
                                                                </div>
                                                            </div>
                                                            <p style="margin: 10px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                                {move || {
                                                                    let cfg = settings.get().tls_proxy;
                                                                    if cfg.mode == TlsInspectionMode::TlsProxy && cfg.auto_start {
                                                                        format!(
                                                                            "Current MITM listener: {}:{} . Firefox may need a restart after trust changes. Website alerts can now be trusted without MITM, which adds that host to this bypass list.",
                                                                            cfg.listen_host, cfg.listen_port
                                                                        )
                                                                    } else {
                                                                        "MITM proxy is currently disabled; packet and metadata logging remain available.".to_string()
                                                                    }
                                                                }}
                                                            </p>
                                                            <p style="margin: 8px 0 0 0; color: var(--accent-orange); font-size: 12px; line-height: 1.5">
                                                                "Even when interception is hidden, some browsers and other antivirus/security products can still flag it as a MITM-style attack if trust is not accepted."
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <div class="input-group" style="margin-top: 18px">
                                                        <label>"Kernel blocked paths"</label>
                                                        <textarea
                                                            style="min-height: 110px; width: 100%; box-sizing: border-box; padding: 10px; resize: vertical"
                                                            prop:value=move || settings.get().kernel_block_paths.join("\n")
                                                            on:input=move |ev| {
                                                                let value = event_target_value(&ev);
                                                                let entries = value
                                                                    .split(['\n', '\r', ';'])
                                                                    .filter_map(|item| {
                                                                        let trimmed = item.trim();
                                                                        if trimmed.is_empty() {
                                                                            None
                                                                        } else {
                                                                            Some(trimmed.to_string())
                                                                        }
                                                                    })
                                                                    .collect::<Vec<_>>();
                                                                set_settings.update(|s| s.kernel_block_paths = entries);
                                                            }
                                                        />
                                                        <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "These paths are sent to the kernel deny list. One full path per line."
                                                        </p>
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Custom Filter Path"</label>
                                                        <input type="text" prop:value=move || settings.get().website_path on:input=move |ev| update_path(event_target_value(&ev)) />
                                                    </div>
                                                    <div style="margin: 12px 0 18px 0; padding: 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(148, 163, 184, 0.12); display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; font-size: 12px;">
                                                        <div><strong>"Rules loaded: "</strong>{move || settings.get().rules.len().to_string()}</div>
                                                        <div><strong>"Trusted entries: "</strong>{move || settings.get().app_decisions.len().to_string()}</div>
                                                        <div><strong>"Kernel blocks: "</strong>{move || settings.get().kernel_block_paths.len().to_string()}</div>
                                                        <div><strong>"Metadata keys: "</strong>{move || settings.get().metadata.len().to_string()}</div>
                                                    </div>
                                                    <div style="margin: 0 0 18px 0; padding: 12px; border-radius: 8px; background: rgba(15, 23, 42, 0.32); border: 1px solid rgba(148, 163, 184, 0.12);">
                                                        <div style="font-size: 12px; font-weight: 700; margin-bottom: 6px;">"Managed Settings Coverage"</div>
                                                        <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "Protection rules are managed in the Protection Rules tab, trusted applications are managed in Exclusions, and the raw JSON editor below still includes every available setting."
                                                        </p>
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Metadata entries"</label>
                                                        <textarea
                                                            style="min-height: 110px; width: 100%; box-sizing: border-box; padding: 10px; resize: vertical; font-family: Consolas, monospace; font-size: 12px"
                                                            prop:value=move || metadata_to_editor_string(&settings.get().metadata)
                                                            on:input=move |ev| {
                                                                let value = event_target_value(&ev);
                                                                set_settings.update(|s| {
                                                                    s.metadata = parse_metadata_editor_string(&value);
                                                                });
                                                            }
                                                        />
                                                        <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "Format: one `key=value` entry per line. This updates the normal metadata map without needing raw JSON."
                                                        </p>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().show_blocked_only
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.show_blocked_only = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Only show blocked firewall events"
                                                        </label>
                                                        <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "Skips allowed packet, proxy, and HTTP activity events before they enter the GUI lists. Blocked and error events stay visible."
                                                        </p>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().save_all_logs
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.save_all_logs = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Save all logs to disk"
                                                        </label>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().prune_old_logs
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.prune_old_logs = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Remove old logs from the GUI when the list gets too large"
                                                        </label>
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"Maximum visible logs"</label>
                                                        <input
                                                            type="number"
                                                            min="1"
                                                            prop:value=move || settings.get().max_visible_logs.to_string()
                                                            on:input=move |ev| {
                                                                if let Ok(value) = event_target_value(&ev).parse::<usize>() {
                                                                    set_settings.update(|s| s.max_visible_logs = value.max(1));
                                                                }
                                                            }
                                                        />
                                                    </div>
                                                    <div style="margin: 14px 0 12px 0; padding: 12px; border-radius: 8px; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.16);">
                                                        <div style="font-size: 12px; font-weight: 700; margin-bottom: 6px;">"HTTP Inspector History"</div>
                                                        <p style="margin: 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "These options control only the HTTP Inspector request history. They do not change the normal log list limit above."
                                                        </p>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().prune_http_history
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.prune_http_history = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Prune HTTP inspector history in the GUI"
                                                        </label>
                                                    </div>
                                                    <div class="input-group">
                                                        <label>"HTTP inspector history limit"</label>
                                                        <input
                                                            type="number"
                                                            min="1"
                                                            prop:value=move || settings.get().max_visible_http_events.to_string()
                                                            on:input=move |ev| {
                                                                if let Ok(value) = event_target_value(&ev).parse::<usize>() {
                                                                    set_settings.update(|s| s.max_visible_http_events = value.max(1));
                                                                }
                                                            }
                                                        />
                                                        <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "Turn pruning off if you want the inspector to keep growing during the current session."
                                                        </p>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().late_blocking_mode
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.late_blocking_mode = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Late blocking mode"
                                                        </label>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().headless_mode
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.headless_mode = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Headless mode (hide main window on start)"
                                                        </label>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().log_mode
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.log_mode = event_target_checked(&ev));
                                                                }
                                                            />
                                                            "Log mode (log all packets, including forwarded)"
                                                        </label>
                                                    </div>
                                                    <div class="input-group">
                                                        <label style="display: flex; align-items: center; gap: 10px">
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=move || settings.get().no_alert_mode
                                                                on:change=move |ev| {
                                                                    set_settings.update(|s| s.no_alert_mode = event_target_checked(&ev));
                                                                }
                                                            />
                                                            <span>
                                                                "No-alert mode "
                                                                <span style="color: var(--accent-orange); font-size: 11px; font-weight: 700">"[not recommended — skips firewall decision prompts for testing]"</span>
                                                            </span>
                                                        </label>
                                                    </div>
                                                    <p style="margin: 8px 0 18px 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                        "Saved logs stay on disk. GUI pruning only controls how many entries remain visible in the on-screen log list."
                                                    </p>
                                                    <button class="btn-primary" on:click=move |_| save_settings_action()> "Save Changes" </button>
                                                    {move || if saved_status.get() { view! { <span style="margin-left: 10px; color: var(--accent-green)">"Saved!"</span> }.into_view() } else { view! {}.into_view() }}
                                                    <div class="input-group" style="margin-top: 20px">
                                                        <label>"Raw Settings JSON"</label>
                                                        <textarea
                                                            style="min-height: 360px; width: 100%; box-sizing: border-box; padding: 10px; resize: vertical; font-family: Consolas, monospace; font-size: 12px"
                                                            prop:value=move || settings_raw.get()
                                                            on:input=move |ev| {
                                                                set_settings_raw.set(event_target_value(&ev));
                                                                set_settings_raw_status.set(String::new());
                                                            }
                                                        />
                                                        <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                            "The GUI remains the normal path. This raw editor is for direct JSON edits when you need full control."
                                                        </p>
                                                        <div style="display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap;">
                                                            <button class="btn-secondary" on:click=move |_| set_settings_raw.set(serde_json::to_string_pretty(&settings.get()).unwrap_or_default())>
                                                                "Refresh Raw From GUI"
                                                            </button>
                                                            <button class="btn-primary" on:click=move |_| apply_raw_settings_action()>
                                                                "Apply Raw JSON"
                                                            </button>
                                                        </div>
                                                        {move || if !settings_raw_status.get().is_empty() {
                                                            view! {
                                                                <p style="margin: 8px 0 0 0; color: var(--text-muted); font-size: 12px; line-height: 1.5">
                                                                    {settings_raw_status.get()}
                                                                </p>
                                                            }.into_view()
                                                        } else {
                                                            view! {}.into_view()
                                                        }}
                                                    </div>
                                                </div>
                                            }.into_view(),
                                            SettingsSubTab::About => view! {
                                                <div class="glass-card" style="padding: 24px">
                                                    <h3 style="color: var(--t-primary)">"About HydraDragon Firewall"</h3>
                                                    <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 15px">
                                                        <div style="display: flex; align-items: center; gap: 12px">
                                                            <div style="width: 48px; height: 48px; background: var(--accent-blue); border-radius: 12px; display: flex; align-items: center; justify-content: center">
                                                                <span style="font-size: 24px">"🛡️"</span>
                                                            </div>
                                                            <div>
                                                                <div style="font-size: 18px; font-weight: 700">"HydraDragon Firewall"</div>
                                                                <div style="font-size: 12px; color: var(--text-muted)">"Advanced Network & Application Security"</div>
                                                            </div>
                                                        </div>

                                                        <p style="font-size: 14px; line-height: 1.6">
                                                            "HydraDragon is a modern, high-performance firewall and endpoint protection system designed for Windows. It combines kernel-level packet filtering with behavioral analysis to provide comprehensive security."
                                                        </p>

                                                        <div style="padding: 15px; border-radius: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05)">
                                                            <div style="font-size: 13px; font-weight: 700; margin-bottom: 8px">"Project Links"</div>
                                                            <div style="display: flex; flex-direction: column; gap: 6px">
                                                                <a href="https://github.com/HydraDragonAntivirus/HydraDragonAntivirus" target="_blank" style="color: var(--accent-blue); text-decoration: none; font-size: 13px">
                                                                    "GitHub Repository: HydraDragonAntivirus/HydraDragonAntivirus"
                                                                </a>
                                                                <a href="https://hydradragon.org" target="_blank" style="color: var(--accent-blue); text-decoration: none; font-size: 13px">
                                                                    "Official Website"
                                                                </a>
                                                            </div>
                                                        </div>

                                                        <div style="margin-top: 10px">
                                                            <div style="font-size: 13px; font-weight: 700; margin-bottom: 10px">"README.md Content"</div>
                                                            <textarea readonly style="width: 100%; min-height: 400px; padding: 15px; border-radius: 10px; background: var(--bg-deep); border: 1px solid var(--border-main); color: var(--t-primary); font-family: 'Consolas', monospace; font-size: 12px; resize: vertical">
                                                                {readme_content.get()}
                                                            </textarea>
                                                        </div>
                                                    </div>
                                                </div>
                                            }.into_view(),
                                            SettingsSubTab::Help => view! {
                                                <div class="glass-card" style="padding: 24px">
                                                    <h3 style="color: var(--t-primary)">"Help & Documentation"</h3>
                                                    <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 20px">
                                                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px">
                                                            <div style="padding: 15px; border-radius: 10px; background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.1)">
                                                                <div style="font-weight: 700; margin-bottom: 5px">"Quick Start"</div>
                                                                <div style="font-size: 12px; color: var(--text-muted)">"Learn how to configure basic rules and enable TLS proxy."</div>
                                                            </div>
                                                            <div style="padding: 15px; border-radius: 10px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.1)">
                                                                <div style="font-weight: 700; margin-bottom: 5px">"Troubleshooting"</div>
                                                                <div style="font-size: 12px; color: var(--text-muted)">"Common issues and how to resolve them."</div>
                                                            </div>
                                                        </div>

                                                        <div>
                                                            <div style="font-size: 13px; font-weight: 700; margin-bottom: 10px">"Project Documentation"</div>
                                                            <textarea readonly style="width: 100%; min-height: 500px; padding: 15px; border-radius: 10px; background: var(--bg-deep); border: 1px solid var(--border-main); color: var(--t-primary); font-family: 'Consolas', monospace; font-size: 12px; resize: vertical">
                                                                {readme_content.get()}
                                                            </textarea>
                                                        </div>
                                                    </div>
                                                </div>
                                            }.into_view(),
                                        }}
                                    </div>
                                </div>
                            }.into_view(),
                        }}
                    </main>
                </div>
            }.into_view()
        }}
    }
}

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}

#[component]
fn AlertWindow(
    pending_app: ReadSignal<Option<PendingApp>>,
    set_pending_app: WriteSignal<Option<PendingApp>>,
) -> impl IntoView {
    // Poll the backend every second to keep queue_position/queue_total accurate.
    create_effect(move |_| {
        set_interval(
            move || {
                spawn_local(async move {
                    let res = invoke("get_active_alert", JsValue::NULL).await;
                    if let Ok(app_opt) = serde_wasm_bindgen::from_value::<Option<PendingApp>>(res) {
                        if app_opt.is_none() {
                            let _ = invoke("close_window", JsValue::NULL).await;
                        }
                        set_pending_app.set(app_opt);
                    }
                });
            },
            Duration::from_millis(1000),
        );
    });

    let next_alert_action = move || {
        spawn_local(async move {
            let _ = invoke("next_alert", JsValue::NULL).await;
        });
    };

    let prev_alert_action = move || {
        spawn_local(async move {
            let _ = invoke("previous_alert", JsValue::NULL).await;
        });
    };

    let resolve_decision_internal = move |name: String, path: String, decision: String| {
        spawn_local(async move {
            // Prioritize path for "Always Allow" (TRUST)
            let identifier = if (decision == "allow_always" || decision == "allow_always_no_mitm")
                && !path.trim().is_empty()
                && !path.eq_ignore_ascii_case("unknown")
            {
                path
            } else {
                name
            };

            let args = serde_wasm_bindgen::to_value(&ResolveArgs {
                name: identifier,
                decision,
            })
            .unwrap();
            let _ = invoke("resolve_app_decision", args).await;

            // Close via backend command for reliability
            let _ = invoke("close_window", JsValue::NULL).await;
        });
    };

    view! {
        <div class="alert-window-root" style=move || if pending_app.get().is_some() { "" } else { "display: none;" }>
             <div class="alert-window-header">
                 <div class="alert-window-brand"> <div class="dragon-icon"></div> "HYDRADRAGON" </div>
                 <div class="alert-window-meta">
                     {move || pending_app.get().and_then(|app| {
                         let n = next_alert_action.clone();
                         let p = prev_alert_action.clone();
                         Some(view! {
                             <div style="display: flex; align-items: center; gap: 8px">
                                 <div class="alert-nav-controls" style="display: flex; gap: 4px; margin-right: 4px">
                                     <button class="nav-arrow" title="Previous Alert" on:click=move |_| p() style="background: rgba(255,255,255,0.1); border: none; color: #fff; cursor: pointer; padding: 2px 6px; border-radius: 4px; font-size: 10px"> "❮" </button>
                                     <button class="nav-arrow" title="Next Alert" on:click=move |_| n() style="background: rgba(255,255,255,0.1); border: none; color: #fff; cursor: pointer; padding: 2px 6px; border-radius: 4px; font-size: 10px"> "❯" </button>
                                 </div>
                                 <div class="alert-window-count">
                                     {format!("{}/{}", app.queue_position.max(1), app.queue_total)}
                                 </div>
                             </div>
                         })
                     })}
                     <div class="alert-window-tag">
                         {move || if pending_app.get().is_some() { "PENDING DECISION" } else { "NEW EVENT ALERT" }}
                     </div>
                 </div>
             </div>
             <div class="alert-window-body">
                 {move || pending_app.get().map(|app| {
                     let n1 = app.name.clone(); let n2 = app.name.clone(); let n5 = app.name.clone();
                     let res1 = resolve_decision_internal.clone(); let res2 = resolve_decision_internal.clone(); let res5 = resolve_decision_internal.clone();
                     let is_registry_alert = app.alert_kind.as_deref() == Some("registry");
                     let is_owlyshield_alert = app.alert_source.as_deref() == Some("owlyshield");
                     let is_browser_mitm_prompt = app.alert_source.as_deref() == Some("browser_mitm")
                         || app.alert_kind.as_deref() == Some("browser_mitm_prompt");
                     let is_website_alert = app.alert_source.as_deref() == Some("website")
                         || app.alert_kind.as_deref() == Some("malicious_website")
                         || app.decision_key.as_deref().map(|value| value.starts_with("website:")).unwrap_or(false);
                     let is_behavior_alert = is_owlyshield_alert && !is_registry_alert;
                     let always_decision = if is_website_alert {
                         "allow_always_no_mitm".to_string()
                     } else {
                         "allow_always".to_string()
                     };
                     let always_label = if is_website_alert {
                         "TRUST (NO MITM)"
                     } else {
                         "TRUST"
                     };
                     let title = if is_browser_mitm_prompt {
                         app.full_url
                             .clone()
                             .or_else(|| app.target.clone())
                             .or_else(|| app.hostname.clone())
                             .map(|value| format!("{} reported an HTTPS interception warning for {}", app.name, value))
                             .unwrap_or_else(|| format!("{} reported an HTTPS interception warning", app.name))
                     } else if is_registry_alert {
                         "Registry protection triggered".to_string()
                     } else if is_website_alert {
                         app.full_url
                             .clone()
                             .or_else(|| app.target.clone())
                             .or_else(|| app.hostname.clone())
                             .map(|value| format!("Malicious website detected: {}", value))
                             .unwrap_or_else(|| format!("Malicious website detected in {}", app.name))
                     } else if is_behavior_alert {
                         format!("Behavioral threat detected in {}", app.name)
                     } else if let Some(ref h) = app.hostname {
                         format!("{} wants connection", h)
                     } else {
                         app.name.clone()
                     };
                     let description = if is_browser_mitm_prompt {
                         app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| format!(
                                 "{} reported browser-side anti-MITM behavior. This can be a legitimate trust mismatch or explicit anti-interception logic. Choose ALLOW MITM to keep interception enabled, ALLOW MITM ONCE for a one-time retry, or NO MITM to bypass interception for this target.",
                                 app.name
                             ))
                     } else if is_registry_alert {
                         app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| format!("{} is attempting a protected registry modification.", app.name))
                     } else if is_website_alert {
                         let base = app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| "The request matched the website intelligence feeds and is waiting for your decision.".to_string());
                         format!(
                             "{} Choosing TRUST (NO MITM) keeps the site allowed while adding it to the MITM bypass list.",
                             base
                         )
                     } else if is_behavior_alert {
                         app.reason
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| format!("{} triggered a behavioral detection.", app.name))
                     } else {
                         format!(
                             "{} is attempting network access.",
                             if app.hostname.is_some() {
                                 app.name.clone()
                             } else {
                                 "System intercept".to_string()
                             }
                         )
                     };
                     let description = if is_owlyshield_alert && !is_browser_mitm_prompt && !is_website_alert {
                         format!(
                             "{} Choose DENY to block access, ONCE to allow this session only, or TRUST to always allow.",
                             description
                         )
                     } else {
                         description
                     };
                     let target_label = if is_browser_mitm_prompt {
                         "Website:"
                     } else if is_registry_alert {
                         "Registry:"
                     } else if is_website_alert {
                         "URL:"
                     } else if is_behavior_alert {
                         "Detection:"
                     } else {
                         "Target:"
                     };
                     let target_value = if is_browser_mitm_prompt {
                         app.full_url
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .or_else(|| app.target.clone().filter(|value| !value.trim().is_empty()))
                             .or_else(|| app.hostname.clone().filter(|value| !value.trim().is_empty()))
                             .unwrap_or_else(|| format!("127.0.0.1:{} (TCP)", app.dst_port))
                     } else if is_registry_alert {
                         app.target
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| "Protected registry target".to_string())
                     } else if is_website_alert {
                         app.full_url
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .or_else(|| app.target.clone().filter(|value| !value.trim().is_empty()))
                             .or_else(|| app.hostname.clone().filter(|value| !value.trim().is_empty()))
                             .unwrap_or_else(|| format!("{}:{} ({})", app.dst_ip, app.dst_port, match app.protocol {
                                 Protocol::TCP => "TCP",
                                 Protocol::UDP => "UDP",
                                 Protocol::ICMP => "ICMP",
                                 Protocol::Raw(_) => "RAW",
                             }))
                     } else if is_behavior_alert {
                         app.target
                             .clone()
                             .filter(|value| !value.trim().is_empty())
                             .unwrap_or_else(|| app.alert_kind.clone().unwrap_or_else(|| "Behavioral Threat".to_string()))
                     } else {
                         format!(
                             "{}:{} ({})",
                             app.dst_ip,
                             app.dst_port,
                             match app.protocol {
                                 Protocol::TCP => "TCP",
                                 Protocol::UDP => "UDP",
                                 Protocol::ICMP => "ICMP",
                                 Protocol::Raw(_) => "RAW",
                             }
                         )
                     };
                     view! {
                         <div class="alert-window-scroll">
                             <div class="alert-content-grid" style="margin-top: 0">
                                 <div class="alert-info-container">
                                      <h2 class="alert-title" style="margin-bottom: 5px">
                                          {title}
                                      </h2>
                                      <div class="alert-desc" style="margin-bottom: 8px">
                                          {description}
                                      </div>
                                      <div class="alert-details-box">
                                          <div class="detail-row"> <span class="detail-label">{target_label}</span> <span class="detail-value" title=target_value.clone()>{target_value}</span> </div>
                                          <div class="detail-row"> <span class="detail-label">"Path:"</span> <span class="detail-value path" title=app.path.clone()>{app.path.clone()}</span> </div>
                                          {app.http_method.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Method:"</span> <span class="detail-value">{value}</span> </div>
                                          })}
                                          {app.hostname.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Host:"</span> <span class="detail-value" title=value.clone()>{value}</span> </div>
                                          })}
                                          {app.http_referer.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Referer:"</span> <span class="detail-value path" title=value.clone()>{value}</span> </div>
                                          })}
                                          {app.http_content_type.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"Content-Type:"</span> <span class="detail-value" title=value.clone()>{value}</span> </div>
                                          })}
                                          {app.detected_file_type.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                              <div class="detail-row"> <span class="detail-label">"File Type:"</span> <span class="detail-value">{value}</span> </div>
                                          })}
                                      </div>
                                      {app.http_request_body.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                          <div class="alert-details-box" style="margin-top: 12px;">
                                              <div class="detail-row" style="display: block;">
                                                  <span class="detail-label">"Request Body:"</span>
                                                  <pre class="detail-value path" style="display: block; white-space: pre-wrap; overflow-wrap: anywhere; max-height: none; overflow-x: auto; overflow-y: visible; margin-top: 6px;">{value}</pre>
                                              </div>
                                          </div>
                                      })}
                                      {app.http_response_body.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                          <div class="alert-details-box" style="margin-top: 12px;">
                                              <div class="detail-row" style="display: block;">
                                                  <span class="detail-label">"Response Body:"</span>
                                                  <pre class="detail-value path" style="display: block; white-space: pre-wrap; overflow-wrap: anywhere; max-height: none; overflow-x: auto; overflow-y: visible; margin-top: 6px;">{value}</pre>
                                              </div>
                                          </div>
                                      })}
                                      {app.packet_json.clone().filter(|value| !value.trim().is_empty()).map(|value| view! {
                                          <div class="alert-details-box" style="margin-top: 12px;">
                                              <div class="detail-row" style="display: block;">
                                                  <span class="detail-label">"Packet JSON:"</span>
                                                  <pre class="detail-value path" style="display: block; white-space: pre-wrap; overflow-wrap: anywhere; max-height: none; overflow-x: auto; overflow-y: visible; margin-top: 6px;">{value}</pre>
                                              </div>
                                          </div>
                                      })}
                                 </div>
                             </div>
                         </div>
                         <div class="alert-footer-actions">
                             {if is_browser_mitm_prompt {
                                 view! {
                                     <>
                                         <button class="alert-btn session" on:click={let p = app.path.clone(); move |_| res1(n1.clone(), p.clone(), "allow_once".to_string())}> "ALLOW MITM ONCE" </button>
                                         <button class="alert-btn quarantine" on:click={let p = app.path.clone(); move |_| res5(n5.clone(), p.clone(), "allow_always_no_mitm".to_string())}> "NO MITM" </button>
                                         <button class="alert-btn always" on:click={let p = app.path.clone(); move |_| res2(n2.clone(), p.clone(), "allow_always".to_string())}> "ALLOW MITM" </button>
                                     </>
                                 }.into_view()
                             } else {
                                 view! {
                                     <>
                                         <button class="alert-btn block" on:click={let p = app.path.clone(); move |_| res5(n5.clone(), p.clone(), "deny".to_string())}> "DENY" </button>
                                         <button class="alert-btn session" on:click={let p = app.path.clone(); move |_| res1(n1.clone(), p.clone(), "allow_once".to_string())}> "ONCE" </button>
                                         <button class="alert-btn always" on:click={let p = app.path.clone(); let decision = always_decision.clone(); move |_| res2(n2.clone(), p.clone(), decision.clone())}> {always_label} </button>
                                     </>
                                 }.into_view()
                             }}
                         </div>
                     }
                 })}
             </div>
        </div>
    }
}
