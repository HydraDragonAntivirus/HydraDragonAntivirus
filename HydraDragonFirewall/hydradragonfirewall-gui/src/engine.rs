use crate::file_magic::FileMagicChecker;
use crate::quarantine::{compute_sha256, quarantine_file as write_quarantine_file};
use crate::web_filter::WebFilter;
use hydradragon_shared::{QUARANTINE_PATH, TlsInspectionMode, TlsProxyConfig};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use shared_no_std::ghost_hunting::{NetworkActivityData, NtFunction, Syscall};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Position, Runtime, Size, WebviewUrl,
    WebviewWindowBuilder,
};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::oneshot;
use windivert::prelude::*;

lazy_static! {
    static ref URL_REGEX: Regex =
        Regex::new(r"(?i)https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+")
            .expect("failed to compile URL regex");
    static ref DOMAIN_TOKEN_REGEX: Regex =
        Regex::new(r"(?i)\b(([a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,})\b")
            .expect("failed to compile domain token regex");
}
// Imports updated below

#[derive(Clone, Debug, Default)]
struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    fn from_cidrs(cidrs: &[String]) -> Self {
        let mut index = Self::default();
        for cidr in cidrs {
            index.add(cidr);
        }
        index.normalize();
        index
    }

    fn add(&mut self, cidr: &str) -> bool {
        let trimmed = cidr.trim();
        if trimmed == "0.0.0.0/0"
            || trimmed == "0.0.0.0"
            || trimmed == "::/0"
            || trimmed == "::"
            || trimmed.ends_with("/0")
        {
            return false;
        }
        match Self::parse_interval(cidr) {
            Some(CidrInterval::V4(start, end)) => {
                self.v4.push((start, end));
                true
            }
            Some(CidrInterval::V6(start, end)) => {
                self.v6.push((start, end));
                true
            }
            None => false,
        }
    }

    fn normalize(&mut self) {
        Self::merge_intervals_u32(&mut self.v4);
        Self::merge_intervals_u128(&mut self.v6);
    }

    fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        match ip {
            IpAddr::V4(ipv4) => Self::contains_value(&self.v4, u32::from(ipv4)),
            IpAddr::V6(ipv6) => Self::contains_value(&self.v6, u128::from(ipv6)),
        }
    }

    fn parse_interval(cidr: &str) -> Option<CidrInterval> {
        let cidr = cidr.trim();
        if let Some((network, prefix)) = cidr.split_once('/') {
            let prefix_len = prefix.parse::<u32>().ok()?;

            if let Ok(ipv4) = network.parse::<Ipv4Addr>() {
                // 0.0.0.0/0 protection: prefix_len == 0 or unspecified IP matches entire IPv4 space
                if prefix_len == 0 || prefix_len > 32 || ipv4.is_unspecified() {
                    return None;
                }
                let mask = !0u32 << (32 - prefix_len);
                let start = u32::from(ipv4) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V4(start, end));
            }

            if let Ok(ipv6) = network.parse::<Ipv6Addr>() {
                // ::/0 protection: prefix_len == 0 or unspecified IP matches entire IPv6 space
                if prefix_len == 0 || prefix_len > 128 || ipv6.is_unspecified() {
                    return None;
                }
                let mask = !0u128 << (128 - prefix_len);
                let start = u128::from(ipv6) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V6(start, end));
            }

            return None;
        }

        match cidr.parse::<IpAddr>().ok()? {
            IpAddr::V4(ipv4) => {
                if ipv4.is_unspecified() || ipv4.is_broadcast() {
                    return None;
                }
                let value = u32::from(ipv4);
                Some(CidrInterval::V4(value, value))
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unspecified() {
                    return None;
                }
                let value = u128::from(ipv6);
                Some(CidrInterval::V6(value, value))
            }
        }
    }

    fn merge_intervals_u32(intervals: &mut Vec<(u32, u32)>) {
        intervals.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(intervals.len());

        for &(start, end) in intervals.iter() {
            let Some(last) = merged.last_mut() else {
                merged.push((start, end));
                continue;
            };

            if start > last.1.saturating_add(1) {
                merged.push((start, end));
            } else if end > last.1 {
                last.1 = end;
            }
        }

        *intervals = merged;
    }

    fn merge_intervals_u128(intervals: &mut Vec<(u128, u128)>) {
        intervals.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(intervals.len());

        for &(start, end) in intervals.iter() {
            let Some(last) = merged.last_mut() else {
                merged.push((start, end));
                continue;
            };

            if start > last.1.saturating_add(1) {
                merged.push((start, end));
            } else if end > last.1 {
                last.1 = end;
            }
        }

        *intervals = merged;
    }

    fn contains_value<T>(intervals: &[(T, T)], value: T) -> bool
    where
        T: Copy + Ord,
    {
        let index = intervals.partition_point(|&(start, _)| start <= value);
        index > 0 && intervals[index - 1].1 >= value
    }
}

enum CidrInterval {
    V4(u32, u32),
    V6(u128, u128),
}

fn normalize_kernel_block_path_candidate(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return None;
    }

    let normalized = trimmed.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();

    if lower.contains("://") {
        return None;
    }

    let chars: Vec<char> = normalized.chars().collect();
    let is_drive_path =
        chars.len() >= 3 && chars[1] == ':' && (chars[2] == '\\' || chars[2] == '/');
    let is_unc_path = normalized.starts_with("\\\\");
    let is_nt_path = lower.starts_with("\\device\\")
        || lower.starts_with("\\??\\")
        || lower.starts_with("\\\\?\\");

    if is_drive_path || is_unc_path || is_nt_path {
        Some(normalized)
    } else {
        None
    }
}

fn select_kernel_block_path(alert: &PendingApp) -> Option<String> {
    alert
        .target
        .as_deref()
        .and_then(normalize_kernel_block_path_candidate)
        .or_else(|| normalize_kernel_block_path_candidate(&alert.path))
}

fn kernel_block_message(path: &str) -> String {
    format!("KERNEL_BLOCK_PATH:{}\n", path)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenEdrVerdict {
    Absent,
    Safe,
    Malicious,
    Unknown,
    Fail,
}

impl OpenEdrVerdict {
    fn label(self) -> &'static str {
        match self {
            Self::Absent => "Unrecognized",
            Self::Safe => "Possible Safe",
            Self::Malicious => "Malware",
            Self::Unknown => "Unknown",
            Self::Fail => "Fail",
        }
    }

    fn log_level(self) -> LogLevel {
        match self {
            Self::Safe => LogLevel::Success,
            Self::Absent | Self::Unknown | Self::Fail => LogLevel::Warning,
            Self::Malicious => LogLevel::Error,
        }
    }

    fn is_cloud_trusted(self) -> bool {
        matches!(self, Self::Safe)
    }
}

fn normalize_openedr_verdict(raw: Option<&str>, trust_message: bool) -> OpenEdrVerdict {
    fn from_openedr_token(token: &str) -> Option<OpenEdrVerdict> {
        match token {
            "0" | "0x0" | "absent" => Some(OpenEdrVerdict::Absent),
            "1" | "0x1" | "safe" => Some(OpenEdrVerdict::Safe),
            "2" | "0x2" | "malicious" | "malware" => Some(OpenEdrVerdict::Malicious),
            "3" | "0x3" | "unknown" => Some(OpenEdrVerdict::Unknown),
            "4" | "0x4" | "fail" | "failed" => Some(OpenEdrVerdict::Fail),
            _ => None,
        }
    }

    let value = raw
        .map(str::trim)
        .unwrap_or_default()
        .trim_matches('"')
        .trim_matches('\'')
        .trim();

    if value.is_empty() {
        return if trust_message {
            OpenEdrVerdict::Safe
        } else {
            OpenEdrVerdict::Unknown
        };
    }

    let lowered = value.to_ascii_lowercase();
    if let Some(verdict) = from_openedr_token(lowered.trim()) {
        return verdict;
    }

    for token in lowered
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        if matches!(token, "verdict" | "fls" | "flsverdict" | "fileverdict") {
            continue;
        }
        if let Some(verdict) = from_openedr_token(token) {
            return verdict;
        }
    }

    OpenEdrVerdict::Unknown
}

fn is_known_browser_process(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "firefox.exe"
            | "chrome.exe"
            | "msedge.exe"
            | "brave.exe"
            | "opera.exe"
            | "launcher.exe"
            | "vivaldi.exe"
            | "librewolf.exe"
            | "waterfox.exe"
            | "iexplore.exe"
    )
}

fn browser_mitm_error_hint(name: &str) -> &'static str {
    let lower = name.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "firefox.exe" | "librewolf.exe" | "waterfox.exe"
    ) {
        "SEC_ERROR_UNKNOWN_ISSUER"
    } else {
        "NET::ERR_CERT_AUTHORITY_INVALID"
    }
}

fn browser_family(name: &str) -> &'static str {
    let lower = name.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "firefox.exe" | "librewolf.exe" | "waterfox.exe"
    ) {
        "firefox"
    } else {
        "chromium"
    }
}

fn browser_mitm_prompt_decision_key(browser_name: &str, target: &str) -> String {
    format!(
        "browser-mitm:{}:{}",
        browser_name.trim().to_ascii_lowercase(),
        target.trim().to_ascii_lowercase()
    )
}

fn is_unresolved_identity(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown")
}

const SANCTUM_FIREWALL_TELEMETRY_PIPE: &str = r"\\.\pipe\hydradragon_firewall_telemetry";

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

impl Protocol {
    fn label(&self) -> &'static str {
        match self {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Raw(_) => "RAW",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub size: usize,
    pub outbound: bool,
    pub process_id: u32,
    /// DNS question name if this packet carries a DNS query
    pub dns_query: Option<String>,
    /// Hostname extracted from HTTP Host header or TLS SNI
    pub hostname: Option<String>,
    /// Full URL (HTTP only, HTTPS only has hostname)
    pub full_url: Option<String>,
    /// Whether the packet looked like a TLS Client Hello (used to trigger HTTPS hooks)
    pub tls_handshake: bool,
    /// HTTP method when available
    pub http_method: Option<String>,
    /// HTTP path when available
    pub http_path: Option<String>,
    /// HTTP User-Agent when available
    pub http_user_agent: Option<String>,
    /// HTTP Content-Type header when available
    pub http_content_type: Option<String>,
    /// HTTP Referer header when available
    pub http_referer: Option<String>,
    /// Shannon entropy of the packet payload for entropy-based anomaly checks
    pub payload_entropy: Option<f64>,
    /// Hex preview of the first bytes of the payload for forensic visibility
    pub payload_sample: Option<String>,
    /// URLs discovered anywhere in the payload (helps catch malware beacons and C2s)
    pub payload_urls: Vec<String>,
    /// Domain-like tokens discovered in the payload for additional matching
    pub payload_domains: Vec<String>,
    /// Full image path of the process associated with this packet
    pub image_path: String,
    /// Detected file type from magic bytes (e.g. "exe", "zip", "pdf")
    pub detected_file_type: Option<String>,
    /// Decrypted HTTP request body captured by the Transparent TLS Proxy (UTF-8 text or hex)
    pub http_request_body: Option<String>,
    /// Decrypted HTTP response body captured by the Transparent TLS Proxy (UTF-8 text or hex)
    pub http_response_body: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp: u64,
    pub domain: String,
    pub blocked: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
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

fn default_queue_position() -> usize {
    1
}

fn default_queue_total() -> usize {
    1
}

fn firewall_data_dir() -> PathBuf {
    PathBuf::from("C:\\ProgramData")
        .join("HydraDragonAntivirus")
        .join("HydraDragonFirewall")
}

fn firewall_log_file_path() -> PathBuf {
    firewall_data_dir()
        .join("logs")
        .join("firewall_activity.jsonl")
}

fn default_website_path() -> String {
    let repo_path = PathBuf::from("hydradragon").join("website");
    if repo_path.exists() {
        return repo_path.to_string_lossy().to_string();
    }
    "hydradragon\\website".to_string()
}

fn persist_log_entry(entry: &LogEntry, settings: Option<&FirewallSettings>) {
    if settings.is_some_and(|current| !current.save_all_logs) {
        return;
    }

    let log_path = firewall_log_file_path();
    if let Some(parent) = log_path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }

    let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    else {
        return;
    };

    let Ok(line) = serde_json::to_string(entry) else {
        return;
    };

    let _ = writeln!(file, "{line}");
}

pub fn load_saved_logs(limit: Option<usize>) -> Vec<LogEntry> {
    let log_path = firewall_log_file_path();
    let Ok(file) = fs::File::open(log_path) else {
        return Vec::new();
    };

    let reader = BufReader::new(file);
    if let Some(limit) = limit {
        let keep = limit.max(1);
        let mut tail = VecDeque::with_capacity(keep);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(entry) = serde_json::from_str::<LogEntry>(&line) {
                if tail.len() == keep {
                    tail.pop_front();
                }
                tail.push_back(entry);
            }
        }
        return tail.into_iter().collect();
    }

    reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<LogEntry>(&line).ok())
        .collect()
}

pub fn emit_log_event<R: Runtime>(app: &AppHandle<R>, entry: LogEntry) {
    let settings_snapshot = app
        .try_state::<Arc<FirewallEngine>>()
        .map(|engine| engine.settings.read().unwrap().clone());
    persist_log_entry(&entry, settings_snapshot.as_ref());
    let _ = app.emit("log", entry);
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppDecision {
    Pending,
    Allow,
    Block,
    AllowOnce,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingApp {
    pub process_id: u32,
    pub name: String,
    pub path: String,
    pub dst_ip: IpAddr,
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
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub block: bool,
    pub protocol: Option<Protocol>,
    pub remote_ips: Vec<String>,
    pub remote_ports: Vec<u16>,
    pub app_name: Option<String>,
    /// Hostname pattern for URL-based filtering (supports wildcards like *.facebook.com)
    pub hostname_pattern: Option<String>,
    /// URL pattern for HTTP filtering (supports wildcards)
    pub url_pattern: Option<String>,
    /// File types to match (e.g. "exe", "zip") based on magic bytes
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
    #[serde(default)]
    pub network_whitelist: Vec<String>,
}

impl FirewallRule {
    pub fn matches(&self, packet: &PacketInfo, app_name: &str) -> bool {
        if !self.enabled {
            return false;
        }

        for cidr in &self.network_whitelist {
            if ip_in_cidr(packet.src_ip, cidr) || ip_in_cidr(packet.dst_ip, cidr) {
                return false;
            }
        }

        if let Some(ref proto) = self.protocol {
            if proto != &packet.protocol {
                return false;
            }
        }

        // Direction-aware IP/Port matching
        let remote_ip = if packet.outbound {
            packet.dst_ip
        } else {
            packet.src_ip
        };
        let remote_port = if packet.outbound {
            packet.dst_port
        } else {
            packet.src_port
        };

        if !self.remote_ips.is_empty() {
            let mut matched_ip = false;
            let remote_ip_str = remote_ip.to_string();
            for pattern in &self.remote_ips {
                if pattern == "any" || pattern == "*" {
                    matched_ip = true;
                    break;
                }
                // Support inline port notation: "1.2.3.4:443" or "[::1]:443"
                let (ip_part, inline_port) = Self::split_ip_port(pattern);
                if ip_part == remote_ip_str || ip_part == "any" || ip_part == "*" {
                    if let Some(p) = inline_port {
                        if p == remote_port {
                            matched_ip = true;
                            break;
                        }
                        // IP matched but port didn't — keep looking
                    } else {
                        matched_ip = true;
                        break;
                    }
                }
            }
            if !matched_ip {
                return false;
            }
        }

        if !self.remote_ports.is_empty() {
            if !self.remote_ports.contains(&remote_port) {
                return false;
            }
        }

        if let Some(ref rule_app) = self.app_name {
            if !app_name.to_lowercase().contains(&rule_app.to_lowercase()) {
                return false;
            }
        }

        // Hostname pattern matching (for HTTPS SNI and HTTP Host)
        // Supports inline port: "example.com:443" or "*.example.com:8443"
        if let Some(ref pattern) = self.hostname_pattern {
            if let Some(ref hostname) = packet.hostname {
                let (host_part, inline_port) = Self::split_host_port(pattern);
                let host_matched = Self::wildcard_match(&host_part, hostname);
                let port_matched = inline_port.map_or(true, |p| p == remote_port);
                if !host_matched || !port_matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        // URL pattern matching (for HTTP only)
        if let Some(ref pattern) = self.url_pattern {
            if let Some(ref url) = packet.full_url {
                if !Self::wildcard_match(pattern, url) {
                    return false;
                }
            } else {
                // No URL in packet but rule requires it
            }
        }

        // File Magic matching
        if !self.file_types.is_empty() {
            if let Some(ref ftype) = packet.detected_file_type {
                if !self.file_types.contains(ftype) {
                    return false;
                }
            } else {
                // Rule requires file type match, but packet has none
                return false;
            }
        }

        true
    }

    /// Simple wildcard matching (supports * for any characters)
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        let text_lower = text.to_lowercase();

        if pattern_lower == "*" || pattern_lower == "any" {
            return true;
        }

        // Handle *.example.com pattern
        if pattern_lower.starts_with("*.") {
            let suffix = &pattern_lower[1..]; // Keep the dot
            return text_lower.ends_with(suffix) || text_lower == &pattern_lower[2..];
        }

        // Handle *keyword* pattern
        if pattern_lower.starts_with('*') && pattern_lower.ends_with('*') {
            let keyword = &pattern_lower[1..pattern_lower.len() - 1];
            return text_lower.contains(keyword);
        }

        // Handle keyword* pattern
        if pattern_lower.ends_with('*') {
            let prefix = &pattern_lower[..pattern_lower.len() - 1];
            return text_lower.starts_with(prefix);
        }

        // Handle *keyword pattern
        if pattern_lower.starts_with('*') {
            let suffix = &pattern_lower[1..];
            return text_lower.ends_with(suffix);
        }

        // Exact match
        text_lower == pattern_lower
    }

    /// Split an IP entry that may carry an inline port.
    ///
    /// Handles:
    ///   "1.2.3.4"        → ("1.2.3.4", None)
    ///   "1.2.3.4:443"    → ("1.2.3.4", Some(443))
    ///   "[::1]"          → ("::1",     None)
    ///   "[::1]:443"      → ("::1",     Some(443))
    ///   "any" / "*"      → ("any"/"*", None)
    fn split_ip_port(s: &str) -> (String, Option<u16>) {
        let s = s.trim();
        // IPv6 bracketed form: [addr]:port or [addr]
        if s.starts_with('[') {
            if let Some(close) = s.find(']') {
                let addr = s[1..close].to_string();
                let rest = &s[close + 1..];
                if let Some(port_str) = rest.strip_prefix(':') {
                    if let Ok(p) = port_str.parse::<u16>() {
                        return (addr, Some(p));
                    }
                }
                return (addr, None);
            }
        }
        // IPv4 or plain string: split on the last ':'
        if let Some(colon) = s.rfind(':') {
            let maybe_port = &s[colon + 1..];
            if let Ok(p) = maybe_port.parse::<u16>() {
                // Make sure the left side isn't itself an IPv6 address
                // (bare IPv6 without brackets would have multiple colons).
                let left = &s[..colon];
                if !left.contains(':') {
                    return (left.to_string(), Some(p));
                }
            }
        }
        (s.to_string(), None)
    }

    /// Split a hostname pattern that may carry an inline port.
    ///
    /// Handles:
    ///   "example.com"         → ("example.com", None)
    ///   "example.com:443"     → ("example.com", Some(443))
    ///   "*.example.com:8443"  → ("*.example.com", Some(8443))
    fn split_host_port(s: &str) -> (String, Option<u16>) {
        let s = s.trim();
        if let Some(colon) = s.rfind(':') {
            let maybe_port = &s[colon + 1..];
            if let Ok(p) = maybe_port.parse::<u16>() {
                return (s[..colon].to_string(), Some(p));
            }
        }
        (s.to_string(), None)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallSettings {
    pub app_decisions: HashMap<String, AppDecision>,
    #[serde(default)]
    pub kernel_block_paths: Vec<String>,
    pub website_path: String,
    pub rules: Vec<FirewallRule>,
    pub late_blocking_mode: bool,
    #[serde(default)]
    pub headless_mode: bool,
    #[serde(default)]
    pub log_mode: bool,
    #[serde(default)]
    #[serde(alias = "show_blocked_only")]
    pub show_blocked_logs_only: bool,
    #[serde(default)]
    pub show_blocked_http_inspector_only: bool,
    #[serde(default)]
    pub show_blocked_graphics_only: bool,
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
    pub tls_proxy: TlsProxyConfig,
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub network_whitelist: Vec<String>,
    #[serde(default)]
    pub allow_unknown_apps: bool,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        let apps = HashMap::new();

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "2.0.0".to_string());
        metadata.insert(
            "description".to_string(),
            "HydraDragon Next-Gen Firewall Configuration".to_string(),
        );
        metadata.insert("theme".to_string(), "cyberpunk".to_string());

        Self {
            app_decisions: apps,
            kernel_block_paths: Vec::new(),
            website_path: String::new(),
            rules: Vec::new(),
            late_blocking_mode: false,
            headless_mode: false,
            log_mode: false,
            show_blocked_logs_only: false,
            show_blocked_http_inspector_only: false,
            show_blocked_graphics_only: false,
            no_alert_mode: false,
            save_all_logs: true,
            prune_old_logs: true,
            max_visible_logs: default_max_visible_logs(),
            prune_http_history: default_prune_http_history(),
            max_visible_http_events: default_max_visible_http_history(),
            log_full_bodies: false,
            tls_proxy: TlsProxyConfig::default(),
            metadata,
            network_whitelist: Vec::new(),
            allow_unknown_apps: false,
        }
    }
}

pub struct Statistics {
    pub packets_total: AtomicU64,
    pub packets_blocked: AtomicU64,
    pub packets_allowed: AtomicU64,
    pub icmp_blocked: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub tcp_connections: AtomicU64,
    pub last_log_time: AtomicU64,         // Rate limiting for blocked
    pub last_allowed_log_time: AtomicU64, // Rate limiting for allowed
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            packets_total: AtomicU64::new(0),
            packets_blocked: AtomicU64::new(0),
            packets_allowed: AtomicU64::new(0),
            icmp_blocked: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            dns_blocked: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            last_log_time: AtomicU64::new(0),
            last_allowed_log_time: AtomicU64::new(0),
        }
    }
}

pub struct DnsHandler {
    queries: RwLock<VecDeque<DnsQuery>>,
    ip_map: RwLock<HashMap<String, (String, SystemTime)>>,
    /// Maps domain → (pid, app_name) so proxy-attributed packets can be
    /// re-attributed to the original app that queried the domain.
    domain_pid_map: RwLock<HashMap<String, (u32, String)>>,
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            queries: RwLock::new(VecDeque::new()),
            ip_map: RwLock::new(HashMap::new()),
            domain_pid_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn should_block(&self, _domain: &str, _settings: &FirewallSettings) -> bool {
        // DNS blocking is now handled by SDK signatures; the legacy keyword list has been removed.
        false
    }

    pub fn log_query(&self, domain: String, blocked: bool) {
        let mut queries = self.queries.write().unwrap();
        queries.push_back(DnsQuery {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            domain,
            blocked,
        });
        if queries.len() > 500 {
            queries.pop_front();
        }
    }

    pub fn update_ip_map(&self, ip: String, domain: String) {
        let mut map = self.ip_map.write().unwrap();
        map.insert(ip, (domain, SystemTime::now()));
        // Optional: Periodic cleanup of old entries could be added here
        if map.len() > 2000 {
            // Very basic cleanup if it gets too large
            map.clear();
        }
    }

    pub fn resolve_ip(&self, ip: &str) -> Option<String> {
        let map = self.ip_map.read().unwrap();
        map.get(ip).map(|(domain, _)| domain.clone())
    }

    /// Record which app (pid + name) made an outbound DNS query for a domain.
    /// Only call this for non-proxy processes so the original requester is preserved.
    pub fn record_domain_pid(&self, domain: String, pid: u32, app_name: String) {
        let mut map = self.domain_pid_map.write().unwrap();
        map.insert(domain.to_lowercase(), (pid, app_name));
        if map.len() > 2000 {
            map.clear();
        }
    }

    /// Given a hostname, return the (pid, app_name) of the app that originally
    /// queried for it — used to re-attribute proxy upstream connections.
    pub fn resolve_domain_pid(&self, domain: &str) -> Option<(u32, String)> {
        let map = self.domain_pid_map.read().unwrap();
        map.get(&domain.to_lowercase()).cloned()
    }
}

// ============================================================================
// APP NAME CACHE - CRITICAL FIX #1
// ============================================================================
pub struct AppInfoCache {
    cache: RwLock<HashMap<u32, (AppInfoContext, SystemTime)>>,
    cache_duration: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppInfoContext {
    pub name: String,
    pub path: String,
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

impl AppInfoCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            cache_duration: Duration::from_secs(300),
        }
    }

    pub fn get_info(&self, pid: u32) -> AppInfoContext {
        // Fast path: check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some((info, timestamp)) = cache.get(&pid) {
                if timestamp.elapsed().unwrap_or(Duration::MAX) < self.cache_duration {
                    return info.clone();
                }
            }
        }

        // Slow path: fetch and cache
        let (name, path) = Self::get_process_info_native(pid);
        let info = AppInfoContext { name, path };
        let mut cache = self.cache.write().unwrap();
        cache.insert(pid, (info.clone(), SystemTime::now()));

        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }

        info
    }

    fn get_process_info_native(pid: u32) -> (String, String) {
        if pid == 0 || pid == 4 {
            return ("System".to_string(), "System".to_string());
        }

        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        };
        use windows::core::PWSTR;

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if let Ok(handle) = handle {
                let mut wide_buffer = vec![0u16; 1024];
                let mut wide_len = wide_buffer.len() as u32;
                let wide_ok = QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    PWSTR(wide_buffer.as_mut_ptr()),
                    &mut wide_len,
                )
                .is_ok();

                if wide_ok && wide_len > 0 {
                    let full_path = String::from_utf16_lossy(&wide_buffer[..wide_len as usize]);
                    let _ = CloseHandle(handle);
                    let name = Path::new(&full_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    return (name, full_path);
                }

                let mut ansi_buffer = [0u8; 1024];
                let ansi_len = GetModuleFileNameExA(Some(handle), None, &mut ansi_buffer);
                let _ = CloseHandle(handle);

                if ansi_len > 0 {
                    let full_path =
                        String::from_utf8_lossy(&ansi_buffer[..ansi_len as usize]).to_string();
                    let name = Path::new(&full_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    return (name, full_path);
                }
            }
        }

        ("Unknown".to_string(), "Unknown".to_string())
    }
}

pub struct AppManager {
    pub decisions: RwLock<HashMap<String, AppDecision>>,
    pub pending: RwLock<VecDeque<PendingApp>>,
    pub known_apps: RwLock<HashSet<String>>,
    pub allow_unknown_apps: RwLock<bool>,
    pub port_map: RwLock<HashMap<u16, u32>>,
    pub info_cache: AppInfoCache,
    pub url_cache: RwLock<HashMap<u32, String>>,
    pub ghost_urls: RwLock<HashMap<u32, String>>,
    pub active_alert: RwLock<Option<PendingApp>>,
    pub suspicious_pids: RwLock<HashSet<u32>>,
    pub cloud_trusted_pids: RwLock<HashSet<u32>>,
    pub openedr_verdicts: RwLock<HashMap<u32, String>>,
    /// Tracks which slot (0-based) the user is currently viewing, for the position counter.
    pub view_index: AtomicU64,
}

impl AppManager {
    pub fn new(initial_decisions: HashMap<String, AppDecision>) -> Self {
        Self {
            decisions: RwLock::new(initial_decisions),
            pending: RwLock::new(VecDeque::new()),
            known_apps: RwLock::new(HashSet::new()),
            allow_unknown_apps: RwLock::new(false),
            port_map: RwLock::new(HashMap::new()),
            info_cache: AppInfoCache::new(),
            url_cache: RwLock::new(HashMap::new()),
            ghost_urls: RwLock::new(HashMap::new()),
            active_alert: RwLock::new(None),
            suspicious_pids: RwLock::new(HashSet::new()),
            cloud_trusted_pids: RwLock::new(HashSet::new()),
            openedr_verdicts: RwLock::new(HashMap::new()),
            view_index: AtomicU64::new(0),
        }
    }

    pub fn update_port_mapping(&self, port: u16, pid: u32) {
        if port == 0 || pid == 0 {
            return;
        }
        let mut map = self.port_map.write().unwrap();
        map.insert(port, pid);
    }

    pub fn get_pid_for_port(&self, port: u16) -> Option<u32> {
        self.port_map.read().unwrap().get(&port).cloned()
    }

    // OPTIMIZED: Now uses cache
    pub fn check_app(&self, packet: &PacketInfo) -> (AppDecision, String, String) {
        let mut pid = packet.process_id;

        if pid == 0 {
            if packet.outbound {
                if let Some(p) = self.get_pid_for_port(packet.src_port) {
                    pid = p;
                }
            } else {
                if let Some(p) = self.get_pid_for_port(packet.dst_port) {
                    pid = p;
                }
            }
        }

        let info = self.info_cache.get_info(pid);
        let app_name = info.name;
        let app_path = info.path;
        let app_name_lower = app_name.to_lowercase();

        // Hard-code only the immutable OS-level identifiers.
        // Everything else — firewall, AV, proxy processes — is driven exclusively
        // by app_decisions entries in settings.json (full paths).
        if pid == std::process::id() || app_name_lower == "system" || pid == 0 || pid == 4 {
            return (AppDecision::Allow, app_name, app_path);
        }

        // Check decision cache: full image path takes priority, short name as fallback.
        {
            let decisions = self.decisions.read().unwrap();
            let app_path_lower = app_path.to_lowercase();
            let allow_name_fallback = !is_unresolved_identity(&app_name_lower);
            if let Some(decision) = decisions.get(&app_path_lower).or_else(|| {
                if allow_name_fallback {
                    decisions.get(&app_name_lower)
                } else {
                    None
                }
            }) {
                return (decision.clone(), app_name, app_path);
            }
        }

        // Check if new
        {
            let known = self.known_apps.read().unwrap();
            if !known.contains(&app_name_lower) {
                if self.allow_unknown_apps.read().unwrap().clone() {
                    return (AppDecision::Allow, app_name, app_path);
                }
                return (AppDecision::Pending, app_name, app_path);
            }
        }

        (AppDecision::Allow, app_name, app_path)
    }
    pub fn resolve_decision(&self, name: &str, decision: AppDecision) {
        let name_lower = name.to_lowercase();
        let mut decisions = self.decisions.write().unwrap();
        decisions.insert(name_lower, decision);
    }

    pub fn get_decision(&self, key: &str) -> Option<AppDecision> {
        self.decisions
            .read()
            .unwrap()
            .get(&key.to_lowercase())
            .cloned()
    }

    pub fn remove_decision(&self, name_lower: &str) {
        let mut decisions = self.decisions.write().unwrap();
        decisions.remove(name_lower);
    }

    pub fn clear_decisions(&self) {
        let mut decisions = self.decisions.write().unwrap();
        decisions.clear();
    }

    fn pending_identity(app: &PendingApp) -> String {
        if let Some(request_id) = app.request_id.as_ref() {
            return format!("request:{}", request_id.to_lowercase());
        }

        if let Some(decision_key) = app.decision_key.as_ref() {
            return format!("decision:{}", decision_key.to_lowercase());
        }

        let path = app.path.trim();
        if !path.is_empty() && !path.eq_ignore_ascii_case("unknown") {
            format!("path:{}", path.to_lowercase())
        } else {
            format!("name:{}", app.name.to_lowercase())
        }
    }

    pub fn enqueue_pending_app(&self, app: PendingApp, remember_unknown_app: bool) -> bool {
        let app_name_lower = app.name.to_lowercase();

        if remember_unknown_app {
            let mut known = self.known_apps.write().unwrap();
            if known.contains(&app_name_lower) {
                return false;
            }
            known.insert(app_name_lower);
        }

        let app_identity = Self::pending_identity(&app);

        {
            let active = self.active_alert.read().unwrap();
            if let Some(current) = active.as_ref() {
                if Self::pending_identity(current) == app_identity
                    && current.dst_ip == app.dst_ip
                    && current.dst_port == app.dst_port
                    && current.protocol == app.protocol
                    && current.reason == app.reason
                {
                    return false;
                }
            }
        }

        let mut pending = self.pending.write().unwrap();
        if pending.iter().any(|existing| {
            Self::pending_identity(existing) == app_identity
                && existing.dst_ip == app.dst_ip
                && existing.dst_port == app.dst_port
                && existing.protocol == app.protocol
                && existing.reason == app.reason
        }) {
            return false;
        }

        pending.push_back(app);
        true
    }

    fn with_queue_state(&self, mut app: PendingApp) -> PendingApp {
        let queued_after_active = self.pending.read().unwrap().len();
        let total = queued_after_active.saturating_add(1);
        let idx = self.view_index.load(Ordering::Relaxed) as usize;
        app.queue_position = (idx % total) + 1;
        app.queue_total = total;
        app
    }

    fn reset_view_index(&self) {
        self.view_index.store(0, Ordering::Relaxed);
    }

    pub fn get_active_alert(&self) -> Option<PendingApp> {
        let active = self.active_alert.read().unwrap().clone();
        active.map(|app| self.with_queue_state(app))
    }

    /// Rotate to the next or previous queued alert and immediately promote it
    /// to active so the caller can emit the event without waiting for the
    /// monitor thread's next polling cycle.  Returns the new active alert (with
    /// queue position/total filled in) or None when there is nothing to rotate
    /// (e.g. only one alert in the queue).
    pub fn rotate_alerts(&self, forward: bool) -> Option<PendingApp> {
        let mut active_lock = self.active_alert.write().unwrap();
        if let Some(current) = active_lock.take() {
            let mut pending_lock = self.pending.write().unwrap();
            if forward {
                // Next: Current goes to the back
                pending_lock.push_back(current);
            } else {
                // Prev: Current goes to the front, and the one from the back comes to the front
                pending_lock.push_front(current);
                if let Some(last) = pending_lock.pop_back() {
                    pending_lock.push_front(last);
                }
            }
            // Immediately promote the new front item so active_alert is never
            // None for longer than this critical section.  This prevents the
            // monitor thread from racing on an empty active slot and ensures
            // rapid repeated clicks still rotate correctly.
            if let Some(next) = pending_lock.pop_front() {
                let queue_total = pending_lock.len().saturating_add(1);
                // Update the view index so the position counter advances correctly.
                // Uses modular arithmetic that works for both directions.
                let old_idx = self.view_index.load(Ordering::Relaxed) as usize;
                let new_idx = if forward {
                    (old_idx + 1) % queue_total
                } else {
                    (old_idx + queue_total - 1) % queue_total
                };
                self.view_index.store(new_idx as u64, Ordering::Relaxed);
                let position = new_idx + 1;
                *active_lock = Some(next.clone());
                drop(pending_lock);
                let mut result = next;
                result.queue_position = position;
                result.queue_total = queue_total;
                return Some(result);
            }
        }
        None
    }
}

// ============================================================================
// TRANSPARENT NAT TABLE — maps client connections to their original destinations
// ============================================================================

/// Key: client source port (unique per connection on the local machine).
/// Value: (original_dst_ip, original_dst_port).
/// Used to reverse-NAT inbound packets from the proxy back to the original IP
/// so the client's TCP stack accepts them.
#[derive(Clone)]
pub struct TransparentNatTable {
    inner: Arc<std::sync::RwLock<HashMap<u16, (IpAddr, u16, IpAddr)>>>,
}

impl TransparentNatTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, client_src_port: u16, original_dst: (IpAddr, u16, IpAddr)) {
        self.inner
            .write()
            .unwrap()
            .insert(client_src_port, original_dst);
    }

    pub fn get(&self, client_src_port: u16) -> Option<(IpAddr, u16, IpAddr)> {
        self.inner.read().unwrap().get(&client_src_port).copied()
    }

    pub fn remove(&self, client_src_port: u16) {
        self.inner.write().unwrap().remove(&client_src_port);
    }

    /// Prune stale entries — call periodically.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }
}

// ── IPv4 + TCP header rewrite helpers for transparent proxy NAT ─────────────

/// Rewrite the destination IPv4 address and TCP port in a raw packet.
/// Returns true if the rewrite was performed (IPv4 + TCP with enough bytes).
fn nat_rewrite_dst_ipv4(data: &mut [u8], new_ip: Ipv4Addr, new_port: u16) -> bool {
    if data.len() < 20 {
        return false;
    }
    let ip_version = (data[0] >> 4) & 0x0F;
    if ip_version != 4 {
        return false;
    }
    // Protocol must be TCP (6)
    if data[9] != 6 {
        return false;
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if data.len() < ihl + 4 {
        return false;
    }
    // Overwrite dst IP (bytes 16..20)
    let octets = new_ip.octets();
    data[16] = octets[0];
    data[17] = octets[1];
    data[18] = octets[2];
    data[19] = octets[3];
    // Overwrite dst port (bytes ihl+2..ihl+4)
    let port_bytes = new_port.to_be_bytes();
    data[ihl + 2] = port_bytes[0];
    data[ihl + 3] = port_bytes[1];
    true
}

/// Rewrite the source IPv4 address and TCP port in a raw packet.
/// Used for reverse-NAT on inbound packets from the proxy.
fn nat_rewrite_src_ipv4(data: &mut [u8], new_ip: Ipv4Addr, new_port: u16) -> bool {
    if data.len() < 20 {
        return false;
    }
    let ip_version = (data[0] >> 4) & 0x0F;
    if ip_version != 4 {
        return false;
    }
    if data[9] != 6 {
        return false;
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if data.len() < ihl + 4 {
        return false;
    }
    // Overwrite src IP (bytes 12..16)
    let octets = new_ip.octets();
    data[12] = octets[0];
    data[13] = octets[1];
    data[14] = octets[2];
    data[15] = octets[3];
    // Overwrite src port (bytes ihl..ihl+2)
    let port_bytes = new_port.to_be_bytes();
    data[ihl] = port_bytes[0];
    data[ihl + 1] = port_bytes[1];
    true
}

// ── IPv6 + TCP header rewrite helpers for transparent proxy NAT ─────────────

/// Rewrite the destination IPv6 address and TCP port in a raw packet.
fn nat_rewrite_dst_ipv6(data: &mut [u8], new_ip: std::net::Ipv6Addr, new_port: u16) -> bool {
    if data.len() < 40 {
        return false;
    }
    let ip_version = (data[0] >> 4) & 0x0F;
    if ip_version != 6 {
        return false;
    }
    // Protocol (Next Header) must be TCP (6)
    if data[6] != 6 {
        return false;
    }
    if data.len() < 44 {
        return false;
    }
    // Overwrite dst IP (bytes 24..40)
    let octets = new_ip.octets();
    data[24..40].copy_from_slice(&octets);
    // Overwrite dst port (bytes 42..44)
    let port_bytes = new_port.to_be_bytes();
    data[42] = port_bytes[0];
    data[43] = port_bytes[1];
    true
}

/// Rewrite the source IPv6 address and TCP port in a raw packet.
fn nat_rewrite_src_ipv6(data: &mut [u8], new_ip: std::net::Ipv6Addr, new_port: u16) -> bool {
    if data.len() < 40 {
        return false;
    }
    let ip_version = (data[0] >> 4) & 0x0F;
    if ip_version != 6 {
        return false;
    }
    // Next Header must be TCP (6)
    if data[6] != 6 {
        return false;
    }
    if data.len() < 42 {
        return false;
    }
    // Overwrite src IP (bytes 8..24)
    let octets = new_ip.octets();
    data[8..24].copy_from_slice(&octets);
    // Overwrite src port (bytes 40..42)
    let port_bytes = new_port.to_be_bytes();
    data[40] = port_bytes[0];
    data[41] = port_bytes[1];
    true
}

/// Check if the TCP FIN or RST flag is set (connection teardown).
fn tcp_is_fin_or_rst(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let ip_version = (data[0] >> 4) & 0x0F;
    match ip_version {
        4 => {
            if data.len() < 20 {
                return false;
            }
            if data[9] != 6 {
                return false;
            }
            let ihl = ((data[0] & 0x0F) as usize) * 4;
            if data.len() < ihl + 14 {
                return false;
            }
            let flags = data[ihl + 13];
            // FIN = 0x01, RST = 0x04
            (flags & 0x01) != 0 || (flags & 0x04) != 0
        }
        6 => {
            if data.len() < 40 {
                return false;
            }
            if data[6] != 6 {
                return false;
            }
            let tcp_header_start = 40;
            if data.len() < tcp_header_start + 14 {
                return false;
            }
            let flags = data[tcp_header_start + 13];
            // FIN = 0x01, RST = 0x04
            (flags & 0x01) != 0 || (flags & 0x04) != 0
        }
        _ => false,
    }
}

// ============================================================================
// PACKET PROCESSING RESULT - Using raw bytes for cross-thread safety
// ============================================================================
#[allow(dead_code)]
struct PacketDecision {
    packet_data: Vec<u8>,
    address_data: Vec<u8>, // Serialized address for cross-thread safety
    should_forward: bool,
    recalc_checksums: bool,
    _reason: String,
}

pub struct FirewallEngine {
    pub stats: Arc<Statistics>,
    pub rules: Arc<RwLock<Vec<FirewallRule>>>,
    pub dns_handler: Arc<DnsHandler>,
    pub app_manager: Arc<AppManager>,
    pub web_filter: Arc<WebFilter>,
    pub settings: Arc<RwLock<FirewallSettings>>,
    pub stop_signal: Arc<AtomicBool>,
    pub sdk: Arc<RwLock<crate::sdk::SdkRegistry>>,
    pub file_checker: Arc<FileMagicChecker>,
    pub tls_proxy_backend_child: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    pub windows_root_trust_ready: Arc<AtomicBool>,
    pub firefox_policy_ready: Arc<AtomicBool>,
    pub browser_mitm_warning_cache: Arc<Mutex<HashSet<String>>>,
    network_whitelist_index: Arc<RwLock<CidrIndex>>,
    /// Retained so stop() can call shutdown() and unblock all recv() threads.
    pub divert_handle: Arc<Mutex<Option<WinDivertArc<windivert::prelude::NetworkLayer>>>>,
    pub hydranet_tx: Arc<Mutex<Option<std::sync::mpsc::Sender<String>>>>,
    /// Transparent NAT table for WinDivert-based TLS proxy redirection.
    pub nat_table: TransparentNatTable,
}

// RADICAL REFACTOR: Wrapper to make WinDivert Send + Sync (Safe for WinDivert handles)
pub struct WinDivertArc<L: windivert::layer::WinDivertLayerTrait>(pub Arc<WinDivert<L>>);
unsafe impl<L: windivert::layer::WinDivertLayerTrait> Send for WinDivertArc<L> {}
unsafe impl<L: windivert::layer::WinDivertLayerTrait> Sync for WinDivertArc<L> {}
impl<L: windivert::layer::WinDivertLayerTrait> Clone for WinDivertArc<L> {
    fn clone(&self) -> Self {
        WinDivertArc(Arc::clone(&self.0))
    }
}
impl<L: windivert::layer::WinDivertLayerTrait> std::ops::Deref for WinDivertArc<L> {
    type Target = WinDivert<L>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl FirewallEngine {
    pub fn new() -> Self {
        let stats = Arc::new(Statistics::default());
        let dns_handler = Arc::new(DnsHandler::new());
        let web_filter = Arc::new(WebFilter::new());
        let stop_signal = Arc::new(AtomicBool::new(false));
        let file_checker = Arc::new(FileMagicChecker::new());

        let settings_data = Self::load_settings().unwrap_or_default();

        // Default allow rules are now handled in Default impl or loaded from disk.
        // We do NOT hardcode them here to allow user to override/remove them.

        let network_whitelist_index = Arc::new(RwLock::new(CidrIndex::from_cidrs(
            &settings_data.network_whitelist,
        )));
        let app_decisions = settings_data.app_decisions.clone();
        let app_manager = Arc::new(AppManager::new(app_decisions));
        *app_manager.allow_unknown_apps.write().unwrap() = settings_data.allow_unknown_apps;
        let rules = Arc::new(RwLock::new(settings_data.rules.clone()));
        let settings = Arc::new(RwLock::new(settings_data));
        let sdk = Arc::new(RwLock::new(crate::sdk::SdkRegistry::with_defaults()));
        let tls_proxy_backend_child = Arc::new(Mutex::new(None));
        let windows_root_trust_ready = Arc::new(AtomicBool::new(false));
        let firefox_policy_ready = Arc::new(AtomicBool::new(false));
        let browser_mitm_warning_cache = Arc::new(Mutex::new(HashSet::new()));
        let divert_handle = Arc::new(Mutex::new(None));
        let hydranet_tx = Arc::new(Mutex::new(None));
        let nat_table = TransparentNatTable::new();

        Self {
            stats,
            rules,
            dns_handler,
            app_manager,
            web_filter,
            settings,
            stop_signal,
            sdk,
            file_checker,
            tls_proxy_backend_child,
            windows_root_trust_ready,
            firefox_policy_ready,
            browser_mitm_warning_cache,
            network_whitelist_index,
            divert_handle,
            hydranet_tx,
            nat_table,
        }
    }

    pub fn load_settings() -> Option<FirewallSettings> {
        let path = PathBuf::from("json/settings.json");
        fs::read_to_string(&path).ok()
            .and_then(|content| serde_json::from_str::<FirewallSettings>(&content).ok())
    }

    pub fn apply_settings(&self, new_settings: FirewallSettings) {
        let new_network_whitelist_index = CidrIndex::from_cidrs(&new_settings.network_whitelist);

        // Sync App Decisions
        {
            let mut decisions = self.app_manager.decisions.write().unwrap();
            *decisions = new_settings.app_decisions.clone();
        }

        // Sync allow-unknown-apps flag
        {
            let mut allow_unknown = self.app_manager.allow_unknown_apps.write().unwrap();
            *allow_unknown = new_settings.allow_unknown_apps;
        }

        // Sync Rules
        {
            let mut rules = self.rules.write().unwrap();
            *rules = new_settings.rules.clone();
        }

        // Sync Core Settings
        {
            let mut settings = self.settings.write().unwrap();
            *settings = new_settings;
        }

        {
            let mut network_whitelist_index = self.network_whitelist_index.write().unwrap();
            *network_whitelist_index = new_network_whitelist_index;
        }
    }

    fn proxy_addr_string(tls_proxy: &TlsProxyConfig) -> String {
        format!("{}:{}", tls_proxy.listen_host, tls_proxy.listen_port)
    }

    fn normalize_proxy_bypass_entry(entry: &str) -> Option<String> {
        let trimmed = entry.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            return None;
        }

        let without_scheme = trimmed
            .split_once("://")
            .map(|(_, remainder)| remainder)
            .unwrap_or(trimmed);
        let host_port = without_scheme
            .split(['/', '\\', '?', '#'])
            .next()
            .unwrap_or(without_scheme)
            .trim();
        let cleaned = host_port.trim_start_matches('.');

        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned.to_string())
        }
    }

    fn proxy_bypass_entry_matches_target(entry: &str, target: &str) -> bool {
        let entry_lower = entry.to_ascii_lowercase();
        let target_lower = target.to_ascii_lowercase();

        if entry_lower == target_lower {
            return true;
        }

        if let Some(suffix) = entry_lower.strip_prefix("*.") {
            return target_lower == suffix || target_lower.ends_with(&format!(".{}", suffix));
        }

        if let Some(suffix) = entry_lower.strip_prefix('*') {
            return target_lower.ends_with(suffix);
        }

        !entry_lower.contains(':') && target_lower.ends_with(&format!(".{}", entry_lower))
    }

    fn select_proxy_bypass_target(
        hostname: Option<&str>,
        full_url: Option<&str>,
        bypass_target: Option<&str>,
    ) -> Option<String> {
        hostname
            .and_then(Self::normalize_proxy_bypass_entry)
            .or_else(|| full_url.and_then(Self::normalize_proxy_bypass_entry))
            .or_else(|| bypass_target.and_then(Self::normalize_proxy_bypass_entry))
    }

    fn proxy_bypass_matches_target(
        tls_proxy: &TlsProxyConfig,
        hostname: Option<&str>,
        full_url: Option<&str>,
        bypass_target: Option<&str>,
    ) -> bool {
        let Some(target) = Self::select_proxy_bypass_target(hostname, full_url, bypass_target)
        else {
            return false;
        };

        tls_proxy.bypass_hosts.iter().any(|entry| {
            Self::normalize_proxy_bypass_entry(entry).is_some_and(|normalized| {
                Self::proxy_bypass_entry_matches_target(&normalized, &target)
            })
        })
    }

    fn select_proxy_bypass_host(alert: &PendingApp) -> Option<String> {
        Self::select_proxy_bypass_target(
            alert.hostname.as_deref(),
            alert.full_url.as_deref(),
            alert.target.as_deref(),
        )
    }

    fn wait_for_proxy_listener(addr: std::net::SocketAddr, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let test_addr = if addr.ip().is_unspecified() || addr.ip().is_loopback() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                addr.port(),
            )
        } else {
            addr
        };
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect_timeout(&test_addr, Duration::from_millis(250)).is_ok()
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn add_proxy_bypass_host<R: Runtime>(&self, tx: &AppHandle<R>, host: &str) -> bool {
        let Some(normalized) = Self::normalize_proxy_bypass_entry(host) else {
            return false;
        };

        let tls_proxy_cfg = {
            let mut settings = self.settings.write().unwrap();
            if settings.tls_proxy.bypass_hosts.iter().any(|existing| {
                Self::normalize_proxy_bypass_entry(existing).is_some_and(|normalized_existing| {
                    normalized_existing.eq_ignore_ascii_case(&normalized)
                })
            }) {
                return false;
            }

            settings.tls_proxy.bypass_hosts.push(normalized.clone());
            settings.tls_proxy.clone()
        };

        if tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy && tls_proxy_cfg.auto_start {
            let now = Self::now_ts();
            emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-proxy-bypass-added", now),
                    timestamp: now,
                    level: LogLevel::Info,
                    message: format!(
                        "TLS proxy bypass saved for {}; Windows proxy settings are left unchanged",
                        normalized
                    ),
                },
            );
        }

        true
    }

    fn maybe_emit_browser_mitm_warning<R: Runtime>(
        tx: &AppHandle<R>,
        am: &Arc<AppManager>,
        no_alert_mode: bool,
        tls_proxy: &TlsProxyConfig,
        browser_name: &str,
        browser_path: &str,
        pid: u32,
        hostname: Option<&str>,
        full_url: Option<&str>,
        fallback_target: &str,
        windows_root_trust_ready: &Arc<AtomicBool>,
        firefox_policy_ready: &Arc<AtomicBool>,
        browser_mitm_warning_cache: &Arc<Mutex<HashSet<String>>>,
    ) {
        if !is_known_browser_process(browser_name)
            || Self::proxy_bypass_matches_target(
                tls_proxy,
                hostname,
                full_url,
                Some(fallback_target),
            )
        {
            return;
        }

        let family = browser_family(browser_name);
        let trust_ready = if family == "firefox" {
            firefox_policy_ready.load(Ordering::SeqCst)
        } else {
            windows_root_trust_ready.load(Ordering::SeqCst)
        };

        if trust_ready {
            return;
        }

        let target = Self::select_proxy_bypass_target(hostname, full_url, Some(fallback_target))
            .unwrap_or_else(|| fallback_target.to_string());
        let decision_key = browser_mitm_prompt_decision_key(browser_name, &target);

        match am.get_decision(&decision_key) {
            Some(AppDecision::Allow) => return,
            Some(AppDecision::AllowOnce) => {
                am.remove_decision(&decision_key.to_lowercase());
                return;
            }
            _ => {}
        }

        let cache_key = format!(
            "{}|{}|{}|{}",
            browser_name.to_ascii_lowercase(),
            pid,
            family,
            target.to_ascii_lowercase()
        );

        {
            let mut cache = browser_mitm_warning_cache.lock().unwrap();
            if !cache.insert(cache_key) {
                return;
            }
        }

        let trust_text = if family == "firefox" {
            "Firefox enterprise trust policy is not ready"
        } else {
            "Windows root trust is not ready"
        };

        let now = Self::now_ts();
        emit_log_event(
            tx,
            LogEntry {
                id: format!("{}-browser-mitm-warning-{}", now, pid),
                timestamp: now,
                level: LogLevel::Warning,
                message: format!(
                    "Browser HTTPS interception warning likely for {} on {}: {}. The browser may show {} or a visible TLS interception/certificate warning until the proxy trust is accepted or the site is trusted without TLS interception. This may also trigger other antivirus or security products even if the interception is hidden.",
                    browser_name,
                    target,
                    trust_text,
                    browser_mitm_error_hint(browser_name),
                ),
            },
        );

        if family == "firefox" && !no_alert_mode {
            let enqueued = am.enqueue_pending_app(
                PendingApp {
                    process_id: pid,
                    name: browser_name.to_string(),
                    path: browser_path.to_string(),
                    dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    dst_port: tls_proxy.listen_port,
                    protocol: Protocol::TCP,
                    hostname: hostname.map(|value| value.to_string()),
                    reason: Some(format!(
                        "{} is rejecting or warning on HTTPS interception for {} because {}. This can be benign browser trust behavior or specific anti-interception logic. Choose ALLOW TLS PROXY to keep interception enabled, ALLOW TLS PROXY ONCE for a one-time retry, or BYPASS TLS PROXY to bypass interception for this target.",
                        browser_name,
                        target,
                        trust_text
                    )),
                    request_id: None,
                    alert_source: Some("browser_mitm".to_string()),
                    alert_kind: Some("browser_mitm_prompt".to_string()),
                    target: Some(target.clone()),
                    decision_key: Some(decision_key),
                    full_url: full_url.map(|value| value.to_string()),
                    http_method: None,
                    http_path: None,
                    http_user_agent: None,
                    http_content_type: None,
                    http_referer: None,
                    http_request_body: None,
                    http_response_body: None,
                    payload_sample: None,
                    detected_file_type: None,
                    packet_json: None,
                    queue_position: 1,
                    queue_total: 1,
                },
                false,
            );
            if enqueued {
                Self::refresh_active_alert_ui(am, tx);
            }
        }
    }

    pub fn sync_proxy_runtime<R: Runtime>(&self, tx: &AppHandle<R>) {
        let tls_proxy_cfg = {
            let settings = self.settings.read().unwrap();
            settings.tls_proxy.clone()
        };

        if self.stop_signal.load(Ordering::SeqCst) {
            self.stop_embedded_proxy();
            return;
        }

        if tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy && tls_proxy_cfg.auto_start {
            self.start_embedded_proxy(&tls_proxy_cfg, tx);
        } else {
            self.stop_embedded_proxy();
        }
    }

    pub fn save_settings(&self) {
        let current_settings = self.settings.read().unwrap().clone();

        // Filter out one-time and unresolved identities so only stable trusts persist.
        let mut decisions = self.app_manager.decisions.read().unwrap().clone();
        decisions.retain(|key, value| {
            *value != AppDecision::AllowOnce && !is_unresolved_identity(key.as_str())
        });

        let settings = FirewallSettings {
            app_decisions: decisions,
            kernel_block_paths: current_settings.kernel_block_paths.clone(),
            website_path: current_settings.website_path.clone(),
            rules: self.rules.read().unwrap().clone(),
            late_blocking_mode: current_settings.late_blocking_mode,
            headless_mode: current_settings.headless_mode,
            log_mode: current_settings.log_mode,
            show_blocked_logs_only: current_settings.show_blocked_logs_only,
            show_blocked_graphics_only: current_settings.show_blocked_graphics_only,
            show_blocked_http_inspector_only: current_settings.show_blocked_http_inspector_only,
            no_alert_mode: current_settings.no_alert_mode,
            save_all_logs: current_settings.save_all_logs,
            prune_old_logs: current_settings.prune_old_logs,
            max_visible_logs: current_settings.max_visible_logs,
            prune_http_history: current_settings.prune_http_history,
            max_visible_http_events: current_settings.max_visible_http_events,
            log_full_bodies: current_settings.log_full_bodies,
            tls_proxy: current_settings.tls_proxy.clone(),
            network_whitelist: current_settings.network_whitelist.clone(),
            metadata: current_settings.metadata.clone(),
            allow_unknown_apps: current_settings.allow_unknown_apps,
        };

        {
            let mut live_settings = self.settings.write().unwrap();
            live_settings.app_decisions = settings.app_decisions.clone();
        }

        if let Ok(content) = serde_json::to_string_pretty(&settings) {
            let _ = fs::create_dir_all("json");
            let _ = fs::write("json/settings.json", content);
        }
    }

    pub fn is_loopback(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    fn is_proxy_host(ip: IpAddr, tls_proxy: &TlsProxyConfig) -> bool {
        if tls_proxy.listen_host.eq_ignore_ascii_case("localhost")
            || tls_proxy.listen_host == "127.0.0.1"
            || tls_proxy.listen_host == "::1"
        {
            return Self::is_loopback(ip);
        }

        match tls_proxy.listen_host.parse::<IpAddr>() {
            Ok(proxy_ip) => ip == proxy_ip,
            Err(_) => Self::is_loopback(ip),
        }
    }

    fn is_proxy_destination(info: &PacketInfo, tls_proxy: &TlsProxyConfig) -> bool {
        if !matches!(info.protocol, Protocol::TCP) {
            return false;
        }

        if info.dst_port != tls_proxy.listen_port {
            return false;
        }

        Self::is_proxy_host(info.dst_ip, tls_proxy)
    }

    fn is_proxy_listener_flow(info: &PacketInfo, tls_proxy: &TlsProxyConfig) -> bool {
        if !matches!(info.protocol, Protocol::TCP) {
            return false;
        }

        (info.dst_port == tls_proxy.listen_port && Self::is_proxy_host(info.dst_ip, tls_proxy))
            || (info.src_port == tls_proxy.listen_port
                && Self::is_proxy_host(info.src_ip, tls_proxy))
    }

    fn enforce_tls_proxy_mode(
        info: &PacketInfo,
        outbound: bool,
        tls_proxy: &TlsProxyConfig,
        should_forward: &mut bool,
        reason: &mut Option<String>,
    ) {
        if tls_proxy.mode != TlsInspectionMode::TlsProxy || !outbound || !*should_forward {
            return;
        }

        // Block QUIC/UDP:443 — the embedded http-mitm-proxy handles TCP only.
        if matches!(info.protocol, Protocol::UDP)
            && info.dst_port == 443
            && tls_proxy.block_quic_udp_443
        {
            *should_forward = false;
            // Always override reason — get_or_insert_with would silently retain a
            // stale "App Allowed: <name>" reason from the app-decision step and
            // make firewall activity logs misleading.
            *reason = Some(
                "Transparent TLS Proxy mode: blocked QUIC (UDP/443); the local proxy handles TCP only"
                    .to_string(),
            );
        }
    }

    fn is_tls_proxy_intercept_candidate(
        info: &PacketInfo,
        outbound: bool,
        tls_proxy: &TlsProxyConfig,
    ) -> bool {
        tls_proxy.mode == TlsInspectionMode::TlsProxy
            && outbound
            && matches!(info.protocol, Protocol::TCP)
            && info.dst_port == 443
            && info.process_id != std::process::id()
            && !http_mitm_proxy::is_registered_upstream_local_port(info.src_port)
            && !Self::is_loopback(info.dst_ip)
            && !info.dst_ip.is_unspecified()
            && !info.dst_ip.is_multicast()
            && !Self::is_proxy_listener_flow(info, tls_proxy)
    }

    fn emit_tls_proxy_intercept_probe(
        tx: &AppHandle,
        am: &Arc<AppManager>,
        dns_handler: &Arc<DnsHandler>,
        info: &PacketInfo,
        tls_proxy: &TlsProxyConfig,
        no_alert_mode: bool,
        windows_root_trust_ready: &Arc<AtomicBool>,
        firefox_policy_ready: &Arc<AtomicBool>,
        browser_mitm_warning_cache: &Arc<Mutex<HashSet<String>>>,
    ) {
        if Self::proxy_bypass_matches_target(
            tls_proxy,
            info.hostname.as_deref(),
            info.full_url.as_deref(),
            None,
        ) {
            return;
        }

        let host_label = info
            .hostname
            .clone()
            .or_else(|| dns_handler.resolve_ip(&info.dst_ip.to_string()))
            .unwrap_or_else(|| info.dst_ip.to_string());
        let full_url = info
            .full_url
            .clone()
            .unwrap_or_else(|| format!("https://{}:{}/", host_label, info.dst_port));
        let app_info = am.info_cache.get_info(info.process_id);

        Self::maybe_emit_browser_mitm_warning(
            tx,
            am,
            no_alert_mode,
            tls_proxy,
            &app_info.name,
            &app_info.path,
            info.process_id,
            Some(&host_label),
            Some(&full_url),
            &host_label,
            windows_root_trust_ready,
            firefox_policy_ready,
            browser_mitm_warning_cache,
        );

        let cache_key = format!(
            "proxy-http:{}:{}:{}:{}:{}",
            info.process_id,
            info.src_ip,
            info.src_port,
            host_label.to_ascii_lowercase(),
            info.dst_port
        );
        {
            let mut cache = browser_mitm_warning_cache.lock().unwrap();
            if !cache.insert(cache_key) {
                return;
            }
        }

        let now = Self::now_ts();
        emit_log_event(
            tx,
            LogEntry {
                id: format!("{}-proxy-intercept-{}", now, info.process_id),
                timestamp: now,
                level: LogLevel::Info,
                message: format!(
                    "Proxy Intercept: {} (pid={}) -> {}:{} via transparent TLS proxy {}",
                    app_info.name,
                    info.process_id,
                    host_label,
                    info.dst_port,
                    Self::proxy_addr_string(tls_proxy)
                ),
            },
        );
    }

    fn start_embedded_proxy<R: Runtime>(&self, tls_proxy: &TlsProxyConfig, tx: &AppHandle<R>) {
        if tls_proxy.mode != TlsInspectionMode::TlsProxy || !tls_proxy.auto_start {
            return;
        }

        // Already running?
        if self.tls_proxy_backend_child.lock().unwrap().is_some() {
            return;
        }

        let listen_port = tls_proxy.listen_port;
        // CRITICAL FIX: Only spawn ONE proxy listener instead of two conflicting ones
        let addr_v4: std::net::SocketAddr = format!("127.0.0.1:{}", listen_port)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:8877".parse().unwrap());
        let addr_string = format!("127.0.0.1:{}", listen_port);

        let ca_bundle = crate::proxy::generate_ca();

        // Check if user has consented to certificate installation
        if tls_proxy.cert_install_consent {
            // Install the generated CA into Windows Trusted Root so browsers accept it.
            match Self::install_ca_der(&ca_bundle.cert_der) {
                Ok(()) => {
                    self.windows_root_trust_ready.store(true, Ordering::SeqCst);
                    let now = Self::now_ts();
                    emit_log_event(
                        &tx,
                        LogEntry {
                            id: format!("{}-ca-installed", now),
                            timestamp: now,
                            level: LogLevel::Success,
                            message: "Certificate installed to Windows Root Trust Store with user consent.".to_string(),
                        },
                    );
                }
                Err(e) => {
                    self.windows_root_trust_ready.store(false, Ordering::SeqCst);
                    let now = Self::now_ts();
                    emit_log_event(
                        &tx,
                        LogEntry {
                            id: format!("{}-ca-install-failed", now),
                            timestamp: now,
                            level: LogLevel::Error,
                            message: format!(
                                "Certificate installation failed (run as admin): {}. Browsers will show certificate warnings. Manual installation: Open certmgr.msc, import '{}' to Trusted Root Certification Authorities.",
                                e,
                                Self::proxy_ca_cert_path().display()
                            ),
                        },
                    );
                }
            }

            let firefox_ca_path = Self::proxy_ca_cert_path();
            match Self::install_firefox_ca_policy(&firefox_ca_path) {
                Ok(()) => {
                    self.firefox_policy_ready.store(true, Ordering::SeqCst);
                    let now = Self::now_ts();
                    emit_log_event(
                        &tx,
                        LogEntry {
                            id: format!("{}-firefox-policy-installed", now),
                            timestamp: now,
                            level: LogLevel::Success,
                            message: "Firefox enterprise policy configured with user consent."
                                .to_string(),
                        },
                    );
                }
                Err(e) => {
                    self.firefox_policy_ready.store(false, Ordering::SeqCst);
                    let now = Self::now_ts();
                    emit_log_event(
                        &tx,
                        LogEntry {
                            id: format!("{}-firefox-policy-failed", now),
                            timestamp: now,
                            level: LogLevel::Error,
                            message: format!(
                                "Firefox policy setup failed: {}. Firefox will show SEC_ERROR_UNKNOWN_ISSUER. Manual fix: Import '{}' in Firefox Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import.",
                                e,
                                firefox_ca_path.display()
                            ),
                        },
                    );
                }
            }
        } else {
            // User has not consented - do not install certificates
            self.windows_root_trust_ready.store(false, Ordering::SeqCst);
            self.firefox_policy_ready.store(false, Ordering::SeqCst);
            let now = Self::now_ts();
            emit_log_event(
                &tx,
                LogEntry {
                    id: format!("{}-cert-consent-required", now),
                    timestamp: now,
                    level: LogLevel::Warning,
                    message: format!(
                        "Certificate installation requires user consent. The Transparent TLS Proxy will start but browsers will show certificate warnings until you grant consent in settings. Certificate location: '{}'",
                        Self::proxy_ca_cert_path().display()
                    ),
                },
            );
        }

        let (stop_tx_main, stop_rx_main) = oneshot::channel::<()>();

        *self.tls_proxy_backend_child.lock().unwrap() = Some(stop_tx_main);
        self.browser_mitm_warning_cache.lock().unwrap().clear();

        let app = tx.clone();
        let sdk = self.sdk.clone();
        let settings = self.settings.clone();

        let ca_bundle = crate::proxy::generate_ca();
        tauri::async_runtime::spawn(crate::proxy::run_proxy(
            addr_v4,
            ca_bundle.issuer,
            app,
            sdk,
            settings,
            stop_rx_main,
        ));

        let tx_ready = tx.clone();
        let proxy_runtime = self.tls_proxy_backend_child.clone();
        std::thread::Builder::new()
            .name("proxy_ready_waiter".to_string())
            .spawn(move || {
                let listener_ready = Self::wait_for_proxy_listener(addr_v4, Duration::from_secs(5));
                let still_running = proxy_runtime.lock().unwrap().is_some();
                if !still_running {
                    return;
                }

                let now = Self::now_ts();
                if listener_ready {
                    emit_log_event(
                        &tx_ready,
                        LogEntry {
                            id: format!("{}-proxy-ready", now),
                            timestamp: now,
                            level: LogLevel::Success,
                            message: format!(
                                "Transparent TLS Proxy/Inspector ready on {}; Windows proxy settings left unchanged",
                                addr_string
                            ),
                        },
                    );
                } else {
                    emit_log_event(
                        &tx_ready,
                        LogEntry {
                            id: format!("{}-proxy-not-ready", now),
                            timestamp: now,
                            level: LogLevel::Warning,
                            message: format!(
                                "Transparent TLS Proxy/Inspector did not become ready on {} - Windows proxy was left disabled to avoid breaking internet access",
                                addr_string
                            ),
                        },
                    );
                }
            })
            .expect("failed to spawn proxy_ready_waiter");
    }

    fn stop_embedded_proxy(&self) {
        self.browser_mitm_warning_cache.lock().unwrap().clear();
    }

    fn proxy_ca_cert_path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("hydradragon_ca.der")
    }

    fn install_firefox_ca_policy(cert_path: &Path) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            use winreg::RegKey;
            use winreg::enums::*;

            let cert_path_string = cert_path.to_string_lossy().to_string();
            let write_policy = |root: RegKey| -> Result<(), String> {
                let (certs_key, _) = root
                    .create_subkey(r"Software\Policies\Mozilla\Firefox\Certificates")
                    .map_err(|e| e.to_string())?;
                certs_key
                    .set_value("ImportEnterpriseRoots", &1u32)
                    .map_err(|e| e.to_string())?;

                let (install_key, _) = root
                    .create_subkey(r"Software\Policies\Mozilla\Firefox\Certificates\Install")
                    .map_err(|e| e.to_string())?;
                install_key
                    .set_value("1", &cert_path_string)
                    .map_err(|e| e.to_string())?;
                Ok(())
            };

            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            write_policy(hkcu)?;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let _ = write_policy(hklm);

            return Ok(());
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    /// Install a raw DER certificate into the Windows LocalMachine\Root trust store.
    fn install_ca_der(der: &[u8]) -> Result<(), String> {
        use windows::Win32::Security::Cryptography::{
            CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, CertAddEncodedCertificateToStore,
            CertCloseStore, CertOpenSystemStoreA, X509_ASN_ENCODING,
        };
        use windows::core::PCSTR;
        unsafe {
            let store = CertOpenSystemStoreA(None, PCSTR(b"ROOT\0".as_ptr()))
                .map_err(|e| format!("CertOpenSystemStoreA: {:?}", e))?;
            let result = CertAddEncodedCertificateToStore(
                Some(store),
                X509_ASN_ENCODING,
                der,
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                None,
            );
            let _ = CertCloseStore(Some(store), 0);
            match result {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("CertAddEncodedCertificateToStore: {:?}", e)),
            }
        }
    }

    fn remove_firewall_ca_from_windows_stores() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let script = r#"
$ErrorActionPreference = "SilentlyContinue"
$stores = @(
  "Cert:\LocalMachine\Root",
  "Cert:\CurrentUser\Root",
  "Cert:\LocalMachine\CA",
  "Cert:\CurrentUser\CA",
  "Cert:\LocalMachine\TrustedPublisher",
  "Cert:\CurrentUser\TrustedPublisher",
  "Cert:\LocalMachine\My",
  "Cert:\CurrentUser\My"
)
foreach ($store in $stores) {
  Get-ChildItem -Path $store |
    Where-Object { $_.Subject -like "*HydraDragon Firewall CA*" } |
    Remove-Item -Force
}
"#;

            let status = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ])
                .status()
                .map_err(|error| {
                    format!("Failed to start PowerShell certificate cleanup: {error}")
                })?;

            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "PowerShell certificate cleanup exited with status {status}"
                ))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(())
        }
    }

    fn remove_firefox_ca_policy(cert_path: &Path) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            use winreg::RegKey;
            use winreg::enums::*;

            let cert_path_string = cert_path.to_string_lossy().to_string();
            let remove_policy = |root: RegKey| -> Result<(), String> {
                if let Ok(install_key) = root.open_subkey_with_flags(
                    r"Software\Policies\Mozilla\Firefox\Certificates\Install",
                    KEY_READ | KEY_WRITE,
                ) {
                    if install_key
                        .get_value::<String, _>("1")
                        .is_ok_and(|value| value.eq_ignore_ascii_case(&cert_path_string))
                    {
                        let _ = install_key.delete_value("1");
                    }
                }
                Ok(())
            };

            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            remove_policy(hkcu)?;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let _ = remove_policy(hklm);

            return Ok(());
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    pub fn install_firewall_certificate<R: Runtime>(
        &self,
        tx: &AppHandle<R>,
    ) -> Result<String, String> {
        let ca_bundle = crate::proxy::generate_ca();
        Self::install_ca_der(&ca_bundle.cert_der)?;
        self.windows_root_trust_ready.store(true, Ordering::SeqCst);

        let cert_path = Self::proxy_ca_cert_path();
        Self::install_firefox_ca_policy(&cert_path)?;
        self.firefox_policy_ready.store(true, Ordering::SeqCst);

        {
            let mut settings = self.settings.write().unwrap();
            settings.tls_proxy.cert_install_consent = true;
        }
        self.save_settings();

        let message =
            "HydraDragon Firewall CA installed into Windows trust and Firefox policy.".to_string();
        emit_log_event(
            tx,
            LogEntry {
                id: format!("{}-certificate-installed-manual", Self::now_ts()),
                timestamp: Self::now_ts(),
                level: LogLevel::Success,
                message: message.clone(),
            },
        );

        Ok(message)
    }

    pub fn remove_firewall_certificate<R: Runtime>(
        &self,
        tx: &AppHandle<R>,
    ) -> Result<String, String> {
        let mut errors = Vec::new();
        if let Err(error) = Self::remove_firewall_ca_from_windows_stores() {
            errors.push(error);
        }
        if let Err(error) = Self::remove_firefox_ca_policy(&Self::proxy_ca_cert_path()) {
            errors.push(error);
        }

        self.windows_root_trust_ready.store(false, Ordering::SeqCst);
        self.firefox_policy_ready.store(false, Ordering::SeqCst);
        {
            let mut settings = self.settings.write().unwrap();
            settings.tls_proxy.cert_install_consent = false;
        }
        self.save_settings();

        if errors.is_empty() {
            let message =
                "HydraDragon Firewall CA removed from trust stores and Firefox policy.".to_string();
            emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-certificate-removed-manual", Self::now_ts()),
                    timestamp: Self::now_ts(),
                    level: LogLevel::Success,
                    message: message.clone(),
                },
            );
            Ok(message)
        } else {
            let message = format!(
                "HydraDragon Firewall CA removal finished with warnings: {}",
                errors.join("; ")
            );
            emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-certificate-remove-warning", Self::now_ts()),
                    timestamp: Self::now_ts(),
                    level: LogLevel::Warning,
                    message: message.clone(),
                },
            );
            Err(message)
        }
    }

    // CA auto-trust is handled natively via `install_ca_der` during proxy startup
    // and can also be controlled manually from the firewall settings UI.

    pub fn send_hydranet_message(&self, message: String) {
        let tx_opt = self.hydranet_tx.lock().unwrap().clone();
        if let Some(tx) = tx_opt {
            let _ = tx.send(message);
        } else {
            eprintln!("[HydraNet] No active pipe writer available for outbound message");
        }
    }

    pub fn request_owlyshield_report(&self) {
        self.send_hydranet_message("GENERATE_REPORT\n".to_string());
    }

    fn remember_kernel_block_path(&self, path: &str) {
        let mut settings = self.settings.write().unwrap();
        if settings
            .kernel_block_paths
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(path))
        {
            return;
        }
        settings.kernel_block_paths.push(path.to_string());
    }

    fn refresh_active_alert_ui<R: Runtime>(am: &Arc<AppManager>, tx: &AppHandle<R>) {
        if let Some(alert) = am.get_active_alert() {
            Self::spawn_alert_window(tx);
            let _ = tx.emit("ask_app_decision", alert);
        }
    }

    pub fn resolve_app_decision(&self, name: String, decision: String, tx: &AppHandle) {
        let active_alert = self.app_manager.active_alert.read().unwrap().clone();
        let mut persist_settings = true;
        let mut effective_decision = decision;
        let kernel_block_path = active_alert.as_ref().and_then(select_kernel_block_path);
        let decision_identifier = active_alert
            .as_ref()
            .and_then(|alert| alert.decision_key.clone())
            .unwrap_or_else(|| name.clone());
        let decision_label = active_alert
            .as_ref()
            .map(|alert| {
                let target = alert
                    .target
                    .as_ref()
                    .filter(|target| !target.trim().is_empty())
                    .cloned();
                let path = if !alert.path.trim().is_empty()
                    && !alert.path.eq_ignore_ascii_case("unknown")
                {
                    Some(alert.path.clone())
                } else {
                    None
                };
                target.or(path).unwrap_or_else(|| alert.name.clone())
            })
            .unwrap_or_else(|| name.clone());

        let missing_stable_path = active_alert
            .as_ref()
            .is_some_and(|alert| is_unresolved_identity(&alert.path));
        let has_configured_decision_key = active_alert
            .as_ref()
            .and_then(|alert| alert.decision_key.as_ref())
            .is_some();

        if effective_decision == "allow_always"
            && missing_stable_path
            && !has_configured_decision_key
        {
            effective_decision = "allow_once".to_string();
            persist_settings = false;
        }

        let routed_to_owlyshield = active_alert
            .as_ref()
            .and_then(|alert| {
                if alert.alert_source.as_deref() == Some("owlyshield") {
                    alert.request_id.as_ref()
                } else {
                    None
                }
            })
            .map(|request_id| {
                let msg = format!(
                    "HIPS_DECISION:{}|{}\n",
                    request_id,
                    effective_decision.as_str()
                );
                self.send_hydranet_message(msg);
            })
            .is_some();

        let app_decision = match effective_decision.as_str() {
            "allow_always" => AppDecision::Allow,
            "allow_always_no_mitm" => AppDecision::Allow,
            "allow_once" => AppDecision::AllowOnce,
            "quarantine" => AppDecision::Block,
            "block" => AppDecision::Block,
            "deny" => AppDecision::Pending,
            _ => AppDecision::Pending,
        };

        if routed_to_owlyshield {
            // Owlyshield owns remediation for its HIPS prompts. Mirroring those
            // decisions into the firewall's own app-decision store can
            // accidentally poison generic names like `svchost.exe` or install
            // unrelated persistent kernel block paths.
            persist_settings = false;
        } else {
            self.app_manager
                .resolve_decision(&decision_identifier, app_decision);
        }

        if !routed_to_owlyshield
            && effective_decision == "block"
            && let Some(path) = kernel_block_path.as_deref()
        {
            self.remember_kernel_block_path(path);
            self.send_hydranet_message(kernel_block_message(path));
        }

        if effective_decision == "allow_always_no_mitm"
            && let Some(alert) = active_alert.as_ref()
            && let Some(host) = Self::select_proxy_bypass_host(alert)
        {
            let _ = self.add_proxy_bypass_host(tx, &host);
        }

        let now = Self::now_ts();
        match effective_decision.as_str() {
            "deny" => emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-user-deny", now),
                    timestamp: now,
                    level: LogLevel::Warning,
                    message: format!(
                        "Blocked: Access denied for {} (no termination requested)",
                        decision_label
                    ),
                },
            ),
            "block" => emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-user-block", now),
                    timestamp: now,
                    level: LogLevel::Warning,
                    message: format!("Blocked: User decision for {}", decision_label),
                },
            ),
            "quarantine" => emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-user-quarantine", now),
                    timestamp: now,
                    level: LogLevel::Warning,
                    message: format!(
                        "Blocked: User decision for {} (quarantine requested)",
                        decision_label
                    ),
                },
            ),
            "allow_always" => emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-user-allow", now),
                    timestamp: now,
                    level: LogLevel::Success,
                    message: format!("Allowed: User decision for {}", decision_label),
                },
            ),
            "allow_always_no_mitm" => emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-user-allow-no-mitm", now),
                    timestamp: now,
                    level: LogLevel::Success,
                    message: format!(
                        "Trusted With TLS Proxy Bypass: User decision for {}",
                        decision_label
                    ),
                },
            ),
            "allow_once" => emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-user-allow-once", now),
                    timestamp: now,
                    level: LogLevel::Success,
                    message: format!("Allowed Once: User decision for {}", decision_label),
                },
            ),
            _ => {}
        }

        if effective_decision == "allow_once" && missing_stable_path && !has_configured_decision_key
        {
            emit_log_event(
                tx,
                LogEntry {
                    id: format!("{}-allow-once-unresolved-path", now),
                    timestamp: now,
                    level: LogLevel::Warning,
                    message: format!(
                        "Persistent trust was not saved for {} because the executable path could not be resolved. Only a one-time allow was applied to avoid broadly trusting other unknown files.",
                        decision_label
                    ),
                },
            );
        }

        // Clear the active alert so it doesn't linger
        {
            let mut active = self.app_manager.active_alert.write().unwrap();
            *active = None;
        }

        if persist_settings {
            self.save_settings();
        }
    }

    pub fn remove_app_decision(&self, name_lower: String) {
        let normalized = name_lower.to_ascii_lowercase();
        self.app_manager.remove_decision(&normalized);
        self.settings
            .write()
            .unwrap()
            .app_decisions
            .remove(&normalized);
        self.save_settings();
    }

    pub fn set_process_decision(
        &self,
        name: String,
        path: String,
        decision: String,
        tx: &AppHandle,
    ) -> Result<String, String> {
        let identifier = normalize_kernel_block_path_candidate(&path)
            .or_else(|| {
                let trimmed = name.trim();
                (!is_unresolved_identity(trimmed)).then(|| trimmed.to_string())
            })
            .ok_or_else(|| "Process identity is unavailable.".to_string())?;

        let app_decision = match decision.as_str() {
            "allow" | "allow_always" => AppDecision::Allow,
            "allow_once" => AppDecision::AllowOnce,
            "block" => AppDecision::Block,
            "pending" => AppDecision::Pending,
            other => return Err(format!("Unsupported process decision: {other}")),
        };

        self.app_manager
            .resolve_decision(&identifier, app_decision.clone());
        self.save_settings();

        let now = Self::now_ts();
        let action_label = match app_decision {
            AppDecision::Allow => "Allowed",
            AppDecision::AllowOnce => "Allowed Once",
            AppDecision::Block => "Blocked",
            AppDecision::Pending => "Set Pending",
        };
        emit_log_event(
            tx,
            LogEntry {
                id: format!("{}-process-decision", now),
                timestamp: now,
                level: if app_decision == AppDecision::Block {
                    LogLevel::Warning
                } else {
                    LogLevel::Success
                },
                message: format!("{action_label}: Process decision for {identifier}"),
            },
        );

        Ok(identifier)
    }

    pub fn clear_app_decisions(&self) {
        self.app_manager.clear_decisions();
        self.settings.write().unwrap().app_decisions.clear();
        self.save_settings();
    }

    pub fn get_active_alert(&self) -> Option<PendingApp> {
        self.app_manager.get_active_alert()
    }

    pub fn next_alert(&self) -> Option<PendingApp> {
        self.app_manager.rotate_alerts(true)
    }

    pub fn previous_alert(&self) -> Option<PendingApp> {
        self.app_manager.rotate_alerts(false)
    }

    pub fn get_app_decisions(&self) -> HashMap<String, AppDecision> {
        self.app_manager
            .decisions
            .read()
            .unwrap()
            .iter()
            .filter(|(key, value)| {
                **value != AppDecision::AllowOnce && !is_unresolved_identity(key.as_str())
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    pub fn get_process_inventory(&self) -> Vec<ProcessInventoryEntry> {
        #[cfg(target_os = "windows")]
        {
            return self.get_process_inventory_windows();
        }

        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }

    pub fn get_settings(&self) -> FirewallSettings {
        self.settings.read().unwrap().clone()
    }

    pub fn get_saved_logs(&self) -> Vec<LogEntry> {
        let settings = self.settings.read().unwrap().clone();
        if !settings.save_all_logs {
            return Vec::new();
        }

        if settings.show_blocked_logs_only {
            return Vec::new();
        }

        let limit = if settings.prune_old_logs {
            Some(settings.max_visible_logs.max(1))
        } else {
            None
        };

        let mut logs = load_saved_logs(limit);

        if settings.show_blocked_logs_only {
            logs.retain(|entry| {
                entry.message.contains("blocked") || entry.message.contains("Blocked")
            });
        }

        logs
    }

    #[cfg(target_os = "windows")]
    fn get_process_inventory_windows(&self) -> Vec<ProcessInventoryEntry> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };

        fn process_name_from_entry(entry: &PROCESSENTRY32W) -> String {
            let len = entry
                .szExeFile
                .iter()
                .position(|ch| *ch == 0)
                .unwrap_or(entry.szExeFile.len());
            String::from_utf16_lossy(&entry.szExeFile[..len])
        }

        fn decision_label(decision: &AppDecision) -> &'static str {
            match decision {
                AppDecision::Allow => "allow",
                AppDecision::Block => "block",
                AppDecision::Pending => "pending",
                AppDecision::AllowOnce => "allow_once",
            }
        }

        let observed_pids: HashSet<u32> = self
            .app_manager
            .info_cache
            .cache
            .read()
            .unwrap()
            .keys()
            .copied()
            .collect();
        let suspicious_pids = self.app_manager.suspicious_pids.read().unwrap().clone();
        let active_alert_pid = self
            .app_manager
            .active_alert
            .read()
            .unwrap()
            .as_ref()
            .map(|alert| alert.process_id);
        let pending_pids: HashSet<u32> = self
            .app_manager
            .pending
            .read()
            .unwrap()
            .iter()
            .map(|alert| alert.process_id)
            .collect();
        let decisions = self.app_manager.decisions.read().unwrap().clone();
        let cloud_trusted_pids = self.app_manager.cloud_trusted_pids.read().unwrap().clone();
        let openedr_verdicts = self.app_manager.openedr_verdicts.read().unwrap().clone();

        let mut processes = Vec::new();
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        let Ok(snapshot) = snapshot else {
            return processes;
        };

        unsafe {
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let fallback_name = process_name_from_entry(&entry);
                    let info = self.app_manager.info_cache.get_info(pid);
                    let name = if !is_unresolved_identity(&info.name) {
                        info.name.clone()
                    } else if !fallback_name.trim().is_empty() {
                        fallback_name
                    } else {
                        "Unknown".to_string()
                    };
                    let path = if !is_unresolved_identity(&info.path) {
                        info.path.clone()
                    } else {
                        name.clone()
                    };
                    let path_lower = path.to_ascii_lowercase();
                    let name_lower = name.to_ascii_lowercase();
                    let decision = decisions
                        .get(&path_lower)
                        .or_else(|| decisions.get(&name_lower))
                        .map(|decision| decision_label(decision).to_string());

                    processes.push(ProcessInventoryEntry {
                        pid,
                        parent_pid: entry.th32ParentProcessID,
                        thread_count: entry.cntThreads,
                        name,
                        path,
                        observed_by_firewall: observed_pids.contains(&pid),
                        suspicious: suspicious_pids.contains(&pid),
                        pending_alert: active_alert_pid == Some(pid) || pending_pids.contains(&pid),
                        decision,
                        cloud_trusted: cloud_trusted_pids.contains(&pid),
                        openedr_verdict: openedr_verdicts.get(&pid).cloned(),
                    });

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        processes.sort_by(|a, b| {
            b.pending_alert
                .cmp(&a.pending_alert)
                .then_with(|| b.suspicious.cmp(&a.suspicious))
                .then_with(|| b.observed_by_firewall.cmp(&a.observed_by_firewall))
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        processes
    }

    /// Resolve PID from port using Windows TCP/UDP extended tables
    pub fn resolve_pid_from_port(port: u16, is_tcp: bool) -> u32 {
        unsafe {
            // TCP lookup
            if is_tcp {
                let mut size: u32 = 0;
                // First call to get buffer size
                let _ = windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable(
                    None,
                    &mut size,
                    false,
                    windows::Win32::Networking::WinSock::AF_INET.0 as u32,
                    windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if size > 0 {
                    let mut buffer = vec![0u8; size as usize];
                    if windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable(
                        Some(buffer.as_mut_ptr() as *mut _),
                        &mut size,
                        false,
                        windows::Win32::Networking::WinSock::AF_INET.0 as u32,
                        windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL,
                        0,
                    ) == 0
                    {
                        let table = buffer.as_ptr() as *const windows::Win32::NetworkManagement::IpHelper::MIB_TCPTABLE_OWNER_PID;
                        let num_entries = (*table).dwNumEntries as usize;
                        let entries =
                            std::slice::from_raw_parts((*table).table.as_ptr(), num_entries);

                        for entry in entries {
                            let local_port = u16::from_be(entry.dwLocalPort as u16);
                            if local_port == port {
                                return entry.dwOwningPid;
                            }
                        }
                    }
                }
            } else {
                // UDP lookup
                let mut size: u32 = 0;
                let _ = windows::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable(
                    None,
                    &mut size,
                    false,
                    windows::Win32::Networking::WinSock::AF_INET.0 as u32,
                    windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_OWNER_PID,
                    0,
                );

                if size > 0 {
                    let mut buffer = vec![0u8; size as usize];
                    if windows::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable(
                        Some(buffer.as_mut_ptr() as *mut _),
                        &mut size,
                        false,
                        windows::Win32::Networking::WinSock::AF_INET.0 as u32,
                        windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_OWNER_PID,
                        0,
                    ) == 0
                    {
                        let table = buffer.as_ptr() as *const windows::Win32::NetworkManagement::IpHelper::MIB_UDPTABLE_OWNER_PID;
                        let num_entries = (*table).dwNumEntries as usize;
                        let entries =
                            std::slice::from_raw_parts((*table).table.as_ptr(), num_entries);

                        for entry in entries {
                            let local_port = u16::from_be(entry.dwLocalPort as u16);
                            if local_port == port {
                                return entry.dwOwningPid;
                            }
                        }
                    }
                }
            }
        }
        0 // Not found
    }
}

impl FirewallEngine {
    pub fn start(&self, app_handle: AppHandle) {
        // Load Network Whitelists from Website folder before starting capture
        self.load_website_whitelists();

        // Auto-install the proxy CA into Windows Trusted Root so browsers
        // CA generation and installation is now handled by start_embedded_proxy() on demand.

        let stats = Arc::clone(&self.stats);
        let rules = Arc::clone(&self.rules);
        let dns = Arc::clone(&self.dns_handler);
        let am = Arc::clone(&self.app_manager);
        let wf = Arc::clone(&self.web_filter);
        let stop = Arc::clone(&self.stop_signal);
        let tx = app_handle.clone();
        let settings_arc = Arc::clone(&self.settings);

        // Web Filter Loader Thread
        let wf_loader = Arc::clone(&self.web_filter);
        let tx_loader = app_handle.clone();
        let settings_arc_loader = Arc::clone(&settings_arc);

        std::thread::Builder::new()
            .name("web_filter_loader".to_string())
            .spawn(move || {
                let ts = Self::now_ts();
                // Prioritize the user's configured request: "website"
                // We check settings first, but default strictly to "website" if empty/invalid.
                let path_str = {
                    let s = settings_arc_loader.read().unwrap();
                    if s.website_path.is_empty() {
                        default_website_path()
                    } else {
                        s.website_path.clone()
                    }
                };

                emit_log_event(
                    &tx_loader,
                    LogEntry {
                        id: format!("{}-web-load-start", ts),
                        timestamp: ts,
                        level: LogLevel::Info,
                        message: format!("Loading threat intelligence from: {}", path_str),
                    },
                );

                // Execute the load
                match wf_loader.load_from_website_folder(&path_str) {
                    Ok(count) => {
                        emit_log_event(
                            &tx_loader,
                            LogEntry {
                                id: format!("{}-web-load-success", Self::now_ts()),
                                timestamp: Self::now_ts(),
                                level: LogLevel::Success,
                                message: format!("WebFilter Loaded: {} rules active.", count),
                            },
                        );
                    }
                    Err(e) => {
                        emit_log_event(
                            &tx_loader,
                            LogEntry {
                                id: format!("{}-web-load-error", Self::now_ts()),
                                timestamp: Self::now_ts(),
                                level: LogLevel::Error,
                                message: format!("Failed to load 'website' folder: {}", e),
                            },
                        );
                    }
                }
            })
            .expect("failed to spawn web_filter_loader thread");

        // OPEN WINDIVERT HANDLE ONCE
        // The embedded proxy uses http-mitm-proxy which operates at the TCP/HTTP layer,
        // not via WinDivert, so we don't need to compete with another WinDivert handle.
        // Priority 0 is fine.
        let divert_priority: i16 = 0;
        let divert = match WinDivert::network("true", divert_priority, WinDivertFlags::new()) {
            Ok(d) => WinDivertArc(Arc::new(d)),
            Err(e) => {
                let ts = Self::now_ts();
                emit_log_event(
                    &tx,
                    LogEntry {
                        id: format!("{}-divert-fail", ts),
                        timestamp: ts,
                        level: LogLevel::Error,
                        message: format!("WinDivert Open Failed: {:?}", e),
                    },
                );
                return;
            }
        };

        // Store a clone so stop() can call shutdown() and unblock all recv() threads.
        *self.divert_handle.lock().unwrap() = Some(divert.clone());

        let ts = Self::now_ts();
        let sdk_count = self.sdk.read().unwrap().rules.len();
        emit_log_event(
            &tx,
            LogEntry {
                id: format!("{}-sdk-init", ts),
                timestamp: ts,
                level: LogLevel::Info,
                message: format!("SDK Registry: {} rules active.", sdk_count),
            },
        );

        emit_log_event(
            &tx,
            LogEntry {
                id: format!("{}-divert-active", ts),
                timestamp: ts,
                level: LogLevel::Success,
                message: "Firewall Engine ACTIVE (RADICAL Parallel Mode Enabled)".into(),
            },
        );

        let tls_proxy_cfg = {
            let settings = settings_arc.read().unwrap();
            settings.tls_proxy.clone()
        };
        if tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy && tls_proxy_cfg.auto_start {
            let ts = Self::now_ts();
            emit_log_event(
                &tx,
                LogEntry {
                    id: format!("{}-tls-proxy-mode", ts),
                    timestamp: ts,
                    level: LogLevel::Info,
                    message: format!(
                        "TLS Proxy mode enabled (embedded): proxy={}:{}, block_quic_udp_443={}",
                        tls_proxy_cfg.listen_host,
                        tls_proxy_cfg.listen_port,
                        tls_proxy_cfg.block_quic_udp_443,
                    ),
                },
            );
        } else {
            let ts = Self::now_ts();
            emit_log_event(
                &tx,
                LogEntry {
                    id: format!("{}-tls-proxy-disabled", ts),
                    timestamp: ts,
                    level: LogLevel::Info,
                    message: "TLS Proxy mode disabled or not auto-started - Windows proxy cleanup enforced".into(),
                },
            );
        }
        self.sync_proxy_runtime(&tx);

        {
            let am_telemetry = Arc::clone(&am);
            let tx_telemetry = tx.clone();
            tauri::async_runtime::spawn(async move {
                let mut carry = String::new();
                loop {
                    match ClientOptions::new().open(SANCTUM_FIREWALL_TELEMETRY_PIPE) {
                        Ok(mut client) => {
                            let now = Self::now_ts();
                            emit_log_event(
                                &tx_telemetry,
                                LogEntry {
                                    id: format!("{}-sanctum-telemetry-connected", now),
                                    timestamp: now,
                                    level: LogLevel::Success,
                                    message: "Connected to Sanctum ETW URL telemetry relay"
                                        .to_string(),
                                },
                            );

                            let mut buffer = vec![0u8; 8192];
                            loop {
                                match client.read(&mut buffer).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        carry.push_str(&String::from_utf8_lossy(&buffer[..n]));
                                        while let Some(pos) = carry.find('\n') {
                                            let line = carry[..pos].trim().to_string();
                                            carry = carry[pos + 1..].to_string();
                                            if line.is_empty() {
                                                continue;
                                            }

                                            if let Ok(syscall) =
                                                serde_json::from_str::<Syscall>(&line)
                                                && let NtFunction::NetworkActivity(data) =
                                                    syscall.data
                                            {
                                                let url = match data {
                                                    NetworkActivityData::Http(http) => http.url,
                                                    NetworkActivityData::WinINet(wininet) => {
                                                        wininet.url
                                                    }
                                                };
                                                if !url.trim().is_empty() {
                                                    am_telemetry
                                                        .ghost_urls
                                                        .write()
                                                        .unwrap()
                                                        .insert(syscall.pid, url);
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }

        // PENDING APP MONITOR THREAD
        // Checks for new unknown apps and asks the UI
        let am_monitor = Arc::clone(&am);
        let tx_monitor = app_handle.clone();

        std::thread::Builder::new()
            .name("pending_monitor".to_string())
            .spawn(move || {
                loop {
                    let has_active_alert = am_monitor.active_alert.read().unwrap().is_some();
                    if has_active_alert {
                        std::thread::sleep(Duration::from_millis(120));
                        continue;
                    }

                    let mut app_opt = None;
                    if let Ok(mut pending) = am_monitor.pending.write() {
                        app_opt = pending.pop_front();
                    }

                    if let Some(app) = app_opt {
                        // 1. Store it as the active alert for windows to fetch if they miss the emit
                        {
                            let mut active = am_monitor.active_alert.write().unwrap();
                            am_monitor.reset_view_index();
                            *active = Some(app.clone());
                        }

                        // 1. Trigger Alert Window Spawning logic
                        Self::spawn_alert_window(&tx_monitor);

                        // 2. Emit data to all windows (Main + Alert)
                        if let Some(alert) = am_monitor.get_active_alert() {
                            let _ = tx_monitor.emit("ask_app_decision", alert);
                        }

                        // Don't spam the UI
                        std::thread::sleep(Duration::from_millis(150));

                        // 3. Re-emit after delay so queue_total reflects any items
                        //    that were enqueued while the window was opening.
                        if let Some(alert) = am_monitor.get_active_alert() {
                            let _ = tx_monitor.emit("ask_app_decision", alert);
                        }
                    } else {
                        std::thread::sleep(Duration::from_millis(120));
                    }
                }
            })
            .expect("failed to spawn pending_monitor thread");

        // OWLYSHIELD HIPS PIPE READER
        // Receives registry/HIPS prompts from Owlyshield and feeds them into the
        // same pending alert queue used by firewall network prompts.
        {
            let am_hips = Arc::clone(&am);
            let stop_hips = Arc::clone(&stop);
            let tx_hips = app_handle.clone();
            std::thread::Builder::new()
                .name("owlyshield_hips_pipe".to_string())
                .spawn(move || {
                    use std::ffi::OsStr;
                    use std::net::{IpAddr, Ipv4Addr};
                    use std::os::windows::ffi::OsStrExt;
                    use windows::Win32::Foundation::{
                        CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
                        INVALID_HANDLE_VALUE,
                    };
                    use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
                    use windows::Win32::System::Pipes::{
                        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                        GetNamedPipeClientProcessId, NAMED_PIPE_MODE, PIPE_UNLIMITED_INSTANCES,
                    };
                    use windows::core::PCWSTR;

                    let pipe_name = r"\\.\pipe\HydraHipEvent";
                    let wide_name: Vec<u16> = OsStr::new(pipe_name)
                        .encode_wide()
                        .chain(std::iter::once(0u16))
                        .collect();
                    while !stop_hips.load(Ordering::Relaxed) {
                        let handle: HANDLE = unsafe {
                            CreateNamedPipeW(
                                PCWSTR(wide_name.as_ptr()),
                                PIPE_ACCESS_INBOUND,
                                NAMED_PIPE_MODE(0),
                                PIPE_UNLIMITED_INSTANCES,
                                0,
                                4096,
                                0,
                                None,
                            )
                        };

                        if handle == INVALID_HANDLE_VALUE {
                            std::thread::sleep(Duration::from_secs(2));
                            continue;
                        }

                        let connected = unsafe { ConnectNamedPipe(handle, None) }.is_ok()
                            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

                        if !connected {
                            unsafe {
                                let _ = DisconnectNamedPipe(handle);
                                let _ = CloseHandle(handle);
                            }
                            std::thread::sleep(Duration::from_millis(250));
                            continue;
                        }

                        let mut client_pid: u32 = 0;
                        let client_ok =
                            unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) }.is_ok()
                                && client_pid != 0;

                        if !client_ok {
                            unsafe {
                                let _ = DisconnectNamedPipe(handle);
                                let _ = CloseHandle(handle);
                            }
                            continue;
                        }

                        let mut buf = vec![0u8; 4096];
                        let mut leftover = String::new();

                        loop {
                            let mut bytes_read: u32 = 0;
                            let ok = unsafe {
                                ReadFile(
                                    handle,
                                    Some(buf.as_mut_slice()),
                                    Some(&mut bytes_read as *mut u32),
                                    None,
                                )
                            };

                            if ok.is_err() || bytes_read == 0 {
                                break;
                            }

                            leftover
                                .push_str(&String::from_utf8_lossy(&buf[..bytes_read as usize]));

                            while let Some(pos) = leftover.find('\n') {
                                let line = leftover[..pos].trim().to_string();
                                leftover = leftover[pos + 1..].to_string();

                                if let Some(rest) = line.strip_prefix("HIPS_ASK:") {
                                    let mut parts = rest.splitn(7, '|');
                                    let request_id = parts.next().unwrap_or("").trim().to_string();
                                    let process_id = parts
                                        .next()
                                        .unwrap_or("0")
                                        .trim()
                                        .parse::<u32>()
                                        .unwrap_or(0);
                                    let name =
                                        parts.next().unwrap_or("Owlyshield").trim().to_string();
                                    let path = parts.next().unwrap_or("").trim().to_string();
                                    let alert_kind =
                                        parts.next().unwrap_or("behavior").trim().to_string();
                                    let target = parts.next().unwrap_or("").trim().to_string();
                                    let reason = parts
                                        .next()
                                        .unwrap_or("Owlyshield HIPS detection")
                                        .trim()
                                        .to_string();

                                    if !request_id.is_empty() {
                                        let enqueued = am_hips.enqueue_pending_app(
                                            PendingApp {
                                                process_id,
                                                name,
                                                path,
                                                dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                                dst_port: 0,
                                                protocol: Protocol::Raw(0),
                                                hostname: None,
                                                reason: Some(reason),
                                                request_id: Some(request_id),
                                                alert_source: Some("owlyshield".to_string()),
                                                alert_kind: Some(alert_kind),
                                                target: Some(target),
                                                decision_key: None,
                                                full_url: None,
                                                http_method: None,
                                                http_path: None,
                                                http_user_agent: None,
                                                http_content_type: None,
                                                http_referer: None,
                                                http_request_body: None,
                                                http_response_body: None,
                                                payload_sample: None,
                                                detected_file_type: None,
                                                packet_json: None,
                                                queue_position: 1,
                                                queue_total: 1,
                                            },
                                            false,
                                        );
                                        if enqueued {
                                            if let Some(active_alert) = am_hips.get_active_alert() {
                                                let _ =
                                                    tx_hips.emit("ask_app_decision", active_alert);
                                            }
                                        }
                                    }
                                } else if let Some((rest, trust_message)) = line
                                    .strip_prefix("HIPS_TRUST:")
                                    .map(|rest| (rest, true))
                                    .or_else(|| {
                                        line.strip_prefix("HIPS_VERDICT:").map(|rest| (rest, false))
                                    })
                                {
                                    let parts = rest.split('|').collect::<Vec<_>>();
                                    let pid = parts
                                        .get(0)
                                        .copied()
                                        .unwrap_or("0")
                                        .parse::<u32>()
                                        .unwrap_or(0);
                                    let path = parts.get(1).copied().unwrap_or("").trim();
                                    let verdict = normalize_openedr_verdict(
                                        parts.get(2).copied(),
                                        trust_message,
                                    );
                                    let details = if parts.len() > 3 {
                                        parts[3..].join(" | ")
                                    } else {
                                        parts.get(2).copied().unwrap_or("").trim().to_string()
                                    };

                                    if pid != 0 {
                                        if verdict.is_cloud_trusted() {
                                            am_hips.cloud_trusted_pids.write().unwrap().insert(pid);
                                        } else {
                                            am_hips
                                                .cloud_trusted_pids
                                                .write()
                                                .unwrap()
                                                .remove(&pid);
                                        }
                                        am_hips
                                            .openedr_verdicts
                                            .write()
                                            .unwrap()
                                            .insert(pid, verdict.label().to_string());

                                        let details_suffix = if details.trim().is_empty() {
                                            String::new()
                                        } else {
                                            format!(" ({})", details.trim())
                                        };
                                        emit_log_event(
                                            &tx_hips,
                                            LogEntry {
                                                id: format!(
                                                    "openedr_verdict_{}_{}",
                                                    pid,
                                                    SystemTime::now()
                                                        .duration_since(UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_millis()
                                                ),
                                                timestamp: SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_millis()
                                                    as u64,
                                                level: verdict.log_level(),
                                                message: format!(
                                                    "[OpenEDR Verdict] {} => {}{}",
                                                    if path.is_empty() { "Unknown" } else { path },
                                                    verdict.label(),
                                                    details_suffix
                                                ),
                                            },
                                        );
                                    }
                                }
                            }
                        }

                        unsafe {
                            let _ = DisconnectNamedPipe(handle);
                            let _ = CloseHandle(handle);
                        }
                    }
                })
                .expect("failed to spawn owlyshield_hips_pipe thread");
        }

        // RAW PACKET UI EMITTER
        // Keep frontend traffic off the packet workers by using a bounded queue.
        let (raw_packet_tx, raw_packet_rx) =
            std::sync::mpsc::sync_channel::<crate::sdk::RawPacket>(512);
        {
            let stop_raw = Arc::clone(&stop);
            let tx_raw = app_handle.clone();
            std::thread::Builder::new()
                .name("raw_packet_emitter".to_string())
                .spawn(move || {
                    while !stop_raw.load(Ordering::Relaxed) {
                        match raw_packet_rx.recv_timeout(Duration::from_millis(250)) {
                            Ok(raw_packet) => {
                                let _ = tx_raw.emit("raw_packet", raw_packet);
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }

                    while let Ok(raw_packet) = raw_packet_rx.try_recv() {
                        let _ = tx_raw.emit("raw_packet", raw_packet);
                    }
                })
                .expect("failed to spawn raw_packet_emitter thread");
        }

        // ── NETWORK EVENT PIPE WRITER ────────────────────────────────────────────
        // Sends real network I/O events to the AV behavior engine so it can track
        // actual network activity per process instead of guessing from DLL loads.
        //
        // Protocol (UTF-8, newline-delimited):
        //   NET_EVENT:<pid>:<dst_ip>:<dst_port>
        //
        // Behavior engine owns the pipe server (\\.\pipe\HydraNetEvent).
        // This thread is the persistent client; packet workers feed it via a channel.
        // One message is sent per new PID per session to avoid flooding the pipe.
        let (net_event_tx, net_event_rx) = std::sync::mpsc::channel::<String>();
        *self.hydranet_tx.lock().unwrap() = Some(net_event_tx.clone());
        for blocked_path in self.settings.read().unwrap().kernel_block_paths.clone() {
            let _ = net_event_tx.send(kernel_block_message(&blocked_path));
        }
        {
            let stop_pipe = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("net_event_pipe_writer".to_string())
                .spawn(move || {
                    use std::io::Write;
                    const PIPE: &str = r"\\.\pipe\HydraNetEvent";
                    let mut pipe_opt: Option<std::fs::File> = None;
                    let mut pending_msgs: VecDeque<String> = VecDeque::new();

                    while !stop_pipe.load(Ordering::Relaxed) {
                        loop {
                            match net_event_rx.try_recv() {
                                Ok(msg) => {
                                    pending_msgs.push_back(msg);
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                            }
                        }

                        if pipe_opt.is_none() && !pending_msgs.is_empty() {
                            if let Ok(file) = std::fs::OpenOptions::new()
                                .write(true)
                                .open(PIPE)
                            {
                                use std::os::windows::io::AsRawHandle;
                                use windows::Win32::Foundation::HANDLE;
                                use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;

                                let mut server_pid: u32 = 0;
                                let handle = HANDLE(file.as_raw_handle() as *mut _);
                                let ok = unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) };

                                if ok.is_ok() && server_pid != 0 {
                                    if server_pid != 0 {
                                        pipe_opt = Some(file);
                                    } else {
                                        println!(
                                            "WARNING: Rejected HydraNetEvent server with invalid PID"
                                        );
                                    }
                                }
                            }
                        }

                        while pipe_opt.is_some() {
                            let Some(msg) = pending_msgs.front() else {
                                break;
                            };

                            let write_res = {
                                let pipe = pipe_opt.as_mut().unwrap();
                                pipe.write_all(msg.as_bytes())
                            };

                            if write_res.is_ok() {
                                pending_msgs.pop_front();
                            } else {
                                pipe_opt = None;
                                break;
                            }
                        }

                        let sleep_ms = if pending_msgs.is_empty() {
                            10
                        } else if pipe_opt.is_some() {
                            5
                        } else {
                            250
                        };
                        std::thread::sleep(Duration::from_millis(sleep_ms));
                    }
                })
                .expect("failed to spawn net_event_pipe_writer thread");
        }

        // Worker Pool - RADICAL REFACTOR: Each worker is a fully independent capture loop
        let num_workers = 8; // Increased workers for parallel processing
        for worker_id in 0..num_workers {
            let stats_w = Arc::clone(&stats);
            let rules_w = Arc::clone(&rules);
            let am_w = Arc::clone(&am);
            let wf_w = Arc::clone(&wf);
            let stop_w = Arc::clone(&stop);
            let settings_w = Arc::clone(&settings_arc);
            let dns_w = Arc::clone(&dns);
            let sdk_w = Arc::clone(&self.sdk);
            let fcheck_w = Arc::clone(&self.file_checker);
            let windows_root_trust_ready_w = Arc::clone(&self.windows_root_trust_ready);
            let firefox_policy_ready_w = Arc::clone(&self.firefox_policy_ready);
            let browser_mitm_warning_cache_w = Arc::clone(&self.browser_mitm_warning_cache);
            let network_whitelist_index_w = Arc::clone(&self.network_whitelist_index);
            let tx_log = app_handle.clone();
            let divert_w = divert.clone();
            let net_ev_tx = net_event_tx.clone();
            let raw_packet_tx_w = raw_packet_tx.clone();
            let nat_table_w = self.nat_table.clone();

            std::thread::Builder::new()
                .name(format!("packet_worker_{}", worker_id))
                .spawn(move || {
                    let mut buffer = vec![0u8; 65535];
                    let mut packet_count = 0u64;
                    // Per-worker dedup: only send one NET_EVENT per PID per session
                    let mut notified_pids: HashSet<u32> = HashSet::new();
                    while !stop_w.load(Ordering::Relaxed) {
                        // Each thread competition for packets on the shared handle
                        match divert_w.recv(Some(&mut buffer)) {
                            Ok(packet) => {
                                packet_count += 1;
                                if packet_count % 100 == 0
                                    && !settings_w.read().unwrap().show_blocked_logs_only
                                {
                                    let ts = Self::now_ts();
                                    emit_log_event(
                                        &tx_log,
                                        LogEntry {
                                            id: format!("{}-worker-{}-count", ts, worker_id),
                                            timestamp: ts,
                                            level: LogLevel::Info,
                                            message: format!(
                                                "Worker {} received {} packets",
                                                worker_id, packet_count
                                            ),
                                        },
                                    );
                                }
                                // println!("DEBUG: Worker Recv Packet len={}", packet.data.len());
                                let outbound = packet.address.outbound();

                                // Skip packets reinjected by the embedded proxy (or any other
                                // WinDivert handle). Impostor packets have wrong PID/port
                                // context and would cause double-processing and noise.
                                if packet.address.impostor() {
                                    let reinject = windivert::packet::WinDivertPacket {
                                        address: packet.address,
                                        data: std::borrow::Cow::Owned(packet.data.to_vec()),
                                    };
                                    let _ = divert_w.send(&reinject);
                                    continue;
                                }

                                // Serialize Address for Decision Logic
                                // (Still keep some structure from previous for compatibility)
                                let addr_bytes = unsafe {
                                    std::slice::from_raw_parts(
                                        &packet.address as *const _ as *const u8,
                                        std::mem::size_of_val(&packet.address),
                                    )
                                    .to_vec()
                                };

                                // PID RESOLUTION:
                                // 1. WinDivert native PID — most reliable, direct from kernel
                                // 2. Native Windows TCP/UDP table lookup
                                // 3. Hook DLL mapping fallback
                                // NetworkLayer addresses do NOT carry process_id;
                                // start at 0 and resolve via TCP/UDP table below.
                                let mut pid: u32 = 0;
                                let data_vec = packet.data.to_vec();
                                let mut pre_parsed =
                                    Self::parse_packet(&data_vec, outbound, 0, &am_w.info_cache);

                                if let Some((ref mut p_info, _)) = pre_parsed {
                                    let lookup_port = if outbound {
                                        p_info.src_port
                                    } else {
                                        p_info.dst_port
                                    };
                                    let is_tcp =
                                        matches!(p_info.protocol, crate::engine::Protocol::TCP);

                                    // WinDivert native PID already set above (step 1).
                                    // Fall through to TCP/UDP table if it returned 0.
                                    if pid == 0 {
                                        pid = Self::resolve_pid_from_port(lookup_port, is_tcp);
                                    }

                                    // Fallback: Hook DLL mapping (if native lookup failed)
                                    if pid == 0 {
                                        if let Some(mapped_pid) = am_w.get_pid_for_port(lookup_port)
                                        {
                                            pid = mapped_pid;
                                        }
                                    }

                                    // Cache the resolved port->PID mapping for future
                                    if pid != 0 {
                                        am_w.update_port_mapping(lookup_port, pid);
                                        p_info.process_id = pid;
                                        p_info.image_path = am_w.info_cache.get_info(pid).path;
                                    }
                                }

                                let decision = Self::process_packet_decision(
                                    &packet.data,
                                    &addr_bytes,
                                    outbound,
                                    &stats_w,
                                    &rules_w,
                                    &am_w,
                                    &wf_w,
                                    &settings_w,
                                    &dns_w,
                                    &sdk_w,
                                    &fcheck_w,
                                    &tx_log,
                                    pid,
                                    &pre_parsed,
                                    &windows_root_trust_ready_w,
                                    &firefox_policy_ready_w,
                                    &browser_mitm_warning_cache_w,
                                    &network_whitelist_index_w,
                                );

                                // Firewall activity telemetry. Network blocks stay in the
                                // firewall; they must not become Owlyshield process-kill alerts.
                                let mut decision_info: Option<PacketInfo> = None;
                                if let Some((ref p_info, _)) = pre_parsed {
                                    decision_info = Some(p_info.clone());
                                }

                                if outbound && pid != 0 {
                                    if let Some(ref parsed_info) = decision_info {
                                        // NET_EVENT records observed network activity only.
                                        if !notified_pids.contains(&pid) {
                                            let msg = format!(
                                                "NET_EVENT:{}:{}:{}\n",
                                                pid, parsed_info.dst_ip, parsed_info.dst_port
                                            );
                                            let _ = net_ev_tx.send(msg);
                                            notified_pids.insert(pid);
                                        }
                                    }
                                }

                                // EMIT RAW PACKET FOR UI (Wireshark-like view)
                                if let Some(info) = decision_info {
                                    let show_blocked_only =
                                        settings_w.read().unwrap().show_blocked_logs_only;
                                    if !(show_blocked_only && decision.should_forward) {
                                        let ts = Self::now_ts();
                                        let app_info = am_w.info_cache.get_info(pid);

                                        let payload_preview = if decision.packet_data.len() > 32 {
                                            format!(
                                                "{}...",
                                                String::from_utf8_lossy(
                                                    &decision.packet_data[..32]
                                                )
                                                .replace("\n", " ")
                                            )
                                        } else {
                                            String::from_utf8_lossy(&decision.packet_data)
                                                .replace("\n", " ")
                                        };

                                        let mut raw_packet = crate::sdk::RawPacket {
                                            id: format!(
                                                "{}-{}-{}",
                                                ts, info.src_port, info.dst_port
                                            ),
                                            timestamp: ts,
                                            src_ip: info.src_ip.to_string(),
                                            dst_ip: info.dst_ip.to_string(),
                                            src_port: info.src_port,
                                            dst_port: info.dst_port,
                                            protocol: info.protocol.clone(),
                                            length: decision.packet_data.len(),
                                            payload_hex: decision
                                                .packet_data
                                                .iter()
                                                .map(|b| format!("{:02X}", b))
                                                .collect::<Vec<_>>()
                                                .join(" "),
                                            payload_preview,
                                            summary: format!("{} -> {}", info.src_ip, info.dst_ip),
                                            process_id: pid,
                                            process_name: app_info.name,
                                            process_path: app_info.path,
                                            action: if decision.should_forward {
                                                "Allow".to_string()
                                            } else {
                                                "Block".to_string()
                                            },
                                            rule: decision._reason.clone(),
                                            hostname: info.hostname.clone(),
                                        };

                                        // Enrich summary with hostname if available
                                        if let Some(ref h) = raw_packet.hostname {
                                            raw_packet.summary =
                                                format!("{} ({})", raw_packet.summary, h);
                                        } else {
                                            // Snooping fallback for raw packet display
                                            if let Some(domain) =
                                                dns_w.resolve_ip(&info.dst_ip.to_string())
                                            {
                                                raw_packet.hostname = Some(domain.clone());
                                                raw_packet.summary =
                                                    format!("{} ({})", raw_packet.summary, domain);
                                            } else if let Some(domain) =
                                                dns_w.resolve_ip(&info.src_ip.to_string())
                                            {
                                                raw_packet.hostname = Some(domain.clone());
                                                raw_packet.summary =
                                                    format!("{} ({})", raw_packet.summary, domain);
                                            }
                                        }
                                        let _ = raw_packet_tx_w.try_send(raw_packet);
                                    }
                                }

                                if decision.should_forward {
                                    let mut packet_data = decision.packet_data;
                                    let mut recalc_checksums = decision.recalc_checksums;
                                    let mut loopback_flag = None;
                                    let mut outbound_flag = None;

                                    let tls_proxy_cfg =
                                        settings_w.read().unwrap().tls_proxy.clone();
                                    // CRITICAL FIX: Only redirect to proxy if it's actually enabled AND auto-started
                                    if tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy
                                        && tls_proxy_cfg.auto_start
                                    {
                                        let mut is_tcp = false;
                                        let mut src_port = 0;
                                        let mut dst_port = 0;
                                        let mut src_ip = None;
                                        let mut dst_ip = None;
                                        if let Some((ref p_info, _)) = pre_parsed {
                                            is_tcp = matches!(
                                                p_info.protocol,
                                                crate::engine::Protocol::TCP
                                            );
                                            src_port = p_info.src_port;
                                            dst_port = p_info.dst_port;
                                            src_ip = Some(p_info.src_ip);
                                            dst_ip = Some(p_info.dst_ip);
                                        }

                                        if is_tcp {
                                            let proxy_return_flow = src_ip
                                                .is_some_and(Self::is_loopback)
                                                && src_port == tls_proxy_cfg.listen_port;

                                            if proxy_return_flow {
                                                if let Some((orig_ip, orig_port, orig_src)) =
                                                    nat_table_w.get(dst_port)
                                                {
                                                    let ok = match orig_ip {
                                                        IpAddr::V4(v4) => {
                                                            let ok_src = nat_rewrite_src_ipv4(
                                                                &mut packet_data,
                                                                v4,
                                                                orig_port,
                                                            );
                                                            let ok_dst =
                                                                if let IpAddr::V4(orig_client_ip) =
                                                                    orig_src
                                                                {
                                                                    nat_rewrite_dst_ipv4(
                                                                        &mut packet_data,
                                                                        orig_client_ip,
                                                                        dst_port,
                                                                    )
                                                                } else {
                                                                    false
                                                                };
                                                            ok_src && ok_dst
                                                        }
                                                        IpAddr::V6(v6) => {
                                                            let ok_src = nat_rewrite_src_ipv6(
                                                                &mut packet_data,
                                                                v6,
                                                                orig_port,
                                                            );
                                                            let ok_dst =
                                                                if let IpAddr::V6(orig_client_ip) =
                                                                    orig_src
                                                                {
                                                                    nat_rewrite_dst_ipv6(
                                                                        &mut packet_data,
                                                                        orig_client_ip,
                                                                        dst_port,
                                                                    )
                                                                } else {
                                                                    false
                                                                };
                                                            ok_src && ok_dst
                                                        }
                                                    };
                                                    if ok {
                                                        recalc_checksums = true;
                                                        loopback_flag = Some(false);
                                                        outbound_flag = Some(false);
                                                        if tcp_is_fin_or_rst(&packet_data) {
                                                            nat_table_w.remove(dst_port);
                                                        }
                                                    }
                                                }
                                            } else if outbound
                                                && dst_port == 443
                                                && pid != std::process::id()
                                                && !http_mitm_proxy::is_registered_upstream_local_port(src_port)
                                            {
                                                if let (Some(orig_dst), Some(orig_src)) =
                                                    (dst_ip, src_ip)
                                                {
                                                    if !Self::is_loopback(orig_dst)
                                                        && !orig_dst.is_unspecified()
                                                        && !orig_dst.is_multicast()
                                                    {
                                                        nat_table_w.insert(
                                                            src_port,
                                                            (orig_dst, 443, orig_src),
                                                        );
                                                        let ok = match orig_dst {
                                                            IpAddr::V4(_v4) => {
                                                                let ok_dst = nat_rewrite_dst_ipv4(
                                                                    &mut packet_data,
                                                                    Ipv4Addr::new(127, 0, 0, 1),
                                                                    tls_proxy_cfg.listen_port,
                                                                );
                                                                let ok_src = nat_rewrite_src_ipv4(
                                                                    &mut packet_data,
                                                                    Ipv4Addr::new(127, 0, 0, 1),
                                                                    src_port,
                                                                );
                                                                ok_dst && ok_src
                                                            }
                                                            IpAddr::V6(_v6) => {
                                                                let ok_dst = nat_rewrite_dst_ipv6(
                                                                    &mut packet_data,
                                                                    std::net::Ipv6Addr::LOCALHOST,
                                                                    tls_proxy_cfg.listen_port,
                                                                );
                                                                let ok_src = nat_rewrite_src_ipv6(
                                                                    &mut packet_data,
                                                                    std::net::Ipv6Addr::LOCALHOST,
                                                                    src_port,
                                                                );
                                                                ok_dst && ok_src
                                                            }
                                                        };
                                                        if ok {
                                                            recalc_checksums = true;
                                                            loopback_flag = Some(true);
                                                            // Local listeners only receive inbound packets; must clear outbound flag
                                                            outbound_flag = Some(false);
                                                            if tcp_is_fin_or_rst(&packet_data) {
                                                                nat_table_w.remove(src_port);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // REINJECT IMMEDIATELY from the SAME thread
                                    // CRITICAL FIX: Only send if should_forward is true
                                    let mut reinject_address = packet.address.clone();
                                    if let Some(val) = loopback_flag {
                                        reinject_address.as_mut().set_loopback(val);
                                    }
                                    if let Some(val) = outbound_flag {
                                        reinject_address.as_mut().set_outbound(val);
                                    }
                                    let mut reinject_packet = windivert::packet::WinDivertPacket {
                                        address: reinject_address,
                                        data: std::borrow::Cow::Owned(packet_data),
                                    };
                                    if recalc_checksums {
                                        let _ = reinject_packet
                                            .recalculate_checksums(Default::default());
                                    }
                                    // Send the packet back to the network stack
                                    if let Err(_e) = divert_w.send(&reinject_packet) {
                                        // Log error selectively?
                                    }
                                } else {
                                    // Packet is blocked - we just don't call divert.send()
                                    // WinDivert drops it automatically since we didn't send it.
                                }
                            }
                            Err(_e) => {
                                let err_str = _e.to_string();
                                if err_str.contains("timeout") {
                                    // Ignore timeouts as they are expected
                                    std::thread::sleep(Duration::from_millis(1));
                                } else if stop_w.load(Ordering::Relaxed) {
                                    // shutdown() was called — exit the worker cleanly.
                                    break;
                                } else {
                                    let ts = Self::now_ts();
                                    emit_log_event(
                                        &tx_log,
                                        LogEntry {
                                            id: format!(
                                                "{}-worker-{}-err-{}",
                                                ts, worker_id, packet_count
                                            ),
                                            timestamp: ts,
                                            level: LogLevel::Error,
                                            message: format!(
                                                "Worker {} Recv Error: {} (count: {})",
                                                worker_id, err_str, packet_count
                                            ),
                                        },
                                    );
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                            }
                        }
                    }
                })
                .expect("failed to spawn packet worker");
        }
    }

    fn process_packet_decision(
        data: &[u8],
        address_data: &[u8],
        outbound: bool,
        stats: &Arc<Statistics>,
        rules: &Arc<RwLock<Vec<FirewallRule>>>,
        am: &Arc<AppManager>,
        wf: &Arc<WebFilter>,
        settings: &Arc<RwLock<FirewallSettings>>,
        dns_handler: &Arc<DnsHandler>,
        sdk: &Arc<RwLock<crate::sdk::SdkRegistry>>,
        file_checker: &Arc<FileMagicChecker>,
        tx: &AppHandle,
        process_id: u32,
        pre_parsed: &Option<(PacketInfo, usize)>,
        windows_root_trust_ready: &Arc<AtomicBool>,
        firefox_policy_ready: &Arc<AtomicBool>,
        browser_mitm_warning_cache: &Arc<Mutex<HashSet<String>>>,
        network_whitelist_index: &Arc<RwLock<CidrIndex>>,
    ) -> PacketDecision {
        let (mut info, mut payload_offset) = match pre_parsed {
            Some(p) => (p.0.clone(), p.1),
            None => {
                if let Some((p_info, offset)) =
                    Self::parse_packet(data, outbound, process_id, &am.info_cache)
                {
                    (p_info, offset)
                } else {
                    stats.packets_total.fetch_add(1, Ordering::Relaxed);
                    stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                    return PacketDecision {
                        packet_data: data.to_vec(),
                        address_data: address_data.to_vec(),
                        should_forward: true,
                        recalc_checksums: false,
                        _reason: "Unparsed packet allowed (no default deny)".to_string(),
                    };
                }
            }
        };

        let mut data_vec = data.to_vec();
        let pid = info.process_id;

        // 2. Resolve Process Metadata
        let app_info = am.info_cache.get_info(pid);
        let sdk_context = crate::sdk::PacketContext {
            process_id: pid,
            process_name: app_info.name.clone(),
            process_path: app_info.path.clone(),
        };

        // Initialize decision state
        let mut should_forward = true;
        let mut reason: Option<String> = None;
        let mut remember_pending_as_unknown_app = true;
        let mut website_decision_key: Option<String> = None;
        let mut website_target: Option<String> = None;
        let (late_blocking_mode, tls_proxy_cfg, log_mode, show_blocked_only, no_alert_mode) = {
            let s = settings.read().unwrap();
            (
                s.late_blocking_mode,
                s.tls_proxy.clone(),
                s.log_mode,
                s.show_blocked_logs_only && s.show_blocked_graphics_only,
                s.no_alert_mode,
            )
        };

        // --- NEW: Global Network Whitelist ---
        {
            let network_whitelist_index_guard = network_whitelist_index.read().unwrap();
            if network_whitelist_index_guard.contains(info.src_ip)
                || network_whitelist_index_guard.contains(info.dst_ip)
            {
                return PacketDecision {
                    packet_data: data.to_vec(),
                    address_data: address_data.to_vec(),
                    should_forward: true,
                    recalc_checksums: false,
                    _reason: "Whitelisted network".to_string(),
                };
            }
        }

        // 3. DNS Snooping Enrichment (CRITICAL: Do this before rules!)
        if info.hostname.is_none() {
            if outbound {
                info.hostname = dns_handler.resolve_ip(&info.dst_ip.to_string());
            } else {
                info.hostname = dns_handler.resolve_ip(&info.src_ip.to_string());
            }
        }

        // 4. SDK PACKET CHANGERS & LISTENERS
        {
            let sdk_read = sdk.read().unwrap();
            for changer in &sdk_read.changers {
                if changer.modify(&mut data_vec, &info, &sdk_context) {
                    if let Some((new_info, new_offset)) =
                        Self::parse_packet(&data_vec, outbound, pid, &am.info_cache)
                    {
                        info = new_info;
                        payload_offset = new_offset;
                        // RE-ENRICH after change (Feature 12/Context)
                        if info.hostname.is_none() {
                            if outbound {
                                info.hostname = dns_handler.resolve_ip(&info.dst_ip.to_string());
                            } else {
                                info.hostname = dns_handler.resolve_ip(&info.src_ip.to_string());
                            }
                        }
                    }
                }
            }
            if !show_blocked_only {
                for listener in &sdk_read.listeners {
                    listener.on_packet(&data_vec, &info, &sdk_context);
                }
            }
        }

        // 5. Core Firewall Logic
        // Only the firewall's own embedded proxy listener is fast-allowed on
        // loopback so we do not interfere with the interception path itself.
        // All other localhost traffic must continue through normal rule and
        // app-decision evaluation.
        if tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy
            && Self::is_proxy_listener_flow(&info, &tls_proxy_cfg)
        {
            stats.packets_total.fetch_add(1, Ordering::Relaxed);
            stats.packets_allowed.fetch_add(1, Ordering::Relaxed);

            // Emit a dedicated event when an app connects to the proxy listener so
            // the user can see which apps are being intercepted by the embedded proxy.
            if outbound && Self::is_proxy_destination(&info, &tls_proxy_cfg) {
                let app_info_loopback = am.info_cache.get_info(pid);
                let host_label = info
                    .hostname
                    .clone()
                    .or_else(|| dns_handler.resolve_ip(&info.dst_ip.to_string()))
                    .unwrap_or_else(|| info.dst_ip.to_string());
                let now = Self::now_ts();
                Self::maybe_emit_browser_mitm_warning(
                    &tx,
                    am,
                    no_alert_mode,
                    &tls_proxy_cfg,
                    &app_info_loopback.name,
                    &app_info_loopback.path,
                    pid,
                    info.hostname.as_deref(),
                    info.full_url.as_deref(),
                    &host_label,
                    windows_root_trust_ready,
                    firefox_policy_ready,
                    browser_mitm_warning_cache,
                );
                if !show_blocked_only {
                    emit_log_event(
                        &tx,
                        LogEntry {
                            id: format!("{}-proxy-intercept-{}", now, pid),
                            timestamp: now,
                            level: LogLevel::Info,
                            message: format!(
                                "Proxy Intercept: {} (pid={}) → {} via embedded proxy",
                                app_info_loopback.name, pid, host_label
                            ),
                        },
                    );
                }
            }

            return PacketDecision {
                packet_data: data_vec,
                address_data: address_data.to_vec(),
                should_forward: true,
                recalc_checksums: false,
                _reason: "Embedded proxy listener".to_string(),
            };
        }

        // Cache URLs by PID for subsequent packets in the same flow.
        // Never cache for PID <= 4 (System, Idle) or non-TCP traffic to prevent sticky global URL pollution.
        if let Some(ref url) = info.full_url {
            if pid > 4 && matches!(info.protocol, Protocol::TCP) {
                am.url_cache.write().unwrap().insert(pid, url.clone());
            }
        } else if pid > 4 && matches!(info.protocol, Protocol::TCP) {
            if let Some(url) = am.url_cache.read().unwrap().get(&pid) {
                if let Ok(parsed_url) = url::Url::parse(url) {
                    let matches_host = info
                        .hostname
                        .as_deref()
                        .map(|h| h.eq_ignore_ascii_case(parsed_url.host_str().unwrap_or("")))
                        .unwrap_or(false);
                    if matches_host {
                        info.full_url = Some(url.clone());
                    }
                }
            } else if let Some(url) = am.ghost_urls.read().unwrap().get(&pid) {
                if let Ok(parsed_url) = url::Url::parse(url) {
                    let matches_host = info
                        .hostname
                        .as_deref()
                        .map(|h| h.eq_ignore_ascii_case(parsed_url.host_str().unwrap_or("")))
                        .unwrap_or(false);
                    if matches_host {
                        info.full_url = Some(url.clone());
                        am.url_cache.write().unwrap().insert(pid, url.clone());
                    }
                }
            }
        }

        let payload = if payload_offset < data_vec.len() {
            &data_vec[payload_offset..]
        } else {
            &[][..]
        };
        let (sdk_needs_entropy, sdk_needs_file_type) = {
            let sdk_lock = sdk.read().unwrap();
            (sdk_lock.needs_entropy(), sdk_lock.needs_file_type())
        };

        // URL telemetry is derived from packet parsing and in-engine caching only.

        let is_dns_query =
            matches!(info.protocol, Protocol::UDP) && (info.src_port == 53 || info.dst_port == 53);
        let dns_domain = info.dns_query.clone();

        // 6. Resolve App Identity
        let (mut app_decision, app_name, _) = am.check_app(&info);

        // 7. Custom Firewall Rules (PRIORITY #1)
        let current_rules = rules.read().unwrap();
        let rules_need_file_type = current_rules
            .iter()
            .any(|rule| rule.enabled && !rule.file_types.is_empty());

        let should_detect_file_type =
            rules_need_file_type || (!late_blocking_mode && sdk_needs_file_type);
        if should_detect_file_type && !payload.is_empty() {
            if let Some(dtype) = file_checker.check(payload) {
                am.url_cache
                    .write()
                    .unwrap()
                    .insert(pid, format!("FILESIG:{}", dtype));
                info.detected_file_type = Some(dtype);
            }
        }

        if !late_blocking_mode
            && sdk_needs_entropy
            && info.payload_entropy.is_none()
            && !payload.is_empty()
        {
            info.payload_entropy = Some(Self::shannon_entropy(payload));
        }

        for rule in current_rules.iter() {
            if rule.matches(&info, &app_name) {
                if rule.block || rule.terminate || rule.quarantine || rule.kill_and_remove {
                    should_forward = false;
                    let rule_reason = format!("Rule [{}]: {}", rule.name, rule.description);
                    reason = Some(rule_reason.clone());

                    if rule.terminate || rule.kill_and_remove {
                        Self::terminate_process(pid);
                    }
                    if rule.quarantine || rule.kill_and_remove {
                        Self::quarantine_file(&app_info.path, &rule_reason);
                    }
                    break;
                } else if rule.ask_user {
                    should_forward = false;
                    app_decision = AppDecision::Pending;
                    reason = Some(format!("Rule [{}]: User decision requested", rule.name));
                    break;
                } else {
                    should_forward = true;
                    reason = Some(format!("Rule Allowed: {}", rule.name));
                }
            }
        }
        drop(current_rules);

        let remote_ip = if info.outbound {
            info.dst_ip
        } else {
            info.src_ip
        };
        if let Some(web_match) = wf.find_match(
            remote_ip,
            info.hostname.as_deref(),
            info.full_url.as_deref(),
            &info.payload_urls,
            &info.payload_domains,
        ) {
            let decision_key = web_match.decision_key();
            website_target = Some(web_match.target.clone());
            website_decision_key = Some(decision_key.clone());

            match am.get_decision(&decision_key) {
                Some(AppDecision::Allow) => {
                    should_forward = true;
                    let reason_prefix = if Self::proxy_bypass_matches_target(
                        &tls_proxy_cfg,
                        info.hostname.as_deref(),
                        info.full_url.as_deref(),
                        Some(&web_match.target),
                    ) {
                        "Website trusted with TLS proxy bypass"
                    } else {
                        "Website trusted"
                    };
                    reason = Some(format!("{}: {}", reason_prefix, web_match.target));
                }
                Some(AppDecision::AllowOnce) => {
                    should_forward = true;
                    reason = Some(format!("Website allowed once: {}", web_match.target));
                    am.remove_decision(&decision_key.to_lowercase());
                }
                Some(AppDecision::Block) => {
                    should_forward = false;
                    app_decision = AppDecision::Block;
                    remember_pending_as_unknown_app = false;
                    reason = Some(format!(
                        "Website blocked [{}]: {}",
                        web_match.target, web_match.reason
                    ));
                }
                Some(AppDecision::Pending) | None => {
                    should_forward = false;
                    app_decision = AppDecision::Pending;
                    remember_pending_as_unknown_app = false;
                    reason = Some(format!(
                        "Website intelligence match [{}]: {}",
                        web_match.target, web_match.reason
                    ));
                }
            }
        }

        // 8. App Decision Check
        if should_forward {
            match app_decision {
                AppDecision::Block => {
                    should_forward = false;
                    reason = Some(format!("Blocked App: {}", app_name));
                }
                AppDecision::Allow => {
                    should_forward = true;
                    reason = Some(format!("App Allowed: {}", app_name));
                }
                AppDecision::AllowOnce => {
                    should_forward = true;
                    reason = Some(format!("App Allowed (Once): {}", app_name));
                    am.remove_decision(&app_name.to_lowercase());
                }
                AppDecision::Pending => {
                    // CRITICAL FIX: Block packets when app decision is pending
                    should_forward = false;
                    reason = Some(format!("App pending decision: {}", app_name));
                }
            }
        }

        // 9. SDK Rule Evaluation
        {
            let s_lock = sdk.read().unwrap();
            let first_match = s_lock.evaluate_first_match(&info, payload, late_blocking_mode);

            if let Some(finding) = first_match {
                match finding.action {
                    crate::sdk::RuleAction::Block => {
                        should_forward = false;
                        reason = Some(format!(
                            "SDK Rule [{}]: {}",
                            finding.rule_name, finding.description
                        ));
                    }
                    crate::sdk::RuleAction::Allow => {
                        should_forward = true;
                        reason = Some(format!("SDK Rule [{}]: Allowed", finding.rule_name));
                    }
                    crate::sdk::RuleAction::TrafficAttack => {
                        // Log as attack but still forward (monitoring)
                        emit_log_event(
                            &tx,
                            LogEntry {
                                id: format!("{}-attack", Self::now_ts()),
                                timestamp: Self::now_ts(),
                                level: LogLevel::Warning,
                                message: format!(
                                    "Attack detected by [{}]: {}",
                                    finding.rule_name, finding.description
                                ),
                            },
                        );
                    }
                    crate::sdk::RuleAction::Ask => {
                        should_forward = false;
                        app_decision = AppDecision::Pending;
                        remember_pending_as_unknown_app = false;
                        reason = Some(format!(
                            "SDK Rule [{}]: Pending user decision",
                            finding.rule_name
                        ));
                    }
                    crate::sdk::RuleAction::Terminate => {
                        should_forward = false;
                        Self::terminate_process(pid);
                        reason = Some(format!("SDK Rule [{}]: Terminated", finding.rule_name));
                    }
                    crate::sdk::RuleAction::Quarantine => {
                        should_forward = false;
                        let quarantine_reason =
                            format!("SDK Rule [{}]: {}", finding.rule_name, finding.description);
                        Self::quarantine_file(&app_info.path, &quarantine_reason);
                        reason = Some(format!("SDK Rule [{}]: Quarantined", finding.rule_name));
                    }
                    crate::sdk::RuleAction::KillAndRemove => {
                        should_forward = false;
                        Self::terminate_process(pid);
                        let quarantine_reason =
                            format!("SDK Rule [{}]: {}", finding.rule_name, finding.description);
                        Self::quarantine_file(&app_info.path, &quarantine_reason);
                        reason = Some(format!(
                            "SDK Rule [{}]: Killed and Removed",
                            finding.rule_name
                        ));
                    }
                    _ => {}
                }
            }
        }

        // 10c. TLS PROXY ENFORCEMENT (QUIC blocking)
        // The embedded proxy handles its own packet capture — no redirection needed here.
        Self::enforce_tls_proxy_mode(
            &info,
            outbound,
            &tls_proxy_cfg,
            &mut should_forward,
            &mut reason,
        );

        // 11. Finalize Pending Decision (Trigger prompt if still unknown)
        if app_decision == AppDecision::Pending && !no_alert_mode {
            let enqueued = am.enqueue_pending_app(
                PendingApp {
                    process_id: pid,
                    name: app_name.clone(),
                    path: app_info.path.clone(),
                    dst_ip: info.dst_ip,
                    dst_port: info.dst_port,
                    protocol: info.protocol.clone(),
                    hostname: info.hostname.clone(),
                    reason: reason.clone(),
                    request_id: None,
                    alert_source: website_decision_key.as_ref().map(|_| "website".to_string()),
                    alert_kind: website_decision_key
                        .as_ref()
                        .map(|_| "malicious_website".to_string()),
                    target: website_target
                        .clone()
                        .or_else(|| info.full_url.clone())
                        .or_else(|| info.hostname.clone())
                        .or_else(|| Some(format!("{}:{}", info.dst_ip, info.dst_port))),
                    decision_key: website_decision_key.clone(),
                    full_url: info.full_url.clone(),
                    http_method: info.http_method.clone(),
                    http_path: info.http_path.clone(),
                    http_user_agent: info.http_user_agent.clone(),
                    http_content_type: info.http_content_type.clone(),
                    http_referer: info.http_referer.clone(),
                    http_request_body: info.http_request_body.clone(),
                    http_response_body: info.http_response_body.clone(),
                    payload_sample: info.payload_sample.clone(),
                    detected_file_type: info.detected_file_type.clone(),
                    packet_json: serde_json::to_string_pretty(&info).ok(),
                    queue_position: 1,
                    queue_total: 1,
                },
                remember_pending_as_unknown_app,
            );
            if enqueued {
                Self::refresh_active_alert_ui(am, tx);
            }
        }

        stats.packets_total.fetch_add(1, Ordering::Relaxed);
        if is_dns_query {
            if let Some(domain) = dns_domain.clone().or_else(|| info.hostname.clone()) {
                dns_handler.log_query(domain.clone(), !should_forward);

                // Record which app queried this domain — skip proxy-originated DNS
                // (src_port == listen_port) so we preserve the original requester.
                if outbound && pid != 0 {
                    let is_proxy_dns = tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy
                        && info.src_port == tls_proxy_cfg.listen_port;
                    if !is_proxy_dns {
                        dns_handler.record_domain_pid(domain.clone(), pid, app_info.name.clone());
                    }
                }

                // DNS Snooping: extract IP addresses from the answer if this is a response
                if info.src_port == 53 && payload_offset < data_vec.len() {
                    let dns_payload = &data_vec[payload_offset..];
                    let ips = Self::parse_dns_answers(dns_payload);
                    for (ip, _) in ips {
                        dns_handler.update_ip_map(ip, domain.clone());
                    }
                }
            }
        }

        if should_forward {
            stats.packets_allowed.fetch_add(1, Ordering::Relaxed);

            if Self::is_tls_proxy_intercept_candidate(&info, outbound, &tls_proxy_cfg) {
                Self::emit_tls_proxy_intercept_probe(
                    tx,
                    am,
                    dns_handler,
                    &info,
                    &tls_proxy_cfg,
                    no_alert_mode,
                    windows_root_trust_ready,
                    firefox_policy_ready,
                    browser_mitm_warning_cache,
                );
            }

            // The embedded proxy makes upstream connections from registered
            // ephemeral source ports.
            let is_proxy_traffic = outbound
                && tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy
                && http_mitm_proxy::is_registered_upstream_local_port(info.src_port);

            // Proxy-originated upstream connections bypass the rate limiter so every
            // intercepted flow is visible. All other traffic stays rate-limited to 500ms.
            let now = Self::now_ts();
            let last = stats.last_allowed_log_time.load(Ordering::Relaxed);

            let should_log = is_proxy_traffic || {
                now > last + 500
                    && stats
                        .last_allowed_log_time
                        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
            };

            if should_log && !show_blocked_only {
                let mut context = Self::format_packet_context(&info);

                // DNS Snooping context enrichment
                if let Some(domain) = dns_handler.resolve_ip(&info.dst_ip.to_string()) {
                    if !context.contains(&domain) {
                        context = format!("host={} | {}", domain, context);
                    }
                } else if let Some(domain) = dns_handler.resolve_ip(&info.src_ip.to_string()) {
                    if !context.contains(&domain) {
                        context = format!("host={} | {}", domain, context);
                    }
                }

                // For proxy-originated traffic, look up which app originally queried
                // this hostname so the log shows the real requester, not the engine PID.
                let allow_reason = if is_proxy_traffic {
                    let attributed = info
                        .hostname
                        .as_deref()
                        .and_then(|h| dns_handler.resolve_domain_pid(h))
                        .or_else(|| {
                            dns_handler
                                .resolve_ip(&info.dst_ip.to_string())
                                .and_then(|h| dns_handler.resolve_domain_pid(&h))
                        });
                    match attributed {
                        Some((orig_pid, orig_name)) => format!(
                            "App Allowed: {} (pid={}, via embedded proxy)",
                            orig_name, orig_pid
                        ),
                        None => "App Allowed: (via embedded proxy)".to_string(),
                    }
                } else {
                    reason
                        .clone()
                        .unwrap_or_else(|| "Allowed (no matching rule)".to_string())
                };

                emit_log_event(
                    &tx,
                    LogEntry {
                        id: format!("{}-allow", now),
                        timestamp: now,
                        level: LogLevel::Success,
                        message: format!("{} | {}", allow_reason, context),
                    },
                );
            }
        } else {
            stats.packets_blocked.fetch_add(1, Ordering::Relaxed);

            let now = Self::now_ts();
            let last = stats.last_log_time.load(Ordering::Relaxed);

            if now > last + 50 {
                if stats
                    .last_log_time
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let mut context = Self::format_packet_context(&info);

                    if let Some(domain) = dns_handler.resolve_ip(&info.dst_ip.to_string()) {
                        if !context.contains(&domain) {
                            context = format!("host={} | {}", domain, context);
                        }
                    } else if let Some(domain) = dns_handler.resolve_ip(&info.src_ip.to_string()) {
                        if !context.contains(&domain) {
                            context = format!("host={} | {}", domain, context);
                        }
                    }

                    let log_reason = reason
                        .clone()
                        .map(|r| {
                            if r.starts_with("App Allowed") {
                                r.replacen("App Allowed", "App Blocked", 1)
                            } else {
                                r
                            }
                        })
                        .unwrap_or_else(|| "Blocked".to_string());
                    emit_log_event(
                        &tx,
                        LogEntry {
                            id: format!("{}-blocked", now),
                            timestamp: now,
                            level: LogLevel::Info,
                            message: format!(
                                "Firewall activity: blocked network | {} | {}",
                                log_reason, context
                            ),
                        },
                    );
                }
            }
        }

        let mut final_forward = should_forward;
        let mut final_reason = reason.unwrap_or_else(|| "Allowed (no matching rule)".to_string());

        if log_mode && !final_forward {
            final_forward = true;
            final_reason = format!("[LOG-ONLY] {}", final_reason);
        }

        PacketDecision {
            packet_data: data_vec,
            address_data: address_data.to_vec(),
            should_forward: final_forward,
            recalc_checksums: false,
            _reason: final_reason,
        }
    }

    pub fn get_sdk_rules(&self) -> Vec<crate::sdk::SdkRule> {
        let sdk = self.sdk.read().unwrap();
        sdk.rules.clone()
    }

    pub fn get_rules_raw(&self) -> String {
        #[cfg(target_os = "windows")]
        if let Some(path) = self.get_sdk_rules_path_from_registry() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                return content;
            }
        }
        std::fs::read_to_string("rules/rules.yaml").unwrap_or_default()
    }

    pub fn save_rules_raw(&self, content: String) -> Result<(), String> {
        if let Err(e) = serde_yaml::from_str::<crate::sdk::SdkRuleFile>(&content) {
            return Err(format!("Invalid YAML: {}", e));
        }
        #[cfg(target_os = "windows")]
        if let Some(path) = self.get_sdk_rules_path_from_registry() {
            return std::fs::write(&path, content).map_err(|e| e.to_string());
        }
        let _ = std::fs::create_dir_all("rules");
        std::fs::write("rules/rules.yaml", content).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    fn get_sdk_rules_path_from_registry(&self) -> Option<PathBuf> {
        use winreg::RegKey;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK")
            .ok()
            .and_then(|key| key.get_value::<String, _>("RULES_PATH").ok())
            .map(PathBuf::from)
    }

    pub fn validate_rules_raw(&self, content: String) -> Result<String, String> {
        match serde_yaml::from_str::<crate::sdk::SdkRuleFile>(&content) {
            Ok(_) => Ok("YAML Syntax is Valid.".to_string()),
            Err(e) => Err(format!("Syntax Error: {}", e)),
        }
    }

    fn alert_window_size<R: Runtime>(app: &AppHandle<R>) -> (f64, f64) {
        if let Some(engine) = app.try_state::<Arc<FirewallEngine>>() {
            if let Some(alert) = engine.get_active_alert() {
                let text_load = alert.name.len()
                    + alert.path.len()
                    + alert.reason.as_ref().map(|v| v.len()).unwrap_or(0)
                    + alert.target.as_ref().map(|v| v.len()).unwrap_or(0)
                    + alert.hostname.as_ref().map(|v| v.len()).unwrap_or(0);
                let is_registry_alert = alert.alert_kind.as_deref() == Some("registry");
                let width = if is_registry_alert {
                    680.0
                } else if text_load > 220 {
                    620.0
                } else {
                    560.0
                };
                let base_height = if is_registry_alert { 320.0 } else { 280.0 };
                let extra_lines = (text_load / 80) as f64;
                let height = (base_height + extra_lines * 16.0).clamp(base_height, 460.0);
                return (width, height);
            }
        }
        (560.0, 280.0)
    }

    fn alert_window_position<R: Runtime>(
        app: &AppHandle<R>,
        width: f64,
        height: f64,
    ) -> Option<(f64, f64)> {
        let monitor = app.primary_monitor().ok().flatten()?;
        let size = monitor.size();
        let scale = monitor.scale_factor();
        let monitor_w = (size.width as f64) / scale;
        let monitor_h = (size.height as f64) / scale;
        Some((monitor_w - width - 20.0, monitor_h - height - 60.0))
    }

    pub fn spawn_alert_window<R: Runtime>(app: &AppHandle<R>) {
        let (width, height) = Self::alert_window_size(app);
        let alert_position = Self::alert_window_position(app, width, height);

        // Window already exists (pre-warmed or reused): resize, reposition, show.
        if let Some(win) = app.get_webview_window("firewall-alert") {
            let mut reused_ok = win
                .set_size(Size::Logical(LogicalSize::new(width, height)))
                .is_ok();
            if let Some((x, y)) = alert_position {
                reused_ok &= win
                    .set_position(Position::Logical(LogicalPosition::new(x, y)))
                    .is_ok();
            }
            reused_ok &= win.show().is_ok();

            if reused_ok {
                reused_ok &= win.set_focus().is_ok();
            }

            if reused_ok {
                return;
            }

            let _ = win.close();
            std::thread::sleep(Duration::from_millis(60));
        }

        // Fallback: create window from scratch (should not normally be reached after prewarm).
        let builder = WebviewWindowBuilder::new(
            app,
            "firewall-alert",
            WebviewUrl::App("index.html?mode=alert".into()),
        )
        .title("HydraDragon Firewall Alert")
        .inner_size(width, height)
        .resizable(false)
        .always_on_top(true)
        .decorations(false)
        .transparent(true)
        .shadow(true);

        if let Some((x, y)) = alert_position {
            if let Ok(win) = builder.position(x, y).build() {
                let _ = win.show();
                let _ = win.set_focus();
            }
        } else if let Ok(win) = builder.build() {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }

    /// Create the alert window hidden at startup so it is fully loaded and its
    /// event listener is already registered when the first alert arrives.
    /// This eliminates WebView2 init + Wasm startup latency from alert display.
    pub fn prewarm_alert_window<R: Runtime>(app: &AppHandle<R>) {
        if app.get_webview_window("firewall-alert").is_some() {
            return;
        }
        let builder = WebviewWindowBuilder::new(
            app,
            "firewall-alert",
            WebviewUrl::App("index.html?mode=alert".into()),
        )
        .title("HydraDragon Firewall Alert")
        .inner_size(560.0, 280.0)
        .resizable(false)
        .always_on_top(true)
        .decorations(false)
        .transparent(true)
        .shadow(true)
        .visible(false);

        if let Some((x, y)) = Self::alert_window_position(app, 560.0, 280.0) {
            let _ = builder.position(x, y).build();
        } else {
            let _ = builder.build();
        }
    }

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn terminate_process(pid: u32) {
        if pid == 0 || pid == 4 {
            return;
        }
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                let _ = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
            }
        }
    }

    fn build_quarantine_destination(src: &Path, qdir: &Path) -> PathBuf {
        let filename = src
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("quarantined_file");
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let prefix = format!("{}_{}", ts.as_secs(), ts.subsec_nanos());

        let mut counter = 0_u32;
        loop {
            let suffix = if counter == 0 {
                String::new()
            } else {
                format!("_{counter}")
            };
            let dst = qdir.join(format!("{prefix}_{filename}{suffix}.hqf"));
            if !dst.exists() {
                return dst;
            }
            counter = counter.saturating_add(1);
        }
    }

    fn quarantine_file(path: &str, detection: &str) {
        if path.is_empty() || path.to_lowercase() == "unknown" || path.to_lowercase() == "system" {
            return;
        }
        let src = Path::new(path);
        if !src.exists() {
            return;
        }

        let qdir = PathBuf::from(QUARANTINE_PATH);
        let _ = fs::create_dir_all(&qdir);
        let dst = Self::build_quarantine_destination(src, &qdir);
        let sha256 = compute_sha256(src).unwrap_or_else(|_| "unknown".to_string());

        if write_quarantine_file(src, &dst, detection, &sha256).is_ok() {
            if let Ok(metadata) = fs::metadata(src) {
                let mut permissions = metadata.permissions();
                if permissions.readonly() {
                    permissions.set_readonly(false);
                    let _ = fs::set_permissions(src, permissions);
                }
            }
            let _ = fs::remove_file(src);
        }
    }

    fn extract_payload_text(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }
        match std::str::from_utf8(bytes) {
            Ok(s) => Some(s.to_string()),
            Err(_) => Some(String::from_utf8_lossy(bytes).to_string()),
        }
    }

    fn discover_urls_and_domains(bytes: &[u8]) -> (Vec<String>, Vec<String>) {
        let mut urls = Vec::new();
        let mut domains = Vec::new();

        if let Some(text) = Self::extract_payload_text(bytes) {
            let mut seen = HashSet::new();
            for m in URL_REGEX.find_iter(&text) {
                let url = m.as_str().trim_matches(|c: char| c == '"' || c == '\'');
                if seen.insert(url.to_string()) {
                    urls.push(url.to_string());
                }
                if urls.len() >= 8 {
                    break;
                }
            }

            for m in DOMAIN_TOKEN_REGEX.find_iter(&text) {
                let domain = m
                    .as_str()
                    .trim_matches(|c: char| c == '.' || c == '[' || c == ']');
                if seen.insert(domain.to_string()) {
                    domains.push(domain.to_string());
                }
                if domains.len() >= 8 {
                    break;
                }
            }
        }

        (urls, domains)
    }

    fn parse_packet(
        data: &[u8],
        outbound: bool,
        process_id: u32,
        cache: &AppInfoCache,
    ) -> Option<(PacketInfo, usize)> {
        if data.is_empty() {
            return None;
        }
        let ip_version = (data[0] >> 4) & 0x0F;

        let (protocol, src_ip, dst_ip, header_len) = match ip_version {
            4 => {
                if data.len() < 20 {
                    // println!("DEBUG: Packet too short for IPv4: {}", data.len());
                    return None;
                }
                let protocol = match data[9] {
                    6 => Protocol::TCP,
                    17 => Protocol::UDP,
                    1 => Protocol::ICMP,
                    n => Protocol::Raw(n),
                };

                let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
                let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
                let header_len = ((data[0] & 0x0F) as usize) * 4;
                (protocol, src_ip, dst_ip, header_len)
            }
            6 => {
                if data.len() < 40 {
                    // println!("DEBUG: Packet too short for IPv6: {}", data.len());
                    return None;
                }
                let protocol = match data[6] {
                    6 => Protocol::TCP,
                    17 => Protocol::UDP,
                    58 => Protocol::ICMP,
                    n => Protocol::Raw(n),
                };

                let src_bytes: [u8; 16] = data[8..24].try_into().ok()?;
                let dst_bytes: [u8; 16] = data[24..40].try_into().ok()?;
                let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
                let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));
                (protocol, src_ip, dst_ip, 40)
            }
            _ => {
                // println!("DEBUG: Unknown IP version: {}", ip_version);
                return None;
            }
        };

        let (src_port, dst_port) = if header_len + 4 <= data.len() {
            match protocol {
                Protocol::TCP | Protocol::UDP => (
                    u16::from_be_bytes([data[header_len], data[header_len + 1]]),
                    u16::from_be_bytes([data[header_len + 2], data[header_len + 3]]),
                ),
                _ => (0, 0),
            }
        } else {
            (0, 0)
        };

        let mut payload_start = header_len;
        if matches!(protocol, Protocol::TCP) {
            let tcp_header_start = header_len;
            let tcp_data_offset = if tcp_header_start + 12 < data.len() {
                ((data[tcp_header_start + 12] >> 4) as usize) * 4
            } else {
                20
            };
            payload_start = header_len + tcp_data_offset;
        } else if matches!(protocol, Protocol::UDP) {
            payload_start = header_len + 8;
        }

        let mut hostname = None;
        let mut full_url = None;
        let mut dns_query = None;
        let mut tls_handshake = false;
        let mut http_method = None;
        let mut http_path = None;
        let mut http_user_agent = None;
        let mut http_content_type = None;
        let mut http_referer = None;
        let payload_entropy = None;
        let mut payload_sample = None;
        let mut payload_bytes: Option<&[u8]> = None;
        let mut payload_urls: Vec<String> = Vec::new();
        let mut payload_domains: Vec<String> = Vec::new();

        // Extract hostname and URL from TCP payloads
        if matches!(protocol, Protocol::TCP) && payload_start < data.len() {
            if payload_start < data.len() {
                let payload = &data[payload_start..];
                payload_bytes = Some(payload);

                // Check for HTTPS (port 443) - TLS SNI extraction
                if dst_port == 443 || src_port == 443 {
                    tls_handshake = crate::tls_parser::is_tls_handshake(payload);
                    if let Some(sni_host) = crate::tls_parser::extract_sni(payload) {
                        // Treat HTTPS SNI as a URL root so downstream hostname/url
                        // checks work the same way they do for HTTP payloads.
                        full_url.get_or_insert_with(|| format!("https://{}/", sni_host));
                        hostname.get_or_insert(sni_host);
                    }
                }

                // Check for HTTP regardless of port if the payload looks like HTTP traffic
                if crate::http_parser::is_http_request(payload) || dst_port == 80 || src_port == 80
                {
                    let hinted_port = if outbound { dst_port } else { src_port };
                    if let Some(http_info) =
                        crate::http_parser::extract_http_info(payload, Some(hinted_port))
                    {
                        hostname = http_info.host.clone().or(hostname);
                        full_url = http_info.full_url.or(full_url);
                        http_method = Some(http_info.method);
                        http_path = Some(http_info.path);
                        http_user_agent = http_info.user_agent;
                        http_content_type = http_info.content_type;
                        http_referer = http_info.referer;
                    }
                }
            }
        }

        // Extract DNS question names from UDP DNS traffic
        if matches!(protocol, Protocol::UDP)
            && (src_port == 53 || dst_port == 53)
            && payload_start <= data.len()
        {
            let dns_payload = &data[payload_start..];
            dns_query = Self::parse_dns_query(dns_payload);
            payload_bytes = Some(dns_payload);
        }

        if payload_bytes.is_none() {
            // For non-TCP/UDP payloads, fall back to bytes after the IP header when possible
            if header_len < data.len() {
                payload_bytes = Some(&data[header_len..]);
            }
        }

        if let Some(bytes) = payload_bytes {
            if !bytes.is_empty() {
                let preview: Vec<String> = bytes
                    .iter()
                    .take(32)
                    .map(|b| format!("{:02X}", b))
                    .collect();
                payload_sample = Some(preview.join(" "));

                let (urls, domains) = Self::discover_urls_and_domains(bytes);
                payload_urls = urls;
                payload_domains = domains;
            }
        }

        if hostname.is_none() {
            hostname = dns_query.clone();
        }

        if hostname.is_none() {
            if let Some(domain) = payload_domains.first() {
                hostname = Some(domain.clone());
            }
        }

        Some((
            PacketInfo {
                timestamp: Self::now_ts(),
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                size: data.len(),
                outbound,
                process_id,
                dns_query,
                hostname,
                full_url,
                tls_handshake,
                http_method,
                http_path,
                http_user_agent,
                http_content_type,
                http_referer,
                payload_entropy,
                payload_sample,
                payload_urls,
                payload_domains,
                image_path: cache.get_info(process_id).path,
                detected_file_type: None,
                http_request_body: None,
                http_response_body: None,
            },
            payload_start,
        ))
    }

    fn format_packet_context(info: &PacketInfo) -> String {
        let mut parts = vec![format!(
            "{}:{} -> {}:{}",
            info.src_ip, info.src_port, info.dst_ip, info.dst_port
        )];

        parts.push(format!(
            "proto={}{}",
            info.protocol.label(),
            if info.outbound {
                " outbound"
            } else {
                " inbound"
            }
        ));
        parts.push(format!("pid={}", info.process_id));
        parts.push(format!("bytes={}", info.size));

        if let Some(ref host) = info.hostname {
            parts.push(format!("host={}", host));
        }
        if let Some(ref url) = info.full_url {
            parts.push(format!("url={}", url));
        }
        if let Some(ref method) = info.http_method {
            parts.push(format!("method={}", method));
        }
        if let Some(ref path) = info.http_path {
            parts.push(format!("path={}", path));
        }
        if let Some(ref ua) = info.http_user_agent {
            parts.push(format!("ua={}", ua));
        }
        if let Some(ref ct) = info.http_content_type {
            parts.push(format!("ctype={}", ct));
        }
        if let Some(ref referer) = info.http_referer {
            parts.push(format!("referer={}", referer));
        }
        if let Some(ref dns) = info.dns_query {
            parts.push(format!("dns={}", dns));
        }
        if let Some(entropy) = info.payload_entropy {
            parts.push(format!("H={:.2}", entropy));
        }
        if let Some(ref sample) = info.payload_sample {
            parts.push(format!("hex={}", sample));
        }
        if !info.payload_urls.is_empty() {
            let summary: Vec<String> = info.payload_urls.iter().take(3).cloned().collect();
            parts.push(format!("urls={}", summary.join(",")));
        }
        if !info.payload_domains.is_empty() {
            let summary: Vec<String> = info.payload_domains.iter().take(3).cloned().collect();
            parts.push(format!("domains={}", summary.join(",")));
        }

        parts.join(" | ")
    }

    fn shannon_entropy(bytes: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }

        let len = bytes.len() as f64;
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    fn parse_dns_query(payload: &[u8]) -> Option<String> {
        // Basic DNS header is 12 bytes, bail out if shorter
        if payload.len() < 12 {
            return None;
        }

        let qd_count = u16::from_be_bytes([payload[4], payload[5]]);
        if qd_count == 0 {
            return None;
        }

        let mut offset = 12usize;
        let mut labels = Vec::new();

        // Parse a single question name (ignoring compression for simplicity)
        while offset < payload.len() {
            let len = payload[offset] as usize;
            offset += 1;

            if len == 0 {
                break;
            }
            if offset + len > payload.len() {
                return None;
            }

            labels.push(String::from_utf8_lossy(&payload[offset..offset + len]).to_string());
            offset += len;
        }

        if labels.is_empty() {
            None
        } else {
            Some(labels.join("."))
        }
    }

    fn parse_dns_answers(payload: &[u8]) -> Vec<(String, String)> {
        if payload.len() < 12 {
            return Vec::new();
        }

        let qd_count = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let an_count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
        if an_count == 0 {
            return Vec::new();
        }

        // Helper to skip a name in DNS format
        fn skip_name(payload: &[u8], mut offset: usize) -> Option<usize> {
            while offset < payload.len() {
                let len = payload[offset] as usize;
                if len == 0 {
                    return Some(offset + 1);
                }
                if (len & 0xC0) == 0xC0 {
                    // Pointer
                    return Some(offset + 2);
                }
                offset += 1 + len;
            }
            None
        }

        let mut offset = 12usize;
        let mut results = Vec::new();

        // 1. Skip Questions
        for _ in 0..qd_count {
            offset = match skip_name(payload, offset) {
                Some(o) => o,
                None => break,
            };
            offset += 4; // Type (2) + Class (2)
        }

        // 2. Parse Answers
        for _ in 0..an_count {
            if offset >= payload.len() {
                break;
            }

            // Skip Name
            offset = match skip_name(payload, offset) {
                Some(o) => o,
                None => break,
            };

            if offset + 10 > payload.len() {
                break;
            }

            let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let rdlen = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlen > payload.len() {
                break;
            }

            if rtype == 1 && rdlen == 4 {
                // A Record (IPv4)
                let ip = format!(
                    "{}.{}.{}.{}",
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3]
                );
                results.push(ip);
            } else if rtype == 28 && rdlen == 16 {
                // AAAA Record (IPv6)
                let mut parts = Vec::new();
                for i in 0..8 {
                    parts.push(format!(
                        "{:x}",
                        u16::from_be_bytes([payload[offset + i * 2], payload[offset + i * 2 + 1]])
                    ));
                }
                results.push(parts.join(":"));
            }

            offset += rdlen;
        }

        results.into_iter().map(|ip| (ip, String::new())).collect()
    }
    /// Cleanly shuts down the firewall engine.
    ///
    /// 1. Sets stop_signal so all worker loops know to exit.
    /// 2. Calls WinDivertShutdown(Both) which immediately unblocks every
    ///    thread that is blocked in recv() — they will return an error,
    ///    see stop_signal == true, and break out of their loops.
    /// 3. Kills the embedded proxy backend process if running.
    ///
    /// Safe to call more than once; subsequent calls are no-ops.
    fn load_website_whitelists(&self) {
        let website_path = {
            let settings = self.settings.read().unwrap();
            if settings.website_path.is_empty() {
                default_website_path()
            } else {
                settings.website_path.clone()
            }
        };

        let mut networks = Vec::new();
        let mut load_network_csv = |path: PathBuf| {
            if !path.exists() {
                return;
            }

            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let entry = line.split(',').next().unwrap_or("").trim();
                    let entry_lower = entry.to_ascii_lowercase();
                    if entry.is_empty()
                        || matches!(
                            entry_lower.as_str(),
                            "entry" | "ip" | "ipv4" | "ipv6" | "address"
                        )
                    {
                        continue;
                    }

                    if entry.contains('.') || entry.contains(':') || entry.contains('/') {
                        networks.push(entry.to_string());
                    }
                }
            }
        };

        // --- Highest Priority: CIDR Whitelists (from CIDRWhiteListIPv4/IPv6.csv) ---
        // These are checked first in packet decisions through the merged CIDR index.
        // Reference-optimized variants are headerless, so header rows are filtered by value
        // instead of always skipping the first line.
        for filename in [
            "CIDRWhiteListIPv4.csv",
            "CIDRWhiteListIPv6.csv",
            "CIDRWhiteListIPv4.optimized.csv",
            "CIDRWhiteListIPv6.optimized.csv",
        ] {
            load_network_csv(PathBuf::from(&website_path).join(filename));
        }

        // Load IPv4 Whitelist (plain single IPs)
        load_network_csv(PathBuf::from(&website_path).join("WhiteListIPv4.csv"));

        // Load IPv6 Whitelist (plain single IPs)
        load_network_csv(PathBuf::from(&website_path).join("WhiteListIPv6.csv"));

        if !networks.is_empty() {
            let mut settings = self.settings.write().unwrap();
            settings.network_whitelist.extend(networks);
            settings.network_whitelist.sort();
            settings.network_whitelist.dedup();
            let mut network_whitelist_index = self.network_whitelist_index.write().unwrap();
            *network_whitelist_index = CidrIndex::from_cidrs(&settings.network_whitelist);
        }
    }

    pub fn stop(&self) {
        // Signal all worker loops to exit after their current recv() returns.
        self.stop_signal.store(true, Ordering::SeqCst);
        *self.hydranet_tx.lock().unwrap() = None;

        // Calling shutdown() unblocks all recv() calls immediately with an error.
        // shutdown() takes &mut self but Arc only yields &T via Deref.
        // Safety: stop_signal is already true so workers will exit on their next
        // loop check. WinDivert shutdown() is specifically designed to be called
        // concurrently from a different thread — that is its entire purpose.
        if let Some(d) = self.divert_handle.lock().unwrap().take() {
            let ptr =
                Arc::as_ptr(&d.0) as *mut windivert::WinDivert<windivert::prelude::NetworkLayer>;
            unsafe {
                let _ = (*ptr).shutdown(WinDivertShutdownMode::Both);
            }
        }

        self.stop_embedded_proxy();
    }
}

impl Drop for FirewallEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        if let Ok(target_ip) = cidr.parse::<IpAddr>() {
            return ip == target_ip;
        }
        return false;
    }
    let Ok(prefix_len) = parts[1].parse::<u32>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            let Ok(net) = parts[0].parse::<Ipv4Addr>() else {
                return false;
            };
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                let shift = 32u32.checked_sub(prefix_len).unwrap_or(0);
                if shift >= 32 { 0 } else { !0u32 << shift }
            };
            (u32::from(v4) & mask) == (u32::from(net) & mask)
        }
        IpAddr::V6(v6) => {
            let Ok(net) = parts[0].parse::<Ipv6Addr>() else {
                return false;
            };
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                let shift = 128u32.checked_sub(prefix_len).unwrap_or(0);
                if shift >= 128 { 0 } else { !0u128 << shift }
            };
            (u128::from(v6) & mask) == (u128::from(net) & mask)
        }
    }
}
