use crate::file_magic::FileMagicChecker;

use crate::web_filter::WebFilter;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Position, Runtime, Size, WebviewUrl, WebviewWindowBuilder};
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
    let is_drive_path = chars.len() >= 3 && chars[1] == ':' && (chars[2] == '\\' || chars[2] == '/');
    let is_unc_path = normalized.starts_with("\\\\");
    let is_nt_path = lower.starts_with("\\device\\") || lower.starts_with("\\??\\") || lower.starts_with("\\\\?\\");

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
    /// Decrypted HTTP request body captured by the MITM proxy (UTF-8 text or hex)
    pub http_request_body: Option<String>,
    /// Decrypted HTTP response body captured by the MITM proxy (UTF-8 text or hex)
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

fn default_queue_position() -> usize {
    1
}

fn default_queue_total() -> usize {
    1
}

fn firewall_data_dir() -> PathBuf {
    if let Ok(program_data) = std::env::var("PROGRAMDATA") {
        return PathBuf::from(program_data)
            .join("HydraDragonAntivirus")
            .join("HydraDragonFirewall");
    }

    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn firewall_log_file_path() -> PathBuf {
    firewall_data_dir().join("logs").join("firewall_activity.jsonl")
}

fn default_website_path() -> String {
    let repo_path = PathBuf::from("hydradragon").join("website");
    if repo_path.exists() {
        return repo_path.to_string_lossy().to_string();
    }

    let local_path = PathBuf::from("website");
    if local_path.exists() {
        return local_path.to_string_lossy().to_string();
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInspectionMode {
    MetadataOnly,
    TlsProxy,
}

impl Default for TlsInspectionMode {
    fn default() -> Self {
        TlsInspectionMode::TlsProxy
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsProxyConfig {
    pub mode: TlsInspectionMode,
    pub listen_host: String,
    pub listen_port: u16,
    pub block_quic_udp_443: bool,
    /// Whether to auto-start the embedded proxy when the firewall starts.
    pub auto_start: bool,
}

impl Default for TlsProxyConfig {
    fn default() -> Self {
        Self {
            mode: TlsInspectionMode::TlsProxy,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 8877,
            block_quic_udp_443: true,
            auto_start: true,
        }
    }
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
}

impl FirewallRule {
    pub fn matches(&self, packet: &PacketInfo, app_name: &str) -> bool {
        if !self.enabled {
            return false;
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
    pub no_alert_mode: bool,
    #[serde(default = "default_true")]
    pub save_all_logs: bool,
    #[serde(default = "default_true")]
    pub prune_old_logs: bool,
    #[serde(default = "default_max_visible_logs")]
    pub max_visible_logs: usize,
    pub tls_proxy: TlsProxyConfig,
    pub metadata: HashMap<String, String>,
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
            no_alert_mode: false,
            save_all_logs: true,
            prune_old_logs: true,
            max_visible_logs: default_max_visible_logs(),
            tls_proxy: TlsProxyConfig::default(),
            metadata,
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
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
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
                    let full_path = String::from_utf8_lossy(&ansi_buffer[..ansi_len as usize]).to_string();
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
    pub port_map: RwLock<HashMap<u16, u32>>,
    pub info_cache: AppInfoCache,
    pub url_cache: RwLock<HashMap<u32, String>>,
    pub active_alert: RwLock<Option<PendingApp>>,
    pub suspicious_pids: RwLock<HashSet<u32>>,
    /// Tracks which slot (0-based) the user is currently viewing, for the position counter.
    pub view_index: AtomicU64,
}

impl AppManager {
    pub fn new(initial_decisions: HashMap<String, AppDecision>) -> Self {
        Self {
            decisions: RwLock::new(initial_decisions),
            pending: RwLock::new(VecDeque::new()),
            known_apps: RwLock::new(HashSet::new()),
            port_map: RwLock::new(HashMap::new()),
            info_cache: AppInfoCache::new(),
            url_cache: RwLock::new(HashMap::new()),
            active_alert: RwLock::new(None),
            suspicious_pids: RwLock::new(HashSet::new()),
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
        if pid == std::process::id()
            || app_name_lower == "system"
            || pid == 0
            || pid == 4
        {
            return (AppDecision::Allow, app_name, app_path);
        }

        // Check decision cache: full image path takes priority, short name as fallback.
        {
            let decisions = self.decisions.read().unwrap();
            let app_path_lower = app_path.to_lowercase();
            if let Some(decision) = decisions
                .get(&app_path_lower)
                .or_else(|| decisions.get(&app_name_lower))
            {
                return (decision.clone(), app_name, app_path);
            }
        }

        // Check if new
        {
            let known = self.known_apps.read().unwrap();
            if !known.contains(&app_name_lower) {
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
    /// Retained so stop() can call shutdown() and unblock all recv() threads.
    pub divert_handle: Arc<Mutex<Option<WinDivertArc<windivert::prelude::NetworkLayer>>>>,
    pub hydranet_tx: Arc<Mutex<Option<std::sync::mpsc::Sender<String>>>>,
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
        // Expose the inner WinDivert handle so wrapper instances support all
        // WinDivert methods (e.g., send/recv) instead of just Arc methods.
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

        let app_decisions = settings_data.app_decisions.clone();
        let app_manager = Arc::new(AppManager::new(app_decisions));
        let rules = Arc::new(RwLock::new(settings_data.rules.clone()));
        let settings = Arc::new(RwLock::new(settings_data));
        let sdk = Arc::new(RwLock::new(crate::sdk::SdkRegistry::with_defaults()));
        let tls_proxy_backend_child = Arc::new(Mutex::new(None));
        let divert_handle = Arc::new(Mutex::new(None));
        let hydranet_tx = Arc::new(Mutex::new(None));

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
            divert_handle,
            hydranet_tx,
        }
    }

    pub fn load_settings() -> Option<FirewallSettings> {
        let path = PathBuf::from("settings.json");
        if let Ok(content) = fs::read_to_string(&path) {
            serde_json::from_str(&content).ok()
        } else {
            None
        }
    }

    pub fn apply_settings(&self, new_settings: FirewallSettings) {
        // Sync App Decisions
        {
            let mut decisions = self.app_manager.decisions.write().unwrap();
            *decisions = new_settings.app_decisions.clone();
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
    }

    pub fn save_settings(&self) {
        let current_settings = self.settings.read().unwrap();
        
        // Filter out AllowOnce decisions so they don't persist
        let mut decisions = self.app_manager.decisions.read().unwrap().clone();
        decisions.retain(|_, v| *v != AppDecision::AllowOnce);

        let settings = FirewallSettings {
            app_decisions: decisions,
            kernel_block_paths: current_settings.kernel_block_paths.clone(),
            website_path: current_settings.website_path.clone(),
            rules: self.rules.read().unwrap().clone(),
            late_blocking_mode: current_settings.late_blocking_mode,
            headless_mode: current_settings.headless_mode,
            log_mode: current_settings.log_mode,
            no_alert_mode: current_settings.no_alert_mode,
            save_all_logs: current_settings.save_all_logs,
            prune_old_logs: current_settings.prune_old_logs,
            max_visible_logs: current_settings.max_visible_logs,
            tls_proxy: current_settings.tls_proxy.clone(),
            metadata: current_settings.metadata.clone(),
        };

        if let Ok(content) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write("settings.json", content);
        }
    }

    pub fn is_loopback(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    fn is_proxy_host(ip: IpAddr, tls_proxy: &TlsProxyConfig) -> bool {
        if tls_proxy.listen_host.eq_ignore_ascii_case("localhost") {
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
            // stale "App Allowed: <name>" reason from the app-decision step, causing
            // BLOCK_EXE to be sent to owlyshield with a misleading reason and
            // resulting in the process being killed even though it was user-allowed.
            *reason = Some(
                "TLS Proxy Mode: blocked QUIC (UDP/443); embedded proxy handles TCP only"
                    .to_string(),
            );
        }
    }

    fn start_embedded_proxy(&self, tls_proxy: &TlsProxyConfig, tx: &AppHandle) {
        if tls_proxy.mode != TlsInspectionMode::TlsProxy || !tls_proxy.auto_start {
            return;
        }

        // Already running?
        if self.tls_proxy_backend_child.lock().unwrap().is_some() {
            return;
        }

        let addr: std::net::SocketAddr = format!(
            "{}:{}",
            tls_proxy.listen_host, tls_proxy.listen_port
        )
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:8877".parse().unwrap());

        let ca_bundle = crate::proxy::generate_ca();

        // Install the generated CA into Windows Trusted Root so browsers accept it.
        if let Err(e) = Self::install_ca_der(&ca_bundle.cert_der) {
            let now = Self::now_ts();
            emit_log_event(&tx, LogEntry {
                id: format!("{}-ca-install-warn", now),
                timestamp: now,
                level: LogLevel::Warning,
                message: format!("CA install skipped (run as admin to trust proxy cert): {}", e),
            });
        }

        // Set Windows system proxy so all apps route through us.
        let _ = Self::set_windows_proxy(&addr.to_string());

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        *self.tls_proxy_backend_child.lock().unwrap() = Some(stop_tx);

        let app = tx.clone();
        let sdk = self.sdk.clone();
        let settings = self.settings.clone();
        tauri::async_runtime::spawn(crate::proxy::run_proxy(
            addr,
            ca_bundle.issuer,
            app,
            sdk,
            settings,
            stop_rx,
        ));
    }

    fn stop_embedded_proxy(&self) {
        if let Some(tx) = self.tls_proxy_backend_child.lock().unwrap().take() {
            let _ = tx.send(());
        }
        // Clear Windows system proxy on shutdown.
        let _ = Self::clear_windows_proxy();
    }

    /// Point the Windows system HTTP+HTTPS proxy to our embedded listener.
    fn set_windows_proxy(addr: &str) -> Result<(), String> {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let (key, _) = hkcu
            .create_subkey(path)
            .map_err(|e| e.to_string())?;
        // `addr` is already "host:port" (e.g. "127.0.0.1:8877").
        // Route both HTTP and HTTPS through the embedded MITM proxy so we can
        // inspect both plaintext and TLS-intercepted traffic.
        key.set_value("ProxyServer", &format!("http={};https={}", addr, addr))
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| e.to_string())?;
        // Bypass the proxy for localhost to prevent infinite loops.
        key.set_value("ProxyOverride", &"localhost;127.0.0.1;<local>")
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Remove the system proxy settings we set on startup.
    fn clear_windows_proxy() -> Result<(), String> {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let (key, _) = hkcu
            .create_subkey(path)
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &0u32)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Install a raw DER certificate into the Windows LocalMachine\Root trust store.
    fn install_ca_der(der: &[u8]) -> Result<(), String> {
        use windows::Win32::Security::Cryptography::{
            CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreA,
            CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, X509_ASN_ENCODING,
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

    // CA auto-trust is handled natively via `install_ca_der` during proxy startup.

    pub fn send_hydranet_message(&self, message: String) {
        let tx_opt = self.hydranet_tx.lock().unwrap().clone();
        if let Some(tx) = tx_opt {
            let _ = tx.send(message);
        } else {
            eprintln!("[HydraNet] No active pipe writer available for outbound message");
        }
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

    fn refresh_active_alert_ui(am: &Arc<AppManager>, tx: &AppHandle) {
        if let Some(alert) = am.get_active_alert() {
            Self::spawn_alert_window(tx);
            let _ = tx.emit("ask_app_decision", alert);
        }
    }

    pub fn resolve_app_decision(&self, name: String, decision: String, tx: &AppHandle) {
        let active_alert = self.app_manager.active_alert.read().unwrap().clone();
        let mut persist_settings = true;
        let kernel_block_path = active_alert
            .as_ref()
            .and_then(select_kernel_block_path);
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
                let path = if !alert.path.trim().is_empty() && !alert.path.eq_ignore_ascii_case("unknown") {
                    Some(alert.path.clone())
                } else {
                    None
                };
                target
                    .or(path)
                    .unwrap_or_else(|| alert.name.clone())
            })
            .unwrap_or_else(|| name.clone());

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
                let msg = format!("HIPS_DECISION:{}|{}\n", request_id, decision.as_str());
                self.send_hydranet_message(msg);
            })
            .is_some();

        let app_decision = match decision.as_str() {
            "allow_always" => AppDecision::Allow,
            "allow_once" => AppDecision::AllowOnce,
            "quarantine" => AppDecision::Block,
            "block" => AppDecision::Block,
            _ => AppDecision::Pending,
        };

        if routed_to_owlyshield {
            // Mirror quarantine/block decisions to firewall for "predict block" security
            if app_decision == AppDecision::Block {
                self.app_manager.resolve_decision(&decision_identifier, app_decision);
                self.save_settings();
            }
            persist_settings = false;
        } else {
            self.app_manager
                .resolve_decision(&decision_identifier, app_decision);
        }

        if decision == "block" && let Some(path) = kernel_block_path.as_deref() {
            self.remember_kernel_block_path(path);
            self.send_hydranet_message(kernel_block_message(path));
        }

        let now = Self::now_ts();
        match decision.as_str() {
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
                    message: format!("Blocked: User decision for {} (quarantine requested)", decision_label),
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
        self.app_manager.remove_decision(&name_lower);
        self.save_settings();
    }

    pub fn clear_app_decisions(&self) {
        self.app_manager.clear_decisions();
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
        self.app_manager.decisions.read().unwrap().clone()
    }

    pub fn get_settings(&self) -> FirewallSettings {
        self.settings.read().unwrap().clone()
    }

    pub fn get_saved_logs(&self) -> Vec<LogEntry> {
        let settings = self.settings.read().unwrap().clone();
        if !settings.save_all_logs {
            return Vec::new();
        }

        let limit = if settings.prune_old_logs {
            Some(settings.max_visible_logs.max(1))
        } else {
            None
        };

        load_saved_logs(limit)
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
                // Prioritize the user's explicit request: "website"
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
        if tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy {
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

            self.start_embedded_proxy(&tls_proxy_cfg, &tx);
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
                    use windows::core::PCWSTR;
                    use windows::Win32::Foundation::{
                        CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, ERROR_PIPE_CONNECTED,
                    };
                    use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
                    use windows::Win32::System::Pipes::{
                        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                        GetNamedPipeClientProcessId, NAMED_PIPE_MODE, PIPE_UNLIMITED_INSTANCES,
                    };

                    let pipe_name = r"\\.\pipe\HydraHipEvent";
                    let wide_name: Vec<u16> = OsStr::new(pipe_name)
                        .encode_wide()
                        .chain(std::iter::once(0u16))
                        .collect();
                    let expected_client =
                        r"c:\program files\hydradragonantivirus\hydradragon\owlyshield\owlyshield service\owlyshield_ransom.exe";

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
                        let client_ok = unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) }.is_ok()
                            && client_pid != 0
                            && am_hips
                                .info_cache
                                .get_info(client_pid)
                                .path
                                .to_lowercase()
                                == expected_client;

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

                            leftover.push_str(&String::from_utf8_lossy(&buf[..bytes_read as usize]));

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
                                    let name = parts.next().unwrap_or("Owlyshield").trim().to_string();
                                    let path = parts.next().unwrap_or("").trim().to_string();
                                    let alert_kind = parts.next().unwrap_or("behavior").trim().to_string();
                                    let target = parts.next().unwrap_or("").trim().to_string();
                                    let reason = parts.next().unwrap_or("Owlyshield HIPS detection").trim().to_string();

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
                                                let _ = tx_hips.emit("ask_app_decision", active_alert);
                                            }
                                        }
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
            let am_pipe = Arc::clone(&am);
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
                                    let server_app = am_pipe.info_cache.get_info(server_pid);
                                    let expected_path = r"c:\program files\hydradragonantivirus\hydradragon\owlyshield\owlyshield service\owlyshield_ransom.exe";
                                    if server_app.path.to_lowercase() == expected_path {
                                        pipe_opt = Some(file);
                                    } else {
                                        println!("WARNING: Rejected unauthorized HydraNetEvent server: {}", server_app.path);
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
            let tx_log = app_handle.clone();
            let divert_w = divert.clone();
            let net_ev_tx = net_event_tx.clone();
            let raw_packet_tx_w = raw_packet_tx.clone();

            std::thread::Builder::new()
                .name(format!("packet_worker_{}", worker_id))
                .spawn(move || {
                    let mut buffer = vec![0u8; 65535];
                    let mut packet_count = 0u64;
                    // Per-worker dedup: only send one NET_EVENT per PID per session
                    let mut notified_pids: HashSet<u32> = HashSet::new();
                    // Per-worker dedup: only send one BLOCK_EXE per exe path per session
                    let mut notified_blocked_exes: HashSet<String> = HashSet::new();
                    while !stop_w.load(Ordering::Relaxed) {
                        // Each thread competition for packets on the shared handle
                        match divert_w.recv(Some(&mut buffer)) {
                            Ok(packet) => {
                                packet_count += 1;
                                if packet_count % 100 == 0 {
                                    let ts = Self::now_ts();
                                    emit_log_event(&tx_log, LogEntry {
                                        id: format!("{}-worker-{}-count", ts, worker_id),
                                        timestamp: ts,
                                        level: LogLevel::Info,
                                        message: format!("Worker {} received {} packets", worker_id, packet_count),
                                    });
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
                                );

                                // ── NET EVENT + BLOCK_EXE → BEHAVIOR ENGINE ─────────
                                // Both messages go to \\.\pipe\HydraNetEvent.
                                //
                                // NET_EVENT  — real outbound I/O observed (once per PID).
                                // BLOCK_EXE  — firewall confirmed malicious traffic from
                                let mut decision_info: Option<PacketInfo> = None;
                                if let Some((ref p_info, _)) = pre_parsed {
                                    decision_info = Some(p_info.clone());
                                }

                                if outbound && pid != 0 {
                                    if let Some(ref parsed_info) = decision_info {
                                        let exe_path = am_w.info_cache.get_info(pid).path;
                                        let exe_path_lc = exe_path.to_lowercase();
                                        let is_system = exe_path_lc.is_empty()
                                            || exe_path_lc == "unknown"
                                            || exe_path_lc == "system";

                                        // NET_EVENT — once per new PID
                                        if !notified_pids.contains(&pid) {
                                            let msg = format!(
                                                "NET_EVENT:{}:{}:{}\n",
                                                pid,
                                                parsed_info.dst_ip,
                                                parsed_info.dst_port
                                            );
                                            let _ = net_ev_tx.send(msg);
                                            notified_pids.insert(pid);
                                        }

                                        // BLOCK_EXE — once per exe path when firewall blocks
                                        // for a genuine security reason. Skip for:
                                        //  • "App Allowed: X" — user-trusted app whose packet
                                        //    was blocked by a later technical step (e.g. TLS
                                        //    proxy QUIC enforcement); escalating to owlyshield
                                        //    would wrongly kill a process the user approved.
                                        //  • "TLS Proxy Mode" — infrastructure block, not a
                                        //    security threat.
                                        //  • "Embedded proxy listener" / "Unparsed packet" —
                                        //    internal engine traffic, never security-relevant.
                                        let reason_lc = decision._reason.to_lowercase();
                                        let is_technical_block = reason_lc.contains("tls proxy")
                                            || reason_lc.contains("embedded proxy")
                                            || reason_lc.contains("unparsed packet");
                                        if !decision.should_forward
                                            && !is_system
                                            && !is_technical_block
                                            && !notified_blocked_exes.contains(&exe_path_lc)
                                        {
                                            let hostname = parsed_info.hostname
                                                .as_deref()
                                                .unwrap_or("")
                                                .replace('|', "/");
                                            let reason = decision._reason
                                                .replace('|', "/");
                                            let msg = format!(
                                                "BLOCK_EXE:{}|{}|{}|{}|{}\n",
                                                exe_path_lc,
                                                parsed_info.dst_ip,
                                                parsed_info.dst_port,
                                                hostname,
                                                reason,
                                            );
                                            let _ = net_ev_tx.send(msg);

                                            // FULL_PACKET — send complete PacketInfo as JSON so
                                            // Owlyshield can log every field for forensic visibility.
                                            if let Ok(json) = serde_json::to_string(parsed_info) {
                                                let full_msg = format!("FULL_PACKET:{}\n", json);
                                                let _ = net_ev_tx.send(full_msg);
                                            }

                                            notified_blocked_exes.insert(exe_path_lc);
                                        }
                                    }
                                }

                                // EMIT RAW PACKET FOR UI (Wireshark-like view)
                                // Use the info already parsed from the decision logic to avoid re-parsing
                                if let Some(info) = decision_info {
                                    let ts = Self::now_ts();
                                    let app_info = am_w.info_cache.get_info(pid);

                                    let payload_preview = if decision.packet_data.len() > 32 {
                                        format!(
                                            "{}...",
                                            String::from_utf8_lossy(&decision.packet_data[..32])
                                                .replace("\n", " ")
                                        )
                                    } else {
                                        String::from_utf8_lossy(&decision.packet_data)
                                            .replace("\n", " ")
                                    };

                                    let mut raw_packet = crate::sdk::RawPacket {
                                        id: format!("{}-{}-{}", ts, info.src_port, info.dst_port),
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
                                        raw_packet.summary = format!("{} ({})", raw_packet.summary, h);
                                    } else {
                                        // Snooping fallback for raw packet display
                                        if let Some(domain) = dns_w.resolve_ip(&info.dst_ip.to_string()) {
                                            raw_packet.hostname = Some(domain.clone());
                                            raw_packet.summary = format!("{} ({})", raw_packet.summary, domain);
                                        } else if let Some(domain) = dns_w.resolve_ip(&info.src_ip.to_string()) {
                                            raw_packet.hostname = Some(domain.clone());
                                            raw_packet.summary = format!("{} ({})", raw_packet.summary, domain);
                                        }
                                    }
                                    let _ = raw_packet_tx_w.try_send(raw_packet);
                                }

                                if decision.should_forward {
                                    // REINJECT IMMEDIATELY from the SAME thread
                                    let mut reinject_packet = windivert::packet::WinDivertPacket {
                                        address: packet.address,
                                        data: std::borrow::Cow::Owned(decision.packet_data),
                                    };
                                    if decision.recalc_checksums {
                                        let _ = reinject_packet.recalculate_checksums(Default::default());
                                    }
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
                                    emit_log_event(&tx_log, LogEntry {
                                        id: format!("{}-worker-{}-err-{}", ts, worker_id, packet_count),
                                        timestamp: ts,
                                        level: LogLevel::Error,
                                        message: format!("Worker {} Recv Error: {} (count: {})", worker_id, err_str, packet_count),
                                    });
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
        let (late_blocking_mode, tls_proxy_cfg, log_mode, no_alert_mode) = {
            let s = settings.read().unwrap();
            (s.late_blocking_mode, s.tls_proxy.clone(), s.log_mode, s.no_alert_mode)
        };

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
            for listener in &sdk_read.listeners {
                listener.on_packet(&data_vec, &info, &sdk_context);
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
            if outbound
                && Self::is_proxy_destination(&info, &tls_proxy_cfg)
            {
                let app_info_loopback = am.info_cache.get_info(pid);
                let host_label = info
                    .hostname
                    .clone()
                    .or_else(|| dns_handler.resolve_ip(&info.dst_ip.to_string()))
                    .unwrap_or_else(|| info.dst_ip.to_string());
                let now = Self::now_ts();
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

            return PacketDecision {
                packet_data: data_vec,
                address_data: address_data.to_vec(),
                should_forward: true,
                recalc_checksums: false,
                _reason: "Embedded proxy listener".to_string(),
            };
        }

        // Cache URLs by PID for subsequent packets in the same flow.
        if let Some(ref url) = info.full_url {
            am.url_cache.write().unwrap().insert(pid, url.clone());
        } else {
            if let Some(url) = am.url_cache.read().unwrap().get(&pid) {
                info.full_url = Some(url.clone());
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

        let is_dns_query = matches!(info.protocol, Protocol::UDP)
            && (info.src_port == 53 || info.dst_port == 53);
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
                    reason = Some(format!("Rule [{}]: {}", rule.name, rule.description));
                    
                    if rule.terminate || rule.kill_and_remove {
                        Self::terminate_process(pid);
                    }
                    if rule.quarantine || rule.kill_and_remove {
                        Self::quarantine_file(&app_info.path);
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

        let remote_ip = if info.outbound { info.dst_ip } else { info.src_ip };
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
                    reason = Some(format!("Website trusted: {}", web_match.target));
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
                    should_forward = true;
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
                        Self::quarantine_file(&app_info.path);
                        reason = Some(format!("SDK Rule [{}]: Quarantined", finding.rule_name));
                    }
                    crate::sdk::RuleAction::KillAndRemove => {
                        should_forward = false;
                        Self::terminate_process(pid);
                        Self::quarantine_file(&app_info.path);
                        reason = Some(format!("SDK Rule [{}]: Killed and Removed", finding.rule_name));
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
                    alert_source: website_decision_key
                        .as_ref()
                        .map(|_| "website".to_string()),
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

            // The embedded proxy makes outbound connections from the listen port.
            // Detect them by src_port so we can attribute them to the original app.
            let is_proxy_traffic = outbound
                && tls_proxy_cfg.mode == TlsInspectionMode::TlsProxy
                && info.src_port == tls_proxy_cfg.listen_port;

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

            if should_log {
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
                    let attributed = info.hostname.as_deref()
                        .and_then(|h| dns_handler.resolve_domain_pid(h))
                        .or_else(|| {
                            dns_handler.resolve_ip(&info.dst_ip.to_string())
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
                            level: LogLevel::Warning,
                            message: format!("Blocked: {} | {}", log_reason, context),
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
        std::fs::read_to_string("rules.yaml").unwrap_or_default()
    }

    pub fn save_rules_raw(&self, content: String) -> Result<(), String> {
        if let Err(e) = serde_yaml::from_str::<crate::sdk::SdkRuleFile>(&content) {
            return Err(format!("Invalid YAML: {}", e));
        }
        #[cfg(target_os = "windows")]
        if let Some(path) = self.get_sdk_rules_path_from_registry() {
            return std::fs::write(&path, content).map_err(|e| e.to_string());
        }
        std::fs::write("rules.yaml", content).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    fn get_sdk_rules_path_from_registry(&self) -> Option<PathBuf> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
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

    fn alert_window_size(app: &AppHandle) -> (f64, f64) {
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

    pub fn spawn_alert_window(app: &AppHandle) {
        let (width, height) = Self::alert_window_size(app);

        // Window already exists (pre-warmed or reused): resize, reposition, show.
        if let Some(win) = app.get_webview_window("firewall-alert") {
            let _ = win.set_size(Size::Logical(LogicalSize::new(width, height)));
            if let Ok(Some(monitor)) = app.primary_monitor() {
                let size = monitor.size();
                let scale = monitor.scale_factor();
                let monitor_w = (size.width as f64) / scale;
                let monitor_h = (size.height as f64) / scale;
                let x = monitor_w - width - 20.0;
                let y = monitor_h - height - 60.0;
                let _ = win.set_position(Position::Logical(LogicalPosition::new(x, y)));
            }
            let _ = win.show();
            let _ = win.set_focus();
            return;
        }

        // Fallback: create window from scratch (should not normally be reached after prewarm).
        let builder = WebviewWindowBuilder::new(app, "firewall-alert", WebviewUrl::App("index.html?mode=alert".into()))
            .title("HydraDragon Firewall Alert")
            .inner_size(width, height)
            .resizable(false)
            .always_on_top(true)
            .decorations(false)
            .transparent(true)
            .shadow(true);

        if let Ok(Some(monitor)) = app.primary_monitor() {
            let size = monitor.size();
            let scale = monitor.scale_factor();
            let monitor_w = (size.width as f64) / scale;
            let monitor_h = (size.height as f64) / scale;
            let x = monitor_w - width - 20.0;
            let y = monitor_h - height - 60.0;
            if let Ok(win) = builder.position(x, y).build() {
                let _ = win.show();
            }
        } else if let Ok(win) = builder.build() {
            let _ = win.show();
        }
    }

    /// Create the alert window hidden at startup so it is fully loaded and its
    /// event listener is already registered when the first alert arrives.
    /// This eliminates WebView2 init + Wasm startup latency from alert display.
    pub fn prewarm_alert_window(app: &AppHandle) {
        if app.get_webview_window("firewall-alert").is_some() {
            return;
        }
        let builder = WebviewWindowBuilder::new(app, "firewall-alert", WebviewUrl::App("index.html?mode=alert".into()))
            .title("HydraDragon Firewall Alert")
            .inner_size(560.0, 280.0)
            .resizable(false)
            .always_on_top(true)
            .decorations(false)
            .transparent(true)
            .shadow(true)
            .visible(false);

        if let Ok(Some(monitor)) = app.primary_monitor() {
            let size = monitor.size();
            let scale = monitor.scale_factor();
            let monitor_w = (size.width as f64) / scale;
            let monitor_h = (size.height as f64) / scale;
            let x = monitor_w - 560.0 - 20.0;
            let y = monitor_h - 280.0 - 60.0;
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
        if pid == 0 || pid == 4 { return; }
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                let _ = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
            }
        }
    }

    fn quarantine_file(path: &str) {
        if path.is_empty() || path.to_lowercase() == "unknown" || path.to_lowercase() == "system" {
            return;
        }
        let src = Path::new(path);
        if !src.exists() { return; }

        let qdir = firewall_data_dir().join("quarantine");
        let _ = fs::create_dir_all(&qdir);
        
        let fname = src.file_name().and_then(|n| n.to_str()).unwrap_or("quarantined_file");
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let dst = qdir.join(format!("{}_{}", ts, fname));

        let _ = fs::rename(src, dst);
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

        Some((PacketInfo {
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
        }, payload_start))
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

        results
            .into_iter()
            .map(|ip| (ip, String::new()))
            .collect()
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
    pub fn stop(&self) {
        // Signal all worker loops to exit after their current recv() returns.
        self.stop_signal.store(true, Ordering::SeqCst);
        *self.hydranet_tx.lock().unwrap() = None;

        // Calling shutdown() unblocks all recv() calls immediately with an error.
        // shutdown() takes &mut self but Arc only yields &T via Deref.
        // Safety: stop_signal is already true so workers will exit on their next
        // loop check. WinDivert shutdown() is explicitly designed to be called
        // concurrently from a different thread — that is its entire purpose.
        if let Some(d) = self.divert_handle.lock().unwrap().take() {
            let ptr = Arc::as_ptr(&d.0)
                as *mut windivert::WinDivert<windivert::prelude::NetworkLayer>;
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
