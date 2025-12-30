use crate::file_magic::FileMagicChecker;
use crate::injector::Injector;
use crate::web_filter::WebFilter;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use windivert::prelude::*;

lazy_static! {
    static ref URL_REGEX: Regex =
        Regex::new(r"(?i)https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+")
            .expect("failed to compile URL regex");
    static ref DOMAIN_TOKEN_REGEX: Regex =
        Regex::new(r"(?i)\b([a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,}\b")
            .expect("failed to compile domain token regex");
}
// Imports updated below

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
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppDecision {
    Pending,
    Allow,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingApp {
    pub process_id: u32,
    pub name: String,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: Protocol,
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
                if pattern == "any" || pattern == "*" || pattern == &remote_ip_str {
                    matched_ip = true;
                    break;
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
        if let Some(ref pattern) = self.hostname_pattern {
            if let Some(ref hostname) = packet.hostname {
                if !Self::wildcard_match(pattern, hostname) {
                    return false;
                }
            } else {
                // No hostname in packet but rule requires it
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallSettings {
    pub blocked_keywords: HashSet<String>, // New: Dynamic DNS blocking keywords
    pub app_decisions: HashMap<String, AppDecision>,
    pub website_path: String,
    pub rules: Vec<FirewallRule>,
    pub metadata: HashMap<String, String>,
    /// Optional DLL that can be injected into processes to enrich HTTPS visibility
    pub https_hook_dll: String,
    /// Whether to auto-inject the hook DLL for TLS Client Hello packets with no SNI/URL
    pub auto_inject_https: bool,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        let apps = HashMap::new();

        let mut keywords = HashSet::new();
        // Default bad keywords
        keywords.insert("malware".to_string());
        keywords.insert("virus".to_string());
        keywords.insert("trojan".to_string());
        keywords.insert("phishing".to_string());

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "2.0.0".to_string());
        metadata.insert(
            "description".to_string(),
            "HydraDragon Next-Gen Firewall Configuration".to_string(),
        );
        metadata.insert("theme".to_string(), "cyberpunk".to_string());

        let mut https_hook_dll = String::new();
        let mut auto_inject_https = false;
        if std::path::Path::new("hook_dll.dll").exists() {
            https_hook_dll = "hook_dll.dll".to_string();
            auto_inject_https = true;
        }

        Self {
            blocked_keywords: keywords,
            app_decisions: apps,
            website_path: String::new(),
            rules: Vec::new(),
            metadata,
            https_hook_dll,
            auto_inject_https,
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
    // No longer stores hardcoded blocked domains, reads from settings
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            queries: RwLock::new(VecDeque::new()),
        }
    }

    pub fn should_block(&self, domain: &str, settings: &FirewallSettings) -> bool {
        let domain_lower = domain.to_lowercase();

        // Check dynamic keywords from settings
        for pattern in &settings.blocked_keywords {
            if domain_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }
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
        let (name, path) = Injector::get_process_info(pid);
        let info = AppInfoContext { name, path };
        let mut cache = self.cache.write().unwrap();
        cache.insert(pid, (info.clone(), SystemTime::now()));

        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }

        info
    }
}

pub struct AppManager {
    pub decisions: RwLock<HashMap<String, AppDecision>>,
    pub pending: RwLock<VecDeque<PendingApp>>,
    pub known_apps: RwLock<HashSet<String>>,
    pub port_map: RwLock<HashMap<u16, u32>>,
    pub info_cache: AppInfoCache,
    pub url_cache: RwLock<HashMap<u32, String>>, // PID -> URL
    pub injected_pids: RwLock<HashSet<u32>>,     // Avoid repeated injections
    pub failed_pids: RwLock<HashSet<u32>>,       // PIDs where injection failed
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
            injected_pids: RwLock::new(HashSet::new()),
            failed_pids: RwLock::new(HashSet::new()),
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

        // Self-bypass
        if pid == std::process::id()
            || app_name_lower == "hydradragonfirewall.exe"
            || app_name_lower == "system"
            || pid == 0
            || pid == 4
        {
            return (AppDecision::Allow, app_name, app_path);
        }

        // Check decision cache
        {
            let decisions = self.decisions.read().unwrap();
            if let Some(decision) = decisions.get(&app_name_lower) {
                return (decision.clone(), app_name, app_path);
            }
        }

        // Add to pending if new
        {
            let mut known = self.known_apps.write().unwrap();
            if !known.contains(&app_name_lower) {
                known.insert(app_name_lower.clone());
                let mut pending = self.pending.write().unwrap();
                pending.push_back(PendingApp {
                    process_id: pid,
                    name: app_name.clone(),
                    dst_ip: packet.dst_ip,
                    dst_port: packet.dst_port,
                    protocol: packet.protocol.clone(),
                });
            }
        }

        (AppDecision::Pending, app_name, app_path)
    }
    pub fn resolve_decision(&self, name: &str, decision: AppDecision) {
        let name_lower = name.to_lowercase();
        let mut decisions = self.decisions.write().unwrap();
        decisions.insert(name_lower, decision);
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(
        dwDesiredAccess: u32,
        bInheritHandle: i32,
        dwProcessId: u32,
    ) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn QueryFullProcessImageNameW(
        hProcess: *mut std::ffi::c_void,
        dwFlags: u32,
        lpExeName: *mut u16,
        lpdwSize: *mut u32,
    ) -> i32;
}

// ============================================================================
// PACKET PROCESSING RESULT - Using raw bytes for cross-thread safety
// ============================================================================
#[allow(dead_code)]
struct PacketDecision {
    packet_data: Vec<u8>,
    address_data: Vec<u8>, // Serialized address for cross-thread safety
    should_forward: bool,
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
}

// RADICAL REFACTOR: Wrapper to make WinDivert Send + Sync (Safe for WinDivert handles)
struct WinDivertArc<L: windivert::layer::WinDivertLayerTrait>(Arc<WinDivert<L>>);
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

        let mut settings_data = Self::load_settings().unwrap_or_default();

        // Default allow rules are now handled in Default impl or loaded from disk.
        // We do NOT hardcode them here to allow user to override/remove them.
        if settings_data.rules.is_empty() {
            settings_data.rules.push(FirewallRule {
                name: "Block ICMP (Ping)".to_string(),
                description: "Blocks all incoming and outgoing ICMP echo requests.".to_string(),
                enabled: true,
                block: true,
                protocol: Some(Protocol::ICMP),
                remote_ips: vec![],
                remote_ports: vec![],
                app_name: None,
                hostname_pattern: None,
                url_pattern: None,
                file_types: vec![],
            });
        }

        let app_decisions = settings_data.app_decisions.clone();
        let app_manager = Arc::new(AppManager::new(app_decisions));
        let rules = Arc::new(RwLock::new(settings_data.rules.clone()));
        let settings = Arc::new(RwLock::new(settings_data));
        let sdk = Arc::new(RwLock::new(crate::sdk::SdkRegistry::with_defaults()));

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
        let settings = FirewallSettings {
            blocked_keywords: current_settings.blocked_keywords.clone(), // Save new field
            app_decisions: self.app_manager.decisions.read().unwrap().clone(),
            website_path: current_settings.website_path.clone(),
            rules: self.rules.read().unwrap().clone(),
            metadata: current_settings.metadata.clone(),
            https_hook_dll: current_settings.https_hook_dll.clone(),
            auto_inject_https: current_settings.auto_inject_https,
        };

        if let Ok(content) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write("settings.json", content);
        }
    }

    pub fn is_loopback(ip: Ipv4Addr) -> bool {
        ip.is_loopback() || ip == Ipv4Addr::new(127, 0, 0, 1) || ip == Ipv4Addr::new(0, 0, 0, 0)
    }

    pub fn resolve_app_decision(&self, name: String, decision: String) {
        let app_decision = match decision.as_str() {
            "Allow" => AppDecision::Allow,
            "Block" => AppDecision::Block,
            _ => AppDecision::Pending,
        };
        self.app_manager.resolve_decision(&name, app_decision);
        self.save_settings();
    }

    pub fn get_settings(&self) -> FirewallSettings {
        self.settings.read().unwrap().clone()
    }

    /// Resolve PID from port using Windows TCP/UDP extended tables
    pub fn resolve_pid_from_port(port: u16, is_tcp: bool) -> u32 {
        use std::mem::size_of;

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
                        "website".to_string()
                    } else {
                        s.website_path.clone()
                    }
                };

                let _ = tx_loader.emit(
                    "log",
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
                        let _ = tx_loader.emit(
                            "log",
                            LogEntry {
                                id: format!("{}-web-load-success", Self::now_ts()),
                                timestamp: Self::now_ts(),
                                level: LogLevel::Success,
                                message: format!("WebFilter Loaded: {} rules active.", count),
                            },
                        );
                    }
                    Err(e) => {
                        let _ = tx_loader.emit(
                            "log",
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
        // Use the network layer so packets can be reinjected after allow decisions.
        let divert = match WinDivert::network("true", 0, WinDivertFlags::new()) {
            Ok(d) => WinDivertArc(Arc::new(d)),
            Err(e) => {
                let ts = Self::now_ts();
                let _ = tx.emit(
                    "log",
                    LogEntry {
                        id: format!("{}-divert-fail", ts),
                        timestamp: ts,
                        level: LogLevel::Error,
                        message: format!("❌ WinDivert Open Failed: {:?}", e),
                    },
                );
                return;
            }
        };

        // PIPE MONITOR FOR HOOK DLL
        let am_pipe = Arc::clone(&am);
        std::thread::Builder::new()
            .name("pipe_monitor".to_string())
            .spawn(move || {
                use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
                use windows::Win32::System::Pipes::{
                    ConnectNamedPipe, CreateNamedPipeA, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
                    PIPE_WAIT,
                };
                let pipe_name = windows::core::s!("\\\\.\\pipe\\HydraDragonFirewall");
                loop {
                    unsafe {
                        let handle: windows::Win32::Foundation::HANDLE = CreateNamedPipeA(
                            pipe_name,
                            PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                            1,
                            1024,
                            1024,
                            0,
                            None,
                        )
                        .unwrap_or_default();

                        if !handle.is_invalid() {
                            if ConnectNamedPipe(handle, None).is_ok() {
                                let mut buffer = [0u8; 1024];
                                let mut bytes_read = 0;
                                if windows::Win32::Storage::FileSystem::ReadFile(
                                    handle,
                                    Some(&mut buffer),
                                    Some(&mut bytes_read),
                                    None,
                                )
                                .is_ok()
                                {
                                    let msg =
                                        String::from_utf8_lossy(&buffer[..bytes_read as usize])
                                            .to_string();

                                    let mut pid_val = None;
                                    if let Some(p_idx) = msg.find("PID:") {
                                        let pid_str: String = msg[p_idx + 4..]
                                            .chars()
                                            .take_while(|c| c.is_digit(10))
                                            .collect();
                                        pid_val = pid_str.parse::<u32>().ok();
                                    }

                                    if let Some(pid) = pid_val {
                                        if msg.contains("URL:") {
                                            if let Some(url_part) = msg.split("URL:").nth(1) {
                                                am_pipe
                                                    .url_cache
                                                    .write()
                                                    .unwrap()
                                                    .insert(pid, url_part.trim().to_string());
                                            }
                                        }
                                        if msg.contains("PORT:") {
                                            if let Some(port_part) = msg.split("PORT:").nth(1) {
                                                let port_str: String = port_part
                                                    .trim()
                                                    .chars()
                                                    .take_while(|c| c.is_digit(10))
                                                    .collect();
                                                if let Ok(port) = port_str.parse::<u16>() {
                                                    am_pipe.update_port_mapping(port, pid);
                                                }
                                            }
                                        }
                                    }
                                }
                                let _ = windows::Win32::Foundation::CloseHandle(handle);
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
            .expect("failed to spawn pipe_monitor thread");

        let ts = Self::now_ts();
        let _ = tx.emit(
            "log",
            LogEntry {
                id: format!("{}-divert-active", ts),
                timestamp: ts,
                level: LogLevel::Success,
                message: "🛡️ Firewall Engine ACTIVE (RADICAL Parallel Mode Enabled)".into(),
            },
        );

        // PENDING APP MONITOR THREAD
        // Checks for new unknown apps and asks the UI
        let am_monitor = Arc::clone(&am);
        let tx_monitor = app_handle.clone();

        std::thread::Builder::new()
            .name("pending_monitor".to_string())
            .spawn(move || {
                loop {
                    let mut app_opt = None;
                    {
                        // Pop one pending app at a time
                        if let Ok(mut pending) = am_monitor.pending.write() {
                            app_opt = pending.pop_front();
                        }
                    }

                    if let Some(app) = app_opt {
                        // 1. Emit data to all windows (Main + Alert)
                        let _ = tx_monitor.emit("ask_app_decision", app);

                        // 2. Ensure Alert Window is Open
                        if tx_monitor.get_webview_window("firewall-alert").is_none() {
                            println!("DEBUG: Spawning Firewall Alert Window...");

                            let toast_width = 420.0;
                            let toast_height = 260.0;
                            let position =
                                tx_monitor
                                    .primary_monitor()
                                    .ok()
                                    .flatten()
                                    .and_then(|monitor| {
                                        let scale = monitor.scale_factor();
                                        let size = monitor.size();

                                        let x = size.width as f64 / scale - toast_width - 24.0;
                                        let y = size.height as f64 / scale - toast_height - 24.0;

                                        Some((x, y))
                                    });

                            let mut builder = WebviewWindowBuilder::new(
                                &tx_monitor,
                                "firewall-alert",
                                WebviewUrl::App("index.html?mode=alert".into()),
                            )
                            .title("Firewall Alert")
                            .inner_size(toast_width, toast_height)
                            .resizable(false)
                            .always_on_top(true)
                            .decorations(false)
                            .skip_taskbar(true);

                            if let Some((x, y)) = position {
                                builder = builder.position(x, y);
                            } else {
                                builder = builder.center();
                            }

                            let _ = builder.build();
                        } else if let Some(win) = tx_monitor.get_webview_window("firewall-alert") {
                            let _ = win.unminimize();
                            let _ = win.show();
                            let _ = win.set_focus();
                        }

                        // Don't spam the UI, wait for user validation interaction
                        std::thread::sleep(Duration::from_millis(500));
                    } else {
                        // If no pending app, we might want to close the alert window?
                        // Actually, if we resolved it, the window might stay open showing "Waiting..." or empty.
                        // Ideally, we close it from the UI side when decision is made.

                        // Check if we should auto-close empty prompt window?
                        // For now, let the user close it or the UI logic handle it.
                        // UI logic: resolve_decision calls invoke -> updates state -> PendingApp becomes None.
                        // If PendingApp is None, the UI shows "Waiting..."

                        // We can optionally hide the window if no pending app?
                        // But let's leave valid "Waiting" state for now.

                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            })
            .expect("failed to spawn pending_monitor thread");

        // GLOBAL INJECTOR THREAD
        let am_global = Arc::clone(&am);
        let settings_global = Arc::clone(&self.settings);
        std::thread::Builder::new()
            .name("global_injector".to_string())
            .spawn(move || {
                use windows::Win32::System::Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                    TH32CS_SNAPPROCESS,
                };

                loop {
                    let (auto_inject, hook_dll) = {
                        let s = settings_global.read().unwrap();
                        (s.auto_inject_https, s.https_hook_dll.clone())
                    };

                    if auto_inject && !hook_dll.is_empty() {
                        unsafe {
                            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                                if !snapshot.is_invalid() {
                                    let mut entry = PROCESSENTRY32W::default();
                                    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                                    if Process32FirstW(snapshot, &mut entry).is_ok() {
                                        loop {
                                            let pid = entry.th32ProcessID;
                                            // More aggressive: Only skip IDLE and SYSTEM
                                            if pid != 0 && pid != 4 && pid != std::process::id() {
                                                let already_tracked = {
                                                    let injected =
                                                        am_global.injected_pids.read().unwrap();
                                                    injected.contains(&pid)
                                                };

                                                if !already_tracked
                                                    || !Injector::is_dll_loaded(pid, "hook_dll.dll")
                                                {
                                                    // Robust check: Is the DLL actually in the process?
                                                    // (Even if we didn't inject it this session or it failed before)
                                                    let (_info_name, info_path) =
                                                        Injector::get_process_info(pid);
                                                    if !Injector::is_path_excluded(&info_path) {
                                                        if Injector::inject(pid, &hook_dll).is_ok()
                                                        {
                                                            let mut injected = am_global
                                                                .injected_pids
                                                                .write()
                                                                .unwrap();
                                                            injected.insert(pid);
                                                        }
                                                    }
                                                }
                                            }
                                            if Process32NextW(snapshot, &mut entry).is_err() {
                                                break;
                                            }
                                        }
                                    }
                                    let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                                }
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_secs(3)); // Faster scan-loop
                }
            })
            .expect("failed to spawn global_injector thread");

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

            std::thread::Builder::new()
                .name(format!("packet_worker_{}", worker_id))
                .spawn(move || {
                    let mut buffer = vec![0u8; 65535];
                    while !stop_w.load(Ordering::Relaxed) {
                        // Each thread competition for packets on the shared handle
                        match divert_w.recv(Some(&mut buffer)) {
                            Ok(packet) => {
                                // println!("DEBUG: Worker Recv Packet len={}", packet.data.len());
                                let outbound = packet.address.outbound();

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
                                // 1. Try native Windows TCP/UDP table lookup (most reliable)
                                // 2. Fallback to hook DLL port mapping
                                let mut pid = 0u32;
                                if let Some(p_info) =
                                    Self::parse_packet(&packet.data, outbound, 0, &am_w.info_cache)
                                {
                                    let lookup_port = if outbound {
                                        p_info.src_port
                                    } else {
                                        p_info.dst_port
                                    };
                                    let is_tcp =
                                        matches!(p_info.protocol, crate::engine::Protocol::TCP);

                                    // Primary: Native Windows API lookup
                                    pid = Self::resolve_pid_from_port(lookup_port, is_tcp);

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
                                );

                                // EMIT RAW PACKET FOR UI (Wireshark-like view)
                                if let Some(info) = Self::parse_packet(
                                    &decision.packet_data,
                                    outbound,
                                    pid,
                                    &am_w.info_cache,
                                ) {
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

                                    let raw_packet = crate::sdk::RawPacket {
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
                                    };
                                    let _ = tx_log.emit("raw_packet", raw_packet);
                                }

                                if decision.should_forward {
                                    // REINJECT IMMEDIATELY from the SAME thread
                                    let reinject_packet = windivert::packet::WinDivertPacket {
                                        address: packet.address,
                                        data: std::borrow::Cow::Borrowed(&decision.packet_data),
                                    };
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
                                if err_str.contains("timeout") || err_str.contains("122") {
                                    std::thread::sleep(Duration::from_millis(1));
                                } else {
                                    // Hard error - log once and maybe exit thread?
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
    ) -> PacketDecision {
        let mut data_vec = data.to_vec();
        let mut pid = process_id;

        // 1. Resolve PID via port mapping if missing (0)
        if pid == 0 {
            if let Some(temp_info) = Self::parse_packet(&data_vec, outbound, 0, &am.info_cache) {
                let lookup_port = if outbound {
                    temp_info.src_port
                } else {
                    temp_info.dst_port
                };
                if let Some(mapped_pid) = am.get_pid_for_port(lookup_port) {
                    pid = mapped_pid;
                }
            }
        }

        // 2. Resolve Process Metadata
        let app_info = am.info_cache.get_info(pid);
        let sdk_context = crate::sdk::PacketContext {
            process_id: pid,
            process_name: app_info.name.clone(),
            process_path: app_info.path.clone(),
        };

        // Initialize decision state before parsing
        let mut should_forward = false;
        let mut reason = String::from("Pending decision");

        // 3. SDK PACKET CHANGERS & LISTENERS
        if let Some(mut info) = Self::parse_packet(&data_vec, outbound, pid, &am.info_cache) {
            let sdk_read = sdk.read().unwrap();
            for changer in &sdk_read.changers {
                if changer.modify(&mut data_vec, &info, &sdk_context) {
                    if let Some(new_info) =
                        Self::parse_packet(&data_vec, outbound, pid, &am.info_cache)
                    {
                        info = new_info;
                    }
                }
            }
            for listener in &sdk_read.listeners {
                listener.on_packet(&data_vec, &info, &sdk_context);
            }
            drop(sdk_read);

            // 4. Core Firewall Logic
            // POLICY CHANGE: Rule-based (Default Allow) instead of Default Deny
            should_forward = true;
            reason = if info.src_ip.is_loopback() || info.dst_ip.is_loopback() {
                "Localhost".to_string()
            } else {
                "Default Allow".to_string()
            };

            // Cache URLs
            if let Some(ref url) = info.full_url {
                am.url_cache.write().unwrap().insert(pid, url.clone());
            } else {
                if let Some(url) = am.url_cache.read().unwrap().get(&pid) {
                    info.full_url = Some(url.clone());
                }
            }

            // File Magic Detection
            let detected_type = file_checker.check(&data_vec);
            if let Some(ref dtype) = detected_type {
                // Reuse info struct? No, it's owned now. We modify the copy or just cache it?
                // 'info' is local.
                am.url_cache
                    .write()
                    .unwrap()
                    .insert(pid, format!("FILESIG:{}", dtype));
                info.detected_file_type = Some(dtype.clone());
            }

            let (auto_inject_https, hook_dll) = {
                let s = settings.read().unwrap();
                (s.auto_inject_https, s.https_hook_dll.clone())
            };

            if auto_inject_https
                && info.tls_handshake
                && info.hostname.is_none()
                && info.process_id != 0
                && !hook_dll.is_empty()
            {
                let mut injected = am.injected_pids.write().unwrap();
                let mut failed = am.failed_pids.write().unwrap();

                if !injected.contains(&info.process_id) && !failed.contains(&info.process_id) {
                    match Injector::inject(info.process_id, &hook_dll) {
                        Ok(()) => {
                            injected.insert(info.process_id);
                            let _ = tx.emit(
                                "log",
                                LogEntry {
                                    id: format!("{}-tls-hook", Self::now_ts()),
                                    timestamp: Self::now_ts(),
                                    level: LogLevel::Info,
                                    message: format!(
                                        "Injected HTTPS hook into PID {} to enrich TLS hostname context",
                                        info.process_id
                                    ),
                                },
                            );
                        }
                        Err(e) => {
                            failed.insert(info.process_id);
                            let _ = tx.emit(
                                "log",
                                LogEntry {
                                    id: format!("{}-tls-hook-fail", Self::now_ts()),
                                    timestamp: Self::now_ts(),
                                    level: LogLevel::Warning,
                                    message: format!(
                                        "Failed to inject HTTPS hook into PID {}: {} (Logic will skip future retries for this PID)",
                                        info.process_id, e
                                    ),
                                },
                            );
                        }
                    }
                }
            }

            let is_dns_query = matches!(info.protocol, Protocol::UDP)
                && (info.src_port == 53 || info.dst_port == 53);
            let dns_domain = info.dns_query.clone();
            // println!("DEBUG: Packet Parsed: {} -> {}", info.src_ip, info.dst_ip);
            // 1. Enforce keyword and signature checks without any implicit whitelist
            let settings_lock = settings.read().unwrap();

            // DNS keyword filtering happens before generic keyword checks so DNS-only traffic can be blocked
            if should_forward && is_dns_query {
                if let Some(ref domain) = dns_domain {
                    if dns_handler.should_block(domain, &*settings_lock) {
                        should_forward = false;
                        reason = format!("DNS Keyword Blocked: {}", domain);
                    }
                }
            }

            drop(settings_lock);

            // 2. App Decision Check
            let (app_decision, app_name, _app_path) = am.check_app(&info);

            match app_decision {
                AppDecision::Allow => {
                    // If we were only blocking because of the default non-localhost policy,
                    // a user allow decision should punch a hole for this app.
                    if !should_forward && reason.starts_with("Default block") {
                        should_forward = true;
                        reason = format!("App Allowed: {}", app_name);
                    } else if should_forward {
                        stats.packets_total.fetch_add(1, Ordering::Relaxed);
                        stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                        return PacketDecision {
                            packet_data: data.to_vec(),
                            address_data: address_data.to_vec(),
                            should_forward: true,
                            _reason: format!("App Allowed: {}", app_name),
                        };
                    }
                }
                AppDecision::Pending => {
                    // POLICY CHANGE: Allow unknown apps by default (No Zero Trust)
                    should_forward = true;
                    reason = format!("New App Detected: {}", app_name);
                }
                AppDecision::Block => {}
            }

            // 3. Web Filter Checks (Hostname/URL lists)
            if should_forward {
                if let Some(ref hostname) = info.hostname {
                    if let Some(block_reason) = wf.check_hostname(hostname) {
                        should_forward = false;
                        reason = block_reason;
                    }
                }
            }

            if should_forward {
                if let Some(ref url) = info.full_url {
                    if let Some(block_reason) = wf.check_url(url) {
                        should_forward = false;
                        reason = block_reason;
                    }
                }
            }

            if should_forward {
                for url in &info.payload_urls {
                    if let Some(block_reason) = wf.check_url(url) {
                        should_forward = false;
                        reason = block_reason;
                        break;
                    }
                }
            }

            if should_forward {
                for domain in &info.payload_domains {
                    if let Some(block_reason) = wf.check_hostname(domain) {
                        should_forward = false;
                        reason = block_reason;
                        break;
                    }
                }
            }

            if should_forward && app_decision == AppDecision::Block {
                should_forward = false;
                reason = format!("Blocked App: {}", app_name);
            }

            // 4. Custom Firewall Rules
            let current_rules = rules.read().unwrap();
            for rule in current_rules.iter() {
                if rule.matches(&info, &app_name) {
                    if rule.block {
                        should_forward = false;
                        reason = format!("Rule: {}", rule.name);
                    } else {
                        should_forward = true;
                        reason = format!("Rule Allowed: {}", rule.name);
                    }
                    break;
                }
            }

            stats.packets_total.fetch_add(1, Ordering::Relaxed);
            if is_dns_query {
                if let Some(domain) = dns_domain.clone().or_else(|| info.hostname.clone()) {
                    dns_handler.log_query(domain, !should_forward);
                }
            }
            if should_forward {
                stats.packets_allowed.fetch_add(1, Ordering::Relaxed);

                // ALLOWED TRAFFIC LOGGING (Rate Limited)
                let now = Self::now_ts();
                let last = stats.last_allowed_log_time.load(Ordering::Relaxed);

                // Debugging: Print rate limit status
                // println!("DEBUG: checking rate limit. Now: {}, Last: {}, Diff: {}", now, last, now.saturating_sub(last));

                // Log max 2 allowed events per second to prevent flood
                if now > last + 500 {
                    if stats
                        .last_allowed_log_time
                        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        let context = Self::format_packet_context(&info);
                        println!("DEBUG: Emitting Log: {}", reason);

                        let _ = tx.emit(
                            "log",
                            LogEntry {
                                id: format!("{}-allow", now),
                                timestamp: now,
                                level: LogLevel::Success,
                                message: format!("✅ {} | {}", reason, context),
                            },
                        );
                    }
                }
            } else {
                stats.packets_blocked.fetch_add(1, Ordering::Relaxed);

                // RATE LIMITING
                let now = Self::now_ts();
                let last = stats.last_log_time.load(Ordering::Relaxed);

                if now > last + 50 {
                    if stats
                        .last_log_time
                        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        let context = Self::format_packet_context(&info);
                        let _ = tx.emit(
                            "log",
                            LogEntry {
                                id: format!("{}-blocked", now),
                                timestamp: now,
                                level: LogLevel::Warning,
                                message: format!("🚫 {} | {}", reason, context),
                            },
                        );
                    }
                }
            }
        }
        // If parsing failed entirely, treat the packet as blocked to preserve the
        // default-deny posture and still surface the drop with minimal context.
        else {
            stats.packets_total.fetch_add(1, Ordering::Relaxed);
            stats.packets_blocked.fetch_add(1, Ordering::Relaxed);
            reason = "Blocked (unsupported or truncated packet)".to_string();

            let now = Self::now_ts();
            let last = stats.last_log_time.load(Ordering::Relaxed);
            if now > last + 50 {
                if stats
                    .last_log_time
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let _ = tx.emit(
                        "log",
                        LogEntry {
                            id: format!("{}-blocked", now),
                            timestamp: now,
                            level: LogLevel::Warning,
                            message: format!("🚫 {} | raw-bytes={}B", reason, data.len()),
                        },
                    );
                }
            }
        }

        // SDK SECURITY SIGNATURES
        {
            let sdk_read = sdk.read().unwrap();
            let s_lock = settings.read().unwrap();
            for sig in &sdk_read.signatures {
                if let Some(sig_reason) = sig.evaluate(&data_vec, &*s_lock, &sdk_context) {
                    should_forward = false;
                    reason = format!("SDK Signature [{}]: {}", sig.name(), sig_reason);
                    break;
                }
            }
        }

        PacketDecision {
            packet_data: data_vec,
            address_data: address_data.to_vec(),
            should_forward,
            _reason: reason,
        }
    }

    pub fn inject_dll(&self, pid: u32, dll_path: &str) -> bool {
        Injector::inject(pid, dll_path).is_ok()
    }

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
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
    ) -> Option<PacketInfo> {
        if data.len() < 20 {
            return None;
        }
        let ip_version = (data[0] >> 4) & 0x0F;
        if ip_version != 4 {
            return None;
        }

        let protocol = match data[9] {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            n => Protocol::Raw(n),
        };

        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let header_len = ((data[0] & 0x0F) as usize) * 4;

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

        let mut hostname = None;
        let mut full_url = None;
        let mut dns_query = None;
        let mut tls_handshake = false;
        let mut http_method = None;
        let mut http_path = None;
        let mut http_user_agent = None;
        let mut http_content_type = None;
        let mut http_referer = None;
        let mut payload_entropy = None;
        let mut payload_sample = None;
        let mut payload_bytes: Option<&[u8]> = None;
        let mut payload_urls: Vec<String> = Vec::new();
        let mut payload_domains: Vec<String> = Vec::new();

        // Extract hostname and URL from TCP payloads
        if matches!(protocol, Protocol::TCP) && header_len + 20 < data.len() {
            // TCP header is at least 20 bytes, data offset is in bits 4-7 of byte 12
            let tcp_header_start = header_len;
            let tcp_data_offset = if tcp_header_start + 12 < data.len() {
                ((data[tcp_header_start + 12] >> 4) as usize) * 4
            } else {
                20
            };
            let payload_start = header_len + tcp_data_offset;

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
            && header_len + 8 <= data.len()
        {
            let dns_payload = &data[header_len + 8..];
            dns_query = Self::parse_dns_query(dns_payload);
            payload_bytes = Some(dns_payload);
        }

        if hostname.is_none() {
            hostname = dns_query.clone();
        }

        if hostname.is_none() {
            if let Some(domain) = payload_domains.first() {
                hostname = Some(domain.clone());
            }
        }

        if payload_bytes.is_none() {
            // For non-TCP/UDP payloads, fall back to bytes after the IP header when possible
            if header_len < data.len() {
                payload_bytes = Some(&data[header_len..]);
            }
        }

        if let Some(bytes) = payload_bytes {
            if !bytes.is_empty() {
                payload_entropy = Some(Self::shannon_entropy(bytes));
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

        Some(PacketInfo {
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
        })
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
}
