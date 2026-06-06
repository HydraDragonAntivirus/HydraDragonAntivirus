pub use super::rule_types::*;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::config::Config;
#[cfg(all(target_os = "windows", feature = "firewall"))]
use crate::windows::edrsvc_client::with_shared_driver;
use crate::extensions::ExtensionList;
use crate::logging::Logging;
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::process::ProcessRecord;
#[cfg(all(target_os = "windows", feature = "firewall"))]
use crate::process::ProcessState;
use crate::shared_def::{
    FileChangeInfo, IOMessage, IrpMajorOp, irp_major_op_label, is_hypervisor_raw_event_type,
    known_raw_event_name,
};
use crate::shared_def::{
    effective_hypervisor_irp_byte, effective_hypervisor_raw_event_type, is_kernel_api_irp,
    is_kernel_process_protection_irp, is_real_hypervisor_irp, normalize_hypervisor_label,
    resolved_hypervisor_event_name,
};
use crate::signature_verification::verify_signature;
use crate::threat_handler::ThreatHandler;
use crate::utils::{
    format_process_descriptor_with_fallback, resolve_process_path,
    suspicious_critical_process_reason,
};
#[cfg(all(target_os = "windows", feature = "firewall"))]
use crate::utils::validate_pipe_client;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::{HashMap, HashSet, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "windows", feature = "firewall"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use num::FromPrimitive;

#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallNetPids = Arc<std::sync::RwLock<HashSet<u32>>>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallBlockedExes = Arc<std::sync::RwLock<HashMap<String, FirewallDetection>>>;
/// Per-PID list of (dst_ip, dst_port) pairs observed by the firewall (NET_EVENT).
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallNetDetails = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, u16)>>>>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallPipeStarted = Arc<AtomicBool>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallHipsPendingPrompts = Arc<std::sync::RwLock<HashMap<String, FirewallHipsPromptState>>>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallHipsDecisions = Arc<std::sync::RwLock<HashMap<String, FirewallHipsDecision>>>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallHipsAllowOnce = Arc<std::sync::RwLock<HashSet<String>>>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallHipsAllowAlways = Arc<std::sync::RwLock<HashSet<String>>>;
/// Per-PID list of (request_body, response_body) pairs received via FULL_PACKED_DATA pipe messages.
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallHttpBodyMap = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, String)>>>>;
/// Per-PID rolling history of full PacketInfo structures from the firewall.
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallFullPackets = Arc<std::sync::RwLock<HashMap<u32, VecDeque<PacketInfo>>>>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallGenerateReport = Arc<AtomicBool>;
#[cfg(all(target_os = "windows", feature = "firewall"))]
type FirewallFileVerdicts = Arc<std::sync::RwLock<HashMap<String, FileVerdictInfo>>>;

#[cfg(all(target_os = "windows", feature = "firewall"))]
#[derive(Clone, Debug, Deserialize)]
struct FirewallPackedDataMessage {
    packet: PacketInfo,
    #[serde(default)]
    request_body: Option<String>,
    #[serde(default)]
    response_body: Option<String>,
}

fn rule_file_fingerprint(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut hasher = DefaultHasher::new();
            bytes.hash(&mut hasher);
            format!("hash={:016x};len={}", hasher.finish(), bytes.len())
        }
        Err(_) => "file-unreadable".to_string(),
    }
}

fn should_log_rule_load_error(key: &str) -> bool {
    static RULE_LOAD_ERROR_CACHE: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();
    let cache = RULE_LOAD_ERROR_CACHE.get_or_init(|| RwLock::new(HashSet::new()));
    let mut cache = cache.write().unwrap();
    cache.insert(key.to_string())
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_net_pids() -> FirewallNetPids {
    static FIREWALL_NET_PIDS: OnceLock<FirewallNetPids> = OnceLock::new();
    FIREWALL_NET_PIDS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_blocked_exes() -> FirewallBlockedExes {
    static FIREWALL_BLOCKED_EXES: OnceLock<FirewallBlockedExes> = OnceLock::new();
    FIREWALL_BLOCKED_EXES
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_net_details() -> FirewallNetDetails {
    static FIREWALL_NET_DETAILS: OnceLock<FirewallNetDetails> = OnceLock::new();
    FIREWALL_NET_DETAILS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_http_body_map() -> FirewallHttpBodyMap {
    static FIREWALL_HTTP_BODY_MAP: OnceLock<FirewallHttpBodyMap> = OnceLock::new();
    FIREWALL_HTTP_BODY_MAP
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_full_packets() -> FirewallFullPackets {
    static FIREWALL_FULL_PACKETS: OnceLock<FirewallFullPackets> = OnceLock::new();
    FIREWALL_FULL_PACKETS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_pipe_started() -> FirewallPipeStarted {
    static FIREWALL_PIPE_STARTED: OnceLock<FirewallPipeStarted> = OnceLock::new();
    FIREWALL_PIPE_STARTED
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_hips_pending_prompts() -> FirewallHipsPendingPrompts {
    static FIREWALL_HIPS_PENDING_PROMPTS: OnceLock<FirewallHipsPendingPrompts> = OnceLock::new();
    FIREWALL_HIPS_PENDING_PROMPTS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_hips_decisions() -> FirewallHipsDecisions {
    static FIREWALL_HIPS_DECISIONS: OnceLock<FirewallHipsDecisions> = OnceLock::new();
    FIREWALL_HIPS_DECISIONS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_hips_allow_once() -> FirewallHipsAllowOnce {
    static FIREWALL_HIPS_ALLOW_ONCE: OnceLock<FirewallHipsAllowOnce> = OnceLock::new();
    FIREWALL_HIPS_ALLOW_ONCE
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_hips_allow_always() -> FirewallHipsAllowAlways {
    static FIREWALL_HIPS_ALLOW_ALWAYS: OnceLock<FirewallHipsAllowAlways> = OnceLock::new();
    FIREWALL_HIPS_ALLOW_ALWAYS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_generate_report() -> FirewallGenerateReport {
    static FIREWALL_GENERATE_REPORT: OnceLock<FirewallGenerateReport> = OnceLock::new();
    FIREWALL_GENERATE_REPORT
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn shared_firewall_file_verdicts() -> FirewallFileVerdicts {
    static FIREWALL_FILE_VERDICTS: OnceLock<FirewallFileVerdicts> = OnceLock::new();
    FIREWALL_FILE_VERDICTS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
fn normalize_firewall_file_verdict_key(file_path: &str) -> String {
    file_path.trim().replace('/', "\\").to_ascii_lowercase()
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
pub fn firewall_file_verdict_for_path(file_path: &str) -> Option<FileVerdictInfo> {
    let key = normalize_firewall_file_verdict_key(file_path);
    let verdicts = shared_firewall_file_verdicts();
    let guard = verdicts.read().ok()?;

    guard.get(&key).cloned().or_else(|| {
        guard
            .values()
            .find(|verdict| normalize_firewall_file_verdict_key(&verdict.file_path) == key)
            .cloned()
    })
}

/// Per-PID stats from Sanctum EDR telemetry (received via HydraSanctumTelemetry pipe).
#[cfg(all(target_os = "windows", feature = "sanctum"))]
type FirewallSanctumStats = Arc<
    std::sync::RwLock<HashMap<u32, crate::realtime_learning::api_tracker::SanctumOperationStats>>,
>;

#[cfg(all(target_os = "windows", feature = "sanctum"))]
fn shared_firewall_sanctum_stats() -> FirewallSanctumStats {
    static FIREWALL_SANCTUM_STATS: OnceLock<FirewallSanctumStats> = OnceLock::new();
    FIREWALL_SANCTUM_STATS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

/// Per-PID OpenEDR telemetry stats collected from the direct edrsvc -> Owlyshield feed.
type OpenEdrTelemetryStatsMap = Arc<std::sync::RwLock<HashMap<u32, OpenEdrTelemetryStats>>>;
type OpenEdrNetPids = Arc<std::sync::RwLock<HashSet<u32>>>;
type OpenEdrNetDetails = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, u16)>>>>;
type SelfDefenseTelemetryMap =
    Arc<std::sync::RwLock<HashMap<u32, VecDeque<SelfDefenseTelemetryEvent>>>>;

const SELF_DEFENSE_DUPLICATE_SUPPRESS_MS: u64 = 2_000;

fn shared_openedr_stats() -> OpenEdrTelemetryStatsMap {
    static OPENEDR_STATS: OnceLock<OpenEdrTelemetryStatsMap> = OnceLock::new();
    OPENEDR_STATS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

fn shared_openedr_net_pids() -> OpenEdrNetPids {
    static OPENEDR_NET_PIDS: OnceLock<OpenEdrNetPids> = OnceLock::new();
    OPENEDR_NET_PIDS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

fn shared_openedr_net_details() -> OpenEdrNetDetails {
    static OPENEDR_NET_DETAILS: OnceLock<OpenEdrNetDetails> = OnceLock::new();
    OPENEDR_NET_DETAILS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

fn shared_self_defense_telemetry() -> SelfDefenseTelemetryMap {
    static SELF_DEFENSE_TELEMETRY: OnceLock<SelfDefenseTelemetryMap> = OnceLock::new();
    SELF_DEFENSE_TELEMETRY
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SelfDefenseTelemetryEvent {
    pub timestamp_ms: u64,
    pub source: String,
    pub category: String,
    pub attack_type: String,
    pub operation: String,
    pub protected_path: String,
    pub attacker_path: String,
    pub attacker_pid: u32,
    pub target_pid: u32,
    pub action: String,
}

impl SelfDefenseTelemetryEvent {
    fn string_field(event: &serde_json::Value, names: &[&str]) -> String {
        names
            .iter()
            .find_map(|name| event.get(*name))
            .and_then(|value| {
                value
                    .as_str()
                    .map(|text| text.trim().to_string())
                    .or_else(|| value.as_u64().map(|num| num.to_string()))
            })
            .unwrap_or_default()
    }

    fn u32_field(event: &serde_json::Value, names: &[&str]) -> u32 {
        let Some(value) = names.iter().find_map(|name| event.get(*name)) else {
            return 0;
        };

        if let Some(num) = value.as_u64() {
            return num.min(u32::MAX as u64) as u32;
        }

        let Some(text) = value
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        else {
            return 0;
        };

        let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            text.parse::<u64>()
                .or_else(|_| u64::from_str_radix(text, 16))
        };

        parsed
            .map(|num| num.min(u32::MAX as u64) as u32)
            .unwrap_or(0)
    }

    fn classify_category(attack_type: &str, operation: &str, protected_path: &str) -> String {
        let haystack = format!("{attack_type} {operation} {protected_path}").to_ascii_lowercase();

        if haystack.contains("com_")
            || haystack.contains("com registry")
            || haystack.contains("\\classes\\clsid")
            || haystack.contains("\\classes\\appid")
            || haystack.contains("\\clsid\\")
            || haystack.contains("\\appid\\")
        {
            "com".to_string()
        } else if haystack.contains("registry")
            || haystack.contains("reg_")
            || haystack.starts_with("hklm\\")
            || haystack.starts_with("hkcu\\")
            || haystack.contains("\\registry\\")
        {
            "registry".to_string()
        } else if haystack.contains("process") || haystack.contains("thread") {
            "process".to_string()
        } else if haystack.contains("disk")
            || haystack.contains("mbr")
            || haystack.contains("ioctl")
        {
            "disk".to_string()
        } else {
            "file".to_string()
        }
    }

    fn classify_action(event: &serde_json::Value, attack_type: &str, operation: &str) -> String {
        let explicit = Self::string_field(event, &["action", "result", "disposition"]);
        if !explicit.is_empty() {
            return explicit.to_ascii_lowercase();
        }

        let marker = format!("{attack_type} {operation}").to_ascii_lowercase();
        if marker.contains("blocked") || marker.contains("denied") {
            "blocked".to_string()
        } else {
            "telemetry".to_string()
        }
    }

    pub fn from_json(event: &serde_json::Value) -> Option<Self> {
        let attack_type = Self::string_field(event, &["attack_type", "event_type", "type"]);
        let operation = Self::string_field(event, &["operation", "op"]);
        let protected_path = Self::string_field(
            event,
            &["protected_file", "protected_path", "target_path", "path"],
        );
        let attacker_path =
            Self::string_field(event, &["attacker_path", "process_path", "image_path"]);
        let attacker_pid = Self::u32_field(event, &["attacker_pid", "pid", "process_id"]);
        let target_pid = Self::u32_field(event, &["target_pid"]);

        if attack_type.is_empty()
            && operation.is_empty()
            && protected_path.is_empty()
            && attacker_pid == 0
        {
            return None;
        }

        let timestamp_ms = event
            .get("timestamp_ms")
            .and_then(|value| value.as_u64())
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
            });
        let source = Self::string_field(event, &["source"]).if_empty("openedr");
        let category = Self::string_field(event, &["category"]).if_empty(Self::classify_category(
            &attack_type,
            &operation,
            &protected_path,
        ));
        let action = Self::classify_action(event, &attack_type, &operation);

        Some(Self {
            timestamp_ms,
            source,
            category,
            attack_type,
            operation,
            protected_path,
            attacker_path,
            attacker_pid,
            target_pid,
            action,
        })
    }

    fn match_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            self.source,
            self.category,
            self.attack_type,
            self.operation,
            self.protected_path,
            self.timestamp_ms
        )
    }

    fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.source,
            self.category,
            self.attack_type,
            self.operation,
            self.protected_path,
            self.attacker_path,
            self.attacker_pid,
            self.target_pid,
            self.action
        )
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: impl Into<String>) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: impl Into<String>) -> String {
        if self.trim().is_empty() {
            fallback.into()
        } else {
            self
        }
    }
}

pub fn record_self_defense_telemetry(event: serde_json::Value) {
    let Some(event) = SelfDefenseTelemetryEvent::from_json(&event) else {
        Logging::warning("[SelfDefenseTelemetry] Ignored incomplete self-defense event");
        return;
    };

    let attacker_pid = event.attacker_pid;
    if attacker_pid == 0 {
        Logging::warning(&format!(
            "[SelfDefenseTelemetry] Event has no attacker PID; source={} category={} attack_type={} target={}",
            event.source, event.category, event.attack_type, event.protected_path
        ));
        return;
    }

    let telemetry = shared_self_defense_telemetry();
    let mut guard = telemetry.write().unwrap();
    let queue = guard
        .entry(attacker_pid)
        .or_insert_with(|| VecDeque::with_capacity(128));
    let event_dedupe_key = event.dedupe_key();
    let is_recent_duplicate = queue.iter().rev().any(|recent| {
        event.timestamp_ms.saturating_sub(recent.timestamp_ms) <= SELF_DEFENSE_DUPLICATE_SUPPRESS_MS
            && recent.dedupe_key() == event_dedupe_key
    });
    if is_recent_duplicate {
        return;
    }

    if queue.len() >= 128 {
        queue.pop_front();
    }
    queue.push_back(event.clone());

    Logging::warning(&format!(
        "[SelfDefenseTelemetry] source={} category={} action={} attacker_pid={} target_pid={} operation={} attack_type={} target={}",
        event.source,
        event.category,
        event.action,
        event.attacker_pid,
        event.target_pid,
        event.operation,
        event.attack_type,
        event.protected_path
    ));
}

fn event_time(event: &SelfDefenseTelemetryEvent) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_millis(event.timestamp_ms)
}

#[derive(Debug, Clone, Default)]
pub struct OpenEdrTelemetryStats {
    pub total_event_count: usize,
    pub process_event_count: usize,
    pub file_event_count: usize,
    pub registry_event_count: usize,
    pub memory_event_count: usize,
    pub network_event_count: usize,
    pub device_event_count: usize,
    pub pipe_event_count: usize,
    pub input_event_count: usize,
    pub user_event_count: usize,
    pub self_defense_event_count: usize,
    pub process_open_count: usize,
    pub memory_write_count: usize,
    pub injection_activity_count: usize,
    pub network_connect_count: usize,
    pub detected_apis: HashSet<String>,
    pub recent_events: VecDeque<String>,
    pub last_event: Option<String>,
    pub cloud_static_label: Option<String>,
    pub cloud_dynamic_label: Option<String>,
    /// OpenEDR FLS verdict/result code: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail.
    pub cloud_static_verdict: Option<u8>,
    /// OpenEDR FLS verdict/result code: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail.
    pub cloud_dynamic_verdict: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenEdrFlsVerdict {
    Absent,
    Safe,
    Malicious,
    Unknown,
    Fail,
}

impl OpenEdrFlsVerdict {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Absent),
            1 => Some(Self::Safe),
            2 => Some(Self::Malicious),
            3 => Some(Self::Unknown),
            4 => Some(Self::Fail),
            _ => None,
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "0" | "0x0" | "absent" => Some(Self::Absent),
            "1" | "0x1" | "safe" => Some(Self::Safe),
            "2" | "0x2" | "malicious" | "malware" => Some(Self::Malicious),
            "3" | "0x3" | "unknown" => Some(Self::Unknown),
            "4" | "0x4" | "fail" | "failed" => Some(Self::Fail),
            _ => None,
        }
    }

    fn from_json_value(value: &serde_json::Value) -> Option<Self> {
        if let Some(code) = value.as_u64().and_then(|code| u8::try_from(code).ok()) {
            return Self::from_code(code);
        }

        value.as_str().and_then(|text| {
            if let Some(verdict) = Self::from_token(text) {
                return Some(verdict);
            }

            text.split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter(|token| !token.is_empty())
                .find_map(Self::from_token)
        })
    }

    fn code(self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Safe => 1,
            Self::Malicious => 2,
            Self::Unknown => 3,
            Self::Fail => 4,
        }
    }

    fn display_label(self) -> &'static str {
        match self {
            Self::Absent => "Unrecognized",
            Self::Safe => "Possible Safe",
            Self::Malicious => "Malware",
            Self::Unknown => "Unknown",
            Self::Fail => "Fail",
        }
    }

    fn is_safe(self) -> bool {
        matches!(self, Self::Safe)
    }

    fn is_malicious(self) -> bool {
        matches!(self, Self::Malicious)
    }
}

fn is_openedr_fls_safe_code(code: Option<u8>) -> bool {
    code.and_then(OpenEdrFlsVerdict::from_code)
        .is_some_and(OpenEdrFlsVerdict::is_safe)
}

// =============================================================================
// FIREWALL DETECTION — details received from the firewall via HydraNetEvent pipe
// =============================================================================

/// File verdict information received from the firewall via VERDICT messages.
/// Contains file reputation data that can be used for allow/block decisions.
#[derive(Debug, Clone)]
#[cfg(all(target_os = "windows", feature = "firewall"))]
pub struct FileVerdictInfo {
    /// SHA256 hash of the file
    pub sha256: String,
    /// File path
    pub file_path: String,
    /// OpenEDR FLS verdict code: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail.
    pub verdict: u8,
    /// Display label derived from the OpenEDR FLS verdict.
    pub verdict_label: String,
    /// Timestamp when verdict was received
    pub timestamp: SystemTime,
}

/// All detection context sent by the firewall when it confirms malicious traffic.
/// Populated from BLOCK_EXE messages and used to build rich ThreatInfo for reports.
#[derive(Debug, Clone)]
#[cfg(all(target_os = "windows", feature = "firewall"))]
pub struct FirewallDetection {
    pub dst_ip: String,
    pub dst_port: u16,
    pub hostname: String,
    /// Full reason string from the firewall (e.g. "SDK Rule [MalwareDomain]: ...")
    pub reason: String,
    /// Whether this detection came from a private rule match (YARA-style)
    /// Private rules are evaluated but don't generate alerts on their own
    pub is_private_rule_match: bool,
    /// Detected subdomain from the packet (if any)
    pub detected_subdomain: Option<String>,
    /// Detected domain from the packet (if any)
    pub detected_domain: Option<String>,
    /// Whether subdomain detection used public_suffixes.txt (true) or simple parsing (false)
    pub used_public_suffix_list: bool,
    /// List of private rule names that matched during evaluation
    pub matched_private_rules: Vec<String>,
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
#[allow(dead_code)]
impl FirewallDetection {
    pub fn is_pending_user_decision(&self) -> bool {
        let reason = self.reason.to_ascii_lowercase();
        reason.contains("pending user decision")
            || reason.contains("app pending decision")
            || reason.contains("user decision requested")
    }

    /// Derive a threat type label from the reason string.
    pub fn threat_type_label(&self) -> &'static str {
        let r = self.reason.to_lowercase();
        if r.contains("ransomware") {
            "Ransomware"
        } else if r.contains("c2") || r.contains("command") || r.contains("botnet") {
            "C2 Communication"
        } else if r.contains("exploit") {
            "Exploit"
        } else if r.contains("intelligence") || r.contains("malware") {
            "Malware"
        } else if r.contains("sdk rule") {
            "Policy Violation"
        } else {
            "Malicious Network Activity"
        }
    }

    /// Build a human-readable match_details string for reports.
    pub fn match_details(&self) -> String {
        use std::fmt::Write;

        let mut details = String::with_capacity(256); // Pre-allocate reasonable capacity

        // Build base details without intermediate allocations
        if self.hostname.is_empty() {
            let _ = write!(
                details,
                "{}:{} — {}",
                self.dst_ip, self.dst_port, self.reason
            );
        } else {
            let _ = write!(
                details,
                "{}:{} ({}) — {}",
                self.dst_ip, self.dst_port, self.hostname, self.reason
            );
        }

        // Include private rule match information for debugging
        if !self.matched_private_rules.is_empty() {
            let _ = write!(
                details,
                " [Private rules matched: {}]",
                self.matched_private_rules.join(", ")
            );
        }

        // Include domain extraction information for debugging
        if let Some(ref domain) = self.detected_domain {
            let _ = write!(details, " [Domain: {}]", domain);
        }
        if let Some(ref subdomain) = self.detected_subdomain {
            if self.detected_subdomain != self.detected_domain {
                let _ = write!(details, " [Subdomain: {}]", subdomain);
            }
        }

        details
    }
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
#[derive(Debug, Clone)]
struct FirewallHipsPromptState {
    request_id: String,
    request_signature: String,
    allow_signature: String,
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallHipsDecision {
    Deny,
    Block,
    Quarantine,
    AllowOnce,
    AllowAlways,
}

#[cfg(all(target_os = "windows", feature = "firewall"))]
impl FirewallHipsDecision {
    fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "deny" => Some(Self::Deny),
            "block" => Some(Self::Block),
            "quarantine" => Some(Self::Quarantine),
            "allow_once" => Some(Self::AllowOnce),
            "allow_always" => Some(Self::AllowAlways),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallHipsPromptOutcome {
    Pending,
    Allowed,
    Deny,
    Block,
    Quarantine,
}

// =============================================================================
// PART 1: IRP OPERATION TRACKING STRUCTURES
// =============================================================================

/// Records every IRP operation with full context
#[derive(Debug, Clone)]
pub struct IrpOperationRecord {
    pub timestamp: SystemTime,
    /// Raw SysmonEvent ID (u32) on Windows; legacy eBPF small-int on Linux.
    pub irp_type: u32,
    pub file_path: String,
    pub file_change: u8,
    pub extension: String,
    pub entropy: f64,
    pub bytes_transferred: u64,
    pub target_pid: u32,         // NEW: For operations targeting another process
    pub function_name: String,   // NEW: For generic API hooks - which function was called
    pub pipe_name: String,       // NEW: For Named Pipe detect
    pub pipe_payload: Vec<u8>,   // NEW: For Named Pipe payload detect
    pub raw_arguments: [u64; 4], // NEW: For API argument matching
}

/// Hypervisor event operation details for detailed tracking and forensics
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HypervisorEventOperation {
    pub timestamp: SystemTime,
    pub api_type: IrpMajorOp,
    pub source_pid: u32,
    pub target_pid: u32,
    pub memory_address: u64,
    pub memory_size: u64,
    pub operation_details: String,
}

/// Non-success status from user-mode hook / kernel API telemetry.
///
/// This is intentionally tracked separately from `detected_apis` and
/// `hypervisor_event_count`: hook/report/query failures are telemetry that
/// rules may inspect, but they must not be counted as successful API behavior.
#[derive(Debug, Clone)]
pub struct HookErrorRecord {
    pub timestamp: SystemTime,
    pub api_name: String,
    pub raw_event_type: u32,
    pub operation_status: i32,
    pub source_pid: u32,
    pub target_pid: u32,
    pub thread_id: u64,
    pub context: u64,
    pub raw_argument1: u64,
    pub raw_argument2: u64,
    pub raw_argument3: u64,
    pub raw_argument4: u64,
}

/// Maintains comprehensive operation statistics
#[derive(Debug, Clone, Default)]
pub struct IrpStatistics {
    // File operations by type
    pub read_count: u64,
    pub write_count: u64,
    pub create_count: u64,
    pub delete_count: u64,
    pub rename_count: u64,
    pub setinfo_count: u64,

    // Registry operations
    pub registry_read_count: u64,
    pub registry_write_count: u64,
    pub registry_delete_count: u64,
    pub registry_create_count: u64,

    // Process operations
    pub process_create_count: u64,
    pub process_terminate_count: u64,
    pub process_exit_count: u64,
    pub process_handle_open_count: u64,
    pub process_terminate_attempt_count: u64,

    pub hypervisor_event_count: u64, // Normalized hypervisor event count

    // Named Pipe operations
    pub pipe_create_count: u64,
    pub pipe_write_count: u64,

    // Bytes transferred
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,

    // File type statistics
    pub files_by_extension: HashMap<String, u64>,
    #[allow(dead_code)]
    pub directories_accessed: HashSet<String>,
    pub unique_paths_accessed: HashSet<String>,

    // High-entropy file tracking
    pub high_entropy_files: HashSet<String>,
    pub average_entropy: f64,
    pub entropy_samples: Vec<f64>,

    // Hypervisor event operation history (limited to last 100 for memory efficiency)
    pub hypervisor_event_operations: Vec<HypervisorEventOperation>,

    // Per-SysmonEvent-ID opcode counters for OpenEDR/Owlyshield bridge rules.
    pub raw_irp_counts: HashMap<u32, u64>,

    // All APIs called (for comprehensive tracking)
    pub all_apis_called: HashSet<String>,
}

impl IrpStatistics {
    pub fn get_total_operations(&self) -> u64 {
        self.read_count
            + self.write_count
            + self.create_count
            + self.delete_count
            + self.rename_count
            + self.setinfo_count
            + self.registry_read_count
            + self.registry_write_count
            + self.registry_delete_count
            + self.registry_create_count
            + self.process_create_count
            + self.process_terminate_count
            + self.process_exit_count
            + self.process_handle_open_count
            + self.process_terminate_attempt_count
            + self.hypervisor_event_count
            + self.pipe_create_count
            + self.pipe_write_count
    }

    pub fn get_high_entropy_count(&self) -> usize {
        self.high_entropy_files.len()
    }

    pub fn get_injection_api_count(&self) -> u64 {
        self.hypervisor_event_count
    }

    pub fn has_injection_indicators(&self) -> bool {
        self.hypervisor_event_count > 0
    }

    pub fn record_operation(&mut self, rec: &IrpOperationRecord) {
        *self.raw_irp_counts.entry(rec.irp_type).or_insert(0) += 1;
        let irp_op = IrpMajorOp::from_sysmonevent(rec.irp_type);

        match irp_op {
            // File operations
            IrpMajorOp::IrpRead => {
                self.read_count += 1;
                self.total_bytes_read += rec.bytes_transferred;
            }
            IrpMajorOp::IrpWrite => {
                self.write_count += 1;
                self.total_bytes_written += rec.bytes_transferred;
            }
            IrpMajorOp::IrpCreate => self.create_count += 1,
            IrpMajorOp::IrpSetInfo => {
                self.setinfo_count += 1;
                // Track specific file changes
                match rec.file_change {
                    _ if rec.file_change == FileChangeInfo::ChangeDeleteFile as u8 => {
                        self.delete_count += 1
                    }
                    _ if rec.file_change == FileChangeInfo::ChangeRenameFile as u8 => {
                        self.rename_count += 1
                    }
                    _ if rec.file_change == FileChangeInfo::ChangeExtensionChanged as u8 => {
                        self.rename_count += 1
                    }
                    _ => {}
                }
            }

            // Registry operations
            IrpMajorOp::IrpRegistry => {
                match rec.file_change {
                    _ if rec.file_change == FileChangeInfo::RegCreateKey as u8 => {
                        self.registry_create_count += 1
                    }
                    _ if rec.file_change == FileChangeInfo::RegSetValue as u8 => {
                        self.registry_write_count += 1
                    }
                    // FIX (Bug #2): RegDeleteKey (14) was missing and fell through to
                    // registry_read_count. Both value-delete and key-delete are deletions.
                    _ if rec.file_change == FileChangeInfo::RegDeleteValue as u8
                        || rec.file_change == FileChangeInfo::RegDeleteKey as u8 =>
                    {
                        self.registry_delete_count += 1
                    }
                    // RegQueryValue / RegQueryKey / RegOpenKey / RegEnumKey / RegEnumValue
                    // are all read-class operations — the catch-all is correct for them.
                    _ => self.registry_read_count += 1,
                }
            }

            // Process operations
            IrpMajorOp::IrpProcessCreate => self.process_create_count += 1,
            IrpMajorOp::IrpProcessTerminate => self.process_terminate_count += 1,
            IrpMajorOp::IrpProcessTerminateAttempt => self.process_terminate_attempt_count += 1,
            IrpMajorOp::IrpProcessExit => self.process_exit_count += 1,
            IrpMajorOp::IrpProcessHandleOpen => self.process_handle_open_count += 1,

            // Named pipe operations
            IrpMajorOp::IrpNamedPipeCreate => {
                self.pipe_create_count += 1;
                if !rec.pipe_name.is_empty() {
                    self.unique_paths_accessed.insert(rec.pipe_name.clone());
                }
            }
            IrpMajorOp::IrpNamedPipeWrite => {
                self.pipe_write_count += 1;
                self.total_bytes_written += if rec.pipe_payload.is_empty() {
                    rec.bytes_transferred
                } else {
                    rec.pipe_payload.len() as u64
                };
                if !rec.pipe_name.is_empty() {
                    self.unique_paths_accessed.insert(rec.pipe_name.clone());
                }
            }

            // Hypervisor/VMM and user-mode hook events are tracked together.
            IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpHypervisorEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection => {
                self.hypervisor_event_count += 1;
                let details = if rec.function_name.is_empty() {
                    "API Hooking Event".to_string()
                } else {
                    format!("API Hooking Event (raw_name={})", rec.function_name)
                };
                self.record_hypervisor_event_operation(
                    rec,
                    IrpMajorOp::from_sysmonevent(rec.irp_type),
                    &details,
                );
                if is_real_api_observation(&rec.function_name) {
                    self.all_apis_called.insert(rec.function_name.clone());
                }
            }

            _ => {}
        }

        // Track file statistics
        if !rec.extension.is_empty() {
            *self
                .files_by_extension
                .entry(rec.extension.clone())
                .or_insert(0) += 1;
        }

        self.unique_paths_accessed.insert(rec.file_path.clone());

        if rec.entropy > 0.7 {
            self.high_entropy_files.insert(rec.file_path.clone());
        }

        if self.entropy_samples.len() < 1000 {
            self.entropy_samples.push(rec.entropy);
            self.average_entropy =
                self.entropy_samples.iter().sum::<f64>() / self.entropy_samples.len() as f64;
        }
    }

    /// Record detailed hypervisor event operation for forensics and analysis
    fn record_hypervisor_event_operation(
        &mut self,
        rec: &IrpOperationRecord,
        api_type: IrpMajorOp,
        details: &str,
    ) {
        let operation = HypervisorEventOperation {
            timestamp: rec.timestamp,
            api_type,
            source_pid: 0, // Will be filled from IOMessage if available
            target_pid: rec.target_pid,
            memory_address: 0, // Will be filled from hypervisor event payload if available
            memory_size: rec.bytes_transferred,
            operation_details: details.to_string(),
        };

        self.hypervisor_event_operations.push(operation);

        // Keep only last 100 operations to prevent memory bloat
        if self.hypervisor_event_operations.len() > 100 {
            self.hypervisor_event_operations.remove(0);
        }
    }

    fn enrich_latest_hypervisor_event_operation(
        &mut self,
        msg: &IOMessage,
        event_name: &str,
        raw_event_type: u32,
    ) {
        let Some(operation) = self.hypervisor_event_operations.last_mut() else {
            return;
        };

        let hyper_event = msg.resolved_hypervisor_event();
        operation.source_pid = hyper_event
            .as_ref()
            .map(|event| event.source_process_id)
            .unwrap_or(msg.kernel_event_info.source_process_id);
        operation.target_pid = hyper_event
            .as_ref()
            .map(|event| event.target_process_id)
            .unwrap_or_else(|| {
                if msg.kernel_event_info.target_process_id != 0 {
                    msg.kernel_event_info.target_process_id
                } else {
                    msg.pid
                }
            });
        operation.memory_address = hyper_event
            .as_ref()
            .map(|event| event.memory_address)
            .unwrap_or(msg.kernel_event_info.memory_address);
        operation.memory_size = hyper_event
            .as_ref()
            .map(|event| event.memory_size)
            .unwrap_or(msg.kernel_event_info.memory_size as u64);
        let operation_status = hyper_event
            .as_ref()
            .map(|event| event.operation_status)
            .unwrap_or(msg.kernel_event_info.operation_status);
        let raw_argument1 = hyper_event
            .as_ref()
            .map(|event| event.raw_argument1)
            .unwrap_or(msg.kernel_event_info.raw_argument1);
        let raw_argument2 = hyper_event
            .as_ref()
            .map(|event| event.raw_argument2)
            .unwrap_or(msg.kernel_event_info.raw_argument2);
        let raw_argument3 = hyper_event
            .as_ref()
            .map(|event| event.raw_argument3)
            .unwrap_or(msg.kernel_event_info.raw_argument3);
        let raw_argument4 = hyper_event
            .as_ref()
            .map(|event| event.raw_argument4)
            .unwrap_or(msg.kernel_event_info.raw_argument4);
        let core_id = hyper_event
            .as_ref()
            .map(|event| event.core_id)
            .unwrap_or(msg.kernel_event_info.core_id);
        let thread_id = hyper_event
            .as_ref()
            .map(|event| event.thread_id)
            .unwrap_or(msg.kernel_event_info.thread_id);
        let context = hyper_event
            .as_ref()
            .map(|event| event.context)
            .unwrap_or(msg.kernel_event_info.context);
        operation.operation_details = format!(
            "{} raw_event_type=0x{:X} status=0x{:08X} core_id={} thread_id={} context=0x{:X} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X}",
            event_name,
            raw_event_type,
            operation_status as u32,
            core_id,
            thread_id,
            context,
            raw_argument1,
            raw_argument2,
            raw_argument3,
            raw_argument4
        );
    }

    pub fn get_operation_count(&self, op_type: &str) -> u64 {
        if let Some(opcode) = irp_opcode_from_operation_token(op_type) {
            return *self.raw_irp_counts.get(&(opcode as u32)).unwrap_or(&0);
        }

        match op_type {
            "read" => self.read_count,
            "write" => self.write_count,
            "create" => self.create_count,
            "delete" => self.delete_count,
            "rename" => self.rename_count,
            "setinfo" => self.setinfo_count,
            "registry_read" => self.registry_read_count,
            "registry_write" => self.registry_write_count,
            "registry_delete" => self.registry_delete_count,
            "registry_create" => self.registry_create_count,
            "process_create" => self.process_create_count,
            "process_terminate" => self.process_terminate_count,
            "process_exit" => self.process_exit_count,
            "process_handle_open" => self.process_handle_open_count,
            "process_terminate_attempt" => self.process_terminate_attempt_count,
            "hypervisor_event" => self.hypervisor_event_count,
            "named_pipe_create" | "pipe_create" => self.pipe_create_count,
            "named_pipe_write" | "pipe_write" => self.pipe_write_count,
            _ => 0,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypervisorStats {
    pub hyp_event_count: u64,
    pub hypervisor_event_count: u64,
}

#[allow(dead_code)]
impl HypervisorStats {
    pub fn get_injection_api_count(&self) -> u64 {
        self.hypervisor_event_count
    }

    /// Check if process has any hypervisor event activity.
    pub fn has_injection_indicators(&self) -> bool {
        self.hypervisor_event_count > 0
    }
}

// ---------------------------------------------------------------------------
// ROOTKIT DETECTION STRUCTURES
// ---------------------------------------------------------------------------

/// A single rootkit detection finding forwarded from the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitFinding {
    pub kind: RootkitFindingKind,
    pub description: String,
    /// Memory address involved (hook target, hidden driver base, etc.)
    pub address: u64,
    /// PID for hidden-process findings, 0 otherwise.
    pub pid: u32,
    /// Auxiliary value (SSDT index, hook redirect address, …)
    pub extra: u64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootkitFindingKind {
    SsdtHook,
    HiddenProcess,
    HiddenDriver,
    KernelInlineHook,
    TerminateProcess,
    FileMove,
    /// Catch-all for any rootkit event opcode not covered by the specific variants above.
    Generic,
    Unknown(u8),
}

impl RootkitFindingKind {
    pub fn from_irp_op(op: IrpMajorOp) -> Self {
        match op {
            IrpMajorOp::IrpRootkitSsdtHook => RootkitFindingKind::SsdtHook,
            IrpMajorOp::IrpRootkitHiddenProcess => RootkitFindingKind::HiddenProcess,
            IrpMajorOp::IrpRootkitHiddenDriver => RootkitFindingKind::HiddenDriver,
            IrpMajorOp::IrpRootkitKernelHook => RootkitFindingKind::KernelInlineHook,
            IrpMajorOp::IrpRootkitTerminateProcess => RootkitFindingKind::TerminateProcess,
            IrpMajorOp::IrpRootkitFileMove => RootkitFindingKind::FileMove,
            IrpMajorOp::IrpRootkitGeneric => RootkitFindingKind::Generic,
            _ => RootkitFindingKind::Unknown(0),
        }
    }

    pub fn threat_label(&self) -> &'static str {
        match self {
            RootkitFindingKind::SsdtHook => "SSDT Hook",
            RootkitFindingKind::HiddenProcess => "Hidden Process (DKOM)",
            RootkitFindingKind::HiddenDriver => "Hidden Driver",
            RootkitFindingKind::KernelInlineHook => "Kernel Inline Hook",
            RootkitFindingKind::TerminateProcess => "Rootkit Terminate Process",
            RootkitFindingKind::FileMove => "Rootkit File Move",
            RootkitFindingKind::Generic => "Generic Rootkit Event",
            RootkitFindingKind::Unknown(_) => "Unknown Rootkit Event",
        }
    }

    pub fn severity(&self) -> u8 {
        // 0 = low, 1 = medium, 2 = high, 3 = critical
        match self {
            RootkitFindingKind::SsdtHook => 3,
            RootkitFindingKind::HiddenProcess => 3,
            RootkitFindingKind::HiddenDriver => 3,
            RootkitFindingKind::KernelInlineHook => 2,
            RootkitFindingKind::TerminateProcess => 3,
            RootkitFindingKind::FileMove => 2,
            RootkitFindingKind::Generic => 2,
            RootkitFindingKind::Unknown(_) => 1,
        }
    }
}

// GLOBAL PROTECTED/EXCLUDED PATHS
// =============================================================================

fn normalize_path_separators(path: &str) -> String {
    path.replace("\\", "/").trim_end_matches('/').to_string()
}

fn normalize_device_prefix(path: &str) -> String {
    let mut p = path.trim().to_string();
    let p_lc = p.to_lowercase();
    if p_lc.starts_with("\\\\?\\") {
        p = p[4..].to_string();
    } else if p_lc.starts_with("\\??\\") {
        p = p[4..].to_string();
    }

    let p_norm = p.replace("\\", "/");
    let p_trim = p_norm.trim_start_matches('/');
    let p_trim_lc = p_trim.to_lowercase();

    // \Device\HarddiskVolumeX\Users\... -> Users\...
    if p_trim_lc.starts_with("device/harddiskvolume") {
        let after_device = &p_trim["device/".len()..];
        if let Some(idx) = after_device.find('/') {
            let remainder = &after_device[idx + 1..];
            if !remainder.is_empty() {
                return remainder.to_string();
            }
        }
    }

    // Defensive: HarddiskVolumeX\Users\... -> Users\...
    if p_trim_lc.starts_with("harddiskvolume")
        && let Some(idx) = p_trim.find('/')
    {
        let remainder = &p_trim[idx + 1..];
        if !remainder.is_empty() {
            return remainder.to_string();
        }
    }

    p
}

fn strip_drive_prefix(path: &str) -> String {
    if path.len() >= 3
        && path.as_bytes()[1] == b':'
        && (path.as_bytes()[2] == b'\\' || path.as_bytes()[2] == b'/')
    {
        return path[2..].trim_start_matches(['\\', '/']).to_string();
    }
    path.to_string()
}

fn build_path_variants(norm_path: &str, raw_path: &str) -> Vec<String> {
    let mut variants = HashSet::new();
    if !norm_path.is_empty() {
        variants.insert(norm_path.to_string());
        let stripped = strip_drive_prefix(norm_path);
        // Add with a leading "/" so patterns like ":/explorer.exe" (from ":\\explorer.exe")
        // can match paths that came through normalize_device_prefix and lost their drive letter.
        if !stripped.starts_with('/') {
            variants.insert(format!("/{}", stripped));
        }
        variants.insert(stripped);
    }
    if !raw_path.is_empty() {
        let raw_norm = raw_path.to_lowercase().replace("\\", "/");
        variants.insert(raw_norm.clone());
        let raw_stripped = strip_drive_prefix(&raw_norm);
        if !raw_stripped.starts_with('/') {
            variants.insert(format!("/{}", raw_stripped));
        }
        variants.insert(raw_stripped);
    }
    variants.into_iter().filter(|v| !v.is_empty()).collect()
}

fn canonical_behavior_path(path: &str) -> String {
    let normalized = normalize_device_prefix(path);
    let normalized = normalize_path_separators(&normalized.to_lowercase());
    strip_drive_prefix(&normalized)
}

fn target_matches_process_image(
    process_path: &Path,
    observed_norm: &str,
    observed_raw: &str,
) -> bool {
    if process_path.as_os_str().is_empty() {
        return false;
    }

    let process_path_str = process_path.to_string_lossy();
    let expected = canonical_behavior_path(&process_path_str);
    if expected.is_empty() {
        return false;
    }

    build_path_variants(observed_norm, observed_raw)
        .into_iter()
        .map(|variant| canonical_behavior_path(&variant))
        .any(|candidate| !candidate.is_empty() && candidate == expected)
}

fn is_delete_like_file_operation(irp_op: &IrpMajorOp, file_change: Option<FileChangeInfo>) -> bool {
    matches!(
        (irp_op, file_change),
        (
            IrpMajorOp::IrpSetInfo,
            Some(FileChangeInfo::ChangeDeleteFile)
        ) | (
            IrpMajorOp::IrpSetInfo,
            Some(FileChangeInfo::ChangeDeleteNewFile)
        )
    )
}

fn is_rename_like_file_operation(irp_op: &IrpMajorOp, file_change: Option<FileChangeInfo>) -> bool {
    matches!(
        (irp_op, file_change),
        (
            IrpMajorOp::IrpSetInfo,
            Some(FileChangeInfo::ChangeRenameFile)
        ) | (
            IrpMajorOp::IrpSetInfo,
            Some(FileChangeInfo::ChangeExtensionChanged)
        )
    )
}

fn is_file_data_irp(irp_op: &IrpMajorOp) -> bool {
    matches!(
        irp_op,
        IrpMajorOp::IrpRead | IrpMajorOp::IrpWrite | IrpMajorOp::IrpCreate | IrpMajorOp::IrpSetInfo
    )
}

fn normalize_irp_operation_token(token: &str) -> String {
    token
        .trim()
        .trim_start_matches("IRP_")
        .trim_start_matches("Irp")
        .replace(['-', ' ', ':'], "_")
        .to_ascii_lowercase()
}

fn irp_opcode_from_operation_token(token: &str) -> Option<u32> {
    let normalized = normalize_irp_operation_token(token);
    let numeric = normalized
        .strip_prefix("opcode_")
        .or_else(|| normalized.strip_prefix("opcode"))
        .or_else(|| normalized.strip_prefix("op_"))
        .or_else(|| normalized.strip_prefix("op"))
        .or_else(|| normalized.strip_prefix("irp_"))
        .or_else(|| normalized.strip_prefix("irp"));
    if let Some(value) = numeric
        && let Ok(opcode) = value.parse::<u32>()
        && opcode <= 29
    {
        return Some(opcode);
    }
    if let Ok(opcode) = normalized.parse::<u32>()
        && opcode <= 29
    {
        return Some(opcode);
    }

    match normalized.as_str() {
        "none" => Some(0),
        "read" => Some(1),
        "write" => Some(2),
        "setinfo" | "set_info" => Some(3),
        "create" | "open" => Some(4),
        "cleanup" | "clean_up" => Some(5),
        "registry" => Some(6),
        "process_create" | "processcreate" | "proc_create" | "proccreate" => Some(7),
        "process_terminate" | "processterminate" | "proc_terminate" | "proc_term" | "procterm" => {
            Some(8)
        }
        "process_terminate_attempt" | "proc_terminate_attempt" | "proc_term_attempt" => Some(9),
        "process_exit" | "processexit" | "proc_exit" | "procexit" => Some(10),
        "process_handle_open" | "processhandleopen" | "proc_handle_open" | "prochandleopen" => {
            Some(11)
        }
        "hypervisor" | "hypervisor_event" | "hypervisorevent" => Some(12),
        "kernel_remote_thread"
        | "kernelremotethread"
        | "kern_remote_thread"
        | "kernremotethread" => Some(13),
        "kernel_write_memory" | "kernelwritememory" | "kern_write_mem" | "kernwritemem" => Some(14),
        "kernel_protect_memory" | "kernelprotectmemory" | "kern_protect_mem" | "kernprotectmem" => {
            Some(15)
        }
        "kernel_create_thread"
        | "kernelcreatethread"
        | "kern_create_thread"
        | "kerncreatethread" => Some(16),
        "kernel_queue_apc" | "kernelqueueapc" | "kern_queue_apc" | "kernqueueapc" => Some(17),
        "kernel_create_section"
        | "kernelcreatesection"
        | "kern_create_section"
        | "kerncreatesection" => Some(18),
        "kernel_map_section" | "kernelmapsection" | "kern_map_section" | "kernmapsection" => {
            Some(19)
        }
        "user_mode_hook"
        | "user_mode_hook_event"
        | "usermode_hook"
        | "usermodehook"
        | "usermodehookevent" => Some(20),
        "rootkit_ssdt_hook" | "rootkitssdthook" | "rk_ssdt_hook" | "rkssdthook" => Some(21),
        "rootkit_hidden_process" | "rootkithiddenprocess" | "rk_hidden_proc" | "rkhiddenproc" => {
            Some(22)
        }
        "rootkit_hidden_driver" | "rootkithiddendriver" | "rk_hidden_drv" | "rkhiddendrv" => {
            Some(23)
        }
        "rootkit_kernel_hook" | "rootkitkernelhook" | "rk_kernel_hook" | "rkkernelhook" => Some(24),
        "rootkit_terminate_process" | "rootkitterminateprocess" | "rk_term_proc" | "rktermproc" => {
            Some(25)
        }
        "rootkit_file_move" | "rootkitfilemove" | "rk_file_move" | "rkfilemove" => Some(26),
        "rootkit_generic" | "rootkitgeneric" | "rk_generic" | "rkgeneric" => Some(27),
        "named_pipe_create" | "namedpipecreate" | "pipe_create" | "pipecreate" => Some(28),
        "named_pipe_write" | "namedpipewrite" | "pipe_write" | "pipewrite" => Some(29),
        _ => None,
    }
}

fn irp_operation_matches_token(irp_type: u32, file_change: u8, token: &str) -> bool {
    let normalized = normalize_irp_operation_token(token);
    let irp_op = IrpMajorOp::from_sysmonevent(irp_type);

    match normalized.as_str() {
        "delete" => {
            return irp_op == IrpMajorOp::IrpSetInfo
                && matches!(
                    file_change,
                    x if x == FileChangeInfo::ChangeDeleteFile as u8
                        || x == FileChangeInfo::ChangeDeleteNewFile as u8
                );
        }
        "rename" => {
            return irp_op == IrpMajorOp::IrpSetInfo
                && matches!(
                    file_change,
                    x if x == FileChangeInfo::ChangeRenameFile as u8
                        || x == FileChangeInfo::ChangeExtensionChanged as u8
                );
        }
        "registry_read" => {
            return irp_op == IrpMajorOp::IrpRegistry
                && !matches!(
                    file_change,
                    x if x == FileChangeInfo::RegCreateKey as u8
                        || x == FileChangeInfo::RegSetValue as u8
                        || x == FileChangeInfo::RegDeleteValue as u8
                        || x == FileChangeInfo::RegDeleteKey as u8
                        || x == FileChangeInfo::RegRenameKey as u8
                );
        }
        "registry_write" => {
            return irp_op == IrpMajorOp::IrpRegistry
                && file_change == FileChangeInfo::RegSetValue as u8;
        }
        "registry_delete" => {
            return irp_op == IrpMajorOp::IrpRegistry
                && matches!(
                    file_change,
                    x if x == FileChangeInfo::RegDeleteValue as u8
                        || x == FileChangeInfo::RegDeleteKey as u8
                );
        }
        "registry_create" => {
            return irp_op == IrpMajorOp::IrpRegistry
                && file_change == FileChangeInfo::RegCreateKey as u8;
        }
        _ => {}
    }

    irp_opcode_from_operation_token(&normalized) == Some(irp_type as u32)
}

const RECENT_WRITTEN_PAYLOAD_RETENTION_SECS: u64 = 300;
const RECENT_WRITTEN_PAYLOAD_MAX_TRACKED: usize = 128;

fn is_launchable_payload_extension(ext: &str) -> bool {
    matches!(
        normalize_extension_token(ext).as_str(),
        "exe"
            | "com"
            | "scr"
            | "dll"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "wsh"
            | "hta"
            | "cpl"
            | "pif"
    )
}

fn is_write_or_create_like_file_operation(
    irp_op: &IrpMajorOp,
    file_change: Option<FileChangeInfo>,
) -> bool {
    matches!(
        (irp_op, file_change),
        (IrpMajorOp::IrpWrite, _)
            | (IrpMajorOp::IrpCreate, _)
            | (IrpMajorOp::IrpSetInfo, Some(FileChangeInfo::ChangeWrite))
            | (
                IrpMajorOp::IrpSetInfo,
                Some(FileChangeInfo::ChangeOverwriteFile)
            )
            | (IrpMajorOp::IrpSetInfo, Some(FileChangeInfo::ChangeNewFile))
            | (
                IrpMajorOp::IrpSetInfo,
                Some(FileChangeInfo::ChangeRenameFile)
            )
            | (
                IrpMajorOp::IrpSetInfo,
                Some(FileChangeInfo::ChangeExtensionChanged)
            )
    )
}

fn extract_path_extension(path: &str) -> String {
    let path = normalize_path_separators(path);
    let last_sep = path.rfind('/').unwrap_or(0);
    let Some(last_dot) = path.rfind('.') else {
        return String::new();
    };
    if last_dot <= last_sep {
        return String::new();
    }
    normalize_extension_token(&path[last_dot + 1..])
}

fn is_cmdline_path_boundary_byte(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'=' | b',' | b';' | b'(' | b')')
}

fn cmdline_contains_candidate_path(cmdline_norm: &str, candidate_path: &str) -> bool {
    let candidate_norm = normalize_path_separators(candidate_path);
    if candidate_norm.is_empty() {
        return false;
    }

    let mut variants = vec![candidate_norm.clone()];
    let stripped = strip_drive_prefix(&candidate_norm);
    if !stripped.is_empty() && stripped != candidate_norm {
        variants.push(stripped);
    }

    for variant in variants {
        let mut search_offset = 0usize;
        while let Some(rel_pos) = cmdline_norm[search_offset..].find(&variant) {
            let abs_pos = search_offset + rel_pos;
            let before_ok =
                abs_pos == 0 || is_cmdline_path_boundary_byte(cmdline_norm.as_bytes()[abs_pos - 1]);
            let after_pos = abs_pos + variant.len();
            let after_ok = after_pos == cmdline_norm.len()
                || is_cmdline_path_boundary_byte(cmdline_norm.as_bytes()[after_pos]);
            if before_ok && after_ok {
                return true;
            }
            search_offset = abs_pos + variant.len();
        }
    }

    false
}

fn is_plain_pattern(pattern: &str) -> bool {
    let trimmed = pattern.trim();
    !trimmed.is_empty()
        && !trimmed.contains('*')
        && !trimmed.contains('?')
        && !trimmed.starts_with("(?")
        && !trimmed.starts_with('^')
        && !trimmed.ends_with('$')
}

fn pattern_looks_like_path(pattern: &str) -> bool {
    let normalized = normalize_path_separators(&pattern.trim().to_lowercase());
    normalized.contains(":/")
        || normalized.starts_with('/')
        || normalized.starts_with('%')
        || normalized.contains('/')
}

fn canonical_hypervisor_event_label(
    irp_op: &IrpMajorOp,
    raw_event_type: u32,
    event_name: &str,
) -> Option<String> {
    let normalized_event_name = normalize_hypervisor_label(event_name);
    if !normalized_event_name.is_empty() && !is_generic_hypervisor_label(&normalized_event_name) {
        return Some(normalized_event_name);
    }

    // raw_event_type 12–29 are the legacy Communication.cpp hypervisor sub-types.
    // For those we map back through from_sysmonevent for semantic resolution.
    let resolved = match raw_event_type {
        12..=29 => IrpMajorOp::from_sysmonevent(raw_event_type),
        _ => irp_op.clone(),
    };
    match resolved {
        IrpMajorOp::IrpHypervisorEvent if is_hypervisor_raw_event_type(raw_event_type) => {
            known_raw_event_name(raw_event_type)
                .map(|name| name.to_string())
                .filter(|name| !is_generic_hypervisor_label(name))
                .or_else(|| Some(format!("RawHypervisorEvent(0x{raw_event_type:X})")))
        }
        IrpMajorOp::IrpHypervisorEvent
        | IrpMajorOp::IrpUserModeHookEvent
        | IrpMajorOp::IrpKernelRemoteThread
        | IrpMajorOp::IrpKernelWriteMemory
        | IrpMajorOp::IrpKernelProtectMemory
        | IrpMajorOp::IrpKernelCreateThread
        | IrpMajorOp::IrpKernelQueueApc
        | IrpMajorOp::IrpKernelCreateSection
        | IrpMajorOp::IrpKernelMapSection
        | IrpMajorOp::IrpRootkitSsdtHook
        | IrpMajorOp::IrpRootkitHiddenProcess
        | IrpMajorOp::IrpRootkitHiddenDriver
        | IrpMajorOp::IrpRootkitKernelHook
        | IrpMajorOp::IrpRootkitTerminateProcess
        | IrpMajorOp::IrpRootkitFileMove
        | IrpMajorOp::IrpRootkitGeneric
        | IrpMajorOp::IrpNamedPipeCreate
        | IrpMajorOp::IrpNamedPipeWrite => Some(format!("{:?}", resolved)),
        _ => None,
    }
}

fn is_generic_hypervisor_label(raw: &str) -> bool {
    matches!(
        raw.trim(),
        "IrpHypervisorEvent"
            | "IrpUserModeHookEvent"
            | "IrpKernelRemoteThread"
            | "IrpKernelWriteMemory"
            | "IrpKernelProtectMemory"
            | "IrpKernelCreateThread"
            | "IrpKernelQueueApc"
            | "IrpKernelCreateSection"
            | "IrpKernelMapSection"
            | "IRP_HYPERVISOR_EVENT"
            | "IRP_USER_MODE_HOOK_EVENT"
            | "IRP_KERNEL_REMOTE_THREAD"
            | "IRP_KERNEL_WRITE_MEMORY"
            | "IRP_KERNEL_PROTECT_MEMORY"
            | "IRP_KERNEL_CREATE_THREAD"
            | "IRP_KERNEL_QUEUE_APC"
            | "IRP_KERNEL_CREATE_SECTION"
            | "IRP_KERNEL_MAP_SECTION"
    )
}

fn is_real_api_observation(raw: &str) -> bool {
    let normalized = normalize_hypervisor_label(raw);
    if normalized.is_empty() || is_generic_hypervisor_label(&normalized) {
        return false;
    }

    let simple_name = normalized
        .rsplit('!')
        .next()
        .unwrap_or(normalized.as_str())
        .trim();
    if simple_name.is_empty() {
        return false;
    }

    if simple_name.starts_with("Nt") || simple_name.starts_with("Zw") {
        return simple_name
            .chars()
            .nth(2)
            .is_some_and(|ch| ch.is_ascii_uppercase());
    }

    let has_lowercase = simple_name.chars().any(|ch| ch.is_ascii_lowercase());
    let has_underscore = simple_name.contains('_');
    let has_path_qualifier = normalized.contains('!');

    (has_path_qualifier || has_lowercase) && !has_underscore
}

const STATUS_SUCCESS_U32: u32 = 0x00000000;
const STATUS_INVALID_HANDLE_U32: u32 = 0xC0000008;
const HRESULT_INVALID_HANDLE_U32: u32 = 0x80070006;
const STATUS_ACCESS_DENIED_U32: u32 = 0xC0000022;
const STATUS_OBJECT_NAME_NOT_FOUND_U32: u32 = 0xC0000034;
const STATUS_INVALID_PAGE_PROTECTION_U32: u32 = 0xC0000045;
const STATUS_DYNAMIC_CODE_BLOCKED_U32: u32 = 0xC0000604;
const HRESULT_DYNAMIC_CODE_BLOCKED_U32: u32 = 0x80070677;
const STATUS_HANDLE_NOT_CLOSABLE_U32: u32 = 0xC0000235;

fn hook_status_code(operation_status: i32) -> u32 {
    operation_status as u32
}

fn hook_status_name(operation_status: i32) -> &'static str {
    match hook_status_code(operation_status) {
        STATUS_SUCCESS_U32 => "STATUS_SUCCESS",
        STATUS_INVALID_HANDLE_U32 => "STATUS_INVALID_HANDLE",
        HRESULT_INVALID_HANDLE_U32 => "HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)",
        STATUS_ACCESS_DENIED_U32 => "STATUS_ACCESS_DENIED",
        STATUS_OBJECT_NAME_NOT_FOUND_U32 => "STATUS_OBJECT_NAME_NOT_FOUND",
        STATUS_INVALID_PAGE_PROTECTION_U32 => "STATUS_INVALID_PAGE_PROTECTION",
        STATUS_DYNAMIC_CODE_BLOCKED_U32 => "STATUS_DYNAMIC_CODE_BLOCKED",
        HRESULT_DYNAMIC_CODE_BLOCKED_U32 => "HRESULT_FROM_WIN32(ERROR_DYNAMIC_CODE_BLOCKED)",
        STATUS_HANDLE_NOT_CLOSABLE_U32 => "STATUS_HANDLE_NOT_CLOSABLE",
        _ => "STATUS_UNKNOWN",
    }
}

fn is_handle_lifetime_failure_status(operation_status: i32) -> bool {
    matches!(
        hook_status_code(operation_status),
        STATUS_INVALID_HANDLE_U32 | HRESULT_INVALID_HANDLE_U32
    )
}

fn is_dynamic_code_or_page_protection_status(operation_status: i32) -> bool {
    matches!(
        hook_status_code(operation_status),
        STATUS_INVALID_PAGE_PROTECTION_U32
            | STATUS_DYNAMIC_CODE_BLOCKED_U32
            | HRESULT_DYNAMIC_CODE_BLOCKED_U32
    )
}

fn is_antitamper_status(operation_status: i32) -> bool {
    matches!(
        hook_status_code(operation_status),
        STATUS_HANDLE_NOT_CLOSABLE_U32 | STATUS_ACCESS_DENIED_U32
    )
}

fn is_benign_hypervisor_failure_status(operation_status: i32, is_acg_enabled: bool) -> bool {
    if operation_status == 0 {
        return false;
    }

    // These failures are expected fallout from ACG/code-integrity/page-protection
    // guarded processes. Keep them in hook_error telemetry, but do not let them
    // become normal successful API observations or behavior score input.
    is_acg_enabled
        && (is_handle_lifetime_failure_status(operation_status)
            || is_dynamic_code_or_page_protection_status(operation_status))
}

fn is_hook_error_status(operation_status: i32) -> bool {
    operation_status != 0
}

fn is_actionable_hypervisor_event(
    irp_op: &IrpMajorOp,
    raw: &str,
    raw_event_type: u32,
    operation_status: i32,
    is_acg_enabled: bool,
) -> bool {
    if !is_kernel_api_irp(irp_op) {
        return false;
    }

    // Benign handle-race fallout from GUI/WebView/browser lifetime churn should
    // stay visible in low-level telemetry, but must not contaminate behavioral
    // API history or trigger higher-level detections.
    if is_benign_hypervisor_failure_status(operation_status, is_acg_enabled) {
        return false;
    }

    if is_kernel_process_protection_irp(irp_op)
        || matches!(irp_op, IrpMajorOp::IrpUserModeHookEvent)
    {
        return true;
    }

    if !is_real_hypervisor_irp(irp_op, raw_event_type) {
        return false;
    }

    let normalized = normalize_hypervisor_label(raw);
    if !normalized.is_empty() && !is_generic_hypervisor_label(&normalized) {
        return true;
    }

    is_hypervisor_raw_event_type(raw_event_type)
}

fn api_function_alias(raw: &str) -> Option<String> {
    let normalized = normalize_hypervisor_label(raw);
    if normalized.is_empty() || !normalized.contains('!') {
        return None;
    }
    normalized
        .rsplit('!')
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn normalize_extension_token(extension: &str) -> String {
    extension
        .trim()
        .trim_matches('"')
        .trim_matches(char::from(0))
        .trim_start_matches('.')
        .to_lowercase()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExtensionWhitelistSourceMode {
    Feedback,
    ExtensionsRsOnly,
    ExtensionsTxtOnly,
}

impl ExtensionWhitelistSourceMode {
    fn as_str(self) -> &'static str {
        match self {
            ExtensionWhitelistSourceMode::Feedback => "feedback",
            ExtensionWhitelistSourceMode::ExtensionsRsOnly => "extensions_rs_only",
            ExtensionWhitelistSourceMode::ExtensionsTxtOnly => "extensions_txt_only",
        }
    }
}

fn parse_extension_whitelist_source_mode(raw: &str) -> Option<ExtensionWhitelistSourceMode> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .replace(' ', "_")
        .replace('-', "_")
        .replace('.', "_");

    match normalized.as_str() {
        "" | "feedback" | "feedback_mode" | "auto" | "auto_feedback" => {
            Some(ExtensionWhitelistSourceMode::Feedback)
        }
        "extensions_rs_only" | "extension_rs_only" | "rs_only" | "rust_only" | "hardcoded_only" => {
            Some(ExtensionWhitelistSourceMode::ExtensionsRsOnly)
        }
        "extensions_txt_only" | "extension_txt_only" | "txt_only" | "list_only" | "rules_only" => {
            Some(ExtensionWhitelistSourceMode::ExtensionsTxtOnly)
        }
        _ => None,
    }
}

fn extension_whitelist_source_mode(configured_mode: Option<&str>) -> ExtensionWhitelistSourceMode {
    if let Some(raw_mode) = configured_mode
        .map(str::trim)
        .filter(|mode| !mode.is_empty())
    {
        if let Some(mode) = parse_extension_whitelist_source_mode(raw_mode) {
            Logging::info(&format!(
                "[BehaviorEngine] ExtensionSource config param=EXTENSION_SOURCE_MODE value={} resolved_mode={}",
                raw_mode,
                mode.as_str()
            ));
            return mode;
        }
        Logging::warning(&format!(
            "[BehaviorEngine] Unknown extension source mode config value={}; using feedback mode. \
             Valid values: feedback, extensions_rs_only, extensions_txt_only",
            raw_mode
        ));
        return ExtensionWhitelistSourceMode::Feedback;
    }

    for env_key in [
        "OWLYSHIELD_EXTENSION_SOURCE_MODE",
        "HYDRADRAGON_EXTENSION_SOURCE_MODE",
    ] {
        let Ok(raw_mode) = std::env::var(env_key) else {
            continue;
        };
        if let Some(mode) = parse_extension_whitelist_source_mode(&raw_mode) {
            Logging::info(&format!(
                "[BehaviorEngine] ExtensionSource config env={} value={} resolved_mode={}",
                env_key,
                raw_mode,
                mode.as_str()
            ));
            return mode;
        }
        Logging::warning(&format!(
            "[BehaviorEngine] Unknown extension source mode env={} value={}; using feedback mode. \
             Valid values: feedback, extensions_rs_only, extensions_txt_only",
            env_key, raw_mode
        ));
        return ExtensionWhitelistSourceMode::Feedback;
    }

    ExtensionWhitelistSourceMode::Feedback
}

fn extension_txt_candidates() -> Vec<(&'static str, PathBuf)> {
    let mut candidates = Vec::new();

    if let Some(rules_path) = crate::globals::RULES_PATH.get() {
        candidates.push(("rules_path", rules_path.join("extensions.txt")));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push((
            "repo_hydradragon_rules",
            cwd.join("hydradragon")
                .join("Owlyshield")
                .join("rules")
                .join("extensions.txt"),
        ));
        candidates.push(("cwd_rules", cwd.join("rules").join("extensions.txt")));
    }

    candidates
}

fn load_extensions_txt_whitelist() -> Option<(HashSet<String>, &'static str, PathBuf)> {
    for (candidate_name, path) in extension_txt_candidates() {
        if !path.exists() {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) => {
                Logging::warning(&format!(
                    "[BehaviorEngine] Failed to read extensions.txt candidate={} path={}: {}",
                    candidate_name,
                    path.display(),
                    error
                ));
                continue;
            }
        };

        let mut whitelist = HashSet::new();
        for line in content.lines() {
            let trimmed = line.trim().trim_matches('"');
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            let normalized = normalize_extension_token(trimmed);
            if !normalized.is_empty() {
                whitelist.insert(normalized);
            }
        }

        return Some((whitelist, candidate_name, path));
    }

    None
}

fn load_extensions_rs_whitelist() -> HashSet<String> {
    let mut whitelist = HashSet::new();
    let extension_list = ExtensionList::new();

    for category in extension_list.categories.values() {
        for ext in category {
            let normalized = normalize_extension_token(ext);
            if !normalized.is_empty() {
                whitelist.insert(normalized);
            }
        }
    }

    whitelist
}

fn log_extension_source(
    mode: ExtensionWhitelistSourceMode,
    source: &str,
    count: usize,
    detail: &str,
) {
    Logging::info(&format!(
        "[BehaviorEngine] ExtensionSource mode={} source={} engine=behavior_engine count={} feedback=\"{}\"",
        mode.as_str(),
        source,
        count,
        detail
    ));
}

fn build_default_extension_whitelist(configured_mode: Option<&str>) -> HashSet<String> {
    let mode = extension_whitelist_source_mode(configured_mode);

    match mode {
        ExtensionWhitelistSourceMode::ExtensionsRsOnly => {
            let whitelist = load_extensions_rs_whitelist();
            log_extension_source(
                mode,
                "extensions.rs",
                whitelist.len(),
                "hardcoded Rust ExtensionList only; extensions.txt is not read",
            );
            whitelist
        }
        ExtensionWhitelistSourceMode::ExtensionsTxtOnly => {
            if let Some((whitelist, candidate_name, path)) = load_extensions_txt_whitelist() {
                log_extension_source(
                    mode,
                    "extensions.txt",
                    whitelist.len(),
                    &format!(
                        "strict extensions.txt only; candidate={} path={}; extensions.rs fallback disabled",
                        candidate_name,
                        path.display()
                    ),
                );
                return whitelist;
            }

            Logging::warning(
                "[BehaviorEngine] ExtensionSource mode=extensions_txt_only source=none \
                 engine=behavior_engine count=0 feedback=\"extensions.txt not found; \
                 extensions.rs fallback disabled; extensionless files are still scanned\"",
            );
            HashSet::new()
        }
        ExtensionWhitelistSourceMode::Feedback => {
            if let Some((whitelist, candidate_name, path)) = load_extensions_txt_whitelist() {
                log_extension_source(
                    mode,
                    "extensions.txt",
                    whitelist.len(),
                    &format!(
                        "preferred repo rule list; candidate={} path={}; extensions.rs not used",
                        candidate_name,
                        path.display()
                    ),
                );
                return whitelist;
            }

            let whitelist = load_extensions_rs_whitelist();
            Logging::warning(&format!(
                "[BehaviorEngine] ExtensionSource mode=feedback source=extensions.rs \
                 engine=behavior_engine count={} feedback=\"extensions.txt not found; \
                 falling back to hardcoded Rust ExtensionList; set \
                 OWLYSHIELD_EXTENSION_SOURCE_MODE=extensions_txt_only to forbid fallback\"",
                whitelist.len()
            ));
            whitelist
        }
    }
}

const ROOTKIT_GLOBAL_GID: u64 = 0xFFFF_FFFF_FFFF_FFFEu64;
const ROOTKIT_PSEUDO_GID_MASK: u64 = 0x8000_0000_0000_0000u64;

fn is_rootkit_irp(irp_op: &IrpMajorOp) -> bool {
    matches!(
        irp_op,
        IrpMajorOp::IrpRootkitSsdtHook
            | IrpMajorOp::IrpRootkitHiddenProcess
            | IrpMajorOp::IrpRootkitHiddenDriver
            | IrpMajorOp::IrpRootkitKernelHook
            | IrpMajorOp::IrpRootkitTerminateProcess
            | IrpMajorOp::IrpRootkitFileMove
            | IrpMajorOp::IrpRootkitGeneric
    )
}

fn is_rootkit_pseudo_gid(gid: u64) -> bool {
    gid == ROOTKIT_GLOBAL_GID || (gid & ROOTKIT_PSEUDO_GID_MASK) == ROOTKIT_PSEUDO_GID_MASK
}

// =============================================================================
// PART 2: ENHANCED PROCESS STATE WITH IRP TRACKING
// =============================================================================

#[derive(Default, Clone)]
pub struct ProcessBehaviorState {
    pub browsed_paths_tracker: HashMap<String, SystemTime>,
    pub accessed_paths_tracker: HashSet<String>,
    pub staged_files_written: HashMap<PathBuf, SystemTime>,
    pub recent_written_payloads: HashMap<String, SystemTime>,
    pub terminated_processes: HashSet<String>,
    pub self_terminated_processes: HashSet<String>,
    pub detected_apis: HashSet<String>,

    #[allow(dead_code)]
    pub monitored_api_count: usize,
    pub high_entropy_detected: bool,
    pub file_action_detected: bool,
    pub extension_match_detected: bool,
    pub parent_name: String,
    pub parent_path: PathBuf,
    pub command_line: String,

    pub pid: u32,
    pub exe_path: PathBuf,
    pub app_name: String,
    pub signature_checked: bool,
    pub signature_checked_path: PathBuf,
    pub has_valid_signature: bool,
    pub is_signed: bool,
    pub signature_status: String,
    pub signature_status_text: String,
    pub signature_raw_hresult: Option<u32>,
    pub signature_verification_failed: bool,
    pub signature_no_signature: bool,
    pub signature_status_issues: bool,
    pub signature_invalid: bool,
    pub signer_name: Option<String>,

    pub satisfied_named_conditions: HashSet<String>,
    pub condition_match_counts: HashMap<String, usize>,
    pub condition_match_values: HashMap<String, HashSet<String>>,
    pub condition_first_seen: HashMap<String, SystemTime>,
    pub condition_last_seen: HashMap<String, SystemTime>,

    // Comprehensive IRP tracking
    pub irp_operations: Vec<IrpOperationRecord>,
    pub irp_stats: IrpStatistics,
    pub all_apis_called: HashSet<String>,
    pub observed_hypervisor_event_labels: HashSet<String>,
    pub recent_kernel_api_events: VecDeque<String>,

    // Self-defense telemetry from OpenEDR/Owlyshield kernel sensors.
    pub self_defense_events: VecDeque<SelfDefenseTelemetryEvent>,
    pub self_defense_event_count: u32,
    pub self_defense_category_counts: HashMap<String, usize>,
    pub self_defense_attack_counts: HashMap<String, usize>,

    // User-mode hook / kernel API failure telemetry. This stays separate from
    // successful API observations so sandbox/handle-query failures can be used
    // by rules without polluting API behavior scores.
    pub hook_error_count: u32,
    pub hook_error_status_counts: HashMap<i32, usize>,
    pub hook_error_api_counts: HashMap<String, usize>,
    pub recent_hook_errors: VecDeque<HookErrorRecord>,

    // Normalized hypervisor event tracking
    pub hypervisor_event_count: u32,
    pub hypervisor_events_total: u32,

    // Stems collected from create events where the file had an unknown (non-whitelisted) extension.
    // Key: lowercase full path with the last extension stripped.
    // e.g., creating "c:/users/foo/document.docx.winball" stores "c:/users/foo/document.docx".
    // Used by `require_same_stem_created_unknown_extension` on delete conditions.
    pub created_unknown_ext_stems: HashSet<String>,

    // Stems collected from write events where the file had an unknown (non-whitelisted) extension.
    // Key: lowercase full path with the last extension stripped.
    // e.g., writing "c:/users/foo/document.docx.winball" stores "c:/users/foo/document.docx".
    // Used by `require_same_stem_written_unknown_extension` on rename conditions.
    pub written_unknown_ext_stems: HashSet<String>,

    // Script file extracted from the interpreter's command line.
    // e.g. for `powershell.exe -File C:\foo\evil.ps1`:
    //   script_file      = "evil.ps1"
    //   script_file_path = "c:/foo/evil.ps1"
    pub script_file: String,
    pub script_file_path: String,

    /// HTTP body pairs (request_body, response_body) received via the FULL_PACKED_DATA pipe message.
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub http_body_entries: Vec<(String, String)>,

    /// Rolling history of network packets captured for this process (FULL_PACKED_DATA).
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub net_packets: VecDeque<PacketInfo>,

    /// AMSI analysis results for script content monitored by the engine.
    pub amsi_results: Vec<crate::behavioral::amsi::AmsiAnalysisResult>,

    /// Sanctum EDR telemetry stats for real-time learning.
    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub sanctum_stats: crate::realtime_learning::api_tracker::SanctumOperationStats,
    /// Historical hits for Sanctum suspicious syscalls throughout the process lifetime.
    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub sanctum_suspicious_hits: HashSet<String>,

    /// True if this process has been implicated in a rootkit finding.
    pub rootkit_implicated: bool,
    /// All rootkit events detected for this process.
    pub rootkit_findings: Vec<RootkitFinding>,
    pub cloud_static_label: Option<String>,
    pub cloud_dynamic_label: Option<String>,
    /// OpenEDR FLS verdict/result code: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail.
    pub cloud_static_verdict: Option<u8>,
    /// OpenEDR FLS verdict/result code: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail.
    pub cloud_dynamic_verdict: Option<u8>,

    // DLL Load Detection - Tracks both API-based and direct DLL loading
    pub dll_load_count: u32,
    pub dll_api_load_count: u32,    // Loaded via API (LoadLibrary)
    pub dll_direct_load_count: u32, // Direct load without API
    pub loaded_dlls_full_path: HashSet<String>, // Full paths for regex matching
    pub loaded_dlls_name_only: HashSet<String>, // DLL names only for regex matching
    pub dll_load_details: Vec<DllLoadInfo>,

    // ACG Detection
    pub is_acg_enabled: bool,

    // Static File Scanning Results (from Sanctum FileScanner integration)
    /// Hash-based IOC matches from static file scanning
    pub static_ioc_matches: Vec<StaticIocMatch>,
    /// Whether this process executable matched a known malicious hash
    pub static_hash_malicious: bool,
    /// MD5 hash of the process executable (if computed)
    pub static_file_hash: Option<String>,
    /// Timestamp of last static scan
    pub static_scan_timestamp: Option<SystemTime>,
    /// Number of files scanned by this process
    pub static_files_scanned: u32,
    /// Static scan state
    pub static_scan_state: StaticScanState,

    /// DetectItEasy static analysis results (from Owlyshield)
    pub detectiteasy_result: Option<DetectItEasyResult>,
    /// Whether the file is packed/protected
    pub is_packed: bool,
    pub is_protected: bool,
    /// Packer/protector names
    pub packer_name: Option<String>,
    pub protector_name: Option<String>,
    /// Special detections
    pub is_vmprotect: bool,
    pub is_themida: bool,
    pub is_dotnet: bool,
    pub is_pyinstaller: bool,
    pub is_upx: bool,
    /// File type from static analysis
    pub static_file_type: Option<String>,

    /// MITRE ATT&CK Integration (only available with behavior_engine feature)
    /// Mapped MITRE ATT&CK techniques observed for this process
    pub mitre_techniques: HashSet<String>,
    /// MITRE ATT&CK timeline events
    pub mitre_timeline_events: Vec<MitreTimelineEvent>,
    /// MITRE ATT&CK threat score
    pub mitre_threat_score: f64,
}

/// Static IOC match information from hash-based file scanning
#[derive(Debug, Clone)]
pub struct StaticIocMatch {
    pub hash: String,
    pub file_path: PathBuf,
    pub match_timestamp: SystemTime,
}

/// State of static file scanning for a process
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticScanState {
    NotScanned,
    Scanning,
    Clean,
    Malicious,
    Error(String),
}

impl Default for StaticScanState {
    fn default() -> Self {
        StaticScanState::NotScanned
    }
}

/// DetectItEasy analysis result summary for behavior engine
#[derive(Debug, Clone)]
pub struct DetectItEasyResult {
    pub is_pe: bool,
    pub is_elf: bool,
    pub is_packed: bool,
    pub is_protected: bool,
    pub packer_name: Option<String>,
    pub protector_name: Option<String>,
    pub is_vmprotect: bool,
    pub is_themida: bool,
    pub is_dotnet: bool,
    pub is_pyinstaller: bool,
    pub is_nuitka: bool,
    pub is_upx: bool,
    pub is_go_garble: bool,
    pub file_type: Option<String>,
    pub is_broken_executable: bool,
}

/// MITRE ATT&CK timeline event for behavior tracking
#[derive(Debug, Clone)]
pub struct MitreTimelineEvent {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub description: String,
    pub timestamp: SystemTime,
    pub severity: MitreSeverity,
}

/// Severity level for MITRE ATT&CK events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitreSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detailed information about a DLL load operation
#[derive(Debug, Clone)]
pub struct DllLoadInfo {
    pub dll_path: String,
    pub dll_name: String,
    pub load_time: SystemTime,
    pub is_api_based: bool, // true if loaded via API, false if direct
    pub normalized_path: String,
}

impl ProcessBehaviorState {
    pub fn new(pid: u32, exe_path: PathBuf, app_name: String) -> Self {
        let mut state = ProcessBehaviorState::default();
        state.pid = pid;
        state.exe_path = exe_path;
        state.app_name = app_name;
        state.signature_checked_path = PathBuf::new();
        state.signature_status = "verification_failed".to_string();
        state.signature_status_text = String::new();
        state.signature_raw_hresult = None;
        state.signature_verification_failed = true;
        state.signature_no_signature = false;
        state.signature_status_issues = false;
        state.signature_invalid = false;
        state.signer_name = None;
        state.parent_name = "unknown".to_string();
        state.parent_path = PathBuf::new();
        state.command_line = String::new();
        state.self_terminated_processes = HashSet::new();
        state.terminated_processes = HashSet::new();
        state.recent_written_payloads = HashMap::new();
        state.detected_apis = HashSet::new();
        state.satisfied_named_conditions = HashSet::new();
        state.condition_match_counts = HashMap::new();
        state.condition_match_values = HashMap::new();
        state.condition_first_seen = HashMap::new();
        state.condition_last_seen = HashMap::new();
        state.irp_operations = Vec::new();
        state.irp_stats = IrpStatistics::default();
        state.all_apis_called = HashSet::new();
        state.observed_hypervisor_event_labels = HashSet::new();
        state.recent_kernel_api_events = VecDeque::with_capacity(128);
        state.self_defense_events = VecDeque::with_capacity(128);
        state.self_defense_event_count = 0;
        state.self_defense_category_counts = HashMap::new();
        state.self_defense_attack_counts = HashMap::new();
        state.hook_error_count = 0;
        state.hook_error_status_counts = HashMap::new();
        state.hook_error_api_counts = HashMap::new();
        state.recent_hook_errors = VecDeque::with_capacity(128);

        // Initialize normalized hypervisor event counters
        state.hypervisor_event_count = 0;
        state.hypervisor_events_total = 0;
        state.created_unknown_ext_stems = HashSet::new();
        state.written_unknown_ext_stems = HashSet::new();
        state.script_file = String::new();
        state.script_file_path = String::new();
        #[cfg(all(target_os = "windows", feature = "firewall"))]
        {
            state.net_packets = VecDeque::with_capacity(500);
            state.http_body_entries = Vec::new();
        }
        #[cfg(all(target_os = "windows", feature = "sanctum"))]
        {
            state.sanctum_stats =
                crate::realtime_learning::api_tracker::SanctumOperationStats::default();
        }
        state.rootkit_implicated = false;
        state.rootkit_findings = Vec::new();

        // Initialize DLL load tracking
        state.dll_load_count = 0;
        state.dll_api_load_count = 0;
        state.dll_direct_load_count = 0;
        state.loaded_dlls_full_path = HashSet::new();
        state.loaded_dlls_name_only = HashSet::new();
        state.dll_load_details = Vec::new();

        // Initialize ACG detection
        state.is_acg_enabled = false;

        // Initialize static scanning fields
        state.static_ioc_matches = Vec::new();
        state.static_hash_malicious = false;
        state.static_file_hash = None;
        state.static_scan_timestamp = None;
        state.static_files_scanned = 0;
        state.static_scan_state = StaticScanState::NotScanned;

        // Initialize DetectItEasy fields
        state.detectiteasy_result = None;
        state.is_packed = false;
        state.is_protected = false;
        state.packer_name = None;
        state.protector_name = None;
        state.is_vmprotect = false;
        state.is_themida = false;
        state.is_dotnet = false;
        state.is_pyinstaller = false;
        state.is_upx = false;
        state.static_file_type = None;

        // Initialize MITRE ATT&CK fields (only with behavior_engine feature)
        {
            state.mitre_techniques = HashSet::new();
            state.mitre_timeline_events = Vec::new();
            state.mitre_threat_score = 0.0;
        }

        state
    }

    fn record_hook_error(&mut self, record: HookErrorRecord) {
        self.hook_error_count = self.hook_error_count.saturating_add(1);
        *self
            .hook_error_status_counts
            .entry(record.operation_status)
            .or_insert(0) += 1;

        if !record.api_name.trim().is_empty() {
            *self
                .hook_error_api_counts
                .entry(record.api_name.clone())
                .or_insert(0) += 1;

            if let Some(alias) = api_function_alias(&record.api_name) {
                *self.hook_error_api_counts.entry(alias).or_insert(0) += 1;
            }
        }

        let status_alias = format!("status:{}", hook_status_name(record.operation_status));
        *self.hook_error_api_counts.entry(status_alias).or_insert(0) += 1;

        if is_antitamper_status(record.operation_status) {
            *self
                .hook_error_api_counts
                .entry("status:ANTI_TAMPER".to_string())
                .or_insert(0) += 1;
        }

        if self.recent_hook_errors.len() >= 128 {
            self.recent_hook_errors.pop_front();
        }
        self.recent_hook_errors.push_back(record);
    }

    /// Record IRP operation with full context and track normalized hypervisor events
    pub fn record_irp_operation(&mut self, msg: &IOMessage, irp_op: u32) {
        let hyper_event = msg.resolved_hypervisor_event();
        let normalized_kernel_api = hyper_event
            .as_ref()
            .map(|event| normalize_hypervisor_label(&event.event_name))
            .unwrap_or_else(|| normalize_hypervisor_label(&msg.kernel_event_info.object_name));
        let raw_event_type = hyper_event
            .as_ref()
            .map(|event| event.raw_event_type)
            .unwrap_or_else(|| effective_hypervisor_raw_event_type(msg));
        let event_name = hyper_event
            .as_ref()
            .map(|event| event.event_name.clone())
            .unwrap_or_else(|| resolved_hypervisor_event_name(msg));
        let rec = IrpOperationRecord {
            timestamp: SystemTime::now(),
            irp_type: irp_op,
            file_path: msg.filepathstr.to_lowercase(),
            file_change: msg.file_change,
            extension: msg.extension.to_lowercase(),
            entropy: msg.entropy,
            bytes_transferred: if let Some(event) = hyper_event.as_ref() {
                if event.memory_size != 0 {
                    event.memory_size
                } else {
                    msg.mem_sized_used
                }
            } else if msg.kernel_event_info.memory_size != 0 {
                msg.kernel_event_info.memory_size as u64
            } else {
                msg.mem_sized_used
            },
            target_pid: if let Some(event) = hyper_event.as_ref() {
                event.target_process_id
            } else if msg.kernel_event_info.target_process_id != 0 {
                msg.kernel_event_info.target_process_id
            } else {
                msg.pid
            },
            function_name: if normalized_kernel_api.is_empty() {
                event_name.clone()
            } else {
                normalized_kernel_api.clone()
            },
            pipe_name: if irp_op == 0x000F_u32 {
                // OpenEDR native LBVS path: NamedPipeCreate event
                // Pipe name comes in filepathstr (FilePath LBVS field)
                msg.filepathstr.trim_matches('\0').to_string()
            } else if matches!(irp_op, 28u32 | 29u32) {
                // Legacy Communication.cpp sub-type path (NamedPipeCreate/Write)
                // Pipe name comes in kernel_event_info.object_name
                msg.kernel_event_info
                    .object_name
                    .trim_matches('\0')
                    .to_string()
            } else {
                String::new()
            },
            pipe_payload: if irp_op == 29u32 {
                msg.kernel_event_info.bin_payload.clone()
            } else {
                Vec::new()
            },
            raw_arguments: if let Some(event) = hyper_event.as_ref() {
                [
                    event.raw_argument1,
                    event.raw_argument2,
                    event.raw_argument3,
                    event.raw_argument4,
                ]
            } else {
                [
                    msg.kernel_event_info.raw_argument1,
                    msg.kernel_event_info.raw_argument2,
                    msg.kernel_event_info.raw_argument3,
                    msg.kernel_event_info.raw_argument4,
                ]
            },
        };

        let irp_kind = hyper_event
            .as_ref()
            .map(|event| event.irp_op.clone())
            .unwrap_or_else(|| IrpMajorOp::from_sysmonevent(irp_op));
        let is_api_event = is_kernel_api_irp(&irp_kind);
        let real_api = is_real_api_observation(&event_name);
        let operation_status = hyper_event
            .as_ref()
            .map(|event| event.operation_status)
            .unwrap_or(msg.kernel_event_info.operation_status);

        if is_api_event && is_hook_error_status(operation_status) {
            self.record_hook_error(HookErrorRecord {
                timestamp: SystemTime::now(),
                api_name: event_name.clone(),
                raw_event_type,
                operation_status,
                source_pid: hyper_event
                    .as_ref()
                    .map(|event| event.source_process_id)
                    .unwrap_or(msg.kernel_event_info.source_process_id),
                target_pid: hyper_event
                    .as_ref()
                    .map(|event| event.target_process_id)
                    .unwrap_or_else(|| {
                        if msg.kernel_event_info.target_process_id != 0 {
                            msg.kernel_event_info.target_process_id
                        } else {
                            msg.pid
                        }
                    }),
                thread_id: hyper_event
                    .as_ref()
                    .map(|event| event.thread_id as u64)
                    .unwrap_or(msg.kernel_event_info.thread_id as u64),
                context: hyper_event
                    .as_ref()
                    .map(|event| event.context)
                    .unwrap_or(msg.kernel_event_info.context),
                raw_argument1: hyper_event
                    .as_ref()
                    .map(|event| event.raw_argument1)
                    .unwrap_or(msg.kernel_event_info.raw_argument1),
                raw_argument2: hyper_event
                    .as_ref()
                    .map(|event| event.raw_argument2)
                    .unwrap_or(msg.kernel_event_info.raw_argument2),
                raw_argument3: hyper_event
                    .as_ref()
                    .map(|event| event.raw_argument3)
                    .unwrap_or(msg.kernel_event_info.raw_argument3),
                raw_argument4: hyper_event
                    .as_ref()
                    .map(|event| event.raw_argument4)
                    .unwrap_or(msg.kernel_event_info.raw_argument4),
            });
        }

        let actionable_hypervisor_event = is_actionable_hypervisor_event(
            &irp_kind,
            &event_name,
            raw_event_type,
            operation_status,
            msg.kernel_event_info.is_acg_enabled,
        );

        if !is_api_event || actionable_hypervisor_event {
            self.irp_stats.record_operation(&rec);
            if actionable_hypervisor_event {
                self.irp_stats.enrich_latest_hypervisor_event_operation(
                    msg,
                    &event_name,
                    raw_event_type,
                );
            }
        }

        if is_api_event {
            let source_pid = hyper_event
                .as_ref()
                .map(|event| event.source_process_id)
                .unwrap_or(msg.kernel_event_info.source_process_id);
            let target_pid = hyper_event
                .as_ref()
                .map(|event| event.target_process_id)
                .unwrap_or_else(|| {
                    if msg.kernel_event_info.target_process_id != 0 {
                        msg.kernel_event_info.target_process_id
                    } else {
                        msg.pid
                    }
                });
            let source_process = format_process_descriptor_with_fallback(source_pid, None);
            let target_process =
                format_process_descriptor_with_fallback(target_pid, Some(self.exe_path.as_path()));
            let raw_argument1 = hyper_event
                .as_ref()
                .map(|event| event.raw_argument1)
                .unwrap_or(msg.kernel_event_info.raw_argument1);
            let raw_argument2 = hyper_event
                .as_ref()
                .map(|event| event.raw_argument2)
                .unwrap_or(msg.kernel_event_info.raw_argument2);
            let raw_argument3 = hyper_event
                .as_ref()
                .map(|event| event.raw_argument3)
                .unwrap_or(msg.kernel_event_info.raw_argument3);
            let raw_argument4 = hyper_event
                .as_ref()
                .map(|event| event.raw_argument4)
                .unwrap_or(msg.kernel_event_info.raw_argument4);
            let core_id = hyper_event
                .as_ref()
                .map(|event| event.core_id)
                .unwrap_or(msg.kernel_event_info.core_id);
            let thread_id = hyper_event
                .as_ref()
                .map(|event| event.thread_id)
                .unwrap_or(msg.kernel_event_info.thread_id);
            let context = hyper_event
                .as_ref()
                .map(|event| event.context)
                .unwrap_or(msg.kernel_event_info.context);
            let event_family = if is_real_hypervisor_irp(&irp_kind, raw_event_type) {
                "hypervisor"
            } else if is_kernel_process_protection_irp(&irp_kind) {
                "kernel_api"
            } else if matches!(irp_kind, IrpMajorOp::IrpUserModeHookEvent) {
                "api_hook"
            } else {
                "kernel_event"
            };

            let mut event_summary = format!(
                "{}:{} raw=0x{:X} status=0x{:08X}({})",
                event_family,
                event_name,
                raw_event_type,
                operation_status as u32,
                hook_status_name(operation_status)
            );
            if source_pid != 0 || target_pid != 0 {
                event_summary.push_str(&format!(" src={} tgt={}", source_pid, target_pid));
            }
            if thread_id != 0 {
                event_summary.push_str(&format!(" tid={}", thread_id));
            }
            if context != 0 {
                event_summary.push_str(&format!(" ctx=0x{:X}", context));
            }
            if self.recent_kernel_api_events.len() >= 128 {
                self.recent_kernel_api_events.pop_front();
            }
            self.recent_kernel_api_events.push_back(event_summary);

            if actionable_hypervisor_event {
                self.hypervisor_event_count += 1;
                if let Some(event_label) =
                    canonical_hypervisor_event_label(&irp_kind, raw_event_type, &event_name)
                {
                    self.observed_hypervisor_event_labels.insert(event_label);
                }
            }

            if real_api {
                if actionable_hypervisor_event {
                    self.detected_apis.insert(event_name.clone());
                    self.all_apis_called.insert(event_name.clone());
                    if let Some(alias) = api_function_alias(&event_name) {
                        self.detected_apis.insert(alias.clone());
                        self.all_apis_called.insert(alias.clone());
                    }
                }
                Logging::info(&format!(
                    "[API HOOKING EVENT{}] opcode={} raw_event_type={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} api=\"{}\" count={}",
                    if actionable_hypervisor_event {
                        ""
                    } else {
                        " IGNORED"
                    },
                    irp_op,
                    raw_event_type,
                    core_id,
                    thread_id,
                    context,
                    source_process,
                    target_process,
                    raw_argument1,
                    raw_argument2,
                    raw_argument3,
                    raw_argument4,
                    event_name,
                    self.hypervisor_event_count
                ));
            } else {
                let event_label =
                    canonical_hypervisor_event_label(&irp_kind, raw_event_type, &event_name)
                        .unwrap_or_else(|| event_name.clone());
                let event_family = if is_real_hypervisor_irp(&irp_kind, raw_event_type) {
                    "HYPERVISOR EVENT"
                } else if is_kernel_process_protection_irp(&irp_kind) {
                    "KERNEL API EVENT"
                } else if matches!(irp_kind, IrpMajorOp::IrpUserModeHookEvent) {
                    "USERMODE HOOK EVENT"
                } else {
                    "KERNEL EVENT"
                };
                Logging::info(&format!(
                    "[{}{}] opcode={} raw_event_type={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} event=\"{}\" count={}",
                    event_family,
                    if actionable_hypervisor_event {
                        ""
                    } else {
                        " IGNORED"
                    },
                    irp_op,
                    raw_event_type,
                    core_id,
                    thread_id,
                    context,
                    source_process,
                    target_process,
                    raw_argument1,
                    raw_argument2,
                    raw_argument3,
                    raw_argument4,
                    event_label,
                    self.hypervisor_event_count
                ));
            }
        }

        // Increment total hypervisor events counter and emit activity signal
        if actionable_hypervisor_event {
            self.hypervisor_events_total += 1;

            // Check for hypervisor event activity after each normalized event
            if self.irp_stats.has_injection_indicators() {
                Logging::warning(&format!(
                    "[API HOOKING DETECTED] PID {} - Total fallback events: {}",
                    msg.pid,
                    self.irp_stats.get_injection_api_count()
                ));
            }
        }

        // NEW: Rootkit Event Tracking
        match irp_kind {
            IrpMajorOp::IrpRootkitSsdtHook
            | IrpMajorOp::IrpRootkitHiddenProcess
            | IrpMajorOp::IrpRootkitHiddenDriver
            | IrpMajorOp::IrpRootkitKernelHook
            | IrpMajorOp::IrpRootkitTerminateProcess
            | IrpMajorOp::IrpRootkitFileMove
            | IrpMajorOp::IrpRootkitGeneric => {
                let kind = RootkitFindingKind::from_irp_op(irp_kind);
                let owner_pid = msg.kernel_event_info.source_process_id;
                let description = msg
                    .kernel_event_info
                    .object_name
                    .trim_matches('\0')
                    .trim()
                    .to_string();
                let attaches_to_state = (owner_pid != 0
                    && self.pid != 0
                    && (self.pid == owner_pid || self.pid == msg.pid))
                    || (owner_pid == 0 && self.pid == 0);

                if attaches_to_state {
                    let finding = RootkitFinding {
                        kind: kind.clone(),
                        description: description.clone(),
                        address: msg.kernel_event_info.memory_address,
                        pid: owner_pid,
                        extra: msg.kernel_event_info.raw_argument1,
                        timestamp_ms: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                    };
                    self.rootkit_findings.push(finding);
                    if matches!(kind, RootkitFindingKind::HiddenProcess) {
                        self.rootkit_implicated = true;
                        let name_is_stale = self.app_name.is_empty()
                            || self.app_name.starts_with("PROC_")
                            || self.app_name == "UNKNOWN";
                        if name_is_stale && !description.is_empty() {
                            self.app_name = description.to_lowercase();
                        }
                    }
                } else {
                    Logging::warning(&format!(
                        "[ROOTKIT DETECTED] Unattributed {:?} finding not attached to process state pid={} src_pid={} msg_pid={}",
                        kind, self.pid, owner_pid, msg.pid
                    ));
                }

                Logging::warning(&format!(
                    "[ROOTKIT DETECTED] PID {} - Type: {:?} - {}",
                    msg.pid, kind, description
                ));
            }
            _ => {}
        }

        // DLL Load Detection - Track both API-based and direct DLL loading
        if msg.kernel_event_info.is_dll_load {
            self.dll_load_count = self.dll_load_count.saturating_add(1);

            if msg.kernel_event_info.is_api_based_load {
                self.dll_api_load_count = self.dll_api_load_count.saturating_add(1);
            } else {
                self.dll_direct_load_count = self.dll_direct_load_count.saturating_add(1);
            }

            let dll_path_raw = msg.kernel_event_info.loaded_dll_path.trim();
            if !dll_path_raw.is_empty() {
                let normalized_path = dll_path_raw.to_lowercase().replace("\\", "/");
                let dll_name = normalized_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&normalized_path)
                    .to_string();

                // Store both full path and name-only for regex matching
                self.loaded_dlls_full_path.insert(normalized_path.clone());
                self.loaded_dlls_name_only.insert(dll_name.clone());

                // Create detailed DLL load info
                let dll_info = DllLoadInfo {
                    dll_path: dll_path_raw.to_string(),
                    dll_name: dll_name.clone(),
                    load_time: SystemTime::now(),
                    is_api_based: msg.kernel_event_info.is_api_based_load,
                    normalized_path: normalized_path.clone(),
                };
                self.dll_load_details.push(dll_info);

                let load_type = if msg.kernel_event_info.is_api_based_load {
                    "API"
                } else {
                    "DIRECT"
                };

                Logging::info(&format!(
                    "[DLL LOAD] PID {} | Type: {} | DLL: {} | Name: {} | Total: {} (API: {}, Direct: {})",
                    msg.pid,
                    load_type,
                    dll_path_raw,
                    dll_name,
                    self.dll_load_count,
                    self.dll_api_load_count,
                    self.dll_direct_load_count
                ));
            }
        }

        // ACG Detection - Update process state
        if msg.kernel_event_info.is_acg_enabled && !self.is_acg_enabled {
            self.is_acg_enabled = true;
            Logging::info(&format!(
                "[ACG ENABLED] PID {} - Process has Arbitrary Code Guard (ACG) enabled: {}",
                msg.pid, self.app_name
            ));
        }

        // Use incremental drain to prevent blocking: remove 10% when hitting 10k
        if self.irp_operations.len() >= 10000 {
            let remove_count = (self.irp_operations.len() / 10).max(500);
            let _ = self.irp_operations.drain(0..remove_count);
        }

        self.irp_operations.push(rec);
    }

    /// Record a static IOC match from hash-based file scanning
    pub fn record_static_ioc_match(&mut self, hash: String, file_path: PathBuf) {
        let match_record = StaticIocMatch {
            hash: hash.clone(),
            file_path: file_path.clone(),
            match_timestamp: SystemTime::now(),
        };
        self.static_ioc_matches.push(match_record);
        self.static_scan_state = StaticScanState::Malicious;
        self.static_hash_malicious = true;

        Logging::warning(&format!(
            "[STATIC SCAN] IOC match detected - PID: {} | Hash: {} | File: {}",
            self.pid,
            hash,
            file_path.display()
        ));
    }

    /// Update static scan state for this process
    pub fn update_static_scan_state(&mut self, state: StaticScanState, file_hash: Option<String>) {
        self.static_scan_state = state;
        self.static_scan_timestamp = Some(SystemTime::now());
        if let Some(hash) = file_hash {
            self.static_file_hash = Some(hash);
        }
    }

    /// Increment the count of files scanned by this process
    pub fn increment_static_files_scanned(&mut self) {
        self.static_files_scanned = self.static_files_scanned.saturating_add(1);
    }

    /// Check if this process has been flagged as malicious by static scanning
    pub fn is_static_malicious(&self) -> bool {
        self.static_hash_malicious || self.static_scan_state == StaticScanState::Malicious
    }

    /// Get all static IOC matches for this process
    pub fn get_static_ioc_matches(&self) -> &[StaticIocMatch] {
        &self.static_ioc_matches
    }

    /// Record DetectItEasy static analysis results from Owlyshield
    pub fn record_detectiteasy_result(&mut self, die_result: DetectItEasyResult) {
        self.is_packed = die_result.is_packed;
        self.is_protected = die_result.is_protected;
        self.packer_name = die_result.packer_name.clone();
        self.protector_name = die_result.protector_name.clone();
        self.is_vmprotect = die_result.is_vmprotect;
        self.is_themida = die_result.is_themida;
        self.is_dotnet = die_result.is_dotnet;
        self.is_pyinstaller = die_result.is_pyinstaller;
        self.is_upx = die_result.is_upx;
        self.static_file_type = die_result.file_type.clone();
        self.detectiteasy_result = Some(die_result.clone());

        Logging::info(&format!(
            "[DetectItEasy] PID: {} | Type: {:?} | Packed: {} | Protected: {} | Packer: {:?} | Protector: {:?}",
            self.pid,
            die_result.file_type,
            die_result.is_packed,
            die_result.is_protected,
            die_result.packer_name,
            die_result.protector_name
        ));
    }

    /// Check if process executable is packed
    pub fn is_packed_executable(&self) -> bool {
        self.is_packed
    }

    /// Check if process executable is protected
    pub fn is_protected_executable(&self) -> bool {
        self.is_protected
    }

    /// Get DetectItEasy result
    pub fn get_detectiteasy_result(&self) -> Option<&DetectItEasyResult> {
        self.detectiteasy_result.as_ref()
    }

    /// Record a MITRE ATT&CK technique observation
    pub fn record_mitre_technique(
        &mut self,
        technique_id: String,
        technique_name: String,
        tactic: String,
        description: String,
        severity: MitreSeverity,
    ) {
        self.mitre_techniques.insert(technique_id.clone());

        let event = MitreTimelineEvent {
            technique_id: technique_id.clone(),
            technique_name: technique_name.clone(),
            tactic: tactic.clone(),
            description,
            timestamp: SystemTime::now(),
            severity,
        };

        self.mitre_timeline_events.push(event);

        // Update threat score based on severity
        let severity_score = match severity {
            MitreSeverity::Low => 1.0,
            MitreSeverity::Medium => 3.0,
            MitreSeverity::High => 7.0,
            MitreSeverity::Critical => 10.0,
        };
        self.mitre_threat_score += severity_score;

        Logging::info(&format!(
            "[MITRE ATT&CK] PID: {} | Technique: {} ({}) | Tactic: {} | Severity: {:?} | Score: {:.1}",
            self.pid, technique_id, technique_name, tactic, severity, self.mitre_threat_score
        ));
    }

    /// Get all MITRE ATT&CK techniques observed for this process
    pub fn get_mitre_techniques(&self) -> &HashSet<String> {
        &self.mitre_techniques
    }

    /// Get MITRE ATT&CK timeline events
    pub fn get_mitre_timeline(&self) -> &[MitreTimelineEvent] {
        &self.mitre_timeline_events
    }

    /// Get MITRE ATT&CK threat score
    pub fn get_mitre_threat_score(&self) -> f64 {
        self.mitre_threat_score
    }
}

// =============================================================================
// BEHAVIOR ENGINE
// =============================================================================

#[derive(Clone)]
pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    regex_cache: Arc<std::sync::RwLock<HashMap<String, Regex>>>,
    pub process_terminated: HashSet<String>,
    default_extension_whitelist: HashSet<String>,
    /// PIDs for which OpenEDR observed network activity from its local telemetry logs.
    pub openedr_net_pids: OpenEdrNetPids,
    /// Per-PID list of (dst_ip, dst_port) records learned from OpenEDR network events.
    pub openedr_net_details: OpenEdrNetDetails,
    /// Per-PID OpenEDR telemetry counters and aliases synced into rule state.
    pub openedr_stats: OpenEdrTelemetryStatsMap,
    /// Per-PID self-defense telemetry emitted by OpenEDR/Owlyshield sensors.
    pub self_defense_telemetry: SelfDefenseTelemetryMap,
    /// Cross-thread IRP record queue: pipe/telemetry threads push (pid, record) here.
    /// The main Worker thread drains this queue in `scan_processes` and applies records
    /// to `process_states` via `ProcessBehaviorState::record_irp_operation`.
    /// `Arc<Mutex<_>>` so the cloned `BehaviorEngine` in the pipe thread shares the
    /// same underlying queue with the main-thread `BehaviorEngine`.
    pub pending_irp_records: Arc<Mutex<std::collections::VecDeque<(u32, IrpOperationRecord)>>>,
    /// PIDs for which the firewall observed real outbound network I/O (NET_EVENT).
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub firewall_net_pids: FirewallNetPids,
    /// Per-PID list of (dst_ip, dst_port) connection records from NET_EVENT messages.
    /// Used by named-condition rules to match specific IPs or ports.
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub firewall_net_details: FirewallNetDetails,
    /// Exe paths for which the firewall confirmed malicious traffic (BLOCK_EXE).
    /// Value holds full detection details for report generation.
    /// scan_all_processes marks matching processes as malicious and acts on them.
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub firewall_blocked_exes: FirewallBlockedExes,
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_pipe_started: FirewallPipeStarted,
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_hips_pending_prompts: FirewallHipsPendingPrompts,
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_hips_decisions: FirewallHipsDecisions,
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_hips_allow_once: FirewallHipsAllowOnce,
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_hips_allow_always: FirewallHipsAllowAlways,
    /// Per-PID HTTP body pairs captured by the MITM proxy (received via HTTP_BODY pipe messages).
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_http_body_map: FirewallHttpBodyMap,
    /// Per-PID rolling history of full network packets from the firewall.
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    firewall_full_packets: FirewallFullPackets,
    /// Per-PID stats from Sanctum EDR telemetry.
    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub firewall_sanctum_stats: FirewallSanctumStats,
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub generate_report_flag: FirewallGenerateReport,
    /// File verdicts received from the firewall (keyed by file path lowercase).
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub firewall_file_verdicts: FirewallFileVerdicts,
    pub rootkit_findings: Vec<RootkitFinding>,
    pub amsi_analyzer: crate::behavioral::amsi::AmsiAnalyzer,
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "windows", feature = "sanctum"))]
fn sanctum_value_is_truthy(value: &serde_json::Value) -> bool {
    value.as_bool().unwrap_or(false)
        || value.as_u64().is_some_and(|num| num == 1)
        || value
            .as_str()
            .map(|text| {
                let text = text.trim();
                text == "1" || text.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false)
}

#[derive(Clone, Copy)]
enum CapemonBsonFormat {
    Log,
    Storage,
}

impl CapemonBsonFormat {
    fn format_array(self, elements: &[String]) -> String {
        match self {
            CapemonBsonFormat::Log => format!("[{}]", elements.join(", ")),
            CapemonBsonFormat::Storage => elements.join(";"),
        }
    }
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self::new_with_extension_source_mode(None)
    }

    pub fn new_with_extension_source_mode(extension_source_mode: Option<&str>) -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
            process_terminated: HashSet::new(),
            default_extension_whitelist: build_default_extension_whitelist(extension_source_mode),
            openedr_net_pids: shared_openedr_net_pids(),
            openedr_net_details: shared_openedr_net_details(),
            openedr_stats: shared_openedr_stats(),
            self_defense_telemetry: shared_self_defense_telemetry(),
            pending_irp_records: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_net_pids: shared_firewall_net_pids(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_net_details: shared_firewall_net_details(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_blocked_exes: shared_firewall_blocked_exes(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_pipe_started: shared_firewall_pipe_started(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_hips_pending_prompts: shared_firewall_hips_pending_prompts(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_hips_decisions: shared_firewall_hips_decisions(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_hips_allow_once: shared_firewall_hips_allow_once(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_hips_allow_always: shared_firewall_hips_allow_always(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_http_body_map: shared_firewall_http_body_map(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_full_packets: shared_firewall_full_packets(),
            #[cfg(all(target_os = "windows", feature = "sanctum"))]
            firewall_sanctum_stats: shared_firewall_sanctum_stats(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            generate_report_flag: shared_firewall_generate_report(),
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            firewall_file_verdicts: shared_firewall_file_verdicts(),
            rootkit_findings: Vec::new(),
            amsi_analyzer: crate::behavioral::amsi::AmsiAnalyzer::new(),
        }
    }

    pub fn find_gid_by_pid(&self, pid: u32) -> Option<u64> {
        if pid == 0 {
            return None;
        }
        for (gid, state) in &self.process_states {
            if state.pid == pid {
                return Some(*gid);
            }
        }
        None
    }

    /// Record static scan results from Sanctum FileScanner integration
    /// This integrates hash-based IOC detection results into the behavior engine
    pub fn record_static_scan_result(
        &mut self,
        gid: u64,
        hash: String,
        file_path: PathBuf,
        is_malicious: bool,
    ) {
        if let Some(state) = self.process_states.get_mut(&gid) {
            if is_malicious {
                state.record_static_ioc_match(hash.clone(), file_path.clone());
                Logging::warning(&format!(
                    "[BehaviorEngine] Static scan detected malicious file - GID: {} | PID: {} | Hash: {} | Path: {}",
                    gid,
                    state.pid,
                    hash,
                    file_path.display()
                ));
            } else {
                state.update_static_scan_state(StaticScanState::Clean, Some(hash));
            }
            state.increment_static_files_scanned();
        }
    }

    /// Check if any process has static scan malicious findings
    pub fn has_static_malicious_processes(&self) -> bool {
        self.process_states
            .values()
            .any(|state| state.is_static_malicious())
    }

    /// Get all processes with static IOC matches
    pub fn get_static_malicious_processes(&self) -> Vec<(u64, &ProcessBehaviorState)> {
        self.process_states
            .iter()
            .filter(|(_, state)| state.is_static_malicious())
            .map(|(gid, state)| (*gid, state))
            .collect()
    }

    /// Spawn the \\.\pipe\HydraNetEvent named pipe server thread.
    /// Firewall sends activity telemetry such as NET_EVENT and HTTP body data.
    /// Legacy BLOCK_EXE messages are still accepted defensively, but firewall
    /// network blocks should stay firewall activity and not become process kills.
    /// Call once after constructing BehaviorEngine, before the scan loop starts.
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    pub fn start_firewall_pipe(&self) {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{
            CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        };
        use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
            PIPE_UNLIMITED_INSTANCES,
        };
        use windows::core::PCWSTR;

        if self.firewall_pipe_started.swap(true, Ordering::SeqCst) {
            Logging::info("[HydraNetPipe] Firewall pipe server already active");
            return;
        }

        let net_pids = Arc::clone(&self.firewall_net_pids);
        let net_details = Arc::clone(&self.firewall_net_details);
        let blocked_exes = Arc::clone(&self.firewall_blocked_exes);
        let hips_decisions = Arc::clone(&self.firewall_hips_decisions);
        let http_body_map = Arc::clone(&self.firewall_http_body_map);
        let full_packets: Arc<RwLock<HashMap<u32, VecDeque<PacketInfo>>>> =
            Arc::clone(&self.firewall_full_packets);
        let generate_report_flag = Arc::clone(&self.generate_report_flag);
        let file_verdicts = Arc::clone(&self.firewall_file_verdicts);
        let regex_cache = Arc::clone(&self.regex_cache);
        let rules_clone = self.rules.clone();

        std::thread::Builder::new()
            .name("hydra_net_event_pipe".to_string())
            .spawn(move || {
                let pipe_name_str = r"\\.\pipe\HydraNetEvent";
                let wide: Vec<u16> = OsStr::new(pipe_name_str)
                    .encode_wide()
                    .chain(std::iter::once(0u16))
                    .collect();

                loop {
                    let handle: HANDLE = unsafe {
                        CreateNamedPipeW(
                            PCWSTR(wide.as_ptr()),
                            PIPE_ACCESS_INBOUND,
                            NAMED_PIPE_MODE(0), // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                            PIPE_UNLIMITED_INSTANCES,
                            0,
                            4096,
                            0,
                            None,
                        )
                    };

                    if handle == INVALID_HANDLE_VALUE {
                        Logging::error("[HydraNetPipe] CreateNamedPipeW failed; retrying");
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }

                    let connected = unsafe { ConnectNamedPipe(handle, None) }.as_bool()
                        || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

                    if !connected {
                        Logging::warning("[HydraNetPipe] ConnectNamedPipe failed; recreating pipe");
                        unsafe {
                            let _ = DisconnectNamedPipe(handle);
                            let _ = CloseHandle(handle);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        continue;
                    }

                    // Validation: Only allow HydraDragon Firewall from the fixed install path.
                    const HYDRADRAGON_FIREWALL_EXE: &str = r"C:\Program Files\HydraDragonAntivirus\hydradragon\HydraDragonFirewall\HydraDragonFirewall.exe";
                    if !unsafe { validate_pipe_client(handle, Some(HYDRADRAGON_FIREWALL_EXE), false) } {
                        Logging::error("[HydraNetPipe] Rejected unauthorized client connection");
                        unsafe {
                            use windows::Win32::System::Pipes::DisconnectNamedPipe;
                            let _ = DisconnectNamedPipe(handle);
                            let _ = CloseHandle(handle);
                        }
                        continue;
                    }

                    Logging::info("[HydraNetPipe] Client connected to HydraNetEvent pipe");

                    let mut buf = vec![0u8; 4096];
                    let mut leftover = String::new();

                    loop {
                        let mut bytes_read: u32 = 0;
                        let ok = unsafe {
                            ReadFile(
                                handle,
                                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                                buf.len() as u32,
                                Some(&mut bytes_read),
                                None,
                            )
                        };
                        if !ok.as_bool() || bytes_read == 0 {
                            break;
                        }
                        leftover.push_str(&String::from_utf8_lossy(&buf[..bytes_read as usize]));

                        while let Some(pos) = leftover.find('\n') {
                            let line = leftover[..pos].trim().to_string();
                            leftover = leftover[pos + 1..].to_string();

                            if let Some(rest) = line.strip_prefix("NET_EVENT:") {
                                let mut parts = rest.splitn(3, ':');
                                if let Some(pid_str) = parts.next()
                                    && let Ok(pid) = pid_str.parse::<u32>() {
                                        net_pids.write().unwrap().insert(pid);
                                        let dst_ip   = parts.next().unwrap_or("").trim().to_string();
                                        let dst_port = parts.next().unwrap_or("0").trim()
                                            .parse::<u16>().unwrap_or(0);
                                        if !dst_ip.is_empty() {
                                            net_details.write().unwrap()
                                                .entry(pid)
                                                .or_default()
                                                .push((dst_ip, dst_port));
                                        }
                                    }
                            } else if let Some(rest) = line.strip_prefix("BLOCK_EXE:") {
                                // BLOCK_EXE:<exe>|<dst_ip>|<dst_port>|<hostname>|<reason>
                                let mut parts = rest.splitn(5, '|');
                                let exe      = parts.next().unwrap_or("").trim().to_string();
                                let dst_ip   = parts.next().unwrap_or("").trim().to_string();
                                let dst_port = parts.next().unwrap_or("0").trim()
                                    .parse::<u16>().unwrap_or(0);
                                let hostname = parts.next().unwrap_or("").trim().to_string();
                                let reason   = parts.next().unwrap_or("Firewall block").trim().to_string();

                                if !exe.is_empty() {
                                    let detection = FirewallDetection {
                                        dst_ip,
                                        dst_port,
                                        hostname: hostname.clone(),
                                        reason: reason.clone(),
                                        is_private_rule_match: false,
                                        detected_subdomain: None,
                                        detected_domain: None,
                                        used_public_suffix_list: false,
                                        matched_private_rules: Vec::new(),
                                    };
                                    if detection.is_pending_user_decision() {
                                        Logging::info(&format!(
                                            "[FirewallPipe] Pending user decision for {}; not treating as confirmed malicious",
                                            exe
                                        ));
                                        continue;
                                    }
                                    Logging::warning(&format!(
                                        "[FirewallPipe] Confirmed malicious: {} -> {}:{} ({}) - {}",
                                        exe,
                                        detection.dst_ip,
                                        detection.dst_port,
                                        hostname,
                                        reason
                                    ));
                                    blocked_exes.write().unwrap().insert(exe, detection);
                                }
                            } else if let Some(rest) = line.strip_prefix("HIPS_DECISION:") {
                                let mut parts = rest.splitn(2, '|');
                                let request_id = parts.next().unwrap_or("").trim().to_string();
                                let decision_raw = parts.next().unwrap_or("").trim();

                                if !request_id.is_empty() {
                                    if let Some(decision) = FirewallHipsDecision::from_wire(decision_raw) {
                                        hips_decisions.write().unwrap().insert(request_id.clone(), decision);
                                        Logging::info(&format!(
                                            "[HydraNetPipe] Received Owlyshield HIPS decision for request {}: {}",
                                            request_id,
                                            decision_raw
                                        ));
                                    } else {
                                        Logging::warning(&format!(
                                            "[HydraNetPipe] Ignored unknown Owlyshield HIPS decision '{}'",
                                            decision_raw
                                        ));
                                    }
                                }
                            } else if let Some(rest) = line.strip_prefix("KERNEL_BLOCK_PATH:") {
                                let block_path = rest.trim().trim_matches('"').replace('/', "\\");
                                if !block_path.is_empty() && !block_path.eq_ignore_ascii_case("unknown") {
                                    let applied = with_shared_driver(|driver| driver.add_block_path(&block_path));
                                    match applied {
                                        Some(Ok(())) => Logging::warning(&format!(
                                            "[HydraNetPipe] Installed kernel block path: {}",
                                            block_path
                                        )),
                                        Some(Err(ref err)) => Logging::error(&format!(
                                            "[HydraNetPipe] Failed to install kernel block path {}: {}",
                                            block_path,
                                            err
                                        )),
                                        None => Logging::warning(&format!(
                                            "[HydraNetPipe] No shared driver handle available for kernel block path {}",
                                            block_path
                                        )),
                                    }
                                }
                            } else if line == "GENERATE_REPORT" {
                                generate_report_flag.store(true, Ordering::SeqCst);
                                Logging::info("[HydraNetPipe] Received on-demand report request");
                            } else if let Some(json) = line.strip_prefix("FULL_PACKED_DATA:") {
                                // Single JSON-only firewall telemetry envelope.
                                // No pipe-delimited HTTP_BODY and no old FULL_PACKET format:
                                // bodies can contain CR/LF, quotes, pipes and binary-looking text.
                                match serde_json::from_str::<FirewallPackedDataMessage>(json) {
                                    Ok(packed) => {
                                        let mut pkt = packed.packet;
                                        let pid = pkt.process_id;

                                        let req_body = packed
                                            .request_body
                                            .or_else(|| pkt.http_request_body.clone())
                                            .unwrap_or_default();
                                        let resp_body = packed
                                            .response_body
                                            .or_else(|| pkt.http_response_body.clone())
                                            .unwrap_or_default();

                                        if pkt.http_request_body.is_none() && !req_body.is_empty() {
                                            pkt.http_request_body = Some(req_body.clone());
                                        }
                                        if pkt.http_response_body.is_none() && !resp_body.is_empty() {
                                            pkt.http_response_body = Some(resp_body.clone());
                                        }

                                        net_pids.write().unwrap().insert(pid);

                                        if !req_body.is_empty() || !resp_body.is_empty() {
                                            http_body_map.write().unwrap()
                                                .entry(pid)
                                                .or_default()
                                                .push((req_body, resp_body));
                                        }

                                        let mut pkt_map = full_packets.write().unwrap();
                                        let history = pkt_map.entry(pid).or_insert_with(|| VecDeque::with_capacity(500));
                                        if history.len() >= 500 {
                                            history.pop_front();
                                        }
                                        history.push_back(pkt.clone());
                                        drop(pkt_map);

                                        // BEHAVIOR RULE MATCHING
                                        let mut matched_any = false;
                                        {
                                            for rule in rules_clone.iter() {
                                                if rule.matches_packet(&regex_cache, &pkt, &[]) {
                                                    matched_any = true;

                                                    // Private rules don't generate detections (YARA-style behavior)
                                                    // They are evaluated and can be used by other rules, but don't produce alerts
                                                    if rule.is_private {
                                                        continue;
                                                    }

                                                    Logging::alert(&format!(
                                                        "[BEHAVIOR RULE MATCH] PID {} matched network condition in rule '{}': {} -> {}",
                                                        pid, rule.name, pkt.src_ip, pkt.dst_ip
                                                    ));

                                                    if !rule.response.ask_user
                                                        && (rule.response.status_access_denied
                                                            || rule.response.quarantine
                                                            || rule.response.kill_and_remove
                                                            || rule.response.terminate_process)
                                                    {
                                                        let mut blocked = blocked_exes.write().unwrap();

                                                        let reason = if rule.response.change_request_body.is_some() || rule.response.change_response_body.is_some() {
                                                            format!("Rule [{}] matched (Replacement suggested)", rule.name)
                                                        } else {
                                                            format!("Rule [{}] matched", rule.name)
                                                        };

                                                        // Extract domain information from packet hostname
                                                        let (detected_domain, detected_subdomain) = if let Some(ref hostname) = pkt.hostname {
                                                            let parts: Vec<&str> = hostname.split('.').collect();
                                                            if parts.len() >= 2 {
                                                                let domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
                                                                let subdomain = if parts.len() > 2 {
                                                                    Some(hostname.clone())
                                                                } else {
                                                                    None
                                                                };
                                                                (Some(domain), subdomain)
                                                            } else {
                                                                (None, None)
                                                            }
                                                        } else {
                                                            (None, None)
                                                        };

                                                        blocked.insert(pkt.image_path.clone(), FirewallDetection {
                                                            dst_ip: pkt.dst_ip.to_string(),
                                                            dst_port: pkt.dst_port,
                                                            hostname: pkt.hostname.clone().unwrap_or_default(),
                                                            reason,
                                                            is_private_rule_match: rule.is_private,
                                                            detected_subdomain,
                                                            detected_domain,
                                                            used_public_suffix_list: false,
                                                            matched_private_rules: if rule.is_private {
                                                                vec![rule.name.clone()]
                                                            } else {
                                                                Vec::new()
                                                            },
                                                        });
                                                    }

                                                    if let Some(ref hostname) = pkt.hostname {
                                                        let _replaced = rule.apply_replacement(hostname);
                                                    }
                                                }
                                            }
                                        }

                                        if !matched_any {
                                            Logging::info(&format!(
                                                "[FirewallEvent] Full packed data recorded for PID {}: {} -> {} ({})",
                                                pid, pkt.src_ip, pkt.dst_ip, pkt.protocol
                                            ));
                                        }
                                    }
                                    Err(error) => {
                                        let preview: String = json.chars().take(240).collect();
                                        Logging::warning(&format!(
                                            "[FirewallEvent] Failed to parse FULL_PACKED_DATA JSON: {}; len={}; preview={}",
                                            error,
                                            json.len(),
                                            preview
                                        ));
                                    }
                                }
                            } else if let Some(rest) = line.strip_prefix("VERDICT:") {
                                // VERDICT:<file_path>|<sha256>|<verdict_code>|<verdict_label>
                                // OpenEDR FLS: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail.
                                let mut parts = rest.splitn(4, '|');
                                let file_path = parts.next().unwrap_or("").trim().to_string();
                                let sha256 = parts.next().unwrap_or("").trim().to_string();
                                let verdict_code_raw = parts.next().unwrap_or("3").trim();
                                let verdict_label_raw = parts.next().unwrap_or("").trim();
                                let verdict = verdict_code_raw
                                    .parse::<u8>()
                                    .ok()
                                    .and_then(OpenEdrFlsVerdict::from_code)
                                    .or_else(|| OpenEdrFlsVerdict::from_token(verdict_code_raw))
                                    .or_else(|| OpenEdrFlsVerdict::from_token(verdict_label_raw))
                                    .unwrap_or(OpenEdrFlsVerdict::Unknown);
                                let verdict_code = verdict.code();
                                let verdict_label = verdict.display_label().to_string();

                                if !file_path.is_empty() && !sha256.is_empty() {
                                    let verdict_info = FileVerdictInfo {
                                        sha256: sha256.clone(),
                                        file_path: file_path.clone(),
                                        verdict: verdict_code,
                                        verdict_label: verdict_label.clone(),
                                        timestamp: SystemTime::now(),
                                    };

                                    let file_path_key =
                                        normalize_firewall_file_verdict_key(&file_path);
                                    file_verdicts.write().unwrap().insert(file_path_key.clone(), verdict_info);

                                    Logging::info(&format!(
                                        "[OpenEDRVerdict] Received file verdict for {}: {} (code {})",
                                        file_path, verdict_label, verdict_code
                                    ));

                                    // If verdict is Malicious (2), also add to blocked_exes for immediate action.
                                    if verdict.is_malicious() {
                                        let detection = FirewallDetection {
                                            dst_ip: String::new(),
                                            dst_port: 0,
                                            hostname: String::new(),
                                            reason: format!("File Verdict: {} (SHA256: {})", verdict_label, sha256),
                                            is_private_rule_match: false,
                                            detected_subdomain: None,
                                            detected_domain: None,
                                            used_public_suffix_list: false,
                                            matched_private_rules: Vec::new(),
                                        };
                                        blocked_exes.write().unwrap().insert(file_path_key, detection);
                                        Logging::warning(&format!(
                                            "[OpenEDRVerdict] Marked {} as malicious based on OpenEDR verdict",
                                            file_path
                                        ));
                                    }
                                } else {
                                    Logging::warning(&format!(
                                        "[OpenEDRVerdict] Received incomplete VERDICT message: {}",
                                        rest
                                    ));
                                }
                            }
                        }
                    }

                    Logging::info("[HydraNetPipe] Client disconnected; waiting for next firewall connection");
                    unsafe {
                        let _ = DisconnectNamedPipe(handle);
                        let _ = CloseHandle(handle);
                    }
                }

            })
            .expect("failed to spawn hydra_net_event_pipe thread");
    }

    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub(crate) fn sanctum_value<'v>(
        event: &'v serde_json::Value,
        args: &'v serde_json::Value,
        names: &[&str],
    ) -> Option<&'v serde_json::Value> {
        for name in names {
            if let Some(value) = event.get(*name) {
                return Some(value);
            }
            if let Some(value) = args.get(*name) {
                return Some(value);
            }
        }
        None
    }

    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub(crate) fn sanctum_u32_field(
        event: &serde_json::Value,
        args: &serde_json::Value,
        names: &[&str],
    ) -> u32 {
        let Some(value) = Self::sanctum_value(event, args, names) else {
            return 0;
        };

        if let Some(num) = value.as_u64() {
            return num.min(u32::MAX as u64) as u32;
        }

        let Some(text) = value
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        else {
            return 0;
        };

        let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            text.parse::<u64>()
                .or_else(|_| u64::from_str_radix(text, 16))
        };

        parsed
            .map(|num| num.min(u32::MAX as u64) as u32)
            .unwrap_or(0)
    }

    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub(crate) fn sanctum_string_field(
        event: &serde_json::Value,
        args: &serde_json::Value,
        names: &[&str],
    ) -> String {
        Self::sanctum_value(event, args, names)
            .and_then(|value| {
                value
                    .as_str()
                    .map(|text| text.trim().to_string())
                    .or_else(|| value.as_u64().map(|num| num.to_string()))
            })
            .unwrap_or_default()
    }

    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub(crate) fn sanctum_bool_field(
        event: &serde_json::Value,
        args: &serde_json::Value,
        names: &[&str],
    ) -> bool {
        Self::sanctum_value(event, args, names).is_some_and(sanctum_value_is_truthy)
    }

    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub(crate) fn sanctum_event_is_detection(
        event: &serde_json::Value,
        args: &serde_json::Value,
        _source: &str,
        _function: &str,
    ) -> bool {
        if Self::sanctum_value(event, args, &["is_detection"]).is_some_and(sanctum_value_is_truthy)
        {
            return true;
        }

        Self::sanctum_value(event, args, &["event_type"])
            .and_then(|value| value.as_str())
            .is_some_and(|text| text.trim().eq_ignore_ascii_case("DETECTION"))
    }

    /// Ingest a telemetry event from Sanctum EDR.
    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    pub fn ingest_sanctum_event(&mut self, event: &serde_json::Value) {
        let null_args = serde_json::Value::Null;
        let args = event.get("args").unwrap_or(&null_args);

        let pid = Self::sanctum_u32_field(
            event,
            args,
            &[
                "pid",
                "process_id",
                "source_pid",
                "attacker_pid",
                "target_pid",
                "client_pid",
            ],
        );
        let mut source = Self::sanctum_string_field(event, args, &["source", "provider", "sensor"]);
        if source.is_empty() {
            source = "-".to_string();
        }

        let mut function = Self::sanctum_string_field(
            event,
            args,
            &["function", "api", "syscall", "operation", "event", "name"],
        );
        if function.is_empty() {
            function = "-".to_string();
        }

        let is_detection = Self::sanctum_event_is_detection(event, args, &source, &function);

        let gid = self.find_gid_by_pid(pid).unwrap_or(0);

        // Register the PID as network-active if Sanctum observes
        // suspicious cross-process operations (NtOpenProcess etc.)
        // so firewall and behavior rules can correlate.
        #[cfg(all(target_os = "windows", feature = "firewall"))]
        if pid != 0
            && matches!(
                function.as_str(),
                "NtOpenProcess"
                    | "NtWriteVirtualMemory"
                    | "NtAllocateVirtualMemory"
                    | "NtCreateThreadEx"
                    | "NtProtectVirtualMemory"
                    | "NtMapViewOfSection"
                    | "NtQueueApcThread"
                    | "NtSetContextThread"
            )
        {
            self.firewall_net_pids.write().unwrap().insert(pid);
            if gid != 0 {
                if let Some(state) = self.process_states.get_mut(&gid) {
                    state.detected_apis.insert(function.to_string());
                }
            }
            Logging::warning(&format!(
                "[SanctumTelemetry] Suspicious syscall from PID {}: {}",
                pid, function
            ));
        }

        // Handle AMSI and EDR bypass attempts from Sanctum (VEH abuse, ETW-TI, Ghost Hunting, etc.)
        if source == "sanctum_veh"
            || source == "etw_ti"
            || source == "syscall_hook"
            || source == "sanctum_ghost"
        {
            if gid != 0 {
                if let Some(state) = self.process_states.get_mut(&gid) {
                    let (risk, pattern) = match source.as_str() {
                        "sanctum_veh" => (
                            crate::behavioral::amsi::AmsiRiskLevel::Critical,
                            format!("VEH_ABUSE: {}", function),
                        ),
                        "etw_ti" => {
                            let is_suspicious = args["suspicious"].as_bool().unwrap_or(false);
                            if is_suspicious {
                                (
                                    crate::behavioral::amsi::AmsiRiskLevel::High,
                                    format!("ETW_TI_SUSPICIOUS: {}", function),
                                )
                            } else {
                                (
                                    crate::behavioral::amsi::AmsiRiskLevel::Medium,
                                    format!("ETW_TI: {}", function),
                                )
                            }
                        }
                        "syscall_hook" => (
                            crate::behavioral::amsi::AmsiRiskLevel::Medium,
                            format!("SYSCALL_HOOK: {}", function),
                        ),
                        "sanctum_ghost" => (
                            crate::behavioral::amsi::AmsiRiskLevel::Critical,
                            format!("DIRECT_SYSCALL: {}", function),
                        ),
                        _ => (crate::behavioral::amsi::AmsiRiskLevel::None, String::new()),
                    };

                    if risk != crate::behavioral::amsi::AmsiRiskLevel::None {
                        let res = crate::behavioral::amsi::AmsiAnalysisResult {
                            risk_level: risk,
                            detected_patterns: vec![pattern],
                            source: source.to_string(),
                            content_sample: String::new(),
                        };
                        state.amsi_results.push(res);
                    }
                }
            }
        }

        // Update shared Sanctum stats for real-time learning.
        if pid != 0 {
            let mut sanctum_lock = self.firewall_sanctum_stats.write().unwrap();
            let stats = sanctum_lock.entry(pid).or_insert_with(
                crate::realtime_learning::api_tracker::SanctumOperationStats::default,
            );
            stats.syscall_count += 1;
            stats.is_detection |= is_detection;

            // Handle forensic syscall telemetry (Ghost Hunting)
            if source == "sanctum_ghost" {
                let caller_address = args["caller_address"]
                    .as_u64()
                    .or_else(|| event["address"].as_u64())
                    .unwrap_or(0);
                let hex_payload = args["hex"]
                    .as_str()
                    .or_else(|| event["hex"].as_str())
                    .unwrap_or("")
                    .to_string();

                if caller_address != 0 || !hex_payload.is_empty() {
                    stats.ghost_telemetry.push(
                        crate::realtime_learning::api_tracker::SanctumGhostTelemetry {
                            function: function.to_string(),
                            caller_address,
                            hex_payload: hex_payload.clone(),
                            timestamp_ms: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                        },
                    );

                    // Cap telemetry to prevent memory bloat
                    if stats.ghost_telemetry.len() > 100 {
                        stats.ghost_telemetry.remove(0);
                    }
                }
            }

            stats.last_event = Some(format!(
                "{} - {}",
                function,
                serde_json::to_string(args).unwrap_or_default()
            ));

            if let Some(target_pid) = args["target_pid"].as_u64() {
                if target_pid as u32 != pid {
                    stats.cross_process_handle_count += 1;
                }
            } else if args["remote"].as_bool().unwrap_or(false) {
                stats.cross_process_handle_count += 1;
            }

            if matches!(
                function.as_str(),
                "NtWriteVirtualMemory"
                    | "NtAllocateVirtualMemory"
                    | "NtCreateThreadEx"
                    | "NtProtectVirtualMemory"
                    | "NtMapViewOfSection"
                    | "NtQueueApcThread"
                    | "NtSetContextThread"
            ) {
                stats.injection_score += 0.1;
                stats.suspicious_syscall_hits.push(function.to_string());
                if stats.suspicious_syscall_hits.len() > 20 {
                    stats.suspicious_syscall_hits.remove(0);
                }
            }

            if stats.injection_score > 1.0 {
                stats.injection_score = 1.0;
            }

            if gid != 0
                && let Some(state) = self.process_states.get_mut(&gid)
            {
                state.sanctum_stats = stats.clone();
                if matches!(
                    function.as_str(),
                    "NtWriteVirtualMemory"
                        | "NtAllocateVirtualMemory"
                        | "NtCreateThreadEx"
                        | "NtProtectVirtualMemory"
                        | "NtMapViewOfSection"
                        | "NtQueueApcThread"
                        | "NtSetContextThread"
                ) {
                    state.sanctum_suspicious_hits.insert(function.to_string());
                }
            }
        }
    }

    /// Notify the firewall GUI about the OpenEDR FLS verdict for this process.
    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn notify_firewall_openedr_verdict(
        &self,
        pid: u32,
        exe_path: &str,
        verdict: OpenEdrFlsVerdict,
        analysis_type: &str,
    ) {
        use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
            FlushFileBuffers, OPEN_EXISTING, WriteFile,
        };
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        use windows::core::PCWSTR;

        const PIPE: &str = r"\\.\pipe\HydraHipEvent";
        const CONNECT_TIMEOUT_MS: u32 = 250;
        const CONNECT_ATTEMPTS: usize = 2;

        // Convert to UTF-16 for Unicode Windows API
        let mut pipe_name_wide: Vec<u16> = PIPE.encode_utf16().collect();
        pipe_name_wide.push(0); // Null terminator
        let pcwstr = PCWSTR(pipe_name_wide.as_ptr());
        let message = format!(
            "HIPS_VERDICT:{}|{}|{}|{}\n",
            pid,
            Self::sanitize_firewall_hips_field(exe_path),
            verdict.code(),
            Self::sanitize_firewall_hips_field(analysis_type),
        );
        let message_bytes = message.as_bytes();

        let mut last_error = String::new();
        for attempt in 0..CONNECT_ATTEMPTS {
            let wait_ok: BOOL = unsafe { WaitNamedPipeW(pcwstr, CONNECT_TIMEOUT_MS) };
            if !wait_ok.as_bool() {
                last_error = format!("WaitNamedPipeW(GetLastError={:?})", unsafe {
                    GetLastError()
                });
            } else {
                let pipe_handle = match unsafe {
                    CreateFileW(
                        pcwstr,
                        FILE_GENERIC_WRITE.0,
                        FILE_SHARE_NONE,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        HANDLE::default(),
                    )
                } {
                    Ok(handle) if !handle.is_invalid() => handle,
                    Ok(_) => {
                        last_error =
                            "CreateFileW returned an invalid HydraHipEvent handle".to_string();
                        if attempt + 1 < CONNECT_ATTEMPTS {
                            std::thread::sleep(std::time::Duration::from_millis(80));
                        }
                        continue;
                    }
                    Err(err) => {
                        last_error = format!("CreateFileW failed: {:?}", err);
                        if attempt + 1 < CONNECT_ATTEMPTS {
                            std::thread::sleep(std::time::Duration::from_millis(80));
                        }
                        continue;
                    }
                };

                let mut bytes_written: u32 = 0;
                let ok: BOOL = unsafe {
                    WriteFile(
                        pipe_handle,
                        Some(message_bytes),
                        Some(&mut bytes_written as *mut u32),
                        None,
                    )
                };

                unsafe {
                    let _ = FlushFileBuffers(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                }

                if ok.as_bool() && bytes_written as usize == message_bytes.len() {
                    Logging::debug(&format!(
                        "[OpenEDRVerdict] Sent {} verdict for PID {} to firewall: {}",
                        analysis_type,
                        pid,
                        verdict.display_label()
                    ));
                    return;
                }

                last_error = if ok.as_bool() {
                    format!(
                        "WriteFile wrote {} of {} bytes",
                        bytes_written,
                        message_bytes.len()
                    )
                } else {
                    format!("WriteFile(GetLastError={:?})", unsafe { GetLastError() })
                };
            }

            if attempt + 1 < CONNECT_ATTEMPTS {
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        }

        Logging::debug(&format!(
            "[OpenEDRVerdict] Firewall verdict update was not delivered for PID {} after {} attempts: {}",
            pid, CONNECT_ATTEMPTS, last_error
        ));
    }

    #[cfg(not(all(target_os = "windows", feature = "firewall")))]
    fn notify_firewall_openedr_verdict(
        &self,
        _pid: u32,
        _exe_path: &str,
        _verdict: OpenEdrFlsVerdict,
        _analysis_type: &str,
    ) {
    }

    /// Notify the firewall GUI via HydraHipEvent about an OpenEDR-sourced threat.
    fn notify_openedr_threat(&self, pid: u32, exe_path: &str, label: &str, analysis_type: &str) {
        let app_name = Path::new(exe_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut dummy_state =
            ProcessBehaviorState::new(pid, PathBuf::from(exe_path), app_name.clone());
        dummy_state.cloud_static_label = if analysis_type == "Static" {
            Some(label.to_string())
        } else {
            None
        };
        dummy_state.cloud_dynamic_label = if analysis_type == "Dynamic" {
            Some(label.to_string())
        } else {
            None
        };

        let rule = BehaviorRule {
            name: format!("Cloud:{}:{}", analysis_type, label),
            description: format!(
                "Threat detected by OpenEDR/Valkyrie Cloud {} Analysis",
                analysis_type
            ),
            response: ResponseAction {
                ask_user: true,
                terminate_process: true,
                quarantine: true,
                notify_user: true,
                ..Default::default()
            },
            ..Default::default()
        };

        // Forward to the HIPS pipe. We use GID 0 for external cloud alerts.
        let _ = self.resolve_firewall_hips_prompt(0, &dummy_state, &rule);
    }

    /// Ingest a telemetry event emitted by OpenEDR's direct edrsvc feed.
    pub fn ingest_openedr_event(&self, event: &serde_json::Value) {
        fn str_at<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
            let mut cur = value;
            for part in path {
                cur = cur.get(*part)?;
            }
            cur.as_str().map(str::trim).filter(|text| !text.is_empty())
        }

        fn u64_at(value: &serde_json::Value, path: &[&str]) -> Option<u64> {
            let mut cur = value;
            for part in path {
                cur = cur.get(*part)?;
            }
            cur.as_u64().or_else(|| {
                cur.as_str()
                    .map(str::trim)
                    .and_then(|text| text.parse::<u64>().ok())
            })
        }

        fn openedr_alias_token(event_type: &str) -> String {
            let mut token = String::new();
            for part in event_type.trim_start_matches("LLE_").split('_') {
                let mut chars = part.chars();
                let Some(first) = chars.next() else {
                    continue;
                };
                token.push(first.to_ascii_uppercase());
                token.push_str(&chars.as_str().to_ascii_lowercase());
            }
            token
        }

        fn is_openedr_registry_event(event_type: &str) -> bool {
            matches!(
                event_type,
                "LLE_REGISTRY_KEY_CREATE"
                    | "LLE_REGISTRY_KEY_DELETE"
                    | "LLE_REGISTRY_KEY_NAME_CHANGE"
                    | "LLE_REGISTRY_VALUE_SET"
                    | "LLE_REGISTRY_VALUE_DELETE"
            )
        }

        fn openedr_event_family(event_type: &str) -> &'static str {
            if event_type.starts_with("LLE_FILE_") {
                "File"
            } else if is_openedr_registry_event(event_type) {
                "Registry"
            } else if matches!(
                event_type,
                "LLE_PROCESS_CREATE"
                    | "LLE_PROCESS_DELETE"
                    | "LLE_PROCESS_OPEN"
                    | "LLE_PROCESS_MEMORY_READ"
                    | "LLE_PROCESS_MEMORY_WRITE"
                    | "LLE_INJECTION_ACTIVITY"
            ) {
                "Process"
            } else if event_type.starts_with("LLE_NETWORK_") {
                "Network"
            } else if matches!(
                event_type,
                "LLE_DEVICE_IOCTL"
                    | "LLE_DISK_RAW_WRITE_ACCESS"
                    | "LLE_VOLUME_RAW_WRITE_ACCESS"
                    | "LLE_DEVICE_RAW_WRITE_ACCESS"
                    | "LLE_DISK_LINK_CREATE"
                    | "LLE_VOLUME_LINK_CREATE"
                    | "LLE_DEVICE_LINK_CREATE"
            ) {
                "Device"
            } else if matches!(event_type, "LLE_NAMED_PIPE_CREATE" | "IRP_NAMED_PIPE_WRITE") {
                "Pipe"
            } else if matches!(
                event_type,
                "LLE_WINDOW_PROC_GLOBAL_HOOK"
                    | "LLE_KEYBOARD_GLOBAL_READ"
                    | "LLE_KEYBOARD_GLOBAL_WRITE"
                    | "LLE_KEYBOARD_BLOCK"
                    | "LLE_CLIPBOARD_READ"
                    | "LLE_MICROPHONE_ENUM"
                    | "LLE_MICROPHONE_READ"
                    | "LLE_MOUSE_GLOBAL_WRITE"
                    | "LLE_MOUSE_BLOCK"
                    | "LLE_WINDOW_DATA_READ"
                    | "LLE_DESKTOP_WALLPAPER_SET"
            ) {
                "Input"
            } else if matches!(event_type, "LLE_USER_LOGON" | "LLE_USER_IMPERSONATION") {
                "User"
            } else if event_type == "LLE_SELF_DEFENSE" {
                "SelfDefense"
            } else if matches!(
                event_type,
                "IRP_USERMODE_HOOK_EVENT"
                    | "IRP_KERNEL_REMOTE_THREAD"
                    | "IRP_KERNEL_WRITE_MEMORY"
                    | "IRP_KERNEL_PROTECT_MEMORY"
                    | "IRP_KERNEL_CREATE_THREAD"
                    | "IRP_KERNEL_QUEUE_APC"
                    | "IRP_KERNEL_CREATE_SECTION"
                    | "IRP_KERNEL_MAP_SECTION"
            ) {
                "KernelHook"
            } else if matches!(
                event_type,
                "IRP_ROOTKIT_SSDT_HOOK"
                    | "IRP_ROOTKIT_HIDDEN_PROCESS"
                    | "IRP_ROOTKIT_HIDDEN_DRIVER"
                    | "IRP_ROOTKIT_KERNEL_HOOK"
                    | "IRP_ROOTKIT_TERMINATE_PROCESS"
                    | "IRP_ROOTKIT_FILE_MOVE"
                    | "IRP_ROOTKIT_GENERIC"
            ) {
                "Rootkit"
            } else if matches!(event_type, "IRP_HYPERVISOR_EVENT") {
                "Hypervisor"
            } else {
                "Other"
            }
        }

        let event_type = str_at(event, &["type"])
            .or_else(|| str_at(event, &["event_type"]))
            .or_else(|| str_at(event, &["baseType"]))
            .unwrap_or("")
            .trim();
        let pid = u64_at(event, &["process", "pid"])
            .or_else(|| u64_at(event, &["process.pid"]))
            .or_else(|| u64_at(event, &["pid"]))
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;
        if pid == 0 || event_type.is_empty() {
            return;
        }

        let target_pid = u64_at(event, &["target", "pid"])
            .or_else(|| u64_at(event, &["target.pid"]))
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;
        let remote_ip = str_at(event, &["connection", "remote", "ip"])
            .or_else(|| str_at(event, &["connection.remote.ip"]))
            .unwrap_or("");
        let remote_port = u64_at(event, &["connection", "remote", "port"])
            .or_else(|| u64_at(event, &["connection.remote.port"]))
            .unwrap_or(0)
            .min(u16::MAX as u64) as u16;
        let exe_path = str_at(event, &["process", "path"])
            .or_else(|| str_at(event, &["process", "imageFile", "rawPath"]))
            .or_else(|| str_at(event, &["process.imageFile.rawPath"]))
            .or_else(|| str_at(event, &["process_path"]))
            .unwrap_or("Unknown");
        let file_path = str_at(event, &["file", "path"])
            .or_else(|| str_at(event, &["file", "rawPath"]))
            .or_else(|| str_at(event, &["file.rawPath"]))
            .or_else(|| str_at(event, &["path"]))
            .unwrap_or("");
        let registry_path = str_at(event, &["registry", "path"])
            .or_else(|| str_at(event, &["registry", "rawPath"]))
            .or_else(|| str_at(event, &["registry.rawPath"]))
            .unwrap_or("");
        let is_registry_event = is_openedr_registry_event(event_type);
        let protected_path = if is_registry_event && !registry_path.is_empty() {
            registry_path
        } else {
            file_path
        };
        let access_or_ioctl = u64_at(event, &["accessMask"])
            .or_else(|| u64_at(event, &["access_mask"]))
            .unwrap_or(0);
        let event_family = openedr_event_family(event_type);
        let event_alias_token = openedr_alias_token(event_type);

        let mut aliases = vec![format!(
            "OpenEDR::{}",
            event_type.trim_start_matches("LLE_")
        )];
        if !event_alias_token.is_empty() {
            aliases.push(format!("OpenEDR::{event_alias_token}"));
            aliases.push(format!("OpenEDR::{event_family}::{event_alias_token}"));
        }
        aliases.push(format!("OpenEDR::Family::{event_family}"));
        match event_type {
            "LLE_PROCESS_CREATE" => {
                aliases.push("OpenEDR::ProcessCreate".to_string());
            }
            "LLE_PROCESS_DELETE" => {
                aliases.push("OpenEDR::ProcessDelete".to_string());
            }
            "LLE_PROCESS_OPEN" => {
                aliases.push("OpenEDR::ProcessOpen".to_string());
                if target_pid != 0 && target_pid != pid {
                    aliases.push("OpenEDR::CrossProcessHandle".to_string());
                }
            }
            "LLE_PROCESS_MEMORY_READ" => {
                aliases.push("OpenEDR::ProcessMemoryRead".to_string());
                aliases.push("OpenEDR::MemoryRead".to_string());
            }
            "LLE_PROCESS_MEMORY_WRITE" => {
                aliases.push("OpenEDR::ProcessMemoryWrite".to_string());
                aliases.push("OpenEDR::MemoryWrite".to_string());
            }
            "LLE_INJECTION_ACTIVITY" => {
                aliases.push("OpenEDR::InjectionActivity".to_string());
                aliases.push("OpenEDR::ProcessInjection".to_string());
            }
            "LLE_NETWORK_CONNECT_IN" | "LLE_NETWORK_CONNECT_OUT" | "LLE_NETWORK_LISTEN" => {
                aliases.push("OpenEDR::NetworkConnect".to_string());
            }
            "LLE_NETWORK_REQUEST_DNS" => {
                aliases.push("OpenEDR::DnsRequest".to_string());
            }
            "LLE_NETWORK_REQUEST_DATA" => {
                aliases.push("OpenEDR::NetworkRequestData".to_string());
            }
            "LLE_FILE_CREATE" => {
                aliases.push("OpenEDR::FileCreate".to_string());
                aliases.push("OpenEDR::FileAccess".to_string());
            }
            "LLE_FILE_DELETE" => {
                aliases.push("OpenEDR::FileDelete".to_string());
                aliases.push("OpenEDR::FileModify".to_string());
            }
            "LLE_FILE_CLOSE" => {
                aliases.push("OpenEDR::FileClose".to_string());
            }
            "LLE_FILE_DATA_CHANGE" => {
                aliases.push("OpenEDR::FileDataChange".to_string());
                aliases.push("OpenEDR::FileModify".to_string());
            }
            "LLE_FILE_DATA_READ_FULL" => {
                aliases.push("OpenEDR::FileRead".to_string());
                aliases.push("OpenEDR::FileAccess".to_string());
            }
            "LLE_FILE_DATA_WRITE_FULL" => {
                aliases.push("OpenEDR::FileWrite".to_string());
                aliases.push("OpenEDR::FileModify".to_string());
            }
            "LLE_REGISTRY_KEY_CREATE" | "LLE_REGISTRY_KEY_NAME_CHANGE" => {
                aliases.push("OpenEDR::RegistryKeyModify".to_string());
                aliases.push("OpenEDR::RegistryModify".to_string());
            }
            "LLE_REGISTRY_KEY_DELETE" => {
                aliases.push("OpenEDR::RegistryKeyDelete".to_string());
                aliases.push("OpenEDR::RegistryModify".to_string());
            }
            "LLE_REGISTRY_VALUE_SET" => {
                aliases.push("OpenEDR::RegistryValueSet".to_string());
                aliases.push("OpenEDR::RegistryModify".to_string());
            }
            "LLE_REGISTRY_VALUE_DELETE" => {
                aliases.push("OpenEDR::RegistryValueDelete".to_string());
                aliases.push("OpenEDR::RegistryModify".to_string());
            }
            "LLE_DEVICE_IOCTL" => {
                aliases.push("OpenEDR::DeviceIoControl".to_string());
                aliases.push(format!("OpenEDR::IOCTL:0x{access_or_ioctl:08X}"));
            }
            "LLE_DISK_RAW_WRITE_ACCESS" | "LLE_VOLUME_RAW_WRITE_ACCESS" => {
                aliases.push("OpenEDR::RawDiskWrite".to_string());
                aliases.push("OpenEDR::DiskTamper".to_string());
            }
            "LLE_DEVICE_RAW_WRITE_ACCESS" => {
                aliases.push("OpenEDR::DeviceRawWrite".to_string());
            }
            "LLE_DISK_LINK_CREATE" | "LLE_VOLUME_LINK_CREATE" | "LLE_DEVICE_LINK_CREATE" => {
                aliases.push("OpenEDR::DeviceLinkCreate".to_string());
            }
            "LLE_NAMED_PIPE_CREATE" => {
                aliases.push("OpenEDR::NamedPipeCreate".to_string());
                aliases.push("OpenEDR::NamedPipe".to_string());
            }
            "LLE_USER_LOGON" => {
                aliases.push("OpenEDR::UserLogon".to_string());
            }
            "LLE_USER_IMPERSONATION" => {
                aliases.push("OpenEDR::UserImpersonation".to_string());
            }
            "LLE_SELF_DEFENSE" => {
                aliases.push("OpenEDR::SelfDefense".to_string());
            }
            // --- Input / surveillance events (events.hpp 0x11–0x26) ---
            "LLE_WINDOW_PROC_GLOBAL_HOOK" => {
                aliases.push("OpenEDR::WindowProcHook".to_string());
                aliases.push("OpenEDR::InputHook".to_string());
            }
            "LLE_KEYBOARD_GLOBAL_READ" => {
                aliases.push("OpenEDR::KeyboardRead".to_string());
                aliases.push("OpenEDR::Keylogger".to_string());
                aliases.push("OpenEDR::InputHook".to_string());
            }
            "LLE_KEYBOARD_GLOBAL_WRITE" => {
                aliases.push("OpenEDR::KeyboardWrite".to_string());
                aliases.push("OpenEDR::InputHook".to_string());
            }
            "LLE_KEYBOARD_BLOCK" => {
                aliases.push("OpenEDR::KeyboardBlock".to_string());
                aliases.push("OpenEDR::InputBlock".to_string());
            }
            "LLE_CLIPBOARD_READ" => {
                aliases.push("OpenEDR::ClipboardRead".to_string());
                aliases.push("OpenEDR::DataTheft".to_string());
            }
            "LLE_MICROPHONE_ENUM" => {
                aliases.push("OpenEDR::MicrophoneEnum".to_string());
                aliases.push("OpenEDR::AudioAccess".to_string());
            }
            "LLE_MICROPHONE_READ" => {
                aliases.push("OpenEDR::MicrophoneRead".to_string());
                aliases.push("OpenEDR::AudioAccess".to_string());
                aliases.push("OpenEDR::DataTheft".to_string());
            }
            "LLE_MOUSE_GLOBAL_WRITE" => {
                aliases.push("OpenEDR::MouseWrite".to_string());
                aliases.push("OpenEDR::InputHook".to_string());
            }
            "LLE_MOUSE_BLOCK" => {
                aliases.push("OpenEDR::MouseBlock".to_string());
                aliases.push("OpenEDR::InputBlock".to_string());
            }
            "LLE_WINDOW_DATA_READ" => {
                aliases.push("OpenEDR::WindowDataRead".to_string());
                aliases.push("OpenEDR::DataTheft".to_string());
            }
            "LLE_DESKTOP_WALLPAPER_SET" => {
                aliases.push("OpenEDR::DesktopWallpaperSet".to_string());
                aliases.push("OpenEDR::UiTamper".to_string());
            }
            // --- Communication.cpp hook / hypervisor / rootkit events ---
            // These arrive via the edrsvc enrichment pipe (post-EventEnricher)
            // as JSON with "type" set to the IRP_ string directly.
            "IRP_USERMODE_HOOK_EVENT" => {
                aliases.push("KernelHook::UserModeHook".to_string());
                aliases.push("KernelHook::Hook".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_REMOTE_THREAD" => {
                aliases.push("KernelHook::RemoteThread".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_WRITE_MEMORY" => {
                aliases.push("KernelHook::WriteMemory".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_PROTECT_MEMORY" => {
                aliases.push("KernelHook::ProtectMemory".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_CREATE_THREAD" => {
                aliases.push("KernelHook::CreateThread".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_QUEUE_APC" => {
                aliases.push("KernelHook::QueueApc".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_CREATE_SECTION" => {
                aliases.push("KernelHook::CreateSection".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_KERNEL_MAP_SECTION" => {
                aliases.push("KernelHook::MapSection".to_string());
                aliases.push("KernelHook::Injection".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_SSDT_HOOK" => {
                aliases.push("KernelHook::SsdtHook".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_HIDDEN_PROCESS" => {
                aliases.push("KernelHook::HiddenProcess".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_HIDDEN_DRIVER" => {
                aliases.push("KernelHook::HiddenDriver".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_KERNEL_HOOK" => {
                aliases.push("KernelHook::KernelHookDetected".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_TERMINATE_PROCESS" => {
                aliases.push("KernelHook::TerminateProcess".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_FILE_MOVE" => {
                aliases.push("KernelHook::FileMove".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_ROOTKIT_GENERIC" => {
                aliases.push("KernelHook::RootkitGeneric".to_string());
                aliases.push("KernelHook::Rootkit".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_HYPERVISOR_EVENT" => {
                aliases.push("KernelHook::HypervisorEvent".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            "IRP_NAMED_PIPE_WRITE" => {
                aliases.push("KernelHook::NamedPipeWrite".to_string());
                aliases.push("KernelHook::Any".to_string());
            }
            _ => {}
        }

        let mut summary = event_type.to_string();
        if target_pid != 0 && target_pid != pid {
            summary.push_str(&format!(" target={}", target_pid));
        }
        if !protected_path.is_empty() {
            summary.push_str(&format!(" path={}", protected_path));
        }
        if is_registry_event && !registry_path.is_empty() {
            summary.push_str(&format!(" registry={}", registry_path));
        }
        if !remote_ip.is_empty() {
            if remote_port != 0 {
                summary.push_str(&format!(" remote={}:{}", remote_ip, remote_port));
            } else {
                summary.push_str(&format!(" remote={}", remote_ip));
            }
        }

        if matches!(
            event_type,
            "LLE_NETWORK_CONNECT_IN"
                | "LLE_NETWORK_CONNECT_OUT"
                | "LLE_NETWORK_LISTEN"
                | "LLE_NETWORK_REQUEST_DNS"
                | "LLE_NETWORK_REQUEST_DATA"
        ) {
            self.openedr_net_pids.write().unwrap().insert(pid);
            if !remote_ip.is_empty() {
                let mut net_details = self.openedr_net_details.write().unwrap();
                let entries = net_details.entry(pid).or_default();
                if !entries
                    .iter()
                    .any(|(ip, port)| ip == remote_ip && *port == remote_port)
                {
                    entries.push((remote_ip.to_string(), remote_port));
                    if entries.len() > 64 {
                        let overflow = entries.len() - 64;
                        entries.drain(0..overflow);
                    }
                }
            }
        }

        let protected_path_lc = protected_path.replace('/', "\\").to_ascii_lowercase();
        let registry_path_lc = registry_path.replace('/', "\\").to_ascii_lowercase();
        let pipe_path = if event_type == "LLE_NAMED_PIPE_CREATE" {
            file_path
        } else {
            ""
        };
        let pipe_lc = pipe_path.replace('/', "\\").to_ascii_lowercase();
        let is_security_file = !protected_path_lc.is_empty()
            && (protected_path_lc.contains("\\program files\\hydradragonantivirus\\")
                || protected_path_lc.contains("\\system32\\tasks\\hydradragonantivirus")
                || protected_path_lc.contains("\\system32\\drivers\\owlyshieldransomfilter.sys")
                || protected_path_lc.contains("\\system32\\drivers\\reddbgdrv.sys")
                || protected_path_lc.contains("\\system32\\drivers\\hyperhv.sys")
                || protected_path_lc.contains("\\system32\\drivers\\mbrfilter.sys")
                || protected_path_lc.contains("\\system32\\drivers\\fs_minifilter.sys")
                || protected_path_lc.contains("\\system32\\drivers\\sanctum.sys")
                || protected_path_lc.contains("\\system32\\drivers\\edrdrv.sys")
                || protected_path_lc.contains("\\system32\\edrpm64.dll")
                || protected_path_lc.contains("\\system32\\edrpm32.dll")
                || protected_path_lc.contains("\\system32\\edrmm.dll"));
        let is_security_registry = is_registry_event
            && !registry_path_lc.is_empty()
            && (registry_path_lc.contains("\\services\\owlyshield_ransom")
                || registry_path_lc.contains("\\services\\reddbg")
                || registry_path_lc.contains("\\services\\hyperdbg")
                || registry_path_lc.contains("\\services\\hyperhv")
                || registry_path_lc.contains("\\services\\sanctum_ppl_runner")
                || registry_path_lc.contains("\\services\\mbrfilter")
                || registry_path_lc.contains("\\services\\fs_minifilter")
                || registry_path_lc.contains("\\services\\sanctum")
                || registry_path_lc.contains("\\services\\edrdrv")
                || registry_path_lc.contains("\\services\\edrsvc")
                || registry_path_lc.contains("\\software\\owlyshield"));
        let is_security_pipe = !pipe_lc.is_empty()
            && (pipe_lc.contains("hydradragon")
                || pipe_lc.contains("owlyshield")
                || pipe_lc.contains("sanctum")
                || pipe_lc.contains("openedr")
                || pipe_lc.contains("hydranet")
                || pipe_lc.contains("hydra"));
        let is_disk_wiper_ioctl = event_type == "LLE_DEVICE_IOCTL";
        let is_cross_process_open =
            event_type == "LLE_PROCESS_OPEN" && target_pid != 0 && target_pid != pid;
        let is_process_memory_tamper = matches!(
            event_type,
            "LLE_PROCESS_MEMORY_WRITE" | "LLE_INJECTION_ACTIVITY"
        );
        let is_raw_device_tamper = matches!(
            event_type,
            "LLE_DISK_RAW_WRITE_ACCESS"
                | "LLE_VOLUME_RAW_WRITE_ACCESS"
                | "LLE_DEVICE_RAW_WRITE_ACCESS"
        );

        if is_security_file
            || is_security_registry
            || is_security_pipe
            || is_disk_wiper_ioctl
            || is_cross_process_open
            || is_process_memory_tamper
            || is_raw_device_tamper
            || event_type == "LLE_SELF_DEFENSE"
        {
            let (category, operation, attack_type, target) = if is_disk_wiper_ioctl {
                (
                    "disk",
                    format!("IOCTL_0x{access_or_ioctl:08X}"),
                    "DISK_WIPER_ATTEMPT".to_string(),
                    if protected_path.is_empty() {
                        "BOOT_DISK_OR_DRIVE_LAYOUT"
                    } else {
                        protected_path
                    }
                    .to_string(),
                )
            } else if is_security_pipe {
                (
                    "pipe",
                    "PIPE_CREATE".to_string(),
                    "NAMED_PIPE_TAMPER_OR_DISCOVERY".to_string(),
                    pipe_path.to_string(),
                )
            } else if is_security_registry {
                (
                    "registry",
                    event_type.trim_start_matches("LLE_REGISTRY_").to_string(),
                    "REGISTRY_TAMPERING".to_string(),
                    protected_path.to_string(),
                )
            } else if is_process_memory_tamper {
                (
                    "process",
                    event_alias_token.clone(),
                    "PROCESS_MEMORY_TAMPERING".to_string(),
                    format!("pid:{}", target_pid),
                )
            } else if is_cross_process_open || event_type == "LLE_SELF_DEFENSE" {
                (
                    "process",
                    event_alias_token.clone().if_empty("PROCESS_OPEN"),
                    if is_cross_process_open {
                        "CROSS_PROCESS_HANDLE".to_string()
                    } else {
                        "PROCESS_TAMPERING".to_string()
                    },
                    format!("pid:{}", target_pid),
                )
            } else if is_raw_device_tamper {
                (
                    "disk",
                    event_alias_token.clone(),
                    "RAW_DEVICE_TAMPERING".to_string(),
                    if protected_path.is_empty() {
                        "BOOT_DISK_OR_DRIVE_LAYOUT"
                    } else {
                        protected_path
                    }
                    .to_string(),
                )
            } else {
                (
                    "file",
                    event_type.trim_start_matches("LLE_FILE_").to_string(),
                    "FILE_TAMPERING".to_string(),
                    protected_path.to_string(),
                )
            };

            record_self_defense_telemetry(serde_json::json!({
                "source": "openedr",
                "category": category,
                "action": "telemetry",
                "attack_type": attack_type,
                "operation": operation,
                "protected_file": target,
                "attacker_path": exe_path,
                "attacker_pid": pid,
                "target_pid": target_pid,
            }));
        }

        let mut openedr_lock = self.openedr_stats.write().unwrap();
        let stats = openedr_lock
            .entry(pid)
            .or_insert_with(OpenEdrTelemetryStats::default);
        stats.total_event_count += 1;
        stats.last_event = Some(summary.clone());
        if stats.recent_events.len() >= 32 {
            stats.recent_events.pop_front();
        }
        stats.recent_events.push_back(summary);
        for alias in aliases {
            stats.detected_apis.insert(alias);
        }

        match event_family {
            "Process" => stats.process_event_count += 1,
            "File" => stats.file_event_count += 1,
            "Registry" => stats.registry_event_count += 1,
            "Network" => stats.network_event_count += 1,
            "Device" => stats.device_event_count += 1,
            "Pipe" => stats.pipe_event_count += 1,
            "Input" => stats.input_event_count += 1,
            "User" => stats.user_event_count += 1,
            "SelfDefense" => stats.self_defense_event_count += 1,
            // Communication.cpp kernel hook / rootkit / hypervisor families
            "KernelHook" | "Rootkit" | "Hypervisor" => stats.memory_event_count += 1,
            _ => {}
        }

        if matches!(
            event_type,
            "LLE_PROCESS_MEMORY_READ" | "LLE_PROCESS_MEMORY_WRITE"
        ) {
            stats.memory_event_count += 1;
        }

        match event_type {
            "LLE_PROCESS_OPEN" => stats.process_open_count += 1,
            "LLE_PROCESS_MEMORY_WRITE" => stats.memory_write_count += 1,
            "LLE_INJECTION_ACTIVITY" => stats.injection_activity_count += 1,
            "LLE_NETWORK_CONNECT_IN"
            | "LLE_NETWORK_CONNECT_OUT"
            | "LLE_NETWORK_LISTEN"
            | "LLE_NETWORK_REQUEST_DNS"
            | "LLE_NETWORK_REQUEST_DATA" => stats.network_connect_count += 1,
            _ => {}
        }

        // ── owlyHook / owlyHv → pending IrpOperationRecord ──────────────────────
        // These fields are populated by controller.cpp parseEvent for
        // DeviceIoControl (hook) and hypervisor events.  We convert them into
        // IrpOperationRecord entries and push them into the shared pending queue so
        // the main Worker thread can apply them to ProcessBehaviorState via
        // record_irp_operation without needing &mut self here.
        {
            // Helper to read a sub-dict string field
            fn hv_str<'a>(event: &'a serde_json::Value, dict: &str, key: &str) -> &'a str {
                event
                    .get(dict)
                    .and_then(|d| d.get(key))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            }
            fn hv_u64(event: &serde_json::Value, dict: &str, key: &str) -> u64 {
                event
                    .get(dict)
                    .and_then(|d| d.get(key))
                    .and_then(|v| v.as_u64().or_else(|| v.as_str()?.trim().parse().ok()))
                    .unwrap_or(0)
            }
            fn hv_u32(event: &serde_json::Value, dict: &str, key: &str) -> u32 {
                hv_u64(event, dict, key).min(u32::MAX as u64) as u32
            }

            // Determine SysmonEvent id for this OpenEDR event type
            use crate::shared_def::SysmonEvent as SE;
            let irp_type_opt: Option<u32> = match event_type {
                // LLE_ events that map to a SysmonEvent
                "LLE_FILE_CREATE" => Some(SE::FileCreate as u32),
                "LLE_FILE_DELETE" => Some(SE::FileDelete as u32),
                "LLE_FILE_CLOSE" => Some(SE::FileClose as u32),
                "LLE_FILE_DATA_CHANGE" => Some(SE::FileDataChange as u32),
                "LLE_FILE_DATA_READ_FULL" => Some(SE::FileDataReadFull as u32),
                "LLE_FILE_DATA_WRITE_FULL" => Some(SE::FileDataWriteFull as u32),
                "LLE_REGISTRY_KEY_CREATE" | "LLE_REGISTRY_KEY_NAME_CHANGE" => {
                    Some(SE::RegistryKeyCreate as u32)
                }
                "LLE_REGISTRY_KEY_DELETE" => Some(SE::RegistryKeyDelete as u32),
                "LLE_REGISTRY_VALUE_SET" => Some(SE::RegistryValueSet as u32),
                "LLE_REGISTRY_VALUE_DELETE" => Some(SE::RegistryValueDelete as u32),
                "LLE_PROCESS_CREATE" => Some(SE::ProcessCreate as u32),
                "LLE_PROCESS_DELETE" => Some(SE::ProcessDelete as u32),
                "LLE_PROCESS_OPEN" => Some(SE::ProcessOpen as u32),
                "LLE_NAMED_PIPE_CREATE" => Some(SE::NamedPipeCreate as u32),
                // IRP_ hook/hypervisor/rootkit events carried as DeviceIoControl
                "IRP_USERMODE_HOOK_EVENT" | "IRP_HYPERVISOR_EVENT" | "LLE_DEVICE_IOCTL" => {
                    Some(SE::DeviceIoControl as u32)
                }
                "IRP_KERNEL_REMOTE_THREAD" => Some(SE::DeviceIoControl as u32),
                "IRP_KERNEL_WRITE_MEMORY" => Some(SE::DeviceIoControl as u32),
                "IRP_KERNEL_PROTECT_MEMORY" => Some(SE::DeviceIoControl as u32),
                "IRP_KERNEL_CREATE_THREAD" => Some(SE::DeviceIoControl as u32),
                "IRP_KERNEL_QUEUE_APC" => Some(SE::DeviceIoControl as u32),
                "IRP_KERNEL_CREATE_SECTION" => Some(SE::DeviceIoControl as u32),
                "IRP_KERNEL_MAP_SECTION" => Some(SE::DeviceIoControl as u32),
                "IRP_ROOTKIT_SSDT_HOOK"
                | "IRP_ROOTKIT_HIDDEN_PROCESS"
                | "IRP_ROOTKIT_HIDDEN_DRIVER"
                | "IRP_ROOTKIT_KERNEL_HOOK"
                | "IRP_ROOTKIT_TERMINATE_PROCESS"
                | "IRP_ROOTKIT_FILE_MOVE"
                | "IRP_ROOTKIT_GENERIC" => Some(SE::DeviceIoControl as u32),
                "IRP_NAMED_PIPE_WRITE" => Some(SE::NamedPipeCreate as u32),
                _ => None,
            };

            if let Some(irp_type) = irp_type_opt {
                // Build the IrpOperationRecord from available JSON sub-dicts.
                // owlyHv.* fields come from hypervisor events (LLE_DEVICE_IOCTL).
                // owlyHook.* fields come from kernel hook events (IRP_*).
                let hook_event_type = hv_u32(event, "owlyHook", "eventType");
                let hook_fn = hv_str(event, "owlyHook", "functionName").to_string();
                let hook_src_pid = hv_u32(event, "owlyHook", "sourcePid");
                let hv_target_pid = hv_u32(event, "owlyHv", "targetPid");

                let effective_target_pid = if hv_target_pid != 0 {
                    hv_target_pid
                } else if hook_src_pid != 0 && hook_src_pid != pid {
                    hook_src_pid
                } else {
                    target_pid
                };

                // Resolve the concrete IRP SysmonEvent byte for hook events.
                // If owlyHook.eventType is non-zero, it is a more specific IRP opcode.
                let effective_irp_type = if hook_event_type != 0 {
                    hook_event_type
                } else {
                    irp_type
                };

                // Pipe name / payload for LLE_NAMED_PIPE_CREATE / IRP_NAMED_PIPE_WRITE
                let pipe_name = if matches!(event_type, "LLE_NAMED_PIPE_CREATE" | "IRP_NAMED_PIPE_WRITE") {
                    protected_path.to_string()
                } else {
                    String::new()
                };

                let rec = IrpOperationRecord {
                    timestamp: std::time::SystemTime::now(),
                    irp_type: effective_irp_type,
                    file_path: if pipe_name.is_empty() {
                        protected_path.to_string()
                    } else {
                        pipe_name.clone()
                    },
                    file_change: 0,
                    extension: {
                        let p = protected_path;
                        if let Some(pos) = p.rfind('.') {
                            p[pos + 1..].to_ascii_lowercase()
                        } else {
                            String::new()
                        }
                    },
                    entropy: 0.0,
                    bytes_transferred: hv_u64(event, "owlyHv", "memorySize"),
                    target_pid: effective_target_pid,
                    function_name: if hook_fn.is_empty() {
                        event_type.to_string()
                    } else {
                        hook_fn
                    },
                    pipe_name,
                    pipe_payload: Vec::new(),
                    raw_arguments: [
                        hv_u64(event, "owlyHook", "arg1"),
                        hv_u64(event, "owlyHook", "arg2"),
                        hv_u64(event, "owlyHook", "arg3"),
                        hv_u64(event, "owlyHook", "arg4"),
                    ],
                };

                if let Ok(mut q) = self.pending_irp_records.lock() {
                    // Cap queue at 4096 entries to bound memory under high event rates.
                    let q: &mut std::collections::VecDeque<(u32, IrpOperationRecord)> = &mut *q;
                    if q.len() < 4096 {
                        q.push_back((pid, rec));
                    }
                }
            }
        }

        // Extract OpenEDR/Valkyrie cloud analysis.
        // Labels are retained only for display/logging. Decisions use numeric verdict/result codes only.
        if let Some(cloud) = event.get("cloud_analysis") {
            if let Some(static_label) = cloud.get("static_label").and_then(|v| v.as_str()) {
                stats.cloud_static_label = Some(static_label.to_string());
            }
            let static_verdict = cloud
                .get("trust_level")
                .or_else(|| cloud.get("verdict"))
                .or_else(|| cloud.get("result"))
                .or_else(|| cloud.get("rating"))
                .and_then(OpenEdrFlsVerdict::from_json_value);
            stats.cloud_static_verdict = static_verdict.map(OpenEdrFlsVerdict::code);

            if let Some(verdict) = static_verdict {
                self.notify_firewall_openedr_verdict(pid, exe_path, verdict, "Static");
            }

            if static_verdict.is_some_and(OpenEdrFlsVerdict::is_malicious) {
                let label = stats
                    .cloud_static_label
                    .as_deref()
                    .unwrap_or("OpenEDR static verdict");
                self.notify_openedr_threat(pid, exe_path, label, "OpenEDR FLS Code 2 (Malware)");
            }

            if let Some(dynamic_label) = cloud.get("dynamic_label").and_then(|v| v.as_str()) {
                stats.cloud_dynamic_label = Some(dynamic_label.to_string());
            }
            let dynamic_verdict = cloud
                .get("dynamic_trust_level")
                .or_else(|| cloud.get("dynamic_verdict"))
                .or_else(|| cloud.get("dynamic_result"))
                .or_else(|| cloud.get("dynamic_rating"))
                .and_then(OpenEdrFlsVerdict::from_json_value);
            stats.cloud_dynamic_verdict = dynamic_verdict.map(OpenEdrFlsVerdict::code);

            if let Some(verdict) = dynamic_verdict {
                self.notify_firewall_openedr_verdict(pid, exe_path, verdict, "Dynamic");
            }

            if dynamic_verdict.is_some_and(OpenEdrFlsVerdict::is_malicious) {
                let label = stats
                    .cloud_dynamic_label
                    .as_deref()
                    .unwrap_or("OpenEDR dynamic verdict");
                self.notify_openedr_threat(pid, exe_path, label, "OpenEDR FLS Code 2 (Malware)");
            }
        }
    }

    fn format_capemon_bson_scalar(value: &bson::Bson) -> Option<String> {
        Some(match value {
            bson::Bson::String(s) => s.clone(),
            bson::Bson::Int32(i) => i.to_string(),
            bson::Bson::Int64(i) => i.to_string(),
            bson::Bson::Double(d) => d.to_string(),
            bson::Bson::Boolean(b) => b.to_string(),
            _ => return None,
        })
    }

    fn format_capemon_bson_value(value: &bson::Bson, format: CapemonBsonFormat) -> String {
        if let Some(scalar) = Self::format_capemon_bson_scalar(value) {
            return scalar;
        }

        match value {
            bson::Bson::Array(arr) => {
                let elements: Vec<String> = arr
                    .iter()
                    .map(|element| {
                        Self::format_capemon_bson_scalar(element)
                            .unwrap_or_else(|| format!("{:?}", element))
                    })
                    .collect();
                format.format_array(&elements)
            }
            bson::Bson::Document(subdoc) if matches!(format, CapemonBsonFormat::Log) => {
                format!("{{{} fields}}", subdoc.len())
            }
            _ => format!("{:?}", value),
        }
    }

    /// Ingest a BSON telemetry event from Capemon API hooks.
    /// Capemon hooks LoadLibrary, CreateProcess, and other APIs, sending BSON-encoded logs.
    /// This method dynamically processes ALL BSON fields without hardcoded API name checks.
    pub fn ingest_capemon_event(&mut self, pid: u32, doc: bson::Document) {
        let gid = self.find_gid_by_pid(pid).unwrap_or(0);

        // Extract API name from BSON document (if present)
        let api_name = doc.get_str("api").unwrap_or("Unknown").to_string();

        // Build a summary of all BSON fields for logging and analysis
        let mut field_summary = Vec::new();

        // Iterate over ALL BSON document fields dynamically
        for (key, value) in doc.iter() {
            let value_str = Self::format_capemon_bson_value(value, CapemonBsonFormat::Log);

            field_summary.push(format!("{}={}", key, value_str));
        }

        // Update process state with detected API and ALL BSON fields
        if gid != 0 {
            if let Some(state) = self.process_states.get_mut(&gid) {
                // Store API name in detected_apis set
                state.detected_apis.insert(api_name.clone());

                // Store ALL BSON fields dynamically in the process state
                // The behavior engine's rule matching system will analyze these fields
                for (key, value) in doc.iter() {
                    let field_key = format!("capemon:{}:{}", api_name, key);

                    // Convert BSON value to string for storage
                    let value_str =
                        Self::format_capemon_bson_value(value, CapemonBsonFormat::Storage);

                    // Store in detected_apis for rule matching
                    state.detected_apis.insert(field_key);

                    // Also store the actual value for potential future use
                    if !value_str.is_empty() && value_str.len() < 512 {
                        let value_key = format!("capemon_value:{}:{}", api_name, key);
                        state
                            .detected_apis
                            .insert(format!("{}={}", value_key, value_str));
                    }
                }
            }
        }

        Logging::debug(&format!(
            "[Capemon] Ingested API hook from PID {}: {} (GID: {}) | Fields: {}",
            pid,
            api_name,
            gid,
            field_summary.join(", ")
        ));
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn sanitize_firewall_hips_field(value: &str) -> String {
        value
            .replace('\r', " ")
            .replace('\n', " ")
            .replace('|', "/")
            .trim()
            .to_string()
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn is_registry_condition_group(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.registry_keys.is_empty()
            || !cond_group.autorun_keys.is_empty()
            || !cond_group.registry_values.is_empty()
            || !cond_group.registry_value_data_patterns.is_empty()
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn detect_firewall_hips_alert_kind(
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
    ) -> &'static str {
        if rule.named_conditions.iter().any(|(cond_name, cond_group)| {
            Self::rule_condition_satisfied(state, rule, cond_name)
                && Self::is_registry_condition_group(cond_group)
        }) {
            "registry"
        } else if rule
            .named_conditions
            .values()
            .any(Self::is_registry_condition_group)
        {
            "registry"
        } else {
            "behavior"
        }
    }

    fn first_real_match_value(values: &HashSet<String>) -> Option<String> {
        let mut candidates: Vec<String> = values
            .iter()
            .filter_map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with("event:")
                    || trimmed.starts_with("fileid:")
                {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();
        candidates.sort();
        candidates.into_iter().next()
    }

    fn scoped_condition_name(rule: &BehaviorRule, cond_name: &str) -> String {
        format!("{}::{}", rule.name, cond_name)
    }

    fn rule_condition_satisfied(
        state: &ProcessBehaviorState,
        rule: &BehaviorRule,
        cond_name: &str,
    ) -> bool {
        let scoped = Self::scoped_condition_name(rule, cond_name);
        state.satisfied_named_conditions.contains(scoped.as_str())
    }

    fn rule_condition_values<'a>(
        state: &'a ProcessBehaviorState,
        rule: &BehaviorRule,
        cond_name: &str,
    ) -> Option<&'a HashSet<String>> {
        let scoped = Self::scoped_condition_name(rule, cond_name);
        state.condition_match_values.get(&scoped)
    }

    fn rule_has_current_named_condition_match(
        state: &ProcessBehaviorState,
        rule: &BehaviorRule,
        event_time: SystemTime,
    ) -> bool {
        if rule.named_conditions.is_empty() {
            return true;
        }

        rule.named_conditions.keys().any(|cond_name| {
            let scoped = Self::scoped_condition_name(rule, cond_name);
            state.condition_last_seen.get(&scoped).copied() == Some(event_time)
        })
    }

    fn truncate_detail_value(value: &str, max_chars: usize) -> String {
        let normalized = value
            .replace('\r', " ")
            .replace('\n', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        let count = normalized.chars().count();
        if count <= max_chars {
            normalized
        } else {
            let truncated: String = normalized.chars().take(max_chars).collect();
            format!("{}...", truncated.trim_end())
        }
    }

    fn file_change_label(file_change: Option<FileChangeInfo>) -> Option<&'static str> {
        match file_change {
            Some(FileChangeInfo::OpenDirectory) => Some("open_directory"),
            Some(FileChangeInfo::ChangeWrite) => Some("write"),
            Some(FileChangeInfo::ChangeNewFile) => Some("create"),
            Some(FileChangeInfo::ChangeRenameFile) => Some("rename"),
            Some(FileChangeInfo::ChangeExtensionChanged) => Some("extension_change"),
            Some(FileChangeInfo::ChangeDeleteFile) => Some("delete"),
            Some(FileChangeInfo::ChangeDeleteNewFile) => Some("delete_on_close"),
            Some(FileChangeInfo::ChangeOverwriteFile) => Some("overwrite"),
            Some(FileChangeInfo::RegCreateKey) => Some("reg_create_key"),
            Some(FileChangeInfo::RegSetValue) => Some("reg_set_value"),
            Some(FileChangeInfo::RegDeleteValue) => Some("reg_delete_value"),
            Some(FileChangeInfo::RegDeleteKey) => Some("reg_delete_key"),
            Some(FileChangeInfo::RegRenameKey) => Some("reg_rename_key"),
            Some(FileChangeInfo::RegQueryValue) => Some("reg_query_value"),
            Some(FileChangeInfo::RegQueryKey) => Some("reg_query_key"),
            Some(FileChangeInfo::RegOpenKey) => Some("reg_open_key"),
            Some(FileChangeInfo::RegEnumKey) => Some("reg_enum_key"),
            Some(FileChangeInfo::RegEnumValue) => Some("reg_enum_value"),
            _ => None,
        }
    }

    fn registry_operation_aliases(file_change: Option<FileChangeInfo>) -> &'static [&'static str] {
        match file_change {
            Some(FileChangeInfo::RegCreateKey) => &["reg_create_key", "reg_create", "create"],
            Some(FileChangeInfo::RegSetValue) => &["reg_set_value", "reg_set", "set"],
            Some(FileChangeInfo::RegDeleteValue) => &["reg_delete_value", "reg_delete", "delete"],
            Some(FileChangeInfo::RegDeleteKey) => &["reg_delete_key", "reg_delete", "delete"],
            Some(FileChangeInfo::RegRenameKey) => &["reg_rename_key", "reg_rename", "rename"],
            Some(FileChangeInfo::RegQueryValue) => &["reg_query_value", "reg_read", "read"],
            Some(FileChangeInfo::RegQueryKey) => &["reg_query_key", "reg_read", "read"],
            Some(FileChangeInfo::RegOpenKey) => &["reg_open_key", "reg_read", "read"],
            Some(FileChangeInfo::RegEnumKey) => &["reg_enum_key", "reg_read", "read"],
            Some(FileChangeInfo::RegEnumValue) => &["reg_enum_value", "reg_read", "read"],
            _ => &[],
        }
    }
    fn operation_label(msg: &IOMessage) -> String {
        let file_change = FromPrimitive::from_u8(msg.file_change);
        let hyper_event = msg.resolved_hypervisor_event();
        let irp_op = hyper_event
            .as_ref()
            .map(|event| event.irp_op.clone())
            .unwrap_or_else(|| IrpMajorOp::from_byte(effective_hypervisor_irp_byte(msg)));
        let raw_event_type = hyper_event
            .as_ref()
            .map(|event| event.raw_event_type)
            .unwrap_or_else(|| effective_hypervisor_raw_event_type(msg));

        match irp_op {
            IrpMajorOp::IrpRegistry => Self::file_change_label(file_change)
                .unwrap_or("registry")
                .to_string(),
            IrpMajorOp::IrpSetInfo => Self::file_change_label(file_change)
                .unwrap_or("setinfo")
                .to_string(),
            IrpMajorOp::IrpCreate => {
                if matches!(file_change, Some(FileChangeInfo::OpenDirectory)) {
                    "open_directory".to_string()
                } else if matches!(file_change, Some(FileChangeInfo::ChangeNewFile)) {
                    "create".to_string()
                } else {
                    "open".to_string()
                }
            }
            IrpMajorOp::IrpRead => "read".to_string(),
            IrpMajorOp::IrpWrite => "write".to_string(),
            IrpMajorOp::IrpProcessCreate => "process_create".to_string(),
            IrpMajorOp::IrpProcessTerminate => "process_terminate".to_string(),
            IrpMajorOp::IrpProcessTerminateAttempt => "process_terminate_attempt".to_string(),
            IrpMajorOp::IrpProcessExit => "process_exit".to_string(),
            IrpMajorOp::IrpProcessHandleOpen => "process_handle_open".to_string(),
            IrpMajorOp::IrpHypervisorEvent => canonical_hypervisor_event_label(
                &irp_op,
                raw_event_type,
                &resolved_hypervisor_event_name(msg),
            )
            .unwrap_or_else(|| "hypervisor_event".to_string()),
            IrpMajorOp::IrpUserModeHookEvent => "user_mode_hook_event".to_string(),
            IrpMajorOp::IrpKernelRemoteThread => "kernel_remote_thread".to_string(),
            IrpMajorOp::IrpKernelWriteMemory => "kernel_write_memory".to_string(),
            IrpMajorOp::IrpKernelProtectMemory => "kernel_protect_memory".to_string(),
            IrpMajorOp::IrpKernelCreateThread => "kernel_create_thread".to_string(),
            IrpMajorOp::IrpKernelQueueApc => "kernel_queue_apc".to_string(),
            IrpMajorOp::IrpKernelCreateSection => "kernel_create_section".to_string(),
            IrpMajorOp::IrpKernelMapSection => "kernel_map_section".to_string(),
            _ => {
                if let Some(name) = known_raw_event_name(effective_hypervisor_raw_event_type(msg)) {
                    return name.to_string();
                }

                format!("op{}", msg.irp_op)
            }
        }
    }

    fn build_rule_match_details(
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>,
        trigger_type: Option<&str>,
        confidence: Option<f32>,
    ) -> String {
        let mut parts = Vec::new();

        if let Some(kind) = trigger_type {
            if let Some(score) = confidence {
                parts.push(format!("Trigger={} ({:.1}%)", kind, score * 100.0));
            } else {
                parts.push(format!("Trigger={}", kind));
            }
        }

        if !rule.description.trim().is_empty() {
            parts.push(format!(
                "Description={}",
                Self::truncate_detail_value(rule.description.trim(), 220)
            ));
        }

        if let Some(msg) = msg {
            parts.push(format!("Operation={}", Self::operation_label(msg)));

            let kernel_event = msg.resolved_hypervisor_event();
            let kernel_irp = kernel_event
                .as_ref()
                .map(|event| event.irp_op.clone())
                .unwrap_or_else(|| IrpMajorOp::from_byte(effective_hypervisor_irp_byte(msg)));
            if is_kernel_api_irp(&kernel_irp) {
                let raw_event_type = kernel_event
                    .as_ref()
                    .map(|event| event.raw_event_type)
                    .unwrap_or_else(|| effective_hypervisor_raw_event_type(msg));
                let event_name = kernel_event
                    .as_ref()
                    .map(|event| event.event_name.clone())
                    .unwrap_or_else(|| resolved_hypervisor_event_name(msg));
                let event_label = match kernel_irp {
                    IrpMajorOp::IrpUserModeHookEvent => "ApiHookEvent",
                    IrpMajorOp::IrpHypervisorEvent => "HypervisorEvent",
                    IrpMajorOp::IrpKernelRemoteThread
                    | IrpMajorOp::IrpKernelWriteMemory
                    | IrpMajorOp::IrpKernelProtectMemory
                    | IrpMajorOp::IrpKernelCreateThread
                    | IrpMajorOp::IrpKernelQueueApc
                    | IrpMajorOp::IrpKernelCreateSection
                    | IrpMajorOp::IrpKernelMapSection => "KernelApiEvent",
                    _ => "KernelApiEvent",
                };
                parts.push(format!(
                    "{}={}",
                    event_label,
                    Self::truncate_detail_value(&event_name, 180)
                ));
                parts.push(format!("RawEventType=0x{:X}", raw_event_type));
                let core_id = kernel_event
                    .as_ref()
                    .map(|event| event.core_id)
                    .unwrap_or(msg.kernel_event_info.core_id);
                if core_id != 0 {
                    parts.push(format!("CoreId={}", core_id));
                }
                let thread_id = kernel_event
                    .as_ref()
                    .map(|event| event.thread_id)
                    .unwrap_or(msg.kernel_event_info.thread_id);
                if thread_id != 0 {
                    parts.push(format!("ThreadId={}", thread_id));
                }
                let context = kernel_event
                    .as_ref()
                    .map(|event| event.context)
                    .unwrap_or(msg.kernel_event_info.context);
                if context != 0 {
                    parts.push(format!("Context=0x{:X}", context));
                }
                let source_pid = kernel_event
                    .as_ref()
                    .map(|event| event.source_process_id)
                    .unwrap_or(msg.kernel_event_info.source_process_id);
                if source_pid != 0 {
                    parts.push(format!("SourcePid={}", source_pid));
                }
                let target_pid = kernel_event
                    .as_ref()
                    .map(|event| event.target_process_id)
                    .unwrap_or(msg.kernel_event_info.target_process_id);
                if target_pid != 0 {
                    parts.push(format!("TargetPid={}", target_pid));
                }
                let memory_address = kernel_event
                    .as_ref()
                    .map(|event| event.memory_address)
                    .unwrap_or(msg.kernel_event_info.memory_address);
                if memory_address != 0 {
                    parts.push(format!("MemoryAddress=0x{:X}", memory_address));
                }
                let memory_size = kernel_event
                    .as_ref()
                    .map(|event| event.memory_size)
                    .unwrap_or(msg.kernel_event_info.memory_size as u64);
                if memory_size != 0 {
                    parts.push(format!("MemorySize={}", memory_size));
                }
                let thread_handle = kernel_event
                    .as_ref()
                    .map(|event| event.thread_handle)
                    .unwrap_or(msg.kernel_event_info.thread_handle);
                if thread_handle != 0 {
                    parts.push(format!("ThreadHandle=0x{:X}", thread_handle));
                }
                let thread_start_routine = kernel_event
                    .as_ref()
                    .map(|event| event.thread_start_routine)
                    .unwrap_or(msg.kernel_event_info.thread_start_routine);
                if thread_start_routine != 0 {
                    parts.push(format!("ThreadStartRoutine=0x{:X}", thread_start_routine));
                }
                let operation_status = kernel_event
                    .as_ref()
                    .map(|event| event.operation_status)
                    .unwrap_or(msg.kernel_event_info.operation_status);
                parts.push(format!(
                    "Status=0x{:08X}({})",
                    operation_status as u32,
                    hook_status_name(operation_status)
                ));
                let raw_argument1 = kernel_event
                    .as_ref()
                    .map(|event| event.raw_argument1)
                    .unwrap_or(msg.kernel_event_info.raw_argument1);
                let raw_argument2 = kernel_event
                    .as_ref()
                    .map(|event| event.raw_argument2)
                    .unwrap_or(msg.kernel_event_info.raw_argument2);
                let raw_argument3 = kernel_event
                    .as_ref()
                    .map(|event| event.raw_argument3)
                    .unwrap_or(msg.kernel_event_info.raw_argument3);
                let raw_argument4 = kernel_event
                    .as_ref()
                    .map(|event| event.raw_argument4)
                    .unwrap_or(msg.kernel_event_info.raw_argument4);
                parts.push(format!(
                    "Args=[0x{:X},0x{:X},0x{:X},0x{:X}]",
                    raw_argument1, raw_argument2, raw_argument3, raw_argument4
                ));
            }

            if !msg.filepathstr.trim().is_empty() {
                parts.push(format!(
                    "Path={}",
                    Self::truncate_detail_value(&msg.filepathstr, 260)
                ));
            } else {
                if !msg.kernel_event_info.object_name.trim().is_empty() {
                    parts.push(format!(
                        "Object={}",
                        Self::truncate_detail_value(&msg.kernel_event_info.object_name, 260)
                    ));
                }
            }

            if !msg.extension.trim().is_empty() {
                parts.push(format!(
                    "Extension={}",
                    Self::truncate_detail_value(&msg.extension, 64)
                ));
            }

            if msg.mem_sized_used > 0 {
                parts.push(format!("Bytes={}", msg.mem_sized_used));
            }

            if msg.file_size > 0 {
                parts.push(format!("FileSize={}", msg.file_size));
            }

            if !msg.runtime_features.command_line.trim().is_empty() {
                parts.push(format!(
                    "CommandLine={}",
                    Self::truncate_detail_value(&msg.runtime_features.command_line, 320)
                ));
            }
        } else if !state.command_line.trim().is_empty() {
            parts.push(format!(
                "CommandLine={}",
                Self::truncate_detail_value(&state.command_line, 320)
            ));
        }

        let mut condition_names: Vec<&String> = rule
            .named_conditions
            .keys()
            .filter(|name| Self::rule_condition_satisfied(state, rule, name))
            .collect();
        condition_names.sort();

        let mut condition_summaries = Vec::new();
        for cond_name in condition_names.into_iter().take(6) {
            let mut rendered = cond_name.clone();
            if let Some(values) = Self::rule_condition_values(state, rule, cond_name) {
                let mut sorted_values: Vec<String> = values
                    .iter()
                    .filter_map(|value| {
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(Self::truncate_detail_value(trimmed, 120))
                        }
                    })
                    .collect();
                sorted_values.sort();

                if !sorted_values.is_empty() {
                    if sorted_values.len() > 3 {
                        sorted_values.truncate(3);
                        rendered = format!("{}=[{}; ...]", cond_name, sorted_values.join("; "));
                    } else {
                        rendered = format!("{}=[{}]", cond_name, sorted_values.join("; "));
                    }
                }
            }
            condition_summaries.push(rendered);
        }

        if !condition_summaries.is_empty() {
            parts.push(format!(
                "MatchedConditions={}",
                condition_summaries.join(" | ")
            ));
        }

        if !state.recent_kernel_api_events.is_empty() {
            let events = state
                .recent_kernel_api_events
                .iter()
                .rev()
                .take(8)
                .map(|entry| Self::truncate_detail_value(entry, 140))
                .collect::<Vec<_>>();
            if !events.is_empty() {
                parts.push(format!("RecentKernelApiEvents={}", events.join(" || ")));
            }
        }

        if !state.recent_hook_errors.is_empty() {
            let hook_errors = state
                .recent_hook_errors
                .iter()
                .rev()
                .take(8)
                .map(|entry| {
                    Self::truncate_detail_value(
                        &format!(
                            "{} status=0x{:08X}({}) raw=0x{:X} src={} tgt={}",
                            entry.api_name,
                            entry.operation_status as u32,
                            hook_status_name(entry.operation_status),
                            entry.raw_event_type,
                            entry.source_pid,
                            entry.target_pid
                        ),
                        160,
                    )
                })
                .collect::<Vec<_>>();
            if !hook_errors.is_empty() {
                parts.push(format!("RecentHookErrors={}", hook_errors.join(" || ")));
            }
        }

        if let Some(target) = Self::build_rule_remediation_target_path(rule, state) {
            parts.push(format!("RemediationTarget={}", target.display()));
        }

        if !state.rootkit_findings.is_empty() {
            let summary = state
                .rootkit_findings
                .iter()
                .take(2)
                .map(|finding| Self::truncate_detail_value(&finding.description, 140))
                .collect::<Vec<_>>()
                .join(" | ");
            if !summary.is_empty() {
                parts.push(format!("RootkitTelemetry={}", summary));
            }
        }

        parts.join(" | ")
    }

    fn is_file_condition_group(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.file_paths.is_empty()
            || !cond_group.file_extensions.is_empty()
            || !cond_group.file_operations.is_empty()
            || !cond_group.staging_paths.is_empty()
            || !cond_group.browsed_paths.is_empty()
            || !cond_group.sensitive_paths.is_empty()
            || !cond_group.persistence_locations.is_empty()
            || cond_group.detect_extension_changes
            || cond_group.detect_non_whitelisted_extensions
            || cond_group.detect_known_to_unknown_extension_change
    }

    fn prune_recent_written_payloads(state: &mut ProcessBehaviorState, now: SystemTime) {
        state.recent_written_payloads.retain(|_, seen_at| {
            now.duration_since(*seen_at)
                .map(|age| age.as_secs() <= RECENT_WRITTEN_PAYLOAD_RETENTION_SECS)
                .unwrap_or(true)
        });

        if state.recent_written_payloads.len() <= RECENT_WRITTEN_PAYLOAD_MAX_TRACKED {
            return;
        }

        let mut entries: Vec<(String, SystemTime)> = state
            .recent_written_payloads
            .iter()
            .map(|(path, seen_at)| (path.clone(), *seen_at))
            .collect();
        entries.sort_by_key(|(_, seen_at)| *seen_at);

        let to_remove = entries
            .len()
            .saturating_sub(RECENT_WRITTEN_PAYLOAD_MAX_TRACKED);
        for (path, _) in entries.into_iter().take(to_remove) {
            state.recent_written_payloads.remove(&path);
        }
    }

    fn remember_recent_written_payload(
        state: &mut ProcessBehaviorState,
        filepath: &str,
        event_extension: &str,
        file_change: Option<FileChangeInfo>,
        irp_op: &IrpMajorOp,
        is_directory_event: bool,
        now: SystemTime,
    ) {
        Self::prune_recent_written_payloads(state, now);

        if filepath.is_empty() || is_directory_event {
            return;
        }

        let normalized_path = normalize_path_separators(&filepath.to_lowercase());

        if is_delete_like_file_operation(irp_op, file_change) {
            state.recent_written_payloads.remove(&normalized_path);
            return;
        }

        if !is_launchable_payload_extension(event_extension)
            || !is_write_or_create_like_file_operation(irp_op, file_change)
        {
            return;
        }

        state.recent_written_payloads.insert(normalized_path, now);
        Self::prune_recent_written_payloads(state, now);
    }

    fn recent_payload_path_matches_filters(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        cond_group: &NamedConditionGroup,
        candidate_path: &str,
    ) -> bool {
        let has_path_filters = !cond_group.file_paths.is_empty()
            || !cond_group.staging_paths.is_empty()
            || !cond_group.browsed_paths.is_empty()
            || !cond_group.sensitive_paths.is_empty()
            || !cond_group.persistence_locations.is_empty();

        if has_path_filters {
            let path_variants = build_path_variants(candidate_path, candidate_path);
            let path_ok = cond_group
                .file_paths
                .iter()
                .chain(cond_group.staging_paths.iter())
                .chain(cond_group.browsed_paths.iter())
                .chain(cond_group.sensitive_paths.iter())
                .chain(cond_group.persistence_locations.iter())
                .any(|pattern| {
                    let pattern_norm = pattern.replace("\\", "/");
                    let pattern_norm_stripped = strip_drive_prefix(&pattern_norm);
                    path_variants.iter().any(|variant| {
                        Self::matches_pattern_internal(cache, &pattern_norm, variant)
                            || Self::matches_pattern_internal(
                                cache,
                                &pattern_norm_stripped,
                                variant,
                            )
                    })
                });
            if !path_ok {
                return false;
            }
        }

        if cond_group.file_extensions.is_empty() {
            return true;
        }

        let ext = extract_path_extension(candidate_path);
        if ext.is_empty() {
            return false;
        }
        let ext_with_dot = format!(".{}", ext);
        cond_group
            .file_extensions
            .iter()
            .any(|pattern| Self::extension_pattern_matches(cache, pattern, &ext, &ext_with_dot))
    }

    fn match_recently_written_payload_launch(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        state: &mut ProcessBehaviorState,
        cond_group: &NamedConditionGroup,
        child_path: &str,
        child_cmdline: &str,
        now: SystemTime,
    ) -> Option<String> {
        Self::prune_recent_written_payloads(state, now);
        if state.recent_written_payloads.is_empty() {
            return None;
        }

        let current_image = canonical_behavior_path(&state.exe_path.to_string_lossy());
        let child_image = canonical_behavior_path(child_path);
        let child_cmdline_norm = normalize_path_separators(&child_cmdline.to_lowercase());

        let mut candidates: Vec<String> = state.recent_written_payloads.keys().cloned().collect();
        candidates.sort();

        for candidate in candidates {
            let candidate_norm = normalize_path_separators(&candidate.to_lowercase());
            let candidate_canon = canonical_behavior_path(&candidate_norm);
            if candidate_canon.is_empty() || candidate_canon == current_image {
                continue;
            }
            if !Self::recent_payload_path_matches_filters(cache, cond_group, &candidate_norm) {
                continue;
            }

            let direct_child_match = !child_image.is_empty() && child_image == candidate_canon;
            let cmdline_match = !child_cmdline_norm.is_empty()
                && cmdline_contains_candidate_path(&child_cmdline_norm, &candidate_norm);

            if direct_child_match || cmdline_match {
                return Some(candidate_norm);
            }
        }

        None
    }

    fn is_probable_artifact_path(value: &str) -> bool {
        let trimmed = value.trim();
        !trimmed.is_empty()
            && !trimmed.starts_with("event:")
            && !trimmed.starts_with("fileid:")
            && (trimmed.contains('/') || trimmed.contains('\\'))
    }

    fn extract_probable_artifact_path(value: &str) -> Option<String> {
        let trimmed = value.trim().trim_matches('"');
        if Self::is_probable_artifact_path(trimmed) {
            return Some(trimmed.to_string());
        }

        let lower = trimmed.to_ascii_lowercase();
        for marker in [r"\device\", r"\\?\", r"\??\", r"\efi\", r"\boot\bcd"] {
            if let Some(idx) = lower.find(marker) {
                let candidate = trimmed[idx..].trim().trim_matches('"');
                if Self::is_probable_artifact_path(candidate) {
                    return Some(candidate.to_string());
                }
            }
        }

        let chars: Vec<(usize, char)> = trimmed.char_indices().collect();
        for window in chars.windows(3) {
            let (idx0, c0) = window[0];
            let (_, c1) = window[1];
            let (_, c2) = window[2];
            if c0.is_ascii_alphabetic() && c1 == ':' && (c2 == '\\' || c2 == '/') {
                let candidate = trimmed[idx0..].trim().trim_matches('"');
                if Self::is_probable_artifact_path(candidate) {
                    return Some(candidate.to_string());
                }
            }
        }

        None
    }

    fn build_rule_remediation_target_path(
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
    ) -> Option<PathBuf> {
        let exe_path = state
            .exe_path
            .to_string_lossy()
            .to_ascii_lowercase()
            .replace('\\', "/");
        let mut best_match: Option<(i32, String)> = None;

        for (cond_name, cond_group) in &rule.named_conditions {
            if !Self::rule_condition_satisfied(state, rule, cond_name)
                || !Self::is_file_condition_group(cond_group)
            {
                continue;
            }

            let Some(values) = Self::rule_condition_values(state, rule, cond_name) else {
                continue;
            };

            let mut sorted_values: Vec<String> = values.iter().cloned().collect();
            sorted_values.sort();

            for value in sorted_values {
                if !Self::is_probable_artifact_path(&value) {
                    continue;
                }

                let extracted = match Self::extract_probable_artifact_path(&value) {
                    Some(path) => path,
                    None => continue,
                };
                let normalized = extracted.to_ascii_lowercase().replace('\\', "/");
                let mut score = 0i32;

                if normalized.ends_with(".efi") {
                    score += 60;
                }
                if normalized.ends_with(".sys") {
                    score += 40;
                }
                if normalized.contains("/efi/") {
                    score += 30;
                }
                if normalized.contains("/windows/system32/drivers/") {
                    score += 20;
                }
                if normalized != exe_path {
                    score += 5;
                }

                let should_replace = match &best_match {
                    Some((best_score, best_value)) => {
                        score > *best_score || (score == *best_score && extracted < *best_value)
                    }
                    None => true,
                };

                if should_replace {
                    best_match = Some((score, extracted));
                }
            }
        }

        if best_match.is_none() {
            for finding in &state.rootkit_findings {
                let Some(extracted) = Self::extract_probable_artifact_path(&finding.description)
                else {
                    continue;
                };

                let normalized = extracted.to_ascii_lowercase().replace('\\', "/");
                let mut score = 10i32;

                if normalized.ends_with(".efi") {
                    score += 60;
                }
                if normalized.ends_with("bcd") {
                    score += 45;
                }
                if normalized.contains("/efi/") {
                    score += 30;
                }
                if normalized.contains("/microsoft/boot/") || normalized.contains("/efi/boot/") {
                    score += 20;
                }

                let should_replace = match &best_match {
                    Some((best_score, best_value)) => {
                        score > *best_score || (score == *best_score && extracted < *best_value)
                    }
                    None => true,
                };

                if should_replace {
                    best_match = Some((score, extracted));
                }
            }
        }

        best_match.map(|(_, value)| PathBuf::from(value.replace('/', "\\")))
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn build_firewall_hips_target(
        &self,
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
    ) -> String {
        let alert_kind = Self::detect_firewall_hips_alert_kind(rule, state);

        if alert_kind == "registry" {
            for (cond_name, cond_group) in &rule.named_conditions {
                if !Self::rule_condition_satisfied(state, rule, cond_name)
                    || !Self::is_registry_condition_group(cond_group)
                {
                    continue;
                }

                if let Some(values) = Self::rule_condition_values(state, rule, cond_name)
                    && let Some(value) = Self::first_real_match_value(values)
                {
                    return value;
                }

                if let Some(pattern) = cond_group
                    .registry_keys
                    .first()
                    .or_else(|| cond_group.autorun_keys.first())
                    .or_else(|| cond_group.registry_values.first())
                {
                    return pattern.clone();
                }
            }
        }

        for cond_name in rule.named_conditions.keys() {
            if let Some(values) = Self::rule_condition_values(state, rule, cond_name)
                && let Some(value) = Self::first_real_match_value(values)
            {
                return value;
            }
        }

        if !state.command_line.trim().is_empty() {
            return state.command_line.clone();
        }

        let exe_path = state.exe_path.to_string_lossy().to_string();
        if !exe_path.trim().is_empty() && exe_path != "UNKNOWN" {
            exe_path
        } else {
            rule.name.clone()
        }
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn build_firewall_hips_reason(rule: &BehaviorRule) -> String {
        let description = rule.description.trim();
        if description.is_empty() {
            format!("Owlyshield rule '{}' matched.", rule.name)
        } else {
            format!("Owlyshield rule '{}' matched: {}", rule.name, description)
        }
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn build_firewall_hips_request_signature(
        gid: u64,
        pid: u32,
        rule_name: &str,
        alert_kind: &str,
        exe_path: &str,
        target: &str,
    ) -> String {
        format!(
            "gid:{}|pid:{}|rule:{}|kind:{}|exe:{}|target:{}",
            gid,
            pid,
            rule_name.to_ascii_lowercase(),
            alert_kind.to_ascii_lowercase(),
            exe_path.to_ascii_lowercase(),
            target.to_ascii_lowercase()
        )
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn build_firewall_hips_allow_signature(
        rule_name: &str,
        alert_kind: &str,
        exe_path: &str,
        target: &str,
    ) -> String {
        format!(
            "rule:{}|kind:{}|exe:{}|target:{}",
            rule_name.to_ascii_lowercase(),
            alert_kind.to_ascii_lowercase(),
            exe_path.to_ascii_lowercase(),
            target.to_ascii_lowercase()
        )
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn build_firewall_hips_request_id(gid: u64, pid: u32, rule_name: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        format!(
            "{}-{}-{}-{}",
            gid,
            pid,
            now,
            rule_name
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .take(24)
                .collect::<String>()
        )
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn send_firewall_hips_prompt(
        &self,
        request_id: &str,
        pid: u32,
        app_name: &str,
        exe_path: &str,
        alert_kind: &str,
        target: &str,
        reason: &str,
    ) -> bool {
        use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
            FlushFileBuffers, OPEN_EXISTING, WriteFile,
        };
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        use windows::core::PCWSTR;

        const PIPE: &str = r"\\.\pipe\HydraHipEvent";
        const CONNECT_TIMEOUT_MS: u32 = 750;
        const CONNECT_ATTEMPTS: usize = 4;

        // Convert to UTF-16 for Unicode Windows API
        let mut pipe_name_wide: Vec<u16> = PIPE.encode_utf16().collect();
        pipe_name_wide.push(0); // Null terminator
        let pcwstr = PCWSTR(pipe_name_wide.as_ptr());

        let message = format!(
            "HIPS_ASK:{}|{}|{}|{}|{}|{}|{}\n",
            Self::sanitize_firewall_hips_field(request_id),
            pid,
            Self::sanitize_firewall_hips_field(app_name),
            Self::sanitize_firewall_hips_field(exe_path),
            Self::sanitize_firewall_hips_field(alert_kind),
            Self::sanitize_firewall_hips_field(target),
            Self::sanitize_firewall_hips_field(reason),
        );
        let message_bytes = message.as_bytes();

        let mut last_error = String::new();
        for attempt in 0..CONNECT_ATTEMPTS {
            let wait_ok: BOOL = unsafe { WaitNamedPipeW(pcwstr, CONNECT_TIMEOUT_MS) };
            if !wait_ok.as_bool() {
                last_error = format!("WaitNamedPipeW(GetLastError={:?})", unsafe {
                    GetLastError()
                });
            } else {
                let pipe_handle = match unsafe {
                    CreateFileW(
                        pcwstr,
                        FILE_GENERIC_WRITE.0,
                        FILE_SHARE_NONE,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        HANDLE::default(),
                    )
                } {
                    Ok(handle) if !handle.is_invalid() => handle,
                    Ok(_) => {
                        last_error =
                            "CreateFileW returned an invalid HydraHipEvent handle".to_string();
                        if attempt + 1 < CONNECT_ATTEMPTS {
                            std::thread::sleep(std::time::Duration::from_millis(120));
                        }
                        continue;
                    }
                    Err(err) => {
                        last_error = format!("CreateFileW failed: {:?}", err);
                        if attempt + 1 < CONNECT_ATTEMPTS {
                            std::thread::sleep(std::time::Duration::from_millis(120));
                        }
                        continue;
                    }
                };

                let mut bytes_written: u32 = 0;
                let ok: BOOL = unsafe {
                    WriteFile(
                        pipe_handle,
                        Some(message_bytes),
                        Some(&mut bytes_written as *mut u32),
                        None,
                    )
                };

                unsafe {
                    let _ = FlushFileBuffers(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                }

                if ok.as_bool() && bytes_written as usize == message_bytes.len() {
                    Logging::info(&format!(
                        "[Owlyshield HIPS] Prompted firewall GUI for request {} (PID {}, {} bytes)",
                        request_id, pid, bytes_written
                    ));
                    return true;
                }

                last_error = if ok.as_bool() {
                    format!(
                        "WriteFile wrote {} of {} bytes",
                        bytes_written,
                        message_bytes.len()
                    )
                } else {
                    format!("WriteFile(GetLastError={:?})", unsafe { GetLastError() })
                };
            }

            if attempt + 1 < CONNECT_ATTEMPTS {
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
        }

        Logging::warning(&format!(
            "[Owlyshield HIPS] Failed to connect/write HydraHipEvent prompt for request {} after {} attempts: {}",
            request_id, CONNECT_ATTEMPTS, last_error
        ));
        false
    }

    #[cfg(all(target_os = "windows", feature = "firewall"))]
    fn resolve_firewall_hips_prompt(
        &self,
        gid: u64,
        state: &ProcessBehaviorState,
        rule: &BehaviorRule,
    ) -> FirewallHipsPromptOutcome {
        let exe_path = state.exe_path.to_string_lossy().to_string();
        let alert_kind = Self::detect_firewall_hips_alert_kind(rule, state);
        let target = self.build_firewall_hips_target(rule, state);
        let request_signature = Self::build_firewall_hips_request_signature(
            gid, state.pid, &rule.name, alert_kind, &exe_path, &target,
        );
        let allow_signature =
            Self::build_firewall_hips_allow_signature(&rule.name, alert_kind, &exe_path, &target);

        if self
            .firewall_hips_allow_always
            .read()
            .unwrap()
            .contains(&allow_signature)
        {
            return FirewallHipsPromptOutcome::Allowed;
        }

        if self
            .firewall_hips_allow_once
            .write()
            .unwrap()
            .remove(&request_signature)
        {
            return FirewallHipsPromptOutcome::Allowed;
        }

        let existing_prompt = self
            .firewall_hips_pending_prompts
            .read()
            .unwrap()
            .get(&request_signature)
            .cloned();

        if let Some(prompt) = existing_prompt {
            let decision = self
                .firewall_hips_decisions
                .write()
                .unwrap()
                .remove(&prompt.request_id);

            if let Some(decision) = decision {
                self.firewall_hips_pending_prompts
                    .write()
                    .unwrap()
                    .remove(&request_signature);

                match decision {
                    FirewallHipsDecision::AllowAlways => {
                        self.firewall_hips_allow_always
                            .write()
                            .unwrap()
                            .insert(prompt.allow_signature);
                        FirewallHipsPromptOutcome::Allowed
                    }
                    FirewallHipsDecision::AllowOnce => {
                        self.firewall_hips_allow_once
                            .write()
                            .unwrap()
                            .insert(prompt.request_signature);
                        FirewallHipsPromptOutcome::Allowed
                    }
                    FirewallHipsDecision::Deny => FirewallHipsPromptOutcome::Deny,
                    FirewallHipsDecision::Quarantine => FirewallHipsPromptOutcome::Quarantine,
                    FirewallHipsDecision::Block => FirewallHipsPromptOutcome::Block,
                }
            } else {
                FirewallHipsPromptOutcome::Pending
            }
        } else {
            let request_id = Self::build_firewall_hips_request_id(gid, state.pid, &rule.name);
            let app_name = if !state.app_name.trim().is_empty() {
                state.app_name.clone()
            } else {
                "unknown".to_string()
            };
            let reason = Self::build_firewall_hips_reason(rule);

            if self.send_firewall_hips_prompt(
                &request_id,
                state.pid,
                &app_name,
                &exe_path,
                alert_kind,
                &target,
                &reason,
            ) {
                self.firewall_hips_pending_prompts.write().unwrap().insert(
                    request_signature.clone(),
                    FirewallHipsPromptState {
                        request_id,
                        request_signature,
                        allow_signature,
                    },
                );
                FirewallHipsPromptOutcome::Pending
            } else {
                Logging::warning(&format!(
                    "[Owlyshield HIPS] Keeping '{}' pending because the firewall GUI prompt could not be delivered yet",
                    rule.name
                ));
                FirewallHipsPromptOutcome::Pending
            }
        }
    }

    #[cfg(not(all(target_os = "windows", feature = "firewall")))]
    fn resolve_firewall_hips_prompt(
        &self,
        _gid: u64,
        _state: &ProcessBehaviorState,
        _rule: &BehaviorRule,
    ) -> FirewallHipsPromptOutcome {
        FirewallHipsPromptOutcome::Allowed
    }

    #[allow(dead_code)]
    fn safe_pattern_match(text: &str, pattern: &str) -> bool {
        let text_lc = text.to_lowercase();
        let pattern_lc = pattern.to_lowercase();

        if text_lc.is_empty() || pattern_lc.is_empty() || text_lc == "unknown" {
            return false;
        }

        text_lc.contains(&pattern_lc) || pattern_lc.contains(&text_lc)
    }

    fn normalize_registry_text(text: &str) -> String {
        let normalized = normalize_path_separators(
            &text.trim().trim_matches(char::from(0)).to_ascii_lowercase(),
        );

        normalized
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                if segment.starts_with("controlset")
                    && segment["controlset".len()..]
                        .chars()
                        .all(|ch| ch.is_ascii_digit())
                {
                    "currentcontrolset".to_string()
                } else {
                    segment.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    fn push_registry_alias(aliases: &mut HashSet<String>, prefix: &str, remainder: &str) {
        let normalized_prefix = prefix.trim_matches('/').to_string();
        let normalized_remainder = remainder.trim_matches('/');

        if normalized_remainder.is_empty() {
            aliases.insert(normalized_prefix);
        } else {
            aliases.insert(format!("{}/{}", normalized_prefix, normalized_remainder));
        }
    }

    fn registry_match_aliases(text: &str) -> Vec<String> {
        let normalized = Self::normalize_registry_text(text);
        let trimmed = normalized.trim_matches('/').to_string();
        let mut aliases = HashSet::new();

        if !trimmed.is_empty() {
            aliases.insert(trimmed.clone());
        }

        let add_classes_root_alias = |aliases: &mut HashSet<String>, remainder: &str| {
            Self::push_registry_alias(aliases, "hkcr", remainder);
        };

        if let Some(remainder) = trimmed.strip_prefix("hkey_local_machine/") {
            Self::push_registry_alias(&mut aliases, "hklm", remainder);
        } else if trimmed == "hkey_local_machine" {
            aliases.insert("hklm".to_string());
        }

        if let Some(remainder) = trimmed.strip_prefix("hkey_current_user/") {
            Self::push_registry_alias(&mut aliases, "hkcu", remainder);
        } else if trimmed == "hkey_current_user" {
            aliases.insert("hkcu".to_string());
        }

        if let Some(remainder) = trimmed.strip_prefix("hkey_users/") {
            Self::push_registry_alias(&mut aliases, "hku", remainder);
        } else if trimmed == "hkey_users" {
            aliases.insert("hku".to_string());
        }

        if let Some(remainder) = trimmed.strip_prefix("hkey_classes_root/") {
            add_classes_root_alias(&mut aliases, remainder);
        } else if trimmed == "hkey_classes_root" {
            aliases.insert("hkcr".to_string());
        }

        if let Some(remainder) = trimmed.strip_prefix("hkey_current_config/") {
            Self::push_registry_alias(&mut aliases, "hkcc", remainder);
        } else if trimmed == "hkey_current_config" {
            aliases.insert("hkcc".to_string());
        }

        if let Some(remainder) = trimmed.strip_prefix("registry/machine/") {
            Self::push_registry_alias(&mut aliases, "hklm", remainder);

            if let Some(classes_remainder) = remainder.strip_prefix("software/classes/") {
                add_classes_root_alias(&mut aliases, classes_remainder);
            } else if remainder == "software/classes" {
                aliases.insert("hkcr".to_string());
            }

            if let Some(config_remainder) =
                remainder.strip_prefix("system/currentcontrolset/hardware profiles/current/")
            {
                Self::push_registry_alias(&mut aliases, "hkcc", config_remainder);
            } else if remainder == "system/currentcontrolset/hardware profiles/current" {
                aliases.insert("hkcc".to_string());
            }
        }

        if let Some(remainder) = trimmed.strip_prefix("registry/user/") {
            if let Some((sid, rest)) = remainder.split_once('/') {
                Self::push_registry_alias(&mut aliases, "hku", &format!("{}/{}", sid, rest));

                if sid.ends_with("_classes") {
                    add_classes_root_alias(&mut aliases, rest);
                } else {
                    Self::push_registry_alias(&mut aliases, "hkcu", rest);
                }
            } else {
                Self::push_registry_alias(&mut aliases, "hku", remainder);
            }
        }

        if let Some(remainder) = trimmed.strip_prefix("hklm/software/classes/") {
            add_classes_root_alias(&mut aliases, remainder);
        } else if trimmed == "hklm/software/classes" {
            aliases.insert("hkcr".to_string());
        }

        if let Some(remainder) = trimmed.strip_prefix("hkcu/software/classes/") {
            add_classes_root_alias(&mut aliases, remainder);
        } else if trimmed == "hkcu/software/classes" {
            aliases.insert("hkcr".to_string());
        }

        let mut sorted_aliases: Vec<String> = aliases.into_iter().collect();
        sorted_aliases.sort();
        sorted_aliases
    }

    fn registry_pattern_matches(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        pattern: &str,
        filepath: &str,
    ) -> bool {
        let pattern_aliases = Self::registry_match_aliases(pattern);
        let filepath_aliases = Self::registry_match_aliases(filepath);

        for pattern_alias in &pattern_aliases {
            for filepath_alias in &filepath_aliases {
                if Self::matches_pattern_internal(cache, pattern_alias, filepath_alias) {
                    return true;
                }
            }
        }

        false
    }

    fn registry_value_pattern_matches(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        pattern: &str,
        filepath: &str,
    ) -> bool {
        let pat = pattern
            .trim()
            .trim_matches('"')
            .trim_matches(char::from(0))
            .to_ascii_lowercase()
            .replace("\\", "/");
        if pat.is_empty() {
            return false;
        }

        let filepath_aliases = Self::registry_match_aliases(filepath);
        for filepath_alias in &filepath_aliases {
            let trimmed = filepath_alias.trim_matches('/');
            let terminal = trimmed
                .rsplit('/')
                .next()
                .unwrap_or(trimmed)
                .split(" (")
                .next()
                .unwrap_or(trimmed)
                .trim();
            let has_glob = pat.contains('*') || pat.contains('?');
            let is_explicit_regex =
                pat.starts_with("(?") || pat.starts_with('^') || pat.ends_with('$');
            let is_path_pattern = pat.contains('/');
            let is_simple_value_name = !has_glob && !is_explicit_regex && !is_path_pattern;

            if !terminal.is_empty() {
                if is_simple_value_name {
                    if terminal.eq_ignore_ascii_case(&pat) {
                        return true;
                    }
                } else if Self::matches_pattern_internal(cache, &pat, terminal) {
                    return true;
                }
            }

            if !is_simple_value_name && Self::matches_pattern_internal(cache, &pat, trimmed) {
                return true;
            }

            if !is_simple_value_name && !pat.contains('/') {
                let suffix_pattern = format!("*/{}", pat);
                if Self::matches_pattern_internal(cache, &suffix_pattern, trimmed) {
                    return true;
                }
            }
        }

        false
    }

    fn registry_op_matches(
        cond_group: &NamedConditionGroup,
        msg: &IOMessage,
        irp_op: &IrpMajorOp,
    ) -> bool {
        if cond_group.registry_operations.is_empty() {
            return true;
        }
        if *irp_op != IrpMajorOp::IrpRegistry {
            return false;
        }

        let change = FromPrimitive::from_u8(msg.file_change);
        let aliases = Self::registry_operation_aliases(change);
        if aliases.is_empty() {
            return false;
        }

        cond_group.registry_operations.iter().any(|required| {
            let required = required.trim().to_ascii_lowercase();
            aliases.iter().any(|alias| *alias == required)
        })
    }

    fn extension_pattern_matches(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        pattern: &str,
        ext_without_dot: &str,
        ext_with_dot: &str,
    ) -> bool {
        let pat = pattern
            .trim()
            .trim_matches('"')
            .trim_matches(char::from(0))
            .to_lowercase();
        if pat.is_empty() {
            return false;
        }

        if pat.contains('*') || pat.contains('?') {
            return Self::matches_pattern_internal(cache, &pat, ext_with_dot)
                || Self::matches_pattern_internal(cache, &pat, ext_without_dot);
        }

        let pat_without_dot = pat.trim_start_matches('.');
        if pat_without_dot.is_empty() {
            return false;
        }
        let pat_with_dot = format!(".{}", pat_without_dot);
        ext_without_dot == pat_without_dot || ext_with_dot == pat_with_dot
    }

    fn is_extension_whitelisted(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        default_whitelist: &HashSet<String>,
        cond_group: &NamedConditionGroup,
        ext_without_dot: &str,
        ext_with_dot: &str,
    ) -> bool {
        if ext_without_dot.is_empty() {
            return false;
        }

        if cond_group.extension_whitelist.is_empty() {
            return default_whitelist.contains(ext_without_dot);
        }

        cond_group
            .extension_whitelist
            .iter()
            .any(|p| Self::extension_pattern_matches(cache, p, ext_without_dot, ext_with_dot))
    }

    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        Logging::info(&format!(
            "[Owlyshield] Starting behavior rule load from {:?}",
            path
        ));
        let rules = self.load_rules_recursive(path, 0)?;
        let count = rules.len();

        if count == 0 {
            let msg = format!(
                "[BehaviorEngine] CRITICAL: No rules were loaded from {:?}.                 The engine will run with zero detection capability.                 Check that rule files exist, are valid YAML, and that all string values                 (file paths, env vars like %TEMP%, API names like dll!Fn, extensions like .zip)                 are enclosed in double quotes.",
                path
            );
            Self::log_rule_load_error_once(path, "no-rules-loaded", msg.clone());
            return Err(msg.into());
        }

        self.rules = rules;
        Logging::info(&format!(
            "[Owlyshield] Successfully loaded {} behavior rules from {:?}",
            count, path
        ));
        Ok(())
    }

    fn log_rule_load_error_once(path: &Path, key_suffix: &str, message: String) {
        let key = format!(
            "{}|{}|{}",
            path.display(),
            rule_file_fingerprint(path),
            key_suffix
        );
        if should_log_rule_load_error(&key) {
            Logging::error(&message);
        }
    }

    /// Scan raw YAML text for common authoring mistakes that cause silent parse failures:
    ///   - Unquoted environment-variable expansions  (%VAR%)
    ///   - Bare YAML tag markers used as values      (!something)
    ///   - Unquoted file extensions at line start    (- .ext)
    ///
    /// Returns a list of human-readable warnings, one per suspicious line.
    fn validate_yaml_content(path: &Path, content: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let file = path.display();
        let mut in_block_scalar = false;
        let mut block_scalar_indent: usize = 0;

        for (idx, line) in content.lines().enumerate() {
            let lineno = idx + 1;
            let trimmed = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Detect entry into a block scalar (| or >) — e.g. description, false_positives prose.
            // Any content inside a block scalar is free text and must not be linted.
            if trimmed.ends_with('|')
                || trimmed.ends_with('>')
                || trimmed.ends_with("|+")
                || trimmed.ends_with(">+")
                || trimmed.ends_with("|-")
                || trimmed.ends_with(">-")
            {
                in_block_scalar = true;
                block_scalar_indent = indent;
                continue;
            }

            // Exit block scalar when we see a non-empty line at or below the
            // indentation level of the key that opened the block.
            if in_block_scalar {
                if trimmed.is_empty() {
                    continue; // blank lines are allowed inside block scalars
                }
                if indent <= block_scalar_indent {
                    in_block_scalar = false;
                    // Fall through — this line is real YAML, lint it below.
                } else {
                    continue; // still inside block scalar body, skip
                }
            }

            // Skip comments and blank lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Only lint YAML list items — lines whose first non-space content
            // starts with "- ". Key lines (description:, tags:, etc.) and
            // flow-sequence content are safe from the unquoted-value problem.
            if !trimmed.starts_with("- ") {
                continue;
            }

            let after_dash = &trimmed["- ".len()..];

            // If the list item is an inline mapping (e.g. `- pattern: "value"`
            // or `- name: foo`), extract only the scalar value after the ": ".
            // The key itself is never problematic; only the unquoted value is.
            let value_part: &str = if let Some(colon_pos) = after_dash.find(": ") {
                after_dash[colon_pos + 2..].trim()
            } else {
                after_dash
            };

            // Already quoted — nothing to flag regardless of content.
            if value_part.starts_with('"') || value_part.starts_with('\'') {
                continue;
            }

            // Unquoted %ENV_VAR% — serde_yaml parses % as a plain scalar but
            // some parser versions silently drop the document when % appears
            // in an unquoted list value.
            if value_part.contains('%') {
                warnings.push(format!(
                    "{}:{}: unquoted list value containing '%' (env-var?): `{}` — wrap in double quotes",
                    file, lineno, trimmed
                ));
            }

            // Bare !tag — YAML treats `!foo` as a local tag; `dll!FnName` on a
            // list value causes a tag-parse error that discards the document.
            if value_part.contains('!') {
                warnings.push(format!(
                    "{}:{}: unquoted list value containing '!' (YAML tag marker?): `{}` — wrap in double quotes",
                    file, lineno, trimmed
                ));
            }

            // Unquoted file extension (e.g. `- .zip`) — flagged for style
            // consistency so all list values in rule files are quoted uniformly.
            if value_part.starts_with('.')
                && value_part.len() <= 6
                && value_part.chars().skip(1).all(|c| c.is_alphanumeric())
            {
                warnings.push(format!(
                    "{}:{}: unquoted list value with file extension: `{}` — wrap in double quotes",
                    file, lineno, trimmed
                ));
            }
        }

        warnings
    }

    /// Extract all unique APIs mentioned across all rules, stages, and named conditions
    pub fn get_all_monitored_apis(&self) -> HashSet<String> {
        fn collect_condition_apis(cond: &RuleCondition, all_apis: &mut HashSet<String>) {
            match cond {
                RuleCondition::Api {
                    functions,
                    arguments: _,
                    module_pattern,
                } => {
                    for name_pattern in functions {
                        if module_pattern.is_empty() {
                            all_apis.insert(name_pattern.clone());
                        } else {
                            all_apis.insert(format!("{}!{}", module_pattern, name_pattern));
                        }
                    }
                }
                RuleCondition::MultiCondition { conditions, .. } => {
                    for subcondition in conditions {
                        collect_condition_apis(subcondition, all_apis);
                    }
                }
                _ => {}
            }
        }

        let mut all_apis = HashSet::new();

        for rule in &self.rules {
            // 1. Rule-level monitored_apis
            for api in &rule.monitored_apis {
                all_apis.insert(api.clone());
            }

            // 2. Named conditions
            for cond_group in rule.named_conditions.values() {
                for api in &cond_group.apis {
                    all_apis.insert(api.clone());
                }
                for api in &cond_group.scheduled_task_apis {
                    all_apis.insert(api.clone());
                }
                for api in &cond_group.anti_debug_apis {
                    all_apis.insert(api.clone());
                }
                for api in &cond_group.anti_vm_apis {
                    all_apis.insert(api.clone());
                }
            }

            // 3. Stage-level conditions
            for stage in &rule.stages {
                for cond in &stage.conditions {
                    collect_condition_apis(cond, &mut all_apis);
                }
            }
        }

        all_apis
    }

    fn load_rules_recursive(
        &self,
        path: &Path,
        depth: u32,
    ) -> Result<Vec<BehaviorRule>, Box<dyn std::error::Error>> {
        if depth > 20 {
            Logging::error(&format!(
                "[BehaviorEngine] CRITICAL: Max recursion depth (20) reached! Possible circular include: {:?}",
                path
            ));
            return Ok(Vec::new());
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                Logging::error(&format!(
                    "[BehaviorEngine] Failed to read rule file {:?}: {}",
                    path, e
                ));
                return Err(Box::new(e));
            }
        };

        Logging::debug(&format!(
            "[BehaviorEngine] Parsing file: {:?} (depth {})",
            path, depth
        ));
        let mut rules = Vec::new();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        // First, handle !include directives
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("!include ") {
                let include_part = if trimmed.starts_with("- ") {
                    trimmed.strip_prefix("- ").unwrap_or(trimmed).trim()
                } else {
                    trimmed
                };

                if let Some(include_path_str) = include_part.strip_prefix("!include ") {
                    let include_path_str = include_path_str.trim();
                    let include_path = parent.join(include_path_str);

                    if include_path.exists() {
                        match self.load_rules_recursive(&include_path, depth + 1) {
                            Ok(sub_rules) => {
                                rules.extend(sub_rules);
                            }
                            Err(e) => Logging::warning(&format!(
                                "[EDR] Failed to load include {:?}: {}",
                                include_path.display(),
                                e
                            )),
                        }
                    } else {
                        Logging::warning(&format!(
                            "[EDR] Include path does not exist: {:?}",
                            include_path.display()
                        ));
                    }
                }
            }
        }

        // Now parse the content as YAML, skipping !include lines
        let filtered_content: String = content
            .lines()
            .filter(|line| {
                !line.trim().starts_with("!include") && !line.trim().starts_with("- !include")
            })
            .collect::<Vec<_>>()
            .join("\n");

        if filtered_content.trim().is_empty() {
            return Ok(rules);
        }

        // Pre-validate the YAML content for common authoring mistakes before
        // attempting deserialization — unquoted %VAR% / dll!Fn / .ext values
        // cause serde_yaml to silently discard the whole document.
        let lint_warnings = Self::validate_yaml_content(path, &filtered_content);
        if !lint_warnings.is_empty() {
            Logging::warning(&format!(
                "[BehaviorEngine] YAML lint warnings in {:?} — these may cause rules to be silently skipped:",
                path
            ));
            for w in &lint_warnings {
                Logging::warning(&format!("[BehaviorEngine]   {}", w));
            }
        }

        // Use Deserializer to handle multi-document YAML (separated by ---)
        let deserializer = serde_yaml::Deserializer::from_str(&filtered_content);
        let mut doc_index = 0usize;
        for document in deserializer {
            doc_index += 1;
            let value = match serde_yaml::Value::deserialize(document) {
                Ok(v) => v,
                Err(e) => {
                    let error_text = e.to_string();
                    Self::log_rule_load_error_once(
                        path,
                        &format!("yaml-parse-doc-{}|{}", doc_index, error_text),
                        format!(
                            "[BehaviorEngine] Failed to parse YAML document #{} in {:?}: {}.                         Hint: ensure all file paths, env vars (%VAR%), API names (dll!Fn),                         and file extensions (.zip) are enclosed in double quotes.",
                            doc_index, path, error_text
                        ),
                    );
                    break;
                }
            };

            if let Some(rules_arr) = value.as_sequence() {
                for (rule_idx, rule_val) in rules_arr.iter().enumerate() {
                    match serde_yaml::from_value::<BehaviorRule>(rule_val.clone()) {
                        Ok(mut rule) => {
                            rule.finalize_rich_fields();
                            rules.push(rule);
                        }
                        Err(e) => {
                            let name_hint = rule_val
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("<unnamed>");
                            Logging::error(&format!(
                                "[BehaviorEngine] Failed to deserialize rule #{} ('{}')                                 in document #{} of {:?}: {}.                                 Hint: check for unquoted special characters in string lists.",
                                rule_idx + 1,
                                name_hint,
                                doc_index,
                                path,
                                e
                            ));
                        }
                    }
                }
            } else if value.get("name").is_some() {
                match serde_yaml::from_value::<BehaviorRule>(value.clone()) {
                    Ok(mut rule) => {
                        rule.finalize_rich_fields();
                        rules.push(rule);
                    }
                    Err(e) => {
                        let name_hint = value
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<unnamed>");
                        Logging::error(&format!(
                            "[BehaviorEngine] Failed to deserialize rule ('{}')                             in document #{} of {:?}: {}.                             Hint: check for unquoted special characters in string lists.",
                            name_hint, doc_index, path, e
                        ));
                    }
                }
            }
        }

        Ok(rules)
    }

    fn normalize_api_signature(raw: &str) -> (String, bool) {
        let mut value = normalize_hypervisor_label(raw).to_lowercase();
        let mut has_path = false;
        if value.is_empty() {
            return (value, false);
        }
        if let Some(idx) = value.rfind('!') {
            let (module_part, function_part) = value.split_at(idx);
            let function_name = function_part.trim_start_matches('!');
            has_path = module_part.contains('\\') || module_part.contains('/');
            let module_name = module_part
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(module_part)
                .trim();
            let module_name = module_name.strip_suffix(".dll").unwrap_or(module_name);
            value = format!("{}!{}", module_name, function_name);
        }
        (value, has_path)
    }

    fn matches_u32_list(filter: &[u32], value: u32) -> bool {
        filter.is_empty() || filter.contains(&value)
    }

    fn matches_u64_list(filter: &[u64], value: u64) -> bool {
        filter.is_empty() || filter.contains(&value)
    }

    fn matches_i32_list(filter: &[i32], value: i32) -> bool {
        filter.is_empty() || filter.contains(&value)
    }

    fn matches_u64_range(value: u64, min: Option<u64>, max: Option<u64>) -> bool {
        if let Some(min_v) = min
            && value < min_v
        {
            return false;
        }
        if let Some(max_v) = max
            && value > max_v
        {
            return false;
        }
        true
    }

    fn has_hypervisor_payload_conditions(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.hypervisor_raw_event_types.is_empty()
            || !cond_group.hypervisor_source_pids.is_empty()
            || !cond_group.hypervisor_target_pids.is_empty()
            || !cond_group.hypervisor_raw_arg1_values.is_empty()
            || !cond_group.hypervisor_raw_arg2_values.is_empty()
            || !cond_group.hypervisor_raw_arg3_values.is_empty()
            || !cond_group.hypervisor_raw_arg4_values.is_empty()
            || cond_group.hypervisor_raw_arg1_min.is_some()
            || cond_group.hypervisor_raw_arg1_max.is_some()
            || cond_group.hypervisor_raw_arg2_min.is_some()
            || cond_group.hypervisor_raw_arg2_max.is_some()
            || cond_group.hypervisor_raw_arg3_min.is_some()
            || cond_group.hypervisor_raw_arg3_max.is_some()
            || cond_group.hypervisor_raw_arg4_min.is_some()
            || cond_group.hypervisor_raw_arg4_max.is_some()
            || !cond_group.hypervisor_memory_addresses.is_empty()
            || cond_group.hypervisor_memory_address_min.is_some()
            || cond_group.hypervisor_memory_address_max.is_some()
            || !cond_group.hypervisor_memory_sizes.is_empty()
            || cond_group.hypervisor_memory_size_min.is_some()
            || cond_group.hypervisor_memory_size_max.is_some()
            || !cond_group.hypervisor_memory_protections.is_empty()
            || cond_group.hypervisor_is_executable_memory.is_some()
            || !cond_group.hypervisor_thread_handles.is_empty()
            || !cond_group.hypervisor_thread_start_routines.is_empty()
            || !cond_group.hypervisor_access_masks.is_empty()
            || !cond_group.hypervisor_operation_statuses.is_empty()
    }

    fn has_hook_error_conditions(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.hook_error_statuses.is_empty()
            || !cond_group.hook_error_api_patterns.is_empty()
            || !cond_group.hook_error_raw_event_types.is_empty()
            || cond_group.hook_error_min_count.is_some()
            || cond_group.hook_error_exclude_benign
    }

    fn hook_error_api_matches(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        patterns: &[String],
        api_name: &str,
    ) -> bool {
        if patterns.is_empty() {
            return true;
        }

        let mut names_to_check = vec![api_name.to_string()];
        if let Some(alias) = api_function_alias(api_name) {
            names_to_check.push(alias);
        }

        patterns.iter().any(|required_api| {
            let (required_norm, required_has_path) = Self::normalize_api_signature(required_api);
            names_to_check.iter().any(|available| {
                let (available_norm, available_has_path) = Self::normalize_api_signature(available);
                if required_has_path {
                    available_has_path
                        && Self::matches_pattern_internal(cache, required_api, available)
                } else {
                    Self::matches_pattern_internal(cache, &required_norm, &available_norm)
                }
            })
        })
    }

    fn hook_error_record_matches(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        cond_group: &NamedConditionGroup,
        record: &HookErrorRecord,
        is_acg_enabled: bool,
    ) -> bool {
        if cond_group.hook_error_exclude_benign
            && is_benign_hypervisor_failure_status(record.operation_status, is_acg_enabled)
        {
            return false;
        }

        let status_name = hook_status_name(record.operation_status);
        let status_alias = format!("status:{}", status_name);
        let antitamper_alias = "status:ANTI_TAMPER";

        let api_or_status_matches = Self::hook_error_api_matches(
            cache,
            &cond_group.hook_error_api_patterns,
            &record.api_name,
        ) || (!cond_group.hook_error_api_patterns.is_empty()
            && cond_group.hook_error_api_patterns.iter().any(|pattern| {
                Self::matches_pattern_internal(cache, pattern, status_name)
                    || Self::matches_pattern_internal(cache, pattern, &status_alias)
                    || (is_antitamper_status(record.operation_status)
                        && Self::matches_pattern_internal(cache, pattern, antitamper_alias))
            }));

        (cond_group.hook_error_statuses.is_empty()
            || cond_group
                .hook_error_statuses
                .contains(&(record.operation_status as u32)))
            && Self::matches_u32_list(
                &cond_group.hook_error_raw_event_types,
                record.raw_event_type,
            )
            && api_or_status_matches
    }

    fn matching_hook_error_summary(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        cond_group: &NamedConditionGroup,
        state: &ProcessBehaviorState,
    ) -> Option<String> {
        if !Self::has_hook_error_conditions(cond_group) {
            return None;
        }

        let required = cond_group.hook_error_min_count.unwrap_or(1).max(1);
        let matches: Vec<&HookErrorRecord> = state
            .recent_hook_errors
            .iter()
            .filter(|record| {
                Self::hook_error_record_matches(cache, cond_group, record, state.is_acg_enabled)
            })
            .collect();

        if matches.len() < required {
            return None;
        }

        let latest = matches.last()?;
        Some(format!(
            "hook_error:{}:status=0x{:08X}:status_name={}:raw=0x{:X}:api={}",
            matches.len(),
            latest.operation_status as u32,
            hook_status_name(latest.operation_status),
            latest.raw_event_type,
            latest.api_name
        ))
    }

    fn matches_hypervisor_payload_conditions(
        cond_group: &NamedConditionGroup,
        msg: &IOMessage,
        irp_op: &IrpMajorOp,
    ) -> bool {
        if !is_kernel_api_irp(irp_op) {
            return false;
        }

        let Some(event) = msg.resolved_hypervisor_event() else {
            return false;
        };

        let raw_event_type = event.raw_event_type;
        let event_name = event.event_name;
        if !is_actionable_hypervisor_event(
            irp_op,
            &event_name,
            raw_event_type,
            event.operation_status,
            msg.kernel_event_info.is_acg_enabled,
        ) {
            return false;
        }
        let source_pid = event.source_process_id;
        let target_pid = event.target_process_id;
        let raw_arg1 = event.raw_argument1;
        let raw_arg2 = event.raw_argument2;
        let raw_arg3 = event.raw_argument3;
        let raw_arg4 = event.raw_argument4;
        let memory_address = event.memory_address;
        let memory_size = event.memory_size;
        let memory_protection = event.memory_protection;
        let is_executable_memory = event.is_executable_memory;
        let thread_handle = event.thread_handle;
        let thread_start_routine = event.thread_start_routine;
        let access_mask = event.access_mask;
        let operation_status = event.operation_status;

        Self::matches_u32_list(&cond_group.hypervisor_raw_event_types, raw_event_type)
            && Self::matches_u32_list(&cond_group.hypervisor_source_pids, source_pid)
            && Self::matches_u32_list(&cond_group.hypervisor_target_pids, target_pid)
            && Self::matches_u64_list(&cond_group.hypervisor_raw_arg1_values, raw_arg1)
            && Self::matches_u64_list(&cond_group.hypervisor_raw_arg2_values, raw_arg2)
            && Self::matches_u64_list(&cond_group.hypervisor_raw_arg3_values, raw_arg3)
            && Self::matches_u64_list(&cond_group.hypervisor_raw_arg4_values, raw_arg4)
            && Self::matches_u64_range(
                raw_arg1,
                cond_group.hypervisor_raw_arg1_min,
                cond_group.hypervisor_raw_arg1_max,
            )
            && Self::matches_u64_range(
                raw_arg2,
                cond_group.hypervisor_raw_arg2_min,
                cond_group.hypervisor_raw_arg2_max,
            )
            && Self::matches_u64_range(
                raw_arg3,
                cond_group.hypervisor_raw_arg3_min,
                cond_group.hypervisor_raw_arg3_max,
            )
            && Self::matches_u64_range(
                raw_arg4,
                cond_group.hypervisor_raw_arg4_min,
                cond_group.hypervisor_raw_arg4_max,
            )
            && Self::matches_u64_list(&cond_group.hypervisor_memory_addresses, memory_address)
            && Self::matches_u64_range(
                memory_address,
                cond_group.hypervisor_memory_address_min,
                cond_group.hypervisor_memory_address_max,
            )
            && Self::matches_u64_list(&cond_group.hypervisor_memory_sizes, memory_size)
            && Self::matches_u64_range(
                memory_size,
                cond_group.hypervisor_memory_size_min,
                cond_group.hypervisor_memory_size_max,
            )
            && Self::matches_u32_list(&cond_group.hypervisor_memory_protections, memory_protection)
            && cond_group
                .hypervisor_is_executable_memory
                .is_none_or(|required| required == is_executable_memory)
            && Self::matches_u64_list(&cond_group.hypervisor_thread_handles, thread_handle)
            && Self::matches_u64_list(
                &cond_group.hypervisor_thread_start_routines,
                thread_start_routine,
            )
            && Self::matches_u32_list(&cond_group.hypervisor_access_masks, access_mask)
            && Self::matches_i32_list(&cond_group.hypervisor_operation_statuses, operation_status)
    }

    /// Drain the cross-thread pending IRP record queue and apply each entry to
    /// the corresponding `ProcessBehaviorState` via `record_irp_operation`.
    ///
    /// Called from the main Worker thread (which owns `&mut self`) so that the
    /// pipe thread — which only holds a cloned `BehaviorEngine` with `&self` access
    /// — can still feed IRP telemetry into `IrpStatistics` without race conditions.
    pub fn drain_pending_irp_records(&mut self) {
        let records: Vec<(u32, IrpOperationRecord)> = {
            match self.pending_irp_records.lock() {
                Ok(mut q) => {
                    let v: Vec<(u32, IrpOperationRecord)> = q.drain(..).collect();
                    v
                }
                Err(_) => return,
            }
        };

        if records.is_empty() {
            return;
        }

        for (pid, rec) in records {
            // Find the GID for this PID
            let gid_opt = self.find_gid_by_pid(pid);
            let gid = match gid_opt {
                Some(g) => g,
                None => continue, // Process not yet tracked — drop the record
            };

            if let Some(state) = self.process_states.get_mut(&gid) {
                let irp_op = rec.irp_type;
                state.record_irp_operation(
                    // record_irp_operation expects &IOMessage — build a minimal one
                    &{
                        use crate::shared_def::{
                            FileId, IOMessage, KernelEventInfo, RuntimeFeatures,
                        };
                        IOMessage {
                            extension: rec.extension.clone(),
                            file_id_id: FileId::default(),
                            mem_sized_used: 0,
                            entropy: rec.entropy,
                            pid,
                            irp_op,
                            is_entropy_calc: 0,
                            file_change: rec.file_change,
                            file_location_info: 0,
                            filepathstr: rec.file_path.clone(),
                            gid,
                            parent_pid: 0,
                            attacker_pid: 0,
                            attacker_gid: 0,
                            kernel_event_info: KernelEventInfo::default(),
                            runtime_features: RuntimeFeatures::default(),
                            file_size: rec.bytes_transferred as i64,
                            time: rec.timestamp,
                        }
                    },
                    irp_op,
                );
            }
        }
    }

    pub fn register_process(&mut self, gid: u64, pid: u32, exe_path: PathBuf, app_name: String) {
        let state = self
            .process_states
            .entry(gid)
            .or_insert_with(|| ProcessBehaviorState::new(pid, exe_path.clone(), app_name.clone()));

        if state.pid == 0 && pid != 0 {
            state.pid = pid;
        }

        // Heal stale placeholder values that may have been set before worker.rs
        // resolved the real process name/path.
        let name_is_stale = state.app_name.is_empty()
            || state.app_name.starts_with("PROC_")
            || state.app_name == "UNKNOWN";
        let path_is_stale =
            state.exe_path.to_string_lossy() == "UNKNOWN" || state.exe_path.as_os_str().is_empty();

        if name_is_stale
            && !app_name.is_empty()
            && !app_name.starts_with("PROC_")
            && app_name != "UNKNOWN"
        {
            state.app_name = app_name;
        }
        if path_is_stale
            && !exe_path.as_os_str().is_empty()
            && exe_path.to_string_lossy() != "UNKNOWN"
        {
            state.exe_path = exe_path;
        }
    }

    fn record_named_condition_match(
        state: &mut ProcessBehaviorState,
        rule_name: &str,
        cond_name: &str,
        match_key: String,
        now: SystemTime,
        required: usize,
        debug: bool,
    ) {
        let scoped_name = format!("{}::{}", rule_name, cond_name);
        let values = state
            .condition_match_values
            .entry(scoped_name.clone())
            .or_insert_with(HashSet::new);
        if values.len() > 256 {
            values.clear();
        }
        let is_new = values.insert(match_key.clone());
        let count = state
            .condition_match_counts
            .entry(scoped_name.clone())
            .or_insert(0);
        if is_new {
            *count += 1;
        }
        state
            .condition_first_seen
            .entry(scoped_name.clone())
            .or_insert(now);
        state.condition_last_seen.insert(scoped_name.clone(), now);

        if *count >= required.max(1) {
            state.satisfied_named_conditions.insert(scoped_name);
            if debug {
                Logging::debug(&format!(
                    "[BehaviorEngine] Named condition '{}' satisfied for PID {} (count: {}/{}, matches: {})",
                    cond_name,
                    state.pid,
                    *count,
                    required.max(1),
                    match_key
                ));
            }
        } else if is_new && debug {
            Logging::debug(&format!(
                "[BehaviorEngine] Condition '{}' match #{}/{} for PID {} ({})",
                cond_name,
                *count,
                required.max(1),
                state.pid,
                match_key
            ));
        }
    }

    fn record_self_defense_event_in_state(
        state: &mut ProcessBehaviorState,
        event: SelfDefenseTelemetryEvent,
    ) {
        state.self_defense_event_count = state.self_defense_event_count.saturating_add(1);
        *state
            .self_defense_category_counts
            .entry(event.category.to_ascii_lowercase())
            .or_insert(0) += 1;
        *state
            .self_defense_attack_counts
            .entry(event.attack_type.to_ascii_lowercase())
            .or_insert(0) += 1;
        if state.self_defense_events.len() >= 128 {
            state.self_defense_events.pop_front();
        }
        state.self_defense_events.push_back(event);
    }

    fn is_self_defense_condition_group(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.self_defense_attack_types.is_empty()
            || !cond_group.self_defense_categories.is_empty()
            || !cond_group.self_defense_operations.is_empty()
            || !cond_group.self_defense_target_patterns.is_empty()
            || !cond_group.self_defense_attacker_patterns.is_empty()
            || !cond_group.self_defense_sources.is_empty()
            || !cond_group.self_defense_actions.is_empty()
            || cond_group.self_defense_min_count.is_some()
    }

    fn pattern_list_matches_any(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        patterns: &[String],
        candidates: &[&str],
    ) -> bool {
        patterns.is_empty()
            || patterns.iter().any(|pattern| {
                candidates.iter().any(|candidate| {
                    !candidate.trim().is_empty()
                        && Self::matches_pattern_internal(cache, pattern, candidate)
                })
            })
    }

    fn self_defense_event_matches(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        cond_group: &NamedConditionGroup,
        event: &SelfDefenseTelemetryEvent,
    ) -> bool {
        Self::pattern_list_matches_any(cache, &cond_group.self_defense_sources, &[&event.source])
            && Self::pattern_list_matches_any(
                cache,
                &cond_group.self_defense_categories,
                &[&event.category],
            )
            && Self::pattern_list_matches_any(
                cache,
                &cond_group.self_defense_attack_types,
                &[&event.attack_type],
            )
            && Self::pattern_list_matches_any(
                cache,
                &cond_group.self_defense_operations,
                &[&event.operation],
            )
            && Self::pattern_list_matches_any(
                cache,
                &cond_group.self_defense_target_patterns,
                &[&event.protected_path],
            )
            && Self::pattern_list_matches_any(
                cache,
                &cond_group.self_defense_attacker_patterns,
                &[&event.attacker_path],
            )
            && Self::pattern_list_matches_any(
                cache,
                &cond_group.self_defense_actions,
                &[&event.action],
            )
    }

    fn apply_self_defense_named_conditions(&mut self, gid: u64, event: &SelfDefenseTelemetryEvent) {
        let Some(state_snapshot) = self.process_states.get(&gid).cloned() else {
            return;
        };

        let debug_enabled = self.rules.iter().any(|rule| rule.debug);
        let mut matches = Vec::new();

        for rule in &self.rules {
            for (cond_name, cond_group) in &rule.named_conditions {
                if !Self::is_self_defense_condition_group(cond_group)
                    || Self::rule_condition_satisfied(&state_snapshot, rule, cond_name)
                {
                    continue;
                }

                if Self::self_defense_event_matches(&self.regex_cache, cond_group, event) {
                    let required = cond_group
                        .self_defense_min_count
                        .or_else(|| {
                            if cond_group.min_matches > 0 {
                                Some(cond_group.min_matches)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(1);
                    matches.push((
                        rule.name.clone(),
                        cond_name.clone(),
                        required,
                        event.match_key(),
                        rule.debug || debug_enabled,
                    ));
                }
            }
        }

        if matches.is_empty() {
            return;
        }

        if let Some(state) = self.process_states.get_mut(&gid) {
            for (rule_name, cond_name, required, match_key, debug) in matches {
                Self::record_named_condition_match(
                    state,
                    &rule_name,
                    &cond_name,
                    match_key,
                    event_time(event),
                    required,
                    debug,
                );
                Logging::info(&format!(
                    "[BehaviorEngine] Self-defense telemetry matched condition '{}' for PID {}: category={} action={} attack_type={} target={}",
                    cond_name,
                    state.pid,
                    event.category,
                    event.action,
                    event.attack_type,
                    event.protected_path
                ));
            }
        }
    }

    pub fn drain_self_defense_telemetry_for_pid(&mut self, pid: u32) {
        if pid == 0 {
            return;
        }
        let Some(gid) = self.find_gid_by_pid(pid) else {
            return;
        };

        let mut events = {
            let mut telemetry = self.self_defense_telemetry.write().unwrap();
            telemetry.remove(&pid).unwrap_or_default()
        };

        while let Some(event) = events.pop_front() {
            if let Some(state) = self.process_states.get_mut(&gid) {
                Self::record_self_defense_event_in_state(state, event.clone());
            }
            self.apply_self_defense_named_conditions(gid, &event);
        }
    }

    pub fn drain_self_defense_telemetry_for_known_states(&mut self) {
        let pids: Vec<u32> = self
            .process_states
            .values()
            .filter_map(|state| (state.pid != 0).then_some(state.pid))
            .collect();
        for pid in pids {
            self.drain_self_defense_telemetry_for_pid(pid);
        }
    }

    // ==========================================================================
    // EVENT DETECTION FROM HIM EVENTS
    // ==========================================================================

    /// Get actual detected labels from HIM events
    #[allow(dead_code)]
    fn get_detected_apis_from_state(state: &ProcessBehaviorState) -> HashSet<String> {
        state.all_apis_called.clone()
    }

    // ==========================================================================
    // COMPLETE EVENT PROCESSING PIPELINE
    // ==========================================================================

    pub fn process_event(
        &mut self,
        precord: &mut ProcessRecord,
        msg: &IOMessage,
        config: &Config,
        threat_handler: &dyn ThreatHandler,
    ) {
        let gid = msg.gid;
        let irp_op_byte = effective_hypervisor_irp_byte(msg);
        let irp_op = IrpMajorOp::from_byte(irp_op_byte);
        let is_rootkit_event = is_rootkit_irp(&irp_op);
        let mut actions = ActionsOnKill::with_handler(threat_handler.clone_box());

        if !self.process_states.contains_key(&gid) {
            // appname and exepath are resolved by worker.rs (register_precord) before reaching here.
            let initial_pid = if is_rootkit_event && gid == ROOTKIT_GLOBAL_GID {
                0
            } else {
                msg.pid
            };
            let initial_exe_path = if is_rootkit_event && gid == ROOTKIT_GLOBAL_GID {
                PathBuf::from(r"\kernel\rootkit")
            } else {
                precord.exepath.clone()
            };
            let initial_app_name = if is_rootkit_event && gid == ROOTKIT_GLOBAL_GID {
                "kernel_rootkit".to_string()
            } else if is_rootkit_event
                && is_rootkit_pseudo_gid(gid)
                && msg.pid != 0
                && (precord.appname.is_empty()
                    || precord.appname.starts_with("PROC_")
                    || precord.appname == "UNKNOWN")
            {
                let fallback_name = msg.kernel_event_info.object_name.trim_matches('\0').trim();
                if fallback_name.is_empty() {
                    format!("rootkit_pid_{}", msg.pid)
                } else {
                    fallback_name.to_lowercase()
                }
            } else {
                precord.appname.clone()
            };
            let mut s = ProcessBehaviorState::new(initial_pid, initial_exe_path, initial_app_name);
            if !msg.runtime_features.command_line.trim().is_empty() {
                s.command_line = msg.runtime_features.command_line.to_lowercase();
                if let Some((fname, fpath)) = Self::extract_script_from_cmdline(
                    &precord.appname,
                    &msg.runtime_features.command_line,
                ) {
                    s.script_file = fname;
                    s.script_file_path = fpath;
                }
            }

            let parent_pid = msg.parent_pid;
            let mut resolved_parent_name: Option<String> = None;
            let mut resolved_parent_path: Option<PathBuf> = None;

            for existing_state in self.process_states.values() {
                if existing_state.pid == parent_pid {
                    if !existing_state.app_name.is_empty() {
                        resolved_parent_name = Some(existing_state.app_name.clone());
                    }
                    if !existing_state.exe_path.as_os_str().is_empty() {
                        resolved_parent_path = Some(existing_state.exe_path.clone());
                    }
                    break;
                }
            }

            if resolved_parent_path.is_none() && parent_pid != 0 {
                resolved_parent_path = resolve_process_path(parent_pid);
            }

            if let Some(parent_name) = resolved_parent_name {
                s.parent_name = parent_name;
            } else if let Some(parent_path) = resolved_parent_path.as_ref() {
                if let Some(parent_name) = parent_path.file_name().and_then(|value| value.to_str())
                {
                    s.parent_name = parent_name.to_lowercase();
                }
            } else {
                s.parent_name = "unknown".to_string();
            }

            if let Some(parent_path) = resolved_parent_path {
                s.parent_path = parent_path;
            }

            self.process_states.insert(gid, s);
        }

        // --- On-the-fly self-defense telemetry generation from standard EDR events ---
        let lowercase_path = msg.filepathstr.to_lowercase().replace("\\", "/");

        let is_protected_registry = if irp_op == IrpMajorOp::IrpRegistry {
            // Check for service registry self-defense
            lowercase_path.contains("/services/owlyshield_ransom")
                || lowercase_path.contains("/services/reddbg")
                || lowercase_path.contains("/services/hyperdbg")
                || lowercase_path.contains("/services/hyperhv")
                || lowercase_path.contains("/services/sanctum_ppl_runner")
                || lowercase_path.contains("/services/mbrfilter")
                || lowercase_path.contains("/services/fs_minifilter")
                || lowercase_path.contains("/services/sanctum")
                || lowercase_path.contains("/services/edrdrv")
                || lowercase_path.contains("/services/edrsvc")
                || lowercase_path.contains("/software/owlyshield")
                || lowercase_path.contains("/software/microsoft/windows nt/currentversion/winlogon")
                || lowercase_path.contains("/software/classes/clsid")
                || lowercase_path.contains("/software/classes/appid")
        } else {
            false
        };

        let is_protected_file = match irp_op {
            IrpMajorOp::IrpCreate | IrpMajorOp::IrpWrite | IrpMajorOp::IrpSetInfo => {
                lowercase_path.contains("program files/hydradragonantivirus")
                    || lowercase_path.contains("system32/sanctum.dll")
                    || lowercase_path.contains("system32/tasks/hydradragonantivirus")
                    || lowercase_path.contains("system32/drivers/owlyshieldransomfilter.sys")
                    || lowercase_path.contains("system32/drivers/reddbgdrv.sys")
                    || lowercase_path.contains("system32/drivers/hyperhv.sys")
                    || lowercase_path.contains("system32/drivers/mbrfilter.sys")
                    || lowercase_path.contains("system32/drivers/fs_minifilter.sys")
                    || lowercase_path.contains("system32/drivers/sanctum.sys")
                    || lowercase_path.contains("system32/drivers/edrdrv.sys")
                    || lowercase_path.contains("system32/edrpm64.dll")
                    || lowercase_path.contains("system32/edrpm32.dll")
                    || lowercase_path.contains("system32/edrmm.dll")
            }
            _ => false,
        };

        if is_protected_registry || is_protected_file {
            let category = if lowercase_path.contains("/software/classes/clsid")
                || lowercase_path.contains("/software/classes/appid")
            {
                "com".to_string()
            } else if is_protected_registry {
                "registry".to_string()
            } else {
                "file".to_string()
            };

            let operation = if is_protected_registry {
                match msg.file_change {
                    _ if msg.file_change == FileChangeInfo::RegSetValue as u8 => {
                        "SET_VALUE".to_string()
                    }
                    _ if msg.file_change == FileChangeInfo::RegDeleteValue as u8 => {
                        "DELETE_VALUE".to_string()
                    }
                    _ if msg.file_change == FileChangeInfo::RegDeleteKey as u8 => {
                        "DELETE_KEY".to_string()
                    }
                    _ if msg.file_change == FileChangeInfo::RegCreateKey as u8 => {
                        "CREATE_KEY".to_string()
                    }
                    _ if msg.file_change == FileChangeInfo::RegRenameKey as u8 => {
                        "RENAME_KEY".to_string()
                    }
                    _ => "REGISTRY_OTHER".to_string(),
                }
            } else {
                match irp_op {
                    IrpMajorOp::IrpWrite => "WRITE".to_string(),
                    IrpMajorOp::IrpSetInfo => "SET_INFO".to_string(),
                    _ => "CREATE".to_string(),
                }
            };

            let operation_str = if category == "com" {
                format!("COM_{}", operation)
            } else {
                operation
            };

            let attack_type = if category == "com" {
                "COM_HIJACK".to_string()
            } else {
                "TAMPER".to_string()
            };

            let action = "telemetry".to_string();

            let self_defense_event = SelfDefenseTelemetryEvent {
                timestamp_ms: msg
                    .time
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                source: "openedr".to_string(),
                category,
                attack_type,
                operation: operation_str,
                protected_path: msg.filepathstr.clone(),
                attacker_path: precord.exepath.to_string_lossy().to_string(),
                attacker_pid: msg.pid,
                target_pid: 0,
                action,
            };

            if let Some(state) = self.process_states.get_mut(&gid) {
                Self::record_self_defense_event_in_state(state, self_defense_event.clone());
            }
            self.apply_self_defense_named_conditions(gid, &self_defense_event);
        }

        self.drain_self_defense_telemetry_for_pid(msg.pid);

        // Self-heal: if the state was created with placeholder values before worker.rs
        // resolved the real appname/exepath (race between event arrival and IrpProcessCreate),
        // update it on every subsequent event until the values are concrete.
        // Also update precord itself so ransomware detection and all other paths get
        // the correct values — process_record_handler.handle_io runs before this function.
        // Resolve parent name before the mutable borrow below (borrow checker).
        let parent_pid = msg.parent_pid;
        let (resolved_parent_name, resolved_parent_path): (Option<String>, Option<PathBuf>) =
            if parent_pid != 0 {
                if let Some(parent_state) = self.process_states.values().find(|s| {
                    s.pid == parent_pid
                        && ((!s.app_name.is_empty()
                            && !s.app_name.starts_with("PROC_")
                            && s.app_name != "UNKNOWN")
                            || !s.exe_path.as_os_str().is_empty())
                }) {
                    (
                        if !parent_state.app_name.is_empty()
                            && !parent_state.app_name.starts_with("PROC_")
                            && parent_state.app_name != "UNKNOWN"
                        {
                            Some(parent_state.app_name.clone())
                        } else {
                            None
                        },
                        if !parent_state.exe_path.as_os_str().is_empty() {
                            Some(parent_state.exe_path.clone())
                        } else {
                            None
                        },
                    )
                } else {
                    let fallback_path = resolve_process_path(parent_pid);
                    let fallback_name = fallback_path
                        .as_ref()
                        .and_then(|path| path.file_name().and_then(|value| value.to_str()))
                        .map(|value| value.to_lowercase());
                    (fallback_name, fallback_path)
                }
            } else {
                (None, None)
            };

        if let Some(state) = self.process_states.get_mut(&gid) {
            let name_is_stale = state.app_name.is_empty()
                || state.app_name.starts_with("PROC_")
                || state.app_name == "UNKNOWN";
            let path_is_stale = state.exe_path.to_string_lossy() == "UNKNOWN"
                || state.exe_path.as_os_str().is_empty();

            if name_is_stale
                && !precord.appname.is_empty()
                && !precord.appname.starts_with("PROC_")
                && precord.appname != "UNKNOWN"
            {
                if self.rules.iter().any(|r| r.debug) {
                    Logging::debug(&format!(
                        "[BehaviorEngine] Resolved stale appname for GID {}: '{}' -> '{}'",
                        gid, state.app_name, precord.appname
                    ));
                }
                state.app_name = precord.appname.clone();
            }

            if path_is_stale
                && !precord.exepath.as_os_str().is_empty()
                && precord.exepath.to_string_lossy() != "UNKNOWN"
            {
                state.exe_path = precord.exepath.clone();
            }

            // Heal precord too — ransomware detection and report generation read
            // directly from ProcessRecord, not from ProcessBehaviorState.
            let precord_name_stale = precord.appname.is_empty()
                || precord.appname.starts_with("PROC_")
                || precord.appname == "UNKNOWN";
            let precord_path_stale = precord.exepath.to_string_lossy() == "UNKNOWN"
                || precord.exepath.as_os_str().is_empty();

            if precord_name_stale
                && !state.app_name.is_empty()
                && !state.app_name.starts_with("PROC_")
                && state.app_name != "UNKNOWN"
            {
                precord.appname = state.app_name.clone();
            }
            if precord_path_stale
                && !state.exe_path.as_os_str().is_empty()
                && state.exe_path.to_string_lossy() != "UNKNOWN"
            {
                precord.exepath = state.exe_path.clone();
            }

            // Heal parent name using the value resolved before the mutable borrow.
            if (state.parent_name == "unknown" || state.parent_name.is_empty())
                && let Some(ref name) = resolved_parent_name
            {
                state.parent_name = name.clone();
            }
            if state.parent_path.as_os_str().is_empty()
                && let Some(ref path) = resolved_parent_path
            {
                state.parent_path = path.clone();
            }
        }
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.record_irp_operation(msg, irp_op_byte);
        }

        let state = self.process_states.get_mut(&gid).unwrap();
        if state.command_line.is_empty() && !msg.runtime_features.command_line.trim().is_empty() {
            state.command_line = msg.runtime_features.command_line.to_lowercase();
        }
        let pid = state.pid;

        // Run AMSI analysis if this is an AMSI event
        if msg.kernel_event_info.is_amsi_event
            && !msg.kernel_event_info.amsi_content_sample.is_empty()
        {
            let amsi_res = self
                .amsi_analyzer
                .analyze(&msg.kernel_event_info.amsi_content_sample, "kernel");
            state.amsi_results.push(amsi_res);

            // Log all AMSI detections for visibility
            if let Some(last_res) = state.amsi_results.last() {
                if last_res.risk_level > crate::behavioral::amsi::AmsiRiskLevel::None {
                    Logging::warning(&format!(
                        "[AMSI][{}] {:?} risk script content detected in process GID {} ({}) [Cmd: {}]. Patterns: {:?}",
                        last_res.source,
                        last_res.risk_level,
                        gid,
                        msg.filepathstr,
                        state.command_line,
                        last_res.detected_patterns
                    ));
                }
            }
        }

        if state.script_file.is_empty() {
            if let Some((fname, fpath)) =
                Self::extract_script_from_cmdline(&state.app_name, &state.command_line)
            {
                state.script_file = fname;
                state.script_file_path = fpath;
            }
        }

        if self.rules.iter().any(|r| r.debug) {
            Logging::debug(&format!(
                "[BehaviorEngine] IO event: pid={} gid={} irp={:?} path={} ext={} entropy={}",
                pid,
                gid,
                irp_op,
                if msg.filepathstr.is_empty() {
                    "<empty>"
                } else {
                    &msg.filepathstr
                },
                if msg.extension.is_empty() {
                    "<none>"
                } else {
                    &msg.extension
                },
                msg.entropy
            ));
        }

        // === STEP 3: SIGNATURE CHECK ===
        let signature_path = if !precord.exepath.as_os_str().is_empty()
            && precord.exepath.to_string_lossy() != "UNKNOWN"
        {
            precord.exepath.clone()
        } else {
            state.exe_path.clone()
        };

        if !signature_path.as_os_str().is_empty() && signature_path.to_string_lossy() != "UNKNOWN" {
            let signature_path_changed = state.signature_checked_path != signature_path;
            if !state.signature_checked || signature_path_changed {
                if signature_path.exists() {
                    let info = verify_signature(&signature_path);
                    state.has_valid_signature = info.is_trusted;
                    state.is_signed = info.is_signed;
                    state.signature_status = info.status.as_str().to_string();
                    state.signature_status_text = info.status_text.clone();
                    state.signature_raw_hresult = Some(info.raw_hresult);
                    state.signature_verification_failed = info.verification_failed;
                    state.signature_no_signature = info.no_signature;
                    state.signature_status_issues = info.signature_status_issues;
                    state.signature_invalid = info.invalid_signature;
                    state.signer_name = info.signer_name.clone();
                    state.signature_checked = true;
                    state.signature_checked_path = signature_path;
                } else {
                    // Do not permanently cache "unsigned" just because the real path
                    // has not been resolved yet. A later event may heal the image path.
                    state.signature_checked = false;
                    state.signature_checked_path = PathBuf::new();
                    state.has_valid_signature = false;
                    state.is_signed = false;
                    state.signature_status = "verification_failed".to_string();
                    state.signature_status_text =
                        "Path does not exist or is unresolved".to_string();
                    state.signature_raw_hresult = None;
                    state.signature_verification_failed = true;
                    state.signature_no_signature = false;
                    state.signature_status_issues = false;
                    state.signature_invalid = false;
                    state.signer_name = None;
                }
            }
        }

        // NOTE: Protected-path filtering is intentionally disabled so every kernel event is processed.
        // This keeps detection/debugging fully transparent for all disk/registry paths.

        // === STEP 4: HANDLE PROCESS TERMINATION ===
        if irp_op == IrpMajorOp::IrpProcessTerminateAttempt {
            let mut victim_path = msg.filepathstr.to_lowercase();
            if victim_path.is_empty() {
                // Fall back to the tracked state name (worker.rs already resolved this).
                if let Some(state) = self.process_states.values().find(|s| s.pid == msg.pid) {
                    victim_path = state.app_name.to_lowercase();
                }
            }

            if msg.attacker_pid != 0 {
                let is_self = msg.attacker_pid == msg.pid;
                let mut attacker_found = false;

                if msg.attacker_gid != 0
                    && let Some(attacker_state) = self.process_states.get_mut(&msg.attacker_gid)
                {
                    attacker_found = true;
                    if !victim_path.is_empty() {
                        if is_self {
                            attacker_state
                                .self_terminated_processes
                                .insert(victim_path.clone());
                        } else {
                            attacker_state
                                .terminated_processes
                                .insert(victim_path.clone());
                        }
                    }
                }

                if !attacker_found && !is_self {
                    let mut resolved_attacker_gid = None;
                    for (gid, state) in &self.process_states {
                        if state.pid == msg.attacker_pid {
                            resolved_attacker_gid = Some(*gid);
                            break;
                        }
                    }

                    if let Some(agid) = resolved_attacker_gid
                        && let Some(attacker_state) = self.process_states.get_mut(&agid)
                        && !victim_path.is_empty()
                    {
                        attacker_state
                            .terminated_processes
                            .insert(victim_path.clone());
                    }
                }

                if !victim_path.is_empty() {
                    self.process_terminated.insert(victim_path.clone());
                }
            }
        }

        let filepath = msg.filepathstr.clone();
        let norm_filepath = filepath.to_lowercase().replace("\\", "/");
        let norm_filepath = norm_filepath.trim_end_matches('/');

        // === STEP 5: UPDATE NAMED CONDITIONS STATE ===
        self.update_named_conditions_state(precord, gid, msg, &irp_op, &filepath);

        // === STEP 6: UPDATE LEGACY TRACKING ===
        for rule in &self.rules {
            if rule.named_conditions.is_empty() {
                continue;
            }

            for cond_group in rule.named_conditions.values() {
                if let Some(state) = self.process_states.get_mut(&gid) {
                    for path_pattern in &cond_group.file_paths {
                        let norm_pattern = path_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(norm_pattern) {
                            state
                                .browsed_paths_tracker
                                .insert(path_pattern.clone(), SystemTime::now());
                        }
                    }

                    for staging_pattern in &cond_group.staging_paths {
                        let norm_pattern = staging_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        let is_staging_op = matches!(
                            irp_op,
                            IrpMajorOp::IrpWrite | IrpMajorOp::IrpCreate | IrpMajorOp::IrpSetInfo
                        );
                        if norm_filepath.contains(norm_pattern) && is_staging_op {
                            state
                                .staged_files_written
                                .insert(PathBuf::from(&filepath), SystemTime::now());
                        }
                    }

                    for browsed_pattern in &cond_group.browsed_paths {
                        let norm_pattern = browsed_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(norm_pattern) {
                            state
                                .browsed_paths_tracker
                                .insert(browsed_pattern.clone(), SystemTime::now());
                        }
                    }

                    for sensitive_pattern in &cond_group.sensitive_paths {
                        let norm_pattern = sensitive_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(norm_pattern) {
                            state
                                .accessed_paths_tracker
                                .insert(sensitive_pattern.clone());
                        }
                    }
                }
            }
        }

        // === STEP 7: EVALUATE RULES ===
        self.check_rules(precord, gid, msg, irp_op.clone(), config, &mut actions);

        // === STEP 8: HANDLE SPECIAL IRP OPERATIONS ===
        match irp_op {
            IrpMajorOp::IrpHypervisorEvent
            | IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection => {
                // handle_hypervisor_event logic is natively merged into record_irp_operation and scan_all_processes.
            }

            IrpMajorOp::IrpRootkitSsdtHook
            | IrpMajorOp::IrpRootkitHiddenProcess
            | IrpMajorOp::IrpRootkitHiddenDriver
            | IrpMajorOp::IrpRootkitKernelHook
            | IrpMajorOp::IrpRootkitTerminateProcess
            | IrpMajorOp::IrpRootkitFileMove
            | IrpMajorOp::IrpRootkitGeneric => {
                self.handle_rootkit_event(&msg);
            }

            _ => {}
        }
    }

    fn update_named_conditions_state(
        &mut self,
        precord: &mut ProcessRecord,
        gid: u64,
        msg: &IOMessage,
        irp_op: &IrpMajorOp,
        filepath: &str,
    ) {
        let now = if msg.time.duration_since(UNIX_EPOCH).is_ok() {
            msg.time
        } else {
            SystemTime::now()
        };
        let mut available_apis = HashSet::new();

        let state_detected_apis = if let Some(state) = self.process_states.get(&gid) {
            state.all_apis_called.clone()
        } else {
            HashSet::new()
        };
        let current_hypervisor_event = msg.resolved_hypervisor_event();
        let current_irp_kind = current_hypervisor_event
            .as_ref()
            .map(|event| event.irp_op.clone())
            .unwrap_or_else(|| irp_op.clone());
        let current_irp_opcode = effective_hypervisor_irp_byte(msg);
        let current_raw_event_type = current_hypervisor_event
            .as_ref()
            .map(|event| event.raw_event_type)
            .unwrap_or_else(|| effective_hypervisor_raw_event_type(msg));
        let current_event_name = current_hypervisor_event
            .as_ref()
            .map(|event| event.event_name.clone())
            .unwrap_or_else(|| resolved_hypervisor_event_name(msg));
        let current_operation_status = current_hypervisor_event
            .as_ref()
            .map(|event| event.operation_status)
            .unwrap_or(msg.kernel_event_info.operation_status);
        let current_actionable_hypervisor_event = is_actionable_hypervisor_event(
            &current_irp_kind,
            &current_event_name,
            current_raw_event_type,
            current_operation_status,
            msg.kernel_event_info.is_acg_enabled,
        );
        let mut current_event_apis = HashSet::new();
        if is_kernel_api_irp(&current_irp_kind)
            && current_actionable_hypervisor_event
            && is_real_api_observation(&current_event_name)
        {
            current_event_apis.insert(current_event_name.clone());
            if let Some(alias) = api_function_alias(&current_event_name) {
                current_event_apis.insert(alias);
            }
        }
        let mut current_event_hypervisor_labels = HashSet::new();
        if current_actionable_hypervisor_event
            && let Some(event_label) = canonical_hypervisor_event_label(
                &current_irp_kind,
                current_raw_event_type,
                &current_event_name,
            )
        {
            current_event_hypervisor_labels.insert(event_label);
        }

        for api in &state_detected_apis {
            available_apis.insert(api.clone());
        }

        if !available_apis.is_empty() {
            let mut api_names: Vec<&str> = available_apis.iter().map(|s| s.as_str()).collect();
            api_names.sort_unstable_by_key(|name| name.to_ascii_lowercase());
            Logging::info(&format!(
                "[BehaviorEngine] Detected APIs for PID {}: {} - {}",
                msg.pid,
                available_apis.len(),
                api_names.join(", ")
            ));
        }

        let event_file_change = FromPrimitive::from_u8(msg.file_change);
        let should_lookup_previous_extension = matches!(
            event_file_change,
            // ChangeRenameFile must be included so that detect_known_to_unknown_extension_change
            // can compare the pre-rename extension against the post-rename extension.
            // Without this, previous_extension is always None for renames and the
            // known→unknown check can never fire (Branch A of ransomware detection was dead).
            Some(FileChangeInfo::ChangeRenameFile)
                | Some(FileChangeInfo::ChangeExtensionChanged)
                | Some(FileChangeInfo::ChangeNewFile)
                | Some(FileChangeInfo::ChangeDeleteFile)
        );
        let event_extension = ProcessRecord::effective_extension_for_event(msg);
        let previous_extension = if should_lookup_previous_extension {
            precord.previous_extension_for_event(msg)
        } else {
            None
        };
        let is_directory_event = matches!(event_file_change, Some(FileChangeInfo::OpenDirectory));

        if let Some(state) = self.process_states.get_mut(&gid) {
            Self::remember_recent_written_payload(
                state,
                filepath,
                &event_extension,
                event_file_change,
                irp_op,
                is_directory_event,
                now,
            );
        }

        let network_activity_observed = self.pid_has_network_activity(msg.pid);

        for rule in &self.rules {
            if rule.named_conditions.is_empty() {
                continue;
            }

            let state = match self.process_states.get_mut(&gid) {
                Some(s) => s,
                None => continue,
            };

            let remaining_conditions: Vec<_> = rule
                .named_conditions
                .iter()
                .filter(|(name, _)| !Self::rule_condition_satisfied(state, rule, name))
                .collect();

            if remaining_conditions.is_empty() {
                continue;
            }

            for (cond_name, cond_group) in remaining_conditions {
                if Self::rule_condition_satisfied(state, rule, cond_name) {
                    continue;
                }

                let mut matched = false;
                let mut matched_artifact_path: Option<String> = None;
                let has_cmdline_requirements = !cond_group.cmdline_keywords.is_empty()
                    || !cond_group.cmdline_patterns.is_empty();
                let process_context_requirement_count = [
                    !cond_group.created_processes.is_empty(),
                    cond_group.detect_recently_written_payload_launch,
                    !cond_group.process_names.is_empty(),
                    !cond_group.parent_names.is_empty(),
                    has_cmdline_requirements,
                    cond_group.has_network_activity,
                    cond_group.is_acg_enabled.is_some(),
                ]
                .into_iter()
                .filter(|configured| *configured)
                .count();
                let conjunctive_process_context = process_context_requirement_count > 1;

                let has_api_conditions = !cond_group.apis.is_empty()
                    || !cond_group.scheduled_task_apis.is_empty()
                    || !cond_group.anti_debug_apis.is_empty()
                    || !cond_group.anti_vm_apis.is_empty();
                let api_context_has_reg_conditions = !cond_group.registry_keys.is_empty()
                    || !cond_group.registry_keys_exclude.is_empty()
                    || !cond_group.autorun_keys.is_empty()
                    || !cond_group.registry_values.is_empty()
                    || !cond_group.registry_value_data_patterns.is_empty();
                let api_context_has_path_filters = !cond_group.file_paths.is_empty()
                    || !cond_group.staging_paths.is_empty()
                    || !cond_group.browsed_paths.is_empty()
                    || !cond_group.sensitive_paths.is_empty()
                    || !cond_group.persistence_locations.is_empty();
                let api_context_has_extension_conditions = !cond_group.file_extensions.is_empty()
                    || cond_group.detect_extension_changes
                    || cond_group.detect_non_whitelisted_extensions
                    || cond_group.detect_known_to_unknown_extension_change;
                let api_only_condition = !api_context_has_reg_conditions
                    && !api_context_has_path_filters
                    && !api_context_has_extension_conditions
                    && cond_group.file_operations.is_empty()
                    && !conjunctive_process_context;

                if !matched
                    && (!cond_group.irp_operations.is_empty() || !cond_group.irp_opcodes.is_empty())
                {
                    let opcode_match = cond_group
                        .irp_opcodes
                        .iter()
                        .any(|opcode| *opcode == current_irp_opcode);
                    let operation_match = cond_group.irp_operations.iter().any(|required| {
                        irp_operation_matches_token(current_irp_opcode, msg.file_change, required)
                    });

                    if opcode_match || operation_match {
                        matched = true;
                        let operation_name = Self::operation_label(msg);
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - IRP op match for PID {}: opcode={} ({}) operation={}",
                            cond_name,
                            state.pid,
                            current_irp_opcode,
                            irp_major_op_label(current_irp_opcode),
                            operation_name
                        ));
                    }
                }

                if has_api_conditions {
                    let api_iter = cond_group
                        .apis
                        .iter()
                        .chain(cond_group.scheduled_task_apis.iter())
                        .chain(cond_group.anti_debug_apis.iter())
                        .chain(cond_group.anti_vm_apis.iter());

                    let matched_apis: Vec<&String> = api_iter
                        .filter(|required_api| {
                            let (required_norm, required_has_path) =
                                Self::normalize_api_signature(required_api);
                            current_event_apis.iter().any(|available| {
                                let (available_norm, available_has_path) =
                                    Self::normalize_api_signature(available);
                                if required_has_path {
                                    available_has_path
                                        && Self::matches_pattern_internal(
                                            &self.regex_cache,
                                            required_api,
                                            available,
                                        )
                                } else {
                                    Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        &required_norm,
                                        &available_norm,
                                    )
                                }
                            })
                        })
                        .collect();

                    if matched_apis.len() >= std::cmp::max(1, cond_group.api_threshold) {
                        let api_names = matched_apis
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        if api_only_condition {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Current API match for PID {}: {} APIs detected: {}",
                                cond_name,
                                state.pid,
                                matched_apis.len(),
                                api_names
                            ));
                        } else if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Condition '{}' observed API activity for PID {} but requires file/registry context too: {}",
                                cond_name, state.pid, api_names
                            ));
                        }
                    }
                }

                if !matched && !cond_group.hypervisor_event_labels.is_empty() {
                    let matched_labels: Vec<&String> = cond_group
                        .hypervisor_event_labels
                        .iter()
                        .filter(|required_label| {
                            let (required_norm, required_has_path) =
                                Self::normalize_api_signature(required_label);
                            current_event_hypervisor_labels
                                .iter()
                                .any(|observed_label| {
                                    let (observed_norm, observed_has_path) =
                                        Self::normalize_api_signature(observed_label);
                                    if required_has_path {
                                        observed_has_path
                                            && Self::matches_pattern_internal(
                                                &self.regex_cache,
                                                required_label,
                                                observed_label,
                                            )
                                    } else {
                                        Self::matches_pattern_internal(
                                            &self.regex_cache,
                                            &required_norm,
                                            &observed_norm,
                                        )
                                    }
                                })
                        })
                        .collect();

                    if matched_labels.len()
                        >= std::cmp::max(1, cond_group.hypervisor_event_threshold)
                    {
                        matched = true;
                        let label_names = matched_labels
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Hypervisor event match for PID {}: {} labels detected: {}",
                            cond_name,
                            state.pid,
                            matched_labels.len(),
                            label_names
                        ));
                    }
                }

                if !matched
                    && let Some(hook_error_summary) =
                        Self::matching_hook_error_summary(&self.regex_cache, cond_group, state)
                {
                    matched = true;
                    matched_artifact_path = Some(hook_error_summary.clone());
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - Hook error status match for PID {}: {}",
                        cond_name, state.pid, hook_error_summary
                    ));
                }

                if !matched
                    && Self::has_hypervisor_payload_conditions(cond_group)
                    && Self::matches_hypervisor_payload_conditions(cond_group, msg, irp_op)
                {
                    let hyper_event = msg.resolved_hypervisor_event();
                    let raw_event_type = hyper_event
                        .as_ref()
                        .map(|event| event.raw_event_type)
                        .unwrap_or_else(|| effective_hypervisor_raw_event_type(msg));
                    let source_pid = hyper_event
                        .as_ref()
                        .map(|event| event.source_process_id)
                        .unwrap_or(msg.kernel_event_info.source_process_id);
                    let target_pid = hyper_event
                        .as_ref()
                        .map(|event| event.target_process_id)
                        .unwrap_or(msg.kernel_event_info.target_process_id);
                    let raw_argument1 = hyper_event
                        .as_ref()
                        .map(|event| event.raw_argument1)
                        .unwrap_or(msg.kernel_event_info.raw_argument1);
                    let raw_argument2 = hyper_event
                        .as_ref()
                        .map(|event| event.raw_argument2)
                        .unwrap_or(msg.kernel_event_info.raw_argument2);
                    let raw_argument3 = hyper_event
                        .as_ref()
                        .map(|event| event.raw_argument3)
                        .unwrap_or(msg.kernel_event_info.raw_argument3);
                    let raw_argument4 = hyper_event
                        .as_ref()
                        .map(|event| event.raw_argument4)
                        .unwrap_or(msg.kernel_event_info.raw_argument4);
                    matched = true;
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - API hooking payload match for PID {}: raw_event_type={} src_pid={} target_pid={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X}",
                        cond_name,
                        state.pid,
                        raw_event_type,
                        source_pid,
                        target_pid,
                        raw_argument1,
                        raw_argument2,
                        raw_argument3,
                        raw_argument4
                    ));
                }

                if !matched
                    && !conjunctive_process_context
                    && cond_group.has_network_activity
                    && network_activity_observed
                {
                    matched = true;
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - Network activity confirmed by firewall for PID {}",
                        cond_name, state.pid
                    ));
                }

                // ── Firewall-content conditions ──────────────────────────────────
                #[cfg(all(target_os = "windows", feature = "firewall"))]
                if !matched {
                    let exe_path_lc = state.exe_path.to_string_lossy().to_lowercase();
                    let fw_blocked_map = self.firewall_blocked_exes.read().unwrap();
                    let fw_net_details = self.firewall_net_details.read().unwrap();
                    let detection = fw_blocked_map.get(&exe_path_lc);

                    // firewall_blocked
                    if !matched {
                        if let Some(require_blocked) = cond_group.firewall_blocked {
                            let is_blocked = detection.is_some();
                            if require_blocked == is_blocked {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - firewall_blocked={} matched for {}",
                                    cond_name, require_blocked, exe_path_lc
                                ));
                            }
                        }
                    }

                    // firewall_dst_ips
                    if !matched && !cond_group.firewall_dst_ips.is_empty() {
                        let ip_match =
                            detection.map_or(false, |d| {
                                cond_group
                                    .firewall_dst_ips
                                    .iter()
                                    .any(|ip| d.dst_ip.to_lowercase().contains(&ip.to_lowercase()))
                            }) || fw_net_details.get(&state.pid).map_or(false, |conns| {
                                cond_group.firewall_dst_ips.iter().any(|ip| {
                                    conns.iter().any(|(c_ip, _)| {
                                        c_ip.to_lowercase().contains(&ip.to_lowercase())
                                    })
                                })
                            });
                        if ip_match {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - firewall_dst_ips matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }

                    // firewall_dst_ports
                    if !matched && !cond_group.firewall_dst_ports.is_empty() {
                        let port_match =
                            detection.map_or(false, |d| {
                                cond_group.firewall_dst_ports.contains(&d.dst_port)
                            }) || fw_net_details.get(&state.pid).map_or(false, |conns| {
                                conns
                                    .iter()
                                    .any(|(_, port)| cond_group.firewall_dst_ports.contains(port))
                            });
                        if port_match {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - firewall_dst_ports matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }

                    // firewall_hostnames
                    if !matched && !cond_group.firewall_hostnames.is_empty() {
                        if detection.map_or(false, |d| {
                            cond_group
                                .firewall_hostnames
                                .iter()
                                .any(|h| d.hostname.to_lowercase().contains(&h.to_lowercase()))
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - firewall_hostnames matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }

                    // firewall_block_reasons
                    if !matched && !cond_group.firewall_block_reasons.is_empty() {
                        if detection.map_or(false, |d| {
                            cond_group
                                .firewall_block_reasons
                                .iter()
                                .any(|r| d.reason.to_lowercase().contains(&r.to_lowercase()))
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - firewall_block_reasons matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }

                    // network_rules (Rich matching using PacketInfo history)
                    if !matched && !cond_group.network_rules.is_empty() {
                        if state.net_packets.iter().any(|pkt| {
                            cond_group.network_rules.iter().all(|rule_cond| {
                                let payload = &[];
                                rule_cond.matches_packet(&self.regex_cache, pkt, payload)
                            })
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - network_rules matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }

                    // dns_query_patterns
                    if !matched && !cond_group.dns_query_patterns.is_empty() {
                        if state.net_packets.iter().any(|pkt| {
                            if let Some(query) = &pkt.dns_query {
                                cond_group.dns_query_patterns.iter().any(|pattern| {
                                    Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        pattern,
                                        query,
                                    )
                                })
                            } else {
                                false
                            }
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - dns_query_patterns matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }
                }

                // ── Sanctum-content conditions ──────────────────────────────────
                #[cfg(all(target_os = "windows", feature = "sanctum"))]
                if !matched {
                    if let Some(min_score) = cond_group.sanctum_injection_score_min {
                        if state.sanctum_stats.injection_score >= min_score {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - sanctum_injection_score_min matched: {} >= {} for PID {}",
                                cond_name,
                                state.sanctum_stats.injection_score,
                                min_score,
                                state.pid
                            ));
                        }
                    }
                    if !matched {
                        if let Some(min_syscalls) = cond_group.sanctum_syscall_count_min {
                            if state.sanctum_stats.syscall_count >= min_syscalls {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - sanctum_syscall_count_min matched: {} >= {} for PID {}",
                                    cond_name,
                                    state.sanctum_stats.syscall_count,
                                    min_syscalls,
                                    state.pid
                                ));
                            }
                        }
                    }
                    if !matched {
                        if let Some(require_shellcode) = cond_group.sanctum_shellcode_detected {
                            if require_shellcode == state.sanctum_stats.shellcode_patterns_found {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - sanctum_shellcode_detected matched: {} for PID {}",
                                    cond_name, require_shellcode, state.pid
                                ));
                            }
                        }
                    }
                    if !matched && !cond_group.sanctum_suspicious_hits.is_empty() {
                        if cond_group
                            .sanctum_suspicious_hits
                            .iter()
                            .any(|hit| state.sanctum_suspicious_hits.contains(hit))
                        {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - sanctum_suspicious_hits matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }
                    if !matched {
                        if let Some(require_detected) = cond_group.sanctum_detected {
                            if require_detected == state.sanctum_stats.is_detection {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - sanctum_detected matched: {} for PID {}",
                                    cond_name, require_detected, state.pid
                                ));
                            }
                        }
                    }
                }

                // ── Rootkit generic conditions ──────────────────────────────────
                if !matched {
                    if !cond_group.rootkit_event_types.is_empty() {
                        let matches_type = state
                            .rootkit_findings
                            .iter()
                            .filter(|f| {
                                let type_str = match f.kind {
                                    RootkitFindingKind::SsdtHook => "ssdt_hook",
                                    RootkitFindingKind::HiddenProcess => "hidden_process",
                                    RootkitFindingKind::HiddenDriver => "hidden_driver",
                                    RootkitFindingKind::KernelInlineHook => "kernel_hook",
                                    RootkitFindingKind::TerminateProcess => "terminate_process",
                                    RootkitFindingKind::FileMove => "file_move",
                                    RootkitFindingKind::Generic => "generic",
                                    RootkitFindingKind::Unknown(_) => "unknown",
                                };
                                cond_group
                                    .rootkit_event_types
                                    .iter()
                                    .any(|rt| rt.to_lowercase() == type_str)
                            })
                            .count();

                        let min_count = cond_group.rootkit_event_min_count.unwrap_or(1);
                        if matches_type >= min_count {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - rootkit_event_types matched for PID {} ({} >= {})",
                                cond_name, state.pid, matches_type, min_count
                            ));
                        }
                    }

                    if !matched && cond_group.rootkit_total_min.is_some() {
                        let total_min = cond_group.rootkit_total_min.unwrap();
                        if state.rootkit_findings.len() >= total_min {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - rootkit_total_min matched for PID {} ({} >= {})",
                                cond_name,
                                state.pid,
                                state.rootkit_findings.len(),
                                total_min
                            ));
                        }
                    }

                    if !matched && !cond_group.rootkit_description_contains.is_empty() {
                        let has_desc = state.rootkit_findings.iter().any(|f| {
                            let desc_lc = f.description.to_lowercase();
                            cond_group
                                .rootkit_description_contains
                                .iter()
                                .any(|d| desc_lc.contains(&d.to_lowercase()))
                        });
                        if has_desc {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - rootkit_description_contains matched for PID {}",
                                cond_name, state.pid
                            ));
                        }
                    }
                }

                let file_change = event_file_change;
                let file_event_irp = is_file_data_irp(irp_op);

                let current_file_op = match *irp_op {
                    IrpMajorOp::IrpRead => Some("read"),
                    IrpMajorOp::IrpWrite => Some("write"),
                    IrpMajorOp::IrpCreate => {
                        if is_directory_event {
                            None
                        } else if matches!(file_change, Some(FileChangeInfo::ChangeNewFile)) {
                            Some("create")
                        } else {
                            Some("open")
                        }
                    }
                    IrpMajorOp::IrpSetInfo => match file_change {
                        Some(FileChangeInfo::ChangeRenameFile) => Some("rename"),
                        Some(FileChangeInfo::ChangeExtensionChanged) => Some("rename"),
                        Some(FileChangeInfo::ChangeDeleteFile) => Some("delete"),
                        Some(FileChangeInfo::ChangeWrite) => Some("write"),
                        Some(FileChangeInfo::ChangeOverwriteFile) => Some("write"),
                        Some(FileChangeInfo::ChangeNewFile) => Some("create"),
                        _ => Some("setinfo"),
                    },
                    _ => None,
                };

                let file_op_allowed = if cond_group.file_operations.is_empty() {
                    true
                } else if let Some(op) = current_file_op {
                    cond_group.file_operations.iter().any(|v| v == op)
                } else {
                    false
                };

                let has_path_filters = !cond_group.file_paths.is_empty()
                    || !cond_group.staging_paths.is_empty()
                    || !cond_group.browsed_paths.is_empty()
                    || !cond_group.sensitive_paths.is_empty()
                    || !cond_group.persistence_locations.is_empty();

                let has_extension_conditions = !cond_group.file_extensions.is_empty()
                    || cond_group.detect_extension_changes
                    || cond_group.detect_non_whitelisted_extensions
                    || cond_group.detect_known_to_unknown_extension_change;
                let skip_direct_file_path_matching =
                    cond_group.detect_recently_written_payload_launch;

                let same_file_requirements_ok = (!cond_group.require_same_file_read
                    || precord.has_read_file_id(&msg.file_id_id))
                    && (!cond_group.require_same_file_write
                        || precord.has_written_file_id(&msg.file_id_id))
                    && (!cond_group.require_same_file_rename
                        || precord.has_renamed_file_id(&msg.file_id_id))
                    && (!cond_group.require_same_stem_created_unknown_extension
                        || state.created_unknown_ext_stems.contains(filepath))
                    && (!cond_group.require_same_stem_written_unknown_extension
                        || state.written_unknown_ext_stems.contains(filepath));

                let parent_image_touched = !state.parent_path.as_os_str().is_empty()
                    && target_matches_process_image(&state.parent_path, filepath, &msg.filepathstr);

                if !matched
                    && file_event_irp
                    && cond_group.detect_parent_image_delete
                    && parent_image_touched
                    && is_delete_like_file_operation(irp_op, file_change)
                {
                    matched = true;
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - Child process PID {} attempted to delete parent image {}",
                        cond_name,
                        state.pid,
                        state.parent_path.to_string_lossy()
                    ));
                }

                if !matched
                    && file_event_irp
                    && cond_group.detect_parent_image_rename
                    && parent_image_touched
                    && is_rename_like_file_operation(irp_op, file_change)
                {
                    matched = true;
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - Child process PID {} attempted to rename parent image {}",
                        cond_name,
                        state.pid,
                        state.parent_path.to_string_lossy()
                    ));
                }

                // Path-only conditions: match on path filters when no extension-specific matcher is requested.
                if !matched
                    && file_event_irp
                    && !skip_direct_file_path_matching
                    && has_path_filters
                    && !has_extension_conditions
                    && file_op_allowed
                {
                    let path_variants = build_path_variants(filepath, &msg.filepathstr);
                    let mut path_iter = cond_group
                        .file_paths
                        .iter()
                        .chain(cond_group.staging_paths.iter())
                        .chain(cond_group.browsed_paths.iter())
                        .chain(cond_group.sensitive_paths.iter())
                        .chain(cond_group.persistence_locations.iter());

                    let matched_path: Option<String> = path_iter
                        .find(|p| {
                            let p_norm = p.replace("\\", "/");
                            let p_norm_stripped = strip_drive_prefix(&p_norm);
                            path_variants.iter().any(|v| {
                                Self::matches_pattern_internal(&self.regex_cache, &p_norm, v)
                                    || Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        &p_norm_stripped,
                                        v,
                                    )
                            })
                        })
                        .map(|s| s.to_string());

                    if matched_path.is_some() {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Path match for PID {}: {}",
                            cond_name,
                            state.pid,
                            matched_path.unwrap_or_default()
                        ));
                    }
                }

                // File-operation-only conditions (no path or extension constraints) should still accumulate.
                if !matched
                    && file_event_irp
                    && !skip_direct_file_path_matching
                    && !cond_group.file_operations.is_empty()
                    && !has_path_filters
                    && !has_extension_conditions
                    && file_op_allowed
                    && current_file_op.is_some()
                {
                    if same_file_requirements_ok {
                        matched = true;
                        if let Some(op) = current_file_op {
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - File operation match for PID {}: {}",
                                cond_name, state.pid, op
                            ));
                        }
                    } else {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition '{}' ignored for PID {} - same-file prerequisites not satisfied",
                            cond_name, state.pid
                        ));
                    }
                }

                if !matched
                    && file_event_irp
                    && !skip_direct_file_path_matching
                    && has_extension_conditions
                    && file_op_allowed
                    && !is_directory_event
                    && same_file_requirements_ok
                {
                    let extension_changed = matches!(
                        file_change,
                        Some(FileChangeInfo::ChangeRenameFile)
                            | Some(FileChangeInfo::ChangeExtensionChanged)
                    );

                    let path_filter_match = if has_path_filters {
                        let path_variants = build_path_variants(filepath, &msg.filepathstr);
                        cond_group
                            .file_paths
                            .iter()
                            .chain(cond_group.staging_paths.iter())
                            .chain(cond_group.browsed_paths.iter())
                            .chain(cond_group.sensitive_paths.iter())
                            .chain(cond_group.persistence_locations.iter())
                            .any(|p| {
                                let p_norm = p.replace("\\", "/");
                                let p_norm_stripped = strip_drive_prefix(&p_norm);
                                path_variants.iter().any(|v| {
                                    Self::matches_pattern_internal(&self.regex_cache, &p_norm, v)
                                        || Self::matches_pattern_internal(
                                            &self.regex_cache,
                                            &p_norm_stripped,
                                            v,
                                        )
                                })
                            })
                    } else {
                        true
                    };

                    if path_filter_match {
                        let ext = event_extension.clone();

                        if !ext.is_empty() {
                            let ext_with_dot = format!(".{}", ext);

                            if !cond_group.file_extensions.is_empty()
                                && let Some(matched_ext) =
                                    cond_group.file_extensions.iter().find(|p| {
                                        Self::extension_pattern_matches(
                                            &self.regex_cache,
                                            p,
                                            &ext,
                                            &ext_with_dot,
                                        )
                                    })
                            {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - Extension match for PID {}: {}",
                                    cond_name, state.pid, matched_ext
                                ));
                            }

                            if !matched && cond_group.detect_non_whitelisted_extensions {
                                let whitelisted = Self::is_extension_whitelisted(
                                    &self.regex_cache,
                                    &self.default_extension_whitelist,
                                    cond_group,
                                    &ext,
                                    &ext_with_dot,
                                );
                                if !whitelisted {
                                    matched = true;
                                    // Record the stem so that a later delete/rename of the original
                                    // file can satisfy `require_same_stem_created_unknown_extension`
                                    // or `require_same_stem_written_unknown_extension`.
                                    // e.g., "c:/users/foo/document.docx.winball" → stem "c:/users/foo/document.docx"
                                    if !filepath.is_empty()
                                        && matches!(current_file_op, Some("create") | Some("write"))
                                    {
                                        let last_sep = filepath.rfind('/').unwrap_or(0);
                                        let stem = if let Some(dot_pos) = filepath.rfind('.') {
                                            if dot_pos > last_sep {
                                                filepath[..dot_pos].to_string()
                                            } else {
                                                filepath.to_string()
                                            }
                                        } else {
                                            filepath.to_string()
                                        };
                                        if stem != *filepath {
                                            if current_file_op == Some("create") {
                                                Logging::debug(&format!(
                                                    "[BehaviorEngine] Stored create stem for delete correlation (PID {}): {}",
                                                    state.pid, stem
                                                ));
                                                state.created_unknown_ext_stems.insert(stem);
                                            } else {
                                                Logging::debug(&format!(
                                                    "[BehaviorEngine] Stored write stem for rename correlation (PID {}): {}",
                                                    state.pid, stem
                                                ));
                                                state.written_unknown_ext_stems.insert(stem);
                                            }
                                        }
                                    }
                                    Logging::info(&format!(
                                        "[BehaviorEngine] Condition '{}' - Non-whitelisted extension for PID {}: {}",
                                        cond_name, state.pid, ext_with_dot
                                    ));
                                }
                            }
                        }

                        if ext.is_empty()
                            && !matched
                            && cond_group.detect_non_whitelisted_extensions
                        {
                            matched = true;
                            if !filepath.is_empty()
                                && matches!(current_file_op, Some("create") | Some("write"))
                            {
                                if current_file_op == Some("create") {
                                    state.created_unknown_ext_stems.insert(filepath.to_string());
                                } else {
                                    state.written_unknown_ext_stems.insert(filepath.to_string());
                                }
                            }
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Extensionless file matched non-whitelisted extension scan for PID {}: {}",
                                cond_name, state.pid, filepath
                            ));
                        }

                        if !matched && extension_changed {
                            if cond_group.detect_known_to_unknown_extension_change {
                                let matched_known_to_unknown = if let Some(previous_ext) =
                                    previous_extension.as_ref()
                                {
                                    let previous_ext_with_dot = format!(".{}", previous_ext);
                                    let previous_is_known = Self::is_extension_whitelisted(
                                        &self.regex_cache,
                                        &self.default_extension_whitelist,
                                        cond_group,
                                        previous_ext,
                                        &previous_ext_with_dot,
                                    );
                                    let current_is_known = if event_extension.is_empty() {
                                        false
                                    } else {
                                        let current_ext_with_dot = format!(".{}", event_extension);
                                        Self::is_extension_whitelisted(
                                            &self.regex_cache,
                                            &self.default_extension_whitelist,
                                            cond_group,
                                            &event_extension,
                                            &current_ext_with_dot,
                                        )
                                    };
                                    previous_is_known && !current_is_known
                                } else {
                                    false
                                };

                                if matched_known_to_unknown {
                                    let new_ext_label = if event_extension.is_empty() {
                                        "<extensionless>".to_string()
                                    } else {
                                        format!(".{}", event_extension)
                                    };
                                    matched = true;
                                    Logging::info(&format!(
                                        "[BehaviorEngine] Condition '{}' - Known-to-unknown extension change for PID {} (prev: .{}, new: {})",
                                        cond_name,
                                        state.pid,
                                        previous_extension.as_deref().unwrap_or(""),
                                        new_ext_label
                                    ));
                                }
                            } else if cond_group.detect_extension_changes {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - Extension-change event matched for PID {}",
                                    cond_name, state.pid
                                ));
                            }
                        }
                    }
                }

                let has_reg_conditions = !cond_group.registry_keys.is_empty()
                    || !cond_group.registry_keys_exclude.is_empty()
                    || !cond_group.autorun_keys.is_empty()
                    || !cond_group.registry_values.is_empty()
                    || !cond_group.registry_value_data_patterns.is_empty();

                if !matched
                    && has_reg_conditions
                    && *irp_op == IrpMajorOp::IrpRegistry
                    && Self::registry_op_matches(cond_group, msg, irp_op)
                {
                    let excluded = cond_group.registry_keys_exclude.iter().any(|pattern| {
                        Self::registry_pattern_matches(&self.regex_cache, pattern, filepath)
                    });

                    if excluded {
                        if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Condition '{}' excluded for PID {}: {}",
                                cond_name, state.pid, filepath
                            ));
                        }
                    } else {
                        let key_ok = if cond_group.registry_keys.is_empty()
                            && cond_group.autorun_keys.is_empty()
                        {
                            true
                        } else {
                            cond_group
                                .registry_keys
                                .iter()
                                .chain(cond_group.autorun_keys.iter())
                                .any(|pattern| {
                                    Self::registry_pattern_matches(
                                        &self.regex_cache,
                                        pattern,
                                        filepath,
                                    )
                                })
                        };

                        let value_ok = if cond_group.registry_values.is_empty() {
                            true
                        } else {
                            cond_group.registry_values.iter().any(|pattern| {
                                Self::registry_value_pattern_matches(
                                    &self.regex_cache,
                                    pattern,
                                    filepath,
                                )
                            })
                        };

                        let data = msg.kernel_event_info.object_name.trim();
                        let data_ok = if cond_group.registry_value_data_patterns.is_empty() {
                            true
                        } else {
                            !data.is_empty()
                                && cond_group
                                    .registry_value_data_patterns
                                    .iter()
                                    .any(|pattern| {
                                        Self::matches_pattern_internal(
                                            &self.regex_cache,
                                            pattern,
                                            data,
                                        )
                                    })
                        };

                        if key_ok && value_ok && data_ok {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Registry match for PID {}: {}",
                                cond_name, state.pid, filepath
                            ));
                        }
                    }
                }

                if !matched && conjunctive_process_context {
                    let child_name = msg
                        .filepathstr
                        .split(['\\', '/'])
                        .filter(|s| !s.is_empty())
                        .last()
                        .unwrap_or("")
                        .to_lowercase();
                    let child_path_norm = canonical_behavior_path(&msg.filepathstr);
                    let process_name_lc = state.app_name.to_lowercase();
                    let process_path_norm =
                        canonical_behavior_path(&state.exe_path.to_string_lossy());
                    let parent_name_lc = state.parent_name.to_lowercase();
                    let parent_path_norm =
                        canonical_behavior_path(&state.parent_path.to_string_lossy());

                    let created_process_ok = if cond_group.created_processes.is_empty() {
                        true
                    } else if *irp_op != IrpMajorOp::IrpProcessCreate {
                        false
                    } else {
                        cond_group.created_processes.iter().any(|pattern| {
                            Self::matches_process_identity_pattern(
                                &self.regex_cache,
                                pattern,
                                &child_name,
                                &child_path_norm,
                            )
                        })
                    };

                    let recent_payload_ok = if !cond_group.detect_recently_written_payload_launch {
                        true
                    } else if *irp_op != IrpMajorOp::IrpProcessCreate {
                        false
                    } else if let Some(payload_path) = Self::match_recently_written_payload_launch(
                        &self.regex_cache,
                        state,
                        cond_group,
                        &msg.filepathstr,
                        &msg.runtime_features.command_line,
                        now,
                    ) {
                        matched_artifact_path = Some(payload_path);
                        true
                    } else {
                        false
                    };

                    let process_name_ok = if cond_group.process_names.is_empty() {
                        true
                    } else {
                        cond_group.process_names.iter().any(|pattern| {
                            Self::matches_process_identity_pattern(
                                &self.regex_cache,
                                pattern,
                                &process_name_lc,
                                &process_path_norm,
                            )
                        })
                    };

                    let parent_ok = if cond_group.parent_names.is_empty() {
                        true
                    } else if parent_name_lc.is_empty() || parent_name_lc == "unknown" {
                        false
                    } else {
                        cond_group.parent_names.iter().any(|pattern| {
                            Self::matches_process_identity_pattern(
                                &self.regex_cache,
                                pattern,
                                &parent_name_lc,
                                &parent_path_norm,
                            )
                        })
                    };

                    let cmdline_source = if !cond_group.created_processes.is_empty()
                        || cond_group.detect_recently_written_payload_launch
                    {
                        msg.runtime_features.command_line.to_lowercase()
                    } else {
                        state.command_line.to_lowercase()
                    };
                    let cmdline_ok = if has_cmdline_requirements {
                        (!cond_group.cmdline_keywords.is_empty()
                            && cond_group.cmdline_keywords.iter().any(|kw| {
                                Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    kw,
                                    &cmdline_source,
                                )
                            }))
                            || (!cond_group.cmdline_patterns.is_empty()
                                && cond_group
                                    .cmdline_patterns
                                    .iter()
                                    .any(|pat| pat.matches(&self.regex_cache, &cmdline_source)))
                    } else {
                        true
                    };

                    let network_ok = !cond_group.has_network_activity || network_activity_observed;
                    let acg_ok = cond_group
                        .is_acg_enabled
                        .map_or(true, |expected| expected == state.is_acg_enabled);

                    if created_process_ok
                        && recent_payload_ok
                        && process_name_ok
                        && parent_ok
                        && cmdline_ok
                        && network_ok
                        && acg_ok
                    {
                        matched = true;
                        let subject = if let Some(payload_path) = matched_artifact_path.as_ref() {
                            payload_path.clone()
                        } else if !cond_group.created_processes.is_empty() {
                            child_name.clone()
                        } else if !process_name_lc.is_empty() {
                            process_name_lc.clone()
                        } else if !parent_name_lc.is_empty() {
                            parent_name_lc.clone()
                        } else {
                            "process-context".to_string()
                        };
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Process context match for PID {}: {}",
                            cond_name, state.pid, subject
                        ));
                    }
                }

                if !matched && !conjunctive_process_context && cond_group.is_acg_enabled.is_some() {
                    let expected_acg = cond_group.is_acg_enabled.unwrap();
                    if expected_acg == state.is_acg_enabled {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - ACG state match (expected={}) for PID {}",
                            cond_name, expected_acg, state.pid
                        ));
                    }
                }

                if !matched
                    && !conjunctive_process_context
                    && cond_group.detect_recently_written_payload_launch
                    && *irp_op == IrpMajorOp::IrpProcessCreate
                    && let Some(payload_path) = Self::match_recently_written_payload_launch(
                        &self.regex_cache,
                        state,
                        cond_group,
                        &msg.filepathstr,
                        &msg.runtime_features.command_line,
                        now,
                    )
                {
                    matched = true;
                    matched_artifact_path = Some(payload_path.clone());
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - Recently written payload launched by PID {}: {}",
                        cond_name, state.pid, payload_path
                    ));
                }

                if !matched && !conjunctive_process_context && !cond_group.parent_names.is_empty() {
                    let parent_lc = state.parent_name.to_lowercase();
                    if !parent_lc.is_empty()
                        && parent_lc != "unknown"
                        && cond_group.parent_names.iter().any(|p| {
                            Self::matches_process_identity_pattern(
                                &self.regex_cache,
                                p,
                                &parent_lc,
                                &canonical_behavior_path(&state.parent_path.to_string_lossy()),
                            )
                        })
                    {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Parent process match for PID {}: {}",
                            cond_name, state.pid, parent_lc
                        ));
                    }
                }

                if !matched && !conjunctive_process_context && has_cmdline_requirements {
                    let cmdline_lc = if cond_group.detect_recently_written_payload_launch
                        || !cond_group.created_processes.is_empty()
                    {
                        msg.runtime_features.command_line.to_lowercase()
                    } else {
                        state.command_line.to_lowercase()
                    };
                    if !cmdline_lc.is_empty() {
                        let keyword_hit = cond_group.cmdline_keywords.iter().any(|kw| {
                            Self::matches_pattern_internal(&self.regex_cache, kw, &cmdline_lc)
                        });
                        let pattern_hit = cond_group
                            .cmdline_patterns
                            .iter()
                            .any(|pat| pat.matches(&self.regex_cache, &cmdline_lc));
                        if keyword_hit || pattern_hit {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Command line match for PID {}: {}",
                                cond_name, state.pid, cmdline_lc
                            ));
                        }
                    }
                }
                if !matched && !cond_group.pipe_names.is_empty() {
                    let is_pipe_op = matches!(
                        irp_op,
                        IrpMajorOp::IrpNamedPipeCreate | IrpMajorOp::IrpNamedPipeWrite
                    );
                    if is_pipe_op {
                        let pipe_name = msg
                            .kernel_event_info
                            .object_name
                            .trim_matches('\0')
                            .to_string();
                        let name_match = cond_group.pipe_names.iter().any(|pattern| {
                            Self::matches_pattern_internal(&self.regex_cache, pattern, &pipe_name)
                        });

                        if name_match {
                            let op_match = if cond_group.pipe_operations.is_empty() {
                                true
                            } else {
                                let current_op = if *irp_op == IrpMajorOp::IrpNamedPipeCreate {
                                    "create"
                                } else {
                                    "write"
                                };
                                cond_group
                                    .pipe_operations
                                    .iter()
                                    .any(|op| op.eq_ignore_ascii_case(current_op))
                            };

                            if op_match {
                                let payload_match = if cond_group.pipe_payloads.is_empty() {
                                    true
                                } else if *irp_op == IrpMajorOp::IrpNamedPipeWrite {
                                    cond_group.pipe_payloads.iter().any(|pm| {
                                        pm.matches(
                                            &self.regex_cache,
                                            &msg.kernel_event_info.bin_payload,
                                        )
                                    })
                                } else {
                                    false
                                };

                                if payload_match {
                                    matched = true;
                                    Logging::info(&format!(
                                        "[BehaviorEngine] Condition '{}' - Named pipe match for PID {}: {} ({})",
                                        cond_name,
                                        state.pid,
                                        pipe_name,
                                        if *irp_op == IrpMajorOp::IrpNamedPipeCreate {
                                            "create"
                                        } else {
                                            "write"
                                        }
                                    ));
                                }
                            }
                        }
                    }
                }

                // script_file_patterns: match against the script file extracted
                // from the interpreter's command line (e.g. "evil.ps1" from
                // `powershell.exe -File evil.ps1`). Matches both the filename
                // and the full normalized path so rules can be as broad or
                // narrow as needed.
                if !matched
                    && !cond_group.script_file_patterns.is_empty()
                    && !state.script_file.is_empty()
                {
                    let hit = cond_group.script_file_patterns.iter().any(|pat| {
                        let p = pat.to_lowercase();
                        Self::matches_pattern_internal(&self.regex_cache, &p, &state.script_file)
                            || Self::matches_pattern_internal(
                                &self.regex_cache,
                                &p,
                                &state.script_file_path,
                            )
                    });
                    if hit {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Script file match for PID {}: {}",
                            cond_name, state.pid, state.script_file
                        ));
                    }
                }

                if !matched && !cond_group.terminated_processes.is_empty() {
                    let mut term_match = false;
                    let mut matched_victim = String::new();
                    if *irp_op == IrpMajorOp::IrpProcessTerminateAttempt
                        && let Some(victim) =
                            cond_group
                                .terminated_processes
                                .iter()
                                .find(|victim_pattern| {
                                    Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        victim_pattern,
                                        filepath,
                                    )
                                })
                    {
                        term_match = true;
                        matched_victim = victim.to_string();
                    }
                    if !term_match
                        && let Some(victim) = state.terminated_processes.iter().find(|victim| {
                            cond_group
                                .terminated_processes
                                .iter()
                                .any(|victim_pattern| {
                                    Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        victim_pattern,
                                        victim,
                                    )
                                })
                        })
                    {
                        term_match = true;
                        matched_victim = victim.to_string();
                    }
                    if term_match {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Process termination match for PID {}: {}",
                            cond_name, state.pid, matched_victim
                        ));
                    }
                }

                // created_processes: fires on IrpProcessCreate events for child processes
                // that share this GID (i.e. were spawned by the tracked parent process).
                // Also checks cmdline_keywords against the CHILD's cmdline (msg.runtime_features),
                // not the parent's stored state.command_line.
                if !matched
                    && !conjunctive_process_context
                    && *irp_op == IrpMajorOp::IrpProcessCreate
                    && !cond_group.created_processes.is_empty()
                {
                    // Extract just the filename from device or drive-letter paths.
                    // split on both \ and / to handle \Device\HarddiskVolume3\...\bcdedit.exe
                    let child_name = msg
                        .filepathstr
                        .split(['\\', '/'])
                        .filter(|s| !s.is_empty())
                        .last()
                        .unwrap_or("")
                        .to_lowercase();
                    let child_path_norm = canonical_behavior_path(&msg.filepathstr);

                    let name_match = cond_group.created_processes.iter().any(|pattern| {
                        Self::matches_process_identity_pattern(
                            &self.regex_cache,
                            pattern,
                            &child_name,
                            &child_path_norm,
                        )
                    });

                    if name_match {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Process name match for PID {}: {}",
                            cond_name, state.pid, child_name
                        ));
                    }
                }

                if !matched && !conjunctive_process_context && !cond_group.process_names.is_empty()
                {
                    let app_lc = state.app_name.to_lowercase();
                    let exe_path_lc = canonical_behavior_path(&state.exe_path.to_string_lossy());
                    if !app_lc.is_empty()
                        && cond_group.process_names.iter().any(|p| {
                            Self::matches_process_identity_pattern(
                                &self.regex_cache,
                                p,
                                &app_lc,
                                &exe_path_lc,
                            )
                        })
                    {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Process name match for PID {}: {}",
                            cond_name, state.pid, app_lc
                        ));
                    }
                }

                if !matched && state.signature_checked && cond_group.is_signed.is_some() {
                    let check_signed = cond_group.is_signed.unwrap();
                    if state.is_signed == check_signed {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature state match for PID {}: is_signed={}",
                            cond_name, state.pid, state.is_signed
                        ));
                    }
                }

                if !matched && state.signature_checked && cond_group.is_valid_signed.is_some() {
                    let check_valid = cond_group.is_valid_signed.unwrap();
                    if state.has_valid_signature == check_valid {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Valid signature match for PID {}: has_valid_signature={}",
                            cond_name, state.pid, state.has_valid_signature
                        ));
                    }
                }

                if !matched && state.signature_checked && cond_group.requires_signed.is_some() {
                    let must_be_signed = cond_group.requires_signed.unwrap();
                    if state.is_signed == must_be_signed {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Required signature match for PID {}: requires_signed={}",
                            cond_name, state.pid, must_be_signed
                        ));
                    }
                }

                if !matched && state.signature_checked && cond_group.signature_status.is_some() {
                    let expected = cond_group
                        .signature_status
                        .as_ref()
                        .unwrap()
                        .trim()
                        .to_ascii_lowercase();
                    if state.signature_status.eq_ignore_ascii_case(&expected) {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature status match for PID {}: status={}",
                            cond_name, state.pid, state.signature_status
                        ));
                    }
                }

                if !matched && state.signature_checked && !cond_group.signature_statuses.is_empty()
                {
                    if cond_group.signature_statuses.iter().any(|expected| {
                        state.signature_status.eq_ignore_ascii_case(expected.trim())
                    }) {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature status list match for PID {}: status={}",
                            cond_name, state.pid, state.signature_status
                        ));
                    }
                }

                if !matched
                    && state.signature_checked
                    && cond_group.signature_verification_failed.is_some()
                {
                    let expected = cond_group.signature_verification_failed.unwrap();
                    if state.signature_verification_failed == expected {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature verification_failed match for PID {}: {}",
                            cond_name, state.pid, state.signature_verification_failed
                        ));
                    }
                }

                if !matched
                    && state.signature_checked
                    && cond_group.signature_no_signature.is_some()
                {
                    let expected = cond_group.signature_no_signature.unwrap();
                    if state.signature_no_signature == expected {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature no_signature match for PID {}: {}",
                            cond_name, state.pid, state.signature_no_signature
                        ));
                    }
                }

                if !matched
                    && state.signature_checked
                    && cond_group.signature_status_issues.is_some()
                {
                    let expected = cond_group.signature_status_issues.unwrap();
                    if state.signature_status_issues == expected {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature status_issues match for PID {}: {}",
                            cond_name, state.pid, state.signature_status_issues
                        ));
                    }
                }

                if !matched && state.signature_checked && cond_group.signature_invalid.is_some() {
                    let expected = cond_group.signature_invalid.unwrap();
                    if state.signature_invalid == expected {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature invalid match for PID {}: {}",
                            cond_name, state.pid, state.signature_invalid
                        ));
                    }
                }

                if !matched && state.signature_checked && cond_group.signature_hresult.is_some() {
                    if state.signature_raw_hresult == cond_group.signature_hresult {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature HRESULT match for PID {}: 0x{:08X}",
                            cond_name,
                            state.pid,
                            state.signature_raw_hresult.unwrap_or_default()
                        ));
                    }
                }

                if !matched && state.signature_checked && !cond_group.signature_hresults.is_empty()
                {
                    if state
                        .signature_raw_hresult
                        .is_some_and(|hr| cond_group.signature_hresults.contains(&hr))
                    {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature HRESULT list match for PID {}: 0x{:08X}",
                            cond_name,
                            state.pid,
                            state.signature_raw_hresult.unwrap_or_default()
                        ));
                    }
                }

                if !matched && state.signature_checked {
                    if let Some(pattern) = &cond_group.signature_status_text_pattern {
                        if Self::matches_pattern_internal(
                            &self.regex_cache,
                            pattern,
                            &state.signature_status_text,
                        ) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Signature status text match for PID {}: {}",
                                cond_name, state.pid, state.signature_status_text
                            ));
                        }
                    }
                }

                if !matched && state.signature_checked {
                    let signer = state.signer_name.as_deref().unwrap_or("");
                    if !signer.is_empty() {
                        if let Some(pattern) = &cond_group.signer_pattern {
                            if Self::matches_pattern_internal(&self.regex_cache, pattern, signer) {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - Signer pattern match for PID {}: {}",
                                    cond_name, state.pid, signer
                                ));
                            }
                        }
                    }
                }

                if !matched && state.signature_checked {
                    let signer = state.signer_name.as_deref().unwrap_or("");
                    if !signer.is_empty() && !cond_group.signer_patterns.is_empty() {
                        if cond_group.signer_patterns.iter().any(|pattern| {
                            Self::matches_pattern_internal(&self.regex_cache, pattern, signer)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Signer pattern list match for PID {}: {}",
                                cond_name, state.pid, signer
                            ));
                        }
                    }
                }

                if !matched && state.signature_checked {
                    let signer = state.signer_name.as_deref().unwrap_or("");
                    if !signer.is_empty()
                        && !cond_group.trusted_signers.is_empty()
                        && state.has_valid_signature
                    {
                        if cond_group.trusted_signers.iter().any(|pattern| {
                            Self::matches_pattern_internal(&self.regex_cache, pattern, signer)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Trusted signer match for PID {}: {}",
                                cond_name, state.pid, signer
                            ));
                        }
                    }
                }

                if !matched && state.signature_checked {
                    let signer = state.signer_name.as_deref().unwrap_or("");
                    if !signer.is_empty()
                        && !cond_group.untrusted_signers.is_empty()
                        && !state.has_valid_signature
                    {
                        if cond_group.untrusted_signers.iter().any(|pattern| {
                            Self::matches_pattern_internal(&self.regex_cache, pattern, signer)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Untrusted signer match for PID {}: {}",
                                cond_name, state.pid, signer
                            ));
                        }
                    }
                }

                if !matched
                    && cond_group.detect_hypervisor_event
                    && state.hypervisor_event_count
                        >= cond_group.hypervisor_event_threshold.max(1) as u32
                {
                    matched = true;
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - API hooking fallback detected for PID {}: {} events",
                        cond_name, state.pid, state.hypervisor_event_count
                    ));
                }

                if matched {
                    let scoped_name = Self::scoped_condition_name(rule, cond_name);
                    let match_key = if let Some(path) = matched_artifact_path.as_ref() {
                        path.clone()
                    } else if !filepath.is_empty() {
                        filepath.to_string()
                    } else if !msg.filepathstr.is_empty() {
                        msg.filepathstr.to_lowercase().replace("\\", "/")
                    } else if msg.file_id_id.0 != 0 {
                        format!(
                            "fileid:{:016x}:op{}:chg{}",
                            msg.file_id_id.0, msg.irp_op, msg.file_change
                        )
                    } else {
                        let event_ts = msg
                            .time
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        format!(
                            "event:{}:pid{}:op{}:{}",
                            cond_name, msg.pid, msg.irp_op, event_ts
                        )
                    };
                    let values = state
                        .condition_match_values
                        .entry(scoped_name.clone())
                        .or_insert_with(HashSet::new);
                    if values.len() > 256 {
                        values.clear();
                    }
                    let is_new = values.insert(match_key.clone());
                    let count = state
                        .condition_match_counts
                        .entry(scoped_name.clone())
                        .or_insert(0);
                    if is_new {
                        *count += 1;
                    }
                    state
                        .condition_first_seen
                        .entry(scoped_name.clone())
                        .or_insert(now);
                    state.condition_last_seen.insert(scoped_name.clone(), now);

                    let required = if cond_group.min_matches > 0 {
                        cond_group.min_matches
                    } else {
                        1
                    };
                    if *count >= required {
                        state.satisfied_named_conditions.insert(scoped_name);
                        if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Named condition '{}' satisfied for PID {} (count: {}/{}, matches: {})",
                                cond_name, state.pid, *count, required, match_key
                            ));
                        }
                    } else if is_new && (rule.debug || self.rules.iter().any(|r| r.debug)) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition '{}' match #{}/{} for PID {} ({})",
                            cond_name, *count, required, state.pid, match_key
                        ));
                    }
                }
            }
        }

        precord.remember_extension_observation(msg, &event_extension);
    }

    fn evaluate_detection_condition(
        &self,
        condition: &DetectionCondition,
        state: &ProcessBehaviorState,
        rule: &BehaviorRule,
    ) -> bool {
        match condition {
            DetectionCondition::Named {
                condition: cond_name,
            } => Self::rule_condition_satisfied(state, rule, cond_name),

            DetectionCondition::And { and } => and
                .iter()
                .all(|c| self.evaluate_detection_condition(c, state, rule)),

            DetectionCondition::Or { or } => or
                .iter()
                .any(|c| self.evaluate_detection_condition(c, state, rule)),

            DetectionCondition::Not { not } => !self.evaluate_detection_condition(not, state, rule),

            DetectionCondition::AllOf { all_of } => all_of
                .iter()
                .all(|cond_name| Self::rule_condition_satisfied(state, rule, cond_name)),

            DetectionCondition::AnyOf { any_of } => any_of
                .iter()
                .any(|cond_name| Self::rule_condition_satisfied(state, rule, cond_name)),

            DetectionCondition::NOf { n_of, conditions } => {
                let satisfied_count = conditions
                    .iter()
                    .filter(|cond_name| Self::rule_condition_satisfied(state, rule, cond_name))
                    .count();
                satisfied_count == *n_of
            }

            DetectionCondition::AtLeast {
                at_least,
                conditions,
            } => {
                let satisfied_count = conditions
                    .iter()
                    .filter(|cond_name| Self::rule_condition_satisfied(state, rule, cond_name))
                    .count();
                satisfied_count >= *at_least
            }

            DetectionCondition::AllOfPattern { all_of_pattern } => {
                let matching_conditions: Vec<_> = rule
                    .named_conditions
                    .keys()
                    .filter(|cond_name| {
                        Self::rule_condition_satisfied(state, rule, cond_name)
                            && Self::matches_pattern_internal(
                                &self.regex_cache,
                                all_of_pattern,
                                cond_name,
                            )
                    })
                    .collect();
                !matching_conditions.is_empty()
            }

            DetectionCondition::AnyOfPattern { any_of_pattern } => {
                rule.named_conditions.keys().any(|cond_name| {
                    Self::rule_condition_satisfied(state, rule, cond_name)
                        && Self::matches_pattern_internal(
                            &self.regex_cache,
                            any_of_pattern,
                            cond_name,
                        )
                })
            }

            DetectionCondition::Count {
                count,
                comparison,
                threshold,
            } => {
                let satisfied_count = count
                    .iter()
                    .filter(|cond_name| Self::rule_condition_satisfied(state, rule, cond_name))
                    .count();
                match comparison {
                    Comparison::Gt => satisfied_count > *threshold,
                    Comparison::Gte => satisfied_count >= *threshold,
                    Comparison::Lt => satisfied_count < *threshold,
                    Comparison::Lte => satisfied_count <= *threshold,
                    Comparison::Eq => satisfied_count == *threshold,
                    Comparison::Ne => satisfied_count != *threshold,
                }
            }

            DetectionCondition::Percentage {
                percentage,
                comparison,
                threshold,
            } => {
                if percentage.is_empty() {
                    return false;
                }
                let satisfied_count = percentage
                    .iter()
                    .filter(|cond_name| Self::rule_condition_satisfied(state, rule, cond_name))
                    .count();
                let ratio = satisfied_count as f32 / percentage.len() as f32;
                match comparison {
                    Comparison::Gt => ratio > *threshold,
                    Comparison::Gte => ratio >= *threshold,
                    Comparison::Lt => ratio < *threshold,
                    Comparison::Lte => ratio <= *threshold,
                    Comparison::Eq => (ratio - threshold).abs() < 0.001,
                    Comparison::Ne => (ratio - threshold).abs() >= 0.001,
                }
            }
        }
    }

    fn check_rules(
        &mut self,
        precord: &mut ProcessRecord,
        gid: u64,
        msg: &IOMessage,
        _irp_op: IrpMajorOp,
        config: &Config,
        actions: &mut ActionsOnKill,
    ) {
        let state_ref = match self.process_states.get_mut(&gid) {
            Some(s) => {
                let pid = s.pid;
                #[cfg(all(target_os = "windows", feature = "firewall"))]
                {
                    // Sync HTTP body entries from the shared map into the per-process state.
                    if let Ok(mut body_map) = self.firewall_http_body_map.write() {
                        if let Some(entries) = body_map.remove(&pid) {
                            s.http_body_entries.extend(entries);
                        }
                    }
                    // Sync detailed PacketInfo objects.
                    if let Ok(mut pkt_map) = self.firewall_full_packets.write() {
                        if let Some(packets) = pkt_map.remove(&pid) {
                            for p in packets {
                                if s.net_packets.len() >= 500 {
                                    s.net_packets.pop_front();
                                }
                                s.net_packets.push_back(p);
                            }
                        }
                    }
                }
                // Sync Sanctum telemetry stats.
                #[cfg(all(target_os = "windows", feature = "sanctum"))]
                if let Ok(mut sanctum_lock) = self.firewall_sanctum_stats.write() {
                    if let Some(stats) = sanctum_lock.remove(&pid) {
                        s.sanctum_stats.syscall_count += stats.syscall_count;
                        s.sanctum_stats.is_detection |= stats.is_detection;
                        s.sanctum_stats.injection_score =
                            (s.sanctum_stats.injection_score + stats.injection_score).min(1.0);
                        s.sanctum_stats.cross_process_handle_count +=
                            stats.cross_process_handle_count;
                        s.sanctum_stats.shellcode_patterns_found |= stats.shellcode_patterns_found;
                        s.sanctum_stats.last_event = stats.last_event;
                        for hit in stats.suspicious_syscall_hits {
                            if !s.sanctum_stats.suspicious_syscall_hits.contains(&hit) {
                                s.sanctum_stats.suspicious_syscall_hits.push(hit);
                            }
                        }
                        if s.sanctum_stats.suspicious_syscall_hits.len() > 50 {
                            s.sanctum_stats.suspicious_syscall_hits.remove(0);
                        }

                        // Sync forensic Ghost Hunting telemetry
                        for ghost in stats.ghost_telemetry {
                            s.sanctum_stats.ghost_telemetry.push(ghost);
                        }
                        if s.sanctum_stats.ghost_telemetry.len() > 100 {
                            let drain = s.sanctum_stats.ghost_telemetry.len() - 100;
                            s.sanctum_stats.ghost_telemetry.drain(0..drain);
                        }
                    }
                }
                if let Ok(mut openedr_lock) = self.openedr_stats.write() {
                    if let Some(stats) = openedr_lock.remove(&pid) {
                        for alias in stats.detected_apis {
                            s.detected_apis.insert(alias.clone());
                            s.all_apis_called.insert(alias);
                        }
                        for event in stats.recent_events {
                            if s.recent_kernel_api_events.len() >= 128 {
                                s.recent_kernel_api_events.pop_front();
                            }
                            s.recent_kernel_api_events
                                .push_back(format!("openedr:{}", event));
                        }
                        if let Some(label) = stats.cloud_static_label {
                            s.cloud_static_label = Some(label);
                        }
                        if let Some(label) = stats.cloud_dynamic_label {
                            s.cloud_dynamic_label = Some(label);
                        }
                        s.cloud_static_verdict = stats.cloud_static_verdict;
                        s.cloud_dynamic_verdict = stats.cloud_dynamic_verdict;
                    }
                }
                s.clone()
            }
            None => return,
        };

        if precord.is_malicious && precord.time_killed.is_some() {
            return;
        }

        for rule in &self.rules {
            if precord.is_malicious && precord.time_killed.is_some() {
                break;
            }

            let script_file_opt = if state_ref.script_file.is_empty() {
                None
            } else {
                Some(state_ref.script_file.as_str())
            };
            if self.check_allowlist(
                &precord.appname,
                rule,
                Some(&precord.exepath),
                script_file_opt,
            ) {
                continue;
            }

            // Cloud Trust Filter: only OpenEDR FLS Safe (code 1) may bypass.
            // Labels such as "clean", "trusted", or "safe" are display-only and never drive decisions.
            if rule.should_trust_comodo_cloud {
                let is_cloud_allowed = is_openedr_fls_safe_code(state_ref.cloud_static_verdict)
                    || is_openedr_fls_safe_code(state_ref.cloud_dynamic_verdict);

                let mut alert_sources = Vec::new();
                if state_ref.rootkit_implicated || !state_ref.rootkit_findings.is_empty() {
                    alert_sources.push("Rootkit");
                }
                if !state_ref.observed_hypervisor_event_labels.is_empty() {
                    alert_sources.push("Hypervisor");
                }
                if !state_ref.recent_kernel_api_events.is_empty() {
                    alert_sources.push("KernelApiAlert");
                }
                if !state_ref.satisfied_named_conditions.is_empty() {
                    alert_sources.push("BehavioralConditions");
                }
                if !state_ref.detected_apis.is_empty() {
                    alert_sources.push("SuspiciousApiCall");
                }
                if state_ref.high_entropy_detected {
                    alert_sources.push("HighEntropy");
                }
                if state_ref.file_action_detected {
                    alert_sources.push("FileAction");
                }
                if state_ref.extension_match_detected {
                    alert_sources.push("ExtensionMatch");
                }

                #[cfg(all(target_os = "windows", feature = "sanctum"))]
                {
                    if !state_ref.sanctum_suspicious_hits.is_empty() {
                        alert_sources.push("Sanctum");
                    }
                }

                let has_behavioral_alerts = !alert_sources.is_empty();

                if is_cloud_allowed && !has_behavioral_alerts {
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] OpenEDR cloud verdict allowed PID {} (static={:?}, dynamic={:?}): bypass rule '{}'",
                            state_ref.pid,
                            state_ref.cloud_static_verdict,
                            state_ref.cloud_dynamic_verdict,
                            rule.name
                        ));
                    }
                    continue;
                } else if is_cloud_allowed && has_behavioral_alerts {
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] OpenEDR cloud verdict allowed but bypass ignored due to behavioral alerts from {:?} for PID {} (Rule: '{}')",
                            alert_sources, state_ref.pid, rule.name
                        ));
                    }
                }
            }

            let browsed_access_count = state_ref.browsed_paths_tracker.len();
            let has_staged_data = !state_ref.staged_files_written.is_empty();
            let is_online = if rule.require_internet {
                self.has_network_activity(&state_ref)
            } else {
                true
            };
            let parent_name = state_ref.parent_name.clone();
            let is_suspicious_parent = if !rule.suspicious_parents.is_empty() {
                let parent_lc = parent_name.to_lowercase();
                if parent_lc.is_empty() || parent_lc == "unknown" {
                    false
                } else {
                    rule.suspicious_parents
                        .iter()
                        .any(|p| Self::matches_pattern_internal(&self.regex_cache, p, &parent_lc))
                }
            } else {
                false
            };
            let has_sensitive_access = !state_ref.accessed_paths_tracker.is_empty();

            let mut legacy_satisfied = 0;
            let mut legacy_total = 0;

            if !rule.browsed_paths.is_empty() {
                legacy_total += 1;
                if browsed_access_count >= rule.multi_access_threshold {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'browsed_paths' matched for PID {}: {} paths >= {}",
                            state_ref.pid, browsed_access_count, rule.multi_access_threshold
                        ));
                    }
                }
            }
            if !rule.staging_paths.is_empty() {
                legacy_total += 1;
                if has_staged_data {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'staging_paths' matched for PID {}: {} files staged",
                            state_ref.pid,
                            state_ref.staged_files_written.len()
                        ));
                    }
                }
            }
            if rule.require_internet {
                legacy_total += 1;
                if is_online {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'require_internet' matched for PID {}: has detected network activity",
                            state_ref.pid
                        ));
                    }
                }
            }
            if !rule.suspicious_parents.is_empty() {
                legacy_total += 1;
                if is_suspicious_parent {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'suspicious_parents' matched for PID {}: parent '{}'",
                            state_ref.pid, parent_name
                        ));
                    }
                }
            }
            if !rule.accessed_paths.is_empty() {
                legacy_total += 1;
                if has_sensitive_access {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'accessed_paths' matched for PID {}: {} sensitive paths",
                            state_ref.pid,
                            state_ref.accessed_paths_tracker.len()
                        ));
                    }
                }
            }
            if rule.entropy_threshold > 0.01 {
                legacy_total += 1;
                if state_ref.high_entropy_detected {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'entropy_threshold' matched for PID {}",
                            state_ref.pid
                        ));
                    }
                }
            }
            if !rule.monitored_apis.is_empty() {
                legacy_total += 1;
                let api_match_count = rule
                    .monitored_apis
                    .iter()
                    .filter(|monitored_api| {
                        let (monitored_norm, monitored_has_path) =
                            Self::normalize_api_signature(monitored_api);
                        state_ref.all_apis_called.iter().any(|tracked_api| {
                            let (tracked_norm, tracked_has_path) =
                                Self::normalize_api_signature(tracked_api);
                            if monitored_has_path {
                                tracked_has_path
                                    && Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        monitored_api,
                                        tracked_api,
                                    )
                            } else {
                                Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    &monitored_norm,
                                    &tracked_norm,
                                )
                            }
                        })
                    })
                    .count();
                let threshold = std::cmp::max(1, rule.multi_access_threshold);
                if api_match_count >= threshold {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'monitored_apis' matched for PID {}: {} APIs",
                            state_ref.pid, api_match_count
                        ));
                    }
                }
            }
            if !rule.file_actions.is_empty() {
                legacy_total += 1;
                if state_ref.file_action_detected {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'file_actions' matched for PID {}",
                            state_ref.pid
                        ));
                    }
                }
            }
            if !rule.file_extensions.is_empty() {
                legacy_total += 1;
                if state_ref.extension_match_detected {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'file_extensions' matched for PID {}",
                            state_ref.pid
                        ));
                    }
                }
            }
            if !rule.terminated_processes.is_empty() {
                legacy_total += 1;
                let term_hit = rule.terminated_processes.iter().any(|rule_proc| {
                    let ext_match = state_ref
                        .terminated_processes
                        .iter()
                        .any(|v| Self::matches_pattern_internal(&self.regex_cache, rule_proc, v));
                    let self_match = rule.detect_self_termination
                        && state_ref.self_terminated_processes.iter().any(|v| {
                            Self::matches_pattern_internal(&self.regex_cache, rule_proc, v)
                        });
                    ext_match || self_match
                });
                if term_hit {
                    legacy_satisfied += 1;
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Condition 'terminated_processes' matched for PID {}",
                            state_ref.pid
                        ));
                    }
                }
            }

            #[cfg(all(target_os = "windows", feature = "firewall"))]
            {
                if !rule.http_request_body_patterns.is_empty() {
                    legacy_total += 1;
                    let matched = state_ref.http_body_entries.iter().any(|(req_body, _)| {
                        rule.http_request_body_patterns
                            .iter()
                            .any(|pat| req_body.contains(pat.as_str()))
                    });
                    if matched {
                        legacy_satisfied += 1;
                        if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Condition 'http_request_body_patterns' matched for PID {}",
                                state_ref.pid
                            ));
                        }
                    }
                }
                if !rule.http_response_body_patterns.is_empty() {
                    legacy_total += 1;
                    let matched = state_ref.http_body_entries.iter().any(|(_, resp_body)| {
                        rule.http_response_body_patterns
                            .iter()
                            .any(|pat| resp_body.contains(pat.as_str()))
                    });
                    if matched {
                        legacy_satisfied += 1;
                        if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Condition 'http_response_body_patterns' matched for PID {}",
                                state_ref.pid
                            ));
                        }
                    }
                }
            }

            let legacy_ratio = if legacy_total > 0 {
                legacy_satisfied as f32 / legacy_total as f32
            } else {
                0.0
            };
            let legacy_threshold = if rule.conditions_percentage > 0.0 {
                rule.conditions_percentage
            } else {
                1.0
            };
            let legacy_triggered = legacy_total > 0 && legacy_ratio >= legacy_threshold;

            if legacy_total > 0
                && legacy_ratio > 0.0
                && legacy_ratio < legacy_threshold
                && (rule.debug || self.rules.iter().any(|r| r.debug))
            {
                Logging::debug(&format!(
                    "[BehaviorEngine] Partial match on rule '{}' for PID {}: {}/{} conditions met ({:.1}% < {:.1}% required)",
                    rule.name,
                    state_ref.pid,
                    legacy_satisfied,
                    legacy_total,
                    legacy_ratio * 100.0,
                    legacy_threshold * 100.0
                ));
            }

            let mut rich_triggered = false;
            if let Some(logic) = &rule.detection_logic {
                rich_triggered = self.evaluate_detection_condition(logic, &state_ref, rule);
                if rich_triggered
                    && !Self::rule_has_current_named_condition_match(&state_ref, rule, msg.time)
                {
                    if rule.debug || self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Skipping stale rich-logic trigger for '{}' on PID {}: current event did not satisfy a rule condition",
                            rule.name, state_ref.pid
                        ));
                    }
                    rich_triggered = false;
                }
            }
            let mut stages_triggered = false;
            let mut stage_conf = 0.0;
            if !rule.stages.is_empty() {
                let (detected, conf) = self.evaluate_stages_from_state(rule, &state_ref, Some(msg));
                stages_triggered = detected;
                stage_conf = conf;
            }

            if legacy_triggered || rich_triggered || stages_triggered {
                let trigger_type = if stages_triggered {
                    "Stage-based"
                } else if rich_triggered {
                    "Rich-logic"
                } else {
                    "Legacy"
                };

                let indicator_ratio = if stages_triggered {
                    stage_conf
                } else if rich_triggered {
                    1.0
                } else {
                    legacy_ratio
                };

                #[cfg_attr(
                    not(all(target_os = "windows", feature = "firewall")),
                    allow(unused_mut)
                )]
                let mut prompted_deny = false;
                #[cfg_attr(
                    not(all(target_os = "windows", feature = "firewall")),
                    allow(unused_mut)
                )]
                let mut prompted_block = false;
                #[cfg_attr(
                    not(all(target_os = "windows", feature = "firewall")),
                    allow(unused_mut)
                )]
                let mut prompted_quarantine = false;
                #[cfg(all(target_os = "windows", feature = "firewall"))]
                if rule.response.ask_user {
                    match self.resolve_firewall_hips_prompt(gid, &state_ref, rule) {
                        FirewallHipsPromptOutcome::Pending => {
                            // Block the process while waiting for the user's decision
                            if rule.response.deny_while_ask {
                                let pending_match_details = Self::build_rule_match_details(
                                    rule,
                                    &state_ref,
                                    Some(msg),
                                    Some(trigger_type),
                                    Some(indicator_ratio),
                                );
                                let pending_threat = ThreatInfo {
                                    threat_type_label: "HIPS Pending",
                                    virus_name: &rule.name,
                                    prediction: 0.0,
                                    match_details: Some(if pending_match_details.is_empty() {
                                        format!("Awaiting user decision for rule '{}'", rule.name)
                                    } else {
                                        format!(
                                            "Awaiting user decision for rule '{}' | {}",
                                            rule.name, pending_match_details
                                        )
                                    }),
                                    deny_access: true,
                                    terminate: false,
                                    quarantine: false,
                                    kill_and_remove: false,
                                    suspend: false,
                                    notify_user: false,
                                    revert: false,
                                };
                                let dummy = VecvecCappedF32::new(0, 0);
                                actions.run_actions_with_info(
                                    config,
                                    precord,
                                    &dummy,
                                    &pending_threat,
                                );
                                Logging::info(&format!(
                                    "[BehaviorEngine] HIPS pending: deny_while_ask active for '{}' (PID: {})",
                                    rule.name, state_ref.pid
                                ));
                            }
                            if rule.response.suspend_while_ask {
                                Logging::info(&format!(
                                    "[BehaviorEngine] HIPS pending: suspend_while_ask active for '{}' (PID: {})",
                                    rule.name, state_ref.pid
                                ));
                                precord.process_state = ProcessState::Suspended;
                                for &pid in &precord.pids {
                                    unsafe {
                                        let _ = windows::Win32::System::Diagnostics::Debug::DebugActiveProcess(pid);
                                    }
                                }
                            }
                            continue;
                        }
                        FirewallHipsPromptOutcome::Allowed => {
                            // User allowed — resume if previously suspended
                            if rule.response.suspend_while_ask
                                && precord.process_state == ProcessState::Suspended
                            {
                                Logging::info(&format!(
                                    "[BehaviorEngine] HIPS allowed: resuming suspended process '{}' (PID: {})",
                                    precord.appname, state_ref.pid
                                ));
                                precord.process_state = ProcessState::Running;
                                for &pid in &precord.pids {
                                    unsafe {
                                        let _ = windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop(pid);
                                    }
                                }
                            }
                            continue;
                        }
                        FirewallHipsPromptOutcome::Deny => {
                            prompted_deny = true;
                        }
                        FirewallHipsPromptOutcome::Block => {
                            prompted_block = true;
                        }
                        FirewallHipsPromptOutcome::Quarantine => {
                            prompted_block = true;
                            prompted_quarantine = true;
                        }
                    }
                }

                // Private rules don't generate detections (YARA-style behavior)
                // They are evaluated and can be used by other rules, but don't produce alerts
                if rule.is_private {
                    continue;
                }

                Logging::warning(&format!(
                    "[BehaviorEngine] DETECTION ({}) : {} (PID: {}) matched '{}' ({:.1}%)",
                    trigger_type,
                    precord.appname,
                    state_ref.pid,
                    rule.name,
                    indicator_ratio * 100.0
                ));

                precord.is_malicious = true;
                let mut threat_info = ThreatInfo {
                    threat_type_label: match rule.level {
                        DetectionLevel::Informational => "Informational",
                        DetectionLevel::Low => "Low Severity",
                        DetectionLevel::Medium => "Behavioral Detection",
                        DetectionLevel::High => "High Severity Threat",
                        DetectionLevel::Critical => "Critical Threat",
                    },
                    virus_name: &rule.name,
                    prediction: indicator_ratio,
                    match_details: Some(Self::build_rule_match_details(
                        rule,
                        &state_ref,
                        Some(msg),
                        Some(trigger_type),
                        Some(indicator_ratio),
                    )),
                    deny_access: if rule.response.ask_user {
                        (prompted_deny || prompted_block || prompted_quarantine)
                            && rule.response.status_access_denied
                    } else {
                        rule.response.status_access_denied
                    },
                    terminate: if rule.response.ask_user {
                        if prompted_deny {
                            false
                        } else {
                            prompted_block || prompted_quarantine || rule.response.terminate_process
                        }
                    } else {
                        rule.response.terminate_process
                    },
                    quarantine: if rule.response.ask_user {
                        prompted_quarantine
                    } else {
                        rule.response.quarantine
                    },
                    kill_and_remove: if rule.response.ask_user {
                        false
                    } else {
                        rule.response.kill_and_remove
                    },
                    suspend: if rule.response.ask_user {
                        false
                    } else {
                        rule.response.suspend_process
                    },
                    notify_user: rule.response.notify_user,
                    revert: rule.response.auto_revert,
                };

                // FAIL-FAST SAFETY GUARD: Prevent rule-based termination of critical system processes
                if (threat_info.terminate || threat_info.quarantine || threat_info.kill_and_remove)
                    && let Some(reason) = crate::utils::protected_process_record_reason(precord)
                {
                    Logging::warning(&format!(
                        "[BehaviorEngine] Rule '{}' triggered termination for protected process {} (GID: {}), but it was BLOCKED: {}",
                        rule.name, precord.appname, precord.gid, reason
                    ));
                    threat_info.terminate = false;
                    threat_info.quarantine = false;
                    threat_info.kill_and_remove = false;
                }

                let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                actions.run_actions_with_info(config, precord, &dummy_pred_mtrx, &threat_info);
                self.process_terminated
                    .insert(precord.appname.to_lowercase());

                if threat_info.terminate {
                    break;
                }
            }
        }
    }

    fn api_candidate_matches(
        &self,
        name_pattern: &str,
        module_pattern: &str,
        candidate: &str,
    ) -> bool {
        let (candidate_norm, _) = Self::normalize_api_signature(candidate);
        let function_part = candidate_norm
            .rsplit('!')
            .next()
            .unwrap_or(candidate_norm.as_str());
        let module_part = candidate_norm.split('!').next().unwrap_or("");

        let name_ok = name_pattern.trim().is_empty()
            || name_pattern.trim() == "*"
            || Self::matches_pattern_internal(&self.regex_cache, name_pattern, function_part)
            || Self::matches_pattern_internal(&self.regex_cache, name_pattern, &candidate_norm)
            || Self::matches_pattern_internal(&self.regex_cache, name_pattern, candidate);

        let module_ok = module_pattern.trim().is_empty()
            || module_pattern.trim() == "*"
            || Self::matches_pattern_internal(&self.regex_cache, module_pattern, module_part)
            || Self::matches_pattern_internal(&self.regex_cache, module_pattern, &candidate_norm)
            || Self::matches_pattern_internal(&self.regex_cache, module_pattern, candidate);

        name_ok && module_ok
    }

    fn latest_api_match_time(
        &self,
        state: &ProcessBehaviorState,
        name_pattern: &str,
        module_pattern: &str,
        arguments: &[crate::behavioral::rule_types::ApiArgument],
    ) -> Option<SystemTime> {
        state
            .irp_operations
            .iter()
            .rev()
            .find(|record| {
                !record.function_name.trim().is_empty()
                    && self.api_candidate_matches(
                        name_pattern,
                        module_pattern,
                        &record.function_name,
                    )
                    && (arguments.is_empty()
                        || arguments
                            .iter()
                            .all(|req_arg| Self::api_argument_matches(req_arg, record)))
            })
            .map(|record| record.timestamp)
    }

    fn evaluate_multi_condition_window(
        &self,
        conditions: &[RuleCondition],
        operator: Option<&String>,
        min_matches: Option<usize>,
        within_ms: Option<u64>,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>,
    ) -> bool {
        let op = operator
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_else(|| "all".to_string());
        let required_matches = min_matches.unwrap_or_else(|| {
            if matches!(op.as_str(), "any" | "or") {
                1
            } else {
                conditions.len()
            }
        });

        if let Some(window_ms) = within_ms {
            let mut match_count = 0usize;
            let mut timestamps = Vec::new();

            for condition in conditions {
                match condition {
                    RuleCondition::Api {
                        functions,
                        arguments,
                        module_pattern,
                        ..
                    } => {
                        let mut best_ts = None;
                        for name_pattern in functions {
                            if let Some(ts) = self.latest_api_match_time(
                                state,
                                name_pattern,
                                module_pattern,
                                arguments,
                            ) {
                                if best_ts.is_none() || ts > best_ts.unwrap() {
                                    best_ts = Some(ts);
                                }
                            }
                        }
                        if let Some(ts) = best_ts {
                            match_count += 1;
                            timestamps.push(ts);
                        }
                    }
                    _ => {
                        if self.evaluate_rule_condition(condition, state, msg) {
                            match_count += 1;
                        }
                    }
                }
            }

            if match_count < required_matches {
                return false;
            }

            if timestamps.len() <= 1 {
                return true;
            }

            let min_ts = timestamps.iter().min().copied().unwrap();
            let max_ts = timestamps.iter().max().copied().unwrap();
            return max_ts
                .duration_since(min_ts)
                .map(|duration| duration.as_millis() <= u128::from(window_ms))
                .unwrap_or(false);
        }

        let match_count = conditions
            .iter()
            .filter(|condition| self.evaluate_rule_condition(condition, state, msg))
            .count();

        match_count >= required_matches
    }

    fn evaluate_process_tree_condition(
        &self,
        parent_patterns: &[String],
        child_patterns: &[String],
        ancestor_patterns: &[String],
        command_line_patterns: &[CommandLinePattern],
        max_depth: Option<u32>,
        require_current_process: bool,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>,
    ) -> bool {
        let parent_name = state.parent_name.to_lowercase();
        let parent_path = canonical_behavior_path(&state.parent_path.to_string_lossy());
        let child_name = state.app_name.to_lowercase();
        let child_path = canonical_behavior_path(&state.exe_path.to_string_lossy());
        let event_path = msg
            .map(|m| canonical_behavior_path(&m.filepathstr))
            .unwrap_or_default();
        let cmdline = msg
            .and_then(|m| {
                let value = m.runtime_features.command_line.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_lowercase())
                }
            })
            .unwrap_or_else(|| state.command_line.to_lowercase());

        let parent_ok = parent_patterns.is_empty()
            || parent_patterns.iter().any(|pattern| {
                Self::matches_pattern_internal(&self.regex_cache, pattern, &parent_name)
                    || Self::matches_pattern_internal(&self.regex_cache, pattern, &parent_path)
            });

        let child_ok = child_patterns.is_empty()
            || child_patterns.iter().any(|pattern| {
                Self::matches_pattern_internal(&self.regex_cache, pattern, &child_name)
                    || Self::matches_pattern_internal(&self.regex_cache, pattern, &child_path)
                    || (!require_current_process
                        && Self::matches_pattern_internal(&self.regex_cache, pattern, &event_path))
            });

        let ancestor_ok = ancestor_patterns.is_empty()
            || max_depth.unwrap_or(1) == 0
            || ancestor_patterns.iter().any(|pattern| {
                Self::matches_pattern_internal(&self.regex_cache, pattern, &parent_name)
                    || Self::matches_pattern_internal(&self.regex_cache, pattern, &parent_path)
            });

        let cmdline_ok = command_line_patterns.is_empty()
            || command_line_patterns
                .iter()
                .any(|pattern| pattern.matches(&self.regex_cache, &cmdline));

        parent_ok && child_ok && ancestor_ok && cmdline_ok
    }

    fn evaluate_rule_condition(
        &self,
        condition: &RuleCondition,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>,
    ) -> bool {
        match condition {
            RuleCondition::OperationCount {
                op_type,
                comparison,
                threshold,
                path_pattern,
            } => {
                let count = if let Some(pattern) = path_pattern {
                    state
                        .irp_operations
                        .iter()
                        .filter(|rec| {
                            let is_match =
                                irp_operation_matches_token(rec.irp_type, rec.file_change, op_type);
                            is_match
                                && Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    pattern,
                                    &rec.file_path,
                                )
                        })
                        .count() as u64
                } else {
                    state.irp_stats.get_operation_count(op_type)
                };

                match comparison {
                    Comparison::Gt => count > *threshold,
                    Comparison::Gte => count >= *threshold,
                    Comparison::Lt => count < *threshold,
                    Comparison::Lte => count <= *threshold,
                    Comparison::Eq => count == *threshold,
                    Comparison::Ne => count != *threshold,
                }
            }
            RuleCondition::ByteThreshold {
                direction,
                comparison,
                threshold,
            } => {
                let bytes = match direction.as_str() {
                    "read" => state.irp_stats.total_bytes_read,
                    "write" => state.irp_stats.total_bytes_written,
                    _ => 0,
                };
                match comparison {
                    Comparison::Gt => bytes > *threshold,
                    Comparison::Gte => bytes >= *threshold,
                    Comparison::Lt => bytes < *threshold,
                    Comparison::Lte => bytes <= *threshold,
                    Comparison::Eq => bytes == *threshold,
                    Comparison::Ne => bytes != *threshold,
                }
            }
            RuleCondition::File { op, path_pattern } => match op.as_str() {
                "write" | "create" | "read" | "delete" | "rename" => {
                    state.irp_stats.unique_paths_accessed.iter().any(|path| {
                        Self::matches_pattern_internal(&self.regex_cache, path_pattern, path)
                    })
                }
                _ => false,
            },
            RuleCondition::EntropyThreshold {
                comparison,
                threshold,
                ..
            } => msg.map_or(false, |m| {
                let entropy = m.entropy;
                match comparison {
                    Comparison::Gt => entropy > *threshold,
                    Comparison::Gte => entropy >= *threshold,
                    Comparison::Lt => entropy < *threshold,
                    Comparison::Lte => entropy <= *threshold,
                    Comparison::Eq => (entropy - threshold).abs() < 0.001,
                    Comparison::Ne => (entropy - threshold).abs() >= 0.001,
                }
            }),
            RuleCondition::NetworkCondition(net_rule) => {
                #[cfg(all(target_os = "windows", feature = "firewall"))]
                {
                    state
                        .net_packets
                        .iter()
                        .any(|pkt| net_rule.matches_packet(&self.regex_cache, pkt, &[]))
                }
                #[cfg(not(all(target_os = "windows", feature = "firewall")))]
                {
                    let _ = net_rule;
                    false
                }
            }
            RuleCondition::Amsi {
                risk_at_least,
                patterns,
                source,
                cmdline_patterns,
            } => {
                let required_risk = risk_at_least
                    .as_deref()
                    .map(crate::behavioral::amsi::AmsiRiskLevel::from_str)
                    .unwrap_or(crate::behavioral::amsi::AmsiRiskLevel::None);

                state.amsi_results.iter().any(|res| {
                    let risk_ok = res.risk_level >= required_risk;
                    let source_ok = source
                        .as_ref()
                        .map(|src| res.source.contains(src))
                        .unwrap_or(true);
                    let patterns_ok = patterns.is_empty()
                        || patterns.iter().any(|p| {
                            res.detected_patterns
                                .iter()
                                .any(|dp| Self::matches_pattern_internal(&self.regex_cache, p, dp))
                                || Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    p,
                                    &res.content_sample,
                                )
                        });
                    let cmdline_ok = cmdline_patterns.is_empty()
                        || cmdline_patterns.iter().any(|p| {
                            Self::matches_pattern_internal(
                                &self.regex_cache,
                                p,
                                &state.command_line,
                            )
                        });
                    risk_ok && source_ok && patterns_ok && cmdline_ok
                })
            }
            RuleCondition::SanctumGhost {
                functions,
                caller_address_patterns,
                hex_patterns,
                min_matches,
            } => {
                #[cfg(not(all(target_os = "windows", feature = "sanctum")))]
                {
                    let _ = (
                        functions,
                        caller_address_patterns,
                        hex_patterns,
                        min_matches,
                    );
                    false
                }
                #[cfg(all(target_os = "windows", feature = "sanctum"))]
                {
                    let mut unique_matches = std::collections::HashSet::new();
                    for ghost in &state.sanctum_stats.ghost_telemetry {
                        let func_ok = functions.is_empty()
                            || functions.iter().any(|f| ghost.function.contains(f));

                        let addr_ok = caller_address_patterns.is_empty() || {
                            let addr_hex = format!("{:X}", ghost.caller_address);
                            caller_address_patterns.iter().any(|p| {
                                let p_lower = p.to_lowercase();
                                if p_lower == "unknown" || p_lower == "unbacked" {
                                    // If the driver couldn't resolve the caller or it's unbacked, it often reports 0
                                    ghost.caller_address == 0
                                } else {
                                    Self::matches_pattern_internal(&self.regex_cache, p, &addr_hex)
                                }
                            })
                        };

                        let hex_ok = hex_patterns.is_empty()
                            || hex_patterns.iter().any(|p| {
                                Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    p,
                                    &ghost.hex_payload,
                                )
                            });

                        if func_ok && addr_ok && hex_ok {
                            // Deduplicate: same function from same caller address counts as 1 unique match
                            let key = format!("{}_{}", ghost.function, ghost.caller_address);
                            unique_matches.insert(key);
                        }
                    }
                    unique_matches.len() >= *min_matches
                }
            }
            RuleCondition::Api {
                functions,
                arguments,
                module_pattern,
            } => {
                let check_api = |api: &IrpOperationRecord| {
                    let func_match = functions.is_empty()
                        || functions.iter().any(|f| {
                            self.api_candidate_matches(f, module_pattern, &api.function_name)
                        });
                    if !func_match {
                        return false;
                    }

                    if arguments.is_empty() {
                        return true;
                    }

                    arguments
                        .iter()
                        .all(|req_arg| Self::api_argument_matches(req_arg, api))
                };

                state.irp_operations.iter().any(|api| check_api(api))
            }
            RuleCondition::CommandLineMatch {
                patterns,
                match_mode,
            } => {
                if patterns.is_empty() {
                    return true;
                }
                match match_mode {
                    MatchMode::All => patterns
                        .iter()
                        .all(|pattern| pattern.matches(&self.regex_cache, &state.command_line)),
                    MatchMode::Exact => patterns.iter().any(|pattern| {
                        pattern
                            .pattern
                            .pattern()
                            .eq_ignore_ascii_case(&state.command_line)
                    }),
                    _ => patterns
                        .iter()
                        .any(|pattern| pattern.matches(&self.regex_cache, &state.command_line)),
                }
            }
            RuleCondition::Process { op, pattern } => {
                let current_name = state.app_name.to_lowercase();
                let current_path = canonical_behavior_path(&state.exe_path.to_string_lossy());
                let parent_name = state.parent_name.to_lowercase();
                let parent_path = canonical_behavior_path(&state.parent_path.to_string_lossy());
                let event_path = msg
                    .map(|m| canonical_behavior_path(&m.filepathstr))
                    .unwrap_or_default();
                match op.as_str() {
                    "parent" => {
                        Self::matches_pattern_internal(&self.regex_cache, pattern, &parent_name)
                            || Self::matches_pattern_internal(
                                &self.regex_cache,
                                pattern,
                                &parent_path,
                            )
                    }
                    "create" | "start" | "child" => {
                        Self::matches_pattern_internal(&self.regex_cache, pattern, &current_name)
                            || Self::matches_pattern_internal(
                                &self.regex_cache,
                                pattern,
                                &current_path,
                            )
                            || Self::matches_pattern_internal(
                                &self.regex_cache,
                                pattern,
                                &event_path,
                            )
                    }
                    _ => {
                        Self::matches_pattern_internal(&self.regex_cache, pattern, &current_name)
                            || Self::matches_pattern_internal(
                                &self.regex_cache,
                                pattern,
                                &current_path,
                            )
                    }
                }
            }
            RuleCondition::ProcessTree {
                parent_patterns,
                child_patterns,
                ancestor_patterns,
                command_line_patterns,
                max_depth,
                require_current_process,
            } => self.evaluate_process_tree_condition(
                parent_patterns,
                child_patterns,
                ancestor_patterns,
                command_line_patterns,
                *max_depth,
                *require_current_process,
                state,
                msg,
            ),
            RuleCondition::MultiCondition {
                conditions,
                operator,
                min_matches,
                within_ms,
                ..
            } => self.evaluate_multi_condition_window(
                conditions,
                operator.as_ref(),
                *min_matches,
                *within_ms,
                state,
                msg,
            ),
            RuleCondition::ExtensionPattern {
                patterns,
                match_mode,
                op_type,
            } => {
                let op_ok =
                    op_type.trim().is_empty() || state.irp_stats.get_operation_count(op_type) > 0;
                if !op_ok {
                    return false;
                }
                let matches =
                    patterns.iter().filter(|pattern| {
                        state.irp_stats.files_by_extension.keys().any(|ext| {
                            Self::matches_pattern_internal(&self.regex_cache, pattern, ext)
                        })
                    });
                match match_mode {
                    MatchMode::All => matches.count() == patterns.len(),
                    _ => matches.count() > 0,
                }
            }
            RuleCondition::RateOfChange {
                metric,
                comparison,
                threshold,
            } => {
                let value = match metric.as_str() {
                    "write_count" => state.irp_stats.write_count as f64,
                    "rename_count" => state.irp_stats.rename_count as f64,
                    "delete_count" => state.irp_stats.delete_count as f64,
                    "process_create_count" => state.irp_stats.process_create_count as f64,
                    _ => 0.0,
                };
                match comparison {
                    Comparison::Gt => value > *threshold,
                    Comparison::Gte => value >= *threshold,
                    Comparison::Lt => value < *threshold,
                    Comparison::Lte => value <= *threshold,
                    Comparison::Eq => (value - threshold).abs() < 0.001,
                    Comparison::Ne => (value - threshold).abs() >= 0.001,
                }
            }
            RuleCondition::KernelHook {
                event_types,
                function_pattern,
                source_pattern,
                target_pattern,
                min_count,
            } => {
                // Canonical IRP event-type token → IrpMajorOp mapping.
                // Covers IRP_USERMODE_HOOK_EVENT, IRP_KERNEL_*, and IRP_ROOTKIT_*.
                fn irp_type_for_token(token: &str) -> Option<u32> {
                    let t = token.trim().to_ascii_uppercase();
                    // Values mirror Communication.cpp OwlyHypervisorEventDefaultLabel ordering
                    // and the IrpMajorOp::from_sysmonevent() mapping in shared_def.rs.
                    match t.as_str() {
                        "IRP_USERMODE_HOOK_EVENT" => Some(0x13), // 19
                        "IRP_KERNEL_REMOTE_THREAD" => Some(0x14),
                        "IRP_KERNEL_WRITE_MEMORY" => Some(0x15),
                        "IRP_KERNEL_PROTECT_MEMORY" => Some(0x16),
                        "IRP_KERNEL_CREATE_THREAD" => Some(0x17),
                        "IRP_KERNEL_QUEUE_APC" => Some(0x18),
                        "IRP_KERNEL_CREATE_SECTION" => Some(0x19),
                        "IRP_KERNEL_MAP_SECTION" => Some(0x1A),
                        "IRP_ROOTKIT_SSDT_HOOK" => Some(0x1B),
                        "IRP_ROOTKIT_HIDDEN_PROCESS" => Some(0x1C),
                        "IRP_ROOTKIT_HIDDEN_DRIVER" => Some(0x1D),
                        "IRP_ROOTKIT_KERNEL_HOOK" => Some(0x1E),
                        "IRP_ROOTKIT_TERMINATE_PROCESS" => Some(0x1F),
                        "IRP_ROOTKIT_FILE_MOVE" => Some(0x20),
                        "IRP_ROOTKIT_GENERIC" => Some(0x21),
                        _ => None,
                    }
                }

                // Build the set of irp_type values we accept (empty = any hook event).
                let accepted_types: Vec<u32> = event_types
                    .iter()
                    .filter_map(|t| irp_type_for_token(t))
                    .collect();

                // Determine whether an IrpMajorOp corresponds to any hook/rootkit category.
                fn is_kernel_hook_or_rootkit_op(irp_type: u32) -> bool {
                    matches!(
                        irp_type,
                        0x13..=0x21 // IRP_USERMODE_HOOK_EVENT through IRP_ROOTKIT_GENERIC
                    )
                }

                let required = (*min_count).max(1);
                let mut match_count = 0usize;

                for rec in &state.irp_operations {
                    // Type gate: accepted_types empty ⇒ any kernel-hook/rootkit event.
                    let type_ok = if accepted_types.is_empty() {
                        is_kernel_hook_or_rootkit_op(rec.irp_type)
                    } else {
                        accepted_types.contains(&rec.irp_type)
                    };
                    if !type_ok {
                        continue;
                    }

                    // Optional function name pattern.
                    let func_ok = match function_pattern {
                        Some(pat) if !pat.is_empty() => {
                            !rec.function_name.is_empty()
                                && Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    pat,
                                    &rec.function_name,
                                )
                        }
                        _ => true,
                    };
                    if !func_ok {
                        continue;
                    }

                    // Optional source process pattern (matched against file_path which
                    // carries the attacker exe path for kernel hook events).
                    let src_ok = match source_pattern {
                        Some(pat) if !pat.is_empty() => {
                            let src_name = rec
                                .file_path
                                .split(['\\', '/'])
                                .filter(|s| !s.is_empty())
                                .last()
                                .unwrap_or(rec.file_path.as_str());
                            Self::matches_pattern_internal(&self.regex_cache, pat, src_name)
                                || Self::matches_pattern_internal(
                                    &self.regex_cache,
                                    pat,
                                    &rec.file_path,
                                )
                        }
                        _ => true,
                    };
                    if !src_ok {
                        continue;
                    }

                    // Optional target process pattern (matched against
                    // the process image for the target PID if available).
                    let tgt_ok = match target_pattern {
                        Some(pat) if !pat.is_empty() => {
                            // target_pid 0 or equal to source = self-targeting event
                            if rec.target_pid == 0 || rec.target_pid == state.pid {
                                false
                            } else {
                                // Best-effort: compare against app_name / exe_path when the
                                // target happens to be the tracked process, otherwise skip.
                                let target_name = state.app_name.to_lowercase();
                                let target_path =
                                    canonical_behavior_path(&state.exe_path.to_string_lossy());
                                Self::matches_pattern_internal(&self.regex_cache, pat, &target_name)
                                    || Self::matches_pattern_internal(
                                        &self.regex_cache,
                                        pat,
                                        &target_path,
                                    )
                            }
                        }
                        _ => true,
                    };
                    if !tgt_ok {
                        continue;
                    }

                    match_count += 1;
                    if match_count >= required {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn api_argument_matches(req_arg: &ApiArgument, api: &IrpOperationRecord) -> bool {
        let Some(idx) = Self::api_argument_index(&api.function_name, &req_arg.name) else {
            return false;
        };
        if idx >= 4 {
            return false;
        }
        let observed_val = api.raw_arguments[idx];
        let req_val_str = req_arg.value.trim().to_lowercase();

        if req_val_str.starts_with("0x") {
            if let Ok(req_val) = u64::from_str_radix(&req_val_str[2..], 16) {
                return observed_val == req_val;
            }
        } else if let Ok(req_val) = req_val_str.parse::<u64>() {
            return observed_val == req_val;
        }

        false
    }

    fn api_argument_index(function: &str, arg_name: &str) -> Option<usize> {
        let f = function.to_lowercase();
        let a = arg_name.to_lowercase();

        match f.as_str() {
            "ntwritevirtualmemory" | "ntreadvirtualmemory" => match a.as_str() {
                "processhandle" => Some(0),
                "baseaddress" => Some(1),
                "buffer" | "bufferaddress" => Some(2),
                "numberofbytestowrite" | "numberofbytestoread" | "size" => Some(3),
                _ => None,
            },
            "ntprotectvirtualmemory" => match a.as_str() {
                "processhandle" => Some(0),
                "baseaddress" => Some(1),
                "numberofbytestoprotect" | "size" => Some(2),
                "newaccessprotection" | "protection" => Some(3),
                _ => None,
            },
            "ntcreatesection" => match a.as_str() {
                "sectionhandle" => Some(0),
                "desiredaccess" => Some(1),
                "objectattributes" => Some(2),
                "maximumsize" => Some(3), // Note: actually more args, but these are first 4
                _ => None,
            },
            "nttracecontrol" => match a.as_str() {
                "controlcode" => Some(0),
                _ => None,
            },
            _ => None,
        }
    }

    fn evaluate_stages_from_state(
        &self,
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>,
    ) -> (bool, f32) {
        let mut satisfied_stages = 0;

        for stage in &rule.stages {
            let mut stage_satisfied_count = 0;
            let mut stage_total_conditions = 0;

            for condition in &stage.conditions {
                stage_total_conditions += 1;
                let condition_matched = self.evaluate_rule_condition(condition, state, msg);

                if condition_matched {
                    stage_satisfied_count += 1;
                }
            }

            if stage_total_conditions > 0 {
                let stage_ratio = stage_satisfied_count as f32 / stage_total_conditions as f32;
                let threshold = if rule.conditions_percentage > 0.0 {
                    rule.conditions_percentage
                } else {
                    1.0
                };

                if stage_ratio >= threshold {
                    satisfied_stages += 1;
                }
            }
        }

        let total_stages = rule.stages.len() as f32;
        let stage_confidence = if total_stages > 0.0 {
            satisfied_stages as f32 / total_stages
        } else {
            0.0
        };

        let min_stages = if rule.min_stages_satisfied > 0 {
            rule.min_stages_satisfied
        } else {
            1
        };

        let detected = satisfied_stages >= min_stages;
        (detected, stage_confidence)
    }

    /// Parse the command line of a known script interpreter and return
    /// `(script_filename, script_full_path_normalized)`.
    /// Returns `None` when the process is not a known interpreter or no script
    /// argument can be identified.
    fn extract_script_from_cmdline(interpreter: &str, cmdline: &str) -> Option<(String, String)> {
        let interp = interpreter.to_lowercase();
        let interp_name = interp
            .split(['\\', '/'])
            .filter(|s| !s.is_empty())
            .last()
            .unwrap_or(&interp);

        // Tokenise: respect double-quoted tokens, strip surrounding quotes.
        let tokens: Vec<String> = {
            let mut result = Vec::new();
            let mut current = String::new();
            let mut in_quotes = false;
            for ch in cmdline.chars() {
                match ch {
                    '"' => in_quotes = !in_quotes,
                    ' ' | '\t' if !in_quotes => {
                        if !current.is_empty() {
                            result.push(current.clone());
                            current.clear();
                        }
                    }
                    _ => current.push(ch),
                }
            }
            if !current.is_empty() {
                result.push(current);
            }
            result
        };

        // Skip token[0] — that is the interpreter itself.
        let args: &[String] = if tokens.len() > 1 {
            &tokens[1..]
        } else {
            return None;
        };

        let script_path: Option<String> = match interp_name {
            // ── PowerShell / pwsh ──────────────────────────────────────────
            n if n == "powershell.exe" || n == "pwsh.exe" => {
                let mut i = 0;
                let mut found: Option<String> = None;
                while i < args.len() {
                    let a = args[i].to_lowercase();
                    if a == "-file" || a == "-f" {
                        found = args.get(i + 1).cloned();
                        break;
                    }
                    // Bare argument that is not a flag and ends with .ps1/.psm1/.psd1
                    if !a.starts_with('-') {
                        let ext = a.rsplit('.').next().unwrap_or("");
                        if matches!(ext, "ps1" | "psm1" | "psd1") {
                            found = Some(args[i].clone());
                            break;
                        }
                    }
                    i += 1;
                }
                found
            }

            // ── cmd.exe ───────────────────────────────────────────────────
            n if n == "cmd.exe" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i].to_lowercase();
                    if a == "/c" || a == "/k" || a == "/r" {
                        // Everything after /c is the command; grab the first token.
                        if let Some(next) = args.get(i + 1) {
                            // Only report it if it looks like a file (has an extension).
                            if next.contains('.') && !next.starts_with('/') {
                                return Some((interp_name.to_string(), next.clone()));
                            }
                        }
                        break;
                    }
                    i += 1;
                }
                None
            }

            // ── wscript.exe / cscript.exe ─────────────────────────────────
            n if n == "wscript.exe" || n == "cscript.exe" => {
                // First non-flag argument is the script file.
                args.iter()
                    .find(|a| !a.starts_with('/') && !a.starts_with('-') && a.contains('.'))
                    .cloned()
            }

            // ── mshta.exe ─────────────────────────────────────────────────
            n if n == "mshta.exe" => args
                .first()
                .filter(|a| !a.starts_with('/') && a.contains('.'))
                .cloned(),

            // ── rundll32.exe ──────────────────────────────────────────────
            // Format: rundll32.exe path\script.dll,EntryPoint
            n if n == "rundll32.exe" => {
                args.first().map(|a| {
                    // Strip the ,EntryPoint suffix if present.
                    if let Some(comma) = a.find(',') {
                        a[..comma].to_string()
                    } else {
                        a.clone()
                    }
                })
            }

            // ── regsvr32.exe ──────────────────────────────────────────────
            n if n == "regsvr32.exe" => args
                .iter()
                .find(|a| {
                    let l = a.to_lowercase();
                    !l.starts_with('/') && (l.ends_with(".dll") || l.ends_with(".ocx"))
                })
                .cloned(),

            // ── msiexec.exe ───────────────────────────────────────────────
            n if n == "msiexec.exe" => {
                let mut i = 0;
                while i < args.len() {
                    let a = args[i].to_lowercase();
                    if a == "/i" || a == "/x" || a == "/a" || a == "/p" {
                        if let Some(next) = args.get(i + 1) {
                            return Some((interp_name.to_string(), next.clone()));
                        }
                    }
                    i += 1;
                }
                None
            }

            // ── Generic script interpreters ───────────────────────────────
            // python.exe, python3.exe, node.exe, ruby.exe, perl.exe, php.exe,
            // bash.exe, sh.exe, lua.exe, Rscript.exe …
            n if matches!(
                n,
                "python.exe"
                    | "python3.exe"
                    | "node.exe"
                    | "node"
                    | "ruby.exe"
                    | "perl.exe"
                    | "php.exe"
                    | "bash.exe"
                    | "sh.exe"
                    | "lua.exe"
                    | "rscript.exe"
                    | "julia.exe"
            ) =>
            {
                // Skip interpreter flags (-c, --version, etc.) and take the
                // first argument that looks like a file path.
                args.iter()
                    .find(|a| !a.starts_with('-') && a.contains('.'))
                    .cloned()
            }

            _ => None,
        };

        script_path.map(|raw| {
            let norm = raw.replace('\\', "/").to_lowercase();
            let filename = norm
                .split('/')
                .filter(|s| !s.is_empty())
                .last()
                .unwrap_or(&norm)
                .to_string();
            (filename, raw)
        })
    }

    fn check_allowlist(
        &self,
        proc_name: &str,
        rule: &BehaviorRule,
        process_path: Option<&Path>,
        script_file: Option<&str>,
    ) -> bool {
        // Check interpreter name first, then fall back to script filename.
        // This lets allowlist entries like `pattern: "benign_deploy.ps1"` work
        // even when the tracked process is `powershell.exe`.
        let names_to_check: &[&str] = &[proc_name, script_file.unwrap_or("")];
        names_to_check.iter().any(|name| {
            if name.is_empty() {
                return false;
            }
            let proc_lc = name.to_lowercase();
            rule.allowlisted_apps.iter().any(|entry| {
                match entry {
                    AllowlistEntry::Simple(pattern) => proc_lc.contains(&pattern.to_lowercase()),
                    AllowlistEntry::Complex {
                        pattern,
                        signers,
                        must_be_signed,
                        is_absolute,
                    } => {
                        let pat_lc = pattern.to_lowercase();
                        let mut name_matched =
                            proc_lc.contains(&pat_lc) || pat_lc.contains(&proc_lc);

                        if *is_absolute {
                            if let Some(path) = process_path {
                                let path_str = canonical_behavior_path(&path.to_string_lossy());
                                let pat_norm = canonical_behavior_path(&pat_lc);
                                if !matches_pattern(&self.regex_cache, &pat_norm, &path_str) {
                                    name_matched = false;
                                }
                            } else {
                                name_matched = false;
                            }
                        }

                        if !name_matched {
                            return false;
                        }

                        if !must_be_signed && signers.is_empty() {
                            return true;
                        }
                        if let Some(path) = process_path {
                            let mut dos_path_buf = path.to_path_buf();
                            if let Some(path_str) = path.to_str() {
                                let path_lc = path_str.to_lowercase();
                                if path_lc.starts_with("\\device\\harddiskvolume") {
                                    use std::ffi::OsString;
                                    use std::os::windows::ffi::OsStringExt;
                                    use windows::Win32::Storage::FileSystem::{
                                        GetLogicalDriveStringsW, QueryDosDeviceW,
                                    };
                                    use windows::core::PCWSTR;

                                    unsafe {
                                        let mut drives_buf = [0u16; 512];
                                        let len = GetLogicalDriveStringsW(Some(&mut drives_buf));
                                        let mut matched_drive = false;
                                        if len > 0 && (len as usize) < drives_buf.len() {
                                            let mut i = 0;
                                            while i < len as usize {
                                                let start = i;
                                                while i < len as usize && drives_buf[i] != 0 {
                                                    i += 1;
                                                }
                                                if i > start {
                                                    let drive =
                                                        OsString::from_wide(&drives_buf[start..i]);
                                                    if let Some(drive_str) = drive.to_str() {
                                                        let drive_letter =
                                                            drive_str.trim_end_matches('\\');
                                                        let drive_wide: Vec<u16> = drive_letter
                                                            .encode_utf16()
                                                            .chain(std::iter::once(0))
                                                            .collect();
                                                        let mut target_buf = [0u16; 512];
                                                        let target_len = QueryDosDeviceW(
                                                            PCWSTR(drive_wide.as_ptr()),
                                                            Some(&mut target_buf),
                                                        );
                                                        if target_len > 0 {
                                                            let target = OsString::from_wide(
                                                                &target_buf
                                                                    [..((target_len as usize) - 1)],
                                                            );
                                                            if let Some(target_str) =
                                                                target.to_str()
                                                            {
                                                                if path_lc.starts_with(
                                                                    &target_str.to_lowercase(),
                                                                ) {
                                                                    let remainder = &path_str
                                                                        [target_str.len()..];
                                                                    dos_path_buf =
                                                                        std::path::PathBuf::from(
                                                                            format!(
                                                                                "{}{}",
                                                                                drive_letter,
                                                                                remainder
                                                                            ),
                                                                        );
                                                                    matched_drive = true;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                i += 1;
                                            }
                                        }

                                        // Fallback to SystemDrive if we couldn't resolve via QueryDosDevice
                                        if !matched_drive {
                                            let system_drive = std::env::var("SystemDrive")
                                                .unwrap_or_else(|_| "C:".to_string());
                                            if let Some(rest) = path_str.splitn(4, '\\').nth(3) {
                                                dos_path_buf = std::path::PathBuf::from(format!(
                                                    "{}\\{}",
                                                    system_drive, rest
                                                ));
                                            }
                                        }
                                    }
                                } else if path_lc.starts_with("\\??\\") {
                                    dos_path_buf = PathBuf::from(&path_str[4..]);
                                } else if path_lc.starts_with("\\\\?\\") {
                                    dos_path_buf = PathBuf::from(&path_str[4..]);
                                }
                            }

                            if !dos_path_buf.exists() {
                                return false;
                            }
                            let info = verify_signature(&dos_path_buf);

                            // Strict requirement: must be signed by one of the specified signers
                            // if the rule engine says it's a mandatory vendor check.
                            if *must_be_signed && !info.is_trusted {
                                return false;
                            }
                            if !signers.is_empty() {
                                if let Some(signer) = &info.signer_name {
                                    signers.iter().any(|s_pattern| {
                                        Self::matches_pattern_internal(
                                            &self.regex_cache,
                                            s_pattern,
                                            signer,
                                        )
                                    })
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        } else {
                            false
                        }
                    }
                }
            })
        }) // end names_to_check.iter().any()
    }

    fn matches_pattern_internal(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        pattern: &str,
        text: &str,
    ) -> bool {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return false;
        }

        let has_glob = trimmed.contains('*') || trimmed.contains('?');
        let is_explicit_regex =
            trimmed.starts_with("(?") || trimmed.starts_with('^') || trimmed.ends_with('$');

        if !has_glob && !is_explicit_regex {
            let text_norm = normalize_path_separators(&text.to_lowercase());
            let pattern_norm = normalize_path_separators(&trimmed.to_lowercase());
            let looks_like_path = pattern_norm.contains(":/")
                || pattern_norm.starts_with('/')
                || pattern_norm.starts_with('%')
                || pattern_norm.contains('/');

            if looks_like_path {
                if text_norm == pattern_norm {
                    return true;
                }

                if pattern_norm.ends_with('/') {
                    return text_norm.starts_with(&pattern_norm);
                }

                let mut prefix = pattern_norm.clone();
                prefix.push('/');
                return text_norm.starts_with(&prefix);
            }

            return text.to_lowercase().contains(&pattern_norm);
        }

        {
            if let Ok(cache_map) = cache.read() {
                if let Some(re) = cache_map.get(trimmed) {
                    return re.is_match(text);
                }
            }
        }

        let mut cache_map = cache.write().unwrap();

        if let Some(re) = cache_map.get(trimmed) {
            return re.is_match(text);
        }

        let regex_str = if has_glob {
            let escaped = regex::escape(trimmed)
                .replace("\\*", ".*")
                .replace("\\?", ".");
            format!("(?i)^{}$", escaped)
        } else if trimmed.starts_with("(?") {
            trimmed.to_string()
        } else {
            format!("(?i){}", trimmed)
        };

        match Regex::new(&regex_str) {
            Ok(re) => {
                let is_match = re.is_match(text);
                cache_map.insert(trimmed.to_string(), re);
                is_match
            }
            Err(_) => text.to_lowercase().contains(&trimmed.to_lowercase()),
        }
    }

    /// Network activity detection — delegates entirely to the firewall.
    /// Returns true if the firewall has observed real outbound I/O for this PID.
    fn matches_process_identity_pattern(
        cache: &Arc<RwLock<HashMap<String, Regex>>>,
        pattern: &str,
        process_name: &str,
        process_path: &str,
    ) -> bool {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return false;
        }

        let name_norm = normalize_path_separators(&process_name.trim().to_lowercase());
        let path_norm = normalize_path_separators(&process_path.trim().to_lowercase());

        if pattern_looks_like_path(trimmed) {
            return (!path_norm.is_empty()
                && Self::matches_pattern_internal(cache, trimmed, &path_norm))
                || (!name_norm.is_empty()
                    && Self::matches_pattern_internal(cache, trimmed, &name_norm));
        }

        if is_plain_pattern(trimmed) {
            return !name_norm.is_empty() && name_norm == trimmed.to_lowercase();
        }

        (!name_norm.is_empty() && Self::matches_pattern_internal(cache, trimmed, &name_norm))
            || (!path_norm.is_empty() && Self::matches_pattern_internal(cache, trimmed, &path_norm))
    }

    fn pid_has_network_activity(&self, pid: u32) -> bool {
        let openedr_observed = self.openedr_net_pids.read().unwrap().contains(&pid);

        #[cfg(all(target_os = "windows", feature = "firewall"))]
        {
            openedr_observed || self.firewall_net_pids.read().unwrap().contains(&pid)
        }
        #[cfg(not(all(target_os = "windows", feature = "firewall")))]
        {
            openedr_observed
        }
    }

    fn has_network_activity(&self, state: &ProcessBehaviorState) -> bool {
        self.pid_has_network_activity(state.pid)
    }

    /// Returns a snapshot of all rootkit findings since last clear.
    pub fn get_rootkit_findings(&self) -> &[RootkitFinding] {
        &self.rootkit_findings
    }

    /// Clears the rootkit findings list (e.g. after writing a report).
    #[allow(dead_code)]
    pub fn clear_rootkit_findings(&mut self) {
        self.rootkit_findings.clear();
    }

    /// Called from the main IRP dispatch loop when irp_op is 21–24.
    pub fn handle_rootkit_event(&mut self, msg: &IOMessage) {
        let op = IrpMajorOp::from_byte(effective_hypervisor_irp_byte(msg));
        let kind = RootkitFindingKind::from_irp_op(op);

        let description = msg
            .kernel_event_info
            .object_name
            .trim_matches('\0')
            .trim()
            .to_string();

        let finding = RootkitFinding {
            kind: kind.clone(),
            description: description.clone(),
            address: msg.kernel_event_info.memory_address,
            pid: msg.kernel_event_info.source_process_id,
            extra: msg.kernel_event_info.raw_argument1,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        Logging::warning(&format!(
            "[ROOTKIT] {} — {} (addr=0x{:X} pid={} extra=0x{:X})",
            kind.threat_label(),
            description,
            finding.address,
            finding.pid,
            finding.extra,
        ));

        // Emit to findings list (used by report generation).
        self.rootkit_findings.push(finding.clone());

        // Immediately act if severity is critical.
        if kind.severity() >= 3 {
            self.on_critical_rootkit_finding(&finding);
        }
    }

    /// Respond to a critical rootkit finding.
    fn on_critical_rootkit_finding(&mut self, finding: &RootkitFinding) {
        Logging::warning(&format!(
            "[ROOTKIT CRITICAL] {} detected: '{}' at 0x{:X}",
            finding.kind.threat_label(),
            finding.description,
            finding.address
        ));

        // Only hidden-process findings identify a concrete user-mode PID.
        if matches!(finding.kind, RootkitFindingKind::HiddenProcess) && finding.pid != 0 {
            if let Some(state) = self
                .process_states
                .values_mut()
                .find(|s| s.pid == finding.pid)
            {
                state.rootkit_implicated = true;
                Logging::warning(&format!(
                    "[ROOTKIT] Hidden process PID {} ({}) is rootkit-implicated",
                    finding.pid, state.app_name
                ));
            }
        }
    }

    #[allow(dead_code)]
    pub fn scan_all_processes(
        &mut self,
        _config: &Config,
        _threat_handler: &dyn ThreatHandler,
    ) -> Vec<ProcessRecord> {
        self.drain_self_defense_telemetry_for_known_states();

        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();

        // Snapshot firewall-confirmed malicious exe paths once per scan cycle
        #[cfg(all(target_os = "windows", feature = "firewall"))]
        let fw_blocked: HashMap<String, FirewallDetection> =
            self.firewall_blocked_exes.read().unwrap().clone();

        for gid in gids {
            let state = match self.process_states.get(&gid) {
                Some(s) => s.clone(),
                None => continue,
            };

            if state.pid == 0 {
                continue;
            }

            let pid = state.pid;
            let mut app_name = state.app_name.clone();
            let mut exe_path_buf = state.exe_path.clone();
            let stale_name =
                app_name.is_empty() || app_name.starts_with("PROC_") || app_name == "UNKNOWN";
            let stale_path =
                exe_path_buf.as_os_str().is_empty() || exe_path_buf.to_string_lossy() == "UNKNOWN";

            if stale_path && let Some(resolved_path) = resolve_process_path(pid) {
                exe_path_buf = resolved_path.clone();
                if stale_name
                    && let Some(file_name) =
                        resolved_path.file_name().and_then(|value| value.to_str())
                {
                    app_name = file_name.to_string();
                }
            }

            let exe_path_str = exe_path_buf.to_string_lossy().to_string();

            // Firewall-confirmed malicious network traffic: act immediately,
            // bypass the normal rule evaluation loop entirely.
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            if !exe_path_str.is_empty()
                && exe_path_str.to_lowercase() != "unknown"
                && let Some(detection) = fw_blocked.get(&exe_path_str.to_lowercase())
            {
                if detection.is_pending_user_decision() {
                    continue;
                }

                let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path_buf.clone());
                p.is_malicious = true;
                p.pids.insert(pid);
                p.termination_requested = true;
                p.notify_user_requested = true;
                p.triggered_rule_name = Some(detection.threat_type_label().to_string());
                p.triggered_rule_details = Some(detection.match_details());
                Logging::warning(&format!(
                    "[FirewallPipe] Acting on firewall-confirmed malicious exe: {} (PID {}) — {}",
                    exe_path_str,
                    pid,
                    detection.match_details()
                ));
                detected_processes.push(p);
                continue;
            }

            // Log Nt API activity summary if any events detected
            if state.hypervisor_events_total > 0 {
                Logging::info(&format!(
                    "[API HOOKING SUMMARY] PID {} ({}) - Total fallback events: {}",
                    pid, app_name, state.hypervisor_events_total
                ));

                if state.irp_stats.has_injection_indicators() {
                    Logging::warning(&format!(
                        "[API HOOKING PATTERN] PID {} ({}) shows API hooking activity - Total fallback events: {}",
                        pid,
                        app_name,
                        state.irp_stats.get_injection_api_count()
                    ));
                }
            }

            let critical_image_display =
                if !exe_path_str.is_empty() && !exe_path_str.eq_ignore_ascii_case("unknown") {
                    exe_path_str.clone()
                } else {
                    app_name.clone()
                };
            if state.signature_checked && !state.signature_verification_failed {
                if let Some(reason) = suspicious_critical_process_reason(
                    state.pid,
                    &critical_image_display,
                    state.is_signed,
                    state.has_valid_signature,
                ) {
                    let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path_buf.clone());
                    p.is_malicious = true;
                    p.pids.insert(pid);
                    p.deny_access_requested = true;
                    p.termination_requested = true;
                    p.quarantine_requested = true;
                    p.notify_user_requested = true;
                    p.triggered_rule_name =
                        Some("HEUR:Win.DefEvasion.CriticalProcessAbuse.gen".to_string());
                    p.triggered_rule_details = Some(reason);
                    p.remediation_target_path = Some(exe_path_buf.clone());
                    detected_processes.push(p);
                    continue;
                }
            }

            // Rootkit telemetry should flow through the normal rule engine so
            // `ask_user`, allowlists, and remediation policy stay consistent.

            for rule in &self.rules {
                let script_file_opt = if state.script_file.is_empty() {
                    None
                } else {
                    Some(state.script_file.as_str())
                };
                if self.check_allowlist(&app_name, rule, Some(&exe_path_buf), script_file_opt) {
                    continue;
                }

                // Cloud Trust Filter: only OpenEDR FLS Safe (code 1) may bypass.
                if rule.should_trust_comodo_cloud
                    && (is_openedr_fls_safe_code(state.cloud_static_verdict)
                        || is_openedr_fls_safe_code(state.cloud_dynamic_verdict))
                {
                    continue;
                }

                let mut legacy_triggered = false;
                let mut rich_triggered = false;
                let mut stages_triggered = false;

                if !rule.browsed_paths.is_empty()
                    && state.browsed_paths_tracker.len() >= rule.multi_access_threshold
                {
                    legacy_triggered = true;
                }
                if !rule.staging_paths.is_empty() && !state.staged_files_written.is_empty() {
                    legacy_triggered = true;
                }
                if rule.require_internet && self.has_network_activity(&state) {
                    legacy_triggered = true;
                }

                if let Some(logic) = &rule.detection_logic {
                    rich_triggered = self.evaluate_detection_condition(logic, &state, rule);
                }

                if !rule.stages.is_empty() {
                    let (detected, _) = self.evaluate_stages_from_state(rule, &state, None);
                    stages_triggered = detected;
                }

                if legacy_triggered || rich_triggered || stages_triggered {
                    let mut prompted_deny = false;
                    let mut prompted_block = false;
                    let mut prompted_quarantine = false;
                    if rule.response.ask_user {
                        match self.resolve_firewall_hips_prompt(gid, &state, rule) {
                            FirewallHipsPromptOutcome::Pending
                            | FirewallHipsPromptOutcome::Allowed => {
                                continue;
                            }
                            FirewallHipsPromptOutcome::Deny => {
                                prompted_deny = true;
                            }
                            FirewallHipsPromptOutcome::Block => {
                                prompted_block = true;
                            }
                            FirewallHipsPromptOutcome::Quarantine => {
                                prompted_block = true;
                                prompted_quarantine = true;
                            }
                        }
                    }

                    let mut p =
                        ProcessRecord::new(gid, app_name.clone(), exe_path_str.clone().into());
                    p.is_malicious = true;
                    p.pids.insert(pid);
                    p.termination_requested = if rule.response.ask_user {
                        if prompted_deny {
                            false
                        } else {
                            prompted_block || prompted_quarantine || rule.response.terminate_process
                        }
                    } else {
                        rule.response.terminate_process
                    };
                    p.quarantine_requested = if rule.response.ask_user {
                        prompted_quarantine
                    } else {
                        rule.response.quarantine
                    };
                    p.deny_access_requested = if rule.response.ask_user {
                        (prompted_deny || prompted_block || prompted_quarantine)
                            && rule.response.status_access_denied
                    } else {
                        rule.response.status_access_denied
                    };
                    p.kill_and_remove_requested = if rule.response.ask_user {
                        false
                    } else {
                        rule.response.kill_and_remove
                    };
                    p.suspend_requested = if rule.response.ask_user {
                        false
                    } else {
                        rule.response.suspend_process
                    };
                    p.notify_user_requested = rule.response.notify_user;
                    p.revert_requested = rule.response.auto_revert;
                    p.triggered_rule_name = Some(rule.name.clone());
                    p.triggered_rule_details = Some(Self::build_rule_match_details(
                        rule,
                        &state,
                        None,
                        Some(if stages_triggered {
                            "Stage-based scan"
                        } else if rich_triggered {
                            "Rich-logic scan"
                        } else {
                            "Legacy scan"
                        }),
                        None,
                    ));
                    p.remediation_target_path =
                        Self::build_rule_remediation_target_path(rule, &state);
                    detected_processes.push(p);
                }
            }
        }

        detected_processes
    }
}
