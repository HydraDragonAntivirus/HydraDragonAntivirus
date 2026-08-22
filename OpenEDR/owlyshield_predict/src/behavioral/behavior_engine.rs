pub use super::rule_types::*;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::config::Config;
use crate::logging::Logging;
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::process::ProcessRecord;

use crate::process::ProcessState;
use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp, known_raw_event_name};
use crate::shared_def::{
    effective_hypervisor_irp_byte, effective_hypervisor_raw_event_type, is_kernel_api_irp,
    is_kernel_process_protection_irp, normalize_hypervisor_label, resolved_hypervisor_event_name,
};
use crate::signature_verification::verify_signature;
use crate::threat_handler::ThreatHandler;

use crate::utils::{
    format_process_descriptor_with_fallback, resolve_process_path,
    suspicious_critical_process_reason,
};

use crate::windows::edrsvc_client::with_shared_driver;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::{HashMap, HashSet, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use num::FromPrimitive;


type FirewallNetPids = Arc<std::sync::RwLock<HashSet<u32>>>;

type FirewallBlockedExes = Arc<std::sync::RwLock<HashMap<String, FirewallDetection>>>;
/// Per-PID list of (dst_ip, dst_port) pairs observed by the firewall (NET_EVENT).

type FirewallNetDetails = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, u16)>>>>;

type FirewallHipsPendingPrompts = Arc<std::sync::RwLock<HashMap<String, FirewallHipsPromptState>>>;

type FirewallHipsDecisions = Arc<std::sync::RwLock<HashMap<String, FirewallHipsDecision>>>;

type FirewallHipsAllowOnce = Arc<std::sync::RwLock<HashSet<String>>>;

type FirewallHipsAllowAlways = Arc<std::sync::RwLock<HashSet<String>>>;
/// Per-PID list of (request_body, response_body) pairs received via FULL_PACKED_DATA pipe messages.

type FirewallHttpBodyMap = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, String)>>>>;
/// Per-PID rolling history of full PacketInfo structures from the firewall.

type FirewallFullPackets = Arc<std::sync::RwLock<HashMap<u32, VecDeque<PacketInfo>>>>;

type FirewallGenerateReport = Arc<AtomicBool>;

type FirewallFileVerdicts = Arc<std::sync::RwLock<HashMap<String, FileVerdictInfo>>>;


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


fn shared_firewall_net_pids() -> FirewallNetPids {
    static FIREWALL_NET_PIDS: OnceLock<FirewallNetPids> = OnceLock::new();
    FIREWALL_NET_PIDS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}


fn shared_firewall_blocked_exes() -> FirewallBlockedExes {
    static FIREWALL_BLOCKED_EXES: OnceLock<FirewallBlockedExes> = OnceLock::new();
    FIREWALL_BLOCKED_EXES
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}


fn shared_firewall_net_details() -> FirewallNetDetails {
    static FIREWALL_NET_DETAILS: OnceLock<FirewallNetDetails> = OnceLock::new();
    FIREWALL_NET_DETAILS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}


fn shared_firewall_http_body_map() -> FirewallHttpBodyMap {
    static FIREWALL_HTTP_BODY_MAP: OnceLock<FirewallHttpBodyMap> = OnceLock::new();
    FIREWALL_HTTP_BODY_MAP
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}


fn shared_firewall_full_packets() -> FirewallFullPackets {
    static FIREWALL_FULL_PACKETS: OnceLock<FirewallFullPackets> = OnceLock::new();
    FIREWALL_FULL_PACKETS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}





fn shared_firewall_hips_pending_prompts() -> FirewallHipsPendingPrompts {
    static FIREWALL_HIPS_PENDING_PROMPTS: OnceLock<FirewallHipsPendingPrompts> = OnceLock::new();
    FIREWALL_HIPS_PENDING_PROMPTS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}


fn shared_firewall_hips_decisions() -> FirewallHipsDecisions {
    static FIREWALL_HIPS_DECISIONS: OnceLock<FirewallHipsDecisions> = OnceLock::new();
    FIREWALL_HIPS_DECISIONS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}


fn shared_firewall_hips_allow_once() -> FirewallHipsAllowOnce {
    static FIREWALL_HIPS_ALLOW_ONCE: OnceLock<FirewallHipsAllowOnce> = OnceLock::new();
    FIREWALL_HIPS_ALLOW_ONCE
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}


fn shared_firewall_hips_allow_always() -> FirewallHipsAllowAlways {
    static FIREWALL_HIPS_ALLOW_ALWAYS: OnceLock<FirewallHipsAllowAlways> = OnceLock::new();
    FIREWALL_HIPS_ALLOW_ALWAYS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}


fn shared_firewall_generate_report() -> FirewallGenerateReport {
    static FIREWALL_GENERATE_REPORT: OnceLock<FirewallGenerateReport> = OnceLock::new();
    FIREWALL_GENERATE_REPORT
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}


fn shared_firewall_file_verdicts() -> FirewallFileVerdicts {
    static FIREWALL_FILE_VERDICTS: OnceLock<FirewallFileVerdicts> = OnceLock::new();
    FIREWALL_FILE_VERDICTS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}


fn normalize_firewall_file_verdict_key(file_path: &str) -> String {
    file_path.trim().replace('/', "\\").to_ascii_lowercase()
}


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

/// Per-PID OpenEDR telemetry stats collected from the direct edrsvc -> Owlyshield feed.
type OpenEdrTelemetryStatsMap = Arc<std::sync::RwLock<HashMap<u32, OpenEdrTelemetryStats>>>;
type OpenEdrNetPids = Arc<std::sync::RwLock<HashSet<u32>>>;
type OpenEdrNetDetails = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, u16)>>>>;
type SelfDefenseTelemetryMap =
    Arc<std::sync::RwLock<HashMap<u32, VecDeque<SelfDefenseTelemetryEvent>>>>;

const SELF_DEFENSE_DUPLICATE_SUPPRESS_MS: u64 = 2_000;

/// Access rights that indicate a real cross-process handle attack attempt.
/// Mirrors `c_nHostileAccessMask` in libsysmon/src/controller.cpp (the
/// SelfDefense gate) so benign read/query probes — including the EDR's own
/// monitoring — are never reported as process attacks.
#[allow(dead_code)]
const HOSTILE_PROCESS_ACCESS_MASK: u64 = 0x0001 // PROCESS_TERMINATE
    | 0x0002 // PROCESS_CREATE_THREAD
    | 0x0008 // PROCESS_VM_OPERATION
    | 0x0020 // PROCESS_VM_WRITE
    | 0x0080 // PROCESS_CREATE_PROCESS
    | 0x0100 // PROCESS_SET_QUOTA
    | 0x0200 // PROCESS_SET_INFORMATION
    | 0x0800; // PROCESS_SUSPEND_RESUME

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

/// Report a blocked MBR write produced by the MBRFilter kernel driver.
///
/// Raised from the MBR alert pipe listener thread (see
/// `crate::windows::mbrfilter`). Logs the alert and forwards a HIPS prompt to
/// the firewall GUI via the `HydraHipEvent` pipe so removable/external MBR
/// writes surface to the user.
pub fn report_mbr_alert(disk_number: i32, process_path: &str) {
    use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        FlushFileBuffers, OPEN_EXISTING, WriteFile,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::PCWSTR;

    const HIPS_PIPE: &str = r"\\.\pipe\HydraHipEvent";
    const CONNECT_TIMEOUT_MS: u32 = 750;
    const CONNECT_ATTEMPTS: usize = 2;

    let target = format!("PhysicalDrive{}", disk_number);
    let reason = format!(
        "Blocked MBR write to removable/external disk {} by process: {}. This may indicate USB MBR malware.",
        disk_number, process_path
    );
    let request_id = format!(
        "mbr_usb_{}_{}",
        disk_number,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let message = format!(
        "HIPS_ASK:{}|{}|{}|{}|{}|{}|{}\n",
        BehaviorEngine::sanitize_firewall_hips_field(&request_id),
        0,
        BehaviorEngine::sanitize_firewall_hips_field("MBRFilter"),
        BehaviorEngine::sanitize_firewall_hips_field(process_path),
        BehaviorEngine::sanitize_firewall_hips_field("MBR_USB_WRITE"),
        BehaviorEngine::sanitize_firewall_hips_field(&target),
        BehaviorEngine::sanitize_firewall_hips_field(&reason),
    );
    let message_bytes = message.as_bytes();

    let mut pipe_name_wide: Vec<u16> = HIPS_PIPE.encode_utf16().collect();
    pipe_name_wide.push(0);
    let pcwstr = PCWSTR(pipe_name_wide.as_ptr());

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
                Logging::info(&format!(
                    "[MBR HIPS] Sent USB MBR alert to firewall GUI for disk {} ({} bytes)",
                    disk_number, bytes_written
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

    Logging::warning(&format!(
        "[MBR HIPS] Firewall GUI prompt not delivered for disk {} after {} attempts: {}",
        disk_number, CONNECT_ATTEMPTS, last_error
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

    // One independent counter for every concrete OpenEDR LLE_*/IRP_* event name.
    pub lle_clipboard_read_count: usize,
    pub lle_desktop_open_count: usize,
    pub lle_desktop_wallpaper_set_count: usize,
    pub lle_device_ioctl_count: usize,
    pub lle_device_link_create_count: usize,
    pub lle_device_raw_write_access_count: usize,
    pub lle_disk_link_create_count: usize,
    pub lle_disk_raw_write_access_count: usize,
    pub lle_file_close_count: usize,
    pub lle_file_create_count: usize,
    pub lle_file_data_change_count: usize,
    pub lle_file_data_read_full_count: usize,
    pub lle_file_data_write_full_count: usize,
    pub lle_file_delete_count: usize,
    pub lle_file_map_read_count: usize,
    pub lle_file_map_write_count: usize,
    pub lle_file_rename_count: usize,
    pub lle_injection_activity_count: usize,
    pub lle_keyboard_block_count: usize,
    pub lle_keyboard_global_read_count: usize,
    pub lle_keyboard_global_write_count: usize,
    pub lle_microphone_enum_count: usize,
    pub lle_microphone_read_count: usize,
    pub lle_mouse_block_count: usize,
    pub lle_mouse_global_write_count: usize,
    pub lle_named_pipe_create_count: usize,
    pub lle_network_connect_in_count: usize,
    pub lle_network_connect_out_count: usize,
    pub lle_network_listen_count: usize,
    pub lle_network_request_data_count: usize,
    pub lle_network_request_dns_count: usize,
    pub lle_process_create_count: usize,
    pub lle_process_delete_count: usize,
    pub lle_process_memory_read_count: usize,
    pub lle_process_memory_write_count: usize,
    pub lle_process_open_count: usize,
    pub lle_registry_key_create_count: usize,
    pub lle_registry_key_delete_count: usize,
    pub lle_registry_key_name_change_count: usize,
    pub lle_registry_value_delete_count: usize,
    pub lle_registry_value_set_count: usize,
    pub lle_self_defense_count: usize,
    pub lle_thread_open_count: usize,
    pub lle_user_impersonation_count: usize,
    pub lle_user_logon_count: usize,
    pub lle_volume_link_create_count: usize,
    pub lle_volume_raw_write_access_count: usize,
    pub lle_window_data_read_count: usize,
    pub lle_window_proc_global_hook_count: usize,
    pub irp_kernel_create_section_count: usize,
    pub irp_kernel_create_thread_count: usize,
    pub irp_kernel_map_section_count: usize,
    pub irp_kernel_protect_memory_count: usize,
    pub irp_kernel_queue_apc_count: usize,
    pub irp_kernel_remote_thread_count: usize,
    pub irp_kernel_write_memory_count: usize,
    pub irp_named_pipe_write_count: usize,
    pub irp_rootkit_file_move_count: usize,
    pub irp_rootkit_generic_count: usize,
    pub irp_rootkit_hidden_driver_count: usize,
    pub irp_rootkit_hidden_process_count: usize,
    pub irp_rootkit_kernel_hook_count: usize,
    pub irp_rootkit_ssdt_hook_count: usize,
    pub irp_rootkit_terminate_process_count: usize,
    pub irp_usermode_hook_event_count: usize,
    pub irp_user_mode_hook_event_count: usize,
    pub irp_create_count: usize,
    pub irp_read_count: usize,
    pub irp_write_count: usize,
    pub irp_cleanup_count: usize,
    pub irp_set_info_count: usize,
    pub irp_registry_count: usize,
    pub irp_process_create_count: usize,
    pub irp_process_terminate_count: usize,
    pub irp_process_terminate_attempt_count: usize,
    pub irp_process_exit_count: usize,
    pub irp_process_handle_open_count: usize,
    pub irp_named_pipe_create_count: usize,

    pub read_count: usize,
    pub write_count: usize,
    pub create_count: usize,
    pub close_count: usize,
    pub delete_count: usize,
    pub rename_count: usize,
    pub setinfo_count: usize,
    pub registry_read_count: usize,
    pub registry_write_count: usize,
    pub registry_create_count: usize,
    pub registry_delete_count: usize,
    pub registry_rename_count: usize,
    pub process_create_count: usize,
    pub process_delete_count: usize,
    pub process_memory_read_count: usize,
    pub process_memory_write_count: usize,
    pub thread_open_count: usize,
    pub network_request_count: usize,
    pub network_listen_count: usize,
    pub pipe_create_count: usize,
    pub pipe_write_count: usize,
    pub memory_read_count: usize,
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

    #[allow(dead_code)]
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
    /// True when the detection came from a rule whose action is `traffic_attack`
    /// (Suricata `alert` semantics). The traffic itself is not blocked inline,
    /// but the process that produced it is remediated like any other confirmed
    /// malicious exe.
    pub is_traffic_attack: bool,
}


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
        } else if self.is_traffic_attack {
            "Network Attack"
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


#[derive(Debug, Clone)]
struct FirewallHipsPromptState {
    request_id: String,
    request_signature: String,
    allow_signature: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallHipsDecision {
    Deny,
    Block,
    Quarantine,
    AllowOnce,
    AllowAlways,
}


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
    /// Indicates whether `irp_type` holds a legacy kernel hook sub-type from owlyHook.eventType
    pub is_legacy_kernel_subtype: bool,
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

/// Non-success status from user-mode hook / kernel API telemetry.
///
/// This is intentionally tracked separately from `detected_apis`:
/// hook/report/query failures are telemetry that rules may inspect, but they
/// must not be counted as successful API behavior.
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
    pub close_count: u64,

    // IRP operation counts
    pub irp_read_count: u64,
    pub irp_write_count: u64,
    pub irp_create_count: u64,
    pub irp_delete_count: u64,
    pub irp_rename_count: u64,
    pub irp_setinfo_count: u64,

    // Registry operations
    pub registry_read_count: u64,
    pub registry_write_count: u64,
    pub registry_delete_count: u64,
    pub registry_create_count: u64,

    // Named Pipe operations
    pub pipe_create_count: u64,
    pub pipe_write_count: u64,

    // Process operations
    pub process_create_count: u64,
    pub process_terminate_count: u64,
    pub process_exit_count: u64,
    pub process_handle_open_count: u64,
    pub process_open_count: u64,
    pub process_memory_read_count: u64,
    pub process_memory_write_count: u64,
    pub process_terminate_attempt_count: u64,
    pub process_delete_count: u64,

    // Memory operations
    pub memory_read_count: u64,
    pub memory_write_count: u64,

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

    // Per-concrete IrpMajorOp counters. Every enum variant has its own counter.
    pub irp_major_irpcreate_count: u64,
    pub irp_major_irpkernelcreatesection_count: u64,
    pub irp_major_irpkernelcreatethread_count: u64,
    pub irp_major_irpkernelmapsection_count: u64,
    pub irp_major_irpkernelprotectmemory_count: u64,
    pub irp_major_irpkernelqueueapc_count: u64,
    pub irp_major_irpkernelremotethread_count: u64,
    pub irp_major_irpkernelwritememory_count: u64,
    pub irp_major_irpnamedpipecreate_count: u64,
    pub irp_major_irpnamedpipewrite_count: u64,
    pub irp_major_irpprocesscreate_count: u64,
    pub irp_major_irpprocessexit_count: u64,
    pub irp_major_irpprocesshandleopen_count: u64,
    pub irp_major_irpprocessterminate_count: u64,
    pub irp_major_irpprocessterminateattempt_count: u64,
    pub irp_major_irpread_count: u64,
    pub irp_major_irpregistry_count: u64,
    pub irp_major_irprootkitfilemove_count: u64,
    pub irp_major_irprootkitgeneric_count: u64,
    pub irp_major_irprootkithiddendriver_count: u64,
    pub irp_major_irprootkithiddenprocess_count: u64,
    pub irp_major_irprootkitkernelhook_count: u64,
    pub irp_major_irprootkitssdthook_count: u64,
    pub irp_major_irprootkitterminateprocess_count: u64,
    pub irp_major_irpsetinfo_count: u64,
    pub irp_major_irpusermodehookevent_count: u64,
    pub irp_major_irpwrite_count: u64,
    pub irp_major_irpcleanup_count: u64,

    // Per-concrete FileChangeInfo counters. Every enum variant has its own counter.
    pub file_change_changedeletefile_count: u64,
    pub file_change_changedeletenewfile_count: u64,
    pub file_change_changeextensionchanged_count: u64,
    pub file_change_changenewfile_count: u64,
    pub file_change_changeoverwritefile_count: u64,
    pub file_change_changerenamefile_count: u64,
    pub file_change_changewrite_count: u64,
    pub file_change_opendirectory_count: u64,
    pub file_change_regcreatekey_count: u64,
    pub file_change_regdeletekey_count: u64,
    pub file_change_regdeletevalue_count: u64,
    pub file_change_regenumkey_count: u64,
    pub file_change_regenumvalue_count: u64,
    pub file_change_regopenkey_count: u64,
    pub file_change_regquerykey_count: u64,
    pub file_change_regqueryvalue_count: u64,
    pub file_change_regrenamekey_count: u64,
    pub file_change_regsetvalue_count: u64,

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
            + self.pipe_create_count
            + self.pipe_write_count
    }

    pub fn get_high_entropy_count(&self) -> usize {
        self.high_entropy_files.len()
    }

    pub fn record_operation(&mut self, rec: &IrpOperationRecord) {
        *self.raw_irp_counts.entry(rec.irp_type).or_insert(0) += 1;
        let irp_op = IrpMajorOp::from_sysmonevent(rec.irp_type);

        // Detailed per-variant IRP counters. Keep each concrete variant independent.
        match irp_op {
            IrpMajorOp::IrpCreate => self.irp_major_irpcreate_count += 1,
            IrpMajorOp::IrpKernelCreateSection => self.irp_major_irpkernelcreatesection_count += 1,
            IrpMajorOp::IrpKernelCreateThread => self.irp_major_irpkernelcreatethread_count += 1,
            IrpMajorOp::IrpKernelMapSection => self.irp_major_irpkernelmapsection_count += 1,
            IrpMajorOp::IrpKernelProtectMemory => self.irp_major_irpkernelprotectmemory_count += 1,
            IrpMajorOp::IrpKernelQueueApc => self.irp_major_irpkernelqueueapc_count += 1,
            IrpMajorOp::IrpKernelRemoteThread => self.irp_major_irpkernelremotethread_count += 1,
            IrpMajorOp::IrpKernelWriteMemory => self.irp_major_irpkernelwritememory_count += 1,
            IrpMajorOp::IrpNamedPipeCreate => self.irp_major_irpnamedpipecreate_count += 1,
            IrpMajorOp::IrpNamedPipeWrite => self.irp_major_irpnamedpipewrite_count += 1,
            IrpMajorOp::IrpProcessCreate => self.irp_major_irpprocesscreate_count += 1,
            IrpMajorOp::IrpProcessExit => self.irp_major_irpprocessexit_count += 1,
            IrpMajorOp::IrpProcessHandleOpen => self.irp_major_irpprocesshandleopen_count += 1,
            IrpMajorOp::IrpProcessTerminate => self.irp_major_irpprocessterminate_count += 1,
            IrpMajorOp::IrpProcessTerminateAttempt => self.irp_major_irpprocessterminateattempt_count += 1,
            IrpMajorOp::IrpRead => self.irp_major_irpread_count += 1,
            IrpMajorOp::IrpRegistry => self.irp_major_irpregistry_count += 1,
            IrpMajorOp::IrpRootkitFileMove => self.irp_major_irprootkitfilemove_count += 1,
            IrpMajorOp::IrpRootkitGeneric => self.irp_major_irprootkitgeneric_count += 1,
            IrpMajorOp::IrpRootkitHiddenDriver => self.irp_major_irprootkithiddendriver_count += 1,
            IrpMajorOp::IrpRootkitHiddenProcess => self.irp_major_irprootkithiddenprocess_count += 1,
            IrpMajorOp::IrpRootkitKernelHook => self.irp_major_irprootkitkernelhook_count += 1,
            IrpMajorOp::IrpRootkitSsdtHook => self.irp_major_irprootkitssdthook_count += 1,
            IrpMajorOp::IrpRootkitTerminateProcess => self.irp_major_irprootkitterminateprocess_count += 1,
            IrpMajorOp::IrpSetInfo => self.irp_major_irpsetinfo_count += 1,
            IrpMajorOp::IrpUserModeHookEvent => self.irp_major_irpusermodehookevent_count += 1,
            IrpMajorOp::IrpWrite => self.irp_major_irpwrite_count += 1,
            IrpMajorOp::_IrpCleanUp => self.irp_major_irpcleanup_count += 1,
            IrpMajorOp::IrpNone => {}
        }

        // Detailed per-variant file-change counters. Keep each concrete variant independent.
        match rec.file_change {
            x if x == FileChangeInfo::ChangeDeleteFile as u8 => self.file_change_changedeletefile_count += 1,
            x if x == FileChangeInfo::ChangeDeleteNewFile as u8 => self.file_change_changedeletenewfile_count += 1,
            x if x == FileChangeInfo::ChangeExtensionChanged as u8 => self.file_change_changeextensionchanged_count += 1,
            x if x == FileChangeInfo::ChangeNewFile as u8 => self.file_change_changenewfile_count += 1,
            x if x == FileChangeInfo::ChangeOverwriteFile as u8 => self.file_change_changeoverwritefile_count += 1,
            x if x == FileChangeInfo::ChangeRenameFile as u8 => self.file_change_changerenamefile_count += 1,
            x if x == FileChangeInfo::ChangeWrite as u8 => self.file_change_changewrite_count += 1,
            x if x == FileChangeInfo::OpenDirectory as u8 => self.file_change_opendirectory_count += 1,
            x if x == FileChangeInfo::RegCreateKey as u8 => self.file_change_regcreatekey_count += 1,
            x if x == FileChangeInfo::RegDeleteKey as u8 => self.file_change_regdeletekey_count += 1,
            x if x == FileChangeInfo::RegDeleteValue as u8 => self.file_change_regdeletevalue_count += 1,
            x if x == FileChangeInfo::RegEnumKey as u8 => self.file_change_regenumkey_count += 1,
            x if x == FileChangeInfo::RegEnumValue as u8 => self.file_change_regenumvalue_count += 1,
            x if x == FileChangeInfo::RegOpenKey as u8 => self.file_change_regopenkey_count += 1,
            x if x == FileChangeInfo::RegQueryKey as u8 => self.file_change_regquerykey_count += 1,
            x if x == FileChangeInfo::RegQueryValue as u8 => self.file_change_regqueryvalue_count += 1,
            x if x == FileChangeInfo::RegRenameKey as u8 => self.file_change_regrenamekey_count += 1,
            x if x == FileChangeInfo::RegSetValue as u8 => self.file_change_regsetvalue_count += 1,
            _ => {}
        }

        match irp_op {
            // File operations
            IrpMajorOp::IrpRead => {
                self.irp_read_count += 1;
                self.read_count += 1;
                self.total_bytes_read += rec.bytes_transferred;
            }
            IrpMajorOp::IrpWrite => {
                self.irp_write_count += 1;
                self.write_count += 1;
                self.total_bytes_written += rec.bytes_transferred;
            }
            IrpMajorOp::IrpCreate => {
                self.irp_create_count += 1;
                self.create_count += 1;
            }
            IrpMajorOp::IrpSetInfo => {
                self.irp_setinfo_count += 1;
                self.setinfo_count += 1;
                // Track specific file changes
                match rec.file_change {
                    _ if rec.file_change == FileChangeInfo::ChangeDeleteFile as u8
                        || rec.file_change == FileChangeInfo::ChangeDeleteNewFile as u8 => {
                        self.irp_delete_count += 1;
                        self.delete_count += 1;
                    }
                    _ if rec.file_change == FileChangeInfo::ChangeRenameFile as u8
                        || rec.file_change == FileChangeInfo::ChangeExtensionChanged as u8 => {
                        self.irp_rename_count += 1;
                        self.rename_count += 1;
                    }
                    _ => {}
                }
            }

            // Registry operations
            IrpMajorOp::IrpRegistry => {
                match rec.file_change {
                    _ if rec.file_change == FileChangeInfo::RegCreateKey as u8 => {
                        self.registry_create_count += 1;
                        self.create_count += 1;
                    }
                    _ if rec.file_change == FileChangeInfo::RegSetValue as u8 => {
                        self.registry_write_count += 1;
                        self.write_count += 1;
                    }
                    // FIX (Bug #2): RegDeleteKey (14) was missing and fell through to
                    // registry_read_count. Both value-delete and key-delete are deletions.
                    _ if rec.file_change == FileChangeInfo::RegDeleteValue as u8
                        || rec.file_change == FileChangeInfo::RegDeleteKey as u8 =>
                    {
                        self.registry_delete_count += 1;
                        self.delete_count += 1;
                    }
                    // RegQueryValue / RegQueryKey / RegOpenKey / RegEnumKey / RegEnumValue
                    // are all read-class operations — the catch-all is correct for them.
                    _ => {
                        self.registry_read_count += 1;
                        self.read_count += 1;
                    },
                }
            }

            // Process operations
            IrpMajorOp::IrpProcessCreate => { self.process_create_count += 1; self.create_count += 1; }
            IrpMajorOp::IrpProcessTerminate => { self.process_terminate_count += 1; self.process_delete_count += 1; }
            IrpMajorOp::IrpProcessTerminateAttempt => { self.process_terminate_attempt_count += 1; self.process_delete_count += 1; }
            IrpMajorOp::IrpProcessExit => { self.process_exit_count += 1; }
            IrpMajorOp::IrpProcessHandleOpen => { self.process_handle_open_count += 1; self.process_open_count += 1; }

            // Named pipe operations
            IrpMajorOp::IrpNamedPipeCreate => {
                self.pipe_create_count += 1; self.create_count += 1;
                if !rec.pipe_name.is_empty() {
                    self.unique_paths_accessed.insert(rec.pipe_name.clone());
                }
            }
            IrpMajorOp::IrpNamedPipeWrite => {
                self.pipe_write_count += 1; self.write_count += 1;
                self.total_bytes_written += if rec.pipe_payload.is_empty() {
                    rec.bytes_transferred
                } else {
                    rec.pipe_payload.len() as u64
                };
                if !rec.pipe_name.is_empty() {
                    self.unique_paths_accessed.insert(rec.pipe_name.clone());
                }
            }

            // User-mode hook and kernel-API events are tracked together.
            IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection => {
                match irp_op {
                    IrpMajorOp::IrpKernelWriteMemory => {
                        self.memory_write_count += 1;
                        self.process_memory_write_count += 1;
                        self.write_count += 1;
                    }
                    IrpMajorOp::IrpKernelCreateSection | IrpMajorOp::IrpKernelMapSection => {
                        self.memory_read_count += 1;
                        self.read_count += 1;
                    }
                    _ => {}
                }
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

    pub fn get_operation_count(&self, op_type: &str) -> u64 {
        if let Some(opcode) = irp_opcode_from_operation_token(op_type) {
            return *self.raw_irp_counts.get(&(opcode as u32)).unwrap_or(&0);
        }

        match op_type {
            "irp_read" => self.irp_read_count,
            "irp_write" => self.irp_write_count,
            "irp_create" => self.irp_create_count,
            "irp_delete" => self.irp_delete_count,
            "irp_rename" => self.irp_rename_count,
            "irp_setinfo" | "irp_set_info" => self.irp_setinfo_count,
            "read" => self.read_count,
            "write" => self.write_count,
            "create" => self.create_count,
            "close" => self.close_count,
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
            "process_open" => self.process_open_count,
            "process_memory_read" => self.process_memory_read_count,
            "process_memory_write" => self.process_memory_write_count,
            "pipe_create" | "named_pipe_create" => self.pipe_create_count,
            "pipe_write" | "named_pipe_write" => self.pipe_write_count,
            "memory_read" => self.memory_read_count,
            "memory_write" => self.memory_write_count,
            "process_terminate_attempt" => self.process_terminate_attempt_count,
            _ => 0,
        }
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
    let p = path.replace("\\\\", "/").replace('\\', "/");
    let mut out = String::with_capacity(p.len());
    let mut prev_slash = false;
    for ch in p.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
                prev_slash = true;
            }
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    out.trim_end_matches('/').to_string()
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

/// Strip the drive prefix from a rule *pattern* while preserving path anchoring.
///
fn canonical_behavior_path(path: &str) -> String {
    let normalized = normalize_device_prefix(path);
    let normalized = normalize_path_separators(&normalized.to_lowercase());
    strip_drive_prefix(&normalized)
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

    use crate::shared_def::SysmonEvent as SE;
    match normalized.as_str() {
        "none" => Some(0),
        // File read
        "read"
        | "file_read"
        | "file_data_read"
        | "file_data_read_full"
        | "filedatareadfull" => Some(SE::FileDataReadFull as u32),
        // File write (full payload)
        "write"
        | "file_write"
        | "file_data_write"
        | "file_data_write_full"
        | "filedatawritefull" => Some(SE::FileDataWriteFull as u32),
        // File data change (metadata/size update)
        "setinfo" | "set_info"
        | "file_data_change"
        | "filedatachange" => Some(SE::FileDataChange as u32),
        // File create / open
        "create" | "open"
        | "file_create"
        | "filecreate" => Some(SE::FileCreate as u32),
        // File delete
        "delete"
        | "file_delete"
        | "filedelete" => Some(SE::FileDelete as u32),
        // File close
        "cleanup" | "clean_up" | "close"
        | "file_close"
        | "fileclose" => Some(SE::FileClose as u32),
        // Registry
        "registry" => Some(SE::RegistryKeyCreate as u32),
        // Process
        "process_create" | "processcreate" | "proc_create" | "proccreate" => {
            Some(SE::ProcessCreate as u32)
        }
        "process_terminate" | "processterminate" | "proc_terminate" | "proc_term" | "procterm" => {
            Some(8)
        }
        "process_terminate_attempt" | "proc_terminate_attempt" | "proc_term_attempt" => Some(9),
        "process_exit" | "processexit" | "proc_exit" | "procexit" => Some(10),
"process_handle_open"
        | "processhandleopen"
        | "proc_handle_open"
        | "prochandleopen"
        | "processopen" => Some(SE::ProcessOpen as u32),
        "cross_process_handle"
        | "crossprocesshandle"
        | "cross_process_open"
        | "crossprocessopen"
        | "cross_process_handle_open"
        | "crossprocesshandleopen" => Some(SE::ProcessOpen as u32),
        // Kernel / rootkit events (mapped through DeviceIoControl opcode space)
        "process_memory_write" | "processmemorywrite" => Some(14),
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
    use crate::shared_def::SysmonEvent as SE;
    let normalized = normalize_irp_operation_token(token);
    let irp_op = IrpMajorOp::from_sysmonevent(irp_type);

    match normalized.as_str() {
        // Delete: IrpSetInfo + delete file_change  OR  direct LLE_FILE_DELETE opcode
        "delete"
        | "file_delete"
        | "filedelete" => {
            // Direct opcode match (LLE_FILE_DELETE = SysmonEvent::FileDelete)
            if irp_type == SE::FileDelete as u32 {
                return true;
            }
            return irp_op == IrpMajorOp::IrpSetInfo
                && matches!(
                    file_change,
                    x if x == FileChangeInfo::ChangeDeleteFile as u8
                        || x == FileChangeInfo::ChangeDeleteNewFile as u8
                );
        }
        // Rename
        "rename" => {
            if irp_type == SE::FileRename as u32 {
                return true;
            }
            return irp_op == IrpMajorOp::IrpSetInfo
                && matches!(
                    file_change,
                    x if x == FileChangeInfo::ChangeRenameFile as u8
                        || x == FileChangeInfo::ChangeExtensionChanged as u8
                );
        }
        // Full read (exact LLE event) or any semantically-classified read
        "read"
        | "file_read"
        | "file_data_read"
        | "file_data_read_full"
        | "filedatareadfull" => {
            return irp_type == SE::FileDataReadFull as u32
                || irp_op == IrpMajorOp::IrpRead;
        }
        // Full write (exact LLE event) or any semantically-classified write
        "write"
        | "file_write"
        | "file_data_write"
        | "file_data_write_full"
        | "filedatawritefull" => {
            return irp_type == SE::FileDataWriteFull as u32
                || irp_op == IrpMajorOp::IrpWrite;
        }
        // Dedicated mmap (section-map) events
        "mmap_read"
        | "file_map_read"
        | "map_read" => {
            return irp_type == SE::FileMapRead as u32;
        }
        "mmap_write"
        | "file_map_write"
        | "map_write" => {
            return irp_type == SE::FileMapWrite as u32;
        }
        // Dedicated ObRegisterCallbacks desktop-handle-open event
        "handle_open"
        | "desktop_handle_open"
        | "ob_register_callbacks" => {
            return irp_type == SE::DesktopOpen as u32;
        }
        // Data change / setinfo
        "setinfo"
        | "set_info"
        | "file_data_change"
        | "filedatachange" => {
            return irp_type == SE::FileDataChange as u32 || irp_op == IrpMajorOp::IrpSetInfo;
        }
        // Create / open
        "create"
        | "open"
        | "file_create"
        | "filecreate" => {
            return irp_type == SE::FileCreate as u32 || irp_op == IrpMajorOp::IrpCreate;
        }
        // Close
        "close"
        | "cleanup"
        | "clean_up"
        | "file_close"
        | "fileclose" => {
            return irp_type == SE::FileClose as u32 || irp_op == IrpMajorOp::_IrpCleanUp;
        }
        // Registry
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
"process_memory_write" | "processmemorywrite" => {
            return irp_type == 14 || irp_op == IrpMajorOp::IrpKernelWriteMemory;
        }
        "cross_process_handle"
        | "crossprocesshandle"
        | "cross_process_open"
        | "crossprocessopen"
        | "cross_process_handle_open"
        | "crossprocesshandleopen" => {
            return irp_type == SE::ProcessOpen as u32
                || irp_op == IrpMajorOp::IrpProcessHandleOpen;
        }
        _ => {}
    }

    irp_opcode_from_operation_token(&normalized) == Some(irp_type as u32)
}

/// Maximum number of distinct match keys remembered per named condition.
/// Entries age out of a FIFO (oldest first) instead of a hard reset, so a
/// sudden burst of events cannot wipe the whole dedup window and re-count
/// recently seen keys.
const CONDITION_MATCH_VALUE_CAP: usize = 256;

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
        IrpMajorOp::IrpUserModeHookEvent
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
        "IrpUserModeHookEvent"
            | "IrpKernelRemoteThread"
            | "IrpKernelWriteMemory"
            | "IrpKernelProtectMemory"
            | "IrpKernelCreateThread"
            | "IrpKernelQueueApc"
            | "IrpKernelCreateSection"
            | "IrpKernelMapSection"
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

fn is_benign_kernel_failure_status(operation_status: i32, is_acg_enabled: bool) -> bool {
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

fn is_actionable_kernel_event(
    irp_op: &IrpMajorOp,
    operation_status: i32,
    is_acg_enabled: bool,
) -> bool {
    if !is_kernel_api_irp(irp_op) {
        return false;
    }

    // Benign handle-race fallout from GUI/WebView/browser lifetime churn should
    // stay visible in low-level telemetry, but must not contaminate behavioral
    // API history or trigger higher-level detections.
    if is_benign_kernel_failure_status(operation_status, is_acg_enabled) {
        return false;
    }

    is_kernel_process_protection_irp(irp_op)
        || matches!(irp_op, IrpMajorOp::IrpUserModeHookEvent)
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
    pub terminated_processes: HashSet<String>,
    pub detected_apis: HashSet<String>,

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
    // Fine-grained signature classification surfaced from SignatureInfo so
    // rules can distinguish attached vs catalog signatures and executable files.
    pub is_executable: bool,
    pub is_catalog_signed: bool,
    pub is_attached_signed: bool,

    // Fast static ML detections (fast_detect_file) recorded for this process:
    // "MaliciousJsScript", "MaliciousPeExecutable". Behavior rules can
    // reference these via the `ml_detection` / `ml_detected` conditions.
    pub ml_detections: Vec<String>,
    // ML feature vector (feature name -> value) from the fast static ML engine,
    // e.g. is_obfuscated, entropy, suspicious_score. Rules reference these via
    // the `ml_features` condition.
    pub ml_features: HashMap<String, f32>,

    pub satisfied_named_conditions: HashSet<String>,
    pub condition_match_counts: HashMap<String, usize>,
    pub condition_match_values: HashMap<String, HashSet<String>>,
    /// Insertion order per condition for FIFO eviction of match keys.
    pub condition_match_order: HashMap<String, VecDeque<String>>,
    pub condition_first_seen: HashMap<String, SystemTime>,
    pub condition_last_seen: HashMap<String, SystemTime>,

    // Comprehensive IRP tracking
    pub irp_operations: Vec<IrpOperationRecord>,
    pub irp_stats: IrpStatistics,
    pub all_apis_called: HashSet<String>,
    pub recent_kernel_api_events: VecDeque<String>,

    /// Opaque OpenEDR events retained exactly as received.
    pub raw_openedr_events: VecDeque<String>,

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
    
    pub http_body_entries: Vec<(String, String)>,

    /// Rolling history of network packets captured for this process (FULL_PACKED_DATA).
    
    pub net_packets: VecDeque<PacketInfo>,

    /// AMSI analysis results for script content monitored by the engine.
    pub amsi_results: Vec<crate::behavioral::amsi::AmsiAnalysisResult>,

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
        state.is_executable = false;
        state.ml_detections = Vec::new();
        state.ml_features = HashMap::new();
        state.is_catalog_signed = false;
        state.is_attached_signed = false;
        state.parent_name = "unknown".to_string();
        state.parent_path = PathBuf::new();
        state.command_line = String::new();
        state.terminated_processes = HashSet::new();
        state.detected_apis = HashSet::new();
        state.satisfied_named_conditions = HashSet::new();
        state.condition_match_counts = HashMap::new();
        state.condition_match_values = HashMap::new();
        state.condition_match_order = HashMap::new();
        state.condition_first_seen = HashMap::new();
        state.condition_last_seen = HashMap::new();
        state.irp_operations = Vec::new();
        state.irp_stats = IrpStatistics::default();
        state.all_apis_called = HashSet::new();
        state.recent_kernel_api_events = VecDeque::with_capacity(128);
        state.self_defense_events = VecDeque::with_capacity(128);
        state.self_defense_event_count = 0;
        state.self_defense_category_counts = HashMap::new();
        state.self_defense_attack_counts = HashMap::new();
        state.hook_error_count = 0;
        state.hook_error_status_counts = HashMap::new();
        state.hook_error_api_counts = HashMap::new();
        state.recent_hook_errors = VecDeque::with_capacity(128);

        state.created_unknown_ext_stems = HashSet::new();
        state.written_unknown_ext_stems = HashSet::new();
        state.script_file = String::new();
        state.script_file_path = String::new();
        
        {
            state.net_packets = VecDeque::with_capacity(500);
            state.http_body_entries = Vec::new();
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

        // Initialize MITRE ATT&CK fields (only with behavior_engine feature)
        {
            state.mitre_techniques = HashSet::new();
            state.mitre_timeline_events = Vec::new();
            state.mitre_threat_score = 0.0;
        }

        state
    }

    /// True when the Comodo cloud has marked this process Safe (FLS code 1).
    /// Once remembered on the state this is what "clean file" means for the
    /// trust policy: reduced monitoring and kill-only remediation.
    pub fn is_comodo_cloud_trusted(&self) -> bool {
        is_openedr_fls_safe_code(self.cloud_static_verdict)
            || is_openedr_fls_safe_code(self.cloud_dynamic_verdict)
    }

    /// Generic condition match recording and threshold evaluation.
    pub fn record_condition_match(
        &mut self,
        scoped_name: &str,
        match_key: String,
        now: SystemTime,
        required: usize,
        debug: bool,
    ) -> bool {
        let values = self
            .condition_match_values
            .entry(scoped_name.to_string())
            .or_insert_with(HashSet::new);
        let order = self
            .condition_match_order
            .entry(scoped_name.to_string())
            .or_insert_with(VecDeque::new);
        let is_new = BehaviorEngine::insert_bounded_match_value(
            values,
            order,
            match_key.clone(),
            CONDITION_MATCH_VALUE_CAP,
        );
        let count = self
            .condition_match_counts
            .entry(scoped_name.to_string())
            .or_insert(0);
        if is_new {
            *count += 1;
        }
        self.condition_first_seen
            .entry(scoped_name.to_string())
            .or_insert(now);
        self.condition_last_seen
            .insert(scoped_name.to_string(), now);

        let satisfied = *count >= required.max(1);
        if satisfied {
            self.satisfied_named_conditions.insert(scoped_name.to_string());
            if debug {
                Logging::debug(&format!(
                    "[BehaviorEngine] Condition '{}' satisfied for PID {} (count: {}/{}, match: {})",
                    scoped_name,
                    self.pid,
                    *count,
                    required.max(1),
                    match_key
                ));
            }
        }
        satisfied
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
            is_legacy_kernel_subtype: msg.kernel_event_info.event_type != 0,
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

        let actionable_kernel_event = is_actionable_kernel_event(
            &irp_kind,
            operation_status,
            msg.kernel_event_info.is_acg_enabled,
        );

        if !is_api_event || actionable_kernel_event {
            self.irp_stats.record_operation(&rec);
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
            let event_family = if is_kernel_process_protection_irp(&irp_kind) {
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

            if real_api {
                if actionable_kernel_event {
                    self.detected_apis.insert(event_name.clone());
                    self.all_apis_called.insert(event_name.clone());
                    if let Some(alias) = api_function_alias(&event_name) {
                        self.detected_apis.insert(alias.clone());
                        self.all_apis_called.insert(alias.clone());
                    }
                }
                Logging::info(&format!(
                    "[API HOOKING EVENT{}] opcode={} raw_event_type={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} api=\"{}\"",
                    if actionable_kernel_event {
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
                ));
            } else {
                let event_label =
                    canonical_hypervisor_event_label(&irp_kind, raw_event_type, &event_name)
                        .unwrap_or_else(|| event_name.clone());
                let event_family = if is_kernel_process_protection_irp(&irp_kind) {
                    "KERNEL API EVENT"
                } else if matches!(irp_kind, IrpMajorOp::IrpUserModeHookEvent) {
                    "USERMODE HOOK EVENT"
                } else {
                    "KERNEL EVENT"
                };
                Logging::info(&format!(
                    "[{}{}] opcode={} raw_event_type={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} event=\"{}\"",
                    event_family,
                    if actionable_kernel_event {
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
    /// Aho-Corasick (daachorse) index over the literal API-name fragments
    /// referenced by loaded rules. Built in `load_rules`; used to quickly
    /// decide whether an incoming hook/IOCTL record's `function_name` is
    /// relevant to any rule before regex evaluation. `Arc<RwLock<_>>` so the
    /// telemetry-thread `BehaviorEngine` clone shares the main thread's index.
    api_pattern_index: Arc<std::sync::RwLock<Option<daachorse::DoubleArrayAhoCorasick<u32>>>>,
    pub process_terminated: HashSet<String>,
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
    /// PIDs queued by the OpenEDR telemetry consumer on LLE_PROCESS_CREATE so the
    /// Worker's periodic scan applies dynamic API hooks to newly started
    /// processes. In the in-process FFI architecture the kernel-IOMessage channel
    /// that drives `process_io` is never fed, so ProcessCreate events only reach
    /// the engine through this queue. `Arc<Mutex<_>>` so the telemetry-thread
    /// `BehaviorEngine` clone shares it with the Worker's main-thread engine.
    pub pending_hook_pids: Arc<Mutex<std::collections::VecDeque<u32>>>,
    /// Raw telemetry lines from OpenEDR/OwlyShield and firewall JSON events.
    /// The original JSON strings are retained for raw_json_patterns evaluation.
    pub pending_raw_events: Arc<Mutex<std::collections::VecDeque<(u32, String)>>>,
    /// PIDs for which the firewall observed real outbound network I/O (NET_EVENT).
    
    pub firewall_net_pids: FirewallNetPids,
    /// Per-PID list of (dst_ip, dst_port) connection records from NET_EVENT messages.
    /// Used by named-condition rules to match specific IPs or ports.
    
    pub firewall_net_details: FirewallNetDetails,
    /// Exe paths for which the firewall confirmed malicious traffic (BLOCK_EXE).
    /// Value holds full detection details for report generation.
    /// scan_all_processes marks matching processes as malicious and acts on them.
    
    pub firewall_blocked_exes: FirewallBlockedExes,
    

    
    firewall_hips_pending_prompts: FirewallHipsPendingPrompts,
    
    firewall_hips_decisions: FirewallHipsDecisions,
    
    firewall_hips_allow_once: FirewallHipsAllowOnce,
    
    firewall_hips_allow_always: FirewallHipsAllowAlways,
    /// Per-PID HTTP body pairs captured by the MITM proxy (received via HTTP_BODY pipe messages).
    
    firewall_http_body_map: FirewallHttpBodyMap,
    /// Per-PID rolling history of full network packets from the firewall.
    
    firewall_full_packets: FirewallFullPackets,
    
    pub generate_report_flag: FirewallGenerateReport,
    /// File verdicts received from the firewall (keyed by file path lowercase).
    
    pub firewall_file_verdicts: FirewallFileVerdicts,
    pub rootkit_findings: Vec<RootkitFinding>,
    pub amsi_analyzer: crate::behavioral::amsi::AmsiAnalyzer,
}

pub trait RawEventInput {
    fn into_raw_event(&self) -> String;
}

impl RawEventInput for str {
    fn into_raw_event(&self) -> String { self.to_owned() }
}

impl RawEventInput for String {
    fn into_raw_event(&self) -> String { self.clone() }
}

#[cfg(test)]
impl RawEventInput for serde_json::Value {
    fn into_raw_event(&self) -> String { self.to_string() }
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new()
    }
}



impl BehaviorEngine {
    pub fn new() -> Self {
        Self::new_with_extension_source_mode(None)
    }

    pub fn new_with_extension_source_mode(_extension_source_mode: Option<&str>) -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
            api_pattern_index: Arc::new(std::sync::RwLock::new(None)),
            process_terminated: HashSet::new(),
            openedr_net_pids: shared_openedr_net_pids(),
            openedr_net_details: shared_openedr_net_details(),
            openedr_stats: shared_openedr_stats(),
            self_defense_telemetry: shared_self_defense_telemetry(),
            pending_irp_records: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            pending_hook_pids: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            pending_raw_events: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            
            firewall_net_pids: shared_firewall_net_pids(),
            
            firewall_net_details: shared_firewall_net_details(),
            
            firewall_blocked_exes: shared_firewall_blocked_exes(),
            

            
            firewall_hips_pending_prompts: shared_firewall_hips_pending_prompts(),
            
            firewall_hips_decisions: shared_firewall_hips_decisions(),
            
            firewall_hips_allow_once: shared_firewall_hips_allow_once(),
            
            firewall_hips_allow_always: shared_firewall_hips_allow_always(),
            
            firewall_http_body_map: shared_firewall_http_body_map(),
            
            firewall_full_packets: shared_firewall_full_packets(),
            
            generate_report_flag: shared_firewall_generate_report(),
            
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

    /// Process a single `FULL_PACKED_DATA:<json>` line forwarded by OpenEDR.
    /// Updates the same shared state as the HydraNetEvent pipe handler so that
    /// behavior-rule matching and HTTP-body analysis work regardless of which
    /// path delivers the packet.
    
    pub fn ingest_firewall_packed_data(&self, json: &str) {
        // Keep the complete firewall JSON opaque for behavior-rule matching.
        // The existing typed firewall path below remains intact for packet/body handling.
        let raw_pid = serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| {
                v.get("packet")
                    .and_then(|p| p.get("process_id"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v.min(u32::MAX as u64) as u32)
                    .or_else(|| {
                        v.get("process_id")
                            .and_then(|v| v.as_u64())
                            .map(|v| v.min(u32::MAX as u64) as u32)
                    })
            })
            .unwrap_or(0);
        self.queue_raw_json_event(raw_pid, json.to_owned());

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

                shared_firewall_net_pids().write().unwrap().insert(pid);

                if !req_body.is_empty() || !resp_body.is_empty() {
                    shared_firewall_http_body_map()
                        .write()
                        .unwrap()
                        .entry(pid)
                        .or_default()
                        .push((req_body, resp_body));
                }

                {
                    let full_packets_arc = shared_firewall_full_packets();
                    let mut pkt_map = full_packets_arc.write().unwrap();
                    let history = pkt_map
                        .entry(pid)
                        .or_insert_with(|| VecDeque::with_capacity(500));
                    if history.len() >= 500 {
                        history.pop_front();
                    }
                    history.push_back(pkt.clone());
                }

                // Behavior rule matching — identical logic to the HydraNetEvent handler.
                let mut matched_any = false;
                for rule in self.rules.iter() {
                    if rule.matches_packet(&self.regex_cache, &pkt, &[]) {
                        matched_any = true;

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
                                || rule.response.terminate_process
                                || rule.response.traffic_attack)
                        {
                            let blocked_exes_arc = shared_firewall_blocked_exes();
                            let mut blocked = blocked_exes_arc.write().unwrap();

                            let reason = if rule.response.traffic_attack {
                                format!("Traffic attack rule [{}] matched", rule.name)
                            } else if rule.response.change_request_body.is_some()
                                || rule.response.change_response_body.is_some()
                            {
                                format!("Rule [{}] matched (Replacement suggested)", rule.name)
                            } else {
                                format!("Rule [{}] matched", rule.name)
                            };

                            let (detected_domain, detected_subdomain) =
                                if let Some(ref hostname) = pkt.hostname {
                                    let parts: Vec<&str> = hostname.split('.').collect();
                                    if parts.len() >= 2 {
                                        let domain = format!(
                                            "{}.{}",
                                            parts[parts.len() - 2],
                                            parts[parts.len() - 1]
                                        );
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

                            blocked.insert(
                                normalize_firewall_file_verdict_key(&pkt.image_path),
                                FirewallDetection {
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
                                    is_traffic_attack: rule.response.traffic_attack,
                                },
                            );
                        }

                        if let Some(ref hostname) = pkt.hostname {
                            let _replaced = rule.apply_replacement(hostname);
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
    }

    /// Spawn the \\.\pipe\HydraNetEvent named pipe server thread.
    /// Firewall sends activity telemetry such as NET_EVENT and HTTP body data.
    /// Legacy BLOCK_EXE messages are still accepted defensively, but firewall
    /// network blocks should stay firewall activity and not become process kills.
    /// Call once after constructing BehaviorEngine, before the scan loop starts.
    
    /// Process a raw telemetry line (e.g. NET_EVENT, BLOCK_EXE, HIPS_DECISION, KERNEL_BLOCK_PATH, VERDICT, FULL_PACKED_DATA).
    /// Delivered in-process via the FFI telemetry channel instead of named pipes.
    pub fn ingest_firewall_raw_line(&self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }

        if crate::ffi::is_protection_stopped() {
            return;
        }

        if let Some(json) = line.strip_prefix("FULL_PACKED_DATA:") {
            self.ingest_firewall_packed_data(json);
        } else if let Some(rest) = line.strip_prefix("NET_EVENT:") {
            let mut parts = rest.splitn(3, ':');
            if let Some(pid_str) = parts.next()
                && let Ok(pid) = pid_str.parse::<u32>()
            {
                self.firewall_net_pids.write().unwrap().insert(pid);
                let dst_ip = parts.next().unwrap_or("").trim().to_string();
                let dst_port = parts
                    .next()
                    .unwrap_or("0")
                    .trim()
                    .parse::<u16>()
                    .unwrap_or(0);
                if !dst_ip.is_empty() {
                    self.firewall_net_details
                        .write()
                        .unwrap()
                        .entry(pid)
                        .or_default()
                        .push((dst_ip, dst_port));
                }
            }
        } else if let Some(rest) = line.strip_prefix("BLOCK_EXE:") {
            let mut parts = rest.splitn(5, '|');
            let exe = parts.next().unwrap_or("").trim().to_string();
            let dst_ip = parts.next().unwrap_or("").trim().to_string();
            let dst_port = parts
                .next()
                .unwrap_or("0")
                .trim()
                .parse::<u16>()
                .unwrap_or(0);
            let hostname = parts.next().unwrap_or("").trim().to_string();
            let reason = parts.next().unwrap_or("Firewall block").trim().to_string();

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
                    is_traffic_attack: reason.to_ascii_lowercase().contains("traffic attack"),
                };
                if detection.is_pending_user_decision() {
                    Logging::info(&format!(
                        "[FirewallTelemetry] Pending user decision for {}; not treating as confirmed malicious",
                        exe
                    ));
                    return;
                }
                Logging::warning(&format!(
                    "[FirewallTelemetry] Confirmed malicious: {} -> {}:{} ({}) - {}",
                    exe, detection.dst_ip, detection.dst_port, hostname, reason
                ));
                self.firewall_blocked_exes
                    .write()
                    .unwrap()
                    .insert(normalize_firewall_file_verdict_key(&exe), detection);
            }
        } else if let Some(rest) = line.strip_prefix("HIPS_DECISION:") {
            let mut parts = rest.splitn(2, '|');
            let request_id = parts.next().unwrap_or("").trim().to_string();
            let decision_raw = parts.next().unwrap_or("").trim();

            if !request_id.is_empty() {
                if let Some(decision) = FirewallHipsDecision::from_wire(decision_raw) {
                    self.firewall_hips_decisions
                        .write()
                        .unwrap()
                        .insert(request_id.clone(), decision);
                    Logging::info(&format!(
                        "[FirewallTelemetry] Received Owlyshield HIPS decision for request {}: {}",
                        request_id, decision_raw
                    ));
                } else {
                    Logging::warning(&format!(
                        "[FirewallTelemetry] Ignored unknown Owlyshield HIPS decision '{}'",
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
                        "[FirewallTelemetry] Installed kernel block path: {}",
                        block_path
                    )),
                    Some(Err(ref err)) => Logging::error(&format!(
                        "[FirewallTelemetry] Failed to install kernel block path {}: {}",
                        block_path, err
                    )),
                    None => Logging::warning(&format!(
                        "[FirewallTelemetry] No shared driver handle available for kernel block path {}",
                        block_path
                    )),
                }
            }
        } else if line == "GENERATE_REPORT" {
            self.generate_report_flag.store(true, Ordering::SeqCst);
            Logging::info("[FirewallTelemetry] Received on-demand report request");
        } else if let Some(rest) = line.strip_prefix("VERDICT:") {
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

                let file_path_key = normalize_firewall_file_verdict_key(&file_path);
                self.firewall_file_verdicts
                    .write()
                    .unwrap()
                    .insert(file_path_key.clone(), verdict_info);

                Logging::info(&format!(
                    "[OpenEDRVerdict] Received file verdict for {}: {} (code {})",
                    file_path, verdict_label, verdict_code
                ));

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
                        is_traffic_attack: false,
                    };
                    self.firewall_blocked_exes
                        .write()
                        .unwrap()
                        .insert(file_path_key, detection);
                    Logging::warning(&format!(
                        "[OpenEDRVerdict] Marked {} as malicious based on OpenEDR verdict",
                        file_path
                    ));

                    Self::quarantine_verdict_file(
                        &file_path,
                        &format!("OpenEDR FLS Verdict: {}", verdict_label),
                    );
                }
            } else {
                Logging::warning(&format!(
                    "[OpenEDRVerdict] Received incomplete VERDICT message: {}",
                    rest
                ));
            }
        } else {
            // Default: ingest as packed data or JSON event
            self.ingest_firewall_packed_data(line);
        }
    }

    /// Seal a file into a .hqf quarantine container and remove the original.
    fn quarantine_verdict_file(file_path: &str, detection: &str) {
        if file_path.is_empty()
            || file_path.to_lowercase() == "unknown"
            || file_path.to_lowercase() == "system"
        {
            return;
        }
        let clean_path = file_path
            .trim_start_matches(r"\??\")
            .trim_start_matches(r"\\?\");
        let src_buf = if Path::new(clean_path).exists() {
            PathBuf::from(clean_path)
        } else if Path::new(file_path).exists() {
            PathBuf::from(file_path)
        } else {
            return;
        };

        match crate::windows::quarantine::quarantine_path(&src_buf, detection) {
            Ok(dst) => Logging::warning(&format!(
                "[OpenEDRVerdict] Quarantined {} into {} ({})",
                src_buf.display(),
                dst.display(),
                detection
            )),
            Err(e) => Logging::error(&format!(
                "[OpenEDRVerdict] Failed to quarantine {}: {}",
                src_buf.display(), e
            )),
        }
    }

    /// Write one newline-terminated message to the HydraHipEvent pipe.
    /// Returns true when the full payload was delivered.
    #[allow(dead_code)]
    fn write_hydra_hip_event(message: &str) -> bool {
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
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        }

        Logging::debug(&format!(
            "[OpenEDRVerdict] HydraHipEvent delivery failed after {} attempts: {}",
            CONNECT_ATTEMPTS, last_error
        ));
        false
    }

    /// Notify the firewall GUI about the OpenEDR FLS verdict for this process.
    #[allow(dead_code)]
    fn notify_firewall_openedr_verdict(
        &self,
        pid: u32,
        exe_path: &str,
        verdict: OpenEdrFlsVerdict,
        analysis_type: &str,
    ) {
        // A malicious FLS verdict is a malware event, not a HIPS event: raise
        // a THREAT_ALERT so every GUI surface classifies it as a detection.
        if verdict.is_malicious() {
            let threat_message = format!(
                "THREAT_ALERT:{}|{}\n",
                Self::sanitize_firewall_hips_field(&format!(
                    "OpenEDR FLS {} Verdict: Malware",
                    analysis_type
                )),
                Self::sanitize_firewall_hips_field(exe_path),
            );
            if Self::write_hydra_hip_event(&threat_message) {
                Logging::warning(&format!(
                    "[OpenEDRVerdict] Sent malware THREAT_ALERT for PID {}: {}",
                    pid, exe_path
                ));
            }
        }

        // The HIPS_VERDICT line is still required so the firewall can update
        // its per-PID cloud trust tracking.
        let message = format!(
            "HIPS_VERDICT:{}|{}|{}|{}\n",
            pid,
            Self::sanitize_firewall_hips_field(exe_path),
            verdict.code(),
            Self::sanitize_firewall_hips_field(analysis_type),
        );
        if Self::write_hydra_hip_event(&message) {
            Logging::debug(&format!(
                "[OpenEDRVerdict] Sent {} verdict for PID {} to firewall: {}",
                analysis_type,
                pid,
                verdict.display_label()
            ));
        } else {
            Logging::debug(&format!(
                "[OpenEDRVerdict] Firewall verdict update was not delivered for PID {}",
                pid
            ));
        }
    }


    /// Notify the firewall GUI via HydraHipEvent about an OpenEDR-sourced threat.
    /// Malware detections are THREAT_ALERTs, never HIPS ask prompts.
    #[allow(dead_code)]
    fn notify_openedr_threat(&self, pid: u32, exe_path: &str, label: &str, analysis_type: &str) {
        let threat_message = format!(
            "THREAT_ALERT:{}|{}\n",
            Self::sanitize_firewall_hips_field(&format!(
                "OpenEDR {} : {}",
                analysis_type, label
            )),
            Self::sanitize_firewall_hips_field(exe_path),
        );
        if Self::write_hydra_hip_event(&threat_message) {
            Logging::warning(&format!(
                "[OpenEDRVerdict] Sent malware THREAT_ALERT for PID {}: {} ({})",
                pid, exe_path, label
            ));
        }
    }

    /// Ingest an OpenEDR event with one generic JSON deserialization pass.
    ///
    /// The event is deserialized only into `serde_json::Value` so routing can read
    /// a tiny set of generic envelope fields (`type` and PID). No OpenEDR event
    /// schema is mapped into Rust structs and the original JSON string is retained
    /// unchanged for rule evaluation.
    pub fn ingest_openedr_event<T: RawEventInput + ?Sized>(&self, event: &T) {
        let raw_event = event.into_raw_event();

        let parsed: serde_json::Value = match serde_json::from_str(&raw_event) {
            Ok(value) => value,
            Err(err) => {
                Logging::warning(&format!(
                    "[OpenEDRTelemetry] Ignoring invalid JSON event: {}",
                    err
                ));
                return;
            }
        };

        let event_type = Self::json_string_field(
            &parsed,
            &["type", "event_type", "eventType", "event_name", "eventName"],
        )
        .unwrap_or_default();

        let pid = Self::json_u32_field(&parsed, &["pid", "processId"]).or_else(|| {
            parsed
                .get("process")
                .and_then(|process| Self::json_u32_field(process, &["pid", "processId"]))
        })
        .unwrap_or(0);

        if pid == 0 || event_type.is_empty() {
            Logging::debug(&format!(
                "[OpenEDRTelemetry] raw event retained without PID/type routing: {}",
                raw_event
            ));
            return;
        }

        if event_type.eq_ignore_ascii_case("LLE_PROCESS_CREATE") {
            Logging::info(&format!(
                "[OpenEDR ProcessCreate] QUEUE PID {} for dynamic hooks (raw)",
                pid
            ));
            if let Ok(mut q) = self.pending_hook_pids.lock() {
                if q.len() < 512 && !q.contains(&pid) {
                    q.push_front(pid);
                }
            }
            if let Ok(client) = crate::windows::edrsvc_client::Driver::open_kernel_driver_com() {
                let _ = client.hook_process(pid);
            }
        }

        self.queue_raw_json_event(pid, raw_event);
    }

    fn json_string_field(event: &serde_json::Value, names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| {
            event
                .get(*name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
    }

    fn json_u32_field(event: &serde_json::Value, names: &[&str]) -> Option<u32> {
        for name in names {
            if let Some(value) = event.get(*name) {
                if let Some(number) = value.as_u64() {
                    return Some(number.min(u32::MAX as u64) as u32);
                }
                if let Some(text) = value.as_str() {
                    if let Ok(number) = text.parse::<u64>() {
                        return Some(number.min(u32::MAX as u64) as u32);
                    }
                }
            }
        }

        None
    }

    /// Queue an opaque raw JSON event for behavior-rule evaluation.
    /// Used by both OpenEDR/OwlyShield telemetry and firewall JSON telemetry.
    fn queue_raw_json_event(&self, pid: u32, raw_json: String) {
        if pid == 0 || raw_json.trim().is_empty() {
            return;
        }

        if let Ok(mut q) = self.pending_raw_events.lock() {
            if q.len() >= 4096 {
                q.pop_front();
            }
            q.push_back((pid, raw_json));
        }
    }

    /// Drain opaque OpenEDR/firewall JSON events on the Worker thread.
    pub fn drain_pending_raw_events(&mut self) -> Vec<(u32, String)> {
        match self.pending_raw_events.lock() {
            Ok(mut q) => q.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Evaluates opaque raw JSON telemetry against named condition groups.
    /// Behavior YAML rules use `raw_json_patterns`; the original JSON is retained.
    pub fn apply_raw_openedr_events(&mut self, events: Vec<(u32, String)>) {
        if events.is_empty() {
            return;
        }

        for (pid, raw) in events {
            let Some(gid) = self.find_gid_by_pid(pid) else { continue };

            if let Some(state) = self.process_states.get_mut(&gid) {
                if state.raw_openedr_events.len() >= 256 {
                    state.raw_openedr_events.pop_front();
                }
                state.raw_openedr_events.push_back(raw.clone());

                let now = SystemTime::now();

                for rule in &self.rules {
                    for (cond_name, cond_group) in &rule.named_conditions {
                        let matched = !cond_group.raw_json_patterns.is_empty()
                            && cond_group.raw_json_patterns.iter().any(|p| {
                                Self::matches_pattern_internal(&self.regex_cache, p, &raw)
                            });

                        if matched {
                            state.record_condition_match(
                                &Self::scoped_condition_name(rule, cond_name),
                                format!(
                                    "raw:{}:{}",
                                    pid,
                                    now.duration_since(UNIX_EPOCH)
                                        .map(|d| d.as_nanos())
                                        .unwrap_or(0)
                                ),
                                now,
                                cond_group.min_matches.max(1),
                                rule.debug,
                            );
                        }
                    }
                }
            }
        }
    }
    pub fn ingest_capemon_event(&mut self, pid: u32, doc: bson::Document) {
        let gid = self.find_gid_by_pid(pid).unwrap_or(0);
        if gid == 0 {
            return;
        }

        // Convert BSON Document to serde_json::Value
        let json_val = serde_json::to_value(&doc).unwrap_or(serde_json::Value::Null);
        let json_str = serde_json::to_string(&json_val).unwrap_or_default();

        Logging::debug(&format!(
            "[Capemon] Ingested API hook from PID {} as JSON: {}",
            pid, json_str
        ));

        // Evaluate directly as a raw JSON event
        self.apply_raw_openedr_events(vec![(pid, json_str)]);
    }


    
    fn sanitize_firewall_hips_field(value: &str) -> String {
        value
            .replace('\r', " ")
            .replace('\n', " ")
            .replace('|', "/")
            .trim()
            .to_string()
    }

    
    fn is_registry_condition_group(cond_group: &NamedConditionGroup) -> bool {
        cond_group.json_field_conditions.iter().any(|jm| jm.field.contains("reg") || jm.field.contains("key"))
            || cond_group.json_match.as_ref().map_or(false, |jm| jm.field.contains("reg") || jm.field.contains("key"))
    }

    
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

    fn operation_label(msg: &IOMessage) -> String {
        let file_change = FromPrimitive::from_u8(msg.file_change);
        let hyper_event = msg.resolved_hypervisor_event();
        let irp_op = hyper_event
            .as_ref()
            .map(|event| event.irp_op.clone())
            .unwrap_or_else(|| IrpMajorOp::from_byte(effective_hypervisor_irp_byte(msg)));

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

        for (cond_name, _) in &rule.named_conditions {
            if !Self::rule_condition_satisfied(state, rule, cond_name) {
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

                if let Some(jm) = cond_group.json_field_conditions.iter().find(|jm| jm.field.contains("reg") || jm.field.contains("key")) {
                    if let serde_json::Value::String(ref s) = jm.value {
                        return s.clone();
                    }
                }
                if let Some(ref jm) = cond_group.json_match {
                    if jm.field.contains("reg") || jm.field.contains("key") {
                        if let serde_json::Value::String(ref s) = jm.value {
                            return s.clone();
                        }
                    }
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

    
    fn build_firewall_hips_reason(rule: &BehaviorRule) -> String {
        let description = rule.description.trim();
        if description.is_empty() {
            format!("Owlyshield rule '{}' matched.", rule.name)
        } else {
            format!("Owlyshield rule '{}' matched: {}", rule.name, description)
        }
    }

    
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


    #[allow(dead_code)]
    fn safe_pattern_match(text: &str, pattern: &str) -> bool {
        let text_lc = text.to_lowercase();
        let pattern_lc = pattern.to_lowercase();

        if text_lc.is_empty() || pattern_lc.is_empty() || text_lc == "unknown" {
            return false;
        }

        text_lc.contains(&pattern_lc) || pattern_lc.contains(&text_lc)
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
        self.rebuild_api_pattern_index();
        Logging::info(&format!(
            "[Owlyshield] Successfully loaded {} behavior rules from {:?}",
            count, path
        ));
        Ok(())
    }

    /// Rebuild the daachorse Aho-Corasick index over every literal API-name
    /// fragment referenced by the loaded rules' named conditions. Patterns that
    /// contain glob (`*`/`?`) or look like explicit regex are excluded — those
    /// still go through the regex cache. The index is used to fast-path incoming
    /// hook/IOCTL records: if `function_name` matches no indexed fragment, no
    /// rule can match it on the API field, so the record can be shed under
    /// pressure without touching regex.
    fn rebuild_api_pattern_index(&self) {
        let mut literals: Vec<(String, u32)> = Vec::new();
        for rule in &self.rules {
            for group in rule.named_conditions.values() {
                let mut push_group = |patterns: &[String]| {
                    for pat in patterns {
                        let trimmed = pat.trim();
                        if trimmed.is_empty()
                            || trimmed.contains('*')
                            || trimmed.contains('?')
                            || trimmed.starts_with("(?")
                            || trimmed.starts_with('^')
                            || trimmed.ends_with('$')
                        {
                            continue;
                        }
                        let (norm, _) = Self::normalize_api_signature(trimmed);
                        let norm = norm.to_ascii_lowercase();
                        if norm.is_empty() {
                            continue;
                        }
                        let idx = literals.len() as u32;
                        literals.push((norm, idx));
                    }
                };
                push_group(&group.hook_error_api_patterns);
            }
        }

        literals.sort_unstable();
        literals.dedup_by(|a, b| a.0 == b.0);

        let index = if literals.is_empty() {
            None
        } else {
            match daachorse::DoubleArrayAhoCorasick::with_values(literals) {
                Ok(index) => Some(index),
                Err(e) => {
                    Logging::warning(&format!(
                        "[BehaviorEngine] Failed to build daachorse API pattern index: {}",
                        e
                    ));
                    None
                }
            }
        };

        *self.api_pattern_index.write().unwrap() = index;
    }

    /// Fast check whether `text` contains any API-name fragment indexed by the
    /// daachorse automaton. Returns false when the index is empty (meaning no
    /// literal API conditions exist — caller must fall back to regex).
    pub fn api_index_contains(&self, text: &str) -> bool {
        let guard = match self.api_pattern_index.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match guard.as_ref() {
            None => false,
            Some(index) => {
                let haystack = text.to_ascii_lowercase();
                index
                    .find_overlapping_iter(haystack.as_bytes())
                    .next()
                    .is_some()
            }
        }
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
    /// Behavior rules no longer declare APIs. API monitoring is global/raw-event driven.
    pub fn get_all_monitored_apis(&self) -> HashSet<String> {
        HashSet::new()
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

    /// Drain the cross-thread pending IRP record queue.
    ///
    pub fn drain_pending_hook_pids(&mut self) -> Vec<u32> {
        match self.pending_hook_pids.lock() {
            Ok(mut q) => q.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Called from the main Worker thread (which owns `&mut self`) so that the
    /// pipe thread — which only holds a cloned `BehaviorEngine` with `&self` access
    /// — can still feed IRP telemetry without race conditions.
    /// Returns each record as a `(gid, IOMessage)` pair so the Worker can route
    /// them through `process_event` — giving OpenEDR-only (non-edrdrv) events the
    /// same named-condition group + rule evaluation as driver events.
    pub fn drain_pending_irp_records(&mut self) -> Vec<(u64, IOMessage)> {
        let records: Vec<(u32, IrpOperationRecord)> = {
            match self.pending_irp_records.lock() {
                Ok(mut q) => {
                    let v: Vec<(u32, IrpOperationRecord)> = q.drain(..).collect();
                    v
                }
                Err(_) => return Vec::new(),
            }
        };

        if records.is_empty() {
            return Vec::new();
        }

        let mut drained = Vec::with_capacity(records.len());
        for (pid, rec) in records {
            // Find the GID for this PID
            let gid_opt = self.find_gid_by_pid(pid);
            let gid = match gid_opt {
                Some(g) => g,
                None => {
                    // Process not yet tracked — do NOT drop the record. Use the
                    // same PID-scoped synthetic GID the worker uses
                    // (Worker::PID_FALLBACK_GID_MASK | pid) so process_event
                    // creates a placeholder state and the event still logs.
                    const PID_FALLBACK_GID_MASK: u64 = 0x8000_0000_0000_0000;
                    let synthetic_gid = PID_FALLBACK_GID_MASK | (pid as u64);
                    if rec.irp_type >= 0x6000 || rec.irp_type == 0x000E {
                        Logging::debug(&format!(
                            "[API HOOKING] DRAIN DROP AVOIDED pid={} irp_type=0x{:X} fn=\"{}\" -> synthetic GID {}",
                            pid, rec.irp_type, rec.function_name, synthetic_gid
                        ));
                    }
                    synthetic_gid
                }
            };

            use crate::shared_def::{FileId, IrpMajorOp, KernelEventInfo, RuntimeFeatures, SysmonEvent};
            let raw_irp_type = rec.irp_type;
            // Legacy Communication.cpp hypervisor/hook sub-types (12-29) are
            // carried on the DeviceIoControl (0x000E) LBVS carrier with the
            // specific opcode in kernel_event_info.event_type — mirror the
            // driver's encoding so effective_hypervisor_irp_byte resolves it.
            //
            // Dynamic user-mode API hooks (e.g. "ntdll!NtCreateFile") carry the
            // worker-allocated hook event-id (0x6000+, see
            // Worker::DYNAMIC_HOOK_EVENT_ID_START) as the sub-type. Those ids are
            // opaque to IrpMajorOp::from_sysmonevent, so encode them on the
            // usermode-hook wire opcode (0x0010 -> IrpUserModeHookEvent) with the
            // event-id preserved in kernel_event_info.event_type for raw-event
            // display and dynamic_hook_event_map name resolution. Without this the
            // events resolved to IrpNone and were dropped from detected_apis.
            let (irp_op, event_type): (u32, u32) =
                if raw_irp_type >= 0x6000 {
                    (
                        IrpMajorOp::IrpUserModeHookEvent.to_sysmonevent_u32(),
                        raw_irp_type,
                    )
                } else if rec.is_legacy_kernel_subtype {
                    (
                        SysmonEvent::DeviceIoControl as u32,
                        raw_irp_type,
                    )
                } else if raw_irp_type == 0x000E {
                    (
                        SysmonEvent::DeviceIoControl as u32,
                        0,
                    )
                } else {
                    (raw_irp_type, 0)
                };
            let iomsg = IOMessage {
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
                    kernel_event_info: KernelEventInfo {
                        object_name: rec.function_name.clone(),
                        event_type,
                        source_process_id: pid,
                        target_process_id: rec.target_pid,
                        raw_argument1: rec.raw_arguments[0],
                        raw_argument2: rec.raw_arguments[1],
                        raw_argument3: rec.raw_arguments[2],
                        raw_argument4: rec.raw_arguments[3],
                        ..Default::default()
                    },
                    runtime_features: RuntimeFeatures::default(),
                    file_size: rec.bytes_transferred as i64,
                    time: rec.timestamp,
                };
            drained.push((gid, iomsg));
        }
        drained
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

    /// Insert a match key into a bounded dedup window. New keys are appended to
    /// a FIFO; when the window exceeds `cap` the oldest keys age out one by one
    /// (instead of clearing the whole set), so a sudden burst of events cannot
    /// wipe the dedup state and re-count recently seen keys. Returns whether the
    /// key was new.
    fn insert_bounded_match_value(
        values: &mut HashSet<String>,
        order: &mut VecDeque<String>,
        match_key: String,
        cap: usize,
    ) -> bool {
        let is_new = values.insert(match_key.clone());
        if is_new {
            order.push_back(match_key);
            while order.len() > cap {
                if let Some(evicted) = order.pop_front() {
                    values.remove(&evicted);
                }
            }
        }
        is_new
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
        state.record_condition_match(&scoped_name, match_key, now, required, debug);
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

        // Record fast static ML detections (fast_detect_file) into the process
        // state so behavior rules can reference them via the `ml_detection` /
        // `ml_detected` conditions.
        if let Some(ml_name) = precord.triggered_rule_name.as_deref() {
            if crate::ml::fast_detect::is_ml_detection_name(ml_name)
                && !state.ml_detections.iter().any(|existing| existing == ml_name)
            {
                state.ml_detections.push(ml_name.to_string());
                Logging::info(&format!(
                    "[BehaviorEngine] Recorded ML detection '{}' for PID {} (GID {})",
                    ml_name, pid, gid
                ));
            }
        }

        // Record the actual ML feature values (is_obfuscated, entropy,
        // suspicious_score, ...) into the state so rules can reference them via
        // the `ml_features` condition. Feature values are merged per-name; the
        // latest recorded values win for each feature.
        if let Some(features) = &precord.fast_detection_features {
            for (name, value) in features {
                state.ml_features.insert(name.clone(), *value);
            }
            Logging::info(&format!(
                "[BehaviorEngine] Recorded {} ML feature(s) for PID {} (GID {})",
                features.len(),
                pid,
                gid
            ));
        }

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
                    state.is_executable = info.is_executable;
                    state.is_catalog_signed = info.is_catalog_signed;
                    state.is_attached_signed = info.is_attached_signed;
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
                    state.is_executable = false;
                    state.is_catalog_signed = false;
                    state.is_attached_signed = false;
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
                        attacker_state
                            .terminated_processes
                            .insert(victim_path.clone());
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

        // === STEP 6: EVALUATE RULES ===
        self.check_rules(precord, gid, msg, irp_op.clone(), config, &mut actions);

        // === STEP 8: HANDLE SPECIAL IRP OPERATIONS ===
        match irp_op {
            IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection => {
                // handle_kernel_event logic is natively merged into record_irp_operation and scan_all_processes.
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
                if let Ok(mut openedr_lock) = self.openedr_stats.write() {
                    if let Some(stats) = openedr_lock.remove(&pid) {
                        // OpenEDR event aliases (e.g. "OpenEDR::File::FileDataReadFull")
                        // are deliberately NOT merged into detected_apis/all_apis_called:
                        // those sets must only contain real user-mode hook / kernel-API
                        // observations (e.g. "ntdll!NtCreateFile"). Normal OpenEDR events
                        // stay visible below via recent_events instead.
                        // NOTE: telemetry is intentionally NOT appended to
                        // recent_kernel_api_events either — that deque feeds the
                        // "[API HOOKING SUMMARY]" and match_details() and must only
                        // carry genuine hook/kernel-API observations, otherwise a
                        // protected/non-hooked process (e.g. explorer.exe) would
                        // surface registry/file telemetry as if it were API hooks.
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
                if !state_ref.recent_kernel_api_events.is_empty() {
                    alert_sources.push("KernelApiAlert");
                }
                if !state_ref.satisfied_named_conditions.is_empty() {
                    alert_sources.push("BehavioralConditions");
                }
                if !state_ref.detected_apis.is_empty() {
                    alert_sources.push("SuspiciousApiCall");
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

            // RAW JSON ONLY: named conditions are satisfied exclusively by raw_json_patterns.
            let raw_json_triggered = !rule.named_conditions.is_empty()
                && rule.named_conditions.keys().all(|cond_name| {
                    Self::rule_condition_satisfied(&state_ref, rule, cond_name)
                });

            if raw_json_triggered {
                let trigger_type = "Raw-JSON";
                let indicator_ratio = 1.0;

                let mut prompted_deny = false;
                let mut prompted_block = false;
                let mut prompted_quarantine = false;
                
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
                                    // Operator-facing label comes from
                                    // display_threat_type_label(): this reports
                                    // as "Access Denied", because that is what
                                    // deny_while_ask actually enforced.
                                    threat_type_label: "Access Denied",
                                    virus_name: &rule.name,
                                    prediction: indicator_ratio,
                                    match_details: Some(if pending_match_details.is_empty() {
                                        format!(
                                            "Access denied while awaiting user decision for rule '{}'",
                                            rule.name
                                        )
                                    } else {
                                        format!(
                                            "Access denied while awaiting user decision for rule '{}' | {}",
                                            rule.name, pending_match_details
                                        )
                                    }),
                                    deny_access: true,
                                    terminate: false,
                                    quarantine: false,
                                    kill_and_remove: false,
                                    suspend: false,
                                    notify_user: rule.response.notify_user,
                                    revert: false,
                                    pending_user_decision: true,
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
                    revert: rule.response.auto_revert || config.always_auto_revert(),
                    pending_user_decision: false,
                };

                // FAIL-FAST SAFETY GUARD: Prevent rule-based termination or revert of critical system processes
                if let Some(reason) = crate::utils::protected_process_record_reason(precord) {
                    if threat_info.terminate || threat_info.quarantine || threat_info.kill_and_remove || threat_info.revert {
                        Logging::warning(&format!(
                            "[BehaviorEngine] Rule '{}' triggered remediation for protected process {} (GID: {}), but it was BLOCKED: {}",
                            rule.name, precord.appname, precord.gid, reason
                        ));
                        threat_info.terminate = false;
                        threat_info.quarantine = false;
                        threat_info.kill_and_remove = false;
                        threat_info.revert = false;
                    }
                }

                // CLOUD-TRUST GUARD: A file the Comodo cloud marked Safe must
                // never be quarantined (the artifact is trusted, moving or
                // removing it would destroy a clean file). If it still trips a
                // rule, only terminate/kill is allowed. Gated by the
                // TRUST_COMODO_CLOUD registry switch.
                if crate::config::is_trust_comodo_cloud_enabled()
                    && state_ref.is_comodo_cloud_trusted()
                    && (threat_info.quarantine || threat_info.kill_and_remove)
                {
                    Logging::warning(&format!(
                        "[BehaviorEngine] Rule '{}' triggered quarantine for cloud-trusted process {} (GID: {}); quarantine suppressed (kill-only policy)",
                        rule.name, precord.appname, precord.gid
                    ));
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

    /// Returns true if the given path is the executable this engine itself is
    /// running in (resolved once via `current_exe`). The engine must never
    /// flag its own host process.
    fn is_own_host_process(process_path: &Path) -> bool {
        static OWN_EXE: OnceLock<Option<String>> = OnceLock::new();
        let own = OWN_EXE.get_or_init(|| {
            std::env::current_exe()
                .ok()
                .map(|p| canonical_behavior_path(&p.to_string_lossy()))
                .filter(|s| !s.is_empty())
        });
        match own {
            Some(own_norm) => {
                canonical_behavior_path(&process_path.to_string_lossy()) == *own_norm
            }
            None => false,
        }
    }

    fn check_allowlist(
        &self,
        proc_name: &str,
        rule: &BehaviorRule,
        process_path: Option<&Path>,
        script_file: Option<&str>,
    ) -> bool {
        // Global exclusions from settings.yaml (`excluded_processes`):
        // a process whose canonical path matches any pattern is never
        // evaluated by any rule. Patterns are normalized the same way as the
        // process path (drive prefix stripped), so `C:\...` style entries work.
        if let Some(path) = process_path {
            let norm = canonical_behavior_path(&path.to_string_lossy());
            if !norm.is_empty()
                && crate::globals::EXCLUDED_PROCESSES.get().is_some_and(|list| {
                    list.iter().any(|pattern| {
                        let pat_norm =
                            strip_drive_prefix(&normalize_path_separators(
                                &pattern.trim().to_lowercase(),
                            ));
                        Self::matches_pattern_internal(&self.regex_cache, &pat_norm, &norm)
                    })
                })
            {
                return true;
            }

            // Self-exclusion: never evaluate the process this engine itself
            // runs in. The host exe is located dynamically at first use, so
            // no install path is hardcoded anywhere.
            if Self::is_own_host_process(path) {
                return true;
            }
        }

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
            let text_lc = text.to_lowercase();
            let pattern_lc = trimmed.to_lowercase();

            if text_lc.contains(&pattern_lc) {
                return true;
            }

            let text_norm = normalize_path_separators(&text_lc);
            let pattern_norm = normalize_path_separators(&pattern_lc);

            if text_norm == pattern_norm {
                return true;
            }

            let looks_like_path = pattern_norm.contains(":/")
                || pattern_norm.starts_with('/')
                || pattern_norm.starts_with('%')
                || pattern_norm.contains('/');

            if looks_like_path {
                if pattern_norm.ends_with('/') {
                    if text_norm.starts_with(&pattern_norm) || text_norm.contains(&pattern_norm) {
                        return true;
                    }
                }

                let mut dir_prefix = pattern_norm.clone();
                dir_prefix.push('/');
                if text_norm.starts_with(&dir_prefix) || text_norm.contains(&dir_prefix) {
                    return true;
                }

                // Check for exact path token match inside text_norm with boundary checks
                let p_len = pattern_norm.len();
                let mut start = 0;
                while let Some(pos) = text_norm[start..].find(&pattern_norm) {
                    let idx = start + pos;
                    let end_idx = idx + p_len;

                    let before_ok = idx == 0 || {
                        let prev = text_norm[..idx].chars().next_back().unwrap();
                        prev == '"' || prev == '\'' || prev == ' ' || prev == '/' || prev == ':' || prev == ',' || prev == '<' || prev == '>' || prev == '\\'
                    };

                    let after_ok = end_idx == text_norm.len() || {
                        let next = text_norm[end_idx..].chars().next().unwrap();
                        next == '"' || next == '\'' || next == ' ' || next == '/' || next == ',' || next == ';' || next == '}' || next == '\r' || next == '\n' || next == '\\'
                    };

                    if before_ok && after_ok {
                        return true;
                    }

                    start = idx + 1;
                    if start >= text_norm.len() {
                        break;
                    }
                }

                if pattern_norm.starts_with('/') && !pattern_norm.is_empty() {
                    let without_slash = pattern_norm.trim_start_matches('/');
                    if !without_slash.is_empty() && text_norm == without_slash {
                        return true;
                    }
                }

                return false;
            }

            return text_lc.contains(&pattern_lc) || text_norm.contains(&pattern_norm);
        }

        {
            if let Ok(cache_map) = cache.read() {
                if let Some(re) = cache_map.get(trimmed) {
                    let text_norm = normalize_path_separators(&text.to_lowercase());
                    return re.is_match(text) || re.is_match(&text_norm);
                }
            }
        }

        let mut cache_map = cache.write().unwrap();

        if let Some(re) = cache_map.get(trimmed) {
            let text_norm = normalize_path_separators(&text.to_lowercase());
            return re.is_match(text) || re.is_match(&text_norm);
        }

        let regex_str = if has_glob {
            let pattern_norm = normalize_path_separators(&trimmed.to_lowercase());
            let escaped = regex::escape(&pattern_norm)
                .replace("\\*", ".*")
                .replace("\\?", ".");
            format!("(?i){}", escaped)
        } else if trimmed.starts_with("(?") {
            trimmed.to_string()
        } else {
            format!("(?i){}", trimmed)
        };

        match Regex::new(&regex_str) {
            Ok(re) => {
                let text_norm = normalize_path_separators(&text.to_lowercase());
                let is_match = re.is_match(text) || re.is_match(&text_norm);
                cache_map.insert(trimmed.to_string(), re);
                is_match
            }
            Err(_) => {
                let text_lc = text.to_lowercase();
                let pattern_lc = trimmed.to_lowercase();
                text_lc.contains(&pattern_lc)
                    || normalize_path_separators(&text_lc)
                        .contains(&normalize_path_separators(&pattern_lc))
            }
        }
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
        config: &Config,
        _threat_handler: &dyn ThreatHandler,
    ) -> Vec<ProcessRecord> {
        self.drain_self_defense_telemetry_for_known_states();

        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();

        // Snapshot firewall-confirmed malicious exe paths once per scan cycle
        
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
            
            if !exe_path_str.is_empty()
                && exe_path_str.to_lowercase() != "unknown"
                && let Some(detection) = fw_blocked.get(&exe_path_str.to_lowercase())
            {
                if detection.is_pending_user_decision() {
                    continue;
                }

                // `traffic_attack` carries Suricata `alert` semantics and can be
                // driven by very broad rulesets, so never seal a validly signed
                // image on the strength of a single alert match.
                if detection.is_traffic_attack
                    && state.signature_checked
                    && state.has_valid_signature
                {
                    Logging::info(&format!(
                        "[FirewallPipe] Traffic-attack match on validly signed image {} (PID {}); reporting only — {}",
                        exe_path_str,
                        pid,
                        detection.match_details()
                    ));
                    continue;
                }

                let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path_buf.clone());
                p.is_malicious = true;
                p.pids.insert(pid);
                // `traffic_attack` keeps Suricata `alert` semantics: the packet
                // is still forwarded and the process is left running, but the
                // exe that produced the attack traffic is quarantined.
                p.termination_requested = !detection.is_traffic_attack;
                p.quarantine_requested = true;
                p.notify_user_requested = true;
                p.remediation_target_path = Some(exe_path_buf.clone());
                p.triggered_rule_name = Some(detection.threat_type_label().to_string());
                p.triggered_rule_details = Some(detection.match_details());
                Logging::warning(&format!(
                    "[FirewallPipe] Acting on firewall-confirmed malicious exe: {} (PID {}) — {} (response: {})",
                    exe_path_str,
                    pid,
                    detection.match_details(),
                    if detection.is_traffic_attack {
                        "quarantine"
                    } else {
                        "kill and quarantine"
                    }
                ));
                detected_processes.push(p);
                continue;
            }

            // Log Nt API activity summary if any events detected
            if !state.recent_kernel_api_events.is_empty() {
                let mut api_names: Vec<&str> = state.detected_apis.iter().map(|s| s.as_str()).collect();
                api_names.sort();
                let api_list = if api_names.is_empty() {
                    // Fall back to the raw event summaries so the log still shows
                    // which APIs were observed even when none qualified as an
                    // actionable (real_api + success) observation.
                    state
                        .recent_kernel_api_events
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                } else {
                    api_names
                };
                Logging::info(&format!(
                    "[API HOOKING SUMMARY] PID {} ({}) - Total kernel API events: {} - Detected APIs: {}",
                    pid,
                    app_name,
                    state.recent_kernel_api_events.len(),
                    api_list.join(", ")
                ));
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

                // RAW JSON ONLY: scan uses only named conditions satisfied by raw JSON patterns.
                let raw_json_triggered = !rule.named_conditions.is_empty()
                    && rule.named_conditions.keys().all(|cond_name| {
                        Self::rule_condition_satisfied(&state, rule, cond_name)
                    });

                if raw_json_triggered {
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
                    p.quarantine_requested = true;
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
                    // CLOUD-TRUST GUARD: never quarantine a Comodo-cloud Safe
                    // process — only kill is allowed.
                    if crate::config::is_trust_comodo_cloud_enabled()
                        && state.is_comodo_cloud_trusted()
                    {
                        p.quarantine_requested = false;
                        p.kill_and_remove_requested = false;
                        Logging::warning(&format!(
                            "[BehaviorEngine] Rule '{}' triggered quarantine for cloud-trusted process {} (GID: {}); quarantine suppressed (kill-only policy)",
                            rule.name, app_name, gid
                        ));
                    }
                    p.suspend_requested = if rule.response.ask_user {
                        false
                    } else {
                        rule.response.suspend_process
                    };
                    p.notify_user_requested = rule.response.notify_user;
                    p.revert_requested = rule.response.auto_revert || config.always_auto_revert();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern_cache() -> Arc<RwLock<HashMap<String, Regex>>> {
        Arc::new(RwLock::new(HashMap::new()))
    }

    #[test]
    fn drive_absolute_pattern_does_not_substring_match_long_hash_paths() {
        // Regression: rule pattern "C:\BCD" must stay anchored. Before the fix the
        // stripped pattern "bcd" was a bare substring and matched
        // "ec7fabcd7b908f90_1" inside an EBWebView cache path (false positive).
        let cache = pattern_cache();
        let pattern = "C:\\BCD";
        let evasive_path =
            "C:/Users/openedr/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/\
             LocalState/EBWebView/Default/Service Worker/CacheStorage/\
             3b278e44f1419f0b07a0417a936be8182ad635d4/\
             bc40b11f-8376-4527-bc53-bc6b1f7cf24d/ec7fabcd7b908f90_1";

        assert!(!BehaviorEngine::matches_pattern_internal(&cache, pattern, evasive_path));
    }

    #[test]
    fn drive_absolute_pattern_still_matches_its_own_path() {
        let cache = pattern_cache();
        assert!(BehaviorEngine::matches_pattern_internal(
            &cache,
            "C:\\BCD",
            "c:/bcd"
        ));
        assert!(BehaviorEngine::matches_pattern_internal(
            &cache,
            "C:\\boot.ini",
            "c:/boot.ini"
        ));
        // Path anchoring: a sibling file with a different name must not match.
        assert!(!BehaviorEngine::matches_pattern_internal(
            &cache,
            "C:\\boot.ini",
            "c:/boot.ini.bak"
        ));
        // A path nested under the pattern's directory still matches.
        assert!(BehaviorEngine::matches_pattern_internal(
            &cache,
            "C:\\boot",
            "c:/boot/efi/BCD"
        ));
    }


    #[test]
    fn process_create_event_type_alias_and_process_id_are_accepted() {
        let mut engine = BehaviorEngine::new();

        let event = serde_json::json!({
            "eventType": "lle_process_create",
            "process": { "processId": 4242 }
        });

        engine.ingest_openedr_event(&event);

        let drained = engine.drain_pending_hook_pids();
        assert_eq!(drained, vec![4242]);
    }

    #[test]
    fn process_create_event_queues_hook_pid() {
        let mut engine = BehaviorEngine::new();
        let event = serde_json::json!({
            "type": "LLE_PROCESS_CREATE",
            "pid": 4242,
        });
        engine.ingest_openedr_event(&event);

        let drained = engine.drain_pending_hook_pids();
        assert_eq!(drained, vec![4242]);
    }

    #[test]
    fn process_create_event_queues_hook_pid_first() {
        let mut engine = BehaviorEngine::new();

        // Pre-fill the hook queue with a backlogged PID so ordering is observable.
        {
            let mut q = engine.pending_hook_pids.lock().unwrap();
            q.push_back(1000);
        }
        let event = serde_json::json!({
            "type": "LLE_PROCESS_CREATE",
            "pid": 4242,
        });
        engine.ingest_openedr_event(&event);

        let drained = engine.drain_pending_hook_pids();
        assert_eq!(
            drained,
            vec![4242, 1000],
            "newly created processes must be hooked before backlogged PIDs"
        );
    }

    #[test]
    fn ingest_openedr_event_queues_raw_json() {
        let engine = BehaviorEngine::new();
        let file_event = serde_json::json!({
            "type": "LLE_FILE_CREATE",
            "pid": 4242,
            "file": { "path": r"C:\Temp\test.txt" }
        });
        engine.ingest_openedr_event(&file_event);

        let mut drained = engine.pending_raw_events.lock().unwrap();
        assert_eq!(drained.len(), 1);
        let (pid, raw) = drained.pop_front().unwrap();
        assert_eq!(pid, 4242);
        assert!(raw.contains("LLE_FILE_CREATE"));
        assert!(raw.contains("test.txt"));
    }

    #[test]
    fn raw_json_patterns_match_with_env_vars_and_min_matches() {
        use crate::behavioral::rule_types::{BehaviorRule, NamedConditionGroup};

        let mut engine = BehaviorEngine::new();
        engine.register_process(
            1,
            5000,
            PathBuf::from(r"C:\Windows\System32\cmd.exe"),
            "cmd.exe".into(),
        );

        let mut cond = NamedConditionGroup::default();
        cond.raw_json_patterns = vec!["%APPDATA%/*".to_string(), "*ransom_target*".to_string()];
        cond.min_matches = 2;

        let mut rule = BehaviorRule::default();
        rule.name = "RawJsonPatternTest".to_string();
        rule.named_conditions.insert("raw_cond".to_string(), cond);
        rule.finalize_rich_fields();
        engine.rules.push(rule);

        let appdata_val = std::env::var("APPDATA").unwrap_or_else(|_| r"C:\Users\Default\AppData\Roaming".to_string());
        let event1 = format!(
            "{{\"type\":\"LLE_FILE_CREATE\",\"pid\":5000,\"file\":{{\"path\":\"{}\\\\payload.exe\"}}}}",
            appdata_val.replace('\\', "\\\\")
        );
        let event2 = "{\"type\":\"LLE_FILE_WRITE\",\"pid\":5000,\"file\":{\"path\":\"C:\\\\data\\\\ransom_target.docx\"}}".to_string();

        engine.apply_raw_openedr_events(vec![(5000, event1)]);
        let state = engine.process_states.get(&1).unwrap();
        assert!(
            !state.satisfied_named_conditions.iter().any(|c| c.ends_with("raw_cond")),
            "min_matches: 2 must NOT be satisfied after 1 event"
        );

        engine.apply_raw_openedr_events(vec![(5000, event2)]);
        let state = engine.process_states.get(&1).unwrap();
        assert!(
            state.satisfied_named_conditions.iter().any(|c| c.ends_with("raw_cond")),
            "min_matches: 2 MUST be satisfied after 2 matching events (got {:?})",
            state.satisfied_named_conditions
        );
    }

    #[test]
    fn drain_pending_irp_records_encodes_usermode_hook_events() {
        use crate::shared_def::effective_hypervisor_irp_byte;
        use crate::shared_def::IrpMajorOp;

        let mut engine = BehaviorEngine::new();
        engine.register_process(
            7,
            4242,
            PathBuf::from(r"C:\Windows\System32\cmd.exe"),
            "cmd.exe".into(),
        );

        {
            let mut q = engine.pending_irp_records.lock().unwrap();
            q.push_back((
                4242,
                IrpOperationRecord {
                    timestamp: std::time::SystemTime::now(),
                    irp_type: 0x6000,
                    is_legacy_kernel_subtype: false,
                    file_path: String::new(),
                    file_change: 0,
                    extension: String::new(),
                    entropy: 0.0,
                    bytes_transferred: 0,
                    target_pid: 4242,
                    function_name: "ntdll!NtCreateFile".to_string(),
                    pipe_name: String::new(),
                    pipe_payload: Vec::new(),
                    raw_arguments: [0; 4],
                },
            ));
        }

        let drained = engine.drain_pending_irp_records();
        assert_eq!(drained.len(), 1, "hook record must drain to one IOMessage");
        let (gid, msg) = &drained[0];
        assert_eq!(*gid, 7);

        assert_eq!(
            msg.irp_op,
            IrpMajorOp::IrpUserModeHookEvent.to_sysmonevent_u32(),
            "usermode hook events must map to IrpUserModeHookEvent (0x0010)"
        );
        assert_eq!(msg.kernel_event_info.event_type, 0x6000);
        assert_eq!(msg.kernel_event_info.object_name, "ntdll!NtCreateFile");
        assert_eq!(
            effective_hypervisor_irp_byte(msg),
            IrpMajorOp::IrpUserModeHookEvent.to_sysmonevent_u32()
        );

        let state = engine.process_states.get_mut(&7).unwrap();
        state.record_irp_operation(msg, effective_hypervisor_irp_byte(msg));
        assert!(
            state.detected_apis.contains("ntdll!NtCreateFile"),
            "detected_apis must contain the real hook API name, got {:?}",
            state.detected_apis
        );
    }

    #[test]
    fn api_pattern_index_fast_paths_literal_apis_only() {
        use crate::behavioral::rule_types::{BehaviorRule, NamedConditionGroup};

        let mut engine = BehaviorEngine::new();

        let mut group = NamedConditionGroup::default();
        group.hook_error_api_patterns = vec![
            "ntdll!NtWriteVirtualMemory".to_string(),
            "(?i)(^|!)(Nt|Zw)(Close)$".to_string(),
            "kernel32!WriteFile".to_string(),
        ];

        let mut rule = BehaviorRule::default();
        rule.named_conditions.insert("api_cond".to_string(), group);
        engine.rules.push(rule);
        engine.rebuild_api_pattern_index();

        let guard = engine.api_pattern_index.read().unwrap();
        let index = guard.as_ref().expect("index must be built");

        assert!(
            index
                .find_overlapping_iter(b"ntdll!ntwritevirtualmemory")
                .next()
                .is_some(),
            "literal api must be indexed"
        );
        assert!(
            index
                .find_overlapping_iter(b"kernel32!writefile")
                .next()
                .is_some(),
            "literal hook-error api must be indexed"
        );
        assert!(
            index
                .find_overlapping_iter(b"(?i)(^|!)(nt|zw)(close)$")
                .next()
                .is_none(),
            "regex patterns must not be indexed"
        );

        drop(guard);
        assert!(engine.api_index_contains("ntdll!NtWriteVirtualMemory"));
        assert!(engine.api_index_contains("KERNEL32!WRITEFILE"));
        assert!(!engine.api_index_contains("ntdll!NtCreateFile"));

        let empty = BehaviorEngine::new();
        empty.rebuild_api_pattern_index();
        assert!(empty.api_index_contains("anything").eq(&false));
    }

    #[test]
    fn shipped_process_hollowing_rule_uses_supported_cross_process_logic() {
        let rules_path = Path::new("../edrav2/rules/behavior_rules.yaml");
        if !rules_path.exists() {
            return;
        }
        let mut engine = BehaviorEngine::new();
        engine
            .load_rules(rules_path)
            .expect("shipped rules must deserialize without errors");

        let hollow = engine
            .rules
            .iter()
            .find(|r| r.name == "Process Hollowing")
            .expect("Process Hollowing rule must be present in shipped rules");

        assert!(
            hollow.detection_logic.is_some(),
            "Process Hollowing must define detection_logic"
        );

        let _telemetry = hollow
            .named_conditions
            .get("kernel_hollowing_telemetry")
            .expect("kernel_hollowing_telemetry must be defined");


        for leg in ["image_unmap", "context_takeover"] {
            assert!(
                hollow.named_conditions.contains_key(leg),
                "{leg} leg must be defined"
            );
        }
        assert!(
            !hollow
                .named_conditions
                .contains_key("remote_process_access"),
            "weak remote_process_access leg must be removed"
        );
        for leg in [
            "hollowing_bootstrap",
            "remote_memory_replacement",
            "thread_takeover_and_resume",
        ] {
            assert!(
                hollow.named_conditions.contains_key(leg),
                "{leg} leg must be preserved"
            );
        }
    }


    #[test]
    fn all_shipped_yaml_rules_load_and_deserialize_successfully() {
        let rules_dir = Path::new("../edrav2/rules");
        if !rules_dir.exists() {
            return;
        }

        let mut engine = BehaviorEngine::new();
        let mut loaded_count = 0;

        for entry in std::fs::read_dir(rules_dir).expect("rules directory must be readable") {
            let entry = entry.expect("valid dir entry");
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
                let filename = path.file_name().unwrap().to_string_lossy();
                if filename == "settings.yaml" {
                    continue;
                }
                match engine.load_rules(&path) {
                    Ok(_) => {
                        loaded_count += 1;
                    }
                    Err(e) => {
                        panic!("Failed to load rule file {}: {}", path.display(), e);
                    }
                }
            }
        }

        let rule_count = engine.rules.len();
        assert!(loaded_count > 0, "must load at least one rule file");
        assert!(rule_count > 0, "must have parsed rules across yaml files");
    }
}
