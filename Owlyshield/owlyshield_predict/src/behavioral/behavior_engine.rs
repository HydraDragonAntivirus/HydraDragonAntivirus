use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_yaml;
use regex::Regex;
use std::sync::{Arc, OnceLock, RwLock};
use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp, known_raw_event_name};
#[cfg(feature = "firewall")]
use crate::driver_com::with_shared_driver;
use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::config::Config;
pub use super::rule_types::*;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::extensions::ExtensionList;
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::threat_handler::ThreatHandler;
use crate::signature_verification::verify_signature;
use crate::utils::{format_process_descriptor_with_fallback, resolve_process_path, validate_pipe_client};
use std::sync::atomic::{AtomicBool, Ordering};

use num::FromPrimitive;

#[cfg(feature = "firewall")]
type FirewallNetPids = Arc<std::sync::RwLock<HashSet<u32>>>;
#[cfg(feature = "firewall")]
type FirewallBlockedExes = Arc<std::sync::RwLock<HashMap<String, FirewallDetection>>>;
/// Per-PID list of (dst_ip, dst_port) pairs observed by the firewall (NET_EVENT).
#[cfg(feature = "firewall")]
type FirewallNetDetails = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, u16)>>>>;
#[cfg(feature = "firewall")]
type FirewallPipeStarted = Arc<AtomicBool>;
#[cfg(feature = "firewall")]
type FirewallHipsPendingPrompts = Arc<std::sync::RwLock<HashMap<String, FirewallHipsPromptState>>>;
#[cfg(feature = "firewall")]
type FirewallHipsDecisions = Arc<std::sync::RwLock<HashMap<String, FirewallHipsDecision>>>;
#[cfg(feature = "firewall")]
type FirewallHipsAllowOnce = Arc<std::sync::RwLock<HashSet<String>>>;
#[cfg(feature = "firewall")]
type FirewallHipsAllowAlways = Arc<std::sync::RwLock<HashSet<String>>>;
/// Per-PID list of (request_body, response_body) pairs received via HTTP_BODY pipe messages.
#[cfg(feature = "firewall")]
type FirewallHttpBodyMap = Arc<std::sync::RwLock<HashMap<u32, Vec<(String, String)>>>>;
/// Per-PID rolling history of full PacketInfo structures from the firewall.
#[cfg(feature = "firewall")]
type FirewallFullPackets = Arc<std::sync::RwLock<HashMap<u32, VecDeque<PacketInfo>>>>;
#[cfg(feature = "firewall")]
type FirewallGenerateReport = Arc<AtomicBool>;

#[cfg(feature = "firewall")]
fn shared_firewall_net_pids() -> FirewallNetPids {
    static FIREWALL_NET_PIDS: OnceLock<FirewallNetPids> = OnceLock::new();
    FIREWALL_NET_PIDS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_blocked_exes() -> FirewallBlockedExes {
    static FIREWALL_BLOCKED_EXES: OnceLock<FirewallBlockedExes> = OnceLock::new();
    FIREWALL_BLOCKED_EXES
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_net_details() -> FirewallNetDetails {
    static FIREWALL_NET_DETAILS: OnceLock<FirewallNetDetails> = OnceLock::new();
    FIREWALL_NET_DETAILS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_http_body_map() -> FirewallHttpBodyMap {
    static FIREWALL_HTTP_BODY_MAP: OnceLock<FirewallHttpBodyMap> = OnceLock::new();
    FIREWALL_HTTP_BODY_MAP
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_full_packets() -> FirewallFullPackets {
    static FIREWALL_FULL_PACKETS: OnceLock<FirewallFullPackets> = OnceLock::new();
    FIREWALL_FULL_PACKETS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_pipe_started() -> FirewallPipeStarted {
    static FIREWALL_PIPE_STARTED: OnceLock<FirewallPipeStarted> = OnceLock::new();
    FIREWALL_PIPE_STARTED
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_hips_pending_prompts() -> FirewallHipsPendingPrompts {
    static FIREWALL_HIPS_PENDING_PROMPTS: OnceLock<FirewallHipsPendingPrompts> = OnceLock::new();
    FIREWALL_HIPS_PENDING_PROMPTS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_hips_decisions() -> FirewallHipsDecisions {
    static FIREWALL_HIPS_DECISIONS: OnceLock<FirewallHipsDecisions> = OnceLock::new();
    FIREWALL_HIPS_DECISIONS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_hips_allow_once() -> FirewallHipsAllowOnce {
    static FIREWALL_HIPS_ALLOW_ONCE: OnceLock<FirewallHipsAllowOnce> = OnceLock::new();
    FIREWALL_HIPS_ALLOW_ONCE
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_hips_allow_always() -> FirewallHipsAllowAlways {
    static FIREWALL_HIPS_ALLOW_ALWAYS: OnceLock<FirewallHipsAllowAlways> = OnceLock::new();
    FIREWALL_HIPS_ALLOW_ALWAYS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashSet::new())))
        .clone()
}

#[cfg(feature = "firewall")]
fn shared_firewall_generate_report() -> FirewallGenerateReport {
    static FIREWALL_GENERATE_REPORT: OnceLock<FirewallGenerateReport> = OnceLock::new();
    FIREWALL_GENERATE_REPORT
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// Per-PID stats from Sanctum EDR telemetry (received via HydraSanctumTelemetry pipe).
#[cfg(feature = "sanctum")]
type FirewallSanctumStats = Arc<std::sync::RwLock<HashMap<u32, crate::realtime_learning::api_tracker::SanctumOperationStats>>>;

#[cfg(feature = "sanctum")]
fn shared_firewall_sanctum_stats() -> FirewallSanctumStats {
    static FIREWALL_SANCTUM_STATS: OnceLock<FirewallSanctumStats> = OnceLock::new();
    FIREWALL_SANCTUM_STATS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(HashMap::new())))
        .clone()
}

// =============================================================================
// FIREWALL DETECTION — details received from the firewall via HydraNetEvent pipe
// =============================================================================

/// All detection context sent by the firewall when it confirms malicious traffic.
/// Populated from BLOCK_EXE messages and used to build rich ThreatInfo for reports.
#[derive(Debug, Clone)]
#[cfg(feature = "firewall")]
pub struct FirewallDetection {
    pub dst_ip: String,
    pub dst_port: u16,
    pub hostname: String,
    /// Full reason string from the firewall (e.g. "SDK Rule [MalwareDomain]: ...")
    pub reason: String,
}

#[cfg(feature = "firewall")]
#[allow(dead_code)]
impl FirewallDetection {
    /// Derive a threat type label from the reason string.
    pub fn threat_type_label(&self) -> &'static str {
        let r = self.reason.to_lowercase();
        if r.contains("ransomware") { "Ransomware" }
        else if r.contains("c2") || r.contains("command") || r.contains("botnet") { "C2 Communication" }
        else if r.contains("exploit") { "Exploit" }
        else if r.contains("intelligence") || r.contains("malware") { "Malware" }
        else if r.contains("sdk rule") { "Policy Violation" }
        else { "Malicious Network Activity" }
    }

    /// Build a human-readable match_details string for reports.
    pub fn match_details(&self) -> String {
        if self.hostname.is_empty() {
            format!("{}:{} — {}", self.dst_ip, self.dst_port, self.reason)
        } else {
            format!("{}:{} ({}) — {}", self.dst_ip, self.dst_port, self.hostname, self.reason)
        }
    }
}

#[cfg(feature = "firewall")]
#[derive(Debug, Clone)]
struct FirewallHipsPromptState {
    request_id: String,
    request_signature: String,
    allow_signature: String,
}

#[cfg(feature = "firewall")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallHipsDecision {
    Deny,
    Block,
    Quarantine,
    AllowOnce,
    AllowAlways,
}

#[cfg(feature = "firewall")]
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

#[cfg(feature = "firewall")]
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
    pub irp_type: u8,
    pub file_path: String,
    pub file_change: u8,
    pub extension: String,
    pub entropy: f64,
    pub bytes_transferred: u64,
    pub target_pid: u32,  // NEW: For operations targeting another process
    pub function_name: String,  // NEW: For generic API hooks - which function was called
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
    
    pub hypervisor_event_count: u64,  // Normalized hypervisor event count
    
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
    
    // All APIs called (for comprehensive tracking)
    pub all_apis_called: HashSet<String>,
}

impl IrpStatistics {
    pub fn get_total_operations(&self) -> u64 {
        self.read_count + self.write_count + self.create_count + self.delete_count + self.rename_count + self.setinfo_count + self.registry_read_count + self.registry_write_count + self.registry_delete_count + self.registry_create_count + self.process_create_count + self.process_terminate_count + self.process_exit_count + self.process_handle_open_count + self.process_terminate_attempt_count + self.hypervisor_event_count
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
        let irp_op = IrpMajorOp::from_byte(rec.irp_type);
        
        match irp_op {
            // File operations
            IrpMajorOp::IrpRead => {
                self.read_count += 1;
                self.total_bytes_read += rec.bytes_transferred;
            },
            IrpMajorOp::IrpWrite => {
                self.write_count += 1;
                self.total_bytes_written += rec.bytes_transferred;
            },
            IrpMajorOp::IrpCreate => self.create_count += 1,
            IrpMajorOp::IrpSetInfo => {
                self.setinfo_count += 1;
                // Track specific file changes
                match rec.file_change {
                    _ if rec.file_change == FileChangeInfo::ChangeDeleteFile as u8 => self.delete_count += 1,
                    _ if rec.file_change == FileChangeInfo::ChangeRenameFile as u8 => self.rename_count += 1,
                    _ if rec.file_change == FileChangeInfo::ChangeExtensionChanged as u8 => self.rename_count += 1,
                    _ => {},
                }
            },
            
            // Registry operations
            IrpMajorOp::IrpRegistry => {
                match rec.file_change {
                    _ if rec.file_change == FileChangeInfo::RegCreateKey as u8 => self.registry_create_count += 1,
                    _ if rec.file_change == FileChangeInfo::RegSetValue as u8 => self.registry_write_count += 1,
                    _ if rec.file_change == FileChangeInfo::RegDeleteValue as u8 => self.registry_delete_count += 1,
                    _ => self.registry_read_count += 1,
                }
            },
            
            // Process operations
            IrpMajorOp::IrpProcessCreate => self.process_create_count += 1,
            IrpMajorOp::IrpProcessTerminate => self.process_terminate_count += 1,
            IrpMajorOp::IrpProcessTerminateAttempt => self.process_terminate_attempt_count += 1,
            IrpMajorOp::IrpProcessExit => self.process_exit_count += 1,
            IrpMajorOp::IrpProcessHandleOpen => self.process_handle_open_count += 1,
            
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
                    IrpMajorOp::from_byte(rec.irp_type),
                    &details,
                );
                if is_real_api_observation(&rec.function_name) {
                    self.all_apis_called.insert(rec.function_name.clone());
                }
            },
            
            _ => {},
        }
        
        // Track file statistics
        if !rec.extension.is_empty() {
            *self.files_by_extension.entry(rec.extension.clone()).or_insert(0) += 1;
        }
        
        self.unique_paths_accessed.insert(rec.file_path.clone());
        
        if rec.entropy > 0.7 {
            self.high_entropy_files.insert(rec.file_path.clone());
        }
        
        if self.entropy_samples.len() < 1000 {
            self.entropy_samples.push(rec.entropy);
            self.average_entropy = self.entropy_samples.iter().sum::<f64>() / self.entropy_samples.len() as f64;
        }
    }
    
    /// Record detailed hypervisor event operation for forensics and analysis
    fn record_hypervisor_event_operation(&mut self, rec: &IrpOperationRecord, api_type: IrpMajorOp, details: &str) {
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
    
    pub fn get_operation_count(&self, op_type: &str) -> u64 {
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
            RootkitFindingKind::SsdtHook        => "SSDT Hook",
            RootkitFindingKind::HiddenProcess   => "Hidden Process (DKOM)",
            RootkitFindingKind::HiddenDriver    => "Hidden Driver",
            RootkitFindingKind::KernelInlineHook => "Kernel Inline Hook",
            RootkitFindingKind::TerminateProcess => "Rootkit Terminate Process",
            RootkitFindingKind::FileMove         => "Rootkit File Move",
            RootkitFindingKind::Generic          => "Generic Rootkit Event",
            RootkitFindingKind::Unknown(_)      => "Unknown Rootkit Event",
        }
    }

    pub fn severity(&self) -> u8 {
        // 0 = low, 1 = medium, 2 = high, 3 = critical
        match self {
            RootkitFindingKind::SsdtHook        => 3,
            RootkitFindingKind::HiddenProcess   => 3,
            RootkitFindingKind::HiddenDriver    => 3,
            RootkitFindingKind::KernelInlineHook => 2,
            RootkitFindingKind::TerminateProcess => 3,
            RootkitFindingKind::FileMove         => 2,
            RootkitFindingKind::Generic          => 2,
            RootkitFindingKind::Unknown(_)      => 1,
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
        && let Some(idx) = p_trim.find('/') {
            let remainder = &p_trim[idx + 1..];
            if !remainder.is_empty() {
                return remainder.to_string();
            }
        }

    p
}

fn strip_drive_prefix(path: &str) -> String {
    if path.len() >= 3 && path.as_bytes()[1] == b':' && (path.as_bytes()[2] == b'\\' || path.as_bytes()[2] == b'/') {
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

fn target_matches_process_image(process_path: &Path, observed_norm: &str, observed_raw: &str) -> bool {
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
        (IrpMajorOp::IrpSetInfo, Some(FileChangeInfo::ChangeDeleteFile))
            | (IrpMajorOp::IrpSetInfo, Some(FileChangeInfo::ChangeDeleteNewFile))
    )
}

fn is_rename_like_file_operation(irp_op: &IrpMajorOp, file_change: Option<FileChangeInfo>) -> bool {
    matches!(
        (irp_op, file_change),
        (IrpMajorOp::IrpSetInfo, Some(FileChangeInfo::ChangeRenameFile))
            | (IrpMajorOp::IrpSetInfo, Some(FileChangeInfo::ChangeExtensionChanged))
    )
}

fn normalize_hypervisor_api_label(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    if let Some(idx) = value.find(" (syscall=0x") {
        value.truncate(idx);
    }
    value.trim().to_string()
}

fn canonical_hypervisor_event_label(irp_op: &IrpMajorOp, raw_event_type: u32) -> Option<String> {
    let resolved = match raw_event_type {
        12..=20 => IrpMajorOp::from_byte(raw_event_type as u8),
        _ => irp_op.clone(),
    };
    match resolved {
        IrpMajorOp::IrpHypervisorEvent
        | IrpMajorOp::IrpUserModeHookEvent
        | IrpMajorOp::IrpKernelRemoteThread
        | IrpMajorOp::IrpKernelWriteMemory
        | IrpMajorOp::IrpKernelProtectMemory
        | IrpMajorOp::IrpKernelCreateThread
        | IrpMajorOp::IrpKernelQueueApc
        | IrpMajorOp::IrpKernelCreateSection
        | IrpMajorOp::IrpKernelMapSection => Some(format!("{:?}", resolved)),
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
    let trimmed = raw.trim();
    !trimmed.is_empty() && !is_generic_hypervisor_label(trimmed)
}

fn effective_hypervisor_irp_byte(msg: &IOMessage) -> u8 {
    if msg.irp_op == 12
        && (12..=20).contains(&msg.kernel_event_info.event_type)
    {
        msg.kernel_event_info.event_type as u8
    } else {
        msg.irp_op
    }
}

fn is_kernel_api_event(irp_op: &IrpMajorOp) -> bool {
    matches!(
        irp_op,
        IrpMajorOp::IrpHypervisorEvent
            | IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection
    )
}

fn api_function_alias(raw: &str) -> Option<String> {
    let normalized = normalize_hypervisor_api_label(raw);
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

fn build_default_extension_whitelist() -> HashSet<String> {
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





// =============================================================================
// PART 2: ENHANCED PROCESS STATE WITH IRP TRACKING
// =============================================================================

#[derive(Default, Clone)]
pub struct ProcessBehaviorState {
    pub browsed_paths_tracker: HashMap<String, SystemTime>,
    pub accessed_paths_tracker: HashSet<String>,
    pub staged_files_written: HashMap<PathBuf, SystemTime>,
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
    pub has_valid_signature: bool,
    pub is_signed: bool, 
    
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

    /// HTTP body pairs (request_body, response_body) received via the HTTP_BODY pipe message.
    #[cfg(feature = "firewall")]
    pub http_body_entries: Vec<(String, String)>,
    
    /// Rolling history of network packets captured for this process (FULL_PACKET).
    #[cfg(feature = "firewall")]
    pub net_packets: VecDeque<PacketInfo>,

    /// Sanctum EDR telemetry stats for real-time learning.
    #[cfg(feature = "sanctum")]
    pub sanctum_stats: crate::realtime_learning::api_tracker::SanctumOperationStats,
    /// Historical hits for Sanctum suspicious syscalls throughout the process lifetime.
    #[cfg(feature = "sanctum")]
    pub sanctum_suspicious_hits: HashSet<String>,

    /// True if this process has been implicated in a rootkit finding.
    pub rootkit_implicated: bool,
    /// All rootkit events detected for this process.
    pub rootkit_findings: Vec<RootkitFinding>,
}

impl ProcessBehaviorState {
    pub fn new(pid: u32, exe_path: PathBuf, app_name: String) -> Self {
        let mut state = ProcessBehaviorState::default();
        state.pid = pid;
        state.exe_path = exe_path;
        state.app_name = app_name;
        state.parent_name = "unknown".to_string();
        state.parent_path = PathBuf::new();
        state.command_line = String::new();
        state.self_terminated_processes = HashSet::new();
        state.terminated_processes = HashSet::new();
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
        
        // Initialize normalized hypervisor event counters
        state.hypervisor_event_count = 0;
        state.hypervisor_events_total = 0;
        state.created_unknown_ext_stems = HashSet::new();
        state.written_unknown_ext_stems = HashSet::new();
        state.script_file = String::new();
        state.script_file_path = String::new();
        #[cfg(feature = "firewall")]
        {
            state.net_packets = VecDeque::with_capacity(500);
            state.http_body_entries = Vec::new();
        }
        #[cfg(feature = "sanctum")]
        {
            state.sanctum_stats = crate::realtime_learning::api_tracker::SanctumOperationStats::default();
        }
        state.rootkit_implicated = false;
        state.rootkit_findings = Vec::new();

        state
    }
    
    /// Record IRP operation with full context and track normalized hypervisor events
    pub fn record_irp_operation(&mut self, msg: &IOMessage, irp_op: u8) {
        let normalized_kernel_api = normalize_hypervisor_api_label(&msg.kernel_event_info.object_name);
        let rec = IrpOperationRecord {
            timestamp: SystemTime::now(),
            irp_type: irp_op,
            file_path: msg.filepathstr.to_lowercase(),
            file_change: msg.file_change,
            extension: msg.extension.to_lowercase(),
            entropy: msg.entropy,
            bytes_transferred: msg.mem_sized_used,
            target_pid: msg.pid,
            function_name: normalized_kernel_api.clone(),
        };
        
        self.irp_stats.record_operation(&rec);
        let irp_kind = IrpMajorOp::from_byte(irp_op);
        let is_api_event = is_kernel_api_event(&irp_kind);
        
        if is_api_event {
            self.hypervisor_event_count += 1;
            let raw_event_type = if msg.kernel_event_info.event_type != 0 {
                msg.kernel_event_info.event_type
            } else {
                irp_op as u32
            };
            if let Some(event_label) = canonical_hypervisor_event_label(&irp_kind, raw_event_type) {
                self.observed_hypervisor_event_labels.insert(event_label);
            }
            let source_process = format_process_descriptor_with_fallback(
                msg.kernel_event_info.source_process_id,
                None,
            );
            let target_process = format_process_descriptor_with_fallback(
                msg.kernel_event_info.target_process_id,
                Some(self.exe_path.as_path()),
            );
            let event_name = if normalized_kernel_api.is_empty() {
                known_raw_event_name(raw_event_type)
                    .map(|name| name.to_string())
                    .unwrap_or_else(|| format!("RawEventType({raw_event_type})"))
            } else {
                normalized_kernel_api.clone()
            };
            let real_api = is_real_api_observation(&event_name);
            if real_api {
                self.detected_apis.insert(event_name.clone());
                self.all_apis_called.insert(event_name.clone());
                if let Some(alias) = api_function_alias(&event_name) {
                    self.detected_apis.insert(alias.clone());
                    self.all_apis_called.insert(alias.clone());
                }
            }

            if real_api {
                Logging::info(&format!(
                    "[API HOOKING EVENT] opcode={} raw_event_type={} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} api=\"{}\" count={}",
                    irp_op,
                    raw_event_type,
                    source_process,
                    target_process,
                    msg.kernel_event_info.raw_argument1,
                    msg.kernel_event_info.raw_argument2,
                    msg.kernel_event_info.raw_argument3,
                    msg.kernel_event_info.raw_argument4,
                    event_name,
                    self.hypervisor_event_count
                ));
            } else {
                let event_label = canonical_hypervisor_event_label(&irp_kind, raw_event_type)
                    .unwrap_or_else(|| event_name.clone());
                Logging::info(&format!(
                    "[HYPERVISOR EVENT] opcode={} raw_event_type={} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} event=\"{}\" count={}",
                    irp_op,
                    raw_event_type,
                    source_process,
                    target_process,
                    msg.kernel_event_info.raw_argument1,
                    msg.kernel_event_info.raw_argument2,
                    msg.kernel_event_info.raw_argument3,
                    msg.kernel_event_info.raw_argument4,
                    event_label,
                    self.hypervisor_event_count
                ));
            }
        }

        // Increment total hypervisor events counter and emit activity signal
        if is_api_event {
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
                let attaches_to_state = owner_pid != 0
                    && self.pid != 0
                    && (self.pid == owner_pid || self.pid == msg.pid);

                if attaches_to_state {
                    let finding = RootkitFinding {
                        kind: kind.clone(),
                        description: msg.kernel_event_info.object_name.trim_matches('\0').to_string(),
                        address: msg.kernel_event_info.memory_address,
                        pid: owner_pid,
                        extra: msg.kernel_event_info.raw_argument1,
                        timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                    };
                    self.rootkit_findings.push(finding);
                    if matches!(kind, RootkitFindingKind::HiddenProcess) {
                        self.rootkit_implicated = true;
                    }
                } else {
                    Logging::warning(&format!(
                        "[ROOTKIT DETECTED] Unattributed {:?} finding not attached to process state pid={} src_pid={} msg_pid={}",
                        kind,
                        self.pid,
                        owner_pid,
                        msg.pid
                    ));
                }
                
                Logging::warning(&format!(
                    "[ROOTKIT DETECTED] PID {} - Type: {:?} - {}",
                    msg.pid, kind, msg.kernel_event_info.object_name.trim_matches('\0')
                ));
            },
            _ => {},
        }
        
        // Use incremental drain to prevent blocking: remove 10% when hitting 10k
        if self.irp_operations.len() >= 10000 {
            let remove_count = (self.irp_operations.len() / 10).max(500);
            let _ = self.irp_operations.drain(0..remove_count);
        }
        
        self.irp_operations.push(rec);
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
    /// PIDs for which the firewall observed real outbound network I/O (NET_EVENT).
    #[cfg(feature = "firewall")]
    pub firewall_net_pids: FirewallNetPids,
    /// Per-PID list of (dst_ip, dst_port) connection records from NET_EVENT messages.
    /// Used by named-condition rules to match specific IPs or ports.
    #[cfg(feature = "firewall")]
    pub firewall_net_details: FirewallNetDetails,
    /// Exe paths for which the firewall confirmed malicious traffic (BLOCK_EXE).
    /// Value holds full detection details for report generation.
    /// scan_all_processes marks matching processes as malicious and acts on them.
    #[cfg(feature = "firewall")]
    pub firewall_blocked_exes: FirewallBlockedExes,
    #[cfg(feature = "firewall")]
    firewall_pipe_started: FirewallPipeStarted,
    #[cfg(feature = "firewall")]
    firewall_hips_pending_prompts: FirewallHipsPendingPrompts,
    #[cfg(feature = "firewall")]
    firewall_hips_decisions: FirewallHipsDecisions,
    #[cfg(feature = "firewall")]
    firewall_hips_allow_once: FirewallHipsAllowOnce,
    #[cfg(feature = "firewall")]
    firewall_hips_allow_always: FirewallHipsAllowAlways,
    /// Per-PID HTTP body pairs captured by the MITM proxy (received via HTTP_BODY pipe messages).
    #[cfg(feature = "firewall")]
    firewall_http_body_map: FirewallHttpBodyMap,
    /// Per-PID rolling history of full network packets from the firewall.
    #[cfg(feature = "firewall")]
    firewall_full_packets: FirewallFullPackets,
    /// Per-PID stats from Sanctum EDR telemetry.
    #[cfg(feature = "sanctum")]
    pub firewall_sanctum_stats: FirewallSanctumStats,
    #[cfg(feature = "firewall")]
    pub generate_report_flag: FirewallGenerateReport,
    pub rootkit_findings: Vec<RootkitFinding>,
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
            process_terminated: HashSet::new(),
            default_extension_whitelist: build_default_extension_whitelist(),
            #[cfg(feature = "firewall")]
            firewall_net_pids: shared_firewall_net_pids(),
            #[cfg(feature = "firewall")]
            firewall_net_details: shared_firewall_net_details(),
            #[cfg(feature = "firewall")]
            firewall_blocked_exes: shared_firewall_blocked_exes(),
            #[cfg(feature = "firewall")]
            firewall_pipe_started: shared_firewall_pipe_started(),
            #[cfg(feature = "firewall")]
            firewall_hips_pending_prompts: shared_firewall_hips_pending_prompts(),
            #[cfg(feature = "firewall")]
            firewall_hips_decisions: shared_firewall_hips_decisions(),
            #[cfg(feature = "firewall")]
            firewall_hips_allow_once: shared_firewall_hips_allow_once(),
            #[cfg(feature = "firewall")]
            firewall_hips_allow_always: shared_firewall_hips_allow_always(),
            #[cfg(feature = "firewall")]
            firewall_http_body_map: shared_firewall_http_body_map(),
            #[cfg(feature = "firewall")]
            firewall_full_packets: shared_firewall_full_packets(),
            #[cfg(feature = "sanctum")]
            firewall_sanctum_stats: shared_firewall_sanctum_stats(),
            #[cfg(feature = "firewall")]
            generate_report_flag: shared_firewall_generate_report(),
            rootkit_findings: Vec::new(),
        }
    }

    /// Spawn the \\.\pipe\HydraNetEvent named pipe server thread.
    /// Firewall sends: NET_EVENT:<pid>:<dst_ip>:<dst_port> and BLOCK_EXE:<exe_path>.
    /// Call once after constructing BehaviorEngine, before the scan loop starts.
    #[cfg(feature = "firewall")]
    pub fn start_firewall_pipe(&self) {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{
            CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, ERROR_PIPE_CONNECTED,
        };
        use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
            NAMED_PIPE_MODE, PIPE_UNLIMITED_INSTANCES,
        };
        use windows::core::PCWSTR;

        if self.firewall_pipe_started.swap(true, Ordering::SeqCst) {
            Logging::info("[HydraNetPipe] Firewall pipe server already active");
            return;
        }

        let net_pids      = Arc::clone(&self.firewall_net_pids);
        let net_details   = Arc::clone(&self.firewall_net_details);
        let blocked_exes  = Arc::clone(&self.firewall_blocked_exes);
        let hips_decisions = Arc::clone(&self.firewall_hips_decisions);
        let http_body_map = Arc::clone(&self.firewall_http_body_map);
        let full_packets: Arc<RwLock<HashMap<u32, VecDeque<PacketInfo>>>> = Arc::clone(&self.firewall_full_packets);
        let generate_report_flag = Arc::clone(&self.generate_report_flag);
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

                    // Validation: Only allow HydraDragon Firewall
                    if !unsafe { validate_pipe_client(handle, Some("hydradragonfirewall.exe"), false) } {
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
                                    };
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
                                        Some(Ok(hr)) if hr.is_ok() => Logging::warning(&format!(
                                            "[HydraNetPipe] Installed kernel block path: {}",
                                            block_path
                                        )),
                                        Some(Ok(hr)) => Logging::warning(&format!(
                                            "[HydraNetPipe] Kernel block path returned non-success HRESULT 0x{:08X} for {}",
                                            hr.0 as u32,
                                            block_path
                                        )),
                                        Some(Err(err)) => Logging::error(&format!(
                                            "[HydraNetPipe] Failed to install kernel block path {}: {:?}",
                                            block_path,
                                            err
                                        )),
                                        None => Logging::warning(&format!(
                                            "[HydraNetPipe] No shared driver handle available for kernel block path {}",
                                            block_path
                                        )),
                                    }
                                }
                            } else if let Some(rest) = line.strip_prefix("HTTP_BODY:") {
                                // HTTP_BODY:<pid>|<method>|<url>|<request_body>|<response_body>
                                let mut parts = rest.splitn(5, '|');
                                let pid_str      = parts.next().unwrap_or("").trim();
                                let _method      = parts.next().unwrap_or("").trim().to_string();
                                let _url         = parts.next().unwrap_or("").trim().to_string();
                                let req_body     = parts.next().unwrap_or("").trim().to_string();
                                let resp_body    = parts.next().unwrap_or("").trim().to_string();
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    net_pids.write().unwrap().insert(pid);
                                    http_body_map.write().unwrap()
                                        .entry(pid)
                                        .or_default()
                                        .push((req_body, resp_body));
                                    Logging::info(&format!(
                                        "[HTTP_BODY] Recorded body pair for PID {}", pid
                                    ));
                                }
                            } else if line == "GENERATE_REPORT" {
                                generate_report_flag.store(true, Ordering::SeqCst);
                                Logging::info("[HydraNetPipe] Received on-demand report request");
                            } else if let Some(json) = line.strip_prefix("FULL_PACKET:") {
                                // Full PacketInfo JSON from the firewall.
                                if let Ok(pkt) = serde_json::from_str::<PacketInfo>(json) {
                                    let pid = pkt.process_id;
                                    net_pids.write().unwrap().insert(pid);
                                    let mut pkt_map = full_packets.write().unwrap();
                                    let history = pkt_map.entry(pid).or_insert_with(|| VecDeque::with_capacity(500));
                                    if history.len() >= 500 {
                                        history.pop_front();
                                    }
                                    history.push_back(pkt.clone());
                                    
                                    // BEHAVIOR RULE MATCHING
                                    let mut matched_any = false;
                                    {
                                        for rule in rules_clone.iter() {
                                            if rule.matches_packet(&regex_cache, &pkt, &[]) {
                                                matched_any = true;
                                                Logging::alert(&format!(
                                                    "[BEHAVIOR RULE MATCH] PID {} matched network condition in rule '{}': {} -> {}",
                                                    pid, rule.name, pkt.src_ip, pkt.dst_ip
                                                ));
                                                
                                                if rule.response.status_access_denied || rule.response.quarantine || rule.response.kill_and_remove || rule.response.terminate_process {
                                                    let mut blocked = blocked_exes.write().unwrap();
                                                    
                                                    let reason = if rule.response.change_request_body.is_some() || rule.response.change_response_body.is_some() {
                                                        format!("Rule [{}] matched (Replacement suggested)", rule.name)
                                                    } else {
                                                        format!("Rule [{}] matched", rule.name)
                                                    };

                                                    blocked.insert(pkt.image_path.clone(), FirewallDetection {
                                                        dst_ip: pkt.dst_ip.to_string(),
                                                        dst_port: pkt.dst_port,
                                                        hostname: pkt.hostname.clone().unwrap_or_default(),
                                                        reason,
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
                                            "[FirewallEvent] Full packet recorded for PID {}: {} -> {} ({})",
                                            pid, pkt.src_ip, pkt.dst_ip, pkt.protocol
                                        ));
                                    }
                                } else {
                                    Logging::warning("[FirewallEvent] Failed to parse FULL_PACKET JSON");
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

    /// Ingest a telemetry event from Sanctum EDR.
    #[cfg(feature = "sanctum")]
    pub fn ingest_sanctum_event(&self, event: &serde_json::Value) {
        let pid = event["pid"].as_u64().unwrap_or(0) as u32;
        let source = event["source"].as_str().unwrap_or("-");
        let function = event["function"].as_str().unwrap_or("-");
        let args = &event["args"];
        let is_detection = event["is_detection"].as_bool().unwrap_or(false)
            || event["type"] == "DETECTION"
            || event["function"] == "DETECTION"
            || source == "DETECTION";

        // Register the PID as network-active if Sanctum observes
        // suspicious cross-process operations (NtOpenProcess etc.)
        // so firewall and behavior rules can correlate.
        #[cfg(feature = "firewall")]
        if pid != 0 && matches!(function,
            "NtOpenProcess" | "NtWriteVirtualMemory" |
            "NtAllocateVirtualMemory" | "NtCreateThreadEx"
        ) {
            self.firewall_net_pids.write().unwrap().insert(pid);
            Logging::warning(&format!(
                "[SanctumTelemetry] Suspicious syscall from PID {}: {}",
                pid, function
            ));
        }

        // Update shared Sanctum stats for real-time learning.
        if pid != 0 {
            let mut sanctum_lock = self.firewall_sanctum_stats.write().unwrap();
            let stats = sanctum_lock.entry(pid).or_insert_with(crate::realtime_learning::api_tracker::SanctumOperationStats::default);
            stats.syscall_count += 1;
            stats.is_detection |= is_detection;
            stats.last_event = Some(format!("{} - {}", function, serde_json::to_string(args).unwrap_or_default()));
            
            if let Some(target_pid) = args["target_pid"].as_u64() {
                if target_pid as u32 != pid {
                    stats.cross_process_handle_count += 1;
                }
            }

            if matches!(function, "NtWriteVirtualMemory" | "NtAllocateVirtualMemory" | "NtCreateThreadEx") {
                stats.injection_score += 0.1;
                stats.suspicious_syscall_hits.push(function.to_string());
                if stats.suspicious_syscall_hits.len() > 20 {
                    stats.suspicious_syscall_hits.remove(0);
                }
            }
            
            if stats.injection_score > 1.0 { stats.injection_score = 1.0; }
        }
    }

    #[cfg(feature = "firewall")]
    fn sanitize_firewall_hips_field(value: &str) -> String {
        value
            .replace('\r', " ")
            .replace('\n', " ")
            .replace('|', "/")
            .trim()
            .to_string()
    }

    #[cfg(feature = "firewall")]
    fn is_registry_condition_group(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.registry_keys.is_empty()
            || !cond_group.autorun_keys.is_empty()
            || !cond_group.registry_values.is_empty()
            || !cond_group.registry_value_data_patterns.is_empty()
    }

    #[cfg(feature = "firewall")]
    fn detect_firewall_hips_alert_kind(rule: &BehaviorRule, state: &ProcessBehaviorState) -> &'static str {
        if rule.named_conditions.iter().any(|(cond_name, cond_group)| {
            state.satisfied_named_conditions.contains(cond_name.as_str())
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
            Some(FileChangeInfo::RegCreateKey) => Some("reg_create"),
            Some(FileChangeInfo::RegSetValue) => Some("reg_set"),
            Some(FileChangeInfo::RegDeleteValue) => Some("reg_delete"),
            Some(FileChangeInfo::RegRenameKey) => Some("reg_rename"),
            Some(FileChangeInfo::RegQueryValue) => Some("reg_read"),
            _ => None,
        }
    }

    fn operation_label(msg: &IOMessage) -> String {
        let file_change = FromPrimitive::from_u8(msg.file_change);
        let irp_op = IrpMajorOp::from_byte(effective_hypervisor_irp_byte(msg));

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
                } else {
                    "create".to_string()
                }
            }
            IrpMajorOp::IrpRead => "read".to_string(),
            IrpMajorOp::IrpWrite => "write".to_string(),
            IrpMajorOp::IrpProcessCreate => "process_create".to_string(),
            IrpMajorOp::IrpProcessTerminate => "process_terminate".to_string(),
            IrpMajorOp::IrpProcessTerminateAttempt => "process_terminate_attempt".to_string(),
            IrpMajorOp::IrpProcessExit => "process_exit".to_string(),
            IrpMajorOp::IrpProcessHandleOpen => "process_handle_open".to_string(),
            IrpMajorOp::IrpHypervisorEvent => "hypervisor_event".to_string(),
            IrpMajorOp::IrpUserModeHookEvent => "user_mode_hook_event".to_string(),
            IrpMajorOp::IrpKernelRemoteThread => "kernel_remote_thread".to_string(),
            IrpMajorOp::IrpKernelWriteMemory => "kernel_write_memory".to_string(),
            IrpMajorOp::IrpKernelProtectMemory => "kernel_protect_memory".to_string(),
            IrpMajorOp::IrpKernelCreateThread => "kernel_create_thread".to_string(),
            IrpMajorOp::IrpKernelQueueApc => "kernel_queue_apc".to_string(),
            IrpMajorOp::IrpKernelCreateSection => "kernel_create_section".to_string(),
            IrpMajorOp::IrpKernelMapSection => "kernel_map_section".to_string(),
            _ => {
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                if msg.kernel_event_info.event_type != 0
                    && let Some(name) = known_raw_event_name(msg.kernel_event_info.event_type) {
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

            if !msg.filepathstr.trim().is_empty() {
                parts.push(format!(
                    "Path={}",
                    Self::truncate_detail_value(&msg.filepathstr, 260)
                ));
            } else {
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
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

        let mut condition_names: Vec<&String> = state
            .satisfied_named_conditions
            .iter()
            .filter(|name| rule.named_conditions.contains_key(*name))
            .collect();
        condition_names.sort();

        let mut condition_summaries = Vec::new();
        for cond_name in condition_names.into_iter().take(6) {
            let mut rendered = cond_name.clone();
            if let Some(values) = state.condition_match_values.get(cond_name) {
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
            parts.push(format!("MatchedConditions={}", condition_summaries.join(" | ")));
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
            if !state.satisfied_named_conditions.contains(cond_name.as_str())
                || !Self::is_file_condition_group(cond_group)
            {
                continue;
            }

            let Some(values) = state.condition_match_values.get(cond_name) else {
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
                let Some(extracted) = Self::extract_probable_artifact_path(&finding.description) else {
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

    #[cfg(feature = "firewall")]
    fn build_firewall_hips_target(&self, rule: &BehaviorRule, state: &ProcessBehaviorState) -> String {
        let alert_kind = Self::detect_firewall_hips_alert_kind(rule, state);

        if alert_kind == "registry" {
            for (cond_name, cond_group) in &rule.named_conditions {
                if !state.satisfied_named_conditions.contains(cond_name.as_str())
                    || !Self::is_registry_condition_group(cond_group)
                {
                    continue;
                }

                if let Some(values) = state.condition_match_values.get(cond_name)
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

        for (cond_name, values) in &state.condition_match_values {
            if rule.named_conditions.contains_key(cond_name)
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

    #[cfg(feature = "firewall")]
    fn build_firewall_hips_reason(rule: &BehaviorRule) -> String {
        let description = rule.description.trim();
        if description.is_empty() {
            format!("Owlyshield rule '{}' matched.", rule.name)
        } else {
            format!("Owlyshield rule '{}' matched: {}", rule.name, description)
        }
    }

    #[cfg(feature = "firewall")]
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

    #[cfg(feature = "firewall")]
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

    #[cfg(feature = "firewall")]
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

    #[cfg(feature = "firewall")]
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
        use std::ffi::CString;
        use windows::core::PCSTR;
        use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileA, FlushFileBuffers, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
            FILE_SHARE_NONE, OPEN_EXISTING,
        };
        use windows::Win32::System::Pipes::WaitNamedPipeA;

        const PIPE: &str = r"\\.\pipe\HydraHipEvent";
        const CONNECT_TIMEOUT_MS: u32 = 750;
        const CONNECT_ATTEMPTS: usize = 4;

        let pipe_name = match CString::new(PIPE) {
            Ok(value) => value,
            Err(_) => {
                Logging::error("[Owlyshield HIPS] Invalid HydraHipEvent pipe name");
                return false;
            }
        };
        let pcstr = PCSTR(pipe_name.as_ptr() as *const u8);

        let mut last_error = String::new();
        let mut pipe_handle: Option<HANDLE> = None;
        for _ in 0..CONNECT_ATTEMPTS {
            let wait_ok: BOOL = unsafe { WaitNamedPipeA(pcstr, CONNECT_TIMEOUT_MS) };
            if !wait_ok.as_bool() {
                last_error = format!("WaitNamedPipeA(GetLastError={:?})", unsafe { GetLastError() });
            } else {
                match unsafe {
                    CreateFileA(
                        pcstr,
                        FILE_GENERIC_WRITE.0,
                        FILE_SHARE_NONE,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        HANDLE::default(),
                    )
                } {
                    Ok(handle) if !handle.is_invalid() => {
                        pipe_handle = Some(handle);
                        break;
                    }
                    Ok(_) => {
                        last_error = "CreateFileA returned an invalid HydraHipEvent handle".to_string();
                    }
                    Err(err) => {
                        last_error = format!("CreateFileA failed: {:?}", err);
                    }
                }
            }

        }

        let Some(pipe_handle) = pipe_handle else {
            Logging::warning(&format!(
                "[Owlyshield HIPS] Failed to connect to HydraHipEvent pipe for request {} after {} attempts: {}",
                request_id,
                CONNECT_ATTEMPTS,
                last_error
            ));
            return false;
        };

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

        if !ok.as_bool() {
            Logging::error(&format!(
                "[Owlyshield HIPS] Failed to write HydraHipEvent prompt for request {}",
                request_id
            ));
            return false;
        }

        Logging::info(&format!(
            "[Owlyshield HIPS] Prompted firewall GUI for request {} (PID {}, {} bytes)",
            request_id, pid, bytes_written
        ));
        true
    }

    #[cfg(feature = "firewall")]
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
            gid,
            state.pid,
            &rule.name,
            alert_kind,
            &exe_path,
            &target,
        );
        let allow_signature = Self::build_firewall_hips_allow_signature(
            &rule.name,
            alert_kind,
            &exe_path,
            &target,
        );

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
                self.firewall_hips_pending_prompts
                    .write()
                    .unwrap()
                    .insert(
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

    fn normalize_registry_text(text: &str) -> String {
        let normalized = normalize_path_separators(
            &text
                .trim()
                .trim_matches(char::from(0))
                .to_ascii_lowercase(),
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

    fn registry_pattern_matches(cache: &Arc<RwLock<HashMap<String, Regex>>>, pattern: &str, filepath: &str) -> bool {
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

    fn registry_op_matches(cond_group: &NamedConditionGroup, msg: &IOMessage, irp_op: &IrpMajorOp) -> bool {
        if cond_group.registry_operations.is_empty() {
            return true;
        }
        if *irp_op != IrpMajorOp::IrpRegistry {
            return false;
        }

        let change = FromPrimitive::from_u8(msg.file_change);
        let op = match change {
            Some(FileChangeInfo::RegCreateKey) => "create",
            Some(FileChangeInfo::RegSetValue) => "set",
            Some(FileChangeInfo::RegDeleteValue) => "delete",
            Some(FileChangeInfo::RegRenameKey) => "rename",
            Some(FileChangeInfo::RegQueryValue) => "read",
            _ => return false,
        };
        cond_group.registry_operations.iter().any(|v| v == op)
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

        cond_group.extension_whitelist.iter().any(|p| {
            Self::extension_pattern_matches(cache, p, ext_without_dot, ext_with_dot)
        })
    }

    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let rules = self.load_rules_recursive(path)?;
        self.rules = rules;
        Logging::info(&format!("[EDR]: {} behavior rules loaded from {:?}", self.rules.len(), path));
        Ok(())
    }

    /// Extract all unique APIs mentioned across all rules, stages, and named conditions
    pub fn get_all_monitored_apis(&self) -> HashSet<String> {
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
                    if let RuleCondition::Api { name_pattern, module_pattern } = cond {
                        if module_pattern.is_empty() {
                            all_apis.insert(name_pattern.clone());
                        } else {
                            all_apis.insert(format!("{}!{}", module_pattern, name_pattern));
                        }
                    }
                }
            }
        }

        // Also include runtime-observed qualified API labels so dynamic hooks can
        // expand while the engine is running, not just from static rules.
        for state in self.process_states.values() {
            for api in &state.all_apis_called {
                let normalized = normalize_hypervisor_api_label(api);
                if normalized.contains('!') {
                    all_apis.insert(normalized);
                }
            }
        }

        all_apis
    }

    fn load_rules_recursive(&self, path: &Path) -> Result<Vec<BehaviorRule>, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut rules = Vec::new();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        // First, handle !include directives
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("!include ") {
                let include_part = if trimmed.starts_with("- ") {
                    trimmed.trim_start_matches("- ").trim()
                } else {
                    trimmed
                };
                
                if include_part.starts_with("!include ") {
                    let include_path_str = include_part.trim_start_matches("!include ").trim();
                    let include_path = parent.join(include_path_str);
                    
                    if include_path.exists() {
                        match self.load_rules_recursive(&include_path) {
                            Ok(sub_rules) => {
                                rules.extend(sub_rules);
                            },
                            Err(e) => Logging::warning(&format!("[EDR] Failed to load include {}: {}", include_path.display(), e)),
                        }
                    } else {
                        Logging::warning(&format!("[EDR] Include path does not exist: {}", include_path.display()));
                    }
                }
            }
        }

        // Now parse the content as YAML, skipping !include lines
        let filtered_content: String = content
            .lines()
            .filter(|line| !line.trim().starts_with("!include") && !line.trim().starts_with("- !include"))
            .collect::<Vec<_>>()
            .join("\n");

        if filtered_content.trim().is_empty() {
            return Ok(rules);
        }

        // Use Deserializer to handle multi-document YAML (separated by ---)
        let deserializer = serde_yaml::Deserializer::from_str(&filtered_content);
        for document in deserializer {
            if let Ok(value) = serde_yaml::Value::deserialize(document) {
                if let Some(rules_arr) = value.as_sequence() {
                    for rule_val in rules_arr {
                        if let Ok(mut rule) = serde_yaml::from_value::<BehaviorRule>(rule_val.clone()) {
                            rule.finalize_rich_fields();
                            rules.push(rule);
                        }
                    }
                } else if value.get("name").is_some() {
                    if let Ok(mut rule) = serde_yaml::from_value::<BehaviorRule>(value) {
                        rule.finalize_rich_fields();
                        rules.push(rule);
                    }
                }
            }
        }

        Ok(rules)
    }

    fn normalize_api_signature(raw: &str) -> (String, bool) {
        let mut value = normalize_hypervisor_api_label(raw).to_lowercase();
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
            && value < min_v {
                return false;
            }
        if let Some(max_v) = max
            && value > max_v {
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

    fn matches_hypervisor_payload_conditions(
        cond_group: &NamedConditionGroup,
        msg: &IOMessage,
        irp_op: &IrpMajorOp,
    ) -> bool {
        if !is_kernel_api_event(irp_op) {
            return false;
        }

        let raw_event_type = if msg.kernel_event_info.event_type != 0 {
            msg.kernel_event_info.event_type
        } else {
            effective_hypervisor_irp_byte(msg) as u32
        };
        let source_pid = msg.kernel_event_info.source_process_id;
        let target_pid = msg.kernel_event_info.target_process_id;
        let raw_arg1 = msg.kernel_event_info.raw_argument1;
        let raw_arg2 = msg.kernel_event_info.raw_argument2;
        let raw_arg3 = msg.kernel_event_info.raw_argument3;
        let raw_arg4 = msg.kernel_event_info.raw_argument4;
        let memory_address = msg.kernel_event_info.memory_address;
        let memory_size = msg.kernel_event_info.memory_size as u64;
        let memory_protection = msg.kernel_event_info.memory_protection;
        let is_executable_memory = msg.kernel_event_info.is_executable_memory;
        let thread_handle = msg.kernel_event_info.thread_handle;
        let thread_start_routine = msg.kernel_event_info.thread_start_routine;
        let access_mask = msg.kernel_event_info.access_mask;
        let operation_status = msg.kernel_event_info.operation_status;

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


    pub fn register_process(&mut self, gid: u64, pid: u32, exe_path: PathBuf, app_name: String) {
        let state = self.process_states
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
        let path_is_stale = state.exe_path.to_string_lossy() == "UNKNOWN"
            || state.exe_path.as_os_str().is_empty();

        if name_is_stale && !app_name.is_empty() && !app_name.starts_with("PROC_") && app_name != "UNKNOWN" {
            state.app_name = app_name;
        }
        if path_is_stale && !exe_path.as_os_str().is_empty() && exe_path.to_string_lossy() != "UNKNOWN" {
            state.exe_path = exe_path;
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
    
    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage, config: &Config, threat_handler: &dyn ThreatHandler) {
        let gid = msg.gid;
        let mut actions = ActionsOnKill::with_handler(threat_handler.clone_box());
        
        if !self.process_states.contains_key(&gid) {
            // appname and exepath are resolved by worker.rs (register_precord) before reaching here.
            let mut s = ProcessBehaviorState::new(msg.pid, precord.exepath.clone(), precord.appname.clone());
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
                if let Some(parent_name) = parent_path.file_name().and_then(|value| value.to_str()) {
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

        // Self-heal: if the state was created with placeholder values before worker.rs
        // resolved the real appname/exepath (race between event arrival and IrpProcessCreate),
        // update it on every subsequent event until the values are concrete.
        // Also update precord itself so ransomware detection and all other paths get
        // the correct values — process_record_handler.handle_io runs before this function.
        // Resolve parent name before the mutable borrow below (borrow checker).
        let parent_pid = msg.parent_pid;
        let (resolved_parent_name, resolved_parent_path): (Option<String>, Option<PathBuf>) = if parent_pid != 0 {
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

            if precord_name_stale && !state.app_name.is_empty()
                && !state.app_name.starts_with("PROC_")
                && state.app_name != "UNKNOWN"
            {
                precord.appname = state.app_name.clone();
            }
            if precord_path_stale && !state.exe_path.as_os_str().is_empty()
                && state.exe_path.to_string_lossy() != "UNKNOWN"
            {
                precord.exepath = state.exe_path.clone();
            }

            // Heal parent name using the value resolved before the mutable borrow.
            if (state.parent_name == "unknown" || state.parent_name.is_empty() )
                && let Some(ref name) = resolved_parent_name {
                    state.parent_name = name.clone();
                }
            if state.parent_path.as_os_str().is_empty()
                && let Some(ref path) = resolved_parent_path {
                    state.parent_path = path.clone();
                }
        }
        let irp_op_byte = effective_hypervisor_irp_byte(msg);
        let irp_op = IrpMajorOp::from_byte(irp_op_byte);
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.record_irp_operation(msg, irp_op_byte);
        }
        
        let dev_norm = normalize_device_prefix(&msg.filepathstr);
        let filepath = dev_norm.to_lowercase().replace("\\", "/");
        let norm_filepath = filepath.trim_end_matches('/');
        
        let state = self.process_states.get_mut(&gid).unwrap();
        let pid = state.pid;
        if state.command_line.is_empty() && !msg.runtime_features.command_line.trim().is_empty() {
            state.command_line = msg.runtime_features.command_line.to_lowercase();
            if state.script_file.is_empty() {
                if let Some((fname, fpath)) = Self::extract_script_from_cmdline(
                    &state.app_name,
                    &msg.runtime_features.command_line,
                ) {
                    state.script_file = fname;
                    state.script_file_path = fpath;
                }
            }
        }

        if self.rules.iter().any(|r| r.debug) {
            Logging::debug(&format!(
                "[BehaviorEngine] IO event: pid={} gid={} irp={:?} path={} ext={} entropy={}",
                pid, gid, irp_op,
                if msg.filepathstr.is_empty() { "<empty>" } else { &msg.filepathstr },
                if msg.extension.is_empty() { "<none>" } else { &msg.extension },
                msg.entropy
            ));
        }
        
        // === STEP 3: SIGNATURE CHECK ===
        if !state.signature_checked && !precord.exepath.as_os_str().is_empty() {
            if precord.exepath.exists() {
                let info = verify_signature(&precord.exepath);
                state.has_valid_signature = info.is_trusted;
                state.is_signed = info.is_signed;
                state.signature_checked = true;
            } else {
                state.has_valid_signature = false;
                state.signature_checked = true;
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
                    && let Some(attacker_state) = self.process_states.get_mut(&msg.attacker_gid) {
                        attacker_found = true;
                        if !victim_path.is_empty() {
                            if is_self {
                                attacker_state.self_terminated_processes.insert(victim_path.clone());
                            } else {
                                attacker_state.terminated_processes.insert(victim_path.clone());
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
                            && !victim_path.is_empty() {
                                attacker_state.terminated_processes.insert(victim_path.clone());
                            }
                }
                
                if !victim_path.is_empty() {
                    self.process_terminated.insert(victim_path.clone());
                }
            }
        }

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
                            state.browsed_paths_tracker.insert(path_pattern.clone(), SystemTime::now());
                        }
                    }
                    
                    for staging_pattern in &cond_group.staging_paths {
                        let norm_pattern = staging_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        let is_staging_op = matches!(irp_op, IrpMajorOp::IrpWrite | IrpMajorOp::IrpCreate | IrpMajorOp::IrpSetInfo);
                        if norm_filepath.contains(norm_pattern) && is_staging_op {
                            state.staged_files_written.insert(PathBuf::from(&filepath), SystemTime::now());
                        }
                    }
                    
                    for browsed_pattern in &cond_group.browsed_paths {
                        let norm_pattern = browsed_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(norm_pattern) {
                            state.browsed_paths_tracker.insert(browsed_pattern.clone(), SystemTime::now());
                        }
                    }
                    
                    for sensitive_pattern in &cond_group.sensitive_paths {
                        let norm_pattern = sensitive_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(norm_pattern) {
                            state.accessed_paths_tracker.insert(sensitive_pattern.clone());
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

    fn update_named_conditions_state(&mut self, precord: &mut ProcessRecord, gid: u64, msg: &IOMessage, irp_op: &IrpMajorOp, filepath: &str) {
        let now = SystemTime::now();
        let mut available_apis = HashSet::new();
        
        let state_detected_apis = if let Some(state) = self.process_states.get(&gid) {
            state.all_apis_called.clone()
        } else {
            HashSet::new()
        };
        let observed_hypervisor_event_labels = if let Some(state) = self.process_states.get(&gid) {
            state.observed_hypervisor_event_labels.clone()
        } else {
            HashSet::new()
        };
        
        for api in &state_detected_apis {
            available_apis.insert(api.clone());
        }
        
        if !available_apis.is_empty() {
            let mut api_names: Vec<&str> = available_apis.iter().map(|s| s.as_str()).collect();
            api_names.sort_unstable_by_key(|name| name.to_ascii_lowercase());
            Logging::info(&format!(
                "[BehaviorEngine] Detected APIs for PID {}: {} - {}",
                msg.pid, available_apis.len(), api_names.join(", ")
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

        for rule in &self.rules {
            if rule.named_conditions.is_empty() {
                continue;
            }

            let state = match self.process_states.get_mut(&gid) {
                Some(s) => s,
                None => continue,
            };
            
            let remaining_conditions: Vec<_> = rule.named_conditions.iter()
                .filter(|(name, _)| !state.satisfied_named_conditions.contains(name.as_str()))
                .collect();
            
            if remaining_conditions.is_empty() {
                continue;
            }
            
            for (cond_name, cond_group) in remaining_conditions {
                if state.satisfied_named_conditions.contains(cond_name) {
                    continue;
                }

                let mut matched = false;

                let has_api_conditions = !cond_group.apis.is_empty() || 
                                         !cond_group.scheduled_task_apis.is_empty() || 
                                         !cond_group.anti_debug_apis.is_empty() || 
                                         !cond_group.anti_vm_apis.is_empty();

                if has_api_conditions {
                    let api_iter = cond_group.apis.iter()
                        .chain(cond_group.scheduled_task_apis.iter())
                        .chain(cond_group.anti_debug_apis.iter())
                        .chain(cond_group.anti_vm_apis.iter());

                    let matched_apis: Vec<&String> = api_iter.filter(|required_api| {
                        let (required_norm, required_has_path) = Self::normalize_api_signature(required_api);
                        available_apis.iter().any(|available| {
                            let (available_norm, available_has_path) = Self::normalize_api_signature(available);
                            if required_has_path {
                                available_has_path
                                    && Self::matches_pattern_internal(&self.regex_cache, required_api, available)
                            } else {
                                Self::matches_pattern_internal(&self.regex_cache, &required_norm, &available_norm)
                            }
                        })
                    }).collect();
                    
                    if matched_apis.len() >= std::cmp::max(1, cond_group.api_threshold) {
                        matched = true;
                        let api_names = matched_apis.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - API match for PID {}: {} APIs detected: {}",
                            cond_name, state.pid, matched_apis.len(), api_names
                        ));
                    }
                }

                if !matched && !cond_group.hypervisor_event_labels.is_empty() {
                    let matched_labels: Vec<&String> = cond_group.hypervisor_event_labels.iter().filter(|required_label| {
                        let (required_norm, required_has_path) = Self::normalize_api_signature(required_label);
                        observed_hypervisor_event_labels.iter().any(|observed_label| {
                            let (observed_norm, observed_has_path) = Self::normalize_api_signature(observed_label);
                            if required_has_path {
                                observed_has_path
                                    && Self::matches_pattern_internal(&self.regex_cache, required_label, observed_label)
                            } else {
                                Self::matches_pattern_internal(&self.regex_cache, &required_norm, &observed_norm)
                            }
                        })
                    }).collect();

                    if matched_labels.len() >= std::cmp::max(1, cond_group.hypervisor_event_threshold) {
                        matched = true;
                        let label_names = matched_labels.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Hypervisor event match for PID {}: {} labels detected: {}",
                            cond_name, state.pid, matched_labels.len(), label_names
                        ));
                    }
                }

                if !matched && Self::has_hypervisor_payload_conditions(cond_group)
                    && Self::matches_hypervisor_payload_conditions(cond_group, msg, irp_op) {
                        let raw_event_type = if msg.kernel_event_info.event_type != 0 {
                            msg.kernel_event_info.event_type
                        } else {
                            effective_hypervisor_irp_byte(msg) as u32
                        };
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - API hooking payload match for PID {}: raw_event_type={} src_pid={} target_pid={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X}",
                            cond_name,
                            state.pid,
                            raw_event_type,
                            msg.kernel_event_info.source_process_id,
                            msg.kernel_event_info.target_process_id,
                            msg.kernel_event_info.raw_argument1,
                            msg.kernel_event_info.raw_argument2,
                            msg.kernel_event_info.raw_argument3,
                            msg.kernel_event_info.raw_argument4
                        ));
                    }

                if !matched && cond_group.has_network_activity
                    && self.firewall_net_pids.read().unwrap().contains(&state.pid) {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Network activity confirmed by firewall for PID {}",
                            cond_name, state.pid
                        ));
                    }

                // ── Firewall-content conditions ──────────────────────────────────
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
                        let ip_match = detection.map_or(false, |d| {
                            cond_group.firewall_dst_ips.iter().any(|ip| {
                                d.dst_ip.to_lowercase().contains(&ip.to_lowercase())
                            })
                        }) || fw_net_details.get(&state.pid).map_or(false, |conns| {
                            cond_group.firewall_dst_ips.iter().any(|ip| {
                                conns.iter().any(|(c_ip, _)| c_ip.to_lowercase().contains(&ip.to_lowercase()))
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
                        let port_match = detection.map_or(false, |d| {
                            cond_group.firewall_dst_ports.contains(&d.dst_port)
                        }) || fw_net_details.get(&state.pid).map_or(false, |conns| {
                            conns.iter().any(|(_, port)| cond_group.firewall_dst_ports.contains(port))
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
                            cond_group.firewall_hostnames.iter().any(|h| {
                                d.hostname.to_lowercase().contains(&h.to_lowercase())
                            })
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
                            cond_group.firewall_block_reasons.iter().any(|r| {
                                d.reason.to_lowercase().contains(&r.to_lowercase())
                            })
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
                                    Self::matches_pattern_internal(&self.regex_cache, pattern, query)
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
                #[cfg(feature = "sanctum")]
                if !matched {
                    if let Some(min_score) = cond_group.sanctum_injection_score_min {
                        if state.sanctum_stats.injection_score >= min_score {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - sanctum_injection_score_min matched: {} >= {} for PID {}",
                                cond_name, state.sanctum_stats.injection_score, min_score, state.pid
                            ));
                        }
                    }
                    if !matched {
                        if let Some(min_syscalls) = cond_group.sanctum_syscall_count_min {
                            if state.sanctum_stats.syscall_count >= min_syscalls {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - sanctum_syscall_count_min matched: {} >= {} for PID {}",
                                    cond_name, state.sanctum_stats.syscall_count, min_syscalls, state.pid
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
                        if cond_group.sanctum_suspicious_hits.iter().any(|hit| state.sanctum_suspicious_hits.contains(hit)) {
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
                        let matches_type = state.rootkit_findings.iter().filter(|f| {
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
                            cond_group.rootkit_event_types.iter().any(|rt| rt.to_lowercase() == type_str)
                        }).count();
                        
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
                                cond_name, state.pid, state.rootkit_findings.len(), total_min
                            ));
                        }
                    }

                    if !matched && !cond_group.rootkit_description_contains.is_empty() {
                        let has_desc = state.rootkit_findings.iter().any(|f| {
                            let desc_lc = f.description.to_lowercase();
                            cond_group.rootkit_description_contains.iter().any(|d| desc_lc.contains(&d.to_lowercase()))
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
                let is_directory_event = matches!(file_change, Some(FileChangeInfo::OpenDirectory));

                let current_file_op = match *irp_op {
                    IrpMajorOp::IrpRead => Some("read"),
                    IrpMajorOp::IrpWrite => Some("write"),
                    IrpMajorOp::IrpCreate => {
                        if is_directory_event {
                            None
                        } else {
                            Some("create")
                        }
                    }
                    IrpMajorOp::IrpSetInfo => {
                        match file_change {
                            Some(FileChangeInfo::ChangeRenameFile) => Some("rename"),
                            Some(FileChangeInfo::ChangeExtensionChanged) => Some("rename"),
                            Some(FileChangeInfo::ChangeDeleteFile) => Some("delete"),
                            Some(FileChangeInfo::ChangeWrite) => Some("write"),
                            Some(FileChangeInfo::ChangeOverwriteFile) => Some("write"),
                            Some(FileChangeInfo::ChangeNewFile) => Some("create"),
                            _ => Some("setinfo"),
                        }
                    }
                    _ => None,
                };

                let file_op_allowed = if cond_group.file_operations.is_empty() {
                    true
                } else if let Some(op) = current_file_op {
                    cond_group.file_operations.iter().any(|v| v == op)
                } else {
                    false
                };

                let has_path_filters = !cond_group.file_paths.is_empty() || 
                                       !cond_group.staging_paths.is_empty() ||
                                       !cond_group.browsed_paths.is_empty() ||
                                       !cond_group.sensitive_paths.is_empty() ||
                                       !cond_group.persistence_locations.is_empty();

                let has_extension_conditions = !cond_group.file_extensions.is_empty()
                    || cond_group.detect_extension_changes
                    || cond_group.detect_non_whitelisted_extensions
                    || cond_group.detect_known_to_unknown_extension_change;

                let same_file_requirements_ok =
                    (!cond_group.require_same_file_read || precord.has_read_file_id(&msg.file_id_id))
                        && (!cond_group.require_same_file_write || precord.has_written_file_id(&msg.file_id_id))
                        && (!cond_group.require_same_file_rename || precord.has_renamed_file_id(&msg.file_id_id))
                        && (!cond_group.require_same_stem_created_unknown_extension
                            || state.created_unknown_ext_stems.contains(filepath))
                        && (!cond_group.require_same_stem_written_unknown_extension
                            || state.written_unknown_ext_stems.contains(filepath));

                let parent_image_touched = !state.parent_path.as_os_str().is_empty()
                    && target_matches_process_image(&state.parent_path, filepath, &msg.filepathstr);

                if !matched
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
                if !matched && has_path_filters && !has_extension_conditions && file_op_allowed {
                    let path_variants = build_path_variants(filepath, &msg.filepathstr);
                    let mut path_iter = cond_group.file_paths.iter()
                        .chain(cond_group.staging_paths.iter())
                        .chain(cond_group.browsed_paths.iter())
                        .chain(cond_group.sensitive_paths.iter())
                        .chain(cond_group.persistence_locations.iter());

                    let matched_path: Option<String> = path_iter.find(|p| {
                        let p_norm = p.replace("\\", "/");
                        let p_norm_stripped = strip_drive_prefix(&p_norm);
                        path_variants.iter().any(|v| {
                            Self::matches_pattern_internal(&self.regex_cache, &p_norm, v) ||
                            Self::matches_pattern_internal(&self.regex_cache, &p_norm_stripped, v)
                        })
                    }).map(|s| s.to_string());
                    
                    if matched_path.is_some() {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Path match for PID {}: {}",
                            cond_name, state.pid, matched_path.unwrap_or_default()
                        ));
                    }
                }

                // File-operation-only conditions (no path or extension constraints) should still accumulate.
                if !matched
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

                if !matched && has_extension_conditions && file_op_allowed && !is_directory_event && same_file_requirements_ok {
                    let extension_changed = matches!(
                        file_change,
                        Some(FileChangeInfo::ChangeRenameFile)
                            | Some(FileChangeInfo::ChangeExtensionChanged)
                    );

                    let path_filter_match = if has_path_filters {
                        let path_variants = build_path_variants(filepath, &msg.filepathstr);
                        cond_group.file_paths.iter()
                            .chain(cond_group.staging_paths.iter())
                            .chain(cond_group.browsed_paths.iter())
                            .chain(cond_group.sensitive_paths.iter())
                            .chain(cond_group.persistence_locations.iter())
                            .any(|p| {
                                let p_norm = p.replace("\\", "/");
                                let p_norm_stripped = strip_drive_prefix(&p_norm);
                                path_variants.iter().any(|v| {
                                    Self::matches_pattern_internal(&self.regex_cache, &p_norm, v) ||
                                    Self::matches_pattern_internal(&self.regex_cache, &p_norm_stripped, v)
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
                                && let Some(matched_ext) = cond_group.file_extensions.iter().find(|p| {
                                    Self::extension_pattern_matches(&self.regex_cache, p, &ext, &ext_with_dot)
                                }) {
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
                                    if !filepath.is_empty() && matches!(current_file_op, Some("create") | Some("write")) {
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

                        if !matched && extension_changed {
                            if cond_group.detect_known_to_unknown_extension_change {
                                let matched_known_to_unknown = if let Some(previous_ext) = previous_extension.as_ref() {
                                    if event_extension.is_empty() {
                                        false
                                    } else {
                                        let previous_ext_with_dot = format!(".{}", previous_ext);
                                        let current_ext_with_dot = format!(".{}", event_extension);
                                        let previous_is_known = Self::is_extension_whitelisted(
                                            &self.regex_cache,
                                            &self.default_extension_whitelist,
                                            cond_group,
                                            previous_ext,
                                            &previous_ext_with_dot,
                                        );
                                        let current_is_known = Self::is_extension_whitelisted(
                                            &self.regex_cache,
                                            &self.default_extension_whitelist,
                                            cond_group,
                                            &event_extension,
                                            &current_ext_with_dot,
                                        );
                                        previous_is_known && !current_is_known
                                    }
                                } else {
                                    false
                                };

                                if matched_known_to_unknown {
                                    matched = true;
                                    Logging::info(&format!(
                                        "[BehaviorEngine] Condition '{}' - Known-to-unknown extension change for PID {} (prev: .{}, new: .{})",
                                        cond_name,
                                        state.pid,
                                        previous_extension.as_deref().unwrap_or(""),
                                        event_extension
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

                let has_reg_conditions = !cond_group.registry_keys.is_empty() || 
                                         !cond_group.autorun_keys.is_empty() ||
                                         !cond_group.registry_values.is_empty() ||
                                         !cond_group.registry_value_data_patterns.is_empty();

                if !matched && has_reg_conditions && *irp_op == IrpMajorOp::IrpRegistry
                    && Self::registry_op_matches(cond_group, msg, irp_op) {
                        let reg_iter = cond_group.registry_keys.iter()
                            .chain(cond_group.autorun_keys.iter())
                            .chain(cond_group.registry_values.iter());

                        for reg_pattern in reg_iter {
                            if Self::registry_pattern_matches(&self.regex_cache, reg_pattern, filepath) {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - Registry match for PID {}: {}",
                                    cond_name, state.pid, reg_pattern
                                ));
                                break;
                            }
                        }

                        if !matched && !cond_group.registry_value_data_patterns.is_empty() {
                            // object_name usually contains the data for RegSetValue in this engine's current IOMessage mapping
                            let data = msg.kernel_event_info.object_name.trim();
                            if !data.is_empty() && cond_group.registry_value_data_patterns.iter().any(|pattern| {
                                Self::matches_pattern_internal(&self.regex_cache, pattern, data)
                            }) {
                                matched = true;
                                Logging::info(&format!(
                                    "[BehaviorEngine] Condition '{}' - Registry value data match for PID {}: {}",
                                    cond_name, state.pid, data
                                ));
                            }
                        }
                    }

                if !matched && !cond_group.parent_names.is_empty() {
                    let parent_lc = state.parent_name.to_lowercase();
                    if !parent_lc.is_empty() && parent_lc != "unknown"
                        && cond_group.parent_names.iter().any(|p| {
                            Self::matches_pattern_internal(&self.regex_cache, p, &parent_lc)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Parent process match for PID {}: {}",
                                cond_name, state.pid, parent_lc
                            ));
                        }
                }

                if !matched && (!cond_group.cmdline_keywords.is_empty() || !cond_group.cmdline_patterns.is_empty()) {
                    let cmdline_lc = state.command_line.to_lowercase();
                    if !cmdline_lc.is_empty() {
                        let keyword_hit = cond_group.cmdline_keywords.iter().any(|kw| {
                            Self::matches_pattern_internal(&self.regex_cache, kw, &cmdline_lc)
                        });
                        let pattern_hit = cond_group.cmdline_patterns.iter().any(|pat| {
                            pat.matches(&self.regex_cache, &cmdline_lc)
                        });
                        if keyword_hit || pattern_hit {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Command line match for PID {}: {}",
                                cond_name, state.pid, cmdline_lc
                            ));
                        }
                    }
                }

                // script_file_patterns: match against the script file extracted
                // from the interpreter's command line (e.g. "evil.ps1" from
                // `powershell.exe -File evil.ps1`). Matches both the filename
                // and the full normalized path so rules can be as broad or
                // narrow as needed.
                if !matched && !cond_group.script_file_patterns.is_empty() && !state.script_file.is_empty() {
                    let hit = cond_group.script_file_patterns.iter().any(|pat| {
                        let p = pat.to_lowercase();
                        Self::matches_pattern_internal(&self.regex_cache, &p, &state.script_file)
                            || Self::matches_pattern_internal(&self.regex_cache, &p, &state.script_file_path)
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
                        && let Some(victim) = cond_group.terminated_processes.iter().find(|victim_pattern| {
                            Self::matches_pattern_internal(&self.regex_cache, victim_pattern, filepath)
                        }) {
                            term_match = true;
                            matched_victim = victim.to_string();
                        }
                    if !term_match
                        && let Some(victim) = state.terminated_processes.iter().find(|victim| {
                            cond_group.terminated_processes.iter().any(|victim_pattern| {
                                Self::matches_pattern_internal(&self.regex_cache, victim_pattern, victim)
                            })
                        }) {
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
                    && *irp_op == IrpMajorOp::IrpProcessCreate
                    && !cond_group.created_processes.is_empty()
                {
                    // Extract just the filename from device or drive-letter paths.
                    // split on both \ and / to handle \Device\HarddiskVolume3\...\bcdedit.exe
                    let child_name = msg.filepathstr
                        .split(['\\', '/'])
                        .filter(|s| !s.is_empty())
                        .last()
                        .unwrap_or("")
                        .to_lowercase();
                    let child_path_norm = canonical_behavior_path(&msg.filepathstr);

                    let name_match = cond_group.created_processes.iter().any(|pattern| {
                        let p_lc = pattern.to_lowercase();
                        (!child_name.is_empty() && Self::matches_pattern_internal(&self.regex_cache, &p_lc, &child_name))
                        || (!child_path_norm.is_empty() && Self::matches_pattern_internal(&self.regex_cache, &p_lc, &child_path_norm))
                    });

                    if name_match {
                        // If cmdline_keywords are also specified, ALL must appear in the child's cmdline.
                        let child_cmdline = msg.runtime_features.command_line.to_lowercase();
                        let cmdline_ok = cond_group.cmdline_keywords.is_empty()
                            || cond_group.cmdline_keywords.iter().all(|kw| {
                                Self::matches_pattern_internal(&self.regex_cache, kw, &child_cmdline)
                            });

                        if cmdline_ok {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Process name match for PID {}: {}",
                                cond_name, state.pid, child_name
                            ));
                        }
                    }
                }

                if !matched && !cond_group.process_names.is_empty() {
                    let app_lc = state.app_name.to_lowercase();
                    if !app_lc.is_empty()
                        && cond_group.process_names.iter().any(|p| {
                            Self::matches_pattern_internal(&self.regex_cache, p, &app_lc)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Process name match for PID {}: {}",
                                cond_name, state.pid, app_lc
                            ));
                        }
                }
                
                if !matched && cond_group.is_signed.is_some() {
                    let check_signed = cond_group.is_signed.unwrap();
                    if state.is_signed == check_signed {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Signature state match for PID {}: is_signed={}",
                            cond_name, state.pid, state.is_signed
                        ));
                    }
                }
                
                if !matched && cond_group.is_valid_signed.is_some() {
                    let check_valid = cond_group.is_valid_signed.unwrap();
                    if state.has_valid_signature == check_valid {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Valid signature match for PID {}: has_valid_signature={}",
                            cond_name, state.pid, state.has_valid_signature
                        ));
                    }
                }
                
                if !matched && cond_group.requires_signed.is_some() {
                    let must_be_signed = cond_group.requires_signed.unwrap();
                    if state.is_signed == must_be_signed {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Required signature match for PID {}: requires_signed={}",
                            cond_name, state.pid, must_be_signed
                        ));
                    }
                }
                
                if !matched
                    && cond_group.detect_hypervisor_event
                    && state.hypervisor_event_count >= cond_group.hypervisor_event_threshold.max(1) as u32
                {
                    matched = true;
                    Logging::info(&format!(
                        "[BehaviorEngine] Condition '{}' - API hooking fallback detected for PID {}: {} events",
                        cond_name, state.pid, state.hypervisor_event_count
                    ));
                }
                
                if matched {
                    let match_key = if !filepath.is_empty() {
                        filepath.to_string()
                    } else if !msg.filepathstr.is_empty() {
                        msg.filepathstr.to_lowercase().replace("\\", "/")
                    } else if msg.file_id_id.0 != 0 {
                        format!(
                            "fileid:{:016x}:op{}:chg{}",
                            msg.file_id_id.0, msg.irp_op, msg.file_change
                        )
                    } else {
                        let event_ts = msg.time.duration_since(UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        format!(
                            "event:{}:pid{}:op{}:{}",
                            cond_name, msg.pid, msg.irp_op, event_ts
                        )
                    };
                    let values = state.condition_match_values.entry(cond_name.clone()).or_insert_with(HashSet::new);
                    if values.len() > 256 {
                        values.clear();
                    }
                    let is_new = values.insert(match_key.clone());
                    let count = state.condition_match_counts.entry(cond_name.clone()).or_insert(0);
                    if is_new {
                        *count += 1;
                    }
                    state.condition_first_seen.entry(cond_name.clone()).or_insert(now);
                    state.condition_last_seen.insert(cond_name.clone(), now);

                    let required = if cond_group.min_matches > 0 { cond_group.min_matches } else { 1 };
                    if *count >= required {
                        state.satisfied_named_conditions.insert(cond_name.clone());
                        if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Named condition '{}' satisfied for PID {} (count: {}/{}, matches: {})",
                                cond_name, state.pid, *count, required, match_key
                            ));
                        }
                    } else if is_new
                        && (rule.debug || self.rules.iter().any(|r| r.debug)) {
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
        _rule: &BehaviorRule,
    ) -> bool {
        match condition {
            DetectionCondition::Named { condition: cond_name } => {
                state.satisfied_named_conditions.contains(cond_name)
            },
            
            DetectionCondition::And { and } => {
                and.iter().all(|c| self.evaluate_detection_condition(c, state, _rule))
            },
            
            DetectionCondition::Or { or } => {
                or.iter().any(|c| self.evaluate_detection_condition(c, state, _rule))
            },
            
            DetectionCondition::Not { not } => {
                !self.evaluate_detection_condition(not, state, _rule)
            },
            
            DetectionCondition::AllOf { all_of } => {
                all_of.iter().all(|cond_name| state.satisfied_named_conditions.contains(cond_name))
            },
            
            DetectionCondition::AnyOf { any_of } => {
                any_of.iter().any(|cond_name| state.satisfied_named_conditions.contains(cond_name))
            },
            
            DetectionCondition::NOf { n_of, conditions } => {
                let satisfied_count = conditions.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                satisfied_count == *n_of
            },
            
            DetectionCondition::AtLeast { at_least, conditions } => {
                let satisfied_count = conditions.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                satisfied_count >= *at_least
            },
            
            DetectionCondition::AllOfPattern { all_of_pattern } => {
                let matching_conditions: Vec<_> = state.satisfied_named_conditions.iter()
                    .filter(|cond_name| Self::matches_pattern_internal(&self.regex_cache, all_of_pattern, cond_name))
                    .collect();
                !matching_conditions.is_empty()
            },
            
            DetectionCondition::AnyOfPattern { any_of_pattern } => {
                state.satisfied_named_conditions.iter()
                    .any(|cond_name| Self::matches_pattern_internal(&self.regex_cache, any_of_pattern, cond_name))
            },
            
            DetectionCondition::Count { count, comparison, threshold } => {
                let satisfied_count = count.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                match comparison {
                    Comparison::Gt => satisfied_count > *threshold,
                    Comparison::Gte => satisfied_count >= *threshold,
                    Comparison::Lt => satisfied_count < *threshold,
                    Comparison::Lte => satisfied_count <= *threshold,
                    Comparison::Eq => satisfied_count == *threshold,
                    Comparison::Ne => satisfied_count != *threshold,
                }
            },
            
            DetectionCondition::Percentage { percentage, comparison, threshold } => {
                if percentage.is_empty() { return false; }
                let satisfied_count = percentage.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
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
            },
        }
    }

    fn check_rules(
        &mut self,
        precord: &mut ProcessRecord,
        gid: u64,
        msg: &IOMessage,
        _irp_op: IrpMajorOp,
        config: &Config,
        actions: &mut ActionsOnKill
    ) {
        let state_ref = match self.process_states.get_mut(&gid) {
            Some(s) => {
                let pid = s.pid;
                #[cfg(feature = "firewall")]
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
                #[cfg(feature = "sanctum")]
                if let Ok(mut sanctum_lock) = self.firewall_sanctum_stats.write() {
                    if let Some(stats) = sanctum_lock.remove(&pid) {
                        s.sanctum_stats.syscall_count += stats.syscall_count;
                        s.sanctum_stats.is_detection |= stats.is_detection;
                        s.sanctum_stats.injection_score = (s.sanctum_stats.injection_score + stats.injection_score).min(1.0);
                        s.sanctum_stats.cross_process_handle_count += stats.cross_process_handle_count;
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
            if self.check_allowlist(&precord.appname, rule, Some(&precord.exepath), script_file_opt) {
                continue;
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
                    rule.suspicious_parents.iter().any(|p| {
                        Self::matches_pattern_internal(&self.regex_cache, p, &parent_lc)
                    })
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
                            state_ref.pid, state_ref.staged_files_written.len()
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
                            state_ref.pid, state_ref.accessed_paths_tracker.len()
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
                let api_match_count = rule.monitored_apis.iter().filter(|monitored_api| {
                    let (monitored_norm, monitored_has_path) = Self::normalize_api_signature(monitored_api);
                    state_ref.all_apis_called.iter().any(|tracked_api| {
                        let (tracked_norm, tracked_has_path) = Self::normalize_api_signature(tracked_api);
                        if monitored_has_path {
                            tracked_has_path
                                && Self::matches_pattern_internal(&self.regex_cache, monitored_api, tracked_api)
                        } else {
                            Self::matches_pattern_internal(&self.regex_cache, &monitored_norm, &tracked_norm)
                        }
                    })
                }).count();
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
                    let ext_match = state_ref.terminated_processes.iter().any(|v| 
                        Self::matches_pattern_internal(&self.regex_cache, rule_proc, v)
                    );
                    let self_match = rule.detect_self_termination && state_ref.self_terminated_processes.iter().any(|v|
                        Self::matches_pattern_internal(&self.regex_cache, rule_proc, v)
                    );
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

            #[cfg(feature = "firewall")]
            {
                if !rule.http_request_body_patterns.is_empty() {
                    legacy_total += 1;
                    let matched = state_ref.http_body_entries.iter().any(|(req_body, _)| {
                        rule.http_request_body_patterns.iter().any(|pat| req_body.contains(pat.as_str()))
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
                        rule.http_response_body_patterns.iter().any(|pat| resp_body.contains(pat.as_str()))
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
            
            if legacy_total > 0 && legacy_ratio > 0.0 && legacy_ratio < legacy_threshold && (rule.debug || self.rules.iter().any(|r| r.debug)) {
                Logging::debug(&format!(
                    "[BehaviorEngine] Partial match on rule '{}' for PID {}: {}/{} conditions met ({:.1}% < {:.1}% required)",
                    rule.name, state_ref.pid, legacy_satisfied, legacy_total, legacy_ratio * 100.0, legacy_threshold * 100.0
                ));
            }

            let mut rich_triggered = false;
            if let Some(logic) = &rule.detection_logic {
                rich_triggered = self.evaluate_detection_condition(logic, &state_ref, rule);
            }
            let mut stages_triggered = false;
            let mut stage_conf = 0.0;
            if !rule.stages.is_empty() {
                let (detected, conf) = self.evaluate_stages_from_state(rule, &state_ref, Some(msg));
                stages_triggered = detected;
                stage_conf = conf;
            }

            if legacy_triggered || rich_triggered || stages_triggered {
                let mut prompted_deny = false;
                let mut prompted_block = false;
                let mut prompted_quarantine = false;
                #[cfg(feature = "firewall")]
                if rule.response.ask_user {
                    match self.resolve_firewall_hips_prompt(gid, &state_ref, rule) {
                        FirewallHipsPromptOutcome::Pending | FirewallHipsPromptOutcome::Allowed => {
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

                let trigger_type = if stages_triggered { "Stage-based" }
                                  else if rich_triggered { "Rich-logic" }
                                  else { "Legacy" };

                let indicator_ratio = if stages_triggered { stage_conf }
                                     else if rich_triggered { 1.0 }
                                     else { legacy_ratio };

                Logging::warning(&format!(
                    "[BehaviorEngine] DETECTION ({}) : {} (PID: {}) matched '{}' ({:.1}%)",
                    trigger_type, precord.appname, state_ref.pid, rule.name, indicator_ratio * 100.0
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
                    kill_and_remove: if rule.response.ask_user { false } else { rule.response.kill_and_remove },
                    notify_user: rule.response.notify_user,
                    revert: rule.response.auto_revert,
                };

                // FAIL-FAST SAFETY GUARD: Prevent rule-based termination of critical system processes
                if (threat_info.terminate || threat_info.quarantine || threat_info.kill_and_remove)
                    && let Some(reason) = crate::utils::protected_process_record_reason(precord) {
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
                self.process_terminated.insert(precord.appname.to_lowercase());

                if threat_info.terminate {
                    break;
                }
            }
        }
    }
    
    fn evaluate_stages_from_state(
        &self,
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>
    ) -> (bool, f32) {
        let mut satisfied_stages = 0;
        
        for stage in &rule.stages {
            let mut stage_satisfied_count = 0;
            let mut stage_total_conditions = 0;
            
            for condition in &stage.conditions {
                stage_total_conditions += 1;
                let mut condition_matched = false;
                
                match condition {
                    RuleCondition::OperationCount { op_type, comparison, threshold, .. } => {
                        let count = state.irp_stats.get_operation_count(op_type);
                        condition_matched = match comparison {
                            Comparison::Gt => count > *threshold,
                            Comparison::Gte => count >= *threshold,
                            Comparison::Lt => count < *threshold,
                            Comparison::Lte => count <= *threshold,
                            Comparison::Eq => count == *threshold,
                            Comparison::Ne => count != *threshold,
                        };
                    },
                    
                    RuleCondition::ByteThreshold { direction, comparison, threshold } => {
                        let bytes = match direction.as_str() {
                            "read" => state.irp_stats.total_bytes_read,
                            "write" => state.irp_stats.total_bytes_written,
                            _ => 0,
                        };
                        condition_matched = match comparison {
                            Comparison::Gt => bytes > *threshold,
                            Comparison::Gte => bytes >= *threshold,
                            Comparison::Lt => bytes < *threshold,
                            Comparison::Lte => bytes <= *threshold,
                            Comparison::Eq => bytes == *threshold,
                            Comparison::Ne => bytes != *threshold,
                        };
                    },
                    
                    RuleCondition::File { op, path_pattern } => {
                        let has_match = match op.as_str() {
                            "write" | "create" => {
                                state.irp_stats.unique_paths_accessed.iter().any(|path| {
                                    Self::matches_pattern_internal(&self.regex_cache, path_pattern, path)
                                })
                            },
                            "read" => {
                                state.irp_stats.unique_paths_accessed.iter().any(|path| {
                                    Self::matches_pattern_internal(&self.regex_cache, path_pattern, path)
                                })
                            },
                            _ => false,
                        };
                        condition_matched = has_match;
                    },
                    
                    RuleCondition::EntropyThreshold { comparison, threshold, .. } => {
                        if let Some(m) = msg {
                            let entropy = m.entropy;
                            condition_matched = match comparison {
                                Comparison::Gt => entropy > *threshold,
                                Comparison::Gte => entropy >= *threshold,
                                Comparison::Lt => entropy < *threshold,
                                Comparison::Lte => entropy <= *threshold,
                                Comparison::Eq => (entropy - threshold).abs() < 0.001,
                                Comparison::Ne => (entropy - threshold).abs() >= 0.001,
                            };
                        }
                    },
                    
                    RuleCondition::NetworkCondition(net_rule) => {
                        if let Some(_m) = msg {
                            // We don't have the full packet buffer here, only what's in IOMessage.
                            // However, we can construct a temporary PacketInfo if needed, or check
                            // if there's a recent packet in state.net_packets that matches.
                            condition_matched = state.net_packets.iter().any(|pkt| {
                                net_rule.matches_packet(&self.regex_cache, pkt, &[])
                            });
                        }
                    },
                    
                    _ => condition_matched = false,
                }
                
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
        let args: &[String] = if tokens.len() > 1 { &tokens[1..] } else { return None; };

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
            n if n == "mshta.exe" => {
                args.first()
                    .filter(|a| !a.starts_with('/') && a.contains('.'))
                    .cloned()
            }

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
            n if n == "regsvr32.exe" => {
                args.iter()
                    .find(|a| {
                        let l = a.to_lowercase();
                        !l.starts_with('/') && (l.ends_with(".dll") || l.ends_with(".ocx"))
                    })
                    .cloned()
            }

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
            n if matches!(n,
                "python.exe" | "python3.exe" | "node.exe" | "node" |
                "ruby.exe" | "perl.exe" | "php.exe" | "bash.exe" |
                "sh.exe" | "lua.exe" | "rscript.exe" | "julia.exe"
            ) => {
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
        let names_to_check: &[&str] = &[
            proc_name,
            script_file.unwrap_or(""),
        ];
        names_to_check.iter().any(|name| {
            if name.is_empty() { return false; }
            let proc_lc = name.to_lowercase();
            rule.allowlisted_apps.iter().any(|entry| {
                match entry {
                    AllowlistEntry::Simple(pattern) => proc_lc.contains(&pattern.to_lowercase()),
                    AllowlistEntry::Complex { pattern, signers, must_be_signed, is_absolute } => {
                        let pat_lc = pattern.to_lowercase();
                        let mut name_matched = proc_lc.contains(&pat_lc) || pat_lc.contains(&proc_lc);
                        
                        if *is_absolute {
                            if let Some(path) = process_path {
                                let path_str = path.to_string_lossy().to_lowercase().replace("\\", "/");
                                let pat_norm = pat_lc.replace("\\", "/");
                                if !matches_pattern(&self.regex_cache, &pat_norm, &path_str) {
                                    name_matched = false;
                                }
                            } else {
                                name_matched = false;
                            }
                        }

                        if !name_matched { return false; }

                        if !must_be_signed && signers.is_empty() { 
                            return true; 
                        }
                        if let Some(path) = process_path {
                            if !path.exists() { return false; }
                            let info = verify_signature(path);

                            // Strict requirement: must be signed by one of the specified signers
                            // if the rule engine says it's a mandatory vendor check.
                            if *must_be_signed && !info.is_trusted { 
                                return false; 
                            }
                            if !signers.is_empty() {
                                if let Some(signer) = &info.signer_name {
                                    signers.iter().any(|s_pattern| 
                                        Self::matches_pattern_internal(&self.regex_cache, s_pattern, signer)
                                    )
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

    fn matches_pattern_internal(cache: &Arc<RwLock<HashMap<String, Regex>>>, pattern: &str, text: &str) -> bool {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return false;
        }

        let has_glob = trimmed.contains('*') || trimmed.contains('?');
        let is_explicit_regex = trimmed.starts_with("(?")
            || trimmed.starts_with('^')
            || trimmed.ends_with('$');

        if !has_glob && !is_explicit_regex {
            return text.to_lowercase().contains(&trimmed.to_lowercase());
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
            Err(_) => {
                text.to_lowercase().contains(&trimmed.to_lowercase())
            }
        }
    }
    
    /// Network activity detection — delegates entirely to the firewall.
    /// Returns true if the firewall has observed real outbound I/O for this PID.
    fn has_network_activity(&self, state: &ProcessBehaviorState) -> bool {
        #[cfg(feature = "firewall")]
        {
            // Authoritative: firewall observed real outbound network I/O for this PID.
            self.firewall_net_pids.read().unwrap().contains(&state.pid)
        }
        #[cfg(not(feature = "firewall"))]
        {
            false
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

        let description = msg.kernel_event_info.object_name.clone();

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
            if let Some(state) = self.process_states.values_mut().find(|s| s.pid == finding.pid) {
                state.rootkit_implicated = true;
                Logging::warning(&format!(
                    "[ROOTKIT] Hidden process PID {} ({}) is rootkit-implicated",
                    finding.pid, state.app_name
                ));
            }
        }
    }

    #[allow(dead_code)]
    pub fn scan_all_processes(&mut self, _config: &Config, _threat_handler: &dyn ThreatHandler) -> Vec<ProcessRecord> {
        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();

        // Snapshot firewall-confirmed malicious exe paths once per scan cycle
        #[cfg(feature = "firewall")]
        let fw_blocked: HashMap<String, FirewallDetection> = self.firewall_blocked_exes.read().unwrap().clone();

        for gid in gids {
            let state = match self.process_states.get(&gid) {
                Some(s) => s.clone(),
                None => continue,
            };

            if state.pid == 0 {
                continue;
            }

            let pid = state.pid;
            let app_name = state.app_name.clone();
            let exe_path_buf = state.exe_path.clone();
            let exe_path_str = exe_path_buf.to_string_lossy().to_string();

            // Firewall-confirmed malicious network traffic: act immediately,
            // bypass the normal rule evaluation loop entirely.
            #[cfg(feature = "firewall")]
            if !exe_path_str.is_empty() && exe_path_str.to_lowercase() != "unknown"
                && let Some(detection) = fw_blocked.get(&exe_path_str.to_lowercase()) {
                    let mut p = ProcessRecord::new(
                        gid,
                        app_name.clone(),
                        exe_path_buf.clone(),
                    );
                    p.is_malicious = true;
                    p.pids.insert(pid);
                    p.termination_requested = true;
                    p.notify_user_requested = true;
                    p.triggered_rule_name = Some(detection.threat_type_label().to_string());
                    p.triggered_rule_details = Some(detection.match_details());
                    Logging::warning(&format!(
                        "[FirewallPipe] Acting on firewall-confirmed malicious exe: {} (PID {}) — {}",
                        exe_path_str, pid, detection.match_details()
                    ));
                    detected_processes.push(p);
                    continue;
                }

            // Log Nt API activity summary if any events detected
            if state.hypervisor_events_total > 0 {
                Logging::info(&format!(
                    "[API HOOKING SUMMARY] PID {} ({}) - Total fallback events: {}",
                    pid, app_name,
                    state.hypervisor_events_total
                ));
                
                if state.irp_stats.has_injection_indicators() {
                    Logging::warning(&format!(
                        "[API HOOKING PATTERN] PID {} ({}) shows API hooking activity - Total fallback events: {}",
                        pid, app_name, state.irp_stats.get_injection_api_count()
                    ));
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

                let mut legacy_triggered = false;
                let mut rich_triggered = false;
                let mut stages_triggered = false;

                if !rule.browsed_paths.is_empty() && state.browsed_paths_tracker.len() >= rule.multi_access_threshold {
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
                            FirewallHipsPromptOutcome::Pending | FirewallHipsPromptOutcome::Allowed => {
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

                    let mut p = ProcessRecord::new(
                        gid,
                        app_name.clone(),
                        exe_path_str.clone().into(),
                    );
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
                    p.kill_and_remove_requested = if rule.response.ask_user { false } else { rule.response.kill_and_remove };
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
                    p.remediation_target_path = Self::build_rule_remediation_target_path(rule, &state);
                    detected_processes.push(p);
                }
            }
        }

        detected_processes
    }
}
