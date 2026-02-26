use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_yaml;
use serde_yaml::Value as YamlValue;
use regex::Regex;
use std::cell::RefCell;

use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp, kernel_raw_event_name};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::config::Config;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::extensions::ExtensionList;
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::threat_handler::ThreatHandler;
use crate::signature_verification::verify_signature;

use sysinfo::{System, ProcessRefreshKind, ProcessesToUpdate};
use num::FromPrimitive;

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
            
            // Hypervisor/kernel events are tracked as one fallback class.
            IrpMajorOp::IrpHypervisorEvent => {
                self.hypervisor_event_count += 1;
                let event_name = if rec.function_name.is_empty() {
                    kernel_raw_event_name(rec.irp_type as u32)
                        .map(|name| name.to_string())
                        .unwrap_or_else(|| "IRP_HYPERVISOR_EVENT".to_string())
                } else {
                    rec.function_name.clone()
                };
                let details = if rec.function_name.is_empty() {
                    "Hypervisor Event".to_string()
                } else {
                    format!("Hypervisor Event (raw_name={})", rec.function_name)
                };
                self.record_hypervisor_event_operation(
                    rec,
                    IrpMajorOp::IrpHypervisorEvent,
                    &details,
                );
                self.all_apis_called.insert(event_name);
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
    
    /// Get total count of normalized hypervisor events.
    pub fn get_injection_api_count(&self) -> u64 {
        self.hypervisor_event_count
    }
    
    /// Check if process has any hypervisor event activity.
    pub fn has_injection_indicators(&self) -> bool {
        self.hypervisor_event_count > 0
    }
}

// GLOBAL PROTECTED/EXCLUDED PATHS
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtectedPaths {
    /// File system paths to exclude
    #[serde(default)]
    pub file_paths: Vec<String>,
    
    /// Registry paths to exclude
    #[serde(default)]
    pub registry_paths: Vec<String>,
}

impl ProtectedPaths {
    /// Check if a file path is protected
    pub fn is_file_path_protected(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        self.file_paths.iter().any(|p| {
            let p_lower = p.to_lowercase();
            path_lower.contains(&p_lower)
        })
    }
    
    /// Check if a registry path is protected
    pub fn is_registry_path_protected(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        self.registry_paths.iter().any(|p| {
            let p_lower = p.to_lowercase();
            path_lower.contains(&p_lower)
        })
    }
}

// =============================================================================
// ENUMS AND BASIC TYPES
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Comparison {
    Gt, Gte, Lt, Lte, Eq, Ne,
}

impl Default for Comparison {
    fn default() -> Self { Comparison::Gte }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    All, Any, Count(usize),
    #[serde(rename = "at_least")]
    AtLeast(usize),
}

impl Default for MatchMode {
    fn default() -> Self { MatchMode::Any }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StringModifier {
    Nocase, Contains, Startswith, Endswith, Re, Base64, Not,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PatternSpec {
    Simple(String),
    Complex {
        pattern: String,
        #[serde(default)]
        modifiers: Vec<StringModifier>,
    },
}

impl PatternSpec {
    pub fn pattern(&self) -> &str {
        match self {
            PatternSpec::Simple(p) => p,
            PatternSpec::Complex { pattern, .. } => pattern,
        }
    }
    
    pub fn modifiers(&self) -> &[StringModifier] {
        match self {
            PatternSpec::Simple(_) => &[],
            PatternSpec::Complex { modifiers, .. } => modifiers,
        }
    }
    
    pub fn has_modifier(&self, modifier: &StringModifier) -> bool {
        self.modifiers().iter().any(|m| std::mem::discriminant(m) == std::mem::discriminant(modifier))
    }
    
    pub fn is_case_insensitive(&self) -> bool {
        self.has_modifier(&StringModifier::Nocase)
    }
    
    pub fn is_regex(&self) -> bool {
        self.has_modifier(&StringModifier::Re)
    }
    
    pub fn is_contains(&self) -> bool {
        self.has_modifier(&StringModifier::Contains)
    }
    
    pub fn is_startswith(&self) -> bool {
        self.has_modifier(&StringModifier::Startswith)
    }
    
    pub fn is_endswith(&self) -> bool {
        self.has_modifier(&StringModifier::Endswith)
    }
    
    pub fn is_negated(&self) -> bool {
        self.has_modifier(&StringModifier::Not)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLinePattern {
    pub pattern: String,
    #[serde(default)]
    pub modifiers: Vec<StringModifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    #[default]
    Stable,
    Experimental,
    Test,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DetectionLevel {
    Informational,
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub category: String,
    #[serde(default)]
    pub product: Option<String>,
}

fn default_severity() -> u8 { 50 }
fn default_zero() -> usize { 0 }

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
    if p_trim_lc.starts_with("harddiskvolume") {
        if let Some(idx) = p_trim.find('/') {
            let remainder = &p_trim[idx + 1..];
            if !remainder.is_empty() {
                return remainder.to_string();
            }
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
        variants.insert(strip_drive_prefix(norm_path));
    }
    if !raw_path.is_empty() {
        let raw_norm = raw_path.to_lowercase().replace("\\", "/");
        variants.insert(raw_norm.clone());
        variants.insert(strip_drive_prefix(&raw_norm));
    }
    variants.into_iter().filter(|v| !v.is_empty()).collect()
}

fn normalize_hypervisor_api_label(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    if let Some(idx) = value.find(" (syscall=0x") {
        value.truncate(idx);
    }
    value.trim().to_string()
}

fn api_function_alias(raw: &str) -> Option<String> {
    let normalized = normalize_hypervisor_api_label(raw);
    if normalized.is_empty() {
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
// RICH CONDITION SYSTEM
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NamedConditionGroup {
    #[serde(default)]
    pub apis: Vec<String>,
    #[serde(default = "default_zero")]
    pub api_threshold: usize,
    
    #[serde(default)]
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub file_operations: Vec<String>,
    #[serde(default)]
    pub require_same_file_read: bool,
    #[serde(default)]
    pub require_same_file_write: bool,
    #[serde(default)]
    pub require_same_file_rename: bool,
    
    #[serde(default)]
    pub registry_keys: Vec<String>,
    #[serde(default)]
    pub registry_values: Vec<String>,
    #[serde(default)]
    pub registry_operations: Vec<String>,
    
    #[serde(default)]
    pub network_indicators: Vec<String>,
    #[serde(default)]
    pub network_domains: Vec<String>,
    #[serde(default)]
    pub network_ips: Vec<String>,
    #[serde(default)]
    pub has_network_activity: bool,
    
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub parent_names: Vec<String>,
    #[serde(default)]
    pub terminated_processes: Vec<String>,
    #[serde(default)]
    pub created_processes: Vec<String>,
    #[serde(default)]
    pub detect_self_termination: bool,
    
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub detect_extension_changes: bool,
    #[serde(default)]
    pub detect_known_to_unknown_extension_change: bool,
    #[serde(default, alias = "extension_allowlist")]
    pub extension_whitelist: Vec<String>,
    #[serde(default, alias = "detect_non_allowlisted_extensions")]
    pub detect_non_whitelisted_extensions: bool,
    #[serde(default)]
    pub file_actions: Vec<String>,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub file_size_min: Option<u64>,
    #[serde(default)]
    pub file_size_max: Option<u64>,
    
    #[serde(default)]
    pub cmdline_patterns: Vec<CommandLinePattern>,
    #[serde(default)]
    pub cmdline_keywords: Vec<String>,
    
    #[serde(default)]
    pub staging_paths: Vec<String>,
    #[serde(default)]
    pub browsed_paths: Vec<String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    #[serde(default)]
    pub temp_writes: bool,

    #[serde(default)]
    pub persistence_locations: Vec<String>,
    #[serde(default)]
    pub autorun_keys: Vec<String>,
    #[serde(default)]
    pub scheduled_task_apis: Vec<String>,
    
    #[serde(default)]
    pub obfuscation_indicators: Vec<String>,
    #[serde(default)]
    pub anti_debug_apis: Vec<String>,
    #[serde(default)]
    pub anti_vm_apis: Vec<String>,
    
    #[serde(default)]
    pub requires_signed: Option<bool>,
    #[serde(default)]
    pub is_signed: Option<bool>,        
    #[serde(default)]
    pub is_valid_signed: Option<bool>,  
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default)]
    pub untrusted_signers: Vec<String>,
    
    // Hypervisor event tracking (single normalized opcode path)
    #[serde(default)]
    pub hypervisor_event_labels: Vec<String>,
    #[serde(default)]
    pub detect_hypervisor_event: bool,
    #[serde(default)]
    pub hypervisor_event_threshold: usize,

    // Detailed hypervisor payload filtering
    #[serde(default)]
    pub hypervisor_raw_event_types: Vec<u32>,
    #[serde(default)]
    pub hypervisor_source_pids: Vec<u32>,
    #[serde(default)]
    pub hypervisor_target_pids: Vec<u32>,
    #[serde(default)]
    pub hypervisor_raw_arg1_values: Vec<u64>,
    #[serde(default)]
    pub hypervisor_raw_arg2_values: Vec<u64>,
    #[serde(default)]
    pub hypervisor_raw_arg1_min: Option<u64>,
    #[serde(default)]
    pub hypervisor_raw_arg1_max: Option<u64>,
    #[serde(default)]
    pub hypervisor_raw_arg2_min: Option<u64>,
    #[serde(default)]
    pub hypervisor_raw_arg2_max: Option<u64>,
    #[serde(default)]
    pub hypervisor_memory_addresses: Vec<u64>,
    #[serde(default)]
    pub hypervisor_memory_address_min: Option<u64>,
    #[serde(default)]
    pub hypervisor_memory_address_max: Option<u64>,
    #[serde(default)]
    pub hypervisor_memory_sizes: Vec<u64>,
    #[serde(default)]
    pub hypervisor_memory_size_min: Option<u64>,
    #[serde(default)]
    pub hypervisor_memory_size_max: Option<u64>,
    #[serde(default)]
    pub hypervisor_memory_protections: Vec<u32>,
    #[serde(default)]
    pub hypervisor_is_executable_memory: Option<bool>,
    #[serde(default)]
    pub hypervisor_thread_handles: Vec<u64>,
    #[serde(default)]
    pub hypervisor_thread_start_routines: Vec<u64>,
    #[serde(default)]
    pub hypervisor_access_masks: Vec<u32>,
    #[serde(default)]
    pub hypervisor_operation_statuses: Vec<i32>,
    
    #[serde(default = "default_zero")]
    pub min_matches: usize,
    #[serde(default)]
    pub min_files_accessed: Option<usize>,
    #[serde(default)]
    pub min_directories_accessed: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetectionCondition {
    And { and: Vec<DetectionCondition> },
    Or { or: Vec<DetectionCondition> },
    Not { not: Box<DetectionCondition> },
    Named { condition: String },
    AllOf { all_of: Vec<String> },
    AnyOf { any_of: Vec<String> },
    NOf { n_of: usize, conditions: Vec<String> },
    AtLeast { at_least: usize, conditions: Vec<String> },
    AllOfPattern { all_of_pattern: String },
    AnyOfPattern { any_of_pattern: String },
    Count { count: Vec<String>, #[serde(default)] comparison: Comparison, threshold: usize },
    Percentage { percentage: Vec<String>, #[serde(default)] comparison: Comparison, threshold: f32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    File { op: String, path_pattern: String },
    Registry { op: String, key_pattern: String, value_name: Option<String>, expected_data: Option<String> },
    Process { op: String, pattern: String },
    Service { op: String, name_pattern: String },
    Network { op: String, dest_pattern: Option<String> },
    Api { name_pattern: String, module_pattern: String },
    Heuristic { metric: String, threshold: f64 },
    OperationCount { op_type: String, #[serde(default)] path_pattern: Option<String>, #[serde(default)] comparison: Comparison, threshold: u64 },
    ExtensionPattern { patterns: Vec<String>, #[serde(default)] match_mode: MatchMode, op_type: String },
    ByteThreshold { direction: String, #[serde(default)] comparison: Comparison, threshold: u64 },
    EntropyThreshold { metric: String, #[serde(default)] comparison: Comparison, threshold: f64 },
    FileCount { category: String, #[serde(default)] comparison: Comparison, threshold: u64 },
    Signature { 
        #[serde(default)]
        is_trusted: Option<bool>,  
        #[serde(default)]
        is_signed: Option<bool>,   
        #[serde(default)]
        signer_pattern: Option<String> 
    },
    DirectorySpread { category: String, #[serde(default)] comparison: Comparison, threshold: u64 },
    DriveActivity { drive_type: String, op_type: String, #[serde(default)] comparison: Comparison, threshold: u32 },
    ProcessAncestry { ancestor_pattern: String, #[serde(default)] max_depth: Option<u32> },
    ExtensionRatio { extensions: Vec<String>, #[serde(default)] comparison: Comparison, threshold: f32 },
    RateOfChange { metric: String, #[serde(default)] comparison: Comparison, threshold: f64 },
    SelfModification { modification_type: String },
    CommandLineMatch { patterns: Vec<CommandLinePattern>, #[serde(default)] match_mode: MatchMode },
    SensitivePathAccess { patterns: Vec<String>, op_type: String, #[serde(default)] min_unique_paths: Option<u32> },
    ClusterPattern { #[serde(default)] min_clusters: Option<usize>, #[serde(default)] max_clusters: Option<usize> },
    TempDirectoryWrite { #[serde(default)] min_bytes: Option<u64>, #[serde(default)] min_files: Option<u32> },
    ArchiveCreation { #[serde(default)] extensions: Vec<String>, #[serde(default)] min_size: Option<u64>, #[serde(default)] in_temp: bool },
    DataExfiltrationPattern { source_patterns: Vec<String>, #[serde(default)] min_source_reads: Option<u32>, #[serde(default)] detect_temp_staging: bool, #[serde(default)] detect_archive: bool },
    MemoryScan { #[serde(default)] patterns: Vec<String>, #[serde(default)] detect_pe_headers: bool, #[serde(default)] private_only: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub name: String,
    pub conditions: Vec<RuleCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleMapping {
    And { and: Vec<RuleMapping> },
    Or { or: Vec<RuleMapping> },
    Not { not: Box<RuleMapping> },
    Stage { stage: String },
}

// =============================================================================
// BEHAVIOR RULE
// =============================================================================

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    
    #[serde(default)]
    pub browsed_paths: Vec<String>,
    #[serde(default)]
    pub accessed_paths: Vec<String>,
    #[serde(default)]
    pub staging_paths: Vec<String>,
    #[serde(default = "default_zero")]
    pub multi_access_threshold: usize,
    #[serde(default)]
    pub require_internet: bool,
    #[serde(default)]
    pub monitored_apis: Vec<String>,
    #[serde(default)]
    pub file_actions: Vec<String>,
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub suspicious_parents: Vec<String>,
    #[serde(default)]
    pub terminated_processes: Vec<String>,
    #[serde(default)]
    pub detect_self_termination: bool,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub conditions_percentage: f32,
    
    #[serde(default)]
    pub named_conditions: HashMap<String, NamedConditionGroup>,
    #[serde(default)]
    pub detection_logic: Option<DetectionCondition>,
    
    #[serde(default)]
    pub stages: Vec<AttackStage>,
    #[serde(default)]
    pub mapping: Option<RuleMapping>,
    #[serde(default)]
    pub min_stages_satisfied: usize,
    
    #[serde(default)]
    pub conditions: Option<YamlValue>,
    #[serde(default)]
    pub private_rules: Option<YamlValue>,
    #[serde(default = "default_severity")]
    pub severity: u8,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub status: RuleStatus,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub false_positives: Vec<String>,
    #[serde(default)]
    pub level: DetectionLevel,
    #[serde(default)]
    pub mitre_attack: Vec<String>,
    #[serde(default)]
    pub logsource: Option<LogSource>,
    
    #[serde(default)]
    pub response: ResponseAction,
    #[serde(default)]
    pub is_private: bool,
    
    #[serde(default)]
    pub allowlisted_apps: Vec<AllowlistEntry>,
    
    #[serde(default)]
    pub proximity_log_threshold: f32,
    #[serde(default)]
    pub record_on_start: Vec<String>,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub memory_scan_config: Option<MemoryScanConfig>,
    #[serde(default)]
    pub min_indicator_count: Option<usize>,
    
    // Global protected/excluded paths
    #[serde(default)]
    pub protected_paths: ProtectedPaths,
}

fn expand_environment_variables(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let re = match Regex::new(r"%([^%]+)%") {
        Ok(r) => r,
        Err(_) => return text.to_string(),
    };
    re.replace_all(text, |caps: &regex::Captures| {
        let var_name = &caps[1].to_uppercase();
        match std::env::var(var_name) {
            Ok(val) => val,
            Err(_) => caps[0].to_string()
        }
    }).to_string()
}

impl BehaviorRule {
    pub fn finalize_rich_fields(&mut self) {
        let expand_vec = |vec: &mut Vec<String>| {
            for item in vec.iter_mut() {
                *item = expand_environment_variables(item);
            }
        };
        let expand_opt_string = |opt: &mut Option<String>| {
            if let Some(s) = opt {
                *s = expand_environment_variables(s);
            }
        };
        let expand_cmd_patterns = |patterns: &mut Vec<CommandLinePattern>| {
            for p in patterns.iter_mut() {
                p.pattern = expand_environment_variables(&p.pattern);
            }
        };

        expand_vec(&mut self.browsed_paths);
        expand_vec(&mut self.accessed_paths);
        expand_vec(&mut self.staging_paths);
        expand_vec(&mut self.monitored_apis);
        expand_vec(&mut self.file_actions);
        expand_vec(&mut self.file_extensions);
        expand_vec(&mut self.suspicious_parents);
        expand_vec(&mut self.terminated_processes);
        expand_vec(&mut self.false_positives);

        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = expand_environment_variables(s),
                AllowlistEntry::Complex { pattern, signers, .. } => {
                    *pattern = expand_environment_variables(pattern);
                    expand_vec(signers);
                }
            }
        }

        for (_, cond_group) in &mut self.named_conditions {
            expand_vec(&mut cond_group.apis);
            expand_vec(&mut cond_group.file_paths);
            expand_vec(&mut cond_group.registry_keys);
            expand_vec(&mut cond_group.registry_values);
            expand_vec(&mut cond_group.network_indicators);
            expand_vec(&mut cond_group.network_domains);
            expand_vec(&mut cond_group.network_ips);
            expand_vec(&mut cond_group.process_names);
            expand_vec(&mut cond_group.parent_names);
            expand_vec(&mut cond_group.terminated_processes);
            expand_vec(&mut cond_group.created_processes);
            expand_vec(&mut cond_group.file_extensions);
            expand_vec(&mut cond_group.extension_whitelist);
            expand_vec(&mut cond_group.file_actions);
            expand_cmd_patterns(&mut cond_group.cmdline_patterns);
            expand_vec(&mut cond_group.cmdline_keywords);
            expand_vec(&mut cond_group.staging_paths);
            expand_vec(&mut cond_group.browsed_paths);
            expand_vec(&mut cond_group.sensitive_paths);
            expand_vec(&mut cond_group.persistence_locations);
            expand_vec(&mut cond_group.autorun_keys);
            expand_vec(&mut cond_group.scheduled_task_apis);
            expand_vec(&mut cond_group.obfuscation_indicators);
            expand_vec(&mut cond_group.anti_debug_apis);
            expand_vec(&mut cond_group.anti_vm_apis);
            expand_vec(&mut cond_group.trusted_signers);
            expand_vec(&mut cond_group.untrusted_signers);
            
            // Expand normalized hypervisor event labels
            expand_vec(&mut cond_group.hypervisor_event_labels);
        }

        for stage in &mut self.stages {
            for condition in &mut stage.conditions {
                match condition {
                    RuleCondition::File { path_pattern, .. } => *path_pattern = expand_environment_variables(path_pattern),
                    RuleCondition::Registry { key_pattern, value_name, expected_data, .. } => {
                        *key_pattern = expand_environment_variables(key_pattern);
                        expand_opt_string(value_name);
                        expand_opt_string(expected_data);
                    },
                    RuleCondition::Process { pattern, .. } => *pattern = expand_environment_variables(pattern),
                    RuleCondition::Service { name_pattern, .. } => *name_pattern = expand_environment_variables(name_pattern),
                    RuleCondition::Network { dest_pattern, .. } => expand_opt_string(dest_pattern),
                    RuleCondition::Api { name_pattern, module_pattern } => {
                        *name_pattern = expand_environment_variables(name_pattern);
                        *module_pattern = expand_environment_variables(module_pattern);
                    },
                    RuleCondition::OperationCount { path_pattern, .. } => expand_opt_string(path_pattern),
                    RuleCondition::ExtensionPattern { patterns, .. } => expand_vec(patterns),
                    RuleCondition::Signature { signer_pattern, .. } => expand_opt_string(signer_pattern),
                    RuleCondition::ProcessAncestry { ancestor_pattern, .. } => *ancestor_pattern = expand_environment_variables(ancestor_pattern),
                    RuleCondition::CommandLineMatch { patterns, .. } => expand_cmd_patterns(patterns),
                    RuleCondition::SensitivePathAccess { patterns, .. } => expand_vec(patterns),
                    RuleCondition::ArchiveCreation { extensions, .. } => expand_vec(extensions),
                    RuleCondition::DataExfiltrationPattern { source_patterns, .. } => expand_vec(source_patterns),
                    RuleCondition::MemoryScan { patterns, .. } => expand_vec(patterns),
                    _ => {}
                }
            }
        }

        if let Some(msc) = &mut self.memory_scan_config {
            expand_vec(&mut msc.target_processes);
        }

        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = s.to_lowercase(),
                AllowlistEntry::Complex { pattern, .. } => *pattern = pattern.to_lowercase(),
            }
        }
        
        for (_, cond_group) in &mut self.named_conditions {
            // Keep API names case-preserved so exported symbol hooks resolve correctly in user-mode hook engine.
            cond_group.file_paths = cond_group.file_paths.iter().map(|s| s.to_lowercase()).collect();
            cond_group.registry_keys = cond_group.registry_keys.iter().map(|s| s.to_lowercase()).collect();
            cond_group.process_names = cond_group.process_names.iter().map(|s| s.to_lowercase()).collect();
            cond_group.parent_names = cond_group.parent_names.iter().map(|s| s.to_lowercase()).collect();
            cond_group.file_actions = cond_group.file_actions.iter().map(|s| s.to_lowercase()).collect();
            cond_group.file_operations = cond_group.file_operations.iter().map(|s| s.to_lowercase()).collect();
            cond_group.registry_operations = cond_group.registry_operations.iter().map(|s| s.to_lowercase()).collect();
            cond_group.file_extensions = cond_group.file_extensions.iter().map(|s| s.to_lowercase()).collect();
            cond_group.extension_whitelist = cond_group.extension_whitelist.iter().map(|s| s.to_lowercase()).collect();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanConfig {
    #[serde(default)]
    pub target_processes: Vec<String>,
    #[serde(default)]
    pub scan_on_io_event: bool,
    #[serde(default)]
    pub scan_every_n_ops: u64,
    #[serde(default)]
    pub min_scan_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowlistEntry {
    Simple(String),
    Complex {
        pattern: String,
        #[serde(default)]
        signers: Vec<String>,
        #[serde(default)]
        must_be_signed: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub suspend_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default)] pub kill_and_remove: bool,
    #[serde(default)] pub auto_revert: bool,
    #[serde(default)] pub record: bool,
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

    pub monitored_api_count: usize,
    pub high_entropy_detected: bool,
    pub file_action_detected: bool,
    pub extension_match_detected: bool,
    pub network_activity_detected: bool,
    pub parent_name: String,
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
    pub network_apis_called: HashSet<String>,
    pub all_apis_called: HashSet<String>,
    
    // Normalized hypervisor event tracking
    pub hypervisor_event_count: u32,
    pub hypervisor_events_total: u32,
}

impl ProcessBehaviorState {
    pub fn new(pid: u32, exe_path: PathBuf, app_name: String) -> Self {
        let mut state = ProcessBehaviorState::default();
        state.pid = pid;
        state.exe_path = exe_path;
        state.app_name = app_name;
        state.parent_name = "unknown".to_string();
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
        state.network_apis_called = HashSet::new();
        state.all_apis_called = HashSet::new();
        
        // Initialize normalized hypervisor event counters
        state.hypervisor_event_count = 0;
        state.hypervisor_events_total = 0;
        
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
        let normalized_irp_op = if irp_op >= 12 { 12 } else { irp_op };
        
        if normalized_irp_op == 12 {
            self.hypervisor_event_count += 1;
            let raw_event_type = if msg.kernel_event_info.event_type != 0 {
                msg.kernel_event_info.event_type
            } else {
                irp_op as u32
            };
            let event_name = if normalized_kernel_api.is_empty() {
                kernel_raw_event_name(raw_event_type)
                    .map(|name| name.to_string())
                    .unwrap_or_else(|| format!("RawEventType({raw_event_type})"))
            } else {
                normalized_kernel_api.clone()
            };
            self.detected_apis.insert(event_name.clone());
            self.all_apis_called.insert(event_name.clone());
            if let Some(alias) = api_function_alias(&event_name) {
                self.detected_apis.insert(alias.clone());
                self.all_apis_called.insert(alias);
            }

            Logging::info(&format!(
                "[HYPERVISOR EVENT] opcode=12 raw_event_type={} pid={} src_pid={} target_pid={} arg1=0x{:X} arg2=0x{:X} api=\"{}\" count={}",
                raw_event_type,
                msg.pid,
                msg.kernel_event_info.source_process_id,
                msg.kernel_event_info.target_process_id,
                msg.kernel_event_info.raw_argument1,
                msg.kernel_event_info.raw_argument2,
                event_name,
                self.hypervisor_event_count
            ));
        }

        // Increment total hypervisor events counter and emit activity signal
        if normalized_irp_op == 12 {
            self.hypervisor_events_total += 1;
            
            // Check for hypervisor event activity after each normalized event
            if self.irp_stats.has_injection_indicators() {
                Logging::warning(&format!(
                    "[HYPERVISOR EVENT DETECTED] PID {} - Total fallback events: {}",
                    msg.pid,
                    self.irp_stats.get_injection_api_count()
                ));
            }
        }
        
        // Use incremental drain to prevent blocking: remove 10% when hitting 10k
        if self.irp_operations.len() >= 10000 {
            let remove_count = (self.irp_operations.len() / 10).max(500);
            let _ = self.irp_operations.drain(0..remove_count);
        }
        
        self.irp_operations.push(rec);
    }

    //// TODO: Use Firewall instead of guessing dll loads for better accuracy and coverage of network activity, but this can be a useful heuristic in the meantime
    /// Detect network APIs directly from DLL loading and operation patterns
    pub fn detect_network_apis_from_io(&mut self, msg: &IOMessage) {
        // Detect internet DLLs being loaded
        let path_lower = msg.filepathstr.to_lowercase();
        let ext_lower = msg.extension.to_lowercase();
        
        let internet_dlls = [
            "wininet", "winhttp", "ws2_32", "mswsock", "wsock32", "urlmon"
        ];
        
        for dll in &internet_dlls {
            if path_lower.contains(dll) && ext_lower == "dll" {
                self.network_apis_called.insert(dll.to_string());
                self.all_apis_called.insert(dll.to_string());
            }
        }
    }
}

// =============================================================================
// BEHAVIOR ENGINE
// =============================================================================

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    regex_cache: RefCell<HashMap<String, Regex>>,
    pub process_terminated: HashSet<String>,
    default_extension_whitelist: HashSet<String>,
    system: RefCell<System>,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: RefCell::new(HashMap::new()),
            process_terminated: HashSet::new(),
            default_extension_whitelist: build_default_extension_whitelist(),
            system: RefCell::new(System::new()),
        }
    }

    fn safe_pattern_match(text: &str, pattern: &str) -> bool {
        let text_lc = text.to_lowercase();
        let pattern_lc = pattern.to_lowercase();
        
        if text_lc.is_empty() || pattern_lc.is_empty() || text_lc == "unknown" {
            return false;
        }
        
        text_lc.contains(&pattern_lc) || pattern_lc.contains(&text_lc)
    }

    fn normalize_registry_text(text: &str) -> String {
        normalize_path_separators(&text.to_lowercase())
    }

    fn registry_pattern_matches(cache: &RefCell<HashMap<String, Regex>>, pattern: &str, filepath: &str) -> bool {
        let p = Self::normalize_registry_text(pattern);
        let f = Self::normalize_registry_text(filepath);

        if p.starts_with("hkcu/") || p.starts_with("hkey_current_user/") {
            let remainder = p.splitn(2, '/').nth(1).unwrap_or("");
            if f.contains("/registry/user/") {
                return f.contains(remainder);
            }
        } else if p.starts_with("hku/") || p.starts_with("hkey_users/") {
            let remainder = p.splitn(2, '/').nth(1).unwrap_or("");
            if f.contains("/registry/user/") {
                return f.contains(remainder);
            }
        } else if p.starts_with("hklm/") || p.starts_with("hkey_local_machine/") {
            let remainder = p.splitn(2, '/').nth(1).unwrap_or("");
            if f.contains("/registry/machine/") {
                return f.contains(remainder);
            }
        } else if p.starts_with("hkcc/") || p.starts_with("hkey_current_config/") {
            let remainder = p.splitn(2, '/').nth(1).unwrap_or("");
            if f.contains("/registry/machine/system/currentcontrolset/hardware profiles/current") {
                return f.contains(remainder);
            }
        } else if p.starts_with("hkcr/") || p.starts_with("hkey_classes_root/") {
            let remainder = p.splitn(2, '/').nth(1).unwrap_or("");
            if f.contains("/registry/machine/software/classes/") || f.contains("/registry/user/") {
                return f.contains(remainder);
            }
        }

        Self::matches_pattern_internal(cache, &p, &f)
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
            _ => {
                return true;
            }
        };
        cond_group.registry_operations.iter().any(|v| v == op)
    }

    fn extension_pattern_matches(
        cache: &RefCell<HashMap<String, Regex>>,
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
        cache: &RefCell<HashMap<String, Regex>>,
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
            for (_, cond_group) in &rule.named_conditions {
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

        all_apis
    }

    fn load_rules_recursive(&self, path: &Path) -> Result<Vec<BehaviorRule>, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut rules = Vec::new();

        if content.contains("!include") {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            
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
                                Ok(sub_rules) => rules.extend(sub_rules),
                                Err(e) => Logging::warning(&format!("[EDR] Failed to load include {}: {}", include_path.display(), e)),
                            }
                        }
                    }
                }
            }
            
            let filtered_content: String = content
                .lines()
                .filter(|line| !line.contains("!include"))
                .collect::<Vec<_>>()
                .join("\n");
            
            if !filtered_content.trim().is_empty() && filtered_content.trim() != "---" {
                if let Ok(main_rules) = serde_yaml::from_str::<Vec<BehaviorRule>>(&filtered_content) {
                    rules.extend(self.finalize_rules(main_rules));
                }
            }
        } else {
            let r: Vec<BehaviorRule> = serde_yaml::from_str(&content)?;
            rules.extend(self.finalize_rules(r));
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
            let module_name = module_part.rsplit(['\\', '/']).next().unwrap_or(module_part);
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
        if let Some(min_v) = min {
            if value < min_v {
                return false;
            }
        }
        if let Some(max_v) = max {
            if value > max_v {
                return false;
            }
        }
        true
    }

    fn has_hypervisor_payload_conditions(cond_group: &NamedConditionGroup) -> bool {
        !cond_group.hypervisor_raw_event_types.is_empty()
            || !cond_group.hypervisor_source_pids.is_empty()
            || !cond_group.hypervisor_target_pids.is_empty()
            || !cond_group.hypervisor_raw_arg1_values.is_empty()
            || !cond_group.hypervisor_raw_arg2_values.is_empty()
            || cond_group.hypervisor_raw_arg1_min.is_some()
            || cond_group.hypervisor_raw_arg1_max.is_some()
            || cond_group.hypervisor_raw_arg2_min.is_some()
            || cond_group.hypervisor_raw_arg2_max.is_some()
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
        if *irp_op != IrpMajorOp::IrpHypervisorEvent {
            return false;
        }

        let raw_event_type = if msg.kernel_event_info.event_type != 0 {
            msg.kernel_event_info.event_type
        } else {
            msg.irp_op as u32
        };
        let source_pid = msg.kernel_event_info.source_process_id;
        let target_pid = msg.kernel_event_info.target_process_id;
        let raw_arg1 = msg.kernel_event_info.raw_argument1;
        let raw_arg2 = msg.kernel_event_info.raw_argument2;
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
                .map_or(true, |required| required == is_executable_memory)
            && Self::matches_u64_list(&cond_group.hypervisor_thread_handles, thread_handle)
            && Self::matches_u64_list(
                &cond_group.hypervisor_thread_start_routines,
                thread_start_routine,
            )
            && Self::matches_u32_list(&cond_group.hypervisor_access_masks, access_mask)
            && Self::matches_i32_list(&cond_group.hypervisor_operation_statuses, operation_status)
    }

    fn finalize_rules(&self, raw_rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
        let mut final_rules = Vec::new();
        
        for mut rule in raw_rules {
            rule.finalize_rich_fields();
            
            if let Some(yaml_private) = rule.private_rules.take() {
                if let Ok(private_rules) = serde_yaml::from_value::<Vec<BehaviorRule>>(yaml_private) {
                    let mut processed_private = self.finalize_rules(private_rules);
                    for pr in &mut processed_private {
                        pr.is_private = true;
                    }
                    final_rules.extend(processed_private);
                }
            }
            final_rules.push(rule);
        }
        final_rules
    }

    pub fn register_process(&mut self, gid: u64, pid: u32, exe_path: PathBuf, app_name: String) {
        self.process_states.entry(gid).or_insert_with(|| {
            ProcessBehaviorState::new(pid, exe_path, app_name)
        });
    }

    pub fn load_additional_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(());
        }
        let new_rules = self.load_rules_recursive(path)?;
        self.rules.extend(new_rules);
        Logging::info(&format!("[EDR]: Loaded {} additional rules from {:?}", self.rules.len(), path));
        Ok(())
    }

    // ==========================================================================
    // EVENT DETECTION FROM HYPERVISOR EVENTS
    // ==========================================================================
    
    /// Get actual detected labels from hypervisor events
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
            let mut resolved_appname = precord.appname.clone();
            let mut resolved_exepath = precord.exepath.clone();
            let mut sys_refreshed = false;

            if resolved_appname == "UNKNOWN" || resolved_appname.is_empty() || resolved_appname.starts_with("PROC_") {
                let mut sys = self.system.borrow_mut();
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(msg.pid as u32)]), 
                    false,
                    ProcessRefreshKind::everything()
                );
                sys_refreshed = true;
                
                if let Some(proc) = sys.process(sysinfo::Pid::from_u32(msg.pid as u32)) {
                   resolved_appname = proc.name().to_string_lossy().to_string();
                   if let Some(path) = proc.exe() {
                       resolved_exepath = path.to_path_buf();
                   }
                   precord.appname = resolved_appname.clone();
                   precord.exepath = resolved_exepath.clone();
                   
                   if self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!("[BehaviorEngine] Resolved SELF via sysinfo fallback: PID {} -> {}", msg.pid, resolved_appname));
                   }
                }
            }

            let mut s = ProcessBehaviorState::new(msg.pid as u32, resolved_exepath, resolved_appname);
            if !msg.runtime_features.command_line.trim().is_empty() {
                s.command_line = msg.runtime_features.command_line.to_lowercase();
            }
                        
            let parent_pid = msg.parent_pid as u32;
            let mut parent_found = false;

            for existing_state in self.process_states.values() {
                if existing_state.pid == parent_pid {
                    if !existing_state.app_name.is_empty() {
                        s.parent_name = existing_state.app_name.clone();
                        parent_found = true;
                    }
                    break;
                }
            }

            if !parent_found && parent_pid != 0 {
                let mut sys = self.system.borrow_mut();
                if !sys_refreshed {
                    sys.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(parent_pid)]),
                        false,
                        ProcessRefreshKind::everything()
                    );
                }
                
                if let Some(parent_proc) = sys.process(sysinfo::Pid::from_u32(parent_pid)) {
                    let parent_name_str = parent_proc.name().to_string_lossy().to_string();
                    if !parent_name_str.is_empty() {
                        s.parent_name = parent_name_str;
                        parent_found = true;
                    }
                }
            }

            if !parent_found {
                s.parent_name = "unknown".to_string();
            }
            
            self.process_states.insert(gid, s);
        }
        
        // === STEP 1: RECORD IRP OPERATION ===
        let irp_op_byte = msg.irp_op;
        let irp_op = IrpMajorOp::from_byte(irp_op_byte);
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.record_irp_operation(msg, irp_op_byte);
        }
        
        // === STEP 2: DETECT NETWORK APIs ===
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.detect_network_apis_from_io(msg);
        }
        
        let dev_norm = normalize_device_prefix(&msg.filepathstr);
        let filepath = dev_norm.to_lowercase().replace("\\", "/");
        let norm_filepath = filepath.trim_end_matches('/');
        
        let state = self.process_states.get_mut(&gid).unwrap();
        let pid = state.pid;
        if state.command_line.is_empty() && !msg.runtime_features.command_line.trim().is_empty() {
            state.command_line = msg.runtime_features.command_line.to_lowercase();
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
                let mut sys = self.system.borrow_mut();
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(msg.pid as u32)]),
                    false,
                    ProcessRefreshKind::everything()
                );
                if let Some(proc) = sys.process(sysinfo::Pid::from_u32(msg.pid as u32)) {
                    victim_path = proc.name().to_string_lossy().to_string().to_lowercase();
                }
            }
            
            if msg.attacker_pid != 0 {
                let is_self = msg.attacker_pid == msg.pid;
                let mut attacker_found = false;
                
                if msg.attacker_gid != 0 {
                    if let Some(attacker_state) = self.process_states.get_mut(&msg.attacker_gid) {
                        attacker_found = true;
                        if !victim_path.is_empty() {
                            if is_self {
                                attacker_state.self_terminated_processes.insert(victim_path.clone());
                            } else {
                                attacker_state.terminated_processes.insert(victim_path.clone());
                            }
                        }
                    }
                }

                if !attacker_found && !is_self {
                    let mut resolved_attacker_gid = None;
                    for (gid, state) in &self.process_states {
                        if state.pid == msg.attacker_pid as u32 {
                            resolved_attacker_gid = Some(*gid);
                            break;
                        }
                    }
                    
                    if let Some(agid) = resolved_attacker_gid {
                        if let Some(attacker_state) = self.process_states.get_mut(&agid) {
                            if !victim_path.is_empty() {
                                attacker_state.terminated_processes.insert(victim_path.clone());
                            }
                        }
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
            
            for (_, cond_group) in &rule.named_conditions {
                if let Some(state) = self.process_states.get_mut(&gid) {
                    for path_pattern in &cond_group.file_paths {
                        let norm_pattern = path_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(&norm_pattern) {
                            state.browsed_paths_tracker.insert(path_pattern.clone(), SystemTime::now());
                        }
                    }
                    
                    for staging_pattern in &cond_group.staging_paths {
                        let norm_pattern = staging_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        let is_staging_op = matches!(irp_op, IrpMajorOp::IrpWrite | IrpMajorOp::IrpCreate | IrpMajorOp::IrpSetInfo);
                        if norm_filepath.contains(&norm_pattern) && is_staging_op {
                            state.staged_files_written.insert(PathBuf::from(&filepath), SystemTime::now());
                        }
                    }
                    
                    for browsed_pattern in &cond_group.browsed_paths {
                        let norm_pattern = browsed_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(&norm_pattern) {
                            state.browsed_paths_tracker.insert(browsed_pattern.clone(), SystemTime::now());
                        }
                    }
                    
                    for sensitive_pattern in &cond_group.sensitive_paths {
                        let norm_pattern = sensitive_pattern.to_lowercase().replace("\\", "/");
                        let norm_pattern = norm_pattern.trim_end_matches('/');
                        if norm_filepath.contains(&norm_pattern) {
                            state.accessed_paths_tracker.insert(sensitive_pattern.clone());
                        }
                    }
                }
            }
        }

        // === STEP 7: EVALUATE RULES ===
        self.check_rules(precord, gid, msg, irp_op, config, &mut actions);
    }

    fn update_named_conditions_state(&mut self, precord: &mut ProcessRecord, gid: u64, msg: &IOMessage, irp_op: &IrpMajorOp, filepath: &str) {
        let now = SystemTime::now();
        let mut available_apis = HashSet::new();
        
        let state_detected_apis = if let Some(state) = self.process_states.get(&gid) {
            state.all_apis_called.clone()
        } else {
            HashSet::new()
        };
        
        for api in &state_detected_apis {
            available_apis.insert(api.to_lowercase());
        }
        
        if !state_detected_apis.is_empty() {
            Logging::info(&format!(
                "[BehaviorEngine] Detected APIs for PID {}: {} - {}",
                msg.pid, state_detected_apis.len(), state_detected_apis.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }

        let event_file_change = FromPrimitive::from_u8(msg.file_change);
        let should_lookup_previous_extension = matches!(
            event_file_change,
            Some(FileChangeInfo::ChangeExtensionChanged)
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
                                         !cond_group.hypervisor_event_labels.is_empty() ||
                                         !cond_group.scheduled_task_apis.is_empty() || 
                                         !cond_group.anti_debug_apis.is_empty() || 
                                         !cond_group.anti_vm_apis.is_empty();

                if has_api_conditions {
                    let api_iter = cond_group.apis.iter()
                        .chain(cond_group.hypervisor_event_labels.iter())
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

                if !matched && Self::has_hypervisor_payload_conditions(cond_group) {
                    if Self::matches_hypervisor_payload_conditions(cond_group, msg, irp_op) {
                        let raw_event_type = if msg.kernel_event_info.event_type != 0 {
                            msg.kernel_event_info.event_type
                        } else {
                            msg.irp_op as u32
                        };
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Hypervisor payload match for PID {}: raw_event_type={} src_pid={} target_pid={} arg1=0x{:X} arg2=0x{:X}",
                            cond_name,
                            state.pid,
                            raw_event_type,
                            msg.kernel_event_info.source_process_id,
                            msg.kernel_event_info.target_process_id,
                            msg.kernel_event_info.raw_argument1,
                            msg.kernel_event_info.raw_argument2
                        ));
                    }
                }

                if !matched && cond_group.has_network_activity {
                    if !state.network_apis_called.is_empty() {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Network activity detected for PID {}: {} APIs (legacy DLL tracking)",
                            cond_name, state.pid, state.network_apis_called.len()
                        ));
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
                        && (!cond_group.require_same_file_rename || precord.has_renamed_file_id(&msg.file_id_id));

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

                            if !cond_group.file_extensions.is_empty() {
                                if let Some(matched_ext) = cond_group.file_extensions.iter().find(|p| {
                                    Self::extension_pattern_matches(&self.regex_cache, p, &ext, &ext_with_dot)
                                }) {
                                    matched = true;
                                    Logging::info(&format!(
                                        "[BehaviorEngine] Condition '{}' - Extension match for PID {}: {}",
                                        cond_name, state.pid, matched_ext
                                    ));
                                }
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
                                         !cond_group.registry_values.is_empty();

                if !matched && has_reg_conditions && *irp_op == IrpMajorOp::IrpRegistry {
                    if Self::registry_op_matches(cond_group, msg, irp_op) {
                        let reg_iter = cond_group.registry_keys.iter()
                            .chain(cond_group.autorun_keys.iter());

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
                    }
                }

                if !matched && !cond_group.parent_names.is_empty() {
                    let parent_lc = state.parent_name.to_lowercase();
                    if !parent_lc.is_empty() && parent_lc != "unknown" {
                        if cond_group.parent_names.iter().any(|p| {
                            Self::matches_pattern_internal(&self.regex_cache, p, &parent_lc)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Parent process match for PID {}: {}",
                                cond_name, state.pid, parent_lc
                            ));
                        }
                    }
                }

                if !matched && (!cond_group.cmdline_keywords.is_empty() || !cond_group.cmdline_patterns.is_empty()) {
                    let cmdline_lc = state.command_line.to_lowercase();
                    if !cmdline_lc.is_empty() {
                        let keyword_hit = cond_group.cmdline_keywords.iter().any(|kw| {
                            Self::matches_pattern_internal(&self.regex_cache, kw, &cmdline_lc)
                        });
                        let pattern_hit = cond_group.cmdline_patterns.iter().any(|pat| {
                            Self::matches_pattern_internal(&self.regex_cache, &pat.pattern, &cmdline_lc)
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

                if !matched && !cond_group.terminated_processes.is_empty() {
                    let mut term_match = false;
                    let mut matched_victim = String::new();
                    if *irp_op == IrpMajorOp::IrpProcessTerminateAttempt {
                        if let Some(victim) = cond_group.terminated_processes.iter().find(|victim_pattern| {
                            Self::matches_pattern_internal(&self.regex_cache, victim_pattern, filepath)
                        }) {
                            term_match = true;
                            matched_victim = victim.to_string();
                        }
                    }
                    if !term_match {
                        if let Some(victim) = state.terminated_processes.iter().find(|victim| {
                            cond_group.terminated_processes.iter().any(|victim_pattern| {
                                Self::matches_pattern_internal(&self.regex_cache, victim_pattern, victim)
                            })
                        }) {
                            term_match = true;
                            matched_victim = victim.to_string();
                        }
                    }
                    if term_match {
                        matched = true;
                        Logging::info(&format!(
                            "[BehaviorEngine] Condition '{}' - Process termination match for PID {}: {}",
                            cond_name, state.pid, matched_victim
                        ));
                    }
                }

                if !matched && !cond_group.process_names.is_empty() {
                    let app_lc = state.app_name.to_lowercase();
                    if !app_lc.is_empty() {
                        if cond_group.process_names.iter().any(|p| {
                            Self::matches_pattern_internal(&self.regex_cache, p, &app_lc)
                        }) {
                            matched = true;
                            Logging::info(&format!(
                                "[BehaviorEngine] Condition '{}' - Process name match for PID {}: {}",
                                cond_name, state.pid, app_lc
                            ));
                        }
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
                        "[BehaviorEngine] Condition '{}' - Hypervisor event fallback detected for PID {}: {} events",
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
                    } else if is_new {
                        if rule.debug || self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Condition '{}' match #{}/{} for PID {} ({})",
                                cond_name, *count, required, state.pid, match_key
                            ));
                        }
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
        let state_ref = match self.process_states.get(&gid) {
            Some(s) => s.clone(),
            None => return,
        };

        if precord.is_malicious && precord.time_killed.is_some() {
            return;
        }

        for rule in &self.rules {
            if precord.is_malicious && precord.time_killed.is_some() {
                break;
            }

            // NOTE: Allowlist filtering is intentionally disabled so rules evaluate all processes.

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
                let threat_info = ThreatInfo {
                    threat_type_label: "Behavioral Detection",
                    virus_name: &rule.name,
                    prediction: indicator_ratio,
                    match_details: Some(format!(
                        "Trigger: {}, Ratio: {:.1}%",
                        trigger_type, indicator_ratio * 100.0
                    )),
                    terminate: rule.response.terminate_process,
                    quarantine: rule.response.quarantine,
                    kill_and_remove: rule.response.kill_and_remove,
                    revert: rule.response.auto_revert,
                };

                let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                actions.run_actions_with_info(config, precord, &dummy_pred_mtrx, &threat_info);
                self.process_terminated.insert(precord.appname.to_lowercase());
                
                if rule.response.terminate_process {
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
    
    fn check_allowlist(&self, proc_name: &str, rule: &BehaviorRule, process_path: Option<&Path>) -> bool {
        let proc_lc = proc_name.to_lowercase();
        rule.allowlisted_apps.iter().any(|entry| {
            match entry {
                AllowlistEntry::Simple(pattern) => proc_lc.contains(&pattern.to_lowercase()),
                AllowlistEntry::Complex { pattern, signers, must_be_signed } => {
                    if !proc_lc.contains(&pattern.to_lowercase()) { 
                        return false; 
                    }
                    if !must_be_signed && signers.is_empty() { 
                        return true; 
                    }
                    if let Some(path) = process_path {
                        if !path.exists() { 
                            return false; 
                        }
                        let info = verify_signature(path);
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
    }
    
    fn matches_pattern_internal(cache: &RefCell<HashMap<String, Regex>>, pattern: &str, text: &str) -> bool {
        if !pattern.contains(['*', '?', '[', '\\', '.', '^', '$']) {
            return text.to_lowercase().contains(&pattern.to_lowercase());
        }

        {
            if let Ok(cache_map) = cache.try_borrow() {
                if let Some(re) = cache_map.get(pattern) {
                    return re.is_match(text);
                }
            }
        }

        let mut cache_map = cache.borrow_mut();
        
        if let Some(re) = cache_map.get(pattern) {
            return re.is_match(text);
        }

        let regex_str = if pattern.contains('*') || pattern.contains('?') {
            let escaped = regex::escape(pattern)
                .replace("\\*", ".*")
                .replace("\\?", ".");
            format!("(?i)^{}$", escaped)
        } else {
            format!("(?i){}", pattern)
        };

        match Regex::new(&regex_str) {
            Ok(re) => {
                let is_match = re.is_match(text);
                cache_map.insert(pattern.to_string(), re);
                is_match
            }
            Err(_) => {
                text.to_lowercase().contains(&pattern.to_lowercase())
            }
        }
    }
    
    /// NT-BASED network activity detection
    /// Detects network activity through Nt-observed indicators:
    /// - DLL loads of network modules (ws2_32.dll, winhttp.dll, wininet.dll)
    /// - File operations on URL cache, cookies, network config
    /// - network_apis_called flag from DLL monitoring
    /// - network_activity_detected flag from file system operations
    fn has_network_activity(&self, state: &ProcessBehaviorState) -> bool {
        if !state.network_apis_called.is_empty() {
            return true;
        }
        
        if state.network_activity_detected {
            return true;
        }
        
        let network_modules = ["ws2_32.dll", "winhttp.dll", "wininet.dll", "mswsock.dll", "wsock32.dll"];
        for api in &state.all_apis_called {
            let api_lower = api.to_lowercase();
            if network_modules.iter().any(|m| api_lower.contains(m)) {
                return true;
            }
        }
        
        for path in &state.irp_stats.unique_paths_accessed {
            let path_lower = path.to_lowercase();
            // URL cache, cookies, network config files
            if path_lower.contains("cache") && (path_lower.contains("url") || path_lower.contains("inet") || path_lower.contains("http")) {
                return true;
            }
            if path_lower.contains("cookies") || path_lower.contains("cookie") {
                return true;
            }
            if path_lower.contains("winsock") || path_lower.contains("tcp") || path_lower.contains("dns") {
                return true;
            }
        }
        
        false
    }
        
    pub fn scan_all_processes(&mut self, _config: &Config, _threat_handler: &dyn ThreatHandler) -> Vec<ProcessRecord> {
        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();

        for gid in gids {
            let state = match self.process_states.get(&gid) {
                Some(s) => s.clone(),
                None => continue,
            };

            let pid = state.pid;
            let app_name = state.app_name.clone();
            let exe_path_buf = state.exe_path.clone();
            let exe_path_str = exe_path_buf.to_string_lossy().to_string();

            // Log Nt API activity summary if any events detected
            if state.hypervisor_events_total > 0 {
                Logging::info(&format!(
                    "[HYPERVISOR EVENT SUMMARY] PID {} ({}) - Total fallback events: {}",
                    pid, app_name,
                    state.hypervisor_events_total
                ));
                
                if state.irp_stats.has_injection_indicators() {
                    Logging::warning(&format!(
                        "[HYPERVISOR EVENT PATTERN] PID {} ({}) shows hypervisor event activity - Total fallback events: {}",
                        pid, app_name, state.irp_stats.get_injection_api_count()
                    ));
                }
            }

            for rule in &self.rules {
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
                    let mut p = ProcessRecord::new(
                        gid,
                        app_name.clone(),
                        exe_path_str.clone().into(),
                    );
                    p.is_malicious = true;
                    p.pids.insert(pid);
                    p.termination_requested = rule.response.terminate_process;
                    p.quarantine_requested = rule.response.quarantine;
                    detected_processes.push(p);
                }
            }
        }

        detected_processes
    }
}
