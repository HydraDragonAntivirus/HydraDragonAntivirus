use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use regex::Regex;

// --- EDR Telemetry & Framework ---
use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::{ProcessRecord, ProcessState};
use crate::logging::Logging;
use crate::config::Config;

use sysinfo::{SystemExt, ProcessExt, PidExt};

#[derive(Clone, Debug)]
pub struct TerminatedProcess {
    pub name: String,
    pub timestamp: SystemTime,
}

#[cfg(target_os = "windows")]
use crate::services::ServiceChecker;
#[cfg(target_os = "windows")]
use crate::signature_verification::verify_signature;
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS, MEM_PRIVATE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;

// ============================================================================
// SUPPORTING TYPES FOR TELEMETRY-BASED DETECTION
// ============================================================================

/// Comparison operators for threshold-based conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Comparison {
    Gt,   // >
    Gte,  // >=
    Lt,   // <
    Lte,  // <=
    Eq,   // ==
    Ne,   // !=
}

impl Default for Comparison {
    fn default() -> Self { Comparison::Gte }
}

/// Match mode for pattern collections (YARA-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// All patterns must match
    All,
    /// At least one pattern must match
    Any,
    /// Exactly N patterns must match
    Count(usize),
    /// At least N patterns must match
    #[serde(rename = "at_least")]
    AtLeast(usize),
}

impl Default for MatchMode {
    fn default() -> Self { MatchMode::Any }
}

/// Aggregation functions for time-windowed metrics (Sigma-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregationFunction {
    Count,
    Sum,
    Avg,
    Max,
    Min,
    Rate,  // per-second rate
}

impl Default for AggregationFunction {
    fn default() -> Self { AggregationFunction::Count }
}

/// String modifiers for command line and pattern matching (Sigma-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringModifier {
    /// Case insensitive
    Nocase,
    /// Substring match
    Contains,
    /// Prefix match
    Startswith,
    /// Suffix match
    Endswith,
    /// Regex mode
    Re,
    /// Base64 decode before matching
    Base64,
    /// Negate the match
    Not,
}

/// Command line pattern with optional modifiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLinePattern {
    pub pattern: String,
    #[serde(default)]
    pub modifiers: Vec<StringModifier>,
}

/// Sigma-style rule status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    #[default]
    Stable,
    Experimental,
    Test,
    Deprecated,
}

/// Detection severity level (Sigma-style)
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

/// Sigma-style log source for categorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub category: String,      // "file_event", "registry_event", "process_creation"
    #[serde(default)]
    pub product: Option<String>,
}

/// Operation history entry for time-windowed aggregations
#[derive(Clone, Debug)]
pub struct OpHistoryEntry {
    pub timestamp: SystemTime,
    pub op_type: u8,
    pub file_change: u8,
    pub bytes: u64,
    pub path: String,
    pub extension: String,
}

// ============================================================================
// GENERIC CONFIGURATION STRUCTURES
// ============================================================================

fn default_severity() -> u8 { 50 } // Medium severity by default
fn default_zero() -> usize { 0 }
fn default_zero_f64() -> f64 { 0.0 }
fn default_scan_frequency() -> u64 { 100 }
fn default_one() -> u64 { 1 }
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    pub description: String,

    // --- Stealer Detection Logic (User Snippet) ---
    #[serde(default)] pub browser_paths: Vec<String>,
    #[serde(default)] pub sensitive_files: Vec<String>,
    #[serde(default)] pub staging_paths: Vec<String>,
    #[serde(default = "default_zero")] pub multi_access_threshold: usize,
    #[serde(default)] pub require_internet: bool,
    #[serde(default)] pub crypto_apis: Vec<String>,
    #[serde(default)] pub suspicious_parents: Vec<String>,
    #[serde(default)] pub archive_actions: Vec<String>,
    #[serde(default)] pub max_staging_lifetime_ms: u64,
    #[serde(default)] pub require_browser_closed_recently: bool,
    #[serde(default)] pub entropy_threshold: f64,
    #[serde(default = "default_severity")]
    pub severity: u8,

    // --- Sigma-style Metadata ---
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
    pub mitre_attack: Vec<String>,  // ["T1486", "TA0040"]
    #[serde(default)]
    pub logsource: Option<LogSource>,
    
    // --- Correlation Configuration ---
    #[serde(default)]
    pub stages: Vec<AttackStage>,
    
    #[serde(default)]
    pub mapping: Option<RuleMapping>,

    /// Minimum number of stages that must be satisfied to trigger the rule
    #[serde(default = "default_min_stages")]
    pub min_stages_satisfied: usize,
    
    /// Percentage of conditions within stages that must be met (optional alternative)
    #[serde(default)]
    pub conditions_percentage: f32,
    
    /// Global time window for correlating all stages
    #[serde(default)]
    pub time_window_ms: u64,
    
    #[serde(default)]
    pub response: ResponseAction,

    #[serde(default)]
    pub is_private: bool,

    #[serde(default)]
    pub allowlisted_apps: Vec<AllowlistEntry>,

    /// Specific threshold to log proximity (0.0 - 100.0)
    #[serde(default)]
    pub proximity_log_threshold: f32,

    /// Executable names that should trigger recording immediately upon process start
    #[serde(default)]
    pub record_on_start: Vec<String>,
    
    /// Enable verbose debugging for this rule
    #[serde(default)]
    pub debug: bool,

    /// NEW: Memory scan configuration
    #[serde(default)]
    pub memory_scan_config: Option<MemoryScanConfig>,
}

/// NEW: Configuration for periodic memory scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanConfig {
    /// Process name patterns to scan (supports wildcards)
    #[serde(default)]
    pub target_processes: Vec<String>,
    
    /// Scan on every I/O event for matched processes (expensive!)
    #[serde(default)]
    pub scan_on_io_event: bool,
    
    /// Scan every N operations for matched processes
    #[serde(default = "default_scan_frequency")]
    pub scan_every_n_ops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowlistEntry {
    /// Legacy: Simple string match on process name (e.g., "chrome.exe")
    Simple(String),
    /// Advanced: Customizable allowlist rule
    Complex {
        /// Process name pattern (substring or regex if implemented, historically substring)
        pattern: String,
        /// List of allowed signer patterns (Regex allowed). If empty and `must_be_signed` is true, any trusted signer is allowed.
        #[serde(default)]
        signers: Vec<String>,
        /// If true, process MUST be signed by a trusted root.
        #[serde(default)]
        must_be_signed: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleMapping {
    And { and: Vec<RuleMapping> },
    Or { or: Vec<RuleMapping> },
    Not { not: Box<RuleMapping> },
    Stage { stage: String },
}

fn default_min_stages() -> usize { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub name: String,
    pub conditions: Vec<RuleCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    // === EXISTING CONDITIONS ===
    File {
        op: String, // "Open", "Read", "Write", "Delete", "Rename", "Create"
        path_pattern: String,
    },
    Registry {
        op: String, // "Create", "Delete", "SetValue", "SetSecurity"
        key_pattern: String,
        value_name: Option<String>,
        expected_data: Option<String>,
    },
    Process {
        op: String, // "Spawn", "Terminate", "CommandLine", "Parent"
        pattern: String,
    },
    Service {
        op: String, // "Start", "Stop", "Delete", "Create"
        name_pattern: String,
    },
    Network {
        op: String, // "Connect", "Listen"
        dest_pattern: Option<String>,
    },
    Api {
        name_pattern: String,
        module_pattern: String,
    },
    Heuristic {
        metric: String, // "Entropy"
        threshold: f64,
    },

    // === NEW TELEMETRY-BASED CONDITIONS ===

    /// Count operations matching criteria (YARA-style)
    OperationCount {
        op_type: String,           // "Read", "Write", "Delete", "Rename", "Create", "Registry"
        #[serde(default)]
        path_pattern: Option<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },

    /// Extension pattern matching during operations (behavioral)
    ExtensionPattern {
        /// Match patterns like "*.encrypted", "*.locked", "*.crypto"
        patterns: Vec<String>,
        #[serde(default)]
        match_mode: MatchMode,
        op_type: String,           // "Read", "Write"
    },

    /// Byte transfer thresholds
    ByteThreshold {
        direction: String,         // "read", "write", "total"
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },

    /// Entropy-based detection (Sigma-style)
    EntropyThreshold {
        metric: String,            // "current", "average", "max"
        #[serde(default)]
        comparison: Comparison,
        threshold: f64,
    },

    /// File count thresholds (Sigma-style)
    FileCount {
        category: String,          // "read", "written", "deleted", "renamed", "created"
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },

    /// Digital Signature Verification
    Signature {
        /// If true, requires valid signature. If false, requires invalid/missing signature.
        is_trusted: bool,
        /// Regex pattern for signer name (e.g. "Microsoft.*"). If None, any signer is accepted (if is_trusted=true).
        #[serde(default)]
        signer_pattern: Option<String>,
    },

    /// Directory spread detection (Sigma-style)
    DirectorySpread {
        category: String,          // "created", "updated", "opened"
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },

    /// Time-windowed aggregation (Sigma-style)
    TimeWindowAggregation {
        metric: String,            // "ops_write", "ops_delete", "bytes_written", "files_modified"
        #[serde(default)]
        function: AggregationFunction,
        time_window_ms: u64,
        #[serde(default)]
        comparison: Comparison,
        threshold: f64,
    },

    /// Drive-based detection (removable/network)
    DriveActivity {
        drive_type: String,        // "removable", "network", "any"
        op_type: String,           // "read", "write"
        #[serde(default)]
        comparison: Comparison,
        threshold: u32,
    },

    /// Process ancestry checks
    ProcessAncestry {
        ancestor_pattern: String,
        #[serde(default)]
        max_depth: Option<u32>,
    },

    /// Extension category ratio
    ExtensionRatio {
        /// List of extensions to include in the ratio (e.g., ["doc", "docx", "pdf"])
        extensions: Vec<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: f32,            // percentage 0.0 - 1.0
    },

    /// Rate of change detection
    RateOfChange {
        metric: String,            // "files_per_second", "bytes_per_second", "ops_per_second"
        #[serde(default)]
        comparison: Comparison,
        threshold: f64,
    },

    /// Self-modification detection
    SelfModification {
        modification_type: String, // "exe_deleted", "exe_not_exists"
    },

    /// Extension change velocity
    ExtensionChangeVelocity {
        time_window_ms: u64,
        #[serde(default)]
        comparison: Comparison,
        threshold: u64,
    },

    /// Command line pattern with modifiers
    CommandLineMatch {
        patterns: Vec<CommandLinePattern>,
        #[serde(default)]
        match_mode: MatchMode,
    },

    /// Sensitive path access detection (combined pattern)
    SensitivePathAccess {
        /// Custom patterns to track (e.g., ["*google\\chrome\\user data*", "*mozilla\\firefox\\profiles*"])
        patterns: Vec<String>,
        op_type: String,
        #[serde(default)]
        min_unique_paths: Option<u32>,
    },

    /// Cluster analysis result (for ransomware patterns)
    ClusterPattern {
        #[serde(default)]
        min_clusters: Option<usize>,
        #[serde(default)]
        max_clusters: Option<usize>,
    },

    /// Detect writes to temp directories (data staging for exfiltration)
    TempDirectoryWrite {
        /// Minimum bytes written to temp to trigger
        #[serde(default)]
        min_bytes: Option<u64>,
        /// Minimum unique files written to temp
        #[serde(default)]
        min_files: Option<u32>,
    },

    /// Detect archive file creation/writes (ZIP, RAR, 7z, etc.)
    ArchiveCreation {
        /// Archive extensions to monitor (default: zip, rar, 7z, tar, gz)
        #[serde(default)]
        extensions: Vec<String>,
        /// Minimum archive size in bytes to trigger
        #[serde(default)]
        min_size: Option<u64>,
        /// Must be in temp directory
        #[serde(default)]
        in_temp: bool,
    },

    /// Combined stealer pattern: reads from sensitive paths + writes to temp/archives
    DataExfiltrationPattern {
        /// Sensitive path patterns to watch for reads
        source_patterns: Vec<String>,
        /// Minimum reads from sensitive paths
        #[serde(default)]
        min_source_reads: Option<u32>,
        /// Detect staging to temp directory
        #[serde(default)]
        detect_temp_staging: bool,
        /// Detect archive creation
        #[serde(default)]
        detect_archive: bool,
    },

    /// Detect signatures or PE headers in process memory
    MemoryScan {
        /// Signatures to look for (hex or strings)
        #[serde(default)]
        patterns: Vec<String>,
        /// Detect MZ/PE headers in private/mapped memory
        #[serde(default)]
        detect_pe_headers: bool,
        /// Only scan private/unmapped regions (likely payloads)
        #[serde(default = "default_true")]
        private_only: bool,
    },
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub suspend_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default)] pub auto_revert: bool,
    #[serde(default)] pub record: bool,
}

// ============================================================================
// DYNAMIC STATE ENGINE
// ============================================================================

#[derive(Clone)]
pub struct ProcessBehaviorState {
    pub gid: u64,
    pub pid: u32,
    pub appname: String,
    pub cmdline: String,
    pub parent_name: String,
    
    // --- Stealer Tracking State (User Snippet) ---
    pub accessed_browsers: HashMap<String, SystemTime>,
    pub sensitive_files_read: HashSet<String>,
    pub staged_files_written: HashMap<PathBuf, SystemTime>,
    pub last_browser_close: Option<SystemTime>,
    pub crypto_api_count: usize,
    pub high_entropy_detected: bool,
    pub archive_action_detected: bool,
    
    /// Track satisfied stages: Map<RuleName, Set<StageIndex>>
    pub satisfied_stages: HashMap<String, HashSet<usize>>,
    
    /// Track satisfied conditions: Map<RuleName, Map<StageIndex, Set<ConditionIndex>>>
    pub satisfied_conditions: HashMap<String, HashMap<usize, HashSet<usize>>>,

    pub first_event_ts: Option<SystemTime>,
    pub last_event_ts: SystemTime,

    // --- Existing telemetry caching ---
    pub entropy_max: f64,
    pub entropy_sum: f64,
    pub entropy_count: u64,
    pub active_connections: bool,

    // --- NEW: Time-series tracking for aggregations ---
    pub op_history: Vec<OpHistoryEntry>,
    
    // --- NEW: Rate tracking ---
    pub ops_total: u64,
    pub bytes_total: u64,
    
    // --- NEW: Extension counting ---
    pub extension_changes: u64,
    pub extension_change_timestamps: Vec<SystemTime>,
    
    // --- NEW: Generic state tracking for rule-specified patterns ---
    // Map<(RuleName, StageIdx, ConditionIdx), Set<UniqueValue>>
    pub condition_specific_state: HashMap<String, HashSet<String>>,
    
    // --- NEW: Process ancestry cache ---
    pub process_ancestry: Vec<String>,  // parent names chain

    // --- NEW: Recording & Proximity ---
    pub is_recording: bool,
    pub file_op_counts: HashMap<String, u32>,

    // --- NEW: Last memory scan timestamp ---
    pub last_memory_scan: Option<SystemTime>,
}

impl Default for ProcessBehaviorState {
    fn default() -> Self {
        Self {
            gid: 0,
            pid: 0,
            appname: String::new(),
            cmdline: String::new(),
            parent_name: String::new(),

            accessed_browsers: HashMap::new(),
            sensitive_files_read: HashSet::new(),
            staged_files_written: HashMap::new(),
            last_browser_close: None,
            crypto_api_count: 0,
            high_entropy_detected: false,
            archive_action_detected: false,
            satisfied_stages: HashMap::new(),
            satisfied_conditions: HashMap::new(),
            first_event_ts: None,
            last_event_ts: SystemTime::now(),
            entropy_max: 0.0,
            entropy_sum: 0.0,
            entropy_count: 0,
            active_connections: false,
            op_history: Vec::new(),
            ops_total: 0,
            bytes_total: 0,
            extension_changes: 0,
            extension_change_timestamps: Vec::new(),
            condition_specific_state: HashMap::new(),
            process_ancestry: Vec::new(),
            is_recording: false,
            file_op_counts: HashMap::new(),
            last_memory_scan: None,
        }
    }
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    regex_cache: HashMap<String, Regex>,
    sys: sysinfo::System,
    terminated_processes: Vec<TerminatedProcess>,
    known_pids: HashMap<u32, String>,
    last_refresh: SystemTime,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: HashMap::new(),
            sys: sysinfo::System::new_all(),
            terminated_processes: Vec::new(),
            known_pids: HashMap::new(),
            last_refresh: SystemTime::now(),
        }
    }

    /// Helper to get or create a GID for a PID (for processes not tracked via I/O)
    fn get_or_create_gid_for_pid(&mut self, pid: u32) -> u64 {
        // Try to find existing state by PID
        for (gid, state) in &self.process_states {
            if state.pid == pid {
                return *gid;
            }
        }
        
        // Create new GID (simple approach: use PID as GID for now)
        // In production, you might want a more sophisticated GID generation
        pid as u64
    }

    /// Helper to check if process is allowlisted
    fn is_process_allowlisted(&self, proc_name: &str, rule: &BehaviorRule) -> bool {
        rule.allowlisted_apps.iter().any(|entry| {
            match entry {
                AllowlistEntry::Simple(pattern) => {
                    proc_name.to_lowercase().contains(&pattern.to_lowercase())
                }
                AllowlistEntry::Complex { pattern, signers, must_be_signed } => {
                    // Name check
                    if !proc_name.to_lowercase().contains(&pattern.to_lowercase()) {
                        return false;
                    }

                    // Signature check (simplified for periodic scan)
                    if *must_be_signed || !signers.is_empty() {
                        #[cfg(target_os = "windows")]
                        {
                            // Note: We can't easily get exe path from sysinfo
                            // In a full implementation, you'd need to query the process path
                            // For now, we'll be conservative and allow it
                            return true;
                        }
                        #[cfg(not(target_os = "windows"))]
                        {
                            return false;
                        }
                    }
                    
                    true
                }
            }
        })
    }

    /// Helper to check if rule should trigger
    fn should_rule_trigger(rule: &BehaviorRule, state: &ProcessBehaviorState, terminated_processes: &[TerminatedProcess]) -> bool {
        let now = SystemTime::now();
        
        // 1. Evaluate Stealer-style conditions if any are defined
        let has_stealer_logic = !rule.browser_paths.is_empty() || !rule.staging_paths.is_empty() || rule.require_internet || !rule.crypto_apis.is_empty();
        
        if has_stealer_logic {
            let mut satisfied = 0;
            let mut total = 0;

            // Multi-browser access
            total += 1;
            let recent_access_count = state.accessed_browsers.values()
                .filter(|&&t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < rule.time_window_ms as u128)
                .count();
            if recent_access_count >= rule.multi_access_threshold { satisfied += 1; }

            // Data staging
            total += 1;
            if !state.staged_files_written.is_empty() { satisfied += 1; }

            // Internet connectivity
            total += 1;
            if !rule.require_internet || Self::static_has_active_connections(state.pid) { satisfied += 1; }

            // Suspicious parent
            total += 1;
            let is_suspicious_parent = rule.suspicious_parents.iter().any(|p| state.parent_name.to_lowercase().contains(&p.to_lowercase()));
            if is_suspicious_parent { satisfied += 1; }

            // Sensitive file access
            total += 1;
            if !state.sensitive_files_read.is_empty() { satisfied += 1; }

            // High entropy
            total += 1;
            if state.high_entropy_detected { satisfied += 1; }

            // Crypto usage
            total += 1;
            if state.crypto_api_count > 0 { satisfied += 1; }

            // Archive actions
            total += 1;
            if state.archive_action_detected { satisfied += 1; }

            // Browser state
            if rule.require_browser_closed_recently {
                total += 1;
                let browser_closed_recently = terminated_processes.iter().any(|tp| {
                    (tp.name.to_lowercase().contains("chrome") || tp.name.to_lowercase().contains("firefox") || tp.name.to_lowercase().contains("msedge"))
                    && now.duration_since(tp.timestamp).unwrap_or(Duration::from_secs(999)).as_millis() < 3600000
                });
                if browser_closed_recently { satisfied += 1; }
            }

            let ratio = satisfied as f32 / total as f32;
            if ratio >= rule.conditions_percentage && total > 0 {
                if rule.debug {
                    Logging::debug(&format!("[DEBUG] Rule '{}': Stealer logic triggered ({}/{} = {:.1}%)", 
                        rule.name, satisfied, total, ratio * 100.0));
                }
                return true;
            }
        }

        // 2. Evaluate Sigma-style Mapping if present
        if let Some(mapping) = &rule.mapping {
            Self::evaluate_mapping_internal(mapping, rule, state, rule.debug)
        } else {
            // Fallback to simple stage counting
            let satisfied_count = state.satisfied_stages.get(&rule.name).map_or(0, |s| s.len());
            if satisfied_count >= rule.min_stages_satisfied && rule.min_stages_satisfied > 0 {
                true
            } else if rule.conditions_percentage > 0.01 {
                let total_conds: usize = rule.stages.iter().map(|s| s.conditions.len()).sum();
                let satisfied_conds: usize = state.satisfied_conditions.get(&rule.name)
                    .map_or(0, |m| m.values().map(|v| v.len()).sum());
                
                if total_conds == 0 { return false; }
                let percentage = satisfied_conds as f32 / total_conds as f32;
                percentage >= rule.conditions_percentage
            } else {
                false
            }
        }
    }

    /// Refresh process list, track terminations, AND detect new processes
    fn track_process_terminations(&mut self) {
            let now = SystemTime::now();

            self.last_refresh = now;
            
            self.sys.refresh_processes();
            
            // --- FIX: Collect data first to release the borrow on self.sys ---
            let mut current_pids = HashSet::new();
            let mut new_processes_to_init = Vec::new();

            for (pid, proc) in self.sys.processes() {
                let pid_u32 = pid.as_u32();
                current_pids.insert(pid_u32);
                
                if !self.known_pids.contains_key(&pid_u32) {
                    // Just store the info we need for later
                    new_processes_to_init.push((pid_u32, proc.name().to_string()));
                }
            }

            // --- Now self.sys is no longer borrowed by the loop, we can mutate self ---
            for (pid_u32, proc_name) in new_processes_to_init {
                //Logging::info(&format!("[NEW PROCESS DETECTED] {} (PID: {})", proc_name, pid_u32));
                
                self.known_pids.insert(pid_u32, proc_name.clone());

                let gid = self.get_or_create_gid_for_pid(pid_u32);
                if !self.process_states.contains_key(&gid) {
                    let new_state = Self::create_new_process_state(
                        &mut self.sys, // Safe to borrow mutably now
                        &self.rules,
                        gid,
                        pid_u32,
                        proc_name,
                        now
                    );
                    self.process_states.insert(gid, new_state);
                }
            }
            
            // Handle vanished processes (Existing logic)
            let vanished_pids: Vec<u32> = self.known_pids.keys()
                .filter(|pid| !current_pids.contains(pid))
                .cloned()
                .collect();
                
            for pid in vanished_pids {
                if let Some(name) = self.known_pids.remove(&pid) {
                    //Logging::info(&format!("[PROCESS TERMINATED] {} (PID: {})", name, pid));
                    
                    // --- CRITICAL FIX: Clean up process state when process dies ---
                    // This ensures that if the PID is reused, we scan it as a new process.
                    let gid = pid as u64; 
                    self.process_states.remove(&gid);

                    self.terminated_processes.push(TerminatedProcess {
                        name,
                        timestamp: now,
                    });
                }
            }
            
            if self.terminated_processes.len() > 1000 {
                self.terminated_processes.retain(|tp| {
                    now.duration_since(tp.timestamp).unwrap_or(Duration::from_secs(0)) < Duration::from_secs(300)
                });
            }
    }
    
    /// NEW: Perform a full scan of all active processes using memory and heuristic rules.
    /// This should be called periodically (e.g. every few seconds) alongside event processing.
    pub fn scan_all_processes(&mut self) -> Vec<ProcessRecord> {
        self.track_process_terminations(); // Ensure list is up to date
        
        let mut detected_threats = Vec::new();
        
        // We need to iterate over process states. 
        // Note: process_states is populated by track_process_terminations for all running processes.
        let keys: Vec<u64> = self.process_states.keys().cloned().collect();

        for gid in keys {
            // We need to temporarily extract state or just access fields we need
            // Since we can't borrow self mutably for the whole loop if we call methods,
            // we have to be careful.
            
            // Gather info needed for scan
            let (pid, appname) = if let Some(s) = self.process_states.get(&gid) {
                (s.pid, s.appname.clone())
            } else {
                continue;
            };

            // Run Memory Scans
            for rule in &self.rules {
                for stage in &rule.stages {
                    for cond in &stage.conditions {
                        if let RuleCondition::MemoryScan { patterns, detect_pe_headers, private_only } = cond {
                            // Check allowlist first
                            if self.is_process_allowlisted(&appname, rule) {
                                continue;
                            }

                            if scan_process_memory(pid, patterns, *detect_pe_headers, *private_only) {
                                Logging::warning(&format!("[FULL SCAN] Memory threat detected in '{}' (PID: {}) via rule '{}'", 
                                    appname, pid, rule.name));
                                
                                // Create a record to return
                                let exepath = self.sys.process(sysinfo::Pid::from(pid as usize)).map(|p| p.exe().to_path_buf()).unwrap_or_default();
                                let mut record = ProcessRecord::new(gid, appname.clone(), exepath);
                                record.pids.insert(pid);
                                record.is_malicious = true;
                                record.termination_requested = rule.response.terminate_process;
                                record.triggered_rule_name = Some(rule.name.clone());
                                record.process_state = if rule.response.suspend_process { ProcessState::Suspended } else { ProcessState::Running };
                                
                                detected_threats.push(record);
                                
                                // Update state to reflect detection
                                if let Some(s) = self.process_states.get_mut(&gid) {
                                    s.last_memory_scan = Some(SystemTime::now());
                                }
                                
                                // Break to next process (avoid duplicate alerts for same process in one sweep)
                                break; 
                            }
                        }
                    }
                    if !detected_threats.is_empty() && detected_threats.last().unwrap().gid == gid { break; }
                }
                if !detected_threats.is_empty() && detected_threats.last().unwrap().gid == gid { break; }
            }
        }
        
        detected_threats
    }

    #[cfg(target_os = "windows")]
    fn static_has_active_connections(pid: u32) -> bool {
        use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
        use windows::Win32::Networking::WinSock::AF_INET;

        if pid == 0 { return false; }

        let mut dw_size = 0;
        unsafe {
            let _ = GetExtendedTcpTable(None, &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
            if dw_size == 0 { return false; }

            let mut buffer = vec![0u8; dw_size as usize];
            if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                return true; 
            }
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    fn static_has_active_connections(_pid: u32) -> bool {
        false
    }

    #[cfg(target_os = "windows")]
    fn has_active_connections(&self, pid: u32) -> bool {
        Self::static_has_active_connections(pid)
    }

    #[cfg(not(target_os = "windows"))]
    fn has_active_connections(&self, _pid: u32) -> bool {
        false
    }

    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let rules = self.load_rules_recursive(path)?;
        self.rules = rules;
        
        // Pre-compile Regex for all patterns
        let mut patterns = HashSet::new();
        for rule in &self.rules {
            for stage in &rule.stages {
                for cond in &stage.conditions {
                    match cond {
                        RuleCondition::File { path_pattern, .. } => { 
                            patterns.insert(Self::wildcard_to_regex(path_pattern)); 
                        }
                        RuleCondition::Registry { key_pattern, .. } => { 
                            patterns.insert(Self::wildcard_to_regex(key_pattern)); 
                        }
                        RuleCondition::Process { pattern, .. } => { 
                            patterns.insert(pattern.clone()); 
                        }
                        RuleCondition::Service { name_pattern, .. } => { 
                            patterns.insert(name_pattern.clone()); 
                        }
                        RuleCondition::Network { dest_pattern, .. } => { 
                            if let Some(p) = dest_pattern { 
                                patterns.insert(p.clone()); 
                            } 
                        }
                        RuleCondition::Api { name_pattern, module_pattern } => {
                            patterns.insert(name_pattern.clone());
                            patterns.insert(module_pattern.clone());
                        }
                        RuleCondition::SensitivePathAccess { patterns: pats, .. } => {
                            for p in pats {
                                patterns.insert(Self::wildcard_to_regex(p));
                            }
                        }
                        RuleCondition::ProcessAncestry { ancestor_pattern, .. } => {
                            patterns.insert(ancestor_pattern.clone());
                        }
                        RuleCondition::DataExfiltrationPattern { source_patterns, .. } => {
                            for p in source_patterns {
                                patterns.insert(Self::wildcard_to_regex(p));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        for pattern in patterns {
            self.cache_regex(&pattern);
        }
        
        Logging::info(&format!("[EDR]: {} generic rules loaded (including sub-rules).", self.rules.len()));
        Ok(())
    }

    fn load_rules_recursive(&self, path: &Path) -> Result<Vec<BehaviorRule>, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut rules = Vec::new();

        // Check if the file uses !include directives
        if content.contains("!include") {
            // Process include directives
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            
            // First, collect all includes and load their rules
            for line in content.lines() {
                let trimmed = line.trim();
                // Handle both "- !include file.yaml" and "!include file.yaml" formats
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
                                Err(e) => {
                                    Logging::warning(&format!("[EDR] Failed to load include {}: {}", include_path.display(), e));
                                }
                            }
                        } else {
                            Logging::warning(&format!("[EDR] Include file not found: {}", include_path.display()));
                        }
                    }
                }
            }
            
            // Now parse the main file, filtering out include lines
            let filtered_content: String = content
                .lines()
                .filter(|line| !line.contains("!include"))
                .collect::<Vec<_>>()
                .join("\n");
            
            if !filtered_content.trim().is_empty() && filtered_content.trim() != "---" {
                match serde_yaml::from_str::<Vec<BehaviorRule>>(&filtered_content) {
                    Ok(main_rules) => rules.extend(main_rules),
                    Err(_) => {
                        // Might be empty or only includes, that's OK
                    }
                }
            }
        } else {
            let r: Vec<BehaviorRule> = serde_yaml::from_str(&content)?;
            rules.extend(r);
        }

        Ok(rules)
    }

    fn cache_regex(&mut self, pattern: &str) {
        if !self.regex_cache.contains_key(pattern) {
            if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
                self.regex_cache.insert(pattern.to_string(), re);
            }
        }
    }

    pub fn wildcard_to_regex(pattern: &str) -> String {
        let mut regex = String::with_capacity(pattern.len() * 2);
        regex.push('^');
    
        for ch in pattern.chars() {
            match ch {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                // escape regex metacharacters
                '.' | '\\' | '+' | '^' | '|' | '(' | ')' | '[' | ']' | '{' | '}' => {
                    regex.push('\\');
                    regex.push(ch);
                }
                other => regex.push(other),
            }
        }
    
        regex.push('$');
        regex
    }

    /// Load additional rules from a path and append/replace existing ones
    pub fn load_additional_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(()); // Optional file, ignore if missing
        }

        let new_rules = self.load_rules_recursive(path)?;
        
        // Extend rules
        self.rules.extend(new_rules);
        
        // Re-compile regex cache for new rules
        let mut patterns = HashSet::new();
        // Since we are appending, we could optimize this, but for now just re-scanning the NEW rules is safer
        // Actually, to be safe and simple, let's just scan ALL rules again to ensure cache is complete
        // Or better: scan the newly added rules only (last N rules)
        // For simplicity: scan all rules. It happens rarely (startup/reload).
        for rule in &self.rules {
             for stage in &rule.stages {
                for cond in &stage.conditions {
                    match cond {
                        RuleCondition::File { path_pattern, .. } => { 
                            patterns.insert(Self::wildcard_to_regex(path_pattern)); 
                        }
                        RuleCondition::Registry { key_pattern, .. } => { 
                            patterns.insert(Self::wildcard_to_regex(key_pattern)); 
                        }
                        RuleCondition::Process { pattern, .. } => { 
                            patterns.insert(pattern.clone()); 
                        }
                        RuleCondition::Service { name_pattern, .. } => { 
                            patterns.insert(name_pattern.clone()); 
                        }
                        RuleCondition::Network { dest_pattern, .. } => { 
                            if let Some(p) = dest_pattern { 
                                patterns.insert(p.clone()); 
                            } 
                        }
                        RuleCondition::Api { name_pattern, module_pattern } => {
                            patterns.insert(name_pattern.clone());
                            patterns.insert(module_pattern.clone());
                        }
                        RuleCondition::SensitivePathAccess { patterns: pats, .. } => {
                            for p in pats {
                                patterns.insert(Self::wildcard_to_regex(p));
                            }
                        }
                        RuleCondition::ProcessAncestry { ancestor_pattern, .. } => {
                            patterns.insert(ancestor_pattern.clone());
                        }
                        RuleCondition::DataExfiltrationPattern { source_patterns, .. } => {
                            for p in source_patterns {
                                patterns.insert(Self::wildcard_to_regex(p));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        for pattern in patterns {
            self.cache_regex(&pattern);
        }

        Logging::info(&format!("[EDR]: Loaded additional rules from {:?}", path));
        Ok(())
    }


    /// Create a new process state with full initialization (ancestry, rules, etc.)
    fn create_new_process_state(
        sys: &mut sysinfo::System,
        rules: &[BehaviorRule],
        gid: u64,
        pid: u32,
        appname: String,
        now: SystemTime
    ) -> ProcessBehaviorState {
        // Perform a refresh for new processes to ensure ancestry is populated
        // Using refresh_processes() instead of refresh_all() for better performance
        sys.refresh_processes();
        
        let mut s = ProcessBehaviorState::default();
        s.gid = gid;
        s.pid = pid;
        s.appname = appname;
        s.first_event_ts = Some(now);
        s.last_event_ts = now;

        if let Some(proc) = sys.process(sysinfo::Pid::from(pid as usize)) {
            let proc_name = proc.name().to_string();
            if !proc_name.is_empty() {
                s.appname = proc_name;
            }
            s.cmdline = proc.cmd().join(" ");
            
            // Build process ancestry chain (upwards towards root)
            let mut current_pid = proc.parent();
            while let Some(parent_pid) = current_pid {
                if let Some(p_proc) = sys.process(parent_pid) {
                    let p_name = p_proc.name().to_string();
                    if !p_name.is_empty() {
                        if s.parent_name.is_empty() {
                            s.parent_name = p_name.clone();
                        }
                        s.process_ancestry.push(p_name);
                    }
                    current_pid = p_proc.parent();
                    if s.process_ancestry.len() >= 10 { break; } // Limit depth
                } else {
                    break;
                }
            }
        }

        // --- Enable direct recording if process name matches rule-level override ---
        for rule in rules {
            if rule.record_on_start.iter().any(|pattern| {
                s.appname.to_lowercase().contains(&pattern.to_lowercase())
            }) {
                s.is_recording = true;
                Logging::info(&format!("[DIRECT RECORDING ACTIVATED] Process '{}' (PID: {}) matched record_on_start in rule '{}'", 
                    s.appname, s.pid, rule.name));
                break;
            }
        }

        s
    }


    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage, _config: &Config) {
        // 1. Refresh process list (Throttled internally to 1s to prevent lag)
        self.track_process_terminations(); 

        let gid = msg.gid;
        let now = SystemTime::now();

        // 2. Check if we need to initialize or re-initialize state
        let needs_init = if let Some(state) = self.process_states.get(&gid) {
            state.pid != msg.pid
        } else {
            true // New GID entry
        };

        if needs_init {
            // Create fresh state with full ancestry and rule checks
            let new_state = Self::create_new_process_state(
                &mut self.sys,
                &self.rules,
                gid,
                msg.pid,
                precord.appname.clone(),
                now
            );
            
            // Log if we are replacing an existing GID's state (context switch)
            if self.process_states.contains_key(&gid) {
                // debug log maybe?
            }
            
            self.process_states.insert(gid, new_state);
        }

        // Now safe to get mutable reference
        let state = self.process_states.get_mut(&gid).unwrap();
        state.last_event_ts = now;

        // --- NEW: Stealer Tracking Logic (User Snippet) ---
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let filepath = msg.filepathstr.to_lowercase();

        for rule in &self.rules {
            // 1. Track Browser Access & Sensitive Files
            for b_path in &rule.browser_paths {
                if filepath.contains(&b_path.to_lowercase()) {
                    state.accessed_browsers.insert(b_path.clone(), now);
                    
                    // Track sensitive files
                    for s_file in &rule.sensitive_files {
                        if filepath.contains(&s_file.to_lowercase()) {
                            state.sensitive_files_read.insert(s_file.clone());
                        }
                    }
                }
            }

            // 2. Track Data Staging
            for s_path in &rule.staging_paths {
                if filepath.contains(&s_path.to_lowercase()) && irp_op == IrpMajorOp::IrpWrite {
                    state.staged_files_written.insert(PathBuf::from(&filepath), now);
                }
            }

            // 3. Track Entropy
            if msg.is_entropy_calc == 1 && rule.entropy_threshold > 0.01 && msg.entropy > rule.entropy_threshold {
                state.high_entropy_detected = true;
            }

            // 4. Track Crypto APIs
            for api in &rule.crypto_apis {
                if filepath.contains(&api.to_lowercase()) {
                    state.crypto_api_count += 1;
                }
            }

            // 5. Track Archive Actions
            for action in &rule.archive_actions {
                if filepath.contains(&action.to_lowercase()) {
                    state.archive_action_detected = true;
                }
            }
        }

        // 3. Pre-process global metrics and update tracking state
        
        // Entropy tracking
        if msg.is_entropy_calc == 1 {
            if msg.entropy > state.entropy_max {
                state.entropy_max = msg.entropy;
            }
            state.entropy_sum += msg.entropy;
            state.entropy_count += 1;
        }

        // Operation history for time-windowed aggregations
        state.op_history.push(OpHistoryEntry {
            timestamp: now,
            op_type: msg.irp_op,
            file_change: msg.file_change,
            bytes: msg.mem_sized_used,
            path: msg.filepathstr.clone(),
            extension: msg.extension.clone(),
        });
        
        // Limit history size to prevent memory bloat (keep last 1000 entries)
        if state.op_history.len() > 1000 {
            state.op_history.drain(0..500);
        }

        // Track totals
        state.ops_total += 1;
        state.bytes_total += msg.mem_sized_used;

        // Extension change tracking
        if msg.file_change == 5 { // EXTENSION_CHANGED
            state.extension_changes += 1;
            state.extension_change_timestamps.push(now);
            // Limit timestamp history
            if state.extension_change_timestamps.len() > 500 {
                state.extension_change_timestamps.drain(0..250);
            }
        }

        // --- NEW: Per-file activity tracking ---
        if state.is_recording && !msg.filepathstr.is_empty() {
            let count = state.file_op_counts.entry(msg.filepathstr.clone()).or_insert(0);
            *count += 1;
            
            // Log every 5 events for the same file if recording is active
            if *count % 5 == 0 {
                let ancestry = state.process_ancestry.join(" -> ");
                Logging::debug(&format!("[RECORDING] File Activity: '{}' (Ops: {}) | Process: '{}' (PID: {}) | Ancestry: [{}]", 
                    msg.filepathstr, count, state.appname, state.pid, ancestry));
            }
        }
        
        // 4. Evaluate each rule's stages
        let mut triggered_rules = Vec::new();

        {
            let state = self.process_states.get_mut(&gid).unwrap();
            for rule in &self.rules {
                // DEBUG: Log rule evaluation start
                if rule.debug {
                    Logging::debug(&format!("[DEBUG] Evaluating rule '{}' for process '{}' (PID: {})", 
                        rule.name, state.appname, state.pid));
                }

                // Allowlisting check
                let allowlisted = rule.allowlisted_apps.iter().any(|entry| {
                    match entry {
                        AllowlistEntry::Simple(pattern) => {
                            state.appname.to_lowercase().contains(&pattern.to_lowercase())
                        }
                        AllowlistEntry::Complex { pattern, signers, must_be_signed } => {
                            if !state.appname.to_lowercase().contains(&pattern.to_lowercase()) {
                                return false; 
                            }
                            if *must_be_signed || !signers.is_empty() {
                                #[cfg(target_os = "windows")]
                                {
                                    let path = Path::new(&precord.exepath);
                                    if !path.exists() { return false; }
                                    let info = verify_signature(path);
                                    if !info.is_trusted { return false; }
                                    if !signers.is_empty() {
                                        if let Some(actual_signer) = &info.signer_name {
                                            signers.iter().any(|s_pattern| {
                                                if let Ok(re) = Regex::new(s_pattern) {
                                                    re.is_match(actual_signer)
                                                } else {
                                                    actual_signer.to_lowercase().contains(&s_pattern.to_lowercase())
                                                }
                                            })
                                        } else { false }
                                    } else { true }
                                }
                                #[cfg(not(target_os = "windows"))] { false }
                            } else { true }
                        }
                    }
                });

                if allowlisted { continue; }

                // Expiration logic
                if rule.time_window_ms > 0 {
                    if let Some(first) = state.first_event_ts {
                        if now.duration_since(first).unwrap_or(Duration::from_secs(0)).as_millis() as u64 > rule.time_window_ms {
                            state.satisfied_stages.remove(&rule.name);
                            state.satisfied_conditions.remove(&rule.name);
                            state.first_event_ts = Some(now);
                        }
                    }
                }

                // Loop stages
                for (s_idx, stage) in rule.stages.iter().enumerate() {
                    for (c_idx, condition) in stage.conditions.iter().enumerate() {
                        let should_eval = Self::should_evaluate_condition_refactored(condition, rule, state.ops_total, state.is_recording, msg);
                        if should_eval {
                            if Self::evaluate_condition_internal(&self.regex_cache, condition, msg, state, precord, &rule.name, s_idx, c_idx, &self.terminated_processes, rule.debug) {
                                state.satisfied_conditions.entry(rule.name.clone()).or_default().entry(s_idx).or_default().insert(c_idx);
                                state.satisfied_stages.entry(rule.name.clone()).or_default().insert(s_idx);
                            }
                        }
                    }
                }

                // Trigger check
                if Self::should_rule_trigger(rule, state, &self.terminated_processes) {
                    triggered_rules.push(rule.clone());
                }
            }
        }

        // 5. Execution
        let state = self.process_states.get_mut(&gid).unwrap();
        for rule in triggered_rules {
            if rule.response.record && !state.is_recording {
                state.is_recording = true;
                Logging::info(&format!("[RECORDING ACTIVATED] Rule '{}' enabled detailed tracking for '{}' (PID: {})", 
                    rule.name, state.appname, state.pid));
            }

            if rule.is_private {
                // Private rules only update state, they don't trigger alerts or actions
                continue;
            }

            // Enhanced alert with full details
            let _satisfied_stages_list: Vec<String> = state.satisfied_stages
                .get(&rule.name)
                .map(|stages| {
                    stages.iter()
                        .filter_map(|idx| rule.stages.get(*idx).map(|s| s.name.clone()))
                        .collect()
                })
                .unwrap_or_default();

            let _ancestry = if state.process_ancestry.is_empty() {
                "Unknown".to_string()
            } else {
                state.process_ancestry.join(" -> ")
            };
            
            // Construct ThreatInfo for ActionsOnKill
            let _threat_info = ThreatInfo {
                threat_type_label: "Behavioral Rule",
                virus_name: &rule.name,
                prediction: 1.0, 
            };

            // Prepare dummy matrix (since this is rule-based, not ML)
            let _pred_mtrx = VecvecCappedF32::new(crate::predictions::prediction::PREDMTRXCOLS, crate::predictions::prediction::PREDMTRXROWS);

            if rule.response.terminate_process {
                precord.termination_requested = true;
                precord.is_malicious = true;
                precord.time_killed = Some(SystemTime::now());
                precord.triggered_rule_name = Some(rule.name.clone());
            }

            if rule.response.suspend_process {
                // For suspend, we also trigger kernel-based actions (reporting/logging)
                precord.termination_requested = true; // Signal intent to driver if supported, or treat as kill flow
                precord.process_state = ProcessState::Suspended; // Update state for the report
                precord.triggered_rule_name = Some(rule.name.clone());
            }

            if rule.response.quarantine {
                precord.quarantine_requested = true;
                precord.termination_requested = true;
                precord.is_malicious = true;
                precord.triggered_rule_name = Some(rule.name.clone());
                Logging::warning(&format!("[ACTION] Process '{}' (PID: {}) QUARANTINED", state.appname, state.pid));
            }

            if rule.response.auto_revert {
                precord.revert_requested = true;
                Logging::warning(&format!("[ACTION] Auto-revert enabled for process '{}' (PID: {})", state.appname, state.pid));
            }
        }

        // Helper function to add at the top of the impl block
        fn truncate(s: &str, max_len: usize) -> String {
            if s.len() <= max_len {
                format!("{:width$}", s, width = max_len)
            } else {
                format!("{}..{:width$}", &s[..max_len-3], "", width = 3)
            }
        }
    }

    /// NEW: Determine if a condition should be evaluated based on memory scan config
    fn should_evaluate_condition_refactored(condition: &RuleCondition, rule: &BehaviorRule, ops_total: u64, is_recording: bool, msg: &IOMessage) -> bool {
        if let RuleCondition::MemoryScan { .. } = condition {
            let op = IrpMajorOp::from_byte(msg.irp_op);
            
            // Check memory scan configuration
            if let Some(config) = &rule.memory_scan_config {
                // Always scan on I/O events if configured
                if config.scan_on_io_event {
                    return true;
                }
                
                // Scan every N operations
                if ops_total % config.scan_every_n_ops == 0 {
                    return true;
                }
            }
            
            // Default behavior: scan on specific triggers
            if op == IrpMajorOp::IrpCreate || is_recording {
                return true;
            }
            
            false
        } else {
            // Non-memory-scan conditions are always evaluated
            true
        }
    }

    fn should_evaluate_condition(&self, condition: &RuleCondition, rule: &BehaviorRule, state: &ProcessBehaviorState, msg: &IOMessage) -> bool {
        Self::should_evaluate_condition_refactored(condition, rule, state.ops_total, state.is_recording, msg)
    }

    fn evaluate_mapping_internal(mapping: &RuleMapping, rule: &BehaviorRule, state: &ProcessBehaviorState, debug: bool) -> bool {
        let result = match mapping {
            RuleMapping::And { and: mappings } => {
                let results: Vec<bool> = mappings.iter().map(|m| Self::evaluate_mapping_internal(m, rule, state, debug)).collect();
                let all_true = results.iter().all(|&r| r);
                if debug {
                    Logging::debug(&format!("[DEBUG] Rule '{}': AND mapping -> {:?} = {}", rule.name, results, all_true));
                }
                all_true
            }
            RuleMapping::Or { or: mappings } => {
                let results: Vec<bool> = mappings.iter().map(|m| Self::evaluate_mapping_internal(m, rule, state, debug)).collect();
                let any_true = results.iter().any(|&r| r);
                if debug {
                    Logging::debug(&format!("[DEBUG] Rule '{}': OR mapping -> {:?} = {}", rule.name, results, any_true));
                }
                any_true
            }
            RuleMapping::Not { not: m } => {
                let inner = Self::evaluate_mapping_internal(m, rule, state, debug);
                let result = !inner;
                if debug {
                    Logging::debug(&format!("[DEBUG] Rule '{}': NOT mapping -> {} = {}", rule.name, inner, result));
                }
                result
            }
            RuleMapping::Stage { stage: name } => {
                if let Some(idx) = rule.stages.iter().position(|s| s.name == *name) {
                    let satisfied = state.satisfied_stages.get(&rule.name).map_or(false, |set| set.contains(&idx));
                    if debug {
                        Logging::debug(&format!("[DEBUG] Rule '{}': Stage '{}' (idx {}) = {}", rule.name, name, idx, satisfied));
                    }
                    satisfied
                } else {
                    if debug {
                        Logging::debug(&format!("[DEBUG] Rule '{}': Stage '{}' NOT FOUND in rule definition", rule.name, name));
                    }
                    false
                }
            }
        };
        result
    }

    fn evaluate_condition_internal(
        regex_cache: &HashMap<String, Regex>, 
        cond: &RuleCondition, 
        msg: &IOMessage, 
        state: &mut ProcessBehaviorState,
        precord: &ProcessRecord,
        rule_name: &str,
        s_idx: usize,
        c_idx: usize,
        terminated_processes: &[TerminatedProcess],
        debug: bool,
    ) -> bool {
        let op = IrpMajorOp::from_byte(msg.irp_op);
        
        let result = match cond {
            RuleCondition::MemoryScan { patterns, detect_pe_headers, private_only } => {
                let matched = scan_process_memory(msg.pid, patterns, *detect_pe_headers, *private_only);
                
                // Update last scan timestamp
                state.last_memory_scan = Some(SystemTime::now());
                
                if debug && matched {
                    Logging::debug(&format!("[DEBUG] MemoryScan matched for PID {}", state.pid));
                }
                matched
            }

            RuleCondition::File { op: f_op, path_pattern } => {
                let regex_pattern = Self::wildcard_to_regex(path_pattern);
                let path_match = Self::matches_internal(regex_cache, &regex_pattern, &msg.filepathstr);
                if !path_match {
                    if debug {
                        Logging::debug(&format!("[DEBUG] File condition: path '{}' didn't match pattern '{}'", 
                            msg.filepathstr, path_pattern));
                    }
                    return false;
                }

                let op_match = match f_op.as_str() {
                    "Write" => op == IrpMajorOp::IrpWrite,
                    "Read" | "Open" => op == IrpMajorOp::IrpRead || op == IrpMajorOp::IrpCreate,
                    "Delete" => msg.file_change == 6 || msg.file_change == 7,
                    "Rename" => msg.file_change == 4,
                    "Create" => msg.file_change == 3,
                    _ => false,
                };

                if debug && !op_match {
                    Logging::debug(&format!("[DEBUG] File condition: operation '{}' didn't match (irp_op: {}, file_change: {})", 
                        f_op, msg.irp_op, msg.file_change));
                }

                op_match
            }

            RuleCondition::Registry { op: r_op, key_pattern, value_name, expected_data } => {
                if op != IrpMajorOp::IrpRegistry { return false; }
                
                let regex_pattern = Self::wildcard_to_regex(key_pattern);
                if !Self::matches_internal(regex_cache, &regex_pattern, &msg.filepathstr) { 
                    if debug {
                        Logging::debug(&format!("[DEBUG] Registry: key '{}' didn't match pattern '{}'", 
                            msg.filepathstr, key_pattern));
                    }
                    return false; 
                }
                
                if let Some(vn) = value_name {
                    if !msg.filepathstr.contains(vn) { 
                        if debug {
                            Logging::debug(&format!("[DEBUG] Registry: value_name '{}' not in path", vn));
                        }
                        return false; 
                    }
                }
                if let Some(ed) = expected_data {
                    if !msg.extension.contains(ed) { 
                        if debug {
                            Logging::debug(&format!("[DEBUG] Registry: expected_data '{}' not found", ed));
                        }
                        return false; 
                    }
                }

                match r_op.as_str() {
                    "SetValue" => msg.mem_sized_used > 0,
                    "SetSecurity" => msg.file_change == 10,
                    "Delete" => msg.file_change == 6,
                    "Create" => msg.file_change == 3,
                    _ => true,
                }
            }

            RuleCondition::Process { op: p_op, pattern } => {
                match p_op.as_str() {
                    "Name" => Self::matches_internal(regex_cache, pattern, &state.appname),
                    "Path" => {
                        if precord.exepath.as_os_str().is_empty() {
                            false // no path -> cannot evaluate Path condition
                        } else {
                            let path = precord.exepath.to_string_lossy();
                            Self::matches_internal(regex_cache, pattern, path.as_ref())
                        }
                    }

                    "CommandLine" => Self::matches_internal(regex_cache, pattern, &state.cmdline),
                    "Parent" => Self::matches_internal(regex_cache, pattern, &state.parent_name),
                    "Spawn" => op == IrpMajorOp::IrpCreate && Self::matches_internal(regex_cache, pattern, &msg.filepathstr),
                    "Terminate" => {
                        let rule_window = Duration::from_secs(30);
                        terminated_processes.iter().any(|tp| {
                            let age = SystemTime::now().duration_since(tp.timestamp).unwrap_or(Duration::from_secs(999));
                            age < rule_window && Self::matches_internal(regex_cache, pattern, &tp.name)
                        })
                    }
                    _ => false,
                }
            }

            RuleCondition::Service { op: s_op, name_pattern } => {
                #[cfg(target_os = "windows")]
                {
                    match s_op.as_str() {
                        "Stop" => !ServiceChecker::is_running(name_pattern),
                        _ => Self::matches_internal(regex_cache, name_pattern, &msg.filepathstr),
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Self::matches_internal(regex_cache, name_pattern, &msg.filepathstr)
                }
            }

            RuleCondition::Api { name_pattern, module_pattern } => {
                // NOTE: This assumes IOMessage contains API info in filepathstr or extension
                // You may need to adjust based on your actual telemetry structure
                let api_match = Self::matches_internal(regex_cache, name_pattern, &msg.filepathstr);
                let module_match = Self::matches_internal(regex_cache, module_pattern, &msg.extension);
                
                if debug && (!api_match || !module_match) {
                    Logging::debug(&format!("[DEBUG] API condition: name_match={}, module_match={} (path: '{}', ext: '{}')", 
                        api_match, module_match, msg.filepathstr, msg.extension));
                }
                
                api_match && module_match
            }

            RuleCondition::Heuristic { metric, threshold } => {
                match metric.as_str() {
                    "Entropy" => msg.is_entropy_calc == 1 && msg.entropy >= *threshold,
                    _ => false,
                }
            }

            RuleCondition::Network { .. } => {
                state.active_connections
            }

            RuleCondition::Signature { is_trusted, signer_pattern } => {
                #[cfg(target_os = "windows")]
                {
                    let path = Path::new(&precord.exepath);
                    if !path.exists() {
                        return !is_trusted;
                    }
                    
                    let info = verify_signature(path);
                    
                    if *is_trusted {
                        if !info.is_trusted {
                            return false;
                        }
                        
                        if let Some(pattern) = signer_pattern {
                            if let Some(signer) = info.signer_name.as_deref() {
                                Self::matches_internal(regex_cache, pattern, signer)
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    } else {
                        !info.is_trusted
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    false 
                }
            }

            RuleCondition::OperationCount { op_type, path_pattern, comparison, threshold } => {
                let count = match op_type.as_str() {
                    "Read" => precord.ops_read,
                    "Write" => precord.ops_written,
                    "Delete" => precord.files_deleted.len() as u64,
                    "Rename" => precord.files_renamed.len() as u64,
                    "Create" => precord.ops_open,
                    "Registry" => precord.ops_setinfo,
                    _ => 0,
                };
                
                if let Some(pattern) = path_pattern {
                    let regex_pattern = Self::wildcard_to_regex(pattern);
                    if !Self::matches_internal(regex_cache, &regex_pattern, &msg.filepathstr) {
                        return false;
                    }
                }
                
                Self::compare_u64(count, comparison, *threshold)
            }

            RuleCondition::ExtensionPattern { patterns, match_mode, op_type } => {
                let is_correct_op = match op_type.as_str() {
                    "Read" => op == IrpMajorOp::IrpRead,
                    "Write" => op == IrpMajorOp::IrpWrite,
                    _ => true,
                };
                if !is_correct_op { return false; }

                let ext = format!("*.{}", msg.extension.trim_matches('\0').to_lowercase());
                let matches: Vec<bool> = patterns.iter()
                    .map(|p| {
                        let pattern_lower = p.to_lowercase();
                        if pattern_lower.starts_with("*.") {
                            ext.ends_with(&pattern_lower[1..])
                        } else {
                            ext.contains(&pattern_lower)
                        }
                    })
                    .collect();
                
                Self::evaluate_match_mode(&matches, match_mode)
            }

            RuleCondition::ByteThreshold { direction, comparison, threshold } => {
                let bytes = match direction.as_str() {
                    "read" => precord.bytes_read,
                    "write" => precord.bytes_written,
                    "total" => precord.bytes_read + precord.bytes_written,
                    _ => 0,
                };
                Self::compare_u64(bytes, comparison, *threshold)
            }

            RuleCondition::EntropyThreshold { metric, comparison, threshold } => {
                let entropy = match metric.as_str() {
                    "current" => msg.entropy,
                    "max" => state.entropy_max,
                    "average" => {
                        if state.entropy_count > 0 {
                            state.entropy_sum / state.entropy_count as f64
                        } else {
                            0.0
                        }
                    }
                    _ => 0.0,
                };
                Self::compare_f64(entropy, comparison, *threshold)
            }

            RuleCondition::FileCount { category, comparison, threshold } => {
                let count = match category.as_str() {
                    "read" => precord.files_read.len() as u64,
                    "written" => precord.files_written.len() as u64,
                    "deleted" => precord.files_deleted.len() as u64,
                    "renamed" => precord.files_renamed.len() as u64,
                    "created" => precord.fpaths_created.len() as u64,
                    _ => 0,
                };
                Self::compare_u64(count, comparison, *threshold)
            }

            RuleCondition::DirectorySpread { category, comparison, threshold } => {
                let count = match category.as_str() {
                    "created" => precord.dirs_with_files_created.len() as u64,
                    "updated" => precord.dirs_with_files_updated.len() as u64,
                    "opened" => precord.dirs_with_files_opened.len() as u64,
                    _ => 0,
                };
                Self::compare_u64(count, comparison, *threshold)
            }

            RuleCondition::TimeWindowAggregation { metric, function, time_window_ms, comparison, threshold } => {
                let now = SystemTime::now();
                let window_start = now.checked_sub(Duration::from_millis(*time_window_ms))
                    .unwrap_or(now);
                
                let relevant_ops: Vec<_> = state.op_history.iter()
                    .filter(|op_entry| op_entry.timestamp >= window_start)
                    .collect();
                
                let value = match (metric.as_str(), function) {
                    ("ops_write", AggregationFunction::Count) => {
                        relevant_ops.iter().filter(|o| o.op_type == 2).count() as f64
                    }
                    ("ops_delete", AggregationFunction::Count) => {
                        relevant_ops.iter().filter(|o| o.file_change == 6 || o.file_change == 7).count() as f64
                    }
                    ("ops_rename", AggregationFunction::Count) => {
                        relevant_ops.iter().filter(|o| o.file_change == 4).count() as f64
                    }
                    ("bytes_written", AggregationFunction::Sum) => {
                        relevant_ops.iter().filter(|o| o.op_type == 2).map(|o| o.bytes as f64).sum()
                    }
                    ("files_modified", AggregationFunction::Count) => {
                        relevant_ops.iter()
                            .filter(|o| o.op_type == 2 || o.op_type == 3 || o.file_change == 4)
                            .map(|o| &o.path)
                            .collect::<HashSet<_>>()
                            .len() as f64
                    }
                    (_, AggregationFunction::Rate) => {
                        let elapsed = (*time_window_ms as f64) / 1000.0;
                        if elapsed > 0.0 {
                            relevant_ops.len() as f64 / elapsed
                        } else {
                            0.0
                        }
                    }
                    (_, AggregationFunction::Count) => relevant_ops.len() as f64,
                    (_, AggregationFunction::Sum) => relevant_ops.iter().map(|o| o.bytes as f64).sum(),
                    (_, AggregationFunction::Avg) => {
                        if relevant_ops.is_empty() { 0.0 } 
                        else { relevant_ops.iter().map(|o| o.bytes as f64).sum::<f64>() / relevant_ops.len() as f64 }
                    }
                    (_, AggregationFunction::Max) => {
                        relevant_ops.iter().map(|o| o.bytes as f64).fold(0.0, f64::max)
                    }
                    (_, AggregationFunction::Min) => {
                        relevant_ops.iter().map(|o| o.bytes as f64).fold(f64::MAX, f64::min)
                    }
                };
                
                Self::compare_f64(value, comparison, *threshold)
            }

            RuleCondition::DriveActivity { drive_type, op_type, comparison, threshold } => {
                let count = match (drive_type.as_str(), op_type.as_str()) {
                    ("removable", "read") => precord.on_removable_drive_read_count,
                    ("removable", "write") => precord.on_removable_drive_write_count,
                    ("network", "read") => precord.on_shared_drive_read_count,
                    ("network", "write") => precord.on_shared_drive_write_count,
                    ("any", "read") => precord.on_removable_drive_read_count + precord.on_shared_drive_read_count,
                    ("any", "write") => precord.on_removable_drive_write_count + precord.on_shared_drive_write_count,
                    _ => 0,
                };
                Self::compare_u32(count, comparison, *threshold)
            }

            RuleCondition::ProcessAncestry { ancestor_pattern, max_depth } => {
                let depth = max_depth.unwrap_or(10) as usize;
                state.process_ancestry.iter()
                    .take(depth)
                    .any(|ancestor| Self::matches_internal(regex_cache, ancestor_pattern, ancestor))
            }

            RuleCondition::ExtensionRatio { extensions, comparison, threshold } => {
                let total_unique_written = precord.files_written.len();
                if total_unique_written == 0 { return false; }

                let key = format!("{}:{}:{}:ext_hits", rule_name, s_idx, c_idx);
                if extensions.iter().any(|ext| msg.extension.to_lowercase().contains(&ext.to_lowercase())) {
                    state.condition_specific_state.entry(key.clone()).or_default().insert(msg.filepathstr.clone());
                }
                
                let unique_extension_hits = state.condition_specific_state.get(&key).map(|s| s.len()).unwrap_or(0);
                let ratio = unique_extension_hits as f32 / total_unique_written as f32;
                Self::compare_f32(ratio, comparison, *threshold)
            }

            RuleCondition::RateOfChange { metric, comparison, threshold } => {
                let elapsed = state.last_event_ts
                    .duration_since(state.first_event_ts.unwrap_or(state.last_event_ts))
                    .unwrap_or(Duration::from_secs(1))
                    .as_secs_f64()
                    .max(0.1);
                
                let rate = match metric.as_str() {
                    "files_per_second" => precord.files_written.len() as f64 / elapsed,
                    "bytes_per_second" => precord.bytes_written as f64 / elapsed,
                    "ops_per_second" => precord.driver_msg_count as f64 / elapsed,
                    _ => 0.0,
                };
                
                Self::compare_f64(rate, comparison, *threshold)
            }

            RuleCondition::SelfModification { modification_type } => {
                match modification_type.as_str() {
                    "exe_deleted" | "exe_not_exists" => !precord.exe_exists,
                    _ => false,
                }
            }

            RuleCondition::ExtensionChangeVelocity { time_window_ms, comparison, threshold } => {
                let now = SystemTime::now();
                let window_start = now.checked_sub(Duration::from_millis(*time_window_ms))
                    .unwrap_or(now);
                
                let count = state.extension_change_timestamps.iter()
                    .filter(|&&ts| ts >= window_start)
                    .count() as u64;
                
                Self::compare_u64(count, comparison, *threshold)
            }

            RuleCondition::CommandLineMatch { patterns, match_mode } => {
                let matches: Vec<bool> = patterns.iter()
                    .map(|p| Self::matches_with_modifiers(&state.cmdline, p, regex_cache))
                    .collect();
                Self::evaluate_match_mode(&matches, match_mode)
            }

            RuleCondition::SensitivePathAccess { patterns, op_type, min_unique_paths } => {
                let is_correct_op = match op_type.as_str() {
                    "Read" => op == IrpMajorOp::IrpRead || op == IrpMajorOp::IrpCreate,
                    "Write" => op == IrpMajorOp::IrpWrite,
                    _ => true,
                };
                if !is_correct_op { 
                    if debug {
                        Logging::debug(&format!("[DEBUG] SensitivePathAccess: wrong op_type (current: {:?}, wanted: {})", 
                            op, op_type));
                    }
                    return false; 
                }

                let key = format!("{}:{}:{}:path_hits", rule_name, s_idx, c_idx);
                let matched_any = patterns.iter().any(|p| {
                    let regex_pattern = Self::wildcard_to_regex(p);
                    Self::matches_internal(regex_cache, &regex_pattern, &msg.filepathstr)
                });
                
                if matched_any {
                    state.condition_specific_state.entry(key.clone()).or_default().insert(msg.filepathstr.clone());
                    if debug {
                        let count = state.condition_specific_state.get(&key).map(|s| s.len()).unwrap_or(0);
                        Logging::debug(&format!("[DEBUG] SensitivePathAccess: matched path '{}' (total unique: {})", 
                            msg.filepathstr, count));
                    }
                }
                
                let unique_paths = state.condition_specific_state.get(&key).map(|s| s.len()).unwrap_or(0);
                let min_paths = min_unique_paths.unwrap_or(1) as usize;
                unique_paths >= min_paths
            }

            RuleCondition::ClusterPattern { min_clusters, max_clusters } => {
                let cluster_count = precord.clusters.len();
                
                let meets_min = min_clusters.map_or(true, |min| cluster_count >= min);
                let meets_max = max_clusters.map_or(true, |max| cluster_count <= max);
                
                meets_min && meets_max
            }

            RuleCondition::TempDirectoryWrite { min_bytes, min_files } => {
                let path_lower = msg.filepathstr.to_lowercase();
                let is_temp = path_lower.contains("\\temp\\") 
                    || path_lower.contains("\\tmp\\")
                    || path_lower.contains("\\appdata\\local\\temp");
                
                if !is_temp || op != IrpMajorOp::IrpWrite {
                    return false;
                }

                let key = format!("{}:{}:{}:temp_writes", rule_name, s_idx, c_idx);
                
                state.condition_specific_state.entry(key.clone()).or_default().insert(msg.filepathstr.clone());
                let current_files = state.condition_specific_state.get(&key).map(|s| s.len()).unwrap_or(0) as u32;
                let current_bytes = msg.mem_sized_used;
                
                let meets_bytes = min_bytes.map_or(true, |mb| current_bytes >= mb);
                let meets_files = min_files.map_or(true, |mf| current_files >= mf);
                
                meets_bytes || meets_files
            }

            RuleCondition::ArchiveCreation { extensions, min_size, in_temp } => {
                let default_exts = vec!["zip", "rar", "7z", "tar", "gz", "bz2", "xz"];
                let exts_to_check: Vec<&str> = if extensions.is_empty() {
                    default_exts
                } else {
                    extensions.iter().map(|s| s.as_str()).collect()
                };
                
                let ext_lower = msg.extension.to_lowercase();
                let is_archive = exts_to_check.iter().any(|e| ext_lower.contains(e));
                
                if !is_archive {
                    return false;
                }
                
                if op != IrpMajorOp::IrpWrite && op != IrpMajorOp::IrpCreate {
                    return false;
                }
                
                if *in_temp {
                    let path_lower = msg.filepathstr.to_lowercase();
                    let is_temp_path = path_lower.contains("\\temp\\") 
                        || path_lower.contains("\\tmp\\")
                        || path_lower.contains("\\appdata\\local\\temp");
                    if !is_temp_path {
                        return false;
                    }
                }
                
                min_size.map_or(true, |ms| msg.mem_sized_used >= ms)
            }

            RuleCondition::DataExfiltrationPattern { source_patterns, min_source_reads, detect_temp_staging, detect_archive } => {
                let reads_key = format!("{}:{}:{}:source_reads", rule_name, s_idx, c_idx);
                let temp_key = format!("{}:{}:{}:temp_staging", rule_name, s_idx, c_idx);
                let archive_key = format!("{}:{}:{}:archive_created", rule_name, s_idx, c_idx);
                
                if op == IrpMajorOp::IrpRead || op == IrpMajorOp::IrpCreate {
                    for pattern in source_patterns {
                        let regex_pattern = Self::wildcard_to_regex(pattern);
                        if Self::matches_internal(regex_cache, &regex_pattern, &msg.filepathstr) {
                            state.condition_specific_state.entry(reads_key.clone()).or_default().insert(msg.filepathstr.clone());
                            break;
                        }
                    }
                }
                
                if *detect_temp_staging && op == IrpMajorOp::IrpWrite {
                    let path_lower = msg.filepathstr.to_lowercase();
                    if path_lower.contains("\\temp\\") || path_lower.contains("\\tmp\\") || path_lower.contains("\\appdata\\local\\temp") {
                        state.condition_specific_state.entry(temp_key.clone()).or_default().insert("true".to_string());
                    }
                }
                
                if *detect_archive && (op == IrpMajorOp::IrpWrite || op == IrpMajorOp::IrpCreate) {
                    let ext_lower = msg.extension.to_lowercase();
                    if ext_lower.contains("zip") || ext_lower.contains("rar") || ext_lower.contains("7z") {
                        state.condition_specific_state.entry(archive_key.clone()).or_default().insert("true".to_string());
                    }
                }
                
                let source_read_count = state.condition_specific_state.get(&reads_key).map(|s| s.len()).unwrap_or(0) as u32;
                let min_reads = min_source_reads.unwrap_or(1);
                let has_enough_reads = source_read_count >= min_reads;
                
                let has_temp_staging = !*detect_temp_staging || state.condition_specific_state.get(&temp_key).map(|s| !s.is_empty()).unwrap_or(false);
                let has_archive = !*detect_archive || state.condition_specific_state.get(&archive_key).map(|s| !s.is_empty()).unwrap_or(false);
                
                has_enough_reads && (has_temp_staging || has_archive)
            }
        };

        if debug && result {
            Logging::debug(&format!("[DEBUG] Condition MATCHED: {:?}", cond));
        }

        result
    }

    fn matches_internal(regex_cache: &HashMap<String, Regex>, pattern: &str, text: &str) -> bool {
        if let Some(re) = regex_cache.get(pattern) {
            re.is_match(text)
        } else {
            text.to_lowercase().contains(&pattern.to_lowercase())
        }
    }

    fn compare_u64(value: u64, comparison: &Comparison, threshold: u64) -> bool {
        match comparison {
            Comparison::Gt => value > threshold,
            Comparison::Gte => value >= threshold,
            Comparison::Lt => value < threshold,
            Comparison::Lte => value <= threshold,
            Comparison::Eq => value == threshold,
            Comparison::Ne => value != threshold,
        }
    }

    fn compare_u32(value: u32, comparison: &Comparison, threshold: u32) -> bool {
        match comparison {
            Comparison::Gt => value > threshold,
            Comparison::Gte => value >= threshold,
            Comparison::Lt => value < threshold,
            Comparison::Lte => value <= threshold,
            Comparison::Eq => value == threshold,
            Comparison::Ne => value != threshold,
        }
    }

    fn compare_f64(value: f64, comparison: &Comparison, threshold: f64) -> bool {
        match comparison {
            Comparison::Gt => value > threshold,
            Comparison::Gte => value >= threshold,
            Comparison::Lt => value < threshold,
            Comparison::Lte => value <= threshold,
            Comparison::Eq => (value - threshold).abs() < 0.0001,
            Comparison::Ne => (value - threshold).abs() >= 0.0001,
        }
    }

    fn compare_f32(value: f32, comparison: &Comparison, threshold: f32) -> bool {
        match comparison {
            Comparison::Gt => value > threshold,
            Comparison::Gte => value >= threshold,
            Comparison::Lt => value < threshold,
            Comparison::Lte => value <= threshold,
            Comparison::Eq => (value - threshold).abs() < 0.0001,
            Comparison::Ne => (value - threshold).abs() >= 0.0001,
        }
    }

    fn evaluate_match_mode(matches: &[bool], mode: &MatchMode) -> bool {
        let match_count = matches.iter().filter(|&&m| m).count();
        let total = matches.len();
        
        match mode {
            MatchMode::All => match_count == total,
            MatchMode::Any => match_count > 0,
            MatchMode::Count(n) => match_count == *n,
            MatchMode::AtLeast(n) => match_count >= *n,
        }
    }

    fn matches_with_modifiers(text: &str, pattern: &CommandLinePattern, regex_cache: &HashMap<String, Regex>) -> bool {
        let mut text_for_match = text.to_string();
        let mut pattern_for_match = pattern.pattern.clone();
        let mut negate = false;
        let mut use_regex = false;
        
        for modifier in &pattern.modifiers {
            match modifier {
                StringModifier::Nocase => {
                    text_for_match = text_for_match.to_lowercase();
                    pattern_for_match = pattern_for_match.to_lowercase();
                }
                StringModifier::Contains => {}
                StringModifier::Startswith => {
                    if !use_regex {
                        return text_for_match.starts_with(&pattern_for_match) != negate;
                    }
                }
                StringModifier::Endswith => {
                    if !use_regex {
                        return text_for_match.ends_with(&pattern_for_match) != negate;
                    }
                }
                StringModifier::Re => {
                    use_regex = true;
                }
                StringModifier::Not => {
                    negate = true;
                }
                StringModifier::Base64 => {
                    if let Ok(decoded) = base64_decode(&text_for_match) {
                        text_for_match = decoded;
                    }
                }
            }
        }
        
        let result = if use_regex {
            if let Some(re) = regex_cache.get(&pattern_for_match) {
                re.is_match(&text_for_match)
            } else if let Ok(re) = Regex::new(&format!("(?i){}", &pattern_for_match)) {
                re.is_match(&text_for_match)
            } else {
                text_for_match.contains(&pattern_for_match)
            }
        } else {
            text_for_match.contains(&pattern_for_match)
        };
        
        if negate { !result } else { result }
    }
}

fn base64_decode(input: &str) -> Result<String, ()> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let input = input.trim().replace('=', "");
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    
    for c in input.chars() {
        let val = CHARS.iter().position(|&x| x == c as u8).ok_or(())?;
        buffer = (buffer << 6) | (val as u32);
        bits += 6;
        
        while bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xFF) as u8);
        }
    }

    String::from_utf8(output).map_err(|_| ())
}

#[cfg(target_os = "windows")]
fn scan_process_memory(pid: u32, patterns: &[String], detect_pe: bool, private_only: bool) -> bool {
    let process_handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).unwrap_or_default()
    };
    
    if process_handle.is_invalid() {
        return false;
    }

    let mut address = std::ptr::null();
    let mut mbi = MEMORY_BASIC_INFORMATION::default();

    unsafe {
        while VirtualQueryEx(process_handle, Some(address), &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
            let is_commited = mbi.State == MEM_COMMIT;
            let is_not_noaccess = mbi.Protect != PAGE_NOACCESS;
            let is_private = mbi.Type == MEM_PRIVATE;

            if is_commited && is_not_noaccess && (!private_only || is_private) {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0;
                
                if ReadProcessMemory(process_handle, mbi.BaseAddress, buffer.as_mut_ptr() as *mut _, mbi.RegionSize, Some(&mut bytes_read)).as_bool() {
                    let data = &buffer[..bytes_read];
                    
                    if detect_pe {
                        for i in 0..(data.len().saturating_sub(64)) {
                            if data[i] == b'M' && data[i+1] == b'Z' {
                                let pe_offset_idx = i + 0x3c;
                                if pe_offset_idx + 4 <= data.len() {
                                    let pe_offset = u32::from_le_bytes([data[pe_offset_idx], data[pe_offset_idx+1], data[pe_offset_idx+2], data[pe_offset_idx+3]]) as usize;
                                    let pe_sig_idx = i + pe_offset;
                                    if pe_sig_idx + 4 <= data.len() {
                                        if data[pe_sig_idx] == b'P' && data[pe_sig_idx+1] == b'E' && data[pe_sig_idx+2] == 0 && data[pe_sig_idx+3] == 0 {
                                            let _ = CloseHandle(process_handle);
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    for pattern in patterns {
                        if data.windows(pattern.len()).any(|window| window == pattern.as_bytes()) {
                            let _ = CloseHandle(process_handle);
                            return true;
                        }
                        
                        if (pattern.starts_with("0x") || pattern.chars().take(2).all(|c| c.is_ascii_hexdigit())) && pattern.len() >= 2 {
                            let hex_bytes = hex_to_bytes(pattern);
                            if !hex_bytes.is_empty() && data.windows(hex_bytes.len()).any(|window| window == &hex_bytes[..]) {
                                let _ = CloseHandle(process_handle);
                                return true;
                            }
                        }
                    }
                }
            }

            address = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize) as *const _;
            if address.is_null() { break; }
        }
        let _ = CloseHandle(process_handle);
    }
    false
}

#[cfg(not(target_os = "windows"))]
fn scan_process_memory(_pid: u32, _patterns: &[String], _detect_pe: bool, _private_only: bool) -> bool {
    false
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let clean_hex = hex.replace("0x", "").replace(" ", "").replace("-", "");
    if clean_hex.len() % 2 != 0 || clean_hex.is_empty() {
        return Vec::new();
    }
    (0..clean_hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean_hex[i..i + 2], 16).unwrap_or(0)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::wildcard_to_regex;
    use regex::Regex;

    #[test]
    fn basic_wildcards() {
        let rx = Regex::new(&wildcard_to_regex("*.rs")).unwrap();
        assert!(rx.is_match("main.rs"));
        assert!(rx.is_match("lib.rs"));
        assert!(!rx.is_match("main.rs.bak"));

        let rx2 = Regex::new(&wildcard_to_regex("file?.txt")).unwrap();
        assert!(rx2.is_match("file1.txt"));
        assert!(rx2.is_match("fileA.txt"));
        assert!(!rx2.is_match("file12.txt"));
    }

    #[test]
    fn escapes_meta_chars() {
        let rx = Regex::new(&wildcard_to_regex("version(1).txt")).unwrap();
        assert!(rx.is_match("version(1).txt"));
    }
}
