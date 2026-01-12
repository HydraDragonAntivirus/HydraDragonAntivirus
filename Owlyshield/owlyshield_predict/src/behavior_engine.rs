use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use regex::Regex;

// --- EDR Telemetry & Framework ---
use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    pub description: String,
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
    #[serde(default)] pub block_network: bool,
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
}

impl Default for ProcessBehaviorState {
    fn default() -> Self {
        Self {
            gid: 0,
            pid: 0,
            appname: String::new(),
            cmdline: String::new(),
            parent_name: String::new(),
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

    /// Refresh process list and track terminations
    fn track_process_terminations(&mut self) {
        let now = SystemTime::now();
        if now.duration_since(self.last_refresh).unwrap_or(Duration::from_secs(0)) < Duration::from_millis(1000) {
            return;
        }
        self.last_refresh = now;
        
        self.sys.refresh_processes();
        
        let mut current_pids = HashSet::new();
        for (pid, proc) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            current_pids.insert(pid_u32);
            self.known_pids.entry(pid_u32).or_insert_with(|| proc.name().to_string());
        }
        
        // Find pids that are in known_pids but not in current_pids
        let vanished_pids: Vec<u32> = self.known_pids.keys()
            .filter(|pid| !current_pids.contains(pid))
            .cloned()
            .collect();
            
        for pid in vanished_pids {
            if let Some(name) = self.known_pids.remove(&pid) {
                self.terminated_processes.push(TerminatedProcess {
                    name,
                    timestamp: now,
                });
            }
        }
        
        // Cleanup old terminations (older than 5 minutes)
        if self.terminated_processes.len() > 1000 {
            self.terminated_processes.retain(|tp| {
                now.duration_since(tp.timestamp).unwrap_or(Duration::from_secs(0)) < Duration::from_secs(300)
            });
        }
    }

    /// Periodic check for registry-based threats (persistence, etc.)
    pub fn check_registry_indicators(&self) {        
        #[cfg(target_os = "windows")]
        {
            use winreg::RegKey;
            use winreg::enums::*;

            for rule in &self.rules {
                if rule.is_private { continue; }

                for stage in &rule.stages {
                    for condition in &stage.conditions {
                        if let RuleCondition::Registry { key_pattern, value_name, expected_data, .. } = condition {
                            if key_pattern.contains("\\") && !key_pattern.contains("(") && !key_pattern.contains("[") {
                                let (root_enum, subkey) = if key_pattern.to_uppercase().starts_with("HKEY_LOCAL_MACHINE") {
                                    (HKEY_LOCAL_MACHINE, key_pattern.splitn(2, "\\").nth(1).unwrap_or(""))
                                } else if key_pattern.to_uppercase().starts_with("HKEY_CURRENT_USER") {
                                    (HKEY_CURRENT_USER, key_pattern.splitn(2, "\\").nth(1).unwrap_or(""))
                                } else {
                                    (HKEY_LOCAL_MACHINE, key_pattern.as_str())
                                };

                                let root = RegKey::predef(root_enum);
                                if let Ok(key) = root.open_subkey(subkey) {
                                    if let Some(vn) = value_name {
                                        if let Ok(val) = key.get_value::<String, _>(vn) {
                                            let mut matched = true;
                                            if let Some(expected) = expected_data {
                                                if !val.contains(expected) { matched = false; }
                                            }
                                            if matched {
                                                Logging::warning(&format!("[HYDRADRAGON SCAN] Found Malicious Registry Persistence: {} | Rule: {}", key_pattern, rule.name));
                                            }
                                        }
                                    } else {
                                        Logging::warning(&format!("[HYDRADRAGON SCAN] Found Malicious Registry Key: {} | Rule: {}", key_pattern, rule.name));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
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

    /// Convert wildcard patterns (* and ?) to a regex string that matches the whole input.
    /// Example: "*.rs" -> r"^.*\.rs$"
    pub fn wildcard_to_regex(pattern: &str) -> String {
        // reserve some capacity to avoid many reallocations
        let mut regex = String::with_capacity(pattern.len() * 2);
        regex.push('^');

        for ch in pattern.chars() {
            match ch {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                // escape regex metacharacters
                '.' | '\\' | '+' | '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}' => {
                    regex.push('\\');
                    regex.push(ch);
                }
                other => regex.push(other),
            }
        }

        regex.push('$');
        regex
    }

    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage) {
        self.track_process_terminations();
        let gid = msg.gid;
        let now = SystemTime::now();

        // 1. Ensure state exists
        let state = self.process_states.entry(gid).or_insert_with(|| {
            // Perform a deep refresh for new processes to ensure ancestry is populated
            self.sys.refresh_all();
            
            let mut s = ProcessBehaviorState::default();
            s.gid = gid;
            s.pid = msg.pid;
            s.appname = precord.appname.clone();
            s.first_event_ts = Some(now);

            if let Some(proc) = self.sys.process(sysinfo::Pid::from(msg.pid as usize)) {
                s.cmdline = proc.cmd().join(" ");
                
                // Build process ancestry chain (upwards towards root)
                let mut current_pid = proc.parent();
                while let Some(parent_pid) = current_pid {
                    if let Some(p_proc) = self.sys.process(parent_pid) {
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
            for rule in &self.rules {
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
        });

        state.last_event_ts = now;

        // 2. Pre-process global metrics and update tracking state
        
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
        
        // 3. Evaluate each rule's stages
        let mut triggered_rules = Vec::new();

        for rule in &self.rules {
            // DEBUG: Log rule evaluation start
            if rule.debug {
                Logging::debug(&format!("[DEBUG] Evaluating rule '{}' for process '{}' (PID: {})", 
                    rule.name, state.appname, state.pid));
            }

            // Allowlisting check with debug
            let allowlisted = rule.allowlisted_apps.iter().any(|entry| {
                match entry {
                    AllowlistEntry::Simple(pattern) => {
                        let matches = state.appname.to_lowercase().contains(&pattern.to_lowercase());
                        if matches && rule.debug {
                            Logging::debug(&format!("[DEBUG] Rule '{}': Process '{}' allowlisted by simple pattern '{}'", 
                                rule.name, state.appname, pattern));
                        }
                        matches
                    }
                    AllowlistEntry::Complex { pattern, signers, must_be_signed } => {
                        // 1. Check Name
                        if !state.appname.to_lowercase().contains(&pattern.to_lowercase()) {
                            return false; 
                        }

                        // 2. Check Signature Requirements
                        if *must_be_signed || !signers.is_empty() {
                            #[cfg(target_os = "windows")]
                            {
                                let path = Path::new(&precord.exepath);
                                if !path.exists() { 
                                    if rule.debug {
                                        Logging::debug(&format!(
                                            "[DEBUG] Rule '{}': Exe path doesn't exist for signature check: {}",
                                            rule.name, precord.exepath.display()));
                                    }
                                    return false; 
                                }
                                
                                let info = verify_signature(path);
                                if !info.is_trusted { 
                                    if rule.debug {
                                        Logging::debug(&format!("[DEBUG] Rule '{}': Process '{}' signature not trusted", 
                                            rule.name, state.appname));
                                    }
                                    return false; 
                                }
                                
                                // 3. Check Signer Patterns (if specific signers required)
                                if !signers.is_empty() {
                                    if let Some(actual_signer) = &info.signer_name {
                                        let signer_match = signers.iter().any(|s_pattern| {
                                            if let Ok(re) = Regex::new(s_pattern) {
                                                re.is_match(actual_signer)
                                            } else {
                                                actual_signer.to_lowercase().contains(&s_pattern.to_lowercase())
                                            }
                                        });
                                        
                                        if !signer_match { 
                                            if rule.debug {
                                                Logging::debug(&format!("[DEBUG] Rule '{}': Signer '{}' doesn't match required patterns", 
                                                    rule.name, actual_signer));
                                            }
                                            return false; 
                                        }
                                    } else {
                                        if rule.debug {
                                            Logging::debug(&format!("[DEBUG] Rule '{}': No signer name available", rule.name));
                                        }
                                        return false;
                                    }
                                }
                                
                                if rule.debug {
                                    Logging::debug(&format!("[DEBUG] Rule '{}': Process '{}' allowlisted by complex signature check", 
                                        rule.name, state.appname));
                                }
                                true
                            }
                            #[cfg(not(target_os = "windows"))]
                            {
                                false
                            }
                        } else {
                            if rule.debug {
                                Logging::debug(&format!("[DEBUG] Rule '{}': Process '{}' allowlisted by complex pattern (no sig required)", 
                                    rule.name, state.appname));
                            }
                            true
                        }
                    }
                }
            });

            if allowlisted {
                continue;
            }

            // Expiration logic with debug
            if rule.time_window_ms > 0 {
                if let Some(first) = state.first_event_ts {
                    let elapsed = now.duration_since(first).unwrap_or(Duration::from_secs(0)).as_millis() as u64;
                    if elapsed > rule.time_window_ms {
                        if rule.debug {
                            Logging::debug(&format!("[DEBUG] Rule '{}': Time window expired ({} ms > {} ms), resetting", 
                                rule.name, elapsed, rule.time_window_ms));
                        }
                        // Reset progress if window exceeded
                        state.satisfied_stages.remove(&rule.name);
                        state.satisfied_conditions.remove(&rule.name);
                        state.first_event_ts = Some(now);
                    }
                }
            }

            for (s_idx, stage) in rule.stages.iter().enumerate() {
                for (c_idx, condition) in stage.conditions.iter().enumerate() {
                    if Self::evaluate_condition_internal(&self.regex_cache, condition, msg, state, precord, &rule.name, s_idx, c_idx, &self.terminated_processes, rule.debug) {
                        if rule.debug {
                            Logging::debug(&format!("[DEBUG] Rule '{}': Stage '{}' Condition #{} MATCHED: {:?}", 
                                rule.name, stage.name, c_idx, condition));
                        }

                        state.satisfied_conditions
                            .entry(rule.name.clone())
                            .or_default()
                            .entry(s_idx)
                            .or_default()
                            .insert(c_idx);

                        state.satisfied_stages
                            .entry(rule.name.clone())
                            .or_default()
                            .insert(s_idx);
                    }
                }
            }

            // Check if rule should trigger
            let mut triggered = false;
            
            if let Some(mapping) = &rule.mapping {
                triggered = Self::evaluate_mapping_internal(mapping, rule, state, rule.debug);
            } else {
                // Fallback to simple stage counting
                let satisfied_count = state.satisfied_stages.get(&rule.name).map_or(0, |s| s.len());
                if satisfied_count >= rule.min_stages_satisfied && rule.min_stages_satisfied > 0 {
                    triggered = true;
                    if rule.debug {
                        Logging::debug(&format!("[DEBUG] Rule '{}': TRIGGERED via stage count ({} >= {})", 
                            rule.name, satisfied_count, rule.min_stages_satisfied));
                    }
                } else if rule.conditions_percentage > 0.01 {
                    let total_conds: usize = rule.stages.iter().map(|s| s.conditions.len()).sum();
                    let satisfied_conds: usize = state.satisfied_conditions.get(&rule.name)
                        .map_or(0, |m| m.values().map(|v| v.len()).sum());
                    
                    let percentage = satisfied_conds as f32 / total_conds as f32;
                    if percentage >= rule.conditions_percentage {
                        triggered = true;
                        if rule.debug {
                            Logging::debug(&format!("[DEBUG] Rule '{}': TRIGGERED via percentage ({:.1}% >= {:.1}%)", 
                                rule.name, percentage * 100.0, rule.conditions_percentage * 100.0));
                        }
                    }
                } else if rule.debug {
                    Logging::debug(&format!("[DEBUG] Rule '{}': Not triggered (stages: {}/{}, no mapping)", 
                        rule.name, satisfied_count, rule.min_stages_satisfied));
                }
            }

            if !triggered && state.is_recording {
                // Log proximity for rules that are partially met
                let total_conds: usize = rule.stages.iter().map(|s| s.conditions.len()).sum();
                let satisfied_conds: usize = state.satisfied_conditions.get(&rule.name)
                    .map_or(0, |m| m.values().map(|v| v.len()).sum());
                
                if total_conds > 0 && rule.proximity_log_threshold > 0.01 {
                    let proximity = (satisfied_conds as f32 / total_conds as f32) * 100.0;
                    if proximity >= rule.proximity_log_threshold { 
                        let ancestry = state.process_ancestry.join(" -> ");
                        Logging::debug(&format!("[DETECTION PROXIMITY] Rule '{}' is {:.1}% near for process '{}' (PID: {}) | Ancestry: [{}] ({} / {} conditions)", 
                            rule.name, proximity, state.appname, state.pid, ancestry, satisfied_conds, total_conds));
                    }
                }
            }

            if triggered {
                triggered_rules.push(rule.clone());
            }
        }

        // 4. Execution
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

            Logging::warning(&format!("[HYDRADRAGON ALERT] Policy Breached: {} | Process: {}", rule.name, state.appname));
            
            if rule.response.terminate_process {
                precord.termination_requested = true;
                precord.is_malicious = true;
                if let Some(proc) = self.sys.process(sysinfo::Pid::from(state.pid as usize)) {
                    proc.kill();
                }
            }

            if rule.response.quarantine {
                precord.quarantine_requested = true;
                precord.termination_requested = true;
                precord.is_malicious = true;
            }

            if rule.response.auto_revert {
                precord.revert_requested = true;
            }
        }
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
                // To avoid constant performance impact, we only scan on certain triggers
                if op == IrpMajorOp::IrpCreate || state.is_recording || state.ops_total % 250 == 0 {
                    let matched = scan_process_memory(state.pid, patterns, *detect_pe_headers, *private_only);
                    if debug && matched {
                        Logging::debug(&format!("[DEBUG] MemoryScan matched for PID {}", state.pid));
                    }
                    matched
                } else {
                    false
                }
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
            // Fallback to substring match if regex not cached
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
