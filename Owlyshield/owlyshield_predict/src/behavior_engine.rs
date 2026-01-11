use std::collections::{HashMap, HashSet};
use std::path::Path;
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub suspend_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default)] pub block_network: bool,
    #[serde(default)] pub auto_revert: bool,
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
        }
    }
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule> ,
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

    /// Perform a proactive sweep of all running processes to find malware variants based on rules
    pub fn find_malware_variants(&mut self, _process_records: &mut lru::LruCache<u64, ProcessRecord>) {
        self.sys.refresh_all();
        let now = SystemTime::now();

        let rules_to_check: Vec<_> = self.rules.iter().cloned().collect();

        for (pid, proc) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            let appname = proc.name().to_string();
            let cmdline = proc.cmd().join(" ");
            let parent_name = if let Some(parent) = proc.parent() {
                self.sys.process(parent).map(|p| p.name().to_string()).unwrap_or_default()
            } else {
                String::new()
            };

            let mut temp_state = ProcessBehaviorState::default();
            temp_state.pid = pid_u32;
            temp_state.appname = appname;
            temp_state.cmdline = cmdline;
            temp_state.parent_name = parent_name;
            temp_state.first_event_ts = Some(now);

            let mut dummy_msg = IOMessage::default();
            dummy_msg.pid = pid_u32;
            
            // Create a minimal ProcessRecord for condition evaluation
            let dummy_precord = ProcessRecord::new(0, temp_state.appname.clone(), std::path::PathBuf::new());
            
            let mut triggered_rules = Vec::new();

            for rule in &rules_to_check {
                for (s_idx, stage) in rule.stages.iter().enumerate() {
                    for (c_idx, condition) in stage.conditions.iter().enumerate() {
                        if let RuleCondition::Process { .. } = condition {
                            if Self::evaluate_condition_internal(&self.regex_cache, condition, &dummy_msg, &mut temp_state, &dummy_precord, &rule.name, s_idx, c_idx, &self.terminated_processes) {
                                temp_state.satisfied_conditions
                                    .entry(rule.name.clone())
                                    .or_default()
                                    .entry(s_idx)
                                    .or_default()
                                    .insert(c_idx);

                                temp_state.satisfied_stages
                                    .entry(rule.name.clone())
                                    .or_default()
                                    .insert(s_idx);
                            }
                        }
                    }
                }

                let mut triggered = false;
                if let Some(mapping) = &rule.mapping {
                    triggered = Self::evaluate_mapping_internal(mapping, rule, &temp_state);
                } else {
                    let satisfied_count = temp_state.satisfied_stages.get(&rule.name).map_or(0, |s| s.len());
                    if satisfied_count >= rule.min_stages_satisfied && rule.min_stages_satisfied > 0 {
                        triggered = true;
                    }
                }

                if triggered && !rule.is_private {
                    triggered_rules.push(rule.clone());
                }
            }

            for rule in triggered_rules {
                Logging::warning(&format!("[HYDRADRAGON SCAN] Found Malicious Process Variant: {} | Rule: {} | PID: {}", temp_state.appname, rule.name, pid_u32));
                if rule.response.terminate_process {
                    proc.kill();
                }
            }
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
                            if key_pattern.contains("\\") && !key_pattern.contains("(" ) && !key_pattern.contains("[" ) {
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
        
        // Pre-compile Regex
        let mut patterns = HashSet::new();
        for rule in &self.rules {
            for stage in &rule.stages {
                for cond in &stage.conditions {
                    match cond {
                        RuleCondition::File { path_pattern, .. } => { patterns.insert(path_pattern.clone()); }
                        RuleCondition::Registry { key_pattern, .. } => { patterns.insert(key_pattern.clone()); }
                        RuleCondition::Process { pattern, .. } => { patterns.insert(pattern.clone()); }
                        RuleCondition::Service { name_pattern, .. } => { patterns.insert(name_pattern.clone()); }
                        RuleCondition::Network { dest_pattern, .. } => { if let Some(p) = dest_pattern { patterns.insert(p.clone()); } }
                        RuleCondition::Api { name_pattern, module_pattern } => {
                            patterns.insert(name_pattern.clone());
                            patterns.insert(module_pattern.clone());
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


    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage) {
        self.track_process_terminations();
        let gid = msg.gid;
        let now = SystemTime::now();

        // 1. Ensure state exists
        let state = self.process_states.entry(gid).or_insert_with(|| {
            self.sys.refresh_processes();
            let mut s = ProcessBehaviorState::default();
            s.gid = gid;
            s.pid = msg.pid;
            s.appname = precord.appname.clone();
            s.first_event_ts = Some(now);
            
            if let Some(proc) = self.sys.process(sysinfo::Pid::from(msg.pid as usize)) {
                s.cmdline = proc.cmd().join(" ");
                
                // Build process ancestry chain
                let mut current_pid = proc.parent();
                while let Some(parent_pid) = current_pid {
                    if let Some(p_proc) = self.sys.process(parent_pid) {
                        if s.parent_name.is_empty() {
                            s.parent_name = p_proc.name().to_string();
                        }
                        s.process_ancestry.push(p_proc.name().to_string());
                        current_pid = p_proc.parent();
                        if s.process_ancestry.len() >= 10 { break; } // Limit depth
                    } else {
                        break;
                    }
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
        // 3. Evaluate each rule's stages
        let mut triggered_rules = Vec::new();

        for rule in &self.rules {
            // Allowlisting
            if rule.allowlisted_apps.iter().any(|entry| {
                match entry {
                    AllowlistEntry::Simple(pattern) => {
                        state.appname.to_lowercase().contains(&pattern.to_lowercase())
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
                                if !path.exists() { return false; } // Can't verify missing file
                                
                                let info = verify_signature(path);
                                if !info.is_trusted { return false; } // Not trusted -> FAIL
                                
                                // 3. Check Signer Patterns (if specific signers required)
                                if !signers.is_empty() {
                                    if let Some(actual_signer) = &info.signer_name {
                                        // Check if ANY of the allowed signer patterns match the actual signer
                                        let signer_match = signers.iter().any(|s_pattern| {
                                            // Try regex match first, then substring as fallback
                                            if let Ok(re) = Regex::new(s_pattern) {
                                                re.is_match(actual_signer)
                                            } else {
                                                actual_signer.to_lowercase().contains(&s_pattern.to_lowercase())
                                            }
                                        });
                                        
                                        if !signer_match { return false; } // Trusted, but wrong signer
                                    } else {
                                        return false; // Trusted but no signer name available (and specific signer required)
                                    }
                                }
                                
                                true // Trusted and (if required) signer matched
                            }
                            #[cfg(not(target_os = "windows"))]
                            {
                                false // Can't verify -> Block
                            }
                        } else {
                            true // Name matched, no signature required -> Allow
                        }
                    }
                }
            }) {
                continue;
            }

            // Expiration logic
            if rule.time_window_ms > 0 {
                if let Some(first) = state.first_event_ts {
                    if now.duration_since(first).unwrap_or(Duration::from_secs(0)).as_millis() as u64 > rule.time_window_ms {
                        // Reset progress if window exceeded
                        state.satisfied_stages.remove(&rule.name);
                        state.satisfied_conditions.remove(&rule.name);
                        state.first_event_ts = Some(now);
                    }
                }
            }

            for (s_idx, stage) in rule.stages.iter().enumerate() {
                for (c_idx, condition) in stage.conditions.iter().enumerate() {
                    if Self::evaluate_condition_internal(&self.regex_cache, condition, msg, state, precord, &rule.name, s_idx, c_idx, &self.terminated_processes) {
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
                triggered = Self::evaluate_mapping_internal(mapping, rule, state);
            } else {
                // Fallback to simple stage counting
                let satisfied_count = state.satisfied_stages.get(&rule.name).map_or(0, |s| s.len());
                if satisfied_count >= rule.min_stages_satisfied && rule.min_stages_satisfied > 0 {
                    triggered = true;
                } else if rule.conditions_percentage > 0.01 {
                    let total_conds: usize = rule.stages.iter().map(|s| s.conditions.len()).sum();
                    let satisfied_conds: usize = state.satisfied_conditions.get(&rule.name)
                        .map_or(0, |m| m.values().map(|v| v.len()).sum());
                    
                    if (satisfied_conds as f32 / total_conds as f32) >= rule.conditions_percentage {
                        triggered = true;
                    }
                }
            }

            if triggered {
                triggered_rules.push(rule.clone());
            }
        }

        // 4. Execution
        for rule in triggered_rules {
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
                precord.termination_requested = true; // Quarantine implies termination
                precord.is_malicious = true;
            }

            if rule.response.auto_revert {
                precord.revert_requested = true;
            }
        }
    }

    fn evaluate_mapping_internal(mapping: &RuleMapping, rule: &BehaviorRule, state: &ProcessBehaviorState) -> bool {
        match mapping {
            RuleMapping::And { and: mappings } => mappings.iter().all(|m| Self::evaluate_mapping_internal(m, rule, state)),
            RuleMapping::Or { or: mappings } => mappings.iter().any(|m| Self::evaluate_mapping_internal(m, rule, state)),
            RuleMapping::Not { not: m } => !Self::evaluate_mapping_internal(m, rule, state),
            RuleMapping::Stage { stage: name } => {
                if let Some(idx) = rule.stages.iter().position(|s| s.name == *name) {
                    state.satisfied_stages.get(&rule.name).map_or(false, |set| set.contains(&idx))
                } else {
                    false
                }
            }
        }
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
        terminated_processes: &[TerminatedProcess]
    ) -> bool {
        let op = IrpMajorOp::from_byte(msg.irp_op);
        
        match cond {
            // === EXISTING CONDITIONS ===
            RuleCondition::File { op: f_op, path_pattern } => {
                let path_match = Self::matches_internal(regex_cache, path_pattern, &msg.filepathstr);
                if !path_match { return false; }

                match f_op.as_str() {
                    "Write" => op == IrpMajorOp::IrpWrite,
                    "Read" | "Open" => op == IrpMajorOp::IrpRead || op == IrpMajorOp::IrpCreate,
                    "Delete" => msg.file_change == 6 || msg.file_change == 7,
                    "Rename" => msg.file_change == 4,
                    "Create" => msg.file_change == 3,
                    _ => false,
                }
            }
            RuleCondition::Registry { op: r_op, key_pattern, value_name, expected_data } => {
                if op != IrpMajorOp::IrpRegistry { return false; }
                if !Self::matches_internal(regex_cache, key_pattern, &msg.filepathstr) { return false; }
                
                // Optional refinements
                if let Some(vn) = value_name {
                    if !msg.filepathstr.contains(vn) { return false; }
                }
                if let Some(ed) = expected_data {
                    if !msg.extension.contains(ed) { return false; }
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
                    "CommandLine" => Self::matches_internal(regex_cache, pattern, &state.cmdline),
                    "Parent" => Self::matches_internal(regex_cache, pattern, &state.parent_name),
                    "Spawn" => op == IrpMajorOp::IrpCreate && Self::matches_internal(regex_cache, pattern, &msg.filepathstr),
                    "Terminate" => {
                        let rule_window = Duration::from_secs(30); // Default 30s for termination window
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
                Self::matches_internal(regex_cache, name_pattern, &msg.filepathstr) && Self::matches_internal(regex_cache, module_pattern, &msg.filepathstr)
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
                                 // Trusted but no signer name? Validation failure if pattern is strict.
                                 // However, usually trusted implies signed.
                                 false
                             }
                         } else {
                             true
                         }
                    } else {
                        // We strictly want it to be NOT TRUSTED
                        !info.is_trusted
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    // Not supported on non-Windows yet
                    false 
                }
            }

            // === NEW TELEMETRY-BASED CONDITIONS ===

            RuleCondition::OperationCount { op_type, path_pattern, comparison, threshold } => {
                let count = match op_type.as_str() {
                    "Read" => precord.ops_read,
                    "Write" => precord.ops_written,
                    "Delete" => precord.files_deleted.len() as u64,
                    "Rename" => precord.files_renamed.len() as u64,
                    "Create" => precord.ops_open,
                    "Registry" => precord.ops_setinfo, // Approximate
                    _ => 0,
                };
                
                // If path_pattern specified, this is a "potential match" indicator
                // The count threshold is the main check
                if let Some(pattern) = path_pattern {
                    if !Self::matches_internal(regex_cache, pattern, &msg.filepathstr) {
                        return false; // Path doesn't match the filter
                    }
                }
                
                Self::compare_u64(count, comparison, *threshold)
            }

            RuleCondition::ExtensionPattern { patterns, match_mode, op_type } => {
                // Check if current operation matches the type
                let is_correct_op = match op_type.as_str() {
                    "Read" => op == IrpMajorOp::IrpRead,
                    "Write" => op == IrpMajorOp::IrpWrite,
                    _ => true,
                };
                if !is_correct_op { return false; }

                // Check extension against patterns
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

                // Dynamic hit tracking for specified extensions
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
                // Check if operation type matches
                let is_correct_op = match op_type.as_str() {
                    "Read" => op == IrpMajorOp::IrpRead || op == IrpMajorOp::IrpCreate,
                    "Write" => op == IrpMajorOp::IrpWrite,
                    _ => true,
                };
                if !is_correct_op { return false; }

                // Dynamic hit tracking for specified path patterns
                let key = format!("{}:{}:{}:path_hits", rule_name, s_idx, c_idx);
                if patterns.iter().any(|p| Self::matches_internal(regex_cache, p, &msg.filepathstr)) {
                    state.condition_specific_state.entry(key.clone()).or_default().insert(msg.filepathstr.clone());
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
                // Check if current write is to a temp directory
                let path_lower = msg.filepathstr.to_lowercase();
                let is_temp = path_lower.contains("\\temp\\") 
                    || path_lower.contains("\\tmp\\")
                    || path_lower.contains("\\appdata\\local\\temp");
                
                if !is_temp || op != IrpMajorOp::IrpWrite {
                    return false;
                }

                // Track temp writes for this condition
                let key = format!("{}:{}:{}:temp_writes", rule_name, s_idx, c_idx);
                let _bytes_key = format!("{}:{}:{}:temp_bytes", rule_name, s_idx, c_idx);
                
                state.condition_specific_state.entry(key.clone()).or_default().insert(msg.filepathstr.clone());
                let current_files = state.condition_specific_state.get(&key).map(|s| s.len()).unwrap_or(0) as u32;
                
                // Track bytes (simplified - just use current message bytes)
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
                
                // Check temp directory requirement
                if *in_temp {
                    let path_lower = msg.filepathstr.to_lowercase();
                    let is_temp_path = path_lower.contains("\\temp\\") 
                        || path_lower.contains("\\tmp\\")
                        || path_lower.contains("\\appdata\\local\\temp");
                    if !is_temp_path {
                        return false;
                    }
                }
                
                // Check size requirement
                min_size.map_or(true, |ms| msg.mem_sized_used >= ms)
            }

            RuleCondition::DataExfiltrationPattern { source_patterns, min_source_reads, detect_temp_staging, detect_archive } => {
                // Track reads from sensitive sources
                let reads_key = format!("{}:{}:{}:source_reads", rule_name, s_idx, c_idx);
                let temp_key = format!("{}:{}:{}:temp_staging", rule_name, s_idx, c_idx);
                let archive_key = format!("{}:{}:{}:archive_created", rule_name, s_idx, c_idx);
                
                // Check if current operation is a read from a sensitive source
                if op == IrpMajorOp::IrpRead || op == IrpMajorOp::IrpCreate {
                    for pattern in source_patterns {
                        if Self::matches_internal(regex_cache, pattern, &msg.filepathstr) {
                            state.condition_specific_state.entry(reads_key.clone()).or_default().insert(msg.filepathstr.clone());
                            break;
                        }
                    }
                }
                
                // Check temp staging
                if *detect_temp_staging && op == IrpMajorOp::IrpWrite {
                    let path_lower = msg.filepathstr.to_lowercase();
                    if path_lower.contains("\\temp\\") || path_lower.contains("\\tmp\\") || path_lower.contains("\\appdata\\local\\temp") {
                        state.condition_specific_state.entry(temp_key.clone()).or_default().insert("true".to_string());
                    }
                }
                
                // Check archive creation
                if *detect_archive && (op == IrpMajorOp::IrpWrite || op == IrpMajorOp::IrpCreate) {
                    let ext_lower = msg.extension.to_lowercase();
                    if ext_lower.contains("zip") || ext_lower.contains("rar") || ext_lower.contains("7z") {
                        state.condition_specific_state.entry(archive_key.clone()).or_default().insert("true".to_string());
                    }
                }
                
                // Evaluate the pattern
                let source_read_count = state.condition_specific_state.get(&reads_key).map(|s| s.len()).unwrap_or(0) as u32;
                let min_reads = min_source_reads.unwrap_or(1);
                let has_enough_reads = source_read_count >= min_reads;
                
                let has_temp_staging = !*detect_temp_staging || state.condition_specific_state.get(&temp_key).map(|s| !s.is_empty()).unwrap_or(false);
                let has_archive = !*detect_archive || state.condition_specific_state.get(&archive_key).map(|s| !s.is_empty()).unwrap_or(false);
                
                has_enough_reads && (has_temp_staging || has_archive)
            }
        }
    }

    fn matches_internal(regex_cache: &HashMap<String, Regex>, pattern: &str, text: &str) -> bool {
        if let Some(re) = regex_cache.get(pattern) {
            re.is_match(text)
        } else {
            text.to_lowercase().contains(&pattern.to_lowercase())
        }
    }

    

    // ============================================================================
    // NEW HELPER FUNCTIONS FOR TELEMETRY-BASED CONDITIONS
    // ============================================================================

    /// Compare u64 values
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

    /// Compare u32 values
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

    /// Compare f64 values
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

    /// Compare f32 values
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



    /// Check if pattern matches using MatchMode logic
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

    /// Apply string modifiers to a pattern match
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
                StringModifier::Contains => {
                    // Default behavior
                }
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
                    // Attempt base64 decode
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

/// Simple base64 decode helper
fn base64_decode(input: &str) -> Result<String, ()> {
    // Simple implementation - only handles standard base64
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
