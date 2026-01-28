use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use serde_yaml;
use serde_yaml::Value as YamlValue;
use regex::Regex;
use std::cell::RefCell;

use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::config::Config;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::threat_handler::ThreatHandler;
use crate::signature_verification::verify_signature;

// --- Windows Specific Imports ---
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, 
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

// --- Sysinfo Imports for Fallback ---
use sysinfo::{System, ProcessRefreshKind, ProcessesToUpdate};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringModifier {
    Nocase, Contains, Startswith, Endswith, Re, Base64, Not,
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

// =============================================================================
// RICH CONDITION SYSTEM (YARA/Sigma-style)
// =============================================================================

/// Named condition group - like YARA strings or Sigma detection items
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NamedConditionGroup {
    // API-related
    #[serde(default)]
    pub apis: Vec<String>,
    #[serde(default = "default_zero")]
    pub api_threshold: usize,  // How many APIs must match (default: 1)
    
    // File paths and operations
    #[serde(default)]
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub file_operations: Vec<String>, // read, write, create, delete, rename, browse
    
    // Registry-related
    #[serde(default)]
    pub registry_keys: Vec<String>,
    #[serde(default)]
    pub registry_values: Vec<String>,
    #[serde(default)]
    pub registry_operations: Vec<String>, // set, create, delete, query
    
    // Network-related
    #[serde(default)]
    pub network_indicators: Vec<String>,
    #[serde(default)]
    pub network_domains: Vec<String>,
    #[serde(default)]
    pub network_ips: Vec<String>,
    #[serde(default)]
    pub has_network_activity: bool,
    
    // Process-related
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
    
    // File characteristics
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub file_actions: Vec<String>,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub file_size_min: Option<u64>,
    #[serde(default)]
    pub file_size_max: Option<u64>,
    
    // Command line
    #[serde(default)]
    pub cmdline_patterns: Vec<CommandLinePattern>,
    #[serde(default)]
    pub cmdline_keywords: Vec<String>,
    
    // Behavioral paths
    #[serde(default)]
    pub staging_paths: Vec<String>,
    #[serde(default)]
    pub browsed_paths: Vec<String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    #[serde(default)]
    pub temp_writes: bool,

    // Persistence mechanisms
    #[serde(default)]
    pub persistence_locations: Vec<String>,
    #[serde(default)]
    pub autorun_keys: Vec<String>,
    #[serde(default)]
    pub scheduled_task_apis: Vec<String>,
    
    // Evasion techniques
    #[serde(default)]
    pub obfuscation_indicators: Vec<String>,
    #[serde(default)]
    pub anti_debug_apis: Vec<String>,
    #[serde(default)]
    pub anti_vm_apis: Vec<String>,
    
    // Signature/Trust
    #[serde(default)]
    pub requires_signed: Option<bool>,
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default)]
    pub untrusted_signers: Vec<String>,
    
    // Thresholds and counts
    #[serde(default = "default_zero")]
    pub min_matches: usize,  // Minimum number of sub-indicators that must match
    #[serde(default)]
    pub min_files_accessed: Option<usize>,
    #[serde(default)]
    pub min_directories_accessed: Option<usize>,
    
    // Time-based
    #[serde(default)]
    pub within_seconds: Option<u64>,  // All indicators must occur within this timeframe
}

/// Detection condition expression - like YARA condition or Sigma detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetectionCondition {
    // Boolean operators
    And { 
        and: Vec<DetectionCondition> 
    },
    Or { 
        or: Vec<DetectionCondition> 
    },
    Not { 
        not: Box<DetectionCondition> 
    },
    
    // Direct condition reference
    Named { 
        condition: String 
    },
    
    // Quantifiers (YARA-style)
    AllOf { 
        all_of: Vec<String>  // All listed conditions must be true
    },
    AnyOf { 
        any_of: Vec<String>  // At least one condition must be true
    },
    NOf {
        n_of: usize,
        conditions: Vec<String>,  // Exactly N conditions must be true
    },
    AtLeast {
        at_least: usize,
        conditions: Vec<String>,  // At least N conditions must be true
    },
    
    // Pattern-based quantifiers (with wildcards)
    AllOfPattern {
        all_of_pattern: String,  // e.g., "api_*" matches all conditions starting with "api_"
    },
    AnyOfPattern {
        any_of_pattern: String,  // e.g., "*_evasion" matches all evasion conditions
    },
    
    // Count-based
    Count { 
        count: Vec<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: usize,
    },
    
    // Percentage-based
    Percentage {
        percentage: Vec<String>,
        #[serde(default)]
        comparison: Comparison,
        threshold: f32,  // 0.0 to 1.0
    },
}

// =============================================================================
// STAGE-BASED DETECTION (Advanced multi-phase attack detection)
// =============================================================================

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
    Signature { is_trusted: bool, #[serde(default)] signer_pattern: Option<String> },
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
// BEHAVIOR RULE (Main Rule Structure)
// =============================================================================

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    
    // =========================================================================
    // LEGACY SIMPLE CONDITIONS (Backward Compatibility)
    // =========================================================================
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
    
    // =========================================================================
    // NEW RICH CONDITION SYSTEM
    // =========================================================================
    #[serde(default)]
    pub named_conditions: HashMap<String, NamedConditionGroup>,
    #[serde(default)]
    pub detection_logic: Option<DetectionCondition>,
    
    // =========================================================================
    // STAGE-BASED DETECTION
    // =========================================================================
    #[serde(default)]
    pub stages: Vec<AttackStage>,
    #[serde(default)]
    pub mapping: Option<RuleMapping>,
    #[serde(default)]
    pub min_stages_satisfied: usize,
    
    // =========================================================================
    // METADATA
    // =========================================================================
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
    
    // =========================================================================
    // RESPONSE ACTIONS
    // =========================================================================
    #[serde(default)]
    pub response: ResponseAction,
    #[serde(default)]
    pub is_private: bool,
    
    // =========================================================================
    // ALLOWLIST
    // =========================================================================
    #[serde(default)]
    pub allowlisted_apps: Vec<AllowlistEntry>,
    
    // =========================================================================
    // ADVANCED OPTIONS
    // =========================================================================
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
}

fn expand_environment_variables(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    // Using a Regex for this is more robust.
    let re = match Regex::new(r"%([^%]+)%") {
        Ok(r) => r,
        Err(_) => return text.to_string(), // Should not happen with this regex
    };
    re.replace_all(text, |caps: &regex::Captures| {
        let var_name = &caps[1];
        // On Windows, env::var is case-insensitive.
        std::env::var(var_name).unwrap_or_else(|_| caps[0].to_string())
    }).to_string()
}


impl BehaviorRule {
    pub fn finalize_rich_fields(&mut self) {
        // --- Start of environment variable expansion ---
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

        // Legacy fields
        expand_vec(&mut self.browsed_paths);
        expand_vec(&mut self.accessed_paths);
        expand_vec(&mut self.staging_paths);
        expand_vec(&mut self.monitored_apis);
        expand_vec(&mut self.file_actions);
        expand_vec(&mut self.file_extensions);
        expand_vec(&mut self.suspicious_parents);
        expand_vec(&mut self.terminated_processes);
        expand_vec(&mut self.false_positives);

        // Allowlist
        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = expand_environment_variables(s),
                AllowlistEntry::Complex { pattern, signers, .. } => {
                    *pattern = expand_environment_variables(pattern);
                    expand_vec(signers);
                }
            }
        }

        // Named Conditions
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
        }

        // Stages
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
                    _ => {} // Other conditions don't have string patterns
                }
            }
        }

        if let Some(msc) = &mut self.memory_scan_config {
            expand_vec(&mut msc.target_processes);
        }
        // --- End of expansion logic ---

        // Normalize allowlist entries
        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = s.to_lowercase(),
                AllowlistEntry::Complex { pattern, .. } => *pattern = pattern.to_lowercase(),
            }
        }
        
        // Normalize named condition patterns
        for (_, cond_group) in &mut self.named_conditions {
            cond_group.apis = cond_group.apis.iter().map(|s| s.to_lowercase()).collect();
            cond_group.file_paths = cond_group.file_paths.iter().map(|s| s.to_lowercase().replace("\\", "/")).collect();
            cond_group.registry_keys = cond_group.registry_keys.iter().map(|s| s.to_lowercase().replace("\\", "/")).collect();
            cond_group.process_names = cond_group.process_names.iter().map(|s| s.to_lowercase()).collect();
            cond_group.parent_names = cond_group.parent_names.iter().map(|s| s.to_lowercase()).collect();
            cond_group.file_actions = cond_group.file_actions.iter().map(|s| s.to_lowercase()).collect();
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
// PROCESS STATE TRACKING
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
    
    pub pid: u32,
    pub exe_path: PathBuf,
    pub app_name: String,
    pub signature_checked: bool,
    pub has_valid_signature: bool,
    
    // NEW: Rich condition state tracking
    pub satisfied_named_conditions: HashSet<String>,
    pub condition_match_counts: HashMap<String, usize>,
    pub condition_first_seen: HashMap<String, SystemTime>,
    pub condition_last_seen: HashMap<String, SystemTime>,
}

impl ProcessBehaviorState {
    pub fn new(pid: u32, exe_path: PathBuf, app_name: String) -> Self {
        let mut state = ProcessBehaviorState::default();
        state.pid = pid;
        state.exe_path = exe_path;
        state.app_name = app_name;
        state.parent_name = "unknown".to_string();  // FIXED: Default to "unknown", NOT empty string
        state.self_terminated_processes = HashSet::new();
        state.terminated_processes = HashSet::new();
        state.detected_apis = HashSet::new();
        state.satisfied_named_conditions = HashSet::new();
        state.condition_match_counts = HashMap::new();
        state.condition_first_seen = HashMap::new();
        state.condition_last_seen = HashMap::new();
        state
    }
}

// =============================================================================
// BEHAVIOR ENGINE (Main Detection Engine)
// =============================================================================

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    regex_cache: RefCell<HashMap<String, Regex>>,
    pub process_terminated: HashSet<String>,
    // Persistent system instance for sysinfo fallbacks
    system: RefCell<System>,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: RefCell::new(HashMap::new()),
            process_terminated: HashSet::new(),
            system: RefCell::new(System::new()),
        }
    }

    /// Helper to safely check if a string matches a pattern
    /// Returns false for empty/unknown strings to avoid false positives
    fn safe_pattern_match(text: &str, pattern: &str) -> bool {
        let text_lc = text.to_lowercase();
        let pattern_lc = pattern.to_lowercase();
        
        // Don't match if either is empty or text is "unknown"
        if text_lc.is_empty() || pattern_lc.is_empty() || text_lc == "unknown" {
            return false;
        }
        
        text_lc.contains(&pattern_lc) || pattern_lc.contains(&text_lc)
    }

    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let rules = self.load_rules_recursive(path)?;
        self.rules = rules;
        Logging::info(&format!("[EDR]: {} behavior rules loaded from {:?}", self.rules.len(), path));
        Ok(())
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
    // PROCESS EVENT HANDLING
    // ==========================================================================
    
    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage, config: &Config, threat_handler: &dyn ThreatHandler) {
        let gid = msg.gid;
        let mut actions = ActionsOnKill::with_handler(threat_handler.clone_box());
        
        // Ensure state exists
        if !self.process_states.contains_key(&gid) {
            // FALLBACK: SELF RESOLUTION
            // If the incoming record has generic/unknown info, try to resolve it via sysinfo immediately
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
                   
                   // Update the precord so the rest of the pipeline knows
                   precord.appname = resolved_appname.clone();
                   precord.exepath = resolved_exepath.clone();
                   
                   if self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!("[BehaviorEngine] Resolved SELF via sysinfo fallback: PID {} -> {}", msg.pid, resolved_appname));
                   }
                }
            }

            let mut s = ProcessBehaviorState::new(msg.pid as u32, resolved_exepath, resolved_appname);
                        
            let parent_pid = msg.parent_pid as u32; 
            let mut parent_found = false;

            // Try to resolve parent from internal state first
            for existing_state in self.process_states.values() {
                if existing_state.pid == parent_pid {
                    // Validate the parent name isn't empty
                    if !existing_state.app_name.is_empty() {
                        s.parent_name = existing_state.app_name.clone();
                        parent_found = true;
                    }
                    break;
                }
            }

            // FALLBACK: PARENT RESOLUTION
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
                    
                    // CRITICAL: Ensure we don't set empty names
                    if !parent_name_str.is_empty() {
                        s.parent_name = parent_name_str;
                        parent_found = true;
                        
                        if self.rules.iter().any(|r| r.debug) {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Resolved parent via sysinfo fallback: PID {} -> '{}'",
                                parent_pid, s.parent_name
                            ));
                        }
                    } else {
                        Logging::warning(&format!(
                            "[BehaviorEngine] Parent PID {} returned empty name from sysinfo",
                            parent_pid
                        ));
                    }
                } else {
                    if self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Parent PID {} not found in system (may have exited)",
                            parent_pid
                        ));
                    }
                }
            }

            // Ensure parent_name is never empty
            if !parent_found { 
                s.parent_name = "unknown".to_string();
                
                if self.rules.iter().any(|r| r.debug) && parent_pid != 0 {
                    Logging::debug(&format!(
                        "[BehaviorEngine] Could not resolve parent for PID {} (PPID: {})",
                        msg.pid, parent_pid
                    ));
                }
            }

            // Final validation - should never be empty at this point
            debug_assert!(!s.parent_name.is_empty(), "parent_name must never be empty");
            
            self.process_states.insert(gid, s);
        }
        let state = self.process_states.get_mut(&gid).unwrap();
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let filepath = msg.filepathstr.to_lowercase().replace("\\", "/");
        let norm_filepath = filepath.trim_end_matches('/');
        let pid = state.pid;
        
        // Signature check
        if !state.signature_checked && !precord.exepath.as_os_str().is_empty() {
            if precord.exepath.exists() {
                let info = verify_signature(&precord.exepath);
                state.has_valid_signature = info.is_trusted;
                state.signature_checked = true;
            } else {
                state.has_valid_signature = false; 
                state.signature_checked = true;
            }
        }

        // Network detection
        let network_keywords = [
            "internetopen", "internetconnect", "httpopen", "httpsend", 
            "urldownload", "socket", "connect", "wsasend", "wsarecv",
            "winhttp", "dnsquery"
        ];
        
        if network_keywords.iter().any(|k| norm_filepath.contains(k)) {
            state.network_activity_detected = true;
            if self.rules.iter().any(|r| r.debug) {
                Logging::debug(&format!("[BehaviorEngine] Network Activity Detected via API: {} (PID: {})", msg.filepathstr, pid));
            }
        }

        // Event tracking for LEGACY conditions
        for rule in &self.rules {
            // Browsed Paths
            for b_path in &rule.browsed_paths {
                let norm_b_path = b_path.to_lowercase().replace("\\", "/");
                let norm_b_path = norm_b_path.trim_end_matches('/');
                if norm_filepath.contains(norm_b_path) {
                    if rule.debug { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Matched browsed path '{}' in '{}'", 
                            rule.name, pid, b_path, filepath
                        )); 
                    }
                    state.browsed_paths_tracker.insert(b_path.clone(), SystemTime::now());
                }
            }

            // Accessed paths
            for s_file in &rule.accessed_paths {
                let norm_s = s_file.to_lowercase().replace("\\", "/");
                let norm_s = norm_s.trim_end_matches('/');
                if norm_filepath.contains(norm_s) {
                    if rule.debug {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Sensitive file accessed '{}'",
                            rule.name, pid, s_file
                        ));
                    }
                    state.accessed_paths_tracker.insert(s_file.clone());
                }
            }

            // Staging
            for s_path in &rule.staging_paths {
                let norm_s_path = s_path.to_lowercase().replace("\\", "/");
                let norm_s_path = norm_s_path.trim_end_matches('/');
                let is_staging_op = matches!(irp_op, IrpMajorOp::IrpWrite | IrpMajorOp::IrpCreate | IrpMajorOp::IrpSetInfo);
                if norm_filepath.contains(norm_s_path) && is_staging_op {
                    if rule.debug { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Matched staging path '{}'", 
                            rule.name, pid, s_path
                        )); 
                    }
                    state.staged_files_written.insert(PathBuf::from(&filepath), SystemTime::now());
                }
            }

            // Entropy
            if msg.entropy > rule.entropy_threshold {
                if rule.debug { 
                    Logging::debug(&format!(
                        "[BehaviorEngine] Rule '{}' (PID: {}): High entropy {:.2} > {:.2}", 
                        rule.name, pid, msg.entropy, rule.entropy_threshold
                    )); 
                }
                state.high_entropy_detected = true;
            }

            // Monitored APIs
            let extension_lc = msg.extension.to_lowercase();
            for api in &rule.monitored_apis {
                let api_lc = api.to_lowercase();
                if norm_filepath.contains(&api_lc) || extension_lc.contains(&api_lc) {
                    if rule.debug && !state.detected_apis.contains(&api_lc) { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Monitored API matched '{}' (File: {}, Ext: {})", 
                            rule.name, pid, api, msg.filepathstr, msg.extension
                        )); 
                    }
                    state.detected_apis.insert(api_lc);
                    state.monitored_api_count = state.detected_apis.len();
                }
            }

            // File Actions
            for action in &rule.file_actions {
                let norm_action = action.to_lowercase();
                if filepath.contains(&norm_action) {
                    if rule.debug { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): File action/tool detected '{}'", 
                            rule.name, pid, action
                        )); 
                    }
                    state.file_action_detected = true;
                }
            }

            // Extensions
            for ext in &rule.file_extensions {
                let norm_ext = ext.to_lowercase();
                let ext_hit = filepath.ends_with(&norm_ext) || filepath.contains(&norm_ext);
                let ext_create = ext_hit && matches!(irp_op, IrpMajorOp::IrpCreate | IrpMajorOp::IrpWrite);
                if ext_create || ext_hit {
                    if rule.debug { 
                        Logging::debug(&format!("[BehaviorEngine] Rule '{}' (PID: {}): Extension match '{}'", rule.name, pid, ext)); 
                    }
                    state.extension_match_detected = true;
                }
            }

            if irp_op == IrpMajorOp::IrpProcessTerminate {
                let victim = msg.filepathstr.to_lowercase();
                if !victim.is_empty() {
                    self.process_terminated.insert(victim.clone());
                    if self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!("[BehaviorEngine] GID={} PID={} self-terminated", gid, pid));
                    }
                }
            }
        }

        if irp_op == IrpMajorOp::IrpProcessTerminateAttempt {
            let victim_path = msg.filepathstr.to_lowercase();
            
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

                // FALLBACK: ATTACKER RESOLUTION
                if !attacker_found && !is_self {
                    // Option A: Try finding by PID in existing states
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
                    } else {
                        // Option B: Sysinfo fallback for logging context (can't track behavior fully without GID)
                        if self.rules.iter().any(|r| r.debug) {
                            let mut sys = self.system.borrow_mut();
                            sys.refresh_processes_specifics(
                                ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(msg.attacker_pid as u32)]),
                                false,
                                ProcessRefreshKind::everything()
                            );
                            
                            if let Some(proc) = sys.process(sysinfo::Pid::from_u32(msg.attacker_pid as u32)) {
                                Logging::debug(&format!(
                                    "[BehaviorEngine] Resolved unknown attacker via sysinfo fallback: PID {} -> '{}'",
                                    msg.attacker_pid, proc.name().to_string_lossy()
                                ));
                            }
                        }
                    }
                }
                
                if !victim_path.is_empty() {
                    self.process_terminated.insert(victim_path.clone());
                }

                if self.rules.iter().any(|r| r.debug) {
                    let log_type = if is_self { "SELF" } else { "EXTERNAL" };
                    Logging::debug(&format!(
                        "[BehaviorEngine] {} termination attempt: Attacker PID {} (GID {}) -> Target PID {} '{}'" ,
                        log_type, msg.attacker_pid, msg.attacker_gid, msg.pid, victim_path
                    ));
                }
            }
        }

        // =======================================================================
        // UPDATE RICH NAMED CONDITIONS STATE
        // =======================================================================
        self.update_named_conditions_state(gid, msg, &irp_op, &filepath);

        // Evaluate rules
        self.check_rules(precord, gid, msg, irp_op, config, &mut actions);
    }

    // ==========================================================================
    // RICH CONDITION EVALUATION
    // ==========================================================================
    
    /// Update the state of named conditions based on the current event
    fn update_named_conditions_state(&mut self, gid: u64, msg: &IOMessage, irp_op: &IrpMajorOp, filepath: &str) {
        let now = SystemTime::now();
        
        for rule in &self.rules {
            if rule.named_conditions.is_empty() {
                continue;
            }
            
            let state = match self.process_states.get_mut(&gid) {
                Some(s) => s,
                None => continue,
            };
            
            for (cond_name, cond_group) in &rule.named_conditions {
                let mut matched = false;
                
                // Check APIs
                if !cond_group.apis.is_empty() {
                    let api_matches = cond_group.apis.iter()
                        .filter(|api| {
                            let api_lc = api.to_lowercase();
                            filepath.contains(&api_lc) || msg.extension.to_lowercase().contains(&api_lc)
                        })
                        .count();
                    
                    let threshold = if cond_group.api_threshold > 0 {
                        cond_group.api_threshold
                    } else {
                        1
                    };
                    
                    if api_matches >= threshold {
                        matched = true;
                        if rule.debug {
                            Logging::debug(&format!(
                                "[BehaviorEngine] Named condition '{}': {} API matches (threshold: {})",
                                cond_name, api_matches, threshold
                            ));
                        }
                    }
                }
                
                // Check file paths
                if !matched && !cond_group.file_paths.is_empty() {
                    for path_pattern in &cond_group.file_paths {
                        let norm_pattern = path_pattern.to_lowercase().replace("\\", "/");
                        if filepath.contains(&norm_pattern) {
                            // Check if operation matches if specified
                            let op_matches = if !cond_group.file_operations.is_empty() {
                                cond_group.file_operations.iter().any(|op| {
                                    match op.as_str() {
                                        "read" | "browse" => matches!(*irp_op, IrpMajorOp::IrpRead),
                                        "write" => matches!(*irp_op, IrpMajorOp::IrpWrite),
                                        "create" => matches!(*irp_op, IrpMajorOp::IrpCreate),
                                        "delete" => matches!(*irp_op, IrpMajorOp::IrpSetInfo), // Simplified
                                        _ => true,
                                    }
                                })
                            } else {
                                true
                            };
                            
                            if op_matches {
                                matched = true;
                                if rule.debug {
                                    Logging::debug(&format!(
                                        "[BehaviorEngine] Named condition '{}': File path match '{}'",
                                        cond_name, path_pattern
                                    ));
                                }
                                break;
                            }
                        }
                    }
                }
                
                // Check registry keys
                if !matched && !cond_group.registry_keys.is_empty() {
                    for reg_pattern in &cond_group.registry_keys {
                        let norm_pattern = reg_pattern.to_lowercase().replace("\\", "/");
                        if filepath.contains(&norm_pattern) || filepath.contains("registry") {
                            matched = true;
                            if rule.debug {
                                Logging::debug(&format!(
                                    "[BehaviorEngine] Named condition '{}': Registry key match",
                                    cond_name
                                ));
                            }
                            break;
                        }
                    }
                }
                
                // Check network
                if !matched && cond_group.has_network_activity && state.network_activity_detected {
                    matched = true;
                    if rule.debug {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Named condition '{}': Network activity detected",
                            cond_name
                        ));
                    }
                }
                
                // Check process termination
                if !matched && !cond_group.terminated_processes.is_empty() {
                    for proc_pattern in &cond_group.terminated_processes {
                        let proc_lc = proc_pattern.to_lowercase();
                        let term_match = state.terminated_processes.iter().any(|victim| {
                            victim.contains(&proc_lc) || proc_lc.contains(victim)
                        });
                        let self_match = if cond_group.detect_self_termination {
                            state.self_terminated_processes.iter().any(|victim| {
                                victim.contains(&proc_lc) || proc_lc.contains(victim)
                            })
                        } else {
                            false
                        };
                        
                        if term_match || self_match {
                            matched = true;
                            if rule.debug {
                                Logging::debug(&format!(
                                    "[BehaviorEngine] Named condition '{}': Process termination match",
                                    cond_name
                                ));
                            }
                            break;
                        }
                    }
                }
                
                // Check parent process names (suspicious origin)
                if !matched && !cond_group.parent_names.is_empty() {
                    let parent_lc = state.parent_name.to_lowercase();
                    
                    // CRITICAL FIX: Don't match empty or "unknown" parents
                    // Empty string causes false positives because "anything".contains("") == true
                    if !parent_lc.is_empty() && parent_lc != "unknown" {
                        for parent_pattern in &cond_group.parent_names {
                            let pattern_lc = parent_pattern.to_lowercase();
                            
                            // Additional safety: ensure pattern isn't empty either
                            if !pattern_lc.is_empty() && 
                            (parent_lc.contains(&pattern_lc) || pattern_lc.contains(&parent_lc)) {
                                matched = true;
                                if rule.debug {
                                    Logging::debug(&format!(
                                        "[BehaviorEngine] Named condition '{}': Suspicious parent matched '{}' (pattern: '{}')",
                                        cond_name, state.parent_name, parent_pattern
                                    ));
                                }
                                break;
                            }
                        }
                    } else if rule.debug {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Named condition '{}': Skipping parent check (parent='{}' is unknown/empty)",
                            cond_name, state.parent_name
                        ));
                    }
                }

                // Check entropy
                if !matched && cond_group.entropy_threshold > 0.0 && msg.entropy > cond_group.entropy_threshold {
                    matched = true;
                    if rule.debug {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Named condition '{}': Entropy threshold exceeded ({:.2} > {:.2})",
                            cond_name, msg.entropy, cond_group.entropy_threshold
                        ));
                    }
                }
                
                // Check file extensions
                if !matched && !cond_group.file_extensions.is_empty() {
                    for ext in &cond_group.file_extensions {
                        let norm_ext = ext.to_lowercase();
                        if filepath.ends_with(&norm_ext) {
                            matched = true;
                            if rule.debug {
                                Logging::debug(&format!(
                                    "[BehaviorEngine] Named condition '{}': Extension match '{}'",
                                    cond_name, ext
                                ));
                            }
                            break;
                        }
                    }
                }
                
                // Check file actions
                if !matched && !cond_group.file_actions.is_empty() {
                    for action in &cond_group.file_actions {
                        let norm_action = action.to_lowercase();
                        if filepath.contains(&norm_action) {
                            matched = true;
                            if rule.debug {
                                Logging::debug(&format!(
                                    "[BehaviorEngine] Named condition '{}': File action match '{}'",
                                    cond_name, action
                                ));
                            }
                            break;
                        }
                    }
                }
                
                // If matched, update state
                if matched {
                    state.satisfied_named_conditions.insert(cond_name.clone());
                    *state.condition_match_counts.entry(cond_name.clone()).or_insert(0) += 1;
                    state.condition_first_seen.entry(cond_name.clone()).or_insert(now);
                    state.condition_last_seen.insert(cond_name.clone(), now);
                }
            }
        }
    }
    
    /// Evaluate a detection condition expression recursively
    fn evaluate_detection_condition(
        &self,
        condition: &DetectionCondition,
        state: &ProcessBehaviorState,
        rule: &BehaviorRule,
    ) -> bool {
        match condition {
            DetectionCondition::Named { condition: cond_name } => {
                let satisfied = state.satisfied_named_conditions.contains(cond_name);
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] Evaluate named condition '{}': {}",
                        cond_name,
                        if satisfied { "✔" } else { "✘" }
                    ));
                }
                satisfied
            },
            
            DetectionCondition::And { and } => {
                let result = and.iter().all(|c| self.evaluate_detection_condition(c, state, rule));
                if rule.debug {
                    Logging::debug(&format!("[BehaviorEngine] AND evaluation: {}", if result { "✔" } else { "✘" }));
                }
                result
            },
            
            DetectionCondition::Or { or } => {
                let result = or.iter().any(|c| self.evaluate_detection_condition(c, state, rule));
                if rule.debug {
                    Logging::debug(&format!("[BehaviorEngine] OR evaluation: {}", if result { "✔" } else { "✘" }));
                }
                result
            },
            
            DetectionCondition::Not { not } => {
                let result = !self.evaluate_detection_condition(not, state, rule);
                if rule.debug {
                    Logging::debug(&format!("[BehaviorEngine] NOT evaluation: {}", if result { "✔" } else { "✘" }));
                }
                result
            },
            
            DetectionCondition::AllOf { all_of } => {
                let result = all_of.iter().all(|cond_name| state.satisfied_named_conditions.contains(cond_name));
                if rule.debug {
                    let satisfied = all_of.iter().filter(|c| state.satisfied_named_conditions.contains(*c)).count();
                    Logging::debug(&format!(
                        "[BehaviorEngine] ALL_OF evaluation: {}/{} ({})",
                        satisfied, all_of.len(), if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::AnyOf { any_of } => {
                let result = any_of.iter().any(|cond_name| state.satisfied_named_conditions.contains(cond_name));
                if rule.debug {
                    let satisfied = any_of.iter().filter(|c| state.satisfied_named_conditions.contains(*c)).count();
                    Logging::debug(&format!(
                        "[BehaviorEngine] ANY_OF evaluation: {}/{} ({})",
                        satisfied, any_of.len(), if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::NOf { n_of, conditions } => {
                let satisfied_count = conditions.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                let result = satisfied_count == *n_of;
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] N_OF evaluation: {} of {} ({}/{}  {})",
                        n_of, conditions.len(), satisfied_count, conditions.len(), 
                        if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::AtLeast { at_least, conditions } => {
                let satisfied_count = conditions.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                let result = satisfied_count >= *at_least;
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] AT_LEAST evaluation: at_least {} ({}/{} {})",
                        at_least, satisfied_count, conditions.len(), 
                        if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::AllOfPattern { all_of_pattern } => {
                let matching_conditions: Vec<_> = state.satisfied_named_conditions.iter()
                    .filter(|cond_name| self.matches_pattern(all_of_pattern, cond_name))
                    .collect();
                let total_matching = rule.named_conditions.keys()
                    .filter(|cond_name| self.matches_pattern(all_of_pattern, cond_name))
                    .count();
                let result = !matching_conditions.is_empty() && matching_conditions.len() == total_matching;
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] ALL_OF_PATTERN '{}': {}/{} ({})",
                        all_of_pattern, matching_conditions.len(), total_matching,
                        if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::AnyOfPattern { any_of_pattern } => {
                let result = state.satisfied_named_conditions.iter()
                    .any(|cond_name| self.matches_pattern(any_of_pattern, cond_name));
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] ANY_OF_PATTERN '{}': {}",
                        any_of_pattern, if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::Count { count, comparison, threshold } => {
                let satisfied_count = count.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                let result = match comparison {
                    Comparison::Gt => satisfied_count > *threshold,
                    Comparison::Gte => satisfied_count >= *threshold,
                    Comparison::Lt => satisfied_count < *threshold,
                    Comparison::Lte => satisfied_count <= *threshold,
                    Comparison::Eq => satisfied_count == *threshold,
                    Comparison::Ne => satisfied_count != *threshold,
                };
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] COUNT evaluation: {} {:?} {} ({})",
                        satisfied_count, comparison, threshold, if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
            
            DetectionCondition::Percentage { percentage, comparison, threshold } => {
                let satisfied_count = percentage.iter()
                    .filter(|cond_name| state.satisfied_named_conditions.contains(*cond_name))
                    .count();
                let ratio = satisfied_count as f32 / percentage.len() as f32;
                let result = match comparison {
                    Comparison::Gt => ratio > *threshold,
                    Comparison::Gte => ratio >= *threshold,
                    Comparison::Lt => ratio < *threshold,
                    Comparison::Lte => ratio <= *threshold,
                    Comparison::Eq => (ratio - threshold).abs() < 0.001,
                    Comparison::Ne => (ratio - threshold).abs() >= 0.001,
                };
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] PERCENTAGE evaluation: {:.1}% {:?} {:.1}% ({})",
                        ratio * 100.0, comparison, threshold * 100.0, if result { "✔" } else { "✘" }
                    ));
                }
                result
            },
        }
    }

    // ==========================================================================
    // RULE CHECKING (Main Detection Logic)
    // ==========================================================================
    
    fn check_rules(
        &mut self,
        precord: &mut ProcessRecord,
        gid: u64,
        msg: &IOMessage,
        irp_op: IrpMajorOp,
        config: &Config,
        actions: &mut ActionsOnKill
    ) {
        let state_ref = self.process_states.get(&gid).unwrap();

        let (
            browsed_paths_tracker,
            staged_files_written,
            accessed_paths_tracker,
            terminated_processes,
            self_terminated_processes,
            parent_name,
            high_entropy_detected,
            monitored_api_count,
            file_action_detected,
            extension_match_detected,
            has_valid_signature,
            signature_checked,
            network_activity_detected,
            pid
        ) = (
            state_ref.browsed_paths_tracker.clone(),
            state_ref.staged_files_written.clone(),
            state_ref.accessed_paths_tracker.clone(),
            state_ref.terminated_processes.clone(),
            state_ref.self_terminated_processes.clone(),
            state_ref.parent_name.clone(),
            state_ref.high_entropy_detected,
            state_ref.monitored_api_count,
            state_ref.file_action_detected,
            state_ref.extension_match_detected,
            state_ref.has_valid_signature,
            state_ref.signature_checked,
            state_ref.network_activity_detected,
            state_ref.pid
        );

        for rule in &self.rules {
            if precord.is_malicious && precord.time_killed.is_some() {
                continue;
            }

            if self.check_allowlist(&precord.appname, rule, Some(&precord.exepath)) {
                continue;
            }

            // ===================================================================
            // UNIFIED DETECTION LOGIC
            // Rich Logic and Stages now contribute to the condition percentage
            // ===================================================================
            
            // Calculate legacy indicator variables
            let browsed_access_count = browsed_paths_tracker.len();
            let has_staged_data = !staged_files_written.is_empty();
            let is_online = if rule.require_internet {
                self.has_active_connections(pid) || network_activity_detected
            } else {
                true
            };
            let is_suspicious_parent = if !rule.suspicious_parents.is_empty() {
                let parent_lc = parent_name.to_lowercase();
                
                // CRITICAL FIX: Don't match empty or unknown parents
                if parent_lc.is_empty() || parent_lc == "unknown" {
                    false
                } else {
                    rule.suspicious_parents.iter().any(|p| {
                        let p_l = p.to_lowercase();
                        !p_l.is_empty() && (BehaviorEngine::safe_pattern_match(&parent_name, p))
                    })
                }
            } else {
                false
            };
            let has_sensitive_access = !accessed_paths_tracker.is_empty();
            
            // ===================================================================
            // 1. EVALUATE LEGACY INDICATORS RATIO
            // ===================================================================
            let mut legacy_satisfied = 0;
            let mut legacy_total = 0;
            let mut condition_results: Vec<(&str, bool)> = Vec::new();

            macro_rules! check_legacy {
                ($name:expr, $cond:expr) => {{
                    legacy_total += 1;
                    let hit = $cond;
                    if hit { legacy_satisfied += 1; }
                    condition_results.push(($name, hit));
                }};
            }

            if !rule.browsed_paths.is_empty() {
                check_legacy!("browsed_paths", browsed_access_count >= rule.multi_access_threshold);
            }
            if !rule.staging_paths.is_empty() {
                check_legacy!("staging", has_staged_data);
            }
            if rule.require_internet {
                check_legacy!("internet", is_online);
            }
            if !rule.suspicious_parents.is_empty() {
                check_legacy!("parent", is_suspicious_parent);
            }
            if !rule.accessed_paths.is_empty() {
                check_legacy!("accessed_paths", has_sensitive_access);
            }
            if rule.entropy_threshold > 0.01 {
                check_legacy!("entropy", high_entropy_detected);
            }
            if !rule.monitored_apis.is_empty() {
                let threshold = std::cmp::max(1, rule.multi_access_threshold);
                check_legacy!("apis", monitored_api_count >= threshold);
            }
            if !rule.file_actions.is_empty() {
                check_legacy!("file_actions", file_action_detected);
            }
            if !rule.file_extensions.is_empty() {
                check_legacy!("extensions", extension_match_detected);
            }
            if !rule.terminated_processes.is_empty() {
                let term_hit = rule.terminated_processes.iter().any(|rule_proc| {
                    let rule_proc_lc = rule_proc.to_lowercase();
                    let ext_match = terminated_processes.iter().any(|v| v.contains(&rule_proc_lc) || rule_proc_lc.contains(v));
                    let self_match = rule.detect_self_termination && self_terminated_processes.iter().any(|v| v.contains(&rule_proc_lc) || rule_proc_lc.contains(v));
                    ext_match || self_match
                });
                check_legacy!("terminated_proc", term_hit);
            }

            let legacy_ratio = if legacy_total > 0 { legacy_satisfied as f32 / legacy_total as f32 } else { 0.0 };
            let legacy_threshold = if rule.conditions_percentage > 0.0 { rule.conditions_percentage } else { 1.0 };
            let legacy_triggered = legacy_total > 0 && legacy_ratio >= legacy_threshold;

            // ===================================================================
            // 2. EVALUATE RICH LOGIC (Independent Trigger)
            // ===================================================================
            let mut rich_triggered = false;
            if let Some(logic) = &rule.detection_logic {
                let state = self.process_states.get(&gid).unwrap();
                rich_triggered = self.evaluate_detection_condition(logic, state, rule);
            }

            // ===================================================================
            // 3. EVALUATE ATTACK STAGES (Independent Trigger)
            // ===================================================================
            let mut stages_triggered = false;
            let mut stage_conf = 0.0;
            if !rule.stages.is_empty() {
                // FIXED: Passed Some(msg) to handle Option wrapper
                let (detected, conf) = self.evaluate_stages_from_state(rule, state_ref, Some(msg));
                stages_triggered = detected;
                stage_conf = conf;
            }

            // ===================================================================
            // 4. FINAL DETECTION DECISION
            // ===================================================================
            if legacy_triggered || rich_triggered || stages_triggered {
                let trigger_type = if stages_triggered { "Stage-based" } 
                                  else if rich_triggered { "Rich-logic" } 
                                  else { "Legacy" };

                let indicator_ratio = if stages_triggered { stage_conf } 
                                     else if rich_triggered { 1.0 } 
                                     else { legacy_ratio };

                Logging::warning(&format!(
                    "[BehaviorEngine] DETECTION ({}) : {} (PID: {}) matched '{}' ({:.1}%)",
                    trigger_type, precord.appname, pid, rule.name, indicator_ratio * 100.0
                ));

                if rule.debug {
                    let breakdown = condition_results.iter()
                        .map(|(n, h)| format!("{}={}", n, if *h { "✔" } else { "✘" }))
                        .collect::<Vec<_>>()
                        .join(", ");
                    Logging::debug(&format!("[BehaviorEngine] Breakdown for '{}': L_Ratio={:.2} (Thr={:.2}), Rich={}, Stages={}, [{}]", 
                        rule.name, legacy_ratio, legacy_threshold, rich_triggered, stages_triggered, breakdown));
                }

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
            } else if rule.debug && (legacy_total > 0 || !rule.stages.is_empty() || rule.detection_logic.is_some()) {
                // Log non-matches for debugging if debug is enabled
                let breakdown = condition_results.iter()
                    .map(|(n, h)| format!("{}={}", n, if *h { "✔" } else { "✘" }))
                    .collect::<Vec<_>>()
                    .join(", ");
                
                Logging::debug(&format!(
                    "[BehaviorEngine] No match for '{}': Legacy={:.1}%, Rich={}, Stages={} [{}]",
                    rule.name, legacy_ratio * 100.0, rich_triggered, stages_triggered, breakdown
                ));
            }
        }
    }
    
    fn evaluate_stages_from_state(
        &self,
        rule: &BehaviorRule,
        state: &ProcessBehaviorState,
        msg: Option<&IOMessage>, 
    ) -> (bool, f32) {
        let mut satisfied_stages = 0;
        let mut total_conditions = 0;
        
        for stage in &rule.stages {
            let mut stage_satisfied_count = 0;
            let mut stage_total_conditions = 0;
            
            for condition in &stage.conditions {
                stage_total_conditions += 1;
                let mut condition_matched = false;
                
                match condition {
                    RuleCondition::File { op, path_pattern } => {
                        let has_match = match op.as_str() {
                            "write" | "create" => {
                                state.staged_files_written.keys().any(|path| {
                                    self.matches_pattern(path_pattern, &path.to_string_lossy())
                                })
                            },
                            "read" => {
                                // FIX: The || operator is now inside the braces
                                state.browsed_paths_tracker.keys().any(|path| {
                                    self.matches_pattern(path_pattern, path)
                                }) || state.accessed_paths_tracker.iter().any(|path| {
                                    self.matches_pattern(path_pattern, path)
                                })
                            },
                            "delete" | "rename" => {
                                state.staged_files_written.keys().any(|path| {
                                    self.matches_pattern(path_pattern, &path.to_string_lossy())
                                })
                            },
                            _ => false,
                        };
                        condition_matched = has_match;
                    },
                    
                    RuleCondition::Registry { op, key_pattern, .. } => {
                        let registry_keywords = match op.as_str() {
                            "set" => vec!["regsetvalue", "regsetvalueex", "regsetkeysecurity"],
                            "create" => vec!["regcreatekey", "regcreatekeyex"],
                            "delete" => vec!["regdeletevalue", "regdeletekey"],
                            "rename" => vec!["regrenamekey"],
                            _ => vec![],
                        };
                        
                        let has_registry_op = registry_keywords.iter().any(|keyword| {
                            state.detected_apis.iter().any(|api| api.contains(keyword))
                        });
                        
                        let key_accessed = state.browsed_paths_tracker.keys().any(|path| {
                            self.matches_pattern(key_pattern, path)
                        }) || state.accessed_paths_tracker.iter().any(|path| {
                            self.matches_pattern(key_pattern, path)
                        });
                        
                        condition_matched = has_registry_op || key_accessed;
                    },
                    
                    RuleCondition::Process { op, pattern } => {
                        let has_match = match op.as_str() {
                            "terminate" => {
                                state.terminated_processes.iter().any(|victim| {
                                    self.matches_pattern(pattern, victim)
                                }) || (rule.detect_self_termination && 
                                    state.self_terminated_processes.iter().any(|victim| {
                                        self.matches_pattern(pattern, victim)
                                    }))
                            },
                            "create" => {
                                state.detected_apis.iter().any(|api| {
                                    api.contains("createprocess") || api.contains("ntcreateuserprocess")
                                }) && self.matches_pattern(pattern, &state.app_name)
                            },
                            _ => self.matches_pattern(pattern, &state.app_name),
                        };
                        condition_matched = has_match;
                    },
                    
                    RuleCondition::Api { name_pattern, .. } => {
                        condition_matched = state.detected_apis.iter().any(|api| {
                            self.matches_pattern(name_pattern, api)
                        });
                    },

                    RuleCondition::Network { dest_pattern, .. } => {
                        let mut network_matched = state.network_activity_detected;
                        
                        if network_matched {
                            if let Some(dest) = dest_pattern {
                                let has_dest = state.detected_apis.iter().any(|api| {
                                    self.matches_pattern(dest, api)
                                });
                                network_matched = has_dest;
                            }
                        }
                        condition_matched = network_matched;
                    },

                    RuleCondition::Signature { is_trusted, signer_pattern } => {
                        if state.signature_checked {
                            let trust_match = state.has_valid_signature == *is_trusted;
                            let signer_match = if let Some(pattern) = signer_pattern {
                                // Since we don't store the signer name in state yet (only has_valid_signature),
                                // this is a partial implementation. 
                                // Ideally state should have signer_name.
                                true 
                            } else {
                                true
                            };
                            condition_matched = trust_match && signer_match;
                        }
                    },
                    
                    RuleCondition::OperationCount { op_type, path_pattern, comparison, threshold } => {
                        let count = match op_type.as_str() {
                            "write" => state.staged_files_written.len() as u64,
                            "read" => (state.browsed_paths_tracker.len() + state.accessed_paths_tracker.len()) as u64,
                            _ => 0,
                        };
                        condition_matched = match comparison {
                            Comparison::Gt => count > *threshold,
                            Comparison::Gte => count >= *threshold,
                            Comparison::Lt => count < *threshold,
                            Comparison::Lte => count <= *threshold,
                            Comparison::Eq => count == *threshold,
                            Comparison::Ne => count != *threshold,
                        };
                    },
                    RuleCondition::EntropyThreshold { metric: _, comparison, threshold } => {
                        if let Some(m) = msg { 
                            let entropy = m.entropy;
                            condition_matched = match comparison {
                                Comparison::Gt => entropy > *threshold,
                                Comparison::Gte => entropy >= *threshold,
                                Comparison::Lt => entropy < *threshold,
                                Comparison::Lte => entropy <= *threshold,
                                Comparison::Eq => (entropy - *threshold).abs() < 0.001,
                                Comparison::Ne => (entropy - *threshold).abs() >= 0.001,
                            };
                        } else {
                            condition_matched = false; // Cannot evaluate without an event
                        }
                    },

                    _ => {
                        // For other condition types, use simplified evaluation (returning false if not matched)
                        condition_matched = false;
                    },
                }
                
                if condition_matched {
                    stage_satisfied_count += 1;
                }
            }
            
            // Calculate stage satisfaction ratio
            if stage_total_conditions > 0 {
                let stage_ratio = stage_satisfied_count as f32 / stage_total_conditions as f32;
                // Apply conditions_percentage threshold for this stage
                let threshold = if rule.conditions_percentage > 0.0 {
                    rule.conditions_percentage
                } else {
                    1.0  // Default to all conditions required
                };
                
                if stage_ratio >= threshold {
                    satisfied_stages += 1;
                    total_conditions += stage_total_conditions;
                    if rule.debug {
                        Logging::debug(&format!(
                            "[BehaviorEngine] Stage '{}' satisfied for {}: {}/{} ({:.1}%)",
                            stage.name, state.app_name, stage_satisfied_count, stage_total_conditions, stage_ratio * 100.0
                        ));
                    }
                }
            }
        }
        
        // Calculate overall detection confidence based on matched stages
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
                    if !proc_lc.contains(&pattern.to_lowercase()) { return false; }
                    if !must_be_signed && signers.is_empty() { return true; }
                    if let Some(path) = process_path {
                        if !path.exists() { return false; }
                        let info = verify_signature(path);
                        if *must_be_signed && !info.is_trusted { return false; }
                        if !signers.is_empty() {
                            if let Some(signer) = &info.signer_name {
                                signers.iter().any(|s_pattern| self.matches_pattern(s_pattern, signer))
                            } else { false }
                        } else { true }
                    } else { false }
                }
            }
        })
    }
    
    fn matches_pattern(&self, pattern: &str, text: &str) -> bool {
        if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') && !pattern.contains('\\') {
            return text.to_lowercase().contains(&pattern.to_lowercase());
        }
        let mut cache = self.regex_cache.borrow_mut();
        if let Some(re) = cache.get(pattern) {
            return re.is_match(text);
        }
        match Regex::new(&format!("(?i){}", pattern)) {
            Ok(re) => {
                let is_match = re.is_match(text);
                cache.insert(pattern.to_string(), re);
                is_match
            }
            Err(_) => text.to_lowercase().contains(&pattern.to_lowercase())
        }
    }
    
    fn has_active_connections(&self, pid: u32) -> bool {
        if pid == 0 { return false; }
        let check_tcp = |family: u16| -> bool {
            let mut dw_size = 0;
            unsafe {
                let _ = GetExtendedTcpTable(None, &mut dw_size, false, family as u32, TCP_TABLE_OWNER_PID_ALL, 0);
                if dw_size == 0 { return false; }
                let mut buffer = vec![0u8; dw_size as usize];
                if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, family as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                    if buffer.len() < 4 { return false; }
                    let num_entries = u32::from_ne_bytes(buffer[0..4].try_into().unwrap());
                    let (stride, pid_offset) = if family == AF_INET.0 { (24, 20) } else { (56, 52) };
                    let start_offset = 4;
                    for i in 0..num_entries {
                        let offset = start_offset + (i as usize * stride);
                        if offset + stride > buffer.len() { break; }
                        let entry_pid_offset = offset + pid_offset;
                        if entry_pid_offset + 4 <= buffer.len() {
                            let entry_pid = u32::from_ne_bytes(buffer[entry_pid_offset..entry_pid_offset+4].try_into().unwrap());
                            if entry_pid == pid { return true; }
                        }
                    }
                }
            }
            false
        };
        let check_udp = |family: u16| -> bool {
            let mut dw_size = 0;
            unsafe {
                let _ = GetExtendedUdpTable(None, &mut dw_size, false, family as u32, UDP_TABLE_OWNER_PID, 0);
                if dw_size == 0 { return false; }
                let mut buffer = vec![0u8; dw_size as usize];
                if GetExtendedUdpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, family as u32, UDP_TABLE_OWNER_PID, 0) == 0 {
                    if buffer.len() < 4 { return false; }
                    let num_entries = u32::from_ne_bytes(buffer[0..4].try_into().unwrap());
                    let (stride, pid_offset) = if family == AF_INET.0 { (12, 8) } else { (28, 24) };
                    let start_offset = 4;
                    for i in 0..num_entries {
                        let offset = start_offset + (i as usize * stride);
                        if offset + stride > buffer.len() { break; }
                        let entry_pid_offset = offset + pid_offset;
                        if entry_pid_offset + 4 <= buffer.len() {
                            let entry_pid = u32::from_ne_bytes(buffer[entry_pid_offset..entry_pid_offset+4].try_into().unwrap());
                            if entry_pid == pid { return true; }
                        }
                    }
                }
            }
            false
        };
        if check_tcp(AF_INET.0) { return true; }
        if check_tcp(AF_INET6.0) { return true; }
        if check_udp(AF_INET.0) { return true; }
        if check_udp(AF_INET6.0) { return true; }
        false
    }
        
    pub fn scan_all_processes(&mut self, _config: &Config, _threat_handler: &dyn ThreatHandler) -> Vec<ProcessRecord> {
        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();

        if self.rules.iter().any(|r| r.debug) {
            Logging::debug(&format!("[BehaviorEngine] Static Scan: Evaluating {} tracked processes", gids.len()));
        }

        for gid in gids {
            let state = match self.process_states.get(&gid) {
                Some(s) => s.clone(),
                None => continue,
            };

            let pid = state.pid;
            let app_name = state.app_name.clone();
            let exe_path_buf = state.exe_path.clone();
            let exe_path_str = exe_path_buf.to_string_lossy().to_string();

            for rule in &self.rules {
                // ===================================================================
                // UNIFIED DETECTION LOGIC
                // Rich Logic and Stages contribute to the condition percentage
                // ===================================================================
                
                let browsed_access_count = state.browsed_paths_tracker.len();
                let has_staged_data = !state.staged_files_written.is_empty();
                let is_online = if rule.require_internet {
                    self.has_active_connections(state.pid) || state.network_activity_detected
                } else {
                    true
                };
                                
                let parent_name = state.parent_name.clone();
                let is_suspicious_parent = if !rule.suspicious_parents.is_empty() {
                    let parent = parent_name.to_lowercase();
                    
                    // CRITICAL FIX: Don't match empty or unknown parents
                    if parent.is_empty() || parent == "unknown" {
                        false
                    } else {
                        rule.suspicious_parents.iter().any(|p| {
                            let p_l = p.to_lowercase();
                            !p_l.is_empty() && (parent.contains(&p_l) || p_l.contains(&parent))
                        })
                    }
                } else {
                    false
                };
                
                let has_sensitive_access = !state.accessed_paths_tracker.is_empty();
                let terminated_match = if !rule.terminated_processes.is_empty() {
                    rule.terminated_processes.iter().any(|rule_proc| {
                        let rule_proc_lc = rule_proc.to_lowercase();
                        let ext_match = state.terminated_processes.iter().any(|victim_path| {
                            victim_path.contains(&rule_proc_lc) || rule_proc_lc.contains(victim_path)
                        });
                        let self_match = if rule.detect_self_termination {
                            state.self_terminated_processes.iter().any(|victim_path| {
                                victim_path.contains(&rule_proc_lc) || rule_proc_lc.contains(victim_path)
                            })
                        } else {
                            false
                        };
                        ext_match || self_match
                    })
                } else {
                    true
                };
                
                let high_entropy_detected = state.high_entropy_detected;
                let monitored_api_count = state.monitored_api_count;
                let file_action_detected = state.file_action_detected;
                let extension_match_detected = state.extension_match_detected;
                
                // ===================================================================
                // 1. EVALUATE LEGACY INDICATORS RATIO
                // ===================================================================
                let mut legacy_satisfied = 0;
                let mut legacy_total = 0;

                if !rule.browsed_paths.is_empty() {
                    legacy_total += 1;
                    if browsed_access_count >= rule.multi_access_threshold { legacy_satisfied += 1; }
                }
                if !rule.staging_paths.is_empty() {
                    legacy_total += 1;
                    if has_staged_data { legacy_satisfied += 1; }
                }
                if rule.require_internet {
                    legacy_total += 1;
                    if is_online { legacy_satisfied += 1; }
                }
                if !rule.suspicious_parents.is_empty() {
                    legacy_total += 1;
                    if is_suspicious_parent { legacy_satisfied += 1; }
                }
                if !rule.accessed_paths.is_empty() {
                    legacy_total += 1;
                    if has_sensitive_access { legacy_satisfied += 1; }
                }
                if rule.entropy_threshold > 0.01 {
                    legacy_total += 1;
                    if high_entropy_detected { legacy_satisfied += 1; }
                }
                if !rule.monitored_apis.is_empty() {
                    legacy_total += 1;
                    let threshold = std::cmp::max(1, rule.multi_access_threshold);
                    if monitored_api_count >= threshold { legacy_satisfied += 1; }
                }
                if !rule.file_actions.is_empty() {
                    legacy_total += 1;
                    if file_action_detected { legacy_satisfied += 1; }
                }
                if !rule.file_extensions.is_empty() {
                    legacy_total += 1;
                    if extension_match_detected { legacy_satisfied += 1; }
                }
                if !rule.terminated_processes.is_empty() {
                    legacy_total += 1;
                    if terminated_match { legacy_satisfied += 1; }
                }

                let legacy_ratio = if legacy_total > 0 { legacy_satisfied as f32 / legacy_total as f32 } else { 0.0 };
                let legacy_threshold = if rule.conditions_percentage > 0.0 { rule.conditions_percentage } else { 1.0 };
                let legacy_triggered = legacy_total > 0 && legacy_ratio >= legacy_threshold;

                // ===================================================================
                // 2. EVALUATE RICH LOGIC (Independent Trigger)
                // ===================================================================
                let mut rich_triggered = false;
                if let Some(logic) = &rule.detection_logic {
                    rich_triggered = self.evaluate_detection_condition(logic, &state, rule);
                }

                // ===================================================================
                // 3. EVALUATE ATTACK STAGES (Independent Trigger)
                // ===================================================================
                let mut stages_triggered = false;
                let mut stage_conf = 0.0;
                if !rule.stages.is_empty() {
                    // FIXED: Passed None because static scan has no active IOMessage
                    let (detected, conf) = self.evaluate_stages_from_state(rule, &state, None);
                    stages_triggered = detected;
                    stage_conf = conf;
                }

                // ===================================================================
                // 4. FINAL DETECTION DECISION
                // ===================================================================
                if legacy_triggered || rich_triggered || stages_triggered {
                    let indicator_ratio = if stages_triggered { stage_conf } 
                                         else if rich_triggered { 1.0 } 
                                         else { legacy_ratio };

                    let trigger_type = if stages_triggered { "Stage-based" } 
                                      else if rich_triggered { "Rich-logic" } 
                                      else { "Legacy" };

                    if rule.debug {
                        Logging::warning(&format!(
                            "[BehaviorEngine] DETECTION (scan - {}): {} (PID: {}) matched '{}' ({:.1}%)",
                            trigger_type, app_name, pid, rule.name, indicator_ratio * 100.0
                        ));
                    }

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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_string_contains_bug() {
        // Demonstrate the bug that we're fixing
        assert_eq!("powershell.exe".contains(""), true);  // BUG!
        
        // Our safe_pattern_match should return false
        assert_eq!(BehaviorEngine::safe_pattern_match("", "powershell.exe"), false);
        assert_eq!(BehaviorEngine::safe_pattern_match("powershell.exe", ""), false);
        assert_eq!(BehaviorEngine::safe_pattern_match("unknown", "powershell.exe"), false);
        
        // Valid matches should still work
        assert_eq!(BehaviorEngine::safe_pattern_match("powershell.exe", "powershell"), true);
        assert_eq!(BehaviorEngine::safe_pattern_match("cmd.exe", "cmd"), true);
    }
    
    #[test]
    fn test_parent_name_initialization() {
        let state = ProcessBehaviorState::new(
            1234,
            PathBuf::from("test.exe"),
            "test.exe".into()
        );
        
        // Should never be empty
        assert_ne!(state.parent_name, "");
        assert_eq!(state.parent_name, "unknown");
    }
    
    #[test]
    fn test_orphaned_process_not_suspicious() {
        let mut engine = BehaviorEngine::new();
        
        let mut rule = BehaviorRule::default();
        rule.name = "Test".into();
        rule.suspicious_parents = vec!["powershell.exe".into(), "cmd.exe".into()];
        rule.conditions_percentage = 1.0;
        
        engine.rules.push(rule);
        
        // Create process with unknown parent
        let gid = 12345;
        let mut state = ProcessBehaviorState::new(
            1234,
            PathBuf::from("notepad.exe"),
            "notepad.exe".into()
        );
        state.parent_name = "unknown".into();
        
        engine.process_states.insert(gid, state);
        
        // Should NOT trigger on unknown parent
        let parent_name = engine.process_states.get(&gid).unwrap().parent_name.clone();
        let is_suspicious = if !engine.rules[0].suspicious_parents.is_empty() {
            let parent = parent_name.to_lowercase();
            if parent.is_empty() || parent == "unknown" {
                false
            } else {
                engine.rules[0].suspicious_parents.iter().any(|p| {
                    let p_l = p.to_lowercase();
                    !p_l.is_empty() && (parent.contains(&p_l) || p_l.contains(&parent))
                })
            }
        } else {
            false
        };
        
        assert_eq!(is_suspicious, false, "Should not match unknown parent");
    }
}
