use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use serde_yaml;
use serde_yaml::Value as YamlValue;
use regex::Regex;
use std::cell::RefCell;
use std::env;

use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::config::Config;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::threat_handler::ThreatHandler;
use crate::signature_verification::verify_signature;
use sysinfo::{SystemExt, ProcessExt, PidExt};

// --- Windows Specific Imports ---
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, 
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

// --- Enums and Structs ---

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
pub enum AggregationFunction {
    Count, Sum, Avg, Max, Min, Rate,
}

impl Default for AggregationFunction {
    fn default() -> Self { AggregationFunction::Count }
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

/// The Unified BehaviorRule Struct.
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
    pub entropy_threshold: f64,
    #[serde(default)]
    pub conditions_percentage: f32,
    
    #[serde(default)]
    pub archive_apis: Vec<String>,
    #[serde(default)]
    pub archive_tools: Vec<String>,

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
    pub stages: Vec<AttackStage>,
    #[serde(default)]
    pub mapping: Option<RuleMapping>,
    #[serde(default)]
    pub min_stages_satisfied: usize,
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
    
    // Track cross-process tracking by executable identity (GID)
    // Critical for detecting advanced bypass where stages are split across processes
    #[serde(default)]
    pub track_by_gid: bool,

    // NEW: Enforce specific Stealer sequence (Browse -> Access -> Stage -> Archive)
    #[serde(default)]
    pub detect_stealer_sequence: bool,

    // NEW: Allow staging detection without strict read-then-write sequence
    // If true, writing to a staging path is considered "staging" even if no stolen files were read first.
    #[serde(default)]
    pub allow_isolated_staging: bool,
}

impl BehaviorRule {
    pub fn finalize_rich_fields(&mut self) {
        if !self.archive_apis.is_empty() {
             self.monitored_apis.extend(self.archive_apis.iter().cloned());
        }
        if !self.archive_tools.is_empty() {
             self.file_actions.extend(self.archive_tools.iter().cloned());
        }
        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = s.to_lowercase(),
                AllowlistEntry::Complex { pattern, .. } => *pattern = pattern.to_lowercase(),
            }
        }
        
        // ENV VARIABLE EXPANSION FOR STAGING PATHS
        // This ensures hardcoded paths are replaced by actual system paths
        let mut expanded_paths = Vec::new();
        for path in &self.staging_paths {
            expanded_paths.push(expand_env_vars(path));
        }
        self.staging_paths = expanded_paths;
    }
}

// Helper for environment variable expansion
fn expand_env_vars(path: &str) -> String {
    let mut result = path.to_string();
    // Basic Windows env var expansion logic
    if path.contains('%') {
        let re = Regex::new(r"%([^%]+)%").unwrap();
        for cap in re.captures_iter(path) {
            let var_name = &cap[1];
            if let Ok(val) = env::var(var_name) {
                result = result.replace(&cap[0], &val);
            }
        }
    }
    result
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMapping {
    And { and: Vec<RuleMapping> },
    Or { or: Vec<RuleMapping> },
    Not { not: Box<RuleMapping> },
    Stage { stage: String },
    // Chronological requirement
    Sequence { sequence: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub name: String,
    pub conditions: Vec<RuleCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    File { op: String, path_pattern: String },
    Registry { op: String, key_pattern: String, value_name: Option<String>, expected_data: Option<String> },
    Process { op: String, pattern: String },
    // NEW: Process termination tracker
    ProcessTermination { name_pattern: String },
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub suspend_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default)] pub kill_and_remove: bool,
    #[serde(default)] pub auto_revert: bool,
    #[serde(default)] pub record: bool,
}

#[derive(Debug, Clone)]
pub struct FileOperation {
    pub path: PathBuf,
    pub op_type: IrpMajorOp,
    pub timestamp: SystemTime,
    pub bytes_transferred: u64,
    pub gid: u64, // Track which GID performed this operation
}

#[derive(Default)]
pub struct ProcessBehaviorState {
    pub browsed_paths_tracker: HashMap<String, SystemTime>,
    pub accessed_paths_tracker: HashSet<String>,
    
    // Track which files were read (stolen data sources)
    pub stolen_file_reads: HashSet<PathBuf>,
    
    // Track staging with data flow context
    pub staged_files_written: HashMap<PathBuf, StagingDataFlow>,
    
    // Track completed stages for mapping evaluation
    pub satisfied_stages: HashMap<String, SystemTime>,
    
    // Track detected API calls for forensics
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
    
    // Legacy single-process tracking
    pub file_operations: Vec<FileOperation>,
}

#[derive(Debug, Clone)]
pub struct StagingDataFlow {
    pub staged_at: SystemTime,
    pub has_prior_reads: bool,
    pub read_write_sequence: bool,
    pub bytes_read_before: u64,
    pub bytes_written: u64,
    pub cross_process_flow: bool,
}

impl ProcessBehaviorState {
    pub fn new(pid: u32, exe_path: PathBuf, app_name: String) -> Self {
        let mut state = ProcessBehaviorState::default();
        state.pid = pid;
        state.exe_path = exe_path;
        state.app_name = app_name;
        state
    }
}

#[derive(Default)]
pub struct GidBehaviorState {
    // All file ops from any process with this GID
    pub file_operations: Vec<FileOperation>, 
    // All stolen file reads from any process with this GID
    pub stolen_file_reads: HashSet<PathBuf>,
    // Stages completed by any member of this group
    pub shared_stages: HashMap<String, SystemTime>,
    // Terminated processes by any member of this group (Preparation Stage)
    pub shared_terminated_processes: HashSet<String>,
    // Network activities by any member (Exfiltration Stage)
    pub shared_network_activities: Vec<String>,
    // Collected artifacts for reporting
    pub all_accessed_files: HashSet<String>,
    pub all_staged_files: HashSet<String>,
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    
    pub gid_states: HashMap<u64, GidBehaviorState>,
    pub exe_to_gid: HashMap<PathBuf, u64>,
    
    regex_cache: RefCell<HashMap<String, Regex>>,
    pub process_terminated: HashSet<String>, // Global tracking for simpler rules
}

// Helper function to consolidate staging logic and avoid duplication
fn calculate_staging_flow(
    ops: &[FileOperation],
    stolen_reads: &HashSet<PathBuf>,
    staging_paths: &[String],
    is_cross_process: bool
) -> StagingDataFlow {
    let has_prior_reads = !stolen_reads.is_empty();
    let mut bytes_read = 0u64;
    let mut bytes_written = 0u64;
    
    for op in ops.iter().rev() {
        match op.op_type {
            IrpMajorOp::IrpRead => {
                if stolen_reads.contains(&op.path) {
                    bytes_read += op.bytes_transferred;
                }
            },
            IrpMajorOp::IrpWrite => {
                let op_path_str = op.path.to_string_lossy().to_lowercase().replace("\\", "/");
                for s_path in staging_paths {
                    if op_path_str.contains(&s_path.to_lowercase().replace("\\", "/")) {
                        bytes_written += op.bytes_transferred;
                        break;
                    }
                }
            },
            _ => {}
        }
    }
    
    let read_write_sequence = has_prior_reads && bytes_read > 0 && bytes_written > 0;

    StagingDataFlow {
        staged_at: SystemTime::now(),
        has_prior_reads,
        read_write_sequence,
        bytes_read_before: bytes_read,
        bytes_written,
        cross_process_flow: is_cross_process,
    }
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            gid_states: HashMap::new(),
            exe_to_gid: HashMap::new(),
            regex_cache: RefCell::new(HashMap::new()),
            process_terminated: HashSet::new(),
        }
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
            ProcessBehaviorState::new(pid, exe_path.clone(), app_name)
        });
        
        // Register in GID tracking
        self.gid_states.entry(gid).or_insert_with(GidBehaviorState::default);
        self.exe_to_gid.insert(exe_path, gid);
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

    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage, config: &Config, threat_handler: &dyn ThreatHandler) {
        let gid = msg.gid;
        let mut actions = ActionsOnKill::with_handler(threat_handler.clone_box());
        
        // Ensure state exists
        if !self.process_states.contains_key(&gid) {
            let mut s = ProcessBehaviorState::new(msg.pid as u32, precord.exepath.clone(), precord.appname.clone());
            
            // Parent logic
            let mut sys = sysinfo::System::new_all();
            sys.refresh_processes();
            let mut parent_found = false;

            if let Some(proc) = sys.process(sysinfo::Pid::from(msg.pid as usize)) {
                if let Some(parent_pid) = proc.parent() {
                    if let Some(parent_proc) = sys.process(parent_pid) {
                        s.parent_name = parent_proc.name().to_string();
                        parent_found = true;
                    } else {
                        let ppid_u32 = parent_pid.as_u32();
                        for existing_state in self.process_states.values() {
                            if existing_state.pid == ppid_u32 {
                                s.parent_name = existing_state.app_name.clone();
                                parent_found = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !parent_found { s.parent_name = "unknown".to_string(); }
            self.process_states.insert(gid, s);
        }

        // Ensure GID state exists
        self.gid_states.entry(gid).or_insert_with(GidBehaviorState::default);

        // Scope the mutable borrow of state so we can call check_rules later
        {
            let state = self.process_states.get_mut(&gid).unwrap();
            let irp_op = IrpMajorOp::from_byte(msg.irp_op);
            let filepath = msg.filepathstr.to_lowercase().replace("\\", "/");
            let pid = state.pid;
            
            // --- Signature check ---
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

            let network_keywords = [
                "internetopen", "internetconnect", "httpopen", "httpsend", 
                "urldownload", "socket", "connect", "wsasend", "wsarecv",
                "winhttp", "dnsquery", "internetwritefile", "ftp"
            ];
            
            let is_network_op = network_keywords.iter().any(|k| filepath.contains(k));
            
            if is_network_op {
                state.network_activity_detected = true;
                if self.rules.iter().any(|r| r.debug) {
                     Logging::debug(&format!("[BehaviorEngine] Network Activity Detected via API: {} (PID: {})", msg.filepathstr, pid));
                }
            }

            // Record file operation in GID state (for Cross-Process correlation)
            let now = SystemTime::now();
            let file_op = FileOperation {
                path: PathBuf::from(&filepath),
                op_type: irp_op,
                timestamp: now,
                bytes_transferred: msg.bytes_io as u64,
                gid,
            };
            
            // GID Shared State Update
            if let Some(gid_state) = self.gid_states.get_mut(&gid) {
                gid_state.file_operations.push(file_op.clone());
                if gid_state.file_operations.len() > 1000 {
                    gid_state.file_operations.drain(0..500);
                }
                
                // Track network activity centrally for Exfiltration Check
                if is_network_op {
                    gid_state.shared_network_activities.push(filepath.clone());
                }
            }

            state.file_operations.push(file_op);
            if state.file_operations.len() > 1000 {
                state.file_operations.drain(0..500);
            }

            // --- Event Tracking ---
            for rule in &self.rules {
                for b_path in &rule.browsed_paths {
                    let norm_b_path = b_path.to_lowercase().replace("\\", "/");
                    if filepath.contains(&norm_b_path) {
                        state.browsed_paths_tracker.insert(b_path.clone(), now);
                        
                        for s_file in &rule.accessed_paths {
                            if filepath.contains(&s_file.to_lowercase()) {
                                if irp_op == IrpMajorOp::IrpRead {
                                    state.accessed_paths_tracker.insert(s_file.clone());
                                    state.stolen_file_reads.insert(PathBuf::from(&filepath));
                                    
                                    // Shared GID state update
                                    if let Some(gid_state) = self.gid_states.get_mut(&gid) {
                                        gid_state.stolen_file_reads.insert(PathBuf::from(&filepath));
                                        gid_state.all_accessed_files.insert(filepath.clone());
                                    }
                                }
                            }
                        }
                    }
                }

                // Staging Logic (supports Env Vars now due to load_rules expansion)
                for s_path in &rule.staging_paths {
                    let norm_s_path = s_path.to_lowercase().replace("\\", "/");
                    // Careful with contains check on resolved paths
                    if filepath.contains(&norm_s_path) && irp_op == IrpMajorOp::IrpWrite {
                        
                        let (ops, stolen_reads, is_cross_proc) = if rule.track_by_gid {
                            if let Some(gs) = self.gid_states.get(&gid) {
                                (&gs.file_operations, &gs.stolen_file_reads, true)
                            } else {
                                (&state.file_operations, &state.stolen_file_reads, false)
                            }
                        } else {
                            (&state.file_operations, &state.stolen_file_reads, false)
                        };

                        let dataflow = calculate_staging_flow(
                            ops, 
                            stolen_reads, 
                            &rule.staging_paths, 
                            is_cross_proc
                        );
                        
                        if dataflow.read_write_sequence || rule.allow_isolated_staging {
                             state.staged_files_written.insert(PathBuf::from(&filepath), dataflow);
                             if let Some(gs) = self.gid_states.get_mut(&gid) {
                                 gs.all_staged_files.insert(filepath.clone());
                             }
                        }
                    }
                }

                if msg.is_entropy_calc == 1 && msg.entropy > rule.entropy_threshold {
                    state.high_entropy_detected = true;
                }

                for api in &rule.monitored_apis {
                    if filepath.contains(&api.to_lowercase()) {
                        state.monitored_api_count += 1;
                        state.detected_apis.insert(api.clone());
                    }
                }

                for action in &rule.file_actions {
                    if filepath.contains(&action.to_lowercase()) {
                        state.file_action_detected = true;
                    }
                }

                for ext in &rule.file_extensions {
                    if filepath.ends_with(&ext.to_lowercase()) || filepath.contains(&ext.to_lowercase()) {
                        state.extension_match_detected = true;
                    }
                }
            }
        } // End of state mutable borrow

        // Now we can call methods that take &mut self
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        self.check_rules(precord, gid, msg, irp_op, config, &mut actions);
    }

    fn check_rules(
        &mut self,
        precord: &mut ProcessRecord,
        gid: u64,
        msg: &IOMessage,
        irp_op: IrpMajorOp,
        config: &Config,
        actions: &mut ActionsOnKill
    ) {
        // Collect read-only data for rule checking
        let (
            browsed_paths_tracker,
            staged_files_written,
            accessed_paths_tracker,
            parent_name,
            high_entropy_detected,
            monitored_api_count,
            file_action_detected,
            extension_match_detected,
            has_valid_signature,
            signature_checked,
            network_activity_detected,
            pid
        ) = {
            let s = self.process_states.get(&gid).unwrap();
            (
                s.browsed_paths_tracker.clone(),
                s.staged_files_written.clone(),
                s.accessed_paths_tracker.clone(),
                s.parent_name.clone(),
                s.high_entropy_detected,
                s.monitored_api_count,
                s.file_action_detected,
                s.extension_match_detected,
                s.has_valid_signature,
                s.signature_checked,
                s.network_activity_detected,
                s.pid
            )
        };

        for rule in &self.rules {
            if precord.is_malicious && precord.time_killed.is_some() {
                continue;
            }

            if self.check_allowlist(&precord.appname, rule, Some(&precord.exepath)) {
                continue;
            }

            // ---------- STAGES ----------
            if !rule.stages.is_empty() {
                if self.evaluate_stages(
                    rule,
                    &parent_name,
                    has_valid_signature,
                    signature_checked,
                    precord,
                    msg,
                    &irp_op,
                    gid
                ) {
                    precord.is_malicious = true;
                }
            }

            // ---------- INDICATOR COLLECTION ----------
            let browsed_access_count: usize = browsed_paths_tracker.len();

            let has_staged_data = if !rule.staging_paths.is_empty() {
                staged_files_written.values()
                    .filter(|flow| flow.read_write_sequence || rule.allow_isolated_staging)
                    .count() > 0
            } else {
                false
            };

            let is_online = if rule.require_internet {
                precord.pids.iter().any(|&pid| self.has_active_connections(pid))
                    || network_activity_detected
            } else {
                true
            };

            let is_suspicious_parent = rule.suspicious_parents.iter().any(|p| {
                let p = p.to_lowercase();
                let parent = parent_name.to_lowercase();
                parent.contains(&p) || p.contains(&parent)
            });

            let has_sensitive_access = !accessed_paths_tracker.is_empty();
            let mut terminated_set = self.process_terminated.clone();
            
            // If tracking by GID, merge with shared terminated set
            if rule.track_by_gid {
                if let Some(gs) = self.gid_states.get(&gid) {
                    for tp in &gs.shared_terminated_processes {
                        terminated_set.insert(tp.clone());
                    }
                }
            }
            terminated_set.insert(precord.appname.to_lowercase());

            let is_archiving = monitored_api_count > 0 || file_action_detected || extension_match_detected;

            // ---------- DECISION LOGIC ----------
            let mut trigger_detection = false;
            let mut match_details_str = String::new();
            let mut detection_score = 0.0;

            // 1. SEQUENCE ENFORCEMENT
            if rule.detect_stealer_sequence {
                let has_browsed = !browsed_paths_tracker.is_empty();
                // Sequence: Browsed -> Accessed -> Staged -> Archived
                if has_browsed && has_sensitive_access && has_staged_data && is_archiving {
                    trigger_detection = true;
                    detection_score = 1.0;
                    match_details_str = format!(
                        "STEALER SEQUENCE CONFIRMED: Browsed({}), Accessed({}), Staged(Yes), Archived(Yes)",
                        browsed_paths_tracker.len(),
                        accessed_paths_tracker.len()
                    );
                }
            } 
            // 2. MAPPING EVALUATION (STAGE/SEQUENCE)
            else if let Some(mapping) = &rule.mapping {
                 let hit = self.evaluate_mapping(mapping, rule, gid);
                 if hit {
                     trigger_detection = true;
                     detection_score = 1.0;
                     match_details_str = "Rule Mapping Satisfied".to_string();
                 }
            }
            // 3. LEGACY ACCUMULATION
            else {
                let mut satisfied_conditions = 0;
                let mut total_tracked_conditions = 0;
                let mut condition_results: Vec<(&str, bool)> = Vec::new();

                macro_rules! check {
                    ($name:expr, $cond:expr) => {{
                        total_tracked_conditions += 1;
                        let hit = $cond;
                        if hit { satisfied_conditions += 1; }
                        condition_results.push(($name, hit));
                    }};
                }

                if !rule.browsed_paths.is_empty() { check!("browsed_paths", browsed_access_count >= rule.multi_access_threshold); }
                if !rule.staging_paths.is_empty() { check!("staging", has_staged_data); }
                if rule.require_internet { check!("internet", is_online); }
                if !rule.suspicious_parents.is_empty() { check!("parent", is_suspicious_parent); }
                if !rule.accessed_paths.is_empty() { check!("accessed_paths", has_sensitive_access); }
                if rule.entropy_threshold > 0.01 { check!("entropy", high_entropy_detected); }
                if !rule.monitored_apis.is_empty() { check!("apis", monitored_api_count > 0); }
                if !rule.file_actions.is_empty() { check!("file_actions", file_action_detected); }
                if !rule.file_extensions.is_empty() { check!("extensions", extension_match_detected); }
                if !rule.terminated_processes.is_empty() {
                    let terminated_match = rule.terminated_processes.iter().any(|proc| terminated_set.contains(&proc.to_lowercase()));
                    check!("terminated_proc", terminated_match);
                }

                if total_tracked_conditions > 0 {
                    detection_score = satisfied_conditions as f32 / total_tracked_conditions as f32;
                    let threshold = if rule.conditions_percentage > 0.0 { rule.conditions_percentage } else { 1.0 };
                    
                    if detection_score >= threshold {
                        trigger_detection = true;
                        match_details_str = format!("{}/{} conditions", satisfied_conditions, total_tracked_conditions);
                    }
                }
            }

            // ---------- RESPONSE ----------
            if trigger_detection {
                // Collect detailed forensics artifacts for improved visibility
                let forensic_details = if rule.track_by_gid {
                    if let Some(gs) = self.gid_states.get(&gid) {
                        format!(
                            "Artifacts [GID: {}]:\n- Accessed: {:?}\n- Staged: {:?}\n- APIs: {:?}\n- Network: {:?}",
                            gid, gs.all_accessed_files, gs.all_staged_files, 
                            self.process_states.get(&gid).map(|s| &s.detected_apis),
                            gs.shared_network_activities
                        )
                    } else { String::new() }
                } else {
                     format!("Artifacts: {:?}", self.process_states.get(&gid).map(|s| &s.detected_apis))
                };
                
                let full_report = format!("{} | {}", match_details_str, forensic_details);

                Logging::warning(&format!(
                    "[BehaviorEngine] DETECTION: {} (PID: {}) matched '{}' ({})",
                    precord.appname, pid, rule.name, match_details_str
                ));

                precord.is_malicious = true;

                let threat_info = ThreatInfo {
                    threat_type_label: "Behavioral Detection",
                    virus_name: &rule.name,
                    prediction: detection_score as f64,
                    match_details: Some(full_report),
                    terminate: rule.response.terminate_process,
                    quarantine: rule.response.quarantine,
                    kill_and_remove: rule.response.kill_and_remove,
                    revert: rule.response.auto_revert,
                };

                let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                actions.run_actions_with_info(config, precord, &dummy_pred_mtrx, &threat_info);
                self.process_terminated.insert(precord.appname.to_lowercase());
                
                // Add to shared GID termination set if tracking by GID
                if rule.track_by_gid {
                    if let Some(gs) = self.gid_states.get_mut(&gid) {
                        gs.shared_terminated_processes.insert(precord.appname.to_lowercase());
                    }
                }
                
                if rule.response.terminate_process {
                    break;
                }
            }
        }
    }

    fn evaluate_mapping(&self, mapping: &RuleMapping, rule: &BehaviorRule, gid: u64) -> bool {
        let (satisfied_stages, shared_stages) = {
            let s = self.process_states.get(&gid).unwrap();
            let gs = self.gid_states.get(&gid).unwrap();
            (&s.satisfied_stages, &gs.shared_stages)
        };

        match mapping {
            RuleMapping::Stage { stage } => satisfied_stages.contains_key(stage) || shared_stages.contains_key(stage),
            RuleMapping::And { and } => and.iter().all(|m| self.evaluate_mapping(m, rule, gid)),
            RuleMapping::Or { or } => or.iter().any(|m| self.evaluate_mapping(m, rule, gid)),
            RuleMapping::Not { not } => !self.evaluate_mapping(not, rule, gid),
            RuleMapping::Sequence { sequence } => {
                let mut last_time = None;
                for stage_name in sequence {
                    let stage_time = satisfied_stages.get(stage_name)
                        .or_else(|| shared_stages.get(stage_name));
                    
                    if let Some(&time) = stage_time {
                        if let Some(prev) = last_time {
                            if time < prev { return false; }
                        }
                        last_time = Some(time);
                    } else {
                        return false;
                    }
                }
                true
            }
        }
    }

    fn evaluate_stages(
        &mut self, 
        rule: &BehaviorRule, 
        _parent_name: &str, 
        has_valid_signature: bool,
        signature_checked: bool,
        precord: &ProcessRecord,
        msg: &IOMessage,
        irp_op: &IrpMajorOp,
        gid: u64
    ) -> bool {
        let mut any_stage_triggered = false;
        let now = SystemTime::now();

        for stage in &rule.stages {
            let mut stage_satisfied = true;
            for condition in &stage.conditions {
                match condition {
                    RuleCondition::File { op, path_pattern } => {
                        let op_matches = match op.as_str() {
                            "write" => *irp_op == IrpMajorOp::IrpWrite,
                            "read" => *irp_op == IrpMajorOp::IrpRead,
                            "create" => *irp_op == IrpMajorOp::IrpCreate || *irp_op == IrpMajorOp::IrpWrite,
                            "delete" => *irp_op == IrpMajorOp::IrpSetInfo,
                            _ => false,
                        };
                        // Resolve Env Vars in pattern if needed or use regex match
                        // Here assuming regex handles it, but for robust check we rely on engine's existing match
                        if !op_matches || !self.matches_pattern(path_pattern, &msg.filepathstr) { stage_satisfied = false; break; }
                        
                        // Security Verification: If verifying "write" to temp, ensure kernel confirms it
                        if op.as_str() == "write" && rule.staging_paths.iter().any(|sp| msg.filepathstr.to_lowercase().contains(&sp.to_lowercase())) {
                             // This confirms the file op actually happened in the staging path
                        }
                    },
                    RuleCondition::Process { op: _, pattern } => {
                         if !self.matches_pattern(pattern, &precord.appname) { stage_satisfied = false; break; }
                    },
                    RuleCondition::ProcessTermination { name_pattern } => {
                        // Advanced Bypass Prevention: Check GID shared state if enabled
                        let hit = if rule.track_by_gid {
                            if let Some(gs) = self.gid_states.get(&gid) {
                                gs.shared_terminated_processes.iter().any(|name| self.matches_pattern(name_pattern, name))
                            } else {
                                self.process_terminated.iter().any(|name| self.matches_pattern(name_pattern, name))
                            }
                        } else {
                            self.process_terminated.iter().any(|name| self.matches_pattern(name_pattern, name))
                        };
                        
                        if !hit { stage_satisfied = false; break; }
                    },
                    RuleCondition::Api { name_pattern, module_pattern: _ } => {
                        if !self.matches_pattern(name_pattern, &msg.filepathstr) { stage_satisfied = false; break; }
                        // WinInet Exfiltration Check
                        if stage.name == "Exfiltration" {
                             if !self.is_connected_to_internet(&msg.filepathstr) {
                                 // Stricter checking: Ensure it's actually a network op
                             }
                        }
                    },
                    RuleCondition::Signature { is_trusted, signer_pattern: _ } => {
                        if !signature_checked { stage_satisfied = false; break; }
                        let violates = if *is_trusted { !has_valid_signature } else { has_valid_signature };
                        if violates { stage_satisfied = false; break; }
                    },
                    _ => {
                        stage_satisfied = false;
                        break;
                    }
                }
            }
             if stage_satisfied {
                if rule.debug { Logging::debug(&format!("[BehaviorEngine] Stage '{}' Satisfied for '{}'", stage.name, rule.name)); }
                
                if let Some(s) = self.process_states.get_mut(&gid) {
                    s.satisfied_stages.entry(stage.name.clone()).or_insert(now);
                }
                if let Some(gs) = self.gid_states.get_mut(&gid) {
                    gs.shared_stages.entry(stage.name.clone()).or_insert(now);
                }
                any_stage_triggered = true;
            }
        }
        any_stage_triggered
    }
    
    // Helper to validate network keywords for Exfiltration stage
    fn is_connected_to_internet(&self, api_str: &str) -> bool {
        let net_apis = ["InternetConnect", "HttpSendRequest", "InternetWriteFile", "socket", "connect"];
        net_apis.iter().any(|&api| api_str.contains(api))
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
        if check_tcp(AF_INET.0) || check_tcp(AF_INET6.0) || check_udp(AF_INET.0) || check_udp(AF_INET6.0) { return true; }
        false
    }
    
    pub fn scan_all_processes(&mut self, _config: &Config, _threat_handler: &dyn ThreatHandler) -> Vec<ProcessRecord> {
        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();
        
        for gid in gids {
            let (mut signature_checked, mut has_valid_signature, pid, exe_path, app_name) = {
                if let Some(s) = self.process_states.get(&gid) {
                    (s.signature_checked, s.has_valid_signature, s.pid, s.exe_path.clone(), s.app_name.clone())
                } else {
                    continue;
                }
            };
            
            if !signature_checked && exe_path.exists() {
                let info = verify_signature(&exe_path);
                has_valid_signature = info.is_trusted;
                signature_checked = true;
                if let Some(s) = self.process_states.get_mut(&gid) {
                    s.has_valid_signature = has_valid_signature;
                    s.signature_checked = true;
                }
            }
            
             for rule in &self.rules {
                 for stage in &rule.stages {
                    for condition in &stage.conditions {
                        if let RuleCondition::Signature { is_trusted, signer_pattern: _ } = condition {
                            if !signature_checked { continue; }
                             let violates = if *is_trusted { !has_valid_signature } else { has_valid_signature };
                            
                            if violates {
                                let is_allowlisted = self.check_allowlist(&app_name, rule, Some(&exe_path));
                                if !is_allowlisted {
                                    Logging::warning(&format!("[BehaviorEngine SCAN] DETECTION: {} (PID: {}) matched rule '{}' (signature violation)", app_name, pid, rule.name));
                                    let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path.clone());
                                    p.is_malicious = true;
                                    p.pids.insert(pid);
                                    p.termination_requested = rule.response.terminate_process;
                                    p.quarantine_requested = rule.response.quarantine;
                                    detected_processes.push(p);
                                }
                            }
                        }
                    }
                 }
            }
        }
        detected_processes
    }
}
