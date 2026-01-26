use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use serde_yaml;
use serde_yaml::Value as YamlValue;
use regex::Regex;
use std::cell::RefCell;

use crate::shared_def::{IOMessage, IrpMajorOp, FileChangeInfo};
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
    pub detect_self_termination: bool,

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
}

impl BehaviorRule {
    pub fn finalize_rich_fields(&mut self) {
        for entry in &mut self.allowlisted_apps {
            match entry {
                AllowlistEntry::Simple(s) => *s = s.to_lowercase(),
                AllowlistEntry::Complex { pattern, .. } => *pattern = pattern.to_lowercase(),
            }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleMapping {
    And { and: Vec<RuleMapping> },
    Or { or: Vec<RuleMapping> },
    Not { not: Box<RuleMapping> },
    Stage { stage: String },
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

#[derive(Default)]
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
}

impl ProcessBehaviorState {
    pub fn new(pid: u32, exe_path: PathBuf, app_name: String) -> Self {
        let mut state = ProcessBehaviorState::default();
        state.pid = pid;
        state.exe_path = exe_path;
        state.app_name = app_name;
        state.self_terminated_processes = HashSet::new();
        state.terminated_processes = HashSet::new();
        state.detected_apis = HashSet::new();
        state
    }
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    regex_cache: RefCell<HashMap<String, Regex>>,
    pub process_terminated: HashSet<String>,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
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

    // MODIFIED: Takes &dyn ThreatHandler to match worker.rs, creates ActionsOnKill internally
    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage, config: &Config, threat_handler: &dyn ThreatHandler) {
        let gid = msg.gid;
        let mut actions = ActionsOnKill::with_handler(threat_handler.clone_box());
        
        // Ensure state exists
        if !self.process_states.contains_key(&gid) {
            let mut s = ProcessBehaviorState::new(msg.pid as u32, precord.exepath.clone(), precord.appname.clone());
            
            // Parent logic: rely on kernel msg.parent_pid instead of sysinfo snapshot
            let parent_pid = msg.parent_pid as u32; 
            let mut parent_found = false;

            // Resolve parent name from internal state tracker
            // We iterate because states are keyed by GID, but we need to match by PID
            for existing_state in self.process_states.values() {
                if existing_state.pid == parent_pid {
                    s.parent_name = existing_state.app_name.clone();
                    parent_found = true;
                    break;
                }
            }

            if !parent_found { s.parent_name = "unknown".to_string(); }
            self.process_states.insert(gid, s);
        }

        let state = self.process_states.get_mut(&gid).unwrap();
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        // Consistently normalize path for matching: lowercase, forward slashes, trim trailing slashes
        let filepath = msg.filepathstr.to_lowercase().replace("\\", "/");
        let norm_filepath = filepath.trim_end_matches('/');
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

        // --- Network (same as before) ---
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

        // --- Event Tracking ---
        for rule in &self.rules {
            // Browsed Paths (record the browse)
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
                    // keep timestamp of last browse (existing structure)
                    state.browsed_paths_tracker.insert(b_path.clone(), SystemTime::now());
                }
            }

            // FIX: accessed_paths must be independent of browsed_paths
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

            // Staging (broadened to include write/create/rename operations)
            for s_path in &rule.staging_paths {
                let norm_s_path = s_path.to_lowercase().replace("\\", "/");
                let norm_s_path = norm_s_path.trim_end_matches('/');
                let is_staging_op = match irp_op {
                    IrpMajorOp::IrpWrite | IrpMajorOp::IrpCreate | IrpMajorOp::IrpSetInfo => true,
                    _ => false,
                };
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
            if msg.is_entropy_calc == 1 && msg.entropy > rule.entropy_threshold {
                if rule.debug { 
                    Logging::debug(&format!(
                        "[BehaviorEngine] Rule '{}' (PID: {}): High entropy {:.2} > {:.2}", 
                        rule.name, pid, msg.entropy, rule.entropy_threshold
                    )); 
                }
                state.high_entropy_detected = true;
            }

            // Monitored APIs
            // Match against both filepath and extension field (which may contain registry value info)
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

            // File Actions (tools / actions)
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

            // Extensions: prefer creation operations but keep previous behavior for compatibility
            for ext in &rule.file_extensions {
                let norm_ext = ext.to_lowercase();
                let ext_hit = filepath.ends_with(&norm_ext) || filepath.contains(&norm_ext);
                let ext_create = ext_hit && (irp_op == IrpMajorOp::IrpCreate || irp_op == IrpMajorOp::IrpWrite);
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
                    // global (keep existing behavior)
                    self.process_terminated.insert(victim.clone());

                    // We DON'T add to state.terminated_processes here because this event 
                    // is for the process itself dying. Crediting itself for self-termination 
                    // is what caused the false positive.
                    
                    if self.rules.iter().any(|r| r.debug) {
                        Logging::debug(&format!(
                            "[BehaviorEngine] GID={} PID={} self-terminated",
                            gid, pid
                        ));
                    }
                }
            }
        }
        // Drop the mutable borrow of `state` here (end of the loop scope)

        if irp_op == IrpMajorOp::IrpProcessTerminateAttempt {
            let victim_path = msg.filepathstr.to_lowercase();
            
            if msg.attacker_pid != 0 {
                // Determine if this is self-termination or external
                let is_self = msg.attacker_pid == msg.pid;
                
                // Track this in the ATTACKER's state
                if msg.attacker_gid != 0 {
                    if let Some(attacker_state) = self.process_states.get_mut(&msg.attacker_gid) {
                        if !victim_path.is_empty() {
                            if is_self {
                                attacker_state.self_terminated_processes.insert(victim_path.clone());
                            } else {
                                attacker_state.terminated_processes.insert(victim_path.clone());
                            }
                        }
                    }
                }
                
                // Also track globally
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

        // Now evaluate rules for this event (original logic)
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
        // Capture reference to state for use in method calls
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

        let now = SystemTime::now();

        for rule in &self.rules {
            if precord.is_malicious && precord.time_killed.is_some() {
                continue;
            }

            if self.check_allowlist(&precord.appname, rule, Some(&precord.exepath)) {
                continue;
            }

            // ---------- STAGES ----------
            if !rule.stages.is_empty() {
                if self.evaluate_stages_from_state(rule, state_ref) {
                    precord.is_malicious = true;
                }
            }

            // ---------- ACCUMULATION ----------
            let browsed_access_count: usize = browsed_paths_tracker.len();

            let has_staged_data = !staged_files_written.is_empty();

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

            // ---------- CONDITION TRACKING ----------
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

            if !rule.browsed_paths.is_empty() {
                check!(
                    "browsed_paths",
                    browsed_access_count >= rule.multi_access_threshold
                );
            }
    
            if !rule.staging_paths.is_empty() {
                check!("staging", has_staged_data);
            }

            if rule.require_internet {
                check!("internet", is_online);
            }

            if !rule.suspicious_parents.is_empty() {
                check!("parent", is_suspicious_parent);
            }

            if !rule.accessed_paths.is_empty() {
                check!("accessed_paths", has_sensitive_access);
            }

            if rule.entropy_threshold > 0.01 {
                check!("entropy", high_entropy_detected);
            }

            if !rule.monitored_apis.is_empty() {
                check!("apis", monitored_api_count > 0);
            }

            if !rule.file_actions.is_empty() {
                check!("file_actions", file_action_detected);
            }

            if !rule.file_extensions.is_empty() {
                check!("extensions", extension_match_detected);
            }

            if !rule.terminated_processes.is_empty() {
                // Correct check: has the actor killed any of the processes in the rule list?
                let terminated_match = rule.terminated_processes.iter().any(|rule_proc| {
                    let rule_proc_lc = rule_proc.to_lowercase();
                    
                    // Check external terminations
                    let ext_match = terminated_processes.iter().any(|victim_path| {
                        victim_path.contains(&rule_proc_lc) || rule_proc_lc.contains(victim_path)
                    });

                    // Check self-terminations only if explicitly allowed by the rule
                    let self_match = if rule.detect_self_termination {
                        self_terminated_processes.iter().any(|victim_path| {
                            victim_path.contains(&rule_proc_lc) || rule_proc_lc.contains(victim_path)
                        })
                    } else {
                        false
                    };

                    ext_match || self_match
                });
                check!("terminated_proc", terminated_match);
            }

            // ---------- DEBUG OUTPUT ----------
            if rule.debug && total_tracked_conditions > 0 {
                let breakdown = condition_results.iter()
                    .map(|(n, h)| format!("{}={}", n, if *h { "✔" } else { "✘" }))
                    .collect::<Vec<_>>()
                    .join(", ");

                Logging::debug(&format!(
                    "[BehaviorEngine] Rule '{}' for {}: {}/{} [{}] (Online: {})",
                    rule.name,
                    precord.appname,
                    satisfied_conditions,
                    total_tracked_conditions,
                    breakdown,
                    is_online
                ));
            }

            // ---------- DECISION ----------
            if total_tracked_conditions > 0 {
                let ratio = satisfied_conditions as f32 / total_tracked_conditions as f32;
                let threshold = if rule.conditions_percentage > 0.0 {
                    rule.conditions_percentage
                } else {
                    1.0
                };

                if ratio >= threshold {
                    Logging::warning(&format!(
                        "[BehaviorEngine] DETECTION: {} (PID: {}) matched '{}' ({:.1}%)",
                        precord.appname,
                        pid,
                        rule.name,
                        ratio * 100.0
                    ));

                    precord.is_malicious = true;

                    let threat_info = ThreatInfo {
                        threat_type_label: "Behavioral Detection",
                        virus_name: &rule.name,
                        prediction: ratio,
                        match_details: Some(format!(
                            "{}/{} conditions ({:.1}%)",
                            satisfied_conditions,
                            total_tracked_conditions,
                            ratio * 100.0
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
    }

    /// Evaluate stages based on accumulated state during static scans
    fn evaluate_stages_from_state(
        &self,
        rule: &BehaviorRule,
        state: &ProcessBehaviorState
    ) -> bool {
        let mut satisfied_stages = 0;
        
        for stage in &rule.stages {
            let mut stage_satisfied = true;
            
            for condition in &stage.conditions {
                match condition {
                    RuleCondition::File { op, path_pattern } => {
                        // Check accumulated file operations based on op type
                        let has_match = match op.as_str() {
                            "write" | "create" => {
                                state.staged_files_written.keys().any(|path| {
                                    self.matches_pattern(path_pattern, &path.to_string_lossy())
                                })
                            },
                            "read" => {
                                state.browsed_paths_tracker.keys().any(|path| {
                                    self.matches_pattern(path_pattern, path)
                                }) || state.accessed_paths_tracker.iter().any(|path| {
                                    self.matches_pattern(path_pattern, path)
                                })
                            },
                            "delete" => {
                                // File deletions are tracked in staged_files_written during delete operations
                                state.staged_files_written.keys().any(|path| {
                                    self.matches_pattern(path_pattern, &path.to_string_lossy())
                                })
                            },
                            "rename" => {
                                // File renames are tracked in staged_files_written during rename operations
                                state.staged_files_written.keys().any(|path| {
                                    self.matches_pattern(path_pattern, &path.to_string_lossy())
                                })
                            },
                            _ => false,
                        };
                        if !has_match { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::Registry { op, key_pattern, value_name, expected_data } => {
                        // Registry operations are tracked via monitored_apis and detected_apis
                        // Check if registry operation pattern matches any detected API calls
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
                        
                        // Also check if the key_pattern was accessed (tracked in browsed/accessed paths)
                        let key_accessed = state.browsed_paths_tracker.keys().any(|path| {
                            self.matches_pattern(key_pattern, path)
                        }) || state.accessed_paths_tracker.iter().any(|path| {
                            self.matches_pattern(key_pattern, path)
                        });
                        
                        if !has_registry_op && !key_accessed {
                            stage_satisfied = false;
                            break;
                        }
                        
                        // Note: value_name and expected_data checks would require more detailed tracking
                        // For static scans, we can only verify the operation type and key pattern
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
                                // Process creation is tracked via detected_apis (CreateProcess, etc.)
                                state.detected_apis.iter().any(|api| {
                                    api.contains("createprocess") || api.contains("ntcreateuserprocess")
                                }) && self.matches_pattern(pattern, &state.app_name)
                            },
                            _ => self.matches_pattern(pattern, &state.app_name),
                        };
                        if !has_match { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::Service { op, name_pattern } => {
                        // Service operations tracked via detected_apis
                        let service_keywords = match op.as_str() {
                            "create" => vec!["createservice"],
                            "start" => vec!["startservice"],
                            "stop" => vec!["stopservice"],
                            "delete" => vec!["deleteservice"],
                            _ => vec!["service"],
                        };
                        
                        let has_service_op = service_keywords.iter().any(|keyword| {
                            state.detected_apis.iter().any(|api| api.contains(keyword))
                        });
                        
                        if !has_service_op {
                            stage_satisfied = false;
                            break;
                        }
                    },
                    
                    RuleCondition::Network { op, dest_pattern } => {
                        // Network activity is tracked via network_activity_detected flag
                        if !state.network_activity_detected {
                            stage_satisfied = false;
                            break;
                        }
                        
                        // If specific destination pattern is required, check detected_apis
                        if let Some(dest) = dest_pattern {
                            let has_dest = state.detected_apis.iter().any(|api| {
                                self.matches_pattern(dest, api)
                            });
                            if !has_dest {
                                stage_satisfied = false;
                                break;
                            }
                        }
                    },
                    
                    RuleCondition::Api { name_pattern, module_pattern } => {
                        let has_api = state.detected_apis.iter().any(|api| {
                            self.matches_pattern(name_pattern, api) &&
                            self.matches_pattern(module_pattern, api)
                        });
                        if !has_api { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::Heuristic { metric, threshold } => {
                        // Heuristics are tracked via state flags
                        let metric_value = match metric.as_str() {
                            "entropy" => if state.high_entropy_detected { 1.0 } else { 0.0 },
                            "api_count" => state.monitored_api_count as f64,
                            "file_access_count" => state.accessed_paths_tracker.len() as f64,
                            "browsed_count" => state.browsed_paths_tracker.len() as f64,
                            "staged_count" => state.staged_files_written.len() as f64,
                            _ => 0.0,
                        };
                        
                        if metric_value < *threshold {
                            stage_satisfied = false;
                            break;
                        }
                    },
                    
                    RuleCondition::OperationCount { op_type, path_pattern, comparison, threshold } => {
                        // Count operations from accumulated state
                        let count = match op_type.as_str() {
                            "read" => state.browsed_paths_tracker.len() + state.accessed_paths_tracker.len(),
                            "write" | "create" => state.staged_files_written.len(),
                            _ => 0,
                        };
                        
                        // Apply path_pattern filter if specified
                        let filtered_count = if let Some(pattern) = path_pattern {
                            match op_type.as_str() {
                                "read" => {
                                    state.browsed_paths_tracker.keys().filter(|p| self.matches_pattern(pattern, p)).count() +
                                    state.accessed_paths_tracker.iter().filter(|p| self.matches_pattern(pattern, p)).count()
                                },
                                "write" | "create" => {
                                    state.staged_files_written.keys()
                                        .filter(|p| self.matches_pattern(pattern, &p.to_string_lossy()))
                                        .count()
                                },
                                _ => 0,
                            }
                        } else {
                            count
                        };
                        
                        let matches = match comparison {
                            Comparison::Gt => filtered_count > *threshold as usize,
                            Comparison::Gte => filtered_count >= *threshold as usize,
                            Comparison::Lt => filtered_count < *threshold as usize,
                            Comparison::Lte => filtered_count <= *threshold as usize,
                            Comparison::Eq => filtered_count == *threshold as usize,
                            Comparison::Ne => filtered_count != *threshold as usize,
                        };
                        
                        if !matches { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::ExtensionPattern { patterns, match_mode, op_type } => {
                        // Check if files with matching extensions were accessed
                        let matching_count = match op_type.as_str() {
                            "write" | "create" => {
                                state.staged_files_written.keys()
                                    .filter(|p| {
                                        if let Some(ext) = p.extension() {
                                            let ext_str = ext.to_string_lossy().to_lowercase();
                                            patterns.iter().any(|pat| {
                                                let pat_lc = pat.trim_start_matches('.').to_lowercase();
                                                ext_str == pat_lc
                                            })
                                        } else {
                                            false
                                        }
                                    })
                                    .count()
                            },
                            _ => {
                                state.browsed_paths_tracker.keys()
                                    .filter(|p| {
                                        patterns.iter().any(|pat| {
                                            let pat_lc = pat.to_lowercase();
                                            p.to_lowercase().ends_with(&pat_lc)
                                        })
                                    })
                                    .count()
                            },
                        };
                        
                        let matches = match match_mode {
                            MatchMode::All => matching_count == patterns.len(),
                            MatchMode::Any => matching_count > 0,
                            MatchMode::Count(n) => matching_count == *n,
                            MatchMode::AtLeast(n) => matching_count >= *n,
                        };
                        
                        if !matches { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::EntropyThreshold { metric, comparison, threshold } => {
                        // Entropy is tracked via high_entropy_detected flag
                        let entropy_detected = state.high_entropy_detected;
                        let matches = match comparison {
                            Comparison::Gte => entropy_detected, // If detected, it exceeded the threshold
                            _ => entropy_detected,
                        };
                        if !matches { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::FileCount { category, comparison, threshold } => {
                        let count = match category.as_str() {
                            "accessed" => state.accessed_paths_tracker.len() as u64,
                            "browsed" => state.browsed_paths_tracker.len() as u64,
                            "staged" => state.staged_files_written.len() as u64,
                            _ => 0,
                        };
                        
                        let matches = match comparison {
                            Comparison::Gt => count > *threshold,
                            Comparison::Gte => count >= *threshold,
                            Comparison::Lt => count < *threshold,
                            Comparison::Lte => count <= *threshold,
                            Comparison::Eq => count == *threshold,
                            Comparison::Ne => count != *threshold,
                        };
                        
                        if !matches { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::Signature { is_trusted, signer_pattern } => {
                        if !state.signature_checked {
                            stage_satisfied = false;
                            break;
                        }
                        if *is_trusted != state.has_valid_signature {
                            stage_satisfied = false;
                            break;
                        }
                        // Note: signer_pattern would require storing signer info in state
                        if signer_pattern.is_some() {
                            // Cannot verify signer pattern in static scan without extended state
                            stage_satisfied = false;
                            break;
                        }
                    },
                    
                    RuleCondition::DirectorySpread { category, comparison, threshold } => {
                        // Count unique directories accessed
                        let unique_dirs: std::collections::HashSet<_> = match category.as_str() {
                            "accessed" => {
                                state.accessed_paths_tracker.iter()
                                    .filter_map(|p| Path::new(p).parent())
                                    .collect()
                            },
                            "browsed" => {
                                state.browsed_paths_tracker.keys()
                                    .filter_map(|p| Path::new(p).parent())
                                    .collect()
                            },
                            "staged" => {
                                state.staged_files_written.keys()
                                    .filter_map(|p| p.parent())
                                    .collect()
                            },
                            _ => std::collections::HashSet::new(),
                        };
                        
                        let count = unique_dirs.len() as u64;
                        let matches = match comparison {
                            Comparison::Gt => count > *threshold,
                            Comparison::Gte => count >= *threshold,
                            Comparison::Lt => count < *threshold,
                            Comparison::Lte => count <= *threshold,
                            Comparison::Eq => count == *threshold,
                            Comparison::Ne => count != *threshold,
                        };
                        
                        if !matches { stage_satisfied = false; break; }
                    },
                    
                    RuleCondition::ProcessAncestry { ancestor_pattern, max_depth } => {
                        // Check parent name (depth 1)
                        if !self.matches_pattern(ancestor_pattern, &state.parent_name) {
                            stage_satisfied = false;
                            break;
                        }
                        // Note: max_depth > 1 would require extended parent chain tracking
                    },
                    
                    RuleCondition::CommandLineMatch { patterns, match_mode } => {
                        // Command line matching would require storing command line in state
                        // For now, this is not supported in static scans
                        stage_satisfied = false;
                        break;
                    },
                    
                    RuleCondition::SensitivePathAccess { patterns, op_type, min_unique_paths } => {
                        let matching_paths: std::collections::HashSet<String> = match op_type.as_str() {
                            "read" => {
                                state.accessed_paths_tracker.iter()
                                    .filter(|p| patterns.iter().any(|pat| self.matches_pattern(pat, p)))
                                    .cloned()
                                    .collect()
                            },
                            "write" => {
                                state.staged_files_written.keys()
                                    .filter(|p| patterns.iter().any(|pat| {
                                        self.matches_pattern(pat, &p.to_string_lossy())
                                    }))
                                    .map(|p| p.to_string_lossy().to_string())
                                    .collect()
                            },
                            _ => std::collections::HashSet::new(),
                        };
                        
                        let count = matching_paths.len() as u32;
                        let min_required = min_unique_paths.unwrap_or(1);
                        
                        if count < min_required {
                            stage_satisfied = false;
                            break;
                        }
                    },
                    
                    // Advanced conditions that require runtime data
                    RuleCondition::ByteThreshold { .. } |
                    RuleCondition::ExtensionRatio { .. } |
                    RuleCondition::RateOfChange { .. } |
                    RuleCondition::SelfModification { .. } |
                    RuleCondition::ClusterPattern { .. } |
                    RuleCondition::TempDirectoryWrite { .. } |
                    RuleCondition::ArchiveCreation { .. } |
                    RuleCondition::DataExfiltrationPattern { .. } |
                    RuleCondition::DriveActivity { .. } |
                    RuleCondition::MemoryScan { .. } => {
                        // These conditions require detailed runtime metrics not available in static state
                        // They can only be evaluated during live event processing
                        stage_satisfied = false;
                        break;
                    },
                }
            }
            
            if stage_satisfied {
                satisfied_stages += 1;
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] Static Scan: Stage '{}' satisfied for {}",
                        stage.name, state.app_name
                    ));
                }
            }
        }
        
        // Check if minimum stages requirement is met
        let min_stages = if rule.min_stages_satisfied > 0 {
            rule.min_stages_satisfied
        } else {
            1 // Default: at least one stage must be satisfied
        };
        
        satisfied_stages >= min_stages
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

        // snapshot gids so we don't borrow self.process_states for the whole scan
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();

        if self.rules.iter().any(|r| r.debug) {
            Logging::debug(&format!("[BehaviorEngine] Static Scan: Evaluating {} tracked processes", gids.len()));
        }

        for gid in gids {
            // fetch a snapshot of state for this gid; skip if gone
            let state = match self.process_states.get(&gid) {
                Some(s) => s.clone(),
                None => continue,
            };

            // local convenience vars
            let pid = state.pid;
            let app_name = state.app_name.clone();
            let exe_path_buf = state.exe_path.clone();
            let exe_path_str = exe_path_buf.to_string_lossy().to_string();

            if self.rules.iter().any(|r| r.debug) {
                Logging::debug(&format!("[BehaviorEngine] Evaluating GID={} PID={} bin='{}'", gid, pid, app_name));
            }

            for rule in &self.rules {
                if rule.debug {
                    Logging::debug(&format!(
                        "[BehaviorEngine] Checking rule '{}' against {} (GID={}, PID={})",
                        rule.name, app_name, gid, pid
                    ));
                }

                // ---------- STAGE EVALUATION ----------
                // For static scans, we evaluate stages based on accumulated state
                // rather than individual IO events
                let stages_satisfied = if !rule.stages.is_empty() {
                    self.evaluate_stages_from_state(rule, &state)
                } else {
                    false
                };

                // If stages are defined and satisfied, mark as detection
                if !rule.stages.is_empty() && stages_satisfied {
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

                    if rule.debug {
                        Logging::warning(&format!(
                            "[BehaviorEngine] DETECTION (scan/stages): {} (PID: {}) matched '{}' via stages",
                            app_name,
                            pid,
                            rule.name
                        ));
                    }
                    continue; // Move to next rule
                }

                // ---------- ACCUMULATION (mirror check_rules) ----------
                let browsed_access_count: usize = state.browsed_paths_tracker.len();
                let has_staged_data = !state.staged_files_written.is_empty();

                // is_online: check active connections for the process or latched network activity
                let is_online = if rule.require_internet {
                    // check active tcp/udp connections for this pid OR the latched network flag
                    self.has_active_connections(state.pid) || state.network_activity_detected
                } else {
                    true
                };

                let parent_name = state.parent_name.clone();
                let is_suspicious_parent = if !rule.suspicious_parents.is_empty() {
                    let parent = parent_name.to_lowercase();
                    rule.suspicious_parents.iter().any(|p| {
                        let p_l = p.to_lowercase();
                        parent.contains(&p_l) || p_l.contains(&parent)
                    })
                } else {
                    false
                };

                let has_sensitive_access = !state.accessed_paths_tracker.is_empty();
                
                // FIX: Use the state's terminated_processes instead of engine-level
                let terminated_match = if !rule.terminated_processes.is_empty() {
                    rule.terminated_processes.iter().any(|rule_proc| {
                        let rule_proc_lc = rule_proc.to_lowercase();
                        
                        // Check external terminations
                        let ext_match = state.terminated_processes.iter().any(|victim_path| {
                            victim_path.contains(&rule_proc_lc) || rule_proc_lc.contains(victim_path)
                        });

                        // Check self-terminations only if explicitly allowed by the rule
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

                // condition trackers from state
                let high_entropy_detected = state.high_entropy_detected;
                let monitored_api_count = state.monitored_api_count;
                let file_action_detected = state.file_action_detected;
                let extension_match_detected = state.extension_match_detected;

                // ---------- CONDITION TRACKING ----------
                let mut satisfied_conditions: usize = 0;
                let mut total_tracked_conditions: usize = 0;
                let mut condition_results: Vec<(&str, bool)> = Vec::new();

                macro_rules! check {
                    ($name:expr, $cond:expr) => {{
                        total_tracked_conditions += 1;
                        let hit = $cond;
                        if hit { satisfied_conditions += 1; }
                        condition_results.push(($name, hit));
                    }};
                }

                if !rule.browsed_paths.is_empty() {
                    check!("browsed_paths", browsed_access_count >= rule.multi_access_threshold);
                }

                if !rule.staging_paths.is_empty() {
                    check!("staging", has_staged_data);
                }

                if rule.require_internet {
                    check!("internet", is_online);
                }

                if !rule.suspicious_parents.is_empty() {
                    check!("parent", is_suspicious_parent);
                }

                if !rule.accessed_paths.is_empty() {
                    check!("accessed_paths", has_sensitive_access);
                }

                if rule.entropy_threshold > 0.01 {
                    check!("entropy", high_entropy_detected);
                }

                if !rule.monitored_apis.is_empty() {
                    check!("apis", monitored_api_count > 0);
                }

                if !rule.file_actions.is_empty() {
                    check!("file_actions", file_action_detected);
                }

                if !rule.file_extensions.is_empty() {
                    check!("extensions", extension_match_detected);
                }

                if !rule.terminated_processes.is_empty() {
                    check!("terminated_proc", terminated_match);
                }

                // ---------- DEBUG OUTPUT ----------
                if rule.debug && total_tracked_conditions > 0 {
                    let breakdown = condition_results.iter()
                        .map(|(n, h)| format!("{}={}", n, if *h { "✔" } else { "✘" }))
                        .collect::<Vec<_>>()
                        .join(", ");

                    Logging::debug(&format!(
                        "[BehaviorEngine] Rule '{}' for {}: {}/{} [{}] (Online: {})",
                        rule.name,
                        app_name,
                        satisfied_conditions,
                        total_tracked_conditions,
                        breakdown,
                        is_online
                    ));
                }

                // ---------- DECISION ----------
                if total_tracked_conditions > 0 {
                    let ratio = satisfied_conditions as f32 / total_tracked_conditions as f32;
                    let threshold = if rule.conditions_percentage > 0.0 {
                        rule.conditions_percentage
                    } else {
                        1.0
                    };

                    if ratio >= threshold {
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

                        if rule.debug {
                            Logging::warning(&format!(
                                "[BehaviorEngine] DETECTION (scan): {} (PID: {}) matched '{}' ({:.1}%)",
                                app_name,
                                pid,
                                rule.name,
                                ratio * 100.0
                            ));
                        }
                    }
                }
            }
        }

        detected_processes
    }
}
