use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
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
            "winhttp", "dnsquery"
        ];
        
        if network_keywords.iter().any(|k| filepath.contains(k)) {
            state.network_activity_detected = true;
            if self.rules.iter().any(|r| r.debug) {
                 Logging::debug(&format!("[BehaviorEngine] Network Activity Detected via API: {} (PID: {})", msg.filepathstr, pid));
            }
        }

        // --- Event Tracking ---
        for rule in &self.rules {
            // Browsed Paths
            for b_path in &rule.browsed_paths {
                let norm_b_path = b_path.to_lowercase().replace("\\", "/");
                if filepath.contains(&norm_b_path) {
                    if rule.debug { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Matched browsed path '{}' in '{}'", 
                            rule.name, pid, b_path, filepath
                        )); 
                    }
                    state.browsed_paths_tracker.insert(b_path.clone(), SystemTime::now());
                    
                    for s_file in &rule.accessed_paths {
                        if filepath.contains(&s_file.to_lowercase()) {
                            if rule.debug { 
                                Logging::debug(&format!(
                                    "[BehaviorEngine] Rule '{}' (PID: {}): Matched accessed path (sensitive) '{}'", 
                                    rule.name, pid, s_file
                                )); 
                            }
                            state.accessed_paths_tracker.insert(s_file.clone());
                        }
                    }
                }
            }

            // Staging
            for s_path in &rule.staging_paths {
                let norm_s_path = s_path.to_lowercase().replace("\\", "/");
                if filepath.contains(&norm_s_path) && irp_op == IrpMajorOp::IrpWrite {
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
            for api in &rule.monitored_apis {
                if filepath.contains(&api.to_lowercase()) {
                    if rule.debug { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Monitored API used '{}'", 
                            rule.name, pid, api
                        )); 
                    }
                    state.monitored_api_count += 1;
                }
            }

            // File Actions
            for action in &rule.file_actions {
                if filepath.contains(&action.to_lowercase()) {
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
                if filepath.ends_with(&ext.to_lowercase()) || filepath.contains(&ext.to_lowercase()) {
                    if rule.debug { 
                        Logging::debug(&format!(
                            "[BehaviorEngine] Rule '{}' (PID: {}): Extension match '{}'", 
                            rule.name, pid, ext
                        )); 
                    }
                    state.extension_match_detected = true;
                }
            }
        }

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
                if self.evaluate_stages(
                    rule,
                    &parent_name,
                    has_valid_signature,
                    signature_checked,
                    precord,
                    msg,
                    &irp_op
                ) {
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

            let terminated_match = if !rule.terminated_processes.is_empty() {
                rule.terminated_processes.iter().any(|proc| {
                    self.process_terminated.contains(&proc.to_lowercase())
                })
            } else {
                true
            };


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

                    if rule.response.terminate_process {
                        break;
                    }
                }
            }
        }
    }

    fn evaluate_stages(
        &self, 
        rule: &BehaviorRule, 
        parent_name: &str, 
        has_valid_signature: bool,
        signature_checked: bool,
        precord: &ProcessRecord,
        msg: &IOMessage,
        irp_op: &IrpMajorOp
    ) -> bool {
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
                        if !op_matches { stage_satisfied = false; break; }
                        if !self.matches_pattern(path_pattern, &msg.filepathstr) { stage_satisfied = false; break; }
                    },
                    RuleCondition::Process { op: _, pattern } => {
                         if !self.matches_pattern(pattern, &precord.appname) { stage_satisfied = false; break; }
                    },
                    _ => {
                        stage_satisfied = false;
                        break;
                    }
                }
            }
             if stage_satisfied {
                if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage '{}' Satisfied!", stage.name)); }
                return true;
            }
        }
        false
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
            let (mut signature_checked, mut has_valid_signature, pid, exe_path, app_name) = {
                if let Some(s) = self.process_states.get(&gid) {
                    (s.signature_checked, s.has_valid_signature, s.pid, s.exe_path.clone(), s.app_name.clone())
                } else {
                    continue;
                }
            };
            
            // Force verify if not done
            if !signature_checked {
                if exe_path.exists() {
                    let info = verify_signature(&exe_path);
                    has_valid_signature = info.is_trusted;
                    signature_checked = true;
                    if let Some(s) = self.process_states.get_mut(&gid) {
                        s.has_valid_signature = has_valid_signature;
                        s.signature_checked = true;
                    }
                }
            }
            
            // Iterate all rules
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
