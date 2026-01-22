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
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
use windows::Win32::Networking::WinSock::AF_INET;

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
/// Contains ALL fields from the Old Behavior Engine for 100% backward compatibility,
/// plus new fields for advanced detection capabilities.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    
    // --- Legacy Fields (Old Behavior Engine - 100% Preserved) ---
    #[serde(default)]
    pub browser_paths: Vec<String>,
    #[serde(default)]
    pub sensitive_files: Vec<String>,
    #[serde(default)]
    pub staging_paths: Vec<String>,
    #[serde(default = "default_zero")]
    pub multi_access_threshold: usize,
    #[serde(default)]
    pub time_window_ms: u64,
    #[serde(default)]
    pub require_internet: bool,
    #[serde(default)]
    pub crypto_apis: Vec<String>,
    #[serde(default)]
    pub archive_actions: Vec<String>,
    #[serde(default)]
    pub suspicious_parents: Vec<String>,
    #[serde(default)]
    pub max_staging_lifetime_ms: u64,
    #[serde(default)]
    pub require_browser_closed_recently: bool,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub conditions_percentage: f32,
    
    // --- Rich / New Fields ---
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
    
    // NOTE: This field supports both simple Strings (Old Engine) and Complex Objects (New Engine)
    // via serde's untagged enum capability.
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
        // Merge separate archive fields into the main one for unified checking
        if !self.archive_apis.is_empty() || !self.archive_tools.is_empty() {
            let mut merged = self.archive_actions.clone();
            merged.extend(self.archive_apis.iter().cloned());
            merged.extend(self.archive_tools.iter().cloned());
            self.archive_actions = merged;
        }

        // Normalize allowlist entries
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
#[serde(untagged)] // CRITICAL: This allows backward compatibility with Old Engine's Vec<String>
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
    TimeWindowAggregation { metric: String, #[serde(default)] function: AggregationFunction, time_window_ms: u64, #[serde(default)] comparison: Comparison, threshold: f64 },
    DriveActivity { drive_type: String, op_type: String, #[serde(default)] comparison: Comparison, threshold: u32 },
    ProcessAncestry { ancestor_pattern: String, #[serde(default)] max_depth: Option<u32> },
    ExtensionRatio { extensions: Vec<String>, #[serde(default)] comparison: Comparison, threshold: f32 },
    RateOfChange { metric: String, #[serde(default)] comparison: Comparison, threshold: f64 },
    SelfModification { modification_type: String },
    ExtensionChangeVelocity { time_window_ms: u64, #[serde(default)] comparison: Comparison, threshold: u64 },
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
    // --- Legacy State Fields ---
    pub accessed_browsers: HashMap<String, SystemTime>,
    pub sensitive_files_read: HashSet<String>,
    pub staged_files_written: HashMap<PathBuf, SystemTime>,
    pub last_browser_close: Option<SystemTime>,
    pub crypto_api_count: usize,
    pub high_entropy_detected: bool,
    pub archive_action_detected: bool,
    pub parent_name: String,
    
    // --- New Identity & State Fields ---
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
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: RefCell::new(HashMap::new()),  
        }
    }

    /// Recursively loads rules, supporting both old flat YAMLs and new !include directives.
    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let rules = self.load_rules_recursive(path)?;
        self.rules = rules;
        Logging::info(&format!("[EDR]: {} behavior rules loaded from {:?}", self.rules.len(), path));
        Ok(())
    }

    fn load_rules_recursive(&self, path: &Path) -> Result<Vec<BehaviorRule>, Box<dyn std::error::Error>> {
        // Fallback to reading file for legacy support, but add !include capability
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
            // Standard loading (superset of Old Engine's loading)
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

    /// Process Event - Supports new signature but preserves OLD tracking logic perfectly.
    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage, _config: &Config, _threat_handler: &dyn ThreatHandler) {
        let gid = msg.gid;
        
        let state = self.process_states.entry(gid).or_insert_with(|| {
            let mut s = ProcessBehaviorState::default();
            
            // Store identity info for robust scanning later (New Feature)
            s.pid = msg.pid as u32;
            s.exe_path = precord.exepath.clone();
            s.app_name = precord.appname.clone();

            let mut sys = sysinfo::System::new_all();
            sys.refresh_processes();
            if let Some(proc) = sys.process(sysinfo::Pid::from(msg.pid as usize)) {
                if let Some(parent_pid) = proc.parent() {
                    if let Some(parent_proc) = sys.process(parent_pid) {
                        s.parent_name = parent_proc.name().to_string();
                    }
                }
            } else {
                s.parent_name = "unknown".to_string();
            }
            s
        });

        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let filepath = msg.filepathstr.to_lowercase();
        
        // --- Signature Verification Logic (New Feature) ---
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

        // --- Event Tracking (Identical Logic to Old Engine) ---
        for rule in &self.rules {
            // 1. Track Browser Access
            for b_path in &rule.browser_paths {
                if filepath.contains(&b_path.to_lowercase()) {
                    state.accessed_browsers.insert(b_path.clone(), SystemTime::now());
                    
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
                    state.staged_files_written.insert(PathBuf::from(&filepath), SystemTime::now());
                }
            }

            // 3. Track Entropy
            if msg.is_entropy_calc == 1 && msg.entropy > rule.entropy_threshold {
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

        self.check_rules(precord, gid, msg, irp_op);
    }

    fn check_rules(&mut self, precord: &mut ProcessRecord, gid: u64, msg: &IOMessage, irp_op: IrpMajorOp) {
        let (
            accessed_browsers,
            staged_files_written,
            sensitive_files_read,
            last_browser_close,
            parent_name,
            high_entropy_detected,
            crypto_api_count,
            archive_action_detected,
            has_valid_signature,
            signature_checked
        ) = {
            let s = self.process_states.get(&gid).unwrap();
            (
                s.accessed_browsers.clone(),
                s.staged_files_written.clone(),
                s.sensitive_files_read.clone(),
                s.last_browser_close,
                s.parent_name.clone(),
                s.high_entropy_detected,
                s.crypto_api_count,
                s.archive_action_detected,
                s.has_valid_signature,
                s.signature_checked
            )
        };

        let now = SystemTime::now();

        for rule in &self.rules {
            if rule.debug {
                 Logging::debug(&format!("[BehaviorEngine] DEBUG: Checking rule '{}' against process '{}' (PID: {})", rule.name, precord.appname, precord.pids.iter().next().unwrap_or(&0)));
            }

            // Allowlist Check - Compatible with both Old (String) and New (Complex)
            let is_allowlisted = self.check_allowlist(&precord.appname, rule, Some(&precord.exepath));
            if is_allowlisted {
                if rule.debug { Logging::debug(&format!("Rule '{}' skipped for {} (allowlisted)", rule.name, precord.appname)); }
                continue;
            }

            // --- New Feature: Stage-Based Logic ---
            if !rule.stages.is_empty() {
                if self.evaluate_stages(rule, &parent_name, has_valid_signature, signature_checked, precord, msg, &irp_op) {
                     Logging::warning(&format!(
                        "[BehaviorEngine] DETECTION: {} matched rule '{}' (stage triggered)",
                        precord.appname, rule.name
                    ));
                    precord.is_malicious = true;
                }
            }

            // --- Legacy Accumulation Logic (100% Old Engine Compatibility) ---
            
            // Condition A: Multi-Browser Access
            let recent_access_count = accessed_browsers.values()
                .filter(|&&t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < rule.time_window_ms as u128)
                .count();

            // Condition B: Data Staging
            let has_staged_data = !staged_files_written.is_empty();

            // Condition C: Internet Connectivity
            let is_online = if rule.require_internet {
                self.has_active_connections(precord.pids.iter().next().cloned().unwrap_or(0))
            } else {
                true
            };

            // Condition D: Suspicious Parent
            let is_suspicious_parent = rule.suspicious_parents.iter().any(|p| parent_name.to_lowercase().contains(&p.to_lowercase()));

            // Condition E: Sensitive File Access
            let has_sensitive_access = !sensitive_files_read.is_empty();

            // Condition G: Browser closed recently
            let browser_closed_recently = if rule.require_browser_closed_recently {
                last_browser_close.map_or(false, |t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < 3600000)
            } else {
                true
            };

            let mut satisfied_conditions = 0;
            let mut total_tracked_conditions = 0;
            
            // Optimized logic from New Engine to prevent false positives from unused fields
            // This preserves the intent of the old engine but improves quality.
            
            if !rule.browser_paths.is_empty() {
                total_tracked_conditions += 1;
                if recent_access_count >= rule.multi_access_threshold { satisfied_conditions += 1; }
            }
            if !rule.staging_paths.is_empty() {
                total_tracked_conditions += 1;
                if has_staged_data { satisfied_conditions += 1; }
            }
            if rule.require_internet {
                total_tracked_conditions += 1;
                if is_online { satisfied_conditions += 1; }
            }
            if !rule.suspicious_parents.is_empty() {
                total_tracked_conditions += 1;
                if is_suspicious_parent { satisfied_conditions += 1; }
            }
            if !rule.sensitive_files.is_empty() {
                total_tracked_conditions += 1;
                if has_sensitive_access { satisfied_conditions += 1; }
            }
            if rule.entropy_threshold > 0.01 {
                total_tracked_conditions += 1;
                if high_entropy_detected { satisfied_conditions += 1; }
            }
            if !rule.crypto_apis.is_empty() {
                total_tracked_conditions += 1;
                if crypto_api_count > 0 { satisfied_conditions += 1; }
            }
            if !rule.archive_actions.is_empty() {
                total_tracked_conditions += 1;
                if archive_action_detected { satisfied_conditions += 1; }
            }
            if rule.require_browser_closed_recently {
                total_tracked_conditions += 1;
                if browser_closed_recently { satisfied_conditions += 1; }
            }

            if rule.debug {
                Logging::debug(&format!("[BehaviorEngine] DEBUG: Rule '{}' Legacy Stats: Browsers={}/{}, Staging={}, Online={}, SuspParent={}, Sensitive={}, Entropy={}, Crypto={}, Archive={}, BrowserClosed={}", 
                    rule.name, recent_access_count, rule.multi_access_threshold, has_staged_data, is_online, is_suspicious_parent, has_sensitive_access, high_entropy_detected, crypto_api_count, archive_action_detected, browser_closed_recently));
            }

            if total_tracked_conditions > 0 {
                let satisfied_ratio = satisfied_conditions as f32 / total_tracked_conditions as f32;
                let threshold = if rule.conditions_percentage > 0.0 { rule.conditions_percentage } else { 1.0 };

                if satisfied_ratio >= threshold {
                    Logging::warning(&format!(
                        "[BehaviorEngine] DETECTION: {} matched rule '{}'. Satisfied {}/{} conditions ({:.1}%)",
                        precord.appname, rule.name, satisfied_conditions, total_tracked_conditions, satisfied_ratio * 100.0
                    ));
                    precord.is_malicious = true;
                } else if rule.debug {
                    Logging::debug(&format!("[BehaviorEngine] DEBUG: Rule '{}' threshold not met: {}/{} ({:.1}%) < {:.1}%", rule.name, satisfied_conditions, total_tracked_conditions, satisfied_ratio * 100.0, threshold * 100.0));
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
            if rule.debug {
                Logging::debug(&format!("[BehaviorEngine] DEBUG: Evaluating Stage '{}' for rule '{}'", stage.name, rule.name));
            }

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

                        if !op_matches {
                            if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: File Op mismatch (Expected: {}, Got: {:?})", op, irp_op)); }
                            stage_satisfied = false;
                            break;
                        }
                        if !self.matches_pattern(path_pattern, &msg.filepathstr) {
                            if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: File Path mismatch (Pattern: {}, Got: {})", path_pattern, msg.filepathstr)); }
                            stage_satisfied = false;
                            break;
                        }
                    },

                    RuleCondition::Process { op: _, pattern } => {
                        if !self.matches_pattern(pattern, &precord.appname) {
                            if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: Process Name mismatch (Pattern: {}, Got: {})", pattern, precord.appname)); }
                            stage_satisfied = false;
                            break;
                        }
                    },

                    RuleCondition::Registry { op: _, key_pattern, value_name: _, expected_data: _ } => {
                        if msg.filepathstr.to_uppercase().starts_with("\\REGISTRY\\") || 
                        msg.filepathstr.to_uppercase().contains("HKLM") ||
                        msg.filepathstr.to_uppercase().contains("HKCU") {
                            if !self.matches_pattern(key_pattern, &msg.filepathstr) {
                                if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: Registry Key mismatch (Pattern: {}, Got: {})", key_pattern, msg.filepathstr)); }
                                stage_satisfied = false;
                                break;
                            }
                        } else {
                            if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: Not a registry path: {}", msg.filepathstr)); }
                            stage_satisfied = false;
                            break;
                        }
                    },

                    RuleCondition::Network { op: _, dest_pattern: _ } => {
                        if !self.has_active_connections(msg.pid as u32) {
                            if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: No active network connections for PID {}", msg.pid)); }
                            stage_satisfied = false;
                            break;
                        }
                    },

                    RuleCondition::EntropyThreshold { metric: _, comparison, threshold } => {
                        if msg.is_entropy_calc == 1 {
                            let matches = match comparison {
                                Comparison::Gt => msg.entropy > *threshold,
                                Comparison::Gte => msg.entropy >= *threshold,
                                Comparison::Lt => msg.entropy < *threshold,
                                Comparison::Lte => msg.entropy <= *threshold,
                                Comparison::Eq => (msg.entropy - *threshold).abs() < f64::EPSILON,
                                Comparison::Ne => (msg.entropy - *threshold).abs() > f64::EPSILON,
                            };
                            if !matches {
                                if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: Entropy threshold mismatch (Got: {}, Threshold: {})", msg.entropy, threshold)); }
                                stage_satisfied = false;
                                break;
                            }
                        } else {
                            if rule.debug { Logging::debug("[BehaviorEngine] DEBUG: Stage condition failed: Not an entropy calculation event"); }
                            stage_satisfied = false;
                            break;
                        }
                    },

                    RuleCondition::Signature { is_trusted, signer_pattern } => {
                        if !signature_checked {
                            if rule.debug { Logging::debug("[BehaviorEngine] DEBUG: Stage condition failed: Signature not yet checked"); }
                            stage_satisfied = false;
                            break;
                        }

                        if *is_trusted {
                            if !has_valid_signature {
                                if rule.debug { Logging::debug("[BehaviorEngine] DEBUG: Stage condition failed: Signature invalid or missing, but required trusted"); }
                                stage_satisfied = false;
                                break;
                            }
                            if let Some(pattern) = signer_pattern {
                                // Re-verify to get signer name. Path guaranteed to exist if has_valid_signature is true.
                                let info = verify_signature(&precord.exepath);
                                if let Some(signer) = &info.signer_name {
                                    if !self.matches_pattern(pattern, signer) {
                                        if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: Signer mismatch (Pattern: {}, Got: {})", pattern, signer)); }
                                        stage_satisfied = false;
                                        break;
                                    }
                                } else {
                                    if rule.debug { Logging::debug("[BehaviorEngine] DEBUG: Stage condition failed: Signer name missing"); }
                                    stage_satisfied = false;
                                    break;
                                }
                            }
                        } else {
                            if has_valid_signature {
                                if rule.debug { Logging::debug("[BehaviorEngine] DEBUG: Stage condition failed: Signature valid, but rule requires untrusted/invalid"); }
                                stage_satisfied = false;
                                break;
                            }
                        }
                    },

                    RuleCondition::ProcessAncestry { ancestor_pattern, max_depth: _ } => {
                        if !self.matches_pattern(ancestor_pattern, parent_name) {
                            if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition failed: Parent mismatch (Pattern: {}, Got: {})", ancestor_pattern, parent_name)); }
                            stage_satisfied = false;
                            break;
                        }
                    },

                    _ => {
                        if rule.debug { Logging::debug(&format!("[BehaviorEngine] DEBUG: Stage condition skipped/failed: Condition type {:?} not fully implemented", condition)); }
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
                // Supports legacy string allowlist
                AllowlistEntry::Simple(pattern) => {
                    proc_lc.contains(&pattern.to_lowercase())
                }

                // Supports new complex allowlist
                AllowlistEntry::Complex {
                    pattern,
                    signers,
                    must_be_signed,
                } => {
                    let name_matches = proc_lc.contains(&pattern.to_lowercase());

                    if !name_matches {
                        return false;
                    }

                    if !must_be_signed && signers.is_empty() {
                        return true;
                    }

                    if let Some(path) = process_path {
                        if !path.exists() {
                            // WARNING: Impossible to check for allowlist
                            Logging::warning(&format!(
                                "[BehaviorEngine] WARNING: Allowlist check failed for '{}'. File missing or inaccessible, cannot verify signature.",
                                path.display()
                            ));
                            return false; // Fail closed
                        }

                        let info = verify_signature(path);

                        if *must_be_signed && !info.is_trusted {
                            return false;
                        }

                        if !signers.is_empty() {
                            if let Some(signer) = &info.signer_name {
                                let match_found = signers.iter().any(|s_pattern| {
                                    self.matches_pattern(s_pattern, signer)
                                });
                                return match_found;
                            } else {
                                return false;
                            }
                        } else {
                            true
                        }
                    } else {
                        // If path is None but signature is required, we cannot verify, so deny.
                        false
                    }
                }
            }
        })
    }


    fn matches_pattern(&self, pattern: &str, text: &str) -> bool {
        // Fast path for plain substring matches (no wildcard/regex characters)
        if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') && !pattern.contains('\\') {
            return text.to_lowercase().contains(&pattern.to_lowercase());
        }

        // Use interior mutability for regex cache
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
            Err(_) => {
                // Fallback to case-insensitive substring if regex fails to compile
                text.to_lowercase().contains(&pattern.to_lowercase())
            }
        }
    }

    // --- Active Connections Logic ---
    
    fn has_active_connections(&self, pid: u32) -> bool {
        if pid == 0 { return false; }

        let mut dw_size = 0;
        unsafe {
            let _ = GetExtendedTcpTable(None, &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
            if dw_size == 0 { return false; }

            let mut buffer = vec![0u8; dw_size as usize];
            if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                if buffer.len() < 4 { return false; }
                
                let num_entries = u32::from_ne_bytes(buffer[0..4].try_into().unwrap());
                // MIB_TCPROW_OWNER_PID size is 24 bytes (DWORD state, localAddr, localPort, remoteAddr, remotePort, owningPid)
                let start_offset = 4;
                for i in 0..num_entries {
                    let offset = start_offset + (i as usize * 24);
                    if offset + 24 > buffer.len() { break; }
                    
                    let pid_offset = offset + 20;
                    let entry_pid = u32::from_ne_bytes(buffer[pid_offset..pid_offset+4].try_into().unwrap());
                    
                    if entry_pid == pid {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    // Fully implemented scan logic using stored state identity (New Feature)
    pub fn scan_all_processes(&mut self, _config: &Config, _threat_handler: &dyn ThreatHandler) -> Vec<ProcessRecord> {
        let mut detected_processes = Vec::new();
        let gids: Vec<u64> = self.process_states.keys().cloned().collect();
        
        // Debug log to track scanning progress (e.g., "0/9")
        if self.rules.iter().any(|r| r.debug) {
            Logging::debug(&format!("[BehaviorEngine] Static Scan: Evaluating {} tracked processes", gids.len()));
        }

        for gid in gids {
            // Reconstruct necessary context from state
            let (mut signature_checked, mut has_valid_signature, pid, exe_path, app_name) = {
                if let Some(s) = self.process_states.get(&gid) {
                    (s.signature_checked, s.has_valid_signature, s.pid, s.exe_path.clone(), s.app_name.clone())
                } else {
                    continue;
                }
            };
            
            // CRITICAL FIX: Force signature verification if not yet checked.
            // This ensures new processes are scanned immediately even if the event handler hasn't flagged them yet.
            if !signature_checked {
                if exe_path.exists() {
                    let info = verify_signature(&exe_path);
                    has_valid_signature = info.is_trusted;
                    signature_checked = true;

                    // Update state so we don't re-verify next time (optimization)
                    if let Some(s) = self.process_states.get_mut(&gid) {
                        s.has_valid_signature = has_valid_signature;
                        s.signature_checked = true;
                    }
                }
            }
            
            if !signature_checked { continue; }

            for rule in &self.rules {
                 for stage in &rule.stages {
                    for condition in &stage.conditions {
                        if let RuleCondition::Signature { is_trusted, signer_pattern: _ } = condition {
                             let violates = if *is_trusted {
                                !has_valid_signature
                            } else {
                                has_valid_signature
                            };
                            
                            if violates {
                                // Rule triggered via static state scan
                                let is_allowlisted = self.check_allowlist(&app_name, rule, Some(&exe_path));
                                if !is_allowlisted {
                                    Logging::warning(&format!(
                                        "[BehaviorEngine SCAN] DETECTION: {} (PID: {}) matched rule '{}' (signature violation)",
                                        app_name, pid, rule.name
                                    ));
                                    
                                    let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path.clone());
                                    p.is_malicious = true;
                                    // p.pids is a HashSet, add the known PID
                                    p.pids.insert(pid);
                                    
                                    // Pass request flags based on rule response
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
