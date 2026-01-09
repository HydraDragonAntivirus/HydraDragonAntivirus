use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use regex::Regex;

// --- EDR Telemetry & Framework ---
use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use sysinfo::{SystemExt, ProcessExt};

#[cfg(target_os = "windows")]
use crate::services::ServiceChecker;

// ============================================================================
// GENERIC CONFIGURATION STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    pub description: String,
    pub severity: u8,
    
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
    pub allowlisted_apps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMapping {
    And(Vec<RuleMapping>),
    Or(Vec<RuleMapping>),
    Not(Box<RuleMapping>),
    Stage(String),
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub suspend_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default)] pub block_network: bool,
    #[serde(default)] pub auto_revert: bool,
    #[serde(default)] pub signal_firewall: Option<String>,
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

    // Performance: caching telemetry results
    pub entropy_max: f64,
    pub active_connections: bool,
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
            active_connections: false,
        }
    }
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    regex_cache: HashMap<String, Regex>,
    sys: sysinfo::System,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            process_states: HashMap::new(),
            regex_cache: HashMap::new(),
            sys: sysinfo::System::new_all(),
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

        // Support !include by pre-parsing or using a custom resolver
        // For simplicity and robustness, we'll look for '!include' lines manually if needed, 
        // but often users prefer a clean YAML-native inclusion.
        // Here we'll implement a simple recursive loader that looks for a top-level 'includes' key if parsing fails as a list,
        // or we preprocess the string.
        
        if content.contains("!include") {
            // Simple preprocessing to resolve !include <path>
            let mut resolved_content = String::new();
            for line in content.lines() {
                if line.trim().starts_with("!include ") {
                    let include_path_str = line.trim().trim_start_matches("!include ").trim();
                    let parent = path.parent().unwrap_or_else(|| Path::new("."));
                    let include_path = parent.join(include_path_str);
                    let sub_rules = self.load_rules_recursive(&include_path)?;
                    // Convert sub-rules back to YAML to merge into the stream
                    resolved_content.push_str(&serde_yaml::to_string(&sub_rules)?);
                } else {
                    resolved_content.push_str(line);
                    resolved_content.push('\n');
                }
            }
            let r: Vec<BehaviorRule> = serde_yaml::from_str(&resolved_content)?;
            rules.extend(r);
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

    fn matches(&self, pattern: &str, text: &str) -> bool {
        if let Some(re) = self.regex_cache.get(pattern) {
            re.is_match(text)
        } else {
            text.to_lowercase().contains(&pattern.to_lowercase())
        }
    }

    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage) {
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
                if let Some(parent) = proc.parent() {
                    if let Some(p_proc) = self.sys.process(parent) {
                        s.parent_name = p_proc.name().to_string();
                    }
                }
            }
            s
        });

        state.last_event_ts = now;

        // 2. Pre-process global metrics
        if msg.is_entropy_calc == 1 && msg.entropy > state.entropy_max {
            state.entropy_max = msg.entropy;
        }

        // 3. Evaluate each rule's stages
        let mut triggered_rules = Vec::new();

        for rule in &self.rules {
            // Allowlisting
            if rule.allowlisted_apps.iter().any(|app| state.appname.to_lowercase().contains(&app.to_lowercase())) {
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
                    if Self::evaluate_condition_internal(&self.regex_cache, condition, msg, state) {
                        let rule_conds = state.satisfied_conditions
                            .entry(rule.name.clone())
                            .or_insert_with(HashMap::new);
                        
                        let stage_conds = rule_conds.entry(s_idx).or_insert_with(HashSet::new);
                        stage_conds.insert(c_idx);

                        state.satisfied_stages
                            .entry(rule.name.clone())
                            .or_insert_with(HashSet::new)
                            .insert(s_idx);
                    }
                }
            }

            // Check if rule should trigger
            let satisfied_count = state.satisfied_stages.get(&rule.name).map_or(0, |s| s.len());
            if satisfied_count >= rule.min_stages_satisfied && rule.min_stages_satisfied > 0 {
                triggered_rules.push(rule.clone());
            } else if rule.conditions_percentage > 0.01 {
                let total_conds: usize = rule.stages.iter().map(|s| s.conditions.len()).sum();
                let satisfied_conds: usize = state.satisfied_conditions.get(&rule.name)
                    .map_or(0, |m| m.values().map(|v| v.len()).sum());
                
                if (satisfied_conds as f32 / total_conds as f32) >= rule.conditions_percentage {
                    triggered_rules.push(rule.clone());
                }
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
            }

            if let Some(signal) = &rule.response.signal_firewall {
                Self::signal_firewall_internal(state.pid, signal);
            }

            if rule.response.auto_revert {
                Self::revert_registry_internal(msg);
            }
        }
    }

    fn evaluate_condition_internal(regex_cache: &HashMap<String, Regex>, cond: &RuleCondition, msg: &IOMessage, state: &ProcessBehaviorState) -> bool {
        let op = IrpMajorOp::from_byte(msg.irp_op);
        
        match cond {
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
                    "SetSecurity" => msg.file_change == 10, // Assuming 10 is SET_SECURITY
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
        }
    }

    fn matches_internal(regex_cache: &HashMap<String, Regex>, pattern: &str, text: &str) -> bool {
        if let Some(re) = regex_cache.get(pattern) {
            re.is_match(text)
        } else {
            text.to_lowercase().contains(&pattern.to_lowercase())
        }
    }

    fn signal_firewall_internal(pid: u32, signal: &str) {
        Logging::info(&format!("[FIREWALL] Signaling: {} for PID {}", signal, pid));
    }

    fn revert_registry_internal(msg: &IOMessage) {
        Logging::info(&format!("[REGISTRY] Reverting change to {}", msg.filepathstr));
    }
}
