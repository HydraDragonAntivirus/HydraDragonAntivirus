use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use sysinfo::{SystemExt, ProcessExt};
#[cfg(target_os = "windows")]
use crate::services::ServiceChecker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryIndicator {
    pub path: String,
    #[serde(default)]
    pub value_name: Option<String>,
    #[serde(default)]
    pub expected_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    #[serde(default)]
    #[serde(default)]
    pub depends_on: Vec<String>,
    
    // --- Legacy Stealer/Attack Fields (Backward Compatible) ---
    #[serde(default)]
    pub attack_line: Vec<String>,
    #[serde(default)]
    pub attack_target: Vec<String>,
    #[serde(default)]
    pub attack_staging: Vec<String>,
    #[serde(default)]
    pub pipeline_threshold: usize,
    #[serde(default)]
    pub time_window_ms: u64,
    #[serde(default)]
    pub detect_exfiltration: bool,
    #[serde(default)]
    pub crypto_apis: Vec<String>,
    #[serde(default)]
    pub suspicious_parents: Vec<String>,
    #[serde(default)]
    pub closed_process_paths: Vec<String>,
    #[serde(default)]
    pub source_locations: Vec<String>,
    #[serde(default)]
    pub target_locations: Vec<String>,
    #[serde(default)]
    pub process_search: Vec<String>,
    #[serde(default)]
    pub blacklisted_users: Vec<String>,
    #[serde(default)]
    pub blacklisted_services: Vec<String>,
    #[serde(default)]
    pub registry_indicators: Vec<RegistryIndicator>,
    #[serde(default)]
    pub commandline_patterns: Vec<String>,
    #[serde(default)]
    pub archive_actions: Vec<String>,
    #[serde(default)]
    pub archive_locations: Vec<String>,
    #[serde(default)]
    pub max_staging_lifetime_ms: u64,
    #[serde(default)]
    pub registry_security_locking: bool,

    // --- Native File Primitives ---
    #[serde(default)]
    pub file_create_patterns: Vec<String>,
    #[serde(default)]
    pub file_write_patterns: Vec<String>,
    #[serde(default)]
    pub file_read_patterns: Vec<String>,
    #[serde(default)]
    pub file_delete_patterns: Vec<String>,
    #[serde(default)]
    pub file_rename_patterns: Vec<String>,

    // --- Native Registry Primitives ---
    #[serde(default)]
    pub reg_key_create_patterns: Vec<String>,
    #[serde(default)]
    pub reg_value_set_patterns: Vec<String>,
    #[serde(default)]
    pub reg_delete_patterns: Vec<String>,
    #[serde(default)]
    pub reg_query_patterns: Vec<String>,

    // --- Native Process Primitives ---
    #[serde(default)]
    pub proc_spawn_patterns: Vec<String>,
    #[serde(default)]
    pub proc_terminate_patterns: Vec<String>,
    #[serde(default)]
    pub parent_commandline_patterns: Vec<String>,

    // --- Native Service Primitives ---
    #[serde(default)]
    pub svc_create_patterns: Vec<String>,
    #[serde(default)]
    pub svc_start_patterns: Vec<String>,
    #[serde(default)]
    pub svc_stop_patterns: Vec<String>,
    #[serde(default)]
    pub svc_delete_patterns: Vec<String>,
    #[serde(default)]
    pub svc_exists_patterns: Vec<String>,
    #[serde(default)]
    pub svc_not_exists_patterns: Vec<String>,

    // --- Native Network Primitives ---
    #[serde(default)]
    pub net_connect_patterns: Vec<String>,
    #[serde(default)]
    pub net_listen_patterns: Vec<String>,

    // --- Heuristic & Metadata Primitives ---
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub min_evasion_delay_ms: u64,
    #[serde(default)]
    pub quarantine: bool,
    #[serde(default)]
    pub conditions_percentage: f32,
    #[serde(default)]
    pub record_mode_enabled: bool,
    #[serde(default)]
    pub allowlisted_apps: Vec<String>,
}

#[derive(Default)]
pub struct ProcessBehaviorState {
    // Legacy
    pub accessed_attack_lines: HashMap<String, SystemTime>,
    pub accessed_attack_targets: HashSet<String>,
    pub staged_attack_files: HashSet<String>,
    pub has_active_connection: bool,
    pub crypto_api_count: u32,
    pub archive_action_detected: bool,
    pub source_target_violation_detected: bool,
    pub registry_security_modification_detected: bool,

    // Granular Native Tracking
    pub files_created: HashSet<String>,
    pub files_written: HashSet<String>,
    pub files_read: HashSet<String>,
    pub files_deleted: HashSet<String>,
    pub files_renamed: HashSet<String>,
    
    pub reg_keys_created: HashSet<String>,
    pub reg_values_set: HashSet<String>,
    pub reg_deleted: HashSet<String>,
    pub reg_queried: HashSet<String>,
    
    pub procs_spawned: HashSet<String>,
    pub procs_terminated: HashSet<String>,
    
    // General State
    pub parent_name: String,
    pub parent_commandline: String,
    pub high_entropy_detected: bool,
    pub first_event_time: Option<SystemTime>,
    pub startup_latency_ms: u64,
    pub appname: String,
    pub exepath: String,
    pub commandline: String,
    
    pub rule_results: HashMap<String, bool>,
    pub is_recording: bool,
    pub recorded_activities: Vec<String>,
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    sys: sysinfo::System,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            sys: sysinfo::System::new_all(),
        }
    }

    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path)?;
        let rules: Vec<BehaviorRule> = serde_yaml::from_reader(file)?;
        self.rules = rules;
        Ok(())
    }

    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage) {
        let gid = msg.gid;
        let pid = msg.pid;
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        
        {
            self.sys.refresh_processes();
            let state = self.process_states.entry(gid).or_insert_with(|| {
                let mut s = ProcessBehaviorState::default();
                s.appname = precord.appname.clone();
                s.exepath = precord.exepath.to_string_lossy().to_string();
                if let Some(proc) = self.sys.process(sysinfo::Pid::from(pid as usize)) {
                    s.commandline = proc.cmd().join(" ");
                    if let Some(parent_pid) = proc.parent() {
                        if let Some(parent_proc) = self.sys.process(parent_pid) {
                            s.parent_name = parent_proc.name().to_string();
                            s.parent_commandline = parent_proc.cmd().join(" ");
                        }
                    }
                }
                s
            });

            if state.first_event_time.is_none() {
                let now = SystemTime::now();
                state.first_event_time = Some(now);
                state.startup_latency_ms = now.duration_since(precord.time_started).unwrap_or(Duration::from_secs(0)).as_millis() as u64;
            }

            let filepath = msg.filepathstr.to_lowercase();
            if state.is_recording { state.recorded_activities.push(format!("{:?} on {}", irp_op, msg.filepathstr)); }

            // Granular Native Primitive Tracking
            match irp_op {
                IrpMajorOp::IrpCreate => { state.files_created.insert(filepath.clone()); },
                IrpMajorOp::IrpWrite => { state.files_written.insert(filepath.clone()); },
                IrpMajorOp::IrpRead => { state.files_read.insert(filepath.clone()); },
                IrpMajorOp::IrpSetInfo => { 
                    if msg.extension.to_lowercase().contains("delete") { state.files_deleted.insert(filepath.clone()); }
                    if msg.extension.to_lowercase().contains("rename") { state.files_renamed.insert(filepath.clone()); }
                },
                IrpMajorOp::IrpRegistry => {
                    let ext_lower = msg.extension.to_lowercase();
                    if ext_lower.contains("createkey") { state.reg_keys_created.insert(filepath.clone()); }
                    else if ext_lower.contains("setvalue") { state.reg_values_set.insert(filepath.clone()); }
                    else if ext_lower.contains("deletekey") || ext_lower.contains("deletevalue") { state.reg_deleted.insert(filepath.clone()); }
                    else if ext_lower.contains("querykey") || ext_lower.contains("queryvalue") { state.reg_queried.insert(filepath.clone()); }
                    
                    if ext_lower == "set_security" { state.registry_security_modification_detected = true; }
                },
                _ => {}
            }

            // Legacy Tracking for backward compatibility
            for rule in &self.rules {
                for b_path in &rule.attack_line {
                    if filepath.contains(&b_path.to_lowercase()) {
                        state.accessed_attack_lines.insert(b_path.clone(), SystemTime::now());
                        for s_file in &rule.attack_target {
                            if filepath.contains(&s_file.to_lowercase()) { state.accessed_attack_targets.insert(s_file.clone()); }
                        }
                    }
                }
                for s_path in &rule.attack_staging {
                    if filepath.contains(&s_path.to_lowercase()) && irp_op == IrpMajorOp::IrpWrite { state.staged_attack_files.insert(filepath.clone()); }
                }
                for api in &rule.crypto_apis { if filepath.contains(&api.to_lowercase()) { state.crypto_api_count += 1; } }
                for action in &rule.archive_actions { if filepath.contains(&action.to_lowercase()) { state.archive_action_detected = true; } }
            }

            if msg.is_entropy_calc == 1 && msg.entropy > 7.0 { state.high_entropy_detected = true; }
        }

        self.check_rules(precord, gid);
    }

    fn check_rules(&self, precord: &mut ProcessRecord, gid: u64) {
        let state = match self.process_states.get(&gid) { Some(s) => s, None => return };
        let mut results = state.rule_results.clone();
        let mut progress = true;

        while progress {
            progress = false;
            for rule in &self.rules {
                if results.contains_key(&rule.name) { continue; }
                if !rule.depends_on.iter().all(|dep| results.get(dep).copied().unwrap_or(false)) { continue; }

                let (is_match, indicators) = self.evaluate_full_native_logic(rule, state);
                if is_match {
                    results.insert(rule.name.clone(), true);
                    progress = true;
                    if !rule.is_private {
                        Logging::warning(&format!("[BehaviorEngine] !!! DETECTION !!!\nProcess: {}\nRule: {}\nIndicators:\n  - {}", precord.appname, rule.name, indicators.join("\n  - ")));
                        precord.is_malicious = true; precord.termination_requested = true;
                        if rule.quarantine { precord.quarantine_requested = true; }
                    }
                    if rule.record_mode_enabled { self.suggest_rule(state); }
                }
            }
        }
    }

    fn evaluate_full_native_logic(&self, rule: &BehaviorRule, state: &ProcessBehaviorState) -> (bool, Vec<String>) {
        if rule.allowlisted_apps.iter().any(|app| state.appname.to_lowercase().contains(&app.to_lowercase())) { return (false, Vec::new()); }

        let mut satisfied = 0;
        let mut total = 0;
        let mut indicators = Vec::new();

        // Legacy Stealer Pipeline
        if !rule.attack_line.is_empty() {
            total += 1;
            let now = SystemTime::now();
            let recent = state.accessed_attack_lines.values().filter(|&&t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < rule.time_window_ms as u128).count();
            if recent >= rule.pipeline_threshold { satisfied += 1; indicators.push(format!("LegacyPipelineMet({})", recent)); }
        }
        if !rule.crypto_apis.is_empty() { total += 1; if state.crypto_api_count > 0 { satisfied += 1; indicators.push(format!("LegacyCryptoMet({})", state.crypto_api_count)); } }

        // Native File Primitives
        for p in &rule.file_create_patterns { total += 1; if state.files_created.iter().any(|f| f.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("FileCreate({})", p)); } }
        for p in &rule.file_write_patterns { total += 1; if state.files_written.iter().any(|f| f.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("FileWrite({})", p)); } }
        for p in &rule.file_read_patterns { total += 1; if state.files_read.iter().any(|f| f.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("FileRead({})", p)); } }
        for p in &rule.file_delete_patterns { total += 1; if state.files_deleted.iter().any(|f| f.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("FileDelete({})", p)); } }
        for p in &rule.file_rename_patterns { total += 1; if state.files_renamed.iter().any(|f| f.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("FileRename({})", p)); } }

        // Native Registry Primitives
        for p in &rule.reg_key_create_patterns { total += 1; if state.reg_keys_created.iter().any(|r| r.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("RegKeyCreate({})", p)); } }
        for p in &rule.reg_value_set_patterns { total += 1; if state.reg_values_set.iter().any(|r| r.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("RegValueSet({})", p)); } }
        for p in &rule.reg_delete_patterns { total += 1; if state.reg_deleted.iter().any(|r| r.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("RegDelete({})", p)); } }
        for p in &rule.reg_query_patterns { total += 1; if state.reg_queried.iter().any(|r| r.contains(&p.to_lowercase())) { satisfied += 1; indicators.push(format!("RegQuery({})", p)); } }

        // Native Command Line & Parent Primitives
        for p in &rule.commandline_patterns { total += 1; if state.commandline.to_lowercase().contains(&p.to_lowercase()) { satisfied += 1; indicators.push(format!("CmdPattern({})", p)); } }
        for p in &rule.parent_commandline_patterns { total += 1; if state.parent_commandline.to_lowercase().contains(&p.to_lowercase()) { satisfied += 1; indicators.push(format!("ParentCmdPattern({})", p)); } }

        // Native Service Primitives (Surgical Win32 Check)
        #[cfg(target_os = "windows")]
        {
            for p in &rule.svc_exists_patterns { total += 1; if ServiceChecker::exists(p) { satisfied += 1; indicators.push(format!("SvcExists({})", p)); } }
            for p in &rule.svc_not_exists_patterns { total += 1; if !ServiceChecker::exists(p) { satisfied += 1; indicators.push(format!("SvcNotExists({})", p)); } }
            for p in &rule.svc_stop_patterns { total += 1; if !ServiceChecker::is_running(p) { satisfied += 1; indicators.push(format!("SvcStopped({})", p)); } }
        }

        // Heuristics
        if rule.entropy_threshold > 0.0 { total += 1; if state.high_entropy_detected { satisfied += 1; indicators.push("HighEntropyMet".to_string()); } }
        if rule.min_evasion_delay_ms > 0 { total += 1; if state.startup_latency_ms >= rule.min_evasion_delay_ms { satisfied += 1; indicators.push("EvasionDelayMet".to_string()); } }

        if total == 0 { return (!rule.depends_on.is_empty(), indicators); }
        let ratio = satisfied as f32 / total as f32;
        (ratio >= rule.conditions_percentage, indicators)
    }

    fn suggest_rule(&self, state: &ProcessBehaviorState) {
        Logging::info(&format!("[BehaviorEngine] RECORD MODE - Suggested Rule for {}:\ncommandline_patterns: [\"{}\"]", state.appname, state.commandline));
    }
}
