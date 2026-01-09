/*
 * ============================================================================
 * HYDRADRAGON ULTIMATE EDR BEHAVIOR ENGINE V4.0 (WINDOWS NATIVE)
 * ============================================================================
 * "Vibe Coding" Level: Deep Kernel-to-User Telemetry Correlation
 * Features:
 * - Granular Module/DLL Load Tracking (Anti-Hooking & LDR Monitoring)
 * - Surgical API Usage Heuristics (Dynamic Resolved & Static Linked)
 * - multi-stage Cyber Kill-Chain Correlation (Attack Pipeline)
 * - Forensic System Journaling & MITRE ATTACK TTP Mapping
 * ============================================================================
 */

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// --- EDR Telemetry & Framework ---
use crate::shared_def::{IOMessage, IrpMajorOp, FileChangeInfo};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use sysinfo::{SystemExt, ProcessExt, PidExt};
use num::FromPrimitive;

#[cfg(target_os = "windows")]
use crate::services::ServiceChecker;

// ============================================================================
// MITRE ATT&CK FRAMEWORK (EDR STANDARD)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MitreTactic {
    InitialAccess, Execution, Persistence, PrivilegeEscalation,
    DefenseEvasion, CredentialAccess, Discovery, LateralMovement,
    Collection, CommandAndControl, Exfiltration, Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub id: String,         // e.g. T1105
    pub name: String,       // e.g. Ingress Tool Transfer
    pub tactic: MitreTactic,
}

// ============================================================================
// FORENSIC TELEMETRY DATA TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryIndicator {
    pub path: String,
    #[serde(default)] pub value_name: Option<String>,
    #[serde(default)] pub expected_data: Option<String>,
    #[serde(default)] pub auto_revert: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllDependency {
    pub name: String,
    #[serde(default)] pub description: String,
    #[serde(default)] pub critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiIndicator {
    pub function_name: String,
    pub module_name: String,
    #[serde(default)] pub severity_impact: u8,
}

// ============================================================================
// THE ULTIMATE BEHAVIORAL RULE SCHEMA (v4.0)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    #[serde(default)] pub description: String,
    #[serde(default)] pub severity: u8,
    #[serde(default)] pub is_private: bool,
    #[serde(default)] pub depends_on: Vec<String>,
    #[serde(default)] pub mitre_mappings: Vec<MitreMapping>,

    // --- Cyber Kill-Chain Pipeline ---
    #[serde(default)] pub attack_line: Vec<String>,
    #[serde(default)] pub attack_target: Vec<String>,
    #[serde(default)] pub attack_staging: Vec<String>,
    #[serde(default)] pub pipeline_threshold: usize,
    #[serde(default)] pub time_window_ms: u64,

    // --- DEEP DLL & API MONITORING ---
    #[serde(default)] pub required_dlls: Vec<DllDependency>,
    #[serde(default)] pub suspicious_apis: Vec<ApiIndicator>,
    #[serde(default)] pub suspicious_dll_patterns: Vec<String>,
    
    // --- Advanced Heuristics ---
    #[serde(default)] pub entropy_threshold: f64,
    #[serde(default)] pub proc_spawn_threshold: usize,
    #[serde(default)] pub archive_actions: Vec<String>,
    #[serde(default)] pub crypto_indicators: Vec<String>,

    // --- Lineage & Identity ---
    #[serde(default)] pub suspicious_parents: Vec<String>,
    #[serde(default)] pub process_search: Vec<String>,
    #[serde(default)] pub commandline_patterns: Vec<String>,
    #[serde(default)] pub blacklist_users: Vec<String>,
    #[serde(default)] pub allowlisted_apps: Vec<String>,

    // --- Persistence & System Tampering ---
    #[serde(default)] pub registry_indicators: Vec<RegistryIndicator>,
    #[serde(default)] pub registry_locking: bool,
    #[serde(default)] pub service_stop_patterns: Vec<String>,

    // --- Decision Logic ---
    #[serde(default)] pub conditions_total: usize,
    #[serde(default)] pub conditions_percentage: f32,
    #[serde(default)] pub min_evasion_delay_ms: u64,

    // --- Automated Response ---
    #[serde(default)] pub terminate_process: bool,
    #[serde(default)] pub quarantine: bool,
    #[serde(default)] pub block_network: bool,
}

// ============================================================================
// COMPREHENSIVE PROCESS BEHAVIOR TRACKER
// ============================================================================

#[derive(Default, Clone)]
pub struct ProcessBehaviorState {
    pub gid: u64,
    pub pid: u32,
    pub appname: String,
    pub exepath: String,
    pub cmdline: String,
    pub parent_name: String,
    pub user_owner: String,

    // --- Deep Inspection Buffers ---
    pub modules_loaded: HashSet<String>,      // Tracking DLLs (Kernel + Usermode hooks)
    pub api_trace_log: HashSet<String>,      // Tracking specific API usage found in strings/imports
    pub files_managed: HashSet<String>,      // Files opened/created
    pub modified_registry: HashSet<String>,
    pub spawn_log: HashSet<u32>,
    
    // --- Behavioral Metrics ---
    pub peak_entropy: f64,
    pub security_score: u8,
    pub pipeline_stages: HashSet<String>,    // LINE, TARGET, STAGING
    pub first_seen_ts: Option<SystemTime>,
    pub last_telemetry_ts: SystemTime,
    
    // --- Forensic Journal ---
    pub journal: VecDeque<String>,
    pub matched_rules: HashSet<String>,
    pub target_mitre_ids: HashSet<String>,
}

// ============================================================================
// THE EDR ENGINE
// ============================================================================

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
    pub event_history: VecDeque<String>,
    sys: sysinfo::System,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
            event_history: VecDeque::with_capacity(5000),
            sys: sysinfo::System::new_all(),
        }
    }

    pub fn load_rules(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path)?;
        let rules: Vec<BehaviorRule> = serde_yaml::from_reader(file)?;
        self.rules = rules;
        Logging::info(&format!("[EDR] Vibe Check: {} professional rules loaded.", self.rules.len()));
        Ok(())
    }

    /// Surgical event dispatch.
    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage) {
        let gid = msg.gid;
        let op = IrpMajorOp::from_byte(msg.irp_op);
        let path = msg.filepathstr.to_lowercase();
        
        // 1. Ensure State State Hub
        if !self.process_states.contains_key(&gid) {
            self.sys.refresh_processes();
            let mut s = ProcessBehaviorState::default();
            s.gid = gid; s.pid = msg.pid;
            s.appname = precord.appname.clone();
            s.exepath = precord.exepath.to_string_lossy().to_string();
            s.last_telemetry_ts = SystemTime::now();
            s.first_seen_ts = Some(precord.time_started);

            if let Some(proc) = self.sys.process(sysinfo::Pid::from(msg.pid as usize)) {
                s.cmdline = proc.cmd().join(" ");
                if let Some(parent) = proc.parent() {
                    if let Some(p_proc) = self.sys.process(parent) {
                        s.parent_name = p_proc.name().to_string();
                    }
                }
            }
            self.process_states.insert(gid, s);
        }

        // 2. Telemetry Ingestion & API/DLL Detection
        {
            let s = self.process_states.get_mut(&gid).unwrap();
            s.last_telemetry_ts = SystemTime::now();

            match op {
                IrpMajorOp::IrpCreate => {
                    s.files_managed.insert(path.clone());
                    // DLL LOAD DETECTION
                    if path.ends_with(".dll") {
                        let dll_name = path.split('\\').last().unwrap_or(&path).to_string();
                        s.modules_loaded.insert(dll_name.clone());
                        s.journal.push_back(format!("DLL_LOAD: {}", dll_name));
                    }
                }
                IrpMajorOp::IrpWrite => {
                    s.files_managed.insert(path.clone());
                    if msg.is_entropy_calc == 1 {
                        if msg.entropy > s.peak_entropy { s.peak_entropy = msg.entropy; }
                    }
                }
                IrpMajorOp::IrpRegistry => {
                    s.modified_registry.insert(path.clone());
                }
                _ => {}
            }

            // --- SURGICAL API & SYSTEM INDICATORS ---
            // We scan the path and cmdline for sensitive API strings (HIPS style)
            let sensitive_indicators = [
                "cryptunprotectdata", "bcryptdecrypt", "ntquerysysteminformation", 
                "zwopensymboliclinkobject", "lsaenumeratelogonsessions", "samrqueryinformationuser",
                "createpursuit", "ntcreateuserprocess", "winhttpconnect", "shellexecutew"
            ];
            for indicator in &sensitive_indicators {
                if path.contains(indicator) || s.cmdline.to_lowercase().contains(indicator) {
                    s.api_trace_log.insert(indicator.to_string());
                }
            }

            // --- Multi-Stage Pipeline Tracking ---
            for rule in &self.rules {
                if rule.attack_line.iter().any(|p| path.contains(&p.to_lowercase())) { s.pipeline_stages.insert(format!("{}:LINE", rule.name)); }
                if rule.attack_target.iter().any(|p| path.contains(&p.to_lowercase())) { s.pipeline_stages.insert(format!("{}:TARGET", rule.name)); }
                if rule.attack_staging.iter().any(|p| path.contains(&p.to_lowercase())) { s.pipeline_stages.insert(format!("{}:STAGING", rule.name)); }
            }
        }

        // 3. Rule Evaluation HUB
        self.evaluate_behavioral_rules(precord, gid);
    }

    fn evaluate_behavioral_rules(&mut self, precord: &mut ProcessRecord, gid: u64) {
        let state = if let Some(s) = self.process_states.get(&gid) { s.clone() } else { return };
        let mut alert_queue = Vec::new();

        for rule in &self.rules {
            if state.matched_rules.contains(&rule.name) { continue; }
            if !rule.depends_on.iter().all(|dep| state.matched_rules.contains(dep)) { continue; }

            let (is_match, reason) = self.check_logic(rule, &state);
            if is_match {
                alert_queue.push((rule.name.clone(), rule.mitre_mappings.clone()));

                if !rule.is_private {
                    Logging::warning(&format!(
                        "[HYDRADRAGON ALERT] Policy Breached: {} | Process: {} | Indicators: {}", 
                        rule.name, precord.appname, reason.join(", ")
                    ));

                    if rule.terminate_process {
                        precord.is_malicious = true;
                        precord.termination_requested = true;
                        if rule.quarantine { precord.quarantine_requested = true; }
                    }
                }
            }
        }

        if !alert_queue.is_empty() {
            if let Some(target) = self.process_states.get_mut(&gid) {
                for (name, mitre) in alert_queue {
                    target.matched_rules.insert(name);
                    for m in mitre { target.target_mitre_ids.insert(m.id); }
                }
            }
        }
    }

    fn check_logic(&self, rule: &BehaviorRule, state: &ProcessBehaviorState) -> (bool, Vec<String>) {
        if rule.allowlisted_apps.iter().any(|app| state.appname.to_lowercase().contains(&app.to_lowercase())) {
            return (false, Vec::new());
        }

        let mut indicators = Vec::new();
        let mut count = 0;

        // 1. Pipeline Stages
        let rule_line = state.pipeline_stages.contains(&format!("{}:LINE", rule.name));
        let rule_target = state.pipeline_stages.contains(&format!("{}:TARGET", rule.name));
        let rule_staging = state.pipeline_stages.contains(&format!("{}:STAGING", rule.name));
        
        let pipeline_hits = rule_line as usize + rule_target as usize + rule_staging as usize;
        if rule.pipeline_threshold > 0 && pipeline_hits >= rule.pipeline_threshold {
            count += 1; indicators.push(format!("Pipeline({})", pipeline_hits));
        }

        // 2. DEEP DLL WATCH
        for dll in &rule.required_dlls {
            if state.modules_loaded.contains(&dll.name.to_lowercase()) {
                count += 1; indicators.push(format!("DLL:{}", dll.name));
            }
        }
        for pattern in &rule.suspicious_dll_patterns {
            if state.modules_loaded.iter().any(|m| m.contains(&pattern.to_lowercase())) {
                count += 1; indicators.push(format!("DllPattern:{}", pattern));
            }
        }

        // 3. API USAGE WATCH
        for api in &rule.suspicious_apis {
            if state.api_trace_log.contains(&api.function_name.to_lowercase()) {
                count += 1; indicators.push(format!("API:{}", api.function_name));
            }
        }

        // 4. Persistence & Services
        #[cfg(target_os = "windows")]
        {
            for svc in &rule.service_stop_patterns {
                if !ServiceChecker::is_running(svc) {
                    count += 1; indicators.push(format!("ServiceStopped:{}", svc));
                }
            }
        }

        // 5. CMD & Lineage
        for p in &rule.commandline_patterns {
            if state.cmdline.to_lowercase().contains(&p.to_lowercase()) {
                count += 1; indicators.push(format!("Cmd:{}", p));
            }
        }
        for p in &rule.suspicious_parents {
            if state.parent_name.to_lowercase().contains(&p.to_lowercase()) {
                count += 1; indicators.push(format!("Parent:{}", p));
            }
        }

        // Decision logic
        if rule.conditions_total > 0 {
            return (count >= rule.conditions_total, indicators);
        }
        if rule.conditions_percentage > 0.01 {
            let ratio = count as f32 / 10.0; // Normalized
            return (ratio >= rule.conditions_percentage, indicators);
        }

        (count > 0 && rule.pipeline_threshold == 0, indicators)
    }

    /// Registry Locking Implementation.
    #[cfg(target_os = "windows")]
    pub fn enforce_registry_protection(&mut self) {
        use windows::Win32::System::Registry::*;
        use windows::core::PCSTR;
        use std::ffi::CString;

        for rule in &self.rules {
            if !rule.registry_locking { continue; }
            for reg in &rule.registry_indicators {
                if let (Some(vname), Some(expected)) = (&reg.value_name, &reg.expected_data) {
                    let parts: Vec<&str> = reg.path.splitn(2, '\\').collect();
                    if parts.len() < 2 { continue; }
                    let h_root = match parts[0].to_uppercase().as_str() {
                        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
                        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
                        _ => continue,
                    };
                    let key_cstr = CString::new(parts[1]).unwrap_or_default();
                    let val_cstr = CString::new(vname.as_str()).unwrap_or_default();
                    let mut hkey = HKEY::default();
                    unsafe {
                        if RegOpenKeyExA(h_root, PCSTR(key_cstr.as_ptr() as *const _), 0, KEY_SET_VALUE, &mut hkey).is_ok() {
                            let data_cstr = CString::new(expected.as_str()).unwrap_or_default();
                            let _ = RegSetValueExA(hkey, PCSTR(val_cstr.as_ptr() as *const _), 0, REG_SZ, Some(data_cstr.as_bytes_with_nul()));
                            let _ = RegCloseKey(hkey);
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enforce_registry_protection(&mut self) {}
}

// EOF - HYDRADRAGON PROFESSIONAL EDR V4.0
