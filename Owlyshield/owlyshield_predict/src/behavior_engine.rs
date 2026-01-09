use std::collections::{HashMap, HashSet};
use lru::LruCache;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use sysinfo::{SystemExt, ProcessExt, PidExt};

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
    
    // Advanced Indicators
    #[serde(default)]
    pub crypto_apis: Vec<String>,
    #[serde(default)]
    pub suspicious_parents: Vec<String>,
    #[serde(default)]
    pub allowlisted_apps: Vec<String>,
    #[serde(default)]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub archive_actions: Vec<String>,
    #[serde(default)]
    pub archive_locations: Vec<String>,
    #[serde(default)]
    pub max_staging_lifetime_ms: u64,
    #[serde(default)]
    pub closed_process_paths: Vec<String>,
    #[serde(default)]
    pub quarantine: bool,
    #[serde(default)]
    pub conditions_percentage: f32,
    #[serde(default)]
    pub registry_indicators: Vec<RegistryIndicator>,
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
    pub registry_security_locking: bool,
    #[serde(default)]
    pub min_evasion_delay_ms: u64,
    #[serde(default)]
    pub commandline_patterns: Vec<String>,
}

#[derive(Default)]
pub struct ProcessBehaviorState {
    pub accessed_attack_lines: HashMap<String, SystemTime>,
    pub staged_attack_files: HashSet<String>,
    pub has_active_connection: bool,
    pub parent_name: String,
    pub accessed_attack_targets: HashSet<String>,
    pub high_entropy_detected: bool,
    pub crypto_api_count: u32,
    pub archive_action_detected: bool,
    pub archive_in_temp_detected: bool,
    pub registry_activity: Vec<(String, String)>,
    pub source_target_violation_detected: bool,
    pub registry_security_modification_detected: bool,
    pub first_event_time: Option<SystemTime>,
    pub startup_latency_ms: u64,
    pub env_violations: Vec<String>,
    pub appname: String,
    pub exepath: String,
    pub commandline: String,
    pub search_target_accessed: HashSet<String>,
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

    /// Proactive sweep of all running processes to find malware variants by behavioral traits.
    /// This is called on startup and can be called periodically.
    pub fn find_malware_variants(&mut self, precords: &mut LruCache<u64, ProcessRecord>) {
        self.sys.refresh_all();
        
        let mut processes_to_check = Vec::new();
        for (pid, process) in self.sys.processes() {
            processes_to_check.push((pid.as_u32(), process.name().to_string(), process.exe().to_path_buf(), process.cmd().join(" ")));
        }

        for (pid, name, exe, cmd) in processes_to_check {
            // Check if we already have a record for this PID (via another GID)
            let mut found_gid = None;
            for (gid, precord) in precords.iter() {
                if precord.appname == name && precord.exepath == exe {
                    found_gid = Some(*gid);
                    break;
                }
            }

            let gid = found_gid.unwrap_or(pid as u64); // Use PID as GID if not found
            
            // Populate state if not exists
            self.process_states.entry(gid).or_insert_with(|| {
                let mut s = ProcessBehaviorState::default();
                s.appname = name.clone();
                s.exepath = exe.to_string_lossy().to_string();
                s.commandline = cmd.clone();
                
                // Try to get parent name
                if let Some(proc) = self.sys.process(sysinfo::Pid::from(pid as usize)) {
                     if let Some(parent_pid) = proc.parent() {
                        if let Some(parent_proc) = self.sys.process(parent_pid) {
                            s.parent_name = parent_proc.name().to_string();
                        }
                    }
                }
                s
            });

            // Perform a check for this process
            // We need a dummy ProcessRecord if we don't have one
            if !precords.contains(&gid) {
                let mut mock_record = ProcessRecord::new(gid, name.clone(), exe.clone());
                self.check_rules(&mut mock_record, gid);
                if mock_record.termination_requested {
                     // If detected, we should add it to precords so the worker can kill it
                     precords.put(gid, mock_record);
                }
            } else {
                let mut precord = precords.get_mut(&gid).unwrap();
                self.check_rules(precord, gid);
            }
        }
    }

    pub fn process_event(&mut self, precord: &mut ProcessRecord, msg: &IOMessage) {
        let gid = msg.gid;
        let pid = msg.pid;

        // 1. Pre-calculate values that require borrowing self
        let exfiltration_enabled = self.rules.iter().any(|r| r.detect_exfiltration);
        let has_active_conn = if exfiltration_enabled {
            let active = self.has_active_connections(pid);
            if active {
                self.signal_firewall(pid);
            }
            active
        } else {
            false
        };

        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        // 2. Perform updates to process state using split borrowing
        {
            // Refresh system state for process lookups (parent, closed processes)
            self.sys.refresh_processes();
            
            let states = &mut self.process_states;
            let rules = &self.rules;

            let state = states.entry(gid).or_insert_with(|| {
                let mut s = ProcessBehaviorState::default();
                s.appname = precord.appname.clone();
                s.exepath = precord.exepath.to_string_lossy().to_string();

                if let Some(proc) = self.sys.process(sysinfo::Pid::from(pid as usize)) {
                    s.commandline = proc.cmd().join(" ");
                    if let Some(parent_pid) = proc.parent() {
                        if let Some(parent_proc) = self.sys.process(parent_pid) {
                            s.parent_name = parent_proc.name().to_string();
                        }
                    }
                } else {
                    s.parent_name = "unknown".to_string();
                    s.commandline = "unknown".to_string();
                }
                s
            });

            if has_active_conn {
                state.has_active_connection = true;
            }

            // 0. Track First Event and Latency
            if state.first_event_time.is_none() {
                let now = SystemTime::now();
                state.first_event_time = Some(now);
                state.startup_latency_ms = now.duration_since(precord.time_started)
                    .unwrap_or(Duration::from_secs(0))
                    .as_millis() as u64;
            }

            let filepath = msg.filepathstr.to_lowercase();

            // Track events for ALL rules
            for rule in rules {
                // 1. Track Attack Line Access
                for b_path in &rule.attack_line {
                    if filepath.contains(&b_path.to_lowercase()) {
                        state.accessed_attack_lines.insert(b_path.clone(), SystemTime::now());
                        
                        // Track attack targets
                        for s_file in &rule.attack_target {
                            if filepath.contains(&s_file.to_lowercase()) {
                                state.accessed_attack_targets.insert(s_file.clone());
                            }
                        }
                    }
                }

                // 2. Track Data Staging
                for s_path in &rule.attack_staging {
                    if filepath.contains(&s_path.to_lowercase()) && irp_op == IrpMajorOp::IrpWrite {
                        state.staged_attack_files.insert(filepath.clone());
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
                        
                        // Track archive specifically in staging paths (Temp)
                        for s_path in &rule.attack_staging {
                            if filepath.contains(&s_path.to_lowercase()) {
                                state.archive_in_temp_detected = true;
                            }
                        }

                        // Track archive in specific archive locations
                        for a_loc in &rule.archive_locations {
                            if filepath.contains(&a_loc.to_lowercase()) {
                                state.archive_in_temp_detected = true; 
                            }
                        }
                    }
                }

                // 6. Track Registry Activity
                if irp_op == IrpMajorOp::IrpRegistry {
                    state.registry_activity.push((filepath.clone(), msg.extension.clone()));
                    
                    if msg.extension.to_uppercase() == "SET_SECURITY" {
                        state.registry_security_modification_detected = true;
                    }

                    // Immediate trigger check for specific registry indicators
                    for indicator in &rule.registry_indicators {
                        if filepath.contains(&indicator.path.to_lowercase()) {
                            // recorded but handled in check_rules
                        }
                    }
                }

                // 7. Track Security Tool Search in Paths (Files & Registry)
                for target in &rule.process_search {
                    let target_lower = target.to_lowercase();
                    if filepath.contains(&target_lower) && !state.appname.to_lowercase().contains(&target_lower) {
                        state.search_target_accessed.insert(target.clone());
                    }
                }

                // 8. Track Source-Target Violations
                for s_loc in &rule.source_locations {
                    if precord.appname.to_lowercase().contains(&s_loc.to_lowercase()) {
                        for t_loc in &rule.target_locations {
                            if filepath.contains(&t_loc.to_lowercase()) && (irp_op == IrpMajorOp::IrpWrite || irp_op == IrpMajorOp::IrpSetInfo) {
                                state.source_target_violation_detected = true;
                            }
                        }
                    }
                }
            }
        } // state and rules borrows are dropped here

        // 3. Check for matches
        self.check_rules(precord, gid);
    }

    fn check_rules(&self, precord: &mut ProcessRecord, gid: u64) {
        let state = match self.process_states.get(&gid) {
            Some(s) => s,
            None => return,
        };

        for rule in &self.rules {
            // Skip detection if app is allowlisted
            if rule.allowlisted_apps.iter().any(|app| precord.appname.to_lowercase().contains(&app.to_lowercase())) {
                continue;
            }

            // Lifetime Check (False Positive Mitigation)
            if rule.max_staging_lifetime_ms > 0 {
                let file_age = self.get_file_age_ms(&precord.exepath);
                if file_age > rule.max_staging_lifetime_ms {
                    // This app is long-established on the system, skip aggressive heuristics
                    continue;
                }
            }

            // Condition A: Attack Pipeline Access within time window
            let now = SystemTime::now();
            let recent_access_count = state.accessed_attack_lines.values()
                .filter(|&&t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < rule.time_window_ms as u128)
                .count();

            // Condition B: Data Staging
            let has_staged_data = !state.staged_attack_files.is_empty();

            // Condition E: Sensitive Access (e.g., Attack Targets)
            let has_sensitive_access = !state.accessed_attack_targets.is_empty();

            // Condition C: Exfiltration (now based on detect_exfiltration rule field and state.has_active_connection)
            let is_uploading = rule.detect_exfiltration && state.has_active_connection && (has_sensitive_access || recent_access_count > 0 || has_staged_data);

            // Condition D: Suspicious Parent
            let is_suspicious_parent = rule.suspicious_parents.iter().any(|p| state.parent_name.to_lowercase().contains(&p.to_lowercase()));

            // Condition G: Specified processes are closed (not running)
            let mut closed_targets = Vec::new();
            for target in &rule.closed_process_paths {
                if !self.is_any_process_running(&[target.clone()]) {
                    closed_targets.push(target.clone());
                }
            }

            // Condition Count Logic
            let mut satisfied_conditions = 0;
            let mut total_tracked_conditions = 0;
            let mut detailed_indicators = Vec::new();
            
            // 1. Attack Pipeline access
            total_tracked_conditions += 1;
            if recent_access_count >= rule.pipeline_threshold { 
                satisfied_conditions += 1; 
                let lines: Vec<String> = state.accessed_attack_lines.keys().cloned().collect();
                detailed_indicators.push(format!("AttackPipelineAccess({})", lines.join(", ")));
            }

            // 2. Data staging
            total_tracked_conditions += 1;
            if has_staged_data { 
                satisfied_conditions += 1; 
                detailed_indicators.push(format!("DataStaging({} files written to Staging)", state.staged_attack_files.len()));
            }

            // 3. Exfiltration / Upload behavior
            total_tracked_conditions += 1;
            if is_uploading { 
                satisfied_conditions += 1; 
                detailed_indicators.push("Exfiltration(Upload detected after data access)".to_string());
            }

            // 4. Suspicious parent
            total_tracked_conditions += 1;
            if is_suspicious_parent { 
                satisfied_conditions += 1; 
                detailed_indicators.push(format!("SuspiciousParent({})", state.parent_name));
            }

            // 5. Sensitive access
            total_tracked_conditions += 1;
            if has_sensitive_access { 
                satisfied_conditions += 1; 
                let targets: Vec<String> = state.accessed_attack_targets.iter().cloned().collect();
                detailed_indicators.push(format!("AttackTargetRead({})", targets.join(", ")));
            }

            // 6. High entropy
            total_tracked_conditions += 1;
            if state.high_entropy_detected { 
                satisfied_conditions += 1; 
                detailed_indicators.push("HighEntropyWrite(Observed)".to_string());
            }

            // 7. Crypto usage
            total_tracked_conditions += 1;
            if state.crypto_api_count > 0 { 
                satisfied_conditions += 1; 
                detailed_indicators.push(format!("CryptoApiUsage({} calls)", state.crypto_api_count));
            }

            // 8. Archive actions
            total_tracked_conditions += 1;
            if state.archive_action_detected { 
                satisfied_conditions += 1; 
                if state.archive_in_temp_detected {
                    detailed_indicators.push("ArchiveCreationInTemp(Detected)".to_string());
                } else {
                    detailed_indicators.push("ArchiveCreation(Detected)".to_string());
                }
            }

            // 9. Target processes closed
            for closed_target in &closed_targets {
                total_tracked_conditions += 1;
                satisfied_conditions += 1;
                detailed_indicators.push(format!("TargetProcessClosed({})", closed_target));
            }

            // 10. Source-Target Violation
            if !rule.source_locations.is_empty() {
                total_tracked_conditions += 1;
                if state.source_target_violation_detected {
                    satisfied_conditions += 1;
                    detailed_indicators.push("SourceTargetFileViolation(Suspicious process modifying system file)".to_string());
                }
            }

            // 11. Registry Security Modification
            total_tracked_conditions += 1;
            if state.registry_security_modification_detected {
                satisfied_conditions += 1;
                detailed_indicators.push("RegistrySecurityModification(DACL change detected)".to_string());
                
                // If the rule specifically requires registry locking detection
                if rule.registry_security_locking {
                     // This already incremented satisfied_conditions above, 
                     // but we could add more weight here if needed.
                }
            }

            // 12. Environmental Violations (Check on every event for aggressive detection)
            if !rule.process_search.is_empty() || !rule.blacklisted_users.is_empty() || !rule.blacklisted_services.is_empty() {
                total_tracked_conditions += 1;
                let (violation, reasons) = self.check_environmental_indicators(rule, &self.sys);
                if violation {
                    satisfied_conditions += 1;
                    detailed_indicators.extend(reasons);
                }
            }

            // 13. Registry Indicators Matching
            for indicator in &rule.registry_indicators {
                total_tracked_conditions += 1;
                // Check if process has accessed this registry key
                if state.registry_activity.iter().any(|(p, _)| p.to_lowercase().contains(&indicator.path.to_lowercase())) {
                    satisfied_conditions += 1;
                    detailed_indicators.push(format!("RegistryIndicatorMatched({})", indicator.path));
                }
            }

            // 14. Anti-Delay / Evasion Detection
            if rule.min_evasion_delay_ms > 0 {
                total_tracked_conditions += 1;
                if state.startup_latency_ms >= rule.min_evasion_delay_ms {
                    satisfied_conditions += 1;
                    detailed_indicators.push(format!("StartupDelayDetected({}ms latency)", state.startup_latency_ms));
                }
            }

            // 15. Tasia Kill-Chain Correlation
            let explorer_killed = closed_targets.iter().any(|p| p.to_lowercase() == "explorer.exe");
            let has_tasia_registry = !rule.registry_indicators.is_empty() && state.registry_activity.iter().any(|(p, _)| {
                rule.registry_indicators.iter().any(|ind| p.to_lowercase().contains(&ind.path.to_lowercase()))
            });

            if explorer_killed && has_tasia_registry {
                total_tracked_conditions += 1;
                satisfied_conditions += 1;
                detailed_indicators.push("TasiaKillChain(Explorer Killed + Registry Lockout detected)".to_string());
            }

            // 16. CommandLine Patterns Match
            for pattern in &rule.commandline_patterns {
                total_tracked_conditions += 1;
                if state.commandline.to_lowercase().contains(&pattern.to_lowercase()) {
                    satisfied_conditions += 1;
                    detailed_indicators.push(format!("CommandLinePatternMatched({})", pattern));
                }
            }

            // 17. Security Tool Search Detection (Unified: CommandLine + Paths)
            for target in &rule.process_search {
                total_tracked_conditions += 1;
                let cmd_lower = state.commandline.to_lowercase();
                let target_lower = target.to_lowercase();
                
                let searched_in_cmd = cmd_lower.contains(&target_lower) && !state.appname.to_lowercase().contains(&target_lower);
                let searched_in_paths = state.search_target_accessed.contains(target);

                if searched_in_cmd || searched_in_paths {
                    satisfied_conditions += 1;
                    let source = if searched_in_cmd && searched_in_paths { "Cmd+Path" } 
                                else if searched_in_cmd { "CommandLine" } 
                                else { "FilePath/Registry" };
                    detailed_indicators.push(format!("SecurityToolSearchDetected(Target: {}, Source: {})", target, source));
                }
            }

            let satisfied_ratio = satisfied_conditions as f32 / total_tracked_conditions as f32;

            if satisfied_ratio >= rule.conditions_percentage {
                 Logging::warning(&format!(
                    "[BehaviorEngine] !!! DETECTION !!!\nProcess: {}\nRule Match: {}\nConfidence: {:.1}% ({}/{})\nIndicators:\n  - {}",
                    precord.appname, rule.name, satisfied_ratio * 100.0, satisfied_conditions, total_tracked_conditions,
                    detailed_indicators.join("\n  - ")
                ));
                // Set detection flags
                precord.is_malicious = true;
                precord.termination_requested = true;
                if rule.quarantine {
                    precord.quarantine_requested = true;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_environmental_indicators(&self, rule: &BehaviorRule, sys: &sysinfo::System) -> (bool, Vec<String>) {
        let mut violations = Vec::new();

        // Check Search Targets (Environmental)
        for target in &rule.process_search {
            if sys.processes().values().any(|p| p.name().to_lowercase().contains(&target.to_lowercase())) {
                violations.push(format!("SearchTargetProcessRunning({})", target));
            }
        }


        // Check Blacklisted Users
        let current_user = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
        for bad_user in &rule.blacklisted_users {
            if current_user.contains(&bad_user.to_lowercase()) {
                violations.push(format!("BlacklistedUser({})", current_user));
            }
        }

        // Check Blacklisted Services
        // Note: Simple check via process list for now as service querying is heavy
        for bad_service in &rule.blacklisted_services {
            if sys.processes().values().any(|p| p.name().to_lowercase().contains(&bad_service.to_lowercase())) {
                violations.push(format!("BlacklistedServiceProcess({})", bad_service));
            }
        }

        (!violations.is_empty(), violations)
    }


    #[cfg(not(target_os = "windows"))]
    fn check_environmental_indicators(&self, _rule: &BehaviorRule, _sys: &sysinfo::System) -> (bool, Vec<String>) {
        (false, Vec::new())
    }

    #[cfg(target_os = "windows")]
    fn is_any_process_running(&self, process_names: &[String]) -> bool {
        for process_name in process_names {
            if self.sys.processes().values().any(|p| p.name().to_lowercase() == process_name.to_lowercase()) {
                return true;
            }
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    fn is_any_process_running(&self, _names: &[String]) -> bool {
        false
    }

    #[cfg(target_os = "windows")]
    fn has_active_connections(&self, pid: u32) -> bool {
        use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};
        use windows::Win32::Networking::WinSock::AF_INET;

        if pid == 0 { return false; }

        let mut dw_size = 0;
        unsafe {
            let _ = GetExtendedTcpTable(None, &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
            if dw_size == 0 { return false; }

            let mut buffer = vec![0u8; dw_size as usize];
            if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                // Parse the table to verify the PID
                let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let num_entries = (*table).dwNumEntries as usize;
                let rows = std::ptr::addr_of!((*table).table) as *const MIB_TCPROW_OWNER_PID;
                
                for i in 0..num_entries {
                    let row = *rows.add(i);
                    if row.dwOwningPid == pid {
                        // Check if it's an established outbound connection (state 5 = ESTABLISHED)
                        if row.dwState == 5 && row.dwRemoteAddr != 0 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    fn has_active_connections(&self, _pid: u32) -> bool {
        false
    }

    fn signal_firewall(&self, pid: u32) {
        use std::io::Write;
        // Try to connect to the HydraDragonFirewall pipe to flag this PID as suspicious
        if let Ok(mut stream) = std::fs::OpenOptions::new()
            .write(true)
            .open("\\\\.\\pipe\\HydraDragonFirewall") {
            let _ = writeln!(stream, "PID:{} SUSPICIOUS_PID:TRUE", pid);
        }
    }

    #[cfg(target_os = "windows")]
    pub fn check_registry_indicators(&self) {
        use windows::Win32::System::Registry::{
            HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG,
            RegOpenKeyExA, RegQueryValueExA, KEY_READ, HKEY, REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_VALUE_TYPE
        };
        use windows::core::PCSTR;
        use std::ffi::CString;

        for rule in &self.rules {
            for indicator in &rule.registry_indicators {
                let parts: Vec<&str> = indicator.path.splitn(2, '\\').collect();
                if parts.len() < 2 { continue; }
                
                let root_key = match parts[0].to_uppercase().as_str() {
                    "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
                    "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
                    "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
                    "HKU" | "HKEY_USERS" => HKEY_USERS,
                    "HKCC" | "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
                    _ => continue,
                };
                
                let subkey = CString::new(parts[1]).unwrap_or_default();
                let mut hkey = HKEY::default();
                
                unsafe {
                    if RegOpenKeyExA(root_key, PCSTR(subkey.as_ptr() as *const _), 0, KEY_READ, &mut hkey).is_ok() {
                        let value_name_opt = indicator.value_name.as_deref();
                        let expected_data_opt = indicator.expected_data.as_deref();

                        // Find process that touched this key recently
                        let mut offending_proc_info = String::from("Unknown Process");
                        let indicator_path_lower = indicator.path.to_lowercase();
                        
                        // Look for the most recent process that touched this key
                        if let Some(state) = self.process_states.values()
                            .filter(|s| s.registry_activity.iter().any(|(p, _)| p.to_lowercase().contains(&indicator_path_lower)))
                            .last() {
                            offending_proc_info = format!("{} ({})", state.appname, state.exepath);
                        } else {
                            // SKIP if we can't attribute it to a process we are tracking
                            let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
                            continue;
                        }

                        if value_name_opt.is_none() && expected_data_opt.is_none() {
                            // Path-only indicator: Key exists, so it's a match!
                            Logging::warning(&format!(
                                "[BehaviorEngine] !!! REGISTRY DETECTION (PATH) !!!\nProcess: {}\nRule: {}\nKey: {}\nAction: Malicious Registry Key Presence Detected",
                                offending_proc_info, rule.name, indicator.path
                            ));
                        } else {
                            let value_name_str = value_name_opt.unwrap_or("");
                            let value_name = CString::new(value_name_str).unwrap_or_default();
                            let mut data_type = REG_VALUE_TYPE::default();
                            let mut data_size = 0u32;
                            
                            // Query size first
                            if RegQueryValueExA(hkey, PCSTR(value_name.as_ptr() as *const _), None, Some(&mut data_type), None, Some(&mut data_size)).is_ok() {
                                 let mut buffer = vec![0u8; data_size as usize];
                                 if RegQueryValueExA(hkey, PCSTR(value_name.as_ptr() as *const _), None, Some(&mut data_type), Some(buffer.as_mut_ptr()), Some(&mut data_size)).is_ok() {
                                     
                                     let actual_value = if data_type == REG_DWORD {
                                         if buffer.len() >= 4 {
                                             let val = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                                             val.to_string()
                                         } else { String::new() }
                                     } else if data_type == REG_SZ || data_type == REG_EXPAND_SZ {
                                         String::from_utf8_lossy(&buffer).trim_end_matches('\0').to_string()
                                     } else {
                                         String::from("Unsupported")
                                     };
    
                                     let expected_data = expected_data_opt.unwrap_or("");
                                     let matched = if data_type == REG_DWORD {
                                         actual_value == expected_data
                                     } else {
                                         actual_value.to_lowercase().contains(&expected_data.to_lowercase())
                                     };
    
                                     if matched {
                                         Logging::warning(&format!(
                                            "[BehaviorEngine] !!! REGISTRY DETECTION !!!\nProcess: {}\nRule: {}\nKey: {}\\{}\nValue: {}\nExpected: {}\nAction: Malicious Registry Modification Detected - REVERTING...",
                                            offending_proc_info, rule.name, indicator.path, indicator.value_name.as_deref().unwrap_or(""), actual_value, expected_data
                                         ));
                                         
                                         // Revert Logic
                                         unsafe {
                                             let vn_lower = value_name_str.to_lowercase();
                                             if vn_lower == "debugger" {
                                                 let _ = windows::Win32::System::Registry::RegDeleteValueA(hkey, PCSTR(value_name.as_ptr() as *const _));
                                                 Logging::info(&format!("Reverted IFEO Hijack on: {} (Offending Process: {})", indicator.path, offending_proc_info));
                                             } else if actual_value == "1" {
                                                 let zero = 0u32;
                                                 let zero_bytes = zero.to_le_bytes();
                                                 let _ = windows::Win32::System::Registry::RegSetValueExA(hkey, PCSTR(value_name.as_ptr() as *const _), 0, REG_DWORD, Some(&zero_bytes));
                                                 Logging::info(&format!("Reverted Security Policy Change: {} = 0 (Offending Process: {})", indicator.value_name.as_deref().unwrap_or(""), offending_proc_info));
                                             } else if actual_value == "0" && (vn_lower == "tamperprotection" || vn_lower == "enablelua") {
                                                 let one = 1u32;
                                                 let one_bytes = one.to_le_bytes();
                                                 let _ = windows::Win32::System::Registry::RegSetValueExA(hkey, PCSTR(value_name.as_ptr() as *const _), 0, REG_DWORD, Some(&one_bytes));
                                                 Logging::info(&format!("Reverted Security Policy Change: {} = 1 (Offending Process: {})", indicator.value_name.as_deref().unwrap_or(""), offending_proc_info));
                                             }
                                         }
                                     }
                                 }
                            }
                        }
                        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn check_registry_indicators(&self) {}

    fn get_file_age_ms(&self, path: &PathBuf) -> u64 {
        #[cfg(target_os = "windows")]
        {
            use std::fs;
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(created) = metadata.created() {
                    if let Ok(duration) = SystemTime::now().duration_since(created) {
                        return duration.as_millis() as u64;
                    }
                }
            }
        }
        0 // Return 0 if we can't get metadata, treating it as "new" for safety
    }
}
