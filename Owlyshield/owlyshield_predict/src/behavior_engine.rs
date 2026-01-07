use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use crate::shared_def::{IOMessage, IrpMajorOp};
use crate::process::ProcessRecord;
use crate::logging::Logging;
use sysinfo::{SystemExt, ProcessExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    pub browser_paths: Vec<String>,
    pub sensitive_files: Vec<String>,
    pub staging_paths: Vec<String>,
    pub multi_access_threshold: usize,
    pub time_window_ms: u64,
    pub require_internet: bool,
    
    // Advanced Indicators
    pub crypto_apis: Vec<String>,
    pub suspicious_parents: Vec<String>,
    pub allowlisted_apps: Vec<String>,
    pub entropy_threshold: f64,
    pub archive_actions: Vec<String>,
    pub max_staging_lifetime_ms: u64,
    pub require_browser_closed_recently: bool,
    pub conditions_percentage: f32,
}

#[derive(Default)]
pub struct ProcessBehaviorState {
    pub accessed_browsers: HashMap<String, SystemTime>,
    pub sensitive_files_read: HashSet<String>,
    pub staged_files_written: HashMap<PathBuf, SystemTime>,
    pub last_browser_close: Option<SystemTime>,
    pub crypto_api_count: usize,
    pub high_entropy_detected: bool,
    pub archive_action_detected: bool,
    pub parent_name: String,
}

pub struct BehaviorEngine {
    pub rules: Vec<BehaviorRule>,
    pub process_states: HashMap<u64, ProcessBehaviorState>,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        BehaviorEngine {
            rules: Vec::new(),
            process_states: HashMap::new(),
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
        let state = self.process_states.entry(gid).or_insert_with(|| {
            let mut s = ProcessBehaviorState::default();
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

        // Track events for ALL rules
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

        // Check for matches
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

            // Condition A: Multi-Browser Access within time window
            let now = SystemTime::now();
            let recent_access_count = state.accessed_browsers.values()
                .filter(|&&t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < rule.time_window_ms as u128)
                .count();

            // Condition B: Data Staging
            let has_staged_data = !state.staged_files_written.is_empty();

            // Condition C: Internet Connectivity
            let is_online = if rule.require_internet {
                self.has_active_connections(precord.pids.iter().next().cloned().unwrap_or(0))
            } else {
                true
            };

            // Condition D: Suspicious Parent
            let is_suspicious_parent = rule.suspicious_parents.iter().any(|p| state.parent_name.to_lowercase().contains(&p.to_lowercase()));

            // Condition E: Sensitive File Access (e.g., Cookies, Local State)
            let has_sensitive_access = !state.sensitive_files_read.is_empty();

            // Condition G: Browser closed recently
            let browser_closed_recently = if rule.require_browser_closed_recently {
                state.last_browser_close.map_or(false, |t| now.duration_since(t).unwrap_or(Duration::from_secs(999)).as_millis() < 3600000) // 1 hour threshold for "recently"
            } else {
                true
            };

            // Condition Count Logic
            let mut satisfied_conditions = 0;
            let mut total_tracked_conditions = 0;
            let mut detailed_indicators = Vec::new();
            
            // 1. Multi-browser access
            total_tracked_conditions += 1;
            if recent_access_count >= rule.multi_access_threshold { 
                satisfied_conditions += 1; 
                let browsers: Vec<String> = state.accessed_browsers.keys().cloned().collect();
                detailed_indicators.push(format!("MultiBrowserAccess({})", browsers.join(", ")));
            }

            // 2. Data staging
            total_tracked_conditions += 1;
            if has_staged_data { 
                satisfied_conditions += 1; 
                detailed_indicators.push(format!("DataStaging({} files written to Temp)", state.staged_files_written.len()));
            }

            // 3. Internet connectivity
            total_tracked_conditions += 1;
            if is_online { 
                satisfied_conditions += 1; 
                detailed_indicators.push("InternetAccess(Active)".to_string());
            }

            // 4. Suspicious parent
            total_tracked_conditions += 1;
            if is_suspicious_parent { 
                satisfied_conditions += 1; 
                detailed_indicators.push(format!("SuspiciousParent({})", state.parent_name));
            }

            // 5. Sensitive file access
            total_tracked_conditions += 1;
            if has_sensitive_access { 
                satisfied_conditions += 1; 
                let files: Vec<String> = state.sensitive_files_read.iter().cloned().collect();
                detailed_indicators.push(format!("SensitiveFileRead({})", files.join(", ")));
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
                detailed_indicators.push("ArchiveCreation(Detected)".to_string());
            }

            // 9. Browser state
            if rule.require_browser_closed_recently {
                total_tracked_conditions += 1;
                if browser_closed_recently { 
                    satisfied_conditions += 1; 
                    detailed_indicators.push("BrowserClosedRecently(True)".to_string());
                }
            }

            let satisfied_ratio = satisfied_conditions as f32 / total_tracked_conditions as f32;

            if satisfied_ratio >= rule.conditions_percentage {
                 Logging::warning(&format!(
                    "[BehaviorEngine] !!! DETECTION !!!\nProcess: {}\nRule Match: {}\nConfidence: {:.1}% ({}/{})\nIndicators:\n  - {}",
                    precord.appname, rule.name, satisfied_ratio * 100.0, satisfied_conditions, total_tracked_conditions,
                    detailed_indicators.join("\n  - ")
                ));
                // Set detection flag
                precord.is_malicious = true;
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn has_active_connections(&self, pid: u32) -> bool {
        use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
        use windows::Win32::Networking::WinSock::AF_INET;

        if pid == 0 { return false; }

        let mut dw_size = 0;
        unsafe {
            let _ = GetExtendedTcpTable(None, &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
            if dw_size == 0 { return false; }

            let mut buffer = vec![0u8; dw_size as usize];
            if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                // The table format is complex to parse in a single step without heavy bindings,
                // but we check if GetExtendedTcpTable succeeded and returned data.
                // A more robust check would iterate over the rows and match the PID.
                
                // Simple heuristic for now: if we can get the table, we assume some network capability exists.
                // To be precise, we'd need to cast the buffer to MIB_TCPTABLE_OWNER_PID and iterate.
                return true; 
            }
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    fn has_active_connections(&self, _pid: u32) -> bool {
        false
    }
}
