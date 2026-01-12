use crate::logging::Logging;
use crate::process::{ProcessRecord, ProcessState};
use crate::worker::threat_handling::ThreatHandler;
use windows::Win32::System::Diagnostics::Debug::{
    DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
};
use crate::driver_com::Driver;
use serde::{Serialize, Deserialize};

use std::io::Write;
use std::time::SystemTime;

#[derive(Serialize, Deserialize, Debug)]
struct QuarantineLogEntry {
    filepath: String,
    timestamp: u64,
    reason: String,
}


pub struct WindowsThreatHandler {
    driver: Driver,
}

impl WindowsThreatHandler {
    pub fn from(driver: Driver) -> WindowsThreatHandler {
        WindowsThreatHandler { driver }
    }
}

impl ThreatHandler for WindowsThreatHandler {
    fn suspend(&self, proc: &mut ProcessRecord) {
        proc.process_state = ProcessState::Suspended;
        for pid in &proc.pids {
            unsafe {
                DebugActiveProcess(*pid);
            }
        }
    }

    fn kill(&self, gid: u64) {
        let proc_handle = self.driver.try_kill(gid).unwrap();
        println!("Killed Process with Handle {}", proc_handle.0);
        Logging::alert(format!("Killed Process with Handle {}", proc_handle.0).as_str());
    }

    fn kill_and_quarantine(&self, gid: u64, path: &std::path::Path) {
        // 1. Kill the process first to release file handles
        let _ = self.driver.try_kill(gid);
        
        // 2. Small delay to ensure process is dead and handles are closed
        std::thread::sleep(std::time::Duration::from_millis(200));

        // 3. Prepare quarantine path
        let quarantine_dir = std::path::Path::new(r"C:\ProgramData\Owlyshield\Quarantine");
        if !quarantine_dir.exists() {
            let _ = std::fs::create_dir_all(quarantine_dir);
        }

        if let Some(filename) = path.file_name() {
            let dest_path = quarantine_dir.join(filename);
            
            // 4. Move the file
            match std::fs::rename(path, &dest_path) {
                Ok(_) => {
                    Logging::alert(&format!("Quarantined malicious file to: {}", dest_path.display()));
                }
                Err(e) => {
                    // If rename fails (e.g. across drives), try copy + delete
                    match std::fs::copy(path, &dest_path) {
                        Ok(_) => {
                            let _ = std::fs::remove_file(path);
                            Logging::alert(&format!("Quarantined malicious file (copy/delete) to: {}", dest_path.display()));
                        }
                        Err(e2) => {
                            Logging::alert(&format!("Failed to quarantine file {}: {} (Copy error: {})", path.display(), e, e2));
                        }
                    }
                }
            }
        }

            
            // 5. Log to JSON for Realtime Learning
            let log_entry = QuarantineLogEntry {
                filepath: path.to_string_lossy().to_string(),
                timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                reason: "Malicious Behavior Detected".to_string(), // In future pass reason
            };
            
            let log_path = quarantine_dir.join("quarantine_log.json");
            
            // Read existing or create new
            let mut entries: Vec<QuarantineLogEntry> = Vec::new();
            if log_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&log_path) {
                    if let Ok(existing) = serde_json::from_str(&content) {
                        entries = existing;
                    }
                }
            }
            
            entries.push(log_entry);
            
            if let Ok(json) = serde_json::to_string_pretty(&entries) {
                if let Ok(mut file) = std::fs::File::create(&log_path) {
                    let _ = file.write_all(json.as_bytes());
                }
            }
        }


    fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool) {
        for pid in &proc.pids {
            unsafe {
                DebugSetProcessKillOnExit(kill_proc_on_exit);
                DebugActiveProcessStop(*pid as u32);
            }
        }
        proc.process_state = ProcessState::Running;
    }

    fn revert_registry(&self, gid: u64) {
        match self.driver.revert_registry_changes(gid) {
            Ok(_) => {
                Logging::alert(&format!("[REGISTRY] Revert signal sent for GID: {}", gid));
            }
            Err(e) => {
                Logging::alert(&format!("[REGISTRY] Failed to revert for GID: {}. Error: {:?}", gid, e));
            }
        }
    }
}
