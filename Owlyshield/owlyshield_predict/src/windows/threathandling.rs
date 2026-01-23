use crate::logging::Logging;
use crate::process::{ProcessRecord, ProcessState};
use crate::threat_handler::ThreatHandler;
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


#[derive(Clone)]
pub struct WindowsThreatHandler {
    driver: Driver,
}

impl WindowsThreatHandler {
    pub fn from(driver: Driver) -> WindowsThreatHandler {
        WindowsThreatHandler { driver }
    }
    
    /// Create a new WindowsThreatHandler with a fresh driver connection.
    /// WARNING: This opens a new kernel driver connection every time it's called.
    /// Reusing a single connection is strongly recommended (e.g. via `WindowsThreatHandler::from(driver)`)
    /// to avoid `ERROR_CONNECTION_COUNT_LIMIT` (0x800704D6).
    pub fn new() -> WindowsThreatHandler {
        let driver = Driver::open_kernel_driver_com()
            .expect("Cannot open driver communication for WindowsThreatHandler (driver connection limit reached?)");
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
        match self.driver.try_kill(gid) {
            Ok(hres) => {
                if hres.is_ok() {
                    Logging::info(&format!("[ThreatHandler] Successfully killed process group GID: {}", gid));
                } else {
                    Logging::error(&format!("[ThreatHandler] Driver failed to kill GID: {}. HRESULT: 0x{:08X}", gid, hres.0 as u32));
                }
            }
            Err(e) => {
                Logging::error(&format!("[ThreatHandler] Failed to communicate with driver for GID: {}. Error: {}", gid, e));
            }
        }
    }

    fn kill_and_remove(&self, gid: u64, path: &std::path::Path) {
        match self.driver.kill_and_remove_driver(gid, path) {
            Ok(hres) => {
                if hres.is_ok() {
                    Logging::info(&format!("[ThreatHandler] Successfully killed and removed process group GID: {}", gid));
                } else {
                    Logging::error(&format!("[ThreatHandler] Driver failed to kill and remove GID: {}. HRESULT: 0x{:08X}", gid, hres.0 as u32));
                }
            }
            Err(e) => {
                Logging::error(&format!("[ThreatHandler] Failed to communicate with driver for GID: {} during removal. Error: {}", gid, e));
            }
        }
    }

    fn kill_and_quarantine(&self, gid: u64, path: &std::path::Path) {
        // 1. Kill the process first to release file handles
        match self.driver.try_kill(gid) {
            Ok(hres) => {
                if hres.is_ok() {
                    Logging::info(&format!("[ThreatHandler] Successfully killed process group GID: {} for quarantine", gid));
                } else {
                    Logging::warning(&format!("[ThreatHandler] Driver returned HRESULT 0x{:08X} when killing GID: {} for quarantine", hres.0 as u32, gid));
                }
            }
            Err(e) => {
                Logging::error(&format!("[ThreatHandler] Failed to communicate with driver for GID: {} during quarantine. Error: {}", gid, e));
            }
        }
        
        // (Removed delay to ensure immediate action)

        // 3. Prepare quarantine path
        let quarantine_dir = std::path::Path::new(r"C:\ProgramData\HydraDragonAntivirus\Quarantine");
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

    fn clone_box(&self) -> Box<dyn ThreatHandler> {
        Box::new(WindowsThreatHandler { driver: self.driver.clone() })
    }
}
