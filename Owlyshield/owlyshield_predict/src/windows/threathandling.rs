use crate::logging::Logging;
use crate::process::{ProcessRecord, ProcessState};
use crate::threat_handler::ThreatHandler;
use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::{
    DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
};
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use windows::core::PCWSTR;
use crate::driver_com::Driver;
use serde::{Serialize, Deserialize};

use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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

impl Default for WindowsThreatHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsThreatHandler {
    const PID_FALLBACK_GID_MASK: u64 = 0x8000_0000_0000_0000;

    pub fn from(driver: Driver) -> WindowsThreatHandler {
        WindowsThreatHandler { driver }
    }
    
    /// Create a new WindowsThreatHandler with a fresh driver connection.
    /// WARNING: This opens a new kernel driver connection every time it's called.
    /// Reusing a single connection is strongly recommended (e.g. via `WindowsThreatHandler::from(driver)`)
    /// to avoid `ERROR_CONNECTION_COUNT_LIMIT` (0x800704D6).
    #[allow(dead_code)]
    pub fn new() -> WindowsThreatHandler {
        let driver = Driver::open_kernel_driver_com()
            .expect("Cannot open driver communication for WindowsThreatHandler (driver connection limit reached?)");
        WindowsThreatHandler { driver }
    }

    fn normalize_driver_path(path: &Path) -> PathBuf {
        PathBuf::from(path.to_string_lossy().replace('/', "\\"))
    }

    fn synthetic_pid_from_gid(gid: u64) -> Option<u32> {
        if gid & Self::PID_FALLBACK_GID_MASK != 0 {
            Some((gid & !Self::PID_FALLBACK_GID_MASK) as u32)
        } else {
            None
        }
    }

    fn kill_pid_direct(pid: u32) -> Result<(), String> {
        unsafe {
            let process = OpenProcess(PROCESS_TERMINATE, BOOL(0), pid)
                .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;

            let terminate_result = if TerminateProcess(process, 1).as_bool() {
                Ok(())
            } else {
                Err(format!(
                    "TerminateProcess({pid}) failed: GetLastError={}",
                    GetLastError().0
                ))
            };
            let _ = CloseHandle(process);
            terminate_result
        }
    }

    fn normalize_usermode_path(path: &Path) -> PathBuf {
        let normalized = path.to_string_lossy().replace('/', "\\");
        let lowered = normalized.to_ascii_lowercase();

        if lowered.starts_with(r"\\?\") || lowered.starts_with(r"\??\") {
            PathBuf::from(normalized)
        } else if lowered.starts_with(r"\device\") {
            PathBuf::from(format!(r"\\?\GLOBALROOT{}", normalized))
        } else {
            PathBuf::from(normalized)
        }
    }

    fn add_kernel_block_path(&self, path: &Path) {
        let driver_path = Self::normalize_driver_path(path);
        if let Some(path_str) = driver_path.to_str() {
            let _ = self.driver.add_block_path(path_str);
            Logging::info(&format!(
                "[ThreatHandler] Added path to KERNEL BLOCK list: {}",
                path_str
            ));
        }
    }

    fn try_delete_file_now(path: &Path) -> std::io::Result<()> {
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut permissions = metadata.permissions();
            if permissions.readonly() {
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(path, permissions);
            }
        }

        std::fs::remove_file(path)
    }

    fn schedule_delete_on_reboot(path: &Path) -> std::io::Result<()> {
        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            if MoveFileExW(
                PCWSTR(wide_path.as_ptr()),
                PCWSTR::null(),
                MOVEFILE_DELAY_UNTIL_REBOOT,
            )
            .as_bool()
            {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    fn delete_with_reboot_fallback(&self, path: &Path) -> bool {
        let usermode_path = Self::normalize_usermode_path(path);

        match Self::try_delete_file_now(&usermode_path) {
            Ok(_) => {
                Logging::alert(&format!(
                    "[ThreatHandler] Removed malicious artifact: {}",
                    usermode_path.display()
                ));
                true
            }
            Err(delete_error) if delete_error.kind() == std::io::ErrorKind::NotFound => {
                Logging::info(&format!(
                    "[ThreatHandler] Artifact already absent after kill: {}",
                    usermode_path.display()
                ));
                true
            }
            Err(delete_error) => {
                Logging::warning(&format!(
                    "[ThreatHandler] Immediate delete failed for {}: {}",
                    usermode_path.display(),
                    delete_error
                ));

                match Self::schedule_delete_on_reboot(&usermode_path) {
                    Ok(_) => {
                        Logging::alert(&format!(
                            "[ThreatHandler] Removal scheduled for reboot: {}",
                            usermode_path.display()
                        ));
                        true
                    }
                    Err(schedule_error) => {
                        Logging::error(&format!(
                            "[ThreatHandler] Failed to schedule reboot removal for {}: {}",
                            usermode_path.display(),
                            schedule_error
                        ));
                        false
                    }
                }
            }
        }
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
        if let Some(pid) = Self::synthetic_pid_from_gid(gid) {
            match Self::kill_pid_direct(pid) {
                Ok(_) => {
                    Logging::info(&format!(
                        "[ThreatHandler] Successfully killed synthetic PID fallback target: PID {} (GID: {})",
                        pid, gid
                    ));
                }
                Err(e) => {
                    Logging::error(&format!(
                        "[ThreatHandler] Failed to kill synthetic PID fallback target: PID {} (GID: {}). Error: {}",
                        pid, gid, e
                    ));
                }
            }
            return;
        }

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

    fn deny_path_access(&self, path: &std::path::Path) {
        self.add_kernel_block_path(path);
    }

    fn kill_and_remove(&self, gid: u64, path: &std::path::Path) {
        let driver_path = Self::normalize_driver_path(path);
        if let Some(pid) = Self::synthetic_pid_from_gid(gid) {
            match Self::kill_pid_direct(pid) {
                Ok(_) => Logging::info(&format!(
                    "[ThreatHandler] Successfully killed synthetic PID fallback target for removal: PID {} (GID: {})",
                    pid, gid
                )),
                Err(e) => Logging::error(&format!(
                    "[ThreatHandler] Failed to kill synthetic PID fallback target for removal: PID {} (GID: {}). Error: {}",
                    pid, gid, e
                )),
            }
        } else {
            match self.driver.kill_and_remove_driver(gid, &driver_path) {
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

        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = self.delete_with_reboot_fallback(path);
        self.add_kernel_block_path(path);
    }

    fn kill_and_quarantine(&self, gid: u64, path: &std::path::Path) {
        // 1. Kill the process first to release file handles
        if let Some(pid) = Self::synthetic_pid_from_gid(gid) {
            match Self::kill_pid_direct(pid) {
                Ok(_) => Logging::info(&format!(
                    "[ThreatHandler] Successfully killed synthetic PID fallback target for quarantine: PID {} (GID: {})",
                    pid, gid
                )),
                Err(e) => Logging::error(&format!(
                    "[ThreatHandler] Failed to kill synthetic PID fallback target for quarantine: PID {} (GID: {}). Error: {}",
                    pid, gid, e
                )),
            }
        } else {
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
        }
        
        // 2. Small delay to ensure process is dead and handles are closed
        std::thread::sleep(std::time::Duration::from_millis(200));

        // 3. Prepare quarantine path
        let quarantine_dir = std::path::Path::new(r"C:\ProgramData\HydraDragonAntivirus\Quarantine");
        if !quarantine_dir.exists() {
            let _ = std::fs::create_dir_all(quarantine_dir);
        }

        let source_path = Self::normalize_usermode_path(path);

        if let Some(filename) = source_path.file_name() {
            let dest_path = quarantine_dir.join(filename);
            
            // 4. Move the file
            match std::fs::rename(&source_path, &dest_path) {
                Ok(_) => {
                    Logging::alert(&format!("Quarantined malicious file to: {}", dest_path.display()));
                }
                Err(e) => {
                    // If rename fails (e.g. across drives), try copy + delete
                    match std::fs::copy(&source_path, &dest_path) {
                        Ok(_) => {
                            let _ = self.delete_with_reboot_fallback(&source_path);
                            Logging::alert(&format!("Quarantined malicious file (copy/delete) to: {}", dest_path.display()));
                        }
                        Err(e2) => {
                            Logging::alert(&format!("Failed to quarantine file {}: {} (Copy error: {})", source_path.display(), e, e2));
                        }
                    }
                }
            }
            
            self.add_kernel_block_path(path);
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
            if log_path.exists()
                && let Ok(content) = std::fs::read_to_string(&log_path)
                    && let Ok(existing) = serde_json::from_str(&content) {
                        entries = existing;
                    }
            
            entries.push(log_entry);
            
            if let Ok(json) = serde_json::to_string_pretty(&entries)
                && let Ok(mut file) = std::fs::File::create(&log_path) {
                    let _ = file.write_all(json.as_bytes());
                }
        }


    fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool) {
        for pid in &proc.pids {
            unsafe {
                DebugSetProcessKillOnExit(kill_proc_on_exit);
                DebugActiveProcessStop(*pid );
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
