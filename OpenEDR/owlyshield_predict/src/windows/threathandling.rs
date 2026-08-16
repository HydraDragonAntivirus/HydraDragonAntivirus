use crate::logging::Logging;
use crate::process::{ProcessRecord, ProcessState};
use crate::quarantine::{
    build_quarantine_destination, compute_sha256, delete_with_reboot_fallback,
    normalize_usermode_path, quarantine_file, schedule_delete_on_reboot,
};
use crate::shadow_copy;
use crate::threat_handler::{QuarantineMetadata, ThreatHandler};
use crate::utils::{
    protected_process_reason, protected_process_record_reason,
    suspicious_critical_process_record_reason,
};
use crate::windows::edrsvc_client::Driver;
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::{
    DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

use std::io::Write;
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

    fn get_child_pids_recursive(parent_pid: u32) -> Vec<u32> {
        use sysinfo::{ProcessesToUpdate, System};
        let mut sys = System::new_all();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let mut child_pids = Vec::new();
        let mut queue = vec![parent_pid];
        let mut index = 0;

        while index < queue.len() {
            let current_parent = queue[index];
            index += 1;

            let current_parent_str = current_parent.to_string();
            for (pid, process) in sys.processes() {
                if let Some(ppid) = process.parent() {
                    if ppid.to_string() == current_parent_str {
                        if let Ok(cpid) = pid.to_string().parse::<u32>() {
                            if !queue.contains(&cpid) {
                                queue.push(cpid);
                                child_pids.push(cpid);
                            }
                        }
                    }
                }
            }
        }
        child_pids
    }

    fn kill_pid_direct(&self, pid: u32) -> Result<(), String> {
        if let Some(reason) = protected_process_reason(pid, None) {
            return Err(format!(
                "Refusing to terminate protected PID {}: {}",
                pid, reason
            ));
        }

        // Enumerate child processes recursively first, so they are terminated as well.
        let child_pids = Self::get_child_pids_recursive(pid);
        for cpid in &child_pids {
            if let Some(reason) = protected_process_reason(*cpid, None) {
                Logging::warning(&format!(
                    "[ThreatHandler] Refusing to terminate protected child PID {}: {}",
                    cpid, reason
                ));
                continue;
            }
            // Terminate child process using the driver first, then user-mode fallback
            let synthetic_gid = *cpid as u64 | Self::PID_FALLBACK_GID_MASK;
            let mut terminated = false;
            match self.driver.try_kill(synthetic_gid) {
                Ok(hres) => {
                    if hres.is_ok() {
                        Logging::info(&format!(
                            "[ThreatHandler] Successfully terminated child process PID {} (GID: {}) via driver",
                            cpid, synthetic_gid
                        ));
                        terminated = true;
                    }
                }
                Err(e) => {
                    Logging::warning(&format!(
                        "[ThreatHandler] Failed to communicate with driver for child PID {}. Error: {}",
                        cpid, e
                    ));
                }
            }

            if !terminated {
                // User-mode fallback for child process
                unsafe {
                    if let Ok(process) = OpenProcess(PROCESS_TERMINATE, BOOL(0), *cpid) {
                        let _ = TerminateProcess(process, 1);
                        let _ = CloseHandle(process);
                        Logging::info(&format!(
                            "[ThreatHandler] Terminated child process PID {} via user-mode TerminateProcess fallback",
                            cpid
                        ));
                    }
                }
            }
        }

        // Now terminate the main process
        let synthetic_gid = pid as u64 | Self::PID_FALLBACK_GID_MASK;
        let mut main_terminated = false;
        match self.driver.try_kill(synthetic_gid) {
            Ok(hres) => {
                if hres.is_ok() {
                    Logging::info(&format!(
                        "[ThreatHandler] Successfully terminated target process PID {} (GID: {}) via driver",
                        pid, synthetic_gid
                    ));
                    main_terminated = true;
                } else {
                    Logging::warning(&format!(
                        "[ThreatHandler] Driver returned HRESULT 0x{:08X} when terminating PID {}",
                        hres.0 as u32, pid
                    ));
                }
            }
            Err(e) => {
                Logging::warning(&format!(
                    "[ThreatHandler] Failed to communicate with driver for PID {}. Error: {}",
                    pid, e
                ));
            }
        }

        if main_terminated {
            Ok(())
        } else {
            // User-mode fallback for main process
            unsafe {
                let process = OpenProcess(PROCESS_TERMINATE, BOOL(0), pid)
                    .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;

                let terminate_result = if TerminateProcess(process, 1).as_bool() {
                    Logging::info(&format!(
                        "[ThreatHandler] Terminated target process PID {} via user-mode TerminateProcess fallback",
                        pid
                    ));
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

    /// Seal `path` into a `.hqf` quarantine container, remove the original and
    /// register the path in the kernel block list.
    ///
    /// Shared by `kill_and_quarantine` (after the process has been terminated)
    /// and `quarantine_only` (no termination requested).
    fn seal_into_quarantine(&self, path: &Path, metadata: &QuarantineMetadata) {
        let quarantine_dir = std::path::Path::new(crate::shared_def::QUARANTINE_PATH);
        if let Err(e) = std::fs::create_dir_all(quarantine_dir) {
            Logging::error(&format!(
                "[ThreatHandler] Failed to create quarantine directory {}: {}",
                quarantine_dir.display(),
                e
            ));
            self.add_kernel_block_path(path);
            return;
        }

        let source_path = normalize_usermode_path(path);
        if source_path.as_os_str().is_empty() {
            Logging::warning("[ThreatHandler] Cannot quarantine an empty remediation path");
            self.add_kernel_block_path(path);
            return;
        }

        let detection = metadata.detection.trim();
        let detection = if detection.is_empty() {
            "Malicious Behavior Detected"
        } else {
            detection
        };
        let dest_path = build_quarantine_destination(&source_path, quarantine_dir);
        let sha256 = compute_sha256(&source_path).unwrap_or_else(|_| "unknown".to_string());

        match quarantine_file(&source_path, &dest_path, detection, &sha256) {
            Ok(_) => {
                Logging::alert(&format!(
                    "[ThreatHandler] Quarantined malicious file into container: {}",
                    dest_path.display()
                ));
                if !delete_with_reboot_fallback(&source_path) {
                    Logging::warning(&format!(
                        "[ThreatHandler] Quarantine container created, but cleanup of the original file failed: {}",
                        source_path.display()
                    ));
                }

                // Log to JSON for Realtime Learning
                let log_entry = QuarantineLogEntry {
                    filepath: source_path.to_string_lossy().to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    reason: detection.to_string(),
                };

                let log_path = quarantine_dir.join("quarantine_log.json");

                let mut entries: Vec<QuarantineLogEntry> = Vec::new();
                if log_path.exists()
                    && let Ok(content) = std::fs::read_to_string(&log_path)
                    && let Ok(existing) = serde_json::from_str(&content)
                {
                    entries = existing;
                }

                entries.push(log_entry);

                if let Ok(json) = serde_json::to_string_pretty(&entries)
                    && let Ok(mut file) = std::fs::File::create(&log_path)
                {
                    let _ = file.write_all(json.as_bytes());
                }
            }
            Err(e) => {
                Logging::alert(&format!(
                    "[ThreatHandler] Failed to quarantine file {} into container {}: {}",
                    source_path.display(),
                    dest_path.display(),
                    e
                ));
            }
        }

        self.add_kernel_block_path(path);
    }
}

impl ThreatHandler for WindowsThreatHandler {
    fn suspend(&self, proc: &mut ProcessRecord) {
        if let Some(reason) = suspicious_critical_process_record_reason(proc) {
            Logging::alert(&format!(
                "[CriticalProcessAbuse] Refusing to suspend suspicious critical-marked process {} (GID: {}): {}",
                proc.appname, proc.gid, reason
            ));
            return;
        }

        if let Some(reason) = protected_process_record_reason(proc) {
            Logging::warning(&format!(
                "[ThreatHandler] Refusing to suspend protected process {} (GID: {}): {}",
                proc.appname, proc.gid, reason
            ));
            return;
        }

        proc.process_state = ProcessState::Suspended;
        for pid in &proc.pids {
            unsafe {
                DebugActiveProcess(*pid);
            }
        }
    }

    fn kill(&self, gid: u64) {
        if let Some(pid) = Self::synthetic_pid_from_gid(gid) {
            match self.kill_pid_direct(pid) {
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

        let mut killed = false;
        match self.driver.try_kill(gid) {
            Ok(hres) => {
                if hres.is_ok() {
                    Logging::info(&format!(
                        "[ThreatHandler] Successfully killed process group GID: {}",
                        gid
                    ));
                    killed = true;
                } else {
                    Logging::error(&format!(
                        "[ThreatHandler] Driver failed to kill GID: {}. HRESULT: 0x{:08X}",
                        gid, hres.0 as u32
                    ));
                }
            }
            Err(e) => {
                Logging::error(&format!(
                    "[ThreatHandler] Failed to communicate with driver for GID: {}. Error: {}",
                    gid, e
                ));
            }
        }

        if !killed {
            let pid = (gid & 0xFFFF_FFFF) as u32;
            if pid > 4 {
                Logging::warning(&format!(
                    "[ThreatHandler] Attempting user-mode TerminateProcess fallback for PID {} (from GID {})",
                    pid, gid
                ));
                let _ = self.kill_pid_direct(pid);
            }
        }
    }

    fn deny_path_access(&self, path: &std::path::Path) {
        self.add_kernel_block_path(path);
    }

    fn kill_and_remove(&self, gid: u64, path: &std::path::Path) {
        let driver_path = Self::normalize_driver_path(path);
        if let Some(pid) = Self::synthetic_pid_from_gid(gid) {
            if let Some(reason) = protected_process_reason(pid, Some(path)) {
                Logging::warning(&format!(
                    "[ThreatHandler] Refusing to kill/remove protected PID {} (GID: {}): {}",
                    pid, gid, reason
                ));
                return;
            }

            match self.kill_pid_direct(pid) {
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
                        Logging::info(&format!(
                            "[ThreatHandler] Successfully killed and removed process group GID: {}",
                            gid
                        ));
                    } else {
                        Logging::error(&format!(
                            "[ThreatHandler] Driver failed to kill and remove GID: {}. HRESULT: 0x{:08X}",
                            gid, hres.0 as u32
                        ));
                    }
                }
                Err(e) => {
                    Logging::error(&format!(
                        "[ThreatHandler] Failed to communicate with driver for GID: {} during removal. Error: {}",
                        gid, e
                    ));
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = delete_with_reboot_fallback(path);
        self.add_kernel_block_path(path);
    }

    fn kill_and_quarantine(&self, gid: u64, path: &std::path::Path, metadata: &QuarantineMetadata) {
        // 1. Kill the process first to release file handles
        if let Some(pid) = Self::synthetic_pid_from_gid(gid) {
            if let Some(reason) = protected_process_reason(pid, Some(path)) {
                Logging::warning(&format!(
                    "[ThreatHandler] Refusing to kill/quarantine protected PID {} (GID: {}): {}",
                    pid, gid, reason
                ));
                return;
            }

            match self.kill_pid_direct(pid) {
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
            let mut killed = false;
            match self.driver.try_kill(gid) {
                Ok(hres) => {
                    if hres.is_ok() {
                        Logging::info(&format!(
                            "[ThreatHandler] Successfully killed process group GID: {} for quarantine",
                            gid
                        ));
                        killed = true;
                    } else {
                        Logging::warning(&format!(
                            "[ThreatHandler] Driver returned HRESULT 0x{:08X} when killing GID: {} for quarantine",
                            hres.0 as u32, gid
                        ));
                    }
                }
                Err(e) => {
                    Logging::error(&format!(
                        "[ThreatHandler] Failed to communicate with driver for GID: {} during quarantine. Error: {}",
                        gid, e
                    ));
                }
            }

            if !killed {
                let pid = (gid & 0xFFFF_FFFF) as u32;
                if pid > 4 {
                    Logging::warning(&format!(
                        "[ThreatHandler] Attempting user-mode TerminateProcess fallback for PID {} during quarantine (GID {})",
                        pid, gid
                    ));
                    let _ = self.kill_pid_direct(pid);
                }
            }
        }

        // 2. Small delay to ensure process is dead and handles are closed
        std::thread::sleep(std::time::Duration::from_millis(200));

        self.seal_into_quarantine(path, metadata);
    }

    fn quarantine_only(&self, path: &std::path::Path, metadata: &QuarantineMetadata) {
        self.seal_into_quarantine(path, metadata);
    }

    fn schedule_cleanup_on_reboot(&self, path: &Path) {
        let usermode_path = normalize_usermode_path(path);
        if usermode_path.as_os_str().is_empty() {
            Logging::warning("[ThreatHandler] Cannot schedule reboot cleanup for an empty path");
            return;
        }

        match schedule_delete_on_reboot(&usermode_path) {
            Ok(_) => {
                Logging::alert(&format!(
                    "[ThreatHandler] Cleanup scheduled for next restart: {}",
                    usermode_path.display()
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Logging::info(&format!(
                    "[ThreatHandler] Reboot cleanup skipped because artifact is already absent: {}",
                    usermode_path.display()
                ));
            }
            Err(e) => {
                Logging::error(&format!(
                    "[ThreatHandler] Failed to schedule reboot cleanup for {}: {}",
                    usermode_path.display(),
                    e
                ));
            }
        }

        self.add_kernel_block_path(path);
    }

    fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool) {
        for pid in &proc.pids {
            unsafe {
                DebugSetProcessKillOnExit(kill_proc_on_exit);
                DebugActiveProcessStop(*pid);
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
                Logging::alert(&format!(
                    "[REGISTRY] Failed to revert for GID: {}. Error: {:?}",
                    gid, e
                ));
            }
        }
    }

    fn restore_files_from_shadow_copy(&self, paths: &[PathBuf]) {
        let summary = shadow_copy::restore_files(paths);
        if summary.requested > 0 {
            Logging::info(&format!(
                "[ThreatHandler] Shadow-copy restore summary: requested={}, attempted={}, restored={}, skipped={}, failed={}",
                summary.requested,
                summary.attempted,
                summary.restored,
                summary.skipped,
                summary.failed
            ));
        }
    }

    fn clone_box(&self) -> Box<dyn ThreatHandler> {
        Box::new(WindowsThreatHandler {
            driver: self.driver.clone(),
        })
    }
}
