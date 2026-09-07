use crate::process::ProcessRecord;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct QuarantineMetadata {
    pub detection: String,
}

/// Trait for handling threat responses (kill, suspend, quarantine, etc.)
pub trait ThreatHandler: Send + Sync {
    fn suspend(&self, proc: &mut ProcessRecord);
    fn kill(&self, gid: u64);
    fn deny_path_access(&self, path: &Path);
    fn kill_and_quarantine(&self, gid: u64, path: &Path, metadata: &QuarantineMetadata);
    /// Quarantine an artifact without terminating the owning process first.
    ///
    /// Used by responses that request `quarantine` without `terminate_process`
    /// (e.g. `action: traffic_attack` network rules), where the offending file
    /// must be sealed even though the process is left running.
    fn quarantine_only(&self, path: &Path, metadata: &QuarantineMetadata);
    fn kill_and_remove(&self, gid: u64, path: &Path);
    fn schedule_cleanup_on_reboot(&self, path: &Path);
    fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool);
    fn revert_registry(&self, gid: u64);
    fn restore_files_from_shadow_copy(&self, paths: &[PathBuf]);
    fn clone_box(&self) -> Box<dyn ThreatHandler>;
}
