use std::path::Path;
use crate::process::ProcessRecord;

    /// Trait for handling threat responses (kill, suspend, quarantine, etc.)
    pub trait ThreatHandler: Send + Sync {
        fn suspend(&self, proc: &mut ProcessRecord);
        fn kill(&self, gid: u64);
        fn kill_and_quarantine(&self, gid: u64, path: &Path);
        fn kill_and_remove(&self, gid: u64, path: &Path);
        fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool);
        fn revert_registry(&self, gid: u64);
        fn clone_box(&self) -> Box<dyn ThreatHandler>;
    }
