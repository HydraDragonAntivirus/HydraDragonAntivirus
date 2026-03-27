use crate::process::ProcessRecord;
use crate::threat_handler::ThreatHandler;
use log::warn;

#[derive(Default, Clone)]
pub struct LinuxThreatHandler {}

impl ThreatHandler for LinuxThreatHandler {
    fn suspend(&self, proc: &mut ProcessRecord) {
        todo!()
    }

    fn kill(&self, gid: u64) {
        todo!()
    }

    fn deny_path_access(&self, path: &std::path::Path) {
        warn!(
            "deny_path_access not supported on Linux; requested kernel deny for {}",
            path.display()
        );
    }

    fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool) {
        todo!()
    }

    fn kill_and_quarantine(&self, gid: u64, _path: &std::path::Path) {
        warn!(
            "kill_and_quarantine not supported on Linux; requested kill/quarantine for gid {gid}, ignoring"
        );
    }

    fn kill_and_remove(&self, gid: u64, _path: &std::path::Path) {
        warn!(
            "kill_and_remove not supported on Linux; requested kill/remove for gid {gid}, ignoring"
        );
    }

    fn schedule_cleanup_on_reboot(&self, path: &std::path::Path) {
        warn!(
            "schedule_cleanup_on_reboot not supported on Linux; requested reboot cleanup for {}, ignoring",
            path.display()
        );
    }

    fn clone_box(&self) -> Box<dyn ThreatHandler> {
        Box::new(LinuxThreatHandler {})
    }

    fn revert_registry(&self, _gid: u64) {
        todo!()
    }
}
  
