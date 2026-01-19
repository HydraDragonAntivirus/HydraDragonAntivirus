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

    fn clone_box(&self) -> Box<dyn ThreatHandler> {
        Box::new(LinuxThreatHandler {})
    }

    fn revert_registry(&self, _gid: u64) {
        todo!()
    }
}
  
