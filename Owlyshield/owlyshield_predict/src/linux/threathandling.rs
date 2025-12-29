use crate::process::ProcessRecord;
use crate::worker::threat_handling::ThreatHandler;
use log::warn;

#[derive(Default)]
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

    fn kill_and_quarantine(&self, gid: u64) {
        warn!(
            "kill_and_quarantine not supported on Linux; requested kill/quarantine for gid {gid}, ignoring"
        );
    }
}
  
