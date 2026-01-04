use alloc::string::String;

use crate::{core::process_monitor::ProcessMonitor, response::containment::Containment};

pub use containment::{DRIVER_MODE, DriverMode};

mod containment;
mod reporting;

pub trait ReportInfo {
    fn explain(&self) -> String;
    fn event_type() -> ReportEventType;
}

#[derive(Debug, Clone, Copy)]
pub enum ReportEventType {
    GhostHunt,
}

/// Reports an event to the telemetry server, containing the process if the EDR is configured in
/// Block mode.
pub fn contain_and_report<T: ReportInfo>(pid: u32, details: &T) {
    if DRIVER_MODE == DriverMode::Blocking {
        ProcessMonitor::disallow_syscalls(pid);
        Containment::contain_process(pid);
    }

    // todo report
}
