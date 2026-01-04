//! This module is concerned with telemetry and reporting that we emit.

use crate::{core::process_monitor::Process, response::ReportInfo};

pub struct ReportData<'a, T: ReportInfo> {
    process: &'a Process,
    event: &'a T,
}
