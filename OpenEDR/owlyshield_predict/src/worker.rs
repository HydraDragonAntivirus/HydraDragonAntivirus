pub mod process_record_handling {
    use std::path::PathBuf;

    use windows::Win32::Foundation::CloseHandle;

    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    use crate::IOMessage;
    use crate::config::Config;
    use crate::process::ProcessRecord;
    use crate::threat_handler::ThreatHandler;

    pub trait Exepath {
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf>;
    }

    #[derive(Default)]
    pub struct ExepathLive;

    impl Exepath for ExepathLive {
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            let pid = iomsg.pid;
            unsafe {
                let r_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if let Ok(handle) = r_handle
                    && !(handle.is_invalid() || handle.0 == 0)
                {
                    let mut buffer = vec![0u16; 1024];
                    let mut size = buffer.len() as u32;
                    let res = QueryFullProcessImageNameW(
                        handle,
                        PROCESS_NAME_WIN32,
                        windows::core::PWSTR(buffer.as_mut_ptr()),
                        &mut size,
                    );

                    CloseHandle(handle);
                    if res.as_bool() {
                        let path = String::from_utf16_lossy(&buffer[..size as usize]);
                        return Some(PathBuf::from(path));
                    }
                }
                None
            }
        }

        #[cfg(target_os = "linux")]
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            Some(iomsg.runtime_features.exepath.clone())
        }
    }

    #[derive(Default)]
    pub struct ExePathReplay;
    impl Exepath for ExePathReplay {
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            Some(iomsg.runtime_features.exepath.clone())
        }
    }

    pub trait ProcessRecordIOHandler {
        fn handle_io(&mut self, process_record: &mut ProcessRecord);
    }

    pub struct ProcessRecordHandlerLive<'a> {
        #[allow(dead_code)]
        config: &'a Config,
        #[allow(dead_code)]
        threat_handler: Box<dyn ThreatHandler>,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerLive<'_> {
        fn handle_io(&mut self, _precord: &mut ProcessRecord) {
            // ML prediction handled by the worker in process_io() (fast static detection)
        }
    }

    impl<'a> ProcessRecordHandlerLive<'a> {
        pub fn new(
            config: &'a Config,
            threat_handler: Box<dyn ThreatHandler>,
        ) -> ProcessRecordHandlerLive<'a> {
            ProcessRecordHandlerLive {
                config,
                threat_handler,
            }
        }
    }

    #[allow(dead_code)]
    pub struct ProcessRecordHandlerReplay {
        timesteps_stride: usize,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerReplay {
        fn handle_io(&mut self, _precord: &mut ProcessRecord) {
            // CSV export removed (no ML model)
        }
    }

    impl ProcessRecordHandlerReplay {
        pub fn new(config: &Config) -> ProcessRecordHandlerReplay {
            ProcessRecordHandlerReplay {
                timesteps_stride: config.timesteps_stride,
            }
        }
    }
}

mod process_records {
    use crate::config::{Config, Param};
    use lru::LruCache;
    use std::fs;
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use crate::logging::Logging;
    use crate::process::{ProcessRecord, ProcessState};
    use crate::threat_handler::ThreatHandler;
    use crate::utils::{
        protected_process_record_reason, suspicious_critical_process_record_reason,
    };

    pub struct ProcessRecords {
        pub process_records: LruCache<u64, ProcessRecord>,
        pub terminated_records: LruCache<u64, ProcessRecord>,
    }

    impl ProcessRecords {
        pub fn new() -> ProcessRecords {
            ProcessRecords {
                process_records: LruCache::new(NonZeroUsize::new(10000).unwrap()),
                terminated_records: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            }
        }

        pub fn get_precord_by_gid(&mut self, gid: u64) -> Option<&ProcessRecord> {
            self.process_records.get(&gid)
        }

        pub fn get_precord_mut_by_gid(&mut self, gid: u64) -> Option<&mut ProcessRecord> {
            self.process_records.get_mut(&gid)
        }

        pub fn insert_precord(&mut self, gid: u64, precord: ProcessRecord) {
            self.process_records.push(gid, precord);
        }

        pub fn process_suspended_procs(
            &mut self,
            config: &Config,
            threat_handler: Box<dyn ThreatHandler>,
        ) {
            let now = SystemTime::now();
            for (gid, proc) in self.process_records.iter_mut() {
                if proc.process_state == ProcessState::Suspended
                    && now
                        .duration_since(proc.time_suspended.unwrap_or(now))
                        .unwrap_or(Duration::from_secs(0))
                        > Duration::from_secs(120)
                {
                    if let Some(reason) = suspicious_critical_process_record_reason(proc) {
                        Logging::alert(&format!(
                            "[CriticalProcessAbuse] Refusing timed kill of suspicious critical-marked process {} (GID: {}): {}",
                            proc.appname, proc.gid, reason
                        ));
                        threat_handler.awake(proc, false);
                    } else if let Some(reason) = protected_process_record_reason(proc) {
                        Logging::warning(&format!(
                            "[ProcessRecords] Refusing timed kill of protected process {} (GID: {}): {}",
                            proc.appname, proc.gid, reason
                        ));
                        threat_handler.awake(proc, false);
                    } else {
                        threat_handler.awake(proc, true);
                        threat_handler.kill(*gid);
                    }
                }
            }

            let command_files_path = Path::new(&config[Param::ConfigPath]).join("tmp");
            if command_files_path.exists() {
                for command_file_dir_entry in fs::read_dir(command_files_path).unwrap() {
                    let pbuf_command_file = command_file_dir_entry.unwrap().path();
                    if pbuf_command_file.is_file()
                        && let Some(ostr_fname) = pbuf_command_file.file_name()
                        && let Some(fname) = ostr_fname.to_str()
                        && let Some((command, str_gid)) = fname.split_once("_")
                        && let Ok(gid) = str_gid.parse::<u64>()
                        && let Some(proc) = self.process_records.get_mut(&gid)
                    {
                        match command {
                            "A" => {
                                threat_handler.awake(proc, false);
                            }
                            "K" => {
                                if let Some(reason) =
                                    suspicious_critical_process_record_reason(proc)
                                {
                                    Logging::alert(&format!(
                                        "[CriticalProcessAbuse] Refusing manual kill of suspicious critical-marked process {} (GID: {}): {}",
                                        proc.appname, proc.gid, reason
                                    ));
                                    threat_handler.awake(proc, false);
                                } else if let Some(reason) = protected_process_record_reason(proc) {
                                    Logging::warning(&format!(
                                        "[ProcessRecords] Refusing manual kill of protected process {} (GID: {}): {}",
                                        proc.appname, proc.gid, reason
                                    ));
                                    threat_handler.awake(proc, false);
                                } else {
                                    threat_handler.awake(proc, true);
                                    threat_handler.kill(gid);
                                }
                            }
                            &_ => {}
                        }
                        if fs::remove_file(pbuf_command_file.as_path()).is_err() {
                            println!("cannot remove");
                            eprintln!("pbuf_command_file = {:?}", pbuf_command_file);
                        }
                    }
                }
            }
        }
    }
}

pub mod worker_instance {
    use crate::ExepathLive;
    use crate::IOMessage;

    use crate::config::Config;
    use crate::logging::Logging;
    use crate::predictions::prediction::input_tensors::VecvecCappedF32;
    use crate::process::ProcessRecord;
    use crate::process::ProcessState;
    use crate::shared_def::IrpMajorOp;

    use crate::shared_def::effective_hypervisor_raw_event_type;
    use crate::threat_handler::ThreatHandler;

    use crate::worker::process_record_handling::{
        ExePathReplay, Exepath, ProcessRecordHandlerReplay, ProcessRecordIOHandler,
    };
    use crate::worker::process_records::ProcessRecords;

    use std::collections::HashSet;

    use std::path::{Path, PathBuf};

    use sysinfo::{ProcessesToUpdate, System};

    pub trait IOMsgPostProcessor {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord);
    }

    /// No-op post-processor (CSV/MQTT/RPC pipeline removed).
    pub struct IOMsgPostProcessorWriter;

    impl IOMsgPostProcessor for IOMsgPostProcessorWriter {
        fn postprocess(&mut self, _iomsg: &mut IOMessage, _precord: &ProcessRecord) {}
    }

    impl IOMsgPostProcessorWriter {
        pub fn from(_config: &Config) -> IOMsgPostProcessorWriter {
            IOMsgPostProcessorWriter
        }
    }

    pub struct Worker<'a> {
        pub config: &'a Config,
        process_records: ProcessRecords,
        process_record_handler: Option<Box<dyn ProcessRecordIOHandler + 'a>>,
        exepath_handler: Box<dyn Exepath>,
        iomsg_postprocessors: Vec<Box<dyn IOMsgPostProcessor>>,

        dynamic_hooks_registered: bool,

        dynamic_hook_event_map: std::collections::HashMap<u32, String>,

        dynamic_registered_apis: HashSet<String>,

        next_dynamic_hook_event_id: u32,

        dynamic_hook_registration_blocked: bool,

        dynamic_hook_last_refresh: std::collections::HashMap<u32, std::time::Instant>,

        dynamic_hook_apply_failures: std::collections::HashMap<u32, u32>,
        pub threat_handler: Option<Box<dyn ThreatHandler>>,

        pub driver: Option<crate::Driver>,
        pub last_report_time: Option<std::time::Instant>,
    }

    impl<'a> Worker<'a> {
        pub fn generate_system_report(&mut self) {
            let config = self.config;
            let _ = &config[crate::config::Param::ConfigPath]; // Explicit read to ensure compiler sees it as used
            let mut report = crate::report::SystemReport::collect(config);

            // Collect process snapshots from tracked process records
            for (gid, precord) in self.process_records.process_records.iter() {
                let pid = precord.pids.iter().next().copied().unwrap_or(0);
                let mut path = precord.exepath.to_string_lossy().into_owned();
                if path.is_empty() || path == "UNKNOWN" {
                    if let Some(resolved) = crate::utils::resolve_process_path(pid) {
                        path = resolved.to_string_lossy().into_owned();
                    }
                }

                let mut snapshot = crate::report::ProcessSnapshot {
                    pid,
                    gid: *gid as u32,
                    name: precord.appname.clone(),
                    path,
                    command_line: None,
                    process_state: precord.process_state.to_string(),
                    total_ops: precord.driver_msg_count as u64,
                    high_entropy_files: 0,
                    driver_message_count: precord.driver_msg_count,
                    ops_read: precord.ops_read,
                    ops_written: precord.ops_written,
                    ops_open: precord.ops_open,
                    ops_setinfo: precord.ops_setinfo,
                    bytes_read: precord.bytes_read,
                    bytes_written: precord.bytes_written,
                    files_created: precord.fpaths_created.len(),
                    files_updated: precord.fpaths_updated.len(),
                    files_deleted: precord.files_deleted.len(),
                    directories_touched: 0,
                    is_malicious: precord.is_malicious,
                    detections: Vec::new(),
                    detection_details: None,
                    named_conditions: Vec::new(),
                    detected_apis: Vec::new(),
                    network_targets: Vec::new(),
                    rootkit_implicated: false,
                    rootkit_findings: Vec::new(),
                    remediation_target: None,
                    signature_summary: "Unsigned or Unknown".to_string(),
                    sample_created_paths: Vec::new(),
                    sample_updated_paths: Vec::new(),
                    restart_cleanup_requested: precord.restart_cleanup_requested,
                };

                {
                    let mut directories_touched = std::collections::BTreeSet::new();
                    directories_touched.extend(precord.dirs_with_files_created.iter().cloned());
                    directories_touched.extend(precord.dirs_with_files_updated.iter().cloned());
                    directories_touched.extend(precord.dirs_with_files_opened.iter().cloned());
                    snapshot.directories_touched = directories_touched.len();
                }

                if !precord.command_line.trim().is_empty() {
                    snapshot.command_line = Some(precord.command_line.clone());
                }

                if let Some(ref rule) = precord.triggered_rule_name {
                    snapshot.detections.push(rule.clone());
                }
                snapshot.detection_details = precord.triggered_rule_details.clone();
                snapshot.remediation_target = precord
                    .remediation_target_path
                    .as_ref()
                    .map(|path| path.display().to_string());

                let mut sample_created_paths =
                    precord.fpaths_created.iter().cloned().collect::<Vec<_>>();
                sample_created_paths.sort();
                sample_created_paths.truncate(6);
                snapshot.sample_created_paths = sample_created_paths;

                let mut sample_updated_paths =
                    precord.fpaths_updated.iter().cloned().collect::<Vec<_>>();
                sample_updated_paths.sort();
                sample_updated_paths.truncate(6);
                snapshot.sample_updated_paths = sample_updated_paths;

                snapshot.detections.sort();
                snapshot.detections.dedup();

                report.monitored_processes.push(snapshot);
            }

            match report.save_to_file() {
                Ok(path) => Logging::info(&format!(
                    "[REPORT] HijackThis-style system diagnostic report generated: {}",
                    path.display()
                )),
                Err(e) => Logging::error(&format!("[REPORT] Failed to save system report: {}", e)),
            }
            self.last_report_time = Some(std::time::Instant::now());
        }

        const PID_FALLBACK_GID_MASK: u64 = 0x8000_0000_0000_0000;

        const DYNAMIC_HOOK_EVENT_ID_START: u32 = 0x6000;

        const DYNAMIC_HOOK_MAX_FAILURES: u32 = 3;

        fn is_internal_service_pid(pid: u32) -> bool {
            if pid == std::process::id() {
                return true;
            }
            crate::utils::protected_process_reason(pid, None)
                .map(|r| r.contains("trusted EDR companion"))
                .unwrap_or(false)
        }

        fn is_rootkit_irp(irp_op: &IrpMajorOp) -> bool {
            matches!(
                irp_op,
                IrpMajorOp::IrpRootkitSsdtHook
                    | IrpMajorOp::IrpRootkitHiddenProcess
                    | IrpMajorOp::IrpRootkitHiddenDriver
                    | IrpMajorOp::IrpRootkitKernelHook
                    | IrpMajorOp::IrpRootkitTerminateProcess
                    | IrpMajorOp::IrpRootkitFileMove
                    | IrpMajorOp::IrpRootkitGeneric
            )
        }

        fn is_unattributed_rootkit_event(iomsg: &IOMessage, irp_op: &IrpMajorOp) -> bool {
            Self::is_rootkit_irp(irp_op)
                && iomsg.gid == 0
                && iomsg.pid == 0
                && iomsg.attacker_pid == 0
                && iomsg.kernel_event_info.source_process_id == 0
        }

        fn default_dynamic_hook_event_map() -> std::collections::HashMap<u32, String> {
            std::collections::HashMap::new()
        }

        fn default_registered_dynamic_apis() -> HashSet<String> {
            HashSet::new()
        }

        fn should_refresh_dynamic_hooks_for_pid(&mut self, pid: u32) -> bool {
            if pid == 0 {
                return false;
            }

            let now = std::time::Instant::now();
            let refresh_interval = std::time::Duration::from_millis(750);

            if let Some(last) = self.dynamic_hook_last_refresh.get(&pid)
                && now.duration_since(*last) < refresh_interval
            {
                return false;
            }

            self.dynamic_hook_last_refresh.insert(pid, now);
            true
        }

        fn refresh_dynamic_hooks_for_pid_if_due(&mut self, pid: u32) {
            if Self::should_skip_dynamic_hooks_for_pid(pid) {
                return;
            }

            if self.should_refresh_dynamic_hooks_for_pid(pid) {
                self.register_dynamic_hooks_for_process(pid);
            }
        }

        fn should_skip_dynamic_hooks_for_pid(pid: u32) -> bool {
            if pid == 0 || Self::is_internal_service_pid(pid) {
                return true;
            }

            crate::utils::protected_process_reason(pid, None).is_some()
        }

        /// Normalize unstable kernel GIDs to keep per-process tracking coherent.
        /// 1) gid=0 => PID-scoped synthetic GID.
        /// 2) If PID is already known under another GID, re-use that GID.
        /// 3) If an incoming GID is already owned by a different PID, remap to synthetic PID GID.
        fn normalize_tracking_gid(&self, iomsg: &mut IOMessage) {
            let pid = if iomsg.pid != 0 {
                iomsg.pid
            } else {
                iomsg.attacker_pid
            };
            if pid == 0 {
                return;
            }

            if iomsg.gid == 0 {
                iomsg.gid = Self::PID_FALLBACK_GID_MASK | (pid as u64);
                return;
            }

            if let Some(existing_gid_for_pid) = self.find_gid_by_pid(pid) {
                if existing_gid_for_pid != iomsg.gid {
                    Logging::warning(&format!(
                        "[GID RESOLVE] PID {} remapped from kernel GID {} to tracked GID {}",
                        pid, iomsg.gid, existing_gid_for_pid
                    ));
                    iomsg.gid = existing_gid_for_pid;
                }
                return;
            }

            let record_pid_conflict = self
                .process_records
                .process_records
                .peek(&iomsg.gid)
                .map(|p| !p.pids.is_empty() && !p.pids.contains(&pid))
                .unwrap_or(false);

            if record_pid_conflict {
                let remapped = Self::PID_FALLBACK_GID_MASK | (pid as u64);
                Logging::warning(&format!(
                    "[GID COLLISION] PID {} kernel GID {} collides with existing tracked process; using synthetic GID {}",
                    pid, iomsg.gid, remapped
                ));
                iomsg.gid = remapped;
            }
        }
        pub fn new(config: &'a Config) -> Self {
            // Event parsing / detection decisions stay on the OpenEDR side.
            // This drain thread only keeps the in-process telemetry channel
            // empty so edrsvc event deliveries never block or leak.
            static TELEMETRY_DRAIN_START: std::sync::Once = std::sync::Once::new();
            TELEMETRY_DRAIN_START.call_once(Self::start_telemetry_drain);

            Worker {
                config,
                process_records: ProcessRecords::new(),
                process_record_handler: None,
                exepath_handler: Box::<ExepathLive>::default(),
                threat_handler: None,

                iomsg_postprocessors: vec![],

                dynamic_hooks_registered: false,

                dynamic_hook_event_map: Self::default_dynamic_hook_event_map(),

                dynamic_registered_apis: Self::default_registered_dynamic_apis(),

                next_dynamic_hook_event_id: Self::DYNAMIC_HOOK_EVENT_ID_START,

                dynamic_hook_registration_blocked: false,

                dynamic_hook_last_refresh: std::collections::HashMap::new(),

                dynamic_hook_apply_failures: std::collections::HashMap::new(),

                driver: None,
                last_report_time: None,
            }
        }

        /// Consume the in-process OpenEDR telemetry channel without parsing.
        /// OpenEDR owns event parsing and detection; firewall packed data stays
        /// with the firewall SDK. Events are logged at debug level only.
        fn start_telemetry_drain() {
            let _ = std::thread::Builder::new()
                .name("openedr_telemetry_drain".to_string())
                .spawn(move || {
                    let Some(rx) = crate::ffi::telemetry_receiver() else {
                        return;
                    };

                    Logging::info(
                        "[TelemetryDrain] OpenEDR telemetry drain started (parsing handled by OpenEDR)",
                    );

                    while let Ok(line) = rx.recv() {
                        match line {
                            crate::ffi::TelemetryLine::FirewallPackedData(raw) => {
                                Logging::debug(&format!(
                                    "[TelemetryDrain] Firewall packed data ({} bytes) handled by firewall SDK",
                                    raw.len()
                                ));
                            }
                            crate::ffi::TelemetryLine::OpenedrEvent(raw) => {
                                Logging::debug(&format!(
                                    "[TelemetryDrain] OpenEDR event ({} bytes)",
                                    raw.len()
                                ));
                            }
                        }
                    }

                    Logging::warning("[TelemetryDrain] Telemetry channel closed; drain exiting");
                });
        }

        /// Discover pre-existing processes at startup (one-time only)
        /// This catches processes that were already running before the kernel driver loaded
        pub fn discover_existing_processes(&mut self) {
            Logging::info("[STARTUP] Discovering pre-existing processes (one-time scan)...");

            let mut sys = System::new_all();
            // FIX #1: Provide required arguments to refresh_processes
            sys.refresh_processes(ProcessesToUpdate::All, true);

            let mut discovered_count = 0;
            let mut skipped_count = 0;

            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();

                // Skip system process
                if pid_u32 == 4 || Self::is_internal_service_pid(pid_u32) {
                    continue;
                }

                let exepath = process.exe().map(PathBuf::from).unwrap_or_default();
                let appname = process.name().to_string_lossy().to_string();

                // Skip invalid paths
                if exepath.to_string_lossy().is_empty() || appname.is_empty() {
                    skipped_count += 1;
                    continue;
                }

                // Generate GID for this pre-existing process
                let gid = self.generate_gid_for_discovery(pid_u32, &exepath);

                // Check if kernel already notified us about this process
                if self.process_records.get_precord_by_gid(gid).is_some() {
                    continue;
                }

                // Create ProcessRecord for pre-existing process
                let mut precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                precord.pids.insert(pid_u32);
                self.process_records.insert_precord(gid, precord);

                // Hook every API on the new process (no rules required).
                self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);

                discovered_count += 1;

                Logging::debug(&format!(
                    "[STARTUP] Pre-existing: {} (PID: {}, GID: {}, Path: {})",
                    appname,
                    pid_u32,
                    gid,
                    exepath.display()
                ));
            }

            Logging::info(&format!(
                "[STARTUP] Discovery complete: {} processes registered, {} skipped",
                discovered_count, skipped_count
            ));
        }

        /// Generate a PID-backed synthetic GID for user-mode discovered processes.
        /// This keeps tracking stable and lets the driver action path fall back to PID.
        fn generate_gid_for_discovery(&self, pid: u32, _exepath: &PathBuf) -> u64 {
            Self::PID_FALLBACK_GID_MASK | (pid as u64)
        }

        /// Find GID by PID - needed because kernel GIDs and discovery GIDs may not match
        /// Returns the GID if we're already tracking this PID
        fn find_gid_by_pid(&self, pid: u32) -> Option<u64> {
            for (gid, precord) in &self.process_records.process_records {
                // Check if this precord contains the PID
                if precord.pids.contains(&pid) {
                    return Some(*gid);
                }
            }

            None
        }

        pub fn process_record_handler(
            mut self,
            phandler: Box<dyn ProcessRecordIOHandler + 'a>,
        ) -> Worker<'a> {
            self.process_record_handler = Some(phandler);
            self
        }

        pub fn exepath_handler(mut self, exepath: Box<dyn Exepath>) -> Worker<'a> {
            self.exepath_handler = exepath;
            self
        }

        pub fn threat_handler(mut self, handler: Box<dyn ThreatHandler>) -> Worker<'a> {
            self.threat_handler = Some(handler);
            self
        }

        pub fn driver(mut self, driver: crate::Driver) -> Worker<'a> {
            crate::windows::edrsvc_client::register_shared_driver(driver.clone());
            self.driver = Some(driver);
            self
        }

        pub fn register_iomsg_postprocessor(
            mut self,
            postprocessor: Box<dyn IOMsgPostProcessor>,
        ) -> Worker<'a> {
            self.iomsg_postprocessors.push(postprocessor);
            self
        }

        pub fn build(self) -> Worker<'a> {
            self
        }

        /// Validate all tracked processes and remove any with dead PIDs
        /// This is a safety net to catch processes tracked with mismatched GIDs
        pub fn validate_tracked_processes(&mut self) {
            use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
            use windows::Win32::System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };

            let mut dead_gids = Vec::new();
            let mut total_checked = 0;

            // Check all tracked process records
            for (gid, precord) in &self.process_records.process_records {
                total_checked += 1;
                let pid = precord.pids.iter().next().copied().unwrap_or(0);
                let mut is_dead = false;

                unsafe {
                    match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        Ok(handle) => {
                            let mut exit_code: u32 = 0;
                            if GetExitCodeProcess(handle, &mut exit_code).as_bool()
                                && exit_code != STILL_ACTIVE.0 as u32
                            {
                                is_dead = true;
                            }
                            let _ = CloseHandle(handle);
                        }
                        Err(_) => {
                            // Process handle invalid - definitely dead
                            is_dead = true;
                        }
                    }
                }

                if is_dead {
                    dead_gids.push(*gid);
                }
            }

            if !dead_gids.is_empty() {
                Logging::info(&format!(
                    "[VALIDATION] Cleaning {} dead processes (checked {} total)",
                    dead_gids.len(),
                    total_checked
                ));

                for gid in dead_gids {
                    self.cleanup_process(gid, "Dead (validation)");
                }
            } else if total_checked > 0 {
                Logging::debug(&format!(
                    "[VALIDATION] All {} tracked processes are alive",
                    total_checked
                ));
            }
        }

        /// Centralized cleanup function for removing process from all tracking structures
        fn cleanup_process(&mut self, gid: u64, reason: &str) {
            // Get process info before removal for logging
            let process_info = self
                .process_records
                .get_precord_by_gid(gid)
                .map(|p| (p.appname.clone(), p.exepath.clone()));

            // Remove from process_records
            let precord_opt = self.process_records.process_records.pop(&gid);

            if let Some(mut precord) = precord_opt {
                precord.process_state = ProcessState::Terminated;

                for pid in &precord.pids {
                    self.dynamic_hook_last_refresh.remove(pid);
                    self.dynamic_hook_apply_failures.remove(pid);
                }

                // Keep terminated history out of the active tracking map so the same
                // dead process cannot be "cleaned up" over and over again.
                self.process_records.terminated_records.push(gid, precord);
            }

            // Log cleanup
            if let Some((appname, exepath)) = process_info {
                Logging::info(&format!(
                    "[CLEANUP] {} removed: {} (GID: {}, Path: {})",
                    reason,
                    appname,
                    gid,
                    exepath.display()
                ));
            } else {
                Logging::debug(&format!("[CLEANUP] {} removed GID: {}", reason, gid));
            }
        }

        /// Periodic housekeeping scan: prune dead processes, discover new ones,
        /// and apply dynamic API hooks to every process (no rules required).
        /// Detection decisions stay with OpenEDR / fast static detection.
        pub fn scan_processes(&mut self, _config: &Config) {
            use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
            use windows::Win32::System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };

            // --- FIRST: Prune dead processes ---
            // We use direct Kernel Queries (OpenProcess) for 100% accuracy.
            let mut dead_gids = Vec::new();
            for (gid, precord) in self.process_records.process_records.iter() {
                let pid = precord.pids.iter().next().copied().unwrap_or(0);
                unsafe {
                    let handle_res = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                    match handle_res {
                        Ok(handle) => {
                            let mut exit_code: u32 = 0;
                            if GetExitCodeProcess(handle, &mut exit_code).as_bool()
                                && exit_code != STILL_ACTIVE.0 as u32
                            {
                                dead_gids.push(*gid);
                            }
                            let _ = CloseHandle(handle);
                        }
                        Err(_) => {
                            // Kernel says PID is invalid or gone
                            dead_gids.push(*gid);
                        }
                    }
                }
            }

            if !dead_gids.is_empty() {
                Logging::info(&format!(
                    "[HOUSEKEEPING] Pruning {} dead processes",
                    dead_gids.len()
                ));
                for gid in dead_gids {
                    self.cleanup_process(gid, "Dead process");
                }
            }

            // --- SECOND: Discover any new processes that started since last scan ---
            let mut sys = System::new_all();
            sys.refresh_processes(ProcessesToUpdate::All, true);

            let mut discovered_new = 0;
            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                if pid_u32 == 4 || Self::is_internal_service_pid(pid_u32) {
                    continue;
                }

                let exepath = process.exe().map(PathBuf::from).unwrap_or_default();
                let appname = process.name().to_string_lossy().to_string();

                if exepath.to_string_lossy().is_empty() || appname.is_empty() {
                    continue;
                }

                // Check if we're ALREADY tracking this PID
                // This prevents duplicate entries when GID generation is non-deterministic
                if self.find_gid_by_pid(pid_u32).is_some() {
                    self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);
                    // Already tracking this PID - skip to avoid duplicates
                    continue;
                }

                // Generate a new GID for this discovered process
                let gid = self.generate_gid_for_discovery(pid_u32, &exepath);

                Logging::debug(&format!(
                    "[HOUSEKEEPING] Discovered new process during scan: {} (PID: {}, GID: {}, Path: {})",
                    appname,
                    pid_u32,
                    gid,
                    exepath.display()
                ));

                let mut precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                precord.pids.insert(pid_u32);
                self.process_records.insert_precord(gid, precord);

                // Hook every API on the new process (no rules required).
                self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);

                discovered_new += 1;
            }

            if discovered_new > 0 {
                Logging::info(&format!(
                    "[HOUSEKEEPING] Discovered {} new processes",
                    discovered_new
                ));
            }
        }

        pub fn new_replay(config: &'a Config) -> Worker<'a> {
            Worker {
                config,
                process_records: ProcessRecords::new(),
                process_record_handler: Some(Box::new(ProcessRecordHandlerReplay::new(config))),
                exepath_handler: Box::<ExePathReplay>::default(),
                iomsg_postprocessors: vec![],

                dynamic_hooks_registered: false,

                dynamic_hook_event_map: Self::default_dynamic_hook_event_map(),

                dynamic_registered_apis: Self::default_registered_dynamic_apis(),

                next_dynamic_hook_event_id: Self::DYNAMIC_HOOK_EVENT_ID_START,

                dynamic_hook_registration_blocked: false,

                dynamic_hook_last_refresh: std::collections::HashMap::new(),

                dynamic_hook_apply_failures: std::collections::HashMap::new(),
                threat_handler: None,

                driver: None,
                last_report_time: None,
            }
        }

        /// Process kernel I/O event - this is the main event handler
        pub fn process_io(&mut self, iomsg: &mut IOMessage, config: &crate::config::Config) {
            self.normalize_tracking_gid(iomsg);

            {
                // Periodic system report: once per hour.
                let now = std::time::Instant::now();
                let report_interval = std::time::Duration::from_secs(3600); // 1 hour

                if self
                    .last_report_time
                    .map_or(true, |t| now.duration_since(t) > report_interval)
                {
                    self.generate_system_report();
                }
            }

            let irp_kind_for_name_resolution = IrpMajorOp::from_sysmonevent(iomsg.irp_op);
            if matches!(
                irp_kind_for_name_resolution,
                IrpMajorOp::IrpUserModeHookEvent
            ) {
                iomsg.normalize_hypervisor_event();

                let raw_event_type = effective_hypervisor_raw_event_type(iomsg);
                let needs_name_resolution = iomsg.needs_hypervisor_name_resolution();
                if needs_name_resolution
                    && let Some(mapped_api) = self.dynamic_hook_event_map.get(&raw_event_type)
                {
                    iomsg.kernel_event_info.object_name = mapped_api.clone();
                }
            }

            let irp_op = IrpMajorOp::from_sysmonevent(iomsg.irp_op);
            let is_process_create = irp_op == IrpMajorOp::IrpProcessCreate;
            let is_process_terminate = irp_op == IrpMajorOp::IrpProcessTerminate;
            let _ = is_process_create;
            let _ = is_process_terminate;

            if Self::is_unattributed_rootkit_event(iomsg, &irp_op) {
                Logging::warning(&format!(
                    "[ROOTKIT] Unattributed kernel finding: opcode={:?} desc={}",
                    irp_op,
                    iomsg.kernel_event_info.object_name.trim_matches('\0')
                ));
                return;
            }

            // Register or update process record based on kernel event
            self.register_precord(iomsg);
            let tracking_key = iomsg.gid;

            if !is_process_terminate {
                self.refresh_dynamic_hooks_for_pid_if_due(iomsg.pid);
            }

            // Backfill command line for events that don't carry it (e.g., kernel API hook events).
            if iomsg.runtime_features.command_line.trim().is_empty()
                && let Some(precord) = self.process_records.get_precord_by_gid(tracking_key)
                && !precord.command_line.trim().is_empty()
            {
                iomsg.runtime_features.command_line = precord.command_line.clone();
            }

            if is_process_create {
                self.refresh_dynamic_hooks_for_pid_if_due(iomsg.pid);
            }

            if irp_op == IrpMajorOp::IrpKernelMapSection
                || irp_op == IrpMajorOp::IrpProcessHandleOpen
            {
                if !iomsg.filepathstr.is_empty()
                    && iomsg.filepathstr.to_lowercase().ends_with(".dll")
                {
                    self.hook_all_apis_in_dll(&iomsg.filepathstr, iomsg.pid);
                }
            }

            if let Some(precord) = self.process_records.get_precord_mut_by_gid(tracking_key) {
                // For new processes (after startup flood), run static scan
                // immediately so pre-loaded malware state is caught on creation.
                // Skipped during startup_complete=false to avoid the O(nÂ²)
                // per-IrpProcessCreate scan backlog; the periodic 750ms scan covers it.
                // Add IRP record to process
                {
                    precord.add_irp_record(iomsg, None);
                }

                {
                    // Heal stale appname/exepath before ANY detection runs.
                    // register_precord may have left "PROC_<pid>" / "UNKNOWN" if the
                    // IrpProcessCreate event hasn't arrived yet.  Try the exepath handler
                    // one more time so ransomware detection, reports, and all other paths
                    // get correct values from the very first event.
                    let precord_name_stale = precord.appname.is_empty()
                        || precord.appname.starts_with("PROC_")
                        || precord.appname == "UNKNOWN";
                    let precord_path_stale = precord.exepath.to_string_lossy() == "UNKNOWN"
                        || precord.exepath.as_os_str().is_empty();

                    if (precord_name_stale || precord_path_stale)
                        && let Some(resolved_path) = self.exepath_handler.exepath(iomsg)
                        && resolved_path.to_string_lossy() != "UNKNOWN"
                        && !resolved_path.as_os_str().is_empty()
                    {
                        let resolved_name =
                            Self::appname_from_exepath_static(&resolved_path).unwrap_or_default();
                        if precord_path_stale {
                            precord.exepath = resolved_path.clone();
                        }
                        if precord_name_stale && !resolved_name.is_empty() {
                            precord.appname = resolved_name.clone();
                        }
                    }

                    // Run fast static detections for MZ executables and JavaScript files
                    let mut fast_det = None;

                    if is_process_create {
                        let exe_path_str = precord.exepath.to_string_lossy().into_owned();
                        fast_det = crate::ml::fast_detect::fast_detect_file(&exe_path_str, iomsg);
                    }

                    if fast_det.is_none() && !iomsg.filepathstr.is_empty() {
                        fast_det =
                            crate::ml::fast_detect::fast_detect_file(&iomsg.filepathstr, iomsg);
                    }

                    if let Some(det) = fast_det {
                        // Pause protection = log the detection but take no
                        // quarantine/kill action while paused.
                        let protection_paused = crate::globals::is_protection_paused();

                        if !protection_paused {
                            precord.is_malicious = true;
                            precord.termination_requested = true;
                            precord.quarantine_requested = true;
                        }
                        precord.triggered_rule_name = Some(det.detection_name.clone());
                        precord.triggered_rule_details = Some(det.reason.clone());
                        precord.fast_detection_features = Some(det.features.clone());

                        Logging::warning(&format!(
                            "[FastDetection]{} Process {} (PID: {}) triggered static detection '{}': {}",
                            if protection_paused {
                                " [PAUSED - logged only]"
                            } else {
                                ""
                            },
                            precord.appname,
                            iomsg.pid,
                            det.detection_name,
                            det.reason
                        ));

                        if !protection_paused && let Some(ref threat_handler) = self.threat_handler
                        {
                            let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                            let threat_info = crate::actions_on_kill::ThreatInfo {
                                threat_type_label: "Fast Static Detection",
                                virus_name: &det.detection_name,
                                prediction: 1.0,
                                match_details: Some(det.reason.clone()),
                                deny_access: false,
                                terminate: true,
                                quarantine: true,
                                kill_and_remove: false,
                                suspend: false,
                                notify_user: true,
                                revert: false,
                                pending_user_decision: false,
                            };
                            let report_context =
                                crate::actions_on_kill::ActionReportContext::default();
                            crate::actions_on_kill::ActionsOnKill::with_handler(
                                threat_handler.clone_box(),
                            )
                            .run_actions_with_info_and_context(
                                config,
                                precord,
                                &dummy_pred_mtrx,
                                &threat_info,
                                &report_context,
                            );
                        }
                    }

                    // Run process record handler (e.g., prediction)
                    if let Some(process_record_handler) = &mut self.process_record_handler {
                        process_record_handler.handle_io(precord);
                    }

                    // Handle process termination
                    if is_process_terminate {
                        precord.process_state = ProcessState::Terminated;
                        Logging::info(&format!(
                            "[KERNEL] Process Terminated: {} (GID: {}, PID: {})",
                            precord.appname, precord.gid, iomsg.pid
                        ));
                    }

                    // Run postprocessors
                    for postprocessor in &mut self.iomsg_postprocessors {
                        postprocessor.postprocess(iomsg, precord);
                    }
                }
            }

            if is_process_create {
                Logging::debug(&format!(
                    "[PROCESS CREATE] Running immediate housekeeping scan for PID {} GID {}",
                    iomsg.pid, tracking_key
                ));
                self.scan_processes(config);
            }

            // FIX: Cleanup on termination - works regardless of feature flags
            if is_process_terminate {
                self.cleanup_process(tracking_key, "Process terminated");
            }
        }

        pub fn process_suspended_records(
            &mut self,
            config: &Config,
            threat_handler: Box<dyn ThreatHandler>,
        ) {
            self.process_records
                .process_suspended_procs(config, threat_handler);

            // FIX: Cleanup terminated processes regardless of feature flags
            let mut terminated_gids = Vec::new();
            for (gid, proc) in self.process_records.process_records.iter() {
                if proc.process_state == ProcessState::Terminated {
                    terminated_gids.push(*gid);
                }
            }

            for gid in terminated_gids {
                self.cleanup_process(gid, "Suspended terminated");
            }
        }

        /// Register or update process record from kernel event
        /// This is the ONLY place where processes should be added to tracking
        fn register_precord(&mut self, iomsg: &mut IOMessage) {
            let gid = iomsg.gid;
            let pid = iomsg.pid;

            if Self::is_internal_service_pid(pid) {
                return;
            }

            // FIX #2: Extract appname computation to avoid borrowing conflicts
            // Check if we need to upgrade or create
            let needs_action = match self.process_records.get_precord_by_gid(gid) {
                None => Some(true), // Need to create new
                Some(precord) => {
                    let needs_upgrade = precord.exepath.to_string_lossy() == "UNKNOWN"
                        || precord.appname.starts_with("PROC_");
                    if needs_upgrade && !iomsg.filepathstr.is_empty() {
                        Some(false) // Need to upgrade existing
                    } else {
                        None // No action needed
                    }
                }
            };

            match needs_action {
                Some(true) => {
                    // New process - get info from kernel
                    let irp_op = IrpMajorOp::from_sysmonevent(iomsg.irp_op);

                    let (exepath, appname) = if irp_op == IrpMajorOp::IrpProcessCreate
                        && !iomsg.filepathstr.is_empty()
                    {
                        // Process creation event with path from kernel
                        let path = PathBuf::from(&iomsg.filepathstr);
                        let name = Self::appname_from_exepath_static(&path)
                            .unwrap_or_else(|| format!("PROC_{}", pid));
                        (path, name)
                    } else {
                        // Non-creation event or missing path - query system
                        match self.exepath_handler.exepath(iomsg) {
                            Some(path) => {
                                let name = Self::appname_from_exepath_static(&path)
                                    .unwrap_or_else(|| format!("PROC_{}", pid));
                                (path, name)
                            }
                            None => {
                                // Kernel doesn't know about this process
                                Logging::warning(&format!(
                                    "[KERNEL] Unknown process PID {} GID {} - kernel may have missed creation event",
                                    pid, gid
                                ));
                                (PathBuf::from("UNKNOWN"), format!("PROC_{}", pid))
                            }
                        }
                    };

                    let log_type = if irp_op == IrpMajorOp::IrpProcessCreate {
                        "[PROCESS CREATE]"
                    } else {
                        "[KERNEL EVENT]"
                    };

                    if appname.starts_with("PROC_") || exepath.to_string_lossy() == "UNKNOWN" {
                        Logging::warning(&format!(
                            "{} [UNRESOLVED] Process: {} (GID: {}, PID: {})",
                            log_type, appname, gid, pid
                        ));
                    } else {
                        Logging::info(&format!(
                            "{} New Process: {} (GID: {}, PID: {}, Path: {})",
                            log_type,
                            appname,
                            gid,
                            pid,
                            exepath.display()
                        ));
                    }

                    // Create process record
                    let precord = ProcessRecord::from(iomsg, appname.clone(), exepath.clone());

                    // Store process record (moves precord)
                    self.process_records.insert_precord(gid, precord);
                }
                Some(false) => {
                    // Existing process - upgrade UNKNOWN info
                    let path = PathBuf::from(&iomsg.filepathstr);
                    if let Some(name) = Self::appname_from_exepath_static(&path) {
                        // Get mutable reference after all immutable operations are done
                        if let Some(precord) = self.process_records.get_precord_mut_by_gid(gid) {
                            let old_name = precord.appname.clone();

                            Logging::info(&format!(
                                "[KERNEL] Updated Process Info: {} -> {} (GID: {}, PID: {}, Path: {})",
                                old_name,
                                name,
                                gid,
                                pid,
                                path.display()
                            ));

                            precord.exepath = path.clone();
                            precord.appname = name.clone();
                        }
                    }
                }
                None => {
                    // No action needed
                }
            }
        }

        fn appname_from_exepath_static(exepath: &Path) -> Option<String> {
            exepath.file_name()?.to_str().map(|s| s.to_string())
        }

        fn is_api_already_registered(&self, api_spec: &str) -> bool {
            self.dynamic_registered_apis
                .contains(&api_spec.to_ascii_lowercase())
        }

        fn resolve_or_allocate_dynamic_event_id(&mut self, api_spec: &str) -> Option<u32> {
            if let Some((event_id, _)) = self
                .dynamic_hook_event_map
                .iter()
                .find(|(_, existing_api)| existing_api.eq_ignore_ascii_case(api_spec))
            {
                return Some(*event_id);
            }

            let mut candidate = self
                .next_dynamic_hook_event_id
                .max(Self::DYNAMIC_HOOK_EVENT_ID_START);

            while self.dynamic_hook_event_map.contains_key(&candidate) {
                if candidate == u32::MAX {
                    return None;
                }
                candidate += 1;
            }

            self.next_dynamic_hook_event_id = candidate.saturating_add(1);
            Some(candidate)
        }

        fn normalize_hook_module_name(raw: &str) -> String {
            let module = raw.trim();
            if module.is_empty() || module == "*" {
                return module.to_string();
            }

            if module.eq_ignore_ascii_case("exe") {
                return "exe".to_string();
            }

            // Allow full paths (user explicitly specified one).
            if module.contains('\\') || module.contains('/') {
                return module.to_string();
            }

            // If the user already specified an extension (e.g. ntdll.dll), keep it.
            if module.rsplit_once('.').is_some() {
                return module.to_string();
            }

            // Driver compares against BaseDllName (e.g. "advapi32.dll"), so add ".dll" by default.
            format!("{module}.dll")
        }

        /// Monitor every user-mode API exposed to the driver, if MONITOR_ALL_APIS is enabled.
        /// The driver cannot match a wildcard module/function, so instead of registering the
        /// non-functional "*!*" spec we enumerate every DLL currently loaded in the process and
        /// emit a concrete `module!function` spec for each exported API (resolved via goblin).
        fn collect_dynamic_hook_api_targets(&mut self, pid: u32) -> Vec<String> {
            if crate::config::is_monitor_all_apis_enabled() {
                self.enumerate_all_exported_api_specs(pid)
            } else {
                vec![]
            }
        }

        /// Enumerate every module loaded in `pid` and collect a concrete `module!function`
        /// spec for each exported symbol. This is the goblin-based replacement for the
        /// broken "*!*" wildcard hooking: it detects all API calls of all DLLs.
        fn enumerate_all_exported_api_specs(&self, pid: u32) -> Vec<String> {
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
            };
            use windows::Win32::Foundation::CloseHandle;

            let mut specs: Vec<String> = Vec::new();
            let snapshot = match unsafe {
                CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            } {
                Ok(s) => s,
                Err(_) => return specs,
            };
            let mut me: MODULEENTRY32W = unsafe { std::mem::zeroed() };
            me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

            let mut more = unsafe { Module32FirstW(snapshot, &mut me).as_bool() };
            while more {
                let path = {
                    let len = me
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(me.szExePath.len());
                    String::from_utf16_lossy(&me.szExePath[..len])
                };
                if !path.is_empty() {
                    Self::collect_export_specs_from_dll(&path, &mut specs);
                }
                more = unsafe { Module32NextW(snapshot, &mut me).as_bool() };
            }
            unsafe {
                let _ = CloseHandle(snapshot);
            }
            specs
        }

        /// Parse one DLL's export table with goblin and append `module!function` specs.
        fn collect_export_specs_from_dll(dll_path: &str, out: &mut Vec<String>) {
            let module_name =
                match std::path::Path::new(dll_path).file_name().and_then(|s| s.to_str()) {
                    Some(n) => n.to_string(),
                    None => return,
                };
            let bytes = match std::fs::read(dll_path) {
                Ok(b) => b,
                Err(_) => return,
            };
            let pe = match goblin::pe::PE::parse(&bytes) {
                Ok(p) => p,
                Err(_) => return,
            };
            for export in pe.exports {
                if let Some(name) = export.name {
                    out.push(format!("{}!{}", module_name, name));
                }
            }
        }

        fn hook_all_apis_in_dll(&mut self, dll_path: &str, pid: u32) {
            if !crate::config::is_monitor_all_apis_enabled() {
                return;
            }

            if self.dynamic_hook_registration_blocked {
                return;
            }

            let path = std::path::Path::new(dll_path);
            let module_name = match path.file_name().and_then(|s| s.to_str()) {
                Some(name) => name.to_string(),
                None => return,
            };

            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(_) => return,
            };

            let pe = match goblin::pe::PE::parse(&bytes) {
                Ok(p) => p,
                Err(_) => return,
            };

            let mut new_apis = Vec::new();
            for export in pe.exports {
                if let Some(name) = export.name {
                    new_apis.push(format!("{}!{}", module_name, name));
                }
            }

            if new_apis.is_empty() {
                return;
            }

            Logging::info(&format!(
                "[DYNAMIC HOOK] Found {} exports in {} for PID {}",
                new_apis.len(),
                module_name,
                pid
            ));

            let mut added = 0;
            let driver_opt = self.driver.clone();

            for api_spec in new_apis {
                if self.is_api_already_registered(&api_spec) {
                    continue;
                }

                let Some(event_id) = self.resolve_or_allocate_dynamic_event_id(&api_spec) else {
                    self.dynamic_hook_registration_blocked = true;
                    Logging::warning(
                        "[DYNAMIC HOOK] Event-id pool exhausted; stopping new registrations",
                    );
                    break;
                };

                let norm_module = Self::normalize_hook_module_name(&module_name);
                let (module, function) = if let Some(idx) = api_spec.find('!') {
                    (norm_module, api_spec[idx + 1..].to_string())
                } else {
                    continue;
                };

                if module.len() >= 64 || function.len() >= 256 {
                    continue;
                }

                if let Some(driver) = driver_opt.as_ref() {
                    if driver.add_hook_target(&module, &function, event_id).is_ok() {
                        self.dynamic_registered_apis
                            .insert(api_spec.to_ascii_lowercase());
                        self.dynamic_hook_event_map.insert(event_id, api_spec);
                        added += 1;
                    }
                }
            }

            if added > 0 {
                Logging::info(&format!(
                    "[DYNAMIC HOOK] Registered {} new APIs from {}. Triggering hook apply for PID {}",
                    added, module_name, pid
                ));
                if let Some(driver) = driver_opt.as_ref() {
                    let _ = driver.hook_process(pid);
                }
            }
        }

        fn register_dynamic_hooks_for_process(&mut self, pid: u32) {
            if Self::should_skip_dynamic_hooks_for_pid(pid) {
                return;
            }

            if self.dynamic_hook_registration_blocked {
                return;
            }

            let Some(driver) = self.driver.clone() else {
                Logging::warning(&format!(
                    "[DYNAMIC HOOK] Driver not available, cannot hook PID {}",
                    pid
                ));
                return;
            };

            let monitored_apis = self.collect_dynamic_hook_api_targets(pid);
            Logging::debug(&format!(
                "[DYNAMIC HOOK] PID {} resolved {} monitored API(s): {:?}",
                pid,
                monitored_apis.len(),
                monitored_apis
            ));
            if monitored_apis.is_empty() {
                Logging::debug(&format!(
                    "[DYNAMIC HOOK] PID {} skipped: no monitored APIs resolved from loaded rules",
                    pid
                ));
                return;
            }

            let mut registered_count = 0;
            let mut already_registered_count = 0;
            let mut failed_count = 0;
            let mut wildcard_count = 0;

            for api_spec in monitored_apis {
                if self.is_api_already_registered(&api_spec) {
                    already_registered_count += 1;
                    continue;
                }

                let Some(event_id) = self.resolve_or_allocate_dynamic_event_id(&api_spec) else {
                    self.dynamic_hook_registration_blocked = true;
                    Logging::warning(
                        "[DYNAMIC HOOK] Event-id pool exhausted; stopping new registrations",
                    );
                    break;
                };

                let (module, function) = if let Some(idx) = api_spec.find('!') {
                    (
                        Self::normalize_hook_module_name(&api_spec[..idx]),
                        api_spec[idx + 1..].to_string(),
                    )
                } else {
                    wildcard_count += 1;
                    ("*".to_string(), api_spec.clone())
                };

                // SharedDefs.HOOK_CONFIG_DATA currently supports ModuleName[64] and FunctionName[256].
                if module != "*" && module.len() >= 64 {
                    failed_count += 1;
                    Logging::warning(&format!(
                        "[DYNAMIC HOOK] PID {} registration failed: module name too long ({} chars): {}",
                        pid,
                        module.len(),
                        module
                    ));
                    continue;
                }
                if function.len() >= 256 {
                    failed_count += 1;
                    Logging::warning(&format!(
                        "[DYNAMIC HOOK] PID {} registration failed: function name too long ({} chars): {}!{}",
                        pid,
                        function.len(),
                        module,
                        function
                    ));
                    continue;
                }

                match driver.add_hook_target(&module, &function, event_id) {
                    Ok(_) => {
                        self.dynamic_registered_apis
                            .insert(api_spec.to_ascii_lowercase());
                        self.dynamic_hook_event_map.insert(event_id, api_spec);
                        registered_count += 1;
                    }
                    Err(e) => {
                        let hr = e.code().0 as u32;
                        if hr == 0x800705AA || hr == 0x8007000E {
                            self.dynamic_hook_registration_blocked = true;
                            Logging::error(&format!(
                                "[DYNAMIC HOOK] Resource exhaustion while registering PID {} (hr=0x{:08X}); pausing new hooks",
                                pid, hr
                            ));
                            break;
                        }
                        failed_count += 1;
                        Logging::error(&format!(
                            "[DYNAMIC HOOK] Failed registration PID {} event {} {}!{}: {}",
                            pid, event_id, module, function, e
                        ));
                    }
                }
            }

            let has_any_targets = registered_count > 0 || already_registered_count > 0;
            // Always apply when targets exist. The old generation timeline
            // (applied_generation < target_generation) skipped the apply for
            // processes created after startup, so those processes were never
            // hooked until a new API was registered globally.
            let needs_apply = has_any_targets;
            let mut apply_attempted = false;
            let mut apply_succeeded = false;

            if needs_apply {
                apply_attempted = true;
                if let Err(e) = driver.hook_process(pid) {
                    let hr = e.code().0 as u32;
                    let low_word = hr & 0xFFFF;
                    let is_access_denied = hr == 0x80070005 || hr == 0x80070000 || low_word == 5;
                    let is_noaccess_like =
                        hr == 0x800703E6 || hr == 0xC0000005 || low_word == 0x03E6;
                    if hr == 0x80070677 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::debug(&format!(
                            "[DYNAMIC HOOK] PID {} apply skipped: process mitigation blocks dynamic code (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if is_access_denied {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::debug(&format!(
                            "[DYNAMIC HOOK] PID {} apply skipped: access denied (likely protected/critical process) (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if is_noaccess_like {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::debug(&format!(
                            "[DYNAMIC HOOK] PID {} apply skipped: NOACCESS while patching hooks (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x80070016 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::debug(&format!(
                            "[DYNAMIC HOOK] PID {} apply skipped: driver command not recognized for this target (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x8007001F {
                        let failures = self.dynamic_hook_apply_failures.entry(pid).or_insert(0);
                        *failures = failures.saturating_add(1);
                        Logging::error(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: generic driver failure (hr=0x{:08X}); inspect kernel 'UserModeHook' / 'MESSAGE_HOOK_PROCESS' debug output for the exact NTSTATUS",
                            pid, hr
                        ));
                    } else {
                        let failures = self.dynamic_hook_apply_failures.entry(pid).or_insert(0);
                        *failures = failures.saturating_add(1);
                        if *failures >= Self::DYNAMIC_HOOK_MAX_FAILURES
                            && (*failures).is_multiple_of(Self::DYNAMIC_HOOK_MAX_FAILURES)
                        {
                            Logging::warning(&format!(
                                "[DYNAMIC HOOK] PID {} still failing to apply hooks (count={}, hr=0x{:08X})",
                                pid, failures, hr
                            ));
                        } else {
                            Logging::error(&format!(
                                "[DYNAMIC HOOK] Failed to apply hooks to PID {} (attempt {}/{} hr=0x{:08X}): {}",
                                pid,
                                failures,
                                Self::DYNAMIC_HOOK_MAX_FAILURES,
                                hr,
                                e
                            ));
                        }
                    }
                } else {
                    self.dynamic_hook_apply_failures.remove(&pid);
                    apply_succeeded = true;
                }
            }

            self.dynamic_hooks_registered = true;
            let message = format!(
                "[DYNAMIC HOOK] PID {} => registered={} already={} failed={} wildcard={} apply_attempted={} apply_succeeded={}",
                pid,
                registered_count,
                already_registered_count,
                failed_count,
                wildcard_count,
                apply_attempted,
                apply_succeeded
            );
            Logging::debug(&message);
        }
    }
}
