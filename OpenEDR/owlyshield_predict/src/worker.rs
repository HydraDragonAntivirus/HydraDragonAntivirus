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
            // ML prediction handled by behavior_engine in process_io()
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

        pub fn get_precord_by_gid_or_pid(&mut self, gid: u64, pid: u32) -> Option<&ProcessRecord> {
            if let Some((_, precord)) = self
                .process_records
                .iter()
                .find(|(candidate_gid, _)| **candidate_gid == gid)
            {
                return Some(precord);
            }

            self.process_records
                .iter()
                .find_map(|(_, precord)| precord.pids.contains(&pid).then_some(precord))
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
    
    use crate::actions_on_kill::{
        ActionReportContext, ActionsOnKill, ThreatInfo, restart_cleanup_reason,
    };
    
    use crate::behavioral::app_settings::AppSettings;
    
    use crate::behavioral::behavior_engine::BehaviorEngine;
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
        
        pub behavior_engine: BehaviorEngine,
        
        pub app_settings: AppSettings,
        
        dynamic_hooks_registered: bool,
        
        dynamic_hook_event_map: std::collections::HashMap<u32, String>,
        
        dynamic_registered_apis: HashSet<String>,
        
        next_dynamic_hook_event_id: u32,
        
        dynamic_hook_registration_blocked: bool,
        
        dynamic_hook_last_refresh: std::collections::HashMap<u32, std::time::Instant>,
        
        dynamic_hook_target_generation: u64,
        
        dynamic_hook_applied_generation: std::collections::HashMap<u32, u64>,
        
        dynamic_hook_apply_failures: std::collections::HashMap<u32, u32>,
        pub threat_handler: Option<Box<dyn ThreatHandler>>,
        
        pub driver: Option<crate::Driver>,
        pub last_report_time: Option<std::time::Instant>,
    }

    impl<'a> Worker<'a> {
        
        pub fn generate_system_report(&mut self) {
            let config = self.config;
            let _ = &config[crate::config::Param::ConfigPath]; // Explicit read to ensure compiler sees it as used
            let signatures_count = self.behavior_engine.rules.len();
            let rootkit_findings = self.behavior_engine.get_rootkit_findings();
            
            let fw_pids = self.behavior_engine.firewall_net_pids.read().unwrap();
            let firewall_pids = Some(&*fw_pids);
            let mut report = crate::report::SystemReport::collect(
                config,
                firewall_pids,
                signatures_count,
                rootkit_findings,
            );
            
            let fw_net_details = self.behavior_engine.firewall_net_details.read().unwrap();

            // Collect process snapshots from behavior engine
            for (gid, state) in &self.behavior_engine.process_states {
                let mut path = state.exe_path.to_string_lossy().into_owned();
                if path.is_empty() || path == "UNKNOWN" {
                    if let Some(resolved) = crate::utils::resolve_process_path(state.pid) {
                        path = resolved.to_string_lossy().into_owned();
                    }
                }

                let fallback_directories_touched = state
                    .irp_stats
                    .unique_paths_accessed
                    .iter()
                    .filter_map(|value| {
                        let normalized = value.replace('\\', "/");
                        if !normalized.contains(":/") && !normalized.starts_with("//") {
                            return None;
                        }
                        Path::new(value)
                            .parent()
                            .map(|parent| parent.to_string_lossy().into_owned())
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();

                let fallback_files_updated = state
                    .irp_stats
                    .write_count
                    .saturating_add(state.irp_stats.setinfo_count)
                    .saturating_add(state.irp_stats.rename_count)
                    as usize;

                let mut snapshot = crate::report::ProcessSnapshot {
                    pid: state.pid,
                    gid: *gid as u32,
                    name: state.app_name.clone(),
                    path,
                    command_line: None,
                    process_state: "RUNNING".to_string(),
                    total_ops: state.irp_stats.get_total_operations(),
                    high_entropy_files: state.irp_stats.get_high_entropy_count(),
                    driver_message_count: state.irp_stats.get_total_operations() as usize,
                    ops_read: state.irp_stats.read_count,
                    ops_written: state.irp_stats.write_count,
                    ops_open: state.irp_stats.create_count,
                    ops_setinfo: state.irp_stats.setinfo_count,
                    bytes_read: state.irp_stats.total_bytes_read,
                    bytes_written: state.irp_stats.total_bytes_written,
                    files_created: state.irp_stats.create_count as usize,
                    files_updated: fallback_files_updated,
                    files_deleted: state.irp_stats.delete_count as usize,
                    directories_touched: fallback_directories_touched,
                    is_malicious: false,
                    detections: Vec::new(),
                    detection_details: None,
                    named_conditions: Vec::new(),
                    detected_apis: Vec::new(),
                    network_targets: Vec::new(),
                    rootkit_implicated: state.rootkit_implicated,
                    rootkit_findings: state
                        .rootkit_findings
                        .iter()
                        .take(12)
                        .map(|finding| {
                            format!(
                                "{} (addr=0x{:X}, pid={})",
                                finding.kind.threat_label(),
                                finding.address,
                                finding.pid
                            )
                        })
                        .collect(),
                    remediation_target: None,
                    signature_summary: if state.is_signed {
                        if state.has_valid_signature {
                            "Signed / Trusted".to_string()
                        } else {
                            "Signed / Untrusted".to_string()
                        }
                    } else {
                        "Unsigned or Unknown".to_string()
                    },
                    sample_created_paths: Vec::new(),
                    sample_updated_paths: Vec::new(),
                    restart_cleanup_requested: false,
                };

                if let Some(precord) = self
                    .process_records
                    .get_precord_by_gid_or_pid(*gid, state.pid)
                {
                    snapshot.is_malicious = precord.is_malicious;
                    snapshot.process_state = precord.process_state.to_string();
                    snapshot.driver_message_count = precord.driver_msg_count;
                    snapshot.ops_read = precord.ops_read;
                    snapshot.ops_written = precord.ops_written;
                    snapshot.ops_open = precord.ops_open;
                    snapshot.ops_setinfo = precord.ops_setinfo;
                    snapshot.bytes_read = precord.bytes_read;
                    snapshot.bytes_written = precord.bytes_written;
                    snapshot.files_created = precord.fpaths_created.len();
                    snapshot.files_updated = precord.fpaths_updated.len();
                    snapshot.files_deleted = precord.files_deleted.len();
                    let mut directories_touched = std::collections::BTreeSet::new();
                    directories_touched.extend(precord.dirs_with_files_created.iter().cloned());
                    directories_touched.extend(precord.dirs_with_files_updated.iter().cloned());
                    directories_touched.extend(precord.dirs_with_files_opened.iter().cloned());
                    snapshot.directories_touched = directories_touched.len();
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
                    snapshot.restart_cleanup_requested = precord.restart_cleanup_requested;
                }

                if snapshot.command_line.is_none() && !state.command_line.trim().is_empty() {
                    snapshot.command_line = Some(state.command_line.clone());
                }

                for cond in &state.satisfied_named_conditions {
                    snapshot.named_conditions.push(cond.clone());
                    snapshot.detections.push(format!("Condition: {}", cond));
                }

                snapshot.named_conditions.sort();
                snapshot.named_conditions.dedup();

                snapshot.detected_apis = state.detected_apis.iter().cloned().collect();
                snapshot.detected_apis.sort();
                snapshot.detected_apis.dedup();

                
                if let Some(targets) = fw_net_details.get(&state.pid) {
                    let mut network_targets = targets
                        .iter()
                        .map(|(ip, port)| format!("{}:{}", ip, port))
                        .collect::<Vec<_>>();
                    network_targets.sort();
                    network_targets.dedup();
                    network_targets.truncate(12);
                    snapshot.network_targets = network_targets;
                }

                if let Some(targets) = self
                    .behavior_engine
                    .openedr_net_details
                    .read()
                    .unwrap()
                    .get(&state.pid)
                {
                    let mut network_targets = snapshot.network_targets.clone();
                    network_targets
                        .extend(targets.iter().map(|(ip, port)| format!("{}:{}", ip, port)));
                    network_targets.sort();
                    network_targets.dedup();
                    network_targets.truncate(12);
                    snapshot.network_targets = network_targets;
                }

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
            pid == std::process::id()
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

        
        fn build_behavior_engine(config: &Config) -> BehaviorEngine {
            
            static OPENEDR_TELEMETRY_START: std::sync::Once = std::sync::Once::new();

            let extension_source_mode = config.extension_source_mode();
            let mut engine =
                BehaviorEngine::new_with_extension_source_mode(extension_source_mode.as_deref());

            // Load behavior rules BEFORE any clone is handed to the telemetry
            // consumer thread, so both the worker engine and the consumer-thread
            // clone have detection capability.
            if let Some(rules_dir) = crate::globals::RULES_PATH.get() {
                if let Ok(app_settings) = AppSettings::load(&rules_dir.to_path_buf()) {
                    let rules_path = app_settings.behavior_rules_path.clone();
                    Logging::info(&format!(
                        "[Owlyshield] Handing rules off to BehaviorEngine from path: {:?}",
                        rules_path
                    ));
                    if let Err(e) = engine.load_rules(&rules_path) {
                        Logging::error(&format!(
                            "Failed to load behavior rules from {:?}: {}",
                            rules_path, e
                        ));
                    }
                } else {
                    Logging::error(&format!(
                        "[Owlyshield] Failed to load app settings from rules/settings.yaml at {:?}",
                        rules_dir
                    ));
                }
            } else {
                Logging::error("[Owlyshield] RULES_PATH globals not initialized; behavior rules not loaded");
            }

            OPENEDR_TELEMETRY_START.call_once({
                let engine = engine.clone();
                move || {
                    Self::start_openedr_telemetry_consumer(engine);
                }
            });

            engine
        }

        
        pub fn start_openedr_telemetry_consumer(behavior_engine: BehaviorEngine) {
            std::thread::Builder::new()
                .name("openedr_telemetry_consumer".to_string())
                .spawn(move || {
                    let Some(rx) = crate::ffi::telemetry_receiver() else {
                        Logging::error(
                            "[OpenEDRTelemetry] Telemetry channel not initialized; consumer exiting",
                        );
                        return;
                    };

                    Logging::info(
                        "[OpenEDRTelemetry] Direct OpenEDR telemetry consumer started (in-process)",
                    );

                    while let Ok(line) = rx.recv() {
                        match line {
                            crate::ffi::TelemetryLine::FirewallPackedData(raw_line) => {
                                behavior_engine.ingest_firewall_raw_line(&raw_line);
                            }
                            crate::ffi::TelemetryLine::OpenedrEvent(json) => {
                                Logging::debug(&format!(
                                    "[OpenEDRTelemetry] EVENT RECEIVED: {}",
                                    json
                                ));
                                match serde_json::from_str::<serde_json::Value>(&json) {
                                    Ok(event) => {
                                        // Always process for behavioral analysis
                                        behavior_engine.ingest_openedr_event(&event);
                                    }
                                    Err(err) => Logging::warning(&format!(
                                        "[OpenEDRTelemetry] Failed to parse direct event JSON: {}",
                                        err
                                    )),
                                }
                            }
                        }
                    }

                    Logging::warning("[OpenEDRTelemetry] Telemetry channel closed; consumer exiting");
                })
                .expect("failed to spawn openedr_telemetry_consumer thread");
        }

        
        #[allow(dead_code)]
        fn apply_behavior_detection_state(record: &mut ProcessRecord, det: &ProcessRecord) {
            record.is_malicious = true;
            record.termination_requested = det.termination_requested;
            record.quarantine_requested = det.quarantine_requested;
            record.deny_access_requested = det.deny_access_requested;
            record.kill_and_remove_requested = det.kill_and_remove_requested;
            record.notify_user_requested = det.notify_user_requested;
            record.revert_requested = det.revert_requested;
            record.restart_cleanup_requested = det.restart_cleanup_requested;
            record.triggered_rule_name = det.triggered_rule_name.clone();
            record.triggered_rule_details = det.triggered_rule_details.clone();
            record.remediation_target_path = det.remediation_target_path.clone();
        }

        
        #[allow(dead_code)]
        fn build_behavior_threat_info<'b>(det: &'b ProcessRecord, context: &str) -> ThreatInfo<'b> {
            let mut virus_name = det
                .triggered_rule_name
                .as_deref()
                .unwrap_or("Behavioral Detection");
            let mut legacy_details = None;

            if let Some(encoded) = det.triggered_rule_name.as_deref()
                && let Some(rest) = encoded.strip_prefix("FirewallNetworkBlock|")
            {
                let mut parts = rest.splitn(2, '|');
                if let Some(label) = parts.next()
                    && !label.trim().is_empty()
                {
                    virus_name = label;
                }
                if let Some(details) = parts.next()
                    && !details.trim().is_empty()
                {
                    legacy_details = Some(details.to_string());
                }
            }

            let match_details = det
                .triggered_rule_details
                .clone()
                .or(legacy_details)
                .or_else(|| match &det.triggered_rule_name {
                    Some(rule_name) => match det.remediation_target_path.as_ref() {
                        Some(path) => Some(format!(
                            "Rule '{}' matched during {}. Target: {}",
                            rule_name,
                            context,
                            path.display()
                        )),
                        None => Some(format!("Rule '{}' matched during {}", rule_name, context)),
                    },
                    None => match det.remediation_target_path.as_ref() {
                        Some(path) => Some(format!(
                            "Behavioral detection matched during {}. Target: {}",
                            context,
                            path.display()
                        )),
                        None => Some(format!("Behavioral detection matched during {}", context)),
                    },
                });

            ThreatInfo {
                threat_type_label: "Behavioral Detection",
                virus_name,
                prediction: 1.0,
                match_details,
                deny_access: det.deny_access_requested,
                terminate: det.termination_requested,
                quarantine: det.quarantine_requested,
                kill_and_remove: det.kill_and_remove_requested,
                suspend: det.suspend_requested,
                notify_user: det.notify_user_requested,
                revert: det.revert_requested,
                pending_user_decision: false,
            }
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
            let refresh_interval = std::time::Duration::from_secs(2);

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

            let behavior_pid_conflict = self
                .behavior_engine
                .process_states
                .get(&iomsg.gid)
                .map(|s| s.pid != 0 && s.pid != pid)
                .unwrap_or(false);

            let record_pid_conflict = self
                .process_records
                .process_records
                .peek(&iomsg.gid)
                .map(|p| !p.pids.is_empty() && !p.pids.contains(&pid))
                .unwrap_or(false);

            if behavior_pid_conflict || record_pid_conflict {
                let remapped = Self::PID_FALLBACK_GID_MASK | (pid as u64);
                Logging::warning(&format!(
                    "[GID COLLISION] PID {} kernel GID {} collides with existing tracked process; using synthetic GID {}",
                    pid, iomsg.gid, remapped
                ));
                iomsg.gid = remapped;
            }
        }
        pub fn new(
            config: &'a Config,
            
            app_settings: AppSettings,
        ) -> Self {
            Worker {
                config,
                process_records: ProcessRecords::new(),
                process_record_handler: None,
                exepath_handler: Box::<ExepathLive>::default(),
                threat_handler: None,
                
                app_settings: app_settings.clone(),
                iomsg_postprocessors: vec![],
                
                behavior_engine: Self::build_behavior_engine(config),
                
                dynamic_hooks_registered: false,
                
                dynamic_hook_event_map: Self::default_dynamic_hook_event_map(),
                
                dynamic_registered_apis: Self::default_registered_dynamic_apis(),
                
                next_dynamic_hook_event_id: Self::DYNAMIC_HOOK_EVENT_ID_START,
                
                dynamic_hook_registration_blocked: false,
                
                dynamic_hook_last_refresh: std::collections::HashMap::new(),
                
                dynamic_hook_target_generation: 0,
                
                dynamic_hook_applied_generation: std::collections::HashMap::new(),
                
                dynamic_hook_apply_failures: std::collections::HashMap::new(),
                
                driver: None,
                last_report_time: None,
            }
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

                // Register in behavior engine
                
                {
                    self.behavior_engine.register_process(
                        gid,
                        pid_u32,
                        exepath.clone(),
                        appname.clone(),
                    );
                    self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);
                }

                self.queue_process_start_scan_if_needed(
                    gid,
                    pid_u32,
                    &appname,
                    &exepath,
                    "Startup process executable scan",
                );

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
            // Check behavior engine first (most likely location)
            
            {
                for (gid, state) in &self.behavior_engine.process_states {
                    if state.pid == pid {
                        return Some(*gid);
                    }
                }
            }

            // Fallback: check process_records (in case behavior_engine not enabled)
            for (gid, precord) in &self.process_records.process_records {
                // Check if this precord contains the PID
                if precord.pids.contains(&pid) {
                    return Some(*gid);
                }
            }

            None
        }

        fn queue_process_start_scan_if_needed(
            &mut self,
            _gid: u64,
            _pid: u32,
            _appname: &str,
            _exepath: &Path,
            _reason: &str,
        ) {
        }
        fn sync_firewall_process_contexts(&mut self) {
            let firewall_pids: Vec<u32> = self
                .behavior_engine
                .firewall_net_pids
                .read()
                .unwrap()
                .iter()
                .copied()
                .collect();
            let mut stale_pids = Vec::new();

            for pid in firewall_pids {
                if pid == 0 || Self::is_internal_service_pid(pid) {
                    continue;
                }

                let Some(exepath) = crate::utils::resolve_process_path(pid) else {
                    if !crate::utils::is_process_alive(pid) {
                        stale_pids.push(pid);
                    }
                    continue;
                };

                let appname = Self::appname_from_exepath_static(&exepath)
                    .unwrap_or_else(|| format!("PROC_{}", pid));
                let gid = self
                    .find_gid_by_pid(pid)
                    .unwrap_or(Self::PID_FALLBACK_GID_MASK | (pid as u64));
                let is_new_record = self.process_records.get_precord_by_gid(gid).is_none();

                self.behavior_engine
                    .register_process(gid, pid, exepath.clone(), appname.clone());

                if let Some(precord) = self.process_records.get_precord_mut_by_gid(gid) {
                    precord.pids.insert(pid);
                    if precord.exepath.as_os_str().is_empty()
                        || precord.exepath.to_string_lossy() == "UNKNOWN"
                    {
                        precord.exepath = exepath.clone();
                    }
                    if precord.appname.is_empty()
                        || precord.appname.starts_with("PROC_")
                        || precord.appname == "UNKNOWN"
                    {
                        precord.appname = appname.clone();
                    }
                } else {
                    let mut precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                    precord.pids.insert(pid);
                    self.process_records.insert_precord(gid, precord);
                }

                self.refresh_dynamic_hooks_for_pid_if_due(pid);
                if is_new_record {
                    self.queue_process_start_scan_if_needed(
                        gid,
                        pid,
                        &appname,
                        &exepath,
                        "Firewall-observed process executable scan",
                    );
                }

                if is_new_record {
                    Logging::info(&format!(
                        "[HydraNetPipe] Registered firewall-observed PID {} as tracked worker process {} (GID: {})",
                        pid,
                        exepath.display(),
                        gid
                    ));
                }
            }

            if !stale_pids.is_empty() {
                let mut firewall_pids = self.behavior_engine.firewall_net_pids.write().unwrap();
                for pid in stale_pids {
                    firewall_pids.remove(&pid);
                }
            }
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
            
            {
                use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
                use windows::Win32::System::Threading::{
                    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                };

                let mut dead_gids = Vec::new();
                let mut total_checked = 0;

                // Check all tracked processes in behavior engine
                for (gid, state) in &self.behavior_engine.process_states {
                    total_checked += 1;
                    let pid = state.pid;
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

                // Remove from behavior engine
                
                {
                    self.behavior_engine.process_states.remove(&gid);
                    
                    {
                        let mut firewall_pids =
                            self.behavior_engine.firewall_net_pids.write().unwrap();
                        for pid in &precord.pids {
                            firewall_pids.remove(pid);
                        }
                    }
                    for pid in &precord.pids {
                        self.dynamic_hook_last_refresh.remove(pid);
                        self.dynamic_hook_applied_generation.remove(pid);
                        self.dynamic_hook_apply_failures.remove(pid);
                    }
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

        /// Scan all tracked processes for behavioral detections
        pub fn scan_processes(
            &mut self,
            config: &Config,
            threat_handler: Box<dyn ThreatHandler>,
        ) {
            
            {
                // Import necessary Win32 modules for the Kernel Check
                use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
                use windows::Win32::System::Threading::{
                    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                };

                // Refresh system state to identify new and dead processes
                // We keep sysinfo here because you requested Discovery logic to remain intact
                let mut sys = System::new_all();
                sys.refresh_processes(ProcessesToUpdate::All, true);

                // Deterministic hooking for newly created processes: the OpenEDR
                // telemetry consumer queues LLE_PROCESS_CREATE PIDs here (the
                // in-process FFI mode never feeds process_io), so apply the dynamic
                // API hooks to them directly instead of relying only on the
                // sysinfo sweep below.
                for hook_pid in self.behavior_engine.drain_pending_hook_pids() {
                    Logging::debug(&format!(
                        "[DYNAMIC HOOK] OpenEDR ProcessCreate queue: applying hooks to PID {}",
                        hook_pid
                    ));
                    self.refresh_dynamic_hooks_for_pid_if_due(hook_pid);
                }

                // --- FIRST: Prune dead processes from behavior engine ---
                // IMPROVEMENT: We use direct Kernel Queries (OpenProcess) for 100% accuracy.
                let mut dead_gids = Vec::new();
                for (gid, state) in self.behavior_engine.process_states.iter() {
                    unsafe {
                        let handle_res =
                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, state.pid);
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

                // FIX: Use centralized cleanup function
                if !dead_gids.is_empty() {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Pruning {} dead processes",
                        dead_gids.len()
                    ));
                    for gid in dead_gids {
                        self.cleanup_process(gid, "Dead process");
                    }
                }

                // --- SECOND: Discover any new processes that started since last scan ---
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

                    // FIX: Check if we're ALREADY tracking this PID
                    // This prevents duplicate entries when GID generation is non-deterministic
                    if self.find_gid_by_pid(pid_u32).is_some() {
                        self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);
                        // Already tracking this PID - skip to avoid duplicates
                        continue;
                    }

                    // Generate a new GID for this discovered process
                    // NOTE: This may not match the kernel's GID, but we use PID lookup
                    // to prevent duplicates regardless
                    let gid = self.generate_gid_for_discovery(pid_u32, &exepath);

                    Logging::debug(&format!(
                        "[BEHAVIOR SCAN] Discovered new process during scan: {} (PID: {}, GID: {}, Path: {})",
                        appname,
                        pid_u32,
                        gid,
                        exepath.display()
                    ));

                    self.behavior_engine.register_process(
                        gid,
                        pid_u32,
                        exepath.clone(),
                        appname.clone(),
                    );
                    let mut precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                    precord.pids.insert(pid_u32);
                    self.process_records.insert_precord(gid, precord);
                    self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);
                    self.queue_process_start_scan_if_needed(
                        gid,
                        pid_u32,
                        &appname,
                        &exepath,
                        "New process executable scan",
                    );

                    discovered_new += 1;
                }

                if discovered_new > 0 {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Discovered {} new processes",
                        discovered_new
                    ));
                }

                // --- THIRD: Sync behavior engine state to process_records ---
                
                self.sync_firewall_process_contexts();
                let mut process_sync_scans = Vec::new();
                for (gid, state) in self.behavior_engine.process_states.iter() {
                    if self.process_records.get_precord_by_gid(*gid).is_none() {
                        let mut precord = ProcessRecord::new(
                            *gid,
                            state.app_name.clone(),
                            state.exe_path.clone(),
                        );
                        precord.pids.insert(state.pid);
                        self.process_records.insert_precord(*gid, precord);
                        process_sync_scans.push((
                            *gid,
                            state.pid,
                            state.app_name.clone(),
                            state.exe_path.clone(),
                        ));
                        Logging::debug(&format!(
                            "[PROCESS SYNC] Registered GID: {} from behavior_engine",
                            gid
                        ));
                    }
                }
                for (gid, pid, appname, exepath) in process_sync_scans {
                    self.queue_process_start_scan_if_needed(
                        gid,
                        pid,
                        &appname,
                        &exepath,
                        "Behavior-engine process executable scan",
                    );
                }

                // Drain IRP records queued by the OpenEDR telemetry pipe thread and
                // route them through process_event so OpenEDR-only (non-edrdrv)
                // events get the same named-condition + rule evaluation as driver
                // events (e.g. the non-whitelisted-extension ransomware rule).
                // Runs after process discovery/sync so freshly seen processes are
                // already tracked. No additional locking needed beyond the
                // Arc<Mutex<_>> inside drain_pending_irp_records itself.
                let drained_records = self.behavior_engine.drain_pending_irp_records();
                for (gid, iomsg) in drained_records {
                    // Ensure a precord exists so process_event can resolve extension
                    // history and file-id state for this GID.
                    if self.process_records.get_precord_by_gid(gid).is_none() {
                        let (app_name, exe_path) = self
                            .behavior_engine
                            .process_states
                            .get(&gid)
                            .map(|s| (s.app_name.clone(), s.exe_path.clone()))
                            .unwrap_or_default();
                        let mut precord = ProcessRecord::new(gid, app_name, exe_path);
                        precord.pids.insert(iomsg.pid);
                        self.process_records.insert_precord(gid, precord);
                    }
                    if let Some(precord) = self.process_records.get_precord_mut_by_gid(gid) {
                        self.behavior_engine
                            .process_event(precord, &iomsg, config, &*threat_handler);
                    }
                }

                // Log Current Status
                let total_tracked = self.behavior_engine.process_states.len();
                if total_tracked > 0 {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Evaluating {} tracked processes",
                        total_tracked
                    ));
                } else {
                    Logging::warning("[BEHAVIOR SCAN] No processes are being tracked!");
                }

                // --- FOURTH: Run the scan on all tracked processes ---
                let detections = self
                    .behavior_engine
                    .scan_all_processes(config, &*threat_handler);

                if !detections.is_empty() {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Found {} detections",
                        detections.len()
                    ));
                }

                // --- FIFTH: Apply detections to process records ---
                let mut terminated_gids = HashSet::new();
                for det in detections {
                    if terminated_gids.contains(&det.gid) {
                        continue;
                    }

                    let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                    let threat_info =
                        Self::build_behavior_threat_info(&det, "periodic behavior scan");
                    let matching_record = self
                        .process_records
                        .process_records
                        .iter_mut()
                        .find(|(gid, _)| **gid == det.gid);

                    if let Some((_, record)) = matching_record {
                        Self::apply_behavior_detection_state(record, &det);
                        let rule_name = det
                            .triggered_rule_name
                            .as_deref()
                            .unwrap_or("Behavioral Detection");
                        Logging::warning(&format!(
                            "[DETECTION] Process {} (GID: {}) marked malicious by rule '{}'",
                            record.appname, det.gid, rule_name
                        ));
                        let report_context = ActionReportContext::default();
                        ActionsOnKill::with_handler(threat_handler.clone_box())
                            .run_actions_with_info_and_context(
                                config,
                                record,
                                &dummy_pred_mtrx,
                                &threat_info,
                                &report_context,
                            );

                        if det.termination_requested
                            && restart_cleanup_reason(record, &threat_info).is_none()
                        {
                            terminated_gids.insert(det.gid);
                        }
                    } else if let Some(state) = self.behavior_engine.process_states.get(&det.gid) {
                        // Handle detection for process not yet in records
                        let mut precord = ProcessRecord::new(
                            det.gid,
                            state.app_name.clone(),
                            state.exe_path.clone(),
                        );
                        Self::apply_behavior_detection_state(&mut precord, &det);
                        let report_context = ActionReportContext::default();
                        ActionsOnKill::with_handler(threat_handler.clone_box())
                            .run_actions_with_info_and_context(
                                config,
                                &mut precord,
                                &dummy_pred_mtrx,
                                &threat_info,
                                &report_context,
                            );

                        if det.termination_requested
                            && restart_cleanup_reason(&precord, &threat_info).is_none()
                        {
                            terminated_gids.insert(det.gid);
                        } else {
                            self.process_records.insert_precord(det.gid, precord);
                        }
                    }
                }

                for gid in terminated_gids.clone() {
                    self.cleanup_process(gid, "Killed (behavior detection)");
                }

                for gid in terminated_gids {
                    if self.process_records.process_records.contains(&gid) {
                        self.cleanup_process(gid, "Killed (behavior detection)");
                    }
                }

            }
        }

        pub fn new_replay(
            config: &'a Config,
            
            app_settings: AppSettings,
        ) -> Worker<'a> {
            Worker {
                config,
                process_records: ProcessRecords::new(),
                process_record_handler: Some(Box::new(ProcessRecordHandlerReplay::new(config))),
                exepath_handler: Box::<ExePathReplay>::default(),
                iomsg_postprocessors: vec![],
                
                behavior_engine: Self::build_behavior_engine(config),
                
                app_settings,
                
                dynamic_hooks_registered: false,
                
                dynamic_hook_event_map: Self::default_dynamic_hook_event_map(),
                
                dynamic_registered_apis: Self::default_registered_dynamic_apis(),
                
                next_dynamic_hook_event_id: Self::DYNAMIC_HOOK_EVENT_ID_START,
                
                dynamic_hook_registration_blocked: false,
                
                dynamic_hook_last_refresh: std::collections::HashMap::new(),
                
                dynamic_hook_target_generation: 0,
                
                dynamic_hook_applied_generation: std::collections::HashMap::new(),
                
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
                let now = std::time::Instant::now();
                let report_interval = std::time::Duration::from_secs(3600); // 1 hour
                
                use std::sync::atomic::Ordering; // Import Ordering
                
                let force_report = self
                    .behavior_engine
                    .generate_report_flag
                    .swap(false, Ordering::SeqCst);
                if force_report
                    || self
                        .last_report_time
                        .map_or(true, |t| now.duration_since(t) > report_interval)
                {
                    if force_report {
                        Logging::info("[REPORT] Triggering on-demand report requested via pipe");
                    }
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
                    "[ROOTKIT] Routing unattributed kernel finding through global handler only: opcode={:?} desc={}",
                    irp_op,
                    iomsg.kernel_event_info.object_name.trim_matches('\0')
                ));
                self.behavior_engine.handle_rootkit_event(iomsg);
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

            if is_process_create && self.threat_handler.is_some() {
                self.sync_firewall_process_contexts();
            }

            if let Some(precord) = self.process_records.get_precord_mut_by_gid(tracking_key) {
                // For new processes (after startup flood), run static scan
                // immediately so pre-loaded malware state is caught on creation.
                // Skipped during startup_complete=false to avoid the O(n²)
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
                        // Propagate to behavior engine state so rule matching
                        // and allowlists are also correct immediately.
                        
                        if let Some(state) =
                            self.behavior_engine.process_states.get_mut(&tracking_key)
                            && (state.app_name.is_empty()
                                || state.app_name.starts_with("PROC_")
                                || state.app_name == "UNKNOWN")
                        {
                            if !resolved_name.is_empty() {
                                state.app_name = resolved_name;
                            }
                            state.exe_path = resolved_path;
                        }
                    }

                    // Run fast static detections for MZ executables and JavaScript files
                    let mut fast_det = None;

                    if is_process_create {
                        let exe_path_str = precord.exepath.to_string_lossy().into_owned();
                        fast_det = crate::ml::fast_detect::fast_detect_file(&exe_path_str, iomsg);
                    }

                    if fast_det.is_none() && !iomsg.filepathstr.is_empty() {
                        fast_det = crate::ml::fast_detect::fast_detect_file(&iomsg.filepathstr, iomsg);
                    }

                    if let Some(det) = fast_det {
                        precord.is_malicious = true;
                        precord.termination_requested = true;
                        precord.quarantine_requested = true;
                        precord.triggered_rule_name = Some(det.detection_name.clone());
                        precord.triggered_rule_details = Some(det.reason.clone());
                        precord.fast_detection_features = Some(det.features.clone());

                        Logging::warning(&format!(
                            "[FastDetection] Process {} (PID: {}) triggered static detection '{}': {}",
                            precord.appname, iomsg.pid, det.detection_name, det.reason
                        ));

                        if let Some(ref threat_handler) = self.threat_handler {
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
                            let report_context = crate::actions_on_kill::ActionReportContext::default();
                            crate::actions_on_kill::ActionsOnKill::with_handler(threat_handler.clone_box())
                                .run_actions_with_info_and_context(
                                    config,
                                    precord,
                                    &dummy_pred_mtrx,
                                    &threat_info,
                                    &report_context,
                                );
                        }
                    }

                    // Process behavioral event
                    
                    if let Some(ref th) = self.threat_handler {
                        self.behavior_engine
                            .process_event(precord, iomsg, config, &**th);
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
                let th_opt = self.threat_handler.as_ref().map(|h| h.clone_box());
                if let Some(threat_handler) = th_opt {
                    Logging::debug(&format!(
                        "[PROCESS CREATE] Running immediate behavior scan for PID {} GID {}",
                        iomsg.pid, tracking_key
                    ));
                    self.scan_processes(config, threat_handler);
                }
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

                    // Register in behavior engine
                    
                    {
                        self.behavior_engine.register_process(
                            gid,
                            pid,
                            exepath.clone(),
                            appname.clone(),
                        );
                    }

                    // Store process record (moves precord)
                    self.process_records.insert_precord(gid, precord);
                    if irp_op == IrpMajorOp::IrpProcessCreate {
                        self.queue_process_start_scan_if_needed(
                            gid,
                            pid,
                            &appname,
                            &exepath,
                            "Kernel process-create executable scan",
                        );
                    }
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

                            // Update behavior engine
                            
                            {
                                if let Some(state) =
                                    self.behavior_engine.process_states.get_mut(&gid)
                                {
                                    state.exe_path = path.clone();
                                    state.app_name = name.clone();
                                }
                            }
                        }

                        if IrpMajorOp::from_sysmonevent(iomsg.irp_op)
                            == IrpMajorOp::IrpProcessCreate
                        {
                            self.queue_process_start_scan_if_needed(
                                gid,
                                pid,
                                &name,
                                &path,
                                "Kernel process-create executable scan",
                            );
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

        
        fn looks_like_hook_offset(raw: &str) -> bool {
            let mut value = raw.trim();
            if value.is_empty() {
                return false;
            }

            if let Some(stripped) = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
            {
                value = stripped;
            }
            if let Some(stripped) = value.strip_suffix('h').or_else(|| value.strip_suffix('H')) {
                value = stripped;
            }

            !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
        }

        
        fn split_module_rva_target(api_spec: &str) -> Option<(&str, &str)> {
            let trimmed = api_spec.trim();
            let (module_raw, offset_raw) = trimmed.rsplit_once('+')?;
            let module = module_raw.trim();
            let offset = offset_raw.trim();

            if module.is_empty() || offset.is_empty() || module.contains('!') {
                return None;
            }

            if !Self::looks_like_hook_offset(offset) {
                return None;
            }

            Some((module, offset))
        }

        
        fn push_unique_hook_target(
            seen_lower: &mut HashSet<String>,
            targets: &mut Vec<String>,
            api_spec: impl Into<String>,
        ) {
            let api_spec = api_spec.into();
            let trimmed = api_spec.trim();
            if trimmed.is_empty() {
                return;
            }

            let key = trimmed.to_ascii_lowercase();
            if seen_lower.insert(key) {
                targets.push(trimmed.to_string());
            }
        }

        
        fn known_hook_function_variants(function_pattern: &str) -> Vec<&'static str> {
            let lowered = function_pattern.trim().to_ascii_lowercase();
            let mut variants = Vec::new();
            let mut push = |name: &'static str| {
                if !variants.contains(&name) {
                    variants.push(name);
                }
            };

            if lowered.contains("setwineventhook") {
                push("SetWinEventHook");
                push("SetWinEventHookA");
                push("SetWinEventHookW");
                push("NtUserSetWinEventHook");
            }
            if lowered.contains("setwindowshookex") {
                push("SetWindowsHookExA");
                push("SetWindowsHookExW");
                push("NtUserSetWindowsHookEx");
            }
            if lowered.contains("setwindowshook") {
                push("SetWindowsHookA");
                push("SetWindowsHookW");
            }
            if lowered.contains("dnsqueryex") {
                push("DnsQueryEx");
            }
            if lowered.contains("dnsquery_a") {
                push("DnsQuery_A");
            }
            if lowered.contains("dnsquery_w") {
                push("DnsQuery_W");
            }
            if lowered.contains("dnsquery") {
                push("DnsQuery_A");
                push("DnsQuery_W");
                push("DnsQuery_UTF8");
                push("DnsQueryEx");
            }
            if lowered.contains("querydnsconfig") {
                push("QueryDnsConfig");
            }
            if lowered.contains("getaddrinfo") {
                push("getaddrinfo");
                push("GetAddrInfoW");
                push("GetAddrInfoExW");
            }
            if lowered.contains("createserviceex") {
                push("CreateServiceExA");
                push("CreateServiceExW");
            }
            if lowered.contains("createservice") {
                push("CreateServiceA");
                push("CreateServiceW");
                push("CreateServiceExA");
                push("CreateServiceExW");
            }
            if lowered.contains("changeserviceconfig2") {
                push("ChangeServiceConfig2A");
                push("ChangeServiceConfig2W");
            }
            if lowered.contains("changeserviceconfig") {
                push("ChangeServiceConfigA");
                push("ChangeServiceConfigW");
                push("ChangeServiceConfig2A");
                push("ChangeServiceConfig2W");
            }
            if lowered.contains("openscmanager") {
                push("OpenSCManagerA");
                push("OpenSCManagerW");
            }
            if lowered.contains("openservice") {
                push("OpenServiceA");
                push("OpenServiceW");
            }
            if lowered.contains("startservice") {
                push("StartServiceA");
                push("StartServiceW");
            }
            if lowered.contains("regcreatekeyex") {
                push("RegCreateKeyExA");
                push("RegCreateKeyExW");
            }
            if lowered.contains("regcreatekey") {
                push("RegCreateKeyA");
                push("RegCreateKeyW");
                push("RegCreateKeyExA");
                push("RegCreateKeyExW");
            }
            if lowered.contains("regsetkeyvalue") {
                push("RegSetKeyValueA");
                push("RegSetKeyValueW");
            }
            if lowered.contains("regsetvalueex") {
                push("RegSetValueExA");
                push("RegSetValueExW");
            }
            if lowered.contains("regsetvalue") {
                push("RegSetValueA");
                push("RegSetValueW");
                push("RegSetValueExA");
                push("RegSetValueExW");
                push("RegSetKeyValueA");
                push("RegSetKeyValueW");
            }
            if lowered.contains("ntloaddriver") {
                push("NtLoadDriver");
            }
            if lowered.contains("zwloaddriver") {
                push("ZwLoadDriver");
            }
            if lowered.contains("ntcreatekey") {
                push("NtCreateKey");
            }
            if lowered.contains("zwcreatekey") {
                push("ZwCreateKey");
            }
            if lowered.contains("ntsetvaluekey") {
                push("NtSetValueKey");
            }
            if lowered.contains("zwsetvaluekey") {
                push("ZwSetValueKey");
            }
            if lowered.contains("ntcreatefile") {
                push("NtCreateFile");
            }
            if lowered.contains("zwcreatefile") {
                push("ZwCreateFile");
            }
            if lowered.contains("ntwritefile") {
                push("NtWriteFile");
            }
            if lowered.contains("zwwritefile") {
                push("ZwWriteFile");
            }
            if lowered.contains("ntsetinformationfile") {
                push("NtSetInformationFile");
            }
            if lowered.contains("zwsetinformationfile") {
                push("ZwSetInformationFile");
            }
            if lowered.contains("ntfscontrolfile") {
                push("NtFsControlFile");
            }
            if lowered.contains("zwfscontrolfile") {
                push("ZwFsControlFile");
            }
            if lowered.contains("createfile") {
                push("CreateFileA");
                push("CreateFileW");
            }
            if lowered.contains("readfile") {
                push("ReadFile");
            }
            if lowered.contains("writefile") {
                push("WriteFile");
            }
            if lowered.contains("copyfileex") {
                push("CopyFileExA");
                push("CopyFileExW");
            }
            if lowered.contains("copyfile") {
                push("CopyFileA");
                push("CopyFileW");
                push("CopyFileExA");
                push("CopyFileExW");
            }
            if lowered.contains("movefileex") {
                push("MoveFileExA");
                push("MoveFileExW");
            }
            if lowered.contains("movefile") {
                push("MoveFileA");
                push("MoveFileW");
                push("MoveFileExA");
                push("MoveFileExW");
            }
            if lowered.contains("replacefile") {
                push("ReplaceFileA");
                push("ReplaceFileW");
            }
            if lowered.contains("deviceiocontrol") {
                push("DeviceIoControl");
            }
            if lowered.contains("cocreateinstance") {
                push("CoCreateInstance");
                push("CoCreateInstanceEx");
            }
            if lowered.contains("cogetobject") {
                push("CoGetObject");
            }
            if lowered.contains("cogetclassobject") {
                push("CoGetClassObject");
            }
            if lowered.contains("coinitializesecurity") {
                push("CoInitializeSecurity");
            }
            if lowered.contains("cosetproxyblanket") {
                push("CoSetProxyBlanket");
            }
            if lowered.contains("impersonateloggedonuser") {
                push("ImpersonateLoggedOnUser");
            }
            if lowered.contains("setthreadtoken") {
                push("SetThreadToken");
            }
            if lowered.contains("duplicatetokenex") {
                push("DuplicateTokenEx");
            }
            if lowered.contains("openthreadtoken") {
                push("OpenThreadToken");
            }
            if lowered.contains("openprocesstoken") {
                push("OpenProcessToken");
            }
            if lowered.contains("adjusttokenprivileges") {
                push("AdjustTokenPrivileges");
            }
            if lowered.contains("impersonatenamedpipeclient") {
                push("ImpersonateNamedPipeClient");
            }
            if lowered.contains("createprocesswithtokenw") {
                push("CreateProcessWithTokenW");
            }
            if lowered.contains("createprocessasuserw") {
                push("CreateProcessAsUserW");
            }
            if lowered.contains("ntimpersonatethread") {
                push("NtImpersonateThread");
            }
            if lowered.contains("ntsetinformationthread") {
                push("NtSetInformationThread");
            }
            if lowered.contains("ntwritevirtualmemory") {
                push("NtWriteVirtualMemory");
            }
            if lowered.contains("zwwritevirtualmemory") {
                push("ZwWriteVirtualMemory");
            }
            if lowered.contains("writeprocessmemory") {
                push("WriteProcessMemory");
            }
            if lowered.contains("ntallocatevirtualmemory") {
                push("NtAllocateVirtualMemory");
            }
            if lowered.contains("zwallocatevirtualmemory") {
                push("ZwAllocateVirtualMemory");
            }
            if lowered.contains("virtualallocex") {
                push("VirtualAllocEx");
            }
            if lowered.contains("virtualalloc") {
                push("VirtualAlloc");
                push("VirtualAllocEx");
            }
            if lowered.contains("ntprotectvirtualmemory") {
                push("NtProtectVirtualMemory");
            }
            if lowered.contains("zwprotectvirtualmemory") {
                push("ZwProtectVirtualMemory");
            }
            if lowered.contains("virtualprotectex") {
                push("VirtualProtectEx");
            }
            if lowered.contains("virtualprotect") {
                push("VirtualProtect");
                push("VirtualProtectEx");
            }
            if lowered.contains("ntcreatethreadex") {
                push("NtCreateThreadEx");
            }
            if lowered.contains("zwcreatethreadex") {
                push("ZwCreateThreadEx");
            }
            if lowered.contains("createremotethread") {
                push("CreateRemoteThread");
                push("CreateRemoteThreadEx");
            }
            if lowered.contains("createthread") {
                push("CreateThread");
                push("CreateRemoteThread");
                push("CreateRemoteThreadEx");
                push("NtCreateThreadEx");
            }
            if lowered.contains("ntqueueapcthread") {
                push("NtQueueApcThread");
            }
            if lowered.contains("zwqueueapcthread") {
                push("ZwQueueApcThread");
            }
            if lowered.contains("queueuserapc") {
                push("QueueUserAPC");
            }
            if lowered.contains("ntsetcontextthread") {
                push("NtSetContextThread");
            }
            if lowered.contains("zwsetcontextthread") {
                push("ZwSetContextThread");
            }
            if lowered.contains("setthreadcontext") {
                push("SetThreadContext");
            }
            if lowered.contains("ntcreatesection") {
                push("NtCreateSection");
            }
            if lowered.contains("zwcreatesection") {
                push("ZwCreateSection");
            }
            if lowered.contains("ntmapviewofsection") {
                push("NtMapViewOfSection");
            }
            if lowered.contains("zwmapviewofsection") {
                push("ZwMapViewOfSection");
            }
            if lowered.contains("mapviewoffile") {
                push("MapViewOfFile");
                push("MapViewOfFileEx");
            }
            if lowered.contains("ntopenprocess") {
                push("NtOpenProcess");
            }
            if lowered.contains("zwopenprocess") {
                push("ZwOpenProcess");
            }
            if lowered == "openprocess" || lowered.ends_with("!openprocess") {
                push("OpenProcess");
            }

            variants
        }

        
        fn expand_dynamic_hook_api_target(api_spec: &str) -> Vec<String> {
            let trimmed = api_spec.trim();
            if trimmed.is_empty() {
                return Vec::new();
            }

            let mut expanded = Vec::new();
            let mut seen_lower = HashSet::new();

            if let Some((module_raw, offset_raw)) = Self::split_module_rva_target(trimmed) {
                let module = Self::normalize_hook_module_name(module_raw);
                Self::push_unique_hook_target(
                    &mut seen_lower,
                    &mut expanded,
                    format!("{module}!rva:{}", offset_raw.trim()),
                );
                return expanded;
            }

            if let Some((module_raw, function_raw)) = trimmed.split_once('!') {
                let module = Self::normalize_hook_module_name(module_raw);
                let function_variants = Self::known_hook_function_variants(function_raw);
                if function_variants.is_empty() {
                    Self::push_unique_hook_target(
                        &mut seen_lower,
                        &mut expanded,
                        format!("{module}!{}", function_raw.trim()),
                    );
                } else {
                    for function in function_variants {
                        Self::push_unique_hook_target(
                            &mut seen_lower,
                            &mut expanded,
                            format!("{module}!{function}"),
                        );
                    }
                }
                return expanded;
            }

            let lowered = trimmed.to_ascii_lowercase();
            let normalized_name = trimmed.trim_matches(|c| c == '*' || c == '?').trim();
            let mut add_many = |module: &str, functions: &[&str]| {
                let normalized_module = Self::normalize_hook_module_name(module);
                for function in functions {
                    Self::push_unique_hook_target(
                        &mut seen_lower,
                        &mut expanded,
                        format!("{normalized_module}!{function}"),
                    );
                }
            };

            match lowered.as_str() {
                value if value.contains("setwineventhook") => {
                    add_many(
                        "user32.dll",
                        &["SetWinEventHook", "SetWinEventHookA", "SetWinEventHookW"],
                    );
                    add_many("win32u.dll", &["NtUserSetWinEventHook"]);
                }
                value if value.contains("setwindowshookex") => {
                    add_many("user32.dll", &["SetWindowsHookExA", "SetWindowsHookExW"]);
                    add_many("win32u.dll", &["NtUserSetWindowsHookEx"]);
                }
                value if value.contains("setwindowshook") => {
                    add_many(
                        "user32.dll",
                        &[
                            "SetWindowsHookA",
                            "SetWindowsHookW",
                            "SetWindowsHookExA",
                            "SetWindowsHookExW",
                        ],
                    );
                }
                value if value.contains("dnsquery") => {
                    add_many(
                        "dnsapi.dll",
                        &["DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8", "DnsQueryEx"],
                    );
                }
                value if value.contains("querydnsconfig") => {
                    add_many("dnsapi.dll", &["QueryDnsConfig"]);
                }
                value if value.contains("getaddrinfo") => {
                    add_many(
                        "ws2_32.dll",
                        &["getaddrinfo", "GetAddrInfoW", "GetAddrInfoExW"],
                    );
                }
                value
                    if value.contains("createservice")
                        || value.contains("changeserviceconfig")
                        || value.contains("openscmanager")
                        || value.contains("openservice")
                        || value.contains("startservice")
                        || value.contains("regcreatekey")
                        || value.contains("regsetvalue")
                        || value.contains("regsetkeyvalue")
                        || value.contains("impersonateloggedonuser")
                        || value.contains("setthreadtoken")
                        || value.contains("duplicatetokenex")
                        || value.contains("openthreadtoken")
                        || value.contains("openprocesstoken")
                        || value.contains("adjusttokenprivileges")
                        || value.contains("impersonatenamedpipeclient")
                        || value.contains("createprocesswithtokenw")
                        || value.contains("createprocessasuserw") =>
                {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("advapi32.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("advapi32.dll", &variants);
                    }
                }
                value if value.contains("nt") || value.contains("zw") => {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("ntdll.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("ntdll.dll", &variants);
                    }
                }
                value
                    if value.contains("cocreateinstance")
                        || value.contains("cogetobject")
                        || value.contains("cogetclassobject")
                        || value.contains("coinitializesecurity")
                        || value.contains("cosetproxyblanket") =>
                {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("ole32.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("ole32.dll", &variants);
                    }
                }
                value
                    if value.contains("createfile")
                        || value.contains("readfile")
                        || value.contains("writefile")
                        || value.contains("copyfile")
                        || value.contains("movefile")
                        || value.contains("replacefile")
                        || value.contains("deviceiocontrol") =>
                {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("kernel32.dll", &[normalized_name]);
                            add_many("kernelbase.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("kernel32.dll", &variants);
                        add_many("kernelbase.dll", &variants);
                    }
                }
                _ => {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if !variants.is_empty() {
                        for function in variants {
                            let function_lower = function.to_ascii_lowercase();
                            if function_lower.starts_with("ntuser") {
                                add_many("win32u.dll", &[function]);
                            } else if function_lower.starts_with("nt")
                                || function_lower.starts_with("zw")
                            {
                                add_many("ntdll.dll", &[function]);
                            } else if function_lower.starts_with("co") {
                                add_many("ole32.dll", &[function]);
                            } else if function_lower.contains("dns") {
                                add_many("dnsapi.dll", &[function]);
                            } else if function_lower.contains("addrinfo") {
                                add_many("ws2_32.dll", &[function]);
                            } else if function_lower.contains("service")
                                || function_lower.starts_with("reg")
                                || function_lower.contains("token")
                                || function_lower.contains("impersonate")
                            {
                                add_many("advapi32.dll", &[function]);
                            } else if function_lower.contains("file")
                                || function_lower.contains("deviceiocontrol")
                                || function_lower.contains("processmemory")
                                || function_lower.contains("virtualalloc")
                                || function_lower.contains("virtualprotect")
                                || function_lower.contains("createremotethread")
                                || function_lower == "createthread"
                                || function_lower.contains("queueuserapc")
                                || function_lower.contains("setthreadcontext")
                                || function_lower.contains("mapviewoffile")
                                || function_lower == "openprocess"
                            {
                                add_many("kernel32.dll", &[function]);
                                add_many("kernelbase.dll", &[function]);
                            } else if function_lower.contains("hook") {
                                add_many("user32.dll", &[function]);
                            }
                        }
                    }
                }
            }

            if expanded.is_empty() {
                Self::push_unique_hook_target(&mut seen_lower, &mut expanded, trimmed.to_string());
            }

            expanded
        }

        
        /// Check if MONITOR_ALL_APIS is enabled in HKLM\SOFTWARE\Owlyshield registry.
        /// Defaults to false (0) — only APIs in active behavioral rules are monitored.
        fn is_monitor_all_apis_enabled() -> bool {
            #[cfg(target_os = "windows")]
            {
                use registry::{Hive, Security};
                if let Ok(regkey) = Hive::LocalMachine.open(r"SOFTWARE\Owlyshield", Security::Read) {
                    if let Ok(val) = regkey.value("MONITOR_ALL_APIS") {
                        let val_str = val.to_string();
                        let clean = val_str.trim_matches('\0').trim().to_ascii_lowercase();
                        return clean == "1" || clean == "true" || clean == "yes" || clean == "enable" || clean == "enabled";
                    }
                }
            }
            false
        }

        /// Collect APIs to monitor for a process:
        /// ONLY APIs required by active behavioral rules are monitored.
        fn collect_dynamic_hook_api_targets(&mut self, _pid: u32) -> Vec<String> {
            let mut seen_lower = HashSet::new();
            let mut merged = Vec::new();

            // Collect APIs defined in loaded behavioral rules
            let mut rule_apis: Vec<String> = self
                .behavior_engine
                .get_all_monitored_apis()
                .into_iter()
                .collect();
            rule_apis.sort_unstable();
            for api in rule_apis {
                let trimmed = api.trim();
                if trimmed.is_empty() {
                    continue;
                }
                for expanded_api in Self::expand_dynamic_hook_api_target(trimmed) {
                    Self::push_unique_hook_target(&mut seen_lower, &mut merged, expanded_api);
                }
            }

            merged
        }

        /// Register high-interest API hooks for a specific PID
        /// Keeps dynamic hooks rule-driven. Import-wide expansion is intentionally
        /// disabled because broad hook sets are too unstable.
        
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
                Logging::warning(&format!(
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

            if registered_count > 0 {
                self.dynamic_hook_target_generation =
                    self.dynamic_hook_target_generation.saturating_add(1);
            }

            let target_generation = self.dynamic_hook_target_generation;
            let applied_generation = self
                .dynamic_hook_applied_generation
                .get(&pid)
                .copied()
                .unwrap_or(0);
            let has_any_targets = registered_count > 0 || already_registered_count > 0;
            let needs_apply = has_any_targets && applied_generation < target_generation;
            let mut apply_attempted = false;
            let mut apply_succeeded = false;

            if needs_apply {
                apply_attempted = true;
                if let Err(e) = driver.hook_process(pid) {
                    let hr = e.code().0 as u32;
                    let low_word = hr & 0xFFFF;
                    let is_noaccess_like =
                        hr == 0x800703E6 || hr == 0xC0000005 || low_word == 0x03E6;
                    if hr == 0x80070677 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: process mitigation blocks dynamic code (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x80070005 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: access denied (likely protected/critical process) (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if is_noaccess_like {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: NOACCESS while patching hooks (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x80070016 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: driver command not recognized for this target (hr=0x{:08X})",
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
                    self.dynamic_hook_applied_generation
                        .insert(pid, target_generation);
                    apply_succeeded = true;
                }
            }

            self.dynamic_hooks_registered = true;
            let message = format!(
                "[DYNAMIC HOOK] PID {} => registered={} already={} failed={} wildcard={} apply_attempted={} apply_succeeded={} generation={}/{}",
                pid,
                registered_count,
                already_registered_count,
                failed_count,
                wildcard_count,
                apply_attempted,
                apply_succeeded,
                applied_generation,
                target_generation
            );
            if registered_count > 0 || failed_count > 0 || apply_attempted {
                Logging::info(&message);
            } else {
                Logging::debug(&message);
            }
        }
    }
}
