//! Timeline Builder
//!
//! Builds attack timelines from process behavior data.

use super::technique_mapping::TechniqueMapper;
use super::timeline::{AttackTimeline, EventSeverity, TimelineEvent};
use crate::process::ProcessRecord;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

#[cfg(feature = "realtime_learning")]
use crate::realtime_learning::api_tracker::{ApiTracker, OperationType};

#[cfg(not(feature = "realtime_learning"))]
#[derive(Debug)]
pub struct ApiTracker;

const MAX_DETAIL_ITEMS: usize = 40;
#[cfg(feature = "realtime_learning")]
const MAX_SEQUENCE_EVENTS: usize = 160;
#[cfg(feature = "realtime_learning")]
const MAX_PACKET_EVENTS: usize = 120;
#[cfg(feature = "realtime_learning")]
const MAX_RAW_EVENTS: usize = 80;

pub struct TimelineBuilder {
    mapper: TechniqueMapper,
}

impl TimelineBuilder {
    pub fn new() -> Self {
        TimelineBuilder {
            mapper: TechniqueMapper::new(),
        }
    }

    /// Build a complete attack timeline from process record and API tracker.
    pub fn build_timeline(
        &self,
        proc: &ProcessRecord,
        api_tracker: Option<&ApiTracker>,
    ) -> AttackTimeline {
        let process_path = if proc.exepath.as_os_str().is_empty() {
            proc.appname.clone()
        } else {
            proc.exepath.to_string_lossy().into_owned()
        };
        let mut timeline = AttackTimeline::new(proc.gid, proc.appname.clone(), process_path);

        timeline.start_time = proc.time_started;

        self.add_process_context_events(&mut timeline, proc);
        self.add_file_events(&mut timeline, proc);
        self.add_registry_events(&mut timeline, proc);
        self.add_network_events(&mut timeline, proc);

        #[cfg(feature = "realtime_learning")]
        if let Some(tracker) = api_tracker {
            self.add_api_events(&mut timeline, tracker);
            self.add_kernel_events(&mut timeline, tracker);
            self.add_operation_sequence_events(&mut timeline, tracker);
            self.add_network_packet_events(&mut timeline, tracker);

            #[cfg(all(target_os = "windows", feature = "sanctum"))]
            self.add_sanctum_events(&mut timeline, tracker);
        }

        #[cfg(not(feature = "realtime_learning"))]
        let _ = api_tracker;

        timeline.finalize();
        timeline
    }

    fn add_process_context_events(&self, timeline: &mut AttackTimeline, proc: &ProcessRecord) {
        let mut event = TimelineEvent::new(
            proc.time_started,
            "Process Observed".to_string(),
            format!("Tracking started for {} (GID {})", proc.appname, proc.gid),
            EventSeverity::Info,
        )
        .with_detail("Executable".to_string(), proc.exepath.display().to_string())
        .with_detail("Command Line".to_string(), empty_label(&proc.command_line))
        .with_detail(
            "PIDs".to_string(),
            join_u32_set(&proc.pids, MAX_DETAIL_ITEMS),
        )
        .with_process_info(proc.appname.clone(), proc.gid);

        if proc.is_signed || proc.has_valid_signature {
            event = event
                .with_detail("Signed".to_string(), proc.is_signed.to_string())
                .with_detail(
                    "Valid Signature".to_string(),
                    proc.has_valid_signature.to_string(),
                );
        }

        timeline.add_event(event);

        // Always show detection events if they exist, regardless of malicious status
        // This allows benign processes to appear in MITRE ATT&CK timeline
        if proc.triggered_rule_name.is_some() || proc.triggered_rule_details.is_some() {
            let mut response = Vec::new();
            if proc.termination_requested {
                response.push("terminate");
            }
            if proc.quarantine_requested {
                response.push("quarantine");
            }
            if proc.deny_access_requested {
                response.push("deny_access");
            }
            if proc.suspend_requested {
                response.push("suspend");
            }
            if proc.kill_and_remove_requested {
                response.push("kill_and_remove");
            }
            if proc.notify_user_requested {
                response.push("notify_user");
            }
            if proc.revert_requested {
                response.push("revert");
            }
            if proc.restart_cleanup_requested {
                response.push("restart_cleanup");
            }

            let severity = if proc.termination_requested
                || proc.quarantine_requested
                || proc.kill_and_remove_requested
            {
                EventSeverity::Critical
            } else if proc.deny_access_requested || proc.suspend_requested {
                EventSeverity::High
            } else {
                EventSeverity::Medium
            };

            let detection_name = proc
                .triggered_rule_name
                .as_deref()
                .unwrap_or("Behavioral Detection");
            let details = proc
                .triggered_rule_details
                .as_deref()
                .unwrap_or("No rule detail was attached");

            let event = TimelineEvent::new(
                proc.time_killed.unwrap_or_else(SystemTime::now),
                "Detection".to_string(),
                format!("{} flagged this process", detection_name),
                severity,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques(details))
            .with_detail("Detection".to_string(), detection_name.to_string())
            .with_detail("Details".to_string(), details.to_string())
            .with_detail("Response".to_string(), response.join(", "))
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }
    }

    fn add_file_events(&self, timeline: &mut AttackTimeline, proc: &ProcessRecord) {
        if proc.entropy_written > 7.5 && !proc.files_written.is_empty() {
            let avg_entropy = proc.entropy_written / proc.files_written.len() as f64;
            let event = TimelineEvent::new(
                proc.time_started,
                "File Encryption".to_string(),
                format!(
                    "Multiple high-entropy file writes observed (avg entropy: {:.2})",
                    avg_entropy
                ),
                EventSeverity::Critical,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("encrypt ransomware"))
            .with_detail(
                "Files Written".to_string(),
                proc.files_written.len().to_string(),
            )
            .with_detail("Avg Entropy".to_string(), format!("{:.2}", avg_entropy))
            .with_detail(
                "Sample Updated Paths".to_string(),
                join_strings(&proc.fpaths_updated, MAX_DETAIL_ITEMS),
            )
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }

        if proc.fpaths_created.len() > 50 || proc.fpaths_updated.len() > 100 {
            let severity = if proc.fpaths_created.len() > 100 || proc.fpaths_updated.len() > 250 {
                EventSeverity::High
            } else {
                EventSeverity::Medium
            };

            let event = TimelineEvent::new(
                proc.time_started,
                "Mass File Operations".to_string(),
                format!(
                    "Created: {}, modified: {}, deleted: {}",
                    proc.fpaths_created.len(),
                    proc.fpaths_updated.len(),
                    proc.files_deleted.len()
                ),
                severity,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("ransomware"))
            .with_detail(
                "Files Created".to_string(),
                proc.fpaths_created.len().to_string(),
            )
            .with_detail(
                "Files Modified".to_string(),
                proc.fpaths_updated.len().to_string(),
            )
            .with_detail(
                "Files Deleted".to_string(),
                proc.files_deleted.len().to_string(),
            )
            .with_detail(
                "Created Samples".to_string(),
                join_strings(&proc.fpaths_created, MAX_DETAIL_ITEMS),
            )
            .with_detail(
                "Modified Samples".to_string(),
                join_strings(&proc.fpaths_updated, MAX_DETAIL_ITEMS),
            )
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }

        if proc.files_read.len() > 50 {
            let event = TimelineEvent::new(
                proc.time_started,
                "Extensive File Access".to_string(),
                format!("Process accessed {} files", proc.files_read.len()),
                EventSeverity::Low,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("discovery"))
            .with_detail("Files Read".to_string(), proc.files_read.len().to_string())
            .with_detail(
                "Directories Opened".to_string(),
                join_strings(&proc.dirs_with_files_opened, MAX_DETAIL_ITEMS),
            )
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }

        if proc.on_shared_drive_read_count > 0 || proc.on_shared_drive_write_count > 0 {
            let event = TimelineEvent::new(
                proc.time_started,
                "Remote Drive Activity".to_string(),
                "Process touched files on a shared drive".to_string(),
                EventSeverity::Medium,
            )
            .with_detail(
                "Shared Reads".to_string(),
                proc.on_shared_drive_read_count.to_string(),
            )
            .with_detail(
                "Shared Writes".to_string(),
                proc.on_shared_drive_write_count.to_string(),
            )
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }
    }

    fn add_registry_events(&self, _timeline: &mut AttackTimeline, _proc: &ProcessRecord) {
        // Registry telemetry is emitted through ApiTracker::operation_sequence when
        // realtime learning is enabled.
    }

    fn add_network_events(&self, _timeline: &mut AttackTimeline, _proc: &ProcessRecord) {
        // Network telemetry is emitted through ApiTracker packet history.
    }

    #[cfg(feature = "realtime_learning")]
    fn add_api_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        self.add_api_category_event(
            timeline,
            tracker,
            "Process Injection APIs",
            "Used injection-related APIs",
            EventSeverity::Critical,
            &tracker.injection_apis,
            "writeprocessmemory createremotethread virtualalloc injection",
        );
        self.add_api_category_event(
            timeline,
            tracker,
            "Evasion APIs",
            "Used evasion APIs",
            EventSeverity::High,
            &tracker.evasion_apis,
            "defense evasion",
        );
        self.add_api_category_event(
            timeline,
            tracker,
            "Anti-Debugging APIs",
            "Used anti-debugging APIs",
            EventSeverity::Medium,
            &tracker.anti_debugging_apis,
            "defense evasion anti debug",
        );
        self.add_api_category_event(
            timeline,
            tracker,
            "Ransomware APIs",
            "Used ransomware-related APIs",
            EventSeverity::Critical,
            &tracker.ransomware_apis,
            "ransomware encrypt",
        );
        self.add_api_category_event(
            timeline,
            tracker,
            "Internet APIs",
            "Used network and internet APIs",
            EventSeverity::Medium,
            &tracker.internet_apis,
            "network http",
        );
    }

    #[cfg(feature = "realtime_learning")]
    fn add_api_category_event(
        &self,
        timeline: &mut AttackTimeline,
        tracker: &ApiTracker,
        event_type: &str,
        description: &str,
        severity: EventSeverity,
        apis: &std::collections::HashSet<String>,
        behavior_key: &str,
    ) {
        if apis.is_empty() {
            return;
        }

        let event = TimelineEvent::new(
            tracker.first_seen,
            event_type.to_string(),
            format!("{} ({})", description, apis.len()),
            severity,
        )
        .with_techniques(self.mapper.map_behavior_to_techniques(behavior_key))
        .with_detail("Count".to_string(), apis.len().to_string())
        .with_detail("APIs".to_string(), join_strings(apis, MAX_DETAIL_ITEMS))
        .with_process_info(tracker.process_name.clone(), tracker.gid);

        timeline.add_event(event);
    }

    #[cfg(feature = "realtime_learning")]
    fn add_kernel_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        let ops = &tracker.kernel_operations;

        if ops.total_kernel_events > 0 {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Kernel Telemetry".to_string(),
                format!(
                    "{} kernel/user-hook events captured",
                    ops.total_kernel_events
                ),
                if ops.write_virtual_memory > 0 || ops.create_thread > 0 {
                    EventSeverity::High
                } else {
                    EventSeverity::Medium
                },
            )
            .with_detail(
                "Total Events".to_string(),
                ops.total_kernel_events.to_string(),
            )
            .with_detail(
                "WriteVirtualMemory".to_string(),
                ops.write_virtual_memory.to_string(),
            )
            .with_detail(
                "AllocateVirtualMemory".to_string(),
                ops.allocate_virtual_memory.to_string(),
            )
            .with_detail(
                "ProtectVirtualMemory".to_string(),
                ops.protect_virtual_memory.to_string(),
            )
            .with_detail("CreateThread".to_string(), ops.create_thread.to_string())
            .with_detail("QueueApc".to_string(), ops.queue_apc.to_string())
            .with_detail("OpenProcess".to_string(), ops.open_process.to_string())
            .with_detail(
                "Loaded Drivers".to_string(),
                join_strings(&ops.loaded_kernel_drivers, MAX_DETAIL_ITEMS),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        if ops.write_virtual_memory > 0 {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Memory Write Operations".to_string(),
                format!("{} write operations", ops.write_virtual_memory),
                EventSeverity::High,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("writeprocessmemory"))
            .with_detail("Writes".to_string(), ops.write_virtual_memory.to_string())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        for (index, raw) in tracker
            .kernel_event_log
            .iter()
            .rev()
            .take(MAX_RAW_EVENTS)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .enumerate()
        {
            let event = TimelineEvent::new(
                offset_time(tracker.first_seen, index),
                "Raw Kernel Event".to_string(),
                raw.clone(),
                EventSeverity::Info,
            )
            .with_detail("Raw".to_string(), raw.clone())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        for (index, raw) in tracker
            .raw_event_log
            .iter()
            .rev()
            .take(MAX_RAW_EVENTS)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .enumerate()
        {
            let event = TimelineEvent::new(
                offset_time(tracker.first_seen, index + MAX_RAW_EVENTS),
                "Raw Driver Event".to_string(),
                raw.clone(),
                EventSeverity::Info,
            )
            .with_detail("Raw".to_string(), raw.clone())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }
    }

    #[cfg(feature = "realtime_learning")]
    fn add_operation_sequence_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        let start = tracker
            .operation_sequence
            .len()
            .saturating_sub(MAX_SEQUENCE_EVENTS);

        for (offset, op) in tracker.operation_sequence.iter().skip(start).enumerate() {
            let timestamp = offset_time(tracker.first_seen, offset);
            match op {
                OperationType::FileRead(path) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "File Read".to_string(),
                        format!("Read {}", path),
                        EventSeverity::Info,
                    )
                    .with_file_path(path.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::FileWrite(path, entropy) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "File Write".to_string(),
                        format!("Wrote {} (entropy {:.2})", path, entropy),
                        if *entropy > 7.5 {
                            EventSeverity::High
                        } else {
                            EventSeverity::Low
                        },
                    )
                    .with_techniques(if *entropy > 7.5 {
                        self.mapper.map_behavior_to_techniques("encrypt ransomware")
                    } else {
                        Vec::new()
                    })
                    .with_file_path(path.clone())
                    .with_detail("Entropy".to_string(), format!("{:.4}", entropy))
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::FileDelete(path) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "File Delete".to_string(),
                        format!("Deleted {}", path),
                        EventSeverity::Medium,
                    )
                    .with_file_path(path.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::FileRename(from, to) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "File Rename".to_string(),
                        format!("Renamed {} -> {}", from, to),
                        EventSeverity::Medium,
                    )
                    .with_file_path(from.clone())
                    .with_detail("Destination".to_string(), to.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::RegistryModify(key) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Registry Modification".to_string(),
                        key.clone(),
                        if key.to_ascii_lowercase().contains("run") {
                            EventSeverity::High
                        } else {
                            EventSeverity::Medium
                        },
                    )
                    .with_techniques(self.mapper.map_behavior_to_techniques(key))
                    .with_registry_key(key.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::NetworkConnect(destination) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Network Connection".to_string(),
                        format!("Connected to {}", destination),
                        EventSeverity::Medium,
                    )
                    .with_techniques(self.mapper.map_behavior_to_techniques("network http"))
                    .with_network_destination(destination.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::KernelApi {
                    opcode,
                    api,
                    raw_event_type,
                    source_pid,
                    target_pid,
                    arg1,
                    arg2,
                    arg3,
                    arg4,
                    size,
                    status,
                } => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Kernel API".to_string(),
                        format!("{} / {}", opcode, api),
                        if api.to_ascii_lowercase().contains("write")
                            || api.to_ascii_lowercase().contains("thread")
                        {
                            EventSeverity::High
                        } else {
                            EventSeverity::Medium
                        },
                    )
                    .with_techniques(self.mapper.map_behavior_to_techniques(api))
                    .with_detail("Opcode".to_string(), opcode.clone())
                    .with_detail("API".to_string(), api.clone())
                    .with_detail("Raw Event Type".to_string(), raw_event_type.to_string())
                    .with_detail("Source PID".to_string(), source_pid.to_string())
                    .with_detail("Target PID".to_string(), target_pid.to_string())
                    .with_detail("Arg1".to_string(), format!("0x{:X}", arg1))
                    .with_detail("Arg2".to_string(), format!("0x{:X}", arg2))
                    .with_detail("Arg3".to_string(), format!("0x{:X}", arg3))
                    .with_detail("Arg4".to_string(), format!("0x{:X}", arg4))
                    .with_detail("Size".to_string(), size.to_string())
                    .with_detail("Status".to_string(), status.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::ProcessCreate(path) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Process Create".to_string(),
                        format!("Created process {}", path),
                        EventSeverity::Medium,
                    )
                    .with_process_info(tracker.process_name.clone(), tracker.gid)
                    .with_detail("Child".to_string(), path.clone()),
                ),
                OperationType::ProcessTerminate(pid) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Process Terminate".to_string(),
                        format!("Terminated PID {}", pid),
                        EventSeverity::Medium,
                    )
                    .with_detail("Target PID".to_string(), pid.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::ProcessTerminateAttempt {
                    source_pid,
                    target_pid,
                } => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Process Termination Attempt".to_string(),
                        format!(
                            "PID {} attempted to terminate PID {}",
                            source_pid, target_pid
                        ),
                        EventSeverity::High,
                    )
                    .with_detail("Source PID".to_string(), source_pid.to_string())
                    .with_detail("Target PID".to_string(), target_pid.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::ProcessHandleOpen {
                    source_pid,
                    target_pid,
                } => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Cross-Process Handle".to_string(),
                        format!("PID {} opened a handle to PID {}", source_pid, target_pid),
                        EventSeverity::Medium,
                    )
                    .with_detail("Source PID".to_string(), source_pid.to_string())
                    .with_detail("Target PID".to_string(), target_pid.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::ProcessInjected(target_pid) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Process Injection".to_string(),
                        format!("Injection into PID {}", target_pid),
                        EventSeverity::Critical,
                    )
                    .with_techniques(self.mapper.map_behavior_to_techniques("injection"))
                    .with_detail("Target PID".to_string(), target_pid.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::MemoryAllocate(size) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Memory Allocate".to_string(),
                        format!("Allocated {} bytes", size),
                        EventSeverity::Medium,
                    )
                    .with_detail("Size".to_string(), size.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::MemoryModify(address, size) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Memory Modify".to_string(),
                        format!("Modified memory at 0x{:X}", address),
                        EventSeverity::High,
                    )
                    .with_techniques(self.mapper.map_behavior_to_techniques("writeprocessmemory"))
                    .with_detail("Address".to_string(), format!("0x{:X}", address))
                    .with_detail("Size".to_string(), size.to_string())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::MemoryProtect(address, protection) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Memory Protection Change".to_string(),
                        format!("Changed protection at 0x{:X}", address),
                        EventSeverity::High,
                    )
                    .with_detail("Address".to_string(), format!("0x{:X}", address))
                    .with_detail("Protection".to_string(), format!("0x{:X}", protection))
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::DriverLoad(path) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        "Driver Load".to_string(),
                        format!("Loaded driver {}", path),
                        EventSeverity::High,
                    )
                    .with_detail("Driver".to_string(), path.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
                OperationType::Generic(value) => timeline.add_event(
                    TimelineEvent::new(
                        timestamp,
                        if value.starts_with("SANCTUM:") {
                            "Sanctum Telemetry".to_string()
                        } else {
                            "Generic Telemetry".to_string()
                        },
                        value.clone(),
                        if value.starts_with("SANCTUM:") {
                            EventSeverity::Medium
                        } else {
                            EventSeverity::Info
                        },
                    )
                    .with_detail("Value".to_string(), value.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid),
                ),
            }
        }
    }

    #[cfg(all(
        feature = "realtime_learning",
        target_os = "windows",
        feature = "behavior_engine"
    ))]
    fn add_network_packet_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        let start = tracker.net_packets.len().saturating_sub(MAX_PACKET_EVENTS);

        for pkt in tracker.net_packets.iter().skip(start) {
            let timestamp = SystemTime::UNIX_EPOCH + Duration::from_millis(pkt.timestamp);
            let destination = format!("{}:{}", pkt.dst_ip, pkt.dst_port);
            let mut description = if let Some(query) = &pkt.dns_query {
                format!("DNS query {} -> {}", query, destination)
            } else if !pkt.url.is_empty() {
                format!(
                    "{} {}",
                    pkt.http_method.as_deref().unwrap_or("HTTP"),
                    pkt.url
                )
            } else if let Some(url) = &pkt.full_url {
                format!("{} {}", pkt.http_method.as_deref().unwrap_or("HTTP"), url)
            } else {
                format!("{} {} -> {}", pkt.protocol, pkt.src_ip, destination)
            };

            if pkt.tls_handshake {
                description.push_str(" (TLS handshake)");
            }

            let has_body = pkt.http_request_body.is_some() || pkt.http_response_body.is_some();
            let event_type = if has_body {
                "MITM HTTP Inspection"
            } else if pkt.dns_query.is_some() {
                "DNS Query"
            } else if pkt.tls_handshake {
                "TLS Handshake"
            } else {
                "Network Connection"
            };

            let severity = if has_body {
                EventSeverity::High
            } else if pkt.outbound {
                EventSeverity::Medium
            } else {
                EventSeverity::Info
            };

            let mut event =
                TimelineEvent::new(timestamp, event_type.to_string(), description, severity)
                    .with_techniques(self.mapper.map_behavior_to_techniques("network http"))
                    .with_network_destination(destination.clone())
                    .with_detail("Protocol".to_string(), pkt.protocol.to_string())
                    .with_detail(
                        "Source".to_string(),
                        format!("{}:{}", pkt.src_ip, pkt.src_port),
                    )
                    .with_detail("Destination".to_string(), destination)
                    .with_detail("Outbound".to_string(), pkt.outbound.to_string())
                    .with_detail("Size".to_string(), pkt.size.to_string())
                    .with_detail("Image Path".to_string(), pkt.image_path.clone())
                    .with_process_info(tracker.process_name.clone(), tracker.gid);

            if let Some(query) = &pkt.dns_query {
                event = event.with_detail("DNS Query".to_string(), query.clone());
            }
            if let Some(hostname) = &pkt.hostname {
                event = event.with_detail("Hostname".to_string(), hostname.clone());
            }
            if !pkt.domain.is_empty() {
                event = event.with_detail("Domain".to_string(), pkt.domain.clone());
            }
            if !pkt.url.is_empty() {
                event = event.with_detail("URL".to_string(), pkt.url.clone());
            }
            if let Some(full_url) = &pkt.full_url {
                event = event.with_detail("Full URL".to_string(), full_url.clone());
            }
            if let Some(method) = &pkt.http_method {
                event = event.with_detail("HTTP Method".to_string(), method.clone());
            }
            if let Some(path) = &pkt.http_path {
                event = event.with_detail("HTTP Path".to_string(), path.clone());
            }
            if let Some(ua) = &pkt.http_user_agent {
                event = event.with_detail("User Agent".to_string(), ua.clone());
            }
            if let Some(content_type) = &pkt.http_content_type {
                event = event.with_detail("Content Type".to_string(), content_type.clone());
            }
            if let Some(referer) = &pkt.http_referer {
                event = event.with_detail("Referer".to_string(), referer.clone());
            }
            if let Some(entropy) = pkt.payload_entropy {
                event = event.with_detail("Payload Entropy".to_string(), format!("{:.4}", entropy));
            }
            if !pkt.payload_domains.is_empty() {
                event = event.with_detail(
                    "Payload Domains".to_string(),
                    pkt.payload_domains.join(", "),
                );
            }
            if !pkt.payload_urls.is_empty() {
                event = event.with_detail("Payload URLs".to_string(), pkt.payload_urls.join(", "));
            }
            if let Some(sample) = &pkt.payload_sample {
                event = event.with_detail("Payload Sample".to_string(), clip(sample, 500));
            }
            if let Some(body) = &pkt.http_request_body {
                event = event.with_detail("MITM Request Body".to_string(), clip(body, 1000));
            }
            if let Some(body) = &pkt.http_response_body {
                event = event.with_detail("MITM Response Body".to_string(), clip(body, 1000));
            }

            timeline.add_event(event);
        }
    }

    #[cfg(all(
        feature = "realtime_learning",
        any(not(target_os = "windows"), not(feature = "behavior_engine"))
    ))]
    fn add_network_packet_events(&self, _timeline: &mut AttackTimeline, _tracker: &ApiTracker) {}

    #[cfg(all(
        target_os = "windows",
        feature = "sanctum",
        feature = "realtime_learning"
    ))]
    fn add_sanctum_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        let sanctum_ops = &tracker.sanctum_operations;

        if sanctum_ops.syscall_count > 0 {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Sanctum Syscall Stream".to_string(),
                format!(
                    "{} Sanctum syscall events captured",
                    sanctum_ops.syscall_count
                ),
                if sanctum_ops.is_detection {
                    EventSeverity::Critical
                } else {
                    EventSeverity::Medium
                },
            )
            .with_detail(
                "Syscall Count".to_string(),
                sanctum_ops.syscall_count.to_string(),
            )
            .with_detail(
                "Injection Score".to_string(),
                format!("{:.2}", sanctum_ops.injection_score),
            )
            .with_detail(
                "Cross-Process Handles".to_string(),
                sanctum_ops.cross_process_handle_count.to_string(),
            )
            .with_detail(
                "Last Event".to_string(),
                sanctum_ops.last_event.clone().unwrap_or_default(),
            )
            .with_detail(
                "Is Detection".to_string(),
                sanctum_ops.is_detection.to_string(),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        if !sanctum_ops.suspicious_syscall_hits.is_empty() {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Suspicious System Calls".to_string(),
                format!(
                    "Detected {} suspicious syscalls",
                    sanctum_ops.suspicious_syscall_hits.len()
                ),
                EventSeverity::High,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("injection"))
            .with_detail(
                "Syscalls".to_string(),
                sanctum_ops.suspicious_syscall_hits.join(", "),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        if sanctum_ops.cross_process_handle_count > 0 {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Cross-Process Operations".to_string(),
                format!(
                    "{} cross-process handle operations",
                    sanctum_ops.cross_process_handle_count
                ),
                EventSeverity::Medium,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("injection"))
            .with_detail(
                "Operations".to_string(),
                sanctum_ops.cross_process_handle_count.to_string(),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        if sanctum_ops.shellcode_patterns_found {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Shellcode Detection".to_string(),
                "Shellcode patterns detected in memory".to_string(),
                EventSeverity::Critical,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("injection"))
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        for ghost in &sanctum_ops.ghost_telemetry {
            let event = TimelineEvent::new(
                SystemTime::UNIX_EPOCH + Duration::from_millis(ghost.timestamp_ms),
                "Ghost Hook Detection".to_string(),
                format!("Hooked function: {}", ghost.function),
                EventSeverity::High,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("injection"))
            .with_detail("Function".to_string(), ghost.function.clone())
            .with_detail(
                "Caller Address".to_string(),
                format!("0x{:X}", ghost.caller_address),
            )
            .with_detail("Hex Payload".to_string(), clip(&ghost.hex_payload, 500))
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }
    }
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn offset_time(base: SystemTime, index: usize) -> SystemTime {
    base + Duration::from_millis(index as u64)
}

fn empty_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "N/A".to_string()
    } else {
        trimmed.to_string()
    }
}

fn clip(value: &str, max_chars: usize) -> String {
    let mut clipped = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        clipped.push_str("...");
    }
    clipped
}

fn join_strings(values: &std::collections::HashSet<String>, limit: usize) -> String {
    if values.is_empty() {
        return "N/A".to_string();
    }

    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    let mut selected = ordered.iter().take(limit).cloned().collect::<Vec<_>>();
    if ordered.len() > limit {
        selected.push(format!("... +{} more", ordered.len() - limit));
    }
    selected.join(", ")
}

fn join_u32_set(values: &std::collections::HashSet<u32>, limit: usize) -> String {
    if values.is_empty() {
        return "N/A".to_string();
    }

    let ordered = values.iter().copied().collect::<BTreeSet<_>>();
    let mut selected = ordered
        .iter()
        .take(limit)
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    if ordered.len() > limit {
        selected.push(format!("... +{} more", ordered.len() - limit));
    }
    selected.join(", ")
}
