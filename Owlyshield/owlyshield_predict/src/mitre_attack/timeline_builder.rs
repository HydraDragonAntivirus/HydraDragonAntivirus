//! Timeline Builder
//!
//! Builds attack timelines from process behavior data

use super::technique_mapping::TechniqueMapper;
use super::timeline::{AttackTimeline, EventSeverity, TimelineEvent};
use crate::process::ProcessRecord;
use crate::realtime_learning::api_tracker::ApiTracker;

pub struct TimelineBuilder {
    mapper: TechniqueMapper,
}

impl TimelineBuilder {
    pub fn new() -> Self {
        TimelineBuilder {
            mapper: TechniqueMapper::new(),
        }
    }

    /// Build a complete attack timeline from process record and API tracker
    pub fn build_timeline(
        &self,
        proc: &ProcessRecord,
        api_tracker: Option<&ApiTracker>,
    ) -> AttackTimeline {
        let mut timeline = AttackTimeline::new(
            proc.gid,
            proc.appname.clone(),
            proc.appname.clone(), // Use appname as path since process_path doesn't exist
        );

        timeline.start_time = proc.time_started;

        // Add events from process record
        self.add_file_events(&mut timeline, proc);
        self.add_registry_events(&mut timeline, proc);
        self.add_network_events(&mut timeline, proc);

        // Add events from API tracker if available
        if let Some(tracker) = api_tracker {
            self.add_api_events(&mut timeline, tracker);
            self.add_kernel_events(&mut timeline, tracker);

            #[cfg(all(target_os = "windows", feature = "sanctum"))]
            self.add_sanctum_events(&mut timeline, tracker);
        }

        timeline.finalize();
        timeline
    }

    fn add_file_events(&self, timeline: &mut AttackTimeline, proc: &ProcessRecord) {
        // High entropy file writes (potential ransomware)
        // Check if entropy_written is high
        if proc.entropy_written > 7.5 && proc.files_written.len() > 5 {
            let event = TimelineEvent::new(
                proc.time_started,
                "File Encryption".to_string(),
                format!(
                    "Multiple high-entropy files written (avg entropy: {:.2})",
                    proc.entropy_written / proc.files_written.len() as f64
                ),
                EventSeverity::Critical,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("encrypt"))
            .with_detail(
                "Files Written".to_string(),
                proc.files_written.len().to_string(),
            )
            .with_detail(
                "Avg Entropy".to_string(),
                format!("{:.2}", proc.entropy_written / proc.files_written.len() as f64),
            )
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }

        // Mass file operations
        if proc.fpaths_created.len() > 50 || proc.fpaths_updated.len() > 100 {
            let severity = if proc.fpaths_created.len() > 100 {
                EventSeverity::High
            } else {
                EventSeverity::Medium
            };

            let event = TimelineEvent::new(
                proc.time_started,
                "Mass File Operations".to_string(),
                format!(
                    "Created: {}, Modified: {}",
                    proc.fpaths_created.len(),
                    proc.fpaths_updated.len()
                ),
                severity,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("ransomware"))
            .with_detail("Files Created".to_string(), proc.fpaths_created.len().to_string())
            .with_detail("Files Modified".to_string(), proc.fpaths_updated.len().to_string())
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }

        // File access patterns - simplified checks based on available fields
        if proc.files_read.len() > 50 {
            let event = TimelineEvent::new(
                proc.time_started,
                "Extensive File Access".to_string(),
                format!("Process accessed {} files", proc.files_read.len()),
                EventSeverity::Low,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("discovery"))
            .with_detail("Files Read".to_string(), proc.files_read.len().to_string())
            .with_process_info(proc.appname.clone(), proc.gid);

            timeline.add_event(event);
        }
    }

    fn add_registry_events(&self, _timeline: &mut AttackTimeline, _proc: &ProcessRecord) {
        // Registry tracking would need to be implemented separately
        // ProcessRecord doesn't have registry_keys_set field
        // This would require behavioral engine integration
    }

    fn add_network_events(&self, timeline: &mut AttackTimeline, _proc: &ProcessRecord) {
        // Network activity detection - would need to be tracked separately
        // Skipping for now as ProcessRecord doesn't have network_connections field
    }

    fn add_api_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        // Process injection APIs
        if !tracker.injection_apis.is_empty() {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Process Injection APIs".to_string(),
                format!("Used {} injection-related APIs", tracker.injection_apis.len()),
                EventSeverity::Critical,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("virtualalloc"))
            .with_detail("APIs".to_string(), tracker.injection_apis.len().to_string())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        // Evasion APIs
        if !tracker.evasion_apis.is_empty() {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Evasion Techniques".to_string(),
                format!("Used {} evasion APIs", tracker.evasion_apis.len()),
                EventSeverity::High,
            )
            .with_detail("APIs".to_string(), tracker.evasion_apis.len().to_string())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        // Anti-debugging
        if !tracker.anti_debugging_apis.is_empty() {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Anti-Debugging".to_string(),
                format!("Used {} anti-debugging APIs", tracker.anti_debugging_apis.len()),
                EventSeverity::Medium,
            )
            .with_detail("APIs".to_string(), tracker.anti_debugging_apis.len().to_string())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        // Ransomware APIs
        if !tracker.ransomware_apis.is_empty() {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Ransomware Indicators".to_string(),
                format!("Used {} ransomware-related APIs", tracker.ransomware_apis.len()),
                EventSeverity::Critical,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("ransomware"))
            .with_detail("APIs".to_string(), tracker.ransomware_apis.len().to_string())
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }
    }

    fn add_kernel_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        // Analyze kernel operation stats
        if tracker.kernel_operations.total_kernel_events > 100 {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "High Kernel Activity".to_string(),
                format!("{} kernel events", tracker.kernel_operations.total_kernel_events),
                EventSeverity::Medium,
            )
            .with_detail(
                "Events".to_string(),
                tracker.kernel_operations.total_kernel_events.to_string(),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        // Check for memory operations
        if tracker.kernel_operations.write_virtual_memory > 0 {
            let event = TimelineEvent::new(
                tracker.first_seen,
                "Memory Write Operations".to_string(),
                format!("{} write operations", tracker.kernel_operations.write_virtual_memory),
                EventSeverity::High,
            )
            .with_techniques(self.mapper.map_behavior_to_techniques("writeprocessmemory"))
            .with_detail(
                "Writes".to_string(),
                tracker.kernel_operations.write_virtual_memory.to_string(),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }
    }

    #[cfg(all(target_os = "windows", feature = "sanctum"))]
    fn add_sanctum_events(&self, timeline: &mut AttackTimeline, tracker: &ApiTracker) {
        let sanctum_ops = &tracker.sanctum_operations;

        // Suspicious syscalls
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
            .with_detail(
                "Syscalls".to_string(),
                sanctum_ops.suspicious_syscall_hits.join(", "),
            )
            .with_process_info(tracker.process_name.clone(), tracker.gid);

            timeline.add_event(event);
        }

        // Cross-process handle operations
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

        // Shellcode patterns
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

        // Ghost telemetry events
        for ghost in &sanctum_ops.ghost_telemetry {
            let event = TimelineEvent::new(
                SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_millis(ghost.timestamp_ms),
                "Ghost Hook Detection".to_string(),
                format!("Hooked function: {}", ghost.function),
                EventSeverity::High,
            )
            .with_detail("Function".to_string(), ghost.function.clone())
            .with_detail(
                "Caller Address".to_string(),
                format!("0x{:X}", ghost.caller_address),
            )
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
