use crate::threat_handler::{QuarantineMetadata, ThreatHandler};
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::Write;
use std::path::Path;
#[cfg(feature = "realtime_learning")]
use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use log::warn;

use crate::config::Config;
use crate::connectors::register::Connectors;
use crate::logging::Logging;
use crate::notifications::notify;
use crate::predictions::prediction::input_tensors::VecvecCappedF32;
use crate::process::{ProcessRecord, ProcessState};
use crate::utils::{
    FILE_TIME_FORMAT, LONG_TIME_FORMAT, protected_process_record_reason, resolve_process_path,
    suspicious_critical_process_record_reason,
};
/// New struct to hold detailed threat information.
#[derive(Debug, Clone)]
pub struct ThreatInfo<'a> {
    pub threat_type_label: &'a str, // e.g., "Ransomware", "Malware", "PUA"
    pub virus_name: &'a str,        // e.g., "Behavioral Detection", "Trojan.Generic"
    pub prediction: f32,
    pub match_details: Option<String>,
    pub deny_access: bool,
    pub terminate: bool,
    pub quarantine: bool,
    pub kill_and_remove: bool, // Added field to match usage in behavior_engine.rs
    pub suspend: bool,
    pub notify_user: bool,
    pub revert: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ActionReportContext {
    #[cfg(feature = "realtime_learning")]
    pub api_tracker: Option<crate::realtime_learning::ApiTracker>,
}

pub const RESTART_CLEANUP_PREDICTION_THRESHOLD: f32 = 0.999;

impl ThreatInfo<'_> {
    fn is_pending_user_decision(&self) -> bool {
        let details = self
            .match_details
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        details.contains("pending user decision")
    }

    fn should_notify(&self) -> bool {
        if self.is_pending_user_decision() {
            return false;
        }

        self.notify_user
            || self.deny_access
            || self.suspend
            || self.terminate
            || self.quarantine
            || self.kill_and_remove
            || self.revert
    }

    fn response_label_for(&self, proc: &ProcessRecord) -> &'static str {
        if restart_cleanup_reason(proc, self).is_some() {
            "Restart to clean"
        } else if self.kill_and_remove {
            "Kill and remove"
        } else if self.terminate && self.quarantine {
            "Kill and quarantine"
        } else if self.terminate {
            "Kill"
        } else if self.deny_access {
            "Access denied"
        } else if self.suspend {
            "Suspend"
        } else if self.revert {
            "Auto-revert"
        } else if self.notify_user {
            "Notify only"
        } else {
            "Record only"
        }
    }

    fn response_time_label_for(&self, proc: &ProcessRecord) -> &'static str {
        if restart_cleanup_reason(proc, self).is_some() {
            "Queued at"
        } else if self.notify_user
            && !self.deny_access
            && !self.suspend
            && !self.terminate
            && !self.quarantine
            && !self.kill_and_remove
            && !self.revert
        {
            "Notified at"
        } else {
            "Responded at"
        }
    }
}

pub struct ActionsOnKill {
    actions: Vec<Box<dyn ActionOnKill>>,
}

pub struct WriteReportFile();
pub struct WriteReportHtmlFile();

pub trait ActionOnKill {
    fn run(
        &self,
        config: &Config,
        proc: &mut ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo struct
        threat_info: &ThreatInfo,
        report_context: &ActionReportContext,
        now: &str,
    ) -> Result<(), Box<dyn Error>>;
}

impl Default for ActionsOnKill {
    fn default() -> Self {
        Self::new()
    }
}

pub fn restart_cleanup_reason(
    proc: &ProcessRecord,
    threat_info: &ThreatInfo<'_>,
) -> Option<String> {
    if !(threat_info.terminate || threat_info.quarantine || threat_info.kill_and_remove) {
        return None;
    }

    if threat_info.prediction < RESTART_CLEANUP_PREDICTION_THRESHOLD {
        return None;
    }

    if let Some(reason) = suspicious_critical_process_record_reason(proc) {
        return Some(format!(
            "{}. Cleanup should run during the next restart instead of a live terminate",
            reason
        ));
    }

    termination_block_reason(proc).map(|reason| {
        format!(
            "{}. Cleanup should run during the next restart instead of a live terminate",
            reason
        )
    })
}

fn normalized_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_matches(char::from(0))
        .to_ascii_lowercase()
}

fn remediation_targets_process_image(proc: &ProcessRecord) -> bool {
    let remediation_path = proc.primary_remediation_path();
    if remediation_path.as_os_str().is_empty() || proc.exepath.as_os_str().is_empty() {
        return false;
    }

    normalized_path_key(remediation_path) == normalized_path_key(proc.exepath.as_path())
}

fn should_install_kernel_deny_for_remediation(
    proc: &ProcessRecord,
    threat_info: &ThreatInfo<'_>,
) -> bool {
    let remediation_path = proc.primary_remediation_path();
    if remediation_path.as_os_str().is_empty() {
        return false;
    }

    if remediation_targets_process_image(proc) {
        let deny_only = threat_info.deny_access
            && !threat_info.suspend
            && !threat_info.terminate
            && !threat_info.quarantine
            && !threat_info.kill_and_remove
            && !threat_info.revert;
        let queued_restart_cleanup = restart_cleanup_reason(proc, threat_info).is_some();

        if deny_only || queued_restart_cleanup {
            return false;
        }
    }

    true
}

fn quarantine_detection_label(proc: &ProcessRecord, threat_info: &ThreatInfo<'_>) -> String {
    let mut segments = Vec::new();

    let mut push_unique = |value: &str| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        if segments
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(trimmed))
        {
            return;
        }
        segments.push(trimmed.to_string());
    };

    push_unique(threat_info.threat_type_label);
    push_unique(threat_info.virus_name);

    if let Some(rule_name) = proc.triggered_rule_name.as_deref() {
        push_unique(rule_name);
    }

    if let Some(details) = threat_info
        .match_details
        .as_deref()
        .or(proc.triggered_rule_details.as_deref())
    {
        let clipped = details.trim().chars().take(240).collect::<String>();
        if !clipped.is_empty() {
            segments.push(format!("Details: {}", clipped));
        }
    }

    if segments.is_empty() {
        "Malicious Behavior Detected".to_string()
    } else {
        segments.join(" | ")
    }
}

impl ActionsOnKill {
    pub fn new() -> ActionsOnKill {
        ActionsOnKill {
            actions: vec![
                Box::new(WriteReportFile()),
                Box::new(WriteReportHtmlFile()),
                Box::new(Connectors),
                Box::new(Logging),
            ],
        }
    }

    pub fn with_handler(handler: Box<dyn ThreatHandler>) -> ActionsOnKill {
        ActionsOnKill {
            actions: vec![
                Box::new(KillAction {
                    handler: handler.clone_box(),
                }),
                Box::new(RevertAction {
                    handler: handler.clone_box(),
                }),
                Box::new(WriteReportFile()),
                Box::new(WriteReportHtmlFile()),
                Box::new(Connectors),
                Box::new(Logging),
            ],
        }
    }

    /// NEW run_actions_with_info: The main logic, now takes ThreatInfo
    pub fn run_actions_with_info(
        &self,
        config: &Config,
        proc: &mut ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo, // Takes the new struct
    ) {
        self.run_actions_with_info_and_context(
            config,
            proc,
            pred_mtrx,
            threat_info,
            &ActionReportContext::default(),
        );
    }

    pub fn run_actions_with_info_and_context(
        &self,
        config: &Config,
        proc: &mut ProcessRecord,
        pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo,
        report_context: &ActionReportContext,
    ) {
        if restart_cleanup_reason(proc, threat_info).is_some() {
            proc.restart_cleanup_requested = true;
            proc.process_state = ProcessState::RestartCleanupPending;
        }

        let now = (DateTime::from(SystemTime::now()) as DateTime<Local>)
            .format(FILE_TIME_FORMAT)
            .to_string();
        for action in &self.actions {
            action
                // MODIFIED: Pass threat_info
                .run(config, proc, pred_mtrx, threat_info, report_context, &now)
                .unwrap_or_else(|e| {
                    Logging::error(format!("Error with post_kill action: {e}").as_str());
                });
        }
    }
}

fn best_process_display(proc: &mut ProcessRecord) -> String {
    let exe_text = proc.exepath.to_string_lossy().trim().to_string();
    if !exe_text.is_empty() && !exe_text.eq_ignore_ascii_case("unknown") {
        return exe_text;
    }

    let app_text = proc.appname.trim().to_string();
    if !app_text.is_empty()
        && !app_text.eq_ignore_ascii_case("unknown")
        && !app_text.starts_with("PROC_")
    {
        return app_text;
    }

    if let Some(resolved) = proc
        .pids
        .iter()
        .find_map(|pid| resolve_process_path(*pid).map(|path| (*pid, path)))
    {
        let (_, path) = resolved;
        if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
            proc.appname = file_name.to_string();
        }
        proc.exepath = path.clone();
        return path.display().to_string();
    }

    if let Some(remediation) = proc.remediation_target_path.as_ref() {
        let text = remediation.to_string_lossy().trim().to_string();
        if !text.is_empty() && !text.eq_ignore_ascii_case("unknown") {
            return text;
        }
    }

    if let Some(pid) = proc.pids.iter().next() {
        return format!("PID {}", pid);
    }

    "UNKNOWN".to_string()
}

impl ActionOnKill for WriteReportFile {
    fn run(
        &self,
        _config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        now: &str,
    ) -> Result<(), Box<dyn Error>> {
        if !threat_info.should_notify() {
            return Ok(());
        }

        let report_dir = crate::globals::report_dir();
        std::fs::create_dir_all(report_dir)?;
        let basename = Path::new(&proc.appname)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let temp = report_dir.join(Path::new(&format!(
            "{}_{}_report_{}.log",
            &basename, now, &proc.gid,
        )));
        let report_path = temp.to_str().unwrap_or("");
        println!("{report_path}");
        let mut file = File::create(Path::new(&report_path))?;
        let stime_started: DateTime<Local> = proc.time_started.into();
        let display_process = best_process_display(proc);
        file.write_all(b"Owlyshield report file\n\n")?;
        file.write_all(
            // MODIFIED: Use threat_type_label
            format!(
                "{} detected running from: {}\n\n",
                threat_info.threat_type_label, display_process
            )
            .as_bytes(),
        )?;
        file.write_all(
            format!("Started at {}\n", stime_started.format(LONG_TIME_FORMAT)).as_bytes(),
        )?;
        file.write_all(
            format!(
                "Response: {}\n{} {}\n\n",
                threat_info.response_label_for(proc),
                threat_info.response_time_label_for(proc),
                DateTime::<Local>::from(proc.time_killed.unwrap_or_else(SystemTime::now))
                    .format(LONG_TIME_FORMAT)
            )
            .as_bytes(),
        )?;
        // MODIFIED: Add virus_name and use prediction from struct
        file.write_all(format!("Detection: {}\n", threat_info.virus_name).as_bytes())?;
        file.write_all(format!("Certainty: {}\n", threat_info.prediction).as_bytes())?;
        if let Some(details) = &threat_info.match_details {
            file.write_all(format!("Details: {}\n", details).as_bytes())?;
        }
        file.write_all(b"\n")?;
        file.write_all(b"Files modified:\n")?;
        for f in &proc.fpaths_updated {
            file.write_all(format!("\t{f:?}\n").as_bytes())?;
        }
        Ok(())
    }
}

/// Helper function to build evidence detections from timeline events
#[cfg(feature = "realtime_learning")]
fn build_evidence_from_timeline(
    timeline: &crate::mitre_attack::timeline::AttackTimeline,
    proc: &crate::process::ProcessRecord,
) -> Vec<crate::mitre_attack::DetectionEvidence> {
    use crate::mitre_attack::{EvidenceBuilder, EvidenceItem, EvidenceSource};
    use std::collections::HashMap;

    let mut detections = Vec::new();

    // Group events by technique
    let mut technique_events: HashMap<String, Vec<&crate::mitre_attack::timeline::TimelineEvent>> =
        HashMap::new();
    for event in &timeline.events {
        for technique in &event.mitre_techniques {
            technique_events
                .entry(technique.id.clone())
                .or_insert_with(Vec::new)
                .push(event);
        }
    }

    // Build evidence for each technique
    for (technique_id, events) in technique_events {
        let technique_name = events[0]
            .mitre_techniques
            .iter()
            .find(|t| t.id == technique_id)
            .map(|t| t.name.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut builder = EvidenceBuilder::new(technique_id, technique_name);
        let pid_list = proc
            .pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        builder = builder.add_process_tree_evidence(format!(
            "Process context: {} ({})",
            proc.appname,
            if pid_list.is_empty() {
                "no pid".to_string()
            } else {
                format!("pid {}", pid_list)
            }
        ));

        if events.iter().any(|event| {
            let event_type = event.event_type.to_ascii_lowercase();
            event_type.contains("kernel")
                || event_type.contains("driver")
                || event_type.contains("sanctum")
                || event_type.contains("hypervisor")
                || event_type.contains("ghost")
        }) {
            builder = builder.add_hypervisor_evidence(
                "Kernel, hypervisor, or Sanctum telemetry contributed to this detection",
            );
        }

        if events
            .iter()
            .any(|event| evidence_source_for_event(&event.event_type) == EvidenceSource::Static)
        {
            builder = builder.add_static_evidence(
                "Static or signature-like evidence contributed to this ATT&CK technique",
            );
        }
        if events
            .iter()
            .any(|event| evidence_source_for_event(&event.event_type) == EvidenceSource::Behavioral)
        {
            builder = builder.add_behavioral_evidence(
                "Behavioral process activity contributed to this ATT&CK technique",
            );
        }
        if events
            .iter()
            .any(|event| evidence_source_for_event(&event.event_type) == EvidenceSource::Network)
        {
            builder = builder
                .add_network_evidence("Network, DNS, HTTP, TLS, C2, or MITM telemetry observed");
        }
        if events
            .iter()
            .any(|event| evidence_source_for_event(&event.event_type) == EvidenceSource::Registry)
        {
            builder = builder
                .add_registry_evidence("Registry activity contributed to this ATT&CK technique");
        }
        if events
            .iter()
            .any(|event| evidence_source_for_event(&event.event_type) == EvidenceSource::Dynamic)
        {
            builder = builder.add_dynamic_evidence(
                "Dynamic runtime telemetry contributed to this ATT&CK technique",
            );
        }

        // Add evidence from each event
        for event in events {
            let mut evidence = EvidenceItem::new(
                evidence_source_for_event(&event.event_type),
                format!("{}: {}", event.event_type, event.description),
            )
            .with_weight(evidence_weight_for_event(event.severity))
            .with_timestamp(event.timestamp);

            let context = timeline_event_context(event);
            if !context.is_empty() {
                evidence = evidence.with_context(context);
            }

            let raw_data = timeline_event_raw_data(event);
            if !raw_data.is_empty() {
                evidence = evidence.with_raw_data(raw_data);
            }

            builder = builder.add_evidence(evidence);
        }

        detections.push(builder.build());
    }

    detections
}

#[cfg(feature = "realtime_learning")]
fn evidence_source_for_event(event_type: &str) -> crate::mitre_attack::EvidenceSource {
    use crate::mitre_attack::EvidenceSource;

    let event_type = event_type.to_ascii_lowercase();
    if event_type.contains("dns")
        || event_type.contains("http")
        || event_type.contains("mitm")
        || event_type.contains("network")
        || event_type.contains("tls")
        || event_type.contains("c2")
    {
        EvidenceSource::Network
    } else if event_type.contains("hash")
        || event_type.contains("signature")
        || event_type.contains("static")
        || event_type.contains("yara")
        || event_type.contains("entropy")
        || event_type.contains("import")
    {
        EvidenceSource::Static
    } else if event_type.contains("registry") {
        EvidenceSource::Registry
    } else if event_type.contains("file")
        || event_type.contains("encryption")
        || event_type.contains("ransomware")
    {
        EvidenceSource::FileSystem
    } else if event_type.contains("memory")
        || event_type.contains("injection")
        || event_type.contains("shellcode")
    {
        EvidenceSource::Memory
    } else if event_type.contains("kernel")
        || event_type.contains("driver")
        || event_type.contains("hypervisor")
        || event_type.contains("ghost")
    {
        EvidenceSource::Hypervisor
    } else if event_type.contains("sanctum") || event_type.contains("syscall") {
        EvidenceSource::SanctumEDR
    } else if event_type.contains("process") || event_type.contains("command") {
        EvidenceSource::Behavioral
    } else {
        EvidenceSource::Dynamic
    }
}

#[cfg(feature = "realtime_learning")]
fn evidence_weight_for_event(severity: crate::mitre_attack::timeline::EventSeverity) -> f32 {
    use crate::mitre_attack::timeline::EventSeverity;

    match severity {
        EventSeverity::Critical => 0.95,
        EventSeverity::High => 0.85,
        EventSeverity::Medium => 0.70,
        EventSeverity::Low => 0.55,
        EventSeverity::Info => 0.40,
    }
}

#[cfg(feature = "realtime_learning")]
fn timeline_event_context(event: &crate::mitre_attack::timeline::TimelineEvent) -> String {
    let mut parts = Vec::new();

    if let Some(pid) = event.pid {
        parts.push(format!("pid={pid}"));
    }
    if let Some(process_name) = &event.process_name {
        parts.push(format!("process={process_name}"));
    }
    if let Some(file_path) = &event.file_path {
        parts.push(format!("file={file_path}"));
    }
    if let Some(registry_key) = &event.registry_key {
        parts.push(format!("registry={registry_key}"));
    }
    if let Some(destination) = &event.network_destination {
        parts.push(format!("network={destination}"));
    }
    for (key, value) in event.details.iter().take(8) {
        parts.push(format!("{key}={value}"));
    }

    parts.join(" | ")
}

#[cfg(feature = "realtime_learning")]
fn timeline_event_raw_data(event: &crate::mitre_attack::timeline::TimelineEvent) -> String {
    event
        .details
        .iter()
        .take(24)
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(feature = "realtime_learning")]
fn build_detection_explanation(
    threat_info: &ThreatInfo,
    timeline: &crate::mitre_attack::AttackTimeline,
    evidence_report: &crate::mitre_attack::DetectionReport,
    score: &crate::mitre_attack::ThreatScore,
) -> crate::explainability::DetectionExplanation {
    use crate::explainability::ExplanationBuilder;
    use crate::mitre_attack::EventSeverity;

    let mut builder = ExplanationBuilder::new().set_severity(score.threat_level.label());
    builder = builder.add_reason(format!(
        "{} generated {} timeline events with max severity {}.",
        threat_info.threat_type_label,
        timeline.events.len(),
        timeline.max_severity.label()
    ));
    builder = builder.add_reason(format!(
        "Overall ATT&CK score is {:.1}/10 with {:.0}% confidence.",
        score.normalized_score,
        score.confidence * 100.0
    ));
    builder = builder.add_reason(format!(
        "Evidence engine primary tactic: {} with {} detected techniques.",
        evidence_report.primary_tactic,
        evidence_report.detections.len()
    ));

    if let Some(details) = threat_info.match_details.as_deref() {
        builder = builder.add_reason(format!("Detector details: {details}"));
    }

    let critical_count = timeline
        .get_events_by_severity(EventSeverity::Critical)
        .len();
    let high_count = timeline.get_events_by_severity(EventSeverity::High).len();
    let c2_count = timeline.get_events_by_tactic("Command and Control").len();
    let impact_count = timeline.get_events_by_tactic("Impact").len();
    let score_bucket = EventSeverity::from_score(score.normalized_score.round() as u8);

    if critical_count > 0 || high_count > 0 {
        builder = builder.add_reason(format!(
            "High-signal event count: {critical_count} critical and {high_count} high severity events."
        ));
    }
    if c2_count > 0 {
        builder = builder.add_reason(format!(
            "{c2_count} command-and-control related timeline events were observed."
        ));
    }
    if impact_count > 0 {
        builder = builder.add_reason(format!(
            "{impact_count} impact-stage events were observed, including ransomware or destructive behavior."
        ));
    }
    builder = builder.add_reason(format!(
        "Score-derived event severity bucket: {}.",
        score_bucket.label()
    ));

    for event in timeline
        .events
        .iter()
        .filter(|event| event.severity >= EventSeverity::High)
        .take(8)
    {
        builder = builder.add_reason(format!(
            "{} [{}]: {}",
            event.event_type,
            event.severity.label(),
            event.description
        ));
    }

    for technique in timeline.get_unique_techniques().into_iter().take(12) {
        builder = builder.add_technique(format!(
            "{} - {} ({})",
            technique.id, technique.name, technique.tactic
        ));
    }

    builder.build()
}

#[cfg(feature = "realtime_learning")]
fn build_correlation_graph(
    timeline: &crate::mitre_attack::AttackTimeline,
    proc: &crate::process::ProcessRecord,
    evidence_report: &crate::mitre_attack::DetectionReport,
    score: &crate::mitre_attack::ThreatScore,
) -> crate::correlation::CorrelationGraph {
    use crate::correlation::{DetectionNode, NodeType, SignalCorrelator};

    let mut signals = Vec::new();
    let process_pid = proc.pids.iter().next().copied().unwrap_or_default();
    signals.push(DetectionNode {
        id: "process-root".to_string(),
        node_type: NodeType::ProcessExecution,
        data: format!(
            "{} pid={} gid={} score={:.1}",
            proc.appname, process_pid, proc.gid, score.normalized_score
        ),
        confidence: score.confidence,
        timestamp_ms: system_time_ms(timeline.start_time),
    });

    for (index, event) in timeline.events.iter().take(90).enumerate() {
        signals.push(DetectionNode {
            id: format!("event-{index}"),
            node_type: node_type_for_timeline_event(&event.event_type),
            data: compact_timeline_event(event),
            confidence: evidence_weight_for_event(event.severity),
            timestamp_ms: event.timestamp_ms,
        });
    }

    for (index, detection) in evidence_report.detections.iter().take(40).enumerate() {
        signals.push(DetectionNode {
            id: format!("technique-{index}-{}", detection.technique_id),
            node_type: node_type_for_detection(detection),
            data: detection.summary(),
            confidence: detection.confidence,
            timestamp_ms: system_time_ms(detection.first_seen),
        });
    }

    SignalCorrelator::correlate(signals)
}

#[cfg(feature = "realtime_learning")]
fn node_type_for_timeline_event(event_type: &str) -> crate::correlation::NodeType {
    use crate::correlation::NodeType;

    let event_type = event_type.to_ascii_lowercase();
    if event_type.contains("network")
        || event_type.contains("dns")
        || event_type.contains("http")
        || event_type.contains("tls")
        || event_type.contains("mitm")
    {
        NodeType::NetworkConnection
    } else if event_type.contains("registry") {
        NodeType::RegistryModification
    } else if event_type.contains("file") || event_type.contains("encrypt") {
        NodeType::FileOperation
    } else if event_type.contains("memory")
        || event_type.contains("injection")
        || event_type.contains("shellcode")
    {
        NodeType::MemoryOperation
    } else if event_type.contains("hash") || event_type.contains("signature") {
        NodeType::FileHash
    } else if event_type.contains("process") {
        NodeType::ProcessExecution
    } else {
        NodeType::APICall
    }
}

#[cfg(feature = "realtime_learning")]
fn node_type_for_detection(
    detection: &crate::mitre_attack::DetectionEvidence,
) -> crate::correlation::NodeType {
    use crate::correlation::NodeType;
    use crate::mitre_attack::EvidenceSource;

    match detection
        .evidence_chain
        .first()
        .map(|evidence| &evidence.source)
    {
        Some(EvidenceSource::Network) | Some(EvidenceSource::Firewall) => {
            NodeType::NetworkConnection
        }
        Some(EvidenceSource::Registry) => NodeType::RegistryModification,
        Some(EvidenceSource::FileSystem) | Some(EvidenceSource::Static) => NodeType::FileOperation,
        Some(EvidenceSource::Memory) => NodeType::MemoryOperation,
        Some(EvidenceSource::ProcessTree) | Some(EvidenceSource::Behavioral) => {
            NodeType::ProcessExecution
        }
        _ => NodeType::APICall,
    }
}

#[cfg(feature = "realtime_learning")]
fn compact_timeline_event(event: &crate::mitre_attack::timeline::TimelineEvent) -> String {
    let mut text = format!(
        "{} [{}]: {}",
        event.event_type,
        event.severity.label(),
        event.description
    );
    if let Some(destination) = event.network_destination.as_deref() {
        text.push_str(&format!(" -> {destination}"));
    }
    if let Some(file_path) = event.file_path.as_deref() {
        text.push_str(&format!(" file={file_path}"));
    }
    text
}

#[cfg(feature = "realtime_learning")]
fn system_time_ms(value: SystemTime) -> u64 {
    value
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(feature = "realtime_learning")]
fn html_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect::<Vec<_>>(),
            '>' => "&gt;".chars().collect::<Vec<_>>(),
            '"' => "&quot;".chars().collect::<Vec<_>>(),
            '\'' => "&#39;".chars().collect::<Vec<_>>(),
            _ => vec![ch],
        })
        .collect()
}

#[cfg(feature = "realtime_learning")]
fn write_timeline_cache(
    report_dir: &Path,
    proc: &ProcessRecord,
    now: &str,
    timeline: &crate::mitre_attack::timeline::AttackTimeline,
) -> Result<(), Box<dyn Error>> {
    let html = format!(
        "<style>{}</style>\n{}",
        crate::mitre_attack::timeline::AttackTimeline::get_timeline_css(),
        timeline.to_html()
    );
    let json = serde_json::to_string_pretty(timeline)?;
    let now = safe_cache_token(now);

    let mut pids = proc.pids.iter().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();

    let mut cache_dirs = vec![report_dir.to_path_buf()];
    let persistent_archive = persistent_mitre_archive_dir();
    if !same_cache_path(report_dir, &persistent_archive) {
        cache_dirs.push(persistent_archive);
    }

    for cache_dir in cache_dirs {
        write_timeline_cache_files(&cache_dir, proc, &now, &html, &json, &pids)?;
    }

    Ok(())
}

#[cfg(feature = "realtime_learning")]
fn write_timeline_cache_files(
    report_dir: &Path,
    proc: &ProcessRecord,
    now: &str,
    html: &str,
    json: &str,
    pids: &[u32],
) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(report_dir)?;

    if pids.is_empty() {
        let latest_html = report_dir.join(format!("latest_timeline_gid_{}.html", proc.gid));
        let latest_json = report_dir.join(format!("latest_timeline_gid_{}.json", proc.gid));
        std::fs::write(latest_html, html)?;
        std::fs::write(latest_json, json)?;
        return Ok(());
    }

    for pid in pids.iter().copied() {
        let latest_html = report_dir.join(format!("latest_timeline_pid_{}.html", pid));
        let latest_json = report_dir.join(format!("latest_timeline_pid_{}.json", pid));
        let history_html = report_dir.join(format!(
            "attack_timeline_pid_{}_{}_gid_{}.html",
            pid, now, proc.gid
        ));
        let history_json = report_dir.join(format!(
            "attack_timeline_pid_{}_{}_gid_{}.json",
            pid, now, proc.gid
        ));

        std::fs::write(latest_html, html)?;
        std::fs::write(latest_json, json)?;
        std::fs::write(history_html, html)?;
        std::fs::write(history_json, json)?;
    }

    Ok(())
}

#[cfg(feature = "realtime_learning")]
fn persistent_mitre_archive_dir() -> PathBuf {
    let program_data = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));

    program_data
        .join("HydraDragonAntivirus")
        .join("Sanctum")
        .join("mitre_attack")
}

#[cfg(feature = "realtime_learning")]
fn same_cache_path(left: &Path, right: &Path) -> bool {
    let left = left
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let right = right
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    left == right
}

#[cfg(feature = "realtime_learning")]
fn safe_cache_token(value: &str) -> String {
    let token = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    if token.is_empty() {
        "timeline".to_string()
    } else {
        token
    }
}

impl ActionOnKill for WriteReportHtmlFile {
    fn run(
        &self,
        _config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        report_context: &ActionReportContext,
        now: &str,
    ) -> Result<(), Box<dyn Error>> {
        #[cfg(not(feature = "realtime_learning"))]
        let _ = report_context;

        if !threat_info.should_notify() {
            return Ok(());
        }

        let report_dir = crate::globals::report_dir();
        std::fs::create_dir_all(report_dir)?;
        let basename = Path::new(&proc.appname)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let temp = match proc.process_state {
            ProcessState::Suspended => report_dir.join(Path::new(&format!(
                "~{}_{}_report_{}.html",
                &basename, now, &proc.gid,
            ))),
            _ => report_dir.join(Path::new(&format!(
                "{}_{}_report_{}.html",
                &basename, now, &proc.gid,
            ))),
        };

        let report_path = temp.to_str().unwrap_or("");
        println!("{report_path}");
        let mut file = File::create(Path::new(&report_path))?;
        let stime_started: DateTime<Local> = proc.time_started.into();
        let display_process = best_process_display(proc);
        file.write_all(b"<!DOCTYPE html><html><head>")?;
        file.write_all(format!("<title>Owlyshield Report {}</title><link rel='icon' href='https://static.thenounproject.com/png/3420953-200.png'/><meta name='viewport' content='width=device-width, initial-scale=1'/>\n", proc.gid).as_bytes())?;

        // Include report CSS
        file.write_all(b"<style>body{font-family:Arial,Helvetica,sans-serif;margin:0;padding:20px;background:#f5f7fa;color:#1f2933;}.tab{display:flex;flex-wrap:wrap;gap:4px;border:1px solid #ccd3dc;background:#eef2f7;padding:6px;margin:20px auto;max-width:1180px;}.tab button{background:#fff;border:1px solid #ccd3dc;outline:none;cursor:pointer;padding:12px 14px;transition:0.2s;font-size:14px;min-width:150px;flex:1 1 auto;}.tab button:hover{background:#e5edf7;}.tab button.active{background:#1f5fbf;color:white;border-color:#1f5fbf;}.tabcontent{display:none;padding:12px;max-width:1180px;margin:0 auto 20px auto;background:white;border:1px solid #d9e1ec;}table{width:80%;align:center;margin-left:auto;margin-right:auto;}th{background-color:red;}select{width:100%;align:center;margin-left:auto;margin-right:auto;}.raw-panel{white-space:pre-wrap;overflow:auto;max-height:680px;background:#0f172a;color:#dbeafe;padding:16px;border-radius:6px;font:12px/1.5 Consolas,monospace;}.raw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;}")?;
        #[cfg(feature = "realtime_learning")]
        {
            file.write_all(
                crate::mitre_attack::timeline::AttackTimeline::get_timeline_css().as_bytes(),
            )?;
            file.write_all(
                crate::mitre_attack::scoring::ScoringEngine::get_scoring_css().as_bytes(),
            )?;
            file.write_all(crate::mitre_attack::StoryBuilder::get_css().as_bytes())?;
            file.write_all(crate::mitre_attack::CoverageHeatmap::get_css().as_bytes())?;
            file.write_all(crate::explainability::DetectionExplanation::get_css().as_bytes())?;
            file.write_all(crate::correlation::CorrelationGraph::get_css().as_bytes())?;
        }
        file.write_all(b"</style>")?;
        file.write_all(b"</head><body>\n")?;
        // MODIFIED: Use threat_type_label
        file.write_all(
                format!("<table><tr><th><h1><b>Owlyshield detected a </b><span style='color: white;'>{}</span><b>!</b></h1></th></tr></table>\n", 
                threat_info.threat_type_label).as_bytes()
            )?;
        // MODIFIED: Use threat_type_label and add Detection (virus_name)
        file.write_all(format!(
                "<br/><table><tr><td style='text-align: center;'><h3>{} detected running from: <span style='color: red;' id='fullPath'>{}</span></h3></td></tr><tr valign='top'><td style='text-align: left;'><ul><li>Process State:<b id='processState'> {}</b></li><li>Started on<b id='startDate'> {}</b></li><li>Response:<b id='response'> {}</b></li><li>{}<b id='responseDate'> {}</b></li><li>GID: <b id='gid'> {}</b></li><li>Detection: <b id='detection'> {}</b></li><li>Certainty: <b id='certainty'> {}</b></li><li>Details: <b id='details'> {}</b></li></ul></td></tr></table>\n",
                threat_info.threat_type_label, // 1. Threat Type
                display_process, // 2. Path
                proc.process_state, // 3. State
                stime_started.format(LONG_TIME_FORMAT), // 4. Start time
                threat_info.response_label_for(proc), // 5. Response action
                threat_info.response_time_label_for(proc), // 6. Response time label
                DateTime::<Local>::from(proc.time_killed.unwrap_or_else(SystemTime::now)).format(LONG_TIME_FORMAT), // 7. Response time
                proc.gid, // 8. GID
                threat_info.virus_name, // 9. Virus Name
                threat_info.prediction, // 10. Certainty
                threat_info.match_details.as_deref().unwrap_or("N/A") // 11. Details
            ).as_bytes())?;

        // Generate attack timeline, scoring, and evidence report
        #[cfg(feature = "realtime_learning")]
        {
            use crate::mitre_attack::{
                CoverageAnalyzer, CoverageHeatmap, EnhancedConfidenceScorer, EvidenceEngine,
                ScoringEngine, StoryBuilder, TechniqueMapper, TimelineBuilder,
                load_all_techniques_from_json,
            };

            let timeline_builder = TimelineBuilder::new();
            let timeline =
                timeline_builder.build_timeline(proc, report_context.api_tracker.as_ref());
            let score = ScoringEngine::calculate_score(&timeline);
            let story: crate::mitre_attack::AttackStory = StoryBuilder::build_story(&timeline);
            let mapper = TechniqueMapper::new_from_json();

            // Build evidence-based detections from timeline
            let evidence_detections = build_evidence_from_timeline(&timeline, proc);
            let mut confidence_scorer = EnhancedConfidenceScorer::new();
            let confidence_breakdowns = evidence_detections
                .iter()
                .map(|detection| {
                    confidence_scorer.update_historical_accuracy(
                        detection.technique_id.clone(),
                        detection.confidence,
                    );
                    confidence_scorer.calculate_confidence(detection)
                })
                .collect::<Vec<_>>();

            // Create evidence engine and generate report
            let technique_db = load_all_techniques_from_json();
            let coverage_analysis: crate::mitre_attack::CoverageAnalysis =
                CoverageAnalyzer::new(technique_db.clone()).analyze_coverage();
            let evidence_engine = EvidenceEngine::new(technique_db);
            let evidence_report = evidence_engine.build_report(
                proc.appname.clone(),
                proc.exepath.to_string_lossy().to_string(),
                proc.pids.iter().next().copied().unwrap_or_default(),
                proc.gid,
                evidence_detections,
                150, // analysis duration in ms
            );
            let _evidence_level: crate::mitre_attack::EvidenceThreatLevel =
                evidence_report.threat_level;
            let explanation =
                build_detection_explanation(threat_info, &timeline, &evidence_report, &score);
            let correlation_graph =
                build_correlation_graph(&timeline, proc, &evidence_report, &score);

            // Add scoring card
            file.write_all(ScoringEngine::to_html(&timeline, &score).as_bytes())?;

            // Store evidence report for later use in tabs
            let evidence_html = evidence_report.to_html();
            let explanation_html = explanation.to_html();
            let story_html = StoryBuilder::to_html(&story);
            let correlation_html = correlation_graph.to_html();
            let coverage_html = CoverageHeatmap::to_html(&coverage_analysis);
            let _evidence_text = evidence_report.to_text();
            let scoring_text = ScoringEngine::generate_report(&timeline, &score);
            let evidence_json = evidence_report
                .to_json()
                .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"));
            let coverage_json = CoverageHeatmap::to_json(&coverage_analysis)
                .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"));
            let confidence_json = serde_json::to_string_pretty(&confidence_breakdowns)
                .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"));
            let mapped_techniques = mapper.all_techniques().len();

            // Add tabs
            file.write_all(b"<table><tr><td><div class='tab'>\n")?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'evidence_report')\" id='defaultOpen'>Evidence Report</button>\n")?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'explainability')\">Explainability</button>\n")?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'attack_story')\">Attack Story</button>\n")?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'correlation_graph')\">Correlation Graph</button>\n")?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'coverage_heatmap')\">ATT&CK Coverage</button>\n")?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'raw_evidence')\">Raw Evidence</button>\n")?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_u')\">Files updated ({})</button>\n", &proc.fpaths_updated.len()).as_bytes())?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_c')\">Files created ({})</button>\n", &proc.fpaths_created.len()).as_bytes())?;
            file.write_all(b"<button class='tablinks' onclick=\"openTab(event,'attack_timeline')\">Attack Timeline</button>\n")?;
            file.write_all(b"</div></td></tr></table>\n")?;

            // Evidence Report tab (NEW - default)
            file.write_all(b"<div id='evidence_report' class='tabcontent'>")?;
            file.write_all(evidence_html.as_bytes())?;
            file.write_all(b"</div>\n")?;

            // Explainability tab
            file.write_all(b"<div id='explainability' class='tabcontent'>")?;
            file.write_all(explanation_html.as_bytes())?;
            file.write_all(
                format!("<p><strong>Loaded ATT&CK techniques:</strong> {mapped_techniques}</p>")
                    .as_bytes(),
            )?;
            file.write_all(b"</div>\n")?;

            // Attack story tab
            file.write_all(b"<div id='attack_story' class='tabcontent'>")?;
            file.write_all(story_html.as_bytes())?;
            file.write_all(b"</div>\n")?;

            // Correlation graph tab
            file.write_all(b"<div id='correlation_graph' class='tabcontent'>")?;
            file.write_all(correlation_html.as_bytes())?;
            file.write_all(b"</div>\n")?;

            // Coverage heatmap tab
            file.write_all(b"<div id='coverage_heatmap' class='tabcontent'>")?;
            file.write_all(coverage_html.as_bytes())?;
            file.write_all(b"</div>\n")?;

            // Raw evidence tab
            file.write_all(b"<div id='raw_evidence' class='tabcontent'><div class='raw-grid'>")?;
            file.write_all(b"<div><h3>Scoring Text</h3><pre class='raw-panel'>")?;
            file.write_all(html_escape(&scoring_text).as_bytes())?;
            file.write_all(b"</pre></div>")?;
            file.write_all(b"<div><h3>Evidence JSON</h3><pre class='raw-panel'>")?;
            file.write_all(html_escape(&evidence_json).as_bytes())?;
            file.write_all(b"</pre></div><div><h3>Confidence JSON</h3><pre class='raw-panel'>")?;
            file.write_all(html_escape(&confidence_json).as_bytes())?;
            file.write_all(b"</pre></div><div><h3>Coverage JSON</h3><pre class='raw-panel'>")?;
            file.write_all(html_escape(&coverage_json).as_bytes())?;
            file.write_all(b"</pre></div></div></div>\n")?;

            // Files updated tab
            file.write_all(b"<div id='files_u' class='tabcontent'><table><tr><td><select name='files_u' size='30' multiple='multiple'>\n")?;
            for f in &proc.fpaths_updated {
                file.write_all(format!("<option value='{f}'>{f}</option>\n").as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;

            // Files created tab
            file.write_all(b"<div id='files_c' class='tabcontent'><table><tr><td><select name='files_c' size='30' multiple='multiple'>\n")?;
            for f in &proc.fpaths_created {
                file.write_all(format!("<option value='{f}'>{f}</option>\n").as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;

            // Attack timeline tab
            file.write_all(b"<div id='attack_timeline' class='tabcontent'>")?;
            file.write_all(timeline.to_html().as_bytes())?;
            file.write_all(b"</div>\n")?;
            write_timeline_cache(report_dir, proc, now, &timeline)?;

            // JavaScript for tabs
            file.write_all(b"<script>function openTab(evt, tab) { var i, tabcontent, tablinks; tabcontent = document.getElementsByClassName('tabcontent'); for (i = 0; i != tabcontent.length; i++) { tabcontent[i].style.display = 'none'; } tablinks = document.getElementsByClassName('tablinks'); for (i = 0; i != tablinks.length; i++) { tablinks[i].className = tablinks[i].className.replace(' active', ''); } document.getElementById(tab).style.display = 'block'; evt.currentTarget.className += ' active'; } document.getElementById('defaultOpen').click();</script>\n")?;
        }

        #[cfg(not(feature = "realtime_learning"))]
        {
            file.write_all(b"<table><tr><td><div class='tab'>\n")?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_u')\" id='defaultOpen'>Files updated ({})</button>\n", &proc.fpaths_updated.len()).as_bytes())?;
            file.write_all(format!("<button class='tablinks' onclick=\"openTab(event,'files_c')\">Files created ({})</button>\n", &proc.fpaths_created.len()).as_bytes())?;
            file.write_all(b"</div></td></tr></table>\n")?;

            file.write_all(b"<div id='files_u' class='tabcontent'><table><tr><td><select name='files_u' size='30' multiple='multiple'>\n")?;
            for f in &proc.fpaths_updated {
                file.write_all(format!("<option value='{f}'>{f}</option>\n").as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;

            file.write_all(b"<div id='files_c' class='tabcontent'><table><tr><td><select name='files_c' size='30' multiple='multiple'>\n")?;
            for f in &proc.fpaths_created {
                file.write_all(format!("<option value='{f}'>{f}</option>\n").as_bytes())?;
            }
            file.write_all(b"</select></td></tr></table></div>\n")?;

            file.write_all(b"<script>function openTab(evt, tab) { var i, tabcontent, tablinks; tabcontent = document.getElementsByClassName('tabcontent'); for (i = 0; i != tabcontent.length; i++) { tabcontent[i].style.display = 'none'; } tablinks = document.getElementsByClassName('tablinks'); for (i = 0; i != tablinks.length; i++) { tablinks[i].className = tablinks[i].className.replace(' active', ''); } document.getElementById(tab).style.display = 'block'; evt.currentTarget.className += ' active'; } document.getElementById('defaultOpen').click();</script>\n")?;
        }

        file.write_all(b"</body></html>")?;
        Ok(())
    }
}

impl ActionOnKill for Connectors {
    fn run(
        &self,
        config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        if !threat_info.should_notify() {
            return Ok(());
        }

        // MODIFIED: Use prediction from struct
        Connectors::on_event_kill(config, proc, threat_info.prediction);
        Ok(())
    }
}

impl ActionOnKill for Logging {
    fn run(
        &self,
        _config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        // MODIFIED: Use ThreatInfo
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        let stime_started: DateTime<Local> = proc.time_started.into();
        if !threat_info.should_notify() {
            return Ok(());
        }

        let response_label = threat_info.response_label_for(proc);
        let display_process = best_process_display(proc);
        // MODIFIED: Use details from threat_info
        let msg = format!(
            "{} detected running from: {}[{}] with certainty {} (detection: {}) (response: {}) (details: {}) (started at {})",
            threat_info.threat_type_label,
            display_process,
            proc.gid,
            threat_info.prediction,
            threat_info.virus_name,
            response_label,
            threat_info.match_details.as_deref().unwrap_or("None"),
            stime_started.format(LONG_TIME_FORMAT)
        );
        Logging::alert(msg.as_str());
        warn!("ALERT: {}", msg);
        Ok(())
    }
}

pub struct KillAction {
    pub handler: Box<dyn ThreatHandler>,
}

fn termination_block_reason(proc: &ProcessRecord) -> Option<String> {
    protected_process_record_reason(proc)
}

impl ActionOnKill for KillAction {
    fn run(
        &self,
        config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        if threat_info.deny_access {
            if should_install_kernel_deny_for_remediation(proc, threat_info) {
                Logging::info(&format!(
                    "[ActionOnKill] Denying future access to: {}",
                    proc.primary_remediation_path().display()
                ));
                self.handler
                    .deny_path_access(proc.primary_remediation_path());
            } else {
                Logging::warning(&format!(
                    "[ActionOnKill] Skipping persistent kernel deny for {} (GID: {}) because the remediation target is the running process image",
                    proc.appname, proc.gid
                ));
            }
        }

        if threat_info.suspend {
            Logging::info(&format!(
                "[ActionOnKill] Suspending process: {}",
                proc.appname
            ));
            self.handler.suspend(proc);
        }

        if let Some(reason) = restart_cleanup_reason(proc, threat_info) {
            let remediation_path = proc.primary_remediation_path();
            Logging::alert(&format!(
                "[RestartCleanup] {} (GID: {}) queued for restart cleanup: {}",
                proc.appname, proc.gid, reason
            ));

            if remediation_path.as_os_str().is_empty() {
                Logging::warning(&format!(
                    "[ActionOnKill] Cannot queue restart cleanup for {} (GID: {}) because no remediation path is known",
                    proc.appname, proc.gid
                ));
            } else {
                if !threat_info.deny_access
                    && should_install_kernel_deny_for_remediation(proc, threat_info)
                {
                    Logging::info(&format!(
                        "[ActionOnKill] Denying future access to: {}",
                        remediation_path.display()
                    ));
                    self.handler.deny_path_access(remediation_path);
                } else if !threat_info.deny_access {
                    Logging::warning(&format!(
                        "[ActionOnKill] Skipping persistent kernel deny during restart-cleanup for {} (GID: {}) because the remediation target is the running process image",
                        proc.appname, proc.gid
                    ));
                }

                Logging::info(&format!(
                    "[ActionOnKill] Scheduling cleanup on restart for: {}",
                    remediation_path.display()
                ));
                self.handler.schedule_cleanup_on_reboot(remediation_path);
            }

            let _ = notify(
                config,
                &format!(
                    "Malware cleanup for {} was queued for the next restart.",
                    proc.appname
                ),
                "",
            );
            return Ok(());
        }

        if threat_info.terminate {
            if let Some(reason) = suspicious_critical_process_record_reason(proc) {
                Logging::alert(&format!(
                    "[CriticalProcessAbuse] {} (GID: {}) attempted to survive via the Windows critical-process flag: {}",
                    proc.appname, proc.gid, reason
                ));
                Logging::warning(&format!(
                    "[ActionOnKill] Refusing to terminate suspicious critical-marked process {} (GID: {}); leaving it for offline/manual remediation",
                    proc.appname, proc.gid
                ));
                return Ok(());
            }

            if let Some(reason) = termination_block_reason(proc) {
                Logging::warning(&format!(
                    "[ActionOnKill] Refusing to terminate protected process {} (GID: {}): {}",
                    proc.appname, proc.gid, reason
                ));
                return Ok(());
            }

            if threat_info.quarantine {
                Logging::info(&format!(
                    "[ActionOnKill] Terminating and Quarantining: {}",
                    proc.appname
                ));
                let quarantine_metadata = QuarantineMetadata {
                    detection: quarantine_detection_label(proc, threat_info),
                };
                self.handler.kill_and_quarantine(
                    proc.gid,
                    proc.primary_remediation_path(),
                    &quarantine_metadata,
                );
            } else if threat_info.kill_and_remove {
                Logging::info(&format!("[ActionOnKill] Kill and Remove: {}", proc.appname));
                self.handler
                    .kill_and_remove(proc.gid, proc.primary_remediation_path());
            } else {
                Logging::info(&format!("[ActionOnKill] Terminating: {}", proc.appname));
                self.handler.kill(proc.gid);
            }
        }
        Ok(())
    }
}

impl Debug for ActionsOnKill {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionsOnKill").finish()
    }
}

pub struct RevertAction {
    pub handler: Box<dyn ThreatHandler>,
}

impl ActionOnKill for RevertAction {
    fn run(
        &self,
        _config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        if threat_info.revert {
            Logging::info(&format!(
                "[ActionOnKill] Reverting registry changes for: {}",
                proc.appname
            ));
            self.handler.revert_registry(proc.gid);
        }
        Ok(())
    }
}
