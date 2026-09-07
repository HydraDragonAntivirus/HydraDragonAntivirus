use crate::threat_handler::{QuarantineMetadata, ThreatHandler};
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Local};
use log::warn;

use crate::config::Config;
use crate::connectors::register::Connectors;
use crate::logging::Logging;

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
    pub kill_and_remove: bool,
    pub suspend: bool,
    pub notify_user: bool,
    pub revert: bool,
    /// True while an `ask_user` rule is still waiting for the operator's answer.
    ///
    /// The interim enforcement is still reported â€” `deny_while_ask` really did
    /// deny access, so operators need to see it â€” but the response is labelled
    /// by what was actually enforced ("Access denied") instead of by the
    /// internal prompt state. Set explicitly rather than sniffed from
    /// `match_details`, whose wording differs per code path.
    pub pending_user_decision: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ActionReportContext {}

pub const RESTART_CLEANUP_PREDICTION_THRESHOLD: f32 = 0.999;

impl ThreatInfo<'_> {
    fn is_pending_user_decision(&self) -> bool {
        if self.pending_user_decision {
            return true;
        }

        let details = self
            .match_details
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        details.contains("pending user decision")
    }

    fn should_notify(&self) -> bool {
        // A prompt that is still pending has enforced something concrete
        // (deny/suspend while asking), so it is reported like any other
        // response. Only firewall detections that are *purely* waiting on the
        // user â€” no enforcement at all â€” stay silent.
        if self.is_pending_user_decision() && !self.has_enforced_response() {
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

    /// True when the response actually enforced something against the process,
    /// as opposed to only recording or notifying.
    fn has_enforced_response(&self) -> bool {
        self.deny_access
            || self.suspend
            || self.terminate
            || self.quarantine
            || self.kill_and_remove
            || self.revert
    }

    /// Label describing what was enforced. Never leaks internal prompt state:
    /// a pending `deny_while_ask` rule reports "Access denied", because that is
    /// what the process actually experienced.
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

    /// Threat label used in reports and alerts.
    ///
    /// While a prompt is pending, the caller-supplied label is an internal
    /// state name ("HIPS Pending") that means nothing to an operator. Report
    /// the enforced action instead.
    fn display_threat_type_label(&self) -> &str {
        if self.is_pending_user_decision() && self.has_enforced_response() {
            if self.deny_access {
                return "Access Denied";
            }
            if self.suspend {
                return "Suspended";
            }
        }

        self.threat_type_label
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

    push_unique(threat_info.display_threat_type_label());
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

const SHADOW_COPY_RESTORE_CANDIDATE_LIMIT: usize = 512;

fn has_active_threat_response(threat_info: &ThreatInfo<'_>) -> bool {
    threat_info.deny_access
        || threat_info.terminate
        || threat_info.quarantine
        || threat_info.kill_and_remove
        || threat_info.suspend
        || threat_info.revert
}

fn destructive_file_threat(proc: &ProcessRecord, threat_info: &ThreatInfo<'_>) -> bool {
    let mut haystack = format!(
        "{} {} {}",
        threat_info.threat_type_label,
        threat_info.virus_name,
        threat_info.match_details.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();

    if let Some(rule_name) = proc.triggered_rule_name.as_deref() {
        haystack.push(' ');
        haystack.push_str(&rule_name.to_ascii_lowercase());
    }
    if let Some(rule_details) = proc.triggered_rule_details.as_deref() {
        haystack.push(' ');
        haystack.push_str(&rule_details.to_ascii_lowercase());
    }

    [
        "ransomware",
        "ransom",
        "wiper",
        "encryptor",
        "encrypt",
        "destructive",
        "data destruction",
        "impact-stage",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

fn should_attempt_shadow_copy_restore(proc: &ProcessRecord, threat_info: &ThreatInfo<'_>) -> bool {
    !proc.fpaths_updated.is_empty()
        && has_active_threat_response(threat_info)
        && (threat_info.revert
            || destructive_file_threat(proc, threat_info)
            || proc.is_malicious
            || threat_info.prediction >= 0.98)
}

fn normalize_shadow_restore_candidate(path: &str) -> Option<PathBuf> {
    let mut normalized = path.trim_matches(char::from(0)).trim().replace('/', "\\");

    for prefix in ["\\\\?\\", "\\??\\"] {
        if let Some(stripped) = normalized.strip_prefix(prefix) {
            normalized = stripped.to_string();
        }
    }

    if !is_drive_absolute_path(&normalized) {
        return None;
    }

    let candidate = PathBuf::from(normalized);
    if candidate.file_name().is_none() {
        return None;
    }

    Some(candidate)
}

fn is_drive_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn is_process_remediation_path(proc: &ProcessRecord, path: &Path) -> bool {
    let candidate = normalized_path_key(path);

    if !proc.exepath.as_os_str().is_empty()
        && candidate == normalized_path_key(proc.exepath.as_path())
    {
        return true;
    }

    let remediation_path = proc.primary_remediation_path();
    !remediation_path.as_os_str().is_empty() && candidate == normalized_path_key(remediation_path)
}

fn shadow_copy_restore_candidates(proc: &ProcessRecord) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut candidates = Vec::new();

    let mut updated_paths = proc.fpaths_updated.iter().collect::<Vec<_>>();
    updated_paths.sort();

    for raw_path in updated_paths {
        let Some(candidate) = normalize_shadow_restore_candidate(raw_path) else {
            continue;
        };
        if is_process_remediation_path(proc, &candidate) {
            continue;
        }

        let key = normalized_path_key(&candidate);
        if seen.insert(key) {
            candidates.push(candidate);
        }

        if candidates.len() == SHADOW_COPY_RESTORE_CANDIDATE_LIMIT {
            Logging::warning(&format!(
                "[ActionOnKill] Shadow-copy restore candidate list reached the {} file limit for {} (GID: {})",
                SHADOW_COPY_RESTORE_CANDIDATE_LIMIT, proc.appname, proc.gid
            ));
            break;
        }
    }

    candidates
}

impl ActionsOnKill {
    pub fn new() -> ActionsOnKill {
        ActionsOnKill {
            actions: vec![
                Box::new(WriteReportFile()),
                Box::new(Connectors),
                Box::new(Logging),
                Box::new(WriteOpenEdrEventLog()),
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
                Box::new(Connectors),
                Box::new(Logging),
                Box::new(WriteOpenEdrEventLog()),
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
        config: &Config,
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
            .and_then(|name| name.to_str())
            .unwrap_or("unknown");
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
            format!(
                "{} detected running from: {}\n\n",
                threat_info.display_threat_type_label(),
                display_process
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

        let msg = format!(
            "{} detected running from: {} with certainty {} (detection: {}) (response: {})",
            threat_info.display_threat_type_label(),
            display_process,
            threat_info.prediction,
            threat_info.virus_name,
            threat_info.response_label_for(proc)
        );
        let _ = crate::notifications::notify(config, &msg, report_path);
        Ok(())
    }
}

pub struct WriteOpenEdrEventLog();

impl ActionOnKill for WriteOpenEdrEventLog {
    fn run(
        &self,
        _config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        if !threat_info.should_notify() {
            return Ok(());
        }

        // Determine output directory: place in same output_events folder OpenEDR uses.
        let log_path_val = crate::config::ConfigReader::read_param_from_registry(
            "LOG_PATH",
            r"SOFTWARE\Owlyshield",
        );
        let log_dir = if !log_path_val.trim().is_empty() {
            PathBuf::from(log_path_val)
        } else if let Some(program_data) = std::env::var_os("ProgramData") {
            PathBuf::from(program_data).join("edrsvc").join("log")
        } else {
            std::env::temp_dir().join("owlyshield")
        };

        // Go up one level from 'owlyshield' subdirectory to get the main 'log' folder if needed
        let mut base_log_dir = log_dir.clone();
        if base_log_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map_or(false, |s| s.eq_ignore_ascii_case("owlyshield"))
        {
            base_log_dir.pop();
        }

        let output_events_dir = base_log_dir.join("output_events");
        std::fs::create_dir_all(&output_events_dir)?;

        // Daily file name: owlyshield_YYYYMMDD.log
        let today = chrono::Local::now().format("%Y%m%d").to_string();
        let log_file_path = output_events_dir.join(format!("owlyshield_{}.log", today));

        // Create the JSON event matching OpenEDR format
        let event_time_iso =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let event = serde_json::json!({
            "customerId": crate::config::ConfigReader::read_param_from_registry("CUSTOMER_ID", r"SOFTWARE\Owlyshield"),
            "endpointId": crate::config::ConfigReader::read_param_from_registry("ENDPOINT_ID", r"SOFTWARE\Owlyshield"),
            "eventGroup": "THREAT",
            "eventType": "BEHAVIORAL_ALERT",
            "eventTime": event_time_iso,
            "status": "ALERT",
            "threat": {
                "type": threat_info.display_threat_type_label(),
                "name": threat_info.virus_name,
                "certainty": threat_info.prediction,
                "matchDetails": threat_info.match_details,
                "response": threat_info.response_label_for(proc),
                "remediation": proc.primary_remediation_path().to_string_lossy()
            },
            "process": {
                "processId": proc.pids.iter().next().copied().unwrap_or(0),
                "processPath": proc.exepath.to_string_lossy(),
                "processName": proc.appname,
                "processGroupId": proc.gid
            },
            "filesModified": proc.fpaths_updated.iter().collect::<Vec<&String>>()
        });

        // Open file in append mode
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;

        let json_line = serde_json::to_string(&event)?;
        writeln!(file, "{}", json_line)?;

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
            threat_info.display_threat_type_label(),
            display_process,
            proc.gid,
            threat_info.prediction,
            threat_info.virus_name,
            response_label,
            threat_info.match_details.as_deref().unwrap_or("None"),
            stime_started.format(LONG_TIME_FORMAT)
        );
        Logging::alert(msg.as_str());

        // Send real-time threat alert popup notification to the firewall GUI
        notify_firewall_threat_alert(threat_info.virus_name, &display_process);

        warn!("ALERT: {}", msg);
        Ok(())
    }
}

pub fn notify_firewall_threat_alert(threat_name: &str, file_path: &str) {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{BOOL, CloseHandle, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
            FlushFileBuffers, OPEN_EXISTING, WriteFile,
        };
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        use windows::core::PCWSTR;

        const PIPE: &str = r"\\.\pipe\HydraHipEvent";
        let mut pipe_name_wide: Vec<u16> = PIPE.encode_utf16().collect();
        pipe_name_wide.push(0);
        let pcwstr = PCWSTR(pipe_name_wide.as_ptr());
        let message = format!("THREAT_ALERT:{}|{}\n", threat_name, file_path);
        let message_bytes = message.as_bytes();

        let wait_ok: BOOL = unsafe { WaitNamedPipeW(pcwstr, 150) };
        if wait_ok.as_bool() {
            if let Ok(handle) = unsafe {
                CreateFileW(
                    pcwstr,
                    FILE_GENERIC_WRITE.0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    HANDLE::default(),
                )
            } {
                if !handle.is_invalid() {
                    let mut written: u32 = 0;
                    unsafe {
                        let _ = WriteFile(
                            handle,
                            Some(message_bytes),
                            Some(&mut written as *mut u32),
                            None,
                        );
                        let _ = FlushFileBuffers(handle);
                        let _ = CloseHandle(handle);
                    }
                }
            }
        }
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
        _config: &Config,
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

            Logging::alert(&format!(
                "[ActionOnKill] Malware cleanup for {} was queued for the next restart.",
                proc.appname
            ));
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
        } else if threat_info.quarantine {
            // Quarantine without termination (e.g. `action: traffic_attack`
            // network rules): the offending artifact still has to be sealed.
            let remediation_path = proc.primary_remediation_path();
            if remediation_path.as_os_str().is_empty() {
                Logging::warning(&format!(
                    "[ActionOnKill] Cannot quarantine {} (GID: {}) because no remediation path is known",
                    proc.appname, proc.gid
                ));
            } else {
                Logging::info(&format!(
                    "[ActionOnKill] Quarantining without termination: {}",
                    remediation_path.display()
                ));
                let quarantine_metadata = QuarantineMetadata {
                    detection: quarantine_detection_label(proc, threat_info),
                };
                self.handler
                    .quarantine_only(remediation_path, &quarantine_metadata);
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
        config: &Config,
        proc: &mut ProcessRecord,
        _pred_mtrx: &VecvecCappedF32,
        threat_info: &ThreatInfo,
        _report_context: &ActionReportContext,
        _now: &str,
    ) -> Result<(), Box<dyn Error>> {
        let should_revert = threat_info.revert || config.always_auto_revert();
        if should_revert {
            if let Some(reason) = crate::utils::protected_process_record_reason(proc) {
                Logging::warning(&format!(
                    "[ActionOnKill] Registry revert blocked for protected process: {} ({})",
                    proc.appname, reason
                ));
            } else {
                Logging::info(&format!(
                    "[ActionOnKill] Reverting registry changes for: {}",
                    proc.appname
                ));
                self.handler.revert_registry(proc.gid);
            }
        }

        if should_attempt_shadow_copy_restore(proc, threat_info) {
            let restore_candidates = shadow_copy_restore_candidates(proc);
            if restore_candidates.is_empty() {
                Logging::info(&format!(
                    "[ActionOnKill] Shadow-copy restore skipped for {} (GID: {}) because no restorable file paths were recorded",
                    proc.appname, proc.gid
                ));
            } else {
                Logging::alert(&format!(
                    "[ActionOnKill] Attempting shadow-copy restore for {} changed file(s) after malware detection: {} (GID: {})",
                    restore_candidates.len(),
                    proc.appname,
                    proc.gid
                ));
                self.handler
                    .restore_files_from_shadow_copy(&restore_candidates);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_handler::QuarantineMetadata;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingThreatHandler {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingThreatHandler {
        fn push(&self, call: &str) {
            self.calls.lock().unwrap().push(call.to_string());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ThreatHandler for RecordingThreatHandler {
        fn suspend(&self, _proc: &mut ProcessRecord) {
            self.push("suspend");
        }

        fn kill(&self, _gid: u64) {
            self.push("kill");
        }

        fn deny_path_access(&self, _path: &Path) {
            self.push("deny_path_access");
        }

        fn kill_and_quarantine(&self, _gid: u64, _path: &Path, _metadata: &QuarantineMetadata) {
            self.push("kill_and_quarantine");
        }

        fn quarantine_only(&self, path: &Path, _metadata: &QuarantineMetadata) {
            self.push(&format!("quarantine_only:{}", path.display()));
        }

        fn kill_and_remove(&self, _gid: u64, _path: &Path) {
            self.push("kill_and_remove");
        }

        fn schedule_cleanup_on_reboot(&self, _path: &Path) {
            self.push("schedule_cleanup_on_reboot");
        }

        fn awake(&self, _proc: &mut ProcessRecord, _kill_proc_on_exit: bool) {
            self.push("awake");
        }

        fn revert_registry(&self, _gid: u64) {
            self.push("revert_registry");
        }

        fn restore_files_from_shadow_copy(&self, _paths: &[PathBuf]) {
            self.push("restore_files_from_shadow_copy");
        }

        fn clone_box(&self) -> Box<dyn ThreatHandler> {
            Box::new(self.clone())
        }
    }

    fn traffic_attack_threat_info() -> ThreatInfo<'static> {
        ThreatInfo {
            threat_type_label: "Network Attack",
            virus_name: "Traffic attack rule [ET SHELLCODE] matched",
            prediction: 1.0,
            match_details: Some("1.2.3.4:80 â€” Traffic attack rule matched".to_string()),
            deny_access: false,
            terminate: false,
            quarantine: true,
            kill_and_remove: false,
            suspend: false,
            notify_user: true,
            revert: false,
            pending_user_decision: false,
        }
    }

    fn pending_deny_threat_info() -> ThreatInfo<'static> {
        ThreatInfo {
            threat_type_label: "Access Denied",
            virus_name: "HEUR:Win.Hijacking.BootConfigTampering.gen",
            prediction: 1.0,
            match_details: Some(
                "Access denied while awaiting user decision for rule 'HEUR:Win.Hijacking.BootConfigTampering.gen'"
                    .to_string(),
            ),
            deny_access: true,
            terminate: false,
            quarantine: false,
            kill_and_remove: false,
            suspend: false,
            notify_user: true,
            revert: false,
            pending_user_decision: true,
        }
    }

    fn test_process_record() -> ProcessRecord {
        ProcessRecord::new(
            1,
            "attacker.exe".to_string(),
            PathBuf::from(r"C:\tmp\attacker.exe"),
        )
    }

    #[test]
    fn quarantine_without_terminate_seals_the_artifact() {
        let handler = RecordingThreatHandler::default();
        let action = KillAction {
            handler: handler.clone_box(),
        };

        let mut proc = test_process_record();
        action
            .run(
                &Config::new(),
                &mut proc,
                &VecvecCappedF32::new(0, 0),
                &traffic_attack_threat_info(),
                &ActionReportContext::default(),
                "now",
            )
            .unwrap();

        assert_eq!(
            handler.calls(),
            vec![format!(r"quarantine_only:C:\tmp\attacker.exe")]
        );
    }

    #[test]
    fn quarantine_with_terminate_still_kills_first() {
        let handler = RecordingThreatHandler::default();
        let action = KillAction {
            handler: handler.clone_box(),
        };

        let mut threat_info = traffic_attack_threat_info();
        threat_info.terminate = true;

        let mut proc = test_process_record();
        action
            .run(
                &Config::new(),
                &mut proc,
                &VecvecCappedF32::new(0, 0),
                &threat_info,
                &ActionReportContext::default(),
                "now",
            )
            .unwrap();

        assert_eq!(handler.calls(), vec!["kill_and_quarantine".to_string()]);
    }

    #[test]
    fn no_quarantine_and_no_terminate_does_nothing() {
        let handler = RecordingThreatHandler::default();
        let action = KillAction {
            handler: handler.clone_box(),
        };

        let mut threat_info = traffic_attack_threat_info();
        threat_info.quarantine = false;

        let mut proc = test_process_record();
        action
            .run(
                &Config::new(),
                &mut proc,
                &VecvecCappedF32::new(0, 0),
                &threat_info,
                &ActionReportContext::default(),
                "now",
            )
            .unwrap();

        assert!(handler.calls().is_empty());
    }

    #[test]
    fn pending_deny_is_reported_as_access_denied() {
        let threat_info = pending_deny_threat_info();
        let proc = test_process_record();

        // The interim deny is real enforcement, so it must be reported.
        assert!(threat_info.should_notify());
        // Neither the label nor the response leaks the internal prompt state.
        assert_eq!(threat_info.display_threat_type_label(), "Access Denied");
        assert_eq!(threat_info.response_label_for(&proc), "Access denied");
    }

    #[test]
    fn pending_without_enforcement_stays_silent() {
        let mut threat_info = pending_deny_threat_info();
        threat_info.deny_access = false;
        threat_info.notify_user = false;

        assert!(!threat_info.should_notify());
    }

    #[test]
    fn pending_suspend_is_reported_as_suspended() {
        let mut threat_info = pending_deny_threat_info();
        threat_info.deny_access = false;
        threat_info.suspend = true;

        assert!(threat_info.should_notify());
        assert_eq!(threat_info.display_threat_type_label(), "Suspended");
    }
}
