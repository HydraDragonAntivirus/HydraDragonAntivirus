#![cfg(feature = "hydradragon")]

use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::PCSTR;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED, BOOL,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, 
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeA, PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, GetNamedPipeClientProcessId,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;

use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::threat_handler::ThreatHandler;
use crate::config::Config;
use crate::worker::predictor::PredictorMalware;
use chrono::Utc;
use crate::shared_def::IOMessage;
use crate::signature_verification::verify_signature;
use crate::driver_com::Driver;
use crate::utils::validate_pipe_client;

// --- Pipe names (single source of truth) ---
#[allow(dead_code)] // Silencing warning, this pipe may be used by the external AV client
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";
const PIPE_MBR_ALERT: &str = r"\\.\pipe\Global\mbr_filter_alerts";
const PIPE_SELF_DEFENSE_ALERT: &str = r"\\.\pipe\Global\self_defense_alerts";

const BUFFER_SIZE: u32 = 8192;
const PIPE_READ_BUFFER_SIZE: u32 = 65536;
#[allow(dead_code)] // Silencing warning, this is used by the (currently) unused send_threat_to_edr
const CONNECT_TIMEOUT_MS: u32 = 900_000; // 900s - adjust as needed

/// Action to take when a threat is detected
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[derive(Default)]
pub enum ThreatAction {
    #[serde(rename = "monitor")]
    Monitor,
    #[serde(rename = "kill_and_quarantine")]
    #[default]
    KillAndQuarantine,
    #[serde(rename = "kill_and_remove")]
    KillAndRemove,
    #[serde(rename = "kill")]
    Kill,
}


impl ThreatAction {
    pub fn from_raw(raw: Option<&str>) -> Self {
        match raw
            .unwrap_or("kill_and_quarantine")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "kill" => ThreatAction::Kill,
            "kill_and_remove" => ThreatAction::KillAndRemove,
            "kill_and_quarantine" => ThreatAction::KillAndQuarantine,
            _ => ThreatAction::KillAndQuarantine,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ThreatAction::Monitor => "monitor",
            ThreatAction::KillAndQuarantine => "kill_and_quarantine",
            ThreatAction::KillAndRemove => "kill_and_remove",
            ThreatAction::Kill => "kill",
        }
    }
}

/// AV -> EDR event
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVThreatEvent {
    pub timestamp: String,
    pub file_path: String,
    pub virus_name: String,
    pub is_malicious: bool,
    pub detection_type: String,
    #[serde(default)]
    pub action_required: ThreatAction,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// EDR-provided Authenticode signature status for a file.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileSignatureStatus {
    pub is_trusted: bool,
    pub is_signed: bool,
    #[serde(default)]
    pub signer_name: Option<String>,
}

/// EDR -> AV request
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EDRScanRequest {
    pub event_type: String,
    pub file_path: String,
    pub timestamp: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub additional_context: Option<String>,
    /// Optional signature status (so HydraDragon doesn't need to re-verify the same executable).
    #[serde(default)]
    pub signature_status: Option<FileSignatureStatus>,
}

/// AV scan response (sent to EDR as a threat event)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVScanResponse {
    pub file_path: String,
    pub is_malicious: bool,
    pub virus_name: Option<String>,
    pub scan_timestamp: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SelfDefenseAlert {
    #[serde(default)]
    protected_file: String,
    #[serde(default)]
    attacker_path: String,
    #[serde(default)]
    attacker_pid: u32,
    #[serde(default)]
    attack_type: String,
    #[serde(default)]
    operation: String,
    #[serde(default)]
    target_pid: u32,
}

fn normalize_path_for_compare(path: &str) -> String {
    normalize_nt_path(path).replace('/', "\\").to_ascii_lowercase()
}

fn path_is_under(prefix: &Path, candidate: &Path) -> bool {
    let p = normalize_path_for_compare(&prefix.to_string_lossy());
    let c = normalize_path_for_compare(&candidate.to_string_lossy());
    c == p || c.starts_with(&(p + "\\"))
}

fn is_protected_path(candidate_path: &str) -> bool {
    let candidate = PathBuf::from(candidate_path);

    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let pf_hda = PathBuf::from(program_files).join("HydraDragonAntivirus");
    if path_is_under(&pf_hda, &candidate) {
        return true;
    }

    if let Ok(appdata) = std::env::var("APPDATA") {
        let sanctum = PathBuf::from(appdata).join("Sanctum");
        if path_is_under(&sanctum, &candidate) {
            return true;
        }
    }

    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let desktop_sanctum = PathBuf::from(user_profile).join("Desktop").join("Sanctum");
        if path_is_under(&desktop_sanctum, &candidate) {
            return true;
        }
    }

    false
}

fn normalize_nt_path(nt_path: &str) -> String {
    if nt_path.trim().is_empty() {
        return nt_path.to_string();
    }

    let mut normalized = nt_path.trim().replace('/', "\\");

    if normalized.starts_with("\\??\\") {
        normalized = normalized.trim_start_matches("\\??\\").to_string();
    } else if normalized.starts_with("\\\\?\\") {
        normalized = normalized.trim_start_matches("\\\\?\\").to_string();
    } else if normalized.to_ascii_lowercase().starts_with("\\device\\harddiskvolume") {
        // Keep this conversion simple and deterministic, aligned with kernel rule matching.
        // If we detect a device-volume path, map it to system drive for fast comparisons.
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if let Some(rest) = normalized.splitn(4, '\\').nth(3) {
            normalized = format!("{}\\{}", system_drive, rest);
        }
    }

    normalized.trim_end_matches('\0').to_string()
}

fn decode_utf16le_message(data: &[u8]) -> String {
    let usable_len = data.len() - (data.len() % 2);
    let mut words = Vec::with_capacity(usable_len / 2);
    for chunk in data[..usable_len].chunks_exact(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

fn parse_av_threat_event(message: &str) -> Result<AVThreatEvent, String> {
    let value: serde_json::Value =
        serde_json::from_str(message).map_err(|e| format!("invalid AV event JSON: {e}"))?;

    let timestamp = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let file_path = value
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let virus_name = value
        .get("virus_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let is_malicious = value
        .get("is_malicious")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let detection_type = value
        .get("detection_type")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let action_required =
        ThreatAction::from_raw(value.get("action_required").and_then(|v| v.as_str()));
    let pid = value
        .get("pid")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    let gid = value.get("gid").and_then(|v| v.as_u64());

    Ok(AVThreatEvent {
        timestamp,
        file_path,
        virus_name,
        is_malicious,
        detection_type,
        action_required,
        pid,
        gid,
    })
}

fn resolve_gid_for_action(event: &AVThreatEvent) -> Option<u64> {
    if let Some(gid) = event.gid {
        return Some(gid);
    }
    event.pid
        .map(|pid| 0x8000_0000_0000_0000u64 | (pid as u64))
}

fn apply_fast_driver_action(event: &AVThreatEvent) {
    if !event.is_malicious {
        return;
    }

    if matches!(event.action_required, ThreatAction::Monitor) {
        return;
    }

    let gid = match resolve_gid_for_action(event) {
        Some(g) => g,
        None => {
            Logging::warning(&format!(
                "[AV->EDR] Threat event has no gid/pid for action '{}': {}",
                event.action_required.as_str(),
                event.file_path
            ));
            return;
        }
    };

    let driver = match Driver::open_kernel_driver_com() {
        Ok(d) => d,
        Err(e) => {
            Logging::error(&format!(
                "[AV->EDR] Failed to open driver for threat action '{}': {}",
                event.action_required.as_str(),
                e
            ));
            return;
        }
    };

    let file_path = Path::new(&event.file_path);
    let action_result = match event.action_required {
        ThreatAction::Kill => driver.try_kill(gid),
        ThreatAction::KillAndQuarantine => driver.kill_and_quarantine_driver(gid, file_path),
        ThreatAction::KillAndRemove => driver.kill_and_remove_driver(gid, file_path),
        ThreatAction::Monitor => return,
    };

    match action_result {
        Ok(hr) => Logging::info(&format!(
            "[AV->EDR] Applied threat action '{}' for gid={} path={} hr=0x{:08X}",
            event.action_required.as_str(),
            gid,
            event.file_path,
            hr.0 as u32
        )),
        Err(e) => Logging::error(&format!(
            "[AV->EDR] Threat action '{}' failed for gid={} path={}: {}",
            event.action_required.as_str(),
            gid,
            event.file_path,
            e
        )),
    }
}

/// Helper to validate pipe client PID or executable path.

fn spawn_av_to_edr_listener() -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        let pipe_name_c = match CString::new(PIPE_AV_TO_EDR) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("[AV->EDR] Invalid pipe name: {}", e));
                return;
            }
        };

        Logging::info(&format!("[AV->EDR] Listener started on {}", PIPE_AV_TO_EDR));
        loop {
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_READ_BUFFER_SIZE,
                PIPE_READ_BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("[AV->EDR] CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                Logging::error(&format!(
                    "[AV->EDR] CreateNamedPipeA returned invalid handle: {:?}",
                    GetLastError()
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let connect_err = GetLastError();
            if connect_ok.as_bool() || connect_err == ERROR_PIPE_CONNECTED {
                // Validation: Only allow Python 3.12 path
                if !validate_pipe_client(pipe_handle, Some(r"python312\python.exe"), false) {
                    Logging::error("[AV->EDR] Rejected unauthorized client connection");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
                Logging::info("[AV->EDR] Authorized Python 3.12 client connected");

                let mut buffer = vec![0u8; PIPE_READ_BUFFER_SIZE as usize];
                let mut bytes_read = 0u32;
                let read_ok = ReadFile(
                    pipe_handle,
                    Some(buffer.as_mut_ptr().cast()),
                    PIPE_READ_BUFFER_SIZE,
                    Some(&mut bytes_read as *mut u32),
                    None,
                );

                if read_ok.as_bool() && bytes_read > 0 {
                    let message =
                        String::from_utf8_lossy(&buffer[..bytes_read as usize]).trim().to_string();
                    match parse_av_threat_event(&message) {
                        Ok(mut event) => {
                            event.file_path = normalize_nt_path(&event.file_path);
                            if !event.file_path.is_empty() && is_protected_path(&event.file_path) {
                                Logging::debug(&format!(
                                    "[AV->EDR] Ignoring protected-path threat event: {}",
                                    event.file_path
                                ));
                            } else {
                                Logging::info(&format!(
                                    "[AV->EDR] Threat event path={} malware={} action={} malicious={}",
                                    event.file_path,
                                    event.virus_name,
                                    event.action_required.as_str(),
                                    event.is_malicious
                                ));
                                apply_fast_driver_action(&event);
                            }
                        }
                        Err(e) => Logging::error(&format!(
                            "[AV->EDR] Failed to parse event JSON: {} | raw={}",
                            e, message
                        )),
                    }
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    })
}

fn spawn_mbr_alert_listener() -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        let pipe_name_c = match CString::new(PIPE_MBR_ALERT) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("[MBR] Invalid pipe name: {}", e));
                return;
            }
        };

        Logging::info(&format!("[MBR] Listener started on {}", PIPE_MBR_ALERT));
        loop {
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_READ_BUFFER_SIZE,
                PIPE_READ_BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("[MBR] CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                Logging::error(&format!(
                    "[MBR] CreateNamedPipeA returned invalid handle: {:?}",
                    GetLastError()
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let connect_err = GetLastError();
            if connect_ok.as_bool() || connect_err == ERROR_PIPE_CONNECTED {
                // Validation: Only allow PID 4 (Kernel/System)
                if !validate_pipe_client(pipe_handle, None, true) {
                    Logging::error("[MBR] Rejected unauthorized client connection");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
                Logging::info("[MBR] Authorized client (Kernel) connected");

                let mut buffer = vec![0u8; PIPE_READ_BUFFER_SIZE as usize];
                let mut bytes_read = 0u32;
                let read_ok = ReadFile(
                    pipe_handle,
                    Some(buffer.as_mut_ptr().cast()),
                    PIPE_READ_BUFFER_SIZE,
                    Some(&mut bytes_read as *mut u32),
                    None,
                );

                if read_ok.as_bool() && bytes_read > 0 {
                    let raw = decode_utf16le_message(&buffer[..bytes_read as usize]);
                    let normalized = normalize_nt_path(&raw);
                    Logging::error(&format!(
                        "[MBR ALERT] Offending process path: {}",
                        normalized
                    ));
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    })
}

fn spawn_self_defense_listener() -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        let pipe_name_c = match CString::new(PIPE_SELF_DEFENSE_ALERT) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("[SelfDefense] Invalid pipe name: {}", e));
                return;
            }
        };

        Logging::info(&format!(
            "[SelfDefense] Listener started on {}",
            PIPE_SELF_DEFENSE_ALERT
        ));
        loop {
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_READ_BUFFER_SIZE,
                PIPE_READ_BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("[SelfDefense] CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                Logging::error(&format!(
                    "[SelfDefense] CreateNamedPipeA returned invalid handle: {:?}",
                    GetLastError()
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let connect_err = GetLastError();
            if connect_ok.as_bool() || connect_err == ERROR_PIPE_CONNECTED {
                // Validation: Only allow PID 4 (Kernel/System)
                if !validate_pipe_client(pipe_handle, None, true) {
                    Logging::error("[SelfDefense] Rejected unauthorized client connection");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
                Logging::info("[SelfDefense] Authorized client (Kernel) connected");

                let mut buffer = vec![0u8; PIPE_READ_BUFFER_SIZE as usize];
                let mut bytes_read = 0u32;
                let read_ok = ReadFile(
                    pipe_handle,
                    Some(buffer.as_mut_ptr().cast()),
                    PIPE_READ_BUFFER_SIZE,
                    Some(&mut bytes_read as *mut u32),
                    None,
                );

                if read_ok.as_bool() && bytes_read > 0 {
                    let raw_message = decode_utf16le_message(&buffer[..bytes_read as usize]);
                    let parsed = serde_json::from_str::<SelfDefenseAlert>(&raw_message).or_else(|_| {
                        let escaped = raw_message.replace('\\', "\\\\");
                        serde_json::from_str::<SelfDefenseAlert>(&escaped)
                    });

                    match parsed {
                        Ok(mut alert) => {
                            alert.protected_file = normalize_nt_path(&alert.protected_file);
                            alert.attacker_path = normalize_nt_path(&alert.attacker_path);
                            Logging::warning(&format!(
                                "[SELF-DEFENSE] attack_type={} attacker_pid={} target_pid={} operation={} attacker_path={} protected={}",
                                alert.attack_type,
                                alert.attacker_pid,
                                alert.target_pid,
                                alert.operation,
                                alert.attacker_path,
                                alert.protected_file
                            ));
                        }
                        Err(e) => Logging::error(&format!(
                            "[SelfDefense] Failed to parse alert JSON: {} | raw={}",
                            e, raw_message
                        )),
                    }
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    })
}

/// Integration struct — keeps internal channel & listener thread
pub struct AVIntegration<'a> {
    config: &'a Config, // <-- MODIFIED: Now a borrow
    predictor_malware: PredictorMalware<'a>,
    internal_scan_tx: Sender<EDRScanRequest>,
    signature_cache: HashMap<String, FileSignatureStatus>,
    _scan_request_handle: thread::JoinHandle<()>,
    _av_to_edr_listener_handle: thread::JoinHandle<()>,
}

impl<'a> AVIntegration<'a> {
    /// Create new AVIntegration instance
    pub fn new(config: &'a Config, predictor_malware: PredictorMalware<'a>) -> Self { // <-- MODIFIED: Takes a borrow
        let (internal_scan_tx, internal_scan_rx) = channel::<EDRScanRequest>();
        
        let scan_request_handle = thread::spawn(move || {
            scan_request_server_loop(internal_scan_rx);
        });
        let av_to_edr_listener_handle = spawn_av_to_edr_listener();
        let _mbr_listener_handle = spawn_mbr_alert_listener();
        let _self_defense_listener_handle = spawn_self_defense_listener();

        AVIntegration {
            config, // <-- MODIFIED: Assigns the borrow
            predictor_malware,
            internal_scan_tx,
            signature_cache: HashMap::new(),
            _scan_request_handle: scan_request_handle,
            _av_to_edr_listener_handle: av_to_edr_listener_handle,
        }
    }

    /// Process a single threat event according to its configured action
    pub fn process_threat_action(
        &self,
        event: &AVThreatEvent,
        precord: &ProcessRecord,
        prediction_behavioral: f32,
        threat_handler: &dyn ThreatHandler,
    ) {
        // Determine threat label
        let threat_label = if event.detection_type.to_lowercase().contains("pua")
            || event.virus_name.to_lowercase().contains("pua")
        {
            "Potentially Unwanted Application"
        } else if event.detection_type.to_lowercase().contains("ransom")
            || event.virus_name.to_lowercase().contains("ransom")
        {
            "Ransomware"
        } else {
            "Malware"
        };

        let threat_info = ThreatInfo {
            threat_type_label: threat_label,
            virus_name: if event.virus_name.is_empty() {
                &event.detection_type
            } else {
                &event.virus_name
            },
            prediction: prediction_behavioral,
            match_details: None,
            terminate: true,
            quarantine: event.action_required == ThreatAction::KillAndQuarantine,
            kill_and_remove: event.action_required == ThreatAction::KillAndRemove,
            notify_user: true,
            revert: false, // AV integration doesn't trigger automatic reversion
        };

        match event.action_required {
            ThreatAction::Monitor => {
                Logging::info(&format!(
                    "Threat event [{}] - Action: MONITOR - Path: {}",
                    event.virus_name, event.file_path
                ));
            }
            ThreatAction::Kill => {
                Logging::info(&format!(
                    "Threat detected [{}] - Action: KILL - Path: {}",
                    event.virus_name, event.file_path
                ));
                Logging::info(&format!(
                    "   Type: {} | Certainty: {:.2}% | GID: {}",
                    threat_label, prediction_behavioral * 100.0, precord.gid
                ));
            }
            ThreatAction::KillAndQuarantine => {
                Logging::info(&format!(
                    "Threat detected [{}] - Action: KILL AND QUARANTINE - Path: {}",
                    event.virus_name, event.file_path
                ));
                Logging::info(&format!(
                    "   Type: {} | Certainty: {:.2}% | GID: {}",
                    threat_label, prediction_behavioral * 100.0, precord.gid
                ));
            }
            ThreatAction::KillAndRemove => {
                Logging::info(&format!(
                    "Threat detected [{}] - Action: KILL AND REMOVE - Path: {}",
                    event.virus_name, event.file_path
                ));
                Logging::info(&format!(
                    "   Type: {} | Certainty: {:.2}% | GID: {}",
                    threat_label, prediction_behavioral * 100.0, precord.gid
                ));
            }
        }

        ActionsOnKill::with_handler(threat_handler.clone_box()).run_actions_with_info(
            self.config, // config is a borrow, this works
            precord,
            &self.predictor_malware.predictor_behavioral.mlp.timesteps,
            &threat_info,
        );
    }
    /// Main loop to handle queued threat events
    pub fn handle_event_loop(&self) {
        loop {
            // Placeholder: integrate event queue or pipe-based event reading later
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    /// Called by kernel/event handling to queue internal requests (no external client)
    pub fn queue_file_event(&mut self, iomsg: &IOMessage, precord: &ProcessRecord) {
        let file_path = precord.exepath.to_string_lossy().to_string();
        let signature_status = self.get_or_compute_signature_status(&file_path, &precord.exepath);

        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path,
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
            signature_status,
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send internal scan request: {}", e));
        }
    }

    fn get_or_compute_signature_status(
        &mut self,
        cache_key: &str,
        path: &std::path::Path,
    ) -> Option<FileSignatureStatus> {
        if let Some(existing) = self.signature_cache.get(cache_key) {
            return Some(existing.clone());
        }

        if !path.exists() {
            return None;
        }

        let info = verify_signature(path);
        let status = FileSignatureStatus {
            is_trusted: info.is_trusted,
            is_signed: info.is_signed,
            signer_name: info.signer_name,
        };

        self.signature_cache
            .insert(cache_key.to_string(), status.clone());
        Some(status)
    }
}

/// AV -> EDR client (one-shot): connect to AV->EDR pipe and write threat event
#[allow(dead_code)] // Silencing warning, this function is likely called by the external AV component
fn send_threat_to_edr(event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        let pipe_name_c =
            CString::new(PIPE_AV_TO_EDR).map_err(|e| format!("Invalid pipe name: {}", e))?;
        let pcstr = PCSTR(pipe_name_c.as_ptr() as *const u8);

        // Wait for the pipe to become available
        let wait_ok: BOOL = WaitNamedPipeA(pcstr, CONNECT_TIMEOUT_MS);
        if !wait_ok.as_bool() {
            let err = GetLastError();
            Logging::error(&format!(
                "Timed out waiting for EDR pipe '{}' ({} ms). GetLastError={:?}",
                PIPE_AV_TO_EDR, CONNECT_TIMEOUT_MS, err
            ));
            return Err(format!(
                "Timed out waiting for EDR pipe '{}' ({} ms). GetLastError={:?}",
                PIPE_AV_TO_EDR, CONNECT_TIMEOUT_MS, err
            ));
        }

        // Connect to the pipe
        let pipe_handle = match CreateFileA(
            pcstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(h) => h,
            Err(e) => {
                let last = GetLastError();
                Logging::error(&format!(
                    "Failed to connect to EDR pipe (CreateFileA error: {:?}, GetLastError={:?})",
                    e, last
                ));
                return Err(format!(
                    "Failed to connect to EDR pipe (CreateFileA error: {:?}, GetLastError={:?})",
                    e, last
                ));
            }
        };

        if pipe_handle.is_invalid() {
            let last = GetLastError();
            Logging::error(&format!(
                "CreateFileA returned invalid handle. GetLastError={:?}",
                last
            ));
            return Err(format!("CreateFileA returned invalid handle: {:?}", last));
        }

        // Serialize and write
        let message = serde_json::to_string(&event).map_err(|e| {
            Logging::error(&format!("serialize error: {}", e));
            format!("serialize error: {}", e)
        })?;
        let message_bytes: &[u8] = message.as_bytes();

        let mut bytes_written: u32 = 0;
        let ok: BOOL = WriteFile(
            pipe_handle,
            Some(message_bytes),
            Some(&mut bytes_written as *mut u32),
            None,
        );

        let _ = FlushFileBuffers(pipe_handle);
        let _ = CloseHandle(pipe_handle);

        if !ok.as_bool() {
            Logging::error("Failed to write to EDR pipe (WriteFile returned false)");
            return Err("Failed to write to EDR pipe".to_string());
        }

        Logging::info(&format!(
            "Successfully sent threat event to EDR: {} - {} [{}] ({} bytes)",
            event.file_path, event.virus_name, event.action_required.as_str(), bytes_written
        ));
        Ok(())
    }
}

fn write_scan_request(pipe_handle: HANDLE, request: &EDRScanRequest) -> Result<u32, String> {
    let message = serde_json::to_string(request).map_err(|e| {
        Logging::error(&format!("serialize error: {}", e));
        format!("serialize error: {}", e)
    })?;
    let message_bytes: &[u8] = message.as_bytes();

    unsafe {
        let mut bytes_written: u32 = 0;
        let ok: BOOL = WriteFile(
            pipe_handle,
            Some(message_bytes),
            Some(&mut bytes_written as *mut u32),
            None,
        );

        let _ = FlushFileBuffers(pipe_handle);

        if !ok.as_bool() {
            return Err("Failed to write to HydraDragon pipe".to_string());
        }

        Ok(bytes_written)
    }
}

/// EDR server: persistent sender for EDR -> AV scan requests.
///
/// Sends one JSON message per connection; the HydraDragon client is expected to reconnect
/// for subsequent messages.
fn scan_request_server_loop(rx: Receiver<EDRScanRequest>) {
    Logging::info(&format!("Starting pipe server (EDR->AV): {}", PIPE_EDR_TO_AV));

    unsafe {
        let pipe_name_c = match CString::new(PIPE_EDR_TO_AV) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("Invalid pipe name: {}", e));
                return;
            }
        };

        loop {
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                let err = GetLastError();
                Logging::error(&format!("CreateNamedPipeA returned invalid handle: {:?}", err));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            Logging::debug("Waiting for HydraDragon client to connect...");

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let err = GetLastError();

            if connect_ok.as_bool() || err == ERROR_PIPE_CONNECTED {
                // Validation: Only allow Python 3.12 path
                if !validate_pipe_client(pipe_handle, Some(r"python312\python.exe"), false) {
                    Logging::error("[EDR->AV] Rejected unauthorized scan request client");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
                
                Logging::info("PIPE: EDR scan request client (Python) connected");

                let request = match rx.recv() {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = CloseHandle(pipe_handle);
                        return;
                    }
                };

                match write_scan_request(pipe_handle, &request) {
                    Ok(bytes_written) => Logging::debug(&format!(
                        "Sent scan request: {} ({} bytes)",
                        request.file_path, bytes_written
                    )),
                    Err(e) => Logging::error(&format!("Failed to send scan request: {}", e)),
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            } else {
                Logging::error(&format!("ConnectNamedPipe failed: {:?}", err));
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    }
}

