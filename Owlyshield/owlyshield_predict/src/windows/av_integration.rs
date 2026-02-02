#![cfg(feature = "hydradragon")]

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::PCSTR;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED, BOOL,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, WriteFile, FILE_ATTRIBUTE_NORMAL, 
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeA, PIPE_READMODE_BYTE, 
};

use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::threat_handler::ThreatHandler;
use crate::config::Config;
use crate::worker::predictor::PredictorMalware;
use chrono::Utc;
use crate::shared_def::IOMessage;
use crate::signature_verification::verify_signature;

// --- Pipe names (single source of truth) ---
#[allow(dead_code)] // Silencing warning, this pipe may be used by the external AV client
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";

const BUFFER_SIZE: u32 = 8192;
#[allow(dead_code)] // Silencing warning, this is used by the (currently) unused send_threat_to_edr
const CONNECT_TIMEOUT_MS: u32 = 900_000; // 900s - adjust as needed

/// Action to take when a threat is detected
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum ThreatAction {
    #[serde(rename = "kill_and_quarantine")]
    KillAndQuarantine,
    #[serde(rename = "kill")]
    Kill,
}

impl Default for ThreatAction {
    fn default() -> Self {
        ThreatAction::KillAndQuarantine
    }
}

impl ThreatAction {
    pub fn as_str(&self) -> &str {
        match self {
            ThreatAction::KillAndQuarantine => "kill_and_quarantine",
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

/// Integration struct — keeps internal channel & listener thread
pub struct AVIntegration<'a> {
    config: &'a Config, // <-- MODIFIED: Now a borrow
    predictor_malware: PredictorMalware<'a>,
    internal_scan_tx: Sender<EDRScanRequest>,
    signature_cache: HashMap<String, FileSignatureStatus>,
    _scan_request_handle: thread::JoinHandle<()>,
}

impl<'a> AVIntegration<'a> {
    /// Create new AVIntegration instance
    pub fn new(config: &'a Config, predictor_malware: PredictorMalware<'a>) -> Self { // <-- MODIFIED: Takes a borrow
        let (internal_scan_tx, internal_scan_rx) = channel::<EDRScanRequest>();
        
        let scan_request_handle = thread::spawn(move || {
            scan_request_server_loop(internal_scan_rx);
        });

        AVIntegration {
            config, // <-- MODIFIED: Assigns the borrow
            predictor_malware,
            internal_scan_tx,
            signature_cache: HashMap::new(),
            _scan_request_handle: scan_request_handle,
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
            || event.virus_name.to_lowercase().contains("pua") {
            "Potentially Unwanted Application"
        } else if event.detection_type.to_lowercase().contains("ransom") 
            || event.virus_name.to_lowercase().contains("ransom") {
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
            revert: false, // AV integration doesn't trigger automatic reversion
        };

        match event.action_required {
            ThreatAction::Kill => {
                Logging::info(&format!(
                    "⚠️ Threat detected [{}] - Action: KILL - Path: {}",
                    event.virus_name, event.file_path
                ));
                Logging::info(&format!(
                    "   Type: {} | Certainty: {:.2}% | GID: {}",
                    threat_label, prediction_behavioral * 100.0, precord.gid
                ));
            }
            ThreatAction::KillAndQuarantine => {
                Logging::info(&format!(
                    "⚠️ Threat detected [{}] - Action: KILL AND QUARANTINE - Path: {}",
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
