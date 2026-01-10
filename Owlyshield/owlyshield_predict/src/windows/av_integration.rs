#![cfg(feature = "hydradragon")]

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
    CreateFileA, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, 
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeA, PIPE_READMODE_BYTE, 
};

use crate::process::ProcessRecord;
use crate::logging::Logging;
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::config::Config;
use crate::worker::predictor::PredictorMalware;
use chrono::Utc;
use crate::shared_def::IOMessage;

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
    scan_request_rx: Receiver<EDRScanRequest>,
    internal_scan_tx: Sender<EDRScanRequest>,
    _scan_request_handle: thread::JoinHandle<()>,
}

impl<'a> AVIntegration<'a> {
    /// Create new AVIntegration instance
    pub fn new(config: &'a Config, predictor_malware: PredictorMalware<'a>) -> Self { // <-- MODIFIED: Takes a borrow
        let (internal_scan_tx, scan_request_rx) = channel::<EDRScanRequest>();
        let tx_clone = internal_scan_tx.clone();
        
        let scan_request_handle = thread::spawn(move || {
            scan_request_server_loop(tx_clone);
        });

        AVIntegration {
            config, // <-- MODIFIED: Assigns the borrow
            predictor_malware,
            scan_request_rx,
            internal_scan_tx,
            _scan_request_handle: scan_request_handle,
        }
    }

    /// Process a single threat event according to its configured action
    pub fn process_threat_action(
        &self,
        event: &AVThreatEvent,
        precord: &ProcessRecord,
        prediction_behavioral: f32,
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

        ActionsOnKill::new().run_actions_with_info(
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

    /// Try to receive scan requests from AV
    pub fn try_receive_scan_request(&self) -> Option<EDRScanRequest> {
        self.scan_request_rx.try_recv().ok()
    }

    /// Called by kernel/event handling to queue internal requests (no external client)
    pub fn queue_file_event(&mut self, iomsg: &IOMessage, precord: &ProcessRecord) {
        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path: precord.exepath.to_string_lossy().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send internal scan request: {}", e));
        }
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

/// Read & parse a single request from a connected pipe handle
fn read_scan_request(pipe_handle: HANDLE) -> Option<EDRScanRequest> {
    unsafe {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        let result: BOOL = ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_read as *mut u32),
            None,
        );

        if !result.as_bool() {
            let err = GetLastError();
            Logging::error(&format!("ReadFile failed: {:?}", err));
            return None;
        }

        if bytes_read == 0 {
            Logging::warning("ReadFile returned 0 bytes");
            return None;
        }

        Logging::info(&format!("Read {} bytes from pipe", bytes_read));

        let preview_len = std::cmp::min(bytes_read as usize, 100);
        Logging::debug(&format!(
            "Raw bytes preview: {:?}", 
            &buffer[..preview_len]
        ));

        let data = match std::str::from_utf8(&buffer[..bytes_read as usize]) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("Invalid UTF-8 in scan request: {}", e));
                Logging::error(&format!("Bytes: {:?}", &buffer[..bytes_read as usize]));
                return None;
            }
        };

        Logging::info(&format!("Received data: {}", data));

        match serde_json::from_str::<EDRScanRequest>(data) {
            Ok(request) => {
                Logging::info(&format!(
                    "Successfully parsed scan request for: {}", 
                    request.file_path
                ));
                Some(request)
            }
            Err(e) => {
                Logging::error(&format!("Failed to parse scan request JSON: {}", e));
                Logging::error(&format!("Data received: {}", data));
                None
            }
        }
    }
}

/// AV server: persistent listener for EDR -> AV requests
fn scan_request_server_loop(tx: Sender<EDRScanRequest>) {
    Logging::info(&format!("Starting pipe server: {}", PIPE_EDR_TO_AV));

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

            Logging::info("Waiting for EDR client to connect...");

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let err = GetLastError();

            Logging::debug(&format!(
                "ConnectNamedPipe result: ok={}, error={:?}", 
                connect_ok.as_bool(), 
                err
            ));

            if connect_ok.as_bool() || err == ERROR_PIPE_CONNECTED {
                Logging::info("EDR client connected!");

                if let Some(request) = read_scan_request(pipe_handle) {
                    if let Err(e) = tx.send(request) {
                        Logging::error(&format!("Failed to forward scan request: {}", e));
                    }
                } else {
                    Logging::warning("Failed to read scan request from connected client");
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
