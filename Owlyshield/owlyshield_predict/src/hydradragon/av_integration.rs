#![cfg(feature = "hydradragon")]

use std::collections::{HashMap, hash_map::DefaultHasher};
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::mem;
#[cfg(windows)]
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use windows::core::PCSTR;

use windows::Win32::Foundation::{BOOL, CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorDacl,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    SetNamedPipeHandleState, WaitNamedPipeW,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{HIGH_PRIORITY_CLASS, SetPriorityClass};

use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::config::{Config, Param};
use crate::hydradragon::threat_response_settings::{
    DetectionEngine, ThreatAction as SettingsThreatAction, ThreatResponseSettings,
};
use crate::logging::Logging;
use crate::process::ProcessRecord;
use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp};
use crate::signature_verification::verify_signature;
use crate::threat_handler::{QuarantineMetadata, ThreatHandler};
use crate::threathandling::WindowsThreatHandler;
use crate::utils::validate_pipe_client;
use crate::worker::predictor::PredictorMalware;
use chrono::Utc;
use hydradragonstatic::models::{ScanReport, Verdict};
use hydradragonstatic::rules::RuleSet;
use hydradragonstatic::{EngineCore, ScanOptions};

// --- Pipe names (single source of truth) ---
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";
const PIPE_MBR_ALERT: &str = r"\\.\pipe\Global\mbr_filter_alerts";
const HYDRADRAGON_AV_PIPE: &str = r"\\.\pipe\HydraDragonAV";
const SANCTUM_GUI_PIPE_CLIENT_SUFFIX: &str = r"hydradragon\Sanctum\app.exe";
const SANCTUM_GUI_DEV_DEBUG_SUFFIX: &str = r"target\debug\app.exe";
const SANCTUM_GUI_DEV_RELEASE_SUFFIX: &str = r"target\release\app.exe";

const BUFFER_SIZE: u32 = 262144;
const PIPE_READ_BUFFER_SIZE: u32 = 262144;
const FAST_SERVICE_PIPE_TIMEOUT_MS: u32 = 750;
const CONNECT_TIMEOUT_MS: u32 = 900_000; // 900s - adjust as needed
const TINYAV_SCAN_DEBOUNCE: Duration = Duration::from_secs(10);
const TINYAV_RECENT_SCAN_LIMIT: usize = 4096;
const TINYAV_PREFERRED_INSTALL_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\TinyAntivirus\TinyAVConsole.exe";
const HYDRADRAGON_VENV_PYTHON_EXE: &str =
    r"C:\Program Files\HydraDragonAntivirus\venv\Scripts\python.exe";
const HYDRADRAGON_BUNDLED_PYTHON_EXE: &str =
    r"C:\Program Files\HydraDragonAntivirus\python\python.exe";
const PYTHON312_SUFFIX: &str = r"python312\python.exe";

const MAX_SCANNABLE_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const SCAN_METADATA_CACHE_LIMIT: usize = 4096;
const DIE_METADATA_WORKER_LIMIT: usize = 2;
const DIE_WORKER_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(750);
const MIN_PARALLEL_SCAN_REQUEST_WORKERS: usize = 20;
const MAX_PARALLEL_SCAN_REQUEST_WORKERS: usize = 64;

fn parallel_scan_request_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(2))
        .unwrap_or(MIN_PARALLEL_SCAN_REQUEST_WORKERS)
        .clamp(
            MIN_PARALLEL_SCAN_REQUEST_WORKERS,
            MAX_PARALLEL_SCAN_REQUEST_WORKERS,
        )
}

const DEEP_SCAN_TIMEOUT_MS: u64 = 180_000;
const MINIMAL_SCAN_TIMEOUT_MS: u64 = 30_000;
const LATE_CHILD_SCAN_GRACE_MS: u64 = 30_000;
const HYDRADRAGON_STATIC_RULES_DIR_NAME: &str = "static_rules";
const HYDRADRAGON_STATIC_RULE_RELOAD_INTERVAL: Duration = Duration::from_secs(5);
const SECURITY_DESCRIPTOR_REVISION_VALUE: u32 = 1;

static ACTIVE_DIE_METADATA_SCANS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticDetectionMode {
    Malware,
    Suspicious,
}

impl StaticDetectionMode {
    fn from_config(raw: Option<&str>) -> Self {
        match raw
            .unwrap_or("malware")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "suspicious" => StaticDetectionMode::Suspicious,
            _ => StaticDetectionMode::Malware,
        }
    }

    fn includes(self, verdict: Verdict) -> bool {
        match self {
            StaticDetectionMode::Malware => verdict == Verdict::Malware,
            StaticDetectionMode::Suspicious => verdict != Verdict::Clean,
        }
    }
}

/// Action to take when a threat is detected
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
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
            "kill_only" => ThreatAction::Kill,
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
    pub match_details: Option<String>,
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
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub status_text: String,
    #[serde(default)]
    pub raw_hresult: u32,
    #[serde(default)]
    pub verification_failed: bool,
    #[serde(default)]
    pub no_signature: bool,
    #[serde(default)]
    pub signature_status_issues: bool,
    #[serde(default)]
    pub invalid_signature: bool,
}

/// Fast Rust-side result from service-backed engines used by minimal mode.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RustServiceScanResult {
    pub engine: String,
    pub malicious: bool,
    pub virus_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_details: Option<String>,
    #[serde(default)]
    pub is_vmprotect: bool,
    #[serde(default)]
    pub error: Option<String>,
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
    #[serde(default)]
    pub yara_x_matches: Option<Vec<String>>,
    #[serde(default)]
    pub is_vmprotect: bool,
    #[serde(default)]
    pub deep_scan: bool,
    #[serde(default = "default_scan_mode")]
    pub scan_mode: String,
    /// DetectItEasy scan result computed by Owlyshield/Rust.
    #[serde(default)]
    pub detectiteasy_scan_result: Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
    /// Root file that initiated this scan chain. Python propagates this to
    /// extracted/decompiled child scans for reporting and late-timeout handling.
    #[serde(default)]
    pub scan_origin_path: Option<String>,
    /// Optional timeout hint for the HydraDragon/Python side. Rust sends the
    /// request, Python must enforce this timeout while running deep scan.
    #[serde(default)]
    pub deep_scan_timeout_ms: Option<u64>,
    #[serde(default)]
    pub late_child_scan_grace_ms: Option<u64>,
    /// Rust already queried fast service engines for minimal mode. Python consumes
    /// these results directly instead of opening the heavy engines itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rust_service_scan_results: Vec<RustServiceScanResult>,
}

fn default_scan_mode() -> String {
    "minimal".to_string()
}

fn timeout_for_scan_mode(config: &Config, scan_mode: &str) -> Option<u64> {
    if is_deep_scan_mode(scan_mode) {
        Some(config.deep_scan_timeout_ms(DEEP_SCAN_TIMEOUT_MS))
    } else {
        Some(config.minimal_scan_timeout_ms(MINIMAL_SCAN_TIMEOUT_MS))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileIdentity {
    normalized_path: String,
    size: u64,
    modified_unix_nanos: u128,
}

fn modified_unix_nanos(path: &Path) -> u128 {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn file_identity_for_path(file_path: &str, path: &Path) -> Option<FileIdentity> {
    let metadata = path.metadata().ok()?;
    Some(FileIdentity {
        normalized_path: normalize_path_for_compare(file_path),
        size: metadata.len(),
        modified_unix_nanos: modified_unix_nanos(path),
    })
}

fn file_is_over_scan_limit(path: &Path) -> bool {
    path.metadata()
        .map(|m| m.len() > MAX_SCANNABLE_FILE_SIZE)
        .unwrap_or(false)
}

fn log_skip_large_file(context: &str, path: &Path) {
    Logging::debug(&format!(
        "[AVIntegration] Skipping {context}; file is over 2 GiB: {}",
        path.display()
    ));
}

#[derive(Debug, Clone)]
struct ScanMetadata {
    signature_status: Option<FileSignatureStatus>,
    yara_x_matches: Vec<String>,
    hydradragon_static_matches: Vec<String>,
    hydradragon_static_match_details: Vec<String>,
    is_vmprotect: bool,
    detectiteasy_scan_result: Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
    should_queue_scan: bool,
}

impl ScanMetadata {
    fn new() -> Self {
        ScanMetadata {
            signature_status: None,
            yara_x_matches: Vec::new(),
            hydradragon_static_matches: Vec::new(),
            hydradragon_static_match_details: Vec::new(),
            is_vmprotect: false,
            detectiteasy_scan_result: None,
            should_queue_scan: true,
        }
    }
}

struct PipeSecurityAttributes {
    _descriptor: Box<SECURITY_DESCRIPTOR>,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurityAttributes {
    fn permissive() -> Result<Self, String> {
        unsafe {
            let mut descriptor = Box::new(mem::zeroed::<SECURITY_DESCRIPTOR>());
            let descriptor_raw = descriptor.as_mut() as *mut _ as *mut core::ffi::c_void;

            if !InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR(descriptor_raw),
                SECURITY_DESCRIPTOR_REVISION_VALUE,
            )
            .as_bool()
            {
                return Err(format!(
                    "InitializeSecurityDescriptor failed (GetLastError={:?})",
                    GetLastError()
                ));
            }
            if !SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR(descriptor_raw), true, None, false)
                .as_bool()
            {
                return Err(format!(
                    "SetSecurityDescriptorDacl failed (GetLastError={:?})",
                    GetLastError()
                ));
            }

            Ok(Self {
                _descriptor: descriptor,
                attributes: SECURITY_ATTRIBUTES {
                    nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor_raw,
                    bInheritHandle: BOOL(0),
                },
            })
        }
    }

    fn as_ptr(&mut self) -> *const SECURITY_ATTRIBUTES {
        &mut self.attributes as *mut SECURITY_ATTRIBUTES as *const SECURITY_ATTRIBUTES
    }
}

fn create_pipe_security_attributes(context: &str) -> Option<PipeSecurityAttributes> {
    match PipeSecurityAttributes::permissive() {
        Ok(attributes) => Some(attributes),
        Err(error) => {
            Logging::warning(&format!(
                "{context} could not initialize permissive pipe security; falling back to default DACL: {error}"
            ));
            None
        }
    }
}

fn is_deep_scan_mode(scan_mode: &str) -> bool {
    scan_mode.trim().eq_ignore_ascii_case("deep")
}

fn signature_status_is_suspicious(status: &Option<FileSignatureStatus>) -> bool {
    status
        .as_ref()
        .is_some_and(|s| s.invalid_signature || s.signature_status_issues || s.verification_failed)
}

fn metadata_is_suspicious(
    signature_status: &Option<FileSignatureStatus>,
    yara_x_matches: &[String],
    is_vmprotect: bool,
) -> bool {
    is_vmprotect || !yara_x_matches.is_empty() || signature_status_is_suspicious(signature_status)
}

#[derive(Debug, Deserialize)]
struct HydraDragonAvPipeResponse {
    status: Option<String>,
    malicious: Option<bool>,
    clamav: Option<String>,
    yara: Option<Vec<String>>,
    is_vmprotect: Option<bool>,
}

fn clean_service_result(engine: &str) -> RustServiceScanResult {
    RustServiceScanResult {
        engine: engine.to_string(),
        malicious: false,
        virus_name: "Clean".to_string(),
        match_details: None,
        is_vmprotect: false,
        error: None,
    }
}

fn service_error_result(engine: &str, error: impl Into<String>) -> RustServiceScanResult {
    RustServiceScanResult {
        engine: engine.to_string(),
        malicious: false,
        virus_name: "Error".to_string(),
        match_details: None,
        is_vmprotect: false,
        error: Some(error.into()),
    }
}

fn open_duplex_pipe(
    pipe_name: &str,
    timeout_ms: u32,
    message_read_mode: bool,
) -> Result<HANDLE, String> {
    use windows::core::PCWSTR;

    // Convert to UTF-16 for Unicode Windows API
    let mut pipe_name_wide: Vec<u16> = pipe_name.encode_utf16().collect();
    pipe_name_wide.push(0); // Null terminator
    let pcwstr = PCWSTR(pipe_name_wide.as_ptr());

    let wait_ok: BOOL = unsafe { WaitNamedPipeW(pcwstr, timeout_ms) };
    if !wait_ok.as_bool() {
        return Err(format!(
            "pipe not ready within {timeout_ms} ms (GetLastError={:?})",
            unsafe { GetLastError() }
        ));
    }

    let pipe_handle = unsafe {
        CreateFileW(
            pcwstr,
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    }
    .map_err(|e| {
        format!(
            "CreateFileW failed for {pipe_name}: {:?} (GetLastError={:?})",
            e,
            unsafe { GetLastError() }
        )
    })?;

    if pipe_handle.is_invalid() {
        return Err(format!(
            "CreateFileW returned invalid handle for {pipe_name} (GetLastError={:?})",
            unsafe { GetLastError() }
        ));
    }

    if message_read_mode {
        let mode = PIPE_READMODE_MESSAGE;
        let ok =
            unsafe { SetNamedPipeHandleState(pipe_handle, Some(&mode as *const _), None, None) };
        if !ok.as_bool() {
            let error = format!(
                "SetNamedPipeHandleState failed for {pipe_name} (GetLastError={:?})",
                unsafe { GetLastError() }
            );
            let _ = unsafe { CloseHandle(pipe_handle) };
            return Err(error);
        }
    }

    Ok(pipe_handle)
}

fn write_pipe_bytes(pipe_handle: HANDLE, bytes: &[u8], context: &str) -> Result<(), String> {
    let mut bytes_written = 0u32;
    let ok = unsafe {
        WriteFile(
            pipe_handle,
            Some(bytes),
            Some(&mut bytes_written as *mut u32),
            None,
        )
    };

    if !ok.as_bool() || bytes_written != bytes.len() as u32 {
        return Err(format!(
            "{context}: WriteFile wrote {bytes_written}/{} bytes (GetLastError={:?})",
            bytes.len(),
            unsafe { GetLastError() }
        ));
    }

    Ok(())
}

fn read_pipe_bytes(pipe_handle: HANDLE, len: usize, context: &str) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0u8; len];
    let mut bytes_read = 0u32;
    let ok = unsafe {
        ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr().cast()),
            len as u32,
            Some(&mut bytes_read as *mut u32),
            None,
        )
    };

    if !ok.as_bool() || bytes_read != len as u32 {
        return Err(format!(
            "{context}: ReadFile read {bytes_read}/{len} bytes (GetLastError={:?})",
            unsafe { GetLastError() }
        ));
    }

    Ok(buffer)
}

fn read_pipe_message(pipe_handle: HANDLE, max_len: u32, context: &str) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0u8; max_len as usize];
    let mut bytes_read = 0u32;
    let ok = unsafe {
        ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr().cast()),
            max_len,
            Some(&mut bytes_read as *mut u32),
            None,
        )
    };

    if !ok.as_bool() || bytes_read == 0 {
        return Err(format!(
            "{context}: ReadFile failed or returned no data (GetLastError={:?})",
            unsafe { GetLastError() }
        ));
    }

    buffer.truncate(bytes_read as usize);
    Ok(buffer)
}

fn utf16_fixed_to_string(bytes: &[u8], wchar_count: usize) -> String {
    let mut code_units = Vec::with_capacity(wchar_count);
    for chunk in bytes.chunks_exact(2).take(wchar_count) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if value == 0 {
            break;
        }
        code_units.push(value);
    }
    String::from_utf16_lossy(&code_units)
}

fn scan_hydradragon_av_service(file_path: &str) -> RustServiceScanResult {
    let pipe_handle =
        match open_duplex_pipe(HYDRADRAGON_AV_PIPE, FAST_SERVICE_PIPE_TIMEOUT_MS, true) {
            Ok(handle) => handle,
            Err(e) => return service_error_result("HydraDragonAV", e),
        };

    let scan_result = (|| -> Result<RustServiceScanResult, String> {
        let request = serde_json::json!({ "path": file_path }).to_string();
        write_pipe_bytes(pipe_handle, request.as_bytes(), "HydraDragonAV request")?;
        let response_bytes =
            read_pipe_message(pipe_handle, PIPE_READ_BUFFER_SIZE, "HydraDragonAV response")?;
        let response_text = String::from_utf8_lossy(&response_bytes).to_string();
        let response: HydraDragonAvPipeResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                format!("invalid HydraDragonAV response JSON: {e}; raw={response_text}")
            })?;

        if response.status.as_deref() != Some("success") {
            return Err(format!(
                "HydraDragonAV returned non-success status: {:?}",
                response.status
            ));
        }

        if response.malicious.unwrap_or(false) {
            if let Some(virus_name) = response.clamav.filter(|v| !v.trim().is_empty()) {
                return Ok(RustServiceScanResult {
                    engine: "HydraDragonAV/ClamAV".to_string(),
                    malicious: true,
                    match_details: Some(format!(
                        "HydraDragonAV/ClamAV matched signature '{}' for {}",
                        virus_name, file_path
                    )),
                    virus_name,
                    is_vmprotect: response.is_vmprotect.unwrap_or(false),
                    error: None,
                });
            }

            if let Some(yara_matches) = response
                .yara
                .filter(|matches| matches.iter().any(|v| !v.trim().is_empty()))
            {
                let virus_name = yara_matches
                    .iter()
                    .find(|v| !v.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| "LegacyYARA.Match".to_string());
                return Ok(RustServiceScanResult {
                    engine: "HydraDragonAV/LegacyYARA".to_string(),
                    malicious: true,
                    match_details: Some(format!(
                        "HydraDragonAV/LegacyYARA matched rule(s) for {}: {}",
                        file_path,
                        yara_matches
                            .iter()
                            .filter(|v| !v.trim().is_empty())
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    virus_name,
                    is_vmprotect: response.is_vmprotect.unwrap_or(false),
                    error: None,
                });
            }

            return Ok(RustServiceScanResult {
                engine: "HydraDragonAV".to_string(),
                malicious: true,
                virus_name: "HydraDragonAV.Detection".to_string(),
                match_details: Some(format!(
                    "HydraDragonAV pipe reported malicious=true for {} but did not return a specific signature name",
                    file_path
                )),
                is_vmprotect: response.is_vmprotect.unwrap_or(false),
                error: None,
            });
        }

        let mut clean = clean_service_result("HydraDragonAV");
        clean.is_vmprotect = response.is_vmprotect.unwrap_or(false);
        Ok(clean)
    })();

    let _ = unsafe { CloseHandle(pipe_handle) };
    scan_result.unwrap_or_else(|e| service_error_result("HydraDragonAV", e))
}

fn collect_minimal_service_scan_results(file_path: &str) -> Vec<RustServiceScanResult> {
    let result = scan_hydradragon_av_service(file_path);

    if result.malicious {
        Logging::info(&format!(
            "[RustServiceScan] {} detected {} in {}",
            result.engine, result.virus_name, file_path
        ));
    } else if let Some(error) = &result.error {
        Logging::debug(&format!(
            "[RustServiceScan] {} unavailable for {}: {}",
            result.engine, file_path, error
        ));
    }

    vec![result]
}

fn should_skip_die_scan(scan_target: &Path) -> bool {
    use crate::hydradragon::detectiteasy::is_plain_text_file;

    is_plain_text_file(scan_target).unwrap_or(false)
}

struct DieMetadataWorkerGuard;

impl DieMetadataWorkerGuard {
    fn acquire() -> Option<Self> {
        let start = Instant::now();
        loop {
            let active = ACTIVE_DIE_METADATA_SCANS.load(Ordering::Relaxed);
            if active < DIE_METADATA_WORKER_LIMIT {
                if ACTIVE_DIE_METADATA_SCANS
                    .compare_exchange(active, active + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return Some(DieMetadataWorkerGuard);
                }
            } else if start.elapsed() >= DIE_WORKER_ACQUIRE_TIMEOUT {
                return None;
            }

            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for DieMetadataWorkerGuard {
    fn drop(&mut self) {
        ACTIVE_DIE_METADATA_SCANS.fetch_sub(1, Ordering::Release);
    }
}

fn run_detectiteasy_metadata_scan(
    file_path: &str,
    scan_target: &Path,
) -> Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult> {
    if should_skip_die_scan(scan_target) {
        Logging::debug(&format!(
            "[DetectItEasy] Skipping DIE metadata scan for plain-text file: {}",
            file_path
        ));
        return None;
    }

    let Some(_guard) = DieMetadataWorkerGuard::acquire() else {
        Logging::warning(&format!(
            "[DetectItEasy] Worker limit reached; skipping DIE metadata scan for {}",
            file_path
        ));
        return None;
    };

    use crate::hydradragon::detectiteasy::DetectItEasyScanner;

    let scanner = DetectItEasyScanner::new();
    Some(match scanner.scan_file(scan_target) {
        Ok(result) => result,
        Err(error) => {
            Logging::warning(&format!(
                "[DetectItEasy] Scan failed for {}: {}",
                file_path, error
            ));
            DetectItEasyScanner::error_result(scan_target, error)
        }
    })
}

fn die_result_is_fully_unknown(
    result: &Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
) -> bool {
    result.as_ref().is_some_and(|r| r.scan_ok && r.is_unknown)
}

fn die_result_has_supported_deep_scan_type(
    result: &Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
) -> bool {
    let Some(result) = result.as_ref() else {
        return false;
    };

    if !result.scan_ok || result.is_plain_text || result.is_unknown {
        return false;
    }

    result.is_pe
        || result.is_elf
        || result.is_macho
        || result.is_apk
        || result.is_broken_executable
        || result.pe_result.is_some()
        || result.elf_result.is_some()
        || result.macho_result.is_some()
        || result.apk_result.is_some()
        || result.file_type.is_some()
        || result.is_protected
        || result.protector_name.is_some()
        || result.is_themida
        || result.themida_type.is_some()
        || result.is_vmprotect
        || result.is_packed
        || result.packer_name.is_some()
        || result.packer_type.is_some()
        || result.is_upx
        || result.is_pyinstaller
        || result.is_nuitka
        || result.nuitka_type.is_some()
        || result.is_cx_freeze
        || result.is_nexe
        || result.is_npm
        || result.is_dotnet
        || result.dotnet_type.is_some()
        || result.is_go_garble
        || result.is_pyc
        || result.is_pyarmor_archive
        || result.is_jar
        || result.is_java_class
        || result.is_jsc.is_some()
        || result.is_inno_setup
        || result.is_nsis
        || result.is_advanced_installer
        || result.is_installshield
        || result.is_clickteam
        || result.is_autoit
        || result.is_compiled_autohotkey
        || result.is_archive
        || result.is_7z
        || result.is_asar
        || result.is_microsoft_compound
        || result.is_enigma_virtual_box
}

fn die_result_is_unsupported_for_deep_scan(
    result: &Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
) -> bool {
    result
        .as_ref()
        .is_some_and(|r| r.scan_ok && !die_result_has_supported_deep_scan_type(result))
}

fn should_inject_python_hook_for_process(
    pid: u32,
    die_result: &Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
) -> bool {
    die_result
        .as_ref()
        .is_some_and(|die_res| die_res.is_python_process)
        || crate::hydradragon::python_hook::process_has_python_runtime(pid)
}

fn maybe_spawn_python_hook(
    pid: Option<u32>,
    die_result: &Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
) {
    if let Some(pid_val) = pid {
        if should_inject_python_hook_for_process(pid_val, die_result) {
            let _ = std::thread::spawn(move || {
                crate::hydradragon::python_hook::inject(pid_val);
            });
        }
    }
}

/// AV scan response (sent to EDR as a threat event)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVScanResponse {
    pub file_path: String,
    pub is_malicious: bool,
    pub virus_name: Option<String>,
    pub scan_timestamp: String,
}

unsafe fn validate_hydradragon_python_client(pipe_handle: HANDLE) -> bool {
    for expected in [
        HYDRADRAGON_VENV_PYTHON_EXE,
        HYDRADRAGON_BUNDLED_PYTHON_EXE,
        PYTHON312_SUFFIX,
    ] {
        if unsafe { validate_pipe_client(pipe_handle, Some(expected), false) } {
            return true;
        }
    }
    false
}

unsafe fn validate_sanctum_manual_scan_client(pipe_handle: HANDLE) -> bool {
    for expected in [
        SANCTUM_GUI_PIPE_CLIENT_SUFFIX,
        SANCTUM_GUI_DEV_DEBUG_SUFFIX,
        SANCTUM_GUI_DEV_RELEASE_SUFFIX,
    ] {
        if unsafe { validate_pipe_client(pipe_handle, Some(expected), false) } {
            return true;
        }
    }
    false
}

fn normalize_path_for_compare(path: &str) -> String {
    normalize_nt_path(path)
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn path_is_under(prefix: &Path, candidate: &Path) -> bool {
    let p = normalize_path_for_compare(&prefix.to_string_lossy());
    let c = normalize_path_for_compare(&candidate.to_string_lossy());
    c == p || c.starts_with(&(p + "\\"))
}

fn is_protected_path(candidate_path: &str) -> bool {
    let candidate = PathBuf::from(candidate_path);

    let program_files = std::env::var("ProgramW6432")
        .or_else(|_| std::env::var("ProgramFiles"))
        .unwrap_or_else(|_| r"C:\Program Files".to_string());
    let pf_hda = PathBuf::from(program_files).join("HydraDragonAntivirus");
    if path_is_under(&pf_hda, &candidate) {
        return true;
    }

    false
}

fn is_openedr_cloud_safe(_file_path: &str) -> bool {
    #[cfg(all(
        target_os = "windows",
        feature = "firewall",
        feature = "behavior_engine"
    ))]
    {
        if let Some(verdict) =
            crate::behavioral::behavior_engine::firewall_file_verdict_for_path(file_path)
        {
            if verdict.verdict == 1 {
                Logging::debug(&format!(
                    "[AVIntegration] Trusting OpenEDR cloud-safe verdict for {} ({}, sha256={})",
                    file_path, verdict.verdict_label, verdict.sha256
                ));
                return true;
            }
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
    } else if normalized
        .to_ascii_lowercase()
        .starts_with("\\device\\harddiskvolume")
    {
        // Keep this conversion simple and deterministic, aligned with kernel rule matching.
        // If we detect a device-volume path, map it to system drive for fast comparisons.
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if let Some(rest) = normalized.splitn(4, '\\').nth(3) {
            normalized = format!("{}\\{}", system_drive, rest);
        }
    }

    normalized.trim_end_matches('\0').to_string()
}

fn is_new_file_event(iomsg: &IOMessage) -> bool {
    IrpMajorOp::from_sysmonevent(iomsg.irp_op) == IrpMajorOp::IrpCreate
        && num::FromPrimitive::from_u8(iomsg.file_change) == Some(FileChangeInfo::ChangeNewFile)
}

fn scan_target_for_iomsg(iomsg: &IOMessage, precord: &ProcessRecord) -> PathBuf {
    if is_new_file_event(iomsg) && !iomsg.filepathstr.trim().is_empty() {
        return PathBuf::from(normalize_nt_path(&iomsg.filepathstr));
    }

    precord.exepath.clone()
}

fn resolve_tinyav_console_path() -> Option<PathBuf> {
    let tinyav_path = PathBuf::from(TINYAV_PREFERRED_INSTALL_PATH);
    tinyav_path.is_file().then_some(tinyav_path)
}

fn wait_until_tinyav_target_is_ready(path: &Path) -> bool {
    let mut previous_len = None;
    let mut stable_observations = 0;

    for _ in 0..12 {
        if let Ok(metadata) = path.metadata()
            && metadata.is_file()
        {
            let len = metadata.len();
            if previous_len == Some(len) {
                stable_observations += 1;
                if stable_observations >= 2 {
                    return true;
                }
            } else {
                previous_len = Some(len);
                stable_observations = 0;
            }
        }

        thread::sleep(Duration::from_millis(250));
    }

    path.is_file()
}

fn tinyav_detected_count(output_text: &str) -> Option<u64> {
    for line in output_text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Detected") {
            let digits: String = rest
                .chars()
                .skip_while(|ch| !ch.is_ascii_digit())
                .take_while(|ch| ch.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                return digits.parse::<u64>().ok();
            }
        }
    }

    None
}

#[cfg(windows)]
fn child_process_handle(child: &std::process::Child) -> HANDLE {
    HANDLE(child.as_handle().as_raw_handle() as isize)
}

fn run_tinyav_scan(tinyav_console: PathBuf, file_path: PathBuf) {
    if !wait_until_tinyav_target_is_ready(&file_path) {
        Logging::debug(&format!(
            "[TinyAV] Skipping new-file scan because target is not ready: {}",
            file_path.display()
        ));
        return;
    }

    let Some(scan_dir) = file_path.parent().map(Path::to_path_buf) else {
        Logging::debug(&format!(
            "[TinyAV] Skipping new-file scan because no parent directory exists: {}",
            file_path.display()
        ));
        return;
    };
    let Some(file_name) = file_path.file_name().map(|name| name.to_os_string()) else {
        Logging::debug(&format!(
            "[TinyAV] Skipping new-file scan because no file name exists: {}",
            file_path.display()
        ));
        return;
    };

    Logging::info(&format!(
        "[TinyAV] Scanning new file detected by Owlyshield: {}",
        file_path.display()
    ));

    let mut command = Command::new(&tinyav_console);
    command
        .arg("-d")
        .arg(&scan_dir)
        .arg("-p")
        .arg(&file_name)
        .arg("-D")
        .arg("0")
        .arg("-m")
        .arg("k");

    if let Some(tinyav_dir) = tinyav_console.parent() {
        command.current_dir(tinyav_dir);
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output_result = match command.spawn() {
        Ok(child) => {
            #[cfg(windows)]
            unsafe {
                if !SetPriorityClass(child_process_handle(&child), HIGH_PRIORITY_CLASS).as_bool() {
                    Logging::warning(&format!(
                        "[TinyAV] Failed to raise scan process priority for {}",
                        file_path.display()
                    ));
                }
            }

            child.wait_with_output()
        }
        Err(e) => Err(e),
    };

    match output_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{stdout}\n{stderr}");
            let detected = tinyav_detected_count(&combined).unwrap_or(0);

            if detected > 0 {
                Logging::warning(&format!(
                    "[TinyAV] Detected {} file(s) while scanning {}",
                    detected,
                    file_path.display()
                ));
            } else if output.status.success() {
                Logging::debug(&format!(
                    "[TinyAV] New-file scan clean: {}",
                    file_path.display()
                ));
            } else {
                Logging::error(&format!(
                    "[TinyAV] Scan exited with status {:?} for {}. stderr={}",
                    output.status.code(),
                    file_path.display(),
                    stderr.trim()
                ));
            }
        }
        Err(e) => Logging::error(&format!(
            "[TinyAV] Failed to launch {} for {}: {}",
            tinyav_console.display(),
            file_path.display(),
            e
        )),
    }
}

fn decode_utf16le_message(data: &[u8]) -> String {
    let usable_len = data.len() - (data.len() % 2);
    let mut words = Vec::with_capacity(usable_len / 2);
    for chunk in data[..usable_len].chunks_exact(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&words)
        .trim_end_matches('\0')
        .to_string()
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
    let match_details = value
        .get("match_details")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
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
        match_details,
        action_required,
        pid,
        gid,
    })
}

fn resolve_gid_for_action(event: &AVThreatEvent) -> Option<u64> {
    if let Some(gid) = event.gid {
        return Some(gid);
    }
    event.pid.map(|pid| 0x8000_0000_0000_0000u64 | (pid as u64))
}

fn synthetic_gid_from_path(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

fn manual_scan_action_label(action: SettingsThreatAction) -> &'static str {
    match action {
        SettingsThreatAction::DoNothing => "DoNothing",
        SettingsThreatAction::NotifyOnly => "NotifyOnly",
        SettingsThreatAction::Suspend => "Suspend",
        SettingsThreatAction::DenyAccess => "DenyAccess",
        SettingsThreatAction::Quarantine => "Quarantine",
        SettingsThreatAction::Kill => "Kill",
        SettingsThreatAction::KillAndQuarantine => "KillAndQuarantine",
        SettingsThreatAction::KillAndRemove => "KillAndRemove",
        SettingsThreatAction::AskUser => "AskUser",
    }
}

fn quarantine_metadata(detection_engine: &str, detection_name: &str) -> QuarantineMetadata {
    QuarantineMetadata {
        detection: format!("{}: {}", detection_engine, detection_name),
    }
}

fn detectiteasy_malware_name(
    result: &Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
) -> Option<String> {
    result.as_ref().and_then(|result| {
        if !result.scan_ok || !result.is_malware {
            return None;
        }

        Some(
            result
                .malware_name
                .clone()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "DetectItEasy.Malware".to_string()),
        )
    })
}

fn quarantine_detectiteasy_malware_with_handler<T: ThreatHandler + ?Sized>(
    threat_handler: &T,
    normalized_file_path: &str,
    detection_name: &str,
) -> &'static str {
    Logging::alert(&format!(
        "[DetectItEasy] Malware flag detected; quarantining in Rust: {} ({})",
        normalized_file_path, detection_name
    ));

    let metadata = quarantine_metadata("DetectItEasy", detection_name);
    threat_handler.kill_and_quarantine(
        synthetic_gid_from_path(normalized_file_path),
        Path::new(normalized_file_path),
        &metadata,
    );
    "success_killed_quarantined"
}

fn quarantine_detectiteasy_malware(
    normalized_file_path: &str,
    detection_name: &str,
) -> &'static str {
    use crate::windows::edrsvc_client::with_shared_driver;
    with_shared_driver(|driver| {
        let threat_handler = WindowsThreatHandler::from(driver.clone());
        quarantine_detectiteasy_malware_with_handler(
            &threat_handler,
            normalized_file_path,
            detection_name,
        )
    })
    .unwrap_or_else(|| {
        Logging::error(&format!(
            "[DetectItEasy] Shared driver unavailable for Rust quarantine of {}",
            normalized_file_path
        ));
        "error_driver_unavailable"
    })
}

fn apply_manual_scan_threat_action<T: ThreatHandler + ?Sized>(
    threat_handler: &T,
    action: SettingsThreatAction,
    normalized_file_path: &str,
    detection_engine: &str,
    detection_name: &str,
) -> &'static str {
    let path = Path::new(normalized_file_path);
    let label = manual_scan_action_label(action);

    match action {
        SettingsThreatAction::DoNothing => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            "success_no_action"
        }
        SettingsThreatAction::NotifyOnly => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            "success_notified"
        }
        SettingsThreatAction::DenyAccess => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            threat_handler.deny_path_access(path);
            "success_denied"
        }
        SettingsThreatAction::Quarantine => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            let metadata = quarantine_metadata(detection_engine, detection_name);
            threat_handler.kill_and_quarantine(
                synthetic_gid_from_path(normalized_file_path),
                path,
                &metadata,
            );
            "success_quarantined"
        }
        SettingsThreatAction::Kill => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            threat_handler.kill(synthetic_gid_from_path(normalized_file_path));
            "success_killed"
        }
        SettingsThreatAction::KillAndQuarantine => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            let metadata = quarantine_metadata(detection_engine, detection_name);
            threat_handler.kill_and_quarantine(
                synthetic_gid_from_path(normalized_file_path),
                path,
                &metadata,
            );
            "success_killed_quarantined"
        }
        SettingsThreatAction::KillAndRemove => {
            Logging::info(&format!(
                "[ManualScan] Action: {} for {}",
                label, normalized_file_path
            ));
            threat_handler.kill_and_remove(synthetic_gid_from_path(normalized_file_path), path);
            "success_killed_removed"
        }
        SettingsThreatAction::Suspend => {
            Logging::warning(&format!(
                "[ManualScan] Action: {} not applicable for manual scan (no process context) for {}",
                label, normalized_file_path
            ));
            "error_suspend_not_applicable"
        }
        SettingsThreatAction::AskUser => {
            Logging::info(&format!(
                "[ManualScan] Action: {} - defaulting to NotifyOnly for {}",
                label, normalized_file_path
            ));
            "success_ask_user_notified"
        }
    }
}

fn apply_fast_driver_action(event: &AVThreatEvent) {
    if !event.is_malicious {
        return;
    }

    if event.virus_name.to_lowercase().contains("sality") {
        let file_path = PathBuf::from(&event.file_path);
        if let Some(tinyav_console) = resolve_tinyav_console_path() {
            if let Err(e) = thread::Builder::new()
                .name("tinyav_sality_disinfect".to_string())
                .spawn(move || run_tinyav_scan(tinyav_console, file_path))
            {
                Logging::error(&format!(
                    "[TinyAV] Failed to spawn sality disinfect worker: {}",
                    e
                ));
            }
        }
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

    use crate::windows::edrsvc_client::with_shared_driver;
    let outcome = with_shared_driver(|driver| {
        let file_path = Path::new(&event.file_path);
        match event.action_required {
            ThreatAction::Kill => driver.try_kill(gid),
            ThreatAction::KillAndQuarantine => driver.kill_and_remove_driver(gid, file_path),
            ThreatAction::KillAndRemove => driver.kill_and_remove_driver(gid, file_path),
            ThreatAction::Monitor => unreachable!("Monitor case handled above"),
        }
    });

    match outcome {
        None => Logging::error(&format!(
            "[AV->EDR] Shared driver unavailable for threat action '{}': {}",
            event.action_required.as_str(),
            event.file_path
        )),
        Some(Ok(hr)) => Logging::info(&format!(
            "[AV->EDR] Applied threat action '{}' for gid={} path={} hr=0x{:08X}",
            event.action_required.as_str(),
            gid,
            event.file_path,
            hr.0 as u32
        )),
        Some(Err(e)) => Logging::error(&format!(
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
        let mut pipe_security = create_pipe_security_attributes("[AV->EDR]");

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
                pipe_security.as_mut().map(|attributes| attributes.as_ptr()),
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
                if !validate_hydradragon_python_client(pipe_handle) {
                    Logging::error("[AV->EDR] Rejected unauthorized client connection");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
                Logging::info("[AV->EDR] Authorized HydraDragon Python client connected");

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
                    let message = String::from_utf8_lossy(&buffer[..bytes_read as usize])
                        .trim()
                        .to_string();
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

                    // Parse enriched format: "DISK:<number>|<process_path>"
                    let (disk_number, process_path) = if raw.starts_with("DISK:") {
                        if let Some(pipe_pos) = raw.find('|') {
                            let disk_str = &raw[5..pipe_pos];
                            let path = &raw[pipe_pos + 1..];
                            let disk_num: i32 = disk_str.parse().unwrap_or(-1);
                            (disk_num, normalize_nt_path(path))
                        } else {
                            (-1, normalize_nt_path(&raw))
                        }
                    } else {
                        // Legacy format: just the process path
                        (0, normalize_nt_path(&raw))
                    };

                    if disk_number == 0 {
                        // System disk MBR write — always blocked, just log
                        Logging::error(&format!(
                            "[MBR ALERT] System disk (PhysicalDrive0) MBR write blocked — Offending process: {}",
                            process_path
                        ));
                    } else {
                        // Non-system disk (USB/external) MBR write — blocked and notify firewall GUI
                        Logging::error(&format!(
                            "[MBR ALERT] USB/External disk {} MBR write blocked — Offending process: {}",
                            disk_number, process_path
                        ));

                        // Forward to firewall GUI HIPS pipe for user notification
                        send_mbr_hips_notification(disk_number, &process_path);
                    }
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    })
}

/// Send a HIPS-style notification to the firewall GUI about a blocked USB MBR write.
fn send_mbr_hips_notification(disk_number: i32, process_path: &str) {
    use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE, FlushFileBuffers,
        OPEN_EXISTING, WriteFile,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::PCWSTR;

    const HIPS_PIPE: &str = r"\\.\pipe\HydraHipEvent";
    const CONNECT_TIMEOUT_MS: u32 = 750;

    // Convert to UTF-16 for Unicode Windows API
    let mut pipe_name_wide: Vec<u16> = HIPS_PIPE.encode_utf16().collect();
    pipe_name_wide.push(0); // Null terminator
    let pcwstr = PCWSTR(pipe_name_wide.as_ptr());

    let wait_ok: BOOL = unsafe { WaitNamedPipeW(pcwstr, CONNECT_TIMEOUT_MS) };
    if !wait_ok.as_bool() {
        Logging::warning(&format!(
            "[MBR HIPS] Firewall GUI pipe not ready for USB MBR alert (disk {}, GetLastError={:?})",
            disk_number,
            unsafe { GetLastError() }
        ));
        return;
    }

    let pipe_handle = unsafe {
        CreateFileW(
            pcwstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };

    let pipe_handle = match pipe_handle {
        Ok(handle) if !handle.is_invalid() => handle,
        Ok(_) => {
            Logging::error("[MBR HIPS] CreateFileW returned invalid HydraHipEvent handle");
            return;
        }
        Err(err) => {
            Logging::warning(&format!(
                "[MBR HIPS] Failed to connect to HydraHipEvent pipe: {:?}",
                err
            ));
            return;
        }
    };

    // Build the HIPS notification JSON
    let hips_json = format!(
        r#"{{"request_id":"mbr_usb_{}_{}", "alert_kind":"MBR_USB_WRITE", "pid":0, "app_name":"MBRFilter", "exe_path":"{}", "target":"PhysicalDrive{}", "reason":"Blocked MBR write to removable/external disk {} by process: {}. This may indicate USB MBR malware."}}"#,
        disk_number,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        process_path.replace('\\', "\\\\").replace('"', "\\\""),
        disk_number,
        disk_number,
        process_path.replace('\\', "\\\\").replace('"', "\\\""),
    );

    let message_bytes = hips_json.as_bytes();
    let mut bytes_written: u32 = 0;

    let ok: BOOL = unsafe {
        WriteFile(
            pipe_handle,
            Some(message_bytes),
            Some(&mut bytes_written as *mut u32),
            None,
        )
    };

    let _ = unsafe { FlushFileBuffers(pipe_handle) };
    let _ = unsafe { CloseHandle(pipe_handle) };

    if ok.as_bool() {
        Logging::info(&format!(
            "[MBR HIPS] Sent USB MBR alert to firewall GUI for disk {} ({} bytes)",
            disk_number, bytes_written
        ));
    } else {
        Logging::error(&format!(
            "[MBR HIPS] Failed to write USB MBR alert to HydraHipEvent pipe (GetLastError={:?})",
            unsafe { GetLastError() }
        ));
    }
}

/// Integration struct — keeps internal channel & listener thread
pub struct AVIntegration<'a> {
    config: &'a Config, // <-- MODIFIED: Now a borrow
    predictor_malware: PredictorMalware,
    internal_scan_tx: Sender<EDRScanRequest>,
    signature_cache: HashMap<FileIdentity, FileSignatureStatus>,
    scan_metadata_cache: HashMap<FileIdentity, ScanMetadata>,
    tinyav_recent_scans: HashMap<String, Instant>,
    tinyav_missing_logged: bool,
    yara_rules: Option<yara_x::Rules>,
    excluded_yara_rules: std::collections::HashSet<String>,
    hydradragon_static_rules_dir: PathBuf,
    hydradragon_static_rules_marker: Option<u128>,
    hydradragon_static_last_reload: Instant,
    hydradragon_static_detection_mode: StaticDetectionMode,
    hydradragon_static_engine: Option<EngineCore>,
    _scan_request_handle: thread::JoinHandle<()>,
    _av_to_edr_listener_handle: thread::JoinHandle<()>,
}

fn load_excluded_rules() -> std::collections::HashSet<String> {
    let mut rules = std::collections::HashSet::new();
    let path = r"C:\Program Files\HydraDragonAntivirus\hydradragon\excluded_yara_rules\excluded_yara_rules.txt";
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                rules.insert(trimmed.to_string());
            }
        }
    }
    rules
}

fn load_yara_x_rules() -> Option<yara_x::Rules> {
    let rules_folder = r"C:\Program Files\HydraDragonAntivirus\hydradragon\yara-x\";
    if !std::path::Path::new(rules_folder).exists() {
        return None;
    }

    let mut compiler = yara_x::Compiler::new();
    let mut added = false;

    if let Ok(entries) = std::fs::read_dir(rules_folder) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yar") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Err(e) = compiler.add_source(content.as_str()) {
                        crate::logging::Logging::error(&format!(
                            "Failed to compile YARA rule {}: {:?}",
                            path.display(),
                            e
                        ));
                    } else {
                        added = true;
                    }
                }
            }
        }
    }

    if added { Some(compiler.build()) } else { None }
}

fn scan_yara_x_metadata(
    rules: Option<&yara_x::Rules>,
    excluded_yara_rules: &std::collections::HashSet<String>,
    scan_target: &Path,
) -> (Vec<String>, bool) {
    let Some(rules) = rules else {
        return (Vec::new(), false);
    };

    let data = match std::fs::read(scan_target) {
        Ok(data) => data,
        Err(error) => {
            Logging::debug(&format!(
                "[YARA-X] Failed to read {} for scan: {}",
                scan_target.display(),
                error
            ));
            return (Vec::new(), false);
        }
    };

    let mut matches = Vec::new();
    let mut is_vmprotect = false;
    let mut scanner = yara_x::Scanner::new(rules);

    match scanner.scan(&data) {
        Ok(scan_results) => {
            for matching_rule in scan_results.matching_rules() {
                let id = matching_rule.identifier().to_string();
                let id_lower = id.to_ascii_lowercase();

                // VMProtect is metadata derived from all matched rules.
                // Excluded rules only control reportable yara_x_matches.
                if id_lower.contains("vmprotect") {
                    is_vmprotect = true;
                }

                if excluded_yara_rules.contains(&id) {
                    continue;
                }

                matches.push(id);
            }
        }
        Err(error) => {
            Logging::debug(&format!(
                "[YARA-X] Scan failed for {}: {:?}",
                scan_target.display(),
                error
            ));
        }
    }

    (matches, is_vmprotect)
}

fn default_program_files_static_rules_dir() -> Option<PathBuf> {
    std::env::var("ProgramFiles").ok().map(|program_files| {
        PathBuf::from(program_files)
            .join("HydraDragonAntivirus")
            .join("hydradragon")
            .join("Owlyshield")
            .join(HYDRADRAGON_STATIC_RULES_DIR_NAME)
    })
}

fn resolve_hydradragon_static_rules_dir(config: &Config) -> PathBuf {
    if let Some(path) = config
        .get_param(Param::StaticRulesPath)
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        return PathBuf::from(path);
    }

    if let Some(path) = config
        .get_param(Param::RulesPath)
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        let rules_path = PathBuf::from(path);
        if let Some(parent) = rules_path.parent() {
            return parent.join(HYDRADRAGON_STATIC_RULES_DIR_NAME);
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        for ancestor in exe_path.ancestors() {
            if ancestor.file_name().and_then(|name| name.to_str()) == Some("Owlyshield") {
                return ancestor.join(HYDRADRAGON_STATIC_RULES_DIR_NAME);
            }
        }
    }

    default_program_files_static_rules_dir()
        .unwrap_or_else(|| PathBuf::from(HYDRADRAGON_STATIC_RULES_DIR_NAME))
}

#[cfg(target_os = "windows")]
fn read_static_rules_mode_from_registry() -> Option<String> {
    use registry::{Hive, Security};
    Hive::LocalMachine
        .open(r"SOFTWARE\Owlyshield", Security::Read)
        .ok()
        .and_then(|key| key.value("STATIC_RULES_MODE").ok())
        .map(|value| value.to_string())
}

#[cfg(not(target_os = "windows"))]
fn read_static_rules_mode_from_registry() -> Option<String> {
    None
}

fn resolve_hydradragon_static_detection_mode(config: &Config) -> StaticDetectionMode {
    let registry_mode = read_static_rules_mode_from_registry();
    StaticDetectionMode::from_config(
        registry_mode
            .as_deref()
            .or_else(|| config.get_param(Param::StaticRulesMode)),
    )
}

fn collect_hydradragon_static_rule_files(dir: &Path) -> Vec<PathBuf> {
    if dir.is_file() {
        return vec![dir.to_path_buf()];
    }

    if !dir.is_dir() {
        return Vec::new();
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yaml" | "yml")
                )
        })
        .collect();

    files.sort_by(|a, b| {
        let rank = |path: &Path| match path.file_name().and_then(|name| name.to_str()) {
            Some("engine_static_rules.yaml") => 0,
            Some("engine_static_rules.yml") => 1,
            Some("user_static_rules.yaml") => 2,
            Some("user_static_rules.yml") => 3,
            _ => 10,
        };

        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.file_name().cmp(&b.file_name()))
    });

    files
}

fn hydradragon_static_rules_marker(dir: &Path, files: &[PathBuf]) -> Option<u128> {
    if !dir.exists() {
        return None;
    }

    let mut marker = files.len() as u128;
    for path in files {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        marker = marker
            .wrapping_mul(16_777_619)
            .wrapping_add(modified)
            .wrapping_add(metadata.len() as u128);
    }

    Some(marker)
}

fn load_hydradragon_static_engine(dir: &Path) -> (Option<EngineCore>, Option<u128>) {
    let files = collect_hydradragon_static_rule_files(dir);
    let marker = hydradragon_static_rules_marker(dir, &files);
    if files.is_empty() {
        Logging::debug(&format!(
            "[HydraDragonStatic] No static rule files found in {}",
            dir.display()
        ));
        return (None, marker);
    }

    let mut rules = RuleSet::empty();
    let mut loaded_files = 0usize;
    for path in &files {
        match RuleSet::from_yaml_file(path) {
            Ok(file_rules) => {
                loaded_files += 1;
                rules.extend(file_rules);
            }
            Err(error) => {
                Logging::error(&format!(
                    "[HydraDragonStatic] Failed to load static rule file {}: {error:#}",
                    path.display()
                ));
            }
        }
    }

    if rules.rules().is_empty() {
        Logging::warning(&format!(
            "[HydraDragonStatic] Static rules directory loaded but no signatures are active: {}",
            dir.display()
        ));
        return (None, marker);
    }

    let mut options = ScanOptions::default();
    options.parallel_rules = true;
    options.stop_on_detection = false;
    options.core_options.load_simple = true;
    options.core_options.break_archive_scan = true;
    options.unpack_config.break_on_threat = true;

    let signature_records = rules.rules().len();
    let engine = EngineCore::init(rules, options);
    Logging::info(&format!(
        "[HydraDragonStatic] Loaded {signature_records} static signature(s) from {loaded_files} file(s) in {}",
        dir.display()
    ));

    (Some(engine), marker)
}

fn hydradragon_static_match_names(
    report: &ScanReport,
    detection_mode: StaticDetectionMode,
) -> Vec<String> {
    if !detection_mode.includes(report.verdict) {
        return Vec::new();
    }

    let mut names = Vec::new();
    for finding in report
        .findings
        .iter()
        .filter(|finding| detection_mode.includes(finding.verdict))
    {
        let name = hydradragon_static_finding_name(finding);
        if !names.iter().any(|existing| existing == &name) {
            names.push(name);
        }
        if names.len() >= 8 {
            break;
        }
    }

    if names.is_empty() {
        if let Some(threat_name) = &report.threat_name {
            names.push(threat_name.clone());
        } else {
            names.push("HydraDragonStatic.Heuristic".to_string());
        }
    }

    names
}

fn hydradragon_static_finding_name(finding: &hydradragonstatic::models::Finding) -> String {
    finding
        .family
        .clone()
        .unwrap_or_else(|| finding.rule_id.clone())
}

fn hydradragon_static_match_details(
    report: &ScanReport,
    detection_mode: StaticDetectionMode,
) -> Vec<String> {
    if !detection_mode.includes(report.verdict) {
        return Vec::new();
    }

    let mut details = Vec::new();
    for finding in report
        .findings
        .iter()
        .filter(|finding| detection_mode.includes(finding.verdict))
    {
        let mut rows = vec![
            "Engine=HydraDragonStatic".to_string(),
            format!("File={}", report.path.display()),
            format!("FileSize={}", report.file_size),
            format!("Entropy={:.3}", report.entropy),
            format!("SHA256={}", report.hashes.sha256),
            format!("MD5={}", report.hashes.md5),
            format!("ReportVerdict={}", report.verdict.label()),
            format!("ReportConfidence={}", report.confidence),
            format!("ReportScore={}", report.score),
            format!("RuleId={}", finding.rule_id),
            format!("RuleTitle={}", finding.title),
            format!("RuleDescription={}", finding.description),
            format!("RuleSeverity={:?}", finding.severity),
            format!("RuleVerdict={}", finding.verdict.label()),
            format!("RuleConfidence={}", finding.confidence),
            format!("RuleScore={}", finding.score),
            format!("ThreatName={}", hydradragon_static_finding_name(finding)),
        ];

        if !finding.tags.is_empty() {
            rows.push(format!("Tags={}", finding.tags.join(", ")));
        }
        if !finding.evidence.is_empty() {
            rows.push("MatchedEvidence:".to_string());
            rows.extend(
                finding
                    .evidence
                    .iter()
                    .map(|evidence| format!("  - {evidence}")),
            );
        }
        rows.push(format!(
            "FileType=primary:{} tags:{}",
            report.file_type.primary,
            report.file_type.tags.join(",")
        ));
        if let Some(pe) = &report.pe {
            rows.push(format!(
                "PE=arch:{} entry:0x{:X} image_base:0x{:X} imports:{} dlls:{} suspicious_imports:{} likely_packed:{}",
                pe.arch,
                pe.entry,
                pe.image_base,
                pe.imports.len(),
                pe.dlls.len(),
                pe.suspicious_imports.join(", "),
                pe.likely_packed
            ));
            if !pe.suspicious_sections.is_empty() {
                rows.push(format!(
                    "SuspiciousSections={}",
                    pe.suspicious_sections.join(", ")
                ));
            }
        }
        if !report.env_hits.is_empty() {
            rows.push(format!(
                "EnvHits={}",
                report
                    .env_hits
                    .iter()
                    .map(|hit| format!("{}:{}", hit.name, hit.reason))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }
        if !report.registry_hits.is_empty() {
            rows.push(format!(
                "RegistryHits={}",
                report
                    .registry_hits
                    .iter()
                    .map(|hit| format!("{}:{}", hit.key_or_value, hit.reason))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }

        details.push(rows.join("\n"));
    }

    if details.is_empty() {
        if let Some(threat_name) = &report.threat_name {
            details.push(format!(
                "Engine=HydraDragonStatic\nFile={}\nReportVerdict={}\nReportConfidence={}\nReportScore={}\nThreatName={}",
                report.path.display(),
                report.verdict.label(),
                report.confidence,
                report.score,
                threat_name
            ));
        }
    }

    details
}

fn scan_with_hydradragon_static(
    engine: &EngineCore,
    path: &Path,
    detection_mode: StaticDetectionMode,
) -> (Vec<String>, Vec<String>) {
    match engine.scan_path(path) {
        Ok(report) => (
            hydradragon_static_match_names(&report, detection_mode),
            hydradragon_static_match_details(&report, detection_mode),
        ),
        Err(error) => {
            Logging::debug(&format!(
                "[HydraDragonStatic] Scan skipped for {}: {error:#}",
                path.display()
            ));
            (Vec::new(), Vec::new())
        }
    }
}

fn hydradragon_static_service_result(
    matches: &[String],
    match_details: &[String],
) -> Option<RustServiceScanResult> {
    let virus_name = matches
        .iter()
        .find(|name| !name.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "HydraDragonStatic.Malware".to_string());

    (!matches.is_empty()).then(|| RustServiceScanResult {
        engine: "HydraDragonStatic".to_string(),
        malicious: true,
        virus_name,
        match_details: (!match_details.is_empty()).then(|| match_details.join("\n\n")),
        is_vmprotect: false,
        error: None,
    })
}

fn append_hydradragon_static_result(
    results: &mut Vec<RustServiceScanResult>,
    matches: &[String],
    match_details: &[String],
) {
    if let Some(result) = hydradragon_static_service_result(matches, match_details) {
        results.insert(0, result);
    }
}

fn yara_x_service_result(matches: &[String], is_vmprotect: bool) -> Option<RustServiceScanResult> {
    let reportable_matches: Vec<String> = matches
        .iter()
        .filter(|name| !name.trim().is_empty())
        .cloned()
        .collect();

    if reportable_matches.is_empty() {
        return None;
    }

    let virus_name = reportable_matches
        .first()
        .cloned()
        .unwrap_or_else(|| "YARA-X.Match".to_string());

    Some(RustServiceScanResult {
        engine: "Owlyshield/YARA-X".to_string(),
        malicious: true,
        virus_name,
        match_details: Some(format!(
            "Owlyshield/YARA-X matched rule(s): {}",
            reportable_matches.join(", ")
        )),
        is_vmprotect,
        error: None,
    })
}

fn append_yara_x_result(
    results: &mut Vec<RustServiceScanResult>,
    matches: &[String],
    is_vmprotect: bool,
) {
    if let Some(result) = yara_x_service_result(matches, is_vmprotect) {
        results.insert(0, result);
    }
}

fn spawn_manual_scan_listener(
    internal_scan_tx: Sender<EDRScanRequest>,
    hydradragon_static_rules_dir: PathBuf,
    hydradragon_static_detection_mode: StaticDetectionMode,
    driver: crate::windows::edrsvc_client::Driver,
) -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        let pipe_name_c = match CString::new(r"\\.\pipe\Global\owlyshield_manual_scan") {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("[ManualScan] Invalid pipe name: {}", e));
                return;
            }
        };

        let mut pipe_security = create_pipe_security_attributes("[ManualScan]");
        let mut manual_scan_rules_loaded = false;
        let mut yara_rules = None;
        let mut excluded_yara_rules = std::collections::HashSet::new();
        let mut hydradragon_static_engine = None;
        let mut hydradragon_static_rules_marker_state = None;
        let mut hydradragon_static_last_reload = Instant::now();

        let threat_settings = match ThreatResponseSettings::new() {
            Ok(settings) => Some(settings),
            Err(e) => {
                Logging::error(&format!(
                    "[ManualScan] Failed to load threat response settings: {}",
                    e
                ));
                None
            }
        };

        let threat_handler = WindowsThreatHandler::from(driver);

        Logging::info(
            "[ManualScan] Listener started on \\\\.\\pipe\\Global\\owlyshield_manual_scan",
        );
        loop {
            if manual_scan_rules_loaded
                && hydradragon_static_last_reload.elapsed()
                    >= HYDRADRAGON_STATIC_RULE_RELOAD_INTERVAL
            {
                hydradragon_static_last_reload = Instant::now();
                let files = collect_hydradragon_static_rule_files(&hydradragon_static_rules_dir);
                let marker = hydradragon_static_rules_marker(&hydradragon_static_rules_dir, &files);
                if marker != hydradragon_static_rules_marker_state {
                    let (engine, new_marker) =
                        load_hydradragon_static_engine(&hydradragon_static_rules_dir);
                    hydradragon_static_engine = engine;
                    hydradragon_static_rules_marker_state = new_marker;
                }
            }

            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_READ_BUFFER_SIZE,
                PIPE_READ_BUFFER_SIZE,
                0,
                pipe_security.as_mut().map(|attributes| attributes.as_ptr()),
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("[ManualScan] CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                Logging::error(&format!(
                    "[ManualScan] CreateNamedPipeA returned invalid handle: {:?}",
                    GetLastError()
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let connect_err = GetLastError();
            if connect_ok.as_bool() || connect_err == ERROR_PIPE_CONNECTED {
                if !validate_sanctum_manual_scan_client(pipe_handle) {
                    Logging::error("[ManualScan] Rejected unauthorized client connection");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }

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
                    let message = String::from_utf8_lossy(&buffer[..bytes_read as usize])
                        .trim()
                        .to_string();
                    match serde_json::from_str::<serde_json::Value>(&message) {
                        Ok(value) => {
                            if let Some(file_path) = value.get("file_path").and_then(|v| v.as_str())
                            {
                                let normalized_file_path = normalize_nt_path(file_path);
                                let scan_target = PathBuf::from(&normalized_file_path);
                                if file_is_over_scan_limit(&scan_target) {
                                    log_skip_large_file("manual scan pipe request", &scan_target);
                                    let response = serde_json::json!({
                                        "status": "error",
                                        "message": "file is over scan size limit",
                                        "file_path": normalized_file_path,
                                    })
                                    .to_string();
                                    let _ = write_pipe_bytes(
                                        pipe_handle,
                                        format!("{response}\n").as_bytes(),
                                        "ManualScan oversized-file response",
                                    );
                                    let _ = DisconnectNamedPipe(pipe_handle);
                                    let _ = CloseHandle(pipe_handle);
                                    continue;
                                }
                                let scan_mode = value
                                    .get("scan_mode")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("minimal")
                                    .to_string();
                                let requested_deep_scan = is_deep_scan_mode(&scan_mode);
                                let requested_timeout_ms = value
                                    .get("deep_scan_timeout_ms")
                                    .and_then(|v| v.as_u64())
                                    .filter(|v| *v > 0)
                                    .unwrap_or(if requested_deep_scan {
                                        DEEP_SCAN_TIMEOUT_MS
                                    } else {
                                        MINIMAL_SCAN_TIMEOUT_MS
                                    });
                                let requested_grace_ms = value
                                    .get("late_child_scan_grace_ms")
                                    .and_then(|v| v.as_u64())
                                    .filter(|v| *v > 0)
                                    .unwrap_or(LATE_CHILD_SCAN_GRACE_MS);
                                let scan_origin_path = value
                                    .get("scan_origin_path")
                                    .and_then(|v| v.as_str())
                                    .map(normalize_nt_path)
                                    .unwrap_or_else(|| normalized_file_path.clone());

                                if !manual_scan_rules_loaded {
                                    excluded_yara_rules = load_excluded_rules();
                                    yara_rules = load_yara_x_rules();
                                    let (engine, marker) = load_hydradragon_static_engine(
                                        &hydradragon_static_rules_dir,
                                    );
                                    hydradragon_static_engine = engine;
                                    hydradragon_static_rules_marker_state = marker;
                                    hydradragon_static_last_reload = Instant::now();
                                    manual_scan_rules_loaded = true;
                                }

                                let (hydradragon_static_matches, hydradragon_static_match_details) =
                                    if let Some(engine) = &hydradragon_static_engine {
                                        scan_with_hydradragon_static(
                                            engine,
                                            &scan_target,
                                            hydradragon_static_detection_mode,
                                        )
                                    } else {
                                        (Vec::new(), Vec::new())
                                    };
                                let (yara_x_matches, is_vmprotect) = scan_yara_x_metadata(
                                    yara_rules.as_ref(),
                                    &excluded_yara_rules,
                                    &scan_target,
                                );
                                let detectiteasy_scan_result = run_detectiteasy_metadata_scan(
                                    &normalized_file_path,
                                    &scan_target,
                                );
                                if let Some(detection_name) =
                                    detectiteasy_malware_name(&detectiteasy_scan_result)
                                {
                                    let action_result =
                                        quarantine_detectiteasy_malware_with_handler(
                                            &threat_handler,
                                            &normalized_file_path,
                                            &detection_name,
                                        );
                                    let threat_response = serde_json::json!({
                                        "status": "threat_detected",
                                        "file_path": &normalized_file_path,
                                        "detection_name": &detection_name,
                                        "engine": "DetectItEasy",
                                        "recommended_action": "kill_and_quarantine",
                                        "trust_level": 100,
                                    })
                                    .to_string();
                                    let _ = write_pipe_bytes(
                                        pipe_handle,
                                        format!("{threat_response}\n").as_bytes(),
                                        "ManualScan DetectItEasy threat_detected response",
                                    );
                                    let action_result_response = serde_json::json!({
                                        "status": "action_executed",
                                        "file_path": &normalized_file_path,
                                        "action": "kill_and_quarantine",
                                        "result": action_result,
                                    })
                                    .to_string();
                                    let _ = write_pipe_bytes(
                                        pipe_handle,
                                        format!("{action_result_response}\n").as_bytes(),
                                        "ManualScan DetectItEasy action_executed response",
                                    );
                                    let _ = DisconnectNamedPipe(pipe_handle);
                                    let _ = CloseHandle(pipe_handle);
                                    continue;
                                }
                                let fast_detected = !hydradragon_static_matches.is_empty()
                                    || !yara_x_matches.is_empty();
                                let effective_scan_mode = if fast_detected {
                                    "minimal"
                                } else if requested_deep_scan {
                                    "deep"
                                } else {
                                    "minimal"
                                };
                                let deep_scan = effective_scan_mode == "deep";
                                let mut rust_service_scan_results = if deep_scan {
                                    Vec::new()
                                } else {
                                    collect_minimal_service_scan_results(&normalized_file_path)
                                };
                                append_yara_x_result(
                                    &mut rust_service_scan_results,
                                    &yara_x_matches,
                                    is_vmprotect,
                                );
                                append_hydradragon_static_result(
                                    &mut rust_service_scan_results,
                                    &hydradragon_static_matches,
                                    &hydradragon_static_match_details,
                                );

                                if let Some(ref settings) = threat_settings {
                                    let mut threat_detected = false;
                                    let mut detection_engine = String::new();
                                    let mut detection_name = String::new();
                                    let mut recommended_action = String::new();
                                    let mut trust_level = 0u8;
                                    let mut current_action =
                                        SettingsThreatAction::KillAndQuarantine;

                                    if !hydradragon_static_matches.is_empty() {
                                        threat_detected = true;
                                        detection_engine = "HydraDragonStatic".to_string();
                                        detection_name = hydradragon_static_matches.join(", ");
                                        let engine_config = settings
                                            .get_engine_config(DetectionEngine::HydraDragonStatic);
                                        recommended_action =
                                            engine_config.action.as_str().to_string();
                                        trust_level = engine_config.trust_level;
                                        current_action = engine_config.action;
                                    } else if !yara_x_matches.is_empty() {
                                        threat_detected = true;
                                        detection_engine = "YaraX".to_string();
                                        detection_name = yara_x_matches.join(", ");
                                        let engine_config =
                                            settings.get_engine_config(DetectionEngine::YaraX);
                                        recommended_action =
                                            engine_config.action.as_str().to_string();
                                        trust_level = engine_config.trust_level;
                                        current_action = engine_config.action;
                                    } else if let Some(clamav_result) = rust_service_scan_results
                                        .iter()
                                        .find(|r| r.engine == "ClamAV" && r.malicious)
                                    {
                                        threat_detected = true;
                                        detection_engine = "ClamAV".to_string();
                                        detection_name = clamav_result.virus_name.clone();
                                        let engine_config =
                                            settings.get_engine_config(DetectionEngine::ClamAV);
                                        recommended_action =
                                            engine_config.action.as_str().to_string();
                                        trust_level = engine_config.trust_level;
                                        current_action = engine_config.action;
                                    }

                                    if threat_detected
                                        && settings.should_act_on_detection(match detection_engine
                                            .as_str()
                                        {
                                            "ClamAV" => DetectionEngine::ClamAV,
                                            "YaraX" => DetectionEngine::YaraX,
                                            "HydraDragonStatic" => {
                                                DetectionEngine::HydraDragonStatic
                                            }
                                            _ => DetectionEngine::ClamAV,
                                        })
                                    {
                                        Logging::info(&format!(
                                            "[ManualScan] Threat detected by {}: {} in file: {}",
                                            detection_engine, detection_name, normalized_file_path
                                        ));

                                        let threat_response = serde_json::json!({
                                            "status": "threat_detected",
                                            "file_path": normalized_file_path,
                                            "detection_name": detection_name,
                                            "engine": detection_engine,
                                            "recommended_action": recommended_action,
                                            "trust_level": trust_level,
                                        })
                                        .to_string();

                                        let _ = write_pipe_bytes(
                                            pipe_handle,
                                            format!("{threat_response}\n").as_bytes(),
                                            "ManualScan threat_detected response",
                                        );

                                        let action_result = apply_manual_scan_threat_action(
                                            &threat_handler,
                                            current_action,
                                            &normalized_file_path,
                                            &detection_engine,
                                            &detection_name,
                                        );

                                        let action_result_response = serde_json::json!({
                                            "status": "action_executed",
                                            "file_path": normalized_file_path,
                                            "action": recommended_action,
                                            "result": action_result,
                                        })
                                        .to_string();

                                        let _ = write_pipe_bytes(
                                            pipe_handle,
                                            format!("{action_result_response}\n").as_bytes(),
                                            "ManualScan action_executed response",
                                        );
                                    }
                                }

                                let request = EDRScanRequest {
                                    event_type: "MANUAL_SCAN_REQUEST".to_string(),
                                    file_path: normalized_file_path,
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                    pid: None,
                                    additional_context: None,
                                    signature_status: None, // Skipped for manual scans via pipe
                                    yara_x_matches: Some(yara_x_matches),
                                    is_vmprotect,
                                    deep_scan,
                                    scan_mode: effective_scan_mode.to_string(),
                                    detectiteasy_scan_result: None,
                                    scan_origin_path: Some(scan_origin_path),
                                    deep_scan_timeout_ms: Some(requested_timeout_ms),
                                    late_child_scan_grace_ms: Some(requested_grace_ms),
                                    rust_service_scan_results,
                                };

                                let ack_scan_mode = request.scan_mode.clone();
                                let ack_file_path = request.file_path.clone();

                                Logging::info(&format!(
                                    "[ManualScan] Queueing {} manual scan for: {}",
                                    request.scan_mode, request.file_path
                                ));

                                match internal_scan_tx.send(request) {
                                    Ok(()) => {
                                        let response = serde_json::json!({
                                            "status": "queued",
                                            "scan_mode": ack_scan_mode,
                                            "file_path": ack_file_path,
                                        })
                                        .to_string();
                                        let _ = write_pipe_bytes(
                                            pipe_handle,
                                            format!("{response}\n").as_bytes(),
                                            "ManualScan queued response",
                                        );
                                    }
                                    Err(error) => {
                                        Logging::error(&format!(
                                            "[ManualScan] Failed to queue manual scan request: {error}"
                                        ));
                                        let response = serde_json::json!({
                                            "status": "error",
                                            "message": format!("failed to queue manual scan request: {error}"),
                                            "file_path": ack_file_path,
                                        })
                                        .to_string();
                                        let _ = write_pipe_bytes(
                                            pipe_handle,
                                            format!("{response}\n").as_bytes(),
                                            "ManualScan queue-error response",
                                        );
                                    }
                                }
                            } else {
                                Logging::error(&format!(
                                    "[ManualScan] Request missing file_path field: {message}"
                                ));
                                let response = serde_json::json!({
                                    "status": "error",
                                    "message": "request missing file_path field",
                                })
                                .to_string();
                                let _ = write_pipe_bytes(
                                    pipe_handle,
                                    format!("{response}\n").as_bytes(),
                                    "ManualScan missing-file-path response",
                                );
                            }
                        }
                        Err(error) => {
                            Logging::error(&format!(
                                "[ManualScan] Invalid request JSON: {error}; raw={message}"
                            ));
                            let response = serde_json::json!({
                                "status": "error",
                                "message": format!("invalid request JSON: {error}"),
                            })
                            .to_string();
                            let _ = write_pipe_bytes(
                                pipe_handle,
                                format!("{response}\n").as_bytes(),
                                "ManualScan invalid-json response",
                            );
                        }
                    }
                } else if !read_ok.as_bool() {
                    Logging::error(&format!(
                        "[ManualScan] ReadFile failed (GetLastError={:?})",
                        GetLastError()
                    ));
                }
                let _ = DisconnectNamedPipe(pipe_handle);
            }
            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    })
}

impl<'a> AVIntegration<'a> {
    /// Create new AVIntegration instance
    pub fn new(
        config: &'a Config,
        predictor_malware: PredictorMalware,
        driver: crate::windows::edrsvc_client::Driver,
    ) -> Self {
        let (internal_scan_tx, internal_scan_rx) = channel::<EDRScanRequest>();

        let scan_request_handle = thread::spawn(move || {
            scan_request_server_loop(internal_scan_rx);
        });
        let av_to_edr_listener_handle = spawn_av_to_edr_listener();
        let _mbr_listener_handle = spawn_mbr_alert_listener();

        // Spawn Dump Receiver for MegaDumper/Exorcism
        crate::hydradragon::dump_receiver::start_dump_receiver_pipe(internal_scan_tx.clone());

        let hydradragon_static_rules_dir = resolve_hydradragon_static_rules_dir(config);
        let hydradragon_static_detection_mode = resolve_hydradragon_static_detection_mode(config);
        let _manual_scan_listener_handle = spawn_manual_scan_listener(
            internal_scan_tx.clone(),
            hydradragon_static_rules_dir.clone(),
            hydradragon_static_detection_mode,
            driver,
        );
        let (hydradragon_static_engine, hydradragon_static_rules_marker) =
            load_hydradragon_static_engine(&hydradragon_static_rules_dir);

        AVIntegration {
            config, // <-- MODIFIED: Assigns the borrow
            predictor_malware,
            internal_scan_tx,
            signature_cache: HashMap::new(),
            scan_metadata_cache: HashMap::new(),
            tinyav_recent_scans: HashMap::new(),
            tinyav_missing_logged: false,
            yara_rules: load_yara_x_rules(),
            excluded_yara_rules: load_excluded_rules(),
            hydradragon_static_rules_dir,
            hydradragon_static_rules_marker,
            hydradragon_static_last_reload: Instant::now(),
            hydradragon_static_detection_mode,
            hydradragon_static_engine,
            _scan_request_handle: scan_request_handle,
            _av_to_edr_listener_handle: av_to_edr_listener_handle,
        }
    }

    fn reload_hydradragon_static_rules_if_changed(&mut self) {
        if self.hydradragon_static_last_reload.elapsed() < HYDRADRAGON_STATIC_RULE_RELOAD_INTERVAL {
            return;
        }

        self.hydradragon_static_last_reload = Instant::now();
        let detection_mode = resolve_hydradragon_static_detection_mode(self.config);
        if detection_mode != self.hydradragon_static_detection_mode {
            self.hydradragon_static_detection_mode = detection_mode;
            self.scan_metadata_cache.clear();
        }

        let files = collect_hydradragon_static_rule_files(&self.hydradragon_static_rules_dir);
        let marker = hydradragon_static_rules_marker(&self.hydradragon_static_rules_dir, &files);
        if marker == self.hydradragon_static_rules_marker {
            return;
        }

        let (engine, marker) = load_hydradragon_static_engine(&self.hydradragon_static_rules_dir);
        self.hydradragon_static_engine = engine;
        self.hydradragon_static_rules_marker = marker;
        self.scan_metadata_cache.clear();
    }

    /// Process a single threat event according to its configured action
    pub fn process_threat_action(
        &self,
        event: &AVThreatEvent,
        precord: &mut ProcessRecord,
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

        let virus_name = if event.virus_name.is_empty() {
            &event.detection_type
        } else {
            &event.virus_name
        };
        let match_details = event.match_details.clone().or_else(|| {
            Some(format!(
                "DetectionType={} VirusName={} File={} Action={}",
                event.detection_type,
                virus_name,
                event.file_path,
                event.action_required.as_str()
            ))
        });

        precord.is_malicious = event.is_malicious;
        precord.termination_requested = event.action_required != ThreatAction::Monitor;
        precord.quarantine_requested = event.action_required == ThreatAction::KillAndQuarantine;
        precord.kill_and_remove_requested = event.action_required == ThreatAction::KillAndRemove;
        precord.notify_user_requested = true;
        precord.triggered_rule_name = Some(virus_name.to_string());
        precord.triggered_rule_details = match_details.clone();
        if precord.remediation_target_path.is_none() && !event.file_path.trim().is_empty() {
            precord.remediation_target_path = Some(PathBuf::from(&event.file_path));
        }

        let threat_info = ThreatInfo {
            threat_type_label: threat_label,
            virus_name,
            prediction: prediction_behavioral,
            match_details,
            deny_access: false,
            terminate: event.action_required != ThreatAction::Monitor,
            quarantine: event.action_required == ThreatAction::KillAndQuarantine,
            kill_and_remove: event.action_required == ThreatAction::KillAndRemove,
            suspend: false,
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
                    threat_label,
                    prediction_behavioral * 100.0,
                    precord.gid
                ));
            }
            ThreatAction::KillAndQuarantine => {
                Logging::info(&format!(
                    "Threat detected [{}] - Action: KILL AND QUARANTINE - Path: {}",
                    event.virus_name, event.file_path
                ));
                Logging::info(&format!(
                    "   Type: {} | Certainty: {:.2}% | GID: {}",
                    threat_label,
                    prediction_behavioral * 100.0,
                    precord.gid
                ));
            }
            ThreatAction::KillAndRemove => {
                Logging::info(&format!(
                    "Threat detected [{}] - Action: KILL AND REMOVE - Path: {}",
                    event.virus_name, event.file_path
                ));
                Logging::info(&format!(
                    "   Type: {} | Certainty: {:.2}% | GID: {}",
                    threat_label,
                    prediction_behavioral * 100.0,
                    precord.gid
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
        let scan_target = scan_target_for_iomsg(iomsg, precord);
        let file_path = scan_target.to_string_lossy().to_string();

        if is_openedr_cloud_safe(&file_path) {
            return;
        }
        if file_is_over_scan_limit(&scan_target) {
            log_skip_large_file("minimal scan request", &scan_target);
            return;
        }

        let metadata = self.collect_scan_metadata(&file_path, &scan_target, "minimal");
        if !metadata.should_queue_scan {
            return;
        }
        let mut rust_service_scan_results = collect_minimal_service_scan_results(&file_path);
        append_yara_x_result(
            &mut rust_service_scan_results,
            &metadata.yara_x_matches,
            metadata.is_vmprotect,
        );
        append_hydradragon_static_result(
            &mut rust_service_scan_results,
            &metadata.hydradragon_static_matches,
            &metadata.hydradragon_static_match_details,
        );

        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path: file_path.clone(),
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: false,
            scan_mode: "minimal".to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
            scan_origin_path: Some(file_path.clone()),
            deep_scan_timeout_ms: timeout_for_scan_mode(self.config, "minimal"),
            late_child_scan_grace_ms: Some(
                self.config
                    .late_child_scan_grace_ms(LATE_CHILD_SCAN_GRACE_MS),
            ),
            rust_service_scan_results,
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send internal scan request: {}", e));
        }
    }

    pub fn queue_deep_scan_request(
        &mut self,
        file_path: &Path,
        pid: Option<u32>,
        additional_context: Option<String>,
    ) {
        let file_path_string = file_path.to_string_lossy().to_string();
        if file_path_string.trim().is_empty()
            || is_openedr_cloud_safe(&file_path_string)
            || !file_path.is_file()
        {
            return;
        }
        if file_is_over_scan_limit(file_path) {
            log_skip_large_file("deep scan request", file_path);
            return;
        }

        let metadata = self.collect_scan_metadata(&file_path_string, file_path, "deep");
        if !metadata.should_queue_scan {
            return;
        }

        let fast_detected =
            !metadata.hydradragon_static_matches.is_empty() || !metadata.yara_x_matches.is_empty();

        // Sanctum requests deep scan when process behavior is suspicious.
        // If a fast detector already found malware, report that detection and skip deep scan.
        let effective_scan_mode = if fast_detected { "minimal" } else { "deep" };

        // Always scan with HydraDragonAV service (ClamAV/YARA)
        let mut rust_service_scan_results = collect_minimal_service_scan_results(&file_path_string);
        append_yara_x_result(
            &mut rust_service_scan_results,
            &metadata.yara_x_matches,
            metadata.is_vmprotect,
        );
        append_hydradragon_static_result(
            &mut rust_service_scan_results,
            &metadata.hydradragon_static_matches,
            &metadata.hydradragon_static_match_details,
        );

        maybe_spawn_python_hook(pid, &metadata.detectiteasy_scan_result);

        let request = EDRScanRequest {
            event_type: "SANCTUM_DEEP_SCAN_REQUEST".to_string(),
            file_path: file_path_string.clone(),
            timestamp: Utc::now().to_rfc3339(),
            pid,
            additional_context,
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: !fast_detected,
            scan_mode: effective_scan_mode.to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
            scan_origin_path: Some(file_path_string.clone()),
            deep_scan_timeout_ms: timeout_for_scan_mode(self.config, effective_scan_mode),
            late_child_scan_grace_ms: Some(
                self.config
                    .late_child_scan_grace_ms(LATE_CHILD_SCAN_GRACE_MS),
            ),
            rust_service_scan_results,
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send Sanctum deep scan request: {}", e));
        }
    }

    pub fn queue_process_start_scan_request(
        &mut self,
        file_path: &Path,
        pid: Option<u32>,
        additional_context: Option<String>,
    ) {
        let file_path_string = file_path.to_string_lossy().to_string();
        if file_path_string.trim().is_empty()
            || is_openedr_cloud_safe(&file_path_string)
            || !file_path.is_file()
        {
            return;
        }
        if file_is_over_scan_limit(file_path) {
            log_skip_large_file("process start scan request", file_path);
            return;
        }

        let metadata = self.collect_scan_metadata(&file_path_string, file_path, "deep");
        if !metadata.should_queue_scan {
            return;
        }

        let fast_detected =
            !metadata.hydradragon_static_matches.is_empty() || !metadata.yara_x_matches.is_empty();
        let effective_scan_mode = if fast_detected { "minimal" } else { "deep" };

        let mut rust_service_scan_results = collect_minimal_service_scan_results(&file_path_string);
        append_yara_x_result(
            &mut rust_service_scan_results,
            &metadata.yara_x_matches,
            metadata.is_vmprotect,
        );
        append_hydradragon_static_result(
            &mut rust_service_scan_results,
            &metadata.hydradragon_static_matches,
            &metadata.hydradragon_static_match_details,
        );

        maybe_spawn_python_hook(pid, &metadata.detectiteasy_scan_result);

        let request = EDRScanRequest {
            event_type: "PROCESS_START_SCAN_REQUEST".to_string(),
            file_path: file_path_string.clone(),
            timestamp: Utc::now().to_rfc3339(),
            pid,
            additional_context,
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: !fast_detected,
            scan_mode: effective_scan_mode.to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
            scan_origin_path: Some(file_path_string.clone()),
            deep_scan_timeout_ms: timeout_for_scan_mode(self.config, effective_scan_mode),
            late_child_scan_grace_ms: Some(
                self.config
                    .late_child_scan_grace_ms(LATE_CHILD_SCAN_GRACE_MS),
            ),
            rust_service_scan_results,
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send process start scan request: {}", e));
        }
    }

    pub fn queue_manual_scan_request(
        &mut self,
        file_path: &Path,
        pid: Option<u32>,
        additional_context: Option<String>,
        scan_mode: &str, // "deep" or "minimal"
    ) {
        let file_path_string = file_path.to_string_lossy().to_string();
        if file_path_string.trim().is_empty()
            || is_openedr_cloud_safe(&file_path_string)
            || !file_path.is_file()
        {
            return;
        }
        if file_is_over_scan_limit(file_path) {
            log_skip_large_file("manual scan request", file_path);
            return;
        }

        let normalized_scan_mode = if is_deep_scan_mode(scan_mode) {
            "deep"
        } else {
            "minimal"
        };
        let metadata =
            self.collect_scan_metadata(&file_path_string, file_path, normalized_scan_mode);
        if !metadata.should_queue_scan {
            return;
        }
        let fast_detected =
            !metadata.hydradragon_static_matches.is_empty() || !metadata.yara_x_matches.is_empty();

        // For manual scans, respect user's choice unless a fast detector already found malware.
        let effective_scan_mode = if fast_detected {
            "minimal"
        } else {
            normalized_scan_mode
        };

        // Always scan with HydraDragonAV service (ClamAV/YARA)
        let mut rust_service_scan_results = collect_minimal_service_scan_results(&file_path_string);
        append_yara_x_result(
            &mut rust_service_scan_results,
            &metadata.yara_x_matches,
            metadata.is_vmprotect,
        );
        append_hydradragon_static_result(
            &mut rust_service_scan_results,
            &metadata.hydradragon_static_matches,
            &metadata.hydradragon_static_match_details,
        );

        let request = EDRScanRequest {
            event_type: "MANUAL_SCAN_REQUEST".to_string(),
            file_path: file_path_string.clone(),
            timestamp: Utc::now().to_rfc3339(),
            pid,
            additional_context,
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: effective_scan_mode == "deep",
            scan_mode: effective_scan_mode.to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
            scan_origin_path: Some(file_path_string.clone()),
            deep_scan_timeout_ms: timeout_for_scan_mode(self.config, effective_scan_mode),
            late_child_scan_grace_ms: Some(
                self.config
                    .late_child_scan_grace_ms(LATE_CHILD_SCAN_GRACE_MS),
            ),
            rust_service_scan_results,
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send manual scan request: {}", e));
        }
    }

    fn collect_scan_metadata(
        &mut self,
        file_path: &str,
        scan_target: &Path,
        scan_mode: &str,
    ) -> ScanMetadata {
        self.reload_hydradragon_static_rules_if_changed();

        let file_identity = file_identity_for_path(file_path, scan_target);
        if let Some(identity) = file_identity.as_ref() {
            if let Some(cached) = self.scan_metadata_cache.get(identity) {
                Logging::debug(&format!(
                    "[AVIntegration] Reusing cached scan metadata for unchanged file: {}",
                    file_path
                ));
                return cached.clone();
            }
        }

        let mut metadata = ScanMetadata::new();
        if let Some(engine) = &self.hydradragon_static_engine {
            (
                metadata.hydradragon_static_matches,
                metadata.hydradragon_static_match_details,
            ) = scan_with_hydradragon_static(
                engine,
                scan_target,
                self.hydradragon_static_detection_mode,
            );
        }

        metadata.signature_status =
            self.get_or_compute_signature_status(file_identity.as_ref(), scan_target);

        (metadata.yara_x_matches, metadata.is_vmprotect) = scan_yara_x_metadata(
            self.yara_rules.as_ref(),
            &self.excluded_yara_rules,
            scan_target,
        );

        let deep_mode = is_deep_scan_mode(scan_mode);

        // Deep mode uses DIE as an early metadata/type gate. Python deep scan is
        // only useful for the known file families we parse from DIE output. If
        // DIE says the file is fully unknown, or it is a parsed binary/archive
        // with no supported HydraDragon type flags, do not queue deep scan.
        // Fast static/YARA-X detections bypass this gate because they are already
        // concrete malware detections.
        if deep_mode
            && metadata.hydradragon_static_matches.is_empty()
            && metadata.yara_x_matches.is_empty()
            && !should_skip_die_scan(scan_target)
        {
            metadata.detectiteasy_scan_result =
                run_detectiteasy_metadata_scan(file_path, scan_target);
            if metadata.detectiteasy_scan_result.is_none() {
                Logging::debug(&format!(
                    "[DetectItEasy] Deep scan gate skipped because DIE metadata was unavailable: {}",
                    file_path
                ));
                metadata.should_queue_scan = false;
                return self.cache_scan_metadata(file_identity.clone(), metadata);
            }

            if let Some(detection_name) =
                detectiteasy_malware_name(&metadata.detectiteasy_scan_result)
            {
                quarantine_detectiteasy_malware(file_path, &detection_name);
                metadata.should_queue_scan = false;
                return self.cache_scan_metadata(file_identity.clone(), metadata);
            }

            if die_result_is_fully_unknown(&metadata.detectiteasy_scan_result) {
                Logging::debug(&format!(
                    "[DetectItEasy] Deep scan gate skipped fully unknown DIE result: {}",
                    file_path
                ));
                metadata.should_queue_scan = false;
                return self.cache_scan_metadata(file_identity.clone(), metadata);
            }

            if die_result_is_unsupported_for_deep_scan(&metadata.detectiteasy_scan_result) {
                Logging::debug(&format!(
                    "[DetectItEasy] Deep scan gate skipped unsupported DIE type: {}",
                    file_path
                ));
                metadata.should_queue_scan = false;
                return self.cache_scan_metadata(file_identity.clone(), metadata);
            }
        }

        // Minimal mode stays fast: do not run DIE unless another detector already
        // produced a suspicious signal. Also, unknown DIE output is not forwarded
        // in minimal mode, so "unknown" cannot become a malware verdict.
        if !deep_mode
            && metadata_is_suspicious(
                &metadata.signature_status,
                &metadata.yara_x_matches,
                metadata.is_vmprotect,
            )
        {
            let die_result = run_detectiteasy_metadata_scan(file_path, scan_target);
            if let Some(detection_name) = detectiteasy_malware_name(&die_result) {
                quarantine_detectiteasy_malware(file_path, &detection_name);
                metadata.should_queue_scan = false;
                return self.cache_scan_metadata(file_identity.clone(), metadata);
            } else if die_result_is_fully_unknown(&die_result) {
                Logging::debug(&format!(
                    "[DetectItEasy] Minimal scan ignored fully unknown DIE result: {}",
                    file_path
                ));
            } else {
                metadata.detectiteasy_scan_result = die_result;
            }
        }

        self.cache_scan_metadata(file_identity, metadata)
    }

    fn cache_scan_metadata(
        &mut self,
        file_identity: Option<FileIdentity>,
        metadata: ScanMetadata,
    ) -> ScanMetadata {
        if let Some(identity) = file_identity {
            if self.scan_metadata_cache.len() >= SCAN_METADATA_CACHE_LIMIT {
                self.scan_metadata_cache.clear();
            }
            self.scan_metadata_cache.insert(identity, metadata.clone());
        }

        metadata
    }

    fn get_or_compute_signature_status(
        &mut self,
        cache_key: Option<&FileIdentity>,
        path: &std::path::Path,
    ) -> Option<FileSignatureStatus> {
        if let Some(cache_key) = cache_key {
            if let Some(existing) = self.signature_cache.get(cache_key) {
                return Some(existing.clone());
            }
        }

        if !path.exists() {
            return None;
        }

        let info = verify_signature(path);
        let status = FileSignatureStatus {
            is_trusted: info.is_trusted,
            is_signed: info.is_signed,
            signer_name: info.signer_name,
            status: info.status.as_str().to_string(),
            status_text: info.status_text,
            raw_hresult: info.raw_hresult,
            verification_failed: info.verification_failed,
            no_signature: info.no_signature,
            signature_status_issues: info.signature_status_issues,
            invalid_signature: info.invalid_signature,
        };

        if let Some(cache_key) = cache_key {
            if self.signature_cache.len() >= SCAN_METADATA_CACHE_LIMIT {
                self.signature_cache.clear();
            }
            self.signature_cache
                .insert(cache_key.clone(), status.clone());
        }

        Some(status)
    }
}

/// AV -> EDR client (one-shot): connect to AV->EDR pipe and write threat event
fn send_threat_to_edr(event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        use windows::core::PCWSTR;

        // Convert to UTF-16 for Unicode Windows API
        let mut pipe_name_wide: Vec<u16> = PIPE_AV_TO_EDR.encode_utf16().collect();
        pipe_name_wide.push(0); // Null terminator
        let pcwstr = PCWSTR(pipe_name_wide.as_ptr());

        // Wait for the pipe to become available
        let wait_ok: BOOL = WaitNamedPipeW(pcwstr, CONNECT_TIMEOUT_MS);
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
        let pipe_handle = match CreateFileW(
            pcwstr,
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
                    "Failed to connect to EDR pipe (CreateFileW error: {:?}, GetLastError={:?})",
                    e, last
                ));
                return Err(format!(
                    "Failed to connect to EDR pipe (CreateFileW error: {:?}, GetLastError={:?})",
                    e, last
                ));
            }
        };

        if pipe_handle.is_invalid() {
            let last = GetLastError();
            Logging::error(&format!(
                "CreateFileW returned invalid handle. GetLastError={:?}",
                last
            ));
            return Err(format!("CreateFileW returned invalid handle: {:?}", last));
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
            event.file_path,
            event.virus_name,
            event.action_required.as_str(),
            bytes_written
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
/// Starts multiple named-pipe server instances so minimal and deep scan requests
/// can be consumed in parallel by multiple HydraDragon/Python scan clients.
/// Each connection still receives exactly one JSON request and then reconnects.
fn scan_request_server_loop(rx: Receiver<EDRScanRequest>) {
    let worker_count = parallel_scan_request_worker_count();
    Logging::info(&format!(
        "Starting parallel pipe server (EDR->AV): {} with {} workers",
        PIPE_EDR_TO_AV, worker_count
    ));

    let shared_rx = Arc::new(Mutex::new(rx));
    let mut handles = Vec::with_capacity(worker_count);

    for worker_id in 0..worker_count {
        let worker_rx = Arc::clone(&shared_rx);
        match thread::Builder::new()
            .name(format!("edr_to_av_scan_pipe_worker_{worker_id}"))
            .spawn(move || {
                scan_request_server_worker_loop(worker_id, worker_rx);
            }) {
            Ok(handle) => handles.push(handle),
            Err(error) => Logging::error(&format!(
                "[EDR->AV] Failed to spawn scan pipe worker {}: {}",
                worker_id, error
            )),
        }
    }

    if handles.is_empty() {
        Logging::error("[EDR->AV] No scan pipe workers could be started");
        return;
    }

    for handle in handles {
        let _ = handle.join();
    }
}

fn scan_request_server_worker_loop(worker_id: usize, rx: Arc<Mutex<Receiver<EDRScanRequest>>>) {
    unsafe {
        let pipe_name_c = match CString::new(PIPE_EDR_TO_AV) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!(
                    "[EDR->AV worker {worker_id}] Invalid pipe name: {}",
                    e
                ));
                return;
            }
        };
        let mut pipe_security = create_pipe_security_attributes("[EDR->AV]");

        Logging::debug(&format!(
            "[EDR->AV worker {worker_id}] ready on {}",
            PIPE_EDR_TO_AV
        ));

        loop {
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                pipe_security.as_mut().map(|attributes| attributes.as_ptr()),
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!(
                        "[EDR->AV worker {worker_id}] CreateNamedPipeA failed: {:?}",
                        e
                    ));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                let err = GetLastError();
                Logging::error(&format!(
                    "[EDR->AV worker {worker_id}] CreateNamedPipeA returned invalid handle: {:?}",
                    err
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            Logging::debug(&format!(
                "[EDR->AV worker {worker_id}] waiting for HydraDragon client..."
            ));

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let err = GetLastError();

            if connect_ok.as_bool() || err == ERROR_PIPE_CONNECTED {
                if !validate_hydradragon_python_client(pipe_handle) {
                    Logging::error(&format!(
                        "[EDR->AV worker {worker_id}] Rejected unauthorized scan request client"
                    ));
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }

                Logging::debug(&format!(
                    "[EDR->AV worker {worker_id}] scan client connected"
                ));

                let request = {
                    let receiver_guard = match rx.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            Logging::warning(&format!(
                                "[EDR->AV worker {worker_id}] scan request queue mutex was poisoned; continuing"
                            ));
                            poisoned.into_inner()
                        }
                    };

                    match receiver_guard.recv() {
                        Ok(request) => request,
                        Err(_) => {
                            let _ = DisconnectNamedPipe(pipe_handle);
                            let _ = CloseHandle(pipe_handle);
                            return;
                        }
                    }
                };

                match write_scan_request(pipe_handle, &request) {
                    Ok(bytes_written) => Logging::debug(&format!(
                        "[EDR->AV worker {worker_id}] sent {} scan request: {} ({} bytes)",
                        request.scan_mode, request.file_path, bytes_written
                    )),
                    Err(e) => Logging::error(&format!(
                        "[EDR->AV worker {worker_id}] Failed to send scan request: {}",
                        e
                    )),
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            } else {
                Logging::error(&format!(
                    "[EDR->AV worker {worker_id}] ConnectNamedPipe failed: {:?}",
                    err
                ));
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(10));
        }
    }
}
