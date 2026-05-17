#![cfg(feature = "hydradragon")]

use std::collections::HashMap;
use std::ffi::CString;
#[cfg(windows)]
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::core::PCSTR;

use windows::Win32::Foundation::{BOOL, CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE, FlushFileBuffers,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    WaitNamedPipeA,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{HIGH_PRIORITY_CLASS, SetPriorityClass};

use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
use crate::config::Config;
use crate::driver_com::Driver;
use crate::logging::Logging;
use crate::process::ProcessRecord;
use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp};
use crate::signature_verification::verify_signature;
use crate::threat_handler::ThreatHandler;
use crate::utils::validate_pipe_client;
use crate::worker::predictor::PredictorMalware;
use chrono::Utc;

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
const TINYAV_SCAN_DEBOUNCE: Duration = Duration::from_secs(10);
const TINYAV_RECENT_SCAN_LIMIT: usize = 4096;
const TINYAV_PREFERRED_INSTALL_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\TinyAntivirus\TinyAVConsole.exe";
const HYDRADRAGON_VENV_PYTHON_EXE: &str =
    r"C:\Program Files\HydraDragonAntivirus\venv\Scripts\python.exe";
const HYDRADRAGON_BUNDLED_PYTHON_EXE: &str =
    r"C:\Program Files\HydraDragonAntivirus\python\python.exe";
const PYTHON312_SUFFIX: &str = r"python312\python.exe";

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
}

fn default_scan_mode() -> String {
    "minimal".to_string()
}


#[derive(Debug, Clone)]
struct ScanMetadata {
    signature_status: Option<FileSignatureStatus>,
    yara_x_matches: Vec<String>,
    is_vmprotect: bool,
    detectiteasy_scan_result: Option<crate::hydradragon::detectiteasy::DetectItEasyScanResult>,
    should_queue_scan: bool,
}

impl ScanMetadata {
    fn new() -> Self {
        ScanMetadata {
            signature_status: None,
            yara_x_matches: Vec::new(),
            is_vmprotect: false,
            detectiteasy_scan_result: None,
            should_queue_scan: true,
        }
    }
}

fn is_deep_scan_mode(scan_mode: &str) -> bool {
    scan_mode.trim().eq_ignore_ascii_case("deep")
}

fn signature_status_is_suspicious(status: &Option<FileSignatureStatus>) -> bool {
    status.as_ref().is_some_and(|s| {
        s.invalid_signature || s.signature_status_issues || s.verification_failed
    })
}

fn metadata_is_suspicious(
    signature_status: &Option<FileSignatureStatus>,
    yara_x_matches: &[String],
    is_vmprotect: bool,
) -> bool {
    is_vmprotect || !yara_x_matches.is_empty() || signature_status_is_suspicious(signature_status)
}

fn should_skip_die_scan(scan_target: &Path) -> bool {
    use crate::hydradragon::detectiteasy::is_plain_text_file;

    is_plain_text_file(scan_target).unwrap_or(false)
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

fn is_openedr_cloud_safe(file_path: &str) -> bool {
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
    IrpMajorOp::from_byte(iomsg.irp_op) == IrpMajorOp::IrpCreate
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
    event.pid.map(|pid| 0x8000_0000_0000_0000u64 | (pid as u64))
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
                Logging::error(&format!("[TinyAV] Failed to spawn sality disinfect worker: {}", e));
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
    use std::ffi::CString;
    use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE, FlushFileBuffers,
        OPEN_EXISTING, WriteFile,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeA;
    use windows::core::PCSTR;

    const HIPS_PIPE: &str = r"\\.\pipe\HydraHipEvent";
    const CONNECT_TIMEOUT_MS: u32 = 750;

    let pipe_name = match CString::new(HIPS_PIPE) {
        Ok(value) => value,
        Err(_) => {
            Logging::error("[MBR HIPS] Invalid HydraHipEvent pipe name");
            return;
        }
    };
    let pcstr = PCSTR(pipe_name.as_ptr() as *const u8);

    let wait_ok: BOOL = unsafe { WaitNamedPipeA(pcstr, CONNECT_TIMEOUT_MS) };
    if !wait_ok.as_bool() {
        Logging::warning(&format!(
            "[MBR HIPS] Firewall GUI pipe not ready for USB MBR alert (disk {}, GetLastError={:?})",
            disk_number,
            unsafe { GetLastError() }
        ));
        return;
    }

    let pipe_handle = unsafe {
        CreateFileA(
            pcstr,
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
            Logging::error("[MBR HIPS] CreateFileA returned invalid HydraHipEvent handle");
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
                    let parsed =
                        serde_json::from_str::<SelfDefenseAlert>(&raw_message).or_else(|_| {
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
    tinyav_recent_scans: HashMap<String, Instant>,
    tinyav_missing_logged: bool,
    yara_rules: Option<yara_x::Rules>,
    excluded_yara_rules: std::collections::HashSet<String>,
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

fn spawn_manual_scan_listener(internal_scan_tx: Sender<EDRScanRequest>) -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        let pipe_name_c = match CString::new(r"\\.\pipe\Global\owlyshield_manual_scan") {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("[ManualScan] Invalid pipe name: {}", e));
                return;
            }
        };

        Logging::info("[ManualScan] Listener started on \\\\.\\pipe\\Global\\owlyshield_manual_scan");
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
                    Logging::error(&format!("[ManualScan] CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                Logging::error(&format!("[ManualScan] CreateNamedPipeA returned invalid handle: {:?}", GetLastError()));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let connect_err = GetLastError();
            if connect_ok.as_bool() || connect_err == ERROR_PIPE_CONNECTED {
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
                    let message = String::from_utf8_lossy(&buffer[..bytes_read as usize]).trim().to_string();
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) {
                        if let Some(file_path) = value.get("file_path").and_then(|v| v.as_str()) {
                            let scan_mode = value.get("scan_mode").and_then(|v| v.as_str()).unwrap_or("minimal").to_string();
                            let deep_scan = scan_mode == "deep";
                            
                            let request = EDRScanRequest {
                                event_type: "MANUAL_SCAN_REQUEST".to_string(),
                                file_path: normalize_nt_path(file_path),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                pid: None,
                                additional_context: None,
                                signature_status: None, // Skipped for manual scans via pipe
                                yara_x_matches: None,
                                is_vmprotect: false,
                                deep_scan,
                                scan_mode,
                                detectiteasy_scan_result: None,
                            };
                            
                            Logging::info(&format!("[ManualScan] Queueing {} manual scan for: {}", request.scan_mode, request.file_path));
                            let _ = internal_scan_tx.send(request);
                        }
                    }
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
    pub fn new(config: &'a Config, predictor_malware: PredictorMalware<'a>) -> Self {
        // <-- MODIFIED: Takes a borrow
        let (internal_scan_tx, internal_scan_rx) = channel::<EDRScanRequest>();

        let scan_request_handle = thread::spawn(move || {
            scan_request_server_loop(internal_scan_rx);
        });
        let av_to_edr_listener_handle = spawn_av_to_edr_listener();
        let _mbr_listener_handle = spawn_mbr_alert_listener();
        let _self_defense_listener_handle = spawn_self_defense_listener();
        let _manual_scan_listener_handle = spawn_manual_scan_listener(internal_scan_tx.clone());

        AVIntegration {
            config, // <-- MODIFIED: Assigns the borrow
            predictor_malware,
            internal_scan_tx,
            signature_cache: HashMap::new(),
            tinyav_recent_scans: HashMap::new(),
            tinyav_missing_logged: false,
            yara_rules: load_yara_x_rules(),
            excluded_yara_rules: load_excluded_rules(),
            _scan_request_handle: scan_request_handle,
            _av_to_edr_listener_handle: av_to_edr_listener_handle,
        }
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

        let threat_info = ThreatInfo {
            threat_type_label: threat_label,
            virus_name: if event.virus_name.is_empty() {
                &event.detection_type
            } else {
                &event.virus_name
            },
            prediction: prediction_behavioral,
            match_details: None,
            deny_access: false,
            terminate: true,
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

        let metadata = self.collect_scan_metadata(&file_path, &scan_target, "minimal");
        if !metadata.should_queue_scan {
            return;
        }

        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path,
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: false,
            scan_mode: "minimal".to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
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

        let metadata = self.collect_scan_metadata(&file_path_string, file_path, "deep");
        if !metadata.should_queue_scan {
            return;
        }

        let request = EDRScanRequest {
            event_type: "SANCTUM_DEEP_SCAN_REQUEST".to_string(),
            file_path: file_path_string,
            timestamp: Utc::now().to_rfc3339(),
            pid,
            additional_context,
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: true,
            scan_mode: "deep".to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send Sanctum deep scan request: {}", e));
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

        let normalized_scan_mode = if is_deep_scan_mode(scan_mode) { "deep" } else { "minimal" };
        let metadata = self.collect_scan_metadata(&file_path_string, file_path, normalized_scan_mode);
        if !metadata.should_queue_scan {
            return;
        }

        let request = EDRScanRequest {
            event_type: "MANUAL_SCAN_REQUEST".to_string(),
            file_path: file_path_string,
            timestamp: Utc::now().to_rfc3339(),
            pid,
            additional_context,
            signature_status: metadata.signature_status,
            yara_x_matches: Some(metadata.yara_x_matches),
            is_vmprotect: metadata.is_vmprotect,
            deep_scan: normalized_scan_mode == "deep",
            scan_mode: normalized_scan_mode.to_string(),
            detectiteasy_scan_result: metadata.detectiteasy_scan_result,
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
        let mut metadata = ScanMetadata::new();
        let deep_mode = is_deep_scan_mode(scan_mode);

        // Deep mode uses DIE as an early metadata/type gate. Python deep scan is
        // only useful for the known file families we parse from DIE output. If
        // DIE says the file is fully unknown, or it is a parsed binary/archive
        // with no supported HydraDragon type flags, do not queue deep scan.
        // Plain-text files never run DIE; they continue without this gate.
        if deep_mode && !should_skip_die_scan(scan_target) {
            metadata.detectiteasy_scan_result = run_detectiteasy_metadata_scan(file_path, scan_target);
            if die_result_is_fully_unknown(&metadata.detectiteasy_scan_result) {
                Logging::debug(&format!(
                    "[DetectItEasy] Deep scan gate skipped fully unknown DIE result: {}",
                    file_path
                ));
                metadata.should_queue_scan = false;
                return metadata;
            }

            if die_result_is_unsupported_for_deep_scan(&metadata.detectiteasy_scan_result) {
                Logging::debug(&format!(
                    "[DetectItEasy] Deep scan gate skipped unsupported DIE type: {}",
                    file_path
                ));
                metadata.should_queue_scan = false;
                return metadata;
            }
        }

        metadata.signature_status = self.get_or_compute_signature_status(file_path, scan_target);

        if let Some(rules) = &self.yara_rules {
            if let Ok(data) = std::fs::read(scan_target) {
                let mut scanner = yara_x::Scanner::new(rules);
                if let Ok(scan_results) = scanner.scan(&data) {
                    for matching_rule in scan_results.matching_rules() {
                        let id = matching_rule.identifier().to_string();
                        let id_lower = id.to_lowercase();

                        if id_lower.contains("vmprotect") {
                            metadata.is_vmprotect = true;
                        }

                        if !self.excluded_yara_rules.contains(&id) {
                            metadata.yara_x_matches.push(id.clone());
                        }
                    }
                }
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
            if die_result_is_fully_unknown(&die_result) {
                Logging::debug(&format!(
                    "[DetectItEasy] Minimal scan ignored fully unknown DIE result: {}",
                    file_path
                ));
            } else {
                metadata.detectiteasy_scan_result = die_result;
            }
        }

        metadata
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
            status: info.status.as_str().to_string(),
            status_text: info.status_text,
            raw_hresult: info.raw_hresult,
            verification_failed: info.verification_failed,
            no_signature: info.no_signature,
            signature_status_issues: info.signature_status_issues,
            invalid_signature: info.invalid_signature,
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
/// Sends one JSON message per connection; the HydraDragon client is expected to reconnect
/// for subsequent messages.
fn scan_request_server_loop(rx: Receiver<EDRScanRequest>) {
    Logging::info(&format!(
        "Starting pipe server (EDR->AV): {}",
        PIPE_EDR_TO_AV
    ));

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
                Logging::error(&format!(
                    "CreateNamedPipeA returned invalid handle: {:?}",
                    err
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            Logging::debug("Waiting for HydraDragon client to connect...");

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let err = GetLastError();

            if connect_ok.as_bool() || err == ERROR_PIPE_CONNECTED {
                if !validate_hydradragon_python_client(pipe_handle) {
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
