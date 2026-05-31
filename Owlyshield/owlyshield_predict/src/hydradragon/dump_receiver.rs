//! dump_receiver.rs — Rust Backend Handler for Exorcism and MegaDumper
//!
//! Exorcism-PowershellEdition hooks Assembly.Load in PowerShell, dumps .dll to disk,
//! then sends a text notification over `\\.\pipe\HydraDragonDumper`.
//!
//! Format: "EXORCISM|C:\path\to\dumped.dll"
//!
//! Rust receives the path and forwards it via a channel to AVIntegration
//! which calls queue_manual_scan_request -> antivirus.py -> YARA/ML.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_UNLIMITED_INSTANCES,
};
use windows::core::PCWSTR;

use crate::hydradragon::av_integration::EDRScanRequest;
use crate::hydradragon::detectiteasy::{DetectItEasyScanner, source_language_from_path};
use crate::hydradragon::python_hook::PYTHON_HOOK_DUMPS_DIR;
use crate::logging::Logging;

fn path_is_under_python_hook_dumps(path: &Path) -> bool {
    let root = PYTHON_HOOK_DUMPS_DIR
        .replace('/', "\\")
        .to_ascii_lowercase();
    let candidate = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    candidate == root || candidate.starts_with(&format!("{root}\\"))
}

fn is_python_hook_source_dump(source: &str, path: &Path) -> bool {
    if !matches!(source_language_from_path(path), Some("python")) {
        return false;
    }

    source.trim().eq_ignore_ascii_case("PYTHON_HOOK") && path_is_under_python_hook_dumps(path)
}

/// Spawns a dedicated pipe server thread that receives dump notifications from
/// Exorcism / MegaDumper / Python hooks. Each received file path is sent over
/// `tx` to the main worker, which calls `AVIntegration::queue_manual_scan_request`.
pub fn start_dump_receiver_pipe(tx: Sender<EDRScanRequest>) {
    thread::Builder::new()
        .name("dump_receiver_pipe".to_string())
        .spawn(move || {
            let pipe_name_str = r"\\.\pipe\HydraDragonDumper";
            let wide: Vec<u16> = OsStr::new(pipe_name_str)
                .encode_wide()
                .chain(std::iter::once(0u16))
                .collect();

            Logging::info("[DumpReceiver] Listening on \\\\.\\pipe\\HydraDragonDumper");

            loop {
                let handle: HANDLE = unsafe {
                    CreateNamedPipeW(
                        PCWSTR(wide.as_ptr()),
                        PIPE_ACCESS_INBOUND,
                        NAMED_PIPE_MODE(0),
                        PIPE_UNLIMITED_INSTANCES,
                        0,
                        65536,
                        0,
                        None,
                    )
                };

                if handle == INVALID_HANDLE_VALUE {
                    Logging::error("[DumpReceiver] CreateNamedPipeW failed; retrying in 2s");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }

                let connected = unsafe { ConnectNamedPipe(handle, None) }.as_bool()
                    || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

                if !connected {
                    unsafe {
                        let _ = DisconnectNamedPipe(handle);
                        let _ = CloseHandle(handle);
                    }
                    continue;
                }

                // Read text message: "EXORCISM|C:\path\to\dumped.dll"
                let mut buf = vec![0u8; 4096];
                let mut bytes_read: u32 = 0;

                let ok = unsafe {
                    ReadFile(
                        handle,
                        Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                        buf.len() as u32,
                        Some(&mut bytes_read),
                        None,
                    )
                };

                if ok.as_bool() && bytes_read > 0 {
                    let msg = String::from_utf8_lossy(&buf[..bytes_read as usize])
                        .trim()
                        .to_string();

                    // Protocol: "SOURCE|C:\path\to\dumped.dll"
                    if let Some((source, path_str)) = msg.split_once('|') {
                        let path = std::path::PathBuf::from(path_str.trim());
                        if path.is_file() {
                            let is_python_hook_source =
                                is_python_hook_source_dump(source.trim(), &path);
                            let event_type = if is_python_hook_source {
                                "PYTHON_HOOK_SOURCE_SCAN"
                            } else {
                                "FILELESS_DUMP_SCAN"
                            };
                            let additional_context = if is_python_hook_source {
                                Some(format!("PYTHON_HOOK;source={}", source.trim()))
                            } else {
                                Some(source.to_string())
                            };
                            let detectiteasy_scan_result = if is_python_hook_source {
                                Some(DetectItEasyScanner::source_result(
                                    &path,
                                    Some("python_hook"),
                                ))
                            } else {
                                None
                            };

                            Logging::info(&format!(
                                "[DumpReceiver] Sending dump to AV scanner: {}",
                                path.display()
                            ));
                            let request = EDRScanRequest {
                                event_type: event_type.to_string(),
                                file_path: path.to_string_lossy().to_string(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                pid: None,
                                additional_context,
                                signature_status: None,
                                yara_x_matches: None,
                                is_vmprotect: false,
                                deep_scan: true,
                                scan_mode: "deep".to_string(),
                                detectiteasy_scan_result,
                                scan_origin_path: Some(path.to_string_lossy().to_string()),
                                deep_scan_timeout_ms: None,
                                late_child_scan_grace_ms: None,
                                rust_service_scan_results: vec![],
                            };
                            let _ = tx.send(request);
                        } else {
                            Logging::error(&format!(
                                "[DumpReceiver] Dump file not found on disk: {}",
                                path.display()
                            ));
                        }
                    } else {
                        Logging::error(&format!("[DumpReceiver] Unknown message format: {msg}"));
                    }
                }

                unsafe {
                    let _ = DisconnectNamedPipe(handle);
                    let _ = CloseHandle(handle);
                }
            }
        })
        .expect("failed to spawn dump_receiver_pipe thread");
}
