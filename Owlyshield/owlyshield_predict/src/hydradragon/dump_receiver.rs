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
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE, HANDLE};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_ACCESS_INBOUND, PIPE_UNLIMITED_INSTANCES,
};
use windows::Win32::Storage::FileSystem::ReadFile;

use crate::logging::Logging;
use crate::hydradragon::av_integration::EDRScanRequest;

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
                            Logging::info(&format!(
                                "[DumpReceiver] Sending dump to AV scanner: {}",
                                path.display()
                            ));
                            let request = EDRScanRequest {
                                event_type: "FILELESS_DUMP_SCAN".to_string(),
                                file_path: path.to_string_lossy().to_string(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                pid: None,
                                additional_context: Some(source.to_string()),
                                signature_status: None,
                                yara_x_matches: None,
                                is_vmprotect: false,
                                deep_scan: true,
                                scan_mode: "deep".to_string(),
                                detectiteasy_scan_result: None,
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
                        Logging::error(&format!(
                            "[DumpReceiver] Unknown message format: {msg}"
                        ));
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
