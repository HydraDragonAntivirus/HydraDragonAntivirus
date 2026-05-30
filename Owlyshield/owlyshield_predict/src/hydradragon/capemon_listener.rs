//! capemon_listener.rs — Listens to Capemon telemetry via Named Pipes
//!
//! Capemon injects into processes and sends BSON-encoded API trace telemetry
//! to the `\\.\pipe\HydraDragonLog_<PID>` named pipe. This module spawns an
//! async/threaded listener to receive these logs and pass them to the behavior engine.

#![cfg(all(target_os = "windows", feature = "hydradragon"))]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE, HANDLE};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_UNLIMITED_INSTANCES,
};
use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};

use crate::logging::Logging;
use crate::behavioral::behavior_engine::BehaviorEngine;

/// Spawns a dedicated thread that listens on `\\.\pipe\HydraDragonCapemon`
/// and dynamically spawns readers for `\\.\pipe\HydraDragonLog_<PID>`
pub fn start_capemon_telemetry_pipe(mut behavior_engine: BehaviorEngine) {
    thread::Builder::new()
        .name("capemon_telemetry_pipe".to_string())
        .spawn(move || {
            let pipe_name_str = r"\\.\pipe\HydraDragonCapemon";
            let wide: Vec<u16> = OsStr::new(pipe_name_str)
                .encode_wide()
                .chain(std::iter::once(0u16))
                .collect();

            Logging::info("[CapemonPipe] Starting Capemon Global Telemetry Pipe");

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
                    Logging::error("[CapemonPipe] CreateNamedPipeW failed; retrying in 2s");
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
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }

                Logging::info("[CapemonPipe] Client connected to Global Capemon pipe");

                // Note: Real Capemon sends initialization packets here.
                // We read and acknowledge them.
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
                    // Capemon initial check-in data processing
                    let data = &buf[..bytes_read as usize];
                    Logging::info(&format!("[CapemonPipe] Received checkin of {} bytes", bytes_read));
                    
                    // TODO: Parse BSON init packet and spawn `HydraDragonLog_<PID>` listener
                    // for that specific PID.
                }

                unsafe {
                    let _ = DisconnectNamedPipe(handle);
                    let _ = CloseHandle(handle);
                }
            }
        })
        .expect("failed to spawn capemon_telemetry_pipe thread");
}

/// Start a log listener for a specific PID. Capemon writes BSON logs here.
pub fn spawn_pid_log_listener(pid: u32, mut behavior_engine: BehaviorEngine) {
    thread::Builder::new()
        .name(format!("capemon_log_{}", pid))
        .spawn(move || {
            let pipe_name_str = format!(r"\\.\pipe\HydraDragonLog_{}", pid);
            let wide: Vec<u16> = OsStr::new(&pipe_name_str)
                .encode_wide()
                .chain(std::iter::once(0u16))
                .collect();

            Logging::info(&format!("[CapemonLog] Listening on {}", pipe_name_str));

            // Run for a limited time (e.g., until process dies)
            let handle: HANDLE = unsafe {
                CreateNamedPipeW(
                    PCWSTR(wide.as_ptr()),
                    PIPE_ACCESS_INBOUND,
                    NAMED_PIPE_MODE(0),
                    1,
                    0,
                    1024 * 1024,
                    0,
                    None,
                )
            };

            if handle == INVALID_HANDLE_VALUE {
                return;
            }

            let connected = unsafe { ConnectNamedPipe(handle, None) }.as_bool()
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

            if connected {
                Logging::info(&format!("[CapemonLog] PID {} connected for logging", pid));
                loop {
                    let mut buf = vec![0u8; 65536];
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

                    if !ok.as_bool() || bytes_read == 0 {
                        break;
                    }

                    // Process BSON data here.
                    let bson_data = &buf[..bytes_read as usize];
                    
                    // We parse the bson_data, map it to Owlyshield behavioral events,
                    // and ingest it into behavior_engine.
                    if let Ok(doc) = bson::Document::from_reader(bson_data) {
                        Logging::info(&format!("[CapemonLog] PID {} sent API hook: {:?}", pid, doc.get_str("api")));
                        behavior_engine.ingest_capemon_event(pid, doc);
                    }
                }
            }

            unsafe {
                let _ = DisconnectNamedPipe(handle);
                let _ = CloseHandle(handle);
            }
            Logging::info(&format!("[CapemonLog] PID {} logging finished", pid));
        })
        .expect("failed to spawn pid log listener");
}
