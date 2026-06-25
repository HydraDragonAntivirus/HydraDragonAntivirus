//! Named-pipe server for right-click scan requests.
//! Listens on `\\.\pipe\HydraDragonAV_Scan` and forwards paths
//! to the GUI's scan worker via the provided channel.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::WorkRequest;

const PIPE_NAME: &str = r"\\.\pipe\HydraDragonAV_Scan";
const BUF_BYTES: usize = 4096;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn u16_slice_to_bytes(s: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(s.as_ptr() as *const u8, s.len() * 2) }
}

pub fn spawn(work_tx: Sender<WorkRequest>) {
    std::thread::spawn(move || run(work_tx));
}

fn run(work_tx: Sender<WorkRequest>) {
    let pipe_wide = to_wide(PIPE_NAME);
    loop {
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUF_BYTES as u32,
                BUF_BYTES as u32,
                0,
                None,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }

        unsafe {
            let connected = ConnectNamedPipe(handle, None);
            if connected.is_err() {
                let err = GetLastError();
                if err != ERROR_PIPE_CONNECTED {
                    let _ = DisconnectNamedPipe(handle);
                    let _ = CloseHandle(handle);
                    continue;
                }
            }
        }

        // Read file path bytes (UTF-16LE null-terminated)
        let mut buf = vec![0u8; BUF_BYTES];
        let mut bytes_read = 0u32;
        if unsafe {
            ReadFile(
                handle,
                Some(&mut buf),
                Some(&mut bytes_read as *mut u32),
                None,
            )
        }
        .is_err()
            || bytes_read < 2
        {
            let _ = unsafe { DisconnectNamedPipe(handle) };
            let _ = unsafe { CloseHandle(handle) };
            continue;
        }

        let nbytes = (bytes_read as usize).min(buf.len());
        let u16_len = nbytes / 2;
        let u16_buf: &[u16] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_len) };
        let null_pos = u16_buf.iter().position(|&c| c == 0).unwrap_or(u16_len);
        let path_str = String::from_utf16_lossy(&u16_buf[..null_pos]);
        let path = PathBuf::from(&path_str);

        // Send to worker and await response
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        if work_tx
            .send(WorkRequest::PipeScan {
                path,
                result_tx,
            })
            .is_err()
        {
            let _ = unsafe { DisconnectNamedPipe(handle) };
            let _ = unsafe { CloseHandle(handle) };
            continue;
        }

        let result = result_rx.recv().unwrap_or_else(|_| "Error: scan failed".to_string());

        // Write result back (UTF-16LE null-terminated)
        let result_wide: Vec<u16> = result.encode_utf16().chain(std::iter::once(0)).collect();
        let result_bytes = u16_slice_to_bytes(&result_wide);
        let mut written = 0u32;
        unsafe {
            let _ = WriteFile(
                handle,
                Some(result_bytes),
                Some(&mut written as *mut u32),
                None,
            );
            let _ = FlushFileBuffers(handle);
            let _ = DisconnectNamedPipe(handle);
            let _ = CloseHandle(handle);
        }
    }
}
