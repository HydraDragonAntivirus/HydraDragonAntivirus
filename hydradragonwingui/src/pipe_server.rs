//! Named-pipe server for right-click scan requests.
//! Listens on `\\.\pipe\HydraDragonAV_Scan` and forwards paths
//! to the GUI's scan worker via the provided channel.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, FlushFileBuffers, ReadFile, WriteFile,
    PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::WorkRequest;

const PIPE_NAME: &str = r"\\.\pipe\HydraDragonAV_Scan";
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const BUF_LEN: usize = 4096;

pub fn spawn(work_tx: Sender<WorkRequest>) {
    std::thread::spawn(move || run(work_tx));
}

fn run(work_tx: Sender<WorkRequest>) {
    loop {
        let handle = unsafe {
            CreateNamedPipeW(
                windows::core::w!(PIPE_NAME),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUF_LEN as u32,
                BUF_LEN as u32,
                0,
                None,
            )
        };

        if handle.is_invalid() {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }

        unsafe {
            let connected = ConnectNamedPipe(handle, None);
            if !connected.as_bool() && GetLastError() != ERROR_PIPE_CONNECTED {
                let _ = DisconnectNamedPipe(handle);
                let _ = CloseHandle(handle);
                continue;
            }
        }

        // Read file path (null-terminated UTF-16LE)
        let mut buf = vec![0u16; BUF_LEN / 2];
        let mut bytes_read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr() as *mut _,
                (buf.len() * 2) as u32,
                &mut bytes_read,
                None,
            )
        };

        if !ok.as_bool() || bytes_read < 2 {
            let _ = unsafe { DisconnectNamedPipe(handle) };
            let _ = unsafe { CloseHandle(handle) };
            continue;
        }

        let nchars = (bytes_read as usize / 2).min(buf.len());
        let null_pos = buf[..nchars].iter().position(|&c| c == 0).unwrap_or(nchars);
        let path_str = String::from_utf16_lossy(&buf[..null_pos]);
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

        // Write result back (null-terminated UTF-16LE)
        let result_wide: Vec<u16> = result.encode_utf16().chain(std::iter::once(0)).collect();
        let mut written = 0u32;
        unsafe {
            let _ = WriteFile(
                handle,
                result_wide.as_ptr() as *const _,
                (result_wide.len() * 2) as u32,
                &mut written,
                None,
            );
            let _ = FlushFileBuffers(handle);
            let _ = DisconnectNamedPipe(handle);
            let _ = CloseHandle(handle);
        }
    }
}
