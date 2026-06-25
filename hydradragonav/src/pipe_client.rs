//! Named-pipe client for right-click scan redirection.
//! Attempts to connect to the running GUI's pipe server.
//! If the pipe is unavailable, returns `None` — the caller falls
//! back to a standalone scan.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

const PIPE_NAME: &str = r"\\.\pipe\HydraDragonAV_Scan";
const BUF_BYTES: usize = 4096;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Try to send `path` to the running GUI pipe server and get the verdict.
/// Returns `None` when the GUI is not running (pipe unavailable).
pub fn try_scan(path: &Path) -> Option<String> {
    let pipe_wide = to_wide(PIPE_NAME);

    unsafe {
        let handle = CreateFileW(
            PCWSTR(pipe_wide.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .ok()?;

        // Send file path as UTF-16LE bytes
        let path_wide: Vec<u16> = OsStr::new(path.as_os_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let path_bytes = u16_slice_to_bytes(&path_wide);
        let mut written = 0u32;
        WriteFile(
            handle,
            Some(path_bytes),
            Some(&mut written as *mut u32),
            None,
        )
        .ok()?;

        // Read response (UTF-16LE null-terminated bytes)
        let mut buf = vec![0u8; BUF_BYTES];
        let mut bytes_read = 0u32;
        ReadFile(
            handle,
            Some(&mut buf),
            Some(&mut bytes_read as *mut u32),
            None,
        )
        .ok()?;
        let _ = CloseHandle(handle);

        if bytes_read < 2 {
            return None;
        }

        let nbytes = (bytes_read as usize).min(buf.len());
        let u16_len = nbytes / 2;
        let u16_buf: &[u16] =
            std::slice::from_raw_parts(buf.as_ptr() as *const u16, u16_len);
        let null_pos = u16_buf.iter().position(|&c| c == 0).unwrap_or(u16_len);
        Some(String::from_utf16_lossy(&u16_buf[..null_pos]))
    }
}

fn u16_slice_to_bytes(s: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(s.as_ptr() as *const u8, s.len() * 2) }
}
