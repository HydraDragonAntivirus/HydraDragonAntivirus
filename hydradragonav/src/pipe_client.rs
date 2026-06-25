//! Named-pipe client for right-click scan redirection.
//! Attempts to connect to the running GUI's pipe server.
//! If the pipe is unavailable, returns `None` — the caller falls
//! back to a standalone scan.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, GetLastError, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WaitNamedPipeW, WriteFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

const PIPE_NAME: &str = r"\\.\pipe\HydraDragonAV_Scan";
const TIMEOUT_MS: u32 = 5000;
const BUF_LEN: usize = 4096;

/// Try to send `path` to the running GUI pipe server and get the verdict.
/// Returns `None` when the GUI is not running (pipe unavailable).
pub fn try_scan(path: &Path) -> Option<String> {
    unsafe {
        let available = WaitNamedPipeW(windows::core::w!(PIPE_NAME), TIMEOUT_MS);
        if !available.as_bool() {
            let err = GetLastError();
            if err == ERROR_FILE_NOT_FOUND || err == WIN32_ERROR(258) {
                return None;
            }
        }

        let handle = CreateFileW(
            windows::core::w!(PIPE_NAME),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        );

        if handle.is_invalid() {
            return None;
        }

        let path_wide: Vec<u16> = OsStr::new(path.as_os_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut written = 0u32;
        let ok = WriteFile(
            handle,
            path_wide.as_ptr() as *const _,
            (path_wide.len() * 2) as u32,
            &mut written,
            None,
        );
        if !ok.as_bool() {
            let _ = CloseHandle(handle);
            return None;
        }

        let mut buf = vec![0u16; BUF_LEN / 2];
        let mut bytes_read = 0u32;
        let ok = ReadFile(
            handle,
            buf.as_mut_ptr() as *mut _,
            (buf.len() * 2) as u32,
            &mut bytes_read,
            None,
        );
        let _ = CloseHandle(handle);

        if !ok.as_bool() || bytes_read < 2 {
            return None;
        }

        let nchars = (bytes_read as usize / 2).min(buf.len());
        let null_pos = buf[..nchars].iter().position(|&c| c == 0).unwrap_or(nchars);
        Some(String::from_utf16_lossy(&buf[..null_pos]))
    }
}
