use std::path::PathBuf;
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::{Win32::System::WindowsProgramming::GetUserNameW, core::PWSTR};

pub fn get_logged_in_username() -> Result<String, String> {
    // get the username of the current logged in user to resolve locations
    let mut buffer: [u16; 256] = [0; 256];
    let mut size = buffer.len() as u32;

    let result = unsafe { GetUserNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut size) };

    if let Err(e) = result {
        return Err(format!("Error getting UserName: {e}"));
    }

    Ok(String::from_utf16_lossy(&buffer[..size as usize - 1]))
}

/// Resolves the full image path for a given process ID.
pub fn resolve_process_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None; // System process or invalid PID
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if let Ok(h) = handle {
            if h.is_invalid() || h.0 == 0 {
                return None;
            }

            let mut buffer = vec![0u16; 1024];
            let mut size = buffer.len() as u32;
            let res = QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );
            let _ = CloseHandle(h);

            if res.as_bool() && size > 0 {
                let path = String::from_utf16_lossy(&buffer[..size as usize]);
                if !path.trim().is_empty() {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Validates that the client connected to the named pipe originates from the expected process path.
pub fn validate_pipe_client(connected_client: &NamedPipeServer, expected_path: &str) -> bool {
    use std::os::windows::io::{AsHandle, AsRawHandle};

    let handle = connected_client.as_handle().as_raw_handle();
    let mut pid: u32 = 0;

    if unsafe { GetNamedPipeClientProcessId(HANDLE(handle), &mut pid) }.is_err() {
        return false;
    }

    if let Some(path) = resolve_process_path(pid) {
        if path.to_lowercase() == expected_path.to_lowercase() {
            return true;
        }
    }

    false
}
