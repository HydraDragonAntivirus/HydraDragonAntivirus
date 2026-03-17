use std::path::{Path, PathBuf};

pub static LONG_TIME_FORMAT: &str = "%d/%m/%Y %H:%M:%S";
pub static FILE_TIME_FORMAT: &str = "%Y%m%d_%H%M%S";
pub static LOG_TIME_FORMAT: &str = "%b %d %H:%M:%S";

pub fn resolve_process_path(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }

    #[cfg(target_os = "windows")]
    {
        use ::windows::Win32::Foundation::CloseHandle;
        use ::windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

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
                    ::windows::core::PWSTR(buffer.as_mut_ptr()),
                    &mut size,
                );
                CloseHandle(h);

                if res.as_bool() && size > 0 {
                    let path = String::from_utf16_lossy(&buffer[..size as usize]);
                    if !path.trim().is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

pub fn format_process_descriptor_with_fallback(pid: u32, fallback_path: Option<&Path>) -> String {
    let fallback = fallback_path
        .and_then(|path| {
            if path.as_os_str().is_empty() {
                None
            } else {
                let text = path.display().to_string();
                if text.trim().is_empty() || text == "UNKNOWN" {
                    None
                } else {
                    Some(text)
                }
            }
        });

    let path = fallback
        .or_else(|| resolve_process_path(pid).map(|p| p.display().to_string()))
        .unwrap_or_else(|| "<unknown>".to_string());

    format!("{pid}:{path}")
}

/// Check if a process is still alive by its PID.
pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        use ::windows::Win32::Foundation::CloseHandle;
        use ::windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if let Ok(h) = handle {
                CloseHandle(h);
                true
            } else {
                false
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::path::Path;
        Path::new(&format!("/proc/{}", pid)).exists()
    }
}

/// Validate the client connecting to a named pipe by its process path or PID.
#[cfg(target_os = "windows")]
pub unsafe fn validate_pipe_client(pipe_handle: ::windows::Win32::Foundation::HANDLE, expected_path: Option<&str>, allow_kernel: bool) -> bool {
    use ::windows::Win32::Foundation::CloseHandle;
    use ::windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use ::windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use ::windows::Win32::System::ProcessStatus::GetModuleFileNameExA;

    let mut client_pid: u32 = 0;
    if !GetNamedPipeClientProcessId(pipe_handle, &mut client_pid).as_bool() {
        return false;
    }

    if allow_kernel && client_pid == 4 {
        return true;
    }

    if let Some(expected) = expected_path {
        if let Ok(h_proc) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, client_pid) {
            let mut buffer = [0u8; 1024];
            let len = GetModuleFileNameExA(h_proc, None, &mut buffer);
            let _ = CloseHandle(h_proc);
            if len > 0 {
                let path = String::from_utf8_lossy(&buffer[..len as usize]).to_ascii_lowercase();
                if path.contains(&expected.to_ascii_lowercase()) {
                    return true;
                }
            }
        }
    }

    false
}

