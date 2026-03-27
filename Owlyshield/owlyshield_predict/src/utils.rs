use std::path::{Path, PathBuf};

use crate::process::ProcessRecord;

pub static LONG_TIME_FORMAT: &str = "%d/%m/%Y %H:%M:%S";
pub static FILE_TIME_FORMAT: &str = "%Y%m%d_%H%M%S";
pub static LOG_TIME_FORMAT: &str = "%b %d %H:%M:%S";

#[cfg(target_os = "windows")]
pub fn protected_process_path_reason(_path: &Path) -> Option<String> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn protected_process_path_reason(_path: &Path) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
pub fn protected_process_reason(pid: u32, _fallback_path: Option<&Path>) -> Option<String> {
    if pid == 0 {
        return Some("PID 0 is not a terminable user process".to_string());
    }

    if pid == 4 {
        return Some("PID 4 is the Windows System process".to_string());
    }

    if is_process_marked_critical(pid) {
        return Some("Windows marks this process as critical".to_string());
    }

    None
}

#[cfg(not(target_os = "windows"))]
pub fn protected_process_reason(_pid: u32, _fallback_path: Option<&Path>) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn is_process_marked_critical(pid: u32) -> bool {
    use ::windows::Win32::Foundation::{BOOL, CloseHandle};
    use ::windows::Win32::System::Threading::{
        IsProcessCritical, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            if !handle.is_invalid() && handle.0 != 0 {
                let mut critical = BOOL(0);
                let critical_res = IsProcessCritical(handle, &mut critical);
                let _ = CloseHandle(handle);
                return critical_res.as_bool() && critical.as_bool();
            }
        }
    }

    false
}

#[cfg(not(target_os = "windows"))]
fn is_process_marked_critical(_pid: u32) -> bool {
    false
}

pub fn protected_process_record_reason(proc: &ProcessRecord) -> Option<String> {
    for pid in &proc.pids {
        if let Some(reason) = protected_process_reason(*pid, None) {
            return Some(format!("PID {}: {}", pid, reason));
        }
    }
    None
}

pub fn suspicious_critical_process_record_reason(proc: &ProcessRecord) -> Option<String> {
    for pid in &proc.pids {
        if is_process_marked_critical(*pid) {
            if proc.has_valid_signature {
                return None;
            }

            let image = if proc.exepath.as_os_str().is_empty() {
                proc.appname.clone()
            } else {
                proc.exepath.display().to_string()
            };
            let signature_state = if proc.is_signed {
                "signed but not trusted"
            } else {
                "unsigned"
            };
            return Some(format!(
                "PID {} ({}) is marked critical and the image is {}",
                pid, image, signature_state
            ));
        }
    }

    None
}

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
///
/// # Safety
/// This function is unsafe because it interacts with raw handles and Windows API calls.
/// The caller must ensure that `pipe_handle` is a valid, open handle to a named pipe.
#[cfg(target_os = "windows")]
pub unsafe fn validate_pipe_client(pipe_handle: ::windows::Win32::Foundation::HANDLE, expected_path: Option<&str>, allow_kernel: bool) -> bool {
    use ::windows::Win32::Foundation::CloseHandle;
    use ::windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use ::windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use ::windows::Win32::System::ProcessStatus::GetModuleFileNameExA;

    let mut client_pid: u32 = 0;
    if !unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut client_pid) }.as_bool() {
        return false;
    }

    if allow_kernel && client_pid == 4 {
        return true;
    }

    if let Some(expected) = expected_path {
        let expected_lc = expected.to_ascii_lowercase();
        // Check if expected is a full path (contains '\' or '/')
        let is_full_path = expected.contains('\\') || expected.contains('/');

        if let Some(path) = resolve_process_path(client_pid) {
            let resolved = path.to_string_lossy().to_ascii_lowercase();
            if is_full_path {
                if resolved == expected_lc {
                    return true;
                }
            } else {
                if resolved.contains(&expected_lc) {
                    return true;
                }
            }
        }

        if let Ok(h_proc) = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, client_pid) } {
            let mut buffer = [0u8; 1024];
            let len = unsafe { GetModuleFileNameExA(h_proc, None, &mut buffer) };
            let _ = unsafe { CloseHandle(h_proc) };
            if len > 0 {
                let path = String::from_utf8_lossy(&buffer[..len as usize]).to_ascii_lowercase();
                if is_full_path {
                    if path == expected_lc {
                        return true;
                    }
                } else {
                    if path.contains(&expected_lc) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_protected_process_path_reason_is_disabled() {
        assert!(protected_process_path_reason(Path::new(r"C:\Windows\System32\svchost.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"c:\windows\system32\LSASS.EXE")).is_none());
        assert!(protected_process_path_reason(Path::new(r"C:\Windows\explorer.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"\Device\HarddiskVolume3\Windows\System32\services.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"\??\C:\Windows\System32\csrss.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"\SystemRoot\System32\smss.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"\SystemRoot\System32\wininit.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"C:\Users\Admin\Downloads\malware.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"C:\Windows\System32\notepad.exe")).is_none());
        assert!(protected_process_path_reason(Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe")).is_none());
        assert!(protected_process_path_reason(Path::new("")).is_none());
    }
}
