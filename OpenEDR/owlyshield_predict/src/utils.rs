use std::path::{Path, PathBuf};

use crate::process::ProcessRecord;

pub static LONG_TIME_FORMAT: &str = "%d/%m/%Y %H:%M:%S";
pub static FILE_TIME_FORMAT: &str = "%Y%m%d_%H%M%S";
pub static LOG_TIME_FORMAT: &str = "%b %d %H:%M:%S";


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



fn is_process_marked_critical(pid: u32) -> bool {
    use windows::Win32::Foundation::{BOOL, CloseHandle};
    use windows::Win32::System::Threading::{
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
        let image = if proc.exepath.as_os_str().is_empty() {
            proc.appname.clone()
        } else {
            proc.exepath.display().to_string()
        };

        if let Some(reason) = suspicious_critical_process_reason(
            *pid,
            &image,
            proc.is_signed,
            proc.has_valid_signature,
        ) {
            return Some(reason);
        }
    }

    None
}

pub fn suspicious_critical_process_reason(
    pid: u32,
    image_display: &str,
    is_signed: bool,
    has_valid_signature: bool,
) -> Option<String> {
    if !is_process_marked_critical(pid) || has_valid_signature {
        return None;
    }

    let normalized_image = if image_display.trim().is_empty() {
        "<unknown>"
    } else {
        image_display
    };
    let signature_state = if is_signed {
        "signed but not trusted"
    } else {
        "unsigned"
    };

    Some(format!(
        "PID {} ({}) is marked critical and the image is {}",
        pid, normalized_image, signature_state
    ))
}

pub fn resolve_process_path(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }

    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
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


pub fn format_process_descriptor_with_fallback(pid: u32, fallback_path: Option<&Path>) -> String {
    let fallback = fallback_path.and_then(|path| {
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
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
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
