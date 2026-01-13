pub static LONG_TIME_FORMAT: &str = "%d/%m/%Y %H:%M:%S";
pub static FILE_TIME_FORMAT: &str = "%Y%m%d_%H%M%S";
pub static LOG_TIME_FORMAT: &str = "%b %d %H:%M:%S";

/// Check if a process is still alive by its PID.
pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        use ::windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use ::windows::Win32::Foundation::CloseHandle;
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
