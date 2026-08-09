use std::io::Write;
use std::path::Path;
#[cfg(feature = "service")]
use std::ptr::null_mut;

use serde::Serialize;

use crate::Logging;
use crate::config::{Config, Param};

#[cfg(feature = "service")]
use widestring::{U16CString, U16String};
#[cfg(feature = "service")]
use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
#[cfg(feature = "service")]
use windows::Win32::Security::{
    DuplicateTokenEx, SECURITY_ATTRIBUTES, SecurityIdentification, TOKEN_ALL_ACCESS, TokenPrimary,
};
#[cfg(feature = "service")]
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQueryUserToken,
};
#[cfg(feature = "service")]
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTUPINFOW,
};
#[cfg(feature = "service")]
use windows::core::{PCWSTR, PWSTR};

/// Structured event appended to `owlyshield.jsonl` (JSONL), so the same
/// Elasticsearch pipeline that consumes `firewall_activity.jsonl` can index
/// Owlyshield detection events.
#[derive(Debug, Clone, Serialize)]
pub struct OwlyshieldLogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: String,
    pub event: String,
    pub message: String,
    pub report_path: String,
}

impl OwlyshieldLogEntry {
    pub fn alert(message: &str, report_path: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            id: format!("owlyshield-alert-{}", now),
            timestamp: now,
            level: "ALERT".to_string(),
            event: "MALWARE_DETECTED".to_string(),
            message: message.to_string(),
            report_path: report_path.to_string(),
        }
    }
}

/// Resolve the log directory holding `owlyshield.jsonl`. Mirrors the firewall
/// layout (`C:\ProgramData\edrsvc\log\firewall_activity.jsonl`) so Filebeat /
/// Logstash can tail both files from one folder.
fn owlyshield_jsonl_path() -> std::path::PathBuf {
    let log_path_val =
        crate::config::ConfigReader::read_param_from_registry("LOG_PATH", r"SOFTWARE\Owlyshield");
    let mut base_log_dir = if !log_path_val.trim().is_empty() {
        std::path::PathBuf::from(log_path_val)
    } else if let Some(program_data) = std::env::var_os("ProgramData") {
        std::path::PathBuf::from(program_data).join("edrsvc").join("log")
    } else {
        std::env::temp_dir().join("owlyshield")
    };

    // Go up one level from the 'owlyshield' subdirectory to get the main 'log' folder.
    if base_log_dir
        .file_name()
        .and_then(|n| n.to_str())
        .map_or(false, |s| s.eq_ignore_ascii_case("owlyshield"))
    {
        base_log_dir.pop();
    }

    base_log_dir.join("owlyshield.jsonl")
}

/// Append one JSON line to `owlyshield.jsonl`. Failures are silent on purpose:
/// a logging hiccup must never break detection handling.
pub fn log_jsonl(entry: &OwlyshieldLogEntry) {
    let path = owlyshield_jsonl_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let Ok(line) = serde_json::to_string(entry) else {
        return;
    };

    let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };

    let _ = writeln!(file, "{line}");
}

#[cfg(feature = "service")]
fn str_to_pcwstr(str: &str) -> U16CString {
    U16CString::from_str(str).unwrap()
}

#[cfg(feature = "service")]
fn str_to_pwstr(str: &str) -> U16String {
    U16String::from_str(str)
}

#[cfg(feature = "service")]
unsafe fn get_active_user_token() -> Option<HANDLE> {
    unsafe {
        // Try the standard active console session first
        let session_id = WTSGetActiveConsoleSessionId();
        if session_id != u32::MAX {
            let mut token = HANDLE(0);
            if WTSQueryUserToken(session_id, &mut token).as_bool() {
                return Some(token);
            }
        }

        // Fall back to enumerating all sessions
        let mut p_sessions = null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(None, 0, 1, &mut p_sessions, &mut count).as_bool() {
            let sessions = std::slice::from_raw_parts(p_sessions, count as usize);
            for s in sessions {
                if s.State == WTSActive {
                    let mut token = HANDLE(0);
                    if WTSQueryUserToken(s.SessionId, &mut token).as_bool() {
                        WTSFreeMemory(p_sessions as *mut _);
                        return Some(token);
                    }
                }
            }
            WTSFreeMemory(p_sessions as *mut _);
        }

        None
    }
}

#[cfg(feature = "service")]
pub fn notify(config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    use std::thread;
    use std::time::Duration;

    log_jsonl(&OwlyshieldLogEntry::alert(message, report_path));

    let toastapp_dir = Path::new(&config[Param::UtilsPath]);
    let toastapp_path = toastapp_dir.join("RustWindowsToast.exe");
    let app_id = &config[Param::AppId];
    let logo_path = Path::new(&config[Param::ConfigPath])
        .parent()
        .unwrap()
        .join("logo.ico");

    let toastapp_args = format!(
        " \"Owlyshield\" \"{}\" \"{}\" \"{}\" \"{}\"",
        message,
        logo_path.to_str().unwrap_or(""),
        app_id,
        report_path
    );

    let mut error_msg = String::new();
    let si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        // Retry logic: wait indefinitely for an active user session
        const RETRY_DELAY_MS: u64 = 3000; // 3 seconds between retries

        let mut attempt = 0u32;

        let service_token = loop {
            let maybe_token = get_active_user_token();

            if let Some(token) = maybe_token {
                Logging::info(&format!(
                    "Toast(): Active user session found after {} attempts",
                    attempt + 1
                ));
                break token;
            }

            if attempt == 0 {
                Logging::warning(
                    "Toast(): no active user session found, waiting for user login...",
                );
            } else if attempt.is_multiple_of(10) {
                // Log every 10th attempt (every 30 seconds) to avoid log spam
                Logging::debug(&format!(
                    "Toast(): Still waiting for user session (attempt {}, {} seconds elapsed)",
                    attempt + 1,
                    (attempt as u64 * RETRY_DELAY_MS) / 1000
                ));
            }

            attempt += 1;
            thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
        };

        let mut primary_token = HANDLE(0);

        if !DuplicateTokenEx(
            service_token,
            TOKEN_ALL_ACCESS,
            Some(null_mut() as *mut SECURITY_ATTRIBUTES),
            SecurityIdentification,
            TokenPrimary,
            &mut primary_token,
        )
        .as_bool()
        {
            CloseHandle(service_token);
            error_msg = format!("Toast(): cannot duplicate token: {}", GetLastError().0);
            Logging::error(error_msg.as_str());
            return Err(error_msg);
        }

        CloseHandle(service_token);

        Logging::debug("Toast(): Creating process as user...");

        if !CreateProcessAsUserW(
            primary_token,
            PCWSTR(str_to_pcwstr(toastapp_path.to_str().unwrap()).as_ptr()),
            PWSTR(str_to_pwstr(&toastapp_args).as_mut_ptr()),
            None,
            None,
            BOOL(0),
            PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW.0),
            Some(null_mut()),
            PCWSTR(str_to_pcwstr(toastapp_dir.to_str().unwrap()).as_ptr()),
            &si,
            &mut pi,
        )
        .as_bool()
        {
            error_msg = format!("Toast(): failed to create process: {}", GetLastError().0);
            Logging::error(error_msg.as_str());
        } else {
            Logging::info("Toast(): Notification process created successfully");
        }

        CloseHandle(primary_token);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if error_msg.is_empty() {
        Ok(())
    } else {
        Err(error_msg)
    }
}

#[cfg(not(feature = "service"))]
pub fn notify(config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    Logging::alert(message);
    log_jsonl(&OwlyshieldLogEntry::alert(message, report_path));

    let toastapp_dir = Path::new(&config[Param::UtilsPath]);
    let toastapp_path = toastapp_dir.join("RustWindowsToast.exe");
    let app_id = &config[Param::AppId];
    let logo_path = Path::new(&config[Param::ConfigPath])
        .parent()
        .unwrap()
        .join("logo.ico");

    let toastapp_args = [
        "Owlyshield",
        message,
        logo_path.to_str().unwrap_or(""),
        app_id,
        report_path,
    ];

    std::process::Command::new(toastapp_path)
        .args(toastapp_args)
        .output()
        .expect("failed to execute process");

    Ok(())
}
