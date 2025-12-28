use std::path::Path;
#[cfg(feature = "service")]
use std::ptr::null_mut;

use crate::config::{Config, Param};
use crate::Logging;

#[cfg(feature = "service")]
use widestring::{U16CString, U16String};
#[cfg(feature = "service")]
use windows::core::{PCWSTR, PWSTR};
#[cfg(feature = "service")]
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, BOOL};
#[cfg(feature = "service")]
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityIdentification, TokenPrimary, SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS,
};
#[cfg(feature = "service")]
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, 
    WTSGetActiveConsoleSessionId, WTSQueryUserToken
};
#[cfg(feature = "service")]
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTUPINFOW,
};

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

#[cfg(feature = "service")]
pub fn notify(config: &Config, message: &str, report_path: &str) -> Result<(), String> {
    use std::thread;
    use std::time::Duration;
    
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
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
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
                Logging::warning("Toast(): no active user session found, waiting for user login...");
            } else if attempt % 10 == 0 {
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
            error_msg = format!(
                "Toast(): cannot duplicate token: {}",
                GetLastError().0
            );
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
            PROCESS_CREATION_FLAGS(CREATE_NEW_CONSOLE.0),
            Some(null_mut()),
            PCWSTR(str_to_pcwstr(toastapp_dir.to_str().unwrap()).as_ptr()),
            &mut si,
            &mut pi,
        )
        .as_bool()
        {
            error_msg = format!(
                "Toast(): failed to create process: {}",
                GetLastError().0
            );
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
