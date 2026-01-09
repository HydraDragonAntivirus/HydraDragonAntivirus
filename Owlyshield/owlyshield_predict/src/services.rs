//! Targeted Windows Service check module.
//! Uses native Win32 APIs for surgical existence checks.

use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, CloseServiceHandle, QueryServiceStatusEx,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SC_STATUS_PROCESS_INFO,
    SERVICE_STATUS_PROCESS, SERVICE_RUNNING,
};
use windows::core::PCWSTR;

/// Surgical Service Checker
pub struct ServiceChecker;

impl ServiceChecker {
    /// Check if a service exists natively without enumeration.
    pub fn exists(name: &str) -> bool {
        unsafe {
            let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let result = match OpenServiceW(scm, PCWSTR(name_u16.as_ptr()), SERVICE_QUERY_STATUS) {
                Ok(h) => {
                    let _ = CloseServiceHandle(h);
                    true
                }
                Err(_) => false, // Service doesn't exist or access denied
            };

            let _ = CloseServiceHandle(scm);
            result
        }
    }

    /// Check if a service is running.
    pub fn is_running(name: &str) -> bool {
        unsafe {
            let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let h_service = match OpenServiceW(scm, PCWSTR(name_u16.as_ptr()), SERVICE_QUERY_STATUS) {
                Ok(h) => h,
                Err(_) => {
                    let _ = CloseServiceHandle(scm);
                    return false;
                }
            };

            let mut status = SERVICE_STATUS_PROCESS::default();
            let mut bytes_needed = 0u32;
            let buffer_ptr = &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8;
            let buffer_slice = std::slice::from_raw_parts_mut(buffer_ptr, std::mem::size_of::<SERVICE_STATUS_PROCESS>());
            
            let ok = QueryServiceStatusEx(
                h_service,
                SC_STATUS_PROCESS_INFO,
                Some(buffer_slice),
                &mut bytes_needed,
            );

            let result = ok.as_bool() && status.dwCurrentState == SERVICE_RUNNING;

            let _ = CloseServiceHandle(h_service);
            let _ = CloseServiceHandle(scm);
            result
        }
    }
}
