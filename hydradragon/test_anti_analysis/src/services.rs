//! Windows Services checking module
//!
//! Provides functions to enumerate and check Windows services.

use crate::{CheckResult, Result, SignatureMonsterError};
use windows::Win32::System::Services::*;
use windows::core::PCWSTR;

/// Service checker
pub struct ServiceChecker {
    _private: (),
}

impl ServiceChecker {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn open_scm(&self) -> Result<SC_HANDLE> {
        unsafe {
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE)
                .map_err(|e| SignatureMonsterError::ServiceError(e.to_string()))
        }
    }

    /// List all services
    pub fn list_services(&self) -> Result<Vec<ServiceInfo>> {
        let scm = self.open_scm()?;
        let mut bytes_needed: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        unsafe {
            let _ = EnumServicesStatusExW(
                scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                None, &mut bytes_needed, &mut services_returned,
                Some(&mut resume_handle), None,
            );
        }

        if bytes_needed == 0 {
            unsafe { let _ = CloseServiceHandle(scm); }
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; bytes_needed as usize];
        resume_handle = 0;

        let result = unsafe {
            EnumServicesStatusExW(
                scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                Some(&mut buffer), &mut bytes_needed, &mut services_returned,
                Some(&mut resume_handle), None,
            )
        };

        if result.is_err() {
            unsafe { let _ = CloseServiceHandle(scm); }
            return Err(SignatureMonsterError::ServiceError("Failed to enumerate".to_string()));
        }

        let ptr = buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        let mut services = Vec::new();

        for i in 0..services_returned as isize {
            let svc = unsafe { &*ptr.offset(i) };
            let name = unsafe {
                let len = (0..).take_while(|&i| *svc.lpServiceName.0.add(i) != 0).count();
                String::from_utf16_lossy(std::slice::from_raw_parts(svc.lpServiceName.0, len))
            };
            let display = unsafe {
                let len = (0..).take_while(|&i| *svc.lpDisplayName.0.add(i) != 0).count();
                String::from_utf16_lossy(std::slice::from_raw_parts(svc.lpDisplayName.0, len))
            };
            let state = match svc.ServiceStatusProcess.dwCurrentState {
                SERVICE_RUNNING => ServiceState::Running,
                SERVICE_STOPPED => ServiceState::Stopped,
                _ => ServiceState::Other,
            };
            services.push(ServiceInfo { name, display_name: display, state, pid: svc.ServiceStatusProcess.dwProcessId });
        }

        unsafe { let _ = CloseServiceHandle(scm); }
        Ok(services)
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        let svcs = self.list_services()?;
        let n = name.to_lowercase();
        Ok(svcs.iter().any(|s| s.name.to_lowercase() == n || s.display_name.to_lowercase() == n))
    }

    pub fn is_running(&self, name: &str) -> Result<bool> {
        let svcs = self.list_services()?;
        let n = name.to_lowercase();
        Ok(svcs.iter().any(|s| (s.name.to_lowercase() == n || s.display_name.to_lowercase() == n) && s.state == ServiceState::Running))
    }

    pub fn find_by_pattern(&self, pattern: &str) -> Result<Vec<ServiceInfo>> {
        let svcs = self.list_services()?;
        let p = pattern.to_lowercase();
        Ok(svcs.into_iter().filter(|s| s.name.to_lowercase().contains(&p)).collect())
    }
}

impl Default for ServiceChecker { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ServiceState { Stopped, Running, Other }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub pid: u32,
}
