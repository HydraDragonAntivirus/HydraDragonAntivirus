use crate::sdk::HookSettings;
use std::ffi::CString;
use std::sync::RwLock;
use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HMODULE};
use windows::core::BOOL;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, IsWow64Process, OpenProcess, OpenProcessToken,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY, LookupPrivilegeValueA,
};

use windows::core::Error;

lazy_static::lazy_static! {
    /// Global hook settings that can be modified at runtime
    pub static ref HOOK_SETTINGS: RwLock<HookSettings> = RwLock::new(HookSettings::default());
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct InjectionError {
    pub message: String,
    pub permission_denied: bool,
}

#[allow(dead_code)]
impl InjectionError {
    fn from_win32(context: &str, err: Error) -> Self {
        let permission_denied = err.code() == ERROR_ACCESS_DENIED.to_hresult();
        Self {
            message: format!("{} failed: {}", context, err),
            permission_denied,
        }
    }
}

#[allow(dead_code)]
pub struct Injector;

#[allow(dead_code)]
impl Injector {
    pub fn is_dll_loaded(pid: u32, dll_name: &str) -> bool {
        unsafe {
            // Try combined permissions for module enumeration
            let handle_res = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false.into(),
                pid,
            ).or_else(|_| {
                // Fallback for some system processes
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false.into(), pid)
            });

            if let Ok(handle) = handle_res {
                let mut modules = [HMODULE::default(); 1024];
                let mut cb_needed = 0;
                
                // Use EnumProcessModulesEx with LIST_MODULES_ALL to see both 32/64 bit modules
                if EnumProcessModulesEx(
                    handle,
                    modules.as_mut_ptr(),
                    std::mem::size_of_val(&modules) as u32,
                    &mut cb_needed,
                    LIST_MODULES_ALL,
                )
                .is_ok()
                {
                    let count = cb_needed as usize / std::mem::size_of::<HMODULE>();
                    for i in 0..(count.min(1024)) {
                        let mut name_buf = [0u16; 256];
                        let len = GetModuleBaseNameW(handle, Some(modules[i]), &mut name_buf);
                        if len > 0 {
                            let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                            if name.to_lowercase() == dll_name.to_lowercase() {
                                let _ = CloseHandle(handle);
                                return true;
                            }
                        }
                    }
                }
                let _ = CloseHandle(handle);
            }
        }
        false
    }

    pub fn is_process_32bit(pid: u32) -> bool {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false.into(), pid) {
                let mut is_wow64 = BOOL::default();
                let res = IsWow64Process(handle, &mut is_wow64);
                let _ = CloseHandle(handle);
                if res.is_ok() {
                    return is_wow64.as_bool();
                }
            }
        }
        false
    }

    pub fn get_process_info(pid: u32) -> (String, String) {
        unsafe {
            let handle_res = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false.into(),
                pid,
            );
            if let Ok(handle) = handle_res {
                let mut name_buf = [0u16; 256];
                let mut path_buf = [0u16; 512];

                let name_len = GetModuleBaseNameW(handle, Some(HMODULE::default()), &mut name_buf);
                let path_len =
                    GetModuleFileNameExW(Some(handle), Some(HMODULE::default()), &mut path_buf);

                let name = if name_len > 0 {
                    String::from_utf16_lossy(&name_buf[..name_len as usize])
                } else {
                    format!("PID:{}", pid)
                };

                let path = if path_len > 0 {
                    String::from_utf16_lossy(&path_buf[..path_len as usize])
                } else {
                    "Unknown".to_string()
                };

                let _ = CloseHandle(handle);
                return (name, path);
            }
        }
        (format!("PID:{}", pid), "Unknown".to_string())
    }

    /// Check if a path is excluded from hooking using global settings
    pub fn is_path_excluded(path: &str) -> bool {
        let settings = HOOK_SETTINGS.read().unwrap();
        settings.is_whitelisted(path)
    }

    /// Check if hooking is enabled
    pub fn is_hooking_enabled() -> bool {
        let settings = HOOK_SETTINGS.read().unwrap();
        settings.enabled
    }

    /// Update hook settings
    pub fn update_settings(new_settings: HookSettings) {
        let mut settings = HOOK_SETTINGS.write().unwrap();
        *settings = new_settings;
    }

    /// Add a path to the whitelist
    pub fn add_whitelist_path(path: String) {
        let mut settings = HOOK_SETTINGS.write().unwrap();
        settings.add_whitelist_path(path);
    }

    /// Remove a path from the whitelist
    pub fn remove_whitelist_path(path: &str) {
        let mut settings = HOOK_SETTINGS.write().unwrap();
        settings.remove_whitelist_path(path);
    }

    /// Get current whitelist paths
    pub fn get_whitelist_paths() -> Vec<String> {
        let settings = HOOK_SETTINGS.read().unwrap();
        settings.whitelist_paths.clone()
    }

    pub fn inject(pid: u32, dll_path: &str) -> Result<(), InjectionError> {
        // Check if hooking is enabled
        if !Self::is_hooking_enabled() {
            return Err(InjectionError {
                message: "Hooking is disabled".to_string(),
                permission_denied: false,
            });
        }

        // Check if process is whitelisted
        let (_, process_path) = Self::get_process_info(pid);
        if Self::is_path_excluded(&process_path) {
            return Err(InjectionError {
                message: format!("Process {} is whitelisted", process_path),
                permission_denied: false,
            });
        }

        unsafe {
            let process_handle = OpenProcess(
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_READ,
                false.into(),
                pid,
            )
            .map_err(|e| InjectionError::from_win32("OpenProcess", e))?;

            if process_handle.is_invalid() {
                return Err(InjectionError {
                    message: "Invalid process handle".to_string(),
                    permission_denied: false,
                });
            }

            // Allocate memory in target process for DLL path
            let dll_path_c = CString::new(dll_path).unwrap();
            let dll_path_len = dll_path_c.as_bytes_with_nul().len();

            let remote_mem = VirtualAllocEx(
                process_handle,
                None,
                dll_path_len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if remote_mem.is_null() {
                let _ = CloseHandle(process_handle);
                return Err(InjectionError {
                    message: "VirtualAllocEx failed".to_string(),
                    permission_denied: false,
                });
            }

            // Write DLL path
            let mut bytes_written = 0;
            let write_result = WriteProcessMemory(
                process_handle,
                remote_mem,
                dll_path_c.as_ptr() as *const _,
                dll_path_len,
                Some(&mut bytes_written),
            );

            // WriteProcessMemory returns BOOL (wrapped in Result by windows-rs)
            if write_result.is_err() || bytes_written != dll_path_len {
                let _ = CloseHandle(process_handle);
                return Err(InjectionError {
                    message: "WriteProcessMemory failed".to_string(),
                    permission_denied: false,
                });
            }

            // Get LoadLibraryA address
            let kernel32 = GetModuleHandleA(windows::core::s!("kernel32.dll")).unwrap();
            let load_library_addr = GetProcAddress(kernel32, windows::core::s!("LoadLibraryA"));

            if load_library_addr.is_none() {
                let _ = CloseHandle(process_handle);
                return Err(InjectionError {
                    message: "LoadLibraryA not found".to_string(),
                    permission_denied: false,
                });
            }

            let start_routine = std::mem::transmute(load_library_addr);

            // Create remote thread
            let thread_handle = CreateRemoteThread(
                process_handle,
                None,
                0,
                start_routine,
                Some(remote_mem),
                0,
                None,
            );

            let _ = CloseHandle(process_handle);

            if let Ok(th) = thread_handle {
                if th.is_invalid() {
                    return Err(InjectionError {
                        message: "CreateRemoteThread returned invalid handle".to_string(),
                        permission_denied: false,
                    });
                }
                let _ = CloseHandle(th);
                Ok(())
            } else {
                Err(InjectionError {
                    message: format!("CreateRemoteThread failed: {:?}", thread_handle.err()),
                    permission_denied: false,
                })
            }
        }
    }

    /// Inject DLL to all running processes except whitelisted ones
    pub fn inject_all_processes(dll_path: &str) -> Vec<(u32, Result<(), InjectionError>)> {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        };

        let mut results = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if let Ok(snap) = snapshot {
                let mut entry = PROCESSENTRY32 {
                    dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
                    ..Default::default()
                };

                if Process32First(snap, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        
                        // Skip self, system, and idle processes
                        if pid != 0 && pid != 4 && pid != std::process::id() {
                            let (_, path) = Self::get_process_info(pid);
                            
                            // Only inject if not whitelisted and not already injected
                            if !Self::is_path_excluded(&path) {
                                if !Self::is_dll_loaded(pid, dll_path) {
                                    let result = Self::inject(pid, dll_path);
                                    results.push((pid, result));
                                }
                            }
                        }

                        if Process32Next(snap, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
            }
        }

        results
    }

    /// Enable SeDebugPrivilege for the current process
    pub fn enable_debug_privilege() -> bool {
        unsafe {
            let mut h_token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token).is_err() {
                return false;
            }

            let mut luid = windows::Win32::Foundation::LUID::default();
            if LookupPrivilegeValueA(None, windows::core::s!("SeDebugPrivilege"), &mut luid).is_err() {
                let _ = CloseHandle(h_token);
                return false;
            }

            let tkp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            let res = AdjustTokenPrivileges(h_token, false, Some(&tkp), 0, None, None);
            let _ = CloseHandle(h_token);
            res.is_ok()
        }
    }
}
