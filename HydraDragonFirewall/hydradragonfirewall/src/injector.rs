use std::ffi::CString;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

#[allow(dead_code)]
pub struct Injector;

#[allow(dead_code)]
impl Injector {
    pub fn inject(pid: u32, dll_path: &str) -> Result<(), String> {
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
            .map_err(|e| format!("OpenProcess failed: {}", e))?;

            if process_handle.is_invalid() {
                return Err("Invalid process handle".to_string());
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
                return Err("VirtualAllocEx failed".to_string());
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
                return Err("WriteProcessMemory failed".to_string());
            }

            // Get LoadLibraryA address
            let kernel32 = GetModuleHandleA(windows::core::s!("kernel32.dll")).unwrap();
            let load_library_addr = GetProcAddress(kernel32, windows::core::s!("LoadLibraryA"));

            if load_library_addr.is_none() {
                let _ = CloseHandle(process_handle);
                return Err("LoadLibraryA not found".to_string());
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
                    return Err("CreateRemoteThread returned invalid handle".to_string());
                }
                let _ = CloseHandle(th);
                Ok(())
            } else {
                Err(format!(
                    "CreateRemoteThread failed: {:?}",
                    thread_handle.err()
                ))
            }
        }
    }
}
