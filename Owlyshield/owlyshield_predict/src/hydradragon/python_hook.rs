use std::os::windows::ffi::OsStrExt;
use std::thread;
use std::time;
use windows::Win32::Foundation::{BOOL, CloseHandle, HANDLE, HMODULE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::{
    FreeLibrary, GetModuleHandleW, GetProcAddress, LoadLibraryW,
};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, IsWow64Process, LPTHREAD_START_ROUTINE, OpenProcess,
    PROCESS_ALL_ACCESS, WaitForSingleObject,
};
use windows::core::{PCWSTR, s, w};

use crate::hydradragon::paths;
use crate::logging::Logging;

/// Helper function to safely cast function pointer for LoadLibraryW
///
/// # Safety
/// This function casts a raw function pointer to LPTHREAD_START_ROUTINE type
/// expected by CreateRemoteThread. The caller must ensure the pointer is valid.
#[inline]
unsafe fn cast_to_thread_start_routine(fn_ptr: *const ()) -> LPTHREAD_START_ROUTINE {
    Some(unsafe { std::mem::transmute(fn_ptr) })
}

fn is_64bit_process(process_handle: HANDLE) -> bool {
    let mut is_wow64 = BOOL(0);
    unsafe {
        if IsWow64Process(process_handle, &mut is_wow64).as_bool() {
            return is_wow64.0 == 0;
        }
    }
    true // Assume 64-bit on error
}

fn find_remote_module_base(pid: u32, module_name: &str) -> Option<usize> {
    let module_name_lower = module_name.to_lowercase();
    for _ in 0..20 {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
                .unwrap_or(HANDLE::default());
            if !snap.is_invalid() {
                let mut entry = MODULEENTRY32W::default();
                entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

                if Module32FirstW(snap, &mut entry).as_bool() {
                    loop {
                        let sz_module = String::from_utf16_lossy(&entry.szModule);
                        let sz_module = sz_module.trim_matches(char::from(0)).to_lowercase();

                        if sz_module == module_name_lower {
                            let _ = CloseHandle(snap);
                            return Some(entry.modBaseAddr as usize);
                        }
                        if !Module32NextW(snap, &mut entry).as_bool() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
            }
        }
        thread::sleep(time::Duration::from_millis(100));
    }
    None
}

pub fn inject(pid: u32) -> bool {
    Logging::info(&format!(
        "[PythonHook] Attempting to inject hook into PID: {}",
        pid
    ));

    let install_dir = paths::resolve_install_dir();
    let hook_py_path = install_dir.join("__hook__.py");

    let h_proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) };
    let h_proc = match h_proc {
        Ok(h) => h,
        Err(e) => {
            Logging::error(&format!(
                "[PythonHook] OpenProcess failed for PID {}: {:?}",
                pid, e
            ));
            return false;
        }
    };

    let is_64 = is_64bit_process(h_proc);
    let target_dll = if is_64 {
        install_dir.join("hook64.dll")
    } else {
        install_dir.join("hook32.dll")
    };

    if !target_dll.exists() {
        Logging::error(&format!(
            "[PythonHook] Target DLL not found: {:?}",
            target_dll
        ));
        let _ = unsafe { CloseHandle(h_proc) };
        return false;
    }

    // Write config
    let dumps_dir = paths::runtime_data_path("Dumps");
    let _ = std::fs::create_dir_all(&dumps_dir);
    let config_path = dumps_dir.join("hook_config.ini");
    let config_content = format!(
        "[General]\nHookPath={}\n",
        hook_py_path.parent().unwrap().display()
    );
    let _ = std::fs::write(&config_path, config_content);

    let mut path_utf16: Vec<u16> = target_dll.as_os_str().encode_wide().collect();
    path_utf16.push(0);
    path_utf16.push(0);

    let path_size = path_utf16.len() * 2;

    unsafe {
        let mem = VirtualAllocEx(
            h_proc,
            None,
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if mem.is_null() {
            Logging::error(&format!(
                "[PythonHook] VirtualAllocEx failed for PID {}",
                pid
            ));
            let _ = CloseHandle(h_proc);
            return false;
        }

        let mut bytes_written = 0;
        if !WriteProcessMemory(
            h_proc,
            mem,
            path_utf16.as_ptr() as *const std::ffi::c_void,
            path_size,
            Some(&mut bytes_written),
        )
        .as_bool()
        {
            Logging::error(&format!(
                "[PythonHook] WriteProcessMemory failed for PID {}",
                pid
            ));
            let _ = CloseHandle(h_proc);
            return false;
        }

        let k32_handle = GetModuleHandleW(w!("kernel32.dll")).unwrap_or(HMODULE::default());
        let load_lib_addr = GetProcAddress(k32_handle, s!("LoadLibraryW"));

        if load_lib_addr.is_none() {
            Logging::error("[PythonHook] Could not resolve LoadLibraryW");
            let _ = CloseHandle(h_proc);
            return false;
        }

        // CreateRemoteThread for LoadLibraryW
        let mut thread_id = 0;
        let h_thread = match CreateRemoteThread(
            h_proc,
            None,
            0,
            cast_to_thread_start_routine(load_lib_addr.unwrap() as *const ()),
            Some(mem),
            0,
            Some(&mut thread_id),
        ) {
            Ok(h) => h,
            Err(_) => {
                Logging::error(&format!(
                    "[PythonHook] CreateRemoteThread (LoadLibraryW) failed for PID {}",
                    pid
                ));
                let _ = CloseHandle(h_proc);
                return false;
            }
        };

        let wait_res = WaitForSingleObject(h_thread, 5000);
        if wait_res == WAIT_OBJECT_0 {
            let mut exit_code = 0;
            let _ = GetExitCodeThread(h_thread, &mut exit_code);
            if exit_code == 0 {
                Logging::error(&format!(
                    "[PythonHook] LoadLibraryW returned NULL for PID {}",
                    pid
                ));
                let _ = CloseHandle(h_thread);
                let _ = CloseHandle(h_proc);
                return false;
            }
        } else {
            Logging::error(&format!(
                "[PythonHook] LoadLibraryW thread timeout/failed for PID {}",
                pid
            ));
            let _ = CloseHandle(h_thread);
            let _ = CloseHandle(h_proc);
            return false;
        }
        let _ = CloseHandle(h_thread);

        // Find module base in remote
        let dll_name = target_dll
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let remote_mod = match find_remote_module_base(pid, &dll_name) {
            Some(addr) => addr,
            None => {
                Logging::error(&format!(
                    "[PythonHook] Could not find {} in PID {}",
                    dll_name, pid
                ));
                let _ = CloseHandle(h_proc);
                return false;
            }
        };

        // Load local to find RVA
        let local_mod = LoadLibraryW(PCWSTR(path_utf16.as_ptr())).unwrap_or(HMODULE::default());
        if local_mod.is_invalid() {
            Logging::error(&format!("[PythonHook] Could not load {} locally", dll_name));
            let _ = CloseHandle(h_proc);
            return false;
        }

        let local_fn_addr = match GetProcAddress(local_mod, s!("HydraStartHook")) {
            Some(addr) => addr as usize,
            None => {
                Logging::error(&format!(
                    "[PythonHook] HydraStartHook export not found in {}",
                    dll_name
                ));
                let _ = FreeLibrary(local_mod);
                let _ = CloseHandle(h_proc);
                return false;
            }
        };

        let remote_fn_addr = remote_mod + (local_fn_addr - local_mod.0 as usize);

        let h_start = match CreateRemoteThread(
            h_proc,
            None,
            0,
            cast_to_thread_start_routine(remote_fn_addr as *const ()),
            None,
            0,
            Some(&mut thread_id),
        ) {
            Ok(h) => h,
            Err(_) => {
                Logging::error(&format!(
                    "[PythonHook] CreateRemoteThread (HydraStartHook) failed for PID {}",
                    pid
                ));
                let _ = FreeLibrary(local_mod);
                let _ = CloseHandle(h_proc);
                return false;
            }
        };

        let wait_start = WaitForSingleObject(h_start, 5000);
        if wait_start == WAIT_OBJECT_0 {
            Logging::info(&format!(
                "[PythonHook] Successfully injected and started hook in PID {}",
                pid
            ));
        } else {
            Logging::error(&format!(
                "[PythonHook] HydraStartHook thread timeout/failed for PID {}",
                pid
            ));
        }

        let _ = CloseHandle(h_start);
        let _ = FreeLibrary(local_mod);
        let _ = CloseHandle(h_proc);
    }

    true
}
