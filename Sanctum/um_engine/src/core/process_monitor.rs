use std::fs;
use std::path::PathBuf;

use shared_no_std::constants::SANCTUM_DLL_RELATIVE_PATH;
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx},
            Threading::{
                CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            },
        },
    },
    core::s,
};

/// Base installation path for HydraDragon Antivirus
const HYDRADRAGON_BASE_PATH: &str = "C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\";

/// Path to Exorcism DLL for PowerShell monitoring
const EXORCISM_DLL_PATH: &str = "C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\Exorcism-PowershellEdition.dll";

/// Helper function to safely cast function pointer for LoadLibraryA
///
/// # Safety
/// This function casts a raw function pointer to LPTHREAD_START_ROUTINE type
/// expected by CreateRemoteThread. The caller must ensure the pointer is valid.
#[inline]
unsafe fn cast_to_thread_start_routine(fn_ptr: *const ()) -> LPTHREAD_START_ROUTINE {
    Some(unsafe { std::mem::transmute(fn_ptr) })
}

/// Inject the EDR's DLL into a given process by PID. This should be done for processes running on start, and for
/// processes which are newly created.
pub fn inject_edr_dll(pid: u64) -> Result<(), ProcessErrors> {
    // Open the process
    let h_process = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid as u32,
        )
    };
    let h_process = match h_process {
        Ok(h) => h,
        Err(_) => {
            return Err(ProcessErrors::FailedToOpenProcess(unsafe {
                GetLastError().0 as i32
            }));
        }
    };

    // Get a handle to Kernel32.dll
    let h_kernel32 = unsafe { GetModuleHandleA(s!("Kernel32.dll")) };
    let h_kernel32 = match h_kernel32 {
        Ok(h) => h,
        Err(_) => return Err(ProcessErrors::BadHandle),
    };

    // Get a function pointer to LoadLibraryA from Kernel32.dll
    let load_library_fn_address = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")) };
    let load_library_fn_address = match load_library_fn_address {
        None => return Err(ProcessErrors::BadFnAddress),
        Some(address) => address as *const (),
    };

    // Allocate memory for the path to the DLL
    let base_path = "C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\";
    let dll_path = format!("{}{}\0", base_path, SANCTUM_DLL_RELATIVE_PATH);
    let path_len = dll_path.len();

    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(
            h_process,
            None,
            path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_buffer_base_address.is_null() {
        return Err(ProcessErrors::BaseAddressNull);
    }

    // Write to the buffer
    let mut bytes_written: usize = 0;
    let buff_result = unsafe {
        WriteProcessMemory(
            h_process,
            remote_buffer_base_address,
            dll_path.as_ptr() as *const _,
            path_len,
            Some(&mut bytes_written as *mut usize),
        )
    };

    if buff_result.is_err() {
        return Err(ProcessErrors::FailedToWriteMemory);
    }

    // correctly cast the address of LoadLibraryA
    let load_library_fn_address = unsafe { cast_to_thread_start_routine(load_library_fn_address) };

    // Create thread in process
    let mut thread: u32 = 0;
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            None, // default security descriptor
            0,    // default stack size
            load_library_fn_address,
            Some(remote_buffer_base_address),
            0,
            Some(&mut thread as *mut u32),
        )
    };

    if h_thread.is_err() {
        return Err(ProcessErrors::FailedToCreateRemoteThread(unsafe {
            GetLastError().0 as _
        }));
    }

    Ok(())
}

/// Injects CAPEMON.DLL into the target process using Sanctum's injection technique
/// (VirtualAllocEx + CreateRemoteThread) instead of relying on a subprocess loader.exe.
pub fn inject_capemon_dll(pid: u64) -> Result<(), ProcessErrors> {
    // DLL sideloading detection is handled by Capemon's LoadLibraryExW hook
    // which reports suspicious DLL loads via BSON telemetry to the behavior engine.
    // The behavior engine analyzes these reports and triggers appropriate responses.

    // Open the process
    let h_process = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid as u32,
        )
    };
    let h_process = match h_process {
        Ok(h) => h,
        Err(_) => {
            return Err(ProcessErrors::FailedToOpenProcess(unsafe {
                GetLastError().0 as i32
            }));
        }
    };

    // Get a handle to Kernel32.dll
    let h_kernel32 = unsafe { GetModuleHandleA(s!("Kernel32.dll")) };
    let h_kernel32 = match h_kernel32 {
        Ok(h) => h,
        Err(_) => return Err(ProcessErrors::BadHandle),
    };

    // Get a function pointer to LoadLibraryA from Kernel32.dll
    let load_library_fn_address = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")) };
    let load_library_fn_address = match load_library_fn_address {
        None => return Err(ProcessErrors::BadFnAddress),
        Some(address) => address as *const (),
    };

    // Allocate memory for the path to the CAPEMON DLL
    // Assuming x64 by default for the EDR
    let base_path = "C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\capemon\\";
    let dll_path = format!("{}capemon64.dll\0", base_path);
    let path_len = dll_path.len();

    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(
            h_process,
            None,
            path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_buffer_base_address.is_null() {
        return Err(ProcessErrors::BaseAddressNull);
    }

    // Write to the buffer
    let mut bytes_written: usize = 0;
    let buff_result = unsafe {
        WriteProcessMemory(
            h_process,
            remote_buffer_base_address,
            dll_path.as_ptr() as *const _,
            path_len,
            Some(&mut bytes_written as *mut usize),
        )
    };

    if buff_result.is_err() {
        return Err(ProcessErrors::FailedToWriteMemory);
    }

    let load_library_fn_address = unsafe { cast_to_thread_start_routine(load_library_fn_address) };

    // Write config.ini for capemon
    let config_dir = PathBuf::from(base_path).join("configs");
    let _ = fs::create_dir_all(&config_dir);
    let config_path = config_dir.join(format!("{}.ini", pid));
    let config_content = format!(
        "host-ip=127.0.0.1\n\
         host-port=8080\n\
         pipe=\\\\.\\pipe\\HydraDragonCapemon\n\
         logserver=\\\\.\\pipe\\HydraDragonLog_{}\n\
         first-process=1\n\
         startup-time=0\n\
         terminate-event=CapeMonTerminate{}\n",
        pid, pid
    );
    let _ = fs::write(config_path, config_content);

    // Create thread in process to LoadLibraryA(capemon64.dll)
    let mut thread: u32 = 0;
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            None, // default security descriptor
            0,    // default stack size
            load_library_fn_address,
            Some(remote_buffer_base_address),
            0,
            Some(&mut thread as *mut u32),
        )
    };

    if h_thread.is_err() {
        return Err(ProcessErrors::FailedToCreateRemoteThread(unsafe {
            GetLastError().0 as _
        }));
    }

    println!("[Capemon] Successfully injected capemon64.dll into PID: {}", pid);
    Ok(())
}

/// Injects Exorcism-PowershellEdition.dll into PowerShell processes.
pub fn inject_exorcism_dll(pid: u64) -> Result<(), ProcessErrors> {
    let h_process = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid as u32,
        )
    };
    let h_process = match h_process {
        Ok(h) => h,
        Err(_) => return Err(ProcessErrors::FailedToOpenProcess(unsafe { GetLastError().0 as i32 })),
    };

    let h_kernel32 = unsafe { GetModuleHandleA(s!("Kernel32.dll")) };
    let h_kernel32 = match h_kernel32 {
        Ok(h) => h,
        Err(_) => return Err(ProcessErrors::BadHandle),
    };

    let load_library_fn_address = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")) };
    let load_library_fn_address = match load_library_fn_address {
        None => return Err(ProcessErrors::BadFnAddress),
        Some(address) => address as *const (),
    };

    let dll_path = format!("{}\0", EXORCISM_DLL_PATH);
    let path_len = dll_path.len();

    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(h_process, None, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };

    if remote_buffer_base_address.is_null() {
        return Err(ProcessErrors::BaseAddressNull);
    }

    let mut bytes_written: usize = 0;
    if unsafe {
        WriteProcessMemory(
            h_process,
            remote_buffer_base_address,
            dll_path.as_ptr() as *const _,
            path_len,
            Some(&mut bytes_written as *mut usize),
        )
    }.is_err() {
        return Err(ProcessErrors::FailedToWriteMemory);
    }

    let load_library_fn_address = unsafe { cast_to_thread_start_routine(load_library_fn_address) };

    let mut thread: u32 = 0;
    if unsafe {
        CreateRemoteThread(
            h_process, None, 0, load_library_fn_address, Some(remote_buffer_base_address), 0, Some(&mut thread as *mut u32),
        )
    }.is_err() {
        return Err(ProcessErrors::FailedToCreateRemoteThread(unsafe { GetLastError().0 as _ }));
    }

    println!("[Exorcism] Successfully injected Exorcism-PowershellEdition.dll into PID: {}", pid);
    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ProcessErrors {
    PidNotFound,
    DuplicatePid,
    BadHandle,
    BadFnAddress,
    BaseAddressNull,
    FailedToWriteMemory,
    FailedToCreateRemoteThread(i32),
    FailedToOpenProcess(i32),
}
