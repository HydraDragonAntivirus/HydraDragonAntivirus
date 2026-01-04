use std::ffi::c_void;

use shared_no_std::constants::SANCTUM_DLL_RELATIVE_PATH;
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualAllocEx,
            },
            Threading::{
                CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            },
        },
    },
    core::s,
};

use crate::utils::env::get_logged_in_username;

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
    // todo needs moving to an admin location
    let username = get_logged_in_username().unwrap();
    let base_path = format!("C:\\Users\\{username}\\AppData\\Roaming\\");
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
    let load_library_fn_address: Option<unsafe extern "system" fn(*mut c_void) -> u32> =
        Some(unsafe { std::mem::transmute(load_library_fn_address) });

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

#[derive(Debug)]
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
