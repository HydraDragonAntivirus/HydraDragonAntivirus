use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            Threading::{
                GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
                THREAD_SUSPEND_RESUME,
            },
        },
        UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
    },
    core::PCSTR,
};

/// Suspend all threads in the current process except for the thread executing our EDR setup (i.e. the current thread)
///
/// # Returns
/// A vector of the suspended handles
pub fn suspend_all_threads() -> Vec<HANDLE> {
    // get all thread ID's except the current thread
    let thread_ids = get_thread_ids();
    if thread_ids.is_err() {
        todo!()
    }
    let thread_ids = thread_ids.unwrap();

    let mut suspended_handles: Vec<HANDLE> = vec![];
    for id in thread_ids {
        let h = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, id) };
        match h {
            Ok(handle) => {
                unsafe { SuspendThread(handle) };
                suspended_handles.push(handle);
            }
            Err(e) => unsafe {
                let x = format!("Error with handle: {:?}\0", e);
                MessageBoxA(
                    None,
                    PCSTR::from_raw(x.as_ptr()),
                    PCSTR::from_raw(x.as_ptr()),
                    MB_OK,
                );
            },
        }
    }

    suspended_handles
}

/// Resume all threads in the process
pub fn resume_all_threads(thread_handles: Vec<HANDLE>) {
    for handle in thread_handles {
        unsafe { ResumeThread(handle) };
        let _ = unsafe { CloseHandle(handle) };
    }
}

/// Enumerate all threads in the current process
///
/// # Returns
/// A vector of thread ID's
pub fn get_thread_ids() -> Result<Vec<u32>, ()> {
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid) };
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(_) => return Err(()),
    };

    // todo hashset
    let mut thread_ids: Vec<u32> = vec![];
    let current_thread = unsafe { GetCurrentThreadId() };

    let mut thread_entry = THREADENTRY32::default();
    thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if unsafe { Thread32First(snapshot, &mut thread_entry) }.is_ok() {
        loop {
            if thread_entry.th32OwnerProcessID == pid {
                // We dont want to suspend our own thread..
                if thread_entry.th32ThreadID != current_thread {
                    thread_ids.push(thread_entry.th32ThreadID);
                }
            }

            if !unsafe { Thread32Next(snapshot, &mut thread_entry) }.is_ok() {
                break;
            }
        }
    }

    Ok(thread_ids)
}
