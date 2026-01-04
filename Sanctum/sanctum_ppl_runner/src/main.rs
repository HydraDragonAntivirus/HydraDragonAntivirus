//! A service runner for the Protected Process Lite Antimalware which allows us to interact with ETW:TI

use std::{
    env, // Added env
    mem::{size_of, size_of_val},
    path::PathBuf, // Added PathBuf
    sync::atomic::{AtomicBool, Ordering},
    thread::sleep,
    time::Duration,
};

use logging::{EventID, event_log};
use tracing::start_threat_intel_trace;
use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::{
            EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_SUCCESS},
            Services::{
                RegisterServiceCtrlHandlerW, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
                SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
                SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
                SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
            },
            Threading::{
                CREATE_PROTECTED_PROCESS, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
                InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, PROCESS_INFORMATION, STARTUPINFOEXW,
                UpdateProcThreadAttribute,
            },
            WindowsProgramming::PROTECTION_LEVEL_SAME,
        },
    },
    core::{PCWSTR, PWSTR},
};

mod ipc;
mod logging;
mod registry;
mod tracing;

static SERVICE_STOP: AtomicBool = AtomicBool::new(false);

/// The service entrypoint for the binary which will be run via powershell / persistence
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ServiceMain(_: u32, _: *mut PWSTR) {
    // register the service with SCM (service control manager)
    let h_status = match unsafe {
        RegisterServiceCtrlHandlerW(PCWSTR(svc_name().as_ptr()), Some(service_handler))
    } {
        Ok(h) => h,
        Err(e) => panic!("[!] Could not register service. {e}"),
    };

    // notify SCM that service is starting
    unsafe { update_service_status(h_status, SERVICE_START_PENDING.0) };

    // start the service main loop
    run_service(h_status);
}

/// Main service execution loop
fn run_service(h_status: SERVICE_STATUS_HANDLE) {
    unsafe {
        update_service_status(h_status, SERVICE_RUNNING.0);

        event_log(
            "Starting SanctumPPLRunner service.",
            EVENTLOG_INFORMATION_TYPE,
            EventID::Info,
        );

        // start tracing session; we spawn this in its own os thread as it is blocking
        std::thread::spawn(|| {
            start_threat_intel_trace();
        });

        // Get ProgramFiles path from environment variable
        let program_files_path = env::var("ProgramW6432")
            .or_else(|_| env::var("ProgramFiles"))
            .unwrap_or_else(|_| {
                event_log(
                    "Neither ProgramW6432 nor ProgramFiles environment variable found. Falling back to C:\\Program Files.",
                    EVENTLOG_ERROR_TYPE,
                    EventID::GeneralError,
                );
                "C:\\Program Files".to_string()
            });

        // Construct path for HydraDragonLauncher.exe
        let mut hydra_dragon_path_buf = PathBuf::from(&program_files_path);
        hydra_dragon_path_buf.push("HydraDragonAntivirus");
        hydra_dragon_path_buf.push("HydraDragonAntivirusLauncher.exe");

        if let Some(hydra_dragon_path) = hydra_dragon_path_buf.to_str() {
            spawn_child_ppl_process(hydra_dragon_path);
        } else {
            event_log(
                "Invalid path for HydraDragonAntivirusLauncher.exe. Skipping.",
                EVENTLOG_ERROR_TYPE,
                EventID::GeneralError,
            );
        }

        // Construct path for owlyshield_ransom.exe
        let mut owlyshield_path_buf = PathBuf::from(&program_files_path);
        owlyshield_path_buf.push("HydraDragonAntivirus");
        owlyshield_path_buf.push("hydradragon");
        owlyshield_path_buf.push("Owlyshield");
        owlyshield_path_buf.push("Owlyshield Service");
        owlyshield_path_buf.push("owlyshield_ransom.exe");

        if let Some(owlyshield_path) = owlyshield_path_buf.to_str() {
            spawn_child_ppl_process(owlyshield_path);
        } else {
            event_log(
                "Invalid path for owlyshield_ransom.exe. Skipping.",
                EVENTLOG_ERROR_TYPE,
                EventID::GeneralError,
            );
        }

        // event loop
        while !SERVICE_STOP.load(Ordering::SeqCst) {
            sleep(Duration::from_secs(1));
        }

        update_service_status(h_status, SERVICE_STOPPED.0);
    }
}

/// Spawns a child process as Protected Process Light.
///
/// **Note** The child process MUST be signed with the ELAM certificate, and any DLLs it relies upon must either
/// be signed correctly by Microsoft including the pagehashes in the signature, or signed by the ELAM certificate used
/// to sign this, and the child process.
fn spawn_child_ppl_process(process_to_run: &str) {
    let mut startup_info = STARTUPINFOEXW::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;

    let mut attribute_size_list: usize = 0;
    let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut attribute_size_list) };

    if attribute_size_list == 0 {
        event_log(
            &format!(
                "Error initialising thread attribute list for {}",
                process_to_run
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return;
    }

    let mut attribute_list_mem = vec![0u8; attribute_size_list];
    startup_info.lpAttributeList =
        LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list_mem.as_mut_ptr() as *mut _);

    if let Err(e) = unsafe {
        InitializeProcThreadAttributeList(
            Some(startup_info.lpAttributeList),
            1,
            None,
            &mut attribute_size_list,
        )
    } {
        event_log(
            &format!(
                "Error initialising thread attribute list for {}: {}",
                process_to_run, e
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return;
    }

    // update protection level to be the same as the PPL service
    let mut protection_level = PROTECTION_LEVEL_SAME;
    if let Err(e) = unsafe {
        UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL as _,
            Some(&mut protection_level as *mut _ as *mut _),
            size_of_val(&protection_level),
            None,
            None,
        )
    } {
        event_log(
            &format!(
                "Error UpdateProcThreadAttribute for {}: {}",
                process_to_run, e
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return;
    }

    // start the process
    let mut process_info = PROCESS_INFORMATION::default();
    let mut path: Vec<u16> = process_to_run.encode_utf16().collect();
    path.push(0);

    if let Err(e) = unsafe {
        CreateProcessW(
            PCWSTR(path.as_ptr()),
            None,
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
            None,
            PCWSTR::null(),
            &mut startup_info as *mut _ as *const _,
            &mut process_info,
        )
    } {
        event_log(
            &format!(
                "Error starting child PPL process via CreateProcessW for {}: {}",
                process_to_run, e
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        // Don't exit the whole service if one process fails to start
        return;
    }

    event_log(
        &format!("SanctumPPLRunner started child process: {}", process_to_run),
        EVENTLOG_SUCCESS,
        EventID::Info,
    );
}

/// Handles service control events (e.g., stop)
unsafe extern "system" fn service_handler(control: u32) {
    match control {
        SERVICE_CONTROL_STOP => {
            SERVICE_STOP.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

/// Update the service status in the SCM
unsafe fn update_service_status(h_status: SERVICE_STATUS_HANDLE, state: u32) {
    let mut service_status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STATUS_CURRENT_STATE(state),
        dwControlsAccepted: if state == SERVICE_RUNNING.0 { 1 } else { 0 },
        dwWin32ExitCode: ERROR_SUCCESS.0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };

    unsafe {
        let _ = SetServiceStatus(h_status, &mut service_status);
    }
}

fn main() {
    let mut service_name: Vec<u16> = "SanctumPPLRunner\0".encode_utf16().collect();

    let service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(ServiceMain),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    unsafe {
        StartServiceCtrlDispatcherW(service_table.as_ptr()).unwrap();
    }
}

fn svc_name() -> Vec<u16> {
    let mut svc_name: Vec<u16> = vec![];
    "sanctum_ppl_runner"
        .encode_utf16()
        .for_each(|c| svc_name.push(c));
    svc_name.push(0);

    svc_name
}
