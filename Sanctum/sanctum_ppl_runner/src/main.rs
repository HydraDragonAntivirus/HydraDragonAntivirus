//! A service runner for the Protected Process Lite Antimalware which allows us to interact with ETW:TI

use std::{
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
                RegisterServiceCtrlHandlerW, SERVICE_RUNNING, SERVICE_START_PENDING,
                SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
                SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
                StartServiceCtrlDispatcherW,
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

        // spawn child PPL - n.b. this is no longer used.
        // spawn_child_ppl_process();

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
fn spawn_child_ppl_process() {
    let mut startup_info = STARTUPINFOEXW::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    let mut attribute_size_list: usize = 0;

    let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut attribute_size_list) };

    if attribute_size_list == 0 {
        event_log(
            "Error initialising thread attribute list",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        std::process::exit(1);
    }

    let mut attribute_list_mem = vec![0u8; attribute_size_list];
    startup_info.lpAttributeList =
        LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list_mem.as_mut_ptr() as *mut _);

    if let Err(_) = unsafe {
        InitializeProcThreadAttributeList(
            Some(startup_info.lpAttributeList),
            1,
            None,
            &mut attribute_size_list,
        )
    } {
        event_log(
            "Error initialising thread attribute list",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        std::process::exit(1);
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
            &format!("Error UpdateProcThreadAttribute, {}", e),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        std::process::exit(1);
    }

    // start the process
    let mut process_info = PROCESS_INFORMATION::default();
    // todo update this
    let path: Vec<u16> = r"C:\Users\flux\AppData\Roaming\Sanctum\etw_consumer.exe"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

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
                "Error calling starting child PPL process via CreateProcessW, {}",
                e
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        std::process::exit(1);
    }

    event_log(
        "SanctumPPLRunner started child process.",
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
