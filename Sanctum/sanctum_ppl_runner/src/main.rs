//! A service runner for the Protected Process Lite Antimalware which allows us to interact with ETW:TI

use std::{
    path::Path,
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
mod tracing;

static SERVICE_STOP: AtomicBool = AtomicBool::new(false);
const EXPECTED_RUNNER_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\OpenEDR\Sanctum\AppData\sanctum_ppl_runner.exe";

/// The service entrypoint for the binary which will be run via powershell / persistence
///
/// # Safety
/// This is an FFI callback for the Windows Service Manager.
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

        // event loop
        while !SERVICE_STOP.load(Ordering::SeqCst) {
            sleep(Duration::from_secs(1));
        }

        update_service_status(h_status, SERVICE_STOPPED.0);
    }
}

/// Handles service control events (e.g., stop)
unsafe extern "system" fn service_handler(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        SERVICE_STOP.store(true, Ordering::SeqCst);
    }
}

/// Update the service status in the SCM
unsafe fn update_service_status(h_status: SERVICE_STATUS_HANDLE, state: u32) {
    let service_status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STATUS_CURRENT_STATE(state),
        dwControlsAccepted: if state == SERVICE_RUNNING.0 { 1 } else { 0 },
        dwWin32ExitCode: ERROR_SUCCESS.0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };

    unsafe {
        let _ = SetServiceStatus(h_status, &service_status);
    }
}

fn main() {
    if !is_started_from_expected_path() {
        std::process::exit(1);
    }

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

fn is_started_from_expected_path() -> bool {
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };

    let path_str = normalize_windows_path(&current_exe);
    let expected = normalize_windows_path(Path::new(EXPECTED_RUNNER_PATH));

    path_str == expected
}

fn normalize_windows_path(path: impl AsRef<Path>) -> String {
    let path = path.as_ref().to_string_lossy();
    let path = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix(r"\??\"))
        .unwrap_or(&path);

    path.trim_end_matches(['\\', '/']).to_ascii_lowercase()
}

fn svc_name() -> Vec<u16> {
    let mut svc_name: Vec<u16> = vec![];
    "sanctum_ppl_runner"
        .encode_utf16()
        .for_each(|c| svc_name.push(c));
    svc_name.push(0);

    svc_name
}
