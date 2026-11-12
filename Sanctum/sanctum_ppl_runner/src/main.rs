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
        Foundation::{CloseHandle, ERROR_SUCCESS, HLOCAL, LocalFree, WAIT_OBJECT_0},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        System::{
            EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE},
            Services::{
                ChangeServiceConfig2W, CloseServiceHandle, OpenSCManagerW, OpenServiceW,
                RegisterServiceCtrlHandlerW, SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG,
                SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_CONTROL_STOP,
                SERVICE_LAUNCH_PROTECTED_INFO, SERVICE_LAUNCH_PROTECTED_NONE, SERVICE_RUNNING,
                SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
                SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
                SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
            },
            Threading::{CreateEventW, WaitForSingleObject},
        },
    },
    core::{PCWSTR, PWSTR},
};

mod ipc;
mod logging;
mod tracing;

pub static SERVICE_STOP: AtomicBool = AtomicBool::new(false);

/// Check if the service was requested to stop by SCM or EDRGUI
pub fn is_service_stopping() -> bool {
    SERVICE_STOP.load(Ordering::SeqCst)
}

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

        spawn_uninstall_listener();

        // event loop
        while !SERVICE_STOP.load(Ordering::SeqCst) {
            sleep(Duration::from_secs(1));
        }

        update_service_status(h_status, SERVICE_STOPPED.0);
    }
}

/// Set by `elam_installer --uninstall`. The service runs as an antimalware PPL: an
/// unprotected process (the uninstaller, the MSI) can neither stop it nor remove its
/// launch protection, so DeleteService failed and the service stayed registered
/// after its exe was removed. On this event the runner removes its own protection
/// and stops; the uninstaller then deletes the service. Keep the name in sync with
/// elam_installer.
const UNINSTALL_EVENT_NAME: &str = r"Global\SanctumPplRunnerUninstall";
/// Only SYSTEM and Administrators may open (and so set) the event.
const UNINSTALL_EVENT_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

fn spawn_uninstall_listener() {
    std::thread::spawn(|| {
        let name = to_wide(UNINSTALL_EVENT_NAME);
        let sddl = to_wide(UNINSTALL_EVENT_SDDL);
        let mut psd = PSECURITY_DESCRIPTOR::default();
        if let Err(e) = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
        } {
            event_log(
                &format!("Uninstall event: security descriptor failed: {e}"),
                EVENTLOG_ERROR_TYPE,
                EventID::GeneralError,
            );
            return;
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };
        let event = unsafe { CreateEventW(Some(&sa), true, false, PCWSTR(name.as_ptr())) };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
        }
        let event = match event {
            Ok(h) => h,
            Err(e) => {
                event_log(
                    &format!("Uninstall event could not be created: {e}"),
                    EVENTLOG_ERROR_TYPE,
                    EventID::GeneralError,
                );
                return;
            }
        };

        while !is_service_stopping() {
            if unsafe { WaitForSingleObject(event, 1000) } == WAIT_OBJECT_0 {
                match unprotect_self() {
                    Ok(()) => event_log(
                        "Uninstall requested: launch protection removed, stopping.",
                        EVENTLOG_INFORMATION_TYPE,
                        EventID::Info,
                    ),
                    Err(e) => event_log(
                        &format!("Uninstall requested: removing launch protection failed: {e}"),
                        EVENTLOG_ERROR_TYPE,
                        EventID::GeneralError,
                    ),
                }
                SERVICE_STOP.store(true, Ordering::SeqCst);
                break;
            }
        }
        unsafe {
            let _ = CloseHandle(event);
        }
    });
}

/// Sets this service's launch protection to none (allowed from inside the PPL).
fn unprotect_self() -> windows::core::Result<()> {
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)?;
        let svc = match OpenServiceW(scm, PCWSTR(svc_name().as_ptr()), SERVICE_CHANGE_CONFIG) {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                return Err(e);
            }
        };
        let mut info = SERVICE_LAUNCH_PROTECTED_INFO {
            dwLaunchProtected: SERVICE_LAUNCH_PROTECTED_NONE,
        };
        let r = ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_LAUNCH_PROTECTED,
            Some(&mut info as *mut _ as *mut _),
        );
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        r
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
