use std::{
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::atomic::{AtomicIsize, Ordering},
};

use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_READ_DATA, FILE_SHARE_READ, OPEN_EXISTING,
        },
        System::{
            Antimalware::InstallELAMCertificateInfo,
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ,
                REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegSetValueExW,
            },
            Services::{
                ChangeServiceConfig2W, CreateServiceW, LPSERVICE_MAIN_FUNCTIONW, OpenSCManagerW,
                RegisterServiceCtrlHandlerW, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
                SERVICE_AUTO_START, SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
                SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT, SERVICE_LAUNCH_PROTECTED_INFO,
                SERVICE_LAUNCH_PROTECTED_NONE, SERVICE_START_PENDING, SERVICE_STATUS_CURRENT_STATE,
                SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
                SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
            },
        },
    },
    core::{Error, PCWSTR, PWSTR},
};

static SVC_STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

fn main() {
    println!("[i] Starting Sanctum & ELAM installer..");

    // If launched by the SCM (auto-start service at boot), go through the
    // service protocol; otherwise SCM kills us with error 1053 even though
    // the work is already done.
    unsafe {
        let name = to_wstring("elam_installer");
        let mut table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_ptr() as *mut u16),
                lpServiceProc: LPSERVICE_MAIN_FUNCTIONW::Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        if StartServiceCtrlDispatcherW(table.as_mut_ptr()).is_ok() {
            // service_main did the work and reported SERVICE_STOPPED.
            return;
        }
        let code = Error::from_win32().code().0 as u32 & 0xFFFF;
        if code != 1063 {
            // 1063 = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (console start)
            println!("[!] Service dispatcher failed (error {code}); running in console mode.");
        }
    }

    run_installer();
}

unsafe extern "system" fn svc_handler(_control: u32) {}

fn log_step(msg: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\ProgramData\edrsvc\log\elam_installer.log")
    {
        let _ = writeln!(f, "[{secs}] {msg}");
    }
}

fn report_status(state: SERVICE_STATUS_CURRENT_STATE) {
    unsafe {
        let handle = SERVICE_STATUS_HANDLE(SVC_STATUS_HANDLE.load(Ordering::SeqCst) as *mut _);
        if handle.0.is_null() {
            return;
        }
        let status = windows::Win32::System::Services::SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        let _ = SetServiceStatus(handle, &status);
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    unsafe {
        let name = to_wstring("elam_installer");
        match RegisterServiceCtrlHandlerW(PCWSTR(name.as_ptr()), Some(svc_handler)) {
            Ok(handle) => SVC_STATUS_HANDLE.store(handle.0 as isize, Ordering::SeqCst),
            Err(_) => return,
        }
        report_status(SERVICE_START_PENDING);

        // Run the installation on a worker thread so the SCM dispatch stays
        // responsive even if a step (e.g. ELAM certificate validation) takes
        // long - the service must never sit in START_PENDING forever.
        let worker = std::thread::spawn(|| {
            log_step("service start: install beginning");
            run_installer();
            log_step("service start: install finished");
            report_status(SERVICE_STOPPED);
        });
        let _ = worker.join();
    }
}

fn run_installer() {
    let h_sc_mgr = unsafe {
        match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) {
            Ok(h) => h,
            Err(e) => {
                println!("[!] Unable to open SC Manager: {e}");
                return;
            }
        }
    };

    let args: Vec<String> = std::env::args().collect();
    if args
        .iter()
        .any(|arg| arg == "--uninstall" || arg == "/uninstall" || arg == "uninstall")
    {
        uninstall_all_sanctum_services(h_sc_mgr);
        return;
    }

    // Step 1: Register Sanctum Kernel Driver Service
    // NOTE: must stay SERVICE_DEMAND_START. Boot-start + Early-Launch group
    // makes winload load the driver before logon; a test-signed or buggy
    // driver there black-screens the machine at next reboot.
    let kernel_svc_name = to_wstring("Sanctum");

    // First check if the service already exists to avoid redundant create requests
    if let Ok(h_existing) = unsafe {
        windows::Win32::System::Services::OpenServiceW(
            h_sc_mgr,
            PCWSTR(kernel_svc_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
    } {
        println!("[+] 2nd boot detected. Starting services...");
        log_step("kernel driver service exists -> starting it");

        let _ = unsafe { windows::Win32::System::Services::StartServiceW(h_existing, None) };
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_existing) };

        // Ensure PPL runner is started on subsequent boots
        let ppl_svc_name = to_wstring("sanctum_ppl_runner");
        if let Ok(h_ppl) = unsafe {
            windows::Win32::System::Services::OpenServiceW(
                h_sc_mgr,
                PCWSTR(ppl_svc_name.as_ptr()),
                SERVICE_ALL_ACCESS,
            )
        } {
            log_step("starting sanctum_ppl_runner...");
            let _ = unsafe { windows::Win32::System::Services::StartServiceW(h_ppl, None) };
            let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_ppl) };
        }

        return; // Early exit on subsequent boots!
    }

    println!("[i] Configuring Sanctum kernel driver service.");
    let kernel_driver_path =
        installed_path("AppData\\sanctum.sys").unwrap_or_else(|_| fallback_driver_path());
    let kernel_path_w = path_to_wstring(&kernel_driver_path);
    let kernel_svc_display = to_wstring("Sanctum Kernel Driver");

    let h_kernel_svc = unsafe {
        CreateServiceW(
            h_sc_mgr,
            PCWSTR(kernel_svc_name.as_ptr()),
            PCWSTR(kernel_svc_display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(kernel_path_w.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };

    match h_kernel_svc {
        Ok(h) => {
            println!("[+] Sanctum kernel driver service created successfully.");
            log_step("kernel driver service created");
            let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h) };
        }
        Err(e) => {
            println!("[!] Warning: Failed to create Sanctum kernel service: {e}");
        }
    }

    // Step 2: Install ELAM Certificate Info
    println!(
        "[i] Installing ELAM certificate from: {}",
        kernel_driver_path.display()
    );
    log_step("opening driver file for ELAM certificate");

    let result = unsafe {
        CreateFileW(
            PCWSTR(kernel_path_w.as_ptr()),
            FILE_READ_DATA.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    match result {
        Ok(handle) => {
            log_step("calling InstallELAMCertificateInfo");
            if let Err(e) = unsafe { InstallELAMCertificateInfo(handle) } {
                println!("[!] Warning: Failed to install ELAM certificate info: {e}");
                log_step("InstallELAMCertificateInfo FAILED");
            } else {
                println!("[+] ELAM certificate installed successfully!");
                log_step("InstallELAMCertificateInfo succeeded");
            }
        }
        Err(e) => {
            println!("[!] Warning: Could not open driver file for ELAM certificate: {e}");
            log_step("could not open driver file for ELAM certificate");
        }
    }

    // Step 3: Register Sanctum PPL Runner Service
    println!("[i] Attempting to create the PPL service.");
    let result = unsafe {
        CreateServiceW(
            h_sc_mgr,
            PCWSTR(svc_name().as_ptr()),
            PCWSTR(svc_name().as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(svc_bin_path().as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };

    let h_svc = match result {
        Ok(h) => Some(h),
        Err(e) => {
            if e.code().0 as u32 == 0x80070431 || e.code().0 as u32 == 1073 {
                println!("[+] PPL service already configured.");
                unsafe {
                    windows::Win32::System::Services::OpenServiceW(
                        h_sc_mgr,
                        PCWSTR(svc_name().as_ptr()),
                        SERVICE_ALL_ACCESS,
                    )
                    .ok()
                }
            } else {
                println!("[!] Failed to create PPL service: {e}");
                None
            }
        }
    };

    if let Some(h_svc) = h_svc {
        let mut info = SERVICE_LAUNCH_PROTECTED_INFO {
            dwLaunchProtected: SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT,
        };

        if let Err(e) = unsafe {
            ChangeServiceConfig2W(
                h_svc,
                SERVICE_CONFIG_LAUNCH_PROTECTED,
                Some(&mut info as *mut _ as *mut _),
            )
        } {
            println!("[!] Warning calling ChangeServiceConfig2W: {e}");
        }
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_svc) };
    }

    if let Err(e) = create_event_source_key() {
        println!("[-] Warning: Failed to create event viewer source key: {e}");
    }

    println!("[+] Successfully initialised the PPL AntiMalware service.");

    // We only reach this point if the Sanctum kernel driver service was newly created.
    // Therefore, this is the first install, and we must reboot.
    trigger_auto_reboot();
}

fn trigger_auto_reboot() {
    println!("[*] Automatically restarting the computer to complete installation...");
    // Use absolute path for shutdown to avoid Session 0 PATH lookup failures
    let _ = std::process::Command::new("C:\\Windows\\System32\\shutdown.exe")
        .args([
            "/r",
            "/t",
            "10",
            "/c",
            "HydraDragon Antivirus ELAM Installation Complete. Restarting...",
        ])
        .status();
}

fn uninstall_all_sanctum_services(h_sc_mgr: windows::Win32::System::Services::SC_HANDLE) {
    println!("[i] Uninstalling Sanctum & ELAM services...");

    // 1. Unprotect sanctum_ppl_runner PPL protection so it can be stopped and deleted without Access Denied
    let ppl_svc_name = svc_name();
    if let Ok(h_svc) = unsafe {
        windows::Win32::System::Services::OpenServiceW(
            h_sc_mgr,
            PCWSTR(ppl_svc_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
    } {
        let mut info = SERVICE_LAUNCH_PROTECTED_INFO {
            dwLaunchProtected: SERVICE_LAUNCH_PROTECTED_NONE,
        };
        let _ = unsafe {
            ChangeServiceConfig2W(
                h_svc,
                SERVICE_CONFIG_LAUNCH_PROTECTED,
                Some(&mut info as *mut _ as *mut _),
            )
        };
        let mut status = windows::Win32::System::Services::SERVICE_STATUS::default();
        let _ = unsafe {
            windows::Win32::System::Services::ControlService(
                h_svc,
                windows::Win32::System::Services::SERVICE_CONTROL_STOP,
                &mut status,
            )
        };
        let _ = unsafe { windows::Win32::System::Services::DeleteService(h_svc) };
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_svc) };
        println!("[+] sanctum_ppl_runner service unprotected, stopped and uninstalled.");
    }

    // 2. Stop and delete Sanctum kernel driver service
    let kernel_svc_name = to_wstring("Sanctum");
    if let Ok(h_svc) = unsafe {
        windows::Win32::System::Services::OpenServiceW(
            h_sc_mgr,
            PCWSTR(kernel_svc_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
    } {
        let mut status = windows::Win32::System::Services::SERVICE_STATUS::default();
        let _ = unsafe {
            windows::Win32::System::Services::ControlService(
                h_svc,
                windows::Win32::System::Services::SERVICE_CONTROL_STOP,
                &mut status,
            )
        };
        let _ = unsafe { windows::Win32::System::Services::DeleteService(h_svc) };
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_svc) };
        println!("[+] Sanctum kernel driver service stopped and uninstalled.");
    }

    // 3. Stop and delete sanctum_elam driver service
    let elam_svc_name = to_wstring("sanctum_elam");
    if let Ok(h_svc) = unsafe {
        windows::Win32::System::Services::OpenServiceW(
            h_sc_mgr,
            PCWSTR(elam_svc_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
    } {
        let mut status = windows::Win32::System::Services::SERVICE_STATUS::default();
        let _ = unsafe {
            windows::Win32::System::Services::ControlService(
                h_svc,
                windows::Win32::System::Services::SERVICE_CONTROL_STOP,
                &mut status,
            )
        };
        let _ = unsafe { windows::Win32::System::Services::DeleteService(h_svc) };
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_svc) };
        println!("[+] sanctum_elam driver service stopped and uninstalled.");
    }

    // 4. Delete the elam_installer service (itself)
    let installer_svc_name = to_wstring("elam_installer");
    if let Ok(h_svc) = unsafe {
        windows::Win32::System::Services::OpenServiceW(
            h_sc_mgr,
            PCWSTR(installer_svc_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
    } {
        let _ = unsafe { windows::Win32::System::Services::DeleteService(h_svc) };
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_svc) };
        println!("[+] elam_installer service uninstalled.");
    }
}

fn svc_name() -> Vec<u16> {
    to_wstring("sanctum_ppl_runner")
}

fn svc_bin_path() -> Vec<u16> {
    let runner_path = installed_path("AppData\\sanctum_ppl_runner.exe")
        .unwrap_or_else(|_| fallback_runner_path());
    path_to_wstring(&runner_path)
}

fn create_event_source_key() -> windows::core::Result<()> {
    let subkey_path =
        to_wstring("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\SanctumPPLRunner");

    let mut hkey: HKEY = HKEY(null_mut());
    let mut disposition: u32 = 0;

    unsafe {
        let ret = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_path.as_ptr()),
            None,
            PWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            None,
            &mut hkey,
            Some(&mut disposition as *mut _ as *mut _),
        );
        if ret != ERROR_SUCCESS {
            return Err(Error::from_win32());
        }

        let value_name = to_wstring("EventMessageFile");
        let event_create_path = to_wstring("%SystemRoot%\\System32\\EventCreate.exe");

        let exe_bytes: &[u8] = std::slice::from_raw_parts(
            event_create_path.as_ptr() as *const u8,
            event_create_path.len() * std::mem::size_of::<u16>(),
        );

        let ret = RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            REG_EXPAND_SZ,
            Some(exe_bytes),
        );
        if ret != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(Error::from_win32());
        }

        let value_name_types = to_wstring("TypesSupported");
        let types_supported: u32 = 7;
        let types_bytes: &[u8] = std::slice::from_raw_parts(
            (&types_supported as *const u32) as *const u8,
            std::mem::size_of::<u32>(),
        );
        let ret = RegSetValueExW(
            hkey,
            PCWSTR(value_name_types.as_ptr()),
            None,
            REG_DWORD,
            Some(types_bytes),
        );
        if ret != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(Error::from_win32());
        }

        let _ = RegCloseKey(hkey);
    }

    Ok(())
}

fn to_wstring(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn path_to_wstring(path: &Path) -> Vec<u16> {
    use std::os::windows::prelude::*;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn installed_path(relative_path: &str) -> std::io::Result<PathBuf> {
    let exe_path = std::env::current_exe()?;
    let install_dir = exe_path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "elam_installer.exe has no parent directory",
        )
    })?;

    Ok(install_dir.join(relative_path))
}

fn fallback_runner_path() -> PathBuf {
    PathBuf::from(
        r"C:\Program Files\HydraDragonAntivirus\OpenEDR\Sanctum\AppData\sanctum_ppl_runner.exe",
    )
}

fn fallback_driver_path() -> PathBuf {
    PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\Sanctum\AppData\sanctum.sys")
}
