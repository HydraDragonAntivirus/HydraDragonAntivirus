use std::{
    env,
    path::{Path, PathBuf},
    ptr::null_mut,
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
                REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
                RegSetValueExW,
            },
            Services::{
                ChangeServiceConfig2W, ControlService, CreateServiceW, DeleteService,
                OpenSCManagerW, OpenServiceW, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
                SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
                SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT, SERVICE_LAUNCH_PROTECTED_INFO,
                SERVICE_STATUS, SERVICE_WIN32_OWN_PROCESS,
            },
        },
    },
    core::{Error, PCWSTR, PWSTR},
};

fn main() {
    let args: Vec<String> = env::args().collect();

    let is_uninstall = args.iter().any(|a| {
        a.eq_ignore_ascii_case("/uninstall")
            || a.eq_ignore_ascii_case("-uninstall")
            || a.eq_ignore_ascii_case("--uninstall")
    });

    if is_uninstall {
        run_uninstall();
        return;
    }

    run_install();
}

fn run_install() {
    println!("[i] Starting Sanctum & ELAM installer..");

    let system32 =
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()) + "\\System32";
    let driver_path = std::path::PathBuf::from(&system32).join("drivers\\sanctum.sys");

    // Step 1: Create Services via SCManager
    println!("[i] Opening Service Control Manager...");
    let result = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) };

    let h_sc_mgr = match result {
        Ok(h) => h,
        Err(e) => {
            println!("[!] Unable to open SC Manager: {e}");
            return;
        }
    };

    // Step 1a: Create Sanctum Kernel Driver Service
    println!("[i] Configuring Sanctum kernel driver service.");
    let kernel_bin_path = path_to_wstring(&driver_path);
    let kernel_svc_name = to_wstring("Sanctum");
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
            PCWSTR(kernel_bin_path.as_ptr()),
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
            let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h) };
        }
        Err(e) => {
            let win_err = e.code().0 as u32;
            if win_err == 0x80070431 || win_err == 1073 {
                println!("[+] Sanctum kernel driver service already exists.");
            } else {
                println!("[!] Failed to create Sanctum kernel service: {e}");
            }
        }
    }

    // Step 1b: Create PPL AntiMalware Service
    println!("[i] Configuring Sanctum PPL Runner service.");
    let result = unsafe {
        CreateServiceW(
            h_sc_mgr,
            PCWSTR(svc_name().as_ptr()),
            PCWSTR(svc_name().as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
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
            let win_err = e.code().0 as u32;
            if win_err == 0x80070431 || win_err == 1073 {
                println!("[+] PPL service already configured.");
                unsafe {
                    OpenServiceW(h_sc_mgr, PCWSTR(svc_name().as_ptr()), SERVICE_ALL_ACCESS).ok()
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
            println!("[!] Warning: Error calling ChangeServiceConfig2W: {e}");
        }
        let _ = unsafe { windows::Win32::System::Services::CloseServiceHandle(h_svc) };
    }

    if let Err(e) = create_event_source_key() {
        println!("[-] Warning: Failed to create event viewer source key: {e}");
    }

    println!("[+] Successfully initialised Sanctum services.");

    // Step 2: Install ELAM certificate gracefully (non-fatal)
    let path = path_to_wstring(&driver_path);
    println!(
        "[i] Installing ELAM certificate from: {}",
        driver_path.display()
    );

    let result = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
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
            if let Err(e) = unsafe { InstallELAMCertificateInfo(handle) } {
                println!("[!] Warning: Failed to install ELAM certificate info: {e}");
            } else {
                println!("[+] ELAM certificate installed successfully!");
            }
        }
        Err(e) => {
            println!("[!] Warning: Could not open driver file for ELAM certificate: {e}");
        }
    }

    // Auto shutdown / reboot on install
    trigger_auto_reboot();
}

fn trigger_auto_reboot() {
    println!("[*] Automatically restarting the computer to complete ELAM installation...");
    let _ = std::process::Command::new("shutdown")
        .args([
            "/r",
            "/t",
            "10",
            "/c",
            "System restart required for ELAM service installation.",
        ])
        .spawn();
}

fn run_uninstall() {
    println!("[i] Starting ELAM uninstaller..");

    let h_sc_mgr = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) };
    if let Ok(h_sc_mgr) = h_sc_mgr {
        let h_svc =
            unsafe { OpenServiceW(h_sc_mgr, PCWSTR(svc_name().as_ptr()), SERVICE_ALL_ACCESS) };

        if let Ok(h_svc) = h_svc {
            let mut status = SERVICE_STATUS::default();
            let _ = unsafe { ControlService(h_svc, SERVICE_CONTROL_STOP, &mut status) };
            let ret = unsafe { DeleteService(h_svc) };
            if ret.is_ok() {
                println!("[+] Service sanctum_ppl_runner deleted successfully.");
            }
        }

        // Delete Sanctum Kernel Driver Service
        let h_kernel_svc = unsafe {
            OpenServiceW(
                h_sc_mgr,
                PCWSTR(to_wstring("Sanctum").as_ptr()),
                SERVICE_ALL_ACCESS,
            )
        };
        if let Ok(h_kernel_svc) = h_kernel_svc {
            let mut status = SERVICE_STATUS::default();
            let _ = unsafe { ControlService(h_kernel_svc, SERVICE_CONTROL_STOP, &mut status) };
            let ret = unsafe { DeleteService(h_kernel_svc) };
            if ret.is_ok() {
                println!("[+] Service Sanctum kernel driver deleted successfully.");
            }
        }
    }

    // Clean up event log registry entry
    let subkey_path =
        to_wstring("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\SanctumPPLRunner");
    unsafe {
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(subkey_path.as_ptr()));
    }

    println!("[+] ELAM uninstallation completed.");
}

fn svc_name() -> Vec<u16> {
    let mut svc_name: Vec<u16> = vec![];
    "sanctum_ppl_runner"
        .encode_utf16()
        .for_each(|c| svc_name.push(c));
    svc_name.push(0);

    svc_name
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
