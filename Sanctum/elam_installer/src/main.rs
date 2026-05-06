use std::{
    path::{Path, PathBuf},
    process::exit,
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
                HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPENED_EXISTING_KEY,
                REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegSetValueExW,
            },
            Services::{
                ChangeServiceConfig2W, CreateServiceW, OpenSCManagerW, SC_MANAGER_ALL_ACCESS,
                SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT, SERVICE_LAUNCH_PROTECTED_INFO,
                SERVICE_WIN32_OWN_PROCESS,
            },
        },
        UI::WindowsAndMessaging::{MB_ICONWARNING, MessageBoxA},
    },
    core::{Error, PCWSTR, PWSTR, s},
};

fn main() {
    //
    // Step 1:
    // Install the ELAM certificate via the driver (.sys) file.
    //
    println!("[i] Starting Elam installer..");

    let driver_path =
        installed_path("AppData\\sanctum.sys").expect("[-] Could not resolve ELAM driver path");
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

    let handle = match result {
        Ok(h) => h,
        Err(e) => panic!("[!] An error occurred whilst trying to open a handle to the driver. {e}"),
    };

    if let Err(e) = unsafe { InstallELAMCertificateInfo(handle) } {
        panic!("[!] Failed to install ELAM certificate. Error: {e}");
    }

    println!("[+] ELAM certificate installed successfully!");

    //
    // Step 2:
    // Create a service with correct privileges
    //

    println!("[i] Attempting to create the service.");
    let result = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) };

    let h_sc_mgr = match result {
        Ok(h) => h,
        Err(e) => panic!("[!] Unable to open SC Manager. {e}"),
    };

    // create an own process service

    let result = unsafe {
        CreateServiceW(
            h_sc_mgr,
            PCWSTR(svc_name().as_ptr()),
            PCWSTR(svc_name().as_ptr()),
            SC_MANAGER_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, // Service that runs in its own process
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
        Ok(h) => h,
        Err(e) => {
            if e.code().0 as u32 == 0x80070431 {
                println!("[+] PPL service configured, you can now run the service.");
                exit(0)
            }
            panic!("[!] Failed to create service. {e}")
        }
    };

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
        panic!("[!] Error calling ChangeServiceConfig2W. {e}");
    }

    if let Err(e) = create_event_source_key() {
        panic!("[-] Failed to create event viewer source key. {e}");
    }

    println!(
        "[+] Successfully initialised the PPL AntiMalware service. It now needs staring with `sc.exe start sanctum_ppl_runner`."
    );
    println!(
        "[*] The computer now needs to be restarted to complete installation. You will need to run elam_installer.exe on every boot (but reboot only occurs on first run when instructed)."
    );
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
            None, // default security
            &mut hkey,
            Some(&mut disposition as *mut _ as *mut _),
        );
        if ret != ERROR_SUCCESS {
            return Err(Error::from_win32());
        }

        // only create the key once, if it exists, return out
        if disposition == REG_OPENED_EXISTING_KEY.0 {
            return Ok(());
        }

        let value_name = to_wstring("EventMessageFile");
        let runner_path = installed_path("AppData\\sanctum_ppl_runner.exe")
            .unwrap_or_else(|_| fallback_runner_path());
        let exe_path = path_to_wstring(&runner_path);

        let exe_bytes: &[u8] = std::slice::from_raw_parts(
            exe_path.as_ptr() as *const u8,
            exe_path.len() * std::mem::size_of::<u16>(),
        );

        let ret = RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            REG_SZ,
            Some(exe_bytes),
        );
        if ret != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(Error::from_win32());
        }

        let value_name_types = to_wstring("TypesSupported");
        let types_supported: u32 = 7; // 7 (0x7) Supports Error, Warning, and Information event types.
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

        // warn user device needs a reboot for the registry change to take proper effect
        MessageBoxA(
            None,
            s!("System needs a reboot for service installation to take effect. Please restart."),
            s!("Reboot required"),
            MB_ICONWARNING,
        );
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
        r"C:\Program Files\HydraDragonAntivirus\hydradragon\Sanctum\AppData\sanctum_ppl_runner.exe",
    )
}
