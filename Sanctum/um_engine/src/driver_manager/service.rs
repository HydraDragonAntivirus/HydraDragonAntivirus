//! Driver service controls

use shared_std::driver_manager::DriverState;
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_DUPLICATE_SERVICE_NAME, ERROR_NOT_ALL_ASSIGNED,
            ERROR_SERVICE_EXISTS, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
            NTSTATUS, STATUS_IMAGE_ALREADY_LOADED, STATUS_OBJECT_NAME_COLLISION,
            STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS,
            UNICODE_STRING, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_LOAD_DRIVER_NAME,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING},
        System::{
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ,
                REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
                RegSetValueExW,
            },
            Services::{
                CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
                OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
                SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                SERVICE_KERNEL_DRIVER, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS,
                SERVICE_STOP, StartServiceW,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
    core::{Error, HRESULT, PCWSTR, PWSTR},
};

use crate::{
    driver_manager::DriverHandleRaii,
    strings::create_unicode_string,
    utils::log::{Log, LogLevel},
};

use super::manager::SanctumDriverManager;

const DELETE_SERVICE_ACCESS: u32 = 0x0001_0000;

#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtLoadDriver"]
    fn nt_load_driver(driver_service_name: *const UNICODE_STRING) -> NTSTATUS;

    #[link_name = "NtUnloadDriver"]
    fn nt_unload_driver(driver_service_name: *const UNICODE_STRING) -> NTSTATUS;
}

impl SanctumDriverManager {
    /// Command for the driver manager to install the driver on the target device.
    ///
    /// # Panics
    ///
    /// This function will panic if it was unable to open the service manager or install the driver
    /// in most cases. ERROR_SERVICE_EXISTS, ERROR_DUPLICATE_SERVICE_NAME will not panic.
    pub fn install_driver(&mut self) {
        //
        // Create a new ScDbMgr to hold the handle of the result of the OpenSCManagerW call.
        //
        let mut sc_mgr = ServiceControlManager::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);

        //
        // Install the driver on the device
        //
        let handle = unsafe {
            match CreateServiceW(
                sc_mgr.mgr_handle.unwrap(),
                PCWSTR::from_raw(self.svc_name.as_ptr()), // service name
                PCWSTR::from_raw(self.svc_name.as_ptr()), // display name
                SERVICE_QUERY_STATUS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR::from_raw(self.svc_path.as_ptr()),
                None,
                None,
                None,
                None,
                None,
            ) {
                Ok(h) => {
                    if h.is_invalid() {
                        let msg = format!(
                            "Handle returned is invalid when attempting to install the service. Error code: {:?}",
                            GetLastError()
                        );
                        self.update_state_msg(msg);
                    }

                    h
                }
                Err(e) => {
                    let le = GetLastError();

                    match le {
                        ERROR_DUPLICATE_SERVICE_NAME => {
                            let msg = "Unable to create service, duplicate service name found."
                                .to_string();
                            self.update_state_msg(msg);
                            return;
                        }
                        ERROR_SERVICE_EXISTS => {
                            self.state = DriverState::Installed("".to_string());
                            return;
                        }
                        _ => {
                            self.log.log(
                                LogLevel::Error,
                                &format!(
                                    "CreateServiceW failed, falling back to trusted registry install. Error: {e}. Win32: {:?}",
                                    le
                                ),
                            );

                            if let Err(registry_error) = self.install_driver_service_registry() {
                                let msg = format!(
                                    "Unable to create service. SCM error: {e}. Registry fallback error: {registry_error}. Svc path: {}",
                                    self.svc_path_string()
                                );
                                self.update_state_msg(msg);
                                return;
                            }

                            self.state = DriverState::Installed(
                                "Installed through trusted registry fallback.".to_string(),
                            );
                            return;
                        }
                    } // close match last err
                }
            } // close match handle result
        };

        self.log
            .log(LogLevel::Success, "Driver successfully installed");
        self.state = DriverState::Installed("".to_string());

        //
        // At this point, we should have the handle, and we can close it.
        //

        if !handle.is_invalid()
            && let Err(e) = unsafe { CloseServiceHandle(handle) }
        {
            self.log.log(
                LogLevel::Error,
                &format!("[-] Unable to close handle after installing service. Error: {e}"),
            );
        }
    }

    /// Updates the state in place without modifying the actual state of the driver, but allows for passing
    /// an error string back to the GUI, this way, if the driver manager encounters an error, but this error
    /// doesn't change the state of the driver, we can communicate this to the user without altering the state.
    ///
    /// Only use this in cases where the state doesn't change to something new, but you wish to emit a string. Usually an
    /// error message.
    fn update_state_msg(&mut self, new_message: String) {
        match self.state {
            DriverState::Uninstalled(ref mut msg)
            | DriverState::Installed(ref mut msg)
            | DriverState::Started(ref mut msg)
            | DriverState::Stopped(ref mut msg) => {
                *msg = new_message;
            }
        };
    }

    /// Start the driver.
    ///
    /// # Panics
    ///
    /// Function will panic if it cannot open a handle to the SC Manager
    pub fn start_driver(&mut self) {
        //
        // Create a new ScDbMgr to hold the handle of the result of the OpenSCManagerW call.
        //
        let mut sc_mgr = ServiceControlManager::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_CONNECT);

        // get a handle to sanctum service
        if let Err(e) = sc_mgr.get_handle_to_sanctum_svc(self, SERVICE_START | SERVICE_QUERY_STATUS)
        {
            self.log.log(
                LogLevel::Error,
                &format!("Failed to get the Sanctum SCM handle, falling back to NtLoadDriver. {e}"),
            );
            self.start_driver_via_nt_load();
            return;
        }

        unsafe {
            if let Err(e) = StartServiceW(sc_mgr.sanctum_handle.unwrap(), None) {
                self.log.log(
                    LogLevel::Error,
                    &format!(
                        "[-] Failed to start service. {e}. Handle: {:?}.",
                        sc_mgr.mgr_handle.unwrap()
                    ),
                );

                self.start_driver_via_nt_load();
                return;
            };
        };

        self.finish_driver_start("Driver started successfully");
    }

    /// Stop the driver
    ///
    /// # Panics
    ///
    /// Function will panic if it cannot open a handle to the SC Manager
    pub fn stop_driver(&mut self) {
        let mut sc_mgr = ServiceControlManager::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_CONNECT);

        // get a handle to sanctum service
        if let Err(e) = sc_mgr.get_handle_to_sanctum_svc(self, SERVICE_STOP | SERVICE_QUERY_STATUS)
        {
            self.log.log(
                LogLevel::Error,
                &format!(
                    "Failed to get the Sanctum SCM handle while stopping, falling back to NtUnloadDriver. {e}"
                ),
            );
            self.stop_driver_via_nt_unload();
            return;
        }

        let mut service_status = SERVICE_STATUS::default();

        if let Err(e) = unsafe {
            ControlService(
                sc_mgr.sanctum_handle.unwrap(),
                SERVICE_CONTROL_STOP,
                &mut service_status,
            )
        } {
            // if was error
            self.log.log(
                LogLevel::Error,
                &format!(
                    "Failed to stop the service through SCM, falling back to NtUnloadDriver. {e}. Handle: {:?}",
                    sc_mgr.mgr_handle.unwrap()
                ),
            );
            self.stop_driver_via_nt_unload();
            return;
        }

        // if we were successful, delete our local reference to the driver handle
        // todo - possible bug here, making the handle None if there was an error
        // maybe some form of IOCTL conversation to make sure unload is unloading..?
        self.handle_via_path = DriverHandleRaii::default(); // drop will be invoked closing the handle

        self.state = DriverState::Stopped("".to_string());

        self.log
            .log(LogLevel::Success, "Driver stopped successfully");
    }

    /// Uninstall the driver.
    ///
    /// # Panics
    ///
    /// Function will panic if it cannot open a handle to the SC Manager
    pub fn uninstall_driver(&mut self) {
        let mut sc_mgr = ServiceControlManager::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_CONNECT);

        // get a handle to sanctum service
        if let Err(e) = sc_mgr.get_handle_to_sanctum_svc(
            self,
            DELETE_SERVICE_ACCESS | SERVICE_STOP | SERVICE_QUERY_STATUS,
        ) {
            self.log.log(
                LogLevel::Error,
                &format!(
                    "Failed to get the Sanctum SCM handle while uninstalling, falling back to trusted registry removal. {e}"
                ),
            );
            self.uninstall_driver_via_registry();
            return;
        }

        if let Err(e) = unsafe { DeleteService(sc_mgr.sanctum_handle.unwrap()) } {
            self.log.log(
                LogLevel::Error,
                &format!(
                    "[-] Failed to uninstall the driver: {e}. Handle: {:?}",
                    sc_mgr.mgr_handle.unwrap()
                ),
            );
            self.uninstall_driver_via_registry();
            return;
        }

        self.state = DriverState::Uninstalled("".to_string());

        self.log
            .log(LogLevel::Success, "Driver uninstalled successfully");
    }

    /// Gets a handle to the driver via its registry path using CreateFileW. This function
    /// may silently fail if the driver is not installed, or there is some other error.
    ///
    /// If unsuccessful, the handle field will be None; otherwise it will be Some(handle). The handle is managed
    /// by Rust's RAII Drop trait so no requirement to manually close the handle.
    ///
    /// todo better error handling for this fn.
    pub fn init_handle_via_registry(&mut self) -> bool {
        let filename = PCWSTR::from_raw(self.device_um_symbolic_link_name.as_ptr());
        let handle = unsafe {
            CreateFileW(
                filename,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(h) => self.handle_via_path.handle = Some(h),
            Err(_e) => {
                // self.log.log(LogLevel::Error, &format!("Unable to get handle to driver via its registry path, error: {e}."));
                return false;
            }
        }

        true
    }

    fn start_driver_via_nt_load(&mut self) {
        match self.load_driver_via_nt() {
            Ok(()) => self.finish_driver_start("Driver started successfully through NtLoadDriver"),
            Err(e) => {
                let msg = format!("Failed to start service through SCM and NtLoadDriver. {e}.");
                self.state = DriverState::Stopped(msg);
            }
        }
    }

    fn finish_driver_start(&mut self, success_message: &str) {
        // try to get a handle now the driver has started
        self.init_handle_via_registry();

        // check the driver version is compatible with the engine
        if !self.ioctl_check_driver_compatibility() {
            self.stop_driver(); // ensure a clean shutdown
            let msg = "Driver and client version incompatible. Please ensure you are running the latest version.".to_string();
            self.state = DriverState::Stopped(msg);
            return;
        }

        self.ioctl_send_base_addresses();

        self.state = DriverState::Started("".to_string());

        self.log.log(LogLevel::Success, success_message);
    }

    fn stop_driver_via_nt_unload(&mut self) {
        match self.unload_driver_via_nt() {
            Ok(()) => {
                self.handle_via_path = DriverHandleRaii::default();
                self.state = DriverState::Stopped("".to_string());
                self.log
                    .log(LogLevel::Success, "Driver stopped through NtUnloadDriver");
            }
            Err(e) => {
                let msg = format!("Failed to stop the service through SCM and NtUnloadDriver. {e}");
                self.update_state_msg(msg);
            }
        }
    }

    fn uninstall_driver_via_registry(&mut self) {
        let _ = self.unload_driver_via_nt();

        match self.delete_driver_service_registry() {
            Ok(()) => {
                self.handle_via_path = DriverHandleRaii::default();
                self.state = DriverState::Uninstalled("".to_string());
                self.log.log(
                    LogLevel::Success,
                    "Driver service registry removed through trusted fallback",
                );
            }
            Err(e) => {
                let msg =
                    format!("Failed to uninstall through SCM and trusted registry fallback. {e}");
                self.update_state_msg(msg);
            }
        }
    }

    fn load_driver_via_nt(&mut self) -> Result<(), Error> {
        self.install_driver_service_registry()?;
        self.enable_load_driver_privilege()?;

        let registry_path = to_wide_null(&self.nt_service_registry_path());
        let registry_path =
            create_unicode_string(&registry_path).expect("registry path is non-empty");
        let status = unsafe { nt_load_driver(&registry_path) };

        match status {
            STATUS_SUCCESS | STATUS_IMAGE_ALREADY_LOADED | STATUS_OBJECT_NAME_COLLISION => Ok(()),
            _ => Err(ntstatus_error(status)),
        }
    }

    fn unload_driver_via_nt(&mut self) -> Result<(), Error> {
        self.enable_load_driver_privilege()?;

        let registry_path = to_wide_null(&self.nt_service_registry_path());
        let registry_path =
            create_unicode_string(&registry_path).expect("registry path is non-empty");
        let status = unsafe { nt_unload_driver(&registry_path) };

        match status {
            STATUS_SUCCESS | STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => Ok(()),
            _ => Err(ntstatus_error(status)),
        }
    }

    fn enable_load_driver_privilege(&self) -> Result<(), Error> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )?;
        }

        let mut luid = Default::default();
        let lookup_result =
            unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_LOAD_DRIVER_NAME, &mut luid) };

        if let Err(e) = lookup_result {
            let _ = unsafe { CloseHandle(token) };
            return Err(e);
        }

        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let adjust_result =
            unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None) };
        let last_error = unsafe { GetLastError() };
        let _ = unsafe { CloseHandle(token) };

        adjust_result?;
        if last_error == ERROR_NOT_ALL_ASSIGNED {
            return Err(win32_error(last_error));
        }

        Ok(())
    }

    fn install_driver_service_registry(&self) -> Result<(), Error> {
        let subkey_path = to_wide_null(&self.service_registry_subkey());
        let mut hkey = HKEY::default();

        let ret = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_path.as_ptr()),
                None,
                PWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                None,
                &mut hkey,
                None,
            )
        };
        if ret != ERROR_SUCCESS {
            return Err(win32_error(ret));
        }

        let result = (|| {
            set_registry_dword(hkey, "Type", SERVICE_KERNEL_DRIVER.0)?;
            set_registry_dword(hkey, "Start", SERVICE_DEMAND_START.0)?;
            set_registry_dword(hkey, "ErrorControl", SERVICE_ERROR_NORMAL.0)?;

            let image_path = to_wide_null(&format!(r"\??\{}", self.svc_path_string()));
            set_registry_string(hkey, "ImagePath", &image_path)?;
            Ok(())
        })();

        let _ = unsafe { RegCloseKey(hkey) };
        result
    }

    fn delete_driver_service_registry(&self) -> Result<(), Error> {
        let subkey_path = to_wide_null(&self.service_registry_subkey());
        let ret = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(subkey_path.as_ptr())) };
        if ret != ERROR_SUCCESS {
            return Err(win32_error(ret));
        }

        Ok(())
    }

    fn service_registry_subkey(&self) -> String {
        format!(
            r"SYSTEM\CurrentControlSet\Services\{}",
            self.service_name_string()
        )
    }

    fn nt_service_registry_path(&self) -> String {
        format!(
            r"\Registry\Machine\System\CurrentControlSet\Services\{}",
            self.service_name_string()
        )
    }

    fn service_name_string(&self) -> String {
        wide_string_without_nul(&self.svc_name)
    }

    fn svc_path_string(&self) -> String {
        wide_string_without_nul(&self.svc_path)
    }
}

fn wide_string_without_nul(value: &[u16]) -> String {
    String::from_utf16_lossy(value)
        .trim_end_matches('\0')
        .to_string()
}

fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_registry_dword(hkey: HKEY, name: &str, value: u32) -> Result<(), Error> {
    let value_name = to_wide_null(name);
    let value_bytes = value.to_le_bytes();
    let ret = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            REG_DWORD,
            Some(&value_bytes),
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(win32_error(ret));
    }

    Ok(())
}

fn set_registry_string(hkey: HKEY, name: &str, value: &[u16]) -> Result<(), Error> {
    let value_name = to_wide_null(name);
    let value_bytes = unsafe {
        std::slice::from_raw_parts(value.as_ptr() as *const u8, std::mem::size_of_val(value))
    };
    let ret = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            REG_EXPAND_SZ,
            Some(value_bytes),
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(win32_error(ret));
    }

    Ok(())
}

fn win32_error(error: WIN32_ERROR) -> Error {
    Error::from_hresult(HRESULT::from_win32(error.0))
}

fn ntstatus_error(status: NTSTATUS) -> Error {
    Error::from_hresult(HRESULT::from_nt(status.0))
}

/// A custom struct to hold a SC_HANDLE. This struct implements the drop trait so that
/// when it goes out of scope, it will clean up its handle so you do not need to remember
/// to call CloseServiceHandle.
struct ServiceControlManager {
    mgr_handle: Option<SC_HANDLE>,
    sanctum_handle: Option<SC_HANDLE>,
}

impl ServiceControlManager {
    /// Establishes a connection to the service control manager on the computer and opens the specified
    /// service control manager database.
    ///
    /// # Panics
    ///
    /// If the call to OpenServiceManagerW fails, this will panic.
    fn open_service_manager_w(&mut self, dw_desired_access: u32) {
        self.mgr_handle = unsafe {
            match OpenSCManagerW(None, None, dw_desired_access) {
                Ok(h) => Some(h),
                Err(e) => panic!("[-] Unable to open service manager handle, {e}."),
            }
        }
    }

    /// Attempt to obtain a handle to the Sanctum service. If this is successful the function returns
    /// a Result<()>, and the field sanctum_handle is given the value of the handle.
    ///
    /// The handle will automatically be closed when it goes out of scope as it is implemented in the
    /// drop trait.
    fn get_handle_to_sanctum_svc(
        &mut self,
        driver_manager: &SanctumDriverManager,
        desired_access: u32,
    ) -> Result<(), Error> {
        let driver_handle = unsafe {
            OpenServiceW(
                self.mgr_handle.unwrap(),
                PCWSTR::from_raw(driver_manager.svc_name.as_ptr()),
                desired_access,
            )
        }?;

        self.sanctum_handle = Some(driver_handle);

        // we return nothing, as the field sanctum_handle is set on success
        Ok(())
    }

    /// Instantiates the ServiceInterface with a null handle.
    fn new() -> ServiceControlManager {
        ServiceControlManager {
            mgr_handle: None,
            sanctum_handle: None,
        }
    }
}

impl Drop for ServiceControlManager {
    /// Automatically close the service handle if it is valid
    fn drop(&mut self) {
        //
        // Close the handle for the SC DB
        //
        if self.mgr_handle.is_none() {
            return;
        }

        let log = Log::new();

        if !self.mgr_handle.unwrap().0.is_null() {
            if let Err(e) = unsafe { CloseServiceHandle(self.mgr_handle.unwrap()) } {
                log.log(
                    LogLevel::Error,
                    &format!("Unable to close handle after installing service. Error: {e}."),
                );
            }
            self.mgr_handle = None;
        } else {
            log.log(LogLevel::Error, "Unable to close handle, handle was null");
        }

        //
        // Close the handle to the sanctum driver
        //
        if self.sanctum_handle.is_none() {
            return;
        }

        if !self.sanctum_handle.unwrap().0.is_null() {
            if let Err(e) = unsafe { CloseServiceHandle(self.sanctum_handle.unwrap()) } {
                log.log(
                    LogLevel::Error,
                    &format!("Unable to close handle after installing service. Error: {e}."),
                );
            }
            self.sanctum_handle = None;
        } else {
            log.log(LogLevel::Error, "Unable to close handle, handle was null");
        }
    }
}
