//! Monitor operations related to the registry

use core::{
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicI64, Ordering},
};

use alloc::{format, string::String, vec::Vec};
use crate::utils::{get_process_name, Log};
use wdk::{nt_success, println};
use wdk_sys::{
    _REG_NOTIFY_CLASS::{RegNtPreDeleteKey, RegNtPreSetValueKey},
    DRIVER_OBJECT, LARGE_INTEGER, NTSTATUS, REG_DELETE_KEY_INFORMATION,
    REG_SET_VALUE_KEY_INFORMATION, REG_NOTIFY_CLASS, STATUS_ACCESS_DENIED, STATUS_SUCCESS,
    UNICODE_STRING,
    ntddk::{
        CmCallbackGetKeyObjectIDEx, CmCallbackReleaseKeyObjectIDEx, CmRegisterCallbackEx,
        CmUnRegisterCallback, RtlInitUnicodeString,
    },
};

static REGISTRY_COOKIE: AtomicI64 = AtomicI64::new(0);

/// Enables the EDR driver component to monitor the registry for changes.
pub fn enable_registry_monitoring(driver_object: &mut DRIVER_OBJECT) -> Result<(), i32> {
    // We probably want the altitude string to be high, we would like this at the very very top of the
    // IO stack to prevent a rootkit 'hiding' the entry from the remaining minifilters. We may also
    // be well placed as we are ELAM?
    let altitude_string = "360000000000000000000";
    let mut altitude_unicode = UNICODE_STRING::default();
    let altitude_string: Vec<u16> = altitude_string.encode_utf16().collect();
    let mut registration_cookie: LARGE_INTEGER = LARGE_INTEGER::default();

    unsafe {
        RtlInitUnicodeString(&mut altitude_unicode, altitude_string.as_ptr());
    }
    let results = unsafe {
        CmRegisterCallbackEx(
            Some(handle_registry_event),
            &altitude_unicode,
            driver_object as *mut _ as *mut _,
            null_mut(),
            &mut registration_cookie,
            null_mut(),
        )
    };

    if !nt_success(results) {
        println!("[sanctum] [-] Failed to set up callback for monitoring registry.");
        return Err(results);
    }

    unsafe {
        REGISTRY_COOKIE.store(registration_cookie.QuadPart, Ordering::SeqCst);
    }

    println!("[sanctum] [+] Registry callback registered.");
    Ok(())
}

/// Unregisters the registry filter from the executive.
///
/// This function should be called on driver unload, or any time you wish to turn off the filtering capability.
///
/// # Safety
///
/// This function should only be called once and does not check for validity of the filter. Calling this twice, without
/// it being started in-between may result in UB.
pub unsafe fn unregister_registry_monitor() {
    let cookie_val = REGISTRY_COOKIE.swap(0, Ordering::SeqCst);
    if cookie_val == 0 {
        return;
    }

    let cookie = LARGE_INTEGER {
        QuadPart: cookie_val,
    };
    let res = unsafe { CmUnRegisterCallback(cookie) };
    if !nt_success(res) {
        println!("[sanctum] [-] Error unregistering registry callback. {res}");
    }
}

/// Callback function for filtering on registry events
unsafe extern "C" fn handle_registry_event(
    _context: *mut c_void,
    arg1: *mut c_void,
    arg2: *mut c_void,
) -> i32 {
    let operation = arg1 as REG_NOTIFY_CLASS;
    match operation {
        RegNtPreDeleteKey => {
            if let Ok(status) = monitor_etw_delete_key(arg2) {
                return status;
            }
        }
        RegNtPreSetValueKey => {
            if let Ok(status) = monitor_driver_service_set_value(arg2) {
                return status;
            }
        }
        _ => (),
    }

    // Return STATUS_SUCCESS so that the executive knows to pass the operation to the next
    // filter in the stack. I.e. the registry operation is permitted by our EDR.
    STATUS_SUCCESS
}

/// HIPS: Monitors registry writes to \Services\ to intercept and block unauthorized kernel driver installations.
fn monitor_driver_service_set_value(object: *mut c_void) -> Result<NTSTATUS, ()> {
    if object.is_null() {
        return Ok(STATUS_SUCCESS);
    }

    let cookie_val = REGISTRY_COOKIE.load(Ordering::SeqCst);
    if cookie_val == 0 {
        return Ok(STATUS_SUCCESS);
    }
    let mut cookie = LARGE_INTEGER {
        QuadPart: cookie_val,
    };

    let set_info = unsafe { *(object as *const REG_SET_VALUE_KEY_INFORMATION) };
    if set_info.Object.is_null() || set_info.ValueName.is_null() {
        return Ok(STATUS_SUCCESS);
    }

    let mut p_registry_path: *const UNICODE_STRING = null_mut();
    let result = unsafe {
        CmCallbackGetKeyObjectIDEx(
            &mut cookie,
            set_info.Object,
            null_mut(),
            &mut p_registry_path,
            0,
        )
    };

    if !nt_success(result) || p_registry_path.is_null() {
        return Ok(STATUS_SUCCESS);
    }

    let registry_path = unsafe { *p_registry_path };
    let name_len = registry_path.Length as usize / 2;
    let name_slice = unsafe { core::slice::from_raw_parts(registry_path.Buffer, name_len) };
    let key_name = String::from_utf16_lossy(name_slice);
    unsafe { CmCallbackReleaseKeyObjectIDEx(p_registry_path) };

    let key_name_lower = key_name.to_lowercase();
    if !key_name_lower.contains(r"\services\") {
        return Ok(STATUS_SUCCESS);
    }

    // Check value name being set
    let val_name_unicode = unsafe { *set_info.ValueName };
    let val_len = val_name_unicode.Length as usize / 2;
    if val_len == 0 || val_name_unicode.Buffer.is_null() {
        return Ok(STATUS_SUCCESS);
    }
    let val_slice = unsafe { core::slice::from_raw_parts(val_name_unicode.Buffer, val_len) };
    let val_name = String::from_utf16_lossy(val_slice);
    let val_name_lower = val_name.to_lowercase();

    let mut is_driver_install = false;
    if val_name_lower == "imagepath" {
        if !set_info.Data.is_null() && set_info.DataSize >= 2 {
            let data_u16_len = (set_info.DataSize as usize) / 2;
            let data_slice = unsafe { core::slice::from_raw_parts(set_info.Data as *const u16, data_u16_len) };
            let data_str = String::from_utf16_lossy(data_slice).to_lowercase();
            if data_str.contains(".sys") {
                is_driver_install = true;
            }
        }
    } else if val_name_lower == "type" {
        if !set_info.Data.is_null() && set_info.DataSize == 4 {
            let type_val = unsafe { *(set_info.Data as *const u32) };
            // SERVICE_KERNEL_DRIVER = 1, SERVICE_FILE_SYSTEM_DRIVER = 2
            if type_val == 1 || type_val == 2 {
                is_driver_install = true;
            }
        }
    }

    if is_driver_install {
        let caller = get_process_name().to_lowercase();
        let is_whitelisted = caller == "services.exe"
            || caller == "trustedinstaller.exe"
            || caller == "drvinst.exe"
            || caller == "msiexec.exe"
            || caller == "tiworker.exe"
            || caller == "setup.exe"
            || caller == "poqexec.exe"
            || caller == "wusa.exe";

        if !is_whitelisted {
            let alert_msg = format!(
                "[sanctum] [HIPS] Blocked unauthorized driver installation: Process '{}' tried to set '{}' on key '{}'",
                caller, val_name, key_name
            );
            println!("{alert_msg}");
            Log::new().log_to_userland(alert_msg);
            return Ok(STATUS_ACCESS_DENIED);
        }
    }

    Ok(STATUS_SUCCESS)
}

/// Determines whether a registry event is occurring on a protected ETW related key.
///
/// # Returns
/// - True: In the event the registry operation is being carried out on an ETW key
/// - False: If otherwise
fn is_modifying_etw_keys(key_path: String) -> bool {
    if key_path.contains(r"SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\") {
        return true;
    }

    false
}

fn monitor_etw_delete_key(object: *mut c_void) -> Result<NTSTATUS, ()> {
    if object.is_null() {
        println!("[sanctum] [-] Arg2 in registry_check_delete_key was null.");
        return Err(());
    }

    let cookie_val = REGISTRY_COOKIE.load(Ordering::SeqCst);
    if cookie_val == 0 {
        return Err(());
    }
    let mut cookie = LARGE_INTEGER {
        QuadPart: cookie_val,
    };

    let delete_info = unsafe { *(object as *const REG_DELETE_KEY_INFORMATION) };

    let mut p_registry_path: *const UNICODE_STRING = null_mut();

    // Get the required information from the Object
    let result = unsafe {
        CmCallbackGetKeyObjectIDEx(
            &mut cookie,
            delete_info.Object,
            null_mut(),
            &mut p_registry_path,
            0,
        )
    };

    if !nt_success(result) || p_registry_path.is_null() {
        println!(
            "[sanctum] [-] Could not get object ID from callback object. Result: {:08X}",
            result as u32
        );
        return Err(());
    }

    let registry_path = unsafe { *p_registry_path };

    let name_len = registry_path.Length as usize / 2;
    let name_slice = unsafe { core::slice::from_raw_parts(registry_path.Buffer, name_len) };
    let name = String::from_utf16_lossy(name_slice);

    // Free the resource as the kernel allocated this string
    unsafe { CmCallbackReleaseKeyObjectIDEx(p_registry_path) };

    // println!("Key name: {}", name);

    // Disallow edits to keys related to ETW as we want them in tact for the EDR & security.
    if is_modifying_etw_keys(name) {
        return Ok(STATUS_ACCESS_DENIED);
    }

    Ok(STATUS_SUCCESS)
}
