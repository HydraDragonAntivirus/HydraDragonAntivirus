#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SE_REGISTRY_KEY, SetNamedSecurityInfoW};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
};

pub fn takeown_file(path: &Path) -> Result<String, String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_READONLY.0 as u32) != 0 {
        unsafe {
            let _ = SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_READONLY);
        }
    }

    unsafe {
        let rc = SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
        );
        if rc != WIN32_ERROR(0) {
            return Err(format!(
                "takeown failed for {}: error {rc:?}",
                path.display()
            ));
        }
    }

    Ok(format!("Took ownership of {}", path.display()))
}

pub fn takeown_registry_key(hive_label: &str, subkey: &str) -> Result<String, String> {
    let full_path = format!("{}\\{}", hive_label, subkey);
    let wide: Vec<u16> = full_path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let rc = SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
        );
        if rc != WIN32_ERROR(0) {
            return Err(format!("takeown failed for {full_path}: error {rc:?}"));
        }
    }

    Ok(format!("Took ownership of {full_path}"))
}
