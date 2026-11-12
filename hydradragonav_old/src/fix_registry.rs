#![cfg(windows)]

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::Security::Authorization::{SE_REGISTRY_KEY, SetNamedSecurityInfoW};
use windows::Win32::Security::DACL_SECURITY_INFORMATION;
use winreg::enums::*;
use winreg::RegKey;

pub fn revert_value(
    hive_label: &str,
    subkey: &str,
    value_name: &str,
    expected_reverted: &str,
) -> Result<String, String> {
    let root = match hive_label.to_uppercase().as_str() {
        "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
        _ => return Err(format!("Unknown hive: {hive_label}")),
    };

    let key = root
        .open_subkey_with_flags(subkey, KEY_SET_VALUE | KEY_WRITE)
        .map_err(|e| format!("Cannot open {hive_label}\\{subkey}: {e}"))?;

    if let Some(val) = parse_dword(expected_reverted) {
        key.set_value(value_name, &val)
            .map_err(|e| format!("Cannot write DWORD {value_name}: {e}"))?;
    } else {
        key.set_value(value_name, &expected_reverted.to_string())
            .map_err(|e| format!("Cannot write string {value_name}: {e}"))?;
    }

    Ok(format!(
        "Reverted {hive_label}\\{subkey}\\{value_name} -> {expected_reverted}"
    ))
}

pub fn restore_acl(hive_label: &str, subkey: &str) -> Result<String, String> {
    let full_path = format!("{}\\{}", hive_label, subkey);
    let path_wide: Vec<u16> = full_path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let rc = SetNamedSecurityInfoW(
            windows::core::PCWSTR(path_wide.as_ptr()),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
        );
        if rc != WIN32_ERROR(0) {
            return Err(format!("SetNamedSecurityInfoW failed on {full_path}: {rc:?}"));
        }
    }
    Ok(format!("ACL restored on {full_path}"))
}

fn parse_dword(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}
