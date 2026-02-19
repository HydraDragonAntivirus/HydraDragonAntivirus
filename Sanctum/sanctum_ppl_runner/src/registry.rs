use std::ptr::null_mut;

use windows::{
    core::{s, Error, PCWSTR, PWSTR}, Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPENED_EXISTING_KEY, REG_OPTION_NON_VOLATILE, REG_SZ
        }, UI::WindowsAndMessaging::{MessageBoxA, MB_ICONWARNING, MB_OK, MESSAGEBOX_STYLE},
    }
};

fn to_wstring(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}