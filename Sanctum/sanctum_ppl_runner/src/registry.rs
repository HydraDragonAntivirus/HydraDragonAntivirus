use std::ptr::null_mut;

use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPENED_EXISTING_KEY,
            REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegSetValueExW,
        },
        UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MESSAGEBOX_STYLE, MessageBoxA},
    },
    core::{Error, PCWSTR, PWSTR, s},
};

fn to_wstring(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
