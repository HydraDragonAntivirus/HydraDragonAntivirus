//! Registry Protection module
//!
//! Provides functions to lock/protect registry keys by modifying DACLs.

use crate::{Result, SignatureMonsterError};
use std::ptr::null_mut;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, WIN32_ERROR};
use windows::Win32::Security::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::System::Registry::*;

pub struct RegistryProtection {
    _private: (),
}

impl RegistryProtection {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn win32_check(err: WIN32_ERROR, msg: &str) -> Result<()> {
        if err == WIN32_ERROR(0) {
            Ok(())
        } else {
            Err(SignatureMonsterError::RegistryError(format!(
                "{}: {:?}",
                msg, err
            )))
        }
    }

    fn parse_path(path: &str) -> Result<(HKEY, String)> {
        let parts: Vec<&str> = path.splitn(2, '\\').collect();
        if parts.len() < 2 {
            return Err(SignatureMonsterError::RegistryError(
                "Invalid registry path".into(),
            ));
        }

        let root = match parts[0].to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKU" | "HKEY_USERS" => HKEY_USERS,
            _ => {
                return Err(SignatureMonsterError::RegistryError(format!(
                    "Unknown root key: {}",
                    parts[0]
                )))
            }
        };

        Ok((root, parts[1].to_string()))
    }

    pub fn lock_key(&self, path: &str) -> Result<()> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);

        let mut hkey = HKEY::default();

        unsafe {
            Self::win32_check(
                RegOpenKeyExW(
                    root,
                    PCWSTR(wide_subkey.as_ptr()),
                    Some(0),
                    KEY_READ
                        | KEY_WRITE
                        | REG_SAM_FLAGS(0x00040000) // READ_CONTROL
                        | REG_SAM_FLAGS(0x00020000), // WRITE_DAC
                    &mut hkey,
                ),
                "RegOpenKeyExW failed",
            )?;
        }

        // --- Create Everyone SID ---
        let mut sid_size = 0u32;

        unsafe {
            let _ = CreateWellKnownSid(
                WinWorldSid,
                None,
                None,
                &mut sid_size,
            );
        }

        let mut sid_buffer = vec![0u8; sid_size as usize];
        let everyone_sid = PSID(sid_buffer.as_mut_ptr() as *mut _);

        unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                None,
                Some(everyone_sid),
                &mut sid_size,
            )
            .map_err(|e| {
                SignatureMonsterError::RegistryError(format!(
                    "CreateWellKnownSid failed: {:?}",
                    e
                ))
            })?;
        }

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: KEY_ALL_ACCESS.0,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: windows::core::PWSTR(everyone_sid.0 as *mut u16),
            },
        };

        let mut new_dacl: *mut ACL = null_mut();

        unsafe {
            Self::win32_check(
                SetEntriesInAclW(Some(&[ea]), None, &mut new_dacl),
                "SetEntriesInAclW failed",
            )?;

            Self::win32_check(
                SetSecurityInfo(
                    HANDLE(hkey.0 as *mut _),
                    SE_REGISTRY_KEY,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(new_dacl),
                    None,
                ),
                "SetSecurityInfo failed",
            )?;

            let _ = RegCloseKey(hkey);
        }

        Ok(())
    }

    pub fn unlock_key(&self, path: &str) -> Result<()> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);

        let mut hkey = HKEY::default();

        unsafe {
            Self::win32_check(
                RegOpenKeyExW(
                    root,
                    PCWSTR(wide_subkey.as_ptr()),
                    Some(0),
                    KEY_READ
                        | KEY_WRITE
                        | REG_SAM_FLAGS(0x00040000)
                        | REG_SAM_FLAGS(0x00020000),
                    &mut hkey,
                ),
                "RegOpenKeyExW failed",
            )?;

            let mut new_dacl: *mut ACL = null_mut();

            Self::win32_check(
                SetEntriesInAclW(None, None, &mut new_dacl),
                "SetEntriesInAclW failed",
            )?;

            Self::win32_check(
                SetSecurityInfo(
                    HANDLE(hkey.0 as *mut _),
                    SE_REGISTRY_KEY,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(new_dacl),
                    None,
                ),
                "SetSecurityInfo failed",
            )?;

            let _ = RegCloseKey(hkey);
        }

        Ok(())
    }

    pub fn is_key_protected(&self, path: &str) -> bool {
        let (root, subkey) = match Self::parse_path(path) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let wide_subkey = Self::to_wide(&subkey);
        let mut hkey = HKEY::default();

        let status = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                Some(0),
                KEY_WRITE,
                &mut hkey,
            )
        };

        if status == WIN32_ERROR(0) {
            unsafe { let _ = RegCloseKey(hkey); }
            false
        } else {
            true
        }
    }
}

impl Default for RegistryProtection {
    fn default() -> Self {
        Self::new()
    }
}
