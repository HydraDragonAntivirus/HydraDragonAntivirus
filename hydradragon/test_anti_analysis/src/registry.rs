//! Registry checking module
//!
//! Provides functions to check registry keys and values using the Windows API.

use crate::{CheckResult, Result, SignatureMonsterError};
use windows::Win32::System::Registry::*;
use windows::core::PCWSTR;
use std::ptr::null_mut;

/// Registry checker
pub struct RegistryChecker {
    _private: (),
}

impl RegistryChecker {
    /// Create a new registry checker
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Parse a registry path into root key and subkey
    fn parse_path(path: &str) -> Result<(HKEY, String)> {
        let parts: Vec<&str> = path.splitn(2, '\\').collect();
        if parts.len() < 2 {
            return Err(SignatureMonsterError::RegistryError(
                "Invalid registry path format".to_string(),
            ));
        }

        let root = match parts[0].to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKU" | "HKEY_USERS" => HKEY_USERS,
            "HKCC" | "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
            _ => {
                return Err(SignatureMonsterError::RegistryError(format!(
                    "Unknown registry root: {}",
                    parts[0]
                )))
            }
        };

        Ok((root, parts[1].to_string()))
    }

    /// Convert a string to wide string (null-terminated)
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Check if a registry key exists
    pub fn key_exists(&self, path: &str) -> bool {
        match Self::parse_path(path) {
            Ok((root, subkey)) => {
                let wide_subkey = Self::to_wide(&subkey);
                let mut hkey = HKEY::default();
                
                let result = unsafe {
                    RegOpenKeyExW(
                        root,
                        PCWSTR(wide_subkey.as_ptr()),
                        Some(0),
                        KEY_READ,
                        &mut hkey,
                    )
                };

                if result.is_ok() {
                    unsafe { let _ = RegCloseKey(hkey); }
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Check if a registry value exists
    pub fn value_exists(&self, path: &str, value_name: &str) -> bool {
        match self.read_value(path, value_name) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Read a registry value as a string
    pub fn read_value(&self, path: &str, value_name: &str) -> Result<String> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);
        let wide_value_name = Self::to_wide(value_name);
        
        let mut hkey = HKEY::default();
        
        unsafe {
            let status = RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            );
            if status.is_err() { return Err(SignatureMonsterError::RegistryError("Failed to open key".into())); }
        }

        // Get the size first
        let mut data_type: REG_VALUE_TYPE = REG_VALUE_TYPE::default();
        let mut data_size: u32 = 0;
        
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(wide_value_name.as_ptr()),
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_size),
            )
        };

        if result.is_err() {
            unsafe { let _ = RegCloseKey(hkey); }
            return Err(SignatureMonsterError::RegistryError(
                "Value not found".to_string(),
            ));
        }

        // Read the data
        let mut buffer: Vec<u8> = vec![0u8; data_size as usize];
        
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(wide_value_name.as_ptr()),
                None,
                Some(&mut data_type),
                Some(buffer.as_mut_ptr()),
                Some(&mut data_size),
            )
        };

        unsafe { let _ = RegCloseKey(hkey); }

        if result.is_err() {
            return Err(SignatureMonsterError::RegistryError(
                "Failed to read value".to_string(),
            ));
        }

        // Convert based on type
        match data_type {
            REG_SZ | REG_EXPAND_SZ => {
                // Wide string
                let wide: Vec<u16> = buffer
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&wide);
                Ok(s.trim_end_matches('\0').to_string())
            }
            REG_DWORD => {
                if buffer.len() >= 4 {
                    let value = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                    Ok(value.to_string())
                } else {
                    Err(SignatureMonsterError::RegistryError(
                        "Invalid DWORD data".to_string(),
                    ))
                }
            }
            REG_QWORD => {
                if buffer.len() >= 8 {
                    let value = u64::from_le_bytes([
                        buffer[0], buffer[1], buffer[2], buffer[3],
                        buffer[4], buffer[5], buffer[6], buffer[7],
                    ]);
                    Ok(value.to_string())
                } else {
                    Err(SignatureMonsterError::RegistryError(
                        "Invalid QWORD data".to_string(),
                    ))
                }
            }
            REG_BINARY => {
                // Return as hex string
                Ok(buffer.iter().map(|b| format!("{:02X}", b)).collect())
            }
            REG_MULTI_SZ => {
                // Multiple null-terminated wide strings
                let wide: Vec<u16> = buffer
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&wide);
                Ok(s.trim_end_matches('\0').replace('\0', "|"))
            }
            _ => Err(SignatureMonsterError::RegistryError(format!(
                "Unsupported registry type: {:?}",
                data_type
            ))),
        }
    }

    /// Read a DWORD value
    pub fn read_dword(&self, path: &str, value_name: &str) -> Result<u32> {
        let value = self.read_value(path, value_name)?;
        value.parse().map_err(|e| {
            SignatureMonsterError::ParseError(format!("Failed to parse DWORD: {}", e))
        })
    }

    /// Check if a value matches an expected value
    pub fn value_matches(&self, path: &str, value_name: &str, expected: &str) -> CheckResult {
        match self.read_value(path, value_name) {
            Ok(actual) => {
                if actual.to_lowercase() == expected.to_lowercase() {
                    CheckResult::matched(actual)
                } else {
                    CheckResult::not_matched().with_details(format!("Actual: {}", actual))
                }
            }
            Err(_) => CheckResult::not_matched(),
        }
    }

    /// Check if a value contains a substring
    pub fn value_contains(&self, path: &str, value_name: &str, substring: &str) -> CheckResult {
        match self.read_value(path, value_name) {
            Ok(actual) => {
                if actual.to_lowercase().contains(&substring.to_lowercase()) {
                    CheckResult::matched(actual)
                } else {
                    CheckResult::not_matched()
                }
            }
            Err(_) => CheckResult::not_matched(),
        }
    }

    /// Enumerate all value names under a key
    pub fn enumerate_values(&self, path: &str) -> Result<Vec<String>> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);
        
        let mut hkey = HKEY::default();
        
        unsafe {
            let status = RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            );
            if status.is_err() { return Err(SignatureMonsterError::RegistryError("Failed to open key".into())); }
        }

        let mut values = Vec::new();
        let mut index = 0u32;
        let mut name_buffer = [0u16; 16384];
        let mut name_size = name_buffer.len() as u32;

        loop {
            name_size = name_buffer.len() as u32;
            
            let result = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    Some(windows::core::PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_size,
                    None,
                    None,
                    None,
                    None,
                )
            };

            if result.is_err() {
                break;
            }

            let name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
            values.push(name);
            index += 1;
        }

        unsafe { let _ = RegCloseKey(hkey); }
        Ok(values)
    }

    /// Enumerate all subkeys under a key
    pub fn enumerate_subkeys(&self, path: &str) -> Result<Vec<String>> {
        let (root, subkey) = Self::parse_path(path)?;
        let wide_subkey = Self::to_wide(&subkey);
        
        let mut hkey = HKEY::default();
        
        unsafe {
            let status = RegOpenKeyExW(
                root,
                PCWSTR(wide_subkey.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            );
            if status.is_err() { return Err(SignatureMonsterError::RegistryError("Failed to open key".into())); }
        }

        let mut subkeys = Vec::new();
        let mut index = 0u32;
        let mut name_buffer = [0u16; 256];

        loop {
            let mut name_size = name_buffer.len() as u32;
            
            let result = unsafe {
                RegEnumKeyExW(
                    hkey,
                    index,
                    Some(windows::core::PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_size,
                    None,
                    Some(windows::core::PWSTR(null_mut())),
                    None,
                    None,
                )
            };

            if result.is_err() {
                break;
            }

            let name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
            subkeys.push(name);
            index += 1;
        }

        unsafe { let _ = RegCloseKey(hkey); }
        Ok(subkeys)
    }
}

impl Default for RegistryChecker {
    fn default() -> Self {
        Self::new()
    }
}
