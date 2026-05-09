#![allow(dead_code)]
//! Sanctum-only OpenEDR driver control helper.
//!
//! This file belongs in the Sanctum PPL runner, not in Owlyshield. The driver
//! side is hardened so these calls succeed only when the caller is exactly:
//!
//!   C:\Program Files\HydraDragonAntivirus\hydradragon\Owlyshield\Sanctum\AppData\sanctum_ppl_runner.exe
//!
//! and Windows reports the caller as Antimalware ProtectedLight.
//!
//! IMPORTANT: OpenEDR rule/config IOCTLs expect OpenEDR's existing serialized
//! LBVS payloads. This helper does not invent a new rule format and does not
//! remove rule functionality. It provides Sanctum-owned forwarding functions for
//! the same config/rule/process-info IOCTLs already handled by ioctl.cpp.

use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

/// User-mode DOS device path for CMD_ERDDRV_IOCTLDEVICE_WIN32_NAME.
/// Matches the symlink GUID from edrdrvapi.hpp.
pub const OPENEDR_IOCTL_DEVICE: &str = r"\\.\{157980D8-09B4-4580-B8B6-D32971D056DA}";

/// IOCTL codes computed from edrdrvapi.hpp:
///   CMD_ERDDRV_CTL_CODE(code, read, write) =
///     CTL_CODE(0x8001, 0x800 + code, METHOD_BUFFERED, access)
///   where access = (read ? FILE_READ_ACCESS : 0) | (write ? FILE_WRITE_ACCESS : 0)
pub const CMD_ERDDRV_IOCTL_START: u32 = 0x80012004;               // code=0x01, access=0
pub const CMD_ERDDRV_IOCTL_STOP: u32 = 0x80012008;                // code=0x02, access=0
pub const CMD_ERDDRV_IOCTL_SET_CONFIG: u32 = 0x80016010;           // code=0x04, access=FILE_READ
pub const CMD_ERDDRV_IOCTL_UPDATE_PROCESS_RULES: u32 = 0x80016014; // code=0x05, access=FILE_READ
pub const CMD_ERDDRV_IOCTL_SET_PROCESS_INFO: u32 = 0x80016018;     // code=0x06, access=FILE_READ
pub const CMD_ERDDRV_IOCTL_UPDATE_FILE_RULES: u32 = 0x8001601C;    // code=0x07, access=FILE_READ
pub const CMD_ERDDRV_IOCTL_UPDATE_REG_RULES: u32 = 0x80016020;     // code=0x08, access=FILE_READ

#[derive(Debug, Clone, Copy)]
pub enum OpenEdrRuleKind {
    File,
    Registry,
    Process,
}

fn open_openedr_device(device_path: &str) -> Result<HANDLE, String> {
    let device_name = CString::new(device_path)
        .map_err(|e| format!("invalid OpenEDR device path '{}': {}", device_path, e))?;

    let handle = unsafe {
        CreateFileA(
            PCSTR(device_name.as_ptr() as *const u8),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| format!("CreateFileA({}) failed: {:?}", device_path, e))?;

    if handle.is_invalid() {
        return Err(format!(
            "CreateFileA({}) returned invalid handle; GetLastError={:?}",
            device_path,
            unsafe { GetLastError() }
        ));
    }

    Ok(handle)
}

fn validate_ioctl_code(name: &str, ioctl_code: u32) -> Result<(), String> {
    if ioctl_code == 0 {
        return Err(format!(
            "{} IOCTL code is 0; wire CMD_ERDDRV_IOCTL_* from shared defs first",
            name
        ));
    }
    Ok(())
}

pub fn send_openedr_ioctl_with_input(
    device_path: &str,
    ioctl_name: &str,
    ioctl_code: u32,
    input: Option<&[u8]>,
) -> Result<(), String> {
    validate_ioctl_code(ioctl_name, ioctl_code)?;

    let handle = open_openedr_device(device_path)?;
    let mut bytes_returned = 0u32;

    let (input_ptr, input_len) = match input {
        Some(data) if !data.is_empty() => (Some(data.as_ptr().cast()), data.len() as u32),
        _ => (None, 0),
    };

    let ioctl_result = unsafe {
        DeviceIoControl(
            handle,
            ioctl_code,
            input_ptr,
            input_len,
            None,
            0,
            Some(&mut bytes_returned as *mut u32),
            None,
        )
    };

    let last = unsafe { GetLastError() };
    let _ = unsafe { CloseHandle(handle) };

    ioctl_result.map_err(|e| {
        format!(
            "DeviceIoControl({}, 0x{:08X}) failed: {:?}; GetLastError={:?}",
            ioctl_name, ioctl_code, e, last
        )
    })?;

    Ok(())
}

pub fn send_openedr_ioctl(device_path: &str, ioctl_name: &str, ioctl_code: u32) -> Result<(), String> {
    send_openedr_ioctl_with_input(device_path, ioctl_name, ioctl_code, None)
}

pub fn activate_openedr_monitoring() -> Result<(), String> {
    send_openedr_ioctl(
        OPENEDR_IOCTL_DEVICE,
        "CMD_ERDDRV_IOCTL_START",
        CMD_ERDDRV_IOCTL_START,
    )
}

pub fn deactivate_openedr_monitoring() -> Result<(), String> {
    send_openedr_ioctl(
        OPENEDR_IOCTL_DEVICE,
        "CMD_ERDDRV_IOCTL_STOP",
        CMD_ERDDRV_IOCTL_STOP,
    )
}

/// Send OpenEDR's existing serialized main-config payload.
pub fn update_openedr_config(serialized_config_blob: &[u8]) -> Result<(), String> {
    send_openedr_ioctl_with_input(
        OPENEDR_IOCTL_DEVICE,
        "CMD_ERDDRV_IOCTL_SET_CONFIG",
        CMD_ERDDRV_IOCTL_SET_CONFIG,
        Some(serialized_config_blob),
    )
}

/// Send OpenEDR's existing serialized rule payload to the matching rule IOCTL.
/// The payload must be the same LBVS format expected by filemon::updateFileRules,
/// regmon::updateRegRules, or procmon::updateProcessRules.
pub fn update_openedr_rules(kind: OpenEdrRuleKind, serialized_rule_blob: &[u8]) -> Result<(), String> {
    let (name, code) = match kind {
        OpenEdrRuleKind::File => (
            "CMD_ERDDRV_IOCTL_UPDATE_FILE_RULES",
            CMD_ERDDRV_IOCTL_UPDATE_FILE_RULES,
        ),
        OpenEdrRuleKind::Registry => (
            "CMD_ERDDRV_IOCTL_UPDATE_REG_RULES",
            CMD_ERDDRV_IOCTL_UPDATE_REG_RULES,
        ),
        OpenEdrRuleKind::Process => (
            "CMD_ERDDRV_IOCTL_UPDATE_PROCESS_RULES",
            CMD_ERDDRV_IOCTL_UPDATE_PROCESS_RULES,
        ),
    };

    send_openedr_ioctl_with_input(
        OPENEDR_IOCTL_DEVICE,
        name,
        code,
        Some(serialized_rule_blob),
    )
}

pub fn update_openedr_file_rules(serialized_rule_blob: &[u8]) -> Result<(), String> {
    update_openedr_rules(OpenEdrRuleKind::File, serialized_rule_blob)
}

pub fn update_openedr_registry_rules(serialized_rule_blob: &[u8]) -> Result<(), String> {
    update_openedr_rules(OpenEdrRuleKind::Registry, serialized_rule_blob)
}

pub fn update_openedr_process_rules(serialized_rule_blob: &[u8]) -> Result<(), String> {
    update_openedr_rules(OpenEdrRuleKind::Process, serialized_rule_blob)
}

/// Send OpenEDR's existing serialized SetProcessInfo payload.
pub fn set_openedr_process_info(serialized_process_info_blob: &[u8]) -> Result<(), String> {
    send_openedr_ioctl_with_input(
        OPENEDR_IOCTL_DEVICE,
        "CMD_ERDDRV_IOCTL_SET_PROCESS_INFO",
        CMD_ERDDRV_IOCTL_SET_PROCESS_INFO,
        Some(serialized_process_info_blob),
    )
}
