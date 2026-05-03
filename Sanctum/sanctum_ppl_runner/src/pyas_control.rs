use std::ffi::CString;

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        Storage::FileSystem::{
            CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
};
use crate::hardcoded_rules::{
    HYDRADRAGON_FILE_PROTECTION_RULES,
    HYDRADRAGON_PROCESS_PROTECTION_RULES,
    HYDRADRAGON_REGISTRY_PROTECTION_RULES,
};


const HYDRADRAGON_RULE_DEVICE: &str = r"\\.\HydraDragonProtection";
const HYDRADRAGON_RULE_BLOB_MAGIC: u32 = 0x4859_4452; // 'HYDR'
const HYDRADRAGON_RULE_BLOB_VERSION: u32 = 1;
const HYDRADRAGON_RULES_FLAG_UTF16LE: u32 = 0x0000_0001;
const MAX_RULE_BLOB_SECTION_SIZE: usize = 256 * 1024;

// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
const IOCTL_HYDRADRAGON_SET_RULES: u32 = 0x22A004;

fn append_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn append_utf16le_text(out: &mut Vec<u8>, text: &str) {
    for word in text.encode_utf16() {
        out.extend_from_slice(&word.to_le_bytes());
    }
}

fn section_len(name: &str, text: &str) -> Result<u32, String> {
    let bytes = text.encode_utf16().count() * 2;
    if bytes > MAX_RULE_BLOB_SECTION_SIZE {
        return Err(format!(
            "{} embedded rules section is too large: {} bytes > {} bytes",
            name, bytes, MAX_RULE_BLOB_SECTION_SIZE
        ));
    }
    u32::try_from(bytes).map_err(|_| format!("{} embedded rule section length overflow", name))
}

pub fn build_hydradragon_embedded_rule_blob() -> Result<Vec<u8>, String> {
    let process_bytes = section_len("Process", HYDRADRAGON_PROCESS_PROTECTION_RULES)?;
    let file_bytes = section_len("File", HYDRADRAGON_FILE_PROTECTION_RULES)?;
    let registry_bytes = section_len("Registry", HYDRADRAGON_REGISTRY_PROTECTION_RULES)?;

    let capacity = 24 + process_bytes as usize + file_bytes as usize + registry_bytes as usize;
    let mut payload = Vec::with_capacity(capacity);
    append_u32_le(&mut payload, HYDRADRAGON_RULE_BLOB_MAGIC);
    append_u32_le(&mut payload, HYDRADRAGON_RULE_BLOB_VERSION);
    append_u32_le(&mut payload, HYDRADRAGON_RULES_FLAG_UTF16LE);
    append_u32_le(&mut payload, process_bytes);
    append_u32_le(&mut payload, file_bytes);
    append_u32_le(&mut payload, registry_bytes);
    append_utf16le_text(&mut payload, HYDRADRAGON_PROCESS_PROTECTION_RULES);
    append_utf16le_text(&mut payload, HYDRADRAGON_FILE_PROTECTION_RULES);
    append_utf16le_text(&mut payload, HYDRADRAGON_REGISTRY_PROTECTION_RULES);
    Ok(payload)
}

/// Pushes hardcoded Process/File/Registry protection rules to SimplePYASProtection.
///
/// The kernel accepts this IOCTL only from the Sanctum runner when it is running
/// as Antimalware ProtectedLight and its full image path matches the hardcoded
/// Sanctum path.
pub fn refresh_hydradragon_protection_rules_from_embedded() -> Result<(), String> {
    let payload = build_hydradragon_embedded_rule_blob()?;

    unsafe {
        let device_name = CString::new(HYDRADRAGON_RULE_DEVICE)
            .map_err(|e| format!("invalid HydraDragon rule device name: {}", e))?;
        let pcstr = PCSTR(device_name.as_ptr() as *const u8);

        let device = CreateFileA(
            pcstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| {
            format!(
                "failed to open HydraDragon rule device {}: {:?}, GetLastError={:?}",
                HYDRADRAGON_RULE_DEVICE,
                e,
                GetLastError()
            )
        })?;

        if device.is_invalid() {
            return Err(format!(
                "CreateFileA returned invalid HydraDragon rule device handle, GetLastError={:?}",
                GetLastError()
            ));
        }

        let mut bytes_returned = 0u32;
        let ioctl_result = DeviceIoControl(
            device,
            IOCTL_HYDRADRAGON_SET_RULES,
            Some(payload.as_ptr().cast()),
            payload.len() as u32,
            None,
            0,
            Some(&mut bytes_returned as *mut u32),
            None,
        );

        let err = GetLastError();
        let _ = CloseHandle(device);

        ioctl_result.map_err(|e| {
            format!(
                "DeviceIoControl(IOCTL_HYDRADRAGON_SET_RULES) failed: {:?}, GetLastError={:?}",
                e, err
            )
        })?;
    }

    Ok(())
}
