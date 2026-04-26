//! HydraDragon kernel protection-rule loader for SanctumPPLRunner.
//!
//! The kernel driver no longer reads rule files from disk during boot. This PPL
//! service reads the rules after service startup and sends one validated blob to
//! the driver through \\.\HydraDragonProtection.

use std::{ffi::CString, fs, path::{Path, PathBuf}};

use windows::{
    Win32::{
        Foundation::{BOOL, CloseHandle, GetLastError, HANDLE},
        Storage::FileSystem::{
            CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
            OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
    core::PCSTR,
};

const HYDRADRAGON_RULE_DEVICE: &str = r"\\.\HydraDragonProtection";
const HYDRADRAGON_RULES_BASE_DIR: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\HydraDragon_Protection_Rules\PYAS";

const HYDRADRAGON_RULE_BLOB_MAGIC: u32 = 0x4859_4452; // 'HYDR'
const HYDRADRAGON_RULE_BLOB_VERSION: u32 = 1;
const HYDRADRAGON_RULES_FLAG_UTF16LE: u32 = 0x0000_0001;
const MAX_RULE_BLOB_SECTION_SIZE: usize = 256 * 1024;

// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
const IOCTL_HYDRADRAGON_SET_RULES: u32 = 0x22A004;

fn read_rule_category(dir: &Path) -> Result<String, String> {
    if !dir.exists() {
        return Ok(String::new());
    }

    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("failed to read rule directory {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();

    files.sort();

    let mut combined = String::new();
    for path in files {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read rule file {}: {e}", path.display()))?;
        combined.push_str(&content);
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
    }

    Ok(combined)
}

fn append_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn append_utf16le_text(out: &mut Vec<u8>, text: &str) {
    for word in text.encode_utf16() {
        out.extend_from_slice(&word.to_le_bytes());
    }
}

fn checked_section_len(name: &str, bytes: usize) -> Result<u32, String> {
    if bytes > MAX_RULE_BLOB_SECTION_SIZE {
        return Err(format!(
            "{name} rules section is too large: {bytes} bytes > {MAX_RULE_BLOB_SECTION_SIZE} bytes"
        ));
    }

    u32::try_from(bytes).map_err(|_| format!("{name} rules section length overflow"))
}

/// Reads Process/File/Registry rule folders and sends one categorized rule blob to the driver.
///
/// The driver accepts this IOCTL only when the caller image path is exactly:
/// C:\Program Files\HydraDragonAntivirus\hydradragon\Owlyshield\Sanctum\AppData\sanctum_ppl_runner.exe
pub fn refresh_hydradragon_protection_rules() -> Result<(), String> {
    let base = Path::new(HYDRADRAGON_RULES_BASE_DIR);

    let process_rules = read_rule_category(&base.join("Process"))?;
    let file_rules = read_rule_category(&base.join("File"))?;
    let registry_rules = read_rule_category(&base.join("Registry"))?;

    let process_len = process_rules.encode_utf16().count() * 2;
    let file_len = file_rules.encode_utf16().count() * 2;
    let registry_len = registry_rules.encode_utf16().count() * 2;

    let process_bytes = checked_section_len("Process", process_len)?;
    let file_bytes = checked_section_len("File", file_len)?;
    let registry_bytes = checked_section_len("Registry", registry_len)?;

    let mut payload = Vec::with_capacity(24 + process_len + file_len + registry_len);
    append_u32_le(&mut payload, HYDRADRAGON_RULE_BLOB_MAGIC);
    append_u32_le(&mut payload, HYDRADRAGON_RULE_BLOB_VERSION);
    append_u32_le(&mut payload, HYDRADRAGON_RULES_FLAG_UTF16LE);
    append_u32_le(&mut payload, process_bytes);
    append_u32_le(&mut payload, file_bytes);
    append_u32_le(&mut payload, registry_bytes);
    append_utf16le_text(&mut payload, &process_rules);
    append_utf16le_text(&mut payload, &file_rules);
    append_utf16le_text(&mut payload, &registry_rules);

    unsafe {
        let device_name = CString::new(HYDRADRAGON_RULE_DEVICE)
            .map_err(|e| format!("invalid HydraDragon rule device name: {e}"))?;
        let pcstr = PCSTR(device_name.as_ptr() as *const u8);

        let device = CreateFileA(
            pcstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
        .map_err(|e| {
            format!(
                "failed to open HydraDragon rule device {HYDRADRAGON_RULE_DEVICE}: {e:?}, GetLastError={:?}",
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
        let ok: BOOL = DeviceIoControl(
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

        if !ok.as_bool() {
            return Err(format!(
                "DeviceIoControl(IOCTL_HYDRADRAGON_SET_RULES) failed: GetLastError={err:?}"
            ));
        }
    }

    Ok(())
}
