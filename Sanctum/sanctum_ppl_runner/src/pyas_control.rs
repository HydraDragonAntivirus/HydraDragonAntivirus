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

pub const HYDRADRAGON_FILE_PROTECTION_RULES: &str = r####"
# =============================================================================
# HydraDragon Antivirus - File Protection Rules
# =============================================================================
#
# REQUIRED FORMAT: every rule must start with one of:
#   C:\          drive-letter path  (any drive letter A-Z is valid)
#   \??\         NT device namespace path
#   \            relative/suffix path - use only when the absolute path cannot
#                be known statically (e.g. per-user AppData paths).
#                Rules using the \ prefix are matched as substrings of the
#                full normalised file path, so they work across all user accounts.
#                Bare names without a leading separator are rejected.
#
# Matching is case-insensitive substring search: a rule fires if the full
# kernel file path CONTAINS the rule string.  Full drive-letter paths give
# the tightest match and should be preferred wherever possible.
#
# One rule per line.  Blank lines and # / // comments are ignored.
# =============================================================================

# ---------------------------------------------------------------------------
# HydraDragon Antivirus install directory (entire tree)
# ---------------------------------------------------------------------------
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc

# ---------------------------------------------------------------------------
# Sanctum in-box DLL
# ---------------------------------------------------------------------------
c:\windows\system32\sanctum.dll

# ---------------------------------------------------------------------------
# Sanctum install directory
# ---------------------------------------------------------------------------
c:\program files\hydradragonantivirus\hydradragon\sanctum

# ---------------------------------------------------------------------------
# Scheduled task entry
# ---------------------------------------------------------------------------
c:\windows\system32\tasks\hydradragonantivirus

# ---------------------------------------------------------------------------
# Kernel-mode driver binaries
# ---------------------------------------------------------------------------
c:\windows\system32\drivers\owlyshieldransomfilter.sys
c:\windows\system32\drivers\RedDbgDrv.sys
c:\windows\system32\drivers\hyperhv.sys
c:\windows\system32\drivers\simplepyasprotection.sys
c:\windows\system32\drivers\mbrfilter.sys
c:\windows\system32\drivers\fs_minifilter.sys
c:\windows\system32\drivers\sanctum.sys
c:\windows\system32\drivers\edrdrv.sys

# ---------------------------------------------------------------------------
# OpenEDR Injection DLLs (Moved to System32)
# ---------------------------------------------------------------------------
c:\windows\system32\edrpm64.dll
c:\windows\system32\edrpm32.dll
c:\windows\system32\edrmm.dll
"####;

pub const HYDRADRAGON_PROCESS_PROTECTION_RULES: &str = r####"
# =============================================================================
# HydraDragon Antivirus - Process Protection Rules
# =============================================================================
#
# REQUIRED FORMAT: every rule must start with one of:
#   C:\          drive-letter path  (most common; any drive letter A-Z is valid)
#   \??\         NT device namespace path
#   \            relative/suffix path - use only when the absolute path is
#                unknown at rule-authoring time (e.g. user-profile executables).
#                Bare filenames without any leading separator are rejected.
#
# Matching is case-insensitive substring search: a rule matches if the full
# image path of the process CONTAINS the rule string.  Full drive-letter paths
# are therefore the most precise and least error-prone choice.
#
# One rule per line.  Blank lines and # / // comments are ignored.
# =============================================================================

# ---------------------------------------------------------------------------
# Windows Shell - protect explorer.exe against termination / injection
# ---------------------------------------------------------------------------
# c:\windows\explorer.exe

# ---------------------------------------------------------------------------
# Sanctum agent executables (installed under Program Files)
# ---------------------------------------------------------------------------
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc
c:\windows\system32\drivers\sanctum.sys
c:\windows\system32\drivers\edrdrv.sys
c:\windows\system32\drivers\OwlyshieldRansomFilter.sys
c:\windows\system32\drivers\RedDbgDrv.sys
c:\windows\system32\drivers\hyperhv.sys

"####;

pub const HYDRADRAGON_REGISTRY_PROTECTION_RULES: &str = r####"
# =============================================================================
# HydraDragon Antivirus - Registry Protection Rules
# =============================================================================
#
# REQUIRED FORMAT: every rule must start with a recognised registry hive.
# Rules that do not match one of the accepted formats are silently rejected
# and a DbgPrint warning is emitted to the kernel debugger.
#
# Accepted prefixes (case-insensitive):
#   HKLM\       -> \REGISTRY\MACHINE\...
#   HKCU\       -> \REGISTRY\USER\...   (NOTE: HKCU is per-SID in the kernel;
#                  the rule will match any user's copy of the key because the
#                  matching engine uses a substring search under \REGISTRY\USER\)
#   HKU\        -> \REGISTRY\USER\...
#   HKCR\       -> \REGISTRY\MACHINE\SOFTWARE\CLASSES\...
#   HKCC\       -> \REGISTRY\MACHINE\SYSTEM\CURRENTCONTROLSET\HARDWARE PROFILES\CURRENT\...
#   \REGISTRY\  -> raw NT kernel path (used verbatim, no conversion)
#
# One rule per line.  Blank lines and lines starting with # or // are ignored.
# Inline comments are also supported:  HKLM\Some\Key  # this is a comment
# =============================================================================

# ---------------------------------------------------------------------------
# OwlyShield antivirus service keys
# ---------------------------------------------------------------------------
HKLM\SOFTWARE\OwlyShield
HKLM\SYSTEM\CurrentControlSet\Services\owlyshield_ransom
HKLM\SYSTEM\CurrentControlSet\Services\SimplePYASProtection
HKLM\SYSTEM\CurrentControlSet\Services\RedDbg
HKLM\SYSTEM\CurrentControlSet\Services\HyperDbg
HKLM\SYSTEM\CurrentControlSet\Services\hyperhv

# ---------------------------------------------------------------------------
# Sanctum / PPL runner service keys
# ---------------------------------------------------------------------------
HKLM\SYSTEM\CurrentControlSet\Services\sanctum_ppl_runner

# ---------------------------------------------------------------------------
# MBRFilter driver service key
# ---------------------------------------------------------------------------
HKLM\SYSTEM\CurrentControlSet\Services\MBRFilter

# ---------------------------------------------------------------------------
# Sanctum fs_minifilter driver service key
# ---------------------------------------------------------------------------
HKLM\SYSTEM\CurrentControlSet\Services\fs_minifilter
HKLM\SYSTEM\CurrentControlSet\Services\sanctum
HKLM\SYSTEM\CurrentControlSet\Services\edrdrv

# ---------------------------------------------------------------------------
# Winlogon Shell value - tampering here enables persistence via shell hijack.
# The driver enforces that the Shell value may only be set to explorer.exe.
# ---------------------------------------------------------------------------
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
"####;

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
