use crate::logging::Logging;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, RPC_E_TOO_LATE};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, VARIANT, VT_BSTR,
};
use windows::Win32::System::Ole::VariantClear;
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
};
use windows::core::{BSTR, Error as WindowsError, PCWSTR, w};

const MAX_SHADOW_COPIES_TO_TRY: usize = 24;

#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowCopyRestoreSummary {
    pub requested: usize,
    pub attempted: usize,
    pub restored: usize,
    pub skipped: usize,
    pub failed: usize,
}

#[derive(Debug)]
struct ComApartment {
    should_uninitialize: bool,
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.should_uninitialize {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

#[derive(Debug)]
struct ShadowCopyInfo {
    device_object: String,
    install_date: String,
}

pub fn restore_files(paths: &[PathBuf]) -> ShadowCopyRestoreSummary {
    let mut summary = ShadowCopyRestoreSummary {
        requested: paths.len(),
        ..ShadowCopyRestoreSummary::default()
    };

    let targets = unique_targets(paths);
    if targets.is_empty() {
        return summary;
    }

    let shadow_devices = match query_shadow_device_objects() {
        Ok(devices) if !devices.is_empty() => devices,
        Ok(_) => {
            summary.skipped = targets.len();
            Logging::warning(
                "[ShadowCopy] No VSS shadow copies are available; file restore fallback skipped",
            );
            return summary;
        }
        Err(error) => {
            summary.failed = targets.len();
            Logging::warning(&format!(
                "[ShadowCopy] Unable to enumerate VSS shadow copies; file restore fallback skipped: {}",
                error
            ));
            return summary;
        }
    };

    let shadow_devices = shadow_devices
        .into_iter()
        .take(MAX_SHADOW_COPIES_TO_TRY)
        .collect::<Vec<_>>();

    for target in targets {
        summary.attempted += 1;
        match restore_one_file(&target, &shadow_devices) {
            Ok(Some(source)) => {
                summary.restored += 1;
                Logging::alert(&format!(
                    "[ShadowCopy] Restored {} from {}",
                    target.display(),
                    source.display()
                ));
            }
            Ok(None) => {
                summary.skipped += 1;
                Logging::debug(&format!(
                    "[ShadowCopy] No shadow-copy version found for {}",
                    target.display()
                ));
            }
            Err(error) => {
                summary.failed += 1;
                Logging::warning(&format!(
                    "[ShadowCopy] Failed to restore {}: {}",
                    target.display(),
                    error
                ));
            }
        }
    }

    if summary.restored > 0 {
        Logging::alert(&format!(
            "[ShadowCopy] Restored {} file(s) from VSS after malware file activity",
            summary.restored
        ));
    } else if summary.attempted > 0 {
        Logging::warning(&format!(
            "[ShadowCopy] Shadow-copy restore attempted for {} file(s), but no files were restored",
            summary.attempted
        ));
    }

    summary
}

fn unique_targets(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for path in paths {
        let Some(normalized) = normalize_drive_path(path) else {
            continue;
        };
        let key = normalized
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        if seen.insert(key) {
            targets.push(normalized);
        }
    }

    targets
}

fn query_shadow_device_objects() -> io::Result<Vec<String>> {
    match query_shadow_device_objects_native() {
        Ok(devices) if !devices.is_empty() => Ok(devices),
        Ok(_) => query_shadow_device_objects_powershell().or_else(|powershell_error| {
            query_shadow_device_objects_wmic().map_err(|wmic_error| {
                io::Error::other(format!(
                    "native WMI returned no shadow copies; PowerShell query failed: {}; WMIC query failed: {}",
                    powershell_error, wmic_error
                ))
            })
        }),
        Err(native_error) => match query_shadow_device_objects_powershell() {
            Ok(devices) => Ok(devices),
            Err(powershell_error) => match query_shadow_device_objects_wmic() {
                Ok(devices) => Ok(devices),
                Err(wmic_error) => Err(io::Error::other(format!(
                    "native WMI query failed: {}; PowerShell query failed: {}; WMIC query failed: {}",
                    native_error, powershell_error, wmic_error
                ))),
            },
        },
    }
}

fn query_shadow_device_objects_native() -> io::Result<Vec<String>> {
    let _com = initialize_wmi_com()?;
    initialize_wmi_security()?;

    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| windows_error("CoCreateInstance(WbemLocator)", error))?;

    let namespace = BSTR::from("ROOT\\CIMV2");
    let empty = BSTR::new();
    let services =
        unsafe { locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None) }
            .map_err(|error| windows_error("IWbemLocator::ConnectServer(ROOT\\CIMV2)", error))?;

    unsafe {
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }
    .map_err(|error| windows_error("CoSetProxyBlanket(IWbemServices)", error))?;

    let query_language = BSTR::from("WQL");
    let query = BSTR::from("SELECT DeviceObject, InstallDate FROM Win32_ShadowCopy");
    let enumerator = unsafe {
        services.ExecQuery(
            &query_language,
            &query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }
    .map_err(|error| windows_error("IWbemServices::ExecQuery(Win32_ShadowCopy)", error))?;

    collect_shadow_copy_devices(&enumerator)
}

fn initialize_wmi_com() -> io::Result<ComApartment> {
    match unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) } {
        Ok(_) => Ok(ComApartment {
            should_uninitialize: true,
        }),
        Err(error) if error.code() == RPC_E_CHANGED_MODE => Ok(ComApartment {
            should_uninitialize: false,
        }),
        Err(error) => Err(windows_error("CoInitializeEx", error)),
    }
}

fn initialize_wmi_security() -> io::Result<()> {
    match unsafe {
        CoInitializeSecurity(
            PSECURITY_DESCRIPTOR::default(),
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    } {
        Ok(_) => Ok(()),
        Err(error) if error.code() == RPC_E_TOO_LATE => Ok(()),
        Err(error) => Err(windows_error("CoInitializeSecurity", error)),
    }
}

fn collect_shadow_copy_devices(enumerator: &IEnumWbemClassObject) -> io::Result<Vec<String>> {
    let mut infos = Vec::new();

    loop {
        let mut returned = 0_u32;
        let mut objects = [None];
        unsafe {
            enumerator
                .Next(WBEM_INFINITE, &mut objects, &mut returned)
                .ok()
        }
        .map_err(|error| windows_error("IEnumWbemClassObject::Next", error))?;

        if returned == 0 {
            break;
        }

        if let Some(object) = objects[0].as_ref()
            && let Some(device_object) = get_wmi_bstr_property(object, w!("DeviceObject"))?
        {
            infos.push(ShadowCopyInfo {
                device_object,
                install_date: get_wmi_bstr_property(object, w!("InstallDate"))?.unwrap_or_default(),
            });
        }
    }

    infos.sort_by(|left, right| right.install_date.cmp(&left.install_date));

    let mut seen = HashSet::new();
    let mut devices = Vec::new();
    for info in infos {
        let device = info.device_object.trim().trim_end_matches('\\');
        if !device.contains(r"GLOBALROOT\Device\HarddiskVolumeShadowCopy") {
            continue;
        }

        let key = device.to_ascii_lowercase();
        if seen.insert(key) {
            devices.push(device.to_string());
        }
    }

    Ok(devices)
}

fn get_wmi_bstr_property(
    object: &IWbemClassObject,
    property_name: PCWSTR,
) -> io::Result<Option<String>> {
    let mut variant = VARIANT::default();

    unsafe {
        object
            .Get(property_name, 0, &mut variant, None, None)
            .map_err(|error| windows_error("IWbemClassObject::Get", error))?;
    }

    let value = variant_bstr_to_string(&variant);
    let _ = unsafe { VariantClear(&mut variant) };
    Ok(value)
}

fn variant_bstr_to_string(variant: &VARIANT) -> Option<String> {
    let vt = unsafe { variant.Anonymous.Anonymous.vt };
    if vt != VT_BSTR {
        return None;
    }

    let bstr =
        unsafe { ManuallyDrop::into_inner(variant.Anonymous.Anonymous.Anonymous.bstrVal.clone()) };
    Some(bstr.to_string())
}

fn windows_error(context: &str, error: WindowsError) -> io::Error {
    io::Error::other(format!(
        "{} failed with HRESULT 0x{:08X}: {}",
        context,
        error.code().0 as u32,
        error
    ))
}

fn query_shadow_device_objects_powershell() -> io::Result<Vec<String>> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | ForEach-Object { $_.DeviceObject }",
        ])
        .output()?;

    if !output.status.success() {
        return Err(command_error(
            "PowerShell VSS query",
            output.status.code(),
            &output.stderr,
        ));
    }

    Ok(parse_shadow_device_lines(&output.stdout))
}

fn query_shadow_device_objects_wmic() -> io::Result<Vec<String>> {
    let output = Command::new("wmic")
        .args(["shadowcopy", "get", "DeviceObject", "/value"])
        .output()?;

    if !output.status.success() {
        return Err(command_error(
            "WMIC VSS query",
            output.status.code(),
            &output.stderr,
        ));
    }

    Ok(parse_shadow_device_lines(&output.stdout))
}

fn command_error(command_name: &str, code: Option<i32>, stderr: &[u8]) -> io::Error {
    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        format!("exit code {:?}", code)
    } else {
        format!("exit code {:?}: {}", code, stderr)
    };
    io::Error::other(format!("{command_name} failed with {detail}"))
}

fn parse_shadow_device_lines(stdout: &[u8]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut devices = Vec::new();
    let text = String::from_utf8_lossy(stdout);

    for line in text.lines() {
        let raw = line
            .trim()
            .strip_prefix("DeviceObject=")
            .unwrap_or_else(|| line.trim())
            .trim()
            .trim_matches('"')
            .trim_end_matches('\\');

        if !raw.contains(r"GLOBALROOT\Device\HarddiskVolumeShadowCopy") {
            continue;
        }

        let key = raw.to_ascii_lowercase();
        if seen.insert(key) {
            devices.push(raw.to_string());
        }
    }

    devices
}

fn restore_one_file(target: &Path, shadow_devices: &[String]) -> io::Result<Option<PathBuf>> {
    let mut last_metadata_error = None;

    for device in shadow_devices {
        let Some(source) = shadow_source_path(device, target) else {
            continue;
        };

        match fs::metadata(&source) {
            Ok(metadata) if metadata.is_file() => {
                copy_shadow_file(&source, target)?;
                return Ok(Some(source));
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => last_metadata_error = Some(error),
        }
    }

    if let Some(error) = last_metadata_error {
        Err(error)
    } else {
        Ok(None)
    }
}

fn copy_shadow_file(source: &Path, target: &Path) -> io::Result<()> {
    if let Some(parent) = target.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    if let Ok(metadata) = fs::metadata(target) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(target, permissions);
        }
    }

    fs::copy(source, target)?;
    Ok(())
}

fn shadow_source_path(device: &str, target: &Path) -> Option<PathBuf> {
    let target = normalize_drive_path(target)?;
    let target_text = target.to_string_lossy().replace('/', "\\");
    let rest = target_text.get(2..)?;
    if !rest.starts_with('\\') {
        return None;
    }

    Some(PathBuf::from(format!(
        "{}{}",
        device.trim_end_matches('\\'),
        rest
    )))
}

fn normalize_drive_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = path
        .to_string_lossy()
        .trim_matches(char::from(0))
        .trim()
        .replace('/', "\\");

    for prefix in ["\\\\?\\", "\\??\\"] {
        if let Some(stripped) = normalized.strip_prefix(prefix) {
            normalized = stripped.to_string();
        }
    }

    if is_drive_absolute_path(&normalized) {
        Some(PathBuf::from(normalized))
    } else {
        None
    }
}

fn is_drive_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_shadow_copy_source_for_drive_path() {
        let source = shadow_source_path(
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12",
            Path::new(r"C:\Users\dev\file.txt"),
        )
        .unwrap();

        assert_eq!(
            source.to_string_lossy(),
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\dev\file.txt"
        );
    }

    #[test]
    fn normalizes_extended_drive_prefix() {
        let source = shadow_source_path(
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12",
            Path::new(r"\\?\C:\Users\dev\file.txt"),
        )
        .unwrap();

        assert_eq!(
            source.to_string_lossy(),
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\dev\file.txt"
        );
    }
}
