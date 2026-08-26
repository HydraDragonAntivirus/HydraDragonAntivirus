//! MBRFilter kernel driver integration.
//!
//! The MBRFilter driver (Talos/Cisco) blocks writes to the Master Boot Record
//! of any physical disk and raises alerts on the `mbr_filter_alerts` named
//! pipe. This module:
//!  * stages the driver binary next to `System32\drivers`,
//!  * registers and starts the `MBRFilter` kernel driver service,
//!  * adds the driver as an upper filter for the disk class,
//!  * listens on the alert pipe: system-disk writes are logged, while
//!    USB/external-disk writes terminate the offending process and forward
//!    an alert into the in-process OpenEDR telemetry channel.

use std::ffi::CString;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{BOOL, CloseHandle, ERROR_PIPE_CONNECTED, GetLastError};
use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::core::PCSTR;

use crate::Logging;
use crate::utils::validate_pipe_client;

const MBR_ALERT_PIPE: &str = r"\\.\pipe\Global\mbr_filter_alerts";
const PIPE_READ_BUFFER_SIZE: u32 = 262144;
const DRIVER_SERVICE_NAME: &str = "MBRFilter";
const DISK_CLASS_FILTERS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}";

/// Stage + register + start the MBRFilter kernel driver. Best effort: any
/// failure is logged and never treated as fatal, so the EDR still runs even
/// when the driver cannot be loaded (e.g. Secure Boot / unsigned driver).
pub fn ensure_mbrfilter_driver() {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let driver_dest = format!("{}\\System32\\drivers\\MBRFilter.sys", system_root);

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.to_path_buf()));
    let staged_src = exe_dir
        .as_ref()
        .map(|dir| dir.join("MBRFilter.sys"))
        .filter(|path| path.is_file());

    if let Some(src) = staged_src {
        let dest_exists = std::path::Path::new(&driver_dest).is_file();
        let needs_copy = !dest_exists; // Sadece hedefte dosya HİÇ YOKSA kopyala. Boyut farkına bakma, çünkü zaten kurulu ve kilitli olabilir.
        if needs_copy {
            match std::fs::read(&src).and_then(|data| std::fs::write(&driver_dest, data)) {
                Ok(_) => Logging::info(&format!("[MBR] Staged MBRFilter.sys to {}", driver_dest)),
                Err(err) => Logging::error(&format!(
                    "[MBR] Failed to copy MBRFilter.sys to {}: {}",
                    driver_dest, err
                )),
            }
        }
    } else {
        Logging::warning(
            "[MBR] MBRFilter.sys not found next to the executable; driver service registration skipped",
        );
    }

    if !std::path::Path::new(&driver_dest).is_file() {
        Logging::warning(&format!(
            "[MBR] Driver binary not present at {}; skipping service registration",
            driver_dest
        ));
        return;
    }

    // If anything is registered for the first time, the filter only attaches at
    // the next boot, so the user must reboot to activate it.
    let changed = set_disk_class_upper_filter();
    let changed = register_and_start_driver_service(&driver_dest) || changed;
    if changed {
        Logging::info(
            "[MBR] MBRFilter registered for the first time; restart required to activate",
        );
    }
}

/// Append `MBRFilter` to the disk-class `UpperFilters` multi-string so the PnP
/// manager attaches the driver to all disk devices at next device start.
/// Returns true if the registry value was modified (i.e. a restart is needed).
fn set_disk_class_upper_filter() -> bool {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};

    let result = (|| -> Result<bool, Box<dyn std::error::Error>> {
        let class_key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(DISK_CLASS_FILTERS_KEY, KEY_READ | KEY_WRITE)?;
        let mut filters: Vec<String> = class_key.get_value("UpperFilters").unwrap_or_default();
        if filters
            .iter()
            .any(|f| f.eq_ignore_ascii_case(DRIVER_SERVICE_NAME))
        {
            return Ok(false);
        }
        filters.push(DRIVER_SERVICE_NAME.to_string());
        class_key.set_value("UpperFilters", &filters)?;
        Ok(true)
    })();

    match result {
        Ok(changed) => {
            if changed {
                Logging::info("[MBR] Added MBRFilter to disk class UpperFilters");
            }
            changed
        }
        Err(err) => {
            Logging::warning(&format!(
                "[MBR] Could not update disk class UpperFilters ({}); INF-based install may be required",
                err
            ));
            false
        }
    }
}

/// Create (if missing) and start the `MBRFilter` kernel driver service.
/// Returns true if the service was created (i.e. a restart is needed).
fn register_and_start_driver_service(driver_path: &str) -> bool {
    use windows::Win32::System::Services::{
        CloseServiceHandle, CreateServiceW, OpenSCManagerW, OpenServiceW, SC_MANAGER_ALL_ACCESS,
        SERVICE_ALL_ACCESS, SERVICE_BOOT_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
        StartServiceW,
    };
    use windows::core::PCWSTR;

    let wname = wide(DRIVER_SERVICE_NAME);
    let wdisplay = wide("MBRFilter Driver");
    let wbinary = wide(driver_path);
    let wload_order_group = wide("PnP Filter");

    unsafe {
        let scm = match OpenSCManagerW(
            PCWSTR(std::ptr::null()),
            PCWSTR(std::ptr::null()),
            SC_MANAGER_ALL_ACCESS,
        ) {
            Ok(handle) => handle,
            Err(err) => {
                Logging::error(&format!("[MBR] OpenSCManagerW failed: {:?}", err));
                return false;
            }
        };

        let (svc, created) = match OpenServiceW(scm, PCWSTR(wname.as_ptr()), SERVICE_ALL_ACCESS) {
            Ok(handle) => (handle, false),
            Err(_) => {
                match CreateServiceW(
                    scm,
                    PCWSTR(wname.as_ptr()),
                    PCWSTR(wdisplay.as_ptr()),
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_BOOT_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(wbinary.as_ptr()),
                    Some(&PCWSTR(wload_order_group.as_ptr())),
                    None,
                    None,
                    None,
                    None,
                ) {
                    Ok(handle) => (handle, true),
                    Err(err) => {
                        Logging::error(&format!("[MBR] CreateServiceW failed: {:?}", err));
                        let _ = CloseServiceHandle(scm);
                        return false;
                    }
                }
            }
        };

        if StartServiceW(svc, None).as_bool() {
            Logging::info("[MBR] MBRFilter driver service started");
        } else {
            let raw = GetLastError().0;
            if raw == 1056 {
                // ERROR_SERVICE_ALREADY_RUNNING
                Logging::info("[MBR] MBRFilter driver service already running");
            } else {
                Logging::warning(&format!(
                    "[MBR] StartServiceW failed (code {}) (driver may load on next boot)",
                    raw
                ));
            }
        }

        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        created
    }
}

/// Spawn the MBR alert pipe listener. Alerts are UTF-16LE messages of the form
/// `DISK:<number>|<process_path>`. System disk (PhysicalDrive0) writes are
/// always blocked by the driver and just logged; USB/external disk writes are
/// additionally forwarded to the behavior engine, which prompts the firewall
/// GUI.
pub fn spawn_mbr_alert_listener() -> thread::JoinHandle<()> {
    thread::spawn(move || unsafe {
        let pipe_name_c = match CString::new(MBR_ALERT_PIPE) {
            Ok(name) => name,
            Err(err) => {
                Logging::error(&format!("[MBR] Invalid pipe name: {}", err));
                return;
            }
        };

        Logging::info(&format!("[MBR] Listener started on {}", MBR_ALERT_PIPE));
        loop {
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_READ_BUFFER_SIZE,
                PIPE_READ_BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(handle) => handle,
                Err(err) => {
                    Logging::error(&format!("[MBR] CreateNamedPipeA failed: {:?}", err));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                Logging::error(&format!(
                    "[MBR] CreateNamedPipeA returned invalid handle: {:?}",
                    GetLastError()
                ));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let connect_err = GetLastError();
            if connect_ok.as_bool() || connect_err == ERROR_PIPE_CONNECTED {
                // Only the kernel (PID 4) may connect; anything else is dropped.
                if !validate_pipe_client(pipe_handle, None, true) {
                    Logging::error("[MBR] Rejected unauthorized client connection");
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
                Logging::info("[MBR] Authorized client (Kernel) connected");

                let mut buffer = vec![0u8; PIPE_READ_BUFFER_SIZE as usize];
                let mut bytes_read = 0u32;
                let read_ok = ReadFile(
                    pipe_handle,
                    Some(buffer.as_mut_ptr().cast()),
                    PIPE_READ_BUFFER_SIZE,
                    Some(&mut bytes_read as *mut u32),
                    None,
                );

                if read_ok.as_bool() && bytes_read > 0 {
                    let raw = decode_utf16le_message(&buffer[..bytes_read as usize]);

                    // Parse enriched format: "DISK:<number>|<process_path>"
                    let (disk_number, process_path) = if raw.starts_with("DISK:") {
                        if let Some(pipe_pos) = raw.find('|') {
                            let disk_str = &raw[5..pipe_pos];
                            let path = &raw[pipe_pos + 1..];
                            let disk_num: i32 = disk_str.parse().unwrap_or(-1);
                            (disk_num, normalize_nt_path(path))
                        } else {
                            (-1, normalize_nt_path(&raw))
                        }
                    } else {
                        // Legacy format: just the process path
                        (0, normalize_nt_path(&raw))
                    };

                    if disk_number == 0 {
                        // System disk MBR write — always blocked, just log.
                        Logging::error(&format!(
                            "[MBR ALERT] System disk (PhysicalDrive0) MBR write blocked — Offending process: {}",
                            process_path
                        ));
                    } else {
                        // Non-system disk (USB/external) MBR write — blocked by
                        // the kernel; kill the offender and alert OpenEDR.
                        handle_mbr_threat(disk_number, &process_path);
                    }
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    })
}

fn wide(value: &str) -> Vec<u16> {
    let mut out: Vec<u16> = value.encode_utf16().collect();
    out.push(0);
    out
}

fn decode_utf16le_message(data: &[u8]) -> String {
    let usable_len = data.len() - (data.len() % 2);
    let mut words = Vec::with_capacity(usable_len / 2);
    for chunk in data[..usable_len].chunks_exact(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&words)
        .trim_end_matches('\0')
        .to_string()
}

fn normalize_nt_path(nt_path: &str) -> String {
    if nt_path.trim().is_empty() {
        return nt_path.to_string();
    }

    let mut normalized = nt_path.trim().replace('/', "\\");

    if normalized.starts_with("\\??\\") {
        normalized = normalized.trim_start_matches("\\??\\").to_string();
    } else if normalized.starts_with("\\\\?\\") {
        normalized = normalized.trim_start_matches("\\\\?\\").to_string();
    } else if normalized
        .to_ascii_lowercase()
        .starts_with("\\device\\harddiskvolume")
    {
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if let Some(rest) = normalized.splitn(4, '\\').nth(3) {
            normalized = format!("{}\\{}", system_drive, rest);
        }
    }

    normalized.trim_end_matches('\0').to_string()
}

/// Respond to a blocked MBR write on a removable/external disk.
///
/// The kernel driver has already blocked the write. Defense-in-depth: a
/// process probing the MBR of a USB disk is hostile, so every matching
/// process is terminated and a `MBR_USB_WRITE_BLOCKED` alert is forwarded
/// into the in-process OpenEDR telemetry channel for the standard
/// detection/report pipeline.
fn handle_mbr_threat(disk_number: i32, process_path: &str) {
    Logging::error(&format!(
        "[MBR ALERT] USB/external disk {} MBR write blocked — Offending process: {}",
        disk_number, process_path
    ));

    let target = process_path.trim_matches('"').trim().to_ascii_lowercase();
    if target.is_empty() || target == "unknown" || target == "system" {
        return;
    }

    // Pause protection: log the alert but do not terminate anyone.
    if crate::globals::is_protection_paused() {
        Logging::warning("[MBR ALERT] Protection is paused - offending process NOT terminated");
        return;
    }

    for pid in find_pids_by_image_path(&target) {
        match terminate_process(pid) {
            Ok(()) => Logging::warning(&format!(
                "[MBR ALERT] Terminated MBR-offending process {} (PID {})",
                process_path, pid
            )),
            Err(err) => Logging::warning(&format!(
                "[MBR ALERT] Failed to terminate PID {}: {}",
                pid, err
            )),
        }
    }

    let alert = serde_json::json!({
        "type": "MBR_USB_WRITE_BLOCKED",
        "disk_number": disk_number,
        "process_path": process_path,
        "timestamp_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    });
    if crate::ffi::send_telemetry_line(crate::ffi::TelemetryLine::OpenedrEvent(alert.to_string())) {
        Logging::info("[MBR ALERT] Alert forwarded to OpenEDR telemetry channel");
    } else {
        Logging::debug("[MBR ALERT] OpenEDR telemetry channel unavailable; alert logged only");
    }
}

/// Enumerate running processes whose full image path matches `image_path_lc`
/// (already lowercased). Matching is suffix-based so `\Device\HarddiskVolumeX`
/// vs drive-letter path differences still resolve.
fn find_pids_by_image_path(image_path_lc: &str) -> Vec<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    let mut pids = Vec::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let Ok(snapshot) = snapshot else {
        return pids;
    };

    unsafe {
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).as_bool() {
            loop {
                let pid = entry.th32ProcessID;
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    if !handle.is_invalid() {
                        let mut buffer = vec![0u16; 1024];
                        let mut size = buffer.len() as u32;
                        if QueryFullProcessImageNameW(
                            handle,
                            PROCESS_NAME_WIN32,
                            windows::core::PWSTR(buffer.as_mut_ptr()),
                            &mut size,
                        )
                        .as_bool()
                        {
                            let path = String::from_utf16_lossy(&buffer[..size as usize])
                                .to_ascii_lowercase();
                            if path.ends_with(image_path_lc) || image_path_lc.ends_with(&path) {
                                pids.push(pid);
                            }
                        }
                        let _ = CloseHandle(handle);
                    }
                }

                if !Process32NextW(snapshot, &mut entry).as_bool() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    pids
}

fn terminate_process(pid: u32) -> Result<(), String> {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
        .map_err(|e| format!("OpenProcess failed: {e}"))?;
        if handle.is_invalid() {
            return Err("OpenProcess returned an invalid handle".to_string());
        }
        let ok = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        if ok.as_bool() {
            Ok(())
        } else {
            Err(format!("TerminateProcess failed: {:?}", GetLastError()))
        }
    }
}
