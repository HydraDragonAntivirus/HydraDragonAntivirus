use std::process::Command;
use std::ffi::CString;
use std::thread;
use std::time::Duration;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

const CRITICAL_DRIVERS: &[&str] = &[
    "sanctum",
    "hyperhv",
    "SimplePYASProtection",
    "RedDbg",
    "OwlyshieldRansomFilter",
];

#[link(name = "FltLib")]
unsafe extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: windows::core::PCWSTR,
        dwOptions: u32,
        lpContext: *const std::ffi::c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const std::ffi::c_void,
        hPort: *mut windows::Win32::Foundation::HANDLE,
    ) -> windows::core::HRESULT;
}

enum ProbeType {
    FileSystemDevice,
    FilterPort,
}

/// Device paths that must exist before bootstrap_protected_driver_control runs.
const EXPECTED_DEVICES: &[(&str, &str, ProbeType)] = &[
    ("SimplePYASProtection", r"\\.\HydraDragonProtection", ProbeType::FileSystemDevice),
    ("OwlyshieldRansomFilter", r"\RWFilter", ProbeType::FilterPort),
];

const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const DEVICE_POLL_MAX_ATTEMPTS: u32 = 20; // 10 seconds total

pub fn start_security_drivers() {
    for driver in CRITICAL_DRIVERS {
        println!("Attempting to start critical driver/service: {}", driver);
        let output = Command::new("sc")
            .arg("start")
            .arg(driver)
            .output();

        match output {
            Ok(out) => {
                let status = String::from_utf8_lossy(&out.stdout);
                let err = String::from_utf8_lossy(&out.stderr);
                if out.status.success() {
                    println!("Successfully started {}:\n{}", driver, status.trim());
                } else {
                    println!("sc start returned error for {}:\n{}\n{}", driver, status.trim(), err.trim());
                }
            }
            Err(e) => {
                println!("Failed to execute sc start for {}: {}", driver, e);
            }
        }
    }
}

fn probe_device(device_path: &str) -> bool {
    let Ok(cstr) = CString::new(device_path) else {
        return false;
    };

    let result = unsafe {
        CreateFileA(
            PCSTR(cstr.as_ptr() as *const u8),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    match result {
        Ok(handle) => {
            let _ = unsafe { CloseHandle(handle) };
            true
        }
        Err(_) => false,
    }
}

fn probe_filter_port(port_name: &str) -> bool {
    let mut handle = windows::Win32::Foundation::HANDLE::default();
    let port_wide: Vec<u16> = port_name.encode_utf16().chain(std::iter::once(0)).collect();
    let hr = unsafe {
        FilterConnectCommunicationPort(
            windows::core::PCWSTR(port_wide.as_ptr()),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut handle,
        )
    };

    if hr.is_ok() && !handle.is_invalid() {
        let _ = unsafe { CloseHandle(handle) };
        true
    } else {
        false
    }
}

/// Wait for DEMAND_START driver device objects to appear.
/// sc start is asynchronous — the device symlinks may not exist immediately.
pub fn wait_for_driver_devices() {
    for (driver_name, path, probe_type) in EXPECTED_DEVICES {
        let mut found = false;
        for attempt in 1..=DEVICE_POLL_MAX_ATTEMPTS {
            let ready = match probe_type {
                ProbeType::FileSystemDevice => probe_device(path),
                ProbeType::FilterPort => probe_filter_port(path),
            };

            if ready {
                println!("{} interface ready: {} (attempt {})", driver_name, path, attempt);
                found = true;
                break;
            }
            thread::sleep(DEVICE_POLL_INTERVAL);
        }

        if !found {
            println!(
                "{} interface NOT available after {}s: {} (driver may have failed to start)",
                driver_name,
                (DEVICE_POLL_MAX_ATTEMPTS as u64 * DEVICE_POLL_INTERVAL.as_millis() as u64) / 1000,
                path
            );
        }
    }
}
