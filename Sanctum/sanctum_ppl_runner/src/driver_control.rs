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

/// Device paths that must exist before bootstrap_protected_driver_control runs.
const EXPECTED_DEVICES: &[(&str, &str)] = &[
    ("SimplePYASProtection", r"\\.\HydraDragonProtection"),
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

/// Wait for DEMAND_START driver device objects to appear.
/// sc start is asynchronous — the device symlinks may not exist immediately.
pub fn wait_for_driver_devices() {
    for (driver_name, device_path) in EXPECTED_DEVICES {
        let mut found = false;
        for attempt in 1..=DEVICE_POLL_MAX_ATTEMPTS {
            if probe_device(device_path) {
                println!("{} device ready: {} (attempt {})", driver_name, device_path, attempt);
                found = true;
                break;
            }
            thread::sleep(DEVICE_POLL_INTERVAL);
        }

        if !found {
            println!(
                "{} device NOT available after {}s: {} (driver may have failed to start)",
                driver_name,
                (DEVICE_POLL_MAX_ATTEMPTS as u64 * DEVICE_POLL_INTERVAL.as_millis() as u64) / 1000,
                device_path
            );
        }
    }
}
