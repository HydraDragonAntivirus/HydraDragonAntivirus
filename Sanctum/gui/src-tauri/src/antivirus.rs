//! Antivirus.rs contains all functions associated with the antivirus UI in Tauri.
//! This module will handle state, requests, async, and events.

use serde_json::{to_value, Value};
use shared_std::file_scanner::{FileScannerState, ScanningLiveInfo};
use shared_std::settings::SanctumSettings;
use std::path::PathBuf;
use tauri::Emitter;

use crate::ipc::IpcClient;

#[tauri::command]
pub async fn scanner_check_page_state() -> Result<String, ()> {
    match IpcClient::send_ipc::<FileScannerState, Option<Value>>("scanner_check_page_state", None)
        .await
    {
        Ok(response) => Ok(format!("{:?}", response)),
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            Ok("Inactive".to_string()) // todo proper error handling
        }
    }
}

/// Reports the scan statistics back to the UI
#[tauri::command]
pub async fn scanner_get_scan_stats() -> Result<String, ()> {
    match IpcClient::send_ipc::<ScanningLiveInfo, Option<Value>>("scanner_get_scan_stats", None)
        .await
    {
        Ok(response) => {
            let response = serde_json::to_string(&response).unwrap();
            Ok(response)
        }
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            Ok("Inactive".to_string()) // todo proper error handling
        }
    }
}

#[tauri::command]
pub async fn scanner_stop_scan() -> Result<(), ()> {
    match IpcClient::send_ipc::<(), Option<Value>>("scanner_cancel_scan", None).await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[-] Error with IPC for stop scan: {e}");
        }
    };

    Ok(())
}

fn send_manual_scan_to_owlyshield(
    file_path: &str,
    scan_mode: &str,
    timeout_ms: u64,
    late_child_scan_grace_ms: u64,
) {
    let message = serde_json::json!({
        "file_path": file_path,
        "scan_mode": scan_mode,
        "scan_origin_path": file_path,
        "deep_scan_timeout_ms": timeout_ms,
        "late_child_scan_grace_ms": late_child_scan_grace_ms
    })
    .to_string();

    let pipe_name = r"\\.\pipe\Global\owlyshield_manual_scan";
    let mut options = std::fs::OpenOptions::new();
    options.write(true);

    if let Ok(mut file) = options.open(pipe_name) {
        use std::io::Write;
        let _ = file.write_all(message.as_bytes());
    }
}

fn scan_dir_recursively(
    dir: &std::path::Path,
    scan_mode: &str,
    timeout_ms: u64,
    late_child_scan_grace_ms: u64,
) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() {
                send_manual_scan_to_owlyshield(
                    &path.to_string_lossy(),
                    scan_mode,
                    timeout_ms,
                    late_child_scan_grace_ms,
                );
            } else if path.is_dir() {
                scan_dir_recursively(&path, scan_mode, timeout_ms, late_child_scan_grace_ms);
            }
        }
    }
}

#[tauri::command]
pub async fn scanner_start_folder_scan(
    file_path: String,
    scanMode: Option<String>,
    app_handle: tauri::AppHandle,
) -> Result<String, ()> {
    let mode = scanMode.unwrap_or_else(|| "minimal".to_string());
    let settings =
        IpcClient::send_ipc::<SanctumSettings, Option<Value>>("settings_load_page_state", None)
            .await
            .unwrap_or_default();
    let timeout_ms = if mode.eq_ignore_ascii_case("deep") {
        settings.deep_scan_timeout_ms
    } else {
        settings.minimal_scan_timeout_ms
    };
    let path_clone = file_path.clone();
    let mode_clone = mode.clone();

    // Spawn a thread to send the manual scan requests to Owlyshield
    std::thread::spawn(move || {
        let p = PathBuf::from(path_clone);
        if p.is_file() {
            send_manual_scan_to_owlyshield(
                &p.to_string_lossy(),
                &mode_clone,
                timeout_ms,
                settings.late_child_scan_grace_ms,
            );
        } else if p.is_dir() {
            scan_dir_recursively(
                &p,
                &mode_clone,
                timeout_ms,
                settings.late_child_scan_grace_ms,
            );
        }
    });

    let path = to_value(vec![PathBuf::from(file_path)]).unwrap();

    tokio::spawn(async move {
        // The result is wrapped inside of an enum from the filescanner module, so we need to first match on that
        // as DirectoryResult (since we are scanning a dir). The result should never be anything else for this scan
        // so if it is something has gone wrong with the internal wiring.

        match IpcClient::send_ipc::<FileScannerState, _>("scanner_start_folder_scan", Some(path))
            .await
        {
            Ok(response) => match response {
                FileScannerState::Finished => {
                    let scan_result = IpcClient::send_ipc::<ScanningLiveInfo, Option<Value>>(
                        "scanner_get_scan_stats",
                        None,
                    )
                    .await
                    .unwrap();

                    if scan_result.scan_results.is_empty() {
                        app_handle
                            .emit("folder_scan_no_results", "No malicious files found.")
                            .unwrap();
                    } else {
                        app_handle
                            .emit("folder_scan_malware_found", &scan_result)
                            .unwrap();
                    }
                }
                FileScannerState::FinishedWithError(v) => {
                    app_handle.emit("folder_scan_error", &v).unwrap();
                }
                FileScannerState::Scanning => app_handle
                    .emit(
                        "folder_scan_error",
                        "A scan is already in progress.".to_string(),
                    )
                    .unwrap(),
                _ => (),
            },
            Err(e) => {
                eprintln!("[-] Error with IPC: {e}");
            }
        };
    });

    // // todo some kind of feedback like 1/1 file scanned; but then same for the mass scanner, be good to show x files scanned, and time taken so far. Then completed time and
    // // total files after.

    // todo this shouldn't show in every case..?
    Ok("Scan in progress...".to_string())
}

#[tauri::command]
pub async fn scanner_start_quick_scan(app_handle: tauri::AppHandle) -> Result<String, ()> {
    tokio::spawn(async move {
        let settings =
            IpcClient::send_ipc::<SanctumSettings, Option<Value>>("settings_load_page_state", None)
                .await
                .unwrap_or_default();
        let paths = IpcClient::send_ipc::<Vec<PathBuf>, Option<Value>>(
            "settings_get_common_scan_areas",
            None,
        )
        .await
        .unwrap();

        let paths_clone = paths.clone();
        std::thread::spawn(move || {
            for p in paths_clone {
                if p.is_file() {
                    send_manual_scan_to_owlyshield(
                        &p.to_string_lossy(),
                        "minimal",
                        settings.minimal_scan_timeout_ms,
                        settings.late_child_scan_grace_ms,
                    );
                } else if p.is_dir() {
                    scan_dir_recursively(
                        &p,
                        "minimal",
                        settings.minimal_scan_timeout_ms,
                        settings.late_child_scan_grace_ms,
                    );
                }
            }
        });

        // The result is wrapped inside of an enum from the filescanner module, so we need to first match on that
        // as DirectoryResult (since we are scanning a dir). The result should never be anything else for this scan
        // so if it is something has gone wrong with the internal wiring.
        match IpcClient::send_ipc::<FileScannerState, _>("scanner_start_folder_scan", Some(paths))
            .await
        {
            Ok(response) => match response {
                FileScannerState::Finished => {
                    let scan_result = IpcClient::send_ipc::<ScanningLiveInfo, Option<Value>>(
                        "scanner_get_scan_stats",
                        None,
                    )
                    .await
                    .unwrap();

                    if scan_result.scan_results.is_empty() {
                        app_handle
                            .emit("folder_scan_no_results", "No malicious files found.")
                            .unwrap();
                    } else {
                        app_handle
                            .emit("folder_scan_malware_found", &scan_result)
                            .unwrap();
                    }
                }
                FileScannerState::FinishedWithError(v) => {
                    app_handle.emit("folder_scan_error", &v).unwrap();
                }
                FileScannerState::Scanning => app_handle
                    .emit(
                        "folder_scan_error",
                        "A scan is already in progress.".to_string(),
                    )
                    .unwrap(),
                _ => (),
            },
            Err(e) => {
                eprintln!("[-] Error with IPC: {e}");
            }
        };
    });

    // // todo some kind of feedback like 1/1 file scanned; but then same for the mass scanner, be good to show x files scanned, and time taken so far. Then completed time and
    // // total files after.

    // todo this shouldn't show in every case..
    Ok("Scan in progress...".to_string())
}
