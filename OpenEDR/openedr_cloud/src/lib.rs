pub mod auth_timestamp;
pub mod authenticode;
pub mod cloud_client;
pub mod hosts;
pub mod memory;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn error_json(msg: &str) -> *mut c_char {
    let err = serde_json::json!({
        "error": true,
        "message": msg
    });
    to_c_string(err.to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_is_ready() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_is_ready() -> u32 {
    openedr_cloud_is_ready()
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_init(_base_rules_dir: *const c_char) -> i32 {
    // Cloud engine doesn't need heavy offline database initialization.
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_init(base_rules_dir: *const c_char) -> i32 {
    openedr_cloud_init(base_rules_dir)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_file(file_path: *const c_char) -> *mut c_char {
    if file_path.is_null() {
        return error_json("file_path pointer is null");
    }

    let path_str = match unsafe { CStr::from_ptr(file_path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return error_json("Invalid UTF-8 in file_path"),
    };

    let report = cloud_client::scan_file(Path::new(&path_str));
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_file(file_path: *const c_char) -> *mut c_char {
    openedr_cloud_scan_file(file_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_file_ecs(file_path: *const c_char) -> *mut c_char {
    openedr_cloud_scan_file(file_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_file_ecs(file_path: *const c_char) -> *mut c_char {
    openedr_cloud_scan_file_ecs(file_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_pid(pid: u32, max_mb: u64) -> *mut c_char {
    let report = memory::scan_pid_memory(pid, max_mb);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_pid(pid: u32, max_mb: u64) -> *mut c_char {
    openedr_cloud_scan_pid(pid, max_mb)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_bytes(
    data: *const u8,
    len: usize,
    file_name: *const c_char,
) -> *mut c_char {
    if data.is_null() || len == 0 {
        return error_json("data buffer is null or empty");
    }

    let name = if !file_name.is_null() {
        unsafe { CStr::from_ptr(file_name) }.to_str().unwrap_or("sample.bin").to_string()
    } else {
        "sample.bin".to_string()
    };

    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let (verdict, detections, sha256) = cloud_client::scan_bytes(slice, &name);

    let report = serde_json::json!({
        "file_path": name,
        "verdict": verdict,
        "detections": detections,
        "sha256": sha256,
        "file_size": len,
        "scanned_at": "now",
    });

    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_bytes(
    data: *const u8,
    len: usize,
    file_name: *const c_char,
) -> *mut c_char {
    openedr_cloud_scan_bytes(data, len, file_name)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_url(url: *const c_char) -> *mut c_char {
    if url.is_null() {
        return error_json("url pointer is null");
    }

    let url_str = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s,
        Err(_) => return error_json("Invalid UTF-8 in url"),
    };

    let report = cloud_client::scan_url(url_str);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_url(url: *const c_char) -> *mut c_char {
    openedr_cloud_scan_url(url)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_inspect_url(url: *const c_char, _liveness_code: i32) -> *mut c_char {
    openedr_cloud_scan_url(url)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_inspect_url(url: *const c_char, liveness_code: i32) -> *mut c_char {
    openedr_cloud_inspect_url(url, liveness_code)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_inspect_url_content(
    url: *const c_char,
    _liveness_code: i32,
    _content: *const c_char,
) -> *mut c_char {
    openedr_cloud_scan_url(url)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_inspect_url_content(
    url: *const c_char,
    liveness_code: i32,
    content: *const c_char,
) -> *mut c_char {
    openedr_cloud_inspect_url_content(url, liveness_code, content)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_url_model_loaded() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_url_model_loaded() -> u32 {
    openedr_cloud_url_model_loaded()
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_check_file_signature(
    file_path: *const c_char,
    out_signer: *mut *mut c_char,
) -> u32 {
    if file_path.is_null() {
        return 0;
    }
    let Ok(path_str) = (unsafe { CStr::from_ptr(file_path) }).to_str() else {
        return 0;
    };

    let mut flags = 0u32;
    let info = authenticode::verify_authenticode(Path::new(path_str));

    if info.is_signed {
        flags |= 1;
    }
    if info.is_trusted {
        flags |= 2;
    }

    if !out_signer.is_null() {
        unsafe {
            *out_signer = to_c_string(info.signer_name.unwrap_or_default());
        }
    }

    flags
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_check_file_signature(
    file_path: *const c_char,
    out_signer: *mut *mut c_char,
) -> u32 {
    openedr_cloud_check_file_signature(file_path, out_signer)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_is_trusted_signer(_signer: *const c_char) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_is_trusted_signer(signer: *const c_char) -> u32 {
    openedr_cloud_is_trusted_signer(signer)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_is_malicious_signer(_signer: *const c_char) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_is_malicious_signer(signer: *const c_char) -> u32 {
    openedr_cloud_is_malicious_signer(signer)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_is_pua_signer(_signer: *const c_char) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_is_pua_signer(signer: *const c_char) -> u32 {
    openedr_cloud_is_pua_signer(signer)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_system_events() -> *mut c_char {
    to_c_string("[]".to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_system_events() -> *mut c_char {
    openedr_cloud_scan_system_events()
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_scan_evtx(_evtx_path: *const c_char) -> *mut c_char {
    to_c_string("[]".to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_evtx(evtx_path: *const c_char) -> *mut c_char {
    openedr_cloud_scan_evtx(evtx_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_check_hosts_file(hosts_path: *const c_char) -> *mut c_char {
    let custom_p = if !hosts_path.is_null() {
        match unsafe { CStr::from_ptr(hosts_path) }.to_str() {
            Ok(s) => Some(PathBuf::from(s)),
            Err(_) => return error_json("Invalid UTF-8 in hosts_path"),
        }
    } else {
        None
    };

    let report = hosts::check_hosts_file(custom_p.as_deref());
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_check_hosts_file(hosts_path: *const c_char) -> *mut c_char {
    openedr_cloud_check_hosts_file(hosts_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_restore_hosts_file(hosts_path: *const c_char, create_backup: i32) -> *mut c_char {
    let custom_p = if !hosts_path.is_null() {
        match unsafe { CStr::from_ptr(hosts_path) }.to_str() {
            Ok(s) => Some(PathBuf::from(s)),
            Err(_) => return error_json("Invalid UTF-8 in hosts_path"),
        }
    } else {
        None
    };

    let report = hosts::restore_hosts_file(custom_p.as_deref(), create_backup != 0);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_restore_hosts_file(hosts_path: *const c_char, create_backup: i32) -> *mut c_char {
    openedr_cloud_restore_hosts_file(hosts_path, create_backup)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_cloud_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_free_string(s: *mut c_char) {
    openedr_cloud_free_string(s);
}

// Stubs for web/diagnostic/model loading parity (no-op in cloud client)
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_model(_kind: u32, _data: *const u8, _len: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_yara(_data: *const u8, _len: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_yara_src(_data: *const u8, _len: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_set_string_rules(_data: *const u8, _len: usize) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_set_registry_rules(_data: *const u8, _len: usize) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_url_rules(_data: *const u8, _len: usize) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_add_unwhitelisted_subdomain(_host: *const c_char) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_is_unwhitelisted_subdomain(_host: *const c_char) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_apk_loaded() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_benign_whitelist(_data: *const u8, _len: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_url_whitelist(_data: *const u8, _len: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_check_registry(_reg_path: *const c_char) -> *mut c_char {
    to_c_string("{}".to_string())
}
