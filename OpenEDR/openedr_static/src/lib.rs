pub mod apk;
pub mod cidr;
pub mod clam;
pub mod crypto;
pub mod engine;
pub mod hayabusa_scanner;
pub mod hosts;
pub mod ml;
pub mod pe_strings;
pub mod ptm_registry;
pub mod report;
pub mod signers;
pub mod string_rules;
pub mod url_rules;
pub mod yara;

/// HydraDragonSig deterministic file-content signature engine (external
/// Yamdle/YAML rules, daachorse matcher, pefile-rs PE parsing).
/// Registry/signer helpers are intentionally absent: those live in the
/// dedicated pipeline crates, not in the portable static engine.
pub use hydradragonsig;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use engine::StaticEngine;

static GLOBAL_ENGINE: OnceLock<RwLock<StaticEngine>> = OnceLock::new();

fn get_dll_directory() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::System::LibraryLoader::GetModuleFileNameW;

        let mut buf = [0u16; 1024];
        let hmodule = HMODULE(get_dll_directory as *const () as *mut std::ffi::c_void);
        let len = unsafe {
            GetModuleFileNameW(
                Some(hmodule),
                &mut buf,
            )
        };
        if len > 0 {
            let path = PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize]));
            if let Some(parent) = path.parent() {
                return parent.to_path_buf();
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn get_or_init_engine(base_dir: Option<PathBuf>) -> Result<&'static RwLock<StaticEngine>, String> {
    if let Some(engine) = GLOBAL_ENGINE.get() {
        return Ok(engine);
    }

    let dir = base_dir.unwrap_or_else(get_dll_directory);
    let engine = StaticEngine::init(&dir);
    let rwlock = RwLock::new(engine);
    let _ = GLOBAL_ENGINE.set(rwlock);
    Ok(GLOBAL_ENGINE.get().expect("GLOBAL_ENGINE must be set"))
}

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

/// Initialize the static scanner engine explicitly with a custom rules/database directory.
/// If base_rules_dir is NULL, defaults to looking for directories next to the loaded DLL.
/// Returns 0 on success, or -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_init(base_rules_dir: *const c_char) -> i32 {
    let path = if !base_rules_dir.is_null() {
        match unsafe { CStr::from_ptr(base_rules_dir) }.to_str() {
            Ok(s) => Some(PathBuf::from(s)),
            Err(_) => return -1,
        }
    } else {
        None
    };

    match get_or_init_engine(path) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Scan a file on disk by its path.
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_file(file_path: *const c_char) -> *mut c_char {
    if file_path.is_null() {
        return error_json("file_path pointer is null");
    }

    let path_str = match unsafe { CStr::from_ptr(file_path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return error_json("Invalid UTF-8 in file_path"),
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let engine_lock = match get_or_init_engine(None) {
            Ok(lock) => lock,
            Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
        };

        let engine = match engine_lock.read() {
            Ok(guard) => guard,
            Err(_) => return error_json("Engine lock poisoned"),
        };

        let report = engine.scan_file(Path::new(&path_str));
        match serde_json::to_string_pretty(&report) {
            Ok(json) => to_c_string(json),
            Err(e) => error_json(&format!("JSON serialization error: {}", e)),
        }
    }));

    match result {
        Ok(ptr) => ptr,
        Err(_) => error_json("Panic occurred during static scan"),
    }
}

/// Scan a buffer in memory.
/// `data`: pointer to byte slice.
/// `len`: length of data.
/// `file_name`: optional virtual filename for extension detection (can be NULL).
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_bytes(
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

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let engine_lock = match get_or_init_engine(None) {
            Ok(lock) => lock,
            Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
        };

        let engine = match engine_lock.read() {
            Ok(guard) => guard,
            Err(_) => return error_json("Engine lock poisoned"),
        };

        let report = engine.scan_bytes(slice, &name);
        match serde_json::to_string_pretty(&report) {
            Ok(json) => to_c_string(json),
            Err(e) => error_json(&format!("JSON serialization error: {}", e)),
        }
    }));

    match result {
        Ok(ptr) => ptr,
        Err(_) => error_json("Panic occurred during bytes scan"),
    }
}



/// Check a registry path against the PTM puaRegPaths indicator list.
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_check_registry(reg_path: *const c_char) -> *mut c_char {
    if reg_path.is_null() {
        return error_json("reg_path pointer is null");
    }

    let path_str = match unsafe { CStr::from_ptr(reg_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return error_json("Invalid UTF-8 in reg_path"),
    };

    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
    };

    let engine = match engine_lock.read() {
        Ok(guard) => guard,
        Err(_) => return error_json("Engine lock poisoned"),
    };

    let report = engine.check_registry(path_str);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

/// Scan a URL for phishing/malware (web parity: ML + CIDR + BinaryFuse16 whitelist).
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_url(url: *const c_char) -> *mut c_char {
    if url.is_null() {
        return error_json("url pointer is null");
    }

    let url_str = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s,
        Err(_) => return error_json("Invalid UTF-8 in url"),
    };

    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
    };

    let engine = match engine_lock.read() {
        Ok(guard) => guard,
        Err(_) => return error_json("Engine lock poisoned"),
    };

    let (prob, is_malicious, whitelisted, blacklisted) = engine.scan_url(url_str);
    let verdict = if blacklisted || is_malicious {
        "Malicious"
    } else if whitelisted {
        "Clean"
    } else {
        "Clean"
    };

    let report = serde_json::json!({
        "target_url": url_str,
        "verdict": verdict,
        "malware_probability": prob,
        "is_malicious": is_malicious,
        "whitelisted": whitelisted,
        "blacklisted": blacklisted,
    });

    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

/// Full URL threat inspection via Rust YAML Threat Engine (web parity:
/// `web_inspect_url`). `liveness_code`: 0=unknown, 1=active, 2=inactive/dead.
/// Returns JSON report. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_inspect_url(url: *const c_char, liveness_code: i32) -> *mut c_char {
    openedr_static_inspect_url_content(url, liveness_code, std::ptr::null())
}

/// Full URL + page-content inspection (web parity: `web_inspect_url_content`).
/// `content` may be NULL (same as `openedr_static_inspect_url`).
/// Returns JSON report. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_inspect_url_content(
    url: *const c_char,
    liveness_code: i32,
    content: *const c_char,
) -> *mut c_char {
    if url.is_null() {
        return error_json("url pointer is null");
    }
    let url_str = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return error_json("Invalid UTF-8 in url"),
    };
    let body: Option<String> = if content.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(content) }.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => return error_json("Invalid UTF-8 in content"),
        }
    };

    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
    };
    let engine = match engine_lock.read() {
        Ok(guard) => guard,
        Err(_) => return error_json("Engine lock poisoned"),
    };

    let report = engine.inspect_url_with_content(&url_str, liveness_code, body.as_deref());
    match serde_json::to_string_pretty(&report) {
        Ok(json) => to_c_string(json),
        Err(e) => error_json(&format!("JSON serialization error: {}", e)),
    }
}

fn take_c_bytes(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() || len > 256 * 1024 * 1024 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

/// Load a tree-model bundle from memory: kind 0=PE, 1=JS, 2=URL, 3=APK (web parity).
/// Returns 1 on success, 0 on parse failure.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_model(kind: u32, data: *const u8, len: usize) -> i32 {
    let Some(bytes) = take_c_bytes(data, len) else {
        return 0;
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return 0,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    engine.load_model(kind, &bytes) as i32
}

/// Load one compiled YARA `.yrc` bundle (web parity). Returns 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_yara(data: *const u8, len: usize) -> i32 {
    let Some(bytes) = take_c_bytes(data, len) else {
        return 0;
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return 0,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    engine.load_yara(&bytes) as i32
}

/// Compile one YARA source document (web parity). Returns 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_yara_src(data: *const u8, len: usize) -> i32 {
    let Some(bytes) = take_c_bytes(data, len) else {
        return 0;
    };
    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return 0,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    engine.add_yara_source(&text) as i32
}

/// Load hydradragonsig string-rule YAML (web parity). Returns rule count or -1.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_set_string_rules(data: *const u8, len: usize) -> i32 {
    let Some(bytes) = take_c_bytes(data, len) else {
        return -1;
    };
    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return -1,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return -1,
    };
    engine.set_string_rules(&text)
}

#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_set_registry_rules(data: *const u8, len: usize) -> i32 {
    openedr_static_set_string_rules(data, len)
}

/// Load BinaryFuse16 URL/domain/IP whitelist (.xf bytes, web parity). Returns 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_url_whitelist(data: *const u8, len: usize) -> i32 {
    let Some(bytes) = take_c_bytes(data, len) else {
        return 0;
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return 0,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    engine.load_url_whitelist(&bytes) as i32
}

/// Load custom YAML URL threat rules (web parity). Returns rule count or -1.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_load_url_rules(data: *const u8, len: usize) -> i32 {
    let Some(bytes) = take_c_bytes(data, len) else {
        return -1;
    };
    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return -1,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return -1,
    };
    match engine.load_url_rules(&text) {
        Ok(n) => n as i32,
        Err(_) => -1,
    }
}

/// Add a subdomain to the unwhitelist set (web parity). Returns 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_add_unwhitelisted_subdomain(host: *const c_char) -> i32 {
    if host.is_null() {
        return 0;
    }
    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return 0,
    };
    let mut engine = match engine_lock.write() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    engine.add_unwhitelisted_subdomain(&host_str);
    1
}

/// Check if a subdomain is unwhitelisted (web parity). Returns 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_is_unwhitelisted_subdomain(host: *const c_char) -> i32 {
    if host.is_null() {
        return 0;
    }
    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let engine_lock = match get_or_init_engine(None) {
        Ok(lock) => lock,
        Err(_) => return 0,
    };
    let engine = match engine_lock.read() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    engine.is_unwhitelisted_subdomain(host_str) as i32
}

/// APK tree-bundle readiness (web parity: 1 = `apk_trees.bin` loaded).
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_apk_loaded() -> u32 {
    match get_or_init_engine(None) {
        Ok(lock) => match lock.read() {
            Ok(engine) => engine.apk_ml_loaded() as u32,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

/// Scan a Windows EVTX log file for threat events using Hayabusa rules.
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_evtx(evtx_path: *const c_char) -> *mut c_char {
    if evtx_path.is_null() {
        return error_json("evtx_path pointer is null");
    }

    let path_str = match unsafe { CStr::from_ptr(evtx_path) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return error_json("Invalid UTF-8 in evtx_path"),
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let engine_lock = match get_or_init_engine(None) {
            Ok(lock) => lock,
            Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
        };

        let engine = match engine_lock.read() {
            Ok(guard) => guard,
            Err(_) => return error_json("Engine lock poisoned"),
        };

        let matches = engine.scan_evtx(Path::new(&path_str));
        match serde_json::to_string_pretty(&matches) {
            Ok(json) => to_c_string(json),
            Err(e) => error_json(&format!("JSON serialization error: {}", e)),
        }
    }));

    match result {
        Ok(ptr) => ptr,
        Err(_) => error_json("Panic occurred during EVTX scan"),
    }
}

/// Scan all live Windows system event logs (winevt/Logs) for threat events using Hayabusa rules.
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_scan_system_events() -> *mut c_char {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let engine_lock = match get_or_init_engine(None) {
            Ok(lock) => lock,
            Err(e) => return error_json(&format!("Failed to initialize engine: {}", e)),
        };

        let engine = match engine_lock.read() {
            Ok(guard) => guard,
            Err(_) => return error_json("Engine lock poisoned"),
        };

        let matches = engine.scan_system_events();
        match serde_json::to_string_pretty(&matches) {
            Ok(json) => to_c_string(json),
            Err(e) => error_json(&format!("JSON serialization error: {}", e)),
        }
    }));

    match result {
        Ok(ptr) => ptr,
        Err(_) => error_json("Panic occurred during live event logs scan"),
    }
}

/// Check if the Windows hosts file has any modifications compared to default template.
/// `hosts_path`: optional custom hosts file path (can be NULL to check standard C:\Windows\System32\drivers\etc\hosts).
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_check_hosts_file(hosts_path: *const c_char) -> *mut c_char {
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

/// Restore the Windows hosts file back to the clean default Microsoft Windows template.
/// `hosts_path`: optional custom hosts file path (can be NULL for default).
/// `create_backup`: 1 to create timestamped .backup file, 0 to overwrite without backup.
/// Returns a JSON-formatted string allocated on the heap. Caller MUST free using `openedr_static_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_restore_hosts_file(hosts_path: *const c_char, create_backup: i32) -> *mut c_char {
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

/// Free a C-string allocated and returned by openedr_static.
#[unsafe(no_mangle)]
pub extern "C" fn openedr_static_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}


