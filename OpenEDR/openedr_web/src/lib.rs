//! openedr_web: Web/WASM edition of the OpenEDR static engine.
//!
//! Plain `extern "C"` exports over linear memory (no wasm-bindgen needed):
//! JS copies input bytes in with [`web_alloc`], calls an operation, reads the
//! UTF-8 JSON out-pointer + [`web_output_len`], then frees it.
//!
//! Always check `web_output_len()` after a call: 0 means the call failed
//! (null input, bad UTF-8, engine error) and the returned pointer is null.

pub mod apk;
pub mod cidr;
pub mod engine;
pub mod ml;
pub mod pe_strings;
pub mod report;
pub mod string_rules;
pub mod url_rules;
pub mod yara;

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};

use engine::WebEngine;

static ENGINE: OnceLock<Mutex<WebEngine>> = OnceLock::new();
static LAST_OUT_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn engine() -> &'static Mutex<WebEngine> {
    ENGINE.get_or_init(|| Mutex::new(WebEngine::new()))
}

fn lock_engine() -> Option<std::sync::MutexGuard<'static, WebEngine>> {
    engine().lock().ok()
}

/// Length in bytes of the JSON returned by the last successful call.
#[no_mangle]
pub extern "C" fn web_output_len() -> usize {
    LAST_OUT_LEN.load(std::sync::atomic::Ordering::Relaxed)
}

/// Allocate `len` bytes in wasm memory; JS writes input there. Free with
/// [`web_free`] (or [`web_free_str`] for returned strings).
#[no_mangle]
pub extern "C" fn web_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    let mut v = Vec::with_capacity(len);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// Free a buffer from [`web_alloc`].
///
/// # Safety
/// `ptr`/`len` must be exactly what [`web_alloc`] returned and unfreed.
#[no_mangle]
pub extern "C" fn web_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, 0, len);
        }
    }
}

fn take_bytes(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    // Empty input is valid (e.g. a 0-byte file): it scans as Unknown rather
    // than failing with a null output pointer. `web_alloc(0)` returns null,
    // so a null pointer is only an error when `len > 0`.
    if len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() {
        return None;
    }
    if len > 256 * 1024 * 1024 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

fn take_str(ptr: *const u8, len: usize) -> Option<String> {
    let bytes = take_bytes(ptr, len)?;
    String::from_utf8(bytes).ok()
}

/// Publish a JSON string to JS. Returns null pointer on serialization error.
fn emit_json(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => {
            LAST_OUT_LEN.store(c.as_bytes().len(), std::sync::atomic::Ordering::Relaxed);
            c.into_raw()
        }
        Err(_) => {
            LAST_OUT_LEN.store(0, std::sync::atomic::Ordering::Relaxed);
            std::ptr::null_mut()
        }
    }
}

/// Free a string returned by `web_scan_*`.
///
/// # Safety
/// Must be a pointer from this module that has not been freed yet.
#[no_mangle]
pub extern "C" fn web_free_str(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Load a tree-model bundle: kind 0 = PE, 1 = JS, 2 = URL.
/// Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_model(kind: u32, ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_model(kind, &data) as i32
}

/// Load BinaryFuse16 URL/domain/IP whitelist (.xf binary).
/// Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_url_whitelist(ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_url_whitelist(&data) as i32
}

/// Load BinaryFuse16 SHA-256 benign whitelist (.xf binary, same format as
/// the URL/domain/IP whitelist). Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_benign_whitelist(ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_benign_whitelist(&data) as i32
}

/// Load one compiled YARA `.yrc` bundle (same bytes as desktop).
/// Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_yara(ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_yara(&data) as i32
}

#[no_mangle]
pub extern "C" fn web_load_yara_rules(ptr: *const u8, len: usize) -> i32 {
    web_load_yara(ptr, len)
}

/// Compile one YARA source document. Returns 1 on success, 0 on error.
#[no_mangle]
pub extern "C" fn web_load_yara_src(ptr: *const u8, len: usize) -> i32 {
    let Some(text) = take_str(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.add_yara_source(&text) as i32
}

/// Load hydradragonsig string-rule YAML (generic `Rule` documents).
/// Returns rule count, or -1 on parse error.
#[no_mangle]
pub extern "C" fn web_set_string_rules(ptr: *const u8, len: usize) -> i32 {
    let Some(text) = take_str(ptr, len) else {
        return -1;
    };
    let Some(mut eng) = lock_engine() else {
        return -1;
    };
    eng.set_string_rules(&text)
}

#[no_mangle]
pub extern "C" fn web_set_registry_rules(ptr: *const u8, len: usize) -> i32 {
    web_set_string_rules(ptr, len)
}

/// Load APK subword vocabulary (`vocab.json` from hydradragonml, token->id).
/// Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_apk_vocab(ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_apk_vocab(&data) as i32
}

/// Load APK corpus percentile stats (`features.json` from hydradragonml).
/// Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_apk_features(ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_apk_features(&data) as i32
}

/// Load APK MLP weights (`apk_weights.bin`, same values as `apk_model.onnx`).
/// Returns 1 on success, 0 on parse failure.
#[no_mangle]
pub extern "C" fn web_load_apk_weights(ptr: *const u8, len: usize) -> i32 {
    let Some(data) = take_bytes(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.load_apk_weights(&data) as i32
}

/// APK ML readiness bitmask: 1 = vocab, 2 = features, 4 = weights (7 = ready).
/// Heuristics run regardless; ML scoring needs all three.
#[no_mangle]
pub extern "C" fn web_apk_loaded() -> u32 {
    lock_engine().map(|eng| eng.apk_loaded_mask()).unwrap_or(0)
}

fn scan_impl(
    data_ptr: *const u8,
    data_len: usize,
    name_ptr: *const u8,
    name_len: usize,
    disasm: Option<(u64, u64, u64)>,
) -> *mut c_char {
    let Some(data) = take_bytes(data_ptr, data_len) else {
        return std::ptr::null_mut();
    };
    let name = take_str(name_ptr, name_len).unwrap_or_else(|| "sample.bin".to_string());
    let Some(eng) = lock_engine() else {
        return std::ptr::null_mut();
    };
    let report = eng.scan_bytes(&data, &name, disasm);
    let json = serde_json::to_string(&report).unwrap_or_else(|_| {
        "{\"error\":true,\"message\":\"serialization failed\"}".to_string()
    });
    emit_json(json)
}

/// Scan bytes (no disassembler counts; PE features 51..53 read 0.0).
/// Returns JSON report pointer (see [`web_output_len`]).
#[no_mangle]
pub extern "C" fn web_scan_bytes(
    data_ptr: *const u8,
    data_len: usize,
    name_ptr: *const u8,
    name_len: usize,
) -> *mut c_char {
    scan_impl(data_ptr, data_len, name_ptr, name_len, None)
}

/// Scan bytes with capstone.js disassembly counts
/// (`total_instructions`, `total_add`, `total_mov`).
/// `has_counts` = 0 ignores the counts (same as [`web_scan_bytes`]).
#[no_mangle]
pub extern "C" fn web_scan_bytes_ex(
    data_ptr: *const u8,
    data_len: usize,
    name_ptr: *const u8,
    name_len: usize,
    has_counts: u32,
    total_insn: u64,
    total_add: u64,
    total_mov: u64,
) -> *mut c_char {
    let disasm = if has_counts != 0 {
        Some((total_insn, total_add, total_mov))
    } else {
        None
    };
    scan_impl(data_ptr, data_len, name_ptr, name_len, disasm)
}

/// Score a URL. Returns JSON: target_url, verdict, malware_probability,
/// is_malicious.
#[no_mangle]
pub extern "C" fn web_scan_url(ptr: *const u8, len: usize) -> *mut c_char {
    let Some(url) = take_str(ptr, len) else {
        return std::ptr::null_mut();
    };
    let Some(eng) = lock_engine() else {
        return std::ptr::null_mut();
    };
    let (prob, malicious, whitelisted, blacklisted) = eng.scan_url(&url);
    let verdict = if blacklisted {
        "Malicious"
    } else if whitelisted {
        "Clean"
    } else if malicious {
        "Malicious"
    } else {
        "Clean"
    };
    let out = serde_json::json!({
        "target_url": url,
        "verdict": verdict,
        "malware_probability": prob,
        "is_malicious": malicious,
        "whitelisted": whitelisted,
        "blacklisted": blacklisted,
    });
    emit_json(out.to_string())
}

/// Inspect a URL with the complete Rust YAML Threat Engine.
/// `liveness_code`: 0 = unknown, 1 = active, 2 = inactive/dead (NXDOMAIN).
/// Returns full JSON report with all signals, rule hits, and final verdict.
#[no_mangle]
pub extern "C" fn web_inspect_url(ptr: *const u8, len: usize, liveness_code: i32) -> *mut c_char {
    web_inspect_url_content(ptr, len, liveness_code, std::ptr::null(), 0)
}

/// Inspect a URL and its fetched site content (HTML/JS/DOM).
/// Evaluates URL heuristics, CIDR subnets, ML models, and content-level threat patterns (phishing forms, drainers, webhooks, YARA).
#[no_mangle]
pub extern "C" fn web_inspect_url_content(
    url_ptr: *const u8,
    url_len: usize,
    liveness_code: i32,
    content_ptr: *const u8,
    content_len: usize,
) -> *mut c_char {
    let Some(url) = take_str(url_ptr, url_len) else {
        return std::ptr::null_mut();
    };
    let content = take_str(content_ptr, content_len);
    let Some(eng) = lock_engine() else {
        return std::ptr::null_mut();
    };
    let report = eng.inspect_url_with_content(&url, liveness_code, content.as_deref());
    let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
    emit_json(json)
}

/// Load custom YAML threat rules into the URL threat engine.
/// Returns number of rules loaded, or -1 on parse error.
#[no_mangle]
pub extern "C" fn web_load_url_rules(ptr: *const u8, len: usize) -> i32 {
    let Some(text) = take_str(ptr, len) else {
        return -1;
    };
    let Some(mut eng) = lock_engine() else {
        return -1;
    };
    match eng.load_url_rules(&text) {
        Ok(n) => n as i32,
        Err(_) => -1,
    }
}

/// Dynamically add a subdomain to the unwhitelist list (e.g. "raw.githubusercontent.com").
/// Bypasses the Tranco whitelist for this specific host, enabling full ML & threat rule evaluation.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn web_add_unwhitelisted_subdomain(ptr: *const u8, len: usize) -> i32 {
    let Some(host) = take_str(ptr, len) else {
        return 0;
    };
    let Some(mut eng) = lock_engine() else {
        return 0;
    };
    eng.add_unwhitelisted_subdomain(&host);
    1
}

/// Check if a subdomain is currently unwhitelisted.
/// Returns 1 if unwhitelisted, 0 if whitelisted / normal.
#[no_mangle]
pub extern "C" fn web_is_unwhitelisted_subdomain(ptr: *const u8, len: usize) -> i32 {
    let Some(host) = take_str(ptr, len) else {
        return 0;
    };
    let Some(eng) = lock_engine() else {
        return 0;
    };
    eng.is_unwhitelisted_subdomain(&host) as i32
}

/// Engine self-test without models (EICAR must hit). Returns 1 on pass.
/// Handy to verify the wasm module wired up correctly from JS.
#[no_mangle]
pub extern "C" fn web_self_test() -> i32 {
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let eng = WebEngine::new();
    let report = eng.scan_bytes(eicar, "eicar.com", None);
    (report.verdict == "Malicious"
        && report
            .detections
            .iter()
            .any(|d| d.name == "EICAR-Test-File")) as i32
}
