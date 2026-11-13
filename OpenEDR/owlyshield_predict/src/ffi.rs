//! C-ABI FFI surface exported by `owlyshield_predict.dll`.
//!
//! OpenEDR (`edrsvc.exe`) calls these symbols after loading the DLL
//! with `LoadLibraryW`. No Windows service is required.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;
use sha2::Digest;

static ENGINE_STOPPED: AtomicBool = AtomicBool::new(false);

/// Returns true if antivirus protection has been paused/stopped via control interface.
pub fn is_protection_stopped() -> bool {
    ENGINE_STOPPED.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_stop_protection() -> i32 {
    ENGINE_STOPPED.store(true, Ordering::SeqCst);
    Logging::warning("[Owlyshield FFI] Antivirus protection STOPPED via control interface");
    OWLY_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_start_protection() -> i32 {
    ENGINE_STOPPED.store(false, Ordering::SeqCst);
    Logging::info("[Owlyshield FFI] Antivirus protection STARTED via control interface");
    OWLY_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_is_protection_stopped() -> i32 {
    if ENGINE_STOPPED.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

use crate::shared_def::IOMessage;
use crate::windows::run::run_worker_loop;
use crate::{Driver, Logging};

const OWLY_OK: i32 = 0;
const OWLY_ALREADY_STARTED: i32 = 1;
const OWLY_DRIVER_ERROR: i32 = 2;
const OWLY_NOT_STARTED: i32 = 3;
const OWLY_DESERIALIZE_ERROR: i32 = 4;
const OWLY_CA_INSTALL_ERROR: i32 = 5;
const OWLY_QUARANTINE_ERROR: i32 = 6;

static SENDER: OnceLock<Sender<IOMessage>> = OnceLock::new();

/// In-process telemetry event delivered from `edrsvc.exe` straight into the
/// behavior engine. Replaces the former
/// `\\.\pipe\Global\HydraDragonOpenEdrTelemetry` named pipe so that no
/// untrusted usermode process can inject events.
pub enum TelemetryLine {
    FirewallPackedData(String),
    OpenedrEvent(String),
}

static TELEMETRY_SENDER: OnceLock<Sender<TelemetryLine>> = OnceLock::new();
static TELEMETRY_RECEIVER: OnceLock<Mutex<Option<mpsc::Receiver<TelemetryLine>>>> = OnceLock::new();

/// Initialize the in-process OpenEDR telemetry channel. Safe to call more than
/// once; only the first call sets the channel.
pub fn init_telemetry_channel() {
    if TELEMETRY_SENDER.get().is_some() {
        return;
    }
    let (tx, rx) = mpsc::channel::<TelemetryLine>();
    let _ = TELEMETRY_SENDER.set(tx);
    let _ = TELEMETRY_RECEIVER.set(Mutex::new(Some(rx)));
}

/// Take the telemetry receiver for the single consumer thread. Returns `None`
/// if the channel has not been initialized or has already been taken.
pub fn telemetry_receiver() -> Option<mpsc::Receiver<TelemetryLine>> {
    TELEMETRY_RECEIVER
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|mut guard| guard.take())
}

/// Send a telemetry line directly into the in-process channel.
pub fn send_telemetry_line(line: TelemetryLine) -> bool {
    if let Some(sender) = TELEMETRY_SENDER.get() {
        sender.send(line).is_ok()
    } else {
        false
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_start() -> i32 {
    if SENDER.get().is_some() {
        Logging::info("[Owlyshield FFI] owlyshield_dll_start called again; engine already running");
        return OWLY_OK;
    }

    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        Logging::error(&format!("[Owlyshield FFI] Critical panic: {pi}"));
    }));
    Logging::start();

    // The C++ side may start ingesting telemetry events as soon as the worker
    // thread is spawned below; initialize the channel up front so no events
    // are dropped while the consumer thread starts up.
    init_telemetry_channel();

    let driver = match Driver::open_kernel_driver_com() {
        Ok(d) => d,
        Err(e) => {
            Logging::error(&format!("[Owlyshield FFI] Cannot open driver: {e}"));
            return OWLY_DRIVER_ERROR;
        }
    };

    if let Err(e) = driver.driver_set_app_pid() {
        Logging::error(&format!("[Owlyshield FFI] driver_set_app_pid failed: {e}"));
        return OWLY_DRIVER_ERROR;
    }

    let (tx, rx) = mpsc::channel::<IOMessage>();

    if SENDER.set(tx).is_err() {
        Logging::error("[Owlyshield FFI] Race: SENDER already set");
        return OWLY_ALREADY_STARTED;
    }

    thread::Builder::new()
        .name("owlyshield-worker".into())
        .spawn(move || {
            run_worker_loop(rx, driver);
        })
        .expect("[Owlyshield FFI] Failed to spawn worker thread");

    Logging::info("[Owlyshield FFI] Engine started successfully (in-process)");
    OWLY_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn owlyshield_dll_ingest(data: *const u8, len: u32) -> i32 {
    let sender = match SENDER.get() {
        Some(s) => s,
        None => return OWLY_NOT_STARTED,
    };

    if data.is_null() || len == 0 {
        return OWLY_OK;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };

    let iomsg: IOMessage = match rmp_serde::from_slice(bytes) {
        Ok(m) => m,
        Err(e) => {
            Logging::error(&format!("[Owlyshield FFI] Deserialize error: {e}"));
            return OWLY_DESERIALIZE_ERROR;
        }
    };

    if sender.send(iomsg).is_err() {
        return OWLY_NOT_STARTED;
    }

    OWLY_OK
}

/// Ingest a serialized OpenEDR enriched event (JSON) into the behavior engine.
/// Called directly by `edrsvc.exe` via GetProcAddress; the old global named
/// pipe has been removed so no other usermode process can inject events.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn owlyshield_dll_ingest_openedr_event(data: *const u8, len: u32) -> i32 {
    init_telemetry_channel();
    let sender = match TELEMETRY_SENDER.get() {
        Some(s) => s,
        None => return OWLY_NOT_STARTED,
    };

    if data.is_null() || len == 0 {
        return OWLY_OK;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let payload = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return OWLY_DESERIALIZE_ERROR,
    };

    if sender.send(TelemetryLine::OpenedrEvent(payload)).is_err() {
        return OWLY_NOT_STARTED;
    }

    OWLY_OK
}

/// Ingest firewall FULL_PACKET packed data (JSON) into the behavior engine.
/// Called directly by `edrsvc.exe` via GetProcAddress; see
/// `owlyshield_dll_ingest_openedr_event` for why there is no pipe anymore.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn owlyshield_dll_ingest_firewall_packed_data(
    data: *const u8,
    len: u32,
) -> i32 {
    init_telemetry_channel();
    let sender = match TELEMETRY_SENDER.get() {
        Some(s) => s,
        None => return OWLY_NOT_STARTED,
    };

    if data.is_null() || len == 0 {
        return OWLY_OK;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let payload = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return OWLY_DESERIALIZE_ERROR,
    };

    if sender
        .send(TelemetryLine::FirewallPackedData(payload))
        .is_err()
    {
        return OWLY_NOT_STARTED;
    }

    OWLY_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_stop() {
    Logging::info("[Owlyshield FFI] Stop requested — worker will exit on channel close");
}

/// Install the HydraDragon firewall CA into the Windows ROOT trust store.
///
/// This is driver-independent: it generates (or reuses) the persisted CA under
/// `C:\ProgramData\edrsvc\ca` and installs the certificate into
/// `LocalMachine\Root`. It is called by edrsvc during setup, BEFORE the edrdrv
/// kernel driver is loaded, so no driver connection is required.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_install_ca() -> i32 {
    Logging::init();

    let ca_bundle = match crate::firewall::proxy::generate_ca() {
        Ok(bundle) => bundle,
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] Firewall CA generation failed: {e}"
            ));
            return OWLY_CA_INSTALL_ERROR;
        }
    };

    match crate::firewall::engine::FirewallEngine::install_ca_der(&ca_bundle.cert_der) {
        Ok(()) => {
            Logging::info("[Owlyshield FFI] Firewall CA installed into Windows trust store");
            OWLY_OK
        }
        Err(e) => {
            Logging::error(&format!("[Owlyshield FFI] Firewall CA install failed: {e}"));
            OWLY_CA_INSTALL_ERROR
        }
    }
}

/// Quarantine a file into an encrypted .hqf container and remove the original.
///
/// Driver-independent: reads `file_path` (UTF-8), XOR-encrypts the payload into
/// `C:\ProgramData\HydraDragonQuarantine\*.hqf` and deletes the source file.
/// Called by the OpenEDR C++ layer when it receives an FLS verdict of 2
/// (Malicious) for a file.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_quarantine_file(file_path: *const u8, len: u32) -> i32 {
    if file_path.is_null() || len == 0 {
        Logging::error("[Owlyshield FFI] owlyshield_dll_quarantine_file: null or empty path");
        return OWLY_QUARANTINE_ERROR;
    }

    let bytes = unsafe { std::slice::from_raw_parts(file_path, len as usize) };
    let path_str = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] owlyshield_dll_quarantine_file: invalid UTF-8 path: {e}"
            ));
            return OWLY_QUARANTINE_ERROR;
        }
    };

    let src = std::path::Path::new(path_str);
    if !src.exists() {
        Logging::error(&format!(
            "[Owlyshield FFI] owlyshield_dll_quarantine_file: source does not exist: {}",
            src.display()
        ));
        return OWLY_QUARANTINE_ERROR;
    }

    match crate::windows::quarantine::quarantine_path(src, "OpenEDR FLS Malicious Verdict") {
        Ok(dst) => {
            Logging::warning(&format!(
                "[Owlyshield FFI] Quarantined {} into {}",
                src.display(),
                dst.display()
            ));
            OWLY_OK
        }
        Err(crate::windows::quarantine::QuarantineError::Excluded) => {
            Logging::info(&format!(
                "[Owlyshield FFI] Quarantine skipped (user exclusion): {}",
                src.display()
            ));
            OWLY_OK
        }
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] Quarantine failed for {}: {e}",
                src.display()
            ));
            OWLY_QUARANTINE_ERROR
        }
    }
}

/// Called by OpenEDR C++ layer to register/update FLS verdict for a process PID.
/// `verdict`: 0=Absent, 1=Safe, 2=Malicious, 3=Unknown, 4=Fail/Error
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_update_process_verdict(pid: u32, verdict: u8) -> i32 {
    if pid == 0 {
        return -1;
    }
    if let Some(eng) = crate::firewall::headless::engine() {
        let mut verdicts = eng.app_manager.openedr_verdicts.write().unwrap();
        verdicts.insert(pid, verdict.to_string());
        Logging::info(&format!(
            "[Owlyshield FFI] Updated PID {} verdict to {}",
            pid, verdict
        ));
        if verdict == 2 {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]), true);
            if let Some(proc) = sys.process(sysinfo::Pid::from_u32(pid)) {
                if let Some(exe_path) = proc.exe().map(|p| p.to_path_buf()) {
                    let file_bytes = std::fs::read(&exe_path).ok();
                    let sha = file_bytes.as_ref()
                        .map(|b| {
                            let mut h = sha2::Sha256::new();
                            h.update(b);
                            hex::encode(h.finalize())
                        })
                        .unwrap_or_else(|| "unknown".to_string());
                    let report = crate::edr_feedback::ThreatReport {
                        sha256: sha,
                        file_name: exe_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "process.exe".to_string()),
                        original_path: exe_path.to_string_lossy().to_string(),
                        detection: "Behavioral.OpenEDR.MaliciousProcess".to_string(),
                        source: "behavioral_engine".to_string(),
                        pid: Some(pid),
                        details: serde_json::json!({
                            "process_name": proc.name().to_string_lossy(),
                            "pid": pid,
                            "verdict": verdict
                        }),
                    };
                    crate::edr_feedback::report_threat_async(report, file_bytes);
                }
            }
        }
        OWLY_OK
    } else {
        -1
    }
}

// Static file-scan exports (restored): thin forwarders to openedr_static.dll,
// the single LOCAL static engine (cloud verdicts stay in the C++ service and
// always win upstream). EICAR and all content verdicts come from
// openedr_static itself — nothing is duplicated here. Same contract as the
// removed revision: 2=malicious, 1=reserved, 0=unknown, -1=bad arguments.
// No cloud, no execution. Used by the Pascal GUI and the C++ local-verdict
// path, local or remote callers alike.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut std::ffi::c_void;
    fn GetModuleHandleW(name: *const u16) -> *mut std::ffi::c_void;
    fn GetProcAddress(module: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
}

type StaticInitFn = unsafe extern "C" fn(*const std::os::raw::c_char) -> i32;
type StaticScanFn =
    unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char;
type StaticUrlScanFn = unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char;
type StaticUrlModelLoadedFn = unsafe extern "C" fn() -> u32;
type StaticFreeFn = unsafe extern "C" fn(*mut std::os::raw::c_char);
type StaticSignerFn = unsafe extern "C" fn(*const std::os::raw::c_char) -> u32;
type StaticEvtxScanFn = unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char;
type StaticSystemEventsScanFn = unsafe extern "C" fn() -> *mut std::os::raw::c_char;
type StaticCheckRegistryFn = unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char;
type StaticCheckRegistryContentFn = unsafe extern "C" fn(
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char;

#[derive(Clone, Copy)]
struct StaticBinding {
    scan: StaticScanFn,
    free: StaticFreeFn,
    #[allow(dead_code)]
    scan_url: Option<StaticUrlScanFn>,
    #[allow(dead_code)]
    url_model_loaded: Option<StaticUrlModelLoadedFn>,
    is_trusted_signer: Option<StaticSignerFn>,
    is_malicious_signer: Option<StaticSignerFn>,
    is_pua_signer: Option<StaticSignerFn>,
    scan_evtx: Option<StaticEvtxScanFn>,
    scan_system_events: Option<StaticSystemEventsScanFn>,
    check_registry: Option<StaticCheckRegistryFn>,
    check_registry_content: Option<StaticCheckRegistryContentFn>,
}
unsafe impl Send for StaticBinding {}
unsafe impl Sync for StaticBinding {}

static STATIC_BINDING: OnceLock<Mutex<Option<StaticBinding>>> = OnceLock::new();

fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Resolve openedr_static.dll once (already-loaded module, exe folder, then
/// PATH) and bind the static scan APIs. Runs openedr_static_init(NULL) once.
fn static_binding() -> Option<StaticBinding> {
    let cell = STATIC_BINDING.get_or_init(|| {
        let dll_candidates = ["openedr_cloud.dll", "openedr_static.dll"];
        unsafe {
            let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
            for name in dll_candidates {
                let dll = wide_nul(name);
                handle = GetModuleHandleW(dll.as_ptr());
                if !handle.is_null() {
                    break;
                }
                handle = LoadLibraryW(dll.as_ptr());
                if !handle.is_null() {
                    break;
                }
                if let Ok(exe) = std::env::current_exe() {
                    if let Some(parent) = exe.parent() {
                        let p = wide_nul(&parent.join(name).to_string_lossy());
                        handle = LoadLibraryW(p.as_ptr());
                        if !handle.is_null() {
                            break;
                        }
                    }
                }
            }
            if handle.is_null() {
                return Mutex::new(None);
            }
            let sym = |n: &[u8]| GetProcAddress(handle, n.as_ptr());
            let scan_ptr = sym(b"openedr_static_scan_file\0");
            let free_ptr = sym(b"openedr_static_free_string\0");
            if scan_ptr.is_null() || free_ptr.is_null() {
                return Mutex::new(None);
            }
            let scan: StaticScanFn = std::mem::transmute(scan_ptr);
            let free: StaticFreeFn = std::mem::transmute(free_ptr);

            let scan_url_ptr = sym(b"openedr_static_scan_url\0");
            let scan_url = if scan_url_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*mut std::ffi::c_void, StaticUrlScanFn>(scan_url_ptr))
            };
            let url_loaded_ptr = sym(b"openedr_static_url_model_loaded\0");
            let url_model_loaded = if url_loaded_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<
                    *mut std::ffi::c_void,
                    StaticUrlModelLoadedFn,
                >(url_loaded_ptr))
            };

            let init_ptr = sym(b"openedr_static_init\0");
            if !init_ptr.is_null() {
                let init: StaticInitFn = std::mem::transmute(init_ptr);
                if init(std::ptr::null()) != 0 {
                    return Mutex::new(None);
                }
            }
            if (scan as usize) == 0 || (free as usize) == 0 {
                return Mutex::new(None);
            }
            let signer = |n: &[u8]| {
                let p = sym(n);
                if p.is_null() {
                    None
                } else {
                    Some(std::mem::transmute::<*mut std::ffi::c_void, StaticSignerFn>(p))
                }
            };
            let scan_evtx_ptr = sym(b"openedr_static_scan_evtx\0");
            let scan_evtx = if scan_evtx_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*mut std::ffi::c_void, StaticEvtxScanFn>(scan_evtx_ptr))
            };

            let scan_sys_events_ptr = sym(b"openedr_static_scan_system_events\0");
            let scan_system_events = if scan_sys_events_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*mut std::ffi::c_void, StaticSystemEventsScanFn>(scan_sys_events_ptr))
            };

            let check_reg_ptr = sym(b"openedr_static_check_registry\0");
            let check_registry = if check_reg_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*mut std::ffi::c_void, StaticCheckRegistryFn>(check_reg_ptr))
            };

            let check_reg_content_ptr = sym(b"openedr_static_check_registry_content\0");
            let check_registry_content = if check_reg_content_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*mut std::ffi::c_void, StaticCheckRegistryContentFn>(
                    check_reg_content_ptr,
                ))
            };

            Mutex::new(Some(StaticBinding {
                scan,
                free,
                scan_url,
                url_model_loaded,
                is_trusted_signer: signer(b"openedr_static_is_trusted_signer\0"),
                is_malicious_signer: signer(b"openedr_static_is_malicious_signer\0"),
                is_pua_signer: signer(b"openedr_static_is_pua_signer\0"),
                scan_evtx,
                scan_system_events,
                check_registry,
                check_registry_content,
            }))
        }
    });
    cell.lock().ok().and_then(|g| *g)
}

#[allow(dead_code)]
pub(crate) fn static_url_model_loaded() -> bool {
    let Some(binding) = static_binding() else {
        return false;
    };
    binding
        .url_model_loaded
        .map(|is_loaded| unsafe { is_loaded() != 0 })
        .unwrap_or(false)
}

/// Single-authority signer checks via openedr_static.dll.
/// Replaces the former duplicate `signer_rules.rs` YAML parsing here:
/// `signer_rules/` is owned solely by openedr_static.
fn static_signer_check(
    f: Option<StaticSignerFn>,
    signer_name: &str,
) -> bool {
    let Some(check) = f else {
        return false;
    };
    if signer_name.is_empty() {
        return false;
    }
    let Ok(c) = std::ffi::CString::new(signer_name) else {
        return false;
    };
    unsafe { check(c.as_ptr()) != 0 }
}

pub(crate) fn static_is_trusted_signer(signer_name: &str) -> bool {
    let Some(b) = static_binding() else {
        return false;
    };
    static_signer_check(b.is_trusted_signer, signer_name)
}

pub(crate) fn static_is_malicious_signer(signer_name: &str) -> bool {
    let Some(b) = static_binding() else {
        return false;
    };
    static_signer_check(b.is_malicious_signer, signer_name)
}

pub(crate) fn static_is_pua_signer(signer_name: &str) -> bool {
    let Some(b) = static_binding() else {
        return false;
    };
    static_signer_check(b.is_pua_signer, signer_name)
}

#[allow(dead_code)]
pub(crate) fn scan_url_with_static(url: &str) -> Option<f32> {
    let binding = static_binding()?;
    let scan_url = binding.scan_url?;
    let c_url = std::ffi::CString::new(url).ok()?;
    let report = unsafe {
        let raw = scan_url(c_url.as_ptr());
        if raw.is_null() {
            return None;
        }
        let report = std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned();
        (binding.free)(raw);
        report
    };
    let value: serde_json::Value = serde_json::from_str(&report).ok()?;
    if value.get("error").and_then(serde_json::Value::as_bool) == Some(true) {
        return None;
    }
    let probability = value.get("malware_probability")?.as_f64()? as f32;
    (probability.is_finite() && (0.0..=1.0).contains(&probability)).then_some(probability)
}

/// Shared scan core so verdict and name can never disagree.
fn scan_file_named(path_buf: &std::path::PathBuf) -> (i32, String) {
    if !path_buf.is_file() {
        return (0, String::new());
    }
    let binding = match static_binding() {
        Some(b) => b,
        None => return (0, String::new()),
    };
    let path_utf8 = path_buf.to_string_lossy().into_owned();
    let c_path = match std::ffi::CString::new(path_utf8) {
        Ok(c) => c,
        Err(_) => return (0, String::new()),
    };
    let report: String = unsafe {
        let raw = (binding.scan)(c_path.as_ptr());
        if raw.is_null() {
            return (0, String::new());
        }
        let s = std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned();
        (binding.free)(raw);
        s
    };
    let v: serde_json::Value = match serde_json::from_str(&report) {
        Ok(v) => v,
        Err(_) => return (0, String::new()),
    };
    match v.get("verdict").and_then(|x| x.as_str()) {
        Some("Malicious") => {
            let name = v
                .get("detections")
                .and_then(|d| d.as_array())
                .and_then(|a| a.first())
                .and_then(|d| d.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Malware.LocalDetection")
                .to_string();
            (2, name)
        }
        Some("Clean") => (1, String::new()),
        _ => (0, String::new()),
    }
}

/// Static-indicator file verdict via the local static engine.
/// `path_ptr`/`path_len`: UTF-16 path (WCHAR count, no NUL).
/// Returns 2=malicious, 0=unknown, -1=bad arguments.
/// No cloud, no execution. Used by the C++ local-verdict path and the GUI.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_scan_file(path_ptr: *const u16, path_len: u32) -> i32 {
    if path_ptr.is_null() || path_len == 0 || path_len > 32768 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(path_ptr, path_len as usize) };
    let path_buf = std::path::PathBuf::from(String::from_utf16_lossy(slice));
    scan_file_named(&path_buf).0
}

/// Static-indicator file verdict with detection NAME.
/// `name_buf`/`name_cap`: UTF-16 detection-name output (WCHAR count incl.
/// NUL); left empty unless verdict is malicious.
/// Returns 2=malicious, 0=unknown, -1=bad arguments.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_scan_file_name(
    path_ptr: *const u16,
    path_len: u32,
    name_buf: *mut u16,
    name_cap: u32,
) -> i32 {
    if path_ptr.is_null() || path_len == 0 || path_len > 32768 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(path_ptr, path_len as usize) };
    let path_buf = std::path::PathBuf::from(String::from_utf16_lossy(slice));
    let (verdict, name) = scan_file_named(&path_buf);
    if verdict == 2 && !name.is_empty() {
        let file_bytes = std::fs::read(&path_buf).ok();
        let sha = file_bytes.as_ref()
            .map(|b| {
                let mut h = sha2::Sha256::new();
                h.update(b);
                hex::encode(h.finalize())
            })
            .unwrap_or_else(|| "unknown".to_string());
        let report = crate::edr_feedback::ThreatReport {
            sha256: sha,
            file_name: path_buf.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "sample.bin".to_string()),
            original_path: path_buf.to_string_lossy().to_string(),
            detection: name.clone(),
            source: "ml_static".to_string(),
            pid: None,
            details: serde_json::json!({ "scanner": "owlyshield_scan_file_name" }),
        };
        crate::edr_feedback::report_threat_async(report, file_bytes);
    }
    if verdict == 2 && !name.is_empty() && !name_buf.is_null() && name_cap > 1 {
        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.truncate((name_cap as usize).saturating_sub(1));
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), name_buf, wide.len());
            *name_buf.add(wide.len()) = 0;
        }
    }
    verdict
}

/// URL-string scanner for external callers (e.g. the Pascal GUI).
///
/// Splits raw UTF-8 text (pasted URLs, string dumps, file text) into
/// URL-like tokens and scores each with the URL ML model
/// (`URL_ML_DETECTION_THRESHOLD`, same as the firewall path).
/// Verdict is Malicious iff any token hits, else Unknown (never Clean:
/// an unscored URL is unknown, not safe).
/// JSON out via the quarantine_list convention: null buffer (or 0 length)
/// returns the needed size.
/// `{"scanned":n,"model_loaded":b,"malicious_count":m,
///   "worst_probability":f,"verdict":"Malicious|Unknown",
///   "findings":[{"url","probability","malicious"}]}` (findings capped).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn owlyshield_scan_url_strings(
    data: *const u8,
    len: u32,
    out_buf: *mut u8,
    buf_len: u32,
) -> u32 {
    let json = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan_url_strings_impl(data, len)
    }))
    .unwrap_or_else(|_| {
        serde_json::json!({"error": true, "message": "panic during URL scan"}).to_string()
    });
    crate::windows::quarantine::write_json_out(&json, out_buf, buf_len)
}

fn scan_url_strings_impl(data: *const u8, len: u32) -> String {
    const MAX_INPUT: u32 = 64 * 1024 * 1024;
    const MAX_TOKENS: usize = 5000;
    const MAX_TOKEN_LEN: usize = 2048;

    if data.is_null() || len == 0 || len > MAX_INPUT {
        return serde_json::json!({"error": true, "message": "null/empty/oversize input"})
            .to_string();
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let text = String::from_utf8_lossy(bytes);

    let mut seen = std::collections::HashSet::new();
    let mut tokens: Vec<String> = Vec::new();
    for raw in text.split(|c: char| {
        c.is_whitespace() || c.is_control() || "<>\"'|,;()[]{}".contains(c)
    }) {
        if tokens.len() >= MAX_TOKENS {
            break;
        }
        let t = raw.trim_matches(|c: char| c.is_whitespace() || "().,;:!?\"'".contains(c));
        if t.len() < 4 || t.len() > MAX_TOKEN_LEN || !t.contains('.') {
            continue;
        }
        if !seen.insert(t.to_ascii_lowercase()) {
            continue;
        }
        tokens.push(t.to_string());
    }

    serde_json::json!({
        "scanned": tokens.len(),
        "model_loaded": false,
        "malicious_count": 0,
        "worst_probability": 0.0,
        "verdict": "Unknown",
        "findings": Vec::<serde_json::Value>::new(),
        "message": "URL ML is handled in the cloud"
    })
    .to_string()
}


/// Scan an EVTX file with the Hayabusa (Sigma) engine via openedr_static.
/// Returns JSON-formatted string on heap. Caller MUST free using `owlyshield_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_scan_evtx(path_ptr: *const u16, path_len: u32) -> *mut std::os::raw::c_char {
    if path_ptr.is_null() || path_len == 0 || path_len > 32768 {
        return std::ptr::null_mut();
    }
    let binding = match static_binding() {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    let scan_evtx = match binding.scan_evtx {
        Some(f) => f,
        None => return std::ptr::null_mut(),
    };
    let slice = unsafe { std::slice::from_raw_parts(path_ptr, path_len as usize) };
    let path_str = String::from_utf16_lossy(slice);
    let c_path = match std::ffi::CString::new(path_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    unsafe { scan_evtx(c_path.as_ptr()) }
}

/// Scan all live Windows system event logs with the Hayabusa (Sigma) engine via openedr_static.
/// Returns JSON-formatted string on heap. Caller MUST free using `owlyshield_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_scan_system_events() -> *mut std::os::raw::c_char {
    let binding = match static_binding() {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    let scan_sys = match binding.scan_system_events {
        Some(f) => f,
        None => return std::ptr::null_mut(),
    };
    unsafe { scan_sys() }
}

/// Check a registry path with the PTM registry engine via openedr_static.
/// Returns JSON-formatted string on heap. Caller MUST free using `owlyshield_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_check_registry(path_ptr: *const u16, path_len: u32) -> *mut std::os::raw::c_char {
    if path_ptr.is_null() || path_len == 0 || path_len > 32768 {
        return std::ptr::null_mut();
    }
    let binding = match static_binding() {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    let check_reg = match binding.check_registry {
        Some(f) => f,
        None => return std::ptr::null_mut(),
    };
    let slice = unsafe { std::slice::from_raw_parts(path_ptr, path_len as usize) };
    let path_str = String::from_utf16_lossy(slice);
    let c_path = match std::ffi::CString::new(path_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    unsafe { check_reg(c_path.as_ptr()) }
}

/// PUM (Potentially Unwanted Modification) check for one live registry
/// write: key path, value name and its data (all UTF-16, as the OpenEDR
/// detection notifier has them from the enriched event), forwarded to the
/// cloud (openedr_cloud.dll -> multron_server's `check_registry_content`,
/// matched against `pum_registry_rules.yaml`). Returns a JSON
/// `RegistryContentCheckReport`, or null on any binding/argument failure -
/// the caller must treat null/`is_pum:false` the same as "do not revert".
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_check_registry_content(
    key_path_ptr: *const u16,
    key_path_len: u32,
    value_name_ptr: *const u16,
    value_name_len: u32,
    value_data_ptr: *const u16,
    value_data_len: u32,
) -> *mut std::os::raw::c_char {
    if key_path_ptr.is_null() || key_path_len == 0 || key_path_len > 32768 {
        return std::ptr::null_mut();
    }
    let binding = match static_binding() {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    let check_reg_content = match binding.check_registry_content {
        Some(f) => f,
        None => return std::ptr::null_mut(),
    };

    let to_cstring = |ptr: *const u16, len: u32| -> Option<std::ffi::CString> {
        if ptr.is_null() || len == 0 {
            return Some(std::ffi::CString::new("").ok()?);
        }
        if len > 65536 {
            return None;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        std::ffi::CString::new(String::from_utf16_lossy(slice)).ok()
    };

    let Some(c_key) = to_cstring(key_path_ptr, key_path_len) else {
        return std::ptr::null_mut();
    };
    let Some(c_value_name) = to_cstring(value_name_ptr, value_name_len) else {
        return std::ptr::null_mut();
    };
    let Some(c_value_data) = to_cstring(value_data_ptr, value_data_len) else {
        return std::ptr::null_mut();
    };

    unsafe { check_reg_content(c_key.as_ptr(), c_value_name.as_ptr(), c_value_data.as_ptr()) }
}

/// Called by OpenEDR's detection notifier (edrsvc.exe, GetProcAddress) for every
/// stored detection: the event as UTF-8 JSON, sent to VirusKov as a behavior record
/// (dashboard "EDR Telemetry"). Returns at once; the upload runs on its own thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn owlyshield_stream_detection(data: *const u8, len: u32) -> i32 {
    if data.is_null() || len == 0 {
        return OWLY_OK;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let event: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            Logging::warning(&format!("[Owlyshield FFI] detection event is not JSON: {e}"));
            return OWLY_DESERIALIZE_ERROR;
        }
    };
    crate::edr_feedback::stream_openedr_detection_async(&event);
    OWLY_OK
}

/// Ingest a Sigma/Hayabusa JSON scan report and stream all detections to VirusKov cloud.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_stream_sigma_report(report_json: *const std::os::raw::c_char) {
    if report_json.is_null() {
        return;
    }
    let s = match unsafe { std::ffi::CStr::from_ptr(report_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(s) else {
        return;
    };
    let Some(arr) = val.as_array() else {
        return;
    };
    if arr.is_empty() {
        return;
    }

    for item in arr {
        let rule_title = item.get("rule_title")
            .or_else(|| item.get("title"))
            .or_else(|| item.get("rule_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown Sigma Detection");
        let level = item.get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("medium");
        let details_val = item.get("details").cloned().unwrap_or_else(|| item.clone());

        crate::edr_feedback::stream_sigma_detection_async(rule_title, level, details_val);
    }
}

/// Free a string returned by any owlyshield scan API (delegated to openedr_static_free_string).
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_free_string(ptr: *mut std::os::raw::c_char) {
    if ptr.is_null() {
        return;
    }
    if let Some(binding) = static_binding() {
        unsafe { (binding.free)(ptr) };
    }
}
