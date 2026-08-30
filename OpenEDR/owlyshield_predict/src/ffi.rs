//! C-ABI FFI surface exported by `owlyshield_predict.dll`.
//!
//! OpenEDR (`edrsvc.exe`) calls these symbols after loading the DLL
//! with `LoadLibraryW`. No Windows service is required.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;

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

/// Callback (provided by edrsvc.exe at startup) used to republish an OpenEDR
/// event — serialized as UTF-8 JSON — back into OpenEDR's own event pipeline.
///
/// This is how hook/`LLE_DEVICE_IOCTL` events observed by the Owlyshield engine
/// (which is the only usermode client the kernel driver delivers API-hook
/// telemetry to) are re-injected into edrsvc so PTM rules such as
/// `CRYPTO_API_MASS` can evaluate `@event.owlyHook.functionName`.
type PublishCallback = extern "C" fn(*const u8, u32);

static PUBLISH_CB: OnceLock<PublishCallback> = OnceLock::new();

/// Register the host-provided callback that forwards a JSON event into OpenEDR.
/// Called by edrsvc during `InitOwlyshield` after the engine starts.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_set_publish_callback(cb: Option<PublishCallback>) {
    if let Some(cb) = cb {
        let _ = PUBLISH_CB.set(cb);
    }
}

/// Republish a serialized OpenEDR event (UTF-8 JSON) into the host pipeline.
/// No-op until a callback has been registered.
pub(crate) fn publish_openedr_event(payload: &[u8]) {
    if let Some(cb) = PUBLISH_CB.get() {
        cb(payload.as_ptr(), payload.len() as u32);
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
        None => {
            Logging::error("[Owlyshield FFI] owlyshield_dll_ingest called before start");
            return OWLY_NOT_STARTED;
        }
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
    let sender = match TELEMETRY_SENDER.get() {
        Some(s) => s,
        None => {
            Logging::error(
                "[Owlyshield FFI] owlyshield_dll_ingest_openedr_event called before start",
            );
            return OWLY_NOT_STARTED;
        }
    };

    if data.is_null() || len == 0 {
        return OWLY_OK;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let payload = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] owlyshield_dll_ingest_openedr_event: invalid UTF-8: {e}"
            ));
            return OWLY_DESERIALIZE_ERROR;
        }
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
    let sender = match TELEMETRY_SENDER.get() {
        Some(s) => s,
        None => {
            Logging::error(
                "[Owlyshield FFI] owlyshield_dll_ingest_firewall_packed_data called before start",
            );
            return OWLY_NOT_STARTED;
        }
    };

    if data.is_null() || len == 0 {
        return OWLY_OK;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let payload = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] owlyshield_dll_ingest_firewall_packed_data: invalid UTF-8: {e}"
            ));
            return OWLY_DESERIALIZE_ERROR;
        }
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
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] Quarantine failed for {}: {e}",
                src.display()
            ));
            OWLY_QUARANTINE_ERROR
        }
    }
}
