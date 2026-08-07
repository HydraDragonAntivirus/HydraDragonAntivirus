//! C-ABI FFI surface exported by `owlyshield_predict.dll`.
//!
//! OpenEDR (`edrsvc.exe`) calls these three symbols after loading the DLL
//! with `LoadLibraryW`. No Windows service is required.

use std::sync::mpsc::{self, Sender};
use std::sync::OnceLock;
use std::thread;

use crate::shared_def::IOMessage;
use crate::windows::run::run_worker_loop;
use crate::{Driver, Logging};

const OWLY_OK: i32 = 0;
const OWLY_ALREADY_STARTED: i32 = 1;
const OWLY_DRIVER_ERROR: i32 = 2;
const OWLY_NOT_STARTED: i32 = 3;
const OWLY_DESERIALIZE_ERROR: i32 = 4;

static SENDER: OnceLock<Sender<IOMessage>> = OnceLock::new();

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_start() -> i32 {
    if SENDER.get().is_some() {
        Logging::error("[Owlyshield FFI] owlyshield_dll_start called more than once");
        return OWLY_ALREADY_STARTED;
    }

    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        Logging::error(&format!("[Owlyshield FFI] Critical panic: {pi}"));
    }));
    Logging::start();

    let driver = match Driver::open_kernel_driver_com() {
        Ok(d) => d,
        Err(e) => {
            Logging::error(&format!(
                "[Owlyshield FFI] Cannot open driver: {e}"
            ));
            return OWLY_DRIVER_ERROR;
        }
    };

    if let Err(e) = driver.driver_set_app_pid() {
        Logging::error(&format!(
            "[Owlyshield FFI] driver_set_app_pid failed: {e}"
        ));
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

#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_dll_stop() {
    Logging::info("[Owlyshield FFI] Stop requested — worker will exit on channel close");
}
