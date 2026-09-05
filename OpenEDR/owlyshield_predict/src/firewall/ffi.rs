use super::engine::{FirewallEngine, LogEntry, LogLevel, emit_log_event};
use std::ffi::c_char;
use std::sync::Arc;

static LAST_ERROR: std::sync::OnceLock<std::sync::Mutex<String>> = std::sync::OnceLock::new();

fn last_error() -> &'static std::sync::Mutex<String> {
    LAST_ERROR.get_or_init(|| std::sync::Mutex::new(String::new()))
}

fn set_last_error(message: impl Into<String>) {
    *last_error().lock().unwrap() = message.into();
}

fn clear_last_error() {
    last_error().lock().unwrap().clear();
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_IsRunning() -> i32 {
    if super::headless::engine().is_some() {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_Start() -> i32 {
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    // Forced start on every launch: tear down any previous instance first,
    // no liveness checks. A previous engine (healthy or zombie) never blocks
    // a fresh start.
    let was_started = super::headless::engine()
        .map(|e| e.is_started())
        .unwrap_or(false);
    super::headless::unregister_and_stop();

    let engine = Arc::new(FirewallEngine::new());
    if !super::headless::register(Arc::clone(&engine)) {
        // Lost a race with a concurrent starter; the winner owns startup now.
        set_last_error("Firewall engine is already registered");
        return 0;
    }

    emit_log_event(LogEntry {
        id: "startup-0".to_string(),
        timestamp: now_ms(),
        level: LogLevel::Info,
        message: format!(
            "--- HydraDragon Firewall Starting (in-process, previous started={}) ---",
            was_started
        ),
    });

    // Never let a start() panic cross the FFI boundary (process abort) or
    // leave a zombie registration behind: clean up and report instead.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.start();
    })) {
        Ok(()) => {
            clear_last_error();
            1
        }
        Err(_) => {
            super::headless::unregister_and_stop();
            set_last_error("Firewall engine start panicked; registry cleared, retry allowed");
            emit_log_event(LogEntry {
                id: format!("{}-startup-panic", now_ms()),
                timestamp: now_ms(),
                level: LogLevel::Error,
                message: "Firewall engine start panicked; registry cleared.".to_string(),
            });
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_Stop() -> i32 {
    super::headless::unregister_and_stop();
    clear_last_error();
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn HydraDragonFirewall_GetLastErrorMessage(
    buffer: *mut c_char,
    buffer_len: usize,
) -> usize {
    let message = last_error().lock().unwrap().clone();
    let bytes = message.as_bytes();

    if buffer.is_null() || buffer_len == 0 {
        return bytes.len();
    }

    let copy_len = bytes.len().min(buffer_len.saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), copy_len);
        *buffer.add(copy_len) = 0;
    }

    copy_len
}
