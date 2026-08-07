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
    if super::headless::engine().is_some() {
        clear_last_error();
        return 1;
    }

    let engine = Arc::new(FirewallEngine::new());
    if !super::headless::register(Arc::clone(&engine)) {
        set_last_error("Firewall engine is already registered");
        return 0;
    }

    emit_log_event(LogEntry {
        id: "startup-0".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        level: LogLevel::Info,
        message: "--- HydraDragon Firewall Starting (in-process) ---".to_string(),
    });

    engine.start();
    clear_last_error();
    1
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
