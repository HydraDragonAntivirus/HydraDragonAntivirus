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

    // Single-start rule: nfwrapper must start owlyshield once, then the
    // firewall with it — never twice. A healthy registered engine is left
    // alone (tearing it down per call flaps traffic); only a zombie
    // (registered but never started) is cleared for a fresh start.
    if let Some(engine) = super::headless::engine() {
        if engine.is_started() {
            clear_last_error();
            return 1;
        }
        emit_log_event(LogEntry {
            id: format!("{}-startup-zombie", now_ms()),
            timestamp: now_ms(),
            level: LogLevel::Warning,
            message: "Firewall engine was registered but never started; clearing zombie and starting fresh.".to_string(),
        });
        super::headless::unregister_and_stop();
    }

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
        message: "--- HydraDragon Firewall Starting (in-process) ---".to_string(),
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

/// Enable (1) or disable (0) transparent TLS (MITM) interception at runtime.
/// Called by edrsvc (`setMitmEnabled` JSON-RPC) on behalf of the Pascal GUI
/// tray toggle. Flips `tls_proxy.auto_start`, kicks the proxy runtime so the
/// listener starts/stops immediately, and persists to both settings files.
/// Returns 1 on success, 0 when the engine is not running.
#[unsafe(no_mangle)]
pub extern "system" fn owlyshield_firewall_set_mitm_enabled(enabled: u8) -> i32 {
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    let Some(engine) = super::headless::engine() else {
        set_last_error("Firewall engine is not running");
        return 0;
    };
    {
        let mut settings = engine.settings.write().unwrap();
        settings.tls_proxy.auto_start = enabled != 0;
    }
    engine.sync_proxy_runtime();
    engine.save_settings();
    emit_log_event(LogEntry {
        id: format!("{}-mitm-toggle", now_ms()),
        timestamp: now_ms(),
        level: LogLevel::Info,
        message: format!(
            "Transparent TLS proxy MITM interception {} via GUI toggle",
            if enabled != 0 { "ENABLED" } else { "DISABLED" }
        ),
    });
    clear_last_error();
    1
}

/// Query whether MITM interception is currently enabled (1) or disabled (0).
/// Returns -1 only if neither a live engine nor readable settings exist.
/// Falls back to the persisted settings file so the GUI shows the on-disk
/// state even while the service is stopped.
#[unsafe(no_mangle)]
pub extern "system" fn owlyshield_firewall_get_mitm_enabled() -> i32 {
    if let Some(engine) = super::headless::engine() {
        return if engine.settings.read().unwrap().tls_proxy.auto_start {
            1
        } else {
            0
        };
    }
    match super::engine::FirewallEngine::load_settings() {
        Some(s) => {
            if s.tls_proxy.auto_start {
                1
            } else {
                0
            }
        }
        None => 1,
    }
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
