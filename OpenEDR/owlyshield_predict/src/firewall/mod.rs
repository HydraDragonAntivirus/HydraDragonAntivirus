pub mod engine;

mod ffi;
pub mod file_magic;
pub mod headless;
pub mod http_parser;
pub mod proxy;
pub mod quarantine;
pub mod sdk;
pub mod tls_parser;
pub mod windivert_api;

use self::engine::{FirewallEngine, LogEntry, LogLevel, emit_log_event};
use std::sync::Arc;

/// Read the Firewall SDK rules folder path from the Windows Registry.
/// Falls back to None if the key is absent or the OS is not Windows.

pub(crate) fn get_firewall_sdk_rules_path() -> Option<std::path::PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK")
        .ok()
        .and_then(|key| key.get_value::<String, _>("RULES_PATH").ok())
        .map(std::path::PathBuf::from)
}

/// Headless in-process entry point. Registers the single engine instance,
/// starts packet capture, and blocks forever.
pub fn run() {
    println!("--- HydraDragon Firewall Booting (headless in-process) ---");

    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Create SOFTWARE\Owlyshield\SDK and ensure RULES_PATH exists.
    // The registry value is treated as a directory that contains YAML rule files.
    if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Owlyshield\SDK") {
        if key.get_value::<String, _>("RULES_PATH").is_err() {
            let default_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("firewall-rules")))
                .unwrap_or_else(|| std::path::PathBuf::from("firewall-rules"));
            let _ = key.set_value("RULES_PATH", &default_dir.to_string_lossy().to_string());
        }
    }

    let engine = Arc::new(FirewallEngine::new());
    if !headless::register(Arc::clone(&engine)) {
        eprintln!("HydraDragon Firewall: engine is already registered.");
        return;
    }

    emit_log_event(LogEntry {
        id: "startup-0".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        level: LogLevel::Info,
        message: "--- HydraDragon Firewall Starting ---".to_string(),
    });

    engine.start();

    // Keep the process alive; engine lifecycle is driven by headless::unregister_and_stop().
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
