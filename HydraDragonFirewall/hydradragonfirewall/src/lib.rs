pub mod engine;
pub mod file_magic;
pub mod http_parser;
pub mod proxy;
pub mod sdk;
pub mod tls_parser;
pub mod web_filter;
pub mod windivert_api;

use crate::engine::{emit_log_event, FirewallEngine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::time::{sleep, Duration};

/// A body changer rule stored in body_changers.json and reflected in rules.yaml.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BodyChangerRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub target: String,       // "request" or "response"
    pub url_pattern: String,
    pub method_pattern: String,
    pub replacement: String,
}

fn body_changers_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("body_changers.json")
}

fn load_body_changers() -> Vec<BodyChangerRule> {
    let path = body_changers_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_body_changers_to_disk(rules: &[BodyChangerRule]) -> Result<(), String> {
    let path = body_changers_path();
    let json = serde_json::to_string_pretty(rules)
        .map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("Write error: {}", e))
}

// FirewallState was redundant as we manage Arc<FirewallEngine> directly in modern Tauri 2

async fn wait_for_engine<R: Runtime>(handle: &AppHandle<R>) -> Option<Arc<FirewallEngine>> {
    for _ in 0..100 {
        if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
            return Some(Arc::clone(&*engine));
        }
        sleep(Duration::from_millis(50)).await;
    }

    None
}

#[derive(Debug, Serialize)]
struct EngineRuntimeStatus {
    active: bool,
    status: String,
}

#[tauri::command]
async fn resolve_app_decision(
    name: String,
    decision: String,
    handle: AppHandle,
) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.resolve_app_decision(name, decision, &handle);
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_settings<R: Runtime>(
    handle: AppHandle<R>,
) -> Result<crate::engine::FirewallSettings, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        Ok(engine.get_settings())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_saved_logs<R: Runtime>(
    handle: AppHandle<R>,
) -> Result<Vec<crate::engine::LogEntry>, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        Ok(engine.get_saved_logs())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn save_settings(
    settings: crate::engine::FirewallSettings,
    handle: AppHandle,
) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.apply_settings(settings);
        engine.save_settings();
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_sdk_rules<R: Runtime>(
    handle: AppHandle<R>,
) -> Result<Vec<crate::sdk::SdkRule>, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        Ok(engine.get_sdk_rules())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_rules_content(handle: AppHandle) -> String {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.get_rules_raw()
    } else {
        String::new()
    }
}

#[tauri::command]
async fn save_rules_content(content: String, handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.save_rules_raw(content)
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn validate_rules_content(content: String, handle: AppHandle) -> Result<String, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.validate_rules_raw(content)
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_owlyshield_rules_path() -> Option<std::path::PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Owlyshield")
        .ok()
        .and_then(|key| key.get_value::<String, _>("RULES_PATH").ok())
        .map(std::path::PathBuf::from)
}

/// Read the Firewall SDK rules folder/file path from the Windows Registry.
/// Falls back to None if the key is absent or the OS is not Windows.
#[cfg(target_os = "windows")]
fn get_firewall_sdk_rules_path() -> Option<std::path::PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK")
        .ok()
        .and_then(|key| key.get_value::<String, _>("RULES_PATH").ok())
        .map(std::path::PathBuf::from)
}

#[tauri::command]
async fn get_owlyshield_rules_raw() -> String {
    // Prefer the registry-configured path (Windows).
    #[cfg(target_os = "windows")]
    if let Some(path) = get_owlyshield_rules_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return content;
        }
    }
    // Fall back to a local override file next to the executable.
    let local_path = "owlyshield_rules.yaml";
    std::fs::read_to_string(local_path).unwrap_or_default()
}

#[tauri::command]
async fn save_owlyshield_rules_raw(content: String) -> Result<(), String> {
    // Prefer the registry-configured path (Windows).
    #[cfg(target_os = "windows")]
    if let Some(path) = get_owlyshield_rules_path() {
        return std::fs::write(&path, content).map_err(|e| e.to_string());
    }
    let local_path = "owlyshield_rules.yaml";
    std::fs::write(local_path, content).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_app_decisions(handle: AppHandle) -> Result<std::collections::HashMap<String, crate::engine::AppDecision>, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        Ok(engine.get_app_decisions())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn remove_app_decision(name_lower: String, handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.remove_app_decision(name_lower);
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn clear_app_decisions(handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.clear_app_decisions();
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_active_alert(handle: AppHandle) -> Result<Option<crate::engine::PendingApp>, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        Ok(engine.get_active_alert())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn next_alert(handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        if let Some(new_alert) = engine.next_alert() {
            let _ = handle.emit("ask_app_decision", new_alert);
        }
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn previous_alert(handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        if let Some(new_alert) = engine.previous_alert() {
            let _ = handle.emit("ask_app_decision", new_alert);
        }
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_engine_runtime_status<R: Runtime>(handle: AppHandle<R>) -> EngineRuntimeStatus {
    if handle.try_state::<Arc<FirewallEngine>>().is_some() {
        EngineRuntimeStatus {
            active: true,
            status: "Firewall Engine ACTIVE".to_string(),
        }
    } else {
        EngineRuntimeStatus {
            active: false,
            status: "Initializing Engine...".to_string(),
        }
    }
}

#[tauri::command]
async fn get_window_label(window: tauri::Window) -> String {
    window.label().to_string()
}

#[tauri::command]
async fn close_window(window: tauri::Window) {
    // Hide the alert window instead of destroying it so it stays pre-loaded
    // for the next alert (eliminates WebView2/Wasm init latency).
    if window.label() == "firewall-alert" {
        let _ = window.hide();
    } else {
        let _ = window.close();
    }
}

#[tauri::command]
async fn quit_app(handle: AppHandle) {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.stop();
    }
    handle.exit(0);
}

/// Return all body changer rules stored in body_changers.json.
#[tauri::command]
async fn get_body_changers() -> Vec<BodyChangerRule> {
    load_body_changers()
}

/// Persist body changer rules and regenerate the SDK entries in rules.yaml.
///
/// Each rule is appended to the existing rules.yaml content as a YAML block
/// with either `action: change_request_body` or `action: change_response_body`.
/// Any previous auto-generated body-changer entries (identified by a `# [body-changer]`
/// comment header) are replaced.
#[tauri::command]
async fn save_body_changers(
    rules: Vec<BodyChangerRule>,
    handle: AppHandle,
) -> Result<(), String> {
    // Persist JSON index
    save_body_changers_to_disk(&rules)?;

    // Rebuild rules.yaml: keep the hand-written portion, replace the generated block.
    if let Some(engine) = wait_for_engine(&handle).await {
        let raw = engine.get_rules_raw();
        // Strip any previously generated block.
        let separator = "# --- body-changer-rules-begin ---";
        let base = if let Some(idx) = raw.find(separator) {
            raw[..idx].trim_end().to_string()
        } else {
            raw.trim_end().to_string()
        };

        let mut generated = String::from("\n\n# --- body-changer-rules-begin ---\n");
        generated.push_str("# Auto-generated by the Body Changer GUI — do not edit manually\n");

        for rule in &rules {
            if !rule.enabled {
                continue;
            }
            let action = if rule.target == "response" {
                "change_response_body"
            } else {
                "change_request_body"
            };
            let replacement_escaped = rule.replacement.replace('\\', "\\\\").replace('"', "\\\"");
            let mut entry = format!(
                "- name: \"{}\"\n  enabled: true\n  action: {}\n",
                rule.name.replace('"', "\\\""),
                action,
            );
            if !rule.url_pattern.is_empty() {
                entry.push_str(&format!(
                    "  url:\n    patterns:\n      - \"{}\"\n",
                    rule.url_pattern.replace('"', "\\\"")
                ));
            }
            if action == "change_request_body" {
                entry.push_str(&format!(
                    "  change_request_body: \"{}\"\n",
                    replacement_escaped
                ));
            } else {
                entry.push_str(&format!(
                    "  change_response_body: \"{}\"\n",
                    replacement_escaped
                ));
            }
            generated.push_str(&entry);
            generated.push('\n');
        }
        generated.push_str("# --- body-changer-rules-end ---\n");

        let new_content = if rules.iter().any(|r| r.enabled) {
            format!("{}{}", base, generated)
        } else {
            base
        };

        engine.save_rules_raw(new_content)?;
    }

    Ok(())
}

pub fn run() {
    println!("DEBUG: hydradragonfirewall::run() entered");
    println!("--- HydraDragon Firewall Booting (Tauri 2.0) ---");

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        // Create SOFTWARE\Owlyshield\SDK and ensure RULES_PATH exists
        if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Owlyshield\SDK") {
            if key.get_value::<String, _>("RULES_PATH").is_err() {
                let _ = key.set_value("RULES_PATH", &"rules.yaml");
            }
        }
        // Ensure SOFTWARE\Owlyshield exists and has its own RULES_PATH
        if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Owlyshield") {
            if key.get_value::<String, _>("RULES_PATH").is_err() {
                let _ = key.set_value("RULES_PATH", &"owlyshield_rules.yaml");
            }
        }
    }

    println!("DEBUG: Initializing tauri::Builder...");
    let builder = tauri::Builder::default();
    println!("DEBUG: tauri::Builder created.");

    builder
        .setup(|app| {
            println!("DEBUG: Entering setup closure...");

            // --- System Tray Setup ---
            let quiet_i =
                tauri::menu::MenuItem::with_id(app, "quit", "Quit", true, None::<&str>).unwrap();
            let show_i =
                tauri::menu::MenuItem::with_id(app, "show", "Show Firewall", true, None::<&str>)
                    .unwrap();
            let menu = tauri::menu::Menu::with_items(app, &[&show_i, &quiet_i]).unwrap();

            let _tray = tauri::tray::TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        if let Some(engine) = app.try_state::<Arc<FirewallEngine>>() {
                            engine.stop();
                        }
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                })
                .icon(app.default_window_icon().unwrap().clone())
                .build(app)?;

            let args: Vec<String> = std::env::args().collect();
            // CLI flags take priority; also check persisted settings for each mode.
            let saved = crate::engine::FirewallEngine::load_settings();
            let headless = args.iter().any(|a| a == "--headless")
                || saved.as_ref().map_or(false, |s| s.headless_mode);
            let log_mode = args.iter().any(|a| a == "--log-mode")
                || saved.as_ref().map_or(false, |s| s.log_mode);
            let no_alert = args.iter().any(|a| a == "--no-alert")
                || saved.as_ref().map_or(false, |s| s.no_alert_mode);

            if headless {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }

            let handle = app.handle().clone();

            // Re-enabling Engine Initialization
            std::thread::Builder::new()
                .name("engine_init".to_string())
                .spawn(move || {
                    // Wait for WebView to be ready
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    // Emit startup message
                    emit_log_event(
                        &handle,
                        crate::engine::LogEntry {
                            id: "startup-0".to_string(),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                            level: crate::engine::LogLevel::Info,
                            message: "--- HydraDragon Firewall Starting ---".to_string(),
                        },
                    );

                    println!("DEBUG: FirewallEngine::new() starting...");
                    let engine_obj = FirewallEngine::new();
                    
                    // Apply CLI flags to engine settings
                    {
                        let mut s = engine_obj.settings.write().unwrap();
                        if headless { s.headless_mode = true; }
                        if log_mode { s.log_mode = true; }
                        if no_alert { s.no_alert_mode = true; }
                    }

                    let engine = Arc::new(engine_obj);
                    println!("DEBUG: FirewallEngine::new() finished.");

                    // manage() MUST come before start(). The worker threads spawned
                    // by start() immediately call handle.try_state::<Arc<FirewallEngine>>()
                    // for every Tauri command. If manage() hasn't been called yet,
                    // try_state() returns None and every command returns
                    // Err("Engine not initialized") -- causing a blank UI.
                    handle.manage(Arc::clone(&engine));
                    engine.start(handle.clone());
                    println!("DEBUG: FirewallEngine managed and started.");

                    // Pre-warm the alert window while no threat is active so the
                    // WebView2 instance and Wasm bundle are already loaded when the
                    // first alert arrives. A short delay lets the main window finish
                    // rendering before we create the hidden secondary window.
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    FirewallEngine::prewarm_alert_window(&handle);
                    println!("DEBUG: Alert window pre-warmed.");
                })
                .expect("Failed to spawn engine_init thread");

            println!("DEBUG: setup closure finished.");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    window.hide().unwrap();
                    api.prevent_close();

                    // Optional: notify the frontend/log that the app is still running.
                    emit_log_event(
                        &window.app_handle(),
                        crate::engine::LogEntry {
                            id: format!("hide-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
                            level: crate::engine::LogLevel::Info,
                            message: "Firewall window hidden. Still running in system tray.".to_string(),
                        },
                    );
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            resolve_app_decision,
            get_settings,
            get_saved_logs,
            save_settings,
            get_sdk_rules,
            get_rules_content,
            save_rules_content,
            validate_rules_content,
            get_app_decisions,
            remove_app_decision,
            clear_app_decisions,
            get_active_alert,
            next_alert,
            previous_alert,
            get_engine_runtime_status,
            get_window_label,
            close_window,
            quit_app,
            get_body_changers,
            save_body_changers,
            get_owlyshield_rules_raw,
            save_owlyshield_rules_raw,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
