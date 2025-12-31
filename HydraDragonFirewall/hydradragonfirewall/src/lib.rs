pub mod engine;
pub mod file_magic;
pub mod http_parser;
pub mod injector;
pub mod sdk;
pub mod tls_parser;
pub mod web_filter;
pub mod windivert_api;

use crate::engine::FirewallEngine;
use std::sync::{Arc, RwLock};
use tauri::{AppHandle, Emitter, Manager, Runtime};

pub struct FirewallState(pub Arc<RwLock<FirewallEngine>>);

#[tauri::command]
async fn resolve_app_decision(
    name: String,
    decision: String,
    handle: AppHandle,
) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        engine.resolve_app_decision(name, decision);
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn get_settings<R: Runtime>(
    handle: AppHandle<R>,
) -> Result<crate::engine::FirewallSettings, String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        Ok(engine.get_settings())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn save_settings(
    settings: crate::engine::FirewallSettings,
    handle: AppHandle,
) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
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
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        Ok(engine.get_sdk_rules())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
fn get_rules_content(state: tauri::State<FirewallState>) -> String {
    let engine = state.inner().0.read().unwrap();
    engine.get_rules_raw()
}

#[tauri::command]
fn save_rules_content(content: String, state: tauri::State<FirewallState>) -> Result<(), String> {
    let engine = state.inner().0.read().unwrap();
    engine.save_rules_raw(content)
}

#[tauri::command]
fn validate_rules_content(content: String, state: tauri::State<FirewallState>) -> Result<String, String> {
    let engine = state.inner().0.read().unwrap();
    engine.validate_rules_raw(content)
}

#[tauri::command]
async fn get_app_decisions(handle: AppHandle) -> Result<std::collections::HashMap<String, crate::engine::AppDecision>, String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        Ok(engine.get_app_decisions())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn remove_app_decision(name_lower: String, handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        engine.remove_app_decision(name_lower);
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn clear_app_decisions(handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        engine.clear_app_decisions();
        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

pub fn run() {
    println!("DEBUG: hydradragonfirewall::run() entered");
    println!("--- HydraDragon Firewall Booting (Tauri 2.0) ---");

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
                    "quit" => app.exit(0),
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

            let handle = app.handle().clone();

            // Re-enabling Engine Initialization
            std::thread::Builder::new()
                .name("engine_init".to_string())
                .spawn(move || {
                    // Wait for WebView to be ready
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    // Emit startup message
                    let _ = handle.emit(
                        "log",
                        crate::engine::LogEntry {
                            id: "startup-0".to_string(),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                            level: crate::engine::LogLevel::Info,
                            message: "🚀 Starting Firewall Engine...".to_string(),
                        },
                    );

                    println!("DEBUG: FirewallEngine::new() starting...");
                    let engine = Arc::new(FirewallEngine::new());
                    println!("DEBUG: FirewallEngine::new() finished.");

                    engine.start(handle.clone());
                    handle.manage(engine);
                    println!("DEBUG: FirewallEngine managed and started.");
                })
                .expect("Failed to spawn engine_init thread");

            println!("DEBUG: setup closure finished.");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.minimize().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            resolve_app_decision,
            get_settings,
            save_settings,
            get_sdk_rules,
            get_rules_content,
            save_rules_content,
            validate_rules_content,
            get_app_decisions,
            remove_app_decision,
            clear_app_decisions
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
