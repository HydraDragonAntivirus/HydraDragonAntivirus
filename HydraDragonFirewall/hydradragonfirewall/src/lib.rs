pub mod engine;
#[cfg(target_os = "windows")]
mod ffi;
pub mod file_magic;
pub mod http_parser;
pub mod proxy;
pub mod quarantine;
pub mod sdk;
pub mod tls_parser;
pub mod web_filter;
pub mod windivert_api;

use crate::engine::{FirewallEngine, emit_log_event};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::time::{Duration, sleep};

/// A body changer rule stored in body_changers.json and reflected in rules.yaml.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BodyChangerRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub target: String, // "request" or "response"
    pub url_pattern: String,
    pub method_pattern: String,
    pub replacement: String,
}

fn body_changers_path() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from("json");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("body_changers.json")
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
    let json =
        serde_json::to_string_pretty(rules).map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Write error: {}", e))
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
    mitm_enabled: bool,
    windows_root_trust_ready: bool,
    firefox_policy_ready: bool,
    mitm_bypass_count: usize,
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
async fn get_process_inventory<R: Runtime>(
    handle: AppHandle<R>,
) -> Result<Vec<crate::engine::ProcessInventoryEntry>, String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        Ok(engine.get_process_inventory())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn generate_owlyshield_report(handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        engine.request_owlyshield_report();
        Ok(())
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
        engine.sync_proxy_runtime(&handle);
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
fn get_owlyshield_rules_dir() -> Option<std::path::PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Owlyshield")
        .ok()
        .and_then(|key| key.get_value::<String, _>("RULES_PATH").ok())
        .map(std::path::PathBuf::from)
}

#[cfg(target_os = "windows")]
fn get_owlyshield_reports_dir() -> Option<std::path::PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Owlyshield")
        .ok()
        .and_then(|key| key.get_value::<String, _>("REPORTS_PATH").ok())
        .map(std::path::PathBuf::from)
}

/// Read the Firewall SDK rules folder path from the Windows Registry.
/// Falls back to None if the key is absent or the OS is not Windows.
#[cfg(target_os = "windows")]
pub(crate) fn get_firewall_sdk_rules_path() -> Option<std::path::PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK")
        .ok()
        .and_then(|key| key.get_value::<String, _>("RULES_PATH").ok())
        .map(std::path::PathBuf::from)
}

#[derive(Clone, Debug, Serialize)]
struct OwlyshieldRulesFileEntry {
    name: String,
    path: String,
    selected: bool,
}

#[derive(Clone, Debug, Serialize)]
struct OwlyshieldRulesDirectoryView {
    directory: String,
    selected_path: Option<String>,
    files: Vec<OwlyshieldRulesFileEntry>,
}

#[derive(Clone, Debug, Serialize)]
struct OwlyshieldReportFileEntry {
    name: String,
    path: String,
    selected: bool,
    modified_ts: Option<u64>,
    size_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
struct OwlyshieldReportsDirectoryView {
    directory: String,
    selected_path: Option<String>,
    files: Vec<OwlyshieldReportFileEntry>,
}

#[derive(Clone, Debug, Serialize)]
struct FirewallQuarantineFileEntry {
    name: String,
    path: String,
    modified_ts: Option<u64>,
    size_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
struct FirewallQuarantineDirectoryView {
    directory: String,
    files: Vec<FirewallQuarantineFileEntry>,
}

#[cfg(target_os = "windows")]
fn list_owlyshield_rule_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    if dir.is_file() {
        return vec![dir.to_path_buf()];
    }

    if !dir.is_dir() {
        return Vec::new();
    }

    let mut yaml_files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yaml" | "yml")
                )
        })
        .collect();

    yaml_files.sort_by(|a, b| {
        let rank = |path: &std::path::Path| match path.file_name().and_then(|name| name.to_str()) {
            Some("owlyshield_rules.yaml") => 0,
            Some("owlyshield_rules.yml") => 1,
            Some("rules.yaml") => 2,
            Some("rules.yml") => 3,
            _ => 10,
        };

        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.file_name().cmp(&b.file_name()))
    });

    yaml_files
}

#[cfg(target_os = "windows")]
fn resolve_rules_file_from_registry_dir(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    list_owlyshield_rule_files(dir).into_iter().next()
}

#[cfg(target_os = "windows")]
fn collect_owlyshield_report_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    if dir.is_file() {
        return vec![dir.to_path_buf()];
    }

    if !dir.is_dir() {
        return Vec::new();
    }

    let mut report_files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();

    report_files.sort_by(|a, b| {
        let modified_key = |path: &std::path::Path| {
            std::fs::metadata(path)
                .ok()
                .and_then(|meta| meta.modified().ok())
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or_default()
        };

        modified_key(b)
            .cmp(&modified_key(a))
            .then_with(|| b.file_name().cmp(&a.file_name()))
    });

    report_files
}

#[tauri::command]
async fn list_owlyshield_rules_files() -> OwlyshieldRulesDirectoryView {
    let dir = {
        #[cfg(target_os = "windows")]
        {
            get_owlyshield_rules_dir().unwrap_or_else(|| std::path::PathBuf::from("rules"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::path::PathBuf::from("rules")
        }
    };

    let selected_path =
        resolve_rules_file_from_registry_dir(&dir).map(|path| path.to_string_lossy().to_string());

    let files = if dir.is_dir() {
        list_owlyshield_rule_files(&dir)
            .into_iter()
            .map(|path| {
                let path_string = path.to_string_lossy().to_string();
                OwlyshieldRulesFileEntry {
                    name: path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("rules")
                        .to_string(),
                    selected: selected_path.as_deref() == Some(path_string.as_str()),
                    path: path_string,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    // If no files found in the dir, add a virtual entry for the expected local path
    let mut files = files;
    if files.is_empty() {
        let local_path = dir.join("owlyshield_rules.yaml");
        files.push(OwlyshieldRulesFileEntry {
            name: "owlyshield_rules.yaml".to_string(),
            path: local_path.to_string_lossy().to_string(),
            selected: true,
        });
    }

    OwlyshieldRulesDirectoryView {
        directory: dir.to_string_lossy().to_string(),
        selected_path: selected_path.or_else(|| {
            Some(
                dir.join("owlyshield_rules.yaml")
                    .to_string_lossy()
                    .to_string(),
            )
        }),
        files,
    }
}

#[tauri::command]
async fn list_owlyshield_report_files() -> OwlyshieldReportsDirectoryView {
    let dir = {
        #[cfg(target_os = "windows")]
        {
            get_owlyshield_reports_dir().unwrap_or_else(|| std::path::PathBuf::from("reports"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::path::PathBuf::from("reports")
        }
    };

    let selected_path = collect_owlyshield_report_files(&dir)
        .into_iter()
        .next()
        .map(|path| path.to_string_lossy().to_string());

    let files = if dir.is_dir() {
        collect_owlyshield_report_files(&dir)
            .into_iter()
            .map(|path| {
                let metadata = std::fs::metadata(&path).ok();
                let modified_ts = metadata
                    .as_ref()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs());
                let size_bytes = metadata.map(|meta| meta.len()).unwrap_or_default();
                let path_string = path.to_string_lossy().to_string();

                OwlyshieldReportFileEntry {
                    name: path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("report")
                        .to_string(),
                    selected: selected_path.as_deref() == Some(path_string.as_str()),
                    path: path_string,
                    modified_ts,
                    size_bytes,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    OwlyshieldReportsDirectoryView {
        directory: dir.to_string_lossy().to_string(),
        selected_path,
        files,
    }
}

#[tauri::command]
async fn get_owlyshield_rules_raw(path: Option<String>) -> String {
    if let Some(p) = path {
        if let Ok(content) = std::fs::read_to_string(p) {
            return content;
        }
    }

    let dir = {
        #[cfg(target_os = "windows")]
        {
            get_owlyshield_rules_dir().unwrap_or_else(|| std::path::PathBuf::from("rules"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::path::PathBuf::from("rules")
        }
    };

    if let Some(path) = resolve_rules_file_from_registry_dir(&dir) {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return content;
        }
    }

    let local_path = dir.join("owlyshield_rules.yaml");
    std::fs::read_to_string(local_path).unwrap_or_default()
}

#[tauri::command]
async fn get_owlyshield_report_raw(path: Option<String>) -> String {
    if let Some(p) = path {
        if let Ok(content) = std::fs::read_to_string(p) {
            return content;
        }
    }

    let dir = {
        #[cfg(target_os = "windows")]
        {
            get_owlyshield_reports_dir().unwrap_or_else(|| std::path::PathBuf::from("reports"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::path::PathBuf::from("reports")
        }
    };

    if let Some(path) = collect_owlyshield_report_files(&dir).into_iter().next() {
        if let Ok(content) = std::fs::read_to_string(path) {
            return content;
        }
    }

    String::new()
}

#[tauri::command]
async fn list_firewall_quarantine_files() -> FirewallQuarantineDirectoryView {
    let dir = std::path::PathBuf::from(hydradragon_shared::QUARANTINE_PATH);
    let mut files = if dir.is_dir() {
        std::fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.filter_map(Result::ok))
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    files.sort_by(|a, b| {
        let modified_key = |path: &std::path::Path| {
            std::fs::metadata(path)
                .ok()
                .and_then(|meta| meta.modified().ok())
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or_default()
        };

        modified_key(b)
            .cmp(&modified_key(a))
            .then_with(|| b.file_name().cmp(&a.file_name()))
    });

    let entries = files
        .into_iter()
        .map(|path| {
            let metadata = std::fs::metadata(&path).ok();
            let modified_ts = metadata
                .as_ref()
                .and_then(|meta| meta.modified().ok())
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs());
            let size_bytes = metadata.map(|meta| meta.len()).unwrap_or_default();

            FirewallQuarantineFileEntry {
                name: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("quarantined_file")
                    .to_string(),
                path: path.to_string_lossy().to_string(),
                modified_ts,
                size_bytes,
            }
        })
        .collect();

    FirewallQuarantineDirectoryView {
        directory: dir.to_string_lossy().to_string(),
        files: entries,
    }
}

#[tauri::command]
async fn save_owlyshield_rules_raw(content: String, path: Option<String>) -> Result<(), String> {
    if let Some(p) = path {
        return std::fs::write(p, content).map_err(|e| e.to_string());
    }

    let dir = {
        #[cfg(target_os = "windows")]
        {
            get_owlyshield_rules_dir().unwrap_or_else(|| std::path::PathBuf::from("rules"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::path::PathBuf::from("rules")
        }
    };

    let _ = std::fs::create_dir_all(&dir);
    let local_path = dir.join("owlyshield_rules.yaml");
    std::fs::write(local_path, content).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_app_decisions(
    handle: AppHandle,
) -> Result<std::collections::HashMap<String, crate::engine::AppDecision>, String> {
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
async fn get_readme_content() -> String {
    let paths = vec![
        "C:\\Program Files\\HydraDragonAntivirus\\README.md",
        "README.md",
    ];

    for path in paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return content;
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        let mut current = exe_path.parent();
        for _ in 0..3 {
            if let Some(p) = current {
                let readme = p.join("README.md");
                if let Ok(content) = std::fs::read_to_string(readme) {
                    return content;
                }
                current = p.parent();
            } else {
                break;
            }
        }
    }

    "README.md file could not be located on this system.".to_string()
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
    if let Some(engine) = handle.try_state::<Arc<FirewallEngine>>() {
        let active = !engine.stop_signal.load(std::sync::atomic::Ordering::SeqCst);
        let status = if active {
            let settings = engine.settings.read().unwrap();
            if settings.tls_proxy.mode == hydradragon_shared::TlsInspectionMode::TlsProxy
                && settings.tls_proxy.auto_start
            {
                "Firewall Engine ACTIVE (Transparent TLS Proxy/Inspector managed)".to_string()
            } else if settings.tls_proxy.mode == hydradragon_shared::TlsInspectionMode::MetadataOnly {
                "Firewall Engine ACTIVE (metadata-only TLS visibility)".to_string()
            } else {
                "Firewall Engine ACTIVE (Transparent TLS Proxy/Inspector disabled)".to_string()
            }
        } else {
            "Firewall Engine INACTIVE".to_string()
        };

        let settings = engine.settings.read().unwrap();
        let mitm_enabled = settings.tls_proxy.mode == hydradragon_shared::TlsInspectionMode::TlsProxy
            && settings.tls_proxy.auto_start;
        let mitm_bypass_count = settings.tls_proxy.bypass_hosts.len();

        EngineRuntimeStatus {
            active,
            status,
            mitm_enabled,
            windows_root_trust_ready: engine
                .windows_root_trust_ready
                .load(std::sync::atomic::Ordering::SeqCst),
            firefox_policy_ready: engine
                .firefox_policy_ready
                .load(std::sync::atomic::Ordering::SeqCst),
            mitm_bypass_count,
        }
    } else {
        EngineRuntimeStatus {
            active: false,
            status: "Initializing Engine...".to_string(),
            mitm_enabled: false,
            windows_root_trust_ready: false,
            firefox_policy_ready: false,
            mitm_bypass_count: 0,
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
        if window.hide().is_err() {
            let _ = window.close();
        }
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

#[tauri::command]
async fn grant_cert_install_consent(handle: AppHandle) -> Result<(), String> {
    if let Some(engine) = wait_for_engine(&handle).await {
        let mut settings = engine.settings.write().unwrap();
        settings.tls_proxy.cert_install_consent = true;
        drop(settings);

        engine.save_settings();
        engine.sync_proxy_runtime(&handle);

        Ok(())
    } else {
        Err("Engine not initialized".to_string())
    }
}

#[tauri::command]
async fn install_firewall_certificate(handle: AppHandle) -> String {
    if let Some(engine) = wait_for_engine(&handle).await {
        match engine.install_firewall_certificate(&handle) {
            Ok(message) => message,
            Err(error) => format!("Certificate install failed: {error}"),
        }
    } else {
        "Certificate install failed: engine not initialized".to_string()
    }
}

#[tauri::command]
async fn remove_firewall_certificate(handle: AppHandle) -> String {
    if let Some(engine) = wait_for_engine(&handle).await {
        match engine.remove_firewall_certificate(&handle) {
            Ok(message) => message,
            Err(error) => error,
        }
    } else {
        "Certificate removal failed: engine not initialized".to_string()
    }
}

#[tauri::command]
async fn clear_firewall_proxy_settings(handle: AppHandle) -> String {
    if let Some(engine) = wait_for_engine(&handle).await {
        match engine.clear_firewall_proxy_settings(&handle) {
            Ok(message) => message,
            Err(error) => format!("Windows proxy cleanup failed: {error}"),
        }
    } else {
        "Windows proxy cleanup failed: engine not initialized".to_string()
    }
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
async fn save_body_changers(rules: Vec<BodyChangerRule>, handle: AppHandle) -> Result<(), String> {
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
        use winreg::RegKey;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        // Create SOFTWARE\Owlyshield\SDK and ensure RULES_PATH exists.
        // The registry value is treated as a directory that contains YAML rule files.
        if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Owlyshield\SDK") {
            if key.get_value::<String, _>("RULES_PATH").is_err() {
                let default_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("rules")))
                    .unwrap_or_else(|| std::path::PathBuf::from("rules"));
                let _ = key.set_value("RULES_PATH", &default_dir.to_string_lossy().to_string());
            }
        }

        // Ensure SOFTWARE\Owlyshield exists and has its own RULES_PATH directory.
        if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Owlyshield") {
            if key.get_value::<String, _>("RULES_PATH").is_err() {
                let default_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("rules")))
                    .unwrap_or_else(|| std::path::PathBuf::from("rules"));
                let _ = key.set_value("RULES_PATH", &default_dir.to_string_lossy().to_string());
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
                        if headless {
                            s.headless_mode = true;
                        }
                        if log_mode {
                            s.log_mode = true;
                        }
                        if no_alert {
                            s.no_alert_mode = true;
                        }
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
                    if window.hide().is_ok() {
                        api.prevent_close();

                        // Optional: notify the frontend/log that the app is still running.
                        emit_log_event(
                            &window.app_handle(),
                            crate::engine::LogEntry {
                                id: format!(
                                    "hide-{}",
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs()
                                ),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64,
                                level: crate::engine::LogLevel::Info,
                                message: "Firewall window hidden. Still running in system tray."
                                    .to_string(),
                            },
                        );
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            resolve_app_decision,
            get_settings,
            get_saved_logs,
            get_process_inventory,
            generate_owlyshield_report,
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
            grant_cert_install_consent,
            install_firewall_certificate,
            remove_firewall_certificate,
            clear_firewall_proxy_settings,
            get_body_changers,
            save_body_changers,
            list_owlyshield_rules_files,
            list_owlyshield_report_files,
            list_firewall_quarantine_files,
            get_owlyshield_rules_raw,
            get_owlyshield_report_raw,
            save_owlyshield_rules_raw,
            get_readme_content,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
