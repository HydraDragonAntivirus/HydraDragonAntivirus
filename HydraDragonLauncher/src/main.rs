#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};

use serde::{Deserialize, Serialize};
use tauri::Manager;

// Windows API imports
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, IsWindowVisible, ShowWindow, SW_HIDE, SW_SHOW,
};

const BASE_DIR: &str = r"C:\Program Files\HydraDragonAntivirus";
const DATA_DIR: &str = r"C:\ProgramData\HydraDragonAntivirus";
const OWLYSHIELD_REG_KEY: &str = r"HKLM\Software\Owlyshield";
const OWLYSHIELD_VERBOSE_LOGGING_VALUE: &str = "VERBOSE_LOGGING";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn hidden_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    configure_hidden_command(&mut command);
    command
}

fn configure_hidden_command(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
}

pub struct Components {
    owlyshield: Option<Child>,
    firewall: Option<Child>,
    av_engine: Option<Child>,
    python_engine: Option<Child>,
}

impl Components {
    fn new() -> Self {
        Self {
            owlyshield: None,
            firewall: None,
            av_engine: None,
            python_engine: None,
        }
    }

    fn kill_all(&mut self) {
        for (name, child) in [
            ("Owlyshield", &mut self.owlyshield),
            ("Firewall", &mut self.firewall),
            ("AV Engine", &mut self.av_engine),
            ("Python Engine", &mut self.python_engine),
        ] {
            if let Some(mut proc) = child.take() {
                info!("Stopping {}", name);
                let _ = proc.kill();
                let _ = proc.wait();
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ComponentStatus {
    name: String,
    running: bool,
    gui_visible: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LauncherSettings {
    owlyshield_verbose_logging: bool,
}

// --- Windows API Helper Functions ---

fn is_process_running(exe_name: &str) -> bool {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_err() {
            return false;
        }
        let snapshot = snapshot.unwrap();

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let file_name = {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let bytes: Vec<u8> = entry.szExeFile[..len].iter().map(|&c| c as u8).collect();
                    String::from_utf8_lossy(&bytes).into_owned()
                };

                if file_name.eq_ignore_ascii_case(exe_name) {
                    let _ = CloseHandle(snapshot);
                    return true;
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    false
}

fn set_window_visibility_by_title(title: &str, show: bool) -> Result<(), String> {
    unsafe {
        let mut title_wide: Vec<u16> = title.encode_utf16().collect();
        title_wide.push(0);

        let hwnd_res = FindWindowW(None, PCWSTR(title_wide.as_ptr()));
        let hwnd = match hwnd_res {
            Ok(h) if !h.0.is_null() => h,
            _ => {
                return Err(format!(
                    "Window '{}' not found. Is the component running?",
                    title
                ))
            }
        };

        let cmd = if show { SW_SHOW } else { SW_HIDE };
        let _ = ShowWindow(hwnd, cmd);
        Ok(())
    }
}

fn is_window_visible_by_title(title: &str) -> Option<bool> {
    unsafe {
        let mut title_wide: Vec<u16> = title.encode_utf16().collect();
        title_wide.push(0);

        let hwnd_res = FindWindowW(None, PCWSTR(title_wide.as_ptr()));
        let hwnd = match hwnd_res {
            Ok(h) if !h.0.is_null() => h,
            _ => return None,
        };

        Some(IsWindowVisible(hwnd).as_bool())
    }
}

fn read_owlyshield_verbose_logging() -> bool {
    let output = hidden_command("reg.exe")
        .args([
            "query",
            OWLYSHIELD_REG_KEY,
            "/v",
            OWLYSHIELD_VERBOSE_LOGGING_VALUE,
        ])
        .output();

    let Ok(output) = output else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.contains(OWLYSHIELD_VERBOSE_LOGGING_VALUE))
        .and_then(|line| line.split_whitespace().last())
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn write_owlyshield_verbose_logging(enabled: bool) -> Result<()> {
    let value = if enabled { "1" } else { "0" };
    let output = hidden_command("reg.exe")
        .args([
            "add",
            OWLYSHIELD_REG_KEY,
            "/v",
            OWLYSHIELD_VERBOSE_LOGGING_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            value,
            "/f",
        ])
        .output()
        .context("Failed to update Owlyshield verbose logging registry value")?;

    if output.status.success() {
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let output_text = format!("{stdout}{stderr}");
        let output_lower = output_text.to_ascii_lowercase();

        if output_lower.contains("access is denied") || output_lower.contains("access denied") {
            anyhow::bail!(
                "Access denied while updating Owlyshield verbose logging. Stop OpenEDR, then try enabling verbose logging again. reg.exe output: {}",
                output_text.trim()
            );
        }

        anyhow::bail!(
            "reg.exe failed while updating Owlyshield verbose logging: {}",
            output_text.trim()
        );
    }
}

// --- Tauri Commands ---

#[tauri::command]
async fn get_components_status() -> Result<Vec<ComponentStatus>, String> {
    let mut statuses = Vec::new();

    // Owlyshield
    statuses.push(ComponentStatus {
        name: "Owlyshield".to_string(),
        running: is_process_running("owlyshield_ransom.exe"),
        gui_visible: None,
    });

    // Firewall
    let fw_running = is_process_running("hydradragonfirewall.exe");
    statuses.push(ComponentStatus {
        name: "Firewall".to_string(),
        running: fw_running,
        gui_visible: if fw_running {
            Some(is_window_visible_by_title("HydraDragon Firewall").unwrap_or(false))
        } else {
            None
        },
    });

    // AV Engine
    statuses.push(ComponentStatus {
        name: "AV Engine".to_string(),
        running: is_process_running("HydraDragonAV.exe"),
        gui_visible: None,
    });

    // Python Engine
    statuses.push(ComponentStatus {
        name: "Python Engine".to_string(),
        running: is_process_running("python.exe"),
        gui_visible: None,
    });

    // OpenEDR
    statuses.push(ComponentStatus {
        name: "OpenEDR".to_string(),
        running: is_process_running("edrsvc.exe"),
        gui_visible: None,
    });

    // Sanctum
    let sanctum_running = is_process_running("um_engine.exe");
    statuses.push(ComponentStatus {
        name: "Sanctum".to_string(),
        running: sanctum_running,
        gui_visible: if sanctum_running {
            Some(is_window_visible_by_title("Sanctum").unwrap_or(false))
        } else {
            None
        },
    });

    Ok(statuses)
}

#[tauri::command]
async fn start_component(
    name: String,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    let mut comps = state.lock().await;
    match name.as_str() {
        "Owlyshield" => {
            if comps.owlyshield.is_none() && !is_process_running("owlyshield_ransom.exe") {
                match start_owlyshield().await {
                    Ok(child) => comps.owlyshield = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "Firewall" => {
            if comps.firewall.is_none() && !is_process_running("hydradragonfirewall.exe") {
                match start_firewall().await {
                    Ok(child) => comps.firewall = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "AV Engine" => {
            if comps.av_engine.is_none() && !is_process_running("HydraDragonAV.exe") {
                match start_av_engine().await {
                    Ok(child) => comps.av_engine = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "Python Engine" => {
            if comps.python_engine.is_none() && !is_process_running("python.exe") {
                match start_python_engine().await {
                    Ok(child) => comps.python_engine = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "OpenEDR" => {
            let _ = start_openedr().await;
        }
        "Sanctum" => {
            let _ = start_sanctum_sequence().await;
        }
        _ => return Err(format!("Unknown component: {}", name)),
    }
    Ok(())
}

#[tauri::command]
async fn stop_component(
    name: String,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    let mut comps = state.lock().await;
    match name.as_str() {
        "Owlyshield" => {
            if let Some(mut child) = comps.owlyshield.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "owlyshield_ransom.exe"])
                .output();
        }
        "Firewall" => {
            if let Some(mut child) = comps.firewall.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "hydradragonfirewall.exe"])
                .output();
        }
        "AV Engine" => {
            if let Some(mut child) = comps.av_engine.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "HydraDragonAV.exe"])
                .output();
        }
        "Python Engine" => {
            if let Some(mut child) = comps.python_engine.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "python.exe"])
                .output();
        }
        "OpenEDR" => {
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "edrsvc.exe"])
                .output();
        }
        "Sanctum" => {
            let _ = hidden_command("sc")
                .args(["stop", "sanctum_ppl_runner"])
                .output();
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "um_engine.exe"])
                .output();
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "app.exe"])
                .output();
        }
        _ => return Err(format!("Unknown component: {}", name)),
    }
    Ok(())
}

#[tauri::command]
async fn toggle_gui_visibility(component: String, show: bool) -> Result<(), String> {
    let title = match component.as_str() {
        "Firewall" => "HydraDragon Firewall",
        "Sanctum" => "Sanctum",
        _ => return Err(format!("Component {} does not have a GUI", component)),
    };

    set_window_visibility_by_title(title, show)
}

#[tauri::command]
async fn get_launcher_settings() -> Result<LauncherSettings, String> {
    Ok(LauncherSettings {
        owlyshield_verbose_logging: read_owlyshield_verbose_logging(),
    })
}

#[tauri::command]
async fn set_owlyshield_verbose_logging(
    enabled: bool,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    write_owlyshield_verbose_logging(enabled).map_err(|e| e.to_string())?;

    if is_process_running("owlyshield_ransom.exe") {
        {
            let mut comps = state.lock().await;
            if let Some(mut child) = comps.owlyshield.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = hidden_command("taskkill")
                .args(["/F", "/IM", "owlyshield_ransom.exe"])
                .output();
        }

        sleep(Duration::from_millis(500)).await;
        let restarted = start_owlyshield().await.map_err(|e| e.to_string())?;
        let mut comps = state.lock().await;
        comps.owlyshield = restarted;
    }

    Ok(())
}

#[tauri::command]
async fn start_all_components(
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    start_components(state.inner().clone())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn stop_all_components(
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    let mut comps = state.lock().await;
    comps.kill_all();
    let _ = hidden_command("taskkill")
        .args(["/F", "/IM", "edrsvc.exe"])
        .output();
    let _ = hidden_command("sc")
        .args(["stop", "sanctum_ppl_runner"])
        .output();
    let _ = hidden_command("taskkill")
        .args(["/F", "/IM", "um_engine.exe"])
        .output();
    let _ = hidden_command("taskkill")
        .args(["/F", "/IM", "app.exe"])
        .output();
    Ok(())
}

#[tauri::command]
async fn quit_launcher(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    let mut comps = state.lock().await;
    comps.kill_all();
    let _ = hidden_command("taskkill")
        .args(["/F", "/IM", "edrsvc.exe"])
        .output();
    let _ = hidden_command("sc")
        .args(["stop", "sanctum_ppl_runner"])
        .output();
    let _ = hidden_command("taskkill")
        .args(["/F", "/IM", "um_engine.exe"])
        .output();
    let _ = hidden_command("taskkill")
        .args(["/F", "/IM", "app.exe"])
        .output();
    app.exit(0);
    Ok(())
}

// --- Main Program ---

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    info!("HydraDragon Launcher starting...");

    let components = Arc::new(Mutex::new(Components::new()));
    let components_clone = components.clone();

    let args: Vec<String> = std::env::args().collect();
    let headless = args
        .iter()
        .any(|arg| arg == "--headless" || arg == "--hidden");

    tauri::Builder::default()
        .manage(components.clone())
        .setup(move |app| {
            // Auto-start all components in the background on startup
            let comps_clone = components_clone.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = start_components(comps_clone).await {
                    error!("Failed to auto-start components: {:#}", e);
                }
            });

            // Set up system tray icon
            let show_i =
                tauri::menu::MenuItem::with_id(app, "show", "Show Controller", true, None::<&str>)
                    .unwrap();
            let hide_i =
                tauri::menu::MenuItem::with_id(app, "hide", "Hide Controller", true, None::<&str>)
                    .unwrap();
            let quit_i = tauri::menu::MenuItem::with_id(
                app,
                "quit",
                "Exit & Stop All Services",
                true,
                None::<&str>,
            )
            .unwrap();
            let menu = tauri::menu::Menu::with_items(
                app,
                &[
                    &show_i,
                    &hide_i,
                    &tauri::menu::PredefinedMenuItem::separator(app).unwrap(),
                    &quit_i,
                ],
            )
            .unwrap();

            let _tray = tauri::tray::TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.hide();
                        }
                    }
                    "quit" => {
                        let state = app.state::<Arc<Mutex<Components>>>();
                        let state_clone = Arc::clone(&state);
                        let app_clone = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let mut comps = state_clone.lock().await;
                            comps.kill_all();
                            let _ = hidden_command("taskkill")
                                .args(["/F", "/IM", "edrsvc.exe"])
                                .output();
                            let _ = hidden_command("sc")
                                .args(["stop", "sanctum_ppl_runner"])
                                .output();
                            let _ = hidden_command("taskkill")
                                .args(["/F", "/IM", "um_engine.exe"])
                                .output();
                            let _ = hidden_command("taskkill")
                                .args(["/F", "/IM", "app.exe"])
                                .output();
                            app_clone.exit(0);
                        });
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
                            if win.is_visible().unwrap_or(false) {
                                let _ = win.hide();
                            } else {
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                        }
                    }
                })
                .icon(app.default_window_icon().unwrap().clone())
                .build(app)?;

            // If headless flag is NOT passed, show the window on startup
            if !headless {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                }
            } else {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_components_status,
            start_component,
            stop_component,
            toggle_gui_visibility,
            get_launcher_settings,
            set_owlyshield_verbose_logging,
            start_all_components,
            stop_all_components,
            quit_launcher,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    Ok(())
}

async fn start_components(components: Arc<Mutex<Components>>) -> Result<()> {
    info!("Starting HydraDragon components...");

    let (
        owlyshield_result,
        firewall_result,
        openedr_result,
        av_result,
        python_result,
        sanctum_result,
    ) = tokio::join!(
        start_owlyshield(),
        start_firewall(),
        start_openedr(),
        start_av_engine(),
        start_python_engine(),
        start_sanctum_sequence()
    );

    let mut comps = components.lock().await;
    if let Ok(child) = owlyshield_result {
        comps.owlyshield = child;
    }
    if let Ok(child) = firewall_result {
        comps.firewall = child;
    }
    if let Ok(child) = av_result {
        comps.av_engine = child;
    }
    if let Ok(child) = python_result {
        comps.python_engine = child;
    }
    drop(comps);

    let _ = openedr_result;
    let _ = sanctum_result;

    info!("✓ All components started successfully");
    Ok(())
}

async fn start_owlyshield() -> Result<Option<Child>> {
    info!("Starting Owlyshield Service...");
    let owlyshield_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("Owlyshield")
        .join("Owlyshield Service")
        .join("owlyshield_ransom.exe");

    match start_process(&owlyshield_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_firewall() -> Result<Option<Child>> {
    info!("Starting HydraDragon Firewall...");
    let firewall_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonFirewall")
        .join("hydradragonfirewall.exe");

    // Pass --headless so that the Firewall starts hidden/headless in background by default
    match start_process(&firewall_path, Some(&["--headless"])) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_openedr() -> Result<()> {
    info!("Starting OpenEDR...");
    let openedr_path = PathBuf::from(BASE_DIR).join("OpenEDR").join("edrsvc.exe");
    if openedr_path.exists() {
        let _ = hidden_command(openedr_path.as_os_str())
            .arg("start")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    Ok(())
}

async fn start_av_engine() -> Result<Option<Child>> {
    info!("Starting HydraDragon AV Engine...");
    let av_path = PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonAV")
        .join("HydraDragonAV.exe");

    match start_process(&av_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_python_engine() -> Result<Option<Child>> {
    info!("Starting HydraDragon Python Engine...");
    let root_dir = PathBuf::from(BASE_DIR);
    let venv_dir = root_dir.join("venv");
    let venv_scripts = venv_dir.join("Scripts");
    let venv_python = venv_scripts.join("python.exe");
    let poetry_exe = venv_scripts.join("poetry.exe");
    let activate_bat = venv_scripts.join("activate.bat");
    let pyproject = root_dir.join("pyproject.toml");

    if !venv_dir.exists() {
        warn!("Python venv not found: {}", venv_dir.display());
        return Ok(None);
    }
    if !pyproject.exists() {
        warn!("pyproject.toml not found: {}", pyproject.display());
        return Ok(None);
    }

    if venv_python.exists() {
        let mut cmd = hidden_command(venv_python.as_os_str());
        cmd.args(["-m", "poetry", "run", "hydradragon"])
            .current_dir(&root_dir);
        configure_python_command(&mut cmd, &root_dir, &venv_dir)?;
        if let Some(child) =
            spawn_python_candidate(cmd, "venv python -m poetry run hydradragon").await?
        {
            return Ok(Some(child));
        }
    } else {
        warn!("venv python.exe not found: {}", venv_python.display());
    }

    if poetry_exe.exists() {
        let mut cmd = hidden_command(poetry_exe.as_os_str());
        cmd.args(["run", "hydradragon"]).current_dir(&root_dir);
        configure_python_command(&mut cmd, &root_dir, &venv_dir)?;
        if let Some(child) = spawn_python_candidate(cmd, "venv poetry.exe run hydradragon").await? {
            return Ok(Some(child));
        }
    } else {
        warn!("venv poetry.exe not found: {}", poetry_exe.display());
    }

    if activate_bat.exists() {
        let cmd_args = format!(
            "call \"{}\" && poetry run hydradragon",
            activate_bat.display()
        );
        let mut cmd = hidden_command("cmd.exe");
        cmd.args(["/d", "/s", "/c", &cmd_args])
            .current_dir(&root_dir);
        configure_python_command(&mut cmd, &root_dir, &venv_dir)?;
        if let Some(child) =
            spawn_python_candidate(cmd, "activate.bat && poetry run hydradragon").await?
        {
            return Ok(Some(child));
        }
    }

    warn!("HydraDragon Python Engine did not stay running. Check hydradragonlauncher-python.log.");
    Ok(None)
}

fn configure_python_command(cmd: &mut Command, root_dir: &Path, venv_dir: &Path) -> Result<()> {
    configure_hidden_command(cmd);

    let scripts_dir = venv_dir.join("Scripts");
    let current_path = env::var_os("PATH").unwrap_or_default();
    let mut path_value = scripts_dir.as_os_str().to_os_string();
    if !current_path.is_empty() {
        path_value.push(";");
        path_value.push(current_path);
    }

    let (stdout_log, stderr_log) = python_engine_log_stdio()?;
    cmd.env("VIRTUAL_ENV", venv_dir)
        .env("PYTHONPATH", root_dir)
        .env("POETRY_VIRTUALENVS_CREATE", "false")
        .env("POETRY_CACHE_DIR", root_dir.join("poetry_cache"))
        .env("POETRY_CONFIG_DIR", root_dir.join("poetry_config"))
        .env("PATH", path_value)
        .stdout(stdout_log)
        .stderr(stderr_log);
    Ok(())
}

fn python_engine_log_stdio() -> Result<(Stdio, Stdio)> {
    let log_path = PathBuf::from(DATA_DIR)
        .join("hydradragon")
        .join("logs")
        .join("hydradragonlauncher-python.log");

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create launcher log directory: {}",
                parent.display()
            )
        })?;
    }

    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open launcher log: {}", log_path.display()))?;
    let stderr_log = stdout_log
        .try_clone()
        .context("Failed to clone launcher log handle")?;

    Ok((Stdio::from(stdout_log), Stdio::from(stderr_log)))
}

async fn spawn_python_candidate(mut cmd: Command, label: &str) -> Result<Option<Child>> {
    match cmd.spawn() {
        Ok(mut child) => {
            sleep(Duration::from_secs(2)).await;
            match child
                .try_wait()
                .context("Failed to query Python engine status")?
            {
                Some(status) => {
                    warn!("{} exited immediately with status: {}", label, status);
                    Ok(None)
                }
                None => {
                    info!("Python engine started via {}", label);
                    Ok(Some(child))
                }
            }
        }
        Err(e) => {
            warn!("Failed to start {}: {}", label, e);
            Ok(None)
        }
    }
}

async fn start_sanctum_sequence() -> Result<()> {
    let sanctum_dir = PathBuf::from(BASE_DIR).join("hydradragon").join("Sanctum");

    // 1. ELAM Installer
    let elam_path = sanctum_dir.join("elam_installer.exe");
    if elam_path.exists() {
        info!("  → Running ELAM installer...");
        let _ = hidden_command(elam_path.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(2)).await;
    }

    // 2. Start Sanctum PPL Runner service
    info!("  → Starting sanctum_ppl_runner service...");
    let _ = hidden_command("sc")
        .args(["start", "sanctum_ppl_runner"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    sleep(Duration::from_millis(1500)).await;

    // 3. UM Engine
    let um_path = sanctum_dir.join("um_engine.exe");
    if um_path.exists() {
        info!("  → Starting Sanctum UM Engine...");
        let _ = hidden_command(um_path.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(2)).await;
    }

    // 4. GUI App (Pass --hidden flag so it boots minimized in tray/headless)
    let app_path = sanctum_dir.join("app.exe");
    if app_path.exists() {
        info!("  → Starting Sanctum GUI...");
        let _ = hidden_command(app_path.as_os_str())
            .arg("--hidden")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

fn start_process(path: &Path, args: Option<&[&str]>) -> Result<Child> {
    if !path.exists() {
        warn!("Executable not found: {}", path.display());
        anyhow::bail!("File not found");
    }

    let mut cmd = hidden_command(path.as_os_str());
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    if let Some(args) = args {
        cmd.args(args);
    }

    if let Some(dir) = path.parent() {
        cmd.current_dir(dir);
    }

    cmd.spawn().context("Failed to spawn process")
}
