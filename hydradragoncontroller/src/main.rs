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
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, Thread32First, Thread32Next,
    PROCESSENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, QueryFullProcessImageNameW, ResumeThread, SuspendThread,
    TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    THREAD_SUSPEND_RESUME,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, FindWindowW, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    IsWindowVisible, ShowWindow, SW_HIDE, SW_RESTORE,
};

const BASE_DIR: &str = r"C:\Program Files\HydraDragonAntivirus";
const DATA_DIR: &str = r"C:\ProgramData\HydraDragonAntivirus";
const CLAMAV_DIR: &str = r"C:\Program Files\ClamAV";
const OWLYSHIELD_REG_KEY: &str = r"HKLM\Software\Owlyshield";
const OWLYSHIELD_VERBOSE_LOGGING_VALUE: &str = "VERBOSE_LOGGING";
const NO_EXCLUDED_WINDOW_TITLES: &[&str] = &[];
const FIREWALL_ALERT_WINDOW_TITLES: &[&str] = &["HydraDragon Firewall Alert"];
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
#[cfg(windows)]
const CREATE_NEW_CONSOLE: u32 = 0x00000010;

fn hidden_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    configure_hidden_command(&mut command);
    command
}

fn visible_console_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NEW_CONSOLE);
    }
    command
}

fn configure_hidden_command(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
}

fn owlyshield_exe_path() -> PathBuf {
    PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("Owlyshield")
        .join("Owlyshield Service")
        .join("owlyshield_ransom.exe")
}

fn firewall_exe_path() -> PathBuf {
    PathBuf::from(BASE_DIR)
        .join("hydradragon")
        .join("HydraDragonFirewall")
        .join("hydradragonfirewall.exe")
}

fn av_engine_exe_path() -> PathBuf {
    PathBuf::from(CLAMAV_DIR).join("HydraDragonAV.exe")
}

fn venv_scripts_dir() -> PathBuf {
    PathBuf::from(BASE_DIR).join("venv").join("Scripts")
}

fn python_engine_exe_paths() -> [PathBuf; 2] {
    let scripts_dir = venv_scripts_dir();
    [
        scripts_dir.join("python.exe"),
        scripts_dir.join("poetry.exe"),
    ]
}

fn openedr_exe_path() -> PathBuf {
    PathBuf::from(BASE_DIR).join("OpenEDR").join("edrsvc.exe")
}

fn sanctum_dir() -> PathBuf {
    PathBuf::from(BASE_DIR).join("hydradragon").join("Sanctum")
}

fn sanctum_um_engine_path() -> PathBuf {
    sanctum_dir().join("um_engine.exe")
}

fn sanctum_app_path() -> PathBuf {
    sanctum_dir().join("app.exe")
}

fn sanctum_ppl_runner_path() -> PathBuf {
    sanctum_dir().join("AppData").join("sanctum_ppl_runner.exe")
}

fn normalize_path_for_compare(path: impl AsRef<Path>) -> String {
    path.as_ref()
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(windows)]
fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        let image_result = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(process);

        if image_result.is_ok() {
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn is_process_running_by_exact_path(path: &Path) -> bool {
    let target = normalize_path_for_compare(path);
    if target.is_empty() {
        return false;
    }

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let Ok(snapshot) = snapshot else {
            return false;
        };

        let current_pid = std::process::id();
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0
                    && pid != current_pid
                    && process_image_path(pid)
                        .as_deref()
                        .is_some_and(|image_path| {
                            normalize_path_for_compare(Path::new(image_path)) == target
                        })
                {
                    let _ = CloseHandle(snapshot);
                    return true;
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        false
    }
}

#[cfg(not(windows))]
fn is_process_running_by_exact_path(_path: &Path) -> bool {
    false
}

fn is_process_running_by_any_exact_path(paths: &[PathBuf]) -> bool {
    paths
        .iter()
        .any(|path| is_process_running_by_exact_path(path))
}

#[cfg(windows)]
fn matching_process_ids_by_exact_path(path: &Path) -> Vec<u32> {
    let target = normalize_path_for_compare(path);
    if target.is_empty() {
        return Vec::new();
    }

    let mut pids = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let Ok(snapshot) = snapshot else {
            return pids;
        };

        let current_pid = std::process::id();
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0
                    && pid != current_pid
                    && process_image_path(pid)
                        .as_deref()
                        .is_some_and(|image_path| {
                            normalize_path_for_compare(Path::new(image_path)) == target
                        })
                {
                    pids.push(pid);
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    pids
}

#[cfg(windows)]
fn set_threads_suspended_for_pid(pid: u32, suspend: bool) -> usize {
    let mut affected = 0usize;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let Ok(snapshot) = snapshot else {
            return affected;
        };

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    if let Ok(thread) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                    {
                        let previous_count = if suspend {
                            SuspendThread(thread)
                        } else {
                            ResumeThread(thread)
                        };

                        if previous_count != u32::MAX {
                            affected += 1;
                        }

                        let _ = CloseHandle(thread);
                    }
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    affected
}

#[cfg(windows)]
fn set_processes_suspended_by_exact_path(path: &Path, suspend: bool) -> usize {
    matching_process_ids_by_exact_path(path)
        .into_iter()
        .map(|pid| set_threads_suspended_for_pid(pid, suspend))
        .sum()
}

#[cfg(not(windows))]
fn set_processes_suspended_by_exact_path(_path: &Path, _suspend: bool) -> usize {
    0
}

fn set_processes_suspended_by_exact_paths(paths: &[PathBuf], suspend: bool) -> usize {
    paths
        .iter()
        .map(|path| set_processes_suspended_by_exact_path(path, suspend))
        .sum()
}

fn component_process_paths(name: &str) -> Result<Vec<PathBuf>, String> {
    match name {
        "Owlyshield" => Ok(vec![owlyshield_exe_path()]),
        "Firewall" => Ok(vec![firewall_exe_path()]),
        "AV Engine" => Ok(vec![av_engine_exe_path()]),
        "Python Engine" => Ok(python_engine_exe_paths().to_vec()),
        "OpenEDR" => Ok(vec![openedr_exe_path()]),
        "Sanctum" => Ok(vec![
            sanctum_ppl_runner_path(),
            sanctum_um_engine_path(),
            sanctum_app_path(),
        ]),
        _ => Err(format!("Unknown component: {}", name)),
    }
}

fn all_component_process_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        owlyshield_exe_path(),
        firewall_exe_path(),
        openedr_exe_path(),
        av_engine_exe_path(),
        sanctum_ppl_runner_path(),
        sanctum_um_engine_path(),
        sanctum_app_path(),
    ];
    paths.extend(python_engine_exe_paths());
    paths
}

fn set_component_suspended(component: &str, suspend: bool) -> Result<usize, String> {
    let paths = component_process_paths(component)?;
    Ok(set_processes_suspended_by_exact_paths(&paths, suspend))
}

fn set_all_components_suspended(suspend: bool) -> usize {
    set_processes_suspended_by_exact_paths(&all_component_process_paths(), suspend)
}

#[cfg(windows)]
fn terminate_processes_by_exact_path(path: &Path) -> usize {
    let target = normalize_path_for_compare(path);
    if target.is_empty() {
        return 0;
    }

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let Ok(snapshot) = snapshot else {
            return 0;
        };

        let mut terminated = 0usize;
        let current_pid = std::process::id();
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0 && pid != current_pid {
                    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
                    if let Ok(process) = OpenProcess(access, false, pid) {
                        let mut buffer = vec![0u16; 32768];
                        let mut size = buffer.len() as u32;
                        let image_result = QueryFullProcessImageNameW(
                            process,
                            PROCESS_NAME_WIN32,
                            PWSTR(buffer.as_mut_ptr()),
                            &mut size,
                        );

                        if image_result.is_ok() {
                            let image_path = String::from_utf16_lossy(&buffer[..size as usize]);
                            if normalize_path_for_compare(Path::new(&image_path)) == target
                                && TerminateProcess(process, 1).is_ok()
                            {
                                terminated += 1;
                            }
                        }

                        let _ = CloseHandle(process);
                    }
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        terminated
    }
}

#[cfg(not(windows))]
fn terminate_processes_by_exact_path(_path: &Path) -> usize {
    0
}

fn terminate_processes_by_exact_paths(paths: &[PathBuf]) {
    for path in paths {
        let count = terminate_processes_by_exact_path(path);
        if count > 0 {
            info!("Terminated {} process(es) at {}", count, path.display());
        }
    }
}

fn terminate_sanctum_processes() {
    terminate_processes_by_exact_paths(&[
        sanctum_ppl_runner_path(),
        sanctum_um_engine_path(),
        sanctum_app_path(),
    ]);
}

fn stop_sanctum_ppl_runner_service() {
    let _ = hidden_command("sc")
        .args(["stop", "sanctum_ppl_runner"])
        .output();
}

fn stop_openedr_service() {
    let openedr_path = openedr_exe_path();
    if openedr_path.exists() {
        let _ = hidden_command(openedr_path.as_os_str())
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
    }
}

fn stop_openedr() {
    stop_openedr_service();
    terminate_processes_by_exact_path(&openedr_exe_path());
}

fn terminate_controller_started_processes() {
    let paths = all_component_process_paths();
    terminate_processes_by_exact_paths(&paths);
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
pub struct ControllerSettings {
    owlyshield_verbose_logging: bool,
}

// Backward-compatible alias for older frontend builds that still use launcher naming.
type LauncherSettings = ControllerSettings;

// --- Windows API Helper Functions ---

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

        let cmd = if show { SW_RESTORE } else { SW_HIDE };
        let _ = ShowWindow(hwnd, cmd);
        Ok(())
    }
}

#[cfg(windows)]
fn window_title(hwnd: HWND) -> String {
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return String::new();
        }

        let mut buffer = vec![0u16; len as usize + 1];
        let copied = GetWindowTextW(hwnd, &mut buffer);
        if copied <= 0 {
            String::new()
        } else {
            String::from_utf16_lossy(&buffer[..copied as usize])
        }
    }
}

#[cfg(windows)]
struct ProcessWindowAction {
    target_path: String,
    show: Option<bool>,
    matched: usize,
    visible: bool,
    excluded_titles: &'static [&'static str],
}

#[cfg(windows)]
unsafe extern "system" fn enum_process_windows(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let action = &mut *(lparam.0 as *mut ProcessWindowAction);
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));

    if pid != 0
        && process_image_path(pid)
            .as_deref()
            .is_some_and(|image_path| {
                normalize_path_for_compare(Path::new(image_path)) == action.target_path
            })
    {
        let title = window_title(hwnd);
        if action
            .excluded_titles
            .iter()
            .any(|excluded| title.eq_ignore_ascii_case(excluded))
        {
            return BOOL(1);
        }

        action.matched += 1;

        if let Some(show) = action.show {
            let cmd = if show { SW_RESTORE } else { SW_HIDE };
            let _ = ShowWindow(hwnd, cmd);
        }

        if IsWindowVisible(hwnd).as_bool() {
            action.visible = true;
        }
    }

    BOOL(1)
}

#[cfg(windows)]
fn visit_process_windows(
    path: &Path,
    show: Option<bool>,
    excluded_titles: &'static [&'static str],
) -> ProcessWindowAction {
    let mut action = ProcessWindowAction {
        target_path: normalize_path_for_compare(path),
        show,
        matched: 0,
        visible: false,
        excluded_titles,
    };

    if !action.target_path.is_empty() {
        unsafe {
            let _ = EnumWindows(
                Some(enum_process_windows),
                LPARAM(&mut action as *mut ProcessWindowAction as isize),
            );
        }
    }

    action
}

#[cfg(windows)]
fn set_window_visibility_by_process_path(
    path: &Path,
    show: bool,
    excluded_titles: &'static [&'static str],
) -> usize {
    visit_process_windows(path, Some(show), excluded_titles).matched
}

#[cfg(not(windows))]
fn set_window_visibility_by_process_path(
    _path: &Path,
    _show: bool,
    _excluded_titles: &'static [&'static str],
) -> usize {
    0
}

#[cfg(windows)]
fn is_window_visible_by_process_path(
    path: &Path,
    excluded_titles: &'static [&'static str],
) -> Option<bool> {
    let action = visit_process_windows(path, None, excluded_titles);
    (action.matched > 0).then_some(action.visible)
}

#[cfg(not(windows))]
fn is_window_visible_by_process_path(
    _path: &Path,
    _excluded_titles: &'static [&'static str],
) -> Option<bool> {
    None
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

fn gui_window_visible(
    title: &str,
    path: &Path,
    excluded_titles: &'static [&'static str],
) -> Option<bool> {
    match (
        is_window_visible_by_title(title),
        is_window_visible_by_process_path(path, excluded_titles),
    ) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        _ => None,
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
    let owlyshield_path = owlyshield_exe_path();
    let owlyshield_running = is_process_running_by_exact_path(&owlyshield_path);
    statuses.push(ComponentStatus {
        name: "Owlyshield".to_string(),
        running: owlyshield_running,
        gui_visible: if owlyshield_running {
            Some(false)
        } else {
            None
        },
    });

    // Firewall
    let firewall_path = firewall_exe_path();
    let fw_running = is_process_running_by_exact_path(&firewall_path);
    statuses.push(ComponentStatus {
        name: "Firewall".to_string(),
        running: fw_running,
        gui_visible: if fw_running {
            Some(
                gui_window_visible(
                    "HydraDragon Firewall",
                    &firewall_path,
                    FIREWALL_ALERT_WINDOW_TITLES,
                )
                .unwrap_or(false),
            )
        } else {
            None
        },
    });

    // AV Engine
    let av_engine_path = av_engine_exe_path();
    let av_engine_running = is_process_running_by_exact_path(&av_engine_path);
    statuses.push(ComponentStatus {
        name: "AV Engine".to_string(),
        running: av_engine_running,
        gui_visible: if av_engine_running { Some(false) } else { None },
    });

    // Python Engine
    let python_engine_paths = python_engine_exe_paths();
    let python_engine_running = is_process_running_by_any_exact_path(&python_engine_paths);
    statuses.push(ComponentStatus {
        name: "Python Engine".to_string(),
        running: python_engine_running,
        gui_visible: if python_engine_running {
            Some(false)
        } else {
            None
        },
    });

    // OpenEDR
    let openedr_path = openedr_exe_path();
    statuses.push(ComponentStatus {
        name: "OpenEDR".to_string(),
        running: is_process_running_by_exact_path(&openedr_path),
        gui_visible: None,
    });

    // Sanctum
    let sanctum_paths = [
        sanctum_ppl_runner_path(),
        sanctum_um_engine_path(),
        sanctum_app_path(),
    ];
    let sanctum_app = sanctum_app_path();
    let sanctum_running = is_process_running_by_any_exact_path(&sanctum_paths);
    statuses.push(ComponentStatus {
        name: "Sanctum".to_string(),
        running: sanctum_running,
        gui_visible: if sanctum_running {
            Some(
                gui_window_visible("Sanctum", &sanctum_app, NO_EXCLUDED_WINDOW_TITLES)
                    .unwrap_or(false),
            )
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
            if comps.owlyshield.is_none()
                && !is_process_running_by_exact_path(&owlyshield_exe_path())
            {
                match start_owlyshield().await {
                    Ok(child) => comps.owlyshield = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "Firewall" => {
            if comps.firewall.is_none() && !is_process_running_by_exact_path(&firewall_exe_path()) {
                match start_firewall().await {
                    Ok(child) => comps.firewall = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "AV Engine" => {
            if comps.av_engine.is_none() && !is_process_running_by_exact_path(&av_engine_exe_path())
            {
                match start_av_engine().await {
                    Ok(child) => comps.av_engine = child,
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        "Python Engine" => {
            if comps.python_engine.is_none()
                && !is_process_running_by_any_exact_path(&python_engine_exe_paths())
            {
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
            terminate_processes_by_exact_path(&owlyshield_exe_path());
        }
        "Firewall" => {
            if let Some(mut child) = comps.firewall.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            terminate_processes_by_exact_path(&firewall_exe_path());
        }
        "AV Engine" => {
            if let Some(mut child) = comps.av_engine.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            terminate_processes_by_exact_path(&av_engine_exe_path());
        }
        "Python Engine" => {
            if let Some(mut child) = comps.python_engine.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            terminate_processes_by_exact_paths(&python_engine_exe_paths());
        }
        "OpenEDR" => {
            stop_openedr();
        }
        "Sanctum" => {
            stop_sanctum_ppl_runner_service();
            terminate_sanctum_processes();
        }
        _ => return Err(format!("Unknown component: {}", name)),
    }
    Ok(())
}

#[tauri::command]
async fn toggle_gui_visibility(
    component: String,
    show: bool,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    set_component_gui_visibility(&component, show, state.inner().clone()).await
}

async fn set_component_gui_visibility(
    component: &str,
    show: bool,
    state: Arc<Mutex<Components>>,
) -> Result<(), String> {
    let (title, process_path, excluded_titles) = match component {
        "Firewall" => (
            "HydraDragon Firewall",
            firewall_exe_path(),
            FIREWALL_ALERT_WINDOW_TITLES,
        ),
        "Sanctum" => ("Sanctum", sanctum_app_path(), NO_EXCLUDED_WINDOW_TITLES),
        _ => {
            return set_non_gui_component_console_visibility(component, show, state).await;
        }
    };

    if set_window_visibility_by_title(title, show).is_ok()
        || set_window_visibility_by_process_path(&process_path, show, excluded_titles) > 0
    {
        return Ok(());
    }

    if show && component == "Firewall" && !is_process_running_by_exact_path(&process_path) {
        let mut comps = state.lock().await;
        comps.firewall = start_firewall_visible().await.map_err(|e| e.to_string())?;
        return Ok(());
    }

    if show && component == "Sanctum" && !is_process_running_by_exact_path(&process_path) {
        start_sanctum_gui_visible()
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    Err(format!(
        "Window '{}' not found for {}. The process may be running without a GUI window.",
        title,
        process_path.display()
    ))
}

async fn set_non_gui_component_console_visibility(
    component: &str,
    show: bool,
    state: Arc<Mutex<Components>>,
) -> Result<(), String> {
    match component {
        "Owlyshield" => {
            {
                let mut comps = state.lock().await;
                if let Some(mut child) = comps.owlyshield.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            terminate_processes_by_exact_path(&owlyshield_exe_path());
            sleep(Duration::from_millis(300)).await;

            let restarted = if show {
                start_owlyshield_visible().await
            } else {
                start_owlyshield().await
            }
            .map_err(|e| e.to_string())?;

            let mut comps = state.lock().await;
            comps.owlyshield = restarted;
            Ok(())
        }
        "AV Engine" => {
            {
                let mut comps = state.lock().await;
                if let Some(mut child) = comps.av_engine.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            terminate_processes_by_exact_path(&av_engine_exe_path());
            sleep(Duration::from_millis(300)).await;

            let restarted = if show {
                start_av_engine_visible().await
            } else {
                start_av_engine().await
            }
            .map_err(|e| e.to_string())?;

            let mut comps = state.lock().await;
            comps.av_engine = restarted;
            Ok(())
        }
        "Python Engine" => {
            {
                let mut comps = state.lock().await;
                if let Some(mut child) = comps.python_engine.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            terminate_processes_by_exact_paths(&python_engine_exe_paths());
            sleep(Duration::from_millis(300)).await;

            let restarted = if show {
                start_python_engine_visible().await
            } else {
                start_python_engine().await
            }
            .map_err(|e| e.to_string())?;

            let mut comps = state.lock().await;
            comps.python_engine = restarted;
            Ok(())
        }
        "OpenEDR" => Err(
            "OpenEDR is controlled as a service, so it cannot be shown as a console window."
                .to_string(),
        ),
        _ => Err(format!(
            "Component {} does not have a GUI/console view",
            component
        )),
    }
}

#[tauri::command]
async fn suspend_component(name: String) -> Result<usize, String> {
    let affected = set_component_suspended(&name, true)?;
    if affected == 0 {
        warn!(
            "Suspend requested for {}, but no threads were suspended.",
            name
        );
    } else {
        info!("Suspended {} thread(s) for {}", affected, name);
    }
    Ok(affected)
}

#[tauri::command]
async fn resume_component(name: String) -> Result<usize, String> {
    let affected = set_component_suspended(&name, false)?;
    if affected == 0 {
        warn!(
            "Resume requested for {}, but no threads were resumed.",
            name
        );
    } else {
        info!("Resumed {} thread(s) for {}", affected, name);
    }
    Ok(affected)
}

#[tauri::command]
async fn suspend_all_components() -> Result<usize, String> {
    let affected = set_all_components_suspended(true);
    if affected == 0 {
        warn!("Suspend all requested, but no component threads were suspended.");
    } else {
        info!("Suspended {} component thread(s).", affected);
    }
    Ok(affected)
}

#[tauri::command]
async fn resume_all_components() -> Result<usize, String> {
    let affected = set_all_components_suspended(false);
    if affected == 0 {
        warn!("Resume all requested, but no component threads were resumed.");
    } else {
        info!("Resumed {} component thread(s).", affected);
    }
    Ok(affected)
}

#[tauri::command]
async fn get_controller_settings() -> Result<ControllerSettings, String> {
    Ok(ControllerSettings {
        owlyshield_verbose_logging: read_owlyshield_verbose_logging(),
    })
}

#[tauri::command]
async fn get_launcher_settings() -> Result<LauncherSettings, String> {
    get_controller_settings().await
}

#[tauri::command]
async fn set_owlyshield_verbose_logging(
    enabled: bool,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    write_owlyshield_verbose_logging(enabled).map_err(|e| e.to_string())?;

    if is_process_running_by_exact_path(&owlyshield_exe_path()) {
        {
            let mut comps = state.lock().await;
            if let Some(mut child) = comps.owlyshield.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            terminate_processes_by_exact_path(&owlyshield_exe_path());
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
    stop_openedr_service();
    stop_sanctum_ppl_runner_service();
    terminate_controller_started_processes();
    Ok(())
}

#[tauri::command]
async fn quit_controller(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    let mut comps = state.lock().await;
    comps.kill_all();
    stop_openedr_service();
    stop_sanctum_ppl_runner_service();
    terminate_controller_started_processes();
    app.exit(0);
    Ok(())
}

#[tauri::command]
async fn quit_launcher(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<Mutex<Components>>>,
) -> Result<(), String> {
    quit_controller(app, state).await
}

// --- Main Program ---

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    info!("HydraDragon Controller starting...");

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
            let show_firewall_i = tauri::menu::MenuItem::with_id(
                app,
                "show_firewall",
                "Show Firewall GUI",
                true,
                None::<&str>,
            )
            .unwrap();
            let hide_firewall_i = tauri::menu::MenuItem::with_id(
                app,
                "hide_firewall",
                "Hide Firewall GUI",
                true,
                None::<&str>,
            )
            .unwrap();
            let show_sanctum_i = tauri::menu::MenuItem::with_id(
                app,
                "show_sanctum",
                "Show Sanctum GUI",
                true,
                None::<&str>,
            )
            .unwrap();
            let hide_sanctum_i = tauri::menu::MenuItem::with_id(
                app,
                "hide_sanctum",
                "Hide Sanctum GUI",
                true,
                None::<&str>,
            )
            .unwrap();
            let show_owlyshield_console_i = tauri::menu::MenuItem::with_id(
                app,
                "show_owlyshield_console",
                "Show Owlyshield Terminal",
                true,
                None::<&str>,
            )
            .unwrap();
            let hide_owlyshield_console_i = tauri::menu::MenuItem::with_id(
                app,
                "hide_owlyshield_console",
                "Hide Owlyshield Terminal",
                true,
                None::<&str>,
            )
            .unwrap();
            let show_av_console_i = tauri::menu::MenuItem::with_id(
                app,
                "show_av_console",
                "Show AV Engine Console",
                true,
                None::<&str>,
            )
            .unwrap();
            let hide_av_console_i = tauri::menu::MenuItem::with_id(
                app,
                "hide_av_console",
                "Hide AV Engine Console",
                true,
                None::<&str>,
            )
            .unwrap();
            let show_python_console_i = tauri::menu::MenuItem::with_id(
                app,
                "show_python_console",
                "Show Python Engine Console",
                true,
                None::<&str>,
            )
            .unwrap();
            let hide_python_console_i = tauri::menu::MenuItem::with_id(
                app,
                "hide_python_console",
                "Hide Python Engine Console",
                true,
                None::<&str>,
            )
            .unwrap();
            let toggle_owlyshield_i = tauri::menu::MenuItem::with_id(
                app,
                "toggle_owlyshield",
                "Suspend Owlyshield",
                true,
                None::<&str>,
            )
            .unwrap();
            let toggle_av_i = tauri::menu::MenuItem::with_id(
                app,
                "toggle_av",
                "Suspend AV Engine",
                true,
                None::<&str>,
            )
            .unwrap();
            let toggle_python_i = tauri::menu::MenuItem::with_id(
                app,
                "toggle_python",
                "Suspend Python Engine",
                true,
                None::<&str>,
            )
            .unwrap();
            let toggle_openedr_i = tauri::menu::MenuItem::with_id(
                app,
                "toggle_openedr",
                "Suspend OpenEDR",
                true,
                None::<&str>,
            )
            .unwrap();
            let toggle_sanctum_i = tauri::menu::MenuItem::with_id(
                app,
                "toggle_sanctum",
                "Suspend Sanctum",
                true,
                None::<&str>,
            )
            .unwrap();
            let toggle_firewall_i = tauri::menu::MenuItem::with_id(
                app,
                "toggle_firewall",
                "Suspend Firewall",
                true,
                None::<&str>,
            )
            .unwrap();
            let suspend_all_i = tauri::menu::MenuItem::with_id(
                app,
                "suspend_all",
                "Suspend All Components",
                true,
                None::<&str>,
            )
            .unwrap();
            let resume_all_i = tauri::menu::MenuItem::with_id(
                app,
                "resume_all",
                "Resume All Components",
                true,
                None::<&str>,
            )
            .unwrap();
            let quit_i = tauri::menu::MenuItem::with_id(
                app,
                "quit",
                "Exit & Stop All Services",
                true,
                None::<&str>,
            )
            .unwrap();
            let controller_separator = tauri::menu::PredefinedMenuItem::separator(app).unwrap();
            let gui_separator = tauri::menu::PredefinedMenuItem::separator(app).unwrap();
            let console_separator = tauri::menu::PredefinedMenuItem::separator(app).unwrap();
            let suspend_separator = tauri::menu::PredefinedMenuItem::separator(app).unwrap();
            let components_separator = tauri::menu::PredefinedMenuItem::separator(app).unwrap();
            let menu = tauri::menu::Menu::with_items(
                app,
                &[
                    &show_i,
                    &hide_i,
                    &controller_separator,
                    &show_firewall_i,
                    &hide_firewall_i,
                    &show_sanctum_i,
                    &hide_sanctum_i,
                    &gui_separator,
                    &show_owlyshield_console_i,
                    &hide_owlyshield_console_i,
                    &show_av_console_i,
                    &hide_av_console_i,
                    &show_python_console_i,
                    &hide_python_console_i,
                    &console_separator,
                    &toggle_owlyshield_i,
                    &toggle_av_i,
                    &toggle_python_i,
                    &toggle_openedr_i,
                    &toggle_sanctum_i,
                    &toggle_firewall_i,
                    &suspend_separator,
                    &suspend_all_i,
                    &resume_all_i,
                    &components_separator,
                    &quit_i,
                ],
            )
            .unwrap();

            let _tray = tauri::tray::TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event({
                    let t_owlyshield = toggle_owlyshield_i.clone();
                    let t_av = toggle_av_i.clone();
                    let t_python = toggle_python_i.clone();
                    let t_openedr = toggle_openedr_i.clone();
                    let t_sanctum = toggle_sanctum_i.clone();
                    let t_firewall = toggle_firewall_i.clone();
                    move |app, event| match event.id.as_ref() {
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
                    "show_firewall" | "hide_firewall" | "show_sanctum" | "hide_sanctum" => {
                        let (component, show) = match event.id.as_ref() {
                            "show_firewall" => ("Firewall", true),
                            "hide_firewall" => ("Firewall", false),
                            "show_sanctum" => ("Sanctum", true),
                            "hide_sanctum" => ("Sanctum", false),
                            _ => unreachable!(),
                        };
                        let state = app.state::<Arc<Mutex<Components>>>();
                        let state_clone = Arc::clone(&state);
                        tauri::async_runtime::spawn(async move {
                            if let Err(e) =
                                set_component_gui_visibility(component, show, state_clone).await
                            {
                                let action = if show { "show" } else { "hide" };
                                warn!("Failed to {} {} GUI from tray: {}", action, component, e);
                            }
                        });
                    }
                    "show_owlyshield_console"
                    | "hide_owlyshield_console"
                    | "show_av_console"
                    | "hide_av_console"
                    | "show_python_console"
                    | "hide_python_console" => {
                        let (component, show) = match event.id.as_ref() {
                            "show_owlyshield_console" => ("Owlyshield", true),
                            "hide_owlyshield_console" => ("Owlyshield", false),
                            "show_av_console" => ("AV Engine", true),
                            "hide_av_console" => ("AV Engine", false),
                            "show_python_console" => ("Python Engine", true),
                            "hide_python_console" => ("Python Engine", false),
                            _ => unreachable!(),
                        };
                        let state = app.state::<Arc<Mutex<Components>>>();
                        let state_clone = Arc::clone(&state);
                        tauri::async_runtime::spawn(async move {
                            if let Err(e) =
                                set_component_gui_visibility(component, show, state_clone).await
                            {
                                let action = if show { "show" } else { "hide" };
                                warn!(
                                    "Failed to {} {} console from tray: {}",
                                    action, component, e
                                );
                            }
                        });
                    }
                    "toggle_owlyshield" | "toggle_av" | "toggle_python"
                    | "toggle_openedr" | "toggle_sanctum" | "toggle_firewall" => {
                        let (menu_item, comp_name) = match event.id.as_ref() {
                            "toggle_owlyshield" => (&t_owlyshield, "Owlyshield"),
                            "toggle_av" => (&t_av, "AV Engine"),
                            "toggle_python" => (&t_python, "Python Engine"),
                            "toggle_openedr" => (&t_openedr, "OpenEDR"),
                            "toggle_sanctum" => (&t_sanctum, "Sanctum"),
                            "toggle_firewall" => (&t_firewall, "Firewall"),
                            _ => unreachable!(),
                        };
                        let text = menu_item.text().unwrap_or_default();
                        let suspend = text.contains("Suspend");
                        let new_text = if suspend {
                            format!("Resume {}", comp_name)
                        } else {
                            format!("Suspend {}", comp_name)
                        };
                        let _ = menu_item.set_text(new_text);
                        let comp_name_string = comp_name.to_string();
                        tauri::async_runtime::spawn(async move {
                            match set_component_suspended(&comp_name_string, suspend) {
                                Ok(affected) => {
                                    info!("Tray action toggled {} suspended={} affected {} thread(s).", comp_name_string, suspend, affected);
                                }
                                Err(e) => warn!("Tray action toggle {} failed: {}", comp_name_string, e),
                            }
                        });
                    }
                    "suspend_all" | "resume_all" => {
                        let suspend = event.id.as_ref() == "suspend_all";
                        tauri::async_runtime::spawn(async move {
                            let affected = set_all_components_suspended(suspend);
                            info!("Tray action suspend_all={} affected {} component thread(s).", suspend, affected);
                        });
                        let _ = t_owlyshield.set_text(if suspend { "Resume Owlyshield" } else { "Suspend Owlyshield" });
                        let _ = t_av.set_text(if suspend { "Resume AV Engine" } else { "Suspend AV Engine" });
                        let _ = t_python.set_text(if suspend { "Resume Python Engine" } else { "Suspend Python Engine" });
                        let _ = t_openedr.set_text(if suspend { "Resume OpenEDR" } else { "Suspend OpenEDR" });
                        let _ = t_sanctum.set_text(if suspend { "Resume Sanctum" } else { "Suspend Sanctum" });
                        let _ = t_firewall.set_text(if suspend { "Resume Firewall" } else { "Suspend Firewall" });
                    }
                    "quit" => {
                        let state = app.state::<Arc<Mutex<Components>>>();
                        let state_clone = Arc::clone(&state);
                        let app_clone = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let mut comps = state_clone.lock().await;
                            comps.kill_all();
                            stop_openedr_service();
                            stop_sanctum_ppl_runner_service();
                            terminate_controller_started_processes();
                            app_clone.exit(0);
                        });
                    }
                    _ => {}
                    }
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
            get_controller_settings,
            start_component,
            stop_component,
            toggle_gui_visibility,
            suspend_component,
            resume_component,
            suspend_all_components,
            resume_all_components,
            get_launcher_settings,
            set_owlyshield_verbose_logging,
            start_all_components,
            stop_all_components,
            quit_controller,
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
    let owlyshield_path = owlyshield_exe_path();

    match start_process(&owlyshield_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_owlyshield_visible() -> Result<Option<Child>> {
    info!("Starting Owlyshield Service with visible console...");
    let owlyshield_path = owlyshield_exe_path();

    match start_process_visible_console(&owlyshield_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_firewall() -> Result<Option<Child>> {
    info!("Starting HydraDragon Firewall...");
    let firewall_path = firewall_exe_path();

    // Pass --headless so that the Firewall starts hidden/headless in background by default
    match start_process(&firewall_path, Some(&["--headless"])) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_firewall_visible() -> Result<Option<Child>> {
    info!("Starting HydraDragon Firewall GUI...");
    let firewall_path = firewall_exe_path();

    start_process(&firewall_path, None).map(Some)
}

async fn start_openedr() -> Result<()> {
    info!("Starting OpenEDR...");
    let openedr_path = openedr_exe_path();
    if !openedr_path.exists() {
        warn!("[OpenEDR] edrsvc.exe not found at {}", openedr_path.display());
        return Ok(());
    }

    match hidden_command(openedr_path.as_os_str())
        .arg("start")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            // Collect output in background so it doesn't block startup
            tauri::async_runtime::spawn(async move {
                match child.wait_with_output() {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        for line in stdout.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                if trimmed.contains("[ERR]") || trimmed.contains("Error") || trimmed.contains("Exception") {
                                    error!("[OpenEDR] {}", trimmed);
                                } else {
                                    info!("[OpenEDR] {}", trimmed);
                                }
                            }
                        }
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        for line in stderr.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                warn!("[OpenEDR stderr] {}", trimmed);
                            }
                        }
                        if !out.status.success() {
                            error!(
                                "[OpenEDR] edrsvc start exited with code {:?}",
                                out.status.code()
                            );
                        }
                    }
                    Err(e) => {
                        error!("[OpenEDR] Failed to collect edrsvc output: {}", e);
                    }
                }
            });
        }
        Err(e) => {
            error!("[OpenEDR] Failed to spawn edrsvc start: {}", e);
        }
    }

    Ok(())
}

async fn start_av_engine() -> Result<Option<Child>> {
    info!("Starting HydraDragon AV Engine...");
    let av_path = av_engine_exe_path();

    match start_process(&av_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_av_engine_visible() -> Result<Option<Child>> {
    info!("Starting HydraDragon AV Engine with visible console...");
    let av_path = av_engine_exe_path();

    match start_process_visible_console(&av_path, None) {
        Ok(child) => Ok(Some(child)),
        Err(_) => Ok(None),
    }
}

async fn start_python_engine() -> Result<Option<Child>> {
    info!("Starting HydraDragon Python Engine...");
    let root_dir = PathBuf::from(BASE_DIR);
    let venv_dir = root_dir.join("venv");
    let venv_scripts = venv_scripts_dir();
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

    warn!(
        "HydraDragon Python Engine did not stay running. Check hydradragoncontroller-python.log."
    );
    Ok(None)
}

async fn start_python_engine_visible() -> Result<Option<Child>> {
    info!("Starting HydraDragon Python Engine with visible console...");
    let root_dir = PathBuf::from(BASE_DIR);
    let venv_dir = root_dir.join("venv");
    let venv_scripts = venv_scripts_dir();
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
        let mut cmd = visible_console_command(venv_python.as_os_str());
        cmd.args(["-m", "poetry", "run", "hydradragon"])
            .current_dir(&root_dir);
        configure_python_environment(&mut cmd, &root_dir, &venv_dir);
        if let Some(child) =
            spawn_python_candidate(cmd, "visible venv python -m poetry run hydradragon").await?
        {
            return Ok(Some(child));
        }
    } else {
        warn!("venv python.exe not found: {}", venv_python.display());
    }

    if poetry_exe.exists() {
        let mut cmd = visible_console_command(poetry_exe.as_os_str());
        cmd.args(["run", "hydradragon"]).current_dir(&root_dir);
        configure_python_environment(&mut cmd, &root_dir, &venv_dir);
        if let Some(child) =
            spawn_python_candidate(cmd, "visible venv poetry.exe run hydradragon").await?
        {
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
        let mut cmd = visible_console_command("cmd.exe");
        cmd.args(["/d", "/s", "/c", &cmd_args])
            .current_dir(&root_dir);
        configure_python_environment(&mut cmd, &root_dir, &venv_dir);
        if let Some(child) =
            spawn_python_candidate(cmd, "visible activate.bat && poetry run hydradragon").await?
        {
            return Ok(Some(child));
        }
    }

    warn!("Visible HydraDragon Python Engine did not stay running.");
    Ok(None)
}

fn configure_python_environment(cmd: &mut Command, root_dir: &Path, venv_dir: &Path) {
    let scripts_dir = venv_dir.join("Scripts");
    let current_path = env::var_os("PATH").unwrap_or_default();
    let mut path_value = scripts_dir.as_os_str().to_os_string();
    if !current_path.is_empty() {
        path_value.push(";");
        path_value.push(current_path);
    }

    cmd.env("VIRTUAL_ENV", venv_dir)
        .env("PYTHONPATH", root_dir)
        .env("POETRY_VIRTUALENVS_CREATE", "false")
        .env("POETRY_CACHE_DIR", root_dir.join("poetry_cache"))
        .env("POETRY_CONFIG_DIR", root_dir.join("poetry_config"))
        .env("PATH", path_value);
}

fn configure_python_command(cmd: &mut Command, root_dir: &Path, venv_dir: &Path) -> Result<()> {
    configure_hidden_command(cmd);
    configure_python_environment(cmd, root_dir, venv_dir);

    let (stdout_log, stderr_log) = python_engine_log_stdio()?;
    cmd.stdout(stdout_log).stderr(stderr_log);
    Ok(())
}

fn python_engine_log_stdio() -> Result<(Stdio, Stdio)> {
    let log_path = PathBuf::from(DATA_DIR)
        .join("hydradragon")
        .join("logs")
        .join("hydradragoncontroller-python.log");

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create controller log directory: {}",
                parent.display()
            )
        })?;
    }

    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open controller log: {}", log_path.display()))?;
    let stderr_log = stdout_log
        .try_clone()
        .context("Failed to clone controller log handle")?;

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
    let sanctum_dir = sanctum_dir();

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
    let um_path = sanctum_um_engine_path();
    if um_path.exists() {
        info!("  → Starting Sanctum UM Engine...");
        let _ = hidden_command(um_path.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        sleep(Duration::from_secs(2)).await;
    }

    // 4. GUI App (Pass --hidden flag so it boots minimized in tray/headless)
    let app_path = sanctum_app_path();
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

async fn start_sanctum_gui_visible() -> Result<()> {
    let app_path = sanctum_app_path();
    if !app_path.exists() {
        warn!("Sanctum GUI not found: {}", app_path.display());
        anyhow::bail!("Sanctum GUI not found");
    }

    info!("Starting Sanctum GUI visibly...");
    let mut cmd = hidden_command(app_path.as_os_str());
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(dir) = app_path.parent() {
        cmd.current_dir(dir);
    }
    cmd.spawn().context("Failed to start Sanctum GUI")?;
    sleep(Duration::from_millis(750)).await;
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

fn start_process_visible_console(path: &Path, args: Option<&[&str]>) -> Result<Child> {
    if !path.exists() {
        warn!("Executable not found: {}", path.display());
        anyhow::bail!("File not found");
    }

    let mut cmd = visible_console_command(path.as_os_str());

    if let Some(args) = args {
        cmd.args(args);
    }

    if let Some(dir) = path.parent() {
        cmd.current_dir(dir);
    }

    cmd.spawn()
        .with_context(|| format!("Failed to spawn visible console: {}", path.display()))
}
