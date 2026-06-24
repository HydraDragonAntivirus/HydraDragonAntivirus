#![cfg(windows)]
#![allow(unsafe_op_in_unsafe_fn)]

use std::path::PathBuf;

use serde::Serialize;
use winreg::enums::*;
use winreg::RegKey;
use winreg::RegValue;
use winreg::HKEY;

#[derive(Debug, Clone, Serialize)]
pub struct StartupDetection {
    pub source: String,
    pub name: String,
    pub command: String,
    pub detail: String,
}

const STARTUP_KEYS_HKLM: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"Software\Microsoft\Active Setup\Installed Components",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Execute Hooks",
    r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    r"Software\Microsoft\Windows\CurrentVersion\App Paths",
    r"System\CurrentControlSet\Services",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Internet Explorer\SearchScopes",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Stats",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
];

const STARTUP_KEYS_HKCU: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Active Setup\Installed Components",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"Software\Microsoft\Internet Explorer\SearchScopes",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Stats",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
];

pub fn scan_startup_objects() -> Vec<StartupDetection> {
    let mut results = Vec::new();

    scan_registry_values("HKLM", STARTUP_KEYS_HKLM, HKEY_LOCAL_MACHINE, &mut results);
    scan_registry_values("HKCU", STARTUP_KEYS_HKCU, HKEY_CURRENT_USER, &mut results);
    scan_startup_folders(&mut results);
    scan_scheduled_tasks(&mut results);

    results
}

fn reg_value_to_string(val: &RegValue) -> String {
    match val.vtype {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
            let s = String::from_utf8_lossy(&val.bytes);
            s.trim_end_matches('\0').to_string()
        }
        RegType::REG_MULTI_SZ => {
            let s = String::from_utf8_lossy(&val.bytes);
            s.trim_end_matches('\0').replace('\0', "; ")
        }
        RegType::REG_DWORD => {
            if val.bytes.len() >= 4 {
                format!("{}", u32::from_le_bytes([val.bytes[0], val.bytes[1], val.bytes[2], val.bytes[3]]))
            } else {
                String::from("(invalid dword)")
            }
        }
        _ => format!("({} bytes)", val.bytes.len()),
    }
}

fn scan_registry_values(hive_name: &str, keys: &[&str], root: HKEY, results: &mut Vec<StartupDetection>) {
    let root_key = RegKey::predef(root);
    for &key_path in keys {
        if let Ok(key) = root_key.open_subkey_with_flags(key_path, KEY_READ) {
            for name_result in key.enum_values() {
                if let Ok((value_name, value_data)) = name_result {
                    let cmd = reg_value_to_string(&value_data);
                    if !cmd.trim().is_empty() {
                        results.push(StartupDetection {
                            source: format!("{}\\{}", hive_name, key_path),
                            name: value_name,
                            command: cmd,
                            detail: format!("Startup/persistence entry in {}\\{}", hive_name, key_path),
                        });
                    }
                }
            }
            // Also scan subkeys for ImagePath/Command values (services, BHOs, etc.)
            for sub_name in key.enum_keys().flatten() {
                if let Ok(sub_key) = key.open_subkey_with_flags(&sub_name, KEY_READ) {
                    if let Some(cmd) = get_image_path_from_subkey(&sub_key) {
                        results.push(StartupDetection {
                            source: format!("{}\\{}\\{}", hive_name, key_path, sub_name),
                            name: sub_name,
                            command: cmd,
                            detail: format!("Startup/persistence subkey in {}\\{}", hive_name, key_path),
                        });
                    }
                }
            }
        }
    }
}

fn get_image_path_from_subkey(key: &winreg::RegKey) -> Option<String> {
    for val_name in &["ImagePath", "Command", "Application", "Module", "(Default)", "Script"] {
        if let Ok(val) = key.get_raw_value(val_name) {
            let s = reg_value_to_string(&val);
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn scan_startup_folders(results: &mut Vec<StartupDetection>) {
    for env_var in &["ProgramData", "ALLUSERSPROFILE"] {
        if let Ok(base) = std::env::var(env_var) {
            let dir = PathBuf::from(base).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            results.push(StartupDetection {
                                source: "StartupFolder (AllUsers)".into(),
                                name: name.to_string(),
                                command: path.display().to_string(),
                                detail: format!("All Users startup entry: {}", path.display()),
                            });
                        }
                    }
                }
            }
        }
    }
    if let Ok(app_data) = std::env::var("APPDATA") {
        let dir = PathBuf::from(app_data).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        results.push(StartupDetection {
                            source: "StartupFolder (CurrentUser)".into(),
                            name: name.to_string(),
                            command: path.display().to_string(),
                            detail: format!("Current User startup entry: {}", path.display()),
                        });
                    }
                }
            }
        }
    }
}

fn scan_scheduled_tasks(results: &mut Vec<StartupDetection>) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new("schtasks.exe")
        .args(["/query", "/fo", "LIST", "/v"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_task = String::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(task_name) = line.strip_prefix("TaskName:").map(|s| s.trim()) {
            current_task = task_name.to_string();
        } else if line.starts_with("Task To Run:") || line.starts_with("Action:") {
            if let Some(cmd) = line.split(':').nth(1).map(|s| s.trim()) {
                if !cmd.is_empty() && !cmd.contains("schtasks") {
                    results.push(StartupDetection {
                        source: "ScheduledTask".into(),
                        name: current_task.clone(),
                        command: cmd.to_string(),
                        detail: format!("Scheduled task: {} -> {}", current_task, cmd),
                    });
                }
            }
        }
    }
}
