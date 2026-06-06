//! Suricata NIDS integration — Windows network interface detection, process management,
//! and EVE JSON log monitoring, fully implemented in Rust.
//!
//! Python equivalent: `suricata_callback`, `monitor_interfaces`,
//! `start_suricata_on_interface`, `monitor_suricata_log_async`,
//! and `parse_suricata_alert` in `antivirus_scripts/antivirus.py`.
//!
//! Settings are read from the Sanctum config file so the user can change them
//! from the Sanctum GUI without recompiling.

#![cfg(all(target_os = "windows", feature = "hydradragon"))]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::Deserialize;

use crate::logging::Logging;

// ---------------------------------------------------------------------------
// Constants — used when no value is supplied in config
// ---------------------------------------------------------------------------

const LOG_POLL_INTERVAL_MS: u64 = 500;
const INTERFACE_CHECK_INTERVAL_SECS: u64 = 30;

const SURICATA_EXE_DEFAULT: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\suricata\suricata.exe";
const SURICATA_CONFIG_DEFAULT: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\hipsconfig\suricata.yaml";
const SURICATA_LOG_DIR_DEFAULT: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\suricata\log";

/// Path of the Sanctum shared config file.
const SANCTUM_CONFIG_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\Sanctum\AppData\config.cfg";

// ---------------------------------------------------------------------------
// Sanctum config subset (only the fields we need)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct SuricataConfig {
    #[serde(default)]
    suricata_enabled: Option<bool>,
    #[serde(default)]
    suricata_exe_path: Option<String>,
    #[serde(default)]
    suricata_config_path: Option<String>,
    #[serde(default)]
    suricata_log_dir: Option<String>,
}

fn load_suricata_config() -> SuricataConfig {
    let text = match std::fs::read_to_string(SANCTUM_CONFIG_PATH) {
        Ok(t) => t,
        Err(_) => return SuricataConfig::default(),
    };
    serde_json::from_str::<SuricataConfig>(&text).unwrap_or_default()
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|v| !v.trim().is_empty())
}

// ---------------------------------------------------------------------------
// EVE JSON alert structures
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct EveAlert {
    severity: Option<u32>,
    signature: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EveEvent {
    event_type: Option<String>,
    src_ip: Option<String>,
    dest_ip: Option<String>,
    alert: Option<EveAlert>,
}

// ---------------------------------------------------------------------------
// Network interface descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct NetworkInterface {
    /// NPF GUID-style name used by Suricata: `\Device\NPF_{GUID}`
    npf_name: String,
    /// Human-readable name (used in log messages)
    friendly_name: String,
}

// ---------------------------------------------------------------------------
// Network interface enumeration (via PowerShell / WMI)
// ---------------------------------------------------------------------------

/// List active physical network adapters and return them in `\Device\NPF_{GUID}` form.
fn enumerate_network_interfaces() -> Vec<NetworkInterface> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"Get-WmiObject Win32_NetworkAdapter |
               Where-Object { $_.PhysicalAdapter -eq $true -and $_.NetEnabled -eq $true } |
               Select-Object -ExpandProperty GUID"#,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let mut interfaces = Vec::new();

    let guids = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        _ => {
            Logging::warning("[Suricata] PowerShell interface query failed");
            return interfaces;
        }
    };

    for line in guids.lines() {
        let guid = line.trim();
        if guid.is_empty() {
            continue;
        }
        let npf_name = if guid.starts_with('{') {
            format!(r"\Device\NPF_{}", guid)
        } else {
            format!(r"\Device\NPF_{{{}}}", guid)
        };

        interfaces.push(NetworkInterface {
            npf_name,
            friendly_name: guid.to_string(),
        });
    }

    Logging::info(&format!(
        "[Suricata] {} active network interface(s) detected",
        interfaces.len()
    ));

    interfaces
}

// ---------------------------------------------------------------------------
// Start Suricata for a single interface
// ---------------------------------------------------------------------------

fn start_suricata_on_interface(
    iface: &NetworkInterface,
    suricata_exe: &Path,
    suricata_cfg: &Path,
    log_dir: &Path,
) -> Option<Child> {
    if !suricata_exe.exists() {
        Logging::error(&format!(
            "[Suricata] Executable not found: {}",
            suricata_exe.display()
        ));
        return None;
    }
    if !suricata_cfg.exists() {
        Logging::error(&format!(
            "[Suricata] Config file not found: {}",
            suricata_cfg.display()
        ));
        return None;
    }

    if let Err(e) = std::fs::create_dir_all(log_dir) {
        Logging::error(&format!(
            "[Suricata] Failed to create log directory {}: {}",
            log_dir.display(),
            e
        ));
        return None;
    }

    Logging::info(&format!(
        "[Suricata] Starting on interface: {}",
        iface.friendly_name
    ));

    let child = Command::new(suricata_exe)
        .args([
            "-c",
            suricata_cfg.to_str().unwrap_or(SURICATA_CONFIG_DEFAULT),
            "-i",
            &iface.npf_name,
            "-l",
            log_dir.to_str().unwrap_or(SURICATA_LOG_DIR_DEFAULT),
            "--set",
            "outputs.0.fast.enabled=yes",
            "--set",
            "outputs.1.eve-log.enabled=yes",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match child {
        Ok(proc) => {
            Logging::info(&format!(
                "[Suricata] Process started (pid={}) interface={}",
                proc.id(),
                iface.friendly_name
            ));
            Some(proc)
        }
        Err(e) => {
            Logging::error(&format!(
                "[Suricata] Failed to start process ({}): {}",
                iface.friendly_name, e
            ));
            None
        }
    }
}

// ---------------------------------------------------------------------------
// EVE JSON line parser
// ---------------------------------------------------------------------------

/// Equivalent to Python's `parse_suricata_alert` + `process_alert_data`.
/// Returns `(priority, src_ip, dest_ip, signature, category)`.
fn parse_eve_line(line: &str) -> Option<(u32, String, String, String, String)> {
    let event: EveEvent = serde_json::from_str(line).ok()?;
    if event.event_type.as_deref() != Some("alert") {
        return None;
    }
    let alert = event.alert?;
    let priority = alert.severity.unwrap_or(3);
    let src_ip = event.src_ip.unwrap_or_default();
    let dest_ip = event.dest_ip.unwrap_or_default();
    let signature = alert.signature.unwrap_or_default();
    let category = alert.category.unwrap_or_default();
    Some((priority, src_ip, dest_ip, signature, category))
}

/// Log the alert and forward high-priority ones to the firewall GUI pipe.
fn process_suricata_alert(
    priority: u32,
    src_ip: &str,
    dest_ip: &str,
    signature: &str,
    category: &str,
) {
    let level = match priority {
        1 => "CRITICAL",
        2 => "HIGH",
        3 => "MEDIUM",
        _ => "LOW",
    };

    Logging::warning(&format!(
        "[Suricata] [{level}] {signature} | {category} | {src_ip} -> {dest_ip}"
    ));

    if priority <= 2 {
        send_suricata_hips_notification(priority, src_ip, dest_ip, signature, category);
    }
}

// ---------------------------------------------------------------------------
// HIPS notification (HydraDragonFirewall GUI pipe)
// ---------------------------------------------------------------------------

fn send_suricata_hips_notification(
    priority: u32,
    src_ip: &str,
    dest_ip: &str,
    signature: &str,
    category: &str,
) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE, FlushFileBuffers,
        OPEN_EXISTING, WriteFile,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::PCWSTR;

    const HIPS_PIPE: &str = r"\\.\pipe\HydraHipEvent";
    const TIMEOUT_MS: u32 = 750;

    let mut pipe_wide: Vec<u16> = HIPS_PIPE.encode_utf16().collect();
    pipe_wide.push(0);
    let pcwstr = PCWSTR(pipe_wide.as_ptr());

    let wait_ok = unsafe { WaitNamedPipeW(pcwstr, TIMEOUT_MS) };
    if !wait_ok.as_bool() {
        return;
    }

    let handle = unsafe {
        CreateFileW(
            pcwstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        _ => return,
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let json = format!(
        r#"{{"request_id":"suricata_{ts}","alert_kind":"SURICATA_ALERT","pid":0,"app_name":"Suricata","exe_path":"suricata.exe","target":"{dest_ip}","reason":"[P{priority}] {sig} ({cat}) {src} -> {dst}"}}"#,
        ts = ts,
        dest_ip = dest_ip.replace('"', "\\\""),
        priority = priority,
        sig = signature.replace('"', "\\\""),
        cat = category.replace('"', "\\\""),
        src = src_ip,
        dst = dest_ip,
    );

    let bytes = json.as_bytes();
    let mut written = 0u32;
    unsafe {
        WriteFile(handle, Some(bytes), Some(&mut written), None);
        FlushFileBuffers(handle);
        CloseHandle(handle);
    }
}

// ---------------------------------------------------------------------------
// EVE JSON log monitor thread
// ---------------------------------------------------------------------------

fn spawn_eve_log_monitor(eve_log_path: PathBuf) {
    thread::Builder::new()
        .name("suricata_eve_monitor".into())
        .spawn(move || {
            Logging::info(&format!(
                "[Suricata] EVE log monitor started: {}",
                eve_log_path.display()
            ));

            // Wait for the log file to appear
            loop {
                if eve_log_path.exists() {
                    break;
                }
                Logging::info(&format!(
                    "[Suricata] Waiting for EVE log: {}",
                    eve_log_path.display()
                ));
                thread::sleep(Duration::from_secs(2));
            }

            let file = match std::fs::File::open(&eve_log_path) {
                Ok(f) => f,
                Err(e) => {
                    Logging::error(&format!("[Suricata] Cannot open EVE log: {}", e));
                    return;
                }
            };

            let mut reader = BufReader::new(file);
            // Seek to end — only process new events
            if let Err(e) = reader.seek(SeekFrom::End(0)) {
                Logging::warning(&format!("[Suricata] EVE seek failed: {}", e));
            }

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        thread::sleep(Duration::from_millis(LOG_POLL_INTERVAL_MS));
                    }
                    Ok(_) => {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            if let Some((priority, src, dst, sig, cat)) = parse_eve_line(trimmed) {
                                process_suricata_alert(priority, &src, &dst, &sig, &cat);
                            }
                        }
                    }
                    Err(e) => {
                        Logging::error(&format!("[Suricata] EVE read error: {}", e));
                        thread::sleep(Duration::from_millis(LOG_POLL_INTERVAL_MS));
                    }
                }
            }
        })
        .ok();
}

// ---------------------------------------------------------------------------
// Interface monitor coordinator thread
// ---------------------------------------------------------------------------

fn spawn_interface_monitor(
    suricata_exe: PathBuf,
    suricata_cfg: PathBuf,
    log_dir: PathBuf,
    eve_log: PathBuf,
) {
    thread::Builder::new()
        .name("suricata_iface_monitor".into())
        .spawn(move || {
            let running: Arc<Mutex<HashMap<String, Child>>> = Arc::new(Mutex::new(HashMap::new()));

            spawn_eve_log_monitor(eve_log);

            loop {
                let interfaces = enumerate_network_interfaces();

                {
                    let mut procs = running.lock().unwrap();

                    // Remove exited processes
                    procs.retain(|guid, child| match child.try_wait() {
                        Ok(Some(status)) => {
                            Logging::warning(&format!(
                                "[Suricata] Process exited (guid={}, status={:?}); will restart",
                                guid, status
                            ));
                            false
                        }
                        Ok(None) => true,
                        Err(e) => {
                            Logging::error(&format!(
                                "[Suricata] Cannot check process status (guid={}): {}",
                                guid, e
                            ));
                            false
                        }
                    });

                    // Start Suricata on new interfaces
                    for iface in &interfaces {
                        let guid = iface.friendly_name.clone();
                        if procs.contains_key(&guid) {
                            continue;
                        }
                        if let Some(child) = start_suricata_on_interface(
                            iface,
                            &suricata_exe,
                            &suricata_cfg,
                            &log_dir,
                        ) {
                            procs.insert(guid, child);
                        }
                    }
                }

                thread::sleep(Duration::from_secs(INTERFACE_CHECK_INTERVAL_SECS));
            }
        })
        .ok();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the Suricata monitoring infrastructure.
/// Paths and enable flag are read from the Sanctum config file so they can be
/// changed from the Sanctum GUI without recompiling.
/// Returns immediately; all work runs in background threads.
pub fn start_suricata_monitor() {
    let cfg = load_suricata_config();

    // Respect the enabled flag from the GUI
    if cfg.suricata_enabled == Some(false) {
        Logging::info("[Suricata] Monitoring disabled via Sanctum settings");
        return;
    }

    let suricata_exe =
        PathBuf::from(non_empty(&cfg.suricata_exe_path).unwrap_or(SURICATA_EXE_DEFAULT));
    let suricata_cfg =
        PathBuf::from(non_empty(&cfg.suricata_config_path).unwrap_or(SURICATA_CONFIG_DEFAULT));
    let log_dir =
        PathBuf::from(non_empty(&cfg.suricata_log_dir).unwrap_or(SURICATA_LOG_DIR_DEFAULT));
    let eve_log = log_dir.join("eve.json");

    if !suricata_exe.exists() {
        Logging::warning(&format!(
            "[Suricata] Executable not found: {}; monitoring disabled",
            suricata_exe.display()
        ));
        return;
    }

    if !suricata_cfg.exists() {
        Logging::warning(&format!(
            "[Suricata] Config not found: {}; monitoring disabled",
            suricata_cfg.display()
        ));
        return;
    }

    Logging::info(&format!(
        "[Suricata] Starting Rust-native Suricata monitor (exe={}, cfg={}, log={})",
        suricata_exe.display(),
        suricata_cfg.display(),
        log_dir.display()
    ));

    spawn_interface_monitor(suricata_exe, suricata_cfg, log_dir, eve_log);
    Logging::info("[Suricata] Monitor started successfully");
}
