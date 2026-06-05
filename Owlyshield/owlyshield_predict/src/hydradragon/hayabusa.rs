//! Hayabusa Windows Event Log scanner integration.
//!
//! Python equivalent: `run_hayabusa_live_async`, `parse_hayabusa_results`,
//! and `notify_user_hayabusa_critical` in `antivirus_scripts/antivirus.py`.
//!
//! Runs Hayabusa in `csv-timeline` mode periodically, parses the output CSV,
//! and sends HIPS notifications for critical-level detections.
//!
//! All configurable values (interval, min-level, time-offset, exe path, enabled)
//! are read from the Sanctum config file so they can be changed from the GUI.

#![cfg(all(target_os = "windows", feature = "hydradragon"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::logging::Logging;

// ---------------------------------------------------------------------------
// Compile-time defaults (used when config value is absent / empty)
// ---------------------------------------------------------------------------

const DEFAULT_SCAN_INTERVAL_SECS: u64 = 30;
const DEFAULT_MIN_LEVEL: &str = "critical";
const DEFAULT_TIME_OFFSET: &str = "60s";

const HAYABUSA_PREFERRED_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\hayabusa\hayabusa-3.9.0-win-x64.exe";
const HAYABUSA_DIR_DEFAULT: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\hayabusa";

/// Output base directory — deliberately inside ProgramData, not Program Files.
const HAYABUSA_OUTPUT_BASE: &str =
    r"C:\ProgramData\HydraDragonAntivirus\hydradragon\logs\hayabusa";

/// Path of the Sanctum shared config file.
const SANCTUM_CONFIG_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\Sanctum\AppData\config.cfg";

// ---------------------------------------------------------------------------
// Sanctum config subset (only the fields we need)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct HayabusaConfig {
    #[serde(default)]
    hayabusa_enabled: Option<bool>,
    #[serde(default)]
    hayabusa_exe_path: Option<String>,
    #[serde(default)]
    hayabusa_scan_interval_secs: Option<u64>,
    #[serde(default)]
    hayabusa_min_level: Option<String>,
    #[serde(default)]
    hayabusa_time_offset: Option<String>,
}

fn load_hayabusa_config() -> HayabusaConfig {
    let text = match fs::read_to_string(SANCTUM_CONFIG_PATH) {
        Ok(t) => t,
        Err(_) => return HayabusaConfig::default(),
    };
    serde_json::from_str::<HayabusaConfig>(&text).unwrap_or_default()
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|v| !v.trim().is_empty())
}

// ---------------------------------------------------------------------------
// Resolve Hayabusa executable path
// ---------------------------------------------------------------------------

fn resolve_hayabusa_exe(config_path: Option<&str>) -> Option<PathBuf> {
    // 1) Value from Sanctum GUI config
    if let Some(p) = config_path {
        let candidate = PathBuf::from(p);
        if candidate.exists() {
            return Some(candidate);
        }
        Logging::warning(&format!(
            "[Hayabusa] Configured exe not found at '{}'; falling back to auto-detect",
            p
        ));
    }

    // 2) Known fixed path
    let preferred = PathBuf::from(HAYABUSA_PREFERRED_PATH);
    if preferred.exists() {
        return Some(preferred);
    }

    // 3) Highest-versioned exe in the default directory
    let dir = PathBuf::from(HAYABUSA_DIR_DEFAULT);
    if !dir.is_dir() {
        return None;
    }

    let mut candidates: Vec<PathBuf> = fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("exe")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("hayabusa-"))
                    .unwrap_or(false)
        })
        .collect();

    candidates.sort();
    candidates.pop()
}

// ---------------------------------------------------------------------------
// CSV parsing — detect critical rows
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HayabusaCriticalAlert {
    rule_title: String,
    details: String,
    computer: String,
    channel: String,
}

/// Equivalent to Python's `parse_hayabusa_results`.
/// Uses the `csv` crate for RFC 4180-compliant parsing.
fn parse_hayabusa_csv(csv_path: &Path, min_level: &str) -> Vec<HayabusaCriticalAlert> {
    let mut alerts = Vec::new();

    let mut rdr = match csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_path(csv_path)
    {
        Ok(r) => r,
        Err(e) => {
            Logging::error(&format!(
                "[Hayabusa] Cannot open CSV {}: {}",
                csv_path.display(),
                e
            ));
            return alerts;
        }
    };

    let headers = match rdr.headers() {
        Ok(h) => h.clone(),
        Err(e) => {
            Logging::warning(&format!("[Hayabusa] Cannot read CSV headers: {}", e));
            return alerts;
        }
    };

    let col = |name: &str| -> Option<usize> { headers.iter().position(|h| h.trim() == name) };

    let idx_level = col("Level");
    let idx_rule = col("RuleTitle");
    let idx_details = col("Details");
    let idx_computer = col("Computer");
    let idx_channel = col("Channel");

    // Build the set of levels that meet or exceed the configured minimum
    let accepted_levels: &[&str] = match min_level.to_ascii_lowercase().as_str() {
        "low" => &["low", "medium", "high", "critical"],
        "medium" => &["medium", "high", "critical"],
        "high" => &["high", "critical"],
        _ => &["critical", "crit"],
    };

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let get = |idx: Option<usize>| -> &str {
            idx.and_then(|i| record.get(i)).unwrap_or("").trim()
        };

        let level = get(idx_level).to_ascii_lowercase();
        if !accepted_levels.iter().any(|&l| level == l) {
            continue;
        }

        let rule_title = get(idx_rule).to_string();
        let details = get(idx_details).to_string();
        let computer = get(idx_computer).to_string();
        let channel = get(idx_channel).to_string();

        Logging::warning(&format!(
            "[Hayabusa] {}: {} | {}",
            level.to_uppercase(),
            rule_title,
            &details[..details.len().min(100)]
        ));

        alerts.push(HayabusaCriticalAlert {
            rule_title,
            details,
            computer,
            channel,
        });
    }

    if alerts.is_empty() {
        Logging::info("[Hayabusa] No qualifying alerts found in this scan");
    } else {
        Logging::warning(&format!(
            "[Hayabusa] {} qualifying alert(s) detected",
            alerts.len()
        ));
    }

    alerts
}

// ---------------------------------------------------------------------------
// HIPS notification
// ---------------------------------------------------------------------------

fn send_hayabusa_hips_notification(alert: &HayabusaCriticalAlert) {
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

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");

    let json = format!(
        r#"{{"request_id":"hayabusa_{ts}","alert_kind":"HAYABUSA_CRITICAL","pid":0,"app_name":"Hayabusa","exe_path":"hayabusa.exe","target":"{computer}","reason":"CRITICAL: {rule} | {details} | channel={channel}"}}"#,
        ts = ts,
        computer = escape(&alert.computer),
        rule = escape(&alert.rule_title),
        details = escape(&alert.details[..alert.details.len().min(200)]),
        channel = escape(&alert.channel),
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
// Single scan execution
// ---------------------------------------------------------------------------

fn run_single_scan(hayabusa_exe: &Path, min_level: &str, time_offset: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let output_dir =
        PathBuf::from(HAYABUSA_OUTPUT_BASE).join(format!("hayabusa_scan_{}", ts));

    if let Err(e) = fs::create_dir_all(&output_dir) {
        Logging::error(&format!(
            "[Hayabusa] Failed to create output directory {}: {}",
            output_dir.display(),
            e
        ));
        return;
    }

    let output_file = output_dir.join(format!("hayabusa_{}.csv", ts));
    let cwd = hayabusa_exe.parent().unwrap_or(Path::new("."));

    Logging::info(&format!(
        "[Hayabusa] Starting scan (min-level={}, offset={}) -> {}",
        min_level,
        time_offset,
        output_file.display()
    ));

    let status = Command::new(hayabusa_exe)
        .args([
            "csv-timeline",
            "--no-wizard",
            "--output",
            output_file.to_str().unwrap_or("hayabusa_out.csv"),
            "--profile",
            "standard",
            "--min-level",
            min_level,
            "--live-analysis",
            "--time-offset",
            time_offset,
            "--quiet",
        ])
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) => {
            Logging::info(&format!(
                "[Hayabusa] Scan completed (rc={})",
                s.code().unwrap_or(-1)
            ));

            if output_file.exists() {
                let alerts = parse_hayabusa_csv(&output_file, min_level);
                for alert in &alerts {
                    send_hayabusa_hips_notification(alert);
                }
            }
        }
        Err(e) => {
            Logging::error(&format!("[Hayabusa] Failed to launch process: {}", e));
        }
    }

    cleanup_old_scan_dirs();
}

// ---------------------------------------------------------------------------
// Old scan directory cleanup (keep last 10)
// ---------------------------------------------------------------------------

fn cleanup_old_scan_dirs() {
    let base = PathBuf::from(HAYABUSA_OUTPUT_BASE);
    if !base.is_dir() {
        return;
    }

    let mut dirs: Vec<PathBuf> = fs::read_dir(&base)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();

    dirs.sort();

    if dirs.len() > 10 {
        for old_dir in &dirs[..dirs.len() - 10] {
            if let Err(e) = fs::remove_dir_all(old_dir) {
                Logging::warning(&format!(
                    "[Hayabusa] Failed to remove old directory {}: {}",
                    old_dir.display(),
                    e
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Periodic scan loop
// ---------------------------------------------------------------------------

fn scan_loop(hayabusa_exe: PathBuf, scan_interval: u64, min_level: String, time_offset: String) {
    Logging::info(&format!(
        "[Hayabusa] Periodic scan loop started (interval={}s, min-level={}, offset={}, exe={})",
        scan_interval,
        min_level,
        time_offset,
        hayabusa_exe.display()
    ));

    loop {
        if !hayabusa_exe.exists() {
            Logging::warning(&format!(
                "[Hayabusa] Executable no longer present: {}",
                hayabusa_exe.display()
            ));
            thread::sleep(Duration::from_secs(scan_interval));
            continue;
        }

        run_single_scan(&hayabusa_exe, &min_level, &time_offset);

        Logging::info(&format!(
            "[Hayabusa] Next scan in {} seconds",
            scan_interval
        ));
        thread::sleep(Duration::from_secs(scan_interval));
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the Hayabusa periodic scan thread.
/// Settings are read from the Sanctum config file so they can be changed
/// from the Sanctum GUI without recompiling.
/// Returns immediately; scanning runs in the background.
pub fn start_hayabusa_monitor() {
    let cfg = load_hayabusa_config();

    // Respect the enabled flag from the GUI
    if cfg.hayabusa_enabled == Some(false) {
        Logging::info("[Hayabusa] Scanning disabled via Sanctum settings");
        return;
    }

    let exe_path_cfg = non_empty(&cfg.hayabusa_exe_path).map(str::to_string);
    let hayabusa_exe = match resolve_hayabusa_exe(exe_path_cfg.as_deref()) {
        Some(p) => p,
        None => {
            Logging::warning(
                "[Hayabusa] Executable not found; periodic scanning disabled",
            );
            return;
        }
    };

    let scan_interval = cfg
        .hayabusa_scan_interval_secs
        .filter(|&v| v >= 10)
        .unwrap_or(DEFAULT_SCAN_INTERVAL_SECS);

    let min_level = non_empty(&cfg.hayabusa_min_level)
        .unwrap_or(DEFAULT_MIN_LEVEL)
        .to_string();

    let time_offset = non_empty(&cfg.hayabusa_time_offset)
        .unwrap_or(DEFAULT_TIME_OFFSET)
        .to_string();

    // Update Hayabusa signatures on startup (equivalent of update_definitions_hayabusa_async in Python).
    // Run in a separate thread so it doesn't block the caller; scanning starts after update finishes.
    thread::Builder::new()
        .name("hayabusa_live_scanner".into())
        .spawn(move || {
            update_rules(&hayabusa_exe);
            scan_loop(hayabusa_exe, scan_interval, min_level, time_offset);
        })
        .ok();

    Logging::info("[Hayabusa] Rust-native Hayabusa monitor started (update-rules + scan loop)");
}

// ---------------------------------------------------------------------------
// Signature update helper
// ---------------------------------------------------------------------------

/// Run `hayabusa update-rules` once on startup.
/// Mirrors the Python `update_definitions_hayabusa_async` from `engine.py`.
fn update_rules(hayabusa_exe: &Path) {
    Logging::info("[Hayabusa] Updating signatures (update-rules)...");

    let exe_dir = match hayabusa_exe.parent() {
        Some(d) => d.to_path_buf(),
        None => {
            Logging::warning("[Hayabusa] Cannot determine exe directory; skipping update-rules");
            return;
        }
    };

    let result = Command::new(hayabusa_exe)
        .arg("update-rules")
        .current_dir(&exe_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match result {
        Ok(out) => {
            // Log stdout lines at info level
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if !line.trim().is_empty() {
                    Logging::info(&format!("[Hayabusa] {}", line));
                }
            }
            // Log stderr lines at warning level
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stderr.lines() {
                if !line.trim().is_empty() {
                    Logging::warning(&format!("[Hayabusa ERR] {}", line));
                }
            }
            if out.status.success() {
                Logging::info("[Hayabusa] Signatures updated successfully");
            } else {
                Logging::warning(&format!(
                    "[Hayabusa] update-rules exited with code {:?}",
                    out.status.code()
                ));
            }
        }
        Err(e) => {
            Logging::warning(&format!("[Hayabusa] update-rules failed to launch: {}", e));
        }
    }
}
