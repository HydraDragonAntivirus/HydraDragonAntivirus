#![cfg(windows)]

//! Post-detection remediation: locate and remove a malicious file's traces and
//! persistence across Windows — autorun registry values, services, scheduled
//! tasks, Prefetch files, Startup `.lnk` shortcuts, and uninstall entries.
//!
//! Finding traces is read-only and always safe. Removal is destructive and must
//! be requested explicitly by the caller. Files (Prefetch, `.lnk`) are
//! quarantined (moved) rather than hard-deleted; registry values/keys, services,
//! and scheduled tasks are deleted.

use std::path::{Path, PathBuf};

use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::System::Restore::{
    SRSetRestorePointW, BEGIN_SYSTEM_CHANGE, END_SYSTEM_CHANGE, MODIFY_SETTINGS, RESTOREPOINTINFOW,
    STATEMGRSTATUS,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, DeleteService, OpenSCManagerW, OpenServiceW,
    SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_STATUS, SERVICE_STOP,
};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

use crate::disinfector::quarantine_file;
use crate::fix_registry;
use crate::takeown;
use crate::registry_scanner::RegistryEntry;

/// Autorun value keys where the *whole value* is a command line, so deleting the
/// matching value is safe. (Winlogon Shell/Userinit are intentionally excluded —
/// removing those values would break the logon shell; they are only reported.)
const AUTORUN_VALUE_KEYS_HKLM: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];

const AUTORUN_VALUE_KEYS_HKCU: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
];

const UNINSTALL_KEYS_HKLM: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
];
const UNINSTALL_KEYS_HKCU: &[&str] =
    &[r"Software\Microsoft\Windows\CurrentVersion\Uninstall"];

const SERVICES_KEY: &str = r"System\CurrentControlSet\Services";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hive {
    Hklm,
    Hkcu,
}

impl Hive {
    fn root(self) -> RegKey {
        RegKey::predef(match self {
            Hive::Hklm => HKEY_LOCAL_MACHINE,
            Hive::Hkcu => HKEY_CURRENT_USER,
        })
    }
    fn label(self) -> &'static str {
        match self {
            Hive::Hklm => "HKLM",
            Hive::Hkcu => "HKCU",
        }
    }
}

/// The concrete removal an applied trace performs.
#[derive(Clone, Debug)]
pub enum TraceAction {
    DeleteRegValue {
        hive: Hive,
        subkey: String,
        value: String,
    },
    DeleteRegKey {
        hive: Hive,
        subkey: String,
    },
    DeleteService {
        name: String,
    },
    DeleteTask {
        name: String,
    },
    QuarantineFile {
        path: PathBuf,
    },
    /// Reported only — needs manual review (e.g. Winlogon Shell/Userinit).
    ManualReview,
    /// Fix a PUM registry entry: revert value and restore ACL.
    FixPumRegistry {
        hive_label: String,
        subkey: String,
        value_name: String,
        expected_reverted_value: String,
    },
    /// Fix a PUM file entry: clear or repair the file (e.g. remove non-comment
    /// lines from the hosts file). `action` describes the repair operation.
    FixPumFile {
        path: PathBuf,
        action: String,
    },
}

#[derive(Clone, Debug)]
pub struct Trace {
    pub category: &'static str,
    pub description: String,
    pub action: TraceAction,
}

/// Correlates registry/filesystem strings against a malicious file.
struct Target {
    path: String,
    name: String,
    dir: String,
}

impl Target {
    fn new(p: &Path) -> Self {
        Self {
            path: p.to_string_lossy().to_lowercase(),
            name: p
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default(),
            dir: p
                .parent()
                .map(|d| d.to_string_lossy().to_lowercase())
                .unwrap_or_default(),
        }
    }

    /// True if `hay` references the file by full path, or by file name when the
    /// name is distinctive enough (>= 5 chars) to avoid noisy matches.
    fn referenced_by(&self, hay: &str) -> bool {
        let h = hay.to_lowercase();
        (!self.path.is_empty() && h.contains(&self.path))
            || (self.name.len() >= 5 && h.contains(&self.name))
    }

    fn dir_referenced(&self, hay: &str) -> bool {
        self.dir.len() > 3 && hay.to_lowercase().contains(&self.dir)
    }
}

/// Create a fix action from a PUM entry (registry or file).
pub fn fix_pum(entry: &RegistryEntry) -> Option<Trace> {
    if !entry.pum {
        return None;
    }
    let expected = entry.expected_reverted_value.as_deref()?;
    if expected.is_empty() {
        return None;
    }
    if entry.hive == "FILE" {
        return Some(Trace {
            category: "pum_file",
            description: format!(
                "{} / {} -> {expected}",
                entry.path, entry.value_name
            ),
            action: TraceAction::FixPumFile {
                path: entry.path.clone().into(),
                action: expected.to_string(),
            },
        });
    }
    Some(Trace {
        category: "pum_registry",
        description: format!(
            "{}\\{}\\{} -> {expected}",
            entry.hive, entry.path, entry.value_name
        ),
        action: TraceAction::FixPumRegistry {
            hive_label: entry.hive.clone(),
            subkey: entry.path.clone(),
            value_name: entry.value_name.clone(),
            expected_reverted_value: expected.to_string(),
        },
    })
}

pub fn find_traces(malware: &Path) -> Vec<Trace> {
    let target = Target::new(malware);
    let mut traces = Vec::new();
    traces.extend(find_autorun_values(&target));
    traces.extend(find_winlogon(&target));
    traces.extend(find_services(&target));
    traces.extend(find_scheduled_tasks(&target));
    traces.extend(find_prefetch(&target));
    traces.extend(find_startup_lnk(&target));
    traces.extend(find_uninstall(&target));
    traces
}

/// Apply a trace's removal. Files go to `quarantine_dir`. Returns a human-
/// readable result line.
pub fn apply(trace: &Trace, quarantine_dir: &Path) -> Result<String, String> {
    match &trace.action {
        TraceAction::DeleteRegValue {
            hive,
            subkey,
            value,
        } => {
            // Back up the whole key (.reg) BEFORE deleting; abort if backup fails.
            let backup = export_reg(*hive, subkey, quarantine_dir)?;
            let key = hive
                .root()
                .open_subkey_with_flags(subkey, KEY_SET_VALUE)
                .map_err(|e| format!("open {}: {e}", subkey))?;
            key.delete_value(value)
                .map_err(|e| format!("delete value {value}: {e}"))?;
            Ok(format!(
                "deleted {}\\{}\\{} (backup: {})",
                hive.label(),
                subkey,
                value,
                backup.display()
            ))
        }
        TraceAction::DeleteRegKey { hive, subkey } => {
            let backup = export_reg(*hive, subkey, quarantine_dir)?;
            hive.root()
                .delete_subkey_all(subkey)
                .map_err(|e| format!("delete key {subkey}: {e}"))?;
            Ok(format!(
                "deleted key {}\\{} (backup: {})",
                hive.label(),
                subkey,
                backup.display()
            ))
        }
        TraceAction::DeleteService { name } => {
            // Back up the service's registry subkey BEFORE deleting; abort if it fails.
            let backup =
                export_reg(Hive::Hklm, &format!("{SERVICES_KEY}\\{name}"), quarantine_dir)?;
            delete_service(name)?;
            Ok(format!("deleted service {name} (backup: {})", backup.display()))
        }
        TraceAction::DeleteTask { name } => {
            delete_task(name)?;
            Ok(format!("deleted scheduled task {name}"))
        }
        TraceAction::QuarantineFile { path } => {
            let to = quarantine_file(path, quarantine_dir)
                .map_err(|e| format!("quarantine {}: {e}", path.display()))?;
            Ok(format!("quarantined {} -> {}", path.display(), to.display()))
        }
        TraceAction::FixPumRegistry {
            hive_label,
            subkey,
            value_name,
            expected_reverted_value,
        } => {
            let r1 = fix_registry::revert_value(
                hive_label, subkey, value_name, expected_reverted_value,
            )?;
            let r2 = fix_registry::restore_acl(hive_label, subkey)?;
            let r3 = takeown::takeown_registry_key(hive_label, subkey)?;
            Ok(format!("{r1}; {r2}; {r3}"))
        }
        TraceAction::FixPumFile { path, action } => {
            match action.as_str() {
                "clear_non_comment_lines" => {
                    let content = std::fs::read_to_string(path)
                        .map_err(|e| format!("read {}: {e}", path.display()))?;
                    let cleaned: Vec<&str> = content
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| l.is_empty() || l.starts_with('#'))
                        .collect();
                    let output = if cleaned.is_empty() {
                        String::new()
                    } else {
                        cleaned.join("\r\n") + "\r\n"
                    };
                    std::fs::write(path, &output)
                        .map_err(|e| format!("write {}: {e}", path.display()))?;
                    Ok(format!("cleared non-comment lines from {}", path.display()))
                }
                _ => Err(format!("unknown file PUM action: {action}")),
            }
        }
        TraceAction::ManualReview => {
            Err("manual review required; not removed automatically".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Registry finders
// ---------------------------------------------------------------------------

fn regvalue_to_string(v: &RegValue) -> String {
    match v.vtype {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            let units: Vec<u16> = v
                .bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            String::from_utf16_lossy(&units)
                .replace('\u{0}', " ")
                .trim()
                .to_string()
        }
        _ => String::new(),
    }
}

fn find_autorun_values(target: &Target) -> Vec<Trace> {
    let mut out = Vec::new();
    for (hive, keys) in [
        (Hive::Hklm, AUTORUN_VALUE_KEYS_HKLM),
        (Hive::Hkcu, AUTORUN_VALUE_KEYS_HKCU),
    ] {
        for subkey in keys {
            let Ok(key) = hive.root().open_subkey_with_flags(subkey, KEY_READ) else {
                continue;
            };
            for (name, value) in key.enum_values().flatten() {
                let data = regvalue_to_string(&value);
                if target.referenced_by(&data) {
                    out.push(Trace {
                        category: "registry_autorun",
                        description: format!("{}\\{}\\{} = {}", hive.label(), subkey, name, data),
                        action: TraceAction::DeleteRegValue {
                            hive,
                            subkey: subkey.to_string(),
                            value: name,
                        },
                    });
                }
            }
        }
    }
    out
}

fn find_winlogon(target: &Target) -> Vec<Trace> {
    let subkey = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let mut out = Vec::new();
    for hive in [Hive::Hklm, Hive::Hkcu] {
        let Ok(key) = hive.root().open_subkey_with_flags(subkey, KEY_READ) else {
            continue;
        };
        for value_name in ["Shell", "Userinit"] {
            if let Ok(value) = key.get_raw_value(value_name) {
                let data = regvalue_to_string(&value);
                if target.referenced_by(&data) {
                    out.push(Trace {
                        category: "registry_winlogon",
                        description: format!(
                            "{}\\{}\\{} = {} (remove only the malicious entry by hand)",
                            hive.label(),
                            subkey,
                            value_name,
                            data
                        ),
                        action: TraceAction::ManualReview,
                    });
                }
            }
        }
    }
    out
}

fn find_services(target: &Target) -> Vec<Trace> {
    let mut out = Vec::new();
    let Ok(services) = Hive::Hklm
        .root()
        .open_subkey_with_flags(SERVICES_KEY, KEY_READ)
    else {
        return out;
    };
    for name in services.enum_keys().flatten() {
        let Ok(svc) = services.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };
        let image = svc
            .get_raw_value("ImagePath")
            .map(|v| regvalue_to_string(&v))
            .unwrap_or_default();
        if !image.is_empty() && target.referenced_by(&image) {
            out.push(Trace {
                category: "service",
                description: format!("service {name} -> {image}"),
                action: TraceAction::DeleteService { name },
            });
        }
    }
    out
}

fn find_uninstall(target: &Target) -> Vec<Trace> {
    let mut out = Vec::new();
    for (hive, keys) in [
        (Hive::Hklm, UNINSTALL_KEYS_HKLM),
        (Hive::Hkcu, UNINSTALL_KEYS_HKCU),
    ] {
        for base in keys {
            let Ok(root) = hive.root().open_subkey_with_flags(base, KEY_READ) else {
                continue;
            };
            for entry in root.enum_keys().flatten() {
                let Ok(k) = root.open_subkey_with_flags(&entry, KEY_READ) else {
                    continue;
                };
                let mut hit: Option<String> = None;
                for field in ["InstallLocation", "UninstallString", "DisplayIcon"] {
                    let val = k
                        .get_raw_value(field)
                        .map(|v| regvalue_to_string(&v))
                        .unwrap_or_default();
                    if !val.is_empty() && (target.referenced_by(&val) || target.dir_referenced(&val))
                    {
                        hit = Some(format!("{field}={val}"));
                        break;
                    }
                }
                if let Some(detail) = hit {
                    let subkey = format!("{base}\\{entry}");
                    out.push(Trace {
                        category: "uninstall_entry",
                        description: format!("{}\\{} ({detail})", hive.label(), subkey),
                        action: TraceAction::DeleteRegKey { hive, subkey },
                    });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Scheduled tasks
// ---------------------------------------------------------------------------

fn find_scheduled_tasks(target: &Target) -> Vec<Trace> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let tasks_root = PathBuf::from(root).join(r"System32\Tasks");
    let mut out = Vec::new();
    walk_tasks(&tasks_root, &tasks_root, target, &mut out);
    out
}

/// Task definitions live as files under `%SystemRoot%\System32\Tasks` mirroring
/// the task-folder tree, so the path relative to that root is the task's full
/// path. We match references in the (UTF-16) task XML without a CSV/schtasks pass.
fn walk_tasks(dir: &Path, root: &Path, target: &Target, out: &mut Vec<Trace>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_tasks(&path, root, target, out);
        } else if let Ok(data) = std::fs::read(&path) {
            if bytes_reference(&data, &target.path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('/', "\\");
                let task_path = format!("\\{rel}");
                out.push(Trace {
                    category: "scheduled_task",
                    description: format!("task {task_path}"),
                    action: TraceAction::DeleteTask { name: task_path },
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem: Prefetch + Startup .lnk
// ---------------------------------------------------------------------------

fn find_prefetch(target: &Target) -> Vec<Trace> {
    let mut out = Vec::new();
    if target.name.is_empty() {
        return out;
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let dir = PathBuf::from(root).join("Prefetch");
    // Prefetch files are named EXENAME.EXE-<HASH>.pf
    let prefix = format!("{}-", target.name);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_lowercase();
            if fname.ends_with(".pf") && fname.starts_with(&prefix) {
                out.push(Trace {
                    category: "prefetch",
                    description: entry.path().display().to_string(),
                    action: TraceAction::QuarantineFile { path: entry.path() },
                });
            }
        }
    }
    out
}

fn startup_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(
            PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
        );
    }
    if let Ok(programdata) = std::env::var("ProgramData") {
        dirs.push(
            PathBuf::from(programdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
        );
    }
    dirs
}

/// True if the malicious path (lowercased) appears in `data` as ASCII or
/// UTF-16LE — used for `.lnk` shortcuts and Task Scheduler XML without a full
/// binary parser.
fn bytes_reference(data: &[u8], path_lower: &str) -> bool {
    if path_lower.len() < 4 {
        return false;
    }
    let needle = path_lower.as_bytes();
    if data.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle)) {
        return true;
    }
    let wide: String = data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<u16>>()
        .iter()
        .map(|&u| char::from_u32(u as u32).unwrap_or('\u{0}'))
        .collect();
    wide.to_lowercase().contains(path_lower)
}

fn find_startup_lnk(target: &Target) -> Vec<Trace> {
    let mut out = Vec::new();
    for dir in startup_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase())
                != Some("lnk".to_string())
            {
                continue;
            }
            if let Ok(data) = std::fs::read(&path) {
                if bytes_reference(&data, &target.path) {
                    out.push(Trace {
                        category: "startup_lnk",
                        description: path.display().to_string(),
                        action: TraceAction::QuarantineFile { path },
                    });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------

/// Create a Windows System Restore Point via `SRSetRestorePointW` (sfc.dll).
/// Requires admin and System Restore enabled on the system drive; Windows may
/// skip it if one was already created in the last 24h.
pub fn create_restore_point(description: &str) -> Result<String, String> {
    let mut info = RESTOREPOINTINFOW {
        dwEventType: BEGIN_SYSTEM_CHANGE,
        dwRestorePtType: MODIFY_SETTINGS,
        llSequenceNumber: 0,
        szDescription: [0u16; 256],
    };
    for (i, unit) in description.encode_utf16().take(255).enumerate() {
        info.szDescription[i] = unit;
    }
    let mut status = STATEMGRSTATUS::default();
    let ok = unsafe { SRSetRestorePointW(&info, &mut status) }.as_bool();
    // STATEMGRSTATUS is a packed struct — copy fields out before using them.
    let nstatus = status.nStatus;
    let seq = status.llSequenceNumber;
    if !ok {
        return Err(format!("SRSetRestorePointW failed (status {})", nstatus.0));
    }
    // Close the bracketed system change to finalize the restore point.
    info.dwEventType = END_SYSTEM_CHANGE;
    info.llSequenceNumber = seq;
    let _ = unsafe { SRSetRestorePointW(&info, &mut status) };
    Ok(format!("restore point #{seq} created"))
}

/// Stop and delete a service via the Service Control Manager API (advapi32) —
/// no `sc.exe`.
pub(crate) fn delete_service(name: &str) -> Result<(), String> {
    let name_w = wide(name);
    const DELETE_ACCESS: u32 = 0x0001_0000; // standard DELETE right
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .map_err(|e| format!("OpenSCManager: {e}"))?;
        let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_STOP | DELETE_ACCESS) {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                return Err(format!("OpenService {name}: {e}"));
            }
        };
        let mut status = SERVICE_STATUS::default();
        let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        let result = DeleteService(svc).map_err(|e| format!("DeleteService {name}: {e}"));
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        result
    }
}

/// Delete a scheduled task by its full path via the Task Scheduler 2.0 COM API —
/// no `schtasks.exe`.
fn delete_task(task_path: &str) -> Result<(), String> {
    let rel = task_path.trim_start_matches('\\');
    let (folder, leaf) = match rel.rsplit_once('\\') {
        Some((f, l)) => (format!("\\{f}"), l.to_string()),
        None => ("\\".to_string(), rel.to_string()),
    };
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("CoCreateInstance(TaskScheduler): {e}"))?;
        let empty = VARIANT::default();
        service
            .Connect(&empty, &empty, &empty, &empty)
            .map_err(|e| format!("ITaskService::Connect: {e}"))?;
        let folder = service
            .GetFolder(&BSTR::from(folder.as_str()))
            .map_err(|e| format!("GetFolder {folder}: {e}"))?;
        folder
            .DeleteTask(&BSTR::from(leaf.as_str()), 0)
            .map_err(|e| format!("DeleteTask {task_path}: {e}"))?;
    }
    Ok(())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Export a registry key to a UTF-16LE `.reg` file under
/// `<quarantine_dir>/regbackup`, serialized in-process via the registry API —
/// no `reg.exe`. Restorable by importing the `.reg`. Returns the backup path.
fn export_reg(hive: Hive, subkey: &str, quarantine_dir: &Path) -> Result<PathBuf, String> {
    let key = hive
        .root()
        .open_subkey_with_flags(subkey, KEY_READ)
        .map_err(|e| format!("open {subkey} for backup: {e}"))?;
    let backup_dir = quarantine_dir.join("regbackup");
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("create backup dir: {e}"))?;

    let mut out = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    write_reg_key(&key, &format!("{}\\{}", hive_full(hive), subkey), &mut out);

    let safe: String = format!("{}_{}", hive.label(), subkey)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let dest = unique_path(backup_dir.join(format!("{safe}.reg")));

    // .reg "Version 5.00" files are UTF-16LE with a BOM.
    let mut bytes = vec![0xFFu8, 0xFE];
    for unit in out.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&dest, &bytes).map_err(|e| format!("write backup: {e}"))?;
    Ok(dest)
}

fn hive_full(hive: Hive) -> &'static str {
    match hive {
        Hive::Hklm => "HKEY_LOCAL_MACHINE",
        Hive::Hkcu => "HKEY_CURRENT_USER",
    }
}

fn write_reg_key(key: &RegKey, full_path: &str, out: &mut String) {
    out.push('[');
    out.push_str(full_path);
    out.push_str("]\r\n");
    for (name, val) in key.enum_values().flatten() {
        out.push_str(&format_reg_value(&name, &val));
    }
    out.push_str("\r\n");
    for sub in key.enum_keys().flatten() {
        if let Ok(subkey) = key.open_subkey_with_flags(&sub, KEY_READ) {
            write_reg_key(&subkey, &format!("{full_path}\\{sub}"), out);
        }
    }
}

fn format_reg_value(name: &str, val: &RegValue) -> String {
    let lhs = if name.is_empty() {
        "@".to_string()
    } else {
        format!("\"{}\"", reg_escape(name))
    };
    match val.vtype {
        REG_SZ => format!("{lhs}=\"{}\"\r\n", reg_escape(&utf16_to_string(&val.bytes))),
        REG_DWORD => {
            let mut b = [0u8; 4];
            for (i, x) in val.bytes.iter().take(4).enumerate() {
                b[i] = *x;
            }
            format!("{lhs}=dword:{:08x}\r\n", u32::from_le_bytes(b))
        }
        REG_BINARY => format!("{lhs}=hex:{}\r\n", hex_csv(&val.bytes)),
        _ => format!(
            "{lhs}=hex({:x}):{}\r\n",
            reg_type_code(&val.vtype),
            hex_csv(&val.bytes)
        ),
    }
}

fn reg_type_code(t: &RegType) -> u32 {
    match t {
        REG_NONE => 0,
        REG_SZ => 1,
        REG_EXPAND_SZ => 2,
        REG_BINARY => 3,
        REG_DWORD => 4,
        REG_DWORD_BIG_ENDIAN => 5,
        REG_LINK => 6,
        REG_MULTI_SZ => 7,
        REG_RESOURCE_LIST => 8,
        REG_FULL_RESOURCE_DESCRIPTOR => 9,
        REG_RESOURCE_REQUIREMENTS_LIST => 10,
        REG_QWORD => 11,
    }
}

fn hex_csv(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn reg_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn utf16_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\u{0}')
        .to_string()
}

fn unique_path(candidate: PathBuf) -> PathBuf {
    if !candidate.exists() {
        return candidate;
    }
    let mut index = 1u32;
    loop {
        let alt = PathBuf::from(format!("{}.{index}", candidate.display()));
        if !alt.exists() {
            return alt;
        }
        index += 1;
    }
}
