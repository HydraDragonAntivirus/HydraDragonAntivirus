#![cfg(windows)]

//! Escalating remediation for malware that resists normal cleanup.
//!
//! The chain, used when a detected file can't simply be quarantined (it's locked
//! by a running process):
//!   1. **Quarantine** the file (move it out of the way).
//!   2. If that fails, **terminate** every process running that image. A process
//!      that protected itself with `RtlSetProcessIsCritical` (so killing it would
//!      BSOD the machine) is first made **non-critical** via
//!      `NtSetInformationProcess(ProcessBreakOnTermination=0)`, then terminated.
//!   3. Retry the quarantine.
//!   4. If it still can't be cleaned (file held open, access denied), **defer the
//!      disinfection to the next boot**: drop a marker recording *what* and *why*,
//!      schedule the locked file for deletion on reboot (`MoveFileEx`), register a
//!      `RunOnce` key that re-runs us with `--disinfect-pending`, and (optionally)
//!      reboot.
//!
//! Rebooting is gated behind `allow_reboot` and uses a 30s delay with a message
//! so the user can abort (`shutdown /a`). Nothing here reboots unasked.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QueryServiceConfigW, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE, QUERY_SERVICE_CONFIGW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_CHANGE_CONFIG, SERVICE_DEMAND_START, SERVICE_DRIVER, SERVICE_ERROR, SERVICE_QUERY_CONFIG,
    SERVICE_STATE_ALL,
};
use windows::Win32::System::Shutdown::{
    InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_APPLICATION,
    SHTDN_REASON_MINOR_SECURITYFIX,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_TERMINATE,
};

use crate::disinfector::quarantine_file;

/// `PROCESSINFOCLASS::ProcessBreakOnTermination` — the "critical process" flag.
const PROCESS_BREAK_ON_TERMINATION: u32 = 29;
/// RunOnce value name + the marker file recording pending work.
const RUNONCE_VALUE: &str = "HydraDragonDisinfect";
const PENDING_MARKER: &str = "pending_disinfect.txt";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Outcome of [`escalated_disinfect`].
#[derive(Debug, Clone)]
pub enum EscalationOutcome {
    /// File quarantined directly (no process interference).
    Quarantined,
    /// `n` blocking process(es) terminated, then the file quarantined.
    KilledAndQuarantined(usize),
    /// Couldn't clean now; deferred to next boot. `reboot` = a restart was started.
    ScheduledForRestart { reboot: bool, detail: String },
    /// Nothing worked and restart could not be scheduled.
    Failed(String),
}

/// Run the full escalation chain against `path`. `reason` is recorded in the
/// restart marker so the boot-time pass knows *why* it is disinfecting.
pub fn escalated_disinfect(
    path: &Path,
    quarantine_dir: &Path,
    reason: &str,
    allow_reboot: bool,
) -> EscalationOutcome {
    // 1. Try a plain quarantine first.
    if quarantine_file(path, quarantine_dir).is_ok() {
        return EscalationOutcome::Quarantined;
    }

    // 2. Stop the threat. A kernel driver (.sys) is handled via its service
    //    (stop+delete, else set to manual start); a user-mode image via its
    //    process(es). Then 3. retry the quarantine.
    let stopped = if path.extension().map_or(false, |e| e.eq_ignore_ascii_case("sys")) {
        handle_driver_service(path)
    } else {
        terminate_image_processes(path)
    };
    if quarantine_file(path, quarantine_dir).is_ok() {
        return EscalationOutcome::KilledAndQuarantined(stopped);
    }

    // 4. Still stuck → defer to next boot.
    match schedule_restart_disinfection(path, reason, quarantine_dir) {
        Ok(detail) => {
            let reboot = allow_reboot && reboot_for_disinfection(reason).is_ok();
            EscalationOutcome::ScheduledForRestart { reboot, detail }
        }
        Err(e) => EscalationOutcome::Failed(e),
    }
}

// ---------------------------------------------------------------------------
// Process termination (with critical-process handling)
// ---------------------------------------------------------------------------

/// Terminate every process whose image is `target`. Returns the kill count.
pub fn terminate_image_processes(target: &Path) -> usize {
    let want = canonical_lossy(target);
    let self_pid = unsafe { GetCurrentProcessId() };
    let mut killed = 0usize;

    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return 0;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0 && pid != self_pid {
                    if let Some(img) = process_image_path(pid) {
                        if canonical_lossy(Path::new(&img)) == want && terminate_pid(pid) {
                            killed += 1;
                        }
                    }
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    killed
}

/// Full image path of a process, or `None` if it can't be queried.
fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        res.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Terminate `pid`. If `TerminateProcess` fails because the process marked itself
/// critical, clear the flag via `NtSetInformationProcess` and retry.
fn terminate_pid(pid: u32) -> bool {
    unsafe {
        let access = PROCESS_TERMINATE | PROCESS_SET_INFORMATION;
        let Ok(handle) = OpenProcess(access, false, pid) else {
            return false;
        };
        let mut ok = TerminateProcess(handle, 1).is_ok();
        if !ok {
            // Possibly a critical process — clear the flag and retry.
            set_process_critical(handle, false);
            ok = TerminateProcess(handle, 1).is_ok();
        }
        let _ = CloseHandle(handle);
        ok
    }
}

/// Set/clear a process's `ProcessBreakOnTermination` (critical) flag via
/// `ntdll!NtSetInformationProcess`, resolved dynamically.
fn set_process_critical(handle: HANDLE, critical: bool) {
    type NtSetInfoProc =
        unsafe extern "system" fn(HANDLE, u32, *const c_void, u32) -> i32;
    unsafe {
        let Ok(ntdll) = GetModuleHandleW(PCWSTR(wide("ntdll.dll").as_ptr())) else {
            return;
        };
        let Some(proc) = GetProcAddress(ntdll, windows::core::PCSTR(b"NtSetInformationProcess\0".as_ptr()))
        else {
            return;
        };
        let f: NtSetInfoProc = std::mem::transmute(proc);
        let value: u32 = critical as u32;
        let _ = f(
            handle,
            PROCESS_BREAK_ON_TERMINATION,
            &value as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        );
    }
}

// ---------------------------------------------------------------------------
// Kernel driver (.sys) service handling — all via the SCM API (no sc.exe)
// ---------------------------------------------------------------------------

/// Handle a malicious driver's service(s): stop + delete via the SCM
/// (`delete_service`, which marks a running driver for deletion on reboot). If
/// deletion fails, fall back to setting the service to **manual start** so it
/// won't auto-load on the next boot. Returns the number of services acted on.
fn handle_driver_service(path: &Path) -> usize {
    let services = find_services_for_image(path);
    for svc in &services {
        if crate::remediation::delete_service(svc).is_err() {
            // Couldn't stop/delete it now → at least stop it auto-starting.
            set_service_start_manual(svc);
        }
    }
    services.len()
}

/// Find service name(s) whose binary path points at `target`, enumerating driver
/// services through the SCM API (`EnumServicesStatusExW` + `QueryServiceConfigW`)
/// — pure advapi32, no `sc.exe`.
fn find_services_for_image(target: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Some(fname) = target.file_name().and_then(|s| s.to_str()) else {
        return out;
    };
    let want = fname.to_ascii_lowercase(); // "driver.sys"

    unsafe {
        let Ok(scm) = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        ) else {
            return out;
        };

        // First call sizes the buffer (returns ERROR_MORE_DATA).
        let mut needed = 0u32;
        let mut returned = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        );
        if needed > 0 {
            let mut buf = vec![0u8; needed as usize];
            resume = 0;
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
            .is_ok();
            if ok {
                // The records sit at the buffer start; their name strings live
                // elsewhere in the same buffer (pointed to by the PWSTR fields).
                let recs = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
                for i in 0..returned as usize {
                    let rec = &*recs.add(i);
                    let name = pwstr_to_string(rec.lpServiceName);
                    if name.is_empty() {
                        continue;
                    }
                    if let Some(bin) = service_binary_path(scm, &name) {
                        let bin = bin.to_ascii_lowercase().replace('/', "\\");
                        if bin.ends_with(&want) || bin.contains(&format!("\\{want}")) {
                            out.push(name);
                        }
                    }
                }
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    out
}

/// The configured binary path of a service via `QueryServiceConfigW` (SCM API).
unsafe fn service_binary_path(scm: SC_HANDLE, name: &str) -> Option<String> {
    unsafe {
        let svc = OpenServiceW(scm, PCWSTR(wide(name).as_ptr()), SERVICE_QUERY_CONFIG).ok()?;
        let mut needed = 0u32;
        // First call sizes the config buffer.
        let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
        let result = if needed > 0 {
            let mut buf = vec![0u8; needed as usize];
            let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
            if QueryServiceConfigW(svc, Some(cfg), needed, &mut needed).is_ok() {
                Some(pwstr_to_string((*cfg).lpBinaryPathName))
            } else {
                None
            }
        } else {
            None
        };
        let _ = CloseServiceHandle(svc);
        result
    }
}

/// Read a NUL-terminated wide string from a `PWSTR` (empty when null).
unsafe fn pwstr_to_string(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.0.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
    }
}

/// Set a service's start type to **manual** (`SERVICE_DEMAND_START`) via
/// `ChangeServiceConfigW` (SCM API). Returns true on success.
fn set_service_start_manual(name: &str) -> bool {
    const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let result = match OpenServiceW(scm, PCWSTR(wide(name).as_ptr()), SERVICE_CHANGE_CONFIG) {
            Ok(svc) => {
                let ok = ChangeServiceConfigW(
                    svc,
                    ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE), // service type: unchanged
                    SERVICE_DEMAND_START,                 // start type: manual
                    SERVICE_ERROR(SERVICE_NO_CHANGE),     // error control: unchanged
                    PCWSTR::null(),                       // binary path: unchanged
                    PCWSTR::null(),                       // load order group
                    None,                                 // tag id
                    PCWSTR::null(),                       // dependencies
                    PCWSTR::null(),                       // service start name
                    PCWSTR::null(),                       // password
                    PCWSTR::null(),                       // display name
                )
                .is_ok();
                let _ = CloseServiceHandle(svc);
                ok
            }
            Err(_) => false,
        };
        let _ = CloseServiceHandle(scm);
        result
    }
}

// ---------------------------------------------------------------------------
// Deferred (boot-time) disinfection
// ---------------------------------------------------------------------------

/// Defer `path`'s cleanup to the next boot: record a marker (what + why), schedule
/// the locked file for deletion on reboot, and register a `RunOnce` re-run.
pub fn schedule_restart_disinfection(
    path: &Path,
    reason: &str,
    quarantine_dir: &Path,
) -> Result<String, String> {
    // Marker: append "<path>\t<reason>" so the boot-time pass knows what/why.
    let marker = quarantine_dir.join(PENDING_MARKER);
    let _ = std::fs::create_dir_all(quarantine_dir);
    let line = format!("{}\t{}\r\n", path.display(), reason);
    let prev = std::fs::read_to_string(&marker).unwrap_or_default();
    std::fs::write(&marker, format!("{prev}{line}"))
        .map_err(|e| format!("write marker: {e}"))?;

    // Schedule the locked file for deletion on reboot (best-effort).
    let delayed_delete = unsafe {
        MoveFileExW(
            PCWSTR(wide(&path.to_string_lossy()).as_ptr()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
        .is_ok()
    };

    // RunOnce: re-run ourselves at next logon to finish the job.
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let cmd = format!("\"{}\" --disinfect-pending", exe.display());
    let runonce = set_runonce(&cmd, reason)?;

    Ok(format!(
        "deferred to restart ({runonce}; delete-on-reboot={delayed_delete}; marker={})",
        marker.display()
    ))
}

/// Write the `RunOnce` value (HKLM, falling back to HKCU without admin) plus a
/// human-readable reason value as the persistence "signature".
fn set_runonce(cmd: &str, reason: &str) -> Result<String, String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
    use winreg::RegKey;
    const RUNONCE: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";

    let write = |hive: winreg::HKEY| -> std::io::Result<()> {
        let (key, _) = RegKey::predef(hive).create_subkey_with_flags(RUNONCE, KEY_SET_VALUE)?;
        key.set_value(RUNONCE_VALUE, &cmd.to_string())?;
        // The "why" marker, so the persistence is self-documenting.
        key.set_value(
            format!("{RUNONCE_VALUE}Reason"),
            &format!("HydraDragon scheduled disinfection: {reason}"),
        )?;
        Ok(())
    };

    if write(HKEY_LOCAL_MACHINE).is_ok() {
        Ok("RunOnce(HKLM)".into())
    } else {
        write(HKEY_CURRENT_USER)
            .map(|_| "RunOnce(HKCU)".into())
            .map_err(|e| format!("RunOnce write: {e}"))
    }
}

/// Process the boot-time pending list (the `--disinfect-pending` entry point):
/// quarantine each recorded file, then clear the marker. Returns status lines.
pub fn run_pending_disinfection(quarantine_dir: &Path) -> Vec<String> {
    let marker = quarantine_dir.join(PENDING_MARKER);
    let Ok(content) = std::fs::read_to_string(&marker) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let (path, reason) = line.split_once('\t').unwrap_or((line, ""));
        let p = Path::new(path.trim());
        if !p.exists() {
            out.push(format!("{path}: already gone ({reason})"));
            continue;
        }
        match quarantine_file(p, quarantine_dir) {
            Ok(_) => out.push(format!("{path}: quarantined ({reason})")),
            Err(e) => out.push(format!("{path}: still failed: {e}")),
        }
    }
    let _ = std::fs::remove_file(&marker);
    out
}

// ---------------------------------------------------------------------------
// Reboot
// ---------------------------------------------------------------------------

/// Reboot the machine to complete disinfection, after a 30s warning the user can
/// abort with `shutdown /a`. Requires `SeShutdownPrivilege` (enabled here).
pub fn reboot_for_disinfection(reason: &str) -> Result<(), String> {
    enable_shutdown_privilege()?;
    let msg = format!(
        "HydraDragon Antivirus will restart this computer in 30 seconds to finish removing a threat ({reason}). Run 'shutdown /a' to cancel."
    );
    unsafe {
        InitiateSystemShutdownExW(
            PCWSTR::null(),
            PCWSTR(wide(&msg).as_ptr()),
            30,
            false, // don't force apps closed (let the user save work)
            true,  // reboot after shutdown
            SHTDN_REASON_MAJOR_APPLICATION
                | SHTDN_REASON_MINOR_SECURITYFIX
                | SHTDN_REASON_FLAG_PLANNED,
        )
        .map_err(|e| format!("InitiateSystemShutdownEx: {e}"))
    }
}

/// Enable `SeShutdownPrivilege` on the current process token (needed to reboot).
fn enable_shutdown_privilege() -> Result<(), String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| format!("OpenProcessToken: {e}"))?;

        let mut luid = LUID::default();
        LookupPrivilegeValueW(
            PCWSTR::null(),
            PCWSTR(wide("SeShutdownPrivilege").as_ptr()),
            &mut luid,
        )
        .map_err(|e| format!("LookupPrivilegeValue: {e}"))?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let res = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        let _ = CloseHandle(token);
        res.map_err(|e| format!("AdjustTokenPrivileges: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonicalize for comparison, falling back to a lowercased lossy string when
/// the path can't be canonicalized (e.g. already deleted).
fn canonical_lossy(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| {
        PathBuf::from(p.to_string_lossy().to_ascii_lowercase().replace('/', "\\"))
    })
}
