#![allow(dead_code)]

use crate::logging::Logging;
use crate::utils::protected_process_reason;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{ProcessesToUpdate, System};
use windows::Win32::Foundation::{BOOL, CloseHandle};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING, MoveFileExW,
    SetFileAttributesW,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
use windows::core::PCWSTR;

const QUARANTINE_MAGIC: &[u8; 7] = b"HYDRA\x00\x01";
const XOR_KEY: u8 = 0xA5;

#[derive(Serialize, Deserialize, Debug)]
pub struct QuarantineMeta {
    pub original_path: String,
    pub detection: String,
    pub sha256: String,
    pub timestamp: u64,
    pub original_size: usize,
}

#[derive(Debug)]
pub enum QuarantineError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidMagic,
}

impl From<io::Error> for QuarantineError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for QuarantineError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::InvalidMagic => write!(f, "Not a HydraDragon quarantine file"),
        }
    }
}

impl std::error::Error for QuarantineError {}

pub fn compute_sha256(src: &Path) -> Result<String, QuarantineError> {
    let mut file = fs::File::open(src)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Normalize path for usermode file access.
pub fn normalize_usermode_path(path: &Path) -> PathBuf {
    let normalized = path.to_string_lossy().replace('/', "\\");
    let lowered = normalized.to_ascii_lowercase();

    if lowered.starts_with(r"\\?\") || lowered.starts_with(r"\??\") {
        PathBuf::from(normalized)
    } else if lowered.starts_with(r"\device\") {
        PathBuf::from(format!(r"\\?\GLOBALROOT{}", normalized))
    } else {
        PathBuf::from(normalized)
    }
}

/// Quarantine a file into a .hqf container.
///
/// Container format:
/// [7B  magic        ]
/// [4B  metadata_len ] (little-endian u32)
/// [NB  metadata JSON]
/// [4B  payload_len  ] (little-endian u32)
/// [NB  XOR'd payload]
pub fn quarantine_file(
    src: &Path,
    dst: &Path,
    detection: &str,
    sha256: &str,
) -> Result<(), QuarantineError> {
    let payload = fs::read(src)?;

    let xored: Vec<u8> = payload.iter().map(|b| b ^ XOR_KEY).collect();

    let meta = QuarantineMeta {
        original_path: src.to_string_lossy().to_string(),
        detection: detection.to_string(),
        sha256: sha256.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        original_size: payload.len(),
    };

    let meta_bytes = serde_json::to_vec(&meta)?;

    let mut file = fs::File::create(dst)?;
    file.write_all(QUARANTINE_MAGIC)?;
    file.write_all(&(meta_bytes.len() as u32).to_le_bytes())?;
    file.write_all(&meta_bytes)?;
    file.write_all(&(xored.len() as u32).to_le_bytes())?;
    file.write_all(&xored)?;

    Ok(())
}

/// Build a unique quarantine destination path in `qdir`.
pub fn build_quarantine_destination(src: &Path, qdir: &Path) -> PathBuf {
    let filename = src
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("quarantined_file");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let prefix = format!("{}_{}", ts.as_secs(), ts.subsec_nanos());

    let mut counter = 0_u32;
    loop {
        let suffix = if counter == 0 {
            String::new()
        } else {
            format!("_{counter}")
        };
        let dst = qdir.join(format!("{prefix}_{filename}{suffix}.hqf"));
        if !dst.exists() {
            return dst;
        }
        counter = counter.saturating_add(1);
    }
}

/// Enumerate and terminate any running process executing or locking `path`.
pub fn terminate_processes_locking_path(path: &Path) -> usize {
    let target_norm = normalize_usermode_path(path);
    let target_canonical =
        std::fs::canonicalize(&target_norm).unwrap_or_else(|_| target_norm.clone());
    let target_str = target_norm.to_string_lossy().to_lowercase();
    let target_canon_str = target_canonical.to_string_lossy().to_lowercase();
    let target_name = target_norm
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if target_name.is_empty() {
        return 0;
    }

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut killed_count = 0;

    for (pid, process) in sys.processes() {
        let mut is_match = false;
        if let Some(exe) = process.exe() {
            let exe_norm = normalize_usermode_path(exe);
            let exe_str = exe_norm.to_string_lossy().to_lowercase();
            if exe_str == target_str || exe_str == target_canon_str {
                is_match = true;
            } else if let Ok(exe_canon) = std::fs::canonicalize(&exe_norm) {
                if exe_canon.to_string_lossy().to_lowercase() == target_canon_str {
                    is_match = true;
                }
            }
        }

        if !is_match {
            let proc_name = process.name().to_string_lossy().to_lowercase();
            if proc_name == target_name {
                is_match = true;
            }
        }

        if is_match {
            let pid_u32 = pid.as_u32();
            if let Some(reason) = protected_process_reason(pid_u32, Some(&target_norm)) {
                Logging::warning(&format!(
                    "[Quarantine] Refusing to terminate protected process PID {} for file {}: {}",
                    pid_u32,
                    target_norm.display(),
                    reason
                ));
                continue;
            }

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, BOOL(0), pid_u32) {
                    if TerminateProcess(handle, 1).as_bool() {
                        Logging::info(&format!(
                            "[Quarantine] Terminated locking process PID {} ({}) for {}",
                            pid_u32,
                            process.name().to_string_lossy(),
                            target_norm.display()
                        ));
                        killed_count += 1;
                    }
                    let _ = CloseHandle(handle);
                }
            }
        }
    }

    if killed_count > 0 {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    killed_count
}

/// Forcibly remove file immediately: clears file attributes, terminates running
/// process instances of the binary, truncates file bytes and moves to temp trash if locked.
pub fn try_delete_file_now(path: &Path) -> std::io::Result<()> {
    let norm_path = normalize_usermode_path(path);
    if !norm_path.exists() {
        return Ok(());
    }

    // Step 1: Clear read-only and restrictive attributes
    if let Ok(metadata) = std::fs::metadata(&norm_path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(&norm_path, permissions);
        }
    }

    let wide_path: Vec<u16> = norm_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let _ = SetFileAttributesW(PCWSTR(wide_path.as_ptr()), FILE_ATTRIBUTE_NORMAL);
    }

    // Step 2: Try immediate removal
    if std::fs::remove_file(&norm_path).is_ok() {
        return Ok(());
    }

    // Step 3: Terminate locking processes
    terminate_processes_locking_path(&norm_path);

    // Step 4: Retry removal after killing process
    if std::fs::remove_file(&norm_path).is_ok() {
        return Ok(());
    }

    // Step 5: Truncate file bytes to 0 to neutralize malware payload immediately even if handle locked
    if let Ok(file) = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&norm_path)
    {
        let _ = file.set_len(0);
    }

    // Step 6: Move locked file to temporary trash to free original path
    let temp_trash = std::env::temp_dir().join(format!(
        "hd_del_{}_{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let wide_trash: Vec<u16> = temp_trash
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        if MoveFileExW(
            PCWSTR(wide_path.as_ptr()),
            PCWSTR(wide_trash.as_ptr()),
            MOVEFILE_REPLACE_EXISTING,
        )
        .as_bool()
        {
            Logging::info(&format!(
                "[Quarantine] Moved locked malicious file {} to trash {}",
                norm_path.display(),
                temp_trash.display()
            ));
            if std::fs::remove_file(&temp_trash).is_err() {
                let _ = schedule_delete_on_reboot(&temp_trash);
            }
            return Ok(());
        }
    }

    std::fs::remove_file(&norm_path)
}

/// Schedule file removal on reboot via MoveFileExW.
pub fn schedule_delete_on_reboot(path: &Path) -> std::io::Result<()> {
    let norm_path = normalize_usermode_path(path);
    let wide_path: Vec<u16> = norm_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        if MoveFileExW(
            PCWSTR(wide_path.as_ptr()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
        .as_bool()
        {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// Attempt immediate file deletion, falling back to reboot deletion only if all immediate actions fail.
pub fn delete_with_reboot_fallback(path: &Path) -> bool {
    let norm_path = normalize_usermode_path(path);
    match try_delete_file_now(&norm_path) {
        Ok(_) => {
            Logging::alert(&format!(
                "[Quarantine] Removed malicious artifact: {}",
                norm_path.display()
            ));
            true
        }
        Err(delete_error) if delete_error.kind() == std::io::ErrorKind::NotFound => {
            Logging::info(&format!(
                "[Quarantine] Artifact already absent: {}",
                norm_path.display()
            ));
            true
        }
        Err(delete_error) => {
            Logging::warning(&format!(
                "[Quarantine] Immediate delete failed for {}: {}",
                norm_path.display(),
                delete_error
            ));

            match schedule_delete_on_reboot(&norm_path) {
                Ok(_) => {
                    Logging::alert(&format!(
                        "[Quarantine] Removal scheduled for reboot: {}",
                        norm_path.display()
                    ));
                    true
                }
                Err(schedule_error) => {
                    Logging::error(&format!(
                        "[Quarantine] Failed to schedule reboot removal for {}: {}",
                        norm_path.display(),
                        schedule_error
                    ));
                    false
                }
            }
        }
    }
}

/// Seal a file into a .hqf quarantine container and remove the original.
/// Returns the quarantine container path on success.
pub fn quarantine_path(src: &Path, detection: &str) -> Result<PathBuf, QuarantineError> {
    let qdir = Path::new(crate::shared_def::QUARANTINE_PATH);
    std::fs::create_dir_all(qdir)?;
    let dst = build_quarantine_destination(src, qdir);
    let sha256 = compute_sha256(src).unwrap_or_else(|_| "unknown".to_string());

    quarantine_file(src, &dst, detection, &sha256)?;

    if !delete_with_reboot_fallback(src) {
        Logging::warning(&format!(
            "[Quarantine] Container created, but cleanup of the original file failed: {}",
            src.display()
        ));
    }
    Ok(dst)
}

/// Restore a .hqf quarantine file back to its original bytes.
pub fn restore_file(src: &Path, dst: &Path) -> Result<QuarantineMeta, QuarantineError> {
    let mut file = fs::File::open(src)?;

    let mut magic = [0_u8; 7];
    file.read_exact(&mut magic)?;
    if &magic != QUARANTINE_MAGIC {
        return Err(QuarantineError::InvalidMagic);
    }

    let mut len_buf = [0_u8; 4];
    file.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;

    let mut meta_bytes = vec![0_u8; meta_len];
    file.read_exact(&mut meta_bytes)?;
    let meta: QuarantineMeta = serde_json::from_slice(&meta_bytes)?;

    file.read_exact(&mut len_buf)?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    let mut xored = vec![0_u8; payload_len];
    file.read_exact(&mut xored)?;

    let payload: Vec<u8> = xored.iter().map(|b| b ^ XOR_KEY).collect();
    fs::write(dst, &payload)?;

    Ok(meta)
}

/// Read metadata from a .hqf file without restoring the payload.
pub fn read_meta(src: &Path) -> Result<QuarantineMeta, QuarantineError> {
    let mut file = fs::File::open(src)?;

    let mut magic = [0_u8; 7];
    file.read_exact(&mut magic)?;
    if &magic != QUARANTINE_MAGIC {
        return Err(QuarantineError::InvalidMagic);
    }

    let mut len_buf = [0_u8; 4];
    file.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;

    let mut meta_bytes = vec![0_u8; meta_len];
    file.read_exact(&mut meta_bytes)?;

    Ok(serde_json::from_slice(&meta_bytes)?)
}
