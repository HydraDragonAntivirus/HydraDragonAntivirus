#![allow(dead_code)]

use crate::logging::Logging;
use crate::utils::protected_process_reason;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
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
    Excluded,
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
            Self::Excluded => write!(f, "Excluded by user (quarantine_exclusions.txt)"),
        }
    }
}

impl std::error::Error for QuarantineError {}

// ── User exclusion list ────────────────────────────────────────────────────
// Plain text next to the store, one rule per line:
//   path:<lowercase path>   exact file path match
//   hash:<lowercase hex>    content match (any location)
// Lines starting with '#' and blanks are ignored. Loaded fresh on every
// check so GUI edits apply without restart. Excluded files are left alone
// entirely: no container, no delete, no block push.

fn exclusions_path() -> PathBuf {
    PathBuf::from(crate::shared_def::QUARANTINE_PATH).join("quarantine_exclusions.txt")
}

fn load_exclusions() -> (HashSet<String>, HashSet<String>) {
    let mut paths = HashSet::new();
    let mut hashes = HashSet::new();
    if let Ok(content) = std::fs::read_to_string(exclusions_path()) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(p) = line.strip_prefix("path:") {
                let p = p.trim().to_ascii_lowercase();
                if !p.is_empty() {
                    paths.insert(p);
                }
            } else if let Some(h) = line.strip_prefix("hash:") {
                let h = h.trim().to_ascii_lowercase();
                if !h.is_empty() {
                    hashes.insert(h);
                }
            }
        }
    }
    (paths, hashes)
}

/// True when the user excluded this exact path or content hash.
pub fn is_excluded(path: &Path, sha256: &str) -> bool {
    let (paths, hashes) = load_exclusions();
    if paths.contains(&path.to_string_lossy().to_ascii_lowercase()) {
        return true;
    }
    let s = sha256.trim().to_ascii_lowercase();
    !s.is_empty() && s != "unknown" && hashes.contains(&s)
}

fn append_exclusion_line(line: &str) -> io::Result<()> {
    use std::fmt::Write as _;
    let p = exclusions_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut existing = std::fs::read_to_string(&p).unwrap_or_default();
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    let _ = write!(existing, "{line}\n");
    std::fs::write(&p, existing)?;
    Ok(())
}

/// Find an existing quarantine container holding the same payload hash.
///
/// Store-level dedup ONLY: the caller must still neutralize the live file
/// (delete + block). This never becomes a "seen before, skip action"
/// allowlist — identical bytes simply don't get a second container.
pub fn find_existing_container_by_hash(qdir: &Path, sha256: &str) -> Option<PathBuf> {
    if sha256.is_empty() || sha256 == "unknown" {
        return None;
    }
    // Cap the scan (most-recent-first): a full walk per quarantine would be
    // O(n^2) during ransomware storms with thousands of containers.
    const SCAN_CAP: usize = 2048;
    let mut candidates: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(qdir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("hqf") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        candidates.push((mtime, path));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in candidates.into_iter().take(SCAN_CAP) {
        if let Ok(meta) = read_meta(&path) {
            if meta.sha256 == sha256 {
                return Some(path);
            }
        }
    }
    None
}

struct IncidentState {
    window_start: u64,
    reported: bool,
    suppressed: u64,
}

fn incidents() -> &'static Mutex<HashMap<String, IncidentState>> {
    static MAP: OnceLock<Mutex<HashMap<String, IncidentState>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Incident-aggregated alert: one virus action finishes with a single attack
/// record instead of one warning per file.
///
/// First event in a window alerts immediately; further events with the same
/// key are counted silently; when the window expires a single summary alert
/// closes it. Window: 10 minutes per key (detection label).
pub fn incident_alert(key: &str, message: &str) {
    const WINDOW_SECS: u64 = 600;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut map = match incidents().lock() {
        Ok(g) => g,
        Err(_) => {
            Logging::alert(message);
            return;
        }
    };
    let st = map.entry(key.to_string()).or_insert(IncidentState {
        window_start: now,
        reported: false,
        suppressed: 0,
    });
    if now.saturating_sub(st.window_start) >= WINDOW_SECS {
        if st.reported && st.suppressed > 0 {
            Logging::alert(&format!(
                "Ongoing incident '{}': {} additional events suppressed in the last 10 minutes",
                key, st.suppressed
            ));
        }
        st.window_start = now;
        st.reported = false;
        st.suppressed = 0;
    }
    if !st.reported {
        Logging::alert(message);
        st.reported = true;
    } else {
        st.suppressed = st.suppressed.saturating_add(1);
    }
}

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
    let sha256 = compute_sha256(src).unwrap_or_else(|_| "unknown".to_string());

    // User exclusion wins over everything: leave the file alone entirely.
    if is_excluded(src, &sha256) {
        Logging::info(&format!(
            "[Quarantine] Skipped (user exclusion): {}",
            src.display()
        ));
        return Err(QuarantineError::Excluded);
    }

    // Store dedup: same bytes already sealed -> reuse the container.
    // The live file is STILL neutralized below; dedup never skips action.
    if let Some(existing) = find_existing_container_by_hash(qdir, &sha256) {
        Logging::info(&format!(
            "[Quarantine] Duplicate store suppressed (already stored): {} -> {}",
            src.display(),
            existing.display()
        ));
        if !delete_with_reboot_fallback(src) {
            Logging::warning(&format!(
                "[Quarantine] Duplicate container reused, but cleanup of the live file failed: {}",
                src.display()
            ));
        }
        return Ok(existing);
    }

    let dst = build_quarantine_destination(src, qdir);

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
    // Integrity: never restore bytes that don't match the sealed hash.
    // (meta "unknown" means the hash was unavailable at seal time: skip check.)
    if !meta.sha256.is_empty() && meta.sha256 != "unknown" {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        if hex::encode(hasher.finalize()) != meta.sha256 {
            return Err(QuarantineError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "quarantine payload hash mismatch: refusing restore",
            )));
        }
    }
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

// ── Quarantine manager FFI (dumb UI shell calls these) ─────────────────────

fn utf16_path(ptr: *const u16, len: u32) -> Option<PathBuf> {
    if ptr.is_null() || len == 0 || len > 32768 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Some(PathBuf::from(String::from_utf16_lossy(slice)))
}

fn utf16_str(ptr: *const u16, len: u32) -> Option<String> {
    if ptr.is_null() || len == 0 || len > 32768 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Some(String::from_utf16_lossy(slice))
}

fn write_json_out(json: &str, out_buf: *mut u8, buf_len: u32) -> u32 {
    let bytes = json.as_bytes();
    if out_buf.is_null() || buf_len == 0 {
        return bytes.len() as u32;
    }
    let n = (buf_len as usize).min(bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, n);
    }
    n as u32
}

/// Containment: the container must resolve inside the quarantine dir.
/// Blocks `..\` escapes and absolute-path tricks from hostile callers.
fn contained_container(path: &Path) -> Option<PathBuf> {
    let root = PathBuf::from(crate::shared_def::QUARANTINE_PATH);
    let root_c = std::fs::canonicalize(&root).ok()?;
    let full_c = std::fs::canonicalize(path).ok()?;
    if full_c.starts_with(&root_c)
        && full_c.extension().and_then(|e| e.to_str()) == Some("hqf")
    {
        Some(full_c)
    } else {
        None
    }
}

/// Lists quarantine containers as JSON
/// (`[{container,original,detection,sha256,timestamp,size}]`, newest first).
/// Null buffer (or 0 length) returns the needed size.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_quarantine_list(out_buf: *mut u8, buf_len: u32) -> u32 {
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let qdir = PathBuf::from(crate::shared_def::QUARANTINE_PATH);
    if let Ok(entries) = std::fs::read_dir(&qdir) {
        let mut metas: Vec<(u64, PathBuf, QuarantineMeta)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("hqf") {
                continue;
            }
            if let Ok(meta) = read_meta(&path) {
                metas.push((meta.timestamp, path, meta));
            }
        }
        metas.sort_by(|a, b| b.0.cmp(&a.0));
        for (ts, path, meta) in &metas {
            rows.push(serde_json::json!({
                "container": path.to_string_lossy(),
                "original": meta.original_path,
                "detection": meta.detection,
                "sha256": meta.sha256,
                "timestamp": ts,
                "size": meta.original_size,
            }));
        }
    }
    write_json_out(&serde_json::Value::Array(rows).to_string(), out_buf, buf_len)
}

/// Restores a container to its original path (hash-verified by
/// [`restore_file`]) and removes the container. Returns 0 on success,
/// -1 bad arguments / outside quarantine dir, -2 restore failed.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_quarantine_restore(
    container_ptr: *const u16,
    container_len: u32,
) -> i32 {
    let Some(path) = utf16_path(container_ptr, container_len) else {
        return -1;
    };
    let Some(full) = contained_container(&path) else {
        Logging::error("[Quarantine] Restore refused: outside quarantine dir");
        return -1;
    };
    let meta = match read_meta(&full) {
        Ok(m) => m,
        Err(e) => {
            Logging::error(&format!("[Quarantine] Restore failed (unreadable): {e}"));
            return -2;
        }
    };
    let dst = PathBuf::from(&meta.original_path);
    match restore_file(&full, &dst) {
        Ok(_) => {
            Logging::warning(&format!(
                "[Quarantine] Restored {} from {}",
                dst.display(),
                full.display()
            ));
            let _ = std::fs::remove_file(&full);
            0
        }
        Err(e) => {
            Logging::error(&format!("[Quarantine] Restore failed: {e}"));
            -2
        }
    }
}

/// Permanently deletes a quarantine container. Returns 0 on success
/// (already-absent counts as success), -1 bad arguments / outside dir,
/// -2 on I/O failure.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_quarantine_delete(
    container_ptr: *const u16,
    container_len: u32,
) -> i32 {
    let Some(path) = utf16_path(container_ptr, container_len) else {
        return -1;
    };
    let Some(full) = contained_container(&path) else {
        Logging::error("[Quarantine] Delete refused: outside quarantine dir");
        return -1;
    };
    match std::fs::remove_file(&full) {
        Ok(_) => {
            Logging::warning(&format!("[Quarantine] Deleted container {}", full.display()));
            0
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            Logging::error(&format!("[Quarantine] Delete failed: {e}"));
            -2
        }
    }
}

/// Lists user exclusions as JSON (`[{kind,value}]`, kind 0=path, 1=hash).
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_exclusion_list(out_buf: *mut u8, buf_len: u32) -> u32 {
    let (paths, hashes) = load_exclusions();
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut pv: Vec<&String> = paths.iter().collect();
    pv.sort();
    for p in pv {
        rows.push(serde_json::json!({ "kind": 0, "value": p }));
    }
    let mut hv: Vec<&String> = hashes.iter().collect();
    hv.sort();
    for h in hv {
        rows.push(serde_json::json!({ "kind": 1, "value": h }));
    }
    write_json_out(&serde_json::Value::Array(rows).to_string(), out_buf, buf_len)
}

/// Adds an exclusion (kind 0=path, 1=hash; value UTF-16). Returns 0 on
/// success (already-present counts as success), -1 bad arguments.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_exclusion_add(
    kind: u32,
    value_ptr: *const u16,
    value_len: u32,
) -> i32 {
    let Some(value) = utf16_str(value_ptr, value_len) else {
        return -1;
    };
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return -1;
    }
    let line = match kind {
        0 => format!("path:{value}"),
        1 => format!("hash:{value}"),
        _ => return -1,
    };
    let (paths, hashes) = load_exclusions();
    if paths.contains(&value) || hashes.contains(&value) {
        return 0;
    }
    match append_exclusion_line(&line) {
        Ok(_) => {
            Logging::warning(&format!("[Quarantine] Exclusion added: {line}"));
            0
        }
        Err(e) => {
            Logging::error(&format!("[Quarantine] Exclusion add failed: {e}"));
            -2
        }
    }
}

/// Removes an exclusion (kind 0=path, 1=hash). Returns 0 on success
/// (absent counts as success), -1 bad arguments, -2 on I/O failure.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_exclusion_remove(
    kind: u32,
    value_ptr: *const u16,
    value_len: u32,
) -> i32 {
    let Some(value) = utf16_str(value_ptr, value_len) else {
        return -1;
    };
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || (kind != 0 && kind != 1) {
        return -1;
    }
    let prefix = if kind == 0 { "path:" } else { "hash:" };
    let p = exclusions_path();
    let content = std::fs::read_to_string(&p).unwrap_or_default();
    let mut kept = Vec::new();
    let mut removed = false;
    for line in content.lines() {
        let t = line.trim();
        if t.eq_ignore_ascii_case(&format!("{prefix}{value}")) {
            removed = true;
            continue;
        }
        kept.push(line);
    }
    if !removed {
        return 0;
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    match std::fs::write(&p, out) {
        Ok(_) => {
            Logging::warning(&format!("[Quarantine] Exclusion removed: {prefix}{value}"));
            0
        }
        Err(e) => {
            Logging::error(&format!("[Quarantine] Exclusion remove failed: {e}"));
            -2
        }
    }
}
