use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};
use lru::LruCache;

use crate::logging::Logging;
use crate::ml::fast_detect::fast_detect_path;
use crate::threat_handler::{QuarantineMetadata, ThreatHandler};

/// Represents an asynchronous background scanning task submitted by real-time protection.
#[derive(Debug, Clone)]
pub struct DaemonScanTask {
    pub path: PathBuf,
    pub is_actor_target: bool,
    pub pid: u32,
    pub gid: u64,
    pub appname: String,
}

pub(crate) struct DaemonScannerState {
    tx: Sender<DaemonScanTask>,
    recent_scans: Mutex<LruCache<PathBuf, Instant>>,
    threat_handler: Mutex<Option<Arc<dyn ThreatHandler>>>,
}

static SCANNER: OnceLock<DaemonScannerState> = OnceLock::new();

/// Initialize or retrieve the daemon scanner worker pool.
/// Spawns 4 background worker threads that process ML and ClamAV scans asynchronously
/// without blocking the kernel I/O event loop.
pub(crate) fn ensure_daemon_scanner() -> &'static DaemonScannerState {
    SCANNER.get_or_init(|| {
        let (tx, rx) = bounded::<DaemonScanTask>(65536);
        let cache_cap = NonZeroUsize::new(16384).unwrap();
        let recent_scans = Mutex::new(LruCache::new(cache_cap));
        let threat_handler = Mutex::new(None);

        // Spawn a single background daemon scanner worker thread to ensure memory
        // remains capped at ~900MB (preventing multi-thread archive & buffer multiplication)
        let thread_rx = rx.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("daemon_scanner_worker".to_string())
            .spawn(move || {
                worker_loop(thread_rx);
            })
        {
            Logging::error(&format!(
                "[DaemonScanner] Failed to spawn worker thread: {}",
                e
            ));
        }

        Logging::info("[DaemonScanner] Background daemon scan worker initialized (single-thread, RAM-capped)");

        DaemonScannerState {
            tx,
            recent_scans,
            threat_handler,
        }
    })
}

/// Attach an active ThreatHandler (driver-level kill and quarantine) to the daemon scanner.
pub fn init_daemon_scanner(handler: Arc<dyn ThreatHandler>) {
    let state = ensure_daemon_scanner();
    if let Ok(mut guard) = state.threat_handler.lock() {
        *guard = Some(handler);
    }
}

fn worker_loop(rx: Receiver<DaemonScanTask>) {
    while let Ok(task) = rx.recv() {
        let path_str = match task.path.to_str() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let p = Path::new(path_str);
        if !p.is_file() {
            continue;
        }

        // 0. Skip user-defined exclusions
        if crate::windows::quarantine::is_excluded(p, "") {
            continue;
        }

        // 0.1 Skip files signed by a trusted company publisher (e.g. Microsoft, Google, Intel)
        if task.is_actor_target || path_str.ends_with(".exe") || path_str.ends_with(".dll") || path_str.ends_with(".sys") {
            let sig_info = crate::signature_verification::verify_signature(p);
            if sig_info.is_trusted {
                if let Some(signer) = sig_info.signer_name {
                    if crate::signer_rules::is_trusted_signer(&signer) {
                        continue;
                    }
                }
            }
        }

        let mut det = None;

        // 1. Check EICAR standard test string
        if let Ok(meta) = std::fs::metadata(p) {
            if matches!(meta.len(), 68..=128) {
                if let Ok(bytes) = crate::utils::read_file_shared(p) {
                    const EICAR_STR: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
                    if bytes.starts_with(EICAR_STR.as_bytes()) {
                        det = Some(crate::ml::fast_detect::FastDetectionResult {
                            detection_name: "EICAR-Standard-AV-Test-File".to_string(),
                            reason: "Standard antivirus test pattern detected".to_string(),
                            features: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }

        // 2. Fast static machine learning detection (PE & JS content inference)
        if det.is_none() {
            det = fast_detect_path(path_str);
        }

        // 3. Fallback to ClamAV deep scan (including archive decompression)
        if det.is_none() {
            det = crate::clamscan::rt_scan_file(path_str);
        }

        if let Some(detection) = det {
            if crate::globals::is_protection_paused() {
                Logging::warning(&format!(
                    "[DaemonScanner][PAUSED - logged only] Threat '{}' in {} (PID: {})",
                    detection.detection_name, path_str, task.pid
                ));
                continue;
            }

            Logging::alert(&format!(
                "[DaemonScanner] THREAT DETECTED: '{}' ({}) in {}",
                detection.detection_name, detection.reason, path_str
            ));

            let meta = QuarantineMetadata {
                detection: detection.detection_name.clone(),
            };

            let mut handled = false;
            if let Some(state) = SCANNER.get() {
                if let Ok(guard) = state.threat_handler.lock() {
                    if let Some(handler) = guard.as_ref() {
                        if task.is_actor_target && task.gid != 0 {
                            handler.kill_and_quarantine(task.gid, &task.path, &meta);
                        } else {
                            handler.quarantine_only(&task.path, &meta);
                        }
                        handled = true;
                    }
                }
            }

            if !handled {
                // Standalone fallback: kill PID if process target, and quarantine file directly
                if task.is_actor_target && task.pid != 0 {
                    unsafe {
                        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
                        if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, task.pid) {
                            if !h.is_invalid() {
                                let _ = TerminateProcess(h, 1);
                                let _ = windows::Win32::Foundation::CloseHandle(h);
                            }
                        }
                    }
                }
                let _ = crate::windows::quarantine::quarantine_path(&task.path, &detection.detection_name);
            }

            // Immediately notify Pascal GUI via \\.\pipe\HydraHipEvent
            notify_gui_threat_alert(&detection.detection_name, path_str);
        }
    }
}

fn notify_gui_threat_alert(threat_name: &str, file_path: &str) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        FlushFileBuffers, OPEN_EXISTING, WriteFile,
    };
    use windows::core::PCWSTR;

    const PIPE: &str = r"\\.\pipe\HydraHipEvent";
    let mut pipe_name_wide: Vec<u16> = PIPE.encode_utf16().collect();
    pipe_name_wide.push(0);
    let pcwstr = PCWSTR(pipe_name_wide.as_ptr());
    let message = format!("THREAT_ALERT:{}|{}\n", threat_name, file_path);
    let message_bytes = message.as_bytes();

    unsafe {
        if let Ok(handle) = CreateFileW(
            pcwstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            if !handle.is_invalid() {
                let mut written: u32 = 0;
                let _ = WriteFile(
                    handle,
                    Some(message_bytes),
                    Some(&mut written as *mut u32),
                    None,
                );
                let _ = FlushFileBuffers(handle);
                let _ = CloseHandle(handle);
            }
        }
    }
}

/// Convert NT device path (\Device\HarddiskVolumeX or \??\) to DOS drive path (e.g. C:\...)
fn nt_to_dos_path(path: &Path) -> PathBuf {
    use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
    use windows::core::PCWSTR;

    let s = path.to_string_lossy();
    let s_clean = if let Some(stripped) = s.strip_prefix(r"\??\") {
        stripped
    } else {
        &s
    };

    if !s_clean.starts_with(r"\Device\") {
        return PathBuf::from(s_clean);
    }

    let mut drives_buf = [0u16; 256];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut drives_buf)) };
    if len == 0 || len > 255 {
        return PathBuf::from(s_clean);
    }

    let mut i = 0;
    while i < len as usize && drives_buf[i] != 0 {
        let drive = &drives_buf[i..i + 2];
        let drive_str = String::from_utf16_lossy(drive);
        let mut target_buf = [0u16; 512];
        let mut drive_w = drive.to_vec();
        drive_w.push(0);
        let query_len = unsafe {
            QueryDosDeviceW(
                PCWSTR(drive_w.as_ptr()),
                Some(&mut target_buf),
            )
        };
        if query_len > 0 {
            let target_nt = String::from_utf16_lossy(&target_buf[..query_len as usize])
                .trim_end_matches('\0')
                .to_string();
            if s_clean.starts_with(&target_nt) {
                let remainder = &s_clean[target_nt.len()..];
                return PathBuf::from(format!("{}{}", drive_str, remainder));
            }
        }

        while i < len as usize && drives_buf[i] != 0 {
            i += 1;
        }
        i += 1;
    }

    PathBuf::from(s_clean)
}

/// Enqueue a path for asynchronous daemon scanning.
/// Non-blocking, deduplicated within 3 seconds, returns immediately.
pub fn enqueue_scan(
    mut path: PathBuf,
    is_actor_target: bool,
    pid: u32,
    gid: u64,
    appname: String,
) {
    let state = ensure_daemon_scanner();

    let path_str = path.to_string_lossy();
    if path_str.is_empty() || path_str.starts_with(r"\\.\pipe\") {
        return;
    }

    if path_str.starts_with(r"\Device\") || path_str.starts_with(r"\??\") {
        path = nt_to_dos_path(&path);
    }

    // Deduplication check: skip if recently submitted within 3 seconds
    {
        if let Ok(mut cache) = state.recent_scans.lock() {
            let now = Instant::now();
            if let Some(last_time) = cache.get(&path) {
                if now.duration_since(*last_time) < Duration::from_secs(3) {
                    return;
                }
            }
            cache.put(path.clone(), now);
        }
    }

    let task = DaemonScanTask {
        path,
        is_actor_target,
        pid,
        gid,
        appname,
    };

    let _ = state.tx.try_send(task);
}
