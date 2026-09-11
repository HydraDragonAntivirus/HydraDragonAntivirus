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

struct DaemonScannerState {
    tx: Sender<DaemonScanTask>,
    recent_scans: Mutex<LruCache<PathBuf, Instant>>,
}

static SCANNER: OnceLock<DaemonScannerState> = OnceLock::new();

/// Initialize the daemon scanner worker pool.
/// Spawns 4 background worker threads that process ML and ClamAV scans asynchronously
/// without blocking the kernel I/O event loop.
pub fn init_daemon_scanner(handler: Arc<dyn ThreatHandler>) {
    SCANNER.get_or_init(|| {
        let (tx, rx) = bounded::<DaemonScanTask>(65536);
        let cache_cap = NonZeroUsize::new(16384).unwrap();
        let recent_scans = Mutex::new(LruCache::new(cache_cap));

        // Spawn 4 daemon scanner worker threads for parallel scanning
        for thread_idx in 0..4 {
            let thread_rx = rx.clone();
            let thread_handler = Arc::clone(&handler);
            if let Err(e) = std::thread::Builder::new()
                .name(format!("daemon_scanner_{}", thread_idx))
                .spawn(move || {
                    worker_loop(thread_rx, thread_handler);
                })
            {
                Logging::error(&format!(
                    "[DaemonScanner] Failed to spawn worker thread {}: {}",
                    thread_idx, e
                ));
            }
        }

        Logging::info("[DaemonScanner] Background daemon scan worker pool initialized (4 threads)");

        DaemonScannerState {
            tx,
            recent_scans,
        }
    });
}

fn worker_loop(rx: Receiver<DaemonScanTask>, handler: Arc<dyn ThreatHandler>) {
    while let Ok(task) = rx.recv() {
        let path_str = match task.path.to_str() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let p = Path::new(path_str);
        if !p.is_file() {
            continue;
        }

        // 1. Fast static machine learning detection (PE & JS content inference)
        let mut det = fast_detect_path(path_str);

        // 2. Fallback to ClamAV deep scan (including archive decompression) if ML undecided
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

            if task.is_actor_target && task.gid != 0 {
                handler.kill_and_quarantine(task.gid, &task.path, &meta);
            } else {
                handler.quarantine_only(&task.path, &meta);
            }
        }
    }
}

/// Enqueue a path for asynchronous daemon scanning.
/// Non-blocking, deduplicated within 3 seconds, returns immediately.
pub fn enqueue_scan(
    path: PathBuf,
    is_actor_target: bool,
    pid: u32,
    gid: u64,
    appname: String,
) {
    let Some(state) = SCANNER.get() else {
        return;
    };

    let path_str = path.to_string_lossy();
    if path_str.is_empty()
        || path_str.starts_with(r"\\.\")
        || path_str.starts_with(r"\Device\")
    {
        return;
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
