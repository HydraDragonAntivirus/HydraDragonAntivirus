// scanner/mod.rs — Scanner traits and types.
//
// Ports TinyAntivirus's IScanModule, IScanObserver, IScanContext, IScanner,
// ScanResult, CleanResult, ScanAction enums, and the SCAN_RESULT struct.

pub mod scan_service;
pub use scan_service::ScanService;

use crate::error::AvResult;
use crate::fs::{EnumContext, VirtualFs};
use crate::module::Module;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Scan result enums (ports ScanObserver.h enums)
// ---------------------------------------------------------------------------

/// Overall scan verdict for a file (ports `ScanResult` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    /// No virus found.
    Clean,
    /// File is not a virus (e.g. wrong type, benign).
    NotAVirus,
    /// Virus detected.
    VirusDetected,
}

impl Default for ScanVerdict {
    fn default() -> Self {
        ScanVerdict::Clean
    }
}

/// Result of a clean/disinfect attempt (ports `CleanResult` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanVerdict {
    /// No cleaning was performed.
    DoNotClean,
    /// Virus was successfully repaired/cleaned.
    CleanSucceeded,
    /// Cleaning was denied (no write access, etc.).
    CleanDenied,
    /// File was quarantined.
    Quarantined,
    /// File was deleted.
    Deleted,
}

impl Default for CleanVerdict {
    fn default() -> Self {
        CleanVerdict::DoNotClean
    }
}

/// Requested action when a virus is detected (ports `ScanAction` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanAction {
    /// Repair / disinfect in-place.
    Repair,
    /// Quarantine the file.
    Quarantine,
    /// Delete the file.
    Delete,
    /// Leave the file untouched.
    Leave,
}

impl Default for ScanAction {
    fn default() -> Self {
        ScanAction::Leave
    }
}

/// Per-file scan outcome (ports `SCAN_RESULT` struct).
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub verdict: ScanVerdict,
    pub action: ScanAction,
    pub malware_name: String,
    pub clean_verdict: CleanVerdict,
}

// ---------------------------------------------------------------------------
// ScanObserver trait (ports IScanObserver)
// ---------------------------------------------------------------------------

/// Receives scanner lifecycle and per-file notifications.
/// Return `Err(AvError::ScanAborted)` from any method to stop scanning.
pub trait ScanObserver: Send + Sync {
    fn on_scan_started(&self, context: &EnumContext) -> AvResult<()>;
    fn on_scan_paused(&self, context: &EnumContext) -> AvResult<()>;
    fn on_scan_resumed(&self, context: &EnumContext) -> AvResult<()>;
    fn on_scan_stopping(&self, context: &EnumContext) -> AvResult<()>;
    fn on_pre_scan(&self, file: &Arc<dyn VirtualFs>, context: &EnumContext) -> AvResult<()>;
    fn on_all_scan_finished(
        &self,
        file: &Arc<dyn VirtualFs>,
        context: &EnumContext,
    ) -> AvResult<()>;
    fn on_pre_clean(
        &self,
        file: &Arc<dyn VirtualFs>,
        context: &EnumContext,
        result: &mut ScanResult,
    ) -> AvResult<()>;
    fn on_post_clean(
        &self,
        file: &Arc<dyn VirtualFs>,
        context: &EnumContext,
        result: &ScanResult,
    ) -> AvResult<()>;
    fn on_error(&self, code: u32, message: Option<&str>);
}

// ---------------------------------------------------------------------------
// ScanModule trait (ports IScanModule : IModule)
// ---------------------------------------------------------------------------

/// A pluggable scan module (ports `IScanModule`).
/// Each module inspects a single file and reports through `ScanObserver`.
///
/// `scan()` returns:
///   - `Ok(false)` → clean / not applicable (S_OK)
///   - `Ok(true)`  → rescan requested (S_FALSE, e.g. after disinfection)
///   - `Err(_)`    → hard failure
pub trait ScanModule: Module + Send + Sync {
    /// Called once at engine start (ports `OnScanInitialize`).
    fn on_initialize(&mut self) -> AvResult<()>;

    /// Scan one file (ports `Scan`).
    fn scan(
        &mut self,
        file: Arc<dyn VirtualFs>,
        context: &EnumContext,
        observer: &Arc<dyn ScanObserver>,
    ) -> AvResult<bool>; // true = rescan requested

    /// Called once at engine shutdown (ports `OnScanShutdown`).
    fn on_shutdown(&mut self) -> AvResult<()>;
}

// ---------------------------------------------------------------------------
// Null / logging observer (useful for tests)
// ---------------------------------------------------------------------------

/// A no-op scan observer. Useful as a default when no UI is attached.
pub struct NullScanObserver;

impl ScanObserver for NullScanObserver {
    fn on_scan_started(&self, _: &EnumContext) -> AvResult<()> {
        Ok(())
    }
    fn on_scan_paused(&self, _: &EnumContext) -> AvResult<()> {
        Ok(())
    }
    fn on_scan_resumed(&self, _: &EnumContext) -> AvResult<()> {
        Ok(())
    }
    fn on_scan_stopping(&self, _: &EnumContext) -> AvResult<()> {
        Ok(())
    }
    fn on_pre_scan(&self, _: &Arc<dyn VirtualFs>, _: &EnumContext) -> AvResult<()> {
        Ok(())
    }
    fn on_all_scan_finished(&self, _: &Arc<dyn VirtualFs>, _: &EnumContext) -> AvResult<()> {
        Ok(())
    }
    fn on_pre_clean(
        &self,
        _: &Arc<dyn VirtualFs>,
        _: &EnumContext,
        _: &mut ScanResult,
    ) -> AvResult<()> {
        Ok(())
    }
    fn on_post_clean(
        &self,
        _: &Arc<dyn VirtualFs>,
        _: &EnumContext,
        _: &ScanResult,
    ) -> AvResult<()> {
        Ok(())
    }
    fn on_error(&self, _: u32, _: Option<&str>) {}
}

/// A logging scan observer that prints events to log::info/warn.
pub struct LogScanObserver;

impl ScanObserver for LogScanObserver {
    fn on_scan_started(&self, ctx: &EnumContext) -> AvResult<()> {
        log::info!("[scan] started — root={:?}", ctx.search_root);
        Ok(())
    }
    fn on_scan_paused(&self, _: &EnumContext) -> AvResult<()> {
        log::info!("[scan] paused");
        Ok(())
    }
    fn on_scan_resumed(&self, _: &EnumContext) -> AvResult<()> {
        log::info!("[scan] resumed");
        Ok(())
    }
    fn on_scan_stopping(&self, _: &EnumContext) -> AvResult<()> {
        log::info!("[scan] stopping");
        Ok(())
    }
    fn on_pre_scan(&self, file: &Arc<dyn VirtualFs>, _: &EnumContext) -> AvResult<()> {
        if let Ok(p) = file.full_path() {
            log::info!("[scan] scanning {}", p.display());
        }
        Ok(())
    }
    fn on_all_scan_finished(&self, file: &Arc<dyn VirtualFs>, _: &EnumContext) -> AvResult<()> {
        if let Ok(p) = file.full_path() {
            log::info!("[scan] finished {}", p.display());
        }
        Ok(())
    }
    fn on_pre_clean(
        &self,
        file: &Arc<dyn VirtualFs>,
        _: &EnumContext,
        result: &mut ScanResult,
    ) -> AvResult<()> {
        if let Ok(p) = file.full_path() {
            log::warn!("[scan] cleaning {} ({:?})", p.display(), result.verdict);
        }
        Ok(())
    }
    fn on_post_clean(
        &self,
        file: &Arc<dyn VirtualFs>,
        _: &EnumContext,
        result: &ScanResult,
    ) -> AvResult<()> {
        if let Ok(p) = file.full_path() {
            log::info!(
                "[scan] clean result for {}: {:?}",
                p.display(),
                result.clean_verdict
            );
        }
        Ok(())
    }
    fn on_error(&self, code: u32, msg: Option<&str>) {
        log::error!("[scan] error {code}: {}", msg.unwrap_or("(none)"));
    }
}
