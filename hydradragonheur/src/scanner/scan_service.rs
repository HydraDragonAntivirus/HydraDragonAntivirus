// scanner/scan_service.rs — Scan service orchestrator.
//
// Ports TinyAntivirus's CScanService / IScanner.
//
// The service:
//   1. Accepts registered ScanModules and ScanObservers.
//   2. When started, builds a FileFsEnumerator over the EnumContext.
//   3. For each file found, runs every registered ScanModule in sequence.
//   4. Supports pause/resume via a Condvar and stop via an AtomicBool.
//   5. Handles S_FALSE (rescan) by re-running all modules up to MAX_RESCAN times.

use super::{NullScanObserver, ScanModule, ScanObserver};
use crate::error::{AvError, AvResult};
use crate::fs::enum_fs::FileFsEnumerator;
use crate::fs::{EnumContext, FsEnumObserver, FsEnumerator, VirtualFs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};

const MAX_RESCAN: usize = 4;

// ---------------------------------------------------------------------------
// ScanService
// ---------------------------------------------------------------------------

/// The central scan engine (ports CScanService / IScanner).
///
/// Usage:
/// ```ignore
/// let mut svc = ScanService::new();
/// svc.add_module(my_module);
/// svc.add_observer(my_observer);
/// svc.start(&context)?;
/// svc.wait();
/// ```
pub struct ScanService {
    modules: Vec<Arc<Mutex<dyn ScanModule>>>,
    observers: Vec<Arc<dyn ScanObserver>>,
    stopped: Arc<AtomicBool>,
    paused: Arc<(Mutex<bool>, Condvar)>,
}

impl ScanService {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            observers: Vec::new(),
            stopped: Arc::new(AtomicBool::new(false)),
            paused: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    // ------------------------------------------------------------------
    // Observer management (ports AddScanObserver / RemoveScanObserver)
    // ------------------------------------------------------------------

    pub fn add_observer(&mut self, observer: Arc<dyn ScanObserver>) -> AvResult<()> {
        self.observers.push(observer);
        Ok(())
    }

    pub fn remove_observer(&mut self, observer: &Arc<dyn ScanObserver>) -> AvResult<()> {
        let ptr = Arc::as_ptr(observer) as *const () as usize;
        self.observers.retain(|o| Arc::as_ptr(o) as *const () as usize != ptr);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Module management (ports AddScanModule / RemoveScanModule)
    // ------------------------------------------------------------------

    pub fn add_module(&mut self, module: Arc<Mutex<dyn ScanModule>>) -> AvResult<()> {
        self.modules.push(module);
        Ok(())
    }

    pub fn remove_module(&mut self, module: &Arc<Mutex<dyn ScanModule>>) -> AvResult<()> {
        let ptr = Arc::as_ptr(module) as *const () as usize;
        self.modules.retain(|m| Arc::as_ptr(m) as *const () as usize != ptr);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Initialize all modules (ports OnScanInitialize for each module).
    pub fn initialize(&mut self) -> AvResult<()> {
        for module in &self.modules {
            module.lock().unwrap().on_initialize()?;
        }
        Ok(())
    }

    /// Shutdown all modules (ports OnScanShutdown for each module).
    pub fn shutdown(&mut self) -> AvResult<()> {
        for module in &self.modules {
            module.lock().unwrap().on_shutdown()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Start / Stop / Pause / Resume
    // ------------------------------------------------------------------

    /// Start synchronous scanning over the given enumeration context.
    /// Ports IScanner::Start().
    pub fn start(&mut self, context: &EnumContext) -> AvResult<()> {
        self.stopped.store(false, Ordering::SeqCst);
        {
            let (lock, _) = &*self.paused;
            *lock.lock().unwrap() = false;
        }

        // Notify observers: scan started
        self.broadcast_started(context)?;

        let default_obs: Arc<dyn ScanObserver> = Arc::new(NullScanObserver);
        let _first_obs = self.observers.first().unwrap_or(&default_obs).clone();

        // Build enumerator with a callback that runs all modules per file
        let modules = self.modules.clone();
        let observers = self.observers.clone();
        let stopped = Arc::clone(&self.stopped);
        let paused = Arc::clone(&self.paused);

        let scan_obs = Arc::new(PerFileScanObserver {
            modules,
            observers,
            stopped: Arc::clone(&stopped),
            paused,
        });

        let mut enumerator = FileFsEnumerator::new();
        enumerator.add_observer(scan_obs as Arc<dyn FsEnumObserver>)?;
        enumerator.enumerate(context)?;

        // Notify observers: scan stopping
        self.broadcast_stopping(context)?;

        Ok(())
    }

    /// Stop scanning (ports IScanner::Stop).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        // Wake up any paused thread so it sees the stop flag
        let (lock, cvar) = &*self.paused;
        *lock.lock().unwrap() = false;
        cvar.notify_all();
    }

    /// Pause scanning (ports IScanner::Pause).
    pub fn pause(&self) -> AvResult<()> {
        let (lock, _) = &*self.paused;
        *lock.lock().unwrap() = true;
        self.broadcast_paused(&EnumContext::default())?;
        Ok(())
    }

    /// Resume scanning (ports IScanner::Resume).
    pub fn resume(&self) -> AvResult<()> {
        let (lock, cvar) = &*self.paused;
        *lock.lock().unwrap() = false;
        cvar.notify_all();
        self.broadcast_resumed(&EnumContext::default())?;
        Ok(())
    }

    /// Block until scanning is complete (ports IScanner::Forever).
    /// For synchronous scanning this is a no-op; in an async variant
    /// this would join the background thread.
    pub fn wait(&self) {}

    // ------------------------------------------------------------------
    // Internal broadcast helpers
    // ------------------------------------------------------------------

    fn broadcast_started(&self, ctx: &EnumContext) -> AvResult<()> {
        for obs in &self.observers {
            obs.on_scan_started(ctx)?;
        }
        Ok(())
    }

    fn broadcast_stopping(&self, ctx: &EnumContext) -> AvResult<()> {
        for obs in &self.observers {
            obs.on_scan_stopping(ctx)?;
        }
        Ok(())
    }

    fn broadcast_paused(&self, ctx: &EnumContext) -> AvResult<()> {
        for obs in &self.observers {
            obs.on_scan_paused(ctx)?;
        }
        Ok(())
    }

    fn broadcast_resumed(&self, ctx: &EnumContext) -> AvResult<()> {
        for obs in &self.observers {
            obs.on_scan_resumed(ctx)?;
        }
        Ok(())
    }
}

impl Default for ScanService {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PerFileScanObserver — bridges FsEnumerator callbacks to ScanModules
// ---------------------------------------------------------------------------

struct PerFileScanObserver {
    modules: Vec<Arc<Mutex<dyn ScanModule>>>,
    observers: Vec<Arc<dyn ScanObserver>>,
    stopped: Arc<AtomicBool>,
    paused: Arc<(Mutex<bool>, Condvar)>,
}

impl FsEnumObserver for PerFileScanObserver {
    fn on_file_found(
        &self,
        file: Arc<dyn VirtualFs>,
        context: &EnumContext,
        _depth: i32,
    ) -> AvResult<()> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(AvError::ScanAborted);
        }

        // Pause handling
        {
            let (lock, cvar) = &*self.paused;
            let mut paused = lock.lock().unwrap();
            while *paused && !self.stopped.load(Ordering::SeqCst) {
                paused = cvar.wait(paused).unwrap();
            }
        }

        if self.stopped.load(Ordering::SeqCst) {
            return Err(AvError::ScanAborted);
        }

        // Notify pre-scan
        for obs in &self.observers {
            obs.on_pre_scan(&file, context)?;
        }

        // Run all modules, supporting rescan (S_FALSE) up to MAX_RESCAN times
        let mut rescan_count = 0;
        loop {
            let mut rescan_requested = false;

            for module in &self.modules {
                let mut m = module.lock().unwrap();
                let first_obs: Arc<dyn ScanObserver> = self
                    .observers
                    .first()
                    .cloned()
                    .unwrap_or_else(|| Arc::new(NullScanObserver));

                match m.scan(Arc::clone(&file), context, &first_obs) {
                    Ok(true) => {
                        rescan_requested = true;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        let msg = e.to_string();
                        for obs in &self.observers {
                            obs.on_error(0, Some(&msg));
                        }
                    }
                }
            }

            rescan_count += 1;
            if !rescan_requested || rescan_count >= MAX_RESCAN {
                break;
            }
        }

        // Notify all scan finished
        for obs in &self.observers {
            obs.on_all_scan_finished(&file, context)?;
        }

        Ok(())
    }

    fn on_error(&self, code: u32, message: Option<&str>) {
        for obs in &self.observers {
            obs.on_error(code, message);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FileAttributes, FsFlags, FsType};
    use crate::module::{Module, ModuleInfo, ModuleType};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    // ---- Minimal VirtualFs stub ----
    struct StubVfs(PathBuf);

    impl VirtualFs for StubVfs {
        fn create(&mut self, _: &Path, _: FsFlags) -> AvResult<()> {
            Ok(())
        }
        fn close(&mut self) -> AvResult<()> {
            Ok(())
        }
        fn recreate(&mut self, _: FsFlags) -> AvResult<()> {
            Ok(())
        }
        fn is_opened(&self) -> bool {
            true
        }
        fn full_path(&self) -> AvResult<PathBuf> {
            Ok(self.0.clone())
        }
        fn file_name(&self) -> AvResult<String> {
            Ok(self
                .0
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned())
        }
        fn file_ext(&self) -> AvResult<String> {
            Ok(self
                .0
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned())
        }
        fn fs_type(&self) -> FsType {
            FsType::Basic
        }
        fn flags(&self) -> FsFlags {
            FsFlags::READ
        }
        fn container(&self) -> Option<Arc<dyn VirtualFs>> {
            None
        }
        fn set_container(&mut self, _: Arc<dyn VirtualFs>) {}
        fn deferred_delete(&mut self) -> AvResult<()> {
            Ok(())
        }
        fn last_error(&self) -> u32 {
            0
        }
        fn attributes(&self) -> AvResult<FileAttributes> {
            Ok(FileAttributes {
                size: 0,
                is_readonly: false,
                is_hidden: false,
                is_system: false,
                created: None,
                accessed: None,
                modified: None,
            })
        }
        fn open_stream(&self) -> AvResult<Box<dyn crate::fs::FsStream>> {
            Err(AvError::NotImplemented)
        }
    }

    // ---- Counting scan module ----
    struct CountingModule {
        scan_count: Arc<Mutex<usize>>,
    }

    impl Module for CountingModule {
        fn module_info(&self) -> ModuleInfo {
            ModuleInfo {
                module_type: ModuleType::ScanModule,
                name: "CountingModule".into(),
            }
        }
        fn module_type(&self) -> ModuleType {
            ModuleType::ScanModule
        }
        fn name(&self) -> &str {
            "CountingModule"
        }
    }

    impl ScanModule for CountingModule {
        fn on_initialize(&mut self) -> AvResult<()> {
            Ok(())
        }
        fn on_shutdown(&mut self) -> AvResult<()> {
            Ok(())
        }
        fn scan(
            &mut self,
            _: Arc<dyn VirtualFs>,
            _: &EnumContext,
            _: &Arc<dyn ScanObserver>,
        ) -> AvResult<bool> {
            *self.scan_count.lock().unwrap() += 1;
            Ok(false)
        }
    }

    // ---- Counting observer ----
    struct CountingObserver {
        started: Mutex<usize>,
        pre_scan: Mutex<usize>,
        finished: Mutex<usize>,
    }

    impl CountingObserver {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                started: Mutex::new(0),
                pre_scan: Mutex::new(0),
                finished: Mutex::new(0),
            })
        }
    }

    impl ScanObserver for CountingObserver {
        fn on_scan_started(&self, _: &EnumContext) -> AvResult<()> {
            *self.started.lock().unwrap() += 1;
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
            *self.pre_scan.lock().unwrap() += 1;
            Ok(())
        }
        fn on_all_scan_finished(&self, _: &Arc<dyn VirtualFs>, _: &EnumContext) -> AvResult<()> {
            *self.finished.lock().unwrap() += 1;
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

    #[test]
    fn scan_service_runs_modules_for_each_file() {
        let tmp = TempDir::new().unwrap();
        for i in 0..3 {
            fs::write(tmp.path().join(format!("{i}.bin")), b"data").unwrap();
        }

        let count = Arc::new(Mutex::new(0usize));
        let module = Arc::new(Mutex::new(CountingModule {
            scan_count: Arc::clone(&count),
        }) as Mutex<dyn ScanModule>);

        let obs = CountingObserver::new();

        let mut svc = ScanService::new();
        svc.add_module(module).unwrap();
        svc.add_observer(Arc::clone(&obs) as Arc<dyn ScanObserver>)
            .unwrap();
        svc.initialize().unwrap();

        let ctx = EnumContext {
            search_root: Some(tmp.path().to_owned()),
            ..Default::default()
        };
        svc.start(&ctx).unwrap();
        svc.shutdown().unwrap();

        assert_eq!(*count.lock().unwrap(), 3);
        assert_eq!(*obs.started.lock().unwrap(), 1);
        assert_eq!(*obs.pre_scan.lock().unwrap(), 3);
        assert_eq!(*obs.finished.lock().unwrap(), 3);
    }
}
