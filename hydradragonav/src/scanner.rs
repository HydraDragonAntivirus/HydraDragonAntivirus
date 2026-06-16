#![cfg(windows)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::ffi::{self, Api, ClEngineFreeFn, ClEngineNewFn, ClInitFn};
use crate::types::{self, ClScanOptions, Error, ScanResult, DEFAULT_ENGINE_OPTIONS};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn wide_to_utf8(wide: &[u16]) -> String {
    if wide.is_empty() {
        return String::new();
    }
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    if len == 0 {
        return String::new();
    }
    unsafe {
        let required = ffi::WideCharToMultiByte(
            ffi::CP_UTF8,
            0,
            wide.as_ptr(),
            len as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        if required <= 0 {
            return String::new();
        }
        let mut buf = vec![0i8; required as usize];
        let written = ffi::WideCharToMultiByte(
            ffi::CP_UTF8,
            0,
            wide.as_ptr(),
            len as i32,
            buf.as_mut_ptr(),
            required,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        if written <= 0 {
            return String::new();
        }
        let bytes: &[u8] = std::slice::from_raw_parts(buf.as_ptr() as *const u8, written as usize);
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn path_to_utf16(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn format_win32_error(code: u32) -> String {
    unsafe {
        let mut buffer: *mut u16 = std::ptr::null_mut();
        let flags = ffi::FORMAT_MESSAGE_ALLOCATE_BUFFER
            | ffi::FORMAT_MESSAGE_FROM_SYSTEM
            | ffi::FORMAT_MESSAGE_IGNORE_INSERTS;
        let len = ffi::FormatMessageW(
            flags,
            std::ptr::null(),
            code,
            0,
            &mut buffer as *mut *mut u16 as *mut u16,
            0,
            std::ptr::null_mut(),
        );
        if len == 0 || buffer.is_null() {
            return format!("Win32 error code: {}", code);
        }
        let wide = std::slice::from_raw_parts(buffer, len as usize);
        let msg = wide_to_utf8(wide);
        ffi::LocalFree(buffer as *mut c_void);
        msg.trim_end_matches(|c: char| c == '\r' || c == '\n')
            .to_string()
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

pub type LogCallback = Box<dyn Fn(&str, &str) + Send + 'static>;

fn default_logger(level: &str, message: &str) {
    let line = format!("[ClamAV][{}] {}", level, message);
    eprintln!("{}", line);
}

// ---------------------------------------------------------------------------
// Engine — the raw ClamAV engine handle
// ---------------------------------------------------------------------------

struct Engine {
    ptr: *mut c_void,
    cl_engine_free: Option<ClEngineFreeFn>,
    cl_load: Option<crate::ffi::ClLoadFn>,
    cl_engine_compile: Option<crate::ffi::ClEngineCompileFn>,
    cl_engine_set_num: Option<crate::ffi::ClEngineSetNumFn>,
    cl_scanfile: Option<crate::ffi::ClScanFileFn>,
    cl_strerror: Option<crate::ffi::ClStrErrorFn>,
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    unsafe fn new(api: &Api) -> Result<Self, Error> {
        let new_fn = api
            .cl_engine_new
            .ok_or(Error::MissingExport("cl_engine_new"))?;
        let ptr = new_fn();
        if ptr.is_null() {
            return Err(Error::ClamavInit("Failed to create ClamAV engine".into()));
        }
        Ok(Self {
            ptr,
            cl_engine_free: api.cl_engine_free,
            cl_load: api.cl_load,
            cl_engine_compile: api.cl_engine_compile,
            cl_engine_set_num: api.cl_engine_set_num,
            cl_scanfile: api.cl_scanfile,
            cl_strerror: api.cl_strerror,
        })
    }

    unsafe fn load_db(&self, utf8_path: &str, dboptions: u32) -> Result<u32, Error> {
        let load_fn = self.cl_load.ok_or(Error::MissingExport("cl_load"))?;
        let c_path = std::ffi::CString::new(utf8_path)
            .map_err(|e| Error::Other(format!("Invalid database path: {}", e)))?;
        let mut signatures_loaded: u32 = 0;
        let res = load_fn(c_path.as_ptr(), self.ptr, &mut signatures_loaded, dboptions);
        if res != types::CL_SUCCESS {
            return Err(Error::DatabaseLoad(self.error_message(res)));
        }
        Ok(signatures_loaded)
    }

    unsafe fn set_options(&self, options: &[(u32, u32)]) {
        let set_num = match self.cl_engine_set_num {
            Some(f) => f,
            None => return,
        };
        for &(opt_id, value) in options {
            let res = set_num(self.ptr, opt_id, value);
            if res != types::CL_SUCCESS {
                let msg = self.error_message(res);
                log_warn(&format!(
                    "Failed to set engine option {} = {}: {}",
                    opt_id, value, msg
                ));
            }
        }
    }

    unsafe fn compile(&self) -> Result<(), Error> {
        let compile_fn = self
            .cl_engine_compile
            .ok_or(Error::MissingExport("cl_engine_compile"))?;
        let res = compile_fn(self.ptr);
        if res != types::CL_SUCCESS {
            return Err(Error::EngineCompile(self.error_message(res)));
        }
        Ok(())
    }

    unsafe fn scan_file(&self, path: &str, scan_opts: &ClScanOptions) -> Result<ScanResult, Error> {
        let scan_fn = self
            .cl_scanfile
            .ok_or(Error::MissingExport("cl_scanfile"))?;
        let c_path = std::ffi::CString::new(path)
            .map_err(|e| Error::Other(format!("Invalid path: {}", e)))?;
        let mut virname: *const i8 = std::ptr::null();
        let mut bytes_scanned: u32 = 0;
        let result = scan_fn(
            c_path.as_ptr(),
            &mut virname,
            &mut bytes_scanned,
            self.ptr as *const c_void,
            scan_opts as *const ClScanOptions,
        );
        let mut output = ScanResult {
            result_code: result,
            virus_name: String::new(),
            bytes_scanned: bytes_scanned as u64,
        };
        if result == types::CL_VIRUS && !virname.is_null() {
            let c_str = std::ffi::CStr::from_ptr(virname);
            output.virus_name = c_str.to_string_lossy().into_owned();
        }
        Ok(output)
    }

    fn error_message(&self, code: i32) -> String {
        unsafe {
            if let Some(f) = self.cl_strerror {
                let ptr = f(code);
                if !ptr.is_null() {
                    let c_str = std::ffi::CStr::from_ptr(ptr);
                    return c_str
                        .to_string_lossy()
                        .trim_end_matches(|c: char| c == '\r' || c == '\n')
                        .to_string();
                }
            }
            format!("Error code: {}", code)
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            if let Some(f) = self.cl_engine_free {
                f(self.ptr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inner — shared mutable state behind Arc<Mutex<>>
// ---------------------------------------------------------------------------

struct Inner {
    libclamav_path: PathBuf,
    dbpath: PathBuf,
    dboptions: u32,
    engine_options: Vec<(u32, u32)>,
    module: ffi::HMODULE,
    api: Api,
    dll_dir_cookie: ffi::DllDirectoryCookie,
    engine: Option<Engine>,
}

unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        self.engine = None;
        unsafe {
            if !self.module.is_null() {
                ffi::FreeLibrary(self.module);
            }
            if !self.dll_dir_cookie.is_null() {
                ffi::RemoveDllDirectory(self.dll_dir_cookie);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state for async init
// ---------------------------------------------------------------------------

struct SharedState {
    ready: AtomicBool,
    init_in_progress: AtomicBool,
    init_success: AtomicBool,
    init_stage: Mutex<String>,
    init_error: Mutex<String>,
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

pub struct Scanner {
    inner: Arc<Mutex<Inner>>,
    shared: Arc<SharedState>,
    cv: Arc<Condvar>,
    logger: LogCallback,
    _init_thread: Mutex<Option<JoinHandle<()>>>,
}

impl Scanner {
    /// Synchronous constructor — blocks until fully initialized.
    pub fn new<P: AsRef<Path>>(libclamav_path: P, dbpath: P) -> Result<Self, Error> {
        let (scanner, shared) = Self::create_inner(
            libclamav_path.as_ref(),
            dbpath.as_ref(),
            types::CL_DB_STDOPT,
            &DEFAULT_ENGINE_OPTIONS,
            Box::new(default_logger),
        )?;

        shared.init_in_progress.store(true, Ordering::SeqCst);
        *shared.init_stage.lock().unwrap() = "Starting".into();

        match Self::init_engine_sync(&scanner.inner) {
            Ok(sigs) => {
                shared.ready.store(true, Ordering::SeqCst);
                shared.init_success.store(true, Ordering::SeqCst);
                *shared.init_stage.lock().unwrap() = "Complete".into();
                (scanner.logger)(
                    "INFO",
                    &format!("ClamAV scanner initialized. Signatures loaded: {}", sigs),
                );
            }
            Err(e) => {
                *shared.init_error.lock().unwrap() = e.to_string();
                *shared.init_stage.lock().unwrap() = "Failed".into();
                shared.init_success.store(false, Ordering::SeqCst);
            }
        }

        shared.init_in_progress.store(false, Ordering::SeqCst);
        scanner.cv.notify_all();

        let success = shared.init_success.load(Ordering::SeqCst);
        if success {
            Ok(scanner)
        } else {
            Err(Error::Other(
                scanner.shared.init_error.lock().unwrap().clone(),
            ))
        }
    }

    /// Asynchronous constructor — spawns a background thread for init.
    pub fn new_async<P: AsRef<Path>>(libclamav_path: P, dbpath: P) -> Result<Self, Error> {
        let (scanner, shared) = Self::create_inner(
            libclamav_path.as_ref(),
            dbpath.as_ref(),
            types::CL_DB_STDOPT,
            &DEFAULT_ENGINE_OPTIONS,
            Box::new(default_logger),
        )?;

        shared.init_in_progress.store(true, Ordering::SeqCst);
        *shared.init_stage.lock().unwrap() = "Starting".into();

        let inner = scanner.inner.clone();
        let shared_clone = shared.clone();
        let cv_clone = scanner.cv.clone();

        let handle = thread::spawn(move || {
            match Self::init_engine_sync(&inner) {
                Ok(sigs) => {
                    shared_clone.ready.store(true, Ordering::SeqCst);
                    shared_clone.init_success.store(true, Ordering::SeqCst);
                    *shared_clone.init_stage.lock().unwrap() = "Complete".into();
                    log_info(&format!(
                        "ClamAV scanner initialized. Signatures loaded: {}",
                        sigs
                    ));
                }
                Err(e) => {
                    *shared_clone.init_error.lock().unwrap() = e.to_string();
                    *shared_clone.init_stage.lock().unwrap() = "Failed".into();
                    shared_clone.init_success.store(false, Ordering::SeqCst);
                    log_error(&format!("ClamAV initialization failed: {}", e));
                }
            }
            shared_clone.init_in_progress.store(false, Ordering::SeqCst);
            cv_clone.notify_all();
        });

        *scanner._init_thread.lock().unwrap() = Some(handle);

        Ok(scanner)
    }

    /// Full-control constructor.
    pub fn with_options<P: AsRef<Path>>(
        libclamav_path: P,
        dbpath: P,
        dboptions: u32,
        engine_options: &[(u32, u32)],
        logger: LogCallback,
        async_init: bool,
    ) -> Result<Self, Error> {
        let (scanner, shared) = Self::create_inner(
            libclamav_path.as_ref(),
            dbpath.as_ref(),
            dboptions,
            engine_options,
            logger,
        )?;

        if async_init {
            shared.init_in_progress.store(true, Ordering::SeqCst);
            *shared.init_stage.lock().unwrap() = "Starting".into();

            let inner = scanner.inner.clone();
            let shared_clone = shared.clone();
            let cv_clone = scanner.cv.clone();

            let handle = thread::spawn(move || {
                match Self::init_engine_sync(&inner) {
                    Ok(sigs) => {
                        shared_clone.ready.store(true, Ordering::SeqCst);
                        shared_clone.init_success.store(true, Ordering::SeqCst);
                        *shared_clone.init_stage.lock().unwrap() = "Complete".into();
                        log_info(&format!(
                            "ClamAV scanner initialized. Signatures loaded: {}",
                            sigs
                        ));
                    }
                    Err(e) => {
                        *shared_clone.init_error.lock().unwrap() = e.to_string();
                        *shared_clone.init_stage.lock().unwrap() = "Failed".into();
                        shared_clone.init_success.store(false, Ordering::SeqCst);
                        log_error(&format!("ClamAV initialization failed: {}", e));
                    }
                }
                shared_clone.init_in_progress.store(false, Ordering::SeqCst);
                cv_clone.notify_all();
            });

            *scanner._init_thread.lock().unwrap() = Some(handle);

            Ok(scanner)
        } else {
            shared.init_in_progress.store(true, Ordering::SeqCst);
            *shared.init_stage.lock().unwrap() = "Starting".into();

            match Self::init_engine_sync(&scanner.inner) {
                Ok(sigs) => {
                    shared.ready.store(true, Ordering::SeqCst);
                    shared.init_success.store(true, Ordering::SeqCst);
                    *shared.init_stage.lock().unwrap() = "Complete".into();
                    (scanner.logger)(
                        "INFO",
                        &format!("ClamAV scanner initialized. Signatures loaded: {}", sigs),
                    );
                }
                Err(e) => {
                    *shared.init_error.lock().unwrap() = e.to_string();
                    *shared.init_stage.lock().unwrap() = "Failed".into();
                    shared.init_success.store(false, Ordering::SeqCst);
                    shared.init_in_progress.store(false, Ordering::SeqCst);
                    scanner.cv.notify_all();
                    return Err(e);
                }
            }

            shared.init_in_progress.store(false, Ordering::SeqCst);
            scanner.cv.notify_all();

            Ok(scanner)
        }
    }

    fn create_inner(
        libclamav_path: &Path,
        dbpath: &Path,
        dboptions: u32,
        engine_options: &[(u32, u32)],
        logger: LogCallback,
    ) -> Result<(Self, Arc<SharedState>), Error> {
        if !libclamav_path.exists() {
            return Err(Error::LibraryNotFound(
                libclamav_path.to_string_lossy().into_owned(),
            ));
        }

        let shared = Arc::new(SharedState {
            ready: AtomicBool::new(false),
            init_in_progress: AtomicBool::new(false),
            init_success: AtomicBool::new(false),
            init_stage: Mutex::new("Not started".into()),
            init_error: Mutex::new(String::new()),
        });

        let inner = Arc::new(Mutex::new(Inner {
            libclamav_path: libclamav_path.to_path_buf(),
            dbpath: dbpath.to_path_buf(),
            dboptions,
            engine_options: engine_options.to_vec(),
            module: std::ptr::null_mut(),
            api: Api::zeroed(),
            dll_dir_cookie: std::ptr::null_mut(),
            engine: None,
        }));

        let scanner = Scanner {
            inner,
            shared: shared.clone(),
            cv: Arc::new(Condvar::new()),
            logger,
            _init_thread: Mutex::new(None),
        };

        Ok((scanner, shared))
    }

    // -----------------------------------------------------------------------
    // Internal: load DLL, bind API, create engine, load DB, compile
    // -----------------------------------------------------------------------

    fn init_engine_sync(inner: &Mutex<Inner>) -> Result<u32, Error> {
        let mut guard = inner.lock().unwrap();

        unsafe {
            let libclamav_path = guard.libclamav_path.clone();

            let dll_dir = libclamav_path.parent().map(|p| p.to_path_buf());
            ffi::SetDefaultDllDirectories(
                ffi::LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | ffi::LOAD_LIBRARY_SEARCH_USER_DIRS,
            );

            guard.dll_dir_cookie = dll_dir
                .as_ref()
                .filter(|d| !d.as_os_str().is_empty())
                .map(|dir| ffi::AddDllDirectory(path_to_utf16(dir).as_ptr()))
                .unwrap_or(std::ptr::null_mut());

            let lib_path_wide = path_to_utf16(&libclamav_path);
            let mut module = ffi::LoadLibraryExW(
                lib_path_wide.as_ptr(),
                std::ptr::null_mut(),
                ffi::LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
                    | ffi::LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
                    | ffi::LOAD_LIBRARY_SEARCH_USER_DIRS,
            );

            if module.is_null() {
                module = ffi::LoadLibraryW(lib_path_wide.as_ptr());
            }

            if module.is_null() {
                let err = format_win32_error(ffi::GetLastError());
                return Err(Error::LoadLibrary(err));
            }
            guard.module = module;

            // Bind API
            macro_rules! bind_required {
                ($name:literal, $field:ident, $ty:ty) => {
                    let ptr =
                        ffi::GetProcAddress(module, concat!($name, "\0").as_ptr() as *const i8);
                    if let Some(f) = ptr {
                        guard.api.$field =
                            Some(std::mem::transmute::<unsafe extern "C" fn(), $ty>(f));
                    } else {
                        return Err(Error::MissingExport($name));
                    }
                };
            }

            macro_rules! bind_optional {
                ($name:literal, $field:ident, $ty:ty) => {
                    let ptr =
                        ffi::GetProcAddress(module, concat!($name, "\0").as_ptr() as *const i8);
                    if let Some(f) = ptr {
                        guard.api.$field =
                            Some(std::mem::transmute::<unsafe extern "C" fn(), $ty>(f));
                    }
                };
            }

            bind_required!("cl_init", cl_init, ClInitFn);
            bind_required!("cl_engine_new", cl_engine_new, ClEngineNewFn);
            bind_required!("cl_engine_free", cl_engine_free, ClEngineFreeFn);
            bind_required!("cl_load", cl_load, crate::ffi::ClLoadFn);
            bind_required!(
                "cl_engine_compile",
                cl_engine_compile,
                crate::ffi::ClEngineCompileFn
            );
            bind_required!("cl_scanfile", cl_scanfile, crate::ffi::ClScanFileFn);
            bind_optional!(
                "cl_engine_set_num",
                cl_engine_set_num,
                crate::ffi::ClEngineSetNumFn
            );
            bind_optional!("cl_retver", cl_retver, crate::ffi::ClRetVerFn);
            bind_optional!("cl_strerror", cl_strerror, crate::ffi::ClStrErrorFn);

            // cl_init
            let init_fn = guard.api.cl_init.ok_or(Error::MissingExport("cl_init"))?;
            let res = init_fn(0);
            if res != types::CL_SUCCESS {
                let msg = guard
                    .api
                    .cl_strerror
                    .map(|f| {
                        let ptr = f(res);
                        if ptr.is_null() {
                            None
                        } else {
                            Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned())
                        }
                    })
                    .flatten()
                    .unwrap_or_else(|| format!("cl_init failed with code {}", res));
                return Err(Error::ClamavInit(msg));
            }

            if !guard.dbpath.exists() {
                return Err(Error::DatabasePath(
                    guard.dbpath.to_string_lossy().into_owned(),
                ));
            }
            if !guard.dbpath.is_dir() {
                return Err(Error::DatabasePath(format!(
                    "Not a directory: {}",
                    guard.dbpath.to_string_lossy()
                )));
            }

            let engine = Engine::new(&guard.api)?;
            let utf8_db = guard.dbpath.to_string_lossy();
            let signatures_loaded = engine.load_db(&utf8_db, guard.dboptions)?;
            engine.set_options(&guard.engine_options);
            engine.compile()?;

            guard.engine = Some(engine);
            Ok(signatures_loaded)
        }
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    pub fn is_ready(&self) -> bool {
        self.shared.ready.load(Ordering::SeqCst)
    }

    pub fn is_initializing(&self) -> bool {
        self.shared.init_in_progress.load(Ordering::SeqCst)
    }

    pub fn init_stage(&self) -> String {
        self.shared.init_stage.lock().unwrap().clone()
    }

    pub fn init_error(&self) -> String {
        self.shared.init_error.lock().unwrap().clone()
    }

    pub fn wait_until_ready(&self) -> bool {
        let mut guard = self.shared.init_stage.lock().unwrap();
        while self.shared.init_in_progress.load(Ordering::SeqCst) {
            guard = self.cv.wait(guard).unwrap();
        }
        self.shared.init_success.load(Ordering::SeqCst) && self.shared.ready.load(Ordering::SeqCst)
    }

    pub fn wait_until_ready_for(&self, timeout: Duration) -> bool {
        let guard = self.shared.init_stage.lock().unwrap();
        let (result, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |_| {
                self.shared.init_in_progress.load(Ordering::SeqCst)
            })
            .unwrap();
        drop(result);
        self.shared.init_success.load(Ordering::SeqCst) && self.shared.ready.load(Ordering::SeqCst)
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    pub fn scan_file<P: AsRef<Path>>(&self, path: P, heuristics: bool) -> Result<ScanResult, Error> {
        if !self.is_ready() {
            if self.is_initializing() {
                (self.logger)(
                    "INFO",
                    "Scanner not ready yet. Waiting for background initialization to finish.",
                );
                if !self.wait_until_ready() {
                    return Err(Error::NotReady);
                }
            } else {
                return Err(Error::NotReady);
            }
        }

        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_string_lossy().into_owned()));
        }
        if !path.is_file() {
            return Err(Error::NotRegularFile(path.to_string_lossy().into_owned()));
        }

        let utf8_path = path.to_string_lossy().into_owned();
        let mut scan_opts = ClScanOptions::default();
        if !heuristics {
            scan_opts.general &= !types::CL_SCAN_GENERAL_HEURISTICS;
        }

        let guard = self.inner.lock().unwrap();
        let engine = guard.engine.as_ref().ok_or(Error::NotReady)?;

        unsafe { engine.scan_file(&utf8_path, &scan_opts) }
    }

    // -----------------------------------------------------------------------
    // Version info
    // -----------------------------------------------------------------------

    pub fn version(&self) -> Option<String> {
        let guard = self.inner.lock().unwrap();
        unsafe {
            guard.api.cl_retver.map(|f| {
                let ptr = f();
                if ptr.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            })
        }
    }

    // -----------------------------------------------------------------------
    // Database reload
    // -----------------------------------------------------------------------

    pub fn reload_database(&self) -> Result<u32, Error> {
        if !self.wait_until_ready() {
            return Err(Error::Other(
                "Cannot reload: initialization did not complete successfully.".into(),
            ));
        }

        (self.logger)("INFO", "Reloading ClamAV database.");

        let mut guard = self.inner.lock().unwrap();

        unsafe {
            let api = &guard.api;
            let dbpath = &guard.dbpath;
            let dboptions = guard.dboptions;

            let engine = Engine::new(api)?;
            let utf8_db = dbpath.to_string_lossy();
            let sigs = engine.load_db(&utf8_db, dboptions)?;
            engine.set_options(&guard.engine_options);
            engine.compile()?;

            guard.engine = Some(engine);
            Ok(sigs)
        }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        if let Some(handle) = self._init_thread.lock().unwrap().take() {
            handle.join().ok();
        }
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

fn log_info(msg: &str) {
    eprintln!("[ClamAV][INFO] {}", msg);
}

fn log_warn(msg: &str) {
    eprintln!("[ClamAV][WARN] {}", msg);
}

fn log_error(msg: &str) {
    eprintln!("[ClamAV][ERROR] {}", msg);
}

/// Update ClamAV databases via libfreshclam.dll.
pub fn run_freshclam_dll<P: AsRef<Path>>(
    dll_path: P,
    db_dir: P,
    certs_dir: Option<&Path>,
) -> Result<(), Error> {
    let dll_path = dll_path.as_ref();
    if !dll_path.exists() {
        return Err(Error::FreshclamNotFound(dll_path.to_string_lossy().into_owned()));
    }

    let dll_wide = path_to_utf16(dll_path);
    let hmodule = unsafe { ffi::LoadLibraryW(dll_wide.as_ptr()) };
    if hmodule.is_null() {
        let err = unsafe { format_win32_error(ffi::GetLastError()) };
        return Err(Error::FreshclamError(format!("failed to load libfreshclam.dll: {}", err)));
    }

    macro_rules! get_proc {
        ($name:literal, $ty:ty) => {{
            let name = concat!($name, "\0").as_bytes();
            match unsafe { ffi::GetProcAddress(hmodule, name.as_ptr() as *const i8) } {
                Some(f) => unsafe { std::mem::transmute::<unsafe extern "C" fn(), $ty>(f) },
                None => {
                    unsafe { ffi::FreeLibrary(hmodule) };
                    return Err(Error::FreshclamError(concat!($name, " not found in libfreshclam.dll").into()));
                }
            }
        }};
    }

    let fc_initialize = get_proc!("fc_initialize", crate::ffi::FcInitializeFn);
    let fc_update_databases = get_proc!("fc_update_databases", crate::ffi::FcUpdateDatabasesFn);
    let fc_cleanup = get_proc!("fc_cleanup", crate::ffi::FcCleanupFn);

    let db_dir_cstr = std::ffi::CString::new(db_dir.as_ref().to_str().unwrap_or_default())
        .map_err(|e| Error::FreshclamError(format!("invalid db_dir: {}", e)))?;

    let certs_cstr = certs_dir
        .and_then(|p| std::ffi::CString::new(p.to_str().unwrap_or_default()).ok());

    let mut config = crate::ffi::FcConfig {
        msg_flags: 0,
        log_flags: 0,
        max_log_size: 0,
        max_attempts: 3,
        connect_timeout: 30,
        request_timeout: 1800,
        b_compress_local_database: 0,
        log_file: std::ptr::null(),
        log_facility: std::ptr::null(),
        local_ip: std::ptr::null(),
        user_agent: std::ptr::null(),
        proxy_server: std::ptr::null(),
        proxy_port: 0,
        proxy_username: std::ptr::null(),
        proxy_password: std::ptr::null(),
        database_directory: db_dir_cstr.as_ptr(),
        temp_directory: std::ptr::null(),
        certs_directory: certs_cstr.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
        b_fips_limits: 0,
    };

    let rc = unsafe { fc_initialize(&mut config) };
    if rc != 0 && rc != 1 {
        unsafe { fc_cleanup(); ffi::FreeLibrary(hmodule); }
        return Err(Error::FreshclamError(format!("fc_initialize failed with code {}", rc)));
    }

    let databases = [
        std::ffi::CString::new("main").unwrap(),
        std::ffi::CString::new("daily").unwrap(),
        std::ffi::CString::new("bytecode").unwrap(),
    ];
    let mut db_ptrs: Vec<*mut i8> = databases.iter().map(|s| s.as_ptr() as *mut i8).collect();

    let server = std::ffi::CString::new("database.clamav.net").unwrap();
    let mut server_ptrs: Vec<*mut i8> = vec![server.as_ptr() as *mut i8];

    let mut n_updated: u32 = 0;
    let rc = unsafe {
        fc_update_databases(
            db_ptrs.as_mut_ptr(),
            db_ptrs.len() as u32,
            server_ptrs.as_mut_ptr(),
            server_ptrs.len() as u32,
            0,
            std::ptr::null(),
            1,
            std::ptr::null_mut(),
            &mut n_updated,
        )
    };

    unsafe { fc_cleanup(); ffi::FreeLibrary(hmodule); }

    if rc != 0 && rc != 1 {
        return Err(Error::FreshclamError(format!("fc_update_databases failed with code {}", rc)));
    }

    Ok(())
}
