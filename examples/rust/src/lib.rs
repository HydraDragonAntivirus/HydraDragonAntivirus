use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

use libloading::{Library, Symbol};

type InitFn = unsafe extern "C" fn(*const c_char) -> i32;
type ScanPathFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type ScanBytesFn = unsafe extern "C" fn(*const u8, usize, *const c_char) -> *mut c_char;
type ScanVoidFn = unsafe extern "C" fn() -> *mut c_char;
type RestoreFn = unsafe extern "C" fn(*const c_char, i32) -> *mut c_char;
type FreeFn = unsafe extern "C" fn(*mut c_char);

pub struct OpenEdrScanner {
    init: Symbol<'static, InitFn>,
    scan_file: Symbol<'static, ScanPathFn>,
    scan_bytes: Symbol<'static, ScanBytesFn>,
    scan_url: Symbol<'static, ScanPathFn>,
    check_registry: Symbol<'static, ScanPathFn>,
    scan_evtx: Symbol<'static, ScanPathFn>,
    scan_system_events: Symbol<'static, ScanVoidFn>,
    check_hosts: Symbol<'static, ScanPathFn>,
    restore_hosts: Symbol<'static, RestoreFn>,
    free_string: Symbol<'static, FreeFn>,
    _lib: Library,
}

fn leak_symbol<'a, T>(sym: Symbol<'a, T>) -> Symbol<'static, T> {
    unsafe { std::mem::transmute(sym) }
}

impl OpenEdrScanner {
    pub fn load(dll_path: &Path, rules_dir: Option<&Path>) -> Result<Self, String> {
        let lib = unsafe { Library::new(dll_path) }.map_err(|e| {
            format!("failed to load {}: {e}", dll_path.display())
        })?;
        unsafe {
            let init: Symbol<InitFn> = lib
                .get(b"openedr_static_init\0")
                .map_err(|e| format!("missing openedr_static_init: {e}"))?;
            let scan_file: Symbol<ScanPathFn> = lib
                .get(b"openedr_static_scan_file\0")
                .map_err(|e| format!("missing openedr_static_scan_file: {e}"))?;
            let scan_bytes: Symbol<ScanBytesFn> = lib
                .get(b"openedr_static_scan_bytes\0")
                .map_err(|e| format!("missing openedr_static_scan_bytes: {e}"))?;
            let scan_url: Symbol<ScanPathFn> = lib
                .get(b"openedr_static_scan_url\0")
                .map_err(|e| format!("missing openedr_static_scan_url: {e}"))?;
            let check_registry: Symbol<ScanPathFn> = lib
                .get(b"openedr_static_check_registry\0")
                .map_err(|e| format!("missing openedr_static_check_registry: {e}"))?;
            let scan_evtx: Symbol<ScanPathFn> = lib
                .get(b"openedr_static_scan_evtx\0")
                .map_err(|e| format!("missing openedr_static_scan_evtx: {e}"))?;
            let scan_system_events: Symbol<ScanVoidFn> = lib
                .get(b"openedr_static_scan_system_events\0")
                .map_err(|e| format!("missing openedr_static_scan_system_events: {e}"))?;
            let check_hosts: Symbol<ScanPathFn> = lib
                .get(b"openedr_static_check_hosts_file\0")
                .map_err(|e| format!("missing openedr_static_check_hosts_file: {e}"))?;
            let restore_hosts: Symbol<RestoreFn> = lib
                .get(b"openedr_static_restore_hosts_file\0")
                .map_err(|e| format!("missing openedr_static_restore_hosts_file: {e}"))?;
            let free_string: Symbol<FreeFn> = lib
                .get(b"openedr_static_free_string\0")
                .map_err(|e| format!("missing openedr_static_free_string: {e}"))?;

            let scanner = Self {
                init: leak_symbol(init),
                scan_file: leak_symbol(scan_file),
                scan_bytes: leak_symbol(scan_bytes),
                scan_url: leak_symbol(scan_url),
                check_registry: leak_symbol(check_registry),
                scan_evtx: leak_symbol(scan_evtx),
                scan_system_events: leak_symbol(scan_system_events),
                check_hosts: leak_symbol(check_hosts),
                restore_hosts: leak_symbol(restore_hosts),
                free_string: leak_symbol(free_string),
                _lib: lib,
            };
            let res = match rules_dir {
                Some(p) => {
                    let s = p.to_str().ok_or("invalid rules path")?;
                    let c = CString::new(s).map_err(|e| e.to_string())?;
                    (scanner.init)(c.as_ptr())
                }
                None => (scanner.init)(std::ptr::null()),
            };
            if res != 0 {
                return Err(format!("openedr_static_init failed with code {res}"));
            }
            Ok(scanner)
        }
    }

    fn take_string(&self, ptr: *mut c_char) -> String {
        if ptr.is_null() {
            return String::new();
        }
        unsafe {
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            (self.free_string)(ptr);
            s
        }
    }

    pub fn scan_file(&self, path: &Path) -> Result<String, String> {
        let s = path.to_str().ok_or("invalid file path")?;
        let c = CString::new(s).map_err(|e| e.to_string())?;
        Ok(self.take_string(unsafe { (self.scan_file)(c.as_ptr()) }))
    }

    pub fn scan_bytes(&self, data: &[u8], virtual_name: Option<&str>) -> String {
        let c_name = virtual_name.and_then(|n| CString::new(n).ok());
        let name_ptr = c_name.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        self.take_string(unsafe { (self.scan_bytes)(data.as_ptr(), data.len(), name_ptr) })
    }

    pub fn scan_url(&self, url: &str) -> Result<String, String> {
        let c = CString::new(url).map_err(|e| e.to_string())?;
        Ok(self.take_string(unsafe { (self.scan_url)(c.as_ptr()) }))
    }

    pub fn check_registry(&self, reg_path: &str) -> Result<String, String> {
        let c = CString::new(reg_path).map_err(|e| e.to_string())?;
        Ok(self.take_string(unsafe { (self.check_registry)(c.as_ptr()) }))
    }

    pub fn scan_evtx(&self, evtx_path: &Path) -> Result<String, String> {
        let s = evtx_path.to_str().ok_or("invalid evtx path")?;
        let c = CString::new(s).map_err(|e| e.to_string())?;
        Ok(self.take_string(unsafe { (self.scan_evtx)(c.as_ptr()) }))
    }

    pub fn scan_system_events(&self) -> String {
        self.take_string(unsafe { (self.scan_system_events)() })
    }

    pub fn check_hosts_file(&self, hosts_path: Option<&Path>) -> String {
        let c_path;
        let ptr = match hosts_path.and_then(|p| p.to_str()) {
            Some(s) => {
                c_path = CString::new(s).unwrap_or_default();
                c_path.as_ptr()
            }
            None => std::ptr::null(),
        };
        self.take_string(unsafe { (self.check_hosts)(ptr) })
    }

    pub fn restore_hosts_file(&self, hosts_path: Option<&Path>, create_backup: bool) -> String {
        let c_path;
        let ptr = match hosts_path.and_then(|p| p.to_str()) {
            Some(s) => {
                c_path = CString::new(s).unwrap_or_default();
                c_path.as_ptr()
            }
            None => std::ptr::null(),
        };
        self.take_string(unsafe { (self.restore_hosts)(ptr, create_backup as i32) })
    }
}

pub fn default_portable_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next_to_exe = dir.join("openedr_static.dll");
            if next_to_exe.is_file() {
                return dir.to_path_buf();
            }
            let portable = dir.join("OpenMalwareScannerPortable");
            if portable.join("openedr_static.dll").is_file() {
                return portable;
            }
        }
    }
    PathBuf::from("OpenMalwareScannerPortable")
}
