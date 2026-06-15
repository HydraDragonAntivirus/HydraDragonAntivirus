#![cfg(windows)]

use std::ffi::c_void;

use crate::types::ClScanOptions;

pub type HMODULE = *mut c_void;
pub type DWORD = u32;
pub type BOOL = i32;
pub type DllDirectoryCookie = *mut c_void;

pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x00001000;
pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x00000400;
pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x00000100;

pub type ClInitFn = unsafe extern "C" fn(u32) -> i32;
pub type ClEngineNewFn = unsafe extern "C" fn() -> *mut c_void;
pub type ClEngineFreeFn = unsafe extern "C" fn(*mut c_void) -> i32;
pub type ClLoadFn = unsafe extern "C" fn(*const i8, *mut c_void, *mut u32, u32) -> i32;
pub type ClEngineCompileFn = unsafe extern "C" fn(*mut c_void) -> i32;
pub type ClEngineSetNumFn = unsafe extern "C" fn(*mut c_void, u32, u32) -> i32;
pub type ClScanFileFn = unsafe extern "C" fn(
    *const i8,
    *mut *const i8,
    *mut u32,
    *const c_void,
    *const ClScanOptions,
) -> i32;
pub type ClRetVerFn = unsafe extern "C" fn() -> *const i8;
pub type ClStrErrorFn = unsafe extern "C" fn(i32) -> *const i8;

#[derive(Clone, Copy)]
pub struct Api {
    pub cl_init: Option<ClInitFn>,
    pub cl_engine_new: Option<ClEngineNewFn>,
    pub cl_engine_free: Option<ClEngineFreeFn>,
    pub cl_load: Option<ClLoadFn>,
    pub cl_engine_compile: Option<ClEngineCompileFn>,
    pub cl_engine_set_num: Option<ClEngineSetNumFn>,
    pub cl_scanfile: Option<ClScanFileFn>,
    pub cl_retver: Option<ClRetVerFn>,
    pub cl_strerror: Option<ClStrErrorFn>,
}

impl Api {
    pub const fn zeroed() -> Self {
        Self {
            cl_init: None,
            cl_engine_new: None,
            cl_engine_free: None,
            cl_load: None,
            cl_engine_compile: None,
            cl_engine_set_num: None,
            cl_scanfile: None,
            cl_retver: None,
            cl_strerror: None,
        }
    }
}

unsafe impl Send for Api {}
unsafe impl Sync for Api {}

extern "system" {
    pub fn SetDefaultDllDirectories(directoryFlags: u32) -> BOOL;
    pub fn AddDllDirectory(NewDirectory: *const u16) -> DllDirectoryCookie;
    pub fn RemoveDllDirectory(Cookie: DllDirectoryCookie) -> BOOL;
    pub fn LoadLibraryExW(lpLibFileName: *const u16, hFile: *mut c_void, dwFlags: u32) -> HMODULE;
    pub fn LoadLibraryW(lpLibFileName: *const u16) -> HMODULE;
    pub fn FreeLibrary(hLibModule: HMODULE) -> BOOL;
    pub fn GetProcAddress(
        hModule: HMODULE,
        lpProcName: *const i8,
    ) -> Option<unsafe extern "C" fn()>;
    pub fn GetLastError() -> DWORD;
    pub fn FormatMessageW(
        dwFlags: DWORD,
        lpSource: *const c_void,
        dwMessageId: DWORD,
        dwLanguageId: DWORD,
        lpBuffer: *mut u16,
        nSize: DWORD,
        Arguments: *mut c_void,
    ) -> DWORD;
    pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    pub fn WideCharToMultiByte(
        CodePage: u32,
        dwFlags: DWORD,
        lpWideCharStr: *const u16,
        cchWideChar: i32,
        lpMultiByteStr: *mut i8,
        cbMultiByte: i32,
        lpDefaultChar: *const i8,
        lpUsedDefaultChar: *mut BOOL,
    ) -> i32;
    pub fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
    ) -> BOOL;
    pub fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: DWORD) -> DWORD;
    pub fn TerminateProcess(hProcess: *mut c_void, uExitCode: u32) -> BOOL;
    pub fn CloseHandle(hObject: *mut c_void) -> BOOL;
    pub fn GetExitCodeProcess(hProcess: *mut c_void, lpExitCode: *mut DWORD) -> BOOL;
}

// libfreshclam bindings
#[repr(C)]
pub struct FcConfig {
    pub msg_flags: u32,
    pub log_flags: u32,
    pub max_log_size: u64,
    pub max_attempts: u32,
    pub connect_timeout: u32,
    pub request_timeout: u32,
    pub b_compress_local_database: u32,
    pub log_file: *const i8,
    pub log_facility: *const i8,
    pub local_ip: *const i8,
    pub user_agent: *const i8,
    pub proxy_server: *const i8,
    pub proxy_port: u16,
    pub proxy_username: *const i8,
    pub proxy_password: *const i8,
    pub database_directory: *const i8,
    pub temp_directory: *const i8,
    pub certs_directory: *const i8,
    pub b_fips_limits: u8,
}

unsafe impl Send for FcConfig {}
unsafe impl Sync for FcConfig {}

pub type FcInitializeFn = unsafe extern "C" fn(*mut FcConfig) -> i32;
pub type FcCleanupFn = unsafe extern "C" fn();
pub type FcUpdateDatabasesFn = unsafe extern "C" fn(
    *mut *mut i8,
    u32,
    *mut *mut i8,
    u32,
    i32,
    *const i8,
    i32,
    *mut c_void,
    *mut u32,
) -> i32;

pub const CP_UTF8: u32 = 65001;
pub const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x00000100;
pub const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
pub const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;
pub const WAIT_TIMEOUT: DWORD = 0x00000102;
pub const WAIT_OBJECT_0: DWORD = 0x00000000;
pub const WAIT_FAILED: DWORD = 0xFFFFFFFF;
