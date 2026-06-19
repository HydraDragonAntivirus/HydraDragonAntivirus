#![cfg(windows)]

use std::ffi::c_void;

pub type HMODULE = *mut c_void;
pub type DWORD = u32;
pub type BOOL = i32;

unsafe extern "system" {
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
