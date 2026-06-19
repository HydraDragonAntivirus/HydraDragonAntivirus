#![cfg(windows)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use crate::error::Error;
use crate::ffi;

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

/// Update ClamAV databases via libfreshclam.dll.
pub fn run_freshclam_dll<P: AsRef<Path>>(
    dll_path: P,
    db_dir: P,
    certs_dir: Option<&Path>,
) -> Result<(), Error> {
    let dll_path = dll_path.as_ref();
    if !dll_path.exists() {
        return Err(Error::FreshclamNotFound(
            dll_path.to_string_lossy().into_owned(),
        ));
    }

    let dll_wide = path_to_utf16(dll_path);
    let hmodule = unsafe { ffi::LoadLibraryW(dll_wide.as_ptr()) };
    if hmodule.is_null() {
        let err = unsafe { format_win32_error(ffi::GetLastError()) };
        return Err(Error::FreshclamError(format!(
            "failed to load libfreshclam.dll: {}",
            err
        )));
    }

    macro_rules! get_proc {
        ($name:literal, $ty:ty) => {{
            let name = concat!($name, "\0").as_bytes();
            match unsafe { ffi::GetProcAddress(hmodule, name.as_ptr() as *const i8) } {
                Some(f) => unsafe { std::mem::transmute::<unsafe extern "C" fn(), $ty>(f) },
                None => {
                    unsafe { ffi::FreeLibrary(hmodule) };
                    return Err(Error::FreshclamError(
                        concat!($name, " not found in libfreshclam.dll").into(),
                    ));
                }
            }
        }};
    }

    let fc_initialize = get_proc!("fc_initialize", ffi::FcInitializeFn);
    let fc_update_databases = get_proc!("fc_update_databases", ffi::FcUpdateDatabasesFn);
    let fc_cleanup = get_proc!("fc_cleanup", ffi::FcCleanupFn);

    let db_dir_cstr = std::ffi::CString::new(db_dir.as_ref().to_str().unwrap_or_default())
        .map_err(|e| Error::FreshclamError(format!("invalid db_dir: {}", e)))?;

    let certs_cstr =
        certs_dir.and_then(|p| std::ffi::CString::new(p.to_str().unwrap_or_default()).ok());

    let mut config = ffi::FcConfig {
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
        unsafe {
            fc_cleanup();
            ffi::FreeLibrary(hmodule);
        }
        return Err(Error::FreshclamError(format!(
            "fc_initialize failed with code {}",
            rc
        )));
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

    unsafe {
        fc_cleanup();
        ffi::FreeLibrary(hmodule);
    }

    if rc != 0 && rc != 1 {
        return Err(Error::FreshclamError(format!(
            "fc_update_databases failed with code {}",
            rc
        )));
    }

    Ok(())
}
