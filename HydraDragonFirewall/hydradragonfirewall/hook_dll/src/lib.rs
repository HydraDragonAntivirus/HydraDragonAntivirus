use std::ffi::{c_void, CString};
use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Networking::WinSock::{SOCKET, SOCKADDR, SOCKADDR_IN, AF_INET};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::Storage::FileSystem::{WriteFile, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ};
use windows::Win32::UI::WindowsAndMessaging::{HHOOK, HOOKPROC, WINDOWS_HOOK_ID};
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, WINEVENTPROC};

// Force linking to the minhook crate
extern crate minhook;

// Raw MinHook FFI (using C calling convention)
unsafe extern "C" {
    fn MH_Initialize() -> i32;
    fn MH_CreateHook(pTarget: *mut c_void, pDetour: *mut c_void, ppOriginal: *mut *mut c_void) -> i32;
    fn MH_EnableHook(pTarget: *mut c_void) -> i32;
}

// Global storage for original functions
static mut ORIGINAL_CONNECT: Option<unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32> = None;
static mut ORIGINAL_SET_WINDOWS_HOOK_EX: Option<unsafe extern "system" fn(WINDOWS_HOOK_ID, HOOKPROC, HINSTANCE, u32) -> HHOOK> = None;
static mut ORIGINAL_SET_WIN_EVENT_HOOK: Option<unsafe extern "system" fn(u32, u32, HINSTANCE, WINEVENTPROC, u32, u32, u32) -> HWINEVENTHOOK> = None;

// WinInet
static mut ORIGINAL_INTERNET_CONNECT_W: Option<unsafe extern "system" fn(*mut c_void, *const u16, u16, *const u16, *const u16, u32, u32, usize) -> *mut c_void> = None;
static mut ORIGINAL_HTTP_OPEN_REQUEST_W: Option<unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32, usize) -> *mut c_void> = None;
static mut ORIGINAL_INTERNET_CLOSE_HANDLE: Option<unsafe extern "system" fn(*mut c_void) -> i32> = None;

// WinHttp
static mut ORIGINAL_WINHTTP_CONNECT: Option<unsafe extern "system" fn(*mut c_void, *const u16, u16, u32) -> *mut c_void> = None;
static mut ORIGINAL_WINHTTP_OPEN_REQUEST: Option<unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32) -> *mut c_void> = None;
static mut ORIGINAL_WINHTTP_CLOSE_HANDLE: Option<unsafe extern "system" fn(*mut c_void) -> i32> = None;

lazy_static! {
    static ref HANDLE_MAP: Mutex<HashMap<usize, String>> = Mutex::new(HashMap::new());
}

// Helper: Send log to firewall pipe
unsafe fn send_log(msg: String) {
    let pipe_name = windows::core::s!("\\\\.\\pipe\\HydraDragonFirewall");
    
    unsafe {
        let handle_res = windows::Win32::Storage::FileSystem::CreateFileA(
            pipe_name,
            windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        );
        
        if let Ok(handle) = handle_res {
            if !handle.is_invalid() {
                let msg_c = CString::new(msg).unwrap_or_default();
                let bytes = msg_c.as_bytes();
                let mut written = 0;
                let _ = WriteFile(handle, Some(bytes), Some(&mut written), None);
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }
}

// CSIDL constants
const CSIDL_DESKTOPDIRECTORY: u32 = 0x0010;
const CSIDL_APPDATA: u32 = 0x001a;
const CSIDL_PROGRAM_FILES: u32 = 0x0026;
const CSIDL_FLAG_CREATE: u32 = 0x8000;

unsafe fn get_folder_path(csidl: u32) -> String {
    use windows::Win32::UI::Shell::SHGetFolderPathW;
    let mut buffer = [0u16; 260];
    if unsafe { SHGetFolderPathW(None, (csidl | CSIDL_FLAG_CREATE) as i32, None, 0, &mut buffer).is_ok() } {
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..len])
    } else {
        String::new()
    }
}

lazy_static! {
    static ref SAFE_PATHS: Vec<String> = {
        unsafe {
            let mut paths = Vec::new();
            let prog_files = get_folder_path(CSIDL_PROGRAM_FILES);
            if !prog_files.is_empty() { paths.push(format!("{}\\{}", prog_files, "HydraDragonAntivirus")); }
            let desktop = get_folder_path(CSIDL_DESKTOPDIRECTORY);
            if !desktop.is_empty() { paths.push(format!("{}\\{}", desktop, "Sanctum")); }
            let appdata = get_folder_path(CSIDL_APPDATA);
            if !appdata.is_empty() { paths.push(format!("{}\\{}", appdata, "Sanctum")); }
            paths
        }
    };
}

unsafe fn get_current_process_path() -> String {
    use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut buffer = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(None, &mut buffer) };
    if len > 0 { String::from_utf16_lossy(&buffer[..len as usize]) } else { String::new() }
}

unsafe fn is_safe_process() -> bool {
    let path = unsafe { get_current_process_path() };
    for safe in SAFE_PATHS.iter() {
        if path.contains(safe) { return true; }
    }
    false
}

// Detours
unsafe extern "system" fn connect_detour(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    let safe = unsafe { is_safe_process() };
    if !safe && !name.is_null() && namelen as usize >= mem::size_of::<SOCKADDR_IN>() {
        let addr = name as *const SOCKADDR_IN;
        if unsafe { (*addr).sin_family } == AF_INET {
            let port = u16::from_be(unsafe { (*addr).sin_port });
            unsafe { send_log(format!("PID: {} PORT: {}", std::process::id(), port)); }
        }
    }
    if let Some(original) = unsafe { ORIGINAL_CONNECT } { unsafe { original(s, name, namelen) } } else { -1 }
}

unsafe extern "system" fn set_windows_hook_ex_detour(id: WINDOWS_HOOK_ID, proc: HOOKPROC, hmod: HINSTANCE, tid: u32) -> HHOOK {
    let safe = unsafe { is_safe_process() };
    if !safe { unsafe { send_log(format!("🛡️ SetWindowsHookEx detected! ID: {:?} TID: {}", id, tid)); } }
    if let Some(original) = unsafe { ORIGINAL_SET_WINDOWS_HOOK_EX } { unsafe { original(id, proc, hmod, tid) } } else { HHOOK::default() }
}

unsafe extern "system" fn set_win_event_hook_detour(event_min: u32, event_max: u32, hmod: HINSTANCE, proc: WINEVENTPROC, pid: u32, tid: u32, flags: u32) -> HWINEVENTHOOK {
    let safe = unsafe { is_safe_process() };
    if !safe { unsafe { send_log(format!("🛡️ SetWinEventHook detected! PID: {} TID: {}", pid, tid)); } }
    if let Some(original) = unsafe { ORIGINAL_SET_WIN_EVENT_HOOK } { unsafe { original(event_min, event_max, hmod, proc, pid, tid, flags) } } else { HWINEVENTHOOK::default() }
}

// WinInet Detours
unsafe extern "system" fn internet_connect_w_detour(h_internet: *mut c_void, server_name: *const u16, port: u16, user: *const u16, pass: *const u16, service: u32, flags: u32, context: usize) -> *mut c_void {
    let result = if let Some(original) = unsafe { ORIGINAL_INTERNET_CONNECT_W } { unsafe { original(h_internet, server_name, port, user, pass, service, flags, context) } } else { ptr::null_mut() };
    if !result.is_null() && !server_name.is_null() {
        let len = (0..).find(|&i| unsafe { *server_name.add(i) == 0 }).unwrap_or(0);
        let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(server_name, len) });
        HANDLE_MAP.lock().unwrap().insert(result as usize, name);
    }
    result
}

unsafe extern "system" fn http_open_request_w_detour(h_connect: *mut c_void, verb: *const u16, path: *const u16, version: *const u16, referer: *const u16, types: *const *const u16, flags: u32, context: usize) -> *mut c_void {
    let result = if let Some(original) = unsafe { ORIGINAL_HTTP_OPEN_REQUEST_W } { unsafe { original(h_connect, verb, path, version, referer, types, flags, context) } } else { ptr::null_mut() };
    let safe = unsafe { is_safe_process() };
    if !safe && !h_connect.is_null() {
        let host = HANDLE_MAP.lock().unwrap().get(&(h_connect as usize)).cloned().unwrap_or_default();
        let path_str = if !path.is_null() {
            let len = (0..).find(|&i| unsafe { *path.add(i) == 0 }).unwrap_or(0);
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(path, len) })
        } else { String::from("/") };
        let scheme = if (flags & 0x00800000) != 0 { "https" } else { "http" };
        let full_url = if !host.is_empty() { format!("{}://{}{}{}", scheme, host, if path_str.starts_with('/') { "" } else { "/" }, path_str) } else { path_str };
        unsafe { send_log(format!("PID: {} URL: {}", std::process::id(), full_url)); }
    }
    result
}

unsafe extern "system" fn internet_close_handle_detour(handle: *mut c_void) -> i32 {
    if !handle.is_null() { HANDLE_MAP.lock().unwrap().remove(&(handle as usize)); }
    if let Some(original) = unsafe { ORIGINAL_INTERNET_CLOSE_HANDLE } { unsafe { original(handle) } } else { 0 }
}

// WinHttp Detours
unsafe extern "system" fn winhttp_connect_detour(h_session: *mut c_void, server_name: *const u16, port: u16, reserved: u32) -> *mut c_void {
    let result = if let Some(original) = unsafe { ORIGINAL_WINHTTP_CONNECT } { unsafe { original(h_session, server_name, port, reserved) } } else { ptr::null_mut() };
    if !result.is_null() && !server_name.is_null() {
        let len = (0..).find(|&i| unsafe { *server_name.add(i) == 0 }).unwrap_or(0);
        let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(server_name, len) });
        HANDLE_MAP.lock().unwrap().insert(result as usize, name);
    }
    result
}

unsafe extern "system" fn winhttp_open_request_detour(h_connect: *mut c_void, verb: *const u16, path: *const u16, version: *const u16, referer: *const u16, types: *const *const u16, flags: u32) -> *mut c_void {
    let result = if let Some(original) = unsafe { ORIGINAL_WINHTTP_OPEN_REQUEST } { unsafe { original(h_connect, verb, path, version, referer, types, flags) } } else { ptr::null_mut() };
    let safe = unsafe { is_safe_process() };
    if !safe && !h_connect.is_null() {
        let host = HANDLE_MAP.lock().unwrap().get(&(h_connect as usize)).cloned().unwrap_or_default();
        let path_str = if !path.is_null() {
            let len = (0..).find(|&i| unsafe { *path.add(i) == 0 }).unwrap_or(0);
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(path, len) })
        } else { String::from("/") };
        let scheme = if (flags & 0x00800000) != 0 { "https" } else { "http" };
        let full_url = if !host.is_empty() { format!("{}://{}{}{}", scheme, host, if path_str.starts_with('/') { "" } else { "/" }, path_str) } else { path_str };
        unsafe { send_log(format!("PID: {} URL: {}", std::process::id(), full_url)); }
    }
    result
}

unsafe extern "system" fn winhttp_close_handle_detour(handle: *mut c_void) -> i32 {
    if !handle.is_null() { HANDLE_MAP.lock().unwrap().remove(&(handle as usize)); }
    if let Some(original) = unsafe { ORIGINAL_WINHTTP_CLOSE_HANDLE } { unsafe { original(handle) } } else { 0 }
}

fn initialize_hooks() {
    unsafe {
        if MH_Initialize() != 0 { return; }

        if let Ok(ws2) = LoadLibraryA(windows::core::s!("ws2_32.dll")) {
            if let Some(target) = GetProcAddress(ws2, windows::core::s!("connect")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, connect_detour as _, &mut original) == 0 {
                    ORIGINAL_CONNECT = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
        }

        if let Ok(user32) = LoadLibraryA(windows::core::s!("user32.dll")) {
            if let Some(target) = GetProcAddress(user32, windows::core::s!("SetWindowsHookExW")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, set_windows_hook_ex_detour as _, &mut original) == 0 {
                    ORIGINAL_SET_WINDOWS_HOOK_EX = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
            if let Some(target) = GetProcAddress(user32, windows::core::s!("SetWinEventHook")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, set_win_event_hook_detour as _, &mut original) == 0 {
                    ORIGINAL_SET_WIN_EVENT_HOOK = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
        }

        if let Ok(wininet) = LoadLibraryA(windows::core::s!("wininet.dll")) {
            if let Some(target) = GetProcAddress(wininet, windows::core::s!("InternetConnectW")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, internet_connect_w_detour as _, &mut original) == 0 {
                    ORIGINAL_INTERNET_CONNECT_W = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
            if let Some(target) = GetProcAddress(wininet, windows::core::s!("HttpOpenRequestW")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, http_open_request_w_detour as _, &mut original) == 0 {
                    ORIGINAL_HTTP_OPEN_REQUEST_W = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
            if let Some(target) = GetProcAddress(wininet, windows::core::s!("InternetCloseHandle")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, internet_close_handle_detour as _, &mut original) == 0 {
                    ORIGINAL_INTERNET_CLOSE_HANDLE = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
        }

        if let Ok(winhttp) = LoadLibraryA(windows::core::s!("winhttp.dll")) {
            if let Some(target) = GetProcAddress(winhttp, windows::core::s!("WinHttpConnect")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, winhttp_connect_detour as _, &mut original) == 0 {
                    ORIGINAL_WINHTTP_CONNECT = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
            if let Some(target) = GetProcAddress(winhttp, windows::core::s!("WinHttpOpenRequest")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, winhttp_open_request_detour as _, &mut original) == 0 {
                    ORIGINAL_WINHTTP_OPEN_REQUEST = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
            if let Some(target) = GetProcAddress(winhttp, windows::core::s!("WinHttpCloseHandle")) {
                let mut original: *mut c_void = ptr::null_mut();
                if MH_CreateHook(target as _, winhttp_close_handle_detour as _, &mut original) == 0 {
                    ORIGINAL_WINHTTP_CLOSE_HANDLE = mem::transmute(original);
                    MH_EnableHook(target as _);
                }
            }
        }
        
        send_log("🛡️ EDR Hooks (Winsock, WinInet, WinHttp) active!".into());
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, reserved: *mut c_void) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(500));
            initialize_hooks();
        });
    }
    true
}
