//! Owlyshield Windows kernel driver communication client.
//!
//! Opens the edrdrv IOCTL device (`\\.\{157980D8-...}`) and exposes typed
//! methods for kill-process, block-path, registry-revert, and dynamic API
//! hook registration.  All commands are serialized as a `COM_MESSAGE`
//! (SharedDefs.h) and sent through the single `IOCTL_OWLY_COMPAT_MESSAGE`
//! control code — the only owlyshield command channel the integrated edrdrv
//! exposes.
//!
//! A process-wide shared `Driver` instance is maintained via `SHARED_DRIVER`
//! so that the single FltPort connection limit is not exceeded.

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::{HRESULT, PCWSTR};

// ── IOCTL device name ────────────────────────────────────────────────────────

const IOCTL_DEVICE_WIN32_NAME: &str = r"\\.\{157980D8-09B4-4580-B8B6-D32971D056DA}";

// ── IOCTL code & COM_MESSAGE protocol (mirror SharedDefs.h) ──────────────────

/// Sole command channel implemented by the integrated edrdrv.
/// `CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)`
const IOCTL_OWLY_COMPAT_MESSAGE: u32 = 0x222484;

/// WCHAR count of `COM_MESSAGE.path` / `COM_MESSAGE.quarantine_path`.
const MAX_FILE_NAME_LENGTH: usize = 520;

/// Byte size of the `COM_MESSAGE` struct (SharedDefs.h):
/// ULONG type @0, ULONG pid @4, ULONGLONG gid @8, WCHAR path[520] @16,
/// WCHAR quarantine_path[520] @1056. Total = 4 + 4 + 8 + 2*520*2 = 2096.
const COM_MESSAGE_SIZE: usize = 4 + 4 + 8 + MAX_FILE_NAME_LENGTH * 2 + MAX_FILE_NAME_LENGTH * 2;

// COM_MESSAGE_TYPE enum (SharedDefs.h) - full driver protocol map
const MESSAGE_ADD_SCAN_DIRECTORY: u32 = 0;
const MESSAGE_REM_SCAN_DIRECTORY: u32 = 1;
const MESSAGE_GET_OPS: u32 = 2;
const MESSAGE_SET_PID: u32 = 3;
const MESSAGE_KILL_GID: u32 = 4;
const MESSAGE_KILL_AND_QUARANTINE_GID: u32 = 5;
const MESSAGE_KILL_ONLY_GID: u32 = 6;
const MESSAGE_KILL_AND_REMOVE_GID: u32 = 7;
const MESSAGE_REVERT_REGISTRY_CHANGES: u32 = 8;
const MESSAGE_ADD_HOOK: u32 = 9;
const MESSAGE_HOOK_PROCESS: u32 = 10;
const MESSAGE_ADD_BLOCK_PATH: u32 = 11;

/// Serialize a `COM_MESSAGE` into its 2096-byte wire layout.
fn build_com_message(
    msg_type: u32,
    pid: u32,
    gid: u64,
    path: &[u16],
    quarantine_path: &[u16],
) -> Vec<u8> {
    let mut buf = vec![0u8; COM_MESSAGE_SIZE];
    buf[0..4].copy_from_slice(&msg_type.to_le_bytes());
    buf[4..8].copy_from_slice(&pid.to_le_bytes());
    buf[8..16].copy_from_slice(&gid.to_le_bytes());
    write_wide_string(&mut buf[16..16 + MAX_FILE_NAME_LENGTH * 2], path);
    write_wide_string(&mut buf[16 + MAX_FILE_NAME_LENGTH * 2..], quarantine_path);
    buf
}

/// Copy a UTF-16LE string into a fixed `WCHAR[MAX_FILE_NAME_LENGTH]` field,
/// truncating and always NUL-terminating (matches driver's `path[...-1]=L'\0'`).
fn write_wide_string(dst: &mut [u8], src: &[u16]) {
    let max_chars = MAX_FILE_NAME_LENGTH - 1;
    let n = src.len().min(max_chars);
    for (i, &w) in src[..n].iter().enumerate() {
        dst[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    dst[n * 2..n * 2 + 2].copy_from_slice(&0u16.to_le_bytes());
}

// ── Shared driver singleton ──────────────────────────────────────────────────

static SHARED_DRIVER: OnceLock<Arc<Mutex<Option<Driver>>>> = OnceLock::new();

/// Register a cloned [`Driver`] as the process-wide shared instance.
pub fn register_shared_driver(driver: Driver) {
    let cell = SHARED_DRIVER.get_or_init(|| Arc::new(Mutex::new(None)));
    if let Ok(mut guard) = cell.lock() {
        *guard = Some(driver);
    }
}

/// Borrow the shared driver and call `f` with a reference to it.
/// Returns `None` if no driver has been registered or the lock is poisoned.
pub fn with_shared_driver<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&Driver) -> T,
{
    let cell = SHARED_DRIVER.get()?;
    let guard = cell.lock().ok()?;
    guard.as_ref().map(f)
}

// ── Driver struct ────────────────────────────────────────────────────────────

/// Handle to the edrdrv IOCTL device.
///
/// `Clone` is cheap — the underlying `HANDLE` is wrapped in an `Arc` so
/// multiple `Driver` instances share the same kernel connection.
#[derive(Clone)]
pub struct Driver {
    handle: Arc<DriverHandle>,
}

struct DriverHandle(HANDLE);

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// SAFETY: The HANDLE is only used from within a Mutex or via the typed methods
// below which enforce exclusivity through the Arc reference count.
unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}

impl Driver {
    /// Open the edrdrv IOCTL device and return a connected [`Driver`].
    pub fn open_kernel_driver_com() -> Result<Driver, String> {
        let wide: Vec<u16> = IOCTL_DEVICE_WIN32_NAME
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();

        // GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000
        let desired_access: u32 = 0x80000000 | 0x40000000;
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                desired_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(h) if h != INVALID_HANDLE_VALUE => Ok(Driver {
                handle: Arc::new(DriverHandle(h)),
            }),
            Ok(_) | Err(_) => Err(format!(
                "Failed to open edrdrv IOCTL device '{}': GetLastError={}",
                IOCTL_DEVICE_WIN32_NAME,
                unsafe { windows::Win32::Foundation::GetLastError().0 }
            )),
        }
    }

    /// Inform the driver of this process's PID so it can exclude self-events.
    pub fn driver_set_app_pid(&self) -> Result<(), String> {
        let pid = std::process::id();
        let input = build_com_message(MESSAGE_SET_PID, pid, 0, &[], &[]);
        self.ioctl_no_output(IOCTL_OWLY_COMPAT_MESSAGE, &input)
            .map_err(|e| format!("driver_set_app_pid failed: {e}"))
    }

    /// Ask the driver to kill every process in the group identified by `gid`.
    ///
    /// Returns the HRESULT reported by the driver so callers can distinguish
    /// "killed" (`is_ok()`) from "process already gone" etc.
    pub fn try_kill(&self, gid: u64) -> Result<HRESULT, String> {
        let input = build_com_message(MESSAGE_KILL_GID, 0, gid, &[], &[]);
        let mut output = [0u8; 4];
        self.ioctl(IOCTL_OWLY_COMPAT_MESSAGE, &input, &mut output)
            .map_err(|e| format!("try_kill(gid={gid}) failed: {e}"))?;
        Ok(HRESULT(i32::from_le_bytes(output)))
    }

    /// Ask the driver to kill only the process group.
    pub fn kill_only_driver(&self, gid: u64) -> Result<HRESULT, String> {
        let input = build_com_message(MESSAGE_KILL_ONLY_GID, 0, gid, &[], &[]);
        let mut output = [0u8; 4];
        self.ioctl(IOCTL_OWLY_COMPAT_MESSAGE, &input, &mut output)
            .map_err(|e| format!("kill_only_driver(gid={gid}) failed: {e}"))?;
        Ok(HRESULT(i32::from_le_bytes(output)))
    }

    /// Ask the driver to kill the process group and quarantine the artifact.
    pub fn kill_and_quarantine_driver(&self, gid: u64, path: &Path) -> Result<HRESULT, String> {
        let path_wide: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
        let input = build_com_message(MESSAGE_KILL_AND_QUARANTINE_GID, 0, gid, &path_wide, &[]);
        let mut output = [0u8; 4];
        self.ioctl(IOCTL_OWLY_COMPAT_MESSAGE, &input, &mut output)
            .map_err(|e| format!("kill_and_quarantine_driver(gid={gid}) failed: {e}"))?;
        Ok(HRESULT(i32::from_le_bytes(output)))
    }

    /// Add a directory to the driver scan list.
    pub fn add_scan_directory(&self, path: &Path) -> Result<(), String> {
        let path_wide: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
        let input = build_com_message(MESSAGE_ADD_SCAN_DIRECTORY, 0, 0, &path_wide, &[]);
        self.ioctl_no_output(IOCTL_OWLY_COMPAT_MESSAGE, &input)
            .map_err(|e| format!("add_scan_directory failed: {e}"))
    }

    /// Remove a directory from the driver scan list.
    pub fn remove_scan_directory(&self, path: &Path) -> Result<(), String> {
        let path_wide: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
        let input = build_com_message(MESSAGE_REM_SCAN_DIRECTORY, 0, 0, &path_wide, &[]);
        self.ioctl_no_output(IOCTL_OWLY_COMPAT_MESSAGE, &input)
            .map_err(|e| format!("remove_scan_directory failed: {e}"))
    }

    /// Query operations counter from the driver.
    pub fn get_ops(&self) -> Result<u64, String> {
        let input = build_com_message(MESSAGE_GET_OPS, 0, 0, &[], &[]);
        let mut output = [0u8; 8];
        self.ioctl(IOCTL_OWLY_COMPAT_MESSAGE, &input, &mut output)
            .map_err(|e| format!("get_ops failed: {e}"))?;
        Ok(u64::from_le_bytes(output))
    }

    /// Ask the driver to kill the process group and delete the on-disk artifact.
    pub fn kill_and_remove_driver(&self, gid: u64, path: &Path) -> Result<HRESULT, String> {
        let path_wide: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
        let input = build_com_message(MESSAGE_KILL_AND_REMOVE_GID, 0, gid, &path_wide, &[]);
        let mut output = [0u8; 4];
        self.ioctl(IOCTL_OWLY_COMPAT_MESSAGE, &input, &mut output)
            .map_err(|e| format!("kill_and_remove_driver(gid={gid}) failed: {e}"))?;
        Ok(HRESULT(i32::from_le_bytes(output)))
    }

    /// Register a file path in the minifilter block list.
    pub fn add_block_path(&self, path: &str) -> Result<(), String> {
        let wide: Vec<u16> = path.encode_utf16().collect();
        let input = build_com_message(MESSAGE_ADD_BLOCK_PATH, 0, 0, &wide, &[]);
        // Driver's WriteBoolResult needs >= 1 output byte.
        let mut output = [0u8; 1];
        self.ioctl(IOCTL_OWLY_COMPAT_MESSAGE, &input, &mut output)
            .map(|_| ())
            .map_err(|e| format!("add_block_path('{path}') failed: {e}"))
    }

    /// Signal the driver to roll back tracked registry changes for a process group.
    pub fn revert_registry_changes(&self, gid: u64) -> Result<(), String> {
        let input = build_com_message(MESSAGE_REVERT_REGISTRY_CHANGES, 0, gid, &[], &[]);
        self.ioctl_no_output(IOCTL_OWLY_COMPAT_MESSAGE, &input)
            .map_err(|e| format!("revert_registry_changes(gid={gid}) failed: {e}"))
    }

    /// Register a (module, function) pair as a dynamic hook target.
    ///
    /// `event_id` is the 32-bit identifier that will appear in the hook-event
    /// LBVS payload so the Rust side can map it back to the API name.
    pub fn add_hook_target(
        &self,
        module: &str,
        function: &str,
        event_id: u32,
    ) -> Result<(), windows::core::Error> {
        // MESSAGE_ADD_HOOK: ModuleName=path, FunctionName=quarantine_path,
        // EventId=(ULONG)gid.
        let module_wide: Vec<u16> = module.encode_utf16().collect();
        let function_wide: Vec<u16> = function.encode_utf16().collect();
        let input = build_com_message(
            MESSAGE_ADD_HOOK,
            0,
            event_id as u64,
            &module_wide,
            &function_wide,
        );
        self.ioctl_no_output(IOCTL_OWLY_COMPAT_MESSAGE, &input)
            .map_err(|e| {
                windows::core::Error::new(
                    windows::core::HRESULT(0x80070000u32 as i32),
                    windows::core::HSTRING::from(e),
                )
            })
    }

    /// Apply all registered hook targets to the process identified by `pid`.
    pub fn hook_process(&self, pid: u32) -> Result<(), windows::core::Error> {
        let input = build_com_message(MESSAGE_HOOK_PROCESS, pid, 0, &[], &[]);
        self.ioctl_no_output(IOCTL_OWLY_COMPAT_MESSAGE, &input)
            .map_err(|e| {
                windows::core::Error::new(
                    windows::core::HRESULT(0x80070000u32 as i32),
                    windows::core::HSTRING::from(e),
                )
            })
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn ioctl(&self, code: u32, input: &[u8], output: &mut [u8]) -> Result<u32, String> {
        let mut bytes_returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                self.handle.0,
                code,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                Some(output.as_mut_ptr() as *mut _),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        if result.as_bool() {
            Ok(bytes_returned)
        } else {
            Err(format!(
                "DeviceIoControl(code=0x{code:08X}) failed: GetLastError={}",
                unsafe { windows::Win32::Foundation::GetLastError().0 }
            ))
        }
    }

    fn ioctl_no_output(&self, code: u32, input: &[u8]) -> Result<(), String> {
        self.ioctl(code, input, &mut []).map(|_| ())
    }
}
