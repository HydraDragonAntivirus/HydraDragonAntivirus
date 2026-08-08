//! Owlyshield Windows kernel driver communication client.
//!
//! Opens the edrdrv IOCTL device (`\\.\{157980D8-...}`) and exposes typed
//! methods for kill-process, block-path, registry-revert, and dynamic API
//! hook registration.  All IOCTL codes match `edrdrvapi.hpp`.
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

// ── IOCTL code helpers (mirror edrdrvapi.hpp CTL_CODE macro) ─────────────────
//
//  CTL_CODE(DeviceType=0x8001, Function=0x0800+code, Method=METHOD_BUFFERED=0,
//           Access)
//  FILE_READ_ACCESS  = 0x0001
//  FILE_WRITE_ACCESS = 0x0002
//  METHOD_BUFFERED   = 0

#[inline(always)]
const fn ctl_code(code: u32, read: bool, write: bool) -> u32 {
    let device_type: u32 = 0x8001;
    let function: u32 = 0x0800 + code;
    let method: u32 = 0; // METHOD_BUFFERED
    let access: u32 = (if read { 0x0001u32 } else { 0 }) | (if write { 0x0002u32 } else { 0 });
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Kill process group by GID.
/// Input: 8-byte little-endian GID. Output: 4-byte HRESULT.
const IOCTL_KILL_GID: u32 = ctl_code(0x10, true, false);

/// Kill and remove file by GID + path.
/// Input: 8-byte GID + UTF-16LE null-terminated path. Output: 4-byte HRESULT.
const IOCTL_KILL_AND_REMOVE: u32 = ctl_code(0x11, true, false);

/// Block path access in the minifilter.
/// Input: UTF-16LE null-terminated path. Output: none.
const IOCTL_BLOCK_PATH: u32 = ctl_code(0x12, true, false);

/// Revert registry changes for a GID.
/// Input: 8-byte little-endian GID. Output: none.
const IOCTL_REVERT_REGISTRY: u32 = ctl_code(0x13, true, false);

/// Register an API hook target (module + function + event_id).
/// Input: 4-byte event_id + UTF-16LE module\0function\0. Output: none.
const IOCTL_ADD_HOOK_TARGET: u32 = ctl_code(0x20, true, false);

/// Apply registered hooks to a process.
/// Input: 4-byte PID. Output: none.
const IOCTL_HOOK_PROCESS: u32 = ctl_code(0x21, true, false);

/// Set the current process PID as the owlyshield monitor process.
/// Input: 4-byte PID. Output: none.
/// Note: Must use FILE_ANY_ACCESS (false, false) to match driver definition.
const IOCTL_SET_APP_PID: u32 = ctl_code(0x30, false, false); // Calculates 0x800120C0

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
        let input = pid.to_le_bytes();
        self.ioctl_no_output(IOCTL_SET_APP_PID, &input)
            .map_err(|e| format!("driver_set_app_pid failed: {e}"))
    }

    /// Ask the driver to kill every process in the group identified by `gid`.
    ///
    /// Returns the HRESULT reported by the driver so callers can distinguish
    /// "killed" (`is_ok()`) from "process already gone" etc.
    pub fn try_kill(&self, gid: u64) -> Result<HRESULT, String> {
        let input = gid.to_le_bytes();
        let mut output = [0u8; 4];
        self.ioctl(IOCTL_KILL_GID, &input, &mut output)
            .map_err(|e| format!("try_kill(gid={gid}) failed: {e}"))?;
        Ok(HRESULT(i32::from_le_bytes(output)))
    }

    /// Ask the driver to kill the process group and delete the on-disk artifact.
    pub fn kill_and_remove_driver(&self, gid: u64, path: &Path) -> Result<HRESULT, String> {
        let path_wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();

        let mut buf = Vec::with_capacity(8 + path_wide.len() * 2);
        buf.extend_from_slice(&gid.to_le_bytes());
        for w in &path_wide {
            buf.extend_from_slice(&w.to_le_bytes());
        }

        let mut output = [0u8; 4];
        self.ioctl(IOCTL_KILL_AND_REMOVE, &buf, &mut output)
            .map_err(|e| format!("kill_and_remove_driver(gid={gid}) failed: {e}"))?;
        Ok(HRESULT(i32::from_le_bytes(output)))
    }

    /// Register a file path in the minifilter block list.
    pub fn add_block_path(&self, path: &str) -> Result<(), String> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.ioctl_no_output(IOCTL_BLOCK_PATH, &bytes)
            .map_err(|e| format!("add_block_path('{path}') failed: {e}"))
    }

    /// Signal the driver to roll back tracked registry changes for a process group.
    pub fn revert_registry_changes(&self, gid: u64) -> Result<(), String> {
        let input = gid.to_le_bytes();
        self.ioctl_no_output(IOCTL_REVERT_REGISTRY, &input)
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
        // Wire format: [event_id: u32 LE] [module: UTF-16LE NUL] [function: UTF-16LE NUL]
        let mut buf = Vec::new();
        buf.extend_from_slice(&event_id.to_le_bytes());
        for w in module.encode_utf16().chain(std::iter::once(0u16)) {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        for w in function.encode_utf16().chain(std::iter::once(0u16)) {
            buf.extend_from_slice(&w.to_le_bytes());
        }

        self.ioctl_no_output(IOCTL_ADD_HOOK_TARGET, &buf)
            .map_err(|e| {
                windows::core::Error::new(
                    windows::core::HRESULT(0x80070000u32 as i32),
                    windows::core::HSTRING::from(e),
                )
            })
    }

    /// Apply all registered hook targets to the process identified by `pid`.
    pub fn hook_process(&self, pid: u32) -> Result<(), windows::core::Error> {
        let input = pid.to_le_bytes();
        self.ioctl_no_output(IOCTL_HOOK_PROCESS, &input)
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
