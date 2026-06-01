//! OpenEDR/edrdrv transport for the Owlyshield behavior engine.
//!
//! This replaces the old Owlyshield `\\RWFilter` polling protocol. Events are
//! received from edrdrv's OpenEDR fltport and converted into the existing
//! `IOMessage` model by the Windows-owned LBVS mapper.

use core::ffi::c_void;
use std::mem;
use std::path::Path;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

use wchar::wchar_t;
use widestring::U16CString;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::Storage::InstallableFileSystems::{
    FILTER_MESSAGE_HEADER, FilterConnectCommunicationPort, FilterGetMessage,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::{Error, PCWSTR};

use crate::shared_def::{DriverComMessageType, IOMessage};

use super::openedr_lbvs::lbvs_to_iomessage;

pub type BufPath = [wchar_t; 520];

const EDRDRV_FLTPORT_NAME: &str = "\\{A6F9548E-BE5E-4BE6-A632-18AC626532FE}";
const EDRDRV_IOCTL_WIN32_NAME: &str = "\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}";

const FILE_DEVICE_UNKNOWN_VALUE: u32 = 0x0000_0022;
const METHOD_BUFFERED_VALUE: u32 = 0;
const FILE_ANY_ACCESS_VALUE: u32 = 0;
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}
const IOCTL_OWLY_COMPAT_MESSAGE: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN_VALUE,
    0x921,
    METHOD_BUFFERED_VALUE,
    FILE_ANY_ACCESS_VALUE,
);

static SHARED_DRIVER: OnceLock<Mutex<Option<Driver>>> = OnceLock::new();

fn shared_driver_slot() -> &'static Mutex<Option<Driver>> {
    SHARED_DRIVER.get_or_init(|| Mutex::new(None))
}

pub fn register_shared_driver(driver: Driver) {
    *shared_driver_slot().lock().unwrap() = Some(driver);
}

pub fn with_shared_driver<T>(f: impl FnOnce(&Driver) -> T) -> Option<T> {
    let driver = shared_driver_slot().lock().unwrap().clone();
    driver.as_ref().map(f)
}

#[derive(Debug)]
#[repr(C)]
struct DriverComMessage {
    r#type: u32,
    pid: u32,
    gid: u64,
    path: BufPath,
    quarantine_path: BufPath,
}

#[derive(Debug, Clone)]
pub struct Driver {
    port_handle: Arc<Mutex<HANDLE>>,
    ioctl_handle: Arc<Mutex<HANDLE>>,
}

impl Driver {
    pub fn open_kernel_driver_com() -> Result<Driver, Error> {
        let port_name = U16CString::from_str(EDRDRV_FLTPORT_NAME).unwrap();
        let port_handle = unsafe {
            FilterConnectCommunicationPort(
                PCWSTR(port_name.as_ptr()),
                0,
                Some(ptr::null()),
                0,
                Some(ptr::null_mut()),
            )?
        };

        let ioctl_name = U16CString::from_str(EDRDRV_IOCTL_WIN32_NAME).unwrap();
        let ioctl_handle = unsafe {
            CreateFileW(
                PCWSTR(ioctl_name.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        Ok(Driver {
            port_handle: Arc::new(Mutex::new(port_handle)),
            ioctl_handle: Arc::new(Mutex::new(ioctl_handle)),
        })
    }

    pub fn _close_kernel_communication(&self) -> bool {
        let mut ok = true;
        for slot in [&self.port_handle, &self.ioctl_handle] {
            let mut guard = slot.lock().unwrap();
            let handle = *guard;
            if !handle.is_invalid() && handle != INVALID_HANDLE_VALUE {
                ok &= unsafe { CloseHandle(handle).as_bool() };
                *guard = HANDLE::default();
            }
        }
        ok
    }

    fn current_port_handle(&self) -> HANDLE {
        *self.port_handle.lock().unwrap()
    }

    fn current_ioctl_handle(&self) -> HANDLE {
        *self.ioctl_handle.lock().unwrap()
    }

    pub fn get_iomsg(&self, scratch: &mut [u8]) -> Result<Option<IOMessage>, Error> {
        let header_size = mem::size_of::<FILTER_MESSAGE_HEADER>();
        if scratch.len() <= header_size + 16 {
            return Ok(None);
        }

        unsafe {
            ptr::write_bytes(scratch.as_mut_ptr(), 0, scratch.len());

            let header = scratch.as_mut_ptr() as *mut FILTER_MESSAGE_HEADER;
            FilterGetMessage(
                self.current_port_handle(),
                header,
                scratch.len() as u32,
                None,
            )?;

            // FilterGetMessage writes FILTER_MESSAGE_HEADER followed by the raw
            // payload passed to FltSendMessage. The payload is LBVS and contains
            // its own declared size, so the parser can safely ignore zeroed tail bytes.
            let payload = &scratch[header_size..];

            match lbvs_to_iomessage(payload) {
                Ok(iomsg) => Ok(Some(iomsg)),
                Err(e) => {
                    crate::Logging::warning(&format!("[OpenEDR] Failed to parse LBVS event: {e}"));
                    Ok(None)
                }
            }
        }
    }

    fn send_compat_message(
        &self,
        msg: &mut DriverComMessage,
        output: Option<&mut [u8]>,
    ) -> Result<u32, Error> {
        let mut bytes_returned = 0u32;
        let (out_ptr, out_len) = if let Some(out) = output {
            (Some(out.as_mut_ptr() as *mut c_void), out.len() as u32)
        } else {
            (None, 0)
        };

        unsafe {
            DeviceIoControl(
                self.current_ioctl_handle(),
                IOCTL_OWLY_COMPAT_MESSAGE,
                Some(msg as *mut _ as *const c_void),
                mem::size_of::<DriverComMessage>() as u32,
                out_ptr,
                out_len,
                Some(&mut bytes_returned),
                None,
            )
            .ok()?;
        }
        Ok(bytes_returned)
    }

    pub fn driver_set_app_pid(&self) -> Result<(), Error> {
        let mut msg = Driver::build_message(
            DriverComMessageType::MessageSetPid,
            std::process::id(),
            0,
            r"\Device\HarddiskVolume",
            "",
        );
        self.send_compat_message(&mut msg, None)?;
        Ok(())
    }

    pub fn try_kill(&self, gid: u64) -> Result<windows::core::HRESULT, Error> {
        self.send_gid_command(DriverComMessageType::MessageKillGid, gid, None)
    }

    pub fn kill_and_quarantine_driver(
        &self,
        gid: u64,
        path: &Path,
    ) -> Result<windows::core::HRESULT, Error> {
        self.send_gid_command(
            DriverComMessageType::MessageKillAndQuarantineGid,
            gid,
            path.to_str(),
        )
    }

    pub fn kill_and_remove_driver(
        &self,
        gid: u64,
        path: &Path,
    ) -> Result<windows::core::HRESULT, Error> {
        self.send_gid_command(
            DriverComMessageType::MessageKillAndRemoveGid,
            gid,
            path.to_str(),
        )
    }

    pub fn revert_registry_changes(&self, gid: u64) -> Result<(), Error> {
        let mut msg = Driver::build_message(
            DriverComMessageType::MessageRevertRegistryChanges,
            0,
            gid,
            "",
            "",
        );
        self.send_compat_message(&mut msg, None)?;
        Ok(())
    }

    pub fn add_hook_target_for_pid(
        &self,
        pid: u32,
        module: &str,
        function: &str,
        event_id: u32,
    ) -> Result<(), Error> {
        let mut msg = Driver::build_message(
            DriverComMessageType::MessageAddHook,
            pid,
            event_id as u64,
            module,
            function,
        );
        self.send_compat_message(&mut msg, None)?;
        Ok(())
    }

    pub fn add_hook_target(
        &self,
        module: &str,
        function: &str,
        event_id: u32,
    ) -> Result<(), Error> {
        self.add_hook_target_for_pid(0, module, function, event_id)
    }

    pub fn hook_process(&self, pid: u32) -> Result<(), Error> {
        let mut msg =
            Driver::build_message(DriverComMessageType::MessageHookProcess, pid, 0, "", "");
        self.send_compat_message(&mut msg, None)?;
        Ok(())
    }

    pub fn add_block_path(&self, path: &str) -> Result<windows::core::HRESULT, Error> {
        self.send_gid_command(DriverComMessageType::MessageAddBlockPath, 0, Some(path))
    }

    fn send_gid_command(
        &self,
        command: DriverComMessageType,
        gid: u64,
        path: Option<&str>,
    ) -> Result<windows::core::HRESULT, Error> {
        let (real_gid, real_pid) = if gid & 0x8000_0000_0000_0000 != 0 {
            (0, (gid & !0x8000_0000_0000_0000) as u32)
        } else {
            (gid, 0)
        };
        let mut msg = Driver::build_message(command, real_pid, real_gid, path.unwrap_or(""), "");
        let mut output = [0u8; 4];
        self.send_compat_message(&mut msg, Some(&mut output))?;
        let code = u32::from_le_bytes(output);
        Ok(windows::core::HRESULT(code as i32))
    }

    fn build_message(
        kind: DriverComMessageType,
        pid: u32,
        gid: u64,
        path: &str,
        quarantine_path: &str,
    ) -> DriverComMessage {
        DriverComMessage {
            r#type: kind as u32,
            pid,
            gid,
            path: Driver::string_to_commessage_buffer(path),
            quarantine_path: Driver::string_to_commessage_buffer(quarantine_path),
        }
    }

    fn string_to_commessage_buffer(text: &str) -> BufPath {
        let wide = U16CString::from_str(text).unwrap_or_else(|_| U16CString::from_str("").unwrap());
        let mut buf: BufPath = [0; 520];
        for (i, c) in wide.as_slice_with_nul().iter().take(520).enumerate() {
            buf[i] = *c as wchar_t;
        }
        buf[519] = 0;
        buf
    }
}
