//! Low-level communication with the minifilter.
use core::ffi::c_void;
use std::mem;
use std::ptr;

use sysinfo::{get_current_pid, Pid};
use wchar::wchar_t;
use widestring::U16CString;

use windows::core::{Error, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};

use std::os::raw::{c_uchar, c_ulong, c_ulonglong, c_ushort};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use std::os::windows::ffi::OsStringExt;

use crate::shared_def::{
    DriverComMessageType,
    FileId,
    IOMessage,
    RuntimeFeatures,
};

pub type BufPath = [wchar_t; 520];

/// The usermode app (this app) can send several messages types to the driver. See [`DriverComMessageType`]
/// for details.
/// Depending on the message type, the *pid*, *gid* and *path* fields can be optional.
#[derive(Debug)]
#[repr(C)]
struct DriverComMessage {
    /// The type message to send. See [DriverComMessageType].
    r#type: c_ulong,
    /// The pid of the process which triggered an i/o activity;
    pid: c_ulong,
    /// The gid is maintained by the driver
    gid: c_ulonglong,
    path: BufPath,
    /// The path of the file to quarantine
    quarantine_path: BufPath,
}

/// A minifilter is identified by a port (know in advance), like a named pipe used for communication,
/// and a handle, retrieved by [`Self::open_kernel_driver_com`].
#[derive(Debug, Copy, Clone)]
pub struct Driver {
    handle: HANDLE, //Full type name because Intellij raises an error...
}

impl Driver {
    /// Can be used to properly close the communication (and unregister) with the minifilter.
    /// If this fn is not used and the program has stopped, the handle is automatically closed,
    /// seemingly without any side-effects.
    pub fn _close_kernel_communication(&self) -> bool {
        unsafe { CloseHandle(self.handle).as_bool() }
    }

    /// The usermode running app (this one) has to register itself to the driver.
    pub fn driver_set_app_pid(&self) -> Result<(), Error> {
        let buf = Driver::string_to_commessage_buffer(r"\Device\harddiskVolume");

        let mut get_irp_msg: DriverComMessage = DriverComMessage {
            r#type: DriverComMessageType::MessageSetPid as c_ulong,
            pid: usize::from(get_current_pid().unwrap()) as c_ulong,
            gid: 140713315094899,
            path: buf, //wch!("\0"),
            quarantine_path: [0; 520],
        };
        let mut tmp: u32 = 0;
        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(ptr::null_mut()),
                0,
                &mut tmp as *mut u32,
            )
        }
    }

    /// Try to open a com canal with the minifilter before this app is registered. This fn can fail
    /// is the minifilter is unreachable:
    /// * if it is not started (try ```sc start owlyshieldransomfilter``` first
    /// * if a connection is already established: it can accepts only one at a time.
    /// In that case the Error is raised by the OS (`windows::Error`) and is generally readable.
    pub fn open_kernel_driver_com() -> Result<Driver, Error> {
        let com_port_name = U16CString::from_str("\\RWFilter").unwrap().into_raw();
        let handle;
        unsafe {
            handle = FilterConnectCommunicationPort(
                PCWSTR(com_port_name),
                0,
                Some(ptr::null()),
                0,
                Some(ptr::null_mut()),
            )?;
        }
        let res = Driver { handle };
        Ok(res)
    }

    /// Ask the driver for a [`ReplyIrp`], if any. This is a low-level function and the returned object
    /// uses C pointers. Managing C pointers requires a special care, because of the Rust timelines.
    /// [`ReplyIrp`] is optional since the minifilter returns null if there is no new activity.
    pub fn get_irp(&self, vecnew: &mut Vec<u8>) -> Result<Option<ReplyIrp>, Error> {
        let mut get_irp_msg = Driver::build_irp_msg(
            DriverComMessageType::MessageGetOps,
            get_current_pid().unwrap(),
            0,
            "",
        );
        let mut tmp: u32 = 0;
        unsafe {
            let status = FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(get_irp_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(vecnew.as_ptr() as *mut c_void),
                65536,
                ptr::addr_of_mut!(tmp) as *mut u32,
            );
            
            if let Err(e) = status {
                crate::logging::Logging::error(&format!("FilterSendMessage failed: 0x{:X}", e.code().0));
                return Err(e);
            }
        }
        if tmp != 0 {
            let mut reply_irp: ReplyIrp;
            unsafe {
                reply_irp = ptr::read_unaligned(vecnew.as_ptr() as *const ReplyIrp);
                // FIX: The kernel cannot set a valid user-mode pointer for `data`.
                // We must set it ourselves to point to the memory immediately following the struct.
                reply_irp.data = vecnew.as_ptr().add(mem::size_of::<ReplyIrp>()) as *const CDriverMsg;
            }
            return Ok(Some(reply_irp));
        }
        Ok(None)
    }

    /// Ask the minifilter to kill all pids related to the given *gid*. Pids are killed in drivermode
    /// by calls to `NtClose`.
    pub fn try_kill(&self, gid: c_ulonglong) -> Result<windows::core::HRESULT, Error> {
        let (real_gid, real_pid) = if gid & 0x80000000_00000000 != 0 {
            (0, (gid & !0x80000000_00000000) as c_ulong)
        } else {
            (gid, 0)
        };

        let mut killmsg = DriverComMessage {
            r#type: DriverComMessageType::MessageKillGid as c_ulong,
            pid: real_pid,
            gid: real_gid,
            path: [0; 520],
            quarantine_path: [0; 520],
        };
        let mut res: u32 = 0;
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(killmsg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(ptr::addr_of_mut!(res) as *mut c_void),
                4,
                ptr::addr_of_mut!(res_size) as *mut u32,
            )?;
        }
        let hres = windows::core::HRESULT(res as i32);
        Ok(hres)
    }

    pub fn revert_registry_changes(&self, gid: c_ulonglong) -> Result<(), Error> {
        let (real_gid, real_pid) = if gid & 0x80000000_00000000 != 0 {
            (0, (gid & !0x80000000_00000000) as c_ulong)
        } else {
            (gid, 0)
        };

        let mut revert_msg = DriverComMessage {
            r#type: DriverComMessageType::MessageRevertRegistryChanges as c_ulong,
            pid: real_pid,
            gid: real_gid,
            path: [0; 520],
            quarantine_path: [0; 520],
        };
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(revert_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                None,
                0,
                ptr::addr_of_mut!(res_size) as *mut u32,
            )?;
        }
        Ok(())
    }

    pub fn kill_and_quarantine_driver(&self, gid: c_ulonglong, path: &Path) -> Result<windows::core::HRESULT, Error> {
        let (real_gid, real_pid) = if gid & 0x80000000_00000000 != 0 {
            (0, (gid & !0x80000000_00000000) as c_ulong)
        } else {
            (gid, 0)
        };

        let mut kill_quarantine_msg = DriverComMessage {
            r#type: DriverComMessageType::MessageKillAndQuarantineGid as c_ulong,
            pid: real_pid,
            gid: real_gid,
            path: [0; 520],
            quarantine_path: Driver::string_to_commessage_buffer(path.to_str().unwrap_or("")),
        };
        let mut res: u32 = 0;
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(kill_quarantine_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(ptr::addr_of_mut!(res) as *mut c_void),
                4,
                ptr::addr_of_mut!(res_size) as *mut u32,
            )?;
        }
        let hres = windows::core::HRESULT(res as i32);
        Ok(hres)
    }

    pub fn kill_and_remove_driver(&self, gid: c_ulonglong, path: &Path) -> Result<windows::core::HRESULT, Error> {
        let (real_gid, real_pid) = if gid & 0x80000000_00000000 != 0 {
            (0, (gid & !0x80000000_00000000) as c_ulong)
        } else {
            (gid, 0)
        };

        let mut kill_remove_msg = DriverComMessage {
            r#type: DriverComMessageType::MessageKillAndRemoveGid as c_ulong,
            pid: real_pid,
            gid: real_gid,
            path: [0; 520],
            quarantine_path: Driver::string_to_commessage_buffer(path.to_str().unwrap_or("")),
        };
        let mut res: u32 = 0;
        let mut res_size: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.handle,
                ptr::addr_of_mut!(kill_remove_msg) as *mut c_void,
                mem::size_of::<DriverComMessage>() as c_ulong,
                Some(ptr::addr_of_mut!(res) as *mut c_void),
                4,
                ptr::addr_of_mut!(res_size) as *mut u32,
            )?;
        }
        let hres = windows::core::HRESULT(res as i32);
        Ok(hres)
    }

    fn string_to_commessage_buffer(bufstr: &str) -> BufPath {
        let temp = U16CString::from_str(&bufstr).unwrap();
        let mut buf: BufPath = [0; 520];
        for (i, c) in temp.as_slice_with_nul().iter().enumerate() {
            buf[i] = *c as wchar_t;
        }
        buf
    }

    fn build_irp_msg(
        commsgtype: DriverComMessageType,
        pid: Pid,
        gid: u64,
        path: &str,
    ) -> DriverComMessage {
        DriverComMessage {
            r#type: commsgtype as c_ulong, // MessageSetPid
            pid: usize::from(pid) as c_ulong,
            gid,
            path: Driver::string_to_commessage_buffer(path),
            quarantine_path: [0; 520],
        }
    }
}

/// Low-level C-like object to communicate with the minifilter.
/// The minifilter yields `ReplyIrp` objects (retrieved by [`Driver::get_irp`] to manage the fixed size of the *data buffer.
/// In other words, a `ReplyIrp` is a collection of [`CDriverMsg`] with a capped size.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ReplyIrp {
    /// The size od the collection.
    pub data_size: c_ulonglong,
    /// The C pointer to the buffer containinf the [CDriverMsg] events.
    pub data: *const CDriverMsg,
    /// The number of different operations in this collection.
    pub num_ops: u64,
}

/// This class is the straight Rust translation of the Win32 API [`UNICODE_STRING`](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string),
/// returned by the driver.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct UnicodeString {
    pub length: c_ushort,
    pub maximum_length: c_ushort,
    pub buffer: *const wchar_t,
}

/// The C object returned by the minifilter, available through [`ReplyIrp`].
/// It is low level and use C pointers logic which is
/// not always compatible with RUST (in particular the lifetime of *next). That's why we convert
/// it asap to a plain Rust [`IOMessage`] object.
/// ```next``` is null (0x0) when there is no [`IOMessage`] remaining
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct CDriverMsg {
    pub extension: [wchar_t; 12],
    pub file_id: FILE_ID_INFO,
    pub mem_sized_used: c_ulonglong,
    pub entropy: f64,
    pub pid: c_ulong,
    pub irp_op: c_uchar,
    pub is_entropy_calc: u8,
    pub file_change: c_uchar,
    pub file_location_info: c_uchar,
    pub filepath: UnicodeString,
    pub gid: c_ulonglong,
    /// For IRP_PROCESS_TERMINATE_ATTEMPT: PID of attacker process (0 if not applicable)
    pub attacker_pid: c_ulong,
    /// For IRP_PROCESS_TERMINATE_ATTEMPT: GID of attacker process (0 if not tracked)
    pub attacker_gid: c_ulonglong,
    /// null (0x0) when there is no [`IOMessage`] remaining
    pub next: *const CDriverMsg,
}

/// To iterate easily over a collection of [`IOMessage`] received from the minifilter, before they
/// are converted to [`IOMessage`]
pub struct CDriverMsgs<'a> {
    drivermsgs: Vec<&'a CDriverMsg>,
    index: usize,
}

impl UnicodeString {
    pub fn as_string_ext(&self, _extension: [wchar_t; 12]) -> String {
        if self.buffer.is_null() || self.length == 0 {
            return String::new();
        }
        
        // UNICODE_STRING.Length is in bytes. wchar_t is 2 bytes.
        let num_elements = self.length as usize / 2;
        
        // Safety check: ensure the pointer is aligned for wchar_t (2 bytes)
        if (self.buffer as usize) % 2 != 0 {
            return String::new();
        }

        unsafe {
            let str_slice = std::slice::from_raw_parts(self.buffer, num_elements);
            // Find the first null terminator or use the full length
            let effective_len = str_slice.iter().position(|&c| c == 0).unwrap_or(num_elements);
            String::from_utf16_lossy(&str_slice[..effective_len])
        }
    }
}

impl ReplyIrp {
    /// Iterate through ```self.data``` and returns the collection of [`CDriverMsg`]
    fn unpack_drivermsg(&self) -> Vec<&CDriverMsg> {
        let mut res = vec![];
        unsafe {
            let mut current_ptr = self.data as *mut u8;
            let end_ptr = current_ptr.add(self.data_size as usize);
            
            for _ in 0..self.num_ops {
                if current_ptr.is_null() || current_ptr >= end_ptr {
                    break;
                }
                let msg_ptr = current_ptr as *mut CDriverMsg;
                
                // Safety check: ensure CDriverMsg fits
                if current_ptr.add(mem::size_of::<CDriverMsg>()) > end_ptr {
                    break;
                }
                
                let msg = &mut *msg_ptr;

                // Always fixup buffer pointer to point to the appended data
                // The pointer coming from kernel is not valid in user space
                if msg.filepath.length > 0 {
                    let path_ptr = current_ptr.add(mem::size_of::<CDriverMsg>());
                    if path_ptr.add(msg.filepath.length as usize) > end_ptr {
                        msg.filepath.buffer = ptr::null();
                        msg.filepath.length = 0;
                    } else {
                        msg.filepath.buffer = path_ptr as *const wchar_t;
                    }
                } else {
                    msg.filepath.buffer = ptr::null();
                }

                res.push(&*msg_ptr);
                
                let name_buffer_size = msg.filepath.length as usize;
                // Align to 8 bytes to find the next CDriverMsg
                let aligned_name_buffer_size = (name_buffer_size + 7) & !7;
                let total_size = mem::size_of::<CDriverMsg>() + aligned_name_buffer_size;
                
                current_ptr = current_ptr.add(total_size);
            }
        }
        res
    }
}

impl IOMessage {
    pub fn from_driver_msg(c_drivermsg: &CDriverMsg) -> IOMessage {
        IOMessage {
            extension: std::ffi::OsString::from_wide(c_drivermsg.extension.split(|&v| v == 0).next().unwrap()).to_string_lossy().into() ,//String::from_utf16_lossy(&c_drivermsg.extension),
            file_id_id: FileId::from(c_drivermsg.file_id.FileId.Identifier),
            mem_sized_used: c_drivermsg.mem_sized_used,
            entropy: c_drivermsg.entropy,
            pid: c_drivermsg.pid,
            irp_op: c_drivermsg.irp_op,
            is_entropy_calc: c_drivermsg.is_entropy_calc,
            file_change: c_drivermsg.file_change,
            file_location_info: c_drivermsg.file_location_info,
            filepathstr: c_drivermsg.filepath.as_string_ext(c_drivermsg.extension),
            gid: c_drivermsg.gid,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            attacker_pid: c_drivermsg.attacker_pid,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            attacker_gid: c_drivermsg.attacker_gid,
            runtime_features: RuntimeFeatures::new(),
            file_size: match PathBuf::from(
                &c_drivermsg.filepath.as_string_ext(c_drivermsg.extension),
            )
                .metadata()
            {
                Ok(f) => f.len() as i64,
                Err(_) => -1,
            },
            time: SystemTime::now(),
        }
    }
}

impl CDriverMsgs<'_> {
    pub fn new(irp: &ReplyIrp) -> CDriverMsgs<'_> {
        CDriverMsgs {
            drivermsgs: irp.unpack_drivermsg(),
            index: 0,
        }
    }
}

impl Iterator for CDriverMsgs<'_> {
    type Item = CDriverMsg;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.drivermsgs.len() {
            None
        } else {
            let res = *self.drivermsgs[self.index];
            self.index += 1;
            Some(res)
        }
    }
}
