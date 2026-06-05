//! OpenEDR/edrdrv fltport transport and native LBVS event parser.
//!
//! Receives events directly from the OpenEDR edrdrv minifilter via FilterGetMessage.
//! Parses the native LBVS (Length-Based Value Serialization) payload produced by
//! `variant::BasicLbvsSerializer<edrdrv::EventField>` and maps it into the
//! Owlyshield `IOMessage` model using only the standard OpenEDR EventField IDs.
//!
//! No owly_schema JSON blob. No OwlyOpenEdrBridge. Events are interpreted
//! purely from the SysmonEvent raw_event_id and the native LBVS fields.
//!
//! Native fields per event type (from filemon/procmon/regmon/objmon):
//!   ProcessCreate (0x0000): RawEventId, TickTime, ProcessPid, ProcessParentPid,
//!     ProcessCreatorPid, ProcessCmdLine, ProcessImageFile, ProcessCreationTime,
//!     ProcessUserSid, ProcessIsElevated, ProcessElevationType
//!   ProcessDelete (0x0001): RawEventId, TickTime, ProcessPid, ProcessDeletionTime,
//!     ProcessExitCode
//!   Registry    (0x0002-0x0006): RawEventId, RegistryPath, TickTime, ProcessPid,
//!     RegistryName, RegistryRawData (actual value binary data), RegistryDataType,
//!     RegistryKeyNewName
//!   FileCreate  (0x0007): RawEventId, TickTime, ProcessPid, FilePath, AccessMask,
//!     FileVolumeGuid, FileVolumeType, FileVolumeDevice
//!   FileDelete  (0x0008): same as FileCreate
//!   FileClose   (0x0009): same as FileCreate
//!   FileData*   (0x000A-0x000C): same as FileCreate
//!   ProcessOpen (0x000D): RawEventId, TickTime, ProcessPid, FilePath, AccessMask
//!   NamedPipe   (0x000F): RawEventId, TickTime, ProcessPid, FilePath
//!
//! gid and attacker_pid are always 0 (OpenEDR has no equivalent concept).
//! file_change is derived from the SysmonEvent ID via sysmonevent_to_file_change.
//! irp_op stores the raw SysmonEvent ID (u32) directly. Consumers call
//! IrpMajorOp::from_sysmonevent(iomsg.irp_op) for semantic classification.
//! KernelEventInfo fields not present in native OpenEDR events are left at their
//! zero-value defaults.

use core::ffi::c_void;
use std::collections::HashMap;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

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

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::shared_def::KernelEventInfo;
use crate::shared_def::{
    DriverComMessageType, FileChangeInfo, FileId, IOMessage, RuntimeFeatures, SysmonEvent,
};

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

            match lbvs_to_iomessage_inner(payload) {
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

// ============================================================================
// LBVS parser and IOMessage mapper (previously openedr_lbvs.rs)
// ============================================================================

// LBVS magic: 'LBVS' in little-endian as written by the C++ serializer.
const LBVS_MAGIC: u32 = 0x5356_424c;

#[derive(Debug, Clone)]
enum LbvsValue {
    Null,
    String(String),
    WString(String),
    Stream(Vec<u8>),
    Bool(bool),
    Uint32(u32),
    Uint64(u64),
    SeqDict,
    SeqSeq,
}

// OpenEDR EventField IDs (edrdrv/src/EventSink.h / edrdrvapi.hpp)
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
enum EventField {
    RawEventId = 0,
    TickTime = 1,
    ProcessPid = 2,
    ProcessParentPid = 3,
    ProcessCmdLine = 4,
    ProcessImageFile = 7,
    RegistryPath = 11,
    RegistryKeyNewName = 12,
    RegistryName = 13,
    RegistryRawData = 14,
    RegistryDataType = 15,
    FilePath = 16,
    FileRawHash = 20,
    TargetProcessPid = 24,
    AccessMask = 25,
    // Owlyshield kernel API hook event fields (ProcessProtection.cpp → LBVS)
    OwlyHookEventType = 102,
    OwlyHookFunctionName = 103,
    OwlyHookArg1 = 104,
    OwlyHookArg2 = 105,
    OwlyHookArg3 = 106,
    OwlyHookArg4 = 107,
    OwlyHookSourcePid = 108,
}

fn read_u16_le(buf: &[u8], off: &mut usize) -> Option<u16> {
    let end = *off + 2;
    let bytes = buf.get(*off..end)?;
    *off = end;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], off: &mut usize) -> Option<u32> {
    let end = *off + 4;
    let bytes = buf.get(*off..end)?;
    *off = end;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(buf: &[u8], off: &mut usize) -> Option<u64> {
    let end = *off + 8;
    let bytes = buf.get(*off..end)?;
    *off = end;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_c_string(buf: &[u8], off: &mut usize) -> Option<String> {
    let start = *off;
    let rel_end = buf.get(start..)?.iter().position(|&b| b == 0)?;
    *off = start + rel_end + 1;
    Some(String::from_utf8_lossy(&buf[start..start + rel_end]).into_owned())
}

fn read_w_string(buf: &[u8], off: &mut usize) -> Option<String> {
    let start = *off;
    let mut cur = start;
    let mut words = Vec::new();
    loop {
        let lo = *buf.get(cur)?;
        let hi = *buf.get(cur + 1)?;
        cur += 2;
        let ch = u16::from_le_bytes([lo, hi]);
        if ch == 0 {
            break;
        }
        words.push(ch);
    }
    *off = cur;
    Some(String::from_utf16_lossy(&words))
}

fn parse_lbvs(buf: &[u8]) -> Result<HashMap<u16, LbvsValue>, String> {
    if buf.len() < 10 {
        return Err("LBVS buffer is too small".to_string());
    }

    let mut off = 0usize;
    let magic = read_u32_le(buf, &mut off).ok_or("missing LBVS magic")?;
    if magic != LBVS_MAGIC {
        return Err(format!("invalid LBVS magic 0x{magic:08X}"));
    }

    let version = *buf.get(off).ok_or("missing LBVS version")?;
    off += 1;
    if version != 1 {
        return Err(format!("unsupported LBVS version {version}"));
    }

    let declared_size = read_u32_le(buf, &mut off).ok_or("missing LBVS size")? as usize;
    let count = *buf.get(off).ok_or("missing LBVS count")? as usize;
    off += 1;

    if declared_size > buf.len() || declared_size < off {
        return Err(format!(
            "invalid LBVS declared size {declared_size}, buffer size {}",
            buf.len()
        ));
    }

    let payload = &buf[..declared_size];
    let mut fields = HashMap::new();

    for _ in 0..count {
        let field_id = read_u16_le(payload, &mut off).ok_or("truncated field id")?;
        let field_type = *payload.get(off).ok_or("truncated field type")?;
        off += 1;

        let value = match field_type {
            0 => LbvsValue::Null,
            1 => LbvsValue::String(read_c_string(payload, &mut off).ok_or("bad string")?),
            2 => LbvsValue::WString(read_w_string(payload, &mut off).ok_or("bad wstring")?),
            3 => {
                let len = read_u16_le(payload, &mut off).ok_or("bad stream length")? as usize;
                let end = off + len;
                let data = payload.get(off..end).ok_or("truncated stream")?.to_vec();
                off = end;
                LbvsValue::Stream(data)
            }
            4 => {
                let v = *payload.get(off).ok_or("bad bool")? != 0;
                off += 1;
                LbvsValue::Bool(v)
            }
            5 => LbvsValue::Uint32(read_u32_le(payload, &mut off).ok_or("bad uint32")?),
            6 => LbvsValue::Uint64(read_u64_le(payload, &mut off).ok_or("bad uint64")?),
            7 => LbvsValue::SeqDict,
            8 => LbvsValue::SeqSeq,
            other => return Err(format!("unsupported LBVS field type {other}")),
        };

        fields.insert(field_id, value);
    }

    Ok(fields)
}

fn lbvs_field_u32(fields: &HashMap<u16, LbvsValue>, id: EventField) -> u32 {
    match fields.get(&(id as u16)) {
        Some(LbvsValue::Uint32(v)) => *v,
        Some(LbvsValue::Uint64(v)) => *v as u32,
        _ => 0,
    }
}

fn lbvs_field_u64(fields: &HashMap<u16, LbvsValue>, id: EventField) -> u64 {
    match fields.get(&(id as u16)) {
        Some(LbvsValue::Uint64(v)) => *v,
        Some(LbvsValue::Uint32(v)) => *v as u64,
        _ => 0,
    }
}

fn lbvs_field_string(fields: &HashMap<u16, LbvsValue>, id: EventField) -> String {
    match fields.get(&(id as u16)) {
        Some(LbvsValue::String(v)) | Some(LbvsValue::WString(v)) => v.clone(),
        Some(LbvsValue::Stream(v)) => String::from_utf8_lossy(v).into_owned(),
        _ => String::new(),
    }
}

// Maps an OpenEDR SysmonEvent raw_event_id to the Owlyshield FileChangeInfo byte.
// Derived purely from the SysmonEvent ID — no JSON blob involved.
fn sysmonevent_to_file_change(raw_event_id: u32) -> u8 {
    match raw_event_id {
        0x0002 => FileChangeInfo::RegRenameKey as u8,
        0x0003 => FileChangeInfo::RegCreateKey as u8,
        0x0004 => FileChangeInfo::RegDeleteKey as u8,
        0x0005 => FileChangeInfo::RegSetValue as u8,
        0x0006 => FileChangeInfo::RegDeleteValue as u8,
        0x0007 => FileChangeInfo::ChangeNewFile as u8,
        0x0008 => FileChangeInfo::ChangeDeleteFile as u8,
        0x000A | 0x000C => FileChangeInfo::ChangeWrite as u8,
        _ => FileChangeInfo::ChangeNotSet as u8,
    }
}

fn registry_display_path(registry_path: String, registry_name: String) -> String {
    let path = registry_path.trim();
    let name = registry_name.trim();
    if path.is_empty() {
        return name.to_string();
    }
    if name.is_empty() {
        return path.to_string();
    }
    if path.ends_with('\\') {
        format!("{path}{name}")
    } else {
        format!("{path}\\{name}")
    }
}

fn lbvs_to_iomessage_inner(buf: &[u8]) -> Result<IOMessage, String> {
    let fields = parse_lbvs(buf)?;

    let raw_event_id = lbvs_field_u32(&fields, EventField::RawEventId);
    // irp_op now stores the raw SysmonEvent ID directly (u32).
    // IrpMajorOp::from_sysmonevent() is used by consumers when semantic
    // classification is needed; no translation happens at the parse layer.
    let irp_op: u32 = raw_event_id;

    let pid = lbvs_field_u32(&fields, EventField::ProcessPid);
    let is_registry_event = SysmonEvent::is_registry_event(raw_event_id);
    let is_kernel_hook_event = (raw_event_id == 0x000E); // SysmonEvent::DeviceIoControl

    // Native OpenEDR field reads — no JSON blob involved.
    // ProcessCreate populates ProcessImageFile and ProcessCmdLine natively.
    // File/pipe events populate FilePath.
    // Registry events populate RegistryPath + RegistryName (RegistryRawData is actual binary data).
    // ProcessOpen populates FilePath + TargetProcessPid + AccessMask.
    // DeviceIoControl (0x000E) carries kernel API hook events with OwlyHookEvent* fields.
    let file_path = lbvs_field_string(&fields, EventField::FilePath);
    let process_image_file = {
        let pif = lbvs_field_string(&fields, EventField::ProcessImageFile);
        if pif.trim().is_empty() {
            file_path.clone()
        } else {
            pif
        }
    };
    let registry_path = registry_display_path(
        lbvs_field_string(&fields, EventField::RegistryPath),
        lbvs_field_string(&fields, EventField::RegistryName),
    );
    let filepath = if is_registry_event {
        registry_path.clone()
    } else if !file_path.trim().is_empty() {
        file_path.clone()
    } else if !process_image_file.trim().is_empty() {
        process_image_file.clone()
    } else {
        registry_path.clone()
    };
    let runtime_exepath = if !process_image_file.trim().is_empty() {
        process_image_file.clone()
    } else {
        filepath.clone()
    };

    let command_line = lbvs_field_string(&fields, EventField::ProcessCmdLine);

    // KernelEventInfo: for DeviceIoControl (0x000E), populate from OwlyHookEvent* fields.
    // ProcessProtection.cpp OnKernelApiEvent now serializes kernel API hook events via LBVS fltport.
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    let kernel_event_info = if is_kernel_hook_event {
        KernelEventInfo {
            event_type: lbvs_field_u32(&fields, EventField::OwlyHookEventType),
            timestamp: lbvs_field_u32(&fields, EventField::TickTime) as u64,
            source_process_id: lbvs_field_u32(&fields, EventField::OwlyHookSourcePid),
            target_process_id: pid, // ProcessPid is the target
            raw_argument1: lbvs_field_u64(&fields, EventField::OwlyHookArg1),
            raw_argument2: lbvs_field_u64(&fields, EventField::OwlyHookArg2),
            raw_argument3: lbvs_field_u64(&fields, EventField::OwlyHookArg3),
            raw_argument4: lbvs_field_u64(&fields, EventField::OwlyHookArg4),
            object_name: lbvs_field_string(&fields, EventField::OwlyHookFunctionName),
            ..KernelEventInfo::default()
        }
    } else {
        KernelEventInfo {
            event_type: irp_op,
            timestamp: lbvs_field_u32(&fields, EventField::TickTime) as u64,
            source_process_id: pid,
            target_process_id: lbvs_field_u32(&fields, EventField::TargetProcessPid),
            access_mask: lbvs_field_u32(&fields, EventField::AccessMask),
            object_name: String::new(),
            loaded_dll_path: registry_path.clone(),
            ..KernelEventInfo::default()
        }
    };

    Ok(IOMessage {
        extension: if is_registry_event {
            String::new()
        } else {
            PathBuf::from(&filepath)
                .extension()
                .and_then(|v| v.to_str())
                .unwrap_or_default()
                .to_string()
        },
        file_id_id: FileId::from([0u8; crate::shared_def::FILE_ID_LEN]),
        mem_sized_used: 0,
        entropy: 0.0,
        pid,
        irp_op,
        is_entropy_calc: 0,
        file_change: sysmonevent_to_file_change(raw_event_id),
        file_location_info: 0,
        filepathstr: filepath.clone(),
        gid: 0,
        parent_pid: lbvs_field_u32(&fields, EventField::ProcessParentPid),
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        attacker_pid: 0,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        attacker_gid: 0,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        kernel_event_info,
        runtime_features: RuntimeFeatures {
            exepath: PathBuf::from(&runtime_exepath),
            exe_still_exists: true,
            command_line,
        },
        file_size: if is_registry_event {
            -1
        } else {
            PathBuf::from(&filepath)
                .metadata()
                .map(|m| m.len() as i64)
                .unwrap_or(-1)
        },
        time: SystemTime::now(),
    })
}
