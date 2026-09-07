use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::SystemTime;

pub const FILE_ID_LEN: usize = 16;
#[cfg(target_os = "linux")]
pub const FILE_ID_LEN: usize = 32;

/// Quarantine directory path (shared across all Rust components)
pub const QUARANTINE_PATH: &str = r"C:\ProgramData\HydraDragonQuarantine";

/// See [`IOMessage`] struct. Used with [`crate::shared_def::IrpMajorOp::IrpSetInfo`]
#[allow(non_local_definitions)]
#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChangeInfo {
    ChangeNotSet = 0,
    OpenDirectory = 1,
    ChangeWrite = 2,
    ChangeNewFile = 3,
    ChangeRenameFile = 4,
    ChangeExtensionChanged = 5,
    ChangeDeleteFile = 6,
    /// Temp file: created and deleted on close
    ChangeDeleteNewFile = 7,
    ChangeOverwriteFile = 8,
    RegCreateKey = 9,
    RegSetValue = 10,
    RegDeleteValue = 11,
    RegRenameKey = 12,
    RegQueryValue = 13,
    // FIX (Bug #2): Added to match the newly corrected SharedDefs.h FILE_CHANGE_INFO enum.
    // Without these, any event arriving with code 14-18 would be silently
    // mishandled as an unknown variant by FromPrimitive consumers.
    RegDeleteKey = 14,
    RegOpenKey = 15,
    RegQueryKey = 16,
    RegEnumKey = 17,
    RegEnumValue = 18,
}

/// See [`IOMessage`] struct.
#[allow(non_local_definitions)]
#[derive(FromPrimitive, Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum FileLocationInfo {
    NotProtected = 0,
    Protected = 1,
    MovedIn = 2,
    MovedOut = 3,
}

/// Messages types to send directives to the minifilter, by using te [`DriverComMessage`] struct.
#[allow(dead_code)]
#[repr(u32)]
pub enum DriverComMessageType {
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    _MessageAddScanDirectory = 0,
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    _MessageRemScanDirectory = 1,
    /// Ask for a [ReplyIrp], if any available.
    MessageGetOps = 2,
    /// Set this app pid to the minifilter (related IRPs will be ignored);
    MessageSetPid = 3,
    MessageKillGid = 4,
    MessageKillAndQuarantineGid = 5,
    MessageKillOnlyGid = 6,
    MessageKillAndRemoveGid = 7, // NEW: Kill process and delete file
    MessageRevertRegistryChanges = 8,
    MessageAddHook = 9,
    MessageHookProcess = 10,
    MessageAddBlockPath = 11,
}

/// OpenEDR SysmonEvent IDs as emitted by edrdrv (edrdrvapi.hpp SysmonEvent enum).
/// These are the raw values stored in `IOMessage.irp_op` on Windows.
/// On Linux, the eBPF monitor uses small integer legacy values (1=read, 2=write, etc).
#[repr(u32)]
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum SysmonEvent {
    ProcessCreate = 0x0000,
    ProcessDelete = 0x0001,
    RegistryKeyNameChange = 0x0002,
    RegistryKeyCreate = 0x0003,
    RegistryKeyDelete = 0x0004,
    RegistryValueSet = 0x0005,
    RegistryValueDelete = 0x0006,
    FileCreate = 0x0007,
    FileDelete = 0x0008,
    FileClose = 0x0009,
    FileDataChange = 0x000A,
    FileDataReadFull = 0x000B,
    FileDataWriteFull = 0x000C,
    ProcessOpen = 0x000D,
    DeviceIoControl = 0x000E,
    NamedPipeCreate = 0x000F,
    SelfDefense = 0x0010,
    FileMapRead = 0x0011,
    FileMapWrite = 0x0012,
    FileRename = 0x0014,
    ThreadOpen = 0x0015,
    DesktopOpen = 0x0016,
    Unknown = 0xFFFF_FFFF,
}

impl SysmonEvent {
    pub fn from_u32(v: u32) -> SysmonEvent {
        match v {
            0x0000 => SysmonEvent::ProcessCreate,
            0x0001 => SysmonEvent::ProcessDelete,
            0x0002 => SysmonEvent::RegistryKeyNameChange,
            0x0003 => SysmonEvent::RegistryKeyCreate,
            0x0004 => SysmonEvent::RegistryKeyDelete,
            0x0005 => SysmonEvent::RegistryValueSet,
            0x0006 => SysmonEvent::RegistryValueDelete,
            0x0007 => SysmonEvent::FileCreate,
            0x0008 => SysmonEvent::FileDelete,
            0x0009 => SysmonEvent::FileClose,
            0x000A => SysmonEvent::FileDataChange,
            0x000B => SysmonEvent::FileDataReadFull,
            0x000C => SysmonEvent::FileDataWriteFull,
            0x000D => SysmonEvent::ProcessOpen,
            0x000E => SysmonEvent::DeviceIoControl,
            0x000F => SysmonEvent::NamedPipeCreate,
            0x0010 => SysmonEvent::SelfDefense,
            0x0011 => SysmonEvent::FileMapRead,
            0x0012 => SysmonEvent::FileMapWrite,
            0x0014 => SysmonEvent::FileRename,
            0x0015 => SysmonEvent::ThreadOpen,
            0x0016 => SysmonEvent::DesktopOpen,
            _ => SysmonEvent::Unknown,
        }
    }

    pub fn label(v: u32) -> &'static str {
        match v {
            0x0000 => "ProcessCreate",
            0x0001 => "ProcessDelete",
            0x0002 => "RegistryKeyNameChange",
            0x0003 => "RegistryKeyCreate",
            0x0004 => "RegistryKeyDelete",
            0x0005 => "RegistryValueSet",
            0x0006 => "RegistryValueDelete",
            0x0007 => "FileCreate",
            0x0008 => "FileDelete",
            0x0009 => "FileClose",
            0x000A => "FileDataChange",
            0x000B => "FileDataReadFull",
            0x000C => "FileDataWriteFull",
            0x000D => "ProcessOpen",
            0x000E => "DeviceIoControl",
            0x000F => "NamedPipeCreate",
            0x0010 => "SelfDefense",
            0x0011 => "FileMapRead",
            0x0012 => "FileMapWrite",
            0x0014 => "FileRename",
            0x0015 => "ThreadOpen",
            0x0016 => "DesktopOpen",
            _ => "Unknown",
        }
    }

    pub fn is_file_event(v: u32) -> bool {
        matches!(v, 0x0007..=0x0014)
    }

    pub fn is_registry_event(v: u32) -> bool {
        matches!(v, 0x0002..=0x0006)
    }

    pub fn is_process_event(v: u32) -> bool {
        matches!(v, 0x0000 | 0x0001 | 0x000D | 0x0015)
    }

    pub fn is_pipe_event(v: u32) -> bool {
        v == 0x000F
    }
}

/// Semantic classification of events for the behavior engine.
/// Maps OpenEDR SysmonEvent IDs to coarse operation categories.
/// Use `IrpMajorOp::from_sysmonevent(iomsg.irp_op)` to classify an event.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum IrpMajorOp {
    IrpNone,
    IrpRead,
    IrpWrite,
    IrpSetInfo,
    IrpCreate,
    _IrpCleanUp,
    IrpRegistry,
    IrpProcessCreate,
    IrpProcessTerminate,
    IrpProcessTerminateAttempt,
    IrpProcessExit,
    IrpProcessHandleOpen,
    IrpKernelRemoteThread,
    IrpKernelWriteMemory,
    IrpKernelProtectMemory,
    IrpKernelCreateThread,
    IrpKernelQueueApc,
    IrpKernelCreateSection,
    IrpKernelMapSection,
    IrpUserModeHookEvent,
    IrpRootkitSsdtHook,
    IrpRootkitHiddenProcess,
    IrpRootkitHiddenDriver,
    IrpRootkitKernelHook,
    IrpRootkitTerminateProcess,
    IrpRootkitFileMove,
    IrpRootkitGeneric,
    IrpNamedPipeCreate,
    IrpNamedPipeWrite,
}

impl IrpMajorOp {
    /// Map a raw SysmonEvent u32 (`IOMessage.irp_op`) to a semantic classification bucket.
    /// OpenEDR LBVS wire uses 0x0000–0x0010. Kernel sub-event types that are identified
    /// by unique sub-IDs in the 0x1000+ range round-trip correctly through to_sysmonevent_u32.
    pub fn from_sysmonevent(v: u32) -> IrpMajorOp {
        match v {
            0x0000 => IrpMajorOp::IrpProcessCreate,
            0x0001 => IrpMajorOp::IrpProcessTerminate,
            0x0002..=0x0006 => IrpMajorOp::IrpRegistry,
            0x0007 => IrpMajorOp::IrpCreate,
            0x0008 => IrpMajorOp::IrpSetInfo,
            0x0009 => IrpMajorOp::_IrpCleanUp,
            0x000A | 0x000C => IrpMajorOp::IrpWrite,
            0x000B => IrpMajorOp::IrpRead,
            0x000D => IrpMajorOp::IrpProcessHandleOpen,
            0x000F => IrpMajorOp::IrpNamedPipeCreate,
            0x0010 => IrpMajorOp::IrpUserModeHookEvent,
            // Owlyshield extension events: collapse to coarse file ops so the
            // aggregate counters work; the fine-grained mmap / handle-open
            // distinction is surfaced at rule-token level (current_file_op).
            0x0011 => IrpMajorOp::IrpRead,
            0x0012 => IrpMajorOp::IrpWrite,
            0x0013 => IrpMajorOp::IrpSetInfo,
            0x0014 => IrpMajorOp::IrpSetInfo,
            0x0015 => IrpMajorOp::IrpProcessHandleOpen,
            // Sub-event type IDs used by to_sysmonevent_u32 for round-trip (not on LBVS wire)
            0x1009 => IrpMajorOp::IrpProcessTerminateAttempt,
            0x100A => IrpMajorOp::IrpProcessExit,
            0x100D => IrpMajorOp::IrpKernelRemoteThread,
            0x100E => IrpMajorOp::IrpKernelWriteMemory,
            0x100F => IrpMajorOp::IrpKernelProtectMemory,
            0x1010 => IrpMajorOp::IrpKernelCreateThread,
            0x1011 => IrpMajorOp::IrpKernelQueueApc,
            0x1012 => IrpMajorOp::IrpKernelCreateSection,
            0x1013 => IrpMajorOp::IrpKernelMapSection,
            0x1015 => IrpMajorOp::IrpRootkitSsdtHook,
            0x1016 => IrpMajorOp::IrpRootkitHiddenProcess,
            0x1017 => IrpMajorOp::IrpRootkitHiddenDriver,
            0x1018 => IrpMajorOp::IrpRootkitKernelHook,
            0x1019 => IrpMajorOp::IrpRootkitTerminateProcess,
            0x101A => IrpMajorOp::IrpRootkitFileMove,
            0x101B => IrpMajorOp::IrpRootkitGeneric,
            0x101D => IrpMajorOp::IrpNamedPipeWrite,
            _ => IrpMajorOp::IrpNone,
        }
    }

    /// Returns a stable u32 identifier for this op suitable for test fixtures and
    /// local dispatch. Wire events from LBVS use 0x0000–0x0010; kernel sub-types
    /// use 0x1000+ range to avoid collisions and round-trip correctly.
    pub fn to_sysmonevent_u32(&self) -> u32 {
        match self {
            IrpMajorOp::IrpNone => 0xFFFF_FFFF,
            IrpMajorOp::IrpRead => 0x000B,
            IrpMajorOp::IrpWrite => 0x000A,
            IrpMajorOp::IrpSetInfo => 0x0008,
            IrpMajorOp::IrpCreate => 0x0007,
            IrpMajorOp::_IrpCleanUp => 0x0009,
            IrpMajorOp::IrpRegistry => 0x0005,
            IrpMajorOp::IrpProcessCreate => 0x0000,
            IrpMajorOp::IrpProcessTerminate => 0x0001,
            IrpMajorOp::IrpProcessHandleOpen => 0x000D,
            IrpMajorOp::IrpUserModeHookEvent => 0x0010,
            IrpMajorOp::IrpNamedPipeCreate => 0x000F,
            // 0x1000+ range: unique sub-type IDs for round-trip, not LBVS wire values
            IrpMajorOp::IrpProcessTerminateAttempt => 0x1009,
            IrpMajorOp::IrpProcessExit => 0x100A,
            IrpMajorOp::IrpKernelRemoteThread => 0x100D,
            IrpMajorOp::IrpKernelWriteMemory => 0x100E,
            IrpMajorOp::IrpKernelProtectMemory => 0x100F,
            IrpMajorOp::IrpKernelCreateThread => 0x1010,
            IrpMajorOp::IrpKernelQueueApc => 0x1011,
            IrpMajorOp::IrpKernelCreateSection => 0x1012,
            IrpMajorOp::IrpKernelMapSection => 0x1013,
            IrpMajorOp::IrpRootkitSsdtHook => 0x1015,
            IrpMajorOp::IrpRootkitHiddenProcess => 0x1016,
            IrpMajorOp::IrpRootkitHiddenDriver => 0x1017,
            IrpMajorOp::IrpRootkitKernelHook => 0x1018,
            IrpMajorOp::IrpRootkitTerminateProcess => 0x1019,
            IrpMajorOp::IrpRootkitFileMove => 0x101A,
            IrpMajorOp::IrpRootkitGeneric => 0x101B,
            IrpMajorOp::IrpNamedPipeWrite => 0x101D,
        }
    }

    pub fn from_byte(b: u32) -> IrpMajorOp {
        match b {
            1 => IrpMajorOp::IrpRead,
            2 => IrpMajorOp::IrpWrite,
            3 => IrpMajorOp::IrpSetInfo,
            4 => IrpMajorOp::IrpCreate,
            5 => IrpMajorOp::_IrpCleanUp,
            6 => IrpMajorOp::IrpRegistry,
            _ => IrpMajorOp::from_sysmonevent(b),
        }
    }
}

/// Human-readable label for a raw SysmonEvent u32 (`IOMessage.irp_op`).
pub fn irp_major_op_label(opcode: u32) -> &'static str {
    SysmonEvent::label(opcode)
}

#[cfg(test)]
mod tests {
    use super::{IrpMajorOp, SysmonEvent};

    #[test]
    fn sysmonevent_roundtrip() {
        let cases = [
            (0x0000u32, SysmonEvent::ProcessCreate),
            (0x0001, SysmonEvent::ProcessDelete),
            (0x0007, SysmonEvent::FileCreate),
            (0x000F, SysmonEvent::NamedPipeCreate),
            (0x0010, SysmonEvent::SelfDefense),
        ];
        for (id, expected) in cases {
            assert_eq!(SysmonEvent::from_u32(id), expected);
        }
    }

    #[test]
    fn from_sysmonevent_maps_correctly() {
        assert_eq!(
            IrpMajorOp::from_sysmonevent(0x0000),
            IrpMajorOp::IrpProcessCreate
        );
        assert_eq!(IrpMajorOp::from_sysmonevent(0x0007), IrpMajorOp::IrpCreate);
        assert_eq!(IrpMajorOp::from_sysmonevent(0x000B), IrpMajorOp::IrpRead);
        assert_eq!(
            IrpMajorOp::from_sysmonevent(0x000F),
            IrpMajorOp::IrpNamedPipeCreate
        );
        // Registry range: multiple wire IDs collapse to one variant
        assert_eq!(
            IrpMajorOp::from_sysmonevent(0x0002),
            IrpMajorOp::IrpRegistry
        );
        assert_eq!(
            IrpMajorOp::from_sysmonevent(0x0005),
            IrpMajorOp::IrpRegistry
        );
        // IrpWrite alias: 0x000C also maps to IrpWrite
        assert_eq!(IrpMajorOp::from_sysmonevent(0x000A), IrpMajorOp::IrpWrite);
        assert_eq!(IrpMajorOp::from_sysmonevent(0x000C), IrpMajorOp::IrpWrite);
        // Unknown → IrpNone
        assert_eq!(IrpMajorOp::from_sysmonevent(0xDEAD), IrpMajorOp::IrpNone);
    }

    #[test]
    fn to_sysmonevent_roundtrip() {
        // Every variant must round-trip: from_sysmonevent(v.to_sysmonevent_u32()) == v
        // (except IrpNone which maps to 0xFFFF_FFFF sentinel)
        let variants = [
            IrpMajorOp::IrpRead,
            IrpMajorOp::IrpWrite,
            IrpMajorOp::IrpSetInfo,
            IrpMajorOp::IrpCreate,
            IrpMajorOp::_IrpCleanUp,
            IrpMajorOp::IrpRegistry,
            IrpMajorOp::IrpProcessCreate,
            IrpMajorOp::IrpProcessTerminate,
            IrpMajorOp::IrpProcessHandleOpen,
            IrpMajorOp::IrpUserModeHookEvent,
            IrpMajorOp::IrpNamedPipeCreate,
            IrpMajorOp::IrpProcessTerminateAttempt,
            IrpMajorOp::IrpProcessExit,
            IrpMajorOp::IrpKernelRemoteThread,
            IrpMajorOp::IrpKernelWriteMemory,
            IrpMajorOp::IrpKernelProtectMemory,
            IrpMajorOp::IrpKernelCreateThread,
            IrpMajorOp::IrpKernelQueueApc,
            IrpMajorOp::IrpKernelCreateSection,
            IrpMajorOp::IrpKernelMapSection,
            IrpMajorOp::IrpRootkitSsdtHook,
            IrpMajorOp::IrpRootkitHiddenProcess,
            IrpMajorOp::IrpRootkitHiddenDriver,
            IrpMajorOp::IrpRootkitKernelHook,
            IrpMajorOp::IrpRootkitTerminateProcess,
            IrpMajorOp::IrpRootkitFileMove,
            IrpMajorOp::IrpRootkitGeneric,
            IrpMajorOp::IrpNamedPipeWrite,
        ];
        for variant in &variants {
            let encoded = variant.to_sysmonevent_u32();
            let decoded = IrpMajorOp::from_sysmonevent(encoded);
            assert_eq!(
                &decoded, variant,
                "round-trip failed for {variant:?}: encoded={encoded:#06X}, decoded={decoded:?}"
            );
        }
        // IrpNone sentinel must not accidentally map to a real variant
        assert_eq!(
            IrpMajorOp::from_sysmonevent(0xFFFF_FFFF),
            IrpMajorOp::IrpNone
        );
    }
}

pub fn kernel_raw_event_name(raw_event_type: u32) -> Option<&'static str> {
    match raw_event_type {
        12 => Some("IRP_HYPERVISOR_EVENT"),
        13 => Some("IRP_KERNEL_REMOTE_THREAD"),
        14 => Some("IRP_KERNEL_WRITE_MEMORY"),
        15 => Some("IRP_KERNEL_PROTECT_MEMORY"),
        16 => Some("IRP_KERNEL_CREATE_THREAD"),
        17 => Some("IRP_KERNEL_QUEUE_APC"),
        18 => Some("IRP_KERNEL_CREATE_SECTION"),
        19 => Some("IRP_KERNEL_MAP_SECTION"),
        20 => Some("IRP_USER_MODE_HOOK_EVENT"),
        21 => Some("IRP_ROOTKIT_SSDT_HOOK"),
        22 => Some("IRP_ROOTKIT_HIDDEN_PROCESS"),
        23 => Some("IRP_ROOTKIT_HIDDEN_DRIVER"),
        24 => Some("IRP_ROOTKIT_KERNEL_HOOK"),
        25 => Some("IRP_ROOTKIT_TERMINATE_PROCESS"),
        26 => Some("IRP_ROOTKIT_FILE_MOVE"),
        27 => Some("IRP_ROOTKIT_GENERIC"),
        28 => Some("IRP_NAMED_PIPE_CREATE"),
        29 => Some("IRP_NAMED_PIPE_WRITE"),
        _ => None,
    }
}

pub fn known_raw_event_name(raw_event_type: u32) -> Option<&'static str> {
    kernel_raw_event_name(raw_event_type)
}

/// See [`shared_def::IOMessage`] struct and [this doc](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea).
#[derive(Debug)]
#[allow(dead_code)]
pub enum DriveType {
    /// The drive type cannot be determined.
    Unknown,
    /// The root path is invalid; for example, there is no volume mounted at the specified path.
    NoRootDir,
    /// The drive has removable media; for example, a floppy drive, thumb drive, or flash card reader.
    Removable,
    /// The drive has fixed media; for example, a hard disk drive or flash drive.
    Fixed,
    /// The drive is a remote (network) drive.
    Remote,
    /// The drive is a CD-ROM drive.
    CDRom,
    /// The drive is a RAM disk.
    RamDisk,
}

impl DriveType {
    /// Best-effort drive classification based on a file path. This mirrors the
    /// simple helpers used by the platform-specific driver modules and keeps
    /// the library build self contained for SDK consumers and examples.
    pub fn from_filepath(filepath: impl AsRef<str>) -> DriveType {
        let filepath = filepath.as_ref();
        if filepath.starts_with("\\\\") {
            return DriveType::Remote;
        }

        if filepath.starts_with('/') {
            // Linux-style paths default to fixed/local media
            return DriveType::Fixed;
        }

        // Windows-style "X:\" drive letter prefixes
        if filepath.chars().nth(1) == Some(':') {
            // Treat removable drive letters explicitly
            let drive_letter = filepath
                .chars()
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if matches!(drive_letter, 'A' | 'B') {
                return DriveType::Removable;
            }
            return DriveType::Fixed;
        }

        DriveType::Unknown
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FileId(pub u64);

impl FileId {
    pub fn from(fileid: [u8; FILE_ID_LEN]) -> FileId {
        let mut hasher = DefaultHasher::new();
        fileid.hash(&mut hasher);
        let hash = hasher.finish();
        FileId(hash)
    }
}

/// NEW: Detailed user-mode API hook event info
/// Matches KERNEL_EVENT_INFO from SharedDefs.h
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[repr(C)]
pub struct KernelEventInfo {
    pub event_type: u32,        // IRP_MAJOR_OP type
    pub timestamp: u64,         // Event timestamp
    pub source_process_id: u32, // Process initiating the operation
    pub target_process_id: u32, // Target process (if applicable)

    // Memory operation details
    pub memory_address: u64,        // Address involved in operation
    pub memory_size: usize,         // Size of memory operation
    pub memory_protection: u32,     // Protection flags
    pub is_executable_memory: bool, // Whether operation targets executable memory

    // Thread operation details
    pub thread_handle: u64,        // Thread handle (for thread operations)
    pub thread_start_routine: u64, // Start routine (for thread creation)

    // Raw HIM/API-hook arguments from the kernel event source
    pub raw_argument1: u64,
    pub raw_argument2: u64,
    pub raw_argument3: u64,
    pub raw_argument4: u64,

    // File/Section operation details
    pub object_name: String, // File/section name (up to 520 WCHARs in C)

    // Access control details
    pub access_mask: u32, // Requested access rights

    // NEW: Raw binary payload (e.g. for Named Pipes)
    pub bin_payload: Vec<u8>,

    // DLL Load Detection - Tracks both API-based and direct DLL loading
    pub is_dll_load: bool,
    pub loaded_dll_path: String,
    pub is_api_based_load: bool, // true if loaded via API (LoadLibrary), false if direct load

    // ACG Detection - Dynamic Code Policy at kernel level
    pub is_acg_enabled: bool,

    // AMSI Detection
    pub is_amsi_event: bool,
    pub amsi_content_sample: String,

    // Operation result
    pub operation_status: i32, // NTSTATUS of the operation
    pub core_id: u32,          // Hypervisor core id (if applicable)
    pub thread_id: u32,        // Thread id captured by the kernel event source
    pub context: u64,          // Hypervisor/event-specific context value
}

/// Represents a driver message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct IOMessage {
    pub extension: String,
    pub file_id_id: FileId,
    pub mem_sized_used: u64,
    pub entropy: f64,
    pub pid: u32,
    /// Raw OpenEDR SysmonEvent ID (0x0000–0x0010 on Windows, legacy small int on Linux).
    /// Use `IrpMajorOp::from_sysmonevent(irp_op)` for semantic classification,
    /// or `SysmonEvent::from_u32(irp_op)` for exact event type matching.
    pub irp_op: u32,
    pub is_entropy_calc: u8,
    pub file_change: u8,
    pub file_location_info: u8,
    pub filepathstr: String,
    pub gid: u64,
    /// Parent PID of the process
    pub parent_pid: u32,
    /// For IrpProcessTerminateAttempt: PID of the attacking process (0 if not applicable)
    pub attacker_pid: u32,
    /// For IrpProcessTerminateAttempt: GID of the attacking process (0 if not tracked)
    pub attacker_gid: u64,
    /// NEW: Ntdll API hook event details (matches KERNEL_EVENT_INFO from SharedDefs.h)
    pub kernel_event_info: KernelEventInfo,
    pub runtime_features: RuntimeFeatures,
    pub file_size: i64,
    pub time: SystemTime,
}

impl Default for IOMessage {
    fn default() -> Self {
        Self {
            extension: String::new(),
            file_id_id: FileId::default(),
            mem_sized_used: 0,
            entropy: 0.0,
            pid: 0,
            irp_op: 0u32,
            is_entropy_calc: 0,
            file_change: 0,
            file_location_info: 0,
            filepathstr: String::new(),
            gid: 0,
            parent_pid: 0,

            attacker_pid: 0,

            attacker_gid: 0,

            kernel_event_info: KernelEventInfo::default(),
            runtime_features: RuntimeFeatures::default(),
            file_size: 0,
            time: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedHypervisorEvent {
    pub irp_op: IrpMajorOp,
    pub raw_event_type: u32,
    pub event_name: String,
    pub source_process_id: u32,
    pub target_process_id: u32,
    pub core_id: u32,
    pub thread_id: u32,
    pub context: u64,
    pub memory_address: u64,
    pub memory_size: u64,
    pub memory_protection: u32,
    pub is_executable_memory: bool,
    pub thread_handle: u64,
    pub thread_start_routine: u64,
    pub raw_argument1: u64,
    pub raw_argument2: u64,
    pub raw_argument3: u64,
    pub raw_argument4: u64,
    pub access_mask: u32,
    pub operation_status: i32,
}

pub fn normalize_hypervisor_label(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    if let Some(idx) = value.find(" (syscall=0x") {
        value.truncate(idx);
    }
    value.trim().to_string()
}

/// Returns the effective IRP opcode for hypervisor/kernel-API events as `u32`.
///
/// `irp_op` now stores raw SysmonEvent IDs (0x0000–0x0010).
/// `DeviceIoControl` (0x000E) is the entry-point for hypervisor bridge events;
/// when `kernel_event_info.event_type` carries a more-specific sub-type (12–29
/// from the old Communication.cpp path) we forward that instead.

pub fn effective_hypervisor_irp_byte(msg: &IOMessage) -> u32 {
    if msg.irp_op == SysmonEvent::DeviceIoControl as u32
        && (12..=29).contains(&msg.kernel_event_info.event_type)
    {
        msg.kernel_event_info.event_type
    } else {
        msg.irp_op
    }
}

pub fn effective_hypervisor_raw_event_type(msg: &IOMessage) -> u32 {
    if msg.kernel_event_info.event_type != 0 {
        msg.kernel_event_info.event_type
    } else {
        effective_hypervisor_irp_byte(msg)
    }
}

pub fn is_kernel_api_irp(irp_op: &IrpMajorOp) -> bool {
    matches!(
        irp_op,
        IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection
    )
}

pub fn is_kernel_process_protection_irp(irp_op: &IrpMajorOp) -> bool {
    matches!(
        irp_op,
        IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection
    )
}

pub fn resolved_hypervisor_event_name(msg: &IOMessage) -> String {
    let normalized = normalize_hypervisor_label(&msg.kernel_event_info.object_name);
    if !normalized.is_empty() {
        return normalized;
    }

    let raw_event_type = effective_hypervisor_raw_event_type(msg);
    known_raw_event_name(raw_event_type)
        .map(|name| name.to_string())
        .unwrap_or_else(|| format!("RawEventType(0x{raw_event_type:X})"))
}

impl IOMessage {
    pub fn normalize_hypervisor_event(&mut self) {
        let raw_event_type = effective_hypervisor_raw_event_type(self);
        self.kernel_event_info.event_type = raw_event_type;

        if self.kernel_event_info.source_process_id == 0 {
            self.kernel_event_info.source_process_id = if self.attacker_pid != 0 {
                self.attacker_pid
            } else {
                self.pid
            };
        }

        if self.kernel_event_info.target_process_id == 0 {
            self.kernel_event_info.target_process_id = self.pid;
        }
    }

    pub fn needs_hypervisor_name_resolution(&self) -> bool {
        let object_name = self.kernel_event_info.object_name.trim();
        let has_qualified_name = object_name.contains('!')
            && !object_name.starts_with('!')
            && !object_name.ends_with('!');
        object_name.is_empty() || !has_qualified_name
    }

    pub fn resolved_hypervisor_event(&self) -> Option<ResolvedHypervisorEvent> {
        let irp_op = IrpMajorOp::from_sysmonevent(effective_hypervisor_irp_byte(self));
        if !is_kernel_api_irp(&irp_op) {
            return None;
        }

        Some(ResolvedHypervisorEvent {
            irp_op,
            raw_event_type: effective_hypervisor_raw_event_type(self),
            event_name: resolved_hypervisor_event_name(self),
            source_process_id: if self.kernel_event_info.source_process_id != 0 {
                self.kernel_event_info.source_process_id
            } else {
                self.pid
            },
            target_process_id: if self.kernel_event_info.target_process_id != 0 {
                self.kernel_event_info.target_process_id
            } else {
                self.pid
            },
            core_id: self.kernel_event_info.core_id,
            thread_id: self.kernel_event_info.thread_id,
            context: self.kernel_event_info.context,
            memory_address: self.kernel_event_info.memory_address,
            memory_size: self.kernel_event_info.memory_size as u64,
            memory_protection: self.kernel_event_info.memory_protection,
            is_executable_memory: self.kernel_event_info.is_executable_memory,
            thread_handle: self.kernel_event_info.thread_handle,
            thread_start_routine: self.kernel_event_info.thread_start_routine,
            raw_argument1: self.kernel_event_info.raw_argument1,
            raw_argument2: self.kernel_event_info.raw_argument2,
            raw_argument3: self.kernel_event_info.raw_argument3,
            raw_argument4: self.kernel_event_info.raw_argument4,
            access_mask: self.kernel_event_info.access_mask,
            operation_status: self.kernel_event_info.operation_status,
        })
    }
}

/// Stores runtime features that come from *`owlyshield_predict`* (and not the minifilter).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeFeatures {
    pub exepath: PathBuf,
    pub exe_still_exists: bool,
    pub command_line: String,
}

impl RuntimeFeatures {
    pub fn new() -> RuntimeFeatures {
        RuntimeFeatures {
            exepath: PathBuf::new(),
            exe_still_exists: true,
            command_line: String::new(),
        }
    }
}
