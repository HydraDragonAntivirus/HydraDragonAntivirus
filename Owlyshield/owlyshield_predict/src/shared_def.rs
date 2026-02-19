use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use num_derive::FromPrimitive;

#[cfg(target_os = "windows")]
const FILE_ID_LEN: usize = 16;
#[cfg(target_os = "linux")]
const FILE_ID_LEN: usize = 32;

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
pub enum DriverComMessageType {
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    _MessageAddScanDirectory,
    /// Not used yet. The minifilter has the ability to monitor a specific part of the fs.
    _MessageRemScanDirectory,
    /// Ask for a [ReplyIrp], if any available.
    MessageGetOps,
    /// Set this app pid to the minifilter (related IRPs will be ignored);
    MessageSetPid,
    MessageKillGid,
    MessageKillAndQuarantineGid,
    MessageKillOnlyGid,
    MessageKillAndRemoveGid, // NEW: Kill process and delete file
    MessageRevertRegistryChanges,
    MessageAddHook,
}

/// See [`shared_def::IOMessage`] struct and [this doc](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes).
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum IrpMajorOp {
    /// Nothing happened
    IrpNone,
    /// On read, any time following the successful completion of a create request.
    IrpRead,
    /// On write, any time following the successful completion of a create request.
    IrpWrite,
    /// Set Metadata about a file or file handle. In that case, [shared_def::FileChangeInfo] indicates
    /// the nature of the modification.
    IrpSetInfo,
    /// Open a handle to a file object or device object.
    IrpCreate,
    /// File object handle has been closed
    _IrpCleanUp, //not used (yet)
    /// Registry operation
    IrpRegistry,
    
    // Process-related operations
    /// Process creation
    IrpProcessCreate,
    /// Process termination (normal exit)
    IrpProcessTerminate,
    /// External process attempting to terminate another (attacker -> target)
    IrpProcessTerminateAttempt,
    /// Process exit/cleanup detected
    IrpProcessExit,
    /// Process handle opened for access (OB callback)
    IrpProcessHandleOpen,
    /// Kernel thread-create callback (cross-process only)
    IrpKernelRemoteThread,

    /// Generic API call telemetry (kernel opcode 13)
    IrpGenericApiCall,
    /// Generic assembly-level telemetry (kernel opcode 14)
    IrpGenericAssemblyEvent,
}

impl IrpMajorOp {
    pub fn from_byte(b: u8) -> IrpMajorOp {
        match b {
            0 => IrpMajorOp::IrpNone,
            1 => IrpMajorOp::IrpRead,
            2 => IrpMajorOp::IrpWrite,
            3 => IrpMajorOp::IrpSetInfo,
            4 => IrpMajorOp::IrpCreate,
            5 => IrpMajorOp::IrpCreate, // Mapping IRP_CLEANUP to Create logic or ignore in old code, keeping for consistency
            6 => IrpMajorOp::IrpRegistry,
            7 => IrpMajorOp::IrpProcessCreate,
            8 => IrpMajorOp::IrpProcessTerminate,
            9 => IrpMajorOp::IrpProcessTerminateAttempt,
            10 => IrpMajorOp::IrpProcessExit,
            11 => IrpMajorOp::IrpProcessHandleOpen,
            
            // Kernel callback + NTDLL hooks
            12 => IrpMajorOp::IrpKernelRemoteThread,
            // Collapsed generic model:
            // 13 => generic api, 14 => generic assembly.
            13 => IrpMajorOp::IrpGenericApiCall,
            14 => IrpMajorOp::IrpGenericAssemblyEvent,
            
            _ => IrpMajorOp::IrpNone,
        }
    }
}

/// See [`shared_def::IOMessage`] struct and [this doc](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea).
#[derive(Debug)]
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

        if filepath.starts_with('/'){ 
            // Linux-style paths default to fixed/local media
            return DriveType::Fixed;
        }

        // Windows-style "X:\" drive letter prefixes
        if filepath.chars().nth(1) == Some(':') {
            // Treat removable drive letters explicitly
            let drive_letter = filepath.chars().next().unwrap_or_default().to_ascii_uppercase();
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
/// Matches NTDLL_EVENT_INFO from SharedDefs.h
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[repr(C)]
pub struct KernelEventInfo {
    pub event_type: u32,           // IRP_MAJOR_OP type
    pub timestamp: u64,            // Event timestamp
    pub source_process_id: u32,    // Process initiating the operation
    pub target_process_id: u32,    // Target process (if applicable)
    
    // Memory operation details
    pub memory_address: u64,       // Address involved in operation
    pub memory_size: usize,        // Size of memory operation
    pub memory_protection: u32,    // Protection flags
    pub is_executable_memory: bool, // Whether operation targets executable memory
    
    // Thread operation details
    pub thread_handle: u64,        // Thread handle (for thread operations)
    pub thread_start_routine: u64, // Start routine (for thread creation)
    
    // File/Section operation details
    pub object_name: String,       // File/section name (up to 520 WCHARs in C)
    
    // Access control details
    pub access_mask: u32,          // Requested access rights
    
    // Operation result
    pub operation_status: i32,     // NTSTATUS of the operation
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
    pub irp_op: u8,
    pub is_entropy_calc: u8,
    pub file_change: u8,
    pub file_location_info: u8,
    pub filepathstr: String,
    pub gid: u64,
    /// Parent PID of the process
    pub parent_pid: u32,
    /// For IrpProcessTerminateAttempt: PID of the attacking process (0 if not applicable)
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    pub attacker_pid: u32,
    /// For IrpProcessTerminateAttempt: GID of the attacking process (0 if not tracked)
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    pub attacker_gid: u64,
    /// Generic kernel API/assembly event details (matches NTDLL_EVENT_INFO from SharedDefs.h)
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
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
            irp_op: 0,
            is_entropy_calc: 0,
            file_change: 0,
            file_location_info: 0,
            filepathstr: String::new(),
            gid: 0,
            parent_pid: 0,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            attacker_pid: 0,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            attacker_gid: 0,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            kernel_event_info: KernelEventInfo::default(),
            runtime_features: RuntimeFeatures::default(),
            file_size: 0,
            time: SystemTime::now(),
        }
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
