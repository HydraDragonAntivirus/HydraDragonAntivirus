use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::SystemTime;

#[cfg(target_os = "windows")]
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

/// See [`shared_def::IOMessage`] struct and [this doc](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
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
    /// Single normalized opcode for real VMM/HyperDbg-origin activity only.
    /// Kernel process-protection signals stay in the dedicated IrpKernel* variants below.
    IrpHypervisorEvent,
    /// User-mode API hook callback from UserModeHookEngine shellcode.
    /// With the handle-free ring transport, the driver drains the ring and
    /// emits this same opcode into the normal IOMessage pipeline.
    IrpUserModeHookEvent,
    /// Kernel process-protection signal: remote thread creation
    IrpKernelRemoteThread,
    /// Kernel process-protection signal: write memory
    IrpKernelWriteMemory,
    /// Kernel process-protection signal: change memory protection
    IrpKernelProtectMemory,
    /// Kernel process-protection signal: create thread
    IrpKernelCreateThread,
    /// Kernel process-protection signal: queue APC
    IrpKernelQueueApc,
    /// Kernel process-protection signal: create section
    IrpKernelCreateSection,
    /// Kernel process-protection signal: map section
    IrpKernelMapSection,

    // Rootkit-related operations
    IrpRootkitSsdtHook,
    IrpRootkitHiddenProcess,
    IrpRootkitHiddenDriver,
    IrpRootkitKernelHook,
    IrpRootkitTerminateProcess,
    IrpRootkitFileMove,
    IrpRootkitGeneric,

    // Named Pipe Operations (Kernel + Usermode)
    IrpNamedPipeCreate,
    IrpNamedPipeWrite,
}

impl IrpMajorOp {
    pub fn from_byte(b: u8) -> IrpMajorOp {
        match b {
            0 => IrpMajorOp::IrpNone,
            1 => IrpMajorOp::IrpRead,
            2 => IrpMajorOp::IrpWrite,
            3 => IrpMajorOp::IrpSetInfo,
            4 => IrpMajorOp::IrpCreate,
            5 => IrpMajorOp::IrpCreate,
            6 => IrpMajorOp::IrpRegistry,
            7 => IrpMajorOp::IrpProcessCreate,
            8 => IrpMajorOp::IrpProcessTerminate,
            9 => IrpMajorOp::IrpProcessTerminateAttempt,
            10 => IrpMajorOp::IrpProcessExit,
            11 => IrpMajorOp::IrpProcessHandleOpen,
            12 => IrpMajorOp::IrpHypervisorEvent,
            20 => IrpMajorOp::IrpUserModeHookEvent,
            13 => IrpMajorOp::IrpKernelRemoteThread,
            14 => IrpMajorOp::IrpKernelWriteMemory,
            15 => IrpMajorOp::IrpKernelProtectMemory,
            16 => IrpMajorOp::IrpKernelCreateThread,
            17 => IrpMajorOp::IrpKernelQueueApc,
            18 => IrpMajorOp::IrpKernelCreateSection,
            19 => IrpMajorOp::IrpKernelMapSection,

            21 => IrpMajorOp::IrpRootkitSsdtHook,
            22 => IrpMajorOp::IrpRootkitHiddenProcess,
            23 => IrpMajorOp::IrpRootkitHiddenDriver,
            24 => IrpMajorOp::IrpRootkitKernelHook,
            25 => IrpMajorOp::IrpRootkitTerminateProcess,
            26 => IrpMajorOp::IrpRootkitFileMove,
            27 => IrpMajorOp::IrpRootkitGeneric,
            28 => IrpMajorOp::IrpNamedPipeCreate,
            29 => IrpMajorOp::IrpNamedPipeWrite,

            _ => IrpMajorOp::IrpNone,
        }
    }
}

pub const OWLY_VMM_RAW_EVENT_BASE: u32 = 0x1000;
pub const OWLY_VMM_RAW_CALLBACK_BASE: u32 = 0x1200;
pub const OWLY_VMM_RAW_HYPEREVADE_BASE: u32 = 0x1300;
pub const OWLY_VMM_RAW_DISASM_BASE: u32 = 0x1400;

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

pub fn hypervisor_raw_event_name(raw_event_type: u32) -> Option<&'static str> {
    match raw_event_type {
        0x1201 => Some("VMMCALL"),
        0x1203 => Some("NMI_BROADCAST"),
        0x1204 => Some("QUERY_TERMINATE_PROTECTED_RESOURCE"),
        0x1206 => Some("UNHANDLED_EPT_VIOLATION"),
        0x1208 => Some("DEBUG_DEBUG_BREAKPOINT_EXCEPTION"),
        0x1209 => Some("DEBUG_THREAD_INTERCEPTION"),
        0x120A => Some("CR3_PROCESS_CHANGE"),
        0x120B => Some("REAPPLY_BREAKPOINT"),
        0x120C => Some("KD_NMI_CALLBACK"),
        0x120D => Some("REGISTERED_MTF_HANDLER"),
        0x120E => Some("DEBUGGER_PROCESS_OR_THREAD_CHANGE"),
        0x120F => Some("KD_QUERY_THREAD_OR_PROCESS_TRACING"),
        0x1301 => Some("TRANSPARENT_HIDE_DEBUGGER"),
        0x1302 => Some("TRANSPARENT_UNHIDE_DEBUGGER"),
        0x1303 => Some("TRANSPARENT_CPUID"),
        0x1304 => Some("TRANSPARENT_TRAP_FLAG_AFTER_VMEXIT"),
        0x1305 => Some("TRANSPARENT_MSR_READ"),
        0x1306 => Some("TRANSPARENT_MSR_WRITE"),
        0x1307 => Some("TRANSPARENT_SYSCALL_HOOK"),
        0x1308 => Some("TRANSPARENT_AFTER_SYSCALL"),
        0x1401 => Some("DISASM_SHOW_INSTR_NONROOT"),
        0x1402 => Some("DISASM_ONE_INSTR_NONROOT"),
        0x1403 => Some("DISASM_ONE_INSTR_ROOT"),
        0x1404 => Some("DISASM_LENGTH_ENGINE"),
        0x1405 => Some("DISASM_LENGTH_ENGINE_ROOT_TARGET"),
        0x1406 => Some("DISASM_LENGTH_ENGINE_BY_PID"),
        _ => None,
    }
}

pub fn is_hypervisor_raw_event_type(raw_event_type: u32) -> bool {
    matches!(
        raw_event_type,
        OWLY_VMM_RAW_EVENT_BASE..=0x11FF
            | OWLY_VMM_RAW_CALLBACK_BASE..=0x12FF
            | OWLY_VMM_RAW_HYPEREVADE_BASE..=0x13FF
            | OWLY_VMM_RAW_DISASM_BASE..=0x14FF
    )
}

pub fn known_raw_event_name(raw_event_type: u32) -> Option<&'static str> {
    kernel_raw_event_name(raw_event_type).or_else(|| hypervisor_raw_event_name(raw_event_type))
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
    /// NEW: Ntdll API hook event details (matches KERNEL_EVENT_INFO from SharedDefs.h)
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

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
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

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub fn normalize_hypervisor_label(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    if let Some(idx) = value.find(" (syscall=0x") {
        value.truncate(idx);
    }
    value.trim().to_string()
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub fn effective_hypervisor_irp_byte(msg: &IOMessage) -> u8 {
    if msg.irp_op == 12 && (12..=20).contains(&msg.kernel_event_info.event_type) {
        msg.kernel_event_info.event_type as u8
    } else {
        msg.irp_op
    }
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub fn effective_hypervisor_raw_event_type(msg: &IOMessage) -> u32 {
    if msg.kernel_event_info.event_type != 0 {
        msg.kernel_event_info.event_type
    } else {
        effective_hypervisor_irp_byte(msg) as u32
    }
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub fn is_kernel_api_irp(irp_op: &IrpMajorOp) -> bool {
    matches!(
        irp_op,
        IrpMajorOp::IrpHypervisorEvent
            | IrpMajorOp::IrpUserModeHookEvent
            | IrpMajorOp::IrpKernelRemoteThread
            | IrpMajorOp::IrpKernelWriteMemory
            | IrpMajorOp::IrpKernelProtectMemory
            | IrpMajorOp::IrpKernelCreateThread
            | IrpMajorOp::IrpKernelQueueApc
            | IrpMajorOp::IrpKernelCreateSection
            | IrpMajorOp::IrpKernelMapSection
    )
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
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

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
pub fn is_real_hypervisor_irp(irp_op: &IrpMajorOp, raw_event_type: u32) -> bool {
    matches!(irp_op, IrpMajorOp::IrpHypervisorEvent) && is_hypervisor_raw_event_type(raw_event_type)
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
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

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
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
        let irp_op = IrpMajorOp::from_byte(effective_hypervisor_irp_byte(self));
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
