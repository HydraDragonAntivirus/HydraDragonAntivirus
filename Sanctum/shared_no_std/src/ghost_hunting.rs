use alloc::string::String;
use core::arch::x86_64::_MM_HINT_NTA;

use serde::{Deserialize, Serialize};
use strum::EnumIter;

/// Bitfields which act as a mask to determine which event types (kernel, syscall hook, etw etc)
/// are required to fully cancel out the ghost hunt timers.
///
/// This is because not all events are capturable in the kernel without tampering with patch guard etc, so there are some events
/// only able to be caught by ETW and the syscall hook.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
pub enum SyscallEventSource {
    EventSourceKernel = 0x1,
    EventSourceSyscallHook = 0x2,
}

/// A wrapper for IPC messages sent by the injected DLL in all processes. This allows the same IPC interface to
/// be used across any number of IPC senders, so long as the enum has a discriminant for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DLLMessage {
    SyscallWrapper(Syscall),
    NtdllOverwrite,
    ProcessReadyForGhostHunting,
}

/****************************** SYSCALLS *******************************/

/// Information relating to a syscall event which happened on the device. This struct holds:
///
/// - `pid`: The ID of the process making the syscall
/// - `source`: Where the system event was captured, e.g. a hooked syscall, ETW, or the driver.
/// - `data`: This field is generic over T which must implement the `HasPid` trait. This field contains the metadata associated
/// with the syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub pid: u32,
    pub source: SyscallEventSource,
    pub data: NtFunction,
}

impl Syscall {
    pub fn from_kernel(process_initiating_pid: u32, data: NtFunction) -> Self {
        Self {
            pid: process_initiating_pid,
            source: SyscallEventSource::EventSourceKernel,
            data,
        }
    }

    pub fn from_sanctum_dll(process_initiating_pid: u32, data: NtFunction) -> Self {
        Self {
            pid: process_initiating_pid,
            source: SyscallEventSource::EventSourceSyscallHook,
            data,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, EnumIter)]
/// A representation of an Nt function which contains an inner data carrier for arguments we wish
/// to monitor related to that syscall directly.
///
/// This is also represented as a C style numbered enum which can be OR'ed into a flag. To see the
/// numeric types, see individual enum docs. To access this functionality, see [`NtFunction::as_mask`]
pub enum NtFunction {
    /// None is provided to allow `EnumIter` to work, this should never match anything
    #[default]
    None,
    NtOpenProcess(NtOpenProcessData),
    NtWriteVirtualMemory(NtWriteVirtualMemoryData),
    NtAllocateVirtualMemory(NtAllocateVirtualMemoryData),
    NtCreateThreadEx(NtCreateThreadExData),
    NetworkActivity(NetworkActivityData),
}

impl NtFunction {
    pub const M_NONE: u64 = 0x0;
    pub const M_NT_OPEN_PROCESS: u64 = 1 << 0;
    pub const M_NT_WRITE_VM: u64 = 1 << 1;
    pub const M_NT_ALLOC_VM: u64 = 1 << 2;
    pub const M_CREATE_THREAD_EX: u64 = 1 << 3;
    pub const M_NETWORK_ACTIVITY: u64 = 1 << 4;

    pub fn as_mask(&self) -> u64 {
        let m = match self {
            NtFunction::None => Self::M_NONE,
            NtFunction::NtOpenProcess(_) => Self::M_NT_OPEN_PROCESS,
            NtFunction::NtWriteVirtualMemory(_) => Self::M_NT_WRITE_VM,
            NtFunction::NtAllocateVirtualMemory(_) => Self::M_NT_ALLOC_VM,
            NtFunction::NtCreateThreadEx(_) => Self::M_CREATE_THREAD_EX,
            NtFunction::NetworkActivity(_) => Self::M_NETWORK_ACTIVITY,
        };

        m
    }
}

/// todo docs
#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtOpenProcessData {
    pub target_pid: u32,
    pub desired_mask: u32,
}

/// todo docs
#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtWriteVirtualMemoryData {
    pub target_pid: u32,
    pub base_address: usize,
    pub buf_len: usize,
}

unsafe impl Send for Syscall {}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtAllocateVirtualMemoryData {
    pub dest_pid: u32,
    pub base_address: usize,
    pub sz: usize,
    pub alloc_type: u32,
    pub protect_flags: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtCreateThreadExData {
    pub target_pid: u32,
    pub start_routine: usize,
    pub argument: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum NetworkActivityData {
    Http(HttpActivity),
    WinINet(WinINetActivity),
}

impl Default for NetworkActivityData {
    fn default() -> Self {
        NetworkActivityData::Http(HttpActivity::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct HttpActivity {
    pub url: String,
    pub method: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct WinINetActivity {
    pub url: String,
    pub server: String,
}
