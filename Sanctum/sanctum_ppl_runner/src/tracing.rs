//! This module is dedicated to tracing via ETW from a PPL security context.

use std::ptr::copy_nonoverlapping;

use crate::{
    ipc::send_etw_info_ipc,
    logging::{EventID, event_log},
};
use shared_no_std::ghost_hunting::{
    EtwThreatIntelligenceData, HttpActivity, NetworkActivityData, NtFunction, Syscall,
    SyscallEventSource, WinINetActivity,
};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, GetLastError, MAX_PATH},
        System::{
            Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, CloseTrace, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER,
                EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
                PROPERTY_DATA_DESCRIPTOR, ProcessTrace, StartTraceW, StopTraceW, TRACE_EVENT_INFO,
                TRACE_LEVEL_VERBOSE, TdhGetEventInformation, TdhGetProperty,
            },
            EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE},
            ProcessStatus::GetProcessImageFileNameW,
            Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

//
// Define constants which are used by this module.
// Note: To query the provider information for ETW:TI, `wevtutil gp Microsoft-Windows-Threat-Intelligence`
//

/// The GUID for Event Tracing for Windows: Threat Intelligence. f4e1897c-bb5d-5668-f1d8-040f4d8dd344
const ETW_TI_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0xf4e1897c_bb5d_5668_f1d8_040f4d8dd344);

/// The GUID for Microsoft-Windows-HttpService. dd5ef90a-6398-47a4-ad34-4d35d2e7171b
const HTTP_SERVICE_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0xdd5ef90a_6398_47a4_ad34_4d35d2e7171b);

/// The GUID for Microsoft-Windows-WinINet. 43d1a55c-76d6-4f7e-995c-97171f3603f8
const WININET_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x43d1a55c_76d6_4f7e_995c_97171f3603f8);

// Task ID's from ETW:TI (wevtutil gp Microsoft-Windows-Threat-Intelligence)
const KERNEL_THREATINT_TASK_ALLOCVM: u16 = 1;
const KERNEL_THREATINT_TASK_PROTECTVM: u16 = 2;
const KERNEL_THREATINT_TASK_MAPVIEW: u16 = 3;
const KERNEL_THREATINT_TASK_QUEUEUSERAPC: u16 = 4;
const KERNEL_THREATINT_TASK_SETTHREADCONTEXT: u16 = 5;
const KERNEL_THREATINT_TASK_READVM: u16 = 6;
const KERNEL_THREATINT_TASK_WRITEVM: u16 = 7;
const KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD: u16 = 8;
const KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS: u16 = 9;
const KERNEL_THREATINT_TASK_DRIVER_DEVICE: u16 = 10;

// Keyword masks for ETW:TI
const KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL: u64 = 0x1;
const KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER: u64 = 0x2;
const KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE: u64 = 0x4;
const KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER: u64 = 0x8;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL: u64 = 0x10;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER: u64 = 0x20;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE: u64 = 0x40;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER: u64 = 0x80;
const KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL: u64 = 0x100;
const KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL_KERNEL_CALLER: u64 = 0x200;
const KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE: u64 = 0x400;
const KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE_KERNEL_CALLER: u64 = 0x800;
const KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE: u64 = 0x1000;
const KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE_KERNEL_CALLER: u64 = 0x2000;
const KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE: u64 = 0x4000;
const KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE_KERNEL_CALLER: u64 = 0x8000;
const KERNEL_THREATINT_KEYWORD_READVM_LOCAL: u64 = 0x10000;
const KERNEL_THREATINT_KEYWORD_READVM_REMOTE: u64 = 0x20000;
const KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL: u64 = 0x40000;
const KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE: u64 = 0x80000;
const KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD: u64 = 0x100000;
const KERNEL_THREATINT_KEYWORD_RESUME_THREAD: u64 = 0x200000;
const KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS: u64 = 0x400000;
const KERNEL_THREATINT_KEYWORD_RESUME_PROCESS: u64 = 0x800000;
const KERNEL_THREATINT_KEYWORD_FREEZE_PROCESS: u64 = 0x1000000;
const KERNEL_THREATINT_KEYWORD_THAW_PROCESS: u64 = 0x2000000;
const KERNEL_THREATINT_KEYWORD_CONTEXT_PARSE: u64 = 0x4000000;
const KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_VAD_PROBE: u64 = 0x8000000;
const KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_MMF_NAME_PROBE: u64 = 0x10000000;
const KERNEL_THREATINT_KEYWORD_READWRITEVM_NO_SIGNATURE_RESTRICTION: u64 = 0x20000000;
const KERNEL_THREATINT_KEYWORD_DRIVER_EVENTS: u64 = 0x40000000;
const KERNEL_THREATINT_KEYWORD_DEVICE_EVENTS: u64 = 0x80000000;
const KERNEL_THREATINT_KEYWORD_READVM_REMOTE_FILL_VAD: u64 = 0x100000000;
const KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE_FILL_VAD: u64 = 0x200000000;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_FILL_VAD: u64 = 0x400000000;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER_FILL_VAD: u64 = 0x800000000;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_FILL_VAD: u64 = 0x1000000000;
const KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER_FILL_VAD: u64 = 0x2000000000;

struct ThreatIntelKeywordTelemetry {
    mask: u64,
    expected_task: u16,
    event_name: &'static str,
    function: &'static str,
    remote: bool,
    suspicious: bool,
}

const THREAT_INTEL_TELEMETRY: &[ThreatIntelKeywordTelemetry] = &[
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL,
        expected_task: KERNEL_THREATINT_TASK_ALLOCVM,
        event_name: "AllocVmLocal",
        function: "NtAllocateVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_ALLOCVM,
        event_name: "AllocVmLocalKernelCaller",
        function: "NtAllocateVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_ALLOCVM,
        event_name: "AllocVmRemote",
        function: "NtAllocateVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_ALLOCVM,
        event_name: "AllocVmRemoteKernelCaller",
        function: "NtAllocateVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmLocal",
        function: "NtProtectVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmLocalKernelCaller",
        function: "NtProtectVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmRemote",
        function: "NtProtectVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmRemoteKernelCaller",
        function: "NtProtectVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL,
        expected_task: KERNEL_THREATINT_TASK_MAPVIEW,
        event_name: "MapViewLocal",
        function: "NtMapViewOfSection",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_MAPVIEW,
        event_name: "MapViewLocalKernelCaller",
        function: "NtMapViewOfSection",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_MAPVIEW,
        event_name: "MapViewRemote",
        function: "NtMapViewOfSection",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_MAPVIEW,
        event_name: "MapViewRemoteKernelCaller",
        function: "NtMapViewOfSection",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_QUEUEUSERAPC,
        event_name: "QueueUserApcRemote",
        function: "NtQueueApcThread",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_QUEUEUSERAPC,
        event_name: "QueueUserApcRemoteKernelCaller",
        function: "NtQueueApcThread",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_SETTHREADCONTEXT,
        event_name: "SetThreadContextRemote",
        function: "NtSetContextThread",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE_KERNEL_CALLER,
        expected_task: KERNEL_THREATINT_TASK_SETTHREADCONTEXT,
        event_name: "SetThreadContextRemoteKernelCaller",
        function: "NtSetContextThread",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_READVM_LOCAL,
        expected_task: KERNEL_THREATINT_TASK_READVM,
        event_name: "ReadVmLocal",
        function: "NtReadVirtualMemory",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_READVM_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_READVM,
        event_name: "ReadVmRemote",
        function: "NtReadVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL,
        expected_task: KERNEL_THREATINT_TASK_WRITEVM,
        event_name: "WriteVmLocal",
        function: "NtWriteVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE,
        expected_task: KERNEL_THREATINT_TASK_WRITEVM,
        event_name: "WriteVmRemote",
        function: "NtWriteVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD,
        expected_task: KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD,
        event_name: "SuspendThread",
        function: "NtSuspendThread",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_RESUME_THREAD,
        expected_task: KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD,
        event_name: "ResumeThread",
        function: "NtResumeThread",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS,
        expected_task: KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS,
        event_name: "SuspendProcess",
        function: "NtSuspendProcess",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_RESUME_PROCESS,
        expected_task: KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS,
        event_name: "ResumeProcess",
        function: "NtResumeProcess",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_FREEZE_PROCESS,
        expected_task: KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS,
        event_name: "FreezeProcess",
        function: "NtSuspendProcess",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_THAW_PROCESS,
        expected_task: KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS,
        event_name: "ThawProcess",
        function: "NtResumeProcess",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_CONTEXT_PARSE,
        expected_task: KERNEL_THREATINT_TASK_SETTHREADCONTEXT,
        event_name: "ContextParse",
        function: "EtwTiContextParse",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_VAD_PROBE,
        expected_task: KERNEL_THREATINT_TASK_SETTHREADCONTEXT,
        event_name: "ExecutionAddressVadProbe",
        function: "EtwTiExecutionAddressVadProbe",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_MMF_NAME_PROBE,
        expected_task: KERNEL_THREATINT_TASK_SETTHREADCONTEXT,
        event_name: "ExecutionAddressMmfNameProbe",
        function: "EtwTiExecutionAddressMmfNameProbe",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_READWRITEVM_NO_SIGNATURE_RESTRICTION,
        expected_task: KERNEL_THREATINT_TASK_WRITEVM,
        event_name: "ReadWriteVmNoSignatureRestriction",
        function: "EtwTiReadWriteVmNoSignatureRestriction",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_DRIVER_EVENTS,
        expected_task: KERNEL_THREATINT_TASK_DRIVER_DEVICE,
        event_name: "DriverEvent",
        function: "EtwTiDriverEvent",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_DEVICE_EVENTS,
        expected_task: KERNEL_THREATINT_TASK_DRIVER_DEVICE,
        event_name: "DeviceEvent",
        function: "EtwTiDeviceEvent",
        remote: false,
        suspicious: false,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_READVM_REMOTE_FILL_VAD,
        expected_task: KERNEL_THREATINT_TASK_READVM,
        event_name: "ReadVmRemoteFillVad",
        function: "NtReadVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE_FILL_VAD,
        expected_task: KERNEL_THREATINT_TASK_WRITEVM,
        event_name: "WriteVmRemoteFillVad",
        function: "NtWriteVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_FILL_VAD,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmLocalFillVad",
        function: "NtProtectVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER_FILL_VAD,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmLocalKernelCallerFillVad",
        function: "NtProtectVirtualMemory",
        remote: false,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_FILL_VAD,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmRemoteFillVad",
        function: "NtProtectVirtualMemory",
        remote: true,
        suspicious: true,
    },
    ThreatIntelKeywordTelemetry {
        mask: KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER_FILL_VAD,
        expected_task: KERNEL_THREATINT_TASK_PROTECTVM,
        event_name: "ProtectVmRemoteKernelCallerFillVad",
        function: "NtProtectVirtualMemory",
        remote: true,
        suspicious: true,
    },
];

//
// Functions
//

fn send_threat_intel_to_engine(
    pid: u32,
    process_image: &str,
    event_id: u16,
    task: u16,
    keyword: u64,
    target_pid: Option<u32>,
) {
    for telemetry in THREAT_INTEL_TELEMETRY {
        if keyword & telemetry.mask != telemetry.mask {
            continue;
        }

        send_etw_info_ipc(Syscall {
            pid,
            source: SyscallEventSource::EventSourceKernel,
            data: NtFunction::EtwThreatIntelligence(EtwThreatIntelligenceData {
                function: telemetry.function.to_string(),
                event_name: telemetry.event_name.to_string(),
                process_image: process_image.to_string(),
                event_id,
                task,
                expected_task: telemetry.expected_task,
                task_matches: task == telemetry.expected_task,
                keyword,
                matched_keyword: telemetry.mask,
                remote: telemetry.remote,
                suspicious: telemetry.suspicious,
                target_pid,
            }),
            caller_address: 0,
            hex_payload: [0; 16],
        });
    }
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn TraceSetInformation(
        session_handle: CONTROLTRACE_HANDLE,
        information_class: u32,
        trace_information: *const std::ffi::c_void,
        information_length: u32,
    ) -> u32;

    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: PCWSTR,
        string_sd_revision: u32,
        security_descriptor: *mut *mut std::ffi::c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;

    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

const TRACE_SECURITY_TRACING: u32 = 9;
const SDDL_REVISION_1: u32 = 1;

/// Locks down the trace session security descriptor so that external processes (even elevated with token manipulation)
/// cannot call ControlTrace(STOP) on our session.
fn protect_trace_session(handle: CONTROLTRACE_HANDLE) {
    // SDDL:
    // D:P -> Protected DACL (no inheritance)
    // (A;;0x120fff;;;SY) -> SYSTEM full access (for PPL service execution)
    // (A;;0x120fff;;;BA) -> Built-in Administrators
    // (A;;0x120fff;;;LS) -> LocalService
    let sddl_wide: Vec<u16> = "D:P(A;;0x120fff;;;SY)(A;;0x120fff;;;BA)(A;;0x120fff;;;LS)\0".encode_utf16().collect();
    let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sd_size = 0u32;

    let res = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut p_sd,
            &mut sd_size,
        )
    };

    if res != 0 && !p_sd.is_null() {
        let ret = unsafe {
            TraceSetInformation(
                handle,
                TRACE_SECURITY_TRACING,
                p_sd,
                sd_size,
            )
        };
        if ret == 0 {
            event_log(
                "Successfully applied hardened DACL to ETW:TI trace session.",
                EVENTLOG_INFORMATION_TYPE,
                EventID::Info,
            );
        } else {
            event_log(
                &format!("TraceSetInformation status: {:#x}", ret),
                EVENTLOG_INFORMATION_TYPE,
                EventID::Info,
            );
        }
        unsafe { LocalFree(p_sd) };
    }
}

/// Public entrypoint to starting the threat intelligence trace routine with a resilient watchdog loop.
pub fn start_threat_intel_trace() {
    while !crate::is_service_stopping() {
        register_ti_session();
        if crate::is_service_stopping() {
            break;
        }
        event_log(
            "CRITICAL SECURITY ALERT: ETW:TI trace was interrupted or terminated externally! Watchdog reviving trace session immediately...",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Internal function which starts the tracing of the ETW: Threat Intelligence module.
///
/// This will register the tracing session and then start it **blocking** the thread until an error occurs from the winternal functions.
fn register_ti_session() {
    event_log(
        "Starting ETW:TI registration.",
        EVENTLOG_INFORMATION_TYPE,
        EventID::Info,
    );

    let mut handle = CONTROLTRACE_HANDLE::default();

    let mut wide_name: Vec<u16> = "SanctumETWThreatIntelligence\0".encode_utf16().collect();
    let session_name = PCWSTR::from_raw(wide_name.as_ptr());

    // SAFETY: null pointer for getting the session name length checked above.
    let total_size: usize =
        size_of::<EVENT_TRACE_PROPERTIES>() + (wide_name.len() * size_of::<u16>());

    // allocate a buffer for the properties plus the session name (len calculated above)
    let mut buffer = vec![0u8; total_size];
    // get a mutable pointer to the start of the buffer, casting as EVENT_TRACE_PROPERTIES
    let properties = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    if properties.is_null() {
        event_log(
            "Buffer was null for EVENT_TRACE_PROPERTIES. Cannot proceed safely.",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return;
    }

    // allocate the correct parameters for the EVENT_TRACE_PROPERTIES in the buffer.
    // SAFETY: Null pointer checked above.
    unsafe {
        (*properties).Wnode.BufferSize = total_size as _;
        (*properties).Wnode.Flags = EVENT_TRACE_REAL_TIME_MODE;
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        // set logger name offset to the right of the structure
        (*properties).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as _;
    }
    let logger_name_ptr = unsafe {
        // copy the session name into the buffer
        let logger_name_ptr =
            (buffer.as_mut_ptr() as usize + (*properties).LoggerNameOffset as usize) as *mut u16;
        copy_nonoverlapping(wide_name.as_ptr(), logger_name_ptr, wide_name.len());

        logger_name_ptr
    };
    let embedded_session_name = PCWSTR::from_raw(logger_name_ptr);

    let mut status = unsafe { StartTraceW(&mut handle, embedded_session_name, properties) };
    if status.is_err() {
        // Attempt clean stop in case a previous dirty session exists
        let _ = unsafe { StopTraceW(handle, embedded_session_name, properties) };
        std::thread::sleep(std::time::Duration::from_millis(50));
        status = unsafe { StartTraceW(&mut handle, embedded_session_name, properties) };
        if status.is_err() {
            event_log(
                &format!(
                    "Unable to register ETW:TI session. Win32 error: {:?}",
                    status
                ),
                EVENTLOG_ERROR_TYPE,
                EventID::GeneralError,
            );
            return;
        }
    }

    // Apply hardened DACL to prevent external callers from terminating the trace
    protect_trace_session(handle);

    event_log(
        "Successfully registered ETW trace.",
        EVENTLOG_INFORMATION_TYPE,
        EventID::Info,
    );

    let status = unsafe {
        EnableTraceEx2(
            handle,
            &ETW_TI_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as _,
            u64::MAX, // set all bits in the mask
            0,
            0,
            None,
        )
    };
    if status.is_err() {
        event_log(
            &format!("EnableTraceEx2 failed with Win32 error: {:?}", status),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        stop_trace(handle, session_name, properties);
        return;
    }

    let _ = unsafe {
        EnableTraceEx2(
            handle,
            &HTTP_SERVICE_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as _,
            u64::MAX,
            0,
            0,
            None,
        )
    };

    let _ = unsafe {
        EnableTraceEx2(
            handle,
            &WININET_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as _,
            u64::MAX,
            0,
            0,
            None,
        )
    };

    event_log(
        "Successfully started trace for ETW:TI.",
        EVENTLOG_INFORMATION_TYPE,
        EventID::Info,
    );

    process_trace_events(&mut wide_name);

    // If we reach here, process_trace_events has unblocked
    if crate::is_service_stopping() {
        stop_trace(handle, session_name, properties);
    } else {
        event_log(
            "ETW:TI trace unblocked unexpectedly (external stop detected). Watchdog reviving trace...",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        let _ = unsafe { StopTraceW(handle, session_name, properties) };
    }
}

/// Stops the tracing session
fn stop_trace(
    handle: CONTROLTRACE_HANDLE,
    session_name: PCWSTR,
    properties: *mut EVENT_TRACE_PROPERTIES,
) {
    event_log(
        "Stopping trace...",
        EVENTLOG_INFORMATION_TYPE,
        EventID::GeneralError,
    );
    if unsafe { StopTraceW(handle, session_name, properties) }.is_err() {
        event_log(
            &format!(
                "Failed to stop ETW:TI session. Failed with Win32 error: {}",
                unsafe { GetLastError().0 }
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
    }
}

/// Begin tracing events
fn process_trace_events(session_name: &mut Vec<u16>) {
    let mut log_file = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(session_name.as_mut_ptr()),
        ..Default::default()
    };
    log_file.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log_file.Anonymous2.EventRecordCallback = Some(trace_callback);

    let trace_handle = unsafe { OpenTraceW(&mut log_file) };
    if trace_handle.Value == u64::MAX {
        event_log(
            &format!(
                "Failed to open trace. Failed with Win32 error: {}",
                unsafe { GetLastError().0 }
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return;
    }

    //
    // This function blocks until processing ends.
    // Trace consumers call this function to process the events from one or more trace processing sessions.
    //
    let status = unsafe { ProcessTrace(&[trace_handle], None, None) };
    let _ = unsafe { CloseTrace(trace_handle) };
    if status != ERROR_SUCCESS {
        event_log(
            &format!(
                "ProcessTrace ended with status: {}",
                status.0
            ),
            EVENTLOG_INFORMATION_TYPE,
            EventID::Info,
        );
    }
}

/// A callback routine that handles trace events, allowing them to be processed as required
unsafe extern "system" fn trace_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        event_log(
            "Event was a null pointer in the tracer callback routine.",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return;
    }

    // SAFETY: Null pointer dereference checked above
    let event_header = unsafe { &(*record).EventHeader };
    let descriptor_id = event_header.EventDescriptor.Id;
    let task = event_header.EventDescriptor.Task;
    let keyword = event_header.EventDescriptor.Keyword;
    let _level = event_header.EventDescriptor.Level;
    let pid = event_header.ProcessId;

    // lookup the process image name
    let process_image = {
        match get_process_image_from_pid(pid, event_header) {
            Ok(s) => s,
            Err(_) => return,
        }
    };

    if event_header.ProviderId == ETW_TI_GUID {
        let target_pid = unsafe { extract_u32_property(record, "TargetProcessId") }
            .or_else(|| unsafe { extract_u32_property(record, "TargetProcessID") })
            .or_else(|| unsafe { extract_u32_property(record, "TargetPid") })
            .or_else(|| unsafe { extract_u32_property(record, "TargetPID") });

        send_threat_intel_to_engine(
            pid,
            &process_image,
            descriptor_id,
            task,
            keyword,
            target_pid,
        );
    }

    if event_header.ProviderId == HTTP_SERVICE_GUID {
        if descriptor_id == 1
            && let Some(url) = unsafe { extract_string_property(record, "Url") }
        {
            let method = unsafe { extract_string_property(record, "Method") }
                .unwrap_or_else(|| "GET".to_string());

            send_etw_info_ipc(Syscall {
                pid,
                source: shared_no_std::ghost_hunting::SyscallEventSource::EventSourceSyscallHook,
                data: NtFunction::NetworkActivity(NetworkActivityData::Http(HttpActivity {
                    url,
                    method,
                    user_agent: "SanctumETW".to_string(),
                })),
                caller_address: 0,
                hex_payload: [0; 16],
            });
        }
    } else if event_header.ProviderId == WININET_GUID
        && let Some(url) = unsafe { extract_string_property(record, "Url") }
    {
        send_etw_info_ipc(Syscall {
            pid,
            source: shared_no_std::ghost_hunting::SyscallEventSource::EventSourceSyscallHook,
            data: NtFunction::NetworkActivity(NetworkActivityData::WinINet(WinINetActivity {
                url,
                server: "Unknown".to_string(),
            })),
            caller_address: 0,
            hex_payload: [0; 16],
        });
    }
}

unsafe fn extract_string_property(record: *mut EVENT_RECORD, name: &str) -> Option<String> {
    let mut buffer_size: u32 = 0;

    let _ = unsafe { TdhGetEventInformation(record, None, None, &mut buffer_size) };
    if buffer_size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let info = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

    if unsafe { TdhGetEventInformation(record, None, Some(info), &mut buffer_size) } != 0 {
        return None;
    }

    let info_ref = unsafe { &*info };
    let property_count = info_ref.TopLevelPropertyCount;
    let property_array_ptr = info_ref.EventPropertyInfoArray.as_ptr();
    let property_array =
        unsafe { std::slice::from_raw_parts(property_array_ptr, property_count as usize) };

    for prop in property_array {
        let prop_name_ptr = (info as usize + prop.NameOffset as usize) as *const u16;
        let prop_name = unsafe { PWSTR(prop_name_ptr as *mut _).to_string() }.ok()?;

        if prop_name == name {
            let mut data_buffer = vec![0u8; 4096];
            let descriptor = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: (info as usize + prop.NameOffset as usize) as u64,
                ArrayIndex: u32::MAX,
                ..Default::default()
            };

            let status =
                unsafe { TdhGetProperty(record, None, &[descriptor], data_buffer.as_mut_slice()) };

            if status == 0 {
                let u16_data = unsafe {
                    std::slice::from_raw_parts(
                        data_buffer.as_ptr() as *const u16,
                        data_buffer.len() / 2,
                    )
                };
                let s = String::from_utf16_lossy(u16_data);
                let trimmed = s.split('\0').next().unwrap_or("").to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }

    None
}

unsafe fn extract_u32_property(record: *mut EVENT_RECORD, name: &str) -> Option<u32> {
    let mut buffer_size: u32 = 0;

    let _ = unsafe { TdhGetEventInformation(record, None, None, &mut buffer_size) };
    if buffer_size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let info = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

    if unsafe { TdhGetEventInformation(record, None, Some(info), &mut buffer_size) } != 0 {
        return None;
    }

    let info_ref = unsafe { &*info };
    let property_count = info_ref.TopLevelPropertyCount;
    let property_array_ptr = info_ref.EventPropertyInfoArray.as_ptr();
    let property_array =
        unsafe { std::slice::from_raw_parts(property_array_ptr, property_count as usize) };

    for prop in property_array {
        let prop_name_ptr = (info as usize + prop.NameOffset as usize) as *const u16;
        let prop_name = unsafe { PWSTR(prop_name_ptr as *mut _).to_string() }.ok()?;

        if prop_name.eq_ignore_ascii_case(name) {
            let mut data_buffer = [0u8; 8];
            let descriptor = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: (info as usize + prop.NameOffset as usize) as u64,
                ArrayIndex: u32::MAX,
                ..Default::default()
            };

            let status = unsafe { TdhGetProperty(record, None, &[descriptor], &mut data_buffer) };
            if status == 0 {
                return Some(u32::from_le_bytes([
                    data_buffer[0],
                    data_buffer[1],
                    data_buffer[2],
                    data_buffer[3],
                ]));
            }
        }
    }

    None
}

/// Get the process image as a string for a given pid
///
/// # Errors
/// This function will return an error if it cannot get a handle to the pid, or there was a string conversion error from the image buffer.
/// This function is unable to get a handle to SYSTEM processes.
fn get_process_image_from_pid(pid: u32, _event_header: &EVENT_HEADER) -> Result<String, ()> {
    if pid == 0 {
        return Ok("Idle".to_string());
    }
    if pid == 4 {
        return Ok("System".to_string());
    }

    let process_handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
    {
        Ok(h) => h,
        Err(_) => match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => {
                return Err(());
            }
        },
    };

    let mut process_img_buffer: Vec<u16> = vec![0u16; MAX_PATH as _];
    let len =
        unsafe { GetProcessImageFileNameW(process_handle, process_img_buffer.as_mut_slice()) };
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(process_handle) };

    if len == 0 {
        return Err(());
    }

    let process_image = String::from_utf16_lossy(&process_img_buffer[..len as usize]);
    Ok(process_image)
}
