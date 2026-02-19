//! This module is dedicated to tracing via ETW from a PPL security context.

use std::{ptr::copy_nonoverlapping, u64};

use crate::{
    ipc::send_etw_info_ipc,
    logging::{EventID, event_log},
};
use shared_no_std::ghost_hunting::{NtFunction, Syscall};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, GetLastError, MAX_PATH, STATUS_SUCCESS},
        System::{
            Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, CloseTrace, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER,
                EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace,
                StartTraceW, StopTraceW, TRACE_EVENT_INFO, TRACE_LEVEL_VERBOSE,
                TdhGetEventInformation,
            },
            EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_SUCCESS},
            ProcessStatus::GetProcessImageFileNameW,
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
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

//
// Functions
//

/// Public entrypoint to starting the threat intelligence trace routine.
pub fn start_threat_intel_trace() {
    register_ti_session();
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
        std::process::exit(1);
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

    let status = unsafe { StartTraceW(&mut handle, embedded_session_name, properties) };
    if status.is_err() {
        event_log(
            &format!(
                "Unable to register ETW:TI session. Failed with Win32 error: {:?}",
                status
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        std::process::exit(1);
    }

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
        std::process::exit(1);
    }

    event_log(
        "Successfully started trace for ETW:TI.",
        EVENTLOG_INFORMATION_TYPE,
        EventID::Info,
    );

    process_trace_events(&mut wide_name);

    // Stop the trace as we are completing the function.
    // If we reach here, an unrecoverable error has probably happened, so we can exit the service.
    // todo do we really want to exit the service?
    stop_trace(handle, session_name, properties);
    std::process::exit(2);
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
    let mut log_file = EVENT_TRACE_LOGFILEW::default();
    log_file.LoggerName = PWSTR(session_name.as_mut_ptr());
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
        std::process::exit(1);
    }

    //
    // This function blocks until processing ends.
    // Trace consumers call this function to process the events from one or more trace processing sessions.
    //
    let status = unsafe { ProcessTrace(&[trace_handle], None, None) };
    if status != ERROR_SUCCESS {
        event_log(
            &format!(
                "Failed to run ProcessTrace. Failed with Win32 error: {}",
                unsafe { GetLastError().0 }
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        let _ = unsafe { CloseTrace(trace_handle) };
        std::process::exit(1);
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
    let level = event_header.EventDescriptor.Level;
    let pid = event_header.ProcessId;

    // lookup the process image name
    let process_image = {
        match get_process_image_from_pid(pid, event_header) {
            Ok(s) => s,
            Err(_) => return,
        }
    };

    if process_image.to_ascii_lowercase().contains("malware")
        || process_image.to_ascii_lowercase().contains("notepad")
    {
        if keyword & KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
            == KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
        {
            event_log(
                &format!(
                    "Remote memory allocation caught for pid: {}, image: {}. Data: {:?}",
                    pid, process_image, event_header.EventDescriptor
                ),
                EVENTLOG_SUCCESS,
                EventID::ProcessOfInterestTI,
            );
            // send_etw_info_ipc(Syscall::new_etw(
            //     pid as u64,
            //     NtFunction::NtAllocateVirtualMemory(None),
            //     60,
            // ));
        }

        if keyword & KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL
            == KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL
        {
            event_log(
                &format!(
                    "Mem protect for pid: {}, image: {}. FLAGS: {:b}, Data: {:?}, keyword - bin: {:b} hex: {:X}.",
                    pid,
                    process_image,
                    unsafe { &(*record).EventHeader.Flags },
                    event_header.EventDescriptor,
                    event_header.EventDescriptor.Task,
                    event_header.EventDescriptor.Task
                ),
                EVENTLOG_SUCCESS,
                EventID::ProcessOfInterestTI,
            );
            // todo
        }

        if keyword & KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL
            == KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL
        {
            event_log(
                &format!(
                    "Write local for pid: {}, image: {}. FLAGS: {:b}, Data: {:?}, keyword - bin: {:b} hex: {:X}",
                    pid,
                    process_image,
                    unsafe { &(*record).EventHeader.Flags },
                    event_header.EventDescriptor,
                    event_header.EventDescriptor.Task,
                    event_header.EventDescriptor.Task
                ),
                EVENTLOG_SUCCESS,
                EventID::ProcessOfInterestTI,
            );
            // send_etw_info_ipc(Syscall::new_etw(
            //     pid as u64,
            //     NtFunction::NtWriteVirtualMemory(None),
            //     60,
            // ));
        }

        if keyword & KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE
            == KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE
        {
            // send_etw_info_ipc(Syscall::new_etw(
            //     pid as u64,
            //     NtFunction::NtWriteVirtualMemory(None),
            //     60,
            // ));
            event_log(
                &format!(
                    "Write remote memory for pid: {}, image: {}, FLAGS: {:b}, Data: {:?}, keyword - bin: {:b} hex: {:X}",
                    pid,
                    process_image,
                    unsafe { &(*record).EventHeader.Flags },
                    event_header.EventDescriptor,
                    event_header.EventDescriptor.Task,
                    event_header.EventDescriptor.Task
                ),
                EVENTLOG_SUCCESS,
                EventID::ProcessOfInterestTI,
            );
        }

        if keyword & KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS
            == KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS
        {
            event_log(
                &format!(
                    "Suspend process for pid: {}, image: {}, FLAGS: {:b}, Data: {:?}, keyword - bin: {:b} hex: {:X}",
                    pid,
                    process_image,
                    unsafe { &(*record).EventHeader.Flags },
                    event_header.EventDescriptor,
                    event_header.EventDescriptor.Task,
                    event_header.EventDescriptor.Task
                ),
                EVENTLOG_SUCCESS,
                EventID::ProcessOfInterestTI,
            );
        }
    }
}

/// Get the process image as a string for a given pid
///
/// # Errors
/// This function will return an error if it cannot get a handle to the pid, or there was a string conversion error from the image buffer.
/// This function is unable to get a handle to SYSTEM processes.
fn get_process_image_from_pid(pid: u32, event_header: &EVENT_HEADER) -> Result<String, ()> {
    let process_handle = match unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) } {
        Ok(h) => h,
        Err(e) => {
            event_log(
                &format!(
                    "Failed to open process for pid: {pid} from event information: {:?}. Error: {e}",
                    event_header.EventDescriptor
                ),
                EVENTLOG_ERROR_TYPE,
                EventID::GeneralError,
            );
            return Err(());
        }
    };

    let mut process_img_buffer: Vec<u16> = vec![0u16; MAX_PATH as _];
    let len =
        unsafe { GetProcessImageFileNameW(process_handle, process_img_buffer.as_mut_slice()) };
    if len == 0 {
        event_log(
            &format!(
                "Failed to get process image for pid: {pid} from event information: {:?}. Win32 Error: {}",
                event_header.EventDescriptor,
                unsafe { GetLastError().0 }
            ),
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );
        return Err(());
    }

    let process_image: String = match String::from_utf16(&process_img_buffer) {
        Ok(mut s) => {
            s.truncate(len as _);
            s
        }
        Err(e) => {
            event_log(
                &format!(
                    "Failed to convert image name to string for process: {pid} from event information: {:?}. Error: {e}",
                    event_header.EventDescriptor
                ),
                EVENTLOG_ERROR_TYPE,
                EventID::GeneralError,
            );
            return Err(());
        }
    };

    Ok(process_image)
}
