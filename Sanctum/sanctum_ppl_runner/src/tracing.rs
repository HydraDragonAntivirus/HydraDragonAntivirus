//! This module is dedicated to tracing via ETW from a PPL security context.

use std::collections::HashMap;
use std::ptr::copy_nonoverlapping;

use crate::{
    ipc::{send_etw_info_ipc, send_telemetry_json_ipc},
    logging::{EventID, event_log},
};
use serde_json::{Map, Value, json};
use shared_no_std::ghost_hunting::{
    EtwThreatIntelligenceData, HttpActivity, NetworkActivityData, NtFunction, Syscall,
    SyscallEventSource, WinINetActivity,
};
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GetLastError, MAX_PATH},
        System::{
            Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, CloseTrace, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER,
                EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_MAP_INFO,
                EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
                PROPERTY_DATA_DESCRIPTOR, ProcessTrace, PropertyParamCount, PropertyParamLength,
                PropertyStruct, StartTraceW, StopTraceW, TRACE_EVENT_INFO, TRACE_LEVEL_INFORMATION,
                TRACE_LEVEL_VERBOSE, TdhFormatProperty, TdhGetEventInformation,
                TdhGetEventMapInformation, TdhGetProperty, WNODE_FLAG_TRACED_GUID,
            },
            EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE},
            ProcessStatus::GetProcessImageFileNameW,
            Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
    core::{GUID, PCWSTR, PWSTR},
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

/// Windows telemetry ETW provider GUIDs consolidated into Sanctum's PPL ETW session.
const GUID_POWERSHELL: GUID = GUID::from_u128(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a);
const GUID_WMI_ACTIVITY: GUID = GUID::from_u128(0x1418ef04_b0b4_4623_bf7e_d74ab47bbdaa);
const GUID_TASK_SCHEDULER: GUID = GUID::from_u128(0xde7b24ea_73c8_4a09_985d_5bdadcfa9017);
const GUID_BITS_CLIENT: GUID = GUID::from_u128(0xef1cc15b_46c1_414e_bb95_e76b077bd51e);
const GUID_VHDMP: GUID = GUID::from_u128(0xe2817345_a999_4659_950e_428190f72360);
const GUID_GROUP_POLICY: GUID = GUID::from_u128(0xaea1b4fa_97d1_45f2_a64c_4d69fffd92c9);
const GUID_WINLOGON: GUID = GUID::from_u128(0xdbe9b383_7cf3_4331_91cc_a3cb16a3b538);
const GUID_DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
const GUID_VOLSNAP: GUID = GUID::from_u128(0x8b7d558f_b13d_4700_93b3_2d2234ac634c);

const WINDOWS_TELEMETRY_PROVIDERS: &[(GUID, &str)] = &[
    (GUID_POWERSHELL, "PowerShell"),
    (GUID_WMI_ACTIVITY, "WMI-Activity"),
    (GUID_TASK_SCHEDULER, "TaskScheduler"),
    (GUID_BITS_CLIENT, "Bits-Client"),
    (GUID_VHDMP, "VHDMP"),
    (GUID_GROUP_POLICY, "GroupPolicy"),
    (GUID_WINLOGON, "Winlogon"),
    (GUID_DNS_CLIENT, "DNS-Client"),
    (GUID_VOLSNAP, "VolSnap"),
];

fn is_windows_telemetry_provider(provider: GUID) -> bool {
    WINDOWS_TELEMETRY_PROVIDERS
        .iter()
        .any(|(guid, _)| *guid == provider)
}

unsafe fn utf16_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 4096 && unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

unsafe fn decode_etw_properties(event: &EVENT_RECORD) -> Map<String, Value> {
    let mut props_map = Map::new();
    if event.UserData.is_null() || event.UserDataLength == 0 {
        return props_map;
    }
    let mut info_len = 4096u32;
    let mut info_buf = vec![0u8; info_len as usize];
    let mut status = unsafe {
        TdhGetEventInformation(
            event,
            None,
            Some(info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO),
            &mut info_len,
        )
    };
    if status == ERROR_INSUFFICIENT_BUFFER.0 && info_len <= 512 * 1024 {
        info_buf.resize(info_len as usize, 0);
        status = unsafe {
            TdhGetEventInformation(
                event,
                None,
                Some(info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO),
                &mut info_len,
            )
        };
    }
    if status != ERROR_SUCCESS.0 || info_len < size_of::<TRACE_EVENT_INFO>() as u32 {
        return props_map;
    }

    let info = unsafe { &*(info_buf.as_ptr() as *const TRACE_EVENT_INFO) };
    let prop_count = (info.TopLevelPropertyCount as usize).min(128);
    let props_arr = info.EventPropertyInfoArray.as_ptr();
    let ptr_size = if (event.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER as u16) != 0 {
        8
    } else if (event.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16) != 0 {
        4
    } else {
        size_of::<usize>() as u32
    };

    let userdata = unsafe {
        std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize)
    };
    let mut offset = 0usize;
    let mut numeric_vals: HashMap<u16, u32> = HashMap::new();

    for idx in 0..prop_count {
        if offset >= userdata.len() {
            break;
        }
        let prop: &EVENT_PROPERTY_INFO = unsafe { &*props_arr.add(idx) };
        if (prop.Flags.0 & PropertyStruct.0) != 0 {
            break;
        }
        let name_off = prop.NameOffset as usize;
        let prop_name = if name_off > 0 && name_off + 2 <= info_buf.len() {
            unsafe { utf16_ptr_to_string(info_buf.as_ptr().add(name_off) as *const u16) }
        } else {
            format!("prop_{idx}")
        };

        let array_len = if (prop.Flags.0 & PropertyParamCount.0) != 0 {
            let c_idx = unsafe { prop.Anonymous2.countPropertyIndex };
            numeric_vals.get(&c_idx).copied().unwrap_or(1)
        } else {
            (unsafe { prop.Anonymous2.count } as u32).max(1)
        };
        let prop_len = if (prop.Flags.0 & PropertyParamLength.0) != 0 {
            let l_idx = unsafe { prop.Anonymous3.lengthPropertyIndex };
            numeric_vals
                .get(&l_idx)
                .copied()
                .unwrap_or(0)
                .min(u16::MAX as u32) as u16
        } else {
            unsafe { prop.Anonymous3.length }
        };

        let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
        let out_type = unsafe { prop.Anonymous1.nonStructType.OutType };
        let map_name_off = unsafe { prop.Anonymous1.nonStructType.MapNameOffset } as usize;

        let mut map_buf: Option<Vec<u8>> = None;
        if map_name_off > 0 && map_name_off + 2 <= info_buf.len() {
            let map_ptr = unsafe { info_buf.as_ptr().add(map_name_off) as *const u16 };
            let mut msize = 0u32;
            let ms = unsafe { TdhGetEventMapInformation(event, PCWSTR(map_ptr), None, &mut msize) };
            if ms == ERROR_INSUFFICIENT_BUFFER.0 && msize > 0 && msize <= 64 * 1024 {
                let mut mb = vec![0u8; msize as usize];
                if unsafe {
                    TdhGetEventMapInformation(
                        event,
                        PCWSTR(map_ptr),
                        Some(mb.as_mut_ptr() as *mut EVENT_MAP_INFO),
                        &mut msize,
                    )
                } == ERROR_SUCCESS.0
                {
                    map_buf = Some(mb);
                }
            }
        }

        let mut formatted_items = Vec::new();
        for _ in 0..array_len.min(16) {
            if offset >= userdata.len() {
                break;
            }
            let mut out_buf = vec![0u16; 1024];
            let mut out_bytes = (out_buf.len() * 2) as u32;
            let mut consumed: u16 = 0;
            let map_ptr = map_buf
                .as_ref()
                .map(|b| b.as_ptr() as *const EVENT_MAP_INFO);
            let mut fstat = unsafe {
                TdhFormatProperty(
                    info,
                    map_ptr,
                    ptr_size,
                    in_type,
                    out_type,
                    prop_len,
                    &userdata[offset..],
                    &mut out_bytes,
                    Some(PWSTR(out_buf.as_mut_ptr())),
                    &mut consumed,
                )
            };
            if fstat == ERROR_INSUFFICIENT_BUFFER.0 && out_bytes > 0 && out_bytes <= 256 * 1024 {
                out_buf.resize((out_bytes as usize + 3) / 2, 0);
                out_bytes = (out_buf.len() * 2) as u32;
                fstat = unsafe {
                    TdhFormatProperty(
                        info,
                        map_ptr,
                        ptr_size,
                        in_type,
                        out_type,
                        prop_len,
                        &userdata[offset..],
                        &mut out_bytes,
                        Some(PWSTR(out_buf.as_mut_ptr())),
                        &mut consumed,
                    )
                };
            }
            if fstat != ERROR_SUCCESS.0 {
                break;
            }
            if consumed == 2 && offset + 2 <= userdata.len() {
                numeric_vals.insert(
                    idx as u16,
                    u16::from_le_bytes([userdata[offset], userdata[offset + 1]]) as u32,
                );
            } else if consumed == 4 && offset + 4 <= userdata.len() {
                numeric_vals.insert(
                    idx as u16,
                    u32::from_le_bytes([
                        userdata[offset],
                        userdata[offset + 1],
                        userdata[offset + 2],
                        userdata[offset + 3],
                    ]),
                );
            }
            offset += consumed as usize;
            let txt = unsafe { utf16_ptr_to_string(out_buf.as_ptr()) }
                .trim()
                .to_string();
            if !txt.is_empty() {
                formatted_items.push(txt);
            }
        }

        if !prop_name.is_empty() && !formatted_items.is_empty() {
            let val = if formatted_items.len() == 1 {
                formatted_items.into_iter().next().unwrap_or_default()
            } else {
                formatted_items.join(", ")
            };
            props_map.insert(prop_name, Value::String(val));
        }
    }
    props_map
}

fn classify_windows_etw_event(
    provider: GUID,
    event_id: u16,
    fields: &Map<String, Value>,
) -> Option<&'static str> {
    if provider == GUID_POWERSHELL {
        return (event_id == 4104).then_some("SCRIPT_BLOCK_ACTIVITY");
    }
    if provider == GUID_WMI_ACTIVITY {
        return match event_id {
            5859 => Some("WMI_EVENT_FILTER"),
            5860 => Some("WMI_EVENT_CONSUMER"),
            5861 => Some("WMI_EVENT_CONSUMER_TO_FILTER"),
            5858 => {
                let op = fields
                    .get("Operation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if op.contains("__filtertoconsumerbinding") {
                    Some("WMI_EVENT_CONSUMER_TO_FILTER")
                } else if op.contains("__eventfilter") {
                    Some("WMI_EVENT_FILTER")
                } else if op.contains("eventconsumer") {
                    Some("WMI_EVENT_CONSUMER")
                } else {
                    None
                }
            }
            _ => None,
        };
    }
    if provider == GUID_TASK_SCHEDULER {
        return match event_id {
            106 => Some("SCHEDULED_TASK_CREATE"),
            140 => Some("SCHEDULED_TASK_MODIFY"),
            141 => Some("SCHEDULED_TASK_DELETE"),
            _ => None,
        };
    }
    if provider == GUID_BITS_CLIENT {
        return matches!(event_id, 3 | 4 | 59 | 60).then_some("BITS_JOB_ACTIVITY");
    }
    if provider == GUID_VHDMP {
        return matches!(event_id, 1 | 2 | 12 | 22 | 23).then_some("VIRTUAL_DISK_MOUNT");
    }
    if provider == GUID_GROUP_POLICY {
        return matches!(event_id, 4000 | 4001 | 4016 | 5016 | 5017 | 8000 | 8001)
            .then_some("GROUP_POLICY_MODIFY");
    }
    if provider == GUID_WINLOGON {
        return match event_id {
            1 | 7001 => Some("ACCOUNT_LOGIN"),
            2 | 7002 => Some("ACCOUNT_LOGOFF"),
            _ => None,
        };
    }
    if provider == GUID_DNS_CLIENT {
        let has_q = fields
            .get("QueryName")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty());
        return (matches!(event_id, 3006 | 3008 | 3010 | 3020) && has_q).then_some("DNS_QUERY");
    }
    if provider == GUID_VOLSNAP {
        return matches!(event_id, 25 | 33 | 36).then_some("VSS_SHADOW_COPY_DELETED");
    }
    None
}

fn handle_windows_telemetry_etw_event(
    record: *mut EVENT_RECORD,
    event_header: &EVENT_HEADER,
    pid: u32,
    process_image: &str,
) {
    let ev = unsafe { &*record };
    let event_id = event_header.EventDescriptor.Id;
    let provider = event_header.ProviderId;
    let fields = unsafe { decode_etw_properties(ev) };
    let Some(out_type) = classify_windows_etw_event(provider, event_id, &fields) else {
        return;
    };

    let mut details = format!("etw_event_id={event_id}");
    for key in [
        "QueryName",
        "TaskName",
        "Name",
        "NamespaceName",
        "Path",
        "jobTitle",
        "VhdFileName",
        "VolumeName",
    ] {
        if let Some(v) = fields.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                details = format!("{key}={v}");
                break;
            }
        }
    }

    let mut body = fields;
    body.insert("sanctumEventType".to_string(), json!(out_type));
    body.insert("type".to_string(), json!(out_type));
    body.insert("pid".to_string(), json!(pid));
    body.insert("details".to_string(), json!(details));
    body.insert("etw_event_id".to_string(), json!(event_id));
    body.insert("source".to_string(), json!("sanctum_ppl_etw"));
    body.insert(
        "process".to_string(),
        json!({
            "pid": pid,
            "imageFile": {
                "rawPath": process_image,
                "abstractPath": process_image,
            }
        }),
    );

    if let Ok(line) = serde_json::to_string(&Value::Object(body)) {
        send_telemetry_json_ipc(line);
    }
}

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
        (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*properties).Wnode.ClientContext = 1;
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*properties).BufferSize = 64;
        (*properties).MinimumBuffers = 8;
        (*properties).MaximumBuffers = 64;
        (*properties).FlushTimer = 1;
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

    for (guid, name) in WINDOWS_TELEMETRY_PROVIDERS {
        let rc = unsafe {
            EnableTraceEx2(
                handle,
                guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as _,
                u64::MAX,
                0,
                0,
                None,
            )
        };
        if rc.is_err() {
            event_log(
                &format!("EnableTraceEx2({name}) returned Win32 error: {:?}", rc),
                EVENTLOG_INFORMATION_TYPE,
                EventID::Info,
            );
        }
    }

    event_log(
        "Successfully started trace for ETW:TI and consolidated Windows telemetry providers.",
        EVENTLOG_INFORMATION_TYPE,
        EventID::Info,
    );

    process_trace_events(&mut wide_name);

    // If we reach here, process_trace_events has unblocked
    if crate::is_service_stopping() {
        stop_trace(handle, session_name, properties);
    } else {
        event_log(
            "CRITICAL SECURITY ALERT: ETW:TI trace was interrupted externally (blinding attempt). Watchdog will auto-revive the session.",
            EVENTLOG_ERROR_TYPE,
            EventID::GeneralError,
        );

        // Notify GUI about the blinding attempt without attributing it to a specific PID.
        // Attributing to RECENT_PIDS would cause false positives (e.g., edrsvc.exe self-accusation).
        // The watchdog loop in start_threat_intel_trace will restart the session automatically.
        crate::ipc::report_etw_blinding_attempt();

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
            &format!("ProcessTrace ended with status: {}", status.0),
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

    // lookup the process image name (do not drop exited/short-lived process events)
    let process_image = get_process_image_from_pid(pid, event_header).unwrap_or_default();

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
        return;
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
    } else if event_header.ProviderId == WININET_GUID {
        if let Some(url) = unsafe { extract_string_property(record, "Url") } {
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
    } else if is_windows_telemetry_provider(event_header.ProviderId) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_windows_telemetry_etw_event(record, event_header, pid, &process_image);
        }));
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
