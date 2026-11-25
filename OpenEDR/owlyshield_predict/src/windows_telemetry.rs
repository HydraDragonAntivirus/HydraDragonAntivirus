//! Real-time native Windows telemetry collectors for complete EDR visibility:
//! - ETW consumer (PowerShell 4104, WMI-Activity, TaskScheduler, BITS, VHDMP, GroupPolicy, Winlogon, DNS-Client, VolSnap)
//! - Push-based EventLog subscriptions (Security/System/Operational channels via wevtapi EvtSubscribe, no .evtx polling)
//! - Native PnP interface notifications (cfgmgr32 CM_Register_Notification for USB & Virtual Disk mount/unmount)
//! - Live kernel driver snapshot diffing (EnumDeviceDrivers -> DRIVER_LOADED / DRIVER_UNLOADED)
//! - Native WMI permanent subscription + Shadow Copy diffing (ROOT\subscription + Win32_ShadowCopy)
//! - Local account (NetUserEnum) & LSA logon session diffing + PE-header Process Tampering verifier.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::OnceLock;

static STARTED: AtomicBool = AtomicBool::new(false);
static STOP_FLAG: AtomicBool = AtomicBool::new(false);

const TAMPER_QUEUE_CAPACITY: usize = 2048;
static TAMPER_TX: OnceLock<SyncSender<(u32, String)>> = OnceLock::new();

pub fn enqueue_tampering_check(pid: u32, image_path: String) {
    if pid <= 4 || image_path.is_empty() || STOP_FLAG.load(Ordering::Relaxed) {
        return;
    }
    if let Some(tx) = TAMPER_TX.get() {
        let _ = tx.try_send((pid, image_path));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEventXml {
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

fn extract_tag_text(xml: &str, open_prefix: &str, close_tag: &str) -> Option<String> {
    let start_pos = xml.find(open_prefix)?;
    let rest = &xml[start_pos + open_prefix.len()..];
    let gt = rest.find('>')?;
    let inner_start = &rest[gt + 1..];
    let end = inner_start.find(close_tag)?;
    Some(inner_start[..end].trim().to_string())
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let needle_dq = format!("{attr}=\"");
    if let Some(pos) = tag.find(&needle_dq) {
        let rest = &tag[pos + needle_dq.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    let needle_sq = format!("{attr}='");
    if let Some(pos) = tag.find(&needle_sq) {
        let rest = &tag[pos + needle_sq.len()..];
        if let Some(end) = rest.find('\'') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn unescape_xml_basic(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Parses key fields from a Windows EventLog XML string rendered by `EvtRender`.
pub fn parse_event_xml_summary(xml: &str) -> Option<ParsedEventXml> {
    let event_id = extract_tag_text(xml, "<EventID", "</EventID>")?
        .parse::<u32>()
        .ok()?;
    let provider = if let Some(p_start) = xml.find("<Provider ") {
        let rest = &xml[p_start..];
        let gt = rest.find('>')?;
        extract_attr(&rest[..gt], "Name").unwrap_or_default()
    } else {
        String::new()
    };
    let channel = extract_tag_text(xml, "<Channel", "</Channel>").unwrap_or_default();

    let mut fields = serde_json::Map::new();
    let mut scan = xml;
    let mut anon_idx = 0usize;
    while let Some(d_pos) = scan.find("<Data") {
        let after = &scan[d_pos + 5..];
        let Some(gt) = after.find('>') else {
            break;
        };
        let attrs = &after[..gt];
        if attrs.ends_with('/') {
            scan = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(end) = body.find("</Data>") else {
            break;
        };
        let val = unescape_xml_basic(body[..end].trim());
        let key = extract_attr(attrs, "Name").unwrap_or_else(|| {
            anon_idx += 1;
            format!("arg_{anon_idx}")
        });
        if !val.is_empty() && val != "-" {
            fields.insert(key, serde_json::Value::String(val));
        }
        scan = &body[end + 7..];
    }

    Some(ParsedEventXml {
        event_id,
        provider,
        channel,
        fields,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeTamperingFinding {
    pub technique: String,
    pub reason: String,
}

#[inline]
fn le_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

struct CompactPeHeader {
    machine: u16,
    sections: u16,
    timestamp: u32,
    entry_point: u32,
    size_of_image: u32,
}

fn parse_compact_pe_header(bytes: &[u8]) -> Option<CompactPeHeader> {
    if bytes.len() < 64 || le_u16(bytes, 0)? != 0x5a4d {
        return None;
    }
    let e_lfanew = le_u32(bytes, 0x3c)? as usize;
    if e_lfanew.checked_add(88)? > bytes.len() {
        return None;
    }
    if le_u32(bytes, e_lfanew)? != 0x0000_4550 {
        return None;
    }
    let coff = e_lfanew + 4;
    let opt = coff + 20;
    Some(CompactPeHeader {
        machine: le_u16(bytes, coff)?,
        sections: le_u16(bytes, coff + 2)?,
        timestamp: le_u32(bytes, coff + 4)?,
        entry_point: le_u32(bytes, opt + 16)?,
        size_of_image: le_u32(bytes, opt + 56)?,
    })
}

/// Compares on-disk PE headers against live process-memory PE headers to detect
/// Process Hollowing, Process Herpaderping, and Process Doppelganging.
pub fn compare_pe_headers(disk_bytes: &[u8], mem_bytes: &[u8]) -> Option<PeTamperingFinding> {
    let Some(mem) = parse_compact_pe_header(mem_bytes) else {
        return Some(PeTamperingFinding {
            technique: "pe_header_corrupt_in_memory".to_string(),
            reason: "In-memory image header is missing valid MZ/PE signature".to_string(),
        });
    };
    let Some(disk) = parse_compact_pe_header(disk_bytes) else {
        return Some(PeTamperingFinding {
            technique: "pe_header_missing_on_disk".to_string(),
            reason: "Backing file on disk lacks valid MZ/PE signature while memory holds PE".to_string(),
        });
    };

    let mut diffs = Vec::new();
    if mem.machine != disk.machine {
        diffs.push(format!("machine:disk={:#x},mem={:#x}", disk.machine, mem.machine));
    }
    if mem.entry_point != disk.entry_point {
        diffs.push(format!(
            "entry_point:disk={:#x},mem={:#x}",
            disk.entry_point, mem.entry_point
        ));
    }
    if mem.size_of_image != disk.size_of_image {
        diffs.push(format!(
            "size_of_image:disk={:#x},mem={:#x}",
            disk.size_of_image, mem.size_of_image
        ));
    }
    if mem.sections != disk.sections {
        diffs.push(format!("sections:disk={},mem={}", disk.sections, mem.sections));
    }
    if mem.timestamp != disk.timestamp {
        diffs.push(format!(
            "timestamp:disk={:#x},mem={:#x}",
            disk.timestamp, mem.timestamp
        ));
    }
    if diffs.is_empty() {
        return None;
    }

    Some(PeTamperingFinding {
        technique: "pe_header_mismatch_hollowing_or_herpaderping".to_string(),
        reason: diffs.join("; "),
    })
}

#[cfg(target_os = "windows")]
mod win_impl {
    use super::*;
    use crate::logging::Logging;
    use moka::sync::Cache;
    use serde_json::{Map, Value, json};
    use std::collections::{HashMap, HashSet};
    use std::ffi::c_void;
    use std::io::Read;
    use std::mem::{ManuallyDrop, size_of};
    use std::ptr::{null, null_mut};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::thread;
    use std::time::Duration;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
        HANDLE, HMODULE, MAX_PATH, RPC_E_CHANGED_MODE, RPC_E_TOO_LATE,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        VARIANT, VT_BSTR,
    };
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_MAP_INFO,
        EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
        PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        ProcessTrace, PropertyParamCount, PropertyParamLength, PropertyStruct, StartTraceW,
        TRACE_EVENT_INFO, TdhFormatProperty, TdhGetEventInformation, TdhGetEventMapInformation,
        WNODE_FLAG_TRACED_GUID,
    };
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtRender, EvtRenderEventXml,
        EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
    use windows::Win32::System::Ole::VariantClear;
    use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        QueryFullProcessImageNameW,
    };
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, GUID, PCSTR, PCWSTR, PWSTR};

    const ETW_SESSION_NAME: &str = "OpenEDR-Telemetry-ETW";

    static ETW_TRACE_HANDLE: AtomicU64 = AtomicU64::new(0);
    static ETW_PROC_HANDLE: AtomicU64 = AtomicU64::new(0);
    static EVT_SUB_HANDLES: OnceLock<Mutex<Vec<isize>>> = OnceLock::new();
    static PNP_REG_HANDLES: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

    const GUID_POWERSHELL: GUID = GUID::from_u128(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a);
    const GUID_WMI_ACTIVITY: GUID = GUID::from_u128(0x1418ef04_b0b4_4623_bf7e_d74ab47bbdaa);
    const GUID_TASK_SCHEDULER: GUID = GUID::from_u128(0xde7b24ea_73c8_4a09_985d_5bdadcfa9017);
    const GUID_BITS_CLIENT: GUID = GUID::from_u128(0xef1cc15b_46c1_414e_bb95_e76b077bd51e);
    const GUID_VHDMP: GUID = GUID::from_u128(0xe2817345_a999_4659_950e_428190f72360);
    const GUID_GROUP_POLICY: GUID = GUID::from_u128(0xaea1b4fa_97d1_45f2_a64c_4d69fffd92c9);
    const GUID_WINLOGON: GUID = GUID::from_u128(0xdbe9b383_7cf3_4331_91cc_a3cb16a3b538);
    const GUID_DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
    const GUID_VOLSNAP: GUID = GUID::from_u128(0x8b7d558f_b13d_4700_93b3_2d2234ac634c);

    fn to_wide_z(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
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

    fn pid_exe_cache() -> &'static Cache<u32, String> {
        static CACHE: OnceLock<Cache<u32, String>> = OnceLock::new();
        CACHE.get_or_init(|| {
            Cache::builder()
                .max_capacity(4096)
                .time_to_live(Duration::from_secs(120))
                .build()
        })
    }

    fn query_pid_image(pid: u32) -> String {
        if pid <= 4 {
            return if pid == 4 { "System".to_string() } else { String::new() };
        }
        if let Some(cached) = pid_exe_cache().get(&pid) {
            return cached;
        }
        let path = unsafe {
            let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                return String::new();
            };
            let mut buf = [0u16; MAX_PATH as usize * 2];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            );
            let _ = CloseHandle(h);
            if ok.as_bool() && len > 0 {
                String::from_utf16_lossy(&buf[..len as usize])
            } else {
                String::new()
            }
        };
        if !path.is_empty() {
            pid_exe_cache().insert(pid, path.clone());
        }
        path
    }

    pub fn start() {
        let (tx, rx) = mpsc::sync_channel::<(u32, String)>(TAMPER_QUEUE_CAPACITY);
        let _ = TAMPER_TX.set(tx);
        let _ = EVT_SUB_HANDLES.get_or_init(|| Mutex::new(Vec::new()));
        let _ = PNP_REG_HANDLES.get_or_init(|| Mutex::new(Vec::new()));

        spawn_worker("edr-etw-telemetry", etw_collector_loop);
        spawn_worker("edr-evtlog-push", eventlog_push_setup);
        spawn_worker("edr-pnp-watcher", pnp_device_watcher_loop);
        spawn_worker("edr-driver-diff", driver_diff_loop);
        spawn_worker("edr-wmi-vss-diff", wmi_and_vss_watcher_loop);
        spawn_worker("edr-account-lsa-diff", account_and_session_diff_loop);
        let _ = thread::Builder::new()
            .name("edr-proc-tampering".into())
            .spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    process_tampering_loop(rx);
                }));
            });
    }

    pub fn stop() {
        let session_w = to_wide_z(ETW_SESSION_NAME);
        let mut props_buf = vec![0u8; size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*props).Wnode.BufferSize = props_buf.len() as u32;
            (*props).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            let th = ETW_TRACE_HANDLE.swap(0, Ordering::SeqCst);
            if th != 0 {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE(th),
                    PCWSTR(session_w.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            } else {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE(0),
                    PCWSTR(session_w.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            let ph = ETW_PROC_HANDLE.swap(0, Ordering::SeqCst);
            if ph != 0 && ph != u64::MAX {
                let _ = CloseTrace(PROCESSTRACE_HANDLE(ph));
            }
        }

        if let Some(mtx) = EVT_SUB_HANDLES.get() {
            if let Ok(mut list) = mtx.lock() {
                for h in list.drain(..) {
                    if h != 0 {
                        unsafe {
                            let _ = EvtClose(EVT_HANDLE(h));
                        }
                    }
                }
            }
        }

        if let Some(mtx) = PNP_REG_HANDLES.get() {
            if let Ok(mut list) = mtx.lock() {
                unregister_pnp_handles(&mut list);
            }
        }
    }

    fn spawn_worker(name: &str, func: fn()) {
        let _ = thread::Builder::new().name(name.into()).spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(func));
        });
    }

    // ------------------------------------------------------------------------
    // 1. Real-Time ETW Consumer + TDH Decoder
    // ------------------------------------------------------------------------

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
                numeric_vals.get(&l_idx).copied().unwrap_or(0).min(u16::MAX as u32) as u16
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
                        PWSTR(out_buf.as_mut_ptr()),
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
                            PWSTR(out_buf.as_mut_ptr()),
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

    fn classify_etw_event(
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
            return (matches!(event_id, 3006 | 3008 | 3010 | 3020) && has_q)
                .then_some("DNS_QUERY");
        }
        if provider == GUID_VOLSNAP {
            return matches!(event_id, 25 | 33 | 36).then_some("VSS_SHADOW_COPY_DELETED");
        }
        None
    }

    unsafe extern "system" fn etw_event_record_callback(event_ptr: *mut EVENT_RECORD) {
        if event_ptr.is_null() || STOP_FLAG.load(Ordering::Relaxed) {
            return;
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            let ev = &*event_ptr;
            let pid = ev.EventHeader.ProcessId;
            let event_id = ev.EventHeader.EventDescriptor.Id;
            let provider = ev.EventHeader.ProviderId;
            let fields = decode_etw_properties(ev);
            let Some(out_type) = classify_etw_event(provider, event_id, &fields) else {
                return;
            };
            let exe = query_pid_image(pid);
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
            body.insert("etw_event_id".to_string(), json!(event_id));
            body.insert("source".to_string(), json!("etw_realtime"));
            crate::telemetry_stream::submit_structured(
                out_type,
                (pid > 0 && pid != u32::MAX).then_some(pid),
                (!exe.is_empty()).then_some(exe),
                Some(details),
                Value::Object(body),
            );
        }));
    }

    fn enable_etw_provider(trace_handle: CONTROLTRACE_HANDLE, guid: GUID, name: &str) {
        let rc = unsafe {
            EnableTraceEx2(
                trace_handle,
                &guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                4, // TRACE_LEVEL_INFORMATION
                u64::MAX,
                0,
                0,
                None,
            )
        };
        if rc.0 != ERROR_SUCCESS.0 {
            Logging::warning(&format!(
                "[WindowsTelemetry] ETW EnableTraceEx2({name}) returned win32={}",
                rc.0
            ));
        }
    }

    fn etw_collector_loop() {
        let session_w = to_wide_z(ETW_SESSION_NAME);
        let mut props_buf = vec![0u8; size_of::<EVENT_TRACE_PROPERTIES>() + 1024];
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        let init_props = |p: *mut EVENT_TRACE_PROPERTIES, len: usize| unsafe {
            std::ptr::write_bytes(p as *mut u8, 0, len);
            (*p).Wnode.BufferSize = len as u32;
            (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*p).Wnode.ClientContext = 1;
            (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*p).BufferSize = 64;
            (*p).MinimumBuffers = 8;
            (*p).MaximumBuffers = 64;
            (*p).FlushTimer = 1;
            (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        };

        init_props(props, props_buf.len());
        let _ = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE(0),
                PCWSTR(session_w.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        init_props(props, props_buf.len());
        let mut trace_handle = CONTROLTRACE_HANDLE(0);
        let mut rc = unsafe { StartTraceW(&mut trace_handle, PCWSTR(session_w.as_ptr()), props) };
        if rc.0 == ERROR_ALREADY_EXISTS.0 {
            init_props(props, props_buf.len());
            let _ = unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE(0),
                    PCWSTR(session_w.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            init_props(props, props_buf.len());
            rc = unsafe { StartTraceW(&mut trace_handle, PCWSTR(session_w.as_ptr()), props) };
        }
        if rc.0 != ERROR_SUCCESS.0 {
            Logging::warning(&format!(
                "[WindowsTelemetry] ETW StartTraceW failed with win32={} (EvtSubscribe push remains active)",
                rc.0
            ));
            return;
        }
        ETW_TRACE_HANDLE.store(trace_handle.0, Ordering::SeqCst);

        enable_etw_provider(trace_handle, GUID_POWERSHELL, "PowerShell");
        enable_etw_provider(trace_handle, GUID_WMI_ACTIVITY, "WMI-Activity");
        enable_etw_provider(trace_handle, GUID_TASK_SCHEDULER, "TaskScheduler");
        enable_etw_provider(trace_handle, GUID_BITS_CLIENT, "Bits-Client");
        enable_etw_provider(trace_handle, GUID_VHDMP, "VHDMP");
        enable_etw_provider(trace_handle, GUID_GROUP_POLICY, "GroupPolicy");
        enable_etw_provider(trace_handle, GUID_WINLOGON, "Winlogon");
        enable_etw_provider(trace_handle, GUID_DNS_CLIENT, "DNS-Client");
        enable_etw_provider(trace_handle, GUID_VOLSNAP, "VolSnap");

        let mut logger_w = session_w;
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = PWSTR(logger_w.as_mut_ptr());
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_record_callback);

        let proc_handle = unsafe { OpenTraceW(&mut logfile) };
        if proc_handle.0 == u64::MAX {
            Logging::warning("[WindowsTelemetry] ETW OpenTraceW failed");
            return;
        }
        ETW_PROC_HANDLE.store(proc_handle.0, Ordering::SeqCst);
        let _ = unsafe { ProcessTrace(&[proc_handle], None, None) };
    }

    // ------------------------------------------------------------------------
    // 2. Real-Time Push EventLog Subscriptions (EvtSubscribe)
    // ------------------------------------------------------------------------

    fn map_eventlog_to_telemetry(parsed: &ParsedEventXml) -> Option<&'static str> {
        let prov_lower = parsed.provider.to_ascii_lowercase();
        let chan_lower = parsed.channel.to_ascii_lowercase();
        if chan_lower == "security" {
            return match parsed.event_id {
                4720 => Some("LOCAL_ACCOUNT_CREATE"),
                4722 | 4724 | 4725 | 4732 | 4733 | 4738 => Some("LOCAL_ACCOUNT_MODIFY"),
                4726 => Some("LOCAL_ACCOUNT_DELETE"),
                4624 => Some("ACCOUNT_LOGIN"),
                4634 | 4647 => Some("ACCOUNT_LOGOFF"),
                4697 => Some("SERVICE_CREATE"),
                4698 => Some("SCHEDULED_TASK_CREATE"),
                4702 => Some("SCHEDULED_TASK_MODIFY"),
                4699 => Some("SCHEDULED_TASK_DELETE"),
                _ => None,
            };
        }
        if chan_lower == "system" {
            if prov_lower.contains("volsnap") && matches!(parsed.event_id, 25 | 33 | 36) {
                return Some("VSS_SHADOW_COPY_DELETED");
            }
            return match parsed.event_id {
                7045 => Some("SERVICE_CREATE"),
                7040 => Some("SERVICE_MODIFY"),
                _ => None,
            };
        }
        if chan_lower.contains("powershell") && parsed.event_id == 4104 {
            return Some("SCRIPT_BLOCK_ACTIVITY");
        }
        if chan_lower.contains("taskscheduler") {
            return match parsed.event_id {
                106 => Some("SCHEDULED_TASK_CREATE"),
                140 => Some("SCHEDULED_TASK_MODIFY"),
                141 => Some("SCHEDULED_TASK_DELETE"),
                _ => None,
            };
        }
        if chan_lower.contains("bits-client") && matches!(parsed.event_id, 3 | 4 | 59 | 60) {
            return Some("BITS_JOB_ACTIVITY");
        }
        if chan_lower.contains("wmi-activity") {
            return match parsed.event_id {
                5859 => Some("WMI_EVENT_FILTER"),
                5860 => Some("WMI_EVENT_CONSUMER"),
                5861 => Some("WMI_EVENT_CONSUMER_TO_FILTER"),
                _ => None,
            };
        }
        None
    }

    unsafe extern "system" fn evt_subscribe_callback(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        _usercontext: *const c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        if action != EvtSubscribeActionDeliver || STOP_FLAG.load(Ordering::Relaxed) {
            return 0;
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            let mut used = 0u32;
            let mut count = 0u32;
            let _ = EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut count);
            if used == 0 || used > 256 * 1024 {
                return;
            }
            let mut buf = vec![0u16; (used as usize + 3) / 2];
            if !EvtRender(
                None,
                event,
                EvtRenderEventXml.0,
                (buf.len() * 2) as u32,
                Some(buf.as_mut_ptr() as *mut c_void),
                &mut used,
                &mut count,
            )
            .as_bool()
            {
                return;
            }
            let wlen = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let xml = String::from_utf16_lossy(&buf[..wlen]);
            let Some(parsed) = parse_event_xml_summary(&xml) else {
                return;
            };
            let Some(out_type) = map_eventlog_to_telemetry(&parsed) else {
                return;
            };
            let mut body = parsed.fields.clone();
            body.insert("event_id".to_string(), json!(parsed.event_id));
            body.insert("provider".to_string(), json!(parsed.provider));
            body.insert("channel".to_string(), json!(parsed.channel));
            body.insert("source".to_string(), json!("wevtapi_push"));
            let pid = parsed
                .fields
                .get("ProcessId")
                .or_else(|| parsed.fields.get("ProcessID"))
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    let s = s.trim();
                    if let Some(hex) = s.strip_prefix("0x") {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        s.parse::<u32>().ok()
                    }
                });
            let exe = parsed
                .fields
                .get("ProcessName")
                .or_else(|| parsed.fields.get("Application"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| pid.map(query_pid_image).filter(|s| !s.is_empty()));
            let details = format!(
                "{} EventID={}",
                parsed.channel, parsed.event_id
            );
            crate::telemetry_stream::submit_structured(
                out_type,
                pid,
                exe,
                Some(details),
                Value::Object(body),
            );
        }));
        0
    }

    fn eventlog_push_setup() {
        let subscriptions: &[(&str, &str)] = &[
            (
                "Security",
                "*[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4732 or EventID=4733 or EventID=4738 or EventID=4624 or EventID=4634 or EventID=4647 or EventID=4697 or EventID=4698 or EventID=4699 or EventID=4702)]]",
            ),
            (
                "System",
                "*[System[(EventID=7045 or EventID=7040 or EventID=25 or EventID=33 or EventID=36)]]",
            ),
            (
                "Microsoft-Windows-PowerShell/Operational",
                "*[System[(EventID=4104)]]",
            ),
            (
                "Microsoft-Windows-TaskScheduler/Operational",
                "*[System[(EventID=106 or EventID=140 or EventID=141)]]",
            ),
            (
                "Microsoft-Windows-Bits-Client/Operational",
                "*[System[(EventID=3 or EventID=4 or EventID=59 or EventID=60)]]",
            ),
            (
                "Microsoft-Windows-WMI-Activity/Operational",
                "*[System[(EventID=5859 or EventID=5860 or EventID=5861)]]",
            ),
        ];

        let mut handles = Vec::new();
        for (channel, query) in subscriptions {
            let chan_w = to_wide_z(channel);
            let query_w = to_wide_z(query);
            match unsafe {
                EvtSubscribe(
                    None,
                    None,
                    PCWSTR(chan_w.as_ptr()),
                    PCWSTR(query_w.as_ptr()),
                    None,
                    None,
                    Some(evt_subscribe_callback),
                    EvtSubscribeToFutureEvents.0,
                )
            } {
                Ok(h) => handles.push(h.0),
                Err(e) => {
                    Logging::debug(&format!(
                        "[WindowsTelemetry] EvtSubscribe({channel}) skipped: {e}"
                    ));
                }
            }
        }
        if let Some(mtx) = EVT_SUB_HANDLES.get() {
            if let Ok(mut guard) = mtx.lock() {
                *guard = handles;
            }
        }
    }

    // ------------------------------------------------------------------------
    // 3. Native PnP Device Interface Watcher (cfgmgr32.dll CM_Register_Notification)
    // ------------------------------------------------------------------------

    #[repr(C)]
    struct CmNotifyFilter {
        cb_size: u32,
        flags: u32,
        filter_type: u32,
        reserved: u32,
        union_bytes: [u8; 400],
    }

    type FnCmRegisterNotification = unsafe extern "system" fn(
        filter: *const CmNotifyFilter,
        context: *const c_void,
        callback: unsafe extern "system" fn(usize, *const c_void, u32, *const c_void, u32) -> u32,
        notification: *mut usize,
    ) -> u32;
    type FnCmUnregisterNotification = unsafe extern "system" fn(notification: usize) -> u32;

    const CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE: u32 = 1;
    const CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL: u32 = 0;
    const CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL: u32 = 1;

    const GUID_DEVINTERFACE_USB_DEVICE: GUID =
        GUID::from_u128(0xa5dcbf10_6530_11d2_901f_00c04fb951ed);
    const GUID_DEVINTERFACE_DISK: GUID =
        GUID::from_u128(0x53f56307_b6bf_11d0_94f2_00a0c91efb8b);
    const GUID_DEVINTERFACE_VOLUME: GUID =
        GUID::from_u128(0x53f5630d_b6bf_11d0_94f2_00a0c91efb8b);

    unsafe extern "system" fn pnp_notify_callback(
        _notify: usize,
        _ctx: *const c_void,
        action: u32,
        event_data: *const c_void,
        event_data_size: u32,
    ) -> u32 {
        if STOP_FLAG.load(Ordering::Relaxed) || event_data.is_null() || event_data_size < 26 {
            return 0;
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            let base = event_data as *const u8;
            let filter_type = u32::from_le_bytes([*base, *base.add(1), *base.add(2), *base.add(3)]);
            if filter_type != 1 {
                return;
            }
            let class_guid = std::ptr::read_unaligned(base.add(8) as *const GUID);
            let sym_bytes = (event_data_size as usize).saturating_sub(24);
            let sym_ptr = base.add(24) as *const u16;
            let max_chars = sym_bytes / 2;
            let mut len = 0usize;
            while len < max_chars && *sym_ptr.add(len) != 0 {
                len += 1;
            }
            let device_path = String::from_utf16_lossy(std::slice::from_raw_parts(sym_ptr, len));
            let lower = device_path.to_ascii_lowercase();
            let is_virtual = lower.contains("msft&prod_virtual_disk")
                || lower.contains("virtual_dvd")
                || lower.contains("vhd")
                || lower.contains("vstor")
                || lower.contains("msvhd");
            let is_usb = class_guid == GUID_DEVINTERFACE_USB_DEVICE
                || lower.contains("usbstor")
                || lower.contains("vid_")
                || lower.contains("usb#");

            let event_type = match action {
                CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL => {
                    if is_virtual {
                        "VIRTUAL_DISK_MOUNT"
                    } else if is_usb {
                        "USB_DEVICE_MOUNT"
                    } else {
                        return;
                    }
                }
                CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL => {
                    if is_usb {
                        "USB_DEVICE_UNMOUNT"
                    } else {
                        return;
                    }
                }
                _ => return,
            };

            crate::telemetry_stream::submit_structured(
                event_type,
                Some(std::process::id()),
                None,
                Some(device_path.clone()),
                json!({
                    "device_path": device_path,
                    "class_guid": format!("{:?}", class_guid),
                    "is_virtual_disk": is_virtual,
                    "is_usb": is_usb,
                    "source": "cfgmgr32_pnp",
                }),
            );
        }));
        0
    }

    fn pnp_device_watcher_loop() {
        let mod_w = to_wide_z("cfgmgr32.dll");
        let hmod: HMODULE = unsafe { LoadLibraryW(PCWSTR(mod_w.as_ptr())) }.unwrap_or_default();
        if hmod.0 == 0 {
            return;
        }
        let Some(reg_ptr) = (unsafe {
            GetProcAddress(hmod, PCSTR(b"CM_Register_Notification\0".as_ptr()))
        }) else {
            return;
        };
        let cm_reg: FnCmRegisterNotification = unsafe { std::mem::transmute(reg_ptr) };
        let mut handles = Vec::new();
        for guid in [
            GUID_DEVINTERFACE_USB_DEVICE,
            GUID_DEVINTERFACE_DISK,
            GUID_DEVINTERFACE_VOLUME,
        ] {
            let mut filter = CmNotifyFilter {
                cb_size: size_of::<CmNotifyFilter>() as u32,
                flags: 0,
                filter_type: CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
                reserved: 0,
                union_bytes: [0u8; 400],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &guid as *const GUID as *const u8,
                    filter.union_bytes.as_mut_ptr(),
                    size_of::<GUID>(),
                );
            }
            let mut out_handle = 0usize;
            let rc = unsafe { cm_reg(&filter, null(), pnp_notify_callback, &mut out_handle) };
            if rc == 0 && out_handle != 0 {
                handles.push(out_handle);
            }
        }
        if let Some(mtx) = PNP_REG_HANDLES.get() {
            if let Ok(mut guard) = mtx.lock() {
                *guard = handles;
            }
        }
    }

    fn unregister_pnp_handles(handles: &mut Vec<usize>) {
        if handles.is_empty() {
            return;
        }
        let mod_w = to_wide_z("cfgmgr32.dll");
        let hmod: HMODULE = unsafe { GetModuleHandleW(PCWSTR(mod_w.as_ptr())) }.unwrap_or_default();
        if hmod.0 != 0 {
            if let Some(unreg_ptr) =
                unsafe { GetProcAddress(hmod, PCSTR(b"CM_Unregister_Notification\0".as_ptr())) }
            {
                let cm_unreg: FnCmUnregisterNotification = unsafe { std::mem::transmute(unreg_ptr) };
                for h in handles.drain(..) {
                    unsafe {
                        let _ = cm_unreg(h);
                    }
                }
                return;
            }
        }
        handles.clear();
    }

    // ------------------------------------------------------------------------
    // 4. Live Kernel Driver Snapshot Diff (EnumDeviceDrivers -> DRIVER_UNLOADED / LOADED)
    // ------------------------------------------------------------------------

    fn snapshot_loaded_drivers() -> HashMap<usize, String> {
        let mut needed = 0u32;
        let _ = unsafe { EnumDeviceDrivers(null_mut(), 0, &mut needed) };
        if needed == 0 {
            return HashMap::new();
        }
        let count = (needed as usize / size_of::<*mut c_void>()) + 32;
        let mut bases: Vec<*mut c_void> = vec![null_mut(); count];
        let mut actual = 0u32;
        if !unsafe {
            EnumDeviceDrivers(
                bases.as_mut_ptr(),
                (bases.len() * size_of::<*mut c_void>()) as u32,
                &mut actual,
            )
        }
        .as_bool()
        {
            return HashMap::new();
        }
        let n = (actual as usize / size_of::<*mut c_void>()).min(bases.len());
        let mut map = HashMap::with_capacity(n);
        let mut name_buf = [0u16; MAX_PATH as usize * 2];
        for &base in &bases[..n] {
            if base.is_null() {
                continue;
            }
            let len = unsafe { GetDeviceDriverFileNameW(base, &mut name_buf) } as usize;
            let raw_path = if len > 0 && len <= name_buf.len() {
                String::from_utf16_lossy(&name_buf[..len])
            } else {
                String::new()
            };
            let path = crate::pe_hashes::normalize_windows_path(&raw_path).unwrap_or(raw_path);
            map.insert(base as usize, path);
        }
        map
    }

    fn driver_diff_loop() {
        let mut prev = snapshot_loaded_drivers();
        while !STOP_FLAG.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(2));
            if STOP_FLAG.load(Ordering::Relaxed) {
                break;
            }
            let curr = snapshot_loaded_drivers();
            if curr.is_empty() {
                continue;
            }
            for (base, old_path) in &prev {
                if !curr.contains_key(base) {
                    crate::telemetry_stream::submit_structured(
                        "DRIVER_UNLOADED",
                        Some(4),
                        Some(old_path.clone()),
                        Some(format!("Unloaded driver {old_path} (base=0x{base:x})")),
                        json!({
                            "driver_base": format!("0x{base:x}"),
                            "driver_path": old_path,
                            "source": "enum_device_drivers_diff",
                        }),
                    );
                }
            }
            for (base, new_path) in &curr {
                if !prev.contains_key(base) {
                    let hashes = crate::pe_hashes::compute_file_hashes_cached(new_path);
                    crate::telemetry_stream::submit_structured(
                        "DRIVER_LOADED",
                        Some(4),
                        Some(new_path.clone()),
                        Some(format!("Loaded driver {new_path} (base=0x{base:x})")),
                        json!({
                            "driver_base": format!("0x{base:x}"),
                            "driver_path": new_path,
                            "hashes": hashes,
                            "source": "enum_device_drivers_diff",
                        }),
                    );
                }
            }
            prev = curr;
        }
    }

    // ------------------------------------------------------------------------
    // 5. WMI Permanent Subscription & VSS Shadow Copy Diff Watcher
    // ------------------------------------------------------------------------

    fn connect_wmi(namespace_str: &str) -> Option<IWbemServices> {
        unsafe {
            match CoInitializeEx(None, COINIT_MULTITHREADED) {
                Ok(_) => {}
                Err(e) if e.code() == RPC_E_CHANGED_MODE => {}
                Err(_) => return None,
            }
            match CoInitializeSecurity(
                PSECURITY_DESCRIPTOR::default(),
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            ) {
                Ok(_) => {}
                Err(e) if e.code() == RPC_E_TOO_LATE => {}
                Err(_) => return None,
            }
            let locator: IWbemLocator =
                CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).ok()?;
            let ns = BSTR::from(namespace_str);
            let empty = BSTR::new();
            let svc = locator
                .ConnectServer(&ns, &empty, &empty, &empty, 0, &empty, None)
                .ok()?;
            let _ = CoSetProxyBlanket(
                &svc,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            );
            Some(svc)
        }
    }

    fn read_wmi_bstr(obj: &IWbemClassObject, prop: PCWSTR) -> String {
        let mut var = VARIANT::default();
        if unsafe { obj.Get(prop, 0, &mut var, None, None) }.is_err() {
            return String::new();
        }
        let res = unsafe {
            if var.Anonymous.Anonymous.vt == VT_BSTR {
                ManuallyDrop::into_inner(var.Anonymous.Anonymous.Anonymous.bstrVal.clone())
                    .to_string()
            } else {
                String::new()
            }
        };
        let _ = unsafe { VariantClear(&mut var) };
        res
    }

    fn query_wmi_rows(
        svc: &IWbemServices,
        wql: &str,
        props: &[PCWSTR],
    ) -> Option<Vec<Vec<String>>> {
        let lang = BSTR::from("WQL");
        let query = BSTR::from(wql);
        let enum_obj = unsafe {
            svc.ExecQuery(
                &lang,
                &query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
        }
        .ok()?;

        let mut rows = Vec::new();
        for _ in 0..4096 {
            let mut returned = 0u32;
            let mut batch = [None];
            if unsafe { enum_obj.Next(WBEM_INFINITE, &mut batch, &mut returned) }.is_err()
                || returned == 0
            {
                break;
            }
            if let Some(obj) = batch[0].as_ref() {
                let row = props.iter().map(|p| read_wmi_bstr(obj, *p)).collect();
                rows.push(row);
            }
        }
        Some(rows)
    }

    fn wmi_and_vss_watcher_loop() {
        let sub_svc = connect_wmi("ROOT\\subscription");
        let cim_svc = connect_wmi("ROOT\\CIMV2");

        let mut prev_filters: Option<HashMap<String, String>> = None;
        let mut prev_consumers: Option<HashMap<String, String>> = None;
        let mut prev_bindings: Option<HashSet<String>> = None;
        let mut prev_shadows: Option<HashMap<String, String>> = None;

        while !STOP_FLAG.load(Ordering::Relaxed) {
            if let Some(ref svc) = sub_svc {
                if let Some(rows) = query_wmi_rows(
                    svc,
                    "SELECT Name, Query, QueryLanguage, EventNamespace FROM __EventFilter",
                    &[
                        windows::core::w!("Name"),
                        windows::core::w!("Query"),
                        windows::core::w!("QueryLanguage"),
                        windows::core::w!("EventNamespace"),
                    ],
                ) {
                    let mut curr = HashMap::new();
                    for r in rows {
                        let key = format!("{}|{}", r[0], r[3]);
                        curr.insert(key, format!("{} ({})", r[1], r[2]));
                    }
                    if let Some(ref prev) = prev_filters {
                        for (k, v) in &curr {
                            if prev.get(k) != Some(v) {
                                crate::telemetry_stream::submit_structured(
                                    "WMI_EVENT_FILTER",
                                    None,
                                    None,
                                    Some(format!("{k}: {v}")),
                                    json!({ "name_ns": k, "query": v, "source": "wmi_subscription_diff" }),
                                );
                            }
                        }
                    }
                    prev_filters = Some(curr);
                }

                if let Some(rows) = query_wmi_rows(
                    svc,
                    "SELECT Name, __CLASS FROM __EventConsumer",
                    &[windows::core::w!("Name"), windows::core::w!("__CLASS")],
                ) {
                    let mut curr = HashMap::new();
                    for r in rows {
                        curr.insert(r[0].clone(), r[1].clone());
                    }
                    if let Some(ref prev) = prev_consumers {
                        for (k, v) in &curr {
                            if prev.get(k) != Some(v) {
                                crate::telemetry_stream::submit_structured(
                                    "WMI_EVENT_CONSUMER",
                                    None,
                                    None,
                                    Some(format!("{v}:{k}")),
                                    json!({ "name": k, "class": v, "source": "wmi_subscription_diff" }),
                                );
                            }
                        }
                    }
                    prev_consumers = Some(curr);
                }

                if let Some(rows) = query_wmi_rows(
                    svc,
                    "SELECT Filter, Consumer FROM __FilterToConsumerBinding",
                    &[windows::core::w!("Filter"), windows::core::w!("Consumer")],
                ) {
                    let mut curr = HashSet::new();
                    for r in rows {
                        curr.insert(format!("{} -> {}", r[0], r[1]));
                    }
                    if let Some(ref prev) = prev_bindings {
                        for binding in &curr {
                            if !prev.contains(binding) {
                                crate::telemetry_stream::submit_structured(
                                    "WMI_EVENT_CONSUMER_TO_FILTER",
                                    None,
                                    None,
                                    Some(binding.clone()),
                                    json!({ "binding": binding, "source": "wmi_subscription_diff" }),
                                );
                            }
                        }
                    }
                    prev_bindings = Some(curr);
                }
            }

            if let Some(ref svc) = cim_svc {
                if let Some(rows) = query_wmi_rows(
                    svc,
                    "SELECT ID, DeviceObject, InstallDate FROM Win32_ShadowCopy",
                    &[
                        windows::core::w!("ID"),
                        windows::core::w!("DeviceObject"),
                        windows::core::w!("InstallDate"),
                    ],
                ) {
                    let mut curr = HashMap::new();
                    for r in rows {
                        if !r[0].is_empty() {
                            curr.insert(r[0].clone(), r[1].clone());
                        }
                    }
                    if let Some(ref prev) = prev_shadows {
                        for (id, dev) in prev {
                            if !curr.contains_key(id) {
                                crate::telemetry_stream::submit_structured(
                                    "VSS_SHADOW_COPY_DELETED",
                                    None,
                                    None,
                                    Some(format!("ShadowCopy deleted: {id} ({dev})")),
                                    json!({
                                        "shadow_id": id,
                                        "device_object": dev,
                                        "source": "wmi_shadowcopy_diff",
                                    }),
                                );
                            }
                        }
                    }
                    prev_shadows = Some(curr);
                }
            }

            for _ in 0..10 {
                if STOP_FLAG.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
        unsafe {
            CoUninitialize();
        }
    }

    // ------------------------------------------------------------------------
    // 6. Native Account (NetUserEnum) & LSA Logon Session Diff
    // ------------------------------------------------------------------------

    #[repr(C)]
    struct UserInfo1 {
        name: *const u16,
        password: *const u16,
        password_age: u32,
        priv_level: u32,
        home_dir: *const u16,
        comment: *const u16,
        flags: u32,
        script_path: *const u16,
    }

    type FnNetUserEnum = unsafe extern "system" fn(
        servername: *const u16,
        level: u32,
        filter: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
    type FnNetApiBufferFree = unsafe extern "system" fn(*mut c_void) -> u32;

    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    struct LsaUnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    #[repr(C)]
    struct SecurityLogonSessionData {
        size: u32,
        logon_id: Luid,
        user_name: LsaUnicodeString,
        logon_domain: LsaUnicodeString,
        auth_package: LsaUnicodeString,
        logon_type: u32,
        session: u32,
        sid: *const c_void,
        logon_time: i64,
    }

    type FnLsaEnumSessions =
        unsafe extern "system" fn(count: *mut u32, sessions: *mut *mut Luid) -> i32;
    type FnLsaGetSessionData = unsafe extern "system" fn(
        logon_id: *const Luid,
        data: *mut *mut SecurityLogonSessionData,
    ) -> i32;
    type FnLsaFreeReturnBuffer = unsafe extern "system" fn(*mut c_void) -> i32;

    fn snapshot_local_users(
        net_enum: Option<FnNetUserEnum>,
        net_free: Option<FnNetApiBufferFree>,
    ) -> Option<HashMap<String, (u32, u32)>> {
        let (f_enum, f_free) = (net_enum?, net_free?);
        let mut buf: *mut u8 = null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let rc = unsafe { f_enum(null(), 1, 0x0002, &mut buf, u32::MAX, &mut read, &mut total, null_mut()) };
        if buf.is_null() {
            return (rc == 0).then(HashMap::new);
        }
        let mut users = HashMap::new();
        if rc == 0 || rc == 234 {
            let entries = unsafe { std::slice::from_raw_parts(buf as *const UserInfo1, read as usize) };
            for u in entries {
                let name = unsafe { utf16_ptr_to_string(u.name) };
                if !name.is_empty() {
                    users.insert(name, (u.flags, u.priv_level));
                }
            }
        }
        unsafe {
            f_free(buf as *mut c_void);
        }
        Some(users)
    }

    unsafe fn lsa_str_to_string(s: &LsaUnicodeString) -> String {
        if s.buffer.is_null() || s.length == 0 {
            return String::new();
        }
        let chars = (s.length as usize) / 2;
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s.buffer, chars) })
    }

    fn snapshot_lsa_sessions(
        f_enum: Option<FnLsaEnumSessions>,
        f_get: Option<FnLsaGetSessionData>,
        f_free: Option<FnLsaFreeReturnBuffer>,
    ) -> Option<HashMap<(u32, i32), (String, String, u32, u32)>> {
        let (fe, fg, ff) = (f_enum?, f_get?, f_free?);
        let mut count = 0u32;
        let mut ptr: *mut Luid = null_mut();
        let st = unsafe { fe(&mut count, &mut ptr) };
        if st != 0 || ptr.is_null() {
            return None;
        }
        let luids = unsafe { std::slice::from_raw_parts(ptr, count as usize) };
        let mut out = HashMap::new();
        for luid in luids {
            let mut data_ptr: *mut SecurityLogonSessionData = null_mut();
            if unsafe { fg(luid, &mut data_ptr) } == 0 && !data_ptr.is_null() {
                let d = unsafe { &*data_ptr };
                let user = unsafe { lsa_str_to_string(&d.user_name) };
                let dom = unsafe { lsa_str_to_string(&d.logon_domain) };
                let pkg = unsafe { lsa_str_to_string(&d.auth_package) };
                let full_user = if dom.is_empty() { user } else { format!("{dom}\\{user}") };
                out.insert(
                    (luid.low_part, luid.high_part),
                    (full_user, pkg, d.logon_type, d.session),
                );
                unsafe {
                    ff(data_ptr as *mut c_void);
                }
            }
        }
        unsafe {
            ff(ptr as *mut c_void);
        }
        Some(out)
    }

    fn account_and_session_diff_loop() {
        let net_w = to_wide_z("netapi32.dll");
        let h_net = unsafe { LoadLibraryW(PCWSTR(net_w.as_ptr())) }.unwrap_or_default();
        let net_enum: Option<FnNetUserEnum> = (h_net.0 != 0)
            .then(|| unsafe { GetProcAddress(h_net, PCSTR(b"NetUserEnum\0".as_ptr())) })
            .flatten()
            .map(|p| unsafe { std::mem::transmute(p) });
        let net_free: Option<FnNetApiBufferFree> = (h_net.0 != 0)
            .then(|| unsafe { GetProcAddress(h_net, PCSTR(b"NetApiBufferFree\0".as_ptr())) })
            .flatten()
            .map(|p| unsafe { std::mem::transmute(p) });

        let sec_w = to_wide_z("secur32.dll");
        let h_sec = unsafe { LoadLibraryW(PCWSTR(sec_w.as_ptr())) }.unwrap_or_default();
        let lsa_enum: Option<FnLsaEnumSessions> = (h_sec.0 != 0)
            .then(|| unsafe {
                GetProcAddress(h_sec, PCSTR(b"LsaEnumerateLogonSessions\0".as_ptr()))
            })
            .flatten()
            .map(|p| unsafe { std::mem::transmute(p) });
        let lsa_get: Option<FnLsaGetSessionData> = (h_sec.0 != 0)
            .then(|| unsafe {
                GetProcAddress(h_sec, PCSTR(b"LsaGetLogonSessionData\0".as_ptr()))
            })
            .flatten()
            .map(|p| unsafe { std::mem::transmute(p) });
        let lsa_free: Option<FnLsaFreeReturnBuffer> = (h_sec.0 != 0)
            .then(|| unsafe { GetProcAddress(h_sec, PCSTR(b"LsaFreeReturnBuffer\0".as_ptr())) })
            .flatten()
            .map(|p| unsafe { std::mem::transmute(p) });

        let mut prev_users = snapshot_local_users(net_enum, net_free);
        let mut prev_sessions = snapshot_lsa_sessions(lsa_enum, lsa_get, lsa_free);

        while !STOP_FLAG.load(Ordering::Relaxed) {
            for _ in 0..8 {
                if STOP_FLAG.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(500));
            }

            if let Some(curr_users) = snapshot_local_users(net_enum, net_free) {
                if let Some(ref prev) = prev_users {
                    for (name, (flags, priv_lv)) in &curr_users {
                        match prev.get(name) {
                            None => crate::telemetry_stream::submit_structured(
                                "LOCAL_ACCOUNT_CREATE",
                                None,
                                None,
                                Some(format!("Account created: {name}")),
                                json!({ "account_name": name, "flags": flags, "priv": priv_lv, "source": "netuserenum_diff" }),
                            ),
                            Some(old_vals) if old_vals != &(*flags, *priv_lv) => {
                                crate::telemetry_stream::submit_structured(
                                    "LOCAL_ACCOUNT_MODIFY",
                                    None,
                                    None,
                                    Some(format!("Account modified: {name}")),
                                    json!({
                                        "account_name": name,
                                        "flags": flags,
                                        "priv": priv_lv,
                                        "old_flags": old_vals.0,
                                        "old_priv": old_vals.1,
                                        "source": "netuserenum_diff",
                                    }),
                                )
                            }
                            _ => {}
                        }
                    }
                    for name in prev.keys() {
                        if !curr_users.contains_key(name) {
                            crate::telemetry_stream::submit_structured(
                                "LOCAL_ACCOUNT_DELETE",
                                None,
                                None,
                                Some(format!("Account deleted: {name}")),
                                json!({ "account_name": name, "source": "netuserenum_diff" }),
                            );
                        }
                    }
                }
                prev_users = Some(curr_users);
            }

            if let Some(curr_sess) = snapshot_lsa_sessions(lsa_enum, lsa_get, lsa_free) {
                if let Some(ref prev) = prev_sessions {
                    for (luid, (user, pkg, ltype, sess_id)) in &curr_sess {
                        if !prev.contains_key(luid) && !user.ends_with('$') {
                            crate::telemetry_stream::submit_structured(
                                "ACCOUNT_LOGIN",
                                None,
                                None,
                                Some(format!("LSA logon {user} (type={ltype}, session={sess_id})")),
                                json!({
                                    "account_name": user,
                                    "auth_package": pkg,
                                    "logon_type": ltype,
                                    "session_id": sess_id,
                                    "luid": format!("0x{:x}:{:x}", luid.1, luid.0),
                                    "source": "lsa_session_diff",
                                }),
                            );
                        }
                    }
                    for (luid, (user, pkg, ltype, sess_id)) in prev {
                        if !curr_sess.contains_key(luid) && !user.ends_with('$') {
                            crate::telemetry_stream::submit_structured(
                                "ACCOUNT_LOGOFF",
                                None,
                                None,
                                Some(format!("LSA logoff {user} (type={ltype}, session={sess_id})")),
                                json!({
                                    "account_name": user,
                                    "auth_package": pkg,
                                    "logon_type": ltype,
                                    "session_id": sess_id,
                                    "luid": format!("0x{:x}:{:x}", luid.1, luid.0),
                                    "source": "lsa_session_diff",
                                }),
                            );
                        }
                    }
                }
                prev_sessions = Some(curr_sess);
            }
        }
    }

    // ------------------------------------------------------------------------
    // 7. Process Tampering Checker (Hollowing / Herpaderping / Ghosting)
    // ------------------------------------------------------------------------

    #[repr(C)]
    #[derive(Default)]
    struct ProcessBasicInfo {
        exit_status: isize,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: isize,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    type FnNtQueryInfoProcess = unsafe extern "system" fn(
        HANDLE,
        u32,
        *mut c_void,
        u32,
        *mut u32,
    ) -> i32;

    fn process_tampering_loop(rx: mpsc::Receiver<(u32, String)>) {
        let ntdll_w = to_wide_z("ntdll.dll");
        let h_nt = unsafe { GetModuleHandleW(PCWSTR(ntdll_w.as_ptr())) }.unwrap_or_default();
        let nt_query: Option<FnNtQueryInfoProcess> = (h_nt.0 != 0)
            .then(|| unsafe { GetProcAddress(h_nt, PCSTR(b"NtQueryInformationProcess\0".as_ptr())) })
            .flatten()
            .map(|p| unsafe { std::mem::transmute(p) });
        let Some(f_nt_query) = nt_query else {
            return;
        };

        while let Ok((pid, raw_path)) = rx.recv() {
            if STOP_FLAG.load(Ordering::Relaxed) {
                break;
            }
            let Some(norm_path) = crate::pe_hashes::normalize_windows_path(&raw_path) else {
                continue;
            };
            let Ok(h_proc) =
                (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid) })
            else {
                continue;
            };

            let finding = unsafe { inspect_process_tampering(h_proc, f_nt_query, &norm_path) };
            unsafe {
                let _ = CloseHandle(h_proc);
            }

            if let Some(f) = finding {
                crate::telemetry_stream::submit_structured(
                    "PROCESS_TAMPERING",
                    Some(pid),
                    Some(norm_path.clone()),
                    Some(format!("{}: {}", f.technique, f.reason)),
                    json!({
                        "technique": f.technique,
                        "reason": f.reason,
                        "image_path": norm_path,
                        "source": "pe_header_tamper_check",
                    }),
                );
            }
        }
    }

    unsafe fn inspect_process_tampering(
        h_proc: HANDLE,
        f_nt_query: FnNtQueryInfoProcess,
        disk_path: &str,
    ) -> Option<PeTamperingFinding> {
        let mut pbi = ProcessBasicInfo::default();
        let mut ret = 0u32;
        if unsafe {
            f_nt_query(
                h_proc,
                0,
                &mut pbi as *mut _ as *mut c_void,
                size_of::<ProcessBasicInfo>() as u32,
                &mut ret,
            )
        } != 0
            || pbi.peb_base_address == 0
        {
            return None;
        }

        let mut img_base: usize = 0;
        let mut bytes_read = 0usize;
        if !unsafe {
            ReadProcessMemory(
                h_proc,
                (pbi.peb_base_address + 0x10) as *const c_void,
                &mut img_base as *mut usize as *mut c_void,
                size_of::<usize>(),
                Some(&mut bytes_read),
            )
        }
        .as_bool()
            || img_base == 0
        {
            return None;
        }

        let mut mem_hdr = [0u8; 4096];
        let mut hdr_read = 0usize;
        if !unsafe {
            ReadProcessMemory(
                h_proc,
                img_base as *const c_void,
                mem_hdr.as_mut_ptr() as *mut c_void,
                mem_hdr.len(),
                Some(&mut hdr_read),
            )
        }
        .as_bool()
            || hdr_read < 128
        {
            return None;
        }

        let mut disk_file = match std::fs::File::open(disk_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Some(PeTamperingFinding {
                    technique: "process_ghosting_or_deleted_image".to_string(),
                    reason: format!("Process running from missing/deleted path: {disk_path}"),
                });
            }
            Err(_) => return None,
        };
        let mut disk_hdr = [0u8; 4096];
        let d_read = disk_file.read(&mut disk_hdr).ok()?;
        if d_read < 128 {
            return None;
        }
        compare_pe_headers(&disk_hdr[..d_read], &mem_hdr[..hdr_read])
    }
}

#[cfg(not(target_os = "windows"))]
mod win_impl {
    pub fn start() {}
    pub fn stop() {}
}

pub fn start() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    STOP_FLAG.store(false, Ordering::SeqCst);
    win_impl::start();
}

pub fn stop() {
    STOP_FLAG.store(true, Ordering::SeqCst);
    win_impl::stop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_security_4720_and_powershell_4104_xml() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4720</EventID><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">backdoor</Data><Data Name="SubjectUserName">Administrator</Data></EventData></Event>"#;
        let parsed = parse_event_xml_summary(xml).unwrap();
        assert_eq!(parsed.event_id, 4720);
        assert_eq!(parsed.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(parsed.channel, "Security");
        assert_eq!(
            parsed.fields.get("TargetUserName").and_then(|v| v.as_str()),
            Some("backdoor")
        );
    }

    #[test]
    fn detects_pe_header_tampering_without_false_positives() {
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&4u16.to_le_bytes());
        pe[0x88..0x8c].copy_from_slice(&0x6500_0000u32.to_le_bytes());
        let opt = 0x80 + 24;
        pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint
        pe[opt + 56..opt + 60].copy_from_slice(&0x10000u32.to_le_bytes()); // SizeOfImage

        assert_eq!(compare_pe_headers(&pe, &pe), None);

        let mut hollowed = pe.clone();
        hollowed[opt + 16..opt + 20].copy_from_slice(&0x9999u32.to_le_bytes());
        let finding = compare_pe_headers(&pe, &hollowed).expect("should flag entrypoint mismatch");
        assert_eq!(finding.technique, "pe_header_mismatch_hollowing_or_herpaderping");
        assert!(finding.reason.contains("entry_point"));
    }
}
