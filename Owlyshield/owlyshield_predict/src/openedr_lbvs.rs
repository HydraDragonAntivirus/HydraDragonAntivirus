//! Minimal OpenEDR LBVS parser and Owlyshield compatibility mapper.
//!
//! This module parses the edrdrv fltport payload produced by
//! `variant::BasicLbvsSerializer<edrdrv::EventField>` and maps it into the
//! existing Owlyshield `IOMessage` model. It is intentionally self-contained so
//! it can replace the old `ReplyIrp/CDriverMsg` path incrementally.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::shared_def::{FileId, IOMessage, KernelEventInfo, RuntimeFeatures};

const LBVS_MAGIC: u32 = 0x5356_424c; // 'SVBL' as written by the C++ serializer on little-endian Windows.

#[derive(Debug, Clone)]
pub enum LbvsValue {
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

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum EventField {
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

pub fn parse_lbvs(buf: &[u8]) -> Result<HashMap<u16, LbvsValue>, String> {
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

fn field_u32(fields: &HashMap<u16, LbvsValue>, id: EventField) -> u32 {
    match fields.get(&(id as u16)) {
        Some(LbvsValue::Uint32(v)) => *v,
        Some(LbvsValue::Uint64(v)) => *v as u32,
        _ => 0,
    }
}

fn field_u64(fields: &HashMap<u16, LbvsValue>, id: EventField) -> u64 {
    match fields.get(&(id as u16)) {
        Some(LbvsValue::Uint64(v)) => *v,
        Some(LbvsValue::Uint32(v)) => *v as u64,
        _ => 0,
    }
}

fn field_string(fields: &HashMap<u16, LbvsValue>, id: EventField) -> String {
    match fields.get(&(id as u16)) {
        Some(LbvsValue::String(v)) | Some(LbvsValue::WString(v)) => v.clone(),
        Some(LbvsValue::Stream(v)) => String::from_utf8_lossy(v).into_owned(),
        _ => String::new(),
    }
}

fn openedr_event_to_owly_irp(raw_event_id: u32, details_irp_op: Option<u8>) -> u8 {
    if let Some(op) = details_irp_op {
        return op;
    }

    match raw_event_id {
        0x0000 => 7,  // ProcessCreate
        0x0001 => 10, // ProcessDelete -> IrpProcessExit
        0x0003 | 0x0004 | 0x0005 | 0x0006 => 6, // Registry
        0x0007 => 4,  // FileCreate
        0x0008 => 3,  // FileDelete as SetInfo
        0x000A | 0x000C => 2, // Write/data change
        0x000B => 1,  // Read
        0x000D => 11, // ProcessOpen
        0x000E => 12, // DeviceIoControl -> Hypervisor/Event
        0x000F => 28, // NamedPipeCreate
        0x0010 => 20, // SelfDefense -> UserModeHook/Kernel event fallback
        _ => 0,
    }
}

fn parse_owly_details(fields: &HashMap<u16, LbvsValue>) -> serde_json::Value {
    match fields.get(&(EventField::RegistryRawData as u16)) {
        Some(LbvsValue::Stream(bytes)) => serde_json::from_slice(bytes).unwrap_or_default(),
        Some(LbvsValue::String(text)) | Some(LbvsValue::WString(text)) => {
            serde_json::from_str(text).unwrap_or_default()
        }
        _ => serde_json::Value::Null,
    }
}

fn json_u64(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn json_i32(v: &serde_json::Value, key: &str) -> i32 {
    v.get(key).and_then(|v| v.as_i64()).unwrap_or(0) as i32
}

pub fn lbvs_to_iomessage(buf: &[u8]) -> Result<IOMessage, String> {
    let fields = parse_lbvs(buf)?;
    let details = parse_owly_details(&fields);

    let raw_event_id = field_u32(&fields, EventField::RawEventId);
    let details_irp = details.get("irp_op").and_then(|v| v.as_u64()).map(|v| v as u8);
    let irp_op = openedr_event_to_owly_irp(raw_event_id, details_irp);

    let pid = field_u32(&fields, EventField::ProcessPid);
    let filepath = {
        let p = field_string(&fields, EventField::FilePath);
        if p.is_empty() {
            field_string(&fields, EventField::ProcessImageFile)
        } else {
            p
        }
    };

    let command_line = field_string(&fields, EventField::ProcessCmdLine);
    let event_name = field_string(&fields, EventField::FileRawHash);

    let kernel_event_info = KernelEventInfo {
        event_type: json_u64(&details, "event_type") as u32,
        timestamp: json_u64(&details, "timestamp"),
        source_process_id: json_u64(&details, "source_pid") as u32,
        target_process_id: {
            let from_details = json_u64(&details, "target_pid") as u32;
            if from_details != 0 { from_details } else { field_u32(&fields, EventField::TargetProcessPid) }
        },
        core_id: json_u64(&details, "core_id") as u32,
        thread_id: json_u64(&details, "thread_id") as u32,
        context: json_u64(&details, "context"),
        memory_address: json_u64(&details, "memory_address"),
        memory_size: json_u64(&details, "memory_size") as usize,
        memory_protection: json_u64(&details, "memory_protection") as u32,
        is_executable_memory: json_u64(&details, "is_executable_memory") != 0,
        thread_handle: json_u64(&details, "thread_handle"),
        thread_start_routine: json_u64(&details, "thread_start_routine"),
        raw_argument1: json_u64(&details, "raw_argument1"),
        raw_argument2: json_u64(&details, "raw_argument2"),
        raw_argument3: json_u64(&details, "raw_argument3"),
        raw_argument4: json_u64(&details, "raw_argument4"),
        object_name: event_name,
        access_mask: {
            let from_details = json_u64(&details, "access_mask") as u32;
            if from_details != 0 { from_details } else { field_u32(&fields, EventField::AccessMask) }
        },
        bin_payload: Vec::new(),
        is_dll_load: json_u64(&details, "is_dll_load") != 0,
        loaded_dll_path: field_string(&fields, EventField::RegistryPath),
        is_api_based_load: json_u64(&details, "is_api_based_load") != 0,
        is_acg_enabled: json_u64(&details, "is_acg_enabled") != 0,
        is_amsi_event: json_u64(&details, "is_amsi_event") != 0,
        amsi_content_sample: String::new(),
        operation_status: json_i32(&details, "operation_status"),
    };

    Ok(IOMessage {
        extension: PathBuf::from(&filepath)
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or_default()
            .to_string(),
        file_id_id: FileId::from([0u8; crate::shared_def::FILE_ID_LEN]),
        mem_sized_used: kernel_event_info.memory_size as u64,
        entropy: 0.0,
        pid,
        irp_op,
        is_entropy_calc: 0,
        file_change: details.get("file_change").and_then(|v| v.as_u64()).unwrap_or(0) as u8,
        file_location_info: 0,
        filepathstr: filepath.clone(),
        gid: json_u64(&details, "gid"),
        parent_pid: field_u32(&fields, EventField::ProcessParentPid),
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        attacker_pid: json_u64(&details, "attacker_pid") as u32,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        attacker_gid: json_u64(&details, "attacker_gid"),
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        kernel_event_info,
        runtime_features: RuntimeFeatures {
            exepath: PathBuf::from(&filepath),
            exe_still_exists: true,
            command_line,
        },
        file_size: PathBuf::from(&filepath)
            .metadata()
            .map(|m| m.len() as i64)
            .unwrap_or(-1),
        time: SystemTime::now(),
    })
}
