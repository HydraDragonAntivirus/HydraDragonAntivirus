#![allow(dead_code)]
//! Sanctum-owned Owlyshield driver registration and embedded rule push.
//!
//! This file belongs in sanctum_ppl_runner.exe. The hardened Owlyshield
//! minifilter should accept the communication-port connection only from the
//! exact Sanctum runner path while it is Antimalware ProtectedLight.

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};

use crate::hardcoded_rules::{
    OWLY_DYNAMIC_HOOK_EXCLUDE_RULES,
    OWLY_FSFILTER_EXCLUDE_RULES,
    OWLY_PROCESS_PROTECTION_EXCLUDE_RULES,
};

/// Must match `ComPortName` in SharedDefs.h.
pub const OWLYSHIELD_FILTER_PORT_NAME: &str = r"\RWFilter";

const OWLY_RULE_BLOB_MAGIC: u32 = 0x4F52_554C; // 'ORUL'
const OWLY_RULE_BLOB_VERSION: u32 = 1;
const OWLY_RULE_BLOB_FLAG_UTF16LE: u32 = 0x0000_0001;
const MAX_OWLY_RULE_BYTES: usize = 256 * 1024;

// Must match COM_MESSAGE_TYPE in SharedDefs.h.
const MESSAGE_SET_OWLY_FSFILTER_RULES: u32 = 12;
const MESSAGE_SET_OWLY_PROCESS_PROTECTION_RULES: u32 = 13;
const MESSAGE_SET_OWLY_DYNAMIC_HOOK_EXCLUDE_RULES: u32 = 14;

#[link(name = "FltLib")]
unsafe extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: PCWSTR,
        dwOptions: u32,
        lpContext: *const c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const c_void,
        hPort: *mut HANDLE,
    ) -> HRESULT;

    fn FilterSendMessage(
        hPort: HANDLE,
        lpInBuffer: *const c_void,
        dwInBufferSize: u32,
        lpOutBuffer: *mut c_void,
        dwOutBufferSize: u32,
        lpBytesReturned: *mut u32,
    ) -> HRESULT;
}

static OWLYSHIELD_PORT_HANDLE: OnceLock<Mutex<Option<isize>>> = OnceLock::new();

fn wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16le_bytes(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.encode_utf16().count() * 2);
    for word in text.encode_utf16() {
        out.extend_from_slice(&word.to_le_bytes());
    }

    if out.len() > MAX_OWLY_RULE_BYTES {
        return Err(format!(
            "embedded Owlyshield rule block too large: {} > {} bytes",
            out.len(), MAX_OWLY_RULE_BYTES
        ));
    }

    Ok(out)
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn build_rule_message(message_type: u32, rules: &str) -> Result<Vec<u8>, String> {
    let rules = utf16le_bytes(rules)?;
    let mut out = Vec::with_capacity(20 + rules.len());
    push_u32(&mut out, message_type);
    push_u32(&mut out, OWLY_RULE_BLOB_MAGIC);
    push_u32(&mut out, OWLY_RULE_BLOB_VERSION);
    push_u32(&mut out, OWLY_RULE_BLOB_FLAG_UTF16LE);
    push_u32(&mut out, rules.len() as u32);
    out.extend_from_slice(&rules);
    Ok(out)
}

fn connected_port() -> Result<HANDLE, String> {
    let slot = OWLYSHIELD_PORT_HANDLE.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| "Owlyshield port handle mutex poisoned".to_string())?;

    if let Some(raw_handle) = *guard {
        return Ok(HANDLE(raw_handle as *mut c_void));
    }

    let mut handle = HANDLE::default();
    let port_name = wide_null(OWLYSHIELD_FILTER_PORT_NAME);
    let hr = unsafe {
        FilterConnectCommunicationPort(
            PCWSTR(port_name.as_ptr()),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut handle,
        )
    };

    if hr.is_err() || handle.is_invalid() {
        return Err(format!(
            "FilterConnectCommunicationPort({}) failed: HRESULT=0x{:08X}",
            OWLYSHIELD_FILTER_PORT_NAME,
            hr.0 as u32
        ));
    }

    *guard = Some(handle.0 as isize);
    Ok(handle)
}

fn send_rule_blob(message_type: u32, label: &str, rules: &str) -> Result<(), String> {
    let port = connected_port()?;
    let blob = build_rule_message(message_type, rules)?;
    let mut bytes_returned = 0u32;

    let hr = unsafe {
        FilterSendMessage(
            port,
            blob.as_ptr().cast(),
            blob.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned as *mut u32,
        )
    };

    if hr.is_err() {
        return Err(format!(
            "FilterSendMessage({label}) failed: HRESULT=0x{:08X}",
            hr.0 as u32
        ));
    }

    Ok(())
}

/// Connect Sanctum to the Owlyshield minifilter communication port.
/// Keeping the handle open is the registration/ownership marker.
pub fn register_owlyshield_from_sanctum() -> Result<(), String> {
    let _ = connected_port()?;
    Ok(())
}

/// Push the Owlyshield rule sets compiled into sanctum_ppl_runner.exe.
/// No mutable rule file is read from Program Files at runtime.
pub fn push_embedded_owlyshield_rules_from_sanctum() -> Result<(), String> {
    send_rule_blob(
        MESSAGE_SET_OWLY_FSFILTER_RULES,
        "MESSAGE_SET_OWLY_FSFILTER_RULES",
        OWLY_FSFILTER_EXCLUDE_RULES,
    )?;
    send_rule_blob(
        MESSAGE_SET_OWLY_PROCESS_PROTECTION_RULES,
        "MESSAGE_SET_OWLY_PROCESS_PROTECTION_RULES",
        OWLY_PROCESS_PROTECTION_EXCLUDE_RULES,
    )?;
    send_rule_blob(
        MESSAGE_SET_OWLY_DYNAMIC_HOOK_EXCLUDE_RULES,
        "MESSAGE_SET_OWLY_DYNAMIC_HOOK_EXCLUDE_RULES",
        OWLY_DYNAMIC_HOOK_EXCLUDE_RULES,
    )?;
    Ok(())
}

#[allow(clippy::collapsible_if)]
pub fn unregister_owlyshield_from_sanctum() {
    if let Some(slot) = OWLYSHIELD_PORT_HANDLE.get() {
        if let Ok(mut guard) = slot.lock() {
            if let Some(raw_handle) = guard.take() {
                let _ = unsafe { CloseHandle(HANDLE(raw_handle as *mut c_void)) };
            }
        }
    }
}
