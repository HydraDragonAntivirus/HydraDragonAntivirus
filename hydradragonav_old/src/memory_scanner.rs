// This module is entirely Win32 FFI; the unsafe fns are the unsafe surface.
#![allow(unsafe_op_in_unsafe_fn)]

//! Process (RAM) memory scanner — the "memory" component of full-mode scanning.
//!
//! Enumerates running processes (Toolhelp snapshot), opens each readable one, and
//! walks its committed readable memory regions (`VirtualQueryEx` +
//! `ReadProcessMemory`), scanning every region's bytes with the engine
//! (`Pipeline::scan_bytes` → YARA-X + hydradragonsig + ML + URL bloom). Processes
//! we can't open (protected/system, or without privilege) are skipped silently;
//! run elevated to cover more of them.

use std::ffi::c_void;

use serde::Serialize;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::pipeline::Pipeline;
use crate::verdict::Verdict;

/// A malicious/suspicious match inside a process's memory.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryDetection {
    pub pid: u32,
    pub process: String,
    pub address: u64,
    pub region_size: usize,
    pub verdict: Verdict,
    pub threat_name: String,
}

/// Don't read regions larger than this (avoids pulling huge mapped files / heaps
/// into RAM); 64 MiB is plenty for injected-code regions.
const MAX_REGION: usize = 64 * 1024 * 1024;

// Page-protection bits that allow reading (PAGE_READONLY/READWRITE/WRITECOPY and
// their EXECUTE_* variants); PAGE_GUARD / PAGE_NOACCESS must be absent.
const READABLE_MASK: u32 = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
const PAGE_GUARD_BIT: u32 = 0x100;

fn exe_name(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Scan the memory of every accessible process. Returns one entry per region
/// that the engine flagged (verdict above Clean).
pub fn scan_process_memory(pipeline: &Pipeline) -> Vec<MemoryDetection> {
    let mut out = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // Honor a GUI Stop: bail out of the (potentially minutes-long)
                // whole-system memory walk between processes.
                if pipeline.is_cancelled() {
                    break;
                }
                let pid = entry.th32ProcessID;
                if pid != 0 {
                    let name = exe_name(&entry.szExeFile);
                    scan_process(pipeline, pid, &name, &mut out);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }
    out
}

unsafe fn scan_process(pipeline: &Pipeline, pid: u32, name: &str, out: &mut Vec<MemoryDetection>) {
    let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
        Ok(h) => h,
        Err(_) => return, // protected/system process or insufficient privilege
    };

    let mut addr: usize = 0;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let written = VirtualQueryEx(
            handle,
            Some(addr as *const c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if written == 0 {
            break;
        }

        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let prot = mbi.Protect.0;
        let readable = mbi.State == MEM_COMMIT
            && (prot & READABLE_MASK != 0)
            && (prot & PAGE_GUARD_BIT == 0);

        if readable && size > 0 && size <= MAX_REGION {
            let mut buf = vec![0u8; size];
            let mut read: usize = 0;
            let ok = ReadProcessMemory(
                handle,
                base as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut read),
            )
            .is_ok();
            if ok && read > 0 {
                buf.truncate(read);
                let result = pipeline.scan_bytes(&buf);
                if result.verdict.priority() > 1 {
                    out.push(MemoryDetection {
                        pid,
                        process: name.to_string(),
                        address: base as u64,
                        region_size: read,
                        verdict: result.verdict,
                        threat_name: result.threat_name.unwrap_or_default(),
                    });
                }
            }
        }

        // Advance to the next region; stop on wrap/overflow.
        match base.checked_add(size) {
            Some(next) if next > addr => addr = next,
            _ => break,
        }
    }

    let _ = CloseHandle(handle);
}
