use crate::cloud_client::{scan_bytes, MemoryScanReport};

#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

pub fn scan_pid_memory(pid: u32, max_mb: u64) -> MemoryScanReport {
    #[cfg(target_os = "windows")]
    {
        scan_pid_windows(pid, max_mb)
    }
    #[cfg(not(target_os = "windows"))]
    {
        MemoryScanReport {
            pid,
            verdict: "Unknown".to_string(),
            detections: Vec::new(),
            sha256: String::new(),
            bytes_scanned: 0,
            scanned_at: "now".to_string(),
            note: Some("Process memory scanning is only supported on Windows".to_string()),
        }
    }
}

#[cfg(target_os = "windows")]
fn scan_pid_windows(pid: u32, max_mb: u64) -> MemoryScanReport {
    let limit_bytes = if max_mb == 0 {
        128 * 1024 * 1024
    } else {
        (max_mb as usize) * 1024 * 1024
    };

    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) } {
        Ok(h) => h,
        Err(e) => {
            return MemoryScanReport {
                pid,
                verdict: "Unknown".to_string(),
                detections: Vec::new(),
                sha256: String::new(),
                bytes_scanned: 0,
                scanned_at: "now".to_string(),
                note: Some(format!("Failed to open process PID {}: {}", pid, e)),
            };
        }
    };

    let mut dump_data = Vec::new();
    let mut current_address: usize = 0;
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    unsafe {
        while VirtualQueryEx(handle, Some(current_address as *const c_void), &mut mbi, mbi_size) != 0 {
            if dump_data.len() >= limit_bytes {
                break;
            }

            let is_committed = mbi.State == MEM_COMMIT;
            let prot = mbi.Protect;
            let is_guarded = (prot & PAGE_GUARD) != windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            let is_no_access = (prot & PAGE_NOACCESS) != windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);

            let is_readable = (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                               != windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);

            if is_committed && !is_guarded && !is_no_access && is_readable {
                let to_read = (mbi.RegionSize).min(limit_bytes.saturating_sub(dump_data.len()));
                if to_read > 0 {
                    let mut chunk = vec![0u8; to_read];
                    let mut bytes_read: usize = 0;
                    if ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        chunk.as_mut_ptr() as *mut c_void,
                        to_read,
                        Some(&mut bytes_read),
                    ).is_ok() && bytes_read > 0 {
                        chunk.truncate(bytes_read);
                        dump_data.extend_from_slice(&chunk);
                    }
                }
            }

            let next_addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if next_addr <= current_address {
                break;
            }
            current_address = next_addr;
        }

        let _ = CloseHandle(handle);
    }

    if dump_data.is_empty() {
        return MemoryScanReport {
            pid,
            verdict: "Clean".to_string(),
            detections: Vec::new(),
            sha256: String::new(),
            bytes_scanned: 0,
            scanned_at: "now".to_string(),
            note: Some("No readable committed memory pages found in process".to_string()),
        };
    }

    let bytes_scanned = dump_data.len();
    let dump_name = format!("pid_{}_memdump.bin", pid);
    let (verdict, detections, sha256) = scan_bytes(&dump_data, &dump_name);

    MemoryScanReport {
        pid,
        verdict,
        detections,
        sha256,
        bytes_scanned,
        scanned_at: "now".to_string(),
        note: None,
    }
}
