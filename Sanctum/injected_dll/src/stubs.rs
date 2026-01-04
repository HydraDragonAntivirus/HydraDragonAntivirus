//! Stubs that act as callback functions from syscalls.

use crate::{SYSCALL_NUMBER, integrity::get_base_and_sz_ntdll, ipc::send_ipc_to_engine};
use shared_no_std::ghost_hunting::{
    DLLMessage, NtAllocateVirtualMemoryData, NtCreateThreadExData, NtFunction, NtOpenProcessData,
    NtWriteVirtualMemoryData, Syscall, SyscallEventSource,
};
use std::{
    arch::{asm, naked_asm},
    ffi::c_void,
};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Memory::{
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOMBINE,
            PAGE_WRITECOPY,
        },
        Threading::{GetCurrentProcessId, GetProcessId},
        WindowsProgramming::CLIENT_ID,
    },
};

/// Injected DLL routine for examining the arguments passed to ZwOpenProcess and NtOpenProcess from
/// any process this DLL is injected into.
pub fn nt_open_process(
    process_handle: HANDLE,
    desired_access: u32,
    object_attrs: *mut c_void,
    client_id: *mut CLIENT_ID,
) {
    if !client_id.is_null() {
        let target_pid = unsafe { (*client_id).UniqueProcess.0 } as u32;
        let pid = unsafe { GetCurrentProcessId() };

        // Currently only interested in foreign process handles..
        if target_pid != pid {
            println!("PID: {pid}, target: {target_pid}");
            let data = DLLMessage::SyscallWrapper(Syscall::from_sanctum_dll(
                pid,
                NtFunction::NtOpenProcess(NtOpenProcessData {
                    target_pid,
                    desired_mask: desired_access,
                }),
            ));

            // send the telemetry to the engine
            send_ipc_to_engine(data);
        }
    }

    let ssn = *SYSCALL_NUMBER
        .get("ZwOpenProcess")
        .expect("failed to find function hook for ZwOpenProcess");

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") ssn,
            // Use the asm macro to load our registers so that the Rust compiler has awareness of the
            // use of the registers. Loading these by hands caused some instability
            in("rcx") process_handle.0,
            in("rdx") desired_access,
            in("r8") object_attrs,
            in("r9") client_id,

            options(nostack, preserves_flags)
        );
    }
}

/// Syscall hook for ZwAllocateVirtualMemory
pub fn virtual_alloc_ex(
    process_handle: HANDLE,
    base_address: *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) {
    //
    // Check whether we are allocating memory in our own process, or a remote process. For now, we are not interested in
    // self allocations - we can deal with that later. We just want remote process memory allocations for the time being.
    // todo - future do self alloc
    //

    let pid = unsafe { GetCurrentProcessId() };
    let remote_pid = unsafe { GetProcessId(process_handle) };

    // send telemetry in the case of a remote allocation
    if pid != remote_pid {
        let region_size_checked = if region_size.is_null() {
            0
        } else {
            // SAFETY: Null pointer checked above
            unsafe { *region_size }
        };

        let data = NtFunction::NtAllocateVirtualMemory(NtAllocateVirtualMemoryData {
            base_address: base_address as usize,
            dest_pid: remote_pid,
            sz: region_size_checked,
            alloc_type: allocation_type,
            protect_flags: protect,
        });

        let syscall = DLLMessage::SyscallWrapper(Syscall::from_sanctum_dll(pid, data));

        send_ipc_to_engine(syscall);
    }

    // proceed with the syscall
    let ssn = *SYSCALL_NUMBER
        .get("ZwAllocateVirtualMemory")
        .expect("[hook] failed to find function hook for ZwAllocateVirtualMemory");

    let mut result: u32 = 999;
    unsafe {
        asm!(
            "sub rsp, 0x30",            // reserve shadow space + 8 byte ptr as it expects a stack of that size
            "mov [rsp + 0x30], {1}",    // 8 byte ptr + 32 byte shadow space + 8 bytes offset from 5th arg
            "mov [rsp + 0x28], {0}",    // 8 byte ptr + 32 byte shadow space
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x30",

            in(reg) allocation_type,
            in(reg) protect,
            inout("rax") ssn => result,
            in("rcx") process_handle.0,
            in("rdx") base_address,
            in("r8") zero_bits,
            in("r9") region_size,
            options(nostack),
        );

        if result != 0 {
            println!("[hook] [i] Result of ntallocvm: {result}")
        }
    }
}

pub fn nt_write_virtual_memory(
    handle: HANDLE,
    base_address: *mut c_void,
    buffer: *mut c_void,
    buf_len: u32,
    num_b_written: *mut u32,
) {
    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html

    let pid = unsafe { GetCurrentProcessId() };
    let remote_pid = unsafe { GetProcessId(handle) };
    let base_addr_as_usize = base_address as usize;
    let buf_len_as_usize = buf_len as usize;

    // todo inspect buffer for signature of malware
    // todo inspect buffer  for magic bytes + dos header, etc

    let data = Syscall::from_sanctum_dll(
        pid,
        NtFunction::NtWriteVirtualMemory(NtWriteVirtualMemoryData {
            target_pid: remote_pid,
            base_address: base_addr_as_usize,
            buf_len: buf_len_as_usize,
        }),
    );

    send_ipc_to_engine(DLLMessage::SyscallWrapper(data));

    // proceed with the syscall
    let ssn = *SYSCALL_NUMBER
        .get("NtWriteVirtualMemory")
        .expect("failed to find function hook for NtWriteVirtualMemory");

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {0}",
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x30",

            in(reg) num_b_written,
            in("rax") ssn,
            in("rcx") handle.0,
            in("rdx") base_address,
            in("r8") buffer,
            in("r9") buf_len,
            options(nostack),
        );
    }
}

pub fn nt_protect_virtual_memory(
    handle: HANDLE,
    base_address: *const usize,
    no_bytes_to_protect: *const u32,
    new_access_protect: u32,
    old_protect: *const usize,
) {
    // Is the process trying to change the protection of NTDLL? If so, that is bad
    // and we do not want to allow that to happen in any circumstance.
    let (base_of_ntdll, size_of_text_sec) = get_base_and_sz_ntdll();

    if base_address.is_null() {
        println!("[sanctum] [-] Base address was null, invalid operation.");
        return;
    }

    let target_base = unsafe { *base_address };
    let target_end = target_base + unsafe { *no_bytes_to_protect } as usize;

    let monitor_from = base_of_ntdll + 372; // account for some weird thing
    let end_of_ntdll: usize = monitor_from + size_of_text_sec;
    if target_end >= monitor_from && target_end <= end_of_ntdll {
        if new_access_protect & PAGE_EXECUTE_READWRITE.0 == PAGE_EXECUTE_READWRITE.0
            || new_access_protect & PAGE_WRITECOPY.0 == PAGE_WRITECOPY.0
            || new_access_protect & PAGE_WRITECOMBINE.0 == PAGE_WRITECOMBINE.0
            || new_access_protect & PAGE_READWRITE.0 == PAGE_READWRITE.0
            || new_access_protect & PAGE_EXECUTE_WRITECOPY.0 == PAGE_EXECUTE_WRITECOPY.0
        {
            // At this point, we have a few options:
            // 1 - Suspend threads until the EDR tells us what to do
            // 2 - Return an error consistent with what we would get from the syscall, maybe access denied, indicating that
            //      the syscall failed (by returning we do not make the syscall)
            // 3 - Exit the process
            // In all cases - the EDR engine should be notified of the event. For demo purposes, this will not be immediately
            // implemented.
            // In this case - we will simply terminate the process.
            // todo - handle more gracefully in the future.
            println!(
                "[sanctum] [!] NTDLL tampering detected, attempting to alter memory protections on NTDLL. Base address: {:p}, new protect: {:b}. No bytes: {}",
                target_base as *const c_void,
                new_access_protect,
                unsafe { *no_bytes_to_protect }
            );
            std::process::exit(0x12345678);
        }
    }

    // proceed with the syscall
    let ssn = *SYSCALL_NUMBER
        .get("NtProtectVirtualMemory")
        .expect("failed to find function hook for NtProtectVirtualMemory");

    unsafe {
        asm!(
            "sub rsp, 0x30",
            "mov [rsp + 0x28], {0}",
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x30",

            in(reg) old_protect,
            in("rax") ssn,
            in("rcx") handle.0,
            in("rdx") base_address,
            in("r8") no_bytes_to_protect,
            in("r9") new_access_protect,
            options(nostack),
        );
    }
}

pub fn nt_create_thread_ex_intercept(
    thread_handle: *const c_void,
    desired_access: u32,
    oa: *const c_void,
    process_handle: HANDLE,
    start_routine: *const c_void,
    arg: *const c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_sz: usize,
    max_stack_sz: usize,
    attribute_list: *const c_void,
) {
    // All monitoring of this hook is taking place in the kernel, so we just want to send the IPC
    // so we can ghost hunt. We could implement some logic here instead of the kernel if desired.. tbh
    // I would only do that at this point now we can use Alt Syscalls if we needed to for performance reasons.

    let pid = unsafe { GetCurrentProcessId() };
    let remote_pid = unsafe { GetProcessId(process_handle) };

    if pid != remote_pid {
        let data = Syscall::from_sanctum_dll(
            pid,
            NtFunction::NtCreateThreadEx(NtCreateThreadExData {
                target_pid: remote_pid,
                start_routine: start_routine as usize,
                argument: arg as usize,
            }),
        );

        send_ipc_to_engine(DLLMessage::SyscallWrapper(data));
    }

    // proceed with the syscall
    let ssn = *SYSCALL_NUMBER
        .get("NtCreateThreadEx")
        .expect("failed to find function hook for NtCreateThreadEx");

    nt_create_thread_ex_naked(
        thread_handle,
        desired_access,
        oa,
        process_handle.0,
        start_routine,
        arg,
        create_flags,
        zero_bits,
        stack_sz,
        max_stack_sz,
        attribute_list,
        ssn,
    );
}

#[unsafe(naked)]
extern "system" fn nt_create_thread_ex_naked(
    thread_handle: *const c_void,
    desired_access: u32,
    oa: *const c_void,
    process_handle: *const c_void,
    start_routine: *const c_void,
    arg: *const c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_sz: usize,
    max_stack_sz: usize,
    attribute_list: *const c_void,
    ssn: u32,
) {
    naked_asm!("mov r10, rcx", "mov eax, [rsp+0x60]", "syscall", "ret",)
}
