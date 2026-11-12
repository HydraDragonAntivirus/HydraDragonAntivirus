//! The `AltSyscalls` module is designed merely as the intercept mechanism for using Alternate Syscalls on Windows 11.
//! This module also defines the callback routine for handling the first stage interception; but actual post-processing of the data
//! is conducted elsewhere (in the case where we do not want to block a certain action).
//!
//! Currently; the Alt Syscalls mechanism is not designed to block activity - but it could be refactored in the future to do so
//! in certain situations.
//!
//! The mechanism of post processing [`queue_syscall_post_processing`] is using queued `wdk_mutex` and offloading the work to a system worker thread within
//! the driver, as to not degrade system performance.

use core::{
    arch::asm,
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicUsize, Ordering},
};

use alloc::{boxed::Box, vec::Vec};
use wdk::{nt_success, println};
use wdk_sys::{
    _KTRAP_FRAME,
    _MODE::KernelMode,
    BOOLEAN, DISPATCHER_HEADER, DRIVER_OBJECT, HANDLE, KTRAP_FRAME, NTSTATUS, OBJ_KERNEL_HANDLE,
    PETHREAD, PKTHREAD, PROCESS_ALL_ACCESS, PsProcessType, PsThreadType, THREAD_ALL_ACCESS,
    UNICODE_STRING,
    ntddk::{
        IoGetCurrentProcess, IoThreadToProcess, MmGetSystemRoutineAddress, ObOpenObjectByPointer,
        ObReferenceObjectByHandle, ObfDereferenceObject, RtlInitUnicodeString, ZwClose,
    },
};

use crate::{
    core::syscall_processing::{AllowSyscall, KernelSyscallIntercept},
    ffi::{ZwGetNextProcess, ZwGetNextThread},
    utils::{
        DriverError, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
        ModuleImageBaseInfo, get_module_base_and_sz, get_process_name, image_sections,
        scan_module_for_byte_pattern, thread_to_process_name,
    },
};

const SLOT_ID: u32 = 0;
const SSN_COUNT: usize = 0x500;

pub const SSN_NT_OPEN_PROCESS: u32 = 0x26;
pub const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;

// NtOpenProcess / NtAllocateVirtualMemory / NtWriteVirtualMemory are identical on Win10 19041 and Win11 26100/26200,
// but NtCreateThreadEx is not (hfiref0x/SyscallTables): 0xC2 on Win10 2004-22H2, 0xC9 on Win11 24H2/25H2. On Win10,
// 0xC9 is NtCreateUserProcess, so a hardcoded 0xC9 would decode its arguments as NtCreateThreadEx's.
const SSN_NT_CREATE_THREAD_EX_WIN10_2004: u32 = 0x00c2;
const SSN_NT_CREATE_THREAD_EX_WIN11_24H2: u32 = 0x00c9;
/// Set once the mechanism is chosen; `u32::MAX` never matches a real SSN.
static SSN_NT_CREATE_THREAD_EX: AtomicU32 = AtomicU32::new(u32::MAX);

/// The `NtCreateThreadEx` SSN for the running kernel (only meaningful once Alt Syscalls are initialised).
#[inline]
pub fn ssn_nt_create_thread_ex() -> u32 {
    SSN_NT_CREATE_THREAD_EX.load(Ordering::Relaxed)
}
pub const SSN_NT_WRITE_VM: u32 = 0x003a;

const NT_OPEN_FILE: u32 = 0x0033;
const NT_CREATE_SECTION: u32 = 0x004a;
const NT_CREATE_SECTION_EX: u32 = 0x00c6;
const NT_DEVICE_IO_CONTROL_FILE: u32 = 0x0007;
const NT_CREATE_FILE_SSN: u32 = 0x0055;
const NT_TRACE_EVENT_SSN: u32 = 0x005e;

pub struct AltSyscalls;

static ALT_SYSCALLS_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Which Alt Syscall implementation the running kernel uses (and which one we installed).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
enum AltSyscallMechanism {
    None = 0,
    /// Windows 10 (< 22000): exported `PsRegisterAltSystemCallHandler` fills `PspAltSystemCallHandlers[1]`, which
    /// `KiSystemServiceUser -> PsAltSystemCallDispatch` calls with the thread's real `KTRAP_FRAME`. Enabled per process
    /// with `NtSetInformationProcess(ProcessAltSystemCallInformation)` and per thread with `DebugActive |= 0x20`.
    LegacyHandler = 1,
    /// Windows 11 24H2+ (>= 26100): syscall providers, `PsSyscallProviderDispatch` + `PspServiceDescriptorGroupTable`.
    ProviderTable = 2,
}

static ALT_SYSCALL_MECHANISM: AtomicU8 = AtomicU8::new(AltSyscallMechanism::None as u8);

/// `&PspAltSystemCallHandlers[0]` for the legacy mechanism, so it can be cleared on unload (there is no unregister API,
/// and a stale pointer into an unloaded driver would bugcheck on the next alt syscall).
static LEGACY_HANDLER_TABLE: AtomicPtr<AtomicUsize> = AtomicPtr::new(null_mut());

/// The only index `PsRegisterAltSystemCallHandler` accepts for third parties (0 is reserved and bugchecks, >= 2 fails).
const LEGACY_HANDLER_INDEX: usize = 1;
/// `PROCESSINFOCLASS::ProcessAltSystemCallInformation`
const PROCESS_ALT_SYSTEM_CALL_INFORMATION: u32 = 0x64;

/// Win10 2004 (20H1). 20H1 - 22H2 (19041 - 19045) share one kernel syscall table.
const BUILD_WIN10_2004: u32 = 19041;
const BUILD_WIN11_21H2: u32 = 22000;
const BUILD_WIN11_24H2: u32 = 26100;

type PsRegisterAltSystemCallHandlerFn =
    unsafe extern "system" fn(handler: *const c_void, handler_index: i32) -> NTSTATUS;

unsafe extern "system" {
    fn PsGetVersion(
        MajorVersion: *mut u32,
        MinorVersion: *mut u32,
        BuildNumber: *mut u32,
        CSDVersion: *mut UNICODE_STRING,
    ) -> BOOLEAN;

    fn ZwSetInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
    ) -> NTSTATUS;
}

fn kernel_build_number() -> u32 {
    let mut major = 0u32;
    let mut minor = 0u32;
    let mut build = 0u32;
    unsafe {
        PsGetVersion(&mut major, &mut minor, &mut build, null_mut());
    }
    build
}

fn current_mechanism() -> AltSyscallMechanism {
    match ALT_SYSCALL_MECHANISM.load(Ordering::Acquire) {
        1 => AltSyscallMechanism::LegacyHandler,
        2 => AltSyscallMechanism::ProviderTable,
        _ => AltSyscallMechanism::None,
    }
}

#[repr(C)]
pub struct PspServiceDescriptorGroupTable {
    rows: [PspServiceDescriptorRow; 0x20],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PspServiceDescriptorRow {
    driver_base: *const c_void,
    ssn_dispatch_table: *const AltSyscallDispatchTable,
    _reserved: *const c_void,
}

#[repr(C)]
struct PspSyscallProviderDispatchContext {
    level: u32,
    slot: u32,
}

#[repr(C)]
struct AltSyscallDispatchTable {
    pub count: u64,
    pub descriptors: [u32; SSN_COUNT],
}

#[derive(Copy, Clone)]
pub enum AltSyscallStatus {
    Enable,
    Disable,
}

impl AltSyscalls {
    /// Initialises the required tables in memory.
    ///
    /// This function should only be called once until it is disabled.
    pub fn initialise_for_system(driver: &mut DRIVER_OBJECT) {
        if ALT_SYSCALLS_INITIALISED.load(Ordering::SeqCst) {
            return;
        }

        // Supported builds:
        //
        // - Windows 10 2004 - 22H2 (19041 - 19045): legacy `PsRegisterAltSystemCallHandler`. Older Windows 10 builds
        //   are untested (BEOTM only validated 22H2) and have different SSNs, so they are left disabled.
        // - Windows 11 21H2 - 23H2 (22000 - 26099): unsupported. Two independent reasons, both verified against
        //   the actual kernel binaries (22000.194, 22000.3260, 22621.382):
        //     1. The legacy `PsRegisterAltSystemCallHandler` table is still filled by the exported function, but
        //        nothing dispatches through it any more (Xacone/BestEdrOfTheMarket#18; author retracted compat
        //        range after confirming).
        //     2. The provider mechanism exists from 22000.3xxx onwards, but `PspServiceDescriptorGroupTable` lives
        //        in the `CFGRO` section on every Win11 build checked. That section is made read-only after boot
        //        and is SLAT-protected under HVCI/KDP, so writing a row into it bugchecks with 0x50 (same as the
        //        original crash on 26100.9974). The safe-write guard below would refuse these builds anyway.
        // - Windows 11 24H2+ (>= 26100): syscall provider table (guarded by the safe-write check).
        let build = kernel_build_number();
        if build >= BUILD_WIN11_24H2 {
            Self::initialise_provider_table(driver);
        } else if (BUILD_WIN10_2004..BUILD_WIN11_21H2).contains(&build) {
            Self::initialise_legacy_handler();
        } else {
            println!(
                "[sanctum] [!] Alt Syscalls are not supported on build {build} (supported: Win10 19041-19045, \
                 Win11 26100+). On Windows 11 21H2-23H2 the legacy PsRegisterAltSystemCallHandler table is no \
                 longer dispatched (BestEdrOfTheMarket#18) and the provider table lives in the read-only CFGRO \
                 section (verified on 22000.3260 and 22621.382). Disabling Alt Syscalls safely."
            );
        }
    }

    /// Windows 10 path: register through the exported `PsRegisterAltSystemCallHandler`.
    fn initialise_legacy_handler() {
        let name: Vec<u16> = "PsRegisterAltSystemCallHandler"
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        let mut us_name = UNICODE_STRING::default();
        unsafe { RtlInitUnicodeString(&mut us_name, name.as_ptr()) };
        let p_register = unsafe { MmGetSystemRoutineAddress(&mut us_name) };
        if p_register.is_null() {
            println!(
                "[sanctum] [-] PsRegisterAltSystemCallHandler is not exported by this kernel; Alt Syscalls disabled."
            );
            return;
        }

        // Resolve PspAltSystemCallHandlers so we can check the slot is free and clear it again on unload.
        let table = match lookup_legacy_handler_table(p_register as *const u8) {
            Ok(t) => t,
            Err(e) => {
                println!(
                    "[sanctum] [-] Could not resolve PspAltSystemCallHandlers: {:?}",
                    e
                );
                return;
            }
        };

        let slot = unsafe { &*table.add(LEGACY_HANDLER_INDEX) };
        let handler = legacy_syscall_handler as *const c_void;
        let existing = slot.load(Ordering::SeqCst);
        if existing != 0 && existing != handler as usize {
            println!(
                "[sanctum] [-] PspAltSystemCallHandlers[{LEGACY_HANDLER_INDEX}] already owned by another driver ({existing:#x}); Alt Syscalls disabled."
            );
            return;
        }

        if existing == 0 {
            let register: PsRegisterAltSystemCallHandlerFn =
                unsafe { core::mem::transmute(p_register) };
            let status = unsafe { register(handler, LEGACY_HANDLER_INDEX as i32) };
            if !nt_success(status) {
                println!("[sanctum] [-] PsRegisterAltSystemCallHandler failed: {status:#x}");
                return;
            }
        }

        SSN_NT_CREATE_THREAD_EX.store(SSN_NT_CREATE_THREAD_EX_WIN10_2004, Ordering::SeqCst);
        LEGACY_HANDLER_TABLE.store(table as *mut AtomicUsize, Ordering::SeqCst);
        ALT_SYSCALL_MECHANISM.store(AltSyscallMechanism::LegacyHandler as u8, Ordering::SeqCst);
        ALT_SYSCALLS_INITIALISED.store(true, Ordering::SeqCst);
        println!(
            "[sanctum] [+] Alt Syscalls enabled via legacy PsRegisterAltSystemCallHandler (Windows 10)."
        );
    }

    /// Windows 11 24H2+ path: insert a row into `PspServiceDescriptorGroupTable`.
    fn initialise_provider_table(driver: &mut DRIVER_OBJECT) {
        // How many stack args we want to memcpy; I use my own method to get these..
        const NUM_QWORD_STACK_ARGS_TO_CPY: u32 = 0x0;
        // These flags ensure we go the PspSyscallProviderServiceDispatchGeneric route
        const GENERIC_PATH_FLAGS: u32 = 0x10;

        // Enforce the SLOT_ID rules at compile time
        const _: () = assert!(SLOT_ID <= 20, "SLOT_ID for alt syscalls cannot be > 20");

        //
        // Get the base address of the driver, so that we can bit shift in the RVA of the callback.
        //
        let driver_base = match get_module_base_and_sz("sanctum.sys") {
            Ok(info) => info.base_address,
            Err(e) => {
                println!("[-] Could not get base address of driver. {:?}", e);
                return;
            }
        };

        // Get the address of PspServiceDescriptorGroupTable from the kernel by doing some pattern matching; I don't believe
        // we can link to the symbol. Resolved (and validated as writable) before allocating anything, so an unsupported
        // kernel build bails out cleanly without leaking the metadata table.
        let kernel_service_descriptor_table = match lookup_global_table_address(driver) {
            Ok(t) => t as *mut PspServiceDescriptorGroupTable,
            Err(_) => {
                println!("[sanctum] failed to find kernel table");
                return;
            }
        };

        //
        // Now build the 'mini dispatch table':  one per descriptor. Each index of the descriptor contains a relative pointer from the driver base
        // address to the callback function.
        //
        // low–4 bits   = metadata (0x10 = generic path + N args to capture via a later memcpy),
        // high bits    = descriptor index<<4.
        //
        // Setting FLAGS |= (METADATA & 0xF) means generic path, capture N args
        //
        let callback_address = syscall_handler as *const c_void as usize;
        let metadata_table = Box::new(AltSyscallDispatchTable {
            count: SSN_COUNT as _,
            descriptors: [0; SSN_COUNT],
        });

        // Leak the box so that we don't (for now) have to manage the memory; yes, this is a memory leak in the kernel, I'll fix it later.
        let p_metadata_table = Box::leak(metadata_table) as *const AltSyscallDispatchTable;

        let rva_offset_callback = callback_address - driver_base as usize;
        // SAFETY: Check the offset size will fit into a u32
        if rva_offset_callback > u32::MAX as _ {
            println!(
                "[sanctum] [-] Offset calculation very wrong? Offset: {:#x}",
                rva_offset_callback
            );
            return;
        }

        for i in 0..SSN_COUNT {
            unsafe { &mut *(p_metadata_table as *mut AltSyscallDispatchTable) }.descriptors[i] =
                ((rva_offset_callback as u32) << 4)
                    | (GENERIC_PATH_FLAGS | (NUM_QWORD_STACK_ARGS_TO_CPY & 0xF));
        }

        //
        // Insert a new row at index 0 in the PspServiceDescriptorGroupTable; in theory, if these were already occupied by other software
        // using alt syscalls, we would want to find an unoccupied slot.
        // This is what the Slot field relates to on the _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT of _EPROCESS - essentially an index into which
        // syscall provider to use.
        //
        let new_row = PspServiceDescriptorRow {
            driver_base,
            ssn_dispatch_table: p_metadata_table,
            _reserved: core::ptr::null(),
        };

        // Write it to the table
        unsafe {
            (*kernel_service_descriptor_table).rows[SLOT_ID as usize] = new_row;
        }

        SSN_NT_CREATE_THREAD_EX.store(SSN_NT_CREATE_THREAD_EX_WIN11_24H2, Ordering::SeqCst);
        ALT_SYSCALL_MECHANISM.store(AltSyscallMechanism::ProviderTable as u8, Ordering::SeqCst);
        ALT_SYSCALLS_INITIALISED.store(true, Ordering::SeqCst);

        // Enumerate all active processes and threads, and enable the relevant bits so that the alt syscall 'machine' can work :)
        // Self::walk_active_processes_and_set_bits(AltSyscallStatus::Enable, None);
    }

    /// Sets the required context bits in memory on thread and KTHREAD.
    pub fn configure_thread_for_alt_syscalls(p_k_thread: PKTHREAD, status: AltSyscallStatus) {
        if !ALT_SYSCALLS_INITIALISED.load(Ordering::Relaxed) {
            return;
        }
        if p_k_thread.is_null() {
            return;
        }

        // Check if is pico process, if it is, we don't want to mess with it, as I haven't spent time reversing the branch
        // for this in PsSyscallProviderDispatch.
        let dispatch_hdr = unsafe { &mut *(p_k_thread as *mut DISPATCHER_HEADER) };

        if unsafe {
            dispatch_hdr
                .__bindgen_anon_1
                .__bindgen_anon_6
                .__bindgen_anon_2
                .DebugActive
                & 4
        } == 4
        {
            return;
        }

        // Assuming now we are not a pico-process; set / unset the AltSyscall bit on the ETHREAD depending upon
        // the `status` argument to this function.
        unsafe {
            match status {
                AltSyscallStatus::Enable => {
                    dispatch_hdr
                        .__bindgen_anon_1
                        .__bindgen_anon_6
                        .__bindgen_anon_2
                        .DebugActive |= 0x20
                }
                AltSyscallStatus::Disable => {
                    dispatch_hdr
                        .__bindgen_anon_1
                        .__bindgen_anon_6
                        .__bindgen_anon_2
                        .DebugActive &= !0x20
                }
            }
        }
    }

    pub fn configure_process_for_alt_syscalls(p_k_thread: PKTHREAD, status: AltSyscallStatus) {
        if !ALT_SYSCALLS_INITIALISED.load(Ordering::Relaxed) || p_k_thread.is_null() {
            return;
        }

        if current_mechanism() == AltSyscallMechanism::LegacyHandler {
            // Windows 10: the process opt-in is a documented-shape info class rather than an EPROCESS offset.
            let p_eprocess = unsafe { IoThreadToProcess(p_k_thread as PETHREAD) };
            if p_eprocess.is_null() {
                return;
            }
            let mut h_process: HANDLE = null_mut();
            let st = unsafe {
                ObOpenObjectByPointer(
                    p_eprocess as *mut _,
                    OBJ_KERNEL_HANDLE,
                    null_mut(),
                    PROCESS_ALL_ACCESS,
                    *PsProcessType,
                    KernelMode as _,
                    &mut h_process,
                )
            };
            if nt_success(st) && !h_process.is_null() {
                Self::configure_process_handle(h_process, status);
                let _ = unsafe { ZwClose(h_process) };
            }
            return;
        }

        if current_mechanism() != AltSyscallMechanism::ProviderTable {
            return;
        }

        // We can cast the KTHREAD* as a ETHREAD* as KTHREAD = ETHREAD bytes 0x0 - 0x4c0
        // so they directly map.
        // We will cast the resulting EPROCESS as a *mut u8 as EPROCESS is not defined by the Windows API, and we can just use
        // some pointer arithmetic to edit the fields we want.
        let p_eprocess = unsafe { IoThreadToProcess(p_k_thread as PETHREAD) } as *mut u8;
        let syscall_provider_dispatch_ctx: &mut PspSyscallProviderDispatchContext =
            if !p_eprocess.is_null() {
                unsafe {
                    let addr = p_eprocess.add(0x7d0) as *mut PspSyscallProviderDispatchContext;
                    // SAFETY: I think the dereference of this is fine; we are dereferencing an offset from the EPROCESS - it is not a double pointer.
                    // We check the validity of the EPROCESS above before doing this, as that should always be valid. But this deref should be safe.
                    &mut *addr
                }
            } else {
                return;
            };

        // Set slot id
        syscall_provider_dispatch_ctx.slot = SLOT_ID;
    }

    /// Legacy (Windows 10) only: opt a process in / out of alt syscall dispatch through an already-open kernel
    /// process handle (`ZwSetInformationProcess(ProcessAltSystemCallInformation)`, which also flips the
    /// `DebugActive` alt-syscall bit on the process's existing threads). No-op for every other mechanism.
    pub fn configure_process_handle(h_process: HANDLE, status: AltSyscallStatus) {
        if !ALT_SYSCALLS_INITIALISED.load(Ordering::Relaxed)
            || current_mechanism() != AltSyscallMechanism::LegacyHandler
            || h_process.is_null()
        {
            return;
        }

        // A one-byte BOOLEAN; any non-zero value enables.
        let mut enable: u8 = match status {
            AltSyscallStatus::Enable => 1,
            AltSyscallStatus::Disable => 0,
        };
        let st = unsafe {
            ZwSetInformationProcess(
                h_process,
                PROCESS_ALT_SYSTEM_CALL_INFORMATION,
                &mut enable as *mut u8 as *mut c_void,
                1,
            )
        };
        if !nt_success(st) {
            println!("[sanctum] [-] ProcessAltSystemCallInformation failed: {st:#x}");
        }
    }

    /// Uninstall the Alt Syscall handlers from the kernel.
    pub fn uninstall() {
        if !ALT_SYSCALLS_INITIALISED.load(Ordering::SeqCst) {
            return;
        }
        // Clear the per-process / per-thread bits while the mechanism is still known, then mark uninitialised.
        Self::walk_active_processes_and_set_bits(AltSyscallStatus::Disable, None);
        ALT_SYSCALLS_INITIALISED.store(false, Ordering::SeqCst);

        if current_mechanism() == AltSyscallMechanism::LegacyHandler {
            // There is no unregister export; clear our slot (only if it is still ours) so the kernel never calls
            // into this driver's image after it is unloaded. The table is in writable `.data`, validated at init.
            let table = LEGACY_HANDLER_TABLE.swap(null_mut(), Ordering::SeqCst);
            if !table.is_null() {
                let slot = unsafe { &*table.add(LEGACY_HANDLER_INDEX) };
                let _ = slot.compare_exchange(
                    legacy_syscall_handler as *const c_void as usize,
                    0,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
        }

        ALT_SYSCALL_MECHANISM.store(AltSyscallMechanism::None as u8, Ordering::SeqCst);

        // todo clean up the allocated memory
    }

    /// Walk all processes and threads, and set the bits on the process & thread to either enable or disable the
    /// alt syscall method.
    ///
    /// # Args:
    /// - `status`: Whether you wish to enable, or disable the feature
    /// - `isolated_processes`: If you wish just to set the relevant bits on a single process; then add a vec of process names
    /// to match on, with a *name* logic.
    ///
    /// # Note:
    /// This function is specifically crafted for W11 23H2 / 24H2; to generalise in the future after POC
    fn walk_active_processes_and_set_bits(
        status: AltSyscallStatus,
        isolated_processes: Option<&[&str]>,
    ) {
        let current_process = unsafe { IoGetCurrentProcess() };
        if current_process.is_null() {
            println!("[sanctum] [-] current_process was NULL");
            return;
        }

        //
        // Walk the active processes & threads via reference counting to ensure that the
        // threads & processes aren't terminated during the walk (led to race condition).
        //
        // For each process & thread, enable to relevant bits for Alt Syscalls.
        //

        let mut next_proc: HANDLE = null_mut();
        let mut cur_proc: HANDLE = null_mut();
        let mut cur_thread: HANDLE = null_mut();
        let mut next_thread: HANDLE = null_mut();

        loop {
            // ZwGetNextProcess automatically closes the handle passed in cur_proc when acquiring next_proc.
            let result = unsafe {
                ZwGetNextProcess(
                    cur_proc,
                    PROCESS_ALL_ACCESS,
                    OBJ_KERNEL_HANDLE,
                    0,
                    &mut next_proc,
                )
            };

            if result != 0 || cur_proc == next_proc {
                break;
            }

            cur_proc = next_proc;

            // Now walk the threads of the process
            cur_thread = null_mut();
            loop {
                // ZwGetNextThread automatically closes the handle passed in cur_thread when acquiring next_thread.
                let result = unsafe {
                    ZwGetNextThread(
                        cur_proc,
                        cur_thread,
                        THREAD_ALL_ACCESS,
                        OBJ_KERNEL_HANDLE,
                        0,
                        &mut next_thread,
                    )
                };

                if result != 0 || cur_thread == next_thread {
                    break;
                }

                cur_thread = next_thread;

                let mut pe_thread: *mut c_void = null_mut();

                let _ = unsafe {
                    ObReferenceObjectByHandle(
                        cur_thread,
                        THREAD_ALL_ACCESS,
                        *PsThreadType,
                        KernelMode as _,
                        &mut pe_thread,
                        null_mut(),
                    )
                };

                if !pe_thread.is_null() {
                    // Before we actually go ahead and set the bits; check whether the caller is requesting the bits
                    // set ONLY on certain processes. If None, set all process & thread info.
                    if let Some(proc_vec) = &isolated_processes {
                        match thread_to_process_name(pe_thread as *mut _) {
                            Ok(current_process_name) => {
                                for needle in proc_vec.iter() {
                                    if current_process_name
                                        .to_lowercase()
                                        .contains(&needle.to_lowercase())
                                    {
                                        println!(
                                            "[sanctum] [+] Process name found for alt syscalls: {}",
                                            needle
                                        );
                                        Self::configure_thread_for_alt_syscalls(
                                            pe_thread as *mut _,
                                            status,
                                        );
                                        Self::configure_process_for_alt_syscalls(
                                            pe_thread as *mut _,
                                            status,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "[sanctum] [-] Unable to get process name to set alt syscall bits on targeted process. {:?}",
                                    e
                                );
                            }
                        }
                    } else {
                        Self::configure_thread_for_alt_syscalls(pe_thread as *mut _, status);
                        Self::configure_process_for_alt_syscalls(pe_thread as *mut _, status);
                    }

                    let _ = unsafe { ObfDereferenceObject(pe_thread) };
                }
            }
        }
    }
}

/// A local definition of a KTHREAD, seeing as though the WDK doesn't export one for us. If this changes
/// between kernel builds, it will cause problems :E
#[repr(C)]
struct KThreadLocalDef {
    junk: [u8; 0x90],
    k_trap_ptr: *mut KTRAP_FRAME,
}

#[inline(always)]
fn extract_trap() -> Option<*const _KTRAP_FRAME> {
    let mut k_thread: *const c_void = null_mut();
    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) k_thread,
        );
    }

    if k_thread.is_null() {
        println!("[-] [Sanctum] No KTHREAD discovered.");
        return None;
    }

    let p_ktrap = unsafe { &*(k_thread as *const KThreadLocalDef) }.k_trap_ptr;

    Some(p_ktrap)
}

/// The callback routine which we control to run when a system call is dispatched via my alt syscall technique.
///
/// # Args:
/// - `p_nt_function`: A function pointer to the real Nt* dispatch function (e.g. NtOpenProcess)
/// - `ssn`: The System Service Number of the syscall
/// - `args_base`: The base address of the args passed into the original syscall rcx, rdx, r8 and r9
/// - `p3_home`: The address of `P3Home` of the _KTRAP_FRAME
///
/// # Note:
/// We can use the `p3_home` arg that is passed into this callback to calculate the actual address of the
/// `KTRAP_FRAME`, where we can get the address of the stack pointer, that we can use to gather any additional
/// arguments which were passed into the syscall.
///
/// # Safety
/// This function is **NOT** compatible with the `PspSyscallProviderServiceDispatch` branch of alt syscalls, it
/// **WILL** result in a bug check in that instance. This can only be used with
/// `PspSyscallProviderServiceDispatchGeneric`.
pub unsafe extern "system" fn syscall_handler(
    _p_nt_function: c_void,
    ssn: u32,
    _args_base: *const c_void,
    _p3_home: *const c_void,
) -> i32 {
    // Cheap name gate before touching the trap frame (see `intercept_syscall`).
    let proc_name = get_process_name().to_lowercase();
    if !proc_name.contains("notepad.e") && !proc_name.contains("alware.e") {
        return 1;
    }

    let ktrap_frame = match extract_trap() {
        Some(p) => unsafe { *p },
        None => {
            println!("[-] [sanctum] Could not get trap for syscall intercept.");
            return 1;
        }
    };

    intercept_syscall(ssn, ktrap_frame) as i32
}

/// Get the address of the non-exported kernel symbol: `PspServiceDescriptorGroupTable`
fn lookup_global_table_address(_driver: &DRIVER_OBJECT) -> Result<*mut c_void, DriverError> {
    let module = match get_module_base_and_sz("ntoskrnl.exe") {
        Ok(k) => k,
        Err(e) => {
            println!("[sanctum] [-] Unable to get kernel base address. {:?}", e);
            return Err(DriverError::ModuleNotFound);
        }
    };

    let fn_address = scan_module_for_byte_pattern(
        module.base_address,
        module.size_of_image,
        &[
            // from nt!PsSyscallProviderDispatch
            0x48, 0x89, 0x5c, 0x24, 0x08, //mov     qword ptr [rsp+8], rbx
            0x55, // push    rbp
            0x56, // push    rsi
            0x57, // push    rdi
            0x41, 0x56, // push    r14
            0x41, 0x57, // push    r15
            0x48, 0x83, 0xec, 0x30, // sub     rsp, 30h
            0x48, 0x83, 0x64, 0x24, 0x70, 0x00, // and     qword ptr [rsp+70h], 0
            0x48, 0x8b, 0xf1, // mov     rsi, rcx
            0x65, 0x48, 0x8b, 0x2c, 0x25, 0x88, 0x01, 0x00,
            0x00, // mov     rbp, qword ptr gs:[188h]
            0xf6, 0x45, 0x03, 0x04, // test    byte ptr [rbp+3], 4
        ],
    )? as *const u8;

    // offset from fn
    let instruction_address = unsafe { fn_address.add(0x77) };

    // The instruction at +0x77 must be `lea r64, [rip+disp32]` (REX.W 8D /r, mod=00 rm=101), e.g.
    // `48 8d 0d xx xx xx xx  lea rcx, [nt!PspServiceDescriptorGroupTable]`. If a kernel update moves it, we must not
    // decode random bytes as a displacement and then write through the result.
    let opcode = unsafe { core::slice::from_raw_parts(instruction_address, 3) };
    if !matches!(opcode[0], 0x48 | 0x4c) || opcode[1] != 0x8d || (opcode[2] & 0xc7) != 0x05 {
        println!(
            "[sanctum] [-] PsSyscallProviderDispatch+0x77 is not `lea r64, [rip+disp32]` ({:02x?}); unsupported kernel build.",
            opcode
        );
        return Err(DriverError::UnexpectedSignature(
            "PsSyscallProviderDispatch layout changed".into(),
        ));
    }

    let disp32 =
        unsafe { core::ptr::read_unaligned((instruction_address.add(3)) as *const i32) } as isize;
    let next_rip = instruction_address as isize + 7;
    let absolute = (next_rip + disp32) as *const c_void;

    // See `is_runtime_writable_kernel_global` for why this check is what prevents the 0x50 bugcheck on newer
    // 26100-family kernels, where the table lives in the read-only-after-boot `CFGRO` section.
    is_runtime_writable_kernel_global(
        &module,
        absolute,
        size_of::<PspServiceDescriptorGroupTable>(),
        "PspServiceDescriptorGroupTable",
    )?;

    Ok(absolute as *mut _)
}

/// Kernel sections that ntoskrnl keeps writable after boot.
const RUNTIME_WRITABLE_SECTIONS: [&[u8]; 3] = [b".data", b"ALMOSTRO", b"CACHEALI"];

/// Refuse to write to a kernel global unless all `len` bytes at `address` sit inside a section the kernel genuinely
/// keeps writable at runtime.
///
/// On newer 26100-family kernels (e.g. 26100.9974 / 26200) PspServiceDescriptorGroupTable was moved into the `CFGRO`
/// section, which the kernel makes read-only once boot initialisation completes (and which HVCI/KDP protect at the
/// SLAT level). Writing a row into it there bugchecks with PAGE_FAULT_IN_NONPAGED_AREA (0x50) on a write to
/// nt+<table RVA>. The PE section characteristics alone are not enough (CFGRO is flagged MEM_WRITE in the file), so
/// only an allow-list of runtime-writable sections is accepted.
fn is_runtime_writable_kernel_global(
    module: &ModuleImageBaseInfo,
    address: *const c_void,
    len: usize,
    what: &str,
) -> Result<(), DriverError> {
    let rva = (address as usize).wrapping_sub(module.base_address as usize);
    let sections = image_sections(module.base_address, module.size_of_image)?;
    let section = sections.iter().find(|s| s.contains_rva(rva, len));

    match section {
        Some(s)
            if s.characteristics & IMAGE_SCN_MEM_WRITE != 0
                && s.characteristics & IMAGE_SCN_MEM_DISCARDABLE == 0
                && RUNTIME_WRITABLE_SECTIONS.contains(&s.name()) =>
        {
            Ok(())
        }
        other => {
            println!(
                "[sanctum] [-] {} (nt+{:#x}) is in a read-only / protected section ({:?});                  Alt Syscalls cannot be enabled safely on this kernel build.",
                what,
                rva,
                other.map(|s| core::str::from_utf8(s.name()).unwrap_or("?"))
            );
            Err(DriverError::UnexpectedSignature(alloc::format!(
                "{what} is not in writable kernel memory"
            )))
        }
    }
}

/// Resolve `PspAltSystemCallHandlers` (Windows 10) from the exported `PsRegisterAltSystemCallHandler`, which loads the
/// table with a RIP-relative `lea` (e.g. `4c 8d 35 xx xx xx xx  lea r14, [nt!PspAltSystemCallHandlers]`).
///
/// Every `lea r64, [rip+disp32]` in the first 0x100 bytes is considered; the first whose target is a 2-entry pointer
/// table inside a runtime-writable kernel data section wins. Nothing is decoded outside the function's own section.
fn lookup_legacy_handler_table(p_register: *const u8) -> Result<*const AtomicUsize, DriverError> {
    let module = get_module_base_and_sz("ntoskrnl.exe").map_err(|e| {
        println!("[sanctum] [-] Unable to get kernel base address. {:?}", e);
        DriverError::ModuleNotFound
    })?;

    let fn_rva = (p_register as usize).wrapping_sub(module.base_address as usize);
    let sections = image_sections(module.base_address, module.size_of_image)?;
    let code = sections
        .iter()
        .find(|s| s.contains_rva(fn_rva, 1) && s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .ok_or(DriverError::FunctionNotFoundInModule)?;

    let scan_len = (code.start + code.size - fn_rva).min(0x100);
    // SAFETY: bounded to the (resident, executable) section containing the exported function.
    let bytes = unsafe { core::slice::from_raw_parts(p_register, scan_len) };
    let table_len = (LEGACY_HANDLER_INDEX + 1) * size_of::<usize>();

    for k in 0..scan_len.saturating_sub(7) {
        let b = &bytes[k..k + 7];
        if !matches!(b[0], 0x48 | 0x4c) || b[1] != 0x8d || (b[2] & 0xc7) != 0x05 {
            continue;
        }
        let disp32 = i32::from_le_bytes([b[3], b[4], b[5], b[6]]) as isize;
        let target = (p_register as isize + k as isize + 7 + disp32) as *const c_void;
        let rva = (target as usize).wrapping_sub(module.base_address as usize);
        if sections.iter().any(|s| {
            s.contains_rva(rva, table_len)
                && s.characteristics & IMAGE_SCN_MEM_WRITE != 0
                && s.characteristics & IMAGE_SCN_MEM_DISCARDABLE == 0
                && RUNTIME_WRITABLE_SECTIONS.contains(&s.name())
        }) {
            return Ok(target as *const AtomicUsize);
        }
    }

    Err(DriverError::UnexpectedSignature(
        "PspAltSystemCallHandlers lea not found in PsRegisterAltSystemCallHandler".into(),
    ))
}

/// Windows 10 alt syscall handler (`PspAltSystemCallHandlers[1]`), called by `PsAltSystemCallDispatch` with a pointer
/// to the thread's real `KTRAP_FRAME`. Returns non-zero to let the system call continue, matching the 24H2 path.
pub unsafe extern "system" fn legacy_syscall_handler(p_trap_frame: *mut KTRAP_FRAME) -> BOOLEAN {
    if p_trap_frame.is_null() {
        return 1;
    }
    let ktrap_frame = unsafe { *p_trap_frame };
    intercept_syscall(ktrap_frame.Rax as u32, ktrap_frame) as BOOLEAN
}

/// Shared policy for both alt syscall mechanisms.
fn intercept_syscall(ssn: u32, ktrap_frame: KTRAP_FRAME) -> AllowSyscall {
    // todo remove once ready for mass testing
    let proc_name = get_process_name().to_lowercase();
    if !proc_name.contains("notepad.e") && !proc_name.contains("alware.e") {
        return AllowSyscall::Yes;
    }

    match ssn {
        SSN_NT_OPEN_PROCESS | SSN_NT_ALLOCATE_VIRTUAL_MEMORY | SSN_NT_WRITE_VM => {
            KernelSyscallIntercept::from_alt_syscall(ktrap_frame)
        }
        ssn if ssn == ssn_nt_create_thread_ex() => {
            KernelSyscallIntercept::from_alt_syscall(ktrap_frame)
        }
        _ => AllowSyscall::Yes,
    }
}
