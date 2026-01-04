// FFI for functions not yet implemented in the Rust Windows Driver project

use core::{arch::asm, ffi::c_void, ptr::null_mut};

use wdk_sys::{
    _EVENT_TYPE::SynchronizationEvent,
    ACCESS_MASK, BOOLEAN, DISPATCH_LEVEL, FALSE, FAST_MUTEX, FM_LOCK_BIT, HANDLE, HANDLE_PTR,
    KPRIORITY, KPROCESSOR_MODE, LIST_ENTRY, NTSTATUS, OBJECT_ATTRIBUTES, PDRIVER_OBJECT, PHANDLE,
    PIO_STACK_LOCATION, PIRP, PKAPC, PKTHREAD, POBJECT_ATTRIBUTES, PRKAPC, PROCESSINFOCLASS,
    PSECURITY_DESCRIPTOR, PSIZE_T, PULONG, PUNICODE_STRING, PVOID, SIZE_T, ULONG,
    ntddk::{KeGetCurrentIrql, KeInitializeEvent},
};

pub unsafe fn IoGetCurrentIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION {
    assert!((*irp).CurrentLocation <= (*irp).StackCount + 1); // todo maybe do error handling instead of an assert?
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
}

#[allow(non_snake_case)]
pub unsafe fn ExInitializeFastMutex(kmutex: *mut FAST_MUTEX) {
    // check IRQL
    let irql = unsafe { KeGetCurrentIrql() };
    assert!(irql as u32 <= DISPATCH_LEVEL);

    core::ptr::write_volatile(&mut (*kmutex).Count, FM_LOCK_BIT as i32);

    (*kmutex).Owner = core::ptr::null_mut();
    (*kmutex).Contention = 0;
    KeInitializeEvent(&mut (*kmutex).Event, SynchronizationEvent, FALSE as _)
}

/// The InitializeObjectAttributes macro initializes the opaque OBJECT_ATTRIBUTES structure,
/// which specifies the properties of an object handle to routines that open handles.
///
/// # Returns
/// This function will return an Err if the POBJECT_ATTRIBUTES is null. Otherwise, it will return
/// Ok(())
#[allow(non_snake_case)]
pub unsafe fn InitializeObjectAttributes(
    p: POBJECT_ATTRIBUTES,
    n: PUNICODE_STRING,
    a: ULONG,
    r: HANDLE,
    s: PSECURITY_DESCRIPTOR,
) -> Result<(), ()> {
    // check the validity of the OBJECT_ATTRIBUTES pointer
    if p.is_null() {
        return Err(());
    }

    (*p).Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    (*p).RootDirectory = r;
    (*p).Attributes = a;
    (*p).ObjectName = n;
    (*p).SecurityDescriptor = s;
    (*p).SecurityQualityOfService = null_mut();

    Ok(())
}

unsafe extern "system" {
    pub unsafe fn PsGetProcessImageFileName(p_eprocess: *const c_void) -> *const c_void;
    pub unsafe fn NtQueryInformationProcess(
        handle: HANDLE,
        flags: i32,
        process_information: *mut c_void,
        len: ULONG,
        return_len: PULONG,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextProcess(
        handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_proc_handle: PHANDLE,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextThread(
        proc_handle: HANDLE,
        thread_handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_thread_handle: PHANDLE,
    ) -> NTSTATUS;

    pub fn KeInitializeApc(
        Apc: PKAPC,
        Thread: PKTHREAD,
        ApcStateIndex: KAPC_ENVIRONMENT,
        KernelRoutine: *const c_void,
        RundownRoutine: *const c_void,
        NormalRoutine: *const c_void,
        ApcMode: KPROCESSOR_MODE,
        NormalContext: PVOID,
    );

    pub fn KeInsertQueueApc(
        Apc: PKAPC,
        SystemArgument1: PVOID,
        SystemArgument2: PVOID,
        Increment: KPRIORITY,
    ) -> BOOLEAN;

    pub unsafe fn PsGetCurrentProcess() -> *const c_void;

    pub fn ZwProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG,
    ) -> NTSTATUS;

    pub fn KeTestAlertThread(AlertMode: KPROCESSOR_MODE);
}

pub type PKNORMAL_ROUTINE = unsafe extern "C" fn(PVOID, PVOID, PVOID);
pub type PKRUNDOWN_ROUTINE = unsafe extern "C" fn(PRKAPC);
pub type PKKERNEL_ROUTINE =
    unsafe extern "C" fn(PRKAPC, PKNORMAL_ROUTINE, *mut PVOID, *mut PVOID, *mut PVOID);

#[repr(C)]
pub enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment,
}

pub type KAPC_ENVIRONMENT = _KAPC_ENVIRONMENT;
pub type PKAPC_ENVIRONMENT = *mut _KAPC_ENVIRONMENT;

#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*mut c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

pub fn GetCurrentThread() -> PKTHREAD {
    let mut k_thread: *const c_void = null_mut();
    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) k_thread,
        );
    }

    k_thread as _
}
