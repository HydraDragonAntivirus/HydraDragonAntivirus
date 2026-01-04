//! Filesystem driver filter to monitor file operations

use core::{
    ffi::c_void,
    mem::zeroed,
    ptr::{null, null_mut},
};

use wdk::{nt_success, println};
use wdk_sys::{
    filesystem::FltRegisterFilter, FLT_CALLBACK_DATA, FLT_OPERATION_REGISTRATION,
    FLT_PREOP_CALLBACK_STATUS, FLT_REGISTRATION, FLT_REGISTRATION_VERSION, FLT_RELATED_OBJECTS,
    IRP_MJ_CREATE, NTSTATUS, PDRIVER_OBJECT, PFLT_FILTER, STATUS_SUCCESS,
    _FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_NO_CALLBACK,
};

pub fn register_filesystem_minifilter(driver: PDRIVER_OBJECT) {
    let mut reg: FLT_REGISTRATION = unsafe { zeroed() };
    reg.Size = size_of::<FLT_REGISTRATION>() as _;
    reg.Version = FLT_REGISTRATION_VERSION as _;
    reg.FilterUnloadCallback = Some(unload_minifilter);

    let operation_file_open: FLT_OPERATION_REGISTRATION = FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_CREATE as _,
        Flags: 0,
        PreOperation: Some(preop_file_create),
        PostOperation: None,
        Reserved1: null_mut(),
    };
    reg.OperationRegistration = &operation_file_open;

    let test = PFLT_FILTER::default();

    let mut reg_handle: PFLT_FILTER = null_mut();

    let result = unsafe { FltRegisterFilter(driver, &reg, &mut reg_handle) };

    if nt_success(result) {
        println!("[sanctum] [+] Filesystem minifilter registered...");
    } else {
        println!("[sanctum] [-] Failed to register fs minifilter!");
    }
}

unsafe extern "C" fn preop_file_create(
    data: *mut FLT_CALLBACK_DATA,
    fltobjects: *const FLT_RELATED_OBJECTS,
    completioncontext: *mut *mut core::ffi::c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    println!("[sanctum] [i] file pre op");
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

extern "C" fn unload_minifilter(_flags: u32) -> NTSTATUS {
    println!("[sanctum] [i] Filesystem minifilter unloading...");

    STATUS_SUCCESS
}
