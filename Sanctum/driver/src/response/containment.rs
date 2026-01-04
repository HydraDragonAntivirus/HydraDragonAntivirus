use core::{ffi::c_void, ptr::null_mut};

use wdk::{nt_success, println};
use wdk_sys::{
    CLIENT_ID, NTSTATUS, OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES, PASSIVE_LEVEL, PROCESS_ALL_ACCESS,
    STATUS_PROCESS_IS_TERMINATING, STATUS_UNSUCCESSFUL,
    ntddk::{KeGetCurrentIrql, ZwOpenProcess, ZwTerminateProcess},
};

use crate::{ffi::InitializeObjectAttributes, utils::get_process_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverMode {
    ReportOnly,
    Blocking,
}

// todo we need to set this via an IOCTL; we can get this from the telemetry server.
// To prevent this being mutable, a device reboot is required for a change to take effect.
pub static DRIVER_MODE: DriverMode = DriverMode::Blocking;

pub struct Containment {}

impl Containment {
    pub fn contain_process(pid: u32) {
        println!("[sanctum] [i] Containing process: {pid}",);
        // todo actual containment

        let _ = terminate_process(pid);
    }
}

fn terminate_process(pid: u32) -> NTSTATUS {
    let mut handle: *mut c_void = null_mut();
    let mut oa = OBJECT_ATTRIBUTES::default();
    let _ = unsafe {
        InitializeObjectAttributes(
            &mut oa,
            null_mut(),
            OBJ_KERNEL_HANDLE,
            null_mut(),
            null_mut(),
        )
    };

    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as *mut c_void,
        UniqueThread: null_mut(),
    };

    // The IRQL required to call into ZwOpenProcess is PASSIVE_LEVEL, doing so > PASSIVE_LEVEL will cause a bugcheck.
    let irql = unsafe { KeGetCurrentIrql() };
    if irql != PASSIVE_LEVEL as u8 {
        // todo fix this in the future; if the IRQL is too high and this prevents the blocking of malware,
        // that would obviously be a bad thing!
        println!("[sanctum] [-] Cannot terminate process, IRQL is too high. IRQL: {irql}.");
        return STATUS_UNSUCCESSFUL;
    }

    let status = unsafe { ZwOpenProcess(&mut handle, PROCESS_ALL_ACCESS, &mut oa, &mut client_id) };

    if !nt_success(status) {
        println!("[sanctum] [-] Failed to suspend process, pid: {pid}. Error: {status:#X}");
        return status;
    }

    let status = unsafe { ZwTerminateProcess(handle, 1) };

    if !nt_success(status) && status != STATUS_PROCESS_IS_TERMINATING {
        println!("[sanctum] [-] Error terminating process. Error code: {status:#X}");
    }

    status
}
