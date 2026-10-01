//! # Image Verification Callbacks (Windows 11 24H2+ HVCI & Driver Notification)
//!
//! Windows 11 24H2 introduced expanded capabilities in `SeRegisterImageVerificationCallback`:
//! - `SeImageVerificationCallbackInformational (0)`: Monitors driver image load verifications.
//! - `SeImageVerificationCallbackBlock (1)`: Notifies EDRs when drivers/images are BLOCKED by HVCI
//!   (e.g., Vulnerable Driver Blocklist, Code Integrity policy, BYOVD attacks).

use core::{
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::{
    format,
    string::{String, ToString},
};
use wdk::{nt_success, println};
use wdk_sys::{BOOLEAN, NTSTATUS, UNICODE_STRING};

use crate::{DRIVER_MESSAGES, utils::unicode_to_string};

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeImageType {
    Driver = 0,
    All = 1,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeImageVerificationCallbackType {
    Informational = 0,
    Block = 1,
}

#[repr(C)]
pub struct BdcbImageInformation {
    pub classification: u32,
    pub image_flags: u32,
    pub image_name: UNICODE_STRING,
    pub registry_path: UNICODE_STRING,
    pub certificate_publisher: UNICODE_STRING,
    pub certificate_issuer: UNICODE_STRING,
    pub image_hash: *mut c_void,
    pub certificate_thumbprint: *mut c_void,
    pub image_hash_algorithm: u32,
    pub thumbprint_hash_algorithm: u32,
    pub image_hash_length: u32,
    pub certificate_thumbprint_length: u32,
}

pub type SeImageVerificationCallbackFunction = unsafe extern "C" fn(
    callback_context: *mut c_void,
    image_type: SeImageType,
    image_information: *mut BdcbImageInformation,
);

unsafe extern "system" {
    fn PsGetVersion(
        MajorVersion: *mut u32,
        MinorVersion: *mut u32,
        BuildNumber: *mut u32,
        CSDVersion: *mut UNICODE_STRING,
    ) -> BOOLEAN;

    fn SeRegisterImageVerificationCallback(
        image_type: SeImageType,
        callback_type: SeImageVerificationCallbackType,
        callback_function: SeImageVerificationCallbackFunction,
        callback_context: *mut c_void,
        token: *mut c_void,
        callback_handle: *mut *mut c_void,
    ) -> NTSTATUS;

    fn SeUnregisterImageVerificationCallback(callback_handle: *mut c_void);
}

static VERIFICATION_INFO_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static VERIFICATION_BLOCK_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

fn is_win11_24h2() -> bool {
    let mut major = 0u32;
    let mut minor = 0u32;
    let mut build = 0u32;
    unsafe {
        PsGetVersion(&mut major, &mut minor, &mut build, null_mut());
    }
    build >= 26100
}

/// Callback for normal driver load verifications (Informational)
unsafe extern "C" fn on_image_verification_info(
    _context: *mut c_void,
    _image_type: SeImageType,
    image_info: *mut BdcbImageInformation,
) {
    if image_info.is_null() {
        return;
    }

    let name = unsafe {
        match unicode_to_string(&(*image_info).image_name) {
            Ok(s) => s,
            Err(_) => "Unknown".to_string(),
        }
    };

    let reg = unsafe {
        match unicode_to_string(&(*image_info).registry_path) {
            Ok(s) => s,
            Err(_) => String::new(),
        }
    };

    let publisher = unsafe {
        match unicode_to_string(&(*image_info).certificate_publisher) {
            Ok(s) => s,
            Err(_) => "Unknown".to_string(),
        }
    };

    let flags = unsafe { (*image_info).image_flags };
    let log_msg = format!(
        "type=DRIVER_LOAD;pid=0;image={};registry={};publisher={};issuer=;flags={:#x};classification=Info",
        name, reg, publisher, flags
    );
    println!("[sanctum] [DRIVER_VERIFY] {}", log_msg);

    let ptr = DRIVER_MESSAGES.load(Ordering::SeqCst);
    if !ptr.is_null() {
        let messages = unsafe { &mut *ptr };
        messages.add_message_to_queue(log_msg);
    }
}

/// Callback for HVCI-blocked drivers/images (Block - New in Windows 11 24H2)
unsafe extern "C" fn on_image_verification_block(
    _context: *mut c_void,
    _image_type: SeImageType,
    image_info: *mut BdcbImageInformation,
) {
    if image_info.is_null() {
        return;
    }

    let image_name = unsafe {
        match unicode_to_string(&(*image_info).image_name) {
            Ok(s) => s,
            Err(_) => "Unknown".to_string(),
        }
    };

    let publisher = unsafe {
        match unicode_to_string(&(*image_info).certificate_publisher) {
            Ok(s) => s,
            Err(_) => "Unknown".to_string(),
        }
    };

    let flags = unsafe { (*image_info).image_flags };
    let alert_msg = format!(
        "type=HVCI_BLOCK;pid=0;image={};registry=;publisher={};issuer=;flags={:#x};classification=Untrusted",
        image_name, publisher, flags
    );

    println!("[sanctum] [ALERT] {}", alert_msg);

    let ptr = DRIVER_MESSAGES.load(Ordering::SeqCst);
    if !ptr.is_null() {
        let messages = unsafe { &mut *ptr };
        messages.add_message_to_queue(alert_msg);
    }
}

/// Registers the two SeRegisterImageVerificationCallback handlers on Windows 11 24H2+:
/// 1) Informational (Driver loads)
/// 2) Block (HVCI-blocked drivers / BYOVD attacks)
pub fn register_image_verification_callbacks() {
    if !is_win11_24h2() {
        println!(
            "[sanctum] [!] SeRegisterImageVerificationCallback with Block type requires Windows 11 24H2+ (Build >= 26100); skipping."
        );
        return;
    }

    // 1. Register Informational callback for drivers
    let mut info_handle: *mut c_void = null_mut();
    let status_info = unsafe {
        SeRegisterImageVerificationCallback(
            SeImageType::Driver,
            SeImageVerificationCallbackType::Informational,
            on_image_verification_info,
            null_mut(),
            null_mut(),
            &mut info_handle,
        )
    };

    if nt_success(status_info) && !info_handle.is_null() {
        VERIFICATION_INFO_HANDLE.store(info_handle, Ordering::SeqCst);
        println!("[sanctum] [+] Registered SeRegisterImageVerificationCallback (Informational).");
    } else {
        println!(
            "[sanctum] [-] Failed to register SeRegisterImageVerificationCallback (Informational): {:#x}",
            status_info
        );
    }

    // 2. Register Block callback for HVCI-blocked drivers/images (24H2 Exclusive)
    let mut block_handle: *mut c_void = null_mut();
    let status_block = unsafe {
        SeRegisterImageVerificationCallback(
            SeImageType::All,
            SeImageVerificationCallbackType::Block,
            on_image_verification_block,
            null_mut(),
            null_mut(),
            &mut block_handle,
        )
    };

    if nt_success(status_block) && !block_handle.is_null() {
        VERIFICATION_BLOCK_HANDLE.store(block_handle, Ordering::SeqCst);
        println!(
            "[sanctum] [+] Registered SeRegisterImageVerificationCallback (Block - 24H2 HVCI telemetry)."
        );
    } else {
        println!(
            "[sanctum] [-] Failed to register SeRegisterImageVerificationCallback (Block): {:#x}",
            status_block
        );
    }
}

/// Unregisters both image verification callbacks on driver unload
pub fn unregister_image_verification_callbacks() {
    let info_handle = VERIFICATION_INFO_HANDLE.swap(null_mut(), Ordering::SeqCst);
    if !info_handle.is_null() {
        unsafe {
            SeUnregisterImageVerificationCallback(info_handle);
        }
        println!("[sanctum] [+] Unregistered SeRegisterImageVerificationCallback (Informational).");
    }

    let block_handle = VERIFICATION_BLOCK_HANDLE.swap(null_mut(), Ordering::SeqCst);
    if !block_handle.is_null() {
        unsafe {
            SeUnregisterImageVerificationCallback(block_handle);
        }
        println!("[sanctum] [+] Unregistered SeRegisterImageVerificationCallback (Block).");
    }
}
