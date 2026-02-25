use lazy_static::lazy_static;
use std::ffi::c_void;

// WinDivert Constants
pub const WINDIVERT_LAYER_NETWORK: u32 = 0;
pub const WINDIVERT_LAYER_NETWORK_FORWARD: u32 = 1;
pub const WINDIVERT_FLAG_SNIFF: u64 = 1;
pub const WINDIVERT_FLAG_DROP: u64 = 2;

// WinDivert Address Struct (Network Layer)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WinDivertAddress {
    pub if_idx: u32,
    pub sub_if_idx: u32,
    pub direction: u8,
}

impl WinDivertAddress {
    pub fn outbound(&self) -> bool {
        self.direction == 1
    }
}

// Function Signatures
type WinDivertOpenFn =
    unsafe extern "system" fn(filter: *const u8, layer: u32, priority: i16, flags: u64) -> isize;
type WinDivertRecvFn = unsafe extern "system" fn(
    handle: isize,
    packet: *mut u8,
    packet_len: u32,
    address: *mut WinDivertAddress,
    read_len: *mut u32,
) -> i32;
type WinDivertSendFn = unsafe extern "system" fn(
    handle: isize,
    packet: *const u8,
    packet_len: u32,
    address: *const WinDivertAddress,
    write_len: *mut u32,
) -> i32;
type WinDivertCloseFn = unsafe extern "system" fn(handle: isize) -> i32;
type WinDivertHelperCalcChecksumsFn = unsafe extern "system" fn(
    packet: *mut u8,
    packet_len: u32,
    address: *mut WinDivertAddress,
    flags: u64,
) -> u32;

// Dynamic Loader
pub struct WinDivertApi {
    pub open: WinDivertOpenFn,
    pub recv: WinDivertRecvFn,
    pub send: WinDivertSendFn,
    pub close: WinDivertCloseFn,
    pub calc_checksums: WinDivertHelperCalcChecksumsFn,
}

lazy_static! {
    pub static ref WINDIVERT_API: Option<WinDivertApi> = load_windivert();
}

fn load_windivert() -> Option<WinDivertApi> {
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
        use windows::core::PCSTR;

        let dll_name = std::ffi::CString::new("WinDivert.dll").unwrap();
        let handle = match LoadLibraryA(PCSTR::from_raw(dll_name.as_ptr() as *const u8)) {
            Ok(h) => h,
            Err(e) => {
                println!("ERROR: Failed to load WinDivert.dll: {}", e);
                return None;
            }
        };

        let get_proc = |name: &str| -> *const c_void {
            let c_name = std::ffi::CString::new(name).unwrap();
            let addr = GetProcAddress(handle, PCSTR::from_raw(c_name.as_ptr() as *const u8));
            addr.map(|f| f as *const c_void).unwrap_or(std::ptr::null())
        };

        let open_ptr = get_proc("WinDivertOpen");
        let recv_ptr = get_proc("WinDivertRecv");
        let send_ptr = get_proc("WinDivertSend");
        let close_ptr = get_proc("WinDivertClose");
        let calc_ptr = get_proc("WinDivertHelperCalcChecksums");

        if open_ptr.is_null()
            || recv_ptr.is_null()
            || send_ptr.is_null()
            || close_ptr.is_null()
            || calc_ptr.is_null()
        {
            println!("ERROR: Could not find all WinDivert functions");
            return None;
        }

        Some(WinDivertApi {
            open: std::mem::transmute(open_ptr),
            recv: std::mem::transmute(recv_ptr),
            send: std::mem::transmute(send_ptr),
            close: std::mem::transmute(close_ptr),
            calc_checksums: std::mem::transmute(calc_ptr),
        })
    }
}
