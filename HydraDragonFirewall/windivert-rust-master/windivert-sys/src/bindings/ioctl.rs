/*!
WinDivert IOCTL types.

This types are not used by this crate but some of them are used by the wrapper crate in order to implement wait variants for `recv` and `recv_ex`.
*/
#![allow(missing_docs)]

#[repr(C)]
#[derive(Copy, Clone)]
pub union WINDIVERT_IOCTL {
    pub recv: WINDIVERT_IOCTL_RECV,
    pub send: WINDIVERT_IOCTL_SEND,
    pub initialize: WINDIVERT_IOCTL_INITIALIZE,
    pub startup: WINDIVERT_IOCTL_STARTUP,
    pub shutdown: WINDIVERT_IOCTL_SHUTDOWN,
    pub get_param: WINDIVERT_IOCTL_GET_PARAM,
    pub set_param: WINDIVERT_IOCTL_SET_PARAM,
    _union_align: [u8; 16usize],
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WINDIVERT_IOCTL_RECV {
    pub addr: u64,
    pub addr_len_ptr: u64,
}

pub type WINDIVERT_IOCTL_SEND = WINDIVERT_IOCTL_RECV;

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WINDIVERT_IOCTL_INITIALIZE {
    pub layer: u32,
    pub priority: u32,
    pub flags: u64,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WINDIVERT_IOCTL_STARTUP {
    pub flags: u64,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WINDIVERT_IOCTL_SHUTDOWN {
    pub how: u32,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WINDIVERT_IOCTL_GET_PARAM {
    pub param: u32,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WINDIVERT_IOCTL_SET_PARAM {
    pub val: u64,
    pub param: u32,
}
