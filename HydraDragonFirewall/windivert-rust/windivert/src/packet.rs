use windivert_sys::{ChecksumFlags, WinDivertHelperCalcChecksums};

use crate::{address::WinDivertAddress, layer, prelude::WinDivertError};

use std::{
    borrow::{BorrowMut, Cow},
    ffi::c_void,
    fmt::Debug,
};

/// Raw captured packet
#[derive(Debug, Clone)]
pub struct WinDivertPacket<'a, L: layer::WinDivertLayerTrait> {
    /// Address data
    pub address: WinDivertAddress<L>,
    /// Raw captured data
    pub data: Cow<'a, [u8]>,
}

impl<'a> WinDivertPacket<'a, layer::NetworkLayer> {
    /// Create a new network packet from a raw buffer
    /// # Safety
    /// `address` is zeroed, user must fill it with correct data before sending.
    pub unsafe fn new(data: Vec<u8>) -> Self {
        Self {
            address: WinDivertAddress::<layer::NetworkLayer>::new(),
            data: Cow::from(data),
        }
    }

    /// Recalculate the checksums of the packet
    /// This is a noop if the packet is not owned.
    pub fn recalculate_checksums(&mut self, flags: ChecksumFlags) -> Result<(), WinDivertError> {
        if let Cow::Owned(ref mut data) = self.data.borrow_mut() {
            let res = unsafe {
                WinDivertHelperCalcChecksums(
                    data.as_mut_ptr() as *mut c_void,
                    data.len() as u32,
                    self.address.as_mut(),
                    flags,
                )
            };
            if !res.as_bool() {
                return Err(WinDivertError::from(windows::core::Error::from_win32()));
            }
        }
        Ok(())
    }
}

impl<'a> WinDivertPacket<'a, layer::ForwardLayer> {
    /// Create a new network forward packet from a raw buffer
    /// # Safety
    /// `address` is zeroed, user must fill it with correct data before sending.
    pub unsafe fn new(data: Vec<u8>) -> Self {
        Self {
            address: WinDivertAddress::<layer::ForwardLayer>::new(),
            data: Cow::from(data),
        }
    }

    /// Recalculate the checksums of the packet
    /// This is a noop if the packet is not owned.
    pub fn recalculate_checksums(&mut self, flags: ChecksumFlags) -> Result<(), WinDivertError> {
        if let Cow::Owned(ref mut data) = self.data.borrow_mut() {
            let res = unsafe {
                WinDivertHelperCalcChecksums(
                    data.as_mut_ptr() as *mut c_void,
                    data.len() as u32,
                    self.address.as_mut(),
                    flags,
                )
            };
            if !res.as_bool() {
                return Err(WinDivertError::from(windows::core::Error::from_win32()));
            }
        }
        Ok(())
    }
}

impl<'a, L: layer::WinDivertLayerTrait> WinDivertPacket<'a, L> {
    /// Create an owned packet from a borrowed packet
    pub fn into_owned(self) -> WinDivertPacket<'static, L> {
        WinDivertPacket {
            address: self.address,
            data: self.data.into_owned().into(),
        }
    }
}
