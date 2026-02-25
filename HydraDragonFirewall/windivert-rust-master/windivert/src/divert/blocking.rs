use std::borrow::Cow;
use std::{ffi::c_void, mem::MaybeUninit};

use crate::address::WinDivertAddress;
use crate::layer;
use crate::prelude::*;
use etherparse::{InternetSlice, SlicedPacket};
use sys::address::WINDIVERT_ADDRESS;
use windivert_sys as sys;

const ADDR_SIZE: usize = std::mem::size_of::<WINDIVERT_ADDRESS>();

impl<L: layer::WinDivertLayerTrait> WinDivert<L> {
    fn internal_recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, L>, WinDivertError> {
        let mut packet_length = 0;
        let mut addr = MaybeUninit::uninit();
        let (buffer_ptr, buffer_len) = if let Some(ref buffer) = buffer {
            (buffer.as_ptr(), buffer.len())
        } else {
            (std::ptr::null(), 0)
        };

        let res = unsafe {
            sys::WinDivertRecv(
                self.handle,
                buffer_ptr as *mut c_void,
                buffer_len as u32,
                &mut packet_length,
                addr.as_mut_ptr(),
            )
        };

        if res.as_bool() {
            Ok(WinDivertPacket {
                address: WinDivertAddress::<L>::from_raw(unsafe { addr.assume_init() }),
                data: buffer
                    .map(|b| Cow::Borrowed(&b[..packet_length as usize]))
                    .unwrap_or_default(),
            })
        } else {
            let recv_err = WinDivertRecvError::try_from(std::io::Error::last_os_error())?;
            Err(recv_err.into())
        }
    }

    fn internal_recv_ex<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
        packet_count: usize,
    ) -> Result<(Option<&'a [u8]>, Vec<WINDIVERT_ADDRESS>), WinDivertError> {
        let mut packet_length = 0;

        let mut addr_len = (ADDR_SIZE * packet_count) as u32;
        let mut addr_buffer: Vec<WINDIVERT_ADDRESS> =
            vec![WINDIVERT_ADDRESS::default(); packet_count];

        let (buffer_ptr, buffer_len) = if let Some(buffer) = &buffer {
            (buffer.as_ptr(), buffer.len())
        } else {
            (std::ptr::null(), 0)
        };

        let res = unsafe {
            sys::WinDivertRecvEx(
                self.handle,
                buffer_ptr as *mut c_void,
                buffer_len as u32,
                &mut packet_length,
                0,
                addr_buffer.as_mut_ptr(),
                &mut addr_len,
                std::ptr::null_mut(),
            )
        };

        if res.as_bool() {
            addr_buffer.truncate((addr_len / ADDR_SIZE as u32) as usize);
            Ok((
                buffer.map(|buffer| &buffer[..packet_length as usize]),
                addr_buffer,
            ))
        } else {
            let recv_err = WinDivertRecvError::try_from(std::io::Error::last_os_error())?;
            Err(recv_err.into())
        }
    }

    fn internal_send(&self, packet: &WinDivertPacket<L>) -> Result<u32, WinDivertError> {
        let mut injected_length = 0;

        let res = unsafe {
            sys::WinDivertSend(
                self.handle,
                packet.data.as_ptr() as *const c_void,
                packet.data.len() as u32,
                &mut injected_length,
                packet.address.as_ref(),
            )
        };

        if !res.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(injected_length)
    }

    fn internal_send_ex<'data, 'packets, P>(&self, packets: P) -> Result<u32, WinDivertError>
    where
        P: ExactSizeIterator<Item = &'packets WinDivertPacket<'data, L>>,
        'data: 'packets,
        L: 'packets,
    {
        let packet_count = packets.len();
        let mut injected_length = 0;
        let mut packet_buffer: Vec<u8> = Vec::new();
        let mut address_buffer: Vec<WINDIVERT_ADDRESS> = Vec::with_capacity(packet_count);
        packets.for_each(|packet: &'packets WinDivertPacket<'data, L>| {
            packet_buffer.extend(&packet.data[..]);
            address_buffer.push(*packet.address.as_ref());
        });

        let res = unsafe {
            sys::WinDivertSendEx(
                self.handle,
                packet_buffer.as_ptr() as *const c_void,
                packet_buffer.len() as u32,
                &mut injected_length,
                0,
                address_buffer.as_ptr(),
                (std::mem::size_of::<WINDIVERT_ADDRESS>() * packet_count) as u32,
                std::ptr::null_mut(),
            )
        };

        if !res.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(injected_length)
    }
}

impl WinDivert<layer::NetworkLayer> {
    /// Single packet blocking recv function.
    pub fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::NetworkLayer>, WinDivertError> {
        self.internal_recv(buffer)
    }

    /// Batched blocking recv function.
    pub fn recv_ex<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
        packet_count: usize,
    ) -> Result<Vec<WinDivertPacket<'a, layer::NetworkLayer>>, WinDivertError> {
        let (mut buffer, addresses) = self.internal_recv_ex(buffer, packet_count)?;
        let mut packets = Vec::with_capacity(addresses.len());
        for addr in addresses.into_iter() {
            packets.push(WinDivertPacket {
                address: WinDivertAddress::<layer::NetworkLayer>::from_raw(addr),
                data: buffer
                    .map(|inner_buffer| {
                        let headers = SlicedPacket::from_ip(inner_buffer)
                            .expect("WinDivert can't capture anything below ip");
                        let offset = match headers.ip.unwrap() {
                            InternetSlice::Ipv4(ip_header, _) => ip_header.total_len() as usize,
                            InternetSlice::Ipv6(ip6header, _) => {
                                ip6header.payload_length() as usize + 40
                            }
                        };
                        let (data, tail) = inner_buffer.split_at(offset);
                        buffer = Some(tail);
                        Cow::Borrowed(data)
                    })
                    .unwrap_or_default(),
            });
        }
        Ok(packets)
    }

    /// Single packet send function.
    pub fn send(
        &self,
        packet: &WinDivertPacket<layer::NetworkLayer>,
    ) -> Result<u32, WinDivertError> {
        self.internal_send(packet)
    }

    /// Batched packet send function.
    pub fn send_ex<'data, 'packets, P, I>(&self, packets: P) -> Result<u32, WinDivertError>
    where
        P: IntoIterator<IntoIter = I>,
        I: ExactSizeIterator<Item = &'packets WinDivertPacket<'data, layer::NetworkLayer>>,
        'data: 'packets,
    {
        self.internal_send_ex(packets.into_iter())
    }
}

impl WinDivert<layer::ForwardLayer> {
    /// Single packet blocking recv function.
    pub fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::ForwardLayer>, WinDivertError> {
        self.internal_recv(buffer)
    }

    /// Batched blocking recv function.
    pub fn recv_ex<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
        packet_count: usize,
    ) -> Result<Vec<WinDivertPacket<'a, layer::NetworkLayer>>, WinDivertError> {
        let (mut buffer, addresses) = self.internal_recv_ex(buffer, packet_count)?;
        let mut packets = Vec::with_capacity(addresses.len());
        for addr in addresses.into_iter() {
            packets.push(WinDivertPacket {
                address: WinDivertAddress::<layer::NetworkLayer>::from_raw(addr),
                data: buffer
                    .map(|inner_buffer| {
                        let headers = SlicedPacket::from_ip(inner_buffer)
                            .expect("WinDivert can't capture anything below ip");
                        let offset = match headers.ip.unwrap() {
                            InternetSlice::Ipv4(ip_header, _) => ip_header.total_len() as usize,
                            InternetSlice::Ipv6(ip6header, _) => {
                                ip6header.payload_length() as usize + 40
                            }
                        };
                        let (data, tail) = inner_buffer.split_at(offset);
                        buffer = Some(tail);
                        Cow::Borrowed(data)
                    })
                    .unwrap_or_default(),
            });
        }
        Ok(packets)
    }

    /// Single packet send function.
    pub fn send(
        &self,
        packet: &WinDivertPacket<layer::ForwardLayer>,
    ) -> Result<u32, WinDivertError> {
        self.internal_send(packet)
    }

    /// Batched packet send function.
    pub fn send_ex<'data, 'packets, P, I>(&self, packets: P) -> Result<u32, WinDivertError>
    where
        P: IntoIterator<IntoIter = I>,
        I: ExactSizeIterator<Item = &'packets WinDivertPacket<'data, layer::ForwardLayer>>,
        'data: 'packets,
    {
        self.internal_send_ex(packets.into_iter())
    }
}

impl WinDivert<layer::FlowLayer> {
    /// Single packet blocking recv function.
    pub fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::FlowLayer>, WinDivertError> {
        self.internal_recv(buffer)
    }

    /// Batched blocking recv function.
    pub fn recv_ex<'a>(
        &self,
        packet_count: usize,
    ) -> Result<Vec<WinDivertPacket<'a, layer::FlowLayer>>, WinDivertError> {
        let (_, addresses) = self.internal_recv_ex(None, packet_count)?;
        let mut packets = Vec::with_capacity(addresses.len());
        for addr in addresses.into_iter() {
            packets.push(WinDivertPacket::<layer::FlowLayer> {
                address: WinDivertAddress::<layer::FlowLayer>::from_raw(addr),
                data: Default::default(),
            });
        }
        Ok(packets)
    }
}

impl WinDivert<layer::SocketLayer> {
    /// Single packet blocking recv function.
    pub fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::SocketLayer>, WinDivertError> {
        self.internal_recv(buffer)
    }

    /// Batched blocking recv function.
    pub fn recv_ex<'a>(
        &self,
        packet_count: usize,
    ) -> Result<Vec<WinDivertPacket<'a, layer::SocketLayer>>, WinDivertError> {
        let (_, addresses) = self.internal_recv_ex(None, packet_count)?;
        let mut packets = Vec::with_capacity(addresses.len());
        for addr in addresses.into_iter() {
            packets.push(WinDivertPacket::<layer::SocketLayer> {
                address: WinDivertAddress::<layer::SocketLayer>::from_raw(addr),
                data: Default::default(),
            });
        }
        Ok(packets)
    }
}

impl WinDivert<layer::ReflectLayer> {
    /// Single packet blocking recv function.
    pub fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, layer::ReflectLayer>, WinDivertError> {
        self.internal_recv(buffer)
    }

    /// Batched blocking recv function.
    pub fn recv_ex<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
        packet_count: usize,
    ) -> Result<Vec<WinDivertPacket<'a, layer::ReflectLayer>>, WinDivertError> {
        let (mut buffer, addresses) = self.internal_recv_ex(buffer, packet_count)?;
        let mut packets = Vec::with_capacity(addresses.len());
        for addr in addresses.into_iter() {
            packets.push(WinDivertPacket {
                address: WinDivertAddress::<layer::ReflectLayer>::from_raw(addr),
                data: buffer
                    .map(|inner_buffer| {
                        let (data, tail) = inner_buffer.split_at(
                            inner_buffer
                                .iter()
                                .position(|&x| x == b'\0')
                                .expect("CStrings always end in null"),
                        );
                        buffer = Some(tail);
                        Cow::Borrowed(data)
                    })
                    .unwrap_or_default(),
            });
        }
        Ok(packets)
    }
}
