/*!
WinDivert header types.
*/
#![allow(missing_docs)]
use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::BitfieldUnit;

/**
IPV4 header.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_iphdr)
*/
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct WINDIVERT_IPHDR {
    addr_bitfield: BitfieldUnit<[u8; 1usize], u8>,
    pub tos: u8,
    length: u16,
    id: u16,
    fragment_offset_and_flags: u16,
    pub ttl: u8,
    pub protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

impl WINDIVERT_IPHDR {
    #[inline]
    pub fn header_length(&self) -> u8 {
        self.addr_bitfield.get(0usize, 4u8) as u8
    }
    #[inline]
    pub fn set_header_length(&mut self, val: u8) {
        self.addr_bitfield.set(0usize, 4u8, val as u64)
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.addr_bitfield.get(4usize, 4u8) as u8
    }
    #[inline]
    pub fn set_version(&mut self, val: u8) {
        self.addr_bitfield.set(4usize, 4u8, val as u64)
    }
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be(self.length)
    }
    #[inline]
    pub fn set_length(&mut self, value: u16) {
        self.length = value.to_be();
    }
    #[inline]
    pub fn id(&self) -> u16 {
        u16::from_be(self.id)
    }
    #[inline]
    pub fn set_id(&mut self, value: u16) {
        self.id = value.to_be();
    }
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be(self.fragment_offset_and_flags & 0xFF1F)
    }
    #[inline]
    pub fn set_fragment_offset(&mut self, value: u16) {
        self.fragment_offset_and_flags =
            self.fragment_offset_and_flags & 0x00E0 | (value & 0x1FFF).to_be()
    }
    #[inline]
    pub fn MF(&self) -> bool {
        self.fragment_offset_and_flags & 0x0020 != 0
    }
    #[inline]
    pub fn set_MF(&mut self, value: bool) {
        self.fragment_offset_and_flags =
            self.fragment_offset_and_flags & 0xFFDF | ((value as u16) << 5)
    }
    #[inline]
    pub fn DF(&self) -> bool {
        self.fragment_offset_and_flags & 0x0040 != 0
    }
    #[inline]
    pub fn set_DF(&mut self, value: bool) {
        self.fragment_offset_and_flags =
            self.fragment_offset_and_flags & 0xFFBF | ((value as u16) << 6)
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        self.checksum = value.to_be();
    }
    #[inline]
    pub fn src_addr(&self) -> u32 {
        u32::from_be(self.src_addr)
    }
    #[inline]
    pub fn src_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src_addr)
    }
    #[inline]
    pub fn set_src_addr(&mut self, value: u32) {
        self.src_addr = value.to_be();
    }
    #[inline]
    pub fn dst_addr(&self) -> u32 {
        u32::from_be(self.dst_addr)
    }
    #[inline]
    pub fn dst_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst_addr)
    }
    #[inline]
    pub fn set_dst_addr(&mut self, value: u32) {
        self.dst_addr = value.to_be();
    }
}

impl Debug for WINDIVERT_IPHDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WINDIVERT_IPHDR {{ header_length: {:?}, version: {:?}, tos: {:?}, length: {:?}, id: {:?}, MF: {:?}, DF: {:?}, fragment_offset: {:?}, ttl: {:?}, protocol: {:?}, checksum: {:?}, src_addr: {:?}, dst_addr: {:?} }}",
        self.header_length(), self.version(), self.tos, self.length(), self.id(), self.MF(), self.DF(), self.fragment_offset(), self.ttl, self.protocol, self.checksum(), self.src_addr(), self.dst_addr())
    }
}

/// [IPV4 header](WINDIVERT_IPHDR) pointer type.
pub type PWINDIVERT_IPHDR = *mut WINDIVERT_IPHDR;

/**
IPV6 header.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_ipv6hdr)
*/
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct WINDIVERT_IPV6HDR {
    addr_bitfield: BitfieldUnit<[u8; 2usize], u8>,
    flow_label_1: u16,
    length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    src_addr: [u32; 4usize],
    dst_addr: [u32; 4usize],
}

impl WINDIVERT_IPV6HDR {
    #[inline]
    pub fn version(&self) -> u8 {
        self.addr_bitfield.get(4usize, 4u8) as u8
    }
    #[inline]
    pub fn set_version(&mut self, val: u8) {
        self.addr_bitfield.set(4usize, 4u8, val as u64)
    }
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        u8::from_be(self.traffic_class0() << 4 | self.traffic_class1())
    }
    pub fn set_traffic_class(&mut self, value: u8) {
        let value = value.to_be();
        self.set_traffic_class0(value >> 4);
        self.set_traffic_class1(value);
    }
    #[inline]
    fn traffic_class0(&self) -> u8 {
        self.addr_bitfield.get(0usize, 4u8) as u8
    }
    #[inline]
    fn set_traffic_class0(&mut self, val: u8) {
        self.addr_bitfield.set(0usize, 4u8, val as u64)
    }
    #[inline]
    fn traffic_class1(&self) -> u8 {
        self.addr_bitfield.get(12usize, 4u8) as u8
    }
    #[inline]
    fn set_traffic_class1(&mut self, val: u8) {
        self.addr_bitfield.set(12usize, 4u8, val as u64)
    }
    #[inline]
    pub fn flow_label(&self) -> u32 {
        u32::from_be((self.flow_label0() as u32) << 16 | self.flow_label_1 as u32)
    }
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        let value = value.to_be();
        self.set_flow_label0((value >> 16) as u8);
        self.flow_label_1 = value as u16;
    }
    #[inline]
    fn flow_label0(&self) -> u8 {
        self.addr_bitfield.get(8usize, 4u8) as u8
    }
    #[inline]
    fn set_flow_label0(&mut self, val: u8) {
        self.addr_bitfield.set(8usize, 4u8, val as u64)
    }
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be(self.length)
    }
    #[inline]
    pub fn src_addr(&self) -> u128 {
        u128::from_be(
            self.src_addr
                .iter()
                .rev()
                .fold(0u128, |acc, &x| (acc << 32) | x as u128),
        )
    }
    #[inline]
    pub fn src_ip_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.src_addr())
    }
    #[inline]
    pub fn set_src_addr(&mut self, value: u128) {
        let tmp = value
            .to_be_bytes()
            .chunks(4)
            .map(|x| {
                let mut tmp: [u8; 4] = Default::default();
                tmp.copy_from_slice(x);
                u32::from_ne_bytes(tmp)
            })
            .collect::<Vec<u32>>();
        self.src_addr.copy_from_slice(&tmp);
    }
    #[inline]
    pub fn dst_addr(&self) -> u128 {
        u128::from_be(
            self.dst_addr
                .iter()
                .rev()
                .fold(0u128, |acc, &x| (acc << 32) | x as u128),
        )
    }
    #[inline]
    pub fn dst_ip_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.dst_addr())
    }
    #[inline]
    pub fn set_dst_addr(&mut self, value: u128) {
        let tmp = value
            .to_be_bytes()
            .chunks(4)
            .map(|x| {
                let mut tmp: [u8; 4] = Default::default();
                tmp.copy_from_slice(x);
                u32::from_ne_bytes(tmp)
            })
            .collect::<Vec<u32>>();
        self.dst_addr.copy_from_slice(&tmp);
    }
}

impl Debug for WINDIVERT_IPV6HDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WINDIVERT_IPV6HDR {{ version: {:?}, traffic_class: {:?}, flow_label: {:?}, length: {:?}, MextHdr: {:?}, hop_limit: {:?}, src_addr: {:?}, dst_addr: {:?} }}", self.version(), self.traffic_class(), self.flow_label(), self.length(), self.next_header, self.hop_limit, self.src_addr(), self.dst_addr())
    }
}

/// [IPV6 header](WINDIVERT_IPV6HDR) pointer type.
pub type PWINDIVERT_IPV6HDR = *mut WINDIVERT_IPV6HDR;

/**
ICMP header.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_icmphdr)
*/
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct WINDIVERT_ICMPHDR {
    pub msg_type: u8,
    pub msg_code: u8,
    checksum: u16,
    body: u32,
}

impl WINDIVERT_ICMPHDR {
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }
    #[inline]
    pub fn set_Checksum(&mut self, value: u16) {
        self.checksum = value.to_be();
    }
    #[inline]
    pub fn body(&self) -> u32 {
        u32::from_be(self.body)
    }
    #[inline]
    pub fn set_Body(&mut self, value: u32) {
        self.body = value.to_be();
    }
}

impl Debug for WINDIVERT_ICMPHDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WINDIVERT_ICMPHDR {{ msg_type: {:?}, msg_code: {:?}, checksum: {:?}, body: {:?} }}",
            self.msg_type,
            self.msg_code,
            self.checksum(),
            self.body()
        )
    }
}

/// [ICMP header](WINDIVERT_ICMPHDR) pointer type.
pub type PWINDIVERT_ICMPHDR = *mut WINDIVERT_ICMPHDR;

/**
ICMPV6 header.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_icmpv6hdr)
*/
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct WINDIVERT_ICMPV6HDR {
    pub msg_type: u8,
    pub msg_code: u8,
    checksum: u16,
    body: u32,
}

impl WINDIVERT_ICMPV6HDR {
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }
    #[inline]
    pub fn set_Checksum(&mut self, value: u16) {
        self.checksum = value.to_be();
    }
    #[inline]
    pub fn body(&self) -> u32 {
        u32::from_be(self.body)
    }
    #[inline]
    pub fn set_Body(&mut self, value: u32) {
        self.body = value.to_be();
    }
}

impl Debug for WINDIVERT_ICMPV6HDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WINDIVERT_ICMPHDR {{ msg_type: {:?}, msg_code: {:?}, checksum: {:?}, body: {:?} }}",
            self.msg_type,
            self.msg_code,
            self.checksum(),
            self.body()
        )
    }
}

/// [ICMPV6 header](WINDIVERT_ICMPV6HDR) pointer type.
pub type PWINDIVERT_ICMPV6HDR = *mut WINDIVERT_ICMPV6HDR;

/**
TCP header.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_tcphdr)
*/
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct WINDIVERT_TCPHDR {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ACK_number: u32,
    addr_bitfield: BitfieldUnit<[u8; 2usize], u8>,
    window: u16,
    checksum: u16,
    urg_ptr: u16,
}

impl WINDIVERT_TCPHDR {
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        self.src_port = value.to_be();
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        self.dst_port = value.to_be();
    }
    #[inline]
    pub fn seq_number(&self) -> u32 {
        u32::from_be(self.seq_number)
    }
    #[inline]
    pub fn set_seq_number(&mut self, value: u32) {
        self.seq_number = value.to_be();
    }
    #[inline]
    pub fn ACK_number(&self) -> u32 {
        u32::from_be(self.ACK_number)
    }
    #[inline]
    pub fn set_ACK_number(&mut self, value: u32) {
        self.ACK_number = value.to_be();
    }
    #[inline]
    pub fn header_length(&self) -> u16 {
        self.addr_bitfield.get(4usize, 4u8) as u16
    }
    #[inline]
    pub fn set_header_length(&mut self, val: u16) {
        self.addr_bitfield.set(4usize, 4u8, val as u64)
    }
    #[inline]
    pub fn FIN(&self) -> u16 {
        self.addr_bitfield.get(8usize, 1u8) as u16
    }
    #[inline]
    pub fn set_FIN(&mut self, val: u16) {
        self.addr_bitfield.set(8usize, 1u8, val as u64)
    }
    #[inline]
    pub fn SYN(&self) -> u16 {
        self.addr_bitfield.get(9usize, 1u8) as u16
    }
    #[inline]
    pub fn set_SYN(&mut self, val: u16) {
        self.addr_bitfield.set(9usize, 1u8, val as u64)
    }
    #[inline]
    pub fn RST(&self) -> u16 {
        self.addr_bitfield.get(10usize, 1u8) as u16
    }
    #[inline]
    pub fn set_RST(&mut self, val: u16) {
        self.addr_bitfield.set(10usize, 1u8, val as u64)
    }
    #[inline]
    pub fn PSH(&self) -> u16 {
        self.addr_bitfield.get(11usize, 1u8) as u16
    }
    #[inline]
    pub fn set_PSH(&mut self, val: u16) {
        self.addr_bitfield.set(11usize, 1u8, val as u64)
    }
    #[inline]
    pub fn ACK(&self) -> u16 {
        self.addr_bitfield.get(12usize, 1u8) as u16
    }
    #[inline]
    pub fn set_ACK(&mut self, val: u16) {
        self.addr_bitfield.set(12usize, 1u8, val as u64)
    }
    #[inline]
    pub fn URG(&self) -> u16 {
        self.addr_bitfield.get(13usize, 1u8) as u16
    }
    #[inline]
    pub fn set_URG(&mut self, val: u16) {
        self.addr_bitfield.set(13usize, 1u8, val as u64)
    }
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be(self.window)
    }
    #[inline]
    pub fn set_window(&mut self, value: u16) {
        self.window = value.to_be();
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }
    #[inline]
    pub fn set_Checksum(&mut self, value: u16) {
        self.checksum = value.to_be();
    }
    #[inline]
    pub fn urg_ptr(&self) -> u16 {
        u16::from_be(self.urg_ptr)
    }
    #[inline]
    pub fn set_urg_ptr(&mut self, value: u16) {
        self.urg_ptr = value.to_be();
    }
}

impl Debug for WINDIVERT_TCPHDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WINDIVERT_TCPHDR {{ src_port: {:?}, dst_port: {:?}, seq_number: {:?}, ACK_number: {:?}, header_length: {:?}, URG: {:?}, ACK: {:?}, PSH: {:?}, RST: {:?}, SYN: {:?}, FIN: {:?}, window: {:?}, checksum: {:?}, urg_ptr: {:?} }}", self.src_port(), self.dst_port(), self.seq_number(), self.ACK_number(), self.header_length(), self.URG(), self.ACK(), self.PSH(), self.RST(), self.SYN(), self.FIN(), self.window(), self.checksum(), self.urg_ptr())
    }
}

/// [TCP header](WINDIVERT_TCPHDR) pointer type.
pub type PWINDIVERT_TCPHDR = *mut WINDIVERT_TCPHDR;

/**
UDP header.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_udphdr)
*/
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct WINDIVERT_UDPHDR {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl WINDIVERT_UDPHDR {
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        self.src_port = value.to_be();
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        self.dst_port = value.to_be();
    }
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be(self.length)
    }
    #[inline]
    pub fn set_length(&mut self, value: u16) {
        self.length = value.to_be();
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }
    #[inline]
    pub fn set_Checksum(&mut self, value: u16) {
        self.checksum = value.to_be();
    }
}

impl Debug for WINDIVERT_UDPHDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WINDIVERT_UDPHDR {{ src_port: {:?}, dst_port: {:?}, length: {:?}, checksum: {:?} }}",
            self.src_port(),
            self.dst_port(),
            self.length(),
            self.checksum()
        )
    }
}

/// [UDP header](WINDIVERT_UDPHDR) pointer type.
pub type PWINDIVERT_UDPHDR = *mut WINDIVERT_UDPHDR;
