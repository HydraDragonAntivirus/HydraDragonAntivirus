/*!
WinDivert address types.

For more info, refer to the [docs](https://reqrypt.org/windivert-doc.html#divert_address).
*/

use std::{convert::TryFrom, fmt::Debug};

use super::{BitfieldUnit, WinDivertEvent, WinDivertFlags, WinDivertLayer};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
/**
Represents the associated data recieved using [`WinDivertLayer::Network`]
*/
pub struct WINDIVERT_DATA_NETWORK {
    /// Interface index on whick the packet arrived (for inbound packets) or will be sent (for outbound packets).
    pub interface_id: u32,
    /// The sub-interface index for `interface_id`
    pub subinterface_id: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
/**
Represents the associated data recieved using [`WinDivertLayer::Flow`]
*/
pub struct WINDIVERT_DATA_FLOW {
    /// The endpoint ID of the flow.
    pub endpoint_id: u64,
    /// The parent endpoint ID of the flow.
    pub parent_endpoint_id: u64,
    /// The id of the process associated with the flow.
    pub process_id: u32,
    /**
    The local address associated with the socket.

    For IPv4, this field will contain IPv4-mapped IPv6 addresses, e.g. the IPv4 address X.Y.Z.W will be represented by ::ffff:X.Y.Z.W.

    This field can contain a value o zero, since [`SocketBind`](WinDivertEvent::SocketBind) and [`SocketBind`](WinDivertEvent::SocketListen) events can occur before a connection attempt has been made.
    */
    pub local_addr: [u32; 4usize],
    /**
    The remote address associated with the socket.

    For IPv4, this field will contain IPv4-mapped IPv6 addresses, e.g. the IPv4 address X.Y.Z.W will be represented by ::ffff:X.Y.Z.W.

    This field can contain a value o zero, since [`SocketBind`](WinDivertEvent::SocketBind) and [`SocketBind`](WinDivertEvent::SocketListen) events can occur before a connection attempt has been made.
    */
    pub remote_addr: [u32; 4usize],
    /// The local port associated with the flow.
    pub local_port: u16,
    /// The remote port associated with the flow.
    pub remote_port: u16,
    /// The flow protocol.
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
/**
Represents the associated data recieved using [`WinDivertLayer::Socket`]
*/
pub struct WINDIVERT_DATA_SOCKET {
    /// The endpoint ID of the socket.
    pub endpoint_id: u64,
    /// The parent endpoint ID of the socket.
    pub parent_endpoint_id: u64,
    /// The id of the process associated with the socket.
    pub process_id: u32,
    /**
    The local address associated with the socket.

    For IPv4, this field will contain IPv4-mapped IPv6 addresses, e.g. the IPv4 address X.Y.Z.W will be represented by ::ffff:X.Y.Z.W.
    */
    pub local_addr: [u32; 4usize],
    /**
    The remote address associated with the socket.

    For IPv4, this field will contain IPv4-mapped IPv6 addresses, e.g. the IPv4 address X.Y.Z.W will be represented by ::ffff:X.Y.Z.W.
    */
    pub remote_addr: [u32; 4usize],
    /// The local port associated with the socket.
    pub local_port: u16,
    /// The remote port associated with the socket.
    pub remote_port: u16,
    /// The socket protocol.
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/**
Represents the associated data recieved using [`WinDivertLayer::Reflect`]
*/
pub struct WINDIVERT_DATA_REFLECT {
    /// Timestamp indicating when the handle was opened.
    pub timestamp: i64,
    /// Process if of the process that opened the handle.
    pub process_id: u32,
    /// [`WinDivertLayer`] parameter on [`WinDivertOpen`](super::WinDivertOpen) for the specified handle.
    pub layer: WinDivertLayer,
    /// [`WinDivertFlags`] parameter on [`WinDivertOpen`](super::WinDivertOpen) for the specified handle.
    pub flags: WinDivertFlags,
    /// Priority parameter on [`WinDivertOpen`](super::WinDivertOpen) for the specified handle.
    pub priority: i16,
}

impl Default for WINDIVERT_DATA_REFLECT {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Union of the different data types associated with the possible layer values.
pub union WINDIVERT_ADDRESS_UNION_FIELD {
    /// Address data related to [`Network`](WinDivertLayer::Network) and [`Forward`](WinDivertLayer::Forward) layers.
    pub Network: WINDIVERT_DATA_NETWORK,
    /// Address data related to [`Flow`](WinDivertLayer::Flow) layer.
    pub Flow: WINDIVERT_DATA_FLOW,
    /// Address data related to [`Socket`](WinDivertLayer::Socket) layer.
    pub Socket: WINDIVERT_DATA_SOCKET,
    /// Address data related to [`Reflect`](WinDivertLayer::Reflect) layer.
    pub Reflect: WINDIVERT_DATA_REFLECT,
    reserved: [u8; 64usize],
    _union_align: [u64; 8usize],
}

impl Default for WINDIVERT_ADDRESS_UNION_FIELD {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
/**
Base data type returned by [`recv`](fn@super::WinDivertRecv) and required by [`send`](fn@super::WinDivertSend)

Most address fields are ignored by [`WinDivertSend()`](fn@super::WinDivertSend). The exceptions are Outbound (for [`WinDivertLayer::Network`] layer only), Impostor, IPChecksum, TCPChecksum, UDPChecksum, [`Network.interface_id`](WINDIVERT_DATA_NETWORK::interface_id) and [`Network.subinterface_id`](WINDIVERT_DATA_NETWORK::subinterface_id).
*/
pub struct WINDIVERT_ADDRESS {
    /// Timestamp indicating when the event occurred.
    pub timestamp: i64,
    addr_bitfield: BitfieldUnit<[u8; 4usize], u8>,
    reserved: u32,
    /// Union of the different data types associated with the possible layer values.
    pub union_field: WINDIVERT_ADDRESS_UNION_FIELD,
}

impl Default for WINDIVERT_ADDRESS {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl WINDIVERT_ADDRESS {
    #[inline]
    /// Getter for the handle [`layer`](super::WinDivertLayer)
    pub fn layer(&self) -> WinDivertLayer {
        WinDivertLayer::try_from(self.addr_bitfield.get(0usize, 8u8) as u32)
            .expect("Layer always is correct since it would have produced an error in Open()")
    }
    #[inline]
    /// Setter for the handle [`layer`](super::WinDivertLayer)
    pub fn set_layer(&mut self, val: WinDivertLayer) {
        self.addr_bitfield.set(0usize, 8u8, u32::from(val) as u64)
    }
    #[inline]
    /// Getter for the handle [`event`](super::WinDivertEvent)
    pub fn event(&self) -> WinDivertEvent {
        WinDivertEvent::try_from(self.addr_bitfield.get(8usize, 8u8) as u8)
            .expect("Event always is correct since the value comes from the DLL functions.")
    }
    #[inline]
    /// Setter for the handle [`event`](super::WinDivertEvent)
    pub fn set_event(&mut self, val: WinDivertEvent) {
        self.addr_bitfield.set(8usize, 8u8, u32::from(val) as u64)
    }
    #[inline]
    /// Set to true if the packet was sniffed (not blocked).
    pub fn sniffed(&self) -> bool {
        self.addr_bitfield.get(16usize, 1u8) == 1
    }
    #[inline]
    /// Sniffed flag setter.
    pub fn set_sniffed(&mut self, val: bool) {
        self.addr_bitfield.set(16usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true for outbound packet events.
    pub fn outbound(&self) -> bool {
        self.addr_bitfield.get(17usize, 1u8) == 1
    }
    #[inline]
    /// Outbound flag setter.
    pub fn set_outbound(&mut self, val: bool) {
        self.addr_bitfield.set(17usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true for loopback packets.
    pub fn loopback(&self) -> bool {
        self.addr_bitfield.get(18usize, 1u8) == 1
    }
    #[inline]
    /// Loopback flag setter.
    pub fn set_loopback(&mut self, val: bool) {
        self.addr_bitfield.set(18usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true for "impostor" packets.
    pub fn impostor(&self) -> bool {
        self.addr_bitfield.get(19usize, 1u8) == 1
    }
    #[inline]
    /// Impostor flag setter.
    pub fn set_impostor(&mut self, val: bool) {
        self.addr_bitfield.set(19usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true for IPv6 packets.
    pub fn ipv6(&self) -> bool {
        self.addr_bitfield.get(20usize, 1u8) == 1
    }
    #[inline]
    /// IPv6 flag setter.
    pub fn set_ipv6(&mut self, val: bool) {
        self.addr_bitfield.set(20usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true if the IPv4 checksum is valid.
    pub fn ipchecksum(&self) -> bool {
        self.addr_bitfield.get(21usize, 1u8) == 1
    }
    #[inline]
    /// IPv4 checksum flag setter.
    pub fn set_ipchecksum(&mut self, val: bool) {
        self.addr_bitfield.set(21usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true if the TCP checksum is valid.
    pub fn tcpchecksum(&self) -> bool {
        self.addr_bitfield.get(22usize, 1u8) == 1
    }
    #[inline]
    /// TCP checksum flag setter.
    pub fn set_tcpchecksum(&mut self, val: bool) {
        self.addr_bitfield.set(22usize, 1u8, val as u64)
    }
    #[inline]
    /// Set to true if the UDP checksum is valid.
    pub fn udpchecksum(&self) -> bool {
        self.addr_bitfield.get(23usize, 1u8) == 1
    }
    #[inline]
    /// UDP checksum flag setter.
    pub fn set_udpchecksum(&mut self, val: bool) {
        self.addr_bitfield.set(23usize, 1u8, val as u64)
    }
}

impl Debug for WINDIVERT_ADDRESS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let union_str = match self.event() {
            WinDivertEvent::NetworkPacket => {
                format!("{:?}", unsafe { self.union_field.Network })
            }
            WinDivertEvent::FlowStablished | WinDivertEvent::FlowDeleted => {
                format!("{:?}", unsafe { self.union_field.Flow })
            }
            WinDivertEvent::SocketBind
            | WinDivertEvent::SocketConnect
            | WinDivertEvent::SocketListen
            | WinDivertEvent::SocketAccept
            | WinDivertEvent::SocketClose => {
                format!("{:?}", unsafe { self.union_field.Socket })
            }
            WinDivertEvent::ReflectOpen | WinDivertEvent::ReflectClose => {
                format!("{:?}", unsafe { self.union_field.Reflect })
            }
        };
        write!(f, "WINDIVERT_ADDRESS {{ Timestamp: {:?}, Layer: {:?}, Event: {:?}, Sniffed: {:?}, Outbound: {:?}, Loopback: {:?}, Impostor: {:?}, IPv6: {:?}, IPChecksum: {:?}, TCPChecksum: {:?}, UDPChecksum: {:?}, {}}}",
        self.timestamp, self.layer(), self.event(), self.sniffed(), self.outbound(), self.loopback(), self.impostor(), self.ipv6(), self.ipchecksum(), self.tcpchecksum(), self.udpchecksum(), union_str)
    }
}
