//! Precompiled CIDR subnet lookup tables for IPv4 and IPv6 whitelist and blacklist.
//!
//! Generated from:
//! - IPv4 Whitelist: `CIDRWhiteListIPv4.csv` (4,286 disjoint ranges, 33.5 KB)
//! - IPv4 Blacklist: `CIDRBlackListIPv4.csv` (6,924 disjoint ranges, 54.1 KB)
//! - IPv6 Whitelist: `CIDRWhiteListIPv6.csv` (37,378 disjoint ranges, 1.14 MB)
//! - IPv6 Blacklist: `CIDRBlackListIPv6.csv` (192 disjoint ranges, 6.1 KB)
//!
//! Evaluates arbitrary IPv4 and IPv6 addresses in O(log N) binary search (~12-15 CPU cycles).

use std::net::{Ipv4Addr, Ipv6Addr};

pub struct CidrTable {
    ranges: &'static [u8],
}

impl CidrTable {
    pub const fn new(ranges: &'static [u8]) -> Self {
        Self { ranges }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.ranges.len() / 8
    }

    #[inline]
    fn get_range(&self, idx: usize) -> (u32, u32) {
        let offset = idx * 8;
        let start = u32::from_le_bytes([
            self.ranges[offset],
            self.ranges[offset + 1],
            self.ranges[offset + 2],
            self.ranges[offset + 3],
        ]);
        let end = u32::from_le_bytes([
            self.ranges[offset + 4],
            self.ranges[offset + 5],
            self.ranges[offset + 6],
            self.ranges[offset + 7],
        ]);
        (start, end)
    }

    pub fn contains_u32(&self, ip: u32) -> bool {
        let n = self.count();
        if n == 0 {
            return false;
        }
        let mut low = 0;
        let mut high = n;
        while low < high {
            let mid = low + (high - low) / 2;
            let (start, end) = self.get_range(mid);
            if ip < start {
                high = mid;
            } else if ip > end {
                low = mid + 1;
            } else {
                return true;
            }
        }
        false
    }

    pub fn contains_str(&self, s: &str) -> bool {
        if let Some(ip) = parse_ipv4(s) {
            self.contains_u32(ip)
        } else {
            false
        }
    }
}

pub struct Cidr6Table {
    ranges: &'static [u8],
}

impl Cidr6Table {
    pub const fn new(ranges: &'static [u8]) -> Self {
        Self { ranges }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.ranges.len() / 32
    }

    #[inline]
    fn get_range(&self, idx: usize) -> (u128, u128) {
        let offset = idx * 32;
        let mut s_bytes = [0u8; 16];
        let mut e_bytes = [0u8; 16];
        s_bytes.copy_from_slice(&self.ranges[offset..offset + 16]);
        e_bytes.copy_from_slice(&self.ranges[offset + 16..offset + 32]);
        let start = u128::from_le_bytes(s_bytes);
        let end = u128::from_le_bytes(e_bytes);
        (start, end)
    }

    pub fn contains_u128(&self, ip: u128) -> bool {
        let n = self.count();
        if n == 0 {
            return false;
        }
        let mut low = 0;
        let mut high = n;
        while low < high {
            let mid = low + (high - low) / 2;
            let (start, end) = self.get_range(mid);
            if ip < start {
                high = mid;
            } else if ip > end {
                low = mid + 1;
            } else {
                return true;
            }
        }
        false
    }

    pub fn contains_str(&self, s: &str) -> bool {
        if let Some(ip) = parse_ipv6(s) {
            self.contains_u128(ip)
        } else {
            false
        }
    }
}

pub struct CidrEngine {
    pub whitelist_v4: CidrTable,
    pub blacklist_v4: CidrTable,
    pub whitelist_v6: Cidr6Table,
    pub blacklist_v6: Cidr6Table,
}

impl CidrEngine {
    pub const fn new() -> Self {
        Self {
            whitelist_v4: CidrTable::new(include_bytes!("cidr_whitelist_ipv4.bin")),
            blacklist_v4: CidrTable::new(include_bytes!("cidr_blacklist_ipv4.bin")),
            whitelist_v6: Cidr6Table::new(include_bytes!("cidr_whitelist_ipv6.bin")),
            blacklist_v6: Cidr6Table::new(include_bytes!("cidr_blacklist_ipv6.bin")),
        }
    }

    #[inline]
    pub fn is_whitelisted(&self, ip_str: &str) -> bool {
        self.whitelist_v4.contains_str(ip_str) || self.whitelist_v6.contains_str(ip_str)
    }

    #[inline]
    pub fn is_blacklisted(&self, ip_str: &str) -> bool {
        self.blacklist_v4.contains_str(ip_str) || self.blacklist_v6.contains_str(ip_str)
    }
}

impl Default for CidrEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_ipv4(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.contains(':') {
        return None;
    }
    s.parse::<Ipv4Addr>().ok().map(|ip| u32::from_be_bytes(ip.octets()))
}

pub fn parse_ipv6(s: &str) -> Option<u128> {
    let s = s.trim();
    let s = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(s);
    if !s.contains(':') {
        return None;
    }
    s.parse::<Ipv6Addr>().ok().map(|ip| u128::from_be_bytes(ip.octets()))
}
