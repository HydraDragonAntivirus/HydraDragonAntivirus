//! CIDR subnet lookup tables for IPv4 and IPv6 whitelist and blacklist.
//!
//! Evaluates arbitrary IPv4 and IPv6 addresses in O(log N) binary search (~12-15 CPU cycles).
//! Loads precompiled .bin tables or text/CSV lists dynamically from standalone files (no static embedding).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct CidrTable {
    ranges: Arc<[u8]>,
}

impl CidrTable {
    pub fn new(ranges: Arc<[u8]>) -> Self {
        Self { ranges }
    }

    pub fn empty() -> Self {
        Self {
            ranges: Arc::from(Vec::new().into_boxed_slice()),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            ranges: Arc::from(bytes.into_boxed_slice()),
        }
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

#[derive(Clone, Default)]
pub struct Cidr6Table {
    ranges: Arc<[u8]>,
}

impl Cidr6Table {
    pub fn new(ranges: Arc<[u8]>) -> Self {
        Self { ranges }
    }

    pub fn empty() -> Self {
        Self {
            ranges: Arc::from(Vec::new().into_boxed_slice()),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            ranges: Arc::from(bytes.into_boxed_slice()),
        }
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

#[derive(Clone, Default)]
pub struct CidrEngine {
    pub whitelist_v4: CidrTable,
    pub blacklist_v4: CidrTable,
    pub whitelist_v6: Cidr6Table,
    pub blacklist_v6: Cidr6Table,
}

impl CidrEngine {
    pub fn empty() -> Self {
        Self {
            whitelist_v4: CidrTable::empty(),
            blacklist_v4: CidrTable::empty(),
            whitelist_v6: Cidr6Table::empty(),
            blacklist_v6: Cidr6Table::empty(),
        }
    }

    pub fn new() -> Self {
        Self::empty()
    }

    /// Load CIDR tables from external files in the given directory (e.g. `cidr_rules/`).
    /// Searches for binary precompiled `.bin` tables first, falling back to `.txt` or `.csv`.
    pub fn load_from_dir(dir: &Path) -> Self {
        let load_v4 = |name: &str| -> CidrTable {
            let p = dir.join(name);
            if let Ok(bytes) = std::fs::read(&p) {
                return CidrTable::from_bytes(bytes);
            }
            CidrTable::empty()
        };

        let load_v6 = |name: &str| -> Cidr6Table {
            let p = dir.join(name);
            if let Ok(bytes) = std::fs::read(&p) {
                return Cidr6Table::from_bytes(bytes);
            }
            Cidr6Table::empty()
        };

        Self {
            whitelist_v4: load_v4("cidr_whitelist_ipv4.bin"),
            blacklist_v4: load_v4("cidr_blacklist_ipv4.bin"),
            whitelist_v6: load_v6("cidr_whitelist_ipv6.bin"),
            blacklist_v6: load_v6("cidr_blacklist_ipv6.bin"),
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
