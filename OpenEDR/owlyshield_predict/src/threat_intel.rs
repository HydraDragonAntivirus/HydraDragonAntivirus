//! High-performance Threat Intelligence Scanner for OwlyShield Rust Engine.
//! Uses `hydradragonxorfilter` (`jdb_xorf` BinaryFuse16) crate directly
//! and CIDR Blacklists with public IP scoping and XorFilter False Positive protection.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub use hydradragonxorfilter::{key, XorFilter};

/// Fast std::net bitwise check for Public IP addresses.
/// Returns false for Loopback, Private (RFC 1918), Link-Local, Broadcast, and Unspecified addresses.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (v6.segments()[0] & 0xfe00) != 0xfc00
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Fast CIDR Subnet Index (IPv4 & IPv6).
#[derive(Default)]
pub struct CidrBlacklistIndex {
    v4: HashMap<u32, HashSet<u32>>,
    v6: HashMap<u32, HashSet<String>>,
}

impl CidrBlacklistIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_v4_file<P: AsRef<Path>>(&mut self, path: P) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((addr_str, prefix_str)) = trimmed.split_once('/') {
                    if let (Ok(ipv4), Ok(prefix)) = (addr_str.parse::<Ipv4Addr>(), prefix_str.parse::<u32>()) {
                        if prefix <= 32 {
                            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                            let net = u32::from(ipv4) & mask;
                            self.v4.entry(prefix).or_default().insert(net);
                        }
                    }
                }
            }
        }
    }

    pub fn load_v6_file<P: AsRef<Path>>(&mut self, path: P) {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((addr_str, prefix_str)) = trimmed.split_once('/') {
                    if let (Ok(ipv6), Ok(prefix)) = (addr_str.parse::<Ipv6Addr>(), prefix_str.parse::<u32>()) {
                        if prefix <= 128 {
                            let key = Self::masked_key_v6(&ipv6.octets(), prefix);
                            self.v6.entry(prefix).or_default().insert(key);
                        }
                    }
                }
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let val = u32::from(ipv4);
                for (&prefix, set) in &self.v4 {
                    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                    if set.contains(&(val & mask)) {
                        return true;
                    }
                }
                false
            }
            IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                for (&prefix, set) in &self.v6 {
                    let key = Self::masked_key_v6(&octets, prefix);
                    if set.contains(&key) {
                        return true;
                    }
                }
                false
            }
        }
    }

    fn masked_key_v6(addr: &[u8; 16], prefix: u32) -> String {
        let mut m = [0u8; 16];
        for i in 0..16 {
            let bit_start = (i * 8) as u32;
            if bit_start + 8 <= prefix {
                m[i] = addr[i];
            } else if bit_start >= prefix {
                m[i] = 0;
            } else {
                let keep = prefix - bit_start;
                let mask = (0xFF << (8 - keep)) & 0xFF;
                m[i] = addr[i] & (mask as u8);
            }
        }
        format!("{}:{}", prefix, hex::encode(m))
    }
}

/// Unified Threat Intelligence Scanner using `hydradragonxorfilter` (`jdb_xorf` BinaryFuse16).
pub struct ThreatIntelScanner {
    ip_filters: HashMap<String, XorFilter>,
    domain_filters: HashMap<String, XorFilter>,
    cidr_index: CidrBlacklistIndex,
}

pub fn get_threat_intel_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        use winreg::RegKey;
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK") {
            if let Ok(p) = key.get_value::<String, _>("THREAT_INTEL_PATH") {
                return std::path::PathBuf::from(p);
            }
        }
    }
    std::path::PathBuf::from(r"C:\ProgramData\edrsvc\threat_intel")
}

impl ThreatIntelScanner {
    pub fn load_default() -> Self {
        Self::load_from_dir(get_threat_intel_path())
    }

    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Self {
        let mut scanner = Self {
            ip_filters: HashMap::new(),
            domain_filters: HashMap::new(),
            cidr_index: CidrBlacklistIndex::new(),
        };

        let dir_path = dir.as_ref();

        // Load CIDR files
        scanner.cidr_index.load_v4_file(dir_path.join("CIDRBlackListIPv4.txt"));
        scanner.cidr_index.load_v6_file(dir_path.join("CIDRBlackListIPv6.txt"));

        // Load `.xf` filters using hydradragonxorfilter (jdb_xorf) crate
        let xf_names = [
            "ipmalware.xf", "ipbruteforce.xf", "ipddos.xf", "ipphishing.xf", "ipspam.xf",
            "malicious.xf", "malwareurl.xf", "phishingurl.xf", "phishing.xf",
            "malicious_mail.xf", "spam.xf", "abuse.xf", "mining.xf"
        ];

        for name in xf_names {
            let path = dir_path.join(name);
            if let Ok(mut file) = File::open(&path) {
                let mut bytes = Vec::new();
                if file.read_to_end(&mut bytes).is_ok() {
                    if let Some(filter) = XorFilter::from_bytes(&bytes) {
                        if name.starts_with("ip") {
                            scanner.ip_filters.insert(name.to_string(), filter);
                        } else {
                            scanner.domain_filters.insert(name.to_string(), filter);
                        }
                    }
                }
            }
        }

        scanner
    }

    /// Check if IP matches any CIDR or IP XorFilter.
    /// Only public IPs are evaluated. Loopback/Private IPs return None.
    pub fn check_ip(&self, ip: IpAddr) -> Option<String> {
        if !is_public_ip(ip) {
            return None;
        }

        // 1. CIDR match
        if self.cidr_index.contains(ip) {
            return Some("CIDR_BLACKLIST_MATCH".to_string());
        }

        // 2. IP XorFilter match using jdb_xorf key derivation
        let ip_str = ip.to_string();
        for (name, filter) in &self.ip_filters {
            if filter.contains(&ip_str) {
                return Some(format!("XORFILTER_IP_MATCH:{}", name));
            }
        }

        None
    }

    /// Check if domain matches any Domain XorFilter.
    pub fn check_domain(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.trim().to_ascii_lowercase();
        if domain_lower.is_empty() {
            return None;
        }

        for (name, filter) in &self.domain_filters {
            if filter.contains(&domain_lower) {
                return Some(format!("XORFILTER_DOMAIN_MATCH:{}", name));
            }
        }

        None
    }
}
