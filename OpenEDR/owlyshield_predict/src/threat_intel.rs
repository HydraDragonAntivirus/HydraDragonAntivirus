//! High-performance Threat Intelligence Scanner for OwlyShield Rust Engine.
//! Uses `hydradragonxorfilter` (`jdb_xorf` BinaryFuse16) crate directly
//! and CIDR Blacklists with public IP scoping and XorFilter False Positive protection.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;
use lru::LruCache;

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

/// Mozilla Gecko / Chromium restricted ports (Cross-Protocol Slipstream / SSRF / NAT Pinning protection).
/// Reference: https://github.com/mozilla/gecko-dev/blob/771bc161e016e2bd1f7982a88d387916fdf350dd/netwerk/base/nsIOService.cpp#L117
pub const RESTRICTED_BAD_PORTS: &[u16] = &[
    1,      // tcpmux - TCP Port Service Multiplexer
    7,      // echo - Echo Protocol
    9,      // discard - Discard Protocol
    11,     // systat - Active Users Protocol
    13,     // daytime - Daytime Protocol
    15,     // netstat - Netstat Service
    17,     // qotd - Quote of the Day
    19,     // chargen - Character Generator Protocol
    20,     // ftp-data - FTP Data Transfer (FileZilla, TotalCmd, FTP clients)
    21,     // ftp - FTP Control Command (FileZilla, WinSCP, FTP clients)
    22,     // ssh - Secure Shell (OpenSSH, PuTTY, Git, VSCode, WinSCP)
    23,     // telnet - Telnet Protocol
    25,     // smtp - Simple Mail Transfer Protocol (Outlook, Thunderbird, Mail clients)
    37,     // time - Time Protocol
    42,     // name - Host Name Server
    43,     // nicname - Whois Protocol
    53,     // domain - Domain Name System (System DNS Resolvers, Windows DNS)
    69,     // tftp - Trivial File Transfer Protocol
    77,     // priv-rjs - Private Remote Job Service
    79,     // finger - Finger Protocol
    87,     // ttylink - TTY Link Service
    95,     // supdup - SUPDUP Protocol
    101,    // hostname - NIC Host Name Server
    102,    // iso-tsap - ISO-TSAP Class 0 Protocol
    103,    // gppitnp - Genesis Point-to-Point Trans Net
    104,    // acr-nema - Digital Imaging & Communications in Medicine
    109,    // pop2 - Post Office Protocol v2
    110,    // pop3 - Post Office Protocol v3 (Outlook, Thunderbird, Mail clients)
    111,    // sunrpc - SUN Remote Procedure Call
    113,    // auth - Authentication Service / Ident
    115,    // sftp - Simple File Transfer Protocol
    117,    // uucp-path - UUCP Path Service
    119,    // nntp - Network News Transfer Protocol
    123,    // ntp - Network Time Protocol (Windows Time Service)
    135,    // loc-srv / epmap - RPC Endpoint Mapper (Windows System, SMB)
    137,    // netbios - NetBIOS Name Service (Windows System, Explorer)
    139,    // netbios - NetBIOS Session Service (Windows System, Explorer)
    143,    // imap2 - Internet Message Access Protocol (Outlook, Thunderbird)
    161,    // snmp - Simple Network Management Protocol
    179,    // bgp - Border Gateway Protocol
    389,    // ldap - Lightweight Directory Access Protocol (Active Directory)
    427,    // afp (alternate) - Apple Filing Protocol
    465,    // smtp (alternate) - SMTPS Secure Mail (Outlook, Thunderbird)
    512,    // print / exec - Remote Process Execution
    513,    // login - Remote Login
    514,    // shell - Remote Shell
    515,    // printer - Line Printer Daemon
    526,    // tempo - Tempo Protocol
    530,    // courier - RPC Courier
    531,    // chat - IRC Chat / Conference
    532,    // netnews - Readnews
    540,    // uucp - UUCP Daemon
    548,    // afp - Apple Filing Protocol
    554,    // rtsp - Real Time Streaming Protocol (VLC, Media Players)
    556,    // remotefs - Remote File System
    563,    // nntp+ssl - NNTPS Secure News
    587,    // smtp (outgoing) - SMTP Submission (Outlook, Thunderbird)
    601,    // syslog-conn - Reliable Syslog Service
    636,    // ldap+ssl - LDAPS Secure Active Directory
    989,    // ftps-data - FTPS Secure Data
    990,    // ftps - FTPS Secure Control (FileZilla, WinSCP)
    993,    // imap+ssl - IMAPS Secure Mail (Outlook, Thunderbird)
    995,    // pop3+ssl - POP3S Secure Mail (Outlook, Thunderbird)
    1719,   // h323gatestat - H.323 Gatekeeper Status
    1720,   // h323hostcall - H.323 Call Setup
    1723,   // pptp - Point-to-Point Tunneling Protocol (VPN)
    2049,   // nfs - Network File System
    3659,   // apple-sasl - Apple SASL Service
    4045,   // lockd - NFS Lock Daemon
    4190,   // sieve - ManageSieve Mail Filter
    5060,   // sip - Session Initiation Protocol (VoIP, Softphones)
    5061,   // sips - SIPS Secure VoIP
    6000,   // x11 - X11 Display Server
    6566,   // sane-port - SANE Network Scanner
    6665,   // irc (alternate) - Internet Relay Chat (HexChat, mIRC)
    6666,   // irc (alternate) - Internet Relay Chat
    6667,   // irc (default) - Internet Relay Chat
    6668,   // irc (alternate) - Internet Relay Chat
    6669,   // irc (alternate) - Internet Relay Chat
    6679,   // osaut - IRC SSL Alternate
    6697,   // irc+tls - Secure IRC TLS (HexChat, mIRC)
    10080,  // amanda - Amanda Backup Protocol
];

pub fn is_restricted_port(port: u16) -> bool {
    RESTRICTED_BAD_PORTS.binary_search(&port).is_ok()
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

///// Unified Threat Intelligence Scanner using `hydradragonxorfilter` (`jdb_xorf` BinaryFuse16).
pub struct ThreatIntelScanner {
    ip_filters: HashMap<String, XorFilter>,
    domain_filters: HashMap<String, XorFilter>,
    cidr_index: CidrBlacklistIndex,
    clean_ip_cache: Mutex<LruCache<IpAddr, bool>>,
    clean_domain_cache: Mutex<LruCache<String, bool>>,
}

pub fn get_threat_intel_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK") {
            if let Ok(p) = key.get_value::<String, _>("THREAT_INTEL_PATH") {
                let path = std::path::PathBuf::from(p);
                if path.exists() {
                    return path;
                }
            }
        }
    }

    let canonical_path = std::path::PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\threat_intel");
    if canonical_path.exists() && canonical_path.is_dir() {
        return canonical_path;
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let relative_path = exe_dir.join("threat_intel");
            if relative_path.exists() && relative_path.is_dir() {
                return relative_path;
            }
        }
    }

    canonical_path
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
            clean_ip_cache: Mutex::new(LruCache::new(NonZeroUsize::new(16384).unwrap())),
            clean_domain_cache: Mutex::new(LruCache::new(NonZeroUsize::new(16384).unwrap())),
        };

        let dir_path = dir.as_ref();

        // Load CIDR files
        scanner.cidr_index.load_v4_file(dir_path.join("CIDRBlackListIPv4.txt"));
        scanner.cidr_index.load_v6_file(dir_path.join("CIDRBlackListIPv6.txt"));

        // Dynamically scan directory for ALL `.xf` files
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext.eq_ignore_ascii_case("xf") {
                            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                                let file_name_lower = file_name.to_ascii_lowercase();
                                if let Ok(mut file) = File::open(&path) {
                                    let mut bytes = Vec::new();
                                    if file.read_to_end(&mut bytes).is_ok() {
                                        if let Some(filter) = XorFilter::from_bytes(&bytes) {
                                            if file_name_lower.starts_with("ip") {
                                                scanner.ip_filters.insert(file_name_lower, filter);
                                            } else {
                                                scanner.domain_filters.insert(file_name_lower, filter);
                                            }
                                        }
                                    }
                                }
                            }
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

        // Fast path: Clean IP Cache (O(1) in ~5 nanoseconds)
        if let Ok(mut cache) = self.clean_ip_cache.lock() {
            if cache.get(&ip).is_some() {
                return None;
            }
        }

        // 1. CIDR match
        if self.cidr_index.contains(ip) {
            return Some("CIDR_BLACKLIST_MATCH".to_string());
        }

        // 2. IP XorFilter match using jdb_xorf key derivation (strictly IP filters)
        let ip_str = ip.to_string();
        for (name, filter) in &self.ip_filters {
            if filter.contains(&ip_str) {
                return Some(format!("XORFILTER_IP_MATCH:{}", name));
            }
        }

        // Remember verified clean IP in cache so subsequent packets never touch CIDR/XorFilters
        if let Ok(mut cache) = self.clean_ip_cache.lock() {
            cache.put(ip, true);
        }

        None
    }

    /// Check if domain or any of its parent subdomains matches any Domain XorFilter.
    /// If target string is actually an IP address, it is routed to check_ip automatically.
    pub fn check_domain(&self, domain: &str) -> Option<String> {
        let mut clean_domain = domain.trim().to_ascii_lowercase();
        if clean_domain.is_empty() {
            return None;
        }

        // Strip protocol prefix (e.g. "https://example.com/path" -> "example.com/path")
        if let Some(pos) = clean_domain.find("://") {
            clean_domain = clean_domain[pos + 3..].to_string();
        }

        // Strip path, query params, or fragments (e.g. "example.com/path?id=1" -> "example.com")
        if let Some(pos) = clean_domain.find('/') {
            clean_domain = clean_domain[..pos].to_string();
        }

        // Strip port if present (e.g. "example.com:443" -> "example.com")
        if let Some((host, _port)) = clean_domain.split_once(':') {
            clean_domain = host.to_string();
        }

        // Strip trailing dot
        if clean_domain.ends_with('.') {
            clean_domain.pop();
        }

        if clean_domain.is_empty() {
            return None;
        }

        // If target is an IP address, route strictly to IP scanner
        if let Ok(ip) = clean_domain.parse::<IpAddr>() {
            return self.check_ip(ip);
        }

        // Fast path: Clean Domain Cache (O(1) in ~5 nanoseconds)
        if let Ok(mut cache) = self.clean_domain_cache.lock() {
            if cache.get(&clean_domain).is_some() {
                return None;
            }
        }

        // Target is a Domain: Query DOMAIN filters using psl (Public Suffix List) eTLD+1 boundary
        use psl::Psl;

        let root_domain = psl::List.domain(clean_domain.as_bytes())
            .and_then(|d| std::str::from_utf8(d.as_bytes()).ok())
            .unwrap_or(&clean_domain);

        let parts: Vec<&str> = clean_domain.split('.').collect();
        if parts.len() <= 1 {
            for (name, filter) in &self.domain_filters {
                if filter.contains(&clean_domain) {
                    return Some(format!("XORFILTER_DOMAIN_MATCH:{}", name));
                }
            }
        } else {
            for i in 0..parts.len() {
                let sub_candidate = parts[i..].join(".");
                if sub_candidate.len() < root_domain.len() {
                    break;
                }

                for (name, filter) in &self.domain_filters {
                    if filter.contains(&sub_candidate) {
                        return Some(format!("XORFILTER_DOMAIN_MATCH:{}", name));
                    }
                }

                if sub_candidate == root_domain {
                    break; // Stop at eTLD+1 root registered domain to prevent False Positives (FP)
                }
            }
        }

        // Remember verified clean domain in cache
        if let Ok(mut cache) = self.clean_domain_cache.lock() {
            cache.put(clean_domain, true);
        }

        None
    }

    /// Check if target port is a Mozilla Gecko / Chromium restricted port (gBadPortList).
    pub fn check_port(&self, port: u16) -> Option<String> {
        if is_restricted_port(port) {
            return Some(format!("RESTRICTED_BAD_PORT_MATCH:port_{}", port));
        }
        None
    }
}
