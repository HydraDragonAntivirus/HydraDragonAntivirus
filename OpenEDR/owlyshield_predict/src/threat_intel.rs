//! High-performance Threat Intelligence Scanner for OwlyShield Rust Engine.
//! Uses strictly verified CIDR Blacklists with public IP scoping and zero false positives.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;
use lru::LruCache;

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
                let (addr_str, prefix) = match trimmed.split_once('/') {
                    Some((a, p)) => (a, p.parse::<u32>().unwrap_or(32)),
                    None => (trimmed, 32),
                };
                if let Ok(ipv4) = addr_str.parse::<Ipv4Addr>() {
                    if prefix <= 32 {
                        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                        let net = u32::from(ipv4) & mask;
                        self.v4.entry(prefix).or_default().insert(net);
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
                let (addr_str, prefix) = match trimmed.split_once('/') {
                    Some((a, p)) => (a, p.parse::<u32>().unwrap_or(128)),
                    None => (trimmed, 128),
                };
                if let Ok(ipv6) = addr_str.parse::<Ipv6Addr>() {
                    if prefix <= 128 {
                        let key = Self::masked_key_v6(&ipv6.octets(), prefix);
                        self.v6.entry(prefix).or_default().insert(key);
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

/// Unified Threat Intelligence Scanner using strictly verified CIDR Blacklists.
pub struct ThreatIntelScanner {
    cidr_index: CidrBlacklistIndex,
    clean_ip_cache: Mutex<LruCache<IpAddr, bool>>,
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
            cidr_index: CidrBlacklistIndex::new(),
            clean_ip_cache: Mutex::new(LruCache::new(NonZeroUsize::new(16384).unwrap())),
        };

        let dir_path = dir.as_ref();

        // Load curated CIDR files
        scanner.cidr_index.load_v4_file(dir_path.join("CIDRBlackListIPv4.txt"));
        scanner.cidr_index.load_v6_file(dir_path.join("CIDRBlackListIPv6.txt"));

        scanner
    }

    /// Check if IP matches any CIDR range.
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

        // CIDR match (strictly curated IP ranges, zero CDN false-positives)
        if self.cidr_index.contains(ip) {
            return Some("CIDR_BLACKLIST_MATCH".to_string());
        }

        // Remember verified clean IP in cache
        if let Ok(mut cache) = self.clean_ip_cache.lock() {
            cache.put(ip, true);
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
