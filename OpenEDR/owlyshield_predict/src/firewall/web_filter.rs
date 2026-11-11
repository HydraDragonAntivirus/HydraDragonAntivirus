use moka::sync::Cache;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    fn add(&mut self, cidr: &str) -> bool {
        let trimmed = cidr.trim();
        if trimmed == "0.0.0.0/0"
            || trimmed == "0.0.0.0"
            || trimmed == "::/0"
            || trimmed == "::"
            || trimmed.ends_with("/0")
        {
            return false;
        }
        match Self::parse_interval(cidr) {
            Some(CidrInterval::V4(start, end)) => {
                self.v4.push((start, end));
                true
            }
            Some(CidrInterval::V6(start, end)) => {
                self.v6.push((start, end));
                true
            }
            None => false,
        }
    }

    fn normalize(&mut self) {
        Self::merge_intervals_u32(&mut self.v4);
        Self::merge_intervals_u128(&mut self.v6);
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => Self::contains_value(&self.v4, u32::from(ipv4)),
            IpAddr::V6(ipv6) => Self::contains_value(&self.v6, u128::from(ipv6)),
        }
    }

    fn parse_interval(cidr: &str) -> Option<CidrInterval> {
        let cidr = cidr.trim();
        if let Some((network, prefix)) = cidr.split_once('/') {
            let prefix_len = prefix.parse::<u32>().ok()?;

            if let Ok(ipv4) = network.parse::<Ipv4Addr>() {
                // 0.0.0.0/0 protection: prefix_len == 0 or unspecified IP matches entire IPv4 space
                if prefix_len == 0 || prefix_len > 32 || ipv4.is_unspecified() {
                    return None;
                }
                let mask = !0u32 << (32 - prefix_len);
                let start = u32::from(ipv4) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V4(start, end));
            }

            if let Ok(ipv6) = network.parse::<Ipv6Addr>() {
                // ::/0 protection: prefix_len == 0 or unspecified IP matches entire IPv6 space
                if prefix_len == 0 || prefix_len > 128 || ipv6.is_unspecified() {
                    return None;
                }
                let mask = !0u128 << (128 - prefix_len);
                let start = u128::from(ipv6) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V6(start, end));
            }

            return None;
        }

        match cidr.parse::<IpAddr>().ok()? {
            IpAddr::V4(ipv4) => {
                if ipv4.is_unspecified() || ipv4.is_broadcast() {
                    return None;
                }
                let value = u32::from(ipv4);
                Some(CidrInterval::V4(value, value))
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unspecified() {
                    return None;
                }
                let value = u128::from(ipv6);
                Some(CidrInterval::V6(value, value))
            }
        }
    }

    fn merge_intervals_u32(intervals: &mut Vec<(u32, u32)>) {
        intervals.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(intervals.len());

        for &(start, end) in intervals.iter() {
            let Some(last) = merged.last_mut() else {
                merged.push((start, end));
                continue;
            };

            if start > last.1.saturating_add(1) {
                merged.push((start, end));
            } else if end > last.1 {
                last.1 = end;
            }
        }

        *intervals = merged;
    }

    fn merge_intervals_u128(intervals: &mut Vec<(u128, u128)>) {
        intervals.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(intervals.len());

        for &(start, end) in intervals.iter() {
            let Some(last) = merged.last_mut() else {
                merged.push((start, end));
                continue;
            };

            if start > last.1.saturating_add(1) {
                merged.push((start, end));
            } else if end > last.1 {
                last.1 = end;
            }
        }

        *intervals = merged;
    }

    fn contains_value<T>(intervals: &[(T, T)], value: T) -> bool
    where
        T: Copy + Ord,
    {
        let index = intervals.partition_point(|&(start, _)| start <= value);
        index > 0 && intervals[index - 1].1 >= value
    }
}

enum CidrInterval {
    V4(u32, u32),
    V6(u128, u128),
}

#[derive(Clone)]
pub struct WebFilter {
    cidr_blocklist: Arc<RwLock<CidrIndex>>,
    clean_flow_cache: Cache<(IpAddr, IpAddr, u16), ()>,
    ssl_blacklist: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl Default for WebFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl WebFilter {
    pub fn new() -> Self {
        Self {
            cidr_blocklist: Arc::new(RwLock::new(CidrIndex::default())),
            clean_flow_cache: Cache::builder()
                .max_capacity(65536)
                .time_to_live(Duration::from_secs(300))
                .build(),
            ssl_blacklist: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Check if an SSL certificate SHA-1 fingerprint (Abuse.ch SSLBL) is blacklisted.
    pub fn is_ssl_blacklisted(&self, sha1: &str) -> bool {
        let clean = sha1.trim().replace(':', "").to_ascii_lowercase();
        if clean.len() != 40 {
            return false;
        }
        if self.ssl_blacklist.read().unwrap().contains(&clean) {
            return true;
        }
        // Also check cloud threat intel target directly
        if query_cloud_threat_target(&clean).is_some() {
            self.ssl_blacklist.write().unwrap().insert(clean);
            return true;
        }
        false
    }

    pub fn add_ssl_blacklist_entry(&self, sha1: &str) {
        let clean = sha1.trim().replace(':', "").to_ascii_lowercase();
        if clean.len() == 40 {
            self.ssl_blacklist.write().unwrap().insert(clean);
        }
    }

    pub fn find_match_cached(
        &self,
        flow_key: (IpAddr, IpAddr, u16),
        remote_ip: IpAddr,
    ) -> Option<WebThreatMatch> {
        if self.clean_flow_cache.contains_key(&flow_key) {
            return None;
        }
        match self.find_match(remote_ip) {
            Some(m) => Some(m),
            None => {
                self.clean_flow_cache.insert(flow_key, ());
                None
            }
        }
    }

    pub fn load_default() -> Self {
        let filter = Self::new();
        let path = Self::get_threat_intel_path();
        if path.exists() {
            let _ = filter.load_from_folder(&path);
        }
        filter
    }

    fn get_threat_intel_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            use winreg::enums::HKEY_LOCAL_MACHINE;
            use winreg::RegKey;
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Owlyshield\SDK") {
                if let Ok(p) = key.get_value::<String, _>("THREAT_INTEL_PATH") {
                    let path = PathBuf::from(p);
                    if path.exists() {
                        return path;
                    }
                }
            }
        }
        PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\threat_intel")
    }

    pub fn load_from_folder(&self, base_path: &Path) -> std::io::Result<usize> {
        let mut count = 0;

        let v4_file = base_path.join("CIDRBlackListIPv4.txt");
        if v4_file.exists() {
            if let Ok(c) = self.load_txt_file(&v4_file) {
                count += c;
            }
        }

        let v6_file = base_path.join("CIDRBlackListIPv6.txt");
        if v6_file.exists() {
            if let Ok(c) = self.load_txt_file(&v6_file) {
                count += c;
            }
        }

        self.cidr_blocklist.write().unwrap().normalize();

        let ssl_file = base_path.join("ssl_blacklist.txt");
        if ssl_file.exists() {
            if let Ok(file) = File::open(&ssl_file) {
                let reader = BufReader::new(file);
                let mut ssl_set = self.ssl_blacklist.write().unwrap();
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim().replace(':', "").to_ascii_lowercase();
                    if trimmed.len() == 40 && !trimmed.starts_with('#') {
                        ssl_set.insert(trimmed);
                    }
                }
            }
        }

        Ok(count)
    }

    fn load_txt_file(&self, path: &Path) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        let mut cidr_blocklist = self.cidr_blocklist.write().unwrap();

        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if cidr_blocklist.add(trimmed) {
                count += 1;
            }
        }

        Ok(count)
    }

    pub fn is_blocked_ip(&self, ip: IpAddr) -> bool {
        // Never block unspecified (0.0.0.0, ::) or loopback addresses via CIDR blacklist
        if ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        if self.cidr_blocklist.read().unwrap().contains(ip) {
            return true;
        }
        query_cloud_threat_target(&ip.to_string()).is_some()
    }

    pub fn find_match(&self, remote_ip: IpAddr) -> Option<WebThreatMatch> {
        if remote_ip.is_unspecified() || remote_ip.is_loopback() {
            return None;
        }

        // 1. Check local in-memory CIDR index if available
        if self.cidr_blocklist.read().unwrap().contains(remote_ip) {
            return Some(WebThreatMatch::ip(
                remote_ip.to_string(),
                format!("Blocked Malicious CIDR: {}", remote_ip),
            ));
        }

        // 2. Query viruskov.com cloud threat intel directly
        let ip_str = remote_ip.to_string();
        if let Some(cloud_hit) = query_cloud_threat_target(&ip_str) {
            return Some(cloud_hit);
        }

        None
    }
}

pub fn query_cloud_threat_target(target: &str) -> Option<WebThreatMatch> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};

        if target.is_empty() || target == "127.0.0.1" || target == "localhost" || target == "::1" {
            return None;
        }

        type ScanUrlFn = unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char;
        type FreeFn = unsafe extern "C" fn(*mut std::os::raw::c_char);

        static SCAN_PAIR: std::sync::OnceLock<Option<(ScanUrlFn, FreeFn)>> = std::sync::OnceLock::new();
        let pair = SCAN_PAIR.get_or_init(|| unsafe {
            for name in &["openedr_cloud.dll\0", "openedr_static.dll\0"] {
                let wide: Vec<u16> = name.encode_utf16().collect();
                let h = GetModuleHandleW(PCWSTR(wide.as_ptr()))
                    .or_else(|_| LoadLibraryW(PCWSTR(wide.as_ptr())))
                    .ok();
                if let Some(mod_handle) = h {
                    let scan_proc = GetProcAddress(mod_handle, PCSTR(b"openedr_cloud_scan_url\0".as_ptr()))
                        .or_else(|| GetProcAddress(mod_handle, PCSTR(b"openedr_static_scan_url\0".as_ptr())));
                    let free_proc = GetProcAddress(mod_handle, PCSTR(b"openedr_cloud_free_string\0".as_ptr()))
                        .or_else(|| GetProcAddress(mod_handle, PCSTR(b"openedr_static_free_string\0".as_ptr())));
                    if let (Some(s_proc), Some(f_proc)) = (scan_proc, free_proc) {
                        return Some((std::mem::transmute(s_proc), std::mem::transmute(f_proc)));
                    }
                }
            }
            None
        });

        let (scan_fn, free_fn) = (*pair)?;
        let c_target = std::ffi::CString::new(target).ok()?;
        let ptr = unsafe { scan_fn(c_target.as_ptr()) };
        if ptr.is_null() {
            return None;
        }
        let json_str = unsafe {
            let s = std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned();
            free_fn(ptr);
            s
        };

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
            let is_mal = val.get("is_malicious").and_then(|v| v.as_bool()).unwrap_or(false);
            let is_black = val.get("blacklisted").and_then(|v| v.as_bool()).unwrap_or(false);
            let verdict = val.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
            if is_mal || is_black || verdict.eq_ignore_ascii_case("malicious") {
                return Some(WebThreatMatch::ip(
                    target.to_string(),
                    format!("VirusKov Cloud Threat Intelligence: {}", target),
                ));
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
pub enum WebThreatTargetKind {
    Url,
    Hostname,
    Ip,
}

#[derive(Clone, Debug)]
pub struct WebThreatMatch {
    pub kind: WebThreatTargetKind,
    pub target: String,
    pub reason: String,
}

impl WebThreatMatch {
    pub fn ip(target: String, reason: String) -> Self {
        Self {
            kind: WebThreatTargetKind::Ip,
            target,
            reason,
        }
    }

    pub fn url(target: String, reason: String) -> Self {
        Self {
            kind: WebThreatTargetKind::Url,
            target,
            reason,
        }
    }

    pub fn decision_key(&self) -> String {
        match self.kind {
            WebThreatTargetKind::Ip => format!("website:ip:{}", self.target.trim().to_lowercase()),
            WebThreatTargetKind::Url => format!("website:url:{}", self.target.trim().to_lowercase()),
            WebThreatTargetKind::Hostname => format!("website:host:{}", self.target.trim().to_lowercase()),
        }
    }
}
