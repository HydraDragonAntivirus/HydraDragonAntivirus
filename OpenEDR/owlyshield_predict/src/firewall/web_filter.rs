use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default)]
struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    fn add(&mut self, cidr: &str) -> bool {
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
                if prefix_len > 32 {
                    return None;
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let start = u32::from(ipv4) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V4(start, end));
            }

            if let Ok(ipv6) = network.parse::<Ipv6Addr>() {
                if prefix_len > 128 {
                    return None;
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let start = u128::from(ipv6) & mask;
                let end = start | !mask;
                return Some(CidrInterval::V6(start, end));
            }

            return None;
        }

        match cidr.parse::<IpAddr>().ok()? {
            IpAddr::V4(ipv4) => {
                let value = u32::from(ipv4);
                Some(CidrInterval::V4(value, value))
            }
            IpAddr::V6(ipv6) => {
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
        self.cidr_blocklist.read().unwrap().contains(ip)
    }

    pub fn find_match(&self, remote_ip: IpAddr) -> Option<WebThreatMatch> {
        if self.is_blocked_ip(remote_ip) {
            Some(WebThreatMatch::ip(
                remote_ip.to_string(),
                format!("Blocked Malicious CIDR: {}", remote_ip),
            ))
        } else {
            None
        }
    }
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

    pub fn decision_key(&self) -> String {
        format!("website:ip:{}", self.target.trim().to_lowercase())
    }
}
