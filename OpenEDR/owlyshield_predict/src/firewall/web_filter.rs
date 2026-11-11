use moka::sync::Cache;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone)]
pub struct WebFilter {
    clean_flow_cache: Cache<(IpAddr, IpAddr, u16), ()>,
    ssl_blacklist: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Resolved cloud verdicts (target -> is_malicious). Filled ONLY by the
    /// background `fw_cloud_intel` thread, read lock-free by packet workers.
    cloud_verdicts: Cache<String, bool>,
    /// Targets already queued for a cloud lookup (dedupe; short TTL so a
    /// lost lookup is retried).
    cloud_inflight: Cache<String, ()>,
    cloud_tx: crossbeam_channel::Sender<String>,
}

impl Default for WebFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl WebFilter {
    pub fn new() -> Self {
        let cloud_verdicts: Cache<String, bool> = Cache::builder()
            .max_capacity(65536)
            .time_to_live(Duration::from_secs(300))
            .build();
        let cloud_inflight: Cache<String, ()> = Cache::builder()
            .max_capacity(4096)
            .time_to_live(Duration::from_secs(30))
            .build();
        let (cloud_tx, cloud_rx) = crossbeam_channel::bounded::<String>(1024);

        // The cloud query is a synchronous WebSocket round-trip (seconds, and
        // serialized on one global session mutex). It must NEVER run on a
        // WinDivert packet worker: the query's own packets need a free worker
        // to be reinjected, so workers blocked on it deadlock the whole
        // network. This thread is the only caller on the packet path's behalf.
        {
            let verdicts = cloud_verdicts.clone();
            let inflight = cloud_inflight.clone();
            let _ = std::thread::Builder::new()
                .name("fw_cloud_intel".to_string())
                .spawn(move || {
                    for target in cloud_rx {
                        let hit = std::panic::catch_unwind(|| {
                            query_cloud_threat_target(&target).is_some()
                        })
                        .unwrap_or(false);
                        verdicts.insert(target.clone(), hit);
                        inflight.invalidate(&target);
                    }
                });
        }

        Self {
            cloud_verdicts,
            cloud_inflight,
            cloud_tx,
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
        // Also check cloud threat intel (non-blocking: resolved in background)
        if self.cloud_verdict_nonblocking(&clean) == Some(true) {
            self.ssl_blacklist.write().unwrap().insert(clean);
            return true;
        }
        false
    }

    /// Cloud verdict for `target` without ever blocking the caller.
    /// `Some(malicious)` once resolved; `None` while the lookup is queued or
    /// in flight (callers fail open until the verdict lands).
    fn cloud_verdict_nonblocking(&self, target: &str) -> Option<bool> {
        if let Some(v) = self.cloud_verdicts.get(target) {
            return Some(v);
        }
        if !self.cloud_inflight.contains_key(target)
            && self.cloud_tx.try_send(target.to_string()).is_ok()
        {
            self.cloud_inflight.insert(target.to_string(), ());
        }
        None
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
        let (hit, resolved) = self.find_match_state(remote_ip);
        // Only cache the flow as clean once the cloud verdict is actually
        // known; a still-pending lookup must be re-checked on later packets
        // so a malicious verdict takes effect as soon as it lands.
        if hit.is_none() && resolved {
            self.clean_flow_cache.insert(flow_key, ());
        }
        hit
    }

    /// Returns `(match, resolved)`. Never blocks: the cloud part is answered
    /// from the verdict cache, and `resolved == false` means the lookup is
    /// still pending in the background.
    fn find_match_state(&self, remote_ip: IpAddr) -> (Option<WebThreatMatch>, bool) {
        if remote_ip.is_unspecified() || remote_ip.is_loopback() {
            return (None, true);
        }

        // viruskov.com cloud threat intel (background-resolved)
        let ip_str = remote_ip.to_string();
        match self.cloud_verdict_nonblocking(&ip_str) {
            Some(true) => {
                let reason = format!("VirusKov Cloud Threat Intelligence: {}", ip_str);
                (Some(WebThreatMatch::ip(ip_str, reason)), true)
            }
            Some(false) => (None, true),
            None => (None, false),
        }
    }

    /// No local CIDR blocklist is loaded: IP reputation lives in the cloud
    /// only (the in-memory CIDR index just burned RAM). Locally we keep the
    /// firewall rule set (SDK rules) and the small SSL certificate blacklist.
    pub fn load_default() -> Self {
        let filter = Self::new();
        filter.load_ssl_blacklist(&Self::get_threat_intel_path());
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

    /// Loads `ssl_blacklist.txt` (one SHA-1 per line) from the threat-intel folder.
    fn load_ssl_blacklist(&self, base_path: &std::path::Path) {
        let Ok(file) = File::open(base_path.join("ssl_blacklist.txt")) else {
            return;
        };
        let mut ssl_set = self.ssl_blacklist.write().unwrap();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let trimmed = line.trim().replace(':', "").to_ascii_lowercase();
            if trimmed.len() == 40 && !trimmed.starts_with('#') {
                ssl_set.insert(trimmed);
            }
        }
    }

    pub fn is_blocked_ip(&self, ip: IpAddr) -> bool {
        // Never block unspecified (0.0.0.0, ::) or loopback addresses via CIDR blacklist
        if ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        query_cloud_threat_target(&ip.to_string()).is_some()
    }

    pub fn find_match(&self, remote_ip: IpAddr) -> Option<WebThreatMatch> {
        self.find_match_state(remote_ip).0
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
