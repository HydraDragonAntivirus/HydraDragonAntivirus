//! URL prefilters and shared static-engine scoring for Owlyshield URL scans.

use std::sync::OnceLock;

/// Resolve auxiliary URL data across all runtime contexts:
/// 1. Registry HKLM\SOFTWARE\Owlyshield\SDK (DATABASE_PATH/MODELS_PATH)
/// 2. Loaded module directory (owlyshield_ransom.dll or companion DLL)
/// 3. current_exe directory
/// 4. Default installation directories (Program Files)
/// 5. CWD-relative models/ (dev / tests)
/// The model itself is owned and loaded by openedr_static.
pub(crate) fn model_path(file: &str) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        for flags in [KEY_READ | KEY_WOW64_64KEY, KEY_READ] {
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SOFTWARE\Owlyshield\SDK", flags) {
                if let Ok(p) = key.get_value::<String, _>("MODELS_PATH") {
                    let cand = std::path::PathBuf::from(&p).join(file);
                    if cand.is_file() {
                        return Some(cand);
                    }
                }
                if let Ok(p) = key.get_value::<String, _>("DATABASE_PATH") {
                    let pb = std::path::PathBuf::from(&p);
                    if let Some(parent) = pb.parent() {
                        let cand = parent.join("models").join(file);
                        if cand.is_file() {
                            return Some(cand);
                        }
                    }
                }
            }
        }
    }

    if let Some(dll_dir) = crate::utils::current_module_dir() {
        let cand = dll_dir.join("models").join(file);
        if cand.is_file() {
            return Some(cand);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("models").join(file);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }

    for install_base in [
        r"C:\Program Files\HydraDragonAntivirus\OpenEDR\models",
        r"C:\Program Files (x86)\HydraDragonAntivirus\OpenEDR\models",
    ] {
        let cand = std::path::PathBuf::from(install_base).join(file);
        if cand.is_file() {
            return Some(cand);
        }
    }

    let cand = std::path::Path::new("models").join(file);
    if cand.is_file() {
        return Some(cand);
    }
    None
}

/// BinaryFuse16 XOR Filter for URL Whitelist (url_whitelist.xf)
pub struct BinaryFuse16Filter {
    seed: u64,
    seg_len: u32,
    seg_len_mask: u32,
    seg_count_len: u32,
    count: usize,
    fingerprints: Vec<u16>,
}

impl BinaryFuse16Filter {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || bytes[0] != 16 || bytes[1] != 2 {
            return None;
        }
        let seed = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let seg_len = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let seg_len_mask = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let seg_count_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let count = usize::try_from(u64::from_le_bytes(bytes[24..32].try_into().ok()?)).ok()?;
        if 32 + count.checked_mul(2)? > bytes.len() {
            return None;
        }
        let mut fingerprints = Vec::with_capacity(count);
        for i in 0..count {
            let off = 32 + i * 2;
            fingerprints.push(u16::from_le_bytes([bytes[off], bytes[off + 1]]));
        }
        Some(Self {
            seed,
            seg_len,
            seg_len_mask,
            seg_count_len,
            count,
            fingerprints,
        })
    }

    pub fn contains(&self, s: &str) -> bool {
        let k = Self::key(s);
        let hash = Self::mix64(k.wrapping_add(self.seed));
        let f = hash as u16;
        let (h0, h1, h2) = Self::hash_of_hash(hash, self.seg_len, self.seg_len_mask, self.seg_count_len);
        let c = self.count;
        if h0 as usize >= c || h1 as usize >= c || h2 as usize >= c {
            return false;
        }
        let fp = self.fingerprints[h0 as usize] ^ self.fingerprints[h1 as usize] ^ self.fingerprints[h2 as usize];
        f ^ fp == 0
    }

    #[inline(always)]
    fn key(s: &str) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = OFFSET;
        for b in s.bytes() {
            h ^= b.to_ascii_lowercase() as u64;
            h = h.wrapping_mul(PRIME);
        }
        h
    }

    #[inline(always)]
    fn mix64(k: u64) -> u64 {
        const MIX_C1: u64 = 0xff51_afd7_ed55_8ccd;
        let r = (k as u128).wrapping_mul(MIX_C1 as u128);
        (r ^ (r >> 64)) as u64
    }

    #[inline(always)]
    fn hash_of_hash(hash: u64, seg_len: u32, seg_len_mask: u32, seg_count_len: u32) -> (u32, u32, u32) {
        let hi = ((hash as u128 * seg_count_len as u128) >> 64) as u64;
        let h0 = hi as u32;
        let mut h1 = h0 + seg_len;
        let mut h2 = h1 + seg_len;
        h1 ^= ((hash >> 18) as u32) & seg_len_mask;
        h2 ^= (hash as u32) & seg_len_mask;
        (h0, h1, h2)
    }
}

static URL_WHITELIST_FILTER: OnceLock<Option<BinaryFuse16Filter>> = OnceLock::new();

pub fn get_url_whitelist() -> Option<&'static BinaryFuse16Filter> {
    URL_WHITELIST_FILTER.get_or_init(|| {
        let cand_paths = [
            model_path("xorfilter_rules/url_whitelist.xf"),
            Some(std::path::PathBuf::from("xorfilter_rules/url_whitelist.xf")),
            Some(std::path::PathBuf::from("models/url_whitelist.xf")),
            Some(std::path::PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\xorfilter_rules\url_whitelist.xf")),
        ];

        for opt_p in cand_paths {
            if let Some(p) = opt_p {
                if p.is_file() {
                    if let Ok(bytes) = std::fs::read(&p) {
                        if let Some(filter) = BinaryFuse16Filter::from_bytes(&bytes) {
                            crate::Logging::info(&format!("[URL Whitelist] Loaded BinaryFuse16 filter from {}", p.display()));
                            return Some(filter);
                        }
                    }
                }
            }
        }
        None
    }).as_ref()
}

pub fn is_url_whitelisted(raw_url: &str) -> bool {
    let filter = match get_url_whitelist() {
        Some(f) => f,
        None => return false,
    };

    let url_to_parse = if !raw_url.starts_with("http://") && !raw_url.starts_with("https://") {
        format!("http://{}", raw_url)
    } else {
        raw_url.to_string()
    };

    let host = match url::Url::parse(&url_to_parse).ok().and_then(|u| u.host_str().map(|h| h.to_lowercase())) {
        Some(h) => h,
        None => raw_url.to_lowercase(),
    };

    if filter.contains(&host) {
        return true;
    }

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 2 {
        for i in 1..parts.len() - 1 {
            let parent = parts[i..].join(".");
            if filter.contains(&parent) {
                return true;
            }
        }
    }
    false
}

static URL_THREAT_ENGINE: OnceLock<crate::url_rules::UrlThreatEngine> = OnceLock::new();
static CIDR_ENGINE: OnceLock<crate::cidr::CidrEngine> = OnceLock::new();

pub fn get_url_threat_engine() -> &'static crate::url_rules::UrlThreatEngine {
    URL_THREAT_ENGINE.get_or_init(crate::url_rules::UrlThreatEngine::new)
}

pub fn get_cidr_engine() -> &'static crate::cidr::CidrEngine {
    CIDR_ENGINE.get_or_init(crate::cidr::CidrEngine::new)
}

pub fn extract_host(raw_url: &str) -> Option<&str> {
    let mut s = raw_url.trim();
    if let Some(idx) = s.find("://") {
        s = &s[idx + 3..];
    }
    let host_and_port = s.split(['/', '?', '#']).next()?.trim();
    if host_and_port.is_empty() {
        return None;
    }
    if host_and_port.starts_with('[') {
        if let Some(end_bracket) = host_and_port.find(']') {
            return Some(&host_and_port[..=end_bracket]);
        }
    }
    let host = host_and_port.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

pub const URL_ML_DETECTION_THRESHOLD: f32 = 0.90;

pub fn scan_url(raw_url: &str) -> Option<f32> {
    let engine = get_url_threat_engine();
    let cidr = get_cidr_engine();
    let host = extract_host(raw_url).unwrap_or("");

    // 0. CIDR IP Blacklist check (fast O(log N) binary search)
    if cidr.is_blacklisted(host) {
        return Some(1.0);
    }

    // 1. Check YAML Exception Engine: unwhitelist_subdomains & override_whitelist rules
    let overrides_whitelist = engine.should_override_whitelist(raw_url, host);

    // 2. Check Whitelists (CIDR Whitelist & Xorfilter Whitelist) only if not an exception in YAML rules
    if !overrides_whitelist {
        if cidr.is_whitelisted(host) || is_url_whitelisted(raw_url) {
            return None; // Whitelisted! Passed immediately with 0 latency & 0 FP
        }
    }

    // 3. Unknown addresses or rule exceptions: evaluate with ML
    let prob = crate::ffi::scan_url_with_static(raw_url)?;

    // Only flag as malicious if ML probability is >= 0.90
    if prob >= URL_ML_DETECTION_THRESHOLD {
        Some(prob)
    } else {
        None
    }
}

/// True when openedr_static loaded its URL tree model.
/// Lets FFI callers distinguish "model missing" from "nothing malicious".
pub fn model_loaded() -> bool {
    crate::ffi::static_url_model_loaded()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_without_scheme() {
        assert_eq!(extract_host("example.com/path"), Some("example.com"));
    }
}
