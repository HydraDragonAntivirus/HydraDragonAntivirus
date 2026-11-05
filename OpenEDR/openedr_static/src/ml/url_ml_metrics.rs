//! URL-ML features for the PE v2, JavaScript and APK feature vectors.
//!
//! A file's embedded links never decide a verdict here. Every `http(s)` URL the
//! file carries is put through the same whitelist the engine uses for URLs
//! (`StaticEngine::check_whitelist_blacklist`: CIDR blacklist, CIDR whitelist,
//! Tranco 1M `url_whitelist.xf` unless the host is in `url_threat_rules.yaml`'s
//! unwhitelist set), and the URLs that remain are scored by `url_trees.bin`.
//! Those scores only become four extra model features ([`UrlMlMetrics`]); the
//! file's own model decides what they are worth.
//!
//! Like [`super::pe_string_ml::PeStringMlEngine`], the signatures are loaded
//! once per process ([`UrlMlFeatureEngine::global`]) from the folders next to
//! the running executable, so `StaticEngine` and the standalone
//! `*_feature_dump.exe` compute the same numbers.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::tree_model::TreeEnsembleModel;
use super::url_features::extract_url_features;
use crate::cidr::CidrEngine;
use crate::embedded_url::{self, EmbeddedUrl};
use crate::signers::BinaryFuse32Filter;
use crate::url_rules::UrlThreatEngine;

/// URLs scored by the URL model per file. The rest still count towards
/// `url_unwhitelisted_count_log`.
pub const MAX_SCORED_URLS: usize = 64;

/// Probability at or above which a scored URL counts in `url_ml_high_count_log`.
pub const HIGH_PROB: f32 = 0.85;

/// URLs collected per file before the whitelist runs: the same order of
/// magnitude as `embedded_url::MAX_URLS`, over all of a file's string sources.
const MAX_COLLECTED_URLS: usize = 1024;

/// XML namespace / schema hosts. They appear in every manifest, layout, SVG and
/// installer manifest as identifiers, never as links that are fetched.
const NOISE_HOSTS: [&str; 8] = [
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "schemas.microsoft.com",
    "schemas.xmlsoap.org",
    "ns.adobe.com",
    "xmlpull.org",
    "apache.org",
];

/// 4 URL ML features, appended to the PE v2 (`inner_*`, `shell_*`), JavaScript and
/// APK vectors:
/// 1. `url_unwhitelisted_count_log`: `ln(1 + URLs left after the whitelist)`
/// 2. `url_ml_max_prob`: highest `url_trees.bin` probability of the scored URLs
/// 3. `url_ml_mean_prob`: mean probability of the scored URLs
/// 4. `url_ml_high_count_log`: `ln(1 + scored URLs with prob >= 0.85 or CIDR-blacklisted)`
///
/// Every feature is 0.0 when no URL is scored.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UrlMlMetrics {
    pub url_unwhitelisted_count_log: f32,
    pub url_ml_max_prob: f32,
    pub url_ml_mean_prob: f32,
    pub url_ml_high_count_log: f32,
}

impl UrlMlMetrics {
    pub const LEN: usize = 4;
    pub const NAMES: [&'static str; Self::LEN] = [
        "url_unwhitelisted_count_log",
        "url_ml_max_prob",
        "url_ml_mean_prob",
        "url_ml_high_count_log",
    ];

    pub fn to_array(&self) -> [f32; Self::LEN] {
        [
            self.url_unwhitelisted_count_log,
            self.url_ml_max_prob,
            self.url_ml_mean_prob,
            self.url_ml_high_count_log,
        ]
    }
}

/// Collects URLs from several string sources of one file (raw bytes, flate
/// streams, decompiler strings, AST literals, DEX strings, ...), with the same
/// case-insensitive dedup `embedded_url` applies within one buffer.
#[derive(Default)]
pub struct UrlCollector {
    urls: Vec<EmbeddedUrl>,
    seen: std::collections::HashSet<String>,
}

impl UrlCollector {
    pub fn new() -> Self {
        Self::default()
    }

    fn full(&self) -> bool {
        self.urls.len() >= MAX_COLLECTED_URLS
    }

    /// Absorb already-harvested URLs.
    pub fn add_urls(&mut self, urls: Vec<EmbeddedUrl>) {
        for u in urls {
            if self.full() {
                return;
            }
            if self.seen.insert(u.url.to_ascii_lowercase()) {
                self.urls.push(u);
            }
        }
    }

    /// URLs of a byte buffer, ASCII and UTF-16LE (`embedded_url::extract_urls`).
    pub fn add_bytes(&mut self, data: &[u8]) {
        if self.full() {
            return;
        }
        self.add_urls(embedded_url::extract_urls(data));
    }

    /// URLs of a byte buffer plus those inside its Flate streams
    /// (`embedded_url::extract_urls_from_streams`), for raw file bytes.
    pub fn add_file_bytes(&mut self, data: &[u8]) {
        self.add_bytes(data);
        if self.full() {
            return;
        }
        self.add_urls(embedded_url::extract_urls_from_streams(data));
    }

    /// URLs of one extracted string. Strings without `://` are skipped before
    /// the byte scan, since most of a file's strings are not links.
    pub fn add_str(&mut self, s: &str) {
        if s.len() < embedded_url::MIN_URL_LEN || !s.contains("://") {
            return;
        }
        self.add_bytes(s.as_bytes());
    }

    pub fn urls(&self) -> &[EmbeddedUrl] {
        &self.urls
    }

    /// Whitelist and score the collected URLs.
    pub fn metrics(&self) -> UrlMlMetrics {
        UrlMlFeatureEngine::global().metrics(&self.urls)
    }
}

/// What the whitelist says about one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostVerdict {
    /// Excluded from scoring: no host, local address, schema host or whitelisted.
    Skip,
    /// On the CIDR blacklist: counts as probability 1.0.
    Blacklisted,
    /// Scored by the URL model.
    Score,
}

/// The URL model and the whitelist signatures, loaded once per process.
pub struct UrlMlFeatureEngine {
    model: Option<TreeEnsembleModel>,
    whitelist: Option<BinaryFuse32Filter>,
    cidr: CidrEngine,
    threat: UrlThreatEngine,
}

impl UrlMlFeatureEngine {
    fn candidate_dirs() -> Vec<PathBuf> {
        let mut bases = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(p) = exe.parent() {
                bases.push(p.to_path_buf());
                // `target/<profile>/deps` (tests) or `target/<profile>` (dumps).
                for up in [2usize, 3] {
                    let mut r = Some(p);
                    for _ in 0..up {
                        r = r.and_then(|x| x.parent());
                    }
                    if let Some(r) = r {
                        bases.push(r.to_path_buf());
                    }
                }
            }
        }
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        bases.push(crate_dir.to_path_buf());
        if let Some(repo) = crate_dir.parent().and_then(|p| p.parent()) {
            bases.push(repo.join("OpenMalwareScannerPortable"));
            bases.push(repo.join("hydradragon_ml_models"));
        }

        let mut dirs = Vec::new();
        for b in bases {
            for sub in ["", "models", "xorfilter_rules", "url_rules", "cidr_rules"] {
                let d = if sub.is_empty() { b.clone() } else { b.join(sub) };
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
        dirs
    }

    fn find(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
        dirs.iter().map(|d| d.join(name)).find(|p| p.is_file())
    }

    fn load() -> Self {
        let dirs = Self::candidate_dirs();

        let model_path = Self::find(&dirs, "url_trees.bin");
        let model = model_path.as_deref().and_then(TreeEnsembleModel::from_bin_file);

        let wl_path = Self::find(&dirs, crate::signers::URL_WHITELIST_XF);
        let (whitelist, wl_status) = match &wl_path {
            Some(p) => match std::fs::read(p).map_err(|e| e.to_string()).and_then(|b| BinaryFuse32Filter::load(&b)) {
                Ok(f) => {
                    let st = format!("loaded ({} keys) from {}", f.len(), p.display());
                    (Some(f), st)
                }
                Err(e) => (None, format!("{e}: {}", p.display())),
            },
            None => (None, "absent".to_string()),
        };

        // The CIDR tables live next to each other; take the first folder that has them.
        let cidr_dir = dirs
            .iter()
            .find(|d| d.join("cidr_blacklist_ipv4.bin").is_file() || d.join("cidr_whitelist_ipv4.bin").is_file())
            .cloned()
            .or_else(|| {
                let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
                src.join("cidr_blacklist_ipv4.bin").is_file().then_some(src)
            });
        let cidr = cidr_dir.as_deref().map(CidrEngine::load_from_dir).unwrap_or_default();

        let mut threat = UrlThreatEngine::new();
        let rules_status = match Self::find(&dirs, crate::url_rules::URL_RULES_FILE) {
            Some(p) => match threat.load_from_file(&p) {
                Ok(n) => format!(
                    "loaded ({n} rules, {} unwhitelisted) from {}",
                    threat.unwhitelisted_count(),
                    p.display()
                ),
                Err(e) => e,
            },
            None => "absent".to_string(),
        };

        crate::diagnostics::log(
            "init-step",
            &format!(
                "url_ml_features: url_trees={}; url_whitelist={wl_status}; cidr={}; url_threat_rules={rules_status}",
                match (&model, &model_path) {
                    (Some(_), Some(p)) => format!("loaded from {}", p.display()),
                    (None, Some(p)) => format!("parse-failed {}", p.display()),
                    _ => "absent".to_string(),
                },
                cidr_dir.as_deref().map(|d| d.display().to_string()).unwrap_or_else(|| "absent".to_string()),
            ),
        );
        if model.is_none() || whitelist.is_none() {
            crate::diagnostics::log(
                "capability-disabled",
                "URL ML features: url_trees.bin / url_whitelist.xf missing or unparseable; \
                 url_ml_* probabilities read as 0 and no host is whitelisted by Tranco",
            );
        }

        Self { model, whitelist, cidr, threat }
    }

    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<UrlMlFeatureEngine> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            crate::memtrack::measure("url_ml_features", crate::memtrack::Kind::Load, 0, Self::load)
        })
    }

    pub fn model_loaded(&self) -> bool {
        self.model.is_some()
    }

    pub fn whitelist_loaded(&self) -> bool {
        self.whitelist.is_some()
    }

    /// Same order as `StaticEngine::check_whitelist_blacklist`: CIDR blacklist,
    /// CIDR whitelist, then the Tranco `.xf` on the host and its parent domains
    /// (bare TLD excluded) unless the host is unwhitelisted by the URL rules.
    fn verdict(&self, host: &str) -> HostVerdict {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || is_local_host(&host) || is_noise_host(&host) {
            return HostVerdict::Skip;
        }
        if self.cidr.is_blacklisted(&host) {
            return HostVerdict::Blacklisted;
        }
        if self.cidr.is_whitelisted(&host) {
            return HostVerdict::Skip;
        }
        if let Some(filter) = self.whitelist.as_ref() {
            if !self.threat.is_unwhitelisted(&host) {
                if filter.contains(&host) {
                    return HostVerdict::Skip;
                }
                let parts: Vec<&str> = host.split('.').collect();
                for i in 1..parts.len().saturating_sub(1) {
                    if filter.contains(&parts[i..].join(".")) {
                        return HostVerdict::Skip;
                    }
                }
            }
        }
        HostVerdict::Score
    }

    fn probability(&self, url: &str) -> f32 {
        match &self.model {
            Some(m) => m.predict_probability(&extract_url_features(url).to_array()),
            None => 0.0,
        }
    }

    /// Whitelist `urls` and score at most [`MAX_SCORED_URLS`] of those left.
    pub fn metrics(&self, urls: &[EmbeddedUrl]) -> UrlMlMetrics {
        let mut remaining = 0usize;
        let mut scored = 0usize;
        let mut sum = 0.0f32;
        let mut max = 0.0f32;
        let mut high = 0usize;
        for u in urls {
            let v = self.verdict(&u.host);
            if v == HostVerdict::Skip {
                continue;
            }
            remaining += 1;
            if scored >= MAX_SCORED_URLS {
                continue;
            }
            let p = if v == HostVerdict::Blacklisted { 1.0 } else { self.probability(&u.url) };
            scored += 1;
            sum += p;
            max = max.max(p);
            if v == HostVerdict::Blacklisted || p >= HIGH_PROB {
                high += 1;
            }
        }
        if scored == 0 {
            return UrlMlMetrics::default();
        }
        UrlMlMetrics {
            url_unwhitelisted_count_log: (remaining as f32).ln_1p(),
            url_ml_max_prob: max,
            url_ml_mean_prob: sum / scored as f32,
            url_ml_high_count_log: (high as f32).ln_1p(),
        }
    }
}

/// Loopback, RFC 1918 / unique-local, link-local and unspecified addresses.
fn is_local_host(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => {
            let seg0 = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link local
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_private() || v4.is_link_local())
        }
        Err(_) => host == "localhost" || host.ends_with(".localhost"),
    }
}

/// A schema / namespace host or one of its subdomains.
fn is_noise_host(host: &str) -> bool {
    NOISE_HOSTS.iter().any(|n| {
        host == *n || (host.len() > n.len() && host.ends_with(n) && host.as_bytes()[host.len() - n.len() - 1] == b'.')
    })
}

/// URL ML features of a byte buffer (ASCII, UTF-16LE and Flate streams).
pub fn url_ml_metrics_of_bytes(data: &[u8]) -> UrlMlMetrics {
    let mut c = UrlCollector::new();
    c.add_file_bytes(data);
    c.metrics()
}

/// URL ML features of a list of extracted strings.
pub fn url_ml_metrics_of_strings<'a, I: IntoIterator<Item = &'a str>>(strings: I) -> UrlMlMetrics {
    let mut c = UrlCollector::new();
    for s in strings {
        c.add_str(s);
    }
    c.metrics()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_load() {
        let e = UrlMlFeatureEngine::global();
        assert!(e.model_loaded(), "url_trees.bin must load");
        assert!(e.whitelist_loaded(), "url_whitelist.xf must load as BinaryFuse32");
    }

    #[test]
    fn whitelisted_and_schema_hosts_are_not_scored() {
        let m = url_ml_metrics_of_bytes(
            b"https://www.microsoft.com/en-us/download \
              http://schemas.android.com/apk/res/android \
              http://www.w3.org/2000/svg https://w3.org/TR/",
        );
        assert_eq!(m.url_unwhitelisted_count_log, 0.0);
        assert_eq!(m.url_ml_max_prob, 0.0);
        assert_eq!(m, UrlMlMetrics::default());
    }

    #[test]
    fn local_hosts_are_not_scored() {
        let m = url_ml_metrics_of_bytes(
            b"http://127.0.0.1:8080/a http://192.168.1.10/cfg http://169.254.1.1/x http://[::1]/y http://10.0.0.5/z",
        );
        assert_eq!(m, UrlMlMetrics::default());
    }

    #[test]
    fn phishing_url_is_scored_high() {
        let m = url_ml_metrics_of_bytes(b"http://login-verify-wallet-8f9a2b.xyz/wp-content/cmd.php");
        assert!(m.url_unwhitelisted_count_log > 0.0, "{m:?}");
        assert!(m.url_ml_max_prob > 0.5, "{m:?}");
    }

    #[test]
    fn raw_githubusercontent_is_not_whitelisted_through_github() {
        let m = url_ml_metrics_of_bytes(b"https://raw.githubusercontent.com/someone/repo/main/stage2.ps1");
        assert!(m.url_unwhitelisted_count_log > 0.0, "{m:?}");
        assert!(UrlMlFeatureEngine::global().threat.is_unwhitelisted("raw.githubusercontent.com"));
    }

    #[test]
    fn strings_and_bytes_are_deduplicated_case_insensitively() {
        let mut c = UrlCollector::new();
        c.add_str("fetch('HTTP://Login-Verify-Wallet-8f9a2b.xyz/a')");
        c.add_bytes(b"http://login-verify-wallet-8f9a2b.xyz/A");
        c.add_str("no link here");
        assert_eq!(c.urls().len(), 1);
    }

    #[test]
    fn noise_host_match_is_label_aligned() {
        assert!(is_noise_host("apache.org"));
        assert!(is_noise_host("www.apache.org"));
        assert!(!is_noise_host("evilapache.org"));
    }
}
