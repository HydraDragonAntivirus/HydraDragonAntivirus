use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use bincode_next::serde::decode_from_slice;
use fastbloom::AtomicBloomFilter;

const WHITELIST_BLOOM_NAME: &str = "whitelist.bloom";
const BLACKLIST_BLOOM_NAME: &str = "blacklist.bloom";
// Merged URL feed (URLhaus + malware-URL list); built by bloom_builder as malwareurl.bloom.
const MALWAREURL_BLOOM_NAME: &str = "malwareurl.bloom";
const PHISHING_BLOOM_NAME: &str = "phishing.bloom";

const DEFAULT_BLOOM_DIR: &str = "bloom_filter";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Ssdeep,
    Tlsh,
    Unknown,
}

impl HashType {
    pub fn detect(hash: &str) -> Self {
        let trimmed = hash.trim();
        if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            HashType::Md5
        } else if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            HashType::Sha1
        } else if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            HashType::Sha256
        } else if trimmed.contains(':') && trimmed.chars().any(|c| c.is_ascii_digit()) {
            HashType::Ssdeep
        } else if trimmed.len() >= 50 && trimmed.len() <= 200 && !trimmed.contains(':') {
            HashType::Tlsh
        } else {
            HashType::Unknown
        }
    }
}

pub struct HashBloomFilter {
    whitelist: Arc<AtomicBloomFilter>,
    blacklist: Arc<AtomicBloomFilter>,
    malware_url: Arc<AtomicBloomFilter>,
    phishing: Arc<AtomicBloomFilter>,
}

fn empty_bloom() -> Arc<AtomicBloomFilter> {
    Arc::new(AtomicBloomFilter::with_false_pos(1e-4).expected_items(1))
}

fn load_bloom_field(data: &[u8], path: &PathBuf, label: &str) -> Arc<AtomicBloomFilter> {
    match decode_from_slice::<AtomicBloomFilter, _>(data, bincode_next::config::standard()) {
        Ok((bf, _)) => {
            log::info!("Loaded {} bloom filter from {:?}", label, path);
            Arc::new(bf)
        }
        Err(e) => {
            eprintln!(
                "[BloomFilter] Failed to deserialize {} bloom from {:?}: {}",
                label, path, e
            );
            log::error!("Failed to deserialize {} bloom: {}", label, e);
            empty_bloom()
        }
    }
}

fn load_bloom_file(path: &PathBuf, label: &str) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(d) => Some(d),
        Err(e) => {
            log::warn!(
                "{} bloom not found at {:?}: {}; {} disabled",
                label,
                path,
                e,
                label
            );
            None
        }
    }
}

fn load_whitelist_from(path: &PathBuf) -> Arc<AtomicBloomFilter> {
    match fs::read(path) {
        Ok(data) => load_bloom_field(&data, path, "whitelist"),
        Err(e) => {
            log::warn!(
                "Whitelist bloom not found at {:?}: {}; whitelist disabled",
                path,
                e
            );
            empty_bloom()
        }
    }
}

impl HashBloomFilter {
    pub fn new() -> Self {
        Self::with_base_dir(PathBuf::from(DEFAULT_BLOOM_DIR))
    }

    pub fn with_base_dir(dir: PathBuf) -> Self {
        Self::with_paths(
            dir.join(WHITELIST_BLOOM_NAME),
            dir.join(BLACKLIST_BLOOM_NAME),
            dir.join(MALWAREURL_BLOOM_NAME),
            dir.join(PHISHING_BLOOM_NAME),
        )
    }

    pub fn with_paths(
        bloom_path: PathBuf,
        blacklist_path: PathBuf,
        malware_url_path: PathBuf,
        phishing_path: PathBuf,
    ) -> Self {
        let whitelist = load_whitelist_from(&bloom_path);
        let blacklist = load_bloom_file(&blacklist_path, "blacklist")
            .map(|d| load_bloom_field(&d, &blacklist_path, "blacklist"))
            .unwrap_or_else(empty_bloom);
        let malware_url = load_bloom_file(&malware_url_path, "malware-URL")
            .map(|d| load_bloom_field(&d, &malware_url_path, "malware-URL"))
            .unwrap_or_else(empty_bloom);
        let phishing = load_bloom_file(&phishing_path, "phishing")
            .map(|d| load_bloom_field(&d, &phishing_path, "phishing"))
            .unwrap_or_else(empty_bloom);

        HashBloomFilter {
            whitelist,
            blacklist,
            malware_url,
            phishing,
        }
    }

    pub fn is_malware_url(&self, url: &str) -> bool {
        self.malware_url.contains(url)
    }

    pub fn is_phishing(&self, url: &str) -> bool {
        self.phishing.contains(url)
    }

    pub fn is_whitelisted(&self, hash: &str) -> bool {
        self.whitelist.contains(hash)
    }

    pub fn is_blacklisted(&self, hash: &str) -> bool {
        self.blacklist.contains(hash)
    }

    pub fn is_md5_blacklisted(&self, hash: &str) -> bool {
        self.blacklist.contains(hash)
    }

    pub fn is_sha256_blacklisted(&self, hash: &str) -> bool {
        self.blacklist.contains(hash)
    }

    pub fn is_hash_allowed(&self, hash: &str) -> bool {
        if self.is_blacklisted(hash) {
            return false;
        }
        self.whitelist.contains(hash)
    }
}

impl Default for HashBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}
