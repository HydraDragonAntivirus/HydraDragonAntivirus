use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use bincode_next::serde::{decode_from_slice, encode_to_vec};
use fastbloom::AtomicBloomFilter;

const WHITELIST_DB_NAME: &str = "whitelist.db";
const SQL_DB_NAME: &str = "RDS_2026.06.1_modern_delta.sql";
const WHITELIST_BLOOM_NAME: &str = "whitelist.bloom";
const BLACKLIST_BLOOM_NAME: &str = "blacklist.bloom";
const URLHAUS_BLOOM_NAME: &str = "urlhaus.bloom";
const PHISHING_BLOOM_NAME: &str = "phishing.bloom";

const DEFAULT_BLOOM_DIR: &str = r"C:\Program Files\HydraDragonAntivirus\hydradragon\bloom_filter";

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
    urlhaus: Arc<AtomicBloomFilter>,
    phishing: Arc<AtomicBloomFilter>,
    whitelist_path: PathBuf,
    sql_path: PathBuf,
    bloom_path: PathBuf,
    blacklist_path: PathBuf,
    urlhaus_path: PathBuf,
    phishing_path: PathBuf,
}

impl HashBloomFilter {
    pub fn new() -> Self {
        Self::with_base_dir(PathBuf::from(DEFAULT_BLOOM_DIR))
    }

    fn load_bloom_field(data: &[u8], path: &PathBuf, label: &str) -> Arc<AtomicBloomFilter> {
        match decode_from_slice::<AtomicBloomFilter, _>(data, bincode_next::config::standard()) {
            Ok((bf, _)) => {
                log::info!("Loaded {} bloom filter from {:?}", label, path);
                Arc::new(bf)
            }
            Err(e) => {
                eprintln!("[BloomFilter] Failed to deserialize {} bloom from {:?}: {}", label, path, e);
                log::error!("Failed to deserialize {} bloom: {}", label, e);
                Arc::new(AtomicBloomFilter::with_false_pos(1e-4).expected_items(1))
            }
        }
    }

    fn load_bloom_file(path: &PathBuf, label: &str) -> Option<Vec<u8>> {
        match fs::read(path) {
            Ok(d) => Some(d),
            Err(e) => {
                log::warn!("{} bloom not found at {:?}: {}; {} disabled", label, path, e, label);
                None
            }
        }
    }

    pub fn with_base_dir(dir: PathBuf) -> Self {
        Self::with_paths(
            dir.join(WHITELIST_DB_NAME),
            dir.join(SQL_DB_NAME),
            dir.join(WHITELIST_BLOOM_NAME),
            dir.join(BLACKLIST_BLOOM_NAME),
            dir.join(URLHAUS_BLOOM_NAME),
            dir.join(PHISHING_BLOOM_NAME),
        )
    }

    pub fn with_paths(
        whitelist_path: PathBuf,
        sql_path: PathBuf,
        bloom_path: PathBuf,
        blacklist_path: PathBuf,
        urlhaus_path: PathBuf,
        phishing_path: PathBuf,
    ) -> Self {
        let whitelist = Arc::new(AtomicBloomFilter::with_false_pos(1e-4).expected_items(300_000));
        let empty = || Arc::new(AtomicBloomFilter::with_false_pos(1e-4).expected_items(1));

        let mut filter = HashBloomFilter {
            whitelist,
            blacklist: empty(),
            urlhaus: empty(),
            phishing: empty(),
            whitelist_path,
            sql_path,
            bloom_path,
            blacklist_path,
            urlhaus_path,
            phishing_path,
        };

        if filter.bloom_path.exists() {
            filter.load();
        } else if filter.whitelist_path.exists() {
            log::info!(
                "Whitelist bloom not found at {:?}; building from {:?}",
                filter.bloom_path,
                filter.whitelist_path
            );
            filter.build_from_db();
            filter.save();
        } else {
            log::warn!(
                "Neither whitelist bloom ({:?}) nor source db ({:?}) found; whitelist disabled",
                filter.bloom_path,
                filter.whitelist_path
            );
        }

        if let Some(data) = Self::load_bloom_file(&filter.blacklist_path, "blacklist") {
            filter.blacklist = Self::load_bloom_field(&data, &filter.blacklist_path, "blacklist");
        }

        if filter.urlhaus_path.exists() {
            filter.load_urlhaus();
        } else {
            log::warn!("URLhaus bloom not found at {:?}; URLhaus disabled", filter.urlhaus_path);
        }

        if filter.phishing_path.exists() {
            filter.load_phishing();
        } else {
            log::warn!("Phishing bloom not found at {:?}; phishing disabled", filter.phishing_path);
        }

        filter
    }

    pub fn build_from_db(&mut self) {
        let mut count = 0usize;

        if self.whitelist_path.exists() {
            let content = match fs::read_to_string(&self.whitelist_path) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Failed to read whitelist db at {:?}: {}", self.whitelist_path, e);
                    return;
                }
            };
            for line in content.lines() {
                let hash = line.trim();
                if hash.is_empty() || hash.starts_with('#') { continue; }
                if !matches!(HashType::detect(hash), HashType::Md5) { continue; }
                self.whitelist.insert(hash);
                count += 1;
            }
            log::info!("Loaded {} MD5 hashes from whitelist db", count);
        }

        if self.sql_path.exists() {
            count += self.build_from_sql();
        }

        log::info!("Built whitelist bloom filter with {} total hashes", count);
    }

    fn build_from_sql(&mut self) -> usize {
        let content = match fs::read_to_string(&self.sql_path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to read SQL db at {:?}: {}", self.sql_path, e);
                return 0;
            }
        };
        let mut count = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("INSERT INTO METADATA") { continue; }
            let vs = match line.find("VALUES(") { Some(p) => p + 7, None => continue };
            let ve = match line.rfind(')') { Some(p) => p, None => continue };
            let parts: Vec<&str> = line[vs..ve].split(',').collect();
            if parts.len() < 23 { continue; }
            let md5 = Self::trim_quotes(parts[20]);
            if !md5.is_empty() && md5.len() == 32 && md5.chars().all(|c| c.is_ascii_hexdigit()) {
                self.whitelist.insert(md5);
                count += 1;
            }
        }
        log::info!("Loaded {} MD5 hashes from SQL db", count);
        count
    }

    fn trim_quotes(s: &str) -> &str {
        let s = s.trim();
        if s.len() >= 2 && s.as_bytes()[0] == b'\'' && s.as_bytes()[s.len() - 1] == b'\'' {
            &s[1..s.len() - 1]
        } else {
            s
        }
    }

    pub fn save(&self) {
        if let Some(parent) = self.bloom_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match encode_to_vec(self.whitelist.as_ref(), bincode_next::config::standard()) {
            Ok(data) => {
                if let Err(e) = fs::write(&self.bloom_path, &data[..]) {
                    log::error!("Failed to save whitelist bloom to {:?}: {}", self.bloom_path, e);
                }
            }
            Err(e) => log::error!("Failed to serialize whitelist bloom: {}", e),
        }
    }

    pub fn load(&mut self) {
        let data = match fs::read(&self.bloom_path) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to read whitelist bloom from {:?}: {}", self.bloom_path, e);
                return;
            }
        };
        match decode_from_slice::<AtomicBloomFilter, _>(&data, bincode_next::config::standard()) {
            Ok((bf, _)) => {
                self.whitelist = Arc::new(bf);
                log::info!("Loaded whitelist bloom filter from {:?}", self.bloom_path);
            }
            Err(e) => log::error!("Failed to deserialize whitelist bloom: {}", e),
        }
    }

    fn load_urlhaus(&mut self) {
        let data = match fs::read(&self.urlhaus_path) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to read URLhaus bloom from {:?}: {}", self.urlhaus_path, e);
                return;
            }
        };
        match decode_from_slice::<AtomicBloomFilter, _>(&data, bincode_next::config::standard()) {
            Ok((bf, _)) => {
                self.urlhaus = Arc::new(bf);
                log::info!("Loaded URLhaus bloom filter from {:?}", self.urlhaus_path);
            }
            Err(e) => log::error!("Failed to deserialize URLhaus bloom: {}", e),
        }
    }

    fn load_phishing(&mut self) {
        let data = match fs::read(&self.phishing_path) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to read phishing bloom from {:?}: {}", self.phishing_path, e);
                return;
            }
        };
        match decode_from_slice::<AtomicBloomFilter, _>(&data, bincode_next::config::standard()) {
            Ok((bf, _)) => {
                self.phishing = Arc::new(bf);
                log::info!("Loaded phishing bloom filter from {:?}", self.phishing_path);
            }
            Err(e) => log::error!("Failed to deserialize phishing bloom: {}", e),
        }
    }

    pub fn rebuild(&mut self) {
        self.whitelist = Arc::new(AtomicBloomFilter::with_false_pos(1e-4).expected_items(300_000));
        if self.whitelist_path.exists() {
            self.build_from_db();
            self.save();
        }
        if self.blacklist_path.exists() {
            if let Some(data) = Self::load_bloom_file(&self.blacklist_path, "blacklist") {
                self.blacklist = Self::load_bloom_field(&data, &self.blacklist_path, "blacklist");
            }
        }
        if self.urlhaus_path.exists() { self.load_urlhaus(); }
        if self.phishing_path.exists() { self.load_phishing(); }
    }

    pub fn is_urlhaus(&self, url: &str) -> bool {
        self.urlhaus.contains(url)
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
        if self.is_blacklisted(hash) { return false; }
        self.whitelist.contains(hash)
    }
}

impl Default for HashBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}
