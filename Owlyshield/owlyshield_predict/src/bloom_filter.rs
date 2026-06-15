use bincode_next::serde::{decode_from_slice, encode_to_vec};
use fastbloom::AtomicBloomFilter;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use crate::globals::BLOOM_FILTER_PATH;

const WHITELIST_DB_NAME: &str = "whitelist.db";
const SQL_DB_NAME: &str = "RDS_2026.06.1_modern_delta.sql";
const WHITELIST_BLOOM_NAME: &str = "whitelist.bloom";
const BLACKLIST_BLOOM_NAME: &str = "blacklist.bloom";
const EXPECTED_ITEMS: usize = 300_000;

/// Resolve the bloom-filter install directory from the
/// `HKLM\SOFTWARE\Owlyshield\BLOOM_FILTER_PATH` registry value (set by the
/// installer and loaded into `globals::BLOOM_FILTER_PATH` at startup).
fn bloom_dir() -> PathBuf {
    BLOOM_FILTER_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| {
            log::warn!(
                "BLOOM_FILTER_PATH not initialized (globals::init_globals not yet called); falling back to relative './bloom_filter'"
            );
            PathBuf::from("bloom_filter")
        })
}

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
    whitelist_path: PathBuf,
    sql_path: PathBuf,
    bloom_path: PathBuf,
    blacklist_path: PathBuf,
}

impl HashBloomFilter {
    pub fn new() -> Self {
        // All four files live next to each other in the bloom_filter dir
        // (configured via HKLM\SOFTWARE\Owlyshield\BLOOM_FILTER_PATH).
        let dir = bloom_dir();
        Self::with_paths(
            dir.join(WHITELIST_DB_NAME),
            dir.join(SQL_DB_NAME),
            dir.join(WHITELIST_BLOOM_NAME),
            dir.join(BLACKLIST_BLOOM_NAME),
        )
    }

    pub fn with_paths(
        whitelist_path: PathBuf,
        sql_path: PathBuf,
        bloom_path: PathBuf,
        blacklist_path: PathBuf,
    ) -> Self {
        let whitelist = Arc::new(
            AtomicBloomFilter::with_false_pos(1e-4).expected_items(EXPECTED_ITEMS),
        );
        let blacklist = Arc::new(
            AtomicBloomFilter::with_false_pos(1e-4).expected_items(EXPECTED_ITEMS),
        );

        let mut filter = HashBloomFilter {
            whitelist,
            blacklist,
            whitelist_path,
            sql_path,
            bloom_path,
            blacklist_path,
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

        if filter.blacklist_path.exists() {
            filter.load_blacklist();
        } else {
            log::warn!(
                "Blacklist bloom not found at {:?}; blacklist disabled",
                filter.blacklist_path
            );
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
                if hash.is_empty() || hash.starts_with('#') {
                    continue;
                }
                if !matches!(HashType::detect(hash), HashType::Md5) {
                    continue;
                }
                self.whitelist.insert(hash);
                count += 1;
            }
            log::info!("Loaded {} MD5 hashes from whitelist db", count);
        }

        if self.sql_path.exists() {
            let sql_count = self.build_from_sql();
            count += sql_count;
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
            if !line.starts_with("INSERT INTO METADATA") {
                continue;
            }
            let values_start = match line.find("VALUES(") {
                Some(pos) => pos + 7,
                None => continue,
            };
            let values_end = match line.rfind(')') {
                Some(pos) => pos,
                None => continue,
            };
            let values = &line[values_start..values_end];
            let parts: Vec<&str> = values.split(',').collect();
            if parts.len() < 23 {
                continue;
            }
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

    pub fn build_blacklist_from_file(&mut self, path: &str) {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to read blacklist file {}: {}", path, e);
                return;
            }
        };

        let mut count = 0usize;
        for line in content.lines() {
            let hash = line.trim();
            if hash.is_empty() || hash.starts_with('#') {
                continue;
            }
            if HashType::detect(hash) == HashType::Unknown {
                continue;
            }
            self.blacklist.insert(hash);
            count += 1;
        }

        log::info!("Built blacklist bloom filter with {} hashes (all types)", count);
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
            Err(e) => {
                log::error!("Failed to serialize whitelist bloom: {}", e);
            }
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
            Err(e) => {
                log::error!("Failed to deserialize whitelist bloom: {}", e);
            }
        }
    }

    fn load_blacklist(&mut self) {
        let data = match fs::read(&self.blacklist_path) {
            Ok(d) => d,
            Err(e) => {
                log::error!(
                    "Failed to read blacklist bloom from {:?}: {}",
                    self.blacklist_path,
                    e
                );
                return;
            }
        };
        match decode_from_slice::<AtomicBloomFilter, _>(&data, bincode_next::config::standard()) {
            Ok((bf, _)) => {
                self.blacklist = Arc::new(bf);
                log::info!("Loaded blacklist bloom filter from {:?}", self.blacklist_path);
            }
            Err(e) => {
                log::error!("Failed to deserialize blacklist bloom: {}", e);
            }
        }
    }

    fn save_blacklist(&self) {
        if let Some(parent) = self.blacklist_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match encode_to_vec(self.blacklist.as_ref(), bincode_next::config::standard()) {
            Ok(data) => {
                if let Err(e) = fs::write(&self.blacklist_path, &data[..]) {
                    log::error!(
                        "Failed to save blacklist bloom to {:?}: {}",
                        self.blacklist_path,
                        e
                    );
                }
            }
            Err(e) => {
                log::error!("Failed to serialize blacklist bloom: {}", e);
            }
        }
    }

    pub fn is_whitelisted(&self, hash: &str) -> bool {
        self.whitelist.contains(hash)
    }

    pub fn is_blacklisted(&self, hash: &str) -> bool {
        self.blacklist.contains(hash)
    }

    /// Returns true if hash is allowed (whitelisted AND NOT blacklisted as false positive)
    pub fn is_hash_allowed(&self, hash: &str) -> bool {
        if self.blacklist.contains(hash) {
            return false;
        }
        self.whitelist.contains(hash)
    }

    pub fn add_to_blacklist(&self, hash: &str) {
        self.blacklist.insert(hash);
        self.save_blacklist();
    }

    pub fn clear_and_rebuild_blacklist(&mut self, hashes: &[String]) {
        self.blacklist = Arc::new(
            AtomicBloomFilter::with_false_pos(1e-4).expected_items(EXPECTED_ITEMS),
        );
        for h in hashes {
            self.blacklist.insert(h.as_str());
        }
        log::info!("Rebuilt blacklist bloom with {} hashes", hashes.len());
        self.save_blacklist();
    }

    pub fn whitelist_len(&self) -> usize {
        // AtomicBloomFilter does not expose count; approximate via expected items
        EXPECTED_ITEMS
    }

    pub fn blacklist_len(&self) -> usize {
        EXPECTED_ITEMS
    }

    pub fn rebuild(&mut self) {
        self.whitelist = Arc::new(
            AtomicBloomFilter::with_false_pos(1e-4).expected_items(EXPECTED_ITEMS),
        );
        if self.whitelist_path.exists() {
            self.build_from_db();
            self.save();
        }
    }
}

