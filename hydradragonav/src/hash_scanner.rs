use std::fs;
use std::io::Read;
use std::path::Path;

use md5::{Digest, Md5};
use sha2::Sha256;

use crate::bloom_filter::{HashBloomFilter, HashType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScanResult {
    Whitelisted,
    Blacklisted,
    Unknown,
}

pub struct HashScanner {
    bloom: HashBloomFilter,
}

impl HashScanner {
    pub fn new() -> Self {
        HashScanner {
            bloom: HashBloomFilter::new(),
        }
    }

    pub fn with_bloom(bloom: HashBloomFilter) -> Self {
        HashScanner { bloom }
    }

    pub fn bloom(&self) -> &HashBloomFilter {
        &self.bloom
    }

    pub fn scan_hash(&self, hash: &str) -> HashScanResult {
        if HashType::detect(hash) == HashType::Unknown {
            return HashScanResult::Unknown;
        }

        if self.bloom.is_blacklisted(hash) {
            return HashScanResult::Blacklisted;
        }

        if HashType::detect(hash) == HashType::Md5 && self.bloom.is_whitelisted(hash) {
            return HashScanResult::Whitelisted;
        }

        HashScanResult::Unknown
    }

    pub fn compute_and_scan_md5(&self, file_path: &Path) -> Result<HashScanResult, String> {
        let hash = compute_md5(file_path)?;
        Ok(self.scan_hash(&hash))
    }

    pub fn compute_and_scan_sha256(&self, file_path: &Path) -> Result<HashScanResult, String> {
        let hash = compute_sha256(file_path)?;
        let htype = HashType::detect(&hash);
        if htype == HashType::Unknown {
            return Ok(HashScanResult::Unknown);
        }
        if self.bloom.is_blacklisted(&hash) {
            return Ok(HashScanResult::Blacklisted);
        }
        Ok(HashScanResult::Unknown)
    }

    /// MD5-only bloom lookup from an **already-computed** MD5 hex digest — no
    /// hashing at all, so the caller that already has the file's MD5 (e.g. the
    /// dedup key) can reuse it. The whitelist/blacklist lookups are the fast
    /// bloom filter (SHA-256 is too slow for the hot scan path).
    pub fn scan_md5(&self, md5_hex: &str) -> HashScanResult {
        if self.bloom.is_whitelisted(md5_hex) {
            return HashScanResult::Whitelisted;
        }
        if self.bloom.is_blacklisted(md5_hex) {
            return HashScanResult::Blacklisted;
        }
        HashScanResult::Unknown
    }

    /// MD5-only bloom lookup over a buffer (hashes it once).
    pub fn scan_data(&self, data: &[u8]) -> HashScanResult {
        self.scan_md5(&hex::encode(Md5::digest(data)))
    }

    pub fn compute_and_scan_all(&self, file_path: &Path) -> Result<HashScanResult, String> {
        let mut file = fs::File::open(file_path)
            .map_err(|e| format!("Failed to open {:?}: {}", file_path, e))?;

        let mut md5 = Md5::new();
        let mut sha256 = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let n = file
                .read(&mut buffer)
                .map_err(|e| format!("Failed to read {:?}: {}", file_path, e))?;
            if n == 0 {
                break;
            }
            md5.update(&buffer[..n]);
            sha256.update(&buffer[..n]);
        }

        let md5_hash = hex::encode(md5.finalize());

        if self.bloom.is_whitelisted(&md5_hash) {
            return Ok(HashScanResult::Whitelisted);
        }
        if self.bloom.is_blacklisted(&md5_hash) {
            return Ok(HashScanResult::Blacklisted);
        }

        let sha256_hash = hex::encode(sha256.finalize());
        if self.bloom.is_blacklisted(&sha256_hash) {
            return Ok(HashScanResult::Blacklisted);
        }

        Ok(HashScanResult::Unknown)
    }
}

impl Default for HashScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn compute_md5(file_path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(file_path).map_err(|e| format!("Failed to open {:?}: {}", file_path, e))?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read {:?}: {}", file_path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn compute_sha256(file_path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(file_path).map_err(|e| format!("Failed to open {:?}: {}", file_path, e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read {:?}: {}", file_path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
