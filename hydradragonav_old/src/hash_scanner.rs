use std::fs;
use std::io::Read;
use std::path::Path;

use md5::{Digest, Md5};
use sha1::Sha1;
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

    /// One-bloom, all-signatures lookup ("old-days" style): check the buffer's
    /// MD5/SHA-1/SHA-256/ssdeep/TLSH against the single blacklist bloom (and the
    /// MD5 whitelist). Every signature type lives in the same bloom; they are
    /// told apart purely by content (hex length, ':' for ssdeep, 'T1' for TLSH).
    /// `md5_hex` is the already-computed MD5 so the buffer isn't hashed twice.
    /// Returns the verdict and which hash matched (`""` when nothing matched).
    pub fn scan_all_buffer(&self, data: &[u8], md5_hex: &str) -> (HashScanResult, &'static str) {
        // Whitelist (MD5) wins and short-circuits everything else.
        if self.bloom.is_whitelisted(md5_hex) {
            return (HashScanResult::Whitelisted, "md5");
        }
        // Cheapest first: the precomputed MD5, then the fixed-size SHA digests.
        if self.bloom.is_blacklisted(md5_hex) {
            return (HashScanResult::Blacklisted, "md5");
        }
        if self.bloom.is_blacklisted(&compute_sha1_bytes(data)) {
            return (HashScanResult::Blacklisted, "sha1");
        }
        if self.bloom.is_blacklisted(&hex::encode(Sha256::digest(data))) {
            return (HashScanResult::Blacklisted, "sha256");
        }
        // Fuzzy digests, treated as exact strings in the same bloom.
        let ssdeep = compute_ssdeep_bytes(data);
        if !ssdeep.is_empty() && self.bloom.is_blacklisted(&ssdeep) {
            return (HashScanResult::Blacklisted, "ssdeep");
        }
        if let Some(tlsh) = compute_tlsh_bytes(data) {
            if self.bloom.is_blacklisted(&tlsh) {
                return (HashScanResult::Blacklisted, "tlsh");
            }
        }
        (HashScanResult::Unknown, "")
    }

    pub fn compute_and_scan_all(&self, file_path: &Path) -> Result<HashScanResult, String> {
        let mut file = fs::File::open(file_path)
            .map_err(|e| format!("Failed to open {:?}: {}", file_path, e))?;

        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
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
            sha1.update(&buffer[..n]);
            sha256.update(&buffer[..n]);
        }

        let md5_hash = hex::encode(md5.finalize());

        if self.bloom.is_whitelisted(&md5_hash) {
            return Ok(HashScanResult::Whitelisted);
        }
        if self.bloom.is_blacklisted(&md5_hash) {
            return Ok(HashScanResult::Blacklisted);
        }

        // SHA-1 and SHA-256 are exact-match lookups against the same blacklist
        // bloom (mirrors MD5/SHA-256 handling — fuzzy hashes go through FuzzyDb).
        let sha1_hash = hex::encode(sha1.finalize());
        if self.bloom.is_blacklisted(&sha1_hash) {
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

pub fn compute_sha1(file_path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(file_path).map_err(|e| format!("Failed to open {:?}: {}", file_path, e))?;
    let mut hasher = Sha1::new();
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

/// SHA-1 hex digest of an in-memory buffer.
pub fn compute_sha1_bytes(data: &[u8]) -> String {
    hex::encode(Sha1::digest(data))
}

/// ssdeep / CTPH fuzzy digest of a buffer (pure-Rust `fuzzyhash`, ssdeep-compatible).
pub fn compute_ssdeep_bytes(data: &[u8]) -> String {
    fuzzyhash::FuzzyHash::new(data).to_string()
}

/// TLSH digest (T1-prefixed, e.g. `T1A2B3…`) of a buffer. The `T1` form matches
/// the MalwareBazaar feed stored in the bloom. Returns `None` for inputs TLSH
/// can't hash (it needs roughly ≥ 50 bytes with enough byte-value variance).
pub fn compute_tlsh_bytes(data: &[u8]) -> Option<String> {
    tlsh_rs::hash_bytes(data).ok().map(|d| d.encoded())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digests the scanner computes must be in the same textual form the
    /// bloom stores, so HashType detection (length / ':' / 'T1') lines up.
    #[test]
    fn digest_formats_match_feed_shapes() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 31 + 7) as u8).collect();

        let tlsh = compute_tlsh_bytes(&data).expect("4 KiB buffer should hash");
        assert!(tlsh.starts_with("T1"), "TLSH must be T1-prefixed: {tlsh}");
        assert_eq!(HashType::detect(&tlsh), HashType::Tlsh);

        let ssdeep = compute_ssdeep_bytes(&data);
        assert!(ssdeep.contains(':'), "ssdeep must contain ':': {ssdeep}");
        assert_eq!(HashType::detect(&ssdeep), HashType::Ssdeep);

        assert_eq!(HashType::detect(&compute_sha1_bytes(&data)), HashType::Sha1);
    }
}
