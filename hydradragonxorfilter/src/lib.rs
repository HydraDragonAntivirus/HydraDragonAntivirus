//! Shared Binary-Fuse (xor) filter container used by BOTH the offline builder
//! (`dev-tools/xorfilter_writer`) and the on-device native scanner
//! (`hydradragonandroid`). Keeping the key derivation, the filter-type selection
//! and the on-disk format in ONE crate guarantees a filter written on the x86
//! build host is queryable byte-for-byte on the arm64 device.
//!
//! **Only BinaryFuse16 (`Bf16`) is used** — it gives ~2.16 bytes/key, which is
//! the best size/accuracy tradeoff for every filter in this project (URL/domain
//! lists, IP blocklists, MD5 whitelists). Using a single width means:
//!   * one file-format tag, no branching on read
//!   * predictable asset sizes before building
//!   * `jdb_xorf::Bf16::from(&keys)` handles construction directly
//!
//! On-disk format (version 2, repr(C)-style, no bitcode):
//! ```text
//! [0]      TAG   = 16 (u8)
//! [1]      VERSION = 2 (u8)
//! [2..4]   reserved (zero)
//! [4..12]  seed (u64, little-endian)
//! [12..16] seg_len (u32 LE)
//! [16..20] seg_len_mask (u32 LE)
//! [20..24] seg_count_len (u32 LE)
//! [24..32] count (u64 LE)  — number of u16 fingerprints
//! [32..]   fingerprints (u16 × count, little-endian)
//! ```
//! A 32-byte fixed header keeps the fingerprint array 2-byte aligned at
//! offset 32, so a zero-copy `&[u16]` can be built from an AAsset / owned
//! buffer without alignment faults. Queries run straight off those bytes —
//! NO decoded heap copy — so the filter's data is file-backed (evictable
//! page cache under memory pressure) instead of anonymous RSS.

use jdb_xorf::{Bf16, Filter as JdbFilter};

/// File-format tag (first byte of every `.xf` file) — always BF16.
const TAG_BF16: u8 = 16;
/// On-disk format version (bumped from 1: bitcode → repr(C) header).
const VERSION: u8 = 2;
/// Header size in bytes (fixed, keeps fingerprints 2-byte aligned).
const HEADER_LEN: usize = 32;

/// Folds a textual item (domain, full URL or hex hash) to the `u64` key the
/// filter is built and queried on.
///
/// FNV-1a 64 over the ASCII-lowercased bytes: deterministic, platform
/// independent and dependency free. Both build and query lowercase, so case can
/// never cause a miss (hostnames and hex digests are case-insensitive). The
/// filter re-mixes this key with its own internal seed, so a simple non-crypto
/// hash is sufficient — its sole job here is to map a string to a `u64`.
pub fn key(s: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in s.bytes() {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ───────────────────────────────────────────────────────────────────────────
// Vendored query primitives (byte-for-byte identical to jdb_xorf 0.13.11 so a
// filter built by that crate answers exactly the same as our zero-copy read).
// jdb_xorf keeps `base::query` internal, so the ~30 lines that matter are
// duplicated here — kept in sync by the round-trip tests in this crate.
// ───────────────────────────────────────────────────────────────────────────

/// RapidHash/WyHash-style 64-bit mixer (128-bit product). From jdb_xorf.
#[inline(always)]
fn mix64(k: u64) -> u64 {
    const MIX_C1: u64 = 0xff51_afd7_ed55_8ccd;
    let r = (k as u128).wrapping_mul(MIX_C1 as u128);
    (r ^ (r >> 64)) as u64
}

/// Binary-fuse index derivation. From jdb_xorf `prelude::bfuse::hash_of_hash`.
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

/// What the `XorFilter` holds on to so its `fingerprints` pointer stays valid
/// for the filter's whole lifetime.
enum Backing {
    /// Open Android AAsset (never closed) whose buffer we point into.
    AAsset(*mut std::ffi::c_void),
    /// Owned copy (fallback when the asset is compressed / host `from_bytes`).
    Owned(Vec<u8>),
}

impl Drop for Backing {
    fn drop(&mut self) {
        match self {
            // The AAsset handle is deliberately LEAKED (never closed): closing
            // it would free the APK's buffer that `fingerprints` still points
            // into. Reading the pointer here both marks it used and documents
            // that the handle outlives the filter.
            Backing::AAsset(asset) => {
                debug_assert!(!asset.is_null(), "AAsset handle must never be null");
            }
            // The Vec's own drop frees the owned copy; nothing to do, but read
            // the slice so the field is genuinely used rather than dead.
            Backing::Owned(bytes) => {
                debug_assert!(bytes.len() >= HEADER_LEN, "owned backing must hold a full header");
            }
        }
    }
}

// SAFETY: Backing::AAsset is only ever read through the immutable buffer
// pointer captured at load time; the handle is never closed. The u16 data is
// immutable for the filter's lifetime, so sharing across threads is safe.
unsafe impl Send for XorFilter {}
unsafe impl Sync for XorFilter {}

/// A loaded BinaryFuse16 filter backed by borrowed bytes (no decoded copy).
pub struct XorFilter {
    seed: u64,
    seg_len: u32,
    seg_len_mask: u32,
    seg_count_len: u32,
    count: usize,
    fingerprints: *const u8,
    _backing: Backing,
}

impl XorFilter {
    /// Parse and validate the 32-byte header, returning the fingerprint
    /// pointer + count into `bytes`.
    fn parse_at(bytes: &[u8]) -> Option<(u64, u32, u32, u32, usize, *const u8)> {
        if bytes.len() < HEADER_LEN || bytes[0] != TAG_BF16 || bytes[1] != VERSION {
            return None;
        }
        let seed = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let seg_len = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let seg_len_mask = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let seg_count_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let count = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        let count = usize::try_from(count).ok()?;
        let fp_bytes = count.checked_mul(2)?;
        if HEADER_LEN.checked_add(fp_bytes)? > bytes.len() {
            return None;
        }
        // SAFETY: `fp_bytes` is checked to fit inside `bytes` above.
        let fp_ptr = unsafe { bytes.as_ptr().add(HEADER_LEN) };
        Some((seed, seg_len, seg_len_mask, seg_count_len, count, fp_ptr))
    }

    /// Decode a filter from its tagged on-disk bytes, OWNING a copy (used by
    /// host tools and the compressed-asset fallback). `None` on a bad tag or a
    /// malformed body.
    pub fn from_bytes(bytes: &[u8]) -> Option<XorFilter> {
        let (seed, seg_len, seg_len_mask, seg_count_len, count, _) = Self::parse_at(bytes)?;
        let owned = bytes[HEADER_LEN..HEADER_LEN + count * 2].to_vec();
        let ptr = owned.as_ptr();
        Some(XorFilter {
            seed,
            seg_len,
            seg_len_mask,
            seg_count_len,
            count,
            fingerprints: ptr,
            _backing: Backing::Owned(owned),
        })
    }

    /// Zero-copy view over an owned buffer (no double copy: caller hands over
    /// the exact bytes it read).
    pub fn from_owned(bytes: Vec<u8>) -> Option<XorFilter> {
        let (seed, seg_len, seg_len_mask, seg_count_len, count, ptr) = Self::parse_at(&bytes)?;
        Some(XorFilter {
            seed,
            seg_len,
            seg_len_mask,
            seg_count_len,
            count,
            fingerprints: ptr,
            _backing: Backing::Owned(bytes),
        })
    }

    /// Zero-copy view over an Android AAsset buffer. The asset is kept open
    /// for the filter's lifetime (the handle moves into `Backing::AAsset` and
    /// is intentionally never closed).
    ///
    /// # Safety
    /// `ptr`/`len` must describe a live, readable region for as long as the
    /// returned filter lives; `asset` must stay open that long too.
    pub unsafe fn from_asset_buffer(
        ptr: *const u8,
        len: usize,
        asset: *mut std::ffi::c_void,
    ) -> Option<XorFilter> {
        // SAFETY: guaranteed by the caller (see `# Safety` above).
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        let (seed, seg_len, seg_len_mask, seg_count_len, count, fp) = Self::parse_at(bytes)?;
        Some(XorFilter {
            seed,
            seg_len,
            seg_len_mask,
            seg_count_len,
            count,
            fingerprints: fp,
            _backing: Backing::AAsset(asset),
        })
    }

    /// Membership test for a precomputed key.
    pub fn contains_key(&self, k: u64) -> bool {
        let hash = mix64(k.wrapping_add(self.seed));
        let f = hash as u16;
        let (h0, h1, h2) = hash_of_hash(hash, self.seg_len, self.seg_len_mask, self.seg_count_len);
        let c = self.count;
        if h0 as usize >= c || h1 as usize >= c || h2 as usize >= c {
            return false; // corrupt file; never index out of bounds
        }
        // SAFETY: indices are bounds-checked above; `fingerprints` points into
        // live backing memory for this filter's lifetime.
        unsafe {
            let read = |i: usize| -> u16 {
                u16::from_le_bytes([
                    *self.fingerprints.add(i * 2),
                    *self.fingerprints.add(i * 2 + 1),
                ])
            };
            let fp = read(h0 as usize) ^ read(h1 as usize) ^ read(h2 as usize);
            f ^ fp == 0
        }
    }

    /// Membership test for a textual item (folds it via [`key`] first).
    pub fn contains(&self, s: &str) -> bool {
        self.contains_key(key(s))
    }
}

/// Build a tagged `.xf` blob from `keys` (raw `u64` keys, i.e. already passed
/// through [`key`]). Always uses BinaryFuse16 (`Bf16`).
///
/// Duplicate keys are removed first: binary-fuse construction requires distinct
/// keys. Returns the bytes to write, or an error string if construction failed.
pub fn build_from_keys(mut keys: Vec<u64>) -> Result<Vec<u8>, String> {
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return Err("no keys to build a filter from".to_string());
    }
    // Bf16::from panics (rather than returning Result) in the extremely
    // unlikely event construction doesn't converge even after dedup; catch
    // that to preserve this function's Result contract.
    let filter = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Bf16::from(&keys)))
        .map_err(|_| "BF16 filter construction panicked".to_string())?;

    let mut out = Vec::with_capacity(HEADER_LEN + filter.len() * 2);
    out.push(TAG_BF16);
    out.push(VERSION);
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(&filter.desc.seed.to_le_bytes());
    out.extend_from_slice(&filter.desc.seg_len.to_le_bytes());
    out.extend_from_slice(&filter.desc.seg_len_mask.to_le_bytes());
    out.extend_from_slice(&filter.desc.seg_count_len.to_le_bytes());
    out.extend_from_slice(&(filter.fingerprints.len() as u64).to_le_bytes());
    for fp in filter.fingerprints.iter() {
        out.extend_from_slice(&fp.to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_build_load_query() {
        let keys: Vec<u64> = (0..10_000u64).map(|i| key(&format!("domain{i}.com"))).collect();
        let bytes = build_from_keys(keys.clone()).unwrap();
        // Owned path
        let f = XorFilter::from_bytes(&bytes).unwrap();
        for k in &keys {
            assert!(f.contains_key(*k));
        }
        assert!(!f.contains_key(key("not-in-set.example")));
        // Owned-buffer path (no copy)
        let f2 = XorFilter::from_owned(bytes.clone()).unwrap();
        assert!(f2.contains_key(keys[0]));
    }

    #[test]
    fn rejects_bad_headers() {
        assert!(XorFilter::from_bytes(&[0u8; 10]).is_none());
        assert!(XorFilter::from_bytes(&[16, 2, 0, 0]).is_none());
        let mut bytes = build_from_keys(vec![1, 2, 3]).unwrap();
        bytes[1] = 99; // wrong version
        assert!(XorFilter::from_bytes(&bytes).is_none());
    }

    #[test]
    fn short_fingerprint_block_rejected() {
        let mut bytes = build_from_keys(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(XorFilter::from_bytes(&bytes).is_none());
    }
}
