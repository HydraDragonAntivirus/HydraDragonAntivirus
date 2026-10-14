use std::path::Path;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SignerRuleFile {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub rules: Vec<SignerRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub conditions: Vec<SignerCondition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerCondition {
    #[serde(rename = "type")]
    pub cond_type: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub nocase: bool,
}

/// Everything the engine needs to know about a file's Authenticode signature.
///
/// Replaces the positional tuple this used to return: five fields were already
/// the limit, and the certificate identity (issuer, chain, thumbprint,
/// validity) needs more than that.
#[derive(Debug, Clone, Default)]
pub struct AuthenticodeInfo {
    /// A signature exists and WinVerifyTrust (or the catalog fallback) could
    /// read a chain from it.
    pub is_signed: bool,
    /// WinVerifyTrust returned `ERROR_SUCCESS` for the embedded or catalog
    /// signature. Independent of `signer_rules/`.
    pub is_trusted: bool,
    /// Publisher display name of the leaf certificate.
    pub signer_name: Option<String>,
    /// Display name of the CA that issued the leaf.
    pub issuer: Option<String>,
    /// `trusted` / `signed_untrusted` / `unsigned`, or an error string.
    pub status: String,
    /// Signed through the Windows Catalog rather than an embedded PKCS#7.
    pub is_catalog_signed: bool,
    /// Certificates in the verified chain, leaf first.
    pub chain_len: usize,
    /// SHA-1 of the leaf certificate, lowercase hex.
    pub thumbprint: Option<String>,
    /// Leaf certificate validity window, Unix seconds.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// The signature carries a countersignature - RFC 3161 or legacy PKCS#9.
    /// Malware routinely strips or re-mints these so a certificate looks
    /// permanently fresh, which makes "signed but never timestamped" a signal
    /// in its own right.
    pub timestamped: bool,
    /// `rfc3161` or `pkcs9`.
    pub timestamp_kind: Option<String>,
    /// Common name of the TSA / countersigner.
    pub timestamp_signer: Option<String>,
    /// `genTime` of the RFC 3161 token, Unix seconds. Always `None` for a
    /// legacy PKCS#9 countersignature, which carries no timestamp value.
    pub timestamp_time: Option<i64>,
}

impl AuthenticodeInfo {
    /// Placeholder verdict for platforms without WinTrust. Only the
    /// `#[cfg(not(windows))]` stub builds it.
    #[cfg_attr(windows, allow(dead_code))]
    fn unsupported(reason: &str) -> Self {
        Self { status: reason.to_string(), ..Default::default() }
    }

    /// True when the leaf certificate was past `not_after` at scan time.
    /// WinVerifyTrust already fails an expired leaf, so this only ever fires on
    /// the `signed_untrusted` path — which is exactly the interesting one.
    pub fn is_expired(&self, now: i64) -> bool {
        self.not_after.map(|t| now > t).unwrap_or(false)
    }

    /// True when the leaf certificate is not valid yet.
    pub fn is_not_yet_valid(&self, now: i64) -> bool {
        self.not_before.map(|t| now < t).unwrap_or(false)
    }

    /// Signed, trusted, and carrying no countersignature at all.
    ///
    /// Only meaningful for embedded signatures: a catalog-signed file has no
    /// PKCS#7 of its own, so the catalog is not "missing" a timestamp and this
    /// must not fire on it.
    pub fn is_undated(&self) -> bool {
        self.is_signed && !self.timestamped && !self.is_catalog_signed
    }
}

#[derive(Debug, Clone)]
pub struct PatternItem {
    pub value: String,
    pub is_exact: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SignerDb {
    trusted: Vec<PatternItem>,
    malicious: Vec<PatternItem>,
    pua: Vec<PatternItem>,
    /// Issuing CAs. A certificate is abused by the CA that minted it, not by
    /// the publisher string it carries, so these lists are matched against
    /// `AuthenticodeInfo::issuer` and catch certificates whose subject has
    /// nothing to do with the abusive CA.
    malicious_issuers: Vec<PatternItem>,
    pua_issuers: Vec<PatternItem>,
    /// Timestamp authorities behind the countersignature. A separate trust
    /// domain from the code-signing certificate: an attacker who cannot get a
    /// code-signing cert can still occasionally talk a friendly TSA into dating
    /// a signature.
    malicious_tsas: Vec<PatternItem>,
    /// Leaf certificate SHA-1 fingerprints, lowercase hex. Pins one exact
    /// certificate - the only way to name a revoked-but-still-trusted one.
    pinned_thumbprints: Vec<String>,
    /// SHA-256 benign whitelist (BinaryFuse16 `.xf`). Owned by the signer side on
    /// purpose: this is the file-identity trust table, and it sits next to the
    /// vendor lists so `SignerDb` stays the single authority for "is this file
    /// trusted" — the answer libedr and owlyshield_predict already ask this
    /// object for.
    benign: Option<BinaryFuse16Filter>,
}

/// File name of the SHA-256 benign whitelist, under `xorfilter_rules/`.
pub const BENIGN_XF: &str = "benign_sha256.xf";

/// File name of the URL/domain/IP whitelist (BinaryFuse16 `.xf`, Tranco 1M),
/// under `xorfilter_rules/`. Web parity: `openedr_web`'s `url_whitelist`.
pub const URL_WHITELIST_XF: &str = "url_whitelist.xf";

impl SignerDb {
    pub fn pattern_counts(&self) -> (usize, usize, usize) {
        (self.trusted.len(), self.malicious.len(), self.pua.len())
    }

    /// True when the SHA-256 whitelist was loaded and can answer queries.
    pub fn benign_loaded(&self) -> bool {
        self.benign.is_some()
    }

    pub fn load_from_dir(dir: &Path) -> Self {
        let mut db = Self::default();
        if !dir.is_dir() {
            return db;
        }

        let trusted = Self::load_file(&dir.join("trusted_signers.yaml"));
        let malicious = Self::load_file(&dir.join("malicious_vendors.yaml"));
        let pua = Self::load_file(&dir.join("pua_vendors.yaml"));

        db.trusted = trusted.names;
        db.malicious = malicious.names;
        db.malicious_issuers = malicious.issuers;
        db.malicious_tsas = malicious.tsas;
        db.pinned_thumbprints = malicious.thumbprints;
        db.pua = pua.names;
        db.pua_issuers = pua.issuers;
        db
    }

    /// Load the SHA-256 benign whitelist from `xorfilter_rules/benign_sha256.xf`.
    ///
    /// Returns `false` when the file is missing or is not a valid filter; the
    /// whitelist then simply stays disabled, which is not an error — an install
    /// built without a corpus ships no `.xf`.
    pub fn load_benign_whitelist(&mut self, xf_path: &Path) -> bool {
        let Ok(bytes) = std::fs::read(xf_path) else {
            return false;
        };
        match BinaryFuse16Filter::from_bytes(&bytes) {
            Some(f) => {
                self.benign = Some(f);
                true
            }
            None => false,
        }
    }

    /// Install a filter loaded from bytes at runtime (FFI parity with the web
    /// engine, which receives the `.xf` over `wasm-bindgen`).
    pub fn set_benign_whitelist(&mut self, data: &[u8]) -> bool {
        match BinaryFuse16Filter::from_bytes(data) {
            Some(f) => {
                self.benign = Some(f);
                true
            }
            None => false,
        }
    }

    /// SHA-256 whitelist hit. Web parity (`openedr_web`: `is_benign(sha256_hex)`).
    ///
    /// The key is the bare lowercase-or-uppercase hex digest, folded to lowercase
    /// by `BinaryFuse16Filter::key`, so digest casing can never cause a miss.
    pub fn is_benign(&self, sha256_hex: &str) -> bool {
        if sha256_hex.is_empty() {
            return false;
        }
        match &self.benign {
            Some(f) => f.contains(sha256_hex),
            None => false,
        }
    }
}

/// Condition values collected from one `signer_rules/*.yaml` file.
///
/// `signature_signer_*` addresses the publisher (the leaf subject);
/// `signature_issuer_*` addresses the CA that minted the certificate. They are
/// kept apart because a compromised CA signs for arbitrary subjects, so a rule
/// written only against publishers never sees it.
#[derive(Default)]
struct LoadedConditions {
    names: Vec<PatternItem>,
    issuers: Vec<PatternItem>,
    /// Timestamp authorities behind the countersignature.
    tsas: Vec<PatternItem>,
    /// Leaf SHA-1 fingerprints, colon-stripped and lowercased.
    thumbprints: Vec<String>,
}

impl SignerDb {
    pub fn is_malicious(&self, signer: &str) -> bool {
        Self::matches_list(&self.malicious, signer)
    }

    pub fn is_pua(&self, signer: &str) -> bool {
        Self::matches_list(&self.pua, signer)
    }

    pub fn is_trusted(&self, signer: &str) -> bool {
        if self.is_malicious(signer) || self.is_pua(signer) {
            return false;
        }
        Self::matches_list(&self.trusted, signer)
    }

    /// Issuing CA is listed as a malware certificate source.
    pub fn is_malicious_issuer(&self, issuer: &str) -> bool {
        Self::matches_list(&self.malicious_issuers, issuer)
    }

    /// Issuing CA is listed as a PUA / unwanted-software certificate source.
    pub fn is_pua_issuer(&self, issuer: &str) -> bool {
        Self::matches_list(&self.pua_issuers, issuer)
    }

    /// Leaf certificate is pinned by exact SHA-1.
    pub fn is_pinned_thumbprint(&self, thumbprint: &str) -> bool {
        if self.pinned_thumbprints.is_empty() || thumbprint.is_empty() {
            return false;
        }
        let t = thumbprint.trim().to_ascii_lowercase();
        self.pinned_thumbprints.iter().any(|p| *p == t)
    }

    /// Timestamp authority behind the countersignature is listed as abusive.
    ///
    /// The TSA is a different trust domain from the code-signing certificate:
    /// an attacker who cannot get a code-signing cert can still occasionally
    /// talk a friendly TSA into dating a signature.
    pub fn is_malicious_tsa(&self, tsa: &str) -> bool {
        Self::matches_list(&self.malicious_tsas, tsa)
    }

    /// `(publisher, issuer, pinned fingerprints)` sizes of the loaded corpus,
    /// for diagnostics.
    pub fn issuer_counts(&self) -> (usize, usize, usize) {
        (self.malicious_issuers.len(), self.pua_issuers.len(), self.pinned_thumbprints.len())
    }

    fn matches_list(list: &[PatternItem], signer: &str) -> bool {
        if list.is_empty() || signer.is_empty() {
            return false;
        }
        let lower = signer.to_lowercase();
        for p in list {
            if p.is_exact {
                if lower == p.value {
                    return true;
                }
            } else if lower.contains(&p.value) {
                return true;
            }
        }
        false
    }

    fn load_file(path: &Path) -> LoadedConditions {
        let mut out = LoadedConditions::default();
        if !path.is_file() {
            return out;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return out,
        };
        let file: SignerRuleFile = match serde_yaml::from_str(&content) {
            Ok(f) => f,
            Err(_) => return out,
        };

        for rule in file.rules {
            for cond in rule.conditions {
                if cond.value.is_empty() {
                    continue;
                }
                let value = cond.value.to_lowercase();
                let item = PatternItem { value, is_exact: cond.cond_type.ends_with("_equals") };
                match cond.cond_type.as_str() {
                    "signature_signer_contains" | "signature_signer_equals" => {
                        out.names.push(item);
                    }
                    "signature_issuer_contains" | "signature_issuer_equals" => {
                        out.issuers.push(item);
                    }
                    "signature_timestamp_signer_contains"
                    | "signature_timestamp_signer_equals" => {
                        out.tsas.push(item);
                    }
                    "signature_thumbprint_any" | "signature_thumbprint_equals" => {
                        // Accept `aa:bb:cc`, `aa bb cc` and bare hex.
                        let hex: String = cond
                            .value
                            .chars()
                            .filter(|c| c.is_ascii_hexdigit())
                            .collect::<String>()
                            .to_ascii_lowercase();
                        if hex.len() == 40 {
                            out.thumbprints.push(hex);
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

/// Self-contained BinaryFuse16 filter (web parity, zero deps).
///
/// Same on-disk format and query path as `hydradragonxorfilter` and as
/// `openedr_web::engine::BinaryFuse16Filter` (tag 16, version 2, FNV-1a
/// lowercased key): a `.xf` built offline with `xorfilter_writer` loads here
/// byte-for-byte. Kept inline so `openedr_static` builds with plain
/// `cargo build` — no AES/SSE2 RUSTFLAGS (the shared crate pulls `gxhash`,
/// which requires them).
#[derive(Clone)]
pub struct BinaryFuse16Filter {
    seed: u64,
    seg_len: u32,
    seg_len_mask: u32,
    seg_count_len: u32,
    count: usize,
    fingerprints: Vec<u16>,
}

impl std::fmt::Debug for BinaryFuse16Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryFuse16Filter")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
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

    /// Number of `u16` fingerprints in the filter (≈ keys × 1.23).
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
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

    /// FNV-1a-64 over the ASCII-lowercased bytes. Deterministic and platform
    /// independent, and case-insensitive so signer/hex casing can never cause a
    /// miss.
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

#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HWND};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CertGetCertificateContextProperty, CertGetNameStringW, CERT_CONTEXT,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
};

/// `CERT_SHA1_HASH_PROP_ID`. Not exported by the `windows` crate.
#[cfg(windows)]
const CERT_SHA1_HASH_PROP_ID: u32 = 3;

/// `FILETIME` (100 ns ticks since 1601-01-01) to Unix seconds.
#[cfg(windows)]
fn filetime_to_unix(ft: windows::Win32::Foundation::FILETIME) -> i64 {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    (ticks as i64 - 116_444_736_000_000_000) / 10_000_000
}

/// Everything `signer_subject_from_state` could see in the verified chain, and a
/// little more. Read while the `WTD_STATEACTION_VERIFY` state is still open —
/// the state is closed right after, so this is the only window onto the chain.
#[cfg(windows)]
#[derive(Debug, Clone, Default)]
pub struct ChainInfo {
    /// Simple display name of the leaf, i.e. the publisher.
    pub subject: Option<String>,
    /// Simple display name of the CA that issued the leaf.
    pub issuer: Option<String>,
    /// Certificates in the chain, leaf first.
    pub chain_len: usize,
    /// SHA-1 of the leaf certificate, lowercase hex.
    pub thumbprint: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

/// SHA-1 of a certificate context, as the lowercase hex everyone publishes.
#[cfg(windows)]
unsafe fn cert_thumbprint(cert: *const CERT_CONTEXT) -> Option<String> {
    if cert.is_null() {
        return None;
    }
    let mut size: u32 = 0;
    let ok = unsafe {
        CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, None, &mut size as *mut u32)
    };
    if ok.is_err() || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA1_HASH_PROP_ID,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            &mut size as *mut u32,
        )
    };
    if ok.is_err() {
        return None;
    }
    Some(buf.iter().take(size as usize).map(|b| format!("{:02x}", b)).collect())
}
#[cfg(windows)]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData,
};

#[cfg(windows)]
/// Cached WinTrust verdict. Catalog verification is the most expensive part
/// of a file scan (hash the file, walk CatRoot .cat members, WinVerifyTrust
/// per candidate), and the same executable is rescanned on every minifilter
/// event (create/write/change/close). Cache on (path, size, mtime) so a
/// rewritten or replaced binary re-verifies automatically.
#[derive(Clone, Debug)]
struct AuthenticodeCacheEntry {
    key: String,
    result: AuthenticodeInfo,
}

/// Bounded FIFO-ish cache: 4096 entries is far beyond the working set of
/// recently touched executables and keeps memory trivial.
#[cfg(windows)]
const AUTHENTICODE_CACHE_CAP: usize = 4096;

#[cfg(windows)]
fn authenticode_cache() -> &'static Mutex<Vec<AuthenticodeCacheEntry>> {
    static CACHE: OnceLock<Mutex<Vec<AuthenticodeCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Identity of the on-disk content for cache invalidation: size + last write
/// time. Cheap; a same-size rewrite still bumps mtime.
#[cfg(windows)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    Some((md.file_size(), md.last_write_time()))
}

#[cfg(windows)]
fn authenticate_cached(
    path: &Path,
) -> Option<AuthenticodeInfo> {
    let (size, mtime) = file_identity(path)?;
    let key = format!("{}\u{0}{size}\u{0}{mtime}", path.to_string_lossy().to_lowercase());
    if let Ok(cache) = authenticode_cache().lock() {
        if let Some(hit) = cache.iter().find(|e| e.key == key) {
            return Some(hit.result.clone());
        }
    }
    None
}

#[cfg(windows)]
fn authenticate_store(
    path: &Path,
    result: AuthenticodeInfo,
) {
    let Some((size, mtime)) = file_identity(path) else {
        return;
    };
    let key = format!("{}\u{0}{size}\u{0}{mtime}", path.to_string_lossy().to_lowercase());
    let Ok(mut cache) = authenticode_cache().lock() else {
        return;
    };
    if cache.iter().any(|e| e.key == key) {
        return;
    }
    if cache.len() >= AUTHENTICODE_CACHE_CAP {
        // Drop the oldest half in one pass: cheaper and simpler than LRU and
        // keeps the cache bounded without per-insert bookkeeping.
        let half = AUTHENTICODE_CACHE_CAP / 2;
        cache.drain(0..half);
    }
    cache.push(AuthenticodeCacheEntry { key, result });
}

#[cfg(windows)]
pub fn verify_authenticode(path: &Path) -> AuthenticodeInfo {
    if let Some(hit) = authenticate_cached(path) {
        return hit;
    }
    let result = verify_authenticode_uncached(path);
    authenticate_store(path, result.clone());
    result
}

/// Publisher display name of the certificate that actually signed the file.
#[cfg(windows)]
unsafe fn signer_subject_from_state(state: HANDLE) -> Option<String> {
    unsafe { cert_chain_from_state(state) }.and_then(|c| c.subject)
}

/// Read the verified chain while the WinTrust state is still open.
///
/// The publisher name used to be `CertEnumCertificatesInStore(store, None)` on a
/// store opened with `CryptQueryObject(..., PKCS7_SIGNED_EMBED, ...)`, which
/// returns whichever certificate happens to sit first in the store - the CA, not
/// the publisher. Every Microsoft binary therefore reported "Microsoft Windows
/// Production PCA 2011" instead of "Microsoft Windows", so no entry in
/// `signer_rules/trusted_signers.yaml` could ever match and the signer field was
/// useless for trust decisions.
///
/// `pasCertChain[0].pCert` is the signer certificate itself. This also works for
/// catalog-signed files (cmd.exe, conhost.exe, ...), where the embedded PKCS#7
/// route is unavailable - the catalog SIP puts the member's own certificate at
/// the head of the chain.
///
/// Safety: `state` must be the live `hWVTStateData` of a `WTD_STATEACTION_VERIFY`
/// WinVerifyTrust call that has not yet been closed with `WTD_STATEACTION_CLOSE`.
#[cfg(windows)]
unsafe fn cert_chain_from_state(state: HANDLE) -> Option<ChainInfo> {
    if state.is_invalid() {
        return None;
    }
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return None;
        }
        let sgnr = &*sgnr;
        if sgnr.pasCertChain.is_null() || sgnr.csCertChain == 0 {
            return None;
        }
        let leaf = &*sgnr.pasCertChain;
        if leaf.pCert.is_null() {
            return None;
        }

        let mut info = ChainInfo { chain_len: sgnr.csCertChain as usize, ..Default::default() };

        let mut name_buf = [0u16; 256];
        let len = CertGetNameStringW(
            leaf.pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        if len > 1 {
            info.subject = Some(String::from_utf16_lossy(&name_buf[..(len as usize - 1)]));
        }

        // The issuer is the next certificate up when the chain has one. A
        // self-signed or single-certificate chain has no such neighbour, and
        // naming the leaf's own issuer string is the only thing left to report.
        if sgnr.csCertChain > 1 {
            let next = &*sgnr.pasCertChain.add(1);
            if !next.pCert.is_null() {
                let mut issuer_buf = [0u16; 256];
                let len = CertGetNameStringW(
                    next.pCert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut issuer_buf),
                );
                if len > 1 {
                    info.issuer = Some(String::from_utf16_lossy(&issuer_buf[..(len as usize - 1)]));
                }
            }
        }

        info.thumbprint = cert_thumbprint(leaf.pCert);

        // `CRYPT_PROVIDER_CERT` has no certificate-info pointer; the validity
        // window lives on the certificate context itself.
        if !leaf.pCert.is_null() {
            let cert_info = (*leaf.pCert).pCertInfo;
            if !cert_info.is_null() {
                let cert_info = &*cert_info;
                info.not_before = Some(filetime_to_unix(cert_info.NotBefore));
                info.not_after = Some(filetime_to_unix(cert_info.NotAfter));
            }
        }

        Some(info)
    }
}

#[cfg(windows)]
fn verify_authenticode_uncached(path: &Path) -> AuthenticodeInfo {
    use std::os::windows::ffi::OsStrExt;

    if !path.is_file() {
        return AuthenticodeInfo {
            status: "File not found".to_string(),
            ..Default::default()
        };
    }

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_wide.as_ptr()),
        hFile: windows::Win32::Foundation::HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: windows::Win32::Security::WinTrust::WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0x00000010 | 0x00001000),
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
        Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let result = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        )
    };

    let mut is_trusted = result == ERROR_SUCCESS.0 as i32;

    // Read the whole verified chain while the state is still open: publisher,
    // issuing CA, depth, leaf thumbprint and validity all come out of the same
    // `pasCertChain` walk, so this costs no extra I/O. The state is then closed;
    // it used to be left open on this path, leaking a handle per verified file.
    let chain = unsafe { cert_chain_from_state(win_trust_data.hWVTStateData) };
    let mut signer_name = chain.as_ref().and_then(|c| c.subject.clone());
    if !win_trust_data.hWVTStateData.is_invalid() {
        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            )
        };
    }

    // Catalog-signed files (conhost.exe, notepad.exe, cmd.exe, ...) often carry
    // no embedded PKCS#7 signature: WTD_CHOICE_FILE reports them unsigned even
    // though they are signed via the Windows Catalog database. Fall back to
    // catalog membership verification for every file type (including
    // extensionless ones) so signed files are not misclassified.
    // (Ported from owlyshield signature_verification.rs; extension gate removed.)
    let mut is_catalog_signed = false;
    if !is_trusted {
        if let Some(catalog_signer) = unsafe { verify_catalog_signature(&path_wide) } {
            is_catalog_signed = true;
            is_trusted = true;
            if signer_name.is_none() {
                signer_name = Some(catalog_signer);
            }
        }
    }

    let is_signed = is_trusted || signer_name.is_some();
    let status = if is_trusted {
        "trusted".to_string()
    } else if is_signed {
        "signed_untrusted".to_string()
    } else {
        "unsigned".to_string()
    };

    // Countersignature, read from the file's own embedded PKCS#7. Skipped for
    // catalog-signed files: they carry no PKCS#7, so the catalog is not
    // "missing" a timestamp. `is_undated()` respects that too.
    let mut timestamped = false;
    let mut timestamp_kind = None;
    let mut timestamp_signer = None;
    let mut timestamp_time = None;
    if let Ok(bytes) = std::fs::read(path) {
        if let Some(pkcs7) = crate::auth_timestamp::embedded_pkcs7(&bytes) {
            if let Some(ts) = crate::auth_timestamp::parse_authenticode_timestamp(pkcs7) {
                timestamped = true;
                timestamp_kind = Some(
                    match ts.kind {
                        crate::auth_timestamp::TimestampKind::Rfc3161 => "rfc3161",
                        crate::auth_timestamp::TimestampKind::Pkcs9 => "pkcs9",
                    }
                    .to_string(),
                );
                timestamp_signer = ts.signer;
                timestamp_time = ts.time;
            }
        }
    }

    AuthenticodeInfo {
        is_signed,
        is_trusted,
        signer_name,
        issuer: chain.as_ref().and_then(|c| c.issuer.clone()),
        status,
        is_catalog_signed,
        chain_len: chain.as_ref().map_or(0, |c| c.chain_len),
        thumbprint: chain.as_ref().and_then(|c| c.thumbprint.clone()),
        not_before: chain.as_ref().and_then(|c| c.not_before),
        not_after: chain.as_ref().and_then(|c| c.not_after),
        timestamped,
        timestamp_kind,
        timestamp_signer,
        timestamp_time,
    }
}

#[repr(C)]
struct CatalogInfo {
    cb_struct: u32,
    catalog_file: [u16; 260],
}

#[link(name = "wintrust")]
unsafe extern "system" {
    fn CryptCATAdminAcquireContext(
        ph_cat_admin: *mut *mut std::ffi::c_void,
        pg_subsystem: *const std::ffi::c_void,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminCalcHashFromFileHandle(
        h_file: windows::Win32::Foundation::HANDLE,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminEnumCatalogFromHash(
        h_cat_admin: *mut std::ffi::c_void,
        pb_hash: *const u8,
        cb_hash: u32,
        dw_flags: u32,
        ph_prev_cat_info: *mut *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn CryptCATCatalogInfoFromContext(
        h_cat_info: *mut std::ffi::c_void,
        ps_cat_info: *mut CatalogInfo,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseCatalogContext(
        h_cat_admin: *mut std::ffi::c_void,
        h_cat_info: *mut std::ffi::c_void,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseContext(h_cat_admin: *mut std::ffi::c_void, dw_flags: u32) -> i32;
}

/// Verifies a file against the Windows Catalog database (CatRoot .cat files).
/// Returns the publisher name (e.g. "Microsoft Windows")
/// when the file hash matches a member of a valid, trusted catalog.
unsafe fn verify_catalog_signature(path_wide: &[u16]) -> Option<String> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::WinTrust::WTD_CHOICE_CATALOG;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::core::PCWSTR;

    const GENERIC_READ: u32 = 0x8000_0000;
    unsafe {
        let file_handle = match CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            GENERIC_READ,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            Some(HANDLE::default()),
        ) {
            Ok(h) => h,
            Err(_) => return None,
        };

        let mut cat_admin: *mut std::ffi::c_void = std::ptr::null_mut();
        if CryptCATAdminAcquireContext(&mut cat_admin, std::ptr::null(), 0) == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut hash_size: u32 = 0;
        if CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_size, std::ptr::null_mut(), 0)
            == 0
        {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }
        let mut hash: Vec<u8> = vec![0u8; hash_size as usize];
        if CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_size, hash.as_mut_ptr(), 0)
            == 0
        {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut prev: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut trusted_signer: Option<String> = None;

        loop {
            let cat_info =
                CryptCATAdminEnumCatalogFromHash(cat_admin, hash.as_ptr(), hash_size, 0, &mut prev);
            if cat_info.is_null() {
                break;
            }
            prev = cat_info;

            let mut cat_info_struct = CatalogInfo {
                cb_struct: std::mem::size_of::<CatalogInfo>() as u32,
                catalog_file: [0u16; 260],
            };
            if CryptCATCatalogInfoFromContext(cat_info, &mut cat_info_struct, 0) == 0 {
                let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
                continue;
            }

            let mut catalog_file_info = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: PCWSTR(cat_info_struct.catalog_file.as_ptr()),
                pcwszMemberTag: PCWSTR::null(),
                pcwszMemberFilePath: PCWSTR(path_wide.as_ptr()),
                hMemberFile: file_handle,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash_size,
                pcCatalogContext: std::ptr::null_mut(),
                hCatAdmin: cat_admin as isize,
            };

            let mut win_trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: windows::Win32::Security::WinTrust::WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: HANDLE::default(),
                pwszURLReference: PWSTR::null(),
                dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0),
                dwUIContext: WINTRUST_DATA_UICONTEXT(0),
                pSignatureSettings: std::ptr::null_mut(),
                Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                    pCatalog: &mut catalog_file_info,
                },
            };

            let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let verify_result = WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            );

            // Read the signer while the state is still open.
            let catalog_signer = signer_subject_from_state(win_trust_data.hWVTStateData);

            win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            );

            if verify_result == ERROR_SUCCESS.0 as i32 {
                trusted_signer = catalog_signer.or_else(|| Some("Microsoft Windows".to_string()));
                let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
                break;
            }

            let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
        }

        let _ = CryptCATAdminReleaseContext(cat_admin, 0);
        let _ = windows::Win32::Foundation::CloseHandle(file_handle);
        trusted_signer
    }
}

#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path) -> AuthenticodeInfo {
    AuthenticodeInfo::unsupported("unsupported_platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built BinaryFuse16 image that contains exactly one key.
    ///
    /// With `seg_count_len = 1` and `seg_len_mask = 0` the three slots always
    /// resolve to indices 0, 1 and 2, so storing the key's fingerprint in slot 0
    /// and zeroing the other two makes `contains()` true for that key alone.
    /// Building it here keeps the test independent of any shipped `.xf`.
    fn one_key_filter(item: &str) -> Vec<u8> {
        const SEED: u64 = 0x0123_4567_89ab_cdef;
        let fingerprint = BinaryFuse16Filter::mix64(
            BinaryFuse16Filter::key(item).wrapping_add(SEED),
        ) as u16;

        let mut bytes = Vec::with_capacity(32 + 6);
        bytes.push(16); // tag
        bytes.push(2); // version
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&SEED.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seg_len
        bytes.extend_from_slice(&0u32.to_le_bytes()); // seg_len_mask
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seg_count_len
        bytes.extend_from_slice(&3u64.to_le_bytes()); // count
        bytes.extend_from_slice(&fingerprint.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    #[test]
    fn filter_rejects_garbage_headers() {
        assert!(BinaryFuse16Filter::from_bytes(b"").is_none());
        assert!(BinaryFuse16Filter::from_bytes(b"nope").is_none());
        assert!(BinaryFuse16Filter::from_bytes(&[16u8, 2, 0, 0]).is_none());
        // Right tag/version but a fingerprint count that runs past the buffer.
        let mut truncated = vec![0u8; 32];
        truncated[0] = 16;
        truncated[1] = 2;
        truncated[24..32].copy_from_slice(&16u64.to_le_bytes());
        assert!(BinaryFuse16Filter::from_bytes(&truncated).is_none());
    }

    #[test]
    fn filter_round_trips_one_key_and_is_case_insensitive() {
        let hash = "000027cd05cdf4f81da50a0be2b719d7ffc80f886e85387d0e467a2056aa9cf2";
        let f = BinaryFuse16Filter::from_bytes(&one_key_filter(hash)).expect("must parse");

        assert_eq!(f.len(), 3);
        assert!(!f.is_empty());
        assert!(f.contains(hash));
        // The key fold lowercases every byte, so an uppercase digest must still
        // hit — same guarantee the web engine relies on.
        assert!(f.contains(&hash.to_ascii_uppercase()));
        assert!(!f.contains("aa".repeat(32).as_str()));
    }

    #[test]
    fn missing_filter_or_empty_sha256_never_whitelists() {
        let mut db = SignerDb::default();
        assert!(!db.benign_loaded());
        assert!(!db.is_benign("aabb"));
        assert!(!db.set_benign_whitelist(b"not a filter"));
        assert!(!db.is_benign(""));

        let hash = "000027cd05cdf4f81da50a0be2b719d7ffc80f886e85387d0e467a2056aa9cf2";
        assert!(db.set_benign_whitelist(&one_key_filter(hash)));
        assert!(db.benign_loaded());
        assert!(db.is_benign(hash));
        assert!(db.is_benign(&hash.to_ascii_uppercase()));
        assert!(!db.is_benign("aa".repeat(32).as_str()));
        assert!(!db.is_benign(""));
    }

    #[test]
    fn native_and_web_engines_fold_the_key_identically() {
        // Web parity contract: `openedr_web::engine::BinaryFuse16Filter::key` and
        // this copy must produce the same u64, otherwise a `.xf` built once for
        // the web demo would answer differently here. Both are FNV-1a-64 over the
        // ASCII-lowercased bytes; this pins the value so a change to one side
        // cannot silently desync the other.
        assert_eq!(
            BinaryFuse16Filter::key("000027cd05cdf4f81da50a0be2b719d7ffc80f886e85387d0e467a2056aa9cf2"),
            0xcb7f_4c3d_3da9_f5a1,
        );
    }

    /// Write a throwaway `signer_rules` directory and load it.
    fn db_from_yaml(tag: &str, malicious: &str) -> (SignerDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "openedr-signer-rules-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("malicious_vendors.yaml"), malicious).expect("write rules");
        let db = SignerDb::load_from_dir(&dir);
        (db, dir)
    }

    #[test]
    fn issuer_rules_are_kept_apart_from_publisher_rules() {
        // A compromised CA mints certificates for arbitrary publisher names, so
        // the two lists must not bleed into each other.
        let (db, dir) = db_from_yaml("issuer_rules_are_kept_apart_from_publisher_rules", 
            r#"
name: t
rules:
  - id: issuer-abuse
    title: "Abusive CA"
    conditions:
      - type: signature_issuer_contains
        value: "ReviverSoft Root"
      - type: signature_signer_contains
        value: "Some Publisher"
"#,
        );

        assert!(db.is_malicious_issuer("ReviverSoft Root CA"));
        assert!(db.is_malicious_issuer("reviversoft root ca")); // case-insensitive
        assert!(!db.is_malicious("ReviverSoft Root CA")); // publisher list unaffected
        assert!(db.is_malicious("Some Publisher Ltd"));
        assert!(!db.is_malicious_issuer("DigiCert Assured ID Root CA"));
        assert_eq!(db.issuer_counts().0, 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn thumbprints_accept_colons_spaces_and_case() {
        let (db, dir) = db_from_yaml("thumbprints_accept_colons_spaces_and_case", 
            r#"
name: t
rules:
  - id: pinned
    title: "Revoked leaf"
    conditions:
      - type: signature_thumbprint_any
        value: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
"#,
        );
        let want = "aabbccddeeff00112233445566778899aabbccdd";
        assert!(db.is_pinned_thumbprint(want));
        assert!(db.is_pinned_thumbprint(&want.to_ascii_uppercase()));
        assert!(db.is_pinned_thumbprint(&format!("{} ", want)));
        assert!(!db.is_pinned_thumbprint(&"ff".repeat(20)));
        assert!(!db.is_pinned_thumbprint(""));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_thumbprint_that_is_not_sha1_is_dropped() {
        // 32 hex chars is a truncated digest, not a certificate thumbprint;
        // silently accepting it would pin nothing.
        let (db, dir) = db_from_yaml("a_thumbprint_that_is_not_sha1_is_dropped", 
            r#"
name: t
rules:
  - id: bad
    title: "bad"
    conditions:
      - type: signature_thumbprint_any
        value: "aabbccdd"
"#,
        );
        assert!(!db.is_pinned_thumbprint("aabbccdd"));
        assert_eq!(db.issuer_counts().2, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signer_equals_does_not_match_a_longer_subject() {
        let (db, dir) = db_from_yaml("signer_equals_does_not_match_a_longer_subject", 
            r#"
name: t
rules:
  - id: exact
    title: "exact"
    conditions:
      - type: signature_signer_equals
        value: "Contoso Ltd"
"#,
        );
        assert!(db.is_malicious("Contoso Ltd"));
        assert!(!db.is_malicious("Contoso Ltd Evil Corp"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cert_validity_window_is_reported() {
        let info = AuthenticodeInfo {
            is_signed: true,
            not_before: Some(1_600_000_000),
            not_after: Some(1_700_000_000),
            ..Default::default()
        };
        assert!(!info.is_expired(1_650_000_000));
        assert!(info.is_expired(1_700_000_001));
        assert!(!info.is_not_yet_valid(1_650_000_000));
        assert!(info.is_not_yet_valid(1_500_000_000));

        // No window reported (catalog-signed, or a chain we could not read)
        // must not be read as "expired".
        let unknown = AuthenticodeInfo { is_signed: true, ..Default::default() };
        assert!(!unknown.is_expired(i64::MAX));
        assert!(!unknown.is_not_yet_valid(0));
    }

    /// End-to-end against a real signed binary: the publisher, the issuing CA,
    /// the leaf thumbprint, the chain depth and the validity window must all come
    /// out of one `WinVerifyTrust` call.
    ///
    /// Only meaningful on Windows with the target present, so it asserts the
    /// shape of the answer rather than any particular value.
    #[test]
    fn reads_certificate_identity_from_a_real_signed_binary() {
        let Ok(info) = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll") else {
            eprintln!("kernel32.dll not reachable, skipping");
            return;
        };
        assert!(info.is_file());
        let info = verify_authenticode(Path::new("C:\\Windows\\System32\\kernel32.dll"));
        assert!(info.is_signed, "a shipping system binary must read as signed");
        assert!(info.is_trusted, "and as trusted");

        let signer = info.signer_name.clone().expect("publisher");
        assert!(!signer.is_empty());
        assert!(!signer.contains("Production PCA"),
            "leaf, not the CA: got {signer:?}");

        assert!(info.issuer.is_some(), "issuing CA is now reported");
        assert!(info.chain_len >= 2, "leaf plus at least one CA, got {}", info.chain_len);

        let tp = info.thumbprint.clone().expect("leaf thumbprint");
        assert_eq!(tp.len(), 40, "lowercase SHA-1 hex");
        assert!(tp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        assert!(info.not_before.unwrap_or(0) > 0);
        assert!(info.not_after.unwrap_or(0) > info.not_before.unwrap_or(0));
    }

    /// The countersignature has to survive the whole path, not just the parser:
    /// PE table -> PKCS#7 -> TSA name -> rule match.
    #[test]
    fn a_real_binary_is_timestamped_and_matches_a_tsa_rule() {
        let Ok(meta) = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll") else {
            eprintln!("kernel32.dll not reachable, skipping");
            return;
        };
        assert!(meta.is_file());
        let info = verify_authenticode(Path::new("C:\\Windows\\System32\\kernel32.dll"));

        assert!(info.timestamped, "a shipping system binary is countersigned");
        assert!(info.timestamp_kind.is_some());
        assert!(info.timestamp_time.is_some(), "RFC 3161 carries a genTime");
        let tsa = info.timestamp_signer.clone().expect("TSA common name");
        assert!(!tsa.is_empty());
        // Not undated: the distinction is what the UndatedSignature rule reads.
        assert!(!info.is_undated());

        let (db, dir) = db_from_yaml(
            "a_real_binary_is_timestamped_and_matches_a_tsa_rule",
            &format!(
                r#"
name: t
rules:
  - id: bad-tsa
    title: "Abusive TSA"
    conditions:
      - type: signature_timestamp_signer_contains
        value: "{tsa}"
"#
            ),
        );
        assert!(db.is_malicious_tsa(&tsa));
        assert!(db.is_malicious_tsa(&tsa.to_lowercase()), "case-insensitive");
        assert!(!db.is_malicious_tsa("Some Other Authority"),
            "the publisher list must not be reused for TSAs");
        assert!(!db.is_malicious(&tsa),
            "a TSA is not the publisher of the file");

        let _ = std::fs::remove_dir_all(dir);
    }
}
