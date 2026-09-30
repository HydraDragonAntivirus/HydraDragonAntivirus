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
    /// SHA-256 benign whitelist (BinaryFuse16 `.xf`). Owned by the signer side on
    /// purpose: this is the file-identity trust table, and it sits next to the
    /// vendor lists so `SignerDb` stays the single authority for "is this file
    /// trusted" — the answer libedr and owlyshield_predict already ask this
    /// object for.
    benign: Option<BinaryFuse16Filter>,
}

/// File name of the SHA-256 benign whitelist, under `xorfilter_rules/`.
pub const BENIGN_XF: &str = "benign_sha256.xf";

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

        db.trusted = Self::load_file(&dir.join("trusted_signers.yaml"));
        db.malicious = Self::load_file(&dir.join("malicious_vendors.yaml"));
        db.pua = Self::load_file(&dir.join("pua_vendors.yaml"));
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

    fn load_file(path: &Path) -> Vec<PatternItem> {
        if !path.is_file() {
            return Vec::new();
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let file: SignerRuleFile = match serde_yaml::from_str(&content) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        for rule in file.rules {
            for cond in rule.conditions {
                if (cond.cond_type == "signature_signer_contains" || cond.cond_type == "signature_signer_equals")
                    && !cond.value.is_empty()
                {
                    out.push(PatternItem {
                        value: cond.value.to_lowercase(),
                        is_exact: cond.cond_type == "signature_signer_equals",
                    });
                }
            }
        }
        out
    }

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
    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
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
    result: (bool, bool, Option<String>, String, bool),
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
) -> Option<(bool, bool, Option<String>, String, bool)> {
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
    result: (bool, bool, Option<String>, String, bool),
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
pub fn verify_authenticode(path: &Path) -> (bool, bool, Option<String>, String, bool) {
    if let Some(hit) = authenticate_cached(path) {
        return hit;
    }
    let result = verify_authenticode_uncached(path);
    authenticate_store(path, result.clone());
    result
}

/// Display name of the certificate that actually signed the file, taken from the
/// chain WinVerifyTrust just built.
///
/// This used to be `CertEnumCertificatesInStore(store, None)` on a store opened
/// with `CryptQueryObject(..., PKCS7_SIGNED_EMBED, ...)`, which returns
/// whichever certificate happens to sit first in the store - the CA/issuer, not
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
unsafe fn signer_subject_from_state(state: HANDLE) -> Option<String> {
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
        let signer_cert = &*sgnr.pasCertChain;
        if signer_cert.pCert.is_null() {
            return None;
        }

        let mut name_buf = [0u16; 256];
        let len = CertGetNameStringW(
            signer_cert.pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        if len > 1 {
            Some(String::from_utf16_lossy(&name_buf[..(len as usize - 1)]))
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn verify_authenticode_uncached(path: &Path) -> (bool, bool, Option<String>, String, bool) {
    use std::os::windows::ffi::OsStrExt;

    if !path.is_file() {
        return (false, false, None, "File not found".to_string(), false);
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

    // Extract the publisher name from the chain WinVerifyTrust just verified,
    // then release the state. The state was previously never closed on this
    // path, leaking a handle per verified file.
    let mut signer_name = unsafe { signer_subject_from_state(win_trust_data.hWVTStateData) };
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

    (is_signed, is_trusted, signer_name, status, is_catalog_signed)
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
pub fn verify_authenticode(_path: &Path) -> (bool, bool, Option<String>, String, bool) {
    (false, false, None, "unsupported_platform".to_string(), false)
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
}
