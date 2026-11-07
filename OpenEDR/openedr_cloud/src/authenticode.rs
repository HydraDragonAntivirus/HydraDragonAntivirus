//! Authenticode verification with Windows WinVerifyTrust (embedded signatures and the
//! Windows catalog), ported unchanged from `openedr_static/src/signers.rs`. The
//! signer is not matched against vendor lists any more: trust is what Windows says.

use std::path::Path;

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

    /// Expired, and no timestamp keeps the signature valid. A timestamped
    /// (countersigned) signature made while the certificate was valid stays valid
    /// after the certificate expires; Windows accepts it the same way. So this
    /// fires only without a timestamp, or with a timestamp outside the
    /// certificate's validity window (signed after it expired, or before it was
    /// issued). A legacy PKCS#9 countersignature carries no time: accepted, as
    /// Windows does.
    pub fn is_expired_untimestamped(&self, now: i64) -> bool {
        if !self.is_expired(now) {
            return false;
        }
        if !self.timestamped {
            return true;
        }
        match self.timestamp_time {
            Some(t) => self.not_after.is_some_and(|to| t > to) || self.not_before.is_some_and(|from| t < from),
            None => false,
        }
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

