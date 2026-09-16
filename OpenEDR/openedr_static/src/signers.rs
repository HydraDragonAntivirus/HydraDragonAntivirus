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
}

impl SignerDb {
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

#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HWND};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext,
    CertGetNameStringW, CryptMsgClose, CryptQueryObject, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
    CERT_QUERY_OBJECT_FILE, HCERTSTORE,
};
#[cfg(windows)]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

#[cfg(windows)]
pub fn verify_authenticode(path: &Path) -> (bool, bool, Option<String>, String, bool) {
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

    // Extract certificate subject name
    let mut signer_name = None;
    unsafe {
        let mut msg_and_cert_encoding = windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE::default();
        let mut content_type = windows::Win32::Security::Cryptography::CERT_QUERY_CONTENT_TYPE::default();
        let mut format_type = windows::Win32::Security::Cryptography::CERT_QUERY_FORMAT_TYPE::default();
        let mut cert_store: HCERTSTORE = HCERTSTORE::default();
        let mut crypt_msg: *mut std::ffi::c_void = std::ptr::null_mut();

        if CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_wide.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut msg_and_cert_encoding),
            Some(&mut content_type),
            Some(&mut format_type),
            Some(&mut cert_store),
            Some(&mut crypt_msg),
            None,
        ).is_ok() {
            if !cert_store.is_invalid() {
                let cert_ctx = CertEnumCertificatesInStore(cert_store, None);
                if !cert_ctx.is_null() {
                    let mut name_buf = [0u16; 256];
                    let len = CertGetNameStringW(
                        cert_ctx,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        None,
                        Some(&mut name_buf),
                    );
                    if len > 1 {
                        signer_name = Some(String::from_utf16_lossy(&name_buf[..(len as usize - 1)]));
                    }
                    let _ = CertFreeCertificateContext(Some(cert_ctx));
                }
                let _ = CertCloseStore(Some(cert_store), 0);
            }
            if !crypt_msg.is_null() {
                let _ = CryptMsgClose(Some(crypt_msg));
            }
        }
    }

    // Catalog-signed files (conhost.exe, notepad.exe, cmd.exe, ...) often carry
    // no embedded PKCS#7 signature: WTD_CHOICE_FILE reports them unsigned even
    // though they are signed via the Windows Catalog database. Fall back to
    // catalog membership verification for every file type (including
    // extensionless ones) so signed files are not misclassified.
    // (Ported from owlyshield signature_verification.rs; extension gate removed.)
    let mut is_catalog_signed = false;
    if !is_trusted {
        if let Some(catalog_signer) = verify_catalog_signature(&path_wide) {
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
/// Returns the catalog signer name (e.g. "Microsoft Windows Production PCA 2011")
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
            HANDLE::default(),
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

            win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            );

            if verify_result == ERROR_SUCCESS.0 as i32 {
                // Signer name is read from the catalog file's own embedded signature.
                let signer = get_signer_name_from_file(&cat_info_struct.catalog_file).ok();
                if signer.is_some() {
                    trusted_signer = signer;
                } else {
                    trusted_signer = Some("Microsoft Windows".to_string());
                }
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

/// Reads the display name of the first certificate in a signed file's
/// embedded PKCS#7 (used for catalog files backing catalog signatures).
unsafe fn get_signer_name_from_file(path_wide: &[u16]) -> Result<String, ()> {
    let wide_nul: Vec<u16> = if path_wide.last() == Some(&0) {
        path_wide.to_vec()
    } else {
        path_wide.iter().copied().chain(std::iter::once(0)).collect()
    };
    unsafe {
        let mut store: HCERTSTORE = HCERTSTORE::default();
        let mut msg: *mut std::ffi::c_void = std::ptr::null_mut();
        if CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_nul.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        )
        .is_err()
        {
            return Err(());
        }
        if store.is_invalid() {
            return Err(());
        }
        let cert_ctx = CertEnumCertificatesInStore(store, None);
        if cert_ctx.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return Err(());
        }
        let mut name_buf = [0u16; 256];
        let len = CertGetNameStringW(
            cert_ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        let _ = CertFreeCertificateContext(Some(cert_ctx));
        let _ = CertCloseStore(Some(store), 0);
        if len > 1 {
            Ok(String::from_utf16_lossy(&name_buf[..(len as usize - 1)]))
        } else {
            Err(())
        }
    }
}

#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path) -> (bool, bool, Option<String>, String, bool) {
    (false, false, None, "unsupported_platform".to_string(), false)
}
