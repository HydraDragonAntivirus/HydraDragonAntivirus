use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HWND};

use windows::Win32::Security::Cryptography::{
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CertCloseStore,
    CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose,
    CryptQueryObject, HCERTSTORE,
};

use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureStatus {
    Trusted,
    SignedUntrusted,
    Unsigned,
    Invalid,
    VerificationFailed,
}

impl SignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureStatus::Trusted => "trusted",
            SignatureStatus::SignedUntrusted => "signed_untrusted",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::VerificationFailed => "verification_failed",
        }
    }
}

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;

const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001u32 as i32;

const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003u32 as i32;

const CERT_E_UNTRUSTEDROOT: i32 = 0x800B_0109u32 as i32;

const TRUST_E_BAD_DIGEST: i32 = 0x8009_6010u32 as i32;

const TRUST_E_CERT_SIGNATURE: i32 = 0x8009_6004u32 as i32;

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
        h_file: HANDLE,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureInfo {
    pub is_trusted: bool,
    pub is_signed: bool,
    pub signer_name: Option<String>,

    // Full verifier result exposed to rule sets and downstream integrations.
    pub status: SignatureStatus,
    pub status_text: String,
    pub raw_hresult: u32,
    pub verification_failed: bool,
    pub no_signature: bool,
    pub signature_status_issues: bool,
    pub invalid_signature: bool,

    // Fine-grained signature classification so rules can distinguish an
    // attached (embedded Authenticode PKCS#7) signature from a catalog
    // (CatRoot .cat membership) signature, and can tell whether the target
    // is an executable image at all.
    pub is_executable: bool,
    pub is_catalog_signed: bool,
    pub is_attached_signed: bool,
}

impl Default for SignatureInfo {
    fn default() -> Self {
        Self {
            is_trusted: false,
            is_signed: false,
            signer_name: None,
            status: SignatureStatus::Unsigned,
            status_text: "Not verified (non-Windows platform)".to_string(),
            raw_hresult: 0,
            verification_failed: false,
            no_signature: true,
            signature_status_issues: false,
            invalid_signature: false,
            is_executable: false,
            is_catalog_signed: false,
            is_attached_signed: false,
        }
    }
}

fn is_authenticode_binary_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "exe"
                    | "dll"
                    | "sys"
                    | "ocx"
                    | "cpl"
                    | "scr"
                    | "drv"
                    | "mui"
                    | "msi"
                    | "msp"
                    | "msu"
                    | "cat"
            )
        })
        .unwrap_or(false)
}

fn is_no_signature_for_non_authenticode_file(path: &Path, result: i32) -> bool {
    // WinVerifyTrust commonly returns provider/subject-form errors for ordinary
    // source/data files. Those files are still unsigned for metadata and tests.
    // For executable-like files, do not collapse provider/catalog ambiguity into
    // unsigned; keep it as VerificationFailed to avoid false "image is unsigned".
    path.is_file()
        && !is_authenticode_binary_path(path)
        && matches!(
            result,
            TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN
        )
}

fn status_text_for(status: SignatureStatus, raw_hresult: u32) -> String {
    match status {
        SignatureStatus::Trusted => "Valid".to_string(),
        SignatureStatus::Unsigned => "No signature".to_string(),
        SignatureStatus::SignedUntrusted => {
            format!("Signed but untrusted (HRESULT=0x{raw_hresult:08X})")
        }
        SignatureStatus::Invalid => format!("Invalid signature (HRESULT=0x{raw_hresult:08X})"),
        SignatureStatus::VerificationFailed => {
            format!("Signature verification failed (HRESULT=0x{raw_hresult:08X})")
        }
    }
}

fn classify_wintrust_result(path: &Path, result: i32) -> SignatureStatus {
    if result == ERROR_SUCCESS.0 as i32 {
        SignatureStatus::Trusted
    } else if result == TRUST_E_NOSIGNATURE
        || is_no_signature_for_non_authenticode_file(path, result)
    {
        SignatureStatus::Unsigned
    } else if matches!(result, TRUST_E_BAD_DIGEST | TRUST_E_CERT_SIGNATURE) {
        SignatureStatus::Invalid
    } else if result == CERT_E_UNTRUSTEDROOT {
        SignatureStatus::SignedUntrusted
    } else {
        SignatureStatus::VerificationFailed
    }
}

pub fn verify_signature(path: &Path) -> SignatureInfo {
    let mut raw_hresult: u32;
    let mut status: SignatureStatus;
    let mut signer_name = None;
    let mut is_catalog_signed = false;
    let mut is_attached_signed = false;
    let is_executable = is_authenticode_binary_path(path);

    unsafe {
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
            dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0),
            dwUIContext: WINTRUST_DATA_UICONTEXT(0),
            pSignatureSettings: std::ptr::null_mut(),
            Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
        };

        let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(
            windows::Win32::Foundation::HWND::default(),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        );

        raw_hresult = result as u32;
        status = classify_wintrust_result(path, result);

        // Catalog-signed system files (conhost.exe, notepad.exe, cmd.exe, etc.)
        // carry no embedded PKCS#7 signature. WinVerifyTrust with WTD_CHOICE_FILE
        // returns TRUST_E_NOSIGNATURE for them even though they are signed via the
        // Windows Catalog database. Fall back to catalog membership verification
        // so Microsoft-signed OS binaries are not misclassified as unsigned.
        if status == SignatureStatus::Unsigned && is_authenticode_binary_path(path) {
            if let Some(catalog_signer) = verify_catalog_signature(&path_wide) {
                is_catalog_signed = true;
                status = SignatureStatus::Trusted;
                signer_name = Some(catalog_signer);
                raw_hresult = ERROR_SUCCESS.0 as u32;
            }
        }

        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            windows::Win32::Foundation::HWND::default(),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        );

        // Signer extraction is metadata only. Do not use CryptQueryObject failure
        // as proof of "unsigned", because catalog-signed system files may not have
        // embedded PKCS#7 signer data.
        if let Ok(name) = get_signer_name_from_file(&path_wide) {
            is_attached_signed = true;
            signer_name = Some(name);
            if matches!(
                status,
                SignatureStatus::Unsigned | SignatureStatus::VerificationFailed
            ) {
                status = SignatureStatus::SignedUntrusted;
            }
        }
    }

    let is_trusted = status == SignatureStatus::Trusted;
    let no_signature = status == SignatureStatus::Unsigned;
    let invalid_signature = status == SignatureStatus::Invalid;
    let verification_failed = status == SignatureStatus::VerificationFailed;
    let is_signed = matches!(
        status,
        SignatureStatus::Trusted | SignatureStatus::SignedUntrusted | SignatureStatus::Invalid
    );
    let signature_status_issues = matches!(
        status,
        SignatureStatus::SignedUntrusted
            | SignatureStatus::Invalid
            | SignatureStatus::VerificationFailed
    );
    let status_text = status_text_for(status, raw_hresult);

    SignatureInfo {
        is_trusted,
        is_signed,
        signer_name,
        status,
        status_text,
        raw_hresult,
        verification_failed,
        no_signature,
        signature_status_issues,
        invalid_signature,
        is_executable,
        is_catalog_signed,
        is_attached_signed,
    }
}

/// Verifies a file against the Windows Catalog database (CatRoot .cat files).
///
/// Returns the catalog signer name (e.g. "Microsoft Windows Production PCA 2011")
/// when the file hash matches a member of a valid, trusted catalog, or `None`
/// when the file is not catalog-signed.
unsafe fn verify_catalog_signature(path_wide: &[u16]) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
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

unsafe fn get_signer_name_from_file(path_wide: &[u16]) -> Result<String, ()> {
    unsafe {
        let mut msg_handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut store_handle: HCERTSTORE = HCERTSTORE::default();
        let mut context_ptr: *mut std::ffi::c_void = std::ptr::null_mut();

        let query_res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_wide.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store_handle),
            Some(&mut msg_handle),
            Some(&mut context_ptr as *mut _ as _),
        );

        if query_res.ok().is_ok() {
            let p_cert_context = CertEnumCertificatesInStore(store_handle, None);

            if !p_cert_context.is_null() {
                let mut name_buf: [u16; 256] = [0; 256];
                let chars_written = CertGetNameStringW(
                    p_cert_context,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut name_buf),
                );

                let result = if chars_written > 1 {
                    let len = (chars_written - 1) as usize;
                    let name = String::from_utf16_lossy(&name_buf[..len]);
                    Ok(name)
                } else {
                    Err(())
                };

                let _ = CertFreeCertificateContext(Some(p_cert_context));
                let _ = CertCloseStore(store_handle, 0);
                let _ = CryptMsgClose(Some(msg_handle as *const std::ffi::c_void));

                return result;
            }

            let _ = CertCloseStore(store_handle, 0);
            let _ = CryptMsgClose(Some(msg_handle as *const std::ffi::c_void));
        }

        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::verify_signature;
    use std::path::PathBuf;

    fn win_dir() -> PathBuf {
        PathBuf::from(std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string()))
    }

    #[test]
    fn catalog_signed_system_file_is_trusted() {
        let path = win_dir().join("System32\\conhost.exe");
        if !path.exists() {
            eprintln!("skip: {} not present", path.display());
            return;
        }
        let info = verify_signature(&path);
        assert!(
            info.is_trusted,
            "conhost.exe (catalog-signed) should be trusted, got status={:?} text={:?} hresult=0x{:08X}",
            info.status, info.status_text, info.raw_hresult
        );
        assert!(
            info.signer_name
                .as_deref()
                .map(|s| s.contains("Microsoft"))
                .unwrap_or(false),
            "signer should be Microsoft, got {:?}",
            info.signer_name
        );
    }

    #[test]
    fn embedded_signed_system_file_is_trusted() {
        let path = win_dir().join("explorer.exe");
        if !path.exists() {
            eprintln!("skip: {} not present", path.display());
            return;
        }
        let info = verify_signature(&path);
        assert!(
            info.is_trusted,
            "explorer.exe should be trusted, got {:?}",
            info.status
        );
    }

    #[test]
    fn unsigned_file_is_not_trusted() {
        let path = win_dir().join("System32\\drivers\\etc\\hosts");
        if !path.exists() {
            eprintln!("skip: {} not present", path.display());
            return;
        }
        let info = verify_signature(&path);
        assert!(
            !info.is_trusted,
            "hosts file must not be trusted, got {:?}",
            info.status
        );
    }
}
