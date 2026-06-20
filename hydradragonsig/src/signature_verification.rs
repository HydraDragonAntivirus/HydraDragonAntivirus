#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, PWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::ERROR_SUCCESS;
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptQueryObject, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
    CERT_QUERY_OBJECT_FILE, HCERTSTORE,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_UICONTEXT,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
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

#[cfg(target_os = "windows")]
const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;
#[cfg(target_os = "windows")]
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001u32 as i32;
#[cfg(target_os = "windows")]
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003u32 as i32;
#[cfg(target_os = "windows")]
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B_0109u32 as i32;
#[cfg(target_os = "windows")]
const TRUST_E_BAD_DIGEST: i32 = 0x8009_6010u32 as i32;
#[cfg(target_os = "windows")]
const TRUST_E_CERT_SIGNATURE: i32 = 0x8009_6004u32 as i32;

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
        }
    }
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
pub fn verify_signature(path: &Path) -> SignatureInfo {
    let raw_hresult: u32;
    let mut status: SignatureStatus;
    let mut signer_name = None;

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
            windows::Win32::Foundation::HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        );

        raw_hresult = result as u32;
        status = classify_wintrust_result(path, result);

        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            windows::Win32::Foundation::HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        );

        // Signer extraction is metadata only. Do not use CryptQueryObject failure
        // as proof of "unsigned", because catalog-signed system files may not have
        // embedded PKCS#7 signer data.
        if let Ok(name) = get_signer_name_from_file(&path_wide) {
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
    }
}

#[cfg(target_os = "windows")]
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

        if query_res.is_ok() {
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
                let _ = CertCloseStore(Some(store_handle), 0);
                let _ = CryptMsgClose(Some(msg_handle as *const std::ffi::c_void));

                return result;
            }

            let _ = CertCloseStore(Some(store_handle), 0);
            let _ = CryptMsgClose(Some(msg_handle as *const std::ffi::c_void));
        }

        Err(())
    }
}

#[cfg(not(target_os = "windows"))]
pub fn verify_signature(_path: &Path) -> SignatureInfo {
    SignatureInfo::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_verify_known_signed_file() {
        let paths = [
            "C:\\Windows\\System32\\notepad.exe",
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\kernel32.dll",
        ];

        let mut found_signed = false;
        for p in paths {
            let path = Path::new(p);
            if path.exists() {
                let info = verify_signature(path);
                if info.is_trusted {
                    found_signed = true;
                    assert!(
                        info.is_signed,
                        "Trusted file should also be marked as signed"
                    );
                    assert_eq!(info.status, SignatureStatus::Trusted);
                    assert!(!info.verification_failed);
                    break;
                }
            }
        }
        assert!(
            found_signed,
            "At least one system file should be verified as signed!"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_verify_unsigned_file() {
        let path = Path::new(file!());
        let info = verify_signature(path);
        assert!(!info.is_trusted, "Source code file should NOT be trusted!");
        assert!(!info.is_signed, "Source code file should NOT be signed!");
        assert_eq!(info.status, SignatureStatus::Unsigned);
        assert!(info.no_signature);
        assert!(!info.verification_failed);
    }
}
