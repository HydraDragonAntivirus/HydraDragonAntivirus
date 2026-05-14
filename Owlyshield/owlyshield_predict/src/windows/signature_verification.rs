use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Security::Cryptography::{
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CertCloseStore,
    CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose,
    CryptQueryObject, HCERTSTORE,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::core::{PCWSTR, PWSTR};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Trusted,
    SignedUntrusted,
    Unsigned,
    VerificationFailed,
}

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;

pub struct SignatureInfo {
    pub is_trusted: bool,
    pub is_signed: bool, // True only when signing evidence was actually found.
    pub signer_name: Option<String>,
    pub status: SignatureStatus,
    pub verification_failed: bool,
}

pub fn verify_signature(path: &Path) -> SignatureInfo {
    let is_trusted;
    let mut is_signed = false;
    let mut signer_name = None;
    let mut status = SignatureStatus::VerificationFailed;
    let mut verification_failed = true;

    unsafe {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // --- 1. Verify Trust (WinVerifyTrust) ---
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
            windows::Win32::Foundation::HWND(0),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        );

        is_trusted = result == ERROR_SUCCESS.0 as i32;
        if is_trusted {
            is_signed = true;
            status = SignatureStatus::Trusted;
            verification_failed = false;
        } else if result == TRUST_E_NOSIGNATURE {
            // WinVerifyTrust positively reported that no embedded/catalog signature
            // is present. This is the only failure case we classify as Unsigned.
            status = SignatureStatus::Unsigned;
            verification_failed = false;
        }

        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            windows::Win32::Foundation::HWND(0),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        );

        // --- 2. Check if file has ANY signature (even if not trusted) ---
        // Try to extract certificate/signer info regardless of trust status
        if let Ok(name) = get_signer_name_from_file(&path_wide) {
            is_signed = true;
            signer_name = Some(name);
            if !is_trusted {
                // Embedded signing evidence exists, but WinVerifyTrust did not trust it.
                // This overrides Unsigned if CryptQueryObject can read a signer.
                status = SignatureStatus::SignedUntrusted;
                verification_failed = false;
            }
        }
    }

    SignatureInfo {
        is_trusted,
        is_signed,
        signer_name,
        status,
        verification_failed,
    }
}

unsafe fn get_signer_name_from_file(path_wide: &[u16]) -> Result<String, ()> {
    unsafe {
        // HCRYPTMSG is *mut c_void in older windows-rs
        let mut msg_handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut store_handle: HCERTSTORE = HCERTSTORE::default();
        let mut context_ptr: *mut std::ffi::c_void = std::ptr::null_mut();

        // Retrieve Certificate Store from file
        let query_res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_wide.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None, // pdwMsgAndCertEncodingType
            None, // pdwContentType
            None, // pdwFormatType
            Some(&mut store_handle),
            Some(&mut msg_handle),
            Some(&mut context_ptr as *mut _ as _),
        );

        if query_res.as_bool() {
            // Get the first certificate: Start with None.
            let p_cert_context = CertEnumCertificatesInStore(store_handle, None);

            if !p_cert_context.is_null() {
                // Extract Name
                let mut name_buf: [u16; 256] = [0; 256];

                // CertGetNameStringW(context, type, flags, typeparam, string_ptr) -> len
                // Windows-rs 0.48 uses Option<&mut [u16]> for the buffer and handles length internally.
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

                // Free context.
                CertFreeCertificateContext(Some(p_cert_context));
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
    use super::*;
    use std::path::Path;

    #[test]
    fn test_verify_known_signed_file() {
        // Notepad is usually signed, but explorer.exe is definitely signed by Microsoft
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
                    // Catalog-signed Windows files may verify as trusted without an embedded
                    // signer certificate that CryptQueryObject can extract.
                    if let Some(name) = info.signer_name {
                        assert!(
                            name.contains("Microsoft"),
                            "Signer of {} should be Microsoft, got {}",
                            p,
                            name
                        );
                    }
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
    fn test_verify_unsigned_file() {
        // This test file itself (the source code) is definitely not signed
        let path = Path::new(file!());
        let info = verify_signature(path);
        // We assert it is NOT trusted and NOT signed, and that the no-signature
        // result is classified as unsigned rather than verification failure.
        assert!(!info.is_trusted, "Source code file should NOT be trusted!");
        assert!(!info.is_signed, "Source code file should NOT be signed!");
        assert_eq!(info.status, SignatureStatus::Unsigned);
        assert!(!info.verification_failed, "Unsigned source file should be unsigned, not verification failed");
    }
}
