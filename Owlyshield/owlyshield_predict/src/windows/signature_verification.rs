use std::path::Path;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, 
    WTD_CHOICE_FILE, WTD_STATEACTION_VERIFY,
    WTD_STATEACTION_CLOSE, WTD_UI_NONE, WINTRUST_FILE_INFO,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_UICONTEXT,
};
use windows::Win32::Security::Cryptography::{
    CryptQueryObject, CERT_QUERY_OBJECT_FILE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, HCERTSTORE, CertCloseStore, CryptMsgClose,
    CertFreeCertificateContext, CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CertEnumCertificatesInStore,
};

pub struct SignatureInfo {
    pub is_trusted: bool,
    pub signer_name: Option<String>,
}

pub fn verify_signature(path: &Path) -> SignatureInfo {
    let is_trusted;
    let mut signer_name = None;

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
            hFile: INVALID_HANDLE_VALUE,
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
            dwProvFlags: windows::Win32::Security::WinTrust::WTD_SAFER_FLAG, 
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
            &mut win_trust_data as *mut _ as *mut std::ffi::c_void
        );

        is_trusted = result == ERROR_SUCCESS.0 as i32;


        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
         let _ = WinVerifyTrust(
            windows::Win32::Foundation::HWND(0), 
            &mut action_guid, 
            &mut win_trust_data as *mut _ as *mut std::ffi::c_void
        );

        // --- 2. Extract Signer Name (CryptQueryObject) ---
        if is_trusted {
             if let Ok(name) = get_signer_name_from_file(&path_wide) {
                 signer_name = Some(name);
             }
        }
    }

    SignatureInfo {
        is_trusted,
        signer_name,
    }
}

unsafe fn get_signer_name_from_file(path_wide: &[u16]) -> Result<String, ()> {
    // HCRYPTMSG is *mut c_void in older windows-rs
    let mut msg_handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut store_handle: HCERTSTORE = HCERTSTORE::default();
    let mut context_ptr: *mut std::ffi::c_void = std::ptr::null_mut();

    // Retrieve Certificate Store from file
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
        Some(&mut context_ptr as *mut _ as *mut *mut std::ffi::c_void),
    );

    if query_res.as_bool() {
        let p_cert_context;
        
        // Get the first certificate: Start with None.
        p_cert_context = CertEnumCertificatesInStore(store_handle, None);
        
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
            "C:\\Windows\\System32\\kernel32.dll"
        ];
        
        let mut found_signed = false;
        for p in paths {
            let path = Path::new(p);
            if path.exists() {
                let info = verify_signature(path);
                if info.is_trusted {
                    found_signed = true;
                    assert!(info.signer_name.is_some(), "Should extract signer name from signed file {}", p);
                    if let Some(name) = info.signer_name {
                         assert!(name.contains("Microsoft"), "Signer of {} should be Microsoft, got {}", p, name);
                    }
                    break;
                }
            }
        }
        assert!(found_signed, "At least one system file should be verified as signed!");
    }

    #[test]
    fn test_verify_unsigned_file() {
        // This test file itself (the source code) is definitely not signed
        let path = Path::new(file!()); 
        let info = verify_signature(path);
        // We assert it is NOT trusted
        assert!(!info.is_trusted, "Source code file should NOT be trusted!");
    }
}
