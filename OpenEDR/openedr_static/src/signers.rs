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
pub fn verify_authenticode(path: &Path) -> (bool, bool, Option<String>, String) {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{ERROR_SUCCESS, HWND};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_UICONTEXT,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptQueryObject, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, HCERTSTORE,
    };

    if !path.is_file() {
        return (false, false, None, "File not found".to_string());
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

    let is_trusted = result == ERROR_SUCCESS.0 as i32;

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

    let is_signed = is_trusted || signer_name.is_some();
    let status = if is_trusted {
        "trusted".to_string()
    } else if is_signed {
        "signed_untrusted".to_string()
    } else {
        "unsigned".to_string()
    };

    (is_signed, is_trusted, signer_name, status)
}

#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path) -> (bool, bool, Option<String>, String) {
    (false, false, None, "unsupported_platform".to_string())
}
