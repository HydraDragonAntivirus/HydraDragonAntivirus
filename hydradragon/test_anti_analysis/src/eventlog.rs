// src/eventlog.rs
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, RegCloseKey, RegOpenKeyExW, KEY_READ,
};

#[derive(Debug, Clone, Default)]
pub struct EventLogChecker;

impl EventLogChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if an event log provider is registered on the system.
    /// This is a strong indicator for technologies like Hyper-V that register their own providers.
    pub fn provider_exists(&self, provider_name: &str) -> bool {
        let path = format!(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{}",
            provider_name
        );
        self.check_registry_key_exists(&path)
    }

    fn check_registry_key_exists(&self, path: &str) -> bool {
        // Root key to query
        let hkey = HKEY_LOCAL_MACHINE;

        // Prepare an "empty" handle to receive the opened key
        let mut subkey_handle = HKEY::default();

        // Convert Rust string to null-terminated wide string (UTF-16)
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let path_pcwstr = PCWSTR(wide_path.as_ptr());

        // Call RegOpenKeyExW:
        // uloptions is Option<u32> -> use Some(0) (or None)
        // samdesired is KEY_READ (do NOT use `.0`)
        let result = unsafe {
            RegOpenKeyExW(
                hkey,
                path_pcwstr,
                Some(0),
                KEY_READ,
                &mut subkey_handle,
            )
        };

        // If we opened it successfully, close the handle and return true
        if result.is_ok() {
            // Safety: RegCloseKey expects a valid handle. We opened it successfully,
            // so close it here. Ignore the returned error code if any.
            let _ = unsafe { RegCloseKey(subkey_handle) };
            true
        } else {
            false
        }
    }
}
