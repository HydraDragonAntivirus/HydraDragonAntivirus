use std::path::Path;

use serde::Serialize;
use winreg::enums::*;
use winreg::RegKey;

use hydradragonstatic::trusted_signers::PuaRegistryList;

#[derive(Debug, Clone, Serialize)]
pub struct RegistryEntry {
    pub hive: String,
    pub path: String,
    pub value_name: String,
    pub value_data: String,
    pub pua_match: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryScanResult {
    pub entries: Vec<RegistryEntry>,
    pub total_scanned: u32,
    pub threats_found: u32,
}

pub struct RegistryScanner {
    pua_list: PuaRegistryList,
}

static PERSISTENCE_PATHS_HKLM: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"Software\Microsoft\Active Setup\Installed Components",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Execute Hooks",
    r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    r"Software\Microsoft\Windows\CurrentVersion\App Paths",
    r"System\CurrentControlSet\Services",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Internet Explorer\SearchScopes",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Stats",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
];

static PERSISTENCE_PATHS_HKCU: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Active Setup\Installed Components",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"Software\Microsoft\Internet Explorer\SearchScopes",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Ext\Stats",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
];

impl RegistryScanner {
    pub fn new(pua_list: PuaRegistryList) -> Self {
        Self { pua_list }
    }

    pub fn load_reglist<P: AsRef<Path>>(path: P) -> Self {
        Self {
            pua_list: PuaRegistryList::load(path),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pua_list.is_empty()
    }

    pub fn scan(&self) -> RegistryScanResult {
        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for &rel_path in PERSISTENCE_PATHS_HKLM {
            self.scan_subkey(&hklm, "HKLM", rel_path, &mut entries, &mut seen);
        }

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for &rel_path in PERSISTENCE_PATHS_HKCU {
            self.scan_subkey(&hkcu, "HKCU", rel_path, &mut entries, &mut seen);
        }

        let threats = entries.iter().filter(|e| e.pua_match).count() as u32;

        RegistryScanResult {
            total_scanned: entries.len() as u32,
            threats_found: threats,
            entries,
        }
    }

    fn scan_subkey(
        &self,
        hive: &RegKey,
        hive_name: &str,
        rel_path: &str,
        entries: &mut Vec<RegistryEntry>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        let subkey = match hive.open_subkey_with_flags(rel_path, KEY_READ) {
            Ok(k) => k,
            Err(_) => return,
        };

        let val_iter = subkey.enum_values();

        for value_result in val_iter {
            let (name, value) = match value_result {
                Ok(v) => v,
                Err(_) => continue,
            };

            let data_str = match value.vtype {
                RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
                    let s = String::from_utf8_lossy(&value.bytes).to_string();
                    s.trim_end_matches('\0').to_string()
                }
                RegType::REG_MULTI_SZ => {
                    let s = String::from_utf8_lossy(&value.bytes).to_string();
                    s.trim_end_matches('\0').replace('\0', "; ")
                }
                RegType::REG_DWORD => {
                    if value.bytes.len() >= 4 {
                        format!(
                            "{}",
                            u32::from_le_bytes([
                                value.bytes[0],
                                value.bytes[1],
                                value.bytes[2],
                                value.bytes[3]
                            ])
                        )
                    } else {
                        String::from("(invalid dword)")
                    }
                }
                _ => format!("({} bytes)", value.bytes.len()),
            };

            let sub_path = format!("{}\\{}", rel_path, name);
            let dedup_key = format!("{}|{}|{}", hive_name, rel_path, name);
            if !seen.insert(dedup_key) {
                continue;
            }

            let pua_match = self.pua_list.is_pua(hive_name, &sub_path);

            let detail = if pua_match {
                "PUA registry pattern match".to_string()
            } else if !data_str.starts_with('(') && !data_str.is_empty() {
                format!("value: {}", truncate_str(&data_str, 120))
            } else {
                "present".to_string()
            };

            entries.push(RegistryEntry {
                hive: hive_name.to_string(),
                path: sub_path,
                value_name: name,
                value_data: data_str,
                pua_match,
                detail,
            });
        }
    }
}

impl Default for RegistryScanner {
    fn default() -> Self {
        Self {
            pua_list: PuaRegistryList::default(),
        }
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
