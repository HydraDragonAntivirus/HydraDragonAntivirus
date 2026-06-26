use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Serialize;
use winreg::enums::*;
use winreg::RegKey;

use crate::file_pum_scanner;
use hydradragonsig::rules::RuleSet;
use hydradragonsig::trusted_signers::PuaRegistryList;

#[derive(Debug, Clone, Serialize)]
pub struct RegistryEntry {
    pub hive: String,
    pub path: String,
    pub value_name: String,
    pub value_data: String,
    pub pua_match: bool,
    pub static_match: bool,
    /// True when the match is a PUM (Potentially Unwanted Modification) —
    /// a registry setting that weakens security or disables tools.
    pub pum: bool,
    /// The safe/default value that should be restored to undo this PUM.
    /// For example DisableTaskMgr=1 should be reverted to "0".
    pub expected_reverted_value: Option<String>,
    pub threat_name: Option<String>,
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
    rules: Option<RuleSet>,
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

/// PUM (Potentially Unwanted Modification) registry paths — policy and security
/// settings that malware commonly alters to weaken the system.
static PUM_PATHS_HKLM: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate",
    r"Software\Policies\Microsoft\Windows\WindowsUpdate",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Windows\Safer",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments",
    r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows Defender",
    r"Software\Microsoft\Windows Defender\Real-Time Protection",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    r"System\CurrentControlSet\Control\Lsa",
    r"System\CurrentControlSet\Control\Lsa\MSV1_0",
    r"System\CurrentControlSet\Services\Tcpip\Parameters",
];

static PUM_PATHS_HKCU: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
];

impl RegistryScanner {
    pub fn new(pua_list: PuaRegistryList, rules: Option<RuleSet>) -> Self {
        Self { pua_list, rules }
    }

    pub fn load<P: AsRef<Path>>(reglist_path: P, rules_dir: Option<&Path>) -> Self {
        let pua_list = PuaRegistryList::load(reglist_path);
        let rules = rules_dir.and_then(|dir| load_hydradragonsig_rules(dir));
        Self { pua_list, rules }
    }

    pub fn is_empty(&self) -> bool {
        self.pua_list.is_empty()
    }

    pub fn scan(&self) -> RegistryScanResult {
        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for &rel_path in PERSISTENCE_PATHS_HKLM {
            self.scan_subkey(&hklm, "HKLM", rel_path, false, &mut entries, &mut seen);
        }
        for &rel_path in PUM_PATHS_HKLM {
            self.scan_subkey(&hklm, "HKLM", rel_path, true, &mut entries, &mut seen);
        }

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for &rel_path in PERSISTENCE_PATHS_HKCU {
            self.scan_subkey(&hkcu, "HKCU", rel_path, false, &mut entries, &mut seen);
        }
        for &rel_path in PUM_PATHS_HKCU {
            self.scan_subkey(&hkcu, "HKCU", rel_path, true, &mut entries, &mut seen);
        }

        self.scan_file_pum_rules(&mut entries, &mut seen);

        let threats = entries
            .iter()
            .filter(|e| e.pua_match || e.static_match)
            .count() as u32;

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
        _is_pum_path: bool,
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

            let (static_match, static_threat, is_pum, expected_reverted_value) =
                self.run_static_scan(hive_name, rel_path, &name, &value.bytes);

            let threat_name = static_threat.or_else(|| {
                if pua_match {
                    Some("PUA registry pattern".into())
                } else {
                    None
                }
            });

            let detail = match (pua_match, static_match) {
                (true, true) => format!(
                    "PUA + static rule match: {}",
                    threat_name.as_deref().unwrap_or("unknown")
                ),
                (true, false) => "PUA registry pattern match".to_string(),
                (false, true) => format!(
                    "static rule match: {}",
                    threat_name.as_deref().unwrap_or("unknown")
                ),
                (false, false) => {
                    if !data_str.starts_with('(') && !data_str.is_empty() {
                        format!("value: {}", truncate_str(&data_str, 120))
                    } else {
                        "present".to_string()
                    }
                }
            };

            entries.push(RegistryEntry {
                hive: hive_name.to_string(),
                path: sub_path,
                value_name: name,
                value_data: data_str,
                pua_match,
                static_match,
                pum: is_pum,
                expected_reverted_value,
                threat_name,
                detail,
            });
        }
    }

    fn run_static_scan(
        &self,
        hive_name: &str,
        rel_path: &str,
        value_name: &str,
        value_bytes: &[u8],
    ) -> (bool, Option<String>, bool, Option<String>) {
        let rules = match &self.rules {
            Some(r) => r,
            None => return (false, None, false, None),
        };

        let ctx = hydradragonsig::models::RegistryScanContext {
            key: format!("{}\\{}", hive_name, rel_path),
            value_name: Some(value_name.to_string()),
            value_data: Some(value_bytes.to_vec()),
        };

        match hydradragonsig::scan_registry_key(
            &ctx,
            rules,
            &hydradragonsig::ScanOptions::default(),
        ) {
            Ok(report) => {
                let detected = matches!(
                    report.verdict,
                    hydradragonsig::models::Verdict::Malware
                        | hydradragonsig::models::Verdict::Suspicious
                        | hydradragonsig::models::Verdict::Pua
                );
                // Check if any finding family matches a known PUM pattern.
                let is_pum = report.findings.iter().any(|f| {
                    f.family.as_deref().map_or(false, |fam| {
                        fam.starts_with("PUM.")
                    })
                });
                let expected = report.findings.first().and_then(|f| {
                    f.expected_reverted_value.clone()
                });
                (detected, report.threat_name, is_pum, expected)
            }
            Err(_) => (false, None, false, None),
        }
    }
    /// Load and apply file PUM rules from `file_pum_rules.yaml`.
    fn scan_file_pum_rules(
        &self,
        entries: &mut Vec<RegistryEntry>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        let rules_dir = std::env::var("HYDRADRAGONSIG_RULES_DIR")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("hydradragonsig_rules")))
            });
        let Some(dir) = rules_dir else { return };
        let rules_file = dir.join("file_pum_rules.yaml");
        let rules = match file_pum_scanner::load_rules(&rules_file) {
            Ok(r) => r,
            Err(_) => return,
        };
        let file_hits = file_pum_scanner::scan_file_pums(&rules, seen);
        entries.extend(file_hits);
    }
}

impl Default for RegistryScanner {
    fn default() -> Self {
        Self {
            pua_list: PuaRegistryList::default(),
            rules: None,
        }
    }
}

static HDS_RULES: OnceLock<Option<RuleSet>> = OnceLock::new();

fn load_hydradragonsig_rules(rules_dir: &Path) -> Option<RuleSet> {
    HDS_RULES
        .get_or_init(|| {
            let reg_file = rules_dir.join("reg_rules.yaml");
            if reg_file.exists() {
                if let Ok(rs) = RuleSet::from_yaml_file(&reg_file) {
                    return Some(rs);
                }
            }
            None
        })
        .clone()
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
