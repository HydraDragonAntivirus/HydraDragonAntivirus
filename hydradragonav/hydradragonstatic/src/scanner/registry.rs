use crate::models::{DecodedString, PeInfo, RegistryHit, StringHit};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static REG_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?ix)(HKEY_(CURRENT_USER|LOCAL_MACHINE|CLASSES_ROOT|USERS)|HKCU|HKLM|\\Registry\\Machine|\\Registry\\User|Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices|Policies|Explorer|Winlogon)|Image\ File\ Execution\ Options|AppInit_DLLs|Shell\ Service\ Object\ DelayLoad|Services\\[^\\]+|WMI|Classes\\ms-settings|CurrentControlSet\\Services)").unwrap()
});

static REG_API_NAMES: &[&str] = &[
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegDeleteKeyA",
    "RegDeleteKeyW",
    "RegDeleteValueA",
    "RegDeleteValueW",
    "NtOpenKey",
    "NtSetValueKey",
    "NtCreateKey",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtEnumerateKey",
];

pub fn scan_registry_indicators(
    strings: &[StringHit],
    decoded: &[DecodedString],
    pe: Option<&PeInfo>,
) -> Vec<RegistryHit> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();

    for s in strings {
        if REG_KEY_RE.is_match(&s.value) {
            push(
                &mut hits,
                &mut seen,
                &s.value,
                "registry key/value persistence or reconnaissance pattern",
            );
        }
    }

    for s in decoded {
        if REG_KEY_RE.is_match(&s.decoded) {
            push(
                &mut hits,
                &mut seen,
                &s.decoded,
                "decoded registry key/value persistence or reconnaissance pattern",
            );
        }
    }

    if let Some(pe) = pe {
        for import in &pe.imports {
            if REG_API_NAMES.iter().any(|api| import.ends_with(api)) {
                push(&mut hits, &mut seen, import, "Windows registry API import");
            }
        }
    }

    hits
}

fn push(hits: &mut Vec<RegistryHit>, seen: &mut HashSet<String>, key_or_value: &str, reason: &str) {
    let value = crate::utils::text::truncate_middle(key_or_value, 256);
    let key = format!("{}:{}", value, reason);
    if seen.insert(key) {
        hits.push(RegistryHit {
            key_or_value: value,
            reason: reason.to_string(),
        });
    }
}
