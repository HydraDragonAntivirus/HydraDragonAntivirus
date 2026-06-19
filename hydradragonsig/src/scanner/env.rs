use crate::models::{DecodedString, EnvHit, StringHit};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static ENV_REF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(%[A-Z0-9_]{2,}%|\$env:[A-Z0-9_]+|getenv\([^)]+\)|GetEnvironmentVariable[A-Za-z]*|USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|COMSPEC|WINDIR|SYSTEMROOT|PROCESSOR_IDENTIFIER|NUMBER_OF_PROCESSORS|USERNAME|USERDOMAIN)").unwrap()
});

static SANDBOX_ENV_NAMES: &[&str] = &[
    "SANDBOX",
    "VBOX_INSTALL_PATH",
    "VBOX_MSI_INSTALL_PATH",
    "VMWARE_TOOLS",
    "PROCESSOR_IDENTIFIER",
    "NUMBER_OF_PROCESSORS",
    "COMPUTERNAME",
    "USERNAME",
    "USERDOMAIN",
    "USERDNSDOMAIN",
];

static SUSPICIOUS_ENV_VALUES: &[&str] = &[
    "vbox",
    "virtualbox",
    "vmware",
    "qemu",
    "xen",
    "sandbox",
    "maltest",
    "analysis",
    "cuckoo",
    "joebox",
    "any.run",
    "triage",
];

pub fn scan_environment(strings: &[StringHit], decoded: &[DecodedString]) -> Vec<EnvHit> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();

    for s in strings
        .iter()
        .map(|h| h.value.as_str())
        .chain(decoded.iter().map(|d| d.decoded.as_str()))
    {
        if ENV_REF_RE.is_match(s) {
            push(
                &mut hits,
                &mut seen,
                "static_reference",
                Some(s),
                "environment variable reference in file strings",
            );
        }
        let lower = s.to_ascii_lowercase();
        if lower.contains("getenvironmentvariable")
            || lower.contains("environ")
            || lower.contains("expandenvironmentstrings")
        {
            push(
                &mut hits,
                &mut seen,
                "env_api",
                Some(s),
                "environment API usage string",
            );
        }
    }

    for name in SANDBOX_ENV_NAMES {
        if let Ok(value) = std::env::var(name) {
            let low = value.to_ascii_lowercase();
            if SUSPICIOUS_ENV_VALUES
                .iter()
                .any(|needle| low.contains(needle))
            {
                push(
                    &mut hits,
                    &mut seen,
                    name,
                    Some(&value),
                    "current host environment contains sandbox/VM-like marker",
                );
            }
        }
    }

    hits
}

fn push(
    hits: &mut Vec<EnvHit>,
    seen: &mut HashSet<String>,
    name: &str,
    value: Option<&str>,
    reason: &str,
) {
    let key = format!("{}:{:?}:{}", name, value, reason);
    if seen.insert(key) {
        hits.push(EnvHit {
            name: name.to_string(),
            value: value.map(|v| crate::utils::text::truncate_middle(v, 256)),
            reason: reason.to_string(),
        });
    }
}
