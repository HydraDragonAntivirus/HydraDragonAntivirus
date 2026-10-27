//! System-inspection conditions implemented over the host OS:
//!
//! * `registry_key` / `registry_value` - hive lookups with recursive subtree
//!   walks.
//! * `clsid` - COM `CLSID` registration and `InprocServer32` checks.
//! * `hosts_entry` - hosts-file hijack lines.
//! * `sector_pattern` - raw disk/volume sector content (`MBR` / `VBR` rules).
//!
//! Reads are read-only; removals live in [`crate::rules::remediation`]. On
//! non-Windows hosts these conditions never match, with a one-time warning.

use crate::rules::glob::glob_match;
use digest::Digest;
use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// %VAR% expansion (registry keys, hosts paths, remediation targets)
// ---------------------------------------------------------------------------

const VAR_ALIASES: &[(&str, &str)] = &[
    ("SYSDIR", "%SystemRoot%\\System32"),
    ("SYSWOW", "%SystemRoot%\\SysWOW64"),
    ("PROGRAMFILES", "%ProgramFiles%"),
    ("COMMONFILES", "%CommonProgramFiles%"),
    ("MYDOCS", "%USERPROFILE%\\Documents"),
    ("DESKTOP", "%USERPROFILE%\\Desktop"),
    ("STARTUP", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
];

const BRACKET_ALIASES: &[(&str, &str)] = &[
    ("<$PROFILE>", "%USERPROFILE%"),
    ("<$WINDIR>", "%SystemRoot%"),
    ("<$SYSDIR>", "%SystemRoot%\\System32"),
    ("<$SYSWOW>", "%SystemRoot%\\SysWOW64"),
    ("<$APPDATA>", "%APPDATA%"),
    ("<$LOCALAPPDATA>", "%LOCALAPPDATA%"),
    ("<$LOCALSETTINGS>", "%LOCALAPPDATA%"),
    ("<$PROGRAMFILES>", "%ProgramFiles%"),
    ("<$COMMONPROGRAMFILES>", "%CommonProgramFiles%"),
    ("<$DESKTOP>", "%USERPROFILE%\\Desktop"),
    ("<$COMMONDESKTOP>", "%PUBLIC%\\Desktop"),
    ("<$PERSONAL>", "%USERPROFILE%\\Documents"),
    ("<$STARTUP>", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    ("<$COMMONSTARTUP>", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    ("<$PROGRAMS>", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs"),
    ("<$COMMONPROGRAMS>", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs"),
    ("<$TEMP>", "%TEMP%"),
    ("<$TEMPLATES>", "%APPDATA%\\Microsoft\\Windows\\Templates"),
    ("<$SYSDRIVE>", "%SystemDrive%"),
];

/// `%VAR%` and `<$VAR>` replacement using the process environment, plus standard
/// path aliases that have no environment twin. Unknown variables are kept
/// verbatim so globs stay deterministic.
pub fn expand_windows_vars(text: &str) -> String {
    let mut base = text.to_string();
    if base.contains("<$") {
        for (tag, replacement) in BRACKET_ALIASES {
            if base.to_ascii_uppercase().contains(tag) {
                base = replace_case_insensitive(&base, tag, replacement);
            }
        }
    }
    for (alias, value) in VAR_ALIASES {
        let needle = format!("%{alias}%");
        if base.to_ascii_uppercase().contains(&needle) {
            base = replace_case_insensitive(&base, &needle, value);
        }
    }
    let mut out = String::with_capacity(base.len());
    let mut iter = base.chars().peekable();
    while let Some(c) = iter.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut name = String::new();
        let closed = loop {
            match iter.next() {
                Some('%') => break true,
                Some(ch) if name.len() < 64 => name.push(ch),
                Some(_) => break false,
                None => break false,
            }
        };
        match (closed, name.as_str()) {
            (true, "") => out.push('%'),
            (true, var) => match std::env::var(var) {
                Ok(value) if !value.is_empty() => out.push_str(&value),
                _ => {
                    out.push('%');
                    out.push_str(var);
                    out.push('%');
                }
            },
            (false, suffix) => {
                out.push('%');
                out.push_str(suffix);
            }
        }
    }
    out
}

fn replace_case_insensitive(haystack: &str, needle_upper: &str, replacement: &str) -> String {
    let upper = haystack.to_ascii_uppercase();
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0usize;
    while let Some(rel) = upper[last..].find(needle_upper) {
        let start = last + rel;
        let end = start + needle_upper.len();
        out.push_str(&haystack[last..start]);
        out.push_str(replacement);
        last = end;
    }
    out.push_str(&haystack[last..]);
    out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

pub fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(md5::Md5::digest(bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

pub fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Deterministic memoization of per-condition queries: evaluating the same rule
/// over thousands of files would otherwise repeat the same syscall.
fn cached(key: String, compute: impl FnOnce() -> Option<String>) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let guard = match cache.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(hit) = guard.get(&key) {
            return hit.clone();
        }
    }
    let computed = compute();
    let mut guard = match cache.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.len() > 4096 {
        guard.clear();
    }
    guard.insert(key, computed.clone());
    computed
}

pub(crate) fn truncate_preview(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        text.to_string()
    } else {
        format!(
            "{}...",
            text.get(..cap)
                .map(str::to_string)
                .unwrap_or_else(|| text.to_string())
        )
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn unsupported_warning(cond: &'static str) {
    static WARNED: OnceLock<Mutex<HashMap<&'static str, ()>>> = OnceLock::new();
    let map = WARNED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.insert(cond, ()).is_some() {
        return;
    }
    log::warn!(
        "condition `{cond}` is Windows-only and never matches ({os})",
        os = std::env::consts::OS
    );
}

/// Printable version of one registry value's raw bytes.
pub fn data_preview(kind: u32, raw: &[u8]) -> String {
    match kind {
        1 | 2 => utf16_text(raw, false),
        7 => utf16_text(raw, true),
        4 => {
            let mut bytes = [0u8; 4];
            let n = raw.len().min(4);
            bytes[..n].copy_from_slice(&raw[..n]);
            u32::from_le_bytes(bytes).to_string()
        }
        5 => {
            let mut bytes = [0u8; 4];
            let n = raw.len().min(4);
            bytes[..n].copy_from_slice(&raw[..n]);
            u32::from_be_bytes(bytes).to_string()
        }
        11 => {
            let mut bytes = [0u8; 8];
            let n = raw.len().min(8);
            bytes[..n].copy_from_slice(&raw[..n]);
            u64::from_le_bytes(bytes).to_string()
        }
        _ => format!("binary {} bytes: {}", raw.len(), truncate_preview(&lower_hex(&raw[..raw.len().min(64)]), 128)),
    }
}

fn utf16_text(raw: &[u8], multi: bool) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let joined = String::from_utf16_lossy(&units);
    if multi {
        joined.split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("; ")
    } else {
        joined.trim_end_matches('\0').replace('\0', " ")
    }
}

fn is_text_kind(kind: u32) -> bool {
    kind == 1 || kind == 2 || kind == 7
}

fn is_number_kind(kind: u32) -> bool {
    kind == 4 || kind == 5 || kind == 11
}

// ---------------------------------------------------------------------------
// Hosts-file conditions
// ---------------------------------------------------------------------------

/// Parse hosts lines against `ip_glob` (glob over the dotted quad) and
/// `host_regex` (regex over every hostname). Deterministic and testable;
/// the file wrappers live in `hosts_entry_evidence`.
pub fn hosts_scan(
    text: &str,
    ip_glob: Option<&str>,
    host_regex: Option<&Regex>,
) -> Option<String> {
    if ip_glob.is_none() && host_regex.is_none() {
        return None;
    }
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let mut matched_host: Option<String> = None;
        for host in parts {
            if let Some(regex) = host_regex {
                if regex.is_match(host) {
                    matched_host = Some(host.to_string());
                    break;
                }
            }
        }
        let ip_ok = ip_glob.map(|glob| glob_match(glob, ip)).unwrap_or(true);
        let host_ok = if host_regex.is_some() {
            matched_host.is_some()
        } else {
            true
        };
        if ip_ok && host_ok {
            return Some(format!("hosts entry: {line}"));
        }
    }
    None
}

/// `hosts_entry` condition: read the Windows hosts file and run the scan.
pub fn hosts_entry_evidence(ip_glob: Option<&str>, host_regex: Option<&Regex>) -> Option<String> {
    let cache_key = format!(
        "hosts|{ip_glob:?}|{}",
        host_regex.map(|r| r.as_str().to_string()).unwrap_or_default()
    );
    cached(cache_key, || {
        #[cfg(not(windows))]
        {
            unsupported_warning("hosts_entry");
            None
        }
        #[cfg(windows)]
        {
            let hosts_path = expand_windows_vars("%SYSDIR%\\drivers\\etc\\hosts");
            let Ok(text) = std::fs::read_to_string(&hosts_path) else {
                return None;
            };
            hosts_scan(&text, ip_glob, host_regex)
        }
    })
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Hive selectors, independent of live key handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveSel {
    LocalMachine,
    CurrentUser,
    ClassesRoot,
    Users,
    CurrentConfig,
}

const MAX_TREE_DEPTH: usize = 8;
const MAX_HITS: usize = 256;
const MAX_VALUES_PER_KEY: usize = 1000;
const MAX_SUBKEYS_PER_KEY: usize = 2000;

/// Split `HKLM\software\...` into (label, hive, rest).
fn split_hive(spec: &str) -> Option<(&'static str, HiveSel, &str)> {
    let (head, rest) = match spec.split_once('\\') {
        Some(pair) => pair,
        None => (spec, ""),
    };
    match head.trim().to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some(("HKLM", HiveSel::LocalMachine, rest)),
        "HKCU" | "HKEY_CURRENT_USER" => Some(("HKCU", HiveSel::CurrentUser, rest)),
        "HKCR" | "HKEY_CLASSES_ROOT" => Some(("HKCR", HiveSel::ClassesRoot, rest)),
        "HKU" | "HKEY_USERS" => Some(("HKU", HiveSel::Users, rest)),
        "HKCC" | "HKEY_CURRENT_CONFIG" => Some(("HKCC", HiveSel::CurrentConfig, rest)),
        _ => None,
    }
}

/// One registry hit: key path, value name and a printable preview of the data.
#[derive(Debug, Clone)]
pub struct RegHit {
    pub key: String,
    pub value: String,
    pub data_preview: String,
}

/// Full registry query spec used by `registry_key` / `registry_value`.
#[derive(Debug, Clone, Default)]
pub struct RegistryQuery {
    /// `HKLM\Software\...`; globs allowed in any component.
    pub key: String,
    pub recursive: bool,
    /// Value-name regex (`None` = any).
    pub value_regex: Option<String>,
    /// Text regex against REG_SZ / EXPAND / MULTI (DWORD/QWORD as text).
    pub data_regex: Option<String>,
    /// Hex glob over REG_BINARY data (must be lower-case hex).
    pub data_hex: Option<String>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    /// At least this many hits (default 1).
    pub min: usize,
}

#[cfg(windows)]
mod win {
    use super::{MAX_SUBKEYS_PER_KEY, MAX_VALUES_PER_KEY};

    pub type HK = isize;

    pub const HK_LOCAL_MACHINE: HK = -2_147_483_646;
    pub const HK_CURRENT_USER: HK = -2_147_483_647;
    pub const HK_CLASSES_ROOT: HK = -2_147_483_648;
    pub const HK_USERS: HK = -2_147_483_645;
    pub const HK_CURRENT_CONFIG: HK = -2_147_483_643;

    const ERROR_SUCCESS: i32 = 0;
    const KEY_READ: u32 = 0x20019;
    const MAX_DATA: usize = 65_536;

    // link to Win32:
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(key: HK, sub_key: *const u16, options: u32, sam: u32, result: *mut HK) -> i32;
        fn RegCloseKey(key: HK) -> i32;
        fn RegEnumKeyExW(
            key: HK,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            class_name: *mut u16,
            class_len: *mut u32,
            last_write_time: *mut u64,
        ) -> i32;
        fn RegEnumValueW(
            key: HK,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            reg_type: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> i32;
    }

    fn zbuf(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn hive_of(sel: super::HiveSel) -> (HK, &'static str) {
        match sel {
            super::HiveSel::LocalMachine => (HK_LOCAL_MACHINE, "HKLM"),
            super::HiveSel::CurrentUser => (HK_CURRENT_USER, "HKCU"),
            super::HiveSel::ClassesRoot => (HK_CLASSES_ROOT, "HKCR"),
            super::HiveSel::Users => (HK_USERS, "HKU"),
            super::HiveSel::CurrentConfig => (HK_CURRENT_CONFIG, "HKCC"),
        }
    }

    fn from16(buf: &[u16]) -> String {
        String::from_utf16_lossy(buf).trim_end_matches('\0').to_string()
    }

    pub fn open(hive: HK, sub: &str) -> Option<HK> {
        let mut result = 0 as HK;
        let status = unsafe {
            if sub.is_empty() {
                RegOpenKeyExW(hive, std::ptr::null(), 0, KEY_READ, &mut result)
            } else {
                let z = zbuf(sub);
                RegOpenKeyExW(hive, z.as_ptr(), 0, KEY_READ, &mut result)
            }
        };
        (status == ERROR_SUCCESS).then_some(result)
    }

    pub fn close(key: HK) {
        unsafe { RegCloseKey(key) };
    }

    pub fn children(key: HK) -> Vec<String> {
        let mut names = Vec::new();
        let mut buffer = [0u16; 256];
        let mut index = 0u32;
        loop {
            let mut len = buffer.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    buffer.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status != ERROR_SUCCESS {
                break;
            }
            names.push(from16(&buffer[..len as usize]));
            index += 1;
            if index as usize >= MAX_SUBKEYS_PER_KEY {
                break;
            }
        }
        names
    }

    /// (value name, type, raw bytes). Oversized values are truncated.
    pub fn values(key: HK) -> Vec<(String, u32, Vec<u8>)> {
        let mut buffer = vec![0u8; MAX_DATA];
        let mut name_buf = [0u16; 256];
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name_len = name_buf.len() as u32;
            let mut data_len = buffer.len() as u32;
            let mut kind = 0u32;
            let status = unsafe {
                RegEnumValueW(
                    key,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut kind,
                    buffer.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if status != ERROR_SUCCESS {
                break;
            }
            let value = from16(&name_buf[..name_len as usize]);
            out.push((value, kind, buffer[..data_len as usize].to_vec()));
            index += 1;
            if index as usize >= MAX_VALUES_PER_KEY {
                break;
            }
        }
        out
    }

    pub fn exists(hive: HK, sub: &str) -> bool {
        let Some(key) = open(hive, sub) else { return false };
        close(key);
        true
    }
}

/// Resolve a key spec with glob components down to concrete leaf paths.
/// Each leaf path is guaranteed to exist. Aborts early when nothing matches.
#[cfg(windows)]
fn resolve_leaves(spec: &str) -> Option<(&'static str, win::HK, Vec<String>)> {
    let expanded = expand_windows_vars(spec);
    let (label, sel, rest) = split_hive(&expanded)?;
    let (hive, _) = win::hive_of(sel);
    if rest.is_empty() {
        return Some((label, hive, vec![String::new()]));
    }
    let mut frontier: Vec<String> = vec![String::new()];
    for component in rest.split('\\').filter(|c| !c.is_empty()) {
        let mut next = Vec::new();
        let has_glob = component.chars().any(|c| c == '*' || c == '?' || c == '#');
        for path in &frontier {
            if has_glob {
                let Some(handle) = win::open(hive, path) else { continue };
                let kids = win::children(handle);
                win::close(handle);
                for child in kids {
                    if glob_match(component, &child) {
                        next.push(join_path(path, &child));
                    }
                }
            } else {
                let candidate = join_path(path, component);
                if win::exists(hive, &candidate) {
                    next.push(candidate);
                }
            }
        }
        frontier = next;
        if frontier.len() > 64 {
            frontier.truncate(64);
        }
        if frontier.is_empty() {
            return Some((label, hive, Vec::new()));
        }
    }
    Some((label, hive, frontier))
}

#[cfg(not(windows))]
fn resolve_leaves(_spec: &str) -> Option<(&'static str, (), Vec<String>)> {
    None
}

fn join_path(prefix: &str, component: &str) -> String {
    if prefix.is_empty() {
        component.to_string()
    } else {
        format!("{prefix}\\{component}")
    }
}

/// Filter one key's raw values; hits appended to `out`.
fn eval_registry_values(
    leaf_label: &str,
    values: Vec<(String, u32, Vec<u8>)>,
    query: &RegistryQuery,
    value_filter: Option<&Regex>,
    data_filter: Option<&Regex>,
    out: &mut Vec<RegHit>,
) {
    for (name, kind, raw) in values {
        if out.len() >= MAX_HITS {
            return;
        }
        if let Some(flag) = value_filter {
            if !flag.is_match(&name) {
                continue;
            }
        }
        if let Some(hex_glob) = &query.data_hex {
            if !is_binary_kind(kind) || !glob_match(hex_glob, &lower_hex(&raw)) {
                continue;
            }
        }
        if let Some(data_re) = data_filter {
            if is_binary_kind(kind) {
                continue;
            }
            let text = data_preview(kind, &raw);
            if !data_re.is_match(&text) {
                continue;
            }
        }
        if let Some(want) = &query.md5 {
            if md5_hex(&raw) != want.to_ascii_lowercase() {
                continue;
            }
        }
        if let Some(want) = &query.sha256 {
            if sha256_hex(&raw) != want.to_ascii_lowercase() {
                continue;
            }
        }
        out.push(RegHit {
            key: leaf_label.to_string(),
            value: name,
            data_preview: data_preview(kind, &raw),
        });
    }
}

fn is_binary_kind(kind: u32) -> bool {
    !is_text_kind(kind) && !is_number_kind(kind)
}

/// `registry_value` condition: recursive subtree walk matching the filters and
/// collecting at least `min` (default 1) hits.
pub fn registry_value_evidence(query: &RegistryQuery) -> Option<String> {
    let cache_key = format!(
        "regvalue|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{}",
        query.key, query.recursive, query.value_regex, query.data_regex,
        query.data_hex, query.md5, query.sha256, query.min
    );
    cached(cache_key, || registry_value_evidence_uncached(query))
}

#[cfg(not(windows))]
fn registry_value_evidence_uncached(_query: &RegistryQuery) -> Option<String> {
    unsupported_warning("registry_value");
    None
}

#[cfg(windows)]
fn registry_value_evidence_uncached(query: &RegistryQuery) -> Option<String> {
    let Some((label, hive, leaves)) = resolve_leaves(&query.key) else {
        return None;
    };
    if leaves.is_empty() {
        return None;
    }
    let value_filter = query.value_regex.as_deref().and_then(|p| Regex::new(p).ok());
    let data_filter = query.data_regex.as_deref().and_then(|p| Regex::new(p).ok());
    let min = query.min.max(1);
    let mut hits: Vec<RegHit> = Vec::new();
    for leaf in &leaves {
        let Some(handle) = win::open(hive, leaf) else { continue };
        let own = win::values(handle);
        win::close(handle);
        eval_registry_values(
            &format!("{label}\\{leaf}"),
            own,
            query,
            value_filter.as_ref(),
            data_filter.as_ref(),
            &mut hits,
        );
        if query.recursive {
            walk_tree(
                hive,
                leaf,
                label,
                query,
                value_filter.as_ref(),
                data_filter.as_ref(),
                &mut hits,
                0,
            );
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    if hits.len() < min {
        return None;
    }
    let summary: Vec<String> = hits
        .iter()
        .take(3)
        .map(|hit| format!("{}: {} = {}", hit.key, hit.value, hit.data_preview))
        .collect();
    Some(format!(
        "registry_value matched {} hit(s): {}",
        hits.len(),
        summary.join("; ")
    ))
}

/// `registry_key` condition: descend the key path and confirm it exists;
/// `value_pattern` additionally searches the (sub)tree for a matching value
/// name.
pub fn registry_key_evidence(key: &str, recursive: bool, value_pattern: Option<&str>) -> Option<String> {
    let cache_key = format!("regkey|{key}|{recursive}|{value_pattern:?}");
    cached(cache_key, || {
        #[cfg(not(windows))]
        {
            unsupported_warning("registry_key");
            None
        }
        #[cfg(windows)]
        {
            let Some((label, hive, leaves)) = resolve_leaves(key) else {
                return None;
            };
            if leaves.is_empty() {
                return None;
            }
            let Some(pattern) = value_pattern.filter(|p| !p.is_empty()) else {
                // Existence was already proven by resolve_leaves.
                return Some(truncate_preview(&format!("registry_key {label}\\{} exists", leaves[0]), 200));
            };
            let Ok(regex) = Regex::new(pattern) else {
                return None;
            };
            let mut found: Option<(String, String)> = None;
            for leaf in leaves.iter().take(64) {
                let Some(handle) = win::open(hive, leaf) else { continue };
                let values = win::values(handle);
                win::close(handle);
                for (name, kind, raw) in values {
                    if regex.is_match(&name) {
                        found = Some((name, data_preview(kind, &raw)));
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
                if recursive {
                    let mut hits = Vec::new();
                    walk_tree(
                        hive,
                        leaf,
                        label,
                        &RegistryQuery { recursive: true, ..RegistryQuery::default() },
                        Some(&regex),
                        None,
                        &mut hits,
                        0,
                    );
                    if let Some(first) = hits.first() {
                        found = Some((first.value.clone(), first.data_preview.clone()));
                        break;
                    }
                }
            }
            found.map(|(value, preview)| {
                truncate_preview(
                    &format!("registry_key {label}\\{}: value {value} = {preview}", leaves[0]),
                    220,
                )
            })
        }
    })
}

/// Depth-first recursive-walk collector (bounded).
#[cfg(windows)]
fn walk_tree(
    hive: win::HK,
    leaf: &str,
    label: &str,
    query: &RegistryQuery,
    value_filter: Option<&Regex>,
    data_filter: Option<&Regex>,
    out: &mut Vec<RegHit>,
    depth: usize,
) {
    if out.len() >= MAX_HITS || depth > MAX_TREE_DEPTH {
        return;
    }
    let Some(handle) = win::open(hive, leaf) else { return };
    let kids = win::children(handle);
    win::close(handle);
    for child in kids {
        let path = join_path(leaf, &child);
        let Some(handle) = win::open(hive, &path) else { continue };
        let own = win::values(handle);
        win::close(handle);
        eval_registry_values(&format!("{label}\\{path}"), own, query, value_filter, data_filter, out);
        if out.len() >= MAX_HITS {
            return;
        }
        walk_tree(hive, &path, label, query, value_filter, data_filter, out, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Clsid (GUID) condition
// ---------------------------------------------------------------------------

/// `clsid` condition: the CLSID keys exist; optionally the InprocServer32
/// default value must match `inproc_regex`.
pub fn clsid_evidence(guids: &[String], inproc_regex: Option<&str>) -> Option<String> {
    let cache_key = format!("clsid|{:?}|{inproc_regex:?}", guids.iter().take(64).collect::<Vec<_>>());
    cached(cache_key, || {
        #[cfg(not(windows))]
        {
            unsupported_warning("clsid");
            None
        }
        #[cfg(windows)]
        {
            let regex = inproc_regex.filter(|p| !p.is_empty()).and_then(|p| Regex::new(p).ok());
            let mut hits: Vec<(String, String)> = Vec::new();
            for guid in guids.iter().take(256) {
                let bare = guid.trim().trim_start_matches('{').trim_end_matches('}');
                if bare.is_empty() {
                    continue;
                }
                let braced = format!("{{{bare}}}");
                for spec in [
                    format!("HKCR\\CLSID\\{braced}\\InprocServer32"),
                    format!("HKLM\\SOFTWARE\\Classes\\CLSID\\{braced}\\InprocServer32"),
                ] {
                    let Some((_, hive, leaves)) = resolve_leaves(&spec) else {
                        continue;
                    };
                    if leaves.is_empty() {
                        continue;
                    }
                    let Some(handle) = win::open(hive, &leaves[0]) else { continue };
                    let values = win::values(handle);
                    win::close(handle);
                    match &regex {
                        Some(re) => {
                            if let Some((_, kind, raw)) = values.iter().find(|(name, _, _)| name.is_empty()) {
                                let text = data_preview(*kind, raw);
                                if re.is_match(&text) {
                                    hits.push((bare.to_string(), text));
                                    break;
                                }
                            }
                        }
                        None => {
                            hits.push((bare.to_string(), String::new()));
                            break;
                        }
                    }
                }
            }
            if hits.is_empty() {
                return None;
            }
            let detail = hits
                .iter()
                .take(3)
                .map(|(guid, text)| {
                    format!(
                        "{{{guid}}} {}",
                        truncate_preview(text, 100)
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            Some(format!("clsid {} registered: {}", hits.len(), detail))
        }
    })
}

// ---------------------------------------------------------------------------
// Raw sector conditions (MBR / VBR bootkit rules)
// ---------------------------------------------------------------------------

/// Which device + geometry to read.
#[derive(Debug, Clone, Default)]
pub struct SectorQuery {
    /// `physical0`, `volume:C` or a raw device path (`\\.\PhysicalDrive0`,
    /// `\\.\C:`).
    pub device: String,
    pub lba: u64,
    /// Sectors to read (default 1, capped at 64 for memory safety).
    pub count: u32,
}

/// Normalize the `device` spec to a Windows device path.
fn sector_device_path(spec: &str) -> Option<String> {
    let lower = spec.trim().to_ascii_lowercase();
    if lower.starts_with("\\\\.\\") {
        return Some(spec.trim().to_string());
    }
    if let Some(rest) = lower.strip_prefix("physical") {
        let digits = rest.trim().trim_start_matches(':').trim().to_string();
        if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
            return Some(format!("\\\\.\\PhysicalDrive{digits}"));
        }
    }
    if let Some(rest) = lower.strip_prefix("volume") {
        let tail = rest.trim_start_matches([':', ' ']).trim();
        let mut it = tail.chars();
        if let (Some(c), None) = (it.next(), it.next()) {
            if c.is_ascii_alphabetic() {
                return Some(format!("\\\\.\\{}:", c.to_ascii_uppercase()));
            }
        }
    }
    None
}

/// Evaluate a `sector_pattern` condition. Read-only; needs the privilege the
/// raw device handle asks for (usually admin), else it never matches.
pub fn sector_pattern_evidence(
    query: &SectorQuery,
    patterns: &[String],
    min: usize,
    excludes: &[String],
) -> Option<String> {
    let device = sector_device_path(&query.device)?;
    let cache_key = format!(
        "sector|{device}|{}|{}|{}|{}|{}",
        query.lba,
        query.count,
        patterns.join(","),
        min,
        excludes.join(",")
    );
    cached(cache_key, || {
        #[cfg(not(windows))]
        {
            unsupported_warning("sector_pattern");
            None
        }
        #[cfg(windows)]
        {
            let Some(bytes) = read_sectors(&device, query.lba, query.count) else {
                return None;
            };
            compare_sectors(&device, query, &bytes, patterns, min, excludes)
        }
    })
}

/// The pattern check is platform-independent once the sectors are read.
pub(crate) fn compare_sectors(
    device: &str,
    query: &SectorQuery,
    bytes: &[u8],
    patterns: &[String],
    min: usize,
    excludes: &[String],
) -> Option<String> {
    for excl in excludes {
        if let Some(units) = crate::rules::pe_anchor::compile(excl)
            && crate::rules::pe_anchor::find_in_range(&units, bytes).is_some()
        {
            return None;
        }
    }
    let needed = min.max(1);
    let mut matched = 0usize;
    let mut detail: Vec<String> = Vec::new();
    for pattern in patterns {
        let Some(units) = crate::rules::pe_anchor::compile(pattern) else {
            continue;
        };
        let count = crate::rules::pe_anchor::count_in_range(&units, bytes);
        if count > 0 {
            matched += 1;
            if detail.len() < 3 {
                let at = crate::rules::pe_anchor::find_in_range(&units, bytes);
                detail.push(format!("{pattern} x{count} at 0x{:x} ({})", at.unwrap_or(0), device));
            }
        }
        if matched >= needed {
            break;
        }
    }
    (matched >= needed).then(|| {
        format!(
            "sector {} lba={}: pattern(s) {}",
            device, query.lba, detail.join(", ")
        )
    })
}

#[cfg(windows)]
fn read_sectors(device: &str, lba: u64, count: u32) -> Option<Vec<u8>> {
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: isize = -1;
    const FILE_BEGIN: u32 = 0;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            security: *mut core::ffi::c_void,
            disposition: u32,
            flags: u32,
            template: isize,
        ) -> isize;
        fn ReadFile(
            handle: isize,
            buffer: *mut u8,
            len: u32,
            read: *mut u32,
            overlapped: *mut core::ffi::c_void,
        ) -> i32;
        fn SetFilePointerEx(handle: isize, to_move: i64, new_ptr: *mut i64, method: u32) -> i32;
        fn CloseHandle(handle: isize) -> i32;
    }

    let count = count.clamp(1, 64);
    let total = (count as usize).saturating_mul(512);
    if total == 0 {
        return None;
    }
    // Sector-aligned buffer, needed for raw device handles.
    let mut storage = vec![0u8; total + 512];
    let base = storage.as_mut_ptr() as usize;
    let aligned_off = ((base + 511) & !511) - base;
    let aligned = &mut storage[aligned_off..aligned_off + total];

    let path: Vec<u16> = device.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        log::debug!("sector_pattern: cannot open {device} (need elevation?)");
        return None;
    }
    let mut new_ptr = 0i64;
    let moved = unsafe { SetFilePointerEx(handle, (lba as usize).saturating_mul(512usize) as i64, &mut new_ptr, FILE_BEGIN) };
    if moved == 0 {
        unsafe { CloseHandle(handle) };
        return None;
    }
    let mut filled = 0usize;
    while filled < total {
        let mut read = 0u32;
        let len = (total - filled).min(u32::MAX as usize) as u32;
        let ok = unsafe { ReadFile(handle, aligned[filled..total].as_mut_ptr(), len, &mut read, std::ptr::null_mut()) };
        if ok == 0 || read == 0 {
            unsafe { CloseHandle(handle) };
            if filled == 0 {
                return None;
            }
            break;
        }
        filled += read as usize;
    }
    _ = unsafe { CloseHandle(handle) };
    _ = new_ptr;
    (filled > 0).then(|| aligned[..filled].to_vec())
}

// ---------------------------------------------------------------------------
// File attributes & file timestamp conditions
// ---------------------------------------------------------------------------

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

pub fn attr_flag_value(name: &str) -> Option<u32> {
    match name.trim().to_ascii_lowercase().as_str() {
        "a" | "archive" => Some(FILE_ATTRIBUTE_ARCHIVE),
        "d" | "dir" | "directory" => Some(FILE_ATTRIBUTE_DIRECTORY),
        "h" | "hidden" => Some(FILE_ATTRIBUTE_HIDDEN),
        "l" | "link" | "reparse" | "reparse_point" => Some(FILE_ATTRIBUTE_REPARSE_POINT),
        "r" | "readonly" | "read_only" => Some(FILE_ATTRIBUTE_READONLY),
        "s" | "system" => Some(FILE_ATTRIBUTE_SYSTEM),
        _ => None,
    }
}

/// Parse a compact attribute specification like `"A+D-H-L-R-S-"` into `(req_mask, forbid_mask)`.
pub fn parse_attr_spec(spec: &str) -> Option<(u32, u32)> {
    let mut req = 0u32;
    let mut forbid = 0u32;
    let bytes = spec.trim().as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        let code = bytes[idx] as char;
        let op = bytes[idx + 1] as char;
        let bit = match code.to_ascii_uppercase() {
            'A' => FILE_ATTRIBUTE_ARCHIVE,
            'D' => FILE_ATTRIBUTE_DIRECTORY,
            'H' => FILE_ATTRIBUTE_HIDDEN,
            'L' => FILE_ATTRIBUTE_REPARSE_POINT,
            'R' => FILE_ATTRIBUTE_READONLY,
            'S' => FILE_ATTRIBUTE_SYSTEM,
            _ => return None,
        };
        match op {
            '+' => req |= bit,
            '-' => forbid |= bit,
            _ => return None,
        }
        idx += 2;
    }
    Some((req, forbid))
}

pub fn check_attr_mask(
    attrs: u32,
    spec: Option<&str>,
    required: &[String],
    forbidden: &[String],
) -> Option<String> {
    let mut req_mask = 0u32;
    let mut forbid_mask = 0u32;
    if let Some(s) = spec {
        let (r, f) = parse_attr_spec(s)?;
        req_mask |= r;
        forbid_mask |= f;
    }
    for name in required {
        req_mask |= attr_flag_value(name)?;
    }
    for name in forbidden {
        forbid_mask |= attr_flag_value(name)?;
    }
    if req_mask == 0 && forbid_mask == 0 {
        return None;
    }
    if (attrs & req_mask) != req_mask || (attrs & forbid_mask) != 0 {
        return None;
    }
    Some(format!(
        "file_attributes attrs=0x{attrs:04x} (required=0x{req_mask:04x}, forbidden=0x{forbid_mask:04x})"
    ))
}

pub fn file_attributes_evidence(
    path: &std::path::Path,
    spec: Option<&str>,
    required: &[String],
    forbidden: &[String],
) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(windows)]
    let attrs = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes()
    };
    #[cfg(not(windows))]
    let attrs = {
        let mut mask = FILE_ATTRIBUTE_ARCHIVE;
        if meta.is_dir() {
            mask |= FILE_ATTRIBUTE_DIRECTORY;
        }
        if meta.permissions().readonly() {
            mask |= FILE_ATTRIBUTE_READONLY;
        }
        mask
    };
    check_attr_mask(attrs, spec, required, forbidden)
}

/// Compute the 32-bit packed DOS date/time word (`((year-1980)<<25)|...`).
pub fn dos_packed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> u32 {
    let y = (year - 1980).clamp(0, 127) as u32;
    let date = (y << 9) | ((month & 0x0F) << 5) | (day & 0x1F);
    let time = ((hour & 0x1F) << 11) | ((minute & 0x3F) << 5) | ((second / 2) & 0x1F);
    (date << 16) | time
}

fn parse_datetime_utc(text: &str) -> Option<i64> {
    use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
    let trimmed = text.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&ndt).timestamp());
    }
    if let Ok(nd) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(0, 0, 0)?;
        return Some(Utc.from_utc_datetime(&ndt).timestamp());
    }
    None
}

pub fn file_timestamp_evidence(
    path: &std::path::Path,
    equals: Option<&str>,
    after: Option<&str>,
    before: Option<&str>,
    raw_hex: Option<&str>,
    age_days_min: Option<u64>,
    age_days_max: Option<u64>,
) -> Option<String> {
    use chrono::{Datelike, Timelike};
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    let dt_utc: chrono::DateTime<chrono::Utc> = mtime.into();
    let dt_local: chrono::DateTime<chrono::Local> = mtime.into();
    let unix_secs = dt_utc.timestamp();

    let fmt_utc = dt_utc.format("%Y-%m-%d %H:%M:%S").to_string();
    let fmt_local = dt_local.format("%Y-%m-%d %H:%M:%S").to_string();

    if let Some(eq) = equals {
        let eq_trim = eq.trim();
        let matches_str = fmt_utc == eq_trim || fmt_local == eq_trim;
        let matches_ts = parse_datetime_utc(eq_trim).is_some_and(|want| want == unix_secs);
        if !matches_str && !matches_ts {
            return None;
        }
    }
    if let Some(after_s) = after {
        let min_ts = parse_datetime_utc(after_s)?;
        if unix_secs < min_ts {
            return None;
        }
    }
    if let Some(before_s) = before {
        let max_ts = parse_datetime_utc(before_s)?;
        if unix_secs > max_ts {
            return None;
        }
    }
    if let Some(hex_str) = raw_hex {
        let clean = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
        let want = u32::from_str_radix(clean, 16).ok()?;
        let dos_utc = dos_packed_timestamp(
            dt_utc.year(),
            dt_utc.month(),
            dt_utc.day(),
            dt_utc.hour(),
            dt_utc.minute(),
            dt_utc.second(),
        );
        let dos_local = dos_packed_timestamp(
            dt_local.year(),
            dt_local.month(),
            dt_local.day(),
            dt_local.hour(),
            dt_local.minute(),
            dt_local.second(),
        );
        let unix_u32 = unix_secs as u32;
        if want != dos_utc && want != dos_local && want != unix_u32 {
            return None;
        }
    }
    if age_days_min.is_some() || age_days_max.is_some() {
        let elapsed_secs = std::time::SystemTime::now()
            .duration_since(mtime)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age_days = elapsed_secs / 86_400;
        if age_days_min.is_some_and(|min| age_days < min) {
            return None;
        }
        if age_days_max.is_some_and(|max| age_days > max) {
            return None;
        }
    }
    Some(format!("file_timestamp mtime={fmt_utc} (unix={unix_secs})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_composition() {
        assert!(glob_match("123.123.*", "123.123.3.4"));
        assert!(!glob_match("10.*", "192.168.0.1"));
    }

    #[test]
    fn attr_spec_and_dos_timestamp() {
        // 2026-10-27 14:32:46 -> DOS packed 0x5D5B7417
        assert_eq!(dos_packed_timestamp(2026, 10, 27, 14, 32, 46), 0x5D5B_7417);
        assert!(check_attr_mask(FILE_ATTRIBUTE_ARCHIVE, Some("A+D-H-L-R-S-"), &[], &[]).is_some());
        assert!(check_attr_mask(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN, Some("A+D-H-L-R-S-"), &[], &[]).is_none());
    }

    #[test]
    fn hosts_file_line_parse() {
        let text = "127.0.0.1 localhost\n123.123.123.123 ads.google.ge\n";
        assert!(hosts_scan(text, Some("123.123.*"), None).is_some());
        assert!(hosts_scan(text, Some("10.*"), None).is_none());
        let regex = Regex::new("google").unwrap();
        assert!(hosts_scan(text, None, Some(&regex)).is_some());
        assert!(hosts_scan(text, None, Some(&Regex::new("bing").unwrap())).is_none());
    }

    #[test]
    fn expand_vars_always_safe() {
        // Unknown variables survive verbatim.
        assert_eq!(expand_windows_vars("%NOPEVARX%"), "%NOPEVARX%");
        assert_eq!(expand_windows_vars("%NOPEVARX%dog"), "%NOPEVARX%dog");
        assert_eq!(expand_windows_vars("a%%b"), "a%b");
        let expanded = expand_windows_vars("%DESKTOP%\\x");
        assert!(expanded.ends_with("\\x") && !expanded.contains('%'), "got {expanded}");
        let sys = expand_windows_vars("%SYSDIR%");
        assert!(sys.ends_with("System32") || sys.ends_with("SYSWOW"), "got {sys}");
        let profile = expand_windows_vars("<$PROFILE>\\Downloads\\client_built.exe");
        assert!(profile.ends_with("\\Downloads\\client_built.exe") && !profile.contains("<$"));
    }

    #[test]
    fn hive_split() {
        let (label, sel, rest) = split_hive("HKLM\\Software\\Microsoft").unwrap();
        assert_eq!(label, "HKLM");
        assert_eq!(sel, HiveSel::LocalMachine);
        assert_eq!(rest, "Software\\Microsoft");
        assert!(split_hive("\\\\nope\\x").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn registry_literal_probe() {
        // Windows always reports ProductName on live systems.
        let query = RegistryQuery {
            key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".into(),
            value_regex: Some("ProductName".into()),
            data_regex: Some(".+".into()),
            min: 1,
            ..Default::default()
        };
        assert!(registry_value_evidence(&query).is_some());
        assert!(registry_key_evidence("HKLM\\SOFTWARE", false, None).is_some());
    }
}
