use crate::models::{PeInfo, PeSectionInfo};
use crate::utils::entropy::byte_entropy;
use std::collections::HashSet;

/// Function names counted by `suspicious_import_count` (compared without regard to case).
pub const SUSPICIOUS_APIS: &[&str] = &[
    // Process injection / memory of other processes
    "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "GetThreadContext",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection", "NtWriteVirtualMemory",
    "NtAllocateVirtualMemory", "OpenProcess", "SuspendThread", "ResumeThread",
    // Hooks and input capture
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState",
    "RegisterRawInputDevices", "GetClipboardData",
    // Credentials, tokens, privileges
    "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW", "OpenProcessToken",
    "DuplicateTokenEx", "ImpersonateLoggedOnUser", "CredEnumerateA", "CredEnumerateW",
    "CryptUnprotectData", "LsaRetrievePrivateData", "MiniDumpWriteDump",
    // Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "NtSetInformationThread", "OutputDebugStringA",
    // Services, drivers and persistence
    "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW", "NtLoadDriver", "ZwLoadDriver",
    // Download and execute
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "InternetOpenUrlA", "InternetOpenUrlW",
];

/// Mandiant / pefile import hash: MD5 of the comma-joined `dll.function` pairs in import
/// order, lower case, `.dll` / `.ocx` / `.sys` cut off the DLL name, `ordN` imports named
/// where pefile names them. `None` without imports. The one implementation: the Multron
/// server's analyzer and imphash signatures call this too.
pub fn imphash<'a>(imports: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<String> {
    use digest::Digest;
    let mut parts = Vec::new();
    for (dll, func) in imports {
        let lower = dll.to_ascii_lowercase();
        let base = match lower.rsplit_once('.') {
            Some((b, e)) if ["dll", "ocx", "sys"].contains(&e) => b.to_string(),
            _ => lower.clone(),
        };
        let func = match func.strip_prefix("ord") {
            Some(n) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
                let ord: u32 = n.parse().unwrap_or(0);
                ordinal_name(&base, ord).map(str::to_string).unwrap_or_else(|| format!("ord{ord}"))
            }
            _ => func.to_ascii_lowercase(),
        };
        parts.push(format!("{base}.{}", func.to_ascii_lowercase()));
    }
    if parts.is_empty() {
        return None;
    }
    Some(hex::encode(md5::Md5::digest(parts.join(",").as_bytes())))
}

/// Ordinal imports pefile names for the imphash (the common ones).
fn ordinal_name(dll: &str, ord: u32) -> Option<&'static str> {
    match (dll, ord) {
        ("ws2_32" | "wsock32", 1) => Some("accept"),
        ("ws2_32" | "wsock32", 2) => Some("bind"),
        ("ws2_32" | "wsock32", 3) => Some("closesocket"),
        ("ws2_32" | "wsock32", 4) => Some("connect"),
        ("ws2_32" | "wsock32", 9) => Some("htons"),
        ("ws2_32" | "wsock32", 11) => Some("inet_addr"),
        ("ws2_32" | "wsock32", 13) => Some("listen"),
        ("ws2_32" | "wsock32", 16) => Some("recv"),
        ("ws2_32" | "wsock32", 19) => Some("send"),
        ("ws2_32" | "wsock32", 23) => Some("socket"),
        ("ws2_32" | "wsock32", 52) => Some("gethostbyname"),
        ("ws2_32" | "wsock32", 115) => Some("wsastartup"),
        ("ws2_32" | "wsock32", 116) => Some("wsacleanup"),
        ("oleaut32", 2) => Some("sysallocstring"),
        ("oleaut32", 6) => Some("sysfreestring"),
        ("oleaut32", 7) => Some("sysstringlen"),
        _ => None,
    }
}

pub fn scan_pe(bytes: &[u8]) -> Option<PeInfo> {
    let pe = pefile_rs::PE::parse(bytes).ok()?;

    let mut imports: Vec<String> = Vec::new();
    for dir in &pe.imports {
        for sym in &dir.entries {
            let name = sym.name.clone().unwrap_or_else(|| {
                sym.ordinal.map(|o| format!("ord{o}")).unwrap_or_default()
            });
            if name.is_empty() {
                continue;
            }
            imports.push(format!("{}!{}", dir.dll, name));
        }
    }

    let dlls: Vec<String> = imports
        .iter()
        .filter_map(|s| s.split_once('!').map(|(dll, _)| dll.to_ascii_lowercase()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // Imports often used for injection, credential theft, anti-analysis or
    // persistence. Common in malware but also in legitimate tools: a count, not a verdict.
    let suspicious_imports: Vec<String> = imports
        .iter()
        .filter(|imp| {
            let func = imp.rsplit_once('!').map(|(_, f)| f).unwrap_or(imp);
            SUSPICIOUS_APIS.iter().any(|api| func.eq_ignore_ascii_case(api))
        })
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let mut sections = Vec::new();
    let mut suspicious_sections = Vec::new();
    for section in &pe.sections {
        // The name ends at the first NUL; bytes after it (left by some tools and
        // infectors, e.g. `UPX1\0c`) are not part of it.
        let name = section.name.split('\0').next().unwrap_or("").to_string();
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let entropy = if start < bytes.len() {
            let end = start.saturating_add(size).min(bytes.len());
            byte_entropy(&bytes[start..end])
        } else {
            0.0
        };
        if entropy >= 7.20
            || name.starts_with("UPX")
            || name.starts_with(".packed")
            || name.is_empty()
        {
            suspicious_sections.push(format!(
                "{} entropy={:.3}",
                if name.is_empty() { "<empty>" } else { &name },
                entropy
            ));
        }
        sections.push(PeSectionInfo {
            name,
            virtual_size: section.virtual_size as u64,
            raw_size: section.size_of_raw_data as u64,
            entropy,
            characteristics: section.characteristics,
            virtual_address: section.virtual_address as u64,
            raw_offset: section.pointer_to_raw_data as u64,
        });
    }

    let likely_packed = suspicious_sections.len() >= 2
        || sections.iter().any(|s| s.name.starts_with("UPX"))
        || (sections.len() <= 3 && sections.iter().any(|s| s.entropy >= 7.40));

    let time_date_stamp = pe.file_header.time_date_stamp;

    let exports: Vec<String> = pe
        .exports
        .iter()
        .flat_map(|exp| exp.symbols.iter())
        .filter_map(|sym| sym.name.clone())
        .collect();

    let imphash = imphash(imports.iter().filter_map(|s| s.split_once('!')));

    Some(PeInfo {
        arch: if pe.is_64bit { "x64".into() } else { "x86".into() },
        is_64: pe.is_64bit,
        entry: pe.optional_header.address_of_entry_point as u64,
        image_base: pe.optional_header.image_base,
        imports,
        exports,
        dlls,
        suspicious_imports,
        sections,
        suspicious_sections,
        likely_packed,
        time_date_stamp,
        imphash,
        data_directories: pe
            .optional_header
            .data_directories
            .iter()
            .map(|d| (d.virtual_address, d.size))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::imphash;

    #[test]
    fn imphash_matches_pefile() {
        // md5("kernel32.exitprocess,ws2_32.connect,user32.messageboxa"): extension cut,
        // lower case, ws2_32 ordinal 4 named like pefile does.
        let got = imphash([("KERNEL32.dll", "ExitProcess"), ("WS2_32.dll", "ord4"), ("user32.DLL", "MessageBoxA")]);
        assert_eq!(got.as_deref(), Some("680797a9ccfa0d4adffde6422712a36a"));
    }

    #[test]
    fn no_imports_no_imphash() {
        assert_eq!(imphash(std::iter::empty()), None);
    }
}
