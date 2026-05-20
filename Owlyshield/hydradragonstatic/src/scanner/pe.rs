use crate::models::{PeInfo, PeSectionInfo};
use crate::utils::entropy::byte_entropy;
use goblin::Object;
use once_cell::sync::Lazy;
use std::collections::HashSet;

static SUSPICIOUS_IMPORTS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "OpenProcess",
        "OpenThread",
        "SuspendThread",
        "ResumeThread",
        "GetThreadContext",
        "SetThreadContext",
        "NtMapViewOfSection",
        "MapViewOfFile",
        "CreateFileMappingA",
        "CreateFileMappingW",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "LdrLoadDll",
        "NtQueryInformationProcess",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "GetTickCount",
        "QueryPerformanceCounter",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegDeleteValueA",
        "RegDeleteValueW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "WSAStartup",
        "connect",
        "send",
        "recv",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptEncrypt",
        "CryptDecrypt",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "LookupPrivilegeValueA",
        "LookupPrivilegeValueW",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
        "ControlService",
    ]
    .into_iter()
    .collect()
});

pub fn scan_pe(bytes: &[u8]) -> Option<PeInfo> {
    let obj = Object::parse(bytes).ok()?;
    let pe = match obj {
        Object::PE(pe) => pe,
        _ => return None,
    };

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|imp| format!("{}!{}", imp.dll, imp.name))
        .collect();

    let dlls: Vec<String> = imports
        .iter()
        .filter_map(|s| s.split_once('!').map(|(dll, _)| dll.to_ascii_lowercase()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let suspicious_imports = imports
        .iter()
        .filter(|name| {
            name.split('!')
                .last()
                .map(|api| SUSPICIOUS_IMPORTS.contains(api))
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut sections = Vec::new();
    let mut suspicious_sections = Vec::new();
    for section in &pe.sections {
        let name = section.name().unwrap_or("").trim_matches('\0').to_string();
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
        });
    }

    let likely_packed = suspicious_sections.len() >= 2
        || sections.iter().any(|s| s.name.starts_with("UPX"))
        || (sections.len() <= 3 && sections.iter().any(|s| s.entropy >= 7.40));

    Some(PeInfo {
        arch: if pe.is_64 { "x64".into() } else { "x86".into() },
        is_64: pe.is_64,
        entry: pe.entry as u64,
        image_base: pe.image_base as u64,
        imports,
        dlls,
        suspicious_imports,
        sections,
        suspicious_sections,
        likely_packed,
    })
}
