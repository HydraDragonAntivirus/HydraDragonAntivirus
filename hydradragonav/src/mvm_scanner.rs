use std::path::Path;

use goblin::pe::PE;

use crate::verdict::{EngineResult, Verdict};

const SENSITIVE_API_KERNEL32: &[&str] = &[
    "CreateRemoteThread",
    "CreateProcessA",
    "WriteFile",
    "DeleteFile",
    "MoveFileExA",
    "MoveFileA",
    "LoadLibraryW",
    "LoadLibraryExW",
    "LoadLibraryExA",
    "GetCurrentThreadId",
    "ExitThread",
    "ExitProcess",
    "CreateThread",
    "WinExec",
    "Sleep",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "SetThreadContext",
    "GetThreadContext",
    "ResumeThread",
    "SuspendThread",
    "TerminateProcess",
];

const SENSITIVE_API_NTDLL: &[&str] = &[
    "ZwSetValueKey",
    "ZwReadFile",
    "ZwQueryInformationFile",
    "ZwCreateFile",
    "ZwOpenProcess",
    "ZwAllocateVirtualMemory",
    "ZwFreeVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwReadVirtualMemory",
    "ZwProtectVirtualMemory",
    "ZwCreateThreadEx",
    "ZwResumeThread",
    "ZwClose",
    "ZwDuplicateObject",
    "ZwQuerySystemInformation",
    "ZwQueryInformationProcess",
];

const SENSITIVE_API_WS2_32: &[&str] = &[
    "WSAStartup",
    "WSACleanup",
    "socket",
    "connect",
    "send",
    "recv",
    "listen",
    "bind",
    "accept",
    "select",
    "recvfrom",
    "sendto",
    "WSASend",
    "WSARecv",
    "WSAConnect",
    "WSASocketA",
    "WSASocketW",
];

const SENSITIVE_API_URLMON: &[&str] = &["URLDownloadToFileA", "URLDownloadToFileW"];

const SENSITIVE_API_SHELL32: &[&str] = &[
    "ShellExecuteA",
    "ShellExecuteExA",
    "ShellExecuteW",
    "ShellExecuteExW",
];

const SENSITIVE_API_ADVAPI32: &[&str] = &[
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
    "OpenSCManagerA",
    "OpenSCManagerW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
];

const SENSITIVE_FILES: &[&str] = &[
    "\\drivers\\etc\\hosts",
    "\\boot.ini",
    "\\ntldr",
    "\\bootmgr",
    "\\windows\\system32\\drivers\\etc\\hosts",
];

const SENSITIVE_PROCESSES: &[&str] = &[
    "explorer.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "svchost.exe",
    "lsass.exe",
    "alg.exe",
    "spoolsv.exe",
];

const SENSITIVE_DRIVES: &[&str] = &[
    "\\\\.\\PhysicalDrive",
    "\\\\.\\Scsi",
    "\\device\\physicalmemory",
];

const SENSITIVE_COMMANDS: &[&str] = &[
    "cmd.exe", "cmd ", "net ", "net.exe", "sc ", "sc.exe",
    "reg ", "regedit.exe", "attrib ", "attrib.exe",
    "rundll32 ", "rundll32.exe", "regsvr32 ", "regsvr32.exe",
    "taskkill", "format ", "ftp ", "copy ",
];

const SENSITIVE_REGISTRY_PATHS: &[&str] = &[
    "\\currentversion\\run",
    "\\policies\\explorer\\run",
    "software\\microsoft\\windows\\currentversion\\run",
];

fn check_api_imports(data: &[u8]) -> Vec<&'static str> {
    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };

    let mut hits = Vec::new();

    for import in &pe.imports {
        let name_upper = import.name.to_uppercase();
        let dll_upper = import.dll.to_uppercase();

        if dll_upper.contains("KERNEL32") {
            for &api in SENSITIVE_API_KERNEL32 {
                if name_upper == api.to_uppercase() {
                    hits.push(api);
                }
            }
        }

        if dll_upper.contains("NTDLL") {
            for &api in SENSITIVE_API_NTDLL {
                if name_upper == api.to_uppercase() {
                    hits.push(api);
                }
            }
        }

        if dll_upper.contains("WS2_32") || dll_upper.contains("WSOCK") {
            for &api in SENSITIVE_API_WS2_32 {
                if name_upper == api.to_uppercase() {
                    hits.push(api);
                }
            }
        }

        if dll_upper.contains("URLMON") {
            for &api in SENSITIVE_API_URLMON {
                if name_upper == api.to_uppercase() {
                    hits.push(api);
                }
            }
        }

        if dll_upper.contains("SHELL32") {
            for &api in SENSITIVE_API_SHELL32 {
                if name_upper == api.to_uppercase() {
                    hits.push(api);
                }
            }
        }

        if dll_upper.contains("ADVAPI32") {
            for &api in SENSITIVE_API_ADVAPI32 {
                if name_upper == api.to_uppercase() {
                    hits.push(api);
                }
            }
        }
    }

    hits
}

fn check_sensitive_path(path: &Path) -> Option<&'static str> {
    let path_lower = path.to_string_lossy().to_lowercase();

    for &sensitive in SENSITIVE_FILES {
        if path_lower.contains(&sensitive.to_lowercase()) {
            return Some(sensitive);
        }
    }

    for &drive in SENSITIVE_DRIVES {
        if path_lower.contains(&drive.to_lowercase()) {
            return Some(drive);
        }
    }

    for &reg in SENSITIVE_REGISTRY_PATHS {
        if path_lower.contains(reg) {
            return Some(reg);
        }
    }

    None
}

fn check_process_name(name: &str) -> Option<&'static str> {
    let name_lower = name.to_lowercase();
    for &proc in SENSITIVE_PROCESSES {
        if name_lower == proc {
            return Some(proc);
        }
    }
    None
}

pub struct MvmScanner;

impl MvmScanner {
    pub fn new() -> Self {
        MvmScanner
    }

    pub fn scan_buffer(&self, data: &[u8], path: Option<&Path>) -> Vec<EngineResult> {
        let mut results = Vec::new();
        let mut suspicious_count = 0;
        let mut malware_apis = Vec::new();

        let api_hits = check_api_imports(data);
        suspicious_count += api_hits.len();
        malware_apis.extend(api_hits);

        if let Some(p) = path {
            if let Some(matched) = check_sensitive_path(p) {
                results.push(EngineResult {
                    engine: "mvm_scanner",
                    verdict: Verdict::Suspicious,
                    detail: format!("sensitive path access: {}", matched),
                    elapsed_ms: None,
                });
                suspicious_count += 1;
            }

            let fname = p
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();
            if let Some(matched) = check_process_name(&fname) {
                results.push(EngineResult {
                    engine: "mvm_scanner",
                    verdict: Verdict::Suspicious,
                    detail: format!("sensitive process name match: {}", matched),
                    elapsed_ms: None,
                });
                suspicious_count += 1;
            }
        }

        let cmd_hits: Vec<&str> = {
            let s = String::from_utf8_lossy(data);
            SENSITIVE_COMMANDS
                .iter()
                .filter(|&&cmd| {
                    let s_lower = s.to_lowercase();
                    let cmd_lower = cmd.to_lowercase();
                    s_lower.contains(&cmd_lower)
                })
                .copied()
                .collect()
        };
        suspicious_count += cmd_hits.len();

        if !malware_apis.is_empty() {
            results.push(EngineResult {
                engine: "mvm_scanner",
                verdict: Verdict::Suspicious,
                detail: format!("suspicious API imports: {}", malware_apis.join(", ")),
                elapsed_ms: None,
            });
        }

        if suspicious_count >= 5 {
            results.push(EngineResult {
                engine: "mvm_scanner",
                verdict: Verdict::Malware,
                detail: format!(
                    "multiple heuristic triggers ({}) — elevated threat score",
                    suspicious_count
                ),
                elapsed_ms: None,
            });
        } else if suspicious_count >= 3 {
            results.push(EngineResult {
                engine: "mvm_scanner",
                verdict: Verdict::Suspicious,
                detail: format!(
                    "multiple heuristic triggers ({}) — elevated suspicion",
                    suspicious_count
                ),
                elapsed_ms: None,
            });
        }

        if !cmd_hits.is_empty() {
            if suspicious_count >= 3 {
                results.push(EngineResult {
                    engine: "mvm_scanner",
                    verdict: Verdict::Malware,
                    detail: format!(
                        "malicious command patterns with API abuse: {}",
                        cmd_hits.join(", ")
                    ),
                    elapsed_ms: None,
                });
            } else {
                results.push(EngineResult {
                    engine: "mvm_scanner",
                    verdict: Verdict::Suspicious,
                    detail: format!("suspicious command patterns: {}", cmd_hits.join(", ")),
                    elapsed_ms: None,
                });
            }
        }

        results
    }
}
