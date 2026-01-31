//! API Usage Tracking Module
//!
//! Tracks Windows API usage patterns from kernel driver messages

use crate::shared_def::{IOMessage, IrpMajorOp, FileChangeInfo};
use crate::process::ProcessRecord;
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

/// Tracks API usage for a specific process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTracker {
    pub gid: u64,
    pub process_name: String,

    // API categories from malapi.json
    pub enumeration_apis: HashSet<String>,
    pub injection_apis: HashSet<String>,
    pub evasion_apis: HashSet<String>,
    pub spying_apis: HashSet<String>,
    pub internet_apis: HashSet<String>,
    pub anti_debugging_apis: HashSet<String>,
    pub ransomware_apis: HashSet<String>,
    pub helper_apis: HashSet<String>,

    // DLL usage tracking
    pub dlls_loaded: HashSet<String>,

    // Behavioral counters
    pub file_operations: FileOperationStats,
    pub registry_operations: RegistryOperationStats,
    pub network_operations: NetworkOperationStats,
    pub process_operations: ProcessOperationStats,

    // Sequence tracking for pattern detection
    pub api_sequence: Vec<ApiCall>,
    pub operation_sequence: Vec<OperationType>,

    // Timing information
    pub first_seen: std::time::SystemTime,
    pub last_activity: std::time::SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationStats {
    pub files_read: usize,
    pub files_written: usize,
    pub files_deleted: usize,
    pub files_renamed: usize,
    pub files_encrypted: usize, // Inferred from high entropy writes
    pub directories_enumerated: usize,
    pub executable_files_accessed: HashSet<String>,
    pub suspicious_extensions_written: HashSet<String>, // .exe, .dll, .sys, .bat, .ps1
    pub mass_file_operations: bool, // True if >100 files modified rapidly
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperationStats {
    pub keys_created: usize,
    pub keys_deleted: usize,
    pub keys_modified: usize,
    pub autorun_keys_modified: bool, // Run, RunOnce, etc.
    pub security_keys_accessed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOperationStats {
    pub connections_established: usize,
    pub data_sent: u64,
    pub data_received: u64,
    pub dns_queries: usize,
    pub suspicious_ports: HashSet<u16>, // Common C2 ports
    pub http_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperationStats {
    pub processes_created: usize,
    pub processes_injected: usize, // Inferred from WriteProcessMemory + CreateRemoteThread
    pub threads_created: usize,
    pub memory_allocated: u64,
    pub privileges_escalated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    pub name: String,
    pub category: ApiCategory,
    pub timestamp: std::time::SystemTime,
    pub associated_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiCategory {
    Enumeration,
    Injection,
    Evasion,
    Spying,
    Internet,
    AntiDebugging,
    Ransomware,
    Helper,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    FileRead(String),
    FileWrite(String, f64), // path, entropy
    FileDelete(String),
    FileRename(String, String),
    ProcessCreate(String),
    MemoryAllocate(u64),
    NetworkConnect(String),
    RegistryModify(String),
}

/// Pattern for detecting API usage sequences
#[derive(Debug, Clone)]
pub struct ApiUsagePattern {
    pub name: String,
    pub description: String,
    pub required_apis: Vec<String>,
    pub required_sequence: Vec<(String, String)>, // (API1, API2) - API2 must follow API1
    pub min_occurrences: usize,
}

impl ApiTracker {
    pub fn new(gid: u64, process_name: String) -> Self {
        let now = std::time::SystemTime::now();

        ApiTracker {
            gid,
            process_name,
            enumeration_apis: HashSet::new(),
            injection_apis: HashSet::new(),
            evasion_apis: HashSet::new(),
            spying_apis: HashSet::new(),
            internet_apis: HashSet::new(),
            anti_debugging_apis: HashSet::new(),
            ransomware_apis: HashSet::new(),
            helper_apis: HashSet::new(),
            dlls_loaded: HashSet::new(),
            file_operations: FileOperationStats {
                files_read: 0,
                files_written: 0,
                files_deleted: 0,
                files_renamed: 0,
                files_encrypted: 0,
                directories_enumerated: 0,
                executable_files_accessed: HashSet::new(),
                suspicious_extensions_written: HashSet::new(),
                mass_file_operations: false,
            },
            registry_operations: RegistryOperationStats {
                keys_created: 0,
                keys_deleted: 0,
                keys_modified: 0,
                autorun_keys_modified: false,
                security_keys_accessed: false,
            },
            network_operations: NetworkOperationStats {
                connections_established: 0,
                data_sent: 0,
                data_received: 0,
                dns_queries: 0,
                suspicious_ports: HashSet::new(),
                http_requests: 0,
            },
            process_operations: ProcessOperationStats {
                processes_created: 0,
                processes_injected: 0,
                threads_created: 0,
                memory_allocated: 0,
                privileges_escalated: false,
            },
            api_sequence: Vec::new(),
            operation_sequence: Vec::new(),
            first_seen: now,
            last_activity: now,
        }
    }

    /// Track an IO operation from the kernel driver
    pub fn track_io_operation(&mut self, msg: &IOMessage, _precord: &ProcessRecord) {
        self.last_activity = msg.time;

        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let file_change: FileChangeInfo = num::FromPrimitive::from_u8(msg.file_change)
            .unwrap_or(FileChangeInfo::ChangeNotSet);

        // Track file operations
        match irp_op {
            IrpMajorOp::IrpRead => {
                self.file_operations.files_read += 1;
                self.operation_sequence.push(OperationType::FileRead(msg.filepathstr.clone()));
            }
            IrpMajorOp::IrpWrite => {
                self.file_operations.files_written += 1;

                // Detect potential encryption (high entropy writes)
                if msg.is_entropy_calc == 1 && msg.entropy > 7.5 {
                    self.file_operations.files_encrypted += 1;
                }

                self.operation_sequence.push(OperationType::FileWrite(
                    msg.filepathstr.clone(),
                    msg.entropy,
                ));

                // Track suspicious extensions
                if self.is_suspicious_extension(&msg.extension) {
                    self.file_operations.suspicious_extensions_written.insert(msg.extension.clone());
                }
            }
            IrpMajorOp::IrpSetInfo => {
                match file_change {
                    FileChangeInfo::ChangeDeleteFile | FileChangeInfo::ChangeDeleteNewFile => {
                        self.file_operations.files_deleted += 1;
                        self.operation_sequence.push(OperationType::FileDelete(msg.filepathstr.clone()));
                    }
                    FileChangeInfo::ChangeRenameFile => {
                        self.file_operations.files_renamed += 1;
                        self.operation_sequence.push(OperationType::FileRename(
                            msg.filepathstr.clone(),
                            "".to_string(),
                        ));
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        // Detect mass file operations
        if self.file_operations.files_written + self.file_operations.files_deleted > 100 {
            self.file_operations.mass_file_operations = true;
        }

        // Track executable access
        if self.is_executable_extension(&msg.extension) {
            self.file_operations.executable_files_accessed.insert(msg.filepathstr.clone());
        }

        // Infer DLL loads from file operations on .dll files
        if msg.extension.to_lowercase() == "dll" {
            self.dlls_loaded.insert(msg.filepathstr.clone());
            // Track network-related DLL loads
            self.track_network_dll(&msg.filepathstr);
        }

        // Detect internet APIs from file path (for DLL imports, API hooks, etc.)
        self.detect_internet_api(&msg.filepathstr, Some(msg.filepathstr.clone()));
    }

    /// Track a specific API call (for future integration with API hooking)
    pub fn track_api_call(&mut self, api_name: String, category: ApiCategory, associated_file: Option<String>) {
        let api_call = ApiCall {
            name: api_name.clone(),
            category,
            timestamp: std::time::SystemTime::now(),
            associated_file,
        };

        self.api_sequence.push(api_call);

        // Add to category sets
        match category {
            ApiCategory::Enumeration => { self.enumeration_apis.insert(api_name); }
            ApiCategory::Injection => { self.injection_apis.insert(api_name); }
            ApiCategory::Evasion => { self.evasion_apis.insert(api_name); }
            ApiCategory::Spying => { self.spying_apis.insert(api_name); }
            ApiCategory::Internet => { self.internet_apis.insert(api_name); }
            ApiCategory::AntiDebugging => { self.anti_debugging_apis.insert(api_name); }
            ApiCategory::Ransomware => { self.ransomware_apis.insert(api_name); }
            ApiCategory::Helper => { self.helper_apis.insert(api_name); }
            ApiCategory::Unknown => {}
        }
    }

    /// Get summary of API usage
    pub fn get_api_usage_summary(&self) -> super::ApiUsageSummary {
        super::ApiUsageSummary {
            enumeration_apis: self.enumeration_apis.iter().cloned().collect(),
            injection_apis: self.injection_apis.iter().cloned().collect(),
            evasion_apis: self.evasion_apis.iter().cloned().collect(),
            spying_apis: self.spying_apis.iter().cloned().collect(),
            internet_apis: self.internet_apis.iter().cloned().collect(),
            anti_debugging_apis: self.anti_debugging_apis.iter().cloned().collect(),
            ransomware_apis: self.ransomware_apis.iter().cloned().collect(),
            helper_apis: self.helper_apis.iter().cloned().collect(),
        }
    }

    /// Check if an API sequence pattern exists
    pub fn has_api_sequence(&self, sequence: &[(String, String)]) -> bool {
        for window in self.api_sequence.windows(2) {
            for (api1, api2) in sequence {
                if window[0].name == *api1 && window[1].name == *api2 {
                    return true;
                }
            }
        }
        false
    }

    fn is_suspicious_extension(&self, ext: &str) -> bool {
        matches!(
            ext.to_lowercase().as_str(),
            "exe" | "dll" | "sys" | "bat" | "ps1" | "vbs" | "js" | "cmd" | "scr"
        )
    }

    fn is_executable_extension(&self, ext: &str) -> bool {
        matches!(
            ext.to_lowercase().as_str(),
            "exe" | "dll" | "sys" | "scr"
        )
    }

    /// Internet/Network API keywords for detection
    const INTERNET_API_KEYWORDS: &'static [&'static str] = &[
        // WinINet APIs
        "internetopen",
        "internetconnect", 
        "httpopen",
        "httpsend",
        "httpsendrequesta",
        "httpsendrequestw",
        "httpopenrequesta",
        "httpopenrequestw",
        "internetopenurla",
        "internetopenurlw",
        "internetreadfile",
        "internetwritefile",
        "internetclosehandle",
        // URL Download APIs
        "urldownload",
        "urldownloadtofile",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "urldownloadtocachefile",
        // Socket APIs  
        "socket",
        "connect",
        "send",
        "recv",
        "bind",
        "listen",
        "accept",
        "closesocket",
        "shutdown",
        "gethostbyname",
        "getaddrinfo",
        // WSA APIs
        "wsasend",
        "wsarecv",
        "wsasocket",
        "wsaconnect",
        "wsastartup",
        "wsacleanup",
        "wsaasyncgethost",
        // WinHTTP APIs
        "winhttp",
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "winhttpreceiveresponse",
        "winhttpreaddata",
        "winhttpwritedata",
        "winhttpclosehandle",
        // DNS APIs
        "dnsquery",
        "dnsquery_a",
        "dnsquery_w",
        "dnsqueryfree",
        "getaddrinfow",
        "getnameinfo",
        // FTP APIs
        "ftpopen",
        "ftpconnect",
        "ftpgetfile",
        "ftpputfile",
        "ftpfindfirstfile",
        // Additional Network APIs
        "internetsetcookie",
        "internetgetcookie",
        "internetsetstatuscallback",
    ];

    /// Check if a string contains an internet/network API keyword
    pub fn is_internet_api(name: &str) -> bool {
        let name_lower = name.to_lowercase();
        Self::INTERNET_API_KEYWORDS.iter().any(|keyword| name_lower.contains(keyword))
    }

    /// Detect and track internet APIs from a file path or operation name
    pub fn detect_internet_api(&mut self, operation_name: &str, associated_file: Option<String>) {
        let name_lower = operation_name.to_lowercase();
        
        for keyword in Self::INTERNET_API_KEYWORDS.iter() {
            if name_lower.contains(keyword) {
                self.track_api_call(
                    operation_name.to_string(),
                    ApiCategory::Internet,
                    associated_file.clone(),
                );
                self.internet_apis.insert(operation_name.to_string());
                
                // Update network statistics based on API type
                self.update_network_stats_from_api(&name_lower);
                break;
            }
        }
    }

    /// Update network operation stats based on detected API
    fn update_network_stats_from_api(&mut self, api_name: &str) {
        if api_name.contains("connect") || api_name.contains("socket") {
            self.network_operations.connections_established += 1;
        }
        if api_name.contains("dnsquery") || api_name.contains("gethostbyname") || api_name.contains("getaddrinfo") {
            self.network_operations.dns_queries += 1;
        }
        if api_name.contains("http") || api_name.contains("winhttp") || api_name.contains("urldownload") {
            self.network_operations.http_requests += 1;
        }
    }

    /// Track network-related DLL loads that indicate internet activity
    pub fn track_network_dll(&mut self, dll_path: &str) {
        let dll_lower = dll_path.to_lowercase();
        
        // Map DLLs to representative APIs/Capabilities
        if dll_lower.contains("ws2_32.dll") || dll_lower.contains("wsock32.dll") {
            self.internet_apis.insert("socket".to_string());
            self.internet_apis.insert("connect".to_string());
            self.network_operations.connections_established += 1; // Assume capability implies usage potential
        } else if dll_lower.contains("wininet.dll") {
            self.internet_apis.insert("internetopen".to_string());
            self.internet_apis.insert("internetconnect".to_string());
            self.network_operations.http_requests += 1;
        } else if dll_lower.contains("winhttp.dll") {
            self.internet_apis.insert("winhttpopen".to_string());
            self.internet_apis.insert("winhttpconnect".to_string());
            self.network_operations.http_requests += 1;
        } else if dll_lower.contains("dnsapi.dll") {
            self.internet_apis.insert("dnsquery".to_string());
            self.network_operations.dns_queries += 1;
        } else if dll_lower.contains("urlmon.dll") {
            self.internet_apis.insert("urldownload".to_string());
        }

        let network_dlls = [
            "wininet.dll",
            "winhttp.dll",
            "ws2_32.dll",
            "wsock32.dll",
            "urlmon.dll",
            "dnsapi.dll",
            "mswsock.dll",
            "iphlpapi.dll",
        ];
        
        for network_dll in &network_dlls {
            if dll_lower.contains(network_dll) {
                self.dlls_loaded.insert(dll_path.to_string());
                break;
            }
        }
    }

    /// Check if process has significant internet activity
    pub fn has_significant_internet_activity(&self) -> bool {
        !self.internet_apis.is_empty()
            || self.network_operations.connections_established > 0
            || self.network_operations.http_requests > 0
            || self.network_operations.dns_queries > 0
    }

    /// Get internet API summary
    pub fn get_internet_api_summary(&self) -> Vec<String> {
        self.internet_apis.iter().cloned().collect()
    }

    /// Get total API calls across all categories
    pub fn total_api_calls(&self) -> usize {
        self.enumeration_apis.len()
            + self.injection_apis.len()
            + self.evasion_apis.len()
            + self.spying_apis.len()
            + self.internet_apis.len()
            + self.anti_debugging_apis.len()
            + self.ransomware_apis.len()
            + self.helper_apis.len()
    }
}
