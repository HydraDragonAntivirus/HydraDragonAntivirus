//! API Usage Tracking Module
//!
//! Tracks Windows API usage patterns from kernel driver messages

use crate::process::ProcessRecord;
use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp, known_raw_event_name};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

fn normalize_hypervisor_api_label(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    if let Some(idx) = value.find(" (syscall=0x") {
        value.truncate(idx);
    }
    value.trim().to_string()
}

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
    pub kernel_operations: KernelOperationStats,

    // Sequence tracking for pattern detection
    pub api_sequence: Vec<ApiCall>,
    pub operation_sequence: Vec<OperationType>,

    // High-volume kernel event history (capped)
    pub kernel_event_log: Vec<String>,
    pub raw_event_log: Vec<String>,

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
    pub files_encrypted: usize,
    pub directories_enumerated: usize,
    pub executable_files_accessed: HashSet<String>,
    pub suspicious_extensions_written: HashSet<String>,
    pub mass_file_operations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperationStats {
    pub keys_created: usize,
    pub keys_deleted: usize,
    pub keys_modified: usize,
    pub autorun_keys_modified: bool,
    pub security_keys_accessed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOperationStats {
    pub connections_established: usize,
    pub data_sent: u64,
    pub data_received: u64,
    pub dns_queries: usize,
    pub suspicious_ports: HashSet<u16>,
    pub http_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperationStats {
    pub processes_created: usize,
    pub processes_injected: usize,
    pub threads_created: usize,
    pub memory_allocated: u64,
    pub privileges_escalated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelOperationStats {
    pub total_kernel_events: usize,
    pub write_virtual_memory: usize,
    pub allocate_virtual_memory: usize,
    pub protect_virtual_memory: usize,
    pub create_thread: usize,
    pub queue_apc: usize,
    pub set_context: usize,
    pub create_section: usize,
    pub map_section: usize,
    pub delete_file: usize,
    pub load_driver: usize,
    pub open_process: usize,
    pub generic_api_call: usize,
    pub process_handle_open: usize,
    pub process_terminate_attempt: usize,
    pub loaded_kernel_drivers: HashSet<String>,
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
    FileWrite(String, f64),
    FileDelete(String),
    FileRename(String, String),
    ProcessCreate(String),
    ProcessTerminate(u32),
    ProcessTerminateAttempt { source_pid: u32, target_pid: u32 },
    ProcessHandleOpen { source_pid: u32, target_pid: u32 },
    MemoryAllocate(u64),
    NetworkConnect(String),
    RegistryModify(String),
    KernelApi {
        opcode: String,
        api: String,
        raw_event_type: u32,
        source_pid: u32,
        target_pid: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        size: u64,
        status: i32,
    },
    DriverLoad(String),
}

#[derive(Debug, Clone)]
pub struct ApiUsagePattern {
    pub name: String,
    pub description: String,
    pub required_apis: Vec<String>,
    pub required_sequence: Vec<(String, String)>,
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
            kernel_operations: KernelOperationStats::default(),
            api_sequence: Vec::new(),
            operation_sequence: Vec::new(),
            kernel_event_log: Vec::new(),
            raw_event_log: Vec::new(),
            first_seen: now,
            last_activity: now,
        }
    }

    /// Track an IO operation from the kernel driver and preserve all kernel-level telemetry.
    pub fn track_io_operation(&mut self, msg: &IOMessage, _precord: &ProcessRecord) {
        self.last_activity = msg.time;
        self.raw_event_log.push(Self::render_raw_event(msg));

        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let file_change: FileChangeInfo = num::FromPrimitive::from_u8(msg.file_change)
            .unwrap_or(FileChangeInfo::ChangeNotSet);

        match irp_op {
            IrpMajorOp::IrpRead => {
                self.file_operations.files_read += 1;
                self.operation_sequence.push(OperationType::FileRead(msg.filepathstr.clone()));
            }
            IrpMajorOp::IrpWrite => {
                self.file_operations.files_written += 1;
                if msg.is_entropy_calc == 1 && msg.entropy > 7.5 {
                    self.file_operations.files_encrypted += 1;
                }
                self.operation_sequence
                    .push(OperationType::FileWrite(msg.filepathstr.clone(), msg.entropy));
                if self.is_suspicious_extension(&msg.extension) {
                    self.file_operations
                        .suspicious_extensions_written
                        .insert(msg.extension.clone());
                }
            }
            IrpMajorOp::IrpSetInfo => match file_change {
                FileChangeInfo::ChangeDeleteFile | FileChangeInfo::ChangeDeleteNewFile => {
                    self.file_operations.files_deleted += 1;
                    self.operation_sequence
                        .push(OperationType::FileDelete(msg.filepathstr.clone()));
                }
                FileChangeInfo::ChangeRenameFile => {
                    self.file_operations.files_renamed += 1;
                    self.operation_sequence
                        .push(OperationType::FileRename(msg.filepathstr.clone(), String::new()));
                }
                FileChangeInfo::RegCreateKey => {
                    self.registry_operations.keys_created += 1;
                    self.operation_sequence
                        .push(OperationType::RegistryModify(format!("REG_CREATE:{}", msg.filepathstr)));
                }
                FileChangeInfo::RegSetValue => {
                    self.registry_operations.keys_modified += 1;
                    self.operation_sequence
                        .push(OperationType::RegistryModify(format!("REG_SET:{}", msg.filepathstr)));
                    let lower = msg.filepathstr.to_ascii_lowercase();
                    if lower.contains("\\run") || lower.contains("runonce") {
                        self.registry_operations.autorun_keys_modified = true;
                    }
                    if lower.contains("security") || lower.contains("sam") {
                        self.registry_operations.security_keys_accessed = true;
                    }
                }
                FileChangeInfo::RegDeleteValue => {
                    self.registry_operations.keys_deleted += 1;
                    self.operation_sequence
                        .push(OperationType::RegistryModify(format!("REG_DELETE:{}", msg.filepathstr)));
                }
                FileChangeInfo::RegRenameKey => {
                    self.registry_operations.keys_modified += 1;
                    self.operation_sequence
                        .push(OperationType::RegistryModify(format!("REG_RENAME:{}", msg.filepathstr)));
                }
                _ => {}
            },
            IrpMajorOp::IrpRegistry => {
                self.registry_operations.keys_modified += 1;
                self.operation_sequence
                    .push(OperationType::RegistryModify(msg.filepathstr.clone()));
            }
            IrpMajorOp::IrpProcessCreate => {
                self.process_operations.processes_created += 1;
                self.operation_sequence
                    .push(OperationType::ProcessCreate(msg.filepathstr.clone()));
            }
            IrpMajorOp::IrpProcessTerminate | IrpMajorOp::IrpProcessExit => {
                self.operation_sequence.push(OperationType::ProcessTerminate(msg.pid));
            }
            IrpMajorOp::IrpProcessTerminateAttempt => {
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                {
                    self.kernel_operations.process_terminate_attempt += 1;
                    self.operation_sequence.push(OperationType::ProcessTerminateAttempt {
                        source_pid: msg.attacker_pid,
                        target_pid: msg.pid,
                    });
                }
                #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                {
                    self.kernel_operations.process_terminate_attempt += 1;
                    self.operation_sequence.push(OperationType::ProcessTerminateAttempt {
                        source_pid: msg.pid,
                        target_pid: msg.pid,
                    });
                }
            }
            IrpMajorOp::IrpProcessHandleOpen => {
                self.kernel_operations.process_handle_open += 1;
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                {
                    self.operation_sequence.push(OperationType::ProcessHandleOpen {
                        source_pid: msg.kernel_event_info.source_process_id,
                        target_pid: msg.kernel_event_info.target_process_id,
                    });
                }
                #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                {
                    self.operation_sequence.push(OperationType::ProcessHandleOpen {
                        source_pid: msg.pid,
                        target_pid: msg.pid,
                    });
                }
            }
            IrpMajorOp::IrpHypervisorEvent => {
                self.record_kernel_api_event(msg, irp_op);
            }
            _ => {}
        }

        if self.file_operations.files_written + self.file_operations.files_deleted > 100 {
            self.file_operations.mass_file_operations = true;
        }

        if self.is_executable_extension(&msg.extension) {
            self.file_operations
                .executable_files_accessed
                .insert(msg.filepathstr.clone());
        }

        if msg.extension.to_lowercase() == "dll" {
            self.dlls_loaded.insert(msg.filepathstr.clone());
        }
    }

    fn record_kernel_api_event(&mut self, msg: &IOMessage, op: IrpMajorOp) {
        self.kernel_operations.total_kernel_events += 1;

        let op_name = "IrpHypervisorEvent".to_string();
        let event_name = self.resolve_api_name(msg, "");
        let category = self.api_category_from_kernel_op(&op, &event_name);
        self.track_api_call(event_name.clone(), category, Some(msg.filepathstr.clone()));

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let (source_pid, target_pid, mem_size, status, raw_event_type, arg1, arg2, arg3, arg4) = (
            msg.kernel_event_info.source_process_id,
            msg.kernel_event_info.target_process_id,
            msg.kernel_event_info.memory_size as u64,
            msg.kernel_event_info.operation_status,
            if msg.kernel_event_info.event_type != 0 {
                msg.kernel_event_info.event_type
            } else {
                msg.irp_op as u32
            },
            msg.kernel_event_info.raw_argument1,
            msg.kernel_event_info.raw_argument2,
            msg.kernel_event_info.raw_argument3,
            msg.kernel_event_info.raw_argument4,
        );
        #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
        let (source_pid, target_pid, mem_size, status, raw_event_type, arg1, arg2, arg3, arg4) = (
            msg.pid,
            msg.pid,
            0u64,
            0i32,
            msg.irp_op as u32,
            0u64,
            0u64,
            0u64,
            0u64,
        );

        self.operation_sequence.push(OperationType::KernelApi {
            opcode: op_name.clone(),
            api: event_name.clone(),
            raw_event_type,
            source_pid,
            target_pid,
            arg1,
            arg2,
            arg3,
            arg4,
            size: mem_size,
            status,
        });

        self.kernel_operations.generic_api_call += 1;

        self.append_kernel_log(format!(
            "op={} raw_event_type={} event={} pid={} gid={} src_pid={} target_pid={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} size={} status={} path={}",
            op_name, raw_event_type, event_name, msg.pid, msg.gid, source_pid, target_pid, arg1, arg2, arg3, arg4, mem_size, status, msg.filepathstr
        ));
    }

    fn resolve_api_name(&self, msg: &IOMessage, fallback: &str) -> String {
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        {
            let api = normalize_hypervisor_api_label(msg.kernel_event_info.object_name.trim());
            if !api.is_empty() {
                return api;
            }
            let raw_event_type = if msg.kernel_event_info.event_type != 0 {
                msg.kernel_event_info.event_type
            } else {
                msg.irp_op as u32
            };
            if let Some(name) = known_raw_event_name(raw_event_type) {
                return name.to_string();
            }
        }
        if !msg.filepathstr.trim().is_empty() {
            return msg.filepathstr.clone();
        }
        fallback.to_string()
    }

    fn api_category_from_kernel_op(&self, op: &IrpMajorOp, api_name: &str) -> ApiCategory {
        if Self::is_internet_api(api_name) {
            return ApiCategory::Internet;
        }
        match op {
            IrpMajorOp::IrpHypervisorEvent => ApiCategory::Helper,
            IrpMajorOp::IrpProcessHandleOpen | IrpMajorOp::IrpProcessTerminateAttempt => ApiCategory::Enumeration,
            _ => ApiCategory::Unknown,
        }
    }

    fn append_kernel_log(&mut self, line: String) {
        self.kernel_event_log.push(line);
        if self.kernel_event_log.len() > 2048 {
            let drain = self.kernel_event_log.len() - 2048;
            self.kernel_event_log.drain(0..drain);
        }
    }

    fn sanitize_raw_field(value: &str) -> String {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return "<empty>".to_string();
        }

        trimmed
            .replace(['\r', '\n', '\t'], " ")
    }

    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    fn render_raw_event(msg: &IOMessage) -> String {
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let file_change: FileChangeInfo = num::FromPrimitive::from_u8(msg.file_change)
            .unwrap_or(FileChangeInfo::ChangeNotSet);
        let raw_event_type = if msg.kernel_event_info.event_type != 0 {
            msg.kernel_event_info.event_type
        } else {
            msg.irp_op as u32
        };
        let timestamp_ms = msg
            .time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        format!(
            "ts_ms={} gid={} pid={} irp={:?} raw_event_type={} change={:?} path={} ext={} bytes={} entropy={:.4} file_size={} parent_pid={} attacker_pid={} attacker_gid={} src_pid={} target_pid={} status={} object={} cmd={}",
            timestamp_ms,
            msg.gid,
            msg.pid,
            irp_op,
            raw_event_type,
            file_change,
            Self::sanitize_raw_field(&msg.filepathstr),
            Self::sanitize_raw_field(&msg.extension),
            msg.mem_sized_used,
            msg.entropy,
            msg.file_size,
            msg.parent_pid,
            msg.attacker_pid,
            msg.attacker_gid,
            msg.kernel_event_info.source_process_id,
            msg.kernel_event_info.target_process_id,
            msg.kernel_event_info.operation_status,
            Self::sanitize_raw_field(&msg.kernel_event_info.object_name),
            Self::sanitize_raw_field(&msg.runtime_features.command_line),
        )
    }

    #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
    fn render_raw_event(msg: &IOMessage) -> String {
        let irp_op = IrpMajorOp::from_byte(msg.irp_op);
        let file_change: FileChangeInfo = num::FromPrimitive::from_u8(msg.file_change)
            .unwrap_or(FileChangeInfo::ChangeNotSet);
        let timestamp_ms = msg
            .time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        format!(
            "ts_ms={} gid={} pid={} irp={:?} change={:?} path={} ext={} bytes={} entropy={:.4} file_size={} parent_pid={} cmd={}",
            timestamp_ms,
            msg.gid,
            msg.pid,
            irp_op,
            file_change,
            Self::sanitize_raw_field(&msg.filepathstr),
            Self::sanitize_raw_field(&msg.extension),
            msg.mem_sized_used,
            msg.entropy,
            msg.file_size,
            msg.parent_pid,
            Self::sanitize_raw_field(&msg.runtime_features.command_line),
        )
    }

    pub fn track_api_call(&mut self, api_name: String, category: ApiCategory, associated_file: Option<String>) {
        let api_call = ApiCall {
            name: api_name.clone(),
            category,
            timestamp: std::time::SystemTime::now(),
            associated_file,
        };

        self.api_sequence.push(api_call);

        match category {
            ApiCategory::Enumeration => {
                self.enumeration_apis.insert(api_name);
            }
            ApiCategory::Injection => {
                self.injection_apis.insert(api_name);
            }
            ApiCategory::Evasion => {
                self.evasion_apis.insert(api_name);
            }
            ApiCategory::Spying => {
                self.spying_apis.insert(api_name);
            }
            ApiCategory::Internet => {
                self.internet_apis.insert(api_name);
            }
            ApiCategory::AntiDebugging => {
                self.anti_debugging_apis.insert(api_name);
            }
            ApiCategory::Ransomware => {
                self.ransomware_apis.insert(api_name);
            }
            ApiCategory::Helper => {
                self.helper_apis.insert(api_name);
            }
            ApiCategory::Unknown => {}
        }
    }

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
        matches!(ext.to_lowercase().as_str(), "exe" | "dll" | "sys" | "scr")
    }

    const INTERNET_API_KEYWORDS: &'static [&'static str] = &[
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
        "urldownload",
        "urldownloadtofile",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "urldownloadtocachefile",
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
        "wsasend",
        "wsarecv",
        "wsasocket",
        "wsaconnect",
        "wsastartup",
        "wsacleanup",
        "wsaasyncgethost",
        "winhttp",
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "winhttpreceiveresponse",
        "winhttpreaddata",
        "winhttpwritedata",
        "winhttpclosehandle",
        "dnsquery",
        "dnsquery_a",
        "dnsquery_w",
        "dnsqueryfree",
        "getaddrinfow",
        "getnameinfo",
        "ftpopen",
        "ftpconnect",
        "ftpgetfile",
        "ftpputfile",
        "ftpfindfirstfile",
        "internetsetcookie",
        "internetgetcookie",
        "internetsetstatuscallback",
    ];

    pub fn is_internet_api(name: &str) -> bool {
        let name_lower = name.to_lowercase();
        Self::INTERNET_API_KEYWORDS
            .iter()
            .any(|keyword| name_lower.contains(keyword))
    }

    pub fn detect_internet_api(&mut self, operation_name: &str, associated_file: Option<String>) {
        let name_lower = operation_name.to_lowercase();

        for keyword in Self::INTERNET_API_KEYWORDS {
            if name_lower.contains(keyword) {
                self.track_api_call(
                    operation_name.to_string(),
                    ApiCategory::Internet,
                    associated_file.clone(),
                );
                self.internet_apis.insert(operation_name.to_string());
                self.update_network_stats_from_api(&name_lower);
                break;
            }
        }
    }

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

    pub fn has_significant_internet_activity(&self) -> bool {
        !self.internet_apis.is_empty()
            || self.network_operations.connections_established > 0
            || self.network_operations.http_requests > 0
            || self.network_operations.dns_queries > 0
    }

    pub fn get_internet_api_summary(&self) -> Vec<String> {
        self.internet_apis.iter().cloned().collect()
    }

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

    pub fn kernel_opcode_counts(&self) -> HashMap<String, usize> {
        HashMap::from([
            ("IrpHypervisorEvent".to_string(), self.kernel_operations.generic_api_call),
            ("IrpProcessHandleOpen".to_string(), self.kernel_operations.process_handle_open),
            (
                "IrpProcessTerminateAttempt".to_string(),
                self.kernel_operations.process_terminate_attempt,
            ),
            ("TotalKernelEvents".to_string(), self.kernel_operations.total_kernel_events),
        ])
    }
}
