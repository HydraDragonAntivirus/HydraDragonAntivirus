//! Machine Learning Data Collection Module
//!
//! Collects comprehensive behavioral data for ML model training

use crate::realtime_learning::api_tracker::{ApiTracker, OperationType};
use crate::process::ProcessRecord;
#[cfg(feature = "behavior_engine")]
use crate::behavioral::behavior_engine::{BehaviorRule, DetectionCondition, NamedConditionGroup};
#[cfg(target_os = "windows")]
use crate::signature_verification::verify_signature;
use md5::{Digest as Md5Digest, Md5};
use serde::{Serialize, Deserialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;
use win_pe_inspection::inspect_pe;

/// Data collection modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionMode {
    /// Collect only malicious samples
    MaliciousOnly,
    /// Collect only benign samples
    BenignOnly,
    /// Collect both malicious and benign samples
    Both,
}

/// Machine learning dataset collector
pub struct MLCollector {
    /// Collection mode
    mode: CollectionMode,
    /// Collected malicious samples
    malicious_samples: Vec<MLSample>,
    /// Collected benign samples
    benign_samples: Vec<MLSample>,
    /// Feature extractors
    feature_extractor: FeatureExtractor,
    /// Auto-save threshold (number of samples before auto-save)
    auto_save_threshold: usize,
    /// Output directory for datasets
    output_dir: PathBuf,
    /// Cache executable telemetry by exe path to avoid reparsing PE on every sample
    executable_cache: HashMap<String, ExecutableTelemetry>,
    /// API names loaded from models/malapi.json
    malapi_api_set: HashSet<String>,
}

/// A single ML sample with features and label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLSample {
    /// Unique sample ID (GID)
    pub id: u64,
    /// Process name
    pub process_name: String,
    /// Executable path
    pub exe_path: String,
    /// Label (true = malicious, false = benign)
    pub is_malicious: bool,
    /// Timestamp of collection
    pub timestamp: std::time::SystemTime,
    /// Feature vector
    pub features: MLFeatures,
    /// Raw API usage data
    pub raw_data: RawBehaviorData,
}

/// Comprehensive feature set for ML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLFeatures {
    // API usage features (normalized counts)
    pub enumeration_api_count: f32,
    pub injection_api_count: f32,
    pub evasion_api_count: f32,
    pub spying_api_count: f32,
    pub internet_api_count: f32,
    pub anti_debugging_api_count: f32,
    pub ransomware_api_count: f32,
    pub helper_api_count: f32,
    pub total_api_count: f32,

    // File operation features
    pub files_read: f32,
    pub files_written: f32,
    pub files_deleted: f32,
    pub files_renamed: f32,
    pub files_encrypted: f32,
    pub directories_enumerated: f32,
    pub mass_file_operations: f32, // 0.0 or 1.0

    // File characteristics
    pub executable_files_accessed: f32,
    pub suspicious_extensions_written: f32,
    pub avg_entropy_written: f32,
    pub high_entropy_writes: f32,

    // Registry features
    pub registry_keys_created: f32,
    pub registry_keys_deleted: f32,
    pub registry_keys_modified: f32,
    pub autorun_keys_modified: f32, // 0.0 or 1.0
    pub security_keys_accessed: f32, // 0.0 or 1.0

    // Network features
    pub network_connections: f32,
    pub data_sent_kb: f32,
    pub data_received_kb: f32,
    pub dns_queries: f32,
    pub http_requests: f32,
    pub suspicious_ports_used: f32, // 0.0 or 1.0

    // Process features
    pub processes_created: f32,
    pub processes_injected: f32,
    pub threads_created: f32,
    pub memory_allocated_mb: f32,
    pub privileges_escalated: f32, // 0.0 or 1.0

    // DLL features
    pub dlls_loaded: f32,
    pub suspicious_dlls_loaded: f32,

    // Behavioral patterns (binary features)
    pub has_keylogging_pattern: f32, // 0.0 or 1.0
    pub has_injection_pattern: f32,
    pub has_persistence_pattern: f32,
    pub has_anti_analysis_pattern: f32,
    pub has_credential_theft_pattern: f32,

    // Temporal features
    pub execution_time_seconds: f32,
    pub operations_per_second: f32,

    // Statistical features
    pub unique_file_extensions_read: f32,
    pub unique_file_extensions_written: f32,
    pub unique_directories_accessed: f32,
    pub file_operation_diversity: f32, // Entropy of operation types

    // Advanced features
    pub api_sequence_complexity: f32,
    pub dll_diversity: f32,
    pub network_diversity: f32,
}

/// Raw behavioral data for detailed analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBehaviorData {
    pub all_apis_used: Vec<String>,
    pub file_paths_accessed: Vec<String>,
    pub file_telemetry: Vec<String>,
    pub dlls_loaded: Vec<String>,
    pub operation_sequence: Vec<String>,
    pub api_call_sequence: Vec<(String, String)>, // (API, category)
    pub entropy_samples: Vec<f64>,
    pub kernel_event_log: Vec<String>,
    pub irp_opcode_counts: HashMap<String, usize>,
    pub loaded_kernel_drivers: Vec<String>,
    pub executable_telemetry: ExecutableTelemetry,
    #[cfg(feature = "behavior_engine")]
    pub rule_format_rule: BehaviorRule,
}

/// Static executable telemetry captured from on-disk binary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutableTelemetry {
    pub executable_path: String,
    pub path_exists: bool,
    pub file_size_bytes: u64,
    pub file_created_unix: Option<u64>,
    pub file_modified_unix: Option<u64>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub binary_entropy: Option<f64>,
    pub is_pe_file: bool,
    pub section_count: usize,
    pub import_count: usize,
    pub imported_dll_count: usize,
    pub imported_api_count: usize,
    pub imported_dlls: Vec<String>,
    pub imported_apis: Vec<String>,
    pub imported_apis_truncated: bool,
    pub suspicious_import_hits: Vec<String>,
    pub has_network_imports: bool,
    pub has_process_injection_imports: bool,
    pub has_crypto_imports: bool,
    pub has_persistence_imports: bool,
    pub has_anti_analysis_imports: bool,
    pub has_debug_symbols: bool,
    pub is_signed: Option<bool>,
    pub is_trusted_signed: Option<bool>,
    pub signer_name: Option<String>,
    pub parse_error: Option<String>,
}

/// Feature extractor
pub struct FeatureExtractor {
    // Normalization parameters (can be learned from data)
    max_api_count: f32,
    max_file_operations: f32,
    max_network_operations: f32,
}

impl MLCollector {
    /// Create a new ML collector
    pub fn new() -> Self {
        MLCollector {
            mode: CollectionMode::Both,
            malicious_samples: Vec::new(),
            benign_samples: Vec::new(),
            feature_extractor: FeatureExtractor::new(),
            auto_save_threshold: 100,
            output_dir: PathBuf::from("./ml_data"),
            executable_cache: HashMap::new(),
            malapi_api_set: Self::load_malapi_api_set(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(mode: CollectionMode, output_dir: PathBuf, auto_save_threshold: usize) -> Self {
        // Create output directory if it doesn't exist
        std::fs::create_dir_all(&output_dir).ok();

        MLCollector {
            mode,
            malicious_samples: Vec::new(),
            benign_samples: Vec::new(),
            feature_extractor: FeatureExtractor::new(),
            auto_save_threshold,
            output_dir,
            executable_cache: HashMap::new(),
            malapi_api_set: Self::load_malapi_api_set(),
        }
    }

    /// Collect a sample from a process
    pub fn collect_sample(&mut self, api_tracker: &ApiTracker, precord: &ProcessRecord, is_malicious: bool) {
        // Check if we should collect this sample based on mode
        match self.mode {
            CollectionMode::MaliciousOnly if !is_malicious => return,
            CollectionMode::BenignOnly if is_malicious => return,
            _ => {}
        }

        // Extract features
        let features = self.feature_extractor.extract_features(api_tracker, precord);

        // Extract executable telemetry and raw data
        let executable_telemetry = self.get_executable_telemetry(precord);
        let raw_data = self.extract_raw_data(api_tracker, precord, executable_telemetry);

        // Create sample
        let sample = MLSample {
            id: api_tracker.gid,
            process_name: api_tracker.process_name.clone(),
            exe_path: precord.exepath.to_string_lossy().to_string(),
            is_malicious,
            timestamp: std::time::SystemTime::now(),
            features,
            raw_data,
        };

        // Add to appropriate collection
        if is_malicious {
            self.malicious_samples.push(sample);
        } else {
            self.benign_samples.push(sample);
        }

        // Auto-save if threshold reached
        if self.auto_save_threshold > 0 && self.total_samples() % self.auto_save_threshold == 0 && self.total_samples() > 0 {
            self.auto_save();
        }
    }

    /// Extract raw behavioral data
    fn extract_raw_data(&self, api_tracker: &ApiTracker, precord: &ProcessRecord, executable_telemetry: ExecutableTelemetry) -> RawBehaviorData {
        let all_apis_used: Vec<String> = api_tracker.enumeration_apis.iter()
            .chain(api_tracker.injection_apis.iter())
            .chain(api_tracker.evasion_apis.iter())
            .chain(api_tracker.spying_apis.iter())
            .chain(api_tracker.internet_apis.iter())
            .chain(api_tracker.anti_debugging_apis.iter())
            .chain(api_tracker.ransomware_apis.iter())
            .chain(api_tracker.helper_apis.iter())
            .cloned()
            .collect();

        let mut file_paths_accessed: HashSet<String> = precord.fpaths_created.iter()
            .chain(precord.fpaths_updated.iter())
            .cloned()
            .collect();
        file_paths_accessed.extend(api_tracker.file_operations.executable_files_accessed.iter().cloned());
        file_paths_accessed.extend(api_tracker.dlls_loaded.iter().cloned());

        let mut file_telemetry = Vec::new();
        let mut operation_sequence = Vec::with_capacity(api_tracker.operation_sequence.len());
        for op in &api_tracker.operation_sequence {
            let rendered = match op {
                OperationType::FileRead(path) => {
                    file_paths_accessed.insert(path.clone());
                    let line = format!("FILE_READ:{path}");
                    file_telemetry.push(line.clone());
                    line
                }
                OperationType::FileWrite(path, entropy) => {
                    file_paths_accessed.insert(path.clone());
                    let line = format!("FILE_WRITE:{path}:{entropy:.4}");
                    file_telemetry.push(line.clone());
                    line
                }
                OperationType::FileDelete(path) => {
                    file_paths_accessed.insert(path.clone());
                    let line = format!("FILE_DELETE:{path}");
                    file_telemetry.push(line.clone());
                    line
                }
                OperationType::FileRename(src, dst) => {
                    if !src.is_empty() {
                        file_paths_accessed.insert(src.clone());
                    }
                    if !dst.is_empty() {
                        file_paths_accessed.insert(dst.clone());
                    }
                    let line = format!("FILE_RENAME:{src}->{dst}");
                    file_telemetry.push(line.clone());
                    line
                }
                OperationType::ProcessCreate(name) => format!("PROC_CREATE:{name}"),
                OperationType::ProcessTerminate(pid) => format!("PROC_TERM:{pid}"),
                OperationType::ProcessTerminateAttempt { source_pid, target_pid } => {
                    format!("PROC_TERM_ATTEMPT:{source_pid}->{target_pid}")
                }
                OperationType::ProcessHandleOpen { source_pid, target_pid } => {
                    format!("PROC_HANDLE_OPEN:{source_pid}->{target_pid}")
                }
                OperationType::MemoryAllocate(sz) => format!("MEM_ALLOC:{sz}"),
                OperationType::NetworkConnect(dest) => format!("NET_CONNECT:{dest}"),
                OperationType::RegistryModify(key) => format!("REG_MOD:{key}"),
                OperationType::KernelApi {
                    opcode,
                    api,
                    raw_event_type,
                    source_pid,
                    target_pid,
                    arg1,
                    arg2,
                    arg3,
                    arg4,
                    size,
                    status,
                } => {
                    format!(
                        "KERNEL_API:{opcode}:{api}:raw_event_type={raw_event_type}:src={source_pid}:target={target_pid}:arg1=0x{arg1:X}:arg2=0x{arg2:X}:arg3=0x{arg3:X}:arg4=0x{arg4:X}:size={size}:status={status}"
                    )
                }
                OperationType::DriverLoad(path) => format!("DRIVER_LOAD:{path}"),
            };
            operation_sequence.push(rendered);
        }

        let mut file_paths_accessed: Vec<String> = file_paths_accessed.into_iter().collect();
        file_paths_accessed.sort_unstable();

        let mut entropy_samples: Vec<f64> = api_tracker.operation_sequence.iter()
            .filter_map(|op| match op {
                OperationType::FileWrite(_, entropy) => Some(*entropy),
                _ => None,
            })
            .collect();
        if entropy_samples.is_empty() && precord.ops_written > 0 {
            entropy_samples.push(precord.entropy_written / precord.ops_written as f64);
        }

        let mut dlls: HashSet<String> = api_tracker.dlls_loaded.iter().cloned().collect();
        for dll in &executable_telemetry.imported_dlls {
            dlls.insert(dll.clone());
        }

        let api_call_sequence: Vec<(String, String)> = api_tracker.api_sequence.iter()
            .map(|call| (call.name.clone(), format!("{:?}", call.category)))
            .collect();

        #[cfg(feature = "behavior_engine")]
        let rule_format_rule = self.build_rule_format_rule(
            api_tracker,
            precord,
            &all_apis_used,
            &file_paths_accessed,
            &file_telemetry,
        );

        RawBehaviorData {
            all_apis_used,
            file_paths_accessed,
            file_telemetry,
            dlls_loaded: dlls.into_iter().collect(),
            operation_sequence,
            api_call_sequence,
            entropy_samples,
            kernel_event_log: api_tracker.kernel_event_log.clone(),
            irp_opcode_counts: api_tracker.kernel_opcode_counts(),
            loaded_kernel_drivers: api_tracker.kernel_operations.loaded_kernel_drivers.iter().cloned().collect(),
            executable_telemetry,
            #[cfg(feature = "behavior_engine")]
            rule_format_rule,
        }
    }

    #[cfg(feature = "behavior_engine")]
    fn build_rule_format_rule(
        &self,
        api_tracker: &ApiTracker,
        precord: &ProcessRecord,
        all_apis_used: &[String],
        file_paths_accessed: &[String],
        _file_telemetry: &[String],
    ) -> BehaviorRule {
        let mut file_operations = HashSet::new();
        let mut registry_keys = HashSet::new();
        let mut registry_operations = HashSet::new();
        let mut network_indicators = HashSet::new();
        let mut created_processes = HashSet::new();
        let mut terminated_processes = HashSet::new();
        let mut file_extensions = HashSet::new();
        let mut hypervisor_event_labels = HashSet::new();
        let mut hypervisor_raw_event_types = HashSet::new();
        let mut hypervisor_source_pids = HashSet::new();
        let mut hypervisor_target_pids = HashSet::new();
        let mut hypervisor_raw_arg1_values = HashSet::new();
        let mut hypervisor_raw_arg2_values = HashSet::new();
        let mut hypervisor_raw_arg3_values = HashSet::new();
        let mut hypervisor_raw_arg4_values = HashSet::new();
        let mut hypervisor_memory_sizes = HashSet::new();
        let mut hypervisor_operation_statuses = HashSet::new();

        for path in file_paths_accessed {
            Self::insert_file_extension(&mut file_extensions, path);
        }

        for ext in &api_tracker.file_operations.suspicious_extensions_written {
            let ext = ext.trim().trim_start_matches('.');
            if !ext.is_empty() {
                file_extensions.insert(format!(".{}", ext.to_ascii_lowercase()));
            }
        }

        for api in &api_tracker.internet_apis {
            if !api.trim().is_empty() {
                network_indicators.insert(api.clone());
            }
        }

        for op in &api_tracker.operation_sequence {
            match op {
                OperationType::FileRead(path) => {
                    file_operations.insert("read".to_string());
                    Self::insert_file_extension(&mut file_extensions, path);
                }
                OperationType::FileWrite(path, _) => {
                    file_operations.insert("write".to_string());
                    Self::insert_file_extension(&mut file_extensions, path);
                }
                OperationType::FileDelete(path) => {
                    file_operations.insert("delete".to_string());
                    Self::insert_file_extension(&mut file_extensions, path);
                }
                OperationType::FileRename(src, dst) => {
                    file_operations.insert("rename".to_string());
                    Self::insert_file_extension(&mut file_extensions, src);
                    Self::insert_file_extension(&mut file_extensions, dst);
                }
                OperationType::ProcessCreate(name) => {
                    if !name.trim().is_empty() {
                        created_processes.insert(name.clone());
                    }
                }
                OperationType::ProcessTerminate(pid) => {
                    terminated_processes.insert(format!("pid:{pid}"));
                }
                OperationType::ProcessTerminateAttempt { target_pid, .. } => {
                    terminated_processes.insert(format!("pid:{target_pid}"));
                }
                OperationType::NetworkConnect(dest) => {
                    if !dest.trim().is_empty() {
                        network_indicators.insert(dest.clone());
                    }
                }
                OperationType::RegistryModify(key) => {
                    let (op_name, reg_key) = Self::split_registry_entry(key);
                    if !reg_key.is_empty() {
                        registry_keys.insert(reg_key);
                    }
                    if let Some(op_name) = op_name {
                        registry_operations.insert(op_name.to_string());
                    }
                }
                OperationType::KernelApi {
                    api,
                    raw_event_type,
                    source_pid,
                    target_pid,
                    arg1,
                    arg2,
                    arg3,
                    arg4,
                    size,
                    status,
                    ..
                } => {
                    if !api.trim().is_empty() {
                        hypervisor_event_labels.insert(api.clone());
                    }
                    hypervisor_raw_event_types.insert(*raw_event_type);
                    if *source_pid != 0 {
                        hypervisor_source_pids.insert(*source_pid);
                    }
                    if *target_pid != 0 {
                        hypervisor_target_pids.insert(*target_pid);
                    }
                    hypervisor_raw_arg1_values.insert(*arg1);
                    hypervisor_raw_arg2_values.insert(*arg2);
                    hypervisor_raw_arg3_values.insert(*arg3);
                    hypervisor_raw_arg4_values.insert(*arg4);
                    if *size != 0 {
                        hypervisor_memory_sizes.insert(*size);
                    }
                    hypervisor_operation_statuses.insert(*status);
                }
                OperationType::ProcessHandleOpen { .. }
                | OperationType::MemoryAllocate(_)
                | OperationType::DriverLoad(_) => {}
            }
        }

        let has_network_activity =
            api_tracker.has_significant_internet_activity() || !network_indicators.is_empty();

        let mut observed_condition = NamedConditionGroup::default();
        observed_condition.apis = all_apis_used.to_vec();
        if !observed_condition.apis.is_empty() {
            observed_condition.api_threshold = 1;
        }
        observed_condition.file_paths = file_paths_accessed.to_vec();
        observed_condition.file_operations = Self::sorted_strings(file_operations);
        observed_condition.registry_keys = Self::sorted_strings(registry_keys);
        observed_condition.registry_operations = Self::sorted_strings(registry_operations);
        observed_condition.network_indicators = Self::sorted_strings(network_indicators);
        observed_condition.has_network_activity = has_network_activity;
        if !precord.appname.trim().is_empty() {
            observed_condition.process_names = vec![precord.appname.clone()];
        }
        observed_condition.created_processes = Self::sorted_strings(created_processes);
        observed_condition.terminated_processes = Self::sorted_strings(terminated_processes);
        observed_condition.file_extensions = Self::sorted_strings(file_extensions);
        observed_condition.cmdline_keywords = Self::extract_cmdline_keywords(&precord.command_line);
        observed_condition.hypervisor_event_labels = Self::sorted_strings(hypervisor_event_labels);
        observed_condition.detect_hypervisor_event = !observed_condition.hypervisor_event_labels.is_empty();
        if observed_condition.detect_hypervisor_event {
            observed_condition.hypervisor_event_threshold = 1;
        }
        observed_condition.hypervisor_raw_event_types = Self::sorted_u32(hypervisor_raw_event_types);
        observed_condition.hypervisor_source_pids = Self::sorted_u32(hypervisor_source_pids);
        observed_condition.hypervisor_target_pids = Self::sorted_u32(hypervisor_target_pids);
        observed_condition.hypervisor_raw_arg1_values = Self::sorted_u64(hypervisor_raw_arg1_values);
        observed_condition.hypervisor_raw_arg2_values = Self::sorted_u64(hypervisor_raw_arg2_values);
        observed_condition.hypervisor_raw_arg3_values = Self::sorted_u64(hypervisor_raw_arg3_values);
        observed_condition.hypervisor_raw_arg4_values = Self::sorted_u64(hypervisor_raw_arg4_values);
        observed_condition.hypervisor_memory_sizes = Self::sorted_u64(hypervisor_memory_sizes);
        observed_condition.hypervisor_operation_statuses = Self::sorted_i32(hypervisor_operation_statuses);

        let mut rule = BehaviorRule::default();
        rule.name = format!("realtime_learning_gid_{}", api_tracker.gid);
        rule.description = format!(
            "Realtime telemetry snapshot for {} ({})",
            precord.appname,
            precord.exepath.display()
        );
        rule.accessed_paths = file_paths_accessed.to_vec();
        rule.require_internet = has_network_activity;
        rule.monitored_apis = all_apis_used.to_vec();
        rule.file_actions = observed_condition.file_operations.clone();
        rule.file_extensions = observed_condition.file_extensions.clone();
        rule.terminated_processes = observed_condition.terminated_processes.clone();
        rule.named_conditions.insert("observed_telemetry".to_string(), observed_condition);
        rule.detection_logic = Some(DetectionCondition::Named {
            condition: "observed_telemetry".to_string(),
        });
        rule
    }

    #[cfg(feature = "behavior_engine")]
    fn sorted_strings(values: HashSet<String>) -> Vec<String> {
        let mut values: Vec<String> = values
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect();
        values.sort_unstable();
        values
    }

    #[cfg(feature = "behavior_engine")]
    fn sorted_u32(values: HashSet<u32>) -> Vec<u32> {
        let mut values: Vec<u32> = values.into_iter().collect();
        values.sort_unstable();
        values
    }

    #[cfg(feature = "behavior_engine")]
    fn sorted_u64(values: HashSet<u64>) -> Vec<u64> {
        let mut values: Vec<u64> = values.into_iter().collect();
        values.sort_unstable();
        values
    }

    #[cfg(feature = "behavior_engine")]
    fn sorted_i32(values: HashSet<i32>) -> Vec<i32> {
        let mut values: Vec<i32> = values.into_iter().collect();
        values.sort_unstable();
        values
    }

    #[cfg(feature = "behavior_engine")]
    fn split_registry_entry(entry: &str) -> (Option<&'static str>, String) {
        let trimmed = entry.trim();
        if let Some(rest) = trimmed.strip_prefix("REG_CREATE:") {
            return (Some("create"), rest.to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("REG_SET:") {
            return (Some("set"), rest.to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("REG_DELETE:") {
            return (Some("delete"), rest.to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("REG_RENAME:") {
            return (Some("rename"), rest.to_string());
        }
        (None, trimmed.to_string())
    }

    #[cfg(feature = "behavior_engine")]
    fn insert_file_extension(extensions: &mut HashSet<String>, path: &str) {
        let Some(ext) = Path::new(path).extension().and_then(|value| value.to_str()) else {
            return;
        };
        let ext = ext.trim().trim_start_matches('.');
        if ext.is_empty() {
            return;
        }
        extensions.insert(format!(".{}", ext.to_ascii_lowercase()));
    }

    #[cfg(feature = "behavior_engine")]
    fn extract_cmdline_keywords(command_line: &str) -> Vec<String> {
        let mut values = HashSet::new();
        let trimmed = command_line.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        values.insert(trimmed.to_string());
        for token in trimmed
            .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';'))
            .map(str::trim)
            .filter(|token| token.len() >= 3)
        {
            values.insert(token.to_string());
        }

        Self::sorted_strings(values)
    }

    fn get_executable_telemetry(&mut self, precord: &ProcessRecord) -> ExecutableTelemetry {
        let exe_path = precord.exepath.to_string_lossy().to_string();
        if let Some(cached) = self.executable_cache.get(&exe_path) {
            return cached.clone();
        }

        let mut telemetry = ExecutableTelemetry {
            executable_path: exe_path.clone(),
            ..ExecutableTelemetry::default()
        };
        let path = precord.exepath.as_path();
        telemetry.path_exists = path.exists();

        if telemetry.path_exists {
            if let Ok(meta) = std::fs::metadata(path) {
                telemetry.file_size_bytes = meta.len();
                telemetry.file_created_unix = meta.created().ok().and_then(Self::system_time_to_unix);
                telemetry.file_modified_unix = meta.modified().ok().and_then(Self::system_time_to_unix);
            }

            if let Ok(bin) = std::fs::read(path) {
                telemetry.md5 = Some(Self::compute_md5(&bin));
                telemetry.sha256 = Some(Self::compute_sha256(&bin));
                telemetry.binary_entropy = Some(Self::compute_entropy(&bin));
            }

            #[cfg(target_os = "windows")]
            {
                let sig = verify_signature(path);
                telemetry.is_signed = Some(sig.is_signed);
                telemetry.is_trusted_signed = Some(sig.is_trusted);
                telemetry.signer_name = sig.signer_name;
            }

            match inspect_pe(path) {
                Ok(static_features) => {
                    telemetry.is_pe_file = true;
                    telemetry.section_count = static_features.section_table_len;
                    telemetry.import_count = static_features.imports.len();
                    telemetry.has_debug_symbols = static_features.has_dbg_symbols;

                    let mut dlls = HashSet::new();
                    let mut api_entries = Vec::with_capacity(static_features.imports.len().min(4096));
                    let mut suspicious_hits = HashSet::new();
                    for imp in static_features.imports {
                        let dll = imp.lib.trim().to_ascii_lowercase();
                        if !dll.is_empty() {
                            dlls.insert(dll.clone());
                        }
                        let api = imp.import.trim();
                        if !api.is_empty() {
                            if self.is_malapi_import(api) {
                                suspicious_hits.insert(api.to_string());
                            }
                            if dll.is_empty() {
                                if api_entries.len() < 4096 {
                                    api_entries.push(api.to_string());
                                }
                            } else {
                                if api_entries.len() < 4096 {
                                    api_entries.push(format!("{dll}!{api}"));
                                }
                            }
                        }
                    }

                    telemetry.imported_dll_count = dlls.len();
                    telemetry.imported_api_count = telemetry.import_count;
                    telemetry.imported_apis_truncated = telemetry.import_count > api_entries.len();
                    telemetry.imported_dlls = dlls.clone().into_iter().collect();
                    telemetry.imported_apis = api_entries;
                    telemetry.suspicious_import_hits = suspicious_hits.into_iter().collect();
                    telemetry.has_network_imports = telemetry.imported_apis.iter().any(|v| Self::contains_any(v, &["!Internet", "!WinHttp", "!WSA", "!socket", "!connect", "!Dns", "!Http"]));
                    telemetry.has_process_injection_imports = telemetry.imported_apis.iter().any(|v| Self::contains_any(v, &["!VirtualAllocEx", "!WriteProcessMemory", "!CreateRemoteThread", "!NtWriteVirtualMemory", "!NtCreateThreadEx"]));
                    telemetry.has_crypto_imports = telemetry.imported_apis.iter().any(|v| Self::contains_any(v, &["!Crypt", "!BCrypt", "!NCrypt", "!RtlEncrypt"]));
                    telemetry.has_persistence_imports = telemetry.imported_apis.iter().any(|v| Self::contains_any(v, &["!RegSetValue", "!RegCreateKey", "!CreateService", "!StartService", "!SchTasks", "!TaskScheduler"]));
                    telemetry.has_anti_analysis_imports = telemetry.imported_apis.iter().any(|v| Self::contains_any(v, &["!IsDebuggerPresent", "!CheckRemoteDebuggerPresent", "!NtQueryInformationProcess", "!OutputDebugString"]));
                }
                Err(e) => {
                    telemetry.parse_error = Some(e.to_string());
                }
            }
        } else {
            telemetry.parse_error = Some("Executable path does not exist".to_string());
        }

        self.executable_cache.insert(exe_path, telemetry.clone());
        telemetry
    }

    fn system_time_to_unix(t: SystemTime) -> Option<u64> {
        t.duration_since(SystemTime::UNIX_EPOCH).ok().map(|d| d.as_secs())
    }

    fn compute_md5(data: &[u8]) -> String {
        let mut h = Md5::new();
        h.update(data);
        format!("{:x}", h.finalize())
    }

    fn compute_sha256(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        format!("{:x}", h.finalize())
    }

    fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0usize; 256];
        for b in data {
            freq[*b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0f64;
        for &count in &freq {
            if count == 0 {
                continue;
            }
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
        entropy
    }

    fn is_malapi_import(&self, api: &str) -> bool {
        self.malapi_api_set.contains(&api.to_ascii_lowercase())
    }

    fn load_malapi_api_set() -> HashSet<String> {
        let path = Path::new("./models/malapi.json");
        let Ok(content) = std::fs::read_to_string(path) else {
            return HashSet::new();
        };

        let Ok(map) = serde_json::from_str::<HashMap<String, Vec<String>>>(&content) else {
            return HashSet::new();
        };

        let mut set = HashSet::new();
        for apis in map.values() {
            for api in apis {
                let v = api.trim().to_ascii_lowercase();
                if !v.is_empty() {
                    set.insert(v);
                }
            }
        }
        set
    }

    fn contains_any(value: &str, needles: &[&str]) -> bool {
        needles.iter().any(|n| value.contains(n))
    }

    /// Get total number of samples
    pub fn total_samples(&self) -> usize {
        self.malicious_samples.len() + self.benign_samples.len()
    }

    /// Get sample counts
    pub fn get_counts(&self) -> (usize, usize) {
        (self.malicious_samples.len(), self.benign_samples.len())
    }

    /// Export dataset to JSON format
    pub fn export_to_json(&self, output_path: &str) -> Result<(), std::io::Error> {
        let dataset = MLDataset {
            malicious_samples: self.malicious_samples.clone(),
            benign_samples: self.benign_samples.clone(),
            collection_timestamp: std::time::SystemTime::now(),
            total_malicious: self.malicious_samples.len(),
            total_benign: self.benign_samples.len(),
        };

        let json = serde_json::to_string_pretty(&dataset)?;
        let mut file = File::create(output_path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    #[cfg(feature = "behavior_engine")]
    fn collected_rule_snapshots(&self) -> Vec<BehaviorRule> {
        let mut rules = Vec::new();

        for sample in self.malicious_samples.iter().chain(self.benign_samples.iter()) {
            let mut rule = sample.raw_data.rule_format_rule.clone();
            let label = if sample.is_malicious { "malicious" } else { "benign" };
            rule.name = format!("realtime_learning_{}_gid_{}", label, sample.id);
            rule.description = format!(
                "Realtime {} telemetry snapshot for {} ({})",
                label,
                sample.process_name,
                sample.exe_path
            );
            rules.push(rule);
        }

        rules
    }

    #[cfg(feature = "behavior_engine")]
    pub fn export_rules_to_yaml(&self, output_path: &str) -> Result<(), std::io::Error> {
        let rules = self.collected_rule_snapshots();
        let file = File::create(output_path)?;
        serde_yaml::to_writer(file, &rules)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    /// Export to CSV format for easy analysis
    pub fn export_to_csv(&self, output_path: &str) -> Result<(), std::io::Error> {
        let mut file = File::create(output_path)?;

        // Write header
        writeln!(file, "{}", self.get_csv_header())?;

        // Write malicious samples
        for sample in &self.malicious_samples {
            writeln!(file, "{}", self.sample_to_csv(sample))?;
        }

        // Write benign samples
        for sample in &self.benign_samples {
            writeln!(file, "{}", self.sample_to_csv(sample))?;
        }

        Ok(())
    }

    /// Get CSV header
    fn get_csv_header(&self) -> String {
        "id,process_name,is_malicious,\
         enumeration_api_count,injection_api_count,evasion_api_count,spying_api_count,\
         internet_api_count,anti_debugging_api_count,ransomware_api_count,helper_api_count,\
         total_api_count,files_read,files_written,files_deleted,files_renamed,files_encrypted,\
         directories_enumerated,mass_file_operations,executable_files_accessed,\
         suspicious_extensions_written,avg_entropy_written,high_entropy_writes,\
         registry_keys_created,registry_keys_deleted,registry_keys_modified,\
         autorun_keys_modified,network_connections,processes_created,processes_injected,\
         threads_created,memory_allocated_mb,dlls_loaded,has_keylogging_pattern,\
         has_injection_pattern,has_persistence_pattern,operations_per_second".to_string()
    }

    /// Convert sample to CSV row
    fn sample_to_csv(&self, sample: &MLSample) -> String {
        let f = &sample.features;
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            sample.id, sample.process_name, sample.is_malicious as u8,
            f.enumeration_api_count, f.injection_api_count, f.evasion_api_count, f.spying_api_count,
            f.internet_api_count, f.anti_debugging_api_count, f.ransomware_api_count, f.helper_api_count,
            f.total_api_count, f.files_read, f.files_written, f.files_deleted, f.files_renamed,
            f.files_encrypted, f.directories_enumerated, f.mass_file_operations, f.executable_files_accessed,
            f.suspicious_extensions_written, f.avg_entropy_written, f.high_entropy_writes,
            f.registry_keys_created, f.registry_keys_deleted, f.registry_keys_modified,
            f.autorun_keys_modified, f.network_connections, f.processes_created, f.processes_injected,
            f.threads_created, f.memory_allocated_mb, f.dlls_loaded, f.has_keylogging_pattern,
            f.has_injection_pattern, f.has_persistence_pattern, f.operations_per_second
        )
    }

    /// Auto-save datasets
    fn auto_save(&self) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json_path = self.output_dir.join(format!("dataset_{}.json", timestamp));
        let csv_path = self.output_dir.join(format!("dataset_{}.csv", timestamp));
        #[cfg(feature = "behavior_engine")]
        let yaml_path = self.output_dir.join(format!("dataset_rules_{}.yaml", timestamp));

        self.export_to_json(json_path.to_str().unwrap()).ok();
        self.export_to_csv(csv_path.to_str().unwrap()).ok();
        #[cfg(feature = "behavior_engine")]
        self.export_rules_to_yaml(yaml_path.to_str().unwrap()).ok();
    }

    /// Clear all collected samples
    pub fn clear(&mut self) {
        self.malicious_samples.clear();
        self.benign_samples.clear();
        self.executable_cache.clear();
    }

    /// Export separate files for malicious and benign
    pub fn export_separated(&self, malicious_path: &str, benign_path: &str) -> Result<(), std::io::Error> {
        // Export malicious
        let mal_dataset = MLDataset {
            malicious_samples: self.malicious_samples.clone(),
            benign_samples: vec![],
            collection_timestamp: std::time::SystemTime::now(),
            total_malicious: self.malicious_samples.len(),
            total_benign: 0,
        };
        let json = serde_json::to_string_pretty(&mal_dataset)?;
        std::fs::write(malicious_path, json)?;

        // Export benign
        let benign_dataset = MLDataset {
            malicious_samples: vec![],
            benign_samples: self.benign_samples.clone(),
            collection_timestamp: std::time::SystemTime::now(),
            total_malicious: 0,
            total_benign: self.benign_samples.len(),
        };
        let json = serde_json::to_string_pretty(&benign_dataset)?;
        std::fs::write(benign_path, json)?;

        Ok(())
    }
}

impl FeatureExtractor {
    pub fn new() -> Self {
        FeatureExtractor {
            max_api_count: 1000.0,
            max_file_operations: 10000.0,
            max_network_operations: 1000.0,
        }
    }

    /// Extract comprehensive feature vector
    pub fn extract_features(&self, api_tracker: &ApiTracker, precord: &ProcessRecord) -> MLFeatures {
        let execution_time = precord.time_started
            .elapsed()
            .unwrap_or(std::time::Duration::from_secs(1))
            .as_secs_f32();

        let total_ops = precord.ops_read + precord.ops_written + precord.ops_setinfo + precord.ops_open;
        let operations_per_second = total_ops as f32 / execution_time.max(1.0);

        // Calculate average entropy
        let avg_entropy = if precord.ops_written > 0 {
            precord.entropy_written / precord.ops_written as f64
        } else {
            0.0
        };

        // Count high entropy writes (>7.5)
        let high_entropy_writes = if avg_entropy > 7.5 { 1.0 } else { 0.0 };

        // Detect patterns
        let has_keylogging = self.detect_keylogging_pattern(api_tracker);
        let has_injection = self.detect_injection_pattern(api_tracker);
        let has_persistence = self.detect_persistence_pattern(api_tracker);
        let has_anti_analysis = !api_tracker.anti_debugging_apis.is_empty() || !api_tracker.evasion_apis.is_empty();
        let has_credential_theft = self.detect_credential_theft_pattern(api_tracker);

        MLFeatures {
            // Normalized API counts
            enumeration_api_count: self.normalize(api_tracker.enumeration_apis.len() as f32, self.max_api_count),
            injection_api_count: self.normalize(api_tracker.injection_apis.len() as f32, self.max_api_count),
            evasion_api_count: self.normalize(api_tracker.evasion_apis.len() as f32, self.max_api_count),
            spying_api_count: self.normalize(api_tracker.spying_apis.len() as f32, self.max_api_count),
            internet_api_count: self.normalize(api_tracker.internet_apis.len() as f32, self.max_api_count),
            anti_debugging_api_count: self.normalize(api_tracker.anti_debugging_apis.len() as f32, self.max_api_count),
            ransomware_api_count: self.normalize(api_tracker.ransomware_apis.len() as f32, self.max_api_count),
            helper_api_count: self.normalize(api_tracker.helper_apis.len() as f32, self.max_api_count),
            total_api_count: self.normalize(api_tracker.total_api_calls() as f32, self.max_api_count),

            // File operations
            files_read: self.normalize(api_tracker.file_operations.files_read as f32, self.max_file_operations),
            files_written: self.normalize(api_tracker.file_operations.files_written as f32, self.max_file_operations),
            files_deleted: self.normalize(api_tracker.file_operations.files_deleted as f32, self.max_file_operations),
            files_renamed: self.normalize(api_tracker.file_operations.files_renamed as f32, self.max_file_operations),
            files_encrypted: self.normalize(api_tracker.file_operations.files_encrypted as f32, self.max_file_operations),
            directories_enumerated: self.normalize(api_tracker.file_operations.directories_enumerated as f32, self.max_file_operations),
            mass_file_operations: if api_tracker.file_operations.mass_file_operations { 1.0 } else { 0.0 },

            // File characteristics
            executable_files_accessed: api_tracker.file_operations.executable_files_accessed.len() as f32,
            suspicious_extensions_written: api_tracker.file_operations.suspicious_extensions_written.len() as f32,
            avg_entropy_written: avg_entropy as f32,
            high_entropy_writes,

            // Registry
            registry_keys_created: api_tracker.registry_operations.keys_created as f32,
            registry_keys_deleted: api_tracker.registry_operations.keys_deleted as f32,
            registry_keys_modified: api_tracker.registry_operations.keys_modified as f32,
            autorun_keys_modified: if api_tracker.registry_operations.autorun_keys_modified { 1.0 } else { 0.0 },
            security_keys_accessed: if api_tracker.registry_operations.security_keys_accessed { 1.0 } else { 0.0 },

            // Network
            network_connections: self.normalize(api_tracker.network_operations.connections_established as f32, self.max_network_operations),
            data_sent_kb: (api_tracker.network_operations.data_sent as f32) / 1024.0,
            data_received_kb: (api_tracker.network_operations.data_received as f32) / 1024.0,
            dns_queries: api_tracker.network_operations.dns_queries as f32,
            http_requests: api_tracker.network_operations.http_requests as f32,
            suspicious_ports_used: if !api_tracker.network_operations.suspicious_ports.is_empty() { 1.0 } else { 0.0 },

            // Process
            processes_created: api_tracker.process_operations.processes_created as f32,
            processes_injected: api_tracker.process_operations.processes_injected as f32,
            threads_created: api_tracker.process_operations.threads_created as f32,
            memory_allocated_mb: (api_tracker.process_operations.memory_allocated as f32) / (1024.0 * 1024.0),
            privileges_escalated: if api_tracker.process_operations.privileges_escalated { 1.0 } else { 0.0 },

            // DLLs
            dlls_loaded: api_tracker.dlls_loaded.len() as f32,
            suspicious_dlls_loaded: 0.0, // TODO: detect suspicious DLLs

            // Patterns
            has_keylogging_pattern: if has_keylogging { 1.0 } else { 0.0 },
            has_injection_pattern: if has_injection { 1.0 } else { 0.0 },
            has_persistence_pattern: if has_persistence { 1.0 } else { 0.0 },
            has_anti_analysis_pattern: if has_anti_analysis { 1.0 } else { 0.0 },
            has_credential_theft_pattern: if has_credential_theft { 1.0 } else { 0.0 },

            // Temporal
            execution_time_seconds: execution_time,
            operations_per_second,

            // Statistical
            unique_file_extensions_read: precord.extensions_read.categories_set.len() as f32,
            unique_file_extensions_written: precord.extensions_written.categories_set.len() as f32,
            unique_directories_accessed: precord.dirs_with_files_opened.len() as f32,
            file_operation_diversity: self.calculate_operation_diversity(precord),

            // Advanced
            api_sequence_complexity: api_tracker.api_sequence.len() as f32,
            dll_diversity: api_tracker.dlls_loaded.len() as f32,
            network_diversity: api_tracker.internet_apis.len() as f32,
        }
    }

    fn normalize(&self, value: f32, max: f32) -> f32 {
        (value / max).min(1.0)
    }

    fn detect_keylogging_pattern(&self, api_tracker: &ApiTracker) -> bool {
        let keylog_apis = ["GetAsyncKeyState", "SetWindowsHookExA", "GetKeyState"];
        keylog_apis.iter().any(|api| api_tracker.spying_apis.contains(*api))
    }

    fn detect_injection_pattern(&self, api_tracker: &ApiTracker) -> bool {
        let injection_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
        injection_apis.iter().filter(|api| api_tracker.injection_apis.contains(&api.to_string())).count() >= 2
    }

    fn detect_persistence_pattern(&self, api_tracker: &ApiTracker) -> bool {
        let persistence_apis = ["RegCreateKeyExA", "RegSetValueExA", "CreateServiceA"];
        persistence_apis.iter().any(|api| api_tracker.helper_apis.contains(*api))
    }

    fn detect_credential_theft_pattern(&self, api_tracker: &ApiTracker) -> bool {
        api_tracker.helper_apis.contains("ReadProcessMemory")
            && api_tracker.enumeration_apis.contains("CreateToolhelp32Snapshot")
    }

    fn calculate_operation_diversity(&self, precord: &ProcessRecord) -> f32 {
        let total_ops = precord.ops_read + precord.ops_written + precord.ops_setinfo + precord.ops_open;
        if total_ops == 0 {
            return 0.0;
        }

        // Simple diversity metric: ratio of different operation types
        let op_types = [
            precord.ops_read > 0,
            precord.ops_written > 0,
            precord.ops_setinfo > 0,
            precord.ops_open > 0,
        ];

        op_types.iter().filter(|&&x| x).count() as f32 / 4.0
    }
}

/// Complete ML dataset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDataset {
    pub malicious_samples: Vec<MLSample>,
    pub benign_samples: Vec<MLSample>,
    pub collection_timestamp: std::time::SystemTime,
    pub total_malicious: usize,
    pub total_benign: usize,
}






