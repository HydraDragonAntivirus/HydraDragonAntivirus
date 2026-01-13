//! Machine Learning Data Collection Module
//!
//! Collects comprehensive behavioral data for ML model training

use crate::realtime_learning::api_tracker::ApiTracker;
use crate::process::ProcessRecord;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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
    pub dlls_loaded: Vec<String>,
    pub operation_sequence: Vec<String>,
    pub api_call_sequence: Vec<(String, String)>, // (API, category)
    pub entropy_samples: Vec<f64>,
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

        // Extract raw data
        let raw_data = self.extract_raw_data(api_tracker, precord);

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
    fn extract_raw_data(&self, api_tracker: &ApiTracker, precord: &ProcessRecord) -> RawBehaviorData {
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

        let file_paths_accessed: Vec<String> = precord.fpaths_created.iter()
            .chain(precord.fpaths_updated.iter())
            .cloned()
            .collect();

        let api_call_sequence: Vec<(String, String)> = api_tracker.api_sequence.iter()
            .map(|call| (call.name.clone(), format!("{:?}", call.category)))
            .collect();

        RawBehaviorData {
            all_apis_used,
            file_paths_accessed,
            dlls_loaded: api_tracker.dlls_loaded.iter().cloned().collect(),
            operation_sequence: vec![], // Could be populated from operation_sequence
            api_call_sequence,
            entropy_samples: vec![], // Could collect entropy values over time
        }
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

        self.export_to_json(json_path.to_str().unwrap()).ok();
        self.export_to_csv(csv_path.to_str().unwrap()).ok();
    }

    /// Clear all collected samples
    pub fn clear(&mut self) {
        self.malicious_samples.clear();
        self.benign_samples.clear();
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
