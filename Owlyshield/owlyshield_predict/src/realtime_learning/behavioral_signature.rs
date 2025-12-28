//! Behavioral Signature Detection Engine
//!
//! Detects malware based on specific combinations of API calls and behaviors

use crate::realtime_learning::api_tracker::ApiTracker;
use crate::process::ProcessRecord;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::fs;

/// Threat levels for detected behaviors
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// A behavioral signature match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub signature_name: String,
    pub description: String,
    pub threat_level: ThreatLevel,
    pub confidence: f32,
    pub matched_behaviors: Vec<String>,
    pub recommended_action: String,
}

/// A behavioral signature definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSignature {
    pub name: String,
    pub description: String,
    pub threat_level: ThreatLevel,

    // Required API categories (at least one API from each category must be present)
    pub required_api_categories: Vec<String>,

    // Specific APIs that must be present
    pub required_apis: Vec<String>,

    // Behavioral requirements
    pub min_files_written: Option<usize>,
    pub min_files_deleted: Option<usize>,
    pub min_files_encrypted: Option<usize>, // High entropy writes
    pub requires_mass_file_ops: Option<bool>,
    pub requires_network_activity: Option<bool>,
    pub requires_process_injection: Option<bool>,
    pub requires_privilege_escalation: Option<bool>,

    // DLL requirements
    pub required_dlls: Vec<String>,
    pub suspicious_dll_patterns: Vec<String>,

    // File extension patterns
    pub suspicious_extensions: Vec<String>,

    // API sequence requirements (ordered pairs)
    pub required_api_sequences: Vec<(String, String)>,

    // Minimum confidence threshold (0.0 - 1.0)
    pub min_confidence: f32,
}

/// Signature detection engine
pub struct SignatureEngine {
    signatures: Vec<BehavioralSignature>,
    #[allow(dead_code)]
    malapi_categories: MalApiCategories,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalApiCategories {
    pub enumeration: Vec<String>,
    pub injection: Vec<String>,
    pub evasion: Vec<String>,
    pub spying: Vec<String>,
    pub internet: Vec<String>,
    #[serde(rename = "anti-debugging")]
    pub anti_debugging: Vec<String>,
    pub ransomware: Vec<String>,
    pub helper: Vec<String>,
}

impl SignatureEngine {
    /// Create a new signature engine with default signatures
    pub fn new(malapi_json_path: &str) -> Self {
        // Load malapi.json
        let malapi_categories = Self::load_malapi_categories(malapi_json_path);

        // Load default signatures
        let signatures = Self::create_default_signatures();

        SignatureEngine {
            signatures,
            malapi_categories,
        }
    }

    /// Load malapi.json categories
    fn load_malapi_categories(path: &str) -> MalApiCategories {
        match fs::read_to_string(path) {
            Ok(content) => {
                serde_json::from_str(&content).unwrap_or_else(|_| MalApiCategories {
                    enumeration: vec![],
                    injection: vec![],
                    evasion: vec![],
                    spying: vec![],
                    internet: vec![],
                    anti_debugging: vec![],
                    ransomware: vec![],
                    helper: vec![],
                })
            }
            Err(_) => MalApiCategories {
                enumeration: vec![],
                injection: vec![],
                evasion: vec![],
                spying: vec![],
                internet: vec![],
                anti_debugging: vec![],
                ransomware: vec![],
                helper: vec![],
            },
        }
    }

    /// Create default behavioral signatures
    fn create_default_signatures() -> Vec<BehavioralSignature> {
        vec![
            // Ransomware signature
            BehavioralSignature {
                name: "Ransomware Behavior".to_string(),
                description: "Exhibits typical ransomware behavior: mass file encryption, deletion, and network C2 communication".to_string(),
                threat_level: ThreatLevel::Critical,
                required_api_categories: vec!["ransomware".to_string()],
                required_apis: vec![],
                min_files_written: Some(50),
                min_files_deleted: Some(10),
                min_files_encrypted: Some(30),
                requires_mass_file_ops: Some(true),
                requires_network_activity: Some(true),
                requires_process_injection: None,
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec![],
                suspicious_extensions: vec![],
                required_api_sequences: vec![
                    ("CryptAcquireContextA".to_string(), "CryptGenRandom".to_string()),
                    ("CryptDeriveKey".to_string(), "CryptEncrypt".to_string()),
                ],
                min_confidence: 0.7,
            },

            // RAT (Remote Access Trojan) signature
            BehavioralSignature {
                name: "RAT Behavior".to_string(),
                description: "Remote Access Trojan: keylogging, screen capture, network communication, and process injection".to_string(),
                threat_level: ThreatLevel::Critical,
                required_api_categories: vec!["spying".to_string(), "internet".to_string(), "injection".to_string()],
                required_apis: vec![
                    "GetAsyncKeyState".to_string(),
                    "SetWindowsHookExA".to_string(),
                ],
                min_files_written: None,
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: Some(true),
                requires_process_injection: Some(true),
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec!["user32".to_string(), "ws2_32".to_string()],
                suspicious_extensions: vec![],
                required_api_sequences: vec![
                    ("VirtualAllocEx".to_string(), "WriteProcessMemory".to_string()),
                    ("WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()),
                ],
                min_confidence: 0.75,
            },

            // Process Injection signature
            BehavioralSignature {
                name: "Process Injection".to_string(),
                description: "Attempts to inject code into other processes".to_string(),
                threat_level: ThreatLevel::High,
                required_api_categories: vec!["injection".to_string()],
                required_apis: vec![
                    "VirtualAllocEx".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ],
                min_files_written: None,
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: None,
                requires_process_injection: Some(true),
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec![],
                suspicious_extensions: vec![],
                required_api_sequences: vec![
                    ("OpenProcess".to_string(), "VirtualAllocEx".to_string()),
                    ("WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()),
                ],
                min_confidence: 0.8,
            },

            // Credential Stealer signature
            BehavioralSignature {
                name: "Credential Theft".to_string(),
                description: "Attempts to steal credentials from memory or files".to_string(),
                threat_level: ThreatLevel::Critical,
                required_api_categories: vec!["enumeration".to_string(), "helper".to_string()],
                required_apis: vec![
                    "ReadProcessMemory".to_string(),
                ],
                min_files_written: None,
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: Some(true),
                requires_process_injection: None,
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec!["lsasrv".to_string(), "samlib".to_string()],
                suspicious_extensions: vec![],
                required_api_sequences: vec![],
                min_confidence: 0.65,
            },

            // Backdoor signature
            BehavioralSignature {
                name: "Backdoor Installation".to_string(),
                description: "Creates persistence mechanisms and network backdoors".to_string(),
                threat_level: ThreatLevel::Critical,
                required_api_categories: vec!["internet".to_string(), "helper".to_string()],
                required_apis: vec![],
                min_files_written: Some(1),
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: Some(true),
                requires_process_injection: None,
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec!["ws2_32".to_string()],
                suspicious_extensions: vec!["exe".to_string(), "dll".to_string()],
                required_api_sequences: vec![
                    ("CreateFileA".to_string(), "WriteFile".to_string()),
                    ("RegCreateKeyExA".to_string(), "RegSetValueExA".to_string()),
                ],
                min_confidence: 0.7,
            },

            // Rootkit signature
            BehavioralSignature {
                name: "Rootkit Behavior".to_string(),
                description: "Attempts to hide presence through driver installation or system modification".to_string(),
                threat_level: ThreatLevel::Critical,
                required_api_categories: vec!["helper".to_string(), "evasion".to_string()],
                required_apis: vec![],
                min_files_written: None,
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: None,
                requires_process_injection: None,
                requires_privilege_escalation: Some(true),
                required_dlls: vec![],
                suspicious_dll_patterns: vec![],
                suspicious_extensions: vec!["sys".to_string()],
                required_api_sequences: vec![],
                min_confidence: 0.8,
            },

            // Banking Trojan signature
            BehavioralSignature {
                name: "Banking Trojan".to_string(),
                description: "Keylogging, browser hooking, and network communication typical of banking trojans".to_string(),
                threat_level: ThreatLevel::Critical,
                required_api_categories: vec!["spying".to_string(), "internet".to_string()],
                required_apis: vec![
                    "GetAsyncKeyState".to_string(),
                    "GetForegroundWindow".to_string(),
                ],
                min_files_written: None,
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: Some(true),
                requires_process_injection: Some(true),
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec!["wininet".to_string(), "urlmon".to_string()],
                suspicious_extensions: vec![],
                required_api_sequences: vec![
                    ("SetWindowsHookExA".to_string(), "CallNextHookEx".to_string()),
                ],
                min_confidence: 0.7,
            },

            // Anti-Analysis signature
            BehavioralSignature {
                name: "Anti-Analysis Techniques".to_string(),
                description: "Uses anti-debugging and anti-VM techniques".to_string(),
                threat_level: ThreatLevel::High,
                required_api_categories: vec!["anti-debugging".to_string(), "evasion".to_string()],
                required_apis: vec![],
                min_files_written: None,
                min_files_deleted: None,
                min_files_encrypted: None,
                requires_mass_file_ops: None,
                requires_network_activity: None,
                requires_process_injection: None,
                requires_privilege_escalation: None,
                required_dlls: vec![],
                suspicious_dll_patterns: vec![],
                suspicious_extensions: vec![],
                required_api_sequences: vec![],
                min_confidence: 0.6,
            },
        ]
    }

    /// Check if a process matches any behavioral signatures
    pub fn check_behavior(&self, api_tracker: &ApiTracker, precord: &ProcessRecord) -> Option<SignatureMatch> {
        for signature in &self.signatures {
            if let Some(match_result) = self.check_signature(signature, api_tracker, precord) {
                return Some(match_result);
            }
        }
        None
    }

    /// Check a specific signature against a process
    fn check_signature(
        &self,
        signature: &BehavioralSignature,
        api_tracker: &ApiTracker,
        _precord: &ProcessRecord,
    ) -> Option<SignatureMatch> {
        let mut matched_behaviors = Vec::new();
        let mut confidence_score = 0.0;
        let mut total_checks = 0.0;

        // Check required API categories
        for category in &signature.required_api_categories {
            total_checks += 1.0;
            if self.has_api_category(api_tracker, category) {
                confidence_score += 1.0;
                matched_behaviors.push(format!("Uses {} APIs", category));
            }
        }

        // Check required APIs
        if !signature.required_apis.is_empty() {
            total_checks += 1.0;
            let matched_apis = self.count_matched_apis(api_tracker, &signature.required_apis);
            if matched_apis > 0 {
                let api_confidence = matched_apis as f32 / signature.required_apis.len() as f32;
                confidence_score += api_confidence;
                matched_behaviors.push(format!("Uses {} specific malicious APIs", matched_apis));
            }
        }

        // Check file operations
        if let Some(min_written) = signature.min_files_written {
            total_checks += 1.0;
            if api_tracker.file_operations.files_written >= min_written {
                confidence_score += 1.0;
                matched_behaviors.push(format!("Wrote {} files", api_tracker.file_operations.files_written));
            }
        }

        if let Some(min_deleted) = signature.min_files_deleted {
            total_checks += 1.0;
            if api_tracker.file_operations.files_deleted >= min_deleted {
                confidence_score += 1.0;
                matched_behaviors.push(format!("Deleted {} files", api_tracker.file_operations.files_deleted));
            }
        }

        if let Some(min_encrypted) = signature.min_files_encrypted {
            total_checks += 1.0;
            if api_tracker.file_operations.files_encrypted >= min_encrypted {
                confidence_score += 1.0;
                matched_behaviors.push(format!("Encrypted {} files", api_tracker.file_operations.files_encrypted));
            }
        }

        // Check behavioral requirements
        if let Some(requires_mass) = signature.requires_mass_file_ops {
            if requires_mass {
                total_checks += 1.0;
                if api_tracker.file_operations.mass_file_operations {
                    confidence_score += 1.0;
                    matched_behaviors.push("Mass file operations detected".to_string());
                }
            }
        }

        if let Some(requires_network) = signature.requires_network_activity {
            if requires_network {
                total_checks += 1.0;
                if api_tracker.internet_apis.len() > 0 {
                    confidence_score += 1.0;
                    matched_behaviors.push("Network activity detected".to_string());
                }
            }
        }

        if let Some(requires_injection) = signature.requires_process_injection {
            if requires_injection {
                total_checks += 1.0;
                if api_tracker.process_operations.processes_injected > 0
                    || self.has_injection_pattern(api_tracker) {
                    confidence_score += 1.0;
                    matched_behaviors.push("Process injection detected".to_string());
                }
            }
        }

        // Check API sequences
        if !signature.required_api_sequences.is_empty() {
            total_checks += 1.0;
            if api_tracker.has_api_sequence(&signature.required_api_sequences) {
                confidence_score += 1.0;
                matched_behaviors.push("Malicious API sequence detected".to_string());
            }
        }

        // Calculate final confidence
        let final_confidence = if total_checks > 0.0 {
            confidence_score / total_checks
        } else {
            0.0
        };

        // Return match if confidence is above threshold
        if final_confidence >= signature.min_confidence {
            Some(SignatureMatch {
                signature_name: signature.name.clone(),
                description: signature.description.clone(),
                threat_level: signature.threat_level,
                confidence: final_confidence,
                matched_behaviors,
                recommended_action: self.get_recommended_action(signature.threat_level),
            })
        } else {
            None
        }
    }

    /// Get all matched signatures for a process
    pub fn get_matched_signatures(&self, api_tracker: &ApiTracker) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        // We need a dummy ProcessRecord for this method
        // In real usage, this should be provided
        let dummy_precord = ProcessRecord::new(
            api_tracker.gid,
            String::new(),
            std::path::PathBuf::new(),
        );

        for signature in &self.signatures {
            if let Some(match_result) = self.check_signature(signature, api_tracker, &dummy_precord) {
                matches.push(match_result);
            }
        }

        matches
    }

    fn has_api_category(&self, api_tracker: &ApiTracker, category: &str) -> bool {
        match category {
            "enumeration" => !api_tracker.enumeration_apis.is_empty(),
            "injection" => !api_tracker.injection_apis.is_empty(),
            "evasion" => !api_tracker.evasion_apis.is_empty(),
            "spying" => !api_tracker.spying_apis.is_empty(),
            "internet" => !api_tracker.internet_apis.is_empty(),
            "anti-debugging" => !api_tracker.anti_debugging_apis.is_empty(),
            "ransomware" => !api_tracker.ransomware_apis.is_empty(),
            "helper" => !api_tracker.helper_apis.is_empty(),
            _ => false,
        }
    }

    fn count_matched_apis(&self, api_tracker: &ApiTracker, required_apis: &[String]) -> usize {
        let all_apis: HashSet<String> = api_tracker.enumeration_apis.iter()
            .chain(api_tracker.injection_apis.iter())
            .chain(api_tracker.evasion_apis.iter())
            .chain(api_tracker.spying_apis.iter())
            .chain(api_tracker.internet_apis.iter())
            .chain(api_tracker.anti_debugging_apis.iter())
            .chain(api_tracker.ransomware_apis.iter())
            .chain(api_tracker.helper_apis.iter())
            .cloned()
            .collect();

        required_apis.iter()
            .filter(|api| all_apis.contains(*api))
            .count()
    }

    fn has_injection_pattern(&self, api_tracker: &ApiTracker) -> bool {
        let injection_apis = vec![
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"
        ];

        let matched = injection_apis.iter()
            .filter(|api| api_tracker.injection_apis.contains(&api.to_string()))
            .count();

        matched >= 2
    }

    fn get_recommended_action(&self, threat_level: ThreatLevel) -> String {
        match threat_level {
            ThreatLevel::Low => "Monitor and log activity".to_string(),
            ThreatLevel::Medium => "Alert user and increase monitoring".to_string(),
            ThreatLevel::High => "Suspend process and alert user".to_string(),
            ThreatLevel::Critical => "Terminate process immediately and quarantine".to_string(),
        }
    }

    /// Add a custom signature
    pub fn add_signature(&mut self, signature: BehavioralSignature) {
        self.signatures.push(signature);
    }

    /// Load signatures from JSON file
    pub fn load_signatures_from_file(&mut self, path: &str) -> Result<(), std::io::Error> {
        let content = fs::read_to_string(path)?;
        let signatures: Vec<BehavioralSignature> = serde_json::from_str(&content)?;
        self.signatures.extend(signatures);
        Ok(())
    }
}
