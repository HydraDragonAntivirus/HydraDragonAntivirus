use crate::signature_verification::SignatureInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::hash::Hash;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Trusted,
    Clean,
    Suspicious,
    Pua,
    Malware,
}

/// SDK-style scan result codes for programmatic integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResultCode {
    Ok = 0,
    Heuristic = 1,
    Malicious = 2,
    Unwanted = 3,
    GeneralError = -1,
    WrongHandle = -2,
    UnknownHandle = -3,
    PathTooLong = -4,
    OpenError = -5,
    FileTooLarge = -6,
    UnsupportedFormat = -7,
}

impl ScanResultCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Heuristic),
            2 => Some(Self::Malicious),
            3 => Some(Self::Unwanted),
            -1 => Some(Self::GeneralError),
            -2 => Some(Self::WrongHandle),
            -3 => Some(Self::UnknownHandle),
            -4 => Some(Self::PathTooLong),
            -5 => Some(Self::OpenError),
            -6 => Some(Self::FileTooLarge),
            -7 => Some(Self::UnsupportedFormat),
            _ => None,
        }
    }

    pub fn is_clean(self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn is_infected(self) -> bool {
        matches!(self, Self::Heuristic | Self::Malicious | Self::Unwanted)
    }

    pub fn is_error(self) -> bool {
        (self as i32) < 0
    }

    pub fn from_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Trusted => Self::Ok,
            Verdict::Clean => Self::Ok,
            Verdict::Suspicious => Self::Heuristic,
            Verdict::Pua => Self::Unwanted,
            Verdict::Malware => Self::Malicious,
        }
    }
}

impl Serialize for ScanResultCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(self.as_i32())
    }
}

impl<'de> Deserialize<'de> for ScanResultCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i32::deserialize(deserializer)?;
        Ok(Self::from_i32(value).unwrap_or(Self::GeneralError))
    }
}

/// SDK-style unpacking/archive extraction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackConfig {
    /// Maximum size of archive being unpacked (bytes)
    pub max_archive_size: u64,
    /// Maximum depth of container extraction
    pub max_archive_depth: u32,
    /// Enable ZIP/archive unpacking
    pub enable_archives: bool,
    /// Enable installer unpacking (NSIS, InnoSetup, etc.)
    pub enable_installers: bool,
    /// Enable container format unpacking (ISO, VHD, etc.)
    pub enable_containers: bool,
    /// Stop checking archive on first detected threat
    pub break_on_threat: bool,
}

impl Default for UnpackConfig {
    fn default() -> Self {
        Self {
            max_archive_size: 2048 * 1024 * 1024, // 2 GB
            max_archive_depth: 5,
            enable_archives: true,
            enable_installers: false,
            enable_containers: false,
            break_on_threat: true,
        }
    }
}

/// SDK-style core initialization options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInitOptions {
    /// Stop checking archive on detected threats
    pub break_archive_scan: bool,
    /// Run core in debug mode with verbose logging
    pub debug_mode: bool,
    /// Load reduced signature base for faster initialization
    pub load_simple: bool,
    /// Enable heuristic analysis
    pub enable_heuristics: bool,
    /// Enable behavioral detection
    pub enable_behavioral: bool,
}

impl Default for CoreInitOptions {
    fn default() -> Self {
        Self {
            break_archive_scan: true,
            debug_mode: false,
            load_simple: false,
            enable_heuristics: true,
            enable_behavioral: true,
        }
    }
}

/// Metadata returned by an initialized static scan core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreData {
    pub engine_version: String,
    pub signature_records: u32,
    pub initialized: bool,
    pub options: CoreInitOptions,
}

impl Default for CoreData {
    fn default() -> Self {
        Self {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            signature_records: 0,
            initialized: false,
            options: CoreInitOptions::default(),
        }
    }
}

/// SDK-style scan statistics and metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Number of objects scanned (including archive members)
    pub files_scanned: u32,
    /// Number of infected objects discovered
    pub infections_found: u32,
    /// Number of suspicious objects discovered
    pub suspicious_found: u32,
    /// Is this file a container/archive
    pub is_container: bool,
    /// Number of archive members extracted
    pub archive_members: u32,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Signature database records used
    pub signature_records_used: u32,
}

impl Default for Verdict {
    fn default() -> Self {
        Self::Clean
    }
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Clean => "CLEAN",
            Self::Suspicious => "SUSPICIOUS",
            Self::Pua => "PUA",
            Self::Malware => "MALWARE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    pub sha256: String,
    pub md5: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeInfo {
    pub primary: String,
    pub tags: Vec<String>,
    pub extension: Option<String>,
    pub is_plain_text: bool,
    pub is_binary: bool,
    pub is_pe: bool,
    pub is_pe32: bool,
    pub is_pe64: bool,
    pub is_elf: bool,
    pub is_elf32: bool,
    pub is_elf64: bool,
    pub is_macho: bool,
    pub is_apk: bool,
    pub is_zip: bool,
    pub is_archive: bool,
    pub is_7z: bool,
    pub is_rar: bool,
    pub is_gzip: bool,
    pub is_tar: bool,
    pub is_jar: bool,
    pub is_dex: bool,
    pub is_java_class: bool,
    pub is_pdf: bool,
    pub is_office: bool,
    pub is_microsoft_compound: bool,
    pub is_script: bool,
    pub is_powershell: bool,
    pub is_batch: bool,
    pub is_javascript: bool,
    pub is_vbs: bool,
    pub is_python: bool,
    pub is_broken_executable: bool,
    pub is_broken_apk: bool,
    pub broken_executable_type: Option<String>,
}

impl Default for FileTypeInfo {
    fn default() -> Self {
        Self {
            primary: "unknown".to_string(),
            tags: Vec::new(),
            extension: None,
            is_plain_text: false,
            is_binary: true,
            is_pe: false,
            is_pe32: false,
            is_pe64: false,
            is_elf: false,
            is_elf32: false,
            is_elf64: false,
            is_macho: false,
            is_apk: false,
            is_zip: false,
            is_archive: false,
            is_7z: false,
            is_rar: false,
            is_gzip: false,
            is_tar: false,
            is_jar: false,
            is_dex: false,
            is_java_class: false,
            is_pdf: false,
            is_office: false,
            is_microsoft_compound: false,
            is_script: false,
            is_powershell: false,
            is_batch: false,
            is_javascript: false,
            is_vbs: false,
            is_python: false,
            is_broken_executable: false,
            is_broken_apk: false,
            broken_executable_type: None,
        }
    }
}

impl FileTypeInfo {
    pub fn matches_type(&self, value: &str) -> bool {
        let needle = normalize_file_type_name(value);
        if needle.is_empty() {
            return false;
        }
        if normalize_file_type_name(&self.primary) == needle {
            return true;
        }
        if self
            .tags
            .iter()
            .any(|tag| normalize_file_type_name(tag) == needle)
        {
            return true;
        }
        match needle.as_str() {
            "pe" | "exe" | "dll" | "sys" => self.is_pe,
            "pe32" => self.is_pe32 || (self.is_pe && self.primary.eq_ignore_ascii_case("pe32")),
            "pe64" => self.is_pe64 || (self.is_pe && self.primary.eq_ignore_ascii_case("pe64")),
            "elf" => self.is_elf,
            "elf32" => self.is_elf32,
            "elf64" => self.is_elf64,
            "macho" | "mach_o" => self.is_macho,
            "apk" | "android" => self.is_apk,
            "zip" => self.is_zip,
            "archive" => self.is_archive,
            "7z" => self.is_7z,
            "rar" => self.is_rar,
            "gzip" | "gz" => self.is_gzip,
            "tar" => self.is_tar,
            "jar" => self.is_jar,
            "dex" => self.is_dex,
            "java_class" | "class" => self.is_java_class,
            "text" | "plain" | "plain_text" | "txt" => self.is_plain_text,
            "script" => self.is_script,
            "powershell" | "ps1" => self.is_powershell,
            "batch" | "bat" | "cmd" => self.is_batch,
            "javascript" | "js" => self.is_javascript,
            "vbs" => self.is_vbs,
            "python" | "py" => self.is_python,
            "pdf" => self.is_pdf,
            "office" => self.is_office,
            "ole" | "compound" | "microsoft_compound" => self.is_microsoft_compound,
            "binary" => self.is_binary,
            "unknown" => self.primary == "unknown",
            "broken" => self.is_broken_executable || self.is_broken_apk,
            "broken_executable" => self.is_broken_executable,
            "broken_apk" => self.is_broken_apk,
            _ => false,
        }
    }
}

fn normalize_file_type_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub arch: String,
    pub is_64: bool,
    pub entry: u64,
    pub image_base: u64,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub dlls: Vec<String>,
    pub suspicious_imports: Vec<String>,
    pub sections: Vec<PeSectionInfo>,
    pub suspicious_sections: Vec<String>,
    pub likely_packed: bool,
    /// Raw value of IMAGE_FILE_HEADER.TimeDateStamp (Unix seconds, little-endian u32).
    /// 0 means the field was absent or the file is not a PE.
    pub time_date_stamp: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringHit {
    pub value: String,
    pub offset: usize,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedString {
    pub method: String,
    pub source: String,
    pub decoded: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvHit {
    pub name: String,
    pub value: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryHit {
    pub key_or_value: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub verdict: Verdict,
    pub confidence: u8,
    pub score: u32,
    pub tags: Vec<String>,
    pub family: Option<String>,
    pub evidence: Vec<String>,
    /// MITRE ATT&CK techniques triggered by this specific finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<MitreTechnique>,
    /// The safe/default registry value to restore when this finding represents a
    /// PUM (Potentially Unwanted Modification). Populated from the rule's
    /// `expected_reverted_value` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_reverted_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePerformance {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub verdict: Verdict,
    pub matched: bool,
    pub condition_count: usize,
    pub signature_atom_count: usize,
    pub elapsed_micros: u64,
}

/// SDK-style archive member scan result for nested file scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMemberResult {
    /// Display name of extracted file
    pub name: String,
    /// Full virtual path within archive hierarchy
    pub path: String,
    /// Scan result code
    pub result_code: ScanResultCode,
    /// Detected threat name if infected
    pub threat_name: Option<String>,
    /// Member file size
    pub size: u64,
    /// Nested depth level
    pub depth: u32,
}

/// SDK-style memory scan context for in-memory buffer scanning.
#[derive(Debug, Clone)]
pub struct MemoryScanContext {
    /// Memory buffer to scan
    pub buffer: Vec<u8>,
    /// Optional identifier for this memory region
    pub identifier: String,
    /// Base address hint (for forensics/debugging)
    pub base_address: Option<u64>,
}

/// SDK-style registry scan context. The caller supplies key/value text; this
/// scanner treats it as a deterministic buffer and never reads the live registry.
#[derive(Debug, Clone)]
pub struct RegistryScanContext {
    pub key: String,
    pub value_name: Option<String>,
    pub value_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub path: PathBuf,
    pub scanned_at: DateTime<Utc>,
    pub file_size: u64,
    pub entropy: f64,
    pub hashes: Hashes,
    pub pe: Option<PeInfo>,
    pub file_type: FileTypeInfo,
    pub strings: Vec<StringHit>,
    pub decoded_strings: Vec<DecodedString>,
    pub env_hits: Vec<EnvHit>,
    pub registry_hits: Vec<RegistryHit>,
    pub features: BTreeMap<String, serde_json::Value>,
    pub findings: Vec<Finding>,
    pub score: u32,
    pub verdict: Verdict,
    pub confidence: u8,
    pub malware_families: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_performance: Vec<RulePerformance>,

    /// SDK-style scan result code.
    #[serde(default)]
    pub result_code: ScanResultCode,

    /// SDK-style scan statistics.
    #[serde(default)]
    pub statistics: ScanStatistics,

    /// SDK-style archive member results for nested scanning.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archive_members: Vec<ArchiveMemberResult>,

    /// Detected threat name in SDK format (family.variant or signature name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,

    /// Digital signature verification information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureInfo>,

    /// MITRE ATT&CK techniques mapped from static analysis findings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_techniques: Vec<MitreTechnique>,
}

/// MITRE ATT&CK technique mapped from static analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g., "T1055")
    pub id: String,
    /// Technique name (e.g., "Process Injection")
    pub name: String,
    /// Tactic (e.g., "Defense Evasion", "Privilege Escalation")
    pub tactic: String,
    /// Evidence from static analysis that triggered this mapping
    pub evidence: String,
    /// Confidence level (0-100)
    pub confidence: u8,
}

impl Default for ScanResultCode {
    fn default() -> Self {
        Self::Ok
    }
}
