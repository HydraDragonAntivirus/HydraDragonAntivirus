use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::Hash;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    Clean,
    Suspicious,
    Malware,
}

impl Default for Verdict {
    fn default() -> Self {
        Self::Clean
    }
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::Suspicious => "SUSPICIOUS",
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
    pub dlls: Vec<String>,
    pub suspicious_imports: Vec<String>,
    pub sections: Vec<PeSectionInfo>,
    pub suspicious_sections: Vec<String>,
    pub likely_packed: bool,
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
}
