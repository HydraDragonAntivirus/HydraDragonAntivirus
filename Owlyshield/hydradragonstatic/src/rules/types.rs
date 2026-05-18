use crate::models::{Severity, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlRulesFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,

    /// HydraDragonStatic verdict. If this rule matches and verdict is Malware,
    /// the final file verdict is Malware even if it is the only matched rule.
    #[serde(default = "default_verdict")]
    pub verdict: Verdict,

    #[serde(default = "default_confidence")]
    pub confidence: u8,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default = "default_score")]
    pub score: u32,
    #[serde(default)]
    pub tags: Vec<String>,

    /// any       => 1 condition is enough
    /// all       => all conditions must match
    /// threshold => N conditions, configured by threshold
    #[serde(default)]
    pub logic: RuleLogic,
    #[serde(default)]
    pub threshold: Option<usize>,
    #[serde(default)]
    pub conditions: Vec<RuleCondition>,
}

fn default_score() -> u32 { 10 }
fn default_verdict() -> Verdict { Verdict::Suspicious }
fn default_confidence() -> u8 { 60 }

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleLogic {
    All,
    #[default]
    Any,
    Threshold,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAtomKind {
    #[default]
    Text,
    Regex,
    Bytes,
}

/// Native static signature atom used by the Yamdle converted signature format.
/// This is not a external rule runtime dependency. It is a small deterministic matcher
/// that supports text, regex and hex/byte atoms plus common modifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureAtom {
    pub id: String,
    #[serde(default)]
    pub kind: SignatureAtomKind,
    pub value: String,
    #[serde(default)]
    pub nocase: bool,
    #[serde(default)]
    pub decoded: bool,
    #[serde(default)]
    pub wide: bool,
    #[serde(default)]
    pub ascii: bool,
    #[serde(default)]
    pub fullword: bool,

    /// Native Yamdle modifier equivalent to YARA's `xor` / `xor(0x01-0xff)`.
    /// This is deterministic raw-byte matching, not a YARA dependency.
    #[serde(default)]
    pub xor: bool,
    #[serde(default)]
    pub xor_min: Option<u8>,
    #[serde(default)]
    pub xor_max: Option<u8>,

    /// Native Yamdle equivalents for YARA's `base64` and `base64wide` modifiers.
    #[serde(default)]
    pub base64: bool,
    #[serde(default)]
    pub base64wide: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    StringContains { value: String, #[serde(default)] nocase: bool, #[serde(default)] decoded: bool },
    StringRegex { pattern: String, #[serde(default)] decoded: bool },

    /// `2 of ($strings*)` style string groups.
    StringSet {
        values: Vec<String>,
        #[serde(default)] min: Option<usize>,
        #[serde(default)] nocase: bool,
        #[serde(default)] decoded: bool,
        #[serde(default)] regex: bool,
    },

    /// HydraDragonStatic native signature format. It holds deterministic
    /// signature atoms and a boolean expression such as:
    /// `any of them`, `2 of ($a*)`, `$a and ($b or $c)`, `filesize < 500KB`.
    NativeSignature {
        atoms: Vec<SignatureAtom>,
        expression: String,
    },

    ImportAny { names: Vec<String> },
    ImportAll { names: Vec<String> },
    ImportSet { names: Vec<String>, #[serde(default)] min: Option<usize> },
    ImportRegex { pattern: String },
    DllAny { names: Vec<String> },
    DllRegex { pattern: String },
    SuspiciousImportCount { min: usize },

    FileEntropy { min: f64 },
    FileSizeGte { bytes: u64 },
    FileSizeLte { bytes: u64 },
    SectionEntropy { min: f64 },
    SectionNameRegex { pattern: String },
    PackedPe,

    EnvReference { #[serde(default)] min: usize },
    RegistryPattern { pattern: String, #[serde(default)] nocase: bool },
    RegistryHitCount { min: usize },
    PathRegex { pattern: String },

    /// Match file type tags produced by the native DetectItEasy-style classifier.
    /// Example values: pe, pe64, elf, macho, apk, zip, jar, text, script, powershell, office, broken_executable.
    FileType { values: Vec<String> },

    HashSha256 { value: String },
    HashMd5 { value: String },
    FeatureGte { name: String, value: f64 },

    /// Hex byte pattern. Supports `{ 4D 5A ?? 90 E8 }` and nibble wildcards like `4?`.
    BytePattern { pattern: String },

    /// Byte pattern group.
    ByteSet { patterns: Vec<String>, #[serde(default)] min: Option<usize> },
}
