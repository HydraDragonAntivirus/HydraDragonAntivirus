use crate::models::{Severity, Verdict};
use serde::{Deserialize, Serialize};

/// Lightweight MITRE ATT&CK reference embedded in a YAML rule.
/// Engine converts these into full [`crate::models::MitreTechnique`] entries
/// using the rule's evidence when a finding is produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    /// Technique or sub-technique ID, e.g. "T1055" or "T1555.003"
    pub id: String,
    /// Technique name, e.g. "Credentials from Password Stores"
    pub name: String,
    /// ATT&CK tactic, e.g. "Credential Access"
    pub tactic: String,
}

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

    /// HydraDragonSig verdict. If this rule matches and verdict is Malware,
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

    /// MITRE ATT&CK technique mappings for this rule.
    /// When the rule matches, these are emitted as [`crate::models::MitreTechnique`] entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<MitreMapping>,

    /// Private rule flag (YARA-style). When true, this rule is evaluated but doesn't generate findings.
    /// Private rules can be used by other rules for detection logic but won't trigger alerts themselves.
    #[serde(default)]
    pub private: bool,

    /// any       => 1 condition is enough
    /// all       => all conditions must match
    /// threshold => N conditions, configured by threshold
    #[serde(default)]
    pub logic: RuleLogic,
    #[serde(default)]
    pub threshold: Option<usize>,
    #[serde(default)]
    pub conditions: Vec<RuleCondition>,
    /// The safe/default value that should be restored when this rule matches a
    /// registry-based PUM (Potentially Unwanted Modification). For example,
    /// DisableTaskMgr=1 should be reverted to "0", UAC disabled (=0) to "1".
    /// This is propagated through the Finding so remediation tools know what
    /// to write back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_reverted_value: Option<String>,

    /// File types this rule can match against, inferred from its conditions.
    /// `None` = all file types. Populated automatically during loading.
    #[serde(skip)]
    pub required_types: Option<Vec<String>>,

    /// If set, only evaluate this rule when the scanned file's path matches
    /// this template. Supports `%VAR%` environment-variable placeholders
    /// (e.g. `%SystemRoot%\\System32\\drivers\\etc\\hosts`).
    /// YAML key: `file_path`.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "file_path")]
    pub required_path: Option<String>,
}

impl Rule {
    /// Infer the file types this rule requires, based on its conditions.
    /// PE-specific conditions (imports, sections, signatures) set `["pe"]`;
    /// explicit `file_type` conditions add their values.
    pub fn compute_required_types(&mut self) {
        let mut types: Vec<String> = Vec::new();
        for condition in &self.conditions {
            match condition {
                RuleCondition::ImportAny { .. }
                | RuleCondition::ImportAll { .. }
                | RuleCondition::ImportSet { .. }
                | RuleCondition::ImportRegex { .. }
                | RuleCondition::DllAny { .. }
                | RuleCondition::DllRegex { .. }
                | RuleCondition::SuspiciousImportCount { .. }
                | RuleCondition::SectionEntropy { .. }
                | RuleCondition::SectionNameRegex { .. }
                | RuleCondition::PackedPe
                | RuleCondition::SignatureSignerContains { .. }
                | RuleCondition::SignatureIsSigned { .. }
                | RuleCondition::SignatureInvalid
                | RuleCondition::SignatureVerificationFailed
                | RuleCondition::SignatureAnyIssue
                | RuleCondition::SignatureHresultIn { .. } => {
                    if !types.contains(&"pe".to_string()) {
                        types.push("pe".to_string());
                    }
                }
                RuleCondition::FileType { values } => {
                    for v in values {
                        if !types.contains(v) {
                            types.push(v.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        self.required_types = if types.is_empty() { None } else { Some(types) };
    }
}

fn default_score() -> u32 {
    10
}
fn default_verdict() -> Verdict {
    Verdict::Suspicious
}
fn default_confidence() -> u8 {
    60
}

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
    StringContains {
        value: String,
        #[serde(default)]
        nocase: bool,
        #[serde(default)]
        decoded: bool,
        #[serde(default = "default_true")]
        ascii: bool,
        #[serde(default)]
        wide: bool,
        #[serde(default)]
        utf8: bool,
        #[serde(default)]
        utf16: bool,
    },
    StringRegex {
        pattern: String,
        #[serde(default)]
        decoded: bool,
    },

    /// `2 of ($strings*)` style string groups.
    StringSet {
        values: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
        #[serde(default)]
        nocase: bool,
        #[serde(default)]
        decoded: bool,
        #[serde(default)]
        regex: bool,
        #[serde(default = "default_true")]
        ascii: bool,
        #[serde(default)]
        wide: bool,
        #[serde(default)]
        utf8: bool,
        #[serde(default)]
        utf16: bool,
    },

    /// HydraDragonSig native signature format. It holds deterministic
    /// signature atoms and a boolean expression such as:
    /// `any of them`, `2 of ($a*)`, `$a and ($b or $c)`, `filesize < 500KB`.
    NativeSignature {
        atoms: Vec<SignatureAtom>,
        expression: String,
    },

    ImportAny {
        names: Vec<String>,
    },
    ImportAll {
        names: Vec<String>,
    },
    ImportSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
    ImportRegex {
        pattern: String,
    },
    DllAny {
        names: Vec<String>,
    },
    DllRegex {
        pattern: String,
    },
    SuspiciousImportCount {
        min: usize,
    },

    FileEntropy {
        min: f64,
    },
    FileSizeGte {
        bytes: u64,
    },
    FileSizeLte {
        bytes: u64,
    },
    SectionEntropy {
        min: f64,
    },
    SectionNameRegex {
        pattern: String,
    },
    PackedPe,

    EnvReference {
        #[serde(default)]
        min: usize,
    },
    RegistryPattern {
        pattern: String,
        #[serde(default)]
        nocase: bool,
    },
    RegistryHitCount {
        min: usize,
    },
    PathRegex {
        pattern: String,
    },

    SignatureSignerContains {
        value: String,
        #[serde(default)]
        nocase: bool,
    },

    /// Fires when the file has a digital signature present (`is_signed = true`).
    /// Use `value: false` to detect unsigned files.
    SignatureIsSigned {
        value: bool,
    },

    /// Fires when WinVerifyTrust returns a hard failure for the embedded signature
    /// (authenticode hash mismatch, revoked cert, tampered binary).
    SignatureInvalid,

    /// Fires when WinVerifyTrust returns a soft verification failure
    /// (expired timestamp counter-signature, chain build error, etc.).
    SignatureVerificationFailed,

    /// Fires when any of the three bad-signature flags is set:
    /// `invalid_signature || verification_failed || signature_status_issues`.
    SignatureAnyIssue,

    /// Fires when the raw WinVerifyTrust HRESULT matches one of the given hex values.
    /// Use to target specific failure codes such as 0x800B0101 (CERT_E_EXPIRED),
    /// 0x800B010A (CERT_E_CHAINING), 0x800B0109 (CERT_E_UNTRUSTEDROOT), etc.
    SignatureHresultIn {
        values: Vec<u32>,
    },

    /// Match file type tags produced by the native DetectItEasy-style classifier.
    /// Example values: pe, pe64, elf, macho, apk, zip, jar, text, script, powershell, office, broken_executable.
    FileType {
        values: Vec<String>,
    },

    HashSha256 {
        value: String,
    },
    HashMd5 {
        value: String,
    },
    FeatureGte {
        name: String,
        value: f64,
    },

    /// Hex byte pattern. Supports `{ 4D 5A ?? 90 E8 }` and nibble wildcards like `4?`.
    BytePattern {
        pattern: String,
    },

    /// Byte pattern group.
    ByteSet {
        patterns: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
}

fn default_true() -> bool {
    true
}
