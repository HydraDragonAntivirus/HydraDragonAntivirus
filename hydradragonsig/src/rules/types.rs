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
    /// Later rules can use it through a `rule_match` condition.
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

    /// Declarative post-detection remediation steps (`--remediate`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remediation: Vec<super::remediation::Remediation>,

    /// File type tags assigned to the file when this rule matches
    /// (`assign_types`; alias `assign_file_type`). Custom tags make rules act
    /// as file type classifiers: later rules can require them with a
    /// `file_type` condition, `--include-type` style routing tools and report
    /// consumers see them in `file_type.tags`, and the automatic
    /// `required_types` inference treats the rule's own conditions as usual.
    /// Tag names are free-form (letters, digits, `_`); every assigned tag is
    /// also pushed as-is so components can route on familiar names.
    #[serde(
        default,
        alias = "assign_file_type",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assign_types: Vec<String>,
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
                | RuleCondition::ExportAny { .. }
                | RuleCondition::ExportAll { .. }
                | RuleCondition::ExportSet { .. }
                | RuleCondition::DllAny { .. }
                | RuleCondition::DllRegex { .. }
                | RuleCondition::SuspiciousImportCount { .. }
                | RuleCondition::ImphashAny { .. }
                | RuleCondition::NewImportSet { .. }
                | RuleCondition::SectionEntropy { .. }
                | RuleCondition::SectionNameRegex { .. }
                | RuleCondition::PeSection { .. }
                | RuleCondition::PackedPe
                | RuleCondition::PeAnchorPattern { .. }
                | RuleCondition::Authenticode { .. }
                | RuleCondition::VersionInfo { .. }
                | RuleCondition::ResourceMatch { .. }
                | RuleCondition::ResourceHashAny { .. }
                | RuleCondition::ResourcesAbsent
                | RuleCondition::PeSectionsSummary { .. }
                | RuleCondition::ExportHashAny { .. }
                | RuleCondition::PeTimestamp { .. } => {
                    if !types.contains(&"pe".to_string()) {
                        types.push("pe".to_string());
                    }
                }
                RuleCondition::DexStringRegex { .. }
                | RuleCondition::DexClassRegex { .. }
                | RuleCondition::DexMethodRegex { .. }
                | RuleCondition::DexClassCount { .. }
                | RuleCondition::DexMethodCount { .. } => {
                    if !types.contains(&"dex".to_string()) {
                        types.push("dex".to_string());
                    }
                }
                RuleCondition::DotnetGuidAny { .. }
                | RuleCondition::DotnetTypeRegex { .. }
                | RuleCondition::DotnetMethodRegex { .. }
                | RuleCondition::DotnetPinvokeAny { .. }
                | RuleCondition::DotnetPinvokeSet { .. }
                | RuleCondition::DotnetStreamAny { .. }
                | RuleCondition::DotnetUserStringRegex { .. } => {
                    if !types.contains(&"dotnet".to_string()) {
                        types.push("dotnet".to_string());
                    }
                }
                RuleCondition::ElfImportAny { .. }
                | RuleCondition::ElfImportSet { .. }
                | RuleCondition::ElfImportRegex { .. }
                | RuleCondition::ElfExportAny { .. }
                | RuleCondition::ElfExportSet { .. }
                | RuleCondition::ElfNeededAny { .. }
                | RuleCondition::ElfSection { .. }
                | RuleCondition::ElfSegment { .. }
                | RuleCondition::ElfBuildIdAny { .. }
                | RuleCondition::NewElfImportSet { .. } => {
                    if !types.contains(&"elf".to_string()) {
                        types.push("elf".to_string());
                    }
                }
                RuleCondition::MachoDylibAny { .. }
                | RuleCondition::MachoSymAny { .. }
                | RuleCondition::MachoSymRegex { .. }
                | RuleCondition::MachoSegment { .. }
                | RuleCondition::MachoUuidAny { .. }
                | RuleCondition::MachoSigned { .. }
                | RuleCondition::MachoEntitlementAny { .. } => {
                    if !types.contains(&"macho".to_string()) {
                        types.push("macho".to_string());
                    }
                }
                RuleCondition::PdfKeyword { .. } | RuleCondition::PdfStreamMatch { .. } => {
                    if !types.contains(&"pdf".to_string()) {
                        types.push("pdf".to_string());
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
        if self.conditions.iter().any(|c| matches!(c, RuleCondition::NotMz)) {
            types.retain(|t| t != "pe");
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleLogic {
    #[serde(alias = "All", alias = "ALL")]
    All,
    #[default]
    #[serde(alias = "Any", alias = "ANY")]
    Any,
    #[serde(alias = "Threshold", alias = "THRESHOLD")]
    Threshold,
}

/// Which section a `pe_section` condition looks at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeSectionSelect {
    /// Any section (the condition holds when one section passes).
    #[default]
    #[serde(alias = "Any", alias = "ANY")]
    Any,
    /// The last section in the section table.
    #[serde(alias = "Last", alias = "LAST")]
    Last,
    /// The section that holds the entry point.
    #[serde(alias = "Entry", alias = "ENTRY")]
    Entry,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAtomKind {
    #[default]
    #[serde(alias = "Text", alias = "TEXT")]
    Text,
    #[serde(alias = "Regex", alias = "REGEX")]
    Regex,
    #[serde(alias = "Bytes", alias = "BYTES", alias = "hex")]
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

// Variants are kept unboxed: rules are built and matched by field from YAML
// and by library users; one condition per variant is small next to a scan.
#[allow(clippy::large_enum_variant)]
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
        #[serde(default)]
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
    ExportAny {
        names: Vec<String>,
    },
    ExportAll {
        names: Vec<String>,
    },
    ExportSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
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
    /// Properties of one chosen PE section (see FORMAT.md 5.2): which section
    /// (`select`), its name, flags, entropy, sizes, code references into it and the
    /// data directories that point into it. Every given key must hold.
    PeSection {
        #[serde(default)]
        select: PeSectionSelect,
        /// Optional 0-based section table index (`sectionindex=0..N`).
        #[serde(default)]
        index: Option<usize>,
        /// Exact section name (e.g. `.text`, `.rsrc`, `/4`, `/19`).
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        name_regex: Option<String>,
        #[serde(default)]
        flags_all: Vec<String>,
        #[serde(default)]
        flags_none: Vec<String>,
        /// Exact `Characteristics` 32-bit field (e.g. `0x60000020`).
        #[serde(default)]
        characteristics: Option<u32>,
        #[serde(default)]
        entropy_min: Option<f64>,
        #[serde(default)]
        entropy_max: Option<f64>,
        /// Exact `SizeOfRawData` (`size[section]` / `physicalsize[section]`).
        #[serde(default)]
        raw_size: Option<u64>,
        #[serde(default)]
        raw_size_min: Option<u64>,
        #[serde(default)]
        raw_size_max: Option<u64>,
        /// Exact `PointerToRawData` (`physicaladdress[section]`).
        #[serde(default)]
        raw_offset: Option<u64>,
        /// Exact `VirtualAddress` (`virtualaddress[section]`).
        #[serde(default)]
        virtual_address: Option<u64>,
        /// Exact `VirtualSize` (`virtualsize[section]`).
        #[serde(default)]
        virtual_size: Option<u64>,
        #[serde(default)]
        virtual_size_min: Option<u64>,
        #[serde(default)]
        virtual_size_max: Option<u64>,
        /// Hashes of the section's raw byte slice (`md5[section]`, etc.).
        #[serde(default)]
        md5: Option<String>,
        #[serde(default)]
        sha1: Option<String>,
        #[serde(default)]
        sha256: Option<String>,
        #[serde(default)]
        crc32: Option<String>,
        /// Direct `call` / `jmp` (rel32) from the other executable sections into it.
        #[serde(default)]
        code_xrefs_min: Option<usize>,
        /// Count `code_xrefs_min` over the code reachable from the entry point
        /// (control-flow walk) instead of a linear sweep, so bytes after a
        /// `ret` / `jmp` / `int3` are not read as code.
        #[serde(default)]
        cfg_xrefs: bool,
        /// Holds the entry point.
        #[serde(default)]
        has_entry: Option<bool>,
        /// Data directories pointing into it: export, import, resource, exception,
        /// security, basereloc, debug, tls, load_config, iat, delay_import, clr.
        #[serde(default)]
        directories_any: Vec<String>,
        /// None of these data directories may point into it.
        #[serde(default)]
        directories_none: Vec<String>,
        /// With `directories_any`: the directories inside it cover at most this share
        /// (0-1) of the section, i.e. the rest of the section is something else.
        #[serde(default)]
        directory_share_max: Option<f64>,
    },
    PackedPe,

    EnvReference {
        #[serde(default)]
        min: usize,
    },
    PathRegex {
        pattern: String,
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
    HashSha1 {
        value: String,
    },
    HashCrc32 {
        value: String,
    },
    /// The PE's import hash (Mandiant / pefile imphash) is one of these.
    ImphashAny {
        values: Vec<String>,
    },
    FeatureGte {
        name: String,
        value: f64,
    },
    FeatureLte {
        name: String,
        value: f64,
    },

    // --- Parent comparison (unpacked dumps, extracted members) ---------------
    /// The buffer was scanned with a parent summary (`ScanOptions::parent`).
    HasParent,
    /// A numeric feature of the parent is >= value.
    ParentFeatureGte {
        name: String,
        value: f64,
    },
    /// A numeric feature of the parent is <= value.
    ParentFeatureLte {
        name: String,
        value: f64,
    },
    /// This file's feature minus the parent's feature is >= value.
    FeatureDeltaGte {
        name: String,
        value: f64,
    },
    /// At least `min` of `names` are imported by this file and NOT by the parent
    /// (same suffix matching as `import_set`).
    NewImportSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },

    /// Hex byte pattern. Supports `{ 4D 5A ?? 90 E8 }` and nibble wildcards like `4?`.
    BytePattern {
        pattern: String,
        /// Restrict the search to a byte window of the file.
        #[serde(default)]
        scope: Option<ByteScope>,
        /// Known-benign blobs that veto this condition when any of them is present.
        #[serde(default)]
        excludes: Vec<String>,
    },

    /// Byte pattern group.
    ByteSet {
        patterns: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
        /// Restrict every search in this group to a byte window of the file.
        #[serde(default)]
        scope: Option<ByteScope>,
        /// Known-benign blobs that veto this condition when any of them is present.
        #[serde(default)]
        excludes: Vec<String>,
    },

    /// True when other rules of the same set matched earlier in this scan
    /// (`private: true` helper rules included). `min` defaults to all `ids`.
    RuleMatch {
        ids: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },

    /// Packer / protector identification by byte signature. Matches the first
    /// signature whose pattern is present and reports the packer name.
    UnpackerAny {
        signatures: Vec<UnpackerSignature>,
    },

    // --- Emulation trace (ScanReport::behavior, filled by the caller's emulator) ---
    /// One of these APIs was called while the sample was emulated.
    EmulatedApiAny {
        names: Vec<String>,
    },
    /// A string argument of a call to `api` matches `pattern`.
    EmulatedArgRegex {
        api: String,
        pattern: String,
    },
    /// The steps were called in this order (other calls may come in between),
    /// all inside a window of `within` calls when given.
    EmulatedSequence {
        steps: Vec<EmulatedStep>,
        #[serde(default)]
        within: Option<usize>,
    },
    /// `api` was called at least `min` times (`distinct`: with at least `min`
    /// different argument lists, e.g. WriteFile to that many files).
    EmulatedCountGte {
        api: String,
        min: usize,
        #[serde(default)]
        distinct: bool,
    },

    /// Perceptual image hash (pHash) of the scanned file. Matches when the file
    /// decodes as an image and its 64-bit pHash is within `max_distance` bits of
    /// any of `hashes`, so a resized or re-encoded copy of the same artwork still
    /// matches.
    ///
    /// Hashes may be written as bare 16-hex or as ClamAV `fuzzy_img#<hex>`
    /// subsignatures. ClamAV itself only supports a distance of 0; a non-zero
    /// `max_distance` is a Hydra extension.
    ImageFuzzyHashAny {
        hashes: Vec<String>,
        #[serde(default)]
        max_distance: Option<u32>,
    },

    /// Icon fingerprint of a PE, matched on any of three independent schemes.
    ///
    /// All three read the same decoded icon, so an executable with several icon
    /// sizes is decoded once and then scored three ways. Any scheme that matches
    /// satisfies the condition; the evidence names which one fired.
    ///
    /// * `dhash` - 64-bit difference hash. Discriminative on the small 16x16
    ///   icons that matter most, and what SpyHunter's `icon_dhash` tables hold.
    /// * `phash` - 64-bit DCT hash, ClamAV `fuzzy_img#` compatible.
    /// * `idb` - ClamAV `.idb` fingerprints, written as whole signature lines
    ///   (`Name:Group1:Group2:<124 hex>`) so they can be pasted straight out of a
    ///   signature database.
    ///
    /// A stored `.idb` group restricts which groups a rule will consider, which
    /// is how ClamAV's `IconGroup1`/`IconGroup2` constraints are expressed here.
    ///
    /// This is a *family* signal: the same stolen icon is shared by many samples
    /// and by plenty of legitimate software, so a match is evidence to weigh,
    /// not a verdict on its own. Whether it is sufficient is the rule author's
    /// call, expressed through `required` - see [`Rule::icon_match_required`].
    PeIconAny {
        #[serde(default)]
        dhash: Vec<String>,
        #[serde(default)]
        dhash_max_distance: Option<u32>,
        #[serde(default)]
        phash: Vec<String>,
        #[serde(default)]
        phash_max_distance: Option<u32>,
        #[serde(default)]
        idb: Vec<String>,
        /// Icon groups a rule is willing to accept, one entry per `.idb` group
        /// position. Empty means "any group", like ClamAV's `*`.
        #[serde(default)]
        idb_groups: Vec<String>,
    },

    /// Hex byte pattern(s) matched at or within `range` bytes of an anchor
    /// (`absolute`, `entry`, `section`, `overlay`, `eof`). Supports `??`, `!!`
    /// (any non-zero byte) and nibble wildcards (`4?`, `?A`).
    PeAnchorPattern {
        #[serde(default = "default_anchor")]
        anchor: String,
        #[serde(default)]
        section: Option<u32>,
        #[serde(default)]
        offset: i64,
        #[serde(default)]
        range: Option<usize>,
        #[serde(default)]
        count: Option<usize>,
        #[serde(default)]
        patterns: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
        #[serde(default)]
        negate: bool,
        #[serde(default)]
        excludes: Vec<String>,
    },

    /// The first `length` bytes at the anchor repeat at least `min` (default 1)
    /// time(s) elsewhere in the file.
    ByteRepeat {
        #[serde(default = "default_anchor")]
        anchor: String,
        #[serde(default)]
        section: Option<u32>,
        #[serde(default)]
        offset: i64,
        length: usize,
        #[serde(default)]
        min: Option<usize>,
    },

    /// Runs a ClamAV bytecode program (`.cbc`) over the file in hydradragonclamav's
    /// VM (see `bytecode`). The rule configures the run: the program, entry
    /// function and its arguments, the instruction budget, what counts as a
    /// match, and new APIs the program may call by the names it declares.
    Bytecode {
        /// `.cbc` file, relative to the rule file.
        program: String,
        /// Entry function index (default 0).
        #[serde(default)]
        entry_func: Option<usize>,
        /// Instruction budget (default 100 000); the run stops there and the
        /// condition does not match.
        #[serde(default)]
        max_ops: Option<u64>,
        /// Arguments of the entry function; also read by the `hds_param(i)` API.
        #[serde(default)]
        params: Vec<u64>,
        /// Match when the entry function returns this value. Default: a non-zero
        /// return value or a virus name set by the program.
        #[serde(default)]
        expect_return: Option<i64>,
        /// Match only when the program sets a virus name matching this glob.
        #[serde(default)]
        virname_glob: Option<String>,
        /// APIs the rule gives the program, keyed by the name the program declares.
        #[serde(default)]
        apis: std::collections::BTreeMap<String, BytecodeApi>,
    },

    /// x86 / x64 instruction pattern(s) over the disassembled code of `region`
    /// (`entry`, `code`, `section_N`, `overlay`, `file`): steps such as
    /// `xor byte ptr [*], *; inc reg; [0-2]; loop *`, matched on what the bytes
    /// decode to, so every encoding of an instruction matches (see `opcode`).
    OpcodePattern {
        #[serde(default)]
        pattern: Option<String>,
        #[serde(default)]
        patterns: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
        #[serde(default = "default_opcode_region")]
        region: String,
        /// Bytes decoded from the start of the region (entry: 4096, else 4 MiB).
        #[serde(default)]
        max_bytes: Option<usize>,
        /// 16, 32 or 64 for code that is not a PE (`file`, `overlay` of a non-PE);
        /// a PE always uses its own.
        #[serde(default)]
        bitness: Option<u32>,
        /// Mnemonic globs left out before matching (junk filler such as `nop`).
        #[serde(default)]
        skip: Vec<String>,
        /// `linear` (default) or `cfg`: decode along direct jumps / branches
        /// from the region start (see `opcode`).
        #[serde(default)]
        mode: Option<String>,
        /// `auto`, `x86`, `x64` or `arm64`. Without it a PE decodes as x86 of
        /// its own bitness and only PE regions exist; with `auto` the PE
        /// machine, ELF `e_machine` or Mach-O CPU type decides, and ELF /
        /// Mach-O `entry` / `code` regions exist.
        #[serde(default)]
        arch: Option<String>,
        /// `mode: cfg` blocks (default 256, at most 2048).
        #[serde(default)]
        max_blocks: Option<usize>,
        /// `mode: cfg` instructions (default 8192, at most 65536).
        #[serde(default)]
        max_insns: Option<usize>,
        /// `mode: cfg`: also walk into direct calls.
        #[serde(default)]
        follow_calls: bool,
        /// `mode: cfg`: continue at the target of an unconditional direct jump
        /// as if the code were contiguous (default true).
        #[serde(default)]
        follow_jumps: Option<bool>,
    },

    /// True when the file does not start with the `MZ` DOS header magic.
    NotMz,

    /// PE Authenticode code-signing check: `signed: true|false` and/or a glob
    /// over certificate subject CN / O / OU strings.
    Authenticode {
        #[serde(default)]
        signed: Option<bool>,
        #[serde(default)]
        subject_glob: Option<String>,
    },

    /// PE `RT_VERSION` (`VS_VERSIONINFO`) check: `absent: true` when no version
    /// resource exists, or a map of field names (or slot numbers `0`..`11`) to
    /// glob patterns.
    VersionInfo {
        #[serde(default)]
        fields: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        absent: bool,
        /// Inclusive numeric bounds on the file / product version, `a[.b[.c[.d]]]`
        /// (missing parts are 0). Compared as four numbers, so `1.10` is above
        /// `1.9`, which a glob on the version text cannot express.
        #[serde(default)]
        file_version_min: Option<String>,
        #[serde(default)]
        file_version_max: Option<String>,
        #[serde(default)]
        product_version_min: Option<String>,
        #[serde(default)]
        product_version_max: Option<String>,
    },

    /// Match PE resources by type glob, byte size bounds and/or hex patterns
    /// inside the resource data.
    ResourceMatch {
        #[serde(default)]
        type_glob: Option<String>,
        #[serde(default)]
        size_min: Option<u64>,
        #[serde(default)]
        size_max: Option<u64>,
        #[serde(default)]
        data_patterns: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },

    /// Any PE resource's MD5 (32 hex) or SHA-256 (64 hex) matches one of `values`.
    ResourceHashAny {
        values: Vec<String>,
    },

    /// The PE has no resources (missing or empty resource directory).
    ResourcesAbsent,

    /// Windows Registry key existence check, optionally searching for a value
    /// name regex in the key or its subtree.
    RegistryKey {
        key: String,
        #[serde(default)]
        recursive: bool,
        #[serde(default)]
        value_pattern: Option<String>,
    },

    /// Windows Registry value filter over a key or subtree.
    RegistryValue {
        key: String,
        #[serde(default)]
        recursive: bool,
        #[serde(default)]
        value_regex: Option<String>,
        #[serde(default)]
        data_regex: Option<String>,
        #[serde(default)]
        data_hex: Option<String>,
        #[serde(default)]
        md5: Option<String>,
        #[serde(default)]
        sha256: Option<String>,
        #[serde(default)]
        min: Option<usize>,
    },

    /// COM `CLSID` registration check, optionally matching `InprocServer32`
    /// default data against `inproc_regex`.
    Clsid {
        guids: Vec<String>,
        #[serde(default)]
        inproc_regex: Option<String>,
    },

    /// Match a line in the system `hosts` file by IP glob and/or hostname regex.
    HostsEntry {
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        host: Option<String>,
    },

    /// Match raw disk or volume sectors (`physical0`, `volume:C`, `\\.\PhysicalDrive0`).
    SectorPattern {
        device: String,
        #[serde(default)]
        lba: u64,
        #[serde(default = "default_sector_count")]
        count: u32,
        patterns: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
        #[serde(default)]
        excludes: Vec<String>,
    },

    /// Match the scanned file path against a wildcard glob (`*`, `**`, `?`, `#`)
    /// with `%VAR%` expansion.
    PathGlob {
        pattern: String,
    },

    /// Check that at least `min` (default: all) numeric feature bounds hold.
    FeatureBounds {
        bounds: Vec<FeatureBound>,
        #[serde(default)]
        min: Option<usize>,
    },

    /// Aggregate properties over all PE sections in table order:
    /// total raw size (`size[sections]`), concatenated raw section hashes
    /// (`md5[sections]`, `crc32[sections]`, `sha1`, `sha256`) and section count.
    PeSectionsSummary {
        #[serde(default)]
        total_raw_size: Option<u64>,
        #[serde(default)]
        total_raw_size_min: Option<u64>,
        #[serde(default)]
        total_raw_size_max: Option<u64>,
        #[serde(default)]
        md5: Option<String>,
        #[serde(default)]
        sha1: Option<String>,
        #[serde(default)]
        sha256: Option<String>,
        #[serde(default)]
        crc32: Option<String>,
        #[serde(default)]
        count: Option<usize>,
        #[serde(default)]
        count_min: Option<usize>,
        #[serde(default)]
        count_max: Option<usize>,
    },

    /// Match the PE export table hash (`md5[exports]`).
    ExportHashAny {
        values: Vec<String>,
    },

    /// Match `IMAGE_FILE_HEADER.TimeDateStamp` by exact integer, hex string or bounds.
    PeTimestamp {
        #[serde(default)]
        value: Option<u32>,
        #[serde(default)]
        hex: Option<String>,
        #[serde(default)]
        min: Option<u32>,
        #[serde(default)]
        max: Option<u32>,
    },

    /// Match the file's modification timestamp, raw DOS/Unix hex timestamp (`timestampraw[file]`)
    /// or age in days (`age[file]`).
    FileTimestamp {
        #[serde(default)]
        equals: Option<String>,
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        before: Option<String>,
        #[serde(default)]
        raw_hex: Option<String>,
        #[serde(default)]
        age_days_min: Option<u64>,
        #[serde(default)]
        age_days_max: Option<u64>,
    },

    /// Match file attributes (`attribs=A+D-H-L-R-S-` or explicit `required`/`forbidden` flags).
    FileAttributes {
        #[serde(default)]
        spec: Option<String>,
        #[serde(default)]
        required: Vec<String>,
        #[serde(default)]
        forbidden: Vec<String>,
    },

    /// Cross-reference the hostnames, domains and URLs found in the scanned file
    /// (plain and decoded strings) against an external categorized blocklist DB.
    /// The DB is a text file of `domain:CATEGORY` entries (one per line, `|`
    /// separated entries also accepted); it is loaded once via the CLI
    /// `--domain-db` flag or, per rule, the `db` field. The rule never carries
    /// the blocked domains themselves, only which categories to report.
    ///
    /// Matches when at least `min` (default 1) distinct listed domains of an
    /// accepted category are referenced by the file. `categories: ["*"]` or an
    /// empty list accepts every category in the DB.
    DomainBlocklist {
        /// Optional `domain:CATEGORY` text file; defaults to the global CLI DB.
        #[serde(default)]
        db: Option<String>,
        /// Categories to report (uppercase). `*` or empty = any category.
        #[serde(default)]
        categories: Vec<String>,
        /// Also look the domains up in the decoded (base64 / hex) strings.
        #[serde(default)]
        decoded: bool,
        /// Minimum distinct domains that must match.
        #[serde(default)]
        min: Option<usize>,
    },

    /// DEX string table matches regular expression.
    DexStringRegex {
        pattern: String,
    },
    /// Dotted Java class name defined in the DEX matches regular expression.
    DexClassRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },
    /// Method reference (`com.foo.Bar->name`) matches regular expression.
    DexMethodRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },
    /// Number of class definitions in the DEX header is at least `min`.
    DexClassCount {
        #[serde(default)]
        min: Option<usize>,
    },
    /// Number of method references in the DEX header is at least `min`.
    DexMethodCount {
        #[serde(default)]
        min: Option<usize>,
    },

    // --- .NET CLR metadata (`scanner::dotnet`) --------------------------------
    /// The module MVID or the assembly's type library GUID is one of `values`
    /// (case and `{}` / `-` are ignored).
    DotnetGuidAny {
        values: Vec<String>,
    },
    /// At least `min` defined or referenced types (`Namespace.Type`) match.
    DotnetTypeRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },
    /// At least `min` defined methods or member references (`Namespace.Type::Method`) match.
    DotnetMethodRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },
    /// One P/Invoke import (`module.dll!function`) ends with one of `names`
    /// (same suffix matching as `import_any`).
    DotnetPinvokeAny {
        names: Vec<String>,
    },
    /// At least `min` of `names` are P/Invoke imports.
    DotnetPinvokeSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
    /// A metadata stream has one of these names (`#Confuser`, `#SuppressIldasm`, ...).
    DotnetStreamAny {
        names: Vec<String>,
    },
    /// At least `min` `#US` user strings match.
    DotnetUserStringRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },

    // --- ELF (`scanner::elf`) -------------------------------------------------
    /// One imported (undefined) symbol is one of `names`.
    ElfImportAny {
        names: Vec<String>,
    },
    /// At least `min` of `names` are imported symbols.
    ElfImportSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
    /// At least `min` imported symbols match.
    ElfImportRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },
    ElfExportAny {
        names: Vec<String>,
    },
    ElfExportSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
    /// A `DT_NEEDED` library is one of `names`.
    ElfNeededAny {
        names: Vec<String>,
        #[serde(default)]
        nocase: bool,
    },
    /// Properties of one chosen ELF section, like `pe_section`.
    ElfSection {
        #[serde(default)]
        select: PeSectionSelect,
        #[serde(default)]
        index: Option<usize>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        name_regex: Option<String>,
        /// `alloc`, `write`, `exec`.
        #[serde(default)]
        flags_all: Vec<String>,
        #[serde(default)]
        flags_none: Vec<String>,
        #[serde(default)]
        entropy_min: Option<f64>,
        #[serde(default)]
        entropy_max: Option<f64>,
        #[serde(default)]
        size_min: Option<u64>,
        #[serde(default)]
        size_max: Option<u64>,
        #[serde(default)]
        md5: Option<String>,
        #[serde(default)]
        sha256: Option<String>,
    },
    /// A program header with these properties: RWX `PT_LOAD`, executable
    /// `PT_GNU_STACK`, large `p_memsz - p_filesz` (unpacker BSS gaps).
    ElfSegment {
        /// `load`, `dynamic`, `interp`, `note`, `gnu_stack`, ... or a number.
        #[serde(default)]
        seg_type: Option<String>,
        /// `r`, `w`, `x`.
        #[serde(default)]
        flags_all: Vec<String>,
        #[serde(default)]
        flags_none: Vec<String>,
        #[serde(default)]
        memsz_minus_filesz_min: Option<u64>,
        #[serde(default)]
        entropy_min: Option<f64>,
    },
    /// The `NT_GNU_BUILD_ID` (hex) is one of `values`.
    ElfBuildIdAny {
        values: Vec<String>,
    },
    /// At least `min` of `names` are imported by this ELF and NOT by the parent.
    NewElfImportSet {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },

    // --- Mach-O (`scanner::macho`) -------------------------------------------
    /// A loaded dylib's path ends with one of `names` (case-insensitive).
    MachoDylibAny {
        names: Vec<String>,
    },
    /// At least `min` of `names` are external symbols.
    MachoSymAny {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
    /// At least `min` external symbols match.
    MachoSymRegex {
        pattern: String,
        #[serde(default)]
        min: Option<usize>,
    },
    /// A segment with these properties (`flags_*` read the initial protection).
    MachoSegment {
        #[serde(default)]
        name: Option<String>,
        /// `r`, `w`, `x`.
        #[serde(default)]
        flags_all: Vec<String>,
        #[serde(default)]
        flags_none: Vec<String>,
        #[serde(default)]
        entropy_min: Option<f64>,
        #[serde(default)]
        entropy_max: Option<f64>,
    },
    /// `LC_UUID` is one of `values`.
    MachoUuidAny {
        values: Vec<String>,
    },
    /// Code signature: `signed`, ad-hoc, a glob over the signing identifier, the team id.
    MachoSigned {
        signed: bool,
        #[serde(default)]
        adhoc: Option<bool>,
        #[serde(default)]
        identifier_glob: Option<String>,
        #[serde(default)]
        team_id: Option<String>,
    },
    /// The embedded entitlements hold one of these keys.
    MachoEntitlementAny {
        keys: Vec<String>,
    },

    // --- PDF (`scanner::pdf`) -------------------------------------------------
    /// At least `min` of these names occur (after `#XX` unescaping).
    PdfKeyword {
        names: Vec<String>,
        #[serde(default)]
        min: Option<usize>,
    },
    /// At least `min` of `patterns` (text, or `{ hex }` byte patterns) occur in
    /// the streams (decoded unless `decoded: false`), optionally only in
    /// streams whose filter chain holds one of `filter_any`.
    PdfStreamMatch {
        #[serde(default)]
        filter_any: Option<Vec<String>>,
        patterns: Vec<String>,
        #[serde(default = "default_true")]
        decoded: bool,
        #[serde(default)]
        min: Option<usize>,
    },
}

/// Numeric feature bound used by [`RuleCondition::FeatureBounds`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureBound {
    pub feature: String,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
}

/// One step of an `emulated_sequence` condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatedStep {
    /// API name, case-insensitive; `CreateFileW|CopyFileW` accepts either.
    pub api: String,
    /// Regex one string argument of the call must match.
    #[serde(default)]
    pub pattern: Option<String>,
}

impl RuleCondition {
    /// The condition reads the emulation trace (`ScanReport::behavior`).
    pub fn is_emulated(&self) -> bool {
        matches!(
            self,
            RuleCondition::EmulatedApiAny { .. }
                | RuleCondition::EmulatedArgRegex { .. }
                | RuleCondition::EmulatedSequence { .. }
                | RuleCondition::EmulatedCountGte { .. }
        )
    }
}

/// One packer signature: a display name plus the byte pattern that identifies it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackerSignature {
    /// Packer name reported in the finding evidence, e.g. `UPack`.
    pub name: String,
    /// Hex byte pattern, same syntax as [`RuleCondition::BytePattern`].
    pub pattern: String,
}

/// Byte window a byte pattern is searched in.
///
/// Offsets are resolved against the file size. Negative values count backwards
/// from the end of the file, so `{ start: -4096 }` restricts the search to the
/// last 4 KiB (typical for appended overlay payloads) and `{ end: -4096 }`
/// restricts it to everything but the last 4 KiB.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ByteScope {
    /// Inclusive start offset, or negative to count from end of file.
    #[serde(default)]
    pub start: Option<i64>,
    /// Exclusive end offset, or negative to count from end of file.
    #[serde(default)]
    pub end: Option<i64>,
}

fn default_true() -> bool {
    true
}

fn default_anchor() -> String {
    "absolute".to_string()
}

fn default_opcode_region() -> String {
    "entry".to_string()
}

fn default_sector_count() -> u32 {
    1
}

/// One API a `bytecode` rule gives its program: what a call of that name returns.
/// Exactly one source is set; `table` and `param_arg` read the call's first argument.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BytecodeApi {
    /// A constant.
    #[serde(default)]
    pub value: Option<i64>,
    /// `params[i]` of the condition.
    #[serde(default)]
    pub param: Option<usize>,
    /// `params[arg0]`.
    #[serde(default)]
    pub param_arg: bool,
    /// `table[arg0]`, 0 past its end.
    #[serde(default)]
    pub table: Vec<i64>,
    /// A fact about the scanned file (`bytecode::FACTS`), e.g. `pe.sections`.
    #[serde(default)]
    pub fact: Option<String>,
    /// 1 when this condition matches the file, else 0.
    #[serde(default)]
    pub condition: Option<Box<RuleCondition>>,
}
