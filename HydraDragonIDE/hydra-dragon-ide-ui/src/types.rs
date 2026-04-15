// src/types.rs — shared types matching backend serde layout exactly.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileInfo { pub path: String, pub size: usize, pub sha256: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HexRow {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub hit_rules: Vec<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HexPage { pub rows: Vec<HexRow>, pub total_rows: usize, pub total_bytes: usize }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisasmRow { pub address: u64, pub bytes_hex: String, pub mnemonic: String, pub operands: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct YaraHit {
    pub rule_name: String, pub namespace: String,
    pub pattern_name: String, pub offset: usize, pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XorCandidate { pub key: u8, pub ascii_score: f32, pub preview: String }

// ── Entropy ─────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntropyResult { pub offset: u64, pub entropy: f32, pub class: String, pub colour: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntropySummary { pub min: f32, pub max: f32, pub mean: f32, pub blocks: Vec<EntropyResult> }

// ── Strings ─────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractedString { pub offset: u64, pub kind: String, pub value: String, pub length: usize }

// ── PE / ELF headers ────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeaderField { pub name: String, pub value: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SectionInfo {
    pub name: String, pub virt_addr: String, pub virt_size: String,
    pub raw_offset: String, pub raw_size: String, pub entropy: f32, pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportEntry { pub dll: String, pub function: String, pub ordinal: Option<u32> }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportEntry { pub name: Option<String>, pub offset: String, pub ordinal: u32 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParsedHeaders {
    pub format: String,
    pub fields: Vec<HeaderField>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
}

// ── Tab enums ────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
pub enum BottomTab {
    YaraRules, YaraResults,
    XorDecoder, Base64,
    Strings, Entropy, PeHeaders,
}
