// src-tauri/src/state.rs
// Shared application state managed by Tauri.

use std::sync::Mutex;
use serde::{Deserialize, Serialize};

/// Global file buffer + scan results — shared across all commands.
#[derive(Default)]
pub struct AppState {
    /// Raw bytes of the currently loaded file.
    pub file_data: Mutex<Option<Vec<u8>>>,
    /// YARA-X scan hits from the last `scan_yara` call.
    pub yara_hits: Mutex<Vec<YaraHit>>,
}

// ─── Serialisable result types shared with the frontend ────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: usize,
    pub sha256: String,
}

/// One rendered row in the hex view (16 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexRow {
    /// Absolute file offset of the first byte in this row.
    pub offset: u64,
    /// Up to 16 raw bytes (last row may be shorter).
    pub bytes: Vec<u8>,
    /// Per-byte YARA hit information.
    /// `None` → no hit at this byte index.
    /// `Some(rule_name)` → this byte is inside a YARA match.
    pub hit_rules: Vec<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPage {
    pub rows: Vec<HexRow>,
    pub total_rows: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmRow {
    pub address: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraHit {
    pub rule_name: String,
    pub namespace: String,
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
}

/// Single-byte XOR brute-force candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorCandidate {
    pub key: u8,
    /// Ratio of printable ASCII bytes in the decoded output.
    pub ascii_score: f32,
    /// First 64 chars of decoded output (printable UTF-8).
    pub preview: String,
}
