// src-tauri/src/decoders.rs
// XOR brute-force, single/multi-byte XOR decode, and Base64 encode/decode.

use base64::{engine::general_purpose, Engine};
use crate::state::XorCandidate;

// ─── XOR ─────────────────────────────────────────────────────────────────────

/// Apply a repeating XOR key to `data`.
pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Brute-force single-byte XOR (keys 0x01..=0xFF).
/// Scores each candidate by printable-ASCII ratio and returns the top 20.
pub fn xor_brute_force(data: &[u8], sample_size: usize) -> Vec<XorCandidate> {
    let sample = &data[..data.len().min(sample_size)];

    let mut candidates: Vec<XorCandidate> = (0x01u8..=0xFFu8)
        .map(|key| {
            let decoded: Vec<u8> = sample.iter().map(|&b| b ^ key).collect();
            let printable = decoded
                .iter()
                .filter(|&&b| b >= 0x20 && b < 0x7F)
                .count();
            let ascii_score = printable as f32 / decoded.len() as f32;

            let preview: String = decoded
                .iter()
                .take(64)
                .map(|&b| if b >= 0x20 && b < 0x7F { b as char } else { '.' })
                .collect();

            XorCandidate { key, ascii_score, preview }
        })
        .collect();

    // Sort descending by ASCII ratio
    candidates.sort_by(|a, b| b.ascii_score.partial_cmp(&a.ascii_score).unwrap());
    candidates.truncate(20);
    candidates
}

// ─── Base64 ──────────────────────────────────────────────────────────────────

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Strip whitespace before decoding
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| e.to_string())
}
