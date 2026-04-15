// src-tauri/src/entropy.rs
// Computes Shannon entropy for the entire file in fixed-size blocks.
// Used to render the entropy graph and flag packed/encrypted regions.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBlock {
    /// File offset of the first byte in this block.
    pub offset: u64,
    /// Shannon entropy value in [0.0, 8.0].
    pub entropy: f32,
}

/// Classify an entropy value into a human-readable category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EntropyClass {
    /// Very low — likely zeroed/padding (< 1.0).
    Zeroed,
    /// Low — plaintext / source code (1.0–4.5).
    Plaintext,
    /// Medium — compiled code / data (4.5–6.5).
    Code,
    /// High — compressed or encrypted (6.5–7.2).
    Compressed,
    /// Very high — likely encrypted / packed (> 7.2).
    Encrypted,
}

impl EntropyClass {
    pub fn from_f32(e: f32) -> Self {
        if e < 1.0      { EntropyClass::Zeroed }
        else if e < 4.5 { EntropyClass::Plaintext }
        else if e < 6.5 { EntropyClass::Code }
        else if e < 7.2 { EntropyClass::Compressed }
        else            { EntropyClass::Encrypted }
    }

    /// CSS colour token for the frontend heat-map.
    pub fn colour(&self) -> &'static str {
        match self {
            EntropyClass::Zeroed     => "#1e2a38",
            EntropyClass::Plaintext  => "#166534",
            EntropyClass::Code       => "#4fc3f7",
            EntropyClass::Compressed => "#fb923c",
            EntropyClass::Encrypted  => "#f87171",
        }
    }
}

impl Serialize for EntropyClass {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            EntropyClass::Zeroed     => "Zeroed",
            EntropyClass::Plaintext  => "Plaintext",
            EntropyClass::Code       => "Code",
            EntropyClass::Compressed => "Compressed",
            EntropyClass::Encrypted  => "Encrypted",
        })
    }
}

impl<'de> Deserialize<'de> for EntropyClass {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.as_str() {
            "Zeroed"     => EntropyClass::Zeroed,
            "Plaintext"  => EntropyClass::Plaintext,
            "Code"       => EntropyClass::Code,
            "Compressed" => EntropyClass::Compressed,
            _            => EntropyClass::Encrypted,
        })
    }
}

/// Annotated block returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub offset:  u64,
    pub entropy: f32,
    pub class:   EntropyClass,
    /// Hex colour for the visualiser.
    pub colour:  String,
}

/// Compute Shannon entropy of a byte slice.
pub fn shannon(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

/// Compute entropy for the full file in `block_size`-byte blocks.
/// A typical call uses `block_size = 256`.
pub fn file_entropy(data: &[u8], block_size: usize) -> Vec<EntropyResult> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }
    data.chunks(block_size)
        .enumerate()
        .map(|(i, chunk)| {
            let offset  = (i * block_size) as u64;
            let entropy = shannon(chunk);
            let class   = EntropyClass::from_f32(entropy);
            let colour  = class.colour().to_string();
            EntropyResult { offset, entropy, class, colour }
        })
        .collect()
}

/// Summary stats over the whole file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropySummary {
    pub min:  f32,
    pub max:  f32,
    pub mean: f32,
    pub blocks: Vec<EntropyResult>,
}

pub fn summarise(data: &[u8], block_size: usize) -> EntropySummary {
    let blocks = file_entropy(data, block_size);
    let (min, max, sum) = blocks.iter().fold(
        (f32::MAX, f32::MIN, 0.0f32),
        |(mn, mx, s), b| (mn.min(b.entropy), mx.max(b.entropy), s + b.entropy),
    );
    let mean = if blocks.is_empty() { 0.0 } else { sum / blocks.len() as f32 };
    let min  = if min == f32::MAX { 0.0 } else { min };
    let max  = if max == f32::MIN { 0.0 } else { max };
    EntropySummary { min, max, mean, blocks }
}
