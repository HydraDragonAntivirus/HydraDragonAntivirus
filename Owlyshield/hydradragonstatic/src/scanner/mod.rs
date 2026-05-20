pub mod env;
pub mod filetype;
pub mod pe;
pub mod registry;
pub mod strings;

use crate::models::{DecodedString, EnvHit, FileTypeInfo, PeInfo, RegistryHit, StringHit};
use crate::utils::{entropy::byte_entropy, hash::hashes};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub file_size: u64,
    pub entropy: f64,
    pub hashes: crate::models::Hashes,
    pub pe: Option<PeInfo>,
    pub file_type: FileTypeInfo,
    pub strings: Vec<StringHit>,
    pub decoded_strings: Vec<DecodedString>,
    pub env_hits: Vec<EnvHit>,
    pub registry_hits: Vec<RegistryHit>,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub min_string_len: usize,
    pub decode_obfuscated_strings: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            min_string_len: 5,
            decode_obfuscated_strings: true,
        }
    }
}

pub struct HydraScanner;

impl HydraScanner {
    pub fn scan(path: &Path) -> Result<ScanContext> {
        Self::scan_with_config(path, &ScannerConfig::default())
    }

    pub fn scan_with_config(path: &Path, config: &ScannerConfig) -> Result<ScanContext> {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let file_size = bytes.len() as u64;
        let entropy = byte_entropy(&bytes);
        let hashes = hashes(&bytes);
        let strings = strings::extract_strings(&bytes, config.min_string_len.max(1));
        let decoded_strings = if config.decode_obfuscated_strings {
            strings::decode_obfuscated_strings(&strings)
        } else {
            Vec::new()
        };
        let pe = pe::scan_pe(&bytes);
        let file_type = filetype::classify_bytes(path, &bytes);
        let env_hits = env::scan_environment(&strings, &decoded_strings);
        let registry_hits =
            registry::scan_registry_indicators(&strings, &decoded_strings, pe.as_ref());
        Ok(ScanContext {
            path: path.to_path_buf(),
            bytes,
            file_size,
            entropy,
            hashes,
            pe,
            file_type,
            strings,
            decoded_strings,
            env_hits,
            registry_hits,
        })
    }
}
