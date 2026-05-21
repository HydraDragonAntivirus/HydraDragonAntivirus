pub mod env;
pub mod filetype;
pub mod pe;
pub mod registry;
pub mod strings;

use crate::models::{
    ArchiveMemberResult, CoreInitOptions, DecodedString, EnvHit, FileTypeInfo, MemoryScanContext,
    PeInfo, RegistryHit, ScanResultCode, ScanStatistics, StringHit, UnpackConfig,
};
use crate::utils::{entropy::byte_entropy, hash::hashes};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Instant;

use strings::{DecodeConfig, ExtractConfig};

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
    pub statistics: ScanStatistics,
    pub result_code: ScanResultCode,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub min_string_len: usize,
    pub decode_obfuscated_strings: bool,
    pub decode_config: DecodeConfig,
    pub core_options: CoreInitOptions,
    pub unpack_config: UnpackConfig,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            min_string_len: 5,
            decode_obfuscated_strings: true,
            decode_config: DecodeConfig::default(),
            core_options: CoreInitOptions::default(),
            unpack_config: UnpackConfig::default(),
        }
    }
}

pub struct HydraScanner;

impl HydraScanner {
    pub fn scan(path: &Path) -> Result<ScanContext> {
        Self::scan_with_config(path, &ScannerConfig::default())
    }

    pub fn scan_with_config(path: &Path, config: &ScannerConfig) -> Result<ScanContext> {
        let start_time = Instant::now();
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let ctx = Self::build_scan_context(
            bytes,
            path.to_path_buf(),
            config,
            start_time,
        )?;
        Ok(ctx)
    }

    pub fn scan_memory(ctx: &MemoryScanContext, config: &ScannerConfig) -> Result<ScanContext> {
        let start_time = Instant::now();
        let path = PathBuf::from(format!("memory://{}", ctx.identifier));
        // Clone only once; all downstream work borrows from this copy.
        let bytes = ctx.buffer.clone();
        Self::build_scan_context(bytes, path, config, start_time)
    }

    pub fn enumerate_archive_members(
        path: &Path,
        config: &UnpackConfig,
    ) -> Result<Vec<ArchiveMemberResult>> {
        if !config.enable_archives {
            return Ok(Vec::new());
        }

        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read archive {}", path.display()))?;

        if bytes.len() as u64 > config.max_archive_size {
            return Ok(Vec::new());
        }

        let file_type = filetype::classify_bytes(path, &bytes);
        if !file_type.is_archive && !file_type.is_zip {
            return Ok(Vec::new());
        }

        Ok(Vec::new())
    }

    // ── Shared core logic ─────────────────────────────────────────────────────

    fn build_scan_context(
        bytes: Vec<u8>,
        path: PathBuf,
        config: &ScannerConfig,
        start_time: Instant,
    ) -> Result<ScanContext> {
        let file_size = bytes.len() as u64;
        let entropy = byte_entropy(&bytes);
        let hashes = hashes(&bytes);

        let extract_cfg = ExtractConfig {
            min_len: config.min_string_len.max(1),
        };
        let strings = strings::extract_strings(&bytes, &extract_cfg);

        let decoded_strings = if config.decode_obfuscated_strings {
            strings::decode_obfuscated_strings(&strings, &config.decode_config)
        } else {
            Vec::new()
        };

        let pe = pe::scan_pe(&bytes);
        let file_type = if path.starts_with("memory://") {
            filetype::classify_bytes_only(&bytes)
        } else {
            filetype::classify_bytes(&path, &bytes)
        };
        let env_hits = env::scan_environment(&strings, &decoded_strings);
        let registry_hits =
            registry::scan_registry_indicators(&strings, &decoded_strings, pe.as_ref());

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;
        let is_container = file_type.is_archive || file_type.is_zip || file_type.is_7z;

        let statistics = ScanStatistics {
            files_scanned: 1,
            infections_found: 0,
            suspicious_found: 0,
            is_container,
            archive_members: 0,
            scan_duration_ms,
            signature_records_used: 0,
        };

        Ok(ScanContext {
            path,
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
            statistics,
            result_code: ScanResultCode::Ok,
        })
    }
}
