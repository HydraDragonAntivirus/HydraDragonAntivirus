#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const QUARANTINE_MAGIC: &[u8; 7] = b"HYDRA\x00\x01";
const XOR_KEY: u8 = 0xA5;

#[derive(Serialize, Deserialize, Debug)]
pub struct QuarantineMeta {
    pub original_path: String,
    pub detection: String,
    pub sha256: String,
    pub timestamp: u64,
    pub original_size: usize,
}

#[derive(Debug)]
pub enum QuarantineError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidMagic,
}

impl From<io::Error> for QuarantineError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for QuarantineError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::InvalidMagic => write!(f, "Not a HydraDragon quarantine file"),
        }
    }
}

impl std::error::Error for QuarantineError {}

pub fn compute_sha256(src: &Path) -> Result<String, QuarantineError> {
    let mut file = fs::File::open(src)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

pub fn quarantine_file(
    src: &Path,
    dst: &Path,
    detection: &str,
    sha256: &str,
) -> Result<(), QuarantineError> {
    let payload = fs::read(src)?;
    let xored: Vec<u8> = payload.iter().map(|b| b ^ XOR_KEY).collect();

    let meta = QuarantineMeta {
        original_path: src.to_string_lossy().to_string(),
        detection: detection.to_string(),
        sha256: sha256.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        original_size: payload.len(),
    };

    let meta_bytes = serde_json::to_vec(&meta)?;

    let mut file = fs::File::create(dst)?;
    file.write_all(QUARANTINE_MAGIC)?;
    file.write_all(&(meta_bytes.len() as u32).to_le_bytes())?;
    file.write_all(&meta_bytes)?;
    file.write_all(&(xored.len() as u32).to_le_bytes())?;
    file.write_all(&xored)?;
    Ok(())
}

pub fn restore_file(src: &Path, dst: &Path) -> Result<QuarantineMeta, QuarantineError> {
    let mut file = fs::File::open(src)?;

    let mut magic = [0_u8; 7];
    file.read_exact(&mut magic)?;
    if &magic != QUARANTINE_MAGIC {
        return Err(QuarantineError::InvalidMagic);
    }

    let mut len_buf = [0_u8; 4];
    file.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;

    let mut meta_bytes = vec![0_u8; meta_len];
    file.read_exact(&mut meta_bytes)?;
    let meta: QuarantineMeta = serde_json::from_slice(&meta_bytes)?;

    file.read_exact(&mut len_buf)?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    let mut xored = vec![0_u8; payload_len];
    file.read_exact(&mut xored)?;

    let payload: Vec<u8> = xored.iter().map(|b| b ^ XOR_KEY).collect();
    fs::write(dst, &payload)?;

    Ok(meta)
}

pub fn read_meta(src: &Path) -> Result<QuarantineMeta, QuarantineError> {
    let mut file = fs::File::open(src)?;

    let mut magic = [0_u8; 7];
    file.read_exact(&mut magic)?;
    if &magic != QUARANTINE_MAGIC {
        return Err(QuarantineError::InvalidMagic);
    }

    let mut len_buf = [0_u8; 4];
    file.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;

    let mut meta_bytes = vec![0_u8; meta_len];
    file.read_exact(&mut meta_bytes)?;

    Ok(serde_json::from_slice(&meta_bytes)?)
}
