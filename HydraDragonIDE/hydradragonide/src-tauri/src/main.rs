// src-tauri/src/main.rs
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose, Engine};
use capstone::prelude::*;
use yara_x;

// --- SHARED DATA STRUCTURES ---

#[derive(Default)]
pub struct AppState {
    pub file_data: Mutex<Option<Vec<u8>>>,
    pub yara_hits: Mutex<Vec<YaraHit>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileInfo {
    pub path: String,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HexRow {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub hit_rules: Vec<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HexPage {
    pub rows: Vec<HexRow>,
    pub total_rows: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisasmRow {
    pub address: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct YaraHit {
    pub rule_name: String,
    pub namespace: String,
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XorCandidate {
    pub key: u8,
    pub ascii_score: f32,
    pub preview: String,
}

// --- ANALYSIS LOGIC ---

pub enum Arch { X86_64, X86_32, ARM64, ARM }

impl Arch {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "x86_64" => Ok(Arch::X86_64),
            "x86_32" | "x86" => Ok(Arch::X86_32),
            "arm64" | "aarch64" => Ok(Arch::ARM64),
            "arm" => Ok(Arch::ARM),
            _ => Err(format!("Unsupported architecture: {}", s)),
        }
    }
}

pub fn disassemble_logic(data: &[u8], offset: usize, arch: Arch, base_addr: u64, num_insns: usize) -> Result<Vec<DisasmRow>, String> {
    let cs = match arch {
        Arch::X86_64 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).syntax(arch::x86::ArchSyntax::Intel).build(),
        Arch::X86_32 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).syntax(arch::x86::ArchSyntax::Intel).build(),
        Arch::ARM64  => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).build(),
        Arch::ARM    => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build(),
    }.map_err(|e| format!("Capstone init error: {}", e))?;

    let start = offset.min(data.len());
    let end = (start + (num_insns * 15)).min(data.len());
    let code = &data[start..end];
    let insns = cs.disasm_all(code, base_addr + offset as u64).map_err(|e| format!("Disassembly failed: {}", e))?;

    Ok(insns.iter().take(num_insns).map(|i| DisasmRow {
        address: i.address(),
        bytes_hex: hex::encode(i.bytes()),
        mnemonic: i.mnemonic().unwrap_or("").to_string(),
        operands: i.op_str().unwrap_or("").to_string(),
    }).collect())
}

pub fn scan_yara_logic(data: &[u8], rules_source: &str) -> Result<Vec<YaraHit>, String> {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(rules_source).map_err(|e| format!("YARA compile error: {e}"))?;
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner.scan(data).map_err(|e| format!("YARA scan error: {e}"))?;

    let mut hits = Vec::new();
    for r in results.matching_rules() {
        let name = r.identifier().to_string();
        let ns   = r.namespace().to_string();
        for p in r.patterns() {
            let p_name = p.identifier().to_string();
            for m in p.matches() {
                hits.push(YaraHit {
                    rule_name: name.clone(), namespace: ns.clone(), pattern_name: p_name.clone(),
                    offset: m.range().start, length: m.range().len(),
                });
            }
        }
    }
    Ok(hits)
}

pub fn hit_mask_for_slice(hits: &[YaraHit], slice_offset: usize, slice_len: usize) -> Vec<Option<String>> {
    let mut mask = vec![None; slice_len];
    for hit in hits {
        let start = hit.offset.max(slice_offset);
        let end   = (hit.offset + hit.length).min(slice_offset + slice_len);
        if start < end {
            for i in start..end {
                mask[i - slice_offset] = Some(hit.rule_name.clone());
            }
        }
    }
    mask
}

pub fn xor_brute_force_logic(data: &[u8], sample_size: usize) -> Vec<XorCandidate> {
    let limit = data.len().min(sample_size);
    let sample = &data[..limit];
    if sample.is_empty() { return Vec::new(); }

    let mut candidates: Vec<XorCandidate> = (0x01u8..=0xFFu8).map(|key| {
        let decoded: Vec<u8> = sample.iter().map(|&b| b ^ key).collect();
        let printable = decoded.iter().filter(|&&b| b >= 0x20 && b < 0x7F).count();
        let ascii_score = printable as f32 / decoded.len() as f32;
        let preview: String = decoded.iter().take(64).map(|&b| if b >= 0x20 && b < 0x7F { b as char } else { '.' }).collect();
        XorCandidate { key, ascii_score, preview }
    }).collect();

    candidates.sort_by(|a, b| b.ascii_score.partial_cmp(&a.ascii_score).unwrap());
    candidates.truncate(20);
    candidates
}

// --- TAURI COMMANDS (WRAPPED) ---

mod commands {
    use super::*;

    #[tauri::command]
    pub fn open_file(state: tauri::State<AppState>) -> Result<Option<FileInfo>, String> {
        let path = rfd::FileDialog::new()
            .set_title("Open file for analysis")
            .pick_file();

        match path {
            None => Ok(None),
            Some(p) => {
                let bytes = std::fs::read(&p).map_err(|e| e.to_string())?;
                let mut h = Sha256::new();
                h.update(&bytes);
                let info = FileInfo {
                    path: p.to_string_lossy().to_string(),
                    size: bytes.len(),
                    sha256: hex::encode(h.finalize()),
                };
                *state.yara_hits.lock().unwrap() = Vec::new();
                *state.file_data.lock().unwrap() = Some(bytes);
                Ok(Some(info))
            }
        }
    }

    #[tauri::command]
    pub fn get_hex_page(offset: u64, num_rows: usize, state: tauri::State<AppState>) -> Result<HexPage, String> {
        let guard = state.file_data.lock().unwrap();
        let data = guard.as_ref().ok_or("No file loaded")?;
        let hits = state.yara_hits.lock().unwrap();
        let total_bytes = data.len();
        let total_rows  = (total_bytes + 15) / 16;
        let start_byte  = (offset as usize).min(total_bytes);

        let rows: Vec<HexRow> = (0..num_rows).filter_map(|i| {
            let row_start = start_byte + i * 16;
            if row_start >= total_bytes { return None; }
            let row_end = (row_start + 16).min(total_bytes);
            let row_bytes = data[row_start..row_end].to_vec();
            let hit_rules = hit_mask_for_slice(&hits, row_start, row_bytes.len());
            Some(HexRow { offset: row_start as u64, bytes: row_bytes, hit_rules })
        }).collect();

        Ok(HexPage { rows, total_rows, total_bytes })
    }

    #[tauri::command]
    pub fn disassemble_at(offset: u64, arch: String, base_addr: u64, num_insns: usize, state: tauri::State<AppState>) -> Result<Vec<DisasmRow>, String> {
        let guard = state.file_data.lock().unwrap();
        let data = guard.as_ref().ok_or("No file loaded")?;
        let arch_enum = Arch::from_str(&arch)?;
        disassemble_logic(data, offset as usize, arch_enum, base_addr, num_insns)
    }

    #[tauri::command]
    pub fn scan_yara(rules_source: String, state: tauri::State<AppState>) -> Result<Vec<YaraHit>, String> {
        let guard = state.file_data.lock().unwrap();
        let data  = guard.as_ref().ok_or("No file loaded")?;
        let hits = scan_yara_logic(data, &rules_source)?;
        *state.yara_hits.lock().unwrap() = hits.clone();
        Ok(hits)
    }

    #[tauri::command]
    pub fn xor_brute_force(sample_size: usize, state: tauri::State<AppState>) -> Result<Vec<XorCandidate>, String> {
        let guard = state.file_data.lock().unwrap();
        let data  = guard.as_ref().ok_or("No file loaded")?;
        Ok(xor_brute_force_logic(data, sample_size))
    }

    #[tauri::command]
    pub fn xor_decode_region(offset: u64, length: usize, key_hex: String, state: tauri::State<AppState>) -> Result<String, String> {
        let guard = state.file_data.lock().unwrap();
        let data  = guard.as_ref().ok_or("No file loaded")?;
        let key = hex::decode(key_hex.trim()).map_err(|e| format!("Bad key hex: {e}"))?;
        if key.is_empty() { return Err("Key empty".into()); }
        let start = (offset as usize).min(data.len());
        let end   = (start + length).min(data.len());
        let decoded: Vec<u8> = data[start..end].iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
        Ok(hex::encode_upper(&decoded))
    }

    #[tauri::command]
    pub fn base64_encode_region(offset: u64, length: usize, state: tauri::State<AppState>) -> Result<String, String> {
        let guard = state.file_data.lock().unwrap();
        let data  = guard.as_ref().ok_or("No file loaded")?;
        let start = (offset as usize).min(data.len());
        let end   = (start + length).min(data.len());
        Ok(general_purpose::STANDARD.encode(&data[start..end]))
    }

    #[tauri::command]
    pub fn base64_decode_str(input: String) -> Result<String, String> {
        let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = general_purpose::STANDARD.decode(cleaned.as_bytes()).map_err(|e| e.to_string())?;
        Ok(hex::encode_upper(&bytes))
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::open_file, commands::get_hex_page, commands::disassemble_at, commands::scan_yara,
            commands::xor_brute_force, commands::xor_decode_region, commands::base64_encode_region, commands::base64_decode_str
        ])
        .run(tauri::generate_context!())
        .expect("error while running HydraDragonIDE");
}
