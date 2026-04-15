// src-tauri/src/lib.rs
// All Tauri commands and the app builder.

mod decoders;
mod disasm;
mod entropy;
mod pe_info;
mod state;
mod strings;
mod yara_scan;

use sha2::{Digest, Sha256};
use state::{AppState, DisasmRow, FileInfo, HexPage, HexRow, XorCandidate, YaraHit};
use entropy::EntropySummary;
use pe_info::ParsedHeaders;
use strings::ExtractedString;

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

const BYTES_PER_ROW: usize = 16;

#[tauri::command]
fn open_file(state: tauri::State<AppState>) -> Result<Option<FileInfo>, String> {
    let path = rfd::FileDialog::new()
        .add_filter("Executables & binaries",
            &["exe","dll","so","dylib","elf","bin","sys","drv"])
        .add_filter("All files", &["*"])
        .pick_file();
    match path {
        None => Ok(None),
        Some(p) => {
            let bytes = std::fs::read(&p).map_err(|e| e.to_string())?;
            let info  = FileInfo {
                path:   p.to_string_lossy().to_string(),
                size:   bytes.len(),
                sha256: sha256_hex(&bytes),
            };
            *state.yara_hits.lock().unwrap() = Vec::new();
            *state.file_data.lock().unwrap() = Some(bytes);
            Ok(Some(info))
        }
    }
}

#[tauri::command]
fn get_hex_page(offset: u64, num_rows: usize, state: tauri::State<AppState>) -> Result<HexPage, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    let hits  = state.yara_hits.lock().unwrap();
    let total_bytes = data.len();
    let total_rows  = (total_bytes + BYTES_PER_ROW - 1) / BYTES_PER_ROW;
    let start_byte  = (offset as usize).min(total_bytes);
    let rows: Vec<HexRow> = (0..num_rows).filter_map(|i| {
        let row_start = start_byte + i * BYTES_PER_ROW;
        if row_start >= total_bytes { return None; }
        let row_end   = (row_start + BYTES_PER_ROW).min(total_bytes);
        let row_bytes = data[row_start..row_end].to_vec();
        let row_len   = row_bytes.len();
        let hit_rules = yara_scan::hit_mask_for_slice(&hits, row_start, row_len);
        Some(HexRow { offset: row_start as u64, bytes: row_bytes, hit_rules })
    }).collect();
    Ok(HexPage { rows, total_rows, total_bytes })
}

#[tauri::command]
fn disassemble_at(offset: u64, arch: String, base_addr: u64, num_insns: usize, state: tauri::State<AppState>) -> Result<Vec<DisasmRow>, String> {
    let guard     = state.file_data.lock().unwrap();
    let data      = guard.as_ref().ok_or("No file loaded")?;
    let arch_enum = disasm::Arch::from_str(&arch)?;
    disasm::disassemble(data, offset as usize, arch_enum, base_addr, num_insns)
}

#[tauri::command]
fn scan_yara(rules_source: String, state: tauri::State<AppState>) -> Result<Vec<YaraHit>, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    let hits  = yara_scan::scan(data, &rules_source)?;
    *state.yara_hits.lock().unwrap() = hits.clone();
    Ok(hits)
}

#[tauri::command]
fn get_yara_hits(state: tauri::State<AppState>) -> Vec<YaraHit> {
    state.yara_hits.lock().unwrap().clone()
}

#[tauri::command]
fn xor_brute_force(sample_size: usize, state: tauri::State<AppState>) -> Result<Vec<XorCandidate>, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    Ok(decoders::xor_brute_force(data, sample_size))
}

#[tauri::command]
fn xor_decode_region(offset: u64, length: usize, key_hex: String, state: tauri::State<AppState>) -> Result<String, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    let key   = hex::decode(key_hex.trim()).map_err(|e| format!("Bad key hex: {e}"))?;
    if key.is_empty() { return Err("Key cannot be empty".into()); }
    let start = (offset as usize).min(data.len());
    let end   = (start + length).min(data.len());
    Ok(hex::encode_upper(&decoders::xor_decode(&data[start..end], &key)))
}

#[tauri::command]
fn base64_encode_region(offset: u64, length: usize, state: tauri::State<AppState>) -> Result<String, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    let start = (offset as usize).min(data.len());
    let end   = (start + length).min(data.len());
    Ok(decoders::base64_encode(&data[start..end]))
}

#[tauri::command]
fn base64_decode_str(input: String) -> Result<String, String> {
    let bytes = decoders::base64_decode(&input)?;
    Ok(hex::encode_upper(&bytes))
}

#[tauri::command]
fn compute_entropy(block_size: usize, state: tauri::State<AppState>) -> Result<EntropySummary, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    let bs    = if block_size == 0 { 256 } else { block_size };
    Ok(entropy::summarise(data, bs))
}

#[tauri::command]
fn extract_strings(min_len: usize, state: tauri::State<AppState>) -> Result<Vec<ExtractedString>, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    let min   = if min_len == 0 { 4 } else { min_len };
    Ok(strings::extract_all(data, min))
}

#[tauri::command]
fn parse_headers(state: tauri::State<AppState>) -> Result<ParsedHeaders, String> {
    let guard = state.file_data.lock().unwrap();
    let data  = guard.as_ref().ok_or("No file loaded")?;
    pe_info::parse(data)
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            open_file, get_hex_page, disassemble_at,
            scan_yara, get_yara_hits,
            xor_brute_force, xor_decode_region,
            base64_encode_region, base64_decode_str,
            compute_entropy, extract_strings, parse_headers,
        ])
        .run(tauri::generate_context!())
        .expect("error while running HydraDragonIDE");
}
