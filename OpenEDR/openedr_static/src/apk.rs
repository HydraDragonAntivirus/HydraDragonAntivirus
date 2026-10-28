//! APK support for the web edition: ZIP/APK detection, DEX/ELF/manifest
//! parsing, heuristics, and our own tree-model feature vector.
//!
//! APKs score **like PE/JS**: a fixed 24-float feature vector
//! ([`apk_tree_features`]) feeds a random-forest bundle (`apk_trees.bin`)
//! executed by the same [`crate::ml::tree_model::TreeEnsembleModel`] that
//! runs the PE/JS/URL trees. The forest is trained on our own benign/malware
//! APK corpora with `src/bin/apk-tree-train.rs` — no mobile weights, no
//! vocabulary files, no ONNX runtime. Until the bundle is shipped the engine
//! still flags APK malware through [`apk_heuristics`], so unscored APKs
//! return `Unknown`, never `Error`.

use std::collections::HashSet;

/// Tree-model feature count. Features 0..23 are frozen for full backward compatibility
/// with existing 24-feature forests; features 24..57 provide deep Dalvik API invocation,
/// native ELF symbols, protector detection, and XOR filter String ML metrics.
pub const APK_TREE_FEATURE_COUNT: usize = 58;

pub const APK_TREE_FEATURE_NAMES: [&str; APK_TREE_FEATURE_COUNT] = [
    // 0..23: Original frozen features
    "dex_classes",
    "dex_strings",
    "dex_methods",
    "dex_files",
    "elf_so_count",
    "perm_total",
    "activities",
    "services",
    "receivers",
    "min_sdk",
    "target_sdk",
    "entropy",
    "entry_count",
    "file_size_log",
    "manifest_size_log",
    "dex_size_log",
    "so_size_log",
    "dangerous_perm_count",
    "sms_trio",
    "has_manifest",
    "multidex",
    "compression_ratio",
    "avg_entry_size_log",
    "native_with_perms",

    // 24..30: Native .so detailed architecture & symbols
    "has_arm64",
    "has_arm32",
    "has_x86",
    "has_x86_64",
    "so_exported_jni_count",
    "so_imported_symbols_count",
    "so_suspicious_imports_count",

    // 31..37: Manifest high-risk capability flags
    "perm_boot_completed",
    "perm_accessibility_service",
    "perm_device_admin",
    "perm_system_alert_window",
    "perm_install_packages",
    "perm_read_phone_state",
    "perm_external_storage_write",

    // 38..46: Dalvik sensitive API invocation signals
    "api_reflection_calls",
    "api_dynamic_dex_loading",
    "api_crypto_cipher_calls",
    "api_process_exec_calls",
    "api_sms_send_calls",
    "api_device_id_calls",
    "api_network_http_calls",
    "api_package_manager_queries",
    "api_anti_debug_root_calls",

    // 47..51: Packaging, assets, protector anomalies
    "assets_entry_count",
    "assets_size_log",
    "has_hidden_payload_in_assets",
    "is_protector_packed",
    "has_non_standard_dex",

    // 52..57: String ML & Threat density metrics
    "mal_str_hits",
    "ben_str_hits",
    "mal_ben_str_ratio",
    "mal_str_density",
    "unknown_str_ratio",
    "total_unique_strings_log",
];

/// Per-entry / total decompression caps so a hostile 200 MB APK cannot OOM
/// the browser tab.
pub const MAX_ENTRY_SCAN: usize = 8 * 1024 * 1024;
pub const MAX_TOTAL_SCAN: usize = 32 * 1024 * 1024;
/// Central-directory walk cap.
const MAX_ENTRIES: usize = 8192;
/// Profile pass caps: manifest bytes and total inflated bytes inspected for
/// features/heuristics (central-dir sizes are free and exact).
const PROFILE_MANIFEST_CAP: usize = 2 * 1024 * 1024;
const PROFILE_TOTAL_CAP: usize = 8 * 1024 * 1024;
const PROFILE_DEX_PREFIX: u64 = 4096;
const PROFILE_MAX_DEX: usize = 32;

// ---------------------------------------------------------------------------
// Minimal ZIP reader (central directory + local headers, no external crate)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ZipEntryMeta {
    name: String,
    method: u16,
    comp_size: u32,
    uncomp_size: u32,
    local_offset: u32,
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn read_i32_le(b: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Locate the End-of-Central-Directory and parse entry metadata.
/// Returns `None` when `data` is not a ZIP (APK) at all.
///
/// Malware APKs often carry trailing overlays/payloads past the EOCD, so the
/// search scans the whole file backwards and accepts the last candidate
/// that validates (sane entry count + central directory offset landing on
/// a `PK\x01\x02` header) instead of only looking at the last 64 KB.
fn parse_central_dir(data: &[u8]) -> Option<Vec<ZipEntryMeta>> {
    if data.len() < 22 || data[0] != b'P' || data[1] != b'K' {
        return None;
    }
    let mut i = data.len().saturating_sub(4);
    loop {
        if data[i] == 0x50 && data[i + 1] == 0x4b && data[i + 2] == 0x05 && data[i + 3] == 0x06
        {
            if i + 22 <= data.len() {
                if let Some(entries) = parse_central_dir_at(data, i) {
                    return Some(entries);
                }
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    // Fallback for EOCD-less archives (malware with a destroyed/overwritten
    // EOCD but an intact central directory, e.g. appended payloads): take
    // the longest run of consecutive valid central-directory headers.
    parse_central_dir_fallback(data)
}

/// Parse up to `limit` entries forward from `cd_offset`. Stops at the first
/// malformed header (returns what parsed so far, possibly empty).
fn parse_entries_at(data: &[u8], cd_offset: usize, limit: usize) -> Vec<ZipEntryMeta> {
    let mut entries = Vec::with_capacity(limit.min(1024));
    let mut off = cd_offset;
    for _ in 0..limit.min(MAX_ENTRIES) {
        if off + 46 > data.len() {
            break;
        }
        let (Some(method), Some(comp_size), Some(uncomp_size)) = (
            read_u16_le(data, off + 10),
            read_u32_le(data, off + 20),
            read_u32_le(data, off + 24),
        ) else {
            break;
        };
        if read_u32_le(data, off) != Some(0x0201_4b50) {
            break;
        }
        let (Some(fname_len), Some(extra_len), Some(comment_len)) = (
            read_u16_le(data, off + 28).map(|v| v as usize),
            read_u16_le(data, off + 30).map(|v| v as usize),
            read_u16_le(data, off + 32).map(|v| v as usize),
        ) else {
            break;
        };
        let local_offset = match read_u32_le(data, off + 42) {
            Some(v) => v,
            None => break,
        };
        let name_off = off + 46;
        let name_end = match name_off.checked_add(fname_len) {
            Some(v) => v,
            None => break,
        };
        if name_end > data.len() || fname_len > 2048 {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_off..name_end]).into_owned();
        entries.push(ZipEntryMeta {
            name,
            method,
            comp_size,
            uncomp_size,
            local_offset,
        });
        off = match name_end.checked_add(extra_len).and_then(|v| v.checked_add(comment_len)) {
            Some(v) => v,
            None => break,
        };
        if off >= data.len() {
            break;
        }
    }
    entries
}

/// EOCD-less fallback: scan for `PK\x01\x02` positions (first 64) and keep
/// the longest valid entry run (minimum 2 — single hits are usually
/// compressed-data coincidence). First wins ties, like the Python trainer.
fn parse_central_dir_fallback(data: &[u8]) -> Option<Vec<ZipEntryMeta>> {
    let mut best: Vec<ZipEntryMeta> = Vec::new();
    let mut found = 0usize;
    let mut i = 0usize;
    while i + 4 <= data.len() && found < 64 {
        if data[i] == 0x50 && data[i + 1] == 0x4b && data[i + 2] == 0x01 && data[i + 3] == 0x02
        {
            found += 1;
            let run = parse_entries_at(data, i, MAX_ENTRIES);
            if run.len() > best.len() {
                best = run;
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    if best.len() >= 2 {
        Some(best)
    } else {
        None
    }
}

/// Parse entries from one EOCD candidate offset. `None` = candidate invalid,
/// keep searching (NOT a final verdict on the file).
fn parse_central_dir_at(data: &[u8], eocd: usize) -> Option<Vec<ZipEntryMeta>> {
    let total_entries = read_u16_le(data, eocd + 10)? as usize;
    let cd_offset = read_u32_le(data, eocd + 16)? as usize;
    if total_entries == 0 || total_entries > MAX_ENTRIES {
        return None;
    }
    if cd_offset >= data.len() {
        return None;
    }
    // The central directory must actually start here — otherwise this
    // PK\x05\x06 was compressed-data coincidence, not an EOCD.
    if read_u32_le(data, cd_offset)? != 0x0201_4b50 {
        return None;
    }
    let entries = parse_entries_at(data, cd_offset, total_entries);
    if entries.is_empty() {
        return None;
    }
    Some(entries)
}

/// Byte offset of an entry's compressed payload (past the local header).
fn local_data_offset(data: &[u8], local_off: u32) -> Option<usize> {
    let off = local_off as usize;
    if off + 30 > data.len() {
        return None;
    }
    if read_u32_le(data, off)? != 0x0403_4b50 {
        return None;
    }
    let fname_len = read_u16_le(data, off + 26)? as usize;
    let extra_len = read_u16_le(data, off + 28)? as usize;
    if fname_len > 4096 || extra_len > 65536 {
        return None;
    }
    off.checked_add(30)?
        .checked_add(fname_len)?
        .checked_add(extra_len)
}

/// Decompress one entry (stored / deflated only), capped at `MAX_ENTRY_SCAN`.
fn read_entry_data(data: &[u8], entry: &ZipEntryMeta) -> Option<Vec<u8>> {
    if entry.comp_size == 0xFFFF_FFFF || entry.uncomp_size == 0xFFFF_FFFF {
        return None;
    }
    let data_off = local_data_offset(data, entry.local_offset)?;
    let comp_len = entry.comp_size as usize;
    let compressed = data.get(data_off..data_off.checked_add(comp_len)?)?;
    match entry.method {
        0 => {
            if compressed.len() > MAX_ENTRY_SCAN {
                return None;
            }
            Some(compressed.to_vec())
        }
        8 => {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            if comp_len == 0 || comp_len > MAX_ENTRY_SCAN * 4 {
                return None;
            }
            let cap = (entry.uncomp_size as usize).min(MAX_ENTRY_SCAN);
            let mut out = Vec::with_capacity(cap.min(1 << 20).max(1024));
            let mut decoder = DeflateDecoder::new(compressed);
            decoder
                .by_ref()
                .take(MAX_ENTRY_SCAN as u64)
                .read_to_end(&mut out)
                .ok()?;
            if out.is_empty() {
                return None;
            }
            Some(out)
        }
        _ => None,
    }
}

/// Inflate at most `limit` uncompressed bytes of an entry (streaming prefix,
/// used for DEX headers without paying for the whole file).
fn read_entry_prefix(data: &[u8], entry: &ZipEntryMeta, limit: u64) -> Option<Vec<u8>> {
    if entry.comp_size == 0xFFFF_FFFF || entry.uncomp_size == 0xFFFF_FFFF {
        return None;
    }
    let data_off = local_data_offset(data, entry.local_offset)?;
    let comp_len = entry.comp_size as usize;
    let compressed = data.get(data_off..data_off.checked_add(comp_len)?)?;
    match entry.method {
        0 => Some(compressed[..compressed.len().min(limit as usize)].to_vec()),
        8 => {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            if comp_len == 0 {
                return None;
            }
            let mut out = Vec::with_capacity((limit as usize).min(1 << 20).max(512));
            let mut decoder = DeflateDecoder::new(compressed);
            decoder.by_ref().take(limit).read_to_end(&mut out).ok()?;
            if out.is_empty() {
                return None;
            }
            Some(out)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DEX / ELF / AXML parsers (content-derived counts, no hardcoded lists)
// ---------------------------------------------------------------------------

fn dex_counts(buf: &[u8]) -> Option<(u32, u32, u32)> {
    if buf.len() < 0x70 || &buf[0..4] != b"dex\n" {
        return None;
    }
    let string_ids = read_u32_le(buf, 0x38)?;
    let method_ids = read_u32_le(buf, 0x58)?;
    let class_defs = read_u32_le(buf, 0x60)?;
    if string_ids > 10_000_000 || method_ids > 10_000_000 || class_defs > 5_000_000 {
        return None;
    }
    Some((class_defs, string_ids, method_ids))
}

fn read_uleb128(buf: &[u8], mut off: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if off >= buf.len() {
            return None;
        }
        let b = buf[off];
        off += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    Some((result, off))
}

pub fn parse_dex_string_table(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 0x70 || &buf[0..4] != b"dex\n" {
        return None;
    }
    let string_ids_size = read_u32_le(buf, 0x38)? as usize;
    let string_ids_off = read_u32_le(buf, 0x3c)? as usize;
    if string_ids_size > 200_000 || string_ids_off >= buf.len() {
        return None;
    }

    let mut strings = Vec::with_capacity(string_ids_size.min(15_000));
    for i in 0..string_ids_size.min(15_000) {
        let entry_off = string_ids_off + i * 4;
        let Some(data_off) = read_u32_le(buf, entry_off).map(|v| v as usize) else {
            break;
        };
        let Some((_utf16_len, str_start)) = read_uleb128(buf, data_off) else {
            continue;
        };
        if str_start >= buf.len() {
            continue;
        }
        let max_read = (buf.len() - str_start).min(512);
        let slice = &buf[str_start..str_start + max_read];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        if end >= 4 {
            if let Ok(s) = std::str::from_utf8(&slice[..end]) {
                strings.push(s.to_string());
            } else {
                strings.push(String::from_utf8_lossy(&slice[..end]).into_owned());
            }
        } else {
            strings.push(String::new());
        }
    }
    Some(strings)
}

pub fn parse_dex_method_signatures(buf: &[u8], strings: &[String]) -> Vec<String> {
    let mut methods = Vec::new();
    let Some(type_ids_size) = read_u32_le(buf, 0x40).map(|v| v as usize) else { return methods };
    let Some(type_ids_off) = read_u32_le(buf, 0x44).map(|v| v as usize) else { return methods };
    let Some(method_ids_size) = read_u32_le(buf, 0x58).map(|v| v as usize) else { return methods };
    let Some(method_ids_off) = read_u32_le(buf, 0x5c).map(|v| v as usize) else { return methods };

    if method_ids_size > 200_000 || method_ids_off >= buf.len() || type_ids_off >= buf.len() {
        return methods;
    }

    let get_type = |idx: usize| -> Option<&str> {
        if idx >= type_ids_size { return None; }
        let desc_idx = read_u32_le(buf, type_ids_off + idx * 4)? as usize;
        strings.get(desc_idx).map(|s| s.as_str())
    };

    for i in 0..method_ids_size.min(15_000) {
        let off = method_ids_off + i * 8;
        let Some(class_idx) = read_u16_le(buf, off).map(|v| v as usize) else { break };
        let Some(name_idx) = read_u32_le(buf, off + 4).map(|v| v as usize) else { break };
        let Some(class_name) = get_type(class_idx) else { continue };
        let Some(method_name) = strings.get(name_idx).map(|s| s.as_str()) else { continue };
        if !class_name.is_empty() && !method_name.is_empty() {
            methods.push(format!("{}->{}", class_name, method_name));
        }
    }
    methods
}

pub fn parse_elf_strings_and_symbols(buf: &[u8], out: &mut Vec<String>) -> Option<(bool, bool, bool, bool, usize, usize, usize)> {
    if buf.len() < 0x34 || &buf[0..4] != b"\x7fELF" {
        return None;
    }
    let machine = read_u16_le(buf, 0x12).unwrap_or(0);
    let is_arm64 = machine == 183;
    let is_arm32 = machine == 40;
    let is_x86 = machine == 3;
    let is_x86_64 = machine == 62;

    let mut in_str = false;
    let mut start = 0;
    let mut exported_jni = 0usize;
    let mut imported = 0usize;
    let mut suspicious = 0usize;

    for (i, &b) in buf.iter().enumerate() {
        if (0x20..0x7f).contains(&b) {
            if !in_str {
                in_str = true;
                start = i;
            }
        } else {
            if in_str {
                in_str = false;
                let len = i - start;
                if len >= 4 && len <= 256 {
                    if let Ok(s) = std::str::from_utf8(&buf[start..i]) {
                        if s.starts_with("Java_") || s.contains("JNI_OnLoad") {
                            exported_jni += 1;
                        } else if s == "dlopen" || s == "dlsym" || s == "system" || s == "execve" || s == "ptrace" || s == "fork" || s == "socket" || s == "connect" {
                            imported += 1;
                            suspicious += 1;
                        }
                        if out.len() < 15_000 {
                            out.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    Some((is_arm64, is_arm32, is_x86, is_x86_64, exported_jni, imported, suspicious))
}

pub const PROTECTOR_SIGNATURES: &[(&str, &str)] = &[
    ("libprotectclass.so", "Qihoo 360"),
    ("libjiagu.so", "Qihoo 360"),
    ("libjiagu_a64.so", "Qihoo 360"),
    ("libjiagu_x86.so", "Qihoo 360"),
    ("libtx_shared.so", "Tencent Legu"),
    ("libshell.so", "Tencent Legu"),
    ("libshellx.so", "Tencent Legu"),
    ("libsecmain.so", "SecShell / Bangcle"),
    ("libsecexe.so", "SecShell / Bangcle"),
    ("secdata0.jar", "SecShell / Bangcle"),
    ("bangcle", "SecShell / Bangcle"),
    ("libexec.so", "Ijiami"),
    ("libexecmain.so", "Ijiami"),
    ("ijm_lib", "Ijiami"),
    ("libbaiduprotect.so", "Baidu Protect"),
    ("libbaiduprotect_art.so", "Baidu Protect"),
    ("libmobisec.so", "Alibaba / AliProtect"),
    ("libfake_jni.so", "Alibaba / AliProtect"),
    ("libdexhelper.so", "SecNeo"),
    ("libdexhelper-x86.so", "SecNeo"),
    ("libkdp.so", "Kingsoft"),
    ("libnsaferonly.so", "NSafer"),
    ("libnqshield.so", "NetQin"),
    ("libaps.so", "AppSolid"),
    ("apkprotect", "APKProtect"),
];

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const ATTR_MIN_SDK_VERSION: u32 = 0x0101_020c;
const ATTR_TARGET_SDK_VERSION: u32 = 0x0101_0270;

#[derive(Debug, Default, Clone)]
struct ManifestCounts {
    total_permissions: u32,
    activities: u32,
    services: u32,
    receivers: u32,
    min_sdk: u32,
    target_sdk: u32,
}

fn parse_axml_string_pool(b: &[u8], chunk_start: usize, chunk_size: usize) -> Option<Vec<String>> {
    let header_size = read_u16_le(b, chunk_start + 2)? as usize;
    let string_count = read_u32_le(b, chunk_start + 8)? as usize;
    if string_count > 100_000 {
        return None;
    }
    let flags = read_u32_le(b, chunk_start + 16)?;
    let strings_start = read_u32_le(b, chunk_start + 20)? as usize;
    let is_utf8 = flags & 0x100 != 0;
    let mut strings = Vec::with_capacity(string_count.min(4096));
    let offsets_off = chunk_start + header_size;
    for i in 0..string_count {
        let entry_off = offsets_off + i * 4;
        let rel = read_u32_le(b, entry_off)? as usize;
        let str_off = chunk_start + strings_start + rel;
        if str_off >= chunk_start + chunk_size || str_off >= b.len() {
            strings.push(String::new());
            continue;
        }
        let s = if is_utf8 {
            let len_off = {
                let mut q = str_off;
                let b0 = *b.get(q)?;
                q += 1;
                if b0 & 0x80 != 0 {
                    q += 1;
                }
                q
            };
            if len_off >= b.len() {
                strings.push(String::new());
                continue;
            }
            let (byte_len, start) = {
                let b0 = b[len_off];
                if b0 & 0x80 != 0 {
                    if len_off + 1 >= b.len() {
                        strings.push(String::new());
                        continue;
                    }
                    let bl = (((b0 as usize) & 0x7f) << 8) | b[len_off + 1] as usize;
                    (bl, len_off + 2)
                } else {
                    (b0 as usize, len_off + 1)
                }
            };
            if byte_len > 1_000_000 {
                strings.push(String::new());
                continue;
            }
            let start = start.min(b.len());
            let end = start.saturating_add(byte_len).min(b.len());
            String::from_utf8_lossy(b.get(start..end)?).into_owned()
        } else {
            let len = read_u16_le(b, str_off)? as usize;
            if len > 100_000 {
                strings.push(String::new());
                continue;
            }
            let start = str_off + 2;
            let mut units = Vec::with_capacity(len.min(512));
            for j in 0..len {
                units.push(read_u16_le(b, start + j * 2)?);
            }
            String::from_utf16_lossy(&units)
        };
        strings.push(s);
        if strings.len() >= 100_000 {
            break;
        }
    }
    Some(strings)
}

pub fn parse_axml_string_pool_from_bytes(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 8 {
        return None;
    }
    let mut off = 0usize;
    let mut chunks = 0usize;
    while off + 8 <= buf.len() && chunks < 50_000 {
        chunks += 1;
        let chunk_type = read_u16_le(buf, off)?;
        let header_size = read_u16_le(buf, off + 2)? as usize;
        let chunk_size = read_u32_le(buf, off + 4)? as usize;
        if chunk_size < header_size || header_size < 8 || chunk_size == 0 || off + chunk_size > buf.len() {
            break;
        }
        if chunk_type == RES_STRING_POOL_TYPE {
            return parse_axml_string_pool(buf, off, chunk_size);
        }
        if chunk_type == RES_XML_TYPE {
            if header_size == 0 || off + header_size > buf.len() {
                break;
            }
            off += header_size;
        } else {
            off += chunk_size;
        }
    }
    None
}

fn analyze_manifest(buf: &[u8]) -> Option<ManifestCounts> {
    if buf.len() < 8 {
        return None;
    }
    let mut pool: Vec<String> = Vec::new();
    let mut resource_map: Vec<u32> = Vec::new();
    let mut feats = ManifestCounts::default();
    let mut seen_any_element = false;

    let mut off = 0usize;
    let mut chunks = 0usize;
    while off + 8 <= buf.len() && chunks < 50_000 {
        chunks += 1;
        let chunk_type = read_u16_le(buf, off)?;
        let header_size = read_u16_le(buf, off + 2)? as usize;
        let chunk_size = read_u32_le(buf, off + 4)? as usize;
        if chunk_size < header_size || header_size < 8 || chunk_size == 0 {
            break;
        }
        if off + chunk_size > buf.len() {
            break;
        }
        match chunk_type {
            RES_STRING_POOL_TYPE => {
                if let Some(p) = parse_axml_string_pool(buf, off, chunk_size) {
                    pool = p;
                }
            }
            0x0180 => {
                let mut p = off + header_size;
                while p + 4 <= off + chunk_size && resource_map.len() < 10_000 {
                    resource_map.push(read_u32_le(buf, p)?);
                    p += 4;
                }
            }
            RES_XML_START_ELEMENT_TYPE => {
                seen_any_element = true;
                let node_off = off + 8;
                let ns_name_off = node_off + 8;
                let name_idx = read_i32_le(buf, ns_name_off + 4)?;
                let elem_name = if name_idx >= 0 {
                    pool.get(name_idx as usize).cloned().unwrap_or_default()
                } else {
                    String::new()
                };
                let attr_start_off = ns_name_off + 8;
                if attr_start_off + 8 > buf.len() {
                    break;
                }
                let attribute_start = read_u16_le(buf, attr_start_off)? as usize;
                let attribute_size = read_u16_le(buf, attr_start_off + 2)? as usize;
                let attribute_count = read_u16_le(buf, attr_start_off + 4)? as usize;
                if attribute_size == 0 || attribute_count > 256 {
                    if chunk_type == RES_XML_TYPE {
                        off += header_size;
                        continue;
                    } else {
                        off += chunk_size;
                        continue;
                    }
                }
                let attrs_base = ns_name_off + attribute_start;
                let is_uses_sdk = elem_name == "uses-sdk";
                match elem_name.as_str() {
                    "activity" | "activity-alias" => feats.activities += 1,
                    "service" => feats.services += 1,
                    "receiver" => feats.receivers += 1,
                    "uses-permission" | "uses-permission-sdk-23" | "permission" => {
                        feats.total_permissions += 1
                    }
                    _ => {}
                }
                if is_uses_sdk {
                    for i in 0..attribute_count {
                        let a_off = attrs_base + i * attribute_size;
                        if a_off + 20 > buf.len() {
                            break;
                        }
                        let attr_name_idx = read_i32_le(buf, a_off + 4)?;
                        let data = read_u32_le(buf, a_off + 16)?;
                        let attr_res_id = if attr_name_idx >= 0 {
                            resource_map.get(attr_name_idx as usize).copied().unwrap_or(0)
                        } else {
                            0
                        };
                        if attr_res_id == ATTR_MIN_SDK_VERSION {
                            feats.min_sdk = data;
                        } else if attr_res_id == ATTR_TARGET_SDK_VERSION {
                            feats.target_sdk = data;
                        }
                    }
                }
            }
            RES_XML_END_ELEMENT_TYPE => {}
            _ => {}
        }
        if chunk_type == RES_XML_TYPE {
            if header_size == 0 || off + header_size > buf.len() {
                break;
            }
            off += header_size;
        } else {
            off += chunk_size;
        }
    }
    if !seen_any_element {
        return None;
    }
    Some(feats)
}

fn shannon_entropy(hist: &[u64; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let mut e = 0.0f64;
    for &c in hist {
        if c > 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    e as f32
}

#[inline]
fn ln1p(x: f32) -> f32 {
    if x.is_nan() || x <= 0.0 {
        0.0
    } else {
        (x + 1.0).ln()
    }
}

// ---------------------------------------------------------------------------
// Single-pass APK profile: everything features + heuristics need, computed
// once with hard decompression caps (central-dir sizes are free and exact).
// ---------------------------------------------------------------------------

const DANGEROUS_PERMS: &[&str] = &[
    "android.permission.send_sms",
    "android.permission.read_sms",
    "android.permission.receive_sms",
    "android.permission.read_contacts",
    "android.permission.read_call_log",
    "android.permission.record_audio",
    "android.permission.camera",
    "android.permission.access_fine_location",
    "android.permission.receive_boot_completed",
    "android.permission.system_alert_window",
    "android.permission.request_install_packages",
    "android.permission.bind_device_admin",
];

#[derive(Debug, Default, Clone)]
struct ApkProfile {
    has_manifest: bool,
    dex_files: u32,
    so_files: u32,
    entry_count: u32,
    comp_total: u64,
    uncomp_total: u64,
    dex_classes: u64,
    dex_strings: u64,
    dex_methods: u64,
    dex_size: u64,
    so_size: u64,
    manifest_size: u64,
    perm_total: u32,
    activities: u32,
    services: u32,
    receivers: u32,
    min_sdk: u32,
    target_sdk: u32,
    entropy: f32,
    dangerous_perm_count: u32,
    sms_trio: bool,
}

/// Printable ASCII + UTF-16LE harvest of manifest bytes for permission grep.
/// Capped; never panics.
fn harvest_manifest_text(buf: &[u8]) -> String {
    let mut out = String::new();
    let mut run: Vec<u8> = Vec::new();
    let flush = |run: &mut Vec<u8>, out: &mut String| {
        if run.len() >= 4 && run.len() <= 256 {
            if let Ok(s) = std::str::from_utf8(run) {
                if !s.is_empty() {
                    out.push(' ');
                    out.push_str(s);
                }
            }
        }
        run.clear();
    };
    for &b in buf.iter().take(2 * 1024 * 1024) {
        if (0x20..0x7f).contains(&b) {
            run.push(b);
            if run.len() > 256 {
                flush(&mut run, &mut out);
            }
        } else {
            flush(&mut run, &mut out);
        }
        if out.len() > 256 * 1024 {
            break;
        }
    }
    flush(&mut run, &mut out);
    let mut u16run: Vec<u8> = Vec::new();
    let mut j = 0;
    while j + 1 < buf.len().min(2 * 1024 * 1024) {
        let (lo, hi) = (buf[j], buf[j + 1]);
        if hi == 0 && (0x20..0x7f).contains(&lo) {
            u16run.push(lo);
        } else if !u16run.is_empty() {
            flush(&mut u16run, &mut out);
        }
        j += 2;
        if out.len() > 256 * 1024 {
            break;
        }
    }
    flush(&mut u16run, &mut out);
    out
}

fn count_dangerous_perms(text_low: &str) -> (u32, bool) {
    let mut n = 0u32;
    for p in DANGEROUS_PERMS {
        if text_low.contains(p) {
            n += 1;
        }
    }
    let trio = text_low.contains("android.permission.send_sms")
        && text_low.contains("android.permission.read_sms")
        && text_low.contains("android.permission.receive_sms");
    (n, trio)
}

fn profile_apk(apk: &[u8]) -> Option<ApkProfile> {
    let entries = parse_central_dir(apk)?;
    let mut p = ApkProfile::default();
    p.entry_count = entries.len() as u32;

    // Pass 1: free metadata from the central directory (no decompression).
    let mut manifest_entry: Option<&ZipEntryMeta> = None;
    let mut dex_entries: Vec<&ZipEntryMeta> = Vec::new();
    for e in &entries {
        if e.comp_size == 0xFFFF_FFFF || e.uncomp_size == 0xFFFF_FFFF {
            continue;
        }
        p.comp_total += e.comp_size as u64;
        p.uncomp_total += e.uncomp_size as u64;
        let l = e.name.to_ascii_lowercase();
        if l == "androidmanifest.xml" {
            p.has_manifest = true;
            p.manifest_size = e.uncomp_size as u64;
            if manifest_entry.is_none() {
                manifest_entry = Some(e);
            }
        } else if l.ends_with(".dex") {
            p.dex_files += 1;
            p.dex_size += e.uncomp_size as u64;
            if dex_entries.len() < PROFILE_MAX_DEX {
                dex_entries.push(e);
            }
        } else if l.starts_with("lib/") && l.ends_with(".so") {
            p.so_files += 1;
            p.so_size += e.uncomp_size as u64;
        }
    }
    if !p.has_manifest && p.dex_files == 0 {
        return None;
    }

    // Pass 2: capped inflation — manifest (perm text + AXML counts) and DEX
    // header prefixes (class/string/method counts). Entropy accumulates over
    // exactly these bytes, so train and inference agree by construction.
    let mut hist = [0u64; 256];
    let mut hist_total: u64 = 0;
    let mut spent: usize = 0;
    let note_bytes = |buf: &[u8], hist: &mut [u64; 256], total: &mut u64| {
        for &b in buf {
            hist[b as usize] += 1;
        }
        *total += buf.len() as u64;
    };

    if let Some(me) = manifest_entry {
        if let Some(mut buf) = read_entry_data(apk, me) {
            buf.truncate(PROFILE_MANIFEST_CAP);
            if !buf.is_empty() {
                spent += buf.len();
                note_bytes(&buf, &mut hist, &mut hist_total);
                let text = harvest_manifest_text(&buf);
                let low = text.to_ascii_lowercase();
                let (dangerous, trio) = count_dangerous_perms(&low);
                p.dangerous_perm_count = dangerous;
                p.sms_trio = trio;
                if let Some(m) = analyze_manifest(&buf) {
                    p.perm_total = m.total_permissions;
                    p.activities = m.activities;
                    p.services = m.services;
                    p.receivers = m.receivers;
                    p.min_sdk = m.min_sdk;
                    p.target_sdk = m.target_sdk;
                }
            }
        }
    }

    for de in dex_entries {
        if spent >= PROFILE_TOTAL_CAP {
            break;
        }
        if let Some(prefix) = read_entry_prefix(apk, de, PROFILE_DEX_PREFIX) {
            spent += prefix.len();
            note_bytes(&prefix, &mut hist, &mut hist_total);
            // DEX header fields live in the first 0x70 bytes — but only trust
            // counts when we actually got a full header.
            if prefix.len() >= 0x70 {
                if let Some((classes, strings, methods)) = dex_counts(&prefix) {
                    p.dex_classes += classes as u64;
                    p.dex_strings += strings as u64;
                    p.dex_methods += methods as u64;
                }
            }
        }
    }

    // Native .so files are counted from names (ELF validation needs the full
    // file; the count signal is what the forest uses).
    p.entropy = shannon_entropy(&hist, hist_total);
    Some(p)
}

/// Our own tree-model feature vector (58 features).
/// Features 0..23 preserve exact parity with the original 24-feature forest;
/// features 24..57 provide native ELF, manifest high-risk permissions, Dalvik API calls,
/// protector signals, and pure XOR filter String ML metrics.
pub fn apk_tree_features(apk: &[u8]) -> Option<[f32; APK_TREE_FEATURE_COUNT]> {
    let p = profile_apk(apk)?;
    let ratio = if p.uncomp_total > 0 {
        (p.comp_total as f32 / p.uncomp_total as f32).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let avg_entry = if p.entry_count > 0 {
        p.uncomp_total as f32 / p.entry_count as f32
    } else {
        0.0
    };

    // Deep inspection via ripzip/hydradragonextractor:
    let mut has_arm64 = 0.0f32;
    let mut has_arm32 = 0.0f32;
    let mut has_x86 = 0.0f32;
    let mut has_x86_64 = 0.0f32;
    let mut so_exported_jni = 0usize;
    let mut so_imported = 0usize;
    let mut so_suspicious = 0usize;

    let mut perm_boot = 0.0f32;
    let mut perm_accessibility = 0.0f32;
    let mut perm_admin = 0.0f32;
    let mut perm_alert = 0.0f32;
    let mut perm_install = 0.0f32;
    let mut perm_phone_state = 0.0f32;
    let mut perm_storage = 0.0f32;

    let mut api_reflection = 0usize;
    let mut api_dynamic_loading = 0usize;
    let mut api_crypto = 0usize;
    let mut api_process = 0usize;
    let mut api_sms = 0usize;
    let mut api_device_id = 0usize;
    let mut api_network = 0usize;
    let mut api_pkg_manager = 0usize;
    let mut api_anti_debug = 0usize;

    let mut assets_count = 0usize;
    let mut assets_size = 0u64;
    let mut hidden_payload_assets = 0.0f32;
    let mut is_protector = 0.0f32;
    let mut has_non_standard_dex = 0.0f32;

    let mut all_strings = Vec::new();

    if let Ok(extracted) = hydradragonextractor::extract_archive_from_bytes(apk, true) {
        for e in &extracted {
            let l = e.name.to_ascii_lowercase();

            // Protector check
            for &(sig, _) in PROTECTOR_SIGNATURES {
                if l.contains(sig) {
                    is_protector = 1.0;
                    break;
                }
            }

            if l.starts_with("assets/") {
                assets_count += 1;
                assets_size += e.data.len() as u64;
                if l.ends_with(".dex") || l.ends_with(".jar") || l.ends_with(".so") || l.ends_with(".dat") || l.ends_with(".bin") {
                    hidden_payload_assets = 1.0;
                }
            }

            if l.ends_with(".dex") {
                let filename = l.rsplit('/').next().unwrap_or(&l);
                if filename != "classes.dex" && !filename.starts_with("classes") {
                    has_non_standard_dex = 1.0;
                }
                if let Some(strs) = parse_dex_string_table(&e.data) {
                    let methods = parse_dex_method_signatures(&e.data, &strs);
                    for m in &methods {
                        if m.contains("java/lang/reflect") { api_reflection += 1; }
                        if m.contains("DexClassLoader") || m.contains("PathClassLoader") { api_dynamic_loading += 1; }
                        if m.contains("Cipher") { api_crypto += 1; }
                        if m.contains("Runtime;->exec") || m.contains("ProcessBuilder") { api_process += 1; }
                        if m.contains("sendTextMessage") || m.contains("SmsManager") { api_sms += 1; }
                        if m.contains("getDeviceId") || m.contains("getSubscriberId") { api_device_id += 1; }
                        if m.contains("HttpURLConnection") || m.contains("HttpClient") || m.contains("okhttp") { api_network += 1; }
                        if m.contains("getInstalledPackages") || m.contains("getInstalledApplications") { api_pkg_manager += 1; }
                        if m.contains("su") || m.contains("isDebuggerConnected") { api_anti_debug += 1; }
                    }
                    all_strings.extend(methods);
                    all_strings.extend(strs);
                }
            } else if l.starts_with("lib/") && l.ends_with(".so") {
                if let Some((arm64, arm32, x86, x86_64, exp_jni, imp, susp)) = parse_elf_strings_and_symbols(&e.data, &mut all_strings) {
                    if arm64 { has_arm64 = 1.0; }
                    if arm32 { has_arm32 = 1.0; }
                    if x86 { has_x86 = 1.0; }
                    if x86_64 { has_x86_64 = 1.0; }
                    so_exported_jni += exp_jni;
                    so_imported += imp;
                    so_suspicious += susp;
                }
            } else if l == "androidmanifest.xml" || l.ends_with("/androidmanifest.xml") {
                let text = harvest_manifest_text(&e.data).to_ascii_lowercase();
                if text.contains("android.permission.receive_boot_completed") { perm_boot = 1.0; }
                if text.contains("android.permission.bind_accessibility_service") { perm_accessibility = 1.0; }
                if text.contains("android.permission.bind_device_admin") { perm_admin = 1.0; }
                if text.contains("android.permission.system_alert_window") { perm_alert = 1.0; }
                if text.contains("android.permission.request_install_packages") { perm_install = 1.0; }
                if text.contains("android.permission.read_phone_state") { perm_phone_state = 1.0; }
                if text.contains("android.permission.write_external_storage") { perm_storage = 1.0; }

                if let Some(pool) = parse_axml_string_pool_from_bytes(&e.data) {
                    all_strings.extend(pool);
                }
            }
        }
    }

    // String ML filter metrics:
    let (mal_hits, ben_hits, mal_ben_ratio, mal_density, unk_ratio, tot_log) = if !all_strings.is_empty() {
        let str_breakdown = crate::ml::pe_string_ml::classify_string_list(all_strings);
        let mal_f = str_breakdown.malicious.len() as f32;
        let ben_f = str_breakdown.benign.len() as f32;
        let tot_f = str_breakdown.total_unique as f32;
        let unk_f = str_breakdown.unknown.len() as f32;
        (
            ln1p(mal_f),
            ln1p(ben_f),
            mal_f / (ben_f + 1.0),
            mal_f / (tot_f + 1.0),
            unk_f / (tot_f + 1.0),
            ln1p(tot_f),
        )
    } else {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    };

    Some([
        // 0..23 (Frozen original features)
        p.dex_classes as f32,
        p.dex_strings as f32,
        p.dex_methods as f32,
        p.dex_files as f32,
        p.so_files as f32,
        p.perm_total as f32,
        p.activities as f32,
        p.services as f32,
        p.receivers as f32,
        p.min_sdk as f32,
        p.target_sdk as f32,
        p.entropy,
        p.entry_count as f32,
        ln1p(apk.len() as f32),
        ln1p(p.manifest_size as f32),
        ln1p(p.dex_size as f32),
        ln1p(p.so_size as f32),
        p.dangerous_perm_count as f32,
        p.sms_trio as u8 as f32,
        p.has_manifest as u8 as f32,
        (p.dex_files >= 2) as u8 as f32,
        ratio,
        ln1p(avg_entry),
        (p.so_files >= 1 && p.dangerous_perm_count >= 5) as u8 as f32,

        // 24..30: Native .so detailed architecture & symbols
        has_arm64,
        has_arm32,
        has_x86,
        has_x86_64,
        ln1p(so_exported_jni as f32),
        ln1p(so_imported as f32),
        ln1p(so_suspicious as f32),

        // 31..37: Manifest high-risk capability flags
        perm_boot,
        perm_accessibility,
        perm_admin,
        perm_alert,
        perm_install,
        perm_phone_state,
        perm_storage,

        // 38..46: Dalvik sensitive API invocation signals
        ln1p(api_reflection as f32),
        ln1p(api_dynamic_loading as f32),
        ln1p(api_crypto as f32),
        ln1p(api_process as f32),
        ln1p(api_sms as f32),
        ln1p(api_device_id as f32),
        ln1p(api_network as f32),
        ln1p(api_pkg_manager as f32),
        ln1p(api_anti_debug as f32),

        // 47..51: Packaging, assets, protector anomalies
        ln1p(assets_count as f32),
        ln1p(assets_size as f32),
        hidden_payload_assets,
        is_protector,
        has_non_standard_dex,

        // 52..57: String ML & Threat density metrics
        mal_hits,
        ben_hits,
        mal_ben_ratio,
        mal_density,
        unk_ratio,
        tot_log,
    ])
}

/// Returns the full string breakdown (malicious, benign, unknown) of the APK:
/// Extracts:
/// 1. AndroidManifest.xml string pool and permissions
/// 2. Dalvik `classes*.dex` string pool + all Class->Method API calls
/// 3. Native `lib/**/*.so` symbols, JNI exports, imports and string tables
/// Powered by `hydradragonextractor` / `ripzip` for maximum decompression speed.
pub fn apk_deobfuscated_string_breakdown(apk_data: &[u8]) -> Option<crate::ml::pe_string_ml::PeStringBreakdown> {
    let extracted: Vec<(String, Vec<u8>)> = if let Ok(ext) = hydradragonextractor::extract_archive_from_bytes(apk_data, true) {
        if ext.is_empty() {
            if let Some(entries) = parse_central_dir(apk_data) {
                let mut list = Vec::new();
                for e in entries {
                    let l = e.name.to_ascii_lowercase();
                    if l == "androidmanifest.xml" || l.ends_with("/androidmanifest.xml") || l.ends_with(".dex") || (l.starts_with("lib/") && l.ends_with(".so")) {
                        if let Some(bytes) = read_entry_data(apk_data, &e) {
                            list.push((e.name, bytes));
                        }
                    }
                }
                list
            } else {
                return None;
            }
        } else {
            ext.into_iter().map(|e| (e.name, e.data)).collect()
        }
    } else if let Some(entries) = parse_central_dir(apk_data) {
        let mut list = Vec::new();
        for e in entries {
            let l = e.name.to_ascii_lowercase();
            if l == "androidmanifest.xml" || l.ends_with("/androidmanifest.xml") || l.ends_with(".dex") || (l.starts_with("lib/") && l.ends_with(".so")) {
                if let Some(bytes) = read_entry_data(apk_data, &e) {
                    list.push((e.name, bytes));
                }
            }
        }
        list
    } else {
        return None;
    };

    let mut candidates = Vec::new();
    let mut method_count = 0usize;
    let mut protector_found = false;

    // Check protector signatures across extracted file names
    for (name, _) in &extracted {
        let l = name.to_ascii_lowercase();
        for &(sig, _) in PROTECTOR_SIGNATURES {
            if l.contains(sig) {
                protector_found = true;
                break;
            }
        }
    }

    for (name, data) in &extracted {
        let l = name.to_ascii_lowercase();
        if l == "androidmanifest.xml" || l.ends_with("/androidmanifest.xml") {
            if let Some(pool) = parse_axml_string_pool_from_bytes(data) {
                candidates.extend(pool);
            } else {
                let text = harvest_manifest_text(data);
                for word in text.split_whitespace() {
                    let w = word.trim();
                    if w.len() >= 4 {
                        candidates.push(w.to_string());
                    }
                }
            }
        } else if l.ends_with(".dex") {
            if let Some(strings) = parse_dex_string_table(data) {
                let methods = parse_dex_method_signatures(data, &strings);
                method_count += methods.len();
                candidates.extend(methods);
                candidates.extend(strings);
            } else {
                let mut in_str = false;
                let mut start = 0;
                for (i, &b) in data.iter().enumerate() {
                    if (0x20..0x7f).contains(&b) {
                        if !in_str { in_str = true; start = i; }
                    } else if in_str {
                        in_str = false;
                        if i - start >= 4 && i - start <= 256 {
                            if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                                candidates.push(s.to_string());
                            }
                        }
                    }
                }
            }
        } else if l.starts_with("lib/") && l.ends_with(".so") {
            parse_elf_strings_and_symbols(data, &mut candidates);
        }
    }

    if candidates.is_empty() {
        return None;
    }

    let mut b = crate::ml::pe_string_ml::classify_string_list(candidates);
    b.decompiler_strings = method_count;
    b.unicorn_trace_strings = if protector_found { 1 } else { 0 };
    Some(b)
}

// ---------------------------------------------------------------------------
// Detection helpers used by the engine
// ---------------------------------------------------------------------------

/// True for APKs: `.apk` extension, or a ZIP whose central directory holds
/// `AndroidManifest.xml` at its root together with code (`*.dex` or `lib/*.so`).
/// The manifest is what makes an APK: a JAR built with the Android SDK carries
/// `classes.dex` (dexed library), and JARs with native code carry `lib/*.so`, but
/// neither has a root `AndroidManifest.xml` (JARs have `META-INF/MANIFEST.MF`).
pub fn is_apk(data: &[u8], name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".apk") {
        return true;
    }
    if data.len() < 4 || &data[0..2] != b"PK" {
        return false;
    }
    let Some(entries) = parse_central_dir(data) else {
        return false;
    };
    let (mut manifest, mut code) = (false, false);
    for e in &entries {
        let l = e.name.to_ascii_lowercase();
        manifest |= l == "androidmanifest.xml";
        code |= l.ends_with(".dex") || (l.starts_with("lib/") && l.ends_with(".so"));
    }
    manifest && code
}

#[derive(Debug, Clone)]
pub struct HeuristicHit {
    pub name: String,
    pub score: f32,
    pub details: String,
}

/// Heuristic APK signals. Runs with no model files loaded, so APK malware is
/// found even before training. All parsing is capped; never panics.
pub fn apk_heuristics(data: &[u8], name: &str) -> Vec<HeuristicHit> {
    if !is_apk(data, name) {
        return Vec::new();
    }
    let Some(entries) = parse_central_dir(data) else {
        return vec![HeuristicHit {
            name: "APK.InvalidStructure".to_string(),
            score: 0.55,
            details: "APK extension but unreadable ZIP central directory".to_string(),
        }];
    };
    let mut has_manifest = false;
    let mut dex_count = 0u32;
    for e in &entries {
        let l = e.name.to_ascii_lowercase();
        if l == "androidmanifest.xml" {
            has_manifest = true;
        } else if l.ends_with(".dex") {
            dex_count += 1;
        }
    }
    if !has_manifest && dex_count == 0 {
        return vec![HeuristicHit {
            name: "APK.NoManifestNoDex".to_string(),
            score: 0.55,
            details: "ZIP named .apk without AndroidManifest.xml or classes.dex".to_string(),
        }];
    }
    let Some(p) = profile_apk(data) else {
        return vec![HeuristicHit {
            name: "APK.InvalidStructure".to_string(),
            score: 0.55,
            details: "APK entries present but content unreadable".to_string(),
        }];
    };
    let mut hits = Vec::new();
    if p.sms_trio {
        hits.push(HeuristicHit {
            name: "APK.SmsTrio".to_string(),
            score: 0.78,
            details: "Manifest requests SEND+READ+RECEIVE_SMS (premium-SMS trojan pattern)"
                .to_string(),
        });
    } else if p.dangerous_perm_count >= 4 {
        hits.push(HeuristicHit {
            name: "APK.SuspiciousPermissionCombo".to_string(),
            score: 0.65,
            details: format!(
                "Manifest holds {} dangerous permissions",
                p.dangerous_perm_count
            ),
        });
    }
    if p.entropy >= 7.6 && (p.dex_size + p.manifest_size) >= 256 * 1024 {
        hits.push(HeuristicHit {
            name: "APK.PackedHighEntropy".to_string(),
            score: 0.60,
            details: format!("Code-section entropy {:.2} bits (packed/obfuscated)", p.entropy),
        });
    }
    if p.dex_methods >= 20_000 && p.dangerous_perm_count >= 5 {
        hits.push(HeuristicHit {
            name: "APK.LargeDexApiSurface".to_string(),
            score: 0.60,
            details: format!(
                "{} DEX methods with {} dangerous permissions",
                p.dex_methods, p.dangerous_perm_count
            ),
        });
    } else if p.dex_classes >= 8_000 && p.dangerous_perm_count >= 5 {
        hits.push(HeuristicHit {
            name: "APK.LargeDexApiSurface".to_string(),
            score: 0.58,
            details: format!(
                "{} DEX classes with {} dangerous permissions",
                p.dex_classes, p.dangerous_perm_count
            ),
        });
    }
    if p.so_files >= 1 && p.dangerous_perm_count >= 5 {
        hits.push(HeuristicHit {
            name: "APK.NativeCodeWithSensitivePerms".to_string(),
            score: 0.55,
            details: format!(
                "{} native .so with {} dangerous permissions",
                p.so_files, p.dangerous_perm_count
            ),
        });
    }
    if p.dex_files >= 5 {
        hits.push(HeuristicHit {
            name: "APK.MultidexHeavy".to_string(),
            score: 0.52,
            details: format!("{} classes*.dex files (multidex)", p.dex_files),
        });
    }
    if hits.len() > 6 {
        hits.truncate(6);
    }
    hits
}

/// Capped string buffer for HydraSig over APKs: manifest + dex bytes only,
/// so a 60 MB APK with hundreds of assets cannot OOM the tab.
pub fn apk_strings_capped(data: &[u8]) -> Vec<String> {
    let mut buf: Vec<u8> = Vec::new();
    if let Some(entries) = parse_central_dir(data) {
        for entry in &entries {
            if buf.len() >= 2 * 1024 * 1024 {
                break;
            }
            let l = entry.name.to_ascii_lowercase();
            if l == "androidmanifest.xml" || l.ends_with(".dex") {
                if let Some(b) = read_entry_data(data, entry) {
                    let take = (2 * 1024 * 1024 - buf.len()).min(b.len());
                    buf.extend_from_slice(&b[..take]);
                }
            }
        }
        for entry in entries.iter().take(512) {
            if buf.len() >= 2 * 1024 * 1024 {
                break;
            }
            buf.extend_from_slice(entry.name.as_bytes());
            buf.push(b'\n');
        }
    }
    if buf.is_empty() {
        buf.extend_from_slice(&data[..data.len().min(512 * 1024)]);
    }
    super::pe_strings::extract_strings(&buf)
        .into_iter()
        .take(20_000)
        .collect()
}

/// YARA input for APKs: decompressed manifest+dex (≤ 8 MB) instead of the
/// whole archive, so large APKs scan fast without OOM. Returns `None` only
/// when nothing parseable exists (caller falls back to a capped raw slice).
pub fn yara_input(data: &[u8]) -> Option<Vec<u8>> {
    let entries = parse_central_dir(data)?;
    let mut out = Vec::new();
    for entry in &entries {
        if out.len() >= 8 * 1024 * 1024 {
            break;
        }
        let l = entry.name.to_ascii_lowercase();
        if l == "androidmanifest.xml" || l.ends_with(".dex") {
            if let Some(b) = read_entry_data(data, entry) {
                let take = (8 * 1024 * 1024 - out.len()).min(b.len());
                out.extend_from_slice(&b[..take]);
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Feature names already seen during training (for trainer diagnostics).
#[allow(dead_code)]
pub fn seen_feature_names(seen: &HashSet<usize>) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = seen
        .iter()
        .filter_map(|&i| APK_TREE_FEATURE_NAMES.get(i).copied())
        .collect();
    out.sort_unstable();
    out
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 != 0 { 0xEDB8_8320 } else { 0 };
            }
        }
        !crc
    }

    /// Minimal STORED-only ZIP writer for tests (shared with engine tests).
    pub(crate) fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let local_off = out.len() as u32;
            let crc = crc32_ieee(data);
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&local_off.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    pub(crate) fn sms_trio_apk() -> Vec<u8> {
        let manifest =
            b"android.permission.SEND_SMS android.permission.READ_SMS android.permission.RECEIVE_SMS"
                .to_vec();
        let mut dex = vec![0u8; 0x70];
        dex[0..4].copy_from_slice(b"dex\n");
        dex[0x38..0x3c].copy_from_slice(&10u32.to_le_bytes());
        dex[0x58..0x5c].copy_from_slice(&50u32.to_le_bytes());
        dex[0x60..0x64].copy_from_slice(&5u32.to_le_bytes());
        stored_zip(&[("AndroidManifest.xml", &manifest), ("classes.dex", &dex)])
    }

    #[test]
    fn detects_apk_by_name_and_content() {
        let zip = stored_zip(&[("AndroidManifest.xml", b"hello"), ("classes.dex", b"dex\n")]);
        assert!(is_apk(&zip, "sample.bin"));
        assert!(is_apk(b"PK junk", "app.apk"));
        assert!(!is_apk(b"MZ fake pe", "app.exe"));
        assert!(!is_apk(b"hello world", "notes.txt"));
    }

    #[test]
    fn jars_with_dex_or_native_code_are_not_apks() {
        // Library JAR dexed by the Android SDK (d8): classes.dex, a JAR manifest.
        let dexed = stored_zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"), ("classes.dex", b"dex\n")]);
        assert!(!is_apk(&dexed, "library.jar"));
        // JAR shipping a JNI library.
        let jni = stored_zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"), ("lib/x86_64/libfoo.so", b"\x7fELF")]);
        assert!(!is_apk(&jni, "native.jar"));
        // An APK renamed to .jar is still an APK (manifest + code).
        let apk = stored_zip(&[("AndroidManifest.xml", b"hello"), ("classes.dex", b"dex\n")]);
        assert!(is_apk(&apk, "renamed.jar"));
    }

    #[test]
    fn heuristics_flag_sms_trio() {
        let zip = sms_trio_apk();
        let hits = apk_heuristics(&zip, "evil.apk");
        assert!(hits.iter().any(|h| h.name == "APK.SmsTrio"));
    }

    #[test]
    fn fallback_parses_eocd_destroyed_archive() {
        // Malware with appended overlay: EOCD gone, central directory intact.
        let mut zip = stored_zip(&[
            ("AndroidManifest.xml", b"android.permission.SEND_SMS"),
            ("classes.dex", b"dex\n"),
        ]);
        let eocd = zip
            .windows(4)
            .position(|w| w == b"PK\x05\x06")
            .expect("test zip has an EOCD");
        zip.truncate(eocd); // destroy the EOCD entirely
        let entries = parse_central_dir(&zip).expect("fallback must find the CD run");
        assert_eq!(entries.len(), 2);
        assert!(is_apk(&zip, "evil.apk"));
        let f = apk_tree_features(&zip).expect("features from fallback entries");
        assert_eq!(f.len(), APK_TREE_FEATURE_COUNT);
    }

    #[test]
    fn tree_features_have_frozen_width_and_values() {
        let zip = sms_trio_apk();
        let f = apk_tree_features(&zip).expect("features extract");
        assert_eq!(f.len(), APK_TREE_FEATURE_COUNT);
        assert!(f.iter().all(|x| x.is_finite()));
        // dex header: 5 classes, 10 strings, 50 methods; sms trio flag set.
        assert_eq!(f[0], 5.0);
        assert_eq!(f[1], 10.0);
        assert_eq!(f[2], 50.0);
        assert_eq!(f[3], 1.0);
        assert_eq!(f[18], 1.0);
        assert_eq!(f[19], 1.0);
        // garbage is not an APK profile.
        assert!(apk_tree_features(b"definitely not a zip").is_none());
    }

    #[test]
    fn test_apk_string_breakdown() {
        let zip = sms_trio_apk();
        let b = apk_deobfuscated_string_breakdown(&zip);
        assert!(b.is_some());
        let b = b.unwrap();
        assert!(b.total_unique > 0);
    }
}
