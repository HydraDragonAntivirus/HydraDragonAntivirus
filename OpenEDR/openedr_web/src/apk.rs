//! APK support for the web edition: ZIP/APK detection, DEX/ELF/manifest
//! parsing, tokenizer, percentile normalization and an ONNX-equivalent MLP.
//!
//! This mirrors `hydradragonml` (HydraDragonAV-Mobile) without the Burn
//! dependency, which cannot target `wasm32-unknown-unknown` at a reasonable
//! binary size. The network math here is exactly the graph emitted by
//! `tools/export_apk_onnx.py`:
//!
//! ```text
//! tokens[int64 N] -> Gather(embedding VOCABx64) -> ReduceMean(axis=0) [64]
//!   -> Gemm(fc_text 64->32) -> Relu -> [32] (text branch)
//! engine[float 11] -> Gemm(fc_engine 11->32) -> Relu -> [32] (engine branch)
//! concat([text, engine]) [64] -> Gemm(fc_fused 64->32) -> Relu
//!   -> Gemm(fc_out 32->1) -> Sigmoid -> malware_prob
//! ```
//!
//! Web weights (`apk_weights.bin`, loaded via `web_load_apk_weights`) and the
//! exported `apk_model.onnx` carry the same float values, so a score produced
//! here matches the ONNX graph on the same inputs. Until a trained model is
//! shipped the engine still flags APK malware through `apk_heuristics` plus
//! YARA/HydraSig on capped APK strings — ML is an additional signal, never a
//! hard requirement, so unscored APKs return `Unknown`, never `Error`.

use std::collections::HashMap;

pub const VOCAB_SIZE: usize = 20000;
pub const EMBED_DIM: usize = 64;
pub const ENGINE_FEATURE_COUNT: usize = 11;
pub const TEXT_HIDDEN: usize = 32;
pub const ENGINE_HIDDEN: usize = 32;
pub const FUSED_HIDDEN: usize = 32;

/// Mobile parity thresholds: >= 0.95 malicious, >= 0.90 suspicious.
pub const APK_MALICIOUS_THRESHOLD: f32 = 0.95;
pub const APK_SUSPICIOUS_THRESHOLD: f32 = 0.90;

/// Per-entry / total decompression caps so a hostile 200 MB APK cannot OOM
/// the browser tab. Entries beyond the caps are skipped (counts still come
/// from headers/central directory, which need no decompression).
pub const MAX_ENTRY_SCAN: usize = 8 * 1024 * 1024;
pub const MAX_TOTAL_SCAN: usize = 32 * 1024 * 1024;
/// Tokenizer output cap (mobile uses 8192).
pub const MAX_TOKENS: usize = 8192;
/// Central-directory walk cap.
const MAX_ENTRIES: usize = 8192;

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
fn parse_central_dir(data: &[u8]) -> Option<Vec<ZipEntryMeta>> {
    if data.len() < 22 || data[0] != b'P' || data[1] != b'K' {
        return None;
    }
    // EOCD is within the last 64KB + 22 bytes.
    let search_start = data.len().saturating_sub(64 * 1024 + 22);
    let mut eocd_off: Option<usize> = None;
    // Search backwards for PK\x05\x06.
    let mut i = data.len().saturating_sub(22);
    loop {
        if i < search_start {
            break;
        }
        if data[i] == 0x50 && data[i + 1] == 0x4b && data[i + 2] == 0x05 && data[i + 3] == 0x06 {
            eocd_off = Some(i);
            break;
        }
        if i == 0 || i == search_start {
            break;
        }
        i -= 1;
    }
    let eocd = eocd_off?;
    let total_entries = read_u16_le(data, eocd + 10)? as usize;
    let cd_offset = read_u32_le(data, eocd + 16)? as usize;
    if total_entries == 0 || total_entries > MAX_ENTRIES {
        if total_entries > MAX_ENTRIES {
            return None;
        }
        if total_entries == 0 {
            return None;
        }
    }
    if cd_offset >= data.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(total_entries.min(1024));
    let mut off = cd_offset;
    for _ in 0..total_entries.min(MAX_ENTRIES) {
        if off + 46 > data.len() {
            break;
        }
        if read_u32_le(data, off)? != 0x0201_4b50 {
            break;
        }
        let method = read_u16_le(data, off + 10)?;
        let comp_size = read_u32_le(data, off + 20)?;
        let uncomp_size = read_u32_le(data, off + 24)?;
        let fname_len = read_u16_le(data, off + 28)? as usize;
        let extra_len = read_u16_le(data, off + 30)? as usize;
        let comment_len = read_u16_le(data, off + 32)? as usize;
        let local_offset = read_u32_le(data, off + 42)?;
        let name_off = off + 46;
        let name_end = name_off.checked_add(fname_len)?;
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
        off = name_end.checked_add(extra_len)?.checked_add(comment_len)?;
        if off >= data.len() {
            break;
        }
    }
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
    // Encrypted entries (bit 0 of central-dir flags is not parsed here, but
    // absurd sizes are a cheap proxy) and ZIP64 placeholders are skipped.
    if entry.comp_size == 0xFFFF_FFFF || entry.uncomp_size == 0xFFFF_FFFF {
        return None;
    }
    let data_off = local_data_offset(data, entry.local_offset)?;
    let comp_len = entry.comp_size as usize;
    // Clamp to what is actually there; a truncated APK yields None.
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

// ---------------------------------------------------------------------------
// DEX / ELF / AXML parsers (ported from hydradragonml, no behavior change)
// ---------------------------------------------------------------------------

fn dex_counts(buf: &[u8]) -> Option<(u32, u32, u32)> {
    if buf.len() < 0x70 || &buf[0..4] != b"dex\n" {
        return None;
    }
    let string_ids = read_u32_le(buf, 0x38)?;
    let method_ids = read_u32_le(buf, 0x58)?;
    let class_defs = read_u32_le(buf, 0x60)?;
    // Sanity: reject absurd headers from a non-DEX blob with coincidental magic.
    if string_ids > 10_000_000 || method_ids > 10_000_000 || class_defs > 5_000_000 {
        return None;
    }
    Some((class_defs, string_ids, method_ids))
}

fn is_valid_elf(buf: &[u8]) -> bool {
    if buf.len() < 20 || &buf[0..4] != b"\x7fELF" {
        return false;
    }
    let class = buf[4];
    class == 1 || class == 2
}

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
            let mut p = str_off;
            // Skip UTF-16 length then UTF-8 length (1-2 bytes each when <32k).
            for _ in 0..2 {
                if p >= b.len() {
                    break;
                }
                let b0 = b[p];
                p += 1;
                if b0 & 0x80 != 0 {
                    p += 1;
                }
            }
            // Re-derive byte length from the second length prefix.
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
            let (byte_len, mut start) = {
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
            let _ = p;
            if byte_len > 1_000_000 {
                strings.push(String::new());
                continue;
            }
            let end = start.saturating_add(byte_len).min(b.len());
            start = start.min(b.len());
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
                            resource_map
                                .get(attr_name_idx as usize)
                                .copied()
                                .unwrap_or(0)
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

// ---------------------------------------------------------------------------
// Engine features + percentile normalization (mobile parity)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct EngineFeatures {
    pub dex_class_count: f32,
    pub dex_string_count: f32,
    pub dex_api_call_count: f32,
    pub elf_count: f32,
    pub manifest_total_permissions: f32,
    pub manifest_activities: f32,
    pub manifest_services: f32,
    pub manifest_receivers: f32,
    pub manifest_min_sdk: f32,
    pub manifest_target_sdk: f32,
    pub entropy: f32,
}

impl EngineFeatures {
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.dex_class_count,
            self.dex_string_count,
            self.dex_api_call_count,
            self.elf_count,
            self.manifest_total_permissions,
            self.manifest_activities,
            self.manifest_services,
            self.manifest_receivers,
            self.manifest_min_sdk,
            self.manifest_target_sdk,
            self.entropy,
        ]
    }

    pub fn extract_from_apk(apk: &[u8]) -> Option<Self> {
        let entries = parse_central_dir(apk)?;
        let mut feats = EngineFeatures::default();
        let mut saw_any = false;
        let mut hist = [0u64; 256];
        let mut total: u64 = 0;
        let mut spent: usize = 0;
        for entry in &entries {
            let lname = entry.name.to_ascii_lowercase();
            let is_dex = lname.ends_with(".dex");
            let is_manifest = lname == "androidmanifest.xml";
            let is_native = lname.starts_with("lib/") && lname.ends_with(".so");
            if !is_dex && !is_manifest && !is_native {
                continue;
            }
            if spent >= MAX_TOTAL_SCAN {
                break;
            }
            let buf = match read_entry_data(apk, entry) {
                Some(b) => b,
                None => continue,
            };
            spent += buf.len();
            for &b in &buf {
                hist[b as usize] += 1;
            }
            total += buf.len() as u64;
            if is_dex {
                if let Some((classes, strings, methods)) = dex_counts(&buf) {
                    saw_any = true;
                    feats.dex_class_count += classes as f32;
                    feats.dex_string_count += strings as f32;
                    feats.dex_api_call_count += methods as f32;
                }
            } else if is_manifest {
                if let Some(m) = analyze_manifest(&buf) {
                    saw_any = true;
                    feats.manifest_total_permissions = m.total_permissions as f32;
                    feats.manifest_activities = m.activities as f32;
                    feats.manifest_services = m.services as f32;
                    feats.manifest_receivers = m.receivers as f32;
                    feats.manifest_min_sdk = m.min_sdk as f32;
                    feats.manifest_target_sdk = m.target_sdk as f32;
                }
            } else if is_native && is_valid_elf(&buf) {
                saw_any = true;
                feats.elf_count += 1.0;
            }
        }
        if !saw_any {
            return None;
        }
        feats.entropy = shannon_entropy(&hist, total);
        Some(feats)
    }
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

#[derive(Clone, Debug, Default)]
pub struct FeaturePercentiles {
    pub per_feature: Vec<Vec<f32>>,
}

impl FeaturePercentiles {
    pub fn from_json_bytes(bytes: &[u8]) -> Option<Self> {
        let per_feature: Vec<Vec<f32>> = serde_json::from_slice(bytes).ok()?;
        if per_feature.len() != ENGINE_FEATURE_COUNT {
            return None;
        }
        for col in &per_feature {
            if col.is_empty() || col.len() > 5_000_000 {
                return None;
            }
        }
        Some(Self { per_feature })
    }

    pub fn normalize(&self, raw: &[f32]) -> Vec<f32> {
        raw.iter()
            .zip(self.per_feature.iter())
            .map(|(x, sorted)| percentile_value(sorted, *x))
            .collect()
    }
}

fn percentile_value(sorted: &[f32], x: f32) -> f32 {
    let n = sorted.len();
    if n == 0 || !x.is_finite() {
        return 0.0;
    }
    if x <= sorted[0] {
        return 0.0;
    }
    if x >= sorted[n - 1] {
        return 1.0;
    }
    let mut lo = 0usize;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if sorted[mid] <= x {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let i = lo.clamp(1, n - 1);
    let a = sorted[i - 1];
    let b = sorted[i];
    let t = if b > a { (x - a) / (b - a) } else { 0.0 };
    (((i - 1) as f32) + t.clamp(0.0, 1.0)) / ((n - 1) as f32)
}

// ---------------------------------------------------------------------------
// Tokenizer (mobile parity, capped)
// ---------------------------------------------------------------------------

const MIN_STR_LEN: usize = 5;

pub struct Tokenizer {
    vocab: HashMap<String, u32>,
}

impl Tokenizer {
    pub fn load_json(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 32 * 1024 * 1024 {
            return None;
        }
        let map: HashMap<String, i64> = serde_json::from_slice(bytes).ok()?;
        if map.is_empty() || map.len() > VOCAB_SIZE + 1024 {
            return None;
        }
        let mut vocab = HashMap::with_capacity(map.len());
        for (k, v) in map {
            if v >= 0 && (v as usize) < VOCAB_SIZE && k.len() <= 256 {
                vocab.insert(k, v as u32);
            }
        }
        if !vocab.contains_key("<UNK>") && !vocab.values().any(|&v| v == 0) {
            // Lenient: UNK id 0 is implied for unknown tokens anyway.
        }
        Some(Self { vocab })
    }

    pub fn tokenize(&self, apk: &[u8]) -> Option<Vec<u32>> {
        let entries = parse_central_dir(apk)?;
        let mut tokens: Vec<u32> = Vec::new();
        let mut has_content = false;
        let mut spent: usize = 0;
        for entry in &entries {
            if tokens.len() >= MAX_TOKENS {
                break;
            }
            let lname = entry.name.to_ascii_lowercase();
            // Entry names are always cheap; content only for the harvest set.
            self.sub_tokenize(&entry.name, &mut tokens);
            let want_content = lname == "androidmanifest.xml"
                || lname == "resources.arsc"
                || lname.ends_with(".dex")
                || lname.starts_with("meta-inf/");
            if want_content && spent < MAX_TOTAL_SCAN {
                if let Some(buf) = read_entry_data(apk, entry) {
                    if !buf.is_empty() {
                        has_content = true;
                        spent += buf.len();
                        self.harvest_strings(&buf, &mut tokens);
                    }
                }
            }
        }
        if !has_content || tokens.is_empty() {
            return None;
        }
        Some(tokens)
    }

    fn sub_tokenize(&self, text: &str, out: &mut Vec<u32>) {
        for part in text.split(['.', '/', ';', ':', '-', '\\', '_']) {
            if part.len() >= 2 && part.len() <= 256 {
                let key = part.to_ascii_lowercase();
                out.push(self.vocab.get(&key).copied().unwrap_or(0));
                if out.len() >= MAX_TOKENS {
                    return;
                }
            }
        }
    }

    fn harvest_strings(&self, data: &[u8], out: &mut Vec<u32>) {
        let mut start: Option<usize> = None;
        for (i, &b) in data.iter().enumerate() {
            let printable = (0x20..0x7f).contains(&b);
            if printable {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                if i - s >= MIN_STR_LEN && i - s <= 4096 {
                    if let Ok(text) = std::str::from_utf8(&data[s..i]) {
                        self.sub_tokenize(text, out);
                        if out.len() >= MAX_TOKENS {
                            return;
                        }
                    }
                }
            }
            if out.len() >= MAX_TOKENS {
                return;
            }
        }
        if let Some(s) = start {
            if data.len() - s >= MIN_STR_LEN && data.len() - s <= 4096 {
                if let Ok(text) = std::str::from_utf8(&data[s..]) {
                    self.sub_tokenize(text, out);
                }
            }
        }
        // UTF-16LE runs.
        let mut utf_buf: Vec<u8> = Vec::new();
        let mut j = 0;
        while j + 1 < data.len() && out.len() < MAX_TOKENS {
            let lo = data[j];
            let hi = data[j + 1];
            if hi == 0 && (0x20..0x7f).contains(&lo) {
                utf_buf.push(lo);
                if utf_buf.len() > 4096 {
                    utf_buf.clear();
                }
            } else if !utf_buf.is_empty() {
                if utf_buf.len() >= MIN_STR_LEN {
                    if let Ok(text) = std::str::from_utf8(&utf_buf) {
                        self.sub_tokenize(text, out);
                    }
                }
                utf_buf.clear();
            }
            j += 2;
        }
        if utf_buf.len() >= MIN_STR_LEN && out.len() < MAX_TOKENS {
            if let Ok(text) = std::str::from_utf8(&utf_buf) {
                self.sub_tokenize(text, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ONNX-equivalent MLP weights + forward pass (no Burn, wasm-safe)
// ---------------------------------------------------------------------------

/// Web weight bundle layout (little-endian):
/// magic `HAPK` (4B) | u32 vocab_size | u32 embed_dim |
/// embedding[vocab*embed] | fc_text_w[32*64] | fc_text_b[32] |
/// fc_engine_w[32*11] | fc_engine_b[32] |
/// fc_fused_w[32*64] | fc_fused_b[32] | fc_out_w[32] | fc_out_b[1]
/// All floats LE f32. Total for the stock shape ≈ 5.1 MB.
#[derive(Clone, Debug, Default)]
pub struct ApkWeights {
    pub vocab_size: usize,
    pub embed: Vec<f32>,
    pub fc_text_w: Vec<f32>,
    pub fc_text_b: Vec<f32>,
    pub fc_engine_w: Vec<f32>,
    pub fc_engine_b: Vec<f32>,
    pub fc_fused_w: Vec<f32>,
    pub fc_fused_b: Vec<f32>,
    pub fc_out_w: Vec<f32>,
    pub fc_out_b: f32,
}

impl ApkWeights {
    pub fn from_bin(data: &[u8]) -> Option<Self> {
        if data.len() < 12 || &data[0..4] != b"HAPK" {
            return None;
        }
        let vocab_size = read_u32_le(data, 4)? as usize;
        let embed_dim = read_u32_le(data, 8)? as usize;
        if vocab_size == 0 || vocab_size > VOCAB_SIZE || embed_dim != EMBED_DIM {
            return None;
        }
        let expect_floats = vocab_size * embed_dim
            + TEXT_HIDDEN * EMBED_DIM
            + TEXT_HIDDEN
            + ENGINE_HIDDEN * ENGINE_FEATURE_COUNT
            + ENGINE_HIDDEN
            + FUSED_HIDDEN * (TEXT_HIDDEN + ENGINE_HIDDEN)
            + FUSED_HIDDEN
            + FUSED_HIDDEN
            + 1;
        if data.len() != 12 + expect_floats * 4 {
            return None;
        }
        let mut floats = Vec::with_capacity(expect_floats);
        let mut off = 12;
        for _ in 0..expect_floats {
            let v = f32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?);
            if !v.is_finite() {
                return None;
            }
            floats.push(v);
            off += 4;
        }
        let mut cur = 0;
        let take = |cur: &mut usize, n: usize| -> Vec<f32> {
            let s = *cur;
            *cur += n;
            floats[s..s + n].to_vec()
        };
        let embed = take(&mut cur, vocab_size * embed_dim);
        let fc_text_w = take(&mut cur, TEXT_HIDDEN * EMBED_DIM);
        let fc_text_b = take(&mut cur, TEXT_HIDDEN);
        let fc_engine_w = take(&mut cur, ENGINE_HIDDEN * ENGINE_FEATURE_COUNT);
        let fc_engine_b = take(&mut cur, ENGINE_HIDDEN);
        let fc_fused_w = take(&mut cur, FUSED_HIDDEN * (TEXT_HIDDEN + ENGINE_HIDDEN));
        let fc_fused_b = take(&mut cur, FUSED_HIDDEN);
        let fc_out_w = take(&mut cur, FUSED_HIDDEN);
        let fc_out_b = floats[cur];
        Some(Self {
            vocab_size,
            embed,
            fc_text_w,
            fc_text_b,
            fc_engine_w,
            fc_engine_b,
            fc_fused_w,
            fc_fused_b,
            fc_out_w,
            fc_out_b,
        })
    }

    /// `y = Wx + b`, `W` row-major `[rows x cols]`, then ReLU.
    fn linear_relu(w: &[f32], b: &[f32], x: &[f32], rows: usize, cols: usize) -> Vec<f32> {
        let mut out = vec![0.0f32; rows];
        for r in 0..rows {
            let mut acc = b.get(r).copied().unwrap_or(0.0);
            let base = r * cols;
            for c in 0..cols {
                acc += w.get(base + c).copied().unwrap_or(0.0) * x.get(c).copied().unwrap_or(0.0);
            }
            out[r] = if acc > 0.0 { acc } else { 0.0 };
        }
        out
    }

    pub fn forward(&self, tokens: &[u32], engine_norm: &[f32]) -> f32 {
        if tokens.is_empty() || engine_norm.len() != ENGINE_FEATURE_COUNT {
            return 0.0;
        }
        // Mean-pooled embedding.
        let mut pooled = vec![0.0f32; EMBED_DIM];
        let n = tokens.len() as f32;
        for &id in tokens {
            let id = (id as usize).min(self.vocab_size.saturating_sub(1));
            let base = id * EMBED_DIM;
            for d in 0..EMBED_DIM {
                pooled[d] += self.embed.get(base + d).copied().unwrap_or(0.0) / n;
            }
        }
        let text = Self::linear_relu(
            &self.fc_text_w,
            &self.fc_text_b,
            &pooled,
            TEXT_HIDDEN,
            EMBED_DIM,
        );
        let eng = Self::linear_relu(
            &self.fc_engine_w,
            &self.fc_engine_b,
            engine_norm,
            ENGINE_HIDDEN,
            ENGINE_FEATURE_COUNT,
        );
        let mut fused_in = Vec::with_capacity(TEXT_HIDDEN + ENGINE_HIDDEN);
        fused_in.extend_from_slice(&text);
        fused_in.extend_from_slice(&eng);
        let fused = Self::linear_relu(
            &self.fc_fused_w,
            &self.fc_fused_b,
            &fused_in,
            FUSED_HIDDEN,
            TEXT_HIDDEN + ENGINE_HIDDEN,
        );
        let mut logit = self.fc_out_b;
        for (w, x) in self.fc_out_w.iter().zip(fused.iter()) {
            logit += w * x;
        }
        1.0 / (1.0 + (-logit.clamp(-30.0, 30.0)).exp())
    }
}

// ---------------------------------------------------------------------------
// Model handle: vocab + percentile stats + weights
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct ApkModel {
    pub tokenizer: Option<Tokenizer>,
    pub feature_stats: Option<FeaturePercentiles>,
    pub weights: Option<ApkWeights>,
}

impl ApkModel {
    pub fn load_vocab(&mut self, data: &[u8]) -> bool {
        match Tokenizer::load_json(data) {
            Some(t) => {
                self.tokenizer = Some(t);
                true
            }
            None => false,
        }
    }

    pub fn load_features(&mut self, data: &[u8]) -> bool {
        match FeaturePercentiles::from_json_bytes(data) {
            Some(f) => {
                self.feature_stats = Some(f);
                true
            }
            None => false,
        }
    }

    pub fn load_weights(&mut self, data: &[u8]) -> bool {
        match ApkWeights::from_bin(data) {
            Some(w) => {
                self.weights = Some(w);
                true
            }
            None => false,
        }
    }

    /// Bitmask for `web_apk_loaded`: 1 = vocab, 2 = features, 4 = weights.
    pub fn loaded_mask(&self) -> u32 {
        (self.tokenizer.is_some() as u32)
            | ((self.feature_stats.is_some() as u32) << 1)
            | ((self.weights.is_some() as u32) << 2)
    }

    pub fn ml_ready(&self) -> bool {
        self.loaded_mask() == 7
    }

    pub fn predict(&self, apk: &[u8]) -> Option<ApkMlResult> {
        let tok = self.tokenizer.as_ref()?;
        let stats = self.feature_stats.as_ref()?;
        let weights = self.weights.as_ref()?;
        let tokens = tok.tokenize(apk)?;
        let raw = EngineFeatures::extract_from_apk(apk)
            .unwrap_or_default()
            .to_vec();
        let norm = stats.normalize(&raw);
        if norm.len() != ENGINE_FEATURE_COUNT {
            return None;
        }
        let confidence = ApkWeights::forward(weights, &tokens, &norm).clamp(0.0, 1.0);
        if !confidence.is_finite() {
            return None;
        }
        Some(ApkMlResult {
            confidence,
            malicious: confidence >= APK_MALICIOUS_THRESHOLD,
            suspicious: !matches!(confidence, c if c >= APK_MALICIOUS_THRESHOLD)
                && confidence >= APK_SUSPICIOUS_THRESHOLD,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ApkMlResult {
    pub confidence: f32,
    pub malicious: bool,
    pub suspicious: bool,
}

// ---------------------------------------------------------------------------
// Detection helpers used by the engine
// ---------------------------------------------------------------------------

/// True for APKs: `.apk` extension, or a ZIP whose central directory holds
/// `AndroidManifest.xml` / `*.dex` / `lib/*.so` entries.
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
    for e in &entries {
        let l = e.name.to_ascii_lowercase();
        if l == "androidmanifest.xml" || l.ends_with(".dex") {
            return true;
        }
        if l.starts_with("lib/") && l.ends_with(".so") {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone)]
pub struct HeuristicHit {
    pub name: String,
    pub score: f32,
    pub details: String,
}

/// Heuristic APK signals. Runs with no model files loaded, so APK malware is
/// found even before training/export. All parsing is capped; never panics.
pub fn apk_heuristics(data: &[u8], name: &str) -> Vec<HeuristicHit> {
    if !is_apk(data, name) {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let Some(entries) = parse_central_dir(data) else {
        hits.push(HeuristicHit {
            name: "APK.InvalidStructure".to_string(),
            score: 0.55,
            details: "APK extension but unreadable ZIP central directory".to_string(),
        });
        return hits;
    };

    let mut has_manifest = false;
    let mut dex_count = 0u32;
    let mut so_count = 0u32;
    let mut hist = [0u64; 256];
    let mut hist_total: u64 = 0;
    let mut spent: usize = 0;
    let mut class_total: u64 = 0;
    let mut method_total: u64 = 0;
    let mut manifest_text = String::new();

    for entry in &entries {
        let l = entry.name.to_ascii_lowercase();
        if l == "androidmanifest.xml" {
            has_manifest = true;
        }
        if l.ends_with(".dex") {
            dex_count += 1;
        }
        if l.starts_with("lib/") && l.ends_with(".so") {
            so_count += 1;
        }
    }
    if !has_manifest && dex_count == 0 {
        hits.push(HeuristicHit {
            name: "APK.NoManifestNoDex".to_string(),
            score: 0.55,
            details: "ZIP named .apk without AndroidManifest.xml or classes.dex".to_string(),
        });
        return hits;
    }

    for entry in &entries {
        if spent >= MAX_TOTAL_SCAN {
            break;
        }
        let l = entry.name.to_ascii_lowercase();
        let relevant = l == "androidmanifest.xml"
            || l.ends_with(".dex")
            || (l.starts_with("lib/") && l.ends_with(".so"));
        if !relevant {
            continue;
        }
        let Some(buf) = read_entry_data(data, entry) else {
            continue;
        };
        spent += buf.len();
        for &b in &buf {
            hist[b as usize] += 1;
        }
        hist_total += buf.len() as u64;
        if l == "androidmanifest.xml" {
            let capped = &buf[..buf.len().min(4 * 1024 * 1024)];
            manifest_text = harvest_manifest_text(capped);
        } else if l.ends_with(".dex") {
            if let Some((classes, _, methods)) = dex_counts(&buf) {
                class_total += classes as u64;
                method_total += methods as u64;
            }
        }
    }

    // Dangerous-permission combo over manifest strings.
    const DANGEROUS: &[&str] = &[
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
    let low = manifest_text.to_ascii_lowercase();
    let mut perm_hits = 0u32;
    for p in DANGEROUS {
        if low.contains(p) {
            perm_hits += 1;
        }
    }
    let sms_trio = low.contains("android.permission.send_sms")
        && low.contains("android.permission.read_sms")
        && low.contains("android.permission.receive_sms");
    if sms_trio {
        hits.push(HeuristicHit {
            name: "APK.SmsTrio".to_string(),
            score: 0.78,
            details: "Manifest requests SEND+READ+RECEIVE_SMS (premium-SMS trojan pattern)"
                .to_string(),
        });
    } else if perm_hits >= 4 {
        hits.push(HeuristicHit {
            name: "APK.SuspiciousPermissionCombo".to_string(),
            score: 0.65,
            details: format!("Manifest holds {perm_hits} dangerous permissions"),
        });
    }

    let entropy = shannon_entropy(&hist, hist_total);
    if entropy >= 7.6 && hist_total >= 256 * 1024 {
        hits.push(HeuristicHit {
            name: "APK.PackedHighEntropy".to_string(),
            score: 0.60,
            details: format!("Code-section entropy {entropy:.2} bits (packed/obfuscated)"),
        });
    }
    if method_total >= 20_000 && perm_hits >= 5 {
        hits.push(HeuristicHit {
            name: "APK.LargeDexApiSurface".to_string(),
            score: 0.60,
            details: format!("{method_total} DEX methods with {perm_hits} dangerous permissions"),
        });
    } else if class_total >= 8_000 && perm_hits >= 5 {
        hits.push(HeuristicHit {
            name: "APK.LargeDexApiSurface".to_string(),
            score: 0.58,
            details: format!("{class_total} DEX classes with {perm_hits} dangerous permissions"),
        });
    }
    if so_count >= 1 && perm_hits >= 5 {
        hits.push(HeuristicHit {
            name: "APK.NativeCodeWithSensitivePerms".to_string(),
            score: 0.55,
            details: format!("{so_count} native .so with {perm_hits} dangerous permissions"),
        });
    }
    if dex_count >= 5 {
        hits.push(HeuristicHit {
            name: "APK.MultidexHeavy".to_string(),
            score: 0.52,
            details: format!("{dex_count} classes*.dex files (multidex)"),
        });
    }
    if hits.len() > 6 {
        hits.truncate(6);
    }
    hits
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
    // UTF-16LE pass.
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
        // Entry names always help FileType-agnostic rules.
        for entry in entries.iter().take(512) {
            if buf.len() >= 2 * 1024 * 1024 {
                break;
            }
            buf.extend_from_slice(entry.name.as_bytes());
            buf.push(b'\n');
        }
    }
    if buf.is_empty() {
        // Fallback: head of the raw file (still capped).
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

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    /// Minimal STORED-only ZIP writer for tests (shared with engine tests).
    pub(crate) fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let local_off = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
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
            central.extend_from_slice(&0u32.to_le_bytes());
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

    #[test]
    fn detects_apk_by_name_and_content() {
        let zip = stored_zip(&[("AndroidManifest.xml", b"hello"), ("classes.dex", b"dex\n")]);
        assert!(is_apk(&zip, "sample.bin"));
        assert!(is_apk(b"PK junk", "app.apk"));
        assert!(!is_apk(b"MZ fake pe", "app.exe"));
        assert!(!is_apk(b"hello world", "notes.txt"));
    }

    #[test]
    fn heuristics_flag_sms_trio() {
        let manifest = b"android.permission.SEND_SMS android.permission.READ_SMS android.permission.RECEIVE_SMS".to_vec();
        let mut dex = vec![0u8; 0x70];
        dex[0..4].copy_from_slice(b"dex\n");
        dex[0x38..0x3c].copy_from_slice(&10u32.to_le_bytes());
        dex[0x58..0x5c].copy_from_slice(&50u32.to_le_bytes());
        dex[0x60..0x64].copy_from_slice(&5u32.to_le_bytes());
        let zip = stored_zip(&[("AndroidManifest.xml", &manifest), ("classes.dex", &dex)]);
        let hits = apk_heuristics(&zip, "evil.apk");
        assert!(hits.iter().any(|h| h.name == "APK.SmsTrio"));
    }

    #[test]
    fn weights_reject_garbage() {
        assert!(ApkWeights::from_bin(b"nope").is_none());
        assert!(ApkWeights::from_bin(&[0u8; 64]).is_none());
    }

    #[test]
    fn vocab_features_reject_garbage() {
        assert!(Tokenizer::load_json(b"not json").is_none());
        assert!(FeaturePercentiles::from_json_bytes(b"[]").is_none());
    }
}
