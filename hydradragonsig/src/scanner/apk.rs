//! Android package (APK) profile: the 58-float tree-model feature vector.
//!
//! Ported from the OpenEDR static engine's APK module (`openedr_static/src/apk.rs`),
//! feature for feature and in the same order, so a forest trained there scores
//! vectors built here. Features 0..23 come from a capped single pass (central
//! directory sizes, manifest, DEX header prefixes); 24..57 from a deep pass over
//! the inflated entries (native libraries, manifest capability flags, Dalvik
//! method references, packaging anomalies, string statistics).
//!
//! Features 52..57 are string-classifier statistics. The classifier is not part
//! of this crate: pass one through [`apk_tree_features_with`] (OpenEDR plugs in
//! its string filter model). Without one every string counts as unknown, so the
//! malicious/benign counts are 0 and `unknown_str_ratio` is `n / (n + 1)`.
//!
//! All parsing is bounded (entry count, per-entry and total inflation caps) and
//! never panics.

use crate::models::ApkInfo;
use std::collections::BTreeMap;

use super::dex::{dex_counts, parse_dex_method_signatures, parse_dex_string_table};

pub const APK_TREE_FEATURE_COUNT: usize = 58;

pub const APK_TREE_FEATURE_NAMES: [&str; APK_TREE_FEATURE_COUNT] = [
    // 0..23: package structure and manifest summary
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
    // 24..30: native libraries
    "has_arm64",
    "has_arm32",
    "has_x86",
    "has_x86_64",
    "so_exported_jni_count",
    "so_imported_symbols_count",
    "so_suspicious_imports_count",
    // 31..37: manifest high-risk capabilities
    "perm_boot_completed",
    "perm_accessibility_service",
    "perm_device_admin",
    "perm_system_alert_window",
    "perm_install_packages",
    "perm_read_phone_state",
    "perm_external_storage_write",
    // 38..46: Dalvik API references
    "api_reflection_calls",
    "api_dynamic_dex_loading",
    "api_crypto_cipher_calls",
    "api_process_exec_calls",
    "api_sms_send_calls",
    "api_device_id_calls",
    "api_network_http_calls",
    "api_package_manager_queries",
    "api_anti_debug_root_calls",
    // 47..51: packaging anomalies
    "assets_entry_count",
    "assets_size_log",
    "has_hidden_payload_in_assets",
    "is_protector_packed",
    "has_non_standard_dex",
    // 52..57: string statistics
    "mal_str_hits",
    "ben_str_hits",
    "mal_ben_str_ratio",
    "mal_str_density",
    "unknown_str_ratio",
    "total_unique_strings_log",
];

/// Per-entry / total inflation caps.
pub const MAX_ENTRY_SCAN: usize = 8 * 1024 * 1024;
pub const MAX_TOTAL_SCAN: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 8192;
const PROFILE_MANIFEST_CAP: usize = 2 * 1024 * 1024;
const PROFILE_TOTAL_CAP: usize = 8 * 1024 * 1024;
const PROFILE_DEX_PREFIX: u64 = 4096;
const PROFILE_MAX_DEX: usize = 32;
const MAX_COLLECTED_STRINGS: usize = 15_000;

/// File names of native loaders shipped by commercial APK protectors/packers.
pub const PROTECTOR_LIBRARIES: &[&str] = &[
    "libprotectclass.so",
    "libjiagu.so",
    "libjiagu_a64.so",
    "libjiagu_x86.so",
    "libtx_shared.so",
    "libshell.so",
    "libshellx.so",
    "libsecmain.so",
    "libsecexe.so",
    "secdata0.jar",
    "bangcle",
    "libexec.so",
    "libexecmain.so",
    "ijm_lib",
    "libbaiduprotect.so",
    "libbaiduprotect_art.so",
    "libmobisec.so",
    "libfake_jni.so",
    "libdexhelper.so",
    "libdexhelper-x86.so",
    "libkdp.so",
    "libnsaferonly.so",
    "libnqshield.so",
    "libaps.so",
    "apkprotect",
];

/// Verdict counts a string classifier returns for one APK's strings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StringVerdictCounts {
    pub malicious: usize,
    pub benign: usize,
    pub unknown: usize,
    pub total_unique: usize,
}

/// Classifies the strings harvested from an APK (manifest pool, DEX strings and
/// method references, native library strings) for features 52..57.
pub trait StringClassifier {
    fn classify(&self, strings: Vec<String>) -> StringVerdictCounts;
}

/// No model: every distinct string is unknown.
pub struct NoStringModel;

impl StringClassifier for NoStringModel {
    fn classify(&self, mut strings: Vec<String>) -> StringVerdictCounts {
        strings.sort_unstable();
        strings.dedup();
        StringVerdictCounts { malicious: 0, benign: 0, unknown: strings.len(), total_unique: strings.len() }
    }
}

// ---------------------------------------------------------------------------
// Minimal ZIP reader (central directory + local headers). Tolerates trailing
// payloads past the EOCD and EOCD-less archives, which `zip` refuses.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct ZipEntryMeta {
    pub name: String,
    method: u16,
    comp_size: u32,
    pub uncomp_size: u32,
    local_offset: u32,
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

fn read_i32_le(b: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

/// Entries of the last EOCD candidate that validates (whole-file backwards
/// search), else the longest run of central-directory headers.
pub(crate) fn parse_central_dir(data: &[u8]) -> Option<Vec<ZipEntryMeta>> {
    if data.len() < 22 || !data.starts_with(b"PK") {
        return None;
    }
    let mut i = data.len() - 4;
    loop {
        if data[i..i + 4] == *b"PK\x05\x06" && i + 22 <= data.len() {
            if let Some(entries) = parse_central_dir_at(data, i) {
                return Some(entries);
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    parse_central_dir_fallback(data)
}

fn parse_entries_at(data: &[u8], cd_offset: usize, limit: usize) -> Vec<ZipEntryMeta> {
    let mut entries = Vec::with_capacity(limit.min(1024));
    let mut off = cd_offset;
    for _ in 0..limit.min(MAX_ENTRIES) {
        if off + 46 > data.len() || read_u32_le(data, off) != Some(0x0201_4b50) {
            break;
        }
        let (Some(method), Some(comp_size), Some(uncomp_size), Some(fname_len), Some(extra_len), Some(comment_len), Some(local_offset)) = (
            read_u16_le(data, off + 10),
            read_u32_le(data, off + 20),
            read_u32_le(data, off + 24),
            read_u16_le(data, off + 28).map(usize::from),
            read_u16_le(data, off + 30).map(usize::from),
            read_u16_le(data, off + 32).map(usize::from),
            read_u32_le(data, off + 42),
        ) else {
            break;
        };
        let name_off = off + 46;
        let name_end = name_off + fname_len;
        if name_end > data.len() || fname_len > 2048 {
            break;
        }
        entries.push(ZipEntryMeta {
            name: String::from_utf8_lossy(&data[name_off..name_end]).into_owned(),
            method,
            comp_size,
            uncomp_size,
            local_offset,
        });
        off = name_end + extra_len + comment_len;
        if off >= data.len() {
            break;
        }
    }
    entries
}

fn parse_central_dir_fallback(data: &[u8]) -> Option<Vec<ZipEntryMeta>> {
    let mut best: Vec<ZipEntryMeta> = Vec::new();
    let mut found = 0usize;
    let mut i = 0usize;
    while i + 4 <= data.len() && found < 64 {
        if data[i..i + 4] == *b"PK\x01\x02" {
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
    (best.len() >= 2).then_some(best)
}

fn parse_central_dir_at(data: &[u8], eocd: usize) -> Option<Vec<ZipEntryMeta>> {
    let total_entries = read_u16_le(data, eocd + 10)? as usize;
    let cd_offset = read_u32_le(data, eocd + 16)? as usize;
    if total_entries == 0 || total_entries > MAX_ENTRIES || cd_offset >= data.len() {
        return None;
    }
    if read_u32_le(data, cd_offset)? != 0x0201_4b50 {
        return None;
    }
    let entries = parse_entries_at(data, cd_offset, total_entries);
    (!entries.is_empty()).then_some(entries)
}

fn local_data_offset(data: &[u8], local_off: u32) -> Option<usize> {
    let off = local_off as usize;
    if read_u32_le(data, off)? != 0x0403_4b50 {
        return None;
    }
    let fname_len = read_u16_le(data, off + 26)? as usize;
    let extra_len = read_u16_le(data, off + 28)? as usize;
    if fname_len > 4096 {
        return None;
    }
    off.checked_add(30)?.checked_add(fname_len)?.checked_add(extra_len)
}

fn compressed_slice<'a>(data: &'a [u8], entry: &ZipEntryMeta) -> Option<&'a [u8]> {
    if entry.comp_size == 0xFFFF_FFFF || entry.uncomp_size == 0xFFFF_FFFF {
        return None;
    }
    let start = local_data_offset(data, entry.local_offset)?;
    data.get(start..start.checked_add(entry.comp_size as usize)?)
}

fn inflate(compressed: &[u8], limit: u64, hint: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    if compressed.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(hint.min(1 << 20).max(512));
    flate2::read::DeflateDecoder::new(compressed).take(limit).read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

/// Inflate one entry (stored / deflated), at most [`MAX_ENTRY_SCAN`] bytes.
pub(crate) fn read_entry_data(data: &[u8], entry: &ZipEntryMeta) -> Option<Vec<u8>> {
    let compressed = compressed_slice(data, entry)?;
    match entry.method {
        0 => (compressed.len() <= MAX_ENTRY_SCAN).then(|| compressed.to_vec()),
        8 if compressed.len() <= MAX_ENTRY_SCAN * 4 => {
            inflate(compressed, MAX_ENTRY_SCAN as u64, entry.uncomp_size as usize)
        }
        _ => None,
    }
}

fn read_entry_prefix(data: &[u8], entry: &ZipEntryMeta, limit: u64) -> Option<Vec<u8>> {
    let compressed = compressed_slice(data, entry)?;
    match entry.method {
        0 => Some(compressed[..compressed.len().min(limit as usize)].to_vec()),
        8 => inflate(compressed, limit, limit as usize),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ELF and binary-XML (AXML) readers
// ---------------------------------------------------------------------------

/// Native library facts: (arm64, arm32, x86, x86_64, JNI exports, imported
/// symbols, suspicious imports). Printable strings (4..=256 bytes) are appended
/// to `out` up to the collection cap.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ElfFacts {
    pub arm64: bool,
    pub arm32: bool,
    pub x86: bool,
    pub x86_64: bool,
    pub exported_jni: usize,
    pub imported: usize,
    pub suspicious: usize,
}

pub fn parse_elf_strings_and_symbols(buf: &[u8], out: &mut Vec<String>) -> Option<ElfFacts> {
    if buf.len() < 0x34 || !buf.starts_with(b"\x7fELF") {
        return None;
    }
    let machine = read_u16_le(buf, 0x12).unwrap_or(0);
    let mut facts = ElfFacts {
        arm64: machine == 183,
        arm32: machine == 40,
        x86: machine == 3,
        x86_64: machine == 62,
        ..ElfFacts::default()
    };
    let mut start = None;
    for i in 0..=buf.len() {
        let printable = buf.get(i).is_some_and(|b| (0x20..0x7f).contains(b));
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                start = None;
                let len = i - s;
                if !(4..=256).contains(&len) {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(&buf[s..i]) else { continue };
                if text.starts_with("Java_") || text.contains("JNI_OnLoad") {
                    facts.exported_jni += 1;
                } else if matches!(text, "dlopen" | "dlsym" | "system" | "execve" | "ptrace" | "fork" | "socket" | "connect") {
                    facts.imported += 1;
                    facts.suspicious += 1;
                }
                if out.len() < MAX_COLLECTED_STRINGS {
                    out.push(text.to_string());
                }
            }
            _ => {}
        }
    }
    Some(facts)
}

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
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
        let rel = read_u32_le(b, offsets_off + i * 4)? as usize;
        let str_off = chunk_start.saturating_add(strings_start).saturating_add(rel);
        if str_off >= chunk_start + chunk_size || str_off >= b.len() {
            strings.push(String::new());
            continue;
        }
        let s = if is_utf8 {
            // utf16 length (1-2 bytes), then utf8 byte length (1-2 bytes).
            let len_off = if b[str_off] & 0x80 != 0 { str_off + 2 } else { str_off + 1 };
            let Some(&b0) = b.get(len_off) else {
                strings.push(String::new());
                continue;
            };
            let (byte_len, start) = if b0 & 0x80 != 0 {
                let Some(&b1) = b.get(len_off + 1) else {
                    strings.push(String::new());
                    continue;
                };
                ((((b0 as usize) & 0x7f) << 8) | b1 as usize, len_off + 2)
            } else {
                (b0 as usize, len_off + 1)
            };
            let start = start.min(b.len());
            let end = start.saturating_add(byte_len).min(b.len());
            String::from_utf8_lossy(&b[start..end]).into_owned()
        } else {
            let len = read_u16_le(b, str_off)? as usize;
            let mut units = Vec::with_capacity(len.min(512));
            for j in 0..len {
                units.push(read_u16_le(b, str_off + 2 + j * 2)?);
            }
            String::from_utf16_lossy(&units)
        };
        strings.push(s);
    }
    Some(strings)
}

/// Walk the AXML chunks; `on_chunk(type, offset, header_size, size)` sees each one.
fn walk_axml(buf: &[u8], mut on_chunk: impl FnMut(u16, usize, usize, usize) -> Option<()>) {
    let mut off = 0usize;
    for _ in 0..50_000 {
        if off + 8 > buf.len() {
            break;
        }
        let (Some(chunk_type), Some(header_size), Some(chunk_size)) =
            (read_u16_le(buf, off), read_u16_le(buf, off + 2).map(usize::from), read_u32_le(buf, off + 4).map(|v| v as usize))
        else {
            break;
        };
        if chunk_size < header_size || header_size < 8 || off + chunk_size > buf.len() {
            break;
        }
        if on_chunk(chunk_type, off, header_size, chunk_size).is_none() {
            break;
        }
        // The XML document chunk wraps every other chunk: step into it.
        off += if chunk_type == RES_XML_TYPE { header_size } else { chunk_size };
    }
}

/// String pool of a binary AndroidManifest.xml.
pub fn parse_axml_string_pool_from_bytes(buf: &[u8]) -> Option<Vec<String>> {
    let mut pool = None;
    walk_axml(buf, |ty, off, _, size| {
        if ty == RES_STRING_POOL_TYPE {
            pool = parse_axml_string_pool(buf, off, size);
            return None;
        }
        Some(())
    });
    pool
}

fn analyze_manifest(buf: &[u8]) -> Option<ManifestCounts> {
    let mut pool: Vec<String> = Vec::new();
    let mut resource_map: Vec<u32> = Vec::new();
    let mut feats = ManifestCounts::default();
    let mut seen_any_element = false;
    walk_axml(buf, |ty, off, header_size, size| {
        match ty {
            RES_STRING_POOL_TYPE => {
                if let Some(p) = parse_axml_string_pool(buf, off, size) {
                    pool = p;
                }
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                let mut p = off + header_size;
                while p + 4 <= off + size && resource_map.len() < 10_000 {
                    resource_map.push(read_u32_le(buf, p)?);
                    p += 4;
                }
            }
            RES_XML_START_ELEMENT_TYPE => {
                seen_any_element = true;
                let ns_name_off = off + 16;
                let name_idx = read_i32_le(buf, ns_name_off + 4)?;
                let elem_name = usize::try_from(name_idx).ok().and_then(|i| pool.get(i)).map(String::as_str).unwrap_or("");
                let attr_start_off = ns_name_off + 8;
                if attr_start_off + 8 > buf.len() {
                    return None;
                }
                let attribute_start = read_u16_le(buf, attr_start_off)? as usize;
                let attribute_size = read_u16_le(buf, attr_start_off + 2)? as usize;
                let attribute_count = read_u16_le(buf, attr_start_off + 4)? as usize;
                if attribute_size == 0 || attribute_count > 256 {
                    return Some(());
                }
                match elem_name {
                    "activity" | "activity-alias" => feats.activities += 1,
                    "service" => feats.services += 1,
                    "receiver" => feats.receivers += 1,
                    "uses-permission" | "uses-permission-sdk-23" | "permission" => feats.total_permissions += 1,
                    _ => {}
                }
                if elem_name == "uses-sdk" {
                    let attrs_base = ns_name_off + attribute_start;
                    for i in 0..attribute_count {
                        let a_off = attrs_base + i * attribute_size;
                        if a_off + 20 > buf.len() {
                            break;
                        }
                        let attr_name_idx = read_i32_le(buf, a_off + 4)?;
                        let data = read_u32_le(buf, a_off + 16)?;
                        let res_id = usize::try_from(attr_name_idx).ok().and_then(|i| resource_map.get(i)).copied().unwrap_or(0);
                        if res_id == ATTR_MIN_SDK_VERSION {
                            feats.min_sdk = data;
                        } else if res_id == ATTR_TARGET_SDK_VERSION {
                            feats.target_sdk = data;
                        }
                    }
                }
            }
            _ => {}
        }
        Some(())
    });
    seen_any_element.then_some(feats)
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
    if x.is_nan() || x <= 0.0 { 0.0 } else { (x + 1.0).ln() }
}

// ---------------------------------------------------------------------------
// Capped single-pass profile (features 0..23)
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

/// Printable ASCII and UTF-16LE runs (4..=256 chars) of manifest bytes,
/// space-joined, for permission grep. Capped.
fn harvest_manifest_text(buf: &[u8]) -> String {
    const SCAN_CAP: usize = 2 * 1024 * 1024;
    const OUT_CAP: usize = 256 * 1024;
    let mut out = String::new();
    let flush = |run: &mut Vec<u8>, out: &mut String| {
        if (4..=256).contains(&run.len()) {
            if let Ok(s) = std::str::from_utf8(run) {
                out.push(' ');
                out.push_str(s);
            }
        }
        run.clear();
    };
    let mut run: Vec<u8> = Vec::new();
    for &b in buf.iter().take(SCAN_CAP) {
        if (0x20..0x7f).contains(&b) {
            run.push(b);
            if run.len() > 256 {
                flush(&mut run, &mut out);
            }
        } else {
            flush(&mut run, &mut out);
        }
        if out.len() > OUT_CAP {
            break;
        }
    }
    flush(&mut run, &mut out);
    let mut j = 0;
    while j + 1 < buf.len().min(SCAN_CAP) {
        let (lo, hi) = (buf[j], buf[j + 1]);
        if hi == 0 && (0x20..0x7f).contains(&lo) {
            run.push(lo);
        } else if !run.is_empty() {
            flush(&mut run, &mut out);
        }
        j += 2;
        if out.len() > OUT_CAP {
            break;
        }
    }
    flush(&mut run, &mut out);
    out
}

fn count_dangerous_perms(text_low: &str) -> (u32, bool) {
    let n = DANGEROUS_PERMS.iter().filter(|p| text_low.contains(*p)).count() as u32;
    let trio = text_low.contains("android.permission.send_sms")
        && text_low.contains("android.permission.read_sms")
        && text_low.contains("android.permission.receive_sms");
    (n, trio)
}

fn profile_apk(apk: &[u8], entries: &[ZipEntryMeta]) -> Option<ApkProfile> {
    let mut p = ApkProfile { entry_count: entries.len() as u32, ..ApkProfile::default() };
    let mut manifest_entry: Option<&ZipEntryMeta> = None;
    let mut dex_entries: Vec<&ZipEntryMeta> = Vec::new();
    for e in entries {
        if e.comp_size == 0xFFFF_FFFF || e.uncomp_size == 0xFFFF_FFFF {
            continue;
        }
        p.comp_total += e.comp_size as u64;
        p.uncomp_total += e.uncomp_size as u64;
        let l = e.name.to_ascii_lowercase();
        if l == "androidmanifest.xml" {
            p.has_manifest = true;
            p.manifest_size = e.uncomp_size as u64;
            manifest_entry.get_or_insert(e);
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

    // Entropy covers exactly the inflated bytes inspected here.
    let mut hist = [0u64; 256];
    let mut hist_total: u64 = 0;
    let mut spent: usize = 0;
    let mut note = |buf: &[u8]| {
        for &b in buf {
            hist[b as usize] += 1;
        }
        hist_total += buf.len() as u64;
    };

    if let Some(mut buf) = manifest_entry.and_then(|me| read_entry_data(apk, me)) {
        buf.truncate(PROFILE_MANIFEST_CAP);
        spent += buf.len();
        note(&buf);
        let (dangerous, trio) = count_dangerous_perms(&harvest_manifest_text(&buf).to_ascii_lowercase());
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

    for de in dex_entries {
        if spent >= PROFILE_TOTAL_CAP {
            break;
        }
        if let Some(prefix) = read_entry_prefix(apk, de, PROFILE_DEX_PREFIX) {
            spent += prefix.len();
            note(&prefix);
            if let Some((classes, strings, methods)) = dex_counts(&prefix) {
                p.dex_classes += classes as u64;
                p.dex_strings += strings as u64;
                p.dex_methods += methods as u64;
            }
        }
    }
    p.entropy = shannon_entropy(&hist, hist_total);
    Some(p)
}

// ---------------------------------------------------------------------------
// Deep pass (features 24..57)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct DeepFacts {
    elf: ElfFacts,
    so_exported_jni: usize,
    so_imported: usize,
    so_suspicious: usize,
    perms: [bool; 7],
    api: [usize; 9],
    assets_count: usize,
    assets_size: u64,
    hidden_payload_assets: bool,
    is_protector: bool,
    has_non_standard_dex: bool,
    strings: Vec<String>,
}

const CAPABILITY_PERMS: [&str; 7] = [
    "android.permission.receive_boot_completed",
    "android.permission.bind_accessibility_service",
    "android.permission.bind_device_admin",
    "android.permission.system_alert_window",
    "android.permission.request_install_packages",
    "android.permission.read_phone_state",
    "android.permission.write_external_storage",
];

/// Method-reference substrings per API family (features 38..46, in order).
/// The last family's bare `su` is broad on purpose: the trained forests saw it.
const API_FAMILIES: [&[&str]; 9] = [
    &["java/lang/reflect"],
    &["DexClassLoader", "PathClassLoader"],
    &["Cipher"],
    &["Runtime;->exec", "ProcessBuilder"],
    &["sendTextMessage", "SmsManager"],
    &["getDeviceId", "getSubscriberId"],
    &["HttpURLConnection", "HttpClient", "okhttp"],
    &["getInstalledPackages", "getInstalledApplications"],
    &["su", "isDebuggerConnected"],
];

fn deep_pass(apk: &[u8], entries: &[ZipEntryMeta]) -> DeepFacts {
    let mut f = DeepFacts::default();
    let mut spent = 0usize;
    for e in entries {
        if e.name.ends_with('/') {
            continue;
        }
        let l = e.name.to_ascii_lowercase();
        if PROTECTOR_LIBRARIES.iter().any(|sig| l.contains(sig)) {
            f.is_protector = true;
        }
        if l.starts_with("assets/") {
            f.assets_count += 1;
            f.assets_size += e.uncomp_size as u64;
            if [".dex", ".jar", ".so", ".dat", ".bin"].iter().any(|ext| l.ends_with(ext)) {
                f.hidden_payload_assets = true;
            }
        }
        let is_dex = l.ends_with(".dex");
        let is_so = l.starts_with("lib/") && l.ends_with(".so");
        let is_manifest = l == "androidmanifest.xml" || l.ends_with("/androidmanifest.xml");
        if is_dex {
            let file = l.rsplit('/').next().unwrap_or(&l);
            if !file.starts_with("classes") {
                f.has_non_standard_dex = true;
            }
        }
        if !(is_dex || is_so || is_manifest) || spent >= MAX_TOTAL_SCAN {
            continue;
        }
        let Some(data) = read_entry_data(apk, e) else { continue };
        spent += data.len();
        if is_dex {
            if let Some(strs) = parse_dex_string_table(&data) {
                let methods = parse_dex_method_signatures(&data, &strs);
                for m in &methods {
                    for (slot, needles) in f.api.iter_mut().zip(API_FAMILIES) {
                        if needles.iter().any(|n| m.contains(n)) {
                            *slot += 1;
                        }
                    }
                }
                f.strings.extend(methods);
                f.strings.extend(strs);
            }
        } else if is_so {
            if let Some(facts) = parse_elf_strings_and_symbols(&data, &mut f.strings) {
                f.elf.arm64 |= facts.arm64;
                f.elf.arm32 |= facts.arm32;
                f.elf.x86 |= facts.x86;
                f.elf.x86_64 |= facts.x86_64;
                f.so_exported_jni += facts.exported_jni;
                f.so_imported += facts.imported;
                f.so_suspicious += facts.suspicious;
            }
        } else {
            let text = harvest_manifest_text(&data).to_ascii_lowercase();
            for (flag, perm) in f.perms.iter_mut().zip(CAPABILITY_PERMS) {
                *flag |= text.contains(perm);
            }
            if let Some(pool) = parse_axml_string_pool_from_bytes(&data) {
                f.strings.extend(pool);
            }
        }
    }
    f
}

/// True for an APK by content: a ZIP whose root holds `AndroidManifest.xml`
/// together with code (`*.dex` or `lib/*.so`).
pub fn looks_like_apk(data: &[u8]) -> bool {
    let Some(entries) = parse_central_dir(data) else { return false };
    let (mut manifest, mut code) = (false, false);
    for e in &entries {
        let l = e.name.to_ascii_lowercase();
        manifest |= l == "androidmanifest.xml";
        code |= l.ends_with(".dex") || (l.starts_with("lib/") && l.ends_with(".so"));
    }
    manifest && code
}

/// The 58-feature vector with no string model (see the module docs).
pub fn apk_tree_features(apk: &[u8]) -> Option<[f32; APK_TREE_FEATURE_COUNT]> {
    apk_tree_features_with(apk, &NoStringModel)
}

/// The 58-feature vector, features 52..57 from `classifier`. `None` when `apk`
/// is not a ZIP with a manifest or DEX code.
pub fn apk_tree_features_with(apk: &[u8], classifier: &dyn StringClassifier) -> Option<[f32; APK_TREE_FEATURE_COUNT]> {
    let entries = parse_central_dir(apk)?;
    let p = profile_apk(apk, &entries)?;
    let ratio = if p.uncomp_total > 0 { (p.comp_total as f32 / p.uncomp_total as f32).clamp(0.0, 1.0) } else { 0.0 };
    let avg_entry = if p.entry_count > 0 { p.uncomp_total as f32 / p.entry_count as f32 } else { 0.0 };

    let mut d = deep_pass(apk, &entries);
    let strings = std::mem::take(&mut d.strings);
    let (mal_hits, ben_hits, mal_ben_ratio, mal_density, unk_ratio, tot_log) = if strings.is_empty() {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        let c = classifier.classify(strings);
        let (mal, ben, unk, tot) = (c.malicious as f32, c.benign as f32, c.unknown as f32, c.total_unique as f32);
        (ln1p(mal), ln1p(ben), mal / (ben + 1.0), mal / (tot + 1.0), unk / (tot + 1.0), ln1p(tot))
    };
    let flag = |b: bool| b as u8 as f32;
    let api = |i: usize| ln1p(d.api[i] as f32);

    Some([
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
        flag(p.sms_trio),
        flag(p.has_manifest),
        flag(p.dex_files >= 2),
        ratio,
        ln1p(avg_entry),
        flag(p.so_files >= 1 && p.dangerous_perm_count >= 5),
        flag(d.elf.arm64),
        flag(d.elf.arm32),
        flag(d.elf.x86),
        flag(d.elf.x86_64),
        ln1p(d.so_exported_jni as f32),
        ln1p(d.so_imported as f32),
        ln1p(d.so_suspicious as f32),
        flag(d.perms[0]),
        flag(d.perms[1]),
        flag(d.perms[2]),
        flag(d.perms[3]),
        flag(d.perms[4]),
        flag(d.perms[5]),
        flag(d.perms[6]),
        api(0),
        api(1),
        api(2),
        api(3),
        api(4),
        api(5),
        api(6),
        api(7),
        api(8),
        ln1p(d.assets_count as f32),
        ln1p(d.assets_size as f32),
        flag(d.hidden_payload_assets),
        flag(d.is_protector),
        flag(d.has_non_standard_dex),
        mal_hits,
        ben_hits,
        mal_ben_ratio,
        mal_density,
        unk_ratio,
        tot_log,
    ])
}

/// Report view of [`apk_tree_features`]: feature name -> value.
pub fn apk_info(apk: &[u8]) -> Option<ApkInfo> {
    let vector = apk_tree_features(apk)?;
    let features: BTreeMap<String, f64> = APK_TREE_FEATURE_NAMES
        .iter()
        .zip(vector)
        .map(|(name, v)| (name.to_string(), v as f64))
        .collect();
    Some(ApkInfo { features })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut out);
            for (name, data) in files {
                let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        out.into_inner()
    }

    fn elf_arm64(symbols: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; 0x40];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
        for s in symbols {
            b.extend_from_slice(s.as_bytes());
            b.push(0);
        }
        b
    }

    fn feature(v: &[f32; APK_TREE_FEATURE_COUNT], name: &str) -> f32 {
        v[APK_TREE_FEATURE_NAMES.iter().position(|n| *n == name).unwrap()]
    }

    #[test]
    fn feature_vector_from_synthetic_apk() {
        let dex = super::super::dex::tests::build_dex(
            &["Ldalvik/system/DexClassLoader;", "Ljavax/crypto/Cipher;", "loadClass", "getInstance"],
            &[0, 1],
            &[0],
            &[(0, 2), (1, 3)],
        );
        let manifest = b"\x03\x00\x08\x00 android.permission.SEND_SMS android.permission.READ_SMS android.permission.RECEIVE_SMS android.permission.RECEIVE_BOOT_COMPLETED ";
        let apk = zip_of(&[
            ("AndroidManifest.xml", manifest),
            ("classes.dex", &dex),
            ("classes2.dex", &dex),
            ("lib/arm64-v8a/libjiagu.so", &elf_arm64(&["Java_com_x_Init", "dlopen", "ptrace"])),
            ("assets/payload.bin", b"\x00\x01\x02"),
        ]);
        assert!(looks_like_apk(&apk));
        let v = apk_tree_features(&apk).unwrap();
        assert_eq!(feature(&v, "dex_classes"), 2.0);
        assert_eq!(feature(&v, "dex_methods"), 4.0);
        assert_eq!(feature(&v, "dex_files"), 2.0);
        assert_eq!(feature(&v, "multidex"), 1.0);
        assert_eq!(feature(&v, "elf_so_count"), 1.0);
        assert_eq!(feature(&v, "sms_trio"), 1.0);
        assert_eq!(feature(&v, "has_manifest"), 1.0);
        assert_eq!(feature(&v, "has_arm64"), 1.0);
        assert_eq!(feature(&v, "so_exported_jni_count"), 2f32.ln());
        assert_eq!(feature(&v, "so_suspicious_imports_count"), 3f32.ln());
        assert_eq!(feature(&v, "perm_boot_completed"), 1.0);
        assert_eq!(feature(&v, "api_dynamic_dex_loading"), 3f32.ln(), "one hit per dex, two dex files");
        assert_eq!(feature(&v, "api_crypto_cipher_calls"), 3f32.ln());
        assert_eq!(feature(&v, "has_hidden_payload_in_assets"), 1.0);
        assert_eq!(feature(&v, "is_protector_packed"), 1.0);
        assert_eq!(feature(&v, "has_non_standard_dex"), 0.0);
        assert_eq!(feature(&v, "mal_str_hits"), 0.0);
        assert!(feature(&v, "unknown_str_ratio") > 0.9);
    }

    struct EverythingMalicious;
    impl StringClassifier for EverythingMalicious {
        fn classify(&self, mut strings: Vec<String>) -> StringVerdictCounts {
            strings.sort_unstable();
            strings.dedup();
            StringVerdictCounts { malicious: strings.len(), benign: 0, unknown: 0, total_unique: strings.len() }
        }
    }

    #[test]
    fn non_apk_inputs() {
        assert!(apk_tree_features(b"not a zip").is_none());
        assert!(apk_tree_features(&zip_of(&[("readme.txt", b"hello")])).is_none());
    }

    #[test]
    fn plugged_string_classifier_drives_string_features() {
        let v = apk_tree_features_with(
            &zip_of(&[("AndroidManifest.xml", b"\x03\x00\x08\x00"), ("lib/x86/libfoo.so", &elf_arm64(&["Java_a_b"]))]),
            &EverythingMalicious,
        )
        .unwrap();
        assert!(feature(&v, "mal_str_hits") > 0.0);
        assert_eq!(feature(&v, "unknown_str_ratio"), 0.0);
    }

    #[test]
    fn truncated_apk_never_panics() {
        let apk = zip_of(&[("AndroidManifest.xml", b"\x03\x00\x08\x00"), ("classes.dex", b"dex\n035\0")]);
        for cut in 0..apk.len() {
            let _ = apk_tree_features(&apk[..cut]);
        }
    }
}
