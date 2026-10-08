//! VirusKovAlyzer: static file report (Rust port of OpenEDR/edrgui/uviruskovalyzer.pas).
//!
//! Pure, bounds-checked parsing of the bytes the server already has after an upload:
//! hashes (CRC32, MD5, SHA-1, SHA-256, imphash), file type, overall entropy, PE headers,
//! sections with entropy, imports, exports, overlay, categorised strings and a list of
//! static indicators. No file I/O and no panics on malformed input; every read is
//! checked. The JSON report is stored next to the verdict and served to the website.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const REPORT_VERSION: u32 = 1;
const MAX_STRINGS_SCAN: usize = 8 * 1024 * 1024;
const MAX_STRINGS_PER_KIND: usize = 300;
const MAX_IMPORT_DLLS: usize = 512;
const MAX_IMPORT_FUNCS: usize = 4096;
const MAX_EXPORTS: usize = 4096;
const MAX_SECTIONS: usize = 96;

// ---------------------------------------------------------------- report types

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub version: u32,
    pub generated_at: String,
    pub file_name: String,
    pub size: u64,
    pub file_type: String,
    pub mime: String,
    pub entropy: f64,
    pub hashes: Hashes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeInfo>,
    /// APK manifest / signer summary (package, certificates, permissions, components).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apk: Option<crate::apk::ApkInfo>,
    pub strings: StringsInfo,
    /// Human-readable static findings ("high entropy section", "W+X section", ...).
    pub indicators: Vec<Indicator>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hashes {
    pub crc32: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    /// TLSH "T1..." digest (None for files too small / too uniform for TLSH).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
    /// APK only: TLSH of the concatenated classes*.dex. An APK is a compressed ZIP, so
    /// the whole-file TLSH says little; the DEX digest reflects the code. Used for
    /// "similar files" and the TLSH blacklist only, never for a verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dex_tlsh: Option<String>,
}

impl Hashes {
    /// Digest used for similarity: DEX TLSH for APKs, file TLSH otherwise.
    pub fn similarity_tlsh(&self) -> Option<&str> {
        self.dex_tlsh.as_deref().or(self.tlsh.as_deref())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Indicator {
    /// "info" | "low" | "medium" | "high"
    pub severity: &'static str,
    pub id: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub kind: String,
    pub machine: String,
    pub machine_raw: u16,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub subsystem: String,
    pub timestamp: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_utc: Option<String>,
    pub entry_point: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_section: Option<String>,
    pub image_base: String,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub characteristics: Vec<&'static str>,
    pub dll_characteristics: Vec<&'static str>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportDll>,
    pub import_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_name: Option<String>,
    pub exports: Vec<ExportInfo>,
    pub overlay_offset: u64,
    pub overlay_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_entropy: Option<f64>,
    pub has_signature: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: String,
    pub virtual_size: u32,
    pub raw_offset: String,
    pub raw_size: u32,
    pub entropy: f64,
    /// "packed" (>= 7.2) | "dense" (>= 6.5) | "normal"
    pub class: &'static str,
    /// e.g. "R-X", "RW-"
    pub perms: String,
    pub flags: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportDll {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportInfo {
    pub ordinal: u32,
    pub name: String,
    pub rva: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StringsInfo {
    pub total: usize,
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub registry: Vec<String>,
    pub paths: Vec<String>,
    pub commands: Vec<String>,
    pub crypto_wallets: Vec<String>,
    /// First strings in file order (both ASCII and UTF-16LE), for a quick look.
    pub sample: Vec<String>,
}

// ---------------------------------------------------------------- entry point

pub fn analyze(data: &[u8], file_name: &str) -> FileReport {
    let mut indicators = Vec::new();
    let entropy = round2(shannon(data));
    let (file_type, mime) = detect_type(data, file_name);

    let pe = parse_pe(data, &mut indicators);
    let imphash = pe.as_ref().and_then(|p| imphash(&p.imports));
    let strings = extract_strings(data);

    if pe.is_none() && entropy >= 7.5 && data.len() > 4096 {
        indicators.push(Indicator {
            severity: "low",
            id: "high_entropy_file",
            detail: format!("Whole-file entropy {entropy:.2}: compressed or encrypted content"),
        });
    }
    string_indicators(&strings, &mut indicators);
    if let Some(p) = &pe {
        api_indicators(&p.imports, &mut indicators);
    }

    FileReport {
        version: REPORT_VERSION,
        generated_at: chrono::Utc::now().to_rfc3339(),
        file_name: file_name.chars().take(260).collect(),
        size: data.len() as u64,
        file_type,
        mime: mime.to_string(),
        entropy,
        hashes: Hashes {
            crc32: format!("{:08X}", crc32(data)),
            md5: hex::encode(md5(data)),
            sha1: hex::encode(sha1(data)),
            sha256: hex::encode(Sha256::digest(data)),
            imphash,
            tlsh: tlsh_digest(data),
            dex_tlsh: dex_tlsh(data),
        },
        pe,
        apk: if data.starts_with(b"PK\x03\x04") { crate::apk::parse(data) } else { None },
        strings,
        indicators,
    }
}

/// TLSH digest in the standard `T1` form (same as MalwareBazaar / VirusTotal).
pub fn tlsh_digest(data: &[u8]) -> Option<String> {
    tlsh::hash_buf(data).ok().map(|h| h.to_string())
}

/// TLSH of an APK's code: classes.dex, classes2.dex, ... concatenated in order.
/// `None` when the file is not a ZIP with DEX entries.
pub fn dex_tlsh(data: &[u8]) -> Option<String> {
    if !data.starts_with(b"PK\x03\x04") {
        return None;
    }
    tlsh_digest(&crate::apk::dex_code(data)?)
}

/// Fast variant for building large reference corpora (`tlsh_builder refs`): PE header,
/// sections, imports, TLSH, SHA-256, imphash and PE/API indicators only. No CRC32/MD5/
/// SHA-1 and no string extraction, so string-based indicators are absent; a candidate
/// that has them is then refused by the injection guard (conservative by design).
// Only built for tlsh_builder, which includes this file by path and enables the feature.
#[cfg(feature = "analyze-light")]
pub fn analyze_light(data: &[u8], file_name: &str) -> FileReport {
    let mut indicators = Vec::new();
    let (file_type, mime) = detect_type(data, file_name);
    let pe = parse_pe(data, &mut indicators);
    let imphash = pe.as_ref().and_then(|p| imphash(&p.imports));
    if let Some(p) = &pe {
        api_indicators(&p.imports, &mut indicators);
    }
    FileReport {
        version: REPORT_VERSION,
        generated_at: chrono::Utc::now().to_rfc3339(),
        file_name: file_name.chars().take(260).collect(),
        size: data.len() as u64,
        file_type,
        mime: mime.to_string(),
        entropy: 0.0,
        hashes: Hashes {
            crc32: String::new(),
            md5: String::new(),
            sha1: String::new(),
            sha256: hex::encode(Sha256::digest(data)),
            imphash,
            tlsh: tlsh_digest(data),
            dex_tlsh: dex_tlsh(data),
        },
        pe,
        apk: if data.starts_with(b"PK\x03\x04") { crate::apk::parse(data) } else { None },
        strings: StringsInfo::default(),
        indicators,
    }
}

// ---------------------------------------------------------------- small readers

fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    let b = d.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}
/// NUL-terminated ASCII at `off`, at most `max` bytes, printable only.
fn rd_cstr(d: &[u8], off: usize, max: usize) -> Option<String> {
    let tail = d.get(off..)?;
    let end = tail.iter().take(max).position(|&c| c == 0).unwrap_or(tail.len().min(max));
    let s = &tail[..end];
    if s.is_empty() || !s.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

pub fn shannon(d: &[u8]) -> f64 {
    if d.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in d {
        counts[b as usize] += 1;
    }
    let n = d.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

// ---------------------------------------------------------------- file type

fn detect_type(d: &[u8], name: &str) -> (String, &'static str) {
    let starts = |m: &[u8]| d.starts_with(m);
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if starts(b"MZ") {
        return ("MZ executable".into(), "application/vnd.microsoft.portable-executable");
    }
    if starts(b"\x7fELF") {
        return ("ELF executable".into(), "application/x-elf");
    }
    if starts(&[0xCF, 0xFA, 0xED, 0xFE]) || starts(&[0xCE, 0xFA, 0xED, 0xFE]) || starts(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return ("Mach-O binary".into(), "application/x-mach-binary");
    }
    if starts(b"PK\x03\x04") {
        let kind = if d.windows(19).take(4096).any(|w| w == b"AndroidManifest.xml") || ext == "apk" {
            "Android package (APK)"
        } else if d.windows(5).take(4096).any(|w| w == b"word/") {
            "Office Open XML document"
        } else if d.windows(3).take(4096).any(|w| w == b"xl/") {
            "Office Open XML spreadsheet"
        } else if ext == "jar" || d.windows(20).take(4096).any(|w| w == b"META-INF/MANIFEST.MF") {
            "Java archive (JAR)"
        } else {
            "ZIP archive"
        };
        return (kind.into(), "application/zip");
    }
    if starts(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return ("OLE2 compound document (legacy Office / MSI)".into(), "application/x-ole-storage");
    }
    if starts(b"%PDF") {
        return ("PDF document".into(), "application/pdf");
    }
    if starts(b"Rar!\x1a\x07") {
        return ("RAR archive".into(), "application/vnd.rar");
    }
    if starts(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return ("7-Zip archive".into(), "application/x-7z-compressed");
    }
    if starts(&[0x1F, 0x8B]) {
        return ("GZIP data".into(), "application/gzip");
    }
    if starts(b"MSCF") {
        return ("Microsoft Cabinet".into(), "application/vnd.ms-cab-compressed");
    }
    if starts(b"L\x00\x00\x00\x01\x14\x02\x00") {
        return ("Windows shortcut (LNK)".into(), "application/x-ms-shortcut");
    }
    if starts(b"{\\rtf") {
        return ("RTF document".into(), "application/rtf");
    }
    if starts(b"#!") {
        return ("Script (shebang)".into(), "text/x-script");
    }
    let script = match ext.as_str() {
        "ps1" | "psm1" => Some("PowerShell script"),
        "bat" | "cmd" => Some("Batch script"),
        "vbs" | "vbe" => Some("VBScript"),
        "js" | "jse" => Some("JavaScript"),
        "hta" => Some("HTML application (HTA)"),
        "py" => Some("Python script"),
        _ => None,
    };
    if let Some(s) = script {
        return (s.into(), "text/plain");
    }
    let sample = &d[..d.len().min(4096)];
    if !sample.is_empty() && sample.iter().all(|&c| c == b'\n' || c == b'\r' || c == b'\t' || (0x20..0x7f).contains(&c) || c >= 0x80) {
        return ("Text".into(), "text/plain");
    }
    ("Data".into(), "application/octet-stream")
}

// ---------------------------------------------------------------- PE

struct Sec {
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
}

fn rva_to_off(secs: &[Sec], rva: u32, headers_size: u32) -> Option<usize> {
    if rva < headers_size {
        return Some(rva as usize);
    }
    for s in secs {
        let span = s.vsize.max(s.raw_size);
        if rva >= s.va && rva < s.va.saturating_add(span) {
            let delta = rva - s.va;
            if delta >= s.raw_size {
                return None; // virtual-only (BSS)
            }
            return Some(s.raw_ptr as usize + delta as usize);
        }
    }
    None
}

fn machine_name(m: u16) -> String {
    match m {
        0x014c => "x86 (32-bit)".into(),
        0x8664 => "x64 (AMD64)".into(),
        0xaa64 => "ARM64".into(),
        0x01c4 => "ARMv7 (Thumb-2)".into(),
        0x0200 => "IA-64".into(),
        other => format!("0x{other:04X}"),
    }
}

fn subsystem_name(s: u16) -> String {
    match s {
        1 => "Native (driver)".into(),
        2 => "Windows GUI".into(),
        3 => "Windows console".into(),
        9 => "Windows CE GUI".into(),
        10 => "EFI application".into(),
        11 => "EFI boot service driver".into(),
        12 => "EFI runtime driver".into(),
        14 => "Xbox".into(),
        16 => "Windows boot application".into(),
        other => format!("Subsystem {other}"),
    }
}

fn parse_pe(d: &[u8], ind: &mut Vec<Indicator>) -> Option<PeInfo> {
    if rd_u16(d, 0)? != 0x5A4D {
        return None;
    }
    let e_lfanew = rd_u32(d, 0x3C)? as usize;
    if rd_u32(d, e_lfanew)? != 0x0000_4550 {
        return None;
    }
    let fh = e_lfanew + 4;
    let machine = rd_u16(d, fh)?;
    let nsec = rd_u16(d, fh + 2)? as usize;
    let timestamp = rd_u32(d, fh + 4)?;
    let opt_size = rd_u16(d, fh + 16)? as usize;
    let chars = rd_u16(d, fh + 18)?;
    let oh = fh + 20;
    let magic = rd_u16(d, oh)?;
    let is64 = match magic {
        0x20b => true,
        0x10b => false,
        _ => return None,
    };
    let entry = rd_u32(d, oh + 16)?;
    let (image_base, dd_off, ndd_off) = if is64 {
        (rd_u64(d, oh + 24)?, oh + 112, oh + 108)
    } else {
        (rd_u32(d, oh + 28)? as u64, oh + 96, oh + 92)
    };
    let sect_align = rd_u32(d, oh + 32).unwrap_or(0);
    let file_align = rd_u32(d, oh + 36).unwrap_or(0);
    let size_image = rd_u32(d, oh + 56).unwrap_or(0);
    let size_headers = rd_u32(d, oh + 60).unwrap_or(0);
    let subsystem = rd_u16(d, oh + 68).unwrap_or(0);
    let dllch = rd_u16(d, oh + 70).unwrap_or(0);
    let ndd = (rd_u32(d, ndd_off).unwrap_or(16) as usize).min(16);
    let data_dir = |i: usize| -> (u32, u32) {
        if i >= ndd {
            return (0, 0);
        }
        (rd_u32(d, dd_off + i * 8).unwrap_or(0), rd_u32(d, dd_off + i * 8 + 4).unwrap_or(0))
    };

    // ---- sections
    let sec_start = oh + opt_size;
    let mut secs = Vec::new();
    let mut sections = Vec::new();
    let mut end_of_raw: u64 = size_headers as u64;
    for i in 0..nsec.min(MAX_SECTIONS) {
        let o = sec_start + i * 40;
        let Some(raw_name) = d.get(o..o + 8) else { break };
        let name_end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
        let mut name: String = String::from_utf8_lossy(&raw_name[..name_end]).trim().to_string();
        if name.is_empty() {
            name = format!("sec_{i}");
        }
        let vsize = rd_u32(d, o + 8).unwrap_or(0);
        let va = rd_u32(d, o + 12).unwrap_or(0);
        let raw_size = rd_u32(d, o + 16).unwrap_or(0);
        let raw_ptr = rd_u32(d, o + 20).unwrap_or(0);
        let sch = rd_u32(d, o + 36).unwrap_or(0);
        let start = raw_ptr as usize;
        let end = (start + raw_size as usize).min(d.len());
        let ent = if start < end { round2(shannon(&d[start..end])) } else { 0.0 };
        if raw_size > 0 {
            end_of_raw = end_of_raw.max(raw_ptr as u64 + raw_size as u64);
        }
        let x = sch & 0x2000_0000 != 0;
        let r = sch & 0x4000_0000 != 0;
        let w = sch & 0x8000_0000 != 0;
        let mut flags = Vec::new();
        if sch & 0x20 != 0 { flags.push("code"); }
        if sch & 0x40 != 0 { flags.push("initialized_data"); }
        if sch & 0x80 != 0 { flags.push("uninitialized_data"); }
        if sch & 0x0200_0000 != 0 { flags.push("discardable"); }
        if sch & 0x1000_0000 != 0 { flags.push("shared"); }
        let class = if ent >= 7.2 { "packed" } else if ent >= 6.5 { "dense" } else { "normal" };

        if x && w {
            ind.push(Indicator { severity: "medium", id: "wx_section", detail: format!("Section {name} is writable and executable") });
        }
        if ent >= 7.2 && raw_size >= 1024 {
            ind.push(Indicator { severity: "medium", id: "packed_section", detail: format!("Section {name} entropy {ent:.2} (packed or encrypted)") });
        }
        if raw_size == 0 && vsize > 0x10000 && x {
            ind.push(Indicator { severity: "low", id: "virtual_exec_section", detail: format!("Executable section {name} has no raw data ({vsize} bytes in memory): typical of unpacking stubs") });
        }
        let lname = name.to_ascii_lowercase();
        let packer = [
            ("upx", "UPX"), (".aspack", "ASPack"), (".adata", "ASPack"), (".themida", "Themida"), (".winlice", "WinLicense"),
            (".vmp", "VMProtect"), (".enigma", "Enigma Protector"), (".mpress", "MPRESS"), (".petite", "Petite"),
            (".nsp", "NsPack"), ("pec", "PECompact"), (".boom", "The Boomerang"), (".perplex", "Perplex"),
        ]
        .iter()
        .find(|(p, _)| lname.starts_with(p))
        .map(|(_, n)| *n);
        if let Some(p) = packer {
            ind.push(Indicator { severity: "low", id: "packer_section", detail: format!("Section name {name} suggests {p}") });
        }

        secs.push(Sec { va, vsize, raw_ptr, raw_size });
        sections.push(SectionInfo {
            name,
            virtual_address: format!("0x{va:08X}"),
            virtual_size: vsize,
            raw_offset: format!("0x{raw_ptr:08X}"),
            raw_size,
            entropy: ent,
            class,
            perms: format!("{}{}{}", if r { 'R' } else { '-' }, if w { 'W' } else { '-' }, if x { 'X' } else { '-' }),
            flags,
        });
    }

    // entry section
    let entry_section = secs.iter().position(|s| entry >= s.va && entry < s.va.saturating_add(s.vsize.max(s.raw_size))).map(|i| sections[i].name.clone());
    if entry != 0 {
        match &entry_section {
            None => ind.push(Indicator { severity: "medium", id: "entry_outside_sections", detail: format!("Entry point 0x{entry:08X} is outside every section") }),
            Some(n) => {
                let i = sections.iter().position(|s| &s.name == n).unwrap_or(0);
                if sections[i].perms.contains('W') {
                    ind.push(Indicator { severity: "medium", id: "entry_in_writable", detail: format!("Entry point is in writable section {n}") });
                } else if i == sections.len() - 1 && sections.len() > 1 {
                    ind.push(Indicator { severity: "low", id: "entry_in_last_section", detail: format!("Entry point is in the last section ({n})") });
                }
            }
        }
    }

    // ---- imports
    let (imp_rva, _imp_size) = data_dir(1);
    let mut imports = Vec::new();
    let mut import_count = 0usize;
    if imp_rva != 0 {
        if let Some(mut desc) = rva_to_off(&secs, imp_rva, size_headers) {
            for _ in 0..MAX_IMPORT_DLLS {
                let oft = rd_u32(d, desc).unwrap_or(0);
                let name_rva = rd_u32(d, desc + 12).unwrap_or(0);
                let ft = rd_u32(d, desc + 16).unwrap_or(0);
                if name_rva == 0 && ft == 0 {
                    break;
                }
                desc += 20;
                let Some(dll) = rva_to_off(&secs, name_rva, size_headers).and_then(|o| rd_cstr(d, o, 256)) else { continue };
                let thunk_rva = if oft != 0 { oft } else { ft };
                let mut funcs = Vec::new();
                if let Some(mut t) = rva_to_off(&secs, thunk_rva, size_headers) {
                    while import_count < MAX_IMPORT_FUNCS {
                        let (val, ord_flag) = if is64 {
                            let v = rd_u64(d, t).unwrap_or(0);
                            t += 8;
                            (v, v & (1u64 << 63) != 0)
                        } else {
                            let v = rd_u32(d, t).unwrap_or(0) as u64;
                            t += 4;
                            (v, v & 0x8000_0000 != 0)
                        };
                        if val == 0 {
                            break;
                        }
                        let f = if ord_flag {
                            format!("ord{}", val & 0xFFFF)
                        } else {
                            match rva_to_off(&secs, (val & 0x7FFF_FFFF) as u32, size_headers).and_then(|o| rd_cstr(d, o + 2, 512)) {
                                Some(n) => n,
                                None => break,
                            }
                        };
                        funcs.push(f);
                        import_count += 1;
                    }
                }
                imports.push(ImportDll { dll, functions: funcs });
            }
        }
    }

    // ---- exports
    let (exp_rva, exp_size) = data_dir(0);
    let mut exports = Vec::new();
    let mut export_name = None;
    if exp_rva != 0 {
        if let Some(eo) = rva_to_off(&secs, exp_rva, size_headers) {
            export_name = rd_u32(d, eo + 12).and_then(|r| rva_to_off(&secs, r, size_headers)).and_then(|o| rd_cstr(d, o, 256));
            let base = rd_u32(d, eo + 16).unwrap_or(1);
            let nfuncs = (rd_u32(d, eo + 20).unwrap_or(0) as usize).min(MAX_EXPORTS);
            let nnames = (rd_u32(d, eo + 24).unwrap_or(0) as usize).min(MAX_EXPORTS);
            let funcs = rd_u32(d, eo + 28).and_then(|r| rva_to_off(&secs, r, size_headers));
            let names = rd_u32(d, eo + 32).and_then(|r| rva_to_off(&secs, r, size_headers));
            let ords = rd_u32(d, eo + 36).and_then(|r| rva_to_off(&secs, r, size_headers));
            let mut named: BTreeMap<usize, String> = BTreeMap::new();
            if let (Some(n), Some(o)) = (names, ords) {
                for i in 0..nnames {
                    let Some(name) = rd_u32(d, n + i * 4).and_then(|r| rva_to_off(&secs, r, size_headers)).and_then(|off| rd_cstr(d, off, 512)) else { continue };
                    if let Some(idx) = rd_u16(d, o + i * 2) {
                        named.insert(idx as usize, name);
                    }
                }
            }
            if let Some(f) = funcs {
                for i in 0..nfuncs {
                    let rva = rd_u32(d, f + i * 4).unwrap_or(0);
                    if rva == 0 {
                        continue;
                    }
                    let forwarder = if rva >= exp_rva && rva < exp_rva.saturating_add(exp_size) {
                        rva_to_off(&secs, rva, size_headers).and_then(|o| rd_cstr(d, o, 256))
                    } else {
                        None
                    };
                    exports.push(ExportInfo {
                        ordinal: base.saturating_add(i as u32),
                        name: named.remove(&i).unwrap_or_default(),
                        rva: format!("0x{rva:08X}"),
                        forwarder,
                    });
                }
            }
        }
    }

    // ---- overlay, signature, .NET
    let (sec_rva, sec_size) = data_dir(4); // security dir: a file offset, not an RVA
    let has_signature = sec_rva != 0 && sec_size != 0;
    let mut overlay_offset = end_of_raw.min(d.len() as u64);
    if has_signature && sec_rva as u64 == overlay_offset {
        overlay_offset = (sec_rva as u64 + sec_size as u64).min(d.len() as u64);
    }
    let overlay_size = d.len() as u64 - overlay_offset;
    let overlay_entropy = if overlay_size > 0 { Some(round2(shannon(&d[overlay_offset as usize..]))) } else { None };
    if overlay_size > 1024 {
        let sev = if overlay_entropy.unwrap_or(0.0) >= 7.2 { "medium" } else { "low" };
        ind.push(Indicator { severity: sev, id: "overlay", detail: format!("{overlay_size} bytes appended after the last section (entropy {:.2})", overlay_entropy.unwrap_or(0.0)) });
    }
    let is_dotnet = data_dir(14).0 != 0;

    // ---- header-level indicators
    let now = chrono::Utc::now().timestamp();
    if timestamp == 0 {
        ind.push(Indicator { severity: "info", id: "zero_timestamp", detail: "Compile timestamp is zero (stripped or reproducible build)".into() });
    } else if (timestamp as i64) > now + 86400 {
        ind.push(Indicator { severity: "low", id: "future_timestamp", detail: "Compile timestamp is in the future (forged)".into() });
    }
    if !is_dotnet && imports.is_empty() && !sections.is_empty() {
        ind.push(Indicator { severity: "medium", id: "no_imports", detail: "No import table: imports are resolved at runtime (packer or shellcode loader)".into() });
    } else if !is_dotnet && import_count > 0 && import_count < 10 {
        ind.push(Indicator { severity: "low", id: "few_imports", detail: format!("Only {import_count} imported functions") });
    }
    if dllch & 0x0040 == 0 {
        ind.push(Indicator { severity: "info", id: "no_aslr", detail: "ASLR (DYNAMIC_BASE) disabled".into() });
    }

    let is_dll = chars & 0x2000 != 0;
    let mut characteristics = Vec::new();
    if chars & 0x0002 != 0 { characteristics.push("executable_image"); }
    if is_dll { characteristics.push("dll"); }
    if chars & 0x0020 != 0 { characteristics.push("large_address_aware"); }
    if chars & 0x0100 != 0 { characteristics.push("32bit_machine"); }
    if chars & 0x1000 != 0 { characteristics.push("system"); }
    if chars & 0x0001 != 0 { characteristics.push("relocs_stripped"); }
    let mut dll_characteristics = Vec::new();
    if dllch & 0x0020 != 0 { dll_characteristics.push("high_entropy_va"); }
    if dllch & 0x0040 != 0 { dll_characteristics.push("aslr"); }
    if dllch & 0x0080 != 0 { dll_characteristics.push("force_integrity"); }
    if dllch & 0x0100 != 0 { dll_characteristics.push("dep_nx"); }
    if dllch & 0x0400 != 0 { dll_characteristics.push("no_seh"); }
    if dllch & 0x4000 != 0 { dll_characteristics.push("control_flow_guard"); }
    if dllch & 0x8000 != 0 { dll_characteristics.push("terminal_server_aware"); }

    let sub = subsystem_name(subsystem);
    let kind = format!(
        "{} {} - {}",
        if is64 { "PE32+" } else { "PE32" },
        if subsystem == 1 { "driver" } else if is_dll { "DLL" } else { "executable" },
        if is_dotnet { format!("{sub}, .NET") } else { sub.clone() }
    );

    Some(PeInfo {
        kind,
        machine: machine_name(machine),
        machine_raw: machine,
        is_64bit: is64,
        is_dll,
        is_dotnet,
        subsystem: sub,
        timestamp,
        timestamp_utc: if timestamp != 0 {
            chrono::DateTime::from_timestamp(timestamp as i64, 0).map(|t| t.to_rfc3339())
        } else {
            None
        },
        entry_point: format!("0x{entry:08X}"),
        entry_section,
        image_base: if is64 { format!("0x{image_base:016X}") } else { format!("0x{image_base:08X}") },
        section_alignment: sect_align,
        file_alignment: file_align,
        size_of_image: size_image,
        size_of_headers: size_headers,
        characteristics,
        dll_characteristics,
        sections,
        import_count,
        imports,
        export_name,
        exports,
        overlay_offset,
        overlay_size,
        overlay_entropy,
        has_signature,
    })
}

/// Mandiant/pefile imphash: md5 of "dll.func" pairs, lowercase, extension stripped.
fn imphash(imports: &[ImportDll]) -> Option<String> {
    let mut parts = Vec::new();
    for imp in imports {
        let lower = imp.dll.to_ascii_lowercase();
        let base = match lower.rsplit_once('.') {
            Some((b, e)) if ["dll", "ocx", "sys"].contains(&e) => b.to_string(),
            _ => lower.clone(),
        };
        for f in &imp.functions {
            let func = match f.strip_prefix("ord") {
                Some(n) if n.chars().all(|c| c.is_ascii_digit()) => {
                    let ord: u32 = n.parse().unwrap_or(0);
                    ordinal_name(&base, ord).map(str::to_string).unwrap_or_else(|| format!("ord{ord}"))
                }
                _ => f.to_ascii_lowercase(),
            };
            parts.push(format!("{base}.{}", func.to_ascii_lowercase()));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(hex::encode(md5(parts.join(",").as_bytes())))
}

/// Ordinal lookups pefile uses for imphash (the common ones).
fn ordinal_name(dll: &str, ord: u32) -> Option<&'static str> {
    match (dll, ord) {
        ("ws2_32" | "wsock32", 1) => Some("accept"),
        ("ws2_32" | "wsock32", 2) => Some("bind"),
        ("ws2_32" | "wsock32", 3) => Some("closesocket"),
        ("ws2_32" | "wsock32", 4) => Some("connect"),
        ("ws2_32" | "wsock32", 9) => Some("htons"),
        ("ws2_32" | "wsock32", 11) => Some("inet_addr"),
        ("ws2_32" | "wsock32", 13) => Some("listen"),
        ("ws2_32" | "wsock32", 16) => Some("recv"),
        ("ws2_32" | "wsock32", 19) => Some("send"),
        ("ws2_32" | "wsock32", 23) => Some("socket"),
        ("ws2_32" | "wsock32", 52) => Some("gethostbyname"),
        ("ws2_32" | "wsock32", 115) => Some("wsastartup"),
        ("ws2_32" | "wsock32", 116) => Some("wsacleanup"),
        ("oleaut32", 2) => Some("sysallocstring"),
        ("oleaut32", 6) => Some("sysfreestring"),
        ("oleaut32", 7) => Some("sysstringlen"),
        _ => None,
    }
}

// ---------------------------------------------------------------- API indicators

fn api_indicators(imports: &[ImportDll], ind: &mut Vec<Indicator>) {
    let has = |names: &[&str]| -> Vec<String> {
        let mut out = Vec::new();
        for imp in imports {
            for f in &imp.functions {
                let base = f.trim_end_matches(['A', 'W']);
                if names.iter().any(|n| f == n || base == *n) && !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
        out
    };
    let groups: [(&str, &str, &str, &[&str]); 7] = [
        ("medium", "api_injection", "Process injection APIs", &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory", "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "RtlCreateUserThread"]),
        ("low", "api_keylogging", "Keyboard capture APIs", &["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "RegisterRawInputDevices"]),
        ("low", "api_anti_debug", "Anti-debugging APIs", &["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"]),
        ("low", "api_privilege", "Token / privilege APIs", &["AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken", "ImpersonateLoggedOnUser"]),
        ("low", "api_crypto", "Encryption APIs", &["CryptEncrypt", "CryptGenKey", "CryptAcquireContext", "BCryptEncrypt", "CryptDeriveKey"]),
        ("low", "api_network", "Network / download APIs", &["InternetOpenUrl", "InternetReadFile", "URLDownloadToFile", "HttpSendRequest", "WinHttpSendRequest", "WSAStartup"]),
        ("low", "api_persistence", "Persistence APIs (registry / services)", &["RegSetValueEx", "CreateService", "StartService", "ChangeServiceConfig"]),
    ];
    for (sev, id, label, names) in groups {
        let found = has(names);
        if !found.is_empty() {
            ind.push(Indicator { severity: sev, id, detail: format!("{label}: {}", found.join(", ")) });
        }
    }
    let shadow = has(&["CreateProcess", "ShellExecute", "WinExec"]);
    let vss = has(&["DeleteFile", "MoveFileEx"]);
    if !shadow.is_empty() && !vss.is_empty() && !has(&["CryptEncrypt", "BCryptEncrypt"]).is_empty() {
        ind.push(Indicator { severity: "medium", id: "api_ransom_combo", detail: "Process launch + file delete/rename + encryption APIs together".into() });
    }
}

// ---------------------------------------------------------------- strings

fn push_unique(v: &mut Vec<String>, s: &str) {
    if v.len() < MAX_STRINGS_PER_KIND && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

fn classify(s: &str, out: &mut StringsInfo) {
    let low = s.to_ascii_lowercase();
    for scheme in ["http://", "https://", "ftp://", "ws://", "wss://"] {
        if let Some(p) = low.find(scheme) {
            let url: String = s[p..].chars().take_while(|c| !c.is_whitespace() && !"\"'<>`".contains(*c)).take(300).collect();
            if url.len() > scheme.len() + 3 {
                push_unique(&mut out.urls, &url);
            }
        }
    }
    if low.contains("hkey_") || low.contains("software\\") || low.contains("system\\currentcontrolset") || low.contains("\\run") && low.contains("currentversion") {
        push_unique(&mut out.registry, s);
    }
    if (low.contains(":\\") || low.contains("%appdata%") || low.contains("%temp%") || low.contains("%programdata%") || low.starts_with("\\\\"))
        || [".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".scr", ".lnk"].iter().any(|e| low.ends_with(e))
    {
        push_unique(&mut out.paths, s);
    }
    if ["powershell", "cmd.exe /c", "cmd /c", "vssadmin", "wmic ", "bcdedit", "schtasks", "reg add", "certutil", "rundll32", "mshta", "bitsadmin", "-encodedcommand", "frombase64string", "invoke-expression", "iex("]
        .iter()
        .any(|k| low.contains(k))
    {
        push_unique(&mut out.commands, s);
    }
    // IPv4 a.b.c.d
    for tok in s.split(|c: char| !(c.is_ascii_digit() || c == '.' || c == ':')) {
        let host = tok.split(':').next().unwrap_or("");
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u16>().is_ok_and(|n| n <= 255)) {
            let first: u16 = parts[0].parse().unwrap_or(0);
            if first != 0 && !(host.starts_with("1.0.") || host.starts_with("2.0.") || host.ends_with(".0.0")) {
                push_unique(&mut out.ips, tok);
            }
        }
    }
    // BTC / ETH / XMR wallets (shape only)
    for tok in s.split(|c: char| !c.is_ascii_alphanumeric()) {
        let is_btc = (tok.starts_with("bc1") && (39..=62).contains(&tok.len()) && tok.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
            || ((tok.starts_with('1') || tok.starts_with('3')) && (26..=35).contains(&tok.len()) && tok.chars().all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c)) && tok.chars().any(|c| c.is_ascii_uppercase()) && tok.chars().any(|c| c.is_ascii_digit()));
        let is_eth = tok.starts_with("0x") && tok.len() == 42 && tok[2..].chars().all(|c| c.is_ascii_hexdigit());
        let is_xmr = tok.starts_with('4') && tok.len() == 95 && tok.chars().all(|c| c.is_ascii_alphanumeric());
        if is_btc || is_eth || is_xmr {
            push_unique(&mut out.crypto_wallets, tok);
        }
    }
}

pub fn extract_strings(data: &[u8]) -> StringsInfo {
    let d = &data[..data.len().min(MAX_STRINGS_SCAN)];
    let mut out = StringsInfo::default();
    let handle = |s: &str, out: &mut StringsInfo| {
        out.total += 1;
        if out.sample.len() < 200 && s.len() >= 6 {
            out.sample.push(s.chars().take(200).collect());
        }
        classify(s, out);
    };
    // ASCII
    let mut start = None;
    for (i, &b) in d.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b) || b == b'\t';
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= 5 {
                    if let Ok(t) = std::str::from_utf8(&d[s..i.min(s + 2048)]) {
                        handle(t, &mut out);
                    }
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if d.len() - s >= 5 {
            if let Ok(t) = std::str::from_utf8(&d[s..d.len().min(s + 2048)]) {
                handle(t, &mut out);
            }
        }
    }
    // UTF-16LE (printable ASCII range), both alignments
    for align in 0..2 {
        let mut cur = String::new();
        let mut i = align;
        while i + 1 < d.len() {
            let (lo, hi) = (d[i], d[i + 1]);
            if hi == 0 && ((0x20..0x7f).contains(&lo) || lo == b'\t') {
                if cur.len() < 2048 {
                    cur.push(lo as char);
                }
            } else {
                if cur.len() >= 5 {
                    handle(&cur, &mut out);
                }
                cur.clear();
            }
            i += 2;
        }
        if cur.len() >= 5 {
            handle(&cur, &mut out);
        }
    }
    out
}

fn string_indicators(s: &StringsInfo, ind: &mut Vec<Indicator>) {
    if !s.crypto_wallets.is_empty() {
        ind.push(Indicator { severity: "medium", id: "crypto_wallet", detail: format!("{} cryptocurrency address(es) embedded", s.crypto_wallets.len()) });
    }
    let cmd_low: Vec<String> = s.commands.iter().map(|c| c.to_ascii_lowercase()).collect();
    if cmd_low.iter().any(|c| c.contains("vssadmin") && c.contains("delete") || c.contains("shadowcopy delete") || c.contains("bcdedit") && c.contains("recoveryenabled")) {
        ind.push(Indicator { severity: "high", id: "shadow_copy_delete", detail: "Commands to delete shadow copies / disable recovery".into() });
    }
    if cmd_low.iter().any(|c| c.contains("-encodedcommand") || c.contains("frombase64string")) {
        ind.push(Indicator { severity: "medium", id: "encoded_powershell", detail: "Encoded or base64-decoded PowerShell".into() });
    }
    if s.registry.iter().any(|r| r.to_ascii_lowercase().contains("currentversion\\run")) {
        ind.push(Indicator { severity: "low", id: "run_key", detail: "References a Run key (autostart)".into() });
    }
}

// ---------------------------------------------------------------- hashes (no extra crates)

fn crc_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    })
}

/// One CRC-32 step on the raw (non-inverted) register; also used by ZipCrypto.
pub fn crc32_step(crc: u32, b: u8) -> u32 {
    crc_table()[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8)
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = crc32_step(c, b);
    }
    !c
}

fn md_pad(data: &[u8], big_endian_len: bool) -> Vec<u8> {
    let mut m = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&if big_endian_len { bit_len.to_be_bytes() } else { bit_len.to_le_bytes() });
    m
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let msg = md_pad(data, false);
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let msg = md_pad(data, true);
    let mut w = [0u32; 80];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5A827999),
                1 => (b ^ c ^ d, 0x6ED9EBA1),
                2 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (hv, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *hv = hv.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
