use crate::models::FileTypeInfo;
use crate::utils::entropy::byte_entropy;
use anyhow::{Context, Result};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::io::Cursor;
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatValidation {
    NotDetected,
    Valid,
    Broken,
}

impl Default for FormatValidation {
    fn default() -> Self {
        Self::NotDetected
    }
}

#[derive(Debug, Clone, Default)]
struct BinaryFormatValidation {
    pe: FormatValidation,
    elf: FormatValidation,
    macho: FormatValidation,
    apk: FormatValidation,
    pe_type: Option<String>,
    elf_type: Option<String>,
    broken_type: Option<String>,
    /// A valid PE without code (see `pe_has_code`).
    pe_no_code: bool,
}

pub fn classify_path(path: &Path) -> Result<FileTypeInfo> {
    let data = std::fs::read(path).with_context(|| {
        format!(
            "failed to read {} for file type classification",
            path.display()
        )
    })?;
    Ok(classify_bytes(path, &data))
}

pub fn classify_bytes(path: &Path, data: &[u8]) -> FileTypeInfo {
    let mut info = FileTypeInfo::default();
    info.extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    let validation = inspect_binary_formats(data);
    apply_binary_validation(&mut info, validation);
    apply_archive_markers(&mut info, data);
    apply_known_formats(&mut info, data);
    apply_language_and_text_markers(&mut info, path, data);
    finalize_file_type(&mut info);
    info
}

pub fn normalize_file_type_alias(value: &str) -> String {
    let mut out = String::new();
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

pub fn known_file_type_aliases() -> &'static [&'static str] {
    &[
        "pe",
        "pe32",
        "pe64",
        "exe",
        "dll",
        "sys",
        "elf",
        "elf32",
        "elf64",
        "macho",
        "mach_o",
        "apk",
        "android",
        "zip",
        "archive",
        "asar",
        "7z",
        "rar",
        "gzip",
        "gz",
        "tar",
        "jar",
        "java",
        "dex",
        "java_class",
        "class",
        "text",
        "plain",
        "plain_text",
        "txt",
        "script",
        "powershell",
        "ps1",
        "batch",
        "bat",
        "cmd",
        "javascript",
        "js",
        "vbs",
        "python",
        "py",
        "shell",
        "pdf",
        "office",
        "openxml",
        "ole",
        "compound",
        "microsoft_compound",
        "mscab",
        "cab",
        "installshield_cab",
        "ico",
        "cur",
        "evtx",
        "evt",
        "registry_hive",
        "der",
        "binary",
        "unknown",
        "broken",
        "broken_executable",
        "broken_apk",
        "pe_no_code",
    ]
}

pub fn is_known_file_type_alias(value: &str) -> bool {
    let normalized = normalize_file_type_alias(value);
    known_file_type_aliases()
        .iter()
        .any(|known| normalize_file_type_alias(known) == normalized)
}

fn apply_binary_validation(info: &mut FileTypeInfo, validation: BinaryFormatValidation) {
    match validation.pe {
        FormatValidation::Valid => {
            info.is_pe = true;
            push_tag(info, "pe");
            if validation.pe_no_code {
                // A tag only: still a valid pe32 / pe64, not a broken one.
                push_tag(info, "pe_no_code");
            }
            match validation.pe_type.as_deref() {
                Some("PE64") => {
                    info.is_pe64 = true;
                    set_primary_if_unknown(info, "pe64");
                    push_tag(info, "pe64");
                }
                Some("PE32") => {
                    info.is_pe32 = true;
                    set_primary_if_unknown(info, "pe32");
                    push_tag(info, "pe32");
                }
                _ => set_primary_if_unknown(info, "pe"),
            }
        }
        FormatValidation::Broken => {
            info.is_pe = true;
            info.is_broken_executable = true;
            info.broken_executable_type = Some("PE".to_string());
            set_primary_if_unknown(info, "broken_pe");
            push_tag(info, "pe");
            push_tag(info, "broken");
            push_tag(info, "broken_executable");
            match validation.pe_type.as_deref() {
                Some("PE64") => {
                    info.is_pe64 = true;
                    push_tag(info, "pe64");
                }
                Some("PE32") => {
                    info.is_pe32 = true;
                    push_tag(info, "pe32");
                }
                _ => {}
            }
        }
        FormatValidation::NotDetected => {}
    }

    match validation.elf {
        FormatValidation::Valid => {
            info.is_elf = true;
            push_tag(info, "elf");
            match validation.elf_type.as_deref() {
                Some("ELF64") => {
                    info.is_elf64 = true;
                    set_primary_if_unknown(info, "elf64");
                    push_tag(info, "elf64");
                }
                Some("ELF32") => {
                    info.is_elf32 = true;
                    set_primary_if_unknown(info, "elf32");
                    push_tag(info, "elf32");
                }
                _ => set_primary_if_unknown(info, "elf"),
            }
        }
        FormatValidation::Broken => {
            info.is_elf = true;
            info.is_broken_executable = true;
            info.broken_executable_type = Some("ELF".to_string());
            set_primary_if_unknown(info, "broken_elf");
            push_tag(info, "elf");
            push_tag(info, "broken");
            push_tag(info, "broken_executable");
            match validation.elf_type.as_deref() {
                Some("ELF64") => {
                    info.is_elf64 = true;
                    push_tag(info, "elf64");
                }
                Some("ELF32") => {
                    info.is_elf32 = true;
                    push_tag(info, "elf32");
                }
                _ => {}
            }
        }
        FormatValidation::NotDetected => {}
    }

    match validation.macho {
        FormatValidation::Valid => {
            info.is_macho = true;
            set_primary_if_unknown(info, "macho");
            push_tag(info, "macho");
            push_tag(info, "mach_o");
        }
        FormatValidation::Broken => {
            info.is_macho = true;
            info.is_broken_executable = true;
            info.broken_executable_type = Some("Mach-O".to_string());
            set_primary_if_unknown(info, "broken_macho");
            push_tag(info, "macho");
            push_tag(info, "mach_o");
            push_tag(info, "broken");
            push_tag(info, "broken_executable");
        }
        FormatValidation::NotDetected => {}
    }

    match validation.apk {
        FormatValidation::Valid => {
            info.is_apk = true;
            info.is_zip = true;
            info.is_archive = true;
            set_primary_if_unknown(info, "apk");
            push_tag(info, "apk");
            push_tag(info, "android");
            push_tag(info, "zip");
            push_tag(info, "archive");
        }
        FormatValidation::Broken => {
            info.is_apk = true;
            info.is_broken_apk = true;
            set_primary_if_unknown(info, "broken_apk");
            push_tag(info, "apk");
            push_tag(info, "android");
            push_tag(info, "broken");
            push_tag(info, "broken_apk");
        }
        FormatValidation::NotDetected => {}
    }

    if info.broken_executable_type.is_none() {
        info.broken_executable_type = validation.broken_type;
    }
}

fn apply_archive_markers(info: &mut FileTypeInfo, data: &[u8]) {
    if info.is_pe || info.is_elf || info.is_macho {
        return;
    }
    if looks_like_zip(data) {
        info.is_zip = true;
        info.is_archive = true;
        set_primary_if_unknown(info, "zip");
        push_tag(info, "zip");
        push_tag(info, "archive");
        inspect_zip_entries(data, info);
    }

    if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        info.is_7z = true;
        info.is_archive = true;
        set_primary_if_unknown(info, "7z");
        push_tag(info, "7z");
        push_tag(info, "archive");
    }

    if data.starts_with(b"Rar!\x1A\x07\x00") || data.starts_with(b"Rar!\x1A\x07\x01\x00") {
        info.is_rar = true;
        info.is_archive = true;
        set_primary_if_unknown(info, "rar");
        push_tag(info, "rar");
        push_tag(info, "archive");
    }

    if data.starts_with(&[0x1f, 0x8b]) {
        info.is_gzip = true;
        info.is_archive = true;
        set_primary_if_unknown(info, "gzip");
        push_tag(info, "gzip");
        push_tag(info, "gz");
        push_tag(info, "archive");
    }

    if data.len() > 262
        && data
            .get(257..262)
            .map(|value| value == b"ustar")
            .unwrap_or(false)
    {
        info.is_tar = true;
        info.is_archive = true;
        set_primary_if_unknown(info, "tar");
        push_tag(info, "tar");
        push_tag(info, "archive");
    }

    if data.starts_with(b"%PDF-") {
        info.is_pdf = true;
        set_primary_if_unknown(info, "pdf");
        push_tag(info, "pdf");
    }

    if data.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        info.is_microsoft_compound = true;
        info.is_office = true;
        set_primary_if_unknown(info, "microsoft_compound");
        push_tag(info, "microsoft_compound");
        push_tag(info, "compound");
        push_tag(info, "ole");
        push_tag(info, "office");
    }

    if data.starts_with(b"dex\n") {
        info.is_dex = true;
        set_primary_if_unknown(info, "dex");
        push_tag(info, "dex");
        push_tag(info, "android");
    }

    if data.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && !info.is_macho {
        info.is_java_class = true;
        set_primary_if_unknown(info, "java_class");
        push_tag(info, "java_class");
        push_tag(info, "class");
        push_tag(info, "java");
    }
}

fn apply_language_and_text_markers(info: &mut FileTypeInfo, path: &Path, data: &[u8]) {
    if info.is_pe || info.is_elf || info.is_macho || info.is_apk {
        return;
    }
    let ext = info.extension.clone().unwrap_or_default();
    let plain_text = is_plain_text_bytes(data);
    if plain_text {
        info.is_plain_text = true;
        push_tag(info, "text");
        push_tag(info, "plain_text");
        set_primary_if_unknown(info, "text");
    }

    let first_line = data
        .split(|b| *b == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "ps1" | "psm1" | "psd1" => mark_script(info, "powershell"),
        "bat" | "cmd" => mark_script(info, "batch"),
        "vbs" | "vbe" => mark_script(info, "vbs"),
        "js" | "jse" | "mjs" | "cjs" => mark_script(info, "javascript"),
        "py" | "pyw" => mark_script(info, "python"),
        "sh" | "bash" | "zsh" | "fish" => mark_script(info, "shell"),
        "txt" | "log" | "csv" | "json" | "xml" | "yaml" | "yml" | "ini" | "cfg" | "conf" => {
            info.is_plain_text = true;
            set_primary_if_unknown(info, "text");
            push_tag(info, "text");
            push_tag(info, "plain_text");
        }
        "apk" => {
            info.is_apk = true;
            push_tag(info, "apk");
            push_tag(info, "android");
        }
        "jar" => {
            info.is_jar = true;
            info.is_zip = true;
            info.is_archive = true;
            set_primary_if_unknown(info, "jar");
            push_tag(info, "jar");
            push_tag(info, "java");
            push_tag(info, "zip");
            push_tag(info, "archive");
        }
        "asar" => {
            info.is_archive = true;
            set_primary_if_unknown(info, "asar");
            push_tag(info, "asar");
            push_tag(info, "archive");
        }
        "doc" | "xls" | "ppt" | "docx" | "xlsx" | "pptx" | "rtf" => {
            info.is_office = true;
            push_tag(info, "office");
        }
        _ => {}
    }

    if first_line.starts_with("#!") {
        if first_line.contains("powershell") || first_line.contains("pwsh") {
            mark_script(info, "powershell");
        } else if first_line.contains("python") {
            mark_script(info, "python");
        } else if first_line.contains("node") || first_line.contains("javascript") {
            mark_script(info, "javascript");
        } else if first_line.contains("sh") || first_line.contains("bash") {
            mark_script(info, "shell");
        } else {
            mark_script(info, "script");
        }
    }

    if !info.is_script && is_javascript(data) {
        mark_script(info, "javascript");
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".app.asar") || name == "app.asar" {
        info.is_archive = true;
        set_primary_if_unknown(info, "asar");
        push_tag(info, "asar");
        push_tag(info, "archive");
    }
}

/// Formats identified by their content only (magic + structure checks, never the
/// file name). CAB / InstallShield CAB are marked as archives so the extractor
/// path picks them up.
fn apply_known_formats(info: &mut FileTypeInfo, data: &[u8]) {
    if info.is_pe || info.is_elf || info.is_macho || info.primary != "unknown" {
        return;
    }
    let Some(kind) = known_format(data) else { return };
    if matches!(kind, "mscab" | "installshield_cab") {
        info.is_archive = true;
        push_tag(info, "cab");
        push_tag(info, "archive");
    }
    set_primary_if_unknown(info, kind);
    push_tag(info, kind);
}

fn le16(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u32)
}

fn le32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// ICO (type 1) / CUR (type 2): header + every directory entry must fit the
/// file. `00 00 01 00` alone also starts ETW traces, so the entries are checked.
fn icon_kind(d: &[u8]) -> Option<&'static str> {
    if d.len() < 22 || d[0] != 0 || d[1] != 0 || d[3] != 0 {
        return None;
    }
    let kind = match d[2] {
        1 => "ico",
        2 => "cur",
        _ => return None,
    };
    let count = le16(d, 4)? as usize;
    if count == 0 || count > 256 {
        return None;
    }
    let dir_end = 6 + 16 * count;
    if d.len() < dir_end {
        return None;
    }
    for i in 0..count {
        let e = 6 + 16 * i;
        if d[e + 3] != 0 {
            return None;
        }
        if kind == "ico" && (le16(d, e + 4)? > 1 || !matches!(le16(d, e + 6)?, 0 | 1 | 2 | 4 | 8 | 16 | 24 | 32)) {
            return None;
        }
        let (size, off) = (le32(d, e + 8)? as usize, le32(d, e + 12)? as usize);
        if size == 0 || off < dir_end || off.checked_add(size)? > d.len() {
            return None;
        }
    }
    Some(kind)
}

fn known_format(d: &[u8]) -> Option<&'static str> {
    let at = |o: usize, m: &[u8]| d.get(o..o + m.len()) == Some(m);
    // Microsoft Cabinet: "MSCF", reserved 0, format version 1.3.
    if at(0, b"MSCF\0\0\0\0") && d.get(24..26) == Some(&[3, 1][..]) {
        return Some("mscab");
    }
    if at(0, b"ISc(") {
        return Some("installshield_cab");
    }
    if let Some(k) = icon_kind(d) {
        return Some(k);
    }
    if at(0, b"ElfFile\0") {
        return Some("evtx");
    }
    if at(4, b"LfLe") && le32(d, 0) == Some(0x30) {
        return Some("evt");
    }
    if at(0, b"regf") && d.len() >= 4096 {
        return Some("registry_hive");
    }
    if at(0, b"mrm_pri") {
        return Some("windows_pri");
    }
    if at(0, b"XBF\0") {
        return Some("xaml_binary");
    }
    if at(0, b"PKCX") {
        return Some("appx_signature");
    }
    if at(0, b"qv4cdata") {
        return Some("qt_qmlc");
    }
    if at(0, &[0x3C, 0xB8, 0x64, 0x18, 0xCA, 0xEF, 0x9C, 0x95, 0xCD, 0x21, 0x1C, 0xBF, 0x60, 0xA1, 0xBD, 0xDD]) {
        return Some("qt_qm");
    }
    if at(0, b"qres\0\0\0") {
        return Some("qt_rcc");
    }
    if at(0, b"wOFF") {
        return Some("woff");
    }
    if at(0, b"wOF2") {
        return Some("woff2");
    }
    if at(0, b"OTTO") || at(0, b"ttcf") {
        return Some("font");
    }
    // TrueType: version 1.0, then a sane table count and a printable first tag.
    if at(0, &[0, 1, 0, 0]) && d.len() >= 6 {
        let tables = u16::from_be_bytes([d[4], d[5]]) as usize;
        if (1..=64).contains(&tables) && d.len() >= 12 + 16 * tables && d[12..16].iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
            return Some("font");
        }
    }
    if at(4, b"ftyp") && d.len() >= 12 && d[8..12].iter().all(|c| c.is_ascii_alphanumeric() || *c == b' ') {
        return Some("mp4");
    }
    // MPEG transport stream: sync byte every 188 bytes.
    if d.len() >= 377 && d[0] == 0x47 && d[188] == 0x47 && d[376] == 0x47 {
        return Some("mpeg_ts");
    }
    if at(0, b"DBPF") {
        return Some("dbpf");
    }
    // One DER-encoded ASN.1 SEQUENCE spanning exactly the file (X.509, PKCS#7, ...).
    if d.len() >= 4 && d[0] == 0x30 {
        let total = match d[1] {
            0x82 => Some(u16::from_be_bytes([d[2], d[3]]) as usize + 4),
            0x83 if d.len() >= 5 => Some(((d[2] as usize) << 16 | (d[3] as usize) << 8 | d[4] as usize) + 5),
            _ => None,
        };
        if total == Some(d.len()) {
            return Some("der");
        }
    }
    None
}

fn finalize_file_type(info: &mut FileTypeInfo) {
    info.tags.sort();
    info.tags.dedup();
    if info.primary == "unknown" && info.is_plain_text {
        info.primary = "text".to_string();
    }
    if info.primary == "unknown" && info.is_archive {
        info.primary = "archive".to_string();
    }
    info.is_binary = !info.is_plain_text;
    if info.primary == "unknown" {
        if info.is_binary {
            push_tag(info, "binary");
        }
        push_tag(info, "unknown");
    } else if info.is_binary {
        push_tag(info, "binary");
    }
    info.tags.sort();
    info.tags.dedup();
}

fn mark_script(info: &mut FileTypeInfo, script_type: &str) {
    info.is_script = true;
    info.is_plain_text = true;
    set_primary_if_unknown(info, script_type);
    push_tag(info, "script");
    push_tag(info, "text");
    push_tag(info, "plain_text");
    push_tag(info, script_type);
    match script_type {
        "powershell" => info.is_powershell = true,
        "batch" => info.is_batch = true,
        "javascript" => info.is_javascript = true,
        "vbs" => info.is_vbs = true,
        "python" => info.is_python = true,
        _ => {}
    }
}

fn inspect_binary_formats(data: &[u8]) -> BinaryFormatValidation {
    let mut validation = BinaryFormatValidation::default();
    if let Some(pe_type) = pe_file_type(data) {
        validation.pe = FormatValidation::Valid;
        validation.pe_type = Some(pe_type);
        validation.pe_no_code = pe_has_code(data) == Some(false);
    } else if has_pe_magic(data) {
        validation.pe = FormatValidation::Broken;
        validation.broken_type = Some("PE".to_string());
    } else if has_elf_magic(data) {
        validation.elf = FormatValidation::Valid;
        validation.elf_type = elf_file_type(data).or_else(|| Some("ELF".to_string()));
    } else if has_macho_magic(data) {
        if macho_header_valid(data) {
            validation.macho = FormatValidation::Valid;
        } else {
            validation.macho = FormatValidation::Broken;
            validation.broken_type = Some("Mach-O".to_string());
        }
    }

    if validation.pe == FormatValidation::NotDetected
        && validation.elf == FormatValidation::NotDetected
        && validation.macho == FormatValidation::NotDetected
    {
        validation.apk = inspect_apk_bytes(data);
    }
    validation
}

/// An APK is a ZIP with `AndroidManifest.xml` at its root and code (`*.dex` or
/// `lib/*.so`). A readable ZIP is judged by its entries only: JARs built with the
/// Android SDK carry `classes.dex`, and Android build-tool JARs (Gradle plugin, d8)
/// hold the strings `AndroidManifest.xml` / `classes.dex` in their classes, but none of
/// them has a root manifest, so they are not APKs. Only a ZIP that cannot be read
/// falls back to the raw `AndroidManifest.xml` marker (broken / tampered APK).
fn inspect_apk_bytes(data: &[u8]) -> FormatValidation {
    if !looks_like_zip(data) {
        return FormatValidation::NotDetected;
    }
    let unreadable = || {
        if contains_bytes(data, b"AndroidManifest.xml") {
            FormatValidation::Broken
        } else {
            FormatValidation::NotDetected
        }
    };

    let cursor = Cursor::new(data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return unreadable();
    };

    let mut has_android_manifest = false;
    let mut has_code = false;
    for index in 0..archive.len() {
        let Ok(file) = archive.by_index(index) else {
            return unreadable();
        };
        let lower = file.name().to_ascii_lowercase();
        if lower == "androidmanifest.xml" {
            has_android_manifest = true;
        } else if lower.ends_with(".dex") || (lower.starts_with("lib/") && lower.ends_with(".so")) {
            has_code = true;
        }
    }

    if has_android_manifest && has_code {
        FormatValidation::Valid
    } else {
        FormatValidation::NotDetected
    }
}

fn inspect_zip_entries(data: &[u8], info: &mut FileTypeInfo) {
    let cursor = Cursor::new(data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return;
    };

    let mut has_manifest = false;
    let mut has_class = false;
    let mut has_dex = false;
    let mut has_office_content_types = false;

    for index in 0..archive.len() {
        let Ok(file) = archive.by_index(index) else {
            continue;
        };
        let name = file.name();
        let lower = name.to_ascii_lowercase();
        if lower == "meta-inf/manifest.mf" {
            has_manifest = true;
        }
        if lower.ends_with(".class") {
            has_class = true;
        }
        if lower == "classes.dex" || (lower.starts_with("classes") && lower.ends_with(".dex")) {
            has_dex = true;
        }
        if lower == "[content_types].xml"
            || lower.starts_with("word/")
            || lower.starts_with("xl/")
            || lower.starts_with("ppt/")
        {
            has_office_content_types = true;
        }
    }

    if has_manifest || has_class {
        info.is_jar = true;
        set_primary_if_unknown(info, "jar");
        push_tag(info, "jar");
        push_tag(info, "java");
    }
    if has_dex {
        info.is_dex = true;
        push_tag(info, "dex");
        push_tag(info, "android");
    }
    if has_office_content_types {
        info.is_office = true;
        push_tag(info, "office");
        push_tag(info, "openxml");
    }
}

pub fn is_plain_text_bytes(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let sample_len = data.len().min(8192);
    let sample = &data[..sample_len];

    let null_ratio = sample.iter().filter(|&&b| b == 0).count() as f64 / sample_len as f64;
    if null_ratio > 0.01 {
        return false;
    }

    let control_count = sample
        .iter()
        .filter(|&&b| {
            b < 32 && b != b'\n' && b != b'\r' && b != b'\t' && b != b'\x0c' && b != b'\x08'
        })
        .count();
    let control_ratio = control_count as f64 / sample_len as f64;
    if control_ratio > 0.05 {
        return false;
    }

    byte_entropy(sample) <= 7.9
}

fn pe_file_type(data: &[u8]) -> Option<String> {
    if !has_pe_magic(data) || data.len() < 0x40 {
        return None;
    }
    let pe_offset = read_u32_le(data, 0x3c)? as usize;
    if pe_offset.checked_add(4)? > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }
    let optional_header_offset = pe_offset.checked_add(24)?;
    let optional_magic = read_u16_le(data, optional_header_offset)?;
    match optional_magic {
        0x20b => Some("PE64".to_string()),
        0x10b | 0x107 => Some("PE32".to_string()),
        _ => Some("PE".to_string()),
    }
}

/// Whether a PE has code: an entry point or at least one executable section
/// (`IMAGE_SCN_MEM_EXECUTE`). `Some(false)` for resource-only DLLs such as `.mui`
/// files: valid PEs Windows loads as data, with nothing to run. `None` when the
/// headers cannot be read that far.
fn pe_has_code(data: &[u8]) -> Option<bool> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    let pe = read_u32_le(data, 0x3c)? as usize;
    let sections = read_u16_le(data, pe.checked_add(6)?)? as usize;
    let opt_size = read_u16_le(data, pe.checked_add(20)?)? as usize;
    let opt = pe.checked_add(24)?;
    if read_u32_le(data, opt.checked_add(16)?)? != 0 {
        return Some(true);
    }
    let table = opt.checked_add(opt_size)?;
    for i in 0..sections.min(96) {
        let flags = read_u32_le(data, table.checked_add(i * 40 + 36)?)?;
        if flags & IMAGE_SCN_MEM_EXECUTE != 0 {
            return Some(true);
        }
    }
    Some(false)
}

fn elf_file_type(data: &[u8]) -> Option<String> {
    if !has_elf_magic(data) || data.len() < 5 {
        return None;
    }
    match data[4] {
        1 => Some("ELF32".to_string()),
        2 => Some("ELF64".to_string()),
        _ => Some("ELF".to_string()),
    }
}

fn set_primary_if_unknown(info: &mut FileTypeInfo, primary: &str) {
    if info.primary == "unknown"
        || info.primary == "text"
        || info.primary == "zip"
        || info.primary == "archive"
    {
        info.primary = primary.to_string();
    }
}

fn push_tag(info: &mut FileTypeInfo, tag: &str) {
    let normalized = normalize_file_type_alias(tag);
    if !normalized.is_empty() && !info.tags.iter().any(|existing| existing == &normalized) {
        info.tags.push(normalized);
    }
}

fn has_pe_magic(data: &[u8]) -> bool {
    data.len() >= 2 && &data[0..2] == b"MZ"
}

fn has_elf_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"\x7fELF"
}

fn has_macho_magic(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    matches!(
        read_u32_be(data, 0).unwrap_or(0),
        0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe
    )
}

/// A thin Mach-O header whose load commands fit in the file: CPU type set,
/// at least one load command, and `sizeofcmds` inside the file.
fn macho_header_valid(data: &[u8]) -> bool {
    let Some(magic) = read_u32_be(data, 0) else { return false };
    let (big_endian, header_len) = match magic {
        0xfeedface => (true, 28usize),
        0xfeedfacf => (true, 32usize),
        0xcefaedfe => (false, 28usize),
        0xcffaedfe => (false, 32usize),
        _ => return false,
    };
    let field = |off: usize| -> Option<u32> {
        let b = data.get(off..off + 4)?;
        let arr = [b[0], b[1], b[2], b[3]];
        Some(if big_endian { u32::from_be_bytes(arr) } else { u32::from_le_bytes(arr) })
    };
    let (Some(cputype), Some(ncmds), Some(sizeofcmds)) = (field(4), field(16), field(20)) else {
        return false;
    };
    cputype != 0
        && ncmds > 0
        && ncmds < 0x10000
        && (sizeofcmds as usize) >= ncmds as usize * 8
        && header_len + sizeofcmds as usize <= data.len()
}

fn looks_like_zip(data: &[u8]) -> bool {
    // Only match on the local-file-header magic at the very start of the file.
    // PK\x05\x06 (end-of-central-directory) and PK\x07\x08 (data-descriptor)
    // can appear anywhere inside a PE or other binary and must NOT be used as
    // a zip indicator unless the file actually starts with a ZIP local header.
    data.len() >= 4 && data.starts_with(b"PK\x03\x04")
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    memchr::memmem::find(haystack, needle).is_some()
}

/// SDK-inspired helper: classify bytes without path context (for memory scanning)
pub fn classify_bytes_only(data: &[u8]) -> FileTypeInfo {
    classify_bytes(Path::new("memory"), data)
}

/// Single-pass AST JavaScript detection using our workspace's native OXC parser.
pub fn is_javascript(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample_len = data.len().min(65536);
    let sample = &data[..sample_len];
    if !is_plain_text_bytes(sample) {
        return false;
    }
    let Ok(source) = std::str::from_utf8(sample) else {
        return false;
    };
    if !source.contains(';')
        && !source.contains('{')
        && !source.contains("function")
        && !source.contains("var ")
        && !source.contains("const ")
        && !source.contains("let ")
    {
        return false;
    }
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, SourceType::mjs()).parse();
    !ret.program.body.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_formats_by_content() {
        let ty = |d: &[u8]| classify_bytes_only(d).primary;
        let mut cab = b"MSCF\0\0\0\0".to_vec();
        cab.resize(36, 0);
        cab[24] = 3;
        cab[25] = 1;
        assert_eq!(ty(&cab), "mscab");
        assert!(classify_bytes_only(&cab).is_archive);
        let mut ico = vec![0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0];
        ico.extend_from_slice(&40u32.to_le_bytes());
        ico.extend_from_slice(&22u32.to_le_bytes());
        ico.resize(62, 0);
        assert_eq!(ty(&ico), "ico");
        // ETW traces also start with 00 00 01 00: not an icon.
        let mut etl = vec![0, 0, 1, 0, 0xd0, 2];
        etl.resize(4096, 0);
        assert_ne!(ty(&etl), "ico");
        let mut evtx = b"ElfFile\0".to_vec();
        evtx.resize(128, 0);
        assert_eq!(ty(&evtx), "evtx");
        let mut der = vec![0x30, 0x82, 0x00, 0x04];
        der.extend_from_slice(&[2, 2, 1, 1]);
        assert_eq!(ty(&der), "der");
    }

    /// PE32 with one section: entry point `ep`, section characteristics `flags`.
    fn pe_with(ep: u32, flags: u32) -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE  ");
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // sections
        d[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // optional header size
        d[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        d[0xa8..0xac].copy_from_slice(&ep.to_le_bytes());
        let sec = 0x98 + 0xe0;
        d[sec..sec + 5].copy_from_slice(b".rsrc");
        d[sec + 36..sec + 40].copy_from_slice(&flags.to_le_bytes());
        d
    }

    #[test]
    fn pe_without_code_is_tagged_not_broken() {
        let mui = classify_bytes_only(&pe_with(0, 0x4000_0040));
        assert_eq!(mui.primary, "pe32");
        assert!(!mui.is_broken_executable);
        assert!(mui.matches_type("pe_no_code"));
        // DllMain-less DLL that runs from its exports: executable section, has code.
        assert!(!classify_bytes_only(&pe_with(0, 0x6000_0020)).matches_type("pe_no_code"));
        assert!(!classify_bytes_only(&pe_with(0x1000, 0x4000_0040)).matches_type("pe_no_code"));
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn android_sdk_jars_are_not_apks() {
        let jar_mf: &[u8] = b"Manifest-Version: 1.0\n";
        // Library JAR dexed by d8.
        let dexed = zip_of(&[("META-INF/MANIFEST.MF", jar_mf), ("classes.dex", b"dex\n")]);
        let info = classify_bytes_only(&dexed);
        assert!(!info.is_apk && !info.is_broken_apk);
        assert!(info.is_jar);
        // Android build-tool JAR: the APK names only as strings inside a class.
        let tool = zip_of(&[
            ("META-INF/MANIFEST.MF", jar_mf),
            ("com/android/build/Packager.class", b"\xca\xfe\xba\xbe AndroidManifest.xml classes.dex"),
        ]);
        let info = classify_bytes_only(&tool);
        assert!(!info.is_apk && !info.is_broken_apk);
        assert_eq!(info.primary, "jar");
        // A real APK, whatever it is named.
        let apk = zip_of(&[("AndroidManifest.xml", b"\x03\x00\x08\x00"), ("classes.dex", b"dex\n")]);
        assert!(classify_bytes_only(&apk).is_apk);
    }

    #[test]
    fn detects_plain_text() {
        let info = classify_bytes(Path::new("test.ps1"), b"Write-Host hello\n");
        assert!(info.is_plain_text);
        assert!(info.is_powershell);
        assert!(info.matches_type("powershell"));
    }

    #[test]
    fn detects_elf_magic() {
        let data = b"\x7fELF\x02\x01\x01";
        let info = classify_bytes(Path::new("x"), data);
        assert!(info.is_elf);
        assert!(info.matches_type("elf64"));
    }

    #[test]
    fn detects_javascript_by_oxc_ast_without_js_extension() {
        let js_code = b"var x = 10; function runMe() { eval('test'); console.log(x); }";
        let info = classify_bytes(Path::new("malware.vir"), js_code);
        assert!(info.is_javascript);
        assert!(info.matches_type("javascript"));
        assert!(info.matches_type("js"));
    }
}
