use crate::models::FileTypeInfo;
use crate::utils::entropy::byte_entropy;
use anyhow::{Context, Result};
use goblin::Object;
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
        "binary",
        "unknown",
        "broken",
        "broken_executable",
        "broken_apk",
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
    match Object::parse(data) {
        Ok(Object::PE(_)) => {
            validation.pe = FormatValidation::Valid;
            validation.pe_type = pe_file_type(data).or_else(|| Some("PE".to_string()));
        }
        Ok(Object::Elf(_)) => {
            validation.elf = FormatValidation::Valid;
            validation.elf_type = elf_file_type(data).or_else(|| Some("ELF".to_string()));
        }
        Ok(Object::Mach(_)) => {
            validation.macho = FormatValidation::Valid;
        }
        Ok(_) | Err(_) => {
            // goblin parse failed — use magic-based fallback.
            // ELF files that goblin cannot fully parse (stripped, unusual headers,
            // non-standard section counts) are still valid ELF binaries from the
            // OS perspective. Mark them Valid so they don't receive broken_executable
            // tags that confuse detection rules.
            // Only PE and Mach-O stay as Broken since truncated/corrupt PE/Mach-O
            // is genuinely anomalous.
            if has_pe_magic(data) {
                validation.pe = FormatValidation::Broken;
                validation.broken_type = Some("PE".to_string());
                validation.pe_type = pe_file_type(data);
            } else if has_elf_magic(data) {
                // Treat as valid ELF — goblin may not support all ELF variants
                // (RISC-V, LoongArch, custom e_type values, etc.)
                validation.elf = FormatValidation::Valid;
                validation.elf_type = elf_file_type(data).or_else(|| Some("ELF".to_string()));
            } else if has_macho_magic(data) {
                validation.macho = FormatValidation::Broken;
                validation.broken_type = Some("Mach-O".to_string());
            }
        }
    }

    validation.apk = inspect_apk_bytes(data);
    validation
}

fn inspect_apk_bytes(data: &[u8]) -> FormatValidation {
    let has_zip_magic = looks_like_zip(data);
    let has_apk_marker = contains_bytes(data, b"AndroidManifest.xml")
        || contains_bytes(data, b"classes.dex")
        || contains_bytes(data, b"classes2.dex");

    if !has_zip_magic && !has_apk_marker {
        return FormatValidation::NotDetected;
    }

    let cursor = Cursor::new(data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return if has_apk_marker {
            FormatValidation::Broken
        } else {
            FormatValidation::NotDetected
        };
    };

    let mut has_android_manifest = false;
    let mut has_dex = false;
    for index in 0..archive.len() {
        let Ok(file) = archive.by_index(index) else {
            return FormatValidation::Broken;
        };
        let name = file.name();
        if name == "AndroidManifest.xml" {
            has_android_manifest = true;
        } else if name == "classes.dex" || (name.starts_with("classes") && name.ends_with(".dex")) {
            has_dex = true;
        }
    }

    if has_android_manifest {
        FormatValidation::Valid
    } else if has_apk_marker || has_dex {
        FormatValidation::Broken
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
    let optional_header_offset = pe_offset.checked_add(24)?;
    let optional_magic = read_u16_le(data, optional_header_offset)?;
    match optional_magic {
        0x20b => Some("PE64".to_string()),
        0x10b | 0x107 => Some("PE32".to_string()),
        _ => Some("PE".to_string()),
    }
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
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// SDK-inspired helper: classify bytes without path context (for memory scanning)
pub fn classify_bytes_only(data: &[u8]) -> FileTypeInfo {
    classify_bytes(Path::new("memory"), data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
}
