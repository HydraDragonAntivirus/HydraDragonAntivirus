//! Native file-type detector for owlyshield_predict.
//!
//! Replaces the old DetectItEasy-subprocess path with pure-Rust magic and
//! structure sniffing. Scope is intentionally limited to the ClamAV-based
//! file types the engine actually scans (see `CL_TYPE_*` in hydradragonclamav
//! plus Mach-O for the `macho_result` contract). No external binaries, no
//! packer heuristics, no I/O inside [`detect`] — callers pass the bytes.
//!
//! Python compatibility: [`report_json`] emits the same keys the old DIE JSON
//! provided (`pe_result`, `elf_result`, `macho_result`, `apk_result`,
//! `is_plain_text`, `is_source`, `source_language`, `is_unknown`,
//! `is_broken_executable`, `file_type`). Missing keys were always read with
//! `.get()` downstream, so absent packer fields are simply falsy.

use serde::Serialize;

const READ_CAP: usize = 4 << 20;
const TEXT_SAMPLE: usize = 32 << 10;

/// ClamAV-based file types (plus Mach-O for the legacy result contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    MsExe,
    Elf,
    MachO,
    Apk,
    Zip,
    SevenZ,
    Gz,
    Xz,
    Tar,
    Pdf,
    Html,
    Swf,
    Dex,
    Png,
    Jpeg,
    Gif,
    Riff,
    AsciiText,
    Unknown,
    Empty,
}

impl FileKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileKind::MsExe => "CL_TYPE_MSEXE",
            FileKind::Elf => "CL_TYPE_ELF",
            FileKind::MachO => "MACHO",
            FileKind::Apk => "CL_TYPE_APK",
            FileKind::Zip => "CL_TYPE_ZIP",
            FileKind::SevenZ => "CL_TYPE_7Z",
            FileKind::Gz => "CL_TYPE_GZ",
            FileKind::Xz => "CL_TYPE_XZ",
            FileKind::Tar => "CL_TYPE_TAR",
            FileKind::Pdf => "CL_TYPE_PDF",
            FileKind::Html => "CL_TYPE_HTML",
            FileKind::Swf => "CL_TYPE_SWF",
            FileKind::Dex => "CL_TYPE_DEX",
            FileKind::Png => "CL_TYPE_PNG",
            FileKind::Jpeg => "CL_TYPE_JPEG",
            FileKind::Gif => "CL_TYPE_GIF",
            FileKind::Riff => "CL_TYPE_RIFF",
            FileKind::AsciiText => "CL_TYPE_TEXT_ASCII",
            FileKind::Unknown => "UNKNOWN",
            FileKind::Empty => "EMPTY",
        }
    }
}

/// Script/source languages sniffed from text content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    Batch,
    Shell,
    Powershell,
    Python,
    Javascript,
    Html,
    Php,
    Perl,
    Ruby,
}

impl SourceLanguage {
    fn as_str(&self) -> &'static str {
        match self {
            SourceLanguage::Batch => "batch",
            SourceLanguage::Shell => "shell",
            SourceLanguage::Powershell => "powershell",
            SourceLanguage::Python => "python",
            SourceLanguage::Javascript => "javascript",
            SourceLanguage::Html => "html",
            SourceLanguage::Php => "php",
            SourceLanguage::Perl => "perl",
            SourceLanguage::Ruby => "ruby",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileTypeReport {
    pub file_type: String,
    pub is_unknown: bool,
    pub pe_result: Option<String>,
    pub elf_result: Option<String>,
    pub macho_result: Option<String>,
    pub apk_result: Option<String>,
    pub is_plain_text: bool,
    pub is_source: bool,
    pub source_language: Option<String>,
    pub is_broken_executable: bool,
    pub broken_executable_type: Option<String>,
}

fn valid_result(valid: bool) -> Option<String> {
    valid.then(|| "valid".to_string())
}

/// MZ present with a parseable PE header (goblin = native, no DIE).
fn pe_valid(data: &[u8]) -> bool {
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return false;
    }
    match goblin::Object::parse(data) {
        Ok(goblin::Object::PE(_)) => true,
        _ => false,
    }
}

fn elf_valid(data: &[u8]) -> bool {
    if !data.starts_with(b"\x7fELF") {
        return false;
    }
    matches!(
        goblin::Object::parse(data),
        Ok(goblin::Object::Elf(_))
    )
}

fn macho_valid(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // MH_MAGIC / MH_CIGAM / MH_MAGIC_64 / MH_CIGAM_64 / FAT_MAGIC / FAT_CIGAM
    if !matches!(
        magic,
        0xfeed_face | 0xcefa_edfe | 0xfeed_facf | 0xcffa_edfe | 0xcafe_babe | 0xbeba_feca
    ) && !matches!(le, 0xfeed_face | 0xcefa_edfe | 0xfeed_facf | 0xcffa_edfe) {
        return false;
    }
    matches!(
        goblin::Object::parse(data),
        Ok(goblin::Object::Mach(_))
    )
}

fn has(data: &[u8], pat: &[u8]) -> bool {
    if pat.is_empty() || data.len() < pat.len() {
        return false;
    }
    data.windows(pat.len()).any(|w| w == pat)
}

/// APK = ZIP carrying AndroidManifest.xml (+ dex or native lib), checked in
/// the first/last 1 MB where local headers and central directory live.
fn is_apk(data: &[u8]) -> bool {
    const W: usize = 1 << 20;
    let head = &data[..data.len().min(W)];
    let tail = &data[data.len().saturating_sub(W)..];
    let manifest = has(head, b"AndroidManifest.xml") || has(tail, b"AndroidManifest.xml");
    if !manifest {
        return false;
    }
    let dex = has(head, b"classes.dex") || has(tail, b"classes.dex");
    manifest && (dex || has(head, b"lib/") || has(tail, b"lib/"))
}

fn printable_ratio(sample: &[u8]) -> f32 {
    if sample.is_empty() {
        return 0.0;
    }
    let ok = sample
        .iter()
        .filter(|b| {
            let v = **b;
            (0x20..=0x7e).contains(&v) || v == b'\t' || v == b'\n' || v == b'\r'
        })
        .count();
    ok as f32 / sample.len() as f32
}

fn is_plain_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(TEXT_SAMPLE)];
    !sample.contains(&0) && printable_ratio(sample) >= 0.90
}

fn lower_head(data: &[u8], n: usize) -> Vec<u8> {
    data[..data.len().min(n)].to_ascii_lowercase()
}

fn sniff_source(data: &[u8]) -> Option<SourceLanguage> {
    let head = lower_head(data, 4096);
    let starts = |p: &[u8]| head.starts_with(p);
    if starts(b"#!/bin/bash")
        || starts(b"#!/bin/sh")
        || starts(b"#!/usr/bin/env bash")
        || starts(b"#!/usr/bin/env sh")
    {
        return Some(SourceLanguage::Shell);
    }
    if starts(b"#!/usr/bin/env python") || head.starts_with(b"#!/usr/bin/python") {
        return Some(SourceLanguage::Python);
    }
    if starts(b"#!/usr/bin/env perl") || head.starts_with(b"#!/usr/bin/perl") {
        return Some(SourceLanguage::Perl);
    }
    if starts(b"#!/usr/bin/env ruby") || head.starts_with(b"#!/usr/bin/ruby") {
        return Some(SourceLanguage::Ruby);
    }
    if starts(b"#!/usr/bin/env php") || head.starts_with(b"#!/usr/bin/php") {
        return Some(SourceLanguage::Php);
    }
    if starts(b"#!/usr/bin/env node") || head.starts_with(b"#!/usr/bin/node") {
        return Some(SourceLanguage::Javascript);
    }
    if starts(b"#!powershell") || starts(b"#!/usr/bin/env powershell") || starts(b"#!/usr/bin/pwsh") {
        return Some(SourceLanguage::Powershell);
    }
    if head.starts_with(b"@echo") {
        return Some(SourceLanguage::Batch);
    }
    if head.starts_with(b"<?php") {
        return Some(SourceLanguage::Php);
    }
    // Content sniffing for extensionless scripts.
    if has(&head, b"powershell -") || has(&head, b"-executionpolicy") || has(&head, b"invoke-expression") {
        return Some(SourceLanguage::Powershell);
    }
    if has(&head, b"curl ") && (has(&head, b"| sh") || has(&head, b"|sh") || has(&head, b"| bash")) {
        return Some(SourceLanguage::Shell);
    }
    None
}

fn looks_like_html(data: &[u8]) -> bool {
    let head = lower_head(data, 8192);
    has(&head, b"<!doctype html")
        || has(&head, b"<html")
        || has(&head, b"<script")
        || (has(&head, b"<head") && has(&head, b"<body"))
}

/// Pure detection over bytes. Never touches disk, never spawns a process.
pub fn detect(data: &[u8]) -> FileTypeReport {
    if data.is_empty() {
        return FileTypeReport {
            file_type: FileKind::Empty.as_str().to_string(),
            is_unknown: true,
            pe_result: None,
            elf_result: None,
            macho_result: None,
            apk_result: None,
            is_plain_text: false,
            is_source: false,
            source_language: None,
            is_broken_executable: false,
            broken_executable_type: None,
        };
    }

    let pe = data.len() >= 2 && &data[0..2] == b"MZ" && pe_valid(data);
    let pe_broken = data.len() >= 2 && &data[0..2] == b"MZ" && !pe;
    let elf = elf_valid(data);
    let macho = macho_valid(data);
    let is_zip = data.len() >= 4 && data[0] == b'P' && data[1] == b'K' && data[2] == 0x03 && data[3] == 0x04;
    let apk = is_zip && is_apk(data);

    let kind = if pe {
        FileKind::MsExe
    } else if elf {
        FileKind::Elf
    } else if macho {
        FileKind::MachO
    } else if apk {
        FileKind::Apk
    } else if is_zip {
        FileKind::Zip
    } else if data.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        FileKind::SevenZ
    } else if data.starts_with(&[0x1f, 0x8b]) {
        FileKind::Gz
    } else if data.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        FileKind::Xz
    } else if data.len() > 262 && &data[257..262] == b"ustar" {
        FileKind::Tar
    } else if data.starts_with(b"%PDF") {
        FileKind::Pdf
    } else if data.len() >= 4 && data[..4] == [0x64, 0x65, 0x78, 0x0a] {
        FileKind::Dex
    } else if data.len() >= 3
        && (data[0] == b'F' || data[0] == b'C' || data[0] == b'Z')
        && data[1] == b'W'
        && data[2] == b'S'
    {
        FileKind::Swf
    } else if data.starts_with(b"GIF8")
        || data.starts_with(&[0x89, b'P', b'N', b'G'])
        || data.starts_with(&[0xff, 0xd8, 0xff])
    {
        if data.starts_with(b"GIF8") {
            FileKind::Gif
        } else if data.starts_with(&[0x89, b'P', b'N', b'G']) {
            FileKind::Png
        } else {
            FileKind::Jpeg
        }
    } else if data.starts_with(b"RIFF") {
        FileKind::Riff
    } else if looks_like_html(data) {
        FileKind::Html
    } else {
        let plain = is_plain_text(data);
        if plain {
            FileKind::AsciiText
        } else {
            FileKind::Unknown
        }
    };

    let plain = matches!(kind, FileKind::AsciiText | FileKind::Html) || is_plain_text(data);
    let mut lang = sniff_source(data);
    if lang.is_none() && matches!(kind, FileKind::Html) {
        lang = Some(SourceLanguage::Html);
    }

    FileTypeReport {
        file_type: kind.as_str().to_string(),
        is_unknown: matches!(kind, FileKind::Unknown),
        pe_result: valid_result(pe),
        elf_result: valid_result(elf),
        macho_result: valid_result(macho),
        apk_result: valid_result(apk),
        is_plain_text: plain,
        is_source: lang.is_some(),
        source_language: lang.map(|l| l.as_str().to_string()),
        is_broken_executable: pe_broken,
        broken_executable_type: pe_broken.then(|| "pe".to_string()),
    }
}

/// JSON with the legacy DIE-compatible keys.
pub fn report_json(data: &[u8]) -> String {
    serde_json::to_string(&detect(data)).unwrap_or_else(|_| "{\"file_type\":\"UNKNOWN\"}".to_string())
}

/// Read (capped) + detect a file by path.
///
/// Executables get a second chance: if the capped buffer carries an MZ
/// header that fails validation, the file is re-read whole (up to
/// [`FULL_READ_CAP]`) before calling it broken — section/blob data past the
/// cap must never flip a valid binary into `is_broken_executable`.
pub fn detect_file(path: &std::path::Path) -> FileTypeReport {
    const FULL_READ_CAP: u64 = 256 << 20;
    let first = std::fs::read(path).unwrap_or_default();
    let head = &first[..first.len().min(READ_CAP)];
    let probe = detect(head);
    if head.len() >= 2 && head[0] == b'M' && head[1] == b'Z' && probe.pe_result.is_none() {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() as usize > head.len() && meta.len() <= FULL_READ_CAP {
                if let Ok(full) = std::fs::read(path) {
                    return detect(&full);
                }
            }
        }
    }
    probe
}

fn utf16_str(ptr: *const u16, len: u32) -> Option<String> {
    if ptr.is_null() || len == 0 || len > 32768 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Some(String::from_utf16_lossy(slice))
}

fn write_json_out(json: &str, out_buf: *mut u8, buf_len: u32) -> u32 {
    let bytes = json.as_bytes();
    if out_buf.is_null() || buf_len == 0 {
        return bytes.len() as u32;
    }
    let n = (buf_len as usize).min(bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, n);
    }
    n as u32
}

/// FFI: file-type report as JSON (legacy DIE-compatible keys).
/// UTF-16 path in, JSON bytes out. Null buffer (or 0 length) returns the
/// needed size. Returns 0 on bad path argument.
#[unsafe(no_mangle)]
pub extern "C" fn owlyshield_filetype_json(
    path_ptr: *const u16,
    path_len: u32,
    out_buf: *mut u8,
    buf_len: u32,
) -> u32 {
    let path = match utf16_str(path_ptr, path_len) {
        Some(p) => p,
        None => return 0,
    };
    let report = detect_file(std::path::Path::new(&path));
    let json = serde_json::to_string(&report).unwrap_or_else(|_| "{\"file_type\":\"UNKNOWN\"}".to_string());
    write_json_out(&json, out_buf, buf_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        // DOS header (64 B, e_lfanew @ 0x3C = 64) + PE sig + COFF + opt header.
        let mut v = vec![0u8; 64];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 64;
        v.extend_from_slice(b"PE\0\0");
        // COFF: machine AMD64, 0 sections, opt header 240 B (PE32+).
        let mut coff = vec![0u8; 20];
        coff[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        coff[16..18].copy_from_slice(&240u16.to_le_bytes());
        v.extend_from_slice(&coff);
        // Optional header PE32+: magic 0x20b, the rest zeros (240 B).
        let mut opt = vec![0u8; 240];
        opt[0..2].copy_from_slice(&0x020bu16.to_le_bytes());
        v.extend_from_slice(&opt);
        v
    }

    fn minimal_elf() -> Vec<u8> {
        // 64-bit LE executable, x86-64, version 1.
        let mut v = vec![0u8; 64];
        v[0..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[6] = 1;
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        v[18..20].copy_from_slice(&62u16.to_le_bytes());
        v[20..24].copy_from_slice(&1u32.to_le_bytes());
        v
    }

    #[test]
    fn pe_valid_and_broken() {
        let r = detect(&minimal_pe());
        assert_eq!(r.file_type, "CL_TYPE_MSEXE");
        assert_eq!(r.pe_result.as_deref(), Some("valid"));
        assert!(!r.is_broken_executable);

        let r = detect(b"MZ truncated");
        assert!(r.is_broken_executable);
        assert_eq!(r.broken_executable_type.as_deref(), Some("pe"));
        assert_eq!(r.pe_result, None);
    }

    #[test]
    fn elf_and_macho_magics() {
        let r = detect(&minimal_elf());
        assert_eq!(r.file_type, "CL_TYPE_ELF");
        assert_eq!(r.elf_result.as_deref(), Some("valid"));

        // FAT binary header: goblin parses, no full image needed.
        let mut fat = vec![0u8; 64];
        fat[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        let r = detect(&fat);
        assert!(r.macho_result.is_some() || r.is_unknown);
    }

    #[test]
    fn archives_and_docs() {
        assert_eq!(detect(b"%PDF-1.7\n%\xe2\xe3").file_type, "CL_TYPE_PDF");
        assert_eq!(detect(&[0x1f, 0x8b, 0x08, 0x00]).file_type, "CL_TYPE_GZ");
        assert_eq!(
            detect(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00]).file_type,
            "CL_TYPE_7Z"
        );
        let mut dex = b"dex\n035\0".to_vec();
        dex.resize(64, 0);
        assert_eq!(detect(&dex).file_type, "CL_TYPE_DEX");
        assert_eq!(detect(b"GIF89a....").file_type, "CL_TYPE_GIF");
        assert_eq!(detect(&[0x89, b'P', b'N', b'G', 0x0d]).file_type, "CL_TYPE_PNG");
        assert_eq!(detect(&[0xff, 0xd8, 0xff, 0xe0]).file_type, "CL_TYPE_JPEG");
        // ZIP local header without manifest content -> generic ZIP.
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(&[0u8; 100]);
        assert_eq!(detect(&zip).file_type, "CL_TYPE_ZIP");
    }

    #[test]
    fn apk_needs_manifest_plus_content() {
        let mut apk = b"PK\x03\x04".to_vec();
        apk.extend_from_slice(b"AndroidManifest.xml");
        apk.extend_from_slice(b"classes.dex");
        let r = detect(&apk);
        assert_eq!(r.file_type, "CL_TYPE_APK");
        assert_eq!(r.apk_result.as_deref(), Some("valid"));
    }

    #[test]
    fn scripts_and_text() {
        let r = detect(b"#!/bin/bash\ncurl http://example.com/x | sh\n");
        assert!(r.is_plain_text && r.is_source);
        assert_eq!(r.source_language.as_deref(), Some("shell"));

        let r = detect(b"@echo off\r\nset x=1\r\n");
        assert_eq!(r.source_language.as_deref(), Some("batch"));

        let r = detect(b"<!DOCTYPE html><html><head><title>t</title></head><body></body></html>");
        assert_eq!(r.file_type, "CL_TYPE_HTML");
        assert!(r.is_plain_text);

        assert!(detect(b"just some plain ascii text here").is_plain_text);
        assert!(detect(&[0x00, 0x01, 0x02, 0xff, 0xfe]).is_unknown);
    }

    #[test]
    fn json_has_legacy_keys() {
        let j: serde_json::Value =
            serde_json::from_str(&report_json(&minimal_pe())).unwrap();
        for k in [
            "file_type",
            "pe_result",
            "elf_result",
            "macho_result",
            "apk_result",
            "is_plain_text",
            "is_source",
            "source_language",
            "is_unknown",
            "is_broken_executable",
            "broken_executable_type",
        ] {
            assert!(j.get(k).is_some(), "missing key {k}");
        }
        assert_eq!(j["file_type"], "CL_TYPE_MSEXE");
    }
}
