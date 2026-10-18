//! Inno Setup installers, via the `innospect` crate.
//!
//! Besides the stored files, the parts that decide what an installer does are
//! returned as entries so the scanners see them: the compiled `[Code]` (Pascal
//! Script: download URLs, offer logic), the decompressed setup header (license
//! text, messages, records) and a text summary of the `[Run]`, `[Registry]` and
//! `[Icons]` actions. A downloader such as OffLoader keeps its URLs in `[Code]`,
//! which is compressed inside the installer and invisible to a plain scan.

use crate::{is_decompression_bomb, EntryInfo, ExtractError, ExtractedEntry, Result, MAX_ARCHIVE_ENTRIES};

/// Name prefix of the entries made from the installer itself (not stored files).
pub const META_PREFIX: &str = "[inno]/";

/// The loader's setup-data marker, e.g. `Inno Setup Setup Data (6.5.0)`.
const MARKER: &[u8] = b"Inno Setup Setup Data (";

pub(crate) fn is_inno(data: &[u8]) -> bool {
    data.starts_with(b"MZ") && crate::pe_embedded::find(data, MARKER).is_some()
}

fn parse(data: &[u8]) -> Result<innospect::InnoInstaller<'_>> {
    innospect::InnoInstaller::from_bytes(data).map_err(|e| ExtractError::OperationFailed {
        reason: format!("inno setup parse failed: {e}"),
    })
}

fn meta(name: &str, data: Vec<u8>) -> ExtractedEntry {
    ExtractedEntry {
        name: format!("{META_PREFIX}{name}"),
        size_real: data.len() as u64,
        file_pos: 0,
        data,
    }
}

/// Registry value bytes as text: UTF-16LE when it looks like it, else lossy UTF-8.
fn text(b: &[u8]) -> String {
    if b.len() >= 2 && b.len() % 2 == 0 && b.iter().skip(1).step_by(2).all(|&x| x == 0) {
        let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&w).trim_end_matches('\0').to_string()
    } else {
        String::from_utf8_lossy(b).trim_end_matches('\0').to_string()
    }
}

/// `[Setup]`, `[Run]`, `[Registry]` and `[Icons]` as plain text lines.
fn summary(inst: &innospect::InnoInstaller<'_>) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let v = inst.version();
    let _ = writeln!(s, "version={}.{}.{}.{}", v.a, v.b, v.c, v.d);
    if let Some(h) = inst.header() {
        let _ = writeln!(s, "app_name={}", h.app_name().unwrap_or(""));
        let _ = writeln!(s, "app_version={}", h.app_version().unwrap_or(""));
        let _ = writeln!(s, "app_publisher={}", h.app_publisher().unwrap_or(""));
        let _ = writeln!(s, "default_dir={}", h.default_dir_name().unwrap_or(""));
    }
    let _ = writeln!(s, "encrypted={}", inst.is_encrypted());
    for cmd in inst.exec_commands() {
        let _ = writeln!(s, "run[{:?}]={} {}", cmd.phase, cmd.filename(), cmd.parameters());
    }
    for op in inst.registry_ops() {
        let r = op.source;
        let _ = writeln!(s, "registry[{:?}]={:?}\\{} {}={}", op.kind, r.hive, r.subkey, r.value_name, text(&r.value));
    }
    for sc in inst.shortcuts() {
        let _ = writeln!(s, "icon={} -> {} {}", sc.icon.name, sc.icon.filename, sc.icon.parameters);
    }
    for f in inst.files() {
        let _ = writeln!(s, "file={} -> {}", f.source, f.destination);
    }
    s
}

pub(crate) fn inno_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let inst = parse(data)?;
    let mut out = vec![meta("summary.txt", summary(&inst).into_bytes())];
    if let Some(code) = inst.compiled_code_bytes().filter(|c| !c.is_empty()) {
        out.push(meta("compiled_code.ifps", code.to_vec()));
    }
    let setup0 = inst.decompressed_setup0();
    if !setup0.is_empty() {
        out.push(meta("setup0.bin", setup0.to_vec()));
    }
    let mut total: usize = 0;
    for (file, content) in inst.extract_files().filter_map(|r| r.ok()) {
        total = total.saturating_add(content.len());
        if is_decompression_bomb(data.len(), total) {
            return Err(ExtractError::DecompressionBomb { format: "inno" });
        }
        let name = if file.destination.is_empty() { file.source.clone() } else { file.destination.clone() };
        out.push(ExtractedEntry {
            name: name.replace('\\', "/"),
            size_real: content.len() as u64,
            file_pos: 0,
            data: content,
        });
        if out.len() >= MAX_ARCHIVE_ENTRIES {
            break;
        }
    }
    Ok(out)
}

pub(crate) fn inno_list_entries(data: &[u8]) -> Result<Vec<EntryInfo>> {
    Ok(inno_to_memory(data)?
        .into_iter()
        .map(|e| EntryInfo { name: e.name, size: e.size_real })
        .collect())
}

pub(crate) fn inno_extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    inno_to_memory(data)?
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| e.data)
        .ok_or_else(|| ExtractError::OperationFailed {
            reason: format!("entry not found in inno setup: {name}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_pe_is_not_inno() {
        assert!(!is_inno(b"MZ\x90\x00 just a stub"));
        assert!(!is_inno(b"Inno Setup Setup Data (6.5.0)"));
    }
}
