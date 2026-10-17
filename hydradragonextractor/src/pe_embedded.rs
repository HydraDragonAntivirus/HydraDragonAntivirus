//! Archives carried inside a PE file: NSIS installers and 7-Zip / RAR / ZIP
//! self-extractors. A PE is never an archive by its own magic, so every `MZ`
//! input is checked here: the bytes after the last section (the overlay) are
//! where installers and SFX stubs keep their payload.

use crate::{
    is_decompression_bomb, EntryInfo, ExtractError, ExtractedEntry, Result, MAX_ARCHIVE_ENTRIES,
    RAR15_MAGIC, RAR5_MAGIC, SEVENZ_MAGIC, ZIP_LOCAL_MAGIC,
};

/// NSIS FirstHeader signature (`flags`, `0xDEADBEEF`, then this string).
const NSIS_SIGNATURE: &[u8] = b"NullsoftInst";
/// Only this much of the overlay is searched for an embedded archive header;
/// SFX stubs put the archive at (or very near) the start of the overlay.
const SFX_SEARCH_LIMIT: usize = 4 * 1024 * 1024;

/// File offset where the PE image ends (raw end of the last section), i.e. where
/// an overlay would start. `None` when the headers are not a valid PE.
pub(crate) fn overlay_offset(data: &[u8]) -> Option<usize> {
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if data.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let sections = u16::from_le_bytes(data.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(data.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let table = coff + 20 + opt_size;
    let mut end = table + sections * 40;
    for i in 0..sections {
        let s = table + i * 40;
        let raw_size = u32::from_le_bytes(data.get(s + 16..s + 20)?.try_into().ok()?) as usize;
        let raw_ptr = u32::from_le_bytes(data.get(s + 20..s + 24)?.try_into().ok()?) as usize;
        if raw_size > 0 {
            end = end.max(raw_ptr.saturating_add(raw_size));
        }
    }
    Some(end.min(data.len()))
}

fn overlay(data: &[u8]) -> Option<&[u8]> {
    let off = overlay_offset(data)?;
    let ov = &data[off..];
    (!ov.is_empty()).then_some(ov)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// NSIS installer: a FirstHeader (`flags`, `0xDEADBEEF`/`0xDEADBEED`,
/// `NullsoftInst`) on a 512-byte boundary after the PE headers. The stub may
/// declare a section that runs past where the data starts, so the overlay
/// boundary is not used here; the siginfo + alignment keep a plain
/// "NullsoftInst" string elsewhere in a binary from matching.
pub(crate) fn is_nsis(data: &[u8]) -> bool {
    if !data.starts_with(b"MZ") {
        return false;
    }
    let mut from = 0;
    while let Some(rel) = find(&data[from..], NSIS_SIGNATURE) {
        let pos = from + rel;
        if pos >= 8
            && (pos - 8) % 512 == 0
            && matches!(&data[pos - 4..pos], [0xef, 0xbe, 0xad, 0xde] | [0xed, 0xbe, 0xad, 0xde])
        {
            return true;
        }
        from = pos + 1;
    }
    false
}

/// A 7z / RAR / ZIP archive appended to a PE stub (self-extractor). Returns the
/// archive bytes, which the regular format handlers then process.
pub(crate) fn sfx_payload(data: &[u8]) -> Option<&[u8]> {
    let ov = overlay(data)?;
    let window = &ov[..ov.len().min(SFX_SEARCH_LIMIT)];
    [&SEVENZ_MAGIC[..], &RAR5_MAGIC[..], &RAR15_MAGIC[..], &ZIP_LOCAL_MAGIC[..]]
        .iter()
        .filter_map(|magic| find(window, magic))
        .min()
        .map(|pos| &ov[pos..])
}

/// "nsis" or "sfx" for a PE that carries an archive.
pub(crate) fn detect(data: &[u8]) -> Option<&'static str> {
    if !data.starts_with(b"MZ") {
        None
    } else if is_nsis(data) {
        Some("nsis")
    } else if sfx_payload(data).is_some() {
        Some("sfx")
    } else {
        None
    }
}

/// Every file stored in an NSIS installer, decompressed. Best-effort: entries
/// that fail to parse or decompress are skipped.
pub(crate) fn nsis_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let installer = nsis::NsisInstaller::from_bytes(data).map_err(|e| ExtractError::OperationFailed {
        reason: format!("nsis parse failed: {e}"),
    })?;
    let mut out = Vec::new();
    for (index, file) in installer.files().enumerate() {
        let Ok(file) = file else { continue };
        let Ok(content) = file.decompress() else { continue };
        if is_decompression_bomb(data.len(), content.len()) {
            return Err(ExtractError::DecompressionBomb { format: "nsis" });
        }
        let name = file
            .name()
            .map(|n| n.to_string().replace('\\', "/"))
            .unwrap_or_default();
        let name = if name.is_empty() { format!("nsis_file_{index}") } else { name };
        out.push(ExtractedEntry {
            name,
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

pub(crate) fn nsis_list_entries(data: &[u8]) -> Result<Vec<EntryInfo>> {
    Ok(nsis_to_memory(data)?
        .into_iter()
        .map(|e| EntryInfo { name: e.name, size: e.size_real })
        .collect())
}

pub(crate) fn nsis_extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    nsis_to_memory(data)?
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| e.data)
        .ok_or_else(|| ExtractError::OperationFailed {
            reason: format!("entry not found in nsis installer: {name}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE: MZ header, PE signature, one section of 0x200 raw bytes at 0x200.
    fn tiny_pe(overlay: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        pe[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
        let s = 0x80 + 4 + 20 + 0xe0;
        pe[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        pe[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        pe.extend_from_slice(overlay);
        pe
    }

    #[test]
    fn overlay_starts_after_last_section() {
        assert_eq!(overlay_offset(&tiny_pe(b"xyz")), Some(0x400));
    }

    #[test]
    fn nsis_needs_aligned_first_header() {
        let mut pe = tiny_pe(b"");
        pe[0x300..0x30c].copy_from_slice(NSIS_SIGNATURE); // bare string, no siginfo
        assert!(!is_nsis(&pe));
        assert!(is_nsis(&tiny_pe(b"\x00\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst")));
    }

    #[test]
    fn finds_7z_sfx_payload() {
        let payload = [&SEVENZ_MAGIC[..], b"rest"].concat();
        let pe = tiny_pe(&[b"padding".as_slice(), &payload].concat());
        assert_eq!(detect(&pe), Some("sfx"));
        assert_eq!(sfx_payload(&pe), Some(&payload[..]));
    }

    #[test]
    fn plain_pe_is_not_an_archive() {
        assert_eq!(detect(&tiny_pe(b"")), None);
        assert_eq!(detect(&tiny_pe(b"just some overlay bytes")), None);
    }
}
