//! Electron `.asar` archives (read-only), via the `asar` crate.

use std::path::PathBuf;

use crate::{EntryInfo, ExtractError, ExtractedEntry, Result, MAX_ARCHIVE_ENTRIES};

/// `.asar` has no dedicated magic: it begins with a Pickle `uint32 = 4` length
/// prefix followed by the JSON header `{"files":...`. Both are required so that
/// arbitrary `04 00 00 00` data is not taken for an archive.
pub(crate) fn is_asar(data: &[u8]) -> bool {
    if !data.starts_with(&[0x04, 0x00, 0x00, 0x00]) || data.len() < 16 {
        return false;
    }
    let head = &data[..data.len().min(64)];
    head.windows(8).any(|w| w == b"{\"files\"")
}

pub(crate) fn asar_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let reader = asar::AsarReader::new(data, None::<PathBuf>).map_err(|e| ExtractError::OperationFailed {
        reason: format!("asar parse failed: {e}"),
    })?;
    let mut out = Vec::new();
    for (path, file) in reader.files() {
        let content = file.data().to_vec();
        out.push(ExtractedEntry {
            name: path.to_string_lossy().replace('\\', "/"),
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

pub(crate) fn asar_list_entries(data: &[u8]) -> Result<Vec<EntryInfo>> {
    Ok(asar_to_memory(data)?
        .into_iter()
        .map(|e| EntryInfo { name: e.name, size: e.size_real })
        .collect())
}

pub(crate) fn asar_extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    asar_to_memory(data)?
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| e.data)
        .ok_or_else(|| ExtractError::OperationFailed {
            reason: format!("entry not found in asar: {name}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_asar_header() {
        let mut data = vec![0x04, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        data.extend_from_slice(b"{\"files\":{}}");
        assert!(is_asar(&data));
        assert!(!is_asar(&[0x04, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
    }

    #[test]
    fn extracts_asar_in_memory() {
        let mut writer = asar::AsarWriter::new();
        writer.write_file("main.js", b"console.log(1)", false).unwrap();
        writer.write_file("lib/a.txt", b"hello", false).unwrap();
        let mut buf = Vec::new();
        writer.finalize(&mut buf).unwrap();
        assert_eq!(crate::detect_format(&buf), Some("asar"));
        let names: Vec<_> = crate::list_entries(&buf).unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"main.js".to_string()));
        assert_eq!(crate::extract_entry(&buf, "lib/a.txt").unwrap(), b"hello");
    }
}
