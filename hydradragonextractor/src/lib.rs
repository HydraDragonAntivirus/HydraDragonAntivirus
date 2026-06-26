use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Magic bytes for detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ZIP_LOCAL_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const LZMA_STREAM_MAGIC: [u8; 2] = [0x5d, 0x00];
/// ustar tar has "ustar" at offset 257.
const TAR_USTAR_OFFSET: usize = 257;
const TAR_USTAR_MAGIC: [u8; 5] = *b"ustar";

/// Result of extracting an archive: list of extracted file paths.
pub struct ExtractResult {
    pub files: Vec<PathBuf>,
    pub output_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("extraction failed: {reason}")]
    OperationFailed { reason: String },
}

type Result<T> = std::result::Result<T, ExtractError>;

/// Detect archive/compression format by content sniffing.
pub fn detect_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&GZIP_MAGIC) {
        Some("gz")
    } else if data.starts_with(&ZIP_LOCAL_MAGIC) {
        Some("zip")
    } else if data.starts_with(&XZ_MAGIC) {
        Some("xz")
    } else if data.starts_with(&LZMA_STREAM_MAGIC) {
        Some("lzma")
    } else if data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
    {
        Some("tar")
    } else if is_asar(data) {
        Some("asar")
    } else if is_nsis(data) {
        Some("nsis")
    } else {
        None
    }
}

/// NSIS installers are PE files whose appended overlay contains a FirstHeader
/// carrying the distinctive `NullsoftInst` signature (after a `0xDEADBEEF`/
/// `0xDEADBEED` siginfo). The MZ guard keeps the scan off non-PE inputs.
fn is_nsis(data: &[u8]) -> bool {
    data.starts_with(b"MZ") && find_subslice(data, b"NullsoftInst").is_some()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Electron `.asar` archives have no dedicated magic: they begin with a Pickle
/// `uint32 = 4` length prefix followed by the JSON header `{"files":...`. Detect
/// both to avoid false positives on arbitrary `04 00 00 00` data.
fn is_asar(data: &[u8]) -> bool {
    if !data.starts_with(&[0x04, 0x00, 0x00, 0x00]) || data.len() < 16 {
        return false;
    }
    let head = &data[..data.len().min(64)];
    head.windows(8).any(|window| window == b"{\"files\"")
}

fn is_tar(data: &[u8]) -> bool {
    data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
}

fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&GZIP_MAGIC)
}

fn is_zip(data: &[u8]) -> bool {
    data.starts_with(&ZIP_LOCAL_MAGIC)
}

fn is_xz(data: &[u8]) -> bool {
    data.starts_with(&XZ_MAGIC)
}

fn is_lzma(data: &[u8]) -> bool {
    data.starts_with(&LZMA_STREAM_MAGIC) || (data.len() > 13 && data[..2] == LZMA_STREAM_MAGIC)
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

fn extract_tar<R: Read>(reader: R, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut archive = tar::Archive::new(reader);
    archive
        .unpack(output_dir)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar extraction failed: {e}"),
        })?;
    let mut files = Vec::new();
    collect_files(output_dir, &mut files);
    Ok(files)
}

fn extract_gzip(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let decoder = flate2::read::GzDecoder::new(file);

    let mut decompressed = Vec::new();
    std::io::Read::take(&mut std::io::BufReader::new(decoder), u64::MAX)
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("gzip decompression failed: {e}"),
        })?;

    if is_tar(&decompressed) {
        extract_tar(Cursor::new(decompressed), output_dir)
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decompressed");
        let out_path = output_dir.join(stem);
        std::fs::write(&out_path, &decompressed)?;
        Ok(vec![out_path])
    }
}

fn extract_xz(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let mut decoder = lzma_rust2::XzReader::new(file, true);

    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("xz decompression failed: {e}"),
        })?;

    if is_tar(&decompressed) {
        extract_tar(Cursor::new(decompressed), output_dir)
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decompressed");
        let out_path = output_dir.join(stem);
        std::fs::write(&out_path, &decompressed)?;
        Ok(vec![out_path])
    }
}

fn extract_lzma(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let mut decoder = lzma_rust2::LzmaReader::new_mem_limit(file, u32::MAX, None).map_err(|e| {
        ExtractError::OperationFailed {
            reason: format!("lzma decoder init failed: {e}"),
        }
    })?;

    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("lzma decompression failed: {e}"),
        })?;

    if is_tar(&decompressed) {
        extract_tar(Cursor::new(decompressed), output_dir)
    } else {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decompressed");
        let out_path = output_dir.join(stem);
        std::fs::write(&out_path, &decompressed)?;
        Ok(vec![out_path])
    }
}

fn extract_plain_tar(path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    extract_tar(file, output_dir)
}

fn extract_zip(data: &[u8], output_dir: &Path) -> Result<Vec<PathBuf>> {
    let eocd = find_eocd(data).ok_or_else(|| ExtractError::OperationFailed {
        reason: "zip end-of-central-directory not found".to_string(),
    })?;
    let total_entries = read_u16(data, eocd + 10).unwrap_or(0) as usize;
    let central_offset = read_u32(data, eocd + 16).unwrap_or(0) as usize;
    let mut cursor = central_offset;
    let mut files = Vec::new();

    for _ in 0..total_entries {
        if data.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let method = read_u16(data, cursor + 10).unwrap_or(0);
        let compressed_size = read_u32(data, cursor + 20).unwrap_or(0) as usize;
        let name_len = read_u16(data, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16(data, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16(data, cursor + 32).unwrap_or(0) as usize;
        let local_offset = read_u32(data, cursor + 42).unwrap_or(0) as usize;
        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        let Some(name_bytes) = data.get(name_start..name_end) else {
            break;
        };
        let name = String::from_utf8_lossy(name_bytes).replace('\\', "/");

        if !name.ends_with('/') {
            if let Some(output_path) = safe_output_path(output_dir, &name) {
                if data.get(local_offset..local_offset + 4) == Some(b"PK\x03\x04") {
                    let local_name_len = read_u16(data, local_offset + 26).unwrap_or(0) as usize;
                    let local_extra_len = read_u16(data, local_offset + 28).unwrap_or(0) as usize;
                    let data_start = local_offset
                        .saturating_add(30)
                        .saturating_add(local_name_len)
                        .saturating_add(local_extra_len);
                    let data_end = data_start.saturating_add(compressed_size);
                    if let Some(compressed) = data.get(data_start..data_end) {
                        let extracted = match method {
                            0 => compressed.to_vec(),
                            8 => {
                                let mut decoder =
                                    flate2::read::DeflateDecoder::new(Cursor::new(compressed));
                                let mut out = Vec::new();
                                decoder.read_to_end(&mut out).map_err(|e| {
                                    ExtractError::OperationFailed {
                                        reason: format!("zip deflate failed: {e}"),
                                    }
                                })?;
                                out
                            }
                            _ => Vec::new(),
                        };
                        if !extracted.is_empty() || method == 0 {
                            if let Some(parent) = output_path.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::write(&output_path, extracted)?;
                            files.push(output_path);
                        }
                    }
                }
            }
        }

        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }

    Ok(files)
}

/// Parse an Electron `.asar` archive entirely in memory and return each
/// member's bytes — no temp files. ASAR members are stored uncompressed, so the
/// reader hands back slices we simply copy out.
fn extract_asar_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let reader =
        asar::AsarReader::new(data, None::<PathBuf>).map_err(|e| ExtractError::OperationFailed {
            reason: format!("asar parse failed: {e}"),
        })?;
    Ok(reader.files().values().map(|f| f.data().to_vec()).collect())
}

/// Parse an Electron `.asar` archive in memory and write each member to disk.
fn extract_asar_to_dir(data: &[u8], output_dir: &Path) -> Result<Vec<PathBuf>> {
    let reader =
        asar::AsarReader::new(data, None::<PathBuf>).map_err(|e| ExtractError::OperationFailed {
            reason: format!("asar parse failed: {e}"),
        })?;
    let mut files = Vec::new();
    for (path, file) in reader.files() {
        if let Some(out) = safe_output_path(output_dir, &path.to_string_lossy()) {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out, file.data())?;
            files.push(out);
        }
    }
    Ok(files)
}

/// Parse an NSIS installer entirely in memory and return each embedded file's
/// decompressed bytes — no temp files. Best-effort: members that fail to parse
/// or decompress are skipped rather than aborting the whole archive.
fn extract_nsis_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let installer = nsis::NsisInstaller::from_bytes(data).map_err(|e| {
        ExtractError::OperationFailed {
            reason: format!("nsis parse failed: {e}"),
        }
    })?;
    let mut out = Vec::new();
    for file in installer.files() {
        let Ok(file) = file else { continue };
        if let Ok(content) = file.decompress() {
            out.push(content);
        }
    }
    Ok(out)
}

/// Parse an NSIS installer in memory and write each embedded file to disk.
fn extract_nsis_to_dir(data: &[u8], output_dir: &Path) -> Result<Vec<PathBuf>> {
    let installer = nsis::NsisInstaller::from_bytes(data).map_err(|e| {
        ExtractError::OperationFailed {
            reason: format!("nsis parse failed: {e}"),
        }
    })?;
    let mut files = Vec::new();
    for (index, file) in installer.files().enumerate() {
        let Ok(file) = file else { continue };
        let Ok(content) = file.decompress() else {
            continue;
        };
        let name = file
            .name()
            .map(|n| n.to_string().replace('\\', "/"))
            .unwrap_or_default();
        let out = if name.is_empty() {
            output_dir.join(format!("nsis_file_{index}"))
        } else {
            safe_output_path(output_dir, &name)
                .unwrap_or_else(|| output_dir.join(format!("nsis_file_{index}")))
        };
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&out, content)?;
        files.push(out);
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Extract any supported archive by content sniffing.
///
/// Supported formats: .tar, .tar.gz/.tgz, .tar.xz, .tar.lzma,
/// .gz, .xz, .lzma, .7z.
/// Detects format by magic bytes, not file extension.
pub fn extract_archive(path: &Path, output_dir: &Path) -> Result<ExtractResult> {
    std::fs::create_dir_all(output_dir)?;
    let data = std::fs::read(path)?;

    let files = if is_gzip(&data) {
        extract_gzip(path, output_dir)?
    } else if is_asar(&data) {
        extract_asar_to_dir(&data, output_dir)?
    } else if is_nsis(&data) {
        extract_nsis_to_dir(&data, output_dir)?
    } else if is_zip(&data) {
        extract_zip(&data, output_dir)?
    } else if is_xz(&data) {
        extract_xz(path, output_dir)?
    } else if is_lzma(&data) {
        extract_lzma(path, output_dir)?
    } else if is_tar(&data) {
        extract_plain_tar(path, output_dir)?
    } else {
        // Try 7z as fallback (it has its own magic check)
        sevenz_rust2::decompress_file(path, output_dir).map_err(|e| {
            ExtractError::OperationFailed {
                reason: format!("7z extraction failed: {e}"),
            }
        })?;
        let mut files = Vec::new();
        collect_files(output_dir, &mut files);
        files
    };

    Ok(ExtractResult {
        files,
        output_dir: output_dir.to_path_buf(),
    })
}

/// Extract an archive from an in-memory byte buffer — entirely in memory,
/// no temp files written to disk.
pub fn extract_archive_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if is_asar(data) {
        return extract_asar_from_bytes(data);
    }
    if is_nsis(data) {
        return extract_nsis_from_bytes(data);
    }
    if is_gzip(data) {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(data));
        let mut decompressed = Vec::new();
        std::io::Read::take(
            &mut std::io::BufReader::new(decoder),
            u64::MAX,
        )
        .read_to_end(&mut decompressed)
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("gzip decompression failed: {e}"),
        })?;
        if is_tar(&decompressed) {
            return extract_tar_from_bytes(&decompressed);
        }
        return Ok(vec![decompressed]);
    }
    if is_zip(data) {
        return extract_zip_from_bytes(data);
    }
    if is_xz(data) {
        let mut decoder = lzma_rust2::XzReader::new(Cursor::new(data), true);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ExtractError::OperationFailed {
                reason: format!("xz decompression failed: {e}"),
            })?;
        if is_tar(&decompressed) {
            return extract_tar_from_bytes(&decompressed);
        }
        return Ok(vec![decompressed]);
    }
    if is_lzma(data) {
        let mut decoder =
            lzma_rust2::LzmaReader::new_mem_limit(Cursor::new(data), u32::MAX, None).map_err(
                |e| ExtractError::OperationFailed {
                    reason: format!("lzma decoder init failed: {e}"),
                },
            )?;
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| ExtractError::OperationFailed {
                reason: format!("lzma decompression failed: {e}"),
            })?;
        if is_tar(&decompressed) {
            return extract_tar_from_bytes(&decompressed);
        }
        return Ok(vec![decompressed]);
    }
    if is_tar(data) {
        return extract_tar_from_bytes(data);
    }
    // 7z as fallback (in-memory via reader-based API)
    extract_7z_from_bytes(data)
}

fn extract_tar_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let mut out: Vec<Vec<u8>> = Vec::new();
    for entry in archive.entries().map_err(|e| ExtractError::OperationFailed {
        reason: format!("tar entries failed: {e}"),
    })? {
        let mut entry = entry.map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar entry read failed: {e}"),
        })?;
        if entry.header().entry_type().is_file() {
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| ExtractError::OperationFailed {
                    reason: format!("tar entry decompress failed: {e}"),
                })?;
            out.push(content);
        }
    }
    Ok(out)
}

fn extract_zip_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let eocd = find_eocd(data).ok_or_else(|| ExtractError::OperationFailed {
        reason: "zip end-of-central-directory not found".to_string(),
    })?;
    let total_entries = read_u16(data, eocd + 10).unwrap_or(0) as usize;
    let central_offset = read_u32(data, eocd + 16).unwrap_or(0) as usize;
    let mut cursor = central_offset;
    let mut out: Vec<Vec<u8>> = Vec::new();

    for _ in 0..total_entries {
        if data.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let method = read_u16(data, cursor + 10).unwrap_or(0);
        let compressed_size = read_u32(data, cursor + 20).unwrap_or(0) as usize;
        let name_len = read_u16(data, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16(data, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16(data, cursor + 32).unwrap_or(0) as usize;
        let local_offset = read_u32(data, cursor + 42).unwrap_or(0) as usize;
        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        let Some(name_bytes) = data.get(name_start..name_end) else {
            break;
        };
        let name = String::from_utf8_lossy(name_bytes).replace('\\', "/");

        if !name.ends_with('/') {
            if data.get(local_offset..local_offset + 4) == Some(b"PK\x03\x04") {
                let local_name_len = read_u16(data, local_offset + 26).unwrap_or(0) as usize;
                let local_extra_len = read_u16(data, local_offset + 28).unwrap_or(0) as usize;
                let data_start = local_offset
                    .saturating_add(30)
                    .saturating_add(local_name_len)
                    .saturating_add(local_extra_len);
                let data_end = data_start.saturating_add(compressed_size);
                if let Some(compressed) = data.get(data_start..data_end) {
                    let extracted = match method {
                        0 => compressed.to_vec(),
                        8 => {
                            let mut decoder =
                                flate2::read::DeflateDecoder::new(Cursor::new(compressed));
                            let mut buf = Vec::new();
                            decoder.read_to_end(&mut buf).map_err(|e| {
                                ExtractError::OperationFailed {
                                    reason: format!("zip deflate failed: {e}"),
                                }
                            })?;
                            buf
                        }
                        _ => Vec::new(),
                    };
                    if !extracted.is_empty() || method == 0 {
                        out.push(extracted);
                    }
                }
            }
        }

        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }

    Ok(out)
}

fn extract_7z_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let dest = std::env::temp_dir().join(format!("hdext7z_{:x}", rand_byte()));

    let result = sevenz_rust2::decompress_with_extract_fn(
        Cursor::new(data),
        &dest,
        |_entry, reader, _suggested| {
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .map_err(sevenz_rust2::Error::from)?;
            out.push(content);
            Ok(true)
        },
    );

    let _ = std::fs::remove_dir_all(&dest);

    result.map_err(|e| ExtractError::OperationFailed {
        reason: format!("7z extraction failed: {e}"),
    })?;

    Ok(out)
}

/// Generate a random byte for directory name uniqueness.
fn rand_byte() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // Mix with a simple counter-like value from the process
    (nanos as u32).wrapping_mul(6364136223846793005u64 as u32)
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let min = data.len().saturating_sub(65_557);
    (min..data.len().saturating_sub(3))
        .rev()
        .find(|offset| data.get(*offset..offset + 4) == Some(b"PK\x05\x06"))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn safe_output_path(output_dir: &Path, name: &str) -> Option<PathBuf> {
    let mut out = output_dir.to_path_buf();
    for component in Path::new(name).components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_asar_header() {
        let mut data = vec![0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00];
        data.extend_from_slice(b"{\"files\":{}}");
        assert_eq!(detect_format(&data), Some("asar"));

        // A bare `04 00 00 00` prefix without the JSON header is not asar.
        let other = vec![0x04, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb];
        assert_eq!(detect_format(&other), None);
    }

    #[test]
    fn extracts_asar_in_memory() {
        let mut writer = asar::AsarWriter::new();
        writer
            .write_file("hello.txt", b"Hello, World!", false)
            .unwrap();
        writer
            .write_file("config/c2.txt", b"http://evil.example", false)
            .unwrap();
        let mut buf = Vec::new();
        writer.finalize(&mut buf).unwrap();

        assert_eq!(detect_format(&buf), Some("asar"));

        let files = extract_archive_from_bytes(&buf).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f == b"Hello, World!"));
        assert!(files.iter().any(|f| f == b"http://evil.example"));
    }

    #[test]
    fn detects_nsis_signature() {
        // PE start + the NSIS FirstHeader signature (siginfo + NullsoftInst).
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(&[0u8; 200]);
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend_from_slice(b"NullsoftInst");
        assert_eq!(detect_format(&data), Some("nsis"));

        // The signature without an MZ header is not treated as NSIS.
        let mut not_pe = vec![0u8; 50];
        not_pe.extend_from_slice(b"NullsoftInst");
        assert_eq!(detect_format(&not_pe), None);
    }
}
