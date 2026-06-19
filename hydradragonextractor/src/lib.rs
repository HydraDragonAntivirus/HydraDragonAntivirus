use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Magic bytes for detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
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
    } else if data.starts_with(&XZ_MAGIC) {
        Some("xz")
    } else if data.starts_with(&LZMA_STREAM_MAGIC) {
        Some("lzma")
    } else if data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
    {
        Some("tar")
    } else {
        None
    }
}

fn is_tar(data: &[u8]) -> bool {
    data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
}

fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&GZIP_MAGIC)
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
    archive.unpack(output_dir).map_err(|e| ExtractError::OperationFailed {
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
    let mut decoder =
        lzma_rust2::LzmaReader::new_mem_limit(file, u32::MAX, None).map_err(|e| {
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
    } else if is_xz(&data) {
        extract_xz(path, output_dir)?
    } else if is_lzma(&data) {
        extract_lzma(path, output_dir)?
    } else if is_tar(&data) {
        extract_plain_tar(path, output_dir)?
    } else {
        // Try 7z as fallback (it has its own magic check)
        sevenz_rust2::decompress_file(path, output_dir)
            .map_err(|e| ExtractError::OperationFailed {
                reason: format!("7z extraction failed: {e}"),
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

/// Extract an archive from an in-memory byte buffer.
///
/// Detects format by magic bytes, extracts to a temporary directory,
/// reads all extracted file contents into memory, cleans up, and returns
/// the file contents as `Vec<Vec<u8>>`.
pub fn extract_archive_from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Create a temp working directory in the system temp
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("hdext_{:x}", rand_byte()));

    // Write bytes to a temp file so extract_archive can work on it
    let input_path = tmp.join("input");
    std::fs::create_dir_all(&tmp)?;
    std::fs::write(&input_path, data)?;

    let output_dir = tmp.join("out");
    let _ = extract_archive(&input_path, &output_dir);

    // Read all extracted files into memory
    let mut result: Vec<Vec<u8>> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&output_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    result.push(bytes);
                }
            }
        }
    }

    // Clean up temp files
    let _ = std::fs::remove_dir_all(&tmp);

    Ok(result)
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
