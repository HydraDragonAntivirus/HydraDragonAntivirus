use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

/// Cached CPU count, capped at 4. `std::thread::available_parallelism()` probes
/// cgroup-v2 CPU-quota files under `/sys/fs/cgroup` on Android, which the app
/// sandbox is denied `search` on — each call emits an SELinux `avc: denied
/// { search } … cgroup2` audit line. Extraction is called once per nested
/// archive, so caching the count avoids both the repeated probe and the logcat
/// AVC spam. The value can't change over a process's lifetime.
fn extractor_worker_count() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(1, 4);
    CACHED.store(n, Ordering::Relaxed);
    n
}

/// Magic bytes for format detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ZIP_LOCAL_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const BZ2_MAGIC: [u8; 3] = [0x42, 0x5a, 0x68];
const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// ISO 9660 has "CD001" at sector 16 offset 1 (byte 32769).
const ISO_MAGIC_OFFSET: usize = 32769;
const ISO_MAGIC: [u8; 5] = *b"CD001";
/// ustar tar has "ustar" at offset 257.
const TAR_USTAR_OFFSET: usize = 257;
const TAR_USTAR_MAGIC: [u8; 5] = *b"ustar";
/// RAR v1.5: `Rar!\x1a\x07\x00`
const RAR15_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
/// RAR v5: `Rar!\x1a\x07\x01\x00`
const RAR5_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

mod rar;

pub struct ExtractResult {
    pub files: Vec<PathBuf>,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    pub name: String,
    pub data: Vec<u8>,
    /// Real (uncompressed) size of this entry.
    pub size_real: u64,
    /// Byte offset of this entry's data within the archive.
    pub file_pos: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("extraction failed: {reason}")]
    OperationFailed { reason: String },
    #[error("decompression bomb detected ({format})")]
    DecompressionBomb { format: &'static str },
}

pub(crate) type Result<T> = std::result::Result<T, ExtractError>;

fn map_err(e: impl ToString) -> ExtractError {
    ExtractError::OperationFailed {
        reason: e.to_string(),
    }
}

pub fn detect_format(data: &[u8]) -> Option<&'static str> {
    if is_rar(data) {
        Some("rar")
    } else if data.starts_with(&GZIP_MAGIC) {
        Some("gz")
    } else if data.starts_with(&ZIP_LOCAL_MAGIC) {
        Some("zip")
    } else if data.starts_with(&XZ_MAGIC) {
        Some("xz")
    } else if data.starts_with(&BZ2_MAGIC) {
        Some("bz2")
    } else if data.starts_with(&SEVENZ_MAGIC) {
        Some("7z")
    } else if data.starts_with(&ZSTD_MAGIC) {
        Some("zst")
    } else if data.starts_with(&[0x5d, 0x00]) {
        Some("lzma")
    } else if is_tar(data) {
        Some("tar")
    } else if is_iso(data) {
        Some("iso")
    } else {
        None
    }
}

fn is_tar(data: &[u8]) -> bool {
    data.len() > TAR_USTAR_OFFSET + 5
        && data[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] == TAR_USTAR_MAGIC
}

fn is_rar(data: &[u8]) -> bool {
    data.starts_with(&RAR5_MAGIC) || data.starts_with(&RAR15_MAGIC)
}

fn is_iso(data: &[u8]) -> bool {
    data.len() > ISO_MAGIC_OFFSET + 5
        && data[ISO_MAGIC_OFFSET..ISO_MAGIC_OFFSET + 5] == ISO_MAGIC
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn extract_archive(path: &Path, output_dir: &Path) -> Result<ExtractResult> {
    std::fs::create_dir_all(output_dir)?;
    let data = std::fs::read(path)?;

    let entries = if is_rar(&data) {
        rar::extract_from_bytes(&data)?
    } else {
        extract_to_memory(&data, false)?
    };

    let mut files = Vec::new();
    for e in entries {
        if let Some(out_path) = safe_output_path(output_dir, &e.name) {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out_path, e.data)?;
            files.push(out_path);
        }
    }

    Ok(ExtractResult {
        files,
        output_dir: output_dir.to_path_buf(),
    })
}

/// Extract every entry of an archive into memory, paired with its in-archive
/// name/path (e.g. `lib/arm64-v8a/libfoo.so`) so callers can report detections
/// against the real member instead of an opaque index.
pub fn extract_archive_from_bytes(data: &[u8], relevant_only: bool) -> Result<Vec<ExtractedEntry>> {
    if is_rar(data) {
        return rar::extract_from_bytes(data);
    }
    extract_to_memory(data, relevant_only)
}

#[derive(Clone, Debug)]
pub struct ZipEntryInfo {
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
}

/// List ZIP entry names and sizes without extracting their content.
/// Enables the caller to filter by name first, then extract only relevant entries.
pub fn zip_list_entries(data: &[u8]) -> Result<Vec<ZipEntryInfo>> {
    let info = ripzip::extract::zip_reader::parse_archive(data)
        .map_err(map_err)?;
    Ok(info.entries
        .iter()
        .filter(|e| !e.is_dir)
        .take(MAX_ARCHIVE_ENTRIES)
        .map(|e| ZipEntryInfo {
            name: e.file_name.clone(),
            size: e.uncompressed_size,
            compressed_size: e.compressed_size,
        })
        .collect())
}

/// Extract a single ZIP entry by name. More efficient than extracting all
/// entries when only a subset is needed — the caller first filters names
/// from [`zip_list_entries`], then extracts only matching entries.
pub fn zip_extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    let info = ripzip::extract::zip_reader::parse_archive(data)
        .map_err(map_err)?;
    let entry = info.entries.iter()
        .find(|e| e.file_name == name && !e.is_dir)
        .ok_or_else(|| ExtractError::OperationFailed {
            reason: format!("entry not found in zip: {name}"),
        })?;
    extract_ripzip_entry(data, entry)
}

fn extract_ripzip_entry(
    archive_data: &[u8],
    entry: &ripzip::extract::zip_reader::ZipEntry,
) -> Result<Vec<u8>> {
    let data_offset = ripzip::extract::zip_reader::parse_local_header_data_offset(
        archive_data, entry.local_header_offset,
    ).map_err(map_err)?;

    let start = data_offset as usize;
    let end = start + entry.compressed_size as usize;
    if end > archive_data.len() {
        return Err(ExtractError::OperationFailed {
            reason: format!("entry data for '{}' extends beyond archive", entry.file_name),
        });
    }
    let compressed = &archive_data[start..end];

    match entry.compression_method {
        ripzip::zip_format::COMPRESSION_STORED => {
            if entry.uncompressed_size > 0 {
                let crc = ripzip::zip_format::crc::crc32(compressed);
                if crc != entry.crc32 {
                    return Err(ExtractError::OperationFailed {
                        reason: format!("CRC32 mismatch for '{}'", entry.file_name),
                    });
                }
            }
            Ok(compressed.to_vec())
        }
        ripzip::zip_format::COMPRESSION_DEFLATED => {
            use std::io::Read;
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut out = Vec::with_capacity(entry.uncompressed_size as usize);
            decoder.read_to_end(&mut out).map_err(|e| ExtractError::OperationFailed {
                reason: format!("deflate decompression failed for '{}': {e}", entry.file_name),
            })?;
            let crc = ripzip::zip_format::crc::crc32(&out);
            if entry.uncompressed_size > 0 && crc != entry.crc32 {
                return Err(ExtractError::OperationFailed {
                    reason: format!("CRC32 mismatch for '{}'", entry.file_name),
                });
            }
            Ok(out)
        }
        ripzip::zip_format::COMPRESSION_ZSTD => {
            use std::io::Read;
            let mut decoder = zstd::Decoder::new(compressed).map_err(|e| ExtractError::OperationFailed {
                reason: format!("zstd init failed for '{}': {e}", entry.file_name),
            })?;
            let mut out = Vec::with_capacity(entry.uncompressed_size as usize);
            decoder.read_to_end(&mut out).map_err(|e| ExtractError::OperationFailed {
                reason: format!("zstd decompression failed for '{}': {e}", entry.file_name),
            })?;
            let crc = ripzip::zip_format::crc::crc32(&out);
            if entry.uncompressed_size > 0 && crc != entry.crc32 {
                return Err(ExtractError::OperationFailed {
                    reason: format!("CRC32 mismatch for '{}'", entry.file_name),
                });
            }
            Ok(out)
        }
        m => Err(ExtractError::OperationFailed {
            reason: format!("unsupported compression method {m} for '{}'", entry.file_name),
        }),
    }
}

// ---------------------------------------------------------------------------
// Generic lazy-list + extract API (all archive formats)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct EntryInfo {
    pub name: String,
    pub size: u64,
}

/// List entry names without extracting their content.
pub fn list_entries(data: &[u8]) -> Result<Vec<EntryInfo>> {
    if is_rar(data) {
        return rar::list_entries(data);
    }
    if data.starts_with(&ZIP_LOCAL_MAGIC) {
        return zip_list_entries(data).map(|v| {
            v.into_iter()
                .map(|e| EntryInfo { name: e.name, size: e.size })
                .collect()
        });
    }
    if data.starts_with(&SEVENZ_MAGIC) {
        return sz_list_entries(data);
    }
    if is_tar(data) {
        return Ok(tar_entries(data)?.into_iter().map(|e| EntryInfo { name: e.name, size: e.size_real }).collect());
    }
    // Compression formats: report a single "decompressed" entry.
    if data.starts_with(&GZIP_MAGIC) || data.starts_with(&XZ_MAGIC)
        || data.starts_with(&BZ2_MAGIC) || data.starts_with(&ZSTD_MAGIC)
        || data.starts_with(&[0x5d, 0x00]) {
        return Ok(vec![EntryInfo { name: "decompressed".to_string(), size: 0 }]);
    }
    if is_iso(data) {
        return iso_list_entries(data);
    }
    Err(ExtractError::OperationFailed {
        reason: "listing not supported for this format".to_string(),
    })
}

/// Extract a single entry by name from an archive.
pub fn extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    if is_rar(data) {
        return rar::extract_entry(data, name);
    }
    if data.starts_with(&ZIP_LOCAL_MAGIC) {
        return zip_extract_entry(data, name);
    }
    if data.starts_with(&SEVENZ_MAGIC) {
        return sz_extract_entry(data, name);
    }
    if is_tar(data) {
        let entries = tar_entries(data)?;
        return entries.into_iter().find(|e| e.name == name).map(|e| e.data)
            .ok_or_else(|| ExtractError::OperationFailed {
                reason: format!("entry not found in tar: {name}"),
            });
    }
    if data.starts_with(&GZIP_MAGIC) {
        return decompress_gzip(data);
    }
    if data.starts_with(&XZ_MAGIC) || data.starts_with(&[0x5d, 0x00]) {
        return decompress_xz(data);
    }
    if data.starts_with(&BZ2_MAGIC) {
        return decompress_bzip2(data);
    }
    if is_iso(data) {
        return iso_extract_entry(data, name);
    }
    Err(ExtractError::OperationFailed {
        reason: "extraction not supported for this format".to_string(),
    })
}



// ---------------------------------------------------------------------------
// Internal: in-memory extraction
// ---------------------------------------------------------------------------

fn extract_to_memory(data: &[u8], relevant_only: bool) -> Result<Vec<ExtractedEntry>> {
    if data.starts_with(&ZIP_LOCAL_MAGIC) {
        return zip_to_memory(data, relevant_only);
    }
    if data.starts_with(&GZIP_MAGIC) {
        return gzip_to_memory(data);
    }
    if data.starts_with(&XZ_MAGIC) || data.starts_with(&[0x5d, 0x00]) {
        return xz_to_memory(data);
    }
    if data.starts_with(&BZ2_MAGIC) {
        return bzip2_to_memory(data);
    }
    if data.starts_with(&SEVENZ_MAGIC) {
        return sz_to_memory(data);
    }
    if is_tar(data) {
        return tar_to_memory(data);
    }
    if is_iso(data) {
        return iso_to_memory(data);
    }
    Err(ExtractError::OperationFailed {
        reason: "unsupported or unknown archive format".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Single-file compression: decompress, check for TAR
// ---------------------------------------------------------------------------

// Decompression-bomb guard: catches "small compressed input, absurd output"
// regardless of which single-stream format it comes from. Two independent
// triggers, either one is enough to reject:
//   - absolute output size past MAX_DECOMPRESSED_SIZE (bounds memory/CPU no
//     matter the ratio — catches bombs built from already-large input)
//   - ratio of output:input past BOMB_RATIO, but only once output is also
//     past a modest floor (MIN_RATIO_CHECK_SIZE) — a 10-byte input expanding
//     to 1KB is a 100:1 ratio and completely normal, so ratio alone is not
//     used to flag small buffers; this keeps zero-FP on legitimate highly
//     compressible content (sparse files, repeated-byte images, logs).
pub(crate) const MAX_DECOMPRESSED_SIZE: usize = 200_000_000;
const BOMB_RATIO: usize = 1000;
const MIN_RATIO_CHECK_SIZE: usize = 10_000_000;

/// User-toggleable from settings — disabling removes all decompression-bomb
/// caps above, at the cost of allowing unbounded extraction time/memory on a
/// crafted archive.
static DETECT_BOMBS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn set_bomb_detection_enabled(enabled: bool) {
    DETECT_BOMBS.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn is_decompression_bomb(compressed_len: usize, decompressed_len: usize) -> bool {
    if !DETECT_BOMBS.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    if decompressed_len > MAX_DECOMPRESSED_SIZE {
        return true;
    }
    if decompressed_len < MIN_RATIO_CHECK_SIZE {
        return false;
    }
    let ratio = decompressed_len / compressed_len.max(1);
    ratio > BOMB_RATIO
}

/// True if `e` is specifically a decompression-bomb rejection (as opposed to
/// a corrupt/unsupported archive) — callers use this to surface a bomb as a
/// detection rather than treating it as an ordinary extraction failure.
pub fn is_bomb_error(e: &ExtractError) -> bool {
    matches!(e, ExtractError::DecompressionBomb { .. })
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| ExtractError::OperationFailed {
        reason: format!("gzip decompression failed: {e}"),
    })?;
    if is_decompression_bomb(data.len(), out.len()) {
        return Err(ExtractError::DecompressionBomb { format: "gzip" });
    }
    Ok(out)
}

fn decompress_xz(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = lzma_rust2::XzReader::new(Cursor::new(data), true);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| ExtractError::OperationFailed {
        reason: format!("xz decompression failed: {e}"),
    })?;
    if is_decompression_bomb(data.len(), out.len()) {
        return Err(ExtractError::DecompressionBomb { format: "xz" });
    }
    Ok(out)
}

fn decompress_bzip2(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = bzip2::read::BzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| ExtractError::OperationFailed {
        reason: format!("bzip2 decompression failed: {e}"),
    })?;
    if is_decompression_bomb(data.len(), out.len()) {
        return Err(ExtractError::DecompressionBomb { format: "bzip2" });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Concretely typed GZIP helpers
// ---------------------------------------------------------------------------

fn gzip_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let d = decompress_gzip(data)?;
    if is_tar(&d) {
        tar_to_memory(&d)
    } else {
        Ok(vec![ExtractedEntry {
            name: "decompressed".to_string(),
            size_real: d.len() as u64,
            file_pos: 0,
            data: d,
        }])
    }
}

fn xz_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let d = decompress_xz(data)?;
    if is_tar(&d) {
        tar_to_memory(&d)
    } else {
        Ok(vec![ExtractedEntry {
            name: "decompressed".to_string(),
            size_real: d.len() as u64,
            file_pos: 0,
            data: d,
        }])
    }
}

fn bzip2_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let d = decompress_bzip2(data)?;
    if is_tar(&d) {
        tar_to_memory(&d)
    } else {
        Ok(vec![ExtractedEntry {
            name: "decompressed".to_string(),
            size_real: d.len() as u64,
            file_pos: 0,
            data: d,
        }])
    }
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

/// Decompress ZIP entries in parallel using ripzip for central-directory
/// parsing + per-entry extraction. The central directory is parsed once
/// (instead of per-thread), then each thread extracts a contiguous chunk of
/// entries via `extract_ripzip_entry`.
/// Hard cap on entries extracted from a single archive in one call — without
/// this, a zip/tar/7z/rar bomb with an enormous entry count would be fully
/// decompressed into memory before the caller's outer buffer cap ever runs.
pub(crate) const MAX_ARCHIVE_ENTRIES: usize = 4096;

/// Skip full decompression for entries whose name + size make them unlikely
/// to be relevant — a name-based pre-filter that mirrors the post-decompress
/// [`is_relevant_buffer`] logic in the caller.  Large files with no executable
/// or security-relevant extension are almost never worth inflating.
fn should_extract_by_name(name: &str, uncompressed_size: u64, relevant_only: bool) -> bool {
    if !relevant_only {
        return true;
    }

    let lower = name.to_ascii_lowercase();
    let filename = lower.split(['/', '!']).last().unwrap_or(&lower);

    // Always extract known executable/archive/security types.
    if filename == "androidmanifest.xml"
        || (lower.contains("classes")
            && (lower.ends_with(".dex")
                || lower.ends_with(".vdex")
                || lower.ends_with(".odex")))
        || lower.ends_with(".so")
        || lower.ends_with(".apk")
        || lower.ends_with(".zip")
        || lower.ends_with(".jar")
        || lower.ends_with(".class")
        || lower.ends_with(".sh")
        || lower.ends_with(".elf")
        || lower.ends_with(".dex")
        || lower.ends_with(".vdex")
        || lower.ends_with(".odex")
        || lower.ends_with(".rsa")
        || lower.ends_with(".dsa")
        || lower.ends_with(".ec")
        || lower.ends_with(".sf")
        || lower.ends_with(".mf")
    {
        return true;
    }

    // Files with no '.' in the filename part — potential polyglot / hidden data.
    if !filename.contains('.') {
        return true;
    }

    // Small files of any type might hide polyglot content; decompress them.
    const SMALL_FILE_THRESHOLD: u64 = 256 * 1024; // 256 KiB
    if uncompressed_size <= SMALL_FILE_THRESHOLD {
        return true;
    }

    false
}

fn is_harmless_asset_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".bmp")
        || lower.ends_with(".webp")
        || lower.ends_with(".tiff")
        || lower.ends_with(".tif")
        || lower.ends_with(".ico")
        || lower.ends_with(".svg")
        || lower.ends_with(".heic")
        || lower.ends_with(".heif")
        || lower.ends_with(".avif")
        || lower.ends_with(".mp3")
        || lower.ends_with(".wav")
        || lower.ends_with(".ogg")
        || lower.ends_with(".aac")
        || lower.ends_with(".flac")
        || lower.ends_with(".m4a")
        || lower.ends_with(".mp4")
        || lower.ends_with(".mkv")
        || lower.ends_with(".webm")
        || lower.ends_with(".3gp")
        || lower.ends_with(".ttf")
        || lower.ends_with(".otf")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".css")
}

fn zip_to_memory(data: &[u8], relevant_only: bool) -> Result<Vec<ExtractedEntry>> {
    use ripzip::extract::zip_reader::parse_archive;

    let info = parse_archive(data).map_err(map_err)?;

    let entries_to_extract: Vec<(usize, &ripzip::extract::zip_reader::ZipEntry)> = info.entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            if e.is_dir { return false; }
            if is_harmless_asset_extension(&e.file_name) { return false; }
            should_extract_by_name(&e.file_name, e.uncompressed_size, relevant_only)
        })
        .take(MAX_ARCHIVE_ENTRIES)
        .collect();

    if entries_to_extract.is_empty() {
        return Ok(Vec::new());
    }

    let n_threads = extractor_worker_count();
    let chunk_size = (entries_to_extract.len() + n_threads - 1) / n_threads;

    let (tx, rx) = std::sync::mpsc::channel::<Vec<ExtractedEntry>>();
    let bomb_found = std::sync::atomic::AtomicBool::new(false);
    let bomb_found_ref = &bomb_found;

    std::thread::scope(|s| {
        for chunk in entries_to_extract.chunks(chunk_size) {
            let tx = tx.clone();
            s.spawn(move || {
                let mut local = Vec::with_capacity(chunk.len());
                for (_, entry) in chunk {
                    let content = match extract_ripzip_entry(data, entry) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    if is_decompression_bomb(entry.compressed_size as usize, content.len()) {
                        bomb_found_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        local.push(ExtractedEntry {
                            name: entry.file_name.clone(),
                            size_real: entry.uncompressed_size,
                            file_pos: entry.local_header_offset,
                            data: content,
                        });
                    }
                }
                let _ = tx.send(local);
            });
        }
        drop(tx);
    });

    if bomb_found.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(ExtractError::DecompressionBomb { format: "zip" });
    }

    let mut out = Vec::with_capacity(entries_to_extract.len());
    while let Ok(chunk) = rx.recv() {
        out.extend(chunk);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// TAR
// ---------------------------------------------------------------------------

fn tar_entries(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let mut archive = tar::Archive::new(data);
    let mut out = Vec::new();
    for entry in archive.entries().map_err(|e| ExtractError::OperationFailed {
        reason: format!("tar entries failed: {e}"),
    })? {
        let mut entry = entry.map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar entry read failed: {e}"),
        })?;
        let path = entry.path().map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar entry path failed: {e}"),
        })?;
        let name = path.to_string_lossy().to_string();
        if name.ends_with('/') {
            continue;
        }
        let size_real = entry.size();
        let mut data_buf = Vec::new();
        entry.read_to_end(&mut data_buf).map_err(|e| ExtractError::OperationFailed {
            reason: format!("tar entry data read failed: {e}"),
        })?;
        out.push(ExtractedEntry {
            name,
            size_real,
            file_pos: 0,
            data: data_buf,
        });
        if out.len() >= MAX_ARCHIVE_ENTRIES {
            break;
        }
    }
    Ok(out)
}

fn tar_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    tar_entries(data)
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

fn sz_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    use std::io::Write;
    let dir = tempfile::tempdir().map_err(|e| ExtractError::OperationFailed {
        reason: format!("temp dir creation failed: {e}"),
    })?;
    let input_path = dir.path().join("archive.7z");
    let out_dir = dir.path().join("out");
    std::fs::create_dir_all(&out_dir).map_err(|e| ExtractError::OperationFailed {
        reason: format!("output dir creation failed: {e}"),
    })?;
    {
        let mut f = std::fs::File::create(&input_path).map_err(|e| ExtractError::OperationFailed {
            reason: format!("temp file creation failed: {e}"),
        })?;
        f.write_all(data).map_err(|e| ExtractError::OperationFailed {
            reason: format!("temp file write failed: {e}"),
        })?;
    }
    sevenz_rust2::decompress_file(&input_path, &out_dir).map_err(|e| ExtractError::OperationFailed {
        reason: format!("7z decompress failed: {e}"),
    })?;
    let mut file_paths = Vec::new();
    collect_files(&out_dir, &mut file_paths);
    let mut out = Vec::new();
    for p in file_paths {
        let rel = p.strip_prefix(&out_dir).unwrap_or(&p).to_string_lossy().to_string();
        let content = std::fs::read(&p).map_err(|e| ExtractError::OperationFailed {
            reason: format!("7z entry read failed: {e}"),
        })?;
        if is_decompression_bomb(data.len(), content.len()) {
            return Err(ExtractError::DecompressionBomb { format: "7z" });
        }
        if !content.is_empty() {
            out.push(ExtractedEntry {
                name: rel,
                size_real: content.len() as u64,
                file_pos: 0,
                data: content,
            });
        }
        if out.len() >= MAX_ARCHIVE_ENTRIES {
            break;
        }
    }
    Ok(out)
}

fn sz_list_entries(data: &[u8]) -> Result<Vec<EntryInfo>> {
    let entries = sz_to_memory(data)?;
    Ok(entries.into_iter().map(|e| EntryInfo { name: e.name, size: e.size_real }).collect())
}

fn sz_extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    let entries = sz_to_memory(data)?;
    entries.into_iter().find(|e| e.name == name).map(|e| e.data)
        .ok_or_else(|| ExtractError::OperationFailed {
            reason: format!("entry not found in 7z: {name}"),
        })
}

// ---------------------------------------------------------------------------
// ISO
// ---------------------------------------------------------------------------

fn iso_entries(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    let mut cursor = Cursor::new(data);
    let root = isomage::detect_and_parse_filesystem(&mut cursor, "image.iso")
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("ISO parse failed: {e}"),
        })?;
    let mut out = Vec::new();
    collect_iso_entries(&mut cursor, &root, &mut out, data.len())?;
    Ok(out)
}

fn collect_iso_entries(
    reader: &mut (impl Read + Seek),
    node: &isomage::TreeNode,
    entries: &mut Vec<ExtractedEntry>,
    compressed_len: usize,
) -> Result<()> {
    for child in &node.children {
        if entries.len() >= MAX_ARCHIVE_ENTRIES {
            break;
        }
        if child.is_directory {
            collect_iso_entries(reader, child, entries, compressed_len)?;
        } else {
            let mut buf = Vec::new();
            isomage::cat_node(reader, child, &mut buf).map_err(|e| ExtractError::OperationFailed {
                reason: format!("ISO read failed: {e}"),
            })?;
            if is_decompression_bomb(compressed_len, buf.len()) {
                return Err(ExtractError::DecompressionBomb { format: "iso" });
            }
            entries.push(ExtractedEntry {
                name: child.name.clone(),
                size_real: child.size,
                file_pos: 0,
                data: buf,
            });
        }
    }
    Ok(())
}

fn iso_to_memory(data: &[u8]) -> Result<Vec<ExtractedEntry>> {
    iso_entries(data)
}

fn iso_list_entries(data: &[u8]) -> Result<Vec<EntryInfo>> {
    let entries = iso_entries(data)?;
    Ok(entries.into_iter().map(|e| EntryInfo { name: e.name, size: e.size_real }).collect())
}

fn iso_extract_entry(data: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(data);
    let root = isomage::detect_and_parse_filesystem(&mut cursor, "image.iso")
        .map_err(|e| ExtractError::OperationFailed {
            reason: format!("ISO parse failed: {e}"),
        })?;
    let node = root.find_node(name).ok_or_else(|| ExtractError::OperationFailed {
        reason: format!("entry not found in ISO: {name}"),
    })?;
    let mut buf = Vec::new();
    isomage::cat_node(&mut cursor, node, &mut buf).map_err(|e| ExtractError::OperationFailed {
        reason: format!("ISO read failed: {e}"),
    })?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn rand_byte() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos as u32).wrapping_mul(6364136223846793005u64 as u32)
}

pub(crate) fn safe_output_path(output_dir: &Path, name: &str) -> Option<PathBuf> {
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

pub(crate) fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
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
    use std::io::Write;

    // ── Format detection ────────────────────────────────────────

    #[test]
    fn detects_rar_signature() {
        let rar5 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
        assert_eq!(detect_format(&rar5), Some("rar"));
        let rar15 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
        assert_eq!(detect_format(&rar15), Some("rar"));
        let not_rar = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&not_rar), None);
    }

    #[test]
    fn detects_zip() {
        assert_eq!(detect_format(&[0x50, 0x4b, 0x03, 0x04]), Some("zip"));
    }

    #[test]
    fn detects_gzip() {
        assert_eq!(detect_format(&[0x1f, 0x8b]), Some("gz"));
    }

    #[test]
    fn detects_xz() {
        assert_eq!(
            detect_format(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
            Some("xz")
        );
    }

    #[test]
    fn detects_tar() {
        let mut tar = [0u8; 300];
        tar[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5].copy_from_slice(b"ustar");
        assert_eq!(detect_format(&tar), Some("tar"));
    }

    #[test]
    fn detects_lzma() {
        assert_eq!(detect_format(&[0x5d, 0x00]), Some("lzma"));
    }

    #[test]
    fn detects_iso() {
        let mut iso = vec![0u8; ISO_MAGIC_OFFSET + 10];
        iso[ISO_MAGIC_OFFSET..ISO_MAGIC_OFFSET + 5].copy_from_slice(b"CD001");
        assert_eq!(detect_format(&iso), Some("iso"));
    }

    #[test]
    fn detects_7z() {
        assert_eq!(
            detect_format(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
            Some("7z")
        );
    }

    // ── Gzip roundtrip ──────────────────────────────────────────

    #[test]
    fn gzip_roundtrip() {
        let input = b"Hello HydraDragon gzip test\x00\x01\x02\x03";
        let mut compressed = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::fast());
            enc.write_all(input).unwrap();
            enc.finish().unwrap();
        }
        assert_eq!(detect_format(&compressed), Some("gz"));
        let entries = extract_to_memory(&compressed, false).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "decompressed");
        assert_eq!(entries[0].data, input);
    }

    #[test]
    fn gzip_tar_roundtrip() {
        let content = b"nested tar content";
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path("inner.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&tar_bytes).unwrap();
            enc.finish().unwrap();
        }
        assert_eq!(detect_format(&gz), Some("gz"));
        let entries = extract_to_memory(&gz, false).unwrap();
        assert_eq!(entries.len(), 1, "tar.gz should yield the inner tar entry");
        assert_eq!(entries[0].name, "inner.txt");
        assert_eq!(entries[0].data, content);
    }

    // ── Xz roundtrip ────────────────────────────────────────────

    #[test]
    fn xz_roundtrip() {
        let input = b"xz payload data \xf0\xf1\xf2\xf3";
        let compressed = {
            let mut buf = Vec::new();
            let mut enc = lzma_rust2::XzWriter::new(&mut buf, lzma_rust2::XzOptions::default()).unwrap();
            enc.write_all(input).unwrap();
            enc.finish().unwrap();
            buf
        };
        assert_eq!(detect_format(&compressed), Some("xz"));
        let entries = extract_to_memory(&compressed, false).unwrap();
        assert_eq!(entries[0].data, input);
    }

    // ── Bzip2 roundtrip ─────────────────────────────────────────

    #[test]
    fn bzip2_roundtrip() {
        let input = b"bzip2 roundtrip works! \r\nline2";
        let compressed = {
            let mut buf = Vec::new();
            let mut enc = bzip2::write::BzEncoder::new(&mut buf, bzip2::Compression::fast());
            enc.write_all(input).unwrap();
            enc.finish().unwrap();
            buf
        };
        assert_eq!(detect_format(&compressed), Some("bz2"));
        let entries = extract_to_memory(&compressed, false).unwrap();
        assert_eq!(entries[0].data, input);
    }

    // ── Tar roundtrip ───────────────────────────────────────────

    #[test]
    fn tar_roundtrip() {
        let content1 = b"first file content";
        let content2 = b"second file with \x00\xff bytes";
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut h1 = tar::Header::new_gnu();
            h1.set_path("a.txt").unwrap();
            h1.set_size(content1.len() as u64);
            h1.set_cksum();
            builder.append(&h1, &content1[..]).unwrap();

            let mut h2 = tar::Header::new_gnu();
            h2.set_path("sub/b.bin").unwrap();
            h2.set_size(content2.len() as u64);
            h2.set_cksum();
            builder.append(&h2, &content2[..]).unwrap();
            builder.finish().unwrap();
        }
        assert_eq!(detect_format(&tar_bytes), Some("tar"));

        let infos = list_entries(&tar_bytes).unwrap();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].name, "a.txt");
        assert_eq!(infos[1].name, "sub/b.bin");

        let extracted = extract_entry(&tar_bytes, "sub/b.bin").unwrap();
        assert_eq!(extracted, content2);

        let all = extract_to_memory(&tar_bytes, false).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "a.txt");
        assert_eq!(all[0].data, content1);
        assert_eq!(all[1].name, "sub/b.bin");
        assert_eq!(all[1].data, content2);
    }

    #[test]
    fn tar_missing_entry_returns_error() {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut h = tar::Header::new_gnu();
            h.set_path("present.txt").unwrap();
            h.set_size(4);
            h.set_cksum();
            builder.append(&h, &b"data"[..]).unwrap();
            builder.finish().unwrap();
        }
        let err = extract_entry(&tar_bytes, "nonexistent.txt").unwrap_err();
        assert!(err.to_string().contains("not found in tar"));
    }

    // ── Compression bomb guard ──────────────────────────────────

    fn setup_bomb_detection(enabled: bool) {
        DETECT_BOMBS.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn bomb_detection_rejects_high_ratio() {
        setup_bomb_detection(true);
        let small = vec![0u8; 16];
        let big = vec![0u8; 16_001_000];
        assert!(is_decompression_bomb(small.len(), big.len()));
    }

    #[test]
    fn bomb_detection_allows_small_ratio() {
        setup_bomb_detection(true);
        assert!(!is_decompression_bomb(1000, 500_000));
    }

    #[test]
    fn bomb_detection_disabled_allows_anything() {
        setup_bomb_detection(false);
        assert!(!is_decompression_bomb(1, MAX_DECOMPRESSED_SIZE + 1));
        setup_bomb_detection(true);
    }

    // ── Safe output path ────────────────────────────────────────

    #[test]
    fn safe_output_path_rejects_absolute() {
        let base = Path::new("/tmp/out");
        assert!(safe_output_path(base, "/etc/passwd").is_none());
    }

    #[test]
    fn safe_output_path_rejects_parent_escape() {
        let base = Path::new("/tmp/out");
        assert!(safe_output_path(base, "../../etc/passwd").is_none());
    }

    #[test]
    fn safe_output_path_allows_normal() {
        let base = Path::new("/tmp/out");
        let got = safe_output_path(base, "sub/dir/file.txt");
        assert_eq!(got, Some(PathBuf::from("/tmp/out/sub/dir/file.txt")));
    }

    // ── Unsupported formats ─────────────────────────────────────

    #[test]
    fn detect_unknown_format_returns_none() {
        assert_eq!(detect_format(b"\x00\x01\x02\x03\x04\x05\x06\x07"), None);
        assert_eq!(detect_format(b""), None);
        assert_eq!(detect_format(b"hello world"), None);
    }

    #[test]
    fn extract_invalid_data_returns_err() {
        assert!(extract_to_memory(b"not an archive at all", false).is_err());
    }
}
