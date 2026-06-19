use std::path::{Path, PathBuf};

use crate::error::{AvError, AvResult};

/// Supported archive formats for extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    SevenZip,
    Zip,
}

/// Result of extracting an archive: list of extracted file paths.
pub struct ExtractResult {
    pub files: Vec<PathBuf>,
    pub output_dir: PathBuf,
}

/// Detect archive format from file extension.
pub fn detect_format(path: &Path) -> Option<ArchiveFormat> {
    match path.extension()?.to_str()?.to_lowercase().as_str() {
        "7z" => Some(ArchiveFormat::SevenZip),
        "zip" => Some(ArchiveFormat::Zip),
        _ => None,
    }
}

/// Extract a 7z archive to a temporary directory.
fn extract_7z(path: &Path, output_dir: &Path) -> AvResult<Vec<PathBuf>> {
    sevenz_rust2::decompress_file(path, output_dir)
        .map_err(|e| AvError::OperationFailed { reason: format!("7z extraction failed: {e}") })?;

    let mut files = Vec::new();
    collect_files(output_dir, &mut files, output_dir);
    Ok(files)
}

/// Extract a ZIP archive to a temporary directory.
fn extract_zip(path: &Path, output_dir: &Path) -> AvResult<Vec<PathBuf>> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| AvError::OperationFailed { reason: format!("zip open failed: {e}") })?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| AvError::OperationFailed { reason: format!("zip entry #{i}: {e}") })?;
        let entry_path = output_dir.join(entry.name());
        if entry.is_dir() {
            std::fs::create_dir_all(&entry_path)?;
        } else {
            if let Some(parent) = entry_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::File::create(&entry_path)?;
            std::io::copy(&mut entry, &mut out)?;
        }
    }

    let mut files = Vec::new();
    collect_files(output_dir, &mut files, output_dir);
    Ok(files)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, base: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, out, base);
            } else {
                out.push(path);
            }
        }
    }
}

/// Extract an archive file to a temporary directory.
/// Returns the list of extracted file paths.
pub fn extract_archive(path: &Path, output_dir: &Path) -> AvResult<ExtractResult> {
    let fmt = detect_format(path)
        .ok_or_else(|| AvError::OperationFailed { reason: format!("unsupported archive: {}", path.display()) })?;

    std::fs::create_dir_all(output_dir)?;

    let files = match fmt {
        ArchiveFormat::SevenZip => extract_7z(path, output_dir)?,
        ArchiveFormat::Zip => extract_zip(path, output_dir)?,
    };

    Ok(ExtractResult {
        files,
        output_dir: output_dir.to_path_buf(),
    })
}
