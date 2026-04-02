//! Filesystem checking module
//!
//! Provides functions to check file and directory existence, attributes, etc.

use crate::{CheckResult, Result, SignatureMonsterError};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::Foundation::*;
use windows::core::PCWSTR;
use std::path::Path;

/// Filesystem checker
pub struct FilesystemChecker {
    _private: (),
}

impl FilesystemChecker {
    /// Create a new filesystem checker
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Convert a string to wide string (null-terminated)
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Check if a file exists
    pub fn file_exists(&self, path: &str) -> bool {
        let wide_path = Self::to_wide(path);
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };
        
        if attrs == INVALID_FILE_ATTRIBUTES {
            return false;
        }
        
        // Check it's not a directory
        (attrs & FILE_ATTRIBUTE_DIRECTORY.0) == 0
    }

    /// Check if a directory exists
    pub fn directory_exists(&self, path: &str) -> bool {
        let wide_path = Self::to_wide(path);
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };
        
        if attrs == INVALID_FILE_ATTRIBUTES {
            return false;
        }
        
        // Check it is a directory
        (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0
    }

    /// Check if a path exists (file or directory)
    pub fn path_exists(&self, path: &str) -> bool {
        let wide_path = Self::to_wide(path);
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };
        attrs != INVALID_FILE_ATTRIBUTES
    }

    /// Get file attributes
    pub fn get_attributes(&self, path: &str) -> Result<FileAttributes> {
        let wide_path = Self::to_wide(path);
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };
        
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(SignatureMonsterError::IoError(std::io::Error::last_os_error()));
        }
        
        Ok(FileAttributes {
            raw: attrs,
            readonly: (attrs & FILE_ATTRIBUTE_READONLY.0) != 0,
            hidden: (attrs & FILE_ATTRIBUTE_HIDDEN.0) != 0,
            system: (attrs & FILE_ATTRIBUTE_SYSTEM.0) != 0,
            directory: (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0,
            archive: (attrs & FILE_ATTRIBUTE_ARCHIVE.0) != 0,
            encrypted: (attrs & FILE_ATTRIBUTE_ENCRYPTED.0) != 0,
            compressed: (attrs & FILE_ATTRIBUTE_COMPRESSED.0) != 0,
            temporary: (attrs & FILE_ATTRIBUTE_TEMPORARY.0) != 0,
        })
    }

    /// Check if file has specific attribute
    pub fn has_attribute(&self, path: &str, attribute: FileAttributeType) -> bool {
        match self.get_attributes(path) {
            Ok(attrs) => match attribute {
                FileAttributeType::ReadOnly => attrs.readonly,
                FileAttributeType::Hidden => attrs.hidden,
                FileAttributeType::System => attrs.system,
                FileAttributeType::Directory => attrs.directory,
                FileAttributeType::Archive => attrs.archive,
                FileAttributeType::Encrypted => attrs.encrypted,
                FileAttributeType::Compressed => attrs.compressed,
                FileAttributeType::Temporary => attrs.temporary,
            },
            Err(_) => false,
        }
    }

    /// Check if a file path matches a pattern (case-insensitive)
    pub fn path_matches(&self, path: &str, pattern: &str) -> CheckResult {
        let normalized = path.to_lowercase().replace('/', "\\");
        let pattern_lower = pattern.to_lowercase();
        
        if normalized.contains(&pattern_lower) {
            CheckResult::matched(path)
        } else {
            CheckResult::not_matched()
        }
    }

    /// Check if a file path matches a regex pattern
    pub fn path_matches_regex(&self, path: &str, pattern: &str) -> Result<CheckResult> {
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        
        if re.is_match(path) {
            Ok(CheckResult::matched(path))
        } else {
            Ok(CheckResult::not_matched())
        }
    }

    /// Get file size in bytes
    pub fn get_file_size(&self, path: &str) -> Result<u64> {
        let wide_path = Self::to_wide(path);
        
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        let mut size: i64 = 0;
        let result = unsafe { GetFileSizeEx(handle, &mut size) };
        unsafe { let _ = CloseHandle(handle); }

        if result.is_ok() {
            Ok(size as u64)
        } else {
            Err(SignatureMonsterError::IoError(std::io::Error::last_os_error()))
        }
    }

    /// Check if file is larger than a given size
    pub fn is_larger_than(&self, path: &str, size_bytes: u64) -> bool {
        match self.get_file_size(path) {
            Ok(actual) => actual > size_bytes,
            Err(_) => false,
        }
    }

    /// Check if file is smaller than a given size
    pub fn is_smaller_than(&self, path: &str, size_bytes: u64) -> bool {
        match self.get_file_size(path) {
            Ok(actual) => actual < size_bytes,
            Err(_) => false,
        }
    }

    /// Get the extension of a file path
    pub fn get_extension(&self, path: &str) -> Option<String> {
        Path::new(path)
            .extension()
            .map(|ext| ext.to_string_lossy().to_lowercase())
    }

    /// Check if file has a specific extension
    pub fn has_extension(&self, path: &str, extension: &str) -> bool {
        match self.get_extension(path) {
            Some(ext) => ext == extension.to_lowercase().trim_start_matches('.'),
            None => false,
        }
    }

    /// Get the filename from a path
    pub fn get_filename(&self, path: &str) -> Option<String> {
        Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
    }

    /// Check if filename matches a pattern
    pub fn filename_matches(&self, path: &str, pattern: &str) -> bool {
        match self.get_filename(path) {
            Some(name) => name.to_lowercase().contains(&pattern.to_lowercase()),
            None => false,
        }
    }

    /// Enumerate files in a directory (non-recursive)
    pub fn list_directory(&self, dir_path: &str) -> Result<Vec<String>> {
        let pattern = format!("{}\\*", dir_path.trim_end_matches('\\'));
        let wide_pattern = Self::to_wide(&pattern);
        
        let mut find_data = WIN32_FIND_DATAW::default();
        let handle = unsafe {
            FindFirstFileW(PCWSTR(wide_pattern.as_ptr()), &mut find_data)
        }.map_err(|_| SignatureMonsterError::IoError(std::io::Error::last_os_error()))?;

        let mut files = Vec::new();
        
        loop {
            let filename = String::from_utf16_lossy(
                &find_data.cFileName[..find_data.cFileName.iter().position(|&c| c == 0).unwrap_or(find_data.cFileName.len())]
            );
            
            if filename != "." && filename != ".." {
                files.push(format!("{}\\{}", dir_path.trim_end_matches('\\'), filename));
            }

            if unsafe { FindNextFileW(handle, &mut find_data) }.is_err() {
                break;
            }
        }

        unsafe { let _ = FindClose(handle); }
        Ok(files)
    }
}

impl Default for FilesystemChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// File attribute types for checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAttributeType {
    ReadOnly,
    Hidden,
    System,
    Directory,
    Archive,
    Encrypted,
    Compressed,
    Temporary,
}

/// File attributes structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileAttributes {
    pub raw: u32,
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub temporary: bool,
}
