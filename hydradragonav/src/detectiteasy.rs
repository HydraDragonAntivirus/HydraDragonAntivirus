use std::path::{Path, PathBuf};

use die::ScanFlags;

pub const MAX_SCAN_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_DIE_FILE_SIZE: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DetectItEasyResult {
    pub scan_ok: bool,
    pub scan_error: Option<String>,
    pub die_output: String,
    pub is_unknown: bool,
    pub is_plain_text: bool,
    pub file_type: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DetectItEasyScanner {
    db_path: Option<PathBuf>,
}

impl DetectItEasyScanner {
    pub fn new(configured_dir: Option<&Path>) -> Self {
        Self {
            db_path: configured_dir.map(|p| p.to_path_buf()),
        }
    }

    pub fn scan_file(&self, path: &Path) -> DetectItEasyResult {
        let result = match self.db_path.as_ref().filter(|p| p.exists()) {
            Some(db) => die::scan_file_with_db(path, ScanFlags::DEEP_SCAN, db),
            None => die::scan_file(path, ScanFlags::DEEP_SCAN),
        };
        match result {
            Ok(die_output) => parse_die_output(&die_output),
            Err(err) => DetectItEasyResult::error(format!("die scan failed: {err}")),
        }
    }
}

impl DetectItEasyResult {
    fn error(error: impl Into<String>) -> Self {
        Self {
            scan_ok: false,
            scan_error: Some(error.into()),
            die_output: String::new(),
            is_unknown: false,
            is_plain_text: false,
            file_type: None,
        }
    }
}

fn parse_die_output(die_output: &str) -> DetectItEasyResult {
    let lines: Vec<&str> = die_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let lower = die_output.to_ascii_lowercase();
    let is_unknown = lines.len() >= 2 && lines[0] == "Binary" && lines[1] == "Unknown: Unknown";
    let is_plain_text = lower.contains("format: plain text");
    let file_type = extract_file_type(&lines);

    DetectItEasyResult {
        scan_ok: true,
        scan_error: None,
        die_output: die_output.to_string(),
        is_unknown,
        is_plain_text,
        file_type,
    }
}

fn extract_file_type(lines: &[&str]) -> Option<String> {
    for line in lines {
        if line.starts_with("PE32") {
            return Some("PE32".to_string());
        }
        if line.starts_with("PE64") {
            return Some("PE64".to_string());
        }
        if line.starts_with("ELF32") {
            return Some("ELF32".to_string());
        }
        if line.starts_with("ELF64") {
            return Some("ELF64".to_string());
        }
        if line.starts_with("Mach-O") {
            return Some("Mach-O".to_string());
        }
        if let Some(value) = line.strip_prefix("Format:") {
            return Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("Archive:") {
            return Some(format!("Archive: {}", value.trim()));
        }
    }

    None
}
