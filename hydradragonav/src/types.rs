use serde::Serialize;

// ---------------------------------------------------------------------------
// Result codes
//
// Kept ClamAV-compatible so downstream consumers that switch on a numeric
// virus/clean code keep working after the move to the pure-Rust engine.
// ---------------------------------------------------------------------------
pub const CL_CLEAN: i32 = 0;
pub const CL_VIRUS: i32 = 1;

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub result_code: i32,
    pub virus_name: String,
    pub bytes_scanned: u64,
    /// Matched signature byte ranges `[start, end)` in the scanned file, usable
    /// for in-place disinfection. Only populated for raw top-level matches.
    #[serde(default)]
    pub arenas: Vec<(usize, usize)>,
    /// True when the matching signature came from an **unofficial** database
    /// (i.e. not ClamAV's official main/daily/bytecode), so the UI can tag it.
    #[serde(default)]
    pub unofficial: bool,
}

impl ScanResult {
    pub fn is_clean(&self) -> bool {
        self.result_code == CL_CLEAN
    }

    pub fn is_virus(&self) -> bool {
        self.result_code == CL_VIRUS
    }

    pub fn is_known_result(&self) -> bool {
        self.is_clean() || self.is_virus()
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            result_code: -1,
            virus_name: String::new(),
            bytes_scanned: 0,
            arenas: Vec::new(),
            unofficial: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database path invalid: {0}")]
    DatabasePath(String),
    #[error("Database load failed: {0}")]
    DatabaseLoad(String),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("File is not a regular file: {0}")]
    NotRegularFile(String),
    #[error("Freshclam not found at: {0}")]
    FreshclamNotFound(String),
    #[error("Freshclam execution error: {0}")]
    FreshclamError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
