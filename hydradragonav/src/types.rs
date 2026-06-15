use serde::Serialize;

pub const CL_CLEAN: i32 = 0;
pub const CL_VIRUS: i32 = 1;
pub const CL_SUCCESS: i32 = 0;

pub const CL_DB_STDOPT: u32 = 0;
pub const CL_SCAN_GENERAL_HEURISTICS: u32 = 1 << 2;

pub const CL_SCAN_PARSE_ELF: u32 = 1 << 0;
pub const CL_SCAN_PARSE_PDF: u32 = 1 << 5;
pub const CL_SCAN_PARSE_SWF: u32 = 1 << 8;
pub const CL_SCAN_PARSE_XMLDOCS: u32 = 1 << 10;
pub const CL_SCAN_PARSE_HWP3: u32 = 1 << 11;

pub const CL_ENGINE_MAX_SCANS: u32 = 0;
pub const CL_ENGINE_MAX_FILESIZE: u32 = 1;
pub const CL_ENGINE_MAX_RECURSION: u32 = 2;
pub const CL_ENGINE_MAX_EMBEDDEDPE: u32 = 3;

pub const DEFAULT_ENGINE_OPTIONS: [(u32, u32); 4] = [
    (CL_ENGINE_MAX_SCANS, 512 * 1024 * 1024),
    (CL_ENGINE_MAX_FILESIZE, 512 * 1024 * 1024),
    (CL_ENGINE_MAX_RECURSION, 50),
    (CL_ENGINE_MAX_EMBEDDEDPE, 2000),
];

#[repr(C)]
pub struct ClScanOptions {
    pub general: u32,
    pub parse: u32,
    pub heuristic: u32,
    pub mail: u32,
    pub dev: u32,
}

impl Default for ClScanOptions {
    fn default() -> Self {
        Self {
            general: CL_SCAN_GENERAL_HEURISTICS,
            parse: 0,
            heuristic: 0,
            mail: 0,
            dev: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub result_code: i32,
    pub virus_name: String,
    pub bytes_scanned: u32,
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
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Library path does not exist: {0}")]
    LibraryNotFound(String),
    #[error("Failed to load library: {0}")]
    LoadLibrary(String),
    #[error("Missing required export: {0}")]
    MissingExport(&'static str),
    #[error("ClamAV initialization failed: {0}")]
    ClamavInit(String),
    #[error("Database path invalid: {0}")]
    DatabasePath(String),
    #[error("Database load failed: {0}")]
    DatabaseLoad(String),
    #[error("Engine compile failed: {0}")]
    EngineCompile(String),
    #[error("Scanner not ready")]
    NotReady,
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("File is not a regular file: {0}")]
    NotRegularFile(String),
    #[error("Scan failed: {0}")]
    ScanError(String),
    #[error("Freshclam not found at: {0}")]
    FreshclamNotFound(String),
    #[error("Freshclam execution error: {0}")]
    FreshclamError(String),
    #[error("Freshclam timed out")]
    FreshclamTimeout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
