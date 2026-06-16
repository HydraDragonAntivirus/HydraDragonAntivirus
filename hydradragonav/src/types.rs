use serde::Serialize;

// ---------------------------------------------------------------------------
// Return codes (cl_error_t)
// ---------------------------------------------------------------------------
pub const CL_CLEAN: i32 = 0;
pub const CL_VIRUS: i32 = 1;
pub const CL_SUCCESS: i32 = 0;

// ---------------------------------------------------------------------------
// Database load flags
// From clamav.h: CL_DB_STDOPT = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE
// ---------------------------------------------------------------------------
pub const CL_DB_PHISHING:      u32 = 0x2;
pub const CL_DB_PHISHING_URLS: u32 = 0x8;
pub const CL_DB_BYTECODE:      u32 = 0x2000;
pub const CL_DB_STDOPT:        u32 = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE;

// ---------------------------------------------------------------------------
// Scan option flags — general
// ---------------------------------------------------------------------------
pub const CL_SCAN_GENERAL_HEURISTICS: u32 = 0x4;

// ---------------------------------------------------------------------------
// Scan option flags — parse
// Values from clamav.h CL_SCAN_PARSE_* defines
// ---------------------------------------------------------------------------
pub const CL_SCAN_PARSE_ARCHIVE:  u32 = 0x1;
pub const CL_SCAN_PARSE_ELF:      u32 = 0x2;
pub const CL_SCAN_PARSE_PDF:      u32 = 0x4;
pub const CL_SCAN_PARSE_SWF:      u32 = 0x8;
pub const CL_SCAN_PARSE_HWP3:     u32 = 0x10;
pub const CL_SCAN_PARSE_XMLDOCS:  u32 = 0x20;
pub const CL_SCAN_PARSE_MAIL:     u32 = 0x40;
pub const CL_SCAN_PARSE_OLE2:     u32 = 0x80;
pub const CL_SCAN_PARSE_HTML:     u32 = 0x100;
pub const CL_SCAN_PARSE_PE:       u32 = 0x200;

// ---------------------------------------------------------------------------
// Engine field ordinals — from enum cl_engine_field in clamav.h
// ---------------------------------------------------------------------------
pub const CL_ENGINE_MAX_SCANSIZE:   u32 = 0;  // uint64_t — total bytes across all recursive layers
pub const CL_ENGINE_MAX_FILESIZE:   u32 = 1;  // uint64_t — per-file size limit
pub const CL_ENGINE_MAX_RECURSION:  u32 = 2;  // uint32_t — max extraction depth
pub const CL_ENGINE_MAX_FILES:      u32 = 3;  // uint32_t — max files extracted during scan
pub const CL_ENGINE_MAX_EMBEDDEDPE: u32 = 18; // uint64_t — ordinal 18 in the enum

// ---------------------------------------------------------------------------
// Engine defaults
//
// MAX_SCANSIZE is the key knob: it caps the u32 accumulator in the scan
// callback before it can overflow UINT32_MAX and emit the warning.
// 32 MiB is plenty for file-by-file scanning; raise if you scan archives.
//
// Tuple is (field_ordinal: u32, value: u64) — cl_engine_set_num takes long long.
// ---------------------------------------------------------------------------
pub const DEFAULT_ENGINE_OPTIONS: [(u32, u32); 4] = [
    (CL_ENGINE_MAX_SCANSIZE,   32 * 1024 * 1024),  // 32 MiB total recursive scan budget
    (CL_ENGINE_MAX_FILESIZE,   32 * 1024 * 1024),  // 32 MiB per file
    (CL_ENGINE_MAX_RECURSION,  10),                 // was 50; deep recursion multiplies byte counts fast
    (CL_ENGINE_MAX_FILES,      200),                // replaces the old MAX_EMBEDDEDPE at wrong ordinal
];

// ---------------------------------------------------------------------------
// Scan options struct — mirrors struct cl_scan_options in clamav.h
// ---------------------------------------------------------------------------
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
            parse: CL_SCAN_PARSE_PE
                | CL_SCAN_PARSE_ELF
                | CL_SCAN_PARSE_PDF
                | CL_SCAN_PARSE_OLE2
                | CL_SCAN_PARSE_HTML
                | CL_SCAN_PARSE_XMLDOCS,
            heuristic: 0,
            mail: 0,
            dev: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Scan result
// bytes_scanned is u64 to match cl_engine_set_num / uint64_t semantics.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub result_code: i32,
    pub virus_name: String,
    pub bytes_scanned: u64,
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

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------
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
