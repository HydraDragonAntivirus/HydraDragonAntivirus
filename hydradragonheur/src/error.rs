// error.rs — replaces HRESULT / DWORD error codes from TinyAntivirus.
// Maps the engine's EMULATOR_ERROR_CODE_BASE (100) and
// ENUMERATION_ERROR_CODE_BASE (200) families to proper Rust variants.

use thiserror::Error;

/// The central error type for the HydraDragon heuristic engine.
/// Replaces `HRESULT` and ad-hoc `DWORD` error codes used throughout TinyAntivirus.
#[derive(Debug, Error)]
pub enum AvError {
    // ------------------------------------------------------------------ I/O
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // ------------------------------------------------------------------ VFS
    #[error("file not found: {path}")]
    FileNotFound { path: String },

    #[error("file not opened")]
    FileNotOpened,

    #[error("invalid flags: 0x{flags:08x}")]
    InvalidFlags { flags: u32 },

    #[error("access denied")]
    AccessDenied,

    #[error("buffer too small (need {need}, got {got})")]
    BufferTooSmall { need: usize, got: usize },

    // ------------------------------------------------------------------ PE
    #[error("not a PE file")]
    NotPeFile,

    #[error("malformed PE: {reason}")]
    MalformedPe { reason: String },

    #[error("section index {index} out of range (count={count})")]
    SectionOutOfRange { index: usize, count: usize },

    #[error("RVA 0x{rva:08x} not in any section")]
    RvaNotMapped { rva: u32 },

    #[error("VA 0x{va:08x} not in any section")]
    VaNotMapped { va: u64 },

    // ------------------------------------------------------------------ Emulator (base 100)
    #[error("emulator error (code {code})")]
    EmulatorError { code: u32 },

    #[error("emulator not found")]
    EmulatorNotFound,

    #[error("emulator is not runnable")]
    EmulatorNotRunnable,

    #[error("emulator internal error: {reason}")]
    EmulatorInternal { reason: String },

    // ------------------------------------------------------------------ Enumeration (base 200)
    #[error("enumeration error (code {code})")]
    EnumerationError { code: u32 },

    #[error("enumeration access denied")]
    EnumAccessDenied,

    #[error("enumeration target not found")]
    EnumNotFound,

    // ------------------------------------------------------------------ Module
    #[error("module not found: {name}")]
    ModuleNotFound { name: String },

    #[error("module already registered: {name}")]
    ModuleAlreadyRegistered { name: String },

    // ------------------------------------------------------------------ Scanner
    #[error("scan aborted")]
    ScanAborted,

    #[error("invalid argument")]
    InvalidArgument,

    #[error("out of memory")]
    OutOfMemory,

    // ------------------------------------------------------------------ Generic
    #[error("operation failed: {reason}")]
    OperationFailed { reason: String },

    #[error("not implemented")]
    NotImplemented,
}

/// Convenience alias used throughout the crate.
pub type AvResult<T> = Result<T, AvError>;

impl AvError {
    /// Emulator error from a raw numeric code (mirrors EMULATOR_ERROR_CODE_BASE + N).
    pub fn emul(code: u32) -> Self {
        match code {
            100 => AvError::EmulatorError { code },
            101 => AvError::EmulatorNotFound,
            102 => AvError::EmulatorNotRunnable,
            103 => AvError::EmulatorInternal {
                reason: "internal emulator fault".into(),
            },
            c => AvError::EmulatorError { code: c },
        }
    }

    /// Enumeration error from a raw numeric code (mirrors ENUMERATION_ERROR_CODE_BASE + N).
    pub fn enumeration(code: u32) -> Self {
        match code {
            200 => AvError::EnumerationError { code },
            201 => AvError::EnumAccessDenied,
            202 => AvError::EnumNotFound,
            c => AvError::EnumerationError { code: c },
        }
    }
}
