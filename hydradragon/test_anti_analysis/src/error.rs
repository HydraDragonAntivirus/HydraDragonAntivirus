//! Error types for the Signature Monster SDK

use thiserror::Error;

/// Main error type for the SDK
#[derive(Error, Debug)]
pub enum SignatureMonsterError {
    #[error("Windows API error: {0}")]
    WindowsError(#[from] windows::core::Error),

    #[error("Registry error: {0}")]
    RegistryError(String),

    #[error("Process enumeration error: {0}")]
    ProcessError(String),

    #[error("Service enumeration error: {0}")]
    ServiceError(String),

    #[error("Task enumeration error: {0}")]
    TaskError(String),

    #[error("HWID retrieval error: {0}")]
    HwidError(String),

    #[error("PowerShell execution error: {0}")]
    PowerShellError(String),

    #[error("Regex error: {0}")]
    RegexError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

/// Result type alias for SDK operations
pub type Result<T> = std::result::Result<T, SignatureMonsterError>;
