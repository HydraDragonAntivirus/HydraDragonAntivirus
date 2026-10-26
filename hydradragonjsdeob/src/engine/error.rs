//! Error types for the deobfuscator.
//!
//! Leaf type — no dependencies on other layers.

use thiserror::Error;

/// Deobfuscation error.
#[derive(Error, Debug)]
pub enum DeobError {
    /// Source code failed to parse.
    #[error("parse error: {0}")]
    Parse(String),

    /// A transformation pass failed.
    #[error("transform error in {pass}: {message}")]
    Transform {
        pass: &'static str,
        message: String,
    },
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, DeobError>;
