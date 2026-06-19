use std::path::Path;

use crate::error::{AvError, AvResult};

/// Re-export the hydradragonextractor types + functions for backward compat.
pub use hydradragonextractor::{detect_format, ExtractResult};

/// Extract any supported archive by content sniffing.
///
/// Delegates to `hydradragonextractor::extract_archive` and converts errors.
pub fn extract_archive(path: &Path, output_dir: &Path) -> AvResult<ExtractResult> {
    hydradragonextractor::extract_archive(path, output_dir).map_err(|e| AvError::OperationFailed {
        reason: e.to_string(),
    })
}
