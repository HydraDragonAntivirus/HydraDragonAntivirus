//! Storage of VirusKovAlyzer static reports: `reports/<ab>/<sha256>.json` next to the
//! executable (sharded by the first two hex characters so no folder grows too large).

use std::path::PathBuf;

use crate::analyzer::FileReport;

fn path_for(sha_lower: &str) -> Option<PathBuf> {
    if sha_lower.len() != 64 || !sha_lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(crate::config::app_dir().join("reports").join(&sha_lower[..2]).join(format!("{sha_lower}.json")))
}

pub fn exists(sha256: &str) -> bool {
    path_for(&sha256.to_ascii_lowercase()).is_some_and(|p| p.is_file())
}

/// Writes the report once; an existing report is kept (same bytes give the same report).
pub fn save(report: &FileReport) {
    let Some(p) = path_for(&report.hashes.sha256.to_ascii_lowercase()) else { return };
    if p.is_file() {
        return;
    }
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_vec(report) {
        let tmp = p.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
}

pub fn load(sha256: &str) -> Option<serde_json::Value> {
    let p = path_for(&sha256.to_ascii_lowercase())?;
    let bytes = std::fs::read(p).ok()?;
    serde_json::from_slice(&bytes).ok()
}
