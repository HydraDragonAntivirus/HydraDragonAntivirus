//! Signature-based disinfection and cloud restoration.
//!
//! REST (scan_server.rs): `POST /api/v1/disinfect`, `GET /api/v1/restore/:sha256`.
//!
//! Policy, which is also what the API tells clients in `recommended_action`:
//!
//! * The infected part is cut out only when a disinfector RECOGNISES the infection
//!   by signature (hydradragonunicorn: W32.Sality.PE today). A generic or ML
//!   detection is never "repaired": there is nothing known to remove.
//! * Disinfection is NOT the recommended action for ordinary files. A repaired
//!   program is not the vendor's file (a virus may have changed more than its
//!   signature shows), so the advice is to restore a clean copy or delete and
//!   reinstall. It is recommended only for Windows system files, which cannot
//!   simply be deleted. The repaired bytes stay available on explicit request
//!   (`?download=repaired`) for every file.
//! * Cloud restoration: the closest file this server keeps that is KNOWN clean
//!   (analyst-verified clean, or an exact member of the verified benign reference
//!   corpus) is offered as the replacement, after the same structure guard the
//!   smart whitelist uses (same sections, entry point, imports, no added payload).
//!   Engine-clean or unknown files are never offered.

use serde::Serialize;

use crate::engine_adapter::EngineAdapter;
use crate::fingerprint::{accept, Structure, SMART_WL_MAX_DIST, SMART_WL_MAX_DIST_EP_MOVED};
use crate::threat_intel::ThreatIntelStore;

/// What the client should do with the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Nothing known was found.
    None,
    /// Replace the file with the clean copy from `/api/v1/restore/<sha256>`.
    RestoreCleanCopy,
    /// System file without a clean copy here: use the repaired file.
    UseRepaired,
    /// Delete (or quarantine) the file and reinstall the program.
    Delete,
    /// System file that cannot be repaired here: repair Windows (`sfc /scannow`, DISM).
    RepairWindows,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreCandidate {
    pub sha256: String,
    pub size: u64,
    /// TLSH distance between the (repaired) file and the clean copy.
    pub distance: u32,
    /// "analyst-verified clean" or "benign reference corpus".
    pub source: &'static str,
    pub download: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisinfectReport {
    pub sha256: String,
    pub size: u64,
    /// A disinfector recognised the infection by signature.
    pub infected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malware_name: Option<String>,
    /// The infected part was removed (`?download=repaired` returns the bytes).
    pub repaired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repaired_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repaired_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_repairable_reason: Option<String>,
    /// The client path (`X-File-Path`) is a Windows system location.
    pub system_file: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_file_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreCandidate>,
    pub recommended_action: Action,
    pub advice: String,
}

/// Windows system locations (case-insensitive, `\\?\` and `/` tolerated).
/// Only these get disinfection as the recommended action.
pub fn system_path_reason(path: &str) -> Option<&'static str> {
    let p = path.trim().trim_start_matches(r"\\?\").replace('/', "\\").to_ascii_lowercase();
    if p.is_empty() {
        return None;
    }
    const DIRS: &[(&str, &str)] = &[
        (r"\windows\system32\", "Windows\\System32"),
        (r"\windows\syswow64\", "Windows\\SysWOW64"),
        (r"\windows\sysnative\", "Windows\\Sysnative"),
        (r"\windows\winsxs\", "Windows\\WinSxS (component store)"),
        (r"\windows\systemapps\", "Windows\\SystemApps"),
        (r"\windows\servicing\", "Windows\\servicing"),
        (r"\windows\boot\", "Windows\\Boot"),
        (r"\windows\microsoft.net\", "Windows\\Microsoft.NET"),
    ];
    for (needle, label) in DIRS {
        if p.contains(needle) {
            return Some(label);
        }
    }
    for root in [r"%systemroot%\", r"%windir%\"] {
        if let Some(rest) = p.strip_prefix(root) {
            if rest.starts_with(r"system32\") || rest.starts_with(r"syswow64\") || rest.starts_with(r"winsxs\") {
                return Some("Windows system directory");
            }
        }
    }
    // Files directly in the Windows folder (explorer.exe, regedit.exe, ...).
    if let Some(idx) = p.find(r":\windows\") {
        let rest = &p[idx + r":\windows\".len()..];
        if !rest.contains('\\') && (rest.ends_with(".exe") || rest.ends_with(".dll") || rest.ends_with(".sys")) {
            return Some("Windows folder");
        }
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    use hex::ToHex;
    use sha2::Digest;
    sha2::Sha256::digest(data).encode_hex::<String>()
}

/// Known-clean source of a stored file, or None when it may not be offered.
pub fn known_clean_source(ti: &ThreatIntelStore, sha: &str) -> Option<&'static str> {
    if ti.similarity.in_benign_corpus(sha) {
        return Some("benign reference corpus");
    }
    let human = ti.reviews.completed(sha).and_then(|r| r.verdict);
    (human.as_deref() == Some("clean")).then_some("analyst-verified clean")
}

/// Closest known-clean file kept on this server. `repaired` = `data` is the
/// disinfected file (full structure guard); otherwise only a near-identical copy
/// (distance <= SMART_WL_MAX_DIST_EP_MOVED) is accepted.
pub fn find_restore(
    ti: &ThreatIntelStore,
    engine: &EngineAdapter,
    data: &[u8],
    name: &str,
    repaired: bool,
) -> Option<RestoreCandidate> {
    let trimmed = crate::similarity::trim_trailing_padding(data);
    let tlsh = crate::analyzer::tlsh_digest(trimmed)?;
    let max = if repaired { SMART_WL_MAX_DIST } else { SMART_WL_MAX_DIST_EP_MOVED };
    let cand = if repaired {
        let rep = crate::analyzer::analyze(data, name);
        serde_json::to_value(&rep).ok().as_ref().and_then(Structure::from_report)
    } else {
        None
    };
    for s in ti.similarity.nearest(&tlsh, max, 32, "") {
        if s.sha256.is_empty() {
            continue; // TLSH blacklist entry, not a stored file
        }
        let Some(source) = known_clean_source(ti, &s.sha256) else { continue };
        if repaired {
            let (Some(c), Some(r)) = (cand.as_ref(), crate::reports::load(&s.sha256).as_ref().and_then(Structure::from_report)) else {
                continue;
            };
            if let Err(why) = accept(s.distance, c, &r) {
                eprintln!("[disinfect] restore candidate {} refused: {why}", s.sha256);
                continue;
            }
        }
        if engine.find_kept(&s.sha256.to_ascii_uppercase()).is_none() {
            continue; // not stored here, nothing to download
        }
        return Some(RestoreCandidate {
            download: format!("/api/v1/restore/{}", s.sha256),
            sha256: s.sha256,
            size: s.size,
            distance: s.distance,
            source,
        });
    }
    None
}

/// Disinfect `data` in memory and decide what to recommend. Returns the report and
/// the repaired bytes (when the infection was removed).
pub fn run(
    ti: &ThreatIntelStore,
    engine: &EngineAdapter,
    data: &[u8],
    client_path: &str,
) -> (DisinfectReport, Option<Vec<u8>>) {
    use hydradragonunicorn::DisinfectOutcome;

    let name = client_path.rsplit(['\\', '/']).next().filter(|n| !n.is_empty()).unwrap_or("file");
    let system = system_path_reason(client_path);
    let outcome = std::panic::catch_unwind(|| hydradragonunicorn::disinfect_bytes(data)).unwrap_or(DisinfectOutcome::NotInfected);

    let mut report = DisinfectReport {
        sha256: sha256_hex(data),
        size: data.len() as u64,
        infected: false,
        malware_name: None,
        repaired: false,
        repaired_sha256: None,
        repaired_size: None,
        removed_bytes: None,
        not_repairable_reason: None,
        system_file: system.is_some(),
        system_file_reason: system,
        restore: None,
        recommended_action: Action::None,
        advice: String::new(),
    };

    let repaired = match outcome {
        DisinfectOutcome::NotInfected => {
            report.advice = "No infection known to a signature disinfector was found. A detection by \
                another engine is not repaired: delete or quarantine the file."
                .into();
            return (report, None);
        }
        DisinfectOutcome::NotRepairable { malware_name, reason } => {
            report.infected = true;
            report.malware_name = Some(malware_name);
            report.not_repairable_reason = Some(reason);
            None
        }
        DisinfectOutcome::Disinfected { malware_name, data: fixed, removed_bytes } => {
            report.infected = true;
            report.malware_name = Some(malware_name);
            report.repaired = true;
            report.repaired_sha256 = Some(sha256_hex(&fixed));
            report.repaired_size = Some(fixed.len() as u64);
            report.removed_bytes = Some(removed_bytes as u64);
            Some(fixed)
        }
    };

    report.restore = match &repaired {
        Some(fixed) => find_restore(ti, engine, fixed, name, true),
        None => find_restore(ti, engine, data, name, false),
    };

    let (action, advice) = match (&report.restore, report.system_file, report.repaired) {
        (Some(r), _, _) => (
            Action::RestoreCleanCopy,
            format!(
                "Replace the file with the known-clean copy {} ({}, TLSH distance {}).",
                r.sha256, r.source, r.distance
            ),
        ),
        (None, true, true) => (
            Action::UseRepaired,
            "Windows system file: no clean copy is stored here, so the repaired file \
             (?download=repaired) is recommended. Run sfc /scannow afterwards."
                .into(),
        ),
        (None, true, false) => (
            Action::RepairWindows,
            "Windows system file that cannot be repaired here: restore it with \
             sfc /scannow or DISM /Online /Cleanup-Image /RestoreHealth."
                .into(),
        ),
        (None, false, _) => (
            Action::Delete,
            "Not a system file: delete or quarantine it and reinstall the program. \
             Disinfection is not recommended for ordinary files (the repaired copy is \
             still available with ?download=repaired)."
                .into(),
        ),
    };
    report.recommended_action = action;
    report.advice = advice;
    (report, repaired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths() {
        assert!(system_path_reason(r"C:\Windows\System32\kernel32.dll").is_some());
        assert!(system_path_reason(r"\\?\C:\WINDOWS\SysWOW64\cmd.exe").is_some());
        assert!(system_path_reason("c:/windows/winsxs/amd64_x/foo.dll").is_some());
        assert!(system_path_reason(r"C:\Windows\explorer.exe").is_some());
        assert!(system_path_reason(r"%SystemRoot%\system32\drivers\x.sys").is_some());
        assert!(system_path_reason(r"C:\Windows\Temp\evil.exe").is_none());
        assert!(system_path_reason(r"C:\Users\a\Downloads\setup.exe").is_none());
        assert!(system_path_reason(r"D:\Games\Windows\System32Clone\a.exe").is_none());
        assert!(system_path_reason("").is_none());
    }
}
