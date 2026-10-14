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
//! * Generic repair (NEVER recommended, `generic_repair` in the report, bytes with
//!   `?download=generic`): only for a MALICIOUS file that no signature disinfector
//!   recognises (suspicious / PUA files are never cut). The verdict is the analyst's,
//!   else the stored one; only a file never seen is scanned again, with the same TLSH
//!   refinements (smart whitelist included) as a normal scan. The byte ranges of the
//!   malicious-level matches (ClamAV and YARA-X without PUA, HydraDragonSig score
//!   >= 85, analyst malware rules) are zeroed and data appended after the last
//!   section is cut; ranges touching the import / export tables are left alone, and
//!   text evidence is used only where the engine located it. With no matched range,
//!   the closest known-clean file of the SAME build (TLSH, then section names and
//!   addresses, PE timestamp, linker version and import table) is compared and what
//!   the infected file has on top of it is removed: added sections, the growth of
//!   the last section, the moved entry point and appended data, and only when that
//!   removed part is malicious on its own. It never changes `recommended_action`: a
//!   repaired program is not the vendor's file.

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
    /// Generic repair of a file no signature disinfector recognises (never recommended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_repair: Option<GenericRepair>,
    /// Why a detected file got no generic repair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_repair_note: Option<String>,
}

/// Signature ranges re-located per file, at most.
const GENERIC_MAX_RANGES: usize = 4096;
/// TLSH distance for clean-relative candidates of the heuristic repair. A candidate
/// is used only when its section layout matches (`diff_with_relative`).
pub const HEURISTIC_MAX_DIST: u32 = 100;
const GENERIC_WARNING: &str = "Not recommended. A generic repair removes what the signatures matched \
    or what differs from a similar clean file; the virus may have changed more than that, and the \
    result is not the vendor's file. Delete or quarantine the file and reinstall the program, or use \
    the recommended action.";

/// The clean file a heuristic repair was compared with.
#[derive(Debug, Clone, Serialize)]
pub struct CleanRelative {
    pub sha256: String,
    pub distance: u32,
    /// "analyst-verified clean" or "benign reference corpus".
    pub source: &'static str,
}

/// Generic (not recommended) repair: what was removed and how.
#[derive(Debug, Clone, Serialize)]
pub struct GenericRepair {
    /// `signature_ranges` or `clean_relative_diff`.
    pub method: &'static str,
    /// Always false: never use this instead of the recommended action.
    pub recommended: bool,
    pub warning: &'static str,
    pub sha256: String,
    pub size: u64,
    pub zeroed_bytes: u64,
    pub cut_bytes: u64,
    /// `engine: signature` whose matched bytes were zeroed (signature_ranges).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative: Option<CleanRelative>,
    pub changes: Vec<String>,
    /// `?download=generic` on the same request returns the bytes.
    pub download: &'static str,
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
) -> (DisinfectReport, Option<Vec<u8>>, Option<Vec<u8>>) {
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
        generic_repair: None,
        generic_repair_note: None,
    };

    let repaired = match outcome {
        DisinfectOutcome::NotInfected => {
            report.advice = "No infection known to a signature disinfector was found. A detection by \
                another engine is not repaired: delete or quarantine the file."
                .into();
            let generic = match generic_repair(ti, engine, data, name, &report.sha256) {
                Ok(Some((g, bytes))) => {
                    report.generic_repair = Some(g);
                    Some(bytes)
                }
                Ok(None) => None,
                Err(note) => {
                    report.generic_repair_note = Some(note);
                    None
                }
            };
            return (report, None, generic);
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
    (report, repaired, None)
}

/// The verdict the generic repair goes by: the analyst's when there is one, else the
/// stored engine verdict. Only a file this server never saw is scanned again, with the
/// same refinements as a normal scan (analyst TLSH, TLSH blacklist, TLSH smart
/// whitelist), so the repair never sees a verdict the scan server would not give.
fn repair_verdict(ti: &ThreatIntelStore, engine: &EngineAdapter, data: &[u8], name: &str, sha: &str) -> String {
    let (verdict, source, _) = ti.effective(sha);
    if source != "unseen" {
        return verdict;
    }
    engine
        .scan_blocking_opts(data, name, sha, false, |res| {
            crate::scan_server::apply_analyst_tlsh(ti, data, res);
            crate::scan_server::apply_tlsh_blacklist(ti, data, res);
            crate::scan_server::apply_smart_whitelist(ti, data, name, res);
        })
        .map(|r| r.verdict)
        .unwrap_or_else(|_| "unknown".into())
}

/// Whether the removed part of a heuristic repair is malicious on its own (each
/// removed piece scanned by itself; at least one must be malicious).
fn removed_part_is_malicious(engine: &EngineAdapter, data: &[u8], pieces: &[(usize, usize)], name: &str) -> bool {
    pieces.iter().any(|&(s, e)| {
        let Some(piece) = data.get(s..e).filter(|p| !p.is_empty()) else { return false };
        let sha = sha256_hex(piece);
        engine
            .scan_blocking_opts(piece, &format!("{name}.removed"), &sha, false, |_| {})
            .is_ok_and(|r| r.verdict == "malicious")
    })
}

/// Generic repair of a detected file no signature disinfector recognises: the
/// signatures' byte ranges first, the clean-relative comparison when there are none.
/// `Ok(None)` = not detected (nothing to do); `Err` = detected but not repairable.
fn generic_repair(
    ti: &ThreatIntelStore,
    engine: &EngineAdapter,
    data: &[u8],
    name: &str,
    sha: &str,
) -> Result<Option<(GenericRepair, Vec<u8>)>, String> {
    if data.is_empty() {
        return Ok(None);
    }
    match repair_verdict(ti, engine, data, name, sha).as_str() {
        "malicious" => {}
        // Suspicious / PUA is often a single weak heuristic: never cut a file for it.
        "suspicious" => {
            return Err("the verdict is suspicious / PUA: a generic repair is made only for malicious files".into());
        }
        _ => return Ok(None),
    }
    // Only the malicious-level matches (`match_ranges` drops PUA and low-score ones),
    // and never a range touching the import / export tables: zeroing an imported API
    // name would keep the program from loading at all.
    let hits = engine.match_ranges(data, name, GENERIC_MAX_RANGES);
    let protected = PeLayout::parse(data).map(|pe| pe.import_export_ranges(data)).unwrap_or_default();
    let (hits, skipped): (Vec<_>, Vec<_>) = hits.into_iter().partition(|h| !overlaps_any(h.2, h.3, &protected));
    if !hits.is_empty() {
        let ranges: Vec<(usize, usize)> = hits.iter().map(|h| (h.2, h.3)).collect();
        let mut signatures: Vec<String> = hits.iter().map(|h| format!("{}: {}", h.0, h.1)).collect();
        signatures.sort();
        signatures.dedup();
        if let Some(mut fix) = neutralize_ranges(data, &ranges) {
            if !skipped.is_empty() {
                fix.changes.push(format!(
                    "{} matched range(s) in the import / export tables were left as they are",
                    skipped.len()
                ));
            }
            return Ok(Some(fix.into_report("signature_ranges", signatures, None)));
        }
    }
    let trimmed = crate::similarity::trim_trailing_padding(data);
    let Some(tlsh) = crate::analyzer::tlsh_digest(trimmed) else {
        return Err("no signature byte range to remove, and the file is too small or uniform for TLSH".into());
    };
    let mut why = "no signature byte range to remove, and no known-clean file with a TLSH distance <= 100 is stored here".to_string();
    for s in ti.similarity.nearest(&tlsh, HEURISTIC_MAX_DIST, 32, sha) {
        if s.sha256.is_empty() || s.sha256.eq_ignore_ascii_case(sha) {
            continue;
        }
        let Some(source) = known_clean_source(ti, &s.sha256) else { continue };
        let Some(rel) = engine.read_kept_sample(&s.sha256.to_ascii_uppercase()) else { continue };
        match diff_with_relative(data, &rel) {
            // Same build, but what it has on top of the clean file must itself be
            // malicious; otherwise the difference may be legitimate (patched, re-signed).
            Ok(fix) if !removed_part_is_malicious(engine, data, &fix.removed, name) => {
                why = format!(
                    "closest clean file {} (distance {}): the part that differs from it is not malicious on its own",
                    s.sha256, s.distance
                );
            }
            Ok(fix) => {
                let relative = CleanRelative { sha256: s.sha256.clone(), distance: s.distance, source };
                return Ok(Some(fix.into_report("clean_relative_diff", Vec::new(), Some(relative))));
            }
            Err(e) => why = format!("closest clean file {} (distance {}): {e}", s.sha256, s.distance),
        }
    }
    Err(why)
}

/// Result of a generic repair, before it becomes a report.
#[derive(Debug)]
struct Fix {
    data: Vec<u8>,
    zeroed: u64,
    cut: u64,
    changes: Vec<String>,
    /// Byte ranges of the ORIGINAL file that were removed as the infection
    /// (heuristic repair: added sections, the growth of the last section, cut data).
    removed: Vec<(usize, usize)>,
}

fn overlaps_any(s: usize, e: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|&(a, b)| s < b && a < e)
}

impl Fix {
    fn into_report(self, method: &'static str, signatures: Vec<String>, relative: Option<CleanRelative>) -> (GenericRepair, Vec<u8>) {
        let g = GenericRepair {
            method,
            recommended: false,
            warning: GENERIC_WARNING,
            sha256: sha256_hex(&self.data),
            size: self.data.len() as u64,
            zeroed_bytes: self.zeroed,
            cut_bytes: self.cut,
            signatures,
            relative,
            changes: self.changes,
            download: "?download=generic",
        };
        (g, self.data)
    }
}

/// PE layout, just what the generic repair needs.
#[derive(Debug, Clone)]
struct PeLayout {
    /// COFF TimeDateStamp.
    timestamp: u32,
    /// Major and minor linker version (optional header bytes 2 and 3).
    linker: u16,
    opt_off: usize,
    pe32plus: bool,
    entry: u32,
    size_of_image: u32,
    size_of_headers: u32,
    nsec_off: usize,
    sections: Vec<PeSection>,
}

#[derive(Debug, Clone)]
struct PeSection {
    name: [u8; 8],
    vsize: u32,
    va: u32,
    raw_size: u32,
    raw_ptr: u32,
    header_off: usize,
}

fn rd16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn rd32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn wr16(d: &mut [u8], o: usize, v: u16) {
    if let Some(b) = d.get_mut(o..o + 2) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}
fn wr32(d: &mut [u8], o: usize, v: u32) {
    if let Some(b) = d.get_mut(o..o + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

impl PeLayout {
    fn parse(d: &[u8]) -> Option<Self> {
        if !d.starts_with(b"MZ") {
            return None;
        }
        let pe = rd32(d, 0x3c)? as usize;
        if d.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let nsec = rd16(d, pe + 6)? as usize;
        let opt_size = rd16(d, pe + 20)? as usize;
        let opt_off = pe + 24;
        let pe32plus = match rd16(d, opt_off)? {
            0x10b => false,
            0x20b => true,
            _ => return None,
        };
        let mut sections = Vec::with_capacity(nsec);
        let table = opt_off + opt_size;
        for i in 0..nsec.min(96) {
            let h = table + i * 40;
            let name: [u8; 8] = d.get(h..h + 8)?.try_into().ok()?;
            sections.push(PeSection {
                name,
                vsize: rd32(d, h + 8)?,
                va: rd32(d, h + 12)?,
                raw_size: rd32(d, h + 16)?,
                raw_ptr: rd32(d, h + 20)?,
                header_off: h,
            });
        }
        Some(PeLayout {
            timestamp: rd32(d, pe + 8)?,
            linker: rd16(d, opt_off + 2)?,
            opt_off,
            pe32plus,
            entry: rd32(d, opt_off + 16)?,
            size_of_image: rd32(d, opt_off + 56)?,
            size_of_headers: rd32(d, opt_off + 60)?,
            nsec_off: pe + 6,
            sections,
        })
    }

    /// End of the last section's raw data (start of the overlay).
    fn raw_end(&self) -> usize {
        self.sections
            .iter()
            .filter(|s| s.raw_size > 0)
            .map(|s| s.raw_ptr as usize + s.raw_size as usize)
            .max()
            .unwrap_or(self.size_of_headers as usize)
    }

    fn section_of_rva(&self, rva: u32) -> Option<usize> {
        self.sections.iter().position(|s| rva >= s.va && rva < s.va.saturating_add(s.vsize.max(s.raw_size)))
    }

    /// File offset of the certificate-table data directory (index 4).
    fn security_dir_off(&self) -> usize {
        self.opt_off + if self.pe32plus { 112 } else { 96 } + 4 * 8
    }

    /// (RVA, size) of data directory `idx`, None when absent or empty.
    fn data_dir(&self, d: &[u8], idx: usize) -> Option<(u32, u32)> {
        let count = rd32(d, self.opt_off + if self.pe32plus { 108 } else { 92 })? as usize;
        if idx >= count.min(16) {
            return None;
        }
        let o = self.opt_off + if self.pe32plus { 112 } else { 96 } + idx * 8;
        let (rva, size) = (rd32(d, o)?, rd32(d, o + 4)?);
        (rva != 0).then_some((rva, size))
    }

    /// File offset of an RVA that has raw data in the file.
    fn rva_to_off(&self, rva: u32, len: usize) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva as usize).filter(|&o| o < len);
        }
        let s = self.sections.iter().find(|s| rva >= s.va && rva - s.va < s.raw_size)?;
        let off = s.raw_ptr as usize + (rva - s.va) as usize;
        (off < len).then_some(off)
    }

    /// `[start, end)` of the NUL-terminated string at `rva` (NUL included) and its text.
    fn cstr(&self, d: &[u8], rva: u32) -> Option<(usize, usize, String)> {
        let s = self.rva_to_off(rva, d.len())?;
        let n = d[s..d.len().min(s + 4096)].iter().position(|&b| b == 0)?;
        Some((s, s + n + 1, String::from_utf8_lossy(&d[s..s + n]).to_ascii_lowercase()))
    }

    /// One import thunk array: its range, and the hint/name entries it points to
    /// (`names` = None for a bound IAT, whose entries are addresses, not RVAs).
    fn walk_thunks(&self, d: &[u8], arr: u32, dll: &str, ranges: &mut Vec<(usize, usize)>, mut names: Option<&mut Vec<String>>) {
        let Some(start) = self.rva_to_off(arr, d.len()) else { return };
        let ptr = if self.pe32plus { 8 } else { 4 };
        let mut o = start;
        for _ in 0..65_536 {
            let v = if self.pe32plus {
                d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            } else {
                rd32(d, o).map(u64::from)
            };
            let Some(v) = v else { break };
            o += ptr;
            if v == 0 {
                break;
            }
            let Some(names) = names.as_deref_mut() else { continue };
            let by_ordinal = if self.pe32plus { v >> 63 == 1 } else { v & 0x8000_0000 != 0 };
            if by_ordinal {
                names.push(format!("{dll}!#{}", v & 0xffff));
            } else if let Some((s, e, name)) = u32::try_from(v).ok().and_then(|r| self.cstr(d, r.checked_add(2)?)) {
                ranges.push((s.saturating_sub(2), e));
                names.push(format!("{dll}!{name}"));
            }
        }
        ranges.push((start, o.min(d.len())));
    }

    /// Import table (and delay imports): file ranges of the descriptors, thunk arrays,
    /// DLL names and hint/name entries, plus the imported `dll!api` names in order.
    fn walk_imports(&self, d: &[u8], ranges: &mut Vec<(usize, usize)>) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(mut desc) = self.data_dir(d, 1).and_then(|(rva, _)| self.rva_to_off(rva, d.len())) {
            for _ in 0..4096 {
                let Some(b) = d.get(desc..desc + 20) else { break };
                ranges.push((desc, desc + 20));
                if b.iter().all(|&x| x == 0) {
                    break;
                }
                let (oft, name_rva, ft) = (rd32(d, desc).unwrap_or(0), rd32(d, desc + 12).unwrap_or(0), rd32(d, desc + 16).unwrap_or(0));
                let dll = match self.cstr(d, name_rva) {
                    Some((s, e, n)) => {
                        ranges.push((s, e));
                        n
                    }
                    None => String::new(),
                };
                if oft != 0 {
                    self.walk_thunks(d, oft, &dll, ranges, Some(&mut names));
                    self.walk_thunks(d, ft, &dll, ranges, None);
                } else {
                    self.walk_thunks(d, ft, &dll, ranges, Some(&mut names));
                }
                desc += 20;
            }
        }
        // Delay imports, RVA-based descriptors only (attribute bit 0).
        if let Some(mut desc) = self.data_dir(d, 13).and_then(|(rva, _)| self.rva_to_off(rva, d.len())) {
            for _ in 0..4096 {
                let Some(b) = d.get(desc..desc + 32) else { break };
                ranges.push((desc, desc + 32));
                if b.iter().all(|&x| x == 0) || rd32(d, desc).unwrap_or(0) & 1 == 0 {
                    break;
                }
                let dll = match self.cstr(d, rd32(d, desc + 4).unwrap_or(0)) {
                    Some((s, e, n)) => {
                        ranges.push((s, e));
                        format!("delay:{n}")
                    }
                    None => "delay:".into(),
                };
                self.walk_thunks(d, rd32(d, desc + 16).unwrap_or(0), &dll, ranges, Some(&mut names));
                self.walk_thunks(d, rd32(d, desc + 12).unwrap_or(0), &dll, ranges, None);
                desc += 32;
            }
        }
        names
    }

    /// Imported `dll!api` names in table order (lower case).
    fn imports(&self, d: &[u8]) -> Vec<String> {
        self.walk_imports(d, &mut Vec::new())
    }

    /// File ranges a generic repair must not touch: the import, export, IAT and
    /// delay-import directories and everything they point to (names, thunk arrays).
    fn import_export_ranges(&self, d: &[u8]) -> Vec<(usize, usize)> {
        let len = d.len();
        let mut out = Vec::new();
        for idx in [0, 1, 12, 13] {
            if let Some((rva, size)) = self.data_dir(d, idx) {
                if let Some(o) = self.rva_to_off(rva, len) {
                    out.push((o, o.saturating_add(size as usize).min(len)));
                }
            }
        }
        self.walk_imports(d, &mut out);
        if let Some(e) = self.data_dir(d, 0).and_then(|(rva, _)| self.rva_to_off(rva, len)) {
            if let Some((s, end, _)) = rd32(d, e + 12).and_then(|r| self.cstr(d, r)) {
                out.push((s, end));
            }
            let field = |o: usize| rd32(d, e + o).unwrap_or(0);
            let (nfun, nnames) = (field(20).min(65_536) as usize, field(24).min(65_536) as usize);
            for (rva, bytes) in [(field(28), nfun * 4), (field(32), nnames * 4), (field(36), nnames * 2)] {
                if let Some(o) = self.rva_to_off(rva, len) {
                    out.push((o, o.saturating_add(bytes).min(len)));
                }
            }
            if let Some(names) = self.rva_to_off(field(32), len) {
                for i in 0..nnames {
                    let Some(r) = rd32(d, names + i * 4) else { break };
                    if let Some((s, end, _)) = self.cstr(d, r) {
                        out.push((s, end));
                    }
                }
            }
        }
        out.retain(|&(s, e)| s < e);
        out
    }
}

/// After the bytes changed: clear the PE checksum and drop a certificate table that
/// no longer lies inside the file (it signed the original bytes anyway).
fn fix_pe_after_edit(d: &mut [u8]) {
    let Some(pe) = PeLayout::parse(d) else { return };
    wr32(d, pe.opt_off + 64, 0);
    let dir = pe.security_dir_off();
    if let (Some(off), Some(size)) = (rd32(d, dir), rd32(d, dir + 4)) {
        if off != 0 && (off as usize).saturating_add(size as usize) > d.len() {
            wr32(d, dir, 0);
            wr32(d, dir + 4, 0);
        }
    }
}

/// Zero the matched ranges (never the PE headers) and, when a range lies in the
/// data appended after the last section, cut the file there. None = nothing changed.
fn neutralize_ranges(data: &[u8], ranges: &[(usize, usize)]) -> Option<Fix> {
    let pe = PeLayout::parse(data);
    let len = data.len();
    let headers = pe.as_ref().map_or(0, |p| (p.size_of_headers as usize).min(len));
    let overlay = pe.as_ref().map(PeLayout::raw_end).filter(|&e| e < len);
    let cut_at = overlay.filter(|&ov| ranges.iter().any(|&(s, _)| s >= ov));
    let keep = cut_at.unwrap_or(len);
    let mut merged: Vec<(usize, usize)> = ranges
        .iter()
        .map(|&(s, e)| (s.max(headers), e.min(keep)))
        .filter(|&(s, e)| s < e)
        .collect();
    merged.sort_unstable();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (s, e) in merged {
        match runs.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => runs.push((s, e)),
        }
    }
    let skipped_header = ranges.iter().any(|&(s, _)| s < headers);
    if runs.is_empty() && cut_at.is_none() {
        return None;
    }
    let mut out = data[..keep].to_vec();
    let mut zeroed = 0u64;
    for &(s, e) in &runs {
        out[s..e].fill(0);
        zeroed += (e - s) as u64;
    }
    let mut changes = Vec::new();
    if zeroed > 0 {
        changes.push(format!("zeroed {zeroed} bytes in {} matched range(s)", runs.len()));
    }
    if let Some(c) = cut_at {
        changes.push(format!("cut {} bytes appended after the last section (from 0x{c:x})", len - c));
    }
    if skipped_header {
        changes.push("matches inside the PE headers were left as they are".into());
    }
    if pe.is_some() {
        fix_pe_after_edit(&mut out);
    }
    Some(Fix { data: out, zeroed, cut: (len - keep) as u64, changes, removed: Vec::new() })
}

/// Heuristic repair against a known-clean relative with the same section layout
/// (names and virtual addresses of the relative's sections, in order): removes added
/// sections, the growth of the last shared section, a moved entry point and data
/// appended after the sections (the relative's own overlay is kept when found).
fn diff_with_relative(data: &[u8], rel: &[u8]) -> Result<Fix, String> {
    let inf = PeLayout::parse(data).ok_or("not a PE file")?;
    let cl = PeLayout::parse(rel).ok_or("the clean file is not a PE")?;
    if inf.pe32plus != cl.pe32plus {
        return Err("PE32 / PE32+ differ".into());
    }
    // Versions of one program share section names and addresses; the build stamp,
    // linker and imports tell them apart. A file infector leaves these as they are.
    if inf.timestamp != cl.timestamp {
        return Err("PE timestamp differs (another build, not the same program)".into());
    }
    if inf.linker != cl.linker {
        return Err("linker version differs (another build, not the same program)".into());
    }
    if inf.imports(data) != cl.imports(rel) {
        return Err("import table differs (another build, or the imports were changed)".into());
    }
    let keep_n = cl.sections.len();
    if keep_n == 0 || inf.sections.len() < keep_n {
        return Err("the infected file has fewer sections than the clean file".into());
    }
    for (a, b) in inf.sections.iter().zip(&cl.sections) {
        if a.name != b.name || a.va != b.va {
            return Err("section layout differs (another build, not the same program)".into());
        }
    }
    let len = data.len();
    let mut out = data.to_vec();
    let mut changes = Vec::new();
    let mut zeroed = 0u64;
    let mut removed: Vec<(usize, usize)> = Vec::new();
    let zero = |out: &mut Vec<u8>, s: usize, e: usize| -> u64 {
        let (s, e) = (s.min(out.len()), e.min(out.len()));
        if s < e {
            out[s..e].fill(0);
            (e - s) as u64
        } else {
            0
        }
    };

    // 1. Sections the clean file does not have.
    if inf.sections.len() > keep_n {
        let mut names = Vec::new();
        for s in &inf.sections[keep_n..] {
            let (rs, re) = (s.raw_ptr as usize, s.raw_ptr as usize + s.raw_size as usize);
            removed.push((rs.min(len), re.min(len)));
            zeroed += zero(&mut out, rs, re);
            zero(&mut out, s.header_off, s.header_off + 40);
            names.push(String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string());
        }
        wr16(&mut out, inf.nsec_off, keep_n as u16);
        changes.push(format!("removed {} added section(s): {}", names.len(), names.join(", ")));
    }
    // 2. The last shared section grew (the virus body was appended into it).
    let last = keep_n - 1;
    let (a, b) = (&inf.sections[last], &cl.sections[last]);
    let mut last_raw = a.raw_size;
    if a.raw_size > b.raw_size || a.vsize > b.vsize {
        if a.raw_size > b.raw_size {
            let (gs, ge) = (a.raw_ptr as usize + b.raw_size as usize, a.raw_ptr as usize + a.raw_size as usize);
            removed.push((gs.min(len), ge.min(len)));
            zeroed += zero(&mut out, gs, ge);
            last_raw = b.raw_size;
        }
        wr32(&mut out, a.header_off + 8, b.vsize.min(a.vsize));
        wr32(&mut out, a.header_off + 16, last_raw);
        changes.push(format!(
            "shrank the last section back to the clean size ({} -> {} bytes)",
            a.raw_size, last_raw
        ));
    }
    if inf.sections.len() > keep_n || a.raw_size > b.raw_size || a.vsize > b.vsize {
        wr32(&mut out, inf.opt_off + 56, cl.size_of_image.min(inf.size_of_image));
    }
    // 3. Entry point moved away from the clean file's.
    if inf.entry != cl.entry {
        if cl.section_of_rva(cl.entry).is_some_and(|i| i < keep_n) {
            wr32(&mut out, inf.opt_off + 16, cl.entry);
            changes.push(format!("entry point 0x{:x} -> 0x{:x} (the clean file's)", inf.entry, cl.entry));
        } else {
            return Err("the clean file's entry point is not in a shared section".into());
        }
    }
    // 4. Data after the kept sections: keep only the clean file's own overlay.
    let kept_end = inf.sections[..keep_n]
        .iter()
        .enumerate()
        .filter(|(_, s)| s.raw_size > 0)
        .map(|(i, s)| s.raw_ptr as usize + if i == last { last_raw as usize } else { s.raw_size as usize })
        .max()
        .unwrap_or(inf.size_of_headers as usize)
        .min(len);
    let cl_end = cl.raw_end().min(rel.len());
    let cl_overlay = &rel[cl_end..];
    let mut cut = 0u64;
    if kept_end < len {
        if cl_overlay.is_empty() {
            cut = (len - kept_end) as u64;
            removed.push((kept_end, len));
            out.truncate(kept_end);
        } else {
            let probe = &cl_overlay[..cl_overlay.len().min(256)];
            let found = data[kept_end..].windows(probe.len()).position(|w| w == probe).map(|p| kept_end + p);
            match found {
                Some(p) if p + cl_overlay.len() <= len => {
                    let mut rebuilt = out[..kept_end].to_vec();
                    rebuilt.extend_from_slice(&data[p..p + cl_overlay.len()]);
                    // The certificate table points into the overlay: move it with it.
                    let dir = inf.security_dir_off();
                    if let Some(off) = rd32(&rebuilt, dir) {
                        if off as usize >= p {
                            wr32(&mut rebuilt, dir, (off as usize - (p - kept_end)) as u32);
                        }
                    }
                    cut = (len - rebuilt.len()) as u64;
                    removed.push((kept_end, p));
                    removed.push((p + cl_overlay.len(), len));
                    out = rebuilt;
                }
                _ => changes.push("appended data kept: the clean file's overlay was not found in it".into()),
            }
        }
        if cut > 0 {
            changes.push(format!("cut {cut} bytes of data appended after the sections"));
        }
    }
    let changed = inf.sections.len() > keep_n || a.raw_size > b.raw_size || a.vsize > b.vsize || inf.entry != cl.entry || cut > 0;
    if !changed {
        return Err("no difference to the clean file was found".into());
    }
    fix_pe_after_edit(&mut out);
    removed.retain(|&(s, e)| s < e);
    Ok(Fix { data: out, zeroed, cut, changes, removed })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32: headers 0x200, file alignment 0x200, section alignment 0x1000.
    /// `sections` = (name, virtual address, raw bytes).
    fn build_pe(sections: &[(&str, u32, Vec<u8>)], entry: u32, overlay: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 0x200];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        wr16(&mut d, 0x44, 0x14c);
        wr16(&mut d, 0x46, sections.len() as u16);
        wr16(&mut d, 0x54, 0xE0);
        let opt = 0x58;
        wr16(&mut d, opt, 0x10b);
        wr32(&mut d, opt + 16, entry);
        wr32(&mut d, opt + 60, 0x200);
        let mut raw_ptr = 0x200u32;
        let mut image = 0x1000u32;
        for (i, (name, va, raw)) in sections.iter().enumerate() {
            let h = opt + 0xE0 + i * 40;
            d[h..h + name.len()].copy_from_slice(name.as_bytes());
            let raw_size = (raw.len() as u32).div_ceil(0x200) * 0x200;
            wr32(&mut d, h + 8, raw.len() as u32);
            wr32(&mut d, h + 12, *va);
            wr32(&mut d, h + 16, raw_size);
            wr32(&mut d, h + 20, raw_ptr);
            raw_ptr += raw_size;
            image = image.max((va + raw.len() as u32).div_ceil(0x1000) * 0x1000);
        }
        wr32(&mut d, opt + 56, image);
        for (_, _, raw) in sections {
            let mut r = raw.clone();
            r.resize((raw.len()).div_ceil(0x200) * 0x200, 0);
            d.extend(r);
        }
        d.extend_from_slice(overlay);
        d
    }

    fn text() -> Vec<u8> {
        (0..0x300u32).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn signature_ranges_are_zeroed_and_appended_data_cut() {
        let mut t = text();
        t[0x40..0x49].copy_from_slice(b"EVILBYTES");
        let pe = build_pe(&[(".text", 0x1000, t)], 0x1000, b"....EVILTAIL....");
        let body = 0x200 + 0x40;
        let tail = pe.len() - 12;
        let fix = neutralize_ranges(&pe, &[(body, body + 9), (tail, tail + 8), (0x3c, 0x40)]).unwrap();
        assert!(fix.data[body..body + 9].iter().all(|&b| b == 0));
        assert_eq!(fix.data.len(), 0x200 + 0x400, "cut at the end of the last section");
        assert_eq!(fix.cut, 16);
        assert_eq!(fix.zeroed, 9);
        assert_eq!(&fix.data[0x3c..0x40], &0x40u32.to_le_bytes(), "headers are never zeroed");
        assert!(PeLayout::parse(&fix.data).is_some());
        assert!(neutralize_ranges(&pe, &[(0x10, 0x20)]).is_none(), "only header ranges: nothing to do");
        // Not a PE: zeroed, nothing cut.
        let fix = neutralize_ranges(b"var a = evil(); ok", &[(8, 14)]).unwrap();
        assert_eq!(fix.data, b"var a = \0\0\0\0\0\0; ok");
    }

    #[test]
    fn added_section_and_moved_entry_point_are_removed() {
        let clean = build_pe(&[(".text", 0x1000, text()), (".data", 0x2000, vec![5u8; 0x100])], 0x1010, b"");
        let infected = build_pe(
            &[(".text", 0x1000, text()), (".data", 0x2000, vec![5u8; 0x100]), (".virus", 0x3000, vec![0xCC; 0x250])],
            0x3000,
            b"",
        );
        let fix = diff_with_relative(&infected, &clean).unwrap();
        assert_eq!(fix.data, clean, "the infected file is turned back into the clean one");
        assert!(fix.changes.iter().any(|c| c.contains(".virus")), "{:?}", fix.changes);
        assert!(fix.cut > 0);
    }

    #[test]
    fn grown_last_section_is_shrunk() {
        let clean = build_pe(&[(".text", 0x1000, text()), (".data", 0x2000, vec![5u8; 0x100])], 0x1010, b"");
        let mut grown = vec![5u8; 0x100];
        grown.resize(0x200, 0);
        grown.extend(vec![0xCC; 0x300]); // virus body appended into the last section
        let infected = build_pe(&[(".text", 0x1000, text()), (".data", 0x2000, grown)], 0x2200, b"");
        let fix = diff_with_relative(&infected, &clean).unwrap();
        assert_eq!(fix.data, clean, "section sizes, entry point and length back to the clean file");
    }

    #[test]
    fn clean_overlay_is_kept_and_virus_before_it_removed() {
        let ov = b"INSTALLER-OVERLAY-DATA-0123456789".repeat(4);
        let clean = build_pe(&[(".text", 0x1000, text())], 0x1000, &ov);
        let infected = build_pe(&[(".text", 0x1000, text()), (".v", 0x2000, vec![0xCC; 0x80])], 0x2000, &ov);
        let fix = diff_with_relative(&infected, &clean).unwrap();
        assert_eq!(fix.data, clean);
    }

    #[test]
    fn other_builds_are_refused() {
        let clean = build_pe(&[(".text", 0x1000, text()), (".rdata", 0x2000, vec![1; 16])], 0x1000, b"");
        let other = build_pe(&[(".text", 0x1000, text()), (".data", 0x2000, vec![1; 16])], 0x1000, b"");
        assert!(diff_with_relative(&other, &clean).is_err());
        assert!(diff_with_relative(&clean, &clean).is_err(), "no difference");
        assert!(diff_with_relative(b"not a pe", &clean).is_err());
    }

    /// `.text` plus an `.rdata` holding one import (kernel32.dll!VirtualAlloc).
    fn pe_with_import(api: &str, timestamp: u32) -> Vec<u8> {
        let mut rdata = vec![0u8; 0x100];
        wr32(&mut rdata, 0x00, 0x2040); // OriginalFirstThunk
        wr32(&mut rdata, 0x0c, 0x2080); // Name
        wr32(&mut rdata, 0x10, 0x2060); // FirstThunk
        wr32(&mut rdata, 0x40, 0x20a0);
        wr32(&mut rdata, 0x60, 0x20a0);
        rdata[0x80..0x8c].copy_from_slice(b"kernel32.dll");
        rdata[0xa2..0xa2 + api.len()].copy_from_slice(api.as_bytes());
        let mut pe = build_pe(&[(".text", 0x1000, text()), (".rdata", 0x2000, rdata)], 0x1000, b"");
        wr32(&mut pe, 0x48, timestamp);
        wr32(&mut pe, 0x58 + 92, 16); // NumberOfRvaAndSizes
        wr32(&mut pe, 0x58 + 96 + 8, 0x2000); // import directory
        wr32(&mut pe, 0x58 + 96 + 12, 40);
        pe
    }

    #[test]
    fn import_tables_are_found_and_protected() {
        let pe = pe_with_import("VirtualAlloc", 0);
        let layout = PeLayout::parse(&pe).unwrap();
        assert_eq!(layout.imports(&pe), vec!["kernel32.dll!virtualalloc".to_string()]);
        let prot = layout.import_export_ranges(&pe);
        let rdata = 0x200 + 0x400; // .text is 0x300 bytes -> 0x400 raw
        let api = rdata + 0xa2;
        assert!(overlaps_any(api, api + 12, &prot), "the API name is protected: {prot:x?}");
        assert!(overlaps_any(rdata + 0x80, rdata + 0x8c, &prot), "the DLL name is protected");
        assert!(overlaps_any(rdata, rdata + 20, &prot), "the descriptor is protected");
        assert!(!overlaps_any(0x200 + 0x40, 0x200 + 0x49, &prot), "code is not protected");
    }

    #[test]
    fn other_build_with_same_layout_is_refused() {
        let infected = {
            let mut p = pe_with_import("VirtualAlloc", 0x5000_0000);
            p.extend(vec![0xCC; 0x80]);
            p
        };
        let same = pe_with_import("VirtualAlloc", 0x5000_0000);
        let fix = diff_with_relative(&infected, &same).unwrap();
        assert_eq!(fix.data, same);
        assert_eq!(fix.removed, vec![(same.len(), infected.len())], "the removed part is reported");

        let other_stamp = pe_with_import("VirtualAlloc", 0x5100_0000);
        assert!(diff_with_relative(&infected, &other_stamp).unwrap_err().contains("timestamp"));
        let other_imports = pe_with_import("VirtualFree", 0x5000_0000);
        assert!(diff_with_relative(&infected, &other_imports).unwrap_err().contains("import"));
        let mut other_linker = same.clone();
        other_linker[0x58 + 2] = 14;
        assert!(diff_with_relative(&infected, &other_linker).unwrap_err().contains("linker"));
    }

    #[test]
    fn removed_parts_of_added_section_and_grown_section() {
        let clean = build_pe(&[(".text", 0x1000, text()), (".data", 0x2000, vec![5u8; 0x100])], 0x1010, b"");
        let infected = build_pe(
            &[(".text", 0x1000, text()), (".data", 0x2000, vec![5u8; 0x100]), (".virus", 0x3000, vec![0xCC; 0x250])],
            0x3000,
            b"",
        );
        let fix = diff_with_relative(&infected, &clean).unwrap();
        let v = 0x200 + 0x400 + 0x200; // raw pointer of .virus
        assert!(fix.removed.contains(&(v, v + 0x400)), "{:x?}", fix.removed);
        assert!(fix.removed.iter().all(|&(s, e)| infected[s..e].iter().all(|&b| b == 0xCC || b == 0)));
    }

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
