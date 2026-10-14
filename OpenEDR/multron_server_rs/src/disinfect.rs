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
//!   `?download=generic`): only for a detected file that no signature disinfector
//!   recognises. The byte ranges the signatures matched (ClamAV, YARA-X,
//!   HydraDragonSig, shipped and analyst) are zeroed and data appended after the
//!   last section is cut. With no matched range, the closest known-clean file with
//!   the same section layout (TLSH, then section names and addresses) is compared
//!   and what the infected file has on top of it is removed: added sections, the
//!   growth of the last section, the moved entry point and appended data. It never
//!   changes `recommended_action`: a repaired program is not the vendor's file.

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

/// Detected = an analyst verdict says so, or (without one) the stored verdict or a
/// fresh engine scan is malicious / suspicious.
fn is_detected(ti: &ThreatIntelStore, engine: &EngineAdapter, data: &[u8], name: &str, sha: &str) -> bool {
    let bad = |v: &str| v == "malicious" || v == "suspicious";
    let (verdict, source, _) = ti.effective(sha);
    if source == "human" {
        return bad(&verdict);
    }
    bad(&verdict) || engine.scan_blocking_opts(data, name, sha, false, |_| {}).is_ok_and(|r| bad(&r.verdict))
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
    if data.is_empty() || !is_detected(ti, engine, data, name, sha) {
        return Ok(None);
    }
    let hits = engine.match_ranges(data, name, GENERIC_MAX_RANGES);
    if !hits.is_empty() {
        let ranges: Vec<(usize, usize)> = hits.iter().map(|h| (h.2, h.3)).collect();
        let mut signatures: Vec<String> = hits.iter().map(|h| format!("{}: {}", h.0, h.1)).collect();
        signatures.sort();
        signatures.dedup();
        if let Some(fix) = neutralize_ranges(data, &ranges) {
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
    Some(Fix { data: out, zeroed, cut: (len - keep) as u64, changes })
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
            zeroed += zero(&mut out, s.raw_ptr as usize, s.raw_ptr as usize + s.raw_size as usize);
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
            zeroed += zero(&mut out, a.raw_ptr as usize + b.raw_size as usize, a.raw_ptr as usize + a.raw_size as usize);
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
    Ok(Fix { data: out, zeroed, cut, changes })
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
