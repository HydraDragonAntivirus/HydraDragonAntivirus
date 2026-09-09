//! ClamAV deep scan: top-level scan plus recursive archive extraction.
//!
//! The engine (`hydradragonclamav`) is extractor-free by design: plain
//! `scan_bytes` / `scan_path` never evaluate `.cdb` container signatures (no
//! member metadata reaches them) and never look inside archives. This module
//! is the integration layer that wires `hydradragonextractor` to the engine:
//!
//! 1. Scan the buffer itself (ClamAV + YARA).
//! 2. If it is an archive, extract its members and scan each one **with its
//!    container metadata** (parent type, real size, 1-based position, name) —
//!    this is what makes `.cdb` signatures and `Container:`-gated logical
//!    signatures evaluate.
//! 3. Recurse into nested archives up to `ScanOptions.max_recursion`.
//!
//! Child matches carry `object_path` values like `file.zip#archive[2]` (deeper:
//! `outer.zip#archive[0]#archive[1]`), so callers can attribute them.
//! The engine's own per-buffer caps (`max_scan_bytes`, chunking, blank-skip)
//! apply to every buffer scanned here.

use hydradragonclamav::{Engine, ScanMatch, ScanOptions, TimingBreakdown};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Hard cap on extracted members scanned per archive level (DoS guard on top
/// of the extractor's own decompression-bomb protection).
const MAX_ARCHIVE_CHILDREN: usize = 2048;

/// Process-wide ClamAV engine, loaded once from the installed database
/// directory. `None` when no database is installed — callers then skip
/// content scanning and keep the previous (ML-only) behavior.
static CLAM_ENGINE: OnceLock<Option<Engine>> = OnceLock::new();

/// Resolve the installed ClamAV database directory:
/// 1. `HKLM\SOFTWARE\Owlyshield\SDK\DATABASE_PATH` (written by the MSI),
/// 2. `database/` next to the running module (dev layout).
fn database_dir() -> Option<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Owlyshield\SDK") {
        if let Ok(p) = key.get_value::<String, _>("DATABASE_PATH") {
            let dir = PathBuf::from(&p);
            if dir.is_dir() {
                return Some(dir);
            }
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("database")))
        .filter(|d| d.is_dir())
}

pub(crate) fn global_engine() -> Option<&'static Engine> {
    CLAM_ENGINE
        .get_or_init(|| {
            let dir = database_dir()?;
            match Engine::from_database_dir(&dir) {
                Ok((engine, _report)) => Some(engine),
                Err(_) => None,
            }
        })
        .as_ref()
}

/// PE gate for the ML stage, typed by the ClamAV engine (single authority:
/// `.ftm` magic + builtin magics incl. the PE parser). Falls back to the MZ
/// magic only when no engine/database is available, preserving legacy
/// behavior on DB-less setups.
pub fn is_pe_bytes(bytes: &[u8]) -> bool {
    match global_engine().and_then(|e| e.detect_target(bytes)) {
        Some(1) => true,
        Some(_) => false,
        None => bytes.len() >= 2 && bytes[..2] == *b"MZ",
    }
}

/// JS trial-parse cap: the gate parses at most this prefix. Real scripts
/// declare themselves early; bounding the parse keeps big text files cheap.
/// Inference itself (predict_js) still runs on the FULL content.
const JS_PARSE_CAP: usize = 512 * 1024;

/// JS gate for the ML stage — NO extension involved (evasive samples rename
/// them). Decision chain, in order:
/// 1. ClamAV typing is authoritative: anything positively typed as a
///    non-script format (PE, ELF, archives, docs, …) is out. Only HTML/text
///    (`Some(3)`/`Some(7)`) or unrecognized (`None`) buffers continue.
/// 2. ASCII check: script source is ASCII. Binary fails here, fast.
/// 3. Trial parse with the real JS parser (oxc): prose/logs/HTML fail with
///    piles of errors, real code parses. A small error budget (<=3) tolerates
///    the cut edge on capped prefixes and sloppy-but-real scripts — the MODEL
///    (not the gate) makes the verdict.
pub fn is_js_candidate(bytes: &[u8]) -> bool {
    let target = global_engine().and_then(|e| e.detect_target(bytes));
    match target {
        Some(3) | Some(7) | None => {}
        // Positively typed non-script (PE/ELF/DEX/ZIP/PDF/…) — never JS.
        Some(_) => return false,
    }
    // ASCII-first: mirrors `hydradragonclamav::is_text_like` sampling cost
    // (~256 bytes) and rejects binaries before any parsing.
    if !hydradragonclamav::is_text_like(bytes) {
        return false;
    }
    let head = &bytes[..bytes.len().min(JS_PARSE_CAP)];
    let Ok(source) = std::str::from_utf8(head) else {
        return false;
    };
    let allocator = oxc_allocator::Allocator::default();
    let ret = oxc_parser::Parser::new(&allocator, source, oxc_span::SourceType::mjs()).parse();
    ret.errors.len() <= 3
}

/// Content verdict for one file: deep scan (signatures + archives) and map
/// any hit to malicious (`Some(2)`). Returns `None` when there is no verdict
/// (clean, unscannable, oversized, or no database installed) so the caller
/// falls through to the next verdict stage (ML models).
pub fn verdict_scan_file(path: &Path) -> Option<i32> {
    let engine = global_engine()?;
    let options = ScanOptions::default();
    let len = std::fs::metadata(path).ok()?.len();
    // Above the engine's own child cap the scan would be skipped anyway —
    // don't pay a giant read first.
    if len > options.max_child_size as u64 {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    let (matches, _timing) = scan_deep(engine, &data, &path.display().to_string(), options, &[]);
    if matches.is_empty() {
        None
    } else {
        Some(2)
    }
}

/// Extractor format tag → engine parent-container tag (extractor vocabulary:
/// `"zip"`, `"gz"`, …). Formats the engine cannot map yield `None`: their
/// children are still content-scanned, but container-gated signatures stay
/// silent for them (never a false positive).
fn parent_tag(format: &str) -> Option<&'static str> {
    match format {
        "zip" => Some("zip"),
        "gz" => Some("gz"),
        "xz" => Some("xz"),
        "7z" => Some("7z"),
        "tar" => Some("tar"),
        // rar/bz2/zst/lzma/iso/…: content scan only.
        _ => None,
    }
}

/// Scan one buffer plus, recursively, everything extractable inside it.
///
/// ClamAV signatures and YARA-x rules run on the top-level buffer AND on
/// every extracted member (each member with its container metadata).
/// Returns all matches with per-buffer attribution plus the merged timing
/// breakdown. Pass `&[]` for `module_meta` unless hydradragon-module JSON
/// metadata was built for this file.
pub fn scan_deep(
    engine: &Engine,
    data: &[u8],
    object_path: &str,
    options: ScanOptions,
    module_meta: &[(&str, &[u8])],
) -> (Vec<ScanMatch>, TimingBreakdown) {
    let mut matches = Vec::new();
    let mut timing = TimingBreakdown::default();
    let (mut top, top_breakdown) =
        engine.scan_bytes_named_with_breakdown(data, object_path, options, module_meta);
    matches.append(&mut top);
    timing.accumulate(top_breakdown);
    scan_children(
        engine,
        data,
        object_path,
        options,
        module_meta,
        0,
        &mut matches,
        &mut timing,
    );
    (matches, timing)
}

fn scan_children(
    engine: &Engine,
    data: &[u8],
    object_path: &str,
    options: ScanOptions,
    module_meta: &[(&str, &[u8])],
    depth: usize,
    matches: &mut Vec<ScanMatch>,
    timing: &mut TimingBreakdown,
) {
    if depth >= options.max_recursion {
        return;
    }
    let Some(fmt) = hydradragonextractor::detect_format(data) else {
        return;
    };
    let tag = parent_tag(fmt);
    let entries = match hydradragonextractor::extract_archive_from_bytes(data, false) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for (index, entry) in entries.iter().take(MAX_ARCHIVE_CHILDREN).enumerate() {
        if entry.data.len() > options.max_child_size {
            continue;
        }
        let child_path = format!("{object_path}#archive[{index}]");
        // ClamAV FilePos = 1-based member ordinal.
        let (mut child_matches, child_breakdown) =
            engine.scan_bytes_named_with_container(
                &entry.data,
                &child_path,
                options,
                module_meta,
                tag,
                Some(entry.size_real),
                Some((index + 1) as u64),
                Some(entry.name.clone()),
            );
        matches.append(&mut child_matches);
        timing.accumulate(child_breakdown);
        // Nested archives are parented to THIS archive.
        scan_children(
            engine,
            &entry.data,
            &child_path,
            options,
            module_meta,
            depth + 1,
            matches,
            timing,
        );
    }
}
