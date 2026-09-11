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
/// Process-wide ClamAV engine, loaded on demand from the installed database
/// directory. Once loaded, cached permanently as &'static Engine.
/// Retries on subsequent calls if database was not yet ready at service startup.
static CLAM_ENGINE: OnceLock<&'static Engine> = OnceLock::new();

/// Resolve the installed ClamAV database directory:
/// 1. `HKLM\SOFTWARE\Owlyshield\SDK\DATABASE_PATH` (with 64-bit and 32-bit hive support),
/// 2. `database/` next to the running DLL module,
/// 3. `database/` next to the running executable,
/// 4. standard installation paths,
/// 5. `database/` CWD relative.
fn database_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        for flags in [KEY_READ | KEY_WOW64_64KEY, KEY_READ] {
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SOFTWARE\Owlyshield\SDK", flags) {
                if let Ok(p) = key.get_value::<String, _>("DATABASE_PATH") {
                    let dir = PathBuf::from(&p);
                    if dir.is_dir() {
                        return Some(dir);
                    }
                }
            }
        }
    }

    if let Some(dll_dir) = crate::utils::current_module_dir() {
        let cand = dll_dir.join("database");
        if cand.is_dir() {
            return Some(cand);
        }
    }

    if let Some(cand) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("database")))
        .filter(|d| d.is_dir())
    {
        return Some(cand);
    }

    for default_path in [
        r"C:\Program Files\HydraDragonAntivirus\OpenEDR\database",
        r"C:\Program Files (x86)\HydraDragonAntivirus\OpenEDR\database",
    ] {
        let cand = PathBuf::from(default_path);
        if cand.is_dir() {
            return Some(cand);
        }
    }

    let cand = PathBuf::from("database");
    if cand.is_dir() {
        return Some(cand);
    }
    None
}

pub(crate) fn global_engine() -> Option<&'static Engine> {
    if let Some(engine) = CLAM_ENGINE.get() {
        return Some(*engine);
    }

    static LAST_TRY: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    if let Ok(mut guard) = LAST_TRY.lock() {
        if let Some(prev) = *guard {
            if prev.elapsed() < std::time::Duration::from_secs(3) {
                return None;
            }
        }
        *guard = Some(std::time::Instant::now());
    }

    let Some(dir) = database_dir() else {
        crate::Logging::error(
            "[ClamScan] No database directory found: registry DATABASE_PATH missing, not next to module/exe, and not at standard install paths",
        );
        return None;
    };

    match Engine::from_database_dir(&dir) {
        Ok((engine, report)) => {
            crate::Logging::info(&format!(
                "[ClamScan] Loaded database from {} (ext={} logical={} container={} ftm={} icons={} certs={} bytecode={})",
                dir.display(),
                report.extended_loaded,
                report.logical_loaded,
                report.container_loaded,
                report.ftm_loaded,
                report.icon_loaded,
                report.cert_loaded,
                report.bytecodes_loaded,
            ));
            let leaked: &'static Engine = Box::leak(Box::new(engine));
            let _ = CLAM_ENGINE.set(leaked);
            Some(leaked)
        }
        Err(e) => {
            crate::Logging::error(&format!(
                "[ClamScan] Failed to load database from {}: {}",
                dir.display(),
                e
            ));
            None
        }
    }
}

/// PE gate for the ML stage. Checks MZ magic header first, followed by
/// ClamAV target detection if available.
pub fn is_pe_bytes(bytes: &[u8]) -> bool {
    if bytes.len() >= 2 && bytes[..2] == *b"MZ" {
        return true;
    }
    match global_engine().and_then(|e| e.detect_target(bytes)) {
        Some(1) => true,
        _ => false,
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
    let data = crate::utils::read_file_shared(path).ok()?;
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
    // Archive budget: all extracted members combined stay within
    // `max_archive_bytes` (default 100MB total on top of the file's own
    // 100MB scan cap); 0 disables archive recursion entirely.
    let mut budget = options.max_archive_bytes;
    scan_children(
        engine,
        data,
        object_path,
        options,
        module_meta,
        0,
        &mut budget,
        &mut matches,
        &mut timing,
    );
    (matches, timing)
}

/// Real-time content fallback for the behavior pipeline: ClamAV (+archives)
/// when ML is undecided. Bounded by `max_child_size` (giants skipped
/// pre-read), the engine's scan cap and the archive budget — one file can
/// never stall the RT loop. Returns `None` when clean/unscannable.
///
/// RT events routinely arrive while the file is still being written
/// (copy/download in flight: missing, zero-length, or locked). The read is
/// retried a few times on a short backoff so a mid-write event doesn't
/// silently skip a malicious file that a manual scan seconds later catches.
pub fn rt_scan_file(
    path_str: &str,
) -> Option<crate::ml::fast_detect::FastDetectionResult> {
    let engine = global_engine()?;
    let mut options = ScanOptions::default();
    options.max_scan_bytes = 32 * 1024 * 1024;
    options.max_archive_bytes = 16 * 1024 * 1024;
    options.max_child_size = 32 * 1024 * 1024;
    let path = std::path::Path::new(path_str);
    let mut data: Option<Vec<u8>> = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        match std::fs::metadata(path).ok().map(|m| m.len()) {
            Some(len) if len > 0 && len <= options.max_child_size as u64 => {
                if let Ok(bytes) = crate::utils::read_file_shared(path) {
                    if !bytes.is_empty() {
                        data = Some(bytes);
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    let data = data?;
    let (matches, _timing) = scan_deep(engine, &data, path_str, options, &[]);
    let first = matches.first()?;
    Some(crate::ml::fast_detect::FastDetectionResult {
        detection_name: format!("ClamAV:{}", first.name),
        reason: format!(
            "ClamAV content detection '{}' (kind {:?})",
            first.name, first.kind
        ),
        features: std::collections::HashMap::new(),
    })
}

fn scan_children(
    engine: &Engine,
    data: &[u8],
    object_path: &str,
    options: ScanOptions,
    module_meta: &[(&str, &[u8])],
    depth: usize,
    budget: &mut usize,
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
        // Spend archive budget: members beyond the remaining budget are
        // skipped (extraction itself stays bomb-guarded inside the extractor).
        if entry.data.len() > *budget {
            continue;
        }
        *budget -= entry.data.len();
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
            budget,
            matches,
            timing,
        );
    }
}
