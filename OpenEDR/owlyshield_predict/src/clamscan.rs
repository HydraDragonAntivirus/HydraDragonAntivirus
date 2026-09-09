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

/// Hard cap on extracted members scanned per archive level (DoS guard on top
/// of the extractor's own decompression-bomb protection).
const MAX_ARCHIVE_CHILDREN: usize = 2048;

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
