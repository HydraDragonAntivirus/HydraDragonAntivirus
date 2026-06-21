use crate::database::{ContainerType, Database, OffsetAnchor, SourceLocation};
use crate::logical::Subsignature;
use crate::pe::{parse_pe, PeInfo};
use hydradragonextractor::{detect_format, extract_archive_from_bytes};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct Engine {
    pub database: Database,
    /// ClamAV bytecode programs loaded from bytecode.cvd/.cld/.cbc. Stage 1:
    /// parsed (header + trigger) but not yet executed.
    pub bytecodes: Vec<crate::bytecode::Bytecode>,
    /// Atom prefilter: selects the few signatures worth fully evaluating per
    /// buffer instead of scanning all of them linearly, and threads the atom
    /// match offsets into verification. It also owns the per-logical-signature
    /// gating info (see `AtomPrefilter::logical_gate`), kept there so the gating
    /// subsignature is exactly the one whose atoms were indexed — that alignment
    /// is what makes threading the gate's offsets correct.
    prefilter: crate::prefilter::AtomPrefilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    pub strict_targets: bool,
    pub max_matches: usize,
    pub max_subsignature_matches: usize,
    pub scan_archives: bool,
    pub scan_normalized: bool,
    pub max_recursion: usize,
    pub max_child_objects: usize,
    pub max_child_size: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            strict_targets: false,
            max_matches: 128,
            max_subsignature_matches: 4096,
            scan_archives: true,
            scan_normalized: true,
            max_recursion: 8,
            max_child_objects: 4096,
            max_child_size: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanMatch {
    pub name: String,
    pub kind: SignatureKind,
    pub source: SourceLocation,
    pub object_path: String,
    pub view: ScanView,
    /// Byte ranges `[start, end)` in the scanned object that produced this match.
    /// These map to file offsets only for `view == Raw` on the top-level object
    /// (an `object_path` with no `#archive[...]` segment). Used for disinfection.
    pub arenas: Vec<(usize, usize)>,
}

/// Upper bound on arenas recorded per signature match, to keep memory bounded.
const ARENA_CAP: usize = 64;

/// Whether `HDA_PROF` profiling is on (checked once). Gates slow-candidate logs.
fn prof_enabled() -> bool {
    static P: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *P.get_or_init(|| std::env::var_os("HDA_PROF").is_some())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureKind {
    Extended,
    Logical,
    Container,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanView {
    Raw,
    NormalizedText,
    HtmlNoComments,
    HtmlNoTags,
    HtmlScript,
}

pub(crate) struct ScanContext<'a> {
    pub data: &'a [u8],
    pub pe: Option<PeInfo>,
    /// Target forced by a normalized view (text=7, html=3).
    pub target_hint: Option<u32>,
    /// Target derived from `.ftm` file-type magic (used only in strict mode).
    pub detected_target: Option<u32>,
    pub object_path: &'a str,
    pub view: ScanView,
}

struct ScanState {
    matches: Vec<ScanMatch>,
    objects_seen: usize,
}

impl Engine {
    pub fn from_database_dir(path: impl AsRef<Path>) -> io::Result<(Self, crate::LoadReport)> {
        let path = path.as_ref();
        let (database, mut report) = Database::load_dir(path)?;
        // Load (parse) bytecode programs from the same directory.
        let bc = crate::bytecode::BytecodeSet::load_from_dir(path);
        report.bytecodes_loaded = bc.report.loaded;
        // Atom prefilter (daachorse): one selective required atom per signature,
        // built via a compact CSR mapping. One pass per buffer picks the few
        // candidate signatures instead of scanning all ~500k — fast scans and
        // far fewer page faults.
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        Ok((
            Self {
                database,
                bytecodes: bc.bytecodes,
                prefilter,
            },
            report,
        ))
    }

    pub fn scan_path(
        &self,
        path: impl AsRef<Path>,
        options: ScanOptions,
    ) -> io::Result<Vec<ScanMatch>> {
        let path = path.as_ref();
        let data = fs::read(path)?;
        Ok(self.scan_bytes_named(&data, &path.display().to_string(), options))
    }

    pub fn scan_bytes(&self, data: &[u8], options: ScanOptions) -> Vec<ScanMatch> {
        self.scan_bytes_named(data, "root", options)
    }

    pub fn scan_bytes_named(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
    ) -> Vec<ScanMatch> {
        let mut state = ScanState {
            matches: Vec::new(),
            objects_seen: 0,
        };
        self.scan_object(data, object_path, 0, options, &mut state);
        state.matches
    }

    fn scan_object(
        &self,
        data: &[u8],
        object_path: &str,
        depth: usize,
        options: ScanOptions,
        state: &mut ScanState,
    ) {
        if state.matches.len() >= options.max_matches
            || state.objects_seen >= options.max_child_objects
        {
            return;
        }
        state.objects_seen += 1;
        if data.len() > options.max_child_size {
            return;
        }

        let detected_target = if options.strict_targets && !self.database.file_type_magic.is_empty()
        {
            self.detect_clamav_type(data).and_then(clamav_type_to_target)
        } else {
            None
        };

        let pe = parse_pe(data);
        let is_pe = pe.is_some();
        let ctx = ScanContext {
            data,
            pe,
            target_hint: None,
            detected_target,
            object_path,
            view: ScanView::Raw,
        };
        self.scan_context(&ctx, options, &mut state.matches);

        // Normalized text/HTML views exist to catch text-like malware (scripts,
        // HTML). A PE executable is neither text nor HTML, so generating and
        // rescanning up to four derived copies of it is pure waste — skip it.
        // (Text/HTML files still go through the views below.)
        if options.scan_normalized && !is_pe && state.matches.len() < options.max_matches {
            self.scan_normalized_views(data, object_path, options, state);
        }

        if options.scan_archives
            && state.matches.len() < options.max_matches
            && looks_like_supported_archive(data)
        {
            if let Ok(children) = extract_archive_from_bytes(data) {
                if !self.database.container.is_empty() {
                    self.scan_containers(data, &children, object_path, options, &mut state.matches);
                }
                if depth < options.max_recursion {
                    for (index, child) in children.iter().enumerate() {
                        if state.matches.len() >= options.max_matches
                            || state.objects_seen >= options.max_child_objects
                        {
                            break;
                        }
                        let child_path = format!("{object_path}#archive[{index}]");
                        self.scan_object(child, &child_path, depth + 1, options, state);
                    }
                }
            }
        }
    }

    /// Match container metadata (`.cdb`) signatures against an extracted archive.
    fn scan_containers(
        &self,
        data: &[u8],
        children: &[Vec<u8>],
        object_path: &str,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        let container_format = detect_container_format(data);
        let container_size = data.len() as u64;

        for sig in &self.database.container {
            if matches.len() >= options.max_matches {
                return;
            }
            // Skip signatures that constrain metadata we cannot observe, so we
            // never false-positive on unknowable fields.
            if sig.filename.is_some()
                || sig.encrypted.is_some()
                || sig.size_in_container.is_constrained()
            {
                continue;
            }
            match sig.container_type {
                ContainerType::Any => {}
                ContainerType::Format(fmt) => {
                    if container_format != Some(fmt) {
                        continue;
                    }
                }
                ContainerType::Unsupported => continue,
            }
            if !sig.container_size.matches(container_size) {
                continue;
            }
            let member_match = children.iter().enumerate().any(|(index, child)| {
                sig.file_pos.matches((index + 1) as u64)
                    && sig.size_real.matches(child.len() as u64)
            });
            if member_match {
                matches.push(ScanMatch {
                    name: sig.name.clone(),
                    kind: SignatureKind::Container,
                    source: sig.source.clone(),
                    object_path: object_path.to_string(),
                    view: ScanView::Raw,
                    arenas: Vec::new(),
                });
            }
        }
    }

    /// Identify the ClamAV file type (`CL_TYPE_*`) of `data` via `.ftm` magic.
    fn detect_clamav_type(&self, data: &[u8]) -> Option<&str> {
        for magic in &self.database.file_type_magic {
            let ranges = magic.offset.scan_ranges(data.len(), None);
            if ranges.is_empty() {
                continue;
            }
            if magic
                .patterns
                .iter()
                .any(|pattern| !pattern.find_all(data, &ranges, 1).is_empty())
            {
                return Some(magic.clamav_type.as_str());
            }
        }
        None
    }

    fn scan_context(
        &self,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        // One Aho-Corasick pass picks the candidate signatures for this buffer;
        // both phases then evaluate only those instead of all ~500k.
        if std::env::var_os("HDA_PROF").is_some() {
            use std::time::Instant;
            let t0 = Instant::now();
            let (ext_cands, log_cands) = self.prefilter.candidates(ctx.data);
            let t1 = Instant::now();
            let (ne, nl) = (ext_cands.len(), log_cands.len());
            eprintln!(
                "[PROF] {}KB view={:?} ext_cands={ne} log_cands={nl} prefilter={}ms (scanning…)",
                ctx.data.len() / 1024,
                ctx.view,
                (t1 - t0).as_millis(),
            );
            self.scan_extended(ctx, options, matches, &ext_cands);
            let t2 = Instant::now();
            if matches.len() < options.max_matches {
                self.scan_logical(ctx, options, matches, &log_cands);
            }
            let t3 = Instant::now();
            eprintln!(
                "[PROF] {}KB view={:?} ext_cands={ne} log_cands={nl} prefilter={}ms ext_scan={}ms log_scan={}ms",
                ctx.data.len() / 1024,
                ctx.view,
                (t1 - t0).as_millis(),
                (t2 - t1).as_millis(),
                (t3 - t2).as_millis(),
            );
            return;
        }
        let (ext_cands, log_cands) = self.prefilter.candidates(ctx.data);
        self.scan_extended(ctx, options, matches, &ext_cands);
        if matches.len() < options.max_matches {
            self.scan_logical(ctx, options, matches, &log_cands);
        }
    }

    fn scan_normalized_views(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        state: &mut ScanState,
    ) {
        if looks_like_ascii_text(data) {
            let normalized = normalize_ascii_text(data);
            self.scan_derived_view(
                &normalized,
                object_path,
                7,
                ScanView::NormalizedText,
                options,
                state,
            );
        }

        if looks_like_html(data) {
            let html = normalize_html_views(data);
            self.scan_derived_view(
                &html.no_comments,
                object_path,
                3,
                ScanView::HtmlNoComments,
                options,
                state,
            );
            self.scan_derived_view(
                &html.no_tags,
                object_path,
                3,
                ScanView::HtmlNoTags,
                options,
                state,
            );
            if !html.scripts.is_empty() {
                self.scan_derived_view(
                    &html.scripts,
                    object_path,
                    3,
                    ScanView::HtmlScript,
                    options,
                    state,
                );
            }
        }
    }

    fn scan_derived_view(
        &self,
        data: &[u8],
        object_path: &str,
        target_hint: u32,
        view: ScanView,
        options: ScanOptions,
        state: &mut ScanState,
    ) {
        if data.is_empty() || state.matches.len() >= options.max_matches {
            return;
        }
        let ctx = ScanContext {
            data,
            pe: None,
            target_hint: Some(target_hint),
            detected_target: None,
            object_path,
            view,
        };
        self.scan_context(&ctx, options, &mut state.matches);
    }

    fn scan_extended(
        &self,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
        cands: &crate::prefilter::Candidates,
    ) {
        // Static dispatch (two concrete loops) instead of a `Box<dyn Iterator>`:
        // the candidate list carries per-signature atom offsets to thread into
        // verification. An empty offset slice (or the `All` arm) means "no
        // threading — full scan".
        match cands {
            crate::prefilter::Candidates::All => {
                for si in 0..self.database.extended.len() {
                    if matches.len() >= options.max_matches {
                        return;
                    }
                    self.scan_one_extended(si, None, ctx, options, matches);
                }
            }
            crate::prefilter::Candidates::List(set) => {
                for (sig, offsets) in set.iter() {
                    if matches.len() >= options.max_matches {
                        return;
                    }
                    let hints = (!offsets.is_empty()).then_some(offsets);
                    self.scan_one_extended(sig as usize, hints, ctx, options, matches);
                }
            }
        }
    }

    /// Evaluate a single extended signature. `hints`, when `Some`, are the buffer
    /// offsets where this signature's atom occurred — verification is restricted
    /// to those positions (`find_all_at`); `None` means a full window scan.
    fn scan_one_extended(
        &self,
        si: usize,
        hints: Option<&[u32]>,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        let signature = &self.database.extended[si];
        if !target_matches(signature.target, ctx, options.strict_targets) {
            return;
        }
        if matches!(
            signature.offset.anchor,
            OffsetAnchor::Unsupported(_) | OffsetAnchor::MacroGroup(_) | OffsetAnchor::VersionInfo
        ) {
            return;
        }
        let ranges = signature
            .offset
            .scan_ranges(ctx.data.len(), ctx.pe.as_ref());
        if ranges.is_empty() {
            return;
        }
        let prof = prof_enabled().then(std::time::Instant::now);
        let mut arenas: Vec<(usize, usize)> = Vec::new();
        for pattern in &signature.patterns {
            let hits = match hints {
                Some(h) => pattern.find_all_at(ctx.data, &ranges, ARENA_CAP, h),
                None => pattern.find_all(ctx.data, &ranges, ARENA_CAP),
            };
            for hit in hits {
                if arenas.len() >= ARENA_CAP {
                    break;
                }
                arenas.push((hit.start, hit.end));
            }
        }
        if let Some(t) = prof {
            let ms = t.elapsed().as_millis();
            if ms >= 20 {
                eprintln!(
                    "[SLOW-EXT] {ms}ms {} ({}:{}) hints={} threaded={}",
                    signature.name,
                    signature.source.path.display(),
                    signature.source.line,
                    hints.map_or(0, |h| h.len()),
                    hints.is_some(),
                );
            }
        }
        if !arenas.is_empty() {
            matches.push(ScanMatch {
                name: signature.name.clone(),
                kind: SignatureKind::Extended,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
                arenas,
            });
        }
    }

    fn scan_logical(
        &self,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
        cands: &crate::prefilter::Candidates,
    ) {
        // Static dispatch (mirrors scan_extended): thread the gating subsig's
        // atom offsets into its verification when available.
        match cands {
            crate::prefilter::Candidates::All => {
                for si in 0..self.database.logical.len() {
                    if matches.len() >= options.max_matches {
                        return;
                    }
                    self.scan_one_logical(si, None, ctx, options, matches);
                }
            }
            crate::prefilter::Candidates::List(set) => {
                for (sig, offsets) in set.iter() {
                    if matches.len() >= options.max_matches {
                        return;
                    }
                    let hints = (!offsets.is_empty()).then_some(offsets);
                    self.scan_one_logical(sig as usize, hints, ctx, options, matches);
                }
            }
        }
    }

    /// Evaluate a single logical signature. `hints`, when `Some`, are the buffer
    /// offsets of the gating subsignature's atom — threaded into that subsig's
    /// verification when the gate is `threadable` (i.e. the prefilter indexed
    /// exactly that subsig, so the offsets correspond to it).
    fn scan_one_logical(
        &self,
        si: usize,
        hints: Option<&[u32]>,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        let signature = &self.database.logical[si];
        if !target_matches(signature.target, ctx, options.strict_targets) {
            return;
        }
        let subsigs = &signature.subsignatures;
        let mut counts = vec![0usize; subsigs.len()];
        // Match offset of each body subsignature's first hit — PCRE triggers
        // and byte-compare anchors reference these.
        let mut first_offsets: Vec<Option<usize>> = vec![None; subsigs.len()];
        // Matched byte ranges per body subsignature, for disinfection.
        let mut body_arenas: Vec<Vec<(usize, usize)>> = vec![Vec::new(); subsigs.len()];

        // Early cutoff: evaluate the gating subsig first; if the gate is absent
        // the expression can't match, so skip every other subsig of this
        // signature (the big win on logical-heavy databases / large files, where
        // most candidates are prefilter false positives). The gate comes from the
        // prefilter, which guarantees it is exactly the subsig whose atoms were
        // indexed — so when `threadable` the candidate's offsets verify it with
        // no whole-buffer rescan.
        let gate = self.prefilter.logical_gate(si);
        let mut gating_done: Option<usize> = None;
        if let Some(g) = gate {
            let gi = g.subsig as usize;
            if let Some(Subsignature::Body { offset, patterns }) = subsigs.get(gi) {
                let ranges = offset.scan_ranges(ctx.data.len(), ctx.pe.as_ref());
                if !ranges.is_empty() {
                    let gate_hints = if g.threadable { hints } else { None };
                    let prof = prof_enabled().then(std::time::Instant::now);
                    let (count, arenas) = body_matches(
                        patterns,
                        ctx.data,
                        &ranges,
                        options.max_subsignature_matches,
                        gate_hints,
                    );
                    if let Some(t) = prof {
                        let ms = t.elapsed().as_millis();
                        if ms >= 20 {
                            eprintln!(
                                "[SLOW-GATE] {ms}ms {} ({}:{}) hints={} threadable={}",
                                signature.name,
                                signature.source.path.display(),
                                signature.source.line,
                                gate_hints.map_or(0, |h| h.len()),
                                g.threadable,
                            );
                        }
                    }
                    if count == 0 {
                        return; // gate absent → signature cannot match
                    }
                    counts[gi] = count;
                    first_offsets[gi] = arenas.iter().map(|a| a.0).min();
                    body_arenas[gi] = arenas;
                    gating_done = Some(gi);
                }
            }
        }

        // Phase 1: body subsignatures (the gate, if any, is already done).
        for (i, subsig) in subsigs.iter().enumerate() {
            if Some(i) == gating_done {
                continue; // already evaluated above as the gate
            }
            if let Subsignature::Body {
                offset, patterns, ..
            } = subsig
            {
                if matches!(
                    offset.anchor,
                    OffsetAnchor::Unsupported(_)
                        | OffsetAnchor::MacroGroup(_)
                        | OffsetAnchor::VersionInfo
                ) {
                    continue;
                }
                let ranges = offset.scan_ranges(ctx.data.len(), ctx.pe.as_ref());
                if ranges.is_empty() {
                    continue;
                }
                // Non-gate subsigs have no threaded offsets → full scan.
                let (count, arenas) = body_matches(
                    patterns,
                    ctx.data,
                    &ranges,
                    options.max_subsignature_matches,
                    None,
                );
                counts[i] = count;
                first_offsets[i] = arenas.iter().map(|a| a.0).min();
                body_arenas[i] = arenas;
            }
        }

        // Phase 2: PCRE and byte-compare subsignatures, whose triggers
        // reference the phase-1 body results.
        for (i, subsig) in subsigs.iter().enumerate() {
            match subsig {
                Subsignature::Pcre {
                    trigger,
                    regex,
                    global,
                } => {
                    if trigger.eval(&counts).matched {
                        // Compile the regex on first trigger (lazy — most PCREs
                        // never fire, so they stay uncompiled and cost no RAM).
                        if let Some(re) = regex.get() {
                            counts[i] = if *global {
                                re.find_iter(ctx.data)
                                    .take(options.max_subsignature_matches)
                                    .count()
                            } else {
                                usize::from(re.is_match(ctx.data))
                            };
                        }
                    }
                }
                Subsignature::ByteCompare { spec, .. } => {
                    let trigger_hit = counts.get(spec.trigger_subsig).copied().unwrap_or(0) > 0;
                    if trigger_hit {
                        if let Some(base) = first_offsets.get(spec.trigger_subsig).copied().flatten()
                        {
                            if spec.evaluate(ctx.data, base) {
                                counts[i] = 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if signature.expression.eval(&counts).matched {
            // Collect the matched body arenas (capped) for disinfection.
            let mut arenas: Vec<(usize, usize)> = Vec::new();
            for sub in &body_arenas {
                for &range in sub {
                    if arenas.len() >= ARENA_CAP {
                        break;
                    }
                    arenas.push(range);
                }
            }
            matches.push(ScanMatch {
                name: signature.name.clone(),
                kind: SignatureKind::Logical,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
                arenas,
            });
        }
    }
}

/// Count pattern hits within `ranges` and collect the matched byte ranges
/// (capped at `ARENA_CAP`) for disinfection. When `hints` is `Some`, each
/// pattern is verified only at the prefilter-provided atom offsets
/// (`find_all_at`) instead of rescanning the whole buffer; `None` is a full scan.
fn body_matches(
    patterns: &[crate::pattern::Pattern],
    data: &[u8],
    ranges: &[(usize, usize)],
    limit: usize,
    hints: Option<&[u32]>,
) -> (usize, Vec<(usize, usize)>) {
    let mut count = 0usize;
    let mut arenas: Vec<(usize, usize)> = Vec::new();
    for pattern in patterns {
        let remaining = limit.saturating_sub(count);
        if remaining == 0 {
            break;
        }
        let hits = match hints {
            Some(h) => pattern.find_all_at(data, ranges, remaining, h),
            None => pattern.find_all(data, ranges, remaining),
        };
        for hit in hits {
            count += 1;
            if arenas.len() < ARENA_CAP {
                arenas.push((hit.start, hit.end));
            }
        }
    }
    (count, arenas)
}

fn target_matches(target: Option<u32>, ctx: &ScanContext<'_>, strict: bool) -> bool {
    if let Some(hint) = ctx.target_hint {
        let target = target.unwrap_or(0);
        return target == 0 || target == hint;
    }

    if !strict {
        return true;
    }

    let target = target.unwrap_or(0);
    if target == 0 {
        return true;
    }

    // Prefer the precise `.ftm`-derived type when available.
    if let Some(detected) = ctx.detected_target {
        return target == detected;
    }

    // Fall back to lightweight built-in heuristics.
    match target {
        1 => ctx.pe.is_some(),
        3 => looks_like_html(ctx.data),
        7 => looks_like_ascii_text(ctx.data),
        _ => true,
    }
}

/// Detect the container format for `.cdb` matching (extractor formats plus 7z).
fn detect_container_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some("7z");
    }
    detect_format(data)
}

/// Map a ClamAV `CL_TYPE_*` string to a ClamAV logical/extended target number.
fn clamav_type_to_target(clamav_type: &str) -> Option<u32> {
    Some(match clamav_type {
        "CL_TYPE_MSEXE" => 1,
        "CL_TYPE_OLE2" | "CL_TYPE_MSOLE2" => 2,
        "CL_TYPE_HTML" => 3,
        "CL_TYPE_MAIL" => 4,
        "CL_TYPE_GRAPHICS" | "CL_TYPE_GIF" | "CL_TYPE_PNG" | "CL_TYPE_JPEG" => 5,
        "CL_TYPE_ELF" => 6,
        "CL_TYPE_TEXT_ASCII" => 7,
        "CL_TYPE_MACHO" | "CL_TYPE_MACHO_UNIBIN" => 9,
        "CL_TYPE_PDF" => 10,
        "CL_TYPE_SWF" => 11,
        "CL_TYPE_JAVA" => 12,
        _ => return None,
    })
}

fn looks_like_ascii_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(8192)];
    let printable = sample
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    printable * 100 / sample.len() >= 85
}

fn looks_like_html(data: &[u8]) -> bool {
    let sample_len = data.len().min(4096);
    let sample = &data[..sample_len];
    contains_ascii_case_insensitive(sample, b"<html")
        || contains_ascii_case_insensitive(sample, b"<!doctype html")
        || contains_ascii_case_insensitive(sample, b"<script")
}

fn looks_like_supported_archive(data: &[u8]) -> bool {
    detect_format(data).is_some() || data.starts_with(b"7z\xbc\xaf\x27\x1c")
}

fn normalize_ascii_text(data: &[u8]) -> Vec<u8> {
    data.iter()
        .filter_map(|byte| match *byte {
            b'\t' | b'\n' | b'\r' | 0x00..=0x20 => None,
            0x21..=0x7e => Some(byte.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

struct HtmlViews {
    no_comments: Vec<u8>,
    no_tags: Vec<u8>,
    scripts: Vec<u8>,
}

fn normalize_html_views(data: &[u8]) -> HtmlViews {
    let decoded = decode_html_numeric_entities(data);
    let no_comments_raw = remove_html_comments(&decoded);
    let scripts_raw = extract_script_bodies(&no_comments_raw);
    HtmlViews {
        no_comments: normalize_ascii_text(&no_comments_raw),
        no_tags: normalize_ascii_text(&strip_html_tags(&no_comments_raw)),
        scripts: normalize_ascii_text(&scripts_raw),
    }
}

fn decode_html_numeric_entities(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if data[index] == b'&' && data.get(index + 1) == Some(&b'#') {
            let mut cursor = index + 2;
            let radix = if matches!(data.get(cursor), Some(b'x' | b'X')) {
                cursor += 1;
                16
            } else {
                10
            };
            let start = cursor;
            while cursor < data.len()
                && ((radix == 16 && data[cursor].is_ascii_hexdigit())
                    || (radix == 10 && data[cursor].is_ascii_digit()))
            {
                cursor += 1;
            }
            if cursor > start && data.get(cursor) == Some(&b';') {
                if let Ok(raw) = std::str::from_utf8(&data[start..cursor]) {
                    if let Ok(value) = u32::from_str_radix(raw, radix) {
                        if let Some(ch) = char::from_u32(value) {
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            index = cursor + 1;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(data[index]);
        index += 1;
    }
    out
}

fn remove_html_comments(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if data[index..].starts_with(b"<!--") {
            if let Some(end) = find_bytes(&data[index + 4..], b"-->") {
                index += 4 + end + 3;
                continue;
            }
        }
        out.push(data[index]);
        index += 1;
    }
    out
}

fn strip_html_tags(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut in_tag = false;
    for byte in data {
        match *byte {
            b'<' => in_tag = true,
            b'>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(*byte),
            _ => {}
        }
    }
    out
}

fn extract_script_bodies(data: &[u8]) -> Vec<u8> {
    let lower = data
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(start) = find_bytes(&lower[cursor..], b"<script") {
        let tag_start = cursor + start;
        let Some(tag_end_rel) = find_bytes(&lower[tag_start..], b">") else {
            break;
        };
        let body_start = tag_start + tag_end_rel + 1;
        let Some(body_end_rel) = find_bytes(&lower[body_start..], b"</script") else {
            break;
        };
        let body_end = body_start + body_end_rel;
        out.extend_from_slice(&data[body_start..body_end]);
        out.push(b'\n');
        cursor = body_end + b"</script".len();
    }
    out
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.to_ascii_lowercase() == right.to_ascii_lowercase())
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{
        ContainerSignature, ExtendedSignature, FileTypeMagic, NumSpec, OffsetSpec, SourceLocation,
    };
    use crate::logical::parse_logical_signature;
    use crate::pattern::{compile_pattern_variants, Modifiers};

    #[test]
    fn scans_extended_signature() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: "Test.Signature".to_string(),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap(),
                source: source.clone(),
            }],
            logical: Vec::new(),
            container: Vec::new(),
            file_type_magic: Vec::new(),
            unsupported: Vec::new(),
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        let found = engine.scan_bytes(b"xxABCyy", ScanOptions::default());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Test.Signature");
        assert_eq!(found[0].source, source);
        assert_eq!(found[0].object_path, "root");
        assert_eq!(found[0].view, ScanView::Raw);
    }

    #[test]
    fn prefilter_matches_exhaustive_scan() {
        // Same DB scanned with the real Aho-Corasick prefilter ("ABC" is the atom)
        // must give identical results: matches when the atom is present, skips
        // (no false negative, no false positive) when it isn't.
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: "Test.Signature".to_string(),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap(),
                source: source.clone(),
            }],
            logical: Vec::new(),
            container: Vec::new(),
            file_type_magic: Vec::new(),
            unsupported: Vec::new(),
        };
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        let engine = Engine { database, bytecodes: Vec::new(), prefilter };

        // Atom present → detected.
        let hit = engine.scan_bytes(b"xxABCyy", ScanOptions::default());
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].name, "Test.Signature");

        // Atom absent → correctly skipped, no match.
        let miss = engine.scan_bytes(b"xxxyyyzzz", ScanOptions::default());
        assert!(miss.is_empty());
    }

    #[test]
    fn scans_normalized_text_target() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: "Test.Text".to_string(),
                target: Some(7),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("68656c6c6f776f726c64", Modifiers::default())
                    .unwrap(),
                source,
            }],
            logical: Vec::new(),
            container: Vec::new(),
            file_type_magic: Vec::new(),
            unsupported: Vec::new(),
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        let found = engine.scan_bytes(b"HeLLo   \r\nWorld", ScanOptions::default());
        assert!(found
            .iter()
            .any(|hit| hit.name == "Test.Text" && hit.view == ScanView::NormalizedText));
    }

    #[test]
    fn scans_html_without_tags() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: "Test.Html".to_string(),
                target: Some(3),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("7061796c6f6164", Modifiers::default()).unwrap(),
                source,
            }],
            logical: Vec::new(),
            container: Vec::new(),
            file_type_magic: Vec::new(),
            unsupported: Vec::new(),
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        let found = engine.scan_bytes(
            b"<html><body>Pay<!--x-->load</body></html>",
            ScanOptions::default(),
        );
        assert!(found
            .iter()
            .any(|hit| hit.name == "Test.Html" && hit.view == ScanView::HtmlNoTags));
    }

    #[test]
    fn scans_extracted_zip_child() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: "Test.Zip.Child".to_string(),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("4d414c57415245", Modifiers::default()).unwrap(),
                source,
            }],
            logical: Vec::new(),
            container: Vec::new(),
            file_type_magic: Vec::new(),
            unsupported: Vec::new(),
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        let found = engine.scan_bytes(&stored_zip("child.bin", b"MALWARE"), ScanOptions::default());
        assert!(found.iter().any(|hit| {
            hit.name == "Test.Zip.Child"
                && hit.object_path == "root#archive[0]"
                && hit.view == ScanView::Raw
        }));
    }

    #[test]
    fn scans_pcre_logical_signature() {
        let (sig, warnings) = crate::logical::parse_logical_signature(
            "Test.Pcre;Target:0;0&1;4141;0/world/",
            SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ldb")),
                line: 1,
            },
        )
        .unwrap();
        assert!(warnings.is_empty());
        let database = Database {
            logical: vec![sig],
            ..Default::default()
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        // Body "AA" present and regex "world" present -> match.
        let found = engine.scan_bytes(b"AA hello world", ScanOptions::default());
        assert!(found.iter().any(|m| m.name == "Test.Pcre"));
        // Body trigger "AA" absent -> PCRE not evaluated -> no match.
        let none = engine.scan_bytes(b"hello world", ScanOptions::default());
        assert!(none.is_empty());
    }

    #[test]
    fn scans_byte_compare_logical_signature() {
        let (sig, warnings) = crate::logical::parse_logical_signature(
            "Test.Bc;Target:0;0&1;53495a45;0(>>4#il2#>0)",
            SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ldb")),
                line: 1,
            },
        )
        .unwrap();
        assert!(warnings.is_empty());
        let database = Database {
            logical: vec![sig],
            ..Default::default()
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        // "SIZE" then 2 LE bytes = 5 (>0) -> match.
        let found = engine.scan_bytes(b"SIZE\x05\x00tail", ScanOptions::default());
        assert!(found.iter().any(|m| m.name == "Test.Bc"));
        // 2 LE bytes = 0 -> byte-compare fails.
        let none = engine.scan_bytes(b"SIZE\x00\x00tail", ScanOptions::default());
        assert!(none.is_empty());
    }

    #[test]
    fn scans_container_metadata_signature() {
        let container = ContainerSignature {
            name: "Test.Cdb".to_string(),
            container_type: ContainerType::Format("zip"),
            container_size: NumSpec::Any,
            filename: None,
            size_in_container: NumSpec::Any,
            size_real: NumSpec::Exact(7),
            encrypted: None,
            file_pos: NumSpec::Exact(1),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.cdb")),
                line: 1,
            },
        };
        let database = Database {
            container: vec![container],
            ..Default::default()
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        // Member "MALWARE" is 7 bytes at position 1 inside a zip.
        let found =
            engine.scan_bytes(&stored_zip("child.bin", b"MALWARE"), ScanOptions::default());
        assert!(found
            .iter()
            .any(|m| m.name == "Test.Cdb" && m.kind == SignatureKind::Container));
    }

    #[test]
    fn ftm_strict_typing_filters_mismatched_target() {
        let magic = FileTypeMagic {
            offset: OffsetSpec {
                anchor: OffsetAnchor::Absolute(0),
                max_shift: None,
            },
            patterns: compile_pattern_variants("4d5a", Modifiers::default()).unwrap(),
            clamav_type: "CL_TYPE_MSEXE".to_string(),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ftm")),
                line: 1,
            },
        };
        let ext = ExtendedSignature {
            name: "Html.Sig".to_string(),
            target: Some(3),
            offset: OffsetSpec::any(),
            patterns: compile_pattern_variants("4142", Modifiers::default()).unwrap(),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ndb")),
                line: 1,
            },
        };
        let database = Database {
            extended: vec![ext],
            file_type_magic: vec![magic],
            ..Default::default()
        };
        let engine = Engine { database, bytecodes: Vec::new(), prefilter: crate::prefilter::AtomPrefilter::disabled() };
        // "MZAB": .ftm types it MSEXE (target 1); the sig's target 3 -> filtered when strict.
        let strict = ScanOptions {
            strict_targets: true,
            ..ScanOptions::default()
        };
        assert!(engine.scan_bytes(b"MZAB", strict).is_empty());
        // Permissive mode ignores target typing -> matches.
        assert!(engine
            .scan_bytes(b"MZAB", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Html.Sig"));
    }

    // --- Offset-threading equivalence: the built prefilter (threaded verify +
    // gating cutoff) must report EXACTLY the same signatures as a disabled
    // prefilter (full per-position scan, the ground truth). This is the core
    // "no detection regression" guarantee for offset-threading. ---

    fn match_keys(found: &[ScanMatch]) -> Vec<String> {
        let mut v: Vec<String> = found
            .iter()
            .map(|m| format!("{}@{}", m.name, m.object_path))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    fn assert_threading_equiv(build_db: impl Fn() -> Database, data: &[u8]) -> Vec<String> {
        let opts = ScanOptions {
            max_matches: 4096,
            ..ScanOptions::default()
        };
        // Ground truth: prefilter disabled → Candidates::All → full scan, no gating.
        let engine_full = Engine {
            database: build_db(),
            bytecodes: Vec::new(),
            prefilter: crate::prefilter::AtomPrefilter::disabled(),
        };
        let full = match_keys(&engine_full.scan_bytes(data, opts));
        // Threaded: real prefilter → candidate offsets + aligned gating cutoff.
        let db = build_db();
        let prefilter = crate::prefilter::AtomPrefilter::build(&db);
        let engine_thr = Engine {
            database: db,
            bytecodes: Vec::new(),
            prefilter,
        };
        let threaded = match_keys(&engine_thr.scan_bytes(data, opts));
        assert_eq!(
            full, threaded,
            "offset-threading changed the match set on {:?}",
            String::from_utf8_lossy(data)
        );
        threaded
    }

    fn diverse_database() -> Database {
        let src = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("t.ndb")),
            line: 1,
        };
        let ext = |name: &str, target: u32, offset: OffsetSpec, body: &str, m: Modifiers| {
            ExtendedSignature {
                name: name.to_string(),
                target: Some(target),
                offset,
                patterns: compile_pattern_variants(body, m).unwrap(),
                source: src.clone(),
            }
        };
        let nocase = Modifiers {
            nocase: true,
            ..Modifiers::default()
        };
        let extended = vec![
            // Anchored literal, fixed prefix 0.
            ext("E.Anchored", 0, OffsetSpec::any(), "4141414142424242", Modifiers::default()),
            // Masked first byte then literal → required_prefix = 1 (threaded at off-1).
            ext("E.MaskedPrefix", 0, OffsetSpec::any(), "??48495051", Modifiers::default()),
            // nocase → no required_literal → find_all_at falls back to full scan.
            ext("E.Nocase", 0, OffsetSpec::any(), "6d616c7761726e", nocase),
            // nocase atom made of DIGITS only ("012345") — must still match on a
            // letterless buffer (guards against an "is there a letter?" skip).
            ext("E.NocaseDigits", 0, OffsetSpec::any(), "303132333435", nocase),
            // Leading wildcard → required_prefix None → fallback path.
            ext("E.LeadingWild", 0, OffsetSpec::any(), "*5a5a5a5a", Modifiers::default()),
            // Absolute offset 0 only: a match elsewhere must be rejected by ranges.
            ext(
                "E.AbsZero",
                0,
                OffsetSpec { anchor: OffsetAnchor::Absolute(0), max_shift: None },
                "57575757",
                Modifiers::default(),
            ),
            // EOF-relative: only the tail occurrence is in range.
            ext(
                "E.EofTail",
                0,
                OffsetSpec { anchor: OffsetAnchor::EofMinus(8), max_shift: Some(8) },
                "59595959",
                Modifiers::default(),
            ),
        ];
        let logical: Vec<_> = [
            "L.And;Target:0;0&1;6b6b6b6b6b6b;6c6c6c6c6c6c", // "kkkkkk" & "llllll"
            "L.Or;Target:0;0|1;6d6d6d6d6d6d;6e6e6e6e6e6e",  // "mmmmmm" | "nnnnnn"
            "L.AndWild;Target:0;0&1;*6f6f6f6f6f6f;707070707070", // "*oooooo" & "pppppp"
        ]
        .iter()
        .map(|line| parse_logical_signature(line, src.clone()).unwrap().0)
        .collect();
        Database {
            extended,
            logical,
            ..Default::default()
        }
    }

    #[test]
    fn threading_matches_full_scan_across_signature_shapes() {
        // Kitchen-sink buffer triggering a mix of shapes.
        let hits = assert_threading_equiv(
            diverse_database,
            b"00AAAABBBB00 zHIPQ MALWARN prefix-ZZZZ kkkkkk llllll oooooo pppppp",
        );
        // Not vacuous: confirm representative detections actually fired.
        assert!(hits.iter().any(|k| k.starts_with("E.Anchored@")));
        assert!(hits.iter().any(|k| k.starts_with("E.MaskedPrefix@")));
        assert!(hits.iter().any(|k| k.starts_with("E.Nocase@"))); // nocase MALWARN
        assert!(hits.iter().any(|k| k.starts_with("E.LeadingWild@")));
        assert!(hits.iter().any(|k| k.starts_with("L.And@")));
        assert!(hits.iter().any(|k| k.starts_with("L.AndWild@")));

        // Range-sensitive negatives: an out-of-range occurrence must NOT match,
        // identically for threaded and full scan (catches range-bypass bugs).
        // "WWWW" only away from offset 0 → E.AbsZero must not fire.
        let no_abs = assert_threading_equiv(diverse_database, b"....WWWW....");
        assert!(!no_abs.iter().any(|k| k.starts_with("E.AbsZero@")));
        // "WWWW" at offset 0 → E.AbsZero fires.
        let abs = assert_threading_equiv(diverse_database, b"WWWW........");
        assert!(abs.iter().any(|k| k.starts_with("E.AbsZero@")));

        // "YYYY" only at the start → outside the EOF-8 tail window → no match.
        let mut early = b"YYYY".to_vec();
        early.extend(std::iter::repeat(b'.').take(40));
        let no_eof = assert_threading_equiv(diverse_database, &early);
        assert!(!no_eof.iter().any(|k| k.starts_with("E.EofTail@")));
        // "YYYY" in the tail window → match.
        let mut late = vec![b'.'; 40];
        late.extend_from_slice(b"YYYY");
        let eof = assert_threading_equiv(diverse_database, &late);
        assert!(eof.iter().any(|k| k.starts_with("E.EofTail@")));

        // Logical AND with one operand missing → no match (both engines agree).
        let partial = assert_threading_equiv(diverse_database, b"kkkkkk but no ell");
        assert!(!partial.iter().any(|k| k.starts_with("L.And@")));

        // LETTERLESS buffer containing a digit-only nocase atom: the nocase pass
        // must NOT be skipped (regression guard for the alpha-byte fast-path).
        let digits = assert_threading_equiv(diverse_database, b"##!!##012345##!!##");
        assert!(digits.iter().any(|k| k.starts_with("E.NocaseDigits@")));

        // Empty-ish / no-trigger buffer.
        assert_threading_equiv(diverse_database, b"nothing to see here 12345");
    }

    fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut out = Vec::new();
        let local_offset = 0u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        let central_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&local_offset.to_le_bytes());
        out.extend_from_slice(name_bytes);

        let central_size = out.len() as u32 - central_offset;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}
