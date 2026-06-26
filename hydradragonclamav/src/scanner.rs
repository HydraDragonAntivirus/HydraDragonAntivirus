use crate::database::{ContainerType, Database, OffsetAnchor, OffsetSpec, SourceLocation};
use crate::logical::Subsignature;
use crate::pe::{parse_pe, PeInfo};
use hydradragonextractor::{detect_format, extract_archive_from_bytes};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct Engine {
    pub database: Database,
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
            max_matches: 1,
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
    /// Phishing heuristic (`.pdb`/`.gdb`/`.wdb` driven spoofed-domain check).
    Phishing,
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
    /// PE info, parsed **lazily** on first access (the common case is a non-PE
    /// file, so calling `parse_pe` for every object is pure waste — the quick MZ
    /// check in the `is_pe` guard handles the "skip normalized views" decision).
    pe: std::cell::OnceCell<Option<PeInfo>>,
    /// Target forced by a normalized view (text=7, html=3).
    pub target_hint: Option<u32>,
    /// Target derived from `.ftm` file-type magic (used only in strict mode).
    pub detected_target: Option<u32>,
    pub object_path: &'a str,
    pub view: ScanView,
    /// ClamAV `CL_TYPE_*` of this object's IMMEDIATE parent container (the type
    /// of the archive it was extracted from), or `None` at the top level. Used to
    /// evaluate logical signatures' `Container:` TDB constraint, mirroring
    /// ClamAV's `cli_recursion_stack_get_type(ctx, -2)`.
    pub container_type: Option<&'static str>,
    /// The file's image fuzzy hash (perceptual pHash), computed lazily once and
    /// only when a `fuzzy_img#` subsignature is actually evaluated. `None` inside
    /// the cell means "computed, not a decodable image".
    pub image_fuzzy_hash: std::cell::OnceCell<Option<[u8; 8]>>,
    /// Per-buffer 3-gram presence filter, built lazily on first use, for skipping
    /// the whole-buffer scan of non-gate body subsignatures whose literal is
    /// provably absent. `None` inside the cell means the buffer was too small to be
    /// worth a filter.
    pub presence: std::cell::OnceCell<Option<crate::presence::PresenceFilter>>,
}

impl ScanContext<'_> {
    /// Lazily parse (and cache) PE info. Non-PE files return `None` after a
    /// quick magic check; PE files pay the full parse cost once on first access.
    pub(crate) fn pe(&self) -> Option<&PeInfo> {
        self.pe
            .get_or_init(|| parse_pe(self.data))
            .as_ref()
    }

    /// Fast magic-byte PE sniff (just the MZ signature) — no full parse.
    /// Used by the top-level `scan_object` to decide whether to skip normalized
    /// views and phishing heuristics on PE files.
    pub(crate) fn is_pe_magic(&self) -> bool {
        self.data.len() >= 2 && self.data[..2] == *b"MZ"
    }

    /// Lazily build (and cache) this buffer's 3-gram presence filter.
    pub(crate) fn presence(&self) -> Option<&crate::presence::PresenceFilter> {
        self.presence
            .get_or_init(|| crate::presence::PresenceFilter::build(self.data))
            .as_ref()
    }

    /// Lazily compute (and cache) this file's image fuzzy hash, mirroring
    /// ClamAV's per-fmap `fuzzy_hash_calculate_image`. Guarded by an image-magic
    /// check so non-image files never pay the decode cost.
    pub(crate) fn image_fuzzy_hash(&self) -> Option<[u8; 8]> {
        *self.image_fuzzy_hash.get_or_init(|| {
            if looks_like_image(self.data) {
                crate::fuzzy::calculate_image(self.data)
            } else {
                None
            }
        })
    }
}

/// Quick magic-byte test for the raster formats the `image` crate decodes, so we
/// only attempt the (relatively expensive) fuzzy-hash decode on plausible images.
fn looks_like_image(d: &[u8]) -> bool {
    d.starts_with(b"\x89PNG\r\n\x1a\n")            // PNG
        || d.starts_with(&[0xFF, 0xD8, 0xFF])      // JPEG
        || d.starts_with(b"GIF87a")
        || d.starts_with(b"GIF89a")
        || d.starts_with(b"BM")                    // BMP
        || (d.len() >= 12 && d.starts_with(b"RIFF") && &d[8..12] == b"WEBP")
}

struct ScanState {
    matches: Vec<ScanMatch>,
    objects_seen: usize,
}

/// Reusable per-call buffers for `scan_one_logical` — the outer `scan_logical`
/// allocates them once and passes `&mut` so the backing store is reused across
/// every candidate, avoiding ~4 heap allocations per logical-sig evaluation.
struct LogicalScanBufs {
    counts: Vec<usize>,
    last_offsets: Vec<Option<usize>>,
    body_arenas: Vec<Vec<(usize, usize)>>,
    evaluated: Vec<bool>,
}

impl Engine {
    /// Prefilter heap breakdown, for `--mem-stats` profiling.
    pub fn prefilter_mem_report(&self) -> String {
        self.prefilter.mem_report()
    }

    pub fn from_database_dir(path: impl AsRef<Path>) -> io::Result<(Self, crate::LoadReport)> {
        let path = path.as_ref();
        let (mut database, mut report) = Database::load_dir(path)?;
        // Load bytecode containers, then decode + interpreter-prepare each program
        // and register its trigger as a logical signature linked to the program
        // (ClamAV's bytecode-lsig wiring). Must happen BEFORE the prefilter is
        // built so the triggers are indexed as candidates.
        // The raw Bytecode structs (with source strings) are DROPPED after decoding
        // — their source text is not needed at scan time, saving 50-200 MB.
        let bc = crate::bytecode::BytecodeSet::load_from_dir(path);
        report.bytecodes_loaded = bc.report.loaded;
        for prog in bc.bytecodes {
            // decode_bytecode borrows prog.source, then we move prog.trigger
            // out. prog is dropped at the end of scope.
            let decoded = match crate::bytecode_vm::decode_bytecode(&prog.source) {
                Ok(Some(mut decoded)) => {
                    if decoded.prepare_interpreter().is_err() {
                        continue;
                    }
                    decoded
                }
                _ => continue,
            };
            let Some(trigger_line) = prog.trigger else {
                continue;
            };
            let source_loc = crate::database::SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("bytecode")),
                line: 0,
            };
            if let Ok((mut sig, _warnings)) =
                crate::logical::parse_logical_signature(&trigger_line, source_loc)
            {
                let bc_idx = database.bytecode_programs.len();
                database.bytecode_programs.push(decoded);
                sig.bytecode = Some(bc_idx);
                database.logical.push(sig);
            }
        }
        // Atom prefilter (daachorse): one selective required atom per signature,
        // built via a compact CSR mapping. One pass per buffer picks the few
        // candidate signatures instead of scanning all ~500k — fast scans and
        // far fewer page faults.
        // Build the Aho-Corasick automata in memory from the loaded rules (no
        // on-disk `.bin` cache); the load high-water-mark is trimmed afterwards.
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        Ok((Self { database, prefilter }, report))
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
        // Top-level object has no parent container.
        self.scan_object(data, object_path, None, 0, options, &mut state);
        state.matches
    }

    fn scan_object(
        &self,
        data: &[u8],
        object_path: &str,
        container_type: Option<&'static str>,
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

        let ctx = ScanContext {
            data,
            pe: std::cell::OnceCell::new(),
            target_hint: None,
            detected_target,
            object_path,
            view: ScanView::Raw,
            container_type,
            image_fuzzy_hash: Default::default(),
            presence: Default::default(),
        };
        let is_pe = ctx.is_pe_magic();
        self.scan_context(&ctx, options, &mut state.matches);

        // Normalized text/HTML views exist to catch text-like malware (scripts,
        // HTML). A PE executable is neither text nor HTML, so generating and
        // rescanning up to four derived copies of it is pure waste — skip it.
        // (Text/HTML files still go through the views below.)
        if options.scan_normalized && !is_pe && state.matches.len() < options.max_matches {
            self.scan_normalized_views(data, object_path, container_type, options, state);
        }

        // Phishing heuristic: harvest `<a href>` link pairs from HTML/email and
        // flag spoofed protected domains (.pdb/.gdb gated by .wdb allow list).
        // Only meaningful for HTML, and only when a protected-domain DB is loaded.
        if !is_pe
            && !self.database.phishing.protected.is_empty()
            && state.matches.len() < options.max_matches
            && looks_like_html(data)
        {
            self.scan_phishing(data, object_path, options, &mut state.matches);
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
                    // Children's immediate parent container is THIS archive.
                    let child_container = clamav_container_type(data);
                    for (index, child) in children.iter().enumerate() {
                        if state.matches.len() >= options.max_matches
                            || state.objects_seen >= options.max_child_objects
                        {
                            break;
                        }
                        let child_path = format!("{object_path}#archive[{index}]");
                        self.scan_object(
                            child,
                            &child_path,
                            child_container,
                            depth + 1,
                            options,
                            state,
                        );
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
            if sig.has_filename
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
                    name: sig.name.to_string(),
                    kind: SignatureKind::Container,
                    source: sig.source.clone(),
                    object_path: object_path.to_string(),
                    view: ScanView::Raw,
                    arenas: Vec::new(),
                });
            }
        }
    }

    /// Run the phishing heuristic over an HTML/email object's link pairs,
    /// appending one `ScanMatch` per detected spoof (`Heuristics.Phishing.*`).
    fn scan_phishing(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        for hit in self.database.phishing.scan_html(data) {
            if matches.len() >= options.max_matches {
                return;
            }
            matches.push(ScanMatch {
                name: hit.name.to_string(),
                kind: SignatureKind::Phishing,
                source: hit.source,
                object_path: object_path.to_string(),
                view: ScanView::Raw,
                arenas: Vec::new(),
            });
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
                return Some(&magic.clamav_type);
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
        if prof_enabled() {
            use std::time::Instant;
            let t0 = Instant::now();
            let (ext_cands, log_cands) = self.prefilter.candidates(ctx.data);
            let t1 = Instant::now();
            let (ne, nl) = (ext_cands.len(), log_cands.len());
            let (te, tl) = (ext_cands.threaded_count(), log_cands.threaded_count());
            eprintln!(
                "[PROF] {}KB view={:?} ext_cands={ne}(threaded {te}) log_cands={nl}(threaded {tl}) prefilter={}ms (scanning…)",
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
        container_type: Option<&'static str>,
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
                container_type,
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
                container_type,
                options,
                state,
            );
            self.scan_derived_view(
                &html.no_tags,
                object_path,
                3,
                ScanView::HtmlNoTags,
                container_type,
                options,
                state,
            );
            if !html.scripts.is_empty() {
                self.scan_derived_view(
                    &html.scripts,
                    object_path,
                    3,
                    ScanView::HtmlScript,
                    container_type,
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
        container_type: Option<&'static str>,
        options: ScanOptions,
        state: &mut ScanState,
    ) {
        if data.is_empty() || state.matches.len() >= options.max_matches {
            return;
        }
        let ctx = ScanContext {
            data,
            pe: std::cell::OnceCell::new(),
            target_hint: Some(target_hint),
            detected_target: None,
            object_path,
            view,
            container_type,
            image_fuzzy_hash: Default::default(),
            presence: Default::default(),
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
            OffsetAnchor::Unsupported(_) | OffsetAnchor::MacroGroup(_)
        ) {
            return;
        }
        // `VI:` (CLI_OFF_VERSION) scans anywhere, then keeps only matches starting
        // inside the PE's version-info string offsets (same as the logical path).
        let is_vinfo = matches!(signature.offset.anchor, OffsetAnchor::VersionInfo);
        let ranges = if is_vinfo {
            vec![(0, ctx.data.len())]
        } else {
            signature.offset.scan_ranges(ctx.data.len(), ctx.pe())
        };
        if ranges.is_empty() {
            return;
        }
        let vinfo: &[u32] = if is_vinfo {
            ctx.pe().map(|p| p.vinfo.as_slice()).unwrap_or(&[])
        } else {
            &[]
        };
        let prof = prof_enabled().then(std::time::Instant::now);
        let mut arenas: Vec<(usize, usize)> = Vec::new();
        for pattern in &signature.patterns {
            let hits = match hints {
                Some(h) => pattern.find_all_at(ctx.data, &ranges, ARENA_CAP, h),
                None => pattern.find_all(ctx.data, &ranges, ARENA_CAP),
            };
            for hit in hits {
                if is_vinfo && vinfo.binary_search(&(hit.start as u32)).is_err() {
                    continue; // VI: match must start at a version-info offset
                }
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
                    "[SLOW-EXT] {ms}ms {} ({}:{}) hints={}",
                    self.database.ext_name(signature),
                    signature.source.path.display(),
                    signature.source.line,
                    hints.map_or(0, |h| h.len()),
                );
            }
        }
        if !arenas.is_empty() {
            matches.push(ScanMatch {
                name: self.database.ext_name(signature).to_string(),
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
        let mut bufs = LogicalScanBufs {
            counts: Vec::new(),
            last_offsets: Vec::new(),
            body_arenas: Vec::new(),
            evaluated: Vec::new(),
        };
        match cands {
            crate::prefilter::Candidates::All => {
                for si in 0..self.database.logical.len() {
                    if matches.len() >= options.max_matches {
                        return;
                    }
                    self.scan_one_logical(si, None, ctx, options, matches, &mut bufs);
                }
            }
            crate::prefilter::Candidates::List(set) => {
                for (sig, offsets) in set.iter() {
                    if matches.len() >= options.max_matches {
                        return;
                    }
                    let hints = (!offsets.is_empty()).then_some(offsets);
                    let t = prof_enabled().then(std::time::Instant::now);
                    self.scan_one_logical(sig as usize, hints, ctx, options, matches, &mut bufs);
                    if let Some(t) = t {
                        let ms = t.elapsed().as_millis();
                        if ms >= 50 {
                            eprintln!("[SLOW-LOG] {ms}ms {}", self.database.logical[sig as usize].name);
                        }
                    }
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
        bufs: &mut LogicalScanBufs,
    ) {
        let signature = &self.database.logical[si];
        if !target_matches(signature.target, ctx, options.strict_targets) {
            return;
        }
        // TDB gating (ClamAV's target description block). A signature only fires
        // when these context constraints hold; matching the body alone would
        // false-positive on every file satisfying the body.
        //
        // `tdb_unsupported` covers constraints we can't yet evaluate (IconGroup,
        // HandlerType, …) — skip entirely. The rest we evaluate from context.
        if signature.tdb_unsupported {
            return;
        }
        if let Some((min, max)) = signature.file_size {
            let len = ctx.data.len() as u64;
            if len < min || len > max {
                return;
            }
        }
        if let Some(want) = signature.container.as_deref() {
            // ClamAV: the immediate parent container type must match (or the sig
            // accepts any container via CL_TYPE_ANY). A top-level object has no
            // parent container, so a container-constrained sig can't fire on it.
            let parent = ctx.container_type;
            let ok = match parent {
                Some(t) => want == "CL_TYPE_ANY" || want == t,
                None => false,
            };
            if !ok {
                return;
            }
        }
        if !signature.intermediates.is_empty() {
            // ClamAV intermediates_eval: the ancestor container-type chain must
            // match the recursion stack (innermost = the immediate parent). We
            // track only the immediate parent, so a single-level intermediate is
            // checked against it; a multi-level chain we cannot confirm and so do
            // not fire on (avoids a false positive, never alerts spuriously).
            let inner = signature.intermediates.last().map(String::as_str).unwrap_or("");
            let inner_ok = inner == "CL_TYPE_ANY" || ctx.container_type == Some(inner);
            if !inner_ok || signature.intermediates.len() > 1 {
                return;
            }
        }
        if let Some((min, max)) = signature.nos {
            // NumberOfSections applies to PE files; without PE info it can't hold.
            let n = match ctx.pe() {
                Some(pe) => pe.sections.len() as u32,
                None => return,
            };
            if n < min || n > max {
                return;
            }
        }
        if let Some((min, max)) = signature.ep {
            // EntryPoint compares against the PE entry point's RAW file offset
            // (ClamAV exeinfo.ep = cli_rawaddr(vep,...)); requires a parsed PE.
            let ep = match ctx.pe().and_then(|pe| pe.entry_point_offset) {
                Some(e) => e as u32,
                None => return,
            };
            if ep < min || ep > max {
                return;
            }
        }
        // IconGroup1/2 (ClamAV matchicon): the PE must carry an icon matching an
        // `.idb` fingerprint in the requested groups, else the signature can't fire.
        if signature.icongrp1.is_some() || signature.icongrp2.is_some() {
            let pe = match ctx.pe() {
                Some(pe) => pe,
                None => return,
            };
            if !crate::icon_match::matchicon(
                ctx.data,
                &pe.sections,
                pe.size_of_headers,
                pe.res_rva,
                &self.database.icons,
                signature.icongrp1.as_deref(),
                signature.icongrp2.as_deref(),
            ) {
                return;
            }
        }
        let subsigs = &signature.subsignatures;
        let n = subsigs.len();
        bufs.counts.clear();
        bufs.counts.resize(n, 0);
        bufs.last_offsets.clear();
        bufs.last_offsets.resize(n, None);
        bufs.body_arenas.clear();
        bufs.body_arenas.resize_with(n, Vec::new);
        bufs.evaluated.clear();
        bufs.evaluated.resize(n, false);
        let counts = &mut bufs.counts;
        let last_offsets = &mut bufs.last_offsets;
        let body_arenas = &mut bufs.body_arenas;
        let evaluated = &mut bufs.evaluated;

        // Early cutoff: evaluate the gating subsig first; if the gate is absent
        // the expression can't match, so skip every other subsig of this
        // signature (the big win on logical-heavy databases / large files, where
        // most candidates are prefilter false positives). The gate comes from the
        // prefilter, which guarantees it is exactly the subsig whose atoms were
        // indexed — so when `threadable` the candidate's offsets verify it with
        // no whole-buffer rescan.
        // OR-indexed signatures (no single required subsig) carry the UNION of all
        // their subsignatures' atom offsets as `hints`. Because a subsig match must
        // contain one of its atoms — whose every occurrence is in that union (it is
        // empty, never partial, on overflow) — each subsig need only be scanned in
        // small windows around those offsets, not over the whole buffer. This is
        // the logical-scan analogue of the threaded extended path; without it these
        // signatures (e.g. 30+ `TwinWave.EvilDoc.*` doc sigs with ~31 keyword
        // subsigs each) rescan the entire buffer once per subsignature.
        let all_indexed =
            self.prefilter.logical_all_indexed(si) && hints.is_some_and(|h| !h.is_empty());

        let gate = self.prefilter.logical_gate(si);
        let mut gating_done: Option<usize> = None;
        // When every subsig is restricted to the union windows below, the separate
        // non-threadable gate cutoff (a full buffer rescan) is redundant.
        if let Some(g) = gate.filter(|_| !all_indexed) {
            let gi = g.subsig as usize;
            if let Some(Subsignature::Body { offset, patterns }) = subsigs.get(gi) {
                let default_offset = OffsetSpec::any();
                let offset = offset.as_deref().unwrap_or(&default_offset);
                let ranges = offset.scan_ranges(ctx.data.len(), ctx.pe());
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
                    last_offsets[gi] = arenas.iter().map(|a| a.0).max();
                    body_arenas[gi] = arenas;
                    evaluated[gi] = true;
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
                let any = OffsetSpec::any();
                let offset = offset.as_deref().unwrap_or(&any);
                if matches!(
                    offset.anchor,
                    OffsetAnchor::Unsupported(_) | OffsetAnchor::MacroGroup(_)
                ) {
                    continue;
                }
                // Presence pre-check: a body subsig matches only if one of its
                // pattern variants' literal occurs. If the per-buffer 3-gram filter
                // proves every variant's atom absent, this subsig is absent (count
                // 0) — skip its whole-buffer scan. Sound: the filter never reports a
                // present literal as absent.
                if let Some(pf) = ctx.presence() {
                    if !patterns.iter().any(|p| p.atom_maybe_present(pf)) {
                        evaluated[i] = true; // counts[i] stays 0
                        if !signature.expression.can_still_match(counts, evaluated) {
                            return;
                        }
                        continue;
                    }
                }
                // `VI:` (ClamAV `CLI_OFF_VERSION`) scans anywhere, then keeps only
                // matches starting inside the PE's version-info string offsets
                // (matcher-ac.c: `cli_hashset_contains(mdata->vinfo, realoff)`).
                let is_vinfo = matches!(offset.anchor, OffsetAnchor::VersionInfo);
                let base_ranges = if is_vinfo {
                    vec![(0, ctx.data.len())]
                } else {
                    offset.scan_ranges(ctx.data.len(), ctx.pe())
                };
                if base_ranges.is_empty() {
                    continue;
                }
                // For OR-indexed sigs, restrict this subsig's scan to windows around
                // the prefilter's union offsets (a match must start within
                // `max_match_len` of one of its atoms). A SIMD scan of those small
                // windows beats threading each subsig against the FULL union hint set
                // (most of which belong to other subsigs and just fail to verify).
                // `None` max length (open gap) can't be bounded → keep the full scan.
                let restricted;
                let ranges: &[(usize, usize)] = if all_indexed && !is_vinfo {
                    match subsig_max_match_len(patterns) {
                        Some(ml) => {
                            restricted =
                                restrict_ranges(&base_ranges, hints.unwrap(), ml, ctx.data.len());
                            &restricted
                        }
                        None => &base_ranges,
                    }
                } else {
                    &base_ranges
                };
                let (mut count, mut arenas) = body_matches(
                    patterns,
                    ctx.data,
                    ranges,
                    options.max_subsignature_matches,
                    None,
                );
                if is_vinfo {
                    let vinfo = ctx.pe().map(|p| p.vinfo.as_slice()).unwrap_or(&[]);
                    arenas.retain(|&(s, _)| vinfo.binary_search(&(s as u32)).is_ok());
                    count = arenas.len();
                }
                counts[i] = count;
                last_offsets[i] = arenas.iter().map(|a| a.0).max();
                body_arenas[i] = arenas;
                evaluated[i] = true;
                // Short-circuit: if this absent subsig already makes the signature
                // unsatisfiable (a missing AND term), skip every remaining subsig.
                if !signature.expression.can_still_match(counts, evaluated) {
                    return;
                }
            }
        }

        // Image fuzzy-hash subsignatures: match when the file's perceptual image
        // hash equals the subsig hash exactly (ClamAV's `fuzzy_hash_check`, which
        // supports only hamming distance 0). The hash is computed once per file.
        for (i, subsig) in subsigs.iter().enumerate() {
            if let Subsignature::Fuzzy(hash) = subsig {
                if ctx.image_fuzzy_hash() == Some(*hash) {
                    counts[i] = 1;
                }
            }
        }

        // Phase 2: PCRE and byte-compare subsignatures, whose triggers
        // reference the phase-1 body results.
        for (i, subsig) in subsigs.iter().enumerate() {
            match subsig {
                Subsignature::Pcre(pcre) => {
                    if pcre.trigger.eval(counts).matched {
                        // Compile the regex on first trigger (lazy — most PCREs
                        // never fire, so they stay uncompiled and cost no RAM).
                        if let Some(re) = pcre.regex.get() {
                            counts[i] = if pcre.global {
                                re.find_iter(ctx.data)
                                    .take(options.max_subsignature_matches)
                                    .count()
                            } else {
                                usize::from(pcre.regex.is_match(ctx.data))
                            };
                        }
                    }
                }
                Subsignature::ByteCompare(spec) => {
                    // ClamAV (cli_bcomp_scanbuf): the referenced subsig must have
                    // matched, then anchor at its LAST match offset, coercing a
                    // missing offset (CLI_OFF_NONE) to 0 rather than skipping.
                    let trigger_hit = counts.get(spec.trigger_subsig).copied().unwrap_or(0) > 0;
                    if trigger_hit {
                        let base = last_offsets
                            .get(spec.trigger_subsig)
                            .copied()
                            .flatten()
                            .unwrap_or(0);
                        if spec.evaluate(ctx.data, base) {
                            counts[i] = 1;
                        }
                    }
                }
                _ => {}
            }
        }

        if signature.expression.eval(counts).matched {
            // HandlerType (ClamAV lsig_eval): a matching signature does NOT alert.
            // Instead ClamAV re-types the file and rescans as `handlertype`. We
            // faithfully suppress the alert; the re-typed rescan would only surface
            // a *different* nested detection, never this signature's name.
            if signature.handlertype.is_some() {
                return;
            }
            // A bytecode trigger does not alert on its own — it runs the ClamBC
            // program, which decides the verdict via setvirusname (cli_bytecode_runlsig).
            if let Some(bc_idx) = signature.bytecode {
                if let Some(name) = self.run_bytecode(bc_idx, counts, ctx) {
                    matches.push(ScanMatch {
                        name,
                        kind: SignatureKind::Logical,
                        source: signature.source.clone(),
                        object_path: ctx.object_path.to_string(),
                        view: ctx.view,
                        arenas: Vec::new(),
                    });
                }
                return;
            }
            // Collect the matched body arenas (capped) for disinfection.
            let mut arenas: Vec<(usize, usize)> = Vec::new();
            for sub in body_arenas.iter() {
                for &range in sub {
                    if arenas.len() >= ARENA_CAP {
                        break;
                    }
                    arenas.push(range);
                }
            }
            matches.push(ScanMatch {
                name: signature.name.to_string(),
                kind: SignatureKind::Logical,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
                arenas,
            });
        }
    }

    /// Run a ClamBC program for a matched trigger, building its context from the
    /// scan (file buffer, trigger subsig match counts, PE info). Returns the
    /// program's `setvirusname`, or `None` on no-detection / VM error.
    fn run_bytecode(
        &self,
        bc_idx: usize,
        counts: &[usize],
        ctx: &ScanContext<'_>,
    ) -> Option<String> {
        let bc = self.database.bytecode_programs.get(bc_idx)?;
        let mut bctx = crate::bytecode_vm::BcCtx::new(ctx.data);
        for (i, &c) in counts.iter().take(64).enumerate() {
            bctx.lsigcnt[i] = c as u32;
        }
        if let Some(pe) = ctx.pe() {
            bctx.ep = pe.entry_point_offset.unwrap_or(0) as u32;
            bctx.nsections = pe.sections.len() as u16;
            bctx.sections = pe
                .sections
                .iter()
                .map(|s| crate::bytecode_vm::PeSection {
                    rva: s.virtual_address,
                    vsz: s.virtual_size,
                    raw: s.raw_start as u32,
                    rsz: s.raw_size as u32,
                    chr: 0,
                    urva: s.virtual_address,
                    uvsz: s.virtual_size,
                    uraw: s.raw_start as u32,
                    ursz: s.raw_size as u32,
                })
                .collect();
        }
        match bc.run(&mut bctx) {
            Ok(_) => bctx.virname,
            Err(_) => None,
        }
    }
}

/// Count pattern hits within `ranges` and collect the matched byte ranges
/// (capped at `ARENA_CAP`) for disinfection. When `hints` is `Some`, each
/// pattern is verified only at the prefilter-provided atom offsets
/// (`find_all_at`) instead of rescanning the whole buffer; `None` is a full scan.
/// The largest match length across a subsignature's pattern variants, or `None`
/// if any variant is unbounded (open gap) — in which case its scan can't be
/// window-restricted.
fn subsig_max_match_len(patterns: &[crate::pattern::Pattern]) -> Option<usize> {
    let mut m = 0usize;
    for p in patterns {
        m = m.max(p.max_match_len()?);
    }
    Some(m)
}

/// Restrict `base` ranges to windows `[h - max_len, h + max_len + 1)` around each
/// hint `h`, merged and intersected with `base`. A match containing an atom at `h`
/// starts in `[h - max_len, h]`, so scanning these windows (rather than the whole
/// buffer) finds every match while skipping the regions no atom touched. The
/// generous end keeps `h` itself a valid start position for `find_all`'s
/// `max_pos = end - min_len` bound.
fn restrict_ranges(
    base: &[(usize, usize)],
    hints: &[u32],
    max_len: usize,
    data_len: usize,
) -> Vec<(usize, usize)> {
    if hints.is_empty() {
        return Vec::new();
    }
    let mut wins: Vec<(usize, usize)> = hints
        .iter()
        .map(|&h| {
            let h = h as usize;
            (h.saturating_sub(max_len), (h + max_len + 1).min(data_len))
        })
        .collect();
    wins.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(wins.len());
    for (s, e) in wins {
        match merged.last_mut() {
            Some(last) if s <= last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => merged.push((s, e)),
        }
    }
    let mut out = Vec::new();
    for &(bs, be) in base {
        for &(ms, me) in &merged {
            let s = bs.max(ms);
            let e = be.min(me);
            if s < e {
                out.push((s, e));
            }
        }
    }
    out
}

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
    let want = target.unwrap_or(0);

    // A normalized view forces its target (text=7, html=3).
    if let Some(hint) = ctx.target_hint {
        return want == 0 || want == hint;
    }
    // Target 0 = generic: applies to every file type.
    if want == 0 {
        return true;
    }
    // Prefer the precise `.ftm`-derived type when available (strict typing).
    if let Some(detected) = ctx.detected_target {
        return want == detected;
    }
    // Concrete magic-based typing. ClamAV always types the file and only runs a
    // signature whose Target matches; without this, a type-specific signature
    // (e.g. a SWF `Target:11` exploit rule) fires on unrelated files (a PE DLL
    // that merely contains the same strings) — a real false positive. So if the
    // file is a KNOWN type different from the signature's target, reject it. This
    // gate applies even in non-strict mode; it only rejects clear cross-type
    // mismatches, never an indeterminate type (which stays permissive to avoid
    // false negatives).
    if let Some(detected) = detect_builtin_target(ctx) {
        return want == detected;
    }
    // Indeterminate file type: strict mode still applies the positive checks it
    // can; non-strict stays permissive.
    if strict {
        match want {
            1 => ctx.pe().is_some(),
            3 => looks_like_html(ctx.data),
            7 => looks_like_ascii_text(ctx.data),
            _ => true,
        }
    } else {
        true
    }
}

/// Best-effort concrete file-type detection by magic → ClamAV target number.
/// Returns `Some` only for confident detections (so callers reject clear
/// cross-type mismatches); `None` when indeterminate (callers stay permissive).
fn detect_builtin_target(ctx: &ScanContext<'_>) -> Option<u32> {
    let d = ctx.data;
    if ctx.pe().is_some() {
        return Some(1); // CL_TYPE_MSEXE (PE)
    }
    if d.starts_with(b"\x7fELF") {
        return Some(6); // CL_TYPE_ELF
    }
    if d.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Some(2); // CL_TYPE_OLE2
    }
    if d.starts_with(b"%PDF") {
        return Some(10); // CL_TYPE_PDF
    }
    if d.starts_with(b"FWS") || d.starts_with(b"CWS") || d.starts_with(b"ZWS") {
        return Some(11); // CL_TYPE_SWF
    }
    // Mach-O thin (the fat magic 0xcafebabe collides with a Java class, so skip it).
    if d.len() >= 4
        && matches!(
            d[..4],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
        )
    {
        return Some(9); // CL_TYPE_MACHO
    }
    if d.starts_with(b"GIF8")
        || d.starts_with(&[0x89, b'P', b'N', b'G'])
        || d.starts_with(&[0xff, 0xd8, 0xff])
    {
        return Some(5); // CL_TYPE_GRAPHICS
    }
    None
}

/// Detect the container format for `.cdb` matching (extractor formats plus 7z).
fn detect_container_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some("7z");
    }
    detect_format(data)
}

/// ClamAV `CL_TYPE_*` for the container format of `data`, used to evaluate
/// logical signatures' `Container:` TDB constraint on extracted children. Only
/// the formats we actually extract are mapped; any other container type yields
/// `None`, so a signature requiring it simply never matches (no false positive),
/// exactly as if the file weren't inside that container.
fn clamav_container_type(data: &[u8]) -> Option<&'static str> {
    match detect_container_format(data) {
        Some("zip") => Some("CL_TYPE_ZIP"),
        Some("gz") => Some("CL_TYPE_GZ"),
        Some("xz") => Some("CL_TYPE_XZ"),
        Some("7z") => Some("CL_TYPE_7Z"),
        Some("tar") => Some("CL_TYPE_POSIX_TAR"),
        _ => None,
    }
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
    // Fail-fast: once the non-printable count exceeds 15% of the sample we
    // know the result without scanning the rest of the sample.
    let threshold = sample.len() * 15 / 100 + 1;
    let mut non_printable = 0usize;
    for &byte in sample {
        if !matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e) {
            non_printable += 1;
            if non_printable >= threshold {
                return false;
            }
        }
    }
    true
}

fn looks_like_html(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(4096)];
    // Scan for '<' first (fast byte search), then do case-insensitive prefix
    // comparison only at those positions. This avoids three full O(n) passes.
    for i in 0..sample.len() {
        if sample[i] != b'<' {
            continue;
        }
        let rest = &sample[i..];
        if rest.len() >= 5
            && rest[1..5].eq_ignore_ascii_case(b"html")
            && (rest.len() == 5 || !rest[5].is_ascii_alphanumeric())
        {
            return true; // <html
        }
        if rest.len() >= 14
            && rest[1..14].eq_ignore_ascii_case(b"!doctype html")
        {
            return true; // <!doctype html
        }
        if rest.len() >= 7
            && rest[1..7].eq_ignore_ascii_case(b"script")
            && (rest.len() == 7 || !rest[7].is_ascii_alphanumeric())
        {
            return true; // <script
        }
    }
    false
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
    // Search case-insensitively without allocating a lowercased copy of the
    // whole buffer: use an in-place case-insensitive window search instead.
    fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > haystack.len() {
            return None;
        }
        haystack.windows(needle.len()).position(|w| {
            w.iter()
                .zip(needle)
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })
    }
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(start) = find_ci(&data[cursor..], b"<script") {
        let tag_start = cursor + start;
        let Some(tag_end_rel) = find_bytes(&data[tag_start..], b">") else {
            break;
        };
        let body_start = tag_start + tag_end_rel + 1;
        let Some(body_end_rel) = find_ci(&data[body_start..], b"</script") else {
            break;
        };
        let body_end = body_start + body_end_rel;
        out.extend_from_slice(&data[body_start..body_end]);
        out.push(b'\n');
        cursor = body_end + b"</script".len();
    }
    out
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
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Signature"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap().into(),
                source: source.clone(),
            }],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Signature"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap().into(),
                source: source.clone(),
            }],
            name_arena,
            ..Default::default()
        };
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        let engine = Engine { database, prefilter };

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
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Text"),
                target: Some(7),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("68656c6c6f776f726c64", Modifiers::default())
                    .unwrap()
                    .into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Html"),
                target: Some(3),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("7061796c6f6164", Modifiers::default()).unwrap().into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Zip.Child"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("4d414c57415245", Modifiers::default()).unwrap().into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
            name: "Test.Cdb".into(),
            container_type: ContainerType::Format("zip"),
            container_size: NumSpec::Any,
            has_filename: false,
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
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
            patterns: compile_pattern_variants("4d5a", Modifiers::default()).unwrap().into(),
            clamav_type: "CL_TYPE_MSEXE".into(),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ftm")),
                line: 1,
            },
        };
        let mut name_arena = String::new();
        let ext = ExtendedSignature {
            name: crate::database::intern_name(&mut name_arena, "Html.Sig"),
            target: Some(3),
            offset: OffsetSpec::any(),
            patterns: compile_pattern_variants("4142", Modifiers::default()).unwrap().into(),
            source: SourceLocation {
                path: std::sync::Arc::from(std::path::Path::new("t.ndb")),
                line: 1,
            },
        };
        let database = Database {
            extended: vec![ext],
            file_type_magic: vec![magic],
            name_arena,
            ..Default::default()
        };
        let engine = Engine { database, prefilter: crate::prefilter::AtomPrefilter::disabled() };
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
            prefilter: crate::prefilter::AtomPrefilter::disabled(),
        };
        let full = match_keys(&engine_full.scan_bytes(data, opts));
        // Threaded: real prefilter → candidate offsets + aligned gating cutoff.
        let db = build_db();
        let prefilter = crate::prefilter::AtomPrefilter::build(&db);
        let engine_thr = Engine {
            database: db,
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
        let mut name_arena = String::new();
        let mut ext = |name: &str, target: u32, offset: OffsetSpec, body: &str, m: Modifiers| {
            ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, name),
                target: Some(target),
                offset,
                patterns: compile_pattern_variants(body, m).unwrap().into(),
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
        drop(ext); // release the &mut name_arena borrow so the arena can move below
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
            name_arena,
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

    // --- TDB (target description block) gating: a logical signature only fires
    // when its Container/FileSize/NumberOfSections context holds, and is skipped
    // entirely when gated by something we can't evaluate (IconGroup). This is the
    // fix for the mass false-positive where icon/container-gated heuristics fired
    // on every file. ---

    fn tdb_src() -> SourceLocation {
        SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("t.ldb")),
            line: 1,
        }
    }

    fn engine_with_logical(line: &str) -> (Engine, Vec<String>) {
        let (sig, warnings) = parse_logical_signature(line, tdb_src()).unwrap();
        let database = Database {
            logical: vec![sig],
            ..Default::default()
        };
        let prefilter = crate::prefilter::AtomPrefilter::build(&database);
        (
            Engine {
                database,
                prefilter,
            },
            warnings,
        )
    }

    #[test]
    fn presence_filter_does_not_drop_matches_on_large_buffers() {
        // The 3-gram presence filter only activates on buffers >= 64 KiB. Build a
        // large buffer and confirm a real match (keyword far from the start, plus a
        // wildcard-prefixed atom) still fires with the filter active.
        let (engine, w) = engine_with_logical(
            "Test.Big;Target:0;0|1;??706f7765727368656c6c;636572747574696c",
        );
        assert!(w.is_empty());
        // 80 KiB of a single byte (so most 3-grams are absent) with the keyword
        // embedded late → presence filter must still report it present.
        let mut buf = vec![0x41u8; 80 * 1024];
        buf.extend_from_slice(b"Zpowershell padding");
        assert!(
            engine.scan_bytes(&buf, ScanOptions::default())
                .iter().any(|m| m.name == "Test.Big"),
            "presence filter dropped a real match on a large buffer"
        );
        // certutil present instead, at a different late offset.
        let mut buf2 = vec![0x00u8; 70 * 1024];
        buf2.extend_from_slice(b"xx certutil xx");
        assert!(engine.scan_bytes(&buf2, ScanOptions::default())
            .iter().any(|m| m.name == "Test.Big"));
        // Neither present in a large buffer → no match (and the filter skips the scan).
        let buf3 = vec![0x7Fu8; 80 * 1024];
        assert!(engine.scan_bytes(&buf3, ScanOptions::default()).is_empty());
    }

    #[test]
    fn or_indexed_window_restriction_matches() {
        // `0|1` is OR-indexed (no required subsig) → every subsig is scanned only
        // in windows around the prefilter's union atom offsets. Exercises the
        // tricky case where the atom is NOT at the match start: subsig 0 is
        // `??powershell` (wildcard then the literal), so a real match starts one
        // byte BEFORE the "powershell" atom — the window must still cover it.
        let (engine, w) = engine_with_logical(
            "Test.Or;Target:0;0|1;??706f7765727368656c6c;636572747574696c",
        );
        assert!(w.is_empty());
        // "Xpowershell" (any byte then the literal) → subsig 0 matches.
        assert!(engine
            .scan_bytes(b"....Xpowershell....", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Or"));
        // "certutil" at the very end of the buffer → subsig 1 matches.
        assert!(engine
            .scan_bytes(b"junkjunkcertutil", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Or"));
        // Atom right at offset 0 (wildcard prefix consumes the byte before it does
        // not exist) — "Apowershell" at start still matches via subsig 0.
        assert!(engine
            .scan_bytes(b"Apowershell tail", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Or"));
        // Neither keyword present → no match (window restriction must not invent one).
        assert!(engine
            .scan_bytes(b"nothing to see here", ScanOptions::default())
            .is_empty());
    }

    #[test]
    fn compare_sibling_does_not_drop_logical_candidate() {
        // `(0=2)|1` matches if subsig 0 occurs exactly twice OR subsig 1 is
        // present. The prefilter's required-subsig probe must NOT wrongly gate this
        // on subsig 1: setting siblings to a huge count makes `0=2` falsely false,
        // which previously flagged subsig 1 as "required" and dropped the candidate
        // when the match came via `0=2` with subsig 1 absent. Regression for a
        // false negative found by adversarial audit.
        let (engine, w) = engine_with_logical("Test.Cmp;Target:0;(0=2)|1;4142;5859");
        assert!(w.is_empty());
        // subsig 0 ("AB") twice, subsig 1 ("XY") absent → `0=2` true → must match.
        let found = engine.scan_bytes(b"AB__AB__", ScanOptions::default());
        assert!(
            found.iter().any(|m| m.name == "Test.Cmp"),
            "false negative: (0=2) match dropped by prefilter gate selection"
        );
    }

    #[test]
    fn less_than_sibling_does_not_drop_logical_candidate() {
        // `(0|1)&(2<3)`: matches when (0 or 1 present) AND subsig 2 occurs < 3
        // times. A non-zero-but-small subsig-2 count satisfies `2<3`, which the
        // max-sibling probe (count = 1<<30) wrongly judges unsatisfiable.
        let (engine, w) =
            engine_with_logical("Test.Lt;Target:0;(0|1)&(2<3);4142;5859;4344");
        assert!(w.is_empty());
        // subsig 1 ("XY") present, subsig 0 absent, subsig 2 ("CD") twice (<3) → match.
        let found = engine.scan_bytes(b"XY__CD__CD", ScanOptions::default());
        assert!(
            found.iter().any(|m| m.name == "Test.Lt"),
            "false negative: (2<3) match dropped by prefilter gate selection"
        );
    }

    #[test]
    fn tdb_container_gates_match() {
        // Sig requires the object to live inside a ZIP container. Body = "MALWARE".
        let (engine, w) =
            engine_with_logical("Test.InZip;Engine:1-255,Container:CL_TYPE_ZIP,Target:0;0;4d414c57415245");
        assert!(w.is_empty());
        // Top-level "MALWARE" (no parent container) → must NOT fire.
        assert!(engine
            .scan_bytes(b"xxMALWAREyy", ScanOptions::default())
            .is_empty());
        // Same bytes inside a ZIP → child's parent container is CL_TYPE_ZIP → fires.
        let zip = stored_zip("c.bin", b"MALWARE");
        assert!(engine
            .scan_bytes(&zip, ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.InZip"));
    }

    /// Build a minimal but `parse_pe`-valid PE32 (MZ + PE header + 1 section).
    fn minimal_pe() -> Vec<u8> {
        let mut d = vec![0u8; 0x160];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        d[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        d[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = coff + 20; // 0x58
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
        d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        let sect = opt + 0xE0; // 0x138
        d[sect + 8..sect + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        d[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        d[sect + 16..sect + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        d[sect + 20..sect + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        d
    }

    #[test]
    fn swf_target_signature_does_not_match_pe() {
        // Regression: a Target:11 (SWF) signature must NOT fire on a PE file even
        // in non-strict mode (the MiscreantPunch.SWF.Exploit false positive on DLLs
        // that merely contain "VirtualProtect"+"Kernel32").
        let (engine, _) = engine_with_logical(
            "Test.Swf;Engine:81-255,Target:11;(0&1);5669727475616c50726f74656374::i;4b65726e656c3332::i",
        );
        // A minimal but valid PE that contains both strings.
        let mut pe = minimal_pe();
        pe.extend_from_slice(b"...VirtualProtect...Kernel32...");
        assert!(
            engine.scan_bytes(&pe, ScanOptions::default()).is_empty(),
            "SWF-targeted signature must not match a PE file"
        );
        // The same strings inside an actual SWF (FWS magic) DO match.
        let mut swf = b"FWS\x06\x00\x00\x00\x00".to_vec();
        swf.extend_from_slice(b"...VirtualProtect...Kernel32...");
        assert!(engine
            .scan_bytes(&swf, ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Swf"));
    }

    #[test]
    fn tdb_engine_flevel_gates_loading() {
        // Engine:1-5 excludes our ENGINE_FLEVEL (240) → signature never fires.
        let (engine, _) = engine_with_logical("Test.OldEngine;Engine:1-5,Target:0;0;4142");
        assert!(engine.scan_bytes(b"xxAByy", ScanOptions::default()).is_empty());
        // Engine:51-255 includes 240 → fires normally.
        let (engine2, _) = engine_with_logical("Test.NewEngine;Engine:51-255,Target:0;0;4142");
        assert!(engine2
            .scan_bytes(b"xxAByy", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.NewEngine"));
    }

    #[test]
    fn tdb_filesize_gates_match() {
        let (engine, _) =
            engine_with_logical("Test.Size;Engine:1-255,FileSize:5-10,Target:0;0;4142");
        // len 3, below FileSize:5-10 → no match.
        assert!(engine.scan_bytes(b"xAB", ScanOptions::default()).is_empty());
        // len 7, within range → match.
        assert!(engine
            .scan_bytes(b"xxABxxy", ScanOptions::default())
            .iter()
            .any(|m| m.name == "Test.Size"));
    }

    #[test]
    fn tdb_icongroup_evaluated_no_false_positive() {
        // IconGroup is now evaluated by the icon matcher (matchicon). It is no
        // longer an "unsupported" TDB, so it produces no warning; and on a non-PE
        // buffer the icon constraint can't hold, so the sig does NOT fire even
        // though its body "AB" is present — still no false positive.
        let (engine, warnings) =
            engine_with_logical("Test.Icon;Engine:1-255,IconGroup1:BROWSER,Target:0;0;4142");
        assert!(
            warnings.is_empty(),
            "IconGroup is supported now; no unsupported-TDB warning"
        );
        assert!(engine.scan_bytes(b"xxAByy", ScanOptions::default()).is_empty());
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
